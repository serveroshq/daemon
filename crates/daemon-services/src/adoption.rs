use std::path::PathBuf;

use daemon_protocol::{AdoptedCapability, DiscoveredService, ServiceOrigin};
use serde::Serialize;

use crate::registry::{ManagedService, Registry, RunBy};
use crate::Result;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AdoptionPreview {
    pub key: String,
    pub name: String,
    pub run_by: String,
    pub will_manage: Vec<AdoptedCapability>,
    pub left_alone: Vec<String>,
    pub unavailable: Vec<(AdoptedCapability, String)>,
    pub restart_required: bool,
    pub estimated_downtime_secs: u64,
    pub warnings: Vec<String>,
}

const ALL: &[AdoptedCapability] = &[
    AdoptedCapability::Lifecycle,
    AdoptedCapability::Logs,
    AdoptedCapability::Metrics,
    AdoptedCapability::Config,
    AdoptedCapability::Backup,
    AdoptedCapability::Deploy,
    AdoptedCapability::Rollback,
    AdoptedCapability::Files,
];

pub fn preview(service: &DiscoveredService) -> AdoptionPreview {
    let run_by = RunBy::from_discovered(service);
    let mut unavailable = Vec::new();

    for capability in ALL {
        if service.capabilities.contains(capability) {
            continue;
        }

        let reason = match (capability, &run_by) {
            (
                AdoptedCapability::Lifecycle | AdoptedCapability::Logs,
                RunBy::Observed { manager },
            ) => {
                format!("run by {manager}; ServerOS does not know how to bring it back if it stopped it")
            }
            (AdoptedCapability::Deploy | AdoptedCapability::Rollback, _) => {
                "no source or build definition was found for it".into()
            }
            (AdoptedCapability::Backup, _) => {
                "no data directory or dump tool is known for this kind of service".into()
            }
            (AdoptedCapability::Config, _) => "no config files were identified".into(),
            (AdoptedCapability::Files, _) => "no working directory was identified".into(),
            _ => "not applicable to this kind of service".into(),
        };

        unavailable.push((*capability, reason));
    }

    let mut left_alone: Vec<String> = service.config_paths.clone();
    if let Some(dir) = &service.working_dir {
        left_alone.push(dir.clone());
    }

    let mut warnings: Vec<String> = service
        .details
        .get("warning")
        .cloned()
        .into_iter()
        .collect();
    if service.confidence < 70 {
        warnings.push(format!(
            "identified with {}% confidence; check the name and kind are right",
            service.confidence
        ));
    }
    if service.details.contains_key("pre_existing_failure") {
        warnings.push("this service was already failed before adoption".into());
    }

    AdoptionPreview {
        key: service.key.clone(),
        name: service.name.clone(),
        run_by: run_by.label(),
        will_manage: service.capabilities.clone(),
        left_alone,
        unavailable,
        restart_required: false,
        estimated_downtime_secs: 0,
        warnings,
    }
}

pub fn commit(
    registry: &Registry<'_>,
    service: &DiscoveredService,
    now: i64,
) -> Result<ManagedService> {
    let mut roots: Vec<PathBuf> = service.working_dir.iter().map(PathBuf::from).collect();
    roots.retain(|r| r != std::path::Path::new("/"));

    let managed = ManagedService {
        key: service.key.clone(),
        name: service.name.clone(),
        run_by: RunBy::from_discovered(service),
        origin: ServiceOrigin::Discovered,
        adopted_at: now,
        capabilities: service.capabilities.clone(),
        roots,
        config_paths: service.config_paths.iter().map(PathBuf::from).collect(),
        data_dir: service.data_dir.as_deref().map(PathBuf::from),
        added_artifacts: Vec::new(),
    };

    registry.upsert(managed.clone())?;

    Ok(managed)
}

pub fn unadopt(registry: &Registry<'_>, key: &str) -> Result<Vec<PathBuf>> {
    Ok(registry
        .remove(key)?
        .map(|s| s.added_artifacts)
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use daemon_protocol::{ServiceKind, ServiceManager, ServiceStatus};
    use daemon_state::State;

    use super::*;

    fn discovered(manager: ServiceManager, caps: &[AdoptedCapability]) -> DiscoveredService {
        DiscoveredService {
            key: "systemd:pg.service".into(),
            name: "postgresql".into(),
            kind: ServiceKind::Database,
            manager,
            status: ServiceStatus::Running,
            version: None,
            ports: vec![5432],
            working_dir: Some("/var/lib/postgresql".into()),
            user: None,
            exec: None,
            config_paths: vec!["/etc/postgresql/16/main/postgresql.conf".into()],
            data_dir: Some("/var/lib/postgresql/16/main".into()),
            confidence: 95,
            details: BTreeMap::from([("unit".into(), "pg.service".into())]),
            capabilities: caps.to_vec(),
            origin: ServiceOrigin::Discovered,
        }
    }

    #[test]
    fn preview_is_honest_about_what_stays_unavailable() {
        let preview = preview(&discovered(
            ServiceManager::Systemd,
            &[
                AdoptedCapability::Lifecycle,
                AdoptedCapability::Logs,
                AdoptedCapability::Backup,
            ],
        ));

        assert!(!preview.restart_required);
        assert_eq!(preview.will_manage.len(), 3);
        assert!(preview
            .unavailable
            .iter()
            .any(|(c, reason)| *c == AdoptedCapability::Deploy && reason.contains("no source")));
        assert!(preview
            .left_alone
            .contains(&"/etc/postgresql/16/main/postgresql.conf".to_string()));
    }

    #[test]
    fn observed_services_explain_why_lifecycle_is_off() {
        let mut service = discovered(ServiceManager::Screen, &[AdoptedCapability::Metrics]);
        service.confidence = 55;

        let preview = preview(&service);
        let (_, reason) = preview
            .unavailable
            .iter()
            .find(|(c, _)| *c == AdoptedCapability::Lifecycle)
            .unwrap();

        assert!(reason.contains("screen"));
        assert!(preview.warnings.iter().any(|w| w.contains("55%")));
    }

    #[test]
    fn commit_and_unadopt_only_touch_the_ledger() {
        let state = State::in_memory().unwrap();
        let registry = Registry::new(&state);
        let service = discovered(ServiceManager::Systemd, &[AdoptedCapability::Lifecycle]);

        let managed = commit(&registry, &service, 42).unwrap();

        assert_eq!(
            managed.run_by,
            RunBy::Systemd {
                unit: "pg.service".into()
            }
        );
        assert_eq!(managed.roots, vec![PathBuf::from("/var/lib/postgresql")]);
        assert_eq!(registry.all().unwrap().len(), 1);

        assert_eq!(
            unadopt(&registry, "systemd:pg.service").unwrap(),
            Vec::<PathBuf>::new()
        );
        assert!(registry.all().unwrap().is_empty());
    }
}
