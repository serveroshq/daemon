use std::path::PathBuf;
use std::sync::Arc;

use daemon_inventory::Scanner;
use daemon_protocol::{DiscoveredService, Event, InventoryReport, ServiceOrigin};
use daemon_services::adoption::{self, AdoptionPreview};
use daemon_services::{ManagedService, Registry};
use daemon_state::State;
use serde::Serialize;
use tracing::info;

use crate::enrich::{self, DataDirInfo};
use crate::history::History;
use crate::{ImportError, Result};

#[derive(Debug, Clone, Serialize)]
pub struct ImportOutcome {
    pub managed: ManagedService,
    pub new_roots: Vec<PathBuf>,
    pub preview: AdoptionPreview,
}

pub struct Importer {
    state: Arc<State>,
    scanner: Scanner,
    pub mounts: Vec<PathBuf>,
}

impl Importer {
    pub fn new(state: Arc<State>, scanner: Scanner) -> Self {
        Self {
            state,
            scanner,
            mounts: vec![PathBuf::from("/")],
        }
    }

    pub async fn scan(&self) -> Result<(InventoryReport, Vec<Event>)> {
        let mut report = self.scanner.scan().await;
        let history = History::new(&self.state);
        let previous = history.last_report()?;
        let owners = history.port_owners()?;
        let followed = Registry::new(&self.state).follow_recreated(&report.services)?;
        if followed > 0 {
            info!(followed, "kept adoptions for recreated containers");
        }
        let managed: std::collections::BTreeMap<String, ManagedService> =
            Registry::new(&self.state)
                .all()?
                .into_iter()
                .map(|m| (m.key.clone(), m))
                .collect();

        for service in report.services.iter_mut() {
            self.enrich(service, &owners).await;

            if let Some(managed) = managed.get(&service.key) {
                service.details.insert("managed".into(), "true".into());
                if managed.origin == ServiceOrigin::Created {
                    service.origin = ServiceOrigin::Created;
                }
                // Whether a backup has anything to copy, so the panel can
                // leave out what it can't back up (Docker itself, a proxy).
                let mounts: Vec<&str> = service
                    .details
                    .get("mounts")
                    // "source:destination" pairs; the host side is what's copied.
                    .map(|m| {
                        m.split(", ")
                            .map(|pair| pair.split(':').next().unwrap_or(pair))
                            .collect()
                    })
                    .unwrap_or_default();
                let method = daemon_backup::Strategy::method_for(managed, &mounts);
                service
                    .details
                    .insert("backup".into(), method.unwrap_or("none").into());
            }
        }

        let events = daemon_inventory::diff(previous.as_ref(), &report);
        history.remember_report(&report)?;

        info!(
            services = report.services.len(),
            unknown = report.unknown.len(),
            events = events.len(),
            "import scan complete"
        );

        Ok((report, events))
    }

    async fn enrich(
        &self,
        service: &mut DiscoveredService,
        owners: &std::collections::BTreeMap<u16, String>,
    ) {
        if service.version.is_none() {
            service.version = enrich::detect_version(service).await;
        }

        let configs = enrich::known_config_paths(service);
        if !configs.is_empty() {
            service.config_paths = configs.iter().map(|p| p.display().to_string()).collect();
        }

        let data = service
            .data_dir
            .as_deref()
            .and_then(|d| enrich::data_dir_info(std::path::Path::new(d), &self.mounts, 200_000));

        if let Some(data) = &data {
            service
                .details
                .insert("data_bytes".into(), data.bytes.to_string());
            service
                .details
                .insert("data_mount".into(), data.mount.display().to_string());
        }

        let previous_owner = service
            .ports
            .first()
            .and_then(|p| owners.get(p))
            .map(String::as_str);
        let notes = enrich::warnings(service, data.as_ref(), previous_owner);

        if !notes.is_empty() {
            service.details.insert("notes".into(), notes.join(" | "));
        }
    }

    pub fn find(&self, key: &str) -> Result<DiscoveredService> {
        History::new(&self.state)
            .last_report()?
            .and_then(|r| r.services.into_iter().find(|s| s.key == key))
            .ok_or_else(|| ImportError::UnknownService(key.into()))
    }

    pub fn preview(&self, key: &str) -> Result<AdoptionPreview> {
        let service = self.find(key)?;
        let mut preview = adoption::preview(&service);

        if let Some(notes) = service.details.get("notes") {
            preview
                .warnings
                .extend(notes.split(" | ").map(str::to_string));
        }

        preview.warnings.dedup();

        Ok(preview)
    }

    pub fn adopt(&self, key: &str, now: i64) -> Result<ImportOutcome> {
        let registry = Registry::new(&self.state);

        if registry.get(key)?.is_some() {
            return Err(ImportError::AlreadyManaged(key.into()));
        }

        let service = self.find(key)?;
        let preview = self.preview(key)?;
        let managed = adoption::commit(&registry, &service, now)?;
        let new_roots: Vec<PathBuf> = managed
            .roots
            .iter()
            .cloned()
            .chain(managed.data_dir.iter().cloned())
            .collect();

        info!(service = key, capabilities = ?managed.capabilities, "adopted without touching the service");

        Ok(ImportOutcome {
            managed,
            new_roots,
            preview,
        })
    }

    pub fn unadopt(&self, key: &str) -> Result<Vec<PathBuf>> {
        let registry = Registry::new(&self.state);

        if registry.get(key)?.is_none() {
            return Err(ImportError::NotManaged(key.into()));
        }

        let artifacts = adoption::unadopt(&registry, key)?;
        let mut removed = Vec::new();

        for artifact in artifacts {
            let gone = if artifact.is_dir() {
                std::fs::remove_dir_all(&artifact).is_ok()
            } else {
                std::fs::remove_file(&artifact).is_ok()
            };
            if gone {
                removed.push(artifact);
            }
        }

        info!(
            service = key,
            removed = removed.len(),
            "un-adopted; only ServerOS-added artifacts removed"
        );

        Ok(removed)
    }

    pub fn managed(&self) -> Result<Vec<ManagedService>> {
        Ok(Registry::new(&self.state).all()?)
    }
}

#[allow(dead_code)]
fn _keep(_: &DataDirInfo) {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use daemon_protocol::{
        AdoptedCapability, ServiceKind, ServiceManager, ServiceOrigin, ServiceStatus,
    };

    use super::*;

    fn seed_report(state: &State) {
        let report = InventoryReport {
            scanned_at: 1,
            duration_ms: 1,
            complete: true,
            services: vec![DiscoveredService {
                key: "systemd:pg.service".into(),
                name: "postgresql".into(),
                kind: ServiceKind::Database,
                manager: ServiceManager::Systemd,
                status: ServiceStatus::Running,
                version: Some("16.3".into()),
                ports: vec![5432],
                working_dir: Some("/var/lib/postgresql".into()),
                user: Some("postgres".into()),
                exec: None,
                config_paths: vec![],
                data_dir: Some("/var/lib/postgresql/16/main".into()),
                confidence: 95,
                details: BTreeMap::from([
                    ("unit".into(), "pg.service".into()),
                    (
                        "notes".into(),
                        "data lives on a separate mount (/data)".into(),
                    ),
                ]),
                capabilities: vec![
                    AdoptedCapability::Lifecycle,
                    AdoptedCapability::Logs,
                    AdoptedCapability::Backup,
                ],
                origin: ServiceOrigin::Discovered,
            }],
            listeners: vec![],
            certificates: vec![],
            scheduled: vec![],
            unknown: vec![],
            warnings: vec![],
        };

        History::new(state).remember_report(&report).unwrap();
    }

    fn importer() -> Importer {
        let state = Arc::new(State::in_memory().unwrap());
        seed_report(&state);
        Importer::new(state, Scanner::default())
    }

    #[test]
    fn preview_adopt_unadopt_round_trip() {
        let importer = importer();

        let preview = importer.preview("systemd:pg.service").unwrap();
        assert!(!preview.restart_required);
        assert!(preview
            .warnings
            .iter()
            .any(|w| w.contains("separate mount")));
        assert!(preview
            .unavailable
            .iter()
            .any(|(c, _)| *c == AdoptedCapability::Deploy));

        let outcome = importer.adopt("systemd:pg.service", 100).unwrap();
        assert_eq!(
            outcome.new_roots,
            vec![
                PathBuf::from("/var/lib/postgresql"),
                PathBuf::from("/var/lib/postgresql/16/main")
            ]
        );
        assert_eq!(importer.managed().unwrap().len(), 1);

        assert!(matches!(
            importer.adopt("systemd:pg.service", 101),
            Err(ImportError::AlreadyManaged(_))
        ));

        assert_eq!(
            importer.unadopt("systemd:pg.service").unwrap(),
            Vec::<PathBuf>::new()
        );
        assert!(importer.managed().unwrap().is_empty());
        assert!(matches!(
            importer.unadopt("systemd:pg.service"),
            Err(ImportError::NotManaged(_))
        ));
    }

    #[test]
    fn unknown_keys_ask_for_a_rescan() {
        let importer = importer();

        assert!(matches!(
            importer.preview("docker:nope"),
            Err(ImportError::UnknownService(_))
        ));
    }
}
