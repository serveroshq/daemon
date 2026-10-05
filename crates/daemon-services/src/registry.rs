use std::path::PathBuf;

use daemon_protocol::{AdoptedCapability, DiscoveredService, ServiceManager, ServiceOrigin};
use daemon_state::State;
use serde::{Deserialize, Serialize};

use crate::Result;

const KEY: &str = "services.registry";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunBy {
    Systemd {
        unit: String,
    },
    Docker {
        container: String,
    },
    Compose {
        container: String,
        project: String,
        dir: String,
        service: Option<String>,
    },
    Observed {
        manager: String,
    },
}

impl RunBy {
    pub fn label(&self) -> String {
        match self {
            RunBy::Systemd { .. } => "systemd".into(),
            RunBy::Docker { .. } => "docker".into(),
            RunBy::Compose { .. } => "docker compose".into(),
            RunBy::Observed { manager } => manager.clone(),
        }
    }

    pub fn from_discovered(service: &DiscoveredService) -> Self {
        match service.manager {
            ServiceManager::Systemd => RunBy::Systemd {
                unit: service
                    .details
                    .get("unit")
                    .cloned()
                    .unwrap_or_else(|| service.key.trim_start_matches("systemd:").to_string()),
            },
            ServiceManager::Docker => RunBy::Docker {
                container: service.key.trim_start_matches("docker:").to_string(),
            },
            ServiceManager::Compose => RunBy::Compose {
                container: service.key.trim_start_matches("docker:").to_string(),
                project: service
                    .details
                    .get("compose_project")
                    .cloned()
                    .unwrap_or_default(),
                dir: service.working_dir.clone().unwrap_or_default(),
                service: None,
            },
            other => RunBy::Observed {
                manager: format!("{other:?}").to_lowercase(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedService {
    pub key: String,
    pub name: String,
    pub run_by: RunBy,
    pub origin: ServiceOrigin,
    pub adopted_at: i64,
    pub capabilities: Vec<AdoptedCapability>,
    pub roots: Vec<PathBuf>,
    pub config_paths: Vec<PathBuf>,
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub added_artifacts: Vec<PathBuf>,
}

impl ManagedService {
    pub fn can(&self, capability: AdoptedCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

pub struct Registry<'a> {
    state: &'a State,
}

impl<'a> Registry<'a> {
    pub fn new(state: &'a State) -> Self {
        Self { state }
    }

    pub fn all(&self) -> Result<Vec<ManagedService>> {
        Ok(match self.state.kv_get(KEY)? {
            Some(json) => serde_json::from_str(&json)?,
            None => Vec::new(),
        })
    }

    pub fn get(&self, key: &str) -> Result<Option<ManagedService>> {
        Ok(self.all()?.into_iter().find(|s| s.key == key))
    }

    pub fn upsert(&self, service: ManagedService) -> Result<()> {
        let mut all = self.all()?;
        all.retain(|s| s.key != service.key);
        all.push(service);
        all.sort_by(|a, b| a.key.cmp(&b.key));

        self.state.kv_set(KEY, &serde_json::to_string(&all)?)?;

        Ok(())
    }

    pub fn remove(&self, key: &str) -> Result<Option<ManagedService>> {
        let mut all = self.all()?;
        let removed = all.iter().position(|s| s.key == key).map(|i| all.remove(i));

        self.state.kv_set(KEY, &serde_json::to_string(&all)?)?;

        Ok(removed)
    }

    pub fn permitted_roots(&self) -> Result<Vec<PathBuf>> {
        Ok(self
            .all()?
            .iter()
            .flat_map(|s| s.roots.iter().cloned().chain(s.data_dir.iter().cloned()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed(key: &str) -> ManagedService {
        ManagedService {
            key: key.into(),
            name: "x".into(),
            run_by: RunBy::Systemd {
                unit: "x.service".into(),
            },
            origin: ServiceOrigin::Discovered,
            adopted_at: 0,
            capabilities: vec![AdoptedCapability::Lifecycle],
            roots: vec![PathBuf::from("/srv/x")],
            config_paths: vec![],
            data_dir: Some(PathBuf::from("/var/lib/x")),
            added_artifacts: vec![],
        }
    }

    #[test]
    fn registry_round_trips_and_removes() {
        let state = State::in_memory().unwrap();
        let registry = Registry::new(&state);

        registry.upsert(managed("systemd:b")).unwrap();
        registry.upsert(managed("systemd:a")).unwrap();
        registry.upsert(managed("systemd:a")).unwrap();

        assert_eq!(registry.all().unwrap().len(), 2);
        assert_eq!(registry.all().unwrap()[0].key, "systemd:a");
        assert_eq!(registry.permitted_roots().unwrap().len(), 4);

        assert!(registry.remove("systemd:a").unwrap().is_some());
        assert!(registry.get("systemd:a").unwrap().is_none());
        assert!(registry.remove("systemd:nope").unwrap().is_none());
    }
}
