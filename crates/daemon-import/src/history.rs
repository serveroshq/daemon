//! What previous scans said, kept in `state.db`: the last full report,
//! and which service each port belonged to, so port reuse over time is
//! noticed instead of silently accepted.

use std::collections::BTreeMap;

use daemon_protocol::InventoryReport;
use daemon_state::State;

use crate::Result;

const LAST_REPORT: &str = "import.last_report";
const PORT_OWNERS: &str = "import.port_owners";

pub struct History<'a> {
    state: &'a State,
}

impl<'a> History<'a> {
    pub fn new(state: &'a State) -> Self {
        Self { state }
    }

    pub fn last_report(&self) -> Result<Option<InventoryReport>> {
        Ok(match self.state.kv_get(LAST_REPORT)? {
            Some(json) => serde_json::from_str(&json).ok(),
            None => None,
        })
    }

    pub fn remember_report(&self, report: &InventoryReport) -> Result<()> {
        self.state
            .kv_set(LAST_REPORT, &serde_json::to_string(report)?)?;

        let mut owners = self.port_owners()?;
        for service in &report.services {
            for port in &service.ports {
                owners.insert(*port, service.name.clone());
            }
        }
        self.state
            .kv_set(PORT_OWNERS, &serde_json::to_string(&owners)?)?;

        Ok(())
    }

    /// Port → the name of whatever last owned it.
    pub fn port_owners(&self) -> Result<BTreeMap<u16, String>> {
        Ok(match self.state.kv_get(PORT_OWNERS)? {
            Some(json) => serde_json::from_str(&json).unwrap_or_default(),
            None => BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use daemon_protocol::{
        DiscoveredService, ServiceKind, ServiceManager, ServiceOrigin, ServiceStatus,
    };

    use super::*;

    fn report(name: &str, port: u16) -> InventoryReport {
        InventoryReport {
            scanned_at: 1,
            duration_ms: 1,
            complete: true,
            services: vec![DiscoveredService {
                key: format!("systemd:{name}"),
                name: name.into(),
                kind: ServiceKind::Other,
                manager: ServiceManager::Systemd,
                status: ServiceStatus::Running,
                version: None,
                ports: vec![port],
                working_dir: None,
                user: None,
                exec: None,
                config_paths: vec![],
                data_dir: None,
                confidence: 90,
                details: Default::default(),
                capabilities: vec![],
                origin: ServiceOrigin::Discovered,
            }],
            listeners: vec![],
            certificates: vec![],
            scheduled: vec![],
            unknown: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn remembers_the_last_report_and_port_owners_across_scans() {
        let state = State::in_memory().unwrap();
        let history = History::new(&state);

        assert!(history.last_report().unwrap().is_none());

        history
            .remember_report(&report("postgresql", 5432))
            .unwrap();
        history.remember_report(&report("thing", 9000)).unwrap();

        let owners = history.port_owners().unwrap();
        assert_eq!(owners[&5432], "postgresql");
        assert_eq!(owners[&9000], "thing");
        assert_eq!(
            history.last_report().unwrap().unwrap().services[0].name,
            "thing"
        );
    }
}
