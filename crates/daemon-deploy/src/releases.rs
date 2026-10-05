use daemon_state::State;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Release {
    pub commit: String,
    pub image: String,
    pub container: String,
    pub port: u16,
    pub deployed_at: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ServiceReleases {
    pub current: Option<String>,
    pub releases: Vec<Release>,
}

pub struct ReleaseLedger<'a> {
    state: &'a State,
}

impl<'a> ReleaseLedger<'a> {
    pub fn new(state: &'a State) -> Self {
        Self { state }
    }

    fn key(service: &str) -> String {
        format!("deploy.{service}")
    }

    pub fn load(&self, service: &str) -> ServiceReleases {
        self.state
            .kv_get(&Self::key(service))
            .ok()
            .flatten()
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, service: &str, releases: &ServiceReleases) -> daemon_state::Result<()> {
        self.state
            .kv_set(&Self::key(service), &serde_json::to_string(releases)?)
    }

    pub fn current(&self, service: &str) -> Option<Release> {
        let all = self.load(service);
        all.current
            .as_ref()
            .and_then(|c| all.releases.iter().find(|r| &r.commit == c).cloned())
    }

    pub fn previous(&self, service: &str) -> Option<Release> {
        let all = self.load(service);
        all.releases
            .iter()
            .rev()
            .find(|r| r.status == "standby" && all.current.as_deref() != Some(&r.commit))
            .cloned()
    }

    pub fn promote(
        &self,
        service: &str,
        release: Release,
        retain: usize,
    ) -> daemon_state::Result<Vec<Release>> {
        let mut all = self.load(service);

        for r in all.releases.iter_mut() {
            if r.status == "live" {
                r.status = "standby".into();
            }
        }

        all.releases.retain(|r| r.commit != release.commit);
        all.current = Some(release.commit.clone());
        all.releases.push(Release {
            status: "live".into(),
            ..release
        });

        let mut evicted = Vec::new();
        while all.releases.len() > retain {
            let oldest = all
                .releases
                .iter()
                .position(|r| r.status != "live")
                .unwrap_or(0);
            evicted.push(all.releases.remove(oldest));
        }

        self.save(service, &all)?;

        Ok(evicted)
    }

    pub fn mark_failed(&self, service: &str, commit: &str) -> daemon_state::Result<()> {
        let mut all = self.load(service);
        if let Some(r) = all.releases.iter_mut().find(|r| r.commit == commit) {
            r.status = "failed".into();
        }
        self.save(service, &all)
    }
}

pub fn port_for(commit: &str) -> u16 {
    let hash = commit
        .bytes()
        .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
    20_000 + (hash % 10_000) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(commit: &str) -> Release {
        Release {
            commit: commit.into(),
            image: format!("serveros/app:{commit}"),
            container: format!("serveros-app-{commit}"),
            port: port_for(commit),
            deployed_at: 0,
            status: "live".into(),
        }
    }

    #[test]
    fn promote_demotes_the_previous_live_and_evicts_beyond_retention() {
        let state = State::in_memory().unwrap();
        let ledger = ReleaseLedger::new(&state);

        for commit in ["a", "b", "c", "d"] {
            ledger.promote("app", release(commit), 3).unwrap();
        }

        let all = ledger.load("app");
        assert_eq!(all.current.as_deref(), Some("d"));
        assert_eq!(all.releases.len(), 3);
        assert_eq!(
            all.releases.iter().filter(|r| r.status == "live").count(),
            1
        );
        assert_eq!(ledger.previous("app").unwrap().commit, "c");
        assert_eq!(ledger.current("app").unwrap().commit, "d");
    }

    #[test]
    fn ports_are_stable_and_in_range() {
        assert_eq!(port_for("abc123"), port_for("abc123"));
        assert!((20_000..30_000).contains(&port_for("deadbeef")));
    }
}
