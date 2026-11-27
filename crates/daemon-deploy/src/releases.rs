use daemon_protocol::HealthCheck;
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
    /// False for apps that don't answer HTTP, like chat bots and workers:
    /// a rollback then checks the container keeps running instead of
    /// asking it for a page. Releases recorded before this was kept did.
    #[serde(default = "answers_http")]
    pub http: bool,
    /// A Compose project rather than one container. Releases recorded
    /// before this was kept are told apart by their container and image
    /// both being the project's name.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compose: bool,
    /// The app's own health check when this release was deployed, so a
    /// rollback to it asks the same page with the same patience. Missing
    /// for releases recorded before it was kept: they get the old check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthCheck>,
    /// The port the app listens on in its container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_port: Option<u16>,
    /// The network it shares with the machine's other apps, made again
    /// before a rollback starts it if it's been removed since.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// A Compose release's file, for starting it again when a deploy over
    /// it fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_file: Option<String>,
}

fn answers_http() -> bool {
    true
}

impl Release {
    /// Whether this release is a Compose project. Compose recreates the
    /// stack in place, so there's no stopped container of it to go back to.
    pub fn is_compose(&self) -> bool {
        self.compose || self.container == self.image
    }
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

/// The local port a release listens on, from its app's name and commit, so
/// two apps at the same commit on one machine (production and a staging
/// copy of it) don't both ask for the same port. Each release keeps the port
/// it was given, so this only decides new ones.
pub fn port_for(service: &str, commit: &str) -> u16 {
    let hash = service
        .bytes()
        .chain(std::iter::once(b'\n'))
        .chain(commit.bytes())
        .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
    20_000 + (hash % 10_000) as u16
}

/// The port for a commit's other container, used when it's deployed again
/// while it's live: the two run side by side until the swap, so it's never
/// the commit's usual port.
pub fn alternate_port(service: &str, commit: &str) -> u16 {
    let usual = port_for(service, commit);
    let port = port_for(service, &format!("{commit}\nalternate"));
    if port == usual {
        20_000 + (port - 20_000 + 1) % 10_000
    } else {
        port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(commit: &str) -> Release {
        Release {
            commit: commit.into(),
            image: format!("serveros/app:{commit}"),
            container: format!("serveros-app-{commit}"),
            port: port_for("app", commit),
            deployed_at: 0,
            status: "live".into(),
            http: true,
            compose: false,
            health: None,
            container_port: None,
            network: None,
            compose_file: None,
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
    fn compose_releases_are_told_apart_old_and_new() {
        assert!(!release("a").is_compose());

        // Recorded before the flag was kept: the project's name twice.
        let old: Release = serde_json::from_str(
            r#"{"commit":"a","image":"serveros-shop","container":"serveros-shop","port":0,"deployed_at":0,"status":"live"}"#,
        )
        .unwrap();
        assert!(old.is_compose());
        assert!(!old.compose);

        let new = Release {
            compose: true,
            ..release("a")
        };
        assert!(new.is_compose());

        // A container release's record is written as it was before.
        let json = serde_json::to_string(&release("a")).unwrap();
        assert!(!json.contains("compose"));
    }

    #[test]
    fn a_release_keeps_its_health_check_and_network() {
        let check = HealthCheck {
            path: "/up".into(),
            expected_status: 0,
            timeout_secs: 10,
            retries: 5,
            start_period_secs: 60,
            interval_secs: Some(3),
        };
        let kept = Release {
            health: Some(check.clone()),
            container_port: Some(3000),
            network: Some("serveros".into()),
            ..release("a")
        };
        let state = State::in_memory().unwrap();
        let ledger = ReleaseLedger::new(&state);
        ledger.promote("app", kept, 5).unwrap();
        let back = ledger.current("app").unwrap();
        assert_eq!(back.health, Some(check));
        assert_eq!(back.container_port, Some(3000));
        assert_eq!(back.network.as_deref(), Some("serveros"));

        // Recorded before these were kept.
        let old: Release = serde_json::from_str(
            r#"{"commit":"a","image":"serveros/app:a","container":"serveros-app-a","port":20001,"deployed_at":0,"status":"live"}"#,
        )
        .unwrap();
        assert!(old.health.is_none() && old.network.is_none());
        assert!(old.http);
    }

    #[test]
    fn ports_are_stable_and_in_range() {
        assert_eq!(port_for("shop", "abc123"), port_for("shop", "abc123"));
        assert_ne!(
            port_for("shop", "abc123"),
            port_for("shop-staging", "abc123")
        );
        assert!((20_000..30_000).contains(&port_for("shop", "deadbeef")));
    }

    #[test]
    fn a_commits_alternate_port_is_stable_in_range_and_not_its_usual_one() {
        for app in ["shop", "shop-staging", "api", "a"] {
            for commit in ["abc123", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "0"] {
                let port = alternate_port(app, commit);
                assert_eq!(port, alternate_port(app, commit));
                assert_ne!(port, port_for(app, commit));
                assert!((20_000..30_000).contains(&port));
            }
        }
    }

    #[test]
    fn deploying_a_commit_again_keeps_one_entry_for_it() {
        let state = State::in_memory().unwrap();
        let ledger = ReleaseLedger::new(&state);
        ledger.promote("app", release("a"), 5).unwrap();
        ledger.promote("app", release("b"), 5).unwrap();
        let again = Release {
            container: "serveros-app-b-b".into(),
            port: alternate_port("app", "b"),
            ..release("b")
        };
        let evicted = ledger.promote("app", again.clone(), 5).unwrap();

        // The entry it replaced isn't evicted: its container is the one the
        // deploy drains, and the image is the same one.
        assert!(evicted.is_empty());
        let all = ledger.load("app");
        assert_eq!(all.releases.len(), 2);
        assert_eq!(ledger.current("app").unwrap().container, again.container);
        assert_eq!(ledger.previous("app").unwrap().commit, "a");
    }

    #[test]
    fn an_app_and_its_copies_at_one_commit_get_different_ports() {
        // The names the panel gives an app's copies in other environments.
        let apps = [
            "shop",
            "shop-staging",
            "shop-staging-2",
            "shop-preview",
            "shop-dev",
            "api",
            "api-staging",
            "web",
            "web-staging",
        ];
        for commit in [
            "0123456789abcdef0123456789abcdef01234567",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "a1b2c3d",
        ] {
            let mut ports: Vec<u16> = apps.iter().map(|app| port_for(app, commit)).collect();
            ports.sort_unstable();
            ports.dedup();
            assert_eq!(ports.len(), apps.len(), "a port is shared at {commit}");
        }
        // The name and commit don't run together: "ab"+"c" isn't "a"+"bc".
        assert_ne!(port_for("ab", "c"), port_for("a", "bc"));
    }
}
