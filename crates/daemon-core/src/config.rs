//! `daemon.toml`: everything about this installation that is not a
//! secret. Secrets (the private key, the client certificate) live in their
//! own root-only files and are never written here.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The current schema. Bumped only for incompatible changes; additive
/// fields carry a `#[serde(default)]` instead.
pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid TOML: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("config version {found} is newer than this daemon understands ({supported}); update the daemon")]
    TooNew { found: u32, supported: u32 },
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub panel: PanelConfig,
    pub machine: MachineConfig,
    #[serde(default)]
    pub updates: UpdateConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub files: FilesConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub integrations: IntegrationsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PanelConfig {
    /// The API host the daemon connects out to, e.g. `api.serveros.com`.
    /// Always port 443; the daemon never listens.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    /// The panel's identifier for this machine, issued at enrolment.
    pub id: String,
    /// A human label shown in the panel; the hostname unless overridden.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateConfig {
    /// `stable` follows releases; `canary` takes prereleases first.
    pub channel: String,
    /// Pin to an exact version for change-controlled environments. Panel
    /// pushed updates are refused while a pin is set.
    pub pinned_version: Option<String>,
    /// Whether the daemon may update itself at all.
    pub automatic: bool,
    pub check_interval_secs: u64,
    /// Hosts a release may be downloaded from, besides the panel itself.
    /// An entry starting with `.` matches every subdomain.
    pub allowed_hosts: Vec<String>,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            channel: "stable".into(),
            pinned_version: None,
            automatic: true,
            check_interval_secs: 6 * 60 * 60,
            allowed_hosts: vec![".serveros.com".into()],
        }
    }
}

impl UpdateConfig {
    /// Whether a release URL's host is one we will download from.
    pub fn permits_host(&self, panel_host: &str, host: &str) -> bool {
        host == panel_host
            || self
                .allowed_hosts
                .iter()
                .any(|allowed| match allowed.strip_prefix('.') {
                    Some(apex) => host == apex || host.ends_with(allowed.as_str()),
                    None => host == allowed,
                })
    }
}

/// Which reverse proxy ServerOS Deploy publishes sites through.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyBackend {
    /// Caddy: automatic TLS, one include directory. The default.
    #[default]
    Caddy,
    /// nginx: a server block per site under conf.d, `nginx -t` before
    /// reload. TLS is whatever certbot or the operator set up.
    Nginx,
    /// No proxy: deploys succeed, but no site is published and the job
    /// says so.
    None,
}

/// Which tool firewall rules are applied with.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    /// ufw, with rules passed through in ufw's own syntax. The default.
    #[default]
    Ufw,
    /// nftables, in a table ServerOS owns (`inet serveros`).
    Nftables,
    /// iptables, appended to INPUT. Not persistent across reboots unless
    /// netfilter-persistent is installed.
    Iptables,
    None,
}

/// Which host tools ServerOS drives for the things it does not do itself.
/// Every default is the tool the installer would pick on a fresh Ubuntu
/// box; an existing server keeps what it has by changing these.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct IntegrationsConfig {
    pub proxy: ProxyBackend,
    pub firewall: FirewallBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    pub sample_interval_secs: u64,
    pub transmit_interval_secs: u64,
    /// How much history the local ring buffer keeps for backfill.
    pub retention_hours: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            sample_interval_secs: 10,
            transmit_interval_secs: 60,
            retention_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    /// Hard ceiling on one scan; a scan that overruns reports what it has.
    pub budget_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60 * 60,
            budget_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct FilesConfig {
    /// Directories the panel's file browser may reach beyond managed
    /// service directories. Empty by default; `/` is never permitted.
    pub extra_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Refuse backups, restores, and builds that would push disk use past this.
    pub disk_high_water_percent: u8,
    /// Ceiling on CPU share for builds, as a percentage of one core.
    pub build_cpu_percent: u32,
    pub build_memory_mb: u64,
    pub job_timeout_secs: u64,
    /// Idle terminal sessions are closed after this.
    pub terminal_idle_timeout_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            disk_high_water_percent: 90,
            build_cpu_percent: 200,
            build_memory_mb: 2048,
            job_timeout_secs: 30 * 60,
            terminal_idle_timeout_secs: 15 * 60,
        }
    }
}

fn default_port() -> u16 {
    443
}

/// `host[:port]` → (host, port), defaulting to 443. A bare IPv6 literal
/// is left alone.
fn split_host_port(value: &str) -> (String, u16) {
    let trimmed = value.trim().trim_end_matches('/');

    match trimmed.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (trimmed.to_string(), default_port()),
        },
        _ => (trimmed.to_string(), default_port()),
    }
}

impl Config {
    /// A fresh config for a machine that just enrolled. `panel_host` may
    /// carry a port (`gateway.example:8443`) for panels not on 443.
    pub fn new(panel_host: impl Into<String>, machine_id: impl Into<String>) -> Self {
        let (host, port) = split_host_port(&panel_host.into());

        Self {
            version: CONFIG_VERSION,
            panel: PanelConfig { host, port },
            machine: MachineConfig {
                id: machine_id.into(),
                label: None,
            },
            updates: UpdateConfig::default(),
            telemetry: TelemetryConfig::default(),
            discovery: DiscoveryConfig::default(),
            files: FilesConfig::default(),
            limits: LimitsConfig::default(),
            integrations: IntegrationsConfig::default(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.into(),
            source,
        })?;
        let config: Self = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.into(),
            source,
        })?;

        config.validate()?;

        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;

        let rendered =
            toml::to_string_pretty(self).map_err(|e| ConfigError::Invalid(e.to_string()))?;

        std::fs::write(path, rendered).map_err(|source| ConfigError::Write {
            path: path.into(),
            source,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version > CONFIG_VERSION {
            return Err(ConfigError::TooNew {
                found: self.version,
                supported: CONFIG_VERSION,
            });
        }

        if self.panel.host.trim().is_empty() {
            return Err(ConfigError::Invalid("panel.host is empty".into()));
        }

        if self.machine.id.trim().is_empty() {
            return Err(ConfigError::Invalid("machine.id is empty".into()));
        }

        if !matches!(self.updates.channel.as_str(), "stable" | "canary") {
            return Err(ConfigError::Invalid(format!(
                "updates.channel must be stable or canary, got {}",
                self.updates.channel
            )));
        }

        if self.limits.disk_high_water_percent == 0 || self.limits.disk_high_water_percent > 100 {
            return Err(ConfigError::Invalid(
                "limits.disk_high_water_percent must be 1..=100".into(),
            ));
        }

        if self
            .files
            .extra_roots
            .iter()
            .any(|root| root == Path::new("/"))
        {
            return Err(ConfigError::Invalid(
                "files.extra_roots may not include /".into(),
            ));
        }

        Ok(())
    }

    pub fn sample_interval(&self) -> Duration {
        Duration::from_secs(self.telemetry.sample_interval_secs.max(1))
    }

    pub fn transmit_interval(&self) -> Duration {
        Duration::from_secs(self.telemetry.transmit_interval_secs.max(1))
    }

    pub fn discovery_interval(&self) -> Duration {
        Duration::from_secs(self.discovery.interval_secs.max(60))
    }

    pub fn job_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.job_timeout_secs.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.toml");
        let config = Config::new("api.serveros.com", "mch_123");

        config.save(&path).unwrap();

        assert_eq!(Config::load(&path).unwrap(), config);
    }

    #[test]
    fn refuses_a_root_file_browser() {
        let mut config = Config::new("api.serveros.com", "mch_123");
        config.files.extra_roots.push(PathBuf::from("/"));

        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn refuses_a_config_from_the_future() {
        let mut config = Config::new("api.serveros.com", "mch_123");
        config.version = CONFIG_VERSION + 1;

        assert!(matches!(config.validate(), Err(ConfigError::TooNew { .. })));
    }

    #[test]
    fn unknown_keys_are_an_error_not_a_silent_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.toml");
        std::fs::write(
            &path,
            "version = 1\n[panel]\nhost = \"x\"\n[machine]\nid = \"m\"\n[panel_typo]\n",
        )
        .unwrap();

        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn a_panel_host_may_carry_a_port() {
        let config = Config::new("localhost:8443", "mch_1");
        assert_eq!(
            (config.panel.host.as_str(), config.panel.port),
            ("localhost", 8443)
        );

        let config = Config::new("api.serveros.com", "mch_1");
        assert_eq!(
            (config.panel.host.as_str(), config.panel.port),
            ("api.serveros.com", 443)
        );
    }

    #[test]
    fn release_hosts_are_the_panel_plus_the_allowlist() {
        let updates = UpdateConfig::default();

        assert!(updates.permits_host("panel.example", "panel.example"));
        assert!(updates.permits_host("panel.example", "releases.serveros.com"));
        assert!(updates.permits_host("panel.example", "serveros.com"));
        assert!(!updates.permits_host("panel.example", "evil.example"));
        assert!(!updates.permits_host("panel.example", "notserveros.com"));

        let custom = UpdateConfig {
            allowed_hosts: vec!["mirror.example".into()],
            ..Default::default()
        };
        assert!(custom.permits_host("panel.example", "mirror.example"));
        assert!(!custom.permits_host("panel.example", "sub.mirror.example"));
    }

    #[test]
    fn integrations_default_to_caddy_and_ufw_and_round_trip() {
        let mut config = Config::new("api.serveros.com", "mch_1");
        assert_eq!(config.integrations.proxy, ProxyBackend::Caddy);
        assert_eq!(config.integrations.firewall, FirewallBackend::Ufw);

        config.integrations.proxy = ProxyBackend::Nginx;
        config.integrations.firewall = FirewallBackend::Nftables;
        let text = toml::to_string(&config).unwrap();
        assert!(text.contains("proxy = \"nginx\""));
        assert!(text.contains("firewall = \"nftables\""));

        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed, config);
    }
}
