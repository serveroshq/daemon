use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    pub logs: LogsConfig,
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
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateConfig {
    pub channel: String,
    pub pinned_version: Option<String>,
    pub automatic: bool,
    pub check_interval_secs: u64,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyBackend {
    #[default]
    Caddy,
    Nginx,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    #[default]
    Ufw,
    Nftables,
    Iptables,
    None,
}

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
    pub budget_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct LogsConfig {
    pub enabled: bool,
    pub lines_per_second: u32,
    /// Replace IP addresses in log lines before they leave the machine.
    /// Only written when on, so a config that never used it still loads
    /// on an older daemon.
    #[serde(skip_serializing_if = "crate::ipmask::IpMasking::is_off")]
    pub mask_ips: crate::ipmask::IpMasking,
    /// Services and line patterns that are never sent. Only written when
    /// there are some, for the same reason.
    #[serde(skip_serializing_if = "crate::logskip::LogSkip::is_empty")]
    pub skip: crate::logskip::LogSkip,
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            lines_per_second: 100,
            mask_ips: crate::ipmask::IpMasking::Off,
            skip: crate::logskip::LogSkip::default(),
        }
    }
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
    pub extra_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    pub disk_high_water_percent: u8,
    pub build_cpu_percent: u32,
    pub build_memory_mb: u64,
    pub job_timeout_secs: u64,
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
            logs: LogsConfig::default(),
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
    fn keeps_log_skip_rules_and_leaves_them_out_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.toml");
        let mut config = Config::new("api.serveros.com", "mch_123");
        config.save(&path).unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("skip"));

        config.logs.skip.services.push("wings".into());
        config.logs.skip.patterns.push(crate::logskip::SkipPattern {
            service: Some("nginx*".into()),
            pattern: r"\d+".into(),
        });
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
