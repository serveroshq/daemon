use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub binary: PathBuf,
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
    pub run_dir: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("/usr/local/bin/serverosd"),
            config_dir: PathBuf::from("/etc/serveros"),
            state_dir: PathBuf::from("/var/lib/serveros"),
            log_dir: PathBuf::from("/var/log/serveros"),
            run_dir: PathBuf::from("/run/serveros"),
        }
    }
}

impl Paths {
    pub fn under(root: &Path) -> Self {
        let defaults = Self::default();
        let rebase = |p: &Path| root.join(p.strip_prefix("/").unwrap_or(p));

        Self {
            binary: rebase(&defaults.binary),
            config_dir: rebase(&defaults.config_dir),
            state_dir: rebase(&defaults.state_dir),
            log_dir: rebase(&defaults.log_dir),
            run_dir: rebase(&defaults.run_dir),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("daemon.toml")
    }

    pub fn private_key(&self) -> PathBuf {
        self.config_dir.join("daemon.key")
    }

    /// The salt for hashed IP addresses in logs (daemon_core::ipmask).
    pub fn ip_mask_salt(&self) -> PathBuf {
        self.config_dir.join("ip-mask.salt")
    }

    pub fn client_cert(&self) -> PathBuf {
        self.config_dir.join("daemon.crt")
    }

    pub fn pinned_ca(&self) -> PathBuf {
        self.config_dir.join("ca.crt")
    }

    pub fn state_db(&self) -> PathBuf {
        self.state_dir.join("state.db")
    }

    pub fn inventory_file(&self) -> PathBuf {
        self.state_dir.join("inventory.json")
    }

    pub fn jobs_dir(&self) -> PathBuf {
        self.state_dir.join("jobs")
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.state_dir.join("backups")
    }

    pub fn manifest_file(&self) -> PathBuf {
        self.state_dir.join("manifest.json")
    }

    pub fn daemon_log(&self) -> PathBuf {
        self.log_dir.join("daemon.log")
    }

    pub fn actions_log(&self) -> PathBuf {
        self.log_dir.join("actions.log")
    }

    pub fn control_socket(&self) -> PathBuf {
        self.run_dir.join("daemon.sock")
    }

    pub fn systemd_unit(&self) -> PathBuf {
        PathBuf::from("/etc/systemd/system/serverosd.service")
    }

    pub fn owned_directories(&self) -> Vec<(PathBuf, u32)> {
        vec![
            (self.config_dir.clone(), 0o700),
            (self.state_dir.clone(), 0o700),
            (self.jobs_dir(), 0o700),
            (self.backups_dir(), 0o700),
            (self.log_dir.clone(), 0o755),
            (self.run_dir.clone(), 0o700),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebases_every_directory_under_the_root() {
        let paths = Paths::under(Path::new("/tmp/sandbox"));

        assert_eq!(
            paths.config_file(),
            PathBuf::from("/tmp/sandbox/etc/serveros/daemon.toml")
        );
        assert_eq!(
            paths.state_db(),
            PathBuf::from("/tmp/sandbox/var/lib/serveros/state.db")
        );
        assert_eq!(
            paths.actions_log(),
            PathBuf::from("/tmp/sandbox/var/log/serveros/actions.log")
        );
        assert_eq!(
            paths.binary,
            PathBuf::from("/tmp/sandbox/usr/local/bin/serverosd")
        );
    }

    #[test]
    fn secrets_live_in_root_only_directories() {
        let modes: Vec<(PathBuf, u32)> = Paths::default().owned_directories();
        let config = modes
            .iter()
            .find(|(p, _)| p == Path::new("/etc/serveros"))
            .unwrap();
        let logs = modes
            .iter()
            .find(|(p, _)| p == Path::new("/var/log/serveros"))
            .unwrap();

        assert_eq!(config.1, 0o700);
        assert_eq!(logs.1, 0o755);
    }
}
