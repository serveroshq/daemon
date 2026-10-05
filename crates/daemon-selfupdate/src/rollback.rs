use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const MARKER: &str = "update.json";
pub const MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Marker {
    pub from: String,
    pub to: String,
    pub installed_at: i64,
    pub attempts: u32,
}

impl Marker {
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(MARKER)
    }

    pub fn read(state_dir: &Path) -> Option<Self> {
        std::fs::read_to_string(Self::path(state_dir))
            .ok()
            .and_then(|j| serde_json::from_str(&j).ok())
    }

    pub fn write(&self, state_dir: &Path) -> std::io::Result<()> {
        std::fs::write(
            Self::path(state_dir),
            serde_json::to_vec_pretty(self).unwrap(),
        )
    }

    pub fn clear(state_dir: &Path) {
        let _ = std::fs::remove_file(Self::path(state_dir));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootDecision {
    Normal,
    OnTrial {
        from: String,
        to: String,
        attempt: u32,
    },
    RolledBack {
        from: String,
        to: String,
    },
}

pub struct RollbackGuard {
    pub binary: PathBuf,
    pub state_dir: PathBuf,
}

impl RollbackGuard {
    pub fn on_boot(&self, running_version: &str) -> BootDecision {
        let Some(mut marker) = Marker::read(&self.state_dir) else {
            return BootDecision::Normal;
        };

        if marker.to != running_version {
            if marker.from == running_version {
                warn!(from = %marker.from, to = %marker.to, "previous binary is running; clearing update marker");
                Marker::clear(&self.state_dir);
            }
            return BootDecision::Normal;
        }

        marker.attempts += 1;

        if marker.attempts > MAX_ATTEMPTS {
            return match self.restore_previous() {
                Ok(()) => {
                    Marker::clear(&self.state_dir);
                    warn!(from = %marker.from, to = %marker.to, "new binary failed {MAX_ATTEMPTS} starts; previous restored");
                    BootDecision::RolledBack {
                        from: marker.from,
                        to: marker.to,
                    }
                }
                Err(e) => {
                    warn!(error = %e, "rollback failed; continuing with the new binary");
                    let _ = marker.write(&self.state_dir);
                    BootDecision::OnTrial {
                        from: marker.from,
                        to: marker.to,
                        attempt: marker.attempts,
                    }
                }
            };
        }

        let _ = marker.write(&self.state_dir);
        info!(to = %marker.to, attempt = marker.attempts, "new binary on trial");

        BootDecision::OnTrial {
            from: marker.from,
            to: marker.to,
            attempt: marker.attempts,
        }
    }

    pub fn confirm(&self) -> Option<Marker> {
        let marker = Marker::read(&self.state_dir)?;
        Marker::clear(&self.state_dir);
        info!(from = %marker.from, to = %marker.to, "update confirmed");
        Some(marker)
    }

    fn restore_previous(&self) -> std::io::Result<()> {
        let previous = self.binary.with_extension("previous");

        if !previous.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no previous binary to restore",
            ));
        }

        let failed = self.binary.with_extension("failed");
        let _ = std::fs::remove_file(&failed);
        std::fs::rename(&self.binary, &failed)?;
        std::fs::rename(&previous, &self.binary)
    }

    pub fn prune_previous(&self) {
        let _ = std::fs::remove_file(self.binary.with_extension("previous"));
        let _ = std::fs::remove_file(self.binary.with_extension("failed"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(dir: &Path) -> RollbackGuard {
        let binary = dir.join("serverosd");
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(binary.with_extension("previous"), b"old").unwrap();
        RollbackGuard {
            binary,
            state_dir: dir.into(),
        }
    }

    #[test]
    fn three_failed_starts_restore_the_previous_binary() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(dir.path());
        Marker {
            from: "1.0.0".into(),
            to: "1.1.0".into(),
            installed_at: 0,
            attempts: 0,
        }
        .write(dir.path())
        .unwrap();

        for attempt in 1..=MAX_ATTEMPTS {
            assert_eq!(
                guard.on_boot("1.1.0"),
                BootDecision::OnTrial {
                    from: "1.0.0".into(),
                    to: "1.1.0".into(),
                    attempt
                }
            );
        }

        assert_eq!(
            guard.on_boot("1.1.0"),
            BootDecision::RolledBack {
                from: "1.0.0".into(),
                to: "1.1.0".into()
            }
        );
        assert_eq!(std::fs::read(&guard.binary).unwrap(), b"old");
        assert!(guard.binary.with_extension("failed").exists());
        assert!(Marker::read(dir.path()).is_none());
    }

    #[test]
    fn a_confirmed_update_clears_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(dir.path());
        Marker {
            from: "1.0.0".into(),
            to: "1.1.0".into(),
            installed_at: 0,
            attempts: 0,
        }
        .write(dir.path())
        .unwrap();

        assert!(matches!(
            guard.on_boot("1.1.0"),
            BootDecision::OnTrial { attempt: 1, .. }
        ));
        assert_eq!(guard.confirm().unwrap().to, "1.1.0");
        assert_eq!(guard.on_boot("1.1.0"), BootDecision::Normal);
    }

    #[test]
    fn the_old_binary_running_again_clears_a_stale_marker() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard(dir.path());
        Marker {
            from: "1.0.0".into(),
            to: "1.1.0".into(),
            installed_at: 0,
            attempts: 2,
        }
        .write(dir.path())
        .unwrap();

        assert_eq!(guard.on_boot("1.0.0"), BootDecision::Normal);
        assert!(Marker::read(dir.path()).is_none());
    }
}
