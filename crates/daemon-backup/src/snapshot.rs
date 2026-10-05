use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_jobs::{run_child, ChildOutcome, Failure, Progress};
use daemon_protocol::ServiceAction;
use daemon_services::{Lifecycle, ManagedService, RunBy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::retention;
use crate::strategy::Strategy;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub service: String,
    pub id: String,
    pub created_at: i64,
    pub reason: String,
    pub strategy: String,
    pub files: Vec<ManifestFile>,
    pub total_bytes: u64,
    #[serde(default)]
    pub uploaded_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFile {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

pub struct Snapshotter {
    pub backups_dir: PathBuf,
    pub disk_high_water_percent: u8,
    pub retention: usize,
}

impl Snapshotter {
    pub fn service_dir(&self, service: &str) -> PathBuf {
        self.backups_dir.join(sanitise(service))
    }

    pub fn list(&self, service: &str) -> Vec<Manifest> {
        let Ok(entries) = std::fs::read_dir(self.service_dir(service)) else {
            return Vec::new();
        };
        let mut manifests: Vec<Manifest> = entries
            .flatten()
            .filter_map(|e| std::fs::read_to_string(e.path().join("manifest.json")).ok())
            .filter_map(|j| serde_json::from_str(&j).ok())
            .collect();
        manifests.sort_by_key(|m| m.created_at);
        manifests
    }

    pub async fn take(
        &self,
        service: &ManagedService,
        strategy: &Strategy,
        reason: &str,
        estimate: u64,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<Manifest, Failure> {
        self.check_disk(estimate)?;

        let id = format!(
            "{}-{}",
            time::OffsetDateTime::now_utc().unix_timestamp(),
            reason
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(12)
                .collect::<String>()
        );
        let dir = self.service_dir(&service.name).join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| {
            Failure::new(
                "prepare",
                format!("could not create {}: {e}", dir.display()),
            )
        })?;
        restrict(&dir);

        progress.phase("dump", Some(20)).await;

        let produced = match strategy {
            Strategy::Postgres { user } => {
                let out = dir.join("postgres.sql");
                let uid_gid = daemon_files::lookup_user(user);
                shell_to_file(
                    "pg_dumpall",
                    &["--clean", "--if-exists"],
                    &out,
                    uid_gid,
                    cancel,
                    progress,
                )
                .await?;
                vec![out]
            }
            Strategy::Mysql => {
                let out = dir.join("mysql.sql");
                shell_to_file(
                    "mysqldump",
                    &[
                        "--all-databases",
                        "--single-transaction",
                        "--routines",
                        "--triggers",
                        "--events",
                    ],
                    &out,
                    None,
                    cancel,
                    progress,
                )
                .await?;
                vec![out]
            }
            Strategy::Redis { .. } => {
                let out = dir.join("dump.rdb");
                let outcome = run_child(
                    "redis-cli",
                    &["--rdb", &out.to_string_lossy()],
                    None,
                    &[],
                    Duration::from_secs(600),
                    cancel,
                    progress,
                    None,
                )
                .await;
                if !outcome.success() {
                    return Err(failure("dump", outcome, "redis-cli --rdb"));
                }
                vec![out]
            }
            Strategy::Files { paths } => {
                let out = dir.join("files.tar.gz");
                let mut args: Vec<String> = vec!["-czf".into(), out.to_string_lossy().into_owned()];
                for ex in Strategy::tar_excludes() {
                    args.push(format!("--exclude={ex}"));
                }
                for p in paths {
                    args.push(p.to_string_lossy().into_owned());
                }
                let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
                let outcome = run_child(
                    "tar",
                    &arg_refs,
                    None,
                    &[],
                    Duration::from_secs(3600),
                    cancel,
                    progress,
                    None,
                )
                .await;
                if !matches!(outcome, ChildOutcome::Exited { code: 0 | 1, .. }) || !out.is_file() {
                    return Err(failure("dump", outcome, "tar"));
                }
                vec![out]
            }
        };

        progress.phase("checksum", Some(80)).await;
        let mut files = Vec::new();
        let mut total = 0u64;

        for path in &produced {
            let bytes = std::fs::read(path).map_err(|e| Failure::new("checksum", e.to_string()))?;
            total += bytes.len() as u64;
            files.push(ManifestFile {
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
            });
        }

        let manifest = Manifest {
            service: service.name.clone(),
            id,
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
            reason: reason.into(),
            strategy: strategy.label().into(),
            files,
            total_bytes: total,
            uploaded_to: None,
        };
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .map_err(|e| Failure::new("record", e.to_string()))?;

        progress.phase("prune", Some(95)).await;
        for old in retention::to_prune(&self.list(&service.name), self.retention) {
            let _ = std::fs::remove_dir_all(self.service_dir(&service.name).join(&old.id));
            progress.line(format!("pruned snapshot {}", old.id)).await;
        }

        Ok(manifest)
    }

    pub async fn restore<L: Lifecycle>(
        &self,
        service: &ManagedService,
        strategy: &Strategy,
        snapshot_id: &str,
        lifecycle: &L,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(String, Manifest), Failure> {
        let manifest = self
            .list(&service.name)
            .into_iter()
            .find(|m| m.id == snapshot_id)
            .ok_or_else(|| Failure::new("restore", format!("snapshot {snapshot_id} not found")))?;
        let dir = self.service_dir(&service.name).join(&manifest.id);

        progress.phase("verify", Some(5)).await;
        for file in &manifest.files {
            let bytes = std::fs::read(dir.join(&file.name))
                .map_err(|e| Failure::new("verify", format!("{}: {e}", file.name)))?;
            if hex::encode(Sha256::digest(&bytes)) != file.sha256 {
                return Err(Failure::new(
                    "verify",
                    format!(
                        "{} does not match its checksum; the snapshot is damaged",
                        file.name
                    ),
                ));
            }
        }

        progress.phase("pre-restore snapshot", Some(15)).await;
        let safety = self
            .take(
                service,
                strategy,
                "pre-restore",
                manifest.total_bytes,
                cancel,
                progress,
            )
            .await?;
        progress
            .line(format!(
                "pre-restore snapshot {} taken; the restore can be undone from it",
                safety.id
            ))
            .await;

        progress.phase("restore", Some(50)).await;

        match strategy {
            Strategy::Postgres { user } => {
                let file = dir.join("postgres.sql");
                let outcome = run_child(
                    "psql",
                    &[
                        "-v",
                        "ON_ERROR_STOP=0",
                        "-f",
                        &file.to_string_lossy(),
                        "postgres",
                    ],
                    None,
                    &[],
                    Duration::from_secs(3600),
                    cancel,
                    progress,
                    daemon_files::lookup_user(user),
                )
                .await;
                if !outcome.success() {
                    return Err(failure("restore", outcome, "psql"));
                }
            }
            Strategy::Mysql => {
                let file = dir.join("mysql.sql");
                let outcome = run_child(
                    "sh",
                    &[
                        "-c",
                        &format!("mysql < '{}'", file.to_string_lossy().replace('\'', "")),
                    ],
                    None,
                    &[],
                    Duration::from_secs(3600),
                    cancel,
                    progress,
                    None,
                )
                .await;
                if !outcome.success() {
                    return Err(failure("restore", outcome, "mysql"));
                }
            }
            Strategy::Redis { data_dir } => {
                let target = target_for(service);
                lifecycle
                    .act(&target, ServiceAction::Stop)
                    .await
                    .map_err(|e| Failure::new("restore", format!("could not stop redis: {e}")))?;
                let result = std::fs::copy(dir.join("dump.rdb"), data_dir.join("dump.rdb"));
                let start = lifecycle.act(&target, ServiceAction::Start).await;
                result.map_err(|e| {
                    Failure::new("restore", format!("could not replace dump.rdb: {e}"))
                })?;
                start.map_err(|e| {
                    Failure::new("restore", format!("redis did not start after restore: {e}"))
                        .with_next_step("Check `journalctl -u redis` on the machine.")
                })?;
            }
            Strategy::Files { .. } => {
                let file = dir.join("files.tar.gz");
                let outcome = run_child(
                    "tar",
                    &["-xzf", &file.to_string_lossy(), "-C", "/", "--overwrite"],
                    None,
                    &[],
                    Duration::from_secs(3600),
                    cancel,
                    progress,
                    None,
                )
                .await;
                if !outcome.success() {
                    return Err(failure("restore", outcome, "tar"));
                }
            }
        }

        Ok((safety.id, manifest))
    }

    fn check_disk(&self, estimate: u64) -> Result<(), Failure> {
        let Some((total, free)) = disk_totals(&self.backups_dir) else {
            return Ok(());
        };

        if total == 0 {
            return Ok(());
        }

        let after = free.saturating_sub(estimate);
        let used_percent = 100 - (after * 100 / total);

        if used_percent as u8 > self.disk_high_water_percent {
            return Err(Failure::new(
                "disk",
                format!(
                    "snapshot of ~{} would push the disk to {used_percent}%, over the {}% limit",
                    human(estimate),
                    self.disk_high_water_percent
                ),
            )
            .with_next_step(
                "Free space, prune old snapshots, or raise limits.disk_high_water_percent.",
            ));
        }

        Ok(())
    }
}

fn target_for(service: &ManagedService) -> String {
    match &service.run_by {
        RunBy::Systemd { unit } => unit.clone(),
        RunBy::Docker { container } | RunBy::Compose { container, .. } => container.clone(),
        RunBy::Observed { .. } => service.name.clone(),
    }
}

async fn shell_to_file(
    program: &str,
    args: &[&str],
    out: &Path,
    run_as: Option<(u32, u32)>,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let cmd = format!(
        "{} {} > '{}'",
        program,
        args.join(" "),
        out.to_string_lossy().replace('\'', "")
    );
    let outcome = run_child(
        "sh",
        &["-c", &cmd],
        None,
        &[],
        Duration::from_secs(3600),
        cancel,
        progress,
        run_as,
    )
    .await;

    if outcome.success() {
        Ok(())
    } else {
        Err(failure("dump", outcome, program))
    }
}

fn failure(phase: &str, outcome: ChildOutcome, what: &str) -> Failure {
    match outcome {
        ChildOutcome::Exited { code, tail } => {
            Failure::new(phase, format!("{what} exited {code}")).with_output(tail)
        }
        ChildOutcome::TimedOut { tail } => {
            Failure::new(phase, format!("{what} timed out")).with_output(tail)
        }
        ChildOutcome::Cancelled { tail } => {
            Failure::new("cancelled", format!("{what} cancelled")).with_output(tail)
        }
        ChildOutcome::Unstartable(e) => {
            Failure::new(phase, e).with_next_step(format!("Install {what} on the machine."))
        }
    }
}

fn sanitise(service: &str) -> String {
    service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn restrict(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
}

#[cfg(unix)]
fn disk_totals(dir: &Path) -> Option<(u64, u64)> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

    (unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } == 0).then(|| {
        (
            stat.f_blocks as u64 * stat.f_frsize as u64,
            stat.f_bavail as u64 * stat.f_frsize as u64,
        )
    })
}

#[cfg(not(unix))]
fn disk_totals(_: &Path) -> Option<(u64, u64)> {
    None
}

fn human(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{:.1} GB", bytes as f64 / (1u64 << 30) as f64)
    } else if bytes >= 1 << 20 {
        format!("{:.1} MB", bytes as f64 / (1u64 << 20) as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use daemon_protocol::ServiceOrigin;
    use daemon_state::State;
    use uuid::Uuid;

    use super::*;

    fn progress() -> Progress {
        let state = Arc::new(State::in_memory().unwrap());
        let id = Uuid::new_v4();
        state.record_job(id, "test", "backup", "{}").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        Progress::new(id, state, tx, vec![])
    }

    #[tokio::test]
    async fn tars_a_directory_with_a_manifest_and_prunes() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("srv/app");
        std::fs::create_dir_all(app.join("node_modules")).unwrap();
        std::fs::write(app.join("index.php"), "<?php echo 1;").unwrap();
        std::fs::write(app.join("node_modules/junk"), "x").unwrap();

        let snapshotter = Snapshotter {
            backups_dir: dir.path().join("backups"),
            disk_high_water_percent: 100,
            retention: 2,
        };
        let service = ManagedService {
            key: "x:app".into(),
            name: "app".into(),
            run_by: RunBy::Systemd {
                unit: "app.service".into(),
            },
            origin: ServiceOrigin::Discovered,
            adopted_at: 0,
            capabilities: vec![],
            roots: vec![app.clone()],
            config_paths: vec![],
            data_dir: None,
            added_artifacts: vec![],
        };
        let strategy = Strategy::Files {
            paths: vec![app.clone()],
        };
        let (_tx, mut cancel) = watch::channel(false);
        let progress = progress();

        for reason in ["manual", "pre-deploy", "scheduled"] {
            let manifest = snapshotter
                .take(&service, &strategy, reason, 1024, &mut cancel, &progress)
                .await
                .unwrap();
            assert_eq!(manifest.files[0].name, "files.tar.gz");
            assert!(manifest.total_bytes > 0);
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }

        let kept = snapshotter.list("app");
        assert_eq!(kept.len(), 2, "retention keeps two");
        assert!(kept.iter().all(|m| m.reason != "manual"));
    }
}
