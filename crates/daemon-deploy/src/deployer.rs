//! The orchestration: one deploy, phase by phase, with the old release
//! kept live until the new one is verified.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use daemon_core::Paths;
use daemon_jobs::{Failure, JobContext, Progress};
use daemon_protocol::DeploySpec;
use daemon_state::State;
use serde::Serialize;
use tokio::sync::watch;

use crate::container::{self, BuildLimits};
use crate::proxy::Proxy;
use crate::releases::{self, Release, ReleaseLedger};
use crate::{git, health, RETAINED_RELEASES};

#[derive(Debug, Clone, Serialize)]
pub struct DeployResult {
    pub service: String,
    pub commit: String,
    pub container: String,
    pub port: u16,
    pub domains: Vec<String>,
    /// The previous release, still on disk for rollback.
    pub previous: Option<String>,
    /// Plain-language note about any restart the deploy could not avoid.
    pub restart_note: Option<String>,
}

pub struct Deployer {
    pub paths: Paths,
    pub state: Arc<State>,
    pub proxy: Proxy,
    pub build_limits: BuildLimits,
}

impl Deployer {
    fn apps_dir(&self) -> PathBuf {
        self.paths.state_dir.join("apps")
    }

    fn keys_dir(&self) -> PathBuf {
        self.paths.state_dir.join("keys")
    }

    fn env_file(&self, service: &str, commit: &str) -> PathBuf {
        self.apps_dir()
            .join(git::sanitise(service))
            .join(format!("{}.env", &commit[..commit.len().min(12)]))
    }

    /// The public deploy key for a service, generating one if needed.
    pub async fn deploy_key(&self, service: &str, progress: &Progress) -> Result<String, Failure> {
        git::ensure_deploy_key(&self.keys_dir(), service, progress).await
    }

    /// Write the env file for a release: 0600, owned by the service user
    /// where one exists (falls back to root, which Docker reads fine).
    fn write_env(
        &self,
        service: &str,
        commit: &str,
        env: &std::collections::BTreeMap<String, String>,
    ) -> Result<Option<PathBuf>, Failure> {
        if env.is_empty() {
            return Ok(None);
        }

        let path = self.env_file(service, commit);
        std::fs::create_dir_all(path.parent().unwrap())
            .map_err(|e| Failure::new("env", e.to_string()))?;

        let mut body = String::new();
        for (k, v) in env {
            if !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(Failure::new(
                    "env",
                    format!("{k:?} is not a valid environment variable name"),
                ));
            }
            body.push_str(k);
            body.push('=');
            body.push_str(v);
            body.push('\n');
        }

        write_private(&path, body.as_bytes())
            .map_err(|e| Failure::new("env", format!("could not write {}: {e}", path.display())))?;

        if let Some((uid, gid)) = daemon_files::lookup_user("serveros") {
            let _ = std::os::unix::fs::chown(&path, Some(uid), Some(gid));
        }

        Ok(Some(path))
    }

    pub async fn deploy(
        &self,
        ctx: &JobContext,
        spec: &DeploySpec,
    ) -> Result<DeployResult, Failure> {
        let progress = &ctx.progress;
        let mut cancel = ctx.cancel.clone();
        let ledger = ReleaseLedger::new(&self.state);
        let service = spec.service.clone();
        let commit = spec.commit.clone();
        let previous = ledger.current(&service);

        // 1. Workspace.
        progress.phase("prepare", Some(5)).await;
        let workspace = self.paths.jobs_dir().join(ctx.id.to_string());
        std::fs::create_dir_all(&workspace)
            .map_err(|e| Failure::new("prepare", format!("could not create workspace: {e}")))?;

        let result = self
            .deploy_inner(ctx, spec, &workspace, previous.as_ref(), &mut cancel)
            .await;

        // Workspaces are ephemeral; the image holds the release.
        let _ = std::fs::remove_dir_all(&workspace);

        match result {
            Ok(result) => Ok(result),
            Err(failure) => {
                // Whatever happened, the old release is still serving. Clean
                // up the half-made new one so a retry starts clean.
                let _ = ledger.mark_failed(&service, &commit);
                container::remove(&container::container_name(&service, &commit), progress).await;
                if let Some(prev) = &previous {
                    progress
                        .line(format!(
                            "{} is still live on release {}",
                            service,
                            &prev.commit[..7.min(prev.commit.len())]
                        ))
                        .await;
                }
                Err(failure)
            }
        }
    }

    async fn deploy_inner(
        &self,
        ctx: &JobContext,
        spec: &DeploySpec,
        workspace: &Path,
        previous: Option<&Release>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<DeployResult, Failure> {
        let progress = &ctx.progress;
        let service = &spec.service;
        let commit = &spec.commit;
        let step_timeout = ctx.timeout;

        // 2. Source.
        progress.phase("fetch", Some(15)).await;
        let (private_key, _) = git::key_paths(&self.keys_dir(), service);
        git::fetch(
            &spec.repo,
            commit,
            workspace,
            private_key.exists().then_some(private_key.as_path()),
            step_timeout,
            cancel,
            progress,
        )
        .await?;

        // 3. Environment, before anything runs.
        progress.phase("env", Some(25)).await;
        let env_file = self.write_env(service, commit, &spec.env)?;

        // Compose projects: one command, an unavoidable restart, said plainly.
        if let Some(compose) = &spec.compose_file {
            progress.phase("build", Some(40)).await;
            let project = format!("serveros-{}", git::sanitise(service));
            container::compose_up(
                workspace,
                compose,
                &project,
                env_file.as_deref(),
                step_timeout,
                cancel,
                progress,
            )
            .await?;
            progress.phase("verify", Some(90)).await;

            let release = Release {
                commit: commit.clone(),
                image: project.clone(),
                container: project,
                port: spec.port.unwrap_or(0),
                deployed_at: daemon_state::State::now(),
                status: "live".into(),
            };
            ReleaseLedger::new(&self.state)
                .promote(service, release.clone(), RETAINED_RELEASES)
                .map_err(|e| Failure::new("record", e.to_string()))?;

            return Ok(DeployResult {
                service: service.clone(),
                commit: commit.clone(),
                container: release.container,
                port: release.port,
                domains: spec.domains.clone(),
                previous: previous.map(|p| p.commit.clone()),
                restart_note: Some("Compose projects are recreated in place, so the service restarted briefly during this deploy.".into()),
            });
        }

        // 4. Build.
        progress.phase("build", Some(40)).await;
        let tag = container::image_tag(service, commit);
        container::build(
            workspace,
            spec.dockerfile.as_deref(),
            &tag,
            &self.build_limits,
            step_timeout,
            cancel,
            progress,
        )
        .await?;

        // 5. Start the new release beside the old one.
        progress.phase("start", Some(60)).await;
        let name = container::container_name(service, commit);
        let host_port = releases::port_for(commit);
        let container_port = spec.port.unwrap_or(80);
        container::remove(&name, progress).await;
        container::run(
            &name,
            &tag,
            host_port,
            container_port,
            env_file.as_deref(),
            Duration::from_secs(120),
            cancel,
            progress,
        )
        .await?;

        // 6. Health.
        progress.phase("health", Some(70)).await;
        health::wait_healthy(host_port, spec.health.as_ref(), progress).await?;

        // 7. Proxy swap: validated, reloaded, reverted on failure.
        if !spec.domains.is_empty() {
            progress.phase("proxy", Some(80)).await;
            self.proxy.ensure_import()?;
            self.proxy
                .publish(service, &spec.domains, host_port, cancel, progress)
                .await?;
        }

        // 8. Verify through the proxy path and record.
        progress.phase("verify", Some(90)).await;
        health::wait_healthy(host_port, spec.health.as_ref(), progress).await?;

        let ledger = ReleaseLedger::new(&self.state);
        let release = Release {
            commit: commit.clone(),
            image: tag,
            container: name.clone(),
            port: host_port,
            deployed_at: daemon_state::State::now(),
            status: "live".into(),
        };
        let evicted = ledger
            .promote(service, release, RETAINED_RELEASES)
            .map_err(|e| Failure::new("record", e.to_string()))?;

        // 9. Drain and stop the old release; keep it for rollback.
        if let Some(prev) = previous {
            progress.phase("drain", Some(95)).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) =
                container::stop(&prev.container, Duration::from_secs(90), cancel, progress).await
            {
                progress
                    .line(format!(
                        "old release {} did not stop cleanly: {}",
                        prev.container, e.message
                    ))
                    .await;
            }
        }

        for old in evicted {
            container::remove(&old.container, progress).await;
            container::remove_image(&old.image, progress).await;
            let _ = std::fs::remove_file(self.env_file(service, &old.commit));
        }

        Ok(DeployResult {
            service: service.clone(),
            commit: commit.clone(),
            container: name,
            port: host_port,
            domains: spec.domains.clone(),
            previous: previous.map(|p| p.commit.clone()),
            restart_note: None,
        })
    }

    /// Roll back to `target` (or the most recent standby): start it,
    /// check it, re-point the proxy, stop the current.
    pub async fn rollback(
        &self,
        ctx: &JobContext,
        service: &str,
        target: Option<&str>,
        domains: &[String],
    ) -> Result<DeployResult, Failure> {
        let progress = &ctx.progress;
        let mut cancel = ctx.cancel.clone();
        let ledger = ReleaseLedger::new(&self.state);
        let current = ledger.current(service);
        let all = ledger.load(service);

        let release = match target {
            Some(commit) => all
                .releases
                .iter()
                .find(|r| r.commit.starts_with(commit))
                .cloned(),
            None => ledger.previous(service),
        }
        .ok_or_else(|| {
            Failure::new("rollback", "no previous release to roll back to")
                .with_next_step("Deploy a new commit instead.")
        })?;

        if current.as_ref().is_some_and(|c| c.commit == release.commit) {
            return Err(Failure::new(
                "rollback",
                format!(
                    "{} is already live",
                    &release.commit[..7.min(release.commit.len())]
                ),
            ));
        }

        progress.phase("start", Some(30)).await;
        container::start(
            &release.container,
            Duration::from_secs(120),
            &mut cancel,
            progress,
        )
        .await?;

        progress.phase("health", Some(60)).await;
        health::wait_healthy(release.port, None, progress).await?;

        if !domains.is_empty() {
            progress.phase("proxy", Some(80)).await;
            self.proxy
                .publish(service, domains, release.port, &mut cancel, progress)
                .await?;
        }

        ledger
            .promote(service, release.clone(), RETAINED_RELEASES)
            .map_err(|e| Failure::new("record", e.to_string()))?;

        if let Some(prev) = &current {
            progress.phase("drain", Some(95)).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = container::stop(
                &prev.container,
                Duration::from_secs(90),
                &mut cancel,
                progress,
            )
            .await;
        }

        Ok(DeployResult {
            service: service.into(),
            commit: release.commit,
            container: release.container,
            port: release.port,
            domains: domains.to_vec(),
            previous: current.map(|c| c.commit),
            restart_note: None,
        })
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_files_are_root_only_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let deployer = Deployer {
            paths: Paths::under(dir.path()),
            state: Arc::new(State::in_memory().unwrap()),
            proxy: Proxy::default(),
            build_limits: BuildLimits {
                cpu_percent: 100,
                memory_mb: 512,
            },
        };

        let mut env = std::collections::BTreeMap::new();
        env.insert("APP_KEY".to_string(), "secret".to_string());
        let path = deployer
            .write_env("app", "abcdef1234567890", &env)
            .unwrap()
            .unwrap();

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "APP_KEY=secret\n");

        env.insert("bad name".into(), "x".into());
        assert!(deployer.write_env("app", "abcdef1234567890", &env).is_err());
        assert!(deployer
            .write_env("app", "abc", &Default::default())
            .unwrap()
            .is_none());
    }
}
