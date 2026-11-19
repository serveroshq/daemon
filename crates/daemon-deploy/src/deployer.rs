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
    pub previous: Option<String>,
    pub restart_note: Option<String>,
}

pub struct Deployer {
    pub paths: Paths,
    pub state: Arc<State>,
    /// The machine's reverse proxy. Behind a lock because a deploy can
    /// move the machine to another one.
    pub proxy: std::sync::RwLock<Proxy>,
    pub build_limits: BuildLimits,
}

impl Deployer {
    /// The reverse proxy in use now.
    pub fn proxy(&self) -> Proxy {
        self.proxy.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_proxy(&self, proxy: Proxy) {
        *self.proxy.write().unwrap_or_else(|e| e.into_inner()) = proxy;
    }

    fn apps_dir(&self) -> PathBuf {
        self.paths.state_dir.join("apps")
    }

    /// Where a compose stack runs from. Compose resolves the stack's relative
    /// paths (config files it bind-mounts) to this folder, and Docker reads
    /// them again on every restart, so it has to outlive the job's workspace.
    fn compose_dir(&self, service: &str) -> PathBuf {
        self.apps_dir().join(git::sanitise(service)).join("compose")
    }

    fn keys_dir(&self) -> PathBuf {
        self.paths.state_dir.join("keys")
    }

    fn env_file(&self, service: &str, commit: &str) -> PathBuf {
        self.apps_dir()
            .join(git::sanitise(service))
            .join(format!("{}.env", &commit[..commit.len().min(12)]))
    }

    pub async fn deploy_key(&self, service: &str, progress: &Progress) -> Result<String, Failure> {
        git::ensure_deploy_key(&self.keys_dir(), service, progress).await
    }

    /// The commit `git_ref` (a branch or tag, or the default branch when
    /// missing) points at in `repo`, asked over the service's deploy key.
    pub async fn resolve_ref(
        &self,
        service: &str,
        repo: &str,
        git_ref: Option<&str>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<git::ResolvedRef, Failure> {
        let (private_key, _) = git::key_paths(&self.keys_dir(), service);
        git::resolve_ref(
            repo,
            git_ref,
            private_key.exists().then_some(private_key.as_path()),
            cancel,
        )
        .await
    }

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
        let slot = slot_for(&service, &commit, previous.as_ref());

        progress.phase("prepare", Some(5)).await;
        let workspace = self.paths.jobs_dir().join(ctx.id.to_string());
        std::fs::create_dir_all(&workspace)
            .map_err(|e| Failure::new("prepare", format!("could not create workspace: {e}")))?;

        let result = self
            .deploy_inner(ctx, spec, &workspace, previous.as_ref(), &slot, &mut cancel)
            .await;

        let _ = std::fs::remove_dir_all(&workspace);

        match result {
            Ok(result) => Ok(result),
            Err(failure) => {
                // The live commit deployed again failed beside it: that
                // release is still serving, so it isn't marked failed.
                let live_again = spec.compose_file.is_none()
                    && previous.as_ref().is_some_and(|p| p.commit == commit);
                if !live_again {
                    let _ = ledger.mark_failed(&service, &commit);
                }
                container::remove(&slot.name, progress).await;
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
        slot: &Slot,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<DeployResult, Failure> {
        let progress = &ctx.progress;
        let service = &spec.service;
        let commit = &spec.commit;
        let step_timeout = ctx.timeout;
        // An app in a subfolder builds from there; a Compose file names
        // its own path, so it builds from the repository's root.
        let base_dir = match (&spec.compose_file, &spec.base_dir) {
            (None, Some(dir)) => Some(base_dir_path(dir)?),
            _ => None,
        };

        // An image already built from these same files (the live commit
        // redeployed for an env change, say) is used as it is.
        let tag = container::image_tag(service, commit);
        let fingerprint = build_fingerprint(spec);
        let built = spec.compose_file.is_none()
            && container::image_label(&tag, container::BUILD_LABEL)
                .await
                .is_some_and(|label| label == fingerprint);

        progress.phase("fetch", Some(15)).await;
        if built {
            progress
                .line(format!(
                    "image for {} is already built with the same files; skipping the build",
                    &commit[..7.min(commit.len())]
                ))
                .await;
        } else if spec.repo.is_empty() {
            if spec.files.is_empty() {
                return Err(
                    Failure::new("fetch", "nothing to deploy: no repository and no files")
                        .with_next_step("Send a repository, or a template's files."),
                );
            }
            progress
                .line("no repository: deploying from the files sent with this job".to_string())
                .await;
        } else {
            let (private_key, _) = git::key_paths(&self.keys_dir(), service);
            git::fetch(
                &spec.repo,
                commit,
                workspace,
                git::Auth {
                    deploy_key: private_key.exists().then_some(private_key.as_path()),
                    token: spec.repo_token.as_ref().map(|t| t.0.as_str()),
                },
                step_timeout,
                cancel,
                progress,
            )
            .await?;
        }
        let context = if built {
            None
        } else {
            let context = build_context(workspace, base_dir, commit, !spec.repo.is_empty())?;
            write_files(&context, &spec.files)?;
            Some(context)
        };

        progress.phase("env", Some(25)).await;
        let env_file = self.write_env(service, commit, &spec.env)?;

        if let Some(compose) = &spec.compose_file {
            progress.phase("build", Some(40)).await;
            let project = format!("serveros-{}", git::sanitise(service));
            let dir = self.compose_dir(service);
            replace_dir(workspace, &dir)?;
            container::compose_up(
                &dir,
                compose,
                &project,
                env_file.as_deref(),
                step_timeout,
                cancel,
                progress,
            )
            .await?;

            let host_port = spec.port.filter(|p| *p > 0);
            if let (Some(port), Some(check)) = (host_port, spec.health.as_ref()) {
                progress.phase("health", Some(70)).await;
                health::wait_healthy(port, Some(check), progress).await?;
            }
            if let (Some(port), false) = (host_port, spec.domains.is_empty()) {
                progress.phase("proxy", Some(80)).await;
                let proxy = self.proxy();
                proxy.ensure_installed(cancel, progress).await?;
                proxy.ensure_import()?;
                proxy
                    .publish(service, &spec.domains, port, spec.https, cancel, progress)
                    .await?;
            }

            progress.phase("verify", Some(90)).await;

            let release = Release {
                commit: commit.clone(),
                image: project.clone(),
                container: project,
                port: spec.port.unwrap_or(0),
                deployed_at: daemon_state::State::now(),
                status: "live".into(),
                http: spec.health.is_some(),
                compose: true,
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

        progress.phase("build", Some(40)).await;
        if let Some(context) = &context {
            container::build(
                context,
                spec.dockerfile.as_deref(),
                &tag,
                &fingerprint,
                &self.build_limits,
                step_timeout,
                cancel,
                progress,
            )
            .await?;
        }

        progress.phase("start", Some(60)).await;
        let name = slot.name.clone();
        let host_port = slot.port;
        if previous.is_some_and(|p| p.commit == *commit) {
            progress
                .line(format!(
                    "{} is live already: starting it again beside itself as {name}, so it keeps serving until the swap",
                    &commit[..7.min(commit.len())]
                ))
                .await;
        }
        let container_port = spec.port.unwrap_or(80);

        // Folders the Dockerfile declares with VOLUME are the app's data:
        // each is a volume every release mounts, so a deploy never starts
        // it over empty. Read the previous release's before it can go.
        let previous_volumes = match previous {
            Some(prev) => container::container_volumes(&prev.container).await,
            None => Default::default(),
        };
        let volumes = container::plan_volumes(
            service,
            &container::image_volumes(&tag).await?,
            &previous_volumes,
        );
        for (volume, path) in &volumes {
            container::ensure_volume(volume, service).await?;
            progress
                .line(format!("{path} is kept in volume {volume} between deploys"))
                .await;
        }

        container::remove(&name, progress).await;
        container::run(
            &name,
            &tag,
            service,
            host_port,
            container_port,
            env_file.as_deref(),
            &volumes,
            Duration::from_secs(120),
            cancel,
            progress,
        )
        .await?;

        progress.phase("health", Some(70)).await;
        Self::check(&name, host_port, spec.health.as_ref(), progress).await?;

        if !spec.domains.is_empty() {
            progress.phase("proxy", Some(80)).await;
            let proxy = self.proxy();
            proxy.ensure_installed(cancel, progress).await?;
            proxy.ensure_import()?;
            proxy
                .publish(
                    service,
                    &spec.domains,
                    host_port,
                    spec.https,
                    cancel,
                    progress,
                )
                .await?;
        }

        progress.phase("verify", Some(90)).await;
        Self::check(&name, host_port, spec.health.as_ref(), progress).await?;

        let ledger = ReleaseLedger::new(&self.state);
        let release = Release {
            commit: commit.clone(),
            image: tag,
            container: name.clone(),
            port: host_port,
            deployed_at: daemon_state::State::now(),
            status: "live".into(),
            http: spec.health.is_some(),
            compose: false,
        };
        let evicted = ledger
            .promote(service, release, RETAINED_RELEASES)
            .map_err(|e| Failure::new("record", e.to_string()))?;

        if let Some(prev) = to_drain(previous, &name) {
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
            // The same commit's other container: the ledger now holds
            // the new one for this commit, so the old one is let go.
            if prev.commit == *commit {
                container::remove(&prev.container, progress).await;
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

    /// A release that answers HTTP is asked for its health page. One that
    /// doesn't, like a chat bot or a worker, passes if its container is
    /// still running a few seconds after starting. One that fails carries
    /// the container's last log lines, which usually say why (it crashed on
    /// start, or listens on another port), since the container is removed.
    async fn check(
        container: &str,
        port: u16,
        health: Option<&daemon_protocol::HealthCheck>,
        progress: &daemon_jobs::Progress,
    ) -> Result<(), Failure> {
        let result = match health {
            Some(check) => health::wait_healthy(port, Some(check), progress).await,
            None => health::wait_running(container, progress).await,
        };
        match result {
            Err(failure) if failure.output_tail.is_empty() => {
                let logs = container::logs_tail(container, 40, progress).await;
                Err(if logs.is_empty() {
                    failure
                } else {
                    failure.with_output(logs)
                })
            }
            other => other,
        }
    }

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
        refuse_compose(current.as_ref())?;
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
        refuse_compose(Some(&release))?;

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
        if release.http {
            health::wait_healthy(release.port, None, progress).await?;
        } else {
            health::wait_running(&release.container, progress).await?;
        }

        if !domains.is_empty() {
            progress.phase("proxy", Some(80)).await;
            self.proxy()
                .publish(service, domains, release.port, None, &mut cancel, progress)
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

/// A Compose release is recorded under its project's name, which isn't a
/// container, and Compose recreates the stack in place, so there's nothing
/// stopped to start again. Checked before anything is touched.
fn refuse_compose(release: Option<&Release>) -> Result<(), Failure> {
    match release {
        Some(release) if release.is_compose() => Err(Failure::new(
            "rollback",
            "Compose apps roll back by deploying the earlier commit again",
        )
        .with_next_step("Deploy the commit you want to go back to.")),
        _ => Ok(()),
    }
}

/// Where a release runs: its container and the local port it listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    name: String,
    port: u16,
}

/// A commit runs as a container named for it, on a port of its own. When
/// it's the commit that's live (an env change redeploys the same commit),
/// that name and port are taken, so it starts under its other name and
/// port beside the live one, which serves until the new one is healthy and
/// the proxy has moved over, as on any deploy. The next time, it goes back
/// to the first.
fn slot_for(service: &str, commit: &str, previous: Option<&Release>) -> Slot {
    let first = Slot {
        name: container::container_name(service, commit),
        port: releases::port_for(service, commit),
    };
    let second = Slot {
        name: container::alternate_container_name(service, commit),
        port: releases::alternate_port(service, commit),
    };
    let Some(prev) = previous else {
        return first;
    };
    let taken = |slot: &Slot| prev.container == slot.name || prev.port == slot.port;
    if !taken(&first) {
        first
    } else if !taken(&second) || prev.container == first.name {
        second
    } else {
        first
    }
}

/// The release to stop once the new one is live: the one before it, unless
/// it has the new one's name, in which case the new one already replaced
/// it and stopping it would take the app down.
fn to_drain<'a>(previous: Option<&'a Release>, container: &str) -> Option<&'a Release> {
    previous.filter(|prev| prev.container != container)
}

const MAX_JOB_FILES: usize = 64;
const MAX_JOB_FILE_BYTES: usize = 256 * 1024;

/// Moves a job's workspace to `dir`, replacing what an earlier deploy left there.
fn replace_dir(workspace: &Path, dir: &Path) -> Result<(), Failure> {
    let fail = |e: std::io::Error| {
        Failure::new("prepare", format!("could not keep the deploy's files: {e}"))
    };
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(fail)?;
    }
    std::fs::create_dir_all(dir.parent().unwrap()).map_err(fail)?;
    std::fs::rename(workspace, dir).map_err(fail)
}

/// What an app's image is built from, as a hex sha256: the repository and
/// commit, the Dockerfile, the job's files and the app's folder. Each part
/// is written with its length first, so no two sets of inputs run together
/// into the same bytes.
fn build_fingerprint(spec: &DeploySpec) -> String {
    use sha2::{Digest, Sha256};

    fn field(hash: &mut Sha256, value: &str) {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    fn optional(hash: &mut Sha256, value: Option<&str>) {
        match value {
            Some(value) => {
                hash.update([1]);
                field(hash, value);
            }
            None => hash.update([0]),
        }
    }

    let mut hash = Sha256::new();
    field(&mut hash, "serveros.build/1");
    field(&mut hash, &spec.repo);
    field(&mut hash, &spec.commit);
    optional(&mut hash, spec.dockerfile.as_deref());
    hash.update((spec.files.len() as u64).to_le_bytes());
    for (name, content) in &spec.files {
        field(&mut hash, name);
        field(&mut hash, content);
    }
    optional(&mut hash, spec.base_dir.as_deref());
    hex::encode(hash.finalize())
}

const MAX_BASE_DIR_LEN: usize = 256;

/// The app's folder in its repository, as a path that can only lead inside
/// it: relative, and without `..` or `.` parts.
fn base_dir_path(base_dir: &str) -> Result<&Path, Failure> {
    use std::path::Component;

    let path = Path::new(base_dir);
    let confined = !base_dir.is_empty()
        && base_dir.len() <= MAX_BASE_DIR_LEN
        && path.components().all(|c| matches!(c, Component::Normal(_)));
    if confined {
        Ok(path)
    } else {
        Err(Failure::new(
            "prepare",
            format!("{base_dir:?} must be a folder inside the repository, like apps/web"),
        )
        .with_next_step("Set the app's folder to a path relative to the repository's root."))
    }
}

/// Where the image is built from and the job's files go: the repository,
/// or the app's folder in it. The folder has to be in the repository at
/// this commit, and a link in the repository can't point it elsewhere on
/// the machine. Without a repository the job's files are the app, so the
/// folder is made for them.
fn build_context(
    workspace: &Path,
    base_dir: Option<&Path>,
    commit: &str,
    fetched: bool,
) -> Result<PathBuf, Failure> {
    let Some(base_dir) = base_dir else {
        return Ok(workspace.to_path_buf());
    };
    let context = workspace.join(base_dir);
    if !fetched {
        std::fs::create_dir_all(&context).map_err(|e| {
            Failure::new(
                "prepare",
                format!("could not create {}: {e}", base_dir.display()),
            )
        })?;
        return Ok(context);
    }

    let missing = || {
        Failure::new(
            "fetch",
            format!(
                "{} isn't in the repository at {}",
                base_dir.display(),
                &commit[..7.min(commit.len())]
            ),
        )
        .with_next_step("Check the app's folder, or push the commit that adds it.")
    };
    let root = workspace
        .canonicalize()
        .map_err(|e| Failure::new("prepare", format!("could not read the workspace: {e}")))?;
    let real = context.canonicalize().map_err(|_| missing())?;
    if !real.starts_with(&root) {
        return Err(Failure::new(
            "fetch",
            format!("{} leads outside the repository", base_dir.display()),
        ));
    }
    if !real.is_dir() {
        return Err(missing());
    }
    Ok(real)
}

fn write_files(
    workspace: &Path,
    files: &std::collections::BTreeMap<String, String>,
) -> Result<(), Failure> {
    use std::path::Component;

    if files.len() > MAX_JOB_FILES {
        return Err(Failure::new(
            "files",
            format!(
                "too many files ({}, the limit is {MAX_JOB_FILES})",
                files.len()
            ),
        ));
    }

    for (name, content) in files {
        let relative = Path::new(name);
        let confined = !name.is_empty()
            && relative
                .components()
                .all(|c| matches!(c, Component::Normal(_)));
        if !confined {
            return Err(Failure::new(
                "files",
                format!("{name:?} must be a relative path inside the workspace"),
            ));
        }
        if content.len() > MAX_JOB_FILE_BYTES {
            return Err(Failure::new(
                "files",
                format!("{name} is larger than {MAX_JOB_FILE_BYTES} bytes"),
            ));
        }

        let path = workspace.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Failure::new(
                    "files",
                    format!("could not create {}: {e}", parent.display()),
                )
            })?;
        }
        std::fs::write(&path, content)
            .map_err(|e| Failure::new("files", format!("could not write {name}: {e}")))?;
    }

    Ok(())
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
    fn job_files_are_written_inside_the_workspace_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = std::collections::BTreeMap::new();
        files.insert("compose.yaml".to_string(), "services: {}\n".to_string());
        files.insert(
            ".serveros/Dockerfile".to_string(),
            "FROM scratch\n".to_string(),
        );

        write_files(dir.path(), &files).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("compose.yaml")).unwrap(),
            "services: {}\n"
        );
        assert!(dir.path().join(".serveros/Dockerfile").is_file());

        for bad in ["../escape", "/etc/passwd", "a/../../b", "./x", ""] {
            let mut files = std::collections::BTreeMap::new();
            files.insert(bad.to_string(), "x".to_string());
            assert!(
                write_files(dir.path(), &files).is_err(),
                "{bad:?} was accepted"
            );
        }

        let mut big = std::collections::BTreeMap::new();
        big.insert("big".to_string(), "x".repeat(MAX_JOB_FILE_BYTES + 1));
        assert!(write_files(dir.path(), &big).is_err());
    }

    #[test]
    fn build_fingerprints_are_stable_and_follow_every_input() {
        let spec: DeploySpec = serde_json::from_value(serde_json::json!({
            "service": "web",
            "repo": "https://github.com/acme/shop.git",
            "commit": "a".repeat(40),
            "files": {".serveros/Dockerfile": "FROM node:22\n"},
        }))
        .unwrap();
        let base = build_fingerprint(&spec);
        assert_eq!(base, build_fingerprint(&spec.clone()));
        assert_eq!(base.len(), 64);

        // What the app runs with, not what it's built from.
        let mut same = spec.clone();
        same.env.insert("APP_KEY".into(), "x".into());
        same.domains.push("shop.example.com".into());
        same.port = Some(3000);
        assert_eq!(build_fingerprint(&same), base);

        type Change = Box<dyn Fn(&mut DeploySpec)>;
        let changes: Vec<Change> = vec![
            Box::new(|s| s.repo.push('x')),
            Box::new(|s| s.commit = "b".repeat(40)),
            Box::new(|s| s.dockerfile = Some("Dockerfile".into())),
            Box::new(|s| s.dockerfile = Some(String::new())),
            Box::new(|s| {
                s.files
                    .insert(".serveros/Dockerfile".into(), "FROM node:20\n".into());
            }),
            Box::new(|s| {
                s.files.insert("extra".into(), String::new());
            }),
            Box::new(|s| s.files.clear()),
            Box::new(|s| s.base_dir = Some("apps/web".into())),
            Box::new(|s| s.base_dir = Some(String::new())),
        ];
        let mut seen = std::collections::BTreeSet::from([base.clone()]);
        for change in changes {
            let mut changed = spec.clone();
            change(&mut changed);
            assert!(seen.insert(build_fingerprint(&changed)), "{changed:?}");
        }

        // A file's name and content don't run together.
        let mut a = spec.clone();
        a.files = [("ab".to_string(), "c".to_string())].into();
        let mut b = spec.clone();
        b.files = [("a".to_string(), "bc".to_string())].into();
        assert_ne!(build_fingerprint(&a), build_fingerprint(&b));
    }

    #[test]
    fn app_folders_must_stay_inside_the_repository() {
        for good in ["apps/web", "web", "apps/web/", "services/api-v2"] {
            assert!(base_dir_path(good).is_ok(), "{good:?} was refused");
        }
        let long = "a/".repeat(MAX_BASE_DIR_LEN);
        for bad in [
            "",
            "/apps/web",
            "../web",
            "apps/../../web",
            "./web",
            ".",
            long.as_str(),
        ] {
            let failure = base_dir_path(bad).unwrap_err();
            assert!(failure.next_step.is_some(), "{bad:?}");
        }
    }

    #[test]
    fn an_apps_folder_is_its_build_context_and_gets_the_job_files() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("apps/web")).unwrap();
        let root = repo.path().canonicalize().unwrap();

        assert_eq!(
            build_context(repo.path(), None, "abcdef1", true).unwrap(),
            repo.path()
        );

        let context =
            build_context(repo.path(), Some(Path::new("apps/web")), "abcdef1", true).unwrap();
        assert_eq!(context, root.join("apps/web"));
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            ".serveros/Dockerfile".to_string(),
            "FROM scratch\n".to_string(),
        );
        write_files(&context, &files).unwrap();
        assert!(root.join("apps/web/.serveros/Dockerfile").is_file());
        assert!(!root.join(".serveros").exists());

        let missing = build_context(repo.path(), Some(Path::new("apps/api")), "abcdef1234", true)
            .unwrap_err();
        assert_eq!(
            missing.message,
            "apps/api isn't in the repository at abcdef1"
        );

        std::fs::write(repo.path().join("README"), "").unwrap();
        assert!(build_context(repo.path(), Some(Path::new("README")), "abcdef1", true).is_err());

        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), repo.path().join("link")).unwrap();
        let outside =
            build_context(repo.path(), Some(Path::new("link")), "abcdef1", true).unwrap_err();
        assert!(outside.message.contains("outside the repository"));

        // No repository: the job's files are the app, so its folder is made.
        let files_only = tempfile::tempdir().unwrap();
        let context = build_context(
            files_only.path(),
            Some(Path::new("apps/web")),
            "abcdef1",
            false,
        )
        .unwrap();
        assert!(context.is_dir());
    }

    #[test]
    fn redeploying_the_live_commit_does_not_stop_it() {
        let release = |container: &str| Release {
            commit: "a".repeat(40),
            image: "serveros/shop:aaaaaaaaaaaa".into(),
            container: container.into(),
            port: 20000,
            deployed_at: 0,
            status: "live".into(),
            http: true,
            compose: false,
        };
        let same = release("serveros-shop-aaaaaaaaaaaa");
        let older = release("serveros-shop-bbbbbbbbbbbb");

        assert!(to_drain(Some(&same), "serveros-shop-aaaaaaaaaaaa").is_none());
        // The live commit deployed again runs beside it, so the old one
        // is drained like any other.
        assert_eq!(
            to_drain(Some(&same), "serveros-shop-aaaaaaaaaaaa-b").map(|r| r.container.as_str()),
            Some("serveros-shop-aaaaaaaaaaaa")
        );
        assert_eq!(
            to_drain(Some(&older), "serveros-shop-aaaaaaaaaaaa").map(|r| r.container.as_str()),
            Some("serveros-shop-bbbbbbbbbbbb")
        );
        assert!(to_drain(None, "serveros-shop-aaaaaaaaaaaa").is_none());
    }

    #[test]
    fn the_live_commit_deployed_again_starts_beside_itself() {
        let commit = "a".repeat(40);
        let release = |slot: &Slot, commit: &str| Release {
            commit: commit.into(),
            image: container::image_tag("shop", commit),
            container: slot.name.clone(),
            port: slot.port,
            deployed_at: 0,
            status: "live".into(),
            http: true,
            compose: false,
        };

        let first = slot_for("shop", &commit, None);
        assert_eq!(first.name, "serveros-shop-aaaaaaaaaaaa");
        assert_eq!(first.port, releases::port_for("shop", &commit));

        // Another commit live: the usual name and port.
        let other = release(&slot_for("shop", &"b".repeat(40), None), &"b".repeat(40));
        assert_eq!(slot_for("shop", &commit, Some(&other)), first);

        // Itself live: the other slot, then back again.
        let second = slot_for("shop", &commit, Some(&release(&first, &commit)));
        assert_eq!(second.name, "serveros-shop-aaaaaaaaaaaa-b");
        assert_ne!(second.port, first.port);
        assert!((20_000..30_000).contains(&second.port));
        assert_eq!(
            slot_for("shop", &commit, Some(&release(&second, &commit))),
            first
        );
    }

    #[test]
    fn compose_releases_are_not_rolled_back_by_starting_a_container() {
        let release = |container: &str, image: &str, compose: bool| Release {
            commit: "a".repeat(40),
            image: image.into(),
            container: container.into(),
            port: 0,
            deployed_at: 0,
            status: "standby".into(),
            http: false,
            compose,
        };

        // Recorded before the flag was kept, and after.
        for compose in [
            release("serveros-shop", "serveros-shop", false),
            release("serveros-shop", "serveros-shop", true),
        ] {
            let failure = refuse_compose(Some(&compose)).unwrap_err();
            assert_eq!(failure.phase, "rollback");
            assert!(failure.message.contains("deploying the earlier commit"));
            assert!(failure.next_step.is_some());
        }

        let container = release(
            "serveros-shop-aaaaaaaaaaaa",
            "serveros/shop:aaaaaaaaaaaa",
            false,
        );
        assert!(refuse_compose(Some(&container)).is_ok());
        assert!(refuse_compose(None).is_ok());
    }

    #[test]
    fn compose_files_outlive_the_job_and_replace_the_last_deploy() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("apps/shop/compose");
        let first = root.path().join("jobs/1");
        std::fs::create_dir_all(first.join("conf")).unwrap();
        std::fs::write(first.join("conf/app.yml"), "one").unwrap();
        std::fs::write(first.join("old.txt"), "gone next time").unwrap();
        replace_dir(&first, &dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("conf/app.yml")).unwrap(),
            "one"
        );
        assert!(!first.exists());

        let second = root.path().join("jobs/2");
        std::fs::create_dir_all(second.join("conf")).unwrap();
        std::fs::write(second.join("conf/app.yml"), "two").unwrap();
        replace_dir(&second, &dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("conf/app.yml")).unwrap(),
            "two"
        );
        assert!(!dir.join("old.txt").exists());
    }

    #[test]
    fn env_files_are_root_only_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let deployer = Deployer {
            paths: Paths::under(dir.path()),
            state: Arc::new(State::in_memory().unwrap()),
            proxy: std::sync::RwLock::new(Proxy::default()),
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
