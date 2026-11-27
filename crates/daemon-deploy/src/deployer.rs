use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime};

use daemon_core::Paths;
use daemon_jobs::{Failure, JobContext, Progress};
use daemon_protocol::{DeploySpec, HealthCheck, ResourceLimits};
use daemon_state::State;
use serde::Serialize;
use tokio::sync::watch;

use crate::container::{self, BuildLimits, RunSpec};
use crate::health::Target;
use crate::proxy::Proxy;
use crate::registry::DockerConfig;
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
    /// The CPU and memory limits the container runs with, when it has any.
    /// Missing from older daemons, so the panel knows not to claim them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceLimits>,
    /// The port the app listens on in its container: the one it was given,
    /// the image's EXPOSE, or 80. Missing for Compose apps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_port: Option<u16>,
    /// How the release's image was made: dockerfile, railpack, image or
    /// compose. Missing from older daemons, and on a rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_method: Option<String>,
}

pub struct Deployer {
    pub paths: Paths,
    pub state: Arc<State>,
    /// The machine's reverse proxy. Behind a lock because a deploy can
    /// move the machine to another one.
    pub proxy: std::sync::RwLock<Proxy>,
    pub build_limits: BuildLimits,
}

/// How long a deploy gives itself: the job's time less a fifth of it, at
/// most two minutes, so it stops on its own with a clear failure and has
/// time to clean up before the job runner gives up on it.
pub fn deploy_budget(job_timeout: Duration) -> Duration {
    job_timeout.saturating_sub((job_timeout / 5).min(Duration::from_secs(120)))
}

/// The time left before `until`.
fn left(until: Instant) -> Duration {
    until.saturating_duration_since(Instant::now())
}

/// What a deploy has changed so far, so one that fails (or runs out of
/// time partway) can put things back. Shared with the steps rather than
/// returned, since a step that's cut off returns nothing.
#[derive(Default)]
struct Touched {
    /// The new release's container was made, or one of its name removed.
    container: AtomicBool,
    /// The proxy was pointed at the new release.
    proxy: AtomicBool,
    /// A Compose app's files were swapped for the new ones.
    compose: AtomicBool,
    /// The new release is live and recorded: from here it isn't undone.
    live: Mutex<Option<DeployResult>>,
}

impl Touched {
    fn set(flag: &AtomicBool) {
        flag.store(true, Ordering::SeqCst);
    }

    fn get(flag: &AtomicBool) -> bool {
        flag.load(Ordering::SeqCst)
    }

    fn live(&self) -> Option<DeployResult> {
        self.live.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Cleans up after a deploy whose future was dropped before it could do
/// so itself (the job runner's own timeout, or a panic): the workspace,
/// the new container, and the release's record. A deploy that gets to
/// clean up disarms it.
struct Leftovers {
    state: Arc<State>,
    service: String,
    commit: String,
    workspace: PathBuf,
    /// The new release's container, removed if it was made.
    container: String,
    touched: Arc<Touched>,
    may_mark_failed: bool,
    armed: bool,
}

impl Drop for Leftovers {
    fn drop(&mut self) {
        if !self.armed || self.touched.live().is_some() {
            return;
        }
        let _ = std::fs::remove_dir_all(&self.workspace);
        if self.may_mark_failed && Touched::get(&self.touched.container) {
            let _ = ReleaseLedger::new(&self.state).mark_failed(&self.service, &self.commit);
        }
        let mut containers = vec![container::release_container_name(&self.container)];
        if Touched::get(&self.touched.container) {
            containers.push(self.container.clone());
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for name in containers {
                    let _ = tokio::process::Command::new("docker")
                        .args(["rm", "-f", &name])
                        .kill_on_drop(true)
                        .output()
                        .await;
                }
            });
        }
    }
}

static APP_LOCKS: LazyLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Mutex::default);

/// One deploy or rollback per app at a time: two at once would start
/// containers of the same name and remove each other's. One that has to
/// wait says so, and waits no longer than it has.
async fn lock_app(
    service: &str,
    until: Instant,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<tokio::sync::OwnedMutexGuard<()>, Failure> {
    let lock = Arc::clone(
        APP_LOCKS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(service.to_string())
            .or_default(),
    );
    if let Ok(guard) = Arc::clone(&lock).try_lock_owned() {
        return Ok(guard);
    }
    progress
        .line(format!(
            "another deploy or rollback of {service} is running: waiting for it to finish"
        ))
        .await;
    let waited = Instant::now();
    tokio::select! {
        guard = lock.lock_owned() => {
            progress
                .line(format!(
                    "the one before finished after {}s; carrying on",
                    waited.elapsed().as_secs()
                ))
                .await;
            Ok(guard)
        }
        _ = tokio::time::sleep_until(until.into()) => Err(Failure::new(
            "waiting",
            format!("another deploy of {service} was still running, so this one never started"),
        )
        .with_next_step("Wait for it to finish, or cancel it, then deploy again.")),
        _ = cancelled(cancel) => Err(Failure::new("cancelled", "deploy cancelled while waiting")),
    }
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// A cancel that never comes, for putting things back after a deploy that
/// was itself cancelled.
fn never() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

/// The check a Compose app's published port gets when it has none of its
/// own: that it answers at all.
fn compose_check() -> HealthCheck {
    HealthCheck {
        path: "/".into(),
        expected_status: 0,
        timeout_secs: 10,
        retries: 5,
        start_period_secs: 30,
        interval_secs: Some(3),
    }
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

    fn app_dir(&self, service: &str) -> PathBuf {
        self.apps_dir().join(git::sanitise(service))
    }

    /// Where a compose stack runs from. Compose resolves the stack's relative
    /// paths (config files it bind-mounts) to this folder, and Docker reads
    /// them again on every restart, so it has to outlive the job's workspace.
    fn compose_dir(&self, service: &str) -> PathBuf {
        self.app_dir(service).join("compose")
    }

    /// The live stack's files and settings while a deploy replaces them,
    /// to go back to if it fails.
    fn compose_backup(&self, service: &str) -> (PathBuf, PathBuf) {
        let dir = self.app_dir(service);
        (
            dir.join("compose.previous"),
            dir.join("compose.previous.env"),
        )
    }

    fn keys_dir(&self) -> PathBuf {
        self.paths.state_dir.join("keys")
    }

    fn env_file(&self, service: &str, commit: &str) -> PathBuf {
        self.app_dir(service)
            .join(format!("{}.env", &commit[..commit.len().min(12)]))
    }

    pub async fn deploy_key(&self, service: &str, progress: &Progress) -> Result<String, Failure> {
        git::ensure_deploy_key(&self.keys_dir(), service, progress).await
    }

    /// The commit `git_ref` (a branch or tag, or the default branch when
    /// missing) points at in `repo`, asked over the service's deploy key,
    /// or with `token` for a private HTTPS repository.
    pub async fn resolve_ref(
        &self,
        service: &str,
        repo: &str,
        git_ref: Option<&str>,
        token: Option<&str>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<git::ResolvedRef, Failure> {
        let (private_key, _) = git::key_paths(&self.keys_dir(), service);
        git::resolve_ref(
            repo,
            git_ref,
            git::Auth {
                deploy_key: private_key.exists().then_some(private_key.as_path()),
                token,
            },
            cancel,
        )
        .await
    }

    /// A repository's files at a commit (the `repo_inspect` job), read in
    /// a folder of the job's own that's removed after. An SSH address uses
    /// `service`'s deploy key when it has one.
    #[allow(clippy::too_many_arguments)]
    pub async fn inspect_repo(
        &self,
        job: &str,
        service: Option<&str>,
        repo: &str,
        git_ref: Option<&str>,
        base_dir: Option<&str>,
        token: Option<&str>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<crate::inspect::RepoFiles, Failure> {
        let key = service
            .map(|s| git::key_paths(&self.keys_dir(), s).0)
            .filter(|k| k.exists());
        crate::inspect::inspect(
            &self.paths.jobs_dir().join(job),
            crate::inspect::Request {
                repo,
                git_ref,
                base_dir,
                auth: git::Auth {
                    deploy_key: key.as_deref(),
                    token,
                },
            },
            cancel,
        )
        .await
    }

    /// The key in state.db holding the last Railpack build of an app, as
    /// `<image tag> <fingerprint>`: Railpack's frontend doesn't take image
    /// labels, so this is how a redeploy of the same files knows it can use
    /// the image as it is.
    fn railpack_key(service: &str) -> String {
        format!("deploy.{}.railpack_build", git::sanitise(service))
    }

    async fn railpack_built(&self, service: &str, tag: &str, fingerprint: &str) -> bool {
        let remembered = self
            .state
            .kv_get(&Self::railpack_key(service))
            .ok()
            .flatten();
        remembered.as_deref() == Some(format!("{tag} {fingerprint}").as_str())
            && container::image_exists(tag).await
    }

    fn remember_railpack_build(&self, service: &str, tag: &str, fingerprint: &str) {
        let _ = self.state.kv_set(
            &Self::railpack_key(service),
            &format!("{tag} {fingerprint}"),
        );
    }

    /// Writes a release's env file, root-only: every setting in Compose's
    /// format for a Compose app (for `${NAME}` in its file), or for a
    /// container only the few settings docker can't be handed by name.
    /// Nothing to write writes nothing.
    fn write_env(
        &self,
        service: &str,
        commit: &str,
        body: &str,
    ) -> Result<Option<PathBuf>, Failure> {
        if body.is_empty() {
            return Ok(None);
        }

        let path = self.env_file(service, commit);
        std::fs::create_dir_all(path.parent().unwrap())
            .map_err(|e| Failure::new("env", e.to_string()))?;

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
        let budget = deploy_budget(ctx.timeout);
        let until = Instant::now() + budget;
        // About when the job runner gives up: putting things back has to be
        // done by then.
        let job_ends = until + (ctx.timeout - budget);
        let service = spec.service.clone();
        let commit = spec.commit.clone();

        let _lock = lock_app(&service, until, &mut cancel, progress).await?;

        let ledger = ReleaseLedger::new(&self.state);
        let previous = ledger.current(&service);
        let slot = slot_for(&service, &commit, previous.as_ref());
        // The live commit deployed again runs beside it: that release is
        // still serving if this one fails, so it isn't marked failed.
        let live_again =
            spec.compose_file.is_none() && previous.as_ref().is_some_and(|p| p.commit == commit);

        progress.phase("prepare", Some(5)).await;
        let workspace = self.paths.jobs_dir().join(ctx.id.to_string());
        std::fs::create_dir_all(&workspace)
            .map_err(|e| Failure::new("prepare", format!("could not create workspace: {e}")))?;
        let touched = Arc::new(Touched::default());
        let mut leftovers = Leftovers {
            state: Arc::clone(&self.state),
            service: service.clone(),
            commit: commit.clone(),
            workspace: workspace.clone(),
            container: slot.name.clone(),
            touched: Arc::clone(&touched),
            may_mark_failed: !live_again,
            armed: true,
        };

        // Outside the workspace, which is the build context: a Dockerfile's
        // COPY . must never be able to pick the logins up.
        let docker_config = if spec.registries.is_empty() {
            None
        } else {
            let config = match DockerConfig::write(
                &self.paths.run_dir,
                &ctx.id.to_string(),
                &spec.registries,
            ) {
                Ok(config) => config,
                Err(failure) => {
                    let _ = std::fs::remove_dir_all(&workspace);
                    leftovers.armed = false;
                    return Err(failure);
                }
            };
            let hosts: Vec<&str> = spec.registries.iter().map(|r| r.host.as_str()).collect();
            progress
                .line(format!(
                    "pulling with the registry logins for {} (for this deploy only)",
                    hosts.join(", ")
                ))
                .await;
            Some(config)
        };
        let docker_env: Vec<(&str, &str)> = docker_config.iter().map(DockerConfig::env).collect();

        let inner = self.deploy_inner(
            ctx,
            spec,
            &workspace,
            previous.as_ref(),
            &slot,
            &docker_env,
            until,
            &touched,
            &mut cancel,
        );
        let result = match tokio::time::timeout_at(until.into(), inner).await {
            Ok(result) => result,
            // Live and recorded before the time ran out: what was cut off
            // was only the tidying after it.
            Err(_) if touched.live().is_some() => {
                progress
                    .line("the deploy went through, but ran out of time tidying up after it")
                    .await;
                Ok(touched.live().unwrap())
            }
            Err(_) => Err(Failure::new(
                "timeout",
                format!(
                    "the deploy didn't finish within {}, so it stopped and put things back",
                    minutes(budget)
                ),
            )
            .with_output(self.log_tail(ctx.id, 40))
            .with_next_step(
                "The log shows the step that was slow. If the build just takes long, give deploys a longer timeout.",
            )),
        };

        let result = match result {
            Ok(result) => Ok(result),
            Err(failure) => {
                let time = left(job_ends).saturating_sub(Duration::from_secs(15));
                self.undo(
                    spec,
                    previous.as_ref(),
                    &slot,
                    &touched,
                    &docker_env,
                    time,
                    progress,
                )
                .await;
                if !live_again && Touched::get(&touched.container) {
                    let _ = ledger.mark_failed(&service, &commit);
                }
                Err(failure)
            }
        };

        drop(docker_config);
        let _ = std::fs::remove_dir_all(&workspace);
        leftovers.armed = false;
        result
    }

    /// The last lines of a job's log, as state.db keeps it.
    fn log_tail(&self, job: uuid::Uuid, lines: usize) -> Vec<String> {
        let log = self
            .state
            .job(job)
            .ok()
            .flatten()
            .map(|record| record.log)
            .unwrap_or_default();
        let all: Vec<&str> = log.lines().collect();
        all[all.len().saturating_sub(lines)..]
            .iter()
            .map(|l| l.to_string())
            .collect()
    }

    /// Puts back what a failed deploy changed, then says truthfully what's
    /// serving the app now.
    #[allow(clippy::too_many_arguments)]
    async fn undo(
        &self,
        spec: &DeploySpec,
        previous: Option<&Release>,
        slot: &Slot,
        touched: &Touched,
        docker_env: &[(&str, &str)],
        time: Duration,
        progress: &Progress,
    ) {
        let service = &spec.service;
        // Its own cancel: a cancelled deploy is still put back.
        let (_tx, mut cancel) = never();
        container::remove(&container::release_container_name(&slot.name), progress).await;
        if Touched::get(&touched.container) {
            container::remove(&slot.name, progress).await;
        }

        if Touched::get(&touched.compose) {
            self.restore_compose(spec, previous, docker_env, time, progress)
                .await;
            return;
        }

        let mut proxy_note = None;
        if Touched::get(&touched.proxy) {
            proxy_note = Some(
                self.point_proxy_back(service, &spec.domains, previous, &mut cancel, progress)
                    .await,
            );
        }

        match previous {
            Some(prev) => {
                let short = &prev.commit[..7.min(prev.commit.len())];
                let running = if prev.is_compose() {
                    compose_running(&prev.container).await
                } else {
                    matches!(container::state(&prev.container).await, Ok((status, _)) if status == "running")
                };
                let line = match (running, proxy_note) {
                    (true, None | Some(Ok(()))) => format!("{service} is still live on release {short}"),
                    (true, Some(Err(e))) => format!(
                        "release {short} is still running, but the proxy couldn't be pointed back at it ({e}), so the site may be down"
                    ),
                    (false, _) => format!(
                        "release {short} isn't running either, so {service} is down until a deploy works"
                    ),
                };
                progress.line(line).await;
            }
            None => {
                let line = match proxy_note {
                    Some(Ok(())) => format!(
                        "{service} has no earlier release to go back to, so its site was taken down"
                    ),
                    Some(Err(e)) => format!(
                        "{service} has no earlier release, and its site couldn't be taken down ({e})"
                    ),
                    None => format!("{service} has no earlier release to go back to"),
                };
                progress.line(line).await;
            }
        }
    }

    /// Points the proxy back at the release that was live, or takes the
    /// app's site down when there was none.
    async fn point_proxy_back(
        &self,
        service: &str,
        domains: &[String],
        previous: Option<&Release>,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), String> {
        let proxy = self.proxy();
        let result = match previous.filter(|p| !p.is_compose()) {
            Some(prev) => {
                progress
                    .line(format!(
                        "pointing the proxy back at release {}",
                        &prev.commit[..7.min(prev.commit.len())]
                    ))
                    .await;
                proxy
                    .publish(service, domains, prev.port, None, cancel, progress)
                    .await
                    .map(|_| ())
            }
            None => proxy.unpublish(service, cancel, progress).await,
        };
        result.map_err(|f| f.message)
    }

    /// Moves a Compose app's live files aside before the new ones go in,
    /// with its settings, so a deploy that fails can put them back.
    fn keep_compose(&self, service: &str, previous: Option<&Release>) -> Result<(), Failure> {
        let fail = |e: std::io::Error| {
            Failure::new("prepare", format!("could not keep the live files: {e}"))
        };
        let dir = self.compose_dir(service);
        let (files, env) = self.compose_backup(service);
        if files.exists() {
            std::fs::remove_dir_all(&files).map_err(fail)?;
        }
        let _ = std::fs::remove_file(&env);
        if dir.exists() {
            std::fs::rename(&dir, &files).map_err(fail)?;
        }
        if let Some(prev) = previous.filter(|p| p.is_compose()) {
            if let Ok(bytes) = std::fs::read(self.env_file(service, &prev.commit)) {
                write_private(&env, &bytes).map_err(fail)?;
            }
        }
        Ok(())
    }

    fn drop_compose_backup(&self, service: &str) {
        let (files, env) = self.compose_backup(service);
        let _ = std::fs::remove_dir_all(files);
        let _ = std::fs::remove_file(env);
    }

    /// After a Compose deploy failed: the previous files and settings back
    /// in place, and the stack brought up from them again.
    async fn restore_compose(
        &self,
        spec: &DeploySpec,
        previous: Option<&Release>,
        docker_env: &[(&str, &str)],
        time: Duration,
        progress: &Progress,
    ) {
        let service = &spec.service;
        let dir = self.compose_dir(service);
        let (files, env) = self.compose_backup(service);
        let Some(prev) = previous.filter(|p| p.is_compose() && files.exists()) else {
            self.drop_compose_backup(service);
            let line = match previous {
                Some(prev) if !prev.is_compose() => {
                    let short = &prev.commit[..7.min(prev.commit.len())];
                    match container::state(&prev.container).await {
                        Ok((status, _)) if status == "running" => {
                            format!("{service} is still live on release {short}")
                        }
                        _ => format!("release {short} isn't running either, so {service} is down until a deploy works"),
                    }
                }
                _ => format!("{service} has no earlier release to go back to"),
            };
            progress.line(line).await;
            return;
        };
        let short = &prev.commit[..7.min(prev.commit.len())];
        progress
            .line(format!("putting back the Compose files of release {short}"))
            .await;

        let restored = (|| -> std::io::Result<Option<PathBuf>> {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)?;
            }
            std::fs::rename(&files, &dir)?;
            match std::fs::read(&env) {
                Ok(bytes) => {
                    let path = self.env_file(service, &prev.commit);
                    write_private(&path, &bytes)?;
                    let _ = std::fs::remove_file(&env);
                    Ok(Some(path))
                }
                Err(_) => Ok(None),
            }
        })();
        let env_file = match restored {
            Ok(env_file) => env_file,
            Err(e) => {
                progress
                    .line(format!(
                        "couldn't put back the files of release {short} ({e}), so {service} may be down"
                    ))
                    .await;
                return;
            }
        };

        let file = prev
            .compose_file
            .clone()
            .or_else(|| spec.compose_file.clone())
            .unwrap_or_else(|| "compose.yaml".into());
        let (_tx, mut cancel) = never();
        let up = container::compose_up(
            &dir,
            &file,
            &prev.container,
            env_file.as_deref(),
            docker_env,
            time,
            &mut cancel,
            progress,
        )
        .await;
        let line = match up {
            Ok(()) => format!("started release {short} again: {service} is live on it"),
            Err(failure) => format!(
                "couldn't start release {short} again ({}), so {service} may be down",
                failure.message
            ),
        };
        progress.line(line).await;
    }

    /// The port the app listens on in its container: the one it was given,
    /// else the lowest its image EXPOSEs, else 80. The log says which.
    async fn container_port(&self, spec: &DeploySpec, image: &str, progress: &Progress) -> u16 {
        if let Some(port) = spec.port.filter(|p| *p > 0) {
            progress
                .line(format!("the app listens on port {port}, as set"))
                .await;
            return port;
        }
        match container::image_ports(image).await.first() {
            Some(port) => {
                progress
                    .line(format!(
                        "the app listens on port {port}, from the image's EXPOSE"
                    ))
                    .await;
                *port
            }
            None => {
                progress
                    .line("no port is set and the image doesn't EXPOSE one, so the app is expected on port 80")
                    .await;
                80
            }
        }
    }

    /// The local port the new release is published on: its usual one, or
    /// the next free one when something else has it (a stopped release
    /// keeps its port for a rollback, so those count as taken).
    async fn host_port(
        &self,
        usual: u16,
        previous: Option<&Release>,
        progress: &Progress,
    ) -> Result<u16, Failure> {
        let claimed = container::claimed_ports().await;
        let taken = |port: u16| {
            claimed.contains(&port)
                || previous.is_some_and(|p| p.port == port)
                || !container::port_is_free(port)
        };
        let port = container::pick_port(usual, taken).ok_or_else(|| {
            Failure::new(
                "start",
                "every local port ServerOS gives apps (20000 to 29999) is in use",
            )
            .with_next_step("Remove apps or old releases you no longer need, then deploy again.")
        })?;
        if port != usual {
            progress
                .line(format!(
                    "port {usual} is already in use on this machine, so this release uses {port}"
                ))
                .await;
        }
        Ok(port)
    }

    #[allow(clippy::too_many_arguments)]
    async fn deploy_inner(
        &self,
        ctx: &JobContext,
        spec: &DeploySpec,
        workspace: &Path,
        previous: Option<&Release>,
        slot: &Slot,
        docker_env: &[(&str, &str)],
        until: Instant,
        touched: &Touched,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<DeployResult, Failure> {
        let progress = &ctx.progress;
        let service = &spec.service;
        let commit = &spec.commit;
        let step_timeout = left(until);
        let method = BuildMethod::of(spec)?;
        let build = spec.build.clone().unwrap_or_default();
        // Settings that can't work are refused before anything is fetched.
        container::plan_env(&spec.env)?;
        container::check_volumes(&spec.volumes)?;
        if let Some(network) = spec.network.as_deref() {
            container::check_network(network)?;
        }
        // An app in a subfolder builds from there; a Compose file names
        // its own path, so it builds from the repository's root.
        let base_dir = match (&spec.compose_file, &spec.base_dir) {
            (None, Some(dir)) => Some(base_dir_path(dir)?),
            _ => None,
        };
        let settings = container::BuildSettings::from_args(&build.args)?;

        // An image already built from these same files (the live commit
        // redeployed for an env change, say) is used as it is, unless the
        // build is asked to start from scratch.
        let tag = container::image_tag(service, commit);
        let fingerprint = build_fingerprint(spec);
        let built = !build.no_cache
            && match method {
                BuildMethod::Dockerfile => container::image_label(&tag, container::BUILD_LABEL)
                    .await
                    .is_some_and(|label| label == fingerprint),
                BuildMethod::Railpack => self.railpack_built(service, &tag, &fingerprint).await,
                BuildMethod::Image | BuildMethod::Compose => false,
            };

        // What the build needs from the machine, before anything is fetched.
        crate::preflight::check(
            crate::preflight::Needs {
                compose: method == BuildMethod::Compose,
                buildx: method == BuildMethod::Railpack && !built,
                image_space: !built,
                fetch_space: !built && method != BuildMethod::Image && !spec.repo.is_empty(),
            },
            &self.paths.jobs_dir(),
            cancel,
            progress,
        )
        .await?;

        progress.phase("fetch", Some(15)).await;
        if built {
            progress
                .line(format!(
                    "image for {} is already built with the same files; skipping the build",
                    &commit[..7.min(commit.len())]
                ))
                .await;
        } else if method == BuildMethod::Image {
            progress
                .line("deploying a prebuilt image: nothing to fetch or build".to_string())
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
                git::FetchOptions {
                    submodules: build.submodules,
                    lfs: build.lfs,
                },
                step_timeout,
                cancel,
                progress,
            )
            .await?;
        }
        let context = if built || method == BuildMethod::Image {
            None
        } else {
            let context = build_context(workspace, base_dir, commit, !spec.repo.is_empty())?;
            write_files(&context, &spec.files)?;
            Some(context)
        };

        if let Some(compose) = &spec.compose_file {
            return self
                .deploy_compose(
                    ctx, spec, compose, workspace, previous, docker_env, until, touched, cancel,
                )
                .await;
        }

        progress.phase("env", Some(25)).await;
        let mut env = container::plan_env(&spec.env)?;
        let env_file = self.write_env(service, commit, &docker_env_file(&env.file))?;

        progress.phase("build", Some(40)).await;
        match (method, &context) {
            (BuildMethod::Image, _) => {
                crate::image::pull(
                    build.image.as_deref().unwrap_or_default(),
                    &tag,
                    docker_env,
                    step_timeout,
                    cancel,
                    progress,
                )
                .await?;
            }
            (BuildMethod::Railpack, Some(context)) => {
                crate::railpack::RailpackBuild {
                    state_dir: &self.paths.state_dir,
                    plan_dir: &self.paths.jobs_dir().join(format!("{}-railpack", ctx.id)),
                    service,
                    context,
                    tag: &tag,
                    build: &build,
                    settings: &settings,
                    limits: &self.build_limits,
                    docker_env,
                    timeout: step_timeout,
                }
                .run(cancel, progress)
                .await?;
                self.remember_railpack_build(service, &tag, &fingerprint);
            }
            (_, Some(context)) => {
                container::build(
                    context,
                    spec.dockerfile.as_deref(),
                    &tag,
                    &fingerprint,
                    &container::DockerfileOptions {
                        target: build.target.as_deref().filter(|t| !t.is_empty()),
                        no_cache: build.no_cache,
                        settings: Some(&settings),
                    },
                    &self.build_limits,
                    docker_env,
                    step_timeout,
                    cancel,
                    progress,
                )
                .await?;
            }
            (_, None) => {}
        }

        progress.phase("start", Some(60)).await;
        let name = slot.name.clone();
        if previous.is_some_and(|p| p.commit == *commit) {
            progress
                .line(format!(
                    "{} is live already: starting it again beside itself as {name}, so it keeps serving until the swap",
                    &commit[..7.min(commit.len())]
                ))
                .await;
        }
        let container_port = self.container_port(spec, &tag, progress).await;

        // The app is told the port it's expected on, unless it sets one.
        if !spec.env.contains_key("PORT") {
            env.add("PORT", &container_port.to_string());
            progress
                .line(format!("PORT is set to {container_port} for the app"))
                .await;
        }

        // Folders the Dockerfile declares with VOLUME are the app's data:
        // each is a volume every release mounts, so a deploy never starts
        // it over empty. Read the previous release's before it can go.
        let previous_volumes = match previous {
            Some(prev) => container::container_volumes(&prev.container).await,
            None => Default::default(),
        };
        let declared = container::plan_volumes(
            service,
            &container::image_volumes(&tag).await?,
            &previous_volumes,
        );
        let volumes = container::with_app_volumes(service, declared, &spec.volumes);
        for (volume, path) in &volumes {
            container::ensure_volume(volume, service).await?;
            progress
                .line(format!("{path} is kept in volume {volume} between deploys"))
                .await;
        }

        if let Some(network) = spec.network.as_deref() {
            container::ensure_network(network).await?;
            progress
                .line(format!(
                    "joining network {network}, where other apps reach it as {}",
                    container::network_alias(service)
                ))
                .await;
        }
        let log_rotation = !container::docker_sets_logging();

        let limits = spec.limits.clone().filter(|l| !l.is_empty());
        if let Some(limits) = &limits {
            progress
                .line(format!(
                    "limited to {}",
                    container::limit_args(limits)?.join(" ")
                ))
                .await;
        }

        let run = RunSpec {
            name: &name,
            image: &tag,
            service,
            env: &env,
            env_file: env_file.as_deref(),
            volumes: &volumes,
            network: spec.network.as_deref(),
            log_rotation,
        };

        if let Some(command) = spec
            .release_command
            .as_deref()
            .filter(|c| !c.trim().is_empty())
        {
            progress.phase("release", Some(64)).await;
            progress
                .line(format!("running the release command: {command}"))
                .await;
            let release_name = container::release_container_name(&name);
            container::run_release_command(
                &RunSpec {
                    name: &release_name,
                    ..run
                },
                command,
                left(until),
                cancel,
                progress,
            )
            .await?;
            progress.line("the release command finished").await;
        }

        progress.phase("start", Some(66)).await;
        Touched::set(&touched.container);
        container::remove(&name, progress).await;
        let host_port = self.host_port(slot.port, previous, progress).await?;
        container::run(
            &run,
            host_port,
            container_port,
            limits.as_ref(),
            Duration::from_secs(120),
            cancel,
            progress,
        )
        .await?;

        let target = Target {
            host_port,
            container_port: Some(container_port),
            domains: &spec.domains,
        };
        progress.phase("health", Some(70)).await;
        Self::check(&name, target, spec.health.as_ref(), cancel, progress).await?;
        if spec.health.is_none() && !spec.domains.is_empty() {
            // Not checked, but a site that will only show an error is
            // worth a word.
            let answer = health::probe(target, "/", 0, Duration::from_secs(5)).await;
            if answer == health::Probe::Refused {
                progress
                    .line(format!(
                        "warning: nothing is accepting connections on port {container_port}, so the site will show an error until the app listens there"
                    ))
                    .await;
            }
        }

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
            Touched::set(&touched.proxy);
        }

        progress.phase("verify", Some(90)).await;
        // Up already: the start period was for booting.
        let verify = spec.health.clone().map(|check| HealthCheck {
            start_period_secs: 0,
            ..check
        });
        Self::check(&name, target, verify.as_ref(), cancel, progress).await?;

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
            health: spec.health.clone(),
            container_port: Some(container_port),
            network: spec.network.clone(),
            compose_file: None,
        };
        let evicted = ledger
            .promote(service, release, RETAINED_RELEASES)
            .map_err(|e| Failure::new("record", e.to_string()))?;
        let result = DeployResult {
            service: service.clone(),
            commit: commit.clone(),
            container: name.clone(),
            port: host_port,
            domains: spec.domains.clone(),
            previous: previous.map(|p| p.commit.clone()),
            restart_note: None,
            limits,
            container_port: Some(container_port),
            build_method: Some(method.name().into()),
        };
        *touched.live.lock().unwrap_or_else(|p| p.into_inner()) = Some(result.clone());

        if let Some(command) = spec
            .post_deploy_command
            .as_deref()
            .filter(|c| !c.trim().is_empty())
        {
            progress.phase("post-deploy", Some(93)).await;
            // Some time is left for stopping the old release after.
            let time = left(until).saturating_sub(Duration::from_secs(45));
            if time.is_zero() {
                progress
                    .line("warning: no time was left to run the post-deploy command")
                    .await;
            } else {
                progress
                    .line(format!("running the post-deploy command: {command}"))
                    .await;
                match container::post_deploy(&name, command, time, cancel, progress).await {
                    Ok(()) => progress.line("the post-deploy command finished").await,
                    Err(why) => {
                        progress
                            .line(format!(
                                "warning: the post-deploy command failed ({why}); the new release is live all the same"
                            ))
                            .await
                    }
                }
            }
        }

        if let Some(prev) = to_drain(previous, &name) {
            progress.phase("drain", Some(95)).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            let time = left(until).clamp(Duration::from_secs(1), Duration::from_secs(90));
            if let Err(e) = container::stop(&prev.container, time, cancel, progress).await {
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

        Ok(result)
    }

    /// A Compose app: its files replace the live stack's (kept aside to go
    /// back to), and the stack is brought up from them and checked.
    #[allow(clippy::too_many_arguments)]
    async fn deploy_compose(
        &self,
        ctx: &JobContext,
        spec: &DeploySpec,
        compose: &str,
        workspace: &Path,
        previous: Option<&Release>,
        docker_env: &[(&str, &str)],
        until: Instant,
        touched: &Touched,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<DeployResult, Failure> {
        let progress = &ctx.progress;
        let service = &spec.service;
        let commit = &spec.commit;

        progress.phase("env", Some(25)).await;
        let project = format!("serveros-{}", git::sanitise(service));
        let dir = self.compose_dir(service);
        for (set, what) in [
            (
                spec.limits.as_ref().is_some_and(|l| !l.is_empty()),
                "CPU and memory limits",
            ),
            (spec.release_command.is_some(), "Release commands"),
            (spec.post_deploy_command.is_some(), "Post-deploy commands"),
            (!spec.volumes.is_empty(), "Volumes"),
            (spec.network.is_some(), "Shared networks"),
        ] {
            if set {
                progress
                    .line(format!(
                        "{what} apply to single-container apps, so this Compose stack runs without them; set them in its Compose file"
                    ))
                    .await;
            }
        }

        let mut body = String::new();
        for (name, value) in &spec.env {
            body.push_str(&container::compose_env_line(name, value));
        }
        self.keep_compose(service, previous)?;
        Touched::set(&touched.compose);
        replace_dir(workspace, &dir)?;
        let env_file = self.write_env(service, commit, &body)?;

        progress.phase("build", Some(40)).await;
        container::compose_up(
            &dir,
            compose,
            &project,
            env_file.as_deref(),
            docker_env,
            left(until),
            cancel,
            progress,
        )
        .await?;

        progress.phase("health", Some(70)).await;
        let host_port = spec.port.filter(|p| *p > 0);
        match host_port {
            Some(port) => {
                let check = spec.health.clone().unwrap_or_else(compose_check);
                let target = Target {
                    host_port: port,
                    container_port: None,
                    domains: &spec.domains,
                };
                if let Err(failure) =
                    health::wait_healthy(target, Some(&check), cancel, progress).await
                {
                    let logs = container::compose_logs_tail(&project, 40, progress).await;
                    return Err(if logs.is_empty() {
                        failure
                    } else {
                        failure.with_output(logs)
                    });
                }
            }
            None => container::compose_settled(&project, progress).await?,
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
            http: host_port.is_some(),
            compose: true,
            health: spec.health.clone(),
            container_port: None,
            network: None,
            compose_file: Some(compose.to_string()),
        };
        ReleaseLedger::new(&self.state)
            .promote(service, release.clone(), RETAINED_RELEASES)
            .map_err(|e| Failure::new("record", e.to_string()))?;
        self.drop_compose_backup(service);
        let result = DeployResult {
            service: service.clone(),
            commit: commit.clone(),
            container: release.container,
            port: release.port,
            domains: spec.domains.clone(),
            previous: previous.map(|p| p.commit.clone()),
            restart_note: Some("Compose projects are recreated in place, so the service restarted briefly during this deploy.".into()),
            limits: None,
            container_port: None,
            build_method: Some("compose".into()),
        };
        *touched.live.lock().unwrap_or_else(|p| p.into_inner()) = Some(result.clone());
        Ok(result)
    }

    /// A release that answers HTTP is asked for its health page. One that
    /// doesn't, like a chat bot or a worker, passes if its container is
    /// still running a few seconds after starting. One that fails carries
    /// the container's last log lines, which usually say why (it crashed on
    /// start, or listens on another port), since the container is removed.
    async fn check(
        container: &str,
        target: Target<'_>,
        health: Option<&HealthCheck>,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let result = match health {
            Some(check) => health::wait_healthy(target, Some(check), cancel, progress).await,
            None => health::wait_running(container, progress).await,
        };
        let Err(failure) = result else {
            return Ok(());
        };
        if failure.phase == "cancelled" {
            return Err(failure);
        }
        // Nothing answering because it crashed says so.
        let crashed = match container::state(container).await {
            Ok((status, _)) if health.is_some() && status != "running" => {
                Some(format!("the app stopped (its container is {status})"))
            }
            Ok((_, restarts)) if health.is_some() && restarts > 0 => Some(format!(
                "the app keeps crashing (restarted {restarts} times)"
            )),
            _ => None,
        };
        let failure = match crashed {
            Some(why) => Failure {
                message: format!("{}; {why}", failure.message),
                ..failure
            },
            None => failure,
        };
        if !failure.output_tail.is_empty() {
            return Err(failure);
        }
        let logs = container::logs_tail(container, 40, progress).await;
        Err(if logs.is_empty() {
            failure
        } else {
            failure.with_output(logs)
        })
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
        let until = Instant::now() + deploy_budget(ctx.timeout);
        let _lock = lock_app(service, until, &mut cancel, progress).await?;
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
        // Docker joins a started container to its networks again, but only
        // if they're still there.
        if let Some(network) = release.network.as_deref() {
            container::ensure_network(network).await?;
        }
        container::start(
            &release.container,
            Duration::from_secs(120),
            &mut cancel,
            progress,
        )
        .await?;

        progress.phase("health", Some(60)).await;
        let checked = if release.http {
            let check = release.health.clone().unwrap_or_else(health::default_check);
            let target = Target {
                host_port: release.port,
                container_port: release.container_port,
                domains,
            };
            Self::check(
                &release.container,
                target,
                Some(&check),
                &mut cancel,
                progress,
            )
            .await
        } else {
            health::wait_running(&release.container, progress).await
        };
        if let Err(failure) = checked {
            // Back as it was: stopped, with the live release serving.
            let (_tx, mut never) = never();
            let _ = container::stop(
                &release.container,
                Duration::from_secs(60),
                &mut never,
                progress,
            )
            .await;
            return Err(failure);
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
            limits: None,
            container_port: release.container_port,
            build_method: None,
        })
    }
}

/// Whether any container of a Compose project is running.
async fn compose_running(project: &str) -> bool {
    container::compose_states(project)
        .await
        .iter()
        .any(|c| c.status == "running")
}

fn minutes(time: Duration) -> String {
    let secs = time.as_secs();
    if secs >= 120 {
        format!("{} minutes", secs / 60)
    } else {
        format!("{secs} seconds")
    }
}

/// A docker env file: one `NAME=value` a line, as docker reads it (it
/// takes no quotes, so values here are single lines).
fn docker_env_file(env: &BTreeMap<String, String>) -> String {
    env.iter().map(|(k, v)| format!("{k}={v}\n")).collect()
}

/// Removes job workspaces deploys left behind when they never got to
/// (the daemon was stopped partway, say), once they're older than
/// `older_than`. Run when the daemon starts, before any job does.
pub fn sweep_workspaces(jobs_dir: &Path, older_than: Duration, now: SystemTime) -> usize {
    let Ok(entries) = std::fs::read_dir(jobs_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let old = meta
            .modified()
            .ok()
            .and_then(|at| now.duration_since(at).ok())
            .is_some_and(|age| age > older_than);
        // Only job workspaces: folders named for a job.
        let job = entry
            .file_name()
            .to_str()
            .is_some_and(|name| uuid::Uuid::parse_str(name).is_ok());
        if old && job && meta.is_dir() && std::fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
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

/// How a deploy makes its image: the spec's build method, or its Compose
/// file, checked against what each needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildMethod {
    Compose,
    Dockerfile,
    Railpack,
    Image,
}

impl BuildMethod {
    fn of(spec: &DeploySpec) -> Result<Self, Failure> {
        use daemon_protocol::BuildMethod as Asked;

        let asked = spec.build.as_ref().map(|b| b.method);
        if spec.compose_file.is_some() {
            return match asked {
                None | Some(Asked::Dockerfile) => Ok(Self::Compose),
                Some(_) => Err(Failure::new(
                    "prepare",
                    "a Compose app is built from its Compose file",
                )
                .with_next_step(
                    "Leave the build method as it is for Compose apps, or stop using the Compose file.",
                )),
            };
        }
        match asked.unwrap_or_default() {
            Asked::Dockerfile => Ok(Self::Dockerfile),
            Asked::Railpack => Ok(Self::Railpack),
            Asked::Image => {
                let image = spec
                    .build
                    .as_ref()
                    .and_then(|b| b.image.as_deref())
                    .unwrap_or_default();
                if image.trim().is_empty() {
                    return Err(Failure::new("prepare", "no image to deploy")
                        .with_next_step("Set the image to run, like nginx:alpine."));
                }
                // The release is named for its commit, so an image deploy
                // still needs one: an id the panel makes for it.
                if !git::valid_commit(&spec.commit) {
                    return Err(Failure::new(
                        "prepare",
                        format!(
                            "{:?} can't name a release: it has to be 7 to 64 hex characters",
                            spec.commit
                        ),
                    ));
                }
                Ok(Self::Image)
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Compose => "compose",
            Self::Dockerfile => "dockerfile",
            Self::Railpack => "railpack",
            Self::Image => "image",
        }
    }
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
    // How it's built, when that isn't the plain Dockerfile build every
    // image before build settings was, so those images stay reusable.
    // Not `no_cache`: a build from scratch makes the same image.
    let plain = |b: &&daemon_protocol::BuildSpec| {
        let mut b = (*b).clone();
        b.no_cache = false;
        b == daemon_protocol::BuildSpec::default()
    };
    if let Some(build) = spec.build.as_ref().filter(|b| !plain(b)) {
        field(&mut hash, "build/2");
        field(
            &mut hash,
            BuildMethod::of(spec).map(BuildMethod::name).unwrap_or("?"),
        );
        optional(&mut hash, build.image.as_deref());
        optional(&mut hash, build.target.as_deref());
        hash.update((build.args.len() as u64).to_le_bytes());
        for (name, value) in &build.args {
            field(&mut hash, name);
            field(&mut hash, value);
        }
        optional(&mut hash, build.install_command.as_deref());
        optional(&mut hash, build.build_command.as_deref());
        optional(&mut hash, build.start_command.as_deref());
        hash.update([u8::from(build.submodules), u8::from(build.lfs)]);
    }
    hex::encode(hash.finalize())
}

const MAX_BASE_DIR_LEN: usize = 256;

/// The app's folder in its repository, as a path that can only lead inside
/// it: relative, and without `..` or `.` parts.
pub(crate) fn base_dir_path(base_dir: &str) -> Result<&Path, Failure> {
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

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
    fn build_settings_change_the_fingerprint_but_old_plain_builds_keep_theirs() {
        let spec: DeploySpec = serde_json::from_value(serde_json::json!({
            "service": "web",
            "repo": "https://github.com/acme/shop.git",
            "commit": "a".repeat(40),
        }))
        .unwrap();
        let base = build_fingerprint(&spec);

        // The default build, sent explicitly or asked to start from
        // scratch, makes the same image as before build settings.
        let mut same = spec.clone();
        same.build = Some(daemon_protocol::BuildSpec::default());
        assert_eq!(build_fingerprint(&same), base);
        same.build.as_mut().unwrap().no_cache = true;
        assert_eq!(build_fingerprint(&same), base);

        type Change = Box<dyn Fn(&mut daemon_protocol::BuildSpec)>;
        let changes: Vec<Change> = vec![
            Box::new(|b| b.method = daemon_protocol::BuildMethod::Railpack),
            Box::new(|b| b.target = Some("web".into())),
            Box::new(|b| {
                b.args.insert("NODE_ENV".into(), "production".into());
            }),
            Box::new(|b| {
                b.args.insert("NODE_ENV".into(), "development".into());
            }),
            Box::new(|b| b.install_command = Some("npm ci".into())),
            Box::new(|b| b.build_command = Some("npm run build".into())),
            Box::new(|b| b.start_command = Some("node server.js".into())),
            Box::new(|b| b.submodules = false),
            Box::new(|b| b.lfs = false),
        ];
        let mut seen = std::collections::BTreeSet::from([base]);
        for change in changes {
            let mut changed = spec.clone();
            let mut build = daemon_protocol::BuildSpec::default();
            change(&mut build);
            changed.build = Some(build);
            assert!(seen.insert(build_fingerprint(&changed)), "{changed:?}");
        }
    }

    #[test]
    fn build_methods_are_checked_against_what_they_need() {
        let spec = |extra: serde_json::Value| -> DeploySpec {
            let mut raw = serde_json::json!({"service": "web", "commit": "a".repeat(40)});
            raw.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            serde_json::from_value(raw).unwrap()
        };
        let method = |extra| BuildMethod::of(&spec(extra));

        assert_eq!(
            method(serde_json::json!({})).unwrap(),
            BuildMethod::Dockerfile
        );
        assert_eq!(
            method(serde_json::json!({"compose_file": "compose.yaml"})).unwrap(),
            BuildMethod::Compose
        );
        assert_eq!(
            method(serde_json::json!({"build": {"method": "railpack"}})).unwrap(),
            BuildMethod::Railpack
        );
        assert_eq!(
            method(serde_json::json!({"build": {"method": "image", "image": "nginx:alpine"}}))
                .unwrap()
                .name(),
            "image"
        );
        let no_image = method(serde_json::json!({"build": {"method": "image"}})).unwrap_err();
        assert!(no_image.next_step.unwrap().contains("nginx:alpine"));
        assert!(method(serde_json::json!({
            "compose_file": "compose.yaml", "build": {"method": "railpack"}
        }))
        .is_err());
        let mut bad_commit = spec(serde_json::json!({
            "build": {"method": "image", "image": "nginx:alpine"}
        }));
        bad_commit.commit = "nginx:alpine".into();
        assert!(BuildMethod::of(&bad_commit).is_err());
    }

    #[test]
    fn deploy_results_say_how_the_image_was_made() {
        let result = DeployResult {
            service: "web".into(),
            commit: "a".repeat(40),
            container: "serveros-web-aaaaaaaaaaaa".into(),
            port: 20001,
            domains: vec![],
            previous: None,
            restart_note: None,
            limits: None,
            container_port: None,
            build_method: Some("railpack".into()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["build_method"], "railpack");
        let json = serde_json::to_value(DeployResult {
            build_method: None,
            ..result
        })
        .unwrap();
        assert!(json.get("build_method").is_none());
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
            health: None,
            container_port: None,
            network: None,
            compose_file: None,
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
            health: None,
            container_port: None,
            network: None,
            compose_file: None,
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
            health: None,
            container_port: None,
            network: None,
            compose_file: None,
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
    fn env_files_are_root_only_and_hold_what_they_are_given() {
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

        let mut env = BTreeMap::new();
        env.insert("APP_KEY".to_string(), "secret".to_string());
        let body: String = env
            .iter()
            .map(|(k, v)| container::compose_env_line(k, v))
            .collect();
        let path = deployer
            .write_env("app", "abcdef1234567890", &body)
            .unwrap()
            .unwrap();

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "APP_KEY=secret\n");
        assert!(deployer.write_env("app", "abc", "").unwrap().is_none());

        // A container's file only has what docker can't be handed by name.
        let plan = container::plan_env(&BTreeMap::from([
            ("PATH".to_string(), "/app/bin:/usr/bin".to_string()),
            ("KEY".to_string(), "line one\nline two".to_string()),
        ]))
        .unwrap();
        assert_eq!(docker_env_file(&plan.file), "PATH=/app/bin:/usr/bin\n");
    }

    #[test]
    fn a_deploy_gives_itself_less_time_than_the_job() {
        assert_eq!(
            deploy_budget(Duration::from_secs(1800)),
            Duration::from_secs(1680)
        );
        assert_eq!(
            deploy_budget(Duration::from_secs(300)),
            Duration::from_secs(240)
        );
        assert_eq!(
            deploy_budget(Duration::from_secs(10)),
            Duration::from_secs(8)
        );
        assert_eq!(minutes(Duration::from_secs(1680)), "28 minutes");
        assert_eq!(minutes(Duration::from_secs(90)), "90 seconds");
    }

    #[test]
    fn old_job_workspaces_are_swept_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let job = dir.path().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(job.join("repo")).unwrap();
        std::fs::write(job.join("repo/Dockerfile"), "FROM scratch").unwrap();
        let other = dir.path().join("keep-me");
        std::fs::create_dir_all(&other).unwrap();
        let a_day = Duration::from_secs(24 * 3600);

        // Fresh: kept.
        assert_eq!(sweep_workspaces(dir.path(), a_day, SystemTime::now()), 0);
        assert!(job.exists());

        // A day and more later: gone, and only the job's.
        let later = SystemTime::now() + a_day + Duration::from_secs(60);
        assert_eq!(sweep_workspaces(dir.path(), a_day, later), 1);
        assert!(!job.exists());
        assert!(other.exists());
        assert_eq!(
            sweep_workspaces(&dir.path().join("missing"), a_day, later),
            0
        );
    }

    #[tokio::test]
    async fn deploys_of_one_app_wait_for_each_other_and_others_do_not() {
        let state = Arc::new(State::in_memory().unwrap());
        let id = uuid::Uuid::new_v4();
        state.record_job(id, "test", "deploy", "{}").unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let progress = Progress::new(id, Arc::clone(&state), tx, vec![]);
        let (_cancel_tx, mut cancel) = watch::channel(false);
        let soon = Instant::now() + Duration::from_secs(30);

        let first = lock_app("lock-test", soon, &mut cancel, &progress)
            .await
            .unwrap();
        // Another app isn't held up.
        let other = lock_app("lock-test-api", soon, &mut cancel, &progress)
            .await
            .unwrap();
        drop(other);

        // The same app waits, and says so, until the first is done.
        let waiter = {
            let progress = progress.clone();
            let mut cancel = cancel.clone();
            tokio::spawn(async move {
                lock_app("lock-test", soon, &mut cancel, &progress)
                    .await
                    .map(|_| ())
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!waiter.is_finished());
        drop(first);
        waiter.await.unwrap().unwrap();
        let log = state.job(id).unwrap().unwrap().log;
        assert!(log.contains("waiting for it to finish"), "{log}");

        // It waits no longer than it has.
        let _held = lock_app("lock-test", soon, &mut cancel, &progress)
            .await
            .unwrap();
        let failure = lock_app(
            "lock-test",
            Instant::now() + Duration::from_millis(100),
            &mut cancel,
            &progress,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.phase, "waiting");
        assert!(failure.next_step.is_some());
    }
}
