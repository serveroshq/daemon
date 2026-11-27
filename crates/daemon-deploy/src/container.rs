use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use daemon_jobs::{capture_child, run_child, ChildOutcome, Failure, Progress};
use daemon_protocol::ResourceLimits;
use tokio::sync::watch;

pub struct BuildLimits {
    pub cpu_percent: u32,
    pub memory_mb: u64,
}

pub fn image_tag(service: &str, commit: &str) -> String {
    format!(
        "serveros/{}:{}",
        crate::git::sanitise(service),
        &commit[..commit.len().min(12)]
    )
}

pub fn container_name(service: &str, commit: &str) -> String {
    format!(
        "serveros-{}-{}",
        crate::git::sanitise(service),
        &commit[..commit.len().min(12)]
    )
}

/// The other name a release of `commit` can run under, so the commit that's
/// live can be started again beside itself. The slot goes after the commit,
/// so the name still reads as `serveros-<app>-<commit>` with `-b` on the end.
pub fn alternate_container_name(service: &str, commit: &str) -> String {
    format!("{}-b", container_name(service, commit))
}

/// The label on an app's containers and volumes naming the app.
pub const APP_LABEL: &str = "com.serveros.app";

/// The label on an app's images holding the fingerprint of what they were
/// built from, so a deploy of the same files can use the image as it is.
pub const BUILD_LABEL: &str = "serveros.build";

/// The named volume an app keeps the folder `path` in. It's the same for
/// every release, so what one version writes there is there for the next.
pub fn volume_name(service: &str, path: &str) -> String {
    let slug: String = path
        .trim_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let slug = if slug.is_empty() { "root".into() } else { slug };
    format!("serveros-{}_{}", crate::git::sanitise(service), slug)
}

/// Which volume to mount at each folder the image declares with VOLUME, as
/// (volume, folder). A folder the previous release already had a volume at
/// keeps that volume, so an app deployed before its folders were named
/// (each release then got an anonymous volume of its own) carries on with
/// its data; any other folder gets the app's named volume for it.
pub fn plan_volumes(
    service: &str,
    declared: &[String],
    previous: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    declared
        .iter()
        .map(|path| {
            let volume = previous
                .get(path)
                .cloned()
                .unwrap_or_else(|| volume_name(service, path));
            (volume, path.clone())
        })
        .collect()
}

async fn docker_output(args: &[&str]) -> Result<String, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("docker")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("docker {} timed out", args.join(" ")))?
    .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// A container's status ("running", "restarting", "exited"…) and how many
/// times Docker has restarted it.
pub async fn state(name: &str) -> Result<(String, u64), String> {
    let out = docker_output(&[
        "container",
        "inspect",
        "--format",
        "{{.State.Status}} {{.RestartCount}}",
        name,
    ])
    .await?;
    parse_state(&out).ok_or_else(|| format!("unexpected docker output: {}", out.trim()))
}

fn parse_state(out: &str) -> Option<(String, u64)> {
    let mut parts = out.split_whitespace();
    let status = parts.next()?.to_string();
    let restarts = parts.next()?.parse().ok()?;
    Some((status, restarts))
}

/// The folders an image declares with VOLUME.
pub async fn image_volumes(tag: &str) -> Result<Vec<String>, Failure> {
    let out = docker_output(&[
        "image",
        "inspect",
        "--format",
        "{{json .Config.Volumes}}",
        tag,
    ])
    .await
    .map_err(|e| Failure::new("volumes", format!("could not read {tag}'s volumes: {e}")))?;
    Ok(parse_image_volumes(&out))
}

fn parse_image_volumes(json: &str) -> Vec<String> {
    serde_json::from_str::<Option<BTreeMap<String, serde_json::Value>>>(json.trim())
        .ok()
        .flatten()
        .map(|volumes| volumes.into_keys().collect())
        .unwrap_or_default()
}

/// Whether there's a local image called `tag`.
pub async fn image_exists(tag: &str) -> bool {
    docker_output(&["image", "inspect", "--format", "{{.Id}}", tag])
        .await
        .is_ok()
}

/// The value of `label` on a local image, or None when there's no such
/// image or it hasn't got the label (images built before it was added).
pub async fn image_label(tag: &str, label: &str) -> Option<String> {
    let out = docker_output(&[
        "image",
        "inspect",
        "--format",
        "{{json .Config.Labels}}",
        tag,
    ])
    .await
    .ok()?;
    parse_label(&out, label)
}

fn parse_label(json: &str, label: &str) -> Option<String> {
    serde_json::from_str::<Option<BTreeMap<String, String>>>(json.trim())
        .ok()
        .flatten()?
        .remove(label)
        .filter(|value| !value.is_empty())
}

/// The volumes a container has mounted, by the folder they're mounted at.
/// Empty when there's no such container.
pub async fn container_volumes(name: &str) -> BTreeMap<String, String> {
    docker_output(&["container", "inspect", "--format", "{{json .Mounts}}", name])
        .await
        .map(|out| parse_container_volumes(&out))
        .unwrap_or_default()
}

fn parse_container_volumes(json: &str) -> BTreeMap<String, String> {
    #[derive(serde::Deserialize)]
    struct Mount {
        #[serde(rename = "Type")]
        kind: String,
        #[serde(rename = "Name", default)]
        name: String,
        #[serde(rename = "Destination")]
        destination: String,
    }

    serde_json::from_str::<Vec<Mount>>(json.trim())
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.kind == "volume" && !m.name.is_empty())
        .map(|m| (m.destination, m.name))
        .collect()
}

/// Creates the app's named volume unless it's there already.
pub async fn ensure_volume(volume: &str, service: &str) -> Result<(), Failure> {
    if docker_output(&["volume", "inspect", volume]).await.is_ok() {
        return Ok(());
    }
    let app = format!("{APP_LABEL}={service}");
    docker_output(&[
        "volume",
        "create",
        "--label",
        "com.serveros.managed=true",
        "--label",
        &app,
        volume,
    ])
    .await
    .map(|_| ())
    .map_err(|e| Failure::new("volumes", format!("could not create volume {volume}: {e}")))
}

fn failure_from(phase: &str, outcome: ChildOutcome, what: &str) -> Failure {
    match outcome {
        ChildOutcome::Exited { code, tail } => {
            let step = tail.iter().rev().find_map(|l| {
                l.strip_prefix("Step ")
                    .or_else(|| l.strip_prefix(" => ERROR "))
                    .map(|s| s.trim().to_string())
            });
            let summary = match step {
                Some(step) => format!("{what} failed at Step {step}, exited {code}"),
                None => format!("{what} exited {code}"),
            };
            Failure::new(phase, summary)
                .with_output(tail)
                .with_next_step("Fix the build locally, push, and redeploy.")
        }
        ChildOutcome::TimedOut { tail } => Failure::new(phase, format!("{what} timed out"))
            .with_output(tail)
            .with_next_step("Raise the job timeout or reduce the build."),
        ChildOutcome::Cancelled { tail } => {
            Failure::new("cancelled", format!("{what} cancelled")).with_output(tail)
        }
        ChildOutcome::Unstartable(e) => {
            Failure::new(phase, e).with_next_step("Install Docker on the machine.")
        }
    }
}

/// A Dockerfile build's settings beyond the file itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct DockerfileOptions<'a> {
    /// The stage to build (`--target`).
    pub target: Option<&'a str>,
    /// No layer cache.
    pub no_cache: bool,
    /// The build's settings (`--build-arg`), by name; values go to docker
    /// through its environment, never its command line.
    pub settings: Option<&'a BuildSettings>,
}

/// Names the docker client and the daemon's children run by themselves, so
/// a build setting can't take their place in the client's environment.
const RESERVED_NAMES: &[&str] = &["PATH", "HOME", "LC_ALL", "TMPDIR", "USER", "SHELL"];
const RESERVED_PREFIXES: &[&str] = &["DOCKER_", "BUILDKIT_", "BUILDX_", "SERVEROS_"];

/// A build's settings (`BuildSpec::args`), ready to hand to docker or
/// Railpack by name, with their values in the child's environment only.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct BuildSettings {
    pub names: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Names the build tools use themselves, left out of the build.
    pub skipped: Vec<String>,
}

impl std::fmt::Debug for BuildSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildSettings")
            .field("names", &self.names)
            .field("skipped", &self.skipped)
            .finish_non_exhaustive()
    }
}

impl BuildSettings {
    pub fn from_args(args: &BTreeMap<String, String>) -> Result<Self, Failure> {
        let mut settings = Self::default();
        for (name, value) in args {
            let valid = name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.len() <= 128
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid {
                return Err(Failure::new(
                    "build",
                    format!("{name:?} is not a valid build setting name"),
                )
                .with_next_step(
                    "Use letters, digits and underscores, starting with a letter, like NODE_ENV.",
                ));
            }
            let upper = name.to_ascii_uppercase();
            if RESERVED_NAMES.contains(&upper.as_str())
                || RESERVED_PREFIXES.iter().any(|p| upper.starts_with(p))
            {
                settings.skipped.push(name.clone());
                continue;
            }
            settings.names.push(name.clone());
            settings.env.push((name.clone(), value.clone()));
        }
        Ok(settings)
    }

    pub fn env_refs(&self) -> Vec<(&str, &str)> {
        self.env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Says which settings the build gets, by name, and which it doesn't.
    pub async fn log(&self, progress: &Progress) {
        if !self.names.is_empty() {
            progress
                .line(format!("build settings: {}", self.names.join(", ")))
                .await;
        }
        if !self.skipped.is_empty() {
            progress
                .line(format!(
                    "{} left out of the build: the build tools use these names themselves",
                    self.skipped.join(", ")
                ))
                .await;
        }
    }
}

/// A build stage's name, as `--target` takes it.
pub fn valid_target(target: &str) -> bool {
    (1..=128).contains(&target.len())
        && !target.starts_with('-')
        && target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn build_args(
    buildkit: bool,
    dockerfile: &str,
    tag: &str,
    fingerprint: &str,
    pull: bool,
    options: &DockerfileOptions<'_>,
) -> Vec<String> {
    let mut args = vec!["build".to_string()];
    if pull {
        args.push("--pull".into());
    }
    if buildkit {
        args.push("--progress=plain".into());
    }
    if let Some(target) = options.target {
        args.extend(["--target".into(), target.into()]);
    }
    if options.no_cache {
        args.push("--no-cache".into());
    }
    // `--build-arg NAME` with no value: docker reads it from its own
    // environment, so the value is never on a command line.
    for name in options.settings.map(|s| s.names.as_slice()).unwrap_or(&[]) {
        args.extend(["--build-arg".into(), name.clone()]);
    }
    args.extend([
        "--label".into(),
        format!("{BUILD_LABEL}={fingerprint}"),
        "-f".into(),
        dockerfile.into(),
        "-t".into(),
        tag.into(),
        ".".into(),
    ]);
    args
}

/// `extra_env` goes to docker as it is: DOCKER_CONFIG, for a deploy that
/// pulls from a private registry.
#[allow(clippy::too_many_arguments)]
pub async fn build(
    workspace: &Path,
    dockerfile: Option<&str>,
    tag: &str,
    fingerprint: &str,
    options: &DockerfileOptions<'_>,
    limits: &BuildLimits,
    extra_env: &[(&str, &str)],
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let dockerfile = dockerfile.unwrap_or("Dockerfile");

    if !workspace.join(dockerfile).exists() {
        return Err(Failure::new(
            "build",
            format!("no {dockerfile} in the repository at this commit"),
        )
        .with_next_step(
            "Add a Dockerfile, point the app at a Compose file, or let ServerOS work out how to build it (Railpack) in the app's build settings.",
        ));
    }
    if let Some(target) = options.target {
        if !valid_target(target) {
            return Err(Failure::new(
                "build",
                format!("{target:?} is not a Dockerfile stage name"),
            )
            .with_next_step("Use the name after AS in the Dockerfile's FROM line."));
        }
    }

    // BuildKit needs Docker's buildx plugin, which distro packages (Ubuntu's
    // docker.io) often leave out; without it, the classic builder.
    let buildkit = has_buildx(cancel).await;
    if !buildkit {
        progress
            .line("buildx isn't installed, so building with Docker's classic builder")
            .await;
    }
    if let Some(settings) = options.settings {
        settings.log(progress).await;
    }
    if options.no_cache {
        progress
            .line("building from scratch, without the layer cache")
            .await;
    }

    let settings_env = options
        .settings
        .map(BuildSettings::env_refs)
        .unwrap_or_default();
    let env = [builder_env(buildkit), extra_env, &settings_env].concat();

    let scoped = scopes_work(cancel).await;
    if !scoped {
        progress
            .line("systemd can't put the build in a scope here, so it runs without CPU and memory limits")
            .await;
    }

    let mut pull = true;
    loop {
        let docker_args = build_args(buildkit, dockerfile, tag, fingerprint, pull, options);
        let docker_args: Vec<&str> = docker_args.iter().map(String::as_str).collect();
        let outcome = run_scoped(
            "docker",
            &docker_args,
            workspace,
            &env,
            limits,
            scoped,
            timeout,
            cancel,
            progress,
        )
        .await;

        if outcome.success() {
            return Ok(());
        }
        // `--pull` asks Docker Hub for the newest base image every time;
        // when it's over its limit, the ones already here will do.
        if pull && crate::buildlog::rate_limited(outcome.tail()) {
            pull = false;
            progress
                .line("Docker Hub's pull limit was reached; building again with the base images already on this machine")
                .await;
            continue;
        }
        return Err(crate::buildlog::build_failure(
            "build",
            outcome,
            "docker build",
        ));
    }
}

/// Runs a build command in a systemd scope with the build's CPU and memory
/// limits when `scoped`, or as it is. The command's environment passes
/// through the scope untouched and never shows in its unit's properties.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_scoped(
    program: &str,
    args: &[&str],
    dir: &Path,
    env: &[(&str, &str)],
    limits: &BuildLimits,
    scoped: bool,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> ChildOutcome {
    if scoped {
        let cpu = format!("CPUQuota={}%", limits.cpu_percent);
        let mem = format!("MemoryMax={}M", limits.memory_mb);
        let mut scope: Vec<&str> = vec!["--scope", "--quiet", "-p", &cpu, "-p", &mem, program];
        scope.extend(args.iter());
        run_child(
            "systemd-run",
            &scope,
            Some(dir),
            env,
            timeout,
            cancel,
            progress,
            None,
        )
        .await
    } else {
        run_child(
            program,
            args,
            Some(dir),
            env,
            timeout,
            cancel,
            progress,
            None,
        )
        .await
    }
}

/// The docker run flags for an app's CPU and memory limits.
pub fn limit_args(limits: &ResourceLimits) -> Result<Vec<String>, Failure> {
    let mut args = Vec::new();
    if let Some(millis) = limits.cpu_millis {
        if millis == 0 {
            return Err(Failure::new("limits", "a CPU limit has to be more than 0"));
        }
        let cpus = format!("{}.{:03}", millis / 1000, millis % 1000);
        let cpus = cpus.trim_end_matches('0').trim_end_matches('.');
        args.push(format!("--cpus={cpus}"));
    }
    if let Some(mb) = limits.memory_mb {
        // Docker's own floor.
        if mb < 6 {
            return Err(Failure::new(
                "limits",
                "a memory limit has to be at least 6 MB",
            ));
        }
        args.push(format!("--memory={mb}m"));
    }
    Ok(args)
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    name: &str,
    tag: &str,
    service: &str,
    host_port: u16,
    container_port: u16,
    env_file: Option<&Path>,
    volumes: &[(String, String)],
    limits: Option<&ResourceLimits>,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let publish = format!("127.0.0.1:{host_port}:{container_port}");
    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.into(),
        "--restart".into(),
        "unless-stopped".into(),
        "-p".into(),
        publish,
        "--label".into(),
        "com.serveros.managed=true".into(),
        "--label".into(),
        format!("{APP_LABEL}={service}"),
    ];

    for (volume, path) in volumes {
        args.push("-v".into());
        args.push(format!("{volume}:{path}"));
    }

    if let Some(env) = env_file {
        args.push("--env-file".into());
        args.push(env.to_string_lossy().into_owned());
    }

    if let Some(limits) = limits {
        args.extend(limit_args(limits)?);
    }

    args.push(tag.into());

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = run_child(
        "docker",
        &arg_refs,
        None,
        &[],
        timeout,
        cancel,
        progress,
        None,
    )
    .await;

    if outcome.success() {
        Ok(())
    } else {
        Err(failure_from("start", outcome, "docker run"))
    }
}

pub async fn stop(
    name: &str,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let outcome = run_child(
        "docker",
        &["stop", "-t", "30", name],
        None,
        &[],
        timeout,
        cancel,
        progress,
        None,
    )
    .await;

    if outcome.success() {
        Ok(())
    } else {
        Err(failure_from("stop", outcome, "docker stop"))
    }
}

pub async fn start(
    name: &str,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let outcome = run_child(
        "docker",
        &["start", name],
        None,
        &[],
        timeout,
        cancel,
        progress,
        None,
    )
    .await;

    if outcome.success() {
        Ok(())
    } else {
        Err(failure_from("start", outcome, "docker start"))
    }
}

pub async fn remove(name: &str, progress: &Progress) {
    let (_tx, mut cancel) = watch::channel(false);
    let _ = run_child(
        "docker",
        &["rm", "-f", name],
        None,
        &[],
        Duration::from_secs(60),
        &mut cancel,
        progress,
        None,
    )
    .await;
}

pub async fn remove_image(tag: &str, progress: &Progress) {
    let (_tx, mut cancel) = watch::channel(false);
    let _ = run_child(
        "docker",
        &["image", "rm", tag],
        None,
        &[],
        Duration::from_secs(60),
        &mut cancel,
        progress,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub async fn compose_up(
    dir: &Path,
    file: &str,
    project: &str,
    env_file: Option<&Path>,
    extra_env: &[(&str, &str)],
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let mut args: Vec<String> = vec![
        "compose".into(),
        "-p".into(),
        project.into(),
        "-f".into(),
        file.into(),
    ];

    if let Some(env) = env_file {
        args.push("--env-file".into());
        args.push(env.to_string_lossy().into_owned());
    }

    args.extend(["up", "-d", "--build", "--remove-orphans"].map(String::from));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let env = [builder_env(has_buildx(cancel).await), extra_env].concat();
    let outcome = run_child(
        "docker",
        &arg_refs,
        Some(dir),
        &env,
        timeout,
        cancel,
        progress,
        None,
    )
    .await;

    if outcome.success() {
        Ok(())
    } else {
        Err(failure_from("build", outcome, "docker compose up"))
    }
}

/// A container's last log lines, what it wrote to stdout then stderr (where
/// most crashes go), for a failure to carry once it's gone.
pub async fn logs_tail(container: &str, lines: usize, progress: &Progress) -> Vec<String> {
    let (_tx, mut cancel) = watch::channel(false);
    let tail = lines.to_string();
    let captured = capture_child(
        "docker",
        &["logs", "--tail", &tail, container],
        &[],
        Duration::from_secs(15),
        &mut cancel,
        lines,
    )
    .await;
    let mut out: Vec<String> = captured.stdout().to_vec();
    out.extend(captured.stderr().iter().cloned());
    let skip = out.len().saturating_sub(lines);
    // An app's output can hold connection strings and keys: scrubbed like
    // the job's own log before it goes anywhere.
    out.into_iter()
        .skip(skip)
        .filter(|l| !l.trim().is_empty())
        .map(|l| progress.scrub(&l))
        .collect()
}

static HAS_BUILDX: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SCOPES_WORK: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// Whether this machine's Docker has the buildx plugin BuildKit needs.
/// Once it has, that's remembered for the daemon's run; until then it's
/// asked each build, since installing Docker from the panel adds it
/// without restarting the daemon.
async fn has_buildx(_cancel: &mut watch::Receiver<bool>) -> bool {
    use std::sync::atomic::Ordering;

    if HAS_BUILDX.load(Ordering::Relaxed) {
        return true;
    }
    // Its own cancel: a job's cancel mustn't decide the answer.
    let (_tx, mut never) = watch::channel(false);
    let found = capture_child(
        "docker",
        &["buildx", "version"],
        &[],
        Duration::from_secs(15),
        &mut never,
        5,
    )
    .await
    .code()
        == Some(0);
    if found {
        HAS_BUILDX.store(true, Ordering::Relaxed);
    }
    found
}

pub(crate) fn builder_env(buildkit: bool) -> &'static [(&'static str, &'static str)] {
    if buildkit {
        &[("DOCKER_BUILDKIT", "1")]
    } else {
        &[("DOCKER_BUILDKIT", "0")]
    }
}

/// Whether a build can run in a systemd scope (for its CPU and memory
/// limits). Having systemd isn't enough: inside containers and some LXC
/// hosts `systemd-run --scope` can't create one and the build never starts,
/// so it's tried first, and without one the build runs as it is.
pub(crate) async fn scopes_work(_cancel: &mut watch::Receiver<bool>) -> bool {
    *SCOPES_WORK
        .get_or_init(|| async {
            let (_tx, mut never) = watch::channel(false);
            Path::new("/run/systemd/system").is_dir()
                && which("systemd-run")
                && capture_child(
                    "systemd-run",
                    &["--scope", "--quiet", "true"],
                    &[],
                    Duration::from_secs(15),
                    &mut never,
                    5,
                )
                .await
                .code()
                    == Some(0)
        })
        .await
}

fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
        .unwrap_or(false)
        || Path::new("/usr/bin").join(program).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_container_state() {
        assert_eq!(parse_state("running 0\n"), Some(("running".into(), 0)));
        assert_eq!(parse_state("restarting 4"), Some(("restarting".into(), 4)));
        assert_eq!(parse_state(""), None);
    }

    #[test]
    fn names_are_derived_from_service_and_commit() {
        assert_eq!(
            image_tag("shop/web", "abcdef1234567890"),
            "serveros/shop-web:abcdef123456"
        );
        assert_eq!(container_name("app", "a1b2c3d"), "serveros-app-a1b2c3d");
        assert_eq!(
            alternate_container_name("shop", "abcdef1234567890"),
            "serveros-shop-abcdef123456-b"
        );
    }

    #[test]
    fn builds_are_labelled_with_what_they_were_built_from() {
        let none = DockerfileOptions::default();
        let args = build_args(true, "Dockerfile", "serveros/shop:abc", "f00d", true, &none);
        assert_eq!(
            args,
            [
                "build",
                "--pull",
                "--progress=plain",
                "--label",
                "serveros.build=f00d",
                "-f",
                "Dockerfile",
                "-t",
                "serveros/shop:abc",
                "."
            ]
        );
        assert!(!build_args(false, "Dockerfile", "t", "f", true, &none)
            .contains(&"--progress=plain".to_string()));
        assert!(
            !build_args(true, "Dockerfile", "t", "f", false, &none).contains(&"--pull".to_string())
        );

        assert_eq!(
            parse_label(r#"{"serveros.build":"f00d","x":"y"}"#, BUILD_LABEL).as_deref(),
            Some("f00d")
        );
        assert_eq!(parse_label("null\n", BUILD_LABEL), None);
        assert_eq!(parse_label(r#"{"x":"y"}"#, BUILD_LABEL), None);
        assert_eq!(parse_label("", BUILD_LABEL), None);
    }

    #[test]
    fn limits_become_docker_run_flags() {
        let limits = |cpu_millis, memory_mb| ResourceLimits {
            cpu_millis,
            memory_mb,
        };
        assert_eq!(
            limit_args(&limits(Some(500), Some(512))).unwrap(),
            ["--cpus=0.5", "--memory=512m"]
        );
        assert_eq!(limit_args(&limits(Some(2000), None)).unwrap(), ["--cpus=2"]);
        assert_eq!(
            limit_args(&limits(Some(1250), None)).unwrap(),
            ["--cpus=1.25"]
        );
        assert_eq!(
            limit_args(&limits(Some(10), None)).unwrap(),
            ["--cpus=0.01"]
        );
        assert_eq!(
            limit_args(&limits(None, Some(2048))).unwrap(),
            ["--memory=2048m"]
        );
        assert!(limit_args(&limits(None, None)).unwrap().is_empty());
        assert_eq!(
            limit_args(&limits(Some(0), None)).unwrap_err().phase,
            "limits"
        );
        assert_eq!(
            limit_args(&limits(None, Some(4))).unwrap_err().phase,
            "limits"
        );
    }

    #[test]
    fn build_settings_go_by_name_and_their_values_never_on_the_command_line() {
        let args: BTreeMap<String, String> = [
            ("NPM_TOKEN", "npm_s3cret"),
            ("NODE_ENV", "production"),
            ("PATH", "/evil"),
            ("DOCKER_HOST", "tcp://x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let settings = BuildSettings::from_args(&args).unwrap();
        assert_eq!(settings.names, ["NODE_ENV", "NPM_TOKEN"]);
        assert_eq!(settings.skipped, ["DOCKER_HOST", "PATH"]);
        assert_eq!(
            settings.env_refs(),
            [("NODE_ENV", "production"), ("NPM_TOKEN", "npm_s3cret")]
        );
        assert!(!format!("{settings:?}").contains("npm_s3cret"));

        let options = DockerfileOptions {
            target: Some("web"),
            no_cache: true,
            settings: Some(&settings),
        };
        let argv = build_args(
            true,
            "Dockerfile",
            "serveros/shop:abc",
            "f00d",
            true,
            &options,
        );
        assert!(argv
            .iter()
            .all(|a| !a.contains("npm_s3cret") && !a.contains("production")));
        let joined = argv.join(" ");
        assert!(joined.contains("--target web"));
        assert!(joined.contains("--no-cache"));
        assert!(joined.contains("--build-arg NODE_ENV --build-arg NPM_TOKEN"));
        assert!(joined.ends_with("-t serveros/shop:abc ."));

        for bad in ["", "1X", "MY-VAR", "a.b", "X Y"] {
            let args = BTreeMap::from([(bad.to_string(), "v".to_string())]);
            assert!(BuildSettings::from_args(&args).is_err(), "{bad:?}");
        }
        assert!(valid_target("web-prod_1.2"));
        for bad in ["", "-x", "a b", "a;b"] {
            assert!(!valid_target(bad), "{bad:?}");
        }
    }

    #[test]
    fn build_failures_name_the_step() {
        let outcome = ChildOutcome::Exited {
            code: 1,
            tail: vec!["Step 7/12 : RUN npm ci".into(), "npm ERR! code 1".into()],
        };
        let failure = failure_from("build", outcome, "docker build");

        assert_eq!(failure.phase, "build");
        assert!(failure.message.contains("Step 7/12"));
        assert!(failure.next_step.is_some());
    }

    #[test]
    fn volume_names_are_per_app_and_folder() {
        assert_eq!(
            volume_name("dayline-media", "/data"),
            "serveros-dayline-media_data"
        );
        assert_eq!(
            volume_name("shop", "/var/www/html/storage/"),
            "serveros-shop_var-www-html-storage"
        );
        assert_eq!(volume_name("my app", "/"), "serveros-my-app_root");
    }

    #[test]
    fn declared_folders_keep_the_previous_releases_volume() {
        let declared = vec!["/data".to_string(), "/cache".to_string()];
        let previous = BTreeMap::from([("/data".to_string(), "4f2a9c".to_string())]);
        assert_eq!(
            plan_volumes("shop", &declared, &previous),
            vec![
                ("4f2a9c".to_string(), "/data".to_string()),
                ("serveros-shop_cache".to_string(), "/cache".to_string()),
            ]
        );
        assert!(plan_volumes("shop", &[], &previous).is_empty());
    }

    #[test]
    fn reads_volumes_from_docker_inspect() {
        assert!(parse_image_volumes("null\n").is_empty());
        assert_eq!(
            parse_image_volumes(r#"{"/data":{},"/logs":{}}"#),
            vec!["/data", "/logs"]
        );

        let mounts = r#"[
            {"Type":"volume","Name":"serveros-shop_data","Source":"/var/lib/docker/volumes/serveros-shop_data/_data","Destination":"/data","RW":true},
            {"Type":"bind","Source":"/etc/hosts","Destination":"/etc/hosts","RW":false}
        ]"#;
        assert_eq!(
            parse_container_volumes(mounts),
            BTreeMap::from([("/data".to_string(), "serveros-shop_data".to_string())])
        );
        assert!(parse_container_volumes("").is_empty());
    }
}
