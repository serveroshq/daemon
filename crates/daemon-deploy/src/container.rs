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

/// Creates the app's named volume unless it's there already. One that's
/// labelled as another app's is refused, so two apps never share data by
/// accident.
pub async fn ensure_volume(volume: &str, service: &str) -> Result<(), Failure> {
    if let Ok(labels) =
        docker_output(&["volume", "inspect", "--format", "{{json .Labels}}", volume]).await
    {
        return match parse_label(&labels, APP_LABEL) {
            Some(owner) if owner != service => Err(Failure::new(
                "volumes",
                format!("volume {volume} belongs to {owner}, not {service}"),
            )
            .with_next_step("Give this app's volume another name.")),
            _ => Ok(()),
        };
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

/// The Docker volume an app's own named volume (`spec.volumes`) is.
pub fn app_volume_name(service: &str, name: &str) -> String {
    format!("serveros-{}-{name}", crate::git::sanitise(service))
}

/// Checks the app's own volumes: names Docker accepts, absolute paths that
/// aren't the container's root, and no folder twice.
pub fn check_volumes(volumes: &[daemon_protocol::VolumeMount]) -> Result<(), Failure> {
    use std::path::Component;

    let bad = |message: String| {
        Err(Failure::new("volumes", message)
            .with_next_step("Fix the app's volumes, then deploy again."))
    };
    let mut paths = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    for volume in volumes {
        let mut chars = volume.name.chars();
        let name_ok = volume.name.len() <= 63
            && matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c));
        if !name_ok {
            return bad(format!(
                "{:?} isn't a volume name: use lowercase letters, digits, dots, dashes and underscores",
                volume.name
            ));
        }
        let path = Path::new(&volume.path);
        let normal = path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && !volume.path.contains([':', ',', '\n', '\0']);
        if !normal {
            return bad(format!(
                "{:?} has to be an absolute folder in the container, like /data",
                volume.path
            ));
        }
        let path = volume.path.trim_end_matches('/');
        if path.is_empty() {
            return bad(format!(
                "volume {} can't be mounted over the container's root folder",
                volume.name
            ));
        }
        if !paths.insert(path.to_string()) {
            return bad(format!("two volumes are mounted at {path}"));
        }
        if !names.insert(volume.name.clone()) {
            return bad(format!("volume {} is listed twice", volume.name));
        }
    }
    Ok(())
}

/// Every volume a release mounts, as (volume, folder): the folders the
/// image declares, then the app's own, which win where both name a folder.
pub fn with_app_volumes(
    service: &str,
    declared: Vec<(String, String)>,
    own: &[daemon_protocol::VolumeMount],
) -> Vec<(String, String)> {
    let own: Vec<(String, String)> = own
        .iter()
        .map(|v| {
            (
                app_volume_name(service, &v.name),
                v.path.trim_end_matches('/').to_string(),
            )
        })
        .collect();
    let mut all: Vec<(String, String)> = declared
        .into_iter()
        .filter(|(_, path)| {
            let path = path.trim_end_matches('/');
            !own.iter().any(|(_, p)| p == path)
        })
        .collect();
    all.extend(own);
    all
}

const BUILD_NEXT_STEP: &str = "Fix the build locally, push, and redeploy.";

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
                .with_next_step(BUILD_NEXT_STEP)
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

/// Settings the docker client reads from its own environment, or that the
/// daemon sets for it. An app's setting with one of these names can't be
/// handed over by name, so it goes in a root-only env file instead.
pub fn is_client_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "PATH"
            | "HOME"
            | "LC_ALL"
            | "TMPDIR"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "NO_PROXY"
            | "ALL_PROXY"
    ) || upper.starts_with("DOCKER_")
        || upper.starts_with("BUILDKIT_")
}

/// Letters, digits and underscores.
pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// How an app's settings reach its container without their values ever
/// being on a command line: `-e NAME` for each, with the value in the
/// docker client's own environment, which docker passes on as it is (so a
/// value can span lines). The few names the client itself reads go in
/// the env file instead.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EnvPlan {
    pub args: Vec<String>,
    pub client_env: Vec<(String, String)>,
    pub file: BTreeMap<String, String>,
}

impl EnvPlan {
    /// One more setting handed over by name (never one the client reads).
    pub fn add(&mut self, name: &str, value: &str) {
        debug_assert!(!is_client_env(name));
        self.args.push("-e".into());
        self.args.push(name.into());
        self.client_env.push((name.into(), value.into()));
    }
}

pub fn plan_env(env: &BTreeMap<String, String>) -> Result<EnvPlan, Failure> {
    let mut plan = EnvPlan::default();
    for (name, value) in env {
        if !valid_env_name(name) {
            return Err(Failure::new(
                "env",
                format!("{name:?} is not a valid environment variable name"),
            )
            .with_next_step("Use letters, digits and underscores."));
        }
        if value.contains('\0') {
            return Err(Failure::new(
                "env",
                format!("{name} has a null character in it"),
            ));
        }
        if is_client_env(name) {
            if value.contains(['\n', '\r']) {
                return Err(Failure::new(
                    "env",
                    format!("{name} can't span more than one line"),
                ));
            }
            plan.file.insert(name.clone(), value.clone());
        } else {
            plan.add(name, value);
        }
    }
    Ok(plan)
}

/// One line of an env file Docker Compose reads to fill in `${NAME}` in a
/// Compose file. Single quotes keep a value exactly as it is, over several
/// lines too; a value with a single quote in it is double-quoted instead,
/// with `\`, `"`, `$` and line breaks escaped.
pub fn compose_env_line(name: &str, value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:@,+=%".contains(c));
    if plain {
        format!("{name}={value}\n")
    } else if !value.contains('\'') {
        format!("{name}='{value}'\n")
    } else {
        let mut quoted = String::with_capacity(value.len() + 2);
        for c in value.chars() {
            match c {
                '\\' => quoted.push_str("\\\\"),
                '"' => quoted.push_str("\\\""),
                '$' => quoted.push_str("\\$"),
                '\n' => quoted.push_str("\\n"),
                '\r' => quoted.push_str("\\r"),
                c => quoted.push(c),
            }
        }
        format!("{name}=\"{quoted}\"\n")
    }
}

/// The ports an image says its app listens on (EXPOSE), TCP only, lowest
/// first.
pub async fn image_ports(tag: &str) -> Vec<u16> {
    docker_output(&[
        "image",
        "inspect",
        "--format",
        "{{json .Config.ExposedPorts}}",
        tag,
    ])
    .await
    .map(|out| parse_exposed_ports(&out))
    .unwrap_or_default()
}

fn parse_exposed_ports(json: &str) -> Vec<u16> {
    let mut ports: Vec<u16> =
        serde_json::from_str::<Option<BTreeMap<String, serde_json::Value>>>(json.trim())
            .ok()
            .flatten()
            .unwrap_or_default()
            .into_keys()
            .filter_map(|key| {
                let (port, proto) = key.split_once('/').unwrap_or((&key, "tcp"));
                (proto == "tcp").then(|| port.parse().ok()).flatten()
            })
            .filter(|p| *p > 0)
            .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The host ports every container ServerOS made has asked for, running or
/// not: a stopped release keeps its port for a rollback.
pub async fn claimed_ports() -> std::collections::BTreeSet<u16> {
    let ids = docker_output(&["ps", "-aq", "--filter", "label=com.serveros.managed=true"])
        .await
        .unwrap_or_default();
    let ids: Vec<&str> = ids.split_whitespace().collect();
    if ids.is_empty() {
        return Default::default();
    }
    let mut args = vec!["inspect", "--format", "{{json .HostConfig.PortBindings}}"];
    args.extend(ids);
    docker_output(&args)
        .await
        .map(|out| out.lines().flat_map(parse_port_bindings).collect())
        .unwrap_or_default()
}

fn parse_port_bindings(json: &str) -> Vec<u16> {
    #[derive(serde::Deserialize)]
    struct Binding {
        #[serde(rename = "HostPort", default)]
        host_port: String,
    }
    serde_json::from_str::<Option<BTreeMap<String, Option<Vec<Binding>>>>>(json.trim())
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_values()
        .flatten()
        .flatten()
        .filter_map(|b| b.host_port.parse().ok())
        .collect()
}

/// Whether nothing on this machine is listening on 127.0.0.1:`port`.
pub fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// The first port from `preferred` on, through the 20000-29999 range ServerOS
/// gives releases, that isn't `taken`.
pub fn pick_port(preferred: u16, taken: impl Fn(u16) -> bool) -> Option<u16> {
    let start = preferred.clamp(20_000, 29_999) - 20_000;
    (0..10_000u16)
        .map(|i| 20_000 + (start + i) % 10_000)
        .find(|port| !taken(*port))
}

/// Whether the machine's Docker sets a log driver or log options for every
/// container already; then ServerOS leaves logging to it.
pub fn docker_sets_logging() -> bool {
    [
        "/etc/docker/daemon.json",
        "/var/snap/docker/current/config/daemon.json",
    ]
    .iter()
    .filter_map(|path| std::fs::read_to_string(path).ok())
    .any(|text| logging_configured(&text))
}

fn logging_configured(daemon_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(daemon_json)
        .ok()
        .and_then(|v| {
            v.as_object()
                .map(|o| o.contains_key("log-driver") || o.contains_key("log-opts"))
        })
        .unwrap_or(false)
}

/// Docker's json-file logs grow for ever unless told otherwise: an app's
/// container keeps three files of 10 MB.
pub const LOG_ROTATION: [&str; 4] = ["--log-opt", "max-size=10m", "--log-opt", "max-file=3"];

/// Names Docker accepts for a network, and not one of its own special ones.
pub fn check_network(name: &str) -> Result<(), Failure> {
    let mut chars = name.chars();
    let valid = name.len() <= 64
        && matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if !valid {
        return Err(Failure::new(
            "network",
            format!("{name:?} isn't a network name Docker accepts"),
        )
        .with_next_step("Use letters, digits, dots, dashes and underscores."));
    }
    if matches!(name, "bridge" | "host" | "none" | "default") {
        return Err(Failure::new(
            "network",
            format!("{name:?} is one of Docker's own networks, so apps can't share it by name"),
        )
        .with_next_step("Pick another name, like serveros."));
    }
    Ok(())
}

/// Creates the network apps share unless it's there already.
pub async fn ensure_network(name: &str) -> Result<(), Failure> {
    check_network(name)?;
    if docker_output(&["network", "inspect", "--format", "{{.Name}}", name])
        .await
        .is_ok()
    {
        return Ok(());
    }
    docker_output(&[
        "network",
        "create",
        "--driver",
        "bridge",
        "--label",
        "com.serveros.managed=true",
        name,
    ])
    .await
    .map(|_| ())
    .or_else(|e| {
        // Made by another deploy in the meantime.
        if e.contains("already exists") {
            Ok(())
        } else {
            Err(Failure::new(
                "network",
                format!("could not create network {name}: {e}"),
            ))
        }
    })
}

/// The name an app has on the network it shares with others.
pub fn network_alias(service: &str) -> String {
    crate::git::sanitise(service).to_ascii_lowercase()
}

/// What a container runs with. Settings go in `env`, never on the command
/// line.
pub struct RunSpec<'a> {
    pub name: &'a str,
    pub image: &'a str,
    pub service: &'a str,
    pub env: &'a EnvPlan,
    pub env_file: Option<&'a Path>,
    pub volumes: &'a [(String, String)],
    pub network: Option<&'a str>,
    pub log_rotation: bool,
}

impl RunSpec<'_> {
    /// The flags every container of the app gets, the app's own and its
    /// release command's alike. On Docker's default bridge first, as
    /// before, so the machine's own services that only let in Docker's
    /// bridge (a database's pg_hba.conf, say) still do; the shared network
    /// is joined after.
    fn common_args(&self) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "--label".into(),
            "com.serveros.managed=true".into(),
            "--label".into(),
            format!("{APP_LABEL}={}", self.service),
            "--add-host".into(),
            "host.docker.internal:host-gateway".into(),
        ];
        for (volume, path) in self.volumes {
            args.push("-v".into());
            args.push(format!("{volume}:{path}"));
        }
        args.extend(self.env.args.iter().cloned());
        if let Some(env) = self.env_file {
            args.push("--env-file".into());
            args.push(env.to_string_lossy().into_owned());
        }
        args
    }

    fn client_env(&self) -> Vec<(&str, &str)> {
        self.env
            .client_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
}

/// The `docker create` arguments for an app's container.
pub fn create_args(
    run: &RunSpec<'_>,
    host_port: u16,
    container_port: u16,
    limits: Option<&ResourceLimits>,
) -> Result<Vec<String>, Failure> {
    let mut args: Vec<String> = vec![
        "create".into(),
        "--name".into(),
        run.name.into(),
        "--restart".into(),
        "unless-stopped".into(),
        "-p".into(),
        format!("127.0.0.1:{host_port}:{container_port}"),
    ];
    if run.log_rotation {
        args.extend(LOG_ROTATION.map(String::from));
    }
    args.extend(run.common_args());
    if let Some(limits) = limits {
        args.extend(limit_args(limits)?);
    }
    args.push(run.image.into());
    Ok(args)
}

/// Starts the app's container: created on Docker's bridge, joined to the
/// shared network under the app's name, then started. A container that
/// doesn't start is removed again.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    run: &RunSpec<'_>,
    host_port: u16,
    container_port: u16,
    limits: Option<&ResourceLimits>,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let args = create_args(run, host_port, container_port, limits)?;
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let env = run.client_env();
    let outcome = run_child(
        "docker", &arg_refs, None, &env, timeout, cancel, progress, None,
    )
    .await;
    if !outcome.success() {
        remove(run.name, progress).await;
        return Err(start_failure(outcome, "docker create", host_port));
    }

    let started = async {
        if let Some(network) = run.network {
            connect(
                run.name,
                network,
                Some(&network_alias(run.service)),
                cancel,
                progress,
            )
            .await?;
        }
        let outcome = run_child(
            "docker",
            &["start", run.name],
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
            Err(start_failure(outcome, "docker start", host_port))
        }
    }
    .await;
    if started.is_err() {
        remove(run.name, progress).await;
    }
    started
}

async fn connect(
    container: &str,
    network: &str,
    alias: Option<&str>,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let mut args = vec!["network", "connect"];
    if let Some(alias) = alias {
        args.extend(["--alias", alias]);
    }
    args.extend([network, container]);
    let outcome = run_child(
        "docker",
        &args,
        None,
        &[],
        Duration::from_secs(60),
        cancel,
        progress,
        None,
    )
    .await;
    if outcome.success() {
        Ok(())
    } else {
        Err(Failure::new(
            "network",
            format!("could not join {container} to network {network}"),
        )
        .with_output(outcome.tail().to_vec()))
    }
}

/// Why a container didn't start, in words that fit: a port that's taken
/// says so.
fn start_failure(outcome: ChildOutcome, what: &str, host_port: u16) -> Failure {
    let clash = outcome
        .tail()
        .iter()
        .any(|l| l.contains("port is already allocated") || l.contains("address already in use"));
    if clash {
        return Failure::new(
            "start",
            format!("port {host_port} on this machine is already in use, so the app couldn't start on it"),
        )
        .with_output(outcome.tail().to_vec())
        .with_next_step("Deploy again: ServerOS picks a port that's free.");
    }
    match failure_from("start", outcome, what) {
        f if f.next_step.as_deref() == Some(BUILD_NEXT_STEP) => f.with_next_step(
            "Check the app's settings (volumes, limits, network), then deploy again.",
        ),
        f => f,
    }
}

/// The name of the throwaway container a release command runs in.
pub fn release_container_name(container: &str) -> String {
    format!("{container}-release")
}

/// The `docker create` arguments for a release command's container: the
/// app's image, settings, volumes and network, but no port and no name on
/// the network, so nothing sends it traffic, and `sh -c` in place of the
/// image's own entrypoint.
pub fn release_args(run: &RunSpec<'_>, command: &str) -> Vec<String> {
    let mut args: Vec<String> = vec!["create".into(), "--name".into(), run.name.into()];
    args.extend(run.common_args());
    args.extend([
        "--entrypoint".into(),
        "sh".into(),
        run.image.into(),
        "-c".into(),
        command.into(),
    ]);
    args
}

/// Runs a release command (migrations, say) in a container of its own,
/// with its output in the job's log, and removes the container after.
pub async fn run_release_command(
    run: &RunSpec<'_>,
    command: &str,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    remove(run.name, progress).await;
    let args = release_args(run, command);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let env = run.client_env();
    let started = std::time::Instant::now();
    let created = run_child(
        "docker", &arg_refs, None, &env, timeout, cancel, progress, None,
    )
    .await;
    let result = if !created.success() {
        Err(failure_from("release", created, "docker create"))
    } else {
        let joined = match run.network {
            Some(network) => connect(run.name, network, None, cancel, progress).await,
            None => Ok(()),
        };
        match joined {
            Err(failure) => Err(failure),
            Ok(()) => {
                let left = timeout.saturating_sub(started.elapsed());
                let outcome = run_child(
                    "docker",
                    &["start", "-a", run.name],
                    None,
                    &[],
                    left,
                    cancel,
                    progress,
                    None,
                )
                .await;
                release_command_result(outcome, left)
            }
        }
    };
    remove(run.name, progress).await;
    result
}

fn release_command_result(outcome: ChildOutcome, timeout: Duration) -> Result<(), Failure> {
    match outcome {
        ChildOutcome::Exited { code: 0, .. } => Ok(()),
        ChildOutcome::Exited { code, tail } => {
            let missing_sh = tail.iter().any(|l| {
                l.contains("\"sh\": executable file not found") || l.contains("sh: not found")
            });
            let next = if missing_sh {
                "The image has no sh to run the command with. Use an image that has one, or run the command in the app's own start-up."
            } else {
                "Fix the command or what it needs (a database it connects to, say), then deploy again."
            };
            Err(
                Failure::new("release", format!("the release command exited {code}"))
                    .with_output(tail)
                    .with_next_step(next),
            )
        }
        ChildOutcome::TimedOut { tail } => Err(Failure::new(
            "release",
            format!(
                "the release command was still running after {} seconds, so it was stopped",
                timeout.as_secs()
            ),
        )
        .with_output(tail)
        .with_next_step("Make the command finish sooner, or give deploys a longer timeout.")),
        ChildOutcome::Cancelled { tail } => {
            Err(Failure::new("cancelled", "release command cancelled").with_output(tail))
        }
        ChildOutcome::Unstartable(e) => {
            Err(Failure::new("release", e).with_next_step("Install Docker on the machine."))
        }
    }
}

/// Runs a command in the app's container once it's live. It never fails
/// the deploy: what happened goes in the log.
pub async fn post_deploy(
    container: &str,
    command: &str,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), String> {
    let outcome = run_child(
        "docker",
        &["exec", container, "sh", "-c", command],
        None,
        &[],
        timeout,
        cancel,
        progress,
        None,
    )
    .await;
    match outcome {
        ChildOutcome::Exited { code: 0, .. } => Ok(()),
        ChildOutcome::Exited { code, .. } => Err(format!("it exited {code}")),
        ChildOutcome::TimedOut { .. } => Err(format!(
            "it was still running after {} seconds, so it was stopped",
            timeout.as_secs()
        )),
        ChildOutcome::Cancelled { .. } => Err("it was cancelled".into()),
        ChildOutcome::Unstartable(e) => Err(e),
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

/// Removes a container, quietly: there may be none of that name.
pub async fn remove(name: &str, _progress: &Progress) {
    let _ = docker_output(&["rm", "-f", name]).await;
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

/// Where one of a Compose stack's containers is at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerState {
    pub name: String,
    pub status: String,
    pub exit_code: i64,
    pub restarts: u64,
}

/// Every container of a Compose project, as Docker sees it now.
pub async fn compose_states(project: &str) -> Vec<ContainerState> {
    let label = format!("label=com.docker.compose.project={project}");
    let ids = docker_output(&["ps", "-aq", "--filter", &label])
        .await
        .unwrap_or_default();
    let ids: Vec<&str> = ids.split_whitespace().collect();
    if ids.is_empty() {
        return Vec::new();
    }
    let mut args = vec![
        "inspect",
        "--format",
        "{{.Name}}\t{{.State.Status}}\t{{.State.ExitCode}}\t{{.RestartCount}}",
    ];
    args.extend(ids);
    docker_output(&args)
        .await
        .map(|out| parse_states(&out))
        .unwrap_or_default()
}

fn parse_states(out: &str) -> Vec<ContainerState> {
    out.lines()
        .filter_map(|line| {
            let mut cols = line.split('\t');
            Some(ContainerState {
                name: cols.next()?.trim().trim_start_matches('/').to_string(),
                status: cols.next()?.trim().to_string(),
                exit_code: cols.next()?.trim().parse().ok()?,
                restarts: cols.next()?.trim().parse().ok()?,
            })
        })
        .collect()
}

/// The first container of a stack that isn't settling: one that exited
/// with an error, keeps restarting, has restarted since `first`, or never
/// started. One that exited 0 did its job (a one-off setup step).
pub fn compose_problem(
    first: &[ContainerState],
    now: &[ContainerState],
) -> Option<(String, String)> {
    now.iter().find_map(|c| {
        let restarted = first
            .iter()
            .find(|f| f.name == c.name)
            .is_some_and(|f| c.restarts > f.restarts);
        let why = match c.status.as_str() {
            "restarting" => Some("keeps restarting".to_string()),
            "exited" | "dead" if c.exit_code != 0 => Some(format!("exited {}", c.exit_code)),
            "created" => Some("never started".to_string()),
            "running" if restarted => Some(format!("restarted {} times", c.restarts)),
            _ => None,
        };
        why.map(|why| (c.name.clone(), why))
    })
}

/// For a Compose stack with no web port to ask: its containers have to
/// keep running (or finish cleanly) for a few seconds after it comes up.
pub async fn compose_settled(project: &str, progress: &Progress) -> Result<(), Failure> {
    let first = compose_states(project).await;
    if first.is_empty() {
        progress
            .line("the Compose stack started no containers to check")
            .await;
        return Ok(());
    }
    for attempt in 0..=3u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let now = compose_states(project).await;
        if let Some((name, why)) = compose_problem(&first, &now) {
            let logs = logs_tail(&name, 40, progress).await;
            return Err(
                Failure::new("health", format!("{name} {why} after starting"))
                    .with_output(logs)
                    .with_next_step(
                        "Check that service's logs for the error, often a missing setting.",
                    ),
            );
        }
        if attempt > 0 {
            progress
                .line(format!("still running after check {attempt}/3"))
                .await;
        }
    }
    progress
        .line("no web port to check, the stack kept running")
        .await;
    Ok(())
}

/// The last log lines of a Compose stack's containers, scrubbed.
pub async fn compose_logs_tail(project: &str, lines: usize, progress: &Progress) -> Vec<String> {
    let mut out = Vec::new();
    for c in compose_states(project).await {
        for line in logs_tail(&c.name, lines, progress).await {
            out.push(format!("{}: {line}", c.name));
        }
    }
    let skip = out.len().saturating_sub(lines);
    out.split_off(skip)
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

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn settings_go_by_name_with_their_values_never_on_the_command_line() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----";
        let plan = plan_env(&env(&[
            ("APP_KEY", "base64:s3cret"),
            ("JWT_KEY", pem),
            ("PATH", "/app/bin:/usr/bin"),
            ("DOCKER_HOST", "tcp://elsewhere:2375"),
            ("http_proxy", "http://proxy:3128"),
        ]))
        .unwrap();
        assert_eq!(plan.args, ["-e", "APP_KEY", "-e", "JWT_KEY"]);
        assert!(plan
            .client_env
            .contains(&("JWT_KEY".to_string(), pem.to_string())));
        // What the docker client reads itself goes in the file instead.
        assert_eq!(
            plan.file.keys().collect::<Vec<_>>(),
            ["DOCKER_HOST", "PATH", "http_proxy"]
        );

        let run = RunSpec {
            name: "serveros-shop-abc",
            image: "serveros/shop:abc",
            service: "shop",
            env: &plan,
            env_file: Some(Path::new("/var/lib/serveros/apps/shop/abc.env")),
            volumes: &[],
            network: None,
            log_rotation: false,
        };
        let args = create_args(&run, 20001, 3000, None).unwrap().join(" ");
        assert!(
            !args.contains("s3cret") && !args.contains("MIIEvQ"),
            "{args}"
        );
        assert!(args.contains("--env-file /var/lib/serveros/apps/shop/abc.env"));

        assert!(plan_env(&env(&[("bad name", "x")])).is_err());
        assert!(plan_env(&env(&[("", "x")])).is_err());
        assert!(plan_env(&env(&[("PATH", "a\nb")])).is_err());
        assert!(plan_env(&env(&[("2FA_SECRET", "x")])).is_ok());
    }

    #[test]
    fn compose_env_files_keep_values_exactly() {
        assert_eq!(compose_env_line("PORT", "3000"), "PORT=3000\n");
        assert_eq!(
            compose_env_line("URL", "https://shop.example.com/a"),
            "URL=https://shop.example.com/a\n"
        );
        assert_eq!(compose_env_line("EMPTY", ""), "EMPTY=''\n");
        assert_eq!(
            compose_env_line("PASS", "p$ss #word"),
            "PASS='p$ss #word'\n"
        );
        assert_eq!(compose_env_line("KEY", "a\nb"), "KEY='a\nb'\n");
        assert_eq!(
            compose_env_line("Q", "it's \"$x\"\\\n"),
            "Q=\"it's \\\"\\$x\\\"\\\\\\n\"\n"
        );
    }

    #[test]
    fn app_containers_join_the_shared_network_and_rotate_logs() {
        let plan = plan_env(&env(&[("PORT", "3000")])).unwrap();
        let volumes = vec![("serveros-shop-uploads".to_string(), "/data".to_string())];
        let run = RunSpec {
            name: "serveros-shop-abc",
            image: "serveros/shop:abc",
            service: "shop",
            env: &plan,
            env_file: None,
            volumes: &volumes,
            network: Some("serveros"),
            log_rotation: true,
        };
        let args = create_args(
            &run,
            20001,
            3000,
            Some(&ResourceLimits {
                cpu_millis: Some(500),
                memory_mb: None,
            }),
        )
        .unwrap();
        let line = args.join(" ");
        assert!(line.starts_with(
            "create --name serveros-shop-abc --restart unless-stopped -p 127.0.0.1:20001:3000 "
        ));
        assert!(line.contains("--log-opt max-size=10m --log-opt max-file=3"));
        assert!(line.contains("--add-host host.docker.internal:host-gateway"));
        assert!(line.contains("-v serveros-shop-uploads:/data"));
        assert!(line.contains("--label com.serveros.app=shop"));
        assert!(line.contains("--cpus=0.5"));
        // Created on Docker's own bridge: the shared network is joined
        // after, so the bridge stays its first.
        assert!(!line.contains("--network"));
        assert_eq!(args.last().unwrap(), "serveros/shop:abc");

        let quiet = RunSpec {
            log_rotation: false,
            ..run
        };
        assert!(!create_args(&quiet, 1, 2, None)
            .unwrap()
            .contains(&"--log-opt".to_string()));
        assert_eq!(network_alias("My_Shop"), "my_shop");
    }

    #[test]
    fn a_release_command_runs_in_a_container_of_its_own() {
        let plan = plan_env(&env(&[("DATABASE_URL", "postgres://a:b@db/app")])).unwrap();
        let volumes = vec![("serveros-shop-data".to_string(), "/data".to_string())];
        let run = RunSpec {
            name: &release_container_name("serveros-shop-abc"),
            image: "serveros/shop:abc",
            service: "shop",
            env: &plan,
            env_file: None,
            volumes: &volumes,
            network: Some("serveros"),
            log_rotation: true,
        };
        let args = release_args(&run, "php artisan migrate --force");
        let line = args.join(" ");
        assert!(line.starts_with("create --name serveros-shop-abc-release "));
        assert!(line.contains("-v serveros-shop-data:/data"));
        assert!(line.contains("-e DATABASE_URL"));
        assert!(!line.contains("postgres://"));
        // Nothing sends it traffic: no port, no name on the network.
        assert!(!line.contains("-p ") && !line.contains("--alias"));
        assert_eq!(
            &args[args.len() - 5..],
            [
                "--entrypoint",
                "sh",
                "serveros/shop:abc",
                "-c",
                "php artisan migrate --force"
            ]
        );

        let failed = release_command_result(
            ChildOutcome::Exited {
                code: 1,
                tail: vec!["SQLSTATE[HY000] [2002] Connection refused".into()],
            },
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert_eq!(failed.phase, "release");
        assert_eq!(failed.message, "the release command exited 1");
        assert_eq!(failed.output_tail.len(), 1);

        let no_sh = release_command_result(
            ChildOutcome::Exited {
                code: 127,
                tail: vec!["exec: \"sh\": executable file not found in $PATH".into()],
            },
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(no_sh.next_step.unwrap().contains("no sh"));

        let slow = release_command_result(
            ChildOutcome::TimedOut { tail: vec![] },
            Duration::from_secs(90),
        )
        .unwrap_err();
        assert!(slow.message.contains("90 seconds"));
        assert!(release_command_result(
            ChildOutcome::Exited {
                code: 0,
                tail: vec![]
            },
            Duration::from_secs(1)
        )
        .is_ok());
    }

    #[test]
    fn reads_exposed_ports_and_bindings() {
        assert_eq!(
            parse_exposed_ports(r#"{"8080/tcp":{},"3000/tcp":{},"53/udp":{}}"#),
            [3000, 8080]
        );
        assert!(parse_exposed_ports("null\n").is_empty());
        assert!(parse_exposed_ports("").is_empty());

        assert_eq!(
            parse_port_bindings(
                r#"{"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"20123"}],"9000/tcp":null}"#
            ),
            [20123]
        );
        assert!(parse_port_bindings("{}").is_empty());
        assert!(parse_port_bindings("null").is_empty());
    }

    #[test]
    fn a_taken_port_moves_to_the_next_free_one_in_range() {
        assert_eq!(pick_port(20500, |_| false), Some(20500));
        assert_eq!(pick_port(20500, |p| p < 20503), Some(20503));
        assert_eq!(pick_port(29999, |p| p == 29999), Some(20000));
        assert_eq!(pick_port(25000, |_| true), None);

        // Something listening is taken.
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(!port_is_free(held.local_addr().unwrap().port()));
    }

    #[test]
    fn log_rotation_is_left_to_a_docker_that_sets_its_own() {
        assert!(logging_configured(r#"{"log-driver":"journald"}"#));
        assert!(logging_configured(r#"{"log-opts":{"max-size":"50m"}}"#));
        assert!(!logging_configured(r#"{"data-root":"/mnt/docker"}"#));
        assert!(!logging_configured("not json"));
    }

    #[test]
    fn network_names_are_checked() {
        assert!(check_network("serveros").is_ok());
        assert!(check_network("acme_apps-1.internal").is_ok());
        for bad in ["", "-x", "has space", "a/b", "bridge", "host", "none"] {
            assert!(check_network(bad).is_err(), "{bad:?}");
        }
    }

    fn mount(name: &str, path: &str) -> daemon_protocol::VolumeMount {
        daemon_protocol::VolumeMount {
            name: name.into(),
            path: path.into(),
        }
    }

    #[test]
    fn an_apps_own_volumes_are_checked_and_named_for_it() {
        assert!(check_volumes(&[
            mount("data", "/data"),
            mount("uploads.v2", "/var/www/uploads/")
        ])
        .is_ok());
        for bad in [
            vec![mount("Data", "/data")],
            vec![mount("-data", "/data")],
            vec![mount("data", "data")],
            vec![mount("data", "/")],
            vec![mount("data", "//")],
            vec![mount("data", "/a/../etc")],
            vec![mount("data", "/a:/b")],
            vec![mount("a", "/data"), mount("b", "/data/")],
            vec![mount("a", "/one"), mount("a", "/two")],
            vec![mount(&"a".repeat(64), "/data")],
        ] {
            let failure = check_volumes(&bad).unwrap_err();
            assert_eq!(failure.phase, "volumes", "{bad:?}");
        }

        assert_eq!(app_volume_name("my shop", "data"), "serveros-my-shop-data");
        let declared = vec![
            ("serveros-shop_data".to_string(), "/data".to_string()),
            ("serveros-shop_cache".to_string(), "/cache".to_string()),
        ];
        // The app's own volume wins where both name a folder.
        assert_eq!(
            with_app_volumes("shop", declared, &[mount("uploads", "/data/")]),
            [
                ("serveros-shop_cache".to_string(), "/cache".to_string()),
                ("serveros-shop-uploads".to_string(), "/data".to_string()),
            ]
        );
    }

    #[test]
    fn a_compose_stack_settles_when_nothing_fails() {
        let parsed = parse_states(
            "/serveros-shop-web-1\trunning\t0\t0\n/serveros-shop-migrate-1\texited\t0\t0\nbad line\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "serveros-shop-web-1");
        assert_eq!(compose_problem(&parsed, &parsed), None);

        let state = |name: &str, status: &str, code: i64, restarts: u64| ContainerState {
            name: name.into(),
            status: status.into(),
            exit_code: code,
            restarts,
        };
        let first = vec![state("web", "running", 0, 0)];
        for (now, why) in [
            (state("web", "exited", 1, 0), "exited 1"),
            (state("web", "restarting", 1, 3), "keeps restarting"),
            (state("web", "running", 0, 2), "restarted 2 times"),
            (state("web", "created", 0, 0), "never started"),
        ] {
            assert_eq!(
                compose_problem(&first, &[now]),
                Some(("web".to_string(), why.to_string()))
            );
        }
    }

    #[test]
    fn a_port_clash_says_so() {
        let failure = start_failure(
            ChildOutcome::Exited {
                code: 125,
                tail: vec!["Error response from daemon: driver failed programming external connectivity: Bind for 127.0.0.1:20123 failed: port is already allocated".into()],
            },
            "docker start",
            20123,
        );
        assert!(failure.message.contains("port 20123"));
        assert!(failure.next_step.unwrap().contains("Deploy again"));

        let other = start_failure(
            ChildOutcome::Exited {
                code: 125,
                tail: vec!["invalid mount config".into()],
            },
            "docker start",
            20123,
        );
        assert!(!other.next_step.unwrap().contains("build"));
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
