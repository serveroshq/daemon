use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use daemon_jobs::{capture_child, run_child, ChildOutcome, Failure, Progress};
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

/// The label on an app's containers and volumes naming the app.
pub const APP_LABEL: &str = "com.serveros.app";

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

pub async fn build(
    workspace: &Path,
    dockerfile: Option<&str>,
    tag: &str,
    limits: &BuildLimits,
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
        .with_next_step("Add a Dockerfile, or point the service at a Compose file."));
    }

    let cpu = format!("CPUQuota={}%", limits.cpu_percent);
    let mem = format!("MemoryMax={}M", limits.memory_mb);
    // BuildKit needs Docker's buildx plugin, which distro packages (Ubuntu's
    // docker.io) often leave out; without it, the classic builder.
    let buildkit = has_buildx(cancel).await;
    if !buildkit {
        progress
            .line("buildx isn't installed, so building with Docker's classic builder")
            .await;
    }
    let mut docker_args = vec!["build", "--pull"];
    if buildkit {
        docker_args.push("--progress=plain");
    }
    docker_args.extend(["-f", dockerfile, "-t", tag, "."]);
    let env = builder_env(buildkit);

    let scoped = scopes_work(cancel).await;
    if !scoped {
        progress
            .line("systemd can't put the build in a scope here, so it runs without CPU and memory limits")
            .await;
    }
    let outcome = if scoped {
        let mut args: Vec<&str> = vec!["--scope", "--quiet", "-p", &cpu, "-p", &mem, "docker"];
        args.extend(docker_args.iter());
        run_child(
            "systemd-run",
            &args,
            Some(workspace),
            env,
            timeout,
            cancel,
            progress,
            None,
        )
        .await
    } else {
        run_child(
            "docker",
            &docker_args,
            Some(workspace),
            env,
            timeout,
            cancel,
            progress,
            None,
        )
        .await
    };

    if outcome.success() {
        Ok(())
    } else {
        Err(failure_from("build", outcome, "docker build"))
    }
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

pub async fn compose_up(
    dir: &Path,
    file: &str,
    project: &str,
    env_file: Option<&Path>,
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
    let env = builder_env(has_buildx(cancel).await);
    let outcome = run_child(
        "docker",
        &arg_refs,
        Some(dir),
        env,
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

static HAS_BUILDX: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();
static SCOPES_WORK: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// Whether this machine's Docker has the buildx plugin BuildKit needs.
/// Asked once per daemon run: it doesn't change while the daemon runs
/// (installing buildx is followed by a restart, like any package).
async fn has_buildx(_cancel: &mut watch::Receiver<bool>) -> bool {
    *HAS_BUILDX
        .get_or_init(|| async {
            // Its own cancel: a job's cancel mustn't decide the answer for every later build.
            let (_tx, mut never) = watch::channel(false);
            capture_child(
                "docker",
                &["buildx", "version"],
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

fn builder_env(buildkit: bool) -> &'static [(&'static str, &'static str)] {
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
async fn scopes_work(_cancel: &mut watch::Receiver<bool>) -> bool {
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
