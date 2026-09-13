//! Building images and running containers through the Docker CLI as a
//! child process with a timeout and streamed output. Builds run under a
//! resource cap so a compile cannot starve production.

use std::path::Path;
use std::time::Duration;

use daemon_jobs::{run_child, ChildOutcome, Failure, Progress};
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

/// `docker build` in the workspace, capped by `limits` via `systemd-run`
/// when available (a transient scope with CPUQuota and MemoryMax).
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
    let docker_args = [
        "build",
        "--pull",
        "--progress=plain",
        "-f",
        dockerfile,
        "-t",
        tag,
        ".",
    ];

    let outcome = if Path::new("/run/systemd/system").is_dir() && which("systemd-run") {
        let mut args: Vec<&str> = vec!["--scope", "--quiet", "-p", &cpu, "-p", &mem, "docker"];
        args.extend(docker_args.iter());
        run_child(
            "systemd-run",
            &args,
            Some(workspace),
            &[("DOCKER_BUILDKIT", "1")],
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
            &[("DOCKER_BUILDKIT", "1")],
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

/// Start a container for a release on `port`, with the env file mounted
/// as its environment. Restart policy `unless-stopped` so it survives a
/// reboot; the daemon decides when it stops.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    name: &str,
    tag: &str,
    host_port: u16,
    container_port: u16,
    env_file: Option<&Path>,
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
    ];

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

/// Compose projects deploy as a unit: `up -d --build` in the project
/// directory. That restarts the project's containers, which the result
/// says plainly.
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
    let outcome = run_child(
        "docker",
        &arg_refs,
        Some(dir),
        &[("DOCKER_BUILDKIT", "1")],
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
}
