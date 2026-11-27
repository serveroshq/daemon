//! What a deploy needs from the machine, checked before anything is fetched
//! or built: Docker installed and running, the plugins the build method
//! uses, and room on disk. Each missing piece is a failure that says what to
//! do, instead of a build that dies halfway with "docker build exited 1".

use std::path::Path;
use std::time::Duration;

use daemon_jobs::{capture_child, Captured, Failure, Progress};
use tokio::sync::watch;

/// The least free space a build may start with, on the disk Docker keeps
/// images on and on the one the repository is fetched to.
pub const MIN_FREE_BYTES: u64 = 2_000_000_000;

/// What this deploy will use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Needs {
    /// `docker compose`.
    pub compose: bool,
    /// `docker buildx` (Railpack builds through it).
    pub buildx: bool,
    /// Room in Docker's folder for a new image.
    pub image_space: bool,
    /// Room in the jobs folder for the repository.
    pub fetch_space: bool,
}

pub fn docker_missing() -> Failure {
    Failure::new("docker", "Docker isn't installed on this machine")
        .with_next_step("Install Docker from the machine's page in ServerOS.")
}

fn docker_not_running(output: Vec<String>) -> Failure {
    Failure::new("docker", "Docker is installed but isn't running")
        .with_output(output)
        .with_next_step(
            "Start it on the machine with `systemctl start docker`, or install Docker again from the machine's page in ServerOS.",
        )
}

fn compose_missing() -> Failure {
    Failure::new("docker", "Docker Compose isn't installed on this machine").with_next_step(
        "Install Docker from the machine's page in ServerOS; it comes with Compose.",
    )
}

fn buildx_missing() -> Failure {
    Failure::new(
        "docker",
        "building without a Dockerfile needs Docker's buildx plugin, which isn't installed here",
    )
    .with_next_step(
        "Install Docker from the machine's page in ServerOS (it comes with buildx), or add a Dockerfile to the repository.",
    )
}

/// The server's version from `docker version`, or why there isn't one.
pub(crate) fn read_version(captured: Captured) -> Result<String, Failure> {
    match captured {
        Captured::Exited {
            code: 0, stdout, ..
        } => Ok(stdout
            .first()
            .map(|v| v.trim().to_string())
            .unwrap_or_default()),
        Captured::Exited { stderr, .. } => Err(docker_not_running(stderr)),
        Captured::Unstartable(_) => Err(docker_missing()),
        Captured::TimedOut => Err(Failure::new("docker", "Docker didn't answer")
            .with_next_step("Check Docker on the machine with `systemctl status docker`.")),
        Captured::Cancelled => Err(Failure::new("cancelled", "deploy cancelled")),
    }
}

/// The version of the Docker that runs here.
pub async fn docker_version(cancel: &mut watch::Receiver<bool>) -> Result<String, Failure> {
    read_version(
        capture_child(
            "docker",
            &["version", "--format", "{{.Server.Version}}"],
            &[],
            Duration::from_secs(20),
            cancel,
            5,
        )
        .await,
    )
}

/// Whether a docker plugin answers (`docker compose version`).
pub async fn has_plugin(plugin: &str, cancel: &mut watch::Receiver<bool>) -> bool {
    capture_child(
        "docker",
        &[plugin, "version"],
        &[],
        Duration::from_secs(20),
        cancel,
        5,
    )
    .await
    .code()
        == Some(0)
}

/// Where Docker keeps its images and containers.
async fn docker_root(cancel: &mut watch::Receiver<bool>) -> Option<String> {
    let captured = capture_child(
        "docker",
        &["info", "--format", "{{.DockerRootDir}}"],
        &[],
        Duration::from_secs(20),
        cancel,
        5,
    )
    .await;
    captured
        .stdout()
        .first()
        .map(|l| l.trim().to_string())
        .filter(|l| l.starts_with('/'))
}

/// `1.4 GB`.
pub fn gigabytes(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / 1e9)
}

/// The failure for too little room at `path`, if there is too little.
pub(crate) fn space_failure(what: &str, path: &Path, available: u64) -> Option<Failure> {
    (available < MIN_FREE_BYTES).then(|| {
        Failure::new(
            "disk",
            format!(
                "only {} is free on the disk {what} ({}), and a build needs at least {}",
                gigabytes(available),
                path.display(),
                gigabytes(MIN_FREE_BYTES)
            ),
        )
        .with_next_step(
            "Free some space: remove images nothing uses from the machine's Docker page in ServerOS, or resize the disk. Then deploy again.",
        )
    })
}

/// Free space for an unprivileged writer at `path`, like `df` shows.
pub fn available_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// Checks everything `needs` says, in order, and stops at the first thing
/// missing.
pub async fn check(
    needs: Needs,
    jobs_dir: &Path,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let version = docker_version(cancel).await?;
    progress.line(format!("Docker {version} is running")).await;

    if needs.compose && !has_plugin("compose", cancel).await {
        return Err(compose_missing());
    }
    if needs.buildx && !has_plugin("buildx", cancel).await {
        return Err(buildx_missing());
    }

    if needs.image_space {
        if let Some(root) = docker_root(cancel).await {
            let root = Path::new(&root);
            if let Some(failure) = available_bytes(root)
                .and_then(|free| space_failure("Docker keeps images on", root, free))
            {
                return Err(failure);
            }
        }
    }
    if needs.fetch_space {
        let _ = std::fs::create_dir_all(jobs_dir);
        if let Some(failure) = available_bytes(jobs_dir)
            .and_then(|free| space_failure("the repository is fetched to", jobs_dir, free))
        {
            return Err(failure);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_missing_or_stopped_says_what_to_do() {
        let missing = read_version(Captured::Unstartable("No such file".into())).unwrap_err();
        assert_eq!(missing.message, "Docker isn't installed on this machine");
        assert_eq!(
            missing.next_step.as_deref(),
            Some("Install Docker from the machine's page in ServerOS.")
        );

        let stopped = read_version(Captured::Exited {
            code: 1,
            stdout: vec![],
            stderr: vec![
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?".into(),
            ],
            truncated: false,
        })
        .unwrap_err();
        assert_eq!(stopped.message, "Docker is installed but isn't running");
        assert!(stopped
            .next_step
            .unwrap()
            .contains("systemctl start docker"));
        assert_eq!(stopped.output_tail.len(), 1);

        assert_eq!(
            read_version(Captured::Exited {
                code: 0,
                stdout: vec!["29.1.2\n".into()],
                stderr: vec![],
                truncated: false,
            })
            .unwrap(),
            "29.1.2"
        );
    }

    #[test]
    fn plugins_missing_name_the_plugin() {
        assert!(compose_missing().message.contains("Compose"));
        assert!(buildx_missing().message.contains("buildx"));
        assert!(buildx_missing().next_step.unwrap().contains("Dockerfile"));
    }

    #[test]
    fn under_two_gigabytes_free_fails_with_where_and_how_much() {
        let failure = space_failure(
            "Docker keeps images on",
            Path::new("/var/lib/docker"),
            1_400_000_000,
        )
        .unwrap();
        assert_eq!(failure.phase, "disk");
        assert_eq!(
            failure.message,
            "only 1.4 GB is free on the disk Docker keeps images on (/var/lib/docker), and a build needs at least 2.0 GB"
        );
        assert!(failure.next_step.is_some());
        assert!(space_failure("x", Path::new("/"), MIN_FREE_BYTES).is_none());
        assert!(available_bytes(Path::new("/")).is_some_and(|b| b > 0));
        assert!(available_bytes(Path::new("/no/such/folder")).is_none());
    }
}
