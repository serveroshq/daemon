//! Fetching source by commit SHA into a job workspace. Deploy keys are
//! generated on the machine and only the public half ever leaves.

use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_jobs::{run_child, ChildOutcome, Failure, Progress};
use tokio::sync::watch;

/// Where per-service deploy keys live: `<keys_dir>/<service>` (0600) and
/// `<keys_dir>/<service>.pub`.
pub fn key_paths(keys_dir: &Path, service: &str) -> (PathBuf, PathBuf) {
    let private = keys_dir.join(sanitise(service));
    let public = keys_dir.join(format!("{}.pub", sanitise(service)));
    (private, public)
}

pub fn sanitise(service: &str) -> String {
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

/// Generate a deploy key if none exists; return the public key text.
pub async fn ensure_deploy_key(
    keys_dir: &Path,
    service: &str,
    progress: &Progress,
) -> Result<String, Failure> {
    std::fs::create_dir_all(keys_dir).map_err(|e| {
        Failure::new(
            "deploy-key",
            format!("could not create {}: {e}", keys_dir.display()),
        )
    })?;
    let (private, public) = key_paths(keys_dir, service);

    if !private.exists() {
        let (_tx, mut cancel) = watch::channel(false);
        let comment = format!("serveros-{}", sanitise(service));
        let outcome = run_child(
            "ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                &comment,
                "-f",
                &private.to_string_lossy(),
            ],
            None,
            &[],
            Duration::from_secs(30),
            &mut cancel,
            progress,
            None,
        )
        .await;

        if !outcome.success() {
            return Err(Failure::new("deploy-key", "ssh-keygen failed")
                .with_output(outcome.tail().to_vec())
                .with_next_step("Install openssh-client on the machine."));
        }
    }

    std::fs::read_to_string(&public)
        .map(|k| k.trim().to_string())
        .map_err(|e| {
            Failure::new(
                "deploy-key",
                format!("could not read {}: {e}", public.display()),
            )
        })
}

pub fn valid_commit(sha: &str) -> bool {
    (7..=64).contains(&sha.len()) && sha.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn valid_repo(url: &str) -> bool {
    !url.contains(char::is_whitespace)
        && !url.starts_with('-')
        && (url.starts_with("https://")
            || url.starts_with("ssh://")
            || url.starts_with("git@")
            || url.starts_with("file://"))
}

/// Shallow-fetch exactly `commit` from `repo` into `workspace`. Refuses
/// anything that is not a full commit: branches move, deploys must not.
pub async fn fetch(
    repo: &str,
    commit: &str,
    workspace: &Path,
    deploy_key: Option<&Path>,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    if !valid_commit(commit) {
        return Err(Failure::new(
            "fetch",
            format!("{commit:?} is not a commit SHA; deploys pin to a commit, not a branch"),
        ));
    }

    if !valid_repo(repo) {
        return Err(Failure::new(
            "fetch",
            format!("{repo:?} is not a repository URL ServerOS will fetch from"),
        ));
    }

    std::fs::create_dir_all(workspace)
        .map_err(|e| Failure::new("fetch", format!("could not create workspace: {e}")))?;

    let ssh_command = match deploy_key {
        Some(key) => format!(
            "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes",
            key.to_string_lossy()
        ),
        None => "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new".into(),
    };
    let env = [
        ("GIT_SSH_COMMAND", ssh_command.as_str()),
        ("GIT_TERMINAL_PROMPT", "0"),
    ];

    let steps: [(&str, Vec<&str>); 4] = [
        ("init", vec!["init", "-q"]),
        ("remote", vec!["remote", "add", "origin", repo]),
        (
            "fetch",
            vec!["fetch", "-q", "--depth", "1", "origin", commit],
        ),
        ("checkout", vec!["checkout", "-q", "FETCH_HEAD"]),
    ];

    for (name, args) in steps {
        let outcome = run_child(
            "git",
            &args,
            Some(workspace),
            &env,
            timeout,
            cancel,
            progress,
            None,
        )
        .await;

        match outcome {
            ChildOutcome::Exited { code: 0, .. } => {}
            ChildOutcome::Cancelled { tail } => {
                return Err(
                    Failure::new("cancelled", "deploy cancelled during fetch").with_output(tail)
                )
            }
            ChildOutcome::TimedOut { tail } => {
                return Err(Failure::new("fetch", format!("git {name} timed out"))
                    .with_output(tail)
                    .with_next_step("Check the repository is reachable from this machine."))
            }
            ChildOutcome::Unstartable(e) => {
                return Err(Failure::new("fetch", e).with_next_step("Install git on the machine."))
            }
            ChildOutcome::Exited { code, tail } => {
                let hint = if tail.iter().any(|l| {
                    l.contains("Permission denied") || l.contains("could not read Username")
                }) {
                    "Add the machine's deploy key to the repository (Settings → Deploy keys)."
                } else if tail
                    .iter()
                    .any(|l| l.contains("couldn't find remote ref") || l.contains("not our ref"))
                {
                    "The commit is not in the repository; push it first."
                } else {
                    "Check the repository URL and the machine's network access."
                };

                return Err(Failure::new("fetch", format!("git {name} exited {code}"))
                    .with_output(tail)
                    .with_next_step(hint));
            }
        }
    }

    progress
        .line(format!("fetched {commit} into {}", workspace.display()))
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_commit_shas_and_real_urls_are_accepted() {
        assert!(valid_commit("a1b2c3d"));
        assert!(valid_commit(&"f".repeat(40)));
        assert!(!valid_commit("main"));
        assert!(!valid_commit("HEAD~1"));

        assert!(valid_repo("git@github.com:serveroshq/app.git"));
        assert!(valid_repo("https://github.com/serveroshq/app.git"));
        assert!(!valid_repo("--upload-pack=evil"));
        assert!(!valid_repo("ftp://x"));
    }

    #[test]
    fn key_paths_are_sanitised() {
        let (private, public) = key_paths(Path::new("/var/lib/serveros/keys"), "shop/web");

        assert_eq!(private, PathBuf::from("/var/lib/serveros/keys/shop-web"));
        assert_eq!(public, PathBuf::from("/var/lib/serveros/keys/shop-web.pub"));
    }
}
