//! `service_exec`: a command run inside a service's container, with
//! settings handed to it by name so their values (a database password for
//! a copy) stay out of the command line, the job's log and `ps`.

use std::collections::BTreeMap;
use std::time::Duration;

use daemon_jobs::{run_child, ChildOutcome, Failure, JobContext};
use daemon_protocol::Job;
use serde_json::{json, Value};

/// Long enough to copy a database from one machine to another.
pub const MAX_EXEC: Duration = Duration::from_secs(3600);

/// Without a timeout from the panel, a command gets this long.
pub const DEFAULT_EXEC: Duration = Duration::from_secs(60);

/// Runs `sh -c command` in `container` with `docker exec`.
pub async fn exec(
    ctx: &JobContext,
    container: &str,
    command: &str,
    timeout_secs: Option<u64>,
    env: &BTreeMap<String, String>,
) -> Result<Value, Failure> {
    exec_with("docker", ctx, container, command, timeout_secs, env).await
}

/// [`exec`] with the docker program named, so tests can stand in for it.
#[doc(hidden)]
pub async fn exec_with(
    docker: &str,
    ctx: &JobContext,
    container: &str,
    command: &str,
    timeout_secs: Option<u64>,
    env: &BTreeMap<String, String>,
) -> Result<Value, Failure> {
    // Checked before anything runs or is logged.
    if let Some(bad) = env.keys().find(|name| !valid_env_name(name)) {
        return Err(Failure::new("exec", format!("{bad} isn't a setting name"))
            .with_next_step("Setting names are letters, digits and underscores, not starting with a digit, and not PATH, HOME or LC_ALL."));
    }

    let timeout = exec_timeout(timeout_secs);
    let mut cancel = ctx.cancel.clone();

    ctx.progress.line(format!("$ {command}")).await;

    // Each setting goes in by name only (`-e NAME`): docker reads its value
    // from our environment, so it never appears in an argument list.
    let args = exec_args(container, command, env);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    match run_child(
        docker,
        &args,
        None,
        &pairs,
        timeout,
        &mut cancel,
        &ctx.progress,
        None,
    )
    .await
    {
        ChildOutcome::Exited { code, .. } => Ok(json!({ "exit_code": code })),
        ChildOutcome::TimedOut { .. } => Err(Failure::new(
            "exec",
            format!("the command was still running after {}s", timeout.as_secs()),
        )
        .with_next_step("Run long tasks as their own service, or raise the timeout.")),
        ChildOutcome::Cancelled { .. } => Err(Failure::new("cancelled", "command cancelled")),
        ChildOutcome::Unstartable(e) => Err(Failure::new("exec", e)),
    }
}

/// What the panel asked for, a minute if nothing, and never over an hour.
fn exec_timeout(timeout_secs: Option<u64>) -> Duration {
    timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_EXEC)
        .min(MAX_EXEC)
}

/// `exec -e NAME ... CONTAINER sh -c COMMAND`: names, never values.
fn exec_args(container: &str, command: &str, env: &BTreeMap<String, String>) -> Vec<String> {
    let mut args = vec!["exec".to_string()];
    for name in env.keys() {
        args.push("-e".into());
        args.push(name.clone());
    }
    args.extend([container, "sh", "-c", command].map(String::from));
    args
}

/// The values a `service_exec` job carries, for the runner to scrub from
/// its log should the command print one.
pub fn secrets(job: &Job) -> Vec<String> {
    match job {
        Job::ServiceExec { env, .. } => env.values().cloned().collect(),
        _ => Vec::new(),
    }
}

/// Letters, digits and underscores, not starting with a digit, and none of
/// the names the runner sets itself.
pub fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !matches!(name, "PATH" | "HOME" | "LC_ALL")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Arc;

    use daemon_jobs::{Handler, HandlerFuture, Runner};
    use daemon_protocol::{Actor, ActorKind, Command, JobState, JobUpdate};
    use daemon_state::State;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    const SECRET: &str = "s3cret-Pa55word-for-the-copy";

    #[test]
    fn names() {
        assert!(valid_env_name("SOURCE_URL"));
        assert!(valid_env_name("_X1"));
        assert!(valid_env_name("source_password"));
        assert!(!valid_env_name("1X"));
        assert!(!valid_env_name("A-B"));
        assert!(!valid_env_name("A=B"));
        assert!(!valid_env_name("A B"));
        assert!(!valid_env_name("ÉTÉ"));
        assert!(!valid_env_name("PATH"));
        assert!(!valid_env_name("HOME"));
        assert!(!valid_env_name("LC_ALL"));
        assert!(!valid_env_name(""));
    }

    #[test]
    fn arguments_carry_names_not_values() {
        let env = BTreeMap::from([
            ("SOURCE_PASSWORD".to_string(), SECRET.to_string()),
            ("SOURCE_HOST".to_string(), "10.64.1.3".to_string()),
        ]);
        let args = exec_args("pg", "pg_dump", &env);

        assert_eq!(
            args,
            [
                "exec",
                "-e",
                "SOURCE_HOST",
                "-e",
                "SOURCE_PASSWORD",
                "pg",
                "sh",
                "-c",
                "pg_dump"
            ]
        );
        assert!(!args.iter().any(|a| a.contains(SECRET)));
    }

    #[test]
    fn secrets_are_the_values_of_an_exec_job() {
        let job = Job::ServiceExec {
            service: "docker:abc".into(),
            command: "true".into(),
            timeout_secs: None,
            env: BTreeMap::from([("SOURCE_PASSWORD".to_string(), SECRET.to_string())]),
        };
        assert_eq!(secrets(&job), vec![SECRET.to_string()]);
        assert!(secrets(&Job::Discover).is_empty());
    }

    // ---- through the job runner, with a stand-in for docker

    /// Calls `exec_with` with the stand-in, as serverosd's handler calls
    /// `exec`, and scrubs the job's settings as serverosd does.
    struct ExecHandler {
        docker: String,
    }

    impl Handler for ExecHandler {
        fn handle(&self, ctx: daemon_jobs::JobContext) -> HandlerFuture {
            let docker = self.docker.clone();
            Box::pin(async move {
                let Job::ServiceExec {
                    service,
                    command,
                    timeout_secs,
                    env,
                } = ctx.command.job.clone()
                else {
                    return Err(Failure::new("test", "only service_exec"));
                };
                exec_with(&docker, &ctx, &service, &command, timeout_secs, &env).await
            })
        }

        fn known_secrets(&self, job: &Job) -> Vec<String> {
            secrets(job)
        }
    }

    /// A `docker` that records its arguments and the settings it was handed
    /// (as `docker exec -e NAME` would read them), then runs the command
    /// with them, the way the command would run in the container.
    fn fake_docker(dir: &Path) -> String {
        let path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$@" > '{dir}/argv'
env > '{dir}/environ'
touch '{dir}/ran'
# drop "exec", the -e NAME pairs and the container; run what's after sh -c
shift
while [ "$1" = "-e" ]; do shift 2; done
shift
exec "$@"
"#,
            dir = dir.display()
        );
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path.display().to_string()
    }

    fn exec_job(command: &str, env: &[(&str, &str)]) -> Command {
        Command {
            actor: Actor {
                kind: ActorKind::Panel,
                name: "test".into(),
                id: None,
                via: None,
                client: None,
                tool: None,
                call: None,
            },
            confirmed: true,
            timeout_secs: None,
            job: Job::ServiceExec {
                service: "pg".into(),
                command: command.into(),
                timeout_secs: Some(30),
                env: env
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
        }
    }

    /// Runs the job; returns every update, and what state.db kept of it: each
    /// line of its log, then the job as recorded.
    async fn run(dir: &Path, command: Command) -> (Vec<JobUpdate>, Vec<String>) {
        let state = Arc::new(State::in_memory().unwrap());
        let (tx, mut rx) = mpsc::channel(256);
        let runner = Runner::new(
            Arc::clone(&state),
            Arc::new(ExecHandler {
                docker: fake_docker(dir),
            }),
            tx,
            Duration::from_secs(60),
        );
        let id = Uuid::new_v4();
        runner.submit(id, command).await;

        let mut updates = Vec::new();
        while let Some(update) = rx.recv().await {
            let done = update.state.is_terminal();
            updates.push(update);
            if done {
                break;
            }
        }
        let record = state.job(id).unwrap().unwrap();
        let stored = record
            .log
            .lines()
            .map(String::from)
            .chain([record.payload])
            .collect();
        (updates, stored)
    }

    fn everything_said(updates: &[JobUpdate]) -> String {
        updates
            .iter()
            .map(|u| serde_json::to_string(u).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn a_bad_setting_name_is_refused_before_anything_runs() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["1X", "A-B", "PATH", "HOME", "LC_ALL", "A=B", ""] {
            let (updates, _) = run(
                dir.path(),
                exec_job("echo hi", &[("SOURCE_HOST", "10.64.1.3"), (bad, "x")]),
            )
            .await;
            let last = updates.last().unwrap();

            assert_eq!(last.state, JobState::Failed, "{bad}");
            assert!(
                last.error
                    .as_ref()
                    .unwrap()
                    .message
                    .contains("isn't a setting name"),
                "{bad}: {:?}",
                last.error
            );
            assert!(!dir.path().join("ran").exists(), "{bad}: docker ran");
            assert!(
                !updates
                    .iter()
                    .any(|u| u.log.iter().any(|l| l == "$ echo hi")),
                "{bad}: the command was logged as if it ran"
            );
        }
    }

    #[tokio::test]
    async fn settings_reach_the_command_by_name_only() {
        let dir = tempfile::tempdir().unwrap();
        let (updates, stored) = run(
            dir.path(),
            exec_job(
                "[ \"$SOURCE_PASSWORD\" = '' ] && exit 9; echo \"host is $SOURCE_HOST\"",
                &[("SOURCE_HOST", "10.64.1.3"), ("SOURCE_PASSWORD", SECRET)],
            ),
        )
        .await;
        let last = updates.last().unwrap();
        assert_eq!(last.state, JobState::Succeeded, "{:?}", last.error);
        assert_eq!(last.result, Some(json!({"exit_code": 0})));

        // docker got names only; the values were in its environment.
        let argv = std::fs::read_to_string(dir.path().join("argv")).unwrap();
        assert!(argv.contains("SOURCE_PASSWORD\n"), "{argv}");
        assert!(!argv.contains(SECRET), "{argv}");
        let environ = std::fs::read_to_string(dir.path().join("environ")).unwrap();
        assert!(environ.contains(&format!("SOURCE_PASSWORD={SECRET}")));

        // The log has the command as written, and none of the values.
        let said = everything_said(&updates);
        assert!(stored
            .iter()
            .any(|l| l.starts_with("$ [ \"$SOURCE_PASSWORD\"")));
        assert!(!said.contains(SECRET), "{said}");
        assert!(!stored.iter().any(|l| l.contains(SECRET)), "{stored:?}");
    }

    #[tokio::test]
    async fn a_value_the_command_prints_is_scrubbed_from_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let (updates, stored) = run(
            dir.path(),
            exec_job(
                "echo \"oops: $SOURCE_PASSWORD\"; echo \"$SOURCE_PASSWORD\" >&2; exit 3",
                &[("SOURCE_PASSWORD", SECRET)],
            ),
        )
        .await;
        let last = updates.last().unwrap();

        // A command that fails still finishes the job; its code is the result.
        assert_eq!(last.state, JobState::Succeeded, "{:?}", last.error);
        assert_eq!(last.result, Some(json!({"exit_code": 3})));
        let said = everything_said(&updates);
        assert!(said.contains("oops: [redacted]"), "{said}");
        assert!(!said.contains(SECRET), "{said}");
        assert!(!stored.iter().any(|l| l.contains(SECRET)), "{stored:?}");
    }

    #[tokio::test]
    async fn older_panels_send_no_settings() {
        let dir = tempfile::tempdir().unwrap();
        let (updates, _) = run(dir.path(), exec_job("echo plain", &[])).await;

        assert_eq!(updates.last().unwrap().state, JobState::Succeeded);
        let argv = std::fs::read_to_string(dir.path().join("argv")).unwrap();
        assert_eq!(argv, "exec\npg\nsh\n-c\necho plain\n");
    }

    #[tokio::test]
    async fn the_panel_cannot_ask_for_more_than_an_hour() {
        assert_eq!(exec_timeout(Some(7200)), Duration::from_secs(3600));
        assert_eq!(exec_timeout(Some(3600)), Duration::from_secs(3600));
        assert_eq!(exec_timeout(Some(300)), Duration::from_secs(300));
        assert_eq!(exec_timeout(None), Duration::from_secs(60));

        // And the job really is stopped when its time is up.
        let dir = tempfile::tempdir().unwrap();
        let mut command = exec_job("sleep 5", &[]);
        if let Job::ServiceExec { timeout_secs, .. } = &mut command.job {
            *timeout_secs = Some(1);
        }
        let (updates, _) = run(dir.path(), command).await;
        let last = updates.last().unwrap();
        assert_eq!(last.state, JobState::Failed);
        assert!(last
            .error
            .as_ref()
            .unwrap()
            .message
            .contains("still running after 1s"));
    }

    /// Against a real container: `cargo test -p daemon-services -- --ignored`
    /// on a machine with Docker and the alpine image.
    #[tokio::test]
    #[ignore = "needs Docker"]
    async fn real_docker_exec_hands_settings_in_by_name() {
        let name = format!("serveros-exec-test-{}", std::process::id());
        let started = std::process::Command::new("docker")
            .args([
                "run", "-d", "--rm", "--name", &name, "alpine:3", "sleep", "60",
            ])
            .status()
            .unwrap();
        assert!(started.success());

        let state = Arc::new(State::in_memory().unwrap());
        let (tx, mut rx) = mpsc::channel(256);
        let runner = Runner::new(
            Arc::clone(&state),
            Arc::new(ExecHandler {
                docker: "docker".into(),
            }),
            tx,
            Duration::from_secs(60),
        );
        let mut command = exec_job(
            "test \"$SOURCE_PASSWORD\" = \"$EXPECT\" && echo matched",
            &[("SOURCE_PASSWORD", SECRET), ("EXPECT", SECRET)],
        );
        if let Job::ServiceExec { service, .. } = &mut command.job {
            *service = name.clone();
        }
        runner.submit(Uuid::new_v4(), command).await;
        let mut updates = Vec::new();
        while let Some(update) = rx.recv().await {
            let done = update.state.is_terminal();
            updates.push(update);
            if done {
                break;
            }
        }
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &name])
            .output();

        let said = everything_said(&updates);
        assert_eq!(
            updates.last().unwrap().result,
            Some(json!({"exit_code": 0})),
            "{said}"
        );
        assert!(said.contains("matched"), "{said}");
        assert!(!said.contains(SECRET), "{said}");
    }
}
