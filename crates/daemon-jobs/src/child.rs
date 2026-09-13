//! Running an external program for a job: output streamed line by line
//! into the job log, a hard timeout, and the child killed (with its
//! process group) when the deadline or a cancellation arrives.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

use crate::progress::Progress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildOutcome {
    Exited {
        code: i32,
        tail: Vec<String>,
    },
    TimedOut {
        tail: Vec<String>,
    },
    Cancelled {
        tail: Vec<String>,
    },
    /// The program could not be started at all.
    Unstartable(String),
}

impl ChildOutcome {
    pub fn success(&self) -> bool {
        matches!(self, ChildOutcome::Exited { code: 0, .. })
    }

    pub fn tail(&self) -> &[String] {
        match self {
            ChildOutcome::Exited { tail, .. }
            | ChildOutcome::TimedOut { tail }
            | ChildOutcome::Cancelled { tail } => tail,
            ChildOutcome::Unstartable(_) => &[],
        }
    }
}

const TAIL_LINES: usize = 40;

/// Run `program args` in `cwd` with `env` on top of a minimal environment.
/// Lines from stdout and stderr go to `progress` as they arrive.
#[allow(clippy::too_many_arguments)]
pub async fn run_child(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: &[(&str, &str)],
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
    run_as: Option<(u32, u32)>,
) -> ChildOutcome {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C.UTF-8")
        .env("HOME", "/var/lib/serveros")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if let Some(dir) = cwd {
        command.current_dir(dir);
    }

    #[cfg(unix)]
    {
        // Own process group, so killing the child kills what it spawned.
        command.process_group(0);

        if let Some((uid, gid)) = run_as {
            command.uid(uid).gid(gid);
        }
    }

    #[cfg(not(unix))]
    let _ = run_as;

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return ChildOutcome::Unstartable(format!("could not start {program}: {e}")),
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(256);

    for reader in [
        stdout.map(|s| Box::pin(s) as std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>),
        stderr.map(|s| Box::pin(s) as _),
    ]
    .into_iter()
    .flatten()
    {
        let tx = line_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(line_tx);

    let mut tail: std::collections::VecDeque<String> =
        std::collections::VecDeque::with_capacity(TAIL_LINES);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut batch: Vec<String> = Vec::new();
    let mut flush = tokio::time::interval(Duration::from_millis(250));
    let mut status = None;
    let mut ended: Option<fn(Vec<String>) -> ChildOutcome> = None;

    loop {
        tokio::select! {
            line = line_rx.recv() => match line {
                Some(line) => {
                    if tail.len() == TAIL_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(progress.scrub(&line));
                    batch.push(line);
                }
                None => {
                    // Output closed; wait for the exit status.
                    if status.is_none() {
                        status = Some(child.wait().await.ok());
                    }
                    break;
                }
            },
            _ = flush.tick() => {
                if !batch.is_empty() {
                    progress.log(std::mem::take(&mut batch)).await;
                }
            }
            _ = &mut deadline => {
                kill_group(&mut child).await;
                ended = Some(|tail| ChildOutcome::TimedOut { tail });
                break;
            }
            changed = cancel.changed() => {
                if changed.is_ok() && *cancel.borrow() {
                    kill_group(&mut child).await;
                    ended = Some(|tail| ChildOutcome::Cancelled { tail });
                    break;
                }
            }
        }
    }

    // Drain anything still buffered.
    while let Ok(line) = line_rx.try_recv() {
        if tail.len() == TAIL_LINES {
            tail.pop_front();
        }
        tail.push_back(progress.scrub(&line));
        batch.push(line);
    }

    if !batch.is_empty() {
        progress.log(batch).await;
    }

    let tail: Vec<String> = tail.into_iter().collect();

    if let Some(make) = ended {
        return make(tail);
    }

    let status = match status {
        Some(Some(s)) => s,
        _ => match child.wait().await {
            Ok(s) => s,
            Err(e) => return ChildOutcome::Unstartable(e.to_string()),
        },
    };

    ChildOutcome::Exited {
        code: status.code().unwrap_or(-1),
        tail,
    }
}

async fn kill_group(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        unsafe {
            libc_kill(-(pid as i32), 15);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        unsafe {
            libc_kill(-(pid as i32), 9);
        }
    }

    let _ = child.kill().await;
}

#[cfg(unix)]
unsafe fn libc_kill(pid: i32, signal: i32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    kill(pid, signal);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use daemon_state::State;
    use uuid::Uuid;

    use super::*;

    fn progress() -> (
        Progress,
        tokio::sync::mpsc::Receiver<daemon_protocol::JobUpdate>,
    ) {
        let state = Arc::new(State::in_memory().unwrap());
        let id = Uuid::new_v4();
        state.record_job(id, "test", "test", "{}").unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        (Progress::new(id, state, tx, vec!["hunter2".into()]), rx)
    }

    #[tokio::test]
    async fn streams_output_and_reports_the_exit_code() {
        let (progress, mut rx) = progress();
        let (_cancel_tx, mut cancel) = watch::channel(false);

        let outcome = run_child(
            "sh",
            &["-c", "echo one; echo password=hunter2 >&2; exit 3"],
            None,
            &[],
            Duration::from_secs(5),
            &mut cancel,
            &progress,
            None,
        )
        .await;

        assert!(matches!(outcome, ChildOutcome::Exited { code: 3, .. }));
        assert!(outcome.tail().iter().any(|l| l == "one"));
        assert!(
            outcome.tail().iter().any(|l| l == "password=[redacted]"),
            "tail is redacted: {:?}",
            outcome.tail()
        );

        let mut logged = Vec::new();
        while let Ok(update) = rx.try_recv() {
            logged.extend(update.log);
        }
        assert!(logged.iter().any(|l| l == "password=[redacted]"));
    }

    #[tokio::test]
    async fn times_out_and_kills_the_child() {
        let (progress, _rx) = progress();
        let (_cancel_tx, mut cancel) = watch::channel(false);
        let started = std::time::Instant::now();

        let outcome = run_child(
            "sh",
            &["-c", "sleep 30"],
            None,
            &[],
            Duration::from_millis(300),
            &mut cancel,
            &progress,
            None,
        )
        .await;

        assert!(matches!(outcome, ChildOutcome::TimedOut { .. }));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn cancellation_stops_a_running_child() {
        let (progress, _rx) = progress();
        let (cancel_tx, mut cancel) = watch::channel(false);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = cancel_tx.send(true);
        });

        let outcome = run_child(
            "sh",
            &["-c", "sleep 30"],
            None,
            &[],
            Duration::from_secs(30),
            &mut cancel,
            &progress,
            None,
        )
        .await;

        assert!(matches!(outcome, ChildOutcome::Cancelled { .. }));
    }

    #[tokio::test]
    async fn a_missing_program_is_unstartable_not_a_panic() {
        let (progress, _rx) = progress();
        let (_cancel_tx, mut cancel) = watch::channel(false);

        let outcome = run_child(
            "/definitely/not/here",
            &[],
            None,
            &[],
            Duration::from_secs(1),
            &mut cancel,
            &progress,
            None,
        )
        .await;

        assert!(matches!(outcome, ChildOutcome::Unstartable(_)));
    }
}
