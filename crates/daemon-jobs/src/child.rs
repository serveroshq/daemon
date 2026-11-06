use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

use crate::progress::Progress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildOutcome {
    Exited { code: i32, tail: Vec<String> },
    TimedOut { tail: Vec<String> },
    Cancelled { tail: Vec<String> },
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
        command.process_group(0);

        if let Some((uid, gid)) = run_as {
            command.uid(uid).gid(gid);
        }
    }

    #[cfg(not(unix))]
    let _ = run_as;

    // A cancel an earlier step already saw (changed() won't fire again for
    // it): don't start this one at all.
    if *cancel.borrow() {
        return ChildOutcome::Cancelled { tail: Vec::new() };
    }

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

/// What a listing command printed: its whole stdout (up to a cap) kept apart
/// from stderr, for output that's parsed rather than shown, where the last
/// [`TAIL_LINES`] lines of a mixed stream would lose most of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Captured {
    Exited {
        code: i32,
        stdout: Vec<String>,
        /// The last lines of stderr.
        stderr: Vec<String>,
        /// More than the cap was printed; `stdout` holds the first lines.
        truncated: bool,
    },
    TimedOut,
    Cancelled,
    Unstartable(String),
}

impl Captured {
    pub fn code(&self) -> Option<i32> {
        match self {
            Captured::Exited { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub fn stdout(&self) -> &[String] {
        match self {
            Captured::Exited { stdout, .. } => stdout,
            _ => &[],
        }
    }

    pub fn stderr(&self) -> &[String] {
        match self {
            Captured::Exited { stderr, .. } => stderr,
            _ => &[],
        }
    }
}

enum Next {
    Exited(std::io::Result<std::process::ExitStatus>),
    TimedOut,
    Cancelled,
    Continue,
}

/// Runs a command to read what it prints, rather than to watch it: stdout is
/// kept whole up to `max_lines` and nothing goes to the job's live log. The
/// environment is the same clean one [`run_child`] gives.
pub async fn capture_child(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    max_lines: usize,
) -> Captured {
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

    #[cfg(unix)]
    command.process_group(0);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return Captured::Unstartable(format!("could not start {program}: {e}")),
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let out_task = tokio::spawn(async move {
        let mut kept = Vec::new();
        let mut truncated = false;
        if let Some(stdout) = stdout {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if kept.len() < max_lines {
                    kept.push(line);
                } else {
                    truncated = true;
                }
            }
        }
        (kept, truncated)
    });
    let err_task = tokio::spawn(async move {
        let mut tail = std::collections::VecDeque::with_capacity(TAIL_LINES);
        if let Some(stderr) = stderr {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tail.len() == TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
        }
        tail.into_iter().collect::<Vec<String>>()
    });

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut watching = true;

    let status = loop {
        let next = tokio::select! {
            status = child.wait() => Next::Exited(status),
            _ = &mut deadline => Next::TimedOut,
            changed = cancel.changed(), if watching => match changed {
                Ok(()) if *cancel.borrow() => Next::Cancelled,
                Ok(()) => Next::Continue,
                Err(_) => {
                    watching = false;
                    Next::Continue
                }
            },
        };

        match next {
            Next::Exited(status) => break status,
            Next::TimedOut => {
                kill_group(&mut child).await;
                return Captured::TimedOut;
            }
            Next::Cancelled => {
                kill_group(&mut child).await;
                return Captured::Cancelled;
            }
            Next::Continue => {}
        }
    };

    let status = match status {
        Ok(status) => status,
        Err(e) => return Captured::Unstartable(e.to_string()),
    };

    // Something the command left running could hold the pipes open; don't
    // wait on it for ever.
    let grace = Duration::from_secs(10);
    let (stdout, truncated) = match tokio::time::timeout(grace, out_task).await {
        Ok(Ok(read)) => read,
        _ => (Vec::new(), false),
    };
    let stderr = match tokio::time::timeout(grace, err_task).await {
        Ok(Ok(tail)) => tail,
        _ => Vec::new(),
    };

    Captured::Exited {
        code: status.code().unwrap_or(-1),
        stdout,
        stderr,
        truncated,
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
    async fn a_cancel_an_earlier_step_saw_stops_the_next_one_starting() {
        let (progress, _rx) = progress();
        let (cancel_tx, mut cancel) = watch::channel(false);
        cancel_tx.send(true).unwrap();
        // The earlier step consumed the change; this one must still see it.
        cancel.borrow_and_update();
        let marker = std::env::temp_dir().join(format!("serveros-cancel-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);

        let outcome = run_child(
            "touch",
            &[marker.to_str().unwrap()],
            None,
            &[],
            Duration::from_secs(5),
            &mut cancel,
            &progress,
            None,
        )
        .await;

        assert!(matches!(outcome, ChildOutcome::Cancelled { .. }));
        assert!(!marker.exists(), "the command must not have run");
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
    async fn capture_keeps_all_of_stdout_up_to_the_cap() {
        let (_cancel_tx, mut cancel) = watch::channel(false);

        let captured = capture_child(
            "sh",
            &["-c", "seq 1 120; echo oops >&2; exit 2"],
            &[],
            Duration::from_secs(5),
            &mut cancel,
            5000,
        )
        .await;

        assert_eq!(captured.code(), Some(2));
        assert_eq!(captured.stdout().len(), 120, "more than the 40-line tail");
        assert_eq!(captured.stdout()[0], "1");
        assert_eq!(captured.stderr(), &["oops".to_string()]);

        let capped = capture_child(
            "sh",
            &["-c", "seq 1 120"],
            &[],
            Duration::from_secs(5),
            &mut cancel,
            100,
        )
        .await;
        assert!(matches!(
            capped,
            Captured::Exited {
                truncated: true,
                ..
            }
        ));
        assert_eq!(capped.stdout().len(), 100);
    }

    #[tokio::test]
    async fn capture_times_out_and_can_be_cancelled() {
        let (_cancel_tx, mut cancel) = watch::channel(false);
        let timed_out = capture_child(
            "sh",
            &["-c", "sleep 30"],
            &[],
            Duration::from_millis(300),
            &mut cancel,
            10,
        )
        .await;
        assert_eq!(timed_out, Captured::TimedOut);

        let (cancel_tx, mut cancel) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = cancel_tx.send(true);
        });
        let cancelled = capture_child(
            "sh",
            &["-c", "sleep 30"],
            &[],
            Duration::from_secs(30),
            &mut cancel,
            10,
        )
        .await;
        assert_eq!(cancelled, Captured::Cancelled);
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
