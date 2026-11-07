use std::process::Stdio;
use std::time::{Duration, Instant};

use daemon_protocol::{StreamFrame, StreamKind};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{frame, LINE_RATE_CAP};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Unit(String),
    Container(String),
    File(String),
}

impl Source {
    pub fn parse(source: &str) -> Option<Self> {
        let (kind, rest) = source.split_once(':')?;

        match kind {
            "unit" if daemon_unit_ok(rest) => Some(Source::Unit(rest.into())),
            "docker"
                if rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                    && !rest.is_empty() =>
            {
                Some(Source::Container(rest.into()))
            }
            "file" if rest.starts_with('/') => Some(Source::File(rest.into())),
            _ => None,
        }
    }

    fn command(&self, backlog: u32) -> Command {
        let n = backlog.to_string();
        let mut cmd = match self {
            Source::Unit(unit) => {
                let mut c = Command::new("journalctl");
                c.args([
                    "-u",
                    unit,
                    "-n",
                    &n,
                    "-f",
                    "--no-pager",
                    "-o",
                    "short-iso",
                    "--no-hostname",
                ]);
                c
            }
            Source::Container(id) => {
                let mut c = Command::new("docker");
                c.args(["logs", "--tail", &n, "-f", "--timestamps", id]);
                c
            }
            Source::File(path) => {
                let mut c = Command::new("tail");
                c.args(["-n", &n, "-F", path]);
                c
            }
        };

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env("LC_ALL", "C.UTF-8");
        cmd
    }
}

fn daemon_unit_ok(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
}

pub struct LogTail {
    child: Child,
}

impl LogTail {
    pub fn start(
        session: Uuid,
        source: &Source,
        backlog: u32,
        out: mpsc::Sender<StreamFrame>,
    ) -> std::io::Result<Self> {
        let mut child = source.command(backlog.clamp(0, 5000)).spawn()?;
        // The service skip rules match against; a file has none.
        let service = match source {
            Source::Unit(name) | Source::Container(name) => Some(name.clone()),
            Source::File(_) => None,
        };
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        for reader in [
            stdout.map(|s| Box::pin(s) as std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>),
            stderr.map(|s| Box::pin(s) as _),
        ]
        .into_iter()
        .flatten()
        {
            let tx = out.clone();
            let service = service.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(reader).lines();
                let mut limiter = RateLimiter::new(LINE_RATE_CAP);

                while let Ok(Some(line)) = lines.next_line().await {
                    if daemon_core::logskip::skips_line(service.as_deref(), &line) {
                        continue;
                    }
                    match limiter.admit() {
                        Admit::Send => {
                            if tx
                                .send(frame(
                                    session,
                                    StreamKind::LogLine,
                                    daemon_core::ipmask::outgoing(&line).as_bytes(),
                                    false,
                                ))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Admit::Drop => {}
                        Admit::Summarise(dropped) => {
                            let marker = format!("[... {dropped} lines dropped: logging faster than {LINE_RATE_CAP}/s ...]");
                            if tx
                                .send(frame(
                                    session,
                                    StreamKind::LogLine,
                                    marker.as_bytes(),
                                    false,
                                ))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            if tx
                                .send(frame(
                                    session,
                                    StreamKind::LogLine,
                                    daemon_core::ipmask::outgoing(&line).as_bytes(),
                                    false,
                                ))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                }

                let _ = tx
                    .send(frame(session, StreamKind::LogLine, b"", true))
                    .await;
            });
        }

        Ok(Self { child })
    }

    pub async fn stop(mut self) {
        let _ = self.child.kill().await;
    }
}

pub enum Admit {
    Send,
    Drop,
    Summarise(usize),
}

pub struct RateLimiter {
    cap: usize,
    window: Instant,
    sent: usize,
    dropped: usize,
}

impl RateLimiter {
    pub fn new(cap: usize) -> Self {
        Self::new_at(cap, Instant::now())
    }

    pub fn new_at(cap: usize, now: Instant) -> Self {
        Self {
            cap,
            window: now,
            sent: 0,
            dropped: 0,
        }
    }

    pub fn admit(&mut self) -> Admit {
        self.admit_at(Instant::now())
    }

    pub fn admit_at(&mut self, now: Instant) -> Admit {
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.sent = 0;

            if self.dropped > 0 {
                let dropped = std::mem::take(&mut self.dropped);
                self.sent = 1;
                return Admit::Summarise(dropped);
            }
        }

        if self.sent < self.cap {
            self.sent += 1;
            Admit::Send
        } else {
            self.dropped += 1;
            Admit::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sources_and_rejects_hostile_ones() {
        assert_eq!(
            Source::parse("unit:nginx.service"),
            Some(Source::Unit("nginx.service".into()))
        );
        assert_eq!(
            Source::parse("docker:shop-web-1"),
            Some(Source::Container("shop-web-1".into()))
        );
        assert_eq!(
            Source::parse("file:/var/log/app.log"),
            Some(Source::File("/var/log/app.log".into()))
        );
        assert_eq!(Source::parse("unit:x; rm -rf /"), None);
        assert_eq!(Source::parse("file:relative.log"), None);
        assert_eq!(Source::parse("shell:ls"), None);
    }

    #[test]
    fn rate_limiter_drops_then_summarises() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new_at(2, start);

        assert!(matches!(limiter.admit_at(start), Admit::Send));
        assert!(matches!(limiter.admit_at(start), Admit::Send));
        assert!(matches!(limiter.admit_at(start), Admit::Drop));
        assert!(matches!(limiter.admit_at(start), Admit::Drop));

        let later = start + Duration::from_secs(1);
        assert!(matches!(limiter.admit_at(later), Admit::Summarise(2)));
        assert!(matches!(limiter.admit_at(later), Admit::Send));
    }

    #[tokio::test]
    async fn tails_a_file_and_redacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        std::fs::write(&path, "boot ok\nAPI_TOKEN=abc123\n").unwrap();
        let (tx, mut rx) = mpsc::channel(16);

        let tail = LogTail::start(
            Uuid::new_v4(),
            &Source::File(path.to_string_lossy().into()),
            10,
            tx,
        )
        .unwrap();
        let mut lines = Vec::new();

        while lines.len() < 2 {
            let f = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            lines.push(String::from_utf8(crate::decode(&f)).unwrap());
        }

        assert_eq!(lines, vec!["boot ok", "API_TOKEN=[redacted]"]);
        tail.stop().await;
    }
}
