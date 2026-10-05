//! Shipping service logs to the panel, which keeps them and makes them
//! searchable. Every running container is followed with `docker logs -f`,
//! and the systemd services discovery found are followed together through
//! one `journalctl -f -o json`. Lines are redacted, capped per service,
//! batched, and sent as `logs` messages while the link is up; lines written
//! while it is down are not kept (the services' own logs still have them).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use daemon_core::redact::redact;
use daemon_import::history::History;
use daemon_protocol::driver::Outbound;
use daemon_protocol::{LogBatch, LogEntry, LogStream, ServiceStatus};
use daemon_streams::logs::{Admit, RateLimiter};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::debug;

use super::app::App;

/// How often the set of followed services is brought up to date.
const RECONCILE_EVERY: Duration = Duration::from_secs(10);
/// A batch goes out when it is this big or this old.
const BATCH_LINES: usize = 500;
const BATCH_EVERY: Duration = Duration::from_secs(2);
/// Longer lines are cut, with a marker.
const MAX_LINE_BYTES: usize = 8 * 1024;
/// Logs from a container's first moments, for one that appears between
/// two reconciles.
const NEW_CONTAINER_LOOKBACK_MS: i64 = 30_000;

pub async fn run(app: Arc<App>) {
    let (enabled, cap) = {
        let c = app.config.read().unwrap();
        (c.logs.enabled, c.logs.lines_per_second.max(1) as usize)
    };
    if !enabled {
        return;
    }

    let (tx, rx) = mpsc::channel::<LogEntry>(4096);
    let dropped = Arc::new(AtomicU64::new(0));
    tokio::spawn(batcher(Arc::clone(&app), rx, Arc::clone(&dropped)));

    let shipper = Shipper {
        tx,
        cap,
        dropped,
        cursors: Arc::new(Mutex::new(HashMap::new())),
    };
    let mut containers: HashMap<String, JoinHandle<()>> = HashMap::new();
    let mut journal: Option<(BTreeSet<String>, JoinHandle<()>)> = None;
    let journal_cursor: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut first = true;
    let mut tick = tokio::time::interval(RECONCILE_EVERY);

    loop {
        tick.tick().await;
        app.supervisor.tick("log_shipper");

        // Containers.
        if let Some(running) = running_containers().await {
            containers.retain(|id, task| {
                let keep = running.contains_key(id) && !task.is_finished();
                if !keep {
                    task.abort();
                }
                keep
            });

            for (id, name) in running {
                if containers.contains_key(&id) {
                    continue;
                }
                let key = format!("docker:{id}");
                let since = shipper.since(&key, first);
                containers.insert(
                    id.clone(),
                    tokio::spawn(shipper.clone().container(id, name, since)),
                );
            }
        }

        // systemd services, as discovery last saw them.
        let units = systemd_units(&app);
        let current = journal
            .as_ref()
            .map(|(set, task)| (set, task.is_finished()));
        let restart = match current {
            Some((set, finished)) => finished || *set != units,
            None => !units.is_empty(),
        };
        if restart {
            if let Some((_, task)) = journal.take() {
                task.abort();
            }
            if !units.is_empty() {
                let task = tokio::spawn(
                    shipper
                        .clone()
                        .journal(units.clone(), Arc::clone(&journal_cursor)),
                );
                journal = Some((units, task));
            }
        }

        first = false;
    }
}

#[derive(Clone)]
struct Shipper {
    tx: mpsc::Sender<LogEntry>,
    cap: usize,
    dropped: Arc<AtomicU64>,
    /// The newest line shipped per service, unix ms, so a restarted follow
    /// picks up where the last one stopped.
    cursors: Arc<Mutex<HashMap<String, i64>>>,
}

impl Shipper {
    /// Where to start following `key`: after its last shipped line; now,
    /// for what was already running when the daemon started; a little
    /// earlier for something new, so its start-up lines aren't missed.
    fn since(&self, key: &str, at_start: bool) -> i64 {
        let now = now_ms();
        match self.cursors.lock().unwrap().get(key) {
            Some(ts) => ts + 1,
            None if at_start => now,
            None => now - NEW_CONTAINER_LOOKBACK_MS,
        }
    }

    async fn container(self, id: String, name: String, since_ms: i64) {
        let key = format!("docker:{id}");
        let since = format!("{}.{:03}", since_ms / 1000, since_ms % 1000);
        let Ok(mut child) = Command::new("docker")
            .args(["logs", "-f", "--timestamps", "--since", &since, &id])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        else {
            return;
        };

        let limiter = Arc::new(Mutex::new(RateLimiter::new(self.cap)));
        let out = child.stdout.take().map(|s| {
            tokio::spawn(self.clone().docker_stream(
                key.clone(),
                name.clone(),
                LogStream::Stdout,
                s,
                Arc::clone(&limiter),
            ))
        });
        let err = child.stderr.take().map(|s| {
            tokio::spawn(self.clone().docker_stream(
                key.clone(),
                name.clone(),
                LogStream::Stderr,
                s,
                Arc::clone(&limiter),
            ))
        });

        // Abort reaches here: the readers go with the child.
        struct Guard(Vec<JoinHandle<()>>);
        impl Drop for Guard {
            fn drop(&mut self) {
                for task in &self.0 {
                    task.abort();
                }
            }
        }
        let _guard = Guard(out.into_iter().chain(err).collect());

        let _ = child.wait().await;
    }

    async fn docker_stream(
        self,
        key: String,
        name: String,
        stream: LogStream,
        reader: impl AsyncRead + Unpin,
        limiter: Arc<Mutex<RateLimiter>>,
    ) {
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(raw)) = lines.next_line().await {
            let (ts, line) = split_docker_timestamp(&raw);
            let admit = limiter.lock().unwrap().admit();
            if !self.ship(&key, &name, ts, stream, None, line, admit).await {
                return;
            }
        }
    }

    async fn journal(self, units: BTreeSet<String>, cursor: Arc<Mutex<Option<String>>>) {
        let mut args: Vec<String> = ["-f", "-o", "json", "--no-pager", "--output-fields"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        args.push("MESSAGE,PRIORITY,_SYSTEMD_UNIT,UNIT".into());
        match cursor.lock().unwrap().clone() {
            Some(c) => args.push(format!("--after-cursor={c}")),
            None => args.extend(["-n".into(), "0".into()]),
        }
        for unit in &units {
            args.push("-u".into());
            args.push(unit.clone());
        }

        let Ok(mut child) = Command::new("journalctl")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .env("LC_ALL", "C.UTF-8")
            .spawn()
        else {
            return;
        };
        let Some(stdout) = child.stdout.take() else {
            return;
        };

        let mut limiters: HashMap<String, RateLimiter> = HashMap::new();
        let mut lines = BufReader::new(stdout).lines();

        while let Ok(Some(raw)) = lines.next_line().await {
            let Some(entry) = parse_journal(&raw) else {
                continue;
            };
            if let Some(c) = entry.cursor {
                *cursor.lock().unwrap() = Some(c);
            }
            if !units.contains(&entry.unit) {
                continue;
            }
            let key = format!("systemd:{}", entry.unit);
            let admit = limiters
                .entry(key.clone())
                .or_insert_with(|| RateLimiter::new(self.cap))
                .admit();
            if !self
                .ship(
                    &key,
                    &entry.unit,
                    entry.ts,
                    LogStream::Journal,
                    entry.priority,
                    &entry.message,
                    admit,
                )
                .await
            {
                return;
            }
        }

        let _ = child.wait().await;
    }

    /// Queue one line. False once the batcher is gone.
    #[allow(clippy::too_many_arguments)]
    async fn ship(
        &self,
        key: &str,
        name: &str,
        ts: Option<i64>,
        stream: LogStream,
        priority: Option<u8>,
        line: &str,
        admit: Admit,
    ) -> bool {
        let ts = ts.unwrap_or_else(now_ms);

        let mut entries = Vec::with_capacity(2);
        match admit {
            Admit::Drop => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return !self.tx.is_closed();
            }
            Admit::Summarise(n) => entries.push(LogEntry {
                service: key.to_string(),
                name: Some(name.to_string()),
                ts,
                stream,
                priority: Some(4),
                line: format!(
                    "[... {n} lines dropped: logging faster than {}/s ...]",
                    self.cap
                ),
            }),
            Admit::Send => {}
        }
        entries.push(LogEntry {
            service: key.to_string(),
            name: Some(name.to_string()),
            ts,
            stream,
            priority,
            line: clip(&redact(line)),
        });

        {
            let mut cursors = self.cursors.lock().unwrap();
            let newest = cursors.entry(key.to_string()).or_insert(ts);
            *newest = (*newest).max(ts);
        }

        for entry in entries {
            if self.tx.send(entry).await.is_err() {
                return false;
            }
        }
        true
    }
}

/// Collects lines and sends them in batches while the panel is connected.
async fn batcher(app: Arc<App>, mut rx: mpsc::Receiver<LogEntry>, dropped: Arc<AtomicU64>) {
    let mut pending: Vec<LogEntry> = Vec::new();
    let mut tick = tokio::time::interval(BATCH_EVERY);

    loop {
        tokio::select! {
            line = rx.recv() => match line {
                Some(line) => {
                    pending.push(line);
                    if pending.len() < BATCH_LINES {
                        continue;
                    }
                }
                None => return,
            },
            _ = tick.tick() => {
                if pending.is_empty() {
                    continue;
                }
            }
        }

        let lines = std::mem::take(&mut pending);
        if app.status.read().unwrap().connected {
            let dropped = dropped.swap(0, Ordering::Relaxed);
            app.send(Outbound::Logs(LogBatch { lines, dropped })).await;
        } else {
            debug!(lines = lines.len(), "panel offline, not shipping logs");
        }
    }
}

/// The running containers, short id to name, or None when Docker can't say.
async fn running_containers() -> Option<BTreeMap<String, String>> {
    let ps = Command::new("docker")
        .args(["ps", "--format", "{{.ID}} {{.Names}}"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    // A wedged Docker must not wedge the worker.
    let output = tokio::time::timeout(Duration::from_secs(5), ps)
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }

    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|row| {
                let (id, name) = row.trim().split_once(' ')?;
                let id: String = id.chars().take(12).collect();
                Some((id, name.split(',').next().unwrap_or(name).to_string()))
            })
            .collect(),
    )
}

/// Running systemd services from discovery's last report.
fn systemd_units(app: &App) -> BTreeSet<String> {
    let Ok(Some(report)) = History::new(&app.state).last_report() else {
        return BTreeSet::new();
    };

    report
        .services
        .iter()
        .filter(|s| s.status == ServiceStatus::Running)
        .filter_map(|s| s.key.strip_prefix("systemd:"))
        .filter(|unit| !unit.starts_with("serverosd"))
        .map(str::to_string)
        .collect()
}

/// `docker logs --timestamps` puts an RFC 3339 time and a space first.
fn split_docker_timestamp(raw: &str) -> (Option<i64>, &str) {
    if let Some((stamp, rest)) = raw.split_once(' ') {
        if let Ok(at) = OffsetDateTime::parse(stamp, &Rfc3339) {
            return (Some((at.unix_timestamp_nanos() / 1_000_000) as i64), rest);
        }
    }
    (None, raw)
}

struct JournalLine {
    unit: String,
    ts: Option<i64>,
    priority: Option<u8>,
    message: String,
    cursor: Option<String>,
}

fn parse_journal(raw: &str) -> Option<JournalLine> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let text = |field: &str| value.get(field).and_then(|v| v.as_str());

    let unit = text("_SYSTEMD_UNIT").or_else(|| text("UNIT"))?.to_string();
    // journald sends non-UTF-8 messages as an array of bytes.
    let message = match value.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(bytes) => {
            let bytes: Vec<u8> = bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|b| b as u8))
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => return None,
    };

    Some(JournalLine {
        unit,
        ts: text("__REALTIME_TIMESTAMP")
            .and_then(|us| us.parse::<i64>().ok())
            .map(|us| us / 1000),
        priority: text("PRIORITY").and_then(|p| p.parse().ok()),
        message,
        cursor: text("__CURSOR").map(str::to_string),
    })
}

fn clip(line: &str) -> String {
    if line.len() <= MAX_LINE_BYTES {
        return line.to_string();
    }
    let mut end = MAX_LINE_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [... cut at 8 KB]", &line[..end])
}

fn now_ms() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_docker_timestamps() {
        let (ts, line) = split_docker_timestamp("2026-10-05T12:00:00.250000000Z GET / 200");
        assert_eq!(ts, Some(1_791_201_600_250));
        assert_eq!(line, "GET / 200");

        assert_eq!(
            split_docker_timestamp("no stamp here"),
            (None, "no stamp here")
        );
    }

    #[test]
    fn parses_journal_json() {
        let raw = r#"{"__CURSOR":"s=abc","__REALTIME_TIMESTAMP":"1791201600250000","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream timed out"}"#;
        let line = parse_journal(raw).unwrap();
        assert_eq!(line.unit, "nginx.service");
        assert_eq!(line.ts, Some(1_791_201_600_250));
        assert_eq!(line.priority, Some(3));
        assert_eq!(line.message, "upstream timed out");
        assert_eq!(line.cursor.as_deref(), Some("s=abc"));

        let bytes = r#"{"_SYSTEMD_UNIT":"x.service","MESSAGE":[104,105]}"#;
        assert_eq!(parse_journal(bytes).unwrap().message, "hi");
        assert!(parse_journal(r#"{"MESSAGE":"no unit"}"#).is_none());
    }

    #[test]
    fn clips_long_lines_on_a_char_boundary() {
        let long = "é".repeat(MAX_LINE_BYTES);
        let clipped = clip(&long);
        assert!(clipped.ends_with("[... cut at 8 KB]"));
        assert!(clipped.len() <= MAX_LINE_BYTES + 20);
        assert_eq!(clip("short"), "short");
    }
}
