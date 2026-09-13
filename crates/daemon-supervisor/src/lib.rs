//! The supervisor watches the daemon itself: its memory, whether each
//! worker is still ticking, whether the panel has been unreachable for a
//! suspiciously long time, and whether the clock agrees with the panel's.
//! It restarts workers before it restarts the process, and turns crash
//! loops into events rather than silence.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use daemon_protocol::{Event, EventKind, Severity};

/// Idle budget from the spec: under 30 MB RSS. The supervisor warns at
/// twice that and asks for a restart at four times.
pub const RSS_WARN_BYTES: u64 = 60 * 1024 * 1024;
pub const RSS_RESTART_BYTES: u64 = 120 * 1024 * 1024;
/// A worker that has not ticked for this long is wedged.
pub const WORKER_STALL: Duration = Duration::from_secs(120);
/// Panel-reported time drifting further than this is worth an event.
pub const CLOCK_SKEW_LIMIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerHealth {
    Ok,
    Stalled(Duration),
}

#[derive(Default)]
pub struct Supervisor {
    ticks: Mutex<BTreeMap<&'static str, Instant>>,
    restarts: Mutex<Vec<Instant>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Fine,
    RestartWorker(&'static str),
    RestartProcess(String),
}

impl Supervisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Workers call this on every loop iteration.
    pub fn tick(&self, worker: &'static str) {
        self.ticks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(worker, Instant::now());
    }

    pub fn worker_health(&self) -> BTreeMap<&'static str, WorkerHealth> {
        self.ticks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(name, last)| {
                let since = last.elapsed();
                (
                    *name,
                    if since > WORKER_STALL {
                        WorkerHealth::Stalled(since)
                    } else {
                        WorkerHealth::Ok
                    },
                )
            })
            .collect()
    }

    /// Record a worker restart; too many in a short window means the
    /// process itself should be restarted by systemd.
    pub fn record_worker_restart(&self) -> usize {
        let mut restarts = self.restarts.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        restarts.push(now);
        restarts.retain(|t| now.duration_since(*t) < Duration::from_secs(600));
        restarts.len()
    }

    /// One pass. `rss` is the process's resident set in bytes.
    pub fn assess(&self, rss: u64) -> Verdict {
        if rss > RSS_RESTART_BYTES {
            return Verdict::RestartProcess(format!(
                "resident memory {} MB is over the {} MB ceiling",
                rss / (1024 * 1024),
                RSS_RESTART_BYTES / (1024 * 1024)
            ));
        }

        for (name, health) in self.worker_health() {
            if let WorkerHealth::Stalled(_) = health {
                if self.record_worker_restart() > 5 {
                    return Verdict::RestartProcess(format!("worker {name} keeps stalling"));
                }
                return Verdict::RestartWorker(name);
            }
        }

        Verdict::Fine
    }

    /// Events worth raising from one pass, rate-limited by the caller.
    pub fn events(&self, rss: u64, panel_ts: Option<i64>, now_ts: i64) -> Vec<Event> {
        let mut events = Vec::new();

        if rss > RSS_WARN_BYTES {
            events.push(Event {
                kind: EventKind::DaemonRestarted,
                severity: Severity::Warning,
                summary: format!(
                    "serverosd is using {} MB of memory, above its {} MB budget",
                    rss / (1024 * 1024),
                    RSS_WARN_BYTES / (1024 * 1024)
                ),
                detail: Some(
                    "It restarts itself if this keeps growing; no customer service is affected."
                        .into(),
                ),
                service: None,
                data: BTreeMap::new(),
                suggested_action: None,
            });
        }

        if let Some(panel_ts) = panel_ts {
            let skew = (panel_ts - now_ts).unsigned_abs();
            if skew > CLOCK_SKEW_LIMIT.as_secs() {
                events.push(Event {
                    kind: EventKind::ClockSkew,
                    severity: Severity::Warning,
                    summary: format!("this machine's clock is {skew}s off the panel's"),
                    detail: Some(
                        "TLS, backups, and scheduled tasks all depend on the clock.".into(),
                    ),
                    service: None,
                    data: BTreeMap::from([("skew_secs".into(), skew.to_string())]),
                    suggested_action: Some("Enable NTP (timedatectl set-ntp true).".into()),
                });
            }
        }

        events
    }
}

/// Resident set size of this process, from `/proc/self/status`.
pub fn own_rss() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;

    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

/// Crash-loop bookkeeping across process restarts: a small file with the
/// last few start times. Systemd restarts us; this notices when it keeps
/// having to.
pub struct StartHistory {
    pub path: std::path::PathBuf,
}

impl StartHistory {
    /// Record this start and return how many starts happened in the last
    /// ten minutes, including this one.
    pub fn record(&self, now_ts: i64) -> usize {
        let mut starts: Vec<i64> = std::fs::read_to_string(&self.path)
            .ok()
            .map(|t| t.lines().filter_map(|l| l.parse().ok()).collect())
            .unwrap_or_default();
        starts.push(now_ts);
        starts.retain(|t| now_ts - t < 600);

        let _ = std::fs::write(
            &self.path,
            starts
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        );

        starts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_over_the_ceiling_asks_for_a_process_restart() {
        let supervisor = Supervisor::new();

        assert_eq!(supervisor.assess(10 * 1024 * 1024), Verdict::Fine);
        assert!(matches!(
            supervisor.assess(RSS_RESTART_BYTES + 1),
            Verdict::RestartProcess(_)
        ));
        assert_eq!(
            supervisor.events(RSS_WARN_BYTES + 1, None, 0)[0].kind,
            EventKind::DaemonRestarted
        );
    }

    #[test]
    fn stalled_workers_are_restarted_then_escalated() {
        let supervisor = Supervisor::new();
        supervisor.ticks.lock().unwrap().insert(
            "collector",
            Instant::now() - WORKER_STALL - Duration::from_secs(1),
        );

        assert_eq!(supervisor.assess(0), Verdict::RestartWorker("collector"));

        for _ in 0..5 {
            supervisor.record_worker_restart();
        }
        assert!(matches!(supervisor.assess(0), Verdict::RestartProcess(_)));
    }

    #[test]
    fn clock_skew_becomes_an_event() {
        let supervisor = Supervisor::new();
        let events = supervisor.events(0, Some(1000), 1100);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ClockSkew);
        assert!(supervisor.events(0, Some(1000), 1010).is_empty());
    }

    #[test]
    fn start_history_counts_recent_starts() {
        let dir = tempfile::tempdir().unwrap();
        let history = StartHistory {
            path: dir.path().join("starts"),
        };

        assert_eq!(history.record(1000), 1);
        assert_eq!(history.record(1100), 2);
        assert_eq!(history.record(5000), 1, "old starts age out");
    }
}
