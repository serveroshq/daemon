use std::collections::BTreeMap;

use daemon_protocol::{Event, EventKind, Sample, Severity};

const QUIET_PERIOD_SECS: i64 = 6 * 60 * 60;
const SUSTAINED_LOAD_SECS: i64 = 15 * 60;

#[derive(Debug, Default)]
pub struct SignalState {
    last_raised: BTreeMap<String, i64>,
    load_high_since: Option<i64>,
    disk_history: BTreeMap<String, Vec<(i64, u64)>>,
}

pub struct Signals {
    pub cores: u32,
    pub disk_warn_percent: u8,
    pub disk_critical_percent: u8,
    pub projection_days: f64,
}

impl Default for Signals {
    fn default() -> Self {
        Self {
            cores: 1,
            disk_warn_percent: 85,
            disk_critical_percent: 95,
            projection_days: 14.0,
        }
    }
}

impl Signals {
    pub fn evaluate(
        &self,
        state: &mut SignalState,
        sample: &Sample,
        memory_pressure: Option<f32>,
    ) -> Vec<Event> {
        let mut events = Vec::new();

        for disk in &sample.disks {
            let total = disk.used_bytes + disk.free_bytes;

            if total == 0 {
                continue;
            }

            let percent = (disk.used_bytes as f64 / total as f64 * 100.0) as u8;
            let key = format!("disk:{}", disk.mount);

            if percent >= self.disk_critical_percent {
                self.raise(state, &mut events, &key, sample.ts, Event {
                    kind: EventKind::DiskThreshold,
                    severity: Severity::Critical,
                    summary: format!("{} is {percent}% full", disk.mount),
                    detail: Some(format!("{} free of {}", human_bytes(disk.free_bytes), human_bytes(total))),
                    service: None,
                    data: BTreeMap::from([("mount".into(), disk.mount.clone()), ("percent".into(), percent.to_string())]),
                    suggested_action: Some("Free space or grow the disk; builds and backups pause above the limit.".into()),
                });
            } else if percent >= self.disk_warn_percent {
                self.raise(
                    state,
                    &mut events,
                    &key,
                    sample.ts,
                    Event {
                        kind: EventKind::DiskThreshold,
                        severity: Severity::Warning,
                        summary: format!("{} is {percent}% full", disk.mount),
                        detail: Some(format!(
                            "{} free of {}",
                            human_bytes(disk.free_bytes),
                            human_bytes(total)
                        )),
                        service: None,
                        data: BTreeMap::from([
                            ("mount".into(), disk.mount.clone()),
                            ("percent".into(), percent.to_string()),
                        ]),
                        suggested_action: None,
                    },
                );
            }

            let history = state.disk_history.entry(disk.mount.clone()).or_default();
            history.push((sample.ts, disk.used_bytes));
            history.retain(|(ts, _)| sample.ts - ts <= 24 * 60 * 60);

            if let Some(days) = project_full_in_days(history, disk.free_bytes) {
                if days <= self.projection_days {
                    self.raise(
                        state,
                        &mut events,
                        &format!("diskfill:{}", disk.mount),
                        sample.ts,
                        Event {
                            kind: EventKind::DiskFillProjected,
                            severity: if days <= 3.0 {
                                Severity::Critical
                            } else {
                                Severity::Warning
                            },
                            summary: format!(
                                "{} will be full in about {}",
                                disk.mount,
                                human_days(days)
                            ),
                            detail: Some("Based on the last 24 hours of growth.".into()),
                            service: None,
                            data: BTreeMap::from([
                                ("mount".into(), disk.mount.clone()),
                                ("days".into(), format!("{days:.1}")),
                            ]),
                            suggested_action: None,
                        },
                    );
                }
            }

            if disk.inodes_free > 0 && disk.inodes_used > 0 {
                let inode_percent = (disk.inodes_used * 100)
                    .checked_div(disk.inodes_used + disk.inodes_free)
                    .unwrap_or(0);

                if inode_percent >= self.disk_critical_percent as u64 {
                    self.raise(
                        state,
                        &mut events,
                        &format!("inodes:{}", disk.mount),
                        sample.ts,
                        Event {
                            kind: EventKind::DiskThreshold,
                            severity: Severity::Critical,
                            summary: format!(
                                "{} is out of inodes ({inode_percent}% used)",
                                disk.mount
                            ),
                            detail: Some(
                                "Many small files, often a cache or log directory.".into(),
                            ),
                            service: None,
                            data: BTreeMap::new(),
                            suggested_action: None,
                        },
                    );
                }
            }
        }

        if let Some(available_percent) = (sample.mem_available * 100).checked_div(sample.mem_total)
        {
            let pressured = memory_pressure.is_some_and(|p| p > 20.0) || available_percent < 5;

            if pressured {
                self.raise(
                    state,
                    &mut events,
                    "memory",
                    sample.ts,
                    Event {
                        kind: EventKind::MemoryPressure,
                        severity: Severity::Warning,
                        summary: format!(
                            "memory is under pressure ({available_percent}% available)"
                        ),
                        detail: memory_pressure.map(|p| {
                            format!("{p:.1}% of the last 10s was spent waiting on memory")
                        }),
                        service: None,
                        data: BTreeMap::new(),
                        suggested_action: None,
                    },
                );
            }
        }

        if sample.load[0] > self.cores as f32 {
            let since = *state.load_high_since.get_or_insert(sample.ts);

            if sample.ts - since >= SUSTAINED_LOAD_SECS {
                self.raise(
                    state,
                    &mut events,
                    "load",
                    sample.ts,
                    Event {
                        kind: EventKind::SustainedLoad,
                        severity: Severity::Warning,
                        summary: format!(
                            "load {:.1} above {} cores for {}",
                            sample.load[0],
                            self.cores,
                            human_secs(sample.ts - since)
                        ),
                        detail: None,
                        service: None,
                        data: BTreeMap::new(),
                        suggested_action: None,
                    },
                );
            }
        } else {
            state.load_high_since = None;
        }

        events
    }

    fn raise(
        &self,
        state: &mut SignalState,
        events: &mut Vec<Event>,
        key: &str,
        ts: i64,
        event: Event,
    ) {
        let quiet = state
            .last_raised
            .get(key)
            .is_some_and(|last| ts - last < QUIET_PERIOD_SECS);

        if !quiet {
            state.last_raised.insert(key.to_string(), ts);
            events.push(event);
        }
    }
}

pub fn project_full_in_days(history: &[(i64, u64)], free_bytes: u64) -> Option<f64> {
    if history.len() < 2 {
        return None;
    }

    let (t0, u0) = history[0];
    let (t1, u1) = *history.last()?;
    let span_secs = (t1 - t0) as f64;

    if span_secs < 3600.0 || u1 <= u0 {
        return None;
    }

    let bytes_per_sec = (u1 - u0) as f64 / span_secs;

    Some(free_bytes as f64 / bytes_per_sec / 86_400.0)
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn human_days(days: f64) -> String {
    if days < 1.0 {
        format!("{} hours", (days * 24.0).round() as u64)
    } else {
        format!("{} days", days.round() as u64)
    }
}

fn human_secs(secs: i64) -> String {
    if secs < 3600 {
        format!("{} min", secs / 60)
    } else {
        format!("{} h", secs / 3600)
    }
}

#[cfg(test)]
mod tests {
    use daemon_protocol::DiskSample;

    use super::*;

    fn sample(ts: i64, used: u64, free: u64, load: f32) -> Sample {
        Sample {
            ts,
            service: None,
            cpu_percent: 0.0,
            cpu_per_core: vec![],
            load: [load, 0.0, 0.0],
            mem_total: 1000,
            mem_used: 500,
            mem_available: 500,
            mem_cached: 0,
            swap_total: 0,
            swap_used: 0,
            disks: vec![DiskSample {
                mount: "/".into(),
                used_bytes: used,
                free_bytes: free,
                inodes_used: 10,
                inodes_free: 90,
                read_bytes: 0,
                write_bytes: 0,
            }],
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            net_rx_errors: 0,
            net_tx_errors: 0,
            process_count: 1,
            started_at: None,
            restarts: None,
        }
    }

    #[test]
    fn a_full_disk_raises_once_then_stays_quiet() {
        let signals = Signals::default();
        let mut state = SignalState::default();

        let first = signals.evaluate(&mut state, &sample(0, 96, 4, 0.0), None);
        let second = signals.evaluate(&mut state, &sample(10, 96, 4, 0.0), None);
        let later = signals.evaluate(&mut state, &sample(QUIET_PERIOD_SECS + 1, 96, 4, 0.0), None);

        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, EventKind::DiskThreshold);
        assert_eq!(first[0].severity, Severity::Critical);
        assert!(second.is_empty());
        assert_eq!(later.len(), 1);
    }

    #[test]
    fn projects_when_a_disk_will_fill() {
        let history: Vec<(i64, u64)> = (0..=2)
            .map(|h| (h * 3600, (h as u64) * 1_000_000_000))
            .collect();

        let days = project_full_in_days(&history, 24_000_000_000).unwrap();

        assert!((days - 1.0).abs() < 0.01);
        assert_eq!(project_full_in_days(&history[..1], 1), None);
    }

    #[test]
    fn sustained_load_needs_fifteen_minutes() {
        let signals = Signals {
            cores: 2,
            ..Default::default()
        };
        let mut state = SignalState::default();

        assert!(signals
            .evaluate(&mut state, &sample(0, 1, 99, 5.0), None)
            .is_empty());
        assert!(signals
            .evaluate(&mut state, &sample(600, 1, 99, 5.0), None)
            .is_empty());

        let events = signals.evaluate(&mut state, &sample(SUSTAINED_LOAD_SECS, 1, 99, 5.0), None);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::SustainedLoad);

        signals.evaluate(
            &mut state,
            &sample(SUSTAINED_LOAD_SECS + 10, 1, 99, 0.5),
            None,
        );
        assert!(state.load_high_since.is_none());
    }

    #[test]
    fn memory_pressure_from_psi() {
        let signals = Signals::default();
        let mut state = SignalState::default();

        let events = signals.evaluate(&mut state, &sample(0, 1, 99, 0.0), Some(35.0));

        assert_eq!(events[0].kind, EventKind::MemoryPressure);
    }

    #[test]
    fn human_bytes_reads_naturally() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}
