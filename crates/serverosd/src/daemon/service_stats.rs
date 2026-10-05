use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemon_protocol::driver::Outbound;
use daemon_protocol::{Sample, TelemetryBatch};
use tokio::process::Command;

use super::app::App;

type Started = (Option<i64>, Option<u32>);

const EVERY: Duration = Duration::from_secs(15);
const SYSTEMD_SLICE: &str = "/sys/fs/cgroup/system.slice";

pub async fn run(app: Arc<App>) {
    let mut tick = tokio::time::interval(EVERY);
    let mut previous: HashMap<String, (u64, Instant)> = HashMap::new();

    loop {
        tick.tick().await;
        app.supervisor.tick("service_stats");

        let cores = app.facts.read().unwrap().cpu_cores.max(1) as f32;
        let now = daemon_state::State::now();

        let mut samples = docker_samples(now, cores, &mut previous).await;
        samples.extend(systemd_samples(now, cores, &mut previous).await);

        if !samples.is_empty() && app.status.read().unwrap().connected {
            app.send(Outbound::Telemetry(TelemetryBatch {
                samples,
                backfill: false,
                gap_before: false,
            }))
            .await;
        }
    }
}

async fn docker_samples(
    now: i64,
    cores: f32,
    previous: &mut HashMap<String, (u64, Instant)>,
) -> Vec<Sample> {
    let Some(stats) = output(
        "docker",
        &[
            "stats",
            "--no-stream",
            "--no-trunc",
            "--format",
            "{{json .}}",
        ],
    )
    .await
    else {
        return Vec::new();
    };

    let rows: Vec<DockerStat> = stats.lines().filter_map(parse_docker_stat).collect();
    if rows.is_empty() {
        return Vec::new();
    }

    let mut args = vec![
        "inspect".to_string(),
        "--format".to_string(),
        "{{.Id}} {{.State.StartedAt}} {{.RestartCount}}".to_string(),
    ];
    args.extend(rows.iter().map(|row| row.id.clone()));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let started: HashMap<String, Started> = output("docker", &arg_refs)
        .await
        .map(|text| text.lines().filter_map(parse_docker_inspect).collect())
        .unwrap_or_default();

    let at = Instant::now();

    rows.into_iter()
        .map(|row| {
            let (started_at, restarts) = started.get(&row.id).copied().unwrap_or((None, None));
            let cgroup = container_cgroup(&row.id).and_then(|dir| {
                cgroup_usage(&dir, &format!("docker:{}", row.id), cores, at, previous)
            });
            let (cpu_percent, mem_used, mem_limit, pids) = match cgroup {
                Some(c) => (
                    c.cpu_percent,
                    c.mem_used,
                    c.mem_limit.unwrap_or(row.mem_limit),
                    c.pids,
                ),
                None => (
                    row.cpu_percent / cores,
                    row.mem_used,
                    row.mem_limit,
                    row.pids,
                ),
            };

            service_sample(ServiceUsage {
                ts: now,
                key: format!("docker:{}", &row.id[..row.id.len().min(12)]),
                cpu_percent,
                mem_used,
                mem_limit,
                pids,
                net_rx: row.net_rx,
                net_tx: row.net_tx,
                started_at,
                restarts,
            })
        })
        .collect()
}

#[derive(Debug, PartialEq)]
struct DockerStat {
    id: String,
    cpu_percent: f32,
    mem_used: u64,
    mem_limit: u64,
    net_rx: u64,
    net_tx: u64,
    pids: u32,
}

fn parse_docker_stat(line: &str) -> Option<DockerStat> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let field = |name: &str| v.get(name).and_then(|x| x.as_str()).unwrap_or("");
    let (mem_used, mem_limit) = pair(field("MemUsage"));
    let (net_rx, net_tx) = pair(field("NetIO"));

    Some(DockerStat {
        id: field("ID").to_string(),
        cpu_percent: field("CPUPerc")
            .trim_end_matches('%')
            .trim()
            .parse()
            .unwrap_or(0.0),
        mem_used,
        mem_limit,
        net_rx,
        net_tx,
        pids: field("PIDs").trim().parse().unwrap_or(0),
    })
    .filter(|s| !s.id.is_empty())
}

fn pair(text: &str) -> (u64, u64) {
    let mut parts = text.split('/').map(|p| parse_size(p.trim()));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0))
}

fn parse_size(text: &str) -> u64 {
    let split = text
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: f64 = number.trim().parse().unwrap_or(0.0);
    let multiplier: f64 = match unit.trim() {
        "kB" | "KB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        "TB" => 1e12,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };

    (number * multiplier) as u64
}

fn parse_docker_inspect(line: &str) -> Option<(String, Started)> {
    let mut parts = line.split_whitespace();
    let id = parts.next()?.to_string();
    let started = parts.next().and_then(|t| {
        time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
            .ok()
            .map(|d| d.unix_timestamp())
            .filter(|ts| *ts > 0)
    });
    let restarts = parts.next().and_then(|r| r.parse().ok());

    Some((id, (started, restarts)))
}

async fn systemd_samples(
    now: i64,
    cores: f32,
    previous: &mut HashMap<String, (u64, Instant)>,
) -> Vec<Sample> {
    let Ok(entries) = std::fs::read_dir(SYSTEMD_SLICE) else {
        return Vec::new();
    };

    let units: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name.ends_with(".service"))
        .collect();
    if units.is_empty() {
        return Vec::new();
    }

    let mut args = vec![
        "show".to_string(),
        "--property=Id,ActiveEnterTimestampMonotonic,NRestarts".to_string(),
    ];
    args.extend(units.iter().cloned());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let shown = output("systemctl", &arg_refs).await.unwrap_or_default();
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok());
    let started = parse_systemctl_show(&shown, now, uptime);

    let at = Instant::now();
    let mut samples = Vec::new();

    for unit in units {
        let dir = Path::new(SYSTEMD_SLICE).join(&unit);
        let Some(usage) = cgroup_usage(&dir, &unit, cores, at, previous) else {
            continue;
        };
        if usage.pids == 0 {
            continue;
        }
        let (started_at, restarts) = started.get(&unit).copied().unwrap_or((None, None));

        samples.push(service_sample(ServiceUsage {
            ts: now,
            key: format!("systemd:{unit}"),
            cpu_percent: usage.cpu_percent,
            mem_used: usage.mem_used,
            mem_limit: usage.mem_limit.unwrap_or(0),
            pids: usage.pids,
            net_rx: 0,
            net_tx: 0,
            started_at,
            restarts,
        }));
    }

    samples
}

fn container_cgroup(id: &str) -> Option<std::path::PathBuf> {
    [
        Path::new(SYSTEMD_SLICE).join(format!("docker-{id}.scope")),
        Path::new("/sys/fs/cgroup/docker").join(id),
    ]
    .into_iter()
    .find(|dir| dir.join("cpu.stat").is_file())
}

struct CgroupUsage {
    cpu_percent: f32,
    mem_used: u64,
    mem_limit: Option<u64>,
    pids: u32,
}

fn cgroup_usage(
    dir: &Path,
    id: &str,
    cores: f32,
    at: Instant,
    previous: &mut HashMap<String, (u64, Instant)>,
) -> Option<CgroupUsage> {
    let usage_usec = std::fs::read_to_string(dir.join("cpu.stat"))
        .ok()
        .and_then(|t| parse_cpu_usage_usec(&t))?;

    let cpu_percent = match previous.insert(id.to_string(), (usage_usec, at)) {
        Some((before, then)) => {
            let elapsed = at.duration_since(then).as_micros() as f64;
            if elapsed > 0.0 {
                (usage_usec.saturating_sub(before) as f64 / elapsed * 100.0) as f32 / cores
            } else {
                0.0
            }
        }
        None => 0.0,
    };

    Some(CgroupUsage {
        cpu_percent: cpu_percent.min(100.0),
        mem_used: read_number(&dir.join("memory.current")).unwrap_or(0),
        mem_limit: read_number(&dir.join("memory.max")),
        pids: read_number(&dir.join("pids.current")).unwrap_or(0) as u32,
    })
}

fn parse_cpu_usage_usec(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
}

fn read_number(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn parse_systemctl_show(
    text: &str,
    now: i64,
    uptime_secs: Option<f64>,
) -> HashMap<String, Started> {
    let mut out = HashMap::new();

    for block in text.split("\n\n") {
        let mut id = None;
        let mut mono = None;
        let mut restarts = None;

        for line in block.lines() {
            match line.split_once('=') {
                Some(("Id", v)) => id = Some(v.to_string()),
                Some(("ActiveEnterTimestampMonotonic", v)) => {
                    mono = v.parse::<u64>().ok().filter(|m| *m > 0)
                }
                Some(("NRestarts", v)) => restarts = v.parse().ok(),
                _ => {}
            }
        }

        if let Some(id) = id {
            let started = match (mono, uptime_secs) {
                (Some(mono), Some(uptime)) => {
                    Some(now - (uptime - mono as f64 / 1_000_000.0).round() as i64)
                }
                _ => None,
            };
            out.insert(id, (started, restarts));
        }
    }

    out
}

struct ServiceUsage {
    ts: i64,
    key: String,
    cpu_percent: f32,
    mem_used: u64,
    mem_limit: u64,
    pids: u32,
    net_rx: u64,
    net_tx: u64,
    started_at: Option<i64>,
    restarts: Option<u32>,
}

fn service_sample(u: ServiceUsage) -> Sample {
    Sample {
        ts: u.ts,
        service: Some(u.key),
        cpu_percent: (u.cpu_percent * 100.0).round() / 100.0,
        cpu_per_core: Vec::new(),
        load: [0.0; 3],
        mem_total: u.mem_limit,
        mem_used: u.mem_used,
        mem_available: u.mem_limit.saturating_sub(u.mem_used),
        mem_cached: 0,
        swap_total: 0,
        swap_used: 0,
        disks: Vec::new(),
        net_rx_bytes: u.net_rx,
        net_tx_bytes: u.net_tx,
        net_rx_errors: 0,
        net_tx_errors: 0,
        process_count: u.pids,
        started_at: u.started_at,
        restarts: u.restarts,
    }
}

async fn output(program: &str, args: &[&str]) -> Option<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .ok()?
    .ok()?;

    result
        .status
        .success()
        .then(|| String::from_utf8_lossy(&result.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_stats_lines_parse_into_bytes() {
        let line = r#"{"BlockIO":"0B / 0B","CPUPerc":"12.50%","ID":"abc123def456789","MemPerc":"0.12%","MemUsage":"9.5MiB / 7.66GiB","Name":"serveros-cache-redis-1","NetIO":"1.05kB / 0B","PIDs":"6"}"#;
        let stat = parse_docker_stat(line).unwrap();

        assert_eq!(stat.id, "abc123def456789");
        assert_eq!(stat.cpu_percent, 12.5);
        assert_eq!(stat.mem_used, (9.5 * 1024.0 * 1024.0) as u64);
        assert_eq!(stat.mem_limit, (7.66 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(stat.net_rx, 1050);
        assert_eq!(stat.pids, 6);
        assert!(parse_docker_stat("not json").is_none());
    }

    #[test]
    fn docker_inspect_lines_give_start_and_restarts() {
        let (id, (started, restarts)) =
            parse_docker_inspect("abc 2026-10-04T21:44:15.123456789Z 2").unwrap();

        assert_eq!(id, "abc");
        assert_eq!(started, Some(1_791_150_255));
        assert_eq!(restarts, Some(2));

        let (_, (started, _)) = parse_docker_inspect("abc 0001-01-01T00:00:00Z 0").unwrap();
        assert_eq!(started, None);
    }

    #[test]
    fn systemd_show_blocks_give_start_and_restarts() {
        let text = "Id=nginx.service\nActiveEnterTimestampMonotonic=5000000\nNRestarts=1\n\nId=cron.service\nActiveEnterTimestampMonotonic=0\nNRestarts=0\n";
        let parsed = parse_systemctl_show(text, 1_000, Some(105.0));

        assert_eq!(parsed["nginx.service"], (Some(900), Some(1)));
        assert_eq!(parsed["cron.service"], (None, Some(0)));
    }

    #[test]
    fn cgroup_cpu_usage_parses() {
        assert_eq!(
            parse_cpu_usage_usec("usage_usec 123456\nuser_usec 100\n"),
            Some(123456)
        );
        assert_eq!(parse_cpu_usage_usec("nothing here"), None);
    }

    #[test]
    fn sizes_cover_decimal_and_binary_units() {
        assert_eq!(parse_size("0B"), 0);
        assert_eq!(parse_size("2kB"), 2000);
        assert_eq!(parse_size("1KiB"), 1024);
        assert_eq!(parse_size("1.5GB"), 1_500_000_000);
    }
}
