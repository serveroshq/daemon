//! Reads the access logs of the sites ServerOS runs, and of the sites the
//! machine's own nginx and Apache serve, while traffic is on, and reports
//! each finished minute's rollup with telemetry. Raw lines are read and
//! counted here; only the rollups leave the machine (see
//! daemon_deploy::traffic and daemon_deploy::existing). ServerOS's own logs
//! are emptied as they're read; the user's are only ever read.

use std::sync::Arc;
use std::time::Duration;

use daemon_deploy::existing::{self, Plan, Tailer};
use daemon_deploy::proxy::Proxy;
use daemon_deploy::traffic::{self, Rollups};
use daemon_protocol::driver::Outbound;
use daemon_protocol::{TelemetryBatch, TrafficRollup, TrafficSite};
use tracing::warn;

use super::app::App;

/// How often the logs are read. Often enough that ServerOS's own stay
/// small on a busy site.
const EVERY: Duration = Duration::from_secs(10);
/// Rollups kept while the panel is out of reach, oldest dropped first.
const MAX_PENDING: usize = 20_000;
const PER_BATCH: usize = 500;
/// Every this many reads, the web server configs are read again for
/// sites, files and formats that changed.
const REPLAN_EVERY: u64 = 6;
/// Every this many reads, the list of sites goes out even if unchanged.
const RESEND_SITES_EVERY: u64 = 30;

/// Whether the sites in the machine's own web server configs are counted:
/// "on" or "off", set by the traffic job.
pub const EXISTING_KEY: &str = "traffic.existing";
/// Where the daemon has read each of their logs to.
const MARKS_KEY: &str = "traffic.existing.marks";

/// Whether sites ServerOS didn't write are counted. Daemons that predate
/// the setting count them whenever traffic is on for ServerOS's sites.
pub fn existing_on(app: &App, proxy: &Proxy) -> bool {
    match app.state.kv_get(EXISTING_KEY).ok().flatten().as_deref() {
        Some("on") => true,
        Some(_) => false,
        None => proxy.traffic_on(),
    }
}

/// The sites in the web server configs on this machine, counted or not.
pub fn existing_plan(proxy: &Proxy) -> Plan {
    existing::plan(
        &daemon_inventory::access_logs::discover(),
        &proxy.traffic_dir,
    )
}

pub async fn run(app: Arc<App>) {
    let mut tick = tokio::time::interval(EVERY);
    let mut rollups = Rollups::new();
    let mut pending: Vec<TrafficRollup> = Vec::new();
    let saved = app.state.kv_get(MARKS_KEY).ok().flatten();
    let mut tailer = Tailer::restore(saved.as_deref());
    let mut plan: Option<Plan> = None;
    let mut ticks: u64 = 0;
    // The site list last sent, and when.
    let mut sent: Option<(String, u64)> = None;

    loop {
        tick.tick().await;
        ticks += 1;
        app.supervisor.tick("traffic");

        let proxy = app.deployer.proxy();
        let ours = proxy.traffic_source();
        let existing_on = existing_on(&app, &proxy);
        let mut sites_out: Option<Vec<TrafficSite>> = None;

        if !existing_on {
            if plan.take().is_some() || !tailer.is_empty() {
                // Next time it's on, every file starts at its end again.
                tailer = Tailer::default();
                let _ = app.state.kv_set(MARKS_KEY, "{}");
            }
            let dir = proxy.traffic_dir.clone();
            let _ = tokio::task::spawn_blocking(move || existing::empty_copies(&dir)).await;
            if sent.as_ref().is_some_and(|(print, _)| print != "[]") {
                sites_out = Some(Vec::new());
            }
        }
        if ours.is_none() && !existing_on {
            rollups.clear();
            pending.clear();
            if let Some(sites) = sites_out {
                if app.status.read().unwrap().connected {
                    send(&app, &[], Some(sites)).await;
                    sent = Some(("[]".into(), ticks));
                }
            }
            continue;
        }

        let sites: Vec<String> = proxy
            .our_sites()
            .into_iter()
            .map(|(stem, _)| stem)
            .collect();
        let replan = existing_on && (plan.is_none() || ticks.is_multiple_of(REPLAN_EVERY));
        let traffic_dir = proxy.traffic_dir.clone();
        let now = daemon_state::State::now();
        let read = tokio::task::spawn_blocking(move || {
            if let Some((format, dir)) = &ours {
                traffic::collect(dir, *format, &sites, &mut rollups);
            }
            if existing_on {
                if replan {
                    plan = Some(existing::plan(
                        &daemon_inventory::access_logs::discover(),
                        &traffic_dir,
                    ));
                }
                if let Some(plan) = &plan {
                    existing::collect(plan, &mut tailer, &mut rollups, now);
                }
            }
            (rollups, tailer, plan)
        })
        .await;
        (rollups, tailer, plan) = match read {
            Ok(read) => read,
            Err(e) => {
                warn!(error = %e, "reading the traffic logs failed");
                (Rollups::new(), Tailer::default(), None)
            }
        };
        if let Some(marks) = tailer.saved() {
            let _ = app.state.kv_set(MARKS_KEY, &marks);
        }

        if existing_on {
            if let Some(plan) = &plan {
                let print = existing::fingerprint(&plan.sites);
                let due = match &sent {
                    Some((last, at)) => *last != print || ticks - at >= RESEND_SITES_EVERY,
                    None => true,
                };
                if due {
                    sites_out = Some(plan.sites.iter().map(|s| s.info.clone()).collect());
                }
            }
        }

        pending.extend(rollups.finished(now));
        if pending.len() > MAX_PENDING {
            pending.drain(..pending.len() - MAX_PENDING);
        }
        if (pending.is_empty() && sites_out.is_none()) || !app.status.read().unwrap().connected {
            continue;
        }
        if let Some(sites) = &sites_out {
            let print = serde_json::to_string(sites).unwrap_or_default();
            sent = Some((print, ticks));
        }
        send(&app, &pending, sites_out).await;
        pending.clear();
    }
}

async fn send(app: &App, rollups: &[TrafficRollup], mut sites: Option<Vec<TrafficSite>>) {
    let mut chunks: Vec<&[TrafficRollup]> = rollups.chunks(PER_BATCH).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    for chunk in chunks {
        app.send(Outbound::Telemetry(TelemetryBatch {
            samples: Vec::new(),
            backfill: false,
            gap_before: false,
            traffic: chunk.to_vec(),
            traffic_sites: sites.take(),
        }))
        .await;
    }
}
