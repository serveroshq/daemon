//! Reads the access logs of the sites ServerOS runs, while traffic is on,
//! and reports each finished minute's rollup with telemetry. Raw lines are
//! read, counted and emptied here; only the rollups leave the machine (see
//! daemon_deploy::traffic).

use std::sync::Arc;
use std::time::Duration;

use daemon_deploy::traffic::{self, Rollups};
use daemon_protocol::driver::Outbound;
use daemon_protocol::{TelemetryBatch, TrafficRollup};
use tracing::warn;

use super::app::App;

/// How often the logs are read and emptied. Often enough that they stay
/// small on a busy site.
const EVERY: Duration = Duration::from_secs(10);
/// Rollups kept while the panel is out of reach, oldest dropped first.
const MAX_PENDING: usize = 20_000;
const PER_BATCH: usize = 500;

pub async fn run(app: Arc<App>) {
    let mut tick = tokio::time::interval(EVERY);
    let mut rollups = Rollups::new();
    let mut pending: Vec<TrafficRollup> = Vec::new();

    loop {
        tick.tick().await;
        app.supervisor.tick("traffic");

        let proxy = app.deployer.proxy();
        let Some((format, dir)) = proxy.traffic_source() else {
            rollups.clear();
            pending.clear();
            continue;
        };
        let sites: Vec<String> = proxy
            .our_sites()
            .into_iter()
            .map(|(stem, _)| stem)
            .collect();

        let read = tokio::task::spawn_blocking(move || {
            traffic::collect(&dir, format, &sites, &mut rollups);
            rollups
        })
        .await;
        rollups = match read {
            Ok(rollups) => rollups,
            Err(e) => {
                warn!(error = %e, "reading the traffic logs failed");
                Rollups::new()
            }
        };

        pending.extend(rollups.finished(daemon_state::State::now()));
        if pending.len() > MAX_PENDING {
            pending.drain(..pending.len() - MAX_PENDING);
        }
        if pending.is_empty() || !app.status.read().unwrap().connected {
            continue;
        }
        for chunk in pending.chunks(PER_BATCH) {
            app.send(Outbound::Telemetry(TelemetryBatch {
                samples: Vec::new(),
                backfill: false,
                gap_before: false,
                traffic: chunk.to_vec(),
            }))
            .await;
        }
        pending.clear();
    }
}
