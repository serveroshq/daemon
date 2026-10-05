//! The background loops: telemetry, discovery, self-health, updates, and
//! the two forwarders that turn job updates and stream frames into
//! outbound messages.

use std::sync::Arc;
use std::time::Duration;

use daemon_protocol::driver::Outbound;
use daemon_protocol::{
    Event, EventKind, JobUpdate, Severity, StreamFrame, StreamKind, TelemetryBatch,
};
use daemon_selfupdate::install;
use daemon_telemetry::{Collector, SignalState, Signals};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::app::App;
use super::EXIT_RESTART;

pub fn spawn_all(app: Arc<App>) {
    tokio::spawn(telemetry(Arc::clone(&app)));
    tokio::spawn(discovery(Arc::clone(&app)));
    tokio::spawn(super::service_stats::run(Arc::clone(&app)));
    tokio::spawn({
        let app = Arc::clone(&app);
        async move {
            let count = super::service_ops::register_earlier_deploys(&app).await;
            if count > 0 {
                info!(count, "registered containers from earlier deploys");
            }
        }
    });
    tokio::spawn(self_health(Arc::clone(&app)));
    tokio::spawn(updates(Arc::clone(&app)));
    tokio::spawn(housekeeping(app));
}

pub fn forward_job_updates(app: Arc<App>, mut updates: mpsc::Receiver<JobUpdate>) {
    tokio::spawn(async move {
        while let Some(update) = updates.recv().await {
            app.send(Outbound::JobUpdate(update)).await;
        }
    });
}

pub fn forward_streams(app: Arc<App>) {
    let Some(mut frames) = app.take_stream_receiver() else {
        return;
    };

    tokio::spawn(async move {
        while let Some(frame) = frames.recv().await {
            if frame.eof {
                close_stream(&app, &frame).await;
            }
            app.send(Outbound::Stream(frame)).await;
        }
    });
}

async fn close_stream(app: &App, frame: &StreamFrame) {
    match frame.kind {
        StreamKind::PtyOutput => {
            if let Some(session) = app.sessions.take(frame.session) {
                let actor = daemon_audit::Actor::user(&session.actor);
                let _ = app.audit.record(daemon_audit::Entry {
                    actor: &actor,
                    action: "terminal.close",
                    target: &session.user,
                    outcome: daemon_audit::Outcome::Ok,
                    duration: Some(session.duration()),
                    note: Some(&format!("session {}", session.id)),
                });
            }
        }
        StreamKind::LogLine => {
            // Take the tail out under the lock, stop it after the lock is gone.
            let tail = app
                .tails
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&frame.session);
            if let Some(tail) = tail {
                tail.stop().await;
            }
        }
        _ => {}
    }
}

async fn telemetry(app: Arc<App>) {
    let (sample_every, transmit_every, retention) = {
        let c = app.config.read().unwrap();
        (
            c.sample_interval(),
            c.transmit_interval(),
            Duration::from_secs(c.telemetry.retention_hours * 3600),
        )
    };
    let mut collector = Collector::new();
    let mut signals_state = SignalState::default();
    let signals = Signals {
        cores: app.facts.read().unwrap().cpu_cores.max(1),
        ..Default::default()
    };
    let mut sample_tick = tokio::time::interval(sample_every);
    let mut transmit_tick = tokio::time::interval(transmit_every);
    let mut pending: Vec<daemon_protocol::Sample> = Vec::new();

    loop {
        tokio::select! {
            _ = sample_tick.tick() => {
                app.supervisor.tick("telemetry");
                let now = daemon_state::State::now();
                match collector.sample(now) {
                    Ok(sample) => {
                        if let Ok(json) = serde_json::to_string(&sample) {
                            let _ = app.state.push_sample(now, None, &json);
                        }
                        for event in signals.evaluate(&mut signals_state, &sample, collector.memory_pressure()) {
                            app.raise(event).await;
                        }
                        pending.push(sample);
                    }
                    Err(daemon_telemetry::TelemetryError::Unsupported) => return,
                    Err(e) => warn!(error = %e, "telemetry sample failed"),
                }
            }
            _ = transmit_tick.tick() => {
                if pending.is_empty() {
                    continue;
                }
                let samples = daemon_telemetry::aggregate::downsample(&std::mem::take(&mut pending), 60);
                if app.status.read().unwrap().connected {
                    app.send(Outbound::Telemetry(TelemetryBatch { samples, backfill: false, gap_before: false })).await;
                }
                let _ = app.state.prune_samples(daemon_state::State::now() - retention.as_secs() as i64);
            }
        }
    }
}

async fn discovery(app: Arc<App>) {
    if !app.config.read().unwrap().discovery.enabled {
        return;
    }

    let interval = app.config.read().unwrap().discovery_interval();

    // First scan once the panel is reachable, so it lands on a live link.
    for _ in 0..60 {
        if app.status.read().unwrap().connected {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    loop {
        app.supervisor.tick("discovery");

        match app.importer.scan().await {
            Ok((report, events)) => {
                for event in events {
                    app.raise(event).await;
                }
                app.send(Outbound::Inventory(report)).await;
            }
            Err(e) => warn!(error = %e, "discovery scan failed"),
        }

        // Facts can drift (kernel, disks); resend when they do.
        let fresh = daemon_telemetry::gather_facts();
        let changed = *app.facts.read().unwrap() != fresh;
        if changed {
            *app.facts.write().unwrap() = fresh.clone();
            app.send(Outbound::Facts(fresh)).await;
        }

        tokio::time::sleep(interval).await;
    }
}

async fn self_health(app: Arc<App>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    let mut last_events: Option<i64> = None;

    loop {
        tick.tick().await;
        let rss = daemon_supervisor::own_rss().unwrap_or(0);

        match app.supervisor.assess(rss) {
            daemon_supervisor::Verdict::Fine => {}
            daemon_supervisor::Verdict::RestartWorker(name) => warn!(
                worker = name,
                "worker stalled; it will be restarted with the process on the next health strike"
            ),
            daemon_supervisor::Verdict::RestartProcess(reason) => {
                error!(reason, "restarting the daemon (systemd brings it back); customer services are unaffected");
                app.raise(Event {
                    kind: EventKind::DaemonRestarted,
                    severity: Severity::Warning,
                    summary: "serverosd restarted itself".into(),
                    detail: Some(reason),
                    service: None,
                    data: Default::default(),
                    suggested_action: None,
                })
                .await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                std::process::exit(EXIT_RESTART);
            }
        }

        let now = daemon_state::State::now();
        if last_events.is_none_or(|t| now - t > 6 * 3600) {
            let panel_ts = app.status.read().unwrap().last_panel_ts;
            let events = app.supervisor.events(rss, panel_ts, now);
            if !events.is_empty() {
                last_events = Some(now);
                for event in events {
                    app.raise(event).await;
                }
            }
        }
    }
}

async fn updates(app: Arc<App>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));

    loop {
        tick.tick().await;
        app.supervisor.tick("updates");

        let pending = app.pending_update.lock().unwrap().clone();
        let Some((candidate, _approved)) = pending else {
            continue;
        };

        if app.running_jobs() > 0 || app.stopping() {
            continue;
        }

        let (panel_host, updates) = {
            let config = app.config.read().unwrap();
            (config.panel.host.clone(), config.updates.clone())
        };
        let _ = app.audit.record(daemon_audit::Entry {
            actor: &daemon_audit::Actor::daemon(),
            action: "daemon.update",
            target: &candidate.version,
            outcome: daemon_audit::Outcome::Started,
            duration: None,
            note: None,
        });

        match install(
            &app.paths.binary,
            &app.paths.state_dir,
            app.build.version,
            &candidate,
            |host| updates.permits_host(&panel_host, host),
        )
        .await
        {
            Ok(installed) => {
                *app.pending_update.lock().unwrap() = None;
                let _ = app.audit.record(daemon_audit::Entry {
                    actor: &daemon_audit::Actor::daemon(),
                    action: "daemon.update",
                    target: &installed.to,
                    outcome: daemon_audit::Outcome::Ok,
                    duration: None,
                    note: Some("restarting to apply; previous binary kept for rollback"),
                });
                info!(
                    from = installed.from,
                    to = installed.to,
                    "restarting into the new release"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                std::process::exit(EXIT_RESTART);
            }
            Err(e) => {
                *app.pending_update.lock().unwrap() = None;
                let note = e.to_string();
                let _ = app.audit.record(daemon_audit::Entry {
                    actor: &daemon_audit::Actor::daemon(),
                    action: "daemon.update",
                    target: &candidate.version,
                    outcome: daemon_audit::Outcome::Failed,
                    duration: None,
                    note: Some(&note),
                });
                app.raise(Event {
                    kind: EventKind::UpdateRolledBack,
                    severity: Severity::Warning,
                    summary: format!("serverosd {} was not installed", candidate.version),
                    detail: Some(note),
                    service: None,
                    data: Default::default(),
                    suggested_action: None,
                })
                .await;
            }
        }
    }
}

async fn housekeeping(app: Arc<App>) {
    let mut tick = tokio::time::interval(Duration::from_secs(6 * 3600));

    loop {
        tick.tick().await;
        let now = daemon_state::State::now();
        let _ = app.state.prune_jobs(now - 30 * 86_400);
        let _ = app.state.outbox_trim(5_000);

        // A confirmed update's previous binary is safe to drop after a day.
        if app.on_trial.is_none() && app.guard.confirm().is_none() {
            let previous = app.paths.binary.with_extension("previous");
            if let Ok(meta) = std::fs::metadata(&previous) {
                if meta
                    .modified()
                    .ok()
                    .and_then(|m| m.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(86_400))
                {
                    app.guard.prune_previous();
                }
            }
        }
    }
}
