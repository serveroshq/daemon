use std::sync::Arc;

use daemon_protocol::driver::{Inbound, Outbound};
use daemon_protocol::{
    Control, Event, EventKind, Heartbeat, Hello, JobUpdate, PanelMode, Severity, TelemetryBatch,
};
use daemon_selfupdate::{decide, Candidate, Decision, Policy};
use daemon_transport::{control_url, Backoff, Link, LinkEvent};
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::app::App;

const OUTBOX_KEEP: usize = 5_000;

pub async fn run(app: Arc<App>, mut outbound: mpsc::Receiver<Outbound>) {
    let mut backoff = Backoff::default();

    loop {
        if app.stopping() || app.status.read().unwrap().disconnected_by_panel {
            return;
        }

        let (host, port) = {
            let c = app.config.read().unwrap();
            (c.panel.host.clone(), c.panel.port)
        };
        let url = control_url(&host, port);
        let hello = hello(&app);
        let heartbeat = heartbeat_source(Arc::clone(&app));

        let link = match Link::connect(&url, &app.identity, hello, heartbeat).await {
            Ok(link) => link,
            Err(e) => {
                let delay = backoff.next_delay();
                {
                    let mut s = app.status.write().unwrap();
                    s.connected = false;
                    s.reconnect_attempt = backoff.attempt();
                }
                warn!(error = %e, retry_in = ?delay, "control channel down");
                let sleep = tokio::time::sleep(delay);
                tokio::pin!(sleep);
                loop {
                    tokio::select! {
                        _ = &mut sleep => break,
                        Some(m) = outbound.recv() => persist(&app, m),
                    }
                }
                continue;
            }
        };

        backoff.reset();
        on_connected(&app, &link).await;

        let mut link = link;
        let reason = pump(&app, &mut link, &mut outbound).await;
        {
            let mut s = app.status.write().unwrap();
            s.connected = false;
        }
        info!(reason = %reason, "control channel closed");
    }
}

fn parse_masking(value: &str) -> Option<daemon_core::ipmask::IpMasking> {
    use daemon_core::ipmask::IpMasking;
    match value {
        "off" => Some(IpMasking::Off),
        "partial" => Some(IpMasking::Partial),
        "hash" => Some(IpMasking::Hash),
        _ => None,
    }
}

fn masking_name(masking: daemon_core::ipmask::IpMasking) -> &'static str {
    use daemon_core::ipmask::IpMasking;
    match masking {
        IpMasking::Off => "off",
        IpMasking::Partial => "partial",
        IpMasking::Hash => "hash",
    }
}

fn skip_to_wire(skip: &daemon_core::logskip::LogSkip) -> daemon_protocol::LogSkipRules {
    daemon_protocol::LogSkipRules {
        services: skip.services.clone(),
        patterns: skip
            .patterns
            .iter()
            .map(|p| daemon_protocol::LogSkipPattern {
                service: p.service.clone(),
                pattern: p.pattern.clone(),
            })
            .collect(),
    }
}

fn skip_from_wire(rules: daemon_protocol::LogSkipRules) -> daemon_core::logskip::LogSkip {
    daemon_core::logskip::LogSkip {
        services: rules.services,
        patterns: rules
            .patterns
            .into_iter()
            .map(|p| daemon_core::logskip::SkipPattern {
                service: p.service,
                pattern: p.pattern,
            })
            .collect(),
    }
}

fn hello(app: &App) -> Hello {
    let facts = app.facts.read().unwrap().clone();
    let config = app.config.read().unwrap();

    Hello {
        machine_id: config.machine.id.clone(),
        daemon_version: app.build.version.into(),
        daemon_commit: app.build.commit.into(),
        channel: config.updates.channel.clone(),
        supported_majors: daemon_protocol::SUPPORTED_MAJORS.to_vec(),
        facts,
        oldest_local_sample_ts: app.state.oldest_sample_ts().ok().flatten(),
        log_ip_masking: Some(masking_name(config.logs.mask_ips).to_string()),
        log_skip: Some(skip_to_wire(&config.logs.skip)),
    }
}

fn heartbeat_source(app: Arc<App>) -> daemon_transport::link::HeartbeatSource {
    Arc::new(move || Heartbeat {
        uptime_secs: app.machine_uptime_secs(),
        daemon_version: app.build.version.into(),
        daemon_uptime_secs: app.uptime_secs(),
        load_1m: std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|t| t.split_whitespace().next()?.parse().ok())
            .unwrap_or(0.0),
        running_jobs: app.running_jobs() as u32,
    })
}

async fn on_connected(app: &App, link: &Link) {
    {
        let mut s = app.status.write().unwrap();
        s.connected = true;
        s.protocol_major = link.major;
        s.reconnect_attempt = 0;
        s.mode = link.ack.mode;
    }

    app.runner().set_mode(link.ack.mode);
    app.broker
        .set_read_only(matches!(link.ack.mode, PanelMode::ReadOnly));

    if let Some(marker) = app.guard.confirm() {
        app.raise(Event {
            kind: EventKind::UpdateApplied,
            severity: Severity::Info,
            summary: format!("serverosd updated from {} to {}", marker.from, marker.to),
            detail: None,
            service: None,
            data: Default::default(),
            suggested_action: None,
        })
        .await;
    }

    loop {
        let items = match app.state.outbox_peek(100) {
            Ok(items) if !items.is_empty() => items,
            _ => break,
        };
        let mut acked = Vec::new();

        for item in items {
            let message = match item.kind.as_str() {
                "job_update" => serde_json::from_str::<JobUpdate>(&item.payload)
                    .ok()
                    .map(Outbound::JobUpdate),
                "event" => serde_json::from_str::<Event>(&item.payload)
                    .ok()
                    .map(Outbound::Event),
                _ => None,
            };

            match message {
                Some(m) => {
                    if link.tx.send(m).await.is_err() {
                        let _ = app.state.outbox_ack(&acked);
                        return;
                    }
                    acked.push(item.id);
                }
                None => acked.push(item.id),
            }
        }

        let _ = app.state.outbox_ack(&acked);
    }

    let last_sent = app
        .state
        .kv_get("telemetry.last_sent_ts")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let now = daemon_state::State::now();
    if last_sent > 0 && now - last_sent > 60 {
        backfill(app, link, last_sent, now).await;
    }

    info!(major = link.major, "connected; outbox drained");
}

async fn backfill(app: &App, link: &Link, from: i64, to: i64) {
    let samples = app
        .state
        .samples_between(from, to, 4000)
        .unwrap_or_default();
    let gap_before = app
        .state
        .oldest_sample_ts()
        .ok()
        .flatten()
        .is_some_and(|oldest| oldest > from);
    let parsed: Vec<daemon_protocol::Sample> = samples
        .iter()
        .filter_map(|s| serde_json::from_str(&s.payload).ok())
        .collect();

    for chunk in daemon_telemetry::aggregate::downsample(&parsed, 60).chunks(500) {
        let _ = link
            .tx
            .send(Outbound::Telemetry(TelemetryBatch {
                samples: chunk.to_vec(),
                backfill: true,
                gap_before,
            }))
            .await;
    }
}

fn persist(app: &App, message: Outbound) {
    let (kind, payload) = match &message {
        Outbound::JobUpdate(u) => ("job_update", serde_json::to_string(u)),
        Outbound::Event(e) => ("event", serde_json::to_string(e)),
        _ => return,
    };

    if let Ok(payload) = payload {
        let _ = app.state.outbox_push(kind, &payload);
        let _ = app.state.outbox_trim(OUTBOX_KEEP);
    }
}

async fn pump(app: &Arc<App>, link: &mut Link, outbound: &mut mpsc::Receiver<Outbound>) -> String {
    loop {
        tokio::select! {
            Some(message) = outbound.recv() => {
                if let Outbound::Telemetry(batch) = &message {
                    if let Some(newest) = batch.samples.iter().map(|s| s.ts).max() {
                        let _ = app.state.kv_set("telemetry.last_sent_ts", &newest.to_string());
                    }
                }
                if link.tx.send(message.clone()).await.is_err() {
                    persist(app, message);
                    return "send failed".into();
                }
            }
            event = link.rx.recv() => match event {
                Some(LinkEvent::Message(inbound)) => dispatch(app, inbound).await,
                Some(LinkEvent::Gap { from, to }) => warn!(from, to, "sequence gap from the panel"),
                Some(LinkEvent::Closed(e)) => return e.to_string(),
                None => return "link task ended".into(),
            }
        }

        if app.stopping() {
            return "stopping".into();
        }
    }
}

async fn dispatch(app: &Arc<App>, inbound: Inbound) {
    match inbound {
        Inbound::Command { id, command } => app.runner().submit(id, command).await,
        Inbound::Stream(frame) => app.sessions.handle_frame(&frame).await,
        Inbound::HelloAck(_) | Inbound::Gap { .. } => {}
        Inbound::Control { control, .. } => match control {
            Control::CancelJob { job_id } => {
                app.runner().cancel(job_id);
            }
            Control::Backfill { from_ts, to_ts } => {
                let samples = app
                    .state
                    .samples_between(from_ts, to_ts, 4000)
                    .unwrap_or_default();
                let parsed: Vec<daemon_protocol::Sample> = samples
                    .iter()
                    .filter_map(|s| serde_json::from_str(&s.payload).ok())
                    .collect();
                let gap_before = app
                    .state
                    .oldest_sample_ts()
                    .ok()
                    .flatten()
                    .is_some_and(|o| o > from_ts);
                for chunk in daemon_telemetry::aggregate::downsample(&parsed, 60).chunks(500) {
                    app.send(Outbound::Telemetry(TelemetryBatch {
                        samples: chunk.to_vec(),
                        backfill: true,
                        gap_before,
                    }))
                    .await;
                }
            }
            Control::Reconfigure {
                updates_channel,
                pinned_version,
                mode,
                log_ip_masking,
                log_skip,
            } => {
                let mut changed = Vec::new();
                {
                    let mut config = app.config.write().unwrap();
                    if let Some(masking) = log_ip_masking.as_deref().and_then(parse_masking) {
                        config.logs.mask_ips = masking;
                        daemon_core::ipmask::set_mode(masking);
                        changed.push(format!("log_ip_masking={}", masking_name(masking)));
                    }
                    if let Some(rules) = log_skip {
                        let skip = skip_from_wire(rules);
                        let rejected = daemon_core::logskip::configure(&skip);
                        changed.push(format!(
                            "log_skip={} services, {} patterns",
                            skip.services.len(),
                            skip.patterns.len()
                        ));
                        if !rejected.is_empty() {
                            changed.push(format!("unusable patterns: {}", rejected.join(" | ")));
                        }
                        config.logs.skip = skip;
                    }
                    if let Some(channel) = updates_channel {
                        config.updates.channel = channel.clone();
                        changed.push(format!("channel={channel}"));
                    }
                    if let Some(pin) = pinned_version {
                        changed.push(format!(
                            "pin={}",
                            pin.clone().unwrap_or_else(|| "none".into())
                        ));
                        config.updates.pinned_version = pin;
                    }
                    let _ = config.save(&app.paths.config_file());
                }
                if let Some(mode) = mode {
                    app.runner().set_mode(mode);
                    app.broker
                        .set_read_only(matches!(mode, PanelMode::ReadOnly));
                    app.status.write().unwrap().mode = mode;
                    changed.push(format!("mode={mode:?}").to_lowercase());
                }
                let _ = app.audit.record(daemon_audit::Entry {
                    actor: &daemon_audit::Actor::automation("panel"),
                    action: "daemon.reconfigure",
                    target: "this machine",
                    outcome: daemon_audit::Outcome::Ok,
                    duration: None,
                    note: Some(&changed.join(" ")),
                });
            }
            Control::Disconnect { reason } => {
                let _ = app.audit.record(daemon_audit::Entry {
                    actor: &daemon_audit::Actor::automation("panel"),
                    action: "daemon.disconnect",
                    target: "this machine",
                    outcome: daemon_audit::Outcome::Ok,
                    duration: None,
                    note: Some(&reason),
                });
                info!(
                    reason,
                    "panel disconnected this machine; management stops, services keep running"
                );
                app.status.write().unwrap().disconnected_by_panel = true;
                for file in [
                    app.paths.private_key(),
                    app.paths.client_cert(),
                    app.paths.pinned_ca(),
                ] {
                    let _ = std::fs::remove_file(file);
                }
                let _ = std::process::Command::new("systemctl")
                    .args(["disable", "--no-block", "serverosd.service"])
                    .status();
                app.set_stopping();
            }
            Control::SelfUpdate {
                version,
                url,
                sha256,
                signature,
                channel,
                min_from,
                approved,
            } => {
                let candidate = Candidate {
                    version,
                    url,
                    sha256,
                    signature,
                    channel: channel.unwrap_or_else(|| "stable".into()),
                    min_from,
                    notes_url: None,
                };
                consider_update(app, candidate, approved).await;
            }
        },
    }
}

pub async fn consider_update(app: &Arc<App>, candidate: Candidate, approved: bool) {
    let policy = Policy::from(&app.config.read().unwrap().updates);
    let local_minutes = time::OffsetDateTime::now_local()
        .map(|t| t.hour() as u16 * 60 + t.minute() as u16)
        .unwrap_or(0);

    match decide(
        &policy,
        app.build.version,
        &candidate,
        approved,
        app.running_jobs(),
        local_minutes,
    ) {
        Decision::Install | Decision::Defer(_) => {
            info!(version = %candidate.version, "update accepted; installing when no jobs are running");
            *app.pending_update.lock().unwrap() = Some((candidate, approved));
        }
        Decision::NeedsApproval(reason) => {
            app.raise(Event {
                kind: EventKind::UpdateAvailable,
                severity: Severity::Info,
                summary: format!("serverosd {} is available", candidate.version),
                detail: Some(reason),
                service: None,
                data: [("version".to_string(), candidate.version.clone())].into(),
                suggested_action: Some("Approve the update for this machine.".into()),
            })
            .await;
        }
        Decision::Refuse(reason) => {
            info!(version = %candidate.version, reason, "update refused");
            let _ = app.audit.record(daemon_audit::Entry {
                actor: &daemon_audit::Actor::automation("panel"),
                action: "daemon.update",
                target: &candidate.version,
                outcome: daemon_audit::Outcome::Refused,
                duration: None,
                note: Some(&reason),
            });
        }
    }
}
