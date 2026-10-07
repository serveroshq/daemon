mod app;
mod backup_ops;
mod control;
mod handler;
mod local;
mod log_shipper;
mod machine;
mod service_ops;
mod service_stats;
mod workers;

use std::sync::Arc;
use std::time::Duration;

use daemon_audit::AuditLog;
use daemon_capability::{Broker, PermittedRoots};
use daemon_core::{BuildInfo, Config, Paths};
use daemon_identity::Identity;
use daemon_jobs::Runner;
use daemon_selfupdate::rollback::BootDecision;
use daemon_selfupdate::RollbackGuard;
use daemon_state::State;
use daemon_supervisor::StartHistory;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub use app::App;

pub const EXIT_RESTART: i32 = 75;

pub fn run(paths: Paths) -> anyhow::Result<()> {
    crate::cli::require_root("running the daemon")?;
    crate::logging::init(&paths.daemon_log(), crate::logging::is_terminal())?;

    let build = BuildInfo::current();
    info!("{}", build.banner());

    let guard = RollbackGuard {
        binary: paths.binary.clone(),
        state_dir: paths.state_dir.clone(),
    };
    let on_trial = match guard.on_boot(build.version) {
        BootDecision::Normal => None,
        BootDecision::OnTrial { from, to, attempt } => {
            info!(from, to, attempt, "running a freshly installed release");
            Some((from, to))
        }
        BootDecision::RolledBack { from, to } => {
            error!(from, to, "new release failed to start repeatedly; the previous binary was restored and will start now");
            std::process::exit(EXIT_RESTART);
        }
    };

    let config = Config::load(&paths.config_file()).map_err(|e| {
        anyhow::anyhow!("{e}. Run `serverosd enrol --token …` to enrol this machine.")
    })?;
    let identity = Identity::load(&paths)
        .map_err(|e| anyhow::anyhow!("{e}. Run `serverosd enrol` to (re-)enrol this machine."))?;

    if let Err(e) = identity.check_validity(time::OffsetDateTime::now_utc().unix_timestamp()) {
        warn!(error = %e, "client certificate is not currently valid; the panel will refuse the connection until it is rotated");
    }

    for (dir, _) in paths.owned_directories() {
        std::fs::create_dir_all(dir)?;
    }

    let state = Arc::new(State::open(&paths.state_db())?);
    let audit = Arc::new(AuditLog::open(&paths.actions_log())?);
    let recent_starts = StartHistory {
        path: paths.state_dir.join("starts"),
    }
    .record(State::now());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;

    rt.block_on(async move {
        let mut roots = PermittedRoots::new(daemon_services::Registry::new(&state).permitted_roots().unwrap_or_default());
        roots.add(paths.jobs_dir());
        roots.add(paths.state_dir.join("apps"));
        for extra in &config.files.extra_roots {
            roots.add(extra.clone());
        }

        let mut broker_state = daemon_capability::broker::BrokerState { roots, ..Default::default() };
        for managed in daemon_services::Registry::new(&state).all().unwrap_or_default() {
            match managed.origin {
                daemon_protocol::ServiceOrigin::Created => broker_state.created.services.push(managed.key.clone()),
                daemon_protocol::ServiceOrigin::Discovered => broker_state.adopted.push(managed.key.clone()),
            }
        }
        broker_state.created.users.push("serveros".into());
        broker_state.created.users.push(backup_ops::RECEIVER_USER.into());
        let broker = Arc::new(Broker::new(Arc::clone(&audit), broker_state));

        let (outbound_tx, outbound_rx) = mpsc::channel(1024);
        let (job_updates_tx, job_updates_rx) = mpsc::channel(1024);

        let app = Arc::new(App::new(paths.clone(), config, build, Arc::clone(&state), audit, broker, identity, outbound_tx, guard, on_trial));

        let handler = Arc::new(handler::JobHandler { app: Arc::clone(&app) });
        let runner = Arc::new(Runner::new(Arc::clone(&state), handler, job_updates_tx, app.config.read().unwrap().job_timeout()));
        app.set_runner(Arc::clone(&runner));

        let closed = runner.close_unfinished("restarted").await;
        if closed > 0 {
            warn!(closed, "closed jobs that were running when the daemon last stopped");
        }

        if recent_starts > 5 {
            app.raise(daemon_protocol::Event {
                kind: daemon_protocol::EventKind::DaemonRestarted,
                severity: daemon_protocol::Severity::Critical,
                summary: format!("serverosd has started {recent_starts} times in ten minutes"),
                detail: Some("Something is crashing it on start. Customer services are unaffected; check `journalctl -u serverosd`.".into()),
                service: None,
                data: Default::default(),
                suggested_action: None,
            })
            .await;
        }

        workers::forward_job_updates(Arc::clone(&app), job_updates_rx);
        workers::forward_streams(Arc::clone(&app));
        workers::spawn_all(Arc::clone(&app));
        local::serve(Arc::clone(&app));

        let control = tokio::spawn(control::run(Arc::clone(&app), outbound_rx));

        tokio::select! {
            _ = control => {}
            _ = shutdown_signal() => {
                info!("shutdown requested; finishing running jobs");
                app.set_stopping();
                let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                while app.running_jobs() > 0 && tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }

        info!("serverosd stopped");
        let _ = std::fs::remove_file(paths.control_socket());
    });

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");

    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
