//! Everything the workers, the handler, and the control loop share.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use daemon_audit::AuditLog;
use daemon_backup::Snapshotter;
use daemon_capability::{Broker, PermittedRoots};
use daemon_core::{BuildInfo, Config, Paths};
use daemon_deploy::container::BuildLimits;
use daemon_deploy::proxy::Proxy;
use daemon_deploy::Deployer;
use daemon_files::Files;
use daemon_identity::Identity;
use daemon_import::Importer;
use daemon_inventory::Scanner;
use daemon_jobs::Runner;
use daemon_protocol::driver::Outbound;
use daemon_protocol::{Event, MachineFacts, PanelMode, StreamFrame};
use daemon_selfupdate::{Candidate, RollbackGuard};
use daemon_state::State;
use daemon_streams::{LogTail, Sessions};
use daemon_supervisor::Supervisor;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub protocol_major: u16,
    pub reconnect_attempt: u32,
    pub mode: PanelMode,
    pub last_panel_ts: Option<i64>,
    pub disconnected_by_panel: bool,
}

pub struct App {
    pub paths: Paths,
    pub config: RwLock<Config>,
    pub build: BuildInfo,
    pub state: Arc<State>,
    pub audit: Arc<AuditLog>,
    pub broker: Arc<Broker>,
    pub identity: Identity,
    pub importer: Importer,
    pub sessions: Sessions,
    pub tails: Mutex<HashMap<Uuid, LogTail>>,
    pub deployer: Deployer,
    pub snapshotter: Snapshotter,
    pub files: RwLock<Files>,
    pub supervisor: Supervisor,
    pub guard: RollbackGuard,
    pub on_trial: Option<(String, String)>,
    pub started: Instant,
    pub facts: RwLock<MachineFacts>,
    pub status: RwLock<ConnectionStatus>,
    pub pending_update: Mutex<Option<(Candidate, bool)>>,
    stopping: std::sync::atomic::AtomicBool,
    outbound: mpsc::Sender<Outbound>,
    stream_tx: mpsc::Sender<StreamFrame>,
    stream_rx: Mutex<Option<mpsc::Receiver<StreamFrame>>>,
    runner: RwLock<Option<Arc<Runner>>>,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        paths: Paths,
        config: Config,
        build: BuildInfo,
        state: Arc<State>,
        audit: Arc<AuditLog>,
        broker: Arc<Broker>,
        identity: Identity,
        outbound: mpsc::Sender<Outbound>,
        guard: RollbackGuard,
        on_trial: Option<(String, String)>,
    ) -> Self {
        let (stream_tx, stream_rx) = mpsc::channel(512);
        let limits = &config.limits;
        let facts = daemon_telemetry::gather_facts();
        let mounts: Vec<PathBuf> = facts
            .disks
            .iter()
            .map(|d| PathBuf::from(&d.mount))
            .collect();

        let mut importer = Importer::new(
            Arc::clone(&state),
            Scanner {
                budget: config
                    .discovery_interval()
                    .min(std::time::Duration::from_secs(config.discovery.budget_secs)),
                ..Default::default()
            },
        );
        importer.mounts = mounts;

        let files = Files::new(PermittedRoots::new(
            daemon_services::Registry::new(&state)
                .permitted_roots()
                .unwrap_or_default()
                .into_iter()
                .chain(config.files.extra_roots.iter().cloned())
                .chain([paths.jobs_dir(), paths.state_dir.join("apps")]),
        ));

        Self {
            deployer: Deployer {
                paths: paths.clone(),
                state: Arc::clone(&state),
                proxy: Proxy::for_backend(config.integrations.proxy),
                build_limits: BuildLimits {
                    cpu_percent: limits.build_cpu_percent,
                    memory_mb: limits.build_memory_mb,
                },
            },
            snapshotter: Snapshotter {
                backups_dir: paths.backups_dir(),
                disk_high_water_percent: limits.disk_high_water_percent,
                retention: daemon_backup::DEFAULT_RETENTION,
            },
            sessions: Sessions::new(
                std::time::Duration::from_secs(limits.terminal_idle_timeout_secs),
                false,
            ),
            tails: Mutex::new(HashMap::new()),
            files: RwLock::new(files),
            supervisor: Supervisor::new(),
            importer,
            paths,
            config: RwLock::new(config),
            build,
            state,
            audit,
            broker,
            identity,
            guard,
            on_trial,
            started: Instant::now(),
            facts: RwLock::new(facts),
            status: RwLock::new(ConnectionStatus::default()),
            pending_update: Mutex::new(None),
            stopping: std::sync::atomic::AtomicBool::new(false),
            outbound,
            stream_tx,
            stream_rx: Mutex::new(Some(stream_rx)),
            runner: RwLock::new(None),
        }
    }

    pub fn set_runner(&self, runner: Arc<Runner>) {
        *self.runner.write().unwrap_or_else(|p| p.into_inner()) = Some(runner);
    }

    pub fn runner(&self) -> Arc<Runner> {
        self.runner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("runner is set at boot")
    }

    pub fn running_jobs(&self) -> usize {
        self.runner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|r| r.running_count())
            .unwrap_or(0)
    }

    pub fn set_stopping(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Send to the panel. The control loop persists durable kinds when
    /// the link is down.
    pub async fn send(&self, message: Outbound) {
        let _ = self.outbound.send(message).await;
    }

    pub async fn raise(&self, event: Event) {
        self.send(Outbound::Event(event)).await;
    }

    pub fn stream_sender(&self) -> mpsc::Sender<StreamFrame> {
        self.stream_tx.clone()
    }

    pub fn take_stream_receiver(&self) -> Option<mpsc::Receiver<StreamFrame>> {
        self.stream_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    /// A newly adopted service opens its directories to the file layer
    /// and the broker.
    pub fn add_roots(&self, roots: &[PathBuf]) {
        for root in roots {
            self.broker.add_root(root.clone());
        }

        let mut files = self.files.write().unwrap_or_else(|p| p.into_inner());
        let mut all = PermittedRoots::new(files.roots().iter().map(|p| p.to_path_buf()));
        for root in roots {
            all.add(root.clone());
        }
        *files = Files::new(all);
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn machine_uptime_secs(&self) -> u64 {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
            .map(|s| s as u64)
            .unwrap_or(0)
    }
}
