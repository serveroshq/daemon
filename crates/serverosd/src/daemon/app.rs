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
        // Log lines leave with IPs masked when the machine says so. The
        // salt is made on first start and stays on the machine.
        let salt = daemon_core::ipmask::load_salt(&paths.ip_mask_salt()).unwrap_or_default();
        daemon_core::ipmask::configure(config.logs.mask_ips, salt);
        // And never at all for the services and lines the skip rules name.
        let rejected = daemon_core::logskip::configure(&config.logs.skip);
        if !rejected.is_empty() {
            tracing::warn!(patterns = ?rejected, "some log skip patterns aren't valid and are ignored");
        }

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

    pub fn sync_adopted(&self) {
        let adopted = daemon_services::Registry::new(&self.state)
            .all()
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.origin == daemon_protocol::ServiceOrigin::Discovered)
            .map(|m| m.key)
            .collect();
        self.broker.set_adopted_services(adopted);
    }

    /// Folders mounted into the containers ServerOS manages (created or
    /// adopted), as the latest scan saw them: where their files actually
    /// live. System locations are never added.
    pub fn add_mount_roots(&self, report: &daemon_protocol::InventoryReport) {
        let managed: std::collections::BTreeSet<String> =
            daemon_services::Registry::new(&self.state)
                .all()
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.key)
                .collect();
        let known = self
            .files
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .roots()
            .clone();

        let fresh: Vec<PathBuf> = report
            .services
            .iter()
            .filter(|s| s.key.starts_with("docker:") && managed.contains(&s.key))
            .flat_map(|s| mount_sources(s.details.get("mounts").map(String::as_str).unwrap_or("")))
            .filter(|path| {
                daemon_capability::roots::mountable_root(path)
                    && path.is_dir()
                    && !known.permits(path)
            })
            .collect();

        if !fresh.is_empty() {
            self.add_roots(&fresh);
        }
    }

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

/// The host side of each mount in a scan's "src:dst, src:dst" list.
pub fn mount_sources(mounts: &str) -> Vec<PathBuf> {
    mounts
        .split(", ")
        .filter_map(|mount| mount.rsplit_once(':').map(|(source, _)| source.trim()))
        .filter(|source| source.starts_with('/'))
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod mount_tests {
    use super::*;

    #[test]
    fn mount_sources_are_the_host_side() {
        assert_eq!(
            mount_sources("/var/lib/serveros/volumes/8f2c:/home/container, /run/wings/machine-id/8f2c:/etc/machine-id"),
            vec![PathBuf::from("/var/lib/serveros/volumes/8f2c"), PathBuf::from("/run/wings/machine-id/8f2c")]
        );
        assert!(mount_sources("").is_empty());
    }
}
