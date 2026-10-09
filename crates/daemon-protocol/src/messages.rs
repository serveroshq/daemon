use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub machine_id: String,
    pub daemon_version: String,
    pub daemon_commit: String,
    pub channel: String,
    pub supported_majors: Vec<u16>,
    pub facts: MachineFacts,
    #[serde(default)]
    pub oldest_local_sample_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloAck {
    pub major: u16,
    #[serde(default)]
    pub panel_version: String,
    #[serde(default)]
    pub last_seen_seq: Option<u64>,
    #[serde(default)]
    pub mode: PanelMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PanelMode {
    #[default]
    Managed,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MachineFacts {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub kernel: String,
    pub arch: String,
    pub libc: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub memory_bytes: u64,
    pub disks: Vec<DiskFact>,
    pub interfaces: Vec<InterfaceFact>,
    pub timezone: String,
    pub boot_ts: i64,
    #[serde(default)]
    pub init_system: String,
    #[serde(default)]
    pub docker_version: Option<String>,
    #[serde(default)]
    pub hosting: HostingFacts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingFacts {
    pub provider: Option<String>,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub instance_type: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskFact {
    pub mount: String,
    pub device: String,
    pub fs_type: String,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceFact {
    pub name: String,
    pub addresses: Vec<String>,
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Heartbeat {
    pub uptime_secs: u64,
    pub daemon_version: String,
    pub daemon_uptime_secs: u64,
    #[serde(default)]
    pub load_1m: f32,
    #[serde(default)]
    pub running_jobs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sample {
    pub ts: i64,
    #[serde(default)]
    pub service: Option<String>,
    pub cpu_percent: f32,
    #[serde(default)]
    pub cpu_per_core: Vec<f32>,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_available: u64,
    pub mem_cached: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disks: Vec<DiskSample>,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub net_rx_errors: u64,
    pub net_tx_errors: u64,
    pub process_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restarts: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskSample {
    pub mount: String,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub inodes_used: u64,
    pub inodes_free: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryBatch {
    pub samples: Vec<Sample>,
    #[serde(default)]
    pub backfill: bool,
    #[serde(default)]
    pub gap_before: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryReport {
    pub scanned_at: i64,
    pub duration_ms: u64,
    pub complete: bool,
    pub services: Vec<DiscoveredService>,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub certificates: Vec<CertificateInfo>,
    #[serde(default)]
    pub scheduled: Vec<ScheduledTask>,
    #[serde(default)]
    pub unknown: Vec<UnknownListener>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredService {
    pub key: String,
    pub name: String,
    pub kind: ServiceKind,
    pub manager: ServiceManager,
    pub status: ServiceStatus,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub exec: Option<String>,
    #[serde(default)]
    pub config_paths: Vec<String>,
    #[serde(default)]
    pub data_dir: Option<String>,
    pub confidence: u8,
    #[serde(default)]
    pub details: BTreeMap<String, String>,
    pub capabilities: Vec<AdoptedCapability>,
    #[serde(default)]
    pub origin: ServiceOrigin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    WebServer,
    Database,
    Cache,
    App,
    GameServer,
    Container,
    Runtime,
    Proxy,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ServiceManager {
    Systemd,
    Docker,
    Compose,
    Pm2,
    Supervisor,
    Screen,
    Cron,
    Manual,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Running,
    Stopped,
    Failed,
    Restarting,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOrigin {
    #[default]
    Discovered,
    Created,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AdoptedCapability {
    Lifecycle,
    Logs,
    Metrics,
    Config,
    Backup,
    Deploy,
    Rollback,
    Files,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Listener {
    pub proto: String,
    pub address: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub exe: Option<String>,
    pub user: Option<String>,
    #[serde(default)]
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnknownListener {
    pub port: u16,
    pub exe: Option<String>,
    pub pid: Option<u32>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateInfo {
    pub path: String,
    pub subject: String,
    pub issuer: String,
    pub not_after: i64,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub renewal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduledTask {
    pub source: String,
    pub schedule: String,
    pub command: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    pub severity: Severity,
    pub summary: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub data: BTreeMap<String, String>,
    #[serde(default)]
    pub suggested_action: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    DiskFillProjected,
    DiskThreshold,
    MemoryPressure,
    OomKill,
    RestartLoop,
    ServiceCrashed,
    CertificateExpiring,
    SecurityUpdates,
    RebootRequired,
    SustainedLoad,
    ServiceDiscovered,
    ServiceGone,
    UpdateAvailable,
    UpdateApplied,
    UpdateRolledBack,
    DaemonRestarted,
    ClockSkew,
    PreExisting,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Command {
    pub actor: Actor,
    #[serde(default)]
    pub confirmed: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    pub job: Job,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub kind: ActorKind,
    pub name: String,
    #[serde(default)]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    Automation,
    Panel,
    Scheduler,
    Local,
    Daemon,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackupDestination {
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        access_key: String,
        secret_key: String,
        #[serde(default)]
        path_style: bool,
    },
    Sftp {
        host: String,
        #[serde(default = "default_ssh_port")]
        port: u16,
        user: String,
        private_key: String,
        host_key: Option<String>,
    },
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Job {
    Discover,
    Facts,
    ServiceAction {
        service: String,
        action: ServiceAction,
    },
    ServiceLogs {
        service: String,
        lines: u32,
    },
    /// A container's `docker inspect`, any container on the machine, adopted
    /// or not; environment values are never sent.
    ServiceInspect {
        service: String,
    },
    ReadFile {
        path: String,
        service: Option<String>,
    },
    WriteFile {
        path: String,
        content_b64: String,
        mode: Option<u32>,
        service: Option<String>,
    },
    ListDir {
        path: String,
        service: Option<String>,
    },
    DeleteFile {
        path: String,
        service: Option<String>,
    },
    Chmod {
        path: String,
        mode: u32,
        service: Option<String>,
    },
    Chown {
        path: String,
        user: String,
        group: Option<String>,
        service: Option<String>,
    },
    Deploy(Box<DeploySpec>),
    /// Deploy a commit onto an app that runs straight on the machine (a
    /// Laravel app behind PHP-FPM, say): check it out where the app lives,
    /// run its steps as the app's user, reload its services and check it's
    /// healthy, putting the last commit back if any of that fails.
    Release(Box<ReleaseSpec>),
    Rollback {
        service: String,
        release: Option<String>,
        /// Data to put back once the code is rolled back: the snapshots taken
        /// before the deploy that came after the release rolled back to.
        #[serde(default)]
        restore: Vec<SnapshotRef>,
    },
    Backup {
        service: String,
        reason: String,
    },
    BackupTo {
        service: String,
        reason: String,
        prefix: String,
        destination: BackupDestination,
    },
    BackupReceiver {
        public_key: String,
    },
    Restore {
        service: String,
        snapshot: String,
    },
    PackageUpdates {
        apply: bool,
        security_only: bool,
    },
    PackageInstall {
        packages: Vec<String>,
    },
    Reboot,
    FirewallRule {
        action: FirewallAction,
        rule: String,
    },
    SshKey {
        user: String,
        action: KeyAction,
        public_key: String,
    },
    Adopt {
        service: String,
        dry_run: bool,
    },
    ServiceExec {
        service: String,
        command: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    ServiceRepair {
        service: String,
    },
    ServiceRemove {
        service: String,
        #[serde(default)]
        delete_data: bool,
        #[serde(default)]
        delete_adopted_volumes: bool,
    },
    Unadopt {
        service: String,
    },
    OpenTerminal {
        user: String,
        session: Uuid,
    },
    TailLogs {
        source: String,
        session: Uuid,
    },
    DeployKey {
        service: String,
    },
    Snapshots {
        service: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Reload,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAction {
    Allow,
    Deny,
    Delete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum KeyAction {
    Add,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploySpec {
    pub service: String,
    #[serde(default)]
    pub repo: String,
    pub commit: String,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub compose_file: Option<String>,
    #[serde(default)]
    pub dockerfile: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub health: Option<HealthCheck>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Snapshot the app's data before deploying over it, so a deploy that
    /// breaks it (a bad migration) can be rolled back with its data.
    #[serde(default = "default_true")]
    pub snapshot_before: bool,
    /// Other services to snapshot with it, by key: the database the app
    /// keeps its data in, say.
    #[serde(default)]
    pub snapshot_also: Vec<String>,
    /// A short-lived token for a private HTTPS repository (a GitHub App
    /// installation token), sent fresh with each deploy and never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_token: Option<RepoToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseSpec {
    /// The adopted service the app belongs to, by key; the app's folder
    /// must be one ServerOS may open because of it.
    pub service: String,
    /// The app's folder: a git checkout.
    pub path: String,
    /// Who the checkout and the steps run as. Never root.
    pub user: String,
    pub repo: String,
    pub commit: String,
    #[serde(default)]
    pub steps: Vec<ReleaseStep>,
    /// Adopted services to reload or restart once the steps have run.
    #[serde(default)]
    pub reload: Vec<ReleaseReload>,
    /// An https address that answers 200 when the app is up.
    #[serde(default)]
    pub health_url: Option<String>,
    /// Throw away edits made on the machine to files git tracks. Without
    /// it, a checkout with edits is left alone and the release fails.
    #[serde(default)]
    pub discard_changes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_token: Option<RepoToken>,
    /// In place updates the checkout where it is. Atomic builds each
    /// release in a folder of its own beside it and switches the app's
    /// folder (then a link) to it in one step, so the app never runs half
    /// set up, and going back to a kept release is a switch, not a build.
    #[serde(default)]
    pub mode: ReleaseMode,
    /// Atomic only: what every release shares rather than ships, relative
    /// to the app's folder: its .env, its storage.
    #[serde(default = "default_shared")]
    pub shared: Vec<String>,
    /// Atomic only: how many releases to keep for going back to.
    #[serde(default = "default_keep")]
    pub keep: u32,
    /// Atomic only: folders removed from releases once they're no longer
    /// live, to save disk: a Laravel app's node_modules, once its assets
    /// are built. Nothing by default, since a Node app runs from them.
    #[serde(default = "default_trim")]
    pub trim: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseMode {
    #[default]
    InPlace,
    Atomic,
}

fn default_shared() -> Vec<String> {
    vec![".env".into(), "storage".into()]
}

fn default_keep() -> u32 {
    3
}

fn default_trim() -> Vec<String> {
    Vec::new()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseStep {
    pub name: String,
    /// A shell command, run with sh -c in the app's folder.
    pub run: String,
    /// Run it again on the old commit when a release is put back:
    /// installs and builds yes, migrations no.
    #[serde(default = "default_true")]
    pub on_rollback: bool,
    #[serde(default = "default_step_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseReload {
    pub service: String,
    #[serde(default = "default_reload_action")]
    pub action: ServiceAction,
}

fn default_step_timeout() -> u64 {
    600
}

fn default_reload_action() -> ServiceAction {
    ServiceAction::Reload
}

/// A repository token. Its Debug says nothing, so a logged spec doesn't
/// leak it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct RepoToken(pub String);

impl std::fmt::Debug for RepoToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepoToken([redacted])")
    }
}

/// One service's snapshot, by the service's key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotRef {
    pub service: String,
    pub snapshot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthCheck {
    pub path: String,
    #[serde(default = "default_expected_status")]
    pub expected_status: u16,
    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_health_retries")]
    pub retries: u32,
}

fn default_true() -> bool {
    true
}

fn default_expected_status() -> u16 {
    200
}

fn default_health_timeout() -> u64 {
    30
}

fn default_health_retries() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobUpdate {
    pub job_id: Uuid,
    pub state: JobState,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub progress: Option<u8>,
    #[serde(default)]
    pub log: Vec<String>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<JobError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Accepted,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Refused,
    Cancelled,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, JobState::Accepted | JobState::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobError {
    pub phase: String,
    pub message: String,
    #[serde(default)]
    pub output_tail: Vec<String>,
    #[serde(default)]
    pub next_step: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamFrame {
    pub session: Uuid,
    pub kind: StreamKind,
    pub data_b64: String,
    #[serde(default)]
    pub eof: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    PtyInput,
    PtyOutput,
    PtyResize,
    LogLine,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogBatch {
    pub lines: Vec<LogEntry>,
    #[serde(default)]
    pub dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ts: i64,
    pub stream: LogStream,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    pub line: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
    Journal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    SelfUpdate {
        version: String,
        url: String,
        sha256: String,
        signature: String,
        #[serde(default)]
        channel: Option<String>,
        #[serde(default)]
        min_from: Option<String>,
        #[serde(default)]
        approved: bool,
    },
    Reconfigure {
        updates_channel: Option<String>,
        pinned_version: Option<Option<String>>,
        mode: Option<PanelMode>,
    },
    Disconnect {
        reason: String,
    },
    Backfill {
        from_ts: i64,
        to_ts: i64,
    },
    CancelJob {
        job_id: Uuid,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_are_tagged_by_type() {
        let job = Job::ServiceAction {
            service: "nginx".into(),
            action: ServiceAction::Reload,
        };
        let json = serde_json::to_value(&job).unwrap();

        assert_eq!(json["type"], "service_action");
        assert_eq!(json["action"], "reload");
    }

    #[test]
    fn there_is_no_shell_job() {
        let raw = serde_json::json!({"type": "shell", "command": "rm -rf /"});

        assert!(serde_json::from_value::<Job>(raw).is_err());
    }

    #[test]
    fn missing_optional_fields_default() {
        let hello: HelloAck = serde_json::from_str(r#"{"major": 1}"#).unwrap();

        assert_eq!(hello.mode, PanelMode::Managed);
        assert_eq!(hello.last_seen_seq, None);

        let facts: MachineFacts = serde_json::from_str(r#"{"hostname":"box","os":"linux","os_version":"","kernel":"","arch":"x86_64","libc":"","cpu_model":"","cpu_cores":1,"memory_bytes":0,"disks":[],"interfaces":[],"timezone":"UTC","boot_ts":0}"#).unwrap();
        assert_eq!(facts.hosting, HostingFacts::default());
    }

    #[test]
    fn terminal_states_are_terminal() {
        assert!(JobState::Failed.is_terminal());
        assert!(!JobState::Running.is_terminal());
    }
}
