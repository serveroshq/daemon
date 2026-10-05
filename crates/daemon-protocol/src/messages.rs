//! Payload types for protocol major 1. Plain data, serde-shaped, with
//! defaults on every field added after the first release so old panels and
//! old daemons keep parsing each other.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------- handshake

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub machine_id: String,
    pub daemon_version: String,
    pub daemon_commit: String,
    pub channel: String,
    /// Protocol majors this daemon can speak, newest first.
    pub supported_majors: Vec<u16>,
    pub facts: MachineFacts,
    /// Where the daemon's local history starts, so the panel knows how far
    /// back it may ask for a backfill.
    #[serde(default)]
    pub oldest_local_sample_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloAck {
    pub major: u16,
    #[serde(default)]
    pub panel_version: String,
    /// The panel's last seen sequence from this daemon, for gap detection
    /// across reconnects.
    #[serde(default)]
    pub last_seen_seq: Option<u64>,
    /// "read_only" makes the daemon refuse every mutating command.
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

// ---------------------------------------------------------------- facts

/// Static-ish description of the machine, sent on connect and whenever it
/// changes (a reboot into a new kernel, a resized disk).
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

/// Provider supplied instance details. Missing fields mean the platform did
/// not expose them; a machine timezone is never treated as a location.
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

// ---------------------------------------------------------------- liveness

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Heartbeat {
    pub uptime_secs: u64,
    pub daemon_version: String,
    pub daemon_uptime_secs: u64,
    #[serde(default)]
    pub load_1m: f32,
    /// Jobs currently executing, so the panel can hold updates and restarts.
    #[serde(default)]
    pub running_jobs: u32,
}

// ---------------------------------------------------------------- telemetry

/// One sample. `service` is `None` for the machine as a whole.
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
    /// Per-service samples only: when the service last started (unix
    /// seconds) and how many times its manager has restarted it.
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

/// A batch of samples, either live or a backfill. `gap_before` marks that
/// samples older than the first one here were lost (buffer overrun, a
/// crash) so the panel draws a break instead of a flat line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryBatch {
    pub samples: Vec<Sample>,
    #[serde(default)]
    pub backfill: bool,
    #[serde(default)]
    pub gap_before: bool,
}

// ---------------------------------------------------------------- inventory

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryReport {
    pub scanned_at: i64,
    pub duration_ms: u64,
    /// Whether the scan finished inside its budget. A truncated scan is
    /// still reported, honestly labelled.
    pub complete: bool,
    pub services: Vec<DiscoveredService>,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub certificates: Vec<CertificateInfo>,
    #[serde(default)]
    pub scheduled: Vec<ScheduledTask>,
    /// Anything discovery could not classify. Reported as-is rather than
    /// guessed at.
    #[serde(default)]
    pub unknown: Vec<UnknownListener>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredService {
    /// Stable across scans: `systemd:nginx.service`, `docker:<container id>`.
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
    /// 0..=100. Below 60 the panel shows it as a guess.
    pub confidence: u8,
    #[serde(default)]
    pub details: BTreeMap<String, String>,
    /// What ServerOS could actually do with this service if adopted.
    pub capabilities: Vec<AdoptedCapability>,
    /// Whether ServerOS created it or found it.
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

/// The capability matrix. An adopted service advertises exactly what works
/// for it rather than a generic set of disabled buttons.
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
}

// ---------------------------------------------------------------- events

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
    /// If the daemon knows the fix, it says so and the panel shows a button.
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

// ---------------------------------------------------------------- commands

/// A durable job. `id` is the envelope id; the payload is one of the
/// fixed job types. There is deliberately no "run this shell string" job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Command {
    /// Who in the panel asked. Recorded in actions.log verbatim.
    pub actor: Actor,
    /// The user confirmed a preview or typed a confirmation; required for
    /// the operations that demand it (restore, reboot, reinstall).
    #[serde(default)]
    pub confirmed: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    pub job: Job,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub kind: ActorKind,
    /// The panel user's email or the automation's name.
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

/// Where a backup goes. Credentials come from the panel with each job and
/// are never written to disk, apart from an SFTP key held in a 0600 file
/// for the length of the upload.
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
        /// The receiver's host key line, pinned so a backup can't be
        /// sent to a machine pretending to be the receiver.
        host_key: Option<String>,
    },
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Job {
    /// Read-only: rescan services now.
    Discover,
    /// Read-only: resend machine facts.
    Facts,
    ServiceAction {
        service: String,
        action: ServiceAction,
    },
    ServiceLogs {
        service: String,
        lines: u32,
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
    Deploy(DeploySpec),
    Rollback {
        service: String,
        release: Option<String>,
    },
    Backup {
        service: String,
        reason: String,
    },
    /// Snapshot a service and send it off the machine: to S3-compatible
    /// storage, or over SFTP to another machine set up as a receiver.
    /// Objects land at `<prefix>/<service>/<snapshot id>/<file>`.
    BackupTo {
        service: String,
        reason: String,
        prefix: String,
        destination: BackupDestination,
    },
    /// Let another machine's daemon drop backups here over SFTP, as the
    /// `serveros-backups` user, which can do nothing but SFTP into its
    /// home directory.
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
    /// Run a one-off command inside a service's container (`sh -c`).
    ServiceExec {
        service: String,
        command: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// Remove a service ServerOS created: its containers, network and
    /// proxy site; its volumes too when `delete_data` is set.
    ServiceRemove {
        service: String,
        #[serde(default)]
        delete_data: bool,
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
    /// The machine's public deploy key for a service, generated if missing.
    DeployKey {
        service: String,
    },
    /// Read-only: the snapshots on disk for a service.
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
    /// Git repository to build from. Empty for deploys made entirely of
    /// `files`, such as a service template's Compose file.
    #[serde(default)]
    pub repo: String,
    /// The commit to build, or for file-only deploys the template revision
    /// (any 40-hex digest); it names the release either way.
    pub commit: String,
    /// Files written into the workspace after the source is fetched, keyed
    /// by relative path: a template's Compose file, or a Dockerfile under
    /// `.serveros/` for an app that has none. Paths are confined to the
    /// workspace.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub compose_file: Option<String>,
    #[serde(default)]
    pub dockerfile: Option<String>,
    /// Encrypted panel-side; decrypted only in transit to this daemon.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub health: Option<HealthCheck>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub port: Option<u16>,
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

fn default_expected_status() -> u16 {
    200
}

fn default_health_timeout() -> u64 {
    30
}

fn default_health_retries() -> u32 {
    5
}

// ---------------------------------------------------------------- job updates

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

/// A failure that names the phase and carries the real output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobError {
    pub phase: String,
    pub message: String,
    #[serde(default)]
    pub output_tail: Vec<String>,
    /// What a person can do next.
    #[serde(default)]
    pub next_step: Option<String>,
}

// ---------------------------------------------------------------- streams

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamFrame {
    pub session: Uuid,
    pub kind: StreamKind,
    /// base64 of the bytes; PTY data is not always UTF-8.
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

// ------------------------------------------------------------------- logs

/// Daemon → panel: lines from the services on the machine, shipped as they
/// are written so the panel can keep and search them. Every line has been
/// redacted. Best effort: lines written while the link is down are lost.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogBatch {
    pub lines: Vec<LogEntry>,
    /// Lines the daemon dropped since the last batch because a service
    /// logged faster than the per-service cap.
    #[serde(default)]
    pub dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    /// The service the line came from, keyed as discovery keys it
    /// (`docker:<short id>`, `systemd:<unit>`).
    pub service: String,
    /// When the service wrote it, unix milliseconds.
    pub ts: i64,
    /// `stdout` or `stderr` for containers; journald lines are `journal`.
    pub stream: LogStream,
    /// syslog severity 0-7 when the source says (journald does), so the
    /// panel needn't guess.
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

// ---------------------------------------------------------------- control

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// Update to `version` from `url`, checked against `signature` (ed25519
    /// over the binary, base64). Refused while a pin is set. `approved`
    /// means a person confirmed this specific version in the panel, which
    /// lifts the automatic-updates and major-version gates.
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
    /// Stop management; leave everything running.
    Disconnect {
        reason: String,
    },
    /// The panel wants samples from `from_ts` to `to_ts` again.
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
        // The capability boundary is enforced by the type system: if this
        // ever parses, someone added a generic exec path.
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
