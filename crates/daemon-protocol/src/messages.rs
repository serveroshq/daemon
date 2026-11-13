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
    /// How IP addresses in log lines are masked before they leave: "off",
    /// "partial" or "hash". Missing from daemons that can't.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_ip_masking: Option<String>,
    /// Services and line patterns never sent. Missing from daemons that
    /// can't skip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_skip: Option<LogSkipRules>,
    /// Whether the daemon reads SSH settings and failed sign-ins for the
    /// panel's security watch. Missing from daemons that can't.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_watch: Option<bool>,
    /// Whether the daemon looks for what's running on its own. Missing
    /// from daemons that can't be told not to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<bool>,
    /// Whether log lines are sent at all. Missing from daemons that can't
    /// be told not to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<bool>,
    /// Whether new releases install on their own or wait for the panel.
    /// Missing from daemons that can't be told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates_automatic: Option<bool>,
    /// Whether crash and error reports are on in `daemon.toml`. Missing
    /// from daemons that can't be told. A local `SERVEROS_ERROR_REPORTS=0`
    /// still keeps them off whatever this says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reports: Option<bool>,
    /// The version it stays on; null when it doesn't. Always sent (even as
    /// null), so a panel can tell "no pin" from a daemon that can't say:
    /// those leave it out.
    #[serde(default, deserialize_with = "present")]
    pub pinned_version: Option<Option<String>>,
}

/// What the panel decides for a machine: each one present is applied and
/// kept, each one missing is left as it is. Sent in `reconfigure` and, for
/// a new machine, with its enrolment, so it holds from the first start.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<bool>,
    /// "off", "partial" or "hash": masking IPs in outgoing log lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_ip_masking: Option<String>,
    /// Replaces the machine's log skip rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_skip: Option<LogSkipRules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_watch: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates_automatic: Option<bool>,
    /// Crash and error reports to ServerOS, switched without a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reports: Option<bool>,
    /// "stable" or "canary".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates_channel: Option<String>,
    /// A version to stay on, or null to stop staying on one.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub pinned_version: Option<Option<String>>,
}

/// Tells a field that's there but null (`Some(None)`, "clear it") apart
/// from one that's missing (`None`, "leave it").
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Log skip rules as the panel and daemon pass them: service names (with
/// `*`) whose lines are never sent, and line patterns (regular
/// expressions), each for every service or the ones its rule matches.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogSkipRules {
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<LogSkipPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogSkipPattern {
    #[serde(default)]
    pub service: Option<String>,
    pub pattern: String,
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
    /// What the security watch reads: SSH settings, failed sign-ins and
    /// automatic updates. None while the watch is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityFacts>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SecurityFacts {
    /// The SSH server's effective settings; None when there isn't one.
    pub ssh: Option<SshFacts>,
    /// Failed SSH sign-ins in the last `window_secs`; None when the
    /// machine's logs couldn't be read.
    pub logins: Option<LoginFacts>,
    /// Whether security updates install themselves (unattended-upgrades,
    /// dnf-automatic); None when the package manager isn't one we know.
    pub auto_updates: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SshFacts {
    pub ports: Vec<u16>,
    /// As sshd says it: yes, no, prohibit-password or forced-commands-only.
    pub permit_root_login: String,
    pub password_authentication: bool,
    pub kbd_interactive_authentication: bool,
    pub use_pam: bool,
    /// "sshd -T" when it ran, "config" when read from sshd_config.
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LoginFacts {
    pub window_secs: u64,
    /// Connections that failed to sign in (each source address and port
    /// once, however many tries it made).
    pub failed: u32,
    /// Distinct addresses they came from. The addresses themselves never
    /// leave the machine.
    pub sources: u32,
    /// Failed connections that tried root.
    pub root: u32,
    /// Connections that signed in with a password.
    pub accepted_password: u32,
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
    /// What the firewall lets in, from the backend ServerOS changes rules
    /// with. Absent from daemons that don't read it.
    #[serde(default)]
    pub firewall: Option<FirewallReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FirewallReport {
    /// ufw, nftables, iptables or none: the `[integrations] firewall` setting.
    pub backend: String,
    pub installed: bool,
    /// Whether it filters incoming traffic at all (ufw can be installed but off).
    pub active: bool,
    #[serde(default)]
    pub default_incoming: Option<FirewallVerdict>,
    /// Rules about incoming traffic, in the order they're checked.
    #[serde(default)]
    pub rules: Vec<FirewallRuleInfo>,
    /// Each port listening beyond loopback, and whether the firewall lets the
    /// internet reach it.
    #[serde(default)]
    pub ports: Vec<PortExposure>,
    /// Rules ServerOS couldn't read (interfaces, jumps to other chains): a
    /// port they might open or close is reported as unknown, never blocked.
    #[serde(default)]
    pub unreadable: u32,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FirewallVerdict {
    Allow,
    /// ufw's rate-limited allow.
    Limit,
    Deny,
    Reject,
}

impl FirewallVerdict {
    pub fn lets_in(self) -> bool {
        matches!(self, FirewallVerdict::Allow | FirewallVerdict::Limit)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallRuleInfo {
    pub verdict: FirewallVerdict,
    /// Empty: every port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    /// tcp or udp; none for both.
    #[serde(default)]
    pub proto: Option<String>,
    /// An address or CIDR; none for anywhere.
    #[serde(default)]
    pub source: Option<String>,
    /// Applies to IPv6 only.
    #[serde(default)]
    pub ipv6: bool,
    /// Added by ServerOS.
    #[serde(default)]
    pub managed: bool,
    /// Matches ServerOS can't read (an interface, a jump to another chain):
    /// its verdict and ports are as far as could be told, and a port it may
    /// let in is reported as unknown.
    #[serde(default)]
    pub opaque: bool,
    /// The rule as the firewall shows it.
    pub text: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortExposure {
    pub port: u16,
    pub proto: String,
    pub exposure: Exposure,
    /// The rule or policy that decided it.
    #[serde(default)]
    pub because: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// Anyone on the internet can connect.
    Open,
    /// Only some addresses are allowed.
    Restricted,
    Blocked,
    /// Published by Docker, whose rules come before the host firewall's.
    Docker,
    /// Rules ServerOS can't read may decide it.
    Unknown,
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
    /// How the person asked: "mcp" (an AI agent), "api", "web", "workflow".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// The app they asked through, like "Claude".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// The MCP tool or API operation that asked for this job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// The panel's id for that call, to match this job to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<String>,
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
    /// Install packages that aren't on the machine yet, by name, from the
    /// repositories it already has. A job of its own rather than a field on
    /// `PackageInstall` (which only upgrades), so a daemon that predates it
    /// refuses the job instead of upgrading and reporting success.
    PackageAdd {
        packages: Vec<String>,
    },
    /// Install exactly these versions, for machines that should match each
    /// other or a version tested elsewhere. A job of its own rather than a
    /// field on `PackageInstall`, so a daemon that predates it drops the job
    /// instead of installing the latest versions. Held packages stay held.
    PackageInstallVersions {
        packages: Vec<PackageVersion>,
        #[serde(default)]
        allow_downgrade: bool,
    },
    /// Hold packages at the version installed (apt-mark, or dnf/yum
    /// versionlock), or let them go again.
    PackageHold {
        packages: Vec<String>,
        hold: bool,
    },
    /// Restart the services still running files an update replaced, so the
    /// update takes effect without a reboot. Only units the daemon finds
    /// stale when the job runs are restarted; `systemd` re-executes PID 1
    /// in place when it is.
    RestartStale {
        units: Vec<String>,
        #[serde(default)]
        systemd: bool,
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
        /// Settings handed to the command inside the container, by name,
        /// so secrets (a database password) stay out of the command line,
        /// the job's log and `ps`.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
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
    /// A copy of a running container under a new name, to try things on:
    /// on a host port and/or a domain, with its data copied or empty.
    ServiceClone {
        service: String,
        name: String,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        container_port: Option<u16>,
        #[serde(default)]
        domain: Option<String>,
        #[serde(default)]
        copy_data: bool,
    },
    /// What's using the disk under a folder (the root filesystem when left
    /// out). Read-only.
    DiskUsage {
        #[serde(default)]
        path: Option<String>,
    },
    /// A project's private WireGuard network on this machine: bring it up
    /// as exactly the given state (peers and exposed ports replaced
    /// wholesale), or take it down.
    Network(Box<NetworkSpec>),
    /// A Cloudflare Tunnel on this machine: up runs cloudflared with the
    /// tunnel's token (kept root-only, never on a command line) and serves
    /// the machine's app domains over plain HTTP for the tunnel to carry;
    /// down takes it away and puts HTTPS back.
    Tunnel {
        action: TunnelAction,
        /// The tunnel token from Cloudflare. Needed for up.
        #[serde(default)]
        token: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TunnelAction {
    Up,
    Down,
}

/// One project network as this machine should have it. "up" is declarative
/// and idempotent; "down" only needs `network`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSpec {
    /// The project's network id, `[a-z0-9]{1,12}`; the interface is
    /// `sos{network}`.
    pub network: String,
    pub action: NetworkAction,
    /// This machine's address on the network with its prefix, like
    /// `10.88.3.2/24`. Needed for up.
    #[serde(default)]
    pub address: Option<String>,
    /// The UDP port the interface listens on. Needed for up.
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Every peer the interface should have; any others are removed.
    #[serde(default)]
    pub peers: Vec<NetworkPeer>,
    /// Every port to offer on this machine's network address; any others
    /// are closed.
    #[serde(default)]
    pub expose: Vec<NetworkExpose>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAction {
    Up,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkPeer {
    /// The peer's WireGuard public key, base64.
    pub public_key: String,
    /// The peer's address on the network, like `10.88.3.3/32`.
    pub address: String,
    /// Where to reach it, `host:port`; left out for a peer that can only
    /// dial in.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// A port offered on this machine's network address, forwarded to a
/// service listening on loopback or the Docker bridge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkExpose {
    pub port: u16,
    /// `127.0.0.1:5432`, say.
    pub target: String,
}

/// A package at a version, as the package manager writes it: Debian
/// versions as dpkg has them (`1:2.3-4ubuntu1`), RPM ones as
/// `[epoch:]version-release` (`1:3.0.7-28.el9`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PackageVersion {
    pub name: String,
    pub version: String,
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
    /// Let the internet reach `PORT/PROTO`, removing what blocks it.
    Open,
    /// Stop the internet reaching `PORT/PROTO`, removing what lets it in.
    /// Refused for SSH and for ports Docker publishes.
    Close,
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
        #[serde(default)]
        mode: Option<PanelMode>,
        #[serde(flatten)]
        settings: MachineSettings,
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
    fn package_version_jobs_have_their_own_types() {
        let raw = serde_json::json!({
            "type": "package_install_versions",
            "packages": [{"name": "openssl", "version": "1:3.0.7-28.el9"}],
            "allow_downgrade": true,
        });
        assert_eq!(
            serde_json::from_value::<Job>(raw).unwrap(),
            Job::PackageInstallVersions {
                packages: vec![PackageVersion {
                    name: "openssl".into(),
                    version: "1:3.0.7-28.el9".into(),
                }],
                allow_downgrade: true,
            }
        );

        let raw = serde_json::json!({"type": "package_add", "packages": ["git", "unzip"]});
        assert_eq!(
            serde_json::from_value::<Job>(raw).unwrap(),
            Job::PackageAdd {
                packages: vec!["git".into(), "unzip".into()],
            }
        );

        let raw = serde_json::json!({"type": "restart_stale", "units": ["nginx.service"]});
        assert_eq!(
            serde_json::from_value::<Job>(raw).unwrap(),
            Job::RestartStale {
                units: vec!["nginx.service".into()],
                systemd: false,
            }
        );

        let raw = serde_json::json!({"type": "package_hold", "packages": ["nginx"], "hold": true});
        assert_eq!(
            serde_json::from_value::<Job>(raw).unwrap(),
            Job::PackageHold {
                packages: vec!["nginx".into()],
                hold: true,
            }
        );
    }

    #[test]
    fn network_jobs_read_the_panel_s_json() {
        let raw = serde_json::json!({
            "type": "network",
            "network": "p7k2q9",
            "action": "up",
            "address": "10.88.3.2/24",
            "listen_port": 51831,
            "peers": [
                {"public_key": "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=", "address": "10.88.3.3/32", "endpoint": "203.0.113.5:51831"},
                {"public_key": "d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGU=", "address": "10.88.3.4/32"}
            ],
            "expose": [{"port": 5432, "target": "127.0.0.1:5432"}]
        });
        let job: Job = serde_json::from_value(raw.clone()).unwrap();
        let Job::Network(spec) = &job else {
            panic!("not a network job: {job:?}");
        };
        assert_eq!(spec.action, NetworkAction::Up);
        assert_eq!(spec.address.as_deref(), Some("10.88.3.2/24"));
        assert_eq!(spec.listen_port, Some(51831));
        assert_eq!(spec.peers[1].endpoint, None);
        assert_eq!(spec.expose[0].target, "127.0.0.1:5432");

        let mut back = serde_json::to_value(&job).unwrap();
        back["peers"][1].as_object_mut().unwrap().remove("endpoint");
        assert_eq!(back, raw);

        let down: Job = serde_json::from_value(
            serde_json::json!({"type": "network", "network": "p7k2q9", "action": "down"}),
        )
        .unwrap();
        assert_eq!(
            down,
            Job::Network(Box::new(NetworkSpec {
                network: "p7k2q9".into(),
                action: NetworkAction::Down,
                address: None,
                listen_port: None,
                peers: vec![],
                expose: vec![],
            }))
        );
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
    fn reconfigure_reads_what_older_panels_send() {
        let raw = r#"{"type":"reconfigure","updates_channel":null,"pinned_version":null,"mode":"managed","log_ip_masking":"hash"}"#;
        let Control::Reconfigure { mode, settings } = serde_json::from_str(raw).unwrap() else {
            panic!("not a reconfigure");
        };

        assert_eq!(mode, Some(PanelMode::Managed));
        assert_eq!(settings.updates_channel, None);
        assert_eq!(settings.log_ip_masking.as_deref(), Some("hash"));
        assert_eq!(settings.discovery, None);
    }

    #[test]
    fn reconfigure_tells_a_cleared_pin_from_a_missing_one() {
        let cleared: Control =
            serde_json::from_str(r#"{"type":"reconfigure","pinned_version":null}"#).unwrap();
        let missing: Control = serde_json::from_str(r#"{"type":"reconfigure"}"#).unwrap();
        let set: Control =
            serde_json::from_str(r#"{"type":"reconfigure","pinned_version":"0.1.2","discovery":false,"logs":false,"updates_automatic":false}"#)
                .unwrap();

        let pin = |c: Control| match c {
            Control::Reconfigure { settings, .. } => settings,
            _ => panic!("not a reconfigure"),
        };
        assert_eq!(pin(cleared).pinned_version, Some(None));
        assert_eq!(pin(missing).pinned_version, None);
        let set = pin(set);
        assert_eq!(set.pinned_version, Some(Some("0.1.2".into())));
        assert_eq!(
            (set.discovery, set.logs, set.updates_automatic),
            (Some(false), Some(false), Some(false))
        );
    }

    #[test]
    fn hello_always_says_whether_it_is_pinned() {
        let raw = r#"{"machine_id":"m","daemon_version":"v","daemon_commit":"c","channel":"stable","supported_majors":[1],"facts":{"hostname":"h","os":"linux","os_version":"","kernel":"","arch":"x86_64","libc":"","cpu_model":"","cpu_cores":1,"memory_bytes":0,"disks":[],"interfaces":[],"timezone":"UTC","boot_ts":0}}"#;
        let mut hello: Hello = serde_json::from_str(raw).unwrap();
        // An older daemon leaves it out.
        assert_eq!(hello.pinned_version, None);

        hello.pinned_version = Some(None);
        let json = serde_json::to_value(&hello).unwrap();
        assert!(json.get("pinned_version").unwrap().is_null());

        hello.pinned_version = Some(Some("v0.1.1-pre.24".into()));
        let back: Hello = serde_json::from_value(serde_json::to_value(&hello).unwrap()).unwrap();
        assert_eq!(back.pinned_version, Some(Some("v0.1.1-pre.24".into())));
    }

    #[test]
    fn reconfigure_round_trips() {
        let control = Control::Reconfigure {
            mode: None,
            settings: MachineSettings {
                logs: Some(false),
                error_reports: Some(false),
                pinned_version: Some(None),
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&control).unwrap();

        assert_eq!(serde_json::from_str::<Control>(&json).unwrap(), control);
        assert!(json.contains(r#""error_reports":false"#), "{json}");

        // Left out when not set, so older daemons see nothing new.
        let quiet = serde_json::to_string(&MachineSettings::default()).unwrap();
        assert!(!quiet.contains("error_reports"), "{quiet}");
    }

    #[test]
    fn service_exec_settings_round_trip_and_are_optional() {
        // An older panel sends no settings.
        let old: Job = serde_json::from_value(serde_json::json!({
            "type": "service_exec",
            "service": "docker:abc123",
            "command": "psql -c 'select 1'",
        }))
        .unwrap();
        assert_eq!(
            old,
            Job::ServiceExec {
                service: "docker:abc123".into(),
                command: "psql -c 'select 1'".into(),
                timeout_secs: None,
                env: BTreeMap::new(),
            }
        );
        // And none are sent back out, so an older daemon reads it too.
        let json = serde_json::to_value(&old).unwrap();
        assert!(json.get("env").is_none(), "{json}");

        let job = Job::ServiceExec {
            service: "docker:abc123".into(),
            command: "pg_dump".into(),
            timeout_secs: Some(3600),
            env: BTreeMap::from([
                ("SOURCE_HOST".to_string(), "10.64.1.3".to_string()),
                ("SOURCE_PASSWORD".to_string(), "p@ss \"w0rd\"".to_string()),
            ]),
        };
        let json = serde_json::to_value(&job).unwrap();
        assert_eq!(json["type"], "service_exec");
        assert_eq!(json["env"]["SOURCE_HOST"], "10.64.1.3");
        assert_eq!(serde_json::from_value::<Job>(json).unwrap(), job);

        // The panel sends an empty object as {} when there are none.
        let empty: Job = serde_json::from_value(serde_json::json!({
            "type": "service_exec", "service": "x", "command": "true", "env": {},
        }))
        .unwrap();
        assert!(matches!(empty, Job::ServiceExec { env, .. } if env.is_empty()));
    }

    #[test]
    fn terminal_states_are_terminal() {
        assert!(JobState::Failed.is_terminal());
        assert!(!JobState::Running.is_terminal());
    }
}
