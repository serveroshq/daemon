//! The security audit, run as the read-only `security_audit` job and by
//! `serverosd audit`: what's installed (language packages, for the panel to
//! match against known vulnerabilities), the websites the machine serves,
//! language runtimes, database settings that let anyone in, risky
//! containers, and what shouldn't be on a server at all (scripts that
//! download and run code, processes from /tmp, a setuid shell, a second
//! root account, a preloaded library).
//!
//! Nothing here changes the machine and nothing leaves it except through
//! the panel. Matching packages to vulnerabilities and looking at websites
//! from outside happen on the panel, which can reach the internet; the
//! daemon only talks to the panel. Commands found in cron and units are
//! redacted before they're reported, and file contents never are: for a
//! web root, only the names of files that shouldn't be there.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

pub mod containers;
pub mod databases;
pub mod host;
pub mod lockfiles;
pub mod packages;
pub mod runtimes;
pub mod sites;
mod util;

/// Bumped when the report's shape changes in a way the panel must know.
pub const REPORT_VERSION: u32 = 1;

/// Where to look. Everything is read under `root` so tests can point it at
/// a fixture; on a machine it's `/`.
#[derive(Debug, Clone)]
pub struct Options {
    pub root: PathBuf,
    pub proc: PathBuf,
    pub docker_socket: Option<PathBuf>,
    /// Where the daemon keeps deployed apps, searched for packages too.
    pub apps_dir: Option<PathBuf>,
    /// Run commands (`node -v`, `rpm -qa`, `sshd`): off in tests.
    pub commands: bool,
    /// How long the filesystem walks may take in all.
    pub budget: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            proc: PathBuf::from("/proc"),
            docker_socket: Some(PathBuf::from(daemon_inventory::docker::SOCKET)),
            apps_dir: Some(PathBuf::from("/var/lib/serveros/apps")),
            commands: true,
            budget: Duration::from_secs(90),
        }
    }
}

impl Options {
    /// A path on the machine, under the root being audited.
    pub fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// The path as the machine knows it, for the report.
    pub fn display(&self, path: &Path) -> String {
        match path.strip_prefix(&self.root) {
            Ok(rest) => format!("/{}", rest.display()),
            Err(_) => path.display().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    pub version: u32,
    pub scanned_at: i64,
    pub duration_ms: u64,
    /// A walk ran out of time or entries: some of the machine wasn't read.
    pub truncated: bool,
    pub packages: Vec<packages::Package>,
    pub projects: Vec<packages::Project>,
    pub runtimes: Vec<runtimes::Runtime>,
    pub sites: Vec<sites::Site>,
    pub apps: Vec<sites::AppSetting>,
    pub host: host::Host,
    pub databases: Vec<databases::DatabaseIssue>,
    pub containers: Vec<containers::ContainerRisk>,
    pub warnings: Vec<String>,
}

/// Shared by every walk: stop when the time is up.
#[derive(Debug, Clone)]
pub struct Deadline(Instant);

impl Deadline {
    pub fn after(budget: Duration) -> Self {
        Self(Instant::now() + budget)
    }

    pub fn passed(&self) -> bool {
        Instant::now() >= self.0
    }
}

pub async fn audit(options: Options) -> Report {
    let started = Instant::now();
    let scanned_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let blocking = options.clone();
    let mut report = tokio::task::spawn_blocking(move || audit_files(&blocking))
        .await
        .unwrap_or_else(|_| Report {
            warnings: vec!["the file checks stopped unexpectedly".into()],
            ..Report::default()
        });

    if let Some(socket) = &options.docker_socket {
        let socket = options
            .root
            .join(socket.strip_prefix("/").unwrap_or(socket));
        if socket.exists() {
            report.containers = containers::audit(&socket).await;
        }
    }

    report.version = REPORT_VERSION;
    report.scanned_at = scanned_at;
    report.duration_ms = started.elapsed().as_millis() as u64;

    report
}

/// Everything that reads files and runs commands, in one blocking pass.
pub fn audit_files(options: &Options) -> Report {
    let deadline = Deadline::after(options.budget);
    let mut report = Report::default();

    let found = packages::gather(options, &deadline);
    report.packages = found.packages;
    report.projects = found.projects;
    report.truncated |= found.truncated;

    report.sites = sites::gather(options);
    report.apps = sites::app_settings(options, &found.laravel);
    report.runtimes = runtimes::gather(options);
    report.host = host::gather(options, &deadline);
    report.databases = databases::gather(options);

    if deadline.passed() {
        report.truncated = true;
        report
            .warnings
            .push("the audit ran out of time; some folders weren't read".into());
    }

    report
}
