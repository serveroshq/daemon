//! After updates: which running programs still use files the update replaced,
//! and whether anything really needs a reboot.
//!
//! An update writes new files, but a program that was already running keeps
//! the old ones open until it restarts. Linux shows them in
//! `/proc/<pid>/maps` (and `/proc/<pid>/exe`) marked "(deleted)". Restarting
//! the services those programs belong to picks the update up, so most updates
//! (openssl, glibc, nginx, ...) never need a reboot. Only a new kernel and
//! microcode do. A few services can't be restarted safely (dbus, logind, the
//! console login); they pick the update up whenever the machine next boots,
//! which isn't a reason to reboot now.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_jobs::{capture_child, Captured, Failure, JobContext};
use serde::Serialize;

use super::packages::rpmvercmp;

/// Where a mapped file has to live to count: what packages install. A
/// deleted file elsewhere (/tmp, /dev/shm, memfd, a database's own files) is
/// how that program works, not an update.
const PACKAGE_PATHS: &[&str] = &["/usr/", "/lib/", "/lib64/", "/lib32/", "/bin/", "/sbin/"];

/// Services that can't be restarted without breaking the machine or the
/// people on it. They pick their update up at the next boot, whenever that is.
const NOT_RESTARTABLE: &[&str] = &[
    "dbus.service",
    "dbus-broker.service",
    "systemd-logind.service",
    "display-manager.service",
    "gdm.service",
    "sddm.service",
    "lightdm.service",
];

/// Template units in the same position: one per terminal or signed-in user.
const NOT_RESTARTABLE_TEMPLATES: &[&str] = &["getty@", "serial-getty@", "user@", "autovt@"];

/// Restarting these stops everything they run (every container), so the
/// panel asks for them by name.
const DISRUPTIVE: &[&str] = &[
    "docker.service",
    "containerd.service",
    "podman.service",
    "libvirtd.service",
    "kubelet.service",
    "k3s.service",
    "k3s-agent.service",
];

/// The daemon and gateway restart with their own updates; restarting
/// ourselves would end the job that's doing it.
const OURS: &[&str] = &["serverosd.service", "serveros-gateway.service"];

/// Packages that only take effect at boot (Debian and Ubuntu list what
/// asked for a reboot in /run/reboot-required.pkgs).
const BOOT_PACKAGES: &[&str] = &[
    "intel-microcode",
    "amd64-microcode",
    "microcode_ctl",
    "linux-firmware",
];

/// Units restarted per job at most; a machine with more is unusual.
const MAX_UNITS: usize = 100;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Restarts {
    /// Services running files an update replaced, restartable to pick the
    /// update up.
    pub services: Vec<StaleService>,
    /// systemd itself (PID 1) runs old files: `systemctl daemon-reexec`
    /// reloads it in place, no reboot.
    pub systemd: bool,
    /// What only a reboot applies: a newer kernel, microcode. Empty: no
    /// reboot needed.
    pub reboot: Vec<RebootReason>,
    /// Stale services that can't be restarted safely; they catch up at the
    /// next boot. Not a reason to reboot on their own.
    pub later: Vec<String>,
    /// The kernel running now, and the newest one installed if it differs.
    pub kernel: Option<String>,
    pub newest_kernel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaleService {
    pub unit: String,
    /// How many of its processes use replaced files.
    pub processes: usize,
    /// A few of those files, for the person deciding.
    pub files: Vec<String>,
    /// Restarting it stops what it runs (every container, for Docker).
    pub disruptive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RebootReason {
    /// kernel or microcode.
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct RestartReport {
    pub restarted: Vec<RestartOutcome>,
    /// The machine afterwards.
    pub restarts: Restarts,
}

#[derive(Debug, Serialize)]
pub struct RestartOutcome {
    pub unit: String,
    pub ok: bool,
    /// Not stale any more, so left alone.
    pub skipped: bool,
    pub message: Option<String>,
}

/// What a scan of /proc found for one process.
#[derive(Debug, Default)]
struct Process {
    owner: Owner,
    files: BTreeSet<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum Owner {
    Systemd,
    Unit(String),
    /// A container, a user's session or a process outside any service.
    #[default]
    Other,
}

/// Looks at every process and the installed kernels. Never fails: what it
/// can't read it leaves out.
pub fn scan() -> Restarts {
    scan_at(Path::new("/proc"), Path::new("/"))
}

fn scan_at(proc: &Path, root: &Path) -> Restarts {
    let mut units: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
    let mut systemd = false;

    for pid in pids(proc) {
        let dir = proc.join(pid.to_string());
        let Some(process) = read_process(&dir, pid) else {
            continue;
        };
        if process.files.is_empty() {
            continue;
        }
        match process.owner {
            Owner::Systemd => systemd = true,
            Owner::Unit(unit) => {
                let entry = units.entry(unit).or_default();
                entry.0 += 1;
                entry.1.extend(process.files);
            }
            Owner::Other => {}
        }
    }

    let mut out = Restarts {
        systemd,
        ..Restarts::default()
    };
    for (unit, (processes, files)) in units {
        if OURS.contains(&unit.as_str()) {
            continue;
        }
        if !restartable(&unit) {
            out.later.push(unit);
            continue;
        }
        out.services.push(StaleService {
            disruptive: DISRUPTIVE.contains(&unit.as_str()),
            unit,
            processes,
            files: files.into_iter().take(5).collect(),
        });
    }

    let (running, newest) = kernels(proc, root);
    if let (Some(running), Some(newest)) = (&running, &newest) {
        out.reboot.push(RebootReason {
            kind: "kernel".into(),
            detail: format!("{newest} is installed, {running} is running"),
        });
    }
    out.kernel = running;
    out.newest_kernel = newest;

    for package in boot_packages(root) {
        out.reboot.push(RebootReason {
            kind: "microcode".into(),
            detail: package,
        });
    }

    out
}

fn pids(proc: &Path) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(proc) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids
}

fn read_process(dir: &Path, pid: u32) -> Option<Process> {
    // Kernel threads have no maps; a process that ended mid-scan has none either.
    let maps = std::fs::read_to_string(dir.join("maps")).ok()?;
    let mut files: BTreeSet<String> = maps.lines().filter_map(deleted_package_file).collect();
    if let Ok(exe) = std::fs::read_link(dir.join("exe")) {
        if let Some(file) = exe.to_str().and_then(deleted_package_file_path) {
            files.insert(file);
        }
    }

    // PID 1 is systemd on a normal machine; in a container it can be
    // anything, and daemon-reexec would mean nothing there.
    let systemd =
        pid == 1 && std::fs::read_to_string(dir.join("comm")).is_ok_and(|c| c.trim() == "systemd");
    let owner = if systemd {
        Owner::Systemd
    } else {
        std::fs::read_to_string(dir.join("cgroup"))
            .map(|c| owner_from_cgroup(&c))
            .unwrap_or_default()
    };

    Some(Process { owner, files })
}

/// The file in one line of /proc/<pid>/maps, if it's a package's file that
/// has been replaced since the process mapped it.
fn deleted_package_file(line: &str) -> Option<String> {
    // address perms offset dev inode path
    let path = line.splitn(6, char::is_whitespace).nth(5)?.trim_start();
    deleted_package_file_path(path)
}

fn deleted_package_file_path(path: &str) -> Option<String> {
    let path = path.strip_suffix(" (deleted)")?;
    if !PACKAGE_PATHS.iter().any(|p| path.starts_with(p)) {
        return None;
    }
    // dpkg and rpm write the new file next to the old one first.
    let path = path.split(".dpkg-new").next().unwrap_or(path);
    let path = path.split(";").next().unwrap_or(path);
    Some(path.to_string())
}

/// Which service a process belongs to, from /proc/<pid>/cgroup. Containers
/// update with their images, not the machine's packages, so they're Other.
fn owner_from_cgroup(cgroup: &str) -> Owner {
    // cgroup v2 has one line "0::/path"; v1 has the systemd hierarchy as
    // "1:name=systemd:/path".
    let path = cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .or_else(|| {
            cgroup
                .lines()
                .find_map(|l| l.split_once(":name=systemd:").map(|(_, p)| p))
        });
    let Some(path) = path else {
        return Owner::Other;
    };

    // A service sits under system.slice, maybe in a slice of its own
    // (system-postgresql.slice/postgresql@16-main.service). A container is
    // a scope there, or nested under its runtime's service.
    let Some(rest) = path.trim().strip_prefix("/system.slice/") else {
        return Owner::Other;
    };
    let mut parts = rest.split('/');
    let Some(unit) = parts.find(|p| !p.ends_with(".slice")) else {
        return Owner::Other;
    };
    if !unit.ends_with(".service") {
        return Owner::Other;
    }
    const CONTAINERS: &[&str] = &["docker", "containerd", "libpod", "lxc", "kubepods", "crio"];
    if parts.any(|p| CONTAINERS.iter().any(|c| p.contains(c))) {
        return Owner::Other;
    }
    Owner::Unit(unit.to_string())
}

fn restartable(unit: &str) -> bool {
    !NOT_RESTARTABLE.contains(&unit)
        && !NOT_RESTARTABLE_TEMPLATES
            .iter()
            .any(|t| unit.starts_with(t))
}

/// The running kernel, and the newest installed one when that's newer. A
/// running kernel that isn't installed here (a container, WSL, a custom
/// build) says nothing about reboots, so both are left out.
fn kernels(proc: &Path, root: &Path) -> (Option<String>, Option<String>) {
    let Some(running) = std::fs::read_to_string(proc.join("sys/kernel/osrelease"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return (None, None);
    };

    let installed = installed_kernels(root);
    if !installed.contains(&running) {
        return (Some(running), None);
    }
    let newest = installed
        .into_iter()
        .max_by(|a, b| rpmvercmp(a, b))
        .filter(|n| rpmvercmp(n, &running).is_gt());

    (Some(running), newest)
}

/// Kernels with an image in /boot (vmlinuz-<release>) or, on newer Fedora
/// and RHEL, in /lib/modules/<release>/vmlinuz.
fn installed_kernels(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(root.join("boot")) {
        for entry in entries.flatten() {
            if let Some(release) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("vmlinuz-"))
                .filter(|r| !r.contains("rescue"))
            {
                out.insert(release.to_string());
            }
        }
    }
    let modules: PathBuf = root.join("lib/modules");
    if let Ok(entries) = std::fs::read_dir(&modules) {
        for entry in entries.flatten() {
            if entry.path().join("vmlinuz").exists() {
                if let Some(release) = entry.file_name().to_str() {
                    out.insert(release.to_string());
                }
            }
        }
    }
    out
}

/// Microcode and firmware updates waiting for a boot, from Debian's and
/// Ubuntu's list of what asked for one.
fn boot_packages(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = ["run/reboot-required.pkgs", "var/run/reboot-required.pkgs"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(root.join(p)).ok())
        .flat_map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| BOOT_PACKAGES.contains(l))
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Restart the services asked for that still run replaced files (and
/// re-execute systemd when asked and needed), one at a time, then look
/// again. A unit that isn't stale any more is skipped, so this can't be used
/// to restart anything else.
pub async fn restart_stale(
    ctx: &JobContext,
    units: &[String],
    systemd: bool,
) -> Result<RestartReport, Failure> {
    if units.len() > MAX_UNITS {
        return Err(Failure::new(
            "invalid",
            format!("at most {MAX_UNITS} services per restart"),
        ));
    }
    if let Some(bad) = units.iter().find(|u| !valid_unit(u)) {
        return Err(Failure::new(
            "invalid",
            format!("not a service name: {bad}"),
        ));
    }

    let mut cancel = ctx.cancel.clone();
    let progress = &ctx.progress;
    progress.phase("scanning", Some(10)).await;
    let before = scan();
    let stale: BTreeSet<&str> = before.services.iter().map(|s| s.unit.as_str()).collect();

    let mut restarted = Vec::new();

    if systemd && before.systemd {
        progress.line("systemctl daemon-reexec").await;
        let outcome = systemctl(&mut cancel, &["daemon-reexec"]).await;
        restarted.push(outcome_for("systemd", outcome));
    }

    let total = units.len().max(1);
    for (i, unit) in units.iter().enumerate() {
        if *cancel.borrow() {
            return Err(Failure::new("cancelled", "restart cancelled"));
        }
        if !stale.contains(unit.as_str()) {
            restarted.push(RestartOutcome {
                unit: unit.clone(),
                ok: true,
                skipped: true,
                message: Some("already running the updated files".into()),
            });
            continue;
        }
        let percent = 20 + (70 * i / total) as u8;
        progress.phase("restarting", Some(percent)).await;
        progress.line(format!("systemctl restart {unit}")).await;
        let outcome = systemctl(&mut cancel, &["restart", unit]).await;
        let mut result = outcome_for(unit, outcome);
        if result.ok {
            let active = systemctl(&mut cancel, &["is-active", unit]).await;
            if active.code() != Some(0) {
                result.ok = false;
                result.message = Some(format!(
                    "restarted but isn't running: {}",
                    active
                        .stdout()
                        .first()
                        .map(String::as_str)
                        .unwrap_or("unknown")
                ));
            }
        }
        progress
            .line(if result.ok {
                format!("{unit} restarted")
            } else {
                format!("{unit} failed: {}", result.message.as_deref().unwrap_or(""))
            })
            .await;
        restarted.push(result);
    }

    progress.phase("scanning", Some(95)).await;
    Ok(RestartReport {
        restarted,
        restarts: scan(),
    })
}

async fn systemctl(cancel: &mut tokio::sync::watch::Receiver<bool>, args: &[&str]) -> Captured {
    capture_child("systemctl", args, &[], Duration::from_secs(120), cancel, 20).await
}

fn outcome_for(unit: &str, captured: Captured) -> RestartOutcome {
    let (ok, message) = match &captured {
        Captured::Exited { code: 0, .. } => (true, None),
        Captured::Exited { code, stderr, .. } => (
            false,
            Some(
                stderr
                    .last()
                    .cloned()
                    .unwrap_or_else(|| format!("systemctl exited {code}")),
            ),
        ),
        Captured::TimedOut => (false, Some("took longer than 2 minutes".into())),
        Captured::Cancelled => (false, Some("cancelled".into())),
        Captured::Unstartable(e) => (false, Some(e.clone())),
    };
    RestartOutcome {
        unit: unit.to_string(),
        ok,
        skipped: false,
        message,
    }
}

/// A systemd service name: what the scan reports, nothing that reads as an
/// option or a path.
fn valid_unit(unit: &str) -> bool {
    unit.len() <= 256
        && unit.ends_with(".service")
        && !unit.starts_with('-')
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._-:\\".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_library_counts_and_other_deleted_files_do_not() {
        let line = "7f1c2a000000-7f1c2a200000 r-xp 00000000 fd:01 1234  /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)";
        assert_eq!(
            deleted_package_file(line).as_deref(),
            Some("/usr/lib/x86_64-linux-gnu/libssl.so.3")
        );

        for line in [
            "7f1c2a000000-7f1c2a200000 r-xp 00000000 fd:01 1234  /usr/lib/x86_64-linux-gnu/libssl.so.3",
            "7f1c2a000000-7f1c2a200000 rw-s 00000000 00:01 99  /dev/shm/pulse-shm-1 (deleted)",
            "7f1c2a000000-7f1c2a200000 rw-s 00000000 00:01 99  /memfd:doublemapper (deleted)",
            "7f1c2a000000-7f1c2a200000 rw-p 00000000 fd:01 99  /var/lib/postgresql/16/main/base/1 (deleted)",
            "7f1c2a000000-7f1c2a200000 rw-p 00000000 00:00 0 ",
            "7f1c2a000000-7f1c2a200000 rw-p 00000000 00:00 0  [heap]",
        ] {
            assert_eq!(deleted_package_file(line), None, "{line}");
        }
    }

    #[test]
    fn the_new_file_dpkg_or_rpm_left_maps_to_the_real_name() {
        assert_eq!(
            deleted_package_file_path("/usr/sbin/nginx.dpkg-new (deleted)").as_deref(),
            Some("/usr/sbin/nginx")
        );
        assert_eq!(
            deleted_package_file_path("/usr/lib64/libc.so.6;6531f2c1 (deleted)").as_deref(),
            Some("/usr/lib64/libc.so.6")
        );
    }

    #[test]
    fn processes_belong_to_their_service_and_containers_to_nobody() {
        assert_eq!(
            owner_from_cgroup("0::/system.slice/nginx.service\n"),
            Owner::Unit("nginx.service".into())
        );
        assert_eq!(
            owner_from_cgroup(
                "0::/system.slice/system-postgresql.slice/postgresql@16-main.service\n"
            ),
            Owner::Unit("postgresql@16-main.service".into())
        );
        assert_eq!(
            owner_from_cgroup(
                "12:pids:/system.slice/cron.service\n1:name=systemd:/system.slice/cron.service\n"
            ),
            Owner::Unit("cron.service".into())
        );
        for cgroup in [
            "0::/system.slice/docker-3f2a1b.scope\n",
            "0::/system.slice/containerd.service/kubepods-besteffort.slice\n",
            "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-1.scope\n",
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/machine.slice/libpod-abc.scope\n",
            "0::/init.scope\n",
            "",
        ] {
            assert_eq!(owner_from_cgroup(cgroup), Owner::Other, "{cgroup:?}");
        }
    }

    #[test]
    fn some_services_wait_for_a_reboot_instead() {
        assert!(restartable("nginx.service"));
        assert!(restartable("postgresql@16-main.service"));
        assert!(!restartable("dbus.service"));
        assert!(!restartable("getty@tty1.service"));
        assert!(!restartable("user@1000.service"));
    }

    #[test]
    fn only_service_names_can_be_asked_for() {
        assert!(valid_unit("nginx.service"));
        assert!(valid_unit("postgresql@16-main.service"));
        assert!(!valid_unit("nginx"));
        assert!(!valid_unit("--all.service"));
        assert!(!valid_unit("../../etc/x.service"));
        assert!(!valid_unit("a b.service"));
    }

    /// A fake /proc and / with nginx on an old libssl, a container on an old
    /// library, dbus on an old libc, systemd on old files and a newer kernel
    /// installed than the one running.
    #[test]
    fn a_scan_sorts_services_reboots_and_kernels() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path().join("proc");
        let root = dir.path().join("root");
        let old_ssl = "0-1 r-xp 0 fd:01 1 /usr/lib/libssl.so.3 (deleted)\n";
        let old_libc = "0-1 r-xp 0 fd:01 1 /usr/lib/libc.so.6 (deleted)\n";
        let fine = "0-1 r-xp 0 fd:01 1 /usr/lib/libc.so.6\n";

        let process = |pid: u32, maps: &str, cgroup: &str| {
            let p = proc.join(pid.to_string());
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("maps"), maps).unwrap();
            std::fs::write(p.join("cgroup"), cgroup).unwrap();
            std::fs::write(p.join("comm"), if pid == 1 { "systemd\n" } else { "x\n" }).unwrap();
        };
        process(1, old_libc, "0::/init.scope\n");
        process(100, old_ssl, "0::/system.slice/nginx.service\n");
        process(101, old_ssl, "0::/system.slice/nginx.service\n");
        process(200, fine, "0::/system.slice/cron.service\n");
        process(300, old_ssl, "0::/system.slice/docker-abc.scope\n");
        process(400, old_libc, "0::/system.slice/dbus.service\n");
        process(500, old_libc, "0::/system.slice/serverosd.service\n");
        process(600, old_libc, "0::/system.slice/docker.service\n");

        std::fs::create_dir_all(proc.join("sys/kernel")).unwrap();
        std::fs::write(proc.join("sys/kernel/osrelease"), "6.8.0-45-generic\n").unwrap();
        std::fs::create_dir_all(root.join("boot")).unwrap();
        for k in ["6.8.0-45-generic", "6.8.0-48-generic", "6.8.0-41-generic"] {
            std::fs::write(root.join("boot").join(format!("vmlinuz-{k}")), "").unwrap();
        }
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::write(
            root.join("run/reboot-required.pkgs"),
            "libc6\nintel-microcode\nlinux-image-6.8.0-48-generic\n",
        )
        .unwrap();

        let found = scan_at(&proc, &root);

        assert!(found.systemd);
        assert_eq!(
            found.services,
            vec![
                StaleService {
                    unit: "docker.service".into(),
                    processes: 1,
                    files: vec!["/usr/lib/libc.so.6".into()],
                    disruptive: true,
                },
                StaleService {
                    unit: "nginx.service".into(),
                    processes: 2,
                    files: vec!["/usr/lib/libssl.so.3".into()],
                    disruptive: false,
                },
            ]
        );
        assert_eq!(found.later, vec!["dbus.service".to_string()]);
        assert_eq!(found.kernel.as_deref(), Some("6.8.0-45-generic"));
        assert_eq!(found.newest_kernel.as_deref(), Some("6.8.0-48-generic"));
        assert_eq!(
            found.reboot,
            vec![
                RebootReason {
                    kind: "kernel".into(),
                    detail: "6.8.0-48-generic is installed, 6.8.0-45-generic is running".into(),
                },
                RebootReason {
                    kind: "microcode".into(),
                    detail: "intel-microcode".into(),
                },
            ]
        );
    }

    /// `cargo test -p serverosd print_this_machines_scan -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this machine's /proc; run by hand on a Linux machine"]
    fn print_this_machines_scan() {
        println!("{}", serde_json::to_string_pretty(&scan()).unwrap());
    }

    #[test]
    fn the_newest_kernel_running_or_one_not_installed_here_needs_no_reboot() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path().join("proc");
        let root = dir.path().join("root");
        std::fs::create_dir_all(proc.join("sys/kernel")).unwrap();
        std::fs::create_dir_all(root.join("lib/modules/5.14.0-427.el9.x86_64")).unwrap();
        std::fs::write(root.join("lib/modules/5.14.0-427.el9.x86_64/vmlinuz"), "").unwrap();
        std::fs::create_dir_all(root.join("lib/modules/5.14.0-362.el9.x86_64")).unwrap();
        std::fs::write(root.join("lib/modules/5.14.0-362.el9.x86_64/vmlinuz"), "").unwrap();

        std::fs::write(proc.join("sys/kernel/osrelease"), "5.14.0-427.el9.x86_64\n").unwrap();
        let found = scan_at(&proc, &root);
        assert_eq!(found.newest_kernel, None);
        assert!(found.reboot.is_empty());

        std::fs::write(
            proc.join("sys/kernel/osrelease"),
            "6.6.87-microsoft-standard\n",
        )
        .unwrap();
        let found = scan_at(&proc, &root);
        assert_eq!(found.kernel.as_deref(), Some("6.6.87-microsoft-standard"));
        assert!(found.reboot.is_empty());
    }
}
