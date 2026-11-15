use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use daemon_jobs::{capture_child, run_child, Captured, ChildOutcome, Failure, JobContext};
use daemon_protocol::PackageVersion;
use serde::Serialize;
use tokio::sync::watch;

use super::restarts::{self, Restarts};

/// How many lines of a listing (upgradable packages, holds) are read. The
/// live log keeps 40; a machine a year behind can have a few thousand.
const MAX_LISTED: usize = 5000;

const APT_ENV: &[(&str, &str)] = &[("DEBIAN_FRONTEND", "noninteractive")];

#[derive(Debug, Serialize)]
pub struct PackageReport {
    pub manager: String,
    /// The package manager's own lines, as before `packages` existed.
    pub upgradable: Vec<String>,
    pub security: Vec<String>,
    pub reboot_required: bool,
    pub applied: bool,
    /// Every package with an update, parsed.
    pub packages: Vec<PackageUpdate>,
    /// Packages held at their version (apt-mark hold, dnf/yum versionlock).
    pub held: Vec<String>,
    pub os: Option<OsRelease>,
    /// After an install, the version of each named package now installed,
    /// so the panel can check the target was reached. Empty for checks.
    pub installed: Vec<PackageVersion>,
    /// Which services still run files an update replaced, and what really
    /// needs a reboot. `reboot_required` stays the system's own answer
    /// (which says yes for a new libc or dbus) for panels that predate this.
    pub restarts: Restarts,
}

/// What `package_hold` leaves: every package held afterwards.
#[derive(Debug, Serialize)]
pub struct HoldReport {
    pub manager: String,
    pub held: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageUpdate {
    pub name: String,
    pub installed: Option<String>,
    pub candidate: String,
    pub security: bool,
    pub arch: Option<String>,
}

/// Which distribution and release this is, from /etc/os-release, so machines
/// whose repositories offer the same versions can be grouped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsRelease {
    pub id: String,
    pub version_id: Option<String>,
    pub pretty_name: Option<String>,
}

fn manager() -> Option<&'static str> {
    if Path::new("/usr/bin/apt-get").exists() {
        Some("apt")
    } else if Path::new("/usr/bin/dnf").exists() {
        Some("dnf")
    } else if Path::new("/usr/bin/yum").exists() {
        Some("yum")
    } else {
        None
    }
}

/// Runs a listing command; cancelling the job stops it and fails the job.
async fn list(
    cancel: &mut watch::Receiver<bool>,
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
    secs: u64,
) -> Result<Captured, Failure> {
    match capture_child(
        program,
        args,
        env,
        Duration::from_secs(secs),
        cancel,
        MAX_LISTED,
    )
    .await
    {
        Captured::Cancelled => Err(Failure::new("cancelled", "package check cancelled")),
        other => Ok(other),
    }
}

fn listing_failed(what: &str, captured: &Captured) -> Failure {
    let message = match captured {
        Captured::TimedOut => format!("{what} took too long"),
        Captured::Unstartable(e) => e.clone(),
        Captured::Exited { code, .. } => format!("{what} failed (exit {code})"),
        Captured::Cancelled => "package check cancelled".into(),
    };
    Failure::new("packages", message).with_output(captured.stderr().to_vec())
}

pub async fn package_updates(
    ctx: &JobContext,
    apply: bool,
    security_only: bool,
) -> Result<PackageReport, Failure> {
    let manager = manager().ok_or_else(|| {
        Failure::new(
            "packages",
            "no supported package manager (apt, dnf, yum) on this machine",
        )
    })?;
    let mut cancel = ctx.cancel.clone();
    let progress = &ctx.progress;

    let (upgradable, security, packages) = match manager {
        "apt" => {
            let _ = run_child(
                "apt-get",
                &["update", "-q"],
                None,
                APT_ENV,
                Duration::from_secs(300),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let listed = list(&mut cancel, "apt", &["list", "--upgradable"], APT_ENV, 120).await?;
            if listed.code() != Some(0) {
                return Err(listing_failed("apt list --upgradable", &listed));
            }
            let lines: Vec<String> = listed
                .stdout()
                .iter()
                .filter(|l| l.contains('/') && l.contains('['))
                .cloned()
                .collect();
            let security: Vec<String> = lines
                .iter()
                .filter(|l| l.contains("-security"))
                .cloned()
                .collect();
            let packages = lines.iter().filter_map(|l| parse_apt_line(l)).collect();
            (lines, security, packages)
        }
        _ => {
            // check-update exits 100 when there are updates, 0 when there
            // are none, and 1 when it couldn't tell.
            let listed = list(&mut cancel, manager, &["check-update", "-q"], &[], 300).await?;
            if !matches!(listed.code(), Some(0 | 100)) {
                return Err(listing_failed(&format!("{manager} check-update"), &listed));
            }
            let updates = parse_check_update(listed.stdout());

            let advisories = list(
                &mut cancel,
                manager,
                &["updateinfo", "list", "security", "-q"],
                &[],
                120,
            )
            .await?;
            let security_lines: Vec<String> = if advisories.code() == Some(0) {
                advisories
                    .stdout()
                    .iter()
                    .filter(|l| !l.trim().is_empty())
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            let secure = security_name_arches(&security_lines);

            let installed = if updates.is_empty() {
                HashMap::new()
            } else {
                let mut args = vec![
                    "-q".to_string(),
                    "--qf".to_string(),
                    RPM_QUERY_FORMAT.to_string(),
                ];
                args.extend(updates.iter().map(|u| format!("{}.{}", u.name, u.arch)));
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                // rpm exits non-zero when any name isn't installed (an update
                // that's new, say); the ones that are still get a line.
                let queried = list(&mut cancel, "rpm", &args, &[], 120).await?;
                parse_rpm_installed(queried.stdout())
            };

            let packages = updates
                .iter()
                .map(|u| {
                    let key = format!("{}.{}", u.name, u.arch);
                    PackageUpdate {
                        name: u.name.clone(),
                        installed: installed.get(&key).cloned(),
                        candidate: u.candidate.clone(),
                        security: secure.contains(&key),
                        arch: Some(u.arch.clone()),
                    }
                })
                .collect();
            let lines = updates.into_iter().map(|u| u.line).collect();

            (lines, security_lines, packages)
        }
    };

    let mut applied = false;

    if apply {
        progress.phase("apply", Some(50)).await;
        let outcome = match (manager, security_only) {
            ("apt", true) => {
                run_child(
                    "unattended-upgrade",
                    &["-v"],
                    None,
                    APT_ENV,
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
            ("apt", false) => {
                run_child(
                    "apt-get",
                    &[
                        "-y",
                        "-q",
                        "-o",
                        "Dpkg::Options::=--force-confold",
                        "upgrade",
                    ],
                    None,
                    APT_ENV,
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
            (m, true) => {
                run_child(
                    m,
                    &["-y", "-q", "upgrade", "--security"],
                    None,
                    &[],
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
            (m, false) => {
                run_child(
                    m,
                    &["-y", "-q", "upgrade"],
                    None,
                    &[],
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
        };

        match outcome {
            ChildOutcome::Exited { code: 0, .. } => applied = true,
            ChildOutcome::Cancelled { tail } => {
                return Err(Failure::new("cancelled", "package upgrade cancelled").with_output(tail))
            }
            other => {
                return Err(
                    Failure::new("apply", format!("{manager} upgrade did not complete"))
                        .with_output(other.tail().to_vec())
                        .with_next_step(
                            "Check the output; a held or broken package usually needs a person.",
                        ),
                )
            }
        }
    }

    Ok(PackageReport {
        manager: manager.into(),
        upgradable,
        security,
        reboot_required: reboot_required(manager, &mut cancel).await,
        applied,
        packages,
        held: held(manager, &mut cancel).await,
        os: os_release(),
        installed: Vec::new(),
        restarts: stale().await,
    })
}

/// The restart scan reads every process's maps, so off the async threads.
async fn stale() -> Restarts {
    tokio::task::spawn_blocking(restarts::scan)
        .await
        .unwrap_or_default()
}

const MAX_INSTALL_PACKAGES: usize = 500;

fn check_names(packages: &[String]) -> Result<(), Failure> {
    if packages.is_empty() || packages.len() > MAX_INSTALL_PACKAGES {
        return Err(Failure::new(
            "packages",
            format!("name between 1 and {MAX_INSTALL_PACKAGES} packages"),
        ));
    }
    if let Some(bad) = packages.iter().find(|p| !valid_package_name(p)) {
        return Err(Failure::new(
            "packages",
            format!("{bad:?} isn't a package name"),
        ));
    }
    Ok(())
}

/// A plain package name. It can't end in `-`: apt reads `nginx-` on an
/// install line as "remove nginx" (a trailing `+` only means install, and
/// real names like `g++` end in one).
fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && !name.ends_with('-')
        && name.len() <= 200
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+._:-~".contains(c))
}

pub async fn install_packages(
    ctx: &JobContext,
    packages: &[String],
) -> Result<PackageReport, Failure> {
    let manager = manager().ok_or_else(|| {
        Failure::new(
            "unsupported",
            "no supported package manager (apt, dnf, yum) on this machine",
        )
    })?;
    check_names(packages)?;

    let mut cancel = ctx.cancel.clone();
    let progress = &ctx.progress;
    progress.phase("apply", Some(30)).await;

    let names: Vec<&str> = packages.iter().map(String::as_str).collect();
    let outcome = if manager == "apt" {
        let mut args = vec![
            "install",
            "--only-upgrade",
            "-y",
            "-q",
            "-o",
            "Dpkg::Options::=--force-confold",
        ];
        args.extend(&names);
        run_child(
            "apt-get",
            &args,
            None,
            APT_ENV,
            ctx.timeout,
            &mut cancel,
            progress,
            None,
        )
        .await
    } else {
        let mut args = vec!["-y", "-q", "upgrade"];
        args.extend(&names);
        run_child(
            manager,
            &args,
            None,
            &[],
            ctx.timeout,
            &mut cancel,
            progress,
            None,
        )
        .await
    };

    match outcome {
        ChildOutcome::Exited { code: 0, .. } => {}
        ChildOutcome::Cancelled { tail } => {
            return Err(Failure::new("cancelled", "package upgrade cancelled").with_output(tail))
        }
        other => {
            return Err(
                Failure::new("apply", format!("{manager} upgrade did not complete"))
                    .with_output(other.tail().to_vec())
                    .with_next_step(
                        "Check the output; a held or broken package usually needs a person.",
                    ),
            )
        }
    }

    Ok(PackageReport {
        manager: manager.into(),
        upgradable: Vec::new(),
        security: Vec::new(),
        reboot_required: reboot_required(manager, &mut cancel).await,
        applied: true,
        packages: Vec::new(),
        held: held(manager, &mut cancel).await,
        os: os_release(),
        installed: installed_versions(manager, packages, &mut cancel).await,
        restarts: stale().await,
    })
}

/// Packages one `package_add` may install: a few tools, not a system.
const MAX_ADD_PACKAGES: usize = 20;

/// Install packages that aren't on the machine yet, from the repositories
/// it already has (it never adds one). apt refreshes its lists first, as a
/// fresh machine's are often stale. Already installed is fine: nothing
/// changes. Held packages stay held.
pub async fn add_packages(ctx: &JobContext, packages: &[String]) -> Result<PackageReport, Failure> {
    let manager = manager().ok_or_else(|| {
        Failure::new(
            "unsupported",
            "no supported package manager (apt, dnf, yum) on this machine",
        )
    })?;
    if packages.len() > MAX_ADD_PACKAGES {
        return Err(Failure::new(
            "packages",
            format!("name at most {MAX_ADD_PACKAGES} packages to add at once"),
        ));
    }
    check_names(packages)?;

    let mut cancel = ctx.cancel.clone();
    let progress = &ctx.progress;
    let names: Vec<&str> = packages.iter().map(String::as_str).collect();

    let outcome = if manager == "apt" {
        progress.phase("refresh", Some(15)).await;
        let _ = run_child(
            "apt-get",
            &["update", "-q", "-o", "DPkg::Lock::Timeout=120"],
            None,
            APT_ENV,
            Duration::from_secs(300),
            &mut cancel,
            progress,
            None,
        )
        .await;
        if *cancel.borrow() {
            return Err(Failure::new("cancelled", "package install cancelled"));
        }
        // What it would do, first: refuse if it would remove anything, or if
        // the names pull in far more than a few tools (an old apt reads an
        // unknown name with . or + in it as a pattern).
        let mut plan_args = vec!["install", "-s", "-q", "--no-install-recommends", "--"];
        plan_args.extend(&names);
        let plan = capture_child(
            "apt-get",
            &plan_args,
            APT_ENV,
            Duration::from_secs(120),
            &mut cancel,
            MAX_LISTED,
        )
        .await;
        if plan.code() != Some(0) {
            let output: Vec<String> = plan.stderr().iter().chain(plan.stdout()).cloned().collect();
            let skip = output.len().saturating_sub(20);
            return Err(Failure::new("apply", "apt can't install those")
                .with_output(output.into_iter().skip(skip).collect())
                .with_next_step(
                    "Check the names: they have to be packages this machine's repositories have.",
                ));
        }
        let removes = plan
            .stdout()
            .iter()
            .filter(|l| l.starts_with("Remv "))
            .count();
        let installs = plan
            .stdout()
            .iter()
            .filter(|l| l.starts_with("Inst "))
            .count();
        if removes > 0 {
            return Err(Failure::new(
                "apply",
                format!("installing those would remove {removes} packages, so nothing was changed"),
            )
            .with_output(
                plan.stdout()
                    .iter()
                    .filter(|l| l.starts_with("Remv "))
                    .take(20)
                    .cloned()
                    .collect(),
            )
            .with_next_step(
                "They conflict with what's installed: a person has to decide which to keep.",
            ));
        }
        if installs > MAX_ADD_PLAN {
            return Err(Failure::new(
                "apply",
                format!("those names would install {installs} packages, so nothing was changed"),
            )
            .with_next_step("Name the exact packages wanted."));
        }

        progress.phase("install", Some(40)).await;
        let mut args = vec![
            "install",
            "-y",
            "-q",
            "--no-install-recommends",
            // Never take something out to make room: it fails instead.
            "--no-remove",
            "-o",
            "DPkg::Lock::Timeout=120",
            "-o",
            "Dpkg::Options::=--force-confold",
            "--",
        ];
        args.extend(&names);
        run_child(
            "apt-get",
            &args,
            None,
            APT_ENV,
            ctx.timeout,
            &mut cancel,
            progress,
            None,
        )
        .await
    } else {
        progress.phase("install", Some(30)).await;
        // yum on EL7 skips names it can't find and still succeeds; dnf doesn't.
        let mut args = vec!["-y", "-q"];
        if manager == "yum" {
            args.push("--setopt=skip_missing_names_on_install=False");
        }
        args.extend(["install", "--"]);
        args.extend(&names);
        run_child(
            manager,
            &args,
            None,
            &[],
            ctx.timeout,
            &mut cancel,
            progress,
            None,
        )
        .await
    };

    match outcome {
        ChildOutcome::Exited { code: 0, .. } => {}
        ChildOutcome::Cancelled { tail } => {
            return Err(Failure::new("cancelled", "package install cancelled").with_output(tail))
        }
        other => {
            return Err(
                Failure::new("apply", format!("{manager} install did not complete"))
                    .with_output(other.tail().to_vec())
                    .with_next_step(
                        "Check the output: a name the machine's repositories don't have, or a broken package, needs a person.",
                    ),
            )
        }
    }

    // Every name asked for has to be there now, whatever the manager said.
    let installed = installed_versions(manager, packages, &mut cancel).await;
    let missing: Vec<&str> = packages
        .iter()
        .map(String::as_str)
        .filter(|p| {
            let bare = p.split(':').next().unwrap_or(p);
            !installed.iter().any(|v| v.name == *p || v.name == bare)
        })
        .collect();
    if !missing.is_empty() {
        return Err(Failure::new(
            "apply",
            format!(
                "{manager} finished but these aren't installed: {}",
                missing.join(", ")
            ),
        )
        .with_next_step(
            "Check the names: they have to be packages this machine's repositories have.",
        ));
    }

    Ok(PackageReport {
        manager: manager.into(),
        upgradable: Vec::new(),
        security: Vec::new(),
        reboot_required: reboot_required(manager, &mut cancel).await,
        applied: true,
        packages: Vec::new(),
        held: held(manager, &mut cancel).await,
        os: os_release(),
        installed,
        restarts: stale().await,
    })
}

/// Packages one package_add may bring in, dependencies and all.
const MAX_ADD_PLAN: usize = 150;

const MAX_VERSION_LEN: usize = 128;

/// A version as apt or dnf writes one: starts with a letter or digit (so it
/// can't pass for an option), then only what versions are made of.
fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && version.starts_with(|c: char| c.is_ascii_alphanumeric())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+~:_-".contains(c))
}

fn check_versions(packages: &[PackageVersion]) -> Result<(), Failure> {
    if packages.is_empty() || packages.len() > MAX_INSTALL_PACKAGES {
        return Err(Failure::new(
            "packages",
            format!("name between 1 and {MAX_INSTALL_PACKAGES} packages"),
        ));
    }
    for p in packages {
        if !valid_package_name(&p.name) {
            return Err(Failure::new(
                "packages",
                format!("{:?} isn't a package name", p.name),
            ));
        }
        if !valid_version(&p.version) {
            return Err(Failure::new(
                "packages",
                format!("{:?} isn't a version of {}", p.version, p.name),
            ));
        }
    }
    let mut seen = HashSet::new();
    if let Some(twice) = packages.iter().find(|p| !seen.insert(p.name.as_str())) {
        return Err(Failure::new(
            "packages",
            format!("{} is named more than once", twice.name),
        ));
    }
    Ok(())
}

fn apt_install_versions_args(packages: &[PackageVersion], allow_downgrade: bool) -> Vec<String> {
    let mut args: Vec<String> = [
        "install",
        "-y",
        "-q",
        "-o",
        "Dpkg::Options::=--force-confold",
    ]
    .map(String::from)
    .to_vec();
    if allow_downgrade {
        args.push("--allow-downgrades".into());
    }
    args.extend(packages.iter().map(|p| format!("{}={}", p.name, p.version)));
    args
}

/// `name-[epoch:]version-release`, the form dnf and yum take for one version.
fn rpm_spec(package: &PackageVersion) -> String {
    format!("{}-{}", package.name, package.version)
}

fn rpm_args(action: &str, packages: &[&PackageVersion]) -> Vec<String> {
    let mut args: Vec<String> = vec!["-y".into(), "-q".into(), action.into()];
    args.extend(packages.iter().map(|p| rpm_spec(p)));
    args
}

fn apt_mark_args(hold: bool, names: &[String]) -> Vec<String> {
    let mut args = vec![if hold { "hold" } else { "unhold" }.to_string()];
    args.extend(names.iter().cloned());
    args
}

fn versionlock_args(hold: bool, names: &[String]) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-q".into(),
        "versionlock".into(),
        if hold { "add" } else { "delete" }.into(),
    ];
    args.extend(names.iter().cloned());
    args
}

async fn run_args(
    ctx: &JobContext,
    cancel: &mut watch::Receiver<bool>,
    program: &str,
    args: &[String],
    env: &[(&str, &str)],
    timeout: Duration,
) -> ChildOutcome {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_child(
        program,
        &args,
        None,
        env,
        timeout,
        cancel,
        &ctx.progress,
        None,
    )
    .await
}

fn install_failed(manager: &str, outcome: ChildOutcome) -> Failure {
    match outcome {
        ChildOutcome::Cancelled { tail } => {
            Failure::new("cancelled", "package install cancelled").with_output(tail)
        }
        other => Failure::new("apply", format!("{manager} install did not complete"))
            .with_output(other.tail().to_vec())
            .with_next_step(
                "Check the output; a version the repositories no longer offer, or a held or broken package, usually needs a person.",
            ),
    }
}

/// A held package: its name, and the entry that holds it, which is what
/// letting it go takes (yum's `versionlock delete` matches whole entries like
/// `0:nginx-1.20.1-1.el7.*`, not names). For apt they're the same.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Hold {
    name: String,
    entry: String,
}

fn hold_names(holds: &[Hold]) -> Vec<String> {
    holds
        .iter()
        .map(|h| h.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn hold_entries(holds: &[Hold]) -> Vec<String> {
    holds.iter().map(|h| h.entry.clone()).collect()
}

/// The holds on any of these packages (`libc6` and `libc6:amd64` are the
/// same package).
fn held_among(held: &[Hold], names: &[&str]) -> Vec<Hold> {
    let base = |n: &str| n.split(':').next().unwrap_or(n).to_string();
    held.iter()
        .filter(|h| {
            names
                .iter()
                .any(|n| *n == h.name || base(n) == base(&h.name))
        })
        .cloned()
        .collect()
}

/// Installs exactly the versions asked for. Packages held now are let go for
/// the install and held again afterwards, whether it worked or not.
pub async fn install_versions(
    ctx: &JobContext,
    packages: &[PackageVersion],
    allow_downgrade: bool,
) -> Result<PackageReport, Failure> {
    let manager = manager().ok_or_else(|| {
        Failure::new(
            "unsupported",
            "no supported package manager (apt, dnf, yum) on this machine",
        )
    })?;
    check_versions(packages)?;

    let mut cancel = ctx.cancel.clone();
    let names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let hold_secs = Duration::from_secs(120);

    // dnf and yum install an older version when asked to by name, so what
    // allow_downgrade forbids has to be worked out first.
    let (upgrades, downgrades): (Vec<&PackageVersion>, Vec<&PackageVersion>) = if manager == "apt" {
        (packages.iter().collect(), Vec::new())
    } else {
        let installed = rpm_installed_by_name(&names, &mut cancel).await?;
        packages.iter().partition(|p| {
            installed.get(&p.name).is_none_or(|versions| {
                versions
                    .iter()
                    .any(|v| compare_evr(&p.version, v) != Ordering::Less)
            })
        })
    };
    if !downgrades.is_empty() && !allow_downgrade {
        let listed: Vec<String> = downgrades.iter().map(|p| rpm_spec(p)).collect();
        return Err(Failure::new(
            "packages",
            format!(
                "{} would be a downgrade; allow downgrades to install it",
                listed.join(", ")
            ),
        ));
    }

    let relock = match holds(manager, &mut cancel).await {
        Some(held) => held_among(&held, &name_refs),
        None => Vec::new(),
    };

    ctx.progress.phase("apply", Some(30)).await;

    let relock_names = hold_names(&relock);
    let mut result = Ok(());

    if !relock.is_empty() {
        let (program, args) = if manager == "apt" {
            ("apt-mark", apt_mark_args(false, &hold_entries(&relock)))
        } else {
            (manager, versionlock_args(false, &hold_entries(&relock)))
        };
        let outcome = run_args(ctx, &mut cancel, program, &args, APT_ENV, hold_secs).await;
        if !outcome.success() {
            // Some may have been let go; they're held again below.
            result = Err(Failure::new(
                "hold",
                format!(
                    "couldn't let go of {} for the install",
                    relock_names.join(", ")
                ),
            )
            .with_output(outcome.tail().to_vec()));
        }
    }

    if result.is_err() {
        // Not installing what's still held.
    } else if manager == "apt" {
        let args = apt_install_versions_args(packages, allow_downgrade);
        let outcome = run_args(ctx, &mut cancel, "apt-get", &args, APT_ENV, ctx.timeout).await;
        if !outcome.success() {
            result = Err(install_failed(manager, outcome));
        }
    } else {
        for (action, list) in [("install", &upgrades), ("downgrade", &downgrades)] {
            if list.is_empty() || result.is_err() {
                continue;
            }
            let args = rpm_args(action, list);
            let outcome = run_args(ctx, &mut cancel, manager, &args, &[], ctx.timeout).await;
            if !outcome.success() {
                result = Err(install_failed(manager, outcome));
            }
        }
    }

    if !relock.is_empty() {
        let (program, args) = if manager == "apt" {
            ("apt-mark", apt_mark_args(true, &relock_names))
        } else {
            (manager, versionlock_args(true, &relock_names))
        };
        // Held again even when the job was cancelled: a hold mustn't be lost.
        let (_tx, mut uncancellable) = watch::channel(false);
        let outcome = run_args(ctx, &mut uncancellable, program, &args, APT_ENV, hold_secs).await;
        if !outcome.success() && result.is_ok() {
            result = Err(Failure::new(
                "hold",
                format!(
                    "installed, but couldn't hold {} again",
                    relock_names.join(", ")
                ),
            )
            .with_output(outcome.tail().to_vec())
            .with_next_step("Hold them again from the panel."));
        }
    }
    result?;

    Ok(PackageReport {
        manager: manager.into(),
        upgradable: Vec::new(),
        security: Vec::new(),
        reboot_required: reboot_required(manager, &mut cancel).await,
        applied: true,
        packages: Vec::new(),
        held: held(manager, &mut cancel).await,
        os: os_release(),
        installed: installed_matching(manager, packages, &mut cancel).await,
        restarts: stale().await,
    })
}

/// Holds packages at the version installed, or lets them go.
pub async fn hold_packages(
    ctx: &JobContext,
    packages: &[String],
    hold: bool,
) -> Result<HoldReport, Failure> {
    let manager = manager().ok_or_else(|| {
        Failure::new(
            "unsupported",
            "no supported package manager (apt, dnf, yum) on this machine",
        )
    })?;
    check_names(packages)?;

    let mut cancel = ctx.cancel.clone();
    ctx.progress.phase("apply", Some(30)).await;

    let (program, args) = if manager == "apt" {
        ("apt-mark", apt_mark_args(hold, packages))
    } else {
        let Some(current) = holds(manager, &mut cancel).await else {
            return Err(Failure::new(
                "unsupported",
                "Holding packages needs the versionlock plugin: install python3-dnf-plugin-versionlock",
            )
            .with_next_step(format!(
                "{manager} install python3-dnf-plugin-versionlock (yum-plugin-versionlock on yum)"
            )));
        };
        let args: Vec<String> = if hold {
            packages.to_vec()
        } else {
            let refs: Vec<&str> = packages.iter().map(String::as_str).collect();
            hold_entries(&held_among(&current, &refs))
        };
        if args.is_empty() {
            return Ok(HoldReport {
                manager: manager.into(),
                held: hold_names(&current),
            });
        }
        (manager, versionlock_args(hold, &args))
    };

    let outcome = run_args(
        ctx,
        &mut cancel,
        program,
        &args,
        APT_ENV,
        Duration::from_secs(120),
    )
    .await;
    if !outcome.success() {
        let verb = if hold { "hold" } else { "unhold" };
        return Err(Failure::new(
            "hold",
            format!("{program} couldn't {verb} {}", packages.join(", ")),
        )
        .with_output(outcome.tail().to_vec()));
    }

    Ok(HoldReport {
        manager: manager.into(),
        held: held(manager, &mut cancel).await,
    })
}

const RPM_NAME_QUERY_FORMAT: &str = "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\\n";
const DPKG_QUERY_FORMAT: &str =
    "--showformat=${db:Status-Abbrev}\\t${binary:Package}\\t${Package}\\t${Version}\\n";

/// Every installed version of each name (more than one for kernels).
async fn rpm_installed_by_name(
    names: &[String],
    cancel: &mut watch::Receiver<bool>,
) -> Result<HashMap<String, Vec<String>>, Failure> {
    let mut args = vec!["-q", "--qf", RPM_NAME_QUERY_FORMAT];
    args.extend(names.iter().map(String::as_str));
    let queried = list(cancel, "rpm", &args, &[], 120).await?;
    Ok(parse_rpm_by_name(queried.stdout()))
}

fn parse_rpm_by_name(lines: &[String]) -> HashMap<String, Vec<String>> {
    let mut installed: HashMap<String, Vec<String>> = HashMap::new();
    for line in lines {
        let mut words = line.split_whitespace();
        let (Some(name), Some(version), None) = (words.next(), words.next(), words.next()) else {
            continue;
        };
        if version.contains(':') {
            installed
                .entry(name.to_string())
                .or_default()
                .push(normalise_epoch(version));
        }
    }
    installed
}

/// `dpkg-query` lines of [`DPKG_QUERY_FORMAT`], installed packages only,
/// by both their `name:arch` and plain names.
fn parse_dpkg_installed(lines: &[String]) -> HashMap<String, String> {
    let mut installed = HashMap::new();
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        let [status, binary, name, version] = fields.as_slice() else {
            continue;
        };
        if status.chars().nth(1) != Some('i') || version.is_empty() {
            continue;
        }
        installed.insert(binary.to_string(), version.to_string());
        installed.insert(name.to_string(), version.to_string());
    }
    installed
}

/// The version of each name installed now (the newest, when there's more
/// than one), leaving out names that aren't installed.
async fn installed_versions(
    manager: &str,
    names: &[String],
    cancel: &mut watch::Receiver<bool>,
) -> Vec<PackageVersion> {
    let wanted: Vec<PackageVersion> = names
        .iter()
        .map(|n| PackageVersion {
            name: n.clone(),
            version: String::new(),
        })
        .collect();
    installed_matching(manager, &wanted, cancel).await
}

/// The version of each package installed now; where several are (kernels),
/// the one asked for if it's among them, else the newest.
async fn installed_matching(
    manager: &str,
    wanted: &[PackageVersion],
    cancel: &mut watch::Receiver<bool>,
) -> Vec<PackageVersion> {
    let names: Vec<String> = wanted.iter().map(|p| p.name.clone()).collect();

    if manager == "apt" {
        let mut args = vec!["-W", DPKG_QUERY_FORMAT];
        args.extend(names.iter().map(String::as_str));
        let Ok(queried) = list(cancel, "dpkg-query", &args, &[], 60).await else {
            return Vec::new();
        };
        let installed = parse_dpkg_installed(queried.stdout());
        return wanted
            .iter()
            .filter_map(|p| {
                let version = installed.get(&p.name)?;
                Some(PackageVersion {
                    name: p.name.clone(),
                    version: version.clone(),
                })
            })
            .collect();
    }

    let Ok(installed) = rpm_installed_by_name(&names, cancel).await else {
        return Vec::new();
    };
    wanted
        .iter()
        .filter_map(|p| {
            let versions = installed.get(&p.name)?;
            let target = normalise_epoch(&p.version);
            let version = versions
                .iter()
                .find(|v| **v == target)
                .or_else(|| versions.iter().max_by(|a, b| compare_evr(a, b)))?;
            Some(PackageVersion {
                name: p.name.clone(),
                version: version.clone(),
            })
        })
        .collect()
}

/// `[epoch:]version[-release]` compared the way rpm does.
fn compare_evr(a: &str, b: &str) -> Ordering {
    fn split(evr: &str) -> (u64, &str, &str) {
        let (epoch, rest) = match evr.split_once(':') {
            Some((e, rest)) if e.chars().all(|c| c.is_ascii_digit()) => {
                (e.parse().unwrap_or(0), rest)
            }
            _ => (0, evr),
        };
        match rest.rsplit_once('-') {
            Some((version, release)) => (epoch, version, release),
            None => (epoch, rest, ""),
        }
    }
    let (ea, va, ra) = split(a);
    let (eb, vb, rb) = split(b);

    ea.cmp(&eb)
        .then_with(|| rpmvercmp(va, vb))
        .then_with(|| rpmvercmp(ra, rb))
}

/// rpm's `rpmvercmp`: runs of digits compare as numbers, runs of letters as
/// strings, digits beat letters, `~` sorts before anything (even the end)
/// and `^` after the end but before anything else.
pub(super) fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    let separator = |c: &u8| !c.is_ascii_alphanumeric() && *c != b'~' && *c != b'^';

    loop {
        while a.first().is_some_and(separator) {
            a = &a[1..];
        }
        while b.first().is_some_and(separator) {
            b = &b[1..];
        }

        if a.first() == Some(&b'~') || b.first() == Some(&b'~') {
            if a.first() != Some(&b'~') {
                return Ordering::Greater;
            }
            if b.first() != Some(&b'~') {
                return Ordering::Less;
            }
            a = &a[1..];
            b = &b[1..];
            continue;
        }

        if a.first() == Some(&b'^') || b.first() == Some(&b'^') {
            if a.is_empty() {
                return Ordering::Less;
            }
            if b.is_empty() {
                return Ordering::Greater;
            }
            if a.first() != Some(&b'^') {
                return Ordering::Greater;
            }
            if b.first() != Some(&b'^') {
                return Ordering::Less;
            }
            a = &a[1..];
            b = &b[1..];
            continue;
        }

        if a.is_empty() || b.is_empty() {
            break;
        }

        let numeric = a[0].is_ascii_digit();
        let run = |s: &[u8]| -> usize {
            s.iter()
                .take_while(|c| {
                    if numeric {
                        c.is_ascii_digit()
                    } else {
                        c.is_ascii_alphabetic()
                    }
                })
                .count()
        };
        let (la, lb) = (run(a), run(b));
        let (sa, sb) = (&a[..la], &b[..lb]);

        if sb.is_empty() {
            // Different kinds of run: a number is newer than letters.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let order = if numeric {
            let trim = |s: &[u8]| -> usize { s.iter().take_while(|c| **c == b'0').count() };
            let (na, nb) = (&sa[trim(sa)..], &sb[trim(sb)..]);
            na.len().cmp(&nb.len()).then_with(|| na.cmp(nb))
        } else {
            sa.cmp(sb)
        };
        if order != Ordering::Equal {
            return order;
        }
        a = &a[la..];
        b = &b[lb..];
    }

    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// A reboot is wanted: Debian and Ubuntu leave a file; on RPM systems
/// `needs-restarting -r` says so with exit code 1. False when neither is
/// there to ask.
async fn reboot_required(manager: &str, cancel: &mut watch::Receiver<bool>) -> bool {
    if Path::new("/var/run/reboot-required").exists() || Path::new("/run/reboot-required").exists()
    {
        return true;
    }
    if manager == "apt" {
        return false;
    }

    let captured = if Path::new("/usr/bin/needs-restarting").exists() {
        list(cancel, "needs-restarting", &["-r"], &[], 60).await
    } else {
        list(cancel, manager, &["needs-restarting", "-r"], &[], 60).await
    };

    match captured {
        Ok(captured) => needs_restarting_says_reboot(
            captured.code(),
            captured.stdout().iter().chain(captured.stderr()),
        ),
        Err(_) => false,
    }
}

/// `needs-restarting -r` exits 1 when a reboot is needed, but dnf also exits
/// 1 when the plugin that provides it isn't installed; that's not a reboot.
fn needs_restarting_says_reboot<'a>(
    code: Option<i32>,
    output: impl IntoIterator<Item = &'a String>,
) -> bool {
    if code != Some(1) {
        return false;
    }
    let output = output
        .into_iter()
        .map(|l| l.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");

    !["no such command", "unknown argument", "command not found"]
        .iter()
        .any(|missing| output.contains(missing))
}

/// Packages held at their version. Empty when nothing is, or on dnf/yum
/// without the versionlock plugin.
async fn held(manager: &str, cancel: &mut watch::Receiver<bool>) -> Vec<String> {
    hold_names(&holds(manager, cancel).await.unwrap_or_default())
}

/// The hold list, or None where packages can't be held (dnf/yum without the
/// versionlock plugin, which is how `versionlock list` failing reads).
async fn holds(manager: &str, cancel: &mut watch::Receiver<bool>) -> Option<Vec<Hold>> {
    let captured = if manager == "apt" {
        list(cancel, "apt-mark", &["showhold"], APT_ENV, 60).await
    } else {
        list(cancel, manager, &["-q", "versionlock", "list"], &[], 60).await
    };

    match captured {
        Ok(captured) if captured.code() == Some(0) => Some(if manager == "apt" {
            parse_showhold(captured.stdout())
                .into_iter()
                .map(|name| Hold {
                    entry: name.clone(),
                    name,
                })
                .collect()
        } else {
            parse_versionlock(captured.stdout())
        }),
        _ => None,
    }
}

fn os_release() -> Option<OsRelease> {
    ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|text| parse_os_release(&text))
}

const RPM_QUERY_FORMAT: &str = "%{NAME}.%{ARCH} %{EPOCH}:%{VERSION}-%{RELEASE}\\n";

/// `openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]`
fn parse_apt_line(line: &str) -> Option<PackageUpdate> {
    let mut words = line.split_whitespace();
    let (name, suites) = words.next()?.split_once('/')?;
    let candidate = words.next()?;
    let arch = words.next()?;

    if name.is_empty() || !candidate.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }

    let installed = line
        .split_once("[upgradable from:")
        .map(|(_, rest)| rest.trim().trim_end_matches(']').trim().to_string())
        .filter(|v| !v.is_empty());

    Some(PackageUpdate {
        name: name.to_string(),
        installed,
        candidate: candidate.to_string(),
        security: suites.split(',').any(|s| s.contains("-security")),
        arch: Some(arch.to_string()),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RpmUpdate {
    name: String,
    arch: String,
    candidate: String,
    /// The line as check-update printed it (joined, when it wrapped).
    line: String,
}

/// `name.arch` split at the last dot, when what follows looks like an arch.
fn split_name_arch(word: &str) -> Option<(&str, &str)> {
    let (name, arch) = word.rsplit_once('.')?;
    let arch_ok = !arch.is_empty() && arch.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    (!name.is_empty() && arch_ok).then_some((name, arch))
}

/// `check-update`'s three columns, `name.arch [epoch:]version-release repo`.
/// A long name wraps the rest onto the next line, and the "Obsoleting
/// Packages" section after the updates isn't more of them.
fn parse_check_update(lines: &[String]) -> Vec<RpmUpdate> {
    let mut updates = Vec::new();
    let mut pending: Option<String> = None;

    for line in lines {
        if line.trim_start().starts_with("Obsoleting") {
            break;
        }
        if line.trim().is_empty() {
            pending = None;
            continue;
        }
        let joined = match pending.take() {
            Some(start) if line.starts_with(char::is_whitespace) => {
                format!("{start} {}", line.trim())
            }
            _ if line.starts_with(char::is_whitespace) => continue,
            _ => line.trim().to_string(),
        };

        let columns: Vec<&str> = joined.split_whitespace().collect();
        match columns.as_slice() {
            [only] if split_name_arch(only).is_some() => pending = Some(joined.clone()),
            [name_arch, evr, _repo] => {
                let Some((name, arch)) = split_name_arch(name_arch) else {
                    continue;
                };
                if !evr.contains('-') || !evr.starts_with(|c: char| c.is_ascii_alphanumeric()) {
                    continue;
                }
                updates.push(RpmUpdate {
                    name: name.to_string(),
                    arch: arch.to_string(),
                    candidate: normalise_epoch(evr),
                    line: columns.join(" "),
                });
            }
            _ => {}
        }
    }

    updates
}

/// RPM versions without an epoch, or with epoch 0, are written without one.
fn normalise_epoch(version: &str) -> String {
    version
        .strip_prefix("(none):")
        .or_else(|| version.strip_prefix("0:"))
        .unwrap_or(version)
        .to_string()
}

/// Lines of [`RPM_QUERY_FORMAT`]: `name.arch epoch:version-release`. A
/// package installed more than once (kernels) keeps the last.
fn parse_rpm_installed(lines: &[String]) -> HashMap<String, String> {
    lines
        .iter()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (key, version) = (words.next()?, words.next()?);
            if words.next().is_some() || !version.contains(':') {
                return None;
            }
            split_name_arch(key)?;
            Some((key.to_string(), normalise_epoch(version)))
        })
        .collect()
}

/// The `name.arch` of a full NEVRA (`openssl-1:3.0.7-28.el9.x86_64`).
fn nevra_name_arch(token: &str) -> Option<String> {
    let (rest, arch) = split_name_arch(token)?;
    let (rest, _release) = rest.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    (!name.is_empty() && !version.is_empty()).then(|| format!("{name}.{arch}"))
}

/// The packages `updateinfo list security` names, as `name.arch`. Whichever
/// column holds the NEVRA (it moves between dnf and yum), it's the token
/// that parses as one.
fn security_name_arches(lines: &[String]) -> HashSet<String> {
    lines
        .iter()
        .flat_map(|line| line.split_whitespace())
        .filter_map(nevra_name_arch)
        .collect()
}

fn parse_showhold(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| valid_package_name(l))
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Package names from `versionlock list`: dnf writes `name-[epoch:]ver-rel.*`,
/// yum `epoch:name-ver-rel.*`, dnf5 `Package name: name`. Excludes (`!`)
/// aren't holds.
fn parse_versionlock(lines: &[String]) -> Vec<Hold> {
    let mut holds = BTreeSet::new();

    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some(name) = line.strip_prefix("Package name:") {
            let name = name.trim();
            if valid_package_name(name) {
                holds.insert(Hold {
                    name: name.to_string(),
                    entry: name.to_string(),
                });
            }
            continue;
        }

        let Some(whole) = line.split_whitespace().next() else {
            continue;
        };
        let entry = whole.strip_suffix(".*").unwrap_or(whole);
        let entry = match entry.split_once(':') {
            Some((epoch, rest))
                if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) =>
            {
                rest
            }
            _ => entry,
        };
        let Some((rest, _release)) = entry.rsplit_once('-') else {
            continue;
        };
        let Some((name, _version)) = rest.rsplit_once('-') else {
            continue;
        };
        if valid_package_name(name) && !whole.starts_with('-') {
            holds.insert(Hold {
                name: name.to_string(),
                entry: whole.to_string(),
            });
        }
    }

    holds.into_iter().collect()
}

fn parse_os_release(text: &str) -> OsRelease {
    let mut values: HashMap<&str, String> = HashMap::new();

    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value)
            .replace("\\\"", "\"");
        if !value.is_empty() {
            values.insert(key.trim(), value);
        }
    }

    OsRelease {
        // os-release(5): ID defaults to "linux".
        id: values.remove("ID").unwrap_or_else(|| "linux".into()),
        version_id: values.remove("VERSION_ID"),
        pretty_name: values.remove("PRETTY_NAME"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names_cant_remove_or_pass_options() {
        for good in [
            "git",
            "build-essential",
            "libssl3",
            "g++",
            "python3.12",
            "lib32z1:i386",
        ] {
            assert!(valid_package_name(good), "{good}");
        }
        // apt reads a trailing - as "remove".
        for bad in [
            "nginx-",
            "openssh-server-",
            "-y",
            "--purge",
            "",
            "a b",
            "pkg=1.0",
            "../x",
            "pkg/stable",
        ] {
            assert!(!valid_package_name(bad), "{bad}");
        }
        assert!(check_names(&["git".into(), "nginx-".into()]).is_err());
    }

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_string).collect()
    }

    #[test]
    fn package_names_cant_pass_for_options() {
        for ok in [
            "openssl",
            "libaudit1",
            "linux-image-6.8.0-45-generic",
            "g++",
            "python3.12",
            "libc6:amd64",
        ] {
            assert!(valid_package_name(ok), "{ok} was refused");
        }
        for bad in ["", "-y", "--reinstall", "a b", "pkg;rm", "$(x)", "../x"] {
            assert!(!valid_package_name(bad), "{bad:?} was accepted");
        }
    }

    fn pv(name: &str, version: &str) -> PackageVersion {
        PackageVersion {
            name: name.into(),
            version: version.into(),
        }
    }

    #[test]
    fn versions_cant_pass_for_options_or_shell() {
        for ok in [
            "3.0.13-0ubuntu3.5",
            "1:3.0.7-28.el9_4",
            "2.39-0ubuntu8.3",
            "1.2~rc1-1",
            "5.14.0-427.el9",
            "1:1.12.0-1+deb12u3",
        ] {
            assert!(valid_version(ok), "{ok} was refused");
        }
        let long = "1".repeat(129);
        for bad in [
            "",
            "--foo",
            "-1.2",
            "x;rm",
            "1.2 3",
            "1.2\n3",
            "$(id)",
            "1.2`id`",
            "1.2|sh",
            "1.2>x",
            "../1",
            "1/2",
            long.as_str(),
        ] {
            assert!(!valid_version(bad), "{bad:?} was accepted");
        }
        assert!(valid_version(&"1".repeat(128)));

        assert!(check_versions(&[pv("openssl", "3.0.13-0ubuntu3.5")]).is_ok());
        assert!(check_versions(&[]).is_err());
        assert!(check_versions(&[pv("--reinstall", "1.0")]).is_err());
        assert!(check_versions(&[pv("openssl", "--allow-unauthenticated")]).is_err());
        assert!(check_versions(&[pv("openssl", "1.0"), pv("openssl", "1.1")]).is_err());
        let many: Vec<PackageVersion> = (0..501).map(|i| pv(&format!("p{i}"), "1.0")).collect();
        assert!(check_versions(&many).is_err());
        assert!(check_versions(&many[..500]).is_ok());
    }

    #[test]
    fn apt_installs_name_equals_version_as_separate_arguments() {
        let packages = [
            pv("openssl", "3.0.13-0ubuntu3.4"),
            pv("libc6:amd64", "2.39-0ubuntu8.3"),
        ];
        assert_eq!(
            apt_install_versions_args(&packages, false),
            vec![
                "install",
                "-y",
                "-q",
                "-o",
                "Dpkg::Options::=--force-confold",
                "openssl=3.0.13-0ubuntu3.4",
                "libc6:amd64=2.39-0ubuntu8.3",
            ]
        );
        assert_eq!(
            apt_install_versions_args(&packages[..1], true),
            vec![
                "install",
                "-y",
                "-q",
                "-o",
                "Dpkg::Options::=--force-confold",
                "--allow-downgrades",
                "openssl=3.0.13-0ubuntu3.4",
            ]
        );
    }

    #[test]
    fn dnf_installs_and_downgrades_name_dash_version_with_epochs() {
        let openssl = pv("openssl", "1:3.0.7-28.el9");
        let tzdata = pv("tzdata", "2024a-1.el9");

        assert_eq!(rpm_spec(&openssl), "openssl-1:3.0.7-28.el9");
        assert_eq!(
            rpm_args("install", &[&openssl, &tzdata]),
            vec![
                "-y",
                "-q",
                "install",
                "openssl-1:3.0.7-28.el9",
                "tzdata-2024a-1.el9"
            ]
        );
        assert_eq!(
            rpm_args("downgrade", &[&tzdata]),
            vec!["-y", "-q", "downgrade", "tzdata-2024a-1.el9"]
        );
    }

    #[test]
    fn holds_are_set_with_apt_mark_or_versionlock() {
        let names = vec!["nginx".to_string(), "openssl".to_string()];
        assert_eq!(
            apt_mark_args(true, &names),
            vec!["hold", "nginx", "openssl"]
        );
        assert_eq!(
            apt_mark_args(false, &names),
            vec!["unhold", "nginx", "openssl"]
        );
        assert_eq!(
            versionlock_args(true, &names),
            vec!["-q", "versionlock", "add", "nginx", "openssl"]
        );
        assert_eq!(
            versionlock_args(false, &names),
            vec!["-q", "versionlock", "delete", "nginx", "openssl"]
        );

        let held: Vec<Hold> = ["libc6:amd64", "nginx"]
            .iter()
            .map(|n| Hold {
                name: n.to_string(),
                entry: n.to_string(),
            })
            .collect();
        assert_eq!(
            hold_names(&held_among(&held, &["nginx", "curl"])),
            vec!["nginx"]
        );
        assert_eq!(
            hold_names(&held_among(&held, &["libc6"])),
            vec!["libc6:amd64"]
        );
        assert!(held_among(&held, &["nginx-common"]).is_empty());
    }

    #[test]
    fn rpm_versions_compare_like_rpm() {
        use std::cmp::Ordering::*;
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0.1", "2.0", Greater),
            ("1.10", "1.9", Greater),
            ("1.010", "1.10", Equal),
            ("1.0a", "1.0", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0^git1", "1.0", Greater),
            ("1.0^git1", "1.0.1", Less),
            ("1.a", "1.1", Less),
            ("el9_4", "el9", Greater),
        ] {
            assert_eq!(rpmvercmp(a, b), want, "{a} vs {b}");
        }
        assert_eq!(compare_evr("1:3.0.7-27.el9", "3.0.8-1.el9"), Greater);
        assert_eq!(compare_evr("3.0.7-27.el9", "0:3.0.7-28.el9"), Less);
        assert_eq!(compare_evr("3.0.7-28.el9_4", "3.0.7-28.el9"), Greater);
        assert_eq!(compare_evr("0:1.2-3", "1.2-3"), Equal);
    }

    #[test]
    fn installed_versions_parse_from_dpkg_and_rpm() {
        let dpkg = parse_dpkg_installed(&lines(
            "ii \topenssl\topenssl\t3.0.13-0ubuntu3.4\n\
             hi \tlibc6:amd64\tlibc6\t2.39-0ubuntu8.3\n\
             rc \told-thing\told-thing\t1.0-1",
        ));
        assert_eq!(dpkg["openssl"], "3.0.13-0ubuntu3.4");
        assert_eq!(dpkg["libc6"], "2.39-0ubuntu8.3");
        assert_eq!(dpkg["libc6:amd64"], "2.39-0ubuntu8.3");
        assert!(
            !dpkg.contains_key("old-thing"),
            "config files only isn't installed"
        );

        let rpm = parse_rpm_by_name(&lines(
            "openssl 1:3.0.7-28.el9\nkernel (none):5.14.0-362.el9\nkernel (none):5.14.0-427.el9\npackage nope is not installed",
        ));
        assert_eq!(rpm["openssl"], vec!["1:3.0.7-28.el9"]);
        assert_eq!(rpm["kernel"], vec!["5.14.0-362.el9", "5.14.0-427.el9"]);
        assert!(!rpm.contains_key("package"));
    }

    #[test]
    fn apt_lines_parse_with_their_versions_and_security() {
        let update = parse_apt_line(
            "openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]",
        )
        .unwrap();
        assert_eq!(
            update,
            PackageUpdate {
                name: "openssl".into(),
                installed: Some("3.0.13-0ubuntu3.4".into()),
                candidate: "3.0.13-0ubuntu3.5".into(),
                security: true,
                arch: Some("amd64".into()),
            }
        );

        let plain = parse_apt_line(
            "tzdata/noble-updates 2024a-3ubuntu1.1 all [upgradable from: 2024a-2ubuntu1]",
        )
        .unwrap();
        assert!(!plain.security);
        assert_eq!(plain.arch.as_deref(), Some("all"));

        let epoch = parse_apt_line(
            "libvpx9/bookworm-security 1:1.12.0-1+deb12u3 amd64 [upgradable from: 1:1.12.0-1+deb12u2]",
        )
        .unwrap();
        assert_eq!(epoch.candidate, "1:1.12.0-1+deb12u3");
        assert_eq!(epoch.installed.as_deref(), Some("1:1.12.0-1+deb12u2"));
        assert!(epoch.security);

        assert!(parse_apt_line("Listing...").is_none());
        assert!(parse_apt_line("Listing... Done").is_none());
        assert!(parse_apt_line("").is_none());
    }

    #[test]
    fn check_update_parses_every_line_not_just_the_last_forty() {
        let mut text = String::from("\n");
        for i in 0..120 {
            text.push_str(&format!(
                "pkg{i}.x86_64                 1.{i}-1.el9                   appstream\n"
            ));
        }
        let updates = parse_check_update(&lines(&text));

        assert_eq!(updates.len(), 120);
        assert_eq!(updates[0].name, "pkg0");
        assert_eq!(updates[119].candidate, "1.119-1.el9");
    }

    #[test]
    fn check_update_handles_epochs_arches_wrapping_and_obsoletes() {
        let output = lines(
            "\
openssl.x86_64                       1:3.0.7-28.el9_4             baseos
python3.12.noarch                    3.12.1-4.el9                 appstream
tzdata.noarch                        0:2024a-1.el9                baseos
a-very-long-package-name-that-wraps.x86_64
                                     2.1-3.el9                    appstream
Security: kernel-core-5.14.0-427.el9.x86_64 is an installed security update
Obsoleting Packages
grub2-tools.x86_64                   1:2.06-80.el9                baseos
    grub2-tools.x86_64               1:2.06-77.el9                @baseos",
        );
        let updates = parse_check_update(&output);
        let names: Vec<(&str, &str, &str)> = updates
            .iter()
            .map(|u| (u.name.as_str(), u.arch.as_str(), u.candidate.as_str()))
            .collect();

        assert_eq!(
            names,
            vec![
                ("openssl", "x86_64", "1:3.0.7-28.el9_4"),
                ("python3.12", "noarch", "3.12.1-4.el9"),
                ("tzdata", "noarch", "2024a-1.el9"),
                ("a-very-long-package-name-that-wraps", "x86_64", "2.1-3.el9"),
            ]
        );
        assert_eq!(
            updates[3].line,
            "a-very-long-package-name-that-wraps.x86_64 2.1-3.el9 appstream"
        );
    }

    #[test]
    fn rpm_versions_drop_an_empty_epoch() {
        let installed = parse_rpm_installed(&lines(
            "\
openssl.x86_64 1:3.0.7-27.el9
tzdata.noarch (none):2023c-1.el9
kernel.x86_64 (none):5.14.0-362.el9
kernel.x86_64 (none):5.14.0-427.el9
package nothere.x86_64 is not installed",
        ));

        assert_eq!(installed["openssl.x86_64"], "1:3.0.7-27.el9");
        assert_eq!(installed["tzdata.noarch"], "2023c-1.el9");
        assert_eq!(installed["kernel.x86_64"], "5.14.0-427.el9");
        assert_eq!(installed.len(), 3);
        assert_eq!(normalise_epoch("0:1.2-3"), "1.2-3");
    }

    #[test]
    fn security_advisories_match_exact_name_and_arch() {
        let secure = security_name_arches(&lines(
            "\
RHSA-2024:3501 Important/Sec. openssl-1:3.0.7-28.el9_4.x86_64
RHSA-2024:3502 Moderate/Sec.  openssl-libs-1:3.0.7-28.el9_4.i686
FEDORA-2024-1a2b3c security Moderate python3.12-3.12.1-4.fc40.noarch 2024-05-01 10:00:00",
        ));

        assert!(secure.contains("openssl.x86_64"));
        assert!(secure.contains("openssl-libs.i686"));
        assert!(secure.contains("python3.12.noarch"));
        assert!(!secure.contains("openssl-libs.x86_64"), "arch must match");
        assert!(!secure.contains("openssl.i686"));
        assert!(!secure.contains("ssl.x86_64"), "no substring matches");
        assert_eq!(secure.len(), 3);
    }

    #[test]
    fn holds_parse_from_apt_mark_and_versionlock() {
        assert_eq!(
            parse_showhold(&lines("nginx\nlinux-image-generic\n\nnginx")),
            vec!["linux-image-generic", "nginx"]
        );

        let locks = parse_versionlock(&lines(
            "\
Last metadata expiration check: 0:10:01 ago on Fri 01 Nov 2026.
openssl-1:3.0.7-28.el9_4.*
kernel-0:5.14.0-427.el9.*
0:httpd-2.4.6-99.el7.*
!tzdata-0:2024a-1.el9.*
# Added by 'versionlock add' command on 2026-11-01
Package name: nginx",
        ));
        assert_eq!(
            hold_names(&locks),
            vec!["httpd", "kernel", "nginx", "openssl"]
        );
        // Letting go passes the entries, which yum's delete matches whole.
        assert_eq!(
            hold_entries(&held_among(&locks, &["httpd", "openssl", "nginx"])),
            vec![
                "0:httpd-2.4.6-99.el7.*",
                "nginx",
                "openssl-1:3.0.7-28.el9_4.*"
            ]
        );
    }

    #[test]
    fn os_release_reads_quoted_and_bare_values() {
        let os = parse_os_release(
            "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
        );
        assert_eq!(
            os,
            OsRelease {
                id: "ubuntu".into(),
                version_id: Some("24.04".into()),
                pretty_name: Some("Ubuntu 24.04.1 LTS".into()),
            }
        );
        assert_eq!(parse_os_release("NAME=x").id, "linux");
    }

    #[test]
    fn needs_restarting_exit_one_is_a_reboot_unless_the_command_is_missing() {
        let reboot = lines("Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.");
        assert!(needs_restarting_says_reboot(Some(1), &reboot));
        assert!(!needs_restarting_says_reboot(
            Some(0),
            &lines("Reboot should not be necessary.")
        ));
        assert!(!needs_restarting_says_reboot(
            Some(1),
            &lines("No such command: needs-restarting. Please use /usr/bin/dnf --help")
        ));
        assert!(!needs_restarting_says_reboot(None, &reboot));
    }
}
