use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use daemon_jobs::{capture_child, run_child, Captured, ChildOutcome, Failure, JobContext};
use serde::Serialize;
use tokio::sync::watch;

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
    })
}

const MAX_INSTALL_PACKAGES: usize = 500;

fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
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
    })
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
    let captured = if manager == "apt" {
        list(cancel, "apt-mark", &["showhold"], APT_ENV, 60).await
    } else {
        list(cancel, manager, &["-q", "versionlock", "list"], &[], 60).await
    };

    match captured {
        Ok(captured) if captured.code() == Some(0) => {
            if manager == "apt" {
                parse_showhold(captured.stdout())
            } else {
                parse_versionlock(captured.stdout())
            }
        }
        _ => Vec::new(),
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
fn parse_versionlock(lines: &[String]) -> Vec<String> {
    let mut names = BTreeSet::new();

    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some(name) = line.strip_prefix("Package name:") {
            let name = name.trim();
            if valid_package_name(name) {
                names.insert(name.to_string());
            }
            continue;
        }

        let Some(entry) = line.split_whitespace().next() else {
            continue;
        };
        let entry = entry.strip_suffix(".*").unwrap_or(entry);
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
        if valid_package_name(name) {
            names.insert(name.to_string());
        }
    }

    names.into_iter().collect()
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

        assert_eq!(
            parse_versionlock(&lines(
                "\
Last metadata expiration check: 0:10:01 ago on Fri 01 Nov 2026.
openssl-1:3.0.7-28.el9_4.*
kernel-0:5.14.0-427.el9.*
0:httpd-2.4.6-99.el7.*
!tzdata-0:2024a-1.el9.*
# Added by 'versionlock add' command on 2026-11-01
Package name: nginx"
            )),
            vec!["httpd", "kernel", "nginx", "openssl"]
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
