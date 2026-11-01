use std::path::Path;
use std::time::Duration;

use daemon_jobs::{run_child, ChildOutcome, Failure, JobContext};

#[derive(serde::Serialize)]
pub struct PackageReport {
    pub manager: String,
    pub upgradable: Vec<String>,
    pub security: Vec<String>,
    pub reboot_required: bool,
    pub applied: bool,
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

    let (upgradable, security) = match manager {
        "apt" => {
            let _ = run_child(
                "apt-get",
                &["update", "-q"],
                None,
                &[("DEBIAN_FRONTEND", "noninteractive")],
                Duration::from_secs(300),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let outcome = run_child(
                "apt",
                &["list", "--upgradable"],
                None,
                &[("DEBIAN_FRONTEND", "noninteractive")],
                Duration::from_secs(120),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let lines: Vec<String> = outcome
                .tail()
                .iter()
                .filter(|l| l.contains('/') && l.contains('['))
                .cloned()
                .collect();
            let security: Vec<String> = lines
                .iter()
                .filter(|l| l.contains("-security"))
                .cloned()
                .collect();
            (lines, security)
        }
        _ => {
            let outcome = run_child(
                manager,
                &["check-update", "-q"],
                None,
                &[],
                Duration::from_secs(300),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let lines: Vec<String> = outcome
                .tail()
                .iter()
                .filter(|l| l.split_whitespace().count() == 3)
                .cloned()
                .collect();
            let outcome = run_child(
                manager,
                &["updateinfo", "list", "security", "-q"],
                None,
                &[],
                Duration::from_secs(120),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let security: Vec<String> = outcome.tail().to_vec();
            (lines, security)
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
                    &[("DEBIAN_FRONTEND", "noninteractive")],
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
                    &[("DEBIAN_FRONTEND", "noninteractive")],
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
        reboot_required: Path::new("/var/run/reboot-required").exists()
            || Path::new("/run/reboot-required").exists(),
        applied,
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
            &[("DEBIAN_FRONTEND", "noninteractive")],
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
        reboot_required: Path::new("/var/run/reboot-required").exists()
            || Path::new("/run/reboot-required").exists(),
        applied: true,
    })
}

#[cfg(test)]
mod tests {
    use super::valid_package_name;

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
}
