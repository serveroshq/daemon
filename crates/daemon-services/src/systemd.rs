use std::process::Stdio;
use std::time::Duration;

use daemon_protocol::{ServiceAction, ServiceStatus};
use tokio::process::Command;

use crate::{Lifecycle, Result, ServiceError};

pub struct SystemdAdapter {
    pub timeout: Duration,
}

impl Default for SystemdAdapter {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(90),
        }
    }
}

pub fn valid_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 256
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':' | '\\'))
}

/// The systemctl arguments for an action. systemctl waits for the job by
/// default, which is what we want; `--no-block` is a bare switch, and
/// `--no-block=false` made systemctl refuse every start, stop and restart.
pub fn action_args(action: ServiceAction, unit: &str) -> [&str; 2] {
    let verb = match action {
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Restart => "restart",
        ServiceAction::Reload => "reload-or-restart",
    };

    [verb, unit]
}

/// Units ServerOS will never remove: the machine needs them to boot, stay
/// reachable or run containers, or they are ServerOS itself.
pub fn protected_unit(unit: &str) -> bool {
    let base = unit.split('@').next().unwrap_or(unit);
    let base = base.strip_suffix(".service").unwrap_or(base);
    const EXACT: &[&str] = &[
        "ssh",
        "sshd",
        "dbus",
        "dbus-broker",
        "networking",
        "NetworkManager",
        "docker",
        "containerd",
        "cron",
        "crond",
        "polkit",
        "udev",
        "rsyslog",
        "snapd",
        "getty",
        "serial-getty",
        "user",
        "multipathd",
    ];
    const PREFIXES: &[&str] = &["systemd-", "serveros", "cloud-", "ifup", "wpa_supplicant"];

    EXACT.contains(&base) || PREFIXES.iter().any(|p| base.starts_with(p))
}

/// What removing a unit did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RemovedUnit {
    /// Unit files and drop-in folders deleted (ones made on the machine).
    pub deleted: Vec<String>,
    /// Installed by a package: stopped and turned off, its files left.
    pub package_owned: bool,
}

/// Where a unit file lives decides what removing it may delete: files an
/// admin made (under /etc/systemd/system) go; a package's (/usr/lib, /lib)
/// stay, since the package owns them.
pub fn made_on_machine(path: &str) -> bool {
    path.starts_with("/etc/systemd/system/") && !path.contains("..")
}

impl SystemdAdapter {
    /// Stop a unit, keep it from starting at boot, and delete its unit file
    /// when it was made on the machine. Data and folders it uses are never
    /// touched.
    pub async fn remove(&self, unit: &str) -> Result<RemovedUnit> {
        if !valid_unit_name(unit) {
            return Err(ServiceError::Command(format!(
                "{unit:?} is not a valid unit name"
            )));
        }
        if protected_unit(unit) {
            return Err(ServiceError::Command(format!(
                "{unit} keeps the machine running, so ServerOS won't remove it"
            )));
        }

        let show = self
            .run(
                "systemctl",
                &[
                    "show",
                    "-p",
                    "FragmentPath",
                    "-p",
                    "DropInPaths",
                    "--value",
                    unit,
                ],
            )
            .await?;
        let mut lines = show.lines();
        let fragment = lines.next().unwrap_or("").trim().to_string();
        let drop_ins: Vec<String> = lines
            .next()
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_string)
            .collect();

        // Stop it and keep it from coming back at boot.
        self.run("systemctl", &["disable", "--now", unit]).await?;

        let mut removed = RemovedUnit::default();
        if made_on_machine(&fragment) {
            tokio::fs::remove_file(&fragment)
                .await
                .map_err(|e| ServiceError::Command(format!("could not delete {fragment}: {e}")))?;
            removed.deleted.push(fragment.clone());
        } else if !fragment.is_empty() {
            removed.package_owned = true;
        }
        for drop_in in drop_ins.iter().filter(|p| made_on_machine(p)) {
            if tokio::fs::remove_file(drop_in).await.is_ok() {
                removed.deleted.push(drop_in.clone());
            }
        }
        let folder = format!("/etc/systemd/system/{unit}.d");
        if tokio::fs::remove_dir(&folder).await.is_ok() {
            removed.deleted.push(folder);
        }

        let _ = self.run("systemctl", &["daemon-reload"]).await;
        let _ = self.run("systemctl", &["reset-failed", unit]).await;

        Ok(removed)
    }

    async fn run(&self, program: &str, args: &[&str]) -> Result<String> {
        let output = tokio::time::timeout(
            self.timeout,
            Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .env("LC_ALL", "C")
                .output(),
        )
        .await
        .map_err(|_| {
            ServiceError::Command(format!(
                "{program} {} timed out after {:?}",
                args.join(" "),
                self.timeout
            ))
        })?
        .map_err(|e| ServiceError::Command(format!("could not run {program}: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(ServiceError::Command(if stderr.is_empty() {
                format!("{program} {} exited with {}", args.join(" "), output.status)
            } else {
                stderr
            }));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

impl Lifecycle for SystemdAdapter {
    async fn act(&self, unit: &str, action: ServiceAction) -> Result<()> {
        if !valid_unit_name(unit) {
            return Err(ServiceError::Command(format!(
                "{unit:?} is not a valid unit name"
            )));
        }

        self.run("systemctl", &action_args(action, unit))
            .await
            .map(|_| ())
    }

    async fn status(&self, unit: &str) -> Result<ServiceStatus> {
        if !valid_unit_name(unit) {
            return Err(ServiceError::Command(format!(
                "{unit:?} is not a valid unit name"
            )));
        }

        let shown = self
            .run(
                "systemctl",
                &["show", "-p", "ActiveState,SubState", "--no-pager", unit],
            )
            .await?;

        Ok(status_from_show(&shown))
    }

    async fn logs(&self, unit: &str, lines: u32) -> Result<Vec<String>> {
        if !valid_unit_name(unit) {
            return Err(ServiceError::Command(format!(
                "{unit:?} is not a valid unit name"
            )));
        }

        let count = lines.clamp(1, 5000).to_string();
        let out = self
            .run(
                "journalctl",
                &[
                    "-u",
                    unit,
                    "-n",
                    &count,
                    "--no-pager",
                    "-o",
                    "short-iso",
                    "--no-hostname",
                ],
            )
            .await?;

        Ok(out
            .lines()
            .filter(|line| !daemon_core::logskip::skips_line(Some(unit), line))
            .map(daemon_core::ipmask::outgoing)
            .collect())
    }
}

pub fn status_from_show(text: &str) -> ServiceStatus {
    let mut active = "";
    let mut sub = "";

    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ActiveState=") {
            active = v.trim();
        } else if let Some(v) = line.strip_prefix("SubState=") {
            sub = v.trim();
        }
    }

    match (active, sub) {
        ("active", "running") | ("active", "exited") => ServiceStatus::Running,
        ("activating", "auto-restart") | ("activating", _) => ServiceStatus::Restarting,
        ("failed", _) => ServiceStatus::Failed,
        ("inactive", _) | ("deactivating", _) => ServiceStatus::Stopped,
        _ => ServiceStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_are_plain_systemctl_verbs_that_wait() {
        assert_eq!(
            action_args(ServiceAction::Start, "app.service"),
            ["start", "app.service"]
        );
        assert_eq!(
            action_args(ServiceAction::Stop, "app.service"),
            ["stop", "app.service"]
        );
        assert_eq!(
            action_args(ServiceAction::Restart, "app.service"),
            ["restart", "app.service"]
        );
        assert_eq!(
            action_args(ServiceAction::Reload, "app.service"),
            ["reload-or-restart", "app.service"]
        );
        for action in [
            ServiceAction::Start,
            ServiceAction::Stop,
            ServiceAction::Restart,
            ServiceAction::Reload,
        ] {
            assert!(action_args(action, "x.service")
                .iter()
                .all(|a| !a.starts_with("--no-block")));
        }
    }

    #[test]
    fn the_machine_s_own_units_are_never_removed() {
        for unit in [
            "ssh.service",
            "sshd.service",
            "systemd-journald.service",
            "dbus.service",
            "docker.service",
            "containerd.service",
            "serverosd.service",
            "serveros-gateway.service",
            "getty@tty1.service",
            "cloud-init.service",
        ] {
            assert!(protected_unit(unit), "{unit}");
        }
        for unit in [
            "laravel-queue.service",
            "myapp.service",
            "nginx.service",
            "php8.4-fpm.service",
        ] {
            assert!(!protected_unit(unit), "{unit}");
        }
    }

    #[test]
    fn only_unit_files_made_on_the_machine_are_deleted() {
        assert!(made_on_machine("/etc/systemd/system/myapp.service"));
        assert!(made_on_machine(
            "/etc/systemd/system/myapp.service.d/override.conf"
        ));
        assert!(!made_on_machine("/usr/lib/systemd/system/nginx.service"));
        assert!(!made_on_machine("/lib/systemd/system/nginx.service"));
        assert!(!made_on_machine(
            "/etc/systemd/system/../../usr/lib/x.service"
        ));
        assert!(!made_on_machine(""));
    }

    #[test]
    fn unit_names_are_validated_before_reaching_a_shell() {
        assert!(valid_unit_name("nginx.service"));
        assert!(valid_unit_name("postgresql@16-main.service"));
        assert!(!valid_unit_name("nginx.service; rm -rf /"));
        assert!(!valid_unit_name("--help"));
        assert!(!valid_unit_name(""));
    }

    #[test]
    fn maps_show_output_to_status() {
        assert_eq!(
            status_from_show("ActiveState=active\nSubState=running\n"),
            ServiceStatus::Running
        );
        assert_eq!(
            status_from_show("ActiveState=activating\nSubState=auto-restart\n"),
            ServiceStatus::Restarting
        );
        assert_eq!(
            status_from_show("ActiveState=failed\nSubState=failed\n"),
            ServiceStatus::Failed
        );
        assert_eq!(
            status_from_show("ActiveState=inactive\nSubState=dead\n"),
            ServiceStatus::Stopped
        );
    }
}
