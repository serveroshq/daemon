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

impl SystemdAdapter {
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

        let verb = match action {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
            ServiceAction::Reload => "reload-or-restart",
        };

        self.run("systemctl", &[verb, "--no-block=false", unit])
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

        Ok(out.lines().map(daemon_core::redact::redact).collect())
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
