//! Scheduled work: system and per-user crontabs, and systemd timers.

use std::path::Path;
use std::time::Duration;

use daemon_protocol::ScheduledTask;

use crate::exec;

/// A crontab. `system` crontabs (`/etc/crontab`, `/etc/cron.d/*`) carry a
/// user column; per-user ones do not.
pub fn parse_crontab(
    text: &str,
    source: &str,
    system: bool,
    default_user: Option<&str>,
) -> Vec<ScheduledTask> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.contains('=') || l.starts_with('@'))
        .filter_map(|line| {
            let (schedule, rest) = if line.starts_with('@') {
                let (s, r) = line.split_once(char::is_whitespace)?;
                (s.to_string(), r.trim())
            } else {
                let fields: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
                if fields.len() < 6 {
                    return None;
                }
                (fields[..5].join(" "), fields[5].trim())
            };

            let (user, command) = if system {
                let (u, c) = rest.split_once(char::is_whitespace)?;
                (Some(u.to_string()), c.trim().to_string())
            } else {
                (default_user.map(str::to_string), rest.to_string())
            };

            (!command.is_empty()).then(|| ScheduledTask {
                source: source.into(),
                schedule,
                command,
                user,
            })
        })
        .collect()
}

/// `systemctl list-timers --all --no-legend --plain`: columns are NEXT LEFT
/// LAST PASSED UNIT ACTIVATES, with dates containing spaces; anchor on the
/// `.timer` token.
pub fn parse_list_timers(text: &str) -> Vec<ScheduledTask> {
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let idx = tokens.iter().position(|t| t.ends_with(".timer"))?;
            let timer = tokens[idx];
            let activates = tokens.get(idx + 1).copied().unwrap_or("");

            Some(ScheduledTask {
                source: "systemd-timer".into(),
                schedule: timer.to_string(),
                command: activates.to_string(),
                user: None,
            })
        })
        .collect()
}

pub async fn discover(timeout: Duration) -> Vec<ScheduledTask> {
    let mut tasks = Vec::new();

    if let Ok(text) = std::fs::read_to_string("/etc/crontab") {
        tasks.extend(parse_crontab(&text, "/etc/crontab", true, None));
    }

    for dir in ["/etc/cron.d"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(text) = std::fs::read_to_string(&path) {
                    tasks.extend(parse_crontab(&text, &path.to_string_lossy(), true, None));
                }
            }
        }
    }

    for spool in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
        if let Ok(entries) = std::fs::read_dir(spool) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let user = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        tasks.extend(parse_crontab(
                            &text,
                            &format!("crontab:{}", user.clone().unwrap_or_default()),
                            false,
                            user.as_deref(),
                        ));
                    }
                }
            }
        }
    }

    if let Some(text) = exec::output(
        "systemctl",
        &[
            "list-timers",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        timeout,
    )
    .await
    {
        tasks.extend(
            parse_list_timers(&text)
                .into_iter()
                .filter(|t| !t.schedule.starts_with("systemd-")),
        );
    }

    tasks
}

/// Whether ServerOS wrote this cron entry (it tags its own).
pub fn is_ours(task: &ScheduledTask) -> bool {
    task.command.contains("serverosd") || task.source.contains("serveros")
}

#[allow(dead_code)]
fn _unused(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_system_and_user_crontabs() {
        let system = "SHELL=/bin/sh\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n@daily backup /usr/local/bin/backup.sh\n";
        let tasks = parse_crontab(system, "/etc/crontab", true, None);

        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].schedule, "17 * * * *");
        assert_eq!(tasks[0].user.as_deref(), Some("root"));
        assert_eq!(tasks[1].schedule, "@daily");
        assert_eq!(tasks[1].command, "/usr/local/bin/backup.sh");

        let user = "*/5 * * * * php /srv/app/artisan schedule:run >> /dev/null 2>&1\n";
        let tasks = parse_crontab(user, "crontab:deploy", false, Some("deploy"));

        assert_eq!(tasks[0].user.as_deref(), Some("deploy"));
        assert!(tasks[0].command.starts_with("php /srv/app/artisan"));
    }

    #[test]
    fn parses_timers_by_anchoring_on_the_unit() {
        let text = "Sat 2026-09-13 20:00:00 UTC 3h left Fri 2026-09-12 20:00:00 UTC 21h ago certbot.timer certbot.service\n";
        let tasks = parse_list_timers(text);

        assert_eq!(tasks[0].schedule, "certbot.timer");
        assert_eq!(tasks[0].command, "certbot.service");
    }
}
