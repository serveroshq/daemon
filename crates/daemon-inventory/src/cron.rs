use std::path::Path;
use std::time::Duration;

use daemon_protocol::ScheduledTask;

use crate::exec;

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
                ..task()
            })
        })
        .collect()
}

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
                unit: Some(timer.to_string()),
                ..task()
            })
        })
        .collect()
}

fn task() -> ScheduledTask {
    ScheduledTask {
        source: String::new(),
        schedule: String::new(),
        command: String::new(),
        user: None,
        unit: None,
        description: None,
        next_run: None,
        last_run: None,
    }
}

const TIMER_PROPERTIES: &[&str] = &[
    "Id",
    "Description",
    "TimersCalendar",
    "TimersMonotonic",
    "NextElapseUSecRealtime",
    "LastTriggerUSec",
];

fn known(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value != "n/a" && value != "0").then(|| value.to_string())
}

fn timer_rule(value: &str) -> Option<String> {
    let inner = value.trim().trim_start_matches('{').trim_end_matches('}');
    let rule = inner.split(';').next()?.trim();
    let (key, spec) = rule.split_once('=')?;
    let key = key.trim().replace("USec", "Sec");
    let spec = spec.trim();

    Some(if key == "OnCalendar" {
        spec.to_string()
    } else {
        format!("{key}={spec}")
    })
}

pub fn apply_timer_details(tasks: &mut [ScheduledTask], show: &str) {
    for block in show.split("\n\n") {
        let mut id = None;
        let mut description = None;
        let mut rules = Vec::new();
        let mut next = None;
        let mut last = None;

        for line in block.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "Id" => id = known(value),
                "Description" => description = known(value),
                "TimersCalendar" | "TimersMonotonic" => rules.extend(timer_rule(value)),
                "NextElapseUSecRealtime" => next = known(value),
                "LastTriggerUSec" => last = known(value),
                _ => {}
            }
        }

        let Some(id) = id else { continue };
        if let Some(task) = tasks
            .iter_mut()
            .find(|t| t.unit.as_deref() == Some(id.as_str()))
        {
            if !rules.is_empty() {
                task.schedule = rules.join("; ");
            }
            task.description = description;
            task.next_run = next;
            task.last_run = last;
        }
    }
}

pub fn periodic_scripts(dir: &str, schedule: &str, names: &[String]) -> Vec<ScheduledTask> {
    let mut names: Vec<&String> = names
        .iter()
        .filter(|n| !n.starts_with('.') && n.as_str() != "placeholder")
        .collect();
    names.sort();

    names
        .into_iter()
        .map(|name| ScheduledTask {
            source: dir.to_string(),
            schedule: schedule.to_string(),
            command: format!("{dir}/{name}"),
            user: Some("root".into()),
            ..task()
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

    for (dir, schedule) in [
        ("/etc/cron.hourly", "@hourly"),
        ("/etc/cron.daily", "@daily"),
        ("/etc/cron.weekly", "@weekly"),
        ("/etc/cron.monthly", "@monthly"),
    ] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            let names: Vec<String> = entries
                .flatten()
                .filter(|e| e.path().is_file())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            tasks.extend(periodic_scripts(dir, schedule, &names));
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
        let mut timers: Vec<ScheduledTask> = parse_list_timers(&text)
            .into_iter()
            .filter(|t| !t.schedule.starts_with("systemd-"))
            .collect();

        let units: Vec<String> = timers.iter().filter_map(|t| t.unit.clone()).collect();
        if !units.is_empty() {
            let property = format!("--property={}", TIMER_PROPERTIES.join(","));
            let mut args: Vec<&str> = vec!["show", &property, "--no-pager"];
            args.extend(units.iter().map(String::as_str));
            if let Some(show) = exec::output("systemctl", &args, timeout).await {
                apply_timer_details(&mut timers, &show);
            }
        }

        tasks.extend(timers);
    }

    tasks
}

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
        assert_eq!(tasks[0].unit.as_deref(), Some("certbot.timer"));
    }

    #[test]
    fn timers_get_their_schedule_and_runs_from_systemctl_show() {
        let mut tasks = parse_list_timers(
            "Sat 2026-09-13 20:00:00 UTC 3h left Fri 2026-09-12 20:00:00 UTC 21h ago certbot.timer certbot.service\n\
             n/a n/a n/a n/a backup.timer backup.service\n",
        );
        let show = "Id=certbot.timer\n\
            Description=Run certbot twice daily\n\
            TimersCalendar={ OnCalendar=*-*-* 00,12:00:00 ; next_elapse=Sat 2026-09-13 00:00:00 UTC }\n\
            NextElapseUSecRealtime=Sat 2026-09-13 00:00:00 UTC\n\
            LastTriggerUSec=Fri 2026-09-12 12:00:03 UTC\n\
            \n\
            Id=backup.timer\n\
            Description=Nightly backup\n\
            TimersMonotonic={ OnUnitActiveUSec=1d ; next_elapse=n/a }\n\
            NextElapseUSecRealtime=n/a\n\
            LastTriggerUSec=n/a\n";

        apply_timer_details(&mut tasks, show);

        assert_eq!(tasks[0].schedule, "*-*-* 00,12:00:00");
        assert_eq!(
            tasks[0].description.as_deref(),
            Some("Run certbot twice daily")
        );
        assert_eq!(
            tasks[0].next_run.as_deref(),
            Some("Sat 2026-09-13 00:00:00 UTC")
        );
        assert_eq!(
            tasks[0].last_run.as_deref(),
            Some("Fri 2026-09-12 12:00:03 UTC")
        );
        assert_eq!(tasks[1].schedule, "OnUnitActiveSec=1d");
        assert_eq!(tasks[1].next_run, None);
    }

    #[test]
    fn scripts_in_the_periodic_folders_are_tasks() {
        let tasks = periodic_scripts(
            "/etc/cron.daily",
            "@daily",
            &[
                "logrotate".into(),
                ".placeholder".into(),
                "backup-2021".into(),
            ],
        );

        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].command, "/etc/cron.daily/backup-2021");
        assert_eq!(tasks[0].schedule, "@daily");
        assert_eq!(tasks[1].user.as_deref(), Some("root"));
    }
}
