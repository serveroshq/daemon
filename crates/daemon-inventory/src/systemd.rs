use std::collections::BTreeMap;
use std::time::Duration;

use crate::exec;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Unit {
    pub name: String,
    pub active: String,
    pub sub: String,
    pub description: String,
    pub exec_start: Option<String>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub environment_files: Vec<String>,
    pub fragment_path: Option<String>,
    pub main_pid: Option<u32>,
    pub restarts: u32,
    pub enabled: bool,
}

impl Unit {
    pub fn user_created(&self) -> bool {
        self.fragment_path
            .as_deref()
            .is_some_and(|p| p.starts_with("/etc/systemd/"))
    }

    pub fn is_running(&self) -> bool {
        self.active == "active" && self.sub == "running"
    }
}

pub fn parse_list_units(text: &str) -> Vec<Unit> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;

            if !name.ends_with(".service") {
                return None;
            }

            let _load = parts.next()?;
            let active = parts.next()?;
            let sub = parts.next()?;
            let description = parts.collect::<Vec<_>>().join(" ");

            Some(Unit {
                name: name.into(),
                active: active.into(),
                sub: sub.into(),
                description,
                ..Default::default()
            })
        })
        .collect()
}

pub fn parse_show(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

pub fn exec_start_command(raw: &str) -> Option<String> {
    if let Some(argv) = raw.split("argv[]=").nth(1) {
        let cmd = argv.split(" ; ").next()?.trim();
        return (!cmd.is_empty()).then(|| cmd.to_string());
    }

    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub fn apply_show(unit: &mut Unit, props: &BTreeMap<String, String>) {
    unit.exec_start = props.get("ExecStart").and_then(|v| exec_start_command(v));
    unit.working_dir = props
        .get("WorkingDirectory")
        .filter(|v| !v.is_empty() && *v != "!")
        .cloned();
    unit.user = props.get("User").filter(|v| !v.is_empty()).cloned();
    unit.environment_files = props
        .get("EnvironmentFiles")
        .map(|v| {
            strip_parenthesised(v)
                .split_whitespace()
                .map(|f| f.trim_start_matches('-').to_string())
                .filter(|f| !f.is_empty())
                .collect()
        })
        .unwrap_or_default();
    unit.fragment_path = props.get("FragmentPath").filter(|v| !v.is_empty()).cloned();
    unit.main_pid = props
        .get("MainPID")
        .and_then(|v| v.parse().ok())
        .filter(|p| *p > 0);
    unit.restarts = props
        .get("NRestarts")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    unit.enabled = props
        .get("UnitFileState")
        .is_some_and(|v| v == "enabled" || v == "static" || v == "enabled-runtime");
}

fn strip_parenthesised(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0usize;

    for c in text.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }

    out
}

const SHOW_PROPERTIES: &str = "ExecStart,WorkingDirectory,User,EnvironmentFiles,FragmentPath,MainPID,NRestarts,UnitFileState,ActiveState,SubState";

pub fn is_system_plumbing(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "systemd-",
        "dbus",
        "getty@",
        "serial-getty@",
        "user@",
        "polkit",
        "udisks2",
        "networkd",
        "resolved",
        "rsyslog",
        "cron",
        "snapd",
        "unattended-upgrades",
        "apparmor",
        "ModemManager",
        "NetworkManager",
        "ssh",
        "sshd",
        "serverosd",
    ];

    PREFIXES.iter().any(|p| name.starts_with(p)) || name.starts_with("session-")
}

pub async fn discover(timeout: Duration) -> Option<Vec<Unit>> {
    let listing = exec::output(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        timeout,
    )
    .await?;
    let mut units = parse_list_units(&listing);

    let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
    let mut args = vec!["show", "-p", SHOW_PROPERTIES, "--no-pager"];
    args.extend(names.iter().copied());

    if let Some(shown) = exec::output("systemctl", &args, timeout).await {
        for (unit, block) in units.iter_mut().zip(shown.split("\n\n")) {
            apply_show(unit, &parse_show(block));
        }
    }

    Some(units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_unit_listing() {
        let text = "nginx.service loaded active running A high performance web server\npostgresql@16-main.service loaded active running PostgreSQL Cluster 16-main\nfoo.socket loaded active listening Foo\nbroken.service loaded failed failed My broken thing\n";
        let units = parse_list_units(text);

        assert_eq!(units.len(), 3);
        assert_eq!(units[0].name, "nginx.service");
        assert!(units[0].is_running());
        assert_eq!(units[2].active, "failed");
        assert_eq!(units[1].description, "PostgreSQL Cluster 16-main");
    }

    #[test]
    fn applies_show_properties() {
        let mut unit = Unit {
            name: "app.service".into(),
            ..Default::default()
        };
        let props = parse_show("ExecStart={ path=/usr/bin/node ; argv[]=/usr/bin/node server.js ; ignore_errors=no ; start_time=[n/a] }\nWorkingDirectory=/srv/app\nUser=app\nEnvironmentFiles=/srv/app/.env (ignore_errors=no)\nFragmentPath=/etc/systemd/system/app.service\nMainPID=4242\nNRestarts=3\nUnitFileState=enabled\n");

        apply_show(&mut unit, &props);

        assert_eq!(unit.exec_start.as_deref(), Some("/usr/bin/node server.js"));
        assert_eq!(unit.working_dir.as_deref(), Some("/srv/app"));
        assert_eq!(unit.user.as_deref(), Some("app"));
        assert_eq!(unit.environment_files, vec!["/srv/app/.env"]);
        assert_eq!(unit.main_pid, Some(4242));
        assert_eq!(unit.restarts, 3);
        assert!(unit.enabled);
        assert!(unit.user_created());
    }

    #[test]
    fn distro_units_are_not_user_created() {
        let unit = Unit {
            fragment_path: Some("/lib/systemd/system/nginx.service".into()),
            ..Default::default()
        };

        assert!(!unit.user_created());
        assert!(is_system_plumbing("systemd-journald.service"));
        assert!(!is_system_plumbing("nginx.service"));
    }
}
