use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use daemon_protocol::{
    AdoptedCapability, DiscoveredService, Listener, ServiceKind, ServiceManager, ServiceStatus,
    UnknownListener,
};

use crate::docker::Container;
use crate::listeners::ProcessInfo;
use crate::systemd::Unit;
use crate::webservers::VirtualHost;

pub const KNOWN_THRESHOLD: u8 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub kind: ServiceKind,
    pub label: &'static str,
    pub confidence: u8,
    pub default_port: Option<u16>,
    pub data_dir_flag: Option<&'static str>,
    pub default_data_dir: Option<&'static str>,
}

pub fn signature_for_exe(comm: &str) -> Option<Signature> {
    let name = comm.trim_end_matches(".exe");

    let sig = match name {
        "nginx" => Signature {
            kind: ServiceKind::WebServer,
            label: "nginx",
            confidence: 95,
            default_port: Some(80),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "apache2" | "httpd" => Signature {
            kind: ServiceKind::WebServer,
            label: "apache",
            confidence: 95,
            default_port: Some(80),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "caddy" => Signature {
            kind: ServiceKind::Proxy,
            label: "caddy",
            confidence: 95,
            default_port: Some(443),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "traefik" => Signature {
            kind: ServiceKind::Proxy,
            label: "traefik",
            confidence: 95,
            default_port: Some(443),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "haproxy" => Signature {
            kind: ServiceKind::Proxy,
            label: "haproxy",
            confidence: 95,
            default_port: None,
            data_dir_flag: None,
            default_data_dir: None,
        },
        "postgres" | "postmaster" => Signature {
            kind: ServiceKind::Database,
            label: "postgresql",
            confidence: 95,
            default_port: Some(5432),
            data_dir_flag: Some("-D"),
            default_data_dir: Some("/var/lib/postgresql"),
        },
        "mysqld" => Signature {
            kind: ServiceKind::Database,
            label: "mysql",
            confidence: 95,
            default_port: Some(3306),
            data_dir_flag: Some("--datadir"),
            default_data_dir: Some("/var/lib/mysql"),
        },
        "mariadbd" => Signature {
            kind: ServiceKind::Database,
            label: "mariadb",
            confidence: 95,
            default_port: Some(3306),
            data_dir_flag: Some("--datadir"),
            default_data_dir: Some("/var/lib/mysql"),
        },
        "redis-server" | "valkey-server" => Signature {
            kind: ServiceKind::Cache,
            label: "redis",
            confidence: 95,
            default_port: Some(6379),
            data_dir_flag: None,
            default_data_dir: Some("/var/lib/redis"),
        },
        "memcached" => Signature {
            kind: ServiceKind::Cache,
            label: "memcached",
            confidence: 95,
            default_port: Some(11211),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "mongod" => Signature {
            kind: ServiceKind::Database,
            label: "mongodb",
            confidence: 95,
            default_port: Some(27017),
            data_dir_flag: Some("--dbpath"),
            default_data_dir: Some("/var/lib/mongodb"),
        },
        "node" | "nodejs" | "bun" | "deno" => Signature {
            kind: ServiceKind::Runtime,
            label: "node",
            confidence: 70,
            default_port: None,
            data_dir_flag: None,
            default_data_dir: None,
        },
        "python" | "python3" | "gunicorn" | "uvicorn" => Signature {
            kind: ServiceKind::Runtime,
            label: "python",
            confidence: 70,
            default_port: None,
            data_dir_flag: None,
            default_data_dir: None,
        },
        "php-fpm" | "php-fpm8.2" | "php-fpm8.3" | "php-fpm8.4" | "php" => Signature {
            kind: ServiceKind::Runtime,
            label: "php",
            confidence: 75,
            default_port: None,
            data_dir_flag: None,
            default_data_dir: None,
        },
        "ruby" | "puma" | "unicorn" => Signature {
            kind: ServiceKind::Runtime,
            label: "ruby",
            confidence: 70,
            default_port: None,
            data_dir_flag: None,
            default_data_dir: None,
        },
        "java" => Signature {
            kind: ServiceKind::Runtime,
            label: "java",
            confidence: 60,
            default_port: None,
            data_dir_flag: None,
            default_data_dir: None,
        },
        "dockerd" | "containerd" => Signature {
            kind: ServiceKind::Other,
            label: "docker",
            confidence: 95,
            default_port: None,
            data_dir_flag: None,
            default_data_dir: None,
        },
        "RustDedicated" => Signature {
            kind: ServiceKind::GameServer,
            label: "rust",
            confidence: 95,
            default_port: Some(28015),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "FXServer" => Signature {
            kind: ServiceKind::GameServer,
            label: "fivem",
            confidence: 95,
            default_port: Some(30120),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "valheim_server.x86_64" => Signature {
            kind: ServiceKind::GameServer,
            label: "valheim",
            confidence: 95,
            default_port: Some(2456),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "srcds_linux" | "srcds_run" => Signature {
            kind: ServiceKind::GameServer,
            label: "source",
            confidence: 90,
            default_port: Some(27015),
            data_dir_flag: None,
            default_data_dir: None,
        },
        "ArkAscendedServer.exe" | "ShooterGameServer" => Signature {
            kind: ServiceKind::GameServer,
            label: "ark",
            confidence: 90,
            default_port: Some(7777),
            data_dir_flag: None,
            default_data_dir: None,
        },
        _ => return None,
    };

    Some(sig)
}

pub fn game_jar(cmdline: &[String]) -> Option<(&'static str, u8)> {
    let joined = cmdline.join(" ").to_ascii_lowercase();
    let jars = [
        ("paper", "minecraft (paper)"),
        ("purpur", "minecraft (purpur)"),
        ("spigot", "minecraft (spigot)"),
        ("craftbukkit", "minecraft (bukkit)"),
        ("forge", "minecraft (forge)"),
        ("fabric", "minecraft (fabric)"),
        ("velocity", "minecraft proxy (velocity)"),
        ("bungeecord", "minecraft proxy (bungeecord)"),
        ("waterfall", "minecraft proxy (waterfall)"),
        ("server.jar", "minecraft"),
        ("minecraft_server", "minecraft"),
    ];

    jars.iter()
        .find(|(needle, _)| joined.contains(needle) && joined.contains(".jar"))
        .map(|(_, label)| (*label, 90))
}

pub fn app_fingerprint(dir: &Path) -> Option<(&'static str, Vec<AdoptedCapability>)> {
    let has = |f: &str| dir.join(f).exists();

    if has("artisan") {
        Some((
            "laravel",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else if has("wp-config.php") {
        Some((
            "wordpress",
            vec![AdoptedCapability::Backup, AdoptedCapability::Files],
        ))
    } else if has("manage.py") {
        Some((
            "django",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else if has("Gemfile") {
        Some((
            "rails",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else if has("next.config.js") || has("next.config.mjs") || has("next.config.ts") {
        Some((
            "nextjs",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else if has("package.json") {
        Some((
            "node",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else if has("go.mod") {
        Some((
            "go",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else if has("docker-compose.yml")
        || has("compose.yml")
        || has("docker-compose.yaml")
        || has("compose.yaml")
    {
        Some((
            "compose",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else if has("Dockerfile") {
        Some((
            "dockerfile",
            vec![
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
                AdoptedCapability::Files,
            ],
        ))
    } else {
        None
    }
}

pub fn looks_like_game_volume(dir: &Path) -> bool {
    dir.starts_with("/var/lib/pterodactyl/volumes")
        || dir.join("eula.txt").exists()
        || dir.join("server.properties").exists()
}

pub fn flag_value(cmdline: &[String], flag: &str) -> Option<String> {
    for (i, arg) in cmdline.iter().enumerate() {
        if arg == flag {
            return cmdline.get(i + 1).cloned();
        }
        if let Some(rest) = arg.strip_prefix(flag) {
            let rest = rest.trim_start_matches('=');
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

pub fn capabilities(
    manager: ServiceManager,
    kind: ServiceKind,
    app: Option<&[AdoptedCapability]>,
) -> Vec<AdoptedCapability> {
    let mut caps = vec![AdoptedCapability::Metrics];

    match manager {
        ServiceManager::Systemd | ServiceManager::Docker | ServiceManager::Compose => {
            caps.push(AdoptedCapability::Lifecycle);
            caps.push(AdoptedCapability::Logs);
        }
        ServiceManager::Pm2 | ServiceManager::Supervisor => {
            caps.push(AdoptedCapability::Lifecycle);
            caps.push(AdoptedCapability::Logs);
        }
        ServiceManager::Screen
        | ServiceManager::Manual
        | ServiceManager::Cron
        | ServiceManager::Unknown => {}
    }

    match kind {
        ServiceKind::Database | ServiceKind::Cache => {
            caps.push(AdoptedCapability::Backup);
            caps.push(AdoptedCapability::Config);
        }
        ServiceKind::WebServer | ServiceKind::Proxy => caps.push(AdoptedCapability::Config),
        ServiceKind::GameServer => {
            caps.push(AdoptedCapability::Backup);
            caps.push(AdoptedCapability::Files);
        }
        _ => {}
    }

    if let Some(app) = app {
        caps.extend(app.iter().copied());
    }

    if matches!(manager, ServiceManager::Compose) {
        caps.push(AdoptedCapability::Deploy);
        caps.push(AdoptedCapability::Rollback);
    }

    caps.sort_by_key(|c| format!("{c:?}"));
    caps.dedup();
    caps
}

#[derive(Default)]
pub struct Findings {
    pub listeners: Vec<Listener>,
    pub processes: HashMap<u32, ProcessInfo>,
    pub units: Vec<Unit>,
    pub containers: Vec<Container>,
    pub vhosts: Vec<VirtualHost>,
}

pub struct Classified {
    pub services: Vec<DiscoveredService>,
    pub unknown: Vec<UnknownListener>,
}

pub fn classify(findings: &Findings) -> Classified {
    let mut services: Vec<DiscoveredService> = Vec::new();
    let mut claimed_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut claimed_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();

    for container in &findings.containers {
        let manager = if container.compose_project.is_some() {
            ServiceManager::Compose
        } else {
            ServiceManager::Docker
        };
        let kind = kind_for_image(&container.image);
        let app = container
            .compose_dir
            .as_deref()
            .and_then(|d| app_fingerprint(Path::new(d)));
        let mut details = BTreeMap::new();
        details.insert("image".into(), container.image.clone());
        if let Some(policy) = &container.restart_policy {
            details.insert("restart_policy".into(), policy.clone());
        }
        if container.will_not_survive_reboot() && container.state == "running" {
            details.insert(
                "warning".into(),
                "no restart policy: will not come back after a reboot".into(),
            );
        }
        if let Some(project) = &container.compose_project {
            details.insert("compose_project".into(), project.clone());
        }
        if !container.mounts.is_empty() {
            details.insert("mounts".into(), container.mounts.join(", "));
        }
        if container.mounts.iter().any(|m| {
            m.split(':').next().is_some_and(|source| {
                source.starts_with("/run/wings/") && !Path::new(source).exists()
            })
        }) {
            details.insert("needs_repair".into(), "wings".into());
        }

        for port in &container.ports {
            claimed_ports.insert(*port);
        }

        services.push(DiscoveredService {
            key: format!("docker:{}", container.short_id()),
            name: container.name.clone(),
            kind,
            manager,
            status: match container.state.as_str() {
                "running" => ServiceStatus::Running,
                "restarting" => ServiceStatus::Restarting,
                "exited" | "created" | "paused" => ServiceStatus::Stopped,
                "dead" => ServiceStatus::Failed,
                _ => ServiceStatus::Unknown,
            },
            version: None,
            ports: container.ports.clone(),
            working_dir: container.compose_dir.clone(),
            user: None,
            exec: None,
            config_paths: container
                .compose_dir
                .as_deref()
                .map(|d| vec![format!("{d}/docker-compose.yml")])
                .unwrap_or_default(),
            data_dir: None,
            confidence: 90,
            details,
            capabilities: capabilities(manager, kind, app.as_ref().map(|a| a.1.as_slice())),
            origin: if container.labels.contains_key("com.serveros.managed") {
                daemon_protocol::ServiceOrigin::Created
            } else {
                daemon_protocol::ServiceOrigin::Discovered
            },
        });
    }

    for unit in &findings.units {
        if crate::systemd::is_system_plumbing(&unit.name)
            || !(unit.is_running() || unit.active == "failed" || unit.user_created())
        {
            continue;
        }

        let process = unit.main_pid.and_then(|p| findings.processes.get(&p));
        let comm = process
            .and_then(|p| p.comm().map(str::to_string))
            .or_else(|| {
                unit.exec_start
                    .as_deref()
                    .and_then(|e| e.split_whitespace().next())
                    .map(|e| e.rsplit('/').next().unwrap_or(e).to_string())
            });
        let signature = comm.as_deref().and_then(signature_for_exe);
        let cmdline = process
            .map(|p| p.cmdline.clone())
            .or_else(|| {
                unit.exec_start
                    .as_deref()
                    .map(|e| e.split_whitespace().map(str::to_string).collect())
            })
            .unwrap_or_default();
        let game = game_jar(&cmdline);
        let working_dir = unit
            .working_dir
            .clone()
            .or_else(|| process.and_then(|p| p.cwd.clone()));
        let app = working_dir
            .as_deref()
            .and_then(|d| app_fingerprint(Path::new(d)));
        let is_game_dir = working_dir
            .as_deref()
            .is_some_and(|d| looks_like_game_volume(Path::new(d)));

        let (kind, label, mut confidence) = match (signature, game) {
            (_, Some((label, c))) => (ServiceKind::GameServer, label.to_string(), c),
            (Some(sig), None) if sig.kind == ServiceKind::Runtime && app.is_some() => {
                (ServiceKind::App, app.as_ref().unwrap().0.to_string(), 85)
            }
            (Some(sig), None) => (sig.kind, sig.label.to_string(), sig.confidence),
            (None, None) if is_game_dir => (ServiceKind::GameServer, "game server".into(), 70),
            (None, None) if app.is_some() => {
                (ServiceKind::App, app.as_ref().unwrap().0.to_string(), 75)
            }
            (None, None) => (
                ServiceKind::Other,
                unit.name.trim_end_matches(".service").to_string(),
                if unit.user_created() { 55 } else { 40 },
            ),
        };

        if unit.user_created() {
            confidence = confidence.saturating_add(5).min(100);
        }

        let ports: Vec<u16> = unit
            .main_pid
            .map(|pid| {
                findings
                    .listeners
                    .iter()
                    .filter(|l| {
                        l.pid == Some(pid)
                            || findings
                                .processes
                                .get(&l.pid.unwrap_or(0))
                                .and_then(|p| p.ppid)
                                == Some(pid)
                    })
                    .map(|l| l.port)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        for port in &ports {
            claimed_ports.insert(*port);
        }
        if let Some(pid) = unit.main_pid {
            claimed_pids.insert(pid);
        }

        let data_dir = signature.and_then(|s| {
            s.data_dir_flag
                .and_then(|f| flag_value(&cmdline, f))
                .or_else(|| s.default_data_dir.map(str::to_string))
        });
        let mut details = BTreeMap::new();
        details.insert("unit".into(), unit.name.clone());
        details.insert(
            "origin".into(),
            if unit.user_created() {
                "user-created unit".into()
            } else {
                "distribution package".into()
            },
        );
        if unit.restarts > 0 {
            details.insert("restarts".into(), unit.restarts.to_string());
        }
        if unit.active == "failed" {
            details.insert(
                "pre_existing_failure".into(),
                "unit was failed before ServerOS looked".into(),
            );
        }
        if let Some(vhost) = findings
            .vhosts
            .iter()
            .find(|v| !v.names.is_empty() && kind == ServiceKind::WebServer)
        {
            details.insert(
                "vhosts".into(),
                findings
                    .vhosts
                    .iter()
                    .filter(|v| v.server == vhost.server)
                    .flat_map(|v| v.names.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }

        let mut config_paths: Vec<String> = unit.fragment_path.iter().cloned().collect();
        config_paths.extend(unit.environment_files.iter().cloned());

        services.push(DiscoveredService {
            key: format!("systemd:{}", unit.name),
            name: label,
            kind,
            manager: ServiceManager::Systemd,
            status: if unit.is_running() {
                ServiceStatus::Running
            } else if unit.active == "failed" {
                ServiceStatus::Failed
            } else if unit.sub == "auto-restart" {
                ServiceStatus::Restarting
            } else {
                ServiceStatus::Stopped
            },
            version: None,
            ports,
            working_dir,
            user: unit
                .user
                .clone()
                .or_else(|| process.and_then(|p| p.user.clone())),
            exec: unit.exec_start.clone(),
            config_paths,
            data_dir,
            confidence,
            details,
            capabilities: capabilities(
                ServiceManager::Systemd,
                kind,
                app.as_ref().map(|a| a.1.as_slice()),
            ),
            origin: if unit.name.starts_with("serveros-") {
                daemon_protocol::ServiceOrigin::Created
            } else {
                daemon_protocol::ServiceOrigin::Discovered
            },
        });
    }

    let mut unknown = Vec::new();

    for listener in &findings.listeners {
        if claimed_ports.contains(&listener.port) {
            continue;
        }

        let Some(pid) = listener.pid else {
            unknown.push(UnknownListener {
                port: listener.port,
                exe: None,
                pid: None,
                note: match &listener.user {
                    Some(user) => format!(
                        "listening socket owned by {user}; its process is not visible (the daemon needs CAP_SYS_PTRACE to read /proc for other users)"
                    ),
                    None => "listening socket with no visible owner".into(),
                },
            });
            continue;
        };

        if claimed_pids.contains(&pid) {
            continue;
        }

        let Some(process) = findings.processes.get(&pid) else {
            continue;
        };
        let comm = process.comm().unwrap_or("");
        let signature = signature_for_exe(comm);
        let game = game_jar(&process.cmdline);
        let app = process
            .cwd
            .as_deref()
            .and_then(|d| app_fingerprint(Path::new(d)));
        let attribution = manager_for_process(process, &findings.processes);
        let manager = attribution.manager;
        let deliberately_run = !matches!(manager, ServiceManager::Manual | ServiceManager::Unknown);

        let (kind, label, confidence) = match (signature, game) {
            (_, Some((label, c))) => (ServiceKind::GameServer, label.to_string(), c - 10),
            (Some(sig), None) if sig.kind == ServiceKind::Runtime && app.is_some() => {
                (ServiceKind::App, app.as_ref().unwrap().0.to_string(), 70)
            }
            (Some(sig), None)
                if sig.kind == ServiceKind::Runtime && attribution.label.is_some() =>
            {
                (
                    ServiceKind::App,
                    attribution.label.clone().unwrap_or_default(),
                    70,
                )
            }
            (Some(sig), None) => (
                sig.kind,
                sig.label.to_string(),
                sig.confidence.saturating_sub(15),
            ),
            (None, None) if app.is_some() => {
                (ServiceKind::App, app.as_ref().unwrap().0.to_string(), 60)
            }
            (None, None) if deliberately_run => (
                ServiceKind::Other,
                attribution
                    .label
                    .clone()
                    .unwrap_or_else(|| comm.to_string()),
                KNOWN_THRESHOLD,
            ),
            (None, None) => (ServiceKind::Other, comm.to_string(), 30),
        };

        claimed_pids.insert(pid);

        if confidence < KNOWN_THRESHOLD {
            unknown.push(UnknownListener {
                port: listener.port,
                exe: process.exe.clone(),
                pid: Some(pid),
                note: format!(
                    "unknown service on :{} (binary: {})",
                    listener.port,
                    process.exe.as_deref().unwrap_or(comm)
                ),
            });
            continue;
        }

        let mut details = BTreeMap::new();
        details.insert("manager".into(), format!("{manager:?}").to_lowercase());
        if let Some(label) = &attribution.label {
            details.insert("managed_as".into(), label.clone());
        }
        if process
            .exe
            .as_deref()
            .is_some_and(|e| e.ends_with("(deleted)"))
            || process
                .exe
                .as_deref()
                .is_some_and(|e| !Path::new(e).exists())
        {
            details.insert(
                "warning".into(),
                "binary has been deleted or replaced on disk; a restart may fail".into(),
            );
        }

        services.push(DiscoveredService {
            key: format!("process:{}:{}", comm, listener.port),
            name: label,
            kind,
            manager,
            status: ServiceStatus::Running,
            version: None,
            ports: {
                let mut ports: Vec<u16> = findings
                    .listeners
                    .iter()
                    .filter(|l| l.pid == Some(pid))
                    .map(|l| l.port)
                    .collect();
                ports.sort_unstable();
                ports.dedup();
                ports
            },
            working_dir: process.cwd.clone(),
            user: process.user.clone(),
            exec: Some(process.cmdline_text()),
            config_paths: Vec::new(),
            data_dir: signature.and_then(|s| {
                s.data_dir_flag
                    .and_then(|f| flag_value(&process.cmdline, f))
            }),
            confidence,
            details,
            capabilities: capabilities(manager, kind, app.as_ref().map(|a| a.1.as_slice())),
            origin: daemon_protocol::ServiceOrigin::Discovered,
        });
    }

    services.sort_by(|a, b| a.key.cmp(&b.key));

    Classified { services, unknown }
}

fn kind_for_image(image: &str) -> ServiceKind {
    let name = image
        .split(':')
        .next()
        .unwrap_or(image)
        .rsplit('/')
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase();

    match name.as_str() {
        "postgres" | "mysql" | "mariadb" | "mongo" | "mongodb" => ServiceKind::Database,
        "redis" | "valkey" | "memcached" => ServiceKind::Cache,
        "nginx" | "httpd" | "apache" => ServiceKind::WebServer,
        "caddy" | "traefik" | "haproxy" => ServiceKind::Proxy,
        n if n.contains("minecraft")
            || n.contains("paper")
            || n.contains("rust") && n.contains("server")
            || n.contains("valheim") =>
        {
            ServiceKind::GameServer
        }
        _ => ServiceKind::Container,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Attribution {
    manager: ServiceManager,
    label: Option<String>,
}

fn manager_for_process(process: &ProcessInfo, all: &HashMap<u32, ProcessInfo>) -> Attribution {
    let mut cursor = process.ppid;
    let mut hops = 0;

    while let Some(ppid) = cursor {
        if ppid <= 1 || hops > 8 {
            break;
        }

        if let Some(parent) = all.get(&ppid) {
            let title = parent.cmdline.first().map(String::as_str).unwrap_or("");
            let exe = parent.exe.as_deref().unwrap_or("");
            let comm = parent.comm().unwrap_or("");

            if title.starts_with("PM2") || title.starts_with("pm2") || exe.contains("/pm2/") {
                return Attribution {
                    manager: ServiceManager::Pm2,
                    label: process.pm2_name.clone(),
                };
            }

            match comm {
                "supervisord" => {
                    return Attribution {
                        manager: ServiceManager::Supervisor,
                        label: None,
                    }
                }
                "screen" | "SCREEN" | "tmux" | "tmux:" | "tmux: server" => {
                    return Attribution {
                        manager: ServiceManager::Screen,
                        label: screen_session_name(&parent.cmdline),
                    }
                }
                "cron" | "crond" => {
                    return Attribution {
                        manager: ServiceManager::Cron,
                        label: None,
                    }
                }
                _ => {}
            }
            cursor = parent.ppid;
        } else {
            break;
        }

        hops += 1;
    }

    Attribution {
        manager: ServiceManager::Manual,
        label: None,
    }
}

fn screen_session_name(cmdline: &[String]) -> Option<String> {
    let words: Vec<&str> = cmdline.iter().flat_map(|c| c.split_whitespace()).collect();

    words.windows(2).find_map(|pair| {
        let flag = pair[0];
        (flag.starts_with('-') && !flag.starts_with("--") && flag.ends_with('S'))
            .then(|| pair[1].to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, exe: &str, cmdline: &[&str], ppid: Option<u32>) -> ProcessInfo {
        ProcessInfo {
            pid,
            exe: Some(exe.into()),
            cmdline: cmdline.iter().map(|s| s.to_string()).collect(),
            cwd: None,
            user: Some("app".into()),
            uid: Some(1000),
            ppid,
            kernel_comm: None,
            pm2_name: None,
        }
    }

    #[test]
    fn a_screen_session_names_and_claims_what_runs_inside_it() {
        let mut findings = Findings::default();
        findings.processes.insert(
            94,
            process(
                94,
                "/usr/bin/screen",
                &[
                    "SCREEN",
                    "-dmS",
                    "minecraft",
                    "python3",
                    "-m",
                    "http.server",
                ],
                Some(1),
            ),
        );
        findings.processes.insert(
            97,
            process(
                97,
                "/usr/bin/python3.11",
                &["python3", "-m", "http.server"],
                Some(94),
            ),
        );
        findings.listeners.push(Listener {
            proto: "tcp".into(),
            address: "0.0.0.0".into(),
            port: 25565,
            pid: Some(97),
            exe: None,
            user: None,
            cmdline: None,
        });

        let classified = classify(&findings);
        let game = classified
            .services
            .iter()
            .find(|s| s.ports.contains(&25565))
            .unwrap();

        assert_eq!(game.manager, ServiceManager::Screen);
        assert_eq!(game.name, "minecraft");
        assert_eq!(
            game.details.get("managed_as").map(String::as_str),
            Some("minecraft")
        );
        assert!(classified.unknown.is_empty());
        assert_eq!(
            screen_session_name(&["screen".into(), "-S".into(), "x".into()]),
            Some("x".into())
        );
        assert_eq!(screen_session_name(&["screen".into(), "-r".into()]), None);
    }

    #[test]
    fn a_pm2_app_takes_the_name_pm2_gave_it() {
        let mut findings = Findings::default();
        findings.processes.insert(
            71,
            process(
                71,
                "/usr/bin/node",
                &["PM2 v5.4.3: God Daemon (/root/.pm2)"],
                Some(1),
            ),
        );
        let mut child = process(
            82,
            "/usr/bin/node",
            &["node /srv/shop-api/server.js"],
            Some(71),
        );
        child.pm2_name = Some("shop-api".into());
        findings.processes.insert(82, child);
        findings.listeners.push(Listener {
            proto: "tcp".into(),
            address: "127.0.0.1".into(),
            port: 3000,
            pid: Some(82),
            exe: None,
            user: None,
            cmdline: None,
        });

        let classified = classify(&findings);
        let app = classified
            .services
            .iter()
            .find(|s| s.ports.contains(&3000))
            .unwrap();

        assert_eq!(app.manager, ServiceManager::Pm2);
        assert_eq!(app.kind, ServiceKind::App);
        assert_eq!(app.name, "shop-api");
        assert!(app.confidence >= KNOWN_THRESHOLD);
    }

    #[test]
    fn a_systemd_postgres_gets_backup_but_not_deploy() {
        let mut findings = Findings::default();
        findings.units.push(Unit {
            name: "postgresql.service".into(),
            active: "active".into(),
            sub: "running".into(),
            main_pid: Some(100),
            fragment_path: Some("/lib/systemd/system/postgresql.service".into()),
            ..Default::default()
        });
        findings.processes.insert(
            100,
            process(
                100,
                "/usr/lib/postgresql/16/bin/postgres",
                &["postgres", "-D", "/srv/pgdata"],
                Some(1),
            ),
        );
        findings.listeners.push(Listener {
            proto: "tcp".into(),
            address: "127.0.0.1".into(),
            port: 5432,
            pid: Some(100),
            exe: None,
            user: None,
            cmdline: None,
        });

        let classified = classify(&findings);
        let pg = &classified.services[0];

        assert_eq!(pg.name, "postgresql");
        assert_eq!(pg.kind, ServiceKind::Database);
        assert_eq!(pg.ports, vec![5432]);
        assert_eq!(pg.data_dir.as_deref(), Some("/srv/pgdata"));
        assert!(pg.capabilities.contains(&AdoptedCapability::Backup));
        assert!(pg.capabilities.contains(&AdoptedCapability::Lifecycle));
        assert!(!pg.capabilities.contains(&AdoptedCapability::Deploy));
        assert!(classified.unknown.is_empty());
    }

    #[test]
    fn a_pm2_child_is_attributed_to_pm2_and_an_unknown_binary_is_reported_honestly() {
        let mut findings = Findings::default();
        findings
            .processes
            .insert(1, process(1, "/sbin/init", &["init"], None));
        findings.processes.insert(
            50,
            process(
                50,
                "/usr/lib/node_modules/pm2/lib/God.js",
                &["PM2", "v5"],
                Some(1),
            ),
        );
        findings.processes.insert(
            51,
            process(51, "/usr/bin/node", &["node", "server.js"], Some(50)),
        );
        findings.processes.insert(
            60,
            process(60, "/opt/thing/run", &["/opt/thing/run"], Some(1)),
        );
        findings.listeners.push(Listener {
            proto: "tcp".into(),
            address: "0.0.0.0".into(),
            port: 3000,
            pid: Some(51),
            exe: None,
            user: None,
            cmdline: None,
        });
        findings.listeners.push(Listener {
            proto: "tcp".into(),
            address: "0.0.0.0".into(),
            port: 9000,
            pid: Some(60),
            exe: None,
            user: None,
            cmdline: None,
        });

        let classified = classify(&findings);

        let node = classified
            .services
            .iter()
            .find(|s| s.ports.contains(&3000))
            .unwrap();
        assert_eq!(node.manager, ServiceManager::Pm2);
        assert!(node.capabilities.contains(&AdoptedCapability::Lifecycle));

        assert_eq!(classified.unknown.len(), 1);
        assert_eq!(
            classified.unknown[0].note,
            "unknown service on :9000 (binary: /opt/thing/run)"
        );
    }

    #[test]
    fn compose_containers_get_deploy_and_manual_containers_get_a_reboot_warning() {
        let mut findings = Findings::default();
        findings.containers.push(Container {
            id: "abcdef123456789".into(),
            name: "shop-web-1".into(),
            image: "nginx:1.25".into(),
            state: "running".into(),
            ports: vec![8080],
            restart_policy: Some("no".into()),
            compose_project: Some("shop".into()),
            ..Default::default()
        });
        findings.listeners.push(Listener {
            proto: "tcp".into(),
            address: "0.0.0.0".into(),
            port: 8080,
            pid: None,
            exe: None,
            user: None,
            cmdline: None,
        });

        let classified = classify(&findings);
        let web = &classified.services[0];

        assert_eq!(web.manager, ServiceManager::Compose);
        assert_eq!(web.kind, ServiceKind::WebServer);
        assert!(web.capabilities.contains(&AdoptedCapability::Deploy));
        assert!(web.details["warning"].contains("reboot"));
        assert!(
            classified.unknown.is_empty(),
            "docker's published port is not an unknown listener"
        );
    }

    #[test]
    fn pterodactyl_containers_missing_their_wings_files_need_repair() {
        let dir = tempfile::tempdir().unwrap();
        let mut findings = Findings::default();
        for (id, name, source) in [
            (
                "aaaaaaaaaaaa1",
                "gone-1",
                "/run/wings/machine-id/aaaa".to_string(),
            ),
            ("bbbbbbbbbbbb1", "plain-1", dir.path().display().to_string()),
        ] {
            findings.containers.push(Container {
                id: id.into(),
                name: name.into(),
                image: "ghcr.io/ptero-eggs/yolks:nodejs_22".into(),
                state: "exited".into(),
                mounts: vec![format!("{source}:/etc/machine-id")],
                ..Default::default()
            });
        }

        let classified = classify(&findings);

        assert_eq!(classified.services[0].details["needs_repair"], "wings");
        assert!(!classified.services[1].details.contains_key("needs_repair"));
    }

    #[test]
    fn recognises_a_paper_jar_as_minecraft() {
        assert_eq!(
            game_jar(&[
                "java".into(),
                "-Xmx4G".into(),
                "-jar".into(),
                "paper-1.21.jar".into()
            ]),
            Some(("minecraft (paper)", 90))
        );
        assert_eq!(
            flag_value(&["mysqld".into(), "--datadir=/data".into()], "--datadir").as_deref(),
            Some("/data")
        );
    }
}
