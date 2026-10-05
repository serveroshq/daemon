use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_inventory::exec;
use daemon_protocol::{DiscoveredService, ServiceKind, ServiceManager};

pub fn known_config_paths(service: &DiscoveredService) -> Vec<PathBuf> {
    let candidates: &[&str] = match service.name.as_str() {
        "postgresql" => &[
            "/etc/postgresql",
            "/var/lib/pgsql/data/postgresql.conf",
            "/var/lib/postgresql/data/postgresql.conf",
        ],
        "mysql" | "mariadb" => &[
            "/etc/mysql/my.cnf",
            "/etc/mysql/mysql.conf.d",
            "/etc/mysql/mariadb.conf.d",
            "/etc/my.cnf",
            "/etc/my.cnf.d",
        ],
        "redis" => &[
            "/etc/redis/redis.conf",
            "/etc/redis.conf",
            "/etc/valkey/valkey.conf",
        ],
        "mongodb" => &["/etc/mongod.conf"],
        "nginx" => &[
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
        ],
        "apache" => &[
            "/etc/apache2/apache2.conf",
            "/etc/apache2/sites-enabled",
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd/conf.d",
        ],
        "caddy" => &["/etc/caddy/Caddyfile"],
        "traefik" => &["/etc/traefik/traefik.yml", "/etc/traefik/traefik.toml"],
        "haproxy" => &["/etc/haproxy/haproxy.cfg"],
        "php" => &["/etc/php"],
        _ => &[],
    };

    let mut paths: Vec<PathBuf> = candidates
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();

    for existing in &service.config_paths {
        let p = PathBuf::from(existing);
        if p.exists() && !paths.contains(&p) {
            paths.push(p);
        }
    }

    if service.manager == ServiceManager::Compose {
        if let Some(dir) = &service.working_dir {
            for name in [
                "docker-compose.yml",
                "docker-compose.yaml",
                "compose.yml",
                "compose.yaml",
            ] {
                let p = Path::new(dir).join(name);
                if p.exists() && !paths.contains(&p) {
                    paths.push(p);
                    break;
                }
            }
        }
    }

    paths
}

fn version_probe(service: &DiscoveredService) -> Option<(&'static str, &'static [&'static str])> {
    Some(match service.name.as_str() {
        "postgresql" => ("postgres", &["--version"]),
        "mysql" => ("mysqld", &["--version"]),
        "mariadb" => ("mariadbd", &["--version"]),
        "redis" => ("redis-server", &["--version"]),
        "mongodb" => ("mongod", &["--version"]),
        "nginx" => ("nginx", &["-v"]),
        "apache" => ("apache2", &["-v"]),
        "caddy" => ("caddy", &["version"]),
        "node" | "nextjs" => ("node", &["--version"]),
        "php" | "laravel" | "wordpress" => ("php", &["--version"]),
        "python" | "django" => ("python3", &["--version"]),
        "ruby" | "rails" => ("ruby", &["--version"]),
        _ => return None,
    })
}

pub async fn detect_version(service: &DiscoveredService) -> Option<String> {
    let (default_program, args) = version_probe(service)?;

    let program: String = service
        .exec
        .as_deref()
        .and_then(|e| e.split_whitespace().next())
        .filter(|p| p.starts_with('/') && Path::new(p).exists())
        .map(str::to_string)
        .unwrap_or_else(|| default_program.to_string());

    let banner = match service.name.as_str() {
        "nginx" | "apache" => exec::output_stderr_ok(&program, args, Duration::from_secs(5)).await,
        _ => exec::output(&program, args, Duration::from_secs(5)).await,
    }?;

    exec::version_from_banner(&banner)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirInfo {
    pub path: PathBuf,
    pub bytes: u64,
    pub mount: PathBuf,
    pub separate_mount: bool,
}

pub fn data_dir_info(path: &Path, mounts: &[PathBuf], max_entries: usize) -> Option<DataDirInfo> {
    if !path.is_dir() {
        return None;
    }

    let bytes = dir_size(path, max_entries);
    let mount = mounts
        .iter()
        .filter(|m| path.starts_with(m))
        .max_by_key(|m| m.as_os_str().len())
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/"));

    Some(DataDirInfo {
        path: path.into(),
        bytes,
        separate_mount: mount != Path::new("/"),
        mount,
    })
}

fn dir_size(path: &Path, max_entries: usize) -> u64 {
    let mut total = 0u64;
    let mut seen = 0usize;
    let mut stack = vec![path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            seen += 1;
            if seen > max_entries {
                return total;
            }

            let Ok(meta) = entry.metadata() else { continue };

            if meta.is_dir() && !entry.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
                stack.push(entry.path());
            } else if meta.is_file() {
                total += meta.len();
            }
        }
    }

    total
}

pub fn warnings(
    service: &DiscoveredService,
    data: Option<&DataDirInfo>,
    previous_owner_of_port: Option<&str>,
) -> Vec<String> {
    let mut notes = Vec::new();

    if let Some(warning) = service.details.get("warning") {
        notes.push(warning.clone());
    }

    if service.details.contains_key("pre_existing_failure") {
        notes.push("this service was already failed before ServerOS looked; it is reported as found, not caused".into());
    }

    if let Some(exec) = &service.exec {
        if let Some(bin) = exec
            .split_whitespace()
            .next()
            .filter(|b| b.starts_with('/'))
        {
            if !Path::new(bin).exists() {
                notes.push(format!("the binary {bin} no longer exists on disk; the running process is fine but a restart would fail"));
            }
        }
    }

    if service.manager == ServiceManager::Manual && service.user.as_deref() == Some("root") {
        notes.push("runs as root with no unit file or supervisor; ServerOS can watch it but cannot restart it safely".into());
    }

    if matches!(service.manager, ServiceManager::Screen) {
        notes.push("runs inside screen or tmux; it will not survive a reboot and ServerOS cannot restart it".into());
    }

    if let Some(previous) = previous_owner_of_port {
        if previous != service.name {
            notes.push(format!(
                "port {} used to belong to {previous}; make sure this is the service you expect",
                service.ports.first().copied().unwrap_or(0)
            ));
        }
    }

    if let Some(data) = data {
        if data.separate_mount {
            notes.push(format!("data lives on a separate mount ({}); backups and disk alerts follow that filesystem", data.mount.display()));
        }
    }

    if service.kind == ServiceKind::Database && service.data_dir.is_none() {
        notes.push(
            "could not find the data directory; backups stay unavailable until it is set".into(),
        );
    }

    if service.confidence < 70 {
        notes.push(format!(
            "identified with {}% confidence; check the name and kind before adopting",
            service.confidence
        ));
    }

    notes
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use daemon_protocol::{ServiceOrigin, ServiceStatus};

    use super::*;

    fn service(name: &str, manager: ServiceManager) -> DiscoveredService {
        DiscoveredService {
            key: format!("x:{name}"),
            name: name.into(),
            kind: ServiceKind::Database,
            manager,
            status: ServiceStatus::Running,
            version: None,
            ports: vec![5432],
            working_dir: None,
            user: Some("root".into()),
            exec: Some("/opt/gone/bin/thing -D /data".into()),
            config_paths: vec![],
            data_dir: None,
            confidence: 95,
            details: BTreeMap::new(),
            capabilities: vec![],
            origin: ServiceOrigin::Discovered,
        }
    }

    #[test]
    fn warnings_cover_the_messy_cases() {
        let notes = warnings(
            &service("thing", ServiceManager::Manual),
            None,
            Some("postgresql"),
        );

        assert!(notes.iter().any(|n| n.contains("no longer exists on disk")));
        assert!(notes
            .iter()
            .any(|n| n.contains("runs as root with no unit file")));
        assert!(notes
            .iter()
            .any(|n| n.contains("used to belong to postgresql")));
        assert!(notes
            .iter()
            .any(|n| n.contains("could not find the data directory")));
    }

    #[test]
    fn data_dir_size_is_bounded_and_mount_aware() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("pgdata");
        std::fs::create_dir_all(data.join("base")).unwrap();
        std::fs::write(data.join("base/1"), vec![0u8; 1000]).unwrap();
        std::fs::write(data.join("base/2"), vec![0u8; 500]).unwrap();

        let info =
            data_dir_info(&data, &[PathBuf::from("/"), dir.path().to_path_buf()], 100).unwrap();

        assert_eq!(info.bytes, 1500);
        assert!(info.separate_mount);
        assert_eq!(info.mount, dir.path());
        assert!(data_dir_info(&data.join("missing"), &[], 100).is_none());
    }

    #[test]
    fn config_paths_only_report_what_exists() {
        let mut svc = service("postgresql", ServiceManager::Systemd);
        svc.config_paths.push("/definitely/not/here.conf".into());

        for path in known_config_paths(&svc) {
            assert!(path.exists());
        }
    }
}
