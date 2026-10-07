use std::path::PathBuf;

use daemon_protocol::ServiceKind;
use daemon_services::{ManagedService, RunBy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strategy {
    Postgres {
        user: String,
    },
    Mysql,
    Redis {
        data_dir: PathBuf,
    },
    Files {
        paths: Vec<PathBuf>,
    },
    /// A Postgres in a container, dumped and restored with its own tools
    /// through `docker exec`, so the copy is consistent while it runs.
    PostgresContainer {
        container: String,
        user: String,
    },
    /// MySQL or MariaDB in a container, the same way, as root with the
    /// password the image was started with.
    MysqlContainer {
        container: String,
    },
}

impl Strategy {
    pub fn for_service(service: &ManagedService) -> Option<Self> {
        match (service.name.as_str(), &service.data_dir) {
            ("postgresql", _) => Some(Strategy::Postgres {
                user: "postgres".into(),
            }),
            ("mysql", _) | ("mariadb", _) => Some(Strategy::Mysql),
            ("redis", Some(dir)) => Some(Strategy::Redis {
                data_dir: dir.clone(),
            }),
            _ if !matches!(service_kind(service), ServiceKind::Database) => {
                let paths: Vec<PathBuf> = service
                    .roots
                    .iter()
                    .cloned()
                    .chain(service.data_dir.iter().cloned())
                    .collect();
                (!paths.is_empty()).then_some(Strategy::Files { paths })
            }
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Strategy::Postgres { .. } => "pg_dumpall",
            Strategy::Mysql => "mysqldump",
            Strategy::Redis { .. } => "redis rdb",
            Strategy::Files { .. } => "tar",
            Strategy::PostgresContainer { .. } => "pg_dumpall",
            Strategy::MysqlContainer { .. } => "mysqldump",
        }
    }

    /// How a managed service would be backed up, as the scan reports it: the
    /// strategy's label, or None when there is nothing to copy. Containers go
    /// by their mounts (`backup_paths` of what the scan saw), since the backup
    /// itself inspects them the same way.
    pub fn method_for(
        service: &ManagedService,
        container_mounts: &[&str],
        image: Option<&str>,
    ) -> Option<&'static str> {
        match &service.run_by {
            RunBy::Docker { .. } | RunBy::Compose { .. } => {
                match database_image(image.unwrap_or("")) {
                    Some(DatabaseImage::Postgres) => Some("pg_dumpall"),
                    Some(DatabaseImage::Mysql) => Some("mysqldump"),
                    None => (!backup_paths(container_mounts.iter().copied()).is_empty())
                        .then_some("tar"),
                }
            }
            _ => Self::for_service(service).map(|s| s.label()),
        }
    }

    /// How to copy a container's data: a database's own dump tool when its
    /// image is one, otherwise its mounts. `env` is the container's
    /// environment, for the database user.
    pub fn for_container(
        container: &str,
        image: &str,
        env: &[String],
        mounts: Vec<PathBuf>,
    ) -> Option<Self> {
        match database_image(image) {
            Some(DatabaseImage::Postgres) => Some(Strategy::PostgresContainer {
                container: container.into(),
                user: env
                    .iter()
                    .find_map(|e| e.strip_prefix("POSTGRES_USER="))
                    .filter(|u| !u.is_empty())
                    .unwrap_or("postgres")
                    .into(),
            }),
            Some(DatabaseImage::Mysql) => Some(Strategy::MysqlContainer {
                container: container.into(),
            }),
            None => (!mounts.is_empty()).then_some(Strategy::Files { paths: mounts }),
        }
    }

    pub fn required_tool(&self) -> &'static str {
        match self {
            Strategy::Postgres { .. } => "pg_dumpall",
            Strategy::Mysql => "mysqldump",
            Strategy::Redis { .. } => "redis-cli",
            Strategy::Files { .. } => "tar",
            Strategy::PostgresContainer { .. } | Strategy::MysqlContainer { .. } => "docker",
        }
    }

    pub fn tar_excludes() -> &'static [&'static str] {
        &[
            "node_modules",
            ".cache",
            "vendor/bundle",
            "__pycache__",
            "*.log",
            "storage/framework/cache",
            "storage/logs",
            ".git/objects/pack/*.pack",
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseImage {
    Postgres,
    Mysql,
}

/// Which database an image runs, by its name: postgres, postgis/postgis,
/// timescale/timescaledb, mysql, mariadb, percona…
fn database_image(image: &str) -> Option<DatabaseImage> {
    let name = image
        .rsplit('/')
        .next()
        .unwrap_or(image)
        .split([':', '@'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.starts_with("postgres")
        || name.starts_with("postgis")
        || name.starts_with("timescaledb")
    {
        Some(DatabaseImage::Postgres)
    } else if name.starts_with("mysql")
        || name.starts_with("mariadb")
        || name.starts_with("percona")
    {
        Some(DatabaseImage::Mysql)
    } else {
        None
    }
}

/// A container's mounts worth backing up: host paths, without sockets or
/// the system's own directories.
pub fn backup_paths<'a>(mounts: impl Iterator<Item = &'a str>) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = mounts
        .map(str::trim)
        .filter(|p| p.starts_with('/'))
        .filter(|p| !p.ends_with(".sock"))
        .filter(|p| !["/", "/proc", "/sys", "/dev", "/run", "/var/run", "/etc"].contains(p))
        .map(PathBuf::from)
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

fn service_kind(service: &ManagedService) -> ServiceKind {
    match service.name.as_str() {
        "postgresql" | "mysql" | "mariadb" | "mongodb" => ServiceKind::Database,
        "redis" | "memcached" => ServiceKind::Cache,
        _ => ServiceKind::App,
    }
}

#[cfg(test)]
mod tests {
    use daemon_protocol::ServiceOrigin;
    use daemon_services::RunBy;

    use super::*;

    fn managed(name: &str, data_dir: Option<&str>, roots: &[&str]) -> ManagedService {
        ManagedService {
            key: format!("x:{name}"),
            name: name.into(),
            run_by: RunBy::Systemd {
                unit: format!("{name}.service"),
            },
            origin: ServiceOrigin::Discovered,
            adopted_at: 0,
            capabilities: vec![],
            roots: roots.iter().map(PathBuf::from).collect(),
            config_paths: vec![],
            data_dir: data_dir.map(PathBuf::from),
            added_artifacts: vec![],
        }
    }

    #[test]
    fn reports_how_a_service_would_be_backed_up() {
        assert_eq!(
            Strategy::method_for(&managed("postgresql", None, &[]), &[], None),
            Some("pg_dumpall")
        );
        assert_eq!(
            Strategy::method_for(&managed("docker", None, &[]), &[], None),
            None
        );
        assert_eq!(
            Strategy::method_for(&managed("caddy", None, &[]), &[], None),
            None
        );

        let mut container = managed("shop", None, &[]);
        container.run_by = RunBy::Docker {
            container: "shop-1".into(),
        };
        assert_eq!(
            Strategy::method_for(&container, &["/srv/shop/data"], Some("nginx:1.25")),
            Some("tar")
        );
        assert_eq!(
            Strategy::method_for(&container, &["/var/run/docker.sock", "/etc"], None),
            None
        );
        assert_eq!(Strategy::method_for(&container, &[], None), None);
        assert_eq!(
            Strategy::method_for(&container, &["/v"], Some("postgres:16-alpine")),
            Some("pg_dumpall")
        );
        assert_eq!(
            Strategy::method_for(&container, &[], Some("docker.io/library/mariadb:11")),
            Some("mysqldump")
        );
    }

    #[test]
    fn dumps_database_containers_with_their_own_tools() {
        assert_eq!(
            Strategy::for_container(
                "db-1",
                "postgres:16",
                &["POSTGRES_USER=shop".into()],
                vec![]
            ),
            Some(Strategy::PostgresContainer {
                container: "db-1".into(),
                user: "shop".into()
            })
        );
        assert_eq!(
            Strategy::for_container("db-1", "timescale/timescaledb:latest-pg16", &[], vec![]),
            Some(Strategy::PostgresContainer {
                container: "db-1".into(),
                user: "postgres".into()
            })
        );
        assert_eq!(
            Strategy::for_container("db-1", "mysql:8", &[], vec![]),
            Some(Strategy::MysqlContainer {
                container: "db-1".into()
            })
        );
        assert_eq!(
            Strategy::for_container("web-1", "nginx", &[], vec![PathBuf::from("/srv/www")]),
            Some(Strategy::Files {
                paths: vec![PathBuf::from("/srv/www")]
            })
        );
        assert_eq!(Strategy::for_container("web-1", "nginx", &[], vec![]), None);
    }

    #[test]
    fn picks_native_dumps_for_databases_and_tar_for_apps() {
        assert_eq!(
            Strategy::for_service(&managed("postgresql", None, &[])),
            Some(Strategy::Postgres {
                user: "postgres".into()
            })
        );
        assert_eq!(
            Strategy::for_service(&managed("mariadb", None, &[])),
            Some(Strategy::Mysql)
        );
        assert_eq!(
            Strategy::for_service(&managed("redis", Some("/var/lib/redis"), &[])),
            Some(Strategy::Redis {
                data_dir: "/var/lib/redis".into()
            })
        );
        assert_eq!(
            Strategy::for_service(&managed("laravel", None, &["/srv/app"])),
            Some(Strategy::Files {
                paths: vec!["/srv/app".into()]
            })
        );
        assert_eq!(Strategy::for_service(&managed("mongodb", None, &[])), None);
        assert_eq!(Strategy::for_service(&managed("thing", None, &[])), None);
    }
}
