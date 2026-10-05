use std::path::PathBuf;

use daemon_protocol::ServiceKind;
use daemon_services::ManagedService;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strategy {
    Postgres { user: String },
    Mysql,
    Redis { data_dir: PathBuf },
    Files { paths: Vec<PathBuf> },
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
        }
    }

    pub fn required_tool(&self) -> &'static str {
        match self {
            Strategy::Postgres { .. } => "pg_dumpall",
            Strategy::Mysql => "mysqldump",
            Strategy::Redis { .. } => "redis-cli",
            Strategy::Files { .. } => "tar",
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
