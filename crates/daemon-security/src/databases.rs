//! Database and cache settings that let anyone in: Postgres trusting
//! connections from the network without a password, Redis or MongoDB
//! listening everywhere with no password, MySQL with its grant tables
//! skipped, Elasticsearch with security off. Whether the port is really
//! open to the internet is the firewall's say; the panel puts both together.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::util::{self, clip};
use crate::Options;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DatabaseIssue {
    /// postgres, redis, mysql, mongodb, elasticsearch or memcached.
    pub service: String,
    pub config: String,
    /// trust_network (no password from the network), trust_local (any local
    /// user can sign in as anyone), cleartext_password, no_password,
    /// no_auth, skip_grant_tables, security_off, udp_on.
    pub issue: String,
    /// The setting as written (never a password).
    pub detail: String,
    /// Listens on every address, not just this machine's own.
    pub listens_everywhere: bool,
}

pub fn gather(options: &Options) -> Vec<DatabaseIssue> {
    let mut out = Vec::new();
    out.extend(postgres(options));
    out.extend(redis(options));
    out.extend(mysql(options));
    out.extend(mongodb(options));
    out.extend(elasticsearch(options));
    out.extend(memcached(options));

    out
}

fn files_in(options: &Options, dirs: &[&str], depth: usize, name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in dirs {
        let mut stack = vec![(options.path(dir), 0)];
        while let Some((path, level)) = stack.pop() {
            for entry in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                let child = entry.path();
                if child.is_dir() && level < depth {
                    stack.push((child, level + 1));
                } else if child.file_name().is_some_and(|n| n == name) {
                    out.push(child);
                }
            }
        }
    }
    out.sort();

    out
}

fn issue(
    options: &Options,
    service: &str,
    path: &Path,
    issue: &str,
    detail: &str,
    everywhere: bool,
) -> DatabaseIssue {
    DatabaseIssue {
        service: service.into(),
        config: options.display(path),
        issue: issue.into(),
        detail: clip(detail.trim(), 200),
        listens_everywhere: everywhere,
    }
}

fn postgres(options: &Options) -> Vec<DatabaseIssue> {
    let mut out = Vec::new();
    for hba in files_in(
        options,
        &["/etc/postgresql", "/var/lib/pgsql", "/var/lib/postgresql"],
        3,
        "pg_hba.conf",
    ) {
        let Some(text) = util::read_limited(&hba, 1024 * 1024) else {
            continue;
        };
        let conf = util::read_limited(&hba.with_file_name("postgresql.conf"), 1024 * 1024)
            .unwrap_or_default();
        let everywhere = postgres_listens_everywhere(&conf);
        for (line, problem) in pg_hba(&text) {
            out.push(issue(options, "postgres", &hba, problem, &line, everywhere));
        }
    }

    out
}

/// `listen_addresses` of `*` or 0.0.0.0 (the default is localhost).
pub fn postgres_listens_everywhere(conf: &str) -> bool {
    conf.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split('#').next()?.trim().strip_prefix("listen_addresses"))
        .filter_map(|rest| {
            rest.trim_start()
                .strip_prefix('=')
                .map(|v| v.trim().trim_matches('\'').to_string())
        })
        .next_back()
        .is_some_and(|v| {
            v.split(',')
                .any(|a| matches!(a.trim(), "*" | "0.0.0.0" | "::"))
        })
}

/// The pg_hba.conf lines that let people in too easily.
pub fn pg_hba(text: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let content = line.split('#').next().unwrap_or("").trim();
        let words: Vec<&str> = content.split_whitespace().collect();
        let Some(kind) = words.first() else {
            continue;
        };
        let (address, method) = match *kind {
            "local" => (None, words.get(3)),
            "host" | "hostssl" | "hostnossl" | "hostgssenc" | "hostnogssenc" => {
                // The address is one word (CIDR) or two (address and mask).
                let address = words.get(3).copied();
                let method = if words.get(4).is_some_and(|w| {
                    w.contains('.') && w.chars().all(|c| c.is_ascii_digit() || c == '.')
                }) {
                    words.get(5)
                } else {
                    words.get(4)
                };
                (address, method)
            }
            _ => continue,
        };
        let Some(method) = method else {
            continue;
        };
        let loopback = address.is_some_and(|a| {
            a.starts_with("127.") || a == "::1/128" || a == "localhost" || a == "::1"
        });
        match (*method, address) {
            ("trust", Some(_)) if !loopback => out.push((content.to_string(), "trust_network")),
            ("trust", None) if words.get(2) == Some(&"all") => {
                out.push((content.to_string(), "trust_local"))
            }
            ("password", Some(_)) if !loopback && *kind != "hostssl" => {
                out.push((content.to_string(), "cleartext_password"))
            }
            _ => {}
        }
    }

    out
}

fn redis(options: &Options) -> Vec<DatabaseIssue> {
    let mut paths = files_in(options, &["/etc/redis"], 1, "redis.conf");
    for name in [
        "/etc/redis.conf",
        "/etc/redis/redis-server.conf",
        "/usr/local/etc/redis.conf",
    ] {
        let path = options.path(name);
        if path.is_file() && !paths.contains(&path) {
            paths.push(path);
        }
    }
    let mut out = Vec::new();
    for path in paths {
        let Some(text) = util::read_limited(&path, 1024 * 1024) else {
            continue;
        };
        let setting = |key: &str| -> Option<String> {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| {
                    let (k, v) = l.split_once(char::is_whitespace)?;
                    k.eq_ignore_ascii_case(key).then(|| v.trim().to_string())
                })
                .next_back()
        };
        // No bind at all listens everywhere; protected mode then refuses
        // outside connections while there's no password.
        let bind = setting("bind");
        let everywhere = bind.as_deref().is_none_or(|b| {
            b.split_whitespace()
                .any(|a| matches!(a.trim_start_matches('-'), "0.0.0.0" | "*" | "::" | "::*"))
        });
        let password = setting("requirepass").is_some_and(|p| !p.trim_matches('"').is_empty())
            || setting("aclfile").is_some()
            || text.lines().any(|l| {
                l.trim_start().starts_with("user default")
                    && !l.contains("nopass")
                    && l.contains('>')
            });
        let protected = setting("protected-mode").is_none_or(|v| v != "no");
        if !password && everywhere && !protected {
            out.push(issue(
                options,
                "redis",
                &path,
                "no_auth",
                &format!(
                    "bind {} with protected-mode no and no requirepass",
                    bind.as_deref().unwrap_or("(everywhere)")
                ),
                true,
            ));
        } else if !password && everywhere {
            out.push(issue(
                options,
                "redis",
                &path,
                "no_password",
                &format!(
                    "bind {} with no requirepass",
                    bind.as_deref().unwrap_or("(everywhere)")
                ),
                true,
            ));
        }
    }

    out
}

fn mysql(options: &Options) -> Vec<DatabaseIssue> {
    let mut paths = Vec::new();
    for dir in ["/etc/mysql", "/etc/my.cnf.d"] {
        let mut stack = vec![(options.path(dir), 0)];
        while let Some((path, level)) = stack.pop() {
            for entry in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                let child = entry.path();
                if child.is_dir() && level < 3 {
                    stack.push((child, level + 1));
                } else if child.extension().is_some_and(|e| e == "cnf") {
                    paths.push(child);
                }
            }
        }
    }
    if options.path("/etc/my.cnf").is_file() {
        paths.push(options.path("/etc/my.cnf"));
    }
    paths.sort();

    let mut out = Vec::new();
    for path in paths {
        let Some(text) = util::read_limited(&path, 1024 * 1024) else {
            continue;
        };
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        {
            let key = line
                .split(['=', ' '])
                .next()
                .unwrap_or("")
                .replace('_', "-");
            if key == "skip-grant-tables" {
                out.push(issue(
                    options,
                    "mysql",
                    &path,
                    "skip_grant_tables",
                    line,
                    false,
                ));
            }
        }
    }

    out
}

fn mongodb(options: &Options) -> Vec<DatabaseIssue> {
    let path = options.path("/etc/mongod.conf");
    let Some(text) = util::read_limited(&path, 1024 * 1024) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .collect();
    let everywhere = lines.iter().any(|l| {
        l.replace(' ', "") == "bindIpAll:true"
            || l.strip_prefix("bindIp:").is_some_and(|v| {
                v.split(',')
                    .any(|a| matches!(a.trim(), "0.0.0.0" | "::" | "*"))
            })
    });
    let auth = lines.iter().any(|l| {
        l.replace(' ', "") == "authorization:enabled"
            || l.replace(' ', "") == "authorization:\"enabled\""
    });
    if everywhere && !auth {
        return vec![issue(
            options,
            "mongodb",
            &path,
            "no_auth",
            "bindIp on every address without security.authorization: enabled",
            true,
        )];
    }

    Vec::new()
}

fn elasticsearch(options: &Options) -> Vec<DatabaseIssue> {
    let path = options.path("/etc/elasticsearch/elasticsearch.yml");
    let Some(text) = util::read_limited(&path, 1024 * 1024) else {
        return Vec::new();
    };
    let value = |key: &str| {
        text.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter_map(|l| {
                l.strip_prefix(key)?
                    .trim_start()
                    .strip_prefix(':')
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
            .next_back()
    };
    let everywhere = value("network.host")
        .is_some_and(|v| matches!(v.as_str(), "0.0.0.0" | "_site_" | "_global_" | "::"));
    if everywhere && value("xpack.security.enabled").as_deref() == Some("false") {
        return vec![issue(
            options,
            "elasticsearch",
            &path,
            "security_off",
            "network.host on every address with xpack.security.enabled: false",
            true,
        )];
    }

    Vec::new()
}

fn memcached(options: &Options) -> Vec<DatabaseIssue> {
    let path = options.path("/etc/memcached.conf");
    let Some(text) = util::read_limited(&path, 256 * 1024) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    let listen = lines
        .iter()
        .find_map(|l| l.strip_prefix("-l").map(|v| v.trim().to_string()));
    let everywhere = listen
        .as_deref()
        .is_none_or(|v| v.split(',').any(|a| matches!(a.trim(), "0.0.0.0" | "::")));
    let udp_off = lines.iter().any(|l| l.replace(' ', "") == "-U0");
    // Old memcached answers UDP by default: a tool for flooding others.
    if everywhere && !udp_off && lines.iter().any(|l| l.starts_with("-U")) {
        return vec![issue(
            options,
            "memcached",
            &path,
            "udp_on",
            "listens on every address with UDP on",
            true,
        )];
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn write(root: &Path, path: &str, text: &str) {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }

    #[test]
    fn reads_pg_hba() {
        let text = "\
local   all             postgres                                peer
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             0.0.0.0/0               trust
host    shop            shop            10.0.0.0 255.0.0.0      password
hostssl all             all             0.0.0.0/0               password
host    all             all             ::/0                    scram-sha-256
";
        let found: Vec<&str> = pg_hba(text).into_iter().map(|(_, p)| p).collect();
        assert_eq!(
            found,
            vec!["trust_local", "trust_network", "cleartext_password"]
        );
        assert!(postgres_listens_everywhere(
            "#listen_addresses = 'localhost'\nlisten_addresses = '*'  # all\n"
        ));
        assert!(!postgres_listens_everywhere(
            "listen_addresses = 'localhost'\n"
        ));
        assert!(!postgres_listens_everywhere(""));
    }

    #[test]
    fn finds_open_databases() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "/etc/postgresql/16/main/pg_hba.conf",
            "host all all 0.0.0.0/0 trust\n",
        );
        write(
            root,
            "/etc/postgresql/16/main/postgresql.conf",
            "listen_addresses = '*'\n",
        );
        write(
            root,
            "/etc/redis/redis.conf",
            "bind 0.0.0.0\nprotected-mode no\n# requirepass foobared\n",
        );
        write(
            root,
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "[mysqld]\nskip-grant-tables\nbind-address = 0.0.0.0\n",
        );
        write(
            root,
            "/etc/mongod.conf",
            "net:\n  port: 27017\n  bindIp: 0.0.0.0\n",
        );
        write(
            root,
            "/etc/elasticsearch/elasticsearch.yml",
            "network.host: 0.0.0.0\nxpack.security.enabled: false\n",
        );

        let options = Options {
            root: root.to_path_buf(),
            proc: root.join("proc"),
            docker_socket: None,
            apps_dir: None,
            commands: false,
            budget: Duration::from_secs(5),
        };
        let found: Vec<(String, String, bool)> = gather(&options)
            .into_iter()
            .map(|i| (i.service, i.issue, i.listens_everywhere))
            .collect();
        assert_eq!(
            found,
            vec![
                ("postgres".into(), "trust_network".into(), true),
                ("redis".into(), "no_auth".into(), true),
                ("mysql".into(), "skip_grant_tables".into(), false),
                ("mongodb".into(), "no_auth".into(), true),
                ("elasticsearch".into(), "security_off".into(), true),
            ]
        );
    }

    #[test]
    fn a_password_or_local_bind_is_fine() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "/etc/redis/redis.conf",
            "bind 127.0.0.1 -::1\nprotected-mode yes\n",
        );
        write(
            root,
            "/etc/mongod.conf",
            "net:\n  bindIp: 0.0.0.0\nsecurity:\n  authorization: enabled\n",
        );
        let options = Options {
            root: root.to_path_buf(),
            proc: root.join("proc"),
            docker_socket: None,
            apps_dir: None,
            commands: false,
            budget: Duration::from_secs(5),
        };
        assert!(gather(&options).is_empty());
    }
}
