//! Language runtimes and servers, by version, so the panel can say which
//! no longer get security fixes (PHP 7.4, Node 16, Python 2, Postgres 11).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;

use crate::util;
use crate::Options;

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Runtime {
    /// node, php, python, ruby, nginx, apache, openssl, openssh, postgres,
    /// mysql, mariadb, redis.
    pub name: String,
    pub version: String,
    pub path: String,
}

/// (name, binaries to try, arguments).
const KNOWN: &[(&str, &[&str], &[&str])] = &[
    (
        "node",
        &["/usr/bin/node", "/usr/local/bin/node"],
        &["--version"],
    ),
    (
        "python",
        &["/usr/bin/python3", "/usr/local/bin/python3"],
        &["--version"],
    ),
    (
        "python",
        &["/usr/bin/python2", "/usr/bin/python2.7"],
        &["--version"],
    ),
    (
        "ruby",
        &["/usr/bin/ruby", "/usr/local/bin/ruby"],
        &["--version"],
    ),
    (
        "nginx",
        &["/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx"],
        &["-v"],
    ),
    ("apache", &["/usr/sbin/apache2", "/usr/sbin/httpd"], &["-v"]),
    ("openssl", &["/usr/bin/openssl"], &["version"]),
    ("openssh", &["/usr/bin/ssh"], &["-V"]),
    (
        "redis",
        &["/usr/bin/redis-server", "/usr/local/bin/redis-server"],
        &["--version"],
    ),
    (
        "mysql",
        &["/usr/sbin/mysqld", "/usr/sbin/mariadbd"],
        &["--version"],
    ),
];

pub fn gather(options: &Options) -> Vec<Runtime> {
    if !options.commands {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for (name, binaries, args) in KNOWN {
        let Some(binary) = binaries.iter().find(|b| options.path(b).is_file()) else {
            continue;
        };
        if let Some(runtime) = version_of(name, binary, args) {
            if seen.insert((runtime.name.clone(), runtime.version.clone())) {
                out.push(runtime);
            }
        }
    }

    // Every PHP installed side by side (php7.4, php8.1), and every Postgres.
    let mut extra: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(options.path("/usr/bin"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let file = entry.file_name().to_string_lossy().into_owned();
        if file == "php" || is_versioned_php(&file) {
            extra.push(("php".into(), format!("/usr/bin/{file}")));
        }
    }
    for entry in std::fs::read_dir(options.path("/usr/lib/postgresql"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let bin = format!(
            "/usr/lib/postgresql/{}/bin/postgres",
            entry.file_name().to_string_lossy()
        );
        if options.path(&bin).is_file() {
            extra.push(("postgres".into(), bin));
        }
    }
    extra.sort();
    for (name, binary) in extra {
        if let Some(runtime) = version_of(&name, &binary, &["--version"]) {
            if seen.insert((runtime.name.clone(), runtime.version.clone())) {
                out.push(runtime);
            }
        }
    }

    out
}

fn is_versioned_php(file: &str) -> bool {
    file.strip_prefix("php")
        .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn version_of(name: &str, binary: &str, args: &[&str]) -> Option<Runtime> {
    let out = util::run(binary, args, TIMEOUT)?;
    // The line naming the program (nginx prints only to stderr, where the
    // loader's own complaints can come first), else the first with a version.
    let line = out
        .lines()
        .find(|l| l.to_ascii_lowercase().contains(name) && parse_version(l).is_some())
        .or_else(|| out.lines().find(|l| parse_version(l).is_some()))?;
    // MariaDB's mysqld says "Ver 10.11.6-MariaDB".
    let name = if name == "mysql" && line.contains("MariaDB") {
        "mariadb"
    } else {
        name
    };

    Some(Runtime {
        name: name.to_string(),
        version: parse_version(line)?,
        path: binary.to_string(),
    })
}

/// The first dotted version in a line: "v18.19.0" → "18.19.0",
/// "OpenSSH_9.6p1 Ubuntu" → "9.6p1", "nginx version: nginx/1.24.0" → "1.24.0".
pub fn parse_version(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit()
            && (i == 0
                || !bytes[i - 1].is_ascii_alphanumeric()
                || bytes[i - 1] == b'v'
                || bytes[i - 1] == b'_')
        {
            let start = i;
            let mut end = i;
            let mut dots = 0;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'.') {
                if bytes[end] == b'.' {
                    dots += 1;
                }
                end += 1;
            }
            let version = line[start..end].trim_end_matches('.');
            if dots >= 1 {
                return Some(version.to_string());
            }
            i = end;
        }
        i += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_versions_from_banners() {
        for (line, want) in [
            ("v18.19.0", "18.19.0"),
            ("Python 3.11.2", "3.11.2"),
            ("PHP 8.1.2-1ubuntu2.14 (cli) (built: Aug 18 2023)", "8.1.2"),
            ("nginx version: nginx/1.24.0 (Ubuntu)", "1.24.0"),
            (
                "OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 30 Jan 2024",
                "9.6p1",
            ),
            (
                "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)",
                "3.0.13",
            ),
            (
                "Redis server v=7.0.15 sha=00000000:0 malloc=jemalloc-5.3.0",
                "7.0.15",
            ),
            (
                "postgres (PostgreSQL) 16.4 (Ubuntu 16.4-0ubuntu0.24.04.2)",
                "16.4",
            ),
            (
                "/usr/sbin/mysqld  Ver 8.0.39-0ubuntu0.22.04.1 for Linux",
                "8.0.39",
            ),
            (
                "ruby 3.0.2p107 (2021-07-07 revision 0db68f0233)",
                "3.0.2p107",
            ),
            ("Server version: Apache/2.4.58 (Ubuntu)", "2.4.58"),
        ] {
            assert_eq!(parse_version(line).as_deref(), Some(want), "{line}");
        }
        assert_eq!(parse_version("no version here 42"), None);
    }

    #[test]
    fn spots_side_by_side_php() {
        assert!(is_versioned_php("php7.4"));
        assert!(is_versioned_php("php8.3"));
        assert!(!is_versioned_php("php-fpm"));
        assert!(!is_versioned_php("phpize8.1"));
        assert!(!is_versioned_php("php"));
    }
}
