//! The web servers running on this machine, found by process name, on the
//! machine itself or inside containers (Docker, Coolify, Dokploy, compose):
//! a container's processes are processes here too. Read-only: this reads
//! /proc, and files inside a container through its process's root.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The servers looked for, by the name their process goes by.
pub const SERVERS: &[&str] = &["nginx", "httpd", "apache2", "caddy", "traefik"];

/// The most processes looked at, so a machine with very many can't slow
/// the daemon down.
const MAX_PROCS: usize = 20_000;
/// The most web servers reported.
const MAX_FOUND: usize = 40;

/// The environment variables kept from a server's process: only the ones
/// that say where its config is. Anything else (secrets, most of all) is
/// never read into memory past this filter.
const ENV_KEYS: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "CADDY_ADMIN",
    "APACHE_LOG_DIR",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebProcess {
    pub pid: u32,
    /// "nginx", "apache", "caddy" or "traefik".
    pub server: String,
    pub args: Vec<String>,
    /// Only `ENV_KEYS`, plus `TRAEFIK_*` for Traefik (its config can be
    /// all environment variables).
    pub env: BTreeMap<String, String>,
    /// The container it runs in, by Docker's 64-character ID.
    pub container_id: Option<String>,
    /// Where its files are as seen from here: `/` on the machine, its
    /// process's root inside a container.
    pub root: PathBuf,
    /// Its working directory, inside its root.
    pub cwd: Option<PathBuf>,
}

impl WebProcess {
    pub fn in_container(&self) -> bool {
        self.root != Path::new("/")
    }

    /// A path inside its root, as seen from here.
    pub fn path(&self, inside: &Path) -> PathBuf {
        rooted(&self.root, inside)
    }

    /// The value of `--name=value`, `--name value` or `-n value`.
    pub fn arg(&self, names: &[&str]) -> Option<String> {
        arg_of(&self.args, names)
    }
}

pub fn arg_of(args: &[String], names: &[&str]) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        for name in names {
            if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
                return Some(value.to_string());
            }
            if arg.eq_ignore_ascii_case(name) {
                return iter.peek().map(|v| v.to_string());
            }
        }
    }
    None
}

/// `inside` (an absolute path in a root) as seen from here.
pub fn rooted(root: &Path, inside: &Path) -> PathBuf {
    if root == Path::new("/") {
        return inside.to_path_buf();
    }
    let relative = inside.strip_prefix("/").unwrap_or(inside);
    root.join(relative)
}

/// What a log path inside a root ends up being once its symlinks are
/// followed inside that root: official images point access logs at the
/// container's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// A file, as seen from here.
    File(PathBuf),
    Stdout,
    Stderr,
}

pub fn resolve_in(root: &Path, inside: &Path) -> Resolved {
    let mut path = inside.to_path_buf();
    for _ in 0..8 {
        match stream_of(&path) {
            Some(1) => return Resolved::Stdout,
            Some(2) => return Resolved::Stderr,
            _ => {}
        }
        let here = rooted(root, &path);
        match std::fs::read_link(&here) {
            Ok(target) => {
                path = if target.is_absolute() {
                    target
                } else {
                    path.parent().unwrap_or(Path::new("/")).join(target)
                };
            }
            Err(_) => return Resolved::File(here),
        }
    }
    Resolved::File(rooted(root, &path))
}

/// 1 or 2 for the paths that mean a process's own output.
fn stream_of(path: &Path) -> Option<u8> {
    match path.to_str()? {
        "/dev/stdout" | "/proc/self/fd/1" | "/dev/fd/1" | "/proc/1/fd/1" => Some(1),
        "/dev/stderr" | "/proc/self/fd/2" | "/dev/fd/2" | "/proc/1/fd/2" => Some(2),
        _ => None,
    }
}

/// Reads a file inside a root, following its symlinks inside that root.
pub fn read_in(root: &Path, inside: &Path) -> Option<String> {
    match resolve_in(root, inside) {
        Resolved::File(path) => std::fs::read_to_string(path).ok(),
        _ => None,
    }
}

/// The files inside a root an include pattern names (`*` in the last part
/// only, as nginx, Apache and Caddy configs use it), in name order, as
/// paths inside the root.
pub fn glob_in(root: &Path, pattern: &Path, budget: &mut usize) -> Vec<PathBuf> {
    let Some(name) = pattern.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let parent = pattern.parent().unwrap_or(Path::new("/"));
    if !name.contains('*') {
        if *budget > 0 && matches!(resolve_in(root, pattern), Resolved::File(ref f) if f.is_file())
        {
            *budget -= 1;
            return vec![pattern.to_path_buf()];
        }
        return Vec::new();
    }
    let (head, tail) = name.split_once('*').unwrap_or((name, ""));
    let dir = match resolve_in(root, parent) {
        Resolved::File(dir) => dir,
        _ => return Vec::new(),
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|f| f.starts_with(head) && f.ends_with(tail) && f.len() >= head.len() + tail.len())
        .collect();
    names.sort();
    let mut found = Vec::new();
    for file in names {
        if *budget == 0 {
            break;
        }
        let inside = parent.join(&file);
        if matches!(resolve_in(root, &inside), Resolved::File(ref f) if f.is_file()) {
            *budget -= 1;
            found.push(inside);
        }
    }
    found
}

/// Every web server process on the machine, one per server and container:
/// the first of its name whose parent isn't one too (nginx's master, not
/// its workers).
pub fn discover() -> Vec<WebProcess> {
    discover_in(Path::new("/proc"))
}

pub fn discover_in(proc_dir: &Path) -> Vec<WebProcess> {
    let Ok(entries) = std::fs::read_dir(proc_dir) else {
        return Vec::new();
    };
    let own_ns = std::fs::read_link(proc_dir.join("self/ns/mnt")).ok();
    let mut found: Vec<WebProcess> = Vec::new();
    let mut seen: Vec<(String, Option<String>, Option<PathBuf>)> = Vec::new();
    let mut pids: Vec<u32> = entries
        .flatten()
        .take(MAX_PROCS)
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    for pid in pids {
        if found.len() >= MAX_FOUND {
            break;
        }
        let dir = proc_dir.join(pid.to_string());
        let Ok(comm) = std::fs::read_to_string(dir.join("comm")) else {
            continue;
        };
        let Some(server) = server_of(comm.trim()) else {
            continue;
        };
        let parent = parent_of(&dir);
        if let Some(parent) = parent {
            let parent_comm =
                std::fs::read_to_string(proc_dir.join(parent.to_string()).join("comm"))
                    .unwrap_or_default();
            if server_of(parent_comm.trim()) == Some(server) {
                continue;
            }
        }
        let args = read_args(&dir.join("cmdline"));
        let ns = std::fs::read_link(dir.join("ns/mnt")).ok();
        // In a container means in another mount namespace than the
        // daemon's; the cgroup says which container, and stands in when
        // the namespaces can't be read.
        let cgroup = container_of(&std::fs::read_to_string(dir.join("cgroup")).unwrap_or_default());
        let in_container = match (&own_ns, &ns) {
            (Some(own), Some(theirs)) => own != theirs,
            _ => cgroup.is_some(),
        };
        let container_id = if in_container { cgroup } else { None };
        let key = (server.to_string(), container_id.clone(), ns.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let root = if in_container {
            dir.join("root")
        } else {
            PathBuf::from("/")
        };
        let cwd = std::fs::read_link(dir.join("cwd")).ok();
        found.push(WebProcess {
            pid,
            server: server.to_string(),
            args,
            env: read_env(&dir.join("environ"), server == "traefik"),
            container_id,
            root,
            cwd,
        });
    }
    found
}

fn server_of(comm: &str) -> Option<&'static str> {
    match comm {
        "nginx" => Some("nginx"),
        "httpd" | "apache2" => Some("apache"),
        "caddy" => Some("caddy"),
        "traefik" => Some("traefik"),
        _ => None,
    }
}

fn parent_of(dir: &Path) -> Option<u32> {
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    // pid (comm) state ppid ...: comm can hold spaces and brackets.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

fn read_args(path: &Path) -> Vec<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    bytes
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .take(200)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

fn read_env(path: &Path, traefik: bool) -> BTreeMap<String, String> {
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeMap::new();
    };
    bytes
        .split(|b| *b == 0)
        .filter_map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            let (key, value) = pair.split_once('=')?;
            let wanted = ENV_KEYS.contains(&key)
                || (traefik
                    && key.starts_with("TRAEFIK_")
                    && (key.contains("ACCESSLOG")
                        || key.starts_with("TRAEFIK_API")
                        || key.starts_with("TRAEFIK_ENTRYPOINTS_TRAEFIK")
                        || key.starts_with("TRAEFIK_PROVIDERS_FILE")));
            wanted.then(|| (key.to_string(), value.to_string()))
        })
        .collect()
}

/// The Docker container ID in a process's cgroup paths: `docker-<id>.scope`
/// (systemd) or `/docker/<id>` (cgroupfs).
pub fn container_of(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        let path = line.rsplit(':').next().unwrap_or(line);
        for part in path.split('/').rev() {
            let id = part
                .strip_prefix("docker-")
                .and_then(|p| p.strip_suffix(".scope"))
                .unwrap_or(part);
            if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_ids_come_from_either_cgroup_layout() {
        let id = "a".repeat(64);
        assert_eq!(
            container_of(&format!("0::/system.slice/docker-{id}.scope\n")),
            Some(id.clone())
        );
        assert_eq!(
            container_of(&format!("12:memory:/docker/{id}\n")),
            Some(id.clone())
        );
        assert_eq!(container_of("0::/system.slice/nginx.service\n"), None);
    }

    #[test]
    fn args_are_read_either_way() {
        let args: Vec<String> = [
            "caddy",
            "run",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter=caddyfile",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            arg_of(&args, &["--config"]).as_deref(),
            Some("/etc/caddy/Caddyfile")
        );
        assert_eq!(arg_of(&args, &["--adapter"]).as_deref(), Some("caddyfile"));
        assert_eq!(arg_of(&args, &["--resume"]), None);
    }

    #[test]
    fn links_to_the_containers_output_are_its_output() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("var/log/nginx")).unwrap();
        std::fs::create_dir_all(root.join("etc/nginx/sites-available")).unwrap();
        std::fs::create_dir_all(root.join("etc/nginx/sites-enabled")).unwrap();
        std::os::unix::fs::symlink("/dev/stdout", root.join("var/log/nginx/access.log")).unwrap();
        std::os::unix::fs::symlink("/dev/stderr", root.join("var/log/nginx/error.log")).unwrap();
        std::fs::write(root.join("etc/nginx/sites-available/shop"), "server {}\n").unwrap();
        // An absolute link, as Debian's sites-enabled has them: followed
        // inside the root, not on the machine.
        std::os::unix::fs::symlink(
            "/etc/nginx/sites-available/shop",
            root.join("etc/nginx/sites-enabled/shop"),
        )
        .unwrap();

        assert_eq!(
            resolve_in(root, Path::new("/var/log/nginx/access.log")),
            Resolved::Stdout
        );
        assert_eq!(
            resolve_in(root, Path::new("/var/log/nginx/error.log")),
            Resolved::Stderr
        );
        assert_eq!(
            read_in(root, Path::new("/etc/nginx/sites-enabled/shop")).as_deref(),
            Some("server {}\n")
        );
        let mut budget = 10;
        assert_eq!(
            glob_in(root, Path::new("/etc/nginx/sites-enabled/*"), &mut budget),
            vec![PathBuf::from("/etc/nginx/sites-enabled/shop")]
        );
        assert_eq!(budget, 9);
    }

    #[test]
    fn finds_masters_not_workers() {
        let dir = tempfile::tempdir().unwrap();
        let proc_dir = dir.path();
        let make = |pid: u32, comm: &str, ppid: u32, cmd: &[&str]| {
            let d = proc_dir.join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
            std::fs::write(d.join("stat"), format!("{pid} ({comm}) S {ppid} 1 1")).unwrap();
            std::fs::write(d.join("cmdline"), cmd.join("\0")).unwrap();
            std::fs::write(d.join("environ"), "HOME=/var/lib/caddy\0SECRET=x\0").unwrap();
            std::fs::write(d.join("cgroup"), "0::/system.slice/x.service\n").unwrap();
        };
        make(10, "nginx", 1, &["nginx: master process /usr/sbin/nginx"]);
        make(11, "nginx", 10, &["nginx: worker process"]);
        make(
            20,
            "caddy",
            1,
            &["/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile"],
        );
        make(30, "bash", 1, &["bash"]);
        let found = discover_in(proc_dir);
        let names: Vec<(&str, u32)> = found.iter().map(|p| (p.server.as_str(), p.pid)).collect();
        assert_eq!(names, vec![("nginx", 10), ("caddy", 20)]);
        assert_eq!(
            found[1].env.get("HOME").map(String::as_str),
            Some("/var/lib/caddy")
        );
        assert!(!found[1].env.contains_key("SECRET"));
        assert!(!found[1].in_container());
    }
}
