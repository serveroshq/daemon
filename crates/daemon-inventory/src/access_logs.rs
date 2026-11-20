//! Where the sites nginx and Apache already serve write their access logs,
//! as their own configs say: each server block's or VirtualHost's
//! `access_log` / `CustomLog`, or the one it inherits from the http block or
//! the main server, and the line format of each file. The same for a server
//! running in a container, read through its process's root, where a log
//! that points at the container's output is read from the container's
//! logs. Caddy and Traefik sites (see `caddy`, `traefik`) are described the
//! same way. Read-only: this only reads config files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::procs::{glob_in, read_in, resolve_in, Resolved};
use crate::webservers::{nginx_statements, NginxItem};

/// nginx's built-in format, used when an `access_log` names none.
pub const NGINX_COMBINED: &str = "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

/// The formats Apache configs usually define, for a CustomLog that names
/// one the config never defines (it's always defined in practice).
const APACHE_DEFAULTS: &[(&str, &str)] = &[
    (
        "combined",
        "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"",
    ),
    ("common", "%h %l %u %t \"%r\" %>s %O"),
    (
        "vhost_combined",
        "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"",
    ),
];

const MAX_FILES: usize = 400;

/// One site's server block (nginx), VirtualHost (Apache), route (Caddy) or
/// router (Traefik), as far as its access logs go.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VhostLogs {
    /// "nginx", "apache", "caddy" or "traefik".
    pub server: String,
    pub names: Vec<String>,
    /// The file the block is in.
    pub config_path: String,
    /// Which block of that file it is, counting from 0.
    pub block: usize,
    pub listen: Vec<u16>,
    pub default_server: bool,
    /// Local ports it proxies to (`proxy_pass http://127.0.0.1:3000`).
    pub upstream_ports: Vec<u16>,
    /// The files it writes, each with its line format. Logs that can't be
    /// read as a file (syslog, pipes, compressed, paths with variables)
    /// are left out.
    pub logs: Vec<LogFile>,
    /// The block names no log of its own, so `logs` are the ones it
    /// inherits from the http block (nginx) or the main server (Apache).
    pub inherited: bool,
    /// The container the server runs in, when it runs in one.
    pub container: Option<Container>,
    /// It answers every host no other site does.
    pub catch_all: bool,
    /// The folders it serves files from.
    pub roots: Vec<String>,
    /// Local sockets it passes requests on to (php-fpm's).
    pub sockets: Vec<String>,
    /// Why it has no log that can be read: "off" or "elsewhere".
    pub unlogged: Option<String>,
    /// Its config is a file on this machine that ServerOS could change on
    /// request.
    pub editable: bool,
    /// Traefik: its routers' full names (`shop@docker`).
    pub routers: Vec<String>,
    /// Containers it passes requests on to, by name (Traefik's labels).
    pub upstream_containers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Container {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFile {
    /// As its config names it (inside the container, for one).
    pub path: PathBuf,
    /// The log line template: an nginx `log_format` or Apache `LogFormat`,
    /// or for Caddy and Traefik one of the `FORMAT_*` names.
    pub format: String,
    /// The format's name in the config, when it has one (`combined`).
    pub format_name: Option<String>,
    /// Where its lines are read from.
    pub target: LogTarget,
}

impl LogFile {
    /// A file on this machine, at the path its config names.
    pub fn file(path: impl Into<PathBuf>, format: &str, format_name: Option<&str>) -> Self {
        let path = path.into();
        Self {
            target: LogTarget::File(path.clone()),
            path,
            format: format.to_string(),
            format_name: format_name.map(str::to_string),
        }
    }
}

/// Where a log's lines can be read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogTarget {
    /// A file, as seen from the machine.
    File(PathBuf),
    /// A container's output, as Docker keeps it.
    Container { id: String, stderr: bool },
}

/// Caddy's JSON access log lines, and its console ones (a JSON object after
/// tab-separated time, level and logger).
pub const FORMAT_CADDY: &str = "@caddy-json";
pub const FORMAT_CADDY_CONSOLE: &str = "@caddy-console";
/// Traefik's JSON access log, and its default common one.
pub const FORMAT_TRAEFIK: &str = "@traefik-json";
pub const FORMAT_TRAEFIK_COMMON: &str = "@traefik-common";

/// Where to look. The real paths in production; folders in tests.
#[derive(Debug, Clone)]
pub struct Paths {
    pub nginx_confs: Vec<(PathBuf, PathBuf)>,
    pub apache_confs: Vec<(PathBuf, PathBuf)>,
    pub apache_envvars: PathBuf,
    /// Where these paths are, as seen from here: `/`, or a container's
    /// process's root.
    pub root: PathBuf,
    pub container: Option<Container>,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            nginx_confs: vec![
                ("/etc/nginx/nginx.conf".into(), "/etc/nginx".into()),
                (
                    "/usr/local/nginx/conf/nginx.conf".into(),
                    "/usr/local/nginx".into(),
                ),
            ],
            apache_confs: vec![
                ("/etc/apache2/apache2.conf".into(), "/etc/apache2".into()),
                ("/etc/httpd/conf/httpd.conf".into(), "/etc/httpd".into()),
            ],
            apache_envvars: "/etc/apache2/envvars".into(),
            root: "/".into(),
            container: None,
        }
    }
}

impl Paths {
    /// Where nginx and Apache usually keep their config in a container
    /// (official images, Debian and Alpine based ones), seen through its
    /// root. `config` is the file its command line names, when it does.
    pub fn in_container(
        root: PathBuf,
        container: Container,
        server: &str,
        config: Option<PathBuf>,
    ) -> Self {
        let mut paths = Self {
            root,
            container: Some(container),
            ..Self::default()
        };
        paths.apache_confs.insert(
            0,
            (
                "/usr/local/apache2/conf/httpd.conf".into(),
                "/usr/local/apache2".into(),
            ),
        );
        if let Some(config) = config {
            let prefix = config
                .parent()
                .map(|p| {
                    if server == "apache" && p.ends_with("conf") {
                        p.parent().unwrap_or(p).to_path_buf()
                    } else {
                        p.to_path_buf()
                    }
                })
                .unwrap_or_else(|| PathBuf::from("/"));
            let list = if server == "nginx" {
                &mut paths.nginx_confs
            } else {
                &mut paths.apache_confs
            };
            list.insert(0, (config, prefix));
        }
        if server == "nginx" {
            paths.apache_confs.clear();
        } else {
            paths.nginx_confs.clear();
        }
        paths
    }
}

/// Every nginx server block and Apache VirtualHost on the machine with the
/// logs it writes.
pub fn discover() -> Vec<VhostLogs> {
    discover_in(&Paths::default())
}

pub fn discover_in(paths: &Paths) -> Vec<VhostLogs> {
    let mut found = Vec::new();
    let root = paths.root.as_path();
    for (conf, prefix) in &paths.nginx_confs {
        if let Some(text) = read_in(root, conf) {
            found.extend(nginx(&text, conf, prefix, paths));
            break;
        }
    }
    for (conf, server_root) in &paths.apache_confs {
        if let Some(text) = read_in(root, conf) {
            let env = apache_envvars(read_in(root, &paths.apache_envvars));
            found.extend(apache(&text, conf, server_root, &env, paths));
            break;
        }
    }
    let editable = paths.container.is_none();
    for host in &mut found {
        host.container = paths.container.clone();
        host.editable = editable;
    }
    found
}

/// Where a log's lines can be read, from the path its config names, and
/// None when they can't (a host server's own output goes to the journal).
pub fn target_of(paths: &Paths, path: &Path) -> Option<LogTarget> {
    match (resolve_in(&paths.root, path), &paths.container) {
        (Resolved::File(file), _) => Some(LogTarget::File(file)),
        (Resolved::Stdout, Some(c)) => Some(LogTarget::Container {
            id: c.id.clone(),
            stderr: false,
        }),
        (Resolved::Stderr, Some(c)) => Some(LogTarget::Container {
            id: c.id.clone(),
            stderr: true,
        }),
        (_, None) => None,
    }
}

#[derive(Debug, Clone)]
enum RawLog {
    Off,
    /// Somewhere that can't be read: syslog, memory, a compressed file.
    Elsewhere,
    File {
        path: String,
        format: String,
    },
}

fn nginx_access_log(args: &[String]) -> Option<RawLog> {
    let first = args.first()?;
    if first == "off" {
        return Some(RawLog::Off);
    }
    let unreadable = first.starts_with("syslog:")
        || first.starts_with("memory:")
        || first.contains('$')
        || args.iter().skip(1).any(|a| a.starts_with("gzip"));
    if unreadable {
        return Some(RawLog::Elsewhere);
    }
    let format = args
        .get(1)
        .filter(|a| !a.contains('='))
        .cloned()
        .unwrap_or_else(|| "combined".into());
    Some(RawLog::File {
        path: first.clone(),
        format,
    })
}

#[derive(Default)]
struct Server {
    host: VhostLogs,
    own: Vec<RawLog>,
    nested: Vec<RawLog>,
}

#[derive(Default)]
struct NginxWalk {
    root: PathBuf,
    budget: usize,
    formats: HashMap<String, String>,
    http: Vec<RawLog>,
    servers: Vec<Server>,
    blocks_in_file: HashMap<String, usize>,
}

impl NginxWalk {
    fn walk(&mut self, text: &str, path: &str, prefix: &Path, stack: &mut Vec<String>) {
        // Index of the open server in `servers`, and the stack depth it opened at.
        let mut open: Option<(usize, usize)> = None;
        for item in nginx_statements(text) {
            match item {
                NginxItem::Open(name) => {
                    stack.push(name.clone());
                    let in_http = stack.len() >= 2 && stack[stack.len() - 2] == "http";
                    if name == "server" && in_http && open.is_none() {
                        let block = self.blocks_in_file.entry(path.to_string()).or_default();
                        self.servers.push(Server {
                            host: VhostLogs {
                                server: "nginx".into(),
                                config_path: path.into(),
                                block: *block,
                                ..Default::default()
                            },
                            ..Default::default()
                        });
                        *block += 1;
                        open = Some((self.servers.len() - 1, stack.len()));
                    }
                }
                NginxItem::Close => {
                    if open.is_some_and(|(_, depth)| depth == stack.len()) {
                        open = None;
                    }
                    stack.pop();
                }
                NginxItem::Directive(name, args) => {
                    self.directive(&name, &args, prefix, stack, open);
                }
            }
        }
    }

    fn directive(
        &mut self,
        name: &str,
        args: &[String],
        prefix: &Path,
        stack: &mut Vec<String>,
        open: Option<(usize, usize)>,
    ) {
        match name {
            "include" => {
                for pattern in args {
                    let pattern = resolve(prefix, pattern);
                    for file in glob_in(&self.root, &pattern, &mut self.budget) {
                        let Some(inner) = read_in(&self.root, &file) else {
                            continue;
                        };
                        match open {
                            // Directives included into a server block belong to it.
                            Some((index, depth)) => {
                                let mut nested = 0usize;
                                for item in nginx_statements(&inner) {
                                    match item {
                                        NginxItem::Open(_) => nested += 1,
                                        NginxItem::Close => nested = nested.saturating_sub(1),
                                        NginxItem::Directive(name, args) => {
                                            let at = if nested == 0 && stack.len() == depth {
                                                Some((index, depth))
                                            } else {
                                                Some((index, usize::MAX))
                                            };
                                            if name != "include" {
                                                self.directive(&name, &args, prefix, stack, at);
                                            }
                                        }
                                    }
                                }
                            }
                            None => self.walk(&inner, &file.to_string_lossy(), prefix, stack),
                        }
                    }
                }
            }
            "log_format" => {
                if let Some((format_name, parts)) = args.split_first() {
                    let text: String = parts
                        .iter()
                        .filter(|p| !p.starts_with("escape="))
                        .map(String::as_str)
                        .collect();
                    self.formats.insert(format_name.clone(), text);
                }
            }
            "access_log" => {
                let Some(log) = nginx_access_log(args) else {
                    return;
                };
                match open {
                    Some((index, depth)) if depth == stack.len() => {
                        self.servers[index].own.push(log)
                    }
                    Some((index, _)) => {
                        if matches!(log, RawLog::File { .. }) {
                            self.servers[index].nested.push(log);
                        }
                    }
                    None if stack.last().map(String::as_str) == Some("http") => self.http.push(log),
                    None => {}
                }
            }
            _ => {
                let Some((index, _)) = open else { return };
                let host = &mut self.servers[index].host;
                match name {
                    "root" => {
                        if let Some(root) = args.first().filter(|r| !r.contains('$')) {
                            if !host.roots.contains(root) {
                                host.roots.push(root.clone());
                            }
                        }
                    }
                    "server_name" => {
                        for a in args {
                            if a != "_" && !a.is_empty() && !host.names.contains(a) {
                                host.names.push(a.to_ascii_lowercase());
                            }
                        }
                    }
                    "listen" => {
                        if let Some(port) = args
                            .first()
                            .and_then(|a| a.rsplit(':').next())
                            .and_then(|p| p.trim_start_matches('[').parse().ok())
                        {
                            if !host.listen.contains(&port) {
                                host.listen.push(port);
                            }
                        }
                        if args.iter().any(|a| a == "default_server" || a == "default") {
                            host.default_server = true;
                        }
                    }
                    "proxy_pass" | "fastcgi_pass" | "uwsgi_pass" | "grpc_pass" => {
                        let Some(target) = args.first() else { return };
                        if let Some(port) = local_port(target) {
                            if !host.upstream_ports.contains(&port) {
                                host.upstream_ports.push(port);
                            }
                        } else if let Some(socket) = unix_socket(target) {
                            if !host.sockets.contains(&socket) {
                                host.sockets.push(socket);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The port of a local upstream: `http://127.0.0.1:3000/`, `localhost:8080`.
fn local_port(target: &str) -> Option<u16> {
    let rest = target.split_once("://").map_or(target, |(_, r)| r);
    let authority = rest.split('/').next()?;
    let (host, port) = authority.rsplit_once(':')?;
    let host = host.trim_matches(['[', ']']);
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "0.0.0.0")
        .then(|| port.parse().ok())
        .flatten()
}

/// The path of a unix socket upstream: `unix:/run/php/php8.3-fpm.sock`,
/// `http://unix:/run/app.sock:/`, Apache's `unix:/run/php.sock|fcgi://x`,
/// Caddy's `unix//run/php.sock`.
pub fn unix_socket(target: &str) -> Option<String> {
    let at = target
        .find("unix:")
        .map(|i| i + 5)
        .or_else(|| target.strip_prefix("unix/").map(|_| 5))?;
    let rest = &target[at..];
    let path: String = rest
        .split(['|', ' '])
        .next()?
        .split(":/")
        .next()?
        .trim_end_matches(':')
        .to_string();
    (path.starts_with('/') && path.len() > 1).then_some(path)
}

fn resolve(base: &Path, path: &str) -> PathBuf {
    if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        base.join(path)
    }
}

fn nginx(text: &str, conf: &Path, prefix: &Path, paths: &Paths) -> Vec<VhostLogs> {
    let mut walk = NginxWalk {
        root: paths.root.clone(),
        budget: MAX_FILES,
        ..Default::default()
    };
    walk.walk(text, &conf.to_string_lossy(), prefix, &mut Vec::new());

    let format_of = |name: &str| -> Option<String> {
        walk.formats
            .get(name)
            .cloned()
            .or_else(|| (name == "combined").then(|| NGINX_COMBINED.to_string()))
    };
    let files = |logs: &[RawLog]| -> Vec<LogFile> {
        if logs.iter().any(|l| matches!(l, RawLog::Off)) {
            return Vec::new();
        }
        logs.iter()
            .filter_map(|log| match log {
                RawLog::File { path, format } => {
                    let path = resolve(prefix, path);
                    Some(LogFile {
                        target: target_of(paths, &path)?,
                        path,
                        format: format_of(format)?,
                        format_name: Some(format.clone()),
                    })
                }
                RawLog::Off | RawLog::Elsewhere => None,
            })
            .collect()
    };
    let why = |logs: &[RawLog]| -> &'static str {
        if logs.is_empty() || logs.iter().any(|l| matches!(l, RawLog::Off)) {
            "off"
        } else {
            "elsewhere"
        }
    };
    // With no access_log at all, nginx writes its built-in log.
    let http = if walk.http.is_empty() {
        vec![RawLog::File {
            path: "/var/log/nginx/access.log".into(),
            format: "combined".into(),
        }]
    } else {
        walk.http.clone()
    };

    walk.servers
        .iter()
        .map(|server| {
            let inherited = server.own.is_empty();
            let mut host = server.host.clone();
            host.logs = files(if inherited { &http } else { &server.own });
            for log in files(&server.nested) {
                if !host.logs.contains(&log) {
                    host.logs.push(log);
                }
            }
            host.inherited = inherited;
            if host.logs.is_empty() {
                host.unlogged = Some(why(if inherited { &http } else { &server.own }).to_string());
            }
            host
        })
        .collect()
}

/// The variables Debian's apache2ctl sets from /etc/apache2/envvars
/// (`APACHE_LOG_DIR` most of all).
fn apache_envvars(text: Option<String>) -> HashMap<String, String> {
    let mut env = HashMap::from([("APACHE_LOG_DIR".to_string(), "/var/log/apache2".to_string())]);
    let Some(text) = text else {
        return env;
    };
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("export ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        // `$SUFFIX` is empty unless apache2ctl runs as a second instance.
        let value = value
            .trim()
            .trim_matches(['"', '\''])
            .replace("$SUFFIX", "")
            .replace("${SUFFIX}", "");
        if !value.contains('$') && !value.contains('`') {
            env.insert(name.to_string(), value);
        }
    }
    env
}

/// An Apache directive's arguments: words, or "quoted strings" in which
/// `\"` is a quote.
pub fn apache_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else { break };
        let mut arg = String::new();
        if first == '"' || first == '\'' {
            chars.next();
            while let Some(c) = chars.next() {
                if c == '\\' && chars.peek() == Some(&first) {
                    arg.push(first);
                    chars.next();
                } else if c == first {
                    break;
                } else {
                    arg.push(c);
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                arg.push(c);
                chars.next();
            }
        }
        args.push(arg);
    }
    args
}

fn substitute(text: &str, env: &HashMap<String, String>) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find('}')? + start;
        out.push_str(env.get(&rest[start + 2..end])?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

struct ApacheWalk<'a> {
    fs_root: PathBuf,
    budget: usize,
    env: &'a HashMap<String, String>,
    root: PathBuf,
    formats: HashMap<String, String>,
    main: Vec<(String, String)>,
    hosts: Vec<(VhostLogs, Vec<(String, String)>)>,
    blocks_in_file: HashMap<String, usize>,
}

impl ApacheWalk<'_> {
    fn walk(&mut self, text: &str, path: &str, open: &mut Option<usize>) {
        let mut logical = String::new();
        for raw in text.lines() {
            let line = raw.trim();
            if let Some(start) = line.strip_suffix('\\') {
                logical.push_str(start);
                logical.push(' ');
                continue;
            }
            logical.push_str(line);
            let line = std::mem::take(&mut logical);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("<virtualhost") {
                let block = self.blocks_in_file.entry(path.to_string()).or_default();
                let mut host = VhostLogs {
                    server: "apache".into(),
                    config_path: path.into(),
                    block: *block,
                    ..Default::default()
                };
                *block += 1;
                for address in line.trim_end_matches('>').split_whitespace().skip(1) {
                    if let Some(port) = address.rsplit(':').next().and_then(|p| p.parse().ok()) {
                        host.listen.push(port);
                    }
                    if address.starts_with("_default_") {
                        host.default_server = true;
                    }
                }
                self.hosts.push((host, Vec::new()));
                *open = Some(self.hosts.len() - 1);
                continue;
            }
            if lower.starts_with("</virtualhost") {
                *open = None;
                continue;
            }
            if line.starts_with('<') {
                continue;
            }
            let Some(line) = substitute(line, self.env) else {
                continue;
            };
            let mut words = line.splitn(2, char::is_whitespace);
            let key = words.next().unwrap_or_default().to_ascii_lowercase();
            let args = apache_args(words.next().unwrap_or_default());
            self.directive(&key, &args, open);
        }
    }

    fn directive(&mut self, key: &str, args: &[String], open: &mut Option<usize>) {
        match key {
            "serverroot" => {
                if let Some(root) = args.first() {
                    self.root = PathBuf::from(root);
                }
            }
            "include" | "includeoptional" => {
                for pattern in args {
                    let full = resolve(&self.root, pattern);
                    let is_dir = matches!(resolve_in(&self.fs_root, &full), Resolved::File(ref d) if d.is_dir());
                    let files = if is_dir {
                        glob_in(&self.fs_root, &full.join("*"), &mut self.budget)
                    } else {
                        glob_in(&self.fs_root, &full, &mut self.budget)
                    };
                    for file in files {
                        if let Some(text) = read_in(&self.fs_root, &file) {
                            self.walk(&text, &file.to_string_lossy(), open);
                        }
                    }
                }
            }
            "logformat" => {
                if let [format, nick, ..] = args {
                    self.formats.insert(nick.clone(), format.clone());
                }
            }
            "customlog" => {
                let [target, format, ..] = args else { return };
                let log = if target.starts_with('|') || target.contains("syslog:") {
                    ("|".to_string(), String::new())
                } else {
                    (target.clone(), format.clone())
                };
                match open {
                    Some(index) => self.hosts[*index].1.push(log),
                    None => self.main.push(log),
                }
            }
            _ => {
                let Some(index) = *open else { return };
                let host = &mut self.hosts[index].0;
                match key {
                    "servername" | "serveralias" => {
                        for name in args {
                            let name = name
                                .split("://")
                                .last()
                                .unwrap_or(name)
                                .split(':')
                                .next()
                                .unwrap_or_default()
                                .to_ascii_lowercase();
                            if !name.is_empty() && !host.names.contains(&name) {
                                host.names.push(name);
                            }
                        }
                    }
                    "proxypass" | "proxypassmatch" | "sethandler" => {
                        for target in args.iter().skip(usize::from(key != "sethandler")).take(1) {
                            if let Some(port) = local_port(target) {
                                if !host.upstream_ports.contains(&port) {
                                    host.upstream_ports.push(port);
                                }
                            } else if let Some(socket) = unix_socket(target) {
                                if !host.sockets.contains(&socket) {
                                    host.sockets.push(socket);
                                }
                            }
                        }
                    }
                    "documentroot" => {
                        if let Some(root) = args.first() {
                            let root = root.trim_end_matches('/').to_string();
                            if !root.is_empty() && !host.roots.contains(&root) {
                                host.roots.push(root);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn apache(
    text: &str,
    conf: &Path,
    root: &Path,
    env: &HashMap<String, String>,
    paths: &Paths,
) -> Vec<VhostLogs> {
    let mut walk = ApacheWalk {
        fs_root: paths.root.clone(),
        budget: MAX_FILES,
        env,
        root: root.to_path_buf(),
        formats: HashMap::new(),
        main: Vec::new(),
        hosts: Vec::new(),
        blocks_in_file: HashMap::new(),
    };
    walk.walk(text, &conf.to_string_lossy(), &mut None);

    let root = walk.root.clone();
    let format_of = |name: &str| -> Option<(String, Option<String>)> {
        if let Some(format) = walk.formats.get(name) {
            return Some((format.clone(), Some(name.to_string())));
        }
        if let Some((_, format)) = APACHE_DEFAULTS.iter().find(|(n, _)| *n == name) {
            return Some((format.to_string(), Some(name.to_string())));
        }
        // Not a nickname: the format itself, inline.
        name.contains('%').then(|| (name.to_string(), None))
    };
    let files = |logs: &[(String, String)]| -> Vec<LogFile> {
        logs.iter()
            .filter(|(path, _)| path != "|")
            .filter_map(|(path, format)| {
                let (format, format_name) = format_of(format)?;
                let path = resolve(&root, path);
                Some(LogFile {
                    target: target_of(paths, &path)?,
                    path,
                    format,
                    format_name,
                })
            })
            .collect()
    };

    walk.hosts
        .iter()
        .map(|(host, own)| {
            let mut host = host.clone();
            host.inherited = own.is_empty();
            let logs = if host.inherited { &walk.main } else { own };
            host.logs = files(logs);
            if host.logs.is_empty() {
                host.unlogged = Some(if logs.is_empty() { "off" } else { "elsewhere" }.to_string());
            }
            host
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn paths(dir: &Path) -> Paths {
        Paths {
            nginx_confs: vec![(dir.join("nginx/nginx.conf"), dir.join("nginx"))],
            apache_confs: vec![(dir.join("apache2/apache2.conf"), dir.join("apache2"))],
            apache_envvars: dir.join("apache2/envvars"),
            ..Paths::default()
        }
    }

    #[test]
    fn nginx_server_blocks_get_their_own_or_the_http_blocks_log() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(
            d,
            "nginx/nginx.conf",
            "http {\n  log_format timed '$remote_addr [$time_local] \"$request\" $status $request_time';\n  access_log /var/log/nginx/access.log;\n  include conf.d/*.conf;\n  include sites-enabled/*;\n}\n",
        );
        write(
            d,
            "nginx/sites-enabled/shop",
            "server {\n  listen 80;\n  server_name shop.test www.shop.test;\n  root /var/www/shop/public;\n  location = /favicon.ico { access_log off; }\n  location / { try_files $uri /index.php; }\n}\nserver {\n  listen 443 ssl default_server;\n  server_name shop.test;\n  access_log /var/log/nginx/shop.log timed;\n  access_log syslog:server=unix:/dev/log;\n  location /api { proxy_pass http://127.0.0.1:3000; access_log /var/log/nginx/api.log; }\n}\n",
        );
        write(
            d,
            "nginx/sites-enabled/quiet",
            "server { server_name quiet.test; access_log off; }\n",
        );
        write(
            d,
            "nginx/serveros.d/app.conf",
            "server { server_name app.test; access_log /var/log/serveros-traffic/app.log serveros_traffic; }\n",
        );

        let found = discover_in(&paths(d));
        assert_eq!(found.len(), 3, "{found:#?}");

        // sites-enabled is read in name order: quiet, then shop.
        assert_eq!(found[0].names, vec!["quiet.test"]);
        assert!(found[0].logs.is_empty());
        assert_eq!(found[0].unlogged.as_deref(), Some("off"));
        assert!(found[0].editable);

        let plain = &found[1];
        assert_eq!(plain.names, vec!["shop.test", "www.shop.test"]);
        assert!(plain.inherited);
        assert_eq!(plain.block, 0);
        assert_eq!(
            plain.logs,
            vec![LogFile::file(
                "/var/log/nginx/access.log",
                NGINX_COMBINED,
                Some("combined")
            )]
        );

        let tls = &found[2];
        assert_eq!(tls.block, 1);
        assert!(!tls.inherited && tls.default_server);
        assert_eq!(tls.upstream_ports, vec![3000]);
        let logs: Vec<_> = tls.logs.iter().map(|l| l.path.clone()).collect();
        assert_eq!(
            logs,
            vec![
                PathBuf::from("/var/log/nginx/shop.log"),
                PathBuf::from("/var/log/nginx/api.log")
            ]
        );
        assert!(tls.logs[0].format.ends_with("$request_time"));
        assert_eq!(plain.roots, vec!["/var/www/shop/public"]);
        assert_eq!(plain.unlogged, None);
    }

    #[test]
    fn sockets_are_read_from_every_way_of_writing_them() {
        assert_eq!(
            unix_socket("unix:/run/php/php8.3-fpm.sock").as_deref(),
            Some("/run/php/php8.3-fpm.sock")
        );
        assert_eq!(
            unix_socket("http://unix:/run/app.sock:/").as_deref(),
            Some("/run/app.sock")
        );
        assert_eq!(
            unix_socket("proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost").as_deref(),
            Some("/run/php/php8.2-fpm.sock")
        );
        assert_eq!(
            unix_socket("unix//run/php/php8.4-fpm.sock").as_deref(),
            Some("/run/php/php8.4-fpm.sock")
        );
        assert_eq!(unix_socket("http://127.0.0.1:3000"), None);
    }

    /// nginx's official image, seen through a container's root: its log
    /// is the container's output, its config is read inside the root.
    #[test]
    fn nginx_in_a_container_logs_to_its_output() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "etc/nginx/nginx.conf",
            "events {}\nhttp {\n  access_log /var/log/nginx/access.log main;\n  log_format main '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"';\n  include /etc/nginx/conf.d/*.conf;\n}\n",
        );
        write(
            root,
            "etc/nginx/conf.d/default.conf",
            "server {\n  listen 80;\n  server_name shop.test;\n  location / { root /usr/share/nginx/html; }\n  location /api { fastcgi_pass unix:/run/php/php-fpm.sock; }\n}\nserver { server_name quiet.test; access_log off; }\n",
        );
        std::fs::create_dir_all(root.join("var/log/nginx")).unwrap();
        std::os::unix::fs::symlink("/dev/stdout", root.join("var/log/nginx/access.log")).unwrap();
        let container = Container {
            id: "c".repeat(64),
            name: "web".into(),
        };
        let paths = Paths::in_container(root.to_path_buf(), container.clone(), "nginx", None);
        let found = discover_in(&paths);
        assert_eq!(found.len(), 2, "{found:#?}");
        let shop = &found[0];
        assert_eq!(shop.names, vec!["shop.test"]);
        assert_eq!(shop.config_path, "/etc/nginx/conf.d/default.conf");
        assert_eq!(shop.container.as_ref(), Some(&container));
        assert!(!shop.editable);
        assert_eq!(
            shop.logs[0].path,
            PathBuf::from("/var/log/nginx/access.log")
        );
        assert_eq!(
            shop.logs[0].target,
            LogTarget::Container {
                id: "c".repeat(64),
                stderr: false
            }
        );
        assert_eq!(shop.roots, vec!["/usr/share/nginx/html"]);
        assert_eq!(shop.sockets, vec!["/run/php/php-fpm.sock"]);
        assert_eq!(found[1].unlogged.as_deref(), Some("off"));
    }

    #[test]
    fn apache_vhosts_read_customlog_with_envvars_and_inherit_the_main_one() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(
            d,
            "apache2/envvars",
            "export APACHE_RUN_USER=www-data\nexport APACHE_LOG_DIR=/var/log/apache2$SUFFIX\n",
        );
        write(
            d,
            "apache2/apache2.conf",
            "LogFormat \"%v:%p %h %l %u %t \\\"%r\\\" %>s %O \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" vhost_combined\nLogFormat \"%h %l %u %t \\\"%r\\\" %>s %O \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" combined\nIncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n",
        );
        write(
            d,
            "apache2/conf-enabled/other-vhosts-access-log.conf",
            "CustomLog ${APACHE_LOG_DIR}/other_vhosts_access.log vhost_combined\n",
        );
        write(
            d,
            "apache2/sites-enabled/000-default.conf",
            "<VirtualHost *:80>\n  ServerName blog.test\n  ServerAlias www.blog.test\n  DocumentRoot /var/www/blog\n  CustomLog ${APACHE_LOG_DIR}/access.log combined\n  CustomLog \"|/usr/bin/rotatelogs /x 86400\" common\n</VirtualHost>\n<VirtualHost *:8080>\n  ServerName api.test\n  ProxyPass / http://localhost:4000/\n</VirtualHost>\n<VirtualHost *:81>\n  ServerName timed.test\n  CustomLog logs/timed.log \"%h %t \\\"%r\\\" %>s %b %D\"\n</VirtualHost>\n",
        );

        let found = discover_in(&paths(d));
        assert_eq!(found.len(), 3, "{found:#?}");
        assert_eq!(found[0].names, vec!["blog.test", "www.blog.test"]);
        assert_eq!(
            found[0].logs,
            vec![LogFile::file(
                "/var/log/apache2/access.log",
                "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"",
                Some("combined")
            )]
        );
        assert!(found[1].inherited);
        assert_eq!(found[1].upstream_ports, vec![4000]);
        assert_eq!(
            found[1].logs[0].path,
            PathBuf::from("/var/log/apache2/other_vhosts_access.log")
        );
        assert!(found[1].logs[0].format.starts_with("%v:%p"));
        assert_eq!(found[2].logs[0].path, d.join("apache2/logs/timed.log"));
        assert_eq!(found[2].logs[0].format, "%h %t \"%r\" %>s %b %D");
        assert_eq!(found[2].logs[0].format_name, None);
    }

    #[test]
    fn apache_arguments_keep_escaped_quotes() {
        assert_eq!(
            apache_args(r#""%h \"%r\"" combined env=!dontlog"#),
            vec!["%h \"%r\"", "combined", "env=!dontlog"]
        );
    }

    #[test]
    fn local_upstreams_give_their_ports() {
        assert_eq!(local_port("http://127.0.0.1:3000/"), Some(3000));
        assert_eq!(local_port("localhost:9000"), Some(9000));
        assert_eq!(local_port("http://[::1]:8080"), Some(8080));
        assert_eq!(local_port("http://backend:3000"), None);
        assert_eq!(local_port("unix:/run/php/php8.3-fpm.sock"), None);
    }
}
