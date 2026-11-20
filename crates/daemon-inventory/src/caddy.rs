//! The sites a Caddy serves and where each writes its access log, read from
//! Caddy's live config: its admin API (`GET /config/`), or the copy Caddy
//! saves of it (`autosave.json`), or the Caddyfile adapted by Caddy itself.
//! The JSON has imports and snippets expanded already, so nothing is
//! guessed from Caddyfile syntax. Read-only.
//!
//! Each top-level route of each server is a site, named by its first host;
//! one with no host is the server's catch-all ("All other hosts"). Which log
//! a host writes comes from the server's `logs` (`logger_names`,
//! `default_logger_name`, `skip_hosts`) and the logs in `logging.logs`. A
//! server without `logs` writes none: Caddy's default.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::access_logs::{
    unix_socket, Container, LogFile, LogTarget, VhostLogs, FORMAT_CADDY, FORMAT_CADDY_CONSOLE,
};
use crate::local_http::{self, Target};
use crate::procs::{read_in, rooted, WebProcess};

/// The most of a config read.
const MAX_CONFIG: usize = 16 * 1024 * 1024;
const MAX_SITES: usize = 500;

/// Caddy's live config, and where it came from.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Value,
    /// "the admin API", or the file it was read from.
    pub source: String,
    /// The Caddyfile it runs from, inside its root, when it runs from one.
    pub caddyfile: Option<PathBuf>,
}

/// What a site's description needs to know about the Caddy it's in.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Shown as where the site is set up.
    pub config_path: String,
    pub editable: bool,
    pub container: Option<Container>,
    /// Where the Caddy's files are, seen from here.
    pub root: PathBuf,
}

/// The Caddyfile a Caddy process runs from, inside its root.
pub fn caddyfile_of(process: &WebProcess) -> Option<PathBuf> {
    let config = process.arg(&["--config", "-c"]);
    let adapter = process.arg(&["--adapter"]);
    match config {
        Some(path) => {
            let path = PathBuf::from(path);
            let named = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.to_ascii_lowercase().contains("caddyfile"));
            let path = if path.is_absolute() {
                path
            } else {
                process.cwd.clone().unwrap_or_else(|| "/".into()).join(path)
            };
            (adapter.as_deref() == Some("caddyfile") || named).then_some(path)
        }
        // `caddy run` with no config reads ./Caddyfile.
        None if process.args.iter().any(|a| a == "run" || a == "start") => {
            let path = process
                .cwd
                .clone()
                .unwrap_or_else(|| "/".into())
                .join("Caddyfile");
            read_in(&process.root, &path).map(|_| path)
        }
        None => None,
    }
}

fn autosave_paths(process: &WebProcess) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(xdg) = process.env.get("XDG_CONFIG_HOME") {
        paths.push(PathBuf::from(xdg).join("caddy/autosave.json"));
    }
    if let Some(home) = process.env.get("HOME") {
        paths.push(PathBuf::from(home).join(".config/caddy/autosave.json"));
    }
    for path in [
        "/config/caddy/autosave.json",
        "/var/lib/caddy/.config/caddy/autosave.json",
        "/root/.config/caddy/autosave.json",
    ] {
        paths.push(PathBuf::from(path));
    }
    paths.dedup();
    paths
}

/// Reads a Caddy's live config. Inside a container, its admin API listens
/// on the container's own localhost, so the saved copy is read there.
pub async fn load(process: &WebProcess) -> Option<Loaded> {
    let caddyfile = caddyfile_of(process);
    let mut saved: Option<(Value, PathBuf)> = None;
    for path in autosave_paths(process) {
        if let Some(text) = read_in(&process.root, &path) {
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                if value.is_object() {
                    saved = Some((value, path));
                    break;
                }
            }
        }
    }

    if !process.in_container() {
        let disabled = saved
            .as_ref()
            .and_then(|(v, _)| v.pointer("/admin/disabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let address = process
            .env
            .get("CADDY_ADMIN")
            .cloned()
            .or_else(|| {
                saved
                    .as_ref()
                    .and_then(|(v, _)| v.pointer("/admin/listen"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "localhost:2019".to_string());
        if !disabled {
            if let Some(config) = from_api(&address).await {
                return Some(Loaded {
                    config,
                    source: "the admin API".into(),
                    caddyfile,
                });
            }
        }
    }
    if let Some((config, path)) = saved {
        return Some(Loaded {
            config,
            source: path.display().to_string(),
            caddyfile,
        });
    }
    if process.in_container() {
        return None;
    }
    let file = caddyfile.clone()?;
    let config = adapt(&file).await?;
    Some(Loaded {
        config,
        source: file.display().to_string(),
        caddyfile,
    })
}

async fn from_api(address: &str) -> Option<Value> {
    let target = Target::parse(address)?;
    let host = match &target {
        Target::Tcp(_) => {
            let port = address.rsplit(':').next().unwrap_or("2019");
            let name = address
                .trim_start_matches("tcp/")
                .rsplit_once(':')
                .map(|(h, _)| h)
                .filter(|h| !h.is_empty() && *h != "0.0.0.0")
                .unwrap_or("localhost");
            format!("{name}:{port}")
        }
        Target::Unix(_) => String::new(),
    };
    let body = local_http::get(
        &target,
        &host,
        "/config/",
        Duration::from_secs(3),
        MAX_CONFIG,
    )
    .await?;
    if body.truncated {
        return None;
    }
    let value: Value = serde_json::from_slice(&body.bytes).ok()?;
    value.is_object().then_some(value)
}

/// The last `caddy adapt`, kept while the Caddyfile is unchanged (same
/// path, size and modified time), so a machine whose Caddy has no admin API
/// or saved config doesn't start a Caddy process every minute. Imported
/// files aren't watched: a change only there is picked up when the
/// Caddyfile itself changes or the daemon restarts.
/// A Caddyfile's path, size and modified time, with what it adapted to.
type Adapted = (
    std::path::PathBuf,
    u64,
    Option<std::time::SystemTime>,
    Value,
);
static ADAPTED: std::sync::Mutex<Option<Adapted>> = std::sync::Mutex::new(None);

/// `caddy adapt`: Caddy turns its Caddyfile into JSON, changing nothing.
async fn adapt(caddyfile: &Path) -> Option<Value> {
    let meta = std::fs::metadata(caddyfile).ok()?;
    let (len, modified) = (meta.len(), meta.modified().ok());
    if let Some((path, l, m, value)) = ADAPTED.lock().ok()?.as_ref() {
        if path == caddyfile && *l == len && *m == modified && modified.is_some() {
            return Some(value.clone());
        }
    }
    let value = adapt_now(caddyfile).await?;
    if let Ok(mut cache) = ADAPTED.lock() {
        *cache = Some((caddyfile.to_path_buf(), len, modified, value.clone()));
    }
    Some(value)
}

async fn adapt_now(caddyfile: &Path) -> Option<Value> {
    let mut command = tokio::process::Command::new("caddy");
    command
        .args(["adapt", "--adapter", "caddyfile", "--config"])
        .arg(caddyfile)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    if let Some(dir) = caddyfile.parent() {
        command.current_dir(dir);
    }
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() || output.stdout.len() > MAX_CONFIG {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

/// Every site in a Caddy config, with the log each writes.
pub fn sites(config: &Value, context: &Context) -> Vec<VhostLogs> {
    let mut found: Vec<VhostLogs> = Vec::new();
    let Some(servers) = config
        .pointer("/apps/http/servers")
        .and_then(Value::as_object)
    else {
        return found;
    };
    let logging = config.pointer("/logging/logs").and_then(Value::as_object);
    for server in servers.values() {
        let listen: Vec<&str> = server
            .get("listen")
            .and_then(Value::as_array)
            .map(|l| l.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if !listen.is_empty() && listen.iter().all(|a| loopback_address(a)) {
            continue;
        }
        let ports: Vec<u16> = listen
            .iter()
            .filter_map(|a| a.rsplit(':').next()?.split('-').next()?.parse().ok())
            .collect();
        let logs = server.get("logs");
        let skip: Vec<&str> = strings(logs.and_then(|l| l.get("skip_hosts")));
        let routes = server.get("routes").and_then(Value::as_array);
        for (index, route) in routes.into_iter().flatten().enumerate() {
            if found.len() >= MAX_SITES {
                return found;
            }
            let hosts = route_hosts(route);
            let catch_all = hosts.is_empty();
            if !catch_all && hosts.iter().all(|h| local_host(h)) {
                continue;
            }
            let mut what = Handlers::default();
            if let Some(handle) = route.get("handle") {
                what.walk(handle, 0);
            }
            if what.redirect_only() {
                continue;
            }
            let mut site = VhostLogs {
                server: "caddy".into(),
                names: hosts.clone(),
                config_path: context.config_path.clone(),
                block: index,
                listen: ports.clone(),
                upstream_ports: what.ports,
                container: context.container.clone(),
                catch_all,
                roots: what.roots,
                sockets: what.sockets,
                editable: context.editable,
                ..Default::default()
            };
            match logs {
                None => site.unlogged = Some("off".into()),
                // The Caddyfile puts the hosts of sites with no `log` in
                // skip_hosts, so other sites' loggers leave them out.
                Some(_) if !catch_all && hosts.iter().all(|h| skip.contains(&h.as_str())) => {
                    site.unlogged = Some("off".into());
                }
                Some(logs) => {
                    let host = hosts.first().map(String::as_str);
                    let names = logger_names(logs, host);
                    match names {
                        None => site.unlogged = Some("off".into()),
                        Some(names) => {
                            let mut elsewhere = false;
                            for name in names {
                                for (writer, format) in writers(logging, &name) {
                                    match file_of(&writer, &format, context) {
                                        Some(Some(file)) => {
                                            if !site.logs.contains(&file) {
                                                site.logs.push(file);
                                            }
                                        }
                                        Some(None) => elsewhere = true,
                                        None => {}
                                    }
                                }
                            }
                            if site.logs.is_empty() {
                                site.unlogged =
                                    Some(if elsewhere { "elsewhere" } else { "off" }.into());
                            }
                        }
                    }
                }
            }
            // A second server with the same hosts (:80 and :443): one site.
            if let Some(same) = found
                .iter_mut()
                .find(|s| s.names == site.names && s.catch_all == site.catch_all)
            {
                for port in site.listen {
                    if !same.listen.contains(&port) {
                        same.listen.push(port);
                    }
                }
                for log in site.logs {
                    if !same.logs.contains(&log) {
                        same.logs.push(log);
                    }
                }
                if !same.logs.is_empty() {
                    same.unlogged = None;
                }
                continue;
            }
            found.push(site);
        }
    }
    found
}

fn strings(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|l| l.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn route_hosts(route: &Value) -> Vec<String> {
    let mut hosts = Vec::new();
    for set in route
        .get("match")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for host in strings(set.get("host")) {
            let host = host.to_ascii_lowercase();
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
    }
    hosts
}

fn loopback_address(address: &str) -> bool {
    let address = address
        .trim_start_matches("tcp/")
        .trim_start_matches("tcp4/");
    address.starts_with("127.")
        || address.starts_with("localhost:")
        || address.starts_with("[::1]")
        || address.starts_with("unix/")
}

fn local_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host == "::1"
        || host == "[::1]"
}

/// What a route does, as far as tying it to an app goes.
#[derive(Default)]
struct Handlers {
    roots: Vec<String>,
    ports: Vec<u16>,
    sockets: Vec<String>,
    serves: bool,
    redirects: bool,
}

impl Handlers {
    fn walk(&mut self, handle: &Value, depth: usize) {
        if depth > 12 {
            return;
        }
        for handler in handle.as_array().into_iter().flatten() {
            match handler.get("handler").and_then(Value::as_str) {
                Some("subroute") => {
                    for route in handler
                        .get("routes")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(inner) = route.get("handle") {
                            self.walk(inner, depth + 1);
                        }
                    }
                }
                Some("vars") | Some("file_server") => {
                    if let Some(root) = handler.get("root").and_then(Value::as_str) {
                        self.root(root);
                    }
                    if handler.get("handler").and_then(Value::as_str) == Some("file_server") {
                        self.serves = true;
                    }
                }
                Some("reverse_proxy") => {
                    self.serves = true;
                    for upstream in handler
                        .get("upstreams")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let Some(dial) = upstream.get("dial").and_then(Value::as_str) else {
                            continue;
                        };
                        if let Some(socket) = unix_socket(dial) {
                            if !self.sockets.contains(&socket) {
                                self.sockets.push(socket);
                            }
                        } else if let Some(port) = local_dial(dial) {
                            if !self.ports.contains(&port) {
                                self.ports.push(port);
                            }
                        }
                    }
                }
                Some("static_response") => {
                    let status = handler
                        .get("status_code")
                        .and_then(|s| s.as_u64().or_else(|| s.as_str()?.parse().ok()))
                        .unwrap_or(200);
                    let location = handler.pointer("/headers/Location").is_some();
                    if (300..400).contains(&status) && location {
                        self.redirects = true;
                    } else {
                        self.serves = true;
                    }
                }
                Some("php_fastcgi") | Some("templates") | Some("authentication") => {}
                Some(_) | None => {}
            }
        }
    }

    fn root(&mut self, root: &str) {
        if root.contains('{') {
            return;
        }
        let root = root.trim_end_matches('/').to_string();
        if !root.is_empty() && !self.roots.contains(&root) {
            self.roots.push(root);
        }
    }

    fn redirect_only(&self) -> bool {
        self.redirects && !self.serves
    }
}

fn local_dial(dial: &str) -> Option<u16> {
    let (host, port) = dial.rsplit_once(':')?;
    let host = host.trim_matches(['[', ']']);
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "0.0.0.0" | "")
        .then(|| port.parse().ok())
        .flatten()
}

/// The loggers a host writes to, from the server's `logs`, or None when
/// it's not logged.
fn logger_names(logs: &Value, host: Option<&str>) -> Option<Vec<String>> {
    if let Some(host) = host {
        if let Some(named) = logs.get("logger_names").and_then(|n| n.get(host)) {
            // Caddy 2.7+ lists them; older ones name one.
            let names: Vec<String> = match named {
                Value::String(one) => vec![one.clone()],
                Value::Array(list) => list
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            if !names.is_empty() {
                return Some(names);
            }
        }
        if logs.get("skip_unmapped_hosts").and_then(Value::as_bool) == Some(true) {
            return None;
        }
    }
    Some(vec![logs
        .get("default_logger_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()])
}

fn covers(list: Option<&Value>, logger: &str) -> bool {
    strings(list)
        .iter()
        .any(|name| logger == *name || logger.starts_with(&format!("{name}.")))
}

/// The writers and encoder formats of the logs an access logger goes to.
fn writers(logging: Option<&serde_json::Map<String, Value>>, name: &str) -> Vec<(Value, String)> {
    let logger = if name.is_empty() {
        "http.log.access".to_string()
    } else {
        format!("http.log.access.{name}")
    };
    let mut found = Vec::new();
    let mut has_default = false;
    for (log_name, log) in logging.into_iter().flatten() {
        has_default |= log_name == "default";
        let include = log.get("include");
        let included = strings(include).is_empty() || covers(include, &logger);
        if !included || covers(log.get("exclude"), &logger) {
            continue;
        }
        found.push((
            log.get("writer").cloned().unwrap_or(Value::Null),
            format_of(log.get("encoder")),
        ));
    }
    if found.is_empty() && !has_default {
        // Caddy's own default log: standard error.
        found.push((Value::Null, "json".into()));
    }
    found
}

fn format_of(encoder: Option<&Value>) -> String {
    let Some(encoder) = encoder else {
        return "json".into();
    };
    match encoder.get("format").and_then(Value::as_str) {
        Some("filter") => format_of(encoder.get("wrap")),
        Some(format) => format.to_string(),
        None => "json".into(),
    }
}

/// A log's file, or Some(None) for one that can't be read (the journal,
/// the network), or None for one that writes nowhere.
fn file_of(writer: &Value, format: &str, context: &Context) -> Option<Option<LogFile>> {
    let format = match format {
        "json" => FORMAT_CADDY,
        "console" => FORMAT_CADDY_CONSOLE,
        _ => return Some(None),
    };
    let output = writer
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or("stderr");
    let stream = |stderr: bool| match &context.container {
        Some(container) => Some(Some(LogFile {
            path: PathBuf::from(if stderr { "/dev/stderr" } else { "/dev/stdout" }),
            format: format.into(),
            format_name: None,
            target: LogTarget::Container {
                id: container.id.clone(),
                stderr,
            },
        })),
        None => Some(None),
    };
    match output {
        "file" => {
            let path = PathBuf::from(writer.get("filename").and_then(Value::as_str)?);
            Some(Some(LogFile {
                target: LogTarget::File(rooted(&context.root, &path)),
                path,
                format: format.into(),
                format_name: None,
            }))
        }
        "stdout" => stream(false),
        "stderr" => stream(true),
        "discard" => None,
        _ => Some(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The shape of production's config: three named loggers into one
    /// file, a catch-all, a loopback-only server, an HTTP redirect server,
    /// a skipped host, and ServerOS's own site with a file of its own.
    fn production() -> Value {
        json!({
            "logging": {"logs": {
                "default": {"exclude": ["http.log.access.log0", "http.log.access.log1", "http.log.access.log2", "http.log.access.log3"]},
                "log0": {"encoder": {"format": "json"}, "include": ["http.log.access.log0"], "writer": {"filename": "/var/log/caddy/access.log", "output": "file"}},
                "log1": {"encoder": {"format": "json"}, "include": ["http.log.access.log1"], "writer": {"filename": "/var/log/caddy/access.log", "output": "file"}},
                "log2": {"encoder": {"format": "json"}, "include": ["http.log.access.log2"], "writer": {"filename": "/var/log/caddy/access.log", "output": "file"}},
                "log3": {"encoder": {"format": "json"}, "include": ["http.log.access.log3"], "writer": {"filename": "/var/log/serveros-traffic/grafana.log", "output": "file"}}
            }},
            "apps": {"http": {"servers": {
                "srv0": {"listen": ["127.0.0.1:9123"], "routes": [{"match": [{"host": ["127.0.0.1"]}], "handle": []}]},
                "srv1": {
                    "listen": [":443"],
                    "logs": {"default_logger_name": "log2", "logger_names": {"gateway.serveros.com": ["log1"], "graf.serveros.com": ["log3"], "releases.serveros.com": ["log0"]}, "skip_hosts": ["origin-cert.localhost"]},
                    "routes": [
                        {"match": [{"host": ["releases.serveros.com"]}], "handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "vars", "root": "/var/www/serveros-releases/shared/public/releases/daemon"}]}, {"handle": [{"handler": "file_server"}]}]}], "terminal": true},
                        {"match": [{"host": ["origin-cert.localhost"]}], "handle": [{"handler": "static_response", "status_code": 404}]},
                        {"match": [{"host": ["gateway.serveros.com"]}], "handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "vars", "root": "/var/www/serveros/public"}]}, {"handle": [{"handler": "reverse_proxy", "transport": {"protocol": "fastcgi"}, "upstreams": [{"dial": "unix//run/php/php8.4-fpm.sock"}]}]}]}]},
                        {"match": [{"host": ["graf.serveros.com"]}], "handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:3000"}]}]}]}]},
                        {"handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "vars", "root": "/var/www/serveros/public"}]}, {"handle": [{"handler": "reverse_proxy", "transport": {"protocol": "fastcgi"}, "upstreams": [{"dial": "unix//run/php/php8.4-fpm.sock"}]}]}]}], "terminal": true}
                    ]
                },
                "srv2": {"listen": [":80"], "routes": [{"handle": [{"handler": "static_response", "headers": {"Location": ["https://{http.request.host}{http.request.uri}"]}, "status_code": 301}]}]},
                "srv3": {"listen": [":8080"], "routes": [{"match": [{"host": ["quiet.test"]}], "handle": [{"handler": "file_server", "root": "/srv/quiet"}]}]},
                "srv4": {"listen": [":8443"], "logs": {"logger_names": {"logged.test": [""]}, "skip_hosts": ["plain.test"]}, "routes": [
                    {"match": [{"host": ["plain.test"]}], "handle": [{"handler": "static_response", "body": "plain"}]},
                    {"match": [{"host": ["logged.test"]}], "handle": [{"handler": "static_response", "body": "logged"}]}
                ]}
            }}}
        })
    }

    fn context() -> Context {
        Context {
            config_path: "/etc/caddy/Caddyfile".into(),
            editable: true,
            root: "/".into(),
            ..Default::default()
        }
    }

    #[test]
    fn production_shaped_config_gives_each_site_its_log() {
        let found = sites(&production(), &context());
        let names: Vec<(Vec<String>, bool)> = found
            .iter()
            .map(|s| (s.names.clone(), s.catch_all))
            .collect();
        assert_eq!(
            names,
            vec![
                (vec!["releases.serveros.com".to_string()], false),
                (vec!["gateway.serveros.com".to_string()], false),
                (vec!["graf.serveros.com".to_string()], false),
                (vec![], true),
                (vec!["quiet.test".to_string()], false),
                (vec!["plain.test".to_string()], false),
                (vec!["logged.test".to_string()], false),
            ]
        );
        // A site with no `log` among ones with: its hosts are skipped.
        assert_eq!(found[5].unlogged.as_deref(), Some("off"));
        // `log` with no output: Caddy's default log, standard error.
        assert_eq!(found[6].unlogged.as_deref(), Some("elsewhere"));
        let access = LogFile::file("/var/log/caddy/access.log", FORMAT_CADDY, None);
        assert_eq!(found[0].logs, vec![access.clone()]);
        assert_eq!(found[1].logs, vec![access.clone()]);
        assert_eq!(found[3].logs, vec![access]);
        assert_eq!(
            found[2].logs[0].path,
            PathBuf::from("/var/log/serveros-traffic/grafana.log")
        );
        assert_eq!(
            found[0].roots,
            vec!["/var/www/serveros-releases/shared/public/releases/daemon"]
        );
        assert_eq!(found[3].roots, vec!["/var/www/serveros/public"]);
        assert_eq!(found[3].sockets, vec!["/run/php/php8.4-fpm.sock"]);
        assert_eq!(found[2].upstream_ports, vec![3000]);
        assert_eq!(found[3].listen, vec![443]);
        // A server with no `logs`: Caddy logs nothing for it.
        assert_eq!(found[4].unlogged.as_deref(), Some("off"));
        assert!(found[4].logs.is_empty());
        assert!(found.iter().all(|s| s.editable && s.server == "caddy"));
    }

    #[test]
    fn standard_error_and_unmapped_hosts() {
        let config = json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "logs": {"logger_names": {"a.test": "log0"}, "skip_unmapped_hosts": true},
                "routes": [
                    {"match": [{"host": ["a.test"]}], "handle": [{"handler": "file_server"}]},
                    {"match": [{"host": ["b.test"]}], "handle": [{"handler": "file_server"}]}
                ]
            }}}}
        });
        // No logging section: log0 goes to Caddy's default, standard error.
        let found = sites(&config, &context());
        assert_eq!(found[0].unlogged.as_deref(), Some("elsewhere"));
        assert_eq!(found[1].unlogged.as_deref(), Some("off"));

        // In a container, standard error is the container's output.
        let mut in_container = context();
        in_container.container = Some(Container {
            id: "f".repeat(64),
            name: "caddy".into(),
        });
        let found = sites(&config, &in_container);
        assert_eq!(
            found[0].logs[0].target,
            LogTarget::Container {
                id: "f".repeat(64),
                stderr: true
            }
        );
    }

    #[test]
    fn console_and_filtered_encoders() {
        assert_eq!(format_of(Some(&json!({"format": "console"}))), "console");
        assert_eq!(
            format_of(Some(
                &json!({"format": "filter", "wrap": {"format": "json"}})
            )),
            "json"
        );
        assert_eq!(format_of(None), "json");
    }

    #[test]
    fn caddyfile_comes_from_the_command_line() {
        let process = WebProcess {
            server: "caddy".into(),
            args: [
                "caddy",
                "run",
                "--environ",
                "--config",
                "/etc/caddy/Caddyfile",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            root: "/".into(),
            ..Default::default()
        };
        assert_eq!(
            caddyfile_of(&process),
            Some(PathBuf::from("/etc/caddy/Caddyfile"))
        );
        let json = WebProcess {
            args: vec![
                "caddy".into(),
                "run".into(),
                "--config".into(),
                "/etc/caddy/caddy.json".into(),
            ],
            ..process
        };
        assert_eq!(caddyfile_of(&json), None);
    }
}
