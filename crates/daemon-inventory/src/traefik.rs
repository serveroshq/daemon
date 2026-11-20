//! The sites a Traefik routes and where it writes its access log, on the
//! machine or in a container (Coolify, Dokploy and docker-compose setups
//! run it in one, with routers from container labels). Read-only.
//!
//! The static config comes from its config file, its command line or its
//! environment, whichever it uses. Routers come from its API when that's
//! open (`api.insecure`), else from the labels on containers (its Docker
//! provider) and its file provider's files. Its one access log is a file,
//! or its output when no file is set. Lines name the router that handled
//! them, so each site is counted by its routers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::access_logs::{
    Container, LogFile, LogTarget, VhostLogs, FORMAT_TRAEFIK, FORMAT_TRAEFIK_COMMON,
};
use crate::local_http::{self, Target};
use crate::procs::{glob_in, read_in, rooted, WebProcess};

const DEFAULT_FILES: &[&str] = &[
    "/etc/traefik/traefik.yml",
    "/etc/traefik/traefik.yaml",
    "/etc/traefik/traefik.toml",
];
const MAX_ROUTERS: usize = 1000;
const MAX_DYNAMIC_FILES: usize = 100;

/// A Traefik's static config, flattened to lowercase dotted keys
/// (`accesslog.filepath`), wherever it came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Setup {
    /// Where it came from, in words: its file, or "its command line".
    pub source: String,
    /// The static config file, inside its root, when it uses one.
    pub file: Option<PathBuf>,
    pub keys: BTreeMap<String, String>,
}

impl Setup {
    fn get(&self, key: &str) -> Option<&str> {
        self.keys.get(key).map(String::as_str)
    }

    /// Whether it writes an access log at all, and where: a file inside its
    /// root, or None for its output.
    pub fn access_log(&self) -> Option<Option<PathBuf>> {
        if self
            .get("accesslog")
            .is_some_and(|v| v.eq_ignore_ascii_case("false"))
        {
            return None;
        }
        let on = self
            .keys
            .keys()
            .any(|k| k == "accesslog" || k.starts_with("accesslog."));
        on.then(|| {
            self.get("accesslog.filepath")
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
        })
    }

    /// Its access log's lines are JSON (else Traefik's common format).
    pub fn json(&self) -> bool {
        self.get("accesslog.format")
            .is_some_and(|f| f.eq_ignore_ascii_case("json"))
    }

    /// The address its API answers on without a password, if it does.
    pub fn open_api(&self) -> Option<String> {
        if !self
            .get("api.insecure")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        {
            return None;
        }
        Some(
            self.get("entrypoints.traefik.address")
                .unwrap_or(":8080")
                .to_string(),
        )
    }

    pub fn docker(&self) -> bool {
        self.keys
            .keys()
            .any(|k| k == "providers.docker" || k.starts_with("providers.docker."))
    }

    fn file_provider(&self) -> (Option<PathBuf>, Option<PathBuf>) {
        (
            self.get("providers.file.directory").map(PathBuf::from),
            self.get("providers.file.filename").map(PathBuf::from),
        )
    }
}

fn flatten(value: &Value, prefix: &str, keys: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            if !prefix.is_empty() {
                keys.entry(prefix.to_string()).or_default();
            }
            for (key, inner) in map {
                let key = key.to_ascii_lowercase();
                let path = if prefix.is_empty() {
                    key
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(inner, &path, keys);
            }
        }
        Value::Null => {
            keys.entry(prefix.to_string()).or_default();
        }
        Value::String(s) => {
            keys.insert(prefix.to_string(), s.clone());
        }
        Value::Array(_) => {
            keys.insert(prefix.to_string(), String::new());
        }
        other => {
            keys.insert(prefix.to_string(), other.to_string());
        }
    }
}

/// A config file (TOML or YAML) as JSON.
pub fn read_config(path: &Path, text: &str) -> Value {
    if path.extension().is_some_and(|x| x == "toml") {
        toml::from_str::<toml::Value>(text)
            .ok()
            .and_then(|v| serde_json::to_value(v).ok())
            .unwrap_or(Value::Null)
    } else {
        crate::mini_yaml::parse(text)
    }
}

/// A Traefik's static config.
pub fn static_config(process: &WebProcess) -> Setup {
    let explicit = process.arg(&["--configfile", "--configFile", "--config.file"]);
    let mut candidates: Vec<PathBuf> = explicit.iter().map(PathBuf::from).collect();
    let flags = process
        .args
        .iter()
        .skip(1)
        .any(|a| a.starts_with("--") && !a.to_ascii_lowercase().starts_with("--configfile"));
    if explicit.is_none() {
        candidates.extend(DEFAULT_FILES.iter().map(PathBuf::from));
        if let Some(cwd) = &process.cwd {
            for name in ["traefik.yml", "traefik.yaml", "traefik.toml"] {
                candidates.push(cwd.join(name));
            }
        }
    }
    for path in candidates {
        let Some(text) = read_in(&process.root, &path) else {
            continue;
        };
        let mut keys = BTreeMap::new();
        flatten(&read_config(&path, &text), "", &mut keys);
        return Setup {
            source: path.display().to_string(),
            file: Some(path),
            keys,
        };
    }
    let mut keys = BTreeMap::new();
    if flags {
        for arg in process.args.iter().skip(1) {
            let Some(flag) = arg.strip_prefix("--") else {
                continue;
            };
            let (key, value) = flag.split_once('=').unwrap_or((flag, "true"));
            keys.insert(key.to_ascii_lowercase(), value.to_string());
        }
        return Setup {
            source: "its command line".into(),
            file: None,
            keys,
        };
    }
    for (name, value) in &process.env {
        if let Some(rest) = name.strip_prefix("TRAEFIK_") {
            keys.insert(rest.to_ascii_lowercase().replace('_', "."), value.clone());
        }
    }
    Setup {
        source: "its environment".into(),
        file: None,
        keys,
    }
}

/// One router: its full name (`shop@docker`), the hosts its rule names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Router {
    pub name: String,
    pub hosts: Vec<String>,
    /// The container whose labels define it, by name.
    pub container: Option<String>,
}

/// The hosts in a rule: ``Host(`a`) || Host(`b`, `c`)``.
pub fn hosts_of(rule: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut rest = rule;
    while let Some(at) = rest.find("Host") {
        let after = &rest[at + 4..];
        let after = after.strip_prefix("Header").unwrap_or(after);
        rest = after;
        let Some(args) = after.strip_prefix('(') else {
            continue;
        };
        let Some(end) = args.find(')') else { break };
        for part in args[..end].split(',') {
            let host = part
                .trim()
                .trim_matches(['`', '"', '\''])
                .to_ascii_lowercase();
            if !host.is_empty() && !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        rest = &args[end..];
    }
    hosts
}

/// Routers as Traefik's API lists them (`/api/http/routers`).
pub fn routers_from_api(value: &Value) -> Vec<Router> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_ROUTERS)
        .filter_map(|r| {
            let name = r.get("name")?.as_str()?;
            if r.get("status").and_then(Value::as_str) == Some("disabled") {
                return None;
            }
            Some(Router {
                name: name.to_string(),
                hosts: hosts_of(r.get("rule").and_then(Value::as_str).unwrap_or("")),
                container: None,
            })
        })
        .collect()
}

/// Routers a dynamic config file names (`http.routers.<name>.rule`).
pub fn routers_from_dynamic(value: &Value) -> Vec<Router> {
    value
        .pointer("/http/routers")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .take(MAX_ROUTERS)
        .map(|(name, r)| Router {
            name: format!("{name}@file"),
            hosts: hosts_of(r.get("rule").and_then(Value::as_str).unwrap_or("")),
            container: None,
        })
        .collect()
}

/// A container's labels, by its name.
pub type Labelled = (String, BTreeMap<String, String>);

/// Routers on containers' labels (`traefik.http.routers.<name>.rule`).
pub fn routers_from_labels(containers: &[Labelled]) -> Vec<Router> {
    let mut routers = Vec::new();
    for (container, labels) in containers {
        if labels.get("traefik.enable").is_some_and(|v| v == "false") {
            continue;
        }
        for (key, value) in labels {
            let Some(name) = key
                .strip_prefix("traefik.http.routers.")
                .and_then(|k| k.strip_suffix(".rule"))
            else {
                continue;
            };
            if routers.len() >= MAX_ROUTERS {
                return routers;
            }
            routers.push(Router {
                name: format!("{name}@docker"),
                hosts: hosts_of(value),
                container: Some(container.clone()),
            });
        }
    }
    routers
}

/// The routers in a Traefik's file provider files.
fn dynamic_routers(process: &WebProcess, setup: &Setup) -> Vec<Router> {
    let (dir, file) = setup.file_provider();
    let mut budget = MAX_DYNAMIC_FILES;
    let mut files = Vec::new();
    if let Some(dir) = dir {
        for pattern in ["*.yml", "*.yaml", "*.toml"] {
            files.extend(glob_in(&process.root, &dir.join(pattern), &mut budget));
        }
    }
    files.extend(file);
    files
        .iter()
        .filter_map(|path| {
            Some(routers_from_dynamic(&read_config(
                path,
                &read_in(&process.root, path)?,
            )))
        })
        .flatten()
        .collect()
}

/// What `load` found.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub setup: Setup,
    pub routers: Vec<Router>,
    /// Where the routers came from, in words.
    pub routers_from: String,
}

/// Reads a Traefik's static config and routers. `address` is how its API
/// is reached from here (the container's address for one in a container);
/// `labelled` the containers on the machine with their labels.
pub async fn load(process: &WebProcess, address: Option<&str>, labelled: &[Labelled]) -> Loaded {
    let setup = static_config(process);
    if let Some(api) = setup.open_api() {
        let port = api.rsplit(':').next().unwrap_or("8080");
        let host = address.unwrap_or("127.0.0.1");
        if let Some(target) = Target::parse(&format!("{host}:{port}")) {
            if let Some(body) = local_http::get(
                &target,
                &format!("{host}:{port}"),
                "/api/http/routers?per_page=1000",
                Duration::from_secs(3),
                8 * 1024 * 1024,
            )
            .await
            {
                if let Ok(value) = serde_json::from_slice::<Value>(&body.bytes) {
                    return Loaded {
                        routers: routers_from_api(&value),
                        routers_from: "its API".into(),
                        setup,
                    };
                }
            }
        }
    }
    let mut routers = dynamic_routers(process, &setup);
    if setup.docker() {
        routers.extend(routers_from_labels(labelled));
    }
    Loaded {
        routers,
        routers_from: "its config and container labels".into(),
        setup,
    }
}

/// What a site's description needs to know about the Traefik it's in.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub container: Option<Container>,
    pub root: PathBuf,
    /// Its static config is a file on this machine.
    pub editable: bool,
}

/// One site per host its routers serve (the http and https routers of one
/// host are one site), or per router for a router with no host.
pub fn sites(loaded: &Loaded, context: &Context) -> Vec<VhostLogs> {
    let setup = &loaded.setup;
    let log = setup.access_log().map(|file| {
        let format = if setup.json() {
            FORMAT_TRAEFIK
        } else {
            FORMAT_TRAEFIK_COMMON
        };
        match (file, &context.container) {
            (Some(path), _) => Some(LogFile {
                target: LogTarget::File(rooted(&context.root, &path)),
                path,
                format: format.into(),
                format_name: None,
            }),
            (None, Some(container)) => Some(LogFile {
                path: PathBuf::from("/dev/stdout"),
                format: format.into(),
                format_name: None,
                target: LogTarget::Container {
                    id: container.id.clone(),
                    stderr: false,
                },
            }),
            (None, None) => None,
        }
    });
    let mut sites: Vec<VhostLogs> = Vec::new();
    for router in &loaded.routers {
        let (short, provider) = router.name.split_once('@').unwrap_or((&router.name, ""));
        if provider == "internal" || short.starts_with("serveros-") || short.starts_with("acme-") {
            continue;
        }
        let names = if router.hosts.is_empty() {
            vec![short.to_ascii_lowercase()]
        } else {
            router.hosts.clone()
        };
        if names
            .iter()
            .all(|h| h == "localhost" || h.ends_with(".localhost"))
        {
            continue;
        }
        let site = match sites
            .iter_mut()
            .find(|s| s.names.iter().any(|n| names.contains(n)))
        {
            Some(site) => site,
            None => {
                sites.push(VhostLogs {
                    server: "traefik".into(),
                    config_path: setup.source.clone(),
                    block: sites.len(),
                    container: context.container.clone(),
                    editable: context.editable && setup.file.is_some(),
                    ..Default::default()
                });
                sites.last_mut().expect("just pushed")
            }
        };
        for name in names {
            if !site.names.contains(&name) {
                site.names.push(name);
            }
        }
        if !site.routers.contains(&router.name) {
            site.routers.push(router.name.clone());
        }
        if let Some(container) = &router.container {
            if !site.upstream_containers.contains(container) {
                site.upstream_containers.push(container.clone());
            }
        }
    }
    for site in &mut sites {
        match &log {
            None => site.unlogged = Some("off".into()),
            Some(None) => site.unlogged = Some("elsewhere".into()),
            Some(Some(file)) => site.logs = vec![file.clone()],
        }
    }
    sites
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn process(args: &[&str], root: &Path) -> WebProcess {
        WebProcess {
            server: "traefik".into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            root: root.to_path_buf(),
            ..Default::default()
        }
    }

    #[test]
    fn rules_name_their_hosts() {
        assert_eq!(
            hosts_of("Host(`shop.test`) || Host(`www.shop.test`)"),
            vec!["shop.test", "www.shop.test"]
        );
        assert_eq!(
            hosts_of("Host(`a.test`, `b.test`) && PathPrefix(`/api`)"),
            vec!["a.test", "b.test"]
        );
        assert_eq!(hosts_of("HostHeader(`old.test`)"), vec!["old.test"]);
        assert!(hosts_of("PathPrefix(`/`)").is_empty());
        assert!(hosts_of("HostRegexp(`.+`)").is_empty());
    }

    /// Coolify's proxy: everything on the command line, routers on labels,
    /// the access log on its output.
    #[test]
    fn a_coolify_style_proxy_in_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let p = process(
            &[
                "traefik",
                "--ping=true",
                "--api.dashboard=true",
                "--api.insecure=false",
                "--entrypoints.http.address=:80",
                "--entrypoints.https.address=:443",
                "--providers.docker.exposedbydefault=false",
                "--accesslog=true",
                "--accesslog.format=json",
            ],
            dir.path(),
        );
        let setup = static_config(&p);
        assert_eq!(setup.source, "its command line");
        assert_eq!(setup.access_log(), Some(None));
        assert!(setup.json() && setup.docker() && setup.open_api().is_none());

        let labels: BTreeMap<String, String> = [
            ("traefik.enable", "true"),
            (
                "traefik.http.routers.http-0-abc.rule",
                "Host(`shop.test`) && PathPrefix(`/`)",
            ),
            (
                "traefik.http.routers.http-0-abc.middlewares",
                "redirect-to-https",
            ),
            (
                "traefik.http.routers.https-0-abc.rule",
                "Host(`shop.test`) && PathPrefix(`/`)",
            ),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let off: BTreeMap<String, String> = [
            ("traefik.enable", "false"),
            ("traefik.http.routers.x.rule", "Host(`hidden.test`)"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let routers = routers_from_labels(&[("shop-app".into(), labels), ("hidden".into(), off)]);
        assert_eq!(routers.len(), 2);
        let loaded = Loaded {
            setup,
            routers,
            routers_from: String::new(),
        };
        let container = Container {
            id: "e".repeat(64),
            name: "coolify-proxy".into(),
        };
        let found = sites(
            &loaded,
            &Context {
                container: Some(container),
                root: dir.path().into(),
                editable: false,
            },
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].names, vec!["shop.test"]);
        assert_eq!(
            found[0].routers,
            vec!["http-0-abc@docker", "https-0-abc@docker"]
        );
        assert_eq!(found[0].upstream_containers, vec!["shop-app"]);
        assert_eq!(
            found[0].logs[0].target,
            LogTarget::Container {
                id: "e".repeat(64),
                stderr: false
            }
        );
        assert!(!found[0].editable);
    }

    /// Traefik on the machine with a YAML static config, a file provider
    /// and no access log: every site is listed as not logged.
    #[test]
    fn a_host_traefik_without_an_access_log() {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc/traefik");
        std::fs::create_dir_all(etc.join("dynamic")).unwrap();
        std::fs::write(
            etc.join("traefik.yml"),
            "entryPoints:\n  web:\n    address: \":80\"\nproviders:\n  file:\n    directory: /etc/traefik/dynamic\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("dynamic/sites.toml"),
            "[http.routers.blog]\n  rule = \"Host(`blog.test`)\"\n  service = \"blog\"\n[http.routers.serveros-shop]\n  rule = \"Host(`shop.test`)\"\n  service = \"shop\"\n",
        )
        .unwrap();
        let p = process(&["traefik"], dir.path());
        let setup = static_config(&p);
        assert_eq!(setup.file, Some(PathBuf::from("/etc/traefik/traefik.yml")));
        assert_eq!(setup.access_log(), None);
        let routers = dynamic_routers(&p, &setup);
        assert_eq!(routers.len(), 2);
        let loaded = Loaded {
            setup,
            routers,
            routers_from: String::new(),
        };
        let found = sites(
            &loaded,
            &Context {
                container: None,
                root: dir.path().into(),
                editable: true,
            },
        );
        assert_eq!(found.len(), 1, "ServerOS's own router is left out");
        assert_eq!(found[0].names, vec!["blog.test"]);
        assert_eq!(found[0].unlogged.as_deref(), Some("off"));
        assert!(found[0].editable);
    }

    #[test]
    fn api_routers_and_a_file_log() {
        let value = json!([
            {"name": "shop@docker", "rule": "Host(`shop.test`)", "status": "enabled", "provider": "docker"},
            {"name": "api@internal", "rule": "PathPrefix(`/api`)", "status": "enabled", "provider": "internal"},
            {"name": "old@file", "rule": "Host(`old.test`)", "status": "disabled"}
        ]);
        let routers = routers_from_api(&value);
        assert_eq!(routers.len(), 2);
        let mut keys = BTreeMap::new();
        flatten(
            &json!({"accessLog": {"filePath": "/logs/access.log", "format": "json"}}),
            "",
            &mut keys,
        );
        let loaded = Loaded {
            setup: Setup {
                source: "/etc/traefik/traefik.yml".into(),
                file: Some("/etc/traefik/traefik.yml".into()),
                keys,
            },
            routers,
            routers_from: "its API".into(),
        };
        let found = sites(
            &loaded,
            &Context {
                container: None,
                root: "/".into(),
                editable: true,
            },
        );
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].logs,
            vec![LogFile::file("/logs/access.log", FORMAT_TRAEFIK, None)]
        );
        // An empty accessLog section turns it on too, in the common format.
        let mut keys = BTreeMap::new();
        flatten(&crate::mini_yaml::parse("accessLog:\n"), "", &mut keys);
        let setup = Setup {
            keys,
            ..Default::default()
        };
        assert_eq!(setup.access_log(), Some(None));
        assert!(!setup.json());
    }
}
