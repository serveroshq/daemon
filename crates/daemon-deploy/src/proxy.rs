use std::path::PathBuf;
use std::time::Duration;

use daemon_core::config::ProxyBackend;
use daemon_jobs::{run_child, Failure, Progress};
use tokio::sync::watch;

pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";
pub const INCLUDE_DIR: &str = "/etc/caddy/serveros.d";
const CADDY_IMPORT_LINE: &str = "import /etc/caddy/serveros.d/*.caddy";

/// Marks the include dir as behind a tunnel (Cloudflare's, say): the edge
/// does HTTPS, so sites are served over plain HTTP. A dotfile without the
/// `.caddy` extension, so the import never picks it up.
const PLAIN_HTTP_MARKER: &str = ".plain-http";

const MANAGED_HEADER: &str = "# Managed by ServerOS.";

/// Where the daemon answers Caddy's on-demand TLS question ("may I get a
/// certificate for this name?"), on loopback only.
pub const ASK_LISTEN: &str = "127.0.0.1:47019";
const ASK_PATH: &str = "/caddy-ask";

const CADDY_INSTALL_SCRIPT: &str = r#"set -eu
export DEBIAN_FRONTEND=noninteractive
if ! command -v apt-get >/dev/null 2>&1; then
  echo "automatic Caddy install needs apt (Debian or Ubuntu)" >&2
  exit 3
fi
apt-get update -q
apt-get install -y -q debian-keyring debian-archive-keyring apt-transport-https curl gnupg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
  | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
  > /etc/apt/sources.list.d/caddy-stable.list
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
apt-get update -q
apt-get install -y -q caddy
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi
systemctl enable --now caddy
"#;

fn fresh_caddyfile() -> String {
    format!(
        "# Installed by ServerOS. Per-service sites live in serveros.d; Caddy\n# gets and renews their certificates on its own.\n{CADDY_IMPORT_LINE}\n"
    )
}

pub const NGINX_CONF: &str = "/etc/nginx/nginx.conf";
pub const NGINX_INCLUDE_DIR: &str = "/etc/nginx/serveros.d";
const NGINX_INCLUDE_LINE: &str = "include /etc/nginx/serveros.d/*.conf;";

pub struct Proxy {
    pub backend: ProxyBackend,
    pub main_config: PathBuf,
    pub include_dir: PathBuf,
}

impl Default for Proxy {
    fn default() -> Self {
        Self::for_backend(ProxyBackend::Caddy)
    }
}

/// A wildcard name, like `*.example.com`: every subdomain one level down.
pub fn is_wildcard(domain: &str) -> bool {
    domain.starts_with("*.")
}

/// Plain names share one site with ordinary automatic HTTPS. Wildcard names
/// get a site of their own with on-demand TLS: each subdomain gets its own
/// certificate the first time it's visited, over the usual HTTP challenge,
/// so no DNS provider is needed. Caddy asks the daemon first (ASK_LISTEN),
/// which only says yes for subdomains of the wildcards in these files.
///
/// Behind a tunnel (`plain_http`) every name, wildcards too, is one plain
/// HTTP site: the tunnel's edge has the certificates, and Caddy neither
/// gets any nor redirects to HTTPS. Apps are told the visitor came over
/// HTTPS, since that's how the edge was reached.
pub fn render(domains: &[String], upstream_port: u16, plain_http: bool) -> Result<String, Failure> {
    validate_domains(domains)?;

    let mut out = format!("{MANAGED_HEADER} Edits here are overwritten on the next deploy.\n");

    if plain_http {
        let names = domains
            .iter()
            .map(|d| format!("http://{d}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str("# Behind a tunnel: plain HTTP here, the tunnel's edge does HTTPS.\n");
        out.push_str(&format!(
            "{names} {{\n\tencode zstd gzip\n\treverse_proxy 127.0.0.1:{upstream_port} {{\n\t\theader_up X-Forwarded-Proto https\n\t}}\n}}\n"
        ));
        return Ok(out);
    }

    let (wildcards, plain): (Vec<&String>, Vec<&String>) =
        domains.iter().partition(|d| is_wildcard(d));
    let join = |names: &[&String]| {
        names
            .iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    if !plain.is_empty() {
        out.push_str(&format!(
            "{} {{\n\tencode zstd gzip\n\treverse_proxy 127.0.0.1:{upstream_port}\n}}\n",
            join(&plain)
        ));
    }
    if !wildcards.is_empty() {
        if !plain.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "{} {{\n\ttls {{\n\t\ton_demand\n\t}}\n\tencode zstd gzip\n\treverse_proxy 127.0.0.1:{upstream_port}\n}}\n",
            join(&wildcards)
        ));
    }

    Ok(out)
}

/// The domains and upstream port of a Caddy site file we wrote, read back
/// so it can be written again in the other mode. None for a file that
/// isn't ours or doesn't look like one of ours.
fn parse_site(text: &str) -> Option<(Vec<String>, u16)> {
    if !text.starts_with(MANAGED_HEADER) {
        return None;
    }

    let mut domains: Vec<String> = Vec::new();
    let mut port = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "}" {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            let addresses = trimmed.strip_suffix('{')?;
            for address in addresses.split(',') {
                let name = address.trim();
                let name = name.strip_prefix("http://").unwrap_or(name);
                if !name.is_empty() && !domains.iter().any(|d| d == name) {
                    domains.push(name.to_string());
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("reverse_proxy 127.0.0.1:") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let found: u16 = digits.parse().ok()?;
            if port.is_some_and(|p| p != found) {
                return None;
            }
            port = Some(found);
        }
    }

    if domains.is_empty() {
        return None;
    }
    Some((domains, port?))
}

pub fn render_nginx(domains: &[String], upstream_port: u16) -> Result<String, Failure> {
    validate_domains(domains)?;

    Ok(format!(
        "# Managed by ServerOS. Edits here are overwritten on the next deploy.\nserver {{\n    listen 80;\n    listen [::]:80;\n    server_name {};\n\n    location / {{\n        proxy_pass http://127.0.0.1:{upstream_port};\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection $connection_upgrade;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }}\n}}\n",
        domains.join(" ")
    ))
}

fn validate_domains(domains: &[String]) -> Result<(), Failure> {
    if domains.is_empty() {
        return Err(
            Failure::new("proxy", "no domains configured for this service")
                .with_next_step("Add a domain to the service in the panel."),
        );
    }

    for d in domains {
        // `*` only as a whole first label, over a name with a dot in it:
        // `*.example.com`, never `*`, `*.com` or `a*.example.com`.
        let rest = d.strip_prefix("*.").unwrap_or(d);
        if rest.is_empty()
            || rest.contains('*')
            || (is_wildcard(d) && !rest.contains('.'))
            || !rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        {
            return Err(Failure::new(
                "proxy",
                format!("{d:?} is not a valid domain"),
            ));
        }
    }

    Ok(())
}

impl Proxy {
    pub fn for_backend(backend: ProxyBackend) -> Self {
        match backend {
            ProxyBackend::Caddy | ProxyBackend::None => Self {
                backend,
                main_config: CADDYFILE.into(),
                include_dir: INCLUDE_DIR.into(),
            },
            ProxyBackend::Nginx => Self {
                backend,
                main_config: NGINX_CONF.into(),
                include_dir: NGINX_INCLUDE_DIR.into(),
            },
        }
    }

    pub fn site_file(&self, service: &str) -> PathBuf {
        let extension = match self.backend {
            ProxyBackend::Nginx => "conf",
            _ => "caddy",
        };

        self.include_dir
            .join(format!("{}.{extension}", crate::git::sanitise(service)))
    }

    fn none_configured() -> Failure {
        Failure::new("proxy", "no reverse proxy is configured on this machine")
            .with_next_step("Set `[integrations] proxy = \"caddy\"` or `\"nginx\"` in daemon.toml, or publish the port yourself.")
    }

    pub async fn ensure_installed(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<bool, Failure> {
        // A caddy binary without its systemd unit (copied in by hand, or
        // left by another tool) can't be started or reloaded: install the
        // package, which brings the unit.
        if self.backend != ProxyBackend::Caddy || (on_path("caddy") && unit_exists("caddy").await) {
            return Ok(false);
        }

        progress
            .line(if on_path("caddy") {
                "Caddy is here but has no systemd service: installing its package for automatic HTTPS".to_string()
            } else {
                "Caddy is not installed: installing it for automatic HTTPS".to_string()
            })
            .await;

        let outcome = run_child(
            "sh",
            &["-c", CADDY_INSTALL_SCRIPT],
            None,
            &[],
            Duration::from_secs(600),
            cancel,
            progress,
            None,
        )
        .await;

        if !outcome.success() {
            return Err(Failure::new("proxy", "could not install Caddy")
                .with_output(outcome.tail().to_vec())
                .with_next_step(
                    "Install Caddy yourself (caddyserver.com/docs/install), then deploy again.",
                ));
        }

        std::fs::write(&self.main_config, fresh_caddyfile()).map_err(|e| {
            Failure::new(
                "proxy",
                format!("could not write {}: {e}", self.main_config.display()),
            )
        })?;

        Ok(true)
    }

    pub fn ensure_import(&self) -> Result<bool, Failure> {
        if self.backend == ProxyBackend::None {
            return Err(Self::none_configured());
        }

        std::fs::create_dir_all(&self.include_dir).map_err(|e| {
            Failure::new(
                "proxy",
                format!("could not create {}: {e}", self.include_dir.display()),
            )
        })?;

        let existing = std::fs::read_to_string(&self.main_config).unwrap_or_default();
        let updated = match self.backend {
            ProxyBackend::Nginx => add_nginx_include(&existing),
            _ => add_caddy_import(&existing),
        };

        let Some(updated) = updated else {
            return Ok(false);
        };

        std::fs::write(&self.main_config, updated).map_err(|e| {
            Failure::new(
                "proxy",
                format!("could not update {}: {e}", self.main_config.display()),
            )
        })?;

        Ok(true)
    }

    pub async fn publish(
        &self,
        service: &str,
        domains: &[String],
        upstream_port: u16,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<PathBuf, Failure> {
        let plain_http = self.plain_http();
        let rendered = match self.backend {
            ProxyBackend::Caddy => render(domains, upstream_port, plain_http)?,
            ProxyBackend::Nginx => render_nginx(domains, upstream_port)?,
            ProxyBackend::None => return Err(Self::none_configured()),
        };
        let site = self.site_file(service);
        let previous = std::fs::read(&site).ok();

        // Wildcards need Caddy told where to ask before it issues a
        // certificate, in the Caddyfile's global options.
        let mut previous_main = None;
        if self.backend == ProxyBackend::Caddy
            && !plain_http
            && domains.iter().any(|d| is_wildcard(d))
        {
            let existing = std::fs::read_to_string(&self.main_config).unwrap_or_default();
            if let Some(updated) = add_on_demand_ask(&existing) {
                std::fs::write(&self.main_config, updated).map_err(|e| {
                    Failure::new(
                        "proxy",
                        format!("could not update {}: {e}", self.main_config.display()),
                    )
                })?;
                previous_main = Some(existing);
                progress
                    .line(
                        "Letting Caddy get a certificate for each subdomain as it's first visited"
                            .to_string(),
                    )
                    .await;
            } else if !has_our_ask(&existing) {
                progress
                    .line("The Caddyfile already sets on_demand_tls: subdomain certificates follow its rules, not ServerOS's".to_string())
                    .await;
            }
        }

        std::fs::write(&site, &rendered).map_err(|e| {
            Failure::new("proxy", format!("could not write {}: {e}", site.display()))
        })?;

        if let Err(failure) = self.validate(cancel, progress).await {
            match previous {
                Some(bytes) => {
                    let _ = std::fs::write(&site, bytes);
                }
                None => {
                    let _ = std::fs::remove_file(&site);
                }
            }
            if let Some(main) = previous_main {
                let _ = std::fs::write(&self.main_config, main);
            }
            return Err(failure);
        }

        self.reload(cancel, progress).await?;

        Ok(site)
    }

    /// Whether sites are served over plain HTTP, for a tunnel in front.
    pub fn plain_http(&self) -> bool {
        self.include_dir.join(PLAIN_HTTP_MARKER).exists()
    }

    /// Switches every site to plain HTTP (a tunnel in front does HTTPS) or
    /// back to Caddy's own HTTPS, rewriting the site files ServerOS wrote and
    /// reloading the proxy. If the new config doesn't validate, the files
    /// and the mode are put back as they were. Nginx sites are plain HTTP
    /// already, so only the mode is kept there.
    pub async fn set_plain_http(
        &self,
        on: bool,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        if self.backend == ProxyBackend::None {
            return Ok(());
        }

        let was_on = self.plain_http();
        std::fs::create_dir_all(&self.include_dir).map_err(|e| {
            Failure::new(
                "proxy",
                format!("could not create {}: {e}", self.include_dir.display()),
            )
        })?;
        let marker = self.include_dir.join(PLAIN_HTTP_MARKER);
        let set_marker = |on: bool| -> std::io::Result<()> {
            if on {
                std::fs::write(
                    &marker,
                    "Written by ServerOS: a tunnel in front of this machine does HTTPS, so sites here are plain HTTP.\n",
                )
            } else {
                match std::fs::remove_file(&marker) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                    _ => Ok(()),
                }
            }
        };

        let rewrites = if self.backend == ProxyBackend::Caddy {
            self.rerendered(on)
        } else {
            Vec::new()
        };

        set_marker(on).map_err(|e| {
            Failure::new(
                "proxy",
                format!("could not update {}: {e}", marker.display()),
            )
        })?;
        if rewrites.is_empty() {
            return Ok(());
        }

        progress
            .line(if on {
                format!(
                    "Serving {} site(s) over plain HTTP for the tunnel",
                    rewrites.len()
                )
            } else {
                format!("Serving {} site(s) over HTTPS again", rewrites.len())
            })
            .await;

        let put_back = |rewrites: &[(PathBuf, String, String)]| {
            for (path, before, _) in rewrites {
                let _ = std::fs::write(path, before);
            }
            let _ = set_marker(was_on);
        };
        for (path, _, after) in &rewrites {
            if let Err(e) = std::fs::write(path, after) {
                put_back(&rewrites);
                return Err(Failure::new(
                    "proxy",
                    format!("could not write {}: {e}", path.display()),
                ));
            }
        }

        if let Err(failure) = self.validate(cancel, progress).await {
            put_back(&rewrites);
            return Err(failure);
        }

        self.reload(cancel, progress).await
    }

    /// Every site file ServerOS wrote, as it reads now and as it would in
    /// the given mode, for the ones that would change.
    fn rerendered(&self, plain_http: bool) -> Vec<(PathBuf, String, String)> {
        let Ok(entries) = std::fs::read_dir(&self.include_dir) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "caddy"))
            .collect();
        paths.sort();

        paths
            .into_iter()
            .filter_map(|path| {
                let before = std::fs::read_to_string(&path).ok()?;
                let (domains, port) = parse_site(&before)?;
                let after = render(&domains, port, plain_http).ok()?;
                (after != before).then_some((path, before, after))
            })
            .collect()
    }

    pub async fn unpublish(
        &self,
        service: &str,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let site = self.site_file(service);

        if site.exists() {
            std::fs::remove_file(&site).map_err(|e| {
                Failure::new("proxy", format!("could not remove {}: {e}", site.display()))
            })?;

            if self.backend != ProxyBackend::None {
                self.reload(cancel, progress).await?;
            }
        }

        Ok(())
    }

    async fn validate(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let main = self.main_config.to_string_lossy().into_owned();
        let (program, args): (&str, Vec<&str>) = match self.backend {
            ProxyBackend::Nginx => ("nginx", vec!["-t", "-c", &main]),
            _ => (
                "caddy",
                vec!["validate", "--config", &main, "--adapter", "caddyfile"],
            ),
        };

        let outcome = run_child(
            program,
            &args,
            None,
            &[],
            Duration::from_secs(30),
            cancel,
            progress,
            None,
        )
        .await;

        if outcome.success() {
            Ok(())
        } else {
            Err(Failure::new(
                "proxy",
                "the new proxy config did not validate; the previous config is still in place",
            )
            .with_output(outcome.tail().to_vec()))
        }
    }

    async fn reload(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let main = self.main_config.to_string_lossy().into_owned();
        let (program, args, unit): (&str, Vec<&str>, &str) = match self.backend {
            ProxyBackend::Nginx => ("nginx", vec!["-s", "reload", "-c", &main], "nginx"),
            _ => (
                "caddy",
                vec!["reload", "--config", &main, "--adapter", "caddyfile"],
                "caddy",
            ),
        };

        // A stopped proxy can't reload (Caddy's reload talks to the running
        // one on localhost:2019). Starting it loads the same config.
        if !unit_active(unit).await {
            progress
                .line(format!("{unit} is not running: starting it"))
                .await;
            let started = run_child(
                "systemctl",
                &["enable", "--now", unit],
                None,
                &[],
                Duration::from_secs(60),
                cancel,
                progress,
                None,
            )
            .await;
            if started.success() && unit_active(unit).await {
                return Ok(());
            }

            let journal = run_child(
                "journalctl",
                &["-u", unit, "-n", "20", "--no-pager"],
                None,
                &[],
                Duration::from_secs(15),
                cancel,
                progress,
                None,
            )
            .await;
            return Err(
                Failure::new("proxy", format!("{unit} is not running and would not start"))
                    .with_output(journal.tail().to_vec())
                    .with_next_step(format!(
                        "Something else may be using port 80 or 443 (`ss -ltnp` shows what), or the config has an error. `journalctl -u {unit}` says which."
                    )),
            );
        }

        let outcome = run_child(
            program,
            &args,
            None,
            &[],
            Duration::from_secs(60),
            cancel,
            progress,
            None,
        )
        .await;

        if outcome.success() {
            Ok(())
        } else {
            Err(Failure::new("proxy", format!("{program} reload failed"))
                .with_output(outcome.tail().to_vec())
                .with_next_step(format!("Check `systemctl status {unit}` on the machine.")))
        }
    }
}

/// Whether systemd knows the unit at all.
async fn unit_exists(unit: &str) -> bool {
    tokio::process::Command::new("systemctl")
        .args(["cat", "--", &format!("{unit}.service")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Whether systemd says the unit is running (still starting counts as no).
async fn unit_active(unit: &str) -> bool {
    tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(program).is_file()))
        .unwrap_or(false)
}

impl Proxy {
    /// Caddy's on-demand question: may `host` have a certificate? Only a
    /// name exactly one label under a wildcard in one of our site files,
    /// so `shop.example.com` under `*.example.com`, but not the apex,
    /// `a.b.example.com`, or anything we don't serve.
    pub fn allows_on_demand(&self, host: &str) -> bool {
        if self.backend != ProxyBackend::Caddy {
            return false;
        }
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let Some((label, parent)) = host.split_once('.') else {
            return false;
        };
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }

        let Ok(entries) = std::fs::read_dir(&self.include_dir) else {
            return false;
        };
        entries
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "caddy"))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .any(|text| wildcard_parents(&text).iter().any(|p| *p == parent))
    }
}

/// The parents of the wildcard site addresses in a site file we wrote:
/// `example.com` for a `*.example.com {` line.
fn wildcard_parents(site_file: &str) -> Vec<String> {
    site_file
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace) && !l.trim_start().starts_with('#'))
        .filter_map(|l| l.trim_end().strip_suffix('{'))
        .flat_map(|addresses| {
            addresses
                .split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter_map(|a| a.strip_prefix("*.").map(|p| p.to_ascii_lowercase()))
        .collect()
}

fn ask_line() -> String {
    format!("ask http://{ASK_LISTEN}{ASK_PATH}")
}

fn has_our_ask(caddyfile: &str) -> bool {
    caddyfile.contains(&ask_line())
}

/// Adds `on_demand_tls { ask … }` to the Caddyfile's global options, which
/// must be its first block: into the block if there is one, or as a new
/// one at the top. Leaves a Caddyfile that already sets on_demand_tls
/// alone, since those rules are the operator's.
fn add_on_demand_ask(existing: &str) -> Option<String> {
    if existing.contains("on_demand_tls") {
        return None;
    }
    let ours = format!(
        "\t# Added by ServerOS: the daemon says which subdomains may get a certificate.\n\ton_demand_tls {{\n\t\t{}\n\t}}\n",
        ask_line()
    );

    // The global options block is a `{` alone on the first line that isn't
    // blank or a comment.
    let mut offset = 0;
    for line in existing.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += line.len();
            continue;
        }
        if trimmed == "{" {
            let at = offset + line.len();
            let mut updated = String::with_capacity(existing.len() + ours.len() + 1);
            updated.push_str(&existing[..at]);
            if !line.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(&ours);
            updated.push_str(&existing[at..]);
            return Some(updated);
        }
        break;
    }

    Some(format!("{{\n{ours}}}\n\n{existing}"))
}

fn add_caddy_import(existing: &str) -> Option<String> {
    if existing.lines().any(|l| l.trim() == CADDY_IMPORT_LINE) {
        return None;
    }

    let mut updated = existing.to_string();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("\n# Added by ServerOS: per-service sites live in serveros.d.\n");
    updated.push_str(CADDY_IMPORT_LINE);
    updated.push('\n');

    Some(updated)
}

fn add_nginx_include(existing: &str) -> Option<String> {
    if existing.lines().any(|l| l.trim() == NGINX_INCLUDE_LINE) {
        return None;
    }

    let http_start = existing.find("http {").or_else(|| existing.find("http{"))?;
    let close = existing[http_start..].rfind("\n}")? + http_start + 1;

    let mut updated = String::with_capacity(existing.len() + 80);
    updated.push_str(&existing[..close]);
    updated.push_str("    # Added by ServerOS: per-service sites live in serveros.d.\n    ");
    updated.push_str(NGINX_INCLUDE_LINE);
    updated.push('\n');
    updated.push_str(&existing[close..]);

    Some(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caddy_serveros_installs_imports_only_our_sites() {
        let caddyfile = fresh_caddyfile();

        assert!(caddyfile.lines().any(|l| l == CADDY_IMPORT_LINE));
        assert!(add_caddy_import(&caddyfile).is_none());
        assert!(!caddyfile.contains(":80"));
    }

    #[test]
    fn installing_caddy_opens_the_ports_its_certificates_need() {
        assert!(CADDY_INSTALL_SCRIPT.contains("apt-get install -y -q caddy"));
        assert!(CADDY_INSTALL_SCRIPT.contains("ufw allow 80/tcp"));
        assert!(CADDY_INSTALL_SCRIPT.contains("ufw allow 443/tcp"));
        assert!(CADDY_INSTALL_SCRIPT.contains("systemctl enable --now caddy"));
    }

    #[test]
    fn caddy_sites_are_rendered_from_validated_domains() {
        let block = render(
            &["shop.example".into(), "www.shop.example".into()],
            3000,
            false,
        )
        .unwrap();

        assert!(block.contains("shop.example, www.shop.example {"));
        assert!(block.contains("reverse_proxy 127.0.0.1:3000"));
        assert!(render(&["bad{domain".into()], 3000, false).is_err());
        assert!(render(&[], 3000, false).is_err());
    }

    #[test]
    fn wildcards_get_their_own_on_demand_site() {
        let block = render(&["acme.io".into(), "*.acme.io".into()], 3000, false).unwrap();

        let (apex, wild) = block.split_once("*.acme.io {").unwrap();
        assert!(apex.contains("acme.io {\n\tencode"));
        assert!(!apex.contains("on_demand"));
        assert!(wild.contains("tls {\n\t\ton_demand\n\t}"));
        assert!(wild.contains("reverse_proxy 127.0.0.1:3000"));

        let only = render(&["*.acme.io".into()], 3000, false).unwrap();
        assert!(only.contains("*.acme.io {\n\ttls"));
        assert!(!only.contains("encode zstd gzip\n\treverse_proxy 127.0.0.1:3000\n}\n\n"));
    }

    #[test]
    fn a_star_is_only_a_whole_first_label() {
        for bad in ["*", "*.com", "a*.acme.io", "*.*.acme.io", "acme.*.io", "*."] {
            assert!(render(&[bad.into()], 3000, false).is_err(), "{bad}");
        }
        assert!(render(&["*.acme.io".into()], 3000, false).is_ok());
        assert!(render(&["*.eu.acme.io".into()], 3000, false).is_ok());
    }

    #[test]
    fn the_ask_goes_into_existing_global_options() {
        let with_globals = "# mine\n{\n\temail ops@acme.io\n}\n\nacme.io {\n}\n";
        let updated = add_on_demand_ask(with_globals).unwrap();

        assert!(updated.starts_with("# mine\n{\n\t# Added by ServerOS"));
        assert!(updated.contains(&ask_line()));
        assert!(updated.contains("\temail ops@acme.io\n}"));
        assert_eq!(
            updated.matches('{').count(),
            with_globals.matches('{').count() + 1
        );
        assert!(add_on_demand_ask(&updated).is_none());
    }

    #[test]
    fn the_ask_opens_a_global_block_when_there_is_none() {
        let updated = add_on_demand_ask(&fresh_caddyfile()).unwrap();

        assert!(updated.starts_with("{\n\t# Added by ServerOS"));
        assert!(updated.contains(CADDY_IMPORT_LINE));
        assert!(has_our_ask(&updated));
        assert!(add_on_demand_ask("{\n\ton_demand_tls {\n\t\task http://x\n\t}\n}\n").is_none());
    }

    #[test]
    fn caddy_may_only_ask_for_one_label_under_a_wildcard_we_serve() {
        let dir = std::env::temp_dir().join(format!("serveros-ask-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("shop.caddy"),
            render(&["acme.io".into(), "*.acme.io".into()], 3000, false).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), "*.other.io {\n}\n").unwrap();
        let proxy = Proxy {
            backend: ProxyBackend::Caddy,
            main_config: dir.join("Caddyfile"),
            include_dir: dir.clone(),
        };

        assert!(proxy.allows_on_demand("tenant-1.acme.io"));
        assert!(proxy.allows_on_demand("Tenant-1.ACME.io."));
        assert!(!proxy.allows_on_demand("acme.io"));
        assert!(!proxy.allows_on_demand("a.b.acme.io"));
        assert!(!proxy.allows_on_demand("x.other.io"));
        assert!(!proxy.allows_on_demand("-x.acme.io"));
        assert!(!proxy.allows_on_demand("evil.io"));
        assert!(!Proxy {
            backend: ProxyBackend::Nginx,
            ..proxy
        }
        .allows_on_demand("tenant-1.acme.io"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn behind_a_tunnel_every_name_is_one_plain_http_site() {
        let block = render(&["acme.io".into(), "*.acme.io".into()], 3000, true).unwrap();

        assert!(block.starts_with(MANAGED_HEADER));
        assert!(block.contains("http://acme.io, http://*.acme.io {"));
        assert!(block.contains("reverse_proxy 127.0.0.1:3000 {"));
        assert!(block.contains("header_up X-Forwarded-Proto https"));
        assert!(!block.contains("on_demand"));
        assert_eq!(block.matches(" {\n\tencode").count(), 1);
        assert!(render(&["bad{domain".into()], 3000, true).is_err());
    }

    #[test]
    fn site_files_read_back_in_either_mode() {
        let domains: Vec<String> = vec!["acme.io".into(), "*.acme.io".into(), "www.acme.io".into()];
        for plain_http in [false, true] {
            let text = render(&domains, 4123, plain_http).unwrap();
            let (read, port) = parse_site(&text).unwrap();
            assert_eq!(port, 4123);
            let mut read = read;
            read.sort();
            let mut expected = domains.clone();
            expected.sort();
            assert_eq!(read, expected, "{text}");
        }

        assert!(parse_site("shop.example {\n\treverse_proxy 127.0.0.1:3000\n}\n").is_none());
        assert!(parse_site(&format!("{MANAGED_HEADER}\nshop.example {{\n}}\n")).is_none());
        assert!(parse_site(&format!(
            "{MANAGED_HEADER}\na.io {{\n\treverse_proxy 127.0.0.1:1\n}}\nb.io {{\n\treverse_proxy 127.0.0.1:2\n}}\n"
        ))
        .is_none());
    }

    #[test]
    fn switching_modes_rewrites_only_our_sites() {
        let dir = std::env::temp_dir().join(format!("serveros-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ours = render(&["acme.io".into(), "*.acme.io".into()], 3000, false).unwrap();
        std::fs::write(dir.join("shop.caddy"), &ours).unwrap();
        std::fs::write(dir.join("mine.caddy"), "mine.io {\n\trespond hi\n}\n").unwrap();
        let proxy = Proxy {
            backend: ProxyBackend::Caddy,
            main_config: dir.join("Caddyfile"),
            include_dir: dir.clone(),
        };

        assert!(!proxy.plain_http());
        let to_plain = proxy.rerendered(true);
        assert_eq!(to_plain.len(), 1);
        assert_eq!(to_plain[0].0, dir.join("shop.caddy"));
        assert!(to_plain[0].2.contains("http://acme.io, http://*.acme.io {"));

        std::fs::write(dir.join("shop.caddy"), &to_plain[0].2).unwrap();
        let back = proxy.rerendered(false);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].2, ours);
        assert!(proxy.rerendered(true).is_empty());

        std::fs::write(dir.join(PLAIN_HTTP_MARKER), "").unwrap();
        assert!(proxy.plain_http());
        assert!(!proxy.allows_on_demand("tenant-1.acme.io"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn nginx_and_no_proxy_only_keep_the_mode() {
        let dir = std::env::temp_dir().join(format!("serveros-plain-nginx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let proxy = Proxy {
            backend: ProxyBackend::Nginx,
            main_config: dir.join("nginx.conf"),
            include_dir: dir.clone(),
        };
        let (_tx, mut cancel) = watch::channel(false);
        let state = std::sync::Arc::new(daemon_state::State::in_memory().unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let progress = Progress::new(uuid::Uuid::new_v4(), state, tx, vec![]);

        proxy
            .set_plain_http(true, &mut cancel, &progress)
            .await
            .unwrap();
        assert!(proxy.plain_http());
        proxy
            .set_plain_http(false, &mut cancel, &progress)
            .await
            .unwrap();
        assert!(!proxy.plain_http());

        let none = Proxy {
            backend: ProxyBackend::None,
            ..proxy
        };
        none.set_plain_http(true, &mut cancel, &progress)
            .await
            .unwrap();
        assert!(!none.plain_http());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nginx_sites_are_server_blocks() {
        let block = render_nginx(&["shop.example".into()], 3000).unwrap();

        assert!(block.contains("server_name shop.example;"));
        assert!(block.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(render_nginx(&["a;b".into()], 3000).is_err());
    }

    #[test]
    fn backends_pick_their_directories_and_extensions() {
        let caddy = Proxy::for_backend(ProxyBackend::Caddy);
        let nginx = Proxy::for_backend(ProxyBackend::Nginx);

        assert_eq!(
            caddy.site_file("shop"),
            PathBuf::from("/etc/caddy/serveros.d/shop.caddy")
        );
        assert_eq!(
            nginx.site_file("shop"),
            PathBuf::from("/etc/nginx/serveros.d/shop.conf")
        );
        assert!(Proxy::for_backend(ProxyBackend::None)
            .ensure_import()
            .is_err());
    }

    #[test]
    fn the_caddy_import_is_added_once() {
        let first = add_caddy_import("example.com {\n}\n").unwrap();

        assert!(first.contains(CADDY_IMPORT_LINE));
        assert!(add_caddy_import(&first).is_none());
    }

    #[test]
    fn the_nginx_include_lands_inside_the_http_block() {
        let conf = "user www-data;\nevents {\n    worker_connections 768;\n}\n\nhttp {\n    sendfile on;\n    include /etc/nginx/conf.d/*.conf;\n}\n";
        let updated = add_nginx_include(conf).unwrap();

        let include_at = updated.find(NGINX_INCLUDE_LINE).unwrap();
        let http_close = updated.rfind("\n}").unwrap();
        assert!(include_at < http_close, "{updated}");
        assert!(updated.ends_with("}\n"));
        assert!(add_nginx_include(&updated).is_none());
        assert!(add_nginx_include("events {}\n").is_none());
    }
}
