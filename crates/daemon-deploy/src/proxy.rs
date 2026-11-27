use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_core::config::ProxyBackend;
use daemon_jobs::{run_child, Failure, Progress};
use tokio::sync::watch;

use crate::site_options::{self, SiteOptions, MAINTENANCE_PORT, SITES_DIR};
use crate::traffic::{self, APACHE_LOG_FORMAT, TRAEFIK_LOG, TRAFFIC_LOG_DIR};

pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";
pub const INCLUDE_DIR: &str = "/etc/caddy/serveros.d";
const CADDY_IMPORT_LINE: &str = "import /etc/caddy/serveros.d/*.caddy";

/// Marks the include dir as behind a tunnel (Cloudflare's, say): the edge
/// does HTTPS, so sites are served over plain HTTP. A dotfile without the
/// `.caddy` extension, so the import never picks it up.
const PLAIN_HTTP_MARKER: &str = ".plain-http";

const MANAGED_HEADER: &str = "# Managed by ServerOS.";

/// Marks traffic as on for every site here, beside the site switches.
const TRAFFIC_MARKER: &str = ".traffic";

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
/// Settings every nginx site of ours shares. Sorts before any site file,
/// since nginx wants a variable defined before a server block uses it.
const NGINX_SHARED_FILE: &str = "00-serveros.conf";
const NGINX_SHARED: &str = "# Written by ServerOS: settings the sites in serveros.d share.\nmap $http_upgrade $serveros_connection_upgrade {\n    default upgrade;\n    ''      close;\n}\n\n# The access log sites write when traffic is on (unused until then).\nlog_format serveros_traffic escape=json '{\"t\":$msec,\"host\":\"$host\",\"ip\":\"$remote_addr\",\"uri\":\"$request_uri\",\"status\":$status,\"bytes\":$body_bytes_sent,\"time\":$request_time,\"referer\":\"$http_referer\",\"ua\":\"$http_user_agent\"}';\n";

pub const APACHE_CONF: &str = "/etc/apache2/apache2.conf";
pub const APACHE_INCLUDE_DIR: &str = "/etc/apache2/serveros.d";
const APACHE_INCLUDE_LINE: &str = "IncludeOptional /etc/apache2/serveros.d/*.conf";
const APACHE_MODULES: [&str; 6] = [
    "proxy",
    "proxy_http",
    "proxy_wstunnel",
    "headers",
    "rewrite",
    "ssl",
];

pub const TRAEFIK_CONF: &str = "/etc/traefik/traefik.toml";
pub const TRAEFIK_INCLUDE_DIR: &str = "/etc/traefik/serveros.d";
/// The certificate resolver Traefik sites of ours ask for certificates.
const TRAEFIK_RESOLVER: &str = "serveros";
const TRAEFIK_OTHER_CONFIGS: [&str; 2] = ["/etc/traefik/traefik.yml", "/etc/traefik/traefik.yaml"];

/// Where certbot answers Let's Encrypt's HTTP challenge for nginx and
/// Apache sites, and where their certificates end up.
/// Outside /var/lib/serveros, which only root may enter: nginx and Apache
/// run as www-data and have to read the challenge files.
pub const ACME_WEBROOT: &str = "/var/lib/serveros-acme";
pub const LETSENCRYPT_LIVE: &str = "/etc/letsencrypt/live";

/// A line in every site file we write, so any proxy can read the site back
/// (to move it to another proxy, or switch it to plain HTTP).
const SITE_META: &str = "# ServerOS site:";

/// How long a proxy has to stay up after a switch before the old one is
/// let go.
const SETTLE: Duration = Duration::from_secs(4);

const NGINX_INSTALL_SCRIPT: &str = r#"set -eu
export DEBIAN_FRONTEND=noninteractive
if ! command -v apt-get >/dev/null 2>&1; then
  echo "automatic nginx install needs apt (Debian or Ubuntu)" >&2
  exit 3
fi
apt-get update -q
apt-get install -y -q nginx certbot
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi
systemctl enable --now nginx
"#;

const APACHE_INSTALL_SCRIPT: &str = r#"set -eu
export DEBIAN_FRONTEND=noninteractive
if ! command -v apt-get >/dev/null 2>&1; then
  echo "automatic Apache install needs apt (Debian or Ubuntu)" >&2
  exit 3
fi
apt-get update -q
apt-get install -y -q apache2 certbot
a2enmod -q proxy proxy_http proxy_wstunnel headers rewrite ssl
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi
systemctl enable --now apache2
systemctl reload apache2
"#;

/// Traefik isn't in Debian's or Ubuntu's archives: the latest v3 release
/// from GitHub, checked against its published checksums, run as its own
/// user with only the right to bind ports 80 and 443. Started once
/// ServerOS has written its config.
const TRAEFIK_INSTALL_SCRIPT: &str = r#"set -eu
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "there's no Traefik build for $(uname -m)" >&2; exit 3 ;;
esac
latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/traefik/traefik/releases/latest)
tag=${latest##*/}
case "$tag" in
  v3.*) ;;
  *) echo "unexpected Traefik release: $tag" >&2; exit 3 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
file="traefik_${tag}_linux_${arch}.tar.gz"
base="https://github.com/traefik/traefik/releases/download/$tag"
curl -fsSL "$base/$file" -o "$tmp/$file"
curl -fsSL "$base/traefik_${tag}_checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && grep " $file\$" checksums.txt | sha256sum -c -)
tar -xzf "$tmp/$file" -C "$tmp" traefik
install -m 0755 "$tmp/traefik" /usr/local/bin/traefik
id traefik >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin traefik
install -d -o traefik -g traefik -m 0750 /var/lib/traefik
install -d -m 0755 /etc/traefik /etc/traefik/serveros.d
cat > /etc/systemd/system/traefik.service <<'UNIT'
[Unit]
Description=Traefik (installed by ServerOS)
After=network-online.target
Wants=network-online.target

[Service]
User=traefik
Group=traefik
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/traefik --configFile=/etc/traefik/traefik.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi
"#;

fn fresh_traefik_config() -> String {
    format!(
        "# Installed by ServerOS. Per-service sites live in serveros.d; Traefik\n# gets and renews their certificates on its own.\n[entryPoints.web]\n  address = \":80\"\n\n[entryPoints.websecure]\n  address = \":443\"\n\n[certificatesResolvers.{TRAEFIK_RESOLVER}.acme]\n  storage = \"/var/lib/traefik/acme.json\"\n  [certificatesResolvers.{TRAEFIK_RESOLVER}.acme.httpChallenge]\n    entryPoint = \"web\"\n\n[providers.file]\n  directory = \"{TRAEFIK_INCLUDE_DIR}\"\n  watch = true\n"
    )
}

#[derive(Debug, Clone)]
pub struct Proxy {
    pub backend: ProxyBackend,
    pub main_config: PathBuf,
    pub include_dir: PathBuf,
    /// Where certbot keeps the certificates for nginx and Apache sites.
    pub cert_root: PathBuf,
    /// Where each app's site switches are kept (site_options), whichever
    /// proxy serves it.
    pub sites_dir: PathBuf,
    /// Where sites write the access logs traffic is counted from, when
    /// it's on.
    pub traffic_dir: PathBuf,
}

/// One app's site: the names it answers to and the port on the machine it
/// sends them to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub domains: Vec<String>,
    pub port: u16,
    /// False for a site served over plain HTTP by choice: no certificate,
    /// no redirect.
    pub https: bool,
}

/// What an app's site switches add to its config, worked out once for
/// every proxy. All off adds nothing: a site without switches is written
/// byte for byte as it was before there were any.
#[derive(Debug, Clone, Default)]
struct Switches {
    options: SiteOptions,
    /// The first plain domain, where a www redirect sends visitors.
    canonical: Option<String>,
    /// The www (or bare) name that redirects to it.
    alias: Option<String>,
    /// The password file nginx and Apache read; Caddy and Traefik take the
    /// hash in their config.
    auth_file: Option<PathBuf>,
    /// The access log this site writes, when traffic is on (Traefik keeps
    /// one for every site, in its own config).
    access_log: Option<PathBuf>,
}

impl Switches {
    fn new(domains: &[String], options: SiteOptions, auth_file: Option<PathBuf>) -> Self {
        let canonical = domains.iter().find(|d| !is_wildcard(d)).cloned();
        let alias = if options.www_redirect {
            canonical
                .as_deref()
                .and_then(site_options::counterpart)
                .filter(|a| !domains.iter().any(|d| d == a))
        } else {
            None
        };
        let auth_file = auth_file.filter(|_| options.basic_auth.is_some());
        Self {
            options,
            canonical,
            alias,
            auth_file,
            access_log: None,
        }
    }

    fn with_access_log(mut self, access_log: Option<PathBuf>) -> Self {
        self.access_log = access_log;
        self
    }

    /// Where visitors go: the app, or the daemon's maintenance page.
    fn port(&self, upstream_port: u16) -> u16 {
        if self.options.maintenance {
            MAINTENANCE_PORT
        } else {
            upstream_port
        }
    }

    /// The alias and the name it redirects to, when there's one.
    fn www(&self) -> Option<(&str, &str)> {
        Some((self.alias.as_deref()?, self.canonical.as_deref()?))
    }

    /// Names a site's plain block answers to: its own and the alias.
    fn with_alias<'a>(&'a self, names: &[&'a String]) -> Vec<&'a String> {
        let mut all = names.to_vec();
        if let Some(alias) = &self.alias {
            if !names.is_empty() {
                all.push(alias);
            }
        }
        all
    }
}

fn status(permanent: bool) -> u16 {
    if permanent {
        301
    } else {
        302
    }
}

/// A plain name or path as a regular expression matching only itself.
fn regex_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(
            c,
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn meta_line(domains: &[String], upstream_port: u16) -> String {
    format!(
        "{SITE_META} port={upstream_port} domains={}\n",
        domains.join(",")
    )
}

fn parse_meta(text: &str) -> Option<Site> {
    let rest = text.lines().find_map(|l| l.strip_prefix(SITE_META))?;
    let mut port = None;
    let mut domains = Vec::new();
    let mut https = true;
    for part in rest.split_whitespace() {
        if let Some(p) = part.strip_prefix("port=") {
            port = p.parse().ok();
        } else if part == "https=off" {
            https = false;
        } else if let Some(d) = part.strip_prefix("domains=") {
            domains = d
                .split(',')
                .filter(|d| !d.is_empty())
                .map(str::to_string)
                .collect();
        }
    }
    (!domains.is_empty()).then_some(Site {
        domains,
        port: port?,
        https,
    })
}

/// An nginx site written before site files said what they were: its
/// server_name and proxy_pass.
fn parse_nginx_legacy(text: &str) -> Option<Site> {
    let mut domains: Vec<String> = Vec::new();
    let mut port = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(names) = line.strip_prefix("server_name ") {
            for name in names.trim_end_matches(';').split_whitespace() {
                if !domains.iter().any(|d| d == name) {
                    domains.push(name.to_string());
                }
            }
        } else if let Some(rest) = line.strip_prefix("proxy_pass http://127.0.0.1:") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            port = digits.parse().ok();
        }
    }
    (!domains.is_empty()).then_some(Site {
        domains,
        port: port?,
        https: true,
    })
}

/// A site file we wrote, read back. None for anyone else's file.
fn read_site(backend: ProxyBackend, text: &str) -> Option<Site> {
    if !text.starts_with(MANAGED_HEADER) {
        return None;
    }
    parse_meta(text).or_else(|| match backend {
        ProxyBackend::Caddy => parse_site(text).map(|(domains, port)| Site {
            domains,
            port,
            https: true,
        }),
        ProxyBackend::Nginx => parse_nginx_legacy(text),
        _ => None,
    })
}

fn split_wildcards(domains: &[String]) -> (Vec<&String>, Vec<&String>) {
    domains.iter().partition(|d| is_wildcard(d))
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
    render_caddy(domains, upstream_port, plain_http, &Switches::default())
}

/// What goes inside a Caddy site block: redirects first, then the
/// password, then the app (or the maintenance page).
fn caddy_body(switches: &Switches, upstream_port: u16, forwarded_https: bool) -> String {
    let mut out = String::new();
    if let Some(file) = &switches.access_log {
        // Rolled at 50 MiB (one backup), in case the daemon isn't there to
        // read and empty it.
        out.push_str(&format!(
            "\tlog {{\n\t\toutput file {} {{\n\t\t\troll_size 50MiB\n\t\t\troll_keep 1\n\t\t\troll_uncompressed\n\t\t}}\n\t\tformat json\n\t}}\n",
            file.display()
        ));
    }
    for r in &switches.options.redirects {
        out.push_str(&format!(
            "\tredir {} {} {}\n",
            r.from,
            r.to,
            if r.permanent {
                "permanent"
            } else {
                "temporary"
            }
        ));
    }
    if let Some(auth) = &switches.options.basic_auth {
        out.push_str(&format!(
            "\tbasicauth {{\n\t\t{} {}\n\t}}\n",
            auth.user, auth.hash
        ));
    }
    out.push_str("\tencode zstd gzip\n");
    let port = switches.port(upstream_port);
    if forwarded_https {
        out.push_str(&format!(
            "\treverse_proxy 127.0.0.1:{port} {{\n\t\theader_up X-Forwarded-Proto https\n\t}}\n"
        ));
    } else {
        out.push_str(&format!("\treverse_proxy 127.0.0.1:{port}\n"));
    }
    out
}

/// A block of its own for the www alias, sending it to the main name.
fn caddy_alias(switches: &Switches, address_prefix: &str, scheme: &str) -> String {
    match switches.www() {
        Some((alias, canonical)) => format!(
            "\n{address_prefix}{alias} {{\n\tredir {scheme}://{canonical}{{uri}} permanent\n}}\n"
        ),
        None => String::new(),
    }
}

fn render_caddy(
    domains: &[String],
    upstream_port: u16,
    plain_http: bool,
    switches: &Switches,
) -> Result<String, Failure> {
    validate_domains(domains)?;

    let mut out = format!("{MANAGED_HEADER} Edits here are overwritten on the next deploy.\n");
    out.push_str(&meta_line(domains, upstream_port));

    if plain_http {
        let names = domains
            .iter()
            .map(|d| format!("http://{d}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str("# Behind a tunnel: plain HTTP here, the tunnel's edge does HTTPS.\n");
        out.push_str(&format!(
            "{names} {{\n{}}}\n",
            caddy_body(switches, upstream_port, true)
        ));
        out.push_str(&caddy_alias(switches, "http://", "https"));
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
            "{} {{\n{}}}\n",
            join(&plain),
            caddy_body(switches, upstream_port, false)
        ));
    }
    if !wildcards.is_empty() {
        if !plain.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "{} {{\n\ttls {{\n\t\ton_demand\n\t}}\n{}}}\n",
            join(&wildcards),
            caddy_body(switches, upstream_port, false)
        ));
    }
    out.push_str(&caddy_alias(switches, "", "https"));

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

fn nginx_proxy(upstream_port: u16, proto: &str) -> String {
    format!(
        "        proxy_pass http://127.0.0.1:{upstream_port};\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection $serveros_connection_upgrade;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto {proto};\n        proxy_read_timeout 300s;\n"
    )
}

/// The locations of an nginx server block: each redirected path exactly,
/// then everything else, which sends the www alias on (inside the
/// location, so certificate challenges are never redirected), asks for
/// the password and passes the rest to the app. `scheme` is where the
/// alias sends visitors: https, http or `$scheme`.
fn nginx_locations(switches: &Switches, upstream_port: u16, proto: &str, scheme: &str) -> String {
    let mut out = String::new();
    if let Some(file) = &switches.access_log {
        out.push_str(&format!(
            "    access_log {} serveros_traffic;\n",
            file.display()
        ));
    }
    for r in &switches.options.redirects {
        out.push_str(&format!(
            "    location = {} {{\n        return {} {};\n    }}\n",
            r.from,
            status(r.permanent),
            r.to
        ));
    }
    out.push_str("    location / {\n");
    if let Some((alias, canonical)) = switches.www() {
        out.push_str(&format!(
            "        if ($host = {alias}) {{\n            return 301 {scheme}://{canonical}$request_uri;\n        }}\n"
        ));
    }
    if let Some(file) = &switches.auth_file {
        out.push_str(&format!(
            "        auth_basic \"Restricted\";\n        auth_basic_user_file {};\n",
            file.display()
        ));
    }
    out.push_str(&nginx_proxy(switches.port(upstream_port), proto));
    out.push_str("    }\n");
    out
}

const NGINX_ACME: &str = "    location ^~ /.well-known/acme-challenge/ {\n        root /var/lib/serveros-acme;\n        default_type text/plain;\n    }\n";

/// nginx server blocks for one app. Plain names answer on port 80 for
/// Let's Encrypt's challenge and, once `tls` (the certificate's folder)
/// exists, redirect to the HTTPS block. Wildcard names get a plain HTTP
/// block of their own: certbot's HTTP challenge can't get a certificate
/// for every subdomain. Behind a tunnel everything is plain HTTP.
pub fn render_nginx(
    domains: &[String],
    upstream_port: u16,
    tls: Option<&Path>,
    plain_http: bool,
) -> Result<String, Failure> {
    render_nginx_with(
        domains,
        upstream_port,
        tls,
        plain_http,
        &Switches::default(),
    )
}

fn render_nginx_with(
    domains: &[String],
    upstream_port: u16,
    tls: Option<&Path>,
    plain_http: bool,
    switches: &Switches,
) -> Result<String, Failure> {
    validate_domains(domains)?;

    let mut out = format!("{MANAGED_HEADER} Edits here are overwritten on the next deploy.\n");
    out.push_str(&meta_line(domains, upstream_port));
    let listen = "    listen 80;\n    listen [::]:80;\n";
    let names = |list: &[&String]| {
        list.iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };

    if plain_http {
        let all: Vec<&String> = domains.iter().collect();
        out.push_str("# Behind a tunnel: plain HTTP here, the tunnel's edge does HTTPS.\n");
        out.push_str(&format!(
            "server {{\n{listen}    server_name {};\n    client_max_body_size 100m;\n\n{}}}\n",
            names(&switches.with_alias(&all)),
            nginx_locations(switches, upstream_port, "https", "https")
        ));
        return Ok(out);
    }

    let (wildcards, plain) = split_wildcards(domains);
    let plain_names = names(&switches.with_alias(&plain));

    if !plain.is_empty() {
        match tls {
            Some(dir) => {
                out.push_str(&format!(
                    "server {{\n{listen}    server_name {plain_names};\n\n{NGINX_ACME}    location / {{\n        return 301 https://$host$request_uri;\n    }}\n}}\n\nserver {{\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    server_name {plain_names};\n    ssl_certificate {cert};\n    ssl_certificate_key {key};\n    client_max_body_size 100m;\n\n{proxy}}}\n",
                    cert = dir.join("fullchain.pem").display(),
                    key = dir.join("privkey.pem").display(),
                    proxy = nginx_locations(switches, upstream_port, "$scheme", "https"),
                ));
            }
            None => {
                out.push_str(&format!(
                    "server {{\n{listen}    server_name {plain_names};\n    client_max_body_size 100m;\n\n{NGINX_ACME}{}}}\n",
                    nginx_locations(switches, upstream_port, "$scheme", "$scheme")
                ));
            }
        }
    }
    if !wildcards.is_empty() {
        if !plain.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "# Wildcard subdomains: plain HTTP, certificates for them need Caddy.\nserver {{\n{listen}    server_name {};\n    client_max_body_size 100m;\n\n{}}}\n",
            names(&wildcards),
            nginx_locations(switches, upstream_port, "$scheme", "$scheme")
        ));
    }

    Ok(out)
}

fn apache_proxy(upstream_port: u16, proto: &str) -> String {
    format!(
        "    ProxyPreserveHost On\n    ProxyRequests Off\n    RequestHeader set X-Forwarded-Proto \"{proto}\"\n    ProxyPass / http://127.0.0.1:{upstream_port}/ upgrade=websocket\n    ProxyPassReverse / http://127.0.0.1:{upstream_port}/\n"
    )
}

const APACHE_ACME: &str = "    Alias /.well-known/acme-challenge/ /var/lib/serveros-acme/.well-known/acme-challenge/\n    <Directory /var/lib/serveros-acme>\n        Require all granted\n    </Directory>\n    ProxyPass /.well-known/acme-challenge/ !\n";

/// The first name a virtual host answers to and the rest. A host with only
/// wildcards gets a name no one visits, since ServerName can't be one.
fn apache_names(stem: &str, names: &[&String]) -> String {
    let (first, rest) = match names.iter().position(|n| !is_wildcard(n)) {
        Some(at) => (
            names[at].to_string(),
            names
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != at)
                .map(|(_, n)| n.as_str())
                .collect::<Vec<_>>(),
        ),
        None => (
            format!("{stem}.serveros.invalid"),
            names.iter().map(|n| n.as_str()).collect(),
        ),
    };
    let mut out = format!("    ServerName {first}\n");
    if !rest.is_empty() {
        out.push_str(&format!("    ServerAlias {}\n", rest.join(" ")));
    }
    out
}

/// What goes in an Apache virtual host before the proxy lines: the www
/// alias and redirected paths as rewrite rules (mod_rewrite runs before
/// mod_proxy), and the password, with certificate challenges left open.
fn apache_body(switches: &Switches, upstream_port: u16, proto: &str, scheme: &str) -> String {
    let mut out = String::new();
    if let Some(file) = &switches.access_log {
        out.push_str(&format!(
            "    CustomLog {} {APACHE_LOG_FORMAT}\n",
            file.display()
        ));
    }
    if switches.www().is_some() || !switches.options.redirects.is_empty() {
        out.push_str("    RewriteEngine On\n");
        if let Some((alias, canonical)) = switches.www() {
            out.push_str(&format!(
                "    RewriteCond %{{HTTP_HOST}} ^{}$ [NC]\n    RewriteRule ^ {scheme}://{canonical}%{{REQUEST_URI}} [R=301,L]\n",
                regex_literal(alias)
            ));
        }
        for r in &switches.options.redirects {
            out.push_str(&format!(
                "    RewriteRule ^{}$ {} [R={},L]\n",
                regex_literal(&r.from),
                r.to,
                status(r.permanent)
            ));
        }
    }
    if let Some(file) = &switches.auth_file {
        out.push_str(&format!(
            "    <Location />\n        AuthType Basic\n        AuthName \"Restricted\"\n        AuthUserFile {}\n        Require valid-user\n    </Location>\n    <Location /.well-known/acme-challenge/>\n        Require all granted\n    </Location>\n",
            file.display()
        ));
    }
    out.push_str(&apache_proxy(switches.port(upstream_port), proto));
    out
}

/// Apache virtual hosts for one app, laid out like the nginx ones.
pub fn render_apache(
    stem: &str,
    domains: &[String],
    upstream_port: u16,
    tls: Option<&Path>,
    plain_http: bool,
) -> Result<String, Failure> {
    render_apache_with(
        stem,
        domains,
        upstream_port,
        tls,
        plain_http,
        &Switches::default(),
    )
}

fn render_apache_with(
    stem: &str,
    domains: &[String],
    upstream_port: u16,
    tls: Option<&Path>,
    plain_http: bool,
    switches: &Switches,
) -> Result<String, Failure> {
    validate_domains(domains)?;

    let mut out = format!("{MANAGED_HEADER} Edits here are overwritten on the next deploy.\n");
    out.push_str(&meta_line(domains, upstream_port));
    let all: Vec<&String> = domains.iter().collect();

    if plain_http {
        out.push_str("# Behind a tunnel: plain HTTP here, the tunnel's edge does HTTPS.\n");
        out.push_str(&format!(
            "<VirtualHost *:80>\n{}{}</VirtualHost>\n",
            apache_names(stem, &switches.with_alias(&all)),
            apache_body(switches, upstream_port, "https", "https")
        ));
        return Ok(out);
    }

    let (wildcards, plain) = split_wildcards(domains);
    if !plain.is_empty() {
        let names = apache_names(stem, &switches.with_alias(&plain));
        match tls {
            Some(dir) => {
                out.push_str(&format!(
                    "<VirtualHost *:80>\n{names}{APACHE_ACME}    RewriteEngine On\n    RewriteCond %{{REQUEST_URI}} !^/\\.well-known/acme-challenge/\n    RewriteRule ^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [R=301,L]\n</VirtualHost>\n\n<VirtualHost *:443>\n{names}    SSLEngine on\n    SSLCertificateFile {cert}\n    SSLCertificateKeyFile {key}\n{proxy}</VirtualHost>\n",
                    cert = dir.join("fullchain.pem").display(),
                    key = dir.join("privkey.pem").display(),
                    proxy = apache_body(switches, upstream_port, "https", "https"),
                ));
            }
            None => {
                out.push_str(&format!(
                    "<VirtualHost *:80>\n{names}{APACHE_ACME}{}</VirtualHost>\n",
                    apache_body(switches, upstream_port, "http", "%{REQUEST_SCHEME}")
                ));
            }
        }
    }
    if !wildcards.is_empty() {
        if !plain.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "# Wildcard subdomains: plain HTTP, certificates for them need Caddy.\n<VirtualHost *:80>\n{}{}</VirtualHost>\n",
            apache_names(&format!("{stem}-wildcard"), &wildcards),
            apache_body(switches, upstream_port, "http", "%{REQUEST_SCHEME}")
        ));
    }

    Ok(out)
}

fn traefik_rule(names: &[&String]) -> String {
    names
        .iter()
        .map(|n| match n.strip_prefix("*.") {
            Some(parent) => format!(
                "HostRegexp(`^[a-z0-9-]+\\.{}$`)",
                parent.replace('.', "\\.")
            ),
            None => format!("Host(`{n}`)"),
        })
        .collect::<Vec<_>>()
        .join(" || ")
}

/// The middlewares a Traefik site's switches need, by name, and their
/// definitions. `scheme` is where the www alias sends visitors.
fn traefik_middlewares(switches: &Switches, id: &str, scheme: &str) -> (Vec<String>, String) {
    let mut names = Vec::new();
    let mut defs = String::new();
    if let Some((alias, canonical)) = switches.www() {
        names.push(format!("{id}-www"));
        defs.push_str(&format!(
            "\n[http.middlewares.{id}-www.redirectRegex]\n  regex = '^https?://{}(:[0-9]+)?/(.*)'\n  replacement = '{scheme}://{canonical}/${{2}}'\n  permanent = true\n",
            regex_literal(alias)
        ));
    }
    for (i, r) in switches.options.redirects.iter().enumerate() {
        names.push(format!("{id}-redirect-{i}"));
        let replacement = if r.to.starts_with('/') {
            format!("${{1}}{}", r.to)
        } else {
            r.to.clone()
        };
        defs.push_str(&format!(
            "\n[http.middlewares.{id}-redirect-{i}.redirectRegex]\n  regex = '^(https?://[^/]+){}(\\?.*)?$'\n  replacement = '{replacement}'\n  permanent = {}\n",
            regex_literal(&r.from),
            r.permanent
        ));
    }
    if let Some(auth) = &switches.options.basic_auth {
        names.push(format!("{id}-auth"));
        defs.push_str(&format!(
            "\n[http.middlewares.{id}-auth.basicAuth]\n  users = ['{}:{}']\n",
            auth.user, auth.hash
        ));
    }
    (names, defs)
}

fn traefik_middleware_line(names: &[String]) -> String {
    if names.is_empty() {
        return String::new();
    }
    format!(
        "  middlewares = [{}]\n",
        names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// A Traefik dynamic config (TOML) for one app. Traefik gets and renews
/// certificates for the plain names itself, through the `serveros`
/// resolver, and redirects HTTP to HTTPS. Wildcards are plain HTTP, like
/// with nginx and Apache. Rules are TOML literal strings, so a regex's
/// backslashes stay as they are.
pub fn render_traefik(
    stem: &str,
    domains: &[String],
    upstream_port: u16,
    plain_http: bool,
) -> Result<String, Failure> {
    render_traefik_with(
        stem,
        domains,
        upstream_port,
        plain_http,
        &Switches::default(),
    )
}

fn render_traefik_with(
    stem: &str,
    domains: &[String],
    upstream_port: u16,
    plain_http: bool,
    switches: &Switches,
) -> Result<String, Failure> {
    validate_domains(domains)?;

    let id = format!("serveros-{stem}");
    let mut out = format!("{MANAGED_HEADER} Edits here are overwritten on the next deploy.\n");
    out.push_str(&meta_line(domains, upstream_port));
    let all: Vec<&String> = domains.iter().collect();
    let (middlewares, defs) = traefik_middlewares(switches, &id, "https");

    if plain_http {
        let mut chain = vec![format!("{id}-forwarded")];
        chain.extend(middlewares.iter().cloned());
        out.push_str(&format!(
            "# Behind a tunnel: plain HTTP here, the tunnel's edge does HTTPS.\n[http.routers.{id}]\n  rule = '{rule}'\n  entryPoints = [\"web\"]\n{chain}  service = \"{id}\"\n\n[http.middlewares.{id}-forwarded.headers.customRequestHeaders]\n  X-Forwarded-Proto = \"https\"\n",
            rule = traefik_rule(&switches.with_alias(&all)),
            chain = traefik_middleware_line(&chain),
        ));
    } else {
        let (wildcards, plain) = split_wildcards(domains);
        if !plain.is_empty() {
            out.push_str(&format!(
                "[http.routers.{id}]\n  rule = '{rule}'\n  entryPoints = [\"websecure\"]\n{chain}  service = \"{id}\"\n  [http.routers.{id}.tls]\n    certResolver = \"{TRAEFIK_RESOLVER}\"\n\n[http.routers.{id}-http]\n  rule = '{rule}'\n  entryPoints = [\"web\"]\n  middlewares = [\"{id}-https\"]\n  service = \"{id}\"\n\n[http.middlewares.{id}-https.redirectScheme]\n  scheme = \"https\"\n  permanent = true\n",
                rule = traefik_rule(&switches.with_alias(&plain)),
                chain = traefik_middleware_line(&middlewares),
            ));
        }
        if !wildcards.is_empty() {
            if !plain.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!(
                "# Wildcard subdomains: plain HTTP, certificates for them need Caddy.\n[http.routers.{id}-wildcard]\n  rule = '{rule}'\n  entryPoints = [\"web\"]\n{chain}  service = \"{id}\"\n",
                rule = traefik_rule(&wildcards),
                chain = traefik_middleware_line(&middlewares),
            ));
        }
    }
    out.push_str(&defs);

    out.push_str(&format!(
        "\n[http.services.{id}.loadBalancer]\n  [[http.services.{id}.loadBalancer.servers]]\n    url = \"http://127.0.0.1:{}\"\n",
        switches.port(upstream_port)
    ));

    Ok(out)
}

/// A site served over plain HTTP because its owner chose that (say, a
/// proxy or CDN in front does HTTPS): no certificate, no redirect, and the
/// app is told the visitor's real scheme.
pub fn render_http_only(
    backend: ProxyBackend,
    stem: &str,
    domains: &[String],
    upstream_port: u16,
) -> Result<String, Failure> {
    render_http_only_with(backend, stem, domains, upstream_port, &Switches::default())
}

fn render_http_only_with(
    backend: ProxyBackend,
    stem: &str,
    domains: &[String],
    upstream_port: u16,
    switches: &Switches,
) -> Result<String, Failure> {
    validate_domains(domains)?;

    let mut out = format!("{MANAGED_HEADER} Edits here are overwritten on the next deploy.\n");
    out.push_str(&format!(
        "{SITE_META} port={upstream_port} domains={} https=off\n",
        domains.join(",")
    ));
    out.push_str("# Plain HTTP by choice: HTTPS is off for this site.\n");
    let all: Vec<&String> = domains.iter().collect();

    match backend {
        ProxyBackend::Caddy => {
            let names = domains
                .iter()
                .map(|d| format!("http://{d}"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "{names} {{\n{}}}\n",
                caddy_body(switches, upstream_port, false)
            ));
            out.push_str(&caddy_alias(switches, "http://", "http"));
        }
        ProxyBackend::Nginx => {
            out.push_str(&format!(
                "server {{\n    listen 80;\n    listen [::]:80;\n    server_name {};\n    client_max_body_size 100m;\n\n{}}}\n",
                switches
                    .with_alias(&all)
                    .iter()
                    .map(|n| n.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
                nginx_locations(switches, upstream_port, "$scheme", "http")
            ));
        }
        ProxyBackend::Apache => {
            out.push_str(&format!(
                "<VirtualHost *:80>\n{}{}</VirtualHost>\n",
                apache_names(stem, &switches.with_alias(&all)),
                apache_body(switches, upstream_port, "http", "http")
            ));
        }
        ProxyBackend::Traefik => {
            let id = format!("serveros-{stem}");
            let (middlewares, defs) = traefik_middlewares(switches, &id, "http");
            out.push_str(&format!(
                "[http.routers.{id}]\n  rule = '{rule}'\n  entryPoints = [\"web\"]\n{chain}  service = \"{id}\"\n{defs}\n[http.services.{id}.loadBalancer]\n  [[http.services.{id}.loadBalancer.servers]]\n    url = \"http://127.0.0.1:{port}\"\n",
                rule = traefik_rule(&switches.with_alias(&all)),
                chain = traefik_middleware_line(&middlewares),
                port = switches.port(upstream_port),
            ));
        }
        ProxyBackend::None => {
            return Err(Failure::new(
                "proxy",
                "no reverse proxy is configured on this machine",
            ));
        }
    }

    Ok(out)
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
        let (main_config, include_dir) = match backend {
            ProxyBackend::Caddy | ProxyBackend::None => (CADDYFILE, INCLUDE_DIR),
            ProxyBackend::Nginx => (NGINX_CONF, NGINX_INCLUDE_DIR),
            ProxyBackend::Apache => (APACHE_CONF, APACHE_INCLUDE_DIR),
            ProxyBackend::Traefik => (TRAEFIK_CONF, TRAEFIK_INCLUDE_DIR),
        };
        Self {
            backend,
            main_config: main_config.into(),
            include_dir: include_dir.into(),
            cert_root: LETSENCRYPT_LIVE.into(),
            sites_dir: SITES_DIR.into(),
            traffic_dir: TRAFFIC_LOG_DIR.into(),
        }
    }

    fn extension(&self) -> &'static str {
        match self.backend {
            ProxyBackend::Nginx | ProxyBackend::Apache => "conf",
            ProxyBackend::Traefik => "toml",
            _ => "caddy",
        }
    }

    pub fn site_file(&self, service: &str) -> PathBuf {
        self.include_dir.join(format!(
            "{}.{}",
            crate::git::sanitise(service),
            self.extension()
        ))
    }

    /// The systemd unit the proxy runs as.
    pub fn unit(&self) -> Option<&'static str> {
        match self.backend {
            ProxyBackend::Caddy => Some("caddy"),
            ProxyBackend::Nginx => Some("nginx"),
            ProxyBackend::Apache => Some("apache2"),
            ProxyBackend::Traefik => Some("traefik"),
            ProxyBackend::None => None,
        }
    }

    /// The line ServerOS adds to the proxy's own config so it reads our
    /// sites, for the uninstaller to take out again. Traefik's config is
    /// ours whole, or the operator's.
    pub fn include_line(&self) -> Option<&'static str> {
        match self.backend {
            ProxyBackend::Caddy => Some(CADDY_IMPORT_LINE),
            ProxyBackend::Nginx => Some(NGINX_INCLUDE_LINE),
            ProxyBackend::Apache => Some(APACHE_INCLUDE_LINE),
            _ => None,
        }
    }

    /// nginx and Apache get their certificates from certbot; Caddy and
    /// Traefik get their own.
    fn uses_certbot(&self) -> bool {
        matches!(self.backend, ProxyBackend::Nginx | ProxyBackend::Apache)
    }

    fn cert_dir(&self, stem: &str) -> PathBuf {
        self.cert_root.join(format!("serveros-{stem}"))
    }

    fn has_cert(&self, stem: &str) -> bool {
        self.cert_dir(stem).join("fullchain.pem").exists()
    }

    fn none_configured() -> Failure {
        Failure::new("proxy", "no reverse proxy is configured on this machine")
            .with_next_step("Pick a reverse proxy when you deploy, or publish the port yourself.")
    }

    /// Whether traffic is on: sites write access logs that the daemon rolls
    /// up and reports. Kept with the site switches, so it outlives deploys
    /// and proxy switches.
    pub fn traffic_on(&self) -> bool {
        self.sites_dir.join(TRAFFIC_MARKER).exists()
    }

    /// The access log a site writes while traffic is on. Traefik writes one
    /// for every site, set in its own config.
    fn access_log(&self, stem: &str) -> Option<PathBuf> {
        (self.traffic_on() && !matches!(self.backend, ProxyBackend::Traefik | ProxyBackend::None))
            .then(|| self.traffic_dir.join(format!("{stem}.log")))
    }

    /// The log files these sites write while traffic is on.
    fn traffic_files(&self, stems: &[String]) -> Vec<PathBuf> {
        match self.backend {
            ProxyBackend::Traefik => vec![self.traffic_dir.join(TRAEFIK_LOG)],
            ProxyBackend::None => Vec::new(),
            _ => stems
                .iter()
                .map(|stem| self.traffic_dir.join(format!("{stem}.log")))
                .collect(),
        }
    }

    /// What the daemon reads traffic from, while it's on: the logs' format
    /// and folder.
    pub fn traffic_source(&self) -> Option<(traffic::Format, PathBuf)> {
        if !self.traffic_on() {
            return None;
        }
        Some((traffic::Format::of(self.backend)?, self.traffic_dir.clone()))
    }

    /// Makes the log folder and files before the proxy (or its config
    /// check, which runs as root) opens them: Caddy and Traefik write as
    /// their own users, nginx and Apache open logs as root. Nobody else can
    /// read them, since they hold visitors' addresses until the daemon
    /// empties them.
    fn prepare_traffic_logs(&self, files: &[PathBuf]) -> Result<(), Failure> {
        use std::os::unix::fs::PermissionsExt;
        let failed = |path: &Path, e: std::io::Error| {
            Failure::new(
                "traffic",
                format!("could not set up {}: {e}", path.display()),
            )
        };
        let dir = &self.traffic_dir;
        std::fs::create_dir_all(dir).map_err(|e| failed(dir, e))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
            .map_err(|e| failed(dir, e))?;
        let owner = match self.backend {
            ProxyBackend::Caddy => system_user("caddy"),
            ProxyBackend::Traefik => system_user("traefik"),
            _ => None,
        };
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(dir, Some(uid), Some(gid)).map_err(|e| failed(dir, e))?;
        }
        for file in files {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(file)
                .map_err(|e| failed(file, e))?;
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o640))
                .map_err(|e| failed(file, e))?;
            if let Some((uid, gid)) = owner {
                std::os::unix::fs::chown(file, Some(uid), Some(gid))
                    .map_err(|e| failed(file, e))?;
            }
        }
        Ok(())
    }

    /// Adds ServerOS's access log section to a Traefik config it wrote, or
    /// takes it out. Returns the config as it was when that changed it.
    /// Traefik reads this config only when it starts.
    fn set_traefik_access_log(&self, on: bool) -> Result<Option<String>, Failure> {
        let before = std::fs::read_to_string(&self.main_config).unwrap_or_default();
        if on && !before.starts_with("# Installed by ServerOS.") {
            return Err(Failure::new(
                "traffic",
                format!(
                    "Traefik's config ({}) isn't one ServerOS wrote, so it can't add an access log to it",
                    self.main_config.display()
                ),
            )
            .with_next_step(format!(
                "Add this to it yourself and restart Traefik, then turn traffic on again:\n{}",
                traffic::traefik_access_log(&self.traffic_dir.join(TRAEFIK_LOG))
            )));
        }
        let Some(after) =
            traffic::with_traefik_access_log(&before, &self.traffic_dir.join(TRAEFIK_LOG), on)
        else {
            return Ok(None);
        };
        std::fs::write(&self.main_config, after).map_err(|e| {
            Failure::new(
                "proxy",
                format!("could not update {}: {e}", self.main_config.display()),
            )
        })?;
        Ok(Some(before))
    }

    /// Turns traffic on or off for every site ServerOS runs here, rewriting
    /// their site files at once (no redeploy). A site with traffic off is
    /// written exactly as before. Traefik keeps its access log in its own
    /// config, so it restarts (a second or so). If the proxy won't take
    /// the change, everything is put back as it was.
    pub async fn set_traffic(
        &self,
        on: bool,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<serde_json::Value, Failure> {
        if self.backend == ProxyBackend::None {
            return Err(Self::none_configured());
        }
        let stems: Vec<String> = self.our_sites().into_iter().map(|(stem, _)| stem).collect();
        if on {
            self.prepare_traffic_logs(&self.traffic_files(&stems))?;
        }
        if self.backend == ProxyBackend::Nginx {
            // The shared file defines the log format the sites use.
            self.ensure_import()?;
        }

        let was_on = self.traffic_on();
        let marker = self.sites_dir.join(TRAFFIC_MARKER);
        let set_marker = |on: bool| -> std::io::Result<()> {
            if on {
                std::fs::create_dir_all(&self.sites_dir)?;
                std::fs::write(
                    &marker,
                    "Written by ServerOS: sites here write access logs for their traffic.\n",
                )
            } else {
                match std::fs::remove_file(&marker) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                    _ => Ok(()),
                }
            }
        };
        let traefik_before = if self.backend == ProxyBackend::Traefik {
            self.set_traefik_access_log(on)?
        } else {
            None
        };
        let put_back = |rewrites: &[(PathBuf, String, String)]| {
            for (path, before, _) in rewrites {
                let _ = std::fs::write(path, before);
            }
            let _ = set_marker(was_on);
            if let Some(config) = &traefik_before {
                let _ = std::fs::write(&self.main_config, config);
            }
        };
        if let Err(e) = set_marker(on) {
            put_back(&[]);
            return Err(Failure::new(
                "traffic",
                format!("could not update {}: {e}", marker.display()),
            ));
        }

        let rewrites = self.rerendered(self.plain_http());
        for (path, _, after) in &rewrites {
            if let Err(e) = std::fs::write(path, after) {
                put_back(&rewrites);
                return Err(Failure::new(
                    "proxy",
                    format!("could not write {}: {e}", path.display()),
                ));
            }
        }
        if !rewrites.is_empty() {
            if let Err(failure) = self.validate(cancel, progress).await {
                put_back(&rewrites);
                return Err(failure);
            }
            self.reload(cancel, progress).await?;
        }
        if traefik_before.is_some() && unit_active("traefik").await {
            progress
                .line(
                    "Restarting Traefik, which reads its access log setting only when it starts"
                        .to_string(),
                )
                .await;
            if !systemctl(&["restart", "traefik"], cancel, progress).await {
                put_back(&rewrites);
                let _ = systemctl(&["restart", "traefik"], cancel, progress).await;
                return Err(
                    Failure::new("traffic", "Traefik didn't restart with its access log")
                        .with_next_step(
                            "`journalctl -u traefik` says why. Its config is back as it was.",
                        ),
                );
            }
        }

        if on {
            progress
                .line(format!(
                    "Counting traffic for {} site(s): it shows up a minute or two after the first visits",
                    stems.len()
                ))
                .await;
        } else {
            if let Ok(entries) = std::fs::read_dir(&self.traffic_dir) {
                for entry in entries.flatten() {
                    if entry.path().extension().is_some_and(|x| x == "log") {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
            progress
                .line("Traffic is off: sites no longer write access logs for it".to_string())
                .await;
        }

        Ok(serde_json::json!({ "enabled": on, "sites": stems.len() }))
    }

    /// The site file for one app, as this proxy writes it now, with the
    /// app's switches.
    fn render_site(&self, stem: &str, site: &Site, plain_http: bool) -> Result<String, Failure> {
        let switches = self.switches(stem, &site.domains);
        if !site.https && !plain_http {
            return render_http_only_with(self.backend, stem, &site.domains, site.port, &switches);
        }
        let tls = (!plain_http && self.has_cert(stem)).then(|| self.cert_dir(stem));
        match self.backend {
            ProxyBackend::Caddy => render_caddy(&site.domains, site.port, plain_http, &switches),
            ProxyBackend::Nginx => render_nginx_with(
                &site.domains,
                site.port,
                tls.as_deref(),
                plain_http,
                &switches,
            ),
            ProxyBackend::Apache => render_apache_with(
                stem,
                &site.domains,
                site.port,
                tls.as_deref(),
                plain_http,
                &switches,
            ),
            ProxyBackend::Traefik => {
                render_traefik_with(stem, &site.domains, site.port, plain_http, &switches)
            }
            ProxyBackend::None => Err(Self::none_configured()),
        }
    }

    fn switches(&self, stem: &str, domains: &[String]) -> Switches {
        let options = site_options::load(&self.sites_dir, stem);
        let auth_file = self.uses_auth_file().then(|| self.auth_file(stem));
        Switches::new(domains, options, auth_file).with_access_log(self.access_log(stem))
    }

    /// nginx and Apache read a site's password from a file of their own;
    /// Caddy and Traefik take the hash in the site's config.
    fn uses_auth_file(&self) -> bool {
        matches!(self.backend, ProxyBackend::Nginx | ProxyBackend::Apache)
    }

    /// Beside the site file, without its extension so the proxy's include
    /// never reads it as config. Readable by the proxy's workers (www-data),
    /// and only ever holds a bcrypt hash.
    fn auth_file(&self, stem: &str) -> PathBuf {
        self.include_dir.join(format!("{stem}.htpasswd"))
    }

    /// Writes (or removes) a site's password file to match its switches.
    fn write_auth_file(&self, stem: &str, options: &SiteOptions) -> Result<(), Failure> {
        if !self.uses_auth_file() {
            return Ok(());
        }
        let path = self.auth_file(stem);
        match &options.basic_auth {
            Some(auth) => {
                std::fs::write(&path, format!("{}:{}\n", auth.user, auth.hash)).map_err(|e| {
                    Failure::new("proxy", format!("could not write {}: {e}", path.display()))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
                }
                Ok(())
            }
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Failure::new(
                    "proxy",
                    format!("could not remove {}: {e}", path.display()),
                )),
                _ => Ok(()),
            },
        }
    }

    /// The names a site's certificate covers: its plain names and the www
    /// alias, when it has one.
    fn cert_names(&self, stem: &str, site: &Site) -> Vec<String> {
        let (_, plain) = split_wildcards(&site.domains);
        let switches = self.switches(stem, &site.domains);
        switches.with_alias(&plain).into_iter().cloned().collect()
    }

    /// Every site ServerOS wrote for this proxy, by file stem (the
    /// service's name as it goes in a file name).
    pub fn our_sites(&self) -> Vec<(String, Site)> {
        let Ok(entries) = std::fs::read_dir(&self.include_dir) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == self.extension()))
            .collect();
        paths.sort();

        paths
            .into_iter()
            .filter_map(|path| {
                let text = std::fs::read_to_string(&path).ok()?;
                let site = read_site(self.backend, &text)?;
                let stem = path.file_stem()?.to_string_lossy().into_owned();
                Some((stem, site))
            })
            .collect()
    }

    pub async fn ensure_installed(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<bool, Failure> {
        let (program, script, next_step) = match self.backend {
            ProxyBackend::Caddy => ("caddy", CADDY_INSTALL_SCRIPT, "Install Caddy yourself (caddyserver.com/docs/install), then deploy again."),
            ProxyBackend::Nginx => ("nginx", NGINX_INSTALL_SCRIPT, "Install nginx and certbot yourself (`apt install nginx certbot`), then deploy again."),
            ProxyBackend::Apache => ("apache2", APACHE_INSTALL_SCRIPT, "Install Apache and certbot yourself (`apt install apache2 certbot`), then deploy again."),
            ProxyBackend::Traefik => ("traefik", TRAEFIK_INSTALL_SCRIPT, "Install Traefik yourself (doc.traefik.io/traefik/getting-started/install-traefik), with a systemd unit called traefik, then deploy again."),
            ProxyBackend::None => return Ok(false),
        };
        let unit = self.unit().unwrap_or(program);
        let label = self.backend.label();

        // A binary without its systemd unit (copied in by hand, or left by
        // another tool) can't be started or reloaded: install the package,
        // which brings the unit.
        if on_path(program) && unit_exists(unit).await {
            if self.backend == ProxyBackend::Apache {
                self.enable_apache_modules(cancel, progress).await?;
            }
            return Ok(false);
        }

        progress
            .line(if on_path(program) {
                format!("{label} is here but has no systemd service: installing its package")
            } else if self.backend == ProxyBackend::Caddy {
                "Caddy is not installed: installing it for automatic HTTPS".to_string()
            } else {
                format!("{label} is not installed: installing it")
            })
            .await;

        let outcome = run_child(
            "sh",
            &["-c", script],
            None,
            &[],
            Duration::from_secs(600),
            cancel,
            progress,
            None,
        )
        .await;

        if !outcome.success() {
            return Err(Failure::new("proxy", format!("could not install {label}"))
                .with_output(outcome.tail().to_vec())
                .with_next_step(next_step));
        }

        let fresh = match self.backend {
            ProxyBackend::Caddy => Some(fresh_caddyfile()),
            ProxyBackend::Traefik if !self.main_config.exists() => Some(fresh_traefik_config()),
            _ => None,
        };
        if let Some(fresh) = fresh {
            std::fs::write(&self.main_config, fresh).map_err(|e| {
                Failure::new(
                    "proxy",
                    format!("could not write {}: {e}", self.main_config.display()),
                )
            })?;
        }

        Ok(true)
    }

    async fn enable_apache_modules(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let mut args = vec!["-q"];
        args.extend(APACHE_MODULES);
        let outcome = run_child(
            "a2enmod",
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
            Err(Failure::new(
                "proxy",
                "could not turn on the Apache modules a reverse proxy needs",
            )
            .with_output(outcome.tail().to_vec())
            .with_next_step(format!(
                "Run `a2enmod {}` on the machine, then deploy again.",
                APACHE_MODULES.join(" ")
            )))
        }
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

        if self.backend == ProxyBackend::Nginx {
            let shared = self.include_dir.join(NGINX_SHARED_FILE);
            if std::fs::read_to_string(&shared).ok().as_deref() != Some(NGINX_SHARED) {
                std::fs::write(&shared, NGINX_SHARED).map_err(|e| {
                    Failure::new(
                        "proxy",
                        format!("could not write {}: {e}", shared.display()),
                    )
                })?;
            }
        }
        if self.uses_certbot() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::create_dir_all(ACME_WEBROOT);
            let _ = std::fs::set_permissions(ACME_WEBROOT, std::fs::Permissions::from_mode(0o755));
        }

        if self.backend == ProxyBackend::Traefik {
            let provider = self.ensure_traefik_provider()?;
            // A Traefik ServerOS just installed or moved to gets its access
            // log before it first starts, when traffic is on.
            let logged =
                self.traffic_on() && matches!(self.set_traefik_access_log(true), Ok(Some(_)));
            return Ok(provider || logged);
        }

        let existing = std::fs::read_to_string(&self.main_config).unwrap_or_default();
        let updated = match self.backend {
            ProxyBackend::Nginx => {
                if existing.lines().any(|l| l.trim() == NGINX_INCLUDE_LINE) {
                    None
                } else {
                    Some(add_nginx_include(&existing).ok_or_else(|| {
                        Failure::new(
                            "proxy",
                            format!("couldn't find the http block in {}", self.main_config.display()),
                        )
                        .with_next_step(format!("Add `{NGINX_INCLUDE_LINE}` inside the http block yourself, then deploy again."))
                    })?)
                }
            }
            ProxyBackend::Apache => add_apache_include(&existing),
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

    /// Traefik reads our sites through a file provider on serveros.d. A
    /// Traefik ServerOS installed has that from the start; one set up by
    /// hand has to have it added, since Traefik allows only one file
    /// provider and its config isn't ours to rewrite.
    fn ensure_traefik_provider(&self) -> Result<bool, Failure> {
        let dir = self.include_dir.to_string_lossy();
        let others: Vec<PathBuf> = TRAEFIK_OTHER_CONFIGS
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists() && self.main_config == Path::new(TRAEFIK_CONF))
            .collect();
        for config in std::iter::once(&self.main_config).chain(others.iter()) {
            let Ok(text) = std::fs::read_to_string(config) else {
                continue;
            };
            if text.contains(dir.as_ref()) {
                return Ok(false);
            }
            return Err(Failure::new(
                "proxy",
                format!("Traefik's config ({}) doesn't read ServerOS's sites", config.display()),
            )
            .with_next_step(format!(
                "Point its file provider at {dir} (with watch on) and add a Let's Encrypt certificate resolver called {TRAEFIK_RESOLVER} on the web entry point, then deploy again. Or remove the config so ServerOS can write its own."
            )));
        }

        std::fs::write(&self.main_config, fresh_traefik_config()).map_err(|e| {
            Failure::new(
                "proxy",
                format!("could not write {}: {e}", self.main_config.display()),
            )
        })?;
        Ok(true)
    }

    /// Writes (or rewrites) one app's site and reloads the proxy. `https`
    /// None keeps what the site had (a rollback, a clone), and HTTPS for a
    /// new one.
    pub async fn publish(
        &self,
        service: &str,
        domains: &[String],
        upstream_port: u16,
        https: Option<bool>,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<PathBuf, Failure> {
        if self.backend == ProxyBackend::None {
            return Err(Self::none_configured());
        }
        let plain_http = self.plain_http();
        let stem = crate::git::sanitise(service);
        let https = https.unwrap_or_else(|| {
            std::fs::read_to_string(self.site_file(service))
                .ok()
                .and_then(|text| read_site(self.backend, &text))
                .is_none_or(|site| site.https)
        });
        let site = Site {
            domains: domains.to_vec(),
            port: upstream_port,
            https,
        };
        let rendered = self.render_site(&stem, &site, plain_http)?;
        self.write_auth_file(&stem, &site_options::load(&self.sites_dir, &stem))?;
        if self.traffic_on() {
            self.prepare_traffic_logs(&self.traffic_files(std::slice::from_ref(&stem)))?;
        }
        let path = self.site_file(service);
        let previous = std::fs::read(&path).ok();

        // Wildcards need Caddy told where to ask before it issues a
        // certificate, in the Caddyfile's global options.
        let mut previous_main = None;
        if self.backend == ProxyBackend::Caddy
            && !plain_http
            && https
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
        if self.backend != ProxyBackend::Caddy
            && !plain_http
            && https
            && domains.iter().any(|d| is_wildcard(d))
        {
            progress
                .line(format!(
                    "Wildcard subdomains are served over plain HTTP with {}: a certificate for every subdomain needs Caddy",
                    self.backend.label()
                ))
                .await;
        }

        std::fs::write(&path, &rendered).map_err(|e| {
            Failure::new("proxy", format!("could not write {}: {e}", path.display()))
        })?;

        if let Err(failure) = self.validate(cancel, progress).await {
            put_back(
                &path,
                previous.as_deref(),
                &self.main_config,
                previous_main.as_deref(),
            );
            return Err(failure);
        }

        // A reload that fails leaves the proxy serving what it had: the
        // files go back to match, so the next reload (for another app, say)
        // doesn't pick this one up.
        if let Err(failure) = self.reload(cancel, progress).await {
            put_back(
                &path,
                previous.as_deref(),
                &self.main_config,
                previous_main.as_deref(),
            );
            return Err(failure);
        }

        if !https && !plain_http {
            progress
                .line(format!(
                    "HTTPS is off for {}: it's served over plain HTTP",
                    domains.join(", ")
                ))
                .await;
        }
        if self.uses_certbot() && !plain_http && https {
            self.certify(&stem, &site, &path, cancel, progress).await;
        }

        Ok(path)
    }

    /// Gets (or renews early, or widens) the certificate for an nginx or
    /// Apache site's plain names, then switches the site to HTTPS. Never
    /// fails the deploy: until the domain points here the site stays on
    /// plain HTTP, and the daemon tries again every so often.
    async fn certify(
        &self,
        stem: &str,
        site: &Site,
        path: &Path,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) {
        let plain = self.cert_names(stem, site);
        if plain.is_empty() {
            return;
        }
        let label = self.backend.label();

        if !on_path("certbot") {
            progress
                .line("certbot is not installed: installing it for HTTPS".to_string())
                .await;
            let outcome = run_child(
                "sh",
                &["-c", "export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q certbot"],
                None,
                &[],
                Duration::from_secs(600),
                cancel,
                progress,
                None,
            )
            .await;
            if !outcome.success() {
                progress
                    .line(format!("Couldn't install certbot, so {} is on plain HTTP. Install it (`apt install certbot`) and deploy again for HTTPS.", plain.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", ")))
                    .await;
                return;
            }
        }

        let args = self.certbot_args(stem, &plain);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let outcome = run_child(
            "certbot",
            &args,
            None,
            &[],
            Duration::from_secs(180),
            cancel,
            progress,
            None,
        )
        .await;
        if !outcome.success() {
            progress
                .line(format!(
                    "{label} couldn't get a certificate for {} yet, usually because the domain doesn't point at this machine. It's on plain HTTP for now, and ServerOS tries again every 15 minutes.",
                    plain.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", ")
                ))
                .await;
            return;
        }

        match self.switch_site_to_https(stem, site, path).await {
            Ok(true) => {
                progress
                    .line(format!(
                        "HTTPS is on for {}",
                        plain
                            .iter()
                            .map(|d| d.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .await;
            }
            Ok(false) => {}
            Err(reason) => {
                progress
                    .line(format!("Got a certificate, but {label} wouldn't take the HTTPS config ({reason}), so the site stays on plain HTTP"))
                    .await;
            }
        }
    }

    fn certbot_args(&self, stem: &str, names: &[String]) -> Vec<String> {
        let reload = format!("systemctl reload {}", self.unit().unwrap_or_default());
        let mut args: Vec<String> = ["certonly", "--webroot", "-w", ACME_WEBROOT, "--cert-name"]
            .into_iter()
            .map(str::to_string)
            .collect();
        args.push(format!("serveros-{stem}"));
        for name in names {
            args.push("-d".into());
            args.push(name.to_string());
        }
        args.extend(
            [
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
                "--keep-until-expiring",
                "--expand",
                "--deploy-hook",
            ]
            .into_iter()
            .map(str::to_string),
        );
        args.push(reload);
        args
    }

    /// Rewrites a site now that its certificate exists, keeping the old
    /// file if the proxy won't load the new one. False when nothing
    /// changed.
    async fn switch_site_to_https(
        &self,
        stem: &str,
        site: &Site,
        path: &Path,
    ) -> Result<bool, String> {
        let before = std::fs::read_to_string(path).unwrap_or_default();
        let after = self
            .render_site(stem, site, false)
            .map_err(|f| f.to_string())?;
        if after == before {
            return Ok(false);
        }
        std::fs::write(path, &after).map_err(|e| e.to_string())?;
        if !quiet(self.validate_command()).await || !quiet(self.reload_command()).await {
            let _ = std::fs::write(path, &before);
            let _ = quiet(self.reload_command()).await;
            return Err("the config didn't validate".into());
        }
        Ok(true)
    }

    /// Rewrites the site files ServerOS wrote that this daemon would now
    /// write differently (after an update changed how sites look), and
    /// reloads the proxy. Puts them back if the proxy won't take them.
    /// Returns how many changed.
    pub async fn refresh_sites(&self) -> usize {
        if self.backend == ProxyBackend::None {
            return 0;
        }
        let rewrites = self.rerendered(self.plain_http());
        if rewrites.is_empty() {
            return 0;
        }
        if self.traffic_on() {
            let stems: Vec<String> = self.our_sites().into_iter().map(|(stem, _)| stem).collect();
            let _ = self.prepare_traffic_logs(&self.traffic_files(&stems));
        }
        if self.uses_certbot() {
            let _ = self.ensure_import();
        }
        for (path, _, after) in &rewrites {
            let _ = std::fs::write(path, after);
        }
        if !quiet(self.validate_command()).await || !quiet(self.reload_command()).await {
            for (path, before, _) in &rewrites {
                let _ = std::fs::write(path, before);
            }
            let _ = quiet(self.reload_command()).await;
            return 0;
        }
        rewrites.len()
    }

    /// Tries again for nginx and Apache sites still without a certificate,
    /// usually because the domain wasn't pointing here at deploy. Returns
    /// how many sites went over to HTTPS.
    pub async fn retry_certificates(&self) -> usize {
        if !self.uses_certbot() || self.plain_http() || !on_path("certbot") {
            return 0;
        }
        let mut done = 0;
        for (stem, site) in self.our_sites() {
            let plain = self.cert_names(&stem, &site);
            if !site.https || plain.is_empty() || self.has_cert(&stem) {
                continue;
            }
            let args = self.certbot_args(&stem, &plain);
            let mut command = tokio::process::Command::new("certbot");
            command.args(&args);
            if !quiet((command, Duration::from_secs(180))).await {
                continue;
            }
            let path = self
                .include_dir
                .join(format!("{stem}.{}", self.extension()));
            if let Ok(true) = self.switch_site_to_https(&stem, &site, &path).await {
                done += 1;
            }
        }
        done
    }

    /// Whether sites are served over plain HTTP, for a tunnel in front.
    pub fn plain_http(&self) -> bool {
        self.include_dir.join(PLAIN_HTTP_MARKER).exists()
    }

    /// Switches every site to plain HTTP (a tunnel in front does HTTPS) or
    /// back to the proxy's own HTTPS, rewriting the site files ServerOS
    /// wrote and reloading the proxy. If the new config doesn't validate,
    /// the files and the mode are put back as they were.
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

        let rewrites = self.rerendered(on);

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
        self.our_sites()
            .into_iter()
            .filter_map(|(stem, site)| {
                let path = self
                    .include_dir
                    .join(format!("{stem}.{}", self.extension()));
                let before = std::fs::read_to_string(&path).ok()?;
                let after = self.render_site(&stem, &site, plain_http).ok()?;
                (after != before).then_some((path, before, after))
            })
            .collect()
    }

    /// Moves every site ServerOS serves on this machine to another proxy:
    /// stops this one (only one can have ports 80 and 443), installs the
    /// other if it needs to, writes each site for it and starts it. If
    /// anything fails on the way, this proxy is put back as it was.
    /// Returns the proxy now in use.
    pub async fn switch_to(
        &self,
        to: ProxyBackend,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<Proxy, Failure> {
        if to == self.backend {
            return Ok(self.clone());
        }
        if to == ProxyBackend::None {
            return Err(Self::none_configured());
        }
        let next = Proxy {
            backend: to,
            cert_root: self.cert_root.clone(),
            sites_dir: self.sites_dir.clone(),
            traffic_dir: self.traffic_dir.clone(),
            ..Proxy::for_backend(to)
        };
        let sites = self.our_sites();
        let from = self.backend.label();
        let label = to.label();
        progress
            .line(format!(
                "Moving {} site(s) from {from} to {label}",
                sites.len()
            ))
            .await;

        let old_running = match self.unit() {
            Some(unit) => unit_active(unit).await,
            None => false,
        };
        let next_running = match next.unit() {
            Some(unit) => unit_active(unit).await,
            None => false,
        };
        if old_running {
            progress
                .line(format!("Stopping {from} so {label} can have ports 80 and 443. Anything else {from} served goes offline with it."))
                .await;
            let _ = systemctl(&["stop", self.unit().unwrap_or_default()], cancel, progress).await;
        }

        let moved = async {
            next.ensure_installed(cancel, progress).await?;
            next.ensure_import()?;
            if self.plain_http() {
                std::fs::write(
                    next.include_dir.join(PLAIN_HTTP_MARKER),
                    "Written by ServerOS: a tunnel in front of this machine does HTTPS, so sites here are plain HTTP.\n",
                )
                .map_err(|e| Failure::new("proxy", format!("could not mark {} as behind a tunnel: {e}", next.include_dir.display())))?;
            }
            for (stem, site) in &sites {
                next.publish(stem, &site.domains, site.port, Some(site.https), cancel, progress).await?;
            }
            if sites.is_empty() {
                next.validate(cancel, progress).await?;
                next.reload(cancel, progress).await?;
            }
            next.settled(cancel, progress).await
        }
        .await;

        if let Err(failure) = moved {
            progress.line(format!("Putting {from} back")).await;
            for (stem, _) in &sites {
                let _ = std::fs::remove_file(next.site_file(stem));
            }
            if !next_running {
                if let Some(unit) = next.unit() {
                    let _ = systemctl(&["disable", "--now", unit], cancel, progress).await;
                }
            }
            if old_running {
                let _ = systemctl(
                    &["start", self.unit().unwrap_or_default()],
                    cancel,
                    progress,
                )
                .await;
            }
            return Err(failure.with_next_step(format!(
                "{from} is still serving this machine's sites. Fix what stopped {label}, then deploy with it again."
            )));
        }

        for (stem, _) in &sites {
            let _ = std::fs::remove_file(
                self.include_dir
                    .join(format!("{stem}.{}", self.extension())),
            );
        }
        let _ = std::fs::remove_file(self.include_dir.join(PLAIN_HTTP_MARKER));
        if let Some(unit) = self.unit() {
            if unit_exists(unit).await {
                let _ = systemctl(&["disable", unit], cancel, progress).await;
            }
        }
        progress
            .line(format!("{label} now serves this machine's sites"))
            .await;

        Ok(next)
    }

    /// A proxy can start and then fall over a moment later: another
    /// program has port 443, or a site file it only reads once running is
    /// wrong. Before the old proxy is let go, wait a few seconds and check
    /// this one is still running and answering on port 80.
    async fn settled(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let Some(unit) = self.unit() else {
            return Ok(());
        };
        tokio::time::sleep(SETTLE).await;
        let running = unit_active(unit).await;
        let answering = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect("127.0.0.1:80"),
        )
        .await
        .is_ok_and(|connected| connected.is_ok());
        if running && answering {
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
        Err(Failure::new(
            "proxy",
            if running {
                format!("{} started but isn't answering on port 80", self.backend.label())
            } else {
                format!("{} started but stopped again", self.backend.label())
            },
        )
        .with_output(journal.tail().to_vec())
        .with_next_step(format!(
            "Something else may be using port 80 or 443 (`ss -ltnp` shows what), or its config has an error. `journalctl -u {unit}` says which."
        )))
    }

    pub async fn unpublish(
        &self,
        service: &str,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let site = self.site_file(service);
        let stem = crate::git::sanitise(service);
        site_options::remove(&self.sites_dir, &stem);
        let _ = std::fs::remove_file(self.auth_file(&stem));

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

    /// The switches of the app a visitor's host belongs to: one of its
    /// names, a subdomain one level under one of its wildcards, or its www
    /// alias. For the maintenance page.
    pub fn options_for_host(&self, host: &str) -> Option<SiteOptions> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let host = host.split(':').next().unwrap_or_default().to_string();
        if host.is_empty() {
            return None;
        }
        self.our_sites().into_iter().find_map(|(stem, site)| {
            let switches = self.switches(&stem, &site.domains);
            let matches = site.domains.iter().any(|d| {
                let d = d.to_ascii_lowercase();
                match d.strip_prefix("*.") {
                    Some(parent) => host
                        .split_once('.')
                        .is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
                    None => d == host,
                }
            }) || switches.alias.as_deref() == Some(host.as_str());
            matches.then_some(switches.options)
        })
    }

    /// Sets an app's site switches and rewrites its site at once, with no
    /// redeploy. If the proxy won't take the new config, the switches, the
    /// site file and its password file are all put back as they were.
    pub async fn set_site_options(
        &self,
        service: &str,
        options: &SiteOptions,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<serde_json::Value, Failure> {
        site_options::validate(options)?;
        if self.backend == ProxyBackend::None {
            return Err(Self::none_configured());
        }
        let stem = crate::git::sanitise(service);
        let path = self.site_file(service);
        let Some((before, site)) = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| read_site(self.backend, &text).map(|site| (text, site)))
        else {
            return Err(Failure::new(
                "site_options",
                format!("{service} has no domain on this machine"),
            )
            .with_next_step("Give the app a domain first, then turn these on."));
        };

        let old_options = site_options::load(&self.sites_dir, &stem);
        let old_auth = std::fs::read(self.auth_file(&stem)).ok();
        let had_alias = self.switches(&stem, &site.domains).alias.is_some();
        let put_back = || {
            let _ = site_options::save(&self.sites_dir, &stem, &old_options);
            let _ = std::fs::write(&path, &before);
            match &old_auth {
                Some(bytes) => {
                    let _ = std::fs::write(self.auth_file(&stem), bytes);
                }
                None => {
                    let _ = std::fs::remove_file(self.auth_file(&stem));
                }
            }
        };

        site_options::save(&self.sites_dir, &stem, options).map_err(|e| {
            Failure::new(
                "site_options",
                format!("could not save the site's settings: {e}"),
            )
        })?;
        let plain_http = self.plain_http();
        let after = match self.render_site(&stem, &site, plain_http) {
            Ok(text) => text,
            Err(failure) => {
                put_back();
                return Err(failure);
            }
        };
        if let Err(failure) = self.write_auth_file(&stem, options) {
            put_back();
            return Err(failure);
        }
        if let Err(e) = std::fs::write(&path, &after) {
            put_back();
            return Err(Failure::new(
                "proxy",
                format!("could not write {}: {e}", path.display()),
            ));
        }
        if let Err(failure) = self.validate(cancel, progress).await {
            put_back();
            return Err(failure);
        }
        self.reload(cancel, progress).await?;

        let switches = self.switches(&stem, &site.domains);
        if options.maintenance {
            progress
                .line(
                    "Visitors see the maintenance page; the app keeps running behind it"
                        .to_string(),
                )
                .await;
        }
        if let Some(auth) = &options.basic_auth {
            progress
                .line(format!("The site asks for a password (user {})", auth.user))
                .await;
        }
        if let Some((alias, canonical)) = switches.www() {
            progress
                .line(format!("{alias} redirects to {canonical}"))
                .await;
        }
        if !options.redirects.is_empty() {
            progress
                .line(format!("{} path redirect(s) set", options.redirects.len()))
                .await;
        }
        // A new www name needs to join the certificate for nginx and Apache;
        // Caddy and Traefik get one for it themselves.
        if switches.alias.is_some()
            && !had_alias
            && self.uses_certbot()
            && site.https
            && !plain_http
        {
            self.certify(&stem, &site, &path, cancel, progress).await;
        }

        Ok(serde_json::json!({
            "service": service,
            "maintenance": options.maintenance,
            "password": options.basic_auth.is_some(),
            "www": switches.www().map(|(alias, canonical)| serde_json::json!({"from": alias, "to": canonical})),
            "redirects": options.redirects.len(),
        }))
    }

    fn validate_command(&self) -> (tokio::process::Command, Duration) {
        let main = self.main_config.to_string_lossy().into_owned();
        let mut command = match self.backend {
            ProxyBackend::Nginx => {
                let mut c = tokio::process::Command::new("nginx");
                c.args(["-t", "-c", &main]);
                c
            }
            ProxyBackend::Apache => {
                let mut c = tokio::process::Command::new("apache2ctl");
                c.arg("configtest");
                c
            }
            ProxyBackend::Traefik => tokio::process::Command::new("true"),
            _ => {
                let mut c = tokio::process::Command::new("caddy");
                c.args(["validate", "--config", &main, "--adapter", "caddyfile"]);
                c
            }
        };
        command.kill_on_drop(true);
        (command, Duration::from_secs(30))
    }

    fn reload_command(&self) -> (tokio::process::Command, Duration) {
        let main = self.main_config.to_string_lossy().into_owned();
        let mut command = match self.backend {
            ProxyBackend::Nginx => {
                let mut c = tokio::process::Command::new("nginx");
                c.args(["-s", "reload", "-c", &main]);
                c
            }
            ProxyBackend::Apache => {
                let mut c = tokio::process::Command::new("systemctl");
                c.args(["reload", "apache2"]);
                c
            }
            ProxyBackend::Traefik => tokio::process::Command::new("true"),
            _ => {
                let mut c = tokio::process::Command::new("caddy");
                c.args(["reload", "--config", &main, "--adapter", "caddyfile"]);
                c
            }
        };
        command.kill_on_drop(true);
        (command, Duration::from_secs(60))
    }

    async fn validate(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let main = self.main_config.to_string_lossy().into_owned();
        let (program, args): (&str, Vec<&str>) = match self.backend {
            ProxyBackend::Nginx => ("nginx", vec!["-t", "-c", &main]),
            ProxyBackend::Apache => ("apache2ctl", vec!["configtest"]),
            // Traefik has no way to check a config without running it; it
            // logs a bad file and keeps serving the rest.
            ProxyBackend::Traefik | ProxyBackend::None => return Ok(()),
            ProxyBackend::Caddy => (
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
        let Some(unit) = self.unit() else {
            return Ok(());
        };
        let main = self.main_config.to_string_lossy().into_owned();
        let (program, args): (&str, Vec<&str>) = match self.backend {
            ProxyBackend::Nginx => ("nginx", vec!["-s", "reload", "-c", &main]),
            ProxyBackend::Apache => ("systemctl", vec!["reload", "apache2"]),
            ProxyBackend::Traefik => ("systemctl", vec!["is-active", "--quiet", "traefik"]),
            _ => (
                "caddy",
                vec!["reload", "--config", &main, "--adapter", "caddyfile"],
            ),
        };

        // A stopped proxy can't reload (Caddy's reload talks to the running
        // one on localhost:2019). Starting it loads the same config.
        if !unit_active(unit).await {
            progress
                .line(format!("{unit} is not running: starting it"))
                .await;
            let started = systemctl(&["enable", "--now", unit], cancel, progress).await;
            if started && unit_active(unit).await {
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
            Err(
                Failure::new("proxy", format!("{} reload failed", self.backend.label()))
                    .with_output(outcome.tail().to_vec())
                    .with_next_step(format!("Check `systemctl status {unit}` on the machine.")),
            )
        }
    }
}

/// A site's file as it was before a publish that didn't take, and the
/// proxy's main config if the publish changed it.
fn put_back(site: &Path, previous: Option<&[u8]>, main: &Path, previous_main: Option<&str>) {
    match previous {
        Some(bytes) => {
            let _ = std::fs::write(site, bytes);
        }
        None => {
            let _ = std::fs::remove_file(site);
        }
    }
    if let Some(text) = previous_main {
        let _ = std::fs::write(main, text);
    }
}

async fn systemctl(args: &[&str], cancel: &mut watch::Receiver<bool>, progress: &Progress) -> bool {
    run_child(
        "systemctl",
        args,
        None,
        &[],
        Duration::from_secs(60),
        cancel,
        progress,
        None,
    )
    .await
    .success()
}

/// Runs a command with nothing watching it (a background retry), true
/// when it finished in time and succeeded.
async fn quiet((mut command, limit): (tokio::process::Command, Duration)) -> bool {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match tokio::time::timeout(limit, command.status()).await {
        Ok(Ok(status)) => status.success(),
        _ => false,
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

/// A system user's uid and gid, from /etc/passwd.
pub(crate) fn system_user(name: &str) -> Option<(u32, u32)> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        let _password = fields.next()?;
        Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
    })
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

fn add_apache_include(existing: &str) -> Option<String> {
    if existing.lines().any(|l| l.trim() == APACHE_INCLUDE_LINE) {
        return None;
    }

    let mut updated = existing.to_string();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("\n# Added by ServerOS: per-service sites live in serveros.d.\n");
    updated.push_str(APACHE_INCLUDE_LINE);
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
    fn a_publish_that_does_not_take_puts_the_files_back() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("shop.caddy");
        let main = dir.path().join("Caddyfile");

        // An app's site that was there: back to what it was.
        std::fs::write(&site, "new").unwrap();
        std::fs::write(&main, "new main").unwrap();
        put_back(&site, Some(b"old"), &main, Some("old main"));
        assert_eq!(std::fs::read_to_string(&site).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(&main).unwrap(), "old main");

        // A new app's site: gone, and the main config left as it is when
        // the publish didn't change it.
        put_back(&site, None, &main, None);
        assert!(!site.exists());
        assert_eq!(std::fs::read_to_string(&main).unwrap(), "old main");
    }

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
            cert_root: dir.join("live"),
            sites_dir: dir.join("sites"),
            traffic_dir: dir.join("traffic"),
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
            cert_root: dir.join("live"),
            sites_dir: dir.join("sites"),
            traffic_dir: dir.join("traffic"),
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
            cert_root: dir.join("live"),
            sites_dir: dir.join("sites"),
            traffic_dir: dir.join("traffic"),
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
        let block = render_nginx(&["shop.example".into()], 3000, None, false).unwrap();

        assert!(block.contains("server_name shop.example;"));
        assert!(block.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(render_nginx(&["a;b".into()], 3000, None, false).is_err());
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

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("serveros-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn proxy_in(backend: ProxyBackend, dir: &Path) -> Proxy {
        Proxy {
            backend,
            main_config: dir.join("main.conf"),
            include_dir: dir.join("serveros.d"),
            cert_root: dir.join("live"),
            sites_dir: dir.join("sites"),
            traffic_dir: dir.join("traffic"),
        }
    }

    #[test]
    fn every_proxy_reads_its_own_sites_back() {
        let domains: Vec<String> = vec!["acme.io".into(), "www.acme.io".into(), "*.acme.io".into()];
        let tls = PathBuf::from("/etc/letsencrypt/live/serveros-shop");
        let texts = [
            (ProxyBackend::Caddy, render(&domains, 4123, false).unwrap()),
            (ProxyBackend::Caddy, render(&domains, 4123, true).unwrap()),
            (
                ProxyBackend::Nginx,
                render_nginx(&domains, 4123, None, false).unwrap(),
            ),
            (
                ProxyBackend::Nginx,
                render_nginx(&domains, 4123, Some(&tls), false).unwrap(),
            ),
            (
                ProxyBackend::Nginx,
                render_nginx(&domains, 4123, None, true).unwrap(),
            ),
            (
                ProxyBackend::Apache,
                render_apache("shop", &domains, 4123, Some(&tls), false).unwrap(),
            ),
            (
                ProxyBackend::Apache,
                render_apache("shop", &domains, 4123, None, true).unwrap(),
            ),
            (
                ProxyBackend::Traefik,
                render_traefik("shop", &domains, 4123, false).unwrap(),
            ),
            (
                ProxyBackend::Traefik,
                render_traefik("shop", &domains, 4123, true).unwrap(),
            ),
        ];
        for (backend, text) in texts {
            let site = read_site(backend, &text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(
                site,
                Site {
                    domains: domains.clone(),
                    port: 4123,
                    https: true
                },
                "{text}"
            );
        }

        assert!(read_site(
            ProxyBackend::Nginx,
            "server {\n    server_name mine.io;\n}\n"
        )
        .is_none());
        assert!(read_site(ProxyBackend::Nginx, NGINX_SHARED).is_none());
    }

    #[test]
    fn nginx_sites_written_before_the_site_line_still_read_back() {
        let old = "# Managed by ServerOS. Edits here are overwritten on the next deploy.\nserver {\n    listen 80;\n    listen [::]:80;\n    server_name shop.example www.shop.example;\n\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n";

        assert_eq!(
            read_site(ProxyBackend::Nginx, old),
            Some(Site {
                domains: vec!["shop.example".into(), "www.shop.example".into()],
                port: 3000,
                https: true
            })
        );
    }

    #[test]
    fn nginx_answers_the_challenge_and_redirects_once_it_has_a_certificate() {
        let tls = PathBuf::from("/etc/letsencrypt/live/serveros-shop");
        let before = render_nginx(&["shop.example".into()], 3000, None, false).unwrap();
        let after = render_nginx(&["shop.example".into()], 3000, Some(&tls), false).unwrap();

        assert!(before.contains("location ^~ /.well-known/acme-challenge/"));
        assert!(before.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(!before.contains("443"));
        assert!(before.contains("$serveros_connection_upgrade"));

        assert!(after.contains("location ^~ /.well-known/acme-challenge/"));
        assert!(after.contains("return 301 https://$host$request_uri;"));
        assert!(after.contains("listen 443 ssl;"));
        assert!(
            after.contains("ssl_certificate /etc/letsencrypt/live/serveros-shop/fullchain.pem;")
        );
        assert!(
            after.contains("ssl_certificate_key /etc/letsencrypt/live/serveros-shop/privkey.pem;")
        );
        assert_eq!(after.matches("proxy_pass").count(), 1);
    }

    #[test]
    fn wildcards_stay_plain_http_on_nginx_apache_and_traefik() {
        let tls = PathBuf::from("/live/serveros-shop");
        let domains: Vec<String> = vec!["acme.io".into(), "*.acme.io".into()];

        let nginx = render_nginx(&domains, 3000, Some(&tls), false).unwrap();
        let (secure, wild) = nginx.split_once("# Wildcard subdomains").unwrap();
        assert!(secure.contains("server_name acme.io;"));
        assert!(wild.contains("server_name *.acme.io;"));
        assert!(!wild.contains("443"));
        assert!(!wild.contains("return 301"));

        let apache = render_apache("shop", &domains, 3000, Some(&tls), false).unwrap();
        let (secure, wild) = apache.split_once("# Wildcard subdomains").unwrap();
        assert!(secure.contains("ServerName acme.io\n"));
        assert!(!secure.contains("ServerAlias *.acme.io"));
        assert!(
            wild.contains("ServerName shop-wildcard.serveros.invalid\n    ServerAlias *.acme.io\n")
        );
        assert!(!wild.contains("SSLEngine"));

        let traefik = render_traefik("shop", &domains, 3000, false).unwrap();
        assert!(traefik.contains("rule = 'Host(`acme.io`)'"));
        assert!(traefik.contains("[http.routers.serveros-shop-wildcard]\n  rule = 'HostRegexp(`^[a-z0-9-]+\\.acme\\.io$`)'\n  entryPoints = [\"web\"]"));
    }

    #[test]
    fn apache_redirects_to_https_and_proxies_websockets() {
        let tls = PathBuf::from("/live/serveros-shop");
        let site = render_apache(
            "shop",
            &["shop.example".into(), "www.shop.example".into()],
            3000,
            Some(&tls),
            false,
        )
        .unwrap();

        assert!(site.contains(
            "<VirtualHost *:80>\n    ServerName shop.example\n    ServerAlias www.shop.example\n"
        ));
        assert!(site.contains("ProxyPass /.well-known/acme-challenge/ !"));
        assert!(site.contains("RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"));
        assert!(site.contains("<VirtualHost *:443>"));
        assert!(site.contains("SSLCertificateFile /live/serveros-shop/fullchain.pem"));
        assert!(site.contains("ProxyPass / http://127.0.0.1:3000/ upgrade=websocket"));
        assert!(site.contains("RequestHeader set X-Forwarded-Proto \"https\""));
        assert!(render_apache("shop", &["a b".into()], 3000, None, false).is_err());
    }

    #[test]
    fn traefik_sites_get_certificates_from_the_serveros_resolver() {
        let site = render_traefik(
            "shop",
            &["shop.example".into(), "www.shop.example".into()],
            3000,
            false,
        )
        .unwrap();

        assert!(site.contains("rule = 'Host(`shop.example`) || Host(`www.shop.example`)'"));
        assert!(site.contains("[http.routers.serveros-shop.tls]\n    certResolver = \"serveros\""));
        assert!(site.contains("[http.middlewares.serveros-shop-https.redirectScheme]"));
        assert!(site.contains("url = \"http://127.0.0.1:3000\""));

        let tunnel = render_traefik("shop", &["shop.example".into()], 3000, true).unwrap();
        assert!(!tunnel.contains("certResolver"));
        assert!(tunnel.contains("X-Forwarded-Proto = \"https\""));
        assert!(fresh_traefik_config().contains(&format!("directory = \"{TRAEFIK_INCLUDE_DIR}\"")));
        assert!(
            fresh_traefik_config().contains("[certificatesResolvers.serveros.acme.httpChallenge]")
        );
    }

    #[test]
    fn certbot_asks_for_the_plain_names_and_reloads_the_proxy_on_renewal() {
        let dir = temp_dir("certbot-args");
        let nginx = proxy_in(ProxyBackend::Nginx, &dir);
        let names: Vec<String> = vec!["acme.io".into(), "www.acme.io".into()];

        let args = nginx.certbot_args("shop", &names).join(" ");
        assert!(args.starts_with("certonly --webroot -w /var/lib/serveros-acme --cert-name serveros-shop -d acme.io -d www.acme.io"));
        assert!(args.contains("--non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring --expand"));
        assert!(args.ends_with("--deploy-hook systemctl reload nginx"));

        let apache = proxy_in(ProxyBackend::Apache, &dir);
        assert!(apache
            .certbot_args("shop", &names)
            .join(" ")
            .ends_with("systemctl reload apache2"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn our_sites_are_only_the_ones_we_wrote_in_this_proxys_format() {
        let dir = temp_dir("our-sites");
        let nginx = proxy_in(ProxyBackend::Nginx, &dir);
        nginx.ensure_import().unwrap_err();
        std::fs::create_dir_all(&nginx.include_dir).unwrap();
        std::fs::write(
            nginx.include_dir.join("shop.conf"),
            render_nginx(&["acme.io".into()], 3000, None, false).unwrap(),
        )
        .unwrap();
        std::fs::write(
            nginx.include_dir.join("mine.conf"),
            "server { server_name mine.io; }\n",
        )
        .unwrap();
        std::fs::write(nginx.include_dir.join(NGINX_SHARED_FILE), NGINX_SHARED).unwrap();
        std::fs::write(
            nginx.include_dir.join("old.caddy"),
            render(&["old.io".into()], 1, false).unwrap(),
        )
        .unwrap();

        assert_eq!(
            nginx.our_sites(),
            vec![(
                "shop".to_string(),
                Site {
                    domains: vec!["acme.io".into()],
                    port: 3000,
                    https: true
                }
            )]
        );

        std::fs::create_dir_all(nginx.cert_dir("shop")).unwrap();
        std::fs::write(nginx.cert_dir("shop").join("fullchain.pem"), "").unwrap();
        let rewrites = nginx.rerendered(false);
        assert_eq!(rewrites.len(), 1);
        assert!(rewrites[0].2.contains("listen 443 ssl;"));
        assert!(nginx.rerendered(true)[0]
            .2
            .contains("X-Forwarded-Proto https;"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nginx_gets_its_shared_settings_and_include_once() {
        let dir = temp_dir("nginx-import");
        let nginx = proxy_in(ProxyBackend::Nginx, &dir);
        std::fs::write(
            &nginx.main_config,
            "events {\n}\n\nhttp {\n    sendfile on;\n}\n",
        )
        .unwrap();

        assert!(nginx.ensure_import().unwrap());
        assert!(!nginx.ensure_import().unwrap());
        assert_eq!(
            std::fs::read_to_string(nginx.include_dir.join(NGINX_SHARED_FILE)).unwrap(),
            NGINX_SHARED
        );
        assert_eq!(
            std::fs::read_to_string(&nginx.main_config)
                .unwrap()
                .matches(NGINX_INCLUDE_LINE)
                .count(),
            1
        );

        std::fs::write(&nginx.main_config, "events {}\n").unwrap();
        assert!(nginx.ensure_import().is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apache_reads_our_sites_through_one_include() {
        let first = add_apache_include(
            "ServerRoot \"/etc/apache2\"\nIncludeOptional sites-enabled/*.conf\n",
        )
        .unwrap();

        assert!(first.ends_with(&format!("{APACHE_INCLUDE_LINE}\n")));
        assert!(first.contains("IncludeOptional sites-enabled/*.conf"));
        assert!(add_apache_include(&first).is_none());
    }

    #[test]
    fn traefik_config_is_written_once_and_someone_elses_is_left_alone() {
        let dir = temp_dir("traefik-import");
        let ours = Proxy {
            main_config: dir.join("traefik.toml"),
            include_dir: PathBuf::from(TRAEFIK_INCLUDE_DIR),
            ..proxy_in(ProxyBackend::Traefik, &dir)
        };
        let config = ours.main_config.clone();

        assert!(ours.ensure_traefik_provider().unwrap());
        assert!(!ours.ensure_traefik_provider().unwrap());
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            fresh_traefik_config()
        );

        std::fs::write(&config, "[providers.docker]\n").unwrap();
        let refused = ours.ensure_traefik_provider().unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("doesn't read ServerOS's sites"),
            "{refused}"
        );
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "[providers.docker]\n"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_proxy_has_its_own_files_and_service() {
        for (backend, file, unit) in [
            (
                ProxyBackend::Caddy,
                "/etc/caddy/serveros.d/shop.caddy",
                "caddy",
            ),
            (
                ProxyBackend::Nginx,
                "/etc/nginx/serveros.d/shop.conf",
                "nginx",
            ),
            (
                ProxyBackend::Apache,
                "/etc/apache2/serveros.d/shop.conf",
                "apache2",
            ),
            (
                ProxyBackend::Traefik,
                "/etc/traefik/serveros.d/shop.toml",
                "traefik",
            ),
        ] {
            let proxy = Proxy::for_backend(backend);
            assert_eq!(proxy.site_file("shop"), PathBuf::from(file));
            assert_eq!(proxy.unit(), Some(unit));
        }
        assert_eq!(Proxy::for_backend(ProxyBackend::None).unit(), None);
        assert!(Proxy::for_backend(ProxyBackend::Traefik)
            .include_line()
            .is_none());
    }

    #[test]
    fn installing_each_proxy_opens_the_ports_its_certificates_need() {
        for script in [
            NGINX_INSTALL_SCRIPT,
            APACHE_INSTALL_SCRIPT,
            TRAEFIK_INSTALL_SCRIPT,
        ] {
            assert!(script.contains("ufw allow 80/tcp"));
            assert!(script.contains("ufw allow 443/tcp"));
        }
        assert!(NGINX_INSTALL_SCRIPT.contains("apt-get install -y -q nginx certbot"));
        assert!(APACHE_INSTALL_SCRIPT
            .contains("a2enmod -q proxy proxy_http proxy_wstunnel headers rewrite ssl"));
        assert!(TRAEFIK_INSTALL_SCRIPT.contains("sha256sum -c -"));
        assert!(TRAEFIK_INSTALL_SCRIPT.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(TRAEFIK_INSTALL_SCRIPT.contains("--configFile=/etc/traefik/traefik.toml"));
    }

    #[test]
    fn the_challenge_folder_is_outside_the_private_state_folder() {
        assert!(!ACME_WEBROOT.starts_with("/var/lib/serveros/"));
        assert!(NGINX_ACME.contains(&format!("root {ACME_WEBROOT};")));
        assert!(APACHE_ACME.contains(&format!("<Directory {ACME_WEBROOT}>")));
    }

    #[test]
    fn a_site_with_https_off_is_plain_http_on_every_proxy_and_reads_back() {
        let domains: Vec<String> = vec!["acme.io".into(), "*.acme.io".into()];
        for backend in [
            ProxyBackend::Caddy,
            ProxyBackend::Nginx,
            ProxyBackend::Apache,
            ProxyBackend::Traefik,
        ] {
            let text = render_http_only(backend, "shop", &domains, 3000).unwrap();
            let site = read_site(backend, &text).unwrap_or_else(|| panic!("{text}"));
            assert!(!site.https, "{text}");
            assert_eq!(site.port, 3000);
            assert_eq!(site.domains, domains);
            for secure in [
                "443",
                "certResolver",
                "SSLEngine",
                "return 301",
                "redirectScheme",
                "on_demand",
            ] {
                assert!(!text.contains(secure), "{backend:?} has {secure}: {text}");
            }
        }

        let caddy = render_http_only(ProxyBackend::Caddy, "shop", &domains, 3000).unwrap();
        assert!(caddy.contains("http://acme.io, http://*.acme.io {"));
        assert!(wildcard_parents(&caddy).is_empty());
    }

    #[test]
    fn https_on_is_the_default_for_site_files_that_dont_say() {
        let text = render(&["acme.io".into()], 3000, false).unwrap();
        assert!(read_site(ProxyBackend::Caddy, &text).unwrap().https);
        assert!(!text.contains("https=off"));
    }

    #[test]
    fn a_proxy_writes_https_off_sites_as_plain_http_even_with_a_certificate() {
        let dir = temp_dir("https-off");
        let nginx = proxy_in(ProxyBackend::Nginx, &dir);
        std::fs::create_dir_all(nginx.cert_dir("shop")).unwrap();
        std::fs::write(nginx.cert_dir("shop").join("fullchain.pem"), "").unwrap();
        let site = Site {
            domains: vec!["acme.io".into()],
            port: 3000,
            https: false,
        };

        let text = nginx.render_site("shop", &site, false).unwrap();
        assert!(text.contains("https=off"));
        assert!(!text.contains("listen 443"));
        let on = nginx
            .render_site(
                "shop",
                &Site {
                    https: true,
                    ..site
                },
                false,
            )
            .unwrap();
        assert!(on.contains("listen 443 ssl;"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    const TEST_HASH: &str = "$2y$10$abcdefghijklmnopqrstuuJ7lYk0x0k9w2v3Zr8mQxqf5yJ1sZ6a.";

    fn all_switches() -> SiteOptions {
        SiteOptions {
            maintenance: true,
            maintenance_html: None,
            basic_auth: Some(site_options::BasicAuth {
                user: "staff".into(),
                hash: TEST_HASH.into(),
            }),
            www_redirect: true,
            redirects: vec![
                site_options::PathRedirect {
                    from: "/old-pricing".into(),
                    to: "/pricing".into(),
                    permanent: true,
                },
                site_options::PathRedirect {
                    from: "/docs".into(),
                    to: "https://docs.acme.io/start".into(),
                    permanent: false,
                },
            ],
        }
    }

    /// Renders shop (acme.io and its wildcard) with every switch on, for
    /// each proxy and mode.
    fn rendered_with_switches(
        backend: ProxyBackend,
        https: bool,
        plain_http: bool,
        cert: bool,
    ) -> String {
        let dir = temp_dir(&format!(
            "switches-{}-{https}-{plain_http}-{cert}",
            backend.label()
        ));
        let proxy = proxy_in(backend, &dir);
        site_options::save(&proxy.sites_dir, "shop", &all_switches()).unwrap();
        if cert {
            std::fs::create_dir_all(proxy.cert_dir("shop")).unwrap();
            std::fs::write(proxy.cert_dir("shop").join("fullchain.pem"), "x").unwrap();
        }
        let site = Site {
            domains: vec!["acme.io".into(), "*.acme.io".into()],
            port: 4123,
            https,
        };
        let text = proxy.render_site("shop", &site, plain_http).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        text
    }

    #[test]
    fn switches_reach_every_proxy_in_every_mode() {
        for backend in [
            ProxyBackend::Caddy,
            ProxyBackend::Nginx,
            ProxyBackend::Apache,
            ProxyBackend::Traefik,
        ] {
            for (https, plain_http, cert) in [
                (true, false, false),
                (true, false, true),
                (true, true, false),
                (false, false, false),
            ] {
                let text = rendered_with_switches(backend, https, plain_http, cert);
                let label = format!(
                    "{} https={https} tunnel={plain_http} cert={cert}",
                    backend.label()
                );
                // Maintenance: visitors go to the daemon, the meta line keeps the app's port.
                assert!(text.contains("port=4123"), "{label}");
                assert!(
                    text.contains(&format!("127.0.0.1:{MAINTENANCE_PORT}")),
                    "{label}"
                );
                assert!(!text.contains("127.0.0.1:4123"), "{label}");
                assert!(text.contains("www.acme.io"), "{label}: no alias");
                assert!(text.contains("old-pricing"), "{label}");
                assert!(text.contains("https://docs.acme.io/start"), "{label}");
                match backend {
                    ProxyBackend::Caddy | ProxyBackend::Traefik => {
                        assert!(text.contains(TEST_HASH), "{label}")
                    }
                    _ => assert!(
                        text.contains("shop.htpasswd") && !text.contains(TEST_HASH),
                        "{label}"
                    ),
                }
            }
        }
    }

    #[test]
    fn caddy_redirects_the_www_name_in_a_block_of_its_own() {
        let text = rendered_with_switches(ProxyBackend::Caddy, true, false, false);
        assert!(text.contains("\nwww.acme.io {\n\tredir https://acme.io{uri} permanent\n}\n"));
        assert!(text.contains("\tredir /old-pricing /pricing permanent\n"));
        assert!(text.contains("\tredir /docs https://docs.acme.io/start temporary\n"));
        assert!(text.contains(&format!("\tbasicauth {{\n\t\tstaff {TEST_HASH}\n\t}}\n")));

        let tunnel = rendered_with_switches(ProxyBackend::Caddy, true, true, false);
        assert!(
            tunnel.contains("\nhttp://www.acme.io {\n\tredir https://acme.io{uri} permanent\n}\n")
        );
        let http = rendered_with_switches(ProxyBackend::Caddy, false, false, false);
        assert!(http.contains("\nhttp://www.acme.io {\n\tredir http://acme.io{uri} permanent\n}\n"));
    }

    #[test]
    fn nginx_never_redirects_or_locks_certificate_challenges() {
        let text = rendered_with_switches(ProxyBackend::Nginx, true, false, true);
        assert!(text.contains("server_name acme.io www.acme.io;"));
        assert!(
            text.contains("    location = /old-pricing {\n        return 301 /pricing;\n    }\n")
        );
        assert!(text.contains(
            "    location = /docs {\n        return 302 https://docs.acme.io/start;\n    }\n"
        ));
        assert!(text.contains("        if ($host = www.acme.io) {\n            return 301 https://acme.io$request_uri;\n        }\n"));
        let acme = text
            .find("location ^~ /.well-known/acme-challenge/")
            .unwrap();
        let challenge_block = &text[acme..acme + 140];
        assert!(!challenge_block.contains("auth_basic"));
    }

    #[test]
    fn apache_rewrites_before_it_proxies_and_leaves_challenges_open() {
        let text = rendered_with_switches(ProxyBackend::Apache, true, false, false);
        assert!(text.contains("ServerAlias *.acme.io") || text.contains("ServerAlias www.acme.io"));
        assert!(text.contains("    RewriteCond %{HTTP_HOST} ^www\\.acme\\.io$ [NC]\n    RewriteRule ^ %{REQUEST_SCHEME}://acme.io%{REQUEST_URI} [R=301,L]\n"));
        assert!(text.contains("    RewriteRule ^/old-pricing$ /pricing [R=301,L]\n"));
        assert!(
            text.contains("<Location /.well-known/acme-challenge/>\n        Require all granted")
        );
        assert!(
            text.find("RewriteRule ^/old-pricing").unwrap() < text.find("ProxyPass / ").unwrap()
        );
    }

    #[test]
    fn traefik_chains_the_switches_on_each_router() {
        let text = rendered_with_switches(ProxyBackend::Traefik, true, false, false);
        assert!(text.contains("rule = 'Host(`acme.io`) || Host(`www.acme.io`)'"));
        assert!(text.contains("  middlewares = [\"serveros-shop-www\", \"serveros-shop-redirect-0\", \"serveros-shop-redirect-1\", \"serveros-shop-auth\"]\n"));
        assert!(text.contains("  regex = '^https?://www\\.acme\\.io(:[0-9]+)?/(.*)'\n  replacement = 'https://acme.io/${2}'\n"));
        assert!(text.contains("  regex = '^(https?://[^/]+)/old-pricing(\\?.*)?$'\n  replacement = '${1}/pricing'\n  permanent = true\n"));
        assert!(text.contains(&format!("  users = ['staff:{TEST_HASH}']\n")));

        let tunnel = rendered_with_switches(ProxyBackend::Traefik, true, true, false);
        assert!(
            tunnel.contains("  middlewares = [\"serveros-shop-forwarded\", \"serveros-shop-www\"")
        );
    }

    #[test]
    fn a_www_domain_redirects_its_bare_name_and_a_listed_name_is_left_alone() {
        let switches = Switches::new(
            &["www.acme.io".into()],
            SiteOptions {
                www_redirect: true,
                ..Default::default()
            },
            None,
        );
        assert_eq!(switches.www(), Some(("acme.io", "www.acme.io")));

        let both = Switches::new(
            &["acme.io".into(), "www.acme.io".into()],
            SiteOptions {
                www_redirect: true,
                ..Default::default()
            },
            None,
        );
        assert_eq!(both.www(), None);
    }

    #[test]
    fn the_maintenance_page_finds_its_site_by_any_name() {
        let dir = temp_dir("maintenance-host");
        let proxy = proxy_in(ProxyBackend::Caddy, &dir);
        std::fs::create_dir_all(&proxy.include_dir).unwrap();
        std::fs::write(
            proxy.site_file("shop"),
            render(&["acme.io".into(), "*.acme.io".into()], 3000, false).unwrap(),
        )
        .unwrap();
        let options = SiteOptions {
            maintenance: true,
            maintenance_html: Some("<p>shop soon</p>".into()),
            www_redirect: true,
            ..Default::default()
        };
        site_options::save(&proxy.sites_dir, "shop", &options).unwrap();

        for host in [
            "acme.io",
            "ACME.io.",
            "acme.io:443",
            "tenant.acme.io",
            "www.acme.io",
        ] {
            assert_eq!(
                proxy.options_for_host(host).as_ref(),
                Some(&options),
                "{host}"
            );
        }
        assert_eq!(proxy.options_for_host("a.b.acme.io"), None);
        assert_eq!(proxy.options_for_host("other.io"), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn switches_need_a_site_and_are_checked_first() {
        let dir = temp_dir("switches-checks");
        let proxy = proxy_in(ProxyBackend::Caddy, &dir);
        let (_tx, mut cancel) = watch::channel(false);
        let state = std::sync::Arc::new(daemon_state::State::in_memory().unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let progress = Progress::new(uuid::Uuid::new_v4(), state, tx, vec![]);

        let missing = proxy
            .set_site_options(
                "shop",
                &SiteOptions {
                    maintenance: true,
                    ..Default::default()
                },
                &mut cancel,
                &progress,
            )
            .await
            .unwrap_err();
        assert!(missing.to_string().contains("no domain"));

        let bad = SiteOptions {
            redirects: vec![site_options::PathRedirect {
                from: "/a;b".into(),
                to: "/c".into(),
                permanent: true,
            }],
            ..Default::default()
        };
        assert!(proxy
            .set_site_options("shop", &bad, &mut cancel, &progress)
            .await
            .is_err());
        assert!(!proxy.sites_dir.join("shop.json").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Renders shop (acme.io and its wildcard) with traffic on or off, and
    /// optionally every switch, logging to the real log folder.
    fn rendered_with_traffic(
        backend: ProxyBackend,
        (https, plain_http, cert): (bool, bool, bool),
        traffic: bool,
        switches: bool,
    ) -> String {
        let dir = temp_dir(&format!(
            "traffic-{}-{https}-{plain_http}-{cert}-{switches}",
            backend.label()
        ));
        let proxy = Proxy {
            traffic_dir: PathBuf::from(TRAFFIC_LOG_DIR),
            ..proxy_in(backend, &dir)
        };
        std::fs::create_dir_all(&proxy.sites_dir).unwrap();
        if switches {
            site_options::save(&proxy.sites_dir, "shop", &all_switches()).unwrap();
        }
        if traffic {
            std::fs::write(proxy.sites_dir.join(TRAFFIC_MARKER), "").unwrap();
        }
        if cert {
            std::fs::create_dir_all(proxy.cert_dir("shop")).unwrap();
            std::fs::write(proxy.cert_dir("shop").join("fullchain.pem"), "x").unwrap();
        }
        let site = Site {
            domains: vec!["acme.io".into(), "*.acme.io".into()],
            port: 4123,
            https,
        };
        assert_eq!(proxy.traffic_on(), traffic);
        let text = proxy.render_site("shop", &site, plain_http).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        text
    }

    const MODES: [(bool, bool, bool); 4] = [
        (true, false, false),
        (true, false, true),
        (true, true, false),
        (false, false, false),
    ];

    /// The traffic lines of a rendered site taken out again: a Caddy log
    /// block, an nginx access_log or an Apache CustomLog.
    fn without_traffic_lines(text: &str) -> String {
        let mut out = String::new();
        let mut in_block = false;
        for line in text.split_inclusive('\n') {
            if line == "\tlog {\n" {
                in_block = true;
                continue;
            }
            if in_block {
                if line == "\t}\n" {
                    in_block = false;
                }
                continue;
            }
            if line.contains("serveros_traffic;") || line.trim_start().starts_with("CustomLog ") {
                continue;
            }
            out.push_str(line);
        }
        out
    }

    #[test]
    fn traffic_only_adds_the_access_log_and_off_is_exactly_as_before() {
        for backend in [
            ProxyBackend::Caddy,
            ProxyBackend::Nginx,
            ProxyBackend::Apache,
            ProxyBackend::Traefik,
        ] {
            for mode in MODES {
                for switches in [false, true] {
                    let label = format!("{} {mode:?} switches={switches}", backend.label());
                    let off = rendered_with_traffic(backend, mode, false, switches);
                    let on = rendered_with_traffic(backend, mode, true, switches);
                    assert_eq!(without_traffic_lines(&on), off, "{label}");
                    let log = "/var/log/serveros-traffic/shop.log";
                    match backend {
                        // Traefik's log is in its own config, for every site.
                        ProxyBackend::Traefik => assert_eq!(on, off, "{label}"),
                        _ => assert!(on.contains(log) && !off.contains(log), "{label}"),
                    }
                }
            }
        }

        // With no switches, off is what the plain renderers always wrote.
        let domains: Vec<String> = vec!["acme.io".into(), "*.acme.io".into()];
        assert_eq!(
            rendered_with_traffic(ProxyBackend::Caddy, MODES[0], false, false),
            render(&domains, 4123, false).unwrap()
        );
        assert_eq!(
            rendered_with_traffic(ProxyBackend::Nginx, MODES[0], false, false),
            render_nginx(&domains, 4123, None, false).unwrap()
        );
        assert_eq!(
            rendered_with_traffic(ProxyBackend::Apache, MODES[2], false, false),
            render_apache("shop", &domains, 4123, None, true).unwrap()
        );
    }

    #[test]
    fn only_blocks_that_serve_the_site_log_it() {
        // With a certificate: the HTTPS block and the wildcard block log;
        // the plain HTTP block only sends visitors to HTTPS.
        let nginx = rendered_with_traffic(ProxyBackend::Nginx, MODES[1], true, false);
        assert_eq!(nginx.matches("access_log ").count(), 2, "{nginx}");
        let redirect = nginx.split("server {").nth(1).unwrap();
        assert!(redirect.contains("return 301 https://$host"));
        assert!(!redirect.contains("access_log"));

        let apache = rendered_with_traffic(ProxyBackend::Apache, MODES[1], true, false);
        assert_eq!(apache.matches("CustomLog ").count(), 2, "{apache}");
        assert!(apache.contains(&format!(
            "CustomLog /var/log/serveros-traffic/shop.log {APACHE_LOG_FORMAT}\n"
        )));

        // Caddy: the site and its wildcard, never the www alias's redirect.
        let caddy = rendered_with_traffic(ProxyBackend::Caddy, MODES[0], true, true);
        assert_eq!(caddy.matches("\tlog {").count(), 2, "{caddy}");
        let alias = caddy.split("\nwww.acme.io {").nth(1).unwrap();
        assert!(!alias.contains("log {"));
        assert!(caddy.contains("output file /var/log/serveros-traffic/shop.log {"));
        assert!(caddy.contains("roll_size 50MiB"));
    }

    #[test]
    fn the_nginx_log_format_matches_what_the_reader_reads() {
        assert!(NGINX_SHARED.contains("log_format serveros_traffic escape=json"));
        // A line as nginx writes it with this format.
        let line = NGINX_SHARED
            .split('\'')
            .nth(3)
            .unwrap()
            .replace("$msec", "1763640005.250")
            .replace("$host", "acme.io")
            .replace("$remote_addr", "203.0.113.1")
            .replace("$request_uri", "/a?b")
            .replace("$status", "200")
            .replace("$body_bytes_sent", "12")
            .replace("$request_time", "0.004")
            .replace("$http_referer", "https://example.org/x")
            .replace("$http_user_agent", "curl/8");
        let hit = traffic::parse_line(traffic::Format::Line, &line).unwrap();
        assert_eq!((hit.ts, hit.status, hit.bytes), (1763640005, 200, 12));
        assert_eq!(hit.path, "/a");
        assert_eq!(hit.referrer.as_deref(), Some("example.org"));
    }

    #[tokio::test]
    async fn traffic_is_kept_beside_the_switches_and_traefik_gets_its_log() {
        let dir = temp_dir("traffic-switch");
        let (_tx, mut cancel) = watch::channel(false);
        let state = std::sync::Arc::new(daemon_state::State::in_memory().unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let progress = Progress::new(uuid::Uuid::new_v4(), state, tx, vec![]);

        // No sites yet: only the setting and the log folder change.
        let caddy = proxy_in(ProxyBackend::Caddy, &dir);
        assert!(caddy.traffic_source().is_none());
        let result = caddy
            .set_traffic(true, &mut cancel, &progress)
            .await
            .unwrap();
        assert_eq!(result["enabled"], true);
        assert!(caddy.traffic_on());
        assert!(caddy.traffic_dir.is_dir());
        let (format, from) = caddy.traffic_source().unwrap();
        assert_eq!(
            (format, from),
            (traffic::Format::Caddy, caddy.traffic_dir.clone())
        );

        std::fs::write(caddy.traffic_dir.join("old.log"), "x").unwrap();
        caddy
            .set_traffic(false, &mut cancel, &progress)
            .await
            .unwrap();
        assert!(!caddy.traffic_on());
        assert!(!caddy.traffic_dir.join("old.log").exists());

        // Traefik: its own config gets the access log, someone else's
        // doesn't, and off takes it out again.
        let traefik = Proxy {
            main_config: dir.join("traefik.toml"),
            ..proxy_in(ProxyBackend::Traefik, &dir)
        };
        std::fs::write(&traefik.main_config, fresh_traefik_config()).unwrap();
        traefik
            .set_traffic(true, &mut cancel, &progress)
            .await
            .unwrap();
        let config = std::fs::read_to_string(&traefik.main_config).unwrap();
        assert!(config.starts_with(&fresh_traefik_config()));
        assert!(config.contains("[accessLog]"));
        assert!(traefik.traffic_dir.join(TRAEFIK_LOG).exists());
        traefik
            .set_traffic(false, &mut cancel, &progress)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&traefik.main_config).unwrap(),
            fresh_traefik_config()
        );

        std::fs::write(
            &traefik.main_config,
            "[providers.file]\n  directory = \"x\"\n",
        )
        .unwrap();
        let refused = traefik
            .set_traffic(true, &mut cancel, &progress)
            .await
            .unwrap_err();
        assert!(
            refused.message.contains("isn't one ServerOS wrote"),
            "{}",
            refused.message
        );
        assert!(!traefik.traffic_on());

        let none = proxy_in(ProxyBackend::None, &dir);
        assert!(none
            .set_traffic(true, &mut cancel, &progress)
            .await
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Writes every proxy's site with all switches on to
    /// $SERVEROS_DUMP_SITES, for checking them against the real proxies.
    #[test]
    #[ignore]
    fn dump_sites_with_switches() {
        let Ok(out) = std::env::var("SERVEROS_DUMP_SITES") else {
            return;
        };
        let out = PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("nginx-shared.conf"), NGINX_SHARED).unwrap();
        std::fs::write(
            out.join("traefik-traffic.toml"),
            traffic::with_traefik_access_log(
                &fresh_traefik_config(),
                &Path::new(TRAFFIC_LOG_DIR).join(TRAEFIK_LOG),
                true,
            )
            .unwrap(),
        )
        .unwrap();
        for backend in [
            ProxyBackend::Caddy,
            ProxyBackend::Nginx,
            ProxyBackend::Apache,
            ProxyBackend::Traefik,
        ] {
            for (name, https, plain_http, cert) in [
                ("https", true, false, false),
                ("cert", true, false, true),
                ("tunnel", true, true, false),
                ("http", false, false, false),
            ] {
                let text = rendered_with_switches(backend, https, plain_http, cert);
                std::fs::write(
                    out.join(format!("{}-{name}.txt", backend.label().to_lowercase())),
                    text,
                )
                .unwrap();
                let text = rendered_with_traffic(backend, (https, plain_http, cert), true, false);
                std::fs::write(
                    out.join(format!(
                        "{}-{name}-traffic.txt",
                        backend.label().to_lowercase()
                    )),
                    text,
                )
                .unwrap();
            }
        }
    }
}
