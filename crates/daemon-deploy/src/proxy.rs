use std::path::PathBuf;
use std::time::Duration;

use daemon_core::config::ProxyBackend;
use daemon_jobs::{run_child, Failure, Progress};
use tokio::sync::watch;

pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";
pub const INCLUDE_DIR: &str = "/etc/caddy/serveros.d";
const CADDY_IMPORT_LINE: &str = "import /etc/caddy/serveros.d/*.caddy";

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

pub fn render(domains: &[String], upstream_port: u16) -> Result<String, Failure> {
    validate_domains(domains)?;

    Ok(format!(
        "# Managed by ServerOS. Edits here are overwritten on the next deploy.\n{} {{\n\tencode zstd gzip\n\treverse_proxy 127.0.0.1:{upstream_port}\n}}\n",
        domains.join(", ")
    ))
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
        if d.is_empty()
            || !d
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | ':'))
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
        let rendered = match self.backend {
            ProxyBackend::Caddy => render(domains, upstream_port)?,
            ProxyBackend::Nginx => render_nginx(domains, upstream_port)?,
            ProxyBackend::None => return Err(Self::none_configured()),
        };
        let site = self.site_file(service);
        let previous = std::fs::read(&site).ok();

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
            return Err(failure);
        }

        self.reload(cancel, progress).await?;

        Ok(site)
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
        let block = render(&["shop.example".into(), "www.shop.example".into()], 3000).unwrap();

        assert!(block.contains("shop.example, www.shop.example {"));
        assert!(block.contains("reverse_proxy 127.0.0.1:3000"));
        assert!(render(&["bad{domain".into()], 3000).is_err());
        assert!(render(&[], 3000).is_err());
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
