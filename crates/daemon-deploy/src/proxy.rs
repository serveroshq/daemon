//! The reverse proxy in front of deployed services. Caddy by default,
//! because it obtains and renews TLS on its own (ACME HTTP-01); nginx for
//! machines that already run it. Both work the same way: one file per
//! service in a directory ServerOS owns, validated before reload, reverted
//! if validation fails, and reload rather than restart so existing
//! connections stay up. The choice is `[integrations] proxy` in
//! `daemon.toml`.

use std::path::PathBuf;
use std::time::Duration;

use daemon_core::config::ProxyBackend;
use daemon_jobs::{run_child, Failure, Progress};
use tokio::sync::watch;

pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";
pub const INCLUDE_DIR: &str = "/etc/caddy/serveros.d";
const CADDY_IMPORT_LINE: &str = "import /etc/caddy/serveros.d/*.caddy";

pub const NGINX_CONF: &str = "/etc/nginx/nginx.conf";
pub const NGINX_INCLUDE_DIR: &str = "/etc/nginx/serveros.d";
const NGINX_INCLUDE_LINE: &str = "include /etc/nginx/serveros.d/*.conf;";

pub struct Proxy {
    pub backend: ProxyBackend,
    /// The main config file that must include our directory.
    pub main_config: PathBuf,
    pub include_dir: PathBuf,
}

impl Default for Proxy {
    fn default() -> Self {
        Self::for_backend(ProxyBackend::Caddy)
    }
}

/// The Caddy site block for a service.
pub fn render(domains: &[String], upstream_port: u16) -> Result<String, Failure> {
    validate_domains(domains)?;

    Ok(format!(
        "# Managed by ServerOS. Edits here are overwritten on the next deploy.\n{} {{\n\tencode zstd gzip\n\treverse_proxy 127.0.0.1:{upstream_port}\n}}\n",
        domains.join(", ")
    ))
}

/// The nginx server block for a service. Plain HTTP on 80; TLS is left to
/// whatever the operator already uses (certbot --nginx keeps working, as
/// it edits this file in place and the next deploy rewrites only ours).
pub fn render_nginx(domains: &[String], upstream_port: u16) -> Result<String, Failure> {
    validate_domains(domains)?;

    Ok(format!(
        "# Managed by ServerOS. Edits here are overwritten on the next deploy.\nserver {{\n    listen 80;\n    listen [::]:80;\n    server_name {};\n\n    location / {{\n        proxy_pass http://127.0.0.1:{upstream_port};\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection $connection_upgrade;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }}\n}}\n",
        domains.join(" ")
    ))
}

/// Domains are validated to hostname characters so a stray brace or
/// semicolon cannot change the config's shape.
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

    /// Make sure the main config imports our directory. Returns `true`
    /// when a line was added (so the caller records it in the manifest).
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

    /// Write the site, validate, reload. On validation failure the
    /// previous file is restored and the proxy is never reloaded.
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
        // Reload, never restart: existing connections stay up.
        let (program, args, unit): (&str, Vec<&str>, &str) = match self.backend {
            ProxyBackend::Nginx => ("nginx", vec!["-s", "reload", "-c", &main], "nginx"),
            _ => (
                "caddy",
                vec!["reload", "--config", &main, "--adapter", "caddyfile"],
                "caddy",
            ),
        };

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

/// Append the Caddy import line unless it is already there.
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

/// Add our include inside nginx's `http { … }` block: just before the
/// closing brace of the block, which is the last `}` at column zero in a
/// stock nginx.conf. A file without an http block is left alone and the
/// include is reported as not added.
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
