//! Command-line and environment configuration. Secrets come from files or
//! the environment, never from arguments, so they stay out of `ps`.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "serveros-gateway", version)]
pub struct Args {
    /// Where daemons connect (mutual TLS, WebSocket).
    #[arg(long, default_value = "0.0.0.0:8443", env = "GATEWAY_LISTEN")]
    pub listen: SocketAddr,

    /// The internal API the panel calls, and browser stream attachments.
    /// Keep this on loopback or a private network; put a reverse proxy with
    /// TLS in front of it for browsers.
    #[arg(long, default_value = "127.0.0.1:8090", env = "GATEWAY_INTERNAL")]
    pub internal: SocketAddr,

    /// The daemon CA certificate (`php artisan daemon:ca show`).
    #[arg(long, env = "GATEWAY_CA")]
    pub ca: PathBuf,

    /// This gateway's server certificate, issued by the same CA
    /// (`php artisan daemon:ca issue-server --host …`).
    #[arg(long, env = "GATEWAY_CERT")]
    pub cert: PathBuf,

    /// The matching private key.
    #[arg(long, env = "GATEWAY_KEY")]
    pub key: PathBuf,

    /// The panel's base URL, e.g. https://serveros.com.
    #[arg(long, env = "GATEWAY_PANEL_URL")]
    pub panel: String,

    /// A CA bundle to trust for the panel instead of the public web PKI
    /// (local development behind Herd, or a private panel).
    #[arg(long, env = "GATEWAY_PANEL_CA")]
    pub panel_ca: Option<PathBuf>,

    /// File holding the shared secret (DAEMON_GATEWAY_SECRET in the panel).
    /// Falls back to the GATEWAY_SECRET environment variable.
    #[arg(long, env = "GATEWAY_SECRET_FILE")]
    pub secret_file: Option<PathBuf>,
}

pub struct Settings {
    pub listen: SocketAddr,
    pub internal: SocketAddr,
    pub ca_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub panel_url: String,
    pub panel_ca_pem: Option<Vec<u8>>,
    pub secret: String,
}

impl Args {
    pub fn load(self) -> anyhow::Result<Settings> {
        let read = |path: &PathBuf| {
            std::fs::read(path).with_context(|| format!("could not read {}", path.display()))
        };

        let secret = match &self.secret_file {
            Some(path) => String::from_utf8(read(path)?)?.trim().to_string(),
            None => std::env::var("GATEWAY_SECRET").unwrap_or_default(),
        };

        if secret.len() < 16 {
            anyhow::bail!(
                "the gateway secret is missing or shorter than 16 characters; set GATEWAY_SECRET or --secret-file to the panel's DAEMON_GATEWAY_SECRET"
            );
        }

        let panel_url = self.panel.trim_end_matches('/').to_string();

        if !panel_url.starts_with("https://") {
            anyhow::bail!("--panel must be an https:// URL (got {panel_url})");
        }

        Ok(Settings {
            listen: self.listen,
            internal: self.internal,
            ca_pem: read(&self.ca)?,
            cert_pem: read(&self.cert)?,
            key_pem: read(&self.key)?,
            panel_url,
            panel_ca_pem: self.panel_ca.as_ref().map(read).transpose()?,
            secret,
        })
    }
}
