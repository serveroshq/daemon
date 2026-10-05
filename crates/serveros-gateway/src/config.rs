use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "serveros-gateway", version)]
pub struct Args {
    #[arg(long, default_value = "0.0.0.0:8443", env = "GATEWAY_LISTEN")]
    pub listen: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:8090", env = "GATEWAY_INTERNAL")]
    pub internal: SocketAddr,

    #[arg(long, env = "GATEWAY_CA")]
    pub ca: PathBuf,

    #[arg(long, env = "GATEWAY_CERT")]
    pub cert: PathBuf,

    #[arg(long, env = "GATEWAY_KEY")]
    pub key: PathBuf,

    #[arg(long, env = "GATEWAY_PANEL_URL")]
    pub panel: String,

    #[arg(long, env = "GATEWAY_PANEL_CA")]
    pub panel_ca: Option<PathBuf>,

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
