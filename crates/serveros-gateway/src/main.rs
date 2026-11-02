use std::sync::Arc;

use clap::Parser;
use daemon_core::error_reports;
use serveros_gateway::config::Args;
use serveros_gateway::panel::PanelClient;
use serveros_gateway::registry::Registry;
use serveros_gateway::{run_listeners, tls, Context};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Error reports: the DSN comes from the build or SERVEROS_SENTRY_DSN,
    // and SERVEROS_ERROR_REPORTS=0 turns them off. No config file here.
    let _reports = error_reports::init(
        "serveros-gateway",
        env!("CARGO_PKG_VERSION"),
        &error_reports::decide(&error_reports::FileSettings::default()),
        &[],
    );

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(error_reports::is_on().then(error_reports::tracing_layer))
        .init();

    let settings = args.load()?;
    let acceptor = TlsAcceptor::from(tls::server_config(
        &settings.ca_pem,
        &settings.cert_pem,
        &settings.key_pem,
    )?);

    let context = Arc::new(Context {
        panel: PanelClient::new(
            settings.panel_url.clone(),
            settings.secret.clone(),
            settings.panel_ca_pem.as_deref(),
        )?,
        registry: Registry::default(),
        secret: settings.secret.clone(),
    });

    let daemons = TcpListener::bind(settings.listen).await?;
    let internal = TcpListener::bind(settings.internal).await?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        daemons = %settings.listen,
        internal = %settings.internal,
        panel = %settings.panel_url,
        majors = ?daemon_protocol::SUPPORTED_MAJORS,
        "serveros-gateway listening"
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
        _ = run_listeners(daemons, internal, acceptor, context) => {}
    }

    Ok(())
}
