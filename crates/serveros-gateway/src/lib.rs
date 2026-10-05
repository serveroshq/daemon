pub mod config;
pub mod daemon_conn;
pub mod internal;
pub mod panel;
pub mod registry;
pub mod replay;
pub mod ticket;
pub mod tls;

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::warn;

use crate::panel::PanelClient;
use crate::registry::Registry;

pub struct Context {
    pub panel: PanelClient,
    pub registry: Registry,
    pub secret: String,
}

pub async fn run_listeners(
    daemons: TcpListener,
    internal: TcpListener,
    acceptor: TlsAcceptor,
    context: Arc<Context>,
) {
    let daemon_ctx = Arc::clone(&context);
    let daemon_loop = tokio::spawn(async move {
        loop {
            match daemons.accept().await {
                Ok((tcp, peer)) => {
                    let acceptor = acceptor.clone();
                    let ctx = Arc::clone(&daemon_ctx);
                    tokio::spawn(async move {
                        daemon_conn::serve(tcp, peer, acceptor, ctx).await;
                    });
                }
                Err(e) => {
                    warn!(error = %e, "accept failed on the daemon listener");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    let internal_loop = tokio::spawn(async move {
        loop {
            match internal.accept().await {
                Ok((tcp, peer)) => {
                    let ctx = Arc::clone(&context);
                    tokio::spawn(async move {
                        if let Err(e) = internal::serve(tcp, peer, ctx).await {
                            warn!(%peer, error = %e, "internal request failed");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "accept failed on the internal listener");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    tokio::select! {
        r = daemon_loop => warn!(result = ?r, "daemon listener ended"),
        r = internal_loop => warn!(result = ?r, "internal listener ended"),
    }
}
