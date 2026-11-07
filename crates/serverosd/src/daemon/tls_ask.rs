//! Caddy's on-demand TLS question, answered on loopback. A wildcard site
//! (`*.acme.io { tls { on_demand } }`) gets a certificate per subdomain the
//! first time it's visited; before each one Caddy asks
//! `GET /caddy-ask?domain=<name>` and only goes ahead on a 2xx. We say yes
//! only for a name one label under a wildcard in our own site files, so
//! nobody can point a stray domain at the machine and run up certificates.

use std::sync::Arc;
use std::time::Duration;

use daemon_deploy::proxy::ASK_LISTEN;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::warn;

use super::app::App;

pub fn serve(app: Arc<App>) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(ASK_LISTEN).await {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, addr = ASK_LISTEN, "on-demand TLS check unavailable; wildcard subdomains won't get certificates");
                return;
            }
        };

        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            let app = Arc::clone(&app);

            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut line = String::new();
                let read = tokio::time::timeout(
                    Duration::from_secs(5),
                    BufReader::new(read).read_line(&mut line),
                )
                .await;

                let allowed = matches!(read, Ok(Ok(_)))
                    && domain_asked(&line)
                        .is_some_and(|domain| app.deployer.proxy.allows_on_demand(&domain));

                let status = if allowed { "200 OK" } else { "403 Forbidden" };
                let _ = write
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = write.shutdown().await;
            });
        }
    });
}

/// The `domain` Caddy asks about, from the request line
/// `GET /caddy-ask?domain=shop.acme.io HTTP/1.1`.
fn domain_asked(request_line: &str) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    let (path, query) = target.split_once('?')?;
    if path != "/caddy-ask" {
        return None;
    }

    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("domain="))
        .filter(|d| !d.is_empty() && !d.contains('%'))
        .map(str::to_ascii_lowercase)
}

#[cfg(test)]
mod tests {
    use super::domain_asked;

    #[test]
    fn reads_the_domain_caddy_asks_about() {
        assert_eq!(
            domain_asked("GET /caddy-ask?domain=Shop.Acme.io HTTP/1.1\r\n").as_deref(),
            Some("shop.acme.io")
        );
        assert_eq!(
            domain_asked("GET /caddy-ask?x=1&domain=a.acme.io HTTP/1.1").as_deref(),
            Some("a.acme.io")
        );
        assert!(domain_asked("POST /caddy-ask?domain=a.acme.io HTTP/1.1").is_none());
        assert!(domain_asked("GET /other?domain=a.acme.io HTTP/1.1").is_none());
        assert!(domain_asked("GET /caddy-ask?domain= HTTP/1.1").is_none());
        assert!(domain_asked("GET /caddy-ask?domain=a%2eacme.io HTTP/1.1").is_none());
        assert!(domain_asked("").is_none());
    }
}
