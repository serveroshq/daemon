//! Maintenance pages, served on loopback. A site in maintenance has its
//! proxy send visitors here instead of to the app (every proxy keeps the
//! visitor's Host), and the daemon answers 503 with the app's page, or a
//! plain one naming the site. The app itself keeps running.

use std::sync::Arc;
use std::time::Duration;

use daemon_deploy::site_options::{self, MAINTENANCE_LISTEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::warn;

use super::app::App;

/// Enough for any real request's headers; the body is never read.
const MAX_HEAD: usize = 16 * 1024;

pub fn serve(app: Arc<App>) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(MAINTENANCE_LISTEN).await {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, addr = MAINTENANCE_LISTEN, "maintenance pages unavailable; sites in maintenance will show a proxy error");
                return;
            }
        };

        loop {
            let Ok((mut stream, peer)) = listener.accept().await else {
                continue;
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            let app = Arc::clone(&app);

            tokio::spawn(async move {
                let head = tokio::time::timeout(Duration::from_secs(10), read_head(&mut stream))
                    .await
                    .unwrap_or_default();
                let request = parse(&head);
                let options = request
                    .host
                    .as_deref()
                    .and_then(|host| app.deployer.proxy().options_for_host(host))
                    .unwrap_or_default();
                let page = site_options::maintenance_page(
                    &options,
                    request.host.as_deref().unwrap_or_default(),
                );
                let _ = stream.write_all(&response(&page, request.head_only)).await;
                let _ = stream.shutdown().await;
            });
        }
    });
}

async fn read_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut buf = [0u8; 2048];
    while head.len() < MAX_HEAD {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    head
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Request {
    host: Option<String>,
    head_only: bool,
}

fn parse(head: &[u8]) -> Request {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let head_only = lines.next().is_some_and(|line| line.starts_with("HEAD "));
    let host = lines
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("host")
                .then(|| value.trim().to_string())
        })
        .filter(|host| !host.is_empty());
    Request { host, head_only }
}

fn response(page: &str, head_only: bool) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nRetry-After: 300\r\nCache-Control: no-store\r\nX-Robots-Tag: noindex\r\nConnection: close\r\n\r\n",
        page.len()
    )
    .into_bytes();
    if !head_only {
        out.extend_from_slice(page.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_comes_from_the_headers() {
        let request =
            parse(b"GET /cart HTTP/1.1\r\nUser-Agent: x\r\nhost: Shop.Acme.io:443\r\n\r\n");
        assert_eq!(request.host.as_deref(), Some("Shop.Acme.io:443"));
        assert!(!request.head_only);

        assert!(parse(b"HEAD / HTTP/1.1\r\nHost: acme.io\r\n\r\n").head_only);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n\r\nHost: late.io\r\n").host, None);
        assert_eq!(parse(b"").host, None);
    }

    #[test]
    fn visitors_get_a_503_they_can_retry() {
        let full = String::from_utf8(response("<p>soon</p>", false)).unwrap();
        assert!(full.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(full.contains("Content-Length: 11\r\n"));
        assert!(full.contains("Retry-After: 300\r\n"));
        assert!(full.ends_with("<p>soon</p>"));

        let head = String::from_utf8(response("<p>soon</p>", true)).unwrap();
        assert!(head.ends_with("\r\n\r\n"));
    }
}
