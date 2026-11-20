//! A plain HTTP GET to something on this machine: Caddy's admin API,
//! Traefik's API, Docker's socket. Read-only, short timeouts, and a cap on
//! how much of the answer is read, so a big or slow one can't hold the
//! daemon up or fill its memory.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Where to send the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `host:port`.
    Tcp(String),
    Unix(PathBuf),
}

impl Target {
    /// From an address as Caddy writes it: `localhost:2019`, `:2019`,
    /// `tcp/localhost:2019`, `unix//run/caddy.sock`.
    pub fn parse(address: &str) -> Option<Self> {
        let address = address.trim();
        if let Some(path) = address.strip_prefix("unix/") {
            return (!path.is_empty()).then(|| Self::Unix(PathBuf::from(path)));
        }
        let address = address
            .strip_prefix("tcp/")
            .or_else(|| address.strip_prefix("tcp4/"))
            .or_else(|| address.strip_prefix("tcp6/"))
            .unwrap_or(address);
        let address = address
            .strip_prefix("http://")
            .unwrap_or(address)
            .trim_end_matches('/');
        let (host, port) = address.rsplit_once(':')?;
        port.parse::<u16>().ok()?;
        let host = if host.is_empty() || host == "0.0.0.0" || host == "[::]" {
            "127.0.0.1"
        } else {
            host
        };
        Some(Self::Tcp(format!("{host}:{port}")))
    }
}

/// The body of a 200 answer to `GET path`, at most `max` bytes of it (the
/// rest is dropped, and `truncated` says so). None for anything but 200,
/// or no answer within `timeout`.
pub async fn get(
    target: &Target,
    host: &str,
    path: &str,
    timeout: Duration,
    max: usize,
) -> Option<Body> {
    let work = async {
        match target {
            Target::Tcp(address) => {
                let stream = tokio::net::TcpStream::connect(address).await.ok()?;
                exchange(stream, host, path, max).await
            }
            Target::Unix(socket) => {
                let stream = tokio::net::UnixStream::connect(socket).await.ok()?;
                exchange(stream, host, path, max).await
            }
        }
    };
    tokio::time::timeout(timeout, work).await.ok().flatten()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

impl Body {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    host: &str,
    path: &str,
    max: usize,
) -> Option<Body> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nUser-Agent: serverosd\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    // Headers are small; a little over the cap leaves room for them.
    let limit = max.saturating_add(64 * 1024);
    let mut raw = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut truncated = false;
    loop {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() >= limit {
            truncated = true;
            break;
        }
    }
    parse(&raw, max, truncated)
}

fn parse(raw: &[u8], max: usize, truncated: bool) -> Option<Body> {
    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut response = httparse::Response::new(&mut headers);
    let header_len = match response.parse(raw).ok()? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return None,
    };
    if response.code? != 200 {
        return None;
    }
    let chunked = response.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && String::from_utf8_lossy(h.value).contains("chunked")
    });
    let body = &raw[header_len..];
    let (mut bytes, cut) = if chunked {
        dechunk(body)
    } else {
        (body.to_vec(), false)
    };
    let mut truncated = truncated || cut;
    if bytes.len() > max {
        bytes.truncate(max);
        truncated = true;
    }
    Some(Body { bytes, truncated })
}

/// The chunks that came in whole, and whether any didn't.
fn dechunk(mut body: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = body.windows(2).position(|w| w == b"\r\n") else {
            return (out, true);
        };
        let size = std::str::from_utf8(&body[..line_end])
            .ok()
            .and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok());
        let Some(size) = size else {
            return (out, true);
        };
        body = &body[line_end + 2..];
        if size == 0 {
            return (out, false);
        }
        match body.get(..size) {
            Some(chunk) => out.extend_from_slice(chunk),
            None => {
                out.extend_from_slice(body);
                return (out, true);
            }
        }
        body = body.get(size + 2..).unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_read_like_caddy_writes_them() {
        assert_eq!(
            Target::parse("localhost:2019"),
            Some(Target::Tcp("localhost:2019".into()))
        );
        assert_eq!(
            Target::parse(":2019"),
            Some(Target::Tcp("127.0.0.1:2019".into()))
        );
        assert_eq!(
            Target::parse("tcp/0.0.0.0:2020"),
            Some(Target::Tcp("127.0.0.1:2020".into()))
        );
        assert_eq!(
            Target::parse("unix//run/caddy/admin.sock"),
            Some(Target::Unix("/run/caddy/admin.sock".into()))
        );
        assert_eq!(Target::parse("nonsense"), None);
    }

    #[test]
    fn answers_are_capped_and_chunks_read_whole() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let body = parse(raw, 100, false).unwrap();
        assert_eq!(body.text(), "hello world");
        assert!(!body.truncated);
        let body = parse(raw, 4, false).unwrap();
        assert_eq!((body.text().as_str(), body.truncated), ("hell", true));
        // Cut off mid-chunk: what came in, marked.
        let body = parse(&raw[..60], 100, true).unwrap();
        assert!(body.truncated && body.text().starts_with("hello"));
        assert!(parse(b"HTTP/1.1 403 Forbidden\r\n\r\nno", 100, false).is_none());
    }

    #[tokio::test]
    async fn gets_from_a_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(request.starts_with("GET /config/ HTTP/1.1\r\nHost: localhost:2019\r\n"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
        });
        let body = get(
            &Target::Tcp(address),
            "localhost:2019",
            "/config/",
            Duration::from_secs(2),
            1024,
        )
        .await
        .unwrap();
        assert_eq!(body.text(), "{}");
    }
}
