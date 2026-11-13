use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("{0} is not a valid https URL")]
    Url(String),
    #[error("could not resolve {host}: {source} (check DNS on this machine)")]
    Dns {
        host: String,
        source: std::io::Error,
    },
    #[error("could not reach {host} on port {port}: {source} (check outbound firewall rules)")]
    Connect {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("TLS handshake with {host} failed: {source}")]
    Tls {
        host: String,
        source: std::io::Error,
    },
    #[error("timed out talking to {0}")]
    Timeout(String),
    #[error("malformed response from {0}")]
    Malformed(String),
    #[error("response from {host} exceeded {limit} bytes")]
    TooLarge { host: String, limit: usize },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

impl Response {
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Clone)]
pub enum Trust {
    WebPki,
    Pinned(Arc<RootCertStore>),
}

impl Trust {
    pub fn pinned_pem(pem: &[u8]) -> Result<Self, HttpError> {
        let mut store = RootCertStore::empty();
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &pem[..])
            .collect::<Result<_, _>>()
            .map_err(|e| HttpError::Malformed(format!("pinned CA: {e}")))?;

        for cert in certs {
            store
                .add(cert)
                .map_err(|e| HttpError::Malformed(format!("pinned CA: {e}")))?;
        }

        // An empty store would fail every handshake with a confusing error.
        if store.is_empty() {
            return Err(HttpError::Malformed(
                "pinned CA: no certificate in it".into(),
            ));
        }

        Ok(Trust::Pinned(Arc::new(store)))
    }

    fn client_config(&self) -> Arc<ClientConfig> {
        let roots = match self {
            Trust::WebPki => {
                let mut store = RootCertStore::empty();
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                Arc::new(store)
            }
            Trust::Pinned(store) => Arc::clone(store),
        };

        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
}

pub struct Client {
    trust: Trust,
    timeout: Duration,
    max_body: usize,
    user_agent: String,
}

impl Client {
    pub fn new(trust: Trust, user_agent: impl Into<String>) -> Self {
        Self {
            trust,
            timeout: Duration::from_secs(30),
            max_body: 256 * 1024 * 1024,
            user_agent: user_agent.into(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub async fn get(&self, url: &str) -> Result<Response, HttpError> {
        self.request("GET", url, &[], None).await
    }

    pub async fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<Response, HttpError> {
        let bytes = serde_json::to_vec(body).map_err(|e| HttpError::Malformed(e.to_string()))?;

        self.request(
            "POST",
            url,
            &[("Content-Type", "application/json")],
            Some(&bytes),
        )
        .await
    }

    pub async fn post_json_with_headers<T: serde::Serialize>(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &T,
    ) -> Result<Response, HttpError> {
        let bytes = serde_json::to_vec(body).map_err(|e| HttpError::Malformed(e.to_string()))?;
        let mut all: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        all.extend_from_slice(headers);

        self.request("POST", url, &all, Some(&bytes)).await
    }

    pub async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, HttpError> {
        self.request("POST", url, headers, Some(body)).await
    }

    pub async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, HttpError> {
        self.request("PUT", url, headers, Some(body)).await
    }

    async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        let parsed = Url::parse(url).map_err(|_| HttpError::Url(url.into()))?;

        if parsed.scheme() != "https" {
            return Err(HttpError::Url(url.into()));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| HttpError::Url(url.into()))?
            .to_string();
        let port = parsed.port().unwrap_or(443);
        let path = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        };

        let work = async {
            let addrs = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|source| HttpError::Dns {
                    host: host.clone(),
                    source,
                })?;
            let tcp = connect_any(addrs.collect())
                .await
                .map_err(|source| HttpError::Connect {
                    host: host.clone(),
                    port,
                    source,
                })?;

            let server_name =
                ServerName::try_from(host.clone()).map_err(|_| HttpError::Url(url.into()))?;
            let connector = TlsConnector::from(self.trust.client_config());
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|source| HttpError::Tls {
                    host: host.clone(),
                    source,
                })?;

            let mut request = format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\nAccept: application/json, */*\r\nConnection: close\r\n",
                self.user_agent
            );

            for (name, value) in headers {
                request.push_str(&format!("{name}: {value}\r\n"));
            }

            if let Some(body) = body {
                request.push_str(&format!("Content-Length: {}\r\n", body.len()));
            }

            request.push_str("\r\n");

            tls.write_all(request.as_bytes()).await?;

            if let Some(body) = body {
                tls.write_all(body).await?;
            }

            let mut raw = Vec::new();
            let mut chunk = [0u8; 16 * 1024];

            loop {
                let n = match tls.read(&mut chunk).await {
                    Ok(n) => n,
                    // Some servers (Sentry's ingest among them) close without
                    // a TLS close_notify. That's fine once the whole response
                    // is here; anything shorter is still an error.
                    Err(e)
                        if e.kind() == std::io::ErrorKind::UnexpectedEof
                            && response_complete(&raw) =>
                    {
                        0
                    }
                    Err(e) => return Err(e.into()),
                };

                if n == 0 {
                    break;
                }

                raw.extend_from_slice(&chunk[..n]);

                if raw.len() > self.max_body + 64 * 1024 {
                    return Err(HttpError::TooLarge {
                        host: host.clone(),
                        limit: self.max_body,
                    });
                }
            }

            parse_response(&raw, &host)
        };

        tokio::time::timeout(self.timeout, work)
            .await
            .map_err(|_| HttpError::Timeout(host_of(url)))?
    }
}

/// How long one address gets before the next is tried alongside it.
const NEXT_ATTEMPT_AFTER: Duration = Duration::from_millis(250);

/// Connects to whichever address answers first, IPv6 and IPv4 taken in
/// turn and each new attempt started 250ms after the last (Happy
/// Eyeballs, RFC 8305). serveros.com is behind Cloudflare, which has IPv6
/// addresses; on a machine whose IPv6 looks set up but goes nowhere, one
/// attempt at a time hung on the first address until the request timed
/// out, while curl on the same machine was fine.
async fn connect_any(addrs: Vec<SocketAddr>) -> std::io::Result<TcpStream> {
    let mut queue = interleave(addrs).into_iter().peekable();
    let mut attempts = tokio::task::JoinSet::new();
    let mut last_err = None;

    loop {
        if let Some(addr) = queue.next() {
            attempts.spawn(TcpStream::connect(addr));
        }
        if attempts.is_empty() {
            return Err(last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses")
            }));
        }
        let more = queue.peek().is_some();

        tokio::select! {
            Some(done) = attempts.join_next() => match done {
                // Dropping the set stops the attempts still going.
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = Some(e),
                Err(e) => last_err = Some(std::io::Error::other(e)),
            },
            _ = tokio::time::sleep(NEXT_ATTEMPT_AFTER), if more => {}
        }
    }
}

/// The addresses with the families alternating, starting with the one
/// the resolver put first.
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (mut lead, mut other): (Vec<_>, Vec<_>) =
        addrs.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(lead.len() + other.len());
    lead.reverse();
    other.reverse();
    while !lead.is_empty() || !other.is_empty() {
        out.extend(lead.pop());
        out.extend(other.pop());
    }
    out
}

fn host_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.into())
}

/// Whether `raw` holds a whole response: headers, then exactly the body
/// its Content-Length or chunked encoding promised.
fn response_complete(raw: &[u8]) -> bool {
    let mut header_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut header_buf);
    let Ok(httparse::Status::Complete(header_len)) = parsed.parse(raw) else {
        return false;
    };
    let body = &raw[header_len..];

    for header in parsed.headers.iter() {
        let value = String::from_utf8_lossy(header.value);
        if header.name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<usize>().ok() == Some(body.len());
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            return dechunk(body).is_some();
        }
    }

    false
}

fn parse_response(raw: &[u8], host: &str) -> Result<Response, HttpError> {
    let mut header_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut header_buf);
    let malformed = || HttpError::Malformed(host.into());

    let header_len = match parsed.parse(raw).map_err(|_| malformed())? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err(malformed()),
    };

    let status = parsed.code.ok_or_else(malformed)?;
    let mut chunked = false;
    let mut content_type = None;

    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value).trim().to_string();

        match name.as_str() {
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => chunked = true,
            "content-type" => content_type = Some(value),
            _ => {}
        }
    }

    let body = &raw[header_len..];
    let body = if chunked {
        dechunk(body).ok_or_else(malformed)?
    } else {
        body.to_vec()
    };

    Ok(Response {
        status,
        body,
        content_type,
    })
}

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();

    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];

        if size == 0 {
            return Some(out);
        }

        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternates_address_families() {
        let a: Vec<SocketAddr> = [
            "[2606::1]:443",
            "[2606::2]:443",
            "1.1.1.1:443",
            "2.2.2.2:443",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let got: Vec<String> = interleave(a).iter().map(ToString::to_string).collect();
        assert_eq!(
            got,
            [
                "[2606::1]:443",
                "1.1.1.1:443",
                "[2606::2]:443",
                "2.2.2.2:443"
            ]
        );
    }

    #[tokio::test]
    async fn an_address_that_never_answers_does_not_hold_up_the_next() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        // TEST-NET-1 and a documentation IPv6 address: nothing answers.
        let dead: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let blackhole: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let started = std::time::Instant::now();
        let stream = connect_any(vec![dead, blackhole, good]).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn knows_when_a_response_is_whole() {
        assert!(response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        ));
        assert!(!response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}"
        ));
        assert!(response_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
        ));
        assert!(!response_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}"
        ));
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\n\r\nbody"));
        assert!(!response_complete(b"HTTP/1.1 200"));
    }

    #[test]
    fn parses_a_plain_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let response = parse_response(raw, "example").unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}");
        assert_eq!(response.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn parses_a_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

        assert_eq!(parse_response(raw, "example").unwrap().body, b"Wikipedia");
    }

    #[test]
    fn rejects_plain_http() {
        let client = Client::new(Trust::WebPki, "test");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        assert!(matches!(
            rt.block_on(client.get("http://example.com/")),
            Err(HttpError::Url(_))
        ));
    }
}
