//! Is the new release actually up? TCP first, then a plain HTTP request
//! written by hand so the check needs no HTTP client and no TLS.

use std::time::Duration;

use daemon_jobs::Failure;
use daemon_protocol::HealthCheck;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn wait_healthy(
    port: u16,
    check: Option<&HealthCheck>,
    log: &daemon_jobs::Progress,
) -> Result<(), Failure> {
    let default = HealthCheck {
        path: "/".into(),
        expected_status: 200,
        timeout_secs: 30,
        retries: 5,
    };
    let check = check.unwrap_or(&default);
    let per_try = Duration::from_secs(check.timeout_secs.max(1));
    let mut last = String::new();

    for attempt in 1..=check.retries.max(1) {
        match tokio::time::timeout(per_try, probe(port, check)).await {
            Ok(Ok(())) => {
                log.line(format!("health check passed on attempt {attempt}"))
                    .await;
                return Ok(());
            }
            Ok(Err(e)) => last = e,
            Err(_) => last = format!("no response within {per_try:?}"),
        }

        log.line(format!(
            "health check attempt {attempt}/{}: {last}",
            check.retries
        ))
        .await;
        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt.min(4)))).await;
    }

    Err(
        Failure::new("health", format!("release never became healthy: {last}")).with_next_step(
            format!(
                "Check the app listens on the configured port and answers {} with HTTP {}.",
                check.path, check.expected_status
            ),
        ),
    )
}

async fn probe(port: u16, check: &HealthCheck) -> Result<(), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("port {port} not accepting connections ({e})"))?;
    let request = format!("GET {} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: serverosd-health\r\nConnection: close\r\n\r\n", check.path);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut head = [0u8; 512];
    let n = stream.read(&mut head).await.map_err(|e| e.to_string())?;
    let status = parse_status(&head[..n]).ok_or_else(|| "response was not HTTP".to_string())?;

    if is_healthy(status, check.expected_status) {
        Ok(())
    } else {
        Err(format!(
            "{} returned HTTP {status}, expected {}",
            check.path, check.expected_status
        ))
    }
}

/// The expected status, or for the default 200 a redirect too: apps that
/// send `/` to their login or setup page (Uptime Kuma, paperless) are up.
pub fn is_healthy(status: u16, expected: u16) -> bool {
    status == expected || (expected == 200 && (300..400).contains(&status))
}

pub fn parse_status(head: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(head).ok()?;
    let mut parts = text.split_whitespace();
    let version = parts.next()?;

    version
        .starts_with("HTTP/")
        .then(|| parts.next()?.parse().ok())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_status_line() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 503 Unavailable"), Some(503));
        assert_eq!(parse_status(b"not http"), None);
    }

    #[test]
    fn a_redirect_counts_as_up_when_200_is_expected() {
        assert!(is_healthy(200, 200));
        assert!(is_healthy(302, 200));
        assert!(is_healthy(308, 200));
        assert!(!is_healthy(404, 200));
        assert!(!is_healthy(502, 200));
        // An explicit expectation stays exact.
        assert!(!is_healthy(302, 204));
    }
}
