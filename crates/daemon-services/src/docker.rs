//! Driving containers through the Docker socket: start, stop, restart,
//! HUP for reload, and the log stream. A few HTTP calls over the unix
//! socket; the Docker CLI is never invoked.

use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_protocol::{ServiceAction, ServiceStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Lifecycle, Result, ServiceError};

pub struct DockerAdapter {
    pub socket: PathBuf,
    pub timeout: Duration,
}

impl Default for DockerAdapter {
    fn default() -> Self {
        Self {
            socket: PathBuf::from("/var/run/docker.sock"),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Container ids and names, as Docker allows them.
pub fn valid_container_ref(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

async fn request(socket: &Path, method: &str, path: &str, timeout: Duration) -> Result<Reply> {
    let work = async {
        let mut stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|e| ServiceError::Docker(format!("{}: {e}", socket.display())))?;
        let request = format!("{method} {path} HTTP/1.1\r\nHost: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| ServiceError::Docker(e.to_string()))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| ServiceError::Docker(e.to_string()))?;

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        let header_len = match response
            .parse(&raw)
            .map_err(|e| ServiceError::Docker(e.to_string()))?
        {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => {
                return Err(ServiceError::Docker("truncated response".into()))
            }
        };
        let status = response.code.unwrap_or(0);
        let chunked = response.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("transfer-encoding")
                && String::from_utf8_lossy(h.value).contains("chunked")
        });
        let body = &raw[header_len..];
        let body = if chunked {
            dechunk(body).unwrap_or_default()
        } else {
            body.to_vec()
        };

        Ok(Reply { status, body })
    };

    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| ServiceError::Docker(format!("{method} {path} timed out")))?
}

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();

    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..line_end]).ok()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];

        if size == 0 {
            return Some(out);
        }

        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

fn docker_error(reply: &Reply, what: &str) -> ServiceError {
    let message = serde_json::from_slice::<serde_json::Value>(&reply.body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(&reply.body).trim().to_string());

    ServiceError::Docker(format!("{what}: HTTP {} {message}", reply.status))
}

impl Lifecycle for DockerAdapter {
    async fn act(&self, container: &str, action: ServiceAction) -> Result<()> {
        if !valid_container_ref(container) {
            return Err(ServiceError::Docker(format!(
                "{container:?} is not a valid container reference"
            )));
        }

        let path = match action {
            ServiceAction::Start => format!("/containers/{container}/start"),
            ServiceAction::Stop => format!("/containers/{container}/stop?t=30"),
            ServiceAction::Restart => format!("/containers/{container}/restart?t=30"),
            ServiceAction::Reload => format!("/containers/{container}/kill?signal=SIGHUP"),
        };

        let reply = request(&self.socket, "POST", &path, self.timeout).await?;

        // 304: already in that state, which is fine.
        match reply.status {
            204 | 304 => Ok(()),
            _ => Err(docker_error(&reply, &format!("{action:?} {container}"))),
        }
    }

    async fn status(&self, container: &str) -> Result<ServiceStatus> {
        if !valid_container_ref(container) {
            return Err(ServiceError::Docker(format!(
                "{container:?} is not a valid container reference"
            )));
        }

        let reply = request(
            &self.socket,
            "GET",
            &format!("/containers/{container}/json"),
            self.timeout,
        )
        .await?;

        if reply.status != 200 {
            return Err(docker_error(&reply, &format!("inspect {container}")));
        }

        let value: serde_json::Value = serde_json::from_slice(&reply.body)?;

        Ok(status_from_inspect(&value))
    }

    async fn logs(&self, container: &str, lines: u32) -> Result<Vec<String>> {
        if !valid_container_ref(container) {
            return Err(ServiceError::Docker(format!(
                "{container:?} is not a valid container reference"
            )));
        }

        let count = lines.clamp(1, 5000);
        let reply = request(
            &self.socket,
            "GET",
            &format!("/containers/{container}/logs?stdout=1&stderr=1&timestamps=1&tail={count}"),
            self.timeout,
        )
        .await?;

        if reply.status != 200 {
            return Err(docker_error(&reply, &format!("logs {container}")));
        }

        Ok(demux_log_stream(&reply.body)
            .lines()
            .map(daemon_core::redact::redact)
            .collect())
    }
}

pub fn status_from_inspect(value: &serde_json::Value) -> ServiceStatus {
    match value
        .pointer("/State/Status")
        .and_then(|s| s.as_str())
        .unwrap_or("")
    {
        "running" => ServiceStatus::Running,
        "restarting" => ServiceStatus::Restarting,
        "exited" | "created" | "paused" => ServiceStatus::Stopped,
        "dead" => ServiceStatus::Failed,
        _ => ServiceStatus::Unknown,
    }
}

/// Docker multiplexes stdout and stderr with 8-byte frame headers when
/// the container has no TTY: `[stream, 0, 0, 0, len_be32]` then bytes.
/// A TTY container sends raw text instead; detect which by the header.
pub fn demux_log_stream(raw: &[u8]) -> String {
    let framed = raw.len() >= 8 && matches!(raw[0], 0..=2) && raw[1..4] == [0, 0, 0];

    if !framed {
        return String::from_utf8_lossy(raw).into_owned();
    }

    let mut out = Vec::new();
    let mut cursor = 0;

    while cursor + 8 <= raw.len() {
        let len = u32::from_be_bytes([
            raw[cursor + 4],
            raw[cursor + 5],
            raw[cursor + 6],
            raw[cursor + 7],
        ]) as usize;
        let start = cursor + 8;
        let end = (start + len).min(raw.len());
        out.extend_from_slice(&raw[start..end]);
        cursor = end;
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demuxes_framed_logs_and_passes_tty_logs_through() {
        let mut framed = vec![1, 0, 0, 0, 0, 0, 0, 6];
        framed.extend_from_slice(b"hello\n");
        framed.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 4]);
        framed.extend_from_slice(b"oops");

        assert_eq!(demux_log_stream(&framed), "hello\noops");
        assert_eq!(
            demux_log_stream(b"plain tty output\n"),
            "plain tty output\n"
        );
    }

    #[test]
    fn container_refs_are_validated() {
        assert!(valid_container_ref("shop-web-1"));
        assert!(valid_container_ref("abcdef123456"));
        assert!(!valid_container_ref("../../etc"));
        assert!(!valid_container_ref("x y"));
    }

    #[test]
    fn maps_inspect_state() {
        assert_eq!(
            status_from_inspect(&serde_json::json!({"State": {"Status": "running"}})),
            ServiceStatus::Running
        );
        assert_eq!(
            status_from_inspect(&serde_json::json!({"State": {"Status": "dead"}})),
            ServiceStatus::Failed
        );
    }
}
