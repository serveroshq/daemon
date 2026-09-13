//! Containers, straight from the Docker socket. A few GETs over the unix
//! socket; no Docker SDK, no shelling out to the CLI.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SOCKET: &str = "/var/run/docker.sock";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub ports: Vec<u16>,
    pub restart_policy: Option<String>,
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
    pub compose_dir: Option<String>,
    pub mounts: Vec<String>,
    pub labels: std::collections::BTreeMap<String, String>,
    pub created: i64,
}

impl Container {
    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(12)]
    }

    /// A manually started container with no restart policy dies with the
    /// daemon or a reboot; worth calling out before adoption.
    pub fn will_not_survive_reboot(&self) -> bool {
        matches!(self.restart_policy.as_deref(), None | Some("no") | Some(""))
    }
}

#[derive(Deserialize)]
struct RawContainer {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Ports", default)]
    ports: Vec<RawPort>,
    #[serde(rename = "Labels", default)]
    labels: std::collections::BTreeMap<String, String>,
    #[serde(rename = "Mounts", default)]
    mounts: Vec<RawMount>,
    #[serde(rename = "Created", default)]
    created: i64,
}

#[derive(Deserialize)]
struct RawPort {
    #[serde(rename = "PublicPort")]
    public_port: Option<u16>,
}

#[derive(Deserialize)]
struct RawMount {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

/// The `/containers/json?all=1` body.
pub fn parse_containers(body: &str) -> Result<Vec<Container>, serde_json::Error> {
    let raw: Vec<RawContainer> = serde_json::from_str(body)?;

    Ok(raw
        .into_iter()
        .map(|c| {
            let mut ports: Vec<u16> = c.ports.iter().filter_map(|p| p.public_port).collect();
            ports.sort_unstable();
            ports.dedup();

            Container {
                name: c
                    .names
                    .first()
                    .map(|n| n.trim_start_matches('/').to_string())
                    .unwrap_or_else(|| c.id[..12].to_string()),
                compose_project: c.labels.get("com.docker.compose.project").cloned(),
                compose_service: c.labels.get("com.docker.compose.service").cloned(),
                compose_dir: c
                    .labels
                    .get("com.docker.compose.project.working_dir")
                    .cloned(),
                mounts: c
                    .mounts
                    .iter()
                    .map(|m| format!("{}:{}", m.source, m.destination))
                    .collect(),
                id: c.id,
                image: c.image,
                state: c.state,
                status: c.status,
                ports,
                // The list endpoint omits the restart policy; inspect fills it in.
                restart_policy: None,
                labels: c.labels,
                created: c.created,
            }
        })
        .collect())
}

/// `HostConfig.RestartPolicy.Name` from `/containers/<id>/json`.
pub fn parse_restart_policy(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;

    value
        .pointer("/HostConfig/RestartPolicy/Name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

pub fn parse_version(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;

    value
        .get("Version")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// One GET against the Docker socket. Returns the body, or `None` if
/// Docker is not there, refuses, or is slow.
pub async fn get(socket: &Path, path: &str, timeout: Duration) -> Option<String> {
    let work = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await.ok()?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.ok()?;

        parse_http_body(&raw)
    };

    tokio::time::timeout(timeout, work).await.ok().flatten()
}

fn parse_http_body(raw: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
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
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };

    String::from_utf8(body).ok()
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

/// Containers plus the Docker version, or `None` when Docker is absent.
pub async fn discover(
    socket: &Path,
    timeout: Duration,
) -> Option<(Vec<Container>, Option<String>)> {
    let listing = get(socket, "/containers/json?all=1", timeout).await?;
    let mut containers = parse_containers(&listing).ok()?;

    for container in containers.iter_mut() {
        if let Some(body) = get(
            socket,
            &format!("/containers/{}/json", container.id),
            timeout,
        )
        .await
        {
            container.restart_policy = parse_restart_policy(&body);
        }
    }

    let version = get(socket, "/version", timeout)
        .await
        .and_then(|b| parse_version(&b));

    Some((containers, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_container_listing_with_compose_labels() {
        let body = r#"[{"Id":"abcdef1234567890","Names":["/web-1"],"Image":"nginx:1.25","State":"running","Status":"Up 3 days","Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"},{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],"Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","com.docker.compose.project.working_dir":"/srv/shop"},"Mounts":[{"Source":"/srv/shop/html","Destination":"/usr/share/nginx/html"}],"Created":1700000000}]"#;
        let containers = parse_containers(body).unwrap();

        assert_eq!(containers.len(), 1);
        let c = &containers[0];
        assert_eq!(c.name, "web-1");
        assert_eq!(c.ports, vec![8080]);
        assert_eq!(c.compose_project.as_deref(), Some("shop"));
        assert_eq!(c.compose_dir.as_deref(), Some("/srv/shop"));
        assert_eq!(c.mounts, vec!["/srv/shop/html:/usr/share/nginx/html"]);
        assert_eq!(c.short_id(), "abcdef123456");
    }

    #[test]
    fn restart_policy_and_version_come_from_inspect_and_version() {
        assert_eq!(
            parse_restart_policy(r#"{"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}"#)
                .as_deref(),
            Some("unless-stopped")
        );
        assert_eq!(
            parse_version(r#"{"Version":"27.1.1"}"#).as_deref(),
            Some("27.1.1")
        );

        let manual = Container {
            restart_policy: Some("no".into()),
            ..Default::default()
        };
        assert!(manual.will_not_survive_reboot());
    }

    #[test]
    fn reads_a_chunked_docker_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n";

        assert_eq!(parse_http_body(raw).as_deref(), Some("[]"));
    }
}
