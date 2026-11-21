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
    /// The image the container runs (`sha256:…`), and the registry digests
    /// Docker has for it (`postgres@sha256:…`), to tell whether the
    /// registry has a newer one. No digests means a local build.
    pub image_id: String,
    pub image_digests: Vec<String>,
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

    pub fn will_not_survive_reboot(&self) -> bool {
        matches!(self.restart_policy.as_deref(), None | Some("no") | Some(""))
    }
}

/// Docker 29 sends `null` for some empty lists (`"Ports": null` on a
/// container that publishes none): read as empty.
fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct RawContainer {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Names", default, deserialize_with = "null_default")]
    names: Vec<String>,
    #[serde(rename = "Image", default, deserialize_with = "null_default")]
    image: String,
    #[serde(rename = "ImageID", default, deserialize_with = "null_default")]
    image_id: String,
    #[serde(rename = "State", default, deserialize_with = "null_default")]
    state: String,
    #[serde(rename = "Status", default, deserialize_with = "null_default")]
    status: String,
    #[serde(rename = "Ports", default, deserialize_with = "null_default")]
    ports: Vec<RawPort>,
    #[serde(rename = "Labels", default, deserialize_with = "null_default")]
    labels: std::collections::BTreeMap<String, String>,
    #[serde(rename = "Mounts", default, deserialize_with = "null_default")]
    mounts: Vec<RawMount>,
    #[serde(rename = "Created", default, deserialize_with = "null_default")]
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
                image_id: c.image_id,
                image_digests: Vec::new(),
                state: c.state,
                status: c.status,
                ports,
                restart_policy: None,
                labels: c.labels,
                created: c.created,
            }
        })
        .collect())
}

#[derive(Deserialize)]
struct RawImage {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoDigests", default, deserialize_with = "null_default")]
    repo_digests: Vec<String>,
}

/// `/images/json` as image id => its registry digests.
pub fn parse_image_digests(
    body: &str,
) -> Result<std::collections::HashMap<String, Vec<String>>, serde_json::Error> {
    let raw: Vec<RawImage> = serde_json::from_str(body)?;

    Ok(raw.into_iter().map(|i| (i.id, i.repo_digests)).collect())
}

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

/// A container's output since `since` (Unix seconds, with a fraction), one
/// stream of it, each line with the time Docker took it down
/// (RFC 3339). At most `max` bytes are read; `truncated` says there was
/// more, which the next read picks up from the last line's time.
pub async fn logs_since(
    socket: &Path,
    id: &str,
    stderr: bool,
    since: &str,
    max: usize,
    timeout: Duration,
) -> Option<(Vec<(String, String)>, bool)> {
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return None;
    }
    let path = format!(
        "/containers/{id}/logs?stdout={}&stderr={}&timestamps=1&since={since}",
        u8::from(!stderr),
        u8::from(stderr)
    );
    let body = crate::local_http::get(
        &crate::local_http::Target::Unix(socket.to_path_buf()),
        "docker",
        &path,
        timeout,
        max,
    )
    .await?;
    let text = demux(&body.bytes);
    let mut lines: Vec<(String, String)> = Vec::new();
    let complete = if body.truncated {
        text.rfind('\n').map_or("", |end| &text[..end])
    } else {
        text.as_str()
    };
    for line in complete.lines() {
        let Some((stamp, rest)) = line.split_once(' ') else {
            continue;
        };
        lines.push((stamp.to_string(), rest.to_string()));
    }
    Some((lines, body.truncated))
}

/// Docker's framed log stream (8-byte headers) as text; output from a
/// container with a TTY isn't framed and passes through.
pub fn demux(raw: &[u8]) -> String {
    let framed = raw.len() >= 8 && matches!(raw[0], 0..=2) && raw[1..4] == [0, 0, 0];
    if !framed {
        return String::from_utf8_lossy(raw).into_owned();
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut cursor = 0;
    while cursor + 8 <= raw.len() {
        let len = u32::from_be_bytes([
            raw[cursor + 4],
            raw[cursor + 5],
            raw[cursor + 6],
            raw[cursor + 7],
        ]) as usize;
        let start = cursor + 8;
        if start + len > raw.len() {
            // Cut off by the read cap: the whole lines in it still count.
            let part = &raw[start..];
            if let Some(end) = part.iter().rposition(|b| *b == b'\n') {
                out.extend_from_slice(&part[..=end]);
            }
            break;
        }
        out.extend_from_slice(&raw[start..start + len]);
        cursor = start + len;
    }
    String::from_utf8_lossy(&out).into_owned()
}

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

    if let Some(digests) = get(socket, "/images/json", timeout)
        .await
        .and_then(|b| parse_image_digests(&b).ok())
    {
        for container in containers.iter_mut() {
            if let Some(list) = digests.get(&container.image_id) {
                container.image_digests = list.clone();
            }
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
    fn image_ids_and_their_registry_digests() {
        let body = r#"[{"Id":"abcdef1234567890","Names":["/db"],"Image":"postgres:16","ImageID":"sha256:111","State":"running","Status":"Up","Ports":null,"Labels":null,"Mounts":null,"Created":1}]"#;
        assert_eq!(parse_containers(body).unwrap()[0].image_id, "sha256:111");

        let images = r#"[{"Id":"sha256:111","RepoDigests":["postgres@sha256:aaa"]},{"Id":"sha256:222","RepoDigests":null}]"#;
        let digests = parse_image_digests(images).unwrap();
        assert_eq!(digests["sha256:111"], vec!["postgres@sha256:aaa"]);
        assert!(digests["sha256:222"].is_empty());
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
    fn null_lists_from_docker_29_read_as_empty() {
        let body = r#"[{"Id":"abcdef1234567890","Names":["/app"],"Image":"python","State":"running","Status":"Up","Ports":null,"Labels":{"traefik.enable":"true"},"Mounts":null,"Created":1}]"#;
        let containers = parse_containers(body).unwrap();
        assert!(containers[0].ports.is_empty() && containers[0].mounts.is_empty());
        assert_eq!(
            containers[0]
                .labels
                .get("traefik.enable")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn framed_output_reads_as_lines_even_when_cut_off() {
        let mut raw = vec![1, 0, 0, 0, 0, 0, 0, 6];
        raw.extend_from_slice(b"a\nbcd\n");
        raw.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 20]);
        raw.extend_from_slice(b"whole\npart");
        assert_eq!(demux(&raw), "a\nbcd\nwhole\n");
        assert_eq!(demux(b"tty\n"), "tty\n");
    }

    #[test]
    fn reads_a_chunked_docker_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n";

        assert_eq!(parse_http_body(raw).as_deref(), Some("[]"));
    }
}
