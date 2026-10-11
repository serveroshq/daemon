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
    request_with(socket, method, path, None, timeout).await
}

async fn request_with(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    timeout: Duration,
) -> Result<Reply> {
    let work = async {
        let mut stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|e| ServiceError::Docker(format!("{}: {e}", socket.display())))?;
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let content_type = if body.is_some() {
            "Content-Type: application/json\r\n"
        } else {
            ""
        };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
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
            .filter(|line| !daemon_core::logskip::skips_line(Some(container), line))
            .map(daemon_core::ipmask::outgoing)
            .collect())
    }
}

/// What leaves the machine when someone looks at a container's config:
/// environment variables keep their names but never their values (they're
/// where passwords and tokens live), and the command line and labels go
/// through the usual secret redaction.
pub fn without_secrets(inspect: &mut serde_json::Value) {
    use daemon_core::redact::{redact, REDACTED};

    if let Some(env) = inspect
        .pointer_mut("/Config/Env")
        .and_then(|v| v.as_array_mut())
    {
        for entry in env.iter_mut() {
            if let Some(text) = entry.as_str() {
                let name = text.split_once('=').map_or(text, |(name, _)| name);
                *entry = serde_json::Value::String(format!("{name}={REDACTED}"));
            }
        }
    }

    for pointer in ["/Config/Cmd", "/Config/Entrypoint", "/Args"] {
        if let Some(parts) = inspect.pointer_mut(pointer).and_then(|v| v.as_array_mut()) {
            for part in parts.iter_mut() {
                if let Some(text) = part.as_str() {
                    *part = serde_json::Value::String(redact(text));
                }
            }
        }
    }
    if let Some(path) = inspect.get_mut("Path") {
        if let Some(text) = path.as_str() {
            *path = serde_json::Value::String(redact(text));
        }
    }

    if let Some(labels) = inspect
        .pointer_mut("/Config/Labels")
        .and_then(|v| v.as_object_mut())
    {
        for value in labels.values_mut() {
            if let Some(text) = value.as_str() {
                *value = serde_json::Value::String(redact(text));
            }
        }
    }
}

pub const WINGS_RUNTIME: &str = "/run/wings/";

fn is_wings_runtime(source: &str) -> bool {
    source.starts_with(WINGS_RUNTIME)
}

pub fn wings_runtime_mounts(inspect: &serde_json::Value) -> Vec<String> {
    let binds = inspect
        .pointer("/HostConfig/Binds")
        .and_then(|b| b.as_array())
        .into_iter()
        .flatten()
        .filter_map(|b| b.as_str())
        .filter_map(|b| b.split(':').next());
    let mounts = inspect
        .pointer("/HostConfig/Mounts")
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("Source").and_then(|s| s.as_str()));

    let mut found: Vec<String> = binds
        .chain(mounts)
        .filter(|s| is_wings_runtime(s))
        .map(str::to_string)
        .collect();
    found.sort();
    found.dedup();
    found
}

pub fn repaired_create_body(inspect: &serde_json::Value) -> Option<serde_json::Value> {
    if wings_runtime_mounts(inspect).is_empty() {
        return None;
    }

    let mut body = inspect.get("Config")?.clone();
    let mut host = inspect.get("HostConfig")?.clone();

    if let Some(binds) = host.get_mut("Binds").and_then(|b| b.as_array_mut()) {
        binds.retain(|b| {
            !b.as_str()
                .and_then(|b| b.split(':').next())
                .is_some_and(is_wings_runtime)
        });
    }
    if let Some(mounts) = host.get_mut("Mounts").and_then(|m| m.as_array_mut()) {
        mounts.retain(|m| {
            !m.get("Source")
                .and_then(|s| s.as_str())
                .is_some_and(is_wings_runtime)
        });
    }
    host["RestartPolicy"] = serde_json::json!({"Name": "unless-stopped", "MaximumRetryCount": 0});

    let mode = host
        .get("NetworkMode")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let networks = inspect
        .pointer("/NetworkSettings/Networks")
        .and_then(|n| n.as_object());
    let endpoint = networks.and_then(|n| {
        n.get(&mode)
            .map(|e| (mode.clone(), e))
            .or_else(|| n.iter().next().map(|(k, e)| (k.clone(), e)))
    });

    let object = body.as_object_mut()?;
    object.insert("HostConfig".into(), host);
    if let Some((name, endpoint)) = endpoint {
        if !matches!(name.as_str(), "bridge" | "host" | "none" | "default") {
            let mut config = serde_json::Map::new();
            for field in ["Aliases", "IPAMConfig", "Links"] {
                if let Some(value) = endpoint.get(field).filter(|v| !v.is_null()) {
                    config.insert(field.into(), value.clone());
                }
            }
            object.insert(
                "NetworkingConfig".into(),
                serde_json::json!({ "EndpointsConfig": { name: config } }),
            );
        }
    }

    Some(body)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repaired {
    pub name: String,
    pub old_id: String,
    pub new_id: String,
    pub dropped: Vec<String>,
    pub old_kept: bool,
}

impl DockerAdapter {
    /// A container's `docker inspect`, with secrets taken out first (see
    /// [`without_secrets`]): read-only, for people looking at its config.
    pub async fn inspect(&self, container: &str) -> Result<serde_json::Value> {
        if !valid_container_ref(container) {
            return Err(ServiceError::Docker(format!(
                "{container:?} is not a valid container reference"
            )));
        }
        let reply = self
            .call(
                "GET",
                &format!("/containers/{container}/json"),
                None,
                &[200],
                &format!("inspect {container}"),
            )
            .await?;
        let mut value: serde_json::Value = serde_json::from_slice(&reply.body)?;
        without_secrets(&mut value);

        Ok(value)
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
        ok: &[u16],
        what: &str,
    ) -> Result<Reply> {
        let reply = request_with(&self.socket, method, path, body, self.timeout).await?;
        if ok.contains(&reply.status) {
            Ok(reply)
        } else {
            Err(docker_error(&reply, what))
        }
    }

    pub async fn repair_wings(&self, container: &str) -> Result<Repaired> {
        if !valid_container_ref(container) {
            return Err(ServiceError::Docker(format!(
                "{container:?} is not a valid container reference"
            )));
        }

        let reply = self
            .call(
                "GET",
                &format!("/containers/{container}/json"),
                None,
                &[200],
                &format!("inspect {container}"),
            )
            .await?;
        let inspect: serde_json::Value = serde_json::from_slice(&reply.body)?;
        let old_id = inspect
            .get("Id")
            .and_then(|i| i.as_str())
            .unwrap_or(container)
            .to_string();
        let name = inspect
            .get("Name")
            .and_then(|n| n.as_str())
            .map(|n| n.trim_start_matches('/').to_string())
            .filter(|n| valid_container_ref(n))
            .ok_or_else(|| ServiceError::Docker(format!("{container} has no usable name")))?;
        let dropped = wings_runtime_mounts(&inspect);
        let body = repaired_create_body(&inspect).ok_or_else(|| {
            ServiceError::Docker(format!(
                "{name} has no Wings mounts, so there's nothing to repair"
            ))
        })?;

        if status_from_inspect(&inspect) == ServiceStatus::Running {
            self.call(
                "POST",
                &format!("/containers/{old_id}/stop?t=30"),
                None,
                &[204, 304],
                &format!("stop {name}"),
            )
            .await?;
        }

        let parked = format!("{name}-before-repair");
        self.call(
            "POST",
            &format!("/containers/{old_id}/rename?name={parked}"),
            None,
            &[204],
            &format!("rename {name}"),
        )
        .await?;

        let restore = || async {
            let _ = self
                .call(
                    "POST",
                    &format!("/containers/{old_id}/rename?name={name}"),
                    None,
                    &[204],
                    "rename back",
                )
                .await;
        };

        let created = match self
            .call(
                "POST",
                &format!("/containers/create?name={name}"),
                Some(&body),
                &[201],
                &format!("create {name}"),
            )
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                restore().await;
                return Err(e);
            }
        };
        let new_id = serde_json::from_slice::<serde_json::Value>(&created.body)?
            .get("Id")
            .and_then(|i| i.as_str())
            .unwrap_or_default()
            .to_string();

        if let Err(e) = self
            .call(
                "POST",
                &format!("/containers/{new_id}/start"),
                None,
                &[204, 304],
                &format!("start {name}"),
            )
            .await
        {
            let _ = self
                .call(
                    "DELETE",
                    &format!("/containers/{new_id}?force=1"),
                    None,
                    &[204, 404],
                    "remove new",
                )
                .await;
            restore().await;
            return Err(e);
        }

        let old_kept = self
            .call(
                "DELETE",
                &format!("/containers/{old_id}?v=0"),
                None,
                &[204, 404],
                "remove old",
            )
            .await
            .is_err();

        Ok(Repaired {
            name,
            old_id,
            new_id,
            dropped,
            old_kept,
        })
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

    fn wings_inspect() -> serde_json::Value {
        serde_json::json!({
            "Id": "82cfe2569cd4aaaa",
            "Name": "/10279aa4-91dd-4187-a5d6-3231719a725d",
            "State": {"Status": "exited"},
            "Config": {
                "Image": "5140/discord-egg:latest",
                "User": "988",
                "Env": ["STARTUP=npm start", "SERVER_MEMORY=512"],
                "ExposedPorts": {"25567/tcp": {}},
                "Labels": {"Service": "Pterodactyl"}
            },
            "HostConfig": {
                "Binds": ["/run/wings/machine-id/10279aa4:/etc/machine-id:ro"],
                "Mounts": [
                    {"Type": "bind", "Source": "/var/lib/serveros/volumes/10279aa4", "Target": "/home/container"},
                    {"Type": "bind", "Source": "/run/wings/passwd/10279aa4", "Target": "/etc/passwd"}
                ],
                "PortBindings": {"25567/tcp": [{"HostIp": "0.0.0.0", "HostPort": "25567"}]},
                "Memory": 617398272,
                "NetworkMode": "pterodactyl_nw",
                "RestartPolicy": {"Name": "", "MaximumRetryCount": 0}
            },
            "NetworkSettings": {"Networks": {"pterodactyl_nw": {"Aliases": null, "IPAMConfig": null, "IPAddress": "172.18.0.4"}}}
        })
    }

    #[test]
    fn finds_the_wings_runtime_mounts() {
        assert_eq!(
            wings_runtime_mounts(&wings_inspect()),
            vec![
                "/run/wings/machine-id/10279aa4",
                "/run/wings/passwd/10279aa4"
            ]
        );
        assert!(
            wings_runtime_mounts(&serde_json::json!({"HostConfig": {"Binds": ["/srv:/srv"]}}))
                .is_empty()
        );
    }

    #[test]
    fn repair_keeps_everything_but_the_wings_mounts() {
        let body = repaired_create_body(&wings_inspect()).unwrap();

        assert_eq!(body["Image"], "5140/discord-egg:latest");
        assert_eq!(body["User"], "988");
        assert_eq!(body["Env"][1], "SERVER_MEMORY=512");
        assert_eq!(body["HostConfig"]["Binds"], serde_json::json!([]));
        assert_eq!(
            body["HostConfig"]["Mounts"],
            serde_json::json!([{"Type": "bind", "Source": "/var/lib/serveros/volumes/10279aa4", "Target": "/home/container"}])
        );
        assert_eq!(
            body["HostConfig"]["PortBindings"]["25567/tcp"][0]["HostPort"],
            "25567"
        );
        assert_eq!(body["HostConfig"]["Memory"], 617398272);
        assert_eq!(
            body["HostConfig"]["RestartPolicy"]["Name"],
            "unless-stopped"
        );
        assert_eq!(
            body["NetworkingConfig"],
            serde_json::json!({"EndpointsConfig": {"pterodactyl_nw": {}}})
        );
    }

    #[test]
    fn nothing_to_repair_without_wings_mounts() {
        let mut inspect = wings_inspect();
        inspect["HostConfig"]["Binds"] = serde_json::json!([]);
        inspect["HostConfig"]["Mounts"] = serde_json::json!([]);

        assert!(repaired_create_body(&inspect).is_none());
    }

    #[test]
    fn container_refs_are_validated() {
        assert!(valid_container_ref("shop-web-1"));
        assert!(valid_container_ref("abcdef123456"));
        assert!(!valid_container_ref("../../etc"));
        assert!(!valid_container_ref("x y"));
    }

    #[test]
    fn inspect_never_sends_env_values() {
        let mut inspect = serde_json::json!({
            "Path": "/app/server",
            "Args": ["--db", "postgres://app:hunter2secret@db/app"],
            "Config": {
                "Env": ["DATABASE_URL=postgres://app:hunter2secret@db/app", "DEBUG", "PORT=8080"],
                "Cmd": ["node", "server.js"],
                "Labels": {"com.docker.swarm.service.name": "web", "token": "api_key=abcdef1234567890abcdef"}
            },
            "NetworkSettings": {"Networks": {"web_net": {"IPAddress": "10.0.1.5"}}}
        });

        without_secrets(&mut inspect);

        let text = inspect.to_string();
        assert!(!text.contains("hunter2secret"), "{text}");
        assert!(!text.contains("8080"), "{text}");
        assert!(!text.contains("abcdef1234567890abcdef"), "{text}");
        assert_eq!(
            inspect.pointer("/Config/Env").unwrap(),
            &serde_json::json!([
                "DATABASE_URL=[redacted]",
                "DEBUG=[redacted]",
                "PORT=[redacted]"
            ])
        );
        // The rest is left as it is.
        assert_eq!(
            inspect
                .pointer("/Config/Labels/com.docker.swarm.service.name")
                .unwrap(),
            "web"
        );
        assert_eq!(
            inspect
                .pointer("/NetworkSettings/Networks/web_net/IPAddress")
                .unwrap(),
            "10.0.1.5"
        );
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
