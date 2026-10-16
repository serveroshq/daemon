//! Containers that can take over the machine they run on (privileged, the
//! Docker socket or the host's root mounted, the host's network or
//! processes), and ports they publish to the internet. Docker's own
//! firewall rules come before ufw's, so a published database port is open
//! whatever ufw says.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::util::clip;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONTAINERS: usize = 300;
/// Capabilities that are root on the host, or close to it.
const DANGEROUS_CAPS: &[&str] = &[
    "ALL",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
    "NET_ADMIN",
    "SYS_RAWIO",
    "BPF",
];
const SENSITIVE_MOUNTS: &[&str] = &[
    "/",
    "/etc",
    "/root",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc",
    "/sys",
    "/boot",
    "/dev",
    "/home",
    "/var/lib/docker",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct ContainerRisk {
    pub name: String,
    pub image: String,
    pub running: bool,
    pub privileged: bool,
    pub host_network: bool,
    pub host_pid: bool,
    pub docker_socket: bool,
    /// Host folders from SENSITIVE_MOUNTS it can see.
    pub sensitive_mounts: Vec<String>,
    pub capabilities: Vec<String>,
    pub public_ports: Vec<Published>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Published {
    pub host_port: u16,
    pub container_port: u16,
    pub proto: String,
}

impl ContainerRisk {
    fn notable(&self) -> bool {
        self.privileged
            || self.host_network
            || self.host_pid
            || self.docker_socket
            || !self.sensitive_mounts.is_empty()
            || !self.capabilities.is_empty()
            || !self.public_ports.is_empty()
    }
}

pub async fn audit(socket: &Path) -> Vec<ContainerRisk> {
    let Some(listing) =
        daemon_inventory::docker::get(socket, "/containers/json?all=1", TIMEOUT).await
    else {
        return Vec::new();
    };
    let Ok(Value::Array(containers)) = serde_json::from_str::<Value>(&listing) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for container in containers.iter().take(MAX_CONTAINERS) {
        let Some(id) = container.get("Id").and_then(Value::as_str) else {
            continue;
        };
        let Some(body) =
            daemon_inventory::docker::get(socket, &format!("/containers/{id}/json"), TIMEOUT).await
        else {
            continue;
        };
        if let Some(risk) = parse_inspect(&body).filter(ContainerRisk::notable) {
            out.push(risk);
        }
    }

    out
}

/// What `docker inspect` says about one container.
pub fn parse_inspect(body: &str) -> Option<ContainerRisk> {
    let json: Value = serde_json::from_str(body).ok()?;
    let host = json.get("HostConfig")?;
    let text = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or("").to_string();

    let mut mounts: Vec<String> = Vec::new();
    for mount in json
        .get("Mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = text(mount.get("Source"));
        let source = source.trim_end_matches('/');
        let source = if source.is_empty() { "/" } else { source };
        if SENSITIVE_MOUNTS.contains(&source) && !mounts.iter().any(|m| m == source) {
            mounts.push(source.to_string());
        }
    }
    let docker_socket = mounts.iter().any(|m| m.ends_with("docker.sock"));

    let mut capabilities: Vec<String> = host
        .get("CapAdd")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|c| c.trim_start_matches("CAP_").to_ascii_uppercase())
        .filter(|c| DANGEROUS_CAPS.contains(&c.as_str()))
        .collect();
    capabilities.sort();
    capabilities.dedup();

    let mut public_ports = Vec::new();
    if let Some(ports) = json
        .pointer("/NetworkSettings/Ports")
        .and_then(Value::as_object)
    {
        for (spec, bindings) in ports {
            let (port, proto) = spec.split_once('/').unwrap_or((spec, "tcp"));
            let Ok(container_port) = port.parse::<u16>() else {
                continue;
            };
            for binding in bindings.as_array().into_iter().flatten() {
                let ip = text(binding.get("HostIp"));
                if !matches!(ip.as_str(), "" | "0.0.0.0" | "::") {
                    continue;
                }
                let Ok(host_port) = text(binding.get("HostPort")).parse::<u16>() else {
                    continue;
                };
                let published = Published {
                    host_port,
                    container_port,
                    proto: proto.to_string(),
                };
                if !public_ports.contains(&published) {
                    public_ports.push(published);
                }
            }
        }
    }
    public_ports.sort_by_key(|p| (p.host_port, p.proto.clone()));

    Some(ContainerRisk {
        name: clip(text(json.get("Name")).trim_start_matches('/'), 120),
        image: clip(&text(json.pointer("/Config/Image")), 200),
        running: json
            .pointer("/State/Running")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        privileged: host
            .get("Privileged")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        host_network: text(host.get("NetworkMode")) == "host",
        host_pid: text(host.get("PidMode")) == "host",
        docker_socket,
        sensitive_mounts: mounts,
        capabilities,
        public_ports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_risky_containers() {
        let body = r#"{
            "Name": "/portainer",
            "Config": {"Image": "portainer/portainer-ce:latest"},
            "State": {"Running": true},
            "HostConfig": {"Privileged": true, "NetworkMode": "bridge", "PidMode": "", "CapAdd": ["CAP_SYS_ADMIN", "NET_BIND_SERVICE"]},
            "Mounts": [
                {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"},
                {"Source": "/var/lib/docker/volumes/data/_data", "Destination": "/data"}
            ],
            "NetworkSettings": {"Ports": {
                "9000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9000"}, {"HostIp": "::", "HostPort": "9000"}],
                "8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8000"}],
                "9443/tcp": null
            }}
        }"#;
        let risk = parse_inspect(body).unwrap();
        assert_eq!(risk.name, "portainer");
        assert!(risk.running && risk.privileged && risk.docker_socket);
        assert_eq!(risk.sensitive_mounts, vec!["/var/run/docker.sock"]);
        assert_eq!(risk.capabilities, vec!["SYS_ADMIN"]);
        assert_eq!(
            risk.public_ports,
            vec![Published {
                host_port: 9000,
                container_port: 9000,
                proto: "tcp".into()
            }]
        );
    }

    #[test]
    fn a_plain_local_container_is_not_notable() {
        let body = r#"{"Name": "/db", "Config": {"Image": "postgres:16"}, "State": {"Running": true},
            "HostConfig": {"NetworkMode": "bridge"}, "Mounts": [],
            "NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]}}}"#;
        assert!(!parse_inspect(body).unwrap().notable());
        let host_root = r#"{"Name": "/x", "Config": {"Image": "alpine"}, "HostConfig": {"NetworkMode": "host", "PidMode": "host"}, "Mounts": [{"Source": "/"}]}"#;
        let risk = parse_inspect(host_root).unwrap();
        assert!(risk.host_network && risk.host_pid);
        assert_eq!(risk.sensitive_mounts, vec!["/"]);
    }
}
