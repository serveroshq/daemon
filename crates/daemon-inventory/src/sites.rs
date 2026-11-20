//! Every site this machine serves through a web server it runs, however
//! it's set up: nginx and Apache from their configs, Caddy from its live
//! config, Traefik from its config and routers, on the machine or inside
//! containers. Read-only, bounded in time, and at most `MAX_SITES` of them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::access_logs::{self, Container, Paths, VhostLogs};
use crate::procs::{self, WebProcess};
use crate::{caddy, docker, traefik};

pub const MAX_SITES: usize = 500;
const DOCKER_TIMEOUT: Duration = Duration::from_secs(3);

/// What Docker says about the container a web server runs in.
#[derive(Debug, Clone, Default)]
struct Inspected {
    name: String,
    address: Option<String>,
}

async fn inspect(socket: &Path, id: &str) -> Option<Inspected> {
    let body = docker::get(socket, &format!("/containers/{id}/json"), DOCKER_TIMEOUT).await?;
    let value: Value = serde_json::from_str(&body).ok()?;
    let name = value
        .get("Name")
        .and_then(Value::as_str)
        .unwrap_or(&id[..id.len().min(12)])
        .trim_start_matches('/')
        .to_string();
    let address = value
        .pointer("/NetworkSettings/Networks")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(_, n)| n.get("IPAddress").and_then(Value::as_str))
        .find(|a| !a.is_empty())
        .map(str::to_string);
    Some(Inspected { name, address })
}

/// Running containers' labels, for Traefik's Docker provider.
async fn labelled(socket: &Path) -> Vec<traefik::Labelled> {
    let Some(body) = docker::get(socket, "/containers/json", DOCKER_TIMEOUT).await else {
        return Vec::new();
    };
    docker::parse_containers(&body)
        .map(|list| {
            list.into_iter()
                .filter(|c| c.labels.keys().any(|k| k.starts_with("traefik.")))
                .map(|c| (c.name, c.labels))
                .collect()
        })
        .unwrap_or_default()
}

/// The sites of the machine's own nginx and Apache (as `access_logs` reads
/// them), and of every web server it finds running: Caddy and Traefik on
/// the machine, and any of the four in a container.
pub async fn discover(socket: &Path) -> Vec<VhostLogs> {
    let (mut found, processes) =
        tokio::task::spawn_blocking(|| (access_logs::discover(), procs::discover()))
            .await
            .unwrap_or_default();
    let has_docker = socket.exists();
    let mut labels: Option<Vec<traefik::Labelled>> = None;
    for process in processes {
        if found.len() >= MAX_SITES {
            break;
        }
        let container = match (&process.container_id, has_docker) {
            (Some(id), true) => {
                let seen = inspect(socket, id).await.unwrap_or_default();
                Some((
                    Container {
                        id: id.clone(),
                        name: if seen.name.is_empty() {
                            id[..12].to_string()
                        } else {
                            seen.name
                        },
                    },
                    seen.address,
                ))
            }
            // In a container Docker doesn't know (Podman, LXC): its logs
            // can't be read, but its files can.
            (Some(id), false) => Some((
                Container {
                    id: id.clone(),
                    name: id[..12].to_string(),
                },
                None,
            )),
            (None, _) => None,
        };
        let sites = match process.server.as_str() {
            "nginx" | "apache" => match &container {
                // The machine's own were read above.
                None => continue,
                Some((c, _)) => {
                    let config = process.arg(&["-c", "-f"]).map(PathBuf::from);
                    let paths = Paths::in_container(
                        process.root.clone(),
                        c.clone(),
                        &process.server,
                        config,
                    );
                    tokio::task::spawn_blocking(move || access_logs::discover_in(&paths))
                        .await
                        .unwrap_or_default()
                }
            },
            "caddy" => caddy_sites(&process, container.as_ref().map(|(c, _)| c.clone())).await,
            "traefik" => {
                if labels.is_none() {
                    labels = Some(if has_docker {
                        labelled(socket).await
                    } else {
                        Vec::new()
                    });
                }
                let loaded = traefik::load(
                    &process,
                    container.as_ref().and_then(|(_, a)| a.as_deref()),
                    labels.as_deref().unwrap_or_default(),
                )
                .await;
                traefik::sites(
                    &loaded,
                    &traefik::Context {
                        container: container.as_ref().map(|(c, _)| c.clone()),
                        root: process.root.clone(),
                        editable: !process.in_container(),
                    },
                )
            }
            _ => continue,
        };
        found.extend(sites);
    }
    found.truncate(MAX_SITES);
    found
}

async fn caddy_sites(process: &WebProcess, container: Option<Container>) -> Vec<VhostLogs> {
    let Some(loaded) = caddy::load(process).await else {
        return Vec::new();
    };
    let editable = container.is_none() && loaded.caddyfile.is_some();
    let config_path = loaded
        .caddyfile
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| loaded.source.clone());
    caddy::sites(
        &loaded.config,
        &caddy::Context {
            config_path,
            editable,
            container,
            root: process.root.clone(),
        },
    )
}
