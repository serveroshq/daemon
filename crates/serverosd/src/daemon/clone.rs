//! Cloning a running container to try things on: the same image, command
//! and environment under a new name, on its own port or domain, with its
//! own volumes, either copied from the original or empty. The original is
//! only read. Databases are copied with their own dump tools, since their
//! files can't be copied safely while they run.

use std::path::Path;
use std::time::Duration;

use daemon_backup::snapshot::{MYSQL_CLIENT, MYSQL_DUMP};
use daemon_backup::Strategy;
use daemon_jobs::{Failure, JobContext};
use daemon_protocol::{AdoptedCapability, ServiceOrigin};
use daemon_services::clone::{bind_target, create_body, main_port, mount_plan, MountPlan};
use daemon_services::docker::{valid_container_ref, DockerAdapter};
use daemon_services::{ManagedService, Registry, RunBy};
use serde_json::{json, Value};
use tokio::process::Command;

use super::app::App;

pub struct CloneRequest {
    pub name: String,
    pub port: Option<u16>,
    pub container_port: Option<u16>,
    pub domain: Option<String>,
    pub copy_data: bool,
}

/// A name for a container: lowercase letters, digits and dashes, starting
/// with a letter.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub async fn clone(
    app: &App,
    ctx: &JobContext,
    source: &ManagedService,
    request: CloneRequest,
) -> Result<Value, Failure> {
    let fail = |message: String| Failure::new("clone", message);
    let container = super::service_ops::container_of(source)
        .ok_or_else(|| {
            fail(format!(
                "{} isn't a container; only containers can be cloned for now",
                source.name
            ))
        })?
        .to_string();
    let name = request.name.trim().to_string();
    if !valid_name(&name) || !valid_container_ref(&name) {
        return Err(fail(format!("{name:?} isn't a usable name: lowercase letters, digits and dashes, starting with a letter")));
    }
    if request.domain.is_some() && request.port.is_none() {
        return Err(fail(
            "a clone on a domain needs a port on the machine for the proxy to send it to".into(),
        ));
    }

    let docker = DockerAdapter::default();
    let inspect = docker
        .inspect_with_secrets(&container)
        .await
        .map_err(|e| fail(e.to_string()))?;
    let source_name = inspect["Name"]
        .as_str()
        .unwrap_or(&container)
        .trim_start_matches('/')
        .to_string();
    let image = inspect
        .pointer("/Config/Image")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string();
    let env: Vec<String> = inspect
        .pointer("/Config/Env")
        .and_then(|e| e.as_array())
        .map(|e| {
            e.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let running = inspect
        .pointer("/State/Running")
        .and_then(|r| r.as_bool())
        .unwrap_or(false);
    // A running database is copied with its own tools once the clone is up.
    let database =
        Strategy::for_container(&container, &image, &env, Vec::new(), running).filter(|s| {
            matches!(
                s,
                Strategy::PostgresContainer { .. } | Strategy::MysqlContainer { .. }
            )
        });
    let copy_files = request.copy_data && database.is_none();

    // Each mount becomes the clone's own (or is shared, read-only or the machine's).
    let clones_dir = app.deployer.paths.state_dir.join("clones");
    let clones_dir = clones_dir.to_string_lossy().to_string();
    let plan = mount_plan(&inspect, &name, |p| Path::new(p).is_file());
    let mut binds = Vec::new();
    let mut made_volumes = Vec::new();
    let mut made_dirs = Vec::new();
    let mut copied = Vec::new();
    let undo = |volumes: Vec<String>, dir: String| async move {
        for volume in volumes {
            let _ = run(
                "docker",
                &["volume", "rm", &volume],
                Duration::from_secs(60),
            )
            .await;
        }
        let _ = std::fs::remove_dir_all(dir);
    };
    let clone_dir = format!("{clones_dir}/{name}");

    for (index, mount) in plan.iter().enumerate() {
        let step = async {
            match mount {
                MountPlan::Volume {
                    from,
                    to,
                    destination,
                } => {
                    run(
                        "docker",
                        &[
                            "volume",
                            "create",
                            "--label",
                            "com.serveros.managed=true",
                            to,
                        ],
                        Duration::from_secs(60),
                    )
                    .await?;
                    made_volumes.push(to.clone());
                    if copy_files {
                        ctx.progress
                            .line(format!("copying volume {from} into {to}"))
                            .await;
                        let src = mountpoint(from).await?;
                        let dst = mountpoint(to).await?;
                        copy_dir(&src, &dst).await?;
                        copied.push(destination.clone());
                    }
                    binds.push(format!("{to}:{destination}"));
                }
                MountPlan::Bind {
                    from,
                    destination,
                    file,
                } => {
                    let target = bind_target(&clones_dir, &name, index, from);
                    made_dirs.push(target.clone());
                    if *file {
                        // Usually config, which the clone needs to start.
                        std::fs::create_dir_all(
                            Path::new(&target).parent().unwrap_or(Path::new("/")),
                        )
                        .map_err(|e| fail(format!("could not make {target}: {e}")))?;
                        run("cp", &["-a", from, &target], Duration::from_secs(600)).await?;
                        copied.push(destination.clone());
                    } else {
                        std::fs::create_dir_all(&target)
                            .map_err(|e| fail(format!("could not make {target}: {e}")))?;
                        if copy_files {
                            ctx.progress
                                .line(format!("copying {from} into {target}"))
                                .await;
                            copy_dir(from, &target).await?;
                            copied.push(destination.clone());
                        }
                    }
                    binds.push(format!("{target}:{destination}"));
                }
                MountPlan::Shared {
                    source,
                    destination,
                    read_only,
                } => {
                    binds.push(format!(
                        "{source}:{destination}{}",
                        if *read_only { ":ro" } else { "" }
                    ));
                }
            }
            Ok::<(), Failure>(())
        }
        .await;
        if let Err(e) = step {
            undo(made_volumes, clone_dir).await;
            return Err(e);
        }
    }

    // Published only on the port asked for: on the machine itself behind a
    // domain, else where the original published that port (or everywhere).
    let port = match (request.port, main_port(&inspect, request.container_port)) {
        (Some(host_port), Some(container_port)) => {
            let address = if request.domain.is_some() {
                "127.0.0.1".to_string()
            } else {
                inspect
                    .pointer(&format!(
                        "/HostConfig/PortBindings/{}",
                        container_port.replace('/', "~1")
                    ))
                    .and_then(|b| b.get(0))
                    .and_then(|b| b.get("HostIp"))
                    .and_then(|h| h.as_str())
                    .filter(|h| !h.is_empty())
                    .unwrap_or("0.0.0.0")
                    .to_string()
            };
            Some((container_port, address, host_port))
        }
        (Some(_), None) => {
            undo(made_volumes, clone_dir).await;
            return Err(fail(format!("{source_name} doesn't publish or expose a port to put on the new one; say which with container_port")));
        }
        _ => None,
    };

    let Some((body, more_networks)) = create_body(&inspect, &source_name, binds, port.clone())
    else {
        undo(made_volumes, clone_dir).await;
        return Err(fail(format!(
            "couldn't read {source_name}'s settings to copy them"
        )));
    };
    ctx.progress.phase("start", Some(60)).await;
    let id = match docker.create_and_start(&name, &body, &more_networks).await {
        Ok(id) => id,
        Err(e) => {
            undo(made_volumes, clone_dir).await;
            return Err(fail(e.to_string()));
        }
    };

    // ServerOS made it, so it can be started, stopped and removed like one.
    let key = format!("docker:{}", &id[..id.len().min(12)]);
    let _ = Registry::new(&app.state).upsert(ManagedService {
        key: key.clone(),
        name: name.clone(),
        run_by: RunBy::Docker {
            container: name.clone(),
        },
        origin: ServiceOrigin::Created,
        adopted_at: daemon_state::State::now(),
        capabilities: vec![
            AdoptedCapability::Lifecycle,
            AdoptedCapability::Logs,
            AdoptedCapability::Metrics,
        ],
        roots: Vec::new(),
        config_paths: Vec::new(),
        data_dir: None,
        added_artifacts: Vec::new(),
    });
    app.broker.record_created_service(key.clone());

    let mut notes = Vec::new();
    if request.copy_data {
        if let Some(database) = &database {
            ctx.progress.phase("copy data", Some(75)).await;
            match copy_database(ctx, database, &container, &name).await {
                Ok(()) => copied.push("the database".into()),
                Err(e) => notes.push(format!(
                    "The clone runs, but its database wasn't copied: {}",
                    e.message
                )),
            }
        }
    }

    if let Some(domain) = &request.domain {
        ctx.progress.phase("domain", Some(90)).await;
        let mut cancel = ctx.cancel.clone();
        let host_port = request.port.unwrap_or_default();
        if let Err(e) = app
            .deployer
            .proxy
            .publish(
                &name,
                std::slice::from_ref(domain),
                host_port,
                &mut cancel,
                &ctx.progress,
            )
            .await
        {
            notes.push(format!(
                "The clone runs on port {host_port}, but {domain} couldn't be set up: {}",
                e.message
            ));
        }
    }

    Ok(json!({
        "key": key,
        "name": name,
        "source": source_name,
        "port": request.port,
        "containerPort": port.map(|(p, _, _)| p),
        "domain": request.domain,
        "copied": copied,
        "database": database.is_some(),
        "notes": notes,
    }))
}

/// Loads the original's databases into the clone, once the clone answers
/// over the network (not the setup server its image runs first).
async fn copy_database(
    ctx: &JobContext,
    database: &Strategy,
    source: &str,
    clone: &str,
) -> Result<(), Failure> {
    let (ready, pipe) = match database {
        Strategy::PostgresContainer { user, .. } => {
            let user = user.replace('\'', "");
            (
                format!("docker exec {clone} pg_isready -h 127.0.0.1 -U '{user}'"),
                format!("docker exec {source} pg_dumpall -U '{user}' --clean --if-exists | docker exec -i {clone} psql -U '{user}' -v ON_ERROR_STOP=0 -q -d postgres"),
            )
        }
        Strategy::MysqlContainer { .. } => (
            format!(
                "docker exec {clone} sh -c '{}'",
                r#"C=mysqladmin; command -v mariadb-admin >/dev/null 2>&1 && C=mariadb-admin; P="${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}"; if [ -n "$P" ]; then set -- -p"$P"; fi; exec $C ping -h 127.0.0.1 --protocol=tcp -uroot "$@""#
            ),
            format!("docker exec {source} sh -c '{MYSQL_DUMP}' | docker exec -i {clone} sh -c '{MYSQL_CLIENT}'"),
        ),
        _ => return Ok(()),
    };

    ctx.progress
        .line(format!("waiting for {clone} to accept connections"))
        .await;
    let mut up = false;
    for _ in 0..60 {
        if run("sh", &["-c", &ready], Duration::from_secs(10))
            .await
            .is_ok()
        {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    if !up {
        return Err(Failure::new(
            "clone",
            format!("{clone} didn't start accepting connections in two minutes"),
        ));
    }

    ctx.progress
        .line(format!("copying the databases from {source}"))
        .await;
    // bash, for pipefail: a dump that fails part-way mustn't count as copied.
    run(
        "bash",
        &["-c", &format!("set -o pipefail; {pipe}")],
        Duration::from_secs(3600),
    )
    .await
}

async fn mountpoint(volume: &str) -> Result<String, Failure> {
    let out = Command::new("docker")
        .args(["volume", "inspect", "-f", "{{.Mountpoint}}", volume])
        .output()
        .await
        .map_err(|e| Failure::new("clone", format!("could not run docker: {e}")))?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || path.is_empty() {
        return Err(Failure::new(
            "clone",
            format!("couldn't find where volume {volume} is kept"),
        ));
    }
    Ok(path)
}

/// Copies a folder's contents, keeping owners and permissions.
async fn copy_dir(from: &str, to: &str) -> Result<(), Failure> {
    run(
        "cp",
        &["-a", &format!("{}/.", from.trim_end_matches('/')), to],
        Duration::from_secs(3600),
    )
    .await
}

async fn run(program: &str, args: &[&str], limit: Duration) -> Result<(), Failure> {
    let out = tokio::time::timeout(
        limit,
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| {
        Failure::new(
            "clone",
            format!("{program} took longer than {} seconds", limit.as_secs()),
        )
    })?
    .map_err(|e| Failure::new("clone", format!("could not run {program}: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(Failure::new(
        "clone",
        format!(
            "{program} failed: {}",
            err.lines().last().unwrap_or("").trim()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercase_and_start_with_a_letter() {
        assert!(valid_name("shop-test-2"));
        assert!(!valid_name("Shop"));
        assert!(!valid_name("2shop"));
        assert!(!valid_name("shop_test"));
        assert!(!valid_name(""));
    }
}
