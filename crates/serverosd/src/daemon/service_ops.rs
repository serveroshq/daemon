use std::time::Duration;

use daemon_jobs::{run_child, ChildOutcome, Failure, JobContext};
use daemon_protocol::{AdoptedCapability, DeploySpec, ServiceOrigin};
use daemon_services::{ManagedService, Registry, RunBy};
use serde_json::{json, Value};
use tokio::process::Command;

use super::app::App;

const MAX_EXEC: Duration = Duration::from_secs(300);

pub fn container_of(service: &ManagedService) -> Option<&str> {
    match &service.run_by {
        RunBy::Docker { container } | RunBy::Compose { container, .. } => Some(container),
        _ => None,
    }
}

pub async fn exec(
    ctx: &JobContext,
    container: &str,
    command: &str,
    timeout_secs: Option<u64>,
) -> Result<Value, Failure> {
    let timeout = timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
        .min(MAX_EXEC);
    let mut cancel = ctx.cancel.clone();

    ctx.progress.line(format!("$ {command}")).await;

    match run_child(
        "docker",
        &["exec", container, "sh", "-c", command],
        None,
        &[],
        timeout,
        &mut cancel,
        &ctx.progress,
        None,
    )
    .await
    {
        ChildOutcome::Exited { code, .. } => Ok(json!({ "exit_code": code })),
        ChildOutcome::TimedOut { .. } => Err(Failure::new(
            "exec",
            format!("the command was still running after {}s", timeout.as_secs()),
        )
        .with_next_step("Run long tasks as their own service, or raise the timeout.")),
        ChildOutcome::Cancelled { .. } => Err(Failure::new("cancelled", "command cancelled")),
        ChildOutcome::Unstartable(e) => Err(Failure::new("exec", e)),
    }
}

pub async fn container_exists(key: &str) -> bool {
    let Some(id) = key.strip_prefix("docker:") else {
        return true;
    };

    match tokio::process::Command::new("docker")
        .args(["container", "inspect", "--format", "{{.Id}}", id])
        .kill_on_drop(true)
        .output()
        .await
    {
        Ok(out) => {
            out.status.success()
                || !String::from_utf8_lossy(&out.stderr).contains("No such container")
        }
        Err(_) => true,
    }
}

pub async fn remove(
    app: &App,
    ctx: &JobContext,
    service: &ManagedService,
    delete_data: bool,
) -> Result<Value, Failure> {
    let registry = Registry::new(&app.state);
    let progress = &ctx.progress;

    match &service.run_by {
        RunBy::Compose { project, .. } => {
            let label = format!("label=com.docker.compose.project={project}");
            let containers = docker_lines(&["ps", "-aq", "--filter", &label]).await;
            if !containers.is_empty() {
                let mut args = vec!["rm", "-f"];
                args.extend(containers.iter().map(String::as_str));
                docker(&args).await?;
            }
            progress
                .line(format!(
                    "removed {} container(s) of {project}",
                    containers.len()
                ))
                .await;

            let _ = docker(&["network", "rm", &format!("{project}_default")]).await;

            let mut volumes = Vec::new();
            if delete_data {
                volumes = docker_lines(&["volume", "ls", "-q", "--filter", &label]).await;
                if !volumes.is_empty() {
                    let mut args = vec!["volume", "rm", "-f"];
                    args.extend(volumes.iter().map(String::as_str));
                    docker(&args).await?;
                }
                progress
                    .line(format!("deleted {} volume(s)", volumes.len()))
                    .await;
            }

            for managed in registry.all().unwrap_or_default() {
                if matches!(&managed.run_by, RunBy::Compose { project: p, .. } if p == project) {
                    let _ = registry.remove(&managed.key);
                }
            }

            Ok(json!({ "removed": containers.len(), "volumes_deleted": volumes.len() }))
        }
        RunBy::Docker { container } => {
            let mut args = vec!["rm", "-f"];
            if delete_data {
                args.push("-v");
            }
            args.push(container);
            docker(&args).await?;
            let _ = registry.remove(&service.key);
            progress.line(format!("removed {container}")).await;

            Ok(json!({ "removed": 1, "volumes_deleted": usize::from(delete_data) }))
        }
        _ => Err(Failure::new(
            "remove",
            format!(
                "{} isn't a container, so ServerOS won't remove it",
                service.name
            ),
        )
        .with_next_step("Stop it instead, or remove it on the machine yourself.")),
    }
}

const DAEMON_DEPENDENCIES: &[&str] = &["serverosd", "serveros-gateway"];

fn is_daemon_dependency(name: &str, image: &str) -> bool {
    let name = name.trim_start_matches('/').to_ascii_lowercase();
    let image = image.to_ascii_lowercase();
    let repo = image.rsplit('/').next().unwrap_or(&image);
    let repo = repo.split([':', '@']).next().unwrap_or(repo);

    DAEMON_DEPENDENCIES
        .iter()
        .any(|d| name == *d || name.starts_with(&format!("{d}-")) || repo == *d)
}

fn parse_mounts(out: &str) -> (Vec<String>, Vec<String>) {
    let mut volumes = Vec::new();
    let mut binds = Vec::new();

    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match line.split_once(' ') {
            Some(("volume", name)) if !name.is_empty() => volumes.push(name.to_string()),
            Some(("bind", path)) if !path.is_empty() => binds.push(path.to_string()),
            _ => {}
        }
    }

    (volumes, binds)
}

pub async fn remove_adopted(
    app: &App,
    ctx: &JobContext,
    service: &ManagedService,
    delete_volumes: bool,
) -> Result<Value, Failure> {
    let progress = &ctx.progress;
    let Some(container) = container_of(service) else {
        return Err(Failure::new(
            "remove",
            format!(
                "{} isn't a container, so ServerOS won't remove it",
                service.name
            ),
        )
        .with_next_step("Stop it instead, or remove it on the machine yourself."));
    };

    let identity = docker(&[
        "container",
        "inspect",
        "--format",
        "{{.Name}}|{{.Config.Image}}",
        container,
    ])
    .await?;
    let (name, image) = identity
        .trim()
        .split_once('|')
        .unwrap_or((identity.trim(), ""));
    if is_daemon_dependency(name, image) {
        return Err(Failure::new(
            "remove",
            format!(
                "{} is part of ServerOS itself, so it can't be removed from here",
                service.name
            ),
        )
        .with_next_step("Uninstall ServerOS from the machine instead."));
    }

    let mounts = docker(&[
        "container",
        "inspect",
        "--format",
        "{{range .Mounts}}{{.Type}} {{if eq .Type \"volume\"}}{{.Name}}{{else}}{{.Source}}{{end}}\n{{end}}",
        container,
    ])
    .await?;
    let (volumes, binds) = parse_mounts(&mounts);

    docker(&["rm", "-f", container]).await?;
    let _ = Registry::new(&app.state).remove(&service.key);
    progress.line(format!("removed {container}")).await;

    let mut deleted = Vec::new();
    let mut kept = Vec::new();
    if delete_volumes {
        for volume in &volumes {
            match docker(&["volume", "rm", volume]).await {
                Ok(_) => deleted.push(volume.clone()),
                Err(e) => {
                    progress
                        .line(format!("kept volume {volume}: {}", e.message))
                        .await;
                    kept.push(volume.clone());
                }
            }
        }
        progress
            .line(format!("deleted {} volume(s)", deleted.len()))
            .await;
    } else {
        kept = volumes;
        if !kept.is_empty() {
            progress
                .line(format!("kept {} volume(s)", kept.len()))
                .await;
        }
    }
    if !binds.is_empty() {
        progress
            .line(format!(
                "left {} folder(s) on the machine untouched",
                binds.len()
            ))
            .await;
    }

    Ok(json!({
        "removed": 1,
        "volumes_deleted": deleted.len(),
        "volumes_kept": kept,
        "folders_kept": binds,
    }))
}

pub async fn register_deploy(app: &App, spec: &DeploySpec, container: &str) -> Vec<String> {
    let registry = Registry::new(&app.state);
    let project = format!("serveros-{}", sanitise(&spec.service));
    let now = daemon_state::State::now();
    let compose = spec.compose_file.is_some();

    let rows = if compose {
        let label = format!("label=com.docker.compose.project={project}");
        docker_lines(&[
            "ps",
            "-a",
            "--filter",
            &label,
            "--format",
            "{{.ID}} {{.Names}} {{.Label \"com.docker.compose.service\"}}",
        ])
        .await
    } else {
        let name = format!("name=^{container}$");
        docker_lines(&[
            "ps",
            "-a",
            "--filter",
            &name,
            "--format",
            "{{.ID}} {{.Names}}",
        ])
        .await
    };

    let mut keys = Vec::new();
    for row in rows {
        let mut parts = row.split_whitespace();
        let (Some(id), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        let key = format!("docker:{}", &id[..id.len().min(12)]);
        let run_by = if compose {
            RunBy::Compose {
                container: name.to_string(),
                project: project.clone(),
                dir: String::new(),
                service: parts.next().map(str::to_string),
            }
        } else {
            RunBy::Docker {
                container: name.to_string(),
            }
        };

        let _ = registry.upsert(ManagedService {
            key: key.clone(),
            name: name.to_string(),
            run_by,
            origin: ServiceOrigin::Created,
            adopted_at: now,
            capabilities: vec![
                AdoptedCapability::Lifecycle,
                AdoptedCapability::Logs,
                AdoptedCapability::Metrics,
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
            ],
            roots: Vec::new(),
            config_paths: Vec::new(),
            data_dir: None,
            added_artifacts: Vec::new(),
        });
        app.broker.record_created_service(key.clone());
        keys.push(key);
    }

    let prefix = format!("{project}-");
    for managed in registry.all().unwrap_or_default() {
        let ours = match &managed.run_by {
            RunBy::Compose { project: p, .. } => p == &project,
            RunBy::Docker { container } => container.starts_with(&prefix),
            _ => false,
        };
        if ours && managed.origin == ServiceOrigin::Created && !keys.contains(&managed.key) {
            let _ = registry.remove(&managed.key);
        }
    }

    keys
}

pub async fn register_earlier_deploys(app: &App) -> usize {
    let registry = Registry::new(&app.state);
    let now = daemon_state::State::now();
    let rows = docker_lines(&[
        "ps",
        "-a",
        "--format",
        "{{.ID}}\t{{.Names}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}",
    ])
    .await;

    let mut count = 0;
    for row in rows {
        let mut cols = row.split('\t');
        let (Some(id), Some(name)) = (cols.next(), cols.next()) else {
            continue;
        };
        let project = cols.next().unwrap_or("").trim();
        let compose_service = cols.next().unwrap_or("").trim();

        let run_by = if project.starts_with("serveros-") {
            RunBy::Compose {
                container: name.to_string(),
                project: project.to_string(),
                dir: String::new(),
                service: (!compose_service.is_empty()).then(|| compose_service.to_string()),
            }
        } else if project.is_empty() && name.starts_with("serveros-") {
            RunBy::Docker {
                container: name.to_string(),
            }
        } else {
            continue;
        };

        let key = format!("docker:{}", &id[..id.len().min(12)]);
        let already_created = registry
            .get(&key)
            .ok()
            .flatten()
            .is_some_and(|m| m.origin == ServiceOrigin::Created);
        if already_created {
            continue;
        }

        let _ = registry.upsert(ManagedService {
            key: key.clone(),
            name: name.to_string(),
            run_by,
            origin: ServiceOrigin::Created,
            adopted_at: now,
            capabilities: vec![
                AdoptedCapability::Lifecycle,
                AdoptedCapability::Logs,
                AdoptedCapability::Metrics,
                AdoptedCapability::Deploy,
                AdoptedCapability::Rollback,
            ],
            roots: Vec::new(),
            config_paths: Vec::new(),
            data_dir: None,
            added_artifacts: Vec::new(),
        });
        app.broker.record_created_service(key);
        count += 1;
    }

    count
}

fn sanitise(service: &str) -> String {
    service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

async fn docker(args: &[&str]) -> Result<String, Failure> {
    let output = tokio::time::timeout(
        Duration::from_secs(120),
        Command::new("docker")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| Failure::new("docker", format!("docker {} timed out", args.join(" "))))?
    .map_err(|e| {
        Failure::new("docker", e.to_string()).with_next_step("Install Docker on the machine.")
    })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Failure::new(
            "docker",
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

async fn docker_lines(args: &[&str]) -> Vec<String> {
    docker(args)
        .await
        .map(|out| {
            out.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daemon_and_gateway_are_never_removable() {
        assert!(is_daemon_dependency(
            "/serveros-gateway",
            "ghcr.io/serveroshq/serveros-gateway:1.4"
        ));
        assert!(is_daemon_dependency("/gw", "serveros-gateway@sha256:abc"));
        assert!(is_daemon_dependency("/serverosd", "debian:12"));
        assert!(!is_daemon_dependency(
            "/8f2c1d-wings",
            "ghcr.io/pterodactyl/yolks:java_17"
        ));
        assert!(!is_daemon_dependency("/my-serverosd-notes", "nginx:1.27"));
    }

    #[test]
    fn mounts_split_into_volumes_and_host_folders() {
        let (volumes, binds) = parse_mounts(
            "volume pgdata\nbind /var/lib/pterodactyl/volumes/8f2c\nvolume 3a9e0c\ntmpfs \n",
        );

        assert_eq!(volumes, vec!["pgdata", "3a9e0c"]);
        assert_eq!(binds, vec!["/var/lib/pterodactyl/volumes/8f2c"]);
    }

    #[test]
    fn sanitise_matches_the_deployer() {
        assert_eq!(sanitise("my app.v2"), "my-app-v2");
        assert_eq!(sanitise("cache_1"), "cache_1");
    }
}
