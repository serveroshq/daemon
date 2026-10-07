use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use daemon_audit::Actor;
use daemon_capability::{DataOp, DeployOp, MachineOp, Operation, Request, ServiceOp};
use daemon_jobs::{Failure, Handler, HandlerFuture, JobContext};
use daemon_protocol::driver::Outbound;
use daemon_protocol::{ActorKind, Job, ServiceAction};
use daemon_services::docker::DockerAdapter;
use daemon_services::systemd::SystemdAdapter;
use daemon_services::{Lifecycle, ManagedService, Registry, RunBy};
use daemon_streams::logs::Source;
use daemon_streams::LogTail;
use serde_json::{json, Value};

use super::app::App;
use super::machine;

pub struct JobHandler {
    pub app: Arc<App>,
}

impl Handler for JobHandler {
    fn handle(&self, ctx: JobContext) -> HandlerFuture {
        let app = Arc::clone(&self.app);
        Box::pin(async move { handle(app, ctx).await })
    }

    fn known_secrets(&self, job: &Job) -> Vec<String> {
        match job {
            Job::Deploy(spec) => spec.env.values().cloned().collect(),
            Job::BackupTo { destination, .. } => super::backup_ops::secrets(destination),
            _ => Vec::new(),
        }
    }
}

fn actor_of(ctx: &JobContext) -> Actor {
    let a = &ctx.command.actor;
    match a.kind {
        ActorKind::User => Actor::user(&a.name),
        ActorKind::Automation | ActorKind::Panel => Actor::automation(&a.name),
        ActorKind::Scheduler => Actor::scheduler(),
        ActorKind::Local => Actor::local(&a.name),
        ActorKind::Daemon => Actor::daemon(),
    }
}

fn denied(d: daemon_capability::Denied) -> Failure {
    Failure::new("policy", d.explanation).with_next_step(
        "This action is outside what ServerOS may do on this machine; see the Trust page.",
    )
}

async fn managed(app: &App, key: &str) -> Result<ManagedService, Failure> {
    let registry = Registry::new(&app.state);
    let lookup = || {
        registry
            .get(key)
            .map_err(|e| Failure::new("registry", e.to_string()))
    };

    if let Some(service) = lookup()? {
        return Ok(service);
    }

    if key.starts_with("docker:") && super::service_ops::register_earlier_deploys(app).await > 0 {
        if let Some(service) = lookup()? {
            return Ok(service);
        }
    }

    Err(
        Failure::new("service", format!("{key} is not managed by ServerOS"))
            .with_next_step("Adopt it from the machine's Services tab first."),
    )
}

fn explain_wings_mount(failure: Failure) -> Failure {
    if !failure
        .message
        .contains("bind source path does not exist: /run/wings/")
    {
        return failure;
    }

    Failure::new(
        "service",
        "This container was set up by Pterodactyl and needs a file Wings used to create, so Docker won't start it.",
    )
    .with_next_step("Repair it from its service page: ServerOS recreates it without that file and keeps its data.")
}

async fn lifecycle(
    service: &ManagedService,
    action: Option<ServiceAction>,
    logs: Option<u32>,
) -> Result<Value, Failure> {
    let map = |e: daemon_services::ServiceError| Failure::new("service", e.to_string());

    match &service.run_by {
        RunBy::Systemd { unit } => {
            let adapter = SystemdAdapter::default();
            if let Some(a) = action {
                adapter.act(unit, a).await.map_err(map)?;
            }
            if let Some(n) = logs {
                return Ok(json!({"lines": adapter.logs(unit, n).await.map_err(map)?}));
            }
            Ok(json!({"status": adapter.status(unit).await.map_err(map)?}))
        }
        RunBy::Docker { container } | RunBy::Compose { container, .. } => {
            let adapter = DockerAdapter::default();
            if let Some(a) = action {
                adapter.act(container, a).await.map_err(map)?;
            }
            if let Some(n) = logs {
                return Ok(json!({"lines": adapter.logs(container, n).await.map_err(map)?}));
            }
            Ok(json!({"status": adapter.status(container).await.map_err(map)?}))
        }
        RunBy::Observed { manager } => Err(Failure::new(
            "service",
            format!(
                "{} is run by {manager}, which ServerOS can observe but not control",
                service.name
            ),
        )),
    }
}

/// Put a snapshot back, stopping and starting the service the way its
/// manager does where the strategy needs it.
async fn restore_one(
    app: &App,
    ctx: &JobContext,
    managed: &ManagedService,
    strategy: &daemon_backup::Strategy,
    snapshot: &str,
) -> Result<(String, daemon_backup::Manifest), Failure> {
    let mut cancel = ctx.cancel.clone();
    match &managed.run_by {
        RunBy::Systemd { .. } => {
            app.snapshotter
                .restore(
                    managed,
                    strategy,
                    snapshot,
                    &SystemdAdapter::default(),
                    &mut cancel,
                    &ctx.progress,
                )
                .await
        }
        _ => {
            app.snapshotter
                .restore(
                    managed,
                    strategy,
                    snapshot,
                    &DockerAdapter::default(),
                    &mut cancel,
                    &ctx.progress,
                )
                .await
        }
    }
}

/// What a deploy replaces: the live release's container, or every container
/// of a Compose app. Nothing on a first deploy.
fn deploy_targets(app: &App, spec: &daemon_protocol::DeploySpec) -> Vec<ManagedService> {
    let Some(current) = daemon_deploy::ReleaseLedger::new(&app.state).current(&spec.service) else {
        return Vec::new();
    };
    let project = format!("serveros-{}", daemon_deploy::git::sanitise(&spec.service));

    Registry::new(&app.state)
        .all()
        .unwrap_or_default()
        .into_iter()
        .filter(|m| match &m.run_by {
            RunBy::Compose { project: p, .. } => spec.compose_file.is_some() && p == &project,
            RunBy::Docker { container } => container == &current.container,
            _ => false,
        })
        .collect()
}

async fn handle(app: Arc<App>, ctx: JobContext) -> Result<Value, Failure> {
    let actor = actor_of(&ctx);
    let confirmed = ctx.command.confirmed;
    let authorize = |op: Operation| {
        app.broker
            .authorize(Request {
                actor: actor.clone(),
                operation: op,
                confirmed,
            })
            .map_err(denied)
    };
    let job = ctx.command.job.clone();

    match job {
        Job::Discover => {
            let grant = authorize(Operation::Machine(MachineOp::ListUnits))?;
            ctx.progress.phase("scanning", Some(10)).await;
            let result = app
                .importer
                .scan()
                .await
                .map_err(|e| Failure::new("discover", e.to_string()));
            grant.finish(&result.as_ref().map(|_| ()), None);
            let (report, events) = result?;
            let summary = json!({"services": report.services.len(), "unknown": report.unknown.len(), "complete": report.complete});
            for event in events {
                app.raise(event).await;
            }
            app.send(Outbound::Inventory(report)).await;
            Ok(summary)
        }

        Job::Facts => {
            let grant = authorize(Operation::Machine(MachineOp::ReadFacts))?;
            let facts = daemon_telemetry::gather_facts();
            *app.facts.write().unwrap_or_else(|p| p.into_inner()) = facts.clone();
            app.send(Outbound::Facts(facts.clone())).await;
            grant.finish::<String>(&Ok(()), None);
            Ok(serde_json::to_value(facts).unwrap_or(Value::Null))
        }

        Job::ServiceAction { service, action } => {
            let managed = managed(&app, &service).await?;
            let op = match action {
                ServiceAction::Start => ServiceOp::Start {
                    service: managed.name.clone(),
                },
                ServiceAction::Stop => ServiceOp::Stop {
                    service: managed.name.clone(),
                },
                ServiceAction::Restart => ServiceOp::Restart {
                    service: managed.name.clone(),
                },
                ServiceAction::Reload => ServiceOp::Reload {
                    service: managed.name.clone(),
                },
            };
            let grant = authorize(Operation::Service(op))?;
            let result = lifecycle(&managed, Some(action), None)
                .await
                .map_err(explain_wings_mount);
            grant.finish(&result.as_ref().map(|_| ()), None);
            result
        }

        Job::ServiceRepair { service } => {
            let managed = managed(&app, &service).await?;
            let container = super::service_ops::container_of(&managed)
                .ok_or_else(|| {
                    Failure::new(
                        "repair",
                        format!(
                            "{} isn't a container, so there's nothing to repair",
                            managed.name
                        ),
                    )
                })?
                .to_string();
            let grant = authorize(Operation::Service(ServiceOp::Repair {
                service: managed.key.clone(),
            }))?;
            ctx.progress
                .line(format!(
                    "recreating {} without the Wings mounts",
                    managed.name
                ))
                .await;
            let result = DockerAdapter::default()
                .repair_wings(&container)
                .await
                .map_err(|e| Failure::new("repair", e.to_string()));
            if let Ok(repaired) = &result {
                let short = &repaired.new_id[..repaired.new_id.len().min(12)];
                let _ = Registry::new(&app.state).rekey(
                    &managed.key,
                    &format!("docker:{short}"),
                    short,
                );
                app.sync_adopted();
                for dropped in &repaired.dropped {
                    ctx.progress.line(format!("dropped {dropped}")).await;
                }
                if repaired.old_kept {
                    ctx.progress
                        .line(format!(
                            "the old container is still there as {}-before-repair",
                            repaired.name
                        ))
                        .await;
                }
            }
            grant.finish(
                &result.as_ref().map(|_| ()),
                Some("restart: unless-stopped"),
            );
            let repaired = result?;
            let short = &repaired.new_id[..repaired.new_id.len().min(12)];
            Ok(json!({
                "service": format!("docker:{short}"),
                "previous": managed.key,
                "dropped": repaired.dropped,
                "old_kept": repaired.old_kept,
            }))
        }

        Job::ServiceExec {
            service,
            command,
            timeout_secs,
        } => {
            let managed = managed(&app, &service).await?;
            let container = super::service_ops::container_of(&managed)
                .ok_or_else(|| {
                    Failure::new(
                        "exec",
                        format!(
                            "{} isn't a container, so there's nowhere to run the command",
                            managed.name
                        ),
                    )
                })?
                .to_string();
            let grant = authorize(Operation::Service(ServiceOp::Exec {
                service: managed.key.clone(),
            }))?;
            let result = super::service_ops::exec(&ctx, &container, &command, timeout_secs).await;
            let summary: String = command.chars().take(80).collect();
            grant.finish(&result.as_ref().map(|_| ()), Some(&summary));
            result
        }

        Job::ServiceRemove {
            service,
            delete_data,
            delete_adopted_volumes,
        } => {
            let managed = match managed(&app, &service).await {
                Ok(managed) => managed,
                Err(_) if !super::service_ops::container_exists(&service).await => {
                    ctx.progress
                        .line(format!("{service} was already removed"))
                        .await;
                    return Ok(json!({ "removed": 0, "volumes_deleted": 0 }));
                }
                Err(failure) => return Err(failure),
            };
            let adopted = managed.origin == daemon_protocol::ServiceOrigin::Discovered;
            if adopted && delete_data && !delete_adopted_volumes {
                return Err(Failure::new(
                    "remove",
                    format!(
                        "{} was adopted, so deleting its data needs delete_adopted_volumes as well",
                        managed.name
                    ),
                )
                .with_next_step("Remove it and keep the data, or ask again with both flags."));
            }
            let grant = authorize(Operation::Service(ServiceOp::Remove {
                service: managed.key.clone(),
            }))?;
            let result = if adopted {
                super::service_ops::remove_adopted(&app, &ctx, &managed, delete_data).await
            } else {
                super::service_ops::remove(&app, &ctx, &managed, delete_data).await
            };
            app.sync_adopted();
            let note = match (adopted, delete_data) {
                (true, true) => Some("adopted; docker volumes deleted"),
                (true, false) => Some("adopted; data kept"),
                (false, true) => Some("data deleted"),
                (false, false) => None,
            };
            grant.finish(&result.as_ref().map(|_| ()), note);
            result
        }

        Job::ServiceLogs { service, lines } => {
            let managed = managed(&app, &service).await?;
            let grant = authorize(Operation::Service(ServiceOp::ReadLogs {
                service: managed.name.clone(),
            }))?;
            let result = lifecycle(&managed, None, Some(lines)).await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                Some(&format!("{lines} lines")),
            );
            result
        }

        Job::ListDir { path, .. } => {
            let path = PathBuf::from(path);
            let grant = authorize(Operation::Data(DataOp::Browse { path: path.clone() }))?;
            let result = app
                .files
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .list(&path)
                .map_err(|e| Failure::new("files", e.to_string()));
            grant.finish(&result.as_ref().map(|_| ()), None);
            Ok(json!({"entries": result?}))
        }

        Job::ReadFile { path, .. } => {
            let path = PathBuf::from(path);
            let grant = authorize(Operation::Data(DataOp::ReadFile { path: path.clone() }))?;
            let result = app
                .files
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .read(&path)
                .map_err(|e| Failure::new("files", e.to_string()));
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .map(|b| format!("{} bytes", b.len()))
                    .as_deref(),
            );
            let bytes = result?;
            Ok(
                json!({"size": bytes.len(), "content_b64": base64::engine::general_purpose::STANDARD.encode(&bytes)}),
            )
        }

        Job::WriteFile {
            path,
            content_b64,
            mode,
            ..
        } => {
            let path = PathBuf::from(path);
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(content_b64.trim())
                .map_err(|_| Failure::new("files", "content was not valid base64"))?;
            let grant = authorize(Operation::Data(DataOp::WriteFile { path: path.clone() }))?;
            let result = app
                .files
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .write(&path, &bytes, mode)
                .map_err(|e| Failure::new("files", e.to_string()));
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .and_then(|b| b.as_ref().map(|p| format!("backup at {}", p.display())))
                    .as_deref(),
            );
            Ok(json!({"backup": result?.map(|p| p.display().to_string()), "bytes": bytes.len()}))
        }

        Job::DeleteFile { path, .. } => {
            let path = PathBuf::from(path);
            let grant = authorize(Operation::Data(DataOp::DeleteFile { path: path.clone() }))?;
            let result = app
                .files
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .delete(&path)
                .map_err(|e| Failure::new("files", e.to_string()));
            grant.finish(&result, None);
            result.map(|_| Value::Null)
        }

        Job::Chmod { path, mode, .. } => {
            let path = PathBuf::from(path);
            let grant = authorize(Operation::Data(DataOp::Chmod { path: path.clone() }))?;
            let result = app
                .files
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .chmod(&path, mode)
                .map_err(|e| Failure::new("files", e.to_string()));
            grant.finish(&result, Some(&format!("{mode:o}")));
            result.map(|_| Value::Null)
        }

        Job::Chown {
            path, user, group, ..
        } => {
            let path = PathBuf::from(path);
            let grant = authorize(Operation::Data(DataOp::Chown { path: path.clone() }))?;
            let result = app
                .files
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .chown(&path, &user, group.as_deref())
                .map_err(|e| Failure::new("files", e.to_string()));
            grant.finish(
                &result,
                Some(&format!("{user}:{}", group.unwrap_or_default())),
            );
            result.map(|_| Value::Null)
        }

        Job::DeployKey { service } => {
            let grant = authorize(Operation::Deploy(DeployOp::FetchSource {
                service: service.clone(),
                workspace: app.paths.jobs_dir(),
            }))?;
            let result = app.deployer.deploy_key(&service, &ctx.progress).await;
            grant.finish(&result.as_ref().map(|_| ()), Some("deploy key"));
            Ok(json!({"public_key": result?}))
        }

        Job::Deploy(spec) => {
            let workspace = app.paths.jobs_dir().join(ctx.id.to_string());
            let grant = authorize(Operation::Deploy(DeployOp::Build {
                service: spec.service.clone(),
                workspace,
            }))?;
            // Snapshot what this deploy replaces, so it can be rolled back
            // with its data. If that fails, nothing is deployed.
            let mut snapshots = Vec::new();
            if spec.snapshot_before {
                for target in deploy_targets(&app, &spec) {
                    let strategy = match super::backup_ops::data_strategy(&target).await {
                        Ok(Some(strategy)) => strategy,
                        Ok(None) => continue,
                        Err(failure) => {
                            grant.finish(&Err(failure.clone()), None);
                            return Err(failure);
                        }
                    };
                    ctx.progress.phase("snapshot", Some(3)).await;
                    let snap = authorize(Operation::Data(DataOp::Snapshot {
                        service: target.name.clone(),
                    }))?;
                    let estimate = app
                        .snapshotter
                        .list(&target.name)
                        .last()
                        .map(|m| m.total_bytes)
                        .unwrap_or(256 * 1024 * 1024);
                    let mut cancel = ctx.cancel.clone();
                    let taken = app
                        .snapshotter
                        .take(
                            &target,
                            &strategy,
                            daemon_backup::PRE_DEPLOY,
                            estimate,
                            &mut cancel,
                            &ctx.progress,
                        )
                        .await;
                    snap.finish(
                        &taken.as_ref().map(|_| ()),
                        taken
                            .as_ref()
                            .ok()
                            .map(|m| format!("pre-deploy snapshot {}", m.id))
                            .as_deref(),
                    );
                    let manifest = match taken {
                        Ok(manifest) => manifest,
                        Err(failure) => {
                            let failure = failure.with_next_step(
                                "Nothing was deployed. Free some disk space, or deploy with the snapshot before deploying turned off.",
                            );
                            grant.finish(&Err(failure.clone()), None);
                            return Err(failure);
                        }
                    };
                    ctx.progress
                        .line(format!("snapshot {} of {} taken", manifest.id, target.name))
                        .await;
                    snapshots.push(json!({
                        "service": target.key,
                        "name": target.name,
                        "snapshot": manifest.id,
                        "bytes": manifest.total_bytes,
                    }));
                }
            }

            let result = app.deployer.deploy(&ctx, &spec).await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .map(|r| format!("commit {}", &r.commit[..7.min(r.commit.len())]))
                    .as_deref(),
            );
            let result = result?;

            app.broker.record_created_service(spec.service.clone());
            let registered =
                super::service_ops::register_deploy(&app, &spec, &result.container).await;
            ctx.progress
                .line(format!(
                    "{} container(s) now managed by ServerOS",
                    registered.len()
                ))
                .await;
            let _ = app.state.kv_set(
                &format!("deploy.{}.domains", spec.service),
                &serde_json::to_string(&spec.domains).unwrap_or_default(),
            );
            let manifest = app.paths.manifest_file();
            let _ = daemon_uninstall::Manifest::record(
                &manifest,
                daemon_uninstall::Artifact::Container {
                    name: result.container.clone(),
                },
            );
            if !spec.domains.is_empty() {
                let _ = daemon_uninstall::Manifest::record(
                    &manifest,
                    daemon_uninstall::Artifact::File {
                        path: app.deployer.proxy.site_file(&spec.service),
                    },
                );
                let _ = daemon_uninstall::Manifest::record(
                    &manifest,
                    daemon_uninstall::Artifact::LineInFile {
                        path: app.deployer.proxy.main_config.clone(),
                        line: "import /etc/caddy/serveros.d/*.caddy".into(),
                    },
                );
            }

            let mut value = serde_json::to_value(result).unwrap_or(Value::Null);
            if let Value::Object(fields) = &mut value {
                fields.insert("pre_deploy_snapshots".into(), Value::Array(snapshots));
            }
            Ok(value)
        }

        Job::Rollback {
            service,
            release,
            restore,
        } => {
            let grant = authorize(Operation::Deploy(DeployOp::Rollback {
                service: service.clone(),
            }))?;
            let domains: Vec<String> = app
                .state
                .kv_get(&format!("deploy.{service}.domains"))
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            let result = app
                .deployer
                .rollback(&ctx, &service, release.as_deref(), &domains)
                .await;
            grant.finish(&result.as_ref().map(|_| ()), None);
            let mut value = serde_json::to_value(result?).unwrap_or(Value::Null);

            // Then the data, from before the deploy that's been undone. Each
            // restore snapshots what's there first, so it can be undone too.
            let mut restored = Vec::new();
            for wanted in &restore {
                let managed = managed(&app, &wanted.service).await?;
                let strategy = super::backup_ops::strategy_for(&managed).await?;
                let grant = authorize(Operation::Data(DataOp::Restore {
                    service: managed.name.clone(),
                    snapshot: wanted.snapshot.clone(),
                }))?;
                let result = restore_one(&app, &ctx, &managed, &strategy, &wanted.snapshot).await;
                grant.finish(
                    &result.as_ref().map(|_| ()),
                    result
                        .as_ref()
                        .ok()
                        .map(|(safety, _)| format!("pre-restore snapshot {safety}"))
                        .as_deref(),
                );
                let (safety, manifest) = result.map_err(|f| {
                    f.with_next_step(
                        "The code is rolled back, but its data isn't. Restore the snapshot from the backups history.",
                    )
                })?;
                restored.push(json!({
                    "service": managed.key,
                    "restored": manifest.id,
                    "pre_restore_snapshot": safety,
                }));
            }
            if let Value::Object(fields) = &mut value {
                fields.insert("restored".into(), Value::Array(restored));
            }
            Ok(value)
        }

        Job::Snapshots { service } => {
            let managed = managed(&app, &service).await?;
            Ok(json!({"snapshots": app.snapshotter.list(&managed.name)}))
        }

        Job::Backup { service, reason } => {
            let managed = managed(&app, &service).await?;
            let strategy = super::backup_ops::strategy_for(&managed).await?;
            let grant = authorize(Operation::Data(DataOp::Snapshot {
                service: managed.name.clone(),
            }))?;
            let estimate = app
                .snapshotter
                .list(&managed.name)
                .last()
                .map(|m| m.total_bytes)
                .unwrap_or(256 * 1024 * 1024);
            let mut cancel = ctx.cancel.clone();
            let result = app
                .snapshotter
                .take(
                    &managed,
                    &strategy,
                    &reason,
                    estimate,
                    &mut cancel,
                    &ctx.progress,
                )
                .await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .map(|m| format!("{} bytes via {}", m.total_bytes, m.strategy))
                    .as_deref(),
            );
            Ok(serde_json::to_value(result?).unwrap_or(Value::Null))
        }

        Job::BackupTo {
            service,
            reason,
            prefix,
            destination,
        } => {
            let managed = managed(&app, &service).await?;
            let grant = authorize(Operation::Data(DataOp::Snapshot {
                service: managed.name.clone(),
            }))?;
            let result =
                super::backup_ops::backup_to(&app, &ctx, &managed, &reason, &prefix, &destination)
                    .await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .and_then(|v| v["location"].as_str())
                    .map(|l| format!("sent to {l}"))
                    .as_deref(),
            );
            result
        }

        Job::BackupReceiver { public_key } => {
            let grant = authorize(Operation::Machine(MachineOp::ManageSshKeys {
                user: super::backup_ops::RECEIVER_USER.into(),
            }))?;
            let result = super::backup_ops::receiver(&public_key).await;
            grant.finish(&result.as_ref().map(|_| ()), Some("backup receiver"));
            result
        }

        Job::Restore { service, snapshot } => {
            let managed = managed(&app, &service).await?;
            // Containers' data is in what they mount, which only inspecting
            // them now tells; the same way the backup found it.
            let strategy = super::backup_ops::strategy_for(&managed).await?;
            let grant = authorize(Operation::Data(DataOp::Restore {
                service: managed.name.clone(),
                snapshot: snapshot.clone(),
            }))?;
            let result = restore_one(&app, &ctx, &managed, &strategy, &snapshot).await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .map(|(safety, _)| format!("pre-restore snapshot {safety}"))
                    .as_deref(),
            );
            let (safety, restored) = result?;
            Ok(json!({"restored": restored.id, "pre_restore_snapshot": safety}))
        }

        Job::PackageUpdates {
            apply,
            security_only,
        } => {
            let grant = authorize(Operation::Machine(if apply {
                MachineOp::ApplyPackageUpdates { security_only }
            } else {
                MachineOp::QueryPackageUpdates
            }))?;
            let result = machine::package_updates(&ctx, apply, security_only).await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .map(|r| {
                        format!(
                            "{} upgradable, {} security",
                            r.upgradable.len(),
                            r.security.len()
                        )
                    })
                    .as_deref(),
            );
            Ok(serde_json::to_value(result?).unwrap_or(Value::Null))
        }

        Job::PackageInstall { packages } => {
            let grant = authorize(Operation::Machine(MachineOp::ApplyPackageUpdates {
                security_only: false,
            }))?;
            let result = machine::install_packages(&ctx, &packages).await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                Some(format!("{} packages", packages.len())).as_deref(),
            );
            Ok(serde_json::to_value(result?).unwrap_or(Value::Null))
        }

        Job::Reboot => {
            let grant = authorize(Operation::Machine(MachineOp::Reboot))?;
            machine::reboot_soon();
            grant.finish::<String>(&Ok(()), Some("in 5 seconds"));
            Ok(json!({"rebooting_in_secs": 5}))
        }

        Job::FirewallRule { action, rule } => {
            let grant = authorize(Operation::Machine(MachineOp::WriteFirewall {
                rule: format!("{action:?} {rule}").to_lowercase(),
            }))?;
            let backend = app.config.read().unwrap().integrations.firewall;
            let result = machine::firewall(&ctx, backend, action, &rule).await;
            grant.finish(&result.as_ref().map(|_| ()), None);
            Ok(json!({"status": result?}))
        }

        Job::SshKey {
            user,
            action,
            public_key,
        } => {
            let grant = authorize(Operation::Machine(MachineOp::ManageSshKeys {
                user: user.clone(),
            }))?;
            let result = machine::ssh_key(&user, action, &public_key);
            grant.finish(
                &result.as_ref().map(|_| ()),
                Some(&format!("{action:?}").to_lowercase()),
            );
            Ok(json!({"keys": result?}))
        }

        Job::Adopt { service, dry_run } => {
            if dry_run {
                return Ok(serde_json::to_value(
                    app.importer
                        .preview(&service)
                        .map_err(|e| Failure::new("adopt", e.to_string()))?,
                )
                .unwrap_or(Value::Null));
            }
            let grant = authorize(Operation::Service(ServiceOp::Adopt {
                service: service.clone(),
            }))?;
            let result = app
                .importer
                .adopt(&service, daemon_state::State::now())
                .map_err(|e| Failure::new("adopt", e.to_string()));
            grant.finish(
                &result.as_ref().map(|_| ()),
                Some("no restart, no config changes"),
            );
            let outcome = result?;
            app.sync_adopted();
            app.add_roots(&outcome.new_roots);
            Ok(serde_json::to_value(outcome).unwrap_or(Value::Null))
        }

        Job::Unadopt { service } => {
            let grant = authorize(Operation::Service(ServiceOp::Unadopt {
                service: service.clone(),
            }))?;
            let result = app
                .importer
                .unadopt(&service)
                .map_err(|e| Failure::new("unadopt", e.to_string()));
            app.sync_adopted();
            grant.finish(
                &result.as_ref().map(|_| ()),
                result
                    .as_ref()
                    .ok()
                    .map(|r| format!("{} ServerOS-added artifact(s) removed", r.len()))
                    .as_deref(),
            );
            Ok(json!({"removed": result?}))
        }

        Job::OpenTerminal { user, session } => {
            let grant = authorize(Operation::Data(DataOp::OpenTerminal { user: user.clone() }))?;
            let result = app
                .sessions
                .open(session, &user, &actor.name, app.stream_sender())
                .map_err(|e| Failure::new("terminal", e.to_string()));
            grant.finish(
                &result.as_ref().map(|_| ()),
                Some(&format!("session {session}")),
            );
            let opened = result?;
            Ok(json!({"session": session, "user": opened.user, "recording": opened.recording}))
        }

        Job::TailLogs { source, session } => {
            let parsed = Source::parse(&source).ok_or_else(|| {
                Failure::new(
                    "logs",
                    format!("{source:?} is not a log source (unit:, docker:, or file:)"),
                )
            })?;
            let op = match &parsed {
                Source::Unit(unit) => Operation::Machine(MachineOp::ReadJournal {
                    unit: Some(unit.clone()),
                }),
                Source::Container(c) => {
                    Operation::Service(ServiceOp::ReadLogs { service: c.clone() })
                }
                Source::File(path) => Operation::Machine(MachineOp::ReadNamedLog {
                    path: PathBuf::from(path),
                }),
            };
            let grant = authorize(op)?;
            let result = LogTail::start(session, &parsed, 200, app.stream_sender())
                .map_err(|e| Failure::new("logs", e.to_string()));
            grant.finish(
                &result.as_ref().map(|_| ()),
                Some(&format!("session {session}")),
            );
            app.tails
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(session, result?);
            Ok(json!({"session": session}))
        }
    }
}

#[allow(dead_code)]
fn _keep(_: &Path) {}
