//! Every job type, wired to its subsystem through the broker. This is the
//! one place a command from the panel becomes an action on the machine,
//! and every branch goes: authorise → do → report.

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

fn managed(app: &App, key: &str) -> Result<ManagedService, Failure> {
    Registry::new(&app.state)
        .get(key)
        .map_err(|e| Failure::new("registry", e.to_string()))?
        .ok_or_else(|| {
            Failure::new("service", format!("{key} is not managed by ServerOS"))
                .with_next_step("Adopt it from the machine's Services tab first.")
        })
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
            let managed = managed(&app, &service)?;
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
            let result = lifecycle(&managed, Some(action), None).await;
            grant.finish(&result.as_ref().map(|_| ()), None);
            result
        }

        Job::ServiceExec {
            service,
            command,
            timeout_secs,
        } => {
            let managed = managed(&app, &service)?;
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
        } => {
            let managed = managed(&app, &service)?;
            let grant = authorize(Operation::Service(ServiceOp::Remove {
                service: managed.key.clone(),
            }))?;
            let result = super::service_ops::remove(&app, &ctx, &managed, delete_data).await;
            grant.finish(
                &result.as_ref().map(|_| ()),
                delete_data.then_some("data deleted"),
            );
            result
        }

        Job::ServiceLogs { service, lines } => {
            let managed = managed(&app, &service)?;
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

            Ok(serde_json::to_value(result).unwrap_or(Value::Null))
        }

        Job::Rollback { service, release } => {
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
            Ok(serde_json::to_value(result?).unwrap_or(Value::Null))
        }

        Job::Snapshots { service } => {
            let managed = managed(&app, &service)?;
            Ok(json!({"snapshots": app.snapshotter.list(&managed.name)}))
        }

        Job::Backup { service, reason } => {
            let managed = managed(&app, &service)?;
            let strategy = daemon_backup::Strategy::for_service(&managed).ok_or_else(|| {
                Failure::new(
                    "backup",
                    format!("ServerOS does not know how to snapshot {}", managed.name),
                )
                .with_next_step("Set a data directory for the service, or back it up by files.")
            })?;
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

        Job::Restore { service, snapshot } => {
            let managed = managed(&app, &service)?;
            let strategy = daemon_backup::Strategy::for_service(&managed).ok_or_else(|| {
                Failure::new(
                    "restore",
                    format!("ServerOS does not know how to restore {}", managed.name),
                )
            })?;
            let grant = authorize(Operation::Data(DataOp::Restore {
                service: managed.name.clone(),
                snapshot: snapshot.clone(),
            }))?;
            let mut cancel = ctx.cancel.clone();
            let result = match &managed.run_by {
                RunBy::Systemd { .. } => {
                    app.snapshotter
                        .restore(
                            &managed,
                            &strategy,
                            &snapshot,
                            &SystemdAdapter::default(),
                            &mut cancel,
                            &ctx.progress,
                        )
                        .await
                }
                _ => {
                    app.snapshotter
                        .restore(
                            &managed,
                            &strategy,
                            &snapshot,
                            &DockerAdapter::default(),
                            &mut cancel,
                            &ctx.progress,
                        )
                        .await
                }
            };
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
