use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use daemon_protocol::{Command, Job, JobState, JobUpdate, PanelMode};
use daemon_state::{JobStatus, State};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};
use uuid::Uuid;

use crate::progress::Progress;
use crate::Failure;

pub struct JobContext {
    pub id: Uuid,
    pub command: Command,
    pub progress: Progress,
    pub cancel: watch::Receiver<bool>,
    pub timeout: Duration,
}

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<serde_json::Value, Failure>> + Send>>;

pub trait Handler: Send + Sync + 'static {
    fn handle(&self, ctx: JobContext) -> HandlerFuture;

    fn known_secrets(&self, _job: &Job) -> Vec<String> {
        Vec::new()
    }
}

pub struct Runner {
    state: Arc<State>,
    handler: Arc<dyn Handler>,
    updates: mpsc::Sender<JobUpdate>,
    default_timeout: Duration,
    running: Arc<Mutex<HashMap<Uuid, watch::Sender<bool>>>>,
    mode: Arc<Mutex<PanelMode>>,
}

impl Runner {
    pub fn new(
        state: Arc<State>,
        handler: Arc<dyn Handler>,
        updates: mpsc::Sender<JobUpdate>,
        default_timeout: Duration,
    ) -> Self {
        Self {
            state,
            handler,
            updates,
            default_timeout,
            running: Arc::default(),
            mode: Arc::new(Mutex::new(PanelMode::Managed)),
        }
    }

    pub fn set_mode(&self, mode: PanelMode) {
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = mode;
    }

    pub fn running_count(&self) -> usize {
        self.running.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub async fn submit(&self, id: Uuid, command: Command) {
        let payload = serde_json::to_string(&command.job).unwrap_or_default();
        let actor = format!("{:?} {}", command.actor.kind, command.actor.name).to_lowercase();
        let kind = job_kind(&command.job);

        let fresh = match self.state.record_job(id, &actor, kind, &payload) {
            Ok(fresh) => fresh,
            Err(e) => {
                warn!(error = %e, "could not record job; refusing rather than running unrecorded");
                self.terminal(
                    id,
                    JobState::Refused,
                    None,
                    Some(Failure::new(
                        "ledger",
                        format!("state.db is not writable: {e}"),
                    )),
                )
                .await;
                return;
            }
        };

        if !fresh {
            self.replay(id).await;
            return;
        }

        let _ = self
            .updates
            .send(JobUpdate {
                job_id: id,
                state: JobState::Accepted,
                phase: None,
                progress: None,
                log: vec![],
                result: None,
                error: None,
            })
            .await;

        let read_only = matches!(
            *self.mode.lock().unwrap_or_else(|p| p.into_inner()),
            PanelMode::ReadOnly
        );

        if read_only && mutates(&command.job) {
            self.terminal(
                id,
                JobState::Refused,
                None,
                Some(
                    Failure::new("policy", "this machine is in read-only mode")
                        .with_next_step("Turn off read-only mode for this machine in the panel."),
                ),
            )
            .await;
            return;
        }

        let timeout = command
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.default_timeout);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        self.running
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, cancel_tx);

        let progress = Progress::new(
            id,
            Arc::clone(&self.state),
            self.updates.clone(),
            self.handler.known_secrets(&command.job),
        );
        let ctx = JobContext {
            id,
            command,
            progress,
            cancel: cancel_rx,
            timeout,
        };
        let handler = Arc::clone(&self.handler);
        let state = Arc::clone(&self.state);
        let updates = self.updates.clone();
        let running = Arc::clone(&self.running);

        let _ = state.start_job(id);
        info!(job = %id, kind, "job started");

        tokio::spawn(async move {
            let outcome = tokio::time::timeout(timeout, handler.handle(ctx)).await;
            running
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);

            let (status, result, error) = match outcome {
                Ok(Ok(value)) => (JobState::Succeeded, Some(value), None),
                Ok(Err(failure)) if failure.phase == "cancelled" => (JobState::Cancelled, None, Some(failure)),
                Ok(Err(failure)) => (JobState::Failed, None, Some(failure)),
                Err(_) => (JobState::TimedOut, None, Some(Failure::new("timeout", format!("gave up after {timeout:?}")).with_next_step("Retry; if it keeps timing out, raise limits.job_timeout_secs in daemon.toml."))),
            };

            finish(&state, &updates, id, status, result, error).await;
        });
    }

    pub fn cancel(&self, id: Uuid) -> bool {
        match self
            .running
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
        {
            Some(tx) => tx.send(true).is_ok(),
            None => false,
        }
    }

    async fn replay(&self, id: Uuid) {
        let Ok(Some(record)) = self.state.job(id) else {
            return;
        };

        let (state, result, error) = match record.status {
            JobStatus::Accepted | JobStatus::Running => (JobState::Running, None, None),
            JobStatus::Succeeded => (
                JobState::Succeeded,
                record
                    .result
                    .as_deref()
                    .and_then(|r| serde_json::from_str(r).ok()),
                None,
            ),
            JobStatus::Failed => (
                JobState::Failed,
                None,
                record
                    .error
                    .as_deref()
                    .and_then(|e| serde_json::from_str(e).ok()),
            ),
            JobStatus::TimedOut => (
                JobState::TimedOut,
                None,
                record
                    .error
                    .as_deref()
                    .and_then(|e| serde_json::from_str(e).ok()),
            ),
            JobStatus::Refused => (
                JobState::Refused,
                None,
                record
                    .error
                    .as_deref()
                    .and_then(|e| serde_json::from_str(e).ok()),
            ),
            JobStatus::Cancelled => (JobState::Cancelled, None, None),
        };

        info!(job = %id, ?state, "re-delivered job answered from the ledger");
        let _ = self
            .updates
            .send(JobUpdate {
                job_id: id,
                state,
                phase: record.phase,
                progress: None,
                log: vec![],
                result,
                error,
            })
            .await;
    }

    async fn terminal(
        &self,
        id: Uuid,
        status: JobState,
        result: Option<serde_json::Value>,
        error: Option<Failure>,
    ) {
        finish(&self.state, &self.updates, id, status, result, error).await;
    }

    pub async fn close_unfinished(&self, reason: &str) -> usize {
        let Ok(unfinished) = self.state.unfinished_jobs() else {
            return 0;
        };
        let count = unfinished.len();

        for record in unfinished {
            let failure = Failure::new(
                "interrupted",
                format!("the daemon {reason} while this job was {:?}", record.status)
                    .to_lowercase(),
            )
            .with_next_step("Check the service's state, then retry the job.");
            finish(
                &self.state,
                &self.updates,
                record.id,
                JobState::Failed,
                None,
                Some(failure),
            )
            .await;
        }

        count
    }
}

async fn finish(
    state: &State,
    updates: &mpsc::Sender<JobUpdate>,
    id: Uuid,
    status: JobState,
    result: Option<serde_json::Value>,
    error: Option<Failure>,
) {
    let ledger_status = match status {
        JobState::Succeeded => JobStatus::Succeeded,
        JobState::TimedOut => JobStatus::TimedOut,
        JobState::Refused => JobStatus::Refused,
        JobState::Cancelled => JobStatus::Cancelled,
        _ => JobStatus::Failed,
    };
    let error_json = error
        .as_ref()
        .map(|e| serde_json::to_string(&e.clone().into_protocol()).unwrap_or_default());
    let result_json = result.as_ref().map(|r| r.to_string());

    let _ = state.finish_job(
        id,
        ledger_status,
        result_json.as_deref(),
        error_json.as_deref(),
    );

    match &error {
        Some(e) => info!(job = %id, ?status, phase = %e.phase, "job finished: {}", e.message),
        None => info!(job = %id, ?status, "job finished"),
    }

    let _ = updates
        .send(JobUpdate {
            job_id: id,
            state: status,
            phase: error.as_ref().map(|e| e.phase.clone()),
            progress: None,
            log: vec![],
            result,
            error: error.map(Failure::into_protocol),
        })
        .await;
}

pub fn job_kind(job: &Job) -> &'static str {
    match job {
        Job::Discover => "discover",
        Job::Facts => "facts",
        Job::ServiceAction { .. } => "service_action",
        Job::ServiceLogs { .. } => "service_logs",
        Job::ReadFile { .. } => "read_file",
        Job::WriteFile { .. } => "write_file",
        Job::ListDir { .. } => "list_dir",
        Job::DeleteFile { .. } => "delete_file",
        Job::Chmod { .. } => "chmod",
        Job::Chown { .. } => "chown",
        Job::Deploy(_) => "deploy",
        Job::Rollback { .. } => "rollback",
        Job::Backup { .. } => "backup",
        Job::BackupTo { .. } => "backup_to",
        Job::BackupReceiver { .. } => "backup_receiver",
        Job::Restore { .. } => "restore",
        Job::PackageUpdates { .. } => "package_updates",
        Job::PackageInstall { .. } => "package_install",
        Job::Reboot => "reboot",
        Job::FirewallRule { .. } => "firewall_rule",
        Job::SshKey { .. } => "ssh_key",
        Job::Adopt { .. } => "adopt",
        Job::Unadopt { .. } => "unadopt",
        Job::ServiceExec { .. } => "service_exec",
        Job::ServiceRemove { .. } => "service_remove",
        Job::ServiceRepair { .. } => "service_repair",
        Job::OpenTerminal { .. } => "open_terminal",
        Job::TailLogs { .. } => "tail_logs",
        Job::DeployKey { .. } => "deploy_key",
        Job::Snapshots { .. } => "snapshots",
    }
}

pub fn mutates(job: &Job) -> bool {
    !matches!(
        job,
        Job::Discover
            | Job::Facts
            | Job::ServiceLogs { .. }
            | Job::ReadFile { .. }
            | Job::ListDir { .. }
            | Job::TailLogs { .. }
            | Job::PackageUpdates { apply: false, .. }
            | Job::Snapshots { .. }
    )
}

#[cfg(test)]
mod tests {
    use daemon_protocol::{Actor, ActorKind};

    use super::*;

    struct EchoHandler;

    impl Handler for EchoHandler {
        fn handle(&self, ctx: JobContext) -> HandlerFuture {
            Box::pin(async move {
                match ctx.command.job {
                    Job::Discover => {
                        ctx.progress.phase("scanning", Some(50)).await;
                        Ok(serde_json::json!({"services": 2}))
                    }
                    Job::Facts => {
                        Err(Failure::new("facts", "procfs missing")
                            .with_output(vec!["boom".into()]))
                    }
                    Job::Reboot => {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        Ok(serde_json::Value::Null)
                    }
                    _ => Ok(serde_json::Value::Null),
                }
            })
        }
    }

    fn command(job: Job) -> Command {
        Command {
            actor: Actor {
                kind: ActorKind::User,
                name: "dylan@serveros.com".into(),
                id: None,
            },
            confirmed: true,
            timeout_secs: None,
            job,
        }
    }

    async fn collect_until_terminal(rx: &mut mpsc::Receiver<JobUpdate>) -> Vec<JobUpdate> {
        let mut updates = Vec::new();
        while let Some(update) = rx.recv().await {
            let terminal = update.state.is_terminal();
            updates.push(update);
            if terminal {
                break;
            }
        }
        updates
    }

    #[tokio::test]
    async fn runs_a_job_and_replays_it_on_redelivery() {
        let state = Arc::new(State::in_memory().unwrap());
        let (tx, mut rx) = mpsc::channel(64);
        let runner = Runner::new(
            Arc::clone(&state),
            Arc::new(EchoHandler),
            tx,
            Duration::from_secs(5),
        );
        let id = Uuid::new_v4();

        runner.submit(id, command(Job::Discover)).await;
        let updates = collect_until_terminal(&mut rx).await;

        assert_eq!(updates[0].state, JobState::Accepted);
        assert!(updates
            .iter()
            .any(|u| u.phase.as_deref() == Some("scanning")));
        assert_eq!(updates.last().unwrap().state, JobState::Succeeded);
        assert_eq!(
            updates.last().unwrap().result,
            Some(serde_json::json!({"services": 2}))
        );

        runner.submit(id, command(Job::Discover)).await;
        let replay = rx.recv().await.unwrap();

        assert_eq!(replay.state, JobState::Succeeded);
        assert_eq!(replay.result, Some(serde_json::json!({"services": 2})));
        assert_eq!(state.job(id).unwrap().unwrap().status, JobStatus::Succeeded);
    }

    #[tokio::test]
    async fn failures_name_the_phase_and_carry_output() {
        let state = Arc::new(State::in_memory().unwrap());
        let (tx, mut rx) = mpsc::channel(64);
        let runner = Runner::new(state, Arc::new(EchoHandler), tx, Duration::from_secs(5));

        runner.submit(Uuid::new_v4(), command(Job::Facts)).await;
        let updates = collect_until_terminal(&mut rx).await;
        let last = updates.last().unwrap();

        assert_eq!(last.state, JobState::Failed);
        let error = last.error.as_ref().unwrap();
        assert_eq!(error.phase, "facts");
        assert_eq!(error.output_tail, vec!["boom"]);
    }

    #[tokio::test]
    async fn slow_jobs_time_out_and_read_only_refuses_mutations() {
        let state = Arc::new(State::in_memory().unwrap());
        let (tx, mut rx) = mpsc::channel(64);
        let runner = Runner::new(state, Arc::new(EchoHandler), tx, Duration::from_millis(200));

        runner.submit(Uuid::new_v4(), command(Job::Reboot)).await;
        assert_eq!(
            collect_until_terminal(&mut rx).await.last().unwrap().state,
            JobState::TimedOut
        );

        runner.set_mode(PanelMode::ReadOnly);
        runner.submit(Uuid::new_v4(), command(Job::Reboot)).await;
        let updates = collect_until_terminal(&mut rx).await;
        assert_eq!(updates.last().unwrap().state, JobState::Refused);

        runner.submit(Uuid::new_v4(), command(Job::Discover)).await;
        assert_eq!(
            collect_until_terminal(&mut rx).await.last().unwrap().state,
            JobState::Succeeded
        );
    }

    #[tokio::test]
    async fn unfinished_jobs_are_closed_on_restart() {
        let state = Arc::new(State::in_memory().unwrap());
        let id = Uuid::new_v4();
        state.record_job(id, "user", "deploy", "{}").unwrap();
        state.start_job(id).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let runner = Runner::new(
            Arc::clone(&state),
            Arc::new(EchoHandler),
            tx,
            Duration::from_secs(1),
        );

        assert_eq!(runner.close_unfinished("restarted").await, 1);

        let update = rx.recv().await.unwrap();
        assert_eq!(update.state, JobState::Failed);
        assert!(update.error.unwrap().message.contains("restarted"));
        assert_eq!(state.job(id).unwrap().unwrap().status, JobStatus::Failed);
    }
}
