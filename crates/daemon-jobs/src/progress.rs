//! The handle a handler reports through. Everything it says is redacted,
//! stored in the ledger, and forwarded to the panel as a job update.

use daemon_core::redact::redact;
use daemon_protocol::{JobState, JobUpdate};
use daemon_state::State;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// How much log a job keeps in the ledger.
const LOG_KEEP_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct Progress {
    job_id: Uuid,
    state: Arc<State>,
    updates: mpsc::Sender<JobUpdate>,
    known_secrets: Arc<Vec<String>>,
}

impl Progress {
    pub fn new(
        job_id: Uuid,
        state: Arc<State>,
        updates: mpsc::Sender<JobUpdate>,
        known_secrets: Vec<String>,
    ) -> Self {
        Self {
            job_id,
            state,
            updates,
            known_secrets: Arc::new(known_secrets),
        }
    }

    pub fn job_id(&self) -> Uuid {
        self.job_id
    }

    /// Announce the phase the job is in (`fetch`, `build`, `health`...).
    pub async fn phase(&self, phase: &str, percent: Option<u8>) {
        let _ = self.state.set_job_phase(self.job_id, phase);
        self.send(JobUpdate {
            job_id: self.job_id,
            state: JobState::Running,
            phase: Some(phase.into()),
            progress: percent,
            log: vec![],
            result: None,
            error: None,
        })
        .await;
    }

    /// Log lines, batched. Redacted at write time.
    pub async fn log(&self, lines: impl IntoIterator<Item = String>) {
        let clean: Vec<String> = lines.into_iter().map(|l| self.scrub(&l)).collect();

        if clean.is_empty() {
            return;
        }

        let _ = self
            .state
            .append_job_log(self.job_id, &clean, LOG_KEEP_BYTES);
        self.send(JobUpdate {
            job_id: self.job_id,
            state: JobState::Running,
            phase: None,
            progress: None,
            log: clean,
            result: None,
            error: None,
        })
        .await;
    }

    pub async fn line(&self, line: impl Into<String>) {
        self.log([line.into()]).await;
    }

    pub(crate) fn scrub(&self, line: &str) -> String {
        let known: Vec<&str> = self.known_secrets.iter().map(String::as_str).collect();
        daemon_core::redact::redact_known(&redact(line), &known)
    }

    pub(crate) async fn send(&self, update: JobUpdate) {
        // A full channel means the panel is far behind; dropping a progress
        // frame is better than stalling the job. Terminal updates go through
        // the runner, which always waits.
        let _ = self.updates.try_send(update);
    }
}
