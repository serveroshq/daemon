use daemon_core::redact::redact;
use daemon_protocol::{JobState, JobUpdate};
use daemon_state::State;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

const LOG_KEEP_BYTES: usize = 256 * 1024;

/// How long a log update waits for room when the link to the panel is
/// behind, before its lines are held for the next update instead.
#[cfg(not(test))]
const LOG_SEND_WAIT: Duration = Duration::from_secs(2);
#[cfg(test)]
const LOG_SEND_WAIT: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub struct Progress {
    job_id: Uuid,
    state: Arc<State>,
    updates: mpsc::Sender<JobUpdate>,
    known_secrets: Arc<Vec<String>>,
    /// Lines that didn't fit in the channel yet: they go out with the
    /// next update, so the panel's copy of the log has every line.
    held: Arc<Mutex<Vec<String>>>,
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
            held: Arc::default(),
        }
    }

    pub fn job_id(&self) -> Uuid {
        self.job_id
    }

    pub async fn phase(&self, phase: &str, percent: Option<u8>) {
        let _ = self.state.set_job_phase(self.job_id, phase);
        self.send(JobUpdate {
            job_id: self.job_id,
            state: JobState::Running,
            phase: Some(phase.into()),
            progress: percent,
            log: self.take_held(),
            result: None,
            error: None,
        })
        .await;
    }

    pub async fn log(&self, lines: impl IntoIterator<Item = String>) {
        let clean: Vec<String> = lines.into_iter().map(|l| self.scrub(&l)).collect();

        if clean.is_empty() {
            return;
        }

        let _ = self
            .state
            .append_job_log(self.job_id, &clean, LOG_KEEP_BYTES);
        let mut lines = self.take_held();
        lines.extend(clean);
        self.send(JobUpdate {
            job_id: self.job_id,
            state: JobState::Running,
            phase: None,
            progress: None,
            log: lines,
            result: None,
            error: None,
        })
        .await;
    }

    /// Sends the lines still held, waiting for room. The runner calls it
    /// before the job's last update, so they arrive before it.
    pub async fn flush(&self) {
        let lines = self.take_held();
        if lines.is_empty() {
            return;
        }
        let _ = self
            .updates
            .send(JobUpdate {
                job_id: self.job_id,
                state: JobState::Running,
                phase: None,
                progress: None,
                log: lines,
                result: None,
                error: None,
            })
            .await;
    }

    fn take_held(&self) -> Vec<String> {
        std::mem::take(&mut *self.held.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Lines that didn't get through are kept for the next update, up to
    /// what state.db keeps of a log; past that the oldest go, as there.
    fn hold(&self, mut lines: Vec<String>) {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        // These were taken first, so anything held since is newer.
        lines.append(&mut held);
        let mut bytes: usize = lines.iter().map(|l| l.len() + 1).sum();
        let mut oldest = 0;
        while bytes > LOG_KEEP_BYTES && oldest < lines.len() {
            bytes -= lines[oldest].len() + 1;
            oldest += 1;
        }
        lines.drain(..oldest);
        *held = lines;
    }

    pub async fn line(&self, line: impl Into<String>) {
        self.log([line.into()]).await;
    }

    /// A line with secrets taken out: the usual patterns, and the values this
    /// job was told are secret.
    pub fn scrub(&self, line: &str) -> String {
        let known: Vec<&str> = self.known_secrets.iter().map(String::as_str).collect();
        daemon_core::redact::redact_known(&redact(line), &known)
    }

    /// A live update. One with log lines waits a moment for room and is
    /// held for the next one if there still isn't any; one without is only
    /// progress, and the next shows newer progress anyway.
    pub(crate) async fn send(&self, update: JobUpdate) {
        if update.log.is_empty() {
            let _ = self.updates.try_send(update);
            return;
        }
        match self.updates.send_timeout(update, LOG_SEND_WAIT).await {
            Ok(()) => {}
            Err(mpsc::error::SendTimeoutError::Timeout(update)) => self.hold(update.log),
            Err(mpsc::error::SendTimeoutError::Closed(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lines_that_do_not_fit_go_out_with_the_next_update() {
        let state = Arc::new(State::in_memory().unwrap());
        let id = Uuid::new_v4();
        state.record_job(id, "test", "test", "{}").unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let progress = Progress::new(id, Arc::clone(&state), tx, vec![]);

        progress.line("one").await;
        // The channel is full: this waits, then is held.
        progress.line("two").await;
        progress.line("three").await;
        // Progress alone is dropped while it's full, as before.
        progress.phase("build", Some(40)).await;

        assert_eq!(rx.recv().await.unwrap().log, ["one"]);
        progress.line("four").await;
        assert_eq!(rx.recv().await.unwrap().log, ["two", "three", "four"]);

        // Held lines at the end are flushed before the job's last update.
        progress.line("five").await;
        progress.line("six").await;
        assert_eq!(rx.recv().await.unwrap().log, ["five"]);
        progress.flush().await;
        assert_eq!(rx.recv().await.unwrap().log, ["six"]);
        progress.flush().await;
        assert!(rx.try_recv().is_err());

        // state.db has every line either way.
        let log = state.job(id).unwrap().unwrap().log;
        assert_eq!(log, "one\ntwo\nthree\nfour\nfive\nsix\n");
    }

    #[test]
    fn what_is_held_is_capped_like_the_stored_log() {
        let state = Arc::new(State::in_memory().unwrap());
        let (tx, _rx) = mpsc::channel(1);
        let progress = Progress::new(Uuid::new_v4(), state, tx, vec![]);
        let line = "x".repeat(1023);
        for _ in 0..300 {
            progress.hold(vec![line.clone()]);
        }
        let held = progress.take_held();
        assert_eq!(held.len(), LOG_KEEP_BYTES / 1024);
    }
}
