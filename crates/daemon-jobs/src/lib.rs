//! Jobs are durable. A command from the panel is written to `state.db`
//! before it runs, re-delivery of the same id answers from the ledger,
//! every job has a deadline, and its outcome names the phase that failed
//! with the real output.
//!
//! This crate owns the mechanics; what each job type does lives with the
//! subsystem that knows how (services, files, deploy, backup) and is wired
//! in through [`Handler`] by the daemon binary. Job bodies run on their
//! own task, and the daemon's heavy lifting is always an external process
//! with a kill-on-timeout, so a wedged build cannot take the control loop
//! with it.

pub mod child;
pub mod progress;
pub mod runner;

pub use child::{run_child, ChildOutcome};
pub use progress::Progress;
pub use runner::{Handler, HandlerFuture, JobContext, Runner};

use daemon_protocol::JobError;
use thiserror::Error;

/// The error a handler returns: which phase, what happened, what next.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{phase}: {message}")]
pub struct Failure {
    pub phase: String,
    pub message: String,
    pub output_tail: Vec<String>,
    pub next_step: Option<String>,
}

impl Failure {
    pub fn new(phase: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            phase: phase.into(),
            message: message.into(),
            output_tail: Vec::new(),
            next_step: None,
        }
    }

    pub fn with_output(mut self, tail: Vec<String>) -> Self {
        self.output_tail = tail;
        self
    }

    pub fn with_next_step(mut self, step: impl Into<String>) -> Self {
        self.next_step = Some(step.into());
        self
    }

    pub fn into_protocol(self) -> JobError {
        JobError {
            phase: self.phase,
            message: self.message,
            output_tail: self.output_tail,
            next_step: self.next_step,
        }
    }
}
