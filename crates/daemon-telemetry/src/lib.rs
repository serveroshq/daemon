//! What the machine is doing, sampled every 10 seconds.
//!
//! The readers are pure functions over the text procfs gives us, so they
//! are tested against fixtures on any platform; only [`platform`] touches
//! the real files, and only on Linux. Samples go into the ring buffer in
//! `state.db`, are aggregated to one-minute points for transmission, and
//! feed [`signals`], which turns trends into events.
//!
//! Telemetry never collects application data, database contents, file
//! contents, environment values, process memory, or network payloads.
//! There is no code path here that could: the readers only open the
//! `/proc` and `/sys` files named in [`platform`].

pub mod aggregate;
pub mod collector;
pub mod facts;
pub mod platform;
pub mod procfs;
pub mod signals;

pub use collector::Collector;
pub use facts::gather_facts;
pub use signals::{SignalState, Signals};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("telemetry is only available on Linux")]
    Unsupported,
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("{path} was not in the expected format")]
    Parse { path: String },
}
