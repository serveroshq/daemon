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
