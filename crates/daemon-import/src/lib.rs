pub mod enrich;
pub mod history;
pub mod importer;

pub use importer::{ImportOutcome, Importer};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("{0} was not found in the last scan; rescan and try again")]
    UnknownService(String),
    #[error("{0} is already managed by ServerOS")]
    AlreadyManaged(String),
    #[error("{0} is not managed by ServerOS")]
    NotManaged(String),
    #[error("{0}")]
    Services(#[from] daemon_services::ServiceError),
    #[error("{0}")]
    State(#[from] daemon_state::StateError),
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ImportError>;
