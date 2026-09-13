//! Import: the product's differentiator, and its riskiest subsystem.
//!
//! Discovery ([`daemon_inventory`]) says what is running. Import turns
//! that into something a person can trust and act on:
//!
//! 1. [`enrich`] fills in what a bare scan cannot: versions, the config
//!    files each kind of service keeps, how big its data is and which
//!    mount it sits on, and the messy-server notes (deleted binary, port
//!    changed hands, no restart policy, root without a unit file).
//! 2. [`Importer::preview`] shows exactly what adoption will manage, leave
//!    alone, and cannot offer.
//! 3. [`Importer::adopt`] records the adoption. It never restarts,
//!    reloads, or rewrites anything.
//! 4. [`Importer::unadopt`] reverses it, removing only what ServerOS added.
//!
//! Every scan is remembered so the next one can say what changed, and so
//! a port that used to be Postgres and is now something else is flagged
//! rather than silently re-labelled.

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
