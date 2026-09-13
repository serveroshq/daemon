//! Services ServerOS manages, whether it created them or adopted them.
//!
//! Adoption is the riskiest moment in the product, so the rules are code:
//! no restart, no config rewrite, preview before commit, reversible, and
//! partial adoption is fine. The [`registry`] remembers what was adopted
//! and what each service can do; the [`systemd`] and [`docker`] adapters
//! do the actual starting, stopping, and log reading.

pub mod adoption;
pub mod docker;
pub mod registry;
pub mod systemd;

pub use adoption::{preview, AdoptionPreview};
pub use registry::{ManagedService, Registry, RunBy};

use daemon_protocol::{ServiceAction, ServiceStatus};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0} is not a managed service; adopt it first")]
    NotManaged(String),
    #[error("{service} cannot be {action:?}ed: it is run by {manager}, which ServerOS can observe but not control")]
    Unsupported {
        service: String,
        action: ServiceAction,
        manager: String,
    },
    #[error("{0}")]
    Command(String),
    #[error("docker did not answer: {0}")]
    Docker(String),
    #[error("{0}")]
    State(#[from] daemon_state::StateError),
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

/// What every adapter can do. Implemented for systemd units and Docker
/// containers; everything else is observe-only.
#[allow(async_fn_in_trait)]
pub trait Lifecycle {
    async fn act(&self, target: &str, action: ServiceAction) -> Result<()>;
    async fn status(&self, target: &str) -> Result<ServiceStatus>;
    async fn logs(&self, target: &str, lines: u32) -> Result<Vec<String>>;
}
