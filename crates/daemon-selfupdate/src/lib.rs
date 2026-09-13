//! Self-update.
//!
//! The daemon runs as root on machines people depend on, so a bad
//! release has the largest blast radius in the product. The rules:
//!
//! - **Nothing installs without a valid signature** from the release key
//!   baked into this binary. No key, no updates.
//! - **Policy decides, not the panel.** The panel offers; [`policy`]
//!   checks the offer against `daemon.toml`: automatic on or off, a pin,
//!   the channel, a maintenance window, and whether a major version jump
//!   needs a person to approve it (it does, by default).
//! - **Releases say how far back they support.** A candidate carries
//!   `min_from`; a daemon older than that is told to step through an
//!   intermediate release.
//! - **In-flight jobs finish first.** The install waits.
//! - **Rollback is automatic.** The old binary stays beside the new one;
//!   if the new one cannot come up and reconnect, the [`rollback`] guard
//!   restores the old one and says so.
//! - **Nothing is silent.** Every step is an event in the activity feed.

pub mod install;
pub mod policy;
pub mod rollback;
pub mod verify;

pub use install::{install, Installed};
pub use policy::{decide, Candidate, Decision, Policy};
pub use rollback::{Marker, RollbackGuard};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("this build carries no release public key, so it cannot verify updates; install releases manually")]
    NoReleaseKey,
    #[error("the download did not match the expected checksum")]
    ChecksumMismatch,
    #[error("the release signature did not verify; the binary was not installed")]
    BadSignature,
    #[error("{0}")]
    Network(#[from] daemon_http::HttpError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Refused(String),
}
