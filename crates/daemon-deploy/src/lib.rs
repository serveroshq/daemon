//! Deploys.
//!
//! ```text
//! receive job → prepare workspace → fetch source → build →
//! start new → health check → swap proxy → verify → stop old → report
//!                                    ↓ on failure
//!                              roll back, keep old release live
//! ```
//!
//! Releases are immutable: each is a container image tagged by commit and
//! a container named for the service and commit. The proxy points at the
//! new container only after its health check passes, so the old release
//! serves until the very last step. A failed deploy names its phase and
//! carries the real output.

pub mod container;
pub mod deployer;
pub mod git;
pub mod health;
pub mod proxy;
pub mod releases;

pub use deployer::{DeployResult, Deployer};
pub use releases::{Release, ReleaseLedger};

/// How many previous releases stay on disk for rollback.
pub const RETAINED_RELEASES: usize = 5;
