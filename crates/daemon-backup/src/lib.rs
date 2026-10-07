pub mod remote;
pub mod retention;
pub mod snapshot;
pub mod strategy;

pub use snapshot::{Manifest, Snapshotter};
pub use strategy::Strategy;

pub const DEFAULT_RETENTION: usize = 7;

/// The reason a deploy's snapshot is taken with. They're kept apart from
/// backups, so deploying often doesn't push those out.
pub const PRE_DEPLOY: &str = "pre-deploy";

/// Pre-deploy snapshots kept per service.
pub const PRE_DEPLOY_RETENTION: usize = 3;
