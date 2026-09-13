//! Backups and restores.
//!
//! A snapshot is a directory under `/var/lib/serveros/backups/<service>/`
//! holding a native dump (`pg_dump`, `mysqldump`, a Redis RDB) or a tar
//! of the service's paths, plus a manifest with sizes and checksums.
//! Retention prunes conservatively and never deletes the last one.
//!
//! Restore is the most dangerous thing the daemon does. It is explicit
//! (a confirmed job), previewed, and always preceded by a fresh
//! pre-restore snapshot so the restore itself can be undone.

pub mod remote;
pub mod retention;
pub mod snapshot;
pub mod strategy;

pub use snapshot::{Manifest, Snapshotter};
pub use strategy::Strategy;

/// Default number of snapshots kept per service.
pub const DEFAULT_RETENTION: usize = 7;
