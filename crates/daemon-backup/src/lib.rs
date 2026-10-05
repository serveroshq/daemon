pub mod remote;
pub mod retention;
pub mod snapshot;
pub mod strategy;

pub use snapshot::{Manifest, Snapshotter};
pub use strategy::Strategy;

pub const DEFAULT_RETENTION: usize = 7;
