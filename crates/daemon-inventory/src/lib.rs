//! Service discovery. Read-only, bounded, low priority, repeatable, and
//! honest about what it does not know.
//!
//! Each source (listeners, systemd, Docker, web servers, cron, TLS) is a
//! pure parser over text plus a thin reader, so the parsers are tested
//! against fixtures on any platform. [`classify`] joins the sources into
//! [`DiscoveredService`]s with a confidence score and the capability
//! matrix that says what ServerOS could actually do with each one.
//!
//! Discovery never reads database contents, credentials, or application
//! data. It reads process metadata, unit files, container metadata, web
//! server configs, crontabs, and certificates: enough to name a service
//! and say how it is run.

pub mod classify;
pub mod cron;
pub mod docker;
pub mod exec;
pub mod listeners;
pub mod scanner;
pub mod systemd;
pub mod tls;
pub mod webservers;

pub use daemon_protocol::{DiscoveredService, InventoryReport};
pub use scanner::{diff, Scanner};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("discovery is only available on Linux")]
    Unsupported,
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("{0} timed out")]
    Timeout(String),
}
