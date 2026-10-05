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
