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
