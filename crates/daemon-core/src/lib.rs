//! The bits every other crate leans on: where things live on disk, the
//! non-secret configuration file, what build this is, and the redaction
//! pass that keeps secrets out of anything that leaves the machine.
//!
//! Nothing in here touches the network or runs privileged code.

pub mod buildinfo;
pub mod config;
pub mod links;
pub mod paths;
pub mod redact;

pub use buildinfo::BuildInfo;
pub use config::Config;
pub use paths::Paths;
