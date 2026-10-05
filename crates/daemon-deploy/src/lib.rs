pub mod container;
pub mod deployer;
pub mod git;
pub mod health;
pub mod proxy;
pub mod releases;

pub use deployer::{DeployResult, Deployer};
pub use releases::{Release, ReleaseLedger};

pub const RETAINED_RELEASES: usize = 5;
