pub(crate) mod atomic;
pub mod container;
pub mod deployer;
pub mod git;
pub mod health;
pub mod native;
pub mod proxy;
pub mod registry;
pub mod releases;
pub mod site_options;
pub mod traffic;

pub use deployer::{DeployResult, Deployer};
pub use releases::{Release, ReleaseLedger};

pub const RETAINED_RELEASES: usize = 5;
