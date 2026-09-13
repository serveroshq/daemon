//! The capability boundary, enforced in code.
//!
//! Every privileged thing the daemon can do is a variant of [`Operation`].
//! Nothing runs unless it comes through [`Broker::authorize`], which checks
//! the request against the rules in [`policy`] and the permitted roots in
//! [`roots`], and records the decision in `actions.log`. There is no
//! operation for "run this shell string" and there never will be: adding a
//! capability means adding a variant here, with a review, and documenting
//! it on the Trust page.
//!
//! The explicit non-capabilities (never read `/etc/shadow`, never read SSH
//! private keys, never leave permitted roots without a logged user action,
//! never phone anywhere but the panel and configured storage) are tests in
//! this crate, not prose.

pub mod broker;
pub mod ops;
pub mod policy;
pub mod roots;

pub use broker::{Broker, Denied, Grant, Request};
pub use ops::{DataOp, DeployOp, MachineOp, Operation, ServiceOp};
pub use roots::PermittedRoots;
