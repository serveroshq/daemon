//! Who this machine is to the panel.
//!
//! The private key is generated here and never leaves. Enrolment sends a
//! CSR with a one-time token; the panel answers with a client certificate
//! scoped to this one machine and the CA to pin. Everything the transport
//! needs for mutual TLS is a [`Identity`].

pub mod enrol;
pub mod keys;

pub use enrol::{enrol, EnrolError, EnrolRequest, EnrolResponse};
pub use keys::{Identity, IdentityError, KeyMaterial};
