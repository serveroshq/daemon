//! The wire protocol. Everything that crosses the control channel is an
//! [`Envelope`]: a protocol major version, a monotonic sequence number, a
//! message kind, and a payload. The version lives in the envelope so the
//! panel can keep talking to daemons two minor versions behind, and so a
//! breaking change is a new [`driver`] rather than a flag day.
//!
//! Rules that keep this honest:
//! - Changes within a major are additive. New fields carry defaults.
//! - A new major gets a new driver. The old one keeps shipping until no
//!   supported daemon speaks it.
//! - Payload types are plain data. No behaviour lives here.

pub mod driver;
pub mod envelope;
pub mod messages;

pub use driver::{negotiate, Driver, DriverError, SUPPORTED_MAJORS};
pub use envelope::{Envelope, Kind, Sequencer};
pub use messages::*;
