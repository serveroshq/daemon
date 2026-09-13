//! The control channel. The daemon dials out to the panel over TLS 1.3
//! with its enrolment certificate, speaks WebSocket, and never listens.
//!
//! One [`Link`] is one connection: it handles the `Hello` handshake,
//! version negotiation, sequence numbers, heartbeats, and liveness. The
//! reconnect policy lives in [`backoff`]; the control loop in `serverosd`
//! decides when to redial, so this crate has no opinion about what
//! happens between connections.

pub mod backoff;
pub mod link;
pub mod tls;

pub use backoff::Backoff;
pub use link::{Link, LinkError, LinkEvent};

use std::time::Duration;

/// Heartbeat every 10 seconds. The panel marks a machine degraded after
/// three missed and offline after six.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// If nothing arrives from the panel for this long (it sends pings), the
/// link is presumed dead and dropped so the backoff can redial.
pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(45);

/// How long the `Hello` / `HelloAck` exchange may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub fn control_url(host: &str, port: u16) -> String {
    if port == 443 {
        format!("wss://{host}/daemon/control")
    } else {
        format!("wss://{host}:{port}/daemon/control")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_url_omits_the_default_port() {
        assert_eq!(
            control_url("api.serveros.com", 443),
            "wss://api.serveros.com/daemon/control"
        );
        assert_eq!(
            control_url("localhost", 8443),
            "wss://localhost:8443/daemon/control"
        );
    }
}
