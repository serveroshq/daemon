pub mod backoff;
pub mod link;
pub mod tls;

pub use backoff::Backoff;
pub use link::{Link, LinkError, LinkEvent};

use std::time::Duration;

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(45);

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
