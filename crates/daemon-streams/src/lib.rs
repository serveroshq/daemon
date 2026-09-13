//! Streams: live log tails and terminal sessions, multiplexed over the
//! control channel as [`StreamFrame`]s.
//!
//! - Log tails are rate-capped: a service that logs faster than the cap
//!   gets a `[... N lines dropped ...]` marker rather than a stalled
//!   channel or a flooded panel. Every line is redacted first.
//! - Terminal sessions are real PTYs, run as the requested user, tied to
//!   the panel identity that opened them, closed on idle, and recorded
//!   only when the account opted in.

pub mod logs;
pub mod pty;
pub mod session;

pub use logs::LogTail;
pub use session::{Sessions, TerminalSession};

use daemon_protocol::{StreamFrame, StreamKind};
use uuid::Uuid;

/// Lines per second any single stream may push; the rest is summarised.
pub const LINE_RATE_CAP: usize = 200;

pub fn frame(session: Uuid, kind: StreamKind, bytes: &[u8], eof: bool) -> StreamFrame {
    use base64::Engine;

    StreamFrame {
        session,
        kind,
        data_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        eof,
    }
}

pub fn decode(frame: &StreamFrame) -> Vec<u8> {
    use base64::Engine;

    base64::engine::general_purpose::STANDARD
        .decode(&frame.data_b64)
        .unwrap_or_default()
}
