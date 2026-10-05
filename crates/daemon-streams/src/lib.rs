pub mod logs;
pub mod pty;
pub mod session;

pub use logs::LogTail;
pub use session::{Sessions, TerminalSession};

use daemon_protocol::{StreamFrame, StreamKind};
use uuid::Uuid;

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
