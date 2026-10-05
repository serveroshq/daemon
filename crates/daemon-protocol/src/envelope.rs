use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// One message on the control channel, in either direction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// Protocol major version the payload conforms to.
    pub v: u16,
    /// Monotonic per-connection sequence. Gaps mean loss; the receiver
    /// asks for a backfill rather than pretending nothing happened.
    pub seq: u64,
    /// Unique per message; for commands this is the job id, and re-delivery
    /// of the same id returns the stored result.
    pub id: Uuid,
    /// Unix seconds when the sender created the message.
    pub ts: i64,
    pub kind: Kind,
    /// The kind-specific body. Decoded by the negotiated driver.
    pub payload: serde_json::Value,
}

/// Message classes. The direction is a convention, enforced by which side
/// bothers to handle each kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Daemon → panel on connect: identity, version, supported majors.
    Hello,
    /// Panel → daemon: the negotiated major and panel capabilities.
    HelloAck,
    /// Daemon → panel every 10 seconds: liveness, version, uptime.
    Heartbeat,
    /// Daemon → panel: machine and service metrics.
    Telemetry,
    /// Daemon → panel: discovered services and changes.
    Inventory,
    /// Daemon → panel: something happened (crash, disk, update available).
    Event,
    /// Panel → daemon: a durable job to run.
    Command,
    /// Daemon → panel: accepted, progress, log lines, terminal result.
    JobUpdate,
    /// Bidirectional: PTY and live log frames.
    Stream,
    /// Panel → daemon: self-update, reconfigure, disconnect.
    Control,
    /// Either direction: the peer noticed a sequence gap.
    Gap,
    /// Daemon → panel: machine facts changed since `Hello` (added in 1.1).
    Facts,
    /// Daemon → panel: service log lines (added in 1.2).
    Logs,
}

impl Envelope {
    pub fn new(v: u16, seq: u64, kind: Kind, payload: serde_json::Value) -> Self {
        Self {
            v,
            seq,
            id: Uuid::new_v4(),
            ts: OffsetDateTime::now_utc().unix_timestamp(),
            kind,
            payload,
        }
    }

    pub fn with_id(mut self, id: Uuid) -> Self {
        self.id = id;
        self
    }

    pub fn encode(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub fn decode(raw: &str) -> serde_json::Result<Self> {
        serde_json::from_str(raw)
    }
}

/// Hands out sequence numbers for one connection and spots gaps on the
/// way in.
#[derive(Debug, Default)]
pub struct Sequencer {
    next_out: u64,
    last_in: Option<u64>,
}

impl Sequencer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_seq(&mut self) -> u64 {
        let seq = self.next_out;
        self.next_out += 1;
        seq
    }

    /// Record an incoming sequence number. Returns the range that went
    /// missing when the number jumped, so the caller can ask for it.
    pub fn observe(&mut self, seq: u64) -> Option<std::ops::Range<u64>> {
        let gap = match self.last_in {
            Some(last) if seq > last + 1 => Some(last + 1..seq),
            _ => None,
        };

        if self.last_in.is_none_or(|last| seq > last) {
            self.last_in = Some(seq);
        }

        gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_round_trip_as_json() {
        let env = Envelope::new(
            1,
            7,
            Kind::Heartbeat,
            serde_json::json!({"uptime_secs": 12}),
        );
        let decoded = Envelope::decode(&env.encode().unwrap()).unwrap();

        assert_eq!(decoded, env);
    }

    #[test]
    fn kinds_serialise_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&Kind::JobUpdate).unwrap(),
            "\"job_update\""
        );
    }

    #[test]
    fn sequencer_reports_gaps_once() {
        let mut seq = Sequencer::new();

        assert_eq!(seq.observe(0), None);
        assert_eq!(seq.observe(1), None);
        assert_eq!(seq.observe(4), Some(2..4));
        assert_eq!(seq.observe(5), None);
        // A late duplicate never moves the high-water mark backwards.
        assert_eq!(seq.observe(3), None);
        assert_eq!(seq.observe(6), None);
    }

    #[test]
    fn outgoing_sequence_is_monotonic_from_zero() {
        let mut seq = Sequencer::new();

        assert_eq!((seq.next_seq(), seq.next_seq(), seq.next_seq()), (0, 1, 2));
    }
}
