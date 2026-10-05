use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub v: u16,
    pub seq: u64,
    pub id: Uuid,
    pub ts: i64,
    pub kind: Kind,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Hello,
    HelloAck,
    Heartbeat,
    Telemetry,
    Inventory,
    Event,
    Command,
    JobUpdate,
    Stream,
    Control,
    Gap,
    Facts,
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
        assert_eq!(seq.observe(3), None);
        assert_eq!(seq.observe(6), None);
    }

    #[test]
    fn outgoing_sequence_is_monotonic_from_zero() {
        let mut seq = Sequencer::new();

        assert_eq!((seq.next_seq(), seq.next_seq(), seq.next_seq()), (0, 1, 2));
    }
}
