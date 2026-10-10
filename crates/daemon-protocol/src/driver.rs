use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::envelope::{Envelope, Kind};
use crate::messages::*;

pub const SUPPORTED_MAJORS: &[u16] = &[1];

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("no common protocol version: daemon speaks {daemon:?}, panel offered {panel}")]
    NoCommonVersion { daemon: Vec<u16>, panel: u16 },
    #[error("envelope is v{0} but this driver speaks v{1}")]
    WrongMajor(u16, u16),
    #[error("{kind:?} payload did not parse: {source}")]
    Payload {
        kind: Kind,
        source: serde_json::Error,
    },
    #[error("unexpected {0:?} message for this direction")]
    UnexpectedKind(Kind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Each message is handled and dropped straight away; boxing the command
// to even out the sizes would buy nothing.
#[allow(clippy::large_enum_variant)]
pub enum Inbound {
    HelloAck(HelloAck),
    Command { id: Uuid, command: Command },
    Control { id: Uuid, control: Control },
    Stream(StreamFrame),
    Gap { from: u64, to: u64 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outbound {
    Hello(Hello),
    Heartbeat(Heartbeat),
    Telemetry(TelemetryBatch),
    Inventory(InventoryReport),
    Event(Event),
    JobUpdate(JobUpdate),
    Stream(StreamFrame),
    Gap { from: u64, to: u64 },
    Facts(MachineFacts),
    Logs(LogBatch),
}

pub trait Driver: Send + Sync {
    fn major(&self) -> u16;
    fn decode(&self, envelope: &Envelope) -> Result<Inbound, DriverError>;
    fn encode(&self, seq: u64, message: &Outbound) -> Result<Envelope, DriverError>;
}

pub fn negotiate(panel_major: u16) -> Result<Box<dyn Driver>, DriverError> {
    match panel_major {
        1 => Ok(Box::new(v1::DriverV1)),
        other => Err(DriverError::NoCommonVersion {
            daemon: SUPPORTED_MAJORS.to_vec(),
            panel: other,
        }),
    }
}

pub fn newest() -> Box<dyn Driver> {
    negotiate(SUPPORTED_MAJORS[0]).expect("newest major is always supported")
}

pub mod v1 {
    use super::*;

    pub struct DriverV1;

    const MAJOR: u16 = 1;

    fn parse<T: serde::de::DeserializeOwned>(
        kind: Kind,
        payload: &Value,
    ) -> Result<T, DriverError> {
        serde_json::from_value(payload.clone())
            .map_err(|source| DriverError::Payload { kind, source })
    }

    fn envelope(
        seq: u64,
        kind: Kind,
        payload: &impl serde::Serialize,
    ) -> Result<Envelope, DriverError> {
        let value = serde_json::to_value(payload)
            .map_err(|source| DriverError::Payload { kind, source })?;

        Ok(Envelope::new(MAJOR, seq, kind, value))
    }

    impl Driver for DriverV1 {
        fn major(&self) -> u16 {
            MAJOR
        }

        fn decode(&self, env: &Envelope) -> Result<Inbound, DriverError> {
            if env.v != MAJOR {
                return Err(DriverError::WrongMajor(env.v, MAJOR));
            }

            Ok(match env.kind {
                Kind::HelloAck => Inbound::HelloAck(parse(env.kind, &env.payload)?),
                Kind::Command => Inbound::Command {
                    id: env.id,
                    command: parse(env.kind, &env.payload)?,
                },
                Kind::Control => Inbound::Control {
                    id: env.id,
                    control: parse(env.kind, &env.payload)?,
                },
                Kind::Stream => Inbound::Stream(parse(env.kind, &env.payload)?),
                Kind::Gap => {
                    let gap: GapPayload = parse(env.kind, &env.payload)?;
                    Inbound::Gap {
                        from: gap.from,
                        to: gap.to,
                    }
                }
                other => return Err(DriverError::UnexpectedKind(other)),
            })
        }

        fn encode(&self, seq: u64, message: &Outbound) -> Result<Envelope, DriverError> {
            match message {
                Outbound::Hello(m) => envelope(seq, Kind::Hello, m),
                Outbound::Heartbeat(m) => envelope(seq, Kind::Heartbeat, m),
                Outbound::Telemetry(m) => envelope(seq, Kind::Telemetry, m),
                Outbound::Inventory(m) => envelope(seq, Kind::Inventory, m),
                Outbound::Event(m) => envelope(seq, Kind::Event, m),
                Outbound::JobUpdate(m) => {
                    envelope(seq, Kind::JobUpdate, m).map(|e| e.with_id(m.job_id))
                }
                Outbound::Stream(m) => envelope(seq, Kind::Stream, m),
                Outbound::Gap { from, to } => envelope(
                    seq,
                    Kind::Gap,
                    &GapPayload {
                        from: *from,
                        to: *to,
                    },
                ),
                Outbound::Facts(m) => envelope(seq, Kind::Facts, m),
                Outbound::Logs(m) => envelope(seq, Kind::Logs, m),
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct GapPayload {
        from: u64,
        to: u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_envelope(job: Value) -> Envelope {
        Envelope::new(
            1,
            3,
            Kind::Command,
            serde_json::json!({
                "actor": {"kind": "user", "name": "dylan@serveros.com"},
                "job": job
            }),
        )
    }

    #[test]
    fn decodes_a_v1_command_into_a_typed_job() {
        let env = command_envelope(serde_json::json!({"type": "discover"}));
        let driver = negotiate(1).unwrap();

        match driver.decode(&env).unwrap() {
            Inbound::Command { id, command } => {
                assert_eq!(id, env.id);
                assert_eq!(command.job, Job::Discover);
                assert!(!command.confirmed);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn refuses_an_envelope_from_another_major() {
        let mut env = command_envelope(serde_json::json!({"type": "discover"}));
        env.v = 2;

        assert!(matches!(
            negotiate(1).unwrap().decode(&env),
            Err(DriverError::WrongMajor(2, 1))
        ));
    }

    #[test]
    fn refuses_a_heartbeat_coming_from_the_panel() {
        let env = Envelope::new(1, 0, Kind::Heartbeat, serde_json::json!({}));

        assert!(matches!(
            negotiate(1).unwrap().decode(&env),
            Err(DriverError::UnexpectedKind(Kind::Heartbeat))
        ));
    }

    #[test]
    fn job_updates_reuse_the_job_id() {
        let job_id = Uuid::new_v4();
        let update = JobUpdate {
            job_id,
            state: JobState::Running,
            phase: Some("build".into()),
            progress: Some(40),
            log: vec![],
            result: None,
            error: None,
        };

        let env = newest().encode(9, &Outbound::JobUpdate(update)).unwrap();

        assert_eq!(env.id, job_id);
        assert_eq!(env.seq, 9);
        assert_eq!(env.kind, Kind::JobUpdate);
    }

    #[test]
    fn unknown_major_has_no_driver() {
        assert!(matches!(
            negotiate(99),
            Err(DriverError::NoCommonVersion { panel: 99, .. })
        ));
    }
}
