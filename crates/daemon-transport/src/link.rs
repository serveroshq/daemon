//! One live connection: dial, handshake, then pump frames both ways
//! until the socket dies or the control loop hangs up.

use std::sync::Arc;
use std::time::Duration;

use daemon_protocol::driver::{negotiate, newest, Driver, Inbound, Outbound};
use daemon_protocol::{Envelope, Heartbeat, Hello, HelloAck, Kind, Sequencer};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use tracing::{debug, info, warn};

use crate::{tls, HANDSHAKE_TIMEOUT, HEARTBEAT_INTERVAL, LIVENESS_TIMEOUT};

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("{0}")]
    Tls(#[from] tls::TlsError),
    #[error("could not connect to {url}: {source} (the daemon only dials out on 443; check outbound firewall rules and DNS)")]
    Connect {
        url: String,
        // Boxed: tungstenite's error is large, and this enum travels in
        // every Result the link returns.
        source: Box<tokio_tungstenite::tungstenite::Error>,
    },
    #[error("the panel did not answer the handshake within {0:?}")]
    HandshakeTimeout(Duration),
    #[error("the panel closed the connection during the handshake")]
    HandshakeClosed,
    #[error("the panel's handshake reply was not understood: {0}")]
    HandshakeMalformed(String),
    #[error("{0}")]
    Protocol(#[from] daemon_protocol::DriverError),
    #[error("the connection was lost: {0}")]
    Lost(String),
    #[error("no frame from the panel for {0:?}")]
    Silent(Duration),
}

/// What the control loop sees from a link.
// Nearly every event is a Message, so boxing it would only add an
// allocation per frame.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum LinkEvent {
    Message(Inbound),
    /// A sequence gap on the inbound side; the control loop may ask the
    /// panel to resend.
    Gap {
        from: u64,
        to: u64,
    },
    Closed(LinkError),
}

/// A connected, negotiated link.
pub struct Link {
    pub ack: HelloAck,
    pub major: u16,
    /// Send typed messages; they are sequenced and framed by the pump.
    pub tx: mpsc::Sender<Outbound>,
    /// Typed messages from the panel, plus the close reason at the end.
    pub rx: mpsc::Receiver<LinkEvent>,
}

/// The heartbeat body is supplied by the caller so the transport does not
/// need to know about uptime or running jobs.
pub type HeartbeatSource = Arc<dyn Fn() -> Heartbeat + Send + Sync>;

impl Link {
    /// Dial, present `hello`, and negotiate. Returns once the panel has
    /// acknowledged; the pumps run on background tasks until the socket
    /// dies or `tx` is dropped.
    pub async fn connect(
        url: &str,
        identity: &daemon_identity::Identity,
        hello: Hello,
        heartbeat: HeartbeatSource,
    ) -> Result<Self, LinkError> {
        let tls_config = tls::client_config(identity)?;
        let host = url
            .trim_start_matches("wss://")
            .split(['/', ':'])
            .next()
            .unwrap_or_default()
            .to_string();

        // Surface a bad hostname before the socket is opened.
        ServerName::try_from(host.clone())
            .map_err(|e| LinkError::HandshakeMalformed(e.to_string()))?;

        let (socket, _) = tokio_tungstenite::connect_async_tls_with_config(
            url,
            None,
            false,
            Some(Connector::Rustls(tls_config)),
        )
        .await
        .map_err(|source| LinkError::Connect {
            url: url.into(),
            source: Box::new(source),
        })?;

        let (mut sink, mut stream) = socket.split();
        let mut sequencer = Sequencer::new();

        // Hello goes out with our newest driver; the ack tells us which to use.
        let hello_env = newest().encode(sequencer.next_seq(), &Outbound::Hello(hello))?;
        sink.send(Message::Text(
            hello_env
                .encode()
                .map_err(|e| LinkError::HandshakeMalformed(e.to_string()))?,
        ))
        .await
        .map_err(|e| LinkError::Lost(e.to_string()))?;

        let ack = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            loop {
                match stream.next().await {
                    Some(Ok(Message::Text(text))) => {
                        let env = Envelope::decode(&text)
                            .map_err(|e| LinkError::HandshakeMalformed(e.to_string()))?;

                        if env.kind == Kind::HelloAck {
                            sequencer.observe(env.seq);
                            return serde_json::from_value::<HelloAck>(env.payload)
                                .map_err(|e| LinkError::HandshakeMalformed(e.to_string()));
                        }
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(Message::Close(_))) | None => return Err(LinkError::HandshakeClosed),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(LinkError::Lost(e.to_string())),
                }
            }
        })
        .await
        .map_err(|_| LinkError::HandshakeTimeout(HANDSHAKE_TIMEOUT))??;

        let driver: Arc<dyn Driver> = Arc::from(negotiate(ack.major)?);
        info!(major = ack.major, panel = %ack.panel_version, "control channel up");

        let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(256);
        let (in_tx, in_rx) = mpsc::channel::<LinkEvent>(256);
        let major = driver.major();

        // Outbound pump: sequences and frames whatever the control loop sends,
        // and emits heartbeats on its own clock.
        let write_driver = Arc::clone(&driver);
        let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                let message = tokio::select! {
                    _ = ticker.tick() => Outbound::Heartbeat(heartbeat()),
                    next = out_rx.recv() => match next {
                        Some(m) => m,
                        None => break,
                    },
                    _ = &mut close_rx => break,
                };

                let env = match write_driver.encode(sequencer.next_seq(), &message) {
                    Ok(env) => env,
                    Err(e) => {
                        warn!(error = %e, "could not encode outbound message");
                        continue;
                    }
                };

                let text = match env.encode() {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(error = %e, "could not serialise envelope");
                        continue;
                    }
                };

                if let Err(e) = sink.send(Message::Text(text)).await {
                    debug!(error = %e, "outbound pump ending");
                    break;
                }
            }

            let _ = sink.close().await;
        });

        // Inbound pump: decodes frames, tracks the panel's sequence, and
        // watches liveness.
        let read_driver = Arc::clone(&driver);
        tokio::spawn(async move {
            let mut inbound_seq = Sequencer::new();
            let reason = loop {
                let frame = match tokio::time::timeout(LIVENESS_TIMEOUT, stream.next()).await {
                    Ok(Some(Ok(frame))) => frame,
                    Ok(Some(Err(e))) => break LinkError::Lost(e.to_string()),
                    Ok(None) => break LinkError::Lost("closed by panel".into()),
                    Err(_) => break LinkError::Silent(LIVENESS_TIMEOUT),
                };

                let text = match frame {
                    Message::Text(text) => text,
                    Message::Close(_) => break LinkError::Lost("closed by panel".into()),
                    // Pings are answered by tungstenite automatically on the next write.
                    _ => continue,
                };

                let env = match Envelope::decode(&text) {
                    Ok(env) => env,
                    Err(e) => {
                        warn!(error = %e, "dropping undecodable frame");
                        continue;
                    }
                };

                if let Some(gap) = inbound_seq.observe(env.seq) {
                    if in_tx
                        .send(LinkEvent::Gap {
                            from: gap.start,
                            to: gap.end,
                        })
                        .await
                        .is_err()
                    {
                        break LinkError::Lost("control loop went away".into());
                    }
                }

                match read_driver.decode(&env) {
                    Ok(message) => {
                        if in_tx.send(LinkEvent::Message(message)).await.is_err() {
                            break LinkError::Lost("control loop went away".into());
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, kind = ?env.kind, "dropping message this driver cannot decode")
                    }
                }
            };

            let _ = close_tx.send(());
            let _ = in_tx.send(LinkEvent::Closed(reason)).await;
        });

        Ok(Self {
            ack,
            major,
            tx: out_tx,
            rx: in_rx,
        })
    }
}
