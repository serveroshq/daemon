//! One daemon connection, from TLS accept to hang-up.
//!
//! 1. Finish the mutual-TLS handshake and read the certificate serial.
//! 2. Accept the WebSocket upgrade on `/daemon/control`.
//! 3. Wait for the daemon's `Hello`, ask the panel who the serial is, and
//!    answer with the panel's `HelloAck` (or close with the refusal code).
//! 4. Relay: daemon frames are batched to the panel once a second; stream
//!    frames go straight to an attached browser; commands from the
//!    internal API are sequenced and written to the socket.
//! 5. On any exit, unregister and tell the panel the machine closed.

// tungstenite's handshake callbacks return its own (large) error response type.
#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use daemon_protocol::{Envelope, Hello, Kind, Sequencer, SUPPORTED_MAJORS};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::panel::PanelError;
use crate::registry::Outgoing;
use crate::{tls, Context};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// Daemons drop a link silent for 45 seconds; ping well inside that.
const PING_INTERVAL: Duration = Duration::from_secs(20);
/// Daemons heartbeat every 10 seconds; six missed is dead.
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(60);
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const FLUSH_AT: usize = 200;
const CONTROL_PATH: &str = "/daemon/control";

pub async fn serve(tcp: TcpStream, peer: SocketAddr, acceptor: TlsAcceptor, ctx: Arc<Context>) {
    let _ = tcp.set_nodelay(true);

    let tls = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            debug!(%peer, error = %e, "tls handshake failed");
            return;
        }
        Err(_) => {
            debug!(%peer, "tls handshake timed out");
            return;
        }
    };

    let Some(serial) = tls::peer_serial(tls.get_ref().1.peer_certificates()) else {
        warn!(%peer, "connection without a readable client certificate");
        return;
    };

    let socket = match tokio_tungstenite::accept_hdr_async(tls, control_path_only).await {
        Ok(s) => s,
        Err(e) => {
            debug!(%peer, %serial, error = %e, "websocket upgrade refused");
            return;
        }
    };

    let (mut sink, mut stream) = socket.split();
    let mut sequencer = Sequencer::new();

    // Step 3: Hello.
    let hello_env = match tokio::time::timeout(HELLO_TIMEOUT, first_text(&mut stream)).await {
        Ok(Some(text)) => match Envelope::decode(&text) {
            Ok(env) if env.kind == Kind::Hello => env,
            Ok(env) => {
                warn!(%peer, %serial, kind = ?env.kind, "expected hello first");
                let _ = close(&mut sink, CloseCode::Protocol, "hello expected").await;
                return;
            }
            Err(e) => {
                warn!(%peer, %serial, error = %e, "undecodable hello");
                let _ = close(&mut sink, CloseCode::Protocol, "hello malformed").await;
                return;
            }
        },
        Ok(None) => return,
        Err(_) => {
            debug!(%peer, %serial, "no hello within the timeout");
            let _ = close(&mut sink, CloseCode::Policy, "hello timeout").await;
            return;
        }
    };
    sequencer.observe(hello_env.seq);

    let hello: Hello = match serde_json::from_value(hello_env.payload.clone()) {
        Ok(h) => h,
        Err(e) => {
            warn!(%peer, %serial, error = %e, "hello payload malformed");
            let _ = close(&mut sink, CloseCode::Protocol, "hello malformed").await;
            return;
        }
    };

    if !hello
        .supported_majors
        .iter()
        .any(|m| SUPPORTED_MAJORS.contains(m))
    {
        warn!(%serial, majors = ?hello.supported_majors, "no common protocol major");
        let _ = close(
            &mut sink,
            CloseCode::Unsupported,
            "protocol_unsupported: update the daemon",
        )
        .await;
        return;
    }

    let reply = match ctx.panel.hello(&serial, &hello).await {
        Ok(reply) => reply,
        Err(PanelError::Refused { code, message, .. }) => {
            info!(%serial, %code, "panel refused the connection");
            let _ = close(&mut sink, CloseCode::Policy, &format!("{code}: {message}")).await;
            return;
        }
        Err(e) => {
            warn!(%serial, error = %e, "panel unreachable during hello");
            let _ = close(&mut sink, CloseCode::Again, "panel unavailable, retry").await;
            return;
        }
    };

    let major = reply.ack.major;
    let ack_env = Envelope::new(
        major,
        sequencer.next_seq(),
        Kind::HelloAck,
        match serde_json::to_value(&reply.ack) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "could not encode hello ack");
                return;
            }
        },
    );

    if let Err(e) = send_envelope(&mut sink, &ack_env).await {
        debug!(%serial, error = %e, "could not send hello ack");
        return;
    }

    let uid = reply.machine_id;
    let (out_tx, mut out_rx) = mpsc::channel::<Outgoing>(256);
    let handle = ctx.registry.handle(
        uid.clone(),
        serial.clone(),
        major,
        hello.daemon_version.clone(),
        out_tx,
    );
    let generation = handle.generation;

    if ctx.registry.register(Arc::clone(&handle)).is_some() {
        info!(%uid, "replaced an earlier connection for this machine");
    }

    info!(%uid, %serial, version = %hello.daemon_version, major, %peer, "daemon connected");

    // Uplink: batches leave the read loop through a channel so a slow
    // panel never stalls the socket.
    let (batch_tx, mut batch_rx) = mpsc::channel::<Vec<Envelope>>(64);
    let uplink_ctx = Arc::clone(&ctx);
    let uplink_uid = uid.clone();
    let uplink = tokio::spawn(async move {
        while let Some(batch) = batch_rx.recv().await {
            let mut attempt = 0;

            loop {
                match uplink_ctx.panel.ingest(&uplink_uid, &batch).await {
                    Ok(()) => break,
                    Err(e) if attempt == 0 => {
                        attempt += 1;
                        debug!(uid = %uplink_uid, error = %e, "ingest failed, retrying once");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        warn!(uid = %uplink_uid, error = %e, count = batch.len(), "dropping a batch the panel would not take");
                        break;
                    }
                }
            }
        }
    });

    let mut pending: Vec<Envelope> = Vec::new();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    let mut flush = tokio::time::interval(FLUSH_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut inbound_seq = Sequencer::new();
    inbound_seq.observe(hello_env.seq);

    let reason = loop {
        tokio::select! {
            outgoing = out_rx.recv() => {
                let Some(message) = outgoing else {
                    break "replaced by a newer connection".to_string();
                };

                let mut env = Envelope::new(major, sequencer.next_seq(), message.kind, message.payload);

                if let Some(id) = message.id {
                    env = env.with_id(id);
                }

                if let Err(e) = send_envelope(&mut sink, &env).await {
                    break format!("write failed: {e}");
                }
            }
            frame = tokio::time::timeout(LIVENESS_TIMEOUT, stream.next()) => {
                let text = match frame {
                    Ok(Some(Ok(Message::Text(text)))) => text,
                    Ok(Some(Ok(Message::Close(frame)))) => {
                        break format!("closed by daemon: {}", frame.map(|f| f.reason.to_string()).unwrap_or_default());
                    }
                    Ok(Some(Ok(_))) => continue,
                    Ok(Some(Err(e))) => break format!("socket error: {e}"),
                    Ok(None) => break "socket ended".to_string(),
                    Err(_) => break format!("silent for {LIVENESS_TIMEOUT:?}"),
                };

                let env = match Envelope::decode(&text) {
                    Ok(env) => env,
                    Err(e) => {
                        warn!(%uid, error = %e, "dropping undecodable frame");
                        continue;
                    }
                };

                if let Some(gap) = inbound_seq.observe(env.seq) {
                    warn!(%uid, from = gap.start, to = gap.end, "sequence gap from daemon");
                }

                match env.kind {
                    Kind::Stream => {
                        match serde_json::from_value(env.payload) {
                            Ok(frame) => {
                                if !handle.route_stream(frame) {
                                    debug!(%uid, "stream frame with no viewer attached");
                                }
                            }
                            Err(e) => warn!(%uid, error = %e, "malformed stream frame"),
                        }
                    }
                    Kind::Hello | Kind::HelloAck | Kind::Command | Kind::Control => {
                        debug!(%uid, kind = ?env.kind, "ignoring a kind the daemon should not send");
                    }
                    Kind::Gap => {
                        debug!(%uid, "daemon reported a gap; the panel does not replay commands");
                    }
                    _ => {
                        pending.push(env);

                        if pending.len() >= FLUSH_AT {
                            flush_pending(&batch_tx, &mut pending, &uid);
                        }
                    }
                }
            }
            _ = flush.tick() => {
                if !pending.is_empty() {
                    flush_pending(&batch_tx, &mut pending, &uid);
                }
            }
            _ = ping.tick() => {
                if let Err(e) = sink.send(Message::Ping(Vec::new())).await {
                    break format!("ping failed: {e}");
                }
            }
        }
    };

    if !pending.is_empty() {
        flush_pending(&batch_tx, &mut pending, &uid);
    }

    drop(batch_tx);
    let _ = tokio::time::timeout(Duration::from_secs(20), uplink).await;

    let _ = sink.close().await;

    if ctx.registry.unregister(&uid, generation) {
        if let Err(e) = ctx.panel.closed(&uid).await {
            warn!(%uid, error = %e, "could not report the disconnect to the panel");
        }
    }

    info!(%uid, %reason, "daemon disconnected");
}

fn control_path_only(request: &Request, response: Response) -> Result<Response, ErrorResponse> {
    if request.uri().path() == CONTROL_PATH {
        Ok(response)
    } else {
        Err(tokio_tungstenite::tungstenite::http::Response::builder()
            .status(404)
            .body(Some(format!("daemons connect to {CONTROL_PATH}")))
            .unwrap_or_default())
    }
}

async fn first_text<S>(stream: &mut S) -> Option<String>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => return Some(text),
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return None,
            Some(Ok(_)) => continue,
        }
    }
}

async fn send_envelope<S>(sink: &mut S, env: &Envelope) -> Result<(), String>
where
    S: SinkExt<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    let text = env.encode().map_err(|e| e.to_string())?;

    sink.send(Message::Text(text))
        .await
        .map_err(|e| e.to_string())
}

async fn close<S>(sink: &mut S, code: CloseCode, reason: &str) -> Result<(), S::Error>
where
    S: SinkExt<Message> + Unpin,
{
    sink.send(Message::Close(Some(CloseFrame {
        code,
        reason: reason.to_string().into(),
    })))
    .await
}

fn flush_pending(tx: &mpsc::Sender<Vec<Envelope>>, pending: &mut Vec<Envelope>, uid: &str) {
    let batch = std::mem::take(pending);

    if let Err(e) = tx.try_send(batch) {
        warn!(%uid, error = %e, "uplink backlog full; dropping a batch (the panel can ask for a backfill)");
    }
}
