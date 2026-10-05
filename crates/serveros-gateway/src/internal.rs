#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use daemon_protocol::{Kind, StreamFrame, StreamKind};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};
use uuid::Uuid;

use crate::registry::{unix_now, Outgoing};
use crate::replay::Replay;
use crate::ticket::{self, constant_time_eq};
use crate::Context;

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_IDLE: Duration = Duration::from_secs(30 * 60);

struct Head {
    method: String,
    path: String,
    query: String,
    content_length: usize,
    secret: Option<String>,
    websocket: bool,
    raw: Vec<u8>,
    overflow: Vec<u8>,
}

pub async fn serve(mut tcp: TcpStream, peer: SocketAddr, ctx: Arc<Context>) -> anyhow::Result<()> {
    let head = match tokio::time::timeout(READ_TIMEOUT, read_head(&mut tcp)).await {
        Ok(Ok(Some(head))) => head,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(e)) => {
            let _ = respond(&mut tcp, 400, &json!({ "error": e.to_string() })).await;
            return Ok(());
        }
        Err(_) => return Ok(()),
    };

    if head.websocket {
        if !head.path.starts_with("/streams/") {
            let _ = respond(&mut tcp, 404, &json!({ "error": "not found" })).await;
            return Ok(());
        }

        let replay = Replay::new(head.raw.clone(), tcp);
        return stream_session(replay, peer, head, ctx).await;
    }

    let response = route(&mut tcp, head, &ctx).await?;
    respond(&mut tcp, response.0, &response.1).await?;

    Ok(())
}

async fn route(tcp: &mut TcpStream, head: Head, ctx: &Context) -> anyhow::Result<(u16, Value)> {
    let segments: Vec<&str> = head.path.trim_matches('/').split('/').collect();

    if head.method == "GET" && head.path == "/healthz" {
        return Ok((200, json!({ "ok": true, "machines": ctx.registry.len() })));
    }

    let authorised = head
        .secret
        .as_deref()
        .is_some_and(|s| constant_time_eq(s.as_bytes(), ctx.secret.as_bytes()));

    if !authorised {
        return Ok((401, json!({ "error": "missing or wrong X-Gateway-Secret" })));
    }

    match (head.method.as_str(), segments.as_slice()) {
        ("GET", ["machines"]) => {
            let detail = ctx.registry.list();
            let uids: Vec<&str> = detail.iter().map(|m| m.uid.as_str()).collect();

            Ok((200, json!({ "machines": uids, "detail": detail })))
        }
        ("POST", ["machines", uid, "commands"]) => {
            let body: CommandBody = read_json(tcp, head.content_length, head.overflow).await?;

            if !body.command.is_object() {
                return Ok((422, json!({ "error": "command must be an object" })));
            }

            dispatch(
                ctx,
                uid,
                Outgoing {
                    kind: Kind::Command,
                    payload: body.command,
                    id: Some(body.id),
                },
            )
        }
        ("POST", ["machines", uid, "control"]) => {
            let body: ControlBody = read_json(tcp, head.content_length, head.overflow).await?;

            if !body.control.is_object() {
                return Ok((422, json!({ "error": "control must be an object" })));
            }

            dispatch(
                ctx,
                uid,
                Outgoing {
                    kind: Kind::Control,
                    payload: body.control,
                    id: None,
                },
            )
        }
        _ => Ok((404, json!({ "error": "not found" }))),
    }
}

fn dispatch(ctx: &Context, uid: &str, message: Outgoing) -> anyhow::Result<(u16, Value)> {
    let Some(handle) = ctx.registry.get(uid) else {
        return Ok((
            404,
            json!({ "error": "not_connected", "message": "The machine is not connected." }),
        ));
    };

    match handle.tx.try_send(message) {
        Ok(()) => Ok((202, json!({ "queued": true }))),
        Err(mpsc::error::TrySendError::Full(_)) => Ok((
            503,
            json!({ "error": "busy", "message": "The machine's outbound queue is full; retry shortly." }),
        )),
        Err(mpsc::error::TrySendError::Closed(_)) => Ok((
            404,
            json!({ "error": "not_connected", "message": "The machine just disconnected." }),
        )),
    }
}

#[derive(Deserialize)]
struct CommandBody {
    id: Uuid,
    command: Value,
}

#[derive(Deserialize)]
struct ControlBody {
    control: Value,
}

async fn stream_session(
    stream: Replay<TcpStream>,
    peer: SocketAddr,
    head: Head,
    ctx: Arc<Context>,
) -> anyhow::Result<()> {
    let session_str = head
        .path
        .trim_start_matches("/streams/")
        .trim_end_matches('/');
    let params = parse_query(&head.query);
    let machine = params.get("machine").cloned().unwrap_or_default();
    let presented = params.get("ticket").cloned().unwrap_or_default();

    let session = Uuid::parse_str(session_str).ok();
    let verdict = match session {
        None => Err((400, "session must be a uuid".to_string())),
        Some(_) => match ticket::verify(&ctx.secret, &machine, session_str, &presented, unix_now())
        {
            Ok(()) => Ok(()),
            Err(e) => Err((401, e.to_string())),
        },
    };

    let handle = match (&verdict, ctx.registry.get(&machine)) {
        (Ok(()), Some(handle)) => Some(handle),
        _ => None,
    };

    let decision = match (&verdict, &handle) {
        (Err(refusal), _) => Err(refusal.clone()),
        (Ok(()), None) => Err((404, "the machine is not connected".to_string())),
        (Ok(()), Some(_)) => Ok(()),
    };

    let socket =
        tokio_tungstenite::accept_hdr_async(stream, |_req: &Request, response: Response| {
            gate(&decision, response)
        })
        .await;

    let socket = match socket {
        Ok(s) => s,
        Err(e) => {
            debug!(%peer, error = %e, "stream attach refused");
            return Ok(());
        }
    };

    let (Some(session), Some(handle)) = (session, handle) else {
        return Ok(());
    };

    let (frames_tx, mut frames_rx) = mpsc::channel::<StreamFrame>(512);
    handle.attach_stream(session, frames_tx);
    info!(%peer, machine = %handle.uid, %session, "stream attached");

    let (mut sink, mut source) = socket.split();

    let reason = loop {
        tokio::select! {
            frame = frames_rx.recv() => {
                let Some(frame) = frame else { break "detached" };
                let eof = frame.eof;
                let text = match serde_json::to_string(&frame) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                if sink.send(Message::Text(text)).await.is_err() {
                    break "browser write failed";
                }

                if eof {
                    break "stream ended";
                }
            }
            incoming = tokio::time::timeout(STREAM_IDLE, source.next()) => {
                let frame = match incoming {
                    Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<BrowserInput>(&text) {
                        Ok(input) => StreamFrame {
                            session,
                            kind: input.kind,
                            data_b64: input.data_b64,
                            eof: input.eof,
                        },
                        Err(e) => {
                            debug!(%peer, error = %e, "ignoring malformed browser frame");
                            continue;
                        }
                    },
                    Ok(Some(Ok(Message::Binary(bytes)))) => {
                        use base64::Engine;

                        StreamFrame {
                            session,
                            kind: StreamKind::PtyInput,
                            data_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
                            eof: false,
                        }
                    }
                    Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break "browser closed",
                    Ok(Some(Ok(_))) => continue,
                    Ok(Some(Err(_))) => break "browser socket error",
                    Err(_) => break "browser idle",
                };

                if !matches!(frame.kind, StreamKind::PtyInput | StreamKind::PtyResize) {
                    continue;
                }

                let payload = match serde_json::to_value(&frame) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if handle.tx.try_send(Outgoing { kind: Kind::Stream, payload, id: None }).is_err() {
                    break "machine disconnected";
                }
            }
        }
    };

    handle.detach_stream(&session);

    if let Ok(payload) = serde_json::to_value(StreamFrame {
        session,
        kind: StreamKind::PtyInput,
        data_b64: String::new(),
        eof: true,
    }) {
        let _ = handle.tx.try_send(Outgoing {
            kind: Kind::Stream,
            payload,
            id: None,
        });
    }

    let _ = sink.close().await;
    info!(%peer, machine = %handle.uid, %session, %reason, "stream detached");

    Ok(())
}

fn gate(
    decision: &Result<(), (u16, String)>,
    response: Response,
) -> Result<Response, tokio_tungstenite::tungstenite::handshake::server::ErrorResponse> {
    match decision {
        Ok(()) => Ok(response),
        Err((status, message)) => Err(tokio_tungstenite::tungstenite::http::Response::builder()
            .status(*status)
            .body(Some(message.clone()))
            .unwrap_or_default()),
    }
}

#[derive(Deserialize)]
struct BrowserInput {
    kind: StreamKind,
    #[serde(default)]
    data_b64: String,
    #[serde(default)]
    eof: bool,
}

async fn read_head(tcp: &mut TcpStream) -> anyhow::Result<Option<Head>> {
    let mut raw = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];

    let end = loop {
        let n = tcp.read(&mut chunk).await?;

        if n == 0 {
            if raw.is_empty() {
                return Ok(None);
            }

            anyhow::bail!("connection closed mid-request");
        }

        raw.extend_from_slice(&chunk[..n]);

        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }

        if raw.len() > MAX_HEAD {
            anyhow::bail!("request head too large");
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);

    if !matches!(request.parse(&raw[..end])?, httparse::Status::Complete(_)) {
        anyhow::bail!("incomplete request head");
    }

    let method = request.method.unwrap_or_default().to_string();
    let target = request.path.unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut content_length = 0usize;
    let mut secret = None;
    let mut upgrade = false;

    for header in request.headers.iter() {
        let value = String::from_utf8_lossy(header.value);

        match header.name.to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.trim().parse().unwrap_or(0),
            "x-gateway-secret" => secret = Some(value.trim().to_string()),
            "upgrade" if value.trim().eq_ignore_ascii_case("websocket") => upgrade = true,
            _ => {}
        }
    }

    if content_length > MAX_BODY {
        anyhow::bail!("request body too large");
    }

    Ok(Some(Head {
        method,
        path: path.to_string(),
        query: query.to_string(),
        content_length,
        secret,
        websocket: upgrade,
        overflow: raw[end..].to_vec(),
        raw,
    }))
}

async fn read_json<T: serde::de::DeserializeOwned>(
    tcp: &mut TcpStream,
    content_length: usize,
    mut body: Vec<u8>,
) -> anyhow::Result<T> {
    while body.len() < content_length {
        let mut chunk = vec![0u8; (content_length - body.len()).min(64 * 1024)];
        let n = tokio::time::timeout(READ_TIMEOUT, tcp.read(&mut chunk)).await??;

        if n == 0 {
            anyhow::bail!("body ended early");
        }

        body.extend_from_slice(&chunk[..n]);
    }

    Ok(serde_json::from_slice(&body[..content_length])?)
}

async fn respond(tcp: &mut TcpStream, status: u16, body: &Value) -> anyhow::Result<()> {
    let text = body.to_string();
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        422 => "Unprocessable Content",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );

    tcp.write_all(response.as_bytes()).await?;
    tcp.shutdown().await?;

    Ok(())
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings_decode() {
        let params = parse_query("machine=abc&ticket=1.ff%20ee");

        assert_eq!(params["machine"], "abc");
        assert_eq!(params["ticket"], "1.ff ee");
    }

    #[tokio::test]
    async fn heads_parse_and_keep_body_overflow() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client
                .write_all(b"POST /machines/m1/commands?x=1 HTTP/1.1\r\nHost: g\r\nX-Gateway-Secret: s\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
            let _ = client.shutdown().await;
        });

        let (mut tcp, _) = listener.accept().await.unwrap();
        let head = read_head(&mut tcp).await.unwrap().unwrap();

        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/machines/m1/commands");
        assert_eq!(head.query, "x=1");
        assert_eq!(head.content_length, 2);
        assert_eq!(head.secret.as_deref(), Some("s"));
        assert!(!head.websocket);
        assert_eq!(head.overflow, b"{}");
    }
}
