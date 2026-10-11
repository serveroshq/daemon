use std::sync::{Arc, Mutex};
use std::time::Duration;

use daemon_protocol::driver::{Inbound, Outbound};
use daemon_protocol::{Event, EventKind, Hello, MachineFacts, Severity, StreamFrame, StreamKind};
use daemon_transport::{Link, LinkEvent};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::CertificateDer;
use serveros_gateway::panel::PanelClient;
use serveros_gateway::registry::Registry;
use serveros_gateway::{run_listeners, ticket, tls, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;

const SECRET: &str = "test-secret-test-secret";

struct Pki {
    ca: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    ca_pem: String,
    gateway_cert: String,
    gateway_key: String,
    daemon_cert: String,
    daemon_key: String,
    panel_cert: String,
    panel_key: String,
}

fn make_pki() -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ServerOS Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let gateway_key = rcgen::KeyPair::generate().unwrap();
    let mut gateway_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    gateway_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let gateway = gateway_params
        .signed_by(&gateway_key, &ca, &ca_key)
        .unwrap();

    let (daemon_cert, daemon_key) = issue_daemon(&ca, &ca_key, vec![0x0a, 0xbc, 0xde]);

    let panel_key = rcgen::KeyPair::generate().unwrap();
    let panel_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let panel = panel_params.self_signed(&panel_key).unwrap();

    Pki {
        ca_pem: ca.pem(),
        gateway_cert: gateway.pem(),
        gateway_key: gateway_key.serialize_pem(),
        daemon_cert,
        daemon_key,
        panel_cert: panel.pem(),
        panel_key: panel_key.serialize_pem(),
        ca,
        ca_key,
    }
}

fn issue_daemon(
    ca: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    serial: Vec<u8>,
) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["vps.example".into()]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.serial_number = Some(rcgen::SerialNumber::from(serial));
    let cert = params.signed_by(&key, ca, ca_key).unwrap();

    (cert.pem(), key.serialize_pem())
}

#[derive(Default)]
struct PanelLog {
    hello_serials: Vec<String>,
    ingested: Vec<serde_json::Value>,
    closed: Vec<String>,
}

async fn fake_panel(cert_pem: &str, key_pem: &str, log: Arc<Mutex<PanelLog>>) -> u16 {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .unwrap()
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let log = Arc::clone(&log);

            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut raw = Vec::new();
                let mut chunk = [0u8; 4096];

                let (head_end, content_length) = loop {
                    let n = tls.read(&mut chunk).await.unwrap();
                    raw.extend_from_slice(&chunk[..n]);

                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..pos]).to_string();
                        let length = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (pos + 4, length);
                    }
                };

                while raw.len() < head_end + content_length {
                    let n = tls.read(&mut chunk).await.unwrap();
                    raw.extend_from_slice(&chunk[..n]);
                }

                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let path = head
                    .lines()
                    .next()
                    .unwrap()
                    .split(' ')
                    .nth(1)
                    .unwrap()
                    .to_string();
                let secret_ok = head
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case(&format!("x-gateway-secret: {SECRET}")));
                let body: serde_json::Value =
                    serde_json::from_slice(&raw[head_end..head_end + content_length])
                        .unwrap_or_default();

                let (status, reply) = if !secret_ok {
                    (401, serde_json::json!({"error": "bad secret"}))
                } else if path == "/api/gateway/hello" {
                    let serial = body["serial"].as_str().unwrap_or_default().to_string();
                    log.lock().unwrap().hello_serials.push(serial.clone());

                    if serial == "abcde" {
                        (
                            200,
                            serde_json::json!({"machine_id": "m-1", "ack": {"major": 1, "panel_version": "test", "last_seen_seq": null, "mode": "managed"}}),
                        )
                    } else {
                        (
                            403,
                            serde_json::json!({"error": "No machine enrolled with that certificate.", "code": "certificate_unknown"}),
                        )
                    }
                } else if path.ends_with("/ingest") {
                    let mut guard = log.lock().unwrap();
                    for env in body["envelopes"].as_array().cloned().unwrap_or_default() {
                        guard.ingested.push(env);
                    }
                    (200, serde_json::json!({"applied": 1, "ignored": 0}))
                } else if path.ends_with("/closed") {
                    log.lock().unwrap().closed.push(path.clone());
                    (200, serde_json::json!({"ok": true}))
                } else {
                    (404, serde_json::json!({"error": "nope"}))
                };

                let text = reply.to_string();
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    port
}

async fn gateway(pki: &Pki, panel_port: u16) -> (u16, u16, Arc<Context>) {
    let acceptor = TlsAcceptor::from(
        tls::server_config(
            pki.ca_pem.as_bytes(),
            pki.gateway_cert.as_bytes(),
            pki.gateway_key.as_bytes(),
        )
        .unwrap(),
    );
    let context = Arc::new(Context {
        panel: PanelClient::new(
            format!("https://localhost:{panel_port}"),
            SECRET.into(),
            Some(pki.panel_cert.as_bytes()),
        )
        .unwrap(),
        registry: Registry::default(),
        secret: SECRET.into(),
    });
    let daemons = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let daemon_port = daemons.local_addr().unwrap().port();
    let internal_port = internal.local_addr().unwrap().port();
    let ctx = Arc::clone(&context);

    tokio::spawn(async move { run_listeners(daemons, internal, acceptor, ctx).await });

    (daemon_port, internal_port, context)
}

fn hello() -> Hello {
    Hello {
        machine_id: String::new(),
        daemon_version: "0.1.0-test".into(),
        daemon_commit: "abc".into(),
        channel: "stable".into(),
        supported_majors: vec![1],
        facts: MachineFacts::default(),
        oldest_local_sample_ts: None,
        log_ip_masking: None,
    }
}

fn heartbeat_source() -> daemon_transport::link::HeartbeatSource {
    Arc::new(|| daemon_protocol::Heartbeat {
        uptime_secs: 1,
        daemon_version: "0.1.0-test".into(),
        daemon_uptime_secs: 1,
        load_1m: 0.5,
        running_jobs: 0,
    })
}

async fn internal_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
    secret: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let body_text = body.map(|b| b.to_string()).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: gateway\r\nContent-Length: {}\r\n",
        body_text.len()
    );

    if let Some(secret) = secret {
        request.push_str(&format!("X-Gateway-Secret: {secret}\r\n"));
    }

    request.push_str("\r\n");
    request.push_str(&body_text);
    tcp.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tcp.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let status: u16 = text.split(' ').nth(1).unwrap().parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("{}");

    (status, serde_json::from_str(body).unwrap())
}

async fn wait_for<F: Fn() -> bool>(what: &str, check: F) {
    for _ in 0..100 {
        if check() {
            return;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn a_daemon_connects_gets_commands_and_streams_to_a_browser() {
    let pki = make_pki();
    let log = Arc::new(Mutex::new(PanelLog::default()));
    let panel_port = fake_panel(&pki.panel_cert, &pki.panel_key, Arc::clone(&log)).await;
    let (daemon_port, internal_port, context) = gateway(&pki, panel_port).await;

    let (status, _) = internal_request(internal_port, "GET", "/machines", None, None).await;
    assert_eq!(status, 401);
    let (status, body) =
        internal_request(internal_port, "GET", "/machines", None, Some(SECRET)).await;
    assert_eq!(status, 200);
    assert_eq!(body["machines"].as_array().unwrap().len(), 0);

    let identity = daemon_identity::Identity {
        key_pem: pki.daemon_key.clone(),
        cert_pem: pki.daemon_cert.clone(),
        ca_pem: pki.ca_pem.clone(),
    };

    let mut link = Link::connect(
        &format!("wss://localhost:{daemon_port}/daemon/control"),
        &identity,
        hello(),
        heartbeat_source(),
    )
    .await
    .expect("the daemon link should come up");

    assert_eq!(link.major, 1);
    assert_eq!(link.ack.panel_version, "test");
    assert_eq!(log.lock().unwrap().hello_serials, vec!["abcde".to_string()]);

    let (status, body) =
        internal_request(internal_port, "GET", "/machines", None, Some(SECRET)).await;
    assert_eq!(status, 200);
    assert_eq!(body["machines"], serde_json::json!(["m-1"]));

    let job_id = uuid::Uuid::new_v4();
    let (status, body) = internal_request(
        internal_port,
        "POST",
        "/machines/m-1/commands",
        Some(serde_json::json!({
            "id": job_id,
            "command": {"actor": {"kind": "user", "name": "dylan"}, "confirmed": false, "job": {"type": "discover"}}
        })),
        Some(SECRET),
    )
    .await;
    assert_eq!(status, 202, "{body}");

    let received = tokio::time::timeout(Duration::from_secs(5), link.rx.recv())
        .await
        .unwrap()
        .unwrap();
    match received {
        LinkEvent::Message(Inbound::Command { id, command }) => {
            assert_eq!(id, job_id);
            assert_eq!(command.actor.name, "dylan");
        }
        other => panic!("expected a command, got {other:?}"),
    }

    let (status, _) = internal_request(
        internal_port,
        "POST",
        "/machines/nobody/commands",
        Some(serde_json::json!({"id": uuid::Uuid::new_v4(), "command": {}})),
        Some(SECRET),
    )
    .await;
    assert_eq!(status, 404);

    link.tx
        .send(Outbound::Event(Event {
            kind: EventKind::DiskThreshold,
            severity: Severity::Warning,
            summary: "Disk is 91% full".into(),
            detail: None,
            service: None,
            data: Default::default(),
            suggested_action: None,
        }))
        .await
        .unwrap();

    wait_for("the event to reach the panel", || {
        log.lock()
            .unwrap()
            .ingested
            .iter()
            .any(|e| e["kind"] == "event")
    })
    .await;

    let session = uuid::Uuid::new_v4();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let good = ticket::sign(SECRET, "m-1", &session.to_string(), now + 60);
    let bad = ticket::sign(
        "wrong-secret-wrong-secret",
        "m-1",
        &session.to_string(),
        now + 60,
    );

    let refused = tokio_tungstenite::connect_async(format!(
        "ws://127.0.0.1:{internal_port}/streams/{session}?machine=m-1&ticket={bad}"
    ))
    .await;
    assert!(refused.is_err(), "a badly signed ticket must not attach");

    let (mut browser, _) = tokio_tungstenite::connect_async(format!(
        "ws://127.0.0.1:{internal_port}/streams/{session}?machine=m-1&ticket={good}"
    ))
    .await
    .expect("a good ticket attaches");

    wait_for("the stream to register", || {
        context
            .registry
            .get("m-1")
            .map(|h| h.stream_count())
            .unwrap_or(0)
            == 1
    })
    .await;

    link.tx
        .send(Outbound::Stream(StreamFrame {
            session,
            kind: StreamKind::PtyOutput,
            data_b64: "JCA=".into(),
            eof: false,
        }))
        .await
        .unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(5), browser.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let frame: StreamFrame = serde_json::from_str(frame.to_text().unwrap()).unwrap();
    assert_eq!(frame.kind, StreamKind::PtyOutput);
    assert_eq!(frame.data_b64, "JCA=");

    browser
        .send(Message::Text(
            serde_json::json!({"kind": "pty_input", "data_b64": "bHMK"}).to_string(),
        ))
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), link.rx.recv())
        .await
        .unwrap()
        .unwrap();
    match received {
        LinkEvent::Message(Inbound::Stream(frame)) => {
            assert_eq!(frame.session, session);
            assert_eq!(frame.kind, StreamKind::PtyInput);
            assert_eq!(frame.data_b64, "bHMK");
        }
        other => panic!("expected pty input, got {other:?}"),
    }

    drop(browser);
    drop(link);

    wait_for("the panel to hear the close", || {
        !log.lock().unwrap().closed.is_empty()
    })
    .await;
    assert_eq!(context.registry.len(), 0);
}

#[tokio::test]
async fn a_certificate_the_panel_does_not_know_is_refused() {
    let pki = make_pki();
    let log = Arc::new(Mutex::new(PanelLog::default()));
    let panel_port = fake_panel(&pki.panel_cert, &pki.panel_key, Arc::clone(&log)).await;
    let (daemon_port, _internal_port, context) = gateway(&pki, panel_port).await;

    let (cert_pem, key_pem) = issue_daemon(&pki.ca, &pki.ca_key, vec![0x99, 0x99]);
    let identity = daemon_identity::Identity {
        key_pem,
        cert_pem,
        ca_pem: pki.ca_pem.clone(),
    };

    let result = Link::connect(
        &format!("wss://localhost:{daemon_port}/daemon/control"),
        &identity,
        hello(),
        heartbeat_source(),
    )
    .await;

    assert!(
        result.is_err(),
        "the gateway must close the link when the panel refuses"
    );
    assert_eq!(log.lock().unwrap().hello_serials.len(), 1);
    assert_ne!(log.lock().unwrap().hello_serials[0], "abcde");
    assert_eq!(context.registry.len(), 0);
}

#[tokio::test]
async fn a_certificate_from_another_ca_never_reaches_the_panel() {
    let pki = make_pki();
    let other = make_pki();
    let log = Arc::new(Mutex::new(PanelLog::default()));
    let panel_port = fake_panel(&pki.panel_cert, &pki.panel_key, Arc::clone(&log)).await;
    let (daemon_port, _internal_port, _context) = gateway(&pki, panel_port).await;

    let identity = daemon_identity::Identity {
        key_pem: other.daemon_key.clone(),
        cert_pem: other.daemon_cert.clone(),
        ca_pem: pki.ca_pem.clone(),
    };

    let result = Link::connect(
        &format!("wss://localhost:{daemon_port}/daemon/control"),
        &identity,
        hello(),
        heartbeat_source(),
    )
    .await;

    assert!(result.is_err());
    assert!(log.lock().unwrap().hello_serials.is_empty());
}
