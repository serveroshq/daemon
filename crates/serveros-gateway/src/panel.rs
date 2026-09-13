//! The gateway's client for the panel: who is this certificate, here is a
//! batch of envelopes, that machine hung up. Authenticated with the shared
//! secret in `X-Gateway-Secret`.

use daemon_http::{Client, HttpError, Trust};
use daemon_protocol::{Envelope, Hello, HelloAck};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PanelError {
    /// The panel answered, and said no. `code` is the machine-readable
    /// reason (certificate_unknown, certificate_expired, protocol_unsupported).
    #[error("{message} ({code})")]
    Refused {
        status: u16,
        code: String,
        message: String,
    },
    #[error("the panel answered HTTP {0}")]
    Status(u16),
    #[error("{0}")]
    Http(#[from] HttpError),
    #[error("the panel's reply was not understood: {0}")]
    Malformed(String),
}

#[derive(Debug, Deserialize)]
pub struct HelloReply {
    pub machine_id: String,
    pub ack: HelloAck,
}

#[derive(Debug, Deserialize)]
struct Refusal {
    #[serde(default)]
    error: String,
    #[serde(default)]
    code: String,
}

pub struct PanelClient {
    base: String,
    secret: String,
    http: Client,
}

impl PanelClient {
    pub fn new(base: String, secret: String, ca_pem: Option<&[u8]>) -> Result<Self, PanelError> {
        let trust = match ca_pem {
            Some(pem) => Trust::pinned_pem(pem)?,
            None => Trust::WebPki,
        };

        Ok(Self {
            base,
            secret,
            http: Client::new(
                trust,
                format!("serveros-gateway/{}", env!("CARGO_PKG_VERSION")),
            )
            .with_timeout(std::time::Duration::from_secs(15))
            .with_max_body(4 * 1024 * 1024),
        })
    }

    pub async fn hello(&self, serial: &str, hello: &Hello) -> Result<HelloReply, PanelError> {
        let response = self
            .post(
                "/api/gateway/hello",
                &serde_json::json!({ "serial": serial, "hello": hello }),
            )
            .await?;

        match response.status {
            200 => response
                .json::<HelloReply>()
                .map_err(|e| PanelError::Malformed(e.to_string())),
            status => Err(refusal(status, &response)),
        }
    }

    pub async fn ingest(&self, uid: &str, envelopes: &[Envelope]) -> Result<(), PanelError> {
        let response = self
            .post(
                &format!("/api/gateway/machines/{uid}/ingest"),
                &serde_json::json!({ "envelopes": envelopes }),
            )
            .await?;

        match response.status {
            200 => Ok(()),
            status => Err(refusal(status, &response)),
        }
    }

    pub async fn closed(&self, uid: &str) -> Result<(), PanelError> {
        let response = self
            .post(
                &format!("/api/gateway/machines/{uid}/closed"),
                &serde_json::json!({}),
            )
            .await?;

        match response.status {
            200 => Ok(()),
            status => Err(refusal(status, &response)),
        }
    }

    async fn post<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<daemon_http::Response, PanelError> {
        Ok(self
            .http
            .post_json_with_headers(
                &format!("{}{path}", self.base),
                &[
                    ("X-Gateway-Secret", self.secret.as_str()),
                    ("Accept", "application/json"),
                ],
                body,
            )
            .await?)
    }
}

fn refusal(status: u16, response: &daemon_http::Response) -> PanelError {
    match response.json::<Refusal>() {
        Ok(r) if !r.code.is_empty() || !r.error.is_empty() => PanelError::Refused {
            status,
            code: if r.code.is_empty() {
                format!("http_{status}")
            } else {
                r.code
            },
            message: r.error,
        },
        _ => PanelError::Status(status),
    }
}
