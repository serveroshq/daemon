use daemon_http::{Client, HttpError, Trust};
use daemon_protocol::MachineFacts;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::{Identity, KeyMaterial};

#[derive(Debug, Error)]
pub enum EnrolError {
    #[error("{0}")]
    Network(#[from] HttpError),
    #[error(
        "the enrolment token has expired; create a new one in the panel (tokens last 15 minutes)"
    )]
    TokenExpired,
    #[error("the enrolment token was already used; create a new one in the panel")]
    TokenUsed,
    #[error("the enrolment token was not recognised; copy the full command from the panel again")]
    TokenInvalid,
    #[error("the panel refused this machine: {0}")]
    Refused(String),
    #[error("the panel answered with HTTP {status}: {body}")]
    Unexpected { status: u16, body: String },
    #[error("the panel's answer was missing {0}")]
    Incomplete(&'static str),
    #[error("{0}")]
    Identity(#[from] crate::keys::IdentityError),
}

#[derive(Debug, Serialize)]
pub struct EnrolRequest<'a> {
    pub token: &'a str,
    pub csr: &'a str,
    pub daemon_version: &'a str,
    pub protocol_majors: &'a [u16],
    pub facts: &'a MachineFacts,
}

#[derive(Debug, Deserialize)]
pub struct EnrolResponse {
    pub machine_id: String,
    pub certificate: String,
    pub ca: String,
    #[serde(default)]
    pub panel_host: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    code: String,
}

pub async fn enrol(
    panel_url: &str,
    token: &str,
    key: &KeyMaterial,
    hostname: &str,
    daemon_version: &str,
    facts: &MachineFacts,
) -> Result<(EnrolResponse, Identity), EnrolError> {
    let csr = key.certificate_request("pending", hostname)?;
    let client = Client::new(Trust::WebPki, format!("serverosd/{daemon_version} (enrol)"));
    let request = EnrolRequest {
        token,
        csr: &csr,
        daemon_version,
        protocol_majors: daemon_protocol::SUPPORTED_MAJORS,
        facts,
    };

    let response = client
        .post_json(
            &format!("{}/api/daemon/enrol", panel_url.trim_end_matches('/')),
            &request,
        )
        .await?;

    match response.status {
        200 | 201 => {}
        401 | 403 | 404 | 409 | 410 => {
            let body: ErrorBody = response.json().unwrap_or(ErrorBody {
                error: response.text(),
                code: String::new(),
            });

            return Err(match (response.status, body.code.as_str()) {
                (410, _) | (_, "token_expired") => EnrolError::TokenExpired,
                (409, _) | (_, "token_used") => EnrolError::TokenUsed,
                (404, _) | (_, "token_invalid") => EnrolError::TokenInvalid,
                _ => EnrolError::Refused(if body.error.is_empty() {
                    "no reason given".into()
                } else {
                    body.error
                }),
            });
        }
        status => {
            return Err(EnrolError::Unexpected {
                status,
                body: response.text(),
            })
        }
    }

    let answer: EnrolResponse = response
        .json()
        .map_err(|_| EnrolError::Incomplete("a JSON body"))?;

    if answer.certificate.trim().is_empty() {
        return Err(EnrolError::Incomplete("a certificate"));
    }

    if answer.ca.trim().is_empty() {
        return Err(EnrolError::Incomplete("the CA certificate"));
    }

    if answer.machine_id.trim().is_empty() {
        return Err(EnrolError::Incomplete("a machine id"));
    }

    let identity = Identity {
        key_pem: key.private_key_pem(),
        cert_pem: answer.certificate.clone(),
        ca_pem: answer.ca.clone(),
    };

    identity.cert_chain_der()?;
    identity.ca_der()?;

    Ok((answer, identity))
}
