use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("could not read the CA bundle: {0}")]
    Ca(String),
    #[error("could not read the server certificate or key: {0}")]
    Identity(String),
    #[error("could not build the TLS configuration: {0}")]
    Config(String),
}

pub fn server_config(
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<ServerConfig>, TlsError> {
    let mut roots = RootCertStore::empty();
    let cas: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &ca_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Ca(e.to_string()))?;

    if cas.is_empty() {
        return Err(TlsError::Ca(
            "no certificates found in the CA bundle".into(),
        ));
    }

    for ca in cas {
        roots.add(ca).map_err(|e| TlsError::Ca(e.to_string()))?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| TlsError::Config(e.to_string()))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Identity(e.to_string()))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| TlsError::Identity(e.to_string()))?
        .ok_or_else(|| TlsError::Identity("no private key in the key file".into()))?;

    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;

    Ok(Arc::new(config))
}

pub fn peer_serial(certs: Option<&[CertificateDer<'_>]>) -> Option<String> {
    let leaf = certs?.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;

    Some(normalise_serial(&hex::encode(cert.raw_serial())))
}

pub fn normalise_serial(serial_hex: &str) -> String {
    let cleaned = serial_hex.replace(':', "").to_ascii_lowercase();
    let trimmed = cleaned.trim_start_matches('0');

    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials_match_the_panel_normalisation() {
        assert_eq!(normalise_serial("00:AB:CD"), "abcd");
        assert_eq!(normalise_serial("0ABCD"), "abcd");
        assert_eq!(normalise_serial("00"), "0");
    }

    #[test]
    fn builds_a_server_config_that_demands_client_certificates() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["ServerOS Test CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["gateway.test".into()]).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();

        let config = server_config(
            ca.pem().as_bytes(),
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();

        assert!(config.max_fragment_size.is_none());

        let serial = peer_serial(Some(&[cert.der().clone()])).unwrap();
        assert!(serial.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!serial.starts_with('0') || serial == "0");
    }

    #[test]
    fn a_bundle_without_certificates_is_refused() {
        assert!(matches!(server_config(b"", b"", b""), Err(TlsError::Ca(_))));
    }
}
