//! Mutual TLS: our certificate to the panel, the pinned CA for the panel.
//! No system roots are consulted; a panel certificate not signed by the
//! CA we were given at enrolment is a hard failure.

use std::sync::Arc;

use daemon_identity::{Identity, IdentityError};
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("{0}")]
    Identity(#[from] IdentityError),
    #[error("could not build the TLS configuration: {0}")]
    Config(String),
}

pub fn client_config(identity: &Identity) -> Result<Arc<ClientConfig>, TlsError> {
    let mut roots = RootCertStore::empty();

    for ca in identity.ca_der()? {
        roots.add(ca).map_err(|e| TlsError::Config(e.to_string()))?;
    }

    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(identity.cert_chain_der()?, identity.private_key_der()?)
        .map_err(|e| TlsError::Config(e.to_string()))?;

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_tls13_only_client_config_from_an_identity() {
        let key = rcgen_key();
        let params = rcgen::CertificateParams::new(vec!["vps.example".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let identity = Identity {
            key_pem: key.serialize_pem(),
            cert_pem: cert.pem(),
            ca_pem: cert.pem(),
        };

        let config = client_config(&identity).unwrap();

        assert!(config.client_auth_cert_resolver.has_certs());
    }

    fn rcgen_key() -> rcgen::KeyPair {
        rcgen::KeyPair::generate().unwrap()
    }
}
