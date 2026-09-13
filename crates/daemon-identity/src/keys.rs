use std::path::Path;

use daemon_core::Paths;
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("could not generate a keypair: {0}")]
    Generate(String),
    #[error("could not build the certificate request: {0}")]
    Csr(String),
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not write {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("{path} does not contain a usable {what}")]
    Malformed { path: String, what: &'static str },
    #[error("client certificate has expired or is not yet valid")]
    CertificateExpired,
}

/// A freshly generated private key, held only long enough to enrol and
/// write it to disk.
pub struct KeyMaterial {
    key_pair: KeyPair,
}

impl KeyMaterial {
    /// ECDSA P-256. Small, fast, and what every TLS stack accepts.
    pub fn generate() -> Result<Self, IdentityError> {
        KeyPair::generate()
            .map(|key_pair| Self { key_pair })
            .map_err(|e| IdentityError::Generate(e.to_string()))
    }

    pub fn from_pem(pem: &str) -> Result<Self, IdentityError> {
        KeyPair::from_pem(pem)
            .map(|key_pair| Self { key_pair })
            .map_err(|_| IdentityError::Malformed {
                path: "daemon.key".into(),
                what: "private key",
            })
    }

    pub fn private_key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// A CSR naming the machine. The panel decides what the certificate
    /// actually says; the CN here is a hint for its logs.
    pub fn certificate_request(
        &self,
        machine_id: &str,
        hostname: &str,
    ) -> Result<String, IdentityError> {
        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| IdentityError::Csr(e.to_string()))?;
        params
            .distinguished_name
            .push(DnType::CommonName, machine_id);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "ServerOS daemon");

        params
            .serialize_request(&self.key_pair)
            .map(|csr| csr.pem().unwrap_or_default())
            .map_err(|e| IdentityError::Csr(e.to_string()))
    }

    /// Write the key with mode 0600, root-owned by virtue of who runs this.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        write_private(path, self.private_key_pem().as_bytes())
    }
}

/// The full credential set the transport loads on every start.
#[derive(Clone)]
pub struct Identity {
    pub key_pem: String,
    pub cert_pem: String,
    pub ca_pem: String,
}

impl Identity {
    pub fn load(paths: &Paths) -> Result<Self, IdentityError> {
        Ok(Self {
            key_pem: read(&paths.private_key())?,
            cert_pem: read(&paths.client_cert())?,
            ca_pem: read(&paths.pinned_ca())?,
        })
    }

    pub fn exists(paths: &Paths) -> bool {
        paths.private_key().exists() && paths.client_cert().exists() && paths.pinned_ca().exists()
    }

    pub fn save(&self, paths: &Paths) -> Result<(), IdentityError> {
        write_private(&paths.private_key(), self.key_pem.as_bytes())?;
        write_plain(&paths.client_cert(), self.cert_pem.as_bytes())?;
        write_plain(&paths.pinned_ca(), self.ca_pem.as_bytes())
    }

    pub fn private_key_der(&self) -> Result<PrivateKeyDer<'static>, IdentityError> {
        rustls_pemfile::private_key(&mut self.key_pem.as_bytes())
            .ok()
            .flatten()
            .ok_or(IdentityError::Malformed {
                path: "daemon.key".into(),
                what: "private key",
            })
    }

    pub fn cert_chain_der(&self) -> Result<Vec<CertificateDer<'static>>, IdentityError> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut self.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|_| IdentityError::Malformed {
                path: "daemon.crt".into(),
                what: "certificate",
            })?;

        if certs.is_empty() {
            return Err(IdentityError::Malformed {
                path: "daemon.crt".into(),
                what: "certificate",
            });
        }

        Ok(certs)
    }

    pub fn ca_der(&self) -> Result<Vec<CertificateDer<'static>>, IdentityError> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut self.ca_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|_| IdentityError::Malformed {
                path: "ca.crt".into(),
                what: "CA certificate",
            })?;

        if certs.is_empty() {
            return Err(IdentityError::Malformed {
                path: "ca.crt".into(),
                what: "CA certificate",
            });
        }

        Ok(certs)
    }

    /// When the client certificate stops being valid, so the daemon can
    /// warn ahead of time and ask for a rotation.
    pub fn certificate_not_after(&self) -> Result<i64, IdentityError> {
        let chain = self.cert_chain_der()?;
        let (_, cert) = x509_parser::parse_x509_certificate(&chain[0]).map_err(|_| {
            IdentityError::Malformed {
                path: "daemon.crt".into(),
                what: "certificate",
            }
        })?;

        Ok(cert.validity().not_after.timestamp())
    }

    pub fn check_validity(&self, now: i64) -> Result<(), IdentityError> {
        let chain = self.cert_chain_der()?;
        let (_, cert) = x509_parser::parse_x509_certificate(&chain[0]).map_err(|_| {
            IdentityError::Malformed {
                path: "daemon.crt".into(),
                what: "certificate",
            }
        })?;
        let validity = cert.validity();

        if now < validity.not_before.timestamp() || now > validity.not_after.timestamp() {
            return Err(IdentityError::CertificateExpired);
        }

        Ok(())
    }
}

fn read(path: &Path) -> Result<String, IdentityError> {
    std::fs::read_to_string(path).map_err(|source| IdentityError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn write_plain(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    std::fs::write(path, bytes).map_err(|source| IdentityError::Write {
        path: path.display().to_string(),
        source,
    })
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| IdentityError::Write {
                path: path.display().to_string(),
                source,
            })?;

        file.write_all(bytes)
            .map_err(|source| IdentityError::Write {
                path: path.display().to_string(),
                source,
            })?;
        let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));

        Ok(())
    }

    #[cfg(not(unix))]
    {
        write_plain(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_key_and_a_csr_naming_the_machine() {
        let key = KeyMaterial::generate().unwrap();
        let csr = key.certificate_request("mch_123", "vps.example").unwrap();

        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(key.private_key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn private_key_is_written_root_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.key");
        KeyMaterial::generate().unwrap().save(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        assert!(KeyMaterial::from_pem(&std::fs::read_to_string(&path).unwrap()).is_ok());
    }

    #[test]
    fn identity_round_trips_and_parses_validity() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(&paths.config_dir).unwrap();

        // Self-signed stand-in for what the panel would issue.
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["vps.example".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();

        let identity = Identity {
            key_pem: key.serialize_pem(),
            cert_pem: cert.pem(),
            ca_pem: cert.pem(),
        };
        identity.save(&paths).unwrap();

        let loaded = Identity::load(&paths).unwrap();
        assert!(loaded.private_key_der().is_ok());
        assert_eq!(loaded.cert_chain_der().unwrap().len(), 1);
        assert!(loaded
            .check_validity(time::OffsetDateTime::now_utc().unix_timestamp())
            .is_ok());
        assert!(
            loaded.certificate_not_after().unwrap()
                > time::OffsetDateTime::now_utc().unix_timestamp()
        );
    }
}
