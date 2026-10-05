use std::collections::BTreeSet;
use std::path::Path;

use daemon_protocol::CertificateInfo;

pub fn parse_certificate(pem: &[u8], path: &str) -> Option<CertificateInfo> {
    let der = rustls_pemfile::certs(&mut &pem[..]).next()?.ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;

    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Some(CertificateInfo {
        path: path.into(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_after: cert.validity().not_after.timestamp(),
        names,
        renewal: None,
    })
}

pub fn read_certificate(path: &Path) -> Option<CertificateInfo> {
    let name = path.file_name()?.to_str()?;

    if name.contains("privkey") || name.ends_with(".key") {
        return None;
    }

    let bytes = std::fs::read(path).ok()?;

    if bytes.windows(11).any(|w| w == b"PRIVATE KEY") {
        return None;
    }

    parse_certificate(&bytes, &path.to_string_lossy())
}

pub fn renewal_method(cert_path: &str) -> Option<String> {
    if !cert_path.starts_with("/etc/letsencrypt/") {
        return None;
    }

    if Path::new("/etc/letsencrypt/renewal").is_dir() {
        if Path::new("/run/systemd/system/certbot.timer").exists()
            || Path::new("/lib/systemd/system/certbot.timer").exists()
        {
            return Some("certbot (systemd timer)".into());
        }
        return Some("certbot".into());
    }

    Some("letsencrypt (unknown renewer)".into())
}

pub fn discover(referenced: &BTreeSet<String>) -> Vec<CertificateInfo> {
    let mut paths: BTreeSet<String> = referenced.clone();

    if let Ok(entries) = std::fs::read_dir("/etc/letsencrypt/live") {
        for entry in entries.flatten().take(200) {
            let fullchain = entry.path().join("fullchain.pem");
            if fullchain.is_file() {
                paths.insert(fullchain.to_string_lossy().into_owned());
            }
        }
    }

    paths
        .iter()
        .filter_map(|p| {
            let mut info = read_certificate(Path::new(p))?;
            info.renewal = renewal_method(p);
            Some(info)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_self_signed_certificate_and_its_names() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["shop.example".into(), "www.shop.example".into()])
                .unwrap();
        let cert = params.self_signed(&key).unwrap();

        let info = parse_certificate(cert.pem().as_bytes(), "/tmp/cert.pem").unwrap();

        assert_eq!(info.names, vec!["shop.example", "www.shop.example"]);
        assert!(info.not_after > time::OffsetDateTime::now_utc().unix_timestamp());
    }

    #[test]
    fn never_reads_private_key_files() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("privkey.pem");
        std::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let sneaky = dir.path().join("cert.pem");
        std::fs::write(
            &sneaky,
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        assert!(read_certificate(&key_path).is_none());
        assert!(read_certificate(&sneaky).is_none());
    }
}
