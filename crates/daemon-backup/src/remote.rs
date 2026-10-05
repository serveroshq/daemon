use std::path::Path;

use daemon_http::{Client, Trust};
use daemon_jobs::Failure;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct S3Target {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
}

impl S3Target {
    pub fn host(&self) -> String {
        if self.path_style {
            self.endpoint.clone()
        } else {
            format!("{}.{}", self.bucket, self.endpoint)
        }
    }

    fn url(&self, key: &str) -> String {
        if self.path_style {
            format!("https://{}/{}/{}", self.endpoint, self.bucket, key)
        } else {
            format!("https://{}/{}", self.host(), key)
        }
    }

    fn canonical_uri(&self, key: &str) -> String {
        if self.path_style {
            format!("/{}/{}", self.bucket, uri_encode(key))
        } else {
            format!("/{}", uri_encode(key))
        }
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn uri_encode(input: &str) -> String {
    let mut out = String::new();

    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }

    out
}

pub fn sign_put(
    target: &S3Target,
    key: &str,
    body_sha256: &str,
    timestamp: &str,
) -> Vec<(String, String)> {
    let date = &timestamp[..8];
    let host = target.host();
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{body_sha256}\nx-amz-date:{timestamp}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "PUT\n{}\n\n{canonical_headers}\n{signed_headers}\n{body_sha256}",
        target.canonical_uri(key)
    );
    let scope = format!("{date}/{}/s3/aws4_request", target.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = hmac(
        format!("AWS4{}", target.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, target.region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

    vec![
        ("x-amz-date".into(), timestamp.into()),
        ("x-amz-content-sha256".into(), body_sha256.into()),
        ("Authorization".into(), format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}", target.access_key)),
    ]
}

pub async fn upload(
    target: &S3Target,
    key: &str,
    file: &Path,
    egress_ok: impl Fn(&str) -> bool,
) -> Result<String, Failure> {
    if !egress_ok(&target.host()) {
        return Err(Failure::new("upload", format!("{} is not a configured storage endpoint; the daemon only talks to the panel and configured storage", target.host())));
    }

    let body = std::fs::read(file)
        .map_err(|e| Failure::new("upload", format!("{}: {e}", file.display())))?;
    let body_hash = hex::encode(Sha256::digest(&body));
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .map_err(|e| Failure::new("upload", e.to_string()))?;
    let headers = sign_put(target, key, &body_hash, &timestamp);
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let client = Client::new(Trust::WebPki, "serverosd-backup")
        .with_timeout(std::time::Duration::from_secs(600));
    let response = client
        .put(&target.url(key), &header_refs, &body)
        .await
        .map_err(|e| Failure::new("upload", e.to_string()))?;

    if (200..300).contains(&response.status) {
        Ok(target.url(key))
    } else {
        Err(Failure::new(
            "upload",
            format!(
                "storage answered HTTP {}: {}",
                response.status,
                response.text().chars().take(300).collect::<String>()
            ),
        )
        .with_next_step("Check the bucket name, region, and credentials in the panel."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_a_deterministic_sigv4_authorization() {
        let target = S3Target {
            endpoint: "s3.eu-west-2.amazonaws.com".into(),
            region: "eu-west-2".into(),
            bucket: "backups".into(),
            access_key: "AKIAEXAMPLE".into(),
            secret_key: "secret".into(),
            path_style: false,
        };
        let headers = sign_put(
            &target,
            "app/snap.tar.gz",
            &hex::encode(Sha256::digest(b"")),
            "20260913T120000Z",
        );

        let auth = &headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap()
            .1;
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260913/eu-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="));
        assert_eq!(auth.len(), auth.rfind('=').unwrap() + 1 + 64);
        assert_eq!(
            sign_put(
                &target,
                "app/snap.tar.gz",
                &hex::encode(Sha256::digest(b"")),
                "20260913T120000Z"
            ),
            headers
        );
    }

    #[test]
    fn path_style_and_virtual_hosted_urls() {
        let mut target = S3Target {
            endpoint: "fsn1.your-objectstorage.com".into(),
            region: "fsn1".into(),
            bucket: "b".into(),
            access_key: "".into(),
            secret_key: "".into(),
            path_style: true,
        };
        assert_eq!(
            target.url("a b"),
            "https://fsn1.your-objectstorage.com/b/a b"
        );
        assert_eq!(target.canonical_uri("a b"), "/b/a%20b");

        target.path_style = false;
        assert_eq!(target.host(), "b.fsn1.your-objectstorage.com");
    }
}
