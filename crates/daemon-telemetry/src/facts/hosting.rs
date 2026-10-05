use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use daemon_protocol::HostingFacts;
use serde_json::Value;

const METADATA: &str = "169.254.169.254:80";
const TIMEOUT: Duration = Duration::from_millis(150);
const MAX_RESPONSE: u64 = 16 * 1024;

pub(super) fn detect() -> HostingFacts {
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return HostingFacts::default();
    }

    probe().unwrap_or_default()
}

fn probe() -> Option<HostingFacts> {
    if let Some(token) = request(
        "PUT",
        "/latest/api/token",
        &[("X-aws-ec2-metadata-token-ttl-seconds", "60")],
    ) {
        let token = token.trim();
        if !token.is_empty() && token.len() <= 256 && token.bytes().all(|c| c.is_ascii_graphic()) {
            if let Some(body) = request(
                "GET",
                "/latest/dynamic/instance-identity/document",
                &[("X-aws-ec2-metadata-token", token)],
            ) {
                if let Some(facts) = parse_aws(&body) {
                    return Some(facts);
                }
            }
        }
    }

    if let Some(zone) = request(
        "GET",
        "/computeMetadata/v1/instance/zone",
        &[("Metadata-Flavor", "Google")],
    ) {
        if let Some(mut facts) = parse_google(&zone) {
            facts.instance_type = request(
                "GET",
                "/computeMetadata/v1/instance/machine-type",
                &[("Metadata-Flavor", "Google")],
            )
            .and_then(|v| safe_component(v.rsplit('/').next().unwrap_or("")));
            return Some(facts);
        }
    }

    if let Some(location) = request(
        "GET",
        "/metadata/instance/compute/location?api-version=2021-02-01&format=text",
        &[("Metadata", "true")],
    ) {
        if let Some(mut facts) = hosting("Azure", Some(&location), None, None) {
            facts.zone = request(
                "GET",
                "/metadata/instance/compute/zone?api-version=2021-02-01&format=text",
                &[("Metadata", "true")],
            )
            .and_then(|v| safe_component(&v));
            facts.instance_type = request(
                "GET",
                "/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text",
                &[("Metadata", "true")],
            )
            .and_then(|v| safe_component(&v));
            return Some(facts);
        }
    }

    if let Some(zone) = request("GET", "/hetzner/v1/metadata/availability-zone", &[]) {
        if let Some(mut facts) = hosting("Hetzner", None, Some(&zone), None) {
            facts.region =
                request("GET", "/hetzner/v1/metadata/region", &[]).and_then(|v| safe_component(&v));
            return Some(facts);
        }
    }

    if let Some(region) = request("GET", "/metadata/v1/region", &[]) {
        if let Some(facts) = hosting("DigitalOcean", Some(&region), None, None) {
            return Some(facts);
        }
    }

    if let Some(token) = request(
        "PUT",
        "/v1/token",
        &[("Metadata-Token-Expiry-Seconds", "60")],
    ) {
        let token = token.trim();
        if !token.is_empty() && token.len() <= 256 && token.bytes().all(|c| c.is_ascii_graphic()) {
            if let Some(body) = request(
                "GET",
                "/v1/instance",
                &[("Metadata-Token", token), ("Accept", "application/json")],
            ) {
                if let Some(facts) = parse_linode(&body) {
                    return Some(facts);
                }
            }
        }
    }

    None
}

fn parse_aws(body: &str) -> Option<HostingFacts> {
    let json: Value = serde_json::from_str(body).ok()?;
    let region = json.get("region")?.as_str()?;
    let zone = json.get("availabilityZone").and_then(Value::as_str);
    let instance_type = json.get("instanceType").and_then(Value::as_str);
    hosting("AWS", Some(region), zone, instance_type)
}

fn parse_google(zone: &str) -> Option<HostingFacts> {
    let zone = zone.trim().rsplit('/').next()?;
    let (region, suffix) = zone.rsplit_once('-')?;
    if !region.bytes().last()?.is_ascii_digit()
        || suffix.len() != 1
        || !suffix.bytes().all(|c| c.is_ascii_lowercase())
    {
        return None;
    }
    hosting("Google Cloud", Some(region), Some(zone), None)
}

fn parse_linode(body: &str) -> Option<HostingFacts> {
    let json: Value = serde_json::from_str(body).ok()?;
    hosting(
        "Linode",
        json.get("region")?.as_str(),
        None,
        json.get("type").and_then(Value::as_str),
    )
}

fn hosting(
    provider: &str,
    region: Option<&str>,
    zone: Option<&str>,
    instance_type: Option<&str>,
) -> Option<HostingFacts> {
    let region = region.and_then(safe_component);
    let zone = zone.and_then(safe_component);
    if region.is_none() && zone.is_none() {
        return None;
    }
    Some(HostingFacts {
        provider: Some(provider.into()),
        region,
        zone,
        instance_type: instance_type.and_then(safe_component),
        source: Some("instance_metadata".into()),
    })
}

fn safe_component(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)))
    .then(|| value.to_owned())
}

fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> Option<String> {
    let address: SocketAddr = METADATA.parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT).ok()?;
    stream.set_read_timeout(Some(TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\nContent-Length: 0\r\n"
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut bytes = Vec::new();
    stream.take(MAX_RESPONSE + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return None;
    }
    let response = String::from_utf8(bytes).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    if !head.lines().next()?.starts_with("HTTP/1.1 200 ")
        && !head.lines().next()?.starts_with("HTTP/1.0 200 ")
    {
        return None;
    }
    if head.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("transfer-encoding: chunked")
    }) {
        return decode_chunked(body);
    }
    Some(body.to_owned())
}

fn decode_chunked(mut body: &str) -> Option<String> {
    let mut decoded = String::new();
    loop {
        let (size, remainder) = body.split_once("\r\n")?;
        let size = usize::from_str_radix(size.split(';').next()?, 16).ok()?;
        if size == 0 {
            return Some(decoded);
        }
        let content = remainder.get(..size)?;
        decoded.push_str(content);
        body = remainder.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_provider_regions() {
        let aws = parse_aws(
            r#"{"region":"eu-west-2","availabilityZone":"eu-west-2a","instanceType":"t3.small"}"#,
        )
        .unwrap();
        assert_eq!(aws.provider.as_deref(), Some("AWS"));
        assert_eq!(aws.zone.as_deref(), Some("eu-west-2a"));
        assert_eq!(
            parse_google("projects/123/zones/europe-west2-b")
                .unwrap()
                .region
                .as_deref(),
            Some("europe-west2")
        );
        assert_eq!(
            parse_linode(r#"{"region":"us-iad","type":"g6-standard-1"}"#)
                .unwrap()
                .instance_type
                .as_deref(),
            Some("g6-standard-1")
        );
    }

    #[test]
    fn rejects_unknown_or_unsafe_metadata() {
        assert!(parse_aws(r#"{"region":"","instanceType":"t3"}"#).is_none());
        assert!(parse_google("not-a-zone").is_none());
        assert!(hosting("Azure", Some("westus\r\nInjected: yes"), None, None).is_none());
        assert!(parse_linode(r#"{"user_data":"secret"}"#).is_none());
    }
}
