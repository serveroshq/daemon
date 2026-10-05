use std::sync::LazyLock;

use regex::Regex;

pub const REDACTED: &str = "[redacted]";

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r#"(?i)\b(?P<key>[A-Z0-9_]*(?:secret|token|password|passwd|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?key)[A-Z0-9_]*)\s*[=:]\s*(?P<secret>[^\s'"]+)"#,
        r"(?i)\b(?P<key>authorization:\s*(?:bearer|basic))\s+(?P<secret>[A-Za-z0-9\-._~+/]+=*)",
        r"(?P<key>[a-z][a-z0-9+.\-]*://[^:/\s]+):(?P<secret>[^@\s]+)@",
        r"\b(?P<key>)(?P<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b",
        r"(?s)(?P<key>-----BEGIN [A-Z ]*PRIVATE KEY-----)(?P<secret>.*?)(?:-----END [A-Z ]*PRIVATE KEY-----)",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("redaction pattern compiles"))
    .collect()
});

pub fn redact(input: &str) -> String {
    let mut out = input.to_string();

    for pattern in PATTERNS.iter() {
        out = pattern
            .replace_all(&out, |caps: &regex::Captures| {
                let key = caps.name("key").map(|m| m.as_str()).unwrap_or("");
                let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                let secret = caps.name("secret").map(|m| m.as_str()).unwrap_or("");

                let start = caps.name("secret").map(|m| m.start()).unwrap_or(0)
                    - caps.get(0).map(|m| m.start()).unwrap_or(0);
                let tail = &whole[start + secret.len()..];

                if key.is_empty() {
                    format!("{REDACTED}{tail}")
                } else {
                    let sep = &whole[key.len()..start];
                    format!("{key}{sep}{REDACTED}{tail}")
                }
            })
            .into_owned();
    }

    out
}

pub fn redact_known(input: &str, known: &[&str]) -> String {
    let mut out = redact(input);

    for secret in known {
        if secret.len() >= 8 {
            out = out.replace(secret, REDACTED);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_env_style_secrets_but_keeps_the_key() {
        assert_eq!(
            redact("DATABASE_PASSWORD=hunter22 APP_ENV=prod"),
            "DATABASE_PASSWORD=[redacted] APP_ENV=prod"
        );
        assert_eq!(redact("api_key: abcdef123"), "api_key: [redacted]");
    }

    #[test]
    fn scrubs_url_credentials() {
        assert_eq!(
            redact("postgres://app:s3cret@db:5432/app"),
            "postgres://app:[redacted]@db:5432/app"
        );
    }

    #[test]
    fn scrubs_bearer_tokens_and_known_prefixes() {
        assert_eq!(
            redact("Authorization: Bearer eyJhbGciOi"),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(
            redact("token ghp_abcdefghijklmnopqrstuvwxyz0123 pushed"),
            "token [redacted] pushed"
        );
    }

    #[test]
    fn scrubs_pem_blocks() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----";
        let out = redact(pem);

        assert!(out.contains("-----BEGIN PRIVATE KEY-----[redacted]-----END PRIVATE KEY-----"));
        assert!(!out.contains("MIIEvQ"));
    }

    #[test]
    fn scrubs_known_values_anywhere() {
        assert_eq!(
            redact_known("echo supersecretvalue", &["supersecretvalue"]),
            "echo [redacted]"
        );
    }

    #[test]
    fn leaves_ordinary_output_alone() {
        let line = "Step 7/12 : RUN npm ci -- exited 1";

        assert_eq!(redact(line), line);
    }
}
