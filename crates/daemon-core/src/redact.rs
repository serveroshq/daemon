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

/// Known values shorter than this are never replaced: they'd match too
/// much ordinary text.
pub const MIN_KNOWN_LEN: usize = 4;

/// [`redact`], then every value in `known` wherever it appears. Longer
/// values go first, so one that contains a shorter one is replaced whole.
pub fn redact_known(input: &str, known: &[&str]) -> String {
    let mut out = redact(input);

    let mut known: Vec<&str> = known
        .iter()
        .copied()
        .filter(|s| s.len() >= MIN_KNOWN_LEN)
        .collect();
    known.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in known {
        out = out.replace(secret, REDACTED);
    }

    out
}

/// The old rule, for jobs that hand over a list of values without saying
/// what they are: only values of 8 characters or more are scrubbed from
/// the log.
pub fn long_values(values: Vec<String>) -> Vec<String> {
    values.into_iter().filter(|v| v.len() >= 8).collect()
}

/// Which of an app's settings to scrub from its deploy log, from their
/// names and values. A setting whose name looks secret (`API_KEY`,
/// `DB_PASSWORD`, `SENTRY_DSN`…) is scrubbed when it's 4 characters or
/// more, and so is any URL with a password in it. Anything else only when
/// it's 12 characters or more and isn't plainly harmless: a word, a
/// number, a yes or no, a host name, a path, or a URL without
/// credentials. So `APP_ENV=production` and `APP_URL=https://shop.example.com`
/// stay readable in the log, and a token under any name doesn't.
///
/// A value over several lines (a PEM key) is scrubbed line by line, since
/// that's how it would turn up in a log.
pub fn env_secrets<'a>(vars: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (name, value) in vars {
        let secret_name = looks_secret_name(name);
        let mut pieces: Vec<&str> = if value.contains('\n') {
            value
                .split('\n')
                .map(|l| l.trim_end_matches('\r'))
                .flat_map(|l| [l, l.trim()])
                .collect()
        } else {
            vec![value]
        };
        pieces.dedup();
        for piece in pieces {
            if should_scrub(secret_name, piece) && !out.iter().any(|o| o == piece) {
                out.push(piece.to_string());
            }
        }
    }
    out
}

fn should_scrub(secret_name: bool, value: &str) -> bool {
    if value.len() < MIN_KNOWN_LEN {
        return false;
    }
    if secret_name || url_has_password(value) {
        return true;
    }
    value.len() >= 12 && !plainly_harmless(value)
}

/// Whether a setting's name says it holds a secret.
pub fn looks_secret_name(name: &str) -> bool {
    const MARKS: &[&str] = &[
        "KEY",
        "TOKEN",
        "SECRET",
        "PASS",
        "PWD",
        "AUTH",
        "CREDENTIAL",
        "PRIVATE",
        "DSN",
        "CERT",
    ];
    let upper = name.to_ascii_uppercase();
    MARKS.iter().any(|mark| upper.contains(mark))
}

static URL_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z][A-Za-z0-9+.\-]*://[^/\s@]*:[^/\s@]+@").expect("url pattern compiles")
});

/// `postgres://app:s3cret@db/app`, `redis://:s3cret@cache`.
pub fn url_has_password(value: &str) -> bool {
    URL_PASSWORD.is_match(value)
}

/// A value no one would mind seeing in a log: a word, a number, a yes or
/// no, a host name, a path, or a URL without credentials or anything in
/// it that looks like a token.
pub fn plainly_harmless(value: &str) -> bool {
    value.split_whitespace().all(|v| {
        is_boolean(v) || is_number(v) || is_word(v) || is_host(v) || is_path(v) || is_plain_url(v)
    })
}

fn is_boolean(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "none"
    )
}

fn is_number(v: &str) -> bool {
    let digits = v.strip_prefix('-').unwrap_or(v);
    !digits.is_empty()
        && digits.starts_with(|c: char| c.is_ascii_digit())
        && digits
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | '_' | ','))
}

/// Letters in one case (or Capitalised), maybe joined by `-` or `_`, and
/// with vowels, as words have: `production`, `eu-west`, `INFO`.
fn is_word(v: &str) -> bool {
    v.split(['-', '_']).all(|part| {
        let letters = !part.is_empty() && part.chars().all(|c| c.is_ascii_alphabetic());
        let rest = part.get(1..).unwrap_or("");
        let one_case = rest.chars().all(|c| c.is_ascii_lowercase())
            || part.chars().all(|c| c.is_ascii_uppercase());
        let vowels = part
            .chars()
            .any(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y'));
        letters && one_case && vowels
    })
}

/// `db.internal`, `shop.example.com:443`, `10.0.0.5`: lowercase labels
/// with a dot, ending in letters (or an IPv4 address), maybe a port.
fn is_host(v: &str) -> bool {
    let host = match v.rsplit_once(':') {
        Some((host, port)) if is_number(port) => host,
        _ => v,
    };
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        && labels.last().is_some_and(|tld| {
            (2..=24).contains(&tld.len()) && tld.chars().all(|c| c.is_ascii_lowercase())
        })
}

/// A run of characters that looks generated rather than written: long,
/// with at least two of lowercase, uppercase and digits.
fn looks_random(segment: &str) -> bool {
    let kinds = [
        segment.chars().any(|c| c.is_ascii_lowercase()),
        segment.chars().any(|c| c.is_ascii_uppercase()),
        segment.chars().any(|c| c.is_ascii_digit()),
    ];
    segment.len() >= 16 && kinds.iter().filter(|k| **k).count() >= 2
}

fn plain_segments(path: &str) -> bool {
    path.split(['/', '.'])
        .filter(|s| !s.is_empty())
        .all(|s| !looks_random(s))
}

fn is_path(v: &str) -> bool {
    let rest = v
        .strip_prefix("~/")
        .or_else(|| v.strip_prefix("./"))
        .or_else(|| v.strip_prefix('/'));
    rest.is_some_and(plain_segments)
}

fn is_plain_url(v: &str) -> bool {
    let Some((scheme, rest)) = v.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    {
        return false;
    }
    let (authority, rest) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    if authority.contains('@') {
        return false;
    }
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let query_ok = query.split('&').filter(|p| !p.is_empty()).all(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        !looks_secret_name(name) && !looks_random(value)
    });
    query_ok && plain_segments(path.split('#').next().unwrap_or(""))
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
    fn a_value_containing_another_is_replaced_whole() {
        assert_eq!(
            redact_known("x=abcd-and-more y=abcd", &["abcd", "abcd-and-more"]),
            "x=[redacted] y=[redacted]"
        );
        // Too short to replace anywhere.
        assert_eq!(redact_known("on at 80", &["80"]), "on at 80");
    }

    fn secrets_of(vars: &[(&str, &str)]) -> Vec<String> {
        env_secrets(vars.iter().copied())
    }

    #[test]
    fn settings_with_secret_names_are_scrubbed_from_4_characters() {
        for name in [
            "API_KEY",
            "STRIPE_SECRET",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "MYSQL_PWD",
            "BASIC_AUTH",
            "GOOGLE_CREDENTIALS",
            "PRIVATE_KEY",
            "SENTRY_DSN",
            "TLS_CERT",
            "db_pass",
        ] {
            assert_eq!(secrets_of(&[(name, "abcd")]), ["abcd"], "{name}");
            assert!(secrets_of(&[(name, "abc")]).is_empty(), "{name}");
        }
    }

    #[test]
    fn harmless_settings_stay_readable() {
        for (name, value) in [
            ("APP_ENV", "production"),
            ("NODE_ENV", "development"),
            ("APP_URL", "https://shop.example.com"),
            (
                "APP_URL",
                "https://shop.example.com/admin/login?next=/orders",
            ),
            ("DB_HOST", "postgres.internal"),
            ("REDIS_HOST", "cache.example.com:6379"),
            ("DB_HOST", "10.0.0.15"),
            ("PORT", "3000"),
            ("WORKERS", "12000000000000"),
            ("DEBUG", "false"),
            ("LOG_LEVEL", "INFO"),
            ("STORAGE_PATH", "/var/www/html/storage/app"),
            ("REGION", "europe-west-central"),
            ("SITE_NAME", "Acme Garden Supplies"),
        ] {
            assert!(
                secrets_of(&[(name, value)]).is_empty(),
                "{name}={value} was scrubbed"
            );
        }
    }

    #[test]
    fn long_values_that_look_generated_are_scrubbed_under_any_name() {
        for value in [
            "pk_demo_51HxQ2pLk9mN3vB7c",
            "aB3dE5fG7hJ9kL1m",
            "550e8400-e29b-41d4-a716-446655440000",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
            "https://hooks.example.com/services/T0001/B0001/XxYyZz0123456789AbCd",
            "https://api.example.com/v1?api_key=abcdef",
            "/run/secrets/aB3dE5fG7hJ9kL1mN",
            "hunter2hunter2!",
        ] {
            assert_eq!(secrets_of(&[("SOMETHING", value)]), [value], "{value}");
        }
        // Short ones under ordinary names are left: too short to tell.
        assert!(secrets_of(&[("SOMETHING", "aB3dE5fG7h")]).is_empty());
    }

    #[test]
    fn urls_with_a_password_are_always_scrubbed() {
        for value in [
            "postgres://app:s3cret@db:5432/app",
            "redis://:pw@cache:6379",
        ] {
            assert_eq!(secrets_of(&[("DATABASE_URL", value)]), [value]);
            assert_eq!(secrets_of(&[("UPSTREAM", value)]), [value]);
        }
        assert!(url_has_password("amqp://guest:guest@rabbit/"));
        assert!(!url_has_password("https://user@example.com/"));
        assert!(!url_has_password("https://example.com/a:b@c"));
    }

    #[test]
    fn values_over_several_lines_are_scrubbed_line_by_line() {
        let pem = "-----BEGIN PRIVATE KEY-----\r\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n  BKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n";
        let found = secrets_of(&[("JWT_PRIVATE_KEY", pem)]);
        assert!(found.contains(&"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC".to_string()));
        assert!(found.contains(&"  BKcwggSjAgEAAoIBAQC7".to_string()));
        assert!(found.contains(&"BKcwggSjAgEAAoIBAQC7".to_string()));
        assert!(found
            .iter()
            .all(|s| !s.contains('\n') && !s.ends_with('\r')));

        // Each line of a printed key is gone from the log.
        let line = "loaded key MIIEvQIBADANBgkqhkiG9w0BAQEFAASC from env";
        let known: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(redact_known(line, &known), "loaded key [redacted] from env");

        // An ordinary setting over lines keeps its plain lines.
        let config = "mode: fast\nendpoint: aB3dE5fG7hJ9kL1mN0pQ";
        assert_eq!(
            secrets_of(&[("APP_CONFIG", config)]),
            ["endpoint: aB3dE5fG7hJ9kL1mN0pQ"]
        );
    }

    #[test]
    fn the_old_rule_keeps_values_of_8_or_more() {
        assert_eq!(
            long_values(vec!["short".into(), "longer-value".into()]),
            ["longer-value"]
        );
    }

    #[test]
    fn leaves_ordinary_output_alone() {
        let line = "Step 7/12 : RUN npm ci -- exited 1";

        assert_eq!(redact(line), line);
    }
}
