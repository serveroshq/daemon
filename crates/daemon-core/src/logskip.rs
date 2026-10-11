//! Skip rules for logs: services, or lines matching a pattern, that never
//! leave the machine. Set in `[logs.skip]` in daemon.toml or from the
//! panel, and applied to everything that sends log lines: the shipper,
//! on-demand service logs and live tails.
//!
//! A service rule is a name with `*` for any run of characters, matched
//! without regard to case against the container or unit name. A unit also
//! matches without its `.service` suffix, so `wings` skips `wings.service`.
//! A pattern is a regular expression, for every service or just the ones
//! its `service` rule matches.

use std::sync::{Arc, LazyLock, RwLock};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// Most rules of each kind, and the longest rule.
pub const MAX_RULES: usize = 100;
pub const MAX_RULE_LEN: usize = 300;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSkip {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<SkipPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkipPattern {
    /// Only for services this rule matches; every service when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub pattern: String,
}

impl LogSkip {
    pub fn is_empty(&self) -> bool {
        self.services.is_empty() && self.patterns.is_empty()
    }
}

#[derive(Default)]
struct Compiled {
    services: Vec<String>,
    patterns: Vec<(Option<String>, Regex)>,
}

static RULES: LazyLock<RwLock<Arc<Compiled>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Compiled::default())));

/// Use these rules from now on. Returns the patterns that couldn't be
/// used (too long, too many, or not a valid expression); the rest apply.
pub fn configure(skip: &LogSkip) -> Vec<String> {
    let mut rejected = Vec::new();
    let services = skip
        .services
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && s.len() <= MAX_RULE_LEN)
        .take(MAX_RULES)
        .map(|s| s.to_lowercase())
        .collect();
    let mut patterns = Vec::new();
    for rule in &skip.patterns {
        if patterns.len() >= MAX_RULES || rule.pattern.len() > MAX_RULE_LEN {
            rejected.push(rule.pattern.clone());
            continue;
        }
        match RegexBuilder::new(&rule.pattern).size_limit(1 << 20).build() {
            Ok(regex) => patterns.push((
                rule.service
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_lowercase),
                regex,
            )),
            Err(_) => rejected.push(rule.pattern.clone()),
        }
    }
    *RULES.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(Compiled { services, patterns });
    rejected
}

fn rules() -> Arc<Compiled> {
    Arc::clone(&RULES.read().unwrap_or_else(|e| e.into_inner()))
}

/// Whether nothing from this service is sent.
pub fn skips_service(name: &str) -> bool {
    let rules = rules();
    rules
        .services
        .iter()
        .any(|rule| service_matches(rule, name))
}

/// Whether this line is held back: its service is skipped, or a pattern
/// for it (or for every service) matches. `None` for a line with no
/// service, which only machine-wide patterns apply to.
pub fn skips_line(service: Option<&str>, line: &str) -> bool {
    let rules = rules();
    if let Some(name) = service {
        if rules
            .services
            .iter()
            .any(|rule| service_matches(rule, name))
        {
            return true;
        }
    }
    rules.patterns.iter().any(|(only, regex)| {
        let applies = match (only, service) {
            (None, _) => true,
            (Some(rule), Some(name)) => service_matches(rule, name),
            (Some(_), None) => false,
        };
        applies && regex.is_match(line)
    })
}

/// `rule` is already lowercase.
fn service_matches(rule: &str, name: &str) -> bool {
    let name = name.trim_start_matches('/').to_lowercase();
    glob(rule, &name)
        || name
            .strip_suffix(".service")
            .is_some_and(|bare| glob(rule, bare))
}

/// `*` matches any run of characters; everything else matches itself.
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || !text[first.len()..].ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test touches the global rules, so tests don't race on them.
    #[test]
    fn skips_services_and_patterns() {
        let rejected = configure(&LogSkip {
            services: vec!["wings".into(), "PTERO-*".into(), "  ".into()],
            patterns: vec![
                SkipPattern {
                    service: None,
                    pattern: r"password=\S+".into(),
                },
                SkipPattern {
                    service: Some("nginx*".into()),
                    pattern: r"^\d+\.\d+\.\d+\.\d+ ".into(),
                },
                SkipPattern {
                    service: None,
                    pattern: "(unclosed".into(),
                },
            ],
        });
        assert_eq!(rejected, vec!["(unclosed".to_string()]);

        assert!(skips_service("wings.service"));
        assert!(skips_service("wings"));
        assert!(skips_service("/ptero-3f2a"));
        assert!(!skips_service("wingsd.service"));
        assert!(!skips_service("caddy"));

        assert!(skips_line(Some("wings.service"), "anything"));
        assert!(skips_line(Some("caddy"), "login password=hunter2"));
        assert!(skips_line(None, "login password=hunter2"));
        assert!(skips_line(Some("nginx.service"), "203.0.113.9 - GET /"));
        assert!(!skips_line(Some("caddy"), "203.0.113.9 - GET /"));
        assert!(!skips_line(None, "203.0.113.9 - GET /"));
        assert!(!skips_line(Some("caddy"), "all good"));

        configure(&LogSkip::default());
        assert!(!skips_service("wings.service"));
        assert!(!skips_line(Some("caddy"), "password=x"));
    }

    #[test]
    fn globs() {
        assert!(glob("a*c", "abc"));
        assert!(glob("a*", "a"));
        assert!(glob("*b*", "abc"));
        assert!(!glob("a*c", "ab"));
        assert!(!glob("abc", "abcd"));
        assert!(glob("*", ""));
    }

    #[test]
    fn empty_rules_stay_out_of_the_config() {
        let toml = toml::to_string(&LogSkip::default()).unwrap();
        assert_eq!(toml.trim(), "");
        let back: LogSkip =
            toml::from_str("services = [\"wings\"]\n[[patterns]]\npattern = \"x\"\n").unwrap();
        assert_eq!(back.services, vec!["wings"]);
        assert_eq!(back.patterns[0].service, None);
    }
}
