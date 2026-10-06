use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: &'static str,
    pub commit: &'static str,
    pub channel: &'static str,
    pub target: &'static str,
}

impl BuildInfo {
    pub const fn current() -> Self {
        Self {
            version: match option_env!("SERVEROS_VERSION") {
                Some(v) => v,
                None => env!("CARGO_PKG_VERSION"),
            },
            commit: match option_env!("SERVEROS_COMMIT") {
                Some(c) => c,
                None => "unknown",
            },
            channel: match option_env!("SERVEROS_CHANNEL") {
                Some(c) => c,
                None => "dev",
            },
            target: match option_env!("SERVEROS_TARGET") {
                Some(t) => t,
                None => "host",
            },
        }
    }

    pub fn banner(&self) -> String {
        format!(
            "serverosd {} ({}, {}, {})",
            self.version, self.commit, self.channel, self.target
        )
    }

    pub fn semver(&self) -> (u64, u64, u64) {
        parse_semver(self.version).unwrap_or((0, 0, 0))
    }
}

pub fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let trimmed = version.trim().trim_start_matches('v');
    let core = trimmed.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());

    Some((parts.next()??, parts.next()??, parts.next()??))
}

pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;

    let core = parse_semver(a)?.cmp(&parse_semver(b)?);
    if core != Ordering::Equal {
        return Some(core);
    }

    let pre = |v: &str| -> Option<String> {
        let v = v.trim().trim_start_matches('v');
        let v = v.split('+').next().unwrap_or(v);
        v.split_once('-').map(|(_, pre)| pre.to_string())
    };

    Some(match (pre(a), pre(b)) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            let (mut xs, mut ys) = (x.split('.'), y.split('.'));
            loop {
                match (xs.next(), ys.next()) {
                    (None, None) => break Ordering::Equal,
                    (None, Some(_)) => break Ordering::Less,
                    (Some(_), None) => break Ordering::Greater,
                    (Some(p), Some(q)) => {
                        let order = match (p.parse::<u64>(), q.parse::<u64>()) {
                            (Ok(m), Ok(n)) => m.cmp(&n),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => p.cmp(q),
                        };
                        if order != Ordering::Equal {
                            break order;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prereleases_order_before_their_release() {
        use std::cmp::Ordering::*;
        assert_eq!(
            compare_versions("v0.1.0-pre.2", "v0.1.0-pre.1"),
            Some(Greater)
        );
        assert_eq!(
            compare_versions("0.1.0-pre.10", "0.1.0-pre.9"),
            Some(Greater)
        );
        assert_eq!(compare_versions("v0.1.0", "v0.1.0-pre.9"), Some(Greater));
        assert_eq!(
            compare_versions("0.1.0-pre.1", "0.1.0-pre.1+abc"),
            Some(Equal)
        );
        assert_eq!(compare_versions("0.2.0-pre.1", "0.1.9"), Some(Greater));
        assert_eq!(compare_versions("1.0.0-alpha", "1.0.0-beta"), Some(Less));
        assert_eq!(compare_versions("garbage", "1.0.0"), None);
    }

    #[test]
    fn parses_tagged_versions() {
        assert_eq!(parse_semver("v1.9.2"), Some((1, 9, 2)));
        assert_eq!(parse_semver("1.9.2-rc.1"), Some((1, 9, 2)));
        assert_eq!(parse_semver("garbage"), None);
    }

    #[test]
    fn dev_builds_still_report_a_version() {
        let info = BuildInfo::current();

        assert!(!info.version.is_empty());
        assert!(info.banner().starts_with("serverosd "));
    }
}
