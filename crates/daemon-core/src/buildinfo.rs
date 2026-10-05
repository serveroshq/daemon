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

#[cfg(test)]
mod tests {
    use super::*;

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
