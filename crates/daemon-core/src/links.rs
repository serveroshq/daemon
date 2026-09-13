//! Every URL the daemon prints or bakes into a file, in one place, each
//! overridable at build time so a self-hosted panel or a fork is a build
//! flag rather than a patch:
//!
//! - `SERVEROS_PANEL_URL`: the default `--panel` for `serverosd enrol`.
//! - `SERVEROS_DOCS_URL`: the base of the documentation links in error
//!   messages and the systemd unit.

/// The panel a bare `serverosd enrol --token …` talks to.
pub const DEFAULT_PANEL_URL: &str = match option_env!("SERVEROS_PANEL_URL") {
    Some(url) if !url.is_empty() => url,
    _ => "https://api.serveros.com",
};

/// The base of every documentation deep link.
pub const DOCS_URL: &str = match option_env!("SERVEROS_DOCS_URL") {
    Some(url) if !url.is_empty() => url,
    _ => "https://serveros.com/docs/daemon",
};

/// A documentation page under [`DOCS_URL`], e.g. `docs("firewall")`.
pub fn docs(topic: &str) -> String {
    format!(
        "{}/{}",
        DOCS_URL.trim_end_matches('/'),
        topic.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_links_join_cleanly() {
        assert_eq!(docs("/firewall"), format!("{DOCS_URL}/firewall"));
        assert!(DEFAULT_PANEL_URL.starts_with("https://"));
    }
}
