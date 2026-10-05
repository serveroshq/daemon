pub const DEFAULT_PANEL_URL: &str = match option_env!("SERVEROS_PANEL_URL") {
    Some(url) if !url.is_empty() => url,
    _ => "https://api.serveros.com",
};

pub const DOCS_URL: &str = match option_env!("SERVEROS_DOCS_URL") {
    Some(url) if !url.is_empty() => url,
    _ => "https://serveros.com/docs/daemon",
};

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
