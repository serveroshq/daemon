use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VirtualHost {
    pub server: String,
    pub names: Vec<String>,
    pub listen: Vec<u16>,
    pub root: Option<String>,
    pub upstreams: Vec<String>,
    pub certificate: Option<String>,
    pub config_path: String,
    pub tls: bool,
}

const MAX_INCLUDED_FILES: usize = 400;

pub fn parse_nginx(
    text: &str,
    path: &str,
    prefix: &Path,
    budget: &mut usize,
    hosts: &mut Vec<VirtualHost>,
) {
    let mut depth = 0usize;
    let mut server_depth: Option<usize> = None;
    let mut current: Option<VirtualHost> = None;

    for statement in nginx_statements(text) {
        match statement {
            NginxItem::Open(name) => {
                depth += 1;
                if name == "server" && server_depth.is_none() {
                    server_depth = Some(depth);
                    current = Some(VirtualHost {
                        server: "nginx".into(),
                        config_path: path.into(),
                        ..Default::default()
                    });
                }
            }
            NginxItem::Close => {
                if server_depth == Some(depth) {
                    if let Some(host) = current.take() {
                        hosts.push(host);
                    }
                    server_depth = None;
                }
                depth = depth.saturating_sub(1);
            }
            NginxItem::Directive(name, args) => {
                if name == "include" {
                    for pattern in args {
                        for file in expand_include(&pattern, prefix, budget) {
                            if let Ok(inner) = std::fs::read_to_string(&file) {
                                if let Some(host) = current.as_mut() {
                                    apply_nginx_snippet(&inner, host);
                                } else {
                                    parse_nginx(
                                        &inner,
                                        &file.to_string_lossy(),
                                        prefix,
                                        budget,
                                        hosts,
                                    );
                                }
                            }
                        }
                    }
                    continue;
                }

                if let Some(host) = current.as_mut() {
                    apply_nginx_directive(host, &name, &args);
                }
            }
        }
    }
}

fn apply_nginx_snippet(text: &str, host: &mut VirtualHost) {
    for statement in nginx_statements(text) {
        if let NginxItem::Directive(name, args) = statement {
            apply_nginx_directive(host, &name, &args);
        }
    }
}

fn apply_nginx_directive(host: &mut VirtualHost, name: &str, args: &[String]) {
    match name {
        "server_name" => host
            .names
            .extend(args.iter().filter(|a| *a != "_").cloned()),
        "listen" => {
            if let Some(port) = args
                .first()
                .and_then(|a| a.rsplit(':').next())
                .and_then(|p| p.trim_start_matches('[').parse().ok())
            {
                if !host.listen.contains(&port) {
                    host.listen.push(port);
                }
            }
            if args.iter().any(|a| a == "ssl") {
                host.tls = true;
            }
        }
        "root" => host.root = args.first().cloned(),
        "proxy_pass" | "fastcgi_pass" | "uwsgi_pass" => {
            if let Some(target) = args.first() {
                if !host.upstreams.contains(target) {
                    host.upstreams.push(target.clone());
                }
            }
        }
        "ssl_certificate" => {
            host.certificate = args.first().cloned();
            host.tls = true;
        }
        _ => {}
    }
}

enum NginxItem {
    Open(String),
    Close,
    Directive(String, Vec<String>),
}

fn nginx_statements(text: &str) -> Vec<NginxItem> {
    let mut items = Vec::new();
    let mut tokens: Vec<String> = Vec::new();
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut chars = text.chars().peekable();

    let flush = |token: &mut String, tokens: &mut Vec<String>| {
        if !token.is_empty() {
            tokens.push(std::mem::take(token));
        }
    };

    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), ch) if ch == q => quote = None,
            (Some(_), ch) => token.push(ch),
            (None, '\'') | (None, '"') => quote = Some(c),
            (None, '#') => {
                for ch in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
            }
            (None, ';') => {
                flush(&mut token, &mut tokens);
                if let Some(name) = tokens.first().cloned() {
                    items.push(NginxItem::Directive(name, tokens[1..].to_vec()));
                }
                tokens.clear();
            }
            (None, '{') => {
                flush(&mut token, &mut tokens);
                items.push(NginxItem::Open(tokens.first().cloned().unwrap_or_default()));
                tokens.clear();
            }
            (None, '}') => {
                flush(&mut token, &mut tokens);
                tokens.clear();
                items.push(NginxItem::Close);
            }
            (None, ch) if ch.is_whitespace() => flush(&mut token, &mut tokens),
            (None, ch) => token.push(ch),
        }
    }

    items
}

fn expand_include(pattern: &str, prefix: &Path, budget: &mut usize) -> Vec<PathBuf> {
    let full = if pattern.starts_with('/') {
        PathBuf::from(pattern)
    } else {
        prefix.join(pattern)
    };
    let Some(parent) = full.parent() else {
        return Vec::new();
    };
    let Some(file_pattern) = full.file_name().and_then(|f| f.to_str()) else {
        return Vec::new();
    };

    let mut files = Vec::new();

    if !file_pattern.contains('*') {
        if full.is_file() && *budget > 0 {
            *budget -= 1;
            files.push(full.clone());
        }
        return files;
    }

    let Ok(entries) = std::fs::read_dir(parent) else {
        return files;
    };
    let (head, tail) = file_pattern.split_once('*').unwrap_or((file_pattern, ""));

    let mut names: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|f| f.to_str())
                    .is_some_and(|f| f.starts_with(head) && f.ends_with(tail))
        })
        .collect();
    names.sort();

    for path in names {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        files.push(path);
    }

    files
}

pub fn parse_apache(text: &str, path: &str, hosts: &mut Vec<VirtualHost>) {
    let mut current: Option<VirtualHost> = None;

    for raw in text.lines() {
        let line = raw.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let lower = line.to_ascii_lowercase();

        if lower.starts_with("<virtualhost") {
            let mut host = VirtualHost {
                server: "apache".into(),
                config_path: path.into(),
                ..Default::default()
            };
            if let Some(port) = line
                .trim_end_matches('>')
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
            {
                host.listen.push(port);
            }
            current = Some(host);
            continue;
        }

        if lower.starts_with("</virtualhost") {
            if let Some(host) = current.take() {
                hosts.push(host);
            }
            continue;
        }

        let Some(host) = current.as_mut() else {
            continue;
        };
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let args: Vec<&str> = parts.collect();

        match key.to_ascii_lowercase().as_str() {
            "servername" | "serveralias" => host.names.extend(args.iter().map(|a| a.to_string())),
            "documentroot" => host.root = args.first().map(|a| a.trim_matches('"').to_string()),
            "proxypass" => {
                if let Some(target) = args.get(1) {
                    host.upstreams.push(target.to_string());
                }
            }
            "sslcertificatefile" => {
                host.certificate = args.first().map(|a| a.to_string());
                host.tls = true;
            }
            "sslengine" if args.first().is_some_and(|a| a.eq_ignore_ascii_case("on")) => {
                host.tls = true
            }
            _ => {}
        }
    }
}

pub fn discover() -> Vec<VirtualHost> {
    let mut hosts = Vec::new();
    let mut budget = MAX_INCLUDED_FILES;

    for (conf, prefix) in [
        ("/etc/nginx/nginx.conf", "/etc/nginx"),
        ("/usr/local/nginx/conf/nginx.conf", "/usr/local/nginx/conf"),
    ] {
        if let Ok(text) = std::fs::read_to_string(conf) {
            parse_nginx(&text, conf, Path::new(prefix), &mut budget, &mut hosts);
            break;
        }
    }

    for dir in ["/etc/apache2/sites-enabled", "/etc/httpd/conf.d"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            paths.sort();

            for path in paths.into_iter().take(200) {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    parse_apache(&text, &path.to_string_lossy(), &mut hosts);
                }
            }
        }
    }

    hosts
}

pub fn certificate_paths(hosts: &[VirtualHost]) -> BTreeSet<String> {
    hosts.iter().filter_map(|h| h.certificate.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_server_blocks_with_quotes_and_comments() {
        let text = r#"
http {
    # a comment { with braces }
    server {
        listen 80;
        listen [::]:80;
        server_name example.com www.example.com;
        root "/var/www/example";
        location / { proxy_pass http://127.0.0.1:3000; }
    }
    server {
        listen 443 ssl;
        server_name _;
        ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    }
}
"#;
        let mut hosts = Vec::new();
        let mut budget = 10;
        parse_nginx(
            text,
            "/etc/nginx/nginx.conf",
            Path::new("/nonexistent"),
            &mut budget,
            &mut hosts,
        );

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].names, vec!["example.com", "www.example.com"]);
        assert_eq!(hosts[0].listen, vec![80]);
        assert_eq!(hosts[0].root.as_deref(), Some("/var/www/example"));
        assert_eq!(hosts[0].upstreams, vec!["http://127.0.0.1:3000"]);
        assert!(!hosts[0].tls);
        assert!(hosts[1].tls);
        assert!(hosts[1].names.is_empty());
        assert_eq!(
            hosts[1].certificate.as_deref(),
            Some("/etc/letsencrypt/live/example.com/fullchain.pem")
        );
    }

    #[test]
    fn follows_includes_within_a_budget() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sites-enabled")).unwrap();
        std::fs::write(
            dir.path().join("sites-enabled/a.conf"),
            "server { listen 8080; server_name a.test; }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("sites-enabled/b.conf"),
            "server { listen 8081; server_name b.test; }",
        )
        .unwrap();
        let main = "http { include sites-enabled/*.conf; }";

        let mut hosts = Vec::new();
        let mut budget = 1;
        parse_nginx(main, "nginx.conf", dir.path(), &mut budget, &mut hosts);

        assert_eq!(hosts.len(), 1, "budget of one file caps the include");
        assert_eq!(hosts[0].names, vec!["a.test"]);
    }

    #[test]
    fn parses_apache_virtual_hosts() {
        let text = "<VirtualHost *:443>\n    ServerName shop.example\n    ServerAlias www.shop.example\n    DocumentRoot \"/var/www/shop\"\n    SSLEngine on\n    SSLCertificateFile /etc/ssl/certs/shop.pem\n    ProxyPass / http://localhost:8000/\n</VirtualHost>\n";
        let mut hosts = Vec::new();
        parse_apache(text, "/etc/apache2/sites-enabled/shop.conf", &mut hosts);

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].listen, vec![443]);
        assert_eq!(hosts[0].names, vec!["shop.example", "www.shop.example"]);
        assert_eq!(hosts[0].upstreams, vec!["http://localhost:8000/"]);
        assert!(hosts[0].tls);
    }
}
