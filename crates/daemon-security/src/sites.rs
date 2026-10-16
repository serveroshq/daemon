//! The websites the machine serves, from nginx, Apache and Caddy, and what
//! in their folders shouldn't be: a .env or .git anyone could download,
//! database dumps and backups, phpinfo pages. Only names are reported,
//! never what's in the files; the panel then asks each site for them from
//! outside to see whether they really can be downloaded.
//!
//! Also WordPress's version and its plugins' and themes' (old ones are
//! how most WordPress sites get broken into), and Laravel apps running in
//! production with debug on, which shows secrets on any error page.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use daemon_inventory::webservers::{self, VirtualHost};
use serde::Serialize;

use crate::util::{self, clip};
use crate::Options;

const MAX_SITES: usize = 200;
const MAX_PLUGINS: usize = 150;

/// Files that are trouble in a folder a web server serves, by name.
pub const RISKY_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.backup",
    ".env.bak",
    ".git",
    ".svn",
    ".hg",
    ".htpasswd",
    ".DS_Store",
    ".bash_history",
    ".ssh",
    "id_rsa",
    "wp-config.php.bak",
    "wp-config.php.old",
    "wp-config.php.save",
    "wp-config.php~",
    "wp-config.bak",
    "config.php.bak",
    "configuration.php.bak",
    "phpinfo.php",
    "info.php",
    "adminer.php",
    "backup.sql",
    "dump.sql",
    "database.sql",
    "db.sql",
    "data.sql",
    "backup.zip",
    "backup.tar.gz",
    "backup.tgz",
    "site.zip",
    "www.zip",
    "html.zip",
    "public_html.zip",
    "error_log",
    "debug.log",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct Site {
    /// nginx, apache or caddy.
    pub server: String,
    pub names: Vec<String>,
    pub root: Option<String>,
    pub tls: bool,
    pub config_path: String,
    /// Proxied to an app rather than served from a folder.
    pub proxied: bool,
    /// Names from RISKY_FILES found in the root (and in wp-content).
    pub risky_files: Vec<String>,
    pub wordpress: Option<WordPress>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct WordPress {
    pub version: Option<String>,
    pub plugins: Vec<Extension>,
    pub themes: Vec<Extension>,
    /// WP_DEBUG_DISPLAY / WP_DEBUG on in wp-config.php.
    pub debug: bool,
    /// DISALLOW_FILE_EDIT isn't set: an admin login can edit PHP files.
    pub file_editing: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Extension {
    pub slug: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AppSetting {
    pub path: String,
    pub framework: String,
    /// APP_DEBUG=true while APP_ENV is production (or unset).
    pub debug_in_production: bool,
    /// APP_KEY empty: sessions and encrypted values aren't protected.
    pub missing_key: bool,
    /// The .env can be read by every user on the machine.
    pub env_world_readable: bool,
}

pub fn gather(options: &Options) -> Vec<Site> {
    let mut hosts = if options.root == Path::new("/") {
        webservers::discover()
    } else {
        discover_under(options)
    };
    hosts.extend(caddy(options));

    let mut sites: Vec<Site> = Vec::new();
    for host in hosts.into_iter().take(MAX_SITES) {
        let names: Vec<String> = host
            .names
            .iter()
            .filter(|n| looks_like_domain(n))
            .map(|n| n.trim_start_matches("*.").to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        // The same site on :80 and :443 is one site.
        if let Some(existing) = sites
            .iter_mut()
            .find(|s| s.server == host.server && s.names == names && s.root == host.root)
        {
            existing.tls |= host.tls;
            existing.proxied |= !host.upstreams.is_empty();
            continue;
        }
        let root = host.root.as_deref().map(|r| options.path(r));
        let mut site = Site {
            server: host.server.clone(),
            names,
            root: host.root.clone(),
            tls: host.tls,
            config_path: clip(&host.config_path, 300),
            proxied: !host.upstreams.is_empty(),
            ..Site::default()
        };
        if let Some(root) = root.filter(|r| r.is_dir()) {
            site.risky_files = risky_files(&root);
            site.wordpress = wordpress(&root);
        }
        sites.push(site);
    }

    sites
}

/// nginx and Apache configs under a test root (the inventory's own
/// discovery reads the real /etc).
fn discover_under(options: &Options) -> Vec<VirtualHost> {
    let mut hosts = Vec::new();
    let mut budget = 400;
    let conf = options.path("/etc/nginx/nginx.conf");
    if let Ok(text) = std::fs::read_to_string(&conf) {
        webservers::parse_nginx(
            &text,
            "/etc/nginx/nginx.conf",
            &options.path("/etc/nginx"),
            &mut budget,
            &mut hosts,
        );
    }
    for dir in ["/etc/apache2/sites-enabled", "/etc/httpd/conf.d"] {
        let mut files: Vec<PathBuf> = std::fs::read_dir(options.path(dir))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in files {
            if let Ok(text) = std::fs::read_to_string(&file) {
                webservers::parse_apache(&text, &options.display(&file), &mut hosts);
            }
        }
    }

    hosts
}

/// Caddy's sites: the Caddyfile and what it imports from serveros.d.
fn caddy(options: &Options) -> Vec<VirtualHost> {
    let mut files = vec![options.path("/etc/caddy/Caddyfile")];
    let mut extra: Vec<PathBuf> = std::fs::read_dir(options.path("/etc/caddy/serveros.d"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "caddy"))
        .collect();
    extra.sort();
    files.extend(extra);

    let mut hosts = Vec::new();
    for file in files {
        if let Some(text) = util::read_limited(&file, 1024 * 1024) {
            hosts.extend(parse_caddyfile(&text, &options.display(&file)));
        }
    }

    hosts
}

/// Site blocks at the top level of a Caddyfile: `example.com, www.example.com {`,
/// with `root * /path` and `reverse_proxy` inside.
pub fn parse_caddyfile(text: &str, path: &str) -> Vec<VirtualHost> {
    let mut hosts = Vec::new();
    let mut depth = 0i32;
    let mut current: Option<VirtualHost> = None;

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if depth == 0 && line.ends_with('{') {
            let addresses = line.trim_end_matches('{').trim();
            // The global options block is a bare `{`; snippets are `(name)`.
            if !addresses.is_empty() && !addresses.starts_with('(') {
                let mut host = VirtualHost {
                    server: "caddy".into(),
                    config_path: path.to_string(),
                    ..VirtualHost::default()
                };
                for address in addresses.split([',', ' ']).filter(|a| !a.is_empty()) {
                    let tls = !address.starts_with("http://");
                    let name = address
                        .trim_start_matches("https://")
                        .trim_start_matches("http://");
                    let name = name.split(['/', ':']).next().unwrap_or("");
                    if !name.is_empty() {
                        host.names.push(name.to_string());
                        host.tls |= tls && looks_like_domain(name);
                    }
                }
                current = Some(host);
            }
        } else if depth == 1 {
            if let Some(host) = current.as_mut() {
                let words: Vec<&str> = line.split_whitespace().collect();
                match words.first().copied() {
                    Some("root") => {
                        host.root = words
                            .iter()
                            .skip(1)
                            .find(|w| w.starts_with('/'))
                            .map(|w| w.to_string());
                    }
                    Some("reverse_proxy") => {
                        host.upstreams.extend(
                            words
                                .iter()
                                .skip(1)
                                .filter(|w| !w.ends_with('{'))
                                .map(|w| w.to_string()),
                        );
                    }
                    _ => {}
                }
            }
        }
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if depth <= 0 {
            depth = 0;
            if let Some(host) = current.take() {
                hosts.push(host);
            }
        }
    }

    hosts
}

/// A public name, not `_`, `localhost`, an address or a port.
pub fn looks_like_domain(name: &str) -> bool {
    let name = name.trim_start_matches("*.");
    name.contains('.')
        && !name.ends_with(".local")
        && !name.ends_with(".localhost")
        && !name.ends_with(".internal")
        && !name.ends_with(".test")
        && name.chars().any(|c| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && name.len() <= 253
}

fn risky_files(root: &Path) -> Vec<String> {
    let mut found: Vec<String> = RISKY_FILES
        .iter()
        .filter(|f| root.join(f).exists())
        .map(|f| f.to_string())
        .collect();
    // Laravel's app folder served instead of its public folder: the whole
    // app is downloadable, starting with storage/logs.
    if root.join("artisan").is_file() && root.join("storage/logs").is_dir() {
        found.push("storage/logs".into());
    }
    if root.join("wp-content/debug.log").is_file() {
        found.push("wp-content/debug.log".into());
    }
    // A SQL dump or archive with another name.
    for entry in std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .take(2000)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        let dump =
            lower.ends_with(".sql") || lower.ends_with(".sql.gz") || lower.ends_with(".sql.zip");
        if dump && !found.contains(&name) && found.len() < 40 {
            found.push(clip(&name, 120));
        }
    }

    found
}

fn wordpress(root: &Path) -> Option<WordPress> {
    let version_file = util::read_limited(&root.join("wp-includes/version.php"), 64 * 1024)?;
    let config = util::read_limited(&root.join("wp-config.php"), 256 * 1024)
        .or_else(|| {
            root.parent()
                .and_then(|p| util::read_limited(&p.join("wp-config.php"), 256 * 1024))
        })
        .unwrap_or_default();

    Some(WordPress {
        version: wp_version(&version_file),
        plugins: extensions(&root.join("wp-content/plugins"), false),
        themes: extensions(&root.join("wp-content/themes"), true),
        debug: wp_define_true(&config, "WP_DEBUG_DISPLAY")
            || (wp_define_true(&config, "WP_DEBUG")
                && !wp_define_false(&config, "WP_DEBUG_DISPLAY")),
        file_editing: !config.is_empty()
            && !wp_define_true(&config, "DISALLOW_FILE_EDIT")
            && !wp_define_true(&config, "DISALLOW_FILE_MODS"),
    })
}

/// `$wp_version = '6.4.2';`
pub fn wp_version(text: &str) -> Option<String> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("$wp_version"))?;
    let value = line.split(['\'', '"']).nth(1)?;

    (!value.is_empty()).then(|| value.to_string())
}

fn wp_define(config: &str, name: &str) -> Option<bool> {
    config
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .find_map(|line| {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let rest = compact
                .strip_prefix(&format!("define('{name}',"))
                .or_else(|| compact.strip_prefix(&format!("define(\"{name}\",")))?;
            let value = rest.split(')').next()?.to_ascii_lowercase();

            Some(value == "true" || value == "1")
        })
}

fn wp_define_true(config: &str, name: &str) -> bool {
    wp_define(config, name) == Some(true)
}

fn wp_define_false(config: &str, name: &str) -> bool {
    wp_define(config, name) == Some(false)
}

/// Plugins (each a folder with a PHP file whose header has "Plugin Name")
/// or themes (style.css), with the header's Version.
fn extensions(dir: &Path, themes: bool) -> Vec<Extension> {
    let mut out = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();

    for path in entries.into_iter().take(MAX_PLUGINS) {
        let slug = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let header = if themes {
            util::read_head(&path.join("style.css"), 8192).filter(|t| t.contains("Theme Name"))
        } else {
            let main = path.join(format!("{slug}.php"));
            util::read_head(&main, 8192)
                .filter(|t| t.contains("Plugin Name"))
                .or_else(|| {
                    std::fs::read_dir(&path)
                        .into_iter()
                        .flatten()
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|e| e == "php"))
                        .take(40)
                        .filter_map(|p| util::read_head(&p, 8192))
                        .find(|t| t.contains("Plugin Name"))
                })
        };
        let Some(header) = header else {
            continue;
        };
        out.push(Extension {
            slug: clip(&slug, 100),
            version: header_value(&header, "Version"),
        });
    }

    out
}

/// ` * Version: 1.2.3` in a plugin or theme header.
pub fn header_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim().trim_start_matches(['*', '#', '/']).trim();
        let value = line
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix(':')?
            .trim();
        (!value.is_empty()).then(|| clip(value, 40))
    })
}

/// Laravel apps' risky settings, from their .env.
pub fn app_settings(options: &Options, laravel: &[PathBuf]) -> Vec<AppSetting> {
    let mut out = Vec::new();
    for dir in laravel.iter().take(MAX_SITES) {
        let env_path = dir.join(".env");
        let Some(env) = util::read_limited(&env_path, 256 * 1024) else {
            continue;
        };
        let value = |key: &str| env_value(&env, key);
        let production = value("APP_ENV")
            .is_none_or(|v| v.eq_ignore_ascii_case("production") || v.eq_ignore_ascii_case("prod"));
        let debug = value("APP_DEBUG").is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");
        let mode = std::fs::metadata(&env_path)
            .map(|m| mode_of(&m))
            .unwrap_or(0);
        out.push(AppSetting {
            path: clip(&options.display(dir), 300),
            framework: "laravel".into(),
            debug_in_production: production && debug,
            missing_key: value("APP_KEY").is_none_or(|v| v.is_empty()),
            env_world_readable: mode & 0o004 != 0,
        });
    }

    out
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> u32 {
    0
}

/// A value in a .env file, without its quotes. Never reported, only tested.
fn env_value(env: &str, key: &str) -> Option<String> {
    env.lines().rev().find_map(|line| {
        let line = line.trim().trim_start_matches("export ");
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| {
            v.split(" #")
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['"', '\''])
                .to_string()
        })
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn write(root: &Path, path: &str, text: &str) {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }

    fn options(root: &Path) -> Options {
        Options {
            root: root.to_path_buf(),
            proc: root.join("proc"),
            docker_socket: None,
            apps_dir: None,
            commands: false,
            budget: Duration::from_secs(30),
        }
    }

    #[test]
    fn reads_caddy_sites() {
        let text = "{\n  email me@example.com\n}\n\n(common) {\n  encode gzip\n}\n\nshop.example.com, www.shop.example.com {\n  reverse_proxy 127.0.0.1:3000\n}\n\nhttp://blog.example.com {\n  root * /var/www/blog\n  file_server\n}\n:8080 {\n  respond ok\n}\n";
        let hosts = parse_caddyfile(text, "/etc/caddy/Caddyfile");
        assert_eq!(hosts.len(), 3);
        assert_eq!(
            hosts[0].names,
            vec!["shop.example.com", "www.shop.example.com"]
        );
        assert!(hosts[0].tls);
        assert_eq!(hosts[0].upstreams, vec!["127.0.0.1:3000"]);
        assert_eq!(hosts[1].names, vec!["blog.example.com"]);
        assert!(!hosts[1].tls);
        assert_eq!(hosts[1].root.as_deref(), Some("/var/www/blog"));
    }

    #[test]
    fn finds_risky_files_wordpress_and_laravel_debug() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Inline: nginx's absolute includes would read this machine's /etc.
        write(root, "/etc/nginx/nginx.conf", "http {\nserver { listen 443 ssl; server_name blog.example.com; root /var/www/blog; }\nserver { listen 80; server_name blog.example.com; root /var/www/blog; }\nserver { listen 80; server_name _; root /var/www/html; }\n}\n");
        write(root, "/var/www/blog/.env", "DB_PASSWORD=secret");
        write(root, "/var/www/blog/.git/HEAD", "ref: refs/heads/main");
        write(root, "/var/www/blog/old-site-2023.sql", "");
        write(root, "/var/www/blog/index.php", "");
        write(
            root,
            "/var/www/blog/wp-includes/version.php",
            "<?php\n$wp_version = '5.8.1';\n",
        );
        write(
            root,
            "/var/www/blog/wp-config.php",
            "<?php\ndefine( 'WP_DEBUG', true );\n",
        );
        write(
            root,
            "/var/www/blog/wp-content/plugins/contact-form-7/wp-contact-form-7.php",
            "<?php\n/*\nPlugin Name: Contact Form 7\nVersion: 5.3.1\n*/",
        );
        write(
            root,
            "/var/www/blog/wp-content/plugins/akismet/akismet.php",
            "<?php\n/**\n * Plugin Name: Akismet\n * Version: 4.1\n */",
        );
        write(
            root,
            "/var/www/blog/wp-content/plugins/empty/readme.txt",
            "",
        );
        write(
            root,
            "/var/www/blog/wp-content/themes/twentytwenty/style.css",
            "/*\nTheme Name: Twenty Twenty\nVersion: 1.0\n*/",
        );
        write(root, "/var/www/html/index.html", "");
        write(
            root,
            "/srv/app/.env",
            "APP_ENV=production\nAPP_KEY=\nAPP_DEBUG=true\n",
        );

        let sites = gather(&options(root));
        let blog = sites
            .iter()
            .find(|s| s.names == vec!["blog.example.com"])
            .unwrap();
        assert!(blog.tls, "the :80 and :443 blocks are one site, with TLS");
        assert_eq!(
            sites
                .iter()
                .filter(|s| s.names == vec!["blog.example.com"])
                .count(),
            1
        );
        assert_eq!(blog.risky_files, vec![".env", ".git", "old-site-2023.sql"]);
        let wp = blog.wordpress.as_ref().unwrap();
        assert_eq!(wp.version.as_deref(), Some("5.8.1"));
        assert!(wp.debug);
        assert!(wp.file_editing);
        assert_eq!(
            wp.plugins,
            vec![
                Extension {
                    slug: "akismet".into(),
                    version: Some("4.1".into())
                },
                Extension {
                    slug: "contact-form-7".into(),
                    version: Some("5.3.1".into())
                },
            ]
        );
        assert_eq!(wp.themes[0].slug, "twentytwenty");
        let default = sites
            .iter()
            .find(|s| s.root.as_deref() == Some("/var/www/html"))
            .unwrap();
        assert!(default.names.is_empty() && default.risky_files.is_empty());

        let apps = app_settings(&options(root), &[root.join("srv/app")]);
        assert_eq!(apps.len(), 1);
        assert!(apps[0].debug_in_production);
        assert!(apps[0].missing_key);
        assert_eq!(apps[0].path, "/srv/app");
    }

    #[test]
    fn wp_defines() {
        let config = "// define('WP_DEBUG', true);\ndefine(\"WP_DEBUG\" , false );\ndefine('DISALLOW_FILE_EDIT', true);";
        assert!(!wp_define_true(config, "WP_DEBUG"));
        assert!(wp_define_true(config, "DISALLOW_FILE_EDIT"));
        assert_eq!(
            wp_version("<?php\n$wp_version = \"6.4.2\";"),
            Some("6.4.2".into())
        );
    }

    #[test]
    fn domains() {
        assert!(looks_like_domain("shop.example.com"));
        assert!(looks_like_domain("*.example.com"));
        assert!(!looks_like_domain("_"));
        assert!(!looks_like_domain("localhost"));
        assert!(!looks_like_domain("127.0.0.1"));
        assert!(!looks_like_domain("app.test"));
        assert!(!looks_like_domain("~^(?<sub>.+)\\.example\\.com$"));
    }
}
