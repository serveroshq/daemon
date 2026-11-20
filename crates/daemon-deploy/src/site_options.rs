//! The switches on an app's site: a maintenance page, a password in front
//! of it and redirects. Kept beside the site files, one JSON file per app,
//! so every proxy writes them the same way and they outlive deploys, proxy
//! switches and tunnels.

use std::path::{Path, PathBuf};

use daemon_jobs::Failure;
pub use daemon_protocol::{BasicAuth, PathRedirect, SiteOptions};

/// Where each app's switches are kept, by the stem of its site file.
pub const SITES_DIR: &str = "/var/lib/serveros/sites";

/// Where the daemon serves maintenance pages, on loopback only. A site in
/// maintenance sends its visitors here instead of to the app, so every
/// proxy, Traefik too, serves the page the same way.
pub const MAINTENANCE_LISTEN: &str = "127.0.0.1:47020";
pub const MAINTENANCE_PORT: u16 = 47020;

const MAX_HTML: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 50;

fn bad(message: impl Into<String>) -> Failure {
    Failure::new("site_options", message)
}

/// Checks switches before anything is written. Everything here ends up in
/// a proxy's config, so only plain characters get through.
pub fn validate(options: &SiteOptions) -> Result<(), Failure> {
    if options
        .maintenance_html
        .as_ref()
        .is_some_and(|html| html.len() > MAX_HTML)
    {
        return Err(bad("the maintenance page is over 256 KB"));
    }

    if let Some(auth) = &options.basic_auth {
        let user_ok = !auth.user.is_empty()
            && auth.user.len() <= 64
            && auth
                .user
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
        if !user_ok {
            return Err(bad(
                "the username can only have letters, numbers and . _ - @",
            ));
        }
        if !is_bcrypt(&auth.hash) {
            return Err(bad("the password has to be sent as a bcrypt hash"));
        }
    }

    if options.redirects.len() > MAX_REDIRECTS {
        return Err(bad(format!("at most {MAX_REDIRECTS} redirects")));
    }
    let mut seen: Vec<&str> = Vec::new();
    for redirect in &options.redirects {
        if !path_ok(&redirect.from) {
            return Err(bad(format!(
                "{:?} isn't a path to redirect: start it with / and use letters, numbers and - . _ ~ /",
                redirect.from
            )));
        }
        if !target_ok(&redirect.to) {
            return Err(bad(format!(
                "{:?} isn't somewhere to redirect to: a path starting with / or an http(s) address, without spaces, quotes, % or $",
                redirect.to
            )));
        }
        if seen.contains(&redirect.from.as_str()) {
            return Err(bad(format!("{} is redirected twice", redirect.from)));
        }
        seen.push(&redirect.from);
    }

    Ok(())
}

/// `$2a$`, `$2b$` or `$2y$`, a two-digit cost and 53 characters of salt
/// and hash.
fn is_bcrypt(hash: &str) -> bool {
    let b = hash.as_bytes();
    b.len() == 60
        && b[0] == b'$'
        && b[1] == b'2'
        && matches!(b[2], b'a' | b'b' | b'y')
        && b[3] == b'$'
        && b[4].is_ascii_digit()
        && b[5].is_ascii_digit()
        && b[6] == b'$'
        && b[7..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'/'))
}

/// An exact path: `/`, then letters, numbers and `- . _ ~ /`. Never under
/// /.well-known/acme-challenge/, which certificates need.
fn path_ok(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && path.len() <= 500
        && !path.starts_with("/.well-known/acme-challenge/")
        && !path.contains("//")
        && !path.split('/').any(|part| part == "..")
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '/'))
}

/// A path on the same site or a full http(s) address. No `%` or `$`
/// (variables or back-references in nginx and Apache), no `{}` (Caddy
/// placeholders), no `#`, quotes, spaces or backslashes.
fn target_ok(to: &str) -> bool {
    let rest = if let Some(rest) = to.strip_prefix("https://") {
        rest
    } else if let Some(rest) = to.strip_prefix("http://") {
        rest
    } else if to.starts_with('/') && !to.starts_with("//") {
        to
    } else {
        return false;
    };
    !rest.is_empty()
        && to.len() <= 2000
        && to.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '.'
                        | '_'
                        | '~'
                        | '/'
                        | ':'
                        | '?'
                        | '&'
                        | '='
                        | '+'
                        | '@'
                        | '!'
                        | ','
                        | '*'
                        | '('
                        | ')'
                )
        })
}

/// The name that redirects to `domain` when www redirects are on:
/// `www.example.com` for `example.com`, and `example.com` for
/// `www.example.com`. None for wildcards.
pub fn counterpart(domain: &str) -> Option<String> {
    if domain.starts_with("*.") {
        return None;
    }
    match domain.strip_prefix("www.") {
        Some(bare) if bare.contains('.') => Some(bare.to_string()),
        Some(_) => None,
        None => Some(format!("www.{domain}")),
    }
}

fn file(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!("{stem}.json"))
}

/// An app's switches, all off when it has none (or the file is unreadable).
pub fn load(dir: &Path, stem: &str) -> SiteOptions {
    std::fs::read_to_string(file(dir, stem))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Keeps an app's switches, root-only. All off removes the file.
pub fn save(dir: &Path, stem: &str, options: &SiteOptions) -> std::io::Result<()> {
    let path = file(dir, stem);
    if *options == SiteOptions::default() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let text = serde_json::to_string(options).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(tmp, path)
}

pub fn remove(dir: &Path, stem: &str) {
    let _ = std::fs::remove_file(file(dir, stem));
}

/// The page visitors see while a site is in maintenance: the app's own
/// HTML, or a plain one naming the site.
pub fn maintenance_page(options: &SiteOptions, host: &str) -> String {
    if let Some(html) = options
        .maintenance_html
        .as_ref()
        .filter(|h| !h.trim().is_empty())
    {
        return html.clone();
    }
    let host: String = host
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        .collect();
    let name = if host.is_empty() {
        "This site".to_string()
    } else {
        host
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Back soon</title>\n<style>\nbody{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,-apple-system,sans-serif;background:#fafafa;color:#1d1d1f}}\n@media (prefers-color-scheme: dark){{body{{background:#161616;color:#ededed}}}}\nmain{{max-width:30rem;padding:2rem;text-align:center}}\nh1{{font-size:1.5rem;margin:0 0 .5rem}}\np{{margin:0;opacity:.75}}\n</style>\n</head>\n<body>\n<main>\n<h1>Back soon</h1>\n<p>{name} is down for maintenance. Try again in a few minutes.</p>\n</main>\n</body>\n</html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "$2y$10$abcdefghijklmnopqrstuuJ7lYk0x0k9w2v3Zr8mQxqf5yJ1sZ6a.";

    fn redirect(from: &str, to: &str) -> PathRedirect {
        PathRedirect {
            from: from.into(),
            to: to.into(),
            permanent: true,
        }
    }

    #[test]
    fn plain_switches_pass() {
        let options = SiteOptions {
            maintenance: true,
            maintenance_html: Some("<h1>Soon</h1>".into()),
            basic_auth: Some(BasicAuth {
                user: "staff".into(),
                hash: HASH.into(),
            }),
            www_redirect: true,
            redirects: vec![
                redirect("/old-pricing", "/pricing"),
                redirect("/docs", "https://docs.acme.io/start?ref=site"),
            ],
        };
        assert!(validate(&options).is_ok());
    }

    #[test]
    fn anything_that_could_reach_a_proxy_config_is_refused() {
        for (from, to) in [
            ("old", "/new"),
            ("/", "/new"),
            ("/a b", "/new"),
            ("/a;b", "/new"),
            ("/a{b}", "/new"),
            ("/../etc", "/new"),
            ("/.well-known/acme-challenge/x", "/new"),
            ("/old", "new"),
            ("/old", "//evil.io"),
            ("/old", "/new$1"),
            ("/old", "/new%20page"),
            ("/old", "/new\"page"),
            ("/old", "/new{uri}"),
            ("/old", "/new#top"),
            ("/old", "javascript:alert(1)"),
            ("/old", "https://"),
        ] {
            let options = SiteOptions {
                redirects: vec![redirect(from, to)],
                ..Default::default()
            };
            assert!(validate(&options).is_err(), "{from} -> {to} got through");
        }

        let twice = SiteOptions {
            redirects: vec![redirect("/a", "/b"), redirect("/a", "/c")],
            ..Default::default()
        };
        assert!(validate(&twice).is_err());
    }

    #[test]
    fn a_password_only_arrives_hashed() {
        for (user, hash) in [
            ("staff", "hunter2"),
            ("staff", "$1$abcdefgh$abcdefghijklmnopqrstuv"),
            ("st aff", HASH),
            ("staff:x", HASH),
            ("", HASH),
        ] {
            let options = SiteOptions {
                basic_auth: Some(BasicAuth {
                    user: user.into(),
                    hash: hash.into(),
                }),
                ..Default::default()
            };
            assert!(validate(&options).is_err(), "{user} {hash} got through");
        }
    }

    #[test]
    fn www_and_bare_names_point_at_each_other() {
        assert_eq!(counterpart("acme.io").as_deref(), Some("www.acme.io"));
        assert_eq!(counterpart("www.acme.io").as_deref(), Some("acme.io"));
        assert_eq!(
            counterpart("shop.acme.io").as_deref(),
            Some("www.shop.acme.io")
        );
        assert_eq!(counterpart("*.acme.io"), None);
        assert_eq!(counterpart("www.io"), None);
    }

    #[test]
    fn switches_are_kept_and_all_off_removes_them() {
        let dir = tempfile::tempdir().unwrap();
        let options = SiteOptions {
            maintenance: true,
            ..Default::default()
        };
        save(dir.path(), "shop", &options).unwrap();
        assert_eq!(load(dir.path(), "shop"), options);

        save(dir.path(), "shop", &SiteOptions::default()).unwrap();
        assert!(!dir.path().join("shop.json").exists());
        assert_eq!(load(dir.path(), "shop"), SiteOptions::default());
    }

    #[test]
    fn the_default_page_names_the_site_and_nothing_else() {
        let page = maintenance_page(&SiteOptions::default(), "shop.acme.io");
        assert!(page.contains("shop.acme.io is down for maintenance"));
        let page = maintenance_page(&SiteOptions::default(), "<script>x</script>");
        assert!(!page.contains("<script>x"));
        let custom = SiteOptions {
            maintenance_html: Some("<p>ours</p>".into()),
            ..Default::default()
        };
        assert_eq!(maintenance_page(&custom, "acme.io"), "<p>ours</p>");
    }
}
