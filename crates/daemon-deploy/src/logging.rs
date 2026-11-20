//! Starting and stopping ServerOS's own access log for a site the machine's
//! own web server serves, only when asked (`TrafficLogging`). Caddy logs
//! nothing for a site without a `log` directive, which is its default;
//! nginx and Apache sites can have logging off; Traefik writes no access
//! log unless its static config says so.
//!
//! Adding never touches the user's own logging: Caddy gets a named log of
//! ServerOS's own in the site's block, nginx and Apache the same copy as
//! the response times fix (`timing`), Traefik on the machine an
//! `accessLog` section into a file ServerOS reads and empties. Every line
//! added is marked "Added by ServerOS", and removing takes out exactly
//! those lines (and puts back an `access_log off;` that adding commented
//! out). Both go through `timing::apply_fix`: backed up first, checked
//! (`caddy validate`, `nginx -t`, `apache2ctl configtest`; Traefik has no
//! check, so it's restarted and must come back up), put back on failure,
//! then reloaded.

use std::path::{Path, PathBuf};

use daemon_inventory::procs::glob_in;
use daemon_jobs::Failure;

use crate::existing::{Site, COPY_DIR};
use crate::timing::{
    self, commands, Edit, Insert, Places, TimingFix, COPY_COMMENT, KEPT_COMMENT, OFF_COMMENT,
};

pub const BEGIN: &str =
    "# Added by ServerOS: an access log of its own for traffic, which the daemon reads and empties.";
pub const END: &str = "# End of what ServerOS added.";
/// The one access log Traefik gets, in ServerOS's folder.
pub const TRAEFIK_FILE: &str = "traefik.access.log";

fn refuse(message: impl Into<String>) -> Failure {
    Failure::new("traffic", message.into())
}

/// The change that starts ServerOS's log for a site.
pub fn plan_add(site: &Site, places: &Places) -> Result<TimingFix, Failure> {
    if !site.info.editable {
        return Err(refuse(match site.info.container.as_deref() {
            Some(name) => format!("this site's server runs in the container {name}, so ServerOS won't change its config; turn on its access log in the container's config instead"),
            None => "this site's config isn't a file ServerOS can change".to_string(),
        }));
    }
    if site.info.copy {
        return Err(refuse("ServerOS already logs this site"));
    }
    match site.info.server.as_str() {
        "nginx" | "apache" => timing::plan_fix(site, places),
        "caddy" => caddy_add(site, places),
        "traefik" => traefik_add(site, places),
        other => Err(refuse(format!("ServerOS can't change {other}'s config"))),
    }
}

/// The change that takes ServerOS's lines out again.
pub fn plan_remove(site: &Site, places: &Places) -> Result<TimingFix, Failure> {
    if !site.info.copy {
        return Err(refuse(
            "ServerOS hasn't added anything to this site's config",
        ));
    }
    let server = site.info.server.as_str();
    let mut files: Vec<PathBuf> = site
        .blocks
        .iter()
        .map(|b| PathBuf::from(&b.config))
        .collect();
    if server == "caddy" {
        files = caddy_files(Path::new(
            site.info.configs.first().map(String::as_str).unwrap_or(""),
        ));
    }
    files.sort();
    files.dedup();
    let mut edits = Vec::new();
    for file in files {
        let Ok(before) = std::fs::read_to_string(&file) else {
            continue;
        };
        let (after, removed) = without_ours(
            &before,
            server,
            &places.traffic_dir.join(COPY_DIR),
            &site.info.site,
        );
        if !removed.is_empty() {
            edits.push(Edit {
                file,
                before: Some(before),
                after,
                inserts: removed,
            });
        }
    }
    if edits.is_empty() {
        return Err(refuse(
            "ServerOS's lines aren't in this site's config any more",
        ));
    }
    let (check, reload, verify, owner) = server_commands(server, site);
    let copies = copies_of(site, places);
    Ok(TimingFix {
        site: site.info.site.clone(),
        server: server.to_string(),
        edits,
        copies,
        check,
        reload,
        verify,
        owner,
        remove: true,
    })
}

fn copies_of(site: &Site, places: &Places) -> Vec<PathBuf> {
    let dir = places.traffic_dir.join(COPY_DIR);
    if site.info.server == "traefik" {
        return vec![dir.join(TRAEFIK_FILE)];
    }
    let mut keys: Vec<&str> = site.blocks.iter().map(|b| b.key.as_str()).collect();
    keys.push(&site.info.site);
    keys.sort_unstable();
    keys.dedup();
    keys.iter().map(|k| dir.join(format!("{k}.log"))).collect()
}

fn server_commands(
    server: &str,
    site: &Site,
) -> (Vec<String>, Vec<String>, Vec<String>, Option<String>) {
    let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    match server {
        "caddy" => {
            let file = site
                .info
                .configs
                .first()
                .cloned()
                .unwrap_or_else(|| "/etc/caddy/Caddyfile".into());
            let reload = if Path::new("/lib/systemd/system/caddy.service").exists()
                || Path::new("/etc/systemd/system/caddy.service").exists()
                || Path::new("/usr/lib/systemd/system/caddy.service").exists()
            {
                words(&["systemctl", "reload", "caddy"])
            } else {
                words(&[
                    "caddy",
                    "reload",
                    "--adapter",
                    "caddyfile",
                    "--config",
                    &file,
                ])
            };
            (
                words(&[
                    "caddy",
                    "validate",
                    "--adapter",
                    "caddyfile",
                    "--config",
                    &file,
                ]),
                reload,
                Vec::new(),
                Some("caddy".into()),
            )
        }
        "traefik" => (
            Vec::new(),
            words(&["systemctl", "restart", "traefik"]),
            words(&["systemctl", "is-active", "--quiet", "traefik"]),
            Some("traefik".into()),
        ),
        _ => {
            let (check, reload) = commands(server);
            (check, reload, Vec::new(), None)
        }
    }
}

/// `text` without the lines ServerOS added, and what came out, where.
fn without_ours(text: &str, server: &str, copies: &Path, key: &str) -> (String, Vec<Insert>) {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut out = String::with_capacity(text.len());
    let mut removed: Vec<Insert> = Vec::new();
    let copies = copies.display().to_string();
    let mut i = 0;
    let note = |removed: &mut Vec<Insert>, line_no: usize, taken: Vec<String>| {
        removed.push(Insert {
            at: format!("line {}", line_no + 1),
            lines: taken,
        });
    };
    while i < lines.len() {
        let line = lines[i].trim();
        if line == BEGIN {
            // Caddy and Traefik: everything up to the end marker.
            let mut taken = Vec::new();
            let start = i;
            let indent = lines[i].len() - lines[i].trim_start().len();
            while i < lines.len() {
                let raw = lines[i].trim_end();
                let cut = raw.len() - raw.trim_start().len();
                taken.push(raw[cut.min(indent)..].to_string());
                i += 1;
                if raw.trim() == END {
                    break;
                }
            }
            // Only this site's (Caddy names its file in the block).
            if server == "caddy" && !taken.iter().any(|l| l.contains(&format!("{key}.log"))) {
                for raw in &lines[start..i] {
                    out.push_str(raw);
                }
                continue;
            }
            // And the blank line put before it.
            if out.ends_with("\n\n") {
                out.pop();
            }
            note(&mut removed, start, taken);
            continue;
        }
        if line == COPY_COMMENT && lines.get(i + 1).is_some_and(|next| next.contains(&copies)) {
            note(
                &mut removed,
                i,
                vec![line.to_string(), lines[i + 1].trim().to_string()],
            );
            i += 2;
            continue;
        }
        if line == KEPT_COMMENT {
            let start = i;
            let mut taken = vec![line.to_string()];
            i += 1;
            while i < lines.len() {
                let next = lines[i].trim_start();
                if next.starts_with("access_log ") || next.starts_with("CustomLog ") {
                    taken.push(next.trim().to_string());
                    i += 1;
                } else {
                    break;
                }
            }
            note(&mut removed, start, taken);
            continue;
        }
        if line == OFF_COMMENT {
            if let Some(next) = lines.get(i + 1) {
                let trimmed = next.trim_start();
                if let Some(original) = trimmed.strip_prefix("# ") {
                    let indent = &next[..next.len() - trimmed.len()];
                    note(
                        &mut removed,
                        i,
                        vec![line.to_string(), trimmed.trim_end().to_string()],
                    );
                    out.push_str(indent);
                    out.push_str(original);
                    i += 2;
                    continue;
                }
            }
        }
        out.push_str(lines[i]);
        i += 1;
    }
    (out, removed)
}

/// The Caddyfile and the files its top-level `import`s name (not
/// snippets, and never ServerOS's own serveros.d).
fn caddy_files(caddyfile: &Path) -> Vec<PathBuf> {
    let mut files = vec![caddyfile.to_path_buf()];
    let Ok(text) = std::fs::read_to_string(caddyfile) else {
        return files;
    };
    let base = caddyfile.parent().unwrap_or(Path::new("/"));
    let mut budget = 100;
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(arg) = line.trim().strip_prefix("import ") else {
            continue;
        };
        let arg = arg.split_whitespace().next().unwrap_or("");
        if arg.contains("/serveros.d/")
            || !(arg.contains('/') || arg.contains('*') || arg.contains('.'))
        {
            continue;
        }
        let pattern = if arg.starts_with('/') {
            PathBuf::from(arg)
        } else {
            base.join(arg)
        };
        files.extend(glob_in(Path::new("/"), &pattern, &mut budget));
    }
    files
}

/// A top-level block of a Caddyfile: its addresses (empty for the global
/// options), and the byte index of its `{` and `}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaddyBlock {
    pub addresses: Vec<String>,
    pub open: usize,
    pub close: usize,
}

pub fn caddy_blocks(text: &str) -> Vec<CaddyBlock> {
    let bytes = text.as_bytes();
    let mut blocks = Vec::new();
    let mut depth = 0usize;
    let mut head = String::new();
    let mut open = 0usize;
    let mut addresses: Vec<String> = Vec::new();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    let mut line_start = true;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'#' if line_start || i == 0 || bytes[i - 1].is_ascii_whitespace() => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'"' | b'`' => quote = Some(c),
            b'{' => {
                // A placeholder like {host} is no block.
                let closes = text[i..].find(['}', '\n']).map(|n| bytes[i + n]);
                let next = bytes.get(i + 1).copied().unwrap_or(b'\n');
                if closes == Some(b'}') && !next.is_ascii_whitespace() {
                    if depth == 0 {
                        head.push(c as char);
                    }
                    i += 1;
                    continue;
                }
                if depth == 0 {
                    addresses = head
                        .split([',', ' ', '\t', '\n'])
                        .map(str::trim)
                        .filter(|a| !a.is_empty())
                        .map(str::to_string)
                        .collect();
                    open = i;
                    head.clear();
                }
                depth += 1;
            }
            b'}' => {
                if depth == 1 {
                    blocks.push(CaddyBlock {
                        addresses: std::mem::take(&mut addresses),
                        open,
                        close: i,
                    });
                }
                depth = depth.saturating_sub(1);
            }
            b'\n' if depth == 0 => {
                if !head.trim_end().ends_with(',') {
                    head.clear();
                }
                head.push(' ');
            }
            _ if depth == 0 => head.push(c as char),
            _ => {}
        }
        line_start = c == b'\n' || (line_start && c.is_ascii_whitespace());
        i += 1;
    }
    blocks
}

/// An address's host: `https://shop.test:443/x` → `shop.test`; empty for a
/// catch-all (`:443`, `https://`).
fn address_host(address: &str) -> String {
    let rest = address.split_once("://").map_or(address, |(_, r)| r);
    let rest = rest.split('/').next().unwrap_or("");
    let host = match rest.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => rest,
    };
    host.to_ascii_lowercase()
}

/// Which file and block a Caddy site is set up in.
fn find_caddy_block(
    site: &Site,
    caddyfile: &Path,
) -> Result<(PathBuf, String, CaddyBlock), Failure> {
    let catch_all = site.info.catch_all;
    let want = site.info.names.first().cloned().unwrap_or_default();
    let mut best: Option<(PathBuf, String, CaddyBlock, u8)> = None;
    for file in caddy_files(caddyfile) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (n, block) in caddy_blocks(&text).into_iter().enumerate() {
            if block.addresses.is_empty() && n == 0 {
                continue;
            }
            if block.addresses.first().is_some_and(|a| a.starts_with('(')) {
                continue;
            }
            let hosts: Vec<String> = block.addresses.iter().map(|a| address_host(a)).collect();
            let score = if catch_all {
                if hosts.iter().all(String::is_empty) {
                    // https:// or :443 before http://.
                    if block
                        .addresses
                        .iter()
                        .any(|a| a.starts_with("http://") || a == ":80")
                    {
                        1
                    } else {
                        2
                    }
                } else {
                    0
                }
            } else {
                u8::from(hosts.contains(&want)) * 2
            };
            if score > 0 && best.as_ref().is_none_or(|b| b.3 < score) {
                best = Some((file.clone(), text.clone(), block, score));
            }
        }
    }
    best.map(|(f, t, b, _)| (f, t, b)).ok_or_else(|| {
        refuse(format!(
            "couldn't find {} in {} or the files it imports, so ServerOS won't change it",
            if catch_all {
                "the catch-all site".to_string()
            } else {
                want
            },
            caddyfile.display()
        ))
    })
}

fn caddy_log_name(key: &str) -> String {
    let name: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(60)
        .collect();
    format!("serveros_{name}")
}

/// The lines a Caddy site gets: a named log of ServerOS's own.
pub fn caddy_lines(key: &str, file: &Path) -> Vec<String> {
    vec![
        BEGIN.to_string(),
        format!("log {} {{", caddy_log_name(key)),
        format!("\toutput file {} {{", file.display()),
        "\t\troll_size 50MiB".into(),
        "\t\troll_keep 1".into(),
        "\t\troll_uncompressed".into(),
        "\t}".into(),
        "\tformat json".into(),
        "}".into(),
        END.to_string(),
    ]
}

fn caddy_add(site: &Site, places: &Places) -> Result<TimingFix, Failure> {
    let caddyfile = PathBuf::from(
        site.info
            .configs
            .first()
            .filter(|c| c.starts_with('/'))
            .ok_or_else(|| {
                refuse(
                    "this Caddy doesn't run from a Caddyfile, so ServerOS won't change its config",
                )
            })?,
    );
    let (file, before, block) = find_caddy_block(site, &caddyfile)?;
    let copy = places
        .traffic_dir
        .join(COPY_DIR)
        .join(format!("{}.log", site.info.site));
    if before[block.open..block.close].contains(&copy.display().to_string()) {
        return Err(refuse("ServerOS already logs this site"));
    }
    let lines = caddy_lines(&site.info.site, &copy);
    let after = insert_lines_before_brace(&before, block.close, &lines);
    let label = format!(
        "the {} block, before its closing }}",
        block.addresses.join(", ")
    );
    let (check, reload, verify, owner) = server_commands("caddy", site);
    Ok(TimingFix {
        site: site.info.site.clone(),
        server: "caddy".into(),
        edits: vec![Edit {
            file,
            before: Some(before),
            after,
            inserts: vec![Insert { at: label, lines }],
        }],
        copies: vec![copy],
        check,
        reload,
        verify,
        owner,
        remove: false,
    })
}

/// `lines` before the `}` at `close`, indented one step in from it with
/// the file's own indent (a tab in most Caddyfiles).
pub fn insert_lines_before_brace(text: &str, close: usize, lines: &[String]) -> String {
    let unit = if text.contains("\n\t") { "\t" } else { "    " };
    let line_start = text[..close].rfind('\n').map_or(0, |n| n + 1);
    let before_brace = &text[line_start..close];
    let mut out = String::with_capacity(text.len() + 400);
    let (head, indent, tail) = if before_brace.trim().is_empty() {
        (
            &text[..line_start],
            format!("{before_brace}{unit}"),
            &text[line_start..],
        )
    } else {
        (text[..close].trim_end(), unit.to_string(), &text[close..])
    };
    out.push_str(head);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    for line in lines {
        out.push_str(&indent);
        out.push_str(&line.replace('\t', unit));
        out.push('\n');
    }
    out.push_str(tail);
    out
}

fn traefik_add(site: &Site, places: &Places) -> Result<TimingFix, Failure> {
    let file = PathBuf::from(site.info.configs.first().cloned().unwrap_or_default());
    if !file.is_absolute() {
        return Err(refuse(
            "Traefik's static config isn't a file, so ServerOS won't change it",
        ));
    }
    let before = std::fs::read_to_string(&file)
        .map_err(|e| refuse(format!("could not read {}: {e}", file.display())))?;
    if before.starts_with("# Installed by ServerOS.") {
        return Err(refuse(
            "this is ServerOS's own Traefik; turn Traefik on in the machine's settings instead",
        ));
    }
    let lower = before.to_ascii_lowercase();
    if lower.contains("accesslog") {
        return Err(refuse(format!(
            "{} already has an accessLog section",
            file.display()
        )));
    }
    let copy = places.traffic_dir.join(COPY_DIR).join(TRAEFIK_FILE);
    let toml = file.extension().is_some_and(|x| x == "toml");
    let lines = traefik_lines(&copy, toml);
    let mut after = before.clone();
    if !after.ends_with('\n') {
        after.push('\n');
    }
    after.push('\n');
    for line in &lines {
        after.push_str(line);
        after.push('\n');
    }
    let (check, reload, verify, owner) = server_commands("traefik", site);
    Ok(TimingFix {
        site: site.info.site.clone(),
        server: "traefik".into(),
        edits: vec![Edit {
            file,
            before: Some(before),
            after,
            inserts: vec![Insert {
                at: "the end of the file (Traefik restarts to read it, a second or so)".into(),
                lines,
            }],
        }],
        copies: vec![copy],
        check,
        reload,
        verify,
        owner,
        remove: false,
    })
}

fn traefik_lines(file: &Path, toml: bool) -> Vec<String> {
    let path = file.display();
    let body: Vec<String> = if toml {
        vec![
            "[accessLog]".into(),
            format!("  filePath = \"{path}\""),
            "  format = \"json\"".into(),
            "  [accessLog.fields.headers]".into(),
            "    defaultMode = \"drop\"".into(),
            "    [accessLog.fields.headers.names]".into(),
            "      \"User-Agent\" = \"keep\"".into(),
            "      \"Referer\" = \"keep\"".into(),
        ]
    } else {
        vec![
            "accessLog:".into(),
            format!("  filePath: \"{path}\""),
            "  format: json".into(),
            "  fields:".into(),
            "    headers:".into(),
            "      defaultMode: drop".into(),
            "      names:".into(),
            "        User-Agent: keep".into(),
            "        Referer: keep".into(),
        ]
    };
    std::iter::once(BEGIN.to_string())
        .chain(body)
        .chain(std::iter::once(END.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::existing::{plan_with, Site};
    use daemon_inventory::access_logs::{discover_in, LogFile, Paths, VhostLogs};

    const CADDYFILE: &str = "{\n\temail ops@example.com\n}\n\n(shared) {\n\tlog {\n\t\toutput file /var/log/caddy/access.log\n\t\tformat json\n\t}\n\troot * /var/www/app/public\n\tphp_fastcgi unix//run/php/php8.4-fpm.sock\n\tfile_server\n}\n\nshop.test {\n\timport shared\n}\n\nhttp:// {\n\tredir https://{host}{uri} permanent\n}\n\nquiet.test, www.quiet.test {\n\troot * /srv/quiet\n\tfile_server\n}\n\nhttps:// {\n\ttls {\n\t\ton_demand\n\t}\n\trespond \"hi\" 200\n}\n";

    fn places(dir: &Path) -> Places {
        Places {
            traffic_dir: dir.join("traffic"),
            nginx_conf: dir.join("nginx/nginx.conf"),
            nginx_format_file: dir.join("nginx/conf.d/00-serveros-timing.conf"),
            backups: dir.join("backups"),
        }
    }

    fn caddy_site(caddyfile: &Path, names: &[&str], catch_all: bool) -> Site {
        let vhost = VhostLogs {
            server: "caddy".into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            config_path: caddyfile.display().to_string(),
            catch_all,
            editable: true,
            unlogged: Some("off".into()),
            ..Default::default()
        };
        let plan = plan_with(&[vhost], Path::new("/var/log/serveros-traffic"), &[], &[]);
        plan.sites[0].clone()
    }

    #[test]
    fn caddyfile_blocks_are_found_by_address() {
        let blocks = caddy_blocks(CADDYFILE);
        let addresses: Vec<Vec<String>> = blocks.iter().map(|b| b.addresses.clone()).collect();
        assert_eq!(
            addresses,
            vec![
                vec![],
                vec!["(shared)".to_string()],
                vec!["shop.test".to_string()],
                vec!["http://".to_string()],
                vec!["quiet.test".to_string(), "www.quiet.test".to_string()],
                vec!["https://".to_string()],
            ]
        );
        assert_eq!(&CADDYFILE[blocks[4].close..blocks[4].close + 1], "}");
        assert_eq!(address_host("https://Shop.test:443/x"), "shop.test");
        assert_eq!(address_host(":443"), "");
    }

    #[test]
    fn a_caddy_site_gets_a_log_of_its_own_and_loses_it_again() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, CADDYFILE).unwrap();
        let places = places(dir.path());

        let quiet = caddy_site(&caddyfile, &["quiet.test", "www.quiet.test"], false);
        assert_eq!(quiet.info.site, "caddy.quiet.test");
        let fix = plan_add(&quiet, &places).unwrap();
        let copy = places.traffic_dir.join("existing/caddy.quiet.test.log");
        assert_eq!(fix.copies, vec![copy.clone()]);
        assert_eq!(
            fix.check[..2],
            ["caddy".to_string(), "validate".to_string()]
        );
        assert_eq!(fix.owner.as_deref(), Some("caddy"));
        let after = &fix.edits[0].after;
        let expected_block = format!(
            "quiet.test, www.quiet.test {{\n\troot * /srv/quiet\n\tfile_server\n\t{BEGIN}\n\tlog serveros_caddy_quiet_test {{\n\t\toutput file {} {{\n\t\t\troll_size 50MiB\n\t\t\troll_keep 1\n\t\t\troll_uncompressed\n\t\t}}\n\t\tformat json\n\t}}\n\t{END}\n}}\n",
            copy.display()
        );
        assert!(after.contains(&expected_block), "{after}");
        // Nothing else moved.
        assert_eq!(
            after.replace(&expected_block, ""),
            CADDYFILE.replace(
                "quiet.test, www.quiet.test {\n\troot * /srv/quiet\n\tfile_server\n}\n",
                ""
            )
        );
        let described = fix.describe(false);
        assert_eq!(described["action"], "add");
        assert_eq!(
            described["changes"][0]["at"],
            "the quiet.test, www.quiet.test block, before its closing }"
        );

        // The catch-all is the https:// block, not the http:// redirect.
        let any = caddy_site(&caddyfile, &[], true);
        assert_eq!(any.info.site, "caddy.any");
        let fix_any = plan_add(&any, &places).unwrap();
        assert!(fix_any.edits[0]
            .after
            .contains("\trespond \"hi\" 200\n\t# Added by ServerOS"));

        // Once it's there, removing takes out exactly those lines.
        std::fs::write(&caddyfile, after).unwrap();
        let mut added = quiet.clone();
        added.info.copy = true;
        let undo = plan_remove(&added, &places).unwrap();
        assert!(undo.remove);
        assert_eq!(undo.edits[0].after, CADDYFILE);
        assert_eq!(undo.edits[0].inserts[0].lines.len(), 10);
        assert_eq!(undo.describe(false)["action"], "remove");
    }

    #[test]
    fn a_site_in_a_container_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut site = caddy_site(Path::new("/etc/caddy/Caddyfile"), &["shop.test"], false);
        site.info.editable = false;
        site.info.container = Some("caddy".into());
        let err = plan_add(&site, &places(dir.path())).unwrap_err();
        assert!(err.message.contains("container caddy"), "{}", err.message);
    }

    #[test]
    fn nginx_logging_off_is_commented_out_and_put_back() {
        let dir = tempfile::tempdir().unwrap();
        let nginx = dir.path().join("nginx");
        std::fs::create_dir_all(nginx.join("sites-enabled")).unwrap();
        std::fs::create_dir_all(nginx.join("conf.d")).unwrap();
        std::fs::write(
            nginx.join("nginx.conf"),
            format!(
                "http {{\n    include {0}/conf.d/*.conf;\n    include {0}/sites-enabled/*;\n}}\n",
                nginx.display()
            ),
        )
        .unwrap();
        let original = "server {\n    server_name quiet.test;\n    access_log off;\n    location /x {\n        access_log off;\n    }\n}\n";
        std::fs::write(nginx.join("sites-enabled/quiet"), original).unwrap();
        let paths = Paths {
            nginx_confs: vec![(nginx.join("nginx.conf"), nginx.clone())],
            apache_confs: vec![],
            ..Paths::default()
        };
        let places = places(dir.path());
        let planned = plan_with(&discover_in(&paths), &places.traffic_dir, &[], &[]);
        let quiet = planned.site("nginx.quiet.test").unwrap();
        assert_eq!(quiet.info.unlogged.as_deref(), Some("off"));
        let fix = plan_add(quiet, &places).unwrap();
        let after = &fix.edits[1].after;
        let copy = places.traffic_dir.join("existing/nginx.quiet.test.log");
        assert_eq!(
            after,
            &format!(
                "server {{\n    server_name quiet.test;\n    {OFF_COMMENT}\n    # access_log off;\n    location /x {{\n        access_log off;\n    }}\n    {COPY_COMMENT}\n    access_log {} serveros_timed;\n}}\n",
                copy.display()
            )
        );
        std::fs::write(nginx.join("sites-enabled/quiet"), after).unwrap();
        let mut added = quiet.clone();
        added.info.copy = true;
        let undo = plan_remove(&added, &places).unwrap();
        assert_eq!(undo.edits[0].after, original);
    }

    #[test]
    fn traefik_gets_an_access_log_section_and_loses_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("traefik.yml");
        let original = "entryPoints:\n  web:\n    address: \":80\"\n";
        std::fs::write(&file, original).unwrap();
        let vhost = VhostLogs {
            server: "traefik".into(),
            names: vec!["blog.test".into()],
            config_path: file.display().to_string(),
            editable: true,
            unlogged: Some("off".into()),
            routers: vec!["blog@file".into()],
            ..Default::default()
        };
        let places = places(dir.path());
        let planned = plan_with(std::slice::from_ref(&vhost), &places.traffic_dir, &[], &[]);
        let fix = plan_add(&planned.sites[0], &places).unwrap();
        assert!(fix.check.is_empty());
        assert_eq!(fix.reload, ["systemctl", "restart", "traefik"]);
        assert!(!fix.verify.is_empty());
        let after = fix.edits[0].after.clone();
        assert!(after.starts_with(original));
        assert!(after.contains("accessLog:\n  filePath: \""));

        // Once it's there, the site is counted from ServerOS's file, which
        // it empties as it reads, and can be taken out again.
        std::fs::write(&file, &after).unwrap();
        let logged = VhostLogs {
            logs: vec![LogFile {
                format: daemon_inventory::access_logs::FORMAT_TRAEFIK.into(),
                ..LogFile::file(
                    places.traffic_dir.join("existing/traefik.access.log"),
                    "",
                    None,
                )
            }],
            unlogged: None,
            ..vhost
        };
        let planned = plan_with(&[logged], &places.traffic_dir, &[], &[]);
        let site = &planned.sites[0];
        assert!(site.info.copy && site.info.unlogged.is_none());
        assert!(matches!(
            planned.sources[0].reader,
            crate::existing::Reader::Drain(_)
        ));
        let undo = plan_remove(site, &places).unwrap();
        assert_eq!(undo.edits[0].after, original);
    }
}
