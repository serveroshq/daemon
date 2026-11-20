//! Response times for a site the machine's own nginx or Apache serves,
//! only when asked: its log formats (`combined` and the like) don't record
//! how long a request took. The fix gives each of the site's server blocks
//! (or VirtualHosts) a second access log, in ServerOS's format, which the
//! daemon reads in place of the first. Nothing else in the user's config
//! changes: the lines are added before each block's closing brace, the log
//! the block wrote before keeps being written (when it was inherited, it's
//! named in the block so it still is), and for nginx the format itself
//! goes in a file of ServerOS's own in conf.d.
//!
//! Without `apply`, nothing changes and the result says exactly which
//! lines would be added where. With it, each file is backed up first, the
//! config is checked (`nginx -t`, `apache2ctl configtest`), every file is
//! put back if the check fails, and the server is reloaded.

use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_jobs::{run_child, Failure, Progress};
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::existing::{Block, Site, COPY_DIR};
use crate::traffic::APACHE_LOG_FORMAT;

/// The name of ServerOS's nginx log format for these copies. Its own name,
/// so it can't clash with the one ServerOS's own sites use.
pub const NGINX_FORMAT: &str = "serveros_timed";
/// In conf.d, named to be read before the other files there: nginx needs
/// a log format defined before an access_log names it.
pub const NGINX_FORMAT_FILE: &str = "/etc/nginx/conf.d/00-serveros-timing.conf";
const FORMAT_FILE_TEXT: &str = "# Written by ServerOS: the format of the copies of access logs it reads\n# for response times. Used by lines it added to your server blocks, each\n# marked \"Added by ServerOS\".\nlog_format serveros_timed escape=json '{\"t\":$msec,\"host\":\"$host\",\"ip\":\"$remote_addr\",\"uri\":\"$request_uri\",\"status\":$status,\"bytes\":$body_bytes_sent,\"time\":$request_time,\"referer\":\"$http_referer\",\"ua\":\"$http_user_agent\"}';\n";
pub(crate) const COPY_COMMENT: &str =
    "# Added by ServerOS: a copy of this site's access log with response times.";
pub(crate) const KEPT_COMMENT: &str =
    "# Added by ServerOS: the access log this block already wrote, so it still does.";
/// Put above a block's own `access_log off;`, which is commented out while
/// ServerOS logs the site (nginx writes no log at all on that level while
/// it's there), and put back when it stops.
pub(crate) const OFF_COMMENT: &str =
    "# Added by ServerOS: the next line was access_log off; it comes back when ServerOS stops logging this site.";

/// Where things are. The real paths in production; folders in tests.
#[derive(Debug, Clone)]
pub struct Places {
    pub traffic_dir: PathBuf,
    pub nginx_conf: PathBuf,
    pub nginx_format_file: PathBuf,
    /// Where the files are copied before they're changed.
    pub backups: PathBuf,
}

/// The lines added in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insert {
    /// Where, in words: "server block 2 (shop.test), before its closing }".
    pub at: String,
    pub lines: Vec<String>,
}

/// One file the fix changes or writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    pub file: PathBuf,
    /// None for a file that isn't there yet.
    pub before: Option<String>,
    pub after: String,
    pub inserts: Vec<Insert>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingFix {
    pub site: String,
    pub server: String,
    pub edits: Vec<Edit>,
    /// The copies the server will write.
    pub copies: Vec<PathBuf>,
    pub check: Vec<String>,
    pub reload: Vec<String>,
    /// Run after the reload until it succeeds (a few tries): for a server
    /// with no config check, that it came back up.
    pub verify: Vec<String>,
    /// The user the server writes its logs as, when that isn't root.
    pub owner: Option<String>,
    /// Takes ServerOS's lines out rather than adding them.
    pub remove: bool,
}

impl TimingFix {
    /// What the panel shows before anything changes: every line, and where.
    pub fn describe(&self, applied: bool) -> Value {
        let places: Vec<Value> = self
            .edits
            .iter()
            .flat_map(|edit| {
                edit.inserts.iter().map(move |insert| {
                    json!({
                        "file": edit.file.display().to_string(),
                        "new": edit.before.is_none(),
                        "at": insert.at,
                        "lines": insert.lines,
                    })
                })
            })
            .collect();
        json!({
            "site": self.site,
            "server": self.server,
            "action": if self.remove { "remove" } else { "add" },
            "applied": applied,
            "changes": places,
            "copies": self.copies.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "check": self.check.join(" "),
            "reload": self.reload.join(" "),
            "verify": self.verify.join(" "),
        })
    }
}

pub(crate) fn refuse(message: impl Into<String>) -> Failure {
    Failure::new("traffic", message.into())
}

/// The byte ranges of the server blocks in an nginx file whose parent is
/// the http block (or the file itself, for an included site file): the
/// index of `{` and of its `}`.
pub(crate) fn nginx_server_blocks(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut blocks = Vec::new();
    let mut stack: Vec<(String, Option<usize>)> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' | b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != c {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                word.push('q');
            }
            b'{' => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
                let name = words.first().cloned().unwrap_or_default();
                let parent_ok = stack.last().is_none_or(|(p, _)| p == "http");
                let open = (name == "server" && parent_ok).then_some(i);
                stack.push((name, open));
                words.clear();
            }
            b'}' => {
                if let Some((_, Some(open))) = stack.pop() {
                    blocks.push((open, i));
                }
                words.clear();
                word.clear();
            }
            b';' => {
                words.clear();
                word.clear();
            }
            c if c.is_ascii_whitespace() => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c as char),
        }
        i += 1;
    }
    blocks.sort();
    blocks
}

/// The line ranges of an Apache file's VirtualHosts: the index of the line
/// that opens each and the one that closes it.
pub(crate) fn apache_vhosts(text: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut open = None;
    for (n, line) in text.lines().enumerate() {
        let lower = line.trim().to_ascii_lowercase();
        if lower.starts_with("<virtualhost") {
            open = Some(n);
        } else if lower.starts_with("</virtualhost") {
            if let Some(start) = open.take() {
                found.push((start, n));
            }
        }
    }
    found
}

pub(crate) fn indent_of(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// `lines` put before the `}` at `close`, indented one step in from it.
pub(crate) fn insert_before_brace(text: &str, close: usize, lines: &[String]) -> String {
    let line_start = text[..close].rfind('\n').map_or(0, |n| n + 1);
    let before_brace = &text[line_start..close];
    let mut out = String::with_capacity(text.len() + 200);
    if before_brace.trim().is_empty() {
        let indent = format!("{before_brace}    ");
        out.push_str(&text[..line_start]);
        for line in lines {
            out.push_str(&format!("{indent}{line}\n"));
        }
        out.push_str(&text[line_start..]);
    } else {
        // `server { ... }` on one line: the brace goes on a line of its own.
        let indent = format!("{}    ", indent_of(before_brace));
        out.push_str(text[..close].trim_end());
        out.push('\n');
        for line in lines {
            out.push_str(&format!("{indent}{line}\n"));
        }
        out.push_str(indent_of(before_brace));
        out.push_str(&text[close..]);
    }
    out
}

pub(crate) fn insert_before_line(text: &str, line_index: usize, lines: &[String]) -> String {
    let mut out = String::with_capacity(text.len() + 200);
    for (n, line) in text.split_inclusive('\n').enumerate() {
        if n == line_index {
            let indent = format!("{}    ", indent_of(line));
            for added in lines {
                out.push_str(&format!("{indent}{added}\n"));
            }
        }
        out.push_str(line);
    }
    out
}

fn copy_path(places: &Places, block: &Block) -> PathBuf {
    places
        .traffic_dir
        .join(COPY_DIR)
        .join(format!("{}.log", block.key))
}

fn apache_quoted(format: &str) -> String {
    format!("\"{}\"", format.replace('"', "\\\""))
}

/// The lines one block gets.
fn lines_for(server: &str, block: &Block, copy: &Path) -> Result<Vec<String>, Failure> {
    let mut lines = Vec::new();
    if let Some(inherited) = &block.inherited {
        if !inherited.is_empty() {
            lines.push(KEPT_COMMENT.to_string());
        }
        for log in inherited {
            let path = log.path.display();
            lines.push(match (server, log.format_name.as_deref()) {
                ("nginx", Some("combined")) => format!("access_log {path};"),
                ("nginx", Some(name)) => format!("access_log {path} {name};"),
                ("nginx", None) => {
                    return Err(refuse(format!(
                        "couldn't tell which log format {path} uses, so ServerOS won't touch the config"
                    )))
                }
                (_, Some(name)) => format!("CustomLog {path} {name}"),
                (_, None) => format!("CustomLog {path} {}", apache_quoted(&log.format)),
            });
        }
    }
    lines.push(COPY_COMMENT.to_string());
    lines.push(if server == "nginx" {
        format!("access_log {} {NGINX_FORMAT};", copy.display())
    } else {
        format!("CustomLog {} {APACHE_LOG_FORMAT}", copy.display())
    });
    Ok(lines)
}

/// What the fix would change for `site`, changing nothing.
pub fn plan_fix(site: &Site, places: &Places) -> Result<TimingFix, Failure> {
    let server = site.info.server.as_str();
    if !matches!(server, "nginx" | "apache") {
        return Err(refuse(format!(
            "{server} sites can't record response times"
        )));
    }
    if site.info.copy {
        return Err(refuse("this site already records response times"));
    }
    if site.info.unlogged.as_deref() == Some("elsewhere") {
        return Err(refuse(
            "this site's log goes to syslog or a pipe, and a log of ServerOS's own here would stop that, so ServerOS won't change it",
        ));
    }
    if !site.info.editable {
        return Err(refuse(
            "this site's config is inside a container, so ServerOS won't change it",
        ));
    }
    let mut edits: Vec<Edit> = Vec::new();
    let mut copies = Vec::new();

    if server == "nginx" {
        let main = std::fs::read_to_string(&places.nginx_conf).unwrap_or_default();
        let includes_conf_d = main.lines().any(|line| {
            let line = line.trim();
            line.starts_with("include") && line.contains("conf.d/*.conf")
        });
        if !includes_conf_d {
            return Err(refuse(format!(
                "{} doesn't include conf.d/*.conf, so there's nowhere for ServerOS's log format without editing it",
                places.nginx_conf.display()
            ))
            .with_next_step("Add `include /etc/nginx/conf.d/*.conf;` to its http block, then try again."));
        }
        let current = std::fs::read_to_string(&places.nginx_format_file).ok();
        if current.as_deref() != Some(FORMAT_FILE_TEXT) {
            if current.is_some_and(|text| !text.starts_with("# Written by ServerOS")) {
                return Err(refuse(format!(
                    "{} is there and isn't ServerOS's, so it won't be overwritten",
                    places.nginx_format_file.display()
                )));
            }
            edits.push(Edit {
                file: places.nginx_format_file.clone(),
                before: std::fs::read_to_string(&places.nginx_format_file).ok(),
                after: FORMAT_FILE_TEXT.to_string(),
                inserts: vec![Insert {
                    at: "a new file of ServerOS's own".into(),
                    lines: FORMAT_FILE_TEXT.lines().map(str::to_string).collect(),
                }],
            });
        }
    }

    let mut configs: Vec<&str> = site.blocks.iter().map(|b| b.config.as_str()).collect();
    configs.dedup();
    configs.sort_unstable();
    configs.dedup();
    for config in configs {
        let before = std::fs::read_to_string(config)
            .map_err(|e| refuse(format!("could not read {config}: {e}")))?;
        let blocks: Vec<&Block> = site.blocks.iter().filter(|b| b.config == config).collect();
        let mut after = before.clone();
        let mut inserts = Vec::new();
        // From the last block up, so earlier positions stay put.
        let mut ordered = blocks.clone();
        ordered.sort_by_key(|b| std::cmp::Reverse(b.block));
        for block in ordered {
            let copy = copy_path(places, block);
            if !copies.contains(&copy) {
                copies.push(copy.clone());
            }
            let lines = lines_for(server, block, &copy)?;
            let label = |kind: &str| {
                let name = block.key.split_once('.').map_or("", |(_, name)| name);
                format!(
                    "{kind} {} ({name}), before its closing line",
                    block.block + 1
                )
            };
            if server == "nginx" {
                let found = nginx_server_blocks(&after);
                let &(open, close) = found.get(block.block).ok_or_else(|| {
                    refuse(format!("{config} changed since it was read; try again"))
                })?;
                if after[open..close].contains(&copy.display().to_string()) {
                    continue;
                }
                let mut lines = lines;
                // Its own `access_log off;` would stop every log on its
                // level, ServerOS's too: commented out, and noted.
                let offs = block_level_off(&after, open, close);
                if !offs.is_empty() {
                    lines.retain(|l| l != KEPT_COMMENT);
                    after = insert_before_brace(&after, close, &lines);
                    for at in offs.into_iter().rev() {
                        after = comment_out_off(&after, at);
                    }
                    inserts.push(Insert {
                        at: label("server block"),
                        lines: [
                            vec![OFF_COMMENT.to_string(), "# access_log off;".to_string()],
                            lines,
                        ]
                        .concat(),
                    });
                    continue;
                }
                after = insert_before_brace(&after, close, &lines);
                inserts.push(Insert {
                    at: label("server block"),
                    lines,
                });
            } else {
                let found = apache_vhosts(&after);
                let &(open, close) = found.get(block.block).ok_or_else(|| {
                    refuse(format!("{config} changed since it was read; try again"))
                })?;
                let inside: String = after.lines().skip(open).take(close - open).collect();
                if inside.contains(&copy.display().to_string()) {
                    continue;
                }
                after = insert_before_line(&after, close, &lines);
                inserts.push(Insert {
                    at: label("VirtualHost"),
                    lines,
                });
            }
        }
        if !inserts.is_empty() {
            inserts.reverse();
            edits.push(Edit {
                file: PathBuf::from(config),
                before: Some(before),
                after,
                inserts,
            });
        }
    }
    if edits.iter().all(|e| e.before.is_none()) && edits.len() <= 1 && copies.is_empty() {
        return Err(refuse("there are no server blocks for this site to change"));
    }

    let (check, reload) = commands(server);
    Ok(TimingFix {
        site: site.info.site.clone(),
        server: server.to_string(),
        edits,
        copies,
        check,
        reload,
        verify: Vec::new(),
        owner: None,
        remove: false,
    })
}

/// Where each `access_log off;` sits directly in a server block (not in
/// its locations): the byte index of its line's start.
fn block_level_off(text: &str, open: usize, close: usize) -> Vec<usize> {
    let mut found = Vec::new();
    let mut depth = 0usize;
    let mut line_start = open + 1;
    let bytes = text.as_bytes();
    let mut i = open + 1;
    while i < close {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b'#' => {
                while i < close && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'\n' => line_start = i + 1,
            _ => {}
        }
        if depth == 0 && text[i..].starts_with("access_log") {
            let rest = &text[i + "access_log".len()..];
            let statement = rest.split(';').next().unwrap_or("");
            if statement.trim() == "off" && text[line_start..i].trim().is_empty() {
                found.push(line_start);
            }
        }
        i += 1;
    }
    found
}

/// The `access_log off;` line at `at` commented out, with ServerOS's note
/// above it.
fn comment_out_off(text: &str, at: usize) -> String {
    let end = text[at..].find('\n').map_or(text.len(), |n| at + n);
    let line = &text[at..end];
    let indent = indent_of(line);
    format!(
        "{}{indent}{OFF_COMMENT}\n{indent}# {}{}",
        &text[..at],
        line.trim_start(),
        &text[end..]
    )
}

pub(crate) fn commands(server: &str) -> (Vec<String>, Vec<String>) {
    let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    if server == "nginx" {
        (words(&["nginx", "-t"]), words(&["nginx", "-s", "reload"]))
    } else if Path::new("/usr/sbin/apache2ctl").exists()
        || !Path::new("/usr/sbin/apachectl").exists()
    {
        (
            words(&["apache2ctl", "configtest"]),
            words(&["systemctl", "reload", "apache2"]),
        )
    } else {
        (
            words(&["apachectl", "configtest"]),
            words(&["systemctl", "reload", "httpd"]),
        )
    }
}

pub(crate) async fn run(
    command: &[String],
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Vec<String>> {
    let Some((program, args)) = command.split_first() else {
        return Ok(());
    };
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = run_child(
        program,
        &args,
        None,
        &[],
        Duration::from_secs(60),
        cancel,
        progress,
        None,
    )
    .await;
    if outcome.success() {
        Ok(())
    } else {
        Err(outcome.tail().to_vec())
    }
}

pub(crate) fn put_back(edits: &[Edit]) {
    for edit in edits {
        match &edit.before {
            Some(before) => {
                let _ = std::fs::write(&edit.file, before);
            }
            None => {
                let _ = std::fs::remove_file(&edit.file);
            }
        }
    }
}

/// Makes the change: backs the files up, writes them, checks the config,
/// and reloads. Puts every file back if the check or the reload fails.
pub async fn apply_fix(
    fix: &TimingFix,
    places: &Places,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<Value, Failure> {
    use std::os::unix::fs::PermissionsExt;

    if fix.edits.is_empty() {
        return Ok(fix.describe(true));
    }
    let stamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let backups = places.backups.join(format!("{}-{stamp}", fix.site));
    std::fs::create_dir_all(&backups)
        .map_err(|e| refuse(format!("could not make {}: {e}", backups.display())))?;
    for edit in &fix.edits {
        if let Some(before) = &edit.before {
            let name = edit
                .file
                .display()
                .to_string()
                .trim_start_matches('/')
                .replace('/', "_");
            std::fs::write(backups.join(name), before)
                .map_err(|e| refuse(format!("could not back up {}: {e}", edit.file.display())))?;
        }
    }
    progress
        .line(format!(
            "Backed up the files it changes to {}",
            backups.display()
        ))
        .await;

    // The server opens its logs as root when it reloads; nobody else may
    // read them, since they hold visitors' addresses until they're read.
    let copies = places.traffic_dir.join(COPY_DIR);
    std::fs::create_dir_all(&copies)
        .and_then(|_| {
            std::fs::set_permissions(&places.traffic_dir, std::fs::Permissions::from_mode(0o750))
        })
        .and_then(|_| std::fs::set_permissions(&copies, std::fs::Permissions::from_mode(0o750)))
        .map_err(|e| refuse(format!("could not make {}: {e}", copies.display())))?;
    let owner = fix.owner.as_deref().and_then(crate::proxy::system_user);
    if let Some((uid, gid)) = owner {
        // The server writes as its own user: it needs into the folder.
        let _ = std::os::unix::fs::chown(&places.traffic_dir, None, Some(gid));
        std::os::unix::fs::chown(&copies, Some(uid), Some(gid)).map_err(|e| {
            refuse(format!(
                "could not hand {} to its server: {e}",
                copies.display()
            ))
        })?;
    }
    for copy in &fix.copies {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(copy)
            .and_then(|_| std::fs::set_permissions(copy, std::fs::Permissions::from_mode(0o640)))
            .map_err(|e| refuse(format!("could not make {}: {e}", copy.display())))?;
        if let Some((uid, gid)) = owner {
            let _ = std::os::unix::fs::chown(copy, Some(uid), Some(gid));
        }
    }

    for (n, edit) in fix.edits.iter().enumerate() {
        if let Err(e) = std::fs::write(&edit.file, &edit.after) {
            put_back(&fix.edits[..n]);
            return Err(refuse(format!(
                "could not write {}: {e}",
                edit.file.display()
            )));
        }
        progress
            .line(format!(
                "{} {} line(s) {} {}",
                if fix.remove { "Took" } else { "Added" },
                edit.inserts.iter().map(|i| i.lines.len()).sum::<usize>(),
                if fix.remove { "out of" } else { "to" },
                edit.file.display()
            ))
            .await;
    }
    if let Err(output) = run(&fix.check, cancel, progress).await {
        put_back(&fix.edits);
        return Err(refuse(format!(
            "`{}` didn't accept the change, so every file is back as it was",
            fix.check.join(" ")
        ))
        .with_output(output));
    }
    if let Err(output) = run(&fix.reload, cancel, progress).await {
        put_back(&fix.edits);
        let _ = run(&fix.reload, cancel, progress).await;
        return Err(refuse(format!(
            "`{}` failed, so every file is back as it was",
            fix.reload.join(" ")
        ))
        .with_output(output));
    }
    if !fix.verify.is_empty() {
        let mut up = Err(Vec::new());
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            up = run(&fix.verify, cancel, progress).await;
            if up.is_ok() {
                break;
            }
        }
        if let Err(output) = up {
            put_back(&fix.edits);
            let _ = run(&fix.reload, cancel, progress).await;
            return Err(refuse(format!(
                "{} didn't come back up after the change, so every file is back as it was and it was restarted again",
                fix.server
            ))
            .with_output(output));
        }
    }
    if fix.remove {
        for copy in &fix.copies {
            let _ = std::fs::remove_file(copy);
        }
    }
    progress
        .line(if fix.remove {
            "ServerOS's lines are out, and the server is back to its own config".to_string()
        } else {
            "New requests show up within a couple of minutes".to_string()
        })
        .await;
    Ok(fix.describe(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::existing::plan;
    use daemon_inventory::access_logs::{discover_in, Paths};

    fn setup(dir: &Path) -> (Places, Paths) {
        let nginx = dir.join("nginx");
        std::fs::create_dir_all(nginx.join("sites-enabled")).unwrap();
        std::fs::create_dir_all(nginx.join("conf.d")).unwrap();
        std::fs::write(
            nginx.join("nginx.conf"),
            "http {\n    access_log /var/log/nginx/access.log;\n    include /NGINX/conf.d/*.conf;\n    include /NGINX/sites-enabled/*;\n}\n"
                .replace("/NGINX", &nginx.display().to_string()),
        )
        .unwrap();
        std::fs::write(
            nginx.join("sites-enabled/shop"),
            "# My shop. Hands off { please }\nserver {\n    listen 80;\n    server_name shop.test;\n    return 301 https://$host$request_uri;\n}\n\nserver {\n    listen 443 ssl;\n    server_name shop.test;\n    access_log /var/log/nginx/shop.log;\n    location / {\n        try_files $uri /index.php?$query_string;\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            nginx.join("sites-enabled/blog"),
            "server { server_name blog.test; root /srv/blog; }\n",
        )
        .unwrap();
        let apache = dir.join("apache2");
        std::fs::create_dir_all(apache.join("sites-enabled")).unwrap();
        std::fs::write(apache.join("apache2.conf"), "IncludeOptional sites-enabled/*.conf\nCustomLog /var/log/apache2/other.log vhost_combined\n").unwrap();
        std::fs::write(
            apache.join("sites-enabled/a.conf"),
            "<VirtualHost *:80>\n\tServerName one.test\n\tDocumentRoot /srv/one\n</VirtualHost>\n",
        )
        .unwrap();
        (
            Places {
                traffic_dir: dir.join("traffic"),
                nginx_conf: nginx.join("nginx.conf"),
                nginx_format_file: nginx.join("conf.d/00-serveros-timing.conf"),
                backups: dir.join("backups"),
            },
            Paths {
                nginx_confs: vec![(nginx.join("nginx.conf"), nginx.clone())],
                apache_confs: vec![(apache.join("apache2.conf"), apache.clone())],
                apache_envvars: apache.join("envvars"),
                ..Paths::default()
            },
        )
    }

    #[test]
    fn nginx_blocks_get_a_copy_and_keep_the_log_they_inherited() {
        let dir = tempfile::tempdir().unwrap();
        let (places, paths) = setup(dir.path());
        let planned = plan(&discover_in(&paths), &places.traffic_dir);
        let shop = planned.site("nginx.shop.test").unwrap();
        let fix = plan_fix(shop, &places).unwrap();
        let file = dir.path().join("nginx/sites-enabled/shop");
        assert_eq!(fix.edits.len(), 2);
        assert_eq!(fix.edits[0].file, places.nginx_format_file);
        assert!(fix.edits[0].before.is_none());
        let copy = places.traffic_dir.join("existing/nginx.shop.test.log");
        assert_eq!(fix.copies, vec![copy.clone()]);

        let after = &fix.edits[1].after;
        let expected = format!(
            "# My shop. Hands off {{ please }}\nserver {{\n    listen 80;\n    server_name shop.test;\n    return 301 https://$host$request_uri;\n    {KEPT_COMMENT}\n    access_log /var/log/nginx/access.log;\n    {COPY_COMMENT}\n    access_log {c} serveros_timed;\n}}\n\nserver {{\n    listen 443 ssl;\n    server_name shop.test;\n    access_log /var/log/nginx/shop.log;\n    location / {{\n        try_files $uri /index.php?$query_string;\n    }}\n    {COPY_COMMENT}\n    access_log {c} serveros_timed;\n}}\n",
            c = copy.display()
        );
        assert_eq!(after, &expected);
        // Only added lines: taking them out gives the file back.
        let stripped: String = after
            .lines()
            .filter(|l| {
                !fix.edits[1]
                    .inserts
                    .iter()
                    .any(|i| i.lines.iter().any(|x| x == l.trim()))
            })
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(stripped, std::fs::read_to_string(&file).unwrap());

        let described = fix.describe(false);
        assert_eq!(described["changes"].as_array().unwrap().len(), 3);
        assert_eq!(
            described["changes"][1]["at"],
            "server block 1 (shop.test), before its closing line"
        );
        assert_eq!(described["check"], "nginx -t");

        // Once it's there, the site is counted from the copy and a second
        // fix has nothing to add.
        std::fs::write(&file, after).unwrap();
        std::fs::write(&places.nginx_format_file, FORMAT_FILE_TEXT).unwrap();
        let again = plan(&discover_in(&paths), &places.traffic_dir);
        assert!(again.site("nginx.shop.test").unwrap().info.copy);
        assert!(plan_fix(again.site("nginx.shop.test").unwrap(), &places).is_err());
    }

    #[test]
    fn a_one_line_server_block_and_an_apache_vhost() {
        let dir = tempfile::tempdir().unwrap();
        let (places, paths) = setup(dir.path());
        let planned = plan(&discover_in(&paths), &places.traffic_dir);

        // blog and shop's port 80 block share the http block's log, with no
        // host in its lines: one shared site, and the fix gives each its own.
        let shared = planned.sites.iter().find(|s| s.info.shared).unwrap();
        let fix = plan_fix(shared, &places).unwrap();
        assert_eq!(fix.edits.len(), 3);
        assert_eq!(fix.copies.len(), 2);
        assert_eq!(
            fix.edits[1].after,
            format!(
                "server {{ server_name blog.test; root /srv/blog;\n    {KEPT_COMMENT}\n    access_log /var/log/nginx/access.log;\n    {COPY_COMMENT}\n    access_log {} serveros_timed;\n}}\n",
                places.traffic_dir.join("existing/nginx.blog.test.log").display()
            )
        );

        let one = planned.site("apache.one.test").unwrap();
        let fix = plan_fix(one, &places).unwrap();
        assert_eq!(fix.edits.len(), 1);
        assert_eq!(
            fix.edits[0].after,
            format!(
                "<VirtualHost *:80>\n\tServerName one.test\n\tDocumentRoot /srv/one\n    {KEPT_COMMENT}\n    CustomLog /var/log/apache2/other.log vhost_combined\n    {COPY_COMMENT}\n    CustomLog {} {APACHE_LOG_FORMAT}\n</VirtualHost>\n",
                places.traffic_dir.join("existing/apache.one.test.log").display()
            )
        );
    }

    #[test]
    fn no_conf_d_include_means_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let (places, paths) = setup(dir.path());
        std::fs::write(&places.nginx_conf, "http { include sites-enabled/*; }\n").unwrap();
        let planned = plan(&discover_in(&paths), &places.traffic_dir);
        let err = plan_fix(planned.site("nginx.shop.test").unwrap(), &places).unwrap_err();
        assert!(err.message.contains("conf.d"), "{}", err.message);
    }

    #[tokio::test]
    async fn a_failed_check_puts_every_file_back() {
        let dir = tempfile::tempdir().unwrap();
        let (places, paths) = setup(dir.path());
        let planned = plan(&discover_in(&paths), &places.traffic_dir);
        let file = dir.path().join("nginx/sites-enabled/shop");
        let original = std::fs::read_to_string(&file).unwrap();
        let (_tx, mut cancel) = watch::channel(false);
        let state = std::sync::Arc::new(daemon_state::State::in_memory().unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(256);
        let progress = Progress::new(uuid::Uuid::new_v4(), state, tx, vec![]);

        let mut fix = plan_fix(planned.site("nginx.shop.test").unwrap(), &places).unwrap();
        fix.check = vec!["false".into()];
        fix.reload = vec!["true".into()];
        let err = apply_fix(&fix, &places, &mut cancel, &progress)
            .await
            .unwrap_err();
        assert!(err.message.contains("back as it was"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
        assert!(!places.nginx_format_file.exists());
        let backups: Vec<_> = std::fs::read_dir(&places.backups).unwrap().collect();
        assert_eq!(backups.len(), 1);

        fix.check = vec!["true".into()];
        let done = apply_fix(&fix, &places, &mut cancel, &progress)
            .await
            .unwrap();
        assert_eq!(done["applied"], true);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), fix.edits[1].after);
        assert!(places
            .traffic_dir
            .join("existing/nginx.shop.test.log")
            .exists());
    }
}
