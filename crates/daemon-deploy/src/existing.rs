//! Traffic for the sites ServerOS didn't write: the ones the machine's own
//! nginx or Apache serves, from the access logs their configs already
//! write. Those files belong to the user, so they're only ever read: the
//! daemon follows each one like `tail -F` (a byte offset and inode per
//! file, kept in its state), never truncates, rotates or writes it, and
//! starts at the end of a file it hasn't seen before, so old history isn't
//! counted.
//!
//! Lines are read with the file's own format (nginx `log_format`, Apache
//! `LogFormat`): `combined`, `common`, `vhost_combined`, or anything else
//! built from the usual variables, JSON included. They're counted exactly
//! like the logs of sites ServerOS runs (see `traffic`), and only the
//! rollups leave the machine.
//!
//! A file several sites write, whose lines don't say which site they were
//! for, is counted as one site and reported as shared, rather than guessed
//! at. Asking for response times on a site (`timing`) gives it a copy of
//! its log in ServerOS's own format, with the host and the time each
//! request took; that copy is ServerOS's, so it's emptied as it's read.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use daemon_inventory::access_logs::{LogFile, VhostLogs};
use daemon_protocol::TrafficSite;
use serde::{Deserialize, Serialize};

use crate::traffic::{self, clean_path, referrer_host, strip_port, Hit, Rollups};

/// Where the copies with response times go, under the traffic log folder.
pub const COPY_DIR: &str = "existing";

/// The most read from one file in one go. A file that grew more than this
/// since the last read is caught up over the next reads.
pub const MAX_READ: u64 = 8 * 1024 * 1024;
/// A file this far behind (the daemon was stopped a long time on a busy
/// machine) skips to its end instead of catching up.
const MAX_BEHIND: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Ip,
    /// `20/Nov/2026:12:00:01 +0000`
    TimeLocal,
    /// The same in brackets (Apache's `%t`).
    TimeBracketed,
    TimeIso,
    EpochSecs,
    EpochMillis,
    EpochMicros,
    /// `GET /path?q HTTP/1.1`
    Request,
    Path,
    Status,
    Bytes,
    Referer,
    Agent,
    Host,
    Secs,
    Millis,
    Micros,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Field(Field),
}

/// A log line format, compiled from an nginx `log_format` or an Apache
/// `LogFormat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pieces: Vec<Piece>,
}

fn push_text(pieces: &mut Vec<Piece>, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(Piece::Text(last)) = pieces.last_mut() {
        last.push_str(text);
    } else {
        pieces.push(Piece::Text(text.to_string()));
    }
}

fn nginx_field(name: &str) -> Field {
    match name {
        "remote_addr" | "realip_remote_addr" => Field::Ip,
        "time_local" => Field::TimeLocal,
        "time_iso8601" => Field::TimeIso,
        "msec" => Field::EpochSecs,
        "request" => Field::Request,
        "request_uri" | "uri" | "document_uri" => Field::Path,
        "status" => Field::Status,
        "body_bytes_sent" | "bytes_sent" => Field::Bytes,
        "http_referer" => Field::Referer,
        "http_user_agent" => Field::Agent,
        "host" | "http_host" | "server_name" => Field::Host,
        "request_time" => Field::Secs,
        _ => Field::Other,
    }
}

fn apache_field(letter: char, arg: Option<&str>) -> Field {
    let arg = arg.map(str::to_ascii_lowercase);
    match (letter, arg.as_deref()) {
        ('h' | 'a', _) => Field::Ip,
        ('t', None) => Field::TimeBracketed,
        ('t', Some(arg)) => match arg.trim_start_matches("begin:").trim_start_matches("end:") {
            "sec" => Field::EpochSecs,
            "msec" => Field::EpochMillis,
            "usec" => Field::EpochMicros,
            _ => Field::Other,
        },
        ('r', _) => Field::Request,
        ('U', _) => Field::Path,
        ('s', _) => Field::Status,
        ('b' | 'B' | 'O', _) => Field::Bytes,
        ('i', Some("referer")) => Field::Referer,
        ('i', Some("user-agent")) => Field::Agent,
        ('i', Some("host")) | ('v' | 'V', _) => Field::Host,
        ('D', _) | ('T', Some("us")) => Field::Micros,
        ('T', Some("ms")) => Field::Millis,
        ('T', None | Some("s")) => Field::Secs,
        _ => Field::Other,
    }
}

impl Template {
    pub fn nginx(format: &str) -> Self {
        let mut pieces = Vec::new();
        let mut rest = format;
        while let Some(at) = rest.find('$') {
            push_text(&mut pieces, &rest[..at]);
            let after = &rest[at + 1..];
            let (name, used) = if let Some(braced) = after.strip_prefix('{') {
                match braced.find('}') {
                    Some(end) => (&braced[..end], end + 2),
                    None => ("", 0),
                }
            } else {
                let end = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(after.len());
                (&after[..end], end)
            };
            if name.is_empty() {
                push_text(&mut pieces, "$");
                rest = after;
            } else {
                pieces.push(Piece::Field(nginx_field(name)));
                rest = &after[used..];
            }
        }
        push_text(&mut pieces, rest);
        Self { pieces }
    }

    pub fn apache(format: &str) -> Self {
        let mut pieces = Vec::new();
        let mut chars = format.chars().peekable();
        let mut text = String::new();
        while let Some(c) = chars.next() {
            if c != '%' {
                text.push(c);
                continue;
            }
            if chars.peek() == Some(&'%') {
                chars.next();
                text.push('%');
                continue;
            }
            // Modifiers: %>s, %<s, %!200,304r, %400,501{User-agent}i
            while chars
                .peek()
                .is_some_and(|c| matches!(c, '<' | '>' | '!' | ',') || c.is_ascii_digit())
            {
                chars.next();
            }
            let mut arg = None;
            if chars.peek() == Some(&'{') {
                chars.next();
                let inner: String = chars.by_ref().take_while(|c| *c != '}').collect();
                arg = Some(inner);
            }
            let Some(letter) = chars.next() else { break };
            push_text(&mut pieces, &std::mem::take(&mut text));
            pieces.push(Piece::Field(apache_field(letter, arg.as_deref())));
        }
        push_text(&mut pieces, &text);
        Self { pieces }
    }

    fn has(&self, wanted: &[Field]) -> bool {
        self.pieces
            .iter()
            .any(|p| matches!(p, Piece::Field(f) if wanted.contains(f)))
    }

    /// Whether the lines say which site (host) each request was for.
    pub fn has_host(&self) -> bool {
        self.has(&[Field::Host])
    }

    /// Whether the lines say how long each request took.
    pub fn timed(&self) -> bool {
        self.has(&[Field::Secs, Field::Millis, Field::Micros])
    }

    /// Whether this reads as a request log at all.
    pub fn usable(&self) -> bool {
        self.has(&[Field::Status]) && self.has(&[Field::Request, Field::Path])
    }

    /// The line's fields, matched against the template, or None when the
    /// line isn't in this format.
    fn split<'a>(&self, line: &'a str) -> Option<Vec<(Field, &'a str)>> {
        let mut out = Vec::new();
        let mut pos = 0;
        for (i, piece) in self.pieces.iter().enumerate() {
            let rest = &line[pos..];
            match piece {
                Piece::Text(text) => {
                    if !rest.starts_with(text.as_str()) {
                        return None;
                    }
                    pos += text.len();
                }
                Piece::Field(field) => {
                    let len = match field {
                        Field::TimeLocal if rest.len() >= 26 && rest.is_char_boundary(26) => 26,
                        Field::TimeBracketed if rest.starts_with('[') => rest.find(']')? + 1,
                        _ => match self.pieces.get(i + 1) {
                            Some(Piece::Text(next)) => find_unescaped(rest, next)?,
                            Some(Piece::Field(_)) => {
                                rest.find(char::is_whitespace).unwrap_or(rest.len())
                            }
                            None => rest.len(),
                        },
                    };
                    out.push((*field, &rest[..len]));
                    pos += len;
                }
            }
        }
        Some(out)
    }

    /// Reads one line. `now` stands in for formats with no time in them.
    pub fn parse(&self, line: &str, now: i64) -> Option<Hit> {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            return None;
        }
        let fields = self.split(line)?;
        let mut hit = Hit {
            ts: now,
            host: String::new(),
            ip: String::new(),
            user_agent: String::new(),
            path: String::new(),
            status: 0,
            bytes: 0,
            ms: None,
            referrer: None,
            router: None,
        };
        let mut referer = String::new();
        let mut request_path = None;
        let mut have_time = false;
        for (field, raw) in fields {
            let value = unescape(raw);
            let value = if value == "-" { String::new() } else { value };
            let number = || value.trim().parse::<f64>().ok();
            match field {
                Field::Ip if hit.ip.is_empty() => hit.ip = value,
                Field::TimeLocal | Field::TimeBracketed if !have_time => {
                    if let Some(ts) = time_local(&value) {
                        hit.ts = ts;
                        have_time = true;
                    }
                }
                Field::TimeIso if !have_time => {
                    if let Ok(t) = time::OffsetDateTime::parse(
                        &value,
                        &time::format_description::well_known::Rfc3339,
                    ) {
                        hit.ts = t.unix_timestamp();
                        have_time = true;
                    }
                }
                Field::EpochSecs | Field::EpochMillis | Field::EpochMicros if !have_time => {
                    if let Some(n) = number() {
                        let per = match field {
                            Field::EpochMillis => 1e3,
                            Field::EpochMicros => 1e6,
                            _ => 1.0,
                        };
                        hit.ts = (n / per).floor() as i64;
                        have_time = true;
                    }
                }
                Field::Request => {
                    let mut words = value.split_whitespace();
                    let first = words.next().unwrap_or_default();
                    request_path = Some(words.next().unwrap_or(first).to_string());
                }
                Field::Path if hit.path.is_empty() => hit.path = clean_path(&value),
                Field::Status => {
                    let status = value.trim().parse::<u16>().ok()?;
                    if !(100..600).contains(&status) {
                        return None;
                    }
                    hit.status = status;
                }
                Field::Bytes if hit.bytes == 0 => {
                    hit.bytes = value.trim().parse().unwrap_or(0);
                }
                Field::Referer => referer = value,
                Field::Agent => hit.user_agent = value,
                Field::Host if hit.host.is_empty() => hit.host = strip_port(&value),
                Field::Secs | Field::Millis | Field::Micros if hit.ms.is_none() => {
                    hit.ms = number().map(|n| match field {
                        Field::Secs => (n * 1000.0) as f32,
                        Field::Micros => (n / 1000.0) as f32,
                        _ => n as f32,
                    });
                }
                _ => {}
            }
        }
        if hit.status == 0 {
            return None;
        }
        if hit.path.is_empty() {
            hit.path = clean_path(request_path.as_deref().unwrap_or("/"));
        }
        hit.referrer = referrer_host(&referer, &hit.host);
        Some(hit)
    }
}

/// Where `needle` first starts in `text`, skipping backslash-escaped
/// characters (both servers escape quotes in values).
fn find_unescaped(text: &str, needle: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if text[i..].starts_with(needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Undoes the escapes nginx (`\xHH`, and JSON's) and Apache (`\"`, `\\`,
/// `\xhh`) put in values.
fn unescape(text: &str) -> String {
    if !text.contains('\\') {
        return text.to_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    let hex = |s: &[u8]| {
        std::str::from_utf8(s)
            .ok()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
    };
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 >= bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            b'x' if i + 4 <= bytes.len() && hex(&bytes[i + 2..i + 4]).is_some() => {
                out.push(hex(&bytes[i + 2..i + 4]).unwrap_or(0) as u8);
                i += 4;
            }
            b'u' if i + 6 <= bytes.len() && hex(&bytes[i + 2..i + 6]).is_some() => {
                let c =
                    char::from_u32(hex(&bytes[i + 2..i + 6]).unwrap_or(0)).unwrap_or('\u{fffd}');
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                i += 6;
            }
            b'"' | b'\\' | b'/' => {
                out.push(bytes[i + 1]);
                i += 2;
            }
            _ => {
                out.push(b'\\');
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `20/Nov/2026:12:00:01 +0100` (with or without brackets) in Unix seconds.
fn time_local(text: &str) -> Option<i64> {
    let text = text.trim().trim_start_matches('[').trim_end_matches(']');
    let (stamp, zone) = text.split_once(' ')?;
    let mut parts = stamp.split(['/', ':']);
    let day: u8 = parts.next()?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => time::Month::January,
        "Feb" => time::Month::February,
        "Mar" => time::Month::March,
        "Apr" => time::Month::April,
        "May" => time::Month::May,
        "Jun" => time::Month::June,
        "Jul" => time::Month::July,
        "Aug" => time::Month::August,
        "Sep" => time::Month::September,
        "Oct" => time::Month::October,
        "Nov" => time::Month::November,
        "Dec" => time::Month::December,
        _ => return None,
    };
    let year: i32 = parts.next()?.parse().ok()?;
    let hour: i64 = parts.next()?.parse().ok()?;
    let minute: i64 = parts.next()?.parse().ok()?;
    let second: i64 = parts.next()?.parse().ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let midnight = date.midnight().assume_utc().unix_timestamp();
    let sign = match zone.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let zone = zone.get(1..5)?;
    let offset =
        sign * (zone[..2].parse::<i64>().ok()? * 3600 + zone[2..].parse::<i64>().ok()? * 60);
    Some(midnight + hour * 3600 + minute * 60 + second - offset)
}

/// Where the daemon has read a file to: its inode and the byte after the
/// last whole line counted. An inode of 0 means the file wasn't there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    pub inode: u64,
    pub offset: u64,
}

/// Follows files like `tail -F`, read-only.
#[derive(Debug, Default)]
pub struct Tailer {
    marks: BTreeMap<PathBuf, Mark>,
    changed: bool,
}

impl Tailer {
    /// From the marks saved in the daemon's state (`saved`).
    pub fn restore(saved: Option<&str>) -> Self {
        let marks = saved
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();
        Self {
            marks,
            changed: false,
        }
    }

    /// The marks to save, when they changed since the last call.
    pub fn saved(&mut self) -> Option<String> {
        if !std::mem::take(&mut self.changed) {
            return None;
        }
        serde_json::to_string(&self.marks).ok()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    pub fn mark(&self, path: &Path) -> Option<Mark> {
        self.marks.get(path).copied()
    }

    /// Forgets files no site logs to any more.
    pub fn keep_only(&mut self, paths: &[&Path]) {
        let before = self.marks.len();
        self.marks.retain(|path, _| paths.contains(&path.as_path()));
        self.changed |= self.marks.len() != before;
    }

    fn set(&mut self, path: &Path, mark: Mark) {
        if self.marks.get(path) != Some(&mark) {
            self.marks.insert(path.to_path_buf(), mark);
            self.changed = true;
        }
    }

    /// The whole lines added to `path` since the last read, at most
    /// `MAX_READ` bytes of them. The first read of a file only notes where
    /// it ends. A file with a new inode was rotated: what's left of the old
    /// one (`<path>.1`, where logrotate puts it) is read first, then the
    /// new one from its start. A file shorter than where the last read
    /// stopped was truncated (`copytruncate`) and is read from its start.
    pub fn read(&mut self, path: &Path) -> Vec<String> {
        let now = std::fs::metadata(path).ok().filter(|m| m.is_file());
        let current = now.as_ref().map(|m| (m.ino(), m.len()));
        let Some(mark) = self.mark(path) else {
            let (inode, len) = current.unwrap_or((0, 0));
            self.set(path, Mark { inode, offset: len });
            return Vec::new();
        };

        let mut lines = Vec::new();
        let mark = match current {
            Some((inode, _)) if inode == mark.inode => mark,
            _ => {
                // Rotated or gone: finish the old file if it's still about.
                if mark.inode != 0 {
                    let mut rotated = path.as_os_str().to_owned();
                    rotated.push(".1");
                    let rotated = PathBuf::from(rotated);
                    if std::fs::metadata(&rotated).is_ok_and(|m| m.ino() == mark.inode) {
                        lines.extend(read_from(&rotated, mark.offset, u64::MAX).0);
                    }
                }
                Mark {
                    inode: current.map_or(0, |(inode, _)| inode),
                    offset: 0,
                }
            }
        };
        let Some((inode, len)) = current else {
            self.set(path, mark);
            return lines;
        };
        let mut offset = if len < mark.offset { 0 } else { mark.offset };
        if len - offset > MAX_BEHIND {
            offset = len;
        }
        let (more, next) = read_from(path, offset, len);
        lines.extend(more);
        self.set(
            path,
            Mark {
                inode,
                offset: next,
            },
        );
        lines
    }
}

/// The whole lines from `offset`, up to `MAX_READ` bytes and not past
/// `until`, and the offset after the last one.
fn read_from(path: &Path, offset: u64, until: u64) -> (Vec<String>, u64) {
    let Ok(mut file) = std::fs::File::open(path) else {
        return (Vec::new(), offset);
    };
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return (Vec::new(), offset);
    }
    let want = until.saturating_sub(offset).min(MAX_READ);
    let mut bytes = Vec::new();
    if (&mut file).take(want).read_to_end(&mut bytes).is_err() {
        return (Vec::new(), offset);
    }
    let whole = match bytes.iter().rposition(|b| *b == b'\n') {
        Some(end) => end + 1,
        // One line longer than a whole read: skip it rather than stall.
        None if bytes.len() as u64 >= MAX_READ => bytes.len(),
        None => 0,
    };
    let text = String::from_utf8_lossy(&bytes[..whole]);
    let lines = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    (lines, offset + whole as u64)
}

/// A site key for one of these sites: the server and its first name. The
/// dot keeps it apart from the sites ServerOS writes, whose keys never
/// have one.
pub fn site_key(server: &str, name: Option<&str>) -> String {
    let name: String = name
        .unwrap_or("default")
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(100)
        .collect();
    format!("{server}.{name}")
}

/// The key of a file several sites write without saying which: the
/// server, the file's name and a hash of its path.
fn shared_key(server: &str, path: &Path) -> String {
    let mut hash: u32 = 0x811c_9dc5;
    for b in path.as_os_str().as_encoded_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = site_key("x", Some(&name));
    format!("{server}.log.{}-{:06x}", &name[2..], hash & 0xff_ffff)
}

/// Whether a request for `host` is one for a site with these names.
fn serves(names: &[String], host: &str) -> bool {
    names.iter().any(|name| {
        if let Some(suffix) = name.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else if let Some(base) = name.strip_prefix('.') {
            host == base || host.ends_with(name.as_str())
        } else {
            name == host
        }
    })
}

/// One server block or VirtualHost of a site, for the timing fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The site it belongs to on its own (not a shared file's key).
    pub key: String,
    pub config: String,
    pub block: usize,
    /// It writes no log of its own: these are the ones it inherits.
    pub inherited: Option<Vec<LogFile>>,
}

/// A site counted here, and what's reported about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub info: TrafficSite,
    /// The vhosts behind it (for a shared file, every site that writes it).
    pub blocks: Vec<Block>,
}

/// Where a file's lines are counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    One(String),
    /// By the host in each line; lines for other hosts aren't counted.
    ByHost(Vec<(String, Vec<String>)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub path: PathBuf,
    /// None: a copy ServerOS writes in its own format, emptied as read.
    pub template: Option<Template>,
    pub route: Route,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub sites: Vec<Site>,
    pub sources: Vec<Source>,
}

impl Plan {
    pub fn site(&self, key: &str) -> Option<&Site> {
        self.sites.iter().find(|s| s.info.site == key)
    }
}

#[derive(Default)]
struct Group {
    server: String,
    names: Vec<String>,
    configs: Vec<String>,
    ports: Vec<u16>,
    logs: Vec<LogFile>,
    blocks: Vec<Block>,
    copy: Option<PathBuf>,
}

/// Which files to read and which site each line counts for, from the
/// vhosts the configs describe. `traffic_dir` is where ServerOS's own logs
/// are (its own sites' files there are skipped; the copies in its
/// `existing` folder are read in place of the logs they copy).
pub fn plan(vhosts: &[VhostLogs], traffic_dir: &Path) -> Plan {
    let copies = traffic_dir.join(COPY_DIR);
    let mut groups: Vec<(String, Group)> = Vec::new();
    for vhost in vhosts {
        if vhost.config_path.contains("/serveros.d/") {
            continue;
        }
        let key = site_key(&vhost.server, vhost.names.first().map(String::as_str));
        let index = match groups.iter().position(|(k, _)| *k == key) {
            Some(index) => index,
            None => {
                groups.push((
                    key.clone(),
                    Group {
                        server: vhost.server.clone(),
                        ..Default::default()
                    },
                ));
                groups.len() - 1
            }
        };
        let group = &mut groups[index].1;
        for name in &vhost.names {
            if !group.names.contains(name) {
                group.names.push(name.clone());
            }
        }
        if !group.configs.contains(&vhost.config_path) {
            group.configs.push(vhost.config_path.clone());
        }
        for port in &vhost.upstream_ports {
            if !group.ports.contains(port) {
                group.ports.push(*port);
            }
        }
        group.blocks.push(Block {
            key: key.clone(),
            config: vhost.config_path.clone(),
            block: vhost.block,
            inherited: vhost.inherited.then(|| vhost.logs.clone()),
        });
        for log in &vhost.logs {
            if log.path == copies.join(format!("{key}.log")) {
                group.copy = Some(log.path.clone());
            } else if !log.path.starts_with(traffic_dir)
                && !group.logs.iter().any(|l| l.path == log.path)
            {
                group.logs.push(log.clone());
            }
        }
    }

    let template_of = |server: &str, format: &str| {
        if server == "apache" {
            Template::apache(format)
        } else {
            Template::nginx(format)
        }
    };

    // Each file, the format it's in and the sites that write it.
    let mut files: Vec<(PathBuf, Template, Vec<usize>)> = Vec::new();
    for (index, (_, group)) in groups.iter().enumerate() {
        if group.copy.is_some() {
            continue;
        }
        for log in &group.logs {
            let template = template_of(&group.server, &log.format);
            if !template.usable() {
                continue;
            }
            match files.iter_mut().find(|(path, _, _)| *path == log.path) {
                Some((_, _, writers)) => writers.push(index),
                None => files.push((log.path.clone(), template, vec![index])),
            }
        }
    }

    let info = |key: &str, group: &Group, logs: Vec<String>, timed: bool| TrafficSite {
        site: key.to_string(),
        server: group.server.clone(),
        names: group.names.clone(),
        logs,
        timed,
        shared: false,
        copy: group.copy.is_some(),
        configs: group.configs.clone(),
        upstream_ports: group.ports.clone(),
    };

    let mut plan = Plan::default();
    for (index, (key, group)) in groups.iter().enumerate() {
        if let Some(copy) = &group.copy {
            plan.sources.push(Source {
                path: copy.clone(),
                template: None,
                route: Route::One(key.clone()),
            });
            plan.sites.push(Site {
                // The copy it reads first, then the site's own logs, so the
                // panel can name the file the person knows.
                info: info(
                    key,
                    group,
                    std::iter::once(copy.display().to_string())
                        .chain(
                            group
                                .logs
                                .iter()
                                .filter(|log| log.path != *copy)
                                .map(|log| log.path.display().to_string()),
                        )
                        .collect(),
                    true,
                ),
                blocks: group.blocks.clone(),
            });
            continue;
        }
        // Its own files: written by it alone, or with hosts in the lines.
        let own: Vec<&(PathBuf, Template, Vec<usize>)> = files
            .iter()
            .filter(|(_, template, writers)| {
                writers.contains(&index) && (writers.len() == 1 || template.has_host())
            })
            .collect();
        if own.is_empty() {
            continue;
        }
        plan.sites.push(Site {
            info: info(
                key,
                group,
                own.iter()
                    .map(|(p, _, _)| p.display().to_string())
                    .collect(),
                own.iter().all(|(_, t, _)| t.timed()),
            ),
            blocks: group.blocks.clone(),
        });
    }

    for (path, template, writers) in files {
        let route = if writers.len() == 1 {
            Route::One(groups[writers[0]].0.clone())
        } else if template.has_host() {
            Route::ByHost(
                writers
                    .iter()
                    .map(|i| (groups[*i].0.clone(), groups[*i].1.names.clone()))
                    .collect(),
            )
        } else {
            // Several sites, no host in the lines: counted together.
            let first = &groups[writers[0]].1;
            let key = shared_key(&first.server, &path);
            let mut merged = Group {
                server: first.server.clone(),
                ..Default::default()
            };
            for i in &writers {
                let group = &groups[*i].1;
                for name in &group.names {
                    if !merged.names.contains(name) {
                        merged.names.push(name.clone());
                    }
                }
                for config in &group.configs {
                    if !merged.configs.contains(config) {
                        merged.configs.push(config.clone());
                    }
                }
                merged.ports.extend(group.ports.iter().copied());
                merged.blocks.extend(group.blocks.iter().cloned());
            }
            merged.ports.sort_unstable();
            merged.ports.dedup();
            let mut site = info(
                &key,
                &merged,
                vec![path.display().to_string()],
                template.timed(),
            );
            site.shared = true;
            plan.sites.push(Site {
                info: site,
                blocks: merged.blocks,
            });
            Route::One(key)
        };
        plan.sources.push(Source {
            path,
            template: Some(template),
            route,
        });
    }
    plan.sites.sort_by(|a, b| a.info.site.cmp(&b.info.site));
    plan
}

/// Reads what's new in every file of the plan into `rollups`. Returns how
/// many requests were counted.
pub fn collect(plan: &Plan, tailer: &mut Tailer, rollups: &mut Rollups, now: i64) -> usize {
    let mut counted = 0;
    for source in &plan.sources {
        let lines = match &source.template {
            Some(_) => tailer.read(&source.path),
            None => traffic::drain(&source.path),
        };
        for line in &lines {
            let hit = match &source.template {
                Some(template) => template.parse(line, now),
                None => traffic::parse_line(traffic::Format::Line, line),
            };
            let Some(hit) = hit else { continue };
            let site = match &source.route {
                Route::One(site) => Some(site.as_str()),
                Route::ByHost(sites) => sites
                    .iter()
                    .find(|(_, names)| serves(names, &hit.host))
                    .map(|(site, _)| site.as_str()),
            };
            if let Some(site) = site {
                rollups.add(site, &hit);
                counted += 1;
            }
        }
    }
    let paths: Vec<&Path> = plan
        .sources
        .iter()
        .filter(|s| s.template.is_some())
        .map(|s| s.path.as_path())
        .collect();
    tailer.keep_only(&paths);
    counted
}

/// Empties the copies ServerOS writes for response times while traffic is
/// off, so they don't grow with nobody reading them.
pub fn empty_copies(traffic_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(traffic_dir.join(COPY_DIR)) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "log") {
            if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&path) {
                let _ = file.set_len(0);
            }
        }
    }
}

/// A short description of each site, so the reported list only goes out
/// when something about it changed.
pub fn fingerprint(sites: &[Site]) -> String {
    let infos: Vec<&TrafficSite> = sites.iter().map(|s| &s.info).collect();
    serde_json::to_string(&infos).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_inventory::access_logs::NGINX_COMBINED;

    const APACHE_COMBINED: &str = "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"";
    const APACHE_VHOST: &str = "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"";

    #[test]
    fn nginx_combined_lines_are_read() {
        let t = Template::nginx(NGINX_COMBINED);
        assert!(t.usable() && !t.has_host() && !t.timed());
        let line = r#"203.0.113.9 - - [20/Nov/2026:12:00:05 +0100] "GET /pricing?utm=x HTTP/1.1" 200 512 "https://www.google.com/search?q=a" "Mozilla/5.0 \x22quoted\x22""#;
        let hit = t.parse(line, 0).unwrap();
        assert_eq!(hit.ts, 1795176005 - 3600);
        assert_eq!(hit.ip, "203.0.113.9");
        assert_eq!(hit.path, "/pricing");
        assert_eq!((hit.status, hit.bytes), (200, 512));
        assert_eq!(hit.referrer.as_deref(), Some("google.com"));
        assert_eq!(hit.user_agent, "Mozilla/5.0 \"quoted\"");
        assert_eq!(hit.ms, None);

        // A bad request has no request line to speak of.
        let bad = t
            .parse(
                r#"198.51.100.1 - - [20/Nov/2026:12:00:06 +0000] "" 400 0 "-" "-""#,
                0,
            )
            .unwrap();
        assert_eq!((bad.status, bad.path.as_str()), (400, "/"));
        assert!(t.parse("not a log line", 0).is_none());
    }

    #[test]
    fn apache_combined_common_and_vhost_combined_are_read() {
        let combined = Template::apache(APACHE_COMBINED);
        let line = r#"192.0.2.4 - frank [20/Nov/2026:12:00:05 +0000] "POST /login HTTP/1.1" 302 - "-" "curl/8.5 \"x\"""#;
        let hit = combined.parse(line, 0).unwrap();
        assert_eq!(
            (hit.status, hit.bytes, hit.path.as_str()),
            (302, 0, "/login")
        );
        assert_eq!(hit.user_agent, "curl/8.5 \"x\"");
        assert_eq!(hit.ts, 1795176005);

        let common = Template::apache("%h %l %u %t \"%r\" %>s %b");
        let hit = common
            .parse(
                r#"192.0.2.4 - - [20/Nov/2026:12:00:05 +0000] "GET / HTTP/1.0" 503 12"#,
                0,
            )
            .unwrap();
        assert_eq!((hit.status, hit.bytes), (503, 12));

        let vhost = Template::apache(APACHE_VHOST);
        assert!(vhost.has_host());
        let hit = vhost
            .parse(r#"blog.test:443 192.0.2.4 - - [20/Nov/2026:12:00:05 +0000] "GET /a HTTP/1.1" 200 10 "https://blog.test/" "x""#, 0)
            .unwrap();
        assert_eq!(hit.host, "blog.test");
        assert_eq!(hit.referrer, None);
    }

    #[test]
    fn timed_and_json_formats_carry_response_times() {
        let timed = Template::nginx(
            "$remote_addr [$time_local] \"$request\" $status $body_bytes_sent $request_time",
        );
        assert!(timed.timed());
        let hit = timed
            .parse(
                r#"10.0.0.1 [20/Nov/2026:12:00:05 +0000] "GET / HTTP/2.0" 200 5 0.125"#,
                0,
            )
            .unwrap();
        assert_eq!(hit.ms, Some(125.0));

        let json = Template::nginx(
            r#"{"time":"$time_iso8601","host":"$host","addr":"$remote_addr","req":"$request_uri","status":$status,"size":$body_bytes_sent,"took":$request_time,"ua":"$http_user_agent"}"#,
        );
        assert!(json.has_host() && json.timed());
        let hit = json
            .parse(r#"{"time":"2026-11-20T12:00:05+00:00","host":"api.test","addr":"10.0.0.2","req":"/v1/x?k=1","status":404,"size":0,"took":0.002,"ua":"a \"b\""}"#, 0)
            .unwrap();
        assert_eq!(
            (hit.host.as_str(), hit.path.as_str(), hit.status),
            ("api.test", "/v1/x", 404)
        );
        assert_eq!(hit.ts, 1795176005);
        assert_eq!(hit.ms, Some(2.0));
        assert_eq!(hit.user_agent, "a \"b\"");

        let apache = Template::apache("%a %{%d}t %>s %U %D %{Host}i");
        let hit = apache
            .parse("10.0.0.3 20 200 /x 1500 shop.test:80", 99)
            .unwrap();
        assert_eq!(
            (hit.ts, hit.ms, hit.host.as_str()),
            (99, Some(1.5), "shop.test")
        );
    }

    fn append(path: &Path, lines: &[&str]) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }

    #[test]
    fn the_tailer_starts_at_the_end_and_follows_rotation_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, &["old 1", "old 2"]);

        let mut tailer = Tailer::default();
        assert!(tailer.read(&log).is_empty(), "history isn't counted");
        append(&log, &["a"]);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"half"))
            .unwrap();
        assert_eq!(tailer.read(&log), vec!["a"]);
        append(&log, &[" a line"]);
        assert_eq!(tailer.read(&log), vec!["half a line"]);
        assert!(tailer.read(&log).is_empty());

        // logrotate's default: move it to .1, a new file in its place.
        append(&log, &["before rotate"]);
        std::fs::rename(&log, dir.path().join("access.log.1")).unwrap();
        append(&log, &["after rotate"]);
        assert_eq!(tailer.read(&log), vec!["before rotate", "after rotate"]);

        // copytruncate: same file, emptied.
        append(&log, &["x"]);
        assert_eq!(tailer.read(&log), vec!["x"]);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&log)
            .unwrap()
            .set_len(0)
            .unwrap();
        append(&log, &["y"]);
        assert_eq!(tailer.read(&log), vec!["y"]);

        // A restart carries on from the saved marks, without counting twice.
        let saved = tailer.saved().unwrap();
        assert!(tailer.saved().is_none());
        append(&log, &["z"]);
        let mut again = Tailer::restore(Some(&saved));
        assert_eq!(again.read(&log), vec!["z"]);

        // A file that wasn't there at first is read from its start.
        let late = dir.path().join("late.log");
        assert!(tailer.read(&late).is_empty());
        append(&late, &["first"]);
        assert_eq!(tailer.read(&late), vec!["first"]);

        // Nothing was ever written by the tailer.
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "y\nz\n");
    }

    fn vhost(server: &str, names: &[&str], config: &str, logs: &[(&str, &str)]) -> VhostLogs {
        VhostLogs {
            server: server.into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            config_path: config.into(),
            logs: logs
                .iter()
                .map(|(path, format)| LogFile {
                    path: path.into(),
                    format: format.to_string(),
                    format_name: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_shared_log_without_hosts_is_one_site_and_with_hosts_is_split() {
        let traffic = Path::new("/var/log/serveros-traffic");
        let vhosts = vec![
            vhost(
                "nginx",
                &["shop.test", "www.shop.test"],
                "/etc/nginx/sites-enabled/shop",
                &[("/var/log/nginx/access.log", NGINX_COMBINED)],
            ),
            // The same site's TLS block: one site with the one above.
            vhost(
                "nginx",
                &["shop.test"],
                "/etc/nginx/sites-enabled/shop",
                &[("/var/log/nginx/access.log", NGINX_COMBINED)],
            ),
            vhost(
                "nginx",
                &["blog.test"],
                "/etc/nginx/sites-enabled/blog",
                &[("/var/log/nginx/access.log", NGINX_COMBINED)],
            ),
            vhost(
                "nginx",
                &["api.test"],
                "/etc/nginx/sites-enabled/api",
                &[("/var/log/nginx/api.log", NGINX_COMBINED)],
            ),
            vhost(
                "nginx",
                &["app.test"],
                "/etc/nginx/serveros.d/app.conf",
                &[("/var/log/serveros-traffic/app.log", "x")],
            ),
            vhost(
                "apache",
                &["one.test"],
                "/etc/apache2/sites-enabled/a.conf",
                &[("/var/log/apache2/other.log", APACHE_VHOST)],
            ),
            vhost(
                "apache",
                &["two.test", "*.two.test"],
                "/etc/apache2/sites-enabled/b.conf",
                &[("/var/log/apache2/other.log", APACHE_VHOST)],
            ),
        ];
        let plan = plan(&vhosts, traffic);
        let keys: Vec<&str> = plan.sites.iter().map(|s| s.info.site.as_str()).collect();
        assert_eq!(keys.len(), 4, "{keys:?}");
        assert!(keys.contains(&"nginx.api.test"));
        assert!(keys.contains(&"apache.one.test") && keys.contains(&"apache.two.test"));
        let shared = plan.sites.iter().find(|s| s.info.shared).unwrap();
        assert!(shared.info.site.starts_with("nginx.log.access.log-"));
        assert_eq!(
            shared.info.names,
            vec!["shop.test", "www.shop.test", "blog.test"]
        );
        assert_eq!(shared.blocks.len(), 3);
        assert!(!plan.sites.iter().any(|s| s.info.site.contains("app.test")));

        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other.log");
        let mut sources = plan.sources.clone();
        for source in &mut sources {
            if source.path == Path::new("/var/log/apache2/other.log") {
                source.path = other.clone();
            }
        }
        let plan = Plan { sources, ..plan };
        let mut tailer = Tailer::default();
        let mut rollups = Rollups::new();
        collect(&plan, &mut tailer, &mut rollups, 0);
        append(
            &other,
            &[
                r#"one.test:80 1.1.1.1 - - [20/Nov/2026:12:00:05 +0000] "GET / HTTP/1.1" 200 1 "-" "x""#,
                r#"a.two.test:443 1.1.1.1 - - [20/Nov/2026:12:00:06 +0000] "GET / HTTP/1.1" 200 1 "-" "x""#,
                r#"stranger.test:80 1.1.1.1 - - [20/Nov/2026:12:00:07 +0000] "GET / HTTP/1.1" 200 1 "-" "x""#,
            ],
        );
        assert_eq!(collect(&plan, &mut tailer, &mut rollups, 0), 2);
        let done = rollups.finished(i64::MAX / 2);
        let mut sites: Vec<&str> = done.iter().map(|r| r.site.as_str()).collect();
        sites.sort();
        assert_eq!(sites, vec!["apache.one.test", "apache.two.test"]);
    }

    #[test]
    fn a_site_with_a_timing_copy_is_counted_from_the_copy_alone() {
        let dir = tempfile::tempdir().unwrap();
        let traffic = dir.path();
        let copy = traffic.join(COPY_DIR).join("nginx.shop.test.log");
        std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
        let vhosts = vec![
            vhost(
                "nginx",
                &["shop.test"],
                "/etc/nginx/sites-enabled/shop",
                &[
                    ("/var/log/nginx/access.log", NGINX_COMBINED),
                    (copy.to_str().unwrap(), "serveros_timed"),
                ],
            ),
            vhost(
                "nginx",
                &["blog.test"],
                "/etc/nginx/sites-enabled/blog",
                &[("/var/log/nginx/access.log", NGINX_COMBINED)],
            ),
        ];
        let plan = plan(&vhosts, traffic);
        let shop = plan.site("nginx.shop.test").unwrap();
        assert!(shop.info.copy && shop.info.timed && !shop.info.shared);
        // The file it shared is blog's alone now.
        assert!(plan.site("nginx.blog.test").is_some());
        assert_eq!(plan.sources.len(), 2);

        std::fs::write(&copy, "{\"t\":1795694405.1,\"host\":\"shop.test\",\"ip\":\"1.2.3.4\",\"uri\":\"/\",\"status\":200,\"bytes\":1,\"time\":0.020,\"referer\":\"\",\"ua\":\"x\"}\n").unwrap();
        let only_copy = Plan {
            sources: plan
                .sources
                .iter()
                .filter(|s| s.template.is_none())
                .cloned()
                .collect(),
            ..plan.clone()
        };
        let mut rollups = Rollups::new();
        assert_eq!(
            collect(&only_copy, &mut Tailer::default(), &mut rollups, 0),
            1
        );
        assert_eq!(
            std::fs::metadata(&copy).unwrap().len(),
            0,
            "ServerOS's own copy is emptied"
        );
        assert_eq!(rollups.finished(i64::MAX / 2)[0].p50_ms, Some(20.0));
    }

    #[test]
    fn keys_never_look_like_the_sites_serveros_writes() {
        assert_eq!(
            site_key("nginx", Some("Shop.Example.com")),
            "nginx.shop.example.com"
        );
        assert_eq!(
            site_key("apache", Some("*.example.com")),
            "apache.-.example.com"
        );
        assert_eq!(site_key("nginx", None), "nginx.default");
        let shared = shared_key("nginx", Path::new("/var/log/nginx/access.log"));
        assert_eq!(
            shared,
            shared_key("nginx", Path::new("/var/log/nginx/access.log"))
        );
        assert_ne!(
            shared,
            shared_key("nginx", Path::new("/srv/logs/access.log"))
        );
        assert!(shared.contains('.'));
    }

    /// Reads logs real servers wrote (nginx.log, apache.log and
    /// apache-vhost.log in $SERVEROS_EXISTING_LOGS), each from the same
    /// five requests, and checks every line counts.
    #[test]
    #[ignore]
    fn reads_what_real_servers_write() {
        let Ok(dir) = std::env::var("SERVEROS_EXISTING_LOGS") else {
            return;
        };
        let dir = PathBuf::from(dir);
        for (file, template) in [
            ("nginx.log", Template::nginx(NGINX_COMBINED)),
            ("apache.log", Template::apache(APACHE_COMBINED)),
            ("apache-vhost.log", Template::apache(APACHE_VHOST)),
        ] {
            let Ok(text) = std::fs::read_to_string(dir.join(file)) else {
                continue;
            };
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            let hits: Vec<Hit> = lines.iter().filter_map(|l| template.parse(l, 0)).collect();
            assert_eq!(hits.len(), lines.len(), "{file}: some lines didn't read");
            assert!(hits.iter().all(|h| h.ts > 1_700_000_000), "{file}");
            assert!(hits.iter().any(|h| h.path == "/pricing"), "{file}");
            assert!(!hits.iter().any(|h| h.path.contains('?')), "{file}");
            println!("{file}: {hits:?}");
        }
    }
}
