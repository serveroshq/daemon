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

use daemon_inventory::access_logs::{
    Container, LogFile, LogTarget, VhostLogs, FORMAT_CADDY, FORMAT_CADDY_CONSOLE, FORMAT_TRAEFIK,
    FORMAT_TRAEFIK_COMMON,
};
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
pub(crate) enum Field {
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
    /// Traefik's router name, in its common format.
    Router,
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
        // Not nginx's: for Traefik's common format, written as a template.
        "serveros_router" => Field::Router,
        "serveros_ms" => Field::Millis,
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

    pub(crate) fn has(&self, wanted: &[Field]) -> bool {
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
                Field::Router if !value.is_empty() => hit.router = Some(value),
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
/// `at` is when that last moved (Unix seconds), to tell a rotation that
/// came after it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    pub inode: u64,
    pub offset: u64,
    #[serde(default)]
    pub at: i64,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
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

    fn set(&mut self, path: &Path, inode: u64, offset: u64) {
        let old = self.marks.get(path).copied();
        if old.is_some_and(|m| m.inode == inode && m.offset == offset) {
            return;
        }
        self.marks.insert(
            path.to_path_buf(),
            Mark {
                inode,
                offset,
                at: unix_now(),
            },
        );
        self.changed = true;
    }

    /// The whole lines added to `path` since the last read, at most
    /// `MAX_READ` bytes of them. The first read of a file only notes where
    /// it ends. A file with a new inode was rotated: what's left of the old
    /// one is read first (from `<path>.1`, where logrotate puts it, or
    /// wherever in the same folder it went, as Caddy's `access-<time>.log`,
    /// or from its compressed copy when it's already been compressed), then
    /// the new one from its start. While the old file has moved and no new
    /// one is there yet (the server hasn't reopened its log), the old one
    /// is followed where it went. A file shorter than where the last read
    /// stopped was truncated (`copytruncate`) and is read from its start.
    pub fn read(&mut self, path: &Path) -> Vec<String> {
        let now = std::fs::metadata(path).ok().filter(|m| m.is_file());
        let current = now.as_ref().map(|m| (m.ino(), m.len()));
        let Some(mark) = self.mark(path) else {
            let (inode, len) = current.unwrap_or((0, 0));
            self.set(path, inode, len);
            return Vec::new();
        };

        let mut lines = Vec::new();
        let start = match current {
            Some((inode, _)) if inode == mark.inode => mark.offset,
            None if mark.inode != 0 => {
                // Moved, and nothing in its place yet: keep following it.
                if let Some(moved) = rotated_to(path, mark.inode) {
                    let (more, next) = read_from(&moved, mark.offset, u64::MAX);
                    self.set(path, mark.inode, next);
                    return more;
                }
                lines.extend(compressed_rest(path, &mark));
                self.set(path, 0, 0);
                return lines;
            }
            None => {
                self.set(path, 0, 0);
                return lines;
            }
            Some(_) => {
                if mark.inode != 0 {
                    match rotated_to(path, mark.inode) {
                        Some(rotated) => lines.extend(read_from(&rotated, mark.offset, u64::MAX).0),
                        None => lines.extend(compressed_rest(path, &mark)),
                    }
                }
                0
            }
        };
        let Some((inode, len)) = current else {
            return lines;
        };
        let mut offset = if len < start { 0 } else { start };
        if len < start && inode == mark.inode {
            // Shorter than where reading stopped, under the same inode:
            // truncated in place, or deleted and a new file given the old
            // inode number (Linux reuses them). Either way, what was left
            // unread went into a rotated copy if it was compressed.
            lines.extend(compressed_rest(path, &mark));
        }
        if len - offset > MAX_BEHIND {
            offset = len;
        }
        let (more, next) = read_from(path, offset, len);
        lines.extend(more);
        self.set(path, inode, next);
        lines
    }
}

/// What was left unread of a rotated log that's already been compressed:
/// the newest `.gz` beside it named like it (`access-<time>.log.gz`,
/// `access.log.1.gz`), written since the last read. Decompressed as a
/// stream, skipping what was read, so a big one never sits in memory.
fn compressed_rest(path: &Path, mark: &Mark) -> Vec<String> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    let stem = name.split('.').next().unwrap_or(name);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let newest = entries
        .flatten()
        .take(500)
        .filter_map(|e| {
            let file = e.file_name().into_string().ok()?;
            if !file.ends_with(".gz") || !file.starts_with(stem) || file == name {
                return None;
            }
            let modified = e.metadata().ok()?.modified().ok()?;
            let secs = modified
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs() as i64;
            (secs >= mark.at).then_some((secs, e.path()))
        })
        .max();
    let Some((_, gz)) = newest else {
        return Vec::new();
    };
    let bytes = gunzip_from(&gz, mark.offset, MAX_READ as usize);
    let whole = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |n| n + 1);
    String::from_utf8_lossy(&bytes[..whole])
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// The decompressed bytes of a gzip file from `skip`, at most `max` of
/// them, reading and inflating a little at a time.
fn gunzip_from(path: &Path, skip: u64, max: usize) -> Vec<u8> {
    use miniz_oxide::inflate::stream::{inflate, InflateState};
    use miniz_oxide::{DataFormat, MZFlush, MZStatus};

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut head = [0u8; 10];
    if file.read_exact(&mut head).is_err() || head[0] != 0x1f || head[1] != 0x8b || head[2] != 8 {
        return Vec::new();
    }
    let flags = head[3];
    if flags & 4 != 0 {
        // FEXTRA: a length, then that much.
        let mut len = [0u8; 2];
        if file.read_exact(&mut len).is_err() {
            return Vec::new();
        }
        let extra = u64::from(u16::from_le_bytes(len));
        if std::io::copy(&mut (&mut file).take(extra), &mut std::io::sink()).is_err() {
            return Vec::new();
        }
    }
    for flag in [8u8, 16] {
        // FNAME, FCOMMENT: zero-terminated.
        if flags & flag != 0 {
            let mut byte = [0u8; 1];
            loop {
                if file.read_exact(&mut byte).is_err() {
                    return Vec::new();
                }
                if byte[0] == 0 {
                    break;
                }
            }
        }
    }
    if flags & 2 != 0 && file.read_exact(&mut [0u8; 2]).is_err() {
        return Vec::new();
    }

    let mut state = InflateState::new_boxed(DataFormat::Raw);
    let mut input = vec![0u8; 64 * 1024];
    let mut output = vec![0u8; 64 * 1024];
    let mut filled = 0usize;
    let mut used = 0usize;
    let mut skipped = 0u64;
    let mut out = Vec::new();
    loop {
        if used == filled {
            filled = match file.read(&mut input) {
                Ok(n) => n,
                Err(_) => break,
            };
            used = 0;
            if filled == 0 {
                break;
            }
        }
        let result = inflate(&mut state, &input[used..filled], &mut output, MZFlush::None);
        used += result.bytes_consumed;
        let mut produced = &output[..result.bytes_written];
        if skipped < skip {
            let drop = (skip - skipped).min(produced.len() as u64) as usize;
            skipped += drop as u64;
            produced = &produced[drop..];
        }
        let room = max - out.len();
        out.extend_from_slice(&produced[..produced.len().min(room)]);
        if out.len() >= max {
            break;
        }
        match result.status {
            Ok(MZStatus::StreamEnd) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    out
}

/// Where a rotated log went: `<path>.1`, or the file in the same folder
/// with its old inode (compressed ones can't be, and aren't looked at).
fn rotated_to(path: &Path, inode: u64) -> Option<PathBuf> {
    let mut first = path.as_os_str().to_owned();
    first.push(".1");
    let first = PathBuf::from(first);
    if std::fs::metadata(&first).is_ok_and(|m| m.ino() == inode) {
        return Some(first);
    }
    let entries = std::fs::read_dir(path.parent()?).ok()?;
    entries
        .flatten()
        .take(500)
        .map(|e| e.path())
        .filter(|p| p.extension().is_none_or(|x| x != "gz" && x != "zst"))
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.ino() == inode))
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

/// Follows containers' output through Docker, read-only: the time of the
/// last line read from each, so the next read asks for what came after.
#[derive(Debug, Default)]
pub struct Streams {
    /// `<id>:out` or `<id>:err`: the last line's time, in Unix nanoseconds.
    marks: BTreeMap<String, i128>,
    changed: bool,
}

/// Docker's socket.
pub const DOCKER_SOCKET: &str = "/var/run/docker.sock";
/// The most of one container's output read in one go.
const MAX_STREAM_READ: usize = 4 * 1024 * 1024;

fn stream_key(id: &str, stderr: bool) -> String {
    format!("{id}:{}", if stderr { "err" } else { "out" })
}

fn nanos_of(stamp: &str) -> Option<i128> {
    time::OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp_nanos())
}

impl Streams {
    pub fn restore(saved: Option<&str>) -> Self {
        Self {
            marks: saved
                .and_then(|json| serde_json::from_str(json).ok())
                .unwrap_or_default(),
            changed: false,
        }
    }

    pub fn saved(&mut self) -> Option<String> {
        if !std::mem::take(&mut self.changed) {
            return None;
        }
        serde_json::to_string(&self.marks).ok()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    /// The new lines of every container output the plan reads, by
    /// `stream_key`. The first read of one only notes the time, so its
    /// history isn't counted; one that's far behind (the daemon was off a
    /// long time) catches up from no more than ten minutes back.
    pub async fn read(
        &mut self,
        socket: &Path,
        plan: &Plan,
        now: i64,
    ) -> BTreeMap<String, Vec<String>> {
        let mut out = BTreeMap::new();
        let mut wanted: Vec<String> = Vec::new();
        for source in &plan.sources {
            let Reader::Container { id, stderr } = &source.reader else {
                continue;
            };
            let key = stream_key(id, *stderr);
            if wanted.contains(&key) {
                continue;
            }
            wanted.push(key.clone());
            let floor = i128::from(now - 600) * 1_000_000_000;
            let Some(last) = self.marks.get(&key).copied() else {
                self.marks.insert(key, i128::from(now) * 1_000_000_000);
                self.changed = true;
                continue;
            };
            let since = last.max(floor);
            let since_text = format!(
                "{}.{:09}",
                since.div_euclid(1_000_000_000),
                since.rem_euclid(1_000_000_000)
            );
            let Some((lines, _)) = daemon_inventory::docker::logs_since(
                socket,
                id,
                *stderr,
                &since_text,
                MAX_STREAM_READ,
                std::time::Duration::from_secs(5),
            )
            .await
            else {
                continue;
            };
            let mut newest = since;
            let mut fresh = Vec::new();
            for (stamp, line) in lines {
                let Some(at) = nanos_of(&stamp) else { continue };
                if at <= since {
                    continue;
                }
                newest = newest.max(at);
                fresh.push(line);
            }
            if newest != last {
                self.marks.insert(key.clone(), newest);
                self.changed = true;
            }
            out.insert(key, fresh);
        }
        let before = self.marks.len();
        self.marks.retain(|key, _| wanted.contains(key));
        self.changed |= self.marks.len() != before;
        out
    }
}

/// A site key for one of these sites: the server (with its container, for
/// one in a container) and its first name. The dot keeps it apart from the
/// sites ServerOS writes, whose keys never have one.
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

/// `nginx`, or `nginx-<container>` for one in a container.
fn server_tag(server: &str, container: Option<&Container>) -> String {
    match container {
        None => server.to_string(),
        Some(c) => {
            let name: String = c
                .name
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || ch == '-' {
                        ch
                    } else {
                        '-'
                    }
                })
                .take(40)
                .collect();
            format!("{server}-{}", name.to_ascii_lowercase())
        }
    }
}

/// The key of a file several sites write without saying which: the
/// server, the file's name and a hash of where it's read from.
fn shared_key(server: &str, target: &LogTarget, path: &Path) -> String {
    let mut hash: u32 = 0x811c_9dc5;
    let identity = format!("{target:?}");
    for b in identity.as_bytes() {
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

/// Whether a request for `host` is one for a site with these names. `*`
/// is a catch-all.
fn serves(names: &[String], host: &str) -> bool {
    names.iter().any(|name| {
        if name == "*" {
            true
        } else if let Some(suffix) = name.strip_prefix("*.") {
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
    /// Its names (the first is what the Caddy fix looks for).
    pub names: Vec<String>,
    pub catch_all: bool,
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
    /// By the host in each line; lines for other hosts aren't counted. A
    /// catch-all (`*`) comes last.
    ByHost(Vec<(String, Vec<String>)>),
    /// By the router in each line (Traefik), then by host.
    ByRouter(Vec<(String, String)>, Vec<(String, Vec<String>)>),
}

/// How a source's lines read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineFormat {
    Template(Template),
    /// ServerOS's own JSON line (its copies for nginx and Apache).
    Line,
    Caddy,
    Traefik,
    /// A file set by hand: JSON, combined or common, whichever reads.
    Auto,
}

impl LineFormat {
    fn of(server: &str, format: &str) -> Self {
        match format {
            FORMAT_CADDY | FORMAT_CADDY_CONSOLE => Self::Caddy,
            FORMAT_TRAEFIK => Self::Traefik,
            FORMAT_TRAEFIK_COMMON => Self::Template(Template::nginx(TRAEFIK_COMMON)),
            _ if server == "apache" => Self::Template(Template::apache(format)),
            _ => Self::Template(Template::nginx(format)),
        }
    }

    fn usable(&self) -> bool {
        match self {
            Self::Template(t) => t.usable(),
            _ => true,
        }
    }

    fn has_host(&self) -> bool {
        match self {
            Self::Template(t) => t.has_host(),
            Self::Auto => false,
            _ => true,
        }
    }

    fn by_router(&self) -> bool {
        match self {
            Self::Traefik => true,
            Self::Template(t) => t.has(&[Field::Router]),
            _ => false,
        }
    }

    fn timed(&self) -> bool {
        match self {
            Self::Template(t) => t.timed(),
            Self::Auto => false,
            _ => true,
        }
    }

    pub fn parse(&self, line: &str, now: i64) -> Option<Hit> {
        match self {
            Self::Template(t) => t.parse(line, now),
            Self::Line => traffic::parse_line(traffic::Format::Line, line),
            Self::Caddy => traffic::parse_caddy(line, now),
            Self::Traefik => traffic::parse_line(traffic::Format::Traefik, line),
            Self::Auto => traffic::parse_any_json(line, now).or_else(|| {
                let combined = Template::nginx(daemon_inventory::access_logs::NGINX_COMBINED);
                combined
                    .parse(line, now)
                    .or_else(|| Template::nginx(COMMON).parse(line, now))
            }),
        }
    }
}

/// Traefik's common format, as a template.
pub const TRAEFIK_COMMON: &str = "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" $request_count \"$serveros_router\" \"$upstream\" ${serveros_ms}ms";
const COMMON: &str =
    "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent";

/// Where a source's lines come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reader {
    /// A file of the user's: followed, never written.
    Tail(PathBuf),
    /// ServerOS's own file: emptied as it's read.
    Drain(PathBuf),
    /// A container's output, through Docker.
    Container { id: String, stderr: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub reader: Reader,
    pub format: LineFormat,
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

/// The most sites and sources a plan holds.
pub const MAX_SITES: usize = 300;
const MAX_SOURCES: usize = 100;

#[derive(Default)]
struct Group {
    server: String,
    names: Vec<String>,
    configs: Vec<String>,
    ports: Vec<u16>,
    roots: Vec<String>,
    sockets: Vec<String>,
    apps: Vec<String>,
    logs: Vec<LogFile>,
    routers: Vec<String>,
    blocks: Vec<Block>,
    copy: Option<(PathBuf, String)>,
    container: Option<Container>,
    catch_all: bool,
    editable: bool,
    unlogged: Option<String>,
    /// Its only logs are ServerOS's own (its sites are counted there).
    ours: bool,
    /// It writes a log ServerOS added for it, shared with other sites
    /// (Traefik's one access log): emptied as it's read.
    drained: bool,
}

fn push_all<T: PartialEq + Clone>(into: &mut Vec<T>, from: &[T]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

/// A file set by hand for an app that writes its own access log
/// (`TrafficSource`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manual {
    pub key: String,
    pub name: String,
    pub path: PathBuf,
}

/// The key of a file set by hand.
pub fn manual_key(name: &str) -> String {
    site_key("log", Some(name))
}

/// Which files and outputs to read and which site each line counts for,
/// from the vhosts the configs describe. `traffic_dir` is where ServerOS's
/// own logs are (its own sites' files there are skipped; the copies in its
/// `existing` folder are read in place of the logs they copy). `ours` are
/// the domains of the sites ServerOS writes, which are counted there.
pub fn plan(vhosts: &[VhostLogs], traffic_dir: &Path) -> Plan {
    plan_with(vhosts, traffic_dir, &[], &[])
}

pub fn plan_with(
    vhosts: &[VhostLogs],
    traffic_dir: &Path,
    ours: &[String],
    manual: &[Manual],
) -> Plan {
    let copies = traffic_dir.join(COPY_DIR);
    let mut groups: Vec<(String, Group)> = Vec::new();
    for vhost in vhosts {
        if vhost.config_path.contains("/serveros.d/") {
            continue;
        }
        if !vhost.names.is_empty() && vhost.names.iter().all(|n| ours.contains(n)) {
            continue;
        }
        let tag = server_tag(&vhost.server, vhost.container.as_ref());
        let first = if vhost.catch_all {
            Some("any")
        } else {
            vhost.names.first().map(String::as_str)
        };
        let key = site_key(&tag, first);
        let index = match groups.iter().position(|(k, _)| *k == key) {
            Some(index) => index,
            None => {
                if groups.len() >= MAX_SITES {
                    continue;
                }
                groups.push((
                    key.clone(),
                    Group {
                        server: vhost.server.clone(),
                        container: vhost.container.clone(),
                        catch_all: vhost.catch_all,
                        editable: vhost.editable,
                        ..Default::default()
                    },
                ));
                groups.len() - 1
            }
        };
        let group = &mut groups[index].1;
        push_all(&mut group.names, &vhost.names);
        push_all(&mut group.configs, std::slice::from_ref(&vhost.config_path));
        push_all(&mut group.ports, &vhost.upstream_ports);
        push_all(&mut group.roots, &vhost.roots);
        push_all(&mut group.sockets, &vhost.sockets);
        push_all(&mut group.apps, &vhost.upstream_containers);
        push_all(&mut group.routers, &vhost.routers);
        group.editable &= vhost.editable;
        if group.unlogged.is_none() || vhost.unlogged.as_deref() == Some("off") {
            group.unlogged.clone_from(&vhost.unlogged);
        }
        group.blocks.push(Block {
            key: key.clone(),
            config: vhost.config_path.clone(),
            block: vhost.block,
            inherited: vhost.inherited.then(|| vhost.logs.clone()),
            names: vhost.names.clone(),
            catch_all: vhost.catch_all,
        });
        for log in &vhost.logs {
            let file = match &log.target {
                LogTarget::File(file) => Some(file),
                LogTarget::Container { .. } => None,
            };
            match file {
                Some(file)
                    if file.parent() == Some(copies.as_path())
                        && file.file_stem().is_some_and(|s| s == key.as_str()) =>
                {
                    group.copy = Some((file.clone(), log.format.clone()));
                }
                Some(file) if file.parent() == Some(copies.as_path()) => {
                    group.drained = true;
                    if !group.logs.iter().any(|l| l.target == log.target) {
                        group.logs.push(log.clone());
                    }
                }
                Some(file) if file.starts_with(traffic_dir) => group.ours = true,
                _ => {
                    if !group.logs.iter().any(|l| l.target == log.target) {
                        group.logs.push(log.clone());
                    }
                }
            }
        }
    }

    // Each file or output, the format it's in and the sites that write it.
    let mut files: Vec<(LogTarget, PathBuf, LineFormat, Vec<usize>)> = Vec::new();
    for (index, (_, group)) in groups.iter().enumerate() {
        if group.copy.is_some() {
            continue;
        }
        for log in &group.logs {
            let format = LineFormat::of(&group.server, &log.format);
            if !format.usable() {
                continue;
            }
            match files.iter_mut().find(|(target, ..)| *target == log.target) {
                Some((.., writers)) => writers.push(index),
                None => {
                    if files.len() < MAX_SOURCES {
                        // A log read from a container's output is named as
                        // that, whatever path its config gives it.
                        let shown = match &log.target {
                            LogTarget::Container { stderr: true, .. } => {
                                PathBuf::from("/dev/stderr")
                            }
                            LogTarget::Container { .. } => PathBuf::from("/dev/stdout"),
                            LogTarget::File(_) => log.path.clone(),
                        };
                        files.push((log.target.clone(), shown, format, vec![index]));
                    }
                }
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
        copy: group.copy.is_some() || group.drained,
        configs: group.configs.clone(),
        upstream_ports: group.ports.clone(),
        container: group.container.as_ref().map(|c| c.name.clone()),
        catch_all: group.catch_all,
        roots: group.roots.clone(),
        sockets: group.sockets.clone(),
        upstream_containers: group.apps.clone(),
        unlogged: None,
        editable: group.editable,
        manual: false,
    };
    let reader_of = |target: &LogTarget| match target {
        LogTarget::File(path) if path.parent() == Some(copies.as_path()) => {
            Reader::Drain(path.clone())
        }
        LogTarget::File(path) => Reader::Tail(path.clone()),
        LogTarget::Container { id, stderr } => Reader::Container {
            id: id.clone(),
            stderr: *stderr,
        },
    };

    let mut plan = Plan::default();
    for (index, (key, group)) in groups.iter().enumerate() {
        if let Some((copy, format)) = &group.copy {
            let format = if matches!(group.server.as_str(), "nginx" | "apache") {
                LineFormat::Line
            } else {
                LineFormat::of(&group.server, format)
            };
            plan.sources.push(Source {
                reader: Reader::Drain(copy.clone()),
                format,
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
        // Its own files: written by it alone, or with hosts or routers in
        // the lines.
        let own: Vec<&(LogTarget, PathBuf, LineFormat, Vec<usize>)> = files
            .iter()
            .filter(|(_, _, format, writers)| {
                writers.contains(&index)
                    && (writers.len() == 1 || format.has_host() || format.by_router())
            })
            .collect();
        if own.is_empty() {
            let readable = group
                .logs
                .iter()
                .any(|l| LineFormat::of(&group.server, &l.format).usable());
            if group.ours && group.logs.is_empty() {
                continue;
            }
            if readable {
                // Its file is counted with others, as a shared site.
                continue;
            }
            let mut site = info(key, group, Vec::new(), false);
            site.unlogged = Some(group.unlogged.clone().unwrap_or_else(|| {
                if group.logs.is_empty() {
                    "off"
                } else {
                    "elsewhere"
                }
                .into()
            }));
            plan.sites.push(Site {
                info: site,
                blocks: group.blocks.clone(),
            });
            continue;
        }
        plan.sites.push(Site {
            info: info(
                key,
                group,
                own.iter()
                    .map(|(_, p, _, _)| p.display().to_string())
                    .collect(),
                own.iter().all(|(_, _, f, _)| f.timed()),
            ),
            blocks: group.blocks.clone(),
        });
    }

    let by_host = |writers: &[usize]| -> Vec<(String, Vec<String>)> {
        let mut list: Vec<(String, Vec<String>)> = writers
            .iter()
            .map(|i| {
                let (key, group) = &groups[*i];
                let names = if group.catch_all {
                    vec!["*".to_string()]
                } else {
                    group.names.clone()
                };
                (key.clone(), names)
            })
            .collect();
        // Catch-alls last, as the server only sends them what nothing
        // else matched.
        list.sort_by_key(|(_, names)| names.iter().any(|n| n == "*"));
        list
    };
    for (target, path, format, writers) in files {
        let route = if format.by_router() {
            let routers = writers
                .iter()
                .flat_map(|i| {
                    let (key, group) = &groups[*i];
                    group.routers.iter().map(move |r| (r.clone(), key.clone()))
                })
                .collect();
            Route::ByRouter(routers, by_host(&writers))
        } else if writers.len() == 1 {
            Route::One(groups[writers[0]].0.clone())
        } else if format.has_host() {
            Route::ByHost(by_host(&writers))
        } else {
            // Several sites, no host in the lines: counted together.
            let first = &groups[writers[0]].1;
            let key = shared_key(
                &server_tag(&first.server, first.container.as_ref()),
                &target,
                &path,
            );
            let mut merged = Group {
                server: first.server.clone(),
                container: first.container.clone(),
                editable: true,
                ..Default::default()
            };
            for i in &writers {
                let group = &groups[*i].1;
                push_all(&mut merged.names, &group.names);
                push_all(&mut merged.configs, &group.configs);
                push_all(&mut merged.ports, &group.ports);
                push_all(&mut merged.roots, &group.roots);
                push_all(&mut merged.sockets, &group.sockets);
                merged.editable &= group.editable;
                merged.blocks.extend(group.blocks.iter().cloned());
            }
            merged.ports.sort_unstable();
            let mut site = info(
                &key,
                &merged,
                vec![path.display().to_string()],
                format.timed(),
            );
            site.shared = true;
            plan.sites.push(Site {
                info: site,
                blocks: merged.blocks,
            });
            Route::One(key)
        };
        plan.sources.push(Source {
            reader: reader_of(&target),
            format,
            route,
        });
    }

    for one in manual.iter().take(20) {
        if plan.sites.iter().any(|s| s.info.site == one.key) {
            continue;
        }
        plan.sources.push(Source {
            reader: Reader::Tail(one.path.clone()),
            format: LineFormat::Auto,
            route: Route::One(one.key.clone()),
        });
        plan.sites.push(Site {
            info: TrafficSite {
                site: one.key.clone(),
                server: "log".into(),
                names: vec![one.name.clone()],
                logs: vec![one.path.display().to_string()],
                manual: true,
                ..Default::default()
            },
            blocks: Vec::new(),
        });
    }
    plan.sites.sort_by(|a, b| a.info.site.cmp(&b.info.site));
    plan.sites.truncate(MAX_SITES);
    plan
}

/// Reads what's new in every file and output of the plan into `rollups`.
/// `streams` are the containers' new lines, by `stream_key` (see
/// `Streams::read`). Returns how many requests were counted.
pub fn collect(
    plan: &Plan,
    tailer: &mut Tailer,
    streams: &BTreeMap<String, Vec<String>>,
    rollups: &mut Rollups,
    now: i64,
) -> usize {
    let mut counted = 0;
    for source in &plan.sources {
        let lines = match &source.reader {
            Reader::Tail(path) => tailer.read(path),
            Reader::Drain(path) => drain_copy(path),
            Reader::Container { id, stderr } => streams
                .get(&stream_key(id, *stderr))
                .cloned()
                .unwrap_or_default(),
        };
        for line in &lines {
            let Some(hit) = source.format.parse(line, now) else {
                continue;
            };
            let host_route = |sites: &[(String, Vec<String>)]| {
                sites
                    .iter()
                    .find(|(_, names)| serves(names, &hit.host))
                    .map(|(site, _)| site.clone())
            };
            let site = match &source.route {
                Route::One(site) => Some(site.clone()),
                Route::ByHost(sites) => host_route(sites),
                Route::ByRouter(routers, sites) => hit
                    .router
                    .as_deref()
                    .and_then(|router| {
                        routers
                            .iter()
                            .find(|(name, _)| {
                                name == router || name.split('@').next() == Some(router)
                            })
                            .map(|(_, site)| site.clone())
                    })
                    .or_else(|| {
                        // A router of ServerOS's own or Traefik's, or one it
                        // doesn't know (counted by host).
                        let ours = hit.router.as_deref().is_some_and(|r| {
                            r.starts_with("serveros-") || r.ends_with("@internal")
                        });
                        (!ours).then(|| host_route(sites)).flatten()
                    }),
            };
            if let Some(site) = site {
                rollups.add(&site, &hit);
                counted += 1;
            }
        }
    }
    let paths: Vec<&Path> = plan
        .sources
        .iter()
        .filter_map(|s| match &s.reader {
            Reader::Tail(path) => Some(path.as_path()),
            _ => None,
        })
        .collect();
    tailer.keep_only(&paths);
    counted
}

/// A copy ServerOS has a web server write, emptied as it's read, with the
/// backups Caddy rolls a full one into (`<name>-<time>.log`): read once,
/// then deleted.
fn drain_copy(path: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    if let (Some(dir), Some(stem)) = (path.parent(), path.file_stem().and_then(|s| s.to_str())) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten().take(200) {
                let other = entry.path();
                let name = other
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if other != path && name.starts_with(&format!("{stem}-")) && name.ends_with(".log")
                {
                    lines.extend(traffic::drain(&other));
                    let _ = std::fs::remove_file(&other);
                }
            }
        }
    }
    lines.extend(traffic::drain(path));
    lines
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
    use daemon_inventory::access_logs::{
        Container, LogTarget, FORMAT_CADDY, FORMAT_TRAEFIK, FORMAT_TRAEFIK_COMMON,
    };

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

        // Moved with nothing in its place (the server hasn't reopened its
        // log yet): followed where it went until a new file shows up.
        append(&log, &["m1"]);
        assert_eq!(tailer.read(&log), vec!["z", "m1"]);
        std::fs::rename(&log, dir.path().join("access.log.1")).unwrap();
        append(&dir.path().join("access.log.1"), &["m2"]);
        assert_eq!(tailer.read(&log), vec!["m2"]);
        append(&dir.path().join("access.log.1"), &["m3"]);
        assert_eq!(tailer.read(&log), vec!["m3"]);
        append(&log, &["m4"]);
        assert_eq!(tailer.read(&log), vec!["m4"]);

        // Rolled and compressed before the next read (Caddy's
        // access-<time>.log.gz): the rest is read from the .gz.
        append(&log, &["g1"]);
        assert_eq!(tailer.read(&log), vec!["g1"]);
        append(&log, &["g2", "g3"]);
        let text = std::fs::read(&log).unwrap();
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        gz.extend(miniz_oxide::deflate::compress_to_vec(&text, 6));
        gz.extend([0u8; 8]);
        std::fs::write(dir.path().join("access-2026-11-20T10-24-10.247.log.gz"), gz).unwrap();
        std::fs::remove_file(&log).unwrap();
        append(&log, &["g4"]);
        assert_eq!(tailer.read(&log), vec!["g2", "g3", "g4"]);
        std::fs::remove_file(dir.path().join("access-2026-11-20T10-24-10.247.log.gz")).unwrap();
        std::fs::remove_file(dir.path().join("access.log.1")).unwrap();

        // A file that wasn't there at first is read from its start.
        let late = dir.path().join("late.log");
        assert!(tailer.read(&late).is_empty());
        append(&late, &["first"]);
        assert_eq!(tailer.read(&late), vec!["first"]);

        // Nothing was ever written by the tailer.
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "g4\n");
    }

    fn vhost(server: &str, names: &[&str], config: &str, logs: &[(&str, &str)]) -> VhostLogs {
        VhostLogs {
            server: server.into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            config_path: config.into(),
            logs: logs
                .iter()
                .map(|(path, format)| LogFile::file(*path, format, None))
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
            if source.reader == Reader::Tail("/var/log/apache2/other.log".into()) {
                source.reader = Reader::Tail(other.clone());
            }
        }
        let plan = Plan { sources, ..plan };
        let mut tailer = Tailer::default();
        let mut rollups = Rollups::new();
        collect(&plan, &mut tailer, &BTreeMap::new(), &mut rollups, 0);
        append(
            &other,
            &[
                r#"one.test:80 1.1.1.1 - - [20/Nov/2026:12:00:05 +0000] "GET / HTTP/1.1" 200 1 "-" "x""#,
                r#"a.two.test:443 1.1.1.1 - - [20/Nov/2026:12:00:06 +0000] "GET / HTTP/1.1" 200 1 "-" "x""#,
                r#"stranger.test:80 1.1.1.1 - - [20/Nov/2026:12:00:07 +0000] "GET / HTTP/1.1" 200 1 "-" "x""#,
            ],
        );
        assert_eq!(
            collect(&plan, &mut tailer, &BTreeMap::new(), &mut rollups, 0),
            2
        );
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
                .filter(|s| matches!(s.reader, Reader::Drain(_)))
                .cloned()
                .collect(),
            ..plan.clone()
        };
        let mut rollups = Rollups::new();
        assert_eq!(
            collect(
                &only_copy,
                &mut Tailer::default(),
                &BTreeMap::new(),
                &mut rollups,
                0
            ),
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
        let key = |p: &str| shared_key("nginx", &LogTarget::File(p.into()), Path::new(p));
        let shared = key("/var/log/nginx/access.log");
        assert_eq!(shared, key("/var/log/nginx/access.log"));
        assert_ne!(shared, key("/srv/logs/access.log"));
        assert!(shared.contains('.'));
    }

    fn caddy_line(host: &str, uri: &str, status: u16, secs: f64) -> String {
        format!(
            r#"{{"level":"info","ts":1795694405.2,"logger":"http.log.access.log2","msg":"handled request","request":{{"remote_ip":"1.2.3.4","client_ip":"1.2.3.4","host":"{host}","uri":"{uri}","headers":{{"User-Agent":["x"]}}}},"duration":{secs},"size":10,"status":{status}}}"#
        )
    }

    /// Production's shape: three sites into one file (a catch-all among
    /// them), ServerOS's own site skipped, a site with no log listed as
    /// not logged, and every line counted for the site Caddy routed it to.
    #[test]
    fn caddy_sites_sharing_one_file_are_split_by_host_with_a_catch_all() {
        let dir = tempfile::tempdir().unwrap();
        let access = dir.path().join("access.log");
        let log = LogFile {
            format: FORMAT_CADDY.into(),
            ..LogFile::file(&access, "", None)
        };
        let site = |names: &[&str], catch_all: bool, logs: Vec<LogFile>| VhostLogs {
            server: "caddy".into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            config_path: "/etc/caddy/Caddyfile".into(),
            catch_all,
            editable: true,
            unlogged: logs.is_empty().then(|| "off".to_string()),
            roots: vec!["/var/www/serveros/public".into()],
            logs,
            ..Default::default()
        };
        let vhosts = vec![
            site(&["releases.serveros.com"], false, vec![log.clone()]),
            site(&["gateway.serveros.com"], false, vec![log.clone()]),
            site(
                &["graf.serveros.com"],
                false,
                vec![LogFile::file(
                    "/var/log/serveros-traffic/grafana.log",
                    FORMAT_CADDY,
                    None,
                )],
            ),
            site(&[], true, vec![log.clone()]),
            site(&["quiet.test"], false, vec![]),
        ];
        let ours = vec!["graf.serveros.com".to_string()];
        let plan = plan_with(&vhosts, Path::new("/var/log/serveros-traffic"), &ours, &[]);
        let keys: Vec<&str> = plan.sites.iter().map(|s| s.info.site.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "caddy.any",
                "caddy.gateway.serveros.com",
                "caddy.quiet.test",
                "caddy.releases.serveros.com"
            ]
        );
        let any = plan.site("caddy.any").unwrap();
        assert!(any.info.catch_all && any.info.timed && !any.info.shared);
        assert_eq!(any.info.roots, vec!["/var/www/serveros/public"]);
        let quiet = plan.site("caddy.quiet.test").unwrap();
        assert_eq!(quiet.info.unlogged.as_deref(), Some("off"));
        assert!(quiet.info.logs.is_empty() && quiet.info.editable);
        assert_eq!(plan.sources.len(), 1);
        assert!(
            matches!(&plan.sources[0].route, Route::ByHost(list) if list.last().unwrap().1 == vec!["*".to_string()])
        );

        let mut tailer = Tailer::default();
        let mut rollups = Rollups::new();
        std::fs::write(&access, "").unwrap();
        collect(&plan, &mut tailer, &BTreeMap::new(), &mut rollups, 0);
        append(
            &access,
            &[
                &caddy_line("releases.serveros.com", "/v1/VERSION", 200, 0.001),
                &caddy_line("gateway.serveros.com:443", "/api/gateway/x", 200, 0.04),
                &caddy_line("liam.serveros.com", "/machines", 200, 0.12),
                &caddy_line("acme.example", "/", 404, 0.01),
                "not json",
            ],
        );
        assert_eq!(
            collect(&plan, &mut tailer, &BTreeMap::new(), &mut rollups, 0),
            4
        );
        let done = rollups.finished(i64::MAX / 2);
        let count = |site: &str| {
            done.iter()
                .filter(|r| r.site == site)
                .map(|r| r.requests)
                .sum::<u64>()
        };
        assert_eq!(count("caddy.releases.serveros.com"), 1);
        assert_eq!(count("caddy.gateway.serveros.com"), 1);
        assert_eq!(count("caddy.any"), 2);
        let any = done.iter().find(|r| r.site == "caddy.any").unwrap();
        assert_eq!(any.p95_ms, Some(120.0));

        // Caddy rolls the file over to access-<time>.log: what was left in
        // it is still read, then the new file from its start.
        append(
            &access,
            &[&caddy_line("acme.example", "/before", 200, 0.01)],
        );
        std::fs::rename(
            &access,
            dir.path().join("access-2026-11-20T10-24-10.247.log"),
        )
        .unwrap();
        append(&access, &[&caddy_line("acme.example", "/after", 200, 0.01)]);
        let mut rollups = Rollups::new();
        assert_eq!(
            collect(&plan, &mut tailer, &BTreeMap::new(), &mut rollups, 0),
            2
        );
    }

    #[test]
    fn container_output_and_traefik_routers() {
        let id = "c".repeat(64);
        let container = Container {
            id: id.clone(),
            name: "coolify-proxy".into(),
        };
        let out = LogFile {
            path: "/dev/stdout".into(),
            format: FORMAT_TRAEFIK.into(),
            format_name: None,
            target: LogTarget::Container {
                id: id.clone(),
                stderr: false,
            },
        };
        let router = |names: &[&str], routers: &[&str]| VhostLogs {
            server: "traefik".into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            config_path: "its command line".into(),
            container: Some(container.clone()),
            routers: routers.iter().map(|r| r.to_string()).collect(),
            upstream_containers: vec![format!("{}-app", names[0])],
            logs: vec![out.clone()],
            ..Default::default()
        };
        let plan = plan_with(
            &[
                router(&["shop.test"], &["http-0-a@docker", "https-0-a@docker"]),
                router(&["blog.test"], &["blog@docker"]),
            ],
            Path::new("/var/log/serveros-traffic"),
            &[],
            &[],
        );
        let keys: Vec<&str> = plan.sites.iter().map(|s| s.info.site.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "traefik-coolify-proxy.blog.test",
                "traefik-coolify-proxy.shop.test"
            ]
        );
        let shop = plan.site("traefik-coolify-proxy.shop.test").unwrap();
        assert_eq!(shop.info.container.as_deref(), Some("coolify-proxy"));
        assert_eq!(shop.info.logs, vec!["/dev/stdout"]);
        assert_eq!(shop.info.upstream_containers, vec!["shop.test-app"]);
        assert!(!shop.info.editable);
        assert_eq!(plan.sources.len(), 1);
        assert_eq!(
            plan.sources[0].reader,
            Reader::Container {
                id: id.clone(),
                stderr: false
            }
        );

        let line = |router: &str, host: &str| {
            format!(
                r#"{{"ClientHost":"192.0.2.1","DownstreamContentSize":42,"DownstreamStatus":200,"Duration":3000000,"RequestHost":"{host}","RequestPath":"/","RouterName":"{router}","time":"2026-11-20T12:00:02Z"}}"#
            )
        };
        let mut lines = BTreeMap::new();
        lines.insert(
            format!("{id}:out"),
            vec![
                line("https-0-a@docker", "shop.test"),
                line("http-0-a@docker", "shop.test"),
                line("blog@docker", "blog.test"),
                line("serveros-x@file", "blog.test"),
                line("dashboard@internal", "shop.test"),
                "time=\"2026-11-20\" level=info msg=\"Configuration loaded\"".to_string(),
            ],
        );
        let mut rollups = Rollups::new();
        // An unknown router falls back to the host; ServerOS's own and
        // Traefik's internal ones don't.
        assert_eq!(
            collect(&plan, &mut Tailer::default(), &lines, &mut rollups, 0),
            3
        );
        let done = rollups.finished(i64::MAX / 2);
        let count = |site: &str| {
            done.iter()
                .filter(|r| r.site == site)
                .map(|r| r.requests)
                .sum::<u64>()
        };
        assert_eq!(count("traefik-coolify-proxy.shop.test"), 2);
        assert_eq!(count("traefik-coolify-proxy.blog.test"), 1);

        // Traefik's common format names the router too.
        let common = LineFormat::of("traefik", FORMAT_TRAEFIK_COMMON);
        let hit = common
            .parse(r#"192.0.2.1 - - [20/Nov/2026:12:00:05 +0000] "GET /pricing?x=1 HTTP/1.1" 404 19 "-" "curl/8" 7 "blog@docker" "http://172.18.0.3:80" 3ms"#, 0)
            .unwrap();
        assert_eq!(
            (hit.status, hit.path.as_str(), hit.ms),
            (404, "/pricing", Some(3.0))
        );
        assert_eq!(hit.router.as_deref(), Some("blog@docker"));
    }

    #[test]
    fn a_file_set_by_hand_reads_whatever_the_app_writes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.log");
        std::fs::write(&file, "").unwrap();
        let manual = vec![Manual {
            key: manual_key("API"),
            name: "API".into(),
            path: file.clone(),
        }];
        let plan = plan_with(&[], Path::new("/var/log/serveros-traffic"), &[], &manual);
        assert_eq!(plan.sites[0].info.site, "log.api");
        assert!(plan.sites[0].info.manual);
        let mut tailer = Tailer::default();
        let mut rollups = Rollups::new();
        collect(&plan, &mut tailer, &BTreeMap::new(), &mut rollups, 0);
        append(
            &file,
            &[
                r#"{"time":"2026-11-20T12:00:05Z","status":200,"path":"/a","duration":0.01}"#,
                r#"10.0.0.1 - - [20/Nov/2026:12:00:05 +0000] "GET /b HTTP/1.1" 500 1 "-" "x""#,
                r#"10.0.0.1 - - [20/Nov/2026:12:00:05 +0000] "GET /c HTTP/1.1" 404 1"#,
                "server started on :3000",
            ],
        );
        assert_eq!(
            collect(&plan, &mut tailer, &BTreeMap::new(), &mut rollups, 0),
            3
        );
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
