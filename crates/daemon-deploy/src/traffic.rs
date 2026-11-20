//! Traffic for the sites ServerOS runs: the proxy writes a JSON access log,
//! the daemon reads it every few seconds, empties it and rolls each site's
//! requests up per minute. Only the rollups leave the machine: counts,
//! timings, the top paths (without query strings) and the hosts of the top
//! referrers. IP addresses, user agents and full referrer URLs stay here,
//! and only for as long as it takes to read them.
//!
//! Unique visitors are counted from a hash of IP and user agent, keyed with
//! a random salt that lives in memory only and changes every UTC day. The
//! hashes never leave the daemon either: a rollup only says how many
//! visitors were new that day in that minute.
//!
//! Countries and devices aren't counted: that needs a GeoIP database and a
//! user agent parser, and the point is to keep this small.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use daemon_core::config::ProxyBackend;
use daemon_protocol::TrafficRollup;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

/// Where proxies write the access logs the daemon reads. Root-only (or the
/// proxy's own user's), and emptied every few seconds.
pub const TRAFFIC_LOG_DIR: &str = "/var/log/serveros-traffic";

/// Traefik writes one access log for every router. The dot keeps it from
/// ever being taken for a site's (site names have none).
pub const TRAEFIK_LOG: &str = "traefik.access.log";

/// The most of one file read at once. A file bigger than this (the daemon
/// was stopped for a long time on a busy machine) is emptied unread, so it
/// can't fill the disk or the daemon's memory.
const MAX_READ: u64 = 64 * 1024 * 1024;

/// How many paths and referrers a rollup names.
pub const TOP: usize = 10;
/// How many different paths or referrers one minute keeps count of; past
/// that, new ones aren't counted by name (they still count as requests).
const MAX_NAMES: usize = 5_000;
/// How many response times one minute keeps for its percentiles.
const MAX_TIMINGS: usize = 50_000;
/// How many visitors a site remembers in a day. Past that, every visitor
/// counts as new.
const MAX_VISITORS: usize = 1_000_000;
/// A minute is reported this long after it ends, for lines still on their
/// way.
const GRACE_SECS: i64 = 5;
const MAX_PATH: usize = 300;

/// One request, as read from a proxy's log line. Lives for as long as it
/// takes to count it.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// When the request finished, in Unix seconds.
    pub ts: i64,
    pub host: String,
    pub ip: String,
    pub user_agent: String,
    /// The path, without its query string.
    pub path: String,
    pub status: u16,
    pub bytes: u64,
    pub ms: Option<f32>,
    /// The referrer's host, when it's another site.
    pub referrer: Option<String>,
    /// Traefik only: the router that handled it.
    pub router: Option<String>,
}

/// The log formats ServerOS has the proxies write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Caddy's own JSON access log.
    Caddy,
    /// The JSON line ServerOS gives nginx and Apache: the same keys for
    /// both, with Apache's time in microseconds.
    Line,
    /// Traefik's JSON access log.
    Traefik,
}

impl Format {
    pub fn of(backend: ProxyBackend) -> Option<Self> {
        match backend {
            ProxyBackend::Caddy => Some(Self::Caddy),
            ProxyBackend::Nginx | ProxyBackend::Apache => Some(Self::Line),
            ProxyBackend::Traefik => Some(Self::Traefik),
            ProxyBackend::None => None,
        }
    }
}

/// Apache's log format for a site, inline in its CustomLog. Apache escapes
/// quotes and backslashes in headers, and other bytes as `\xhh`, which the
/// reader turns back into JSON.
pub const APACHE_LOG_FORMAT: &str = "\"{\\\"t\\\":%{end:msec}t,\\\"host\\\":\\\"%{Host}i\\\",\\\"ip\\\":\\\"%a\\\",\\\"uri\\\":\\\"%U\\\",\\\"status\\\":%>s,\\\"bytes\\\":%B,\\\"time_us\\\":%D,\\\"referer\\\":\\\"%{Referer}i\\\",\\\"ua\\\":\\\"%{User-Agent}i\\\"}\"";

/// The access log section ServerOS adds to a Traefik config it wrote, for
/// `file` (Traefik's one log). Headers are dropped except the two the
/// rollups need.
pub fn traefik_access_log(file: &Path) -> String {
    format!(
        "{TRAEFIK_BEGIN}\n[accessLog]\n  filePath = \"{}\"\n  format = \"json\"\n  [accessLog.fields]\n    defaultMode = \"keep\"\n    [accessLog.fields.headers]\n      defaultMode = \"drop\"\n      [accessLog.fields.headers.names]\n        \"User-Agent\" = \"keep\"\n        \"Referer\" = \"keep\"\n{TRAEFIK_END}\n",
        file.display()
    )
}

pub const TRAEFIK_BEGIN: &str =
    "# ServerOS traffic: an access log the daemon reads, rolls up and empties.";
pub const TRAEFIK_END: &str = "# End of ServerOS traffic.";

/// A Traefik config with ServerOS's access log section added (`on`) or
/// taken out. None when it's already that way.
pub fn with_traefik_access_log(config: &str, file: &Path, on: bool) -> Option<String> {
    let without = match (config.find(TRAEFIK_BEGIN), config.find(TRAEFIK_END)) {
        (Some(start), Some(end)) if end > start => {
            let mut stop = end + TRAEFIK_END.len();
            if config[stop..].starts_with('\n') {
                stop += 1;
            }
            let mut begin = start;
            if config[..begin].ends_with("\n\n") {
                begin -= 1;
            }
            format!("{}{}", &config[..begin], &config[stop..])
        }
        _ => config.to_string(),
    };
    let next = if on {
        let mut text = without.clone();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push('\n');
        text.push_str(&traefik_access_log(file));
        text
    } else {
        without
    };
    (next != config).then_some(next)
}

/// Reads one log line. None for anything that isn't a request we can count.
pub fn parse_line(format: Format, line: &str) -> Option<Hit> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) if format == Format::Line => serde_json::from_str(&apache_unescape(line)).ok()?,
        Err(_) => return None,
    };
    match format {
        Format::Caddy => caddy_hit(&value),
        Format::Line => line_hit(&value),
        Format::Traefik => traefik_hit(&value),
    }
}

fn caddy_hit(v: &Value) -> Option<Hit> {
    let request = v.get("request")?;
    let header = |name: &str| {
        request
            .get("headers")
            .and_then(|h| h.get(name))
            .and_then(|values| values.get(0))
            .and_then(Value::as_str)
            .unwrap_or_default()
    };
    let host = strip_port(request.get("host").and_then(Value::as_str)?);
    let ip = request
        .get("client_ip")
        .and_then(Value::as_str)
        .filter(|ip| !ip.is_empty())
        .or_else(|| request.get("remote_ip").and_then(Value::as_str))
        .unwrap_or_default();
    Some(Hit {
        ts: v.get("ts").and_then(Value::as_f64)?.floor() as i64,
        referrer: referrer_host(header("Referer"), &host),
        host,
        ip: ip.to_string(),
        user_agent: header("User-Agent").to_string(),
        path: clean_path(request.get("uri").and_then(Value::as_str).unwrap_or("/")),
        status: status_of(v.get("status"))?,
        bytes: v.get("size").and_then(Value::as_u64).unwrap_or(0),
        ms: v
            .get("duration")
            .and_then(Value::as_f64)
            .map(|s| (s * 1000.0) as f32),
        router: None,
    })
}

fn line_hit(v: &Value) -> Option<Hit> {
    let text = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .filter(|s| *s != "-")
            .unwrap_or_default()
    };
    let t = v.get("t").and_then(Value::as_f64)?;
    // nginx's $msec is seconds with a fraction; Apache's msec is whole
    // milliseconds.
    let ts = if t > 100_000_000_000.0 { t / 1000.0 } else { t };
    let ms = match (
        v.get("time").and_then(Value::as_f64),
        v.get("time_us").and_then(Value::as_f64),
    ) {
        (Some(seconds), _) => Some((seconds * 1000.0) as f32),
        (None, Some(us)) => Some((us / 1000.0) as f32),
        _ => None,
    };
    let host = strip_port(text("host"));
    Some(Hit {
        ts: ts.floor() as i64,
        referrer: referrer_host(text("referer"), &host),
        host,
        ip: text("ip").to_string(),
        user_agent: text("ua").to_string(),
        path: clean_path(text("uri")),
        status: status_of(v.get("status"))?,
        bytes: v.get("bytes").and_then(Value::as_u64).unwrap_or(0),
        ms,
        router: None,
    })
}

fn traefik_hit(v: &Value) -> Option<Hit> {
    let text = |key: &str| v.get(key).and_then(Value::as_str).unwrap_or_default();
    let router = text("RouterName");
    if router.is_empty() {
        return None;
    }
    let ts = time::OffsetDateTime::parse(text("time"), &Rfc3339)
        .map(|t| t.unix_timestamp())
        .ok()
        .or_else(|| {
            let start = time::OffsetDateTime::parse(text("StartUTC"), &Rfc3339).ok()?;
            let ns = v.get("Duration").and_then(Value::as_i64).unwrap_or(0);
            Some(start.unix_timestamp() + ns / 1_000_000_000)
        })?;
    let host = strip_port(text("RequestHost"));
    Some(Hit {
        ts,
        referrer: referrer_host(text("request_Referer"), &host),
        host,
        ip: text("ClientHost").to_string(),
        user_agent: text("request_User-Agent").to_string(),
        path: clean_path(text("RequestPath")),
        status: status_of(v.get("DownstreamStatus"))?,
        bytes: v
            .get("DownstreamContentSize")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        ms: v
            .get("Duration")
            .and_then(Value::as_f64)
            .map(|ns| (ns / 1_000_000.0) as f32),
        router: Some(router.to_string()),
    })
}

fn status_of(v: Option<&Value>) -> Option<u16> {
    let status = v?.as_u64()?;
    (100..600).contains(&status).then_some(status as u16)
}

/// Apache writes bytes it won't print as `\xhh`, which JSON doesn't have.
fn apache_unescape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('x') => out.push_str("\\u00"),
            Some(next) => {
                out.push('\\');
                out.push(next);
            }
            None => {}
        }
    }
    out
}

pub fn strip_port(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.starts_with('[') {
        return host
            .split_once(']')
            .map(|(h, _)| format!("{h}]"))
            .unwrap_or(host);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name.to_string(),
        _ => host,
    }
}

/// The path without its query string or fragment, cut to a sane length.
pub fn clean_path(uri: &str) -> String {
    let path = uri.split(['?', '#']).next().unwrap_or_default();
    let path: String = path
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_PATH)
        .collect();
    if path.is_empty() {
        "/".to_string()
    } else {
        path
    }
}

/// The host a referrer URL points at, without `www.`, when it's a site
/// other than the one visited. Nothing else of the URL is kept.
pub fn referrer_host(referrer: &str, own_host: &str) -> Option<String> {
    let (_, rest) = referrer.trim().split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = strip_port(authority);
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    let own = own_host.strip_prefix("www.").unwrap_or(own_host);
    let plain = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    (plain && host != own).then_some(host)
}

/// Which of our sites a Traefik router belongs to: `serveros-<site>` and
/// `serveros-<site>-wildcard` serve it; `serveros-<site>-http` only sends
/// visitors on to HTTPS and isn't counted.
pub fn traefik_site<'a>(router: &str, sites: &'a [String]) -> Option<&'a str> {
    let name = router.split('@').next()?.strip_prefix("serveros-")?;
    if let Some(site) = sites.iter().find(|s| s.as_str() == name) {
        return Some(site);
    }
    let base = name.strip_suffix("-wildcard")?;
    sites
        .iter()
        .find(|s| s.as_str() == base)
        .map(String::as_str)
}

#[derive(Debug, Default)]
struct Bucket {
    requests: u64,
    classes: [u64; 4],
    bytes: u64,
    timings: Vec<f32>,
    visitors: u64,
    paths: HashMap<String, u64>,
    referrers: HashMap<String, u64>,
}

fn count(names: &mut HashMap<String, u64>, name: &str) {
    if let Some(n) = names.get_mut(name) {
        *n += 1;
    } else if names.len() < MAX_NAMES {
        names.insert(name.to_string(), 1);
    }
}

fn top(names: HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut list: Vec<(String, u64)> = names.into_iter().collect();
    list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    list.truncate(TOP);
    list
}

/// The value below which `p` percent of the sorted timings fall (nearest
/// rank).
fn percentile(sorted: &[f32], p: f32) -> Option<f32> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f32).ceil() as usize;
    let at = rank.clamp(1, sorted.len()) - 1;
    Some((sorted[at] * 10.0).round() / 10.0)
}

/// Each site's requests, per minute, until the minute is over and
/// reported.
pub struct Rollups {
    minutes: BTreeMap<(i64, String), Bucket>,
    /// Minutes before this have been reported; a late line goes in the
    /// earliest minute still open.
    reported_through: i64,
    day: i64,
    salt: RandomState,
    seen: HashMap<String, HashSet<u64>>,
}

impl Default for Rollups {
    fn default() -> Self {
        Self::new()
    }
}

impl Rollups {
    pub fn new() -> Self {
        Self {
            minutes: BTreeMap::new(),
            reported_through: i64::MIN,
            day: i64::MIN,
            salt: RandomState::new(),
            seen: HashMap::new(),
        }
    }

    pub fn add(&mut self, site: &str, hit: &Hit) {
        let day = hit.ts.div_euclid(86_400);
        if day > self.day {
            // A new day: a new salt, and everyone is new again.
            self.day = day;
            self.salt = RandomState::new();
            self.seen.clear();
        }
        let visitor = self.salt.hash_one((&hit.ip, &hit.user_agent));
        let seen = self.seen.entry(site.to_string()).or_default();
        let new_visitor = if seen.len() >= MAX_VISITORS {
            !seen.contains(&visitor)
        } else {
            seen.insert(visitor)
        };

        let minute = (hit.ts - hit.ts.rem_euclid(60)).max(self.reported_through);
        let bucket = self.minutes.entry((minute, site.to_string())).or_default();
        bucket.requests += 1;
        if (200..600).contains(&hit.status) {
            bucket.classes[(hit.status / 100 - 2) as usize] += 1;
        }
        bucket.bytes += hit.bytes;
        if let Some(ms) = hit.ms.filter(|ms| ms.is_finite() && *ms >= 0.0) {
            if bucket.timings.len() < MAX_TIMINGS {
                bucket.timings.push(ms);
            }
        }
        if new_visitor {
            bucket.visitors += 1;
        }
        count(&mut bucket.paths, &hit.path);
        if let Some(referrer) = &hit.referrer {
            count(&mut bucket.referrers, referrer);
        }
    }

    /// The minutes that are over by `now` (Unix seconds), rolled up, oldest
    /// first. Each is handed out once.
    pub fn finished(&mut self, now: i64) -> Vec<TrafficRollup> {
        let open = (now - GRACE_SECS) - (now - GRACE_SECS).rem_euclid(60);
        self.reported_through = self.reported_through.max(open);
        let keep = self.minutes.split_off(&(open, String::new()));
        let done = std::mem::replace(&mut self.minutes, keep);
        done.into_iter()
            .map(|((minute, site), mut b)| {
                b.timings.sort_by(f32::total_cmp);
                TrafficRollup {
                    site,
                    minute,
                    requests: b.requests,
                    status_2xx: b.classes[0],
                    status_3xx: b.classes[1],
                    status_4xx: b.classes[2],
                    status_5xx: b.classes[3],
                    bytes: b.bytes,
                    p50_ms: percentile(&b.timings, 50.0),
                    p95_ms: percentile(&b.timings, 95.0),
                    visitors: b.visitors,
                    paths: top(b.paths),
                    referrers: top(b.referrers),
                }
            })
            .collect()
    }

    /// Forgets everything (traffic was turned off).
    pub fn clear(&mut self) {
        self.minutes.clear();
        self.seen.clear();
    }
}

/// What's in a log file, after which it's empty. The proxy appends (every
/// one of them opens its log with O_APPEND), so its next line lands at the
/// start again. Unreadable or missing files read as nothing.
pub fn drain(path: &Path) -> Vec<String> {
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    else {
        return Vec::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if len <= MAX_READ {
        let _ = file.rewind();
        let _ = (&mut file).take(MAX_READ).read_to_end(&mut bytes);
    }
    let _ = file.set_len(0);
    String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::to_string)
        .collect()
}

/// The log files in `dir` and the site each is for: `<site>.log`, and the
/// backups Caddy rolls a full one into (`<site>-<when>.log`). Traefik's one
/// log is listed with no site. Backups are read once, then deleted.
pub fn log_files(dir: &Path) -> Vec<(PathBuf, Option<String>, bool)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<(PathBuf, Option<String>, bool)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_string();
            if name == TRAEFIK_LOG {
                return Some((path, None, false));
            }
            let stem = name.strip_suffix(".log")?;
            if is_site(stem) {
                return Some((path, Some(stem.to_string()), false));
            }
            // Caddy's backups: <site>-2006-01-02T15-04-05.000.log
            let (site, when) = stem.split_at(stem.len().checked_sub(24)?);
            let when = when.strip_prefix('-')?;
            let rolled = when.len() == 23
                && when.as_bytes()[10] == b'T'
                && when
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '-' | 'T' | '.'));
            (rolled && is_site(site)).then(|| (path, Some(site.to_string()), true))
        })
        .collect();
    files.sort();
    files
}

fn is_site(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Reads every log in `dir` into `rollups`, for the given sites (the ones
/// ServerOS serves now), and empties them. Logs of sites that are gone are
/// deleted. Returns how many requests were counted.
pub fn collect(dir: &Path, format: Format, sites: &[String], rollups: &mut Rollups) -> usize {
    let mut counted = 0;
    for (path, site, rolled) in log_files(dir) {
        let known = site.as_ref().map(|s| sites.contains(s));
        if known == Some(false) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let lines = drain(&path);
        if rolled {
            let _ = std::fs::remove_file(&path);
        }
        for line in &lines {
            let Some(hit) = parse_line(format, line) else {
                continue;
            };
            let site = match (&site, &hit.router) {
                (Some(site), _) => Some(site.as_str()),
                (None, Some(router)) => traefik_site(router, sites),
                (None, None) => None,
            };
            if let Some(site) = site {
                rollups.add(site, &hit);
                counted += 1;
            }
        }
    }
    counted
}

#[cfg(test)]
mod tests {
    use super::*;

    const CADDY: &str = r#"{"level":"info","ts":1763640005.512,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"172.17.0.1","remote_port":"51234","client_ip":"203.0.113.9","proto":"HTTP/1.1","method":"GET","host":"shop.acme.io:443","uri":"/pricing?utm=x","headers":{"User-Agent":["curl/8.5.0"],"Referer":["https://www.google.com/search?q=acme"]}},"bytes_read":0,"user_id":"","duration":0.0123,"size":512,"status":200,"resp_headers":{}}"#;

    fn hit(ts: i64, ip: &str, path: &str, status: u16, ms: f32) -> Hit {
        Hit {
            ts,
            host: "acme.io".into(),
            ip: ip.into(),
            user_agent: "curl".into(),
            path: path.into(),
            status,
            bytes: 100,
            ms: Some(ms),
            referrer: None,
            router: None,
        }
    }

    #[test]
    fn caddy_lines_are_read_without_query_strings() {
        let hit = parse_line(Format::Caddy, CADDY).unwrap();
        assert_eq!(hit.ts, 1763640005);
        assert_eq!(hit.host, "shop.acme.io");
        assert_eq!(hit.ip, "203.0.113.9");
        assert_eq!(hit.path, "/pricing");
        assert_eq!(hit.status, 200);
        assert_eq!(hit.bytes, 512);
        assert_eq!(hit.referrer.as_deref(), Some("google.com"));
        assert!((hit.ms.unwrap() - 12.3).abs() < 0.01);
    }

    #[test]
    fn nginx_and_apache_lines_share_one_reader() {
        let nginx = r#"{"t":1763640005.123,"host":"acme.io","ip":"198.51.100.4","uri":"/a?b=1","status":404,"bytes":10,"time":0.250,"referer":"","ua":"Mozilla/5.0 \"quoted\""}"#;
        let hit = parse_line(Format::Line, nginx).unwrap();
        assert_eq!(
            (hit.ts, hit.status, hit.path.as_str()),
            (1763640005, 404, "/a")
        );
        assert_eq!(hit.ms, Some(250.0));
        assert_eq!(hit.referrer, None);
        assert_eq!(hit.user_agent, "Mozilla/5.0 \"quoted\"");

        let apache = r#"{"t":1763640005123,"host":"acme.io:80","ip":"198.51.100.4","uri":"/caf\xc3\xa9","status":503,"bytes":0,"time_us":1500,"referer":"-","ua":"curl\x01"}"#;
        let hit = parse_line(Format::Line, apache).unwrap();
        assert_eq!((hit.ts, hit.status), (1763640005, 503));
        assert_eq!(hit.ms, Some(1.5));
        assert_eq!(hit.host, "acme.io");
        assert_eq!(hit.referrer, None);
        assert!(hit.path.starts_with("/caf"));
    }

    #[test]
    fn traefik_lines_are_counted_by_router() {
        let line = r#"{"ClientHost":"192.0.2.1","DownstreamContentSize":42,"DownstreamStatus":502,"Duration":3000000,"RequestHost":"acme.io","RequestPath":"/x?y","RouterName":"serveros-shop@file","StartUTC":"2026-11-20T12:00:01.5Z","request_Referer":"https://news.ycombinator.com/item?id=1","request_User-Agent":"curl/8","time":"2026-11-20T12:00:02Z"}"#;
        let hit = parse_line(Format::Traefik, line).unwrap();
        assert_eq!(hit.status, 502);
        assert_eq!(hit.ms, Some(3.0));
        assert_eq!(hit.path, "/x");
        assert_eq!(hit.referrer.as_deref(), Some("news.ycombinator.com"));
        assert_eq!(hit.router.as_deref(), Some("serveros-shop@file"));

        let sites = vec!["shop".to_string(), "shop-http".to_string(), "blog".into()];
        assert_eq!(traefik_site("serveros-shop@file", &sites), Some("shop"));
        assert_eq!(
            traefik_site("serveros-blog-wildcard@file", &sites),
            Some("blog")
        );
        assert_eq!(traefik_site("serveros-blog-http@file", &sites), None);
        assert_eq!(traefik_site("dashboard@internal", &sites), None);
        assert!(parse_line(Format::Traefik, r#"{"DownstreamStatus":404}"#).is_none());
    }

    #[test]
    fn referrers_are_hosts_of_other_sites_only() {
        assert_eq!(
            referrer_host("https://user:pw@Sub.Example.com:8443/p?q#f", "acme.io").as_deref(),
            Some("sub.example.com")
        );
        assert_eq!(referrer_host("https://acme.io/pricing", "acme.io"), None);
        assert_eq!(referrer_host("https://www.acme.io/", "acme.io"), None);
        assert_eq!(referrer_host("-", "acme.io"), None);
        assert_eq!(referrer_host("not a url", "acme.io"), None);
        assert_eq!(referrer_host("https://ev<il>.io/", "acme.io"), None);
    }

    #[test]
    fn rubbish_is_skipped() {
        for line in ["", "hello", "{", r#"{"t":1}"#, r#"{"request":{}}"#] {
            assert!(parse_line(Format::Caddy, line).is_none(), "{line}");
            assert!(parse_line(Format::Line, line).is_none(), "{line}");
        }
    }

    #[test]
    fn a_minute_is_reported_once_when_it_is_over() {
        let mut rollups = Rollups::new();
        let minute = 1763640000;
        rollups.add("shop", &hit(minute + 1, "a", "/", 200, 10.0));
        rollups.add("shop", &hit(minute + 20, "a", "/", 200, 20.0));
        rollups.add("shop", &hit(minute + 30, "b", "/pricing", 404, 30.0));
        rollups.add("shop", &hit(minute + 59, "c", "/", 503, 400.0));
        rollups.add("blog", &hit(minute + 61, "a", "/", 301, 5.0));

        assert!(rollups.finished(minute + 62).is_empty());
        let done = rollups.finished(minute + 66);
        assert_eq!(done.len(), 1);
        let shop = &done[0];
        assert_eq!((shop.site.as_str(), shop.minute), ("shop", minute));
        assert_eq!(shop.requests, 4);
        assert_eq!(
            [
                shop.status_2xx,
                shop.status_3xx,
                shop.status_4xx,
                shop.status_5xx
            ],
            [2, 0, 1, 1]
        );
        assert_eq!(shop.bytes, 400);
        assert_eq!(shop.visitors, 3);
        assert_eq!(shop.p50_ms, Some(20.0));
        assert_eq!(shop.p95_ms, Some(400.0));
        assert_eq!(
            shop.paths,
            vec![("/".to_string(), 3), ("/pricing".to_string(), 1)]
        );

        // A line for a minute already reported goes in the next one.
        rollups.add("shop", &hit(minute + 2, "d", "/late", 200, 1.0));
        let later = rollups.finished(minute + 200);
        assert_eq!(later.len(), 2);
        assert!(later.iter().all(|r| r.minute == minute + 60));
        assert!(rollups.finished(minute + 400).is_empty());
    }

    #[test]
    fn visitors_are_new_once_a_day() {
        let mut rollups = Rollups::new();
        let day = 1763596800;
        rollups.add("shop", &hit(day + 10, "a", "/", 200, 1.0));
        rollups.add("shop", &hit(day + 70, "a", "/", 200, 1.0));
        rollups.add("blog", &hit(day + 70, "a", "/", 200, 1.0));
        rollups.add("shop", &hit(day + 86_400 + 5, "a", "/", 200, 1.0));
        let all = rollups.finished(day + 86_400 + 100);
        let visitors: Vec<(String, i64, u64)> = all
            .iter()
            .map(|r| (r.site.clone(), r.minute - day, r.visitors))
            .collect();
        assert_eq!(
            visitors,
            vec![
                ("shop".to_string(), 0, 1),
                ("blog".to_string(), 60, 1),
                ("shop".to_string(), 60, 0),
                ("shop".to_string(), 86_400, 1),
            ]
        );
    }

    #[test]
    fn the_top_ten_are_named() {
        let mut rollups = Rollups::new();
        for i in 0..30u32 {
            for _ in 0..=i {
                rollups.add("shop", &hit(1763640000, "a", &format!("/p{i}"), 200, 1.0));
            }
        }
        let done = rollups.finished(1763640100);
        assert_eq!(done[0].paths.len(), TOP);
        assert_eq!(done[0].paths[0], ("/p29".to_string(), 30));
        assert_eq!(done[0].requests, 465);
    }

    #[test]
    fn a_rollup_carries_no_address_or_user_agent() {
        let mut rollups = Rollups::new();
        let mut h = hit(1763640000, "203.0.113.77", "/", 200, 1.0);
        h.user_agent = "SecretAgent/1.0".into();
        h.referrer = Some("example.org".into());
        rollups.add("shop", &h);
        let json = serde_json::to_string(&rollups.finished(1763640100)).unwrap();
        assert!(!json.contains("203.0.113"));
        assert!(!json.contains("SecretAgent"));
        assert!(json.contains("example.org"));
    }

    #[test]
    fn logs_are_emptied_as_they_are_read_and_old_ones_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"t":1763640005.1,"host":"acme.io","ip":"1.2.3.4","uri":"/","status":200,"bytes":1,"time":0.001,"referer":"","ua":"x"}"#;
        std::fs::write(
            dir.path().join("shop.log"),
            format!("{line}\n{line}\nnoise\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join("gone.log"), format!("{line}\n")).unwrap();
        std::fs::write(
            dir.path().join("shop-2026-11-20T12-00-00.000.log"),
            format!("{line}\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "keep").unwrap();

        let mut rollups = Rollups::new();
        let sites = vec!["shop".to_string()];
        assert_eq!(collect(dir.path(), Format::Line, &sites, &mut rollups), 3);
        assert_eq!(
            std::fs::metadata(dir.path().join("shop.log"))
                .unwrap()
                .len(),
            0
        );
        assert!(!dir.path().join("gone.log").exists());
        assert!(!dir.path().join("shop-2026-11-20T12-00-00.000.log").exists());
        assert!(dir.path().join("notes.txt").exists());
        assert_eq!(collect(dir.path(), Format::Line, &sites, &mut rollups), 0);
        assert_eq!(rollups.finished(1763640100)[0].requests, 3);
    }

    /// Reads access logs the real proxies wrote (caddy.log, nginx.log,
    /// apache.log, traefik.access.log in $SERVEROS_TRAFFIC_LOGS), each from
    /// the same five requests to site "shop", and checks every line counts.
    #[test]
    #[ignore]
    fn reads_what_the_real_proxies_write() {
        let Ok(dir) = std::env::var("SERVEROS_TRAFFIC_LOGS") else {
            return;
        };
        let dir = PathBuf::from(dir);
        for (file, format) in [
            ("caddy.log", Format::Caddy),
            ("nginx.log", Format::Line),
            ("apache.log", Format::Line),
            (TRAEFIK_LOG, Format::Traefik),
        ] {
            let Ok(text) = std::fs::read_to_string(dir.join(file)) else {
                continue;
            };
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            let hits: Vec<Hit> = lines
                .iter()
                .filter_map(|line| parse_line(format, line))
                .collect();
            assert_eq!(hits.len(), lines.len(), "{file}: some lines didn't read");
            let mut rollups = Rollups::new();
            let sites = vec!["shop".to_string()];
            for hit in &hits {
                let site = match &hit.router {
                    Some(router) => traefik_site(router, &sites),
                    None => Some("shop"),
                };
                if let Some(site) = site {
                    rollups.add(site, hit);
                }
            }
            let done = rollups.finished(i64::MAX / 2);
            let total = |f: fn(&TrafficRollup) -> u64| done.iter().map(f).sum::<u64>();
            println!("{file}: {}", serde_json::to_string(&done).unwrap());
            assert_eq!(total(|r| r.requests), 5, "{file}");
            assert_eq!(total(|r| r.status_2xx), 3, "{file}");
            assert_eq!(total(|r| r.status_4xx), 1, "{file}");
            assert_eq!(total(|r| r.status_5xx), 1, "{file}");
            assert_eq!(total(|r| r.visitors), 2, "{file}");
            assert!(total(|r| r.bytes) > 0, "{file}");
            assert!(done.iter().all(|r| r.p95_ms.is_some()), "{file}");
            let paths: Vec<&str> = done
                .iter()
                .flat_map(|r| r.paths.iter().map(|(p, _)| p.as_str()))
                .collect();
            assert!(paths.contains(&"/pricing"), "{file}: {paths:?}");
            assert!(!paths.iter().any(|p| p.contains('?')), "{file}");
            let referrers: Vec<&str> = done
                .iter()
                .flat_map(|r| r.referrers.iter().map(|(p, _)| p.as_str()))
                .collect();
            assert_eq!(referrers, vec!["google.com"], "{file}");
            let json = serde_json::to_string(&done).unwrap();
            assert!(!json.contains("Weird") && !json.contains("curl"), "{file}");
        }
    }

    #[test]
    fn traefik_gets_one_access_log_section() {
        let file = Path::new("/var/log/serveros-traffic/traefik.access.log");
        let config = "[entryPoints.web]\n  address = \":80\"\n";
        let on = with_traefik_access_log(config, file, true).unwrap();
        assert!(on.contains("[accessLog]\n  filePath = \"/var/log/serveros-traffic/traefik.access.log\"\n  format = \"json\""));
        assert!(on.contains("\"User-Agent\" = \"keep\""));
        assert!(with_traefik_access_log(&on, file, true).is_none());
        assert_eq!(with_traefik_access_log(&on, file, false).unwrap(), config);
        assert!(with_traefik_access_log(config, file, false).is_none());
    }
}
