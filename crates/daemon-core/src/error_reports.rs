//! Crash and error reports, sent to ServerOS's Sentry so we hear about
//! bugs before customers have to tell us.
//!
//! - The address (DSN) is baked in at build time from `SERVEROS_SENTRY_DSN`,
//!   so only our release builds report. `[error_reports] dsn` in
//!   `daemon.toml` or the `SERVEROS_SENTRY_DSN` environment variable points
//!   them somewhere else.
//! - `[error_reports] enabled = false` or `SERVEROS_ERROR_REPORTS=0` turns
//!   them off: Sentry is then never started at all.
//! - Panics and `error!` events are reported; warnings ride along as
//!   breadcrumbs. Everything is scrubbed before it leaves the machine: no
//!   hostname, user or request data, secrets and env values redacted, IP
//!   addresses replaced, no source lines or file contents.
//! - Reports go out through `daemon-http`, the same rustls client the
//!   daemon already uses, on a thread of their own.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use sentry::protocol::{Breadcrumb, Context, Event, Frame, Level, Map, Value};
use sentry::types::Dsn;
use sentry::{Envelope, Transport, TransportFactory, TransportOptions};

use crate::config::ErrorReportsConfig;
use crate::ipmask::{self, IpMasking};
use crate::redact::{self, REDACTED};

/// Turns reports off when set to `0`, `false`, `off` or `no`.
pub const ENV_SWITCH: &str = "SERVEROS_ERROR_REPORTS";
/// Sends reports to this DSN instead of the built-in one.
pub const ENV_DSN: &str = "SERVEROS_SENTRY_DSN";
/// Only set in our release builds.
pub const BUILT_IN_DSN: Option<&str> = option_env!("SERVEROS_SENTRY_DSN");

/// At most this many error events an hour from one process, so one
/// machine stuck in a loop can't use up the quota. Panics always go.
const EVENTS_PER_HOUR: u32 = 30;
/// Envelopes waiting to be sent; more than this are dropped.
const QUEUE_LIMIT: usize = 30;

/// Where reports would go, or why they won't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    On { dsn: String },
    TurnedOff(&'static str),
    NoDsn,
}

/// What `daemon.toml` says, read leniently: a missing file means the
/// defaults (not enrolled yet), but a file that's there and can't be read
/// or parsed counts as "off", since it may be the one that turned them off.
#[derive(Debug, Clone, Default)]
pub struct FileSettings {
    pub reports: Option<ErrorReportsConfig>,
    pub machine_id: Option<String>,
    unreadable: bool,
}

impl FileSettings {
    pub fn read(path: &Path) -> Self {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(_) => return Self::unreadable(),
        };
        let Ok(doc) = toml::from_str::<toml::Table>(&raw) else {
            return Self::unreadable();
        };
        let reports = match doc.get("error_reports") {
            None => None,
            Some(value) => match value.clone().try_into::<ErrorReportsConfig>() {
                Ok(reports) => Some(reports),
                Err(_) => return Self::unreadable(),
            },
        };
        let machine_id = doc
            .get("machine")
            .and_then(|m| m.get("id"))
            .and_then(|id| id.as_str())
            .map(str::to_string)
            .filter(|id| !id.trim().is_empty());

        Self {
            reports,
            machine_id,
            unreadable: false,
        }
    }

    fn unreadable() -> Self {
        Self {
            unreadable: true,
            ..Self::default()
        }
    }
}

/// Decides from the environment, the config file and the build.
pub fn decide(file: &FileSettings) -> Decision {
    decide_with(
        std::env::var(ENV_SWITCH).ok().as_deref(),
        std::env::var(ENV_DSN).ok().as_deref(),
        file,
        BUILT_IN_DSN,
    )
}

fn decide_with(
    switch: Option<&str>,
    env_dsn: Option<&str>,
    file: &FileSettings,
    built_in: Option<&str>,
) -> Decision {
    if let Some(value) = switch {
        if matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ) {
            return Decision::TurnedOff("SERVEROS_ERROR_REPORTS is off");
        }
    }
    if file.unreadable {
        return Decision::TurnedOff("daemon.toml could not be read");
    }
    let config = file.reports.clone().unwrap_or_default();
    if !config.enabled {
        return Decision::TurnedOff("error_reports.enabled is false in daemon.toml");
    }

    let found = [env_dsn, config.dsn.as_deref(), built_in]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|dsn| !dsn.is_empty())
        .map(|dsn| Decision::On {
            dsn: dsn.to_string(),
        });
    found.unwrap_or(Decision::NoDsn)
}

/// Keeps reports flowing while it lives; dropping it sends what's queued.
pub struct Guard(Option<sentry::ClientInitGuard>);

impl Guard {
    pub fn is_on(&self) -> bool {
        self.0.is_some()
    }
}

/// Starts reporting for `program` (`serverosd`, `serveros-gateway`) when
/// the decision is on; does nothing at all otherwise.
pub fn init(program: &str, version: &str, decision: &Decision, tags: &[(&str, &str)]) -> Guard {
    let Decision::On { dsn } = decision else {
        return Guard(None);
    };
    let Ok(dsn) = Dsn::from_str(dsn) else {
        return Guard(None);
    };

    let mut options = sentry::ClientOptions::default();
    options.dsn = Some(dsn);
    options.release = Some(format!("{program}@{version}").into());
    options.environment = Some(environment().into());
    options.send_default_pii = false;
    options.attach_stacktrace = false;
    options.max_breadcrumbs = 30;
    options.user_agent = format!("{program}/{version}").into();
    options.before_send = Some(Arc::new(|event| {
        if !within_budget(&event) {
            return None;
        }
        Some(scrub_event(event))
    }));
    options.before_breadcrumb = Some(Arc::new(|crumb| Some(scrub_breadcrumb(crumb, None))));
    options.transport = Some(Arc::new(HttpTransportFactory));

    let guard = sentry::init(options);
    sentry::configure_scope(|scope| {
        for (key, value) in tags {
            scope.set_tag(key, value);
        }
    });

    Guard(Some(guard))
}

pub fn environment() -> &'static str {
    if cfg!(debug_assertions) {
        "development"
    } else {
        "production"
    }
}

/// Reports one error-level event, scrubbed like the rest. Returns its id.
pub fn capture_error(message: &str) -> String {
    sentry::capture_message(message, Level::Error).to_string()
}

/// Whether reports were started in this process.
pub fn is_on() -> bool {
    sentry::Hub::current()
        .client()
        .is_some_and(|c| c.is_enabled())
}

/// Sends whatever is queued, waiting up to `timeout`. Call before
/// `std::process::exit`, which skips the guard's own flush.
pub fn flush(timeout: Duration) -> bool {
    match sentry::Hub::current().client() {
        Some(client) => client.flush(Some(timeout)),
        None => true,
    }
}

/// Error events become reports and warnings become breadcrumbs on them.
/// Add it to the tracing subscriber when reports are on.
pub fn tracing_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use sentry::integrations::tracing::{BreadcrumbLayer, ErrorLayer};
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::Layer;

    ErrorLayer::new()
        .with_filter(LevelFilter::ERROR)
        .and_then(BreadcrumbLayer::new().with_filter(LevelFilter::WARN))
}

/// How the last report went, for `serverosd debug sentry-test`.
pub fn last_delivery() -> Option<String> {
    LAST_DELIVERY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

static LAST_DELIVERY: Mutex<Option<String>> = Mutex::new(None);

fn within_budget(event: &Event<'static>) -> bool {
    static WINDOW: Mutex<Option<(Instant, u32)>> = Mutex::new(None);

    if event.level == Level::Fatal {
        return true;
    }
    let mut window = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    match window.as_mut() {
        Some((start, count)) if now.duration_since(*start) < Duration::from_secs(3600) => {
            *count += 1;
            *count <= EVENTS_PER_HOUR
        }
        _ => {
            *window = Some((now, 1));
            true
        }
    }
}

// --- Scrubbing -------------------------------------------------------------

/// Tags we set ourselves; they hold ids, not customer data.
const OUR_TAGS: &[&str] = &["machine", "commit", "channel", "target"];

static URL_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<scheme>\b[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s@]+@").expect("pattern compiles")
});
static ENV_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?P<key>[A-Z][A-Z0-9_]+)=(?P<value>[^\s'"]+)"#).expect("pattern compiles")
});
static OPAQUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9_\-]{24,}").expect("pattern compiles"));
static SENSITIVE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)secret|token|passw|key|dsn|auth|cookie|credential|session|env|host")
        .expect("pattern compiles")
});

/// A per-process salt, so masked addresses are the same within one report
/// but can't be matched to anything outside it.
static IP_SALT: LazyLock<Vec<u8>> = LazyLock::new(|| {
    use std::io::Read;
    let mut salt = vec![0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut salt))
        .is_err()
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        salt = format!("{nanos}{}", std::process::id()).into_bytes();
    }
    salt
});

static HOSTNAME: LazyLock<Option<String>> = LazyLock::new(|| {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|name| name.trim().to_string())
        .filter(|name| name.len() >= 3)
});

/// Text as it may leave the machine.
pub fn scrub_text(text: &str, host: Option<&str>) -> String {
    let mut out = redact::redact(text);
    out = URL_USERINFO
        .replace_all(&out, format!("${{scheme}}{REDACTED}@"))
        .into_owned();
    out = ENV_ASSIGNMENT
        .replace_all(&out, format!("${{key}}={REDACTED}"))
        .into_owned();
    out = OPAQUE
        .replace_all(&out, |caps: &regex::Captures| {
            let token = &caps[0];
            let digits = token.bytes().any(|b| b.is_ascii_digit());
            let letters = token.bytes().any(|b| b.is_ascii_alphabetic());
            if digits && letters {
                REDACTED.to_string()
            } else {
                token.to_string()
            }
        })
        .into_owned();
    for name in [host, HOSTNAME.as_deref()].into_iter().flatten() {
        if name.len() >= 3 {
            out = out.replace(name, "[host]");
        }
    }
    ipmask::mask(&out, IpMasking::Hash, &IP_SALT).into_owned()
}

fn scrub_value(key: Option<&str>, value: &mut Value, host: Option<&str>) {
    if key.is_some_and(|k| SENSITIVE_KEY.is_match(k)) {
        *value = Value::String(REDACTED.into());
        return;
    }
    match value {
        Value::String(s) => *s = scrub_text(s, host),
        Value::Array(items) => items.iter_mut().for_each(|v| scrub_value(None, v, host)),
        Value::Object(map) => map
            .iter_mut()
            .for_each(|(k, v)| scrub_value(Some(k), v, host)),
        _ => {}
    }
}

fn scrub_map(map: &mut Map<String, Value>, host: Option<&str>) {
    for (key, value) in map.iter_mut() {
        scrub_value(Some(key), value, host);
    }
}

fn scrub_frames(frames: &mut [Frame]) {
    for frame in frames {
        frame.pre_context.clear();
        frame.context_line = None;
        frame.post_context.clear();
        frame.vars.clear();
    }
}

fn scrub_breadcrumb(mut crumb: Breadcrumb, host: Option<&str>) -> Breadcrumb {
    crumb.message = crumb.message.map(|m| scrub_text(&m, host));
    scrub_map(&mut crumb.data, host);
    crumb
}

pub fn scrub_event(mut event: Event<'static>) -> Event<'static> {
    // The hostname Sentry picked up, used to scrub it from the text too.
    let host = event.server_name.take().map(|h| h.into_owned());
    let host = host.as_deref();

    event.user = None;
    event.request = None;
    event.modules.clear();
    event.message = event.message.map(|m| scrub_text(&m, host));
    event.culprit = event.culprit.map(|c| scrub_text(&c, host));
    event.transaction = event.transaction.map(|t| scrub_text(&t, host));
    if let Some(entry) = event.logentry.as_mut() {
        entry.message = scrub_text(&entry.message, host);
        entry
            .params
            .iter_mut()
            .for_each(|p| scrub_value(None, p, host));
    }
    for exception in event.exception.values.iter_mut() {
        exception.value = exception.value.take().map(|v| scrub_text(&v, host));
        if let Some(trace) = exception.stacktrace.as_mut() {
            scrub_frames(&mut trace.frames);
        }
    }
    if let Some(trace) = event.stacktrace.as_mut() {
        scrub_frames(&mut trace.frames);
    }
    for thread in event.threads.values.iter_mut() {
        thread.name = thread.name.take().map(|n| scrub_text(&n, host));
        if let Some(trace) = thread.stacktrace.as_mut() {
            scrub_frames(&mut trace.frames);
        }
    }
    let crumbs = std::mem::take(&mut event.breadcrumbs.values);
    event.breadcrumbs.values = crumbs
        .into_iter()
        .map(|crumb| scrub_breadcrumb(crumb, host))
        .collect();
    scrub_map(&mut event.extra, host);
    for (key, value) in event.tags.iter_mut() {
        if !OUR_TAGS.contains(&key.as_str()) {
            *value = if SENSITIVE_KEY.is_match(key) {
                REDACTED.into()
            } else {
                scrub_text(value, host)
            };
        }
    }
    for context in event.contexts.values_mut() {
        if let Context::Other(map) = context {
            scrub_map(map, host);
        }
    }

    event
}

// --- Transport -------------------------------------------------------------

struct HttpTransportFactory;

impl TransportFactory for HttpTransportFactory {
    fn create_transport_with_options(&self, options: TransportOptions) -> Arc<dyn Transport> {
        Arc::new(HttpTransport::spawn(
            options.dsn,
            options.user_agent.into_owned(),
        ))
    }
}

enum Job {
    Send(Vec<u8>),
    Flush(mpsc::SyncSender<()>),
}

struct HttpTransport {
    queue: Mutex<Option<mpsc::Sender<Job>>>,
    pending: Arc<AtomicUsize>,
}

impl HttpTransport {
    fn spawn(dsn: Dsn, user_agent: String) -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        let pending = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&pending);

        let started = std::thread::Builder::new()
            .name("error-reports".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                let client =
                    daemon_http::Client::new(daemon_http::Trust::WebPki, user_agent.clone())
                        .with_timeout(Duration::from_secs(10))
                        .with_max_body(64 * 1024);
                let url = dsn.envelope_api_url().to_string();

                while let Ok(job) = rx.recv() {
                    match job {
                        Job::Send(body) => {
                            let auth = dsn.to_auth(Some(&user_agent)).to_string();
                            let headers = [
                                ("X-Sentry-Auth", auth.as_str()),
                                ("Content-Type", "application/x-sentry-envelope"),
                            ];
                            let outcome = match rt.block_on(client.post(&url, &headers, &body)) {
                                Ok(response) => format!("HTTP {}", response.status),
                                Err(e) => e.to_string(),
                            };
                            *LAST_DELIVERY.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(outcome);
                            counter.fetch_sub(1, Ordering::SeqCst);
                        }
                        Job::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            });

        Self {
            queue: Mutex::new(started.ok().map(|_| tx)),
            pending,
        }
    }

    fn sender(&self) -> Option<mpsc::Sender<Job>> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Transport for HttpTransport {
    fn send_envelope(&self, envelope: Envelope) {
        // We never attach files; refuse anything that tries to.
        if envelope
            .items()
            .any(|item| matches!(item, sentry::protocol::EnvelopeItem::Attachment(_)))
        {
            return;
        }
        let Some(queue) = self.sender() else {
            return;
        };
        if self.pending.load(Ordering::SeqCst) >= QUEUE_LIMIT {
            return;
        }
        let mut body = Vec::new();
        if envelope.to_writer(&mut body).is_err() {
            return;
        }
        self.pending.fetch_add(1, Ordering::SeqCst);
        if queue.send(Job::Send(body)).is_err() {
            self.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn flush(&self, timeout: Duration) -> bool {
        let Some(queue) = self.sender() else {
            return true;
        };
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        if queue.send(Job::Flush(done_tx)).is_err() {
            return false;
        }
        done_rx.recv_timeout(timeout).is_ok()
    }

    fn shutdown(&self, timeout: Duration) -> bool {
        let flushed = self.flush(timeout);
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).take();
        flushed
    }
}

/// Tags for a daemon's reports: its build, and the opaque machine id the
/// panel issued at enrolment (never a hostname or an address).
pub fn daemon_tags(machine_id: Option<&str>) -> BTreeMap<&'static str, String> {
    let build = crate::BuildInfo::current();
    let mut tags = BTreeMap::new();
    tags.insert("commit", build.commit.to_string());
    tags.insert("channel", build.channel.to_string());
    tags.insert("target", build.target.to_string());
    if let Some(id) = machine_id {
        tags.insert("machine", id.to_string());
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(reports: Option<ErrorReportsConfig>) -> FileSettings {
        FileSettings {
            reports,
            ..FileSettings::default()
        }
    }

    const DSN: &str = "https://public@o1.ingest.sentry.io/1";

    #[test]
    fn off_switches_win_and_no_dsn_means_off() {
        assert_eq!(
            decide_with(Some("0"), None, &file(None), Some(DSN)),
            Decision::TurnedOff("SERVEROS_ERROR_REPORTS is off")
        );
        assert!(matches!(
            decide_with(
                None,
                Some(DSN),
                &file(Some(ErrorReportsConfig {
                    enabled: false,
                    dsn: None
                })),
                Some(DSN)
            ),
            Decision::TurnedOff(_)
        ));
        assert!(matches!(
            decide_with(None, None, &FileSettings::unreadable(), Some(DSN)),
            Decision::TurnedOff(_)
        ));
        assert_eq!(decide_with(None, None, &file(None), None), Decision::NoDsn);
        assert_eq!(
            decide_with(Some("1"), Some(""), &file(None), None),
            Decision::NoDsn
        );
    }

    #[test]
    fn env_beats_config_beats_build() {
        let config = Some(ErrorReportsConfig {
            enabled: true,
            dsn: Some("https://cfg@x/2".into()),
        });
        let on = |dsn: &str| Decision::On { dsn: dsn.into() };

        assert_eq!(
            decide_with(
                None,
                Some("https://env@x/3"),
                &file(config.clone()),
                Some(DSN)
            ),
            on("https://env@x/3")
        );
        assert_eq!(
            decide_with(None, None, &file(config), Some(DSN)),
            on("https://cfg@x/2")
        );
        assert_eq!(decide_with(None, None, &file(None), Some(DSN)), on(DSN));
    }

    #[test]
    fn reads_the_config_file_leniently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.toml");
        assert!(!FileSettings::read(&path).unreadable);

        std::fs::write(
            &path,
            "version = 1\n[machine]\nid = \"mch_9\"\n[error_reports]\nenabled = false\n",
        )
        .unwrap();
        let settings = FileSettings::read(&path);
        assert_eq!(settings.machine_id.as_deref(), Some("mch_9"));
        assert!(!settings.reports.unwrap().enabled);

        std::fs::write(&path, "[error_reports]\nenabld = false\n").unwrap();
        assert!(FileSettings::read(&path).unreadable);
    }

    #[test]
    fn scrubs_secrets_hosts_and_addresses() {
        let text = scrub_text(
            "connect to https://abc123@o1.ingest.sentry.io/5 from 203.0.113.9 on web-01 \
             with DATABASE_URL=postgres://u:p@db/x APP_KEY=base64:zzz token ghp_abcdefghijklmnopqrstuvwxyz123456 \
             and 3f9a1c2e4b5d6e7f8a9b0c1d2e3f4a5b",
            Some("web-01"),
        );

        assert!(!text.contains("abc123"), "{text}");
        assert!(!text.contains("203.0.113.9"), "{text}");
        assert!(!text.contains("web-01"), "{text}");
        assert!(!text.contains("postgres://"), "{text}");
        assert!(!text.contains("zzz"), "{text}");
        assert!(!text.contains("ghp_"), "{text}");
        assert!(!text.contains("3f9a1c2e4b5d"), "{text}");
        assert!(text.contains("[host]"), "{text}");
    }

    #[test]
    fn keeps_ordinary_messages_readable() {
        let text = scrub_text(
            "called `Option::unwrap()` on a `None` value at crates/daemon-jobs/src/runner.rs:42",
            None,
        );
        assert_eq!(
            text,
            "called `Option::unwrap()` on a `None` value at crates/daemon-jobs/src/runner.rs:42"
        );
    }

    #[test]
    fn strips_identity_and_sensitive_fields_from_events() {
        let mut event = Event {
            server_name: Some("box.example.com".into()),
            message: Some("failed on box.example.com".into()),
            user: Some(sentry::User {
                username: Some("root".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        event.extra.insert("api_token".into(), "abc".into());
        event
            .extra
            .insert("path".into(), "/srv/app 10.1.2.3".into());
        event.tags.insert("machine".into(), "mch_1".into());
        event.breadcrumbs.values.push(Breadcrumb {
            message: Some("PASSWORD=hunter22".into()),
            ..Default::default()
        });
        let mut fields = Map::new();
        fields.insert("secret".into(), "s".into());
        event
            .contexts
            .insert("Rust Tracing Fields".into(), Context::Other(fields));

        let event = scrub_event(event);

        assert!(event.server_name.is_none());
        assert!(event.user.is_none());
        assert_eq!(event.message.as_deref(), Some("failed on [host]"));
        assert_eq!(event.extra["api_token"], Value::from(REDACTED));
        assert!(!event.extra["path"].as_str().unwrap().contains("10.1.2.3"));
        assert_eq!(event.tags["machine"], "mch_1");
        assert_eq!(
            event.breadcrumbs.values[0].message.as_deref(),
            Some("PASSWORD=[redacted]")
        );
        match &event.contexts["Rust Tracing Fields"] {
            Context::Other(map) => assert_eq!(map["secret"], Value::from(REDACTED)),
            other => panic!("unexpected context {other:?}"),
        }
    }
}
