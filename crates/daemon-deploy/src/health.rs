use std::time::{Duration, Instant};

use daemon_jobs::{Failure, Progress};
use daemon_protocol::HealthCheck;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

/// The check a release that answers HTTP gets when it has none of its own
/// (releases recorded before their check was kept): its home page, as
/// before.
pub fn default_check() -> HealthCheck {
    HealthCheck {
        path: "/".into(),
        expected_status: 200,
        timeout_secs: 30,
        retries: 5,
        start_period_secs: 0,
        interval_secs: None,
    }
}

/// Where a release is asked for its health page.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// The port on 127.0.0.1 Docker publishes the app on.
    pub host_port: u16,
    /// The port the app listens on in its container, for what's said when
    /// nothing answers. The host port when it isn't known.
    pub container_port: Option<u16>,
    /// The app's domains: the first that isn't a wildcard is sent as the
    /// Host, so apps that only answer their own names (Django's
    /// ALLOWED_HOSTS, say) answer the check too.
    pub domains: &'a [String],
}

impl Target<'_> {
    fn app_port(&self) -> u16 {
        self.container_port.unwrap_or(self.host_port)
    }

    fn host(&self) -> &str {
        self.domains
            .iter()
            .map(String::as_str)
            .find(|d| !d.is_empty() && !crate::proxy::is_wildcard(d))
            .unwrap_or("localhost")
    }
}

/// What one try found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Healthy(u16),
    /// An answer that isn't the one expected.
    Status(u16),
    /// Nothing took the connection, or it was closed before any answer:
    /// with Docker's proxy in front, an app that isn't listening looks
    /// like the second.
    Refused,
    TimedOut,
    NotHttp,
}

/// Waits for a new release to answer its health check. During the start
/// period it's asked every interval and failures don't count; then it has
/// `retries` tries, an interval apart (or 2, 4, 8 then 16 seconds when no
/// interval is set). The failure says what the last try found, in words
/// that point at the fix.
pub async fn wait_healthy(
    target: Target<'_>,
    check: Option<&HealthCheck>,
    cancel: &mut watch::Receiver<bool>,
    log: &Progress,
) -> Result<(), Failure> {
    let default = default_check();
    let check = check.unwrap_or(&default);
    let path = request_path(&check.path)?;
    let per_try = Duration::from_secs(check.timeout_secs.max(1));
    let start_period = Duration::from_secs(check.start_period_secs);
    let started = Instant::now();
    let mut last = Probe::Refused;

    log.line(format!(
        "checking {path} on port {} (as {}){}",
        target.app_port(),
        target.host(),
        if start_period.is_zero() {
            String::new()
        } else {
            format!(", giving it {} seconds to start", start_period.as_secs())
        }
    ))
    .await;

    // The start period: tries that fail don't count.
    while started.elapsed() < start_period {
        last = probe(target, &path, check.expected_status, per_try).await;
        if let Probe::Healthy(status) = last {
            log.line(format!(
                "health check passed after {}s (HTTP {status})",
                started.elapsed().as_secs()
            ))
            .await;
            return Ok(());
        }
        log.line(format!(
            "still starting ({}s of {}s): {}",
            started.elapsed().as_secs(),
            start_period.as_secs(),
            describe(&last, target, &path, check)
        ))
        .await;
        let left = start_period.saturating_sub(started.elapsed());
        pause(interval(check, 0).min(left), cancel).await?;
    }

    let retries = check.retries.max(1);
    for attempt in 1..=retries {
        last = probe(target, &path, check.expected_status, per_try).await;
        if let Probe::Healthy(status) = last {
            log.line(format!(
                "health check passed on attempt {attempt} (HTTP {status})"
            ))
            .await;
            return Ok(());
        }
        log.line(format!(
            "health check attempt {attempt}/{retries}: {}",
            describe(&last, target, &path, check)
        ))
        .await;
        if attempt < retries {
            pause(interval(check, attempt), cancel).await?;
        }
    }

    Err(failure(&last, target, &path, check))
}

/// The time to wait after a failed try: the check's interval, or the old
/// backoff when it has none (2 seconds in the start period).
fn interval(check: &HealthCheck, attempt: u32) -> Duration {
    match check.interval_secs {
        Some(secs) => Duration::from_secs(secs.max(1)),
        None if attempt == 0 => Duration::from_secs(2),
        None => Duration::from_secs(2u64.pow(attempt.min(4))),
    }
}

async fn pause(wait: Duration, cancel: &mut watch::Receiver<bool>) -> Result<(), Failure> {
    if *cancel.borrow() {
        return Err(Failure::new("cancelled", "health check cancelled"));
    }
    tokio::select! {
        _ = tokio::time::sleep(wait) => Ok(()),
        changed = cancel.changed() => match changed {
            Ok(()) if *cancel.borrow() => Err(Failure::new("cancelled", "health check cancelled")),
            // The sender is gone or it changed back: wait out the rest.
            _ => {
                tokio::time::sleep(wait).await;
                Ok(())
            }
        },
    }
}

/// The path to ask for, always starting with `/`, and only characters a
/// request line can carry.
fn request_path(path: &str) -> Result<String, Failure> {
    let path = path.trim();
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Failure::new(
            "health",
            format!("{path:?} isn't a path the health check can ask for"),
        )
        .with_next_step("Set the health check path to a page like /up or /health."));
    }
    Ok(if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    })
}

fn expected_words(expected: u16) -> String {
    match expected {
        0 => "any answer below 500".into(),
        200 => "HTTP 200 (or a redirect)".into(),
        status => format!("HTTP {status}"),
    }
}

/// One try's result, for the log.
fn describe(probe: &Probe, target: Target<'_>, path: &str, check: &HealthCheck) -> String {
    let port = target.app_port();
    match probe {
        Probe::Healthy(status) => format!("{path} answered HTTP {status}"),
        Probe::Status(status) => format!(
            "{path} answered HTTP {status}, expected {}",
            expected_words(check.expected_status)
        ),
        Probe::Refused => format!("nothing is accepting connections on port {port}"),
        Probe::TimedOut => format!(
            "no answer from {path} within {} seconds",
            check.timeout_secs.max(1)
        ),
        Probe::NotHttp => format!("port {port} answered, but not with HTTP"),
    }
}

fn failure(probe: &Probe, target: Target<'_>, path: &str, check: &HealthCheck) -> Failure {
    let port = target.app_port();
    let what = describe(probe, target, path, check);
    let next = match probe {
        Probe::Refused => format!(
            "Make sure the app listens on 0.0.0.0 (not localhost or 127.0.0.1) and on port {port}. It can read the port from the PORT variable."
        ),
        Probe::TimedOut => "Check the app isn't stuck while starting, or give it a longer start period in the health check.".into(),
        Probe::Status(status) if *status >= 500 => {
            "The app is up but failing: its logs say why.".into()
        }
        Probe::Status(_) => format!(
            "Point the health check at a page that answers {}, or set the expected status to 0 to accept any answer below 500.",
            expected_words(check.expected_status)
        ),
        Probe::NotHttp => format!(
            "Check that port {port} is the app's web port, not a database's or an HTTPS one."
        ),
        Probe::Healthy(_) => String::new(),
    };
    Failure::new("health", format!("the health check failed: {what}")).with_next_step(next)
}

/// One try: connect, ask for the page, read the status line.
pub async fn probe(target: Target<'_>, path: &str, expected: u16, per_try: Duration) -> Probe {
    match tokio::time::timeout(per_try, ask(target, path)).await {
        Ok(Ok(status)) if is_healthy(status, expected) => Probe::Healthy(status),
        Ok(Ok(status)) => Probe::Status(status),
        Ok(Err(probe)) => probe,
        Err(_) => Probe::TimedOut,
    }
}

async fn ask(target: Target<'_>, path: &str) -> Result<u16, Probe> {
    let mut stream = TcpStream::connect(("127.0.0.1", target.host_port))
        .await
        .map_err(|_| Probe::Refused)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: serverosd-health\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.host()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| Probe::Refused)?;

    let mut head = Vec::with_capacity(64);
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf).await.map_err(|_| {
            if head.is_empty() {
                Probe::Refused
            } else {
                Probe::NotHttp
            }
        })?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
        if head.contains(&b'\n') || head.len() >= 512 {
            break;
        }
    }
    if head.is_empty() {
        return Err(Probe::Refused);
    }
    parse_status(&head).ok_or(Probe::NotHttp)
}

/// 0 is any answer below 500: the app is there and not failing. 200 takes
/// a redirect too, since a home page often sends visitors to a login.
pub fn is_healthy(status: u16, expected: u16) -> bool {
    match expected {
        0 => status < 500,
        200 => status == 200 || (300..400).contains(&status),
        expected => status == expected,
    }
}

pub fn parse_status(head: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(head);
    let mut parts = text.split_whitespace();
    let version = parts.next()?;

    version
        .starts_with("HTTP/")
        .then(|| parts.next()?.parse().ok())?
}

/// For apps that don't answer HTTP: the container has to still be running,
/// without restarting, a few seconds after it started. A bot with a bad
/// token or a missing dependency exits straight away, and that fails here.
pub async fn wait_running(container: &str, log: &Progress) -> Result<(), Failure> {
    let mut first_restarts = None;
    for attempt in 1..=3u32 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (status, restarts) = crate::container::state(container).await.map_err(|e| {
            Failure::new(
                "health",
                format!("couldn't read the container's state: {e}"),
            )
        })?;
        let first = *first_restarts.get_or_insert(restarts);
        if status != "running" || restarts != first {
            return Err(Failure::new(
                "health",
                format!("the app stopped after starting (container is {status}, restarted {restarts} times)"),
            )
            .with_next_step("Check the service's logs for the error, often a missing token or setting."));
        }
        log.line(format!("still running after check {attempt}/3"))
            .await;
    }
    log.line("no web page to check, the app kept running").await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use daemon_state::State;
    use tokio::net::TcpListener;
    use uuid::Uuid;

    use super::*;

    fn progress() -> Progress {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        Progress::new(
            Uuid::new_v4(),
            Arc::new(State::in_memory().unwrap()),
            tx,
            vec![],
        )
    }

    fn check(expected_status: u16) -> HealthCheck {
        HealthCheck {
            path: "/up".into(),
            expected_status,
            timeout_secs: 2,
            retries: 1,
            start_period_secs: 0,
            interval_secs: Some(1),
        }
    }

    /// A server that answers every request with `status` and hands back the
    /// request it read.
    async fn answering(status: &'static str) -> (u16, tokio::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let _ = tx
                    .send(String::from_utf8_lossy(&buf[..n]).into_owned())
                    .await;
                let _ = socket
                    .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                    .await;
            }
        });
        (port, rx)
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn parses_the_status_line() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 503 Unavailable"), Some(503));
        assert_eq!(parse_status(b"not http"), None);
    }

    #[test]
    fn what_counts_as_healthy() {
        assert!(is_healthy(200, 200));
        assert!(is_healthy(302, 200));
        assert!(is_healthy(308, 200));
        assert!(!is_healthy(404, 200));
        assert!(!is_healthy(502, 200));
        assert!(!is_healthy(302, 204));
        assert!(is_healthy(204, 204));

        // 0: the app answers and isn't failing.
        for status in [200, 301, 401, 404, 400, 499] {
            assert!(is_healthy(status, 0), "{status}");
        }
        for status in [500, 502, 503] {
            assert!(!is_healthy(status, 0), "{status}");
        }
    }

    #[test]
    fn the_host_is_the_first_real_domain() {
        let target = |domains: &'static [String]| Target {
            host_port: 1,
            container_port: None,
            domains,
        };
        assert_eq!(target(&[]).host(), "localhost");
        static DOMAINS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
            vec!["*.shop.example.com".into(), "shop.example.com".into()]
        });
        assert_eq!(target(&DOMAINS).host(), "shop.example.com");
    }

    #[test]
    fn paths_are_paths() {
        assert_eq!(request_path("/up").unwrap(), "/up");
        assert_eq!(request_path("health").unwrap(), "/health");
        assert!(request_path("/up HTTP/1.1\r\nX: y").is_err());
    }

    #[test]
    fn waits_follow_the_interval_or_the_old_backoff() {
        let mut c = check(200);
        assert_eq!(interval(&c, 3), Duration::from_secs(1));
        c.interval_secs = None;
        assert_eq!(interval(&c, 0), Duration::from_secs(2));
        assert_eq!(interval(&c, 1), Duration::from_secs(2));
        assert_eq!(interval(&c, 3), Duration::from_secs(8));
        assert_eq!(interval(&c, 9), Duration::from_secs(16));
    }

    #[tokio::test]
    async fn sends_the_apps_domain_and_accepts_any_answer_below_500_for_0() {
        let (port, mut requests) = answering("404 Not Found").await;
        let domains = vec!["shop.example.com".to_string()];
        let target = Target {
            host_port: port,
            container_port: Some(3000),
            domains: &domains,
        };
        let (_tx, mut cancel) = watch::channel(false);

        wait_healthy(target, Some(&check(0)), &mut cancel, &progress())
            .await
            .unwrap();
        let request = requests.recv().await.unwrap();
        assert!(request.starts_with("GET /up HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains("\r\nHost: shop.example.com\r\n"),
            "{request}"
        );

        let failure = wait_healthy(target, Some(&check(200)), &mut cancel, &progress())
            .await
            .unwrap_err();
        assert_eq!(failure.phase, "health");
        assert_eq!(
            failure.message,
            "the health check failed: /up answered HTTP 404, expected HTTP 200 (or a redirect)"
        );
        assert!(failure.next_step.unwrap().contains("expected status to 0"));
    }

    #[tokio::test]
    async fn a_server_error_fails_even_with_0() {
        let (port, _requests) = answering("502 Bad Gateway").await;
        let target = Target {
            host_port: port,
            container_port: None,
            domains: &[],
        };
        let (_tx, mut cancel) = watch::channel(false);
        let failure = wait_healthy(target, Some(&check(0)), &mut cancel, &progress())
            .await
            .unwrap_err();
        assert!(failure.message.contains("HTTP 502"), "{}", failure.message);
        assert!(failure.next_step.unwrap().contains("logs"));
    }

    #[tokio::test]
    async fn nothing_listening_says_so_and_points_at_the_port_and_address() {
        let target = Target {
            host_port: free_port(),
            container_port: Some(8080),
            domains: &[],
        };
        let (_tx, mut cancel) = watch::channel(false);
        let failure = wait_healthy(target, Some(&check(0)), &mut cancel, &progress())
            .await
            .unwrap_err();
        assert_eq!(
            failure.message,
            "the health check failed: nothing is accepting connections on port 8080"
        );
        let next = failure.next_step.unwrap();
        assert!(next.contains("0.0.0.0") && next.contains("8080") && next.contains("PORT"));

        // Docker's proxy takes the connection and closes it when the app
        // isn't listening: the same thing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });
        let closed = probe(
            Target {
                host_port: port,
                ..target
            },
            "/",
            0,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(closed, Probe::Refused);
    }

    #[tokio::test]
    async fn a_silent_app_times_out_and_another_protocol_is_not_http() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let target = Target {
            host_port: port,
            container_port: None,
            domains: &[],
        };
        assert_eq!(
            probe(target, "/", 0, Duration::from_millis(300)).await,
            Probe::TimedOut
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"\x15\x03\x01\x00\x02\x02\x0a").await;
            }
        });
        assert_eq!(
            probe(
                Target {
                    host_port: port,
                    ..target
                },
                "/",
                0,
                Duration::from_secs(2)
            )
            .await,
            Probe::NotHttp
        );
    }

    #[tokio::test]
    async fn a_slow_starting_app_gets_its_start_period() {
        let port = free_port();
        // Starts listening a second and a half after the check begins.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 512];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            }
        });
        let target = Target {
            host_port: port,
            container_port: None,
            domains: &[],
        };
        let (_tx, mut cancel) = watch::channel(false);
        let slow = HealthCheck {
            start_period_secs: 4,
            retries: 1,
            ..check(0)
        };
        // One try after the start period wouldn't be enough without it: the
        // failed tries inside it didn't count.
        wait_healthy(target, Some(&slow), &mut cancel, &progress())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failures_in_the_start_period_do_not_use_up_retries() {
        let target = Target {
            host_port: free_port(),
            container_port: Some(3000),
            domains: &[],
        };
        let (_tx, mut cancel) = watch::channel(false);
        let state = Arc::new(State::in_memory().unwrap());
        let id = Uuid::new_v4();
        state.record_job(id, "test", "deploy", "{}").unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let progress = Progress::new(id, Arc::clone(&state), tx, vec![]);
        let started = Instant::now();
        let check = HealthCheck {
            start_period_secs: 2,
            retries: 2,
            ..check(0)
        };

        assert!(wait_healthy(target, Some(&check), &mut cancel, &progress)
            .await
            .is_err());
        assert!(started.elapsed() >= Duration::from_secs(3));
        let log = state.job(id).unwrap().unwrap().log;
        assert!(log.contains("still starting"), "{log}");
        assert!(
            log.contains("attempt 1/2") && log.contains("attempt 2/2"),
            "{log}"
        );
    }

    #[tokio::test]
    async fn a_cancel_stops_the_wait() {
        let target = Target {
            host_port: free_port(),
            container_port: None,
            domains: &[],
        };
        let (tx, mut cancel) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = tx.send(true);
        });
        let started = Instant::now();
        let long = HealthCheck {
            start_period_secs: 60,
            ..check(0)
        };
        let failure = wait_healthy(target, Some(&long), &mut cancel, &progress())
            .await
            .unwrap_err();
        assert_eq!(failure.phase, "cancelled");
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
