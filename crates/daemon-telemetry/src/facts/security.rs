//! What the security watch reads: the SSH server's effective settings,
//! failed sign-ins over the last hour, and whether security updates install
//! themselves. Only counts leave the machine, never the addresses.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use daemon_protocol::{LoginFacts, SecurityFacts, SshFacts};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const LOGIN_WINDOW_SECS: u64 = 60 * 60;

const SSHD: &[&str] = &["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"];
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const AUTH_LOGS: &[&str] = &["/var/log/auth.log", "/var/log/secure"];
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// Under a heavy attack an hour of auth log is large; the newest part is
/// enough to count from.
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LINES: usize = 200_000;

pub fn gather() -> SecurityFacts {
    SecurityFacts {
        ssh: ssh(),
        logins: logins(),
        auto_updates: auto_updates(),
    }
}

fn ssh() -> Option<SshFacts> {
    let sshd = SSHD.iter().find(|p| Path::new(p).exists())?;
    if let Some(out) = run(sshd, &["-T"]) {
        if let Some(facts) = parse_sshd_t(&out) {
            return Some(facts);
        }
    }

    let mut seen = Vec::new();
    let mut lines = Vec::new();
    collect_config(Path::new(SSHD_CONFIG), &mut seen, &mut lines, 0);
    Some(parse_sshd_config(&lines))
}

/// `sshd -T` prints every effective setting, lower-case, one per line.
pub fn parse_sshd_t(text: &str) -> Option<SshFacts> {
    let mut facts = SshFacts {
        source: "sshd -T".into(),
        ..SshFacts::default()
    };
    let mut any = false;
    for line in text.lines() {
        let mut parts = line.splitn(2, ' ');
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let value = value.trim();
        match key {
            "port" => {
                any = true;
                if let Ok(port) = value.parse() {
                    facts.ports.push(port);
                }
            }
            "permitrootlogin" => {
                any = true;
                facts.permit_root_login = normalise_root(value);
            }
            "passwordauthentication" => facts.password_authentication = value == "yes",
            "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
                facts.kbd_interactive_authentication |= value == "yes"
            }
            "usepam" => facts.use_pam = value == "yes",
            _ => {}
        }
    }

    any.then_some(facts)
}

/// sshd_config read directly, when `sshd -T` can't run: the first value of
/// each keyword wins, and Match blocks (which only apply to some
/// connections) are ignored. Unset keywords take OpenSSH's defaults.
pub fn parse_sshd_config(lines: &[String]) -> SshFacts {
    let mut ports = Vec::new();
    let mut root = None;
    let mut password = None;
    let mut kbd = None;
    let mut pam = None;
    let mut in_match = false;

    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = split_keyword(line);
        let key = key.to_ascii_lowercase();
        if key == "match" {
            in_match = true;
        }
        if in_match {
            continue;
        }
        let yes = value.eq_ignore_ascii_case("yes");
        match key.as_str() {
            "port" => {
                if let Ok(port) = value.parse() {
                    ports.push(port);
                }
            }
            "permitrootlogin" => {
                root.get_or_insert_with(|| normalise_root(&value.to_ascii_lowercase()));
            }
            "passwordauthentication" => {
                password.get_or_insert(yes);
            }
            "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
                kbd.get_or_insert(yes);
            }
            "usepam" => {
                pam.get_or_insert(yes);
            }
            _ => {}
        }
    }

    SshFacts {
        ports: if ports.is_empty() { vec![22] } else { ports },
        permit_root_login: root.unwrap_or_else(|| "prohibit-password".into()),
        password_authentication: password.unwrap_or(true),
        kbd_interactive_authentication: kbd.unwrap_or(true),
        use_pam: pam.unwrap_or(false),
        source: "config".into(),
    }
}

fn normalise_root(value: &str) -> String {
    match value {
        "without-password" => "prohibit-password".into(),
        other => other.into(),
    }
}

fn split_keyword(line: &str) -> (&str, String) {
    let line = line.trim();
    let split = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (key, rest) = line.split_at(split);
    let value = rest
        .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .trim()
        .trim_matches('"');

    (key, value.to_string())
}

/// The config's lines in the order sshd reads them, Include files inlined
/// where they appear (relative paths are under /etc/ssh, `*` globs sorted).
fn collect_config(
    path: &Path,
    seen: &mut Vec<std::path::PathBuf>,
    out: &mut Vec<String>,
    depth: u8,
) {
    if depth > 8 || seen.iter().any(|p| p == path) {
        return;
    }
    seen.push(path.to_path_buf());
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let (key, value) = split_keyword(line);
        if key.eq_ignore_ascii_case("include") {
            for pattern in value.split_whitespace() {
                for file in expand_include(pattern) {
                    collect_config(&file, seen, out, depth + 1);
                }
            }
        } else {
            out.push(line.to_string());
        }
    }
}

fn expand_include(pattern: &str) -> Vec<std::path::PathBuf> {
    let full = if pattern.starts_with('/') {
        std::path::PathBuf::from(pattern)
    } else {
        Path::new("/etc/ssh").join(pattern)
    };
    let Some(name) = full.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    if !name.contains('*') {
        return vec![full];
    }
    let (prefix, suffix) = name.split_once('*').unwrap_or((name, ""));
    let Some(dir) = full.parent() else {
        return Vec::new();
    };
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            (n.starts_with(prefix) && n.ends_with(suffix) && n.len() >= prefix.len() + suffix.len())
                .then(|| e.path())
        })
        .collect();
    files.sort();

    files
}

/// From the journal and the syslog auth file, whichever saw more: most
/// machines write to both (then they agree), some only to one, and a
/// journal can exist with nothing in it.
fn logins() -> Option<LoginFacts> {
    let since = format!("{} seconds ago", LOGIN_WINDOW_SECS);
    let journal = run(
        "journalctl",
        &[
            "--no-pager",
            "-q",
            "-o",
            "cat",
            "-t",
            "sshd",
            "-t",
            "sshd-session",
            "--since",
            &since,
        ],
    )
    .map(|out| count_logins(out.lines().take(MAX_LINES)));

    match (journal, auth_log_logins()) {
        (Some(a), Some(b)) => Some(if b.failed > a.failed { b } else { a }),
        (a, b) => a.or(b),
    }
}

fn auth_log_logins() -> Option<LoginFacts> {
    let path = AUTH_LOGS.iter().find(|p| Path::new(p).exists())?;
    let tail = read_tail(Path::new(path), MAX_LOG_BYTES)?;
    let cutoff = OffsetDateTime::now_utc() - Duration::from_secs(LOGIN_WINDOW_SECS);
    let year = OffsetDateTime::now_utc().year();
    let recent = tail
        .lines()
        .filter(|l| l.contains("sshd"))
        .filter(|l| log_time(l, year).is_some_and(|t| t >= cutoff))
        .take(MAX_LINES);

    Some(count_logins(recent))
}

/// Failed sign-ins, counted per connection (address and source port), from
/// sshd's own messages.
pub fn count_logins<'a>(lines: impl Iterator<Item = &'a str>) -> LoginFacts {
    let mut failed = BTreeSet::new();
    let mut root = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut accepted_password = 0u32;

    for line in lines {
        if line.contains("Accepted password for ") || line.contains("Accepted keyboard-interactive")
        {
            accepted_password += 1;
            continue;
        }
        let failure = line.contains("Failed password for ")
            || line.contains("Failed keyboard-interactive")
            || line.contains("Invalid user ")
            || line.contains("authenticating user ")
            || line.contains("maximum authentication attempts exceeded");
        if !failure {
            continue;
        }
        let Some((address, port)) = address_and_port(line) else {
            continue;
        };
        if line.contains(" root ") {
            root.insert((address.clone(), port.clone()));
        }
        sources.insert(address.clone());
        failed.insert((address, port));
    }

    LoginFacts {
        window_secs: LOGIN_WINDOW_SECS,
        failed: failed.len() as u32,
        sources: sources.len() as u32,
        root: root.len() as u32,
        accepted_password,
    }
}

/// sshd names the client as "… 203.0.113.9 port 51234 …".
fn address_and_port(line: &str) -> Option<(String, String)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words.iter().position(|w| *w == "port")?;
    let address = words.get(at.checked_sub(1)?)?;
    let port = words.get(at + 1)?;
    let looks_like_address = address.contains('.') || address.contains(':');

    looks_like_address.then(|| (address.to_string(), port.trim_end_matches(':').to_string()))
}

/// A syslog line's time: RFC 3339 (rsyslog's high-precision format, the
/// default on recent Ubuntu) or the traditional "Oct 15 12:00:01", which
/// carries no year or zone and is read as this year, UTC.
pub fn log_time(line: &str, year: i32) -> Option<OffsetDateTime> {
    let first = line.split_whitespace().next()?;
    if let Ok(t) = OffsetDateTime::parse(first, &Rfc3339) {
        return Some(t);
    }

    let mut words = line.split_whitespace();
    let month = match words.next()? {
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
    let day: u8 = words.next()?.parse().ok()?;
    let mut clock = words.next()?.split(':').map(|p| p.parse::<u8>().ok());
    let (h, m, s) = (clock.next()??, clock.next()??, clock.next()??);
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let at = date.with_hms(h, m, s).ok()?.assume_utc();

    Some(at)
}

fn read_tail(path: &Path, max: u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len > max {
        file.seek(SeekFrom::Start(len - max)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes).ok()?;

    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn auto_updates() -> Option<bool> {
    if Path::new("/usr/bin/apt-get").exists() {
        let installed = Path::new("/usr/bin/unattended-upgrade").exists();
        let enabled = std::fs::read_dir("/etc/apt/apt.conf.d")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .any(|text| apt_unattended_enabled(&text));

        return Some(installed && enabled);
    }
    if Path::new("/usr/bin/dnf").exists() {
        let timers = Path::new("/etc/systemd/system/timers.target.wants");
        let enabled = ["dnf-automatic.timer", "dnf-automatic-install.timer"]
            .iter()
            .any(|t| timers.join(t).exists());

        return Some(enabled);
    }

    None
}

pub fn apt_unattended_enabled(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        !line.starts_with("//")
            && line.starts_with("APT::Periodic::Unattended-Upgrade")
            && line
                .split('"')
                .nth(1)
                .is_some_and(|v| v.trim() != "0" && !v.trim().is_empty())
    })
}

/// A command's stdout, or None if it's missing, fails or takes too long.
fn run(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("LC_ALL", "C")
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = (&mut stdout).take(64 * 1024 * 1024).read_to_end(&mut out);
        out
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(25))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let out = reader.join().ok()?;

    status
        .success()
        .then(|| String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sshd_t() {
        let facts = parse_sshd_t(
            "port 22\nport 2222\npermitrootlogin without-password\npasswordauthentication no\nkbdinteractiveauthentication no\nusepam yes\n",
        )
        .unwrap();
        assert_eq!(facts.ports, vec![22, 2222]);
        assert_eq!(facts.permit_root_login, "prohibit-password");
        assert!(!facts.password_authentication);
        assert!(!facts.kbd_interactive_authentication);
        assert!(facts.use_pam);
        assert_eq!(facts.source, "sshd -T");
    }

    #[test]
    fn sshd_t_without_settings_is_nothing() {
        assert!(parse_sshd_t("garbage\n").is_none());
    }

    #[test]
    fn config_first_value_wins_and_match_is_ignored() {
        let lines: Vec<String> = [
            "# comment",
            "PermitRootLogin yes",
            "PasswordAuthentication=no",
            "PermitRootLogin no",
            "Port 2200",
            "Match User deploy",
            "  PasswordAuthentication yes",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let facts = parse_sshd_config(&lines);
        assert_eq!(facts.permit_root_login, "yes");
        assert!(!facts.password_authentication);
        assert_eq!(facts.ports, vec![2200]);
        assert_eq!(facts.source, "config");
    }

    #[test]
    fn config_defaults_are_openssh_defaults() {
        let facts = parse_sshd_config(&[]);
        assert_eq!(facts.ports, vec![22]);
        assert_eq!(facts.permit_root_login, "prohibit-password");
        assert!(facts.password_authentication);
        assert!(facts.kbd_interactive_authentication);
        assert!(!facts.use_pam);
    }

    #[test]
    fn counts_failed_connections_once() {
        let log = "\
Invalid user admin from 203.0.113.9 port 51234
Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2
Failed password for root from 198.51.100.4 port 40000 ssh2
Failed password for root from 198.51.100.4 port 40000 ssh2
Connection closed by authenticating user root 198.51.100.4 port 40001 [preauth]
Accepted publickey for deploy from 192.0.2.1 port 50000 ssh2
Accepted password for deploy from 192.0.2.1 port 50001 ssh2
Received disconnect from 192.0.2.1 port 50000:11: disconnected by user
error: kex_exchange_identification: Connection closed by remote host";
        let facts = count_logins(log.lines());
        assert_eq!(facts.failed, 3);
        assert_eq!(facts.sources, 2);
        assert_eq!(facts.root, 2);
        assert_eq!(facts.accepted_password, 1);
        assert_eq!(facts.window_secs, LOGIN_WINDOW_SECS);
    }

    #[test]
    fn counts_ipv6_sources() {
        let facts = count_logins(["Invalid user test from 2001:db8::1 port 2222"].into_iter());
        assert_eq!(facts.failed, 1);
        assert_eq!(facts.sources, 1);
    }

    #[test]
    fn reads_both_syslog_time_formats() {
        let rfc = log_time("2026-10-15T12:00:01.123456+00:00 host sshd[1]: hi", 2026).unwrap();
        assert_eq!(rfc.hour(), 12);
        let old = log_time("Oct  5 09:08:07 host sshd[1]: hi", 2026).unwrap();
        assert_eq!(
            (old.month(), old.day(), old.second()),
            (time::Month::October, 5, 7)
        );
        assert!(log_time("not a time", 2026).is_none());
    }

    #[test]
    #[ignore = "reads this machine's sshd and logs"]
    fn gathers_on_this_machine() {
        let facts = gather();
        println!("{facts:#?}");
        if let Some(ssh) = facts.ssh {
            assert!(!ssh.permit_root_login.is_empty());
        }
    }

    #[test]
    fn reads_unattended_upgrades_setting() {
        assert!(apt_unattended_enabled(
            "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
        ));
        assert!(!apt_unattended_enabled(
            "APT::Periodic::Unattended-Upgrade \"0\";\n"
        ));
        assert!(!apt_unattended_enabled(
            "// APT::Periodic::Unattended-Upgrade \"1\";\n"
        ));
    }
}
