//! IP addresses in log lines, masked on the machine before they're shipped.
//!
//! Hosts' logs (Pterodactyl Wings, web servers, SSH) are full of their
//! customers' addresses. With masking on, none leaves the machine whole:
//!
//! - `partial` keeps the network and drops the host: `203.0.113.x`, and the
//!   first 48 bits of an IPv6 address (`2001:db8:abcd::x`).
//! - `hash` replaces each address with a short code (`ip-3f9a1c2e`) that's
//!   the same every time it appears, so repeat offenders still stand out.
//!   It's keyed by a salt that never leaves the machine: without one, the
//!   whole IPv4 space could be hashed in seconds and the codes reversed.
//!
//! Loopback and unspecified addresses (`127.0.0.1`, `0.0.0.0`, `::1`) say
//! nothing about anyone and are left as they are, so "listening on
//! 0.0.0.0:80" still reads.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{LazyLock, RwLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpMasking {
    #[default]
    Off,
    Partial,
    Hash,
}

impl IpMasking {
    pub fn is_off(&self) -> bool {
        matches!(self, IpMasking::Off)
    }
}

/// The machine's setting, and its salt: set when the daemon starts and when
/// the panel changes it, read by everything that sends log lines out.
static SETTING: RwLock<(IpMasking, Vec<u8>)> = RwLock::new((IpMasking::Off, Vec::new()));

pub fn configure(mode: IpMasking, salt: Vec<u8>) {
    *SETTING.write().unwrap_or_else(|e| e.into_inner()) = (mode, salt);
}

pub fn set_mode(mode: IpMasking) {
    SETTING.write().unwrap_or_else(|e| e.into_inner()).0 = mode;
}

pub fn current() -> IpMasking {
    SETTING.read().unwrap_or_else(|e| e.into_inner()).0
}

/// A log line as it may leave the machine: secrets redacted, then IP
/// addresses masked when the setting is on. Every path that sends log
/// lines to the panel (shipping, a service's logs, a live tail) uses this.
pub fn outgoing(line: &str) -> String {
    let redacted = crate::redact::redact(line);
    let setting = SETTING.read().unwrap_or_else(|e| e.into_inner());
    // No salt (it couldn't be written): an unsalted hash could be reversed,
    // so mask partially instead.
    let mode = match setting.0 {
        IpMasking::Hash if setting.1.is_empty() => IpMasking::Partial,
        mode => mode,
    };
    mask(&redacted, mode, &setting.1).into_owned()
}

/// The machine's salt for hashed addresses, made on first use and kept
/// beside its key (0600). It never leaves the machine.
pub fn load_salt(path: &Path) -> std::io::Result<Vec<u8>> {
    if let Ok(text) = std::fs::read_to_string(path) {
        if let Ok(bytes) = hex::decode(text.trim()) {
            if bytes.len() >= 16 {
                return Ok(bytes);
            }
        }
    }
    let mut salt = vec![0u8; 32];
    getrandom(&mut salt)?;
    write_private(path, &hex::encode(&salt))?;
    Ok(salt)
}

fn getrandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text)
    }
}

/// Runs of characters an address can be made of; each is then checked.
static CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[0-9A-Fa-f:.]+").expect("candidate pattern compiles"));

/// The line with its IP addresses masked. Borrows it untouched when off,
/// or when it holds no address.
pub fn mask<'a>(line: &'a str, mode: IpMasking, salt: &[u8]) -> Cow<'a, str> {
    if mode.is_off() || !line.bytes().any(|b| b == b'.' || b == b':') {
        return Cow::Borrowed(line);
    }

    let mut out = String::with_capacity(line.len());
    let mut last = 0;
    let mut changed = false;
    for found in CANDIDATE.find_iter(line) {
        // Part of a longer word, like a version tag (v1.2.3.4): leave it.
        let before = line[..found.start()].chars().next_back();
        let after = line[found.end()..].chars().next();
        if before.is_some_and(word_char) || after.is_some_and(word_char) {
            continue;
        }
        if let Some(masked) = mask_token(found.as_str(), mode, salt) {
            out.push_str(&line[last..found.start()]);
            out.push_str(&masked);
            last = found.end();
            changed = true;
        }
    }
    if !changed {
        return Cow::Borrowed(line);
    }
    out.push_str(&line[last..]);
    Cow::Owned(out)
}

fn word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// One run of address-like characters, masked if it is (or holds) an
/// address: `1.2.3.4`, `1.2.3.4:8080`, `2001:db8::1`, `::ffff:1.2.3.4`.
fn mask_token(token: &str, mode: IpMasking, salt: &[u8]) -> Option<String> {
    // Sentence punctuation after an address: "from 1.2.3.4." or "1.2.3.4:".
    let trimmed = token.trim_end_matches(['.', ':']);
    let tail = &token[trimmed.len()..];

    let masked = if let Ok(v6) = trimmed.parse::<Ipv6Addr>() {
        masked_ip(IpAddr::V6(v6), mode, salt)?
    } else if let Ok(v4) = trimmed.parse::<Ipv4Addr>() {
        masked_ip(IpAddr::V4(v4), mode, salt)?
    } else if let Some((host, port)) = trimmed.rsplit_once(':') {
        // 1.2.3.4:8080
        let v4 = host.parse::<Ipv4Addr>().ok()?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        format!("{}:{port}", masked_ip(IpAddr::V4(v4), mode, salt)?)
    } else {
        return None;
    };

    Some(format!("{masked}{tail}"))
}

fn masked_ip(ip: IpAddr, mode: IpMasking, salt: &[u8]) -> Option<String> {
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    // ::ffff:1.2.3.4 is an IPv4 address.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }

    Some(match mode {
        IpMasking::Off => return None,
        IpMasking::Partial => match ip {
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                format!("{a}.{b}.{c}.x")
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::x", s[0], s[1], s[2])
            }
        },
        IpMasking::Hash => {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(ip.to_string().as_bytes());
            format!("ip-{}", &hex::encode(hasher.finalize())[..8])
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"a salt that never leaves the machine";

    fn partial(line: &str) -> String {
        mask(line, IpMasking::Partial, SALT).into_owned()
    }

    #[test]
    fn the_salt_is_made_once_and_kept_private() {
        let dir = std::env::temp_dir().join(format!("ipmask-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ip-mask.salt");
        let first = load_salt(&path).unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(load_salt(&path).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn outgoing_lines_have_secrets_redacted_and_addresses_masked() {
        configure(IpMasking::Partial, SALT.to_vec());
        assert_eq!(
            outgoing("login from 203.0.113.7 password=hunter2"),
            "login from 203.0.113.x password=[redacted]"
        );
        // No salt to key a hash with: masked partially, never unsalted.
        configure(IpMasking::Hash, Vec::new());
        assert_eq!(outgoing("from 203.0.113.7"), "from 203.0.113.x");
        configure(IpMasking::Off, Vec::new());
        assert_eq!(outgoing("from 203.0.113.7"), "from 203.0.113.7");
    }

    #[test]
    fn off_leaves_the_line_alone() {
        let line = "connection from 203.0.113.7";
        assert!(matches!(mask(line, IpMasking::Off, SALT), Cow::Borrowed(_)));
    }

    #[test]
    fn partial_keeps_the_network_and_drops_the_host() {
        assert_eq!(
            partial("connection from 203.0.113.7"),
            "connection from 203.0.113.x"
        );
        assert_eq!(
            partial("203.0.113.7:51234 GET /"),
            "203.0.113.x:51234 GET /"
        );
        assert_eq!(partial("ban 198.51.100.24."), "ban 198.51.100.x.");
        assert_eq!(
            partial("[2001:db8:abcd:12::7]:443"),
            "[2001:db8:abcd::x]:443"
        );
        assert_eq!(
            partial("client=2001:db8:abcd:0012:0000:0000:0000:0007"),
            "client=2001:db8:abcd::x"
        );
        assert_eq!(partial("mapped ::ffff:203.0.113.7"), "mapped 203.0.113.x");
        assert_eq!(
            partial(r#"{"ip":"203.0.113.7","to":"10.0.0.5"}"#),
            r#"{"ip":"203.0.113.x","to":"10.0.0.x"}"#
        );
    }

    #[test]
    fn hashes_are_short_stable_and_keyed_by_the_salt() {
        let a = mask("from 203.0.113.7", IpMasking::Hash, SALT).into_owned();
        let b = mask("again 203.0.113.7", IpMasking::Hash, SALT).into_owned();
        let other_machine = mask("from 203.0.113.7", IpMasking::Hash, b"another salt").into_owned();

        let code = a.strip_prefix("from ").unwrap();
        assert!(code.starts_with("ip-") && code.len() == 11, "{a}");
        assert_eq!(b.strip_prefix("again ").unwrap(), code);
        assert_ne!(other_machine, a);
        assert!(!a.contains("203.0.113"));
    }

    #[test]
    fn things_that_only_look_like_addresses_are_left_alone() {
        for line in [
            "listening on 0.0.0.0:8080",
            "listening on 127.0.0.1:6379 and [::1]:6379",
            "started at 12:34:56.789",
            "nic aa:bb:cc:dd:ee:ff up",
            "running v1.2.3.4 of the agent",
            "std::vector<int> and Foo::bar()",
            "took 1.25s, 300.400.500.600 is not an address",
            "sha 3f9a1c2e8b7d6e5f",
        ] {
            assert_eq!(partial(line), line, "{line}");
        }
    }

    #[test]
    fn no_full_address_survives_a_busy_line() {
        let line = "Oct 11 12:00:01 wings[812]: 203.0.113.7 -> 198.51.100.24:25565 via 2001:db8:abcd:12::7 (proxy 192.0.2.1)";
        for mode in [IpMasking::Partial, IpMasking::Hash] {
            let out = mask(line, mode, SALT).into_owned();
            for ip in [
                "203.0.113.7",
                "198.51.100.24",
                "2001:db8:abcd:12::7",
                "192.0.2.1",
            ] {
                assert!(!out.contains(ip), "{mode:?}: {out}");
            }
            assert!(out.starts_with("Oct 11 12:00:01 wings[812]: "), "{out}");
        }
    }
}
