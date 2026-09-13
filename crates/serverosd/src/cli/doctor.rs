//! `serverosd doctor`: checks with a fix attached to each failure.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use daemon_core::{Config, Paths};
use daemon_identity::Identity;

struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
    fix: Option<String>,
}

pub fn run(paths: Paths) -> anyhow::Result<()> {
    let mut checks = Vec::new();

    let config = Config::load(&paths.config_file());
    checks.push(match &config {
        Ok(c) => Check {
            name: "config",
            ok: true,
            detail: format!(
                "{} → {}:{}",
                paths.config_file().display(),
                c.panel.host,
                c.panel.port
            ),
            fix: None,
        },
        Err(e) => Check {
            name: "config",
            ok: false,
            detail: e.to_string(),
            fix: Some("Run `serverosd enrol --token …` to enrol this machine.".into()),
        },
    });

    let identity = Identity::load(&paths);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    checks.push(match &identity {
        Ok(id) => match id.certificate_not_after() {
            Ok(not_after) if not_after > now => {
                let days = (not_after - now) / 86_400;
                Check { name: "credentials", ok: days > 14, detail: format!("client certificate valid for {days} more days"), fix: (days <= 14).then(|| "The panel rotates certificates automatically while connected; if this stays low, re-enrol.".into()) }
            }
            Ok(_) => Check { name: "credentials", ok: false, detail: "client certificate has expired".into(), fix: Some("Re-enrol the machine from the panel.".into()) },
            Err(e) => Check { name: "credentials", ok: false, detail: e.to_string(), fix: Some("Re-enrol the machine.".into()) },
        },
        Err(e) => Check { name: "credentials", ok: false, detail: e.to_string(), fix: Some("Run `serverosd enrol`.".into()) },
    });

    let key_mode = std::fs::metadata(paths.private_key())
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    checks.push(Check {
        name: "key permissions",
        ok: key_mode == 0o600 || key_mode == 0,
        detail: format!("{} is {:o}", paths.private_key().display(), key_mode),
        fix: (key_mode != 0o600 && key_mode != 0)
            .then(|| format!("chmod 600 {}", paths.private_key().display())),
    });

    if let Ok(c) = &config {
        let target = format!("{}:{}", c.panel.host, c.panel.port);
        let reachable = std::net::ToSocketAddrs::to_socket_addrs(&target)
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|addr| {
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok()
            });
        checks.push(match reachable {
            Some(true) => Check {
                name: "panel reachable",
                ok: true,
                detail: format!("{target} accepts connections"),
                fix: None,
            },
            Some(false) => Check {
                name: "panel reachable",
                ok: false,
                detail: format!("could not open a TCP connection to {target}"),
                fix: Some(
                    "Allow outbound TCP 443 in the firewall. The daemon only ever dials out."
                        .into(),
                ),
            },
            None => Check {
                name: "panel reachable",
                ok: false,
                detail: format!("could not resolve {}", c.panel.host),
                fix: Some("Check /etc/resolv.conf; DNS is not working on this machine.".into()),
            },
        });
    }

    checks.push(Check {
        name: "systemd",
        ok: Path::new("/run/systemd/system").is_dir(),
        detail: if Path::new("/run/systemd/system").is_dir() {
            "present".into()
        } else {
            "not running".into()
        },
        fix: (!Path::new("/run/systemd/system").is_dir())
            .then(|| "The daemon needs systemd.".into()),
    });

    let docker = Path::new("/var/run/docker.sock").exists();
    checks.push(Check {
        name: "docker",
        ok: true,
        detail: if docker {
            "socket present".into()
        } else {
            "not installed (deploys and container discovery are off)".into()
        },
        fix: None,
    });

    let caddy = which("caddy");
    checks.push(Check {
        name: "caddy",
        ok: true,
        detail: if caddy {
            "present".into()
        } else {
            "not installed (domains and TLS for deploys are off)".into()
        },
        fix: None,
    });

    let ntp = std::process::Command::new("timedatectl")
        .args(["show", "-p", "NTPSynchronized", "--value"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "yes");
    checks.push(Check {
        name: "clock",
        ok: ntp != Some(false),
        detail: match ntp {
            Some(true) => "NTP synchronised".into(),
            Some(false) => "NTP not synchronised".into(),
            None => "could not query timedatectl".into(),
        },
        fix: (ntp == Some(false)).then(|| "timedatectl set-ntp true".into()),
    });

    let running = std::os::unix::net::UnixStream::connect(paths.control_socket()).is_ok();
    checks.push(Check {
        name: "daemon",
        ok: running,
        detail: if running {
            "running".into()
        } else {
            "not running".into()
        },
        fix: (!running)
            .then(|| "systemctl start serverosd; then `journalctl -u serverosd -n 50`".into()),
    });

    let mut failures = 0;
    for c in &checks {
        println!(
            "{} {:<18} {}",
            if c.ok { "ok  " } else { "FAIL" },
            c.name,
            c.detail
        );
        if let (false, Some(fix)) = (c.ok, &c.fix) {
            println!("     → {fix}");
            failures += 1;
        }
    }

    if failures > 0 {
        anyhow::bail!("{failures} check(s) need attention");
    }

    Ok(())
}

fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(program).is_file()))
        .unwrap_or(false)
}
