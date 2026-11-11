//! A Cloudflare Tunnel on this machine: cloudflared, run by systemd with the
//! tunnel's token, carries visitors from Cloudflare's edge to the reverse
//! proxy, which serves the machine's app domains over plain HTTP while it's
//! there (the edge does HTTPS).
//!
//! The token is the only secret. It lives in a root-only environment file
//! that the unit reads, so it's never on a command line (`ps`), and the job
//! names it as a known secret so progress lines, failures and the job ledger
//! never carry it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use daemon_core::config::ProxyBackend;
use daemon_deploy::proxy::Proxy;
use daemon_jobs::{run_child, Failure, Progress};
use daemon_protocol::TunnelAction;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::watch;

pub const UNIT: &str = "serveros-tunnel";
const UNIT_DIR: &str = "/etc/systemd/system";
const ENV_FILE: &str = "tunnel.env";

const NOT_A_TOKEN: &str = "That isn't a Cloudflare Tunnel token. Copy it from the tunnel's install command in Cloudflare Zero Trust.";

/// Cloudflare's own package repository, as its install docs set it up, so
/// cloudflared gets updates with the rest of the machine.
const INSTALL_SCRIPT: &str = r#"set -eu
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update -q
  apt-get -o DPkg::Lock::Timeout=300 install -y -q curl ca-certificates
  mkdir -p --mode=0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  chmod o+r /usr/share/keyrings/cloudflare-main.gpg
  echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
  apt-get -o DPkg::Lock::Timeout=300 update -q
  apt-get -o DPkg::Lock::Timeout=300 install -y -q cloudflared
elif command -v dnf >/dev/null 2>&1; then
  curl -fsSL https://pkg.cloudflare.com/cloudflared-ascii.repo -o /etc/yum.repos.d/cloudflared.repo
  dnf install -y cloudflared
elif command -v yum >/dev/null 2>&1; then
  curl -fsSL https://pkg.cloudflare.com/cloudflared-ascii.repo -o /etc/yum.repos.d/cloudflared.repo
  yum install -y cloudflared
else
  echo "installing cloudflared needs apt, dnf or yum" >&2
  exit 3
fi
"#;

/// One tunnel job at a time: two at once would race on the unit and the
/// proxy's site files.
static BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A token as Cloudflare hands it out, checked, with the tunnel it's for.
pub struct Token {
    pub value: String,
    pub tunnel_id: String,
}

/// Checks a tunnel token without saying anything about it: base64 of
/// `{"a": account, "t": tunnel id, "s": secret}`.
pub fn check_token(raw: Option<&str>) -> Result<Token, Failure> {
    let not_a_token = || Failure::new("tunnel", NOT_A_TOKEN);
    let value = raw.map(str::trim).unwrap_or_default();
    if value.is_empty()
        || value.len() > 4096
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
    {
        return Err(not_a_token());
    }

    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    let bytes = engines
        .iter()
        .find_map(|engine| engine.decode(value).ok())
        .ok_or_else(not_a_token)?;

    #[derive(Deserialize)]
    struct Parts {
        a: String,
        t: String,
        s: String,
    }
    let parts: Parts = serde_json::from_slice(&bytes).map_err(|_| not_a_token())?;
    let tunnel = uuid::Uuid::parse_str(parts.t.trim()).map_err(|_| not_a_token())?;
    if parts.a.trim().is_empty() || parts.s.trim().is_empty() {
        return Err(not_a_token());
    }

    Ok(Token {
        value: value.to_string(),
        tunnel_id: tunnel.hyphenated().to_string(),
    })
}

/// Where the tunnel's two files go.
pub struct Files {
    pub env: PathBuf,
    pub unit: PathBuf,
}

impl Files {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            env: config_dir.join(ENV_FILE),
            unit: Path::new(UNIT_DIR).join(format!("{UNIT}.service")),
        }
    }
}

/// The systemd unit: cloudflared reads the token from TUNNEL_TOKEN, and
/// tells systemd once it's connected (Type=notify), so a start that never
/// connects fails instead of hanging.
pub fn unit_text(cloudflared: &Path, env_file: &Path) -> String {
    format!(
        "# Written by ServerOS. Taken away when the tunnel is turned off.\n\
         [Unit]\n\
         Description=Cloudflare Tunnel (set up by ServerOS)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=notify\n\
         TimeoutStartSec=60\n\
         EnvironmentFile={}\n\
         ExecStart={} --no-autoupdate tunnel run\n\
         Restart=on-failure\n\
         RestartSec=5s\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        env_file.display(),
        cloudflared.display(),
    )
}

pub fn env_text(token: &str) -> String {
    format!("TUNNEL_TOKEN={token}\n")
}

pub async fn apply(
    proxy: &Proxy,
    files: &Files,
    action: TunnelAction,
    token: Option<&Token>,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<Value, Failure> {
    let _busy = BUSY.lock().await;

    match action {
        TunnelAction::Up => {
            let token = token.ok_or_else(|| Failure::new("tunnel", NOT_A_TOKEN))?;
            // A tunnel that was already running, to put back if this one fails.
            let before = Previous::read(files);
            let result = match up(files, token, cancel, progress).await {
                Ok(()) => proxy.set_plain_http(true, cancel, progress).await,
                Err(failure) => Err(failure),
            };
            if let Err(failure) = result {
                restore(files, before, cancel, progress).await;
                return Err(failure);
            }
            Ok(report(proxy, "connected", Some(&token.tunnel_id)))
        }
        TunnelAction::Down => {
            down(files, cancel, progress).await?;
            proxy.set_plain_http(false, cancel, progress).await?;
            Ok(report(proxy, "removed", None))
        }
    }
}

fn report(proxy: &Proxy, state: &str, tunnel_id: Option<&str>) -> Value {
    json!({
        "tunnel": {
            "state": state,
            "tunnel_id": tunnel_id,
            "proxy": match proxy.backend {
                ProxyBackend::Caddy => "caddy",
                ProxyBackend::Nginx => "nginx",
                ProxyBackend::None => "none",
            },
            "plain_http": proxy.plain_http(),
        }
    })
}

async fn up(
    files: &Files,
    token: &Token,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    progress.phase("install", Some(10)).await;
    let cloudflared = match find_on_path("cloudflared") {
        Some(path) => path,
        None => {
            progress
                .line("cloudflared is not installed: installing it from Cloudflare's package repository")
                .await;
            let outcome = run_child(
                "sh",
                &["-c", INSTALL_SCRIPT],
                None,
                &[],
                Duration::from_secs(600),
                cancel,
                progress,
                None,
            )
            .await;
            if !outcome.success() {
                return Err(Failure::new("install", "could not install cloudflared")
                    .with_output(outcome.tail().to_vec())
                    .with_next_step(
                        "Install cloudflared yourself (developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads), then turn the tunnel on again.",
                    ));
            }
            find_on_path("cloudflared").ok_or_else(|| {
                Failure::new("install", "cloudflared was installed but isn't on the PATH")
                    .with_next_step("Check `command -v cloudflared` on the machine.")
            })?
        }
    };

    progress.phase("configure", Some(40)).await;
    progress
        .line(format!(
            "Running tunnel {} with systemd ({UNIT})",
            token.tunnel_id
        ))
        .await;
    write_atomic(&files.env, &env_text(&token.value), 0o600)?;
    write_atomic(&files.unit, &unit_text(&cloudflared, &files.env), 0o644)?;

    progress.phase("start", Some(60)).await;
    for args in [
        vec!["daemon-reload"],
        vec!["enable", UNIT],
        vec!["restart", UNIT],
    ] {
        let outcome = run_child(
            "systemctl",
            &args,
            None,
            &[],
            Duration::from_secs(90),
            cancel,
            progress,
            None,
        )
        .await;
        if !outcome.success() {
            return Err(not_running(cancel, progress, outcome.tail().to_vec()).await);
        }
    }

    if !unit_active(UNIT).await {
        return Err(not_running(cancel, progress, Vec::new()).await);
    }
    progress.line("The tunnel is connected to Cloudflare").await;

    Ok(())
}

/// The unit and token file as they were before an `up`, if a tunnel was set up.
struct Previous {
    env: String,
    unit: String,
}

impl Previous {
    fn read(files: &Files) -> Option<Self> {
        Some(Self {
            env: std::fs::read_to_string(&files.env).ok()?,
            unit: std::fs::read_to_string(&files.unit).ok()?,
        })
    }
}

/// After a failed `up`, leaves the machine as it was: the earlier tunnel
/// running again with its own token, or no tunnel at all, so a token that
/// doesn't work isn't left retrying on the machine.
async fn restore(
    files: &Files,
    before: Option<Previous>,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) {
    let Some(before) = before else {
        progress
            .line(format!("Taking {UNIT} off again, since it didn't work"))
            .await;
        let _ = down(files, cancel, progress).await;
        return;
    };

    progress
        .line("Putting the tunnel that was running before back".to_string())
        .await;
    if write_atomic(&files.env, &before.env, 0o600).is_err()
        || write_atomic(&files.unit, &before.unit, 0o644).is_err()
    {
        return;
    }
    for args in [vec!["daemon-reload"], vec!["restart", UNIT]] {
        let _ = run_child(
            "systemctl",
            &args,
            None,
            &[],
            Duration::from_secs(90),
            cancel,
            progress,
            None,
        )
        .await;
    }
}

async fn not_running(
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
    mut output: Vec<String>,
) -> Failure {
    // Child output is scrubbed of the job's known secrets, the token
    // among them, before it's kept.
    let journal = run_child(
        "journalctl",
        &["-u", UNIT, "-n", "20", "--no-pager"],
        None,
        &[],
        Duration::from_secs(15),
        cancel,
        progress,
        None,
    )
    .await;
    output.extend(journal.tail().iter().cloned());

    // Cloudflare's answer when the tunnel in the token doesn't exist (deleted,
    // or the token was copied wrong) or its secret is wrong.
    let refused = output
        .iter()
        .any(|l| l.contains("Failed to get tunnel") || l.contains("Unauthorized"));
    let message = if refused {
        "Cloudflare didn't accept the token: the tunnel may have been deleted, or the token copied wrong"
    } else {
        "the tunnel didn't connect to Cloudflare"
    };

    Failure::new("start", message)
        .with_output(output)
        .with_next_step(format!(
            "Check the token is this tunnel's, from Cloudflare Zero Trust › Networks › Tunnels, and that the machine can reach Cloudflare (outbound port 7844). `journalctl -u {UNIT}` says more."
        ))
}

async fn down(
    files: &Files,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    progress.phase("stop", Some(30)).await;
    if files.unit.exists() {
        progress.line(format!("Stopping {UNIT}")).await;
        // Already stopped or never enabled is fine: the files go either way.
        let _ = run_child(
            "systemctl",
            &["disable", "--now", UNIT],
            None,
            &[],
            Duration::from_secs(60),
            cancel,
            progress,
            None,
        )
        .await;
    }

    for path in [&files.unit, &files.env] {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(Failure::new(
                    "stop",
                    format!("could not remove {}: {e}", path.display()),
                ));
            }
            _ => {}
        }
    }

    let _ = run_child(
        "systemctl",
        &["daemon-reload"],
        None,
        &[],
        Duration::from_secs(60),
        cancel,
        progress,
        None,
    )
    .await;

    Ok(())
}

/// Written beside the target and renamed over it, so the file is never
/// half there or briefly readable by others.
fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<(), Failure> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let fail = |e: std::io::Error| {
        Failure::new(
            "configure",
            format!("could not write {}: {e}", path.display()),
        )
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = path.with_file_name(format!(".{file_name}.tmp"));
    let _ = std::fs::remove_file(&temp);

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)
        .and_then(|mut f| {
            f.write_all(contents.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&temp, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            fail(e)
        })
}

async fn unit_active(unit: &str) -> bool {
    tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .chain(["/usr/bin".into(), "/usr/local/bin".into()])
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(json: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(json)
    }

    #[test]
    fn a_token_names_its_tunnel() {
        let raw = token(
            r#"{"a":"6f1c2d","t":"5D2A5E3B-8C1F-4B7A-9E0D-1A2B3C4D5E6F","s":"c2VjcmV0LXNlY3JldA=="}"#,
        );
        let checked = check_token(Some(&format!("  {raw}\n"))).unwrap();

        assert_eq!(checked.tunnel_id, "5d2a5e3b-8c1f-4b7a-9e0d-1a2b3c4d5e6f");
        assert_eq!(checked.value, raw);

        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"a":"6f1c2d","t":"5d2a5e3b-8c1f-4b7a-9e0d-1a2b3c4d5e6f","s":"secret"}"#);
        assert!(check_token(Some(&url_safe)).is_ok());
    }

    #[test]
    fn anything_else_is_refused_without_repeating_it() {
        let wrong: Vec<Option<String>> = vec![
            None,
            Some("".into()),
            Some("   ".into()),
            Some("not a token; rm -rf /".into()),
            Some("aGVsbG8=".into()),
            Some(token(r#"{"a":"x","t":"not-a-uuid","s":"y"}"#)),
            Some(token(
                r#"{"a":"","t":"5d2a5e3b-8c1f-4b7a-9e0d-1a2b3c4d5e6f","s":"y"}"#,
            )),
            Some(token(r#"{"t":"5d2a5e3b-8c1f-4b7a-9e0d-1a2b3c4d5e6f"}"#)),
        ];
        for raw in wrong {
            let failure = check_token(raw.as_deref()).err().unwrap();
            assert_eq!(failure.message, NOT_A_TOKEN);
        }

        let long = "A".repeat(4097);
        assert!(check_token(Some(&long)).is_err());
    }

    #[test]
    fn the_unit_reads_the_token_from_its_file() {
        let files = Files::new(Path::new("/etc/serveros"));
        let unit = unit_text(Path::new("/usr/bin/cloudflared"), &files.env);

        assert_eq!(files.env, PathBuf::from("/etc/serveros/tunnel.env"));
        assert_eq!(
            files.unit,
            PathBuf::from("/etc/systemd/system/serveros-tunnel.service")
        );
        assert!(unit.contains("Type=notify\n"));
        assert!(unit.contains("TimeoutStartSec=60\n"));
        assert!(unit.contains("EnvironmentFile=/etc/serveros/tunnel.env\n"));
        assert!(unit.contains("ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run\n"));
        assert!(unit.contains("Restart=on-failure\n"));
        assert!(unit.contains("WantedBy=multi-user.target\n"));
        assert!(!unit.contains("--token"));
        assert_eq!(env_text("abc"), "TUNNEL_TOKEN=abc\n");
    }

    #[test]
    fn cloudflared_comes_from_cloudflares_repository() {
        assert!(INSTALL_SCRIPT.contains("https://pkg.cloudflare.com/cloudflare-main.gpg"));
        assert!(INSTALL_SCRIPT.contains(
            "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main"
        ));
        assert!(INSTALL_SCRIPT.contains("https://pkg.cloudflare.com/cloudflared-ascii.repo"));
        assert!(INSTALL_SCRIPT.contains("install -y -q cloudflared"));
    }

    #[test]
    fn private_files_are_written_whole_and_root_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tunnel.env");
        write_atomic(&path, "TUNNEL_TOKEN=one\n", 0o600).unwrap();
        write_atomic(&path, "TUNNEL_TOKEN=two\n", 0o600).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "TUNNEL_TOKEN=two\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
