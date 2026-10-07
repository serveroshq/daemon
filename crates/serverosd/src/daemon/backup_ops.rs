use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_backup::remote::{self, S3Target};
use daemon_backup::{Manifest, Strategy};
use daemon_jobs::{run_child, Failure, JobContext};
use daemon_protocol::BackupDestination;
use daemon_services::ManagedService;
use serde_json::{json, Value};
use tokio::process::Command;

use super::app::App;
use super::service_ops::container_of;

pub const RECEIVER_USER: &str = "serveros-backups";
const RECEIVER_HOME: &str = "/var/lib/serveros-backups";

const SFTP_SERVERS: &[&str] = &[
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/sftp-server",
];

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
/// go by what they mount, read now; everything else by what's known about it.
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

    let paths = container_mounts(container).await?;
    if paths.is_empty() {
        return Err(Failure::new(
            "backup",
            format!("{} keeps no data outside its container", service.name),
        )
        .with_next_step("There is nothing to back up; redeploying it gets it back."));
    }

    Ok(Strategy::Files { paths })
}

/// Like `strategy_for`, but None when there's simply nothing to copy, so a
/// deploy can snapshot what has data and pass over what doesn't.
pub async fn data_strategy(service: &ManagedService) -> Result<Option<Strategy>, Failure> {
    match container_of(service) {
        None => Ok(Strategy::for_service(service)),
        Some(container) => {
            let paths = container_mounts(container).await?;
            Ok((!paths.is_empty()).then_some(Strategy::Files { paths }))
        }
    }
}

async fn container_mounts(container: &str) -> Result<Vec<PathBuf>, Failure> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{range .Mounts}}{{.Source}}\n{{end}}",
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

    Ok(mount_paths(&String::from_utf8_lossy(&output.stdout)))
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

pub async fn receiver(public_key: &str) -> Result<Value, Failure> {
    if !super::machine::valid_public_key(public_key) {
        return Err(Failure::new(
            "receiver",
            "that is not a public key ServerOS recognises",
        ));
    }
    let sftp_server = SFTP_SERVERS
        .iter()
        .find(|p| Path::new(p).is_file())
        .ok_or_else(|| {
            Failure::new("receiver", "OpenSSH's SFTP server is not installed")
                .with_next_step("Install openssh-server on this machine, then try again.")
        })?;

    if !user_exists(RECEIVER_USER).await {
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
        .await?;
    }
    run("usermod", &["-p", "*", RECEIVER_USER]).await?;

    let (uid, gid, home, _) = daemon_streams::pty::lookup(RECEIVER_USER)
        .ok_or_else(|| Failure::new("receiver", format!("user {RECEIVER_USER} is missing")))?;
    let ssh_dir = Path::new(&home).join(".ssh");
    let file = ssh_dir.join("authorized_keys");
    std::fs::create_dir_all(&ssh_dir).map_err(|e| Failure::new("receiver", e.to_string()))?;

    let key = public_key
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let line = format!("restrict,command=\"{sftp_server}\" {key} serveros-backups");
    let existing = std::fs::read_to_string(&file).unwrap_or_default();
    if !existing.lines().any(|l| l.contains(&key)) {
        let mut contents = existing.trim_end().to_string();
        if !contents.is_empty() {
            contents.push('\n');
        }
        contents.push_str(&line);
        contents.push('\n');
        std::fs::write(&file, contents).map_err(|e| Failure::new("receiver", e.to_string()))?;
    }

    for (path, mode) in [
        (Path::new(&home), 0o750),
        (ssh_dir.as_path(), 0o700),
        (file.as_path(), 0o600),
    ] {
        let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
        let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode));
    }

    let host_key = ["ed25519", "ecdsa", "rsa"].iter().find_map(|kind| {
        std::fs::read_to_string(format!("/etc/ssh/ssh_host_{kind}_key.pub"))
            .ok()
            .map(|k| k.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
    });

    Ok(json!({
        "user": RECEIVER_USER,
        "home": home,
        "host_key": host_key,
    }))
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

    #[test]
    fn objects_go_under_the_prefix_service_and_snapshot() {
        assert_eq!(
            object_base("/workspace/machine/", "serveros-mc", "1700-daily"),
            "workspace/machine/serveros-mc/1700-daily"
        );
        assert_eq!(object_base("", "a b", "1"), "a-b/1");
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
