//! What's using a machine's disk, read-only: the biggest folders on one
//! filesystem, how full it is, the systemd journal and what Docker could
//! reclaim. Nothing is deleted; the panel turns this into suggestions.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use daemon_jobs::Failure;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Folders this deep under the path are listed.
const DEPTH: u32 = 3;
/// Biggest folders reported.
const TOP: usize = 30;
/// Longest a scan runs; a huge disk reports what it got through.
const SCAN_LIMIT: Duration = Duration::from_secs(45);
/// Folders smaller than this aren't worth listing.
const MIN_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Serialize)]
pub struct DiskUsage {
    pub path: String,
    pub total: Option<u64>,
    pub used: Option<u64>,
    pub available: Option<u64>,
    pub dirs: Vec<Dir>,
    /// The scan stopped at its time limit, so folders may be missing.
    pub partial: bool,
    pub seconds: f64,
    pub journal: Option<u64>,
    pub docker: Option<Vec<DockerUsage>>,
}

#[derive(Serialize)]
pub struct Dir {
    pub path: String,
    pub bytes: u64,
}

#[derive(Serialize)]
pub struct DockerUsage {
    pub kind: String,
    pub count: String,
    pub active: String,
    pub size: String,
    pub reclaimable: String,
}

/// Checks a path asked for: absolute, no `..`, and a folder.
pub fn checked_path(path: Option<String>) -> Result<String, Failure> {
    let path = path.filter(|p| !p.is_empty()).unwrap_or_else(|| "/".into());
    if !path.starts_with('/') || path.split('/').any(|part| part == "..") {
        return Err(Failure::new(
            "disk",
            format!("{path} isn't an absolute path"),
        ));
    }
    if !Path::new(&path).is_dir() {
        return Err(Failure::new(
            "disk",
            format!("{path} isn't a folder on this machine"),
        ));
    }
    Ok(path)
}

pub async fn report(path: &str) -> Result<DiskUsage, Failure> {
    let started = Instant::now();
    let (total, used, available) = df(path).await;
    let (dirs, partial) = biggest(path).await?;

    Ok(DiskUsage {
        path: path.to_string(),
        total,
        used,
        available,
        dirs,
        partial,
        seconds: (started.elapsed().as_millis() as f64) / 1000.0,
        journal: if path == "/" { journal().await } else { None },
        docker: if path == "/" { docker().await } else { None },
    })
}

/// `du` over one filesystem, read as it goes so a scan cut short still
/// reports the folders it finished.
async fn biggest(path: &str) -> Result<(Vec<Dir>, bool), Failure> {
    let mut child = Command::new("du")
        .args(["-x", "-B1", "-d", &DEPTH.to_string(), path])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Failure::new("disk", format!("could not run du: {e}")))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();
    let mut dirs = Vec::new();

    let read = async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(dir) = parse_du(&line) {
                dirs.push(dir);
            }
        }
    };
    let partial = tokio::time::timeout(SCAN_LIMIT, read).await.is_err();
    let _ = child.kill().await;

    Ok((top(dirs, path), partial))
}

fn parse_du(line: &str) -> Option<Dir> {
    let (bytes, path) = line.split_once('\t')?;
    Some(Dir {
        path: path.to_string(),
        bytes: bytes.trim().parse().ok()?,
    })
}

/// The biggest folders, leaving out the scanned path itself (that's `used`).
fn top(mut dirs: Vec<Dir>, root: &str) -> Vec<Dir> {
    dirs.retain(|d| d.path != root && d.bytes >= MIN_BYTES);
    dirs.sort_by_key(|d| std::cmp::Reverse(d.bytes));
    dirs.truncate(TOP);
    dirs
}

async fn df(path: &str) -> (Option<u64>, Option<u64>, Option<u64>) {
    let Some(out) = output("df", &["-B1", "--output=size,used,avail", path]).await else {
        return (None, None, None);
    };
    let numbers: Vec<u64> = out
        .lines()
        .nth(1)
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    match numbers[..] {
        [size, used, avail] => (Some(size), Some(used), Some(avail)),
        _ => (None, None, None),
    }
}

/// Bytes the journal takes, from its folders (journalctl only prints a
/// rounded size).
async fn journal() -> Option<u64> {
    let out = output("du", &["-s", "-B1", "/var/log/journal", "/run/log/journal"]).await?;
    let total: u64 = out.lines().filter_map(parse_du).map(|d| d.bytes).sum();
    (total > 0).then_some(total)
}

async fn docker() -> Option<Vec<DockerUsage>> {
    let out = output("docker", &["system", "df", "--format", "{{json .}}"]).await?;
    let rows: Vec<DockerUsage> = out
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .map(|row| {
            let field = |name: &str| row[name].as_str().unwrap_or_default().to_string();
            DockerUsage {
                kind: field("Type"),
                count: field("TotalCount"),
                active: field("Active"),
                size: field("Size"),
                reclaimable: field("Reclaimable"),
            }
        })
        .collect();
    (!rows.is_empty()).then_some(rows)
}

async fn output(program: &str, args: &[&str]) -> Option<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .ok()?
    .ok()?;
    // du exits 1 when one of several paths is missing; its output still counts.
    (!result.stdout.is_empty()).then(|| String::from_utf8_lossy(&result.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn du_lines_are_read_and_the_biggest_kept() {
        let dirs = [
            "4096\t/tmp",
            "9663676416\t/var/lib/postgresql",
            "2468954112\t/var/log/journal",
            "20000000000\t/",
        ]
        .iter()
        .filter_map(|l| parse_du(l))
        .collect();
        let top = top(dirs, "/");
        assert_eq!(
            top.iter().map(|d| d.path.as_str()).collect::<Vec<_>>(),
            ["/var/lib/postgresql", "/var/log/journal"]
        );
    }

    #[test]
    fn only_absolute_folders_without_dotdot_are_scanned() {
        assert_eq!(checked_path(None).unwrap(), "/");
        assert!(checked_path(Some("var".into())).is_err());
        assert!(checked_path(Some("/var/../etc".into())).is_err());
        assert!(checked_path(Some("/definitely/not/here".into())).is_err());
    }
}
