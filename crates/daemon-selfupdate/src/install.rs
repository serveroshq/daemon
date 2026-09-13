//! Download, verify, swap. The old binary is kept as `serverosd.previous`
//! and a marker records the switch so the rollback guard can act if the
//! new binary never comes up.

use std::path::Path;

use daemon_http::{Client, Trust};
use tracing::info;

use crate::policy::Candidate;
use crate::rollback::Marker;
use crate::{verify, UpdateError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub from: String,
    pub to: String,
    pub previous_binary: std::path::PathBuf,
}

/// Fetch `candidate`, verify it, and put it in place of `binary`. The
/// running process is not restarted here; the caller exits so systemd
/// starts the new binary.
pub async fn install(
    binary: &Path,
    state_dir: &Path,
    current_version: &str,
    candidate: &Candidate,
    egress_ok: impl Fn(&str) -> bool,
) -> Result<Installed, UpdateError> {
    let host = url::host(&candidate.url)
        .ok_or_else(|| UpdateError::Refused(format!("{} is not a URL", candidate.url)))?;

    if !egress_ok(&host) {
        return Err(UpdateError::Refused(format!(
            "{host} is not a release host this daemon will download from"
        )));
    }

    info!(version = %candidate.version, url = %candidate.url, "downloading release");

    let client = Client::new(
        Trust::WebPki,
        format!("serverosd/{current_version} (update)"),
    )
    .with_timeout(std::time::Duration::from_secs(600));
    let response = client.get(&candidate.url).await?;

    if response.status != 200 {
        return Err(UpdateError::Refused(format!(
            "release download answered HTTP {}",
            response.status
        )));
    }

    verify::verify(&response.body, &candidate.sha256, &candidate.signature)?;

    let staged = binary.with_extension("new");
    let previous = binary.with_extension("previous");

    write_executable(&staged, &response.body)?;

    // Keep the old binary for rollback, then swap atomically.
    if binary.exists() {
        std::fs::rename(binary, &previous)?;
    }
    std::fs::rename(&staged, binary)?;

    Marker {
        from: current_version.into(),
        to: candidate.version.clone(),
        installed_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        attempts: 0,
    }
    .write(state_dir)?;

    info!(from = current_version, to = %candidate.version, "release installed; restarting to apply");

    Ok(Installed {
        from: current_version.into(),
        to: candidate.version.clone(),
        previous_binary: previous,
    })
}

fn write_executable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(())
}

mod url {
    pub fn host(url: &str) -> Option<String> {
        let rest = url.strip_prefix("https://")?;
        let end = rest.find(['/', ':', '?']).unwrap_or(rest.len());
        let host = &rest[..end];
        (!host.is_empty()).then(|| host.to_string())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn extracts_hosts_from_https_urls_only() {
        assert_eq!(
            super::url::host("https://releases.serveros.com/v1.2.0/serverosd-linux-amd64")
                .as_deref(),
            Some("releases.serveros.com")
        );
        assert_eq!(super::url::host("http://insecure/x"), None);
    }
}
