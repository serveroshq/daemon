//! Registry logins for one deploy. Docker reads them from a config folder
//! made for the job (DOCKER_CONFIG), not the machine's own, so nothing is
//! left behind in a `~/.docker/config.json`: the folder is under the run
//! directory (memory, not disk, on systemd machines) and removed when the
//! deploy ends, however it ends.

use std::path::{Path, PathBuf};

use base64::Engine;
use daemon_jobs::Failure;
use daemon_protocol::RegistryLogin;
use serde_json::{json, Map, Value};

/// Where Docker keeps Docker Hub's login. `docker login` with no server, or
/// with docker.io, writes it under this key, and pulls look it up there.
const DOCKER_HUB: &str = "https://index.docker.io/v1/";

/// Where plugins like buildx and compose live for the daemon's children
/// (their HOME), so a job's own config folder still finds them.
const PLUGINS: &str = "/var/lib/serveros/.docker/cli-plugins";

/// A Docker config folder holding one deploy's registry logins. Dropping it
/// deletes the folder.
#[derive(Debug)]
pub struct DockerConfig {
    dir: PathBuf,
}

impl DockerConfig {
    /// Write `logins` to `<root>/docker-auth/<job>`.
    pub fn write(root: &Path, job: &str, logins: &[RegistryLogin]) -> Result<Self, Failure> {
        let parent = root.join("docker-auth");
        create_private_dir(&parent)?;
        let config = Self {
            dir: parent.join(job),
        };
        let _ = std::fs::remove_dir_all(&config.dir);
        create_private_dir(&config.dir)?;

        let body = serde_json::to_vec_pretty(&config_json(logins)?)
            .map_err(|e| Failure::new("registry", e.to_string()))?;
        crate::deployer::write_private(&config.dir.join("config.json"), &body).map_err(|e| {
            Failure::new(
                "registry",
                format!("could not write the registry logins: {e}"),
            )
        })?;

        if Path::new(PLUGINS).is_dir() {
            let _ = std::os::unix::fs::symlink(PLUGINS, config.dir.join("cli-plugins"));
        }

        Ok(config)
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The DOCKER_CONFIG variable for a docker command.
    pub fn env(&self) -> (&'static str, &str) {
        ("DOCKER_CONFIG", self.dir.to_str().unwrap_or_default())
    }
}

impl Drop for DockerConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Remove logins a deploy left behind when the daemon stopped mid-way.
pub fn sweep(root: &Path) {
    let _ = std::fs::remove_dir_all(root.join("docker-auth"));
}

fn create_private_dir(dir: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .and_then(|_| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| {
            Failure::new(
                "registry",
                format!("could not create {}: {e}", dir.display()),
            )
        })
}

/// The server name Docker files a registry's login under.
pub fn server_key(host: &str) -> String {
    match host.trim().to_ascii_lowercase().as_str() {
        "docker.io" | "index.docker.io" | "registry-1.docker.io" | "hub.docker.com" => {
            DOCKER_HUB.to_string()
        }
        other => other.to_string(),
    }
}

fn config_json(logins: &[RegistryLogin]) -> Result<Value, Failure> {
    let mut auths = Map::new();
    for login in logins {
        let host = login.host.trim();
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
        if !valid_host {
            return Err(
                Failure::new("registry", format!("{host:?} isn't a registry address"))
                    .with_next_step("Use a host like ghcr.io or registry.example.com:5000."),
            );
        }
        if login.username.is_empty() || login.username.contains(':') || login.password.0.is_empty()
        {
            return Err(Failure::new(
                "registry",
                format!("the login for {host} needs a username (without a colon) and a password"),
            ));
        }
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", login.username, login.password.0));
        auths.insert(server_key(host), json!({ "auth": auth }));
    }

    Ok(json!({ "auths": auths }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_protocol::RepoToken;

    fn login(host: &str, username: &str, password: &str) -> RegistryLogin {
        RegistryLogin {
            host: host.into(),
            username: username.into(),
            password: RepoToken(password.into()),
        }
    }

    #[test]
    fn docker_hub_is_filed_where_docker_looks_for_it() {
        assert_eq!(server_key("docker.io"), DOCKER_HUB);
        assert_eq!(server_key("Index.Docker.io"), DOCKER_HUB);
        assert_eq!(server_key("ghcr.io"), "ghcr.io");
        assert_eq!(
            server_key("registry.example.com:5000"),
            "registry.example.com:5000"
        );
    }

    #[test]
    fn logins_are_written_to_a_private_folder_that_goes_when_dropped() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let config = DockerConfig::write(
            root.path(),
            "job-1",
            &[
                login("ghcr.io", "acme", "ghp_secret"),
                login("docker.io", "acme", "dckr_pat"),
            ],
        )
        .unwrap();
        let dir = config.path().to_path_buf();
        assert_eq!(dir, root.path().join("docker-auth").join("job-1"));
        assert_eq!(config.env().0, "DOCKER_CONFIG");

        let file = dir.join("config.json");
        let body: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let decode = |key: &str| {
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(body["auths"][key]["auth"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(decode("ghcr.io"), "acme:ghp_secret");
        assert_eq!(decode(DOCKER_HUB), "acme:dckr_pat");
        assert!(body.get("credsStore").is_none());
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        drop(config);
        assert!(!dir.exists());
    }

    #[test]
    fn bad_logins_are_turned_down_before_anything_is_written() {
        let root = tempfile::tempdir().unwrap();
        for bad in [
            login("ghcr.io/acme", "acme", "x"),
            login("", "acme", "x"),
            login("ghcr.io", "ac:me", "x"),
            login("ghcr.io", "acme", ""),
        ] {
            let failure = DockerConfig::write(root.path(), "job-2", &[bad]).unwrap_err();
            assert_eq!(failure.phase, "registry");
        }
    }

    #[test]
    fn the_sweep_removes_logins_left_behind() {
        let root = tempfile::tempdir().unwrap();
        let config =
            DockerConfig::write(root.path(), "job-3", &[login("ghcr.io", "a", "b")]).unwrap();
        let dir = config.path().to_path_buf();
        std::mem::forget(config);
        assert!(dir.exists());

        sweep(root.path());
        assert!(!root.path().join("docker-auth").exists());
    }
}
