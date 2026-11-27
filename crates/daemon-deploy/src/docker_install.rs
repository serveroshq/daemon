//! Installing Docker Engine with its Compose and Buildx plugins, from
//! Docker's own package repository as docs.docker.com/engine/install sets it
//! up: apt on Debian, Ubuntu and their derivatives, dnf on Fedora and the
//! RHEL family. Docker then updates with the rest of the machine.

use std::time::Duration;

use daemon_jobs::{run_child, Failure, Progress};
use serde::Serialize;
use tokio::sync::watch;

use crate::preflight;

/// Everything a full install puts on the machine.
pub const PACKAGES: &[&str] = &[
    "docker-ce",
    "docker-ce-cli",
    "containerd.io",
    "docker-buildx-plugin",
    "docker-compose-plugin",
];

/// How the machine installs packages from Docker's repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Distro {
    /// `dist` is the repository's folder (ubuntu or debian), `codename` the
    /// release it's for (noble, bookworm…).
    Apt { dist: String, codename: String },
    /// `dist` is fedora, rhel or centos (Rocky, Alma and Oracle Linux use
    /// CentOS's).
    Dnf { dist: String },
}

fn field(os_release: &str, key: &str) -> Option<String> {
    os_release.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key)
            .then(|| v.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|v| !v.is_empty())
    })
}

fn unsupported(name: &str) -> Failure {
    Failure::new(
        "install",
        format!(
            "ServerOS installs Docker on Debian, Ubuntu, Fedora and the RHEL family, and this machine runs {name}"
        ),
    )
    .with_next_step("Install Docker yourself (docs.docker.com/engine/install), then try again.")
}

/// Which repository fits the machine, from `/etc/os-release`.
pub fn distro(os_release: &str) -> Result<Distro, Failure> {
    let id = field(os_release, "ID")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let like = field(os_release, "ID_LIKE")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let like: Vec<&str> = like.split_whitespace().collect();
    let name = field(os_release, "PRETTY_NAME")
        .or_else(|| field(os_release, "NAME"))
        .unwrap_or_else(|| {
            if id.is_empty() {
                "an unknown system".into()
            } else {
                id.clone()
            }
        });

    let apt = |dist: &str, codename: Option<String>| match codename {
        Some(codename) => Ok(Distro::Apt {
            dist: dist.into(),
            codename,
        }),
        None => Err(unsupported(&name)),
    };
    let ubuntu_codename =
        || field(os_release, "UBUNTU_CODENAME").or_else(|| field(os_release, "VERSION_CODENAME"));

    match id.as_str() {
        "ubuntu" => return apt("ubuntu", ubuntu_codename()),
        "debian" | "raspbian" => return apt("debian", field(os_release, "VERSION_CODENAME")),
        "fedora" => {
            return Ok(Distro::Dnf {
                dist: "fedora".into(),
            })
        }
        "rhel" => {
            return Ok(Distro::Dnf {
                dist: "rhel".into(),
            })
        }
        "centos" | "rocky" | "almalinux" | "ol" => {
            return Ok(Distro::Dnf {
                dist: "centos".into(),
            })
        }
        // Amazon Linux says it's like Fedora, but Docker's repository has
        // no packages for it.
        "amzn" => return Err(unsupported(&name)),
        _ => {}
    }
    if like.contains(&"ubuntu") {
        return apt("ubuntu", field(os_release, "UBUNTU_CODENAME"));
    }
    if like.contains(&"debian") {
        return apt("debian", field(os_release, "VERSION_CODENAME"));
    }
    if like.contains(&"rhel") || like.contains(&"centos") {
        return Ok(Distro::Dnf {
            dist: "centos".into(),
        });
    }
    if like.contains(&"fedora") {
        return Ok(Distro::Dnf {
            dist: "fedora".into(),
        });
    }
    Err(unsupported(&name))
}

/// The install, as Docker's docs do it. Its settings come in through the
/// environment (SOS_*), checked before, so nothing is pasted into the script.
/// A machine that already lists Docker's repository keeps its own entry.
const INSTALL_SCRIPT: &str = r#"set -eu
case "$SOS_PM" in
apt)
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update -q
  apt-get -o DPkg::Lock::Timeout=300 install -y -q ca-certificates curl
  if ! grep -rqs download.docker.com /etc/apt/sources.list /etc/apt/sources.list.d/; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$SOS_DIST/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    printf 'Types: deb\nURIs: https://download.docker.com/linux/%s\nSuites: %s\nComponents: stable\nSigned-By: /etc/apt/keyrings/docker.asc\n' "$SOS_DIST" "$SOS_CODENAME" > /etc/apt/sources.list.d/docker.sources
    apt-get -o DPkg::Lock::Timeout=300 update -q
  fi
  # shellcheck disable=SC2086
  apt-get -o DPkg::Lock::Timeout=300 install -y -q $SOS_PACKAGES
  ;;
dnf)
  if ! command -v dnf >/dev/null 2>&1; then
    echo "installing Docker needs dnf" >&2
    exit 3
  fi
  if ! grep -rqs download.docker.com /etc/yum.repos.d/; then
    curl -fsSL "https://download.docker.com/linux/$SOS_DIST/docker-ce.repo" -o /etc/yum.repos.d/docker-ce.repo
  fi
  # shellcheck disable=SC2086
  dnf install -y $SOS_PACKAGES
  ;;
*)
  echo "unknown package manager $SOS_PM" >&2
  exit 3
  ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl enable --now docker
fi
"#;

/// The script's settings for `distro`, installing `packages`.
pub(crate) fn script_env(distro: &Distro, packages: &[&str]) -> Vec<(&'static str, String)> {
    let packages = packages.join(" ");
    match distro {
        Distro::Apt { dist, codename } => vec![
            ("SOS_PM", "apt".into()),
            ("SOS_DIST", dist.clone()),
            ("SOS_CODENAME", codename.clone()),
            ("SOS_PACKAGES", packages),
        ],
        Distro::Dnf { dist } => vec![
            ("SOS_PM", "dnf".into()),
            ("SOS_DIST", dist.clone()),
            ("SOS_CODENAME", String::new()),
            ("SOS_PACKAGES", packages),
        ],
    }
}

/// A release codename as apt takes it, so nothing odd reaches the script.
fn plain_word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The `docker_install` job's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Installed {
    pub version: String,
    /// False when Docker was already running with both plugins.
    pub installed: bool,
}

static INSTALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The packages to install, given what's here: none when Docker runs with
/// both plugins, the missing plugins when Docker runs without them, and
/// everything otherwise.
pub(crate) fn needed(running: bool, compose: bool, buildx: bool) -> Vec<&'static str> {
    if !running {
        return PACKAGES.to_vec();
    }
    let mut packages = Vec::new();
    if !buildx {
        packages.push("docker-buildx-plugin");
    }
    if !compose {
        packages.push("docker-compose-plugin");
    }
    packages
}

pub async fn install(
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<Installed, Failure> {
    let _one_at_a_time = INSTALL.lock().await;

    progress.phase("check", Some(5)).await;
    let running = preflight::docker_version(cancel).await.ok();
    let compose = preflight::has_plugin("compose", cancel).await;
    let buildx = preflight::has_plugin("buildx", cancel).await;
    let packages = needed(running.is_some(), compose, buildx);
    if packages.is_empty() {
        let version = running.unwrap_or_default();
        progress
            .line(format!(
                "Docker {version} is already running, with Compose and Buildx"
            ))
            .await;
        return Ok(Installed {
            version,
            installed: false,
        });
    }

    let os_release = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    let distro = distro(&os_release)?;
    if let Distro::Apt { codename, .. } = &distro {
        if !plain_word(codename) {
            return Err(unsupported(codename));
        }
    }

    progress.phase("install", Some(20)).await;
    progress
        .line(match &running {
            Some(version) => format!(
                "Docker {version} is running; adding {} from Docker's package repository",
                packages.join(" and ")
            ),
            None => "installing Docker Engine, Compose and Buildx from Docker's package repository"
                .to_string(),
        })
        .await;
    let env = script_env(&distro, &packages);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let outcome = run_child(
        "sh",
        &["-c", INSTALL_SCRIPT],
        None,
        &env,
        Duration::from_secs(15 * 60),
        cancel,
        progress,
        None,
    )
    .await;
    if !outcome.success() {
        if matches!(outcome, daemon_jobs::ChildOutcome::Cancelled { .. }) {
            return Err(Failure::new("cancelled", "Docker install cancelled")
                .with_output(outcome.tail().to_vec()));
        }
        return Err(Failure::new("install", "could not install Docker")
            .with_output(outcome.tail().to_vec())
            .with_next_step(
                "Install Docker yourself (docs.docker.com/engine/install), then try again.",
            ));
    }

    progress.phase("verify", Some(90)).await;
    let mut version = None;
    for _ in 0..30 {
        if let Ok(v) = preflight::docker_version(cancel).await {
            version = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let version = version.ok_or_else(|| {
        Failure::new("install", "Docker was installed but isn't running")
            .with_next_step("Check it on the machine with `systemctl status docker`.")
    })?;
    for (plugin, name) in [("compose", "Compose"), ("buildx", "Buildx")] {
        if !preflight::has_plugin(plugin, cancel).await {
            progress
                .line(format!(
                    "Docker {name} still isn't answering after the install"
                ))
                .await;
        }
    }
    progress.line(format!("Docker {version} is running")).await;
    Ok(Installed {
        version,
        installed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apt(dist: &str, codename: &str) -> Distro {
        Distro::Apt {
            dist: dist.into(),
            codename: codename.into(),
        }
    }

    fn dnf(dist: &str) -> Distro {
        Distro::Dnf { dist: dist.into() }
    }

    #[test]
    fn picks_dockers_repository_for_the_machine() {
        let cases = [
            (
                "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n",
                apt("ubuntu", "noble"),
            ),
            (
                "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_CODENAME=bookworm\n",
                apt("debian", "bookworm"),
            ),
            (
                "NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble\n",
                apt("ubuntu", "noble"),
            ),
            (
                "NAME=\"Pop!_OS\"\nID=pop\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n",
                apt("ubuntu", "jammy"),
            ),
            (
                "ID=raspbian\nID_LIKE=debian\nVERSION_CODENAME=bookworm\n",
                apt("debian", "bookworm"),
            ),
            ("ID=fedora\nVERSION_ID=41\n", dnf("fedora")),
            ("ID=\"rhel\"\nID_LIKE=\"fedora\"\n", dnf("rhel")),
            ("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", dnf("centos")),
            ("ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n", dnf("centos")),
            ("ID=\"centos\"\nID_LIKE=\"rhel fedora\"\n", dnf("centos")),
            ("ID=\"ol\"\nID_LIKE=\"fedora\"\n", dnf("centos")),
            ("ID=nobara\nID_LIKE=\"fedora\"\n", dnf("fedora")),
        ];
        for (text, want) in cases {
            assert_eq!(distro(text).unwrap(), want, "{text}");
        }
    }

    #[test]
    fn other_systems_are_refused_with_a_next_step() {
        for text in [
            "PRETTY_NAME=\"Alpine Linux v3.20\"\nID=alpine\n",
            "NAME=\"Arch Linux\"\nID=arch\n",
            "PRETTY_NAME=\"Amazon Linux 2023\"\nID=\"amzn\"\nID_LIKE=\"fedora\"\n",
            "ID=ubuntu\n",
            "",
        ] {
            let failure = distro(text).unwrap_err();
            assert_eq!(failure.phase, "install");
            assert!(failure
                .message
                .starts_with("ServerOS installs Docker on Debian"));
            assert!(failure.next_step.unwrap().contains("docs.docker.com"));
        }
        assert!(distro("PRETTY_NAME=\"Alpine Linux v3.20\"\nID=alpine\n")
            .unwrap_err()
            .message
            .ends_with("runs Alpine Linux v3.20"));
    }

    #[test]
    fn installs_everything_or_only_whats_missing() {
        assert_eq!(needed(false, false, false), PACKAGES);
        assert_eq!(needed(false, true, true), PACKAGES);
        assert!(needed(true, true, true).is_empty());
        assert_eq!(needed(true, true, false), ["docker-buildx-plugin"]);
        assert_eq!(
            needed(true, false, false),
            ["docker-buildx-plugin", "docker-compose-plugin"]
        );
    }

    #[test]
    fn the_script_follows_dockers_docs_with_settings_from_the_environment() {
        assert!(INSTALL_SCRIPT.contains("https://download.docker.com/linux/$SOS_DIST/gpg"));
        assert!(INSTALL_SCRIPT.contains("Signed-By: /etc/apt/keyrings/docker.asc"));
        assert!(INSTALL_SCRIPT.contains("/linux/$SOS_DIST/docker-ce.repo"));
        assert!(INSTALL_SCRIPT.contains("systemctl enable --now docker"));
        assert!(INSTALL_SCRIPT.contains("grep -rqs download.docker.com"));

        let env = script_env(&apt("ubuntu", "noble"), PACKAGES);
        assert_eq!(env[0], ("SOS_PM", "apt".to_string()));
        assert_eq!(env[2], ("SOS_CODENAME", "noble".to_string()));
        assert_eq!(
            env[3].1,
            "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
        );
        let env = script_env(&dnf("centos"), &["docker-compose-plugin"]);
        assert_eq!(env[0].1, "dnf");
        assert_eq!(env[1].1, "centos");

        assert!(plain_word("bookworm") && plain_word("kali-rolling"));
        assert!(!plain_word("noble; rm -rf /") && !plain_word(""));

        let result = serde_json::to_value(Installed {
            version: "29.1.2".into(),
            installed: true,
        })
        .unwrap();
        assert_eq!(
            result,
            serde_json::json!({"version": "29.1.2", "installed": true})
        );
    }
}
