//! Uninstall and the manifest that makes it honest.
//!
//! Everything ServerOS creates outside its own directories is written to
//! `manifest.json` at the moment it is created: the systemd unit, the
//! Caddy import line, proxy includes, users, cron entries, deploy keys.
//! Uninstall removes exactly those, then its own directories, and prints
//! both lists. Customer services, data, apps, databases, and certificates
//! are never on the list, so they are never touched.

use std::path::{Path, PathBuf};

use daemon_core::Paths;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Artifact {
    File {
        path: PathBuf,
    },
    Directory {
        path: PathBuf,
    },
    /// A line ServerOS appended to a file it does not own.
    LineInFile {
        path: PathBuf,
        line: String,
    },
    SystemdUnit {
        name: String,
    },
    User {
        name: String,
    },
    CronEntry {
        path: PathBuf,
        marker: String,
    },
    Container {
        name: String,
    },
    Image {
        tag: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Manifest {
    pub created: Vec<Artifact>,
}

impl Manifest {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self).unwrap())
    }

    /// Record an artifact the moment it is made. Idempotent.
    pub fn record(path: &Path, artifact: Artifact) -> std::io::Result<()> {
        let mut manifest = Self::load(path);
        if !manifest.created.contains(&artifact) {
            manifest.created.push(artifact);
            manifest.save(path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub removed: Vec<String>,
    pub left_behind: Vec<String>,
    pub failed: Vec<String>,
}

impl Report {
    pub fn render(&self) -> String {
        let mut out = String::from("ServerOS has been removed.\n\nRemoved:\n");
        for r in &self.removed {
            out.push_str(&format!("  - {r}\n"));
        }
        if self.removed.is_empty() {
            out.push_str("  (nothing)\n");
        }
        out.push_str("\nLeft exactly as it was:\n");
        for l in &self.left_behind {
            out.push_str(&format!("  - {l}\n"));
        }
        if !self.failed.is_empty() {
            out.push_str("\nCould not remove (do this by hand):\n");
            for f in &self.failed {
                out.push_str(&format!("  - {f}\n"));
            }
        }
        out
    }
}

/// Plan the removal without doing it: what would go, what would stay.
pub fn plan(paths: &Paths, manifest: &Manifest, managed_services: &[String]) -> Report {
    let mut report = Report::default();

    for artifact in &manifest.created {
        report.removed.push(describe(artifact));
    }

    report
        .removed
        .push(format!("systemd unit {}", paths.systemd_unit().display()));
    report
        .removed
        .push(format!("binary {}", paths.binary.display()));
    report.removed.push(format!(
        "config and credentials in {}",
        paths.config_dir.display()
    ));
    report.removed.push(format!(
        "state, job workspaces, and local backup staging in {}",
        paths.state_dir.display()
    ));
    report
        .removed
        .push(format!("logs in {}", paths.log_dir.display()));

    for service in managed_services {
        report
            .left_behind
            .push(format!("{service} (managed, now unmanaged; still running)"));
    }
    report.left_behind.push(
        "every service, app, database, container, and certificate ServerOS did not create".into(),
    );

    report
}

fn describe(artifact: &Artifact) -> String {
    match artifact {
        Artifact::File { path } => format!("file {}", path.display()),
        Artifact::Directory { path } => format!("directory {}", path.display()),
        Artifact::LineInFile { path, line } => format!("the line `{line}` in {}", path.display()),
        Artifact::SystemdUnit { name } => format!("systemd unit {name}"),
        Artifact::User { name } => format!("user {name}"),
        Artifact::CronEntry { path, marker } => {
            format!("cron entries marked `{marker}` in {}", path.display())
        }
        Artifact::Container { name } => format!("container {name}"),
        Artifact::Image { tag } => format!("image {tag}"),
    }
}

/// Remove an artifact. Returns a human line for the report.
pub fn remove_artifact(
    artifact: &Artifact,
    run: &dyn Fn(&str, &[&str]) -> bool,
) -> Result<String, String> {
    let label = describe(artifact);

    let ok = match artifact {
        Artifact::File { path } => !path.exists() || std::fs::remove_file(path).is_ok(),
        Artifact::Directory { path } => !path.exists() || std::fs::remove_dir_all(path).is_ok(),
        Artifact::LineInFile { path, line } => remove_line(path, line),
        Artifact::SystemdUnit { name } => {
            run("systemctl", &["disable", "--now", name]);
            let unit = PathBuf::from(format!("/etc/systemd/system/{name}"));
            let removed = !unit.exists() || std::fs::remove_file(&unit).is_ok();
            run("systemctl", &["daemon-reload"]);
            removed
        }
        Artifact::User { name } => run("userdel", &[name]),
        Artifact::CronEntry { path, marker } => remove_marked_lines(path, marker),
        Artifact::Container { name } => run("docker", &["rm", "-f", name]),
        Artifact::Image { tag } => run("docker", &["image", "rm", tag]),
    };

    if ok {
        Ok(label)
    } else {
        Err(label)
    }
}

fn remove_line(path: &Path, line: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return true;
    };
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| l.trim() != line.trim() && !l.contains("Added by ServerOS"))
        .collect();
    let mut out = kept.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    std::fs::write(path, out).is_ok()
}

fn remove_marked_lines(path: &Path, marker: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return true;
    };
    let kept: Vec<&str> = text.lines().filter(|l| !l.contains(marker)).collect();
    std::fs::write(path, kept.join("\n") + "\n").is_ok()
}

/// Remove the daemon's own directories, last.
pub fn remove_own(paths: &Paths) -> Vec<Result<String, String>> {
    let mut results = Vec::new();

    for (label, path) in [
        ("binary", paths.binary.clone()),
        ("previous binary", paths.binary.with_extension("previous")),
        ("failed binary", paths.binary.with_extension("failed")),
    ] {
        if path.exists() {
            results.push(
                std::fs::remove_file(&path)
                    .map(|_| format!("{label} {}", path.display()))
                    .map_err(|e| format!("{label} {}: {e}", path.display())),
            );
        }
    }

    for (label, dir) in [
        ("config", &paths.config_dir),
        ("state", &paths.state_dir),
        ("logs", &paths.log_dir),
        ("runtime", &paths.run_dir),
    ] {
        if dir.exists() {
            results.push(
                std::fs::remove_dir_all(dir)
                    .map(|_| format!("{label} {}", dir.display()))
                    .map_err(|e| format!("{label} {}: {e}", dir.display())),
            );
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_records_once_and_reports_what_would_go() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        Manifest::record(
            &path,
            Artifact::SystemdUnit {
                name: "serverosd.service".into(),
            },
        )
        .unwrap();
        Manifest::record(
            &path,
            Artifact::SystemdUnit {
                name: "serverosd.service".into(),
            },
        )
        .unwrap();
        Manifest::record(
            &path,
            Artifact::LineInFile {
                path: "/etc/caddy/Caddyfile".into(),
                line: "import /etc/caddy/serveros.d/*.caddy".into(),
            },
        )
        .unwrap();

        let manifest = Manifest::load(&path);
        assert_eq!(manifest.created.len(), 2);

        let report = plan(
            &Paths::default(),
            &manifest,
            &["systemd:nginx.service".into()],
        );
        assert!(report.removed.iter().any(|r| r.contains("Caddyfile")));
        assert!(report
            .left_behind
            .iter()
            .any(|l| l.contains("nginx") && l.contains("still running")));
        assert!(report.render().contains("Left exactly as it was"));
    }

    #[test]
    fn removes_only_the_line_it_added() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, "example.com {\n}\n\n# Added by ServerOS: per-service sites live in serveros.d.\nimport /etc/caddy/serveros.d/*.caddy\n").unwrap();

        let result = remove_artifact(
            &Artifact::LineInFile {
                path: caddyfile.clone(),
                line: "import /etc/caddy/serveros.d/*.caddy".into(),
            },
            &|_, _| true,
        );

        assert!(result.is_ok());
        assert_eq!(
            std::fs::read_to_string(&caddyfile).unwrap(),
            "example.com {\n}\n\n"
        );
    }

    #[test]
    fn remove_own_wipes_the_daemon_tree_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        for (d, _) in paths.owned_directories() {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        std::fs::write(&paths.binary, b"bin").unwrap();
        let customer = dir.path().join("srv/app/index.php");
        std::fs::create_dir_all(customer.parent().unwrap()).unwrap();
        std::fs::write(&customer, b"<?php").unwrap();

        let results = remove_own(&paths);

        assert!(results.iter().all(Result::is_ok));
        assert!(!paths.binary.exists());
        assert!(!paths.config_dir.exists());
        assert!(customer.exists());
    }
}
