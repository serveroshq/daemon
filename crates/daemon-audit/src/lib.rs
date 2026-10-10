use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use daemon_core::redact::redact;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("could not open {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not append to actions.log: {0}")]
    Write(std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub kind: &'static str,
    pub name: String,
    /// Where the request came from, written at the end of each line as
    /// key=value pairs: the panel job, and the MCP call that asked for it.
    pub context: Vec<(&'static str, String)>,
}

impl Actor {
    pub fn user(name: impl Into<String>) -> Self {
        Self {
            kind: "user",
            name: name.into(),
            context: Vec::new(),
        }
    }

    pub fn automation(name: impl Into<String>) -> Self {
        Self {
            kind: "automation",
            name: name.into(),
            context: Vec::new(),
        }
    }

    pub fn scheduler() -> Self {
        Self {
            kind: "scheduler",
            name: String::new(),
            context: Vec::new(),
        }
    }

    pub fn local(name: impl Into<String>) -> Self {
        Self {
            kind: "local",
            name: name.into(),
            context: Vec::new(),
        }
    }

    pub fn daemon() -> Self {
        Self {
            kind: "daemon",
            name: String::new(),
            context: Vec::new(),
        }
    }

    /// The same actor, with where the request came from.
    pub fn with(mut self, key: &'static str, value: impl Into<String>) -> Self {
        let value: String = value
            .into()
            .chars()
            .filter(|c| !c.is_control())
            .take(120)
            .collect();
        if !value.is_empty() {
            self.context.push((key, value));
        }
        self
    }

    fn column(&self) -> String {
        if self.name.is_empty() {
            self.kind.to_string()
        } else {
            format!("{} {}", self.kind, self.name)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Started,
    Ok,
    Failed,
    Refused,
}

impl Outcome {
    fn word(self) -> &'static str {
        match self {
            Outcome::Started => "started",
            Outcome::Ok => "ok",
            Outcome::Failed => "failed",
            Outcome::Refused => "refused",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry<'a> {
    pub actor: &'a Actor,
    pub action: &'a str,
    pub target: &'a str,
    pub outcome: Outcome,
    pub duration: Option<Duration>,
    pub note: Option<&'a str>,
}

pub struct AuditLog {
    file: Mutex<File>,
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| AuditError::Open {
                path: path.into(),
                source,
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
        }

        Ok(Self {
            file: Mutex::new(file),
            path: path.into(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, entry: Entry<'_>) -> Result<(), AuditError> {
        let line = format_line(&entry, OffsetDateTime::now_utc());
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        file.write_all(line.as_bytes()).map_err(AuditError::Write)?;
        file.flush().map_err(AuditError::Write)
    }

    pub fn around<T, E: std::fmt::Display>(
        &self,
        actor: &Actor,
        action: &str,
        target: &str,
        work: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let _ = self.record(Entry {
            actor,
            action,
            target,
            outcome: Outcome::Started,
            duration: None,
            note: None,
        });
        let started = std::time::Instant::now();
        let result = work();
        let duration = Some(started.elapsed());

        match &result {
            Ok(_) => {
                let _ = self.record(Entry {
                    actor,
                    action,
                    target,
                    outcome: Outcome::Ok,
                    duration,
                    note: None,
                });
            }
            Err(e) => {
                let note = e.to_string();
                let _ = self.record(Entry {
                    actor,
                    action,
                    target,
                    outcome: Outcome::Failed,
                    duration,
                    note: Some(&note),
                });
            }
        }

        result
    }
}

fn format_line(entry: &Entry<'_>, at: OffsetDateTime) -> String {
    let ts = at
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string());
    let mut line = format!(
        "{ts}  {:<28}  {:<20}  {:<32}  {}",
        entry.actor.column(),
        entry.action,
        entry.target,
        entry.outcome.word()
    );

    if let Some(d) = entry.duration {
        line.push_str(&format!("  ({:.1}s)", d.as_secs_f64()));
    }

    if let Some(note) = entry.note.filter(|n| !n.is_empty()) {
        line.push_str("  ");
        line.push_str(&redact(note).replace('\n', " "));
    }

    for (key, value) in &entry.actor.context {
        if value.chars().any(char::is_whitespace) {
            line.push_str(&format!("  {key}={value:?}"));
        } else {
            line.push_str(&format!("  {key}={value}"));
        }
    }

    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_says_which_job_and_which_mcp_call_asked() {
        let actor = Actor::user("dylan@serveros.com")
            .with("job", "4093bc88-f7f3-43cf-84f6-de582c53ece2")
            .with("via", "mcp")
            .with("client", "Claude Desktop")
            .with("tool", "restart_service")
            .with("call", "9b1d2c7e-0000-4000-8000-000000000001")
            .with("empty", "");
        let line = format_line(
            &Entry {
                actor: &actor,
                action: "service.restart",
                target: "nginx.service",
                outcome: Outcome::Ok,
                duration: None,
                note: None,
            },
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        );

        assert!(line.contains("  job=4093bc88-f7f3-43cf-84f6-de582c53ece2  via=mcp  client=\"Claude Desktop\"  tool=restart_service  call=9b1d2c7e-0000-4000-8000-000000000001\n"), "{line}");
        assert!(!line.contains("empty="));
    }

    #[test]
    fn lines_read_like_prose_not_json() {
        let actor = Actor::user("dylan@serveros.com");
        let line = format_line(
            &Entry {
                actor: &actor,
                action: "service.restart",
                target: "nginx.service",
                outcome: Outcome::Ok,
                duration: Some(Duration::from_millis(1234)),
                note: None,
            },
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        );

        assert!(line.starts_with("2027-01-15T08:00:00Z  user dylan@serveros.com"));
        assert!(line.contains("service.restart"));
        assert!(line.contains("nginx.service"));
        assert!(line.contains("ok  (1.2s)"));
        assert!(!line.contains('{'));
    }

    #[test]
    fn notes_are_redacted_and_single_line() {
        let actor = Actor::scheduler();
        let line = format_line(
            &Entry {
                actor: &actor,
                action: "deploy.env",
                target: "app",
                outcome: Outcome::Failed,
                duration: None,
                note: Some("wrote API_TOKEN=abc123\nthen died"),
            },
            OffsetDateTime::UNIX_EPOCH,
        );

        assert!(line.contains("API_TOKEN=[redacted] then died"));
        assert_eq!(line.matches('\n').count(), 1);
    }

    #[test]
    fn around_writes_start_and_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(&dir.path().join("actions.log")).unwrap();
        let actor = Actor::local("serverosd uninstall");

        let result: Result<u8, String> = log.around(&actor, "service.stop", "app.service", || {
            Err("unit not found".into())
        });

        assert_eq!(result, Err("unit not found".to_string()));

        let contents = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("started"));
        assert!(lines[1].contains("failed") && lines[1].contains("unit not found"));
    }
}
