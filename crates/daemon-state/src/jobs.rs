use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Result, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Accepted,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Refused,
    Cancelled,
}

impl JobStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, JobStatus::Accepted | JobStatus::Running)
    }

    fn as_str(self) -> &'static str {
        match self {
            JobStatus::Accepted => "accepted",
            JobStatus::Running => "running",
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timed_out",
            JobStatus::Refused => "refused",
            JobStatus::Cancelled => "cancelled",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "accepted" => JobStatus::Accepted,
            "running" => JobStatus::Running,
            "succeeded" => JobStatus::Succeeded,
            "timed_out" => JobStatus::TimedOut,
            "refused" => JobStatus::Refused,
            "cancelled" => JobStatus::Cancelled,
            _ => JobStatus::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub id: Uuid,
    pub received_at: i64,
    pub actor: String,
    pub kind: String,
    pub payload: String,
    pub status: JobStatus,
    pub phase: Option<String>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub log: String,
}

impl JobRecord {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
            received_at: row.get(1)?,
            actor: row.get(2)?,
            kind: row.get(3)?,
            payload: row.get(4)?,
            status: JobStatus::parse(&row.get::<_, String>(5)?),
            phase: row.get(6)?,
            started_at: row.get(7)?,
            finished_at: row.get(8)?,
            result: row.get(9)?,
            error: row.get(10)?,
            log: row.get(11)?,
        })
    }
}

const COLUMNS: &str = "id, received_at, actor, kind, payload, status, phase, started_at, finished_at, result, error, log";

impl State {
    pub fn record_job(&self, id: Uuid, actor: &str, kind: &str, payload: &str) -> Result<bool> {
        self.with(|c| {
            let inserted = c.execute(
                "INSERT OR IGNORE INTO jobs (id, received_at, actor, kind, payload, status) VALUES (?1, ?2, ?3, ?4, ?5, 'accepted')",
                params![id.to_string(), Self::now(), actor, kind, payload],
            )?;

            Ok(inserted == 1)
        })
    }

    pub fn job(&self, id: Uuid) -> Result<Option<JobRecord>> {
        self.with(|c| {
            Ok(c.query_row(
                &format!("SELECT {COLUMNS} FROM jobs WHERE id = ?1"),
                params![id.to_string()],
                JobRecord::from_row,
            )
            .optional()?)
        })
    }

    pub fn start_job(&self, id: Uuid) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE jobs SET status = 'running', started_at = ?2 WHERE id = ?1",
                params![id.to_string(), Self::now()],
            )?;
            Ok(())
        })
    }

    pub fn set_job_phase(&self, id: Uuid, phase: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE jobs SET phase = ?2 WHERE id = ?1",
                params![id.to_string(), phase],
            )?;
            Ok(())
        })
    }

    pub fn append_job_log(&self, id: Uuid, lines: &[String], keep: usize) -> Result<()> {
        self.with(|c| {
            let existing: String = c
                .query_row(
                    "SELECT log FROM jobs WHERE id = ?1",
                    params![id.to_string()],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or_default();
            let mut log = existing;

            for line in lines {
                log.push_str(line);
                log.push('\n');
            }

            if log.len() > keep {
                let cut = log.len() - keep;
                let boundary = if cut == 0 || log.as_bytes()[cut - 1] == b'\n' {
                    cut
                } else {
                    log[cut..].find('\n').map(|i| cut + i + 1).unwrap_or(cut)
                };
                log = log[boundary..].to_string();
            }

            c.execute(
                "UPDATE jobs SET log = ?2 WHERE id = ?1",
                params![id.to_string(), log],
            )?;
            Ok(())
        })
    }

    pub fn finish_job(
        &self,
        id: Uuid,
        status: JobStatus,
        result: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        debug_assert!(status.is_terminal());

        self.with(|c| {
            c.execute(
                "UPDATE jobs SET status = ?2, finished_at = ?3, result = ?4, error = ?5 WHERE id = ?1",
                params![id.to_string(), status.as_str(), Self::now(), result, error],
            )?;
            Ok(())
        })
    }

    pub fn unfinished_jobs(&self) -> Result<Vec<JobRecord>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!("SELECT {COLUMNS} FROM jobs WHERE status IN ('accepted', 'running') ORDER BY received_at"))?;
            let rows = stmt.query_map([], JobRecord::from_row)?;

            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn prune_jobs(&self, before_ts: i64) -> Result<usize> {
        self.with(|c| {
            Ok(c.execute(
                "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < ?1",
                params![before_ts],
            )?)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redelivery_is_detected_and_the_stored_result_survives() {
        let state = State::in_memory().unwrap();
        let id = Uuid::new_v4();

        assert!(state
            .record_job(id, "user dylan", "discover", "{}")
            .unwrap());
        state.start_job(id).unwrap();
        state
            .finish_job(id, JobStatus::Succeeded, Some("{\"services\": 3}"), None)
            .unwrap();

        assert!(!state
            .record_job(id, "user dylan", "discover", "{}")
            .unwrap());

        let job = state.job(id).unwrap().unwrap();
        assert_eq!(job.status, JobStatus::Succeeded);
        assert_eq!(job.result.as_deref(), Some("{\"services\": 3}"));
    }

    #[test]
    fn unfinished_jobs_are_found_after_a_restart() {
        let state = State::in_memory().unwrap();
        let running = Uuid::new_v4();
        let done = Uuid::new_v4();

        state
            .record_job(running, "scheduler", "backup", "{}")
            .unwrap();
        state.start_job(running).unwrap();
        state.record_job(done, "scheduler", "backup", "{}").unwrap();
        state
            .finish_job(done, JobStatus::Failed, None, Some("disk full"))
            .unwrap();

        let unfinished = state.unfinished_jobs().unwrap();

        assert_eq!(unfinished.len(), 1);
        assert_eq!(unfinished[0].id, running);
    }

    #[test]
    fn job_logs_are_capped_at_a_line_boundary() {
        let state = State::in_memory().unwrap();
        let id = Uuid::new_v4();
        state.record_job(id, "user", "deploy", "{}").unwrap();

        state
            .append_job_log(id, &["one".into(), "two".into(), "three".into()], 10)
            .unwrap();

        assert_eq!(state.job(id).unwrap().unwrap().log, "two\nthree\n");
    }
}
