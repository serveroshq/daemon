use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

pub mod jobs;
pub mod outbox;
pub mod samples;

pub use jobs::{JobRecord, JobStatus};
pub use outbox::OutboxItem;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state.db: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("state.db schema version {found} is newer than this daemon understands ({supported})")]
    TooNew { found: u32, supported: u32 },
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StateError>;

const SCHEMA_VERSION: u32 = 1;

pub struct State {
    conn: Mutex<Connection>,
}

impl State {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;

        let found: u32 = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        if found > SCHEMA_VERSION {
            return Err(StateError::TooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }

        if found < 1 {
            conn.execute_batch(
                "CREATE TABLE jobs (
                    id TEXT PRIMARY KEY,
                    received_at INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT,
                    started_at INTEGER,
                    finished_at INTEGER,
                    result TEXT,
                    error TEXT,
                    log TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX jobs_status ON jobs(status);
                CREATE TABLE samples (
                    ts INTEGER NOT NULL,
                    service TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL,
                    PRIMARY KEY (ts, service)
                );
                CREATE TABLE outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1');",
            )?;
        }

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        f(&conn)
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        self.with(|c| {
            Ok(
                c.query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
                    r.get(0)
                })
                .optional()?,
            )
        })
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                params![key, value],
            )?;
            Ok(())
        })
    }

    pub fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_round_trips() {
        let state = State::in_memory().unwrap();

        assert_eq!(state.kv_get("x").unwrap(), None);
        state.kv_set("x", "1").unwrap();
        state.kv_set("x", "2").unwrap();
        assert_eq!(state.kv_get("x").unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn opening_a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO meta VALUES ('schema_version', '99');").unwrap();
        }

        assert!(matches!(
            State::open(&path),
            Err(StateError::TooNew { found: 99, .. })
        ));
    }
}
