use rusqlite::params;

use crate::{Result, State};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSample {
    pub ts: i64,
    pub service: Option<String>,
    pub payload: String,
}

impl State {
    pub fn push_sample(&self, ts: i64, service: Option<&str>, payload: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO samples (ts, service, payload) VALUES (?1, ?2, ?3)",
                params![ts, service.unwrap_or(""), payload],
            )?;
            Ok(())
        })
    }

    pub fn samples_between(
        &self,
        from_ts: i64,
        to_ts: i64,
        limit: usize,
    ) -> Result<Vec<StoredSample>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT ts, service, payload FROM samples WHERE ts >= ?1 AND ts <= ?2 ORDER BY ts DESC LIMIT ?3",
            )?;
            let rows = stmt.query_map(params![from_ts, to_ts, limit as i64], |r| {
                let service: String = r.get(1)?;
                Ok(StoredSample { ts: r.get(0)?, service: (!service.is_empty()).then_some(service), payload: r.get(2)? })
            })?;

            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn oldest_sample_ts(&self) -> Result<Option<i64>> {
        self.with(|c| {
            Ok(c.query_row("SELECT MIN(ts) FROM samples", [], |r| {
                r.get::<_, Option<i64>>(0)
            })?)
        })
    }

    pub fn prune_samples(&self, before_ts: i64) -> Result<usize> {
        self.with(|c| Ok(c.execute("DELETE FROM samples WHERE ts < ?1", params![before_ts])?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_come_back_newest_first_within_the_window() {
        let state = State::in_memory().unwrap();

        for ts in [100, 110, 120, 130] {
            state
                .push_sample(ts, None, &format!("{{\"ts\":{ts}}}"))
                .unwrap();
        }
        state.push_sample(120, Some("nginx"), "{}").unwrap();

        let page = state.samples_between(105, 125, 10).unwrap();

        assert_eq!(
            page.iter().map(|s| s.ts).collect::<Vec<_>>(),
            vec![120, 120, 110]
        );
        assert!(page.iter().any(|s| s.service.as_deref() == Some("nginx")));
    }

    #[test]
    fn pruning_keeps_the_window() {
        let state = State::in_memory().unwrap();

        for ts in [100, 200, 300] {
            state.push_sample(ts, None, "{}").unwrap();
        }

        assert_eq!(state.prune_samples(250).unwrap(), 2);
        assert_eq!(state.oldest_sample_ts().unwrap(), Some(300));
    }
}
