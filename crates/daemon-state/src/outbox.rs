use rusqlite::params;

use crate::{Result, State};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    pub id: i64,
    pub created_at: i64,
    pub kind: String,
    pub payload: String,
}

impl State {
    pub fn outbox_push(&self, kind: &str, payload: &str) -> Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO outbox (created_at, kind, payload) VALUES (?1, ?2, ?3)",
                params![Self::now(), kind, payload],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn outbox_peek(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT id, created_at, kind, payload FROM outbox ORDER BY id LIMIT ?1")?;
            let rows = stmt.query_map(params![limit as i64], |r| {
                Ok(OutboxItem {
                    id: r.get(0)?,
                    created_at: r.get(1)?,
                    kind: r.get(2)?,
                    payload: r.get(3)?,
                })
            })?;

            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn outbox_ack(&self, ids: &[i64]) -> Result<()> {
        self.with(|c| {
            for id in ids {
                c.execute("DELETE FROM outbox WHERE id = ?1", params![id])?;
            }
            Ok(())
        })
    }

    pub fn outbox_len(&self) -> Result<usize> {
        self.with(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get::<_, i64>(0))? as usize)
        })
    }

    pub fn outbox_trim(&self, keep: usize) -> Result<usize> {
        self.with(|c| {
            Ok(c.execute(
                "DELETE FROM outbox WHERE id NOT IN (SELECT id FROM outbox ORDER BY id DESC LIMIT ?1)",
                params![keep as i64],
            )?)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_drain_in_order_and_only_when_acked() {
        let state = State::in_memory().unwrap();
        let first = state.outbox_push("job_update", "{\"a\":1}").unwrap();
        let second = state.outbox_push("event", "{\"b\":2}").unwrap();

        let peek = state.outbox_peek(10).unwrap();
        assert_eq!(
            peek.iter().map(|i| i.id).collect::<Vec<_>>(),
            vec![first, second]
        );

        state.outbox_ack(&[first]).unwrap();

        assert_eq!(state.outbox_peek(10).unwrap()[0].id, second);
        assert_eq!(state.outbox_len().unwrap(), 1);
    }

    #[test]
    fn trimming_keeps_the_newest() {
        let state = State::in_memory().unwrap();

        for i in 0..5 {
            state.outbox_push("event", &i.to_string()).unwrap();
        }

        assert_eq!(state.outbox_trim(2).unwrap(), 3);
        assert_eq!(
            state
                .outbox_peek(10)
                .unwrap()
                .iter()
                .map(|i| i.payload.as_str())
                .collect::<Vec<_>>(),
            vec!["3", "4"]
        );
    }
}
