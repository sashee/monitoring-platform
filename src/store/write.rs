//! The single writer (SPEC §6.3).
//!
//! One task owns the write connection; nothing else holds it. Handlers send a batch plus a reply
//! channel and await the real outcome, so the HTTP response reflects what actually happened rather
//! than what was hoped.

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

use crate::model::Measurement;

pub struct WriteRequest {
    pub measurements: Vec<Measurement>,
    /// `Err` carries a message rather than the error type, so the writer keeps the error and the
    /// handler gets something it can log and put in a `Status`.
    pub reply: oneshot::Sender<Result<usize, String>>,
}

#[derive(Clone)]
pub struct Writer(mpsc::Sender<WriteRequest>);

impl Writer {
    /// Sends a batch and waits for it to be committed.
    pub async fn write(&self, measurements: Vec<Measurement>) -> Result<usize, String> {
        let (reply, rx) = oneshot::channel();
        self.0
            .send(WriteRequest { measurements, reply })
            .await
            .map_err(|_| "storage writer has shut down".to_owned())?;
        rx.await.map_err(|_| "storage writer dropped the request".to_owned())?
    }
}

/// Spawns the writer on a blocking thread and returns a handle plus its join handle.
///
/// Dropping every `Writer` clone closes the channel, which ends the loop and checkpoints WAL —
/// that is how graceful shutdown drains the queue.
pub fn spawn(conn: Connection) -> (Writer, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<WriteRequest>(64);

    let handle = tokio::task::spawn_blocking(move || {
        let mut conn = conn;
        while let Some(req) = rx.blocking_recv() {
            let result = insert_batch(&mut conn, &req.measurements).map_err(|e| {
                tracing::error!(error = %e, "batch insert failed");
                format!("{e:#}")
            });
            // A dropped receiver means the client went away mid-request; the rows are committed
            // regardless, which is the correct outcome.
            let _ = req.reply.send(result);
        }

        tracing::debug!("writer draining; checkpointing WAL");
        if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)") {
            tracing::warn!(error = %e, "WAL checkpoint on shutdown failed");
        }
    });

    (Writer(tx), handle)
}

/// Inserts a whole batch in one transaction, reusing one prepared statement.
pub fn insert_batch(conn: &mut Connection, measurements: &[Measurement]) -> Result<usize> {
    if measurements.is_empty() {
        return Ok(0);
    }

    let tx = conn.transaction().context("beginning write transaction")?;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO measurement (event_time, processed_time, type, body, attributes) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .context("preparing insert")?;

        for m in measurements {
            // Serialising here is what keeps the JSON columns valid by construction, so no
            // json_valid CHECK is needed on the table (SPEC §6).
            let body = m
                .body
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .context("serialising body")?;
            let attributes =
                serde_json::to_string(&m.attributes).context("serialising attributes")?;

            stmt.execute(rusqlite::params![
                m.event_time,
                m.processed_time,
                m.kind,
                body,
                attributes
            ])
            .context("inserting measurement")?;
        }
    }
    tx.commit().context("committing write transaction")?;

    Ok(measurements.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::schema;
    use serde_json::json;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::migrate(&conn).unwrap();
        conn
    }

    fn measurement(kind: &str, event_time: i64) -> Measurement {
        Measurement {
            event_time,
            processed_time: 2,
            kind: kind.to_owned(),
            body: Some(json!({"v": 1})),
            attributes: json!({"record.attributes.unit": "c"}).as_object().unwrap().clone(),
        }
    }

    #[test]
    fn inserts_a_batch_and_reports_the_count() {
        let mut c = conn();
        let n = insert_batch(&mut c, &[measurement("a", 1), measurement("b", 2)]).unwrap();
        assert_eq!(n, 2);
        let stored: i64 =
            c.query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap();
        assert_eq!(stored, 2);
    }

    #[test]
    fn empty_batch_is_a_no_op() {
        let mut c = conn();
        assert_eq!(insert_batch(&mut c, &[]).unwrap(), 0);
    }

    #[test]
    fn absent_body_is_stored_as_sql_null_distinct_from_json_null() {
        let mut c = conn();
        let mut absent = measurement("a", 1);
        absent.body = None;
        let mut unset = measurement("b", 2);
        unset.body = Some(serde_json::Value::Null);
        insert_batch(&mut c, &[absent, unset]).unwrap();

        let rows: Vec<Option<String>> = c
            .prepare("SELECT body FROM measurement ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![None, Some("null".to_owned())]);
    }

    /// SPEC §5.5: exactness must survive the round trip through storage, asserted on the integer
    /// rather than on JSON text so the test does not depend on serializer formatting.
    #[test]
    fn full_i64_range_survives_storage_and_json_extract() {
        let mut c = conn();
        for (i, n) in [i64::MIN, i64::MAX, 9_007_199_254_740_993i64].into_iter().enumerate() {
            let mut m = measurement("big", i as i64);
            m.body = Some(json!({"n": n}));
            m.attributes = json!({"record.attributes.id": n}).as_object().unwrap().clone();
            insert_batch(&mut c, &[m]).unwrap();

            let (from_body, from_attr): (i64, i64) = c
                .query_row(
                    "SELECT json_extract(body,'$.n'), json_extract(attributes,'$.\"record.attributes.id\"') \
                     FROM measurement ORDER BY id DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(from_body, n, "body value changed");
            assert_eq!(from_attr, n, "attribute value changed");
        }
    }
}
