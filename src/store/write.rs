//! The single writer (SPEC §6.3).
//!
//! One task owns the write connection; nothing else holds it. Handlers send a batch plus a reply
//! channel and await the real outcome, so the HTTP response reflects what actually happened rather
//! than what was hoped.

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

use crate::content_id::content_id;
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
///
/// Returns the number of rows actually stored, which is *not* the batch length when the batch
/// contains measurements already present: `id` is a content hash, so `INSERT OR IGNORE` makes a
/// re-upload a no-op (SPEC §6.6).
pub fn insert_batch(conn: &mut Connection, measurements: &[Measurement]) -> Result<usize> {
    if measurements.is_empty() {
        return Ok(0);
    }

    let mut stored = 0usize;
    let tx = conn.transaction().context("beginning write transaction")?;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO measurement \
                 (id, event_time, processed_time, type, body, attributes) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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

            // Derived from the measurement's own canonical encoding, not from the JSON written
            // above — the two must never be allowed to drift apart (SPEC §6.6).
            let id = content_id(m);

            stored += stmt
                .execute(rusqlite::params![
                    &id[..],
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

    if stored != measurements.len() {
        tracing::debug!(
            received = measurements.len(),
            stored,
            duplicates = measurements.len() - stored,
            "suppressed already-stored measurements"
        );
    }

    Ok(stored)
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

    fn row_count(c: &Connection) -> i64 {
        c.query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn inserts_a_batch_and_reports_the_count() {
        let mut c = conn();
        let n = insert_batch(&mut c, &[measurement("a", 1), measurement("b", 2)]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(row_count(&c), 2);
    }

    /// SPEC §6.6: re-uploading a measurement is a no-op, which is what makes the retryable 503 in
    /// §4.1 safe rather than a duplicate generator.
    #[test]
    fn reinserting_the_same_measurement_is_a_no_op() {
        let mut c = conn();
        let batch = [measurement("a", 1), measurement("b", 2)];

        assert_eq!(insert_batch(&mut c, &batch).unwrap(), 2);
        assert_eq!(insert_batch(&mut c, &batch).unwrap(), 0, "a retry must store nothing");
        assert_eq!(row_count(&c), 2);
    }

    /// A batch that is partly new must store exactly the new part.
    #[test]
    fn overlapping_batches_store_only_what_is_new() {
        let mut c = conn();
        insert_batch(&mut c, &[measurement("a", 1)]).unwrap();

        let stored = insert_batch(&mut c, &[measurement("a", 1), measurement("b", 2)]).unwrap();
        assert_eq!(stored, 1);
        assert_eq!(row_count(&c), 2);
    }

    /// Deduplication must not swallow genuinely distinct readings. A single nanosecond of
    /// difference is enough to make two measurements different.
    #[test]
    fn measurements_differing_only_by_one_nanosecond_both_store() {
        let mut c = conn();
        let stored = insert_batch(&mut c, &[measurement("a", 1), measurement("a", 2)]).unwrap();
        assert_eq!(stored, 2);
        assert_eq!(row_count(&c), 2);
    }

    /// The arrival time is not part of identity, so the same measurement delivered later is still
    /// the same measurement — and the stored row keeps its FIRST arrival time.
    #[test]
    fn a_later_redelivery_does_not_overwrite_the_original_arrival_time() {
        let mut c = conn();
        let mut first = measurement("a", 1);
        first.processed_time = 100;
        let mut again = measurement("a", 1);
        again.processed_time = 999;

        insert_batch(&mut c, &[first]).unwrap();
        assert_eq!(insert_batch(&mut c, &[again]).unwrap(), 0);

        let pt: i64 =
            c.query_row("SELECT processed_time FROM measurement", [], |r| r.get(0)).unwrap();
        assert_eq!(pt, 100, "OR IGNORE keeps the existing row, so first arrival wins");
    }

    /// The id stored must be exactly the one the pure function derives.
    #[test]
    fn stored_id_is_the_content_id() {
        let mut c = conn();
        let m = measurement("a", 1);
        insert_batch(&mut c, std::slice::from_ref(&m)).unwrap();

        let id: Vec<u8> = c.query_row("SELECT id FROM measurement", [], |r| r.get(0)).unwrap();
        assert_eq!(id, content_id(&m).to_vec());
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

        // Ordered by event_time, not id: id is a content hash now, so it carries no arrival order.
        let rows: Vec<Option<String>> = c
            .prepare("SELECT body FROM measurement ORDER BY event_time")
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
                     FROM measurement ORDER BY event_time DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(from_body, n, "body value changed");
            assert_eq!(from_attr, n, "attribute value changed");
        }
    }
}
