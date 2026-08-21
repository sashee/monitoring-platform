//! The single writer (SPEC §6.3).
//!
//! One task owns the write connection; nothing else holds it. Handlers send a batch plus a reply
//! channel and await the real outcome, so the HTTP response reflects what actually happened rather
//! than what was hoped.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};

use crate::content_id::content_id;
use crate::model::Measurement;
use crate::store::series;

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
///
/// Also maintains `series` (SPEC §6.7). A row is folded into the series bookkeeping **only if the
/// insert actually stored it** — counting before the insert would let a retried batch inflate
/// `added_measurements`, which is precisely the kind of untruth those column names exist to prevent.
/// Both writes share this one transaction, so a measurement can never be stored uncounted or counted
/// unstored.
pub fn insert_batch(conn: &mut Connection, measurements: &[Measurement]) -> Result<usize> {
    if measurements.is_empty() {
        return Ok(0);
    }

    let mut stored = 0usize;
    let mut deltas = BTreeMap::new();
    let tx = conn.transaction().context("beginning write transaction")?;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO measurement \
                 (id, event_time, processed_time, body, series_id) \
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
            // Still serialised, but it is `series.attributes` that receives it now — since 4.0
            // `measurement` has no attributes column of its own.
            let attributes =
                serde_json::to_string(&m.attributes).context("serialising attributes")?;

            // Derived from the measurement's own canonical encoding, not from the JSON written
            // above — the two must never be allowed to drift apart (SPEC §6.6).
            let id = content_id(m);
            let series = series::id_of(m);

            let inserted = stmt
                .execute(rusqlite::params![
                    &id[..],
                    m.event_time,
                    m.processed_time,
                    body,
                    &series[..]
                ])
                .context("inserting measurement")?;
            stored += inserted;

            if inserted > 0 {
                series::accumulate(
                    &mut deltas,
                    series,
                    &m.kind,
                    &attributes,
                    m.event_time,
                    m.processed_time,
                );
            }
        }

        series::upsert(&tx, &deltas)?;
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

    // ------------------------------------------------------------------------------- series (§6.7)

    fn series_row(c: &Connection, id: &crate::content_id::ContentId) -> (i64, i64, i64, i64, i64) {
        c.query_row(
            "SELECT added_measurements, added_event_time_min, added_event_time_max, \
             added_processed_time_min, added_processed_time_max FROM series WHERE id = ?1",
            [&id[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap()
    }

    fn series_count(c: &Connection) -> i64 {
        c.query_row("SELECT count(*) FROM series", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn measurements_of_one_series_share_one_series_row() {
        let mut c = conn();
        insert_batch(&mut c, &[measurement("a", 1), measurement("a", 2)]).unwrap();

        assert_eq!(series_count(&c), 1);
        let distinct: i64 = c
            .query_row("SELECT count(DISTINCT series_id) FROM measurement", [], |r| r.get(0))
            .unwrap();
        assert_eq!(distinct, 1, "both rows must point at it");
    }

    #[test]
    fn differing_attributes_make_separate_series() {
        let mut c = conn();
        let mut other = measurement("a", 2);
        other.attributes = json!({"record.attributes.unit": "f"}).as_object().unwrap().clone();
        insert_batch(&mut c, &[measurement("a", 1), other]).unwrap();
        assert_eq!(series_count(&c), 2);
    }

    #[test]
    fn differing_types_make_separate_series() {
        let mut c = conn();
        insert_batch(&mut c, &[measurement("a", 1), measurement("b", 1)]).unwrap();
        assert_eq!(series_count(&c), 2);
    }

    /// `series` is now the *only* record of a measurement's type and attributes, so what it stores has
    /// to be exactly what arrived — asserted on the text, since a JSON-equal but differently-serialised
    /// string would be a change in what is stored.
    #[test]
    fn a_series_stores_the_type_and_attributes_verbatim() {
        let mut c = conn();
        let mut m = measurement("gps", 1);
        m.attributes = json!({"z.last": 1, "a.first": 2, "record.attributes.unit": "wgs84"})
            .as_object()
            .unwrap()
            .clone();
        insert_batch(&mut c, std::slice::from_ref(&m)).unwrap();

        let (kind, attributes): (String, String) = c
            .query_row(
                "SELECT s.type, s.attributes FROM measurement m JOIN series s ON s.id = m.series_id",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(kind, "gps");
        assert_eq!(attributes, serde_json::to_string(&m.attributes).unwrap());
    }

    #[test]
    fn the_stored_series_id_is_the_one_the_pure_function_derives() {
        let mut c = conn();
        let m = measurement("a", 1);
        insert_batch(&mut c, std::slice::from_ref(&m)).unwrap();

        let stored: Vec<u8> =
            c.query_row("SELECT series_id FROM measurement", [], |r| r.get(0)).unwrap();
        assert_eq!(stored, series::id_of(&m).to_vec());
    }

    /// **The count must not be inflatable by a retry.** `id` is a content hash so a re-upload stores
    /// nothing (SPEC §6.6); if the series fold ran before the insert rather than after it, this batch
    /// would report six measurements where three arrived. That is exactly the untruth the `added_`
    /// naming promises against.
    #[test]
    fn a_reuploaded_batch_does_not_inflate_the_count() {
        let mut c = conn();
        let batch = [measurement("a", 1), measurement("a", 2), measurement("a", 3)];

        insert_batch(&mut c, &batch).unwrap();
        insert_batch(&mut c, &batch).unwrap();

        let id = series::id_of(&batch[0]);
        assert_eq!(series_row(&c, &id).0, 3, "a retry must not be counted");
    }

    /// A partly-new batch must count exactly the new part.
    #[test]
    fn an_overlapping_batch_counts_only_what_was_stored() {
        let mut c = conn();
        insert_batch(&mut c, &[measurement("a", 1)]).unwrap();
        insert_batch(&mut c, &[measurement("a", 1), measurement("a", 2)]).unwrap();

        assert_eq!(series_row(&c, &series::id_of(&measurement("a", 1))).0, 2);
    }

    /// The extents accumulate rather than overwrite, in both directions. A later batch carrying older
    /// measurements — a spool drained after a reboot, which this collector does — must widen the
    /// minimum and leave the maximum alone.
    #[test]
    fn extents_widen_and_are_never_narrowed() {
        let mut c = conn();
        // Both stamps move together here, so the assertions cover all four columns at once.
        let at = |event: i64| {
            let mut m = measurement("a", event);
            m.processed_time = event + 1_000;
            m
        };
        let id = series::id_of(&at(5_000));

        insert_batch(&mut c, &[at(5_000)]).unwrap();
        assert_eq!(series_row(&c, &id), (1, 5_000, 5_000, 6_000, 6_000));

        insert_batch(&mut c, &[at(9_000)]).unwrap();
        assert_eq!(series_row(&c, &id), (2, 5_000, 9_000, 6_000, 10_000), "max must extend");

        insert_batch(&mut c, &[at(1_000)]).unwrap();
        assert_eq!(series_row(&c, &id), (3, 1_000, 9_000, 2_000, 10_000), "min must extend");
    }

    /// `added_processed_time_*` must track `processed_time` and not `event_time`. A transposed
    /// parameter is otherwise invisible, since the two are usually close together.
    #[test]
    fn the_arrival_extents_track_processed_time_not_event_time() {
        let mut c = conn();
        let mut m = measurement("a", 1_000);
        m.processed_time = 999_000_000;
        insert_batch(&mut c, std::slice::from_ref(&m)).unwrap();

        let (_, emin, emax, pmin, pmax) = series_row(&c, &series::id_of(&m));
        assert_eq!((emin, emax), (1_000, 1_000));
        assert_eq!((pmin, pmax), (999_000_000, 999_000_000));
    }

    /// The bookkeeping is not part of the key — otherwise every measurement would mint its own series
    /// and the table would be worse than the duplication it replaces.
    #[test]
    fn timestamps_are_not_part_of_the_series_key() {
        let mut c = conn();
        let mut later = measurement("a", 90_000);
        later.processed_time = 500_000;
        insert_batch(&mut c, &[measurement("a", 1), later]).unwrap();
        assert_eq!(series_count(&c), 1);
    }

    /// A batch spanning many series — the `bms.status.cell` shape, 16 cells per flush — must attribute
    /// each row to its own series.
    #[test]
    fn a_batch_spanning_many_series_attributes_each_row_correctly() {
        let mut c = conn();
        let batch: Vec<_> = (0..16)
            .map(|cell| {
                let mut m = measurement("bms.status.cell", 1_000 + cell);
                m.attributes =
                    json!({"record.attributes.cell": cell}).as_object().unwrap().clone();
                m
            })
            .collect();
        insert_batch(&mut c, &batch).unwrap();

        assert_eq!(series_count(&c), 16);
        for m in &batch {
            assert_eq!(series_row(&c, &series::id_of(m)).0, 1);
        }
    }

    /// The invariant that holds only until something starts deleting rows — which is the entire reason
    /// these columns are named `added_*` rather than describing current contents.
    #[test]
    fn every_series_count_matches_the_rows_pointing_at_it() {
        let mut c = conn();
        let mut batch = vec![measurement("a", 1), measurement("a", 2), measurement("b", 3)];
        batch[2].attributes = json!({"record.attributes.unit": "k"}).as_object().unwrap().clone();
        insert_batch(&mut c, &batch).unwrap();

        let disagreeing: i64 = c
            .query_row(
                "SELECT count(*) FROM series s JOIN \
                 (SELECT series_id, count(*) n FROM measurement GROUP BY series_id) m \
                 ON m.series_id = s.id WHERE s.added_measurements <> m.n",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(disagreeing, 0);
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
                    "SELECT json_extract(m.body,'$.n'), \
                            json_extract(s.attributes,'$.\"record.attributes.id\"') \
                     FROM measurement m JOIN series s ON s.id = m.series_id \
                     ORDER BY m.event_time DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(from_body, n, "body value changed");
            assert_eq!(from_attr, n, "attribute value changed");
        }
    }
}
