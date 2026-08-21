//! The `series` dimension table (SPEC §6.7): identity and bookkeeping.
//!
//! Since 4.0 `measurement` carries neither `type` nor `attributes`; both live here, once per distinct
//! combination instead of once per row. On the database this replaced that was 1,458 rows standing in for
//! 120k, and half the file.
//!
//! [`crate::store::write::insert_batch`] is the only writer. It folds a batch into [`Delta`]s and applies
//! them with [`upsert`], which is what makes a batch spanning hundreds of rows of one series cost a single
//! statement.
//!
//! **What used to be here.** 3.2 and 3.3 carried a convergence sweep that assigned a series to rows
//! written before the column existed, or by a binary the nightly auto-upgrade had reverted to. It is gone,
//! and deliberately so: once 3.3 reached the host through the pipeline, every binary in circulation wrote
//! a `series_id`, so 4.0 inherited a fully-assigned table and could enforce that with `NOT NULL` and a
//! foreign key instead of repairing it at every startup. The `NOT NULL` is also what refuses a database
//! that never passed through 3.3 — nothing here could fill one, since minting a series row needs blake3
//! and SQL cannot hash.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::collections::BTreeMap;

use crate::content_id::{ContentId, series_id};
use crate::model::Measurement;

/// What one batch of measurements contributes to one series.
///
/// Pure data: no connection, no clock. Accumulating in memory first is what makes a batch spanning
/// 428 rows of one series cost a single `UPDATE` instead of 428 of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    pub kind: String,
    /// The serialised attributes, passed in rather than re-serialised here. `series` is now their only
    /// record, so what lands in the column is exactly the string the ingest path produced.
    pub attributes: String,
    pub added: i64,
    pub event_min: i64,
    pub event_max: i64,
    pub processed_min: i64,
    pub processed_max: i64,
}

impl Delta {
    /// One row's contribution.
    fn single(kind: String, attributes: String, event_time: i64, processed_time: i64) -> Self {
        Self {
            kind,
            attributes,
            added: 1,
            event_min: event_time,
            event_max: event_time,
            processed_min: processed_time,
            processed_max: processed_time,
        }
    }

    /// Folds another contribution to the *same* series in.
    ///
    /// `min`/`max` rather than assignment: a batch is not ordered by time, so assignment would make the
    /// result depend on which row happened to come first. `kind` and `attributes` are left alone — they
    /// are what the two deltas agree on by definition of the key.
    fn merge(&mut self, other: &Delta) {
        self.added += other.added;
        self.event_min = self.event_min.min(other.event_min);
        self.event_max = self.event_max.max(other.event_max);
        self.processed_min = self.processed_min.min(other.processed_min);
        self.processed_max = self.processed_max.max(other.processed_max);
    }
}

/// Accumulates one row into a delta map, merging when its series is already there.
///
/// Takes the id rather than deriving it, so [`id_of`] is the single place a series id comes from. It
/// used to derive its own, which was right while the 3.x backfill also called this with an id it did
/// not have — but it left the write path hashing every measurement's attributes twice, once for the
/// row and once for the bookkeeping.
///
/// `BTreeMap` rather than `HashMap` so the upserts run in a deterministic order, which keeps a test's
/// expectations stable and makes lock acquisition order predictable.
pub fn accumulate(
    deltas: &mut BTreeMap<ContentId, Delta>,
    id: ContentId,
    kind: &str,
    attributes_json: &str,
    event_time: i64,
    processed_time: i64,
) {
    let delta =
        Delta::single(kind.to_owned(), attributes_json.to_owned(), event_time, processed_time);
    match deltas.get_mut(&id) {
        Some(existing) => existing.merge(&delta),
        None => {
            deltas.insert(id, delta);
        }
    }
}

/// The series a measurement belongs to. The only place this is derived.
pub fn id_of(m: &Measurement) -> ContentId {
    series_id(&m.kind, &m.attributes)
}

/// Writes a batch of deltas, creating rows that do not exist and accumulating into those that do.
///
/// Must be called inside the caller's transaction: the count is only exact because a measurement can
/// never be stored without being counted, and that is a property of them sharing one commit.
///
/// The two-argument `min`/`max` are SQLite's scalar forms, not the aggregates. Every column is NOT
/// NULL and the insert always supplies a value, so there is no NULL case to consider.
pub fn upsert(conn: &Connection, deltas: &BTreeMap<ContentId, Delta>) -> Result<()> {
    if deltas.is_empty() {
        return Ok(());
    }

    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO series (id, type, attributes, added_measurements, \
             added_event_time_min, added_event_time_max, \
             added_processed_time_min, added_processed_time_max) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(id) DO UPDATE SET \
             added_measurements       = added_measurements + excluded.added_measurements, \
             added_event_time_min     = min(added_event_time_min,     excluded.added_event_time_min), \
             added_event_time_max     = max(added_event_time_max,     excluded.added_event_time_max), \
             added_processed_time_min = min(added_processed_time_min, excluded.added_processed_time_min), \
             added_processed_time_max = max(added_processed_time_max, excluded.added_processed_time_max)",
        )
        .context("preparing the series upsert")?;

    for (id, d) in deltas {
        stmt.execute(params![
            &id[..],
            d.kind,
            d.attributes,
            d.added,
            d.event_min,
            d.event_max,
            d.processed_min,
            d.processed_max
        ])
        .with_context(|| format!("upserting series {}", crate::content_id::to_hex(id)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{schema, write};
    use serde_json::json;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // `migrate` turns foreign keys on, which is what makes the constraint tests below meaningful
        // rather than vacuous — see the note on `schema::apply_foreign_keys`.
        schema::migrate(&conn).unwrap();
        conn
    }

    fn measurement(kind: &str, event_time: i64, cell: i64) -> Measurement {
        Measurement {
            event_time,
            processed_time: event_time + 1_000,
            kind: kind.to_owned(),
            body: Some(json!({"v": 1})),
            attributes: json!({"record.attributes.cell": cell}).as_object().unwrap().clone(),
        }
    }

    // ------------------------------------------------------------------------------- the fold

    #[test]
    fn rows_of_one_series_fold_into_one_delta() {
        let mut deltas = BTreeMap::new();
        let id = series_id("t", &json!({"a": 1}).as_object().unwrap().clone());
        accumulate(&mut deltas, id, "t", "{\"a\":1}", 500, 5_500);
        accumulate(&mut deltas, id, "t", "{\"a\":1}", 100, 1_100);
        accumulate(&mut deltas, id, "t", "{\"a\":1}", 300, 3_300);

        assert_eq!(deltas.len(), 1, "one series, one statement");
        let d = deltas.values().next().unwrap();
        assert_eq!((d.added, d.event_min, d.event_max), (3, 100, 500));
        assert_eq!((d.processed_min, d.processed_max), (1_100, 5_500));
    }

    /// The extents are `min`/`max`, not first/last: a batch is not ordered by time, so assignment would
    /// silently depend on arrival order.
    #[test]
    fn extents_do_not_depend_on_the_order_rows_are_folded() {
        let id = series_id("t", &json!({"a": 1}).as_object().unwrap().clone());
        let fold_all = |times: &[(i64, i64)]| {
            let mut deltas = BTreeMap::new();
            for (e, p) in times {
                accumulate(&mut deltas, id, "t", "{\"a\":1}", *e, *p);
            }
            deltas.into_values().next().unwrap()
        };

        assert_eq!(fold_all(&[(1, 10), (9, 90), (5, 50)]), fold_all(&[(9, 90), (5, 50), (1, 10)]));
    }

    #[test]
    fn different_attributes_fold_into_different_deltas() {
        let mut deltas = BTreeMap::new();
        let a = json!({"record.attributes.cell": 1}).as_object().unwrap().clone();
        let b = json!({"record.attributes.cell": 2}).as_object().unwrap().clone();
        accumulate(&mut deltas, series_id("t", &a), "t", "{}", 1, 2);
        accumulate(&mut deltas, series_id("t", &b), "t", "{}", 1, 2);
        assert_eq!(deltas.len(), 2);
    }

    // ------------------------------------------------------- the referential guarantee (4.0)

    /// **What `NOT NULL` alone does not cover.** Since 3.3 the read path joins `series` for every `type`
    /// and `attributes`, so a measurement pointing at a series that does not exist is *invisible* — the
    /// same silent under-reporting a NULL would cause, from a different mistake. Only the foreign key
    /// catches it, and it is worth pinning because the pragma that enforces it is per-connection and
    /// therefore forgettable.
    #[test]
    fn a_measurement_cannot_reference_a_series_that_does_not_exist() {
        let c = conn();
        let err = c
            .execute(
                "INSERT INTO measurement (id, event_time, processed_time, body, series_id) \
                 VALUES (x'0102030405060708090a0b0c0d0e0f10', 1, 2, '{}', x'ffffffffffffffffffffffffffffffff')",
                [],
            )
            .unwrap_err()
            .to_string();
        assert!(err.to_lowercase().contains("foreign key"), "unexpected error: {err}");
    }

    #[test]
    fn a_measurement_cannot_have_no_series_at_all() {
        let c = conn();
        let err = c
            .execute(
                "INSERT INTO measurement (id, event_time, processed_time, body, series_id) \
                 VALUES (x'0102030405060708090a0b0c0d0e0f10', 1, 2, '{}', NULL)",
                [],
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("NOT NULL"), "unexpected error: {err}");
    }

    /// The write path satisfies the key even though it inserts the measurement *before* the series row it
    /// references — which is only legal because the constraint is `DEFERRABLE INITIALLY DEFERRED`. That
    /// order is not incidental: `added_measurements` may only count rows the `INSERT OR IGNORE` actually
    /// stored, so the fold has to come after the insert.
    #[test]
    fn the_write_path_satisfies_the_deferred_key_despite_inserting_the_measurement_first() {
        let mut c = conn();
        let batch = [measurement("bms.status.cell", 1_000, 3), measurement("bms.status.cell", 2_000, 3)];
        assert_eq!(write::insert_batch(&mut c, &batch).unwrap(), 2);

        let dangling: i64 = c
            .query_row(
                "SELECT count(*) FROM measurement m LEFT JOIN series s ON s.id = m.series_id \
                 WHERE s.id IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dangling, 0);
    }

    /// A series with measurements cannot be deleted — `ON DELETE RESTRICT` by omission. Nothing does this
    /// today; it is the guarantee retention will have to work within rather than discover.
    #[test]
    fn a_series_still_holding_measurements_cannot_be_deleted() {
        let mut c = conn();
        let m = measurement("bms.status.cell", 1_000, 3);
        write::insert_batch(&mut c, std::slice::from_ref(&m)).unwrap();

        let err = c.execute("DELETE FROM series", []).unwrap_err().to_string();
        assert!(err.to_lowercase().contains("foreign key"), "unexpected error: {err}");
    }
}
