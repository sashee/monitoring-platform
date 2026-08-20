//! The `series` dimension table (SPEC §6.7): identity, bookkeeping, and the convergence sweep that
//! fills rows the write path did not.
//!
//! Two callers write here and they must agree exactly:
//!
//! - [`crate::store::write::insert_batch`], for measurements arriving now;
//! - [`backfill`], for rows already in the table — either predating 3.2, or written by a 3.1 binary
//!   the nightly auto-upgrade put back.
//!
//! Both go through [`Delta`] and [`upsert`], so there is one statement and one set of accumulation
//! rules rather than two that could drift.
//!
//! **Why a sweep rather than a step in the migration.** A one-shot fill would leave a hole, and not
//! at the head of the table where it could be noticed: 3.2 migrates and fills, the nightly reverts to
//! 3.1, that binary *starts fine* — the entire point of a minor version — and every row it writes
//! gets a NULL `series_id` and no `series` row. Rolling forward then leaves an arbitrary interior
//! range unfilled with nothing marking it. So the invariant is not "the migration filled it" but **a
//! 3.2 binary running drives the gap to zero**, which is what this module implements.
//!
//! **This whole module is transitional and is deleted at 4.0.** It exists to cover the window in which
//! a binary that does not write `series_id` can still run. That window closes once 3.3 reaches the host
//! through the pipeline: from then on the nightly upgrade can only revert to 3.3, so nothing in
//! circulation writes an unassigned row, the queue converges once and stays empty, and 4.0 inherits a
//! fully-assigned table. 4.0 therefore needs no fill — it checks the queue is empty and drops this,
//! `pending`, `measurement_backfill_idx` and the note on `/` together (SPEC §6.7).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde_json::{Map, Value};
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
    /// The serialised attributes, passed in rather than re-serialised, so `series.attributes` is
    /// byte-identical to `measurement.attributes` by construction. Phase two's column drop is only
    /// lossless because of that.
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
    /// `min`/`max` rather than assignment: neither a batch nor the backfill's scan is ordered by time,
    /// so assignment would make the result depend on which row happened to come first. `kind` and
    /// `attributes` are left alone — they are what the two deltas agree on by definition of the key.
    fn merge(&mut self, other: &Delta) {
        self.added += other.added;
        self.event_min = self.event_min.min(other.event_min);
        self.event_max = self.event_max.max(other.event_max);
        self.processed_min = self.processed_min.min(other.processed_min);
        self.processed_max = self.processed_max.max(other.processed_max);
    }
}

/// Adds a delta to a map, merging when the series is already there.
fn fold(deltas: &mut BTreeMap<ContentId, Delta>, id: ContentId, delta: Delta) {
    match deltas.get_mut(&id) {
        Some(existing) => existing.merge(&delta),
        None => {
            deltas.insert(id, delta);
        }
    }
}

/// Accumulates one row into a delta map, keyed by series id.
///
/// `BTreeMap` rather than `HashMap` so the upserts run in a deterministic order, which keeps a test's
/// expectations stable and makes lock acquisition order predictable.
///
/// Returns the series id, because the caller needs it for the measurement row itself.
pub fn accumulate(
    deltas: &mut BTreeMap<ContentId, Delta>,
    kind: &str,
    attributes_json: &str,
    attributes: &Map<String, Value>,
    event_time: i64,
    processed_time: i64,
) -> ContentId {
    let id = series_id(kind, attributes);
    fold(
        deltas,
        id,
        Delta::single(kind.to_owned(), attributes_json.to_owned(), event_time, processed_time),
    );
    id
}

/// The series id a measurement belongs to, without going through a delta map.
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

/// How many measurements are still waiting for a `series_id`.
///
/// An index probe, not a scan: `measurement_backfill_idx` is partial on exactly this predicate, so
/// this costs O(unfilled) and collapses to ~nothing once the fill is done. Cheap enough to call on a
/// page render.
pub fn pending(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT count(*) FROM measurement WHERE series_id IS NULL", [], |r| r.get(0))
        .context("counting measurements without a series")
}

/// Every distinct `(type, attributes)` among the unassigned rows, with its aggregates.
///
/// **One scan, grouped in SQL.** This is what keeps the fill affordable: the deployed database has
/// 118,718 unassigned rows over 1,458 distinct pairs, so hashing and upserting per *group* is 81×
/// less work than per row. The aggregates come from SQL for the same reason — they are exactly the
/// per-group `count`/`min`/`max` that would otherwise be folded row by row in Rust.
///
/// Grouping by the attribute *text* rather than by series id is forced: SQLite cannot compute the
/// hash. Two texts that parse to the same map would therefore arrive as two groups; [`fold`] merges
/// their bookkeeping, and [`backfill`]'s final check catches the assignment consequence.
fn unassigned_groups(tx: &Connection) -> Result<BTreeMap<ContentId, Delta>> {
    let mut stmt = tx
        .prepare(
            "SELECT type, attributes, count(*), \
             min(event_time), max(event_time), min(processed_time), max(processed_time) \
             FROM measurement WHERE series_id IS NULL GROUP BY type, attributes",
        )
        .context("preparing the backfill scan")?;

    let rows = stmt
        .query_map([], |r| {
            Ok(Delta {
                kind: r.get(0)?,
                attributes: r.get(1)?,
                added: r.get(2)?,
                event_min: r.get(3)?,
                event_max: r.get(4)?,
                processed_min: r.get(5)?,
                processed_max: r.get(6)?,
            })
        })
        .context("scanning for measurements without a series")?;

    let mut deltas = BTreeMap::new();
    for row in rows {
        let delta = row.context("reading the backfill scan")?;

        // The one place a series id is derived from *stored JSON* rather than from the measurement the
        // ingest path built — see the 2.0 migration comment in `schema.rs` for why a second encoding
        // path is treated as a hazard, and `tests` below for the pin that the two agree.
        //
        // A parse failure fails the whole fill rather than skipping the group. Deliberate: the write
        // path serialises this column, so unparseable JSON means something else wrote it, and a
        // failure that leaves the rows queued and names them is better than one that quietly excludes
        // them from a table phase two will treat as complete.
        let attributes: Map<String, Value> = serde_json::from_str(&delta.attributes)
            .with_context(|| {
                format!("parsing stored attributes of a {} measurement", delta.kind)
            })?;

        fold(&mut deltas, series_id(&delta.kind, &attributes), delta);
    }
    Ok(deltas)
}

/// Assigns a series to every measurement that has none, returning how many rows were filled.
///
/// Called on every startup (SPEC §6.7). Idempotent — with nothing to do it is a single probe of a
/// partial index — and running it *always* is what makes a revert to a 3.1 binary self-heal instead of
/// leaving a permanent hole in the middle of the table.
///
/// **One transaction for the whole fill**, rather than resumable chunks. Chunking was measured at
/// 168 s against 19 s for this form on the deployed database: 118,718 single-row updates across 60
/// committing transactions, each triggering WAL checkpoints. At ~20 s the failure mode chunking
/// protected against — a power cut mid-fill — costs a clean rollback and a repeat on the next start,
/// which is a better trade than three minutes of startup every time.
pub fn backfill(conn: &mut Connection) -> Result<usize> {
    let remaining = pending(conn)?;
    if remaining == 0 {
        return Ok(0);
    }
    tracing::info!(remaining, "assigning a series to measurements written without one");

    let tx = conn.transaction().context("beginning the backfill transaction")?;

    let deltas = unassigned_groups(&tx)?;
    tracing::debug!(groups = deltas.len(), "distinct series among the unassigned rows");
    upsert(&tx, &deltas)?;

    // Set-wise, so SQLite assigns all 118k rows in one statement instead of one round trip each. The
    // correlation is on the attribute *text*, which is sound because `series.attributes` is written
    // from the very string the measurement column holds — by the write path and by `upsert` above
    // alike — and `series_type_attributes_idx` is what makes each lookup a probe rather than a scan.
    let filled = tx
        .execute(
            "UPDATE measurement SET series_id = \
             (SELECT s.id FROM series s \
              WHERE s.type = measurement.type AND s.attributes = measurement.attributes) \
             WHERE series_id IS NULL",
            [],
        )
        .context("assigning series to measurements")?;

    // Inside the transaction, so a shortfall rolls the whole fill back rather than committing a
    // half-assigned table. The only way to get here is two attribute texts that parse to the same map:
    // they share a series id, so `upsert` keeps the first text and the second finds no match and stays
    // NULL. Nothing the write path produces can do that — it serialises from a sorted map — so this is
    // a report on something else having written the column, and leaving those rows queued and named is
    // the honest outcome.
    let left: i64 =
        tx.query_row("SELECT count(*) FROM measurement WHERE series_id IS NULL", [], |r| r.get(0))
            .context("re-checking the work queue")?;
    if left != 0 {
        anyhow::bail!(
            "{left} of {remaining} measurements could not be matched to a series and the fill was \
             rolled back; this means the `attributes` column holds JSON that was not written by this \
             receiver (two spellings of the same object)"
        );
    }

    tx.commit().context("committing the backfill")?;
    tracing::info!(filled, "series backfill complete");
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{schema, write};
    use serde_json::json;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
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

    /// A 3.1 binary's INSERT, verbatim: it does not name `series_id`, which is exactly why that column
    /// has to be nullable.
    fn insert_as_3_1(conn: &Connection, id: &[u8], kind: &str, attributes: &str, event: i64) {
        conn.execute(
            "INSERT INTO measurement (id, event_time, processed_time, type, body, attributes) \
             VALUES (?1, ?2, ?3, ?4, '{}', ?5)",
            params![id, event, event + 1_000, kind, attributes],
        )
        .unwrap();
    }

    fn stored_series_id(conn: &Connection, measurement_id: &[u8]) -> Option<Vec<u8>> {
        conn.query_row(
            "SELECT series_id FROM measurement WHERE id = ?1",
            [measurement_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn series_rows(conn: &Connection) -> i64 {
        conn.query_row("SELECT count(*) FROM series", [], |r| r.get(0)).unwrap()
    }

    fn added(conn: &Connection, id: &ContentId) -> i64 {
        conn.query_row("SELECT added_measurements FROM series WHERE id = ?1", [&id[..]], |r| {
            r.get(0)
        })
        .unwrap()
    }

    // ------------------------------------------------------------------------------- the fold

    #[test]
    fn rows_of_one_series_fold_into_one_delta() {
        let mut deltas = BTreeMap::new();
        let attrs = json!({"a": 1}).as_object().unwrap().clone();
        accumulate(&mut deltas, "t", "{\"a\":1}", &attrs, 500, 5_500);
        accumulate(&mut deltas, "t", "{\"a\":1}", &attrs, 100, 1_100);
        accumulate(&mut deltas, "t", "{\"a\":1}", &attrs, 300, 3_300);

        assert_eq!(deltas.len(), 1, "one series, one statement");
        let d = deltas.values().next().unwrap();
        assert_eq!((d.added, d.event_min, d.event_max), (3, 100, 500));
        assert_eq!((d.processed_min, d.processed_max), (1_100, 5_500));
    }

    /// The extents are `min`/`max`, not first/last: neither a batch nor the backfill's scan is ordered
    /// by time, so assignment would silently depend on arrival order.
    #[test]
    fn extents_do_not_depend_on_the_order_rows_are_folded() {
        let attrs = json!({"a": 1}).as_object().unwrap().clone();
        let fold = |times: &[(i64, i64)]| {
            let mut deltas = BTreeMap::new();
            for (e, p) in times {
                accumulate(&mut deltas, "t", "{\"a\":1}", &attrs, *e, *p);
            }
            deltas.into_values().next().unwrap()
        };

        assert_eq!(fold(&[(1, 10), (9, 90), (5, 50)]), fold(&[(9, 90), (5, 50), (1, 10)]));
    }

    #[test]
    fn different_attributes_fold_into_different_deltas() {
        let mut deltas = BTreeMap::new();
        let a = json!({"record.attributes.cell": 1}).as_object().unwrap().clone();
        let b = json!({"record.attributes.cell": 2}).as_object().unwrap().clone();
        accumulate(&mut deltas, "t", "{}", &a, 1, 2);
        accumulate(&mut deltas, "t", "{}", &b, 1, 2);
        assert_eq!(deltas.len(), 2);
    }

    // ------------------------------------------------------------------------------- the sweep

    /// **The rollback scenario, as a test.** A 3.1 binary starting against a 3.2 database must be able
    /// to write, and the rows it leaves behind must then be picked up without intervention.
    #[test]
    fn a_row_written_without_a_series_is_filled_by_the_sweep() {
        let mut c = conn();
        insert_as_3_1(&c, &[1u8; 16], "cpu", r#"{"record.attributes.core":0}"#, 1_000);

        assert_eq!(stored_series_id(&c, &[1u8; 16]), None, "a 3.1 insert leaves it NULL");
        assert_eq!(pending(&c).unwrap(), 1);

        assert_eq!(backfill(&mut c).unwrap(), 1);

        assert_eq!(pending(&c).unwrap(), 0);
        let expected = series_id(
            "cpu",
            &serde_json::from_str(r#"{"record.attributes.core":0}"#).unwrap(),
        );
        assert_eq!(stored_series_id(&c, &[1u8; 16]).as_deref(), Some(&expected[..]));
        assert_eq!(added(&c, &expected), 1);
    }

    /// The cross-check that matters most: the sweep derives an id from stored JSON, the write path
    /// derives it from the measurement it built. If those ever disagree, the same series would exist
    /// twice and phase two's join would split it.
    #[test]
    fn the_sweep_derives_the_same_id_as_the_write_path() {
        let mut c = conn();
        let m = measurement("bms.status.cell", 5_000, 7);
        write::insert_batch(&mut c, std::slice::from_ref(&m)).unwrap();
        let from_write_path = stored_series_id(&c, &crate::content_id::content_id(&m)).unwrap();

        // The same measurement as a 3.1 binary would have stored it, then swept.
        let attributes = serde_json::to_string(&m.attributes).unwrap();
        insert_as_3_1(&c, &[9u8; 16], &m.kind, &attributes, 6_000);
        backfill(&mut c).unwrap();
        let from_sweep = stored_series_id(&c, &[9u8; 16]).unwrap();

        assert_eq!(from_write_path, from_sweep);
        assert_eq!(series_rows(&c), 1, "they must be one series, not two");
    }

    /// Many rows of one series collapse to a single `series` row whose count is all of them — the
    /// grouped scan is what makes the fill affordable, so it has to aggregate rather than overwrite.
    #[test]
    fn many_rows_of_one_series_fill_into_one_row_with_the_full_count() {
        let attributes = r#"{"record.attributes.cell":3}"#;
        let expected = series_id("bms.status.cell", &serde_json::from_str(attributes).unwrap());

        let mut c = conn();
        for row in 0..5u8 {
            let mut id = [0u8; 16];
            id[0] = row;
            insert_as_3_1(&c, &id, "bms.status.cell", attributes, 1_000 + i64::from(row));
        }

        assert_eq!(backfill(&mut c).unwrap(), 5);
        assert_eq!(series_rows(&c), 1);
        assert_eq!(added(&c, &expected), 5);
        assert_eq!(pending(&c).unwrap(), 0);

        // And the extents span the whole set, taken from SQL's own min/max over the group.
        let (emin, emax): (i64, i64) = c
            .query_row(
                "SELECT added_event_time_min, added_event_time_max FROM series WHERE id = ?1",
                [&expected[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((emin, emax), (1_000, 1_004));
    }

    /// A fill spanning several series in one pass — the shape the real database has, 1,458 groups over
    /// 118k rows — must not cross-assign.
    #[test]
    fn one_pass_fills_many_series_without_crossing_them() {
        let mut c = conn();
        for cell in 0..4u8 {
            for row in 0..3u8 {
                let mut id = [0u8; 16];
                id[0] = cell;
                id[1] = row;
                insert_as_3_1(
                    &c,
                    &id,
                    "bms.status.cell",
                    &format!(r#"{{"record.attributes.cell":{cell}}}"#),
                    1_000 + i64::from(row),
                );
            }
        }

        assert_eq!(backfill(&mut c).unwrap(), 12);
        assert_eq!(series_rows(&c), 4);
        for cell in 0..4u8 {
            let attributes = format!(r#"{{"record.attributes.cell":{cell}}}"#);
            let id =
                series_id("bms.status.cell", &serde_json::from_str(&attributes).unwrap());
            assert_eq!(added(&c, &id), 3, "cell {cell}");
        }
    }

    /// **The fill rolls back rather than half-assigning.** Two attribute texts that parse to the same
    /// map share a series id, so the upsert keeps the first spelling and the second matches nothing.
    /// Nothing the write path emits can do this — it serialises from a sorted map — so the only honest
    /// outcome is to leave the rows queued, name the cause, and change nothing.
    #[test]
    fn two_spellings_of_one_object_are_refused_rather_than_partly_filled() {
        let mut c = conn();
        insert_as_3_1(&c, &[1u8; 16], "t", r#"{"a":1,"b":2}"#, 1_000);
        insert_as_3_1(&c, &[2u8; 16], "t", r#"{"b":2,"a":1}"#, 2_000);

        let err = backfill(&mut c).unwrap_err().to_string();
        assert!(err.contains("could not be matched to a series"), "unexpected error: {err}");

        // Rolled back whole: neither row assigned, and no series row left behind.
        assert_eq!(pending(&c).unwrap(), 2, "a partial commit would be worse than the error");
        assert_eq!(series_rows(&c), 0);
    }

    /// Idempotence is what lets this run on every startup.
    #[test]
    fn re_running_the_sweep_fills_nothing_and_changes_no_count() {
        let mut c = conn();
        insert_as_3_1(&c, &[1u8; 16], "cpu", "{}", 1_000);
        assert_eq!(backfill(&mut c).unwrap(), 1);

        let id = series_id("cpu", &Map::new());
        assert_eq!(backfill(&mut c).unwrap(), 0, "nothing left to do");
        assert_eq!(added(&c, &id), 1, "a second sweep must not re-count a filled row");
    }

    /// A second sweep over rows added *after* the first must accumulate onto the existing row rather
    /// than replace its aggregates — the case a reverted 3.1 binary produces, twice.
    #[test]
    fn a_later_sweep_accumulates_onto_what_an_earlier_one_left() {
        let mut c = conn();
        insert_as_3_1(&c, &[1u8; 16], "cpu", "{}", 5_000);
        backfill(&mut c).unwrap();

        insert_as_3_1(&c, &[2u8; 16], "cpu", "{}", 1_000);
        assert_eq!(backfill(&mut c).unwrap(), 1);

        let id = series_id("cpu", &Map::new());
        assert_eq!(added(&c, &id), 2);
        let emin: i64 = c
            .query_row("SELECT added_event_time_min FROM series WHERE id = ?1", [&id[..]], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(emin, 1_000, "the older row must widen the extent, not be ignored");
    }

    /// The mixed case a real deploy produces: rows already dual-written by 3.2, plus rows a reverted
    /// 3.1 left behind. They must land in one series whose count is the total.
    #[test]
    fn write_path_and_sweep_accumulate_into_the_same_series() {
        let mut c = conn();
        let m = measurement("bms.status.cell", 1_000, 4);
        write::insert_batch(&mut c, std::slice::from_ref(&m)).unwrap();

        let attributes = serde_json::to_string(&m.attributes).unwrap();
        insert_as_3_1(&c, &[7u8; 16], &m.kind, &attributes, 2_000);
        insert_as_3_1(&c, &[8u8; 16], &m.kind, &attributes, 3_000);
        backfill(&mut c).unwrap();

        let id = id_of(&m);
        assert_eq!(series_rows(&c), 1);
        assert_eq!(added(&c, &id), 3);

        // And the extents span both sources, not just the swept half.
        let (emin, emax): (i64, i64) = c
            .query_row(
                "SELECT added_event_time_min, added_event_time_max FROM series WHERE id = ?1",
                [&id[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((emin, emax), (1_000, 3_000));
    }

    #[test]
    fn an_empty_table_needs_no_sweep() {
        let mut c = conn();
        assert_eq!(pending(&c).unwrap(), 0);
        assert_eq!(backfill(&mut c).unwrap(), 0);
        assert_eq!(series_rows(&c), 0);
    }

    /// Rows the sweep must not choke on: no attributes at all, and a NULL body.
    #[test]
    fn edge_rows_are_filled_like_any_other() {
        let mut c = conn();
        c.execute(
            "INSERT INTO measurement (id, event_time, processed_time, type, body, attributes) \
             VALUES (x'0102030405060708090a0b0c0d0e0f10', 1, 2, 'bare', NULL, '{}')",
            [],
        )
        .unwrap();

        assert_eq!(backfill(&mut c).unwrap(), 1);
        assert_eq!(pending(&c).unwrap(), 0);
        assert_eq!(added(&c, &series_id("bare", &Map::new())), 1);
    }

    /// The queue is a partial index, so "how many are left" must not depend on a table scan — and once
    /// the fill is done the index has to be empty rather than merely unused.
    #[test]
    fn the_work_queue_is_empty_once_the_fill_is_done() {
        let mut c = conn();
        for row in 0..3u8 {
            let mut id = [0u8; 16];
            id[0] = row;
            insert_as_3_1(&c, &id, "cpu", "{}", 1_000 + i64::from(row));
        }
        backfill(&mut c).unwrap();

        let indexed: i64 = c
            .query_row(
                "SELECT count(*) FROM measurement INDEXED BY measurement_backfill_idx \
                 WHERE series_id IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(indexed, 0);
    }
}
