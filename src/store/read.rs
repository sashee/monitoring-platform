//! Query building and row mapping for the read API (SPEC §7.1).
//!
//! SQL construction is a pure function so the predicate logic is testable without a database.

use anyhow::{Context, Result};
use rusqlite::{Connection, types::Value as SqlValue};

use crate::model::StoredMeasurement;

pub const DEFAULT_LIMIT: i64 = 100;
pub const MAX_LIMIT: i64 = 1000;

/// A validated query. Produced by the HTTP layer, consumed here.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuerySpec {
    /// Empty means no `type` filter. Multiple values match any of them.
    pub types: Vec<String>,
    /// Inclusive lower bound on `event_time`.
    pub from: Option<i64>,
    /// Exclusive upper bound on `event_time`.
    pub to: Option<i64>,
    /// Attribute equality filters, ANDed. Keys are full attribute keys, not JSON paths.
    pub attrs: Vec<(String, String)>,
    pub limit: i64,
    /// Keyset position: `(event_time, id)` of the last row of the previous page.
    pub cursor: Option<(i64, i64)>,
}

/// Builds the JSON path for one attribute key.
///
/// The key is *always* one whole literal key, never a path: OTLP keys legitimately contain dots,
/// so splitting on `.` would be ambiguous (SPEC §7.1). `"` and `\` must be escaped, and getting
/// that wrong fails *silently* in SQLite — `json_extract` returns NULL rather than erroring — so a
/// filter with an unescaped quote would match nothing instead of complaining. Hence a tested
/// function rather than inline formatting.
pub fn json_path(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    out.push_str("$.\"");
    for ch in key.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Builds the SELECT and its bound parameters.
///
/// Ordering is always `event_time DESC, id DESC`, matching both indexes, with `id` breaking ties so
/// pagination stays stable when timestamps collide.
pub fn build_query(spec: &QuerySpec) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        "SELECT id, event_time, processed_time, type, body, attributes FROM measurement",
    );
    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();

    if !spec.types.is_empty() {
        let placeholders = spec
            .types
            .iter()
            .map(|t| {
                params.push(SqlValue::Text(t.clone()));
                format!("?{}", params.len())
            })
            .collect::<Vec<_>>()
            .join(", ");
        where_clauses.push(format!("type IN ({placeholders})"));
    }

    if let Some(from) = spec.from {
        params.push(SqlValue::Integer(from));
        where_clauses.push(format!("event_time >= ?{}", params.len()));
    }
    if let Some(to) = spec.to {
        params.push(SqlValue::Integer(to));
        where_clauses.push(format!("event_time < ?{}", params.len()));
    }

    for (key, value) in &spec.attrs {
        params.push(SqlValue::Text(json_path(key)));
        let path_idx = params.len();
        params.push(SqlValue::Text(value.clone()));
        let value_idx = params.len();
        // Two things are load-bearing here:
        //
        // The json_type guard keeps nested values out. Without it, json_extract on an object
        // returns its serialized text, which would match if a caller typed that exact text — an
        // accidental API resting on SQLite's serialization, and one Postgres would break (SPEC §7.1).
        //
        // The CAST is required for the documented "compares as a string" semantics to hold at all:
        // json_extract yields an INTEGER for `2`, and SQLite never compares an INTEGER equal to the
        // TEXT parameter '2', so `attr...index=2` would silently match nothing without it.
        where_clauses.push(format!(
            "json_type(attributes, ?{path_idx}) NOT IN ('object','array') \
             AND CAST(json_extract(attributes, ?{path_idx}) AS TEXT) = ?{value_idx}"
        ));
    }

    // Keyset rather than OFFSET, so pages stay correct while rows are being ingested.
    if let Some((event_time, id)) = spec.cursor {
        params.push(SqlValue::Integer(event_time));
        let t_idx = params.len();
        params.push(SqlValue::Integer(id));
        let id_idx = params.len();
        where_clauses.push(format!(
            "(event_time < ?{t_idx} OR (event_time = ?{t_idx} AND id < ?{id_idx}))"
        ));
    }

    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }

    sql.push_str(" ORDER BY event_time DESC, id DESC LIMIT ?");
    params.push(SqlValue::Integer(spec.limit.clamp(1, MAX_LIMIT)));
    sql.push_str(&params.len().to_string());

    (sql, params)
}

/// Runs a query against a read-only connection.
pub fn query(conn: &Connection, spec: &QuerySpec) -> Result<Vec<StoredMeasurement>> {
    let (sql, params) = build_query(spec);
    let mut stmt = conn.prepare(&sql).context("preparing read query")?;

    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |row| {
            let body: Option<String> = row.get(4)?;
            let attributes: String = row.get(5)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                body,
                attributes,
            ))
        })
        .context("running read query")?;

    let mut out = Vec::new();
    for row in rows {
        let (id, event_time, processed_time, kind, body, attributes) = row?;
        out.push(StoredMeasurement {
            id,
            event_time,
            processed_time,
            kind,
            // Stored by our own serializer, so a parse failure means corruption, not bad input.
            body: body
                .map(|b| serde_json::from_str(&b))
                .transpose()
                .context("parsing stored body JSON")?,
            attributes: serde_json::from_str(&attributes)
                .context("parsing stored attributes JSON")?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Measurement;
    use crate::store::{schema, write};
    use serde_json::json;

    #[test]
    fn json_path_quotes_the_key_as_one_literal_segment() {
        assert_eq!(json_path("record.attributes.unit"), r#"$."record.attributes.unit""#);
    }

    #[test]
    fn json_path_escapes_quotes_and_backslashes() {
        assert_eq!(json_path(r#"we"ird"#), r#"$."we\"ird""#);
        assert_eq!(json_path(r"back\slash"), r#"$."back\\slash""#);
    }

    fn db_with(measurements: Vec<Measurement>) -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        schema::migrate(&conn).unwrap();
        write::insert_batch(&mut conn, &measurements).unwrap();
        conn
    }

    fn m(kind: &str, event_time: i64, attrs: serde_json::Value) -> Measurement {
        Measurement {
            event_time,
            processed_time: event_time + 1,
            kind: kind.to_owned(),
            body: Some(json!({"v": event_time})),
            attributes: attrs.as_object().unwrap().clone(),
        }
    }

    /// SPEC §7.1: every awkward character must round-trip through the path builder into a match.
    #[test]
    fn awkward_attribute_keys_are_matchable() {
        let keys = [r#"we"ird"#, r"back\slash", "a.b", "a[0]", "a$b", "a*b"];
        let attrs: serde_json::Value =
            serde_json::Value::Object(keys.iter().map(|k| ((*k).to_owned(), json!("hit"))).collect());
        let conn = db_with(vec![m("t", 10, attrs)]);

        for key in keys {
            let spec = QuerySpec {
                attrs: vec![(key.to_owned(), "hit".to_owned())],
                limit: DEFAULT_LIMIT,
                ..Default::default()
            };
            let got = query(&conn, &spec).unwrap();
            assert_eq!(got.len(), 1, "key {key:?} did not match");
        }
    }

    /// A literal dotted key must not be reinterpreted as a path into a nested object.
    #[test]
    fn literal_dotted_key_does_not_resolve_as_a_nested_path() {
        let conn = db_with(vec![
            m("flat", 20, json!({"a.b": "flat-hit"})),
            m("nested", 10, json!({"a": {"b": "nested-hit"}})),
        ]);
        let spec = QuerySpec {
            attrs: vec![("a.b".to_owned(), "flat-hit".to_owned())],
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        let got = query(&conn, &spec).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, "flat");
    }

    /// SPEC §7.1: the json_type guard. A caller typing the attribute's exact serialized JSON must
    /// not match, or the API would silently depend on SQLite's serialization.
    #[test]
    fn nested_attribute_values_are_stored_but_never_filterable() {
        let conn = db_with(vec![m("t", 10, json!({"cfg": {"mode": "fast"}, "tags": [1, 2]}))]);

        // Returned in full.
        let all = query(&conn, &QuerySpec { limit: DEFAULT_LIMIT, ..Default::default() }).unwrap();
        assert_eq!(all[0].attributes["cfg"], json!({"mode": "fast"}));
        assert_eq!(all[0].attributes["tags"], json!([1, 2]));

        // But not matchable, however the caller spells the value.
        for probe in [r#"{"mode":"fast"}"#, r#"{"mode": "fast"}"#, "[1,2]"] {
            let spec = QuerySpec {
                attrs: vec![("cfg".to_owned(), probe.to_owned())],
                limit: DEFAULT_LIMIT,
                ..Default::default()
            };
            assert!(query(&conn, &spec).unwrap().is_empty(), "{probe:?} matched a nested value");
        }
    }

    /// Every scalar JSON type must be reachable through the single text-valued query parameter.
    /// Note booleans extract as `1`/`0`, which is how SQLite represents them.
    #[test]
    fn scalar_attribute_filters_of_each_type_match_as_text() {
        let conn =
            db_with(vec![m("t", 10, json!({"unit": "celsius", "idx": 2, "ok": true, "f": 1.02}))]);
        for (k, v) in [("unit", "celsius"), ("idx", "2"), ("ok", "1"), ("f", "1.02")] {
            let spec = QuerySpec {
                attrs: vec![(k.to_owned(), v.to_owned())],
                limit: DEFAULT_LIMIT,
                ..Default::default()
            };
            assert_eq!(query(&conn, &spec).unwrap().len(), 1, "{k}={v} did not match");
        }
    }

    /// A non-matching value must still not match, i.e. the CAST has not made everything equal.
    #[test]
    fn attribute_filters_still_discriminate() {
        let conn = db_with(vec![m("t", 10, json!({"idx": 2}))]);
        let spec = QuerySpec {
            attrs: vec![("idx".to_owned(), "3".to_owned())],
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        assert!(query(&conn, &spec).unwrap().is_empty());
    }

    #[test]
    fn type_filter_matches_any_of_the_given_types_and_attrs_are_anded() {
        let conn = db_with(vec![
            m("cpu", 30, json!({"unit": "ratio"})),
            m("gps", 20, json!({"unit": "wgs84"})),
            m("heart", 10, json!({"unit": "bpm"})),
        ]);

        let spec = QuerySpec {
            types: vec!["cpu".into(), "gps".into()],
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        assert_eq!(query(&conn, &spec).unwrap().len(), 2);

        let spec = QuerySpec {
            types: vec!["cpu".into()],
            attrs: vec![("unit".to_owned(), "wgs84".to_owned())],
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        assert!(query(&conn, &spec).unwrap().is_empty(), "attr filters must AND with type");
    }

    #[test]
    fn time_bounds_are_inclusive_lower_exclusive_upper() {
        let conn = db_with(vec![m("t", 10, json!({})), m("t", 20, json!({})), m("t", 30, json!({}))]);
        let spec = QuerySpec { from: Some(10), to: Some(30), limit: DEFAULT_LIMIT, ..Default::default() };
        let got = query(&conn, &spec).unwrap();
        assert_eq!(got.iter().map(|r| r.event_time).collect::<Vec<_>>(), vec![20, 10]);
    }

    #[test]
    fn ordering_is_newest_first_with_id_breaking_ties() {
        // Same event_time for all three, so only id can order them.
        let conn = db_with(vec![m("t", 5, json!({})), m("t", 5, json!({})), m("t", 5, json!({}))]);
        let got = query(&conn, &QuerySpec { limit: DEFAULT_LIMIT, ..Default::default() }).unwrap();
        assert_eq!(got.iter().map(|r| r.id).collect::<Vec<_>>(), vec![3, 2, 1]);
    }

    #[test]
    fn keyset_pagination_covers_every_row_exactly_once() {
        // Deliberately duplicated timestamps, the case OFFSET-free pagination must still get right.
        let rows: Vec<Measurement> =
            (0..10).map(|i| m("t", if i < 5 { 100 } else { 200 }, json!({}))).collect();
        let conn = db_with(rows);

        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let spec = QuerySpec { limit: 3, cursor, ..Default::default() };
            let page = query(&conn, &spec).unwrap();
            if page.is_empty() {
                break;
            }
            let last = page.last().unwrap();
            cursor = Some((last.event_time, last.id));
            seen.extend(page.iter().map(|r| r.id));
        }

        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 10, "pagination lost or duplicated rows: {seen:?}");
        assert_eq!(seen.len(), 10, "a row was returned twice: {seen:?}");
    }

    #[test]
    fn limit_is_clamped_to_the_maximum() {
        let (_, params) = build_query(&QuerySpec { limit: 99_999, ..Default::default() });
        assert_eq!(params.last(), Some(&SqlValue::Integer(MAX_LIMIT)));

        let (_, params) = build_query(&QuerySpec { limit: 0, ..Default::default() });
        assert_eq!(params.last(), Some(&SqlValue::Integer(1)));
    }
}
