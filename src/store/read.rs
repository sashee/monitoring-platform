//! Query building and row mapping for the read API (SPEC §7.1).
//!
//! SQL construction is a pure function so the predicate logic is testable without a database.

use anyhow::{Context, Result};
use rusqlite::{Connection, types::Value as SqlValue};

use crate::content_id::ContentId;
use crate::model::StoredMeasurement;

pub const DEFAULT_LIMIT: i64 = 100;
pub const MAX_LIMIT: i64 = 1000;

/// Which half of a measurement a field lives in.
///
/// **The distinction is an OTLP artifact, not something a reader should have to know.** An attribute and a
/// body leaf are both just properties of the measurement — `detected-devices.wifi_bss` keeps `bssid` in its
/// attributes and `ssid` in its body, and there is no sense in which one of those is more of a field than
/// the other. But they live in different columns, so a query has to say which, and the two namespaces can
/// legitimately collide. Hence one type that names the half explicitly, rather than a bare string whose
/// meaning depends on where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldRef {
    /// A key in the `attributes` column, structurally prefixed as §5.2 stores it.
    Attribute(String),
    /// A top-level leaf of the `body` column.
    Body(String),
}

impl FieldRef {
    /// Parses the URL form. `b:` marks a body leaf; anything else is an attribute key.
    ///
    /// Bare means attribute so that links and bookmarks made before body fields existed keep working —
    /// they carry a raw attribute key with no prefix.
    pub fn parse(raw: &str) -> Self {
        match raw.strip_prefix("b:") {
            Some(leaf) => FieldRef::Body(leaf.to_owned()),
            None => FieldRef::Attribute(raw.to_owned()),
        }
    }

    pub fn encode(&self) -> String {
        match self {
            FieldRef::Attribute(key) => key.clone(),
            FieldRef::Body(leaf) => format!("b:{leaf}"),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            FieldRef::Attribute(key) => key,
            FieldRef::Body(leaf) => leaf,
        }
    }

    /// The SQL column the field is extracted from.
    fn column(&self) -> &'static str {
        match self {
            FieldRef::Attribute(_) => "attributes",
            FieldRef::Body(_) => "body",
        }
    }
}

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
    /// Body-leaf equality filters, ANDed with each other and with `attrs`. Same semantics, other column —
    /// see [`FieldRef`] for why both exist.
    pub body: Vec<(String, String)>,
    pub limit: i64,
    /// Keyset position: `(event_time, id)` of the last row of the previous page.
    pub cursor: Option<(i64, ContentId)>,
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

/// Appends the `type`, time-window and attribute predicates to a query under construction.
///
/// Shared by the row query ([`build_query`]), the aggregated series query
/// ([`build_series_query`]) and facet discovery ([`build_facet_sample`]) — deliberately, because a
/// filter that meant one thing on the table and another on the chart above it would be a chart that
/// does not describe the rows beneath it. There is one predicate builder so that cannot drift.
///
/// `params` is appended to, and the `?N` placeholders are derived from its length, so this must be
/// called at the point the caller wants these parameters bound.
fn push_filters(spec: &QuerySpec, where_clauses: &mut Vec<String>, params: &mut Vec<SqlValue>) {
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

    // Attributes and body leaves are the same predicate against different columns (see `FieldRef`), so
    // they share one builder rather than two that could drift in their guards.
    for (column, filters) in [("attributes", &spec.attrs), ("body", &spec.body)] {
        for (key, value) in filters {
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
                "json_type({column}, ?{path_idx}) NOT IN ('object','array') \
                 AND CAST(json_extract({column}, ?{path_idx}) AS TEXT) = ?{value_idx}"
            ));
        }
    }
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

    push_filters(spec, &mut where_clauses, &mut params);

    // Keyset rather than OFFSET, so pages stay correct while rows are being ingested. `id` is a
    // content hash, so ties within one event_time break in hash order rather than arrival order —
    // arbitrary, but total and deterministic, which is all keyset pagination needs. SQLite compares
    // blobs with memcmp, so the ordering matches the hex form the API exposes.
    if let Some((event_time, id)) = spec.cursor {
        params.push(SqlValue::Integer(event_time));
        let t_idx = params.len();
        params.push(SqlValue::Blob(id.to_vec()));
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

// ---------------------------------------------------------------- facets: what is there to filter on

/// How many rows facet discovery reads. See [`facets`] for why this is a sample rather than a scan.
pub const FACET_SCAN_LIMIT: i64 = 2_000;

/// Distinct values to offer for one attribute key before giving up on a dropdown.
///
/// Some keys are effectively unique per row — `resource.attributes.boot_id`,
/// `record.attributes.mp.clock.correction_ns` — and a `<select>` with hundreds of options is worse
/// than a text box. Past this, [`AttrFacet::truncated`] tells the UI to offer free text instead.
pub const MAX_FACET_VALUES: usize = 40;

/// Validated categorical hues. The palette's separation guarantees hold for these eight and stop holding
/// past them, which is why a ninth is never invented — see `web::svg::series_style`.
pub const PALETTE_SLOTS: usize = 8;

/// The most series one plot will draw.
///
/// Eight hues × three line patterns (solid, dashed, dotted). Past eight, identity is carried by **hue and
/// pattern together** rather than by a ninth generated hue, which is the one sanctioned way to exceed the
/// palette on a single plot: within each pattern the eight hues clear their gates, and two series sharing a
/// hue never share a pattern.
///
/// A bound is still needed — a scan finding four hundred networks is not a chart — and past this the UI
/// says how many it left out rather than truncating silently.
pub const MAX_SERIES: usize = PALETTE_SLOTS * 3;

/// One measurement type and how many rows carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeCount {
    pub kind: String,
    pub count: i64,
}

/// One attribute key and the values seen for it, for building a filter control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrFacet {
    pub key: String,
    /// Sorted, and at most [`MAX_FACET_VALUES`] long.
    pub values: Vec<String>,
    /// More distinct values exist than are listed, so a dropdown would be lying by omission.
    pub truncated: bool,
}

/// One body leaf: whether it can be charted as a value, and what values it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldFacet {
    pub name: String,
    /// True when the leaf was an `integer` or `real` in at least one sampled row. A leaf that is
    /// sometimes null and sometimes a number (`system.unit.active_enter_seconds_ago` is null on over
    /// half its rows) is still chartable — the nulls are skipped, not read as zero.
    pub numeric: bool,
    /// Sorted, at most [`MAX_FACET_VALUES`] long. Populated for the same reason attributes have values:
    /// a body leaf is filterable and groupable, so its options have to be discoverable. `ssid` is the
    /// motivating case — it is the interesting identity of a wifi measurement and lives in the body.
    pub values: Vec<String>,
    pub truncated: bool,
}

/// What can be filtered and charted within one slice of the data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Facets {
    pub attrs: Vec<AttrFacet>,
    pub fields: Vec<FieldFacet>,
    /// Rows examined. Equal to [`FACET_SCAN_LIMIT`] when the cap was reached.
    pub scanned: i64,
    pub capped: bool,
}

/// Every type in the table, with counts, **in name order**.
///
/// Alphabetical rather than by row count. Count order sounds useful — busiest first — but the thing a reader
/// does with a list of twenty-nine names is *look for one*, and in count order that means reading all of
/// them. Name order also brings each family together (`bms.*`, `detected-devices.*`, `system.*`), which is
/// how these names are actually structured. The count stays in the label, where it is information rather
/// than a sort key.
///
/// Exact rather than sampled: measured at 30 ms over 95k rows, because `type` is the leading column
/// of an index and this never has to touch the JSON.
pub fn types(conn: &Connection) -> Result<Vec<TypeCount>> {
    let mut stmt = conn
        .prepare("SELECT type, count(*) FROM measurement GROUP BY type ORDER BY type")
        .context("preparing the type listing")?;
    let out = stmt
        .query_map([], |row| Ok(TypeCount { kind: row.get(0)?, count: row.get(1)? }))
        .context("listing types")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the type listing")?;
    Ok(out)
}

/// The `WITH sample AS (…)` prefix every facet query shares: the newest matching rows, capped.
fn build_facet_sample(spec: &QuerySpec) -> (String, Vec<SqlValue>) {
    let mut where_clauses = Vec::new();
    let mut params = Vec::new();
    push_filters(spec, &mut where_clauses, &mut params);

    let mut sql = String::from("WITH sample AS (SELECT attributes, body FROM measurement");
    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }
    params.push(SqlValue::Integer(FACET_SCAN_LIMIT));
    sql.push_str(&format!(" ORDER BY event_time DESC, id DESC LIMIT ?{})", params.len()));
    (sql, params)
}

/// Discovers what is filterable and chartable in the slice `spec` describes.
///
/// **A bounded sample, not a scan, and the distinction is deliberate.** Discovery reads the newest
/// [`FACET_SCAN_LIMIT`] matching rows. A full scan of the largest type costs 145 ms today, which
/// would be fine — but that grows with the table, and this host projects millions of rows a year, so
/// the same page would take seconds within a year of running. Sampling is what makes the cost depend
/// on the window being viewed rather than on how long the Pi has been up.
///
/// What makes it sound is that **attribute keys are uniform per type**: all 32,112 `bms.status.cell`
/// rows carry the same twelve keys, so a few hundred rows reveal every one. Distinct *values* can be
/// missed — a device that stopped reporting an hour into a week-long window — which is why
/// [`Facets::capped`] exists for the UI to say so.
///
/// **Only discovery is sampled. Filtering is always exact** over the whole window: these facets
/// populate the controls, they never restrict what a query returns.
pub fn facets(conn: &Connection, spec: &QuerySpec) -> Result<Facets> {
    let (prefix, base_params) = build_facet_sample(spec);

    // Attribute keys and their values. The json_type guard matches what `push_filters` will accept as
    // a filter, so the UI cannot offer an option that provably matches nothing (SPEC §7.1).
    let attr_sql = format!(
        "{prefix} SELECT j.key, CAST(j.value AS TEXT), count(*) \
         FROM sample s, json_each(s.attributes) j \
         WHERE j.type NOT IN ('object','array') GROUP BY 1, 2 ORDER BY 1, 2"
    );
    let mut stmt = conn.prepare(&attr_sql).context("preparing the attribute facet query")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(base_params.clone()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .context("running the attribute facet query")?;

    let mut attrs: Vec<AttrFacet> = Vec::new();
    for row in rows {
        let (key, value) = row?;
        // Already grouped and sorted by the query, so equal keys arrive consecutively.
        if attrs.last().map(|f| f.key.as_str()) != Some(key.as_str()) {
            attrs.push(AttrFacet { key, values: Vec::new(), truncated: false });
        }
        let facet = attrs.last_mut().expect("just pushed");
        match value {
            Some(v) if facet.values.len() < MAX_FACET_VALUES => facet.values.push(v),
            // A JSON null reads as no value to filter on rather than the string "null".
            Some(_) => facet.truncated = true,
            None => {}
        }
    }

    // Body leaves. `json_type(s.body) = 'object'` guards both a NULL body and the scalar case: every
    // type on this host has an object body today, but json_each over a scalar yields one keyless row
    // that would show up as a field named nothing.
    // Body leaves, with their values, exactly as the attributes above: same grouping, same cap, same
    // reason. The `numeric` flag rides along because it decides what can be *plotted* rather than what can
    // be filtered.
    let field_sql = format!(
        "{prefix} SELECT j.key, CAST(j.value AS TEXT), max(j.type IN ('integer','real')) \
         FROM sample s, json_each(s.body) j \
         WHERE json_type(s.body) = 'object' AND j.type NOT IN ('object','array') \
         GROUP BY 1, 2 ORDER BY 1, 2"
    );
    let mut stmt = conn.prepare(&field_sql).context("preparing the field facet query")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(base_params.clone()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, i64>(2)? != 0))
        })
        .context("running the field facet query")?;

    let mut fields: Vec<FieldFacet> = Vec::new();
    for row in rows {
        let (name, value, numeric) = row?;
        if fields.last().map(|f| f.name.as_str()) != Some(name.as_str()) {
            fields.push(FieldFacet { name, numeric: false, values: Vec::new(), truncated: false });
        }
        let facet = fields.last_mut().expect("just pushed");
        // Numeric if it was numeric in *any* sampled row: a leaf that is sometimes null is still chartable.
        facet.numeric |= numeric;
        match value {
            Some(v) if facet.values.len() < MAX_FACET_VALUES => facet.values.push(v),
            Some(_) => facet.truncated = true,
            None => {}
        }
    }

    // How much was actually looked at, so the UI can say whether the options are complete.
    let count_sql = format!("{prefix} SELECT count(*) FROM sample");
    let scanned: i64 = conn
        .query_row(&count_sql, rusqlite::params_from_iter(base_params), |row| row.get(0))
        .context("counting the facet sample")?;

    Ok(Facets { attrs, fields, scanned, capped: scanned >= FACET_SCAN_LIMIT })
}

/// The values to offer for one attribute key, discovered with **that key's own filter removed**.
///
/// Without this, a filter is a one-way door. [`facets`] scopes discovery to every applied filter, which is
/// what keeps the options relevant — but applied to the key being filtered it is circular: once
/// `cell = 3` is set, the only rows sampled have `cell = 3`, so the only value left to offer for `cell`
/// is `3`, and changing your mind means clearing the filter and re-applying. That is the standard
/// faceted-search rule: a key's options answer *"what else could I choose here, given my other filters"*,
/// so its own filter is the one thing excluded from the question.
///
/// Only called for keys that actually have a filter applied — for the rest [`facets`] is already correct —
/// so the extra cost is one query per active filter, not per key.
pub fn facet_values_excluding(
    conn: &Connection,
    spec: &QuerySpec,
    field: &FieldRef,
) -> Result<AttrFacet> {
    let key = field.name();
    // The same slice, minus this field's own constraint — and only its own: the other half's filters still
    // apply, as do the other keys in this half.
    let widened = match field {
        FieldRef::Attribute(_) => QuerySpec {
            attrs: spec.attrs.iter().filter(|(k, _)| k != key).cloned().collect(),
            ..spec.clone()
        },
        FieldRef::Body(_) => QuerySpec {
            body: spec.body.iter().filter(|(k, _)| k != key).cloned().collect(),
            ..spec.clone()
        },
    };
    let (prefix, mut params) = build_facet_sample(&widened);

    params.push(SqlValue::Text(key.to_owned()));
    let key_param = params.len();
    let column = field.column();
    let sql = format!(
        "{prefix} SELECT CAST(j.value AS TEXT) FROM sample s, json_each(s.{column}) j \
         WHERE j.key = ?{key_param} AND j.type NOT IN ('object','array') GROUP BY 1 ORDER BY 1"
    );

    let mut stmt = conn.prepare(&sql).context("preparing the widened facet query")?;
    let values = stmt
        .query_map(rusqlite::params_from_iter(params), |row| row.get::<_, Option<String>>(0))
        .context("running the widened facet query")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the widened facet values")?;

    let mut facet = AttrFacet { key: key.to_owned(), values: Vec::new(), truncated: false };
    for value in values.into_iter().flatten() {
        if facet.values.len() < MAX_FACET_VALUES {
            facet.values.push(value);
        } else {
            facet.truncated = true;
        }
    }
    Ok(facet)
}

/// Sorts facet values numerically when every one of them is a number, and lexicographically otherwise.
///
/// **Not cosmetic.** These values decide which series a chart plots (the first
/// [`MAX_SERIES`]) and in which colour, so the order is load-bearing twice over. SQL's collation is
/// lexicographic, which puts `"10"` before `"2"` — so the sixteen BMS cells would sort 1, 10, 11 … 16, 2,
/// 3, and "the first eight" would be cells 1 and 10–16 rather than 1–8. That is a chart nobody asked for.
///
/// Deterministic either way, which is what colour stability needs: the same set of values always yields
/// the same order, so a group keeps its colour across renders.
pub fn sort_facet_values(values: &mut [String]) {
    let numeric = |s: &String| s.parse::<f64>().ok().filter(|n| n.is_finite());
    if values.iter().all(|v| numeric(v).is_some()) {
        values.sort_by(|a, b| {
            numeric(a)
                .zip(numeric(b))
                .and_then(|(x, y)| x.partial_cmp(&y))
                // Unreachable: both parsed finitely above. Falling back to the string order keeps this
                // total rather than risking a comparator that panics.
                .unwrap_or_else(|| a.cmp(b))
        });
    } else {
        values.sort();
    }
}

/// `(min, max)` of `event_time` over a filtered slice, for the "all time" range.
///
/// Its own tiny query rather than a scan, because both bounds come straight off the `event_time` index.
pub fn build_extent_query(spec: &QuerySpec) -> (String, Vec<SqlValue>) {
    let mut where_clauses = Vec::new();
    let mut params = Vec::new();
    push_filters(spec, &mut where_clauses, &mut params);

    let mut sql = String::from("SELECT min(event_time), max(event_time) FROM measurement");
    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }
    (sql, params)
}

/// Runs [`build_extent_query`]. `None` when the slice is empty.
pub fn extent(conn: &Connection, spec: &QuerySpec) -> Result<Option<(i64, i64)>> {
    let (sql, params) = build_extent_query(spec);
    let got: (Option<i64>, Option<i64>) = conn
        .query_row(&sql, rusqlite::params_from_iter(params), |row| Ok((row.get(0)?, row.get(1)?)))
        .context("reading the time extent")?;
    Ok(match got {
        (Some(min), Some(max)) => Some((min, max)),
        _ => None,
    })
}

// ---------------------------------------------------------------- series: the aggregated chart data

/// What to aggregate, and how finely.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesSpec {
    /// The row filter. `limit` and `cursor` are ignored — a chart is not paginated.
    pub filter: QuerySpec,
    /// Body leaf to aggregate. `None` yields counts only, which is the timeline.
    pub field: Option<String>,
    /// Field to split into series by — either half of the measurement (see [`FieldRef`]).
    pub group: Option<FieldRef>,
    /// The group values to plot, at most [`MAX_SERIES`]. Empty means do not split.
    ///
    /// Passed in explicitly rather than discovered here, so the caller's sorted order is what decides
    /// which series gets which colour — see the note on colour stability in `web::svg`.
    pub groups: Vec<String>,
    /// Bucket width in nanoseconds. See [`bucket_nanos`].
    pub bucket_nanos: i64,
}

/// One bucket of one series.
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    /// `event_time` at the start of the bucket.
    pub start: i64,
    /// Matching rows in the bucket, whether or not they carried a value.
    pub count: i64,
    /// Rows whose `field` was actually numeric. Below `count` when the leaf is sometimes null.
    pub value_count: i64,
    pub avg: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

/// One series: a group value, or `None` when ungrouped.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    pub group: Option<String>,
    pub points: Vec<Point>,
}

/// Bucket width for a window and a target bucket count, never zero.
///
/// A pure function so the arithmetic is testable at the boundaries — a window shorter than the
/// target bucket count would otherwise divide to zero and make every row land in bucket 0.
pub fn bucket_nanos(from: i64, to: i64, buckets: i64) -> i64 {
    let span = to.saturating_sub(from).max(1);
    (span / buckets.max(1)).max(1)
}

/// The aggregated query. Returns `(sql, params)` so the arithmetic is testable without a database.
///
/// Aggregating in SQL rather than fetching rows and folding in Rust is what makes a chart over any
/// window affordable: 24 h of `bms.status.cell` is ~23,000 rows, far past `MAX_LIMIT` and far past
/// useful pixel density, but bucketed it is 240 points per series regardless of the window — measured
/// at 131 ms for 16 series over 24 h.
///
/// Two guards carry most of the correctness:
///
/// - **The field is only aggregated where it is numeric.** `json_extract` on a text leaf returns
///   text, and SQLite's `avg()` coerces text to 0 — so without the `json_type` guard a chart of a
///   text field would render a confident flat line at zero rather than nothing at all. The guard
///   turns non-numeric into `NULL`, which `avg`/`min`/`max` skip.
/// - **`count(*)` and `count(<field>)` are both returned.** The first is the timeline (every matching
///   row); the second is how many actually had a number. A bucket where they differ is a bucket whose
///   average speaks for only part of it, and the UI can say so.
pub fn build_series_query(spec: &SeriesSpec) -> (String, Vec<SqlValue>) {
    let mut where_clauses = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();
    push_filters(&spec.filter, &mut where_clauses, &mut params);

    // The group expression, and the restriction to the chosen group values. Nested values resolve to
    // NULL rather than to their serialized text, for the reason `push_filters` gives: matching on
    // SQLite's serialization would be an accidental API.
    let group_expr = match &spec.group {
        Some(field) => {
            let column = field.column();
            params.push(SqlValue::Text(json_path(field.name())));
            let p = params.len();
            if !spec.groups.is_empty() {
                let placeholders = spec
                    .groups
                    .iter()
                    .map(|g| {
                        params.push(SqlValue::Text(g.clone()));
                        format!("?{}", params.len())
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                where_clauses.push(format!(
                    "CAST(json_extract({column}, ?{p}) AS TEXT) IN ({placeholders})"
                ));
            }
            format!(
                "CASE WHEN json_type({column}, ?{p}) IN ('object','array') THEN NULL \
                 ELSE CAST(json_extract({column}, ?{p}) AS TEXT) END"
            )
        }
        None => "NULL".to_owned(),
    };

    let value_expr = match &spec.field {
        Some(field) => {
            params.push(SqlValue::Text(json_path(field)));
            let p = params.len();
            format!(
                "CASE WHEN json_type(body, ?{p}) IN ('integer','real') \
                 THEN json_extract(body, ?{p}) END"
            )
        }
        None => "NULL".to_owned(),
    };

    params.push(SqlValue::Integer(spec.bucket_nanos.max(1)));
    let bucket_param = params.len();

    let mut sql = format!(
        "SELECT {group_expr} AS g, \
         (event_time / ?{bucket_param}) * ?{bucket_param} AS bucket_start, \
         count(*), count({value_expr}), avg({value_expr}), min({value_expr}), max({value_expr}) \
         FROM measurement"
    );
    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }
    // Grouped by the bucket's start rather than its index so the value selected is the one plotted,
    // and ordered so `series` can fold consecutive rows into one series without a map.
    sql.push_str(" GROUP BY g, bucket_start ORDER BY g, bucket_start");

    (sql, params)
}

/// Runs the aggregated query and folds it into one [`Series`] per group.
///
/// Series come back in the order the caller listed `groups`, not in SQL's collation order, so the
/// colour a group is drawn in depends only on the caller's list — see `web::svg::series_color`.
pub fn series(conn: &Connection, spec: &SeriesSpec) -> Result<Vec<Series>> {
    let (sql, params) = build_series_query(spec);
    let mut stmt = conn.prepare(&sql).context("preparing the series query")?;

    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                Point {
                    start: row.get(1)?,
                    count: row.get(2)?,
                    value_count: row.get(3)?,
                    avg: row.get(4)?,
                    min: row.get(5)?,
                    max: row.get(6)?,
                },
            ))
        })
        .context("running the series query")?;

    let mut collected: Vec<Series> = Vec::new();
    for row in rows {
        let (group, point) = row?;
        if collected.last().map(|s| &s.group) != Some(&group) {
            collected.push(Series { group: group.clone(), points: Vec::new() });
        }
        collected.last_mut().expect("just pushed").points.push(point);
    }

    // Reorder to the caller's list. A group the caller asked for but that has no rows is dropped
    // rather than returned empty: an empty series in a legend is a colour spent on nothing.
    if spec.groups.is_empty() {
        return Ok(collected);
    }
    let mut ordered = Vec::with_capacity(collected.len());
    for wanted in &spec.groups {
        if let Some(pos) = collected.iter().position(|s| s.group.as_deref() == Some(wanted.as_str()))
        {
            ordered.push(collected.remove(pos));
        }
    }
    // Anything left is the NULL group (nested or absent attribute), which no caller can name.
    ordered.extend(collected);
    Ok(ordered)
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
                row.get::<_, Vec<u8>>(0)?,
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
            // Written by this program as a fixed-width hash, so a wrong length means the database
            // was tampered with rather than that a client sent something odd.
            id: crate::content_id::from_bytes(&id)
                .with_context(|| format!("stored id is not {ID_LEN} bytes", ID_LEN = crate::content_id::ID_LEN))?,
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

    /// Ties now break in hash order rather than arrival order — arbitrary, but total and
    /// deterministic, which is all keyset pagination requires. Note the rows must differ in
    /// content: three *identical* measurements are one measurement now (SPEC §6.6).
    #[test]
    fn ordering_is_newest_first_with_id_breaking_ties() {
        let rows: Vec<Measurement> = (0..3).map(|i| m("t", 5, json!({ "n": i }))).collect();
        let conn = db_with(rows);

        let got = query(&conn, &QuerySpec { limit: DEFAULT_LIMIT, ..Default::default() }).unwrap();
        assert_eq!(got.len(), 3, "distinct content must not deduplicate");

        let ids: Vec<_> = got.iter().map(|r| r.id).collect();
        let mut descending = ids.clone();
        descending.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(ids, descending, "ties must break on id descending");
    }

    #[test]
    fn keyset_pagination_covers_every_row_exactly_once() {
        // Deliberately duplicated timestamps, the case OFFSET-free pagination must still get right.
        // Content differs per row so nothing deduplicates.
        let rows: Vec<Measurement> = (0..10)
            .map(|i| m("t", if i < 5 { 100 } else { 200 }, json!({ "n": i })))
            .collect();
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

    // ------------------------------------------------------------------------------- facets

    // ------------------------------------------------------------------------- fields in either half

    /// Bare means attribute, so links made before body fields existed keep working.
    #[test]
    fn a_field_reference_round_trips_and_defaults_to_an_attribute() {
        assert_eq!(FieldRef::parse("record.attributes.bssid"),
                   FieldRef::Attribute("record.attributes.bssid".into()));
        assert_eq!(FieldRef::parse("b:ssid"), FieldRef::Body("ssid".into()));
        for field in [FieldRef::Attribute("a.b".into()), FieldRef::Body("ssid".into())] {
            assert_eq!(FieldRef::parse(&field.encode()), field, "must round trip");
        }
        assert_eq!(FieldRef::Body("ssid".into()).name(), "ssid");
    }

    /// The motivating case: `detected-devices.wifi_bss` keeps `bssid` in its attributes and `ssid` in its
    /// body, and the body one is the interesting identity. Both must be groupable.
    #[test]
    fn a_body_leaf_can_split_a_chart_into_series() {
        let conn = db_with(vec![
            mb("wifi", 10, json!({"signal_dbm": -60.0, "ssid": "home"}), json!({"bssid": "aa"})),
            mb("wifi", 11, json!({"signal_dbm": -70.0, "ssid": "cafe"}), json!({"bssid": "bb"})),
            mb("wifi", 12, json!({"signal_dbm": -50.0, "ssid": "home"}), json!({"bssid": "cc"})),
        ]);
        let spec = SeriesSpec {
            filter: QuerySpec { types: vec!["wifi".into()], ..Default::default() },
            field: Some("signal_dbm".into()),
            group: Some(FieldRef::Body("ssid".into())),
            groups: vec!["home".into(), "cafe".into()],
            bucket_nanos: 100,
        };
        let got = series(&conn, &spec).unwrap();

        assert_eq!(
            got.iter().map(|s| s.group.clone()).collect::<Vec<_>>(),
            vec![Some("home".to_owned()), Some("cafe".to_owned())]
        );
        // "home" averages -60 and -50; grouping by the body leaf really did group.
        assert_eq!(got[0].points[0].avg, Some(-55.0));
        assert_eq!(got[1].points[0].avg, Some(-70.0));
    }

    /// A body leaf must filter exactly as an attribute does — otherwise grouping by one has no escape
    /// hatch when there are more groups than the chart's cap.
    #[test]
    fn a_body_leaf_can_filter_rows() {
        let conn = db_with(vec![
            mb("wifi", 10, json!({"ssid": "home", "signal_dbm": -60.0}), json!({})),
            mb("wifi", 11, json!({"ssid": "cafe", "signal_dbm": -70.0}), json!({})),
        ]);
        let spec = QuerySpec {
            body: vec![("ssid".to_owned(), "home".to_owned())],
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        let got = query(&conn, &spec).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body.as_ref().unwrap()["ssid"], json!("home"));
    }

    /// Both halves AND together, and each keeps its own column — a name present in both must not cross.
    #[test]
    fn the_two_halves_and_together_without_crossing() {
        let conn = db_with(vec![
            // `channel` exists in both halves, with different values.
            mb("t", 10, json!({"channel": "body-1"}), json!({"channel": "attr-1"})),
            mb("t", 11, json!({"channel": "body-2"}), json!({"channel": "attr-1"})),
        ]);

        let spec = QuerySpec {
            attrs: vec![("channel".to_owned(), "attr-1".to_owned())],
            body: vec![("channel".to_owned(), "body-2".to_owned())],
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        assert_eq!(query(&conn, &spec).unwrap().len(), 1, "both must apply, to their own column");

        // And a value from the wrong half matches nothing.
        let crossed = QuerySpec {
            body: vec![("channel".to_owned(), "attr-1".to_owned())],
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        assert!(query(&conn, &crossed).unwrap().is_empty(), "a body filter must not read attributes");
    }

    /// The one-way-door fix applies to body leaves too.
    #[test]
    fn a_filtered_body_leaf_still_offers_its_other_values() {
        let conn = db_with(vec![
            mb("wifi", 10, json!({"ssid": "home"}), json!({})),
            mb("wifi", 11, json!({"ssid": "cafe"}), json!({})),
            mb("wifi", 12, json!({"ssid": "work"}), json!({})),
        ]);
        let filtered =
            QuerySpec { body: vec![("ssid".to_owned(), "cafe".to_owned())], ..Default::default() };

        let widened =
            facet_values_excluding(&conn, &filtered, &FieldRef::Body("ssid".into())).unwrap();
        assert_eq!(widened.values, vec!["cafe", "home", "work"]);
    }

    #[test]
    fn field_facets_carry_their_values() {
        let conn = db_with(vec![
            mb("wifi", 10, json!({"ssid": "home", "security": "wpa3"}), json!({})),
            mb("wifi", 11, json!({"ssid": "cafe", "security": "wpa3"}), json!({})),
        ]);
        let f = facets(&conn, &QuerySpec::default()).unwrap();

        let ssid = f.fields.iter().find(|x| x.name == "ssid").expect("ssid");
        assert_eq!(ssid.values, vec!["cafe", "home"]);
        assert!(!ssid.numeric);
        let security = f.fields.iter().find(|x| x.name == "security").expect("security");
        assert_eq!(security.values, vec!["wpa3"], "a repeated value is listed once");
    }

    /// A measurement with an explicit body, for the field-facet and series tests.
    fn mb(kind: &str, event_time: i64, body: serde_json::Value, attrs: serde_json::Value) -> Measurement {
        Measurement {
            event_time,
            processed_time: event_time + 1,
            kind: kind.to_owned(),
            body: Some(body),
            attributes: attrs.as_object().unwrap().clone(),
        }
    }

    /// Name order, not count order: with twenty-nine types the reader is looking one up, and count order
    /// means reading the whole list to find it.
    #[test]
    fn types_are_listed_by_name_with_their_counts() {
        let conn = db_with(vec![
            m("zebra", 10, json!({})),
            m("zebra", 20, json!({})),
            m("zebra", 25, json!({})),
            m("apple", 30, json!({})),
        ]);
        assert_eq!(
            types(&conn).unwrap(),
            vec![
                // `apple` is rarer but comes first, which is the point.
                TypeCount { kind: "apple".into(), count: 1 },
                TypeCount { kind: "zebra".into(), count: 3 },
            ]
        );
    }

    #[test]
    fn facets_discover_attribute_keys_and_their_values() {
        let conn = db_with(vec![
            mb("s", 10, json!({"c": 1}), json!({"cell": "1", "host": "pi"})),
            mb("s", 20, json!({"c": 2}), json!({"cell": "2", "host": "pi"})),
        ]);
        let f = facets(&conn, &QuerySpec::default()).unwrap();

        let cell = f.attrs.iter().find(|a| a.key == "cell").expect("cell facet");
        assert_eq!(cell.values, vec!["1", "2"]);
        let host = f.attrs.iter().find(|a| a.key == "host").expect("host facet");
        assert_eq!(host.values, vec!["pi"], "a repeated value is listed once");
        assert_eq!(f.scanned, 2);
        assert!(!f.capped);
    }

    /// Facets describe the slice, not the table: an option that matches nothing in view would be a
    /// dead end for the reader.
    #[test]
    fn facets_are_scoped_to_the_filter() {
        let conn = db_with(vec![
            mb("cpu", 10, json!({"c": 1}), json!({"unit": "ratio"})),
            mb("gps", 20, json!({"c": 2}), json!({"unit": "wgs84"})),
        ]);
        let spec = QuerySpec { types: vec!["cpu".into()], ..Default::default() };
        let f = facets(&conn, &spec).unwrap();

        let unit = f.attrs.iter().find(|a| a.key == "unit").expect("unit facet");
        assert_eq!(unit.values, vec!["ratio"], "the other type's value must not be offered");
    }

    /// Nested attributes are not filterable (see `nested_attribute_values_are_stored_but_never_filterable`),
    /// so offering them as filter options would be offering something that cannot work.
    #[test]
    fn facets_omit_attributes_that_cannot_be_filtered() {
        let conn = db_with(vec![mb("s", 10, json!({"c": 1}), json!({"flat": "v", "nested": {"a": 1}}))]);
        let f = facets(&conn, &QuerySpec::default()).unwrap();

        assert!(f.attrs.iter().any(|a| a.key == "flat"));
        assert!(
            !f.attrs.iter().any(|a| a.key == "nested"),
            "a nested attribute is not filterable and must not be offered: {:?}",
            f.attrs
        );
    }

    /// **The regression test for a one-way filter.** Scoping a key's options to its own filter leaves
    /// exactly one option — the one already chosen — so changing your mind means clearing the filter
    /// first. Its own constraint has to be excluded from its own question.
    #[test]
    fn a_filtered_key_still_offers_its_other_values() {
        let conn = db_with(vec![
            mb("c", 10, json!({"v": 1}), json!({"cell": "1", "pack": "a"})),
            mb("c", 20, json!({"v": 2}), json!({"cell": "2", "pack": "a"})),
            mb("c", 30, json!({"v": 3}), json!({"cell": "3", "pack": "b"})),
        ]);
        let filtered = QuerySpec {
            attrs: vec![("cell".to_owned(), "2".to_owned())],
            ..Default::default()
        };

        // Scoped to everything, `cell` collapses to the one value chosen — the bug.
        let narrow = facets(&conn, &filtered).unwrap();
        let narrow_cell = narrow.attrs.iter().find(|a| a.key == "cell").expect("cell");
        assert_eq!(narrow_cell.values, vec!["2"], "precondition: this is why the widened query exists");

        // Excluding its own filter, every value is offered again.
        let widened = facet_values_excluding(&conn, &filtered, &FieldRef::Attribute("cell".into())).unwrap();
        assert_eq!(widened.values, vec!["1", "2", "3"]);
    }

    /// ...but the *other* filters still apply, or the options would include values that match nothing
    /// once you picked them.
    #[test]
    fn widening_one_key_keeps_the_other_filters() {
        let conn = db_with(vec![
            mb("c", 10, json!({"v": 1}), json!({"cell": "1", "pack": "a"})),
            mb("c", 20, json!({"v": 2}), json!({"cell": "2", "pack": "a"})),
            mb("c", 30, json!({"v": 3}), json!({"cell": "3", "pack": "b"})),
        ]);
        let spec = QuerySpec {
            attrs: vec![("cell".to_owned(), "1".to_owned()), ("pack".to_owned(), "a".to_owned())],
            ..Default::default()
        };

        let cells = facet_values_excluding(&conn, &spec, &FieldRef::Attribute("cell".into())).unwrap();
        assert_eq!(cells.values, vec!["1", "2"], "cell 3 is in pack b, which is filtered out");
    }

    #[test]
    fn a_high_cardinality_attribute_is_marked_truncated() {
        let rows: Vec<Measurement> = (0..(MAX_FACET_VALUES as i64 + 5))
            .map(|i| mb("s", i, json!({"c": i}), json!({ "boot": format!("boot-{i:03}") })))
            .collect();
        let conn = db_with(rows);
        let f = facets(&conn, &QuerySpec::default()).unwrap();

        let boot = f.attrs.iter().find(|a| a.key == "boot").expect("boot facet");
        assert_eq!(boot.values.len(), MAX_FACET_VALUES);
        assert!(boot.truncated, "a dropdown must not silently omit options");
    }

    #[test]
    fn field_facets_report_which_leaves_are_numeric() {
        let conn = db_with(vec![
            mb("s", 10, json!({"volts": 3.29, "state": "active", "n": 4}), json!({})),
        ]);
        let f = facets(&conn, &QuerySpec::default()).unwrap();

        let numeric = |name: &str| f.fields.iter().find(|x| x.name == name).expect(name).numeric;
        assert!(numeric("volts"));
        assert!(numeric("n"));
        assert!(!numeric("state"));
    }

    /// `system.unit.active_enter_seconds_ago` is null on over half its rows and real on the rest. It
    /// is chartable — the nulls are skipped — so it must be reported numeric.
    #[test]
    fn a_sometimes_null_leaf_is_still_numeric() {
        let conn = db_with(vec![
            mb("u", 10, json!({"ago": serde_json::Value::Null}), json!({})),
            mb("u", 20, json!({"ago": 12.5}), json!({})),
        ]);
        let f = facets(&conn, &QuerySpec::default()).unwrap();
        assert!(f.fields.iter().find(|x| x.name == "ago").expect("ago").numeric);
    }

    // ------------------------------------------------------------------------------- series

    #[test]
    fn bucket_width_is_never_zero() {
        assert_eq!(bucket_nanos(0, 240, 240), 1);
        assert_eq!(bucket_nanos(0, 2400, 240), 10);
        // A window narrower than the bucket count would divide to zero, putting every row in one
        // bucket at position zero.
        assert_eq!(bucket_nanos(0, 10, 240), 1);
        assert_eq!(bucket_nanos(5, 5, 240), 1, "an empty window still has a usable width");
        assert_eq!(bucket_nanos(0, 240, 0), 240, "a zero target must not divide by zero");
    }

    fn one_series(conn: &Connection, spec: &SeriesSpec) -> Vec<Point> {
        let got = series(conn, spec).unwrap();
        assert_eq!(got.len(), 1, "expected exactly one series, got {got:?}");
        got.into_iter().next().unwrap().points
    }

    #[test]
    fn a_series_aggregates_each_bucket() {
        let conn = db_with(vec![
            mb("s", 10, json!({"v": 1.0}), json!({})),
            mb("s", 15, json!({"v": 3.0}), json!({})),
            mb("s", 30, json!({"v": 5.0}), json!({})),
        ]);
        let spec = SeriesSpec {
            filter: QuerySpec { types: vec!["s".into()], ..Default::default() },
            field: Some("v".into()),
            group: None,
            groups: vec![],
            bucket_nanos: 20,
        };
        let points = one_series(&conn, &spec);

        assert_eq!(points.len(), 2, "two buckets: [0,20) and [20,40)");
        assert_eq!(points[0].start, 0);
        assert_eq!(points[0].count, 2);
        assert_eq!(points[0].avg, Some(2.0), "mean of 1 and 3");
        assert_eq!(points[0].min, Some(1.0));
        assert_eq!(points[0].max, Some(3.0));
        assert_eq!(points[1].start, 20);
        assert_eq!(points[1].avg, Some(5.0));
    }

    /// **The guard that matters most.** `json_extract` on a text leaf returns text, and SQLite's
    /// `avg()` coerces text to 0 — so without the `json_type` guard a chart of a text field would
    /// render a confident flat line at zero instead of nothing.
    #[test]
    fn a_text_field_yields_no_values_rather_than_zeros() {
        let conn = db_with(vec![
            mb("u", 10, json!({"state": "active"}), json!({})),
            mb("u", 20, json!({"state": "inactive"}), json!({})),
        ]);
        let spec = SeriesSpec {
            filter: QuerySpec { types: vec!["u".into()], ..Default::default() },
            field: Some("state".into()),
            group: None,
            groups: vec![],
            bucket_nanos: 100,
        };
        let points = one_series(&conn, &spec);

        assert_eq!(points[0].count, 2, "the rows are still counted for the timeline");
        assert_eq!(points[0].value_count, 0, "but none of them carried a number");
        assert_eq!(points[0].avg, None, "and the average must be absent, NOT 0.0");
        assert_eq!(points[0].min, None);
        assert_eq!(points[0].max, None);
    }

    /// A leaf that is sometimes null must average over the values that exist, and say how many those
    /// were — an average over 2 of 10 rows is not the same claim as an average over 10.
    #[test]
    fn nulls_are_skipped_and_counted_separately() {
        let conn = db_with(vec![
            mb("u", 10, json!({"ago": serde_json::Value::Null}), json!({})),
            mb("u", 11, json!({"ago": 4.0}), json!({})),
            mb("u", 12, json!({"ago": 6.0}), json!({})),
        ]);
        let spec = SeriesSpec {
            filter: QuerySpec { types: vec!["u".into()], ..Default::default() },
            field: Some("ago".into()),
            group: None,
            groups: vec![],
            bucket_nanos: 100,
        };
        let points = one_series(&conn, &spec);

        assert_eq!(points[0].count, 3);
        assert_eq!(points[0].value_count, 2);
        assert_eq!(points[0].avg, Some(5.0), "mean of 4 and 6, not of 4, 6 and 0");
    }

    #[test]
    fn grouping_splits_into_one_series_per_value_in_the_caller_s_order() {
        let conn = db_with(vec![
            mb("c", 10, json!({"v": 1.0}), json!({"cell": "1"})),
            mb("c", 11, json!({"v": 2.0}), json!({"cell": "2"})),
            mb("c", 12, json!({"v": 3.0}), json!({"cell": "3"})),
        ]);
        let spec = SeriesSpec {
            filter: QuerySpec { types: vec!["c".into()], ..Default::default() },
            field: Some("v".into()),
            group: Some(FieldRef::Attribute("cell".into())),
            // Deliberately not ascending: the caller's order is what decides colour, so it must be
            // what comes back.
            groups: vec!["3".into(), "1".into()],
            bucket_nanos: 100,
        };
        let got = series(&conn, &spec).unwrap();

        assert_eq!(
            got.iter().map(|s| s.group.clone()).collect::<Vec<_>>(),
            vec![Some("3".to_owned()), Some("1".to_owned())],
            "cell 2 was not requested and must not appear"
        );
        assert_eq!(got[0].points[0].avg, Some(3.0));
    }

    /// The filter has to apply to the chart exactly as it does to the table, or the plot describes
    /// different rows from the ones listed under it.
    #[test]
    fn the_series_query_honours_every_row_filter() {
        let conn = db_with(vec![
            mb("s", 10, json!({"v": 1.0}), json!({"unit": "a"})),
            mb("s", 20, json!({"v": 100.0}), json!({"unit": "b"})),
            mb("other", 30, json!({"v": 999.0}), json!({"unit": "a"})),
        ]);
        let spec = SeriesSpec {
            filter: QuerySpec {
                types: vec!["s".into()],
                attrs: vec![("unit".into(), "a".into())],
                from: Some(0),
                to: Some(50),
                ..Default::default()
            },
            field: Some("v".into()),
            group: None,
            groups: vec![],
            bucket_nanos: 100,
        };
        let points = one_series(&conn, &spec);

        assert_eq!(points[0].count, 1, "only the one row matching type AND attribute");
        assert_eq!(points[0].avg, Some(1.0));
    }

    /// With no field, the query is still useful: it is the timeline.
    #[test]
    fn no_field_yields_counts_only() {
        let conn = db_with(vec![m("s", 10, json!({})), m("s", 12, json!({})), m("s", 40, json!({}))]);
        let spec = SeriesSpec {
            filter: QuerySpec { types: vec!["s".into()], ..Default::default() },
            field: None,
            group: None,
            groups: vec![],
            bucket_nanos: 20,
        };
        let points = one_series(&conn, &spec);

        assert_eq!(points.len(), 2);
        assert_eq!(points[0].count, 2);
        assert_eq!(points[0].avg, None);
        assert_eq!(points[1].count, 1);
    }

    #[test]
    fn limit_is_clamped_to_the_maximum() {
        let (_, params) = build_query(&QuerySpec { limit: 99_999, ..Default::default() });
        assert_eq!(params.last(), Some(&SqlValue::Integer(MAX_LIMIT)));

        let (_, params) = build_query(&QuerySpec { limit: 0, ..Default::default() });
        assert_eq!(params.last(), Some(&SqlValue::Integer(1)));
    }
}
