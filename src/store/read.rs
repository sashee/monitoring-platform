//! Query building and row mapping for the read API (SPEC §7.1).
//!
//! SQL construction is a pure function so the predicate logic is testable without a database.

use anyhow::{Context, Result};
use rusqlite::{Connection, types::Value as SqlValue};

use crate::content_id::ContentId;
use crate::model::StoredMeasurement;

pub const DEFAULT_LIMIT: i64 = 100;
pub const MAX_LIMIT: i64 = 1000;

/// Where a measurement's `type` and `attributes` come from (SPEC §6.7).
///
/// **One constant, deliberately.** `measurement` still carries both columns and will until 4.0, so the
/// only thing stopping a query from reading the stale copy is that no query names it. Having exactly one
/// FROM clause is what makes that checkable — and it is what lets 4.0 be nothing but `DROP COLUMN`,
/// which matters because 4.0 is the one migration that cannot be rehearsed here: it has to arrive
/// through the pipeline, and once applied there is no reverting to a binary that expects the columns.
///
/// The join is **inner**, so a measurement whose series does not resolve would be invisible. Since 4.0
/// the schema makes that unreachable rather than merely unlikely: `series_id` is `NOT NULL` with a
/// foreign key, so the absent and the dangling case are both refused at write time. Through 3.2 and 3.3
/// the same guarantee cost a startup sweep that had to succeed before the socket was bound.
///
/// Queries about series rather than rows — the type list, attribute facets, the extent, an attribute
/// grouping — start from `series sr` instead and reach `measurement` through a correlated lookup on
/// `measurement_series_event_time_idx`, so their cost follows the number of series rather than of rows.
const FROM_MEASUREMENT: &str = "FROM measurement m JOIN series sr ON sr.id = m.series_id";

/// The same table without the join, for queries that read neither `type` nor `attributes`.
///
/// **Sound because the join can never remove a row.** Every measurement has a `series_id` — that is the
/// startup precondition above — so an inner join to a primary key matches exactly once, and dropping it
/// when nothing reads `sr` changes no result.
///
/// Worth the branch on measured cost, not on principle. On the deployed database the unfiltered timeline
/// goes 126 ms joined → 77 ms bare, on a query that reads nothing from `series` at all. It remains a
/// covering-index scan either way, so this is a constant factor on an already linear scan, not a change in
/// growth. The extent was the other beneficiary until it stopped scanning altogether — see
/// [`build_extent_query`].
const FROM_MEASUREMENT_ONLY: &str = "FROM measurement m";

/// Whether a filter set reads `series`. `body` is still a `measurement` column, so it does not count.
fn filters_need_series(spec: &QuerySpec) -> bool {
    !spec.types.is_empty() || !spec.attrs.is_empty()
}

fn from_clause(needs_series: bool) -> &'static str {
    if needs_series { FROM_MEASUREMENT } else { FROM_MEASUREMENT_ONLY }
}

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

    /// The column qualified by the table it now lives in: attributes moved to `series`, the body did
    /// not. Used everywhere the join itself is in scope (see [`FROM_MEASUREMENT`]).
    fn qualified(&self) -> &'static str {
        match self {
            FieldRef::Attribute(_) => "sr.attributes",
            FieldRef::Body(_) => "m.body",
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

/// Appends the `type`, time-window, attribute and body predicates to a query under construction.
///
/// Shared by the row query ([`build_query`]), the aggregated series query ([`build_series_query`]), facet
/// discovery and the extent — whole, or as its two halves where a query is driven from `series` —
/// deliberately, because a filter that meant one thing on the table and another on the chart above it
/// would be a chart that does not describe the rows beneath it. There is one predicate builder so that
/// cannot drift.
///
/// `params` is appended to, and the `?N` placeholders are derived from its length, so this must be
/// called at the point the caller wants these parameters bound.
fn push_filters(spec: &QuerySpec, where_clauses: &mut Vec<String>, params: &mut Vec<SqlValue>) {
    push_series_filters(spec, where_clauses, params);
    push_measurement_filters(spec, where_clauses, params);
}

/// The half of [`push_filters`] that constrains `series` (as `sr`): the type and the attributes.
///
/// Split out for the queries that are driven from `series` rather than from the rows — attribute facets,
/// the extent, and an attribute-grouped chart. They apply this half once per series and the other half
/// inside a correlated lookup on `measurement`, which is what makes their cost depend on how many series
/// there are rather than on how many rows.
fn push_series_filters(spec: &QuerySpec, where_clauses: &mut Vec<String>, params: &mut Vec<SqlValue>) {
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
        where_clauses.push(format!("sr.type IN ({placeholders})"));
    }
    push_field_filters("sr.attributes", &spec.attrs, where_clauses, params);
}

/// The half of [`push_filters`] that constrains `measurement` (as `m`): the window and the body leaves.
fn push_measurement_filters(
    spec: &QuerySpec,
    where_clauses: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
) {
    if let Some(from) = spec.from {
        params.push(SqlValue::Integer(from));
        where_clauses.push(format!("m.event_time >= ?{}", params.len()));
    }
    if let Some(to) = spec.to {
        params.push(SqlValue::Integer(to));
        where_clauses.push(format!("m.event_time < ?{}", params.len()));
    }
    push_field_filters("m.body", &spec.body, where_clauses, params);
}

/// Equality filters on the leaves of one JSON column.
///
/// Attributes and body leaves are the same predicate against different columns (see `FieldRef`), so
/// they share one builder rather than two that could drift in their guards. They now sit in different
/// *tables* too, which changes nothing about the predicate.
fn push_field_filters(
    column: &str,
    filters: &[(String, String)],
    where_clauses: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
) {
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

/// ` WHERE a AND b …`, or nothing when there are no clauses.
fn where_sql(clauses: &[String]) -> String {
    if clauses.is_empty() { String::new() } else { format!(" WHERE {}", clauses.join(" AND ")) }
}

/// Builds the SELECT and its bound parameters.
///
/// Ordering is always `event_time DESC, id DESC`, matching both indexes, with `id` breaking ties so
/// pagination stays stable when timestamps collide.
pub fn build_query(spec: &QuerySpec) -> (String, Vec<SqlValue>) {
    let mut sql = format!(
        "SELECT m.id, m.event_time, m.processed_time, sr.type, m.body, sr.attributes \
         {FROM_MEASUREMENT}"
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
            "(m.event_time < ?{t_idx} OR (m.event_time = ?{t_idx} AND m.id < ?{id_idx}))"
        ));
    }

    sql.push_str(&where_sql(&where_clauses));
    sql.push_str(" ORDER BY m.event_time DESC, m.id DESC LIMIT ?");
    params.push(SqlValue::Integer(spec.limit.clamp(1, MAX_LIMIT)));
    sql.push_str(&params.len().to_string());

    (sql, params)
}

// ---------------------------------------------------------------- facets: what is there to filter on

/// How many rows body-leaf discovery reads. See [`facets`] for why that half is a sample and the attribute
/// half is not.
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
    /// Rows examined for the body leaves. Equal to [`FACET_SCAN_LIMIT`] when the cap was reached. The
    /// attributes are exact and read no sample.
    pub scanned: i64,
    pub capped: bool,
}

/// Every type that has measurements, **in name order**.
///
/// Alphabetical rather than by row count. Count order sounds useful — busiest first — but the thing a reader
/// does with a list of twenty-nine names is *look for one*, and in count order that means reading all of
/// them. Name order also brings each family together (`bms.*`, `detected-devices.*`, `system.*`), which is
/// how these names are actually structured.
///
/// **No counts.** This used to say how many rows each type had, and that made it the most expensive query on
/// the page: a count is a walk over every entry of `measurement_series_event_time_idx`, so it grew with the
/// age of the database rather than with anything being viewed — 94 ms at a million rows, on every render.
/// `series.added_measurements` would answer instantly but answers a different question the moment anything
/// deletes rows (SPEC §6.7), so the count went rather than become a lie.
///
/// Driven from `series`, with one index probe per series to confirm it still has a row. That probe is what
/// keeps this a list of what is *in* the table rather than of everything ever added: today every series has
/// rows, and once retention exists one may not.
pub fn types(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT sr.type FROM series sr \
             WHERE EXISTS (SELECT 1 FROM measurement m WHERE m.series_id = sr.id) ORDER BY sr.type",
        )
        .context("preparing the type listing")?;
    let out = stmt
        .query_map([], |row| row.get(0))
        .context("listing types")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the type listing")?;
    Ok(out)
}

/// Adds one discovered value to a facet's options, or marks them truncated once they are full.
///
/// A JSON null reads as no value to filter on rather than as the string "null".
fn offer(values: &mut Vec<String>, truncated: &mut bool, value: Option<String>) {
    match value {
        Some(v) if values.len() < MAX_FACET_VALUES => values.push(v),
        Some(_) => *truncated = true,
        None => {}
    }
}

/// Attribute keys and their values over the slice, optionally for one key only. **Exact, from `series`.**
///
/// Attributes are a property of the series, so the question "which values occur in this slice" is "which
/// series have a row in it" — one probe of `measurement_series_event_time_idx` per series, rather than
/// reading rows and parsing the same attribute text once per row. On a million-row table that is 2.5 ms
/// against 31 ms for the old 2,000-row sample, and it is complete where the sample was not: a device that
/// stopped reporting early in a long window is still offered.
///
/// A body filter makes the probe a walk: each series is read until a row matches, so a series that matches
/// nothing is read across the whole window. That bounds it by the rows in the window, which is still no more
/// than the sample had to read to find its matches.
///
/// The json_type guard matches what `push_filters` will accept as a filter, so the UI cannot offer an
/// option that provably matches nothing (SPEC §7.1).
fn attribute_facets(conn: &Connection, spec: &QuerySpec, key: Option<&str>) -> Result<Vec<AttrFacet>> {
    let mut params = Vec::new();
    let mut series_where = Vec::new();
    push_series_filters(spec, &mut series_where, &mut params);
    let mut row_where = vec!["m.series_id = sr.id".to_owned()];
    push_measurement_filters(spec, &mut row_where, &mut params);
    series_where.push(format!("EXISTS (SELECT 1 FROM measurement m{})", where_sql(&row_where)));
    series_where.push("j.type NOT IN ('object','array')".to_owned());
    if let Some(key) = key {
        params.push(SqlValue::Text(key.to_owned()));
        series_where.push(format!("j.key = ?{}", params.len()));
    }

    let sql = format!(
        "SELECT j.key, CAST(j.value AS TEXT) FROM series sr, json_each(sr.attributes) j{} \
         GROUP BY 1, 2 ORDER BY 1, 2",
        where_sql(&series_where)
    );
    let mut stmt = conn.prepare(&sql).context("preparing the attribute facet query")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |row| {
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
        offer(&mut facet.values, &mut facet.truncated, value);
    }
    Ok(attrs)
}

/// The `WITH sample AS (…)` prefix every body-facet query shares: the newest matching rows, capped.
///
/// Joins `series` only when the filters read it, for the reason [`FROM_MEASUREMENT_ONLY`] gives.
fn build_body_sample(spec: &QuerySpec) -> (String, Vec<SqlValue>) {
    let mut where_clauses = Vec::new();
    let mut params = Vec::new();
    push_filters(spec, &mut where_clauses, &mut params);

    params.push(SqlValue::Integer(FACET_SCAN_LIMIT));
    let sql = format!(
        "WITH sample AS (SELECT m.body AS body {}{} ORDER BY m.event_time DESC, m.id DESC LIMIT ?{})",
        from_clause(filters_need_series(spec)),
        where_sql(&where_clauses),
        params.len()
    );
    (sql, params)
}

/// Discovers what is filterable and chartable in the slice `spec` describes.
///
/// **Attributes are exact; body leaves are a bounded sample.** Attributes belong to the series, and there
/// are orders of magnitude fewer series than rows — see [`attribute_facets`]. A body leaf belongs to each
/// row, so discovering one means reading rows, and a full scan of the largest type costs 145 ms today and
/// grows with the table: this host projects millions of rows a year, so the same page would take seconds
/// within a year of running. So body discovery reads the newest [`FACET_SCAN_LIMIT`] matching rows, which
/// makes its cost depend on the window being viewed rather than on how long the Pi has been up.
///
/// What makes that sound is that **body shape is uniform per type**: every row of a type carries the same
/// leaves, so a few hundred rows reveal every one. Distinct *values* can be missed, which is why
/// [`Facets::capped`] exists for the UI to say so.
///
/// **Only discovery is sampled. Filtering is always exact** over the whole window: these facets
/// populate the controls, they never restrict what a query returns.
pub fn facets(conn: &Connection, spec: &QuerySpec) -> Result<Facets> {
    let attrs = attribute_facets(conn, spec, None)?;
    let (prefix, base_params) = build_body_sample(spec);

    // Body leaves, with their values: the same grouping and cap as the attributes. The `numeric` flag rides
    // along because it decides what can be *plotted* rather than what can be filtered.
    //
    // `json_type(s.body) = 'object'` guards both a NULL body and the scalar case: every type on this host
    // has an object body today, but json_each over a scalar yields one keyless row that would show up as a
    // field named nothing.
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
        offer(&mut facet.values, &mut facet.truncated, value);
    }

    // How much was actually looked at, so the UI can say whether the body options are complete.
    let count_sql = format!("{prefix} SELECT count(*) FROM sample");
    let scanned: i64 = conn
        .query_row(&count_sql, rusqlite::params_from_iter(base_params), |row| row.get(0))
        .context("counting the facet sample")?;

    Ok(Facets { attrs, fields, scanned, capped: scanned >= FACET_SCAN_LIMIT })
}

/// The values to offer for one field, discovered with **that field's own filter removed**.
///
/// Without this, a filter is a one-way door. [`facets`] scopes discovery to every applied filter, which is
/// what keeps the options relevant — but applied to the key being filtered it is circular: once
/// `cell = 3` is set, the only rows sampled have `cell = 3`, so the only value left to offer for `cell`
/// is `3`, and changing your mind means clearing the filter and re-applying. That is the standard
/// faceted-search rule: a key's options answer *"what else could I choose here, given my other filters"*,
/// so its own filter is the one thing excluded from the question.
///
/// Only called for keys that actually have a filter applied — for the rest [`facets`] is already correct —
/// so the extra cost is one query per active filter, not per key. Discovered the same way [`facets`]
/// discovers that half: exactly from `series` for an attribute, from the sample for a body leaf.
pub fn facet_values_excluding(
    conn: &Connection,
    spec: &QuerySpec,
    field: &FieldRef,
) -> Result<AttrFacet> {
    let key = field.name();
    let empty = || AttrFacet { key: key.to_owned(), values: Vec::new(), truncated: false };

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
    if let FieldRef::Attribute(_) = field {
        return Ok(attribute_facets(conn, &widened, Some(key))?.into_iter().next().unwrap_or_else(empty));
    }

    let (prefix, mut params) = build_body_sample(&widened);
    params.push(SqlValue::Text(key.to_owned()));
    let sql = format!(
        "{prefix} SELECT CAST(j.value AS TEXT) FROM sample s, json_each(s.body) j \
         WHERE j.key = ?{} AND j.type NOT IN ('object','array') GROUP BY 1 ORDER BY 1",
        params.len()
    );

    let mut stmt = conn.prepare(&sql).context("preparing the widened facet query")?;
    let values = stmt
        .query_map(rusqlite::params_from_iter(params), |row| row.get::<_, Option<String>>(0))
        .context("running the widened facet query")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the widened facet values")?;

    let mut facet = empty();
    for value in values {
        offer(&mut facet.values, &mut facet.truncated, value);
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
/// **Index seeks, not a scan.** SQLite answers `min(x)` or `max(x)` with one seek on an index over `x`, but
/// only when the aggregate stands alone — `SELECT min(x), max(x)` is a full scan, 83 ms at a million rows.
/// So each bound is its own scalar subquery:
///
/// - with no type or attribute filter, two seeks on `measurement_event_time_idx`;
/// - with one, two seeks per matching series on `measurement_series_event_time_idx`, folded by an outer
///   `min`/`max` — 1.9 ms for `bms.status.cell`'s 112 series, against 43 ms for the joined scan.
///
/// Exact either way, so it stays true once rows are deleted — unlike `series.added_event_time_*`, which
/// would answer as fast but describes what was ever added (SPEC §6.7).
///
/// **A body filter falls back to the scan.** It turns each seek into a walk that stops at the first matching
/// row, and for a series where none matches that is every row it has, twice over. The explorer never asks
/// for that — its `all` window deliberately ignores the value filters — but a caller who does should get the
/// one-pass scan rather than the trap.
pub fn build_extent_query(spec: &QuerySpec) -> (String, Vec<SqlValue>) {
    let mut params = Vec::new();

    if !spec.body.is_empty() {
        let mut where_clauses = Vec::new();
        push_filters(spec, &mut where_clauses, &mut params);
        let sql = format!(
            "SELECT min(m.event_time), max(m.event_time) {}{}",
            from_clause(filters_need_series(spec)),
            where_sql(&where_clauses)
        );
        return (sql, params);
    }

    let mut series_where = Vec::new();
    push_series_filters(spec, &mut series_where, &mut params);
    let mut row_where = Vec::new();
    if !series_where.is_empty() {
        row_where.push("m.series_id = sr.id".to_owned());
    }
    push_measurement_filters(spec, &mut row_where, &mut params);
    // Both subqueries bind the same parameters: the placeholders are numbered, not positional.
    let bound =
        |agg: &str| format!("(SELECT {agg}(m.event_time) FROM measurement m{})", where_sql(&row_where));

    let sql = if series_where.is_empty() {
        format!("SELECT {}, {}", bound("min"), bound("max"))
    } else {
        format!(
            "SELECT min({}), max({}) FROM series sr{}",
            bound("min"),
            bound("max"),
            where_sql(&series_where)
        )
    };
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
///
/// And two that are about not repeating work on every row, which is where the time goes on a long window —
/// together they take thirty days of sixteen cells from 1.4 s to 0.76 s on a million-row table:
///
/// - **The value is extracted once per row.** Written into each of the four aggregates, it was extracted
///   four times. The row source `r` computes it once, as a column, and is `MATERIALIZED` so SQLite cannot
///   inline it back into the aggregates. Only when there is a value, though: for the count-only timeline
///   the materialisation is pure overhead (40% on a 30-day window), so there it is inlined.
/// - **An attribute group is resolved once per series**, since it is a property of the series. `sg` reads it
///   off the `series` rows that pass the series-level filters, and the rows join to that — `MATERIALIZED`
///   for the same reason as `r`.
pub fn build_series_query(spec: &SeriesSpec) -> (String, Vec<SqlValue>) {
    let mut where_clauses = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();

    // Where the group comes from decides what the rows are read from.
    let (series_cte, from, group_expr) = match &spec.group {
        Some(field @ FieldRef::Attribute(_)) => {
            let mut series_where = Vec::new();
            push_series_filters(&spec.filter, &mut series_where, &mut params);
            let expr = push_group(field, &spec.groups, &mut series_where, &mut params);
            push_measurement_filters(&spec.filter, &mut where_clauses, &mut params);
            (
                format!(
                    "sg AS MATERIALIZED (SELECT sr.id AS id, {expr} AS g FROM series sr{}), ",
                    where_sql(&series_where)
                ),
                "FROM measurement m JOIN sg ON sg.id = m.series_id",
                "sg.g".to_owned(),
            )
        }
        group => {
            push_filters(&spec.filter, &mut where_clauses, &mut params);
            let expr = match group {
                Some(field) => push_group(field, &spec.groups, &mut where_clauses, &mut params),
                None => "NULL".to_owned(),
            };
            (String::new(), from_clause(filters_need_series(&spec.filter)), expr)
        }
    };

    let value_expr = match &spec.field {
        Some(field) => {
            params.push(SqlValue::Text(json_path(field)));
            let p = params.len();
            format!(
                "CASE WHEN json_type(m.body, ?{p}) IN ('integer','real') \
                 THEN json_extract(m.body, ?{p}) END"
            )
        }
        None => "NULL".to_owned(),
    };

    params.push(SqlValue::Integer(spec.bucket_nanos.max(1)));
    let bucket_param = params.len();

    let materialized = if spec.field.is_some() { "MATERIALIZED" } else { "NOT MATERIALIZED" };
    // Grouped by the bucket's start rather than its index so the value selected is the one plotted,
    // and ordered so `series` can fold consecutive rows into one series without a map.
    let sql = format!(
        "WITH {series_cte}r AS {materialized} \
         (SELECT {group_expr} AS g, m.event_time AS t, {value_expr} AS v {from}{where_}) \
         SELECT g, (t / ?{bucket_param}) * ?{bucket_param} AS bucket_start, \
         count(*), count(v), avg(v), min(v), max(v) \
         FROM r GROUP BY g, bucket_start ORDER BY g, bucket_start",
        where_ = where_sql(&where_clauses)
    );

    (sql, params)
}

/// The expression a chart is split by, restricting `where_clauses` to the requested group values if any.
///
/// Nested values resolve to NULL rather than to their serialized text, for the reason `push_filters`
/// gives: matching on SQLite's serialization would be an accidental API.
fn push_group(
    field: &FieldRef,
    groups: &[String],
    where_clauses: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
) -> String {
    let column = field.qualified();
    params.push(SqlValue::Text(json_path(field.name())));
    let p = params.len();
    if !groups.is_empty() {
        let placeholders = groups
            .iter()
            .map(|g| {
                params.push(SqlValue::Text(g.clone()));
                format!("?{}", params.len())
            })
            .collect::<Vec<_>>()
            .join(", ");
        where_clauses.push(format!("CAST(json_extract({column}, ?{p}) AS TEXT) IN ({placeholders})"));
    }
    format!(
        "CASE WHEN json_type({column}, ?{p}) IN ('object','array') THEN NULL \
         ELSE CAST(json_extract({column}, ?{p}) AS TEXT) END"
    )
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

    // --------------------------------------------------- the read path reads `series`, and only `series`

    /// **The de-synchronisation test that used to live here cannot be written any more, and that is the
    /// point.** Through 3.3 it overwrote `measurement.type` and `measurement.attributes` with values the
    /// `series` row did not say, then demanded the `series` answer from every read — the only way to tell
    /// the two sources apart while both existed. 4.0 deleted the columns, so the guard it provided is now
    /// structural. This asserts that structure directly, so a future migration cannot quietly put a
    /// second copy back and let reads drift onto it.
    #[test]
    fn measurement_has_no_type_or_attributes_of_its_own() {
        let conn = db_with(vec![m("gps", 10, json!({"record.attributes.unit": "wgs84"}))]);

        let columns: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('measurement') ORDER BY cid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(columns, vec!["id", "event_time", "processed_time", "body", "series_id"]);
        for gone in ["type", "attributes"] {
            assert!(!columns.iter().any(|c| c == gone), "`{gone}` came back on measurement");
        }
    }

    /// Every read still resolves both fields, now necessarily through the join. Kept as a whole-surface
    /// sweep rather than trusting the column check above: these are the seven shapes that would have to
    /// be rewritten if the source ever moved again.
    #[test]
    fn every_read_resolves_type_and_attributes_through_the_join() {
        let conn = db_with(vec![m("gps", 10, json!({"record.attributes.unit": "wgs84"}))]);

        let rows = query(&conn, &QuerySpec { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "gps");
        assert_eq!(rows[0].attributes["record.attributes.unit"], json!("wgs84"));

        assert_eq!(types(&conn).unwrap(), vec!["gps".to_owned()]);

        let by_type = QuerySpec { types: vec!["gps".into()], limit: 10, ..Default::default() };
        assert_eq!(query(&conn, &by_type).unwrap().len(), 1);
        assert!(
            query(&conn, &QuerySpec { types: vec!["nope".into()], limit: 10, ..Default::default() })
                .unwrap()
                .is_empty()
        );

        let attr_hit = QuerySpec {
            attrs: vec![("record.attributes.unit".into(), "wgs84".into())],
            limit: 10,
            ..Default::default()
        };
        assert_eq!(query(&conn, &attr_hit).unwrap().len(), 1);

        let facets = facets(&conn, &QuerySpec { limit: 10, ..Default::default() }).unwrap();
        let unit = facets.attrs.iter().find(|f| f.key == "record.attributes.unit").unwrap();
        assert_eq!(unit.values, vec!["wgs84".to_owned()]);

        assert_eq!(extent(&conn, &by_type).unwrap(), Some((10, 10)));

        let grouped = series(
            &conn,
            &SeriesSpec {
                filter: QuerySpec { limit: 10, ..Default::default() },
                field: None,
                group: Some(FieldRef::Attribute("record.attributes.unit".into())),
                groups: vec!["wgs84".to_owned()],
                bucket_nanos: 1_000,
            },
        )
        .unwrap();
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].group.as_deref(), Some("wgs84"));
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
    fn types_are_listed_by_name() {
        let conn = db_with(vec![
            m("zebra", 10, json!({})),
            m("zebra", 20, json!({})),
            m("zebra", 25, json!({ "other": "series" })),
            m("apple", 30, json!({})),
        ]);
        // `apple` is rarer but comes first, which is the point — and `zebra`'s two series list it once.
        assert_eq!(types(&conn).unwrap(), vec!["apple".to_owned(), "zebra".to_owned()]);
    }

    /// **The list describes what is in the table, not what was ever added.** A series outlives its rows —
    /// its `added_*` bookkeeping is the only record of what it carried (SPEC §6.7) — so once retention
    /// deletes them, a type listed from `series` alone would offer a choice that shows nothing.
    #[test]
    fn a_type_whose_rows_are_all_gone_is_not_listed() {
        let conn = db_with(vec![m("kept", 10, json!({})), m("expired", 20, json!({}))]);
        conn.execute(
            "DELETE FROM measurement WHERE series_id IN (SELECT id FROM series WHERE type = 'expired')",
            [],
        )
        .unwrap();

        assert_eq!(types(&conn).unwrap(), vec!["kept".to_owned()]);
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

    /// **The regression test for the gap sampling left.** Attribute options used to come from the newest
    /// [`FACET_SCAN_LIMIT`] rows, so a device that stopped reporting early in the window was not offered —
    /// nor drawn when grouping by it, since a chart's groups are these options. They come from `series` now,
    /// and are exact however many rows bury it.
    #[test]
    fn attribute_options_are_exact_beyond_the_sample() {
        let mut rows: Vec<Measurement> = (1..=FACET_SCAN_LIMIT)
            .map(|i| mb("c", 1_000 + i, json!({ "v": i }), json!({"cell": "1"})))
            .collect();
        rows.push(mb("c", 10, json!({"v": 0}), json!({"cell": "2"})));
        let conn = db_with(rows);

        let f = facets(&conn, &QuerySpec { types: vec!["c".into()], ..Default::default() }).unwrap();
        assert!(f.capped, "precondition: the body sample is full and does not reach cell 2's row");
        let cell = f.attrs.iter().find(|a| a.key == "cell").expect("cell");
        assert_eq!(cell.values, vec!["1", "2"]);
    }

    /// Exact must still mean *in this slice*: a series whose rows all fall outside the window is not offered.
    #[test]
    fn attribute_options_are_scoped_to_the_window() {
        let conn = db_with(vec![
            mb("c", 10, json!({"v": 1}), json!({"cell": "1"})),
            mb("c", 20, json!({"v": 2}), json!({"cell": "2"})),
            mb("c", 30, json!({"v": 3}), json!({"cell": "3"})),
        ]);
        let spec = QuerySpec { from: Some(15), to: Some(30), ..Default::default() };

        let f = facets(&conn, &spec).unwrap();
        let cell = f.attrs.iter().find(|a| a.key == "cell").expect("cell");
        assert_eq!(cell.values, vec!["2"], "10 is before the window, 30 is its exclusive end");
    }

    /// A body filter is a property of rows, not of series, so it has to reach into the per-series lookup:
    /// a series is only offered if one of *its rows* matches.
    #[test]
    fn attribute_options_honour_body_filters() {
        let conn = db_with(vec![
            mb("wifi", 10, json!({"ssid": "home"}), json!({"bssid": "aa"})),
            mb("wifi", 11, json!({"ssid": "cafe"}), json!({"bssid": "bb"})),
            mb("wifi", 12, json!({"ssid": "home"}), json!({"bssid": "cc"})),
        ]);
        let spec =
            QuerySpec { body: vec![("ssid".to_owned(), "home".to_owned())], ..Default::default() };

        let f = facets(&conn, &spec).unwrap();
        let bssid = f.attrs.iter().find(|a| a.key == "bssid").expect("bssid");
        assert_eq!(bssid.values, vec!["aa", "cc"]);
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

    // ------------------------------------------------------------------------------- extent

    /// Two series of one type, one of another. The per-series form has to fold across series and must not
    /// reach the other type; the bare form has to cover everything.
    #[test]
    fn the_extent_spans_every_matching_series_and_nothing_else() {
        let conn = db_with(vec![
            m("t", 10, json!({"unit": "a"})),
            m("t", 50, json!({"unit": "b"})),
            m("other", 5, json!({})),
            m("other", 100, json!({})),
        ]);
        let of = |spec: QuerySpec| extent(&conn, &spec).unwrap();

        assert_eq!(of(QuerySpec::default()), Some((5, 100)));
        assert_eq!(of(QuerySpec { types: vec!["t".into()], ..Default::default() }), Some((10, 50)));
        assert_eq!(
            of(QuerySpec {
                types: vec!["t".into()],
                attrs: vec![("unit".into(), "b".into())],
                ..Default::default()
            }),
            Some((50, 50))
        );
        assert_eq!(
            of(QuerySpec { types: vec!["t".into()], from: Some(20), ..Default::default() }),
            Some((50, 50)),
            "the window applies inside each series' lookup"
        );
        assert_eq!(of(QuerySpec { types: vec!["nope".into()], ..Default::default() }), None);
    }

    /// The body-filtered fallback answers the same question by the other route.
    #[test]
    fn a_body_filtered_extent_still_answers() {
        let conn = db_with(vec![
            mb("wifi", 10, json!({"ssid": "home"}), json!({})),
            mb("wifi", 20, json!({"ssid": "cafe"}), json!({})),
            mb("wifi", 30, json!({"ssid": "home"}), json!({})),
        ]);
        let spec = QuerySpec {
            types: vec!["wifi".into()],
            body: vec![("ssid".to_owned(), "home".to_owned())],
            ..Default::default()
        };
        assert_eq!(extent(&conn, &spec).unwrap(), Some((10, 30)));
    }

    /// **The extent must stay a handful of seeks.** `SELECT min(x), max(x)` reads naturally and walks every
    /// row — SQLite's min/max shortcut only applies to an aggregate on its own — so the regression this
    /// guards against is the obvious simplification, and it would not change a single result. Pinned on the
    /// work done instead: a thousand rows, and fewer virtual-machine steps than that. Not on the query plan,
    /// which reads `SEARCH` for the per-series walk this replaced just as it does for the seeks.
    #[test]
    fn the_extent_does_not_walk_the_rows() {
        const ROWS: i64 = 1_000;
        let conn = db_with((0..ROWS).map(|i| m("t", i, json!({ "unit": i % 2 }))).collect());
        let window = QuerySpec { from: Some(i64::MIN), to: Some(i64::MAX), ..Default::default() };

        for spec in [
            QuerySpec::default(),
            window.clone(),
            QuerySpec { types: vec!["t".into()], ..window.clone() },
            QuerySpec { attrs: vec![("unit".into(), "1".into())], ..window },
        ] {
            let (sql, params) = build_extent_query(&spec);
            let mut stmt = conn.prepare(&sql).unwrap();
            let (min, max): (i64, i64) = stmt
                .query_row(rusqlite::params_from_iter(params), |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap();
            assert!(min < max, "{spec:?} found no extent");
            let steps = stmt.get_status(rusqlite::StatementStatus::VmStep);
            assert!(i64::from(steps) < ROWS, "{spec:?} took {steps} steps over {ROWS} rows: {sql}");
        }
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

    /// The same, for the shape an attribute grouping takes: the type and attribute filters move into the
    /// per-series CTE while the window and body filters stay on the rows, and each must still bind to its
    /// own parameter.
    #[test]
    fn an_attribute_grouping_honours_every_row_filter() {
        let conn = db_with(vec![
            mb("c", 10, json!({"v": 1.0, "ok": "y"}), json!({"cell": "1", "pack": "a"})),
            mb("c", 11, json!({"v": 2.0, "ok": "n"}), json!({"cell": "1", "pack": "a"})),
            mb("c", 12, json!({"v": 3.0, "ok": "y"}), json!({"cell": "2", "pack": "a"})),
            mb("c", 13, json!({"v": 4.0, "ok": "y"}), json!({"cell": "3", "pack": "b"})),
            mb("c", 99, json!({"v": 5.0, "ok": "y"}), json!({"cell": "1", "pack": "a"})),
            mb("other", 10, json!({"v": 9.0, "ok": "y"}), json!({"cell": "1", "pack": "a"})),
        ]);
        let spec = SeriesSpec {
            filter: QuerySpec {
                types: vec!["c".into()],
                attrs: vec![("pack".into(), "a".into())],
                body: vec![("ok".into(), "y".into())],
                from: Some(0),
                to: Some(50),
                ..Default::default()
            },
            field: Some("v".into()),
            group: Some(FieldRef::Attribute("cell".into())),
            groups: vec!["1".into(), "2".into(), "3".into()],
            bucket_nanos: 100,
        };
        let got = series(&conn, &spec).unwrap();

        let summary: Vec<_> =
            got.iter().map(|s| (s.group.clone().unwrap(), s.points[0].count, s.points[0].avg)).collect();
        assert_eq!(
            summary,
            vec![("1".to_owned(), 1, Some(1.0)), ("2".to_owned(), 1, Some(3.0))],
            "cell 3 is pack b; v=2 fails the body filter; v=5 is outside the window; `other` is another type"
        );
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
