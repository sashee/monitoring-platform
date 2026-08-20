//! The browser-facing interface (SPEC §14): a login form, the measurement explorer, and the two
//! credential tables.
//!
//! This is not a second API. It shares the router, the socket and the database with §7's JSON read API and
//! nothing else — in particular **not** the credential.
//! [`crate::api::app`] applies the session layer to these routes and the API-key layer to `/v1/*`, so a
//! cookie cannot reach an OTLP endpoint and a bearer token cannot open a page. That separation is asserted
//! in both directions in `tests/web.rs`, because it is true by construction today and would stop being true
//! the moment someone hoisted a layer out to wrap the merge.
//!
//! Everything is server-rendered, with no JavaScript and no static assets: the styling is inline (see
//! [`html`]), the plots are inline SVG (see [`svg`]), and every control is a plain form submit. A page
//! that needed a build step would need one on the Pi too.
//!
//! **State lives in the URL, not in the browser.** With no scripting, "which type is selected" is a fact
//! about the query string, re-read on every request and re-rendered into the controls. That makes every
//! view a link you can bookmark or paste, which is worth more here than it costs.

pub mod html;
pub mod origin;
pub mod session;
pub mod svg;

use axum::extract::{Form, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;

use crate::AppState;
use crate::api::query::format_nanos;
use crate::model::StoredMeasurement;
use crate::store::read::{
    Facets, FieldRef, MAX_SERIES, Point, QuerySpec, Series, SeriesSpec, TypeCount, bucket_nanos,
};
use session::Identity;

/// Rows the explorer's table shows per page.
const PAGE_LIMIT: i64 = 100;

/// Buckets across the window. 240 across a ~800px plot is about three pixels each — finer would be
/// detail no screen can show, coarser would smooth away real movement.
const SERIES_BUCKETS: i64 = 240;

const SEC: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * SEC;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;

/// The time presets, and the span each covers. `all` derives its window from the data.
///
/// Presets rather than only a pair of date fields, because the range is the control every reader reaches
/// for first and nobody wants to type two timestamps to see the last hour.
const RANGES: &[(&str, &str, i64)] = &[
    ("15m", "last 15 min", 15 * MINUTE),
    ("1h", "last hour", HOUR),
    ("6h", "last 6 hours", 6 * HOUR),
    ("24h", "last 24 hours", DAY),
    ("7d", "last 7 days", 7 * DAY),
    ("30d", "last 30 days", 30 * DAY),
    ("all", "all time", 0),
];
const DEFAULT_RANGE: &str = "24h";

/// The routes requiring a session, and the login routes that must not.
///
/// Returned as two routers rather than one so the caller applies the guard to exactly the first — the same
/// arrangement, and for the same reason, as `/healthz` sitting outside the API-key layer.
///
/// The origin check ([`origin::guard`]) wraps **both**: it applies to `/login` too, since minting a
/// session is a state change and login CSRF is a real attack (SPEC §14.3).
pub fn routers(state: AppState) -> (Router<AppState>, Router<AppState>) {
    let guarded = Router::new()
        .route("/", get(explore))
        .route("/chart", get(chart))
        .route("/users", get(users))
        .route("/users/create", post(create_user))
        .route("/users/delete", post(delete_user))
        .route("/keys", get(keys))
        .route("/keys/create", post(create_key))
        .route("/keys/delete", post(delete_key))
        .route("/sessions", get(sessions))
        .route("/sessions/end", post(end_session))
        .route("/logout", post(logout))
        .layer(axum::middleware::from_fn_with_state(state, session::guard))
        // Outside the session layer, so a forged POST is refused before its cookie is even looked up.
        // The tuple is spelled out because `from_fn` cannot infer it for a middleware that takes no
        // extractors of its own.
        .route_layer(axum::middleware::from_fn::<_, (Request,)>(origin::guard));

    // No session guard, by definition: this is how a request with no session acquires one. It still
    // carries the origin check.
    let open = Router::new()
        .route("/login", get(login_form).post(login))
        .route_layer(axum::middleware::from_fn::<_, (Request,)>(origin::guard));

    (guarded, open)
}

/// An HTML response. `text/html` with an explicit charset, because a browser left to guess at the encoding
/// of a page containing device-supplied UTF-8 can guess wrong.
fn html(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

/// `303 See Other`, root-relative.
///
/// `303` rather than `302` after a successful `POST`: it is the status that tells the browser to follow up
/// with a `GET`, which is what stops a reload from re-submitting the form.
fn see_other(location: &'static str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

/// A response that ends the caller's own session: redirect to the form, and clear the cookie.
///
/// Deleting your own user, or ending your own session, both land here. Sending the browser to a page it
/// can no longer load would render as a redirect loop.
fn logged_out() -> Response {
    let mut response = see_other("/login");
    session::set_cookie(&mut response, &session::clearing_cookie());
    response
}

/// A handler-level failure, rendered as a page rather than an empty 500.
///
/// The message names what was being attempted but **not** the error, which is deliberate: an anyhow chain
/// from rusqlite carries file paths and SQL, and this page is behind a login but a login is not a reason to
/// publish the layout of the filesystem. The full error goes to the journal, where §9.2 sends it anyway.
fn failed(doing: &str, error: &dyn std::fmt::Display) -> Response {
    tracing::error!(%error, "{doing} failed");
    html(
        StatusCode::INTERNAL_SERVER_ERROR,
        html::page(
            "error",
            "",
            &format!("<p class=\"error\">{} failed. The journal has the details.</p>\n", html::escape(doing)),
        ),
    )
}

// ------------------------------------------------------------------------------------ the explorer

/// The explorer's parameters, parsed out of the query string.
#[derive(Debug, Default, Clone)]
struct Explore {
    range: String,
    from: Option<i64>,
    to: Option<i64>,
    kind: Option<String>,
    attrs: Vec<(String, String)>,
    /// Body-leaf equality filters. Separate from `attrs` because they are a different column, not because
    /// a reader should care — see [`FieldRef`].
    body: Vec<(String, String)>,
    /// Body leaves to chart. One plot each — never two measures on one pair of axes.
    fields: Vec<String>,
    group: Option<FieldRef>,
    /// Series the reader has hidden by tapping the legend. Carried in the URL like every other bit of
    /// state, so a view with two networks hidden is still a link you can paste.
    hidden: Vec<String>,
    cursor: Option<(i64, crate::content_id::ContentId)>,
}

/// Parses the query string.
///
/// **Empty values are dropped rather than treated as filters.** A `GET` form submits every control it
/// contains, so an unset `<select>` arrives as `field=` — reading that as "filter where the field is the
/// empty string" would make clearing a filter impossible. This is the no-JS equivalent of not sending the
/// parameter at all.
///
/// Unknown parameters are ignored here, unlike §7.1's read API which rejects them. The difference is who
/// is calling: a device with a typo in a filter name deserves an error, whereas a person following a
/// stale bookmark deserves a page.
fn parse_explore(raw: &[(String, String)]) -> Explore {
    let mut out = Explore { range: DEFAULT_RANGE.to_owned(), ..Default::default() };
    let mut previous_kind = None;

    for (key, value) in raw {
        if value.is_empty() {
            continue;
        }
        match key.as_str() {
            "range" => out.range = value.clone(),
            "from" => out.from = parse_instant(value),
            "to" => out.to = parse_instant(value),
            "type" => out.kind = Some(value.clone()),
            // Repeats: a checkbox group submits one `field` per ticked box.
            "field" => out.fields.push(value.clone()),
            "group" => out.group = Some(FieldRef::parse(value)),
            // Which type the form was rendered for. See below.
            "t0" => previous_kind = Some(value.clone()),
            // Repeats: one per hidden series.
            "hide" => out.hidden.push(value.clone()),
            "cursor" => out.cursor = crate::api::query::decode_cursor(value).ok(),
            k if k.starts_with("attr.") => {
                let attr_key = &k["attr.".len()..];
                if !attr_key.is_empty() {
                    out.attrs.push((attr_key.to_owned(), value.clone()));
                }
            }
            k if k.starts_with("body.") => {
                let leaf = &k["body.".len()..];
                if !leaf.is_empty() {
                    out.body.push((leaf.to_owned(), value.clone()));
                }
            }
            _ => {}
        }
    }

    // **Changing the type clears everything scoped to the old one.** The filter row is one form, so
    // switching the type resubmits the previous type's attribute selects alongside it — and those keys do
    // not exist on the new type, so the page would come back empty with no hint why. `t0` carries the type
    // the form was rendered for; a mismatch means the reader has just changed it.
    if let Some(previous) = previous_kind
        && out.kind.as_deref() != Some(previous.as_str())
    {
        out.attrs.clear();
        out.body.clear();
        out.fields.clear();
        out.group = None;
        out.hidden.clear();
        out.cursor = None;
    }
    out
}

/// Accepts RFC 3339 or a bare nanosecond count, the two forms §7.1 already accepts.
fn parse_instant(s: &str) -> Option<i64> {
    if !s.is_empty() && s.trim_start_matches('-').bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().ok();
    }
    s.parse::<jiff::Timestamp>().ok().and_then(|t| i64::try_from(t.as_nanosecond()).ok())
}

impl Explore {
    /// The row filter, shared by the table, the timeline and the value chart.
    fn filter(&self, window: (i64, i64), limit: i64) -> QuerySpec {
        QuerySpec {
            types: self.kind.iter().cloned().collect(),
            from: Some(window.0),
            to: Some(window.1),
            attrs: self.attrs.clone(),
            body: self.body.clone(),
            limit,
            cursor: self.cursor,
        }
    }
}

/// Everything one render of the explorer needs, gathered in a single blocking task.
///
/// One struct and one connection rather than a `spawn_blocking` per query: they all have to read the same
/// snapshot, and separate tasks could each see a different one — the chart would then describe rows the
/// table does not list.
struct ExploreData {
    types: Vec<TypeCount>,
    facets: Facets,
    window: (i64, i64),
    bucket: i64,
    timeline: Vec<Point>,
    /// One entry per chosen field: the field, its series, and how many groups exist for it.
    charts: Vec<Chart>,
    rows: Vec<StoredMeasurement>,
    more: bool,
    /// Measurements still waiting for a `series_id` (SPEC §6.7). Surfaced only while non-zero, because
    /// it is the signal that decides when the 4.0 migration is safe to deploy — and once the sweep has
    /// converged there is nothing to say. An index probe, so it costs nothing per render.
    series_pending: i64,
}

struct Chart {
    field: String,
    /// Only the visible series, in the order of `groups`.
    series: Vec<Series>,
    /// Each visible series' slot: its index in the **full** ordered group list, which is what keeps a
    /// line's colour and pattern the same when another line is hidden.
    slots: Vec<usize>,
    /// Every group, hidden or not, in the order that decides slots.
    groups: Vec<String>,
    /// How many groups exist, which may exceed what one plot will draw.
    total_groups: usize,
}

/// Everything a render of the explorer or of one full-page chart needs, from one connection.
///
/// Shared by both handlers so the full-page view cannot disagree with the inline one about the window, the
/// buckets or the series — they are the same chart at two sizes, and a second copy of this resolution
/// order is how that would quietly stop being true.
fn gather(conn: &rusqlite::Connection, p: &Explore, now: i64) -> anyhow::Result<ExploreData> {
let types = crate::store::read::types(conn)?;

    // The window, in order of precedence: an explicit bound wins, then a preset, then the extent of
    // the data itself. `all` has to be a query, because the answer is a property of the rows.
    let span = RANGES.iter().find(|(id, _, _)| *id == p.range).map(|(_, _, s)| *s);
    let window = match (p.from, p.to, span) {
        (Some(from), Some(to), _) => (from, to),
        (Some(from), None, _) => (from, now),
        (None, Some(to), Some(s)) if s > 0 => (to.saturating_sub(s), to),
        (None, _, Some(s)) if s > 0 => (now.saturating_sub(s), now),
        // `all`, or an unrecognised preset from a stale bookmark.
        // **`+ 1` on the upper bound, and it is load-bearing.** The window is applied as
        // `event_time < to` (§7.1's exclusive upper bound), so a window of `[min, max]` taken straight
        // from the data excludes the newest row — every time, silently. Visible as "half my rows are
        // missing" with two of them and as nothing at all with a thousand, which is the worse case.
        _ => {
            // **The extent ignores the value filters**, taking only the type into account. Two reasons,
            // both about the window being a stable frame rather than a consequence of the filters: an axis
            // that rescales every time a filter changes makes two views impossible to compare, and — worse
            // — a window derived from `ssid = cafe` rows contains only those rows, so widening that same
            // filter's options (the one-way-door fix) would find nothing else to offer and the door would
            // close again through the back.
            let mut unfiltered = p.filter((i64::MIN, i64::MAX), PAGE_LIMIT);
            unfiltered.attrs.clear();
            unfiltered.body.clear();
            crate::store::read::extent(conn, &unfiltered)?
                .map(|(min, max)| (min, max.saturating_add(1)))
                .unwrap_or((now.saturating_sub(DAY), now))
        }
    };
    // A degenerate window — one row, or none at all — still needs a plottable domain.
    let window = if window.1 > window.0 { window } else { (window.0, window.0 + SEC) };

    let filter = p.filter(window, PAGE_LIMIT);
    let mut facets = crate::store::read::facets(conn, &filter)?;
    let bucket = bucket_nanos(window.0, window.1, SERIES_BUCKETS);

    // **A key that is being filtered has its own filter excluded from its own options**, or the
    // dropdown collapses to the one value already chosen and the filter becomes a one-way door. Only
    // the actively-filtered keys need re-asking; for the rest the scoped answer is already right.
    for (key, _) in &filter.attrs {
        let widened = crate::store::read::facet_values_excluding(
            conn,
            &filter,
            &FieldRef::Attribute(key.clone()),
        )?;
        match facets.attrs.iter_mut().find(|a| a.key == *key) {
            Some(existing) => *existing = widened,
            // The key is filtered but absent from the sample — a filter that matches nothing. Offering
            // its other values is exactly how the reader gets back out.
            None => facets.attrs.push(widened),
        }
    }
    facets.attrs.sort_by(|a, b| a.key.cmp(&b.key));

    // The same widening for body leaves: a filtered field's own options must not be narrowed by its own
    // filter, whichever half of the measurement it lives in.
    for (leaf, _) in &filter.body {
        let widened =
            crate::store::read::facet_values_excluding(conn, &filter, &FieldRef::Body(leaf.clone()))?;
        if let Some(existing) = facets.fields.iter_mut().find(|f| f.name == *leaf) {
            existing.values = widened.values;
            existing.truncated = widened.truncated;
        }
    }

    // Numerically where the values are numbers, so a dropdown of sixteen cells reads 1, 2, 3 … rather
    // than SQL's collation order of 1, 10, 11 … 2. The same function the chart uses to decide series
    // order, for the same reason: lexicographic order on numbers is not what a reader expects.
    for facet in &mut facets.attrs {
        crate::store::read::sort_facet_values(&mut facet.values);
    }
    for facet in &mut facets.fields {
        crate::store::read::sort_facet_values(&mut facet.values);
    }

    // The timeline: counts only, ungrouped, so it renders whatever the bodies contain.
    let timeline = crate::store::read::series(
        conn,
        &SeriesSpec {
            filter: filter.clone(),
            field: None,
            group: None,
            groups: vec![],
            bucket_nanos: bucket,
        },
    )?
    .into_iter()
    .next()
    .map(|s| s.points)
    .unwrap_or_default();

    // The group values are the same for every chart, so they are resolved once. Sorted here, because
    // the order decides both which groups make the cap and which colour each gets.
    // The candidate values come from whichever half the group names.
    let mut group_values = match &p.group {
        Some(FieldRef::Attribute(key)) => facets
            .attrs
            .iter()
            .find(|a| a.key == *key)
            .map(|a| a.values.clone())
            .unwrap_or_default(),
        Some(FieldRef::Body(leaf)) => facets
            .fields
            .iter()
            .find(|f| f.name == *leaf)
            .map(|f| f.values.clone())
            .unwrap_or_default(),
        None => Vec::new(),
    };
    crate::store::read::sort_facet_values(&mut group_values);
    let total_groups = group_values.len();
    // All of them, up to the hard bound — identity past the palette's eight hues is carried by the line
    // pattern instead of by an invented ninth hue (see `svg::series_style`).
    group_values.truncate(MAX_SERIES);

    // **One plot per chosen field, never two measures on one pair of axes.** Two scales on one plot
    // have an arbitrary alignment, which invents a correlation the data does not contain.
    //
    // Only numeric fields are queried. A text field would plot nothing anyway — the json_type guard in
    // `build_series_query` makes sure it plots nothing rather than a flat line of zeros — but there is
    // no reason to ask the database for it.
    let mut charts = Vec::new();
    for field in &p.fields {
        if !facets.fields.iter().any(|x| x.name == *field && x.numeric) {
            continue;
        }
        // Hidden series are not queried at all — there is no point aggregating what will not be drawn —
        // but their slots are still reserved, so hiding one does not repaint the others.
        let visible: Vec<String> =
            group_values.iter().filter(|g| !p.hidden.contains(g)).cloned().collect();
        let slots: Vec<usize> = visible
            .iter()
            .map(|g| group_values.iter().position(|x| x == g).unwrap_or(0))
            .collect();

        let series = crate::store::read::series(
            conn,
            &SeriesSpec {
                filter: filter.clone(),
                field: Some(field.clone()),
                group: p.group.clone(),
                groups: visible,
                bucket_nanos: bucket,
            },
        )?;
        charts.push(Chart {
            field: field.clone(),
            series,
            slots,
            groups: group_values.clone(),
            total_groups,
        });
    }

    // One more than the page, so "is there another page" is answered without a second count.
    let mut probe = filter.clone();
    probe.limit = PAGE_LIMIT + 1;
    let mut rows = crate::store::query(conn, &probe)?;
    let more = rows.len() as i64 > PAGE_LIMIT;
    rows.truncate(PAGE_LIMIT as usize);

    let series_pending = crate::store::series::pending(conn)?;

    Ok(ExploreData { types, facets, window, bucket, timeline, charts, rows, more, series_pending })
}

async fn explore(State(state): State<AppState>, Query(raw): Query<Vec<(String, String)>>) -> Response {
    let params = parse_explore(&raw);
    let db_path = state.config.database_path.clone();
    let now = crate::now_unix_nanos();
    let p = params.clone();

    let gathered =
        tokio::task::spawn_blocking(move || -> anyhow::Result<ExploreData> {
            let conn = crate::store::open_read(&db_path)?;
            gather(&conn, &p, now)
        })
        .await;

    match gathered {
        Ok(Ok(data)) => html(StatusCode::OK, render_explore(&params, &data)),
        Ok(Err(e)) => failed("reading the measurements", &e),
        Err(e) => failed("the measurement query task", &e),
    }
}

/// The filter row: one form, one row, above everything it scopes.
///
/// Every plot and the table re-render against the same slice, so the numbers below always agree with the
/// picture above. Per-chart filters would let them disagree.
fn filter_row(params: &Explore, data: &ExploreData) -> String {
    let mut out = String::from("<form method=\"get\" action=\"/\" class=\"filters\">");

    out.push_str(&html::select(
        "range",
        "range",
        &RANGES.iter().map(|(id, label, _)| ((*id).to_owned(), (*label).to_owned())).collect::<Vec<_>>(),
        Some(&params.range),
        "custom",
    ));
    out.push_str(&html::select(
        "type",
        "type",
        &data
            .types
            .iter()
            .map(|t| (t.kind.clone(), format!("{} ({})", t.kind, t.count)))
            .collect::<Vec<_>>(),
        params.kind.as_deref(),
        "any type",
    ));

    // Which type the controls below were built for, so `parse_explore` can tell a type change from a
    // filter change.
    if let Some(kind) = &params.kind {
        out.push_str(&format!("<input type=\"hidden\" name=\"t0\" value=\"{}\">", html::escape(kind)));
    }

    // Attribute filters, one control per discovered key. Only offered once a type is chosen: without one
    // the keys come from 29 unrelated types at once and none of them narrows anything usefully.
    if params.kind.is_some() {
        for facet in &data.facets.attrs {
            let current = params.attrs.iter().find(|(k, _)| *k == facet.key).map(|(_, v)| v.as_str());
            let name = format!("attr.{}", facet.key);
            let label = short_key(&facet.key);
            // A key with hundreds of distinct values — a boot id, a clock correction in nanoseconds — is a
            // text box rather than a dropdown nobody can scroll.
            if facet.truncated {
                out.push_str(&html::text_input(&name, &label, current, "exact value"));
            } else {
                let options = facet.values.iter().map(|v| (v.clone(), v.clone())).collect::<Vec<_>>();
                out.push_str(&html::select(&name, &label, &options, current, "any"));
            }
        }

        // Checkboxes, not a dropdown: each ticked field gets its own plot, and a multi-select needs
        // ctrl-click, which a touch screen does not have.
        // Body-leaf filters, alongside the attribute ones above and behaving identically. Without these,
        // grouping by a body field would have no escape hatch when there are more groups than the cap —
        // "narrow the filter to see the rest" has to be possible for the field being grouped by.
        for facet in &data.facets.fields {
            // A leaf with one value narrows nothing; a value field like `signal_dbm` has hundreds and is a
            // text box rather than a dropdown nobody can scroll.
            if facet.values.len() < 2 && !facet.truncated {
                continue;
            }
            let current = params.body.iter().find(|(k, _)| *k == facet.name).map(|(_, v)| v.as_str());
            let name = format!("body.{}", facet.name);
            if facet.truncated {
                out.push_str(&html::text_input(&name, &facet.name, current, "exact value"));
            } else {
                let options = facet.values.iter().map(|v| (v.clone(), v.clone())).collect::<Vec<_>>();
                out.push_str(&html::select(&name, &facet.name, &options, current, "any"));
            }
        }

        let numeric_fields: Vec<String> =
            data.facets.fields.iter().filter(|f| f.numeric).map(|f| f.name.clone()).collect();
        if !numeric_fields.is_empty() {
            out.push_str(&html::checkboxes("field", "chart these", &numeric_fields, &params.fields));
        }

        // Only offered once something is being charted, because that is the only time it does anything —
        // which is also the clearest possible answer to "what does this control do".
        //
        // Only keys that actually divide the data: a key with one value would draw one line identical to
        // the ungrouped chart.
        // **Both halves of the measurement can be a series dimension.** `detected-devices.wifi_bss` keeps
        // `bssid` in its attributes and `ssid` in its body, and the second is the more interesting identity
        // — there is no reason the reader should have to know which column a field sits in.
        //
        // Same admission rule for both: a small enough set of distinct values to be a dropdown, and more
        // than one of them, since a single value would draw one line identical to the ungrouped chart. That
        // rule also keeps a value field like `signal_dbm` out on its own merits rather than by type.
        let mut groupable: Vec<(String, String)> = data
            .facets
            .attrs
            .iter()
            .filter(|a| !a.truncated && a.values.len() > 1)
            .map(|a| (FieldRef::Attribute(a.key.clone()).encode(), short_key(&a.key)))
            .collect();
        let attr_labels: Vec<String> = groupable.iter().map(|(_, label)| label.clone()).collect();
        groupable.extend(
            data.facets
                .fields
                .iter()
                .filter(|f| !f.truncated && f.values.len() > 1)
                .map(|f| {
                    // Disambiguated only when it would otherwise read as a duplicate: the two namespaces
                    // can collide, and two identically-labelled options is worse than a little noise.
                    let label = if attr_labels.contains(&f.name) {
                        format!("{} (body)", f.name)
                    } else {
                        f.name.clone()
                    };
                    (FieldRef::Body(f.name.clone()).encode(), label)
                }),
        );
        if !groupable.is_empty() && !params.fields.is_empty() {
            out.push_str(&html::select(
                "group",
                "one line per",
                &groupable,
                params.group.as_ref().map(|g| g.encode()).as_deref(),
                "nothing (a single line)",
            ));
        }
    }

    out.push_str("<button type=\"submit\" class=\"go\">apply</button>");

    // The hint sits inside the filter row, on its own line, and only says the thing that is not obvious
    // from the labels.
    if params.kind.is_some() && !params.fields.is_empty() {
        out.push_str(&html::hint(
            "“one line per” draws a separate line for each value of that attribute — e.g. one line per \
             cell — instead of averaging them all together.",
        ));
    }

    out.push_str("</form>\n");
    out
}

fn render_explore(params: &Explore, data: &ExploreData) -> String {
    let mut body = filter_row(params, data);

    // Self-removing: it says something only while the sweep still has work, and the fill is what makes
    // that condition temporary. Nothing here is wrong while it shows — measurements are stored and
    // served normally — so it reports rather than warns.
    if data.series_pending > 0 {
        body.push_str(&html::note(&format!(
            "{} measurements are still being assigned to a series; this finishes on its own.",
            data.series_pending
        )));
    }
    if params.kind.is_none() {
        body.push_str(&html::note("Choose a type to filter by its attributes and chart its values."));
    }
    if data.facets.capped {
        body.push_str(&html::note(&format!(
            "Filter options come from the newest {} rows in range; filtering itself covers the whole range.",
            data.facets.scanned
        )));
    }

    body.push_str(&format!(
        "<h2>measurements over time — {} to {}</h2>\n",
        html::escape(&format_nanos(data.window.0)),
        html::escape(&format_nanos(data.window.1))
    ));
    body.push_str(&html::plot(&svg::timeline(
        &data.timeline,
        data.window.0,
        data.window.1,
        data.bucket,
        &svg::Geometry::INLINE,
        None,
    )));
    body.push_str(&open_chart_link(params, None));

    // One plot per field, each with its own y axis. Fields that turned out to have no numeric values in
    // range are reported rather than silently dropped.
    for chart in &data.charts {
        body.push_str(&format!("<h2>{}</h2>\n", html::escape(&chart.field)));
        body.push_str(&html::plot(&svg::value_chart(
            &chart.series,
            &chart.slots,
            data.window.0,
            data.window.1,
            &chart.field,
            &svg::Geometry::INLINE,
            None,
        )));
        body.push_str(&chart_legend(params, chart, "/"));
        body.push_str(&chart_notes(chart, &chart.field));
        body.push_str(&open_chart_link(params, Some(&chart.field)));
    }
    for field in &params.fields {
        if !data.charts.iter().any(|c| &c.field == field) {
            body.push_str(&html::note(&format!(
                "{field} has no numeric values in this range — the timeline above still shows when these \
                 measurements arrived."
            )));
        }
    }

    // The table is also the accessible twin of the plots: every value above is readable here without
    // hovering anything, which is what lets the charts carry no scripted tooltip layer, and is the
    // "relief" the light-mode palette's low-contrast slots require.
    body.push_str("<h2>matching measurements</h2>\n");
    body.push_str(&measurement_table(&data.rows, params.kind.is_some(), &data.facets));

    // Pagination as a form rather than a link, so the browser encodes the query string and this page needs
    // no percent-encoder of its own.
    if let (true, Some(last)) = (data.more, data.rows.last()) {
        body.push_str("<form method=\"get\" action=\"/\" class=\"inline\">");
        for (name, value) in current_params(params) {
            body.push_str(&format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                html::escape(&name),
                html::escape(&value)
            ));
        }
        body.push_str(&format!(
            "<input type=\"hidden\" name=\"cursor\" value=\"{}\">\
             <button type=\"submit\">older →</button></form>\n",
            html::escape(&crate::api::query::encode_cursor(last.event_time, &last.id))
        ));
    }

    html::page("measurements", "/", &body)
}

/// One JSON value, rendered as the **HTML** for a table cell.
///
/// A scalar loses its JSON quoting; a null becomes nothing, since a cell reading `null` is noise and the
/// narrow-screen stylesheet hides an empty cell outright. Anything structured becomes indented
/// `key: value` lines (see [`html::yamlish`]) rather than compact JSON, because down a column the braces
/// and quotes are most of the characters and none of the information.
///
/// Returns HTML, so callers must not escape the result again — the escaping happens here, where it can
/// tell a scalar from the markup that wraps a multi-line block.
fn cell(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(s)) => html::escape(s),
        Some(v @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) => {
            html::multiline(&html::yamlish(v))
        }
        Some(other) => html::escape(&other.to_string()),
    }
}

/// The plain-text form of one value, for the "same on every row" line where markup would not fit.
fn cell_text(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Splits the attribute keys present across `rows` into the ones that differ and the ones that do not.
///
/// **The reason the old table was unreadable.** Every row of `bms.status.cell` carries the same twelve
/// attributes, and eleven of them — host name, boot id, service name, scope, clock metadata — are identical
/// on every row in view. Rendering all twelve as one JSON blob per row spent the entire width restating
/// constants. The ones that differ are the information; the rest belong under the table, said once.
fn partition_attributes(rows: &[StoredMeasurement]) -> (Vec<String>, Vec<(String, String)>) {
    let mut keys: Vec<&String> = Vec::new();
    for row in rows {
        if let Some(map) = row.attributes.as_object() {
            for key in map.keys() {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
    }
    keys.sort();

    let mut varying = Vec::new();
    let mut constant = Vec::new();
    for key in keys {
        let mut seen: Option<String> = None;
        let mut differs = false;
        for row in rows {
            let rendered = cell_text(row.attributes.get(key));
            match &seen {
                None => seen = Some(rendered),
                Some(first) if *first != rendered => {
                    differs = true;
                    break;
                }
                Some(_) => {}
            }
        }
        if differs {
            varying.push(key.clone());
        } else if let Some(value) = seen {
            constant.push((key.clone(), value));
        }
    }
    (varying, constant)
}

/// The measurements table.
///
/// Two shapes, because the useful one depends on whether a type is selected:
///
/// - **With a type**, every row has the same body shape (this holds for all 29 types on this host), so each
///   body leaf gets its own column and each *varying* attribute gets one too. Constants go underneath.
/// - **Without one**, the rows are 29 unrelated shapes with nothing in common, so body and attributes stay
///   as compact JSON in single columns — a column per key across every type would be mostly empty cells.
fn measurement_table(rows: &[StoredMeasurement], type_selected: bool, facets: &Facets) -> String {
    if rows.is_empty() {
        return html::table(&["event time"], &[], "no measurements match these filters in this range");
    }

    if !type_selected {
        return html::table(
            &["event time", "type", "body", "attributes"],
            &rows
                .iter()
                .map(|m| {
                    vec![
                        html::escape(&format_nanos(m.event_time)),
                        html::escape(&m.kind),
                        cell(m.body.as_ref()),
                        cell(Some(&m.attributes)),
                    ]
                })
                .collect::<Vec<_>>(),
            "no measurements match these filters in this range",
        );
    }

    // Body leaves in the order discovery found them, which is alphabetical and therefore stable across
    // renders — a table whose columns reorder between page loads is unreadable.
    let body_keys: Vec<String> = facets.fields.iter().map(|f| f.name.clone()).collect();
    let (varying, constant) = partition_attributes(rows);

    let mut headers: Vec<String> = vec!["event time".to_owned()];
    headers.extend(body_keys.iter().cloned());
    headers.extend(varying.iter().map(|k| short_key(k)));
    let header_refs: Vec<&str> = headers.iter().map(String::as_str).collect();

    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|m| {
            let mut out = vec![html::escape(&format_nanos(m.event_time))];
            for key in &body_keys {
                out.push(cell(m.body.as_ref().and_then(|b| b.get(key))));
            }
            for key in &varying {
                out.push(cell(m.attributes.get(key)));
            }
            out
        })
        .collect();

    let mut out = html::table(&header_refs, &table_rows, "no measurements match these filters in this range");
    if !constant.is_empty() {
        let listed = constant
            .iter()
            .map(|(k, v)| format!("<code>{}={}</code>", html::escape(&short_key(k)), html::escape(v)))
            .collect::<Vec<_>>()
            .join(" · ");
        out.push_str(&format!(
            "<p class=\"constant\">Same on every row shown: {listed}</p>\n"
        ));
    }
    out
}

/// The "open this chart" link under an inline plot.
///
/// A link to a page rather than a scripted overlay. It costs a navigation, and buys three things a
/// fullscreen overlay would not: it is bookmarkable, it works with no JavaScript at all (SPEC §14.6), and
/// on a phone it can use a geometry built for a portrait viewport instead of a scaled-down desktop one.
fn open_chart_link(params: &Explore, field: Option<&str>) -> String {
    let mut carried = current_params(params);
    // One chart per page, so the field is *the* subject rather than one of several.
    carried.retain(|(k, _)| k != "field");
    if let Some(field) = field {
        carried.push(("field".to_owned(), field.to_owned()));
    }
    format!(
        "<p class=\"note\"><a href=\"{}\">open {} full size — tap a point for the measurements behind \
         it</a></p>\n",
        html::escape(&html::query_string("/chart", &carried)),
        html::escape(field.unwrap_or("the timeline"))
    )
}

/// The full-page view of one chart (SPEC §14.9).
///
/// Renders the **same** chart at two geometries and lets a media query choose, which is the no-JavaScript
/// answer to a `viewBox` that cannot suit a phone and a desktop at once — see [`svg::Geometry`]. One extra
/// copy of one chart is a cost worth paying on the page whose only job is legibility.
async fn chart(State(state): State<AppState>, Query(raw): Query<Vec<(String, String)>>) -> Response {
    let params = parse_explore(&raw);
    let db_path = state.config.database_path.clone();
    let now = crate::now_unix_nanos();
    let p = params.clone();

    let gathered = tokio::task::spawn_blocking(move || -> anyhow::Result<ExploreData> {
        let conn = crate::store::open_read(&db_path)?;
        gather(&conn, &p, now)
    })
    .await;

    let data = match gathered {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => return failed("reading the measurements", &e),
        Err(e) => return failed("the measurement query task", &e),
    };

    // Each mark links back to the explorer, filtered to that bucket's own window. `range=custom` so the
    // explicit `from`/`to` the link appends are what decide the window rather than the preset.
    let mut back = current_params(&params);
    back.retain(|(k, _)| k != "range" && k != "from" && k != "to");
    back.push(("range".to_owned(), "custom".to_owned()));
    let link = html::query_string("/", &back);

    let mut body = String::new();
    let title = params.fields.first().cloned().unwrap_or_else(|| "measurements".to_owned());

    body.push_str(&format!(
        "<p class=\"note\"><a href=\"{}\">← back to the explorer</a></p>\n",
        html::escape(&html::query_string("/", &current_params(&params)))
    ));
    body.push_str(&format!(
        "<h2>{} — {} to {}</h2>\n",
        html::escape(&title),
        html::escape(&format_nanos(data.window.0)),
        html::escape(&format_nanos(data.window.1))
    ));

    for geo in [&svg::Geometry::FULL_WIDE, &svg::Geometry::FULL_NARROW] {
        match data.charts.first() {
            Some(chart) => body.push_str(&svg::value_chart(
                &chart.series,
                &chart.slots,
                data.window.0,
                data.window.1,
                &chart.field,
                geo,
                Some(&link),
            )),
            // No field chosen: the timeline is the chart, and it is just as clickable.
            None => body.push_str(&svg::timeline(
                &data.timeline,
                data.window.0,
                data.window.1,
                data.bucket,
                geo,
                Some(&link),
            )),
        }
    }

    if let Some(chart) = data.charts.first() {
        body.push_str(&chart_legend(&params, chart, "/chart"));
        body.push_str(&chart_notes(chart, &chart.field));
    }
    body.push_str(&html::note(
        "Every point is an average over its bucket. Tap one to see the measurements it covers; tap a \
         legend entry to hide that line.",
    ));

    html(StatusCode::OK, html::page(&title, "/", &body))
}

/// The legend for one chart, with each entry linking to the same view with that series toggled.
///
/// Built here rather than in `svg` because the links are the point: tapping an entry is how a reader
/// declutters a plot with more lines than colours, and a link is the only way to do that without
/// JavaScript. `path` is where the entries point — the explorer or the full-page chart, whichever is
/// showing.
fn chart_legend(params: &Explore, chart: &Chart, path: &str) -> String {
    let entries: Vec<html::LegendEntry> = chart
        .groups
        .iter()
        .enumerate()
        .map(|(slot, group)| {
            let hidden = params.hidden.contains(group);
            // Toggle: drop it from the hidden list if it is in there, add it if not.
            let mut toggled = current_params(params);
            toggled.retain(|(k, v)| !(k == "hide" && v == group));
            if !hidden {
                toggled.push(("hide".to_owned(), group.clone()));
            }
            let (color, _) = svg::series_style(slot);
            html::LegendEntry {
                label: group.clone(),
                color,
                pattern: svg::series_border_style(slot),
                hidden,
                href: html::query_string(path, &toggled),
            }
        })
        .collect();
    html::legend(&entries)
}

/// What a chart has left out, if anything, and how to reach it.
fn chart_notes(chart: &Chart, field: &str) -> String {
    let mut out = String::new();
    if chart.total_groups > chart.groups.len() {
        out.push_str(&html::note(&format!(
            "Showing {} of {} groups — more than one plot can distinguish. Narrow the filter to reach the \
             rest.",
            chart.groups.len(),
            chart.total_groups
        )));
    }
    // Partial coverage, said out loud whatever the marker density (see `svg`).
    let (rows, valued) = chart
        .series
        .iter()
        .flat_map(|s| &s.points)
        .fold((0i64, 0i64), |(r, v), p| (r + p.count, v + p.value_count));
    if valued < rows {
        out.push_str(&html::note(&format!(
            "{valued} of {rows} matching measurements carried a number for {field}; the rest are counted \
             in the timeline but not averaged here."
        )));
    }
    out
}

/// The current filter state as name/value pairs, for carrying across a pagination submit.
fn current_params(params: &Explore) -> Vec<(String, String)> {
    let mut out = vec![("range".to_owned(), params.range.clone())];
    for (name, value) in [("type", &params.kind), ("t0", &params.kind)] {
        if let Some(v) = value {
            out.push((name.to_owned(), v.clone()));
        }
    }
    if let Some(group) = &params.group {
        out.push(("group".to_owned(), group.encode()));
    }
    for field in &params.fields {
        out.push(("field".to_owned(), field.clone()));
    }
    if let Some(from) = params.from {
        out.push(("from".to_owned(), from.to_string()));
    }
    if let Some(to) = params.to {
        out.push(("to".to_owned(), to.to_string()));
    }
    for (key, value) in &params.attrs {
        out.push((format!("attr.{key}"), value.clone()));
    }
    for (leaf, value) in &params.body {
        out.push((format!("body.{leaf}"), value.clone()));
    }
    for value in &params.hidden {
        out.push(("hide".to_owned(), value.clone()));
    }
    out
}

/// Trims the structural prefix off an attribute key for display.
///
/// `record.attributes.cell` reads as `cell` in a control already labelled as an attribute filter, and the
/// full keys are long enough to push the filter row onto several lines. The **full** key is still what gets
/// submitted and matched — only the label is shortened, since §5.2 makes the prefix meaningful.
fn short_key(key: &str) -> String {
    for prefix in ["record.attributes.", "resource.attributes.", "scope."] {
        if let Some(rest) = key.strip_prefix(prefix) {
            return rest.to_owned();
        }
    }
    key.to_owned()
}

// ------------------------------------------------------------------------------------ users

async fn users(State(state): State<AppState>) -> Response {
    render_users(&state, None).await
}

/// The users page, optionally with an error from a failed mutation.
///
/// A rendered error rather than a redirect: a `303` cannot carry a message without a query parameter or
/// server-side flash state, and `?error=…` is a reflected string in a URL that gets pasted around.
async fn render_users(state: &AppState, error: Option<&str>) -> Response {
    let db_path = state.config.database_path.clone();
    let listed = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_read(&db_path)?;
        crate::store::users::list(&conn)
    })
    .await;

    let listed = match listed {
        Ok(Ok(users)) => users,
        Ok(Err(e)) => return failed("reading the users", &e),
        Err(e) => return failed("the user query task", &e),
    };

    let last = listed.len() <= 1;
    let table = html::table(
        &["username", "created", ""],
        &listed
            .iter()
            .map(|u| {
                vec![
                    html::escape(&u.username),
                    html::escape(&format_nanos(u.created_at)),
                    if last {
                        // Not rendered rather than rendered disabled: the handler refuses it anyway, and a
                        // button that cannot work is a button that invites a bug report.
                        String::new()
                    } else {
                        html::post_button("/users/delete", "username", &u.username, "delete", "link")
                    },
                ]
            })
            .collect::<Vec<_>>(),
        "no users, which cannot happen while you are reading this page",
    );

    let mut body = String::new();
    if let Some(message) = error {
        body.push_str(&format!("<p class=\"error\">{}</p>\n", html::escape(message)));
    }
    body.push_str(&table);
    if last {
        body.push_str(&html::note(
            "The only user cannot be deleted from here — that would lock you out of this interface. Add \
             another first, or use `delete-user` over ssh.",
        ));
    }
    body.push_str(&html::create_user_form());

    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    html(status, html::page("users", "/users", &body))
}

#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    password: String,
}

async fn create_user(State(state): State<AppState>, Form(form): Form<NewUser>) -> Response {
    // The username is trimmed, because one with a trailing space is indistinguishable on screen from one
    // without and would silently never match at login. The password is **not** — §14.7 hashes exactly what
    // was supplied, and trimming would store something other than what was typed.
    let username = form.username.trim().to_owned();
    if username.is_empty() || form.password.is_empty() {
        return render_users(&state, Some("a username and a password are both required.")).await;
    }

    let hash = crate::auth::hash_password(&form.password);
    let db_path = state.config.database_path.clone();
    let name = username.clone();
    let created = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_write_existing(&db_path)?;
        crate::store::users::insert(&conn, &name, &hash, crate::now_unix_nanos())
    })
    .await;

    match created {
        Ok(Ok(())) => {
            tracing::info!(user = %username, "user created from the web interface");
            see_other("/users")
        }
        // The realistic failure is the primary key: a duplicate username. Reported as a page rather than a
        // 500, since it is the operator's typo and not a fault.
        Ok(Err(e)) => {
            tracing::warn!(error = %e, user = %username, "could not create the user");
            render_users(&state, Some("that username already exists.")).await
        }
        Err(e) => failed("the user creation task", &e),
    }
}

#[derive(Deserialize)]
pub struct TargetUser {
    username: String,
}

async fn delete_user(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Form(form): Form<TargetUser>,
) -> Response {
    let db_path = state.config.database_path.clone();
    let target = form.username.clone();

    let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<bool>> {
        let conn = crate::store::open_write_existing(&db_path)?;
        // **Refuse to remove the last user.** Checked here, on the same connection as the delete, rather
        // than trusted from the rendering: the page whose button was pressed may be minutes old.
        if crate::store::users::count(&conn)? <= 1 {
            return Ok(None);
        }
        Ok(Some(crate::store::users::delete(&conn, &target)?))
    })
    .await;

    match outcome {
        Ok(Ok(None)) => {
            render_users(
                &state,
                Some("that is the only user, and deleting it would lock you out of this interface."),
            )
            .await
        }
        Ok(Ok(Some(false))) => render_users(&state, Some("there is no such user.")).await,
        Ok(Ok(Some(true))) => {
            tracing::info!(user = %form.username, by = %identity.username, "user deleted");
            // `users::delete` takes that user's sessions with it, so deleting yourself has just ended this
            // request's own session.
            if form.username == identity.username {
                return logged_out();
            }
            see_other("/users")
        }
        Ok(Err(e)) => failed("deleting the user", &e),
        Err(e) => failed("the user deletion task", &e),
    }
}

// ------------------------------------------------------------------------------------ api keys

async fn keys(State(state): State<AppState>) -> Response {
    render_keys(&state, None, None).await
}

/// The API keys page (SPEC §13, §14.1).
///
/// `issued` carries a token that has just been minted. **It is shown exactly once, on this response**,
/// because only its hash is stored and nothing can recover it afterwards — the same contract
/// `create-api-key` has on the command line. It is deliberately *not* carried through a redirect: a token
/// in a URL lands in history and in any log that records paths.
async fn render_keys(state: &AppState, error: Option<&str>, issued: Option<&str>) -> Response {
    let db_path = state.config.database_path.clone();
    let listed = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_read(&db_path)?;
        crate::store::keys::list(&conn)
    })
    .await;

    let listed = match listed {
        Ok(Ok(keys)) => keys,
        Ok(Err(e)) => return failed("reading the API keys", &e),
        Err(e) => return failed("the API key query task", &e),
    };

    let table = html::table(
        &["id", "label", "created", ""],
        &listed
            .iter()
            .map(|k| {
                vec![
                    html::escape(&k.id),
                    html::escape(&k.label),
                    html::escape(&format_nanos(k.created_at)),
                    html::post_button("/keys/delete", "id", &k.id, "revoke", "link"),
                ]
            })
            .collect::<Vec<_>>(),
        "no API keys — every /v1 request will be refused until one is issued",
    );

    let mut body = String::new();
    if let Some(message) = error {
        body.push_str(&format!("<p class=\"error\">{}</p>\n", html::escape(message)));
    }
    if let Some(token) = issued {
        // The one place a secret is ever rendered. Marked as such, because the reader has one chance.
        body.push_str(&format!(
            "<p class=\"issued\"><strong>Copy this now — it is not stored and cannot be shown \
             again:</strong><br><code>{}</code></p>\n",
            html::escape(token)
        ));
    }
    body.push_str(&table);
    if listed.is_empty() {
        body.push_str(&html::note(
            "Devices authenticate with these (SPEC §13). With none issued, the receiver refuses every \
             request except /healthz.",
        ));
    }
    body.push_str(
        "<h2>issue a key</h2>\n\
         <form method=\"post\" action=\"/keys/create\" class=\"filters\">\
         <label>label<input name=\"label\" placeholder=\"which device\" required></label>\
         <button type=\"submit\" class=\"go\">issue</button></form>\n",
    );
    body.push_str(&html::note(
        "The label is for you; it is never checked against anything. Revoking a key deletes it, so the \
         next request carrying it is refused.",
    ));

    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    html(status, html::page("api keys", "/keys", &body))
}

#[derive(Deserialize)]
pub struct NewKey {
    label: String,
}

async fn create_key(State(state): State<AppState>, Form(form): Form<NewKey>) -> Response {
    let label = form.label.trim().to_owned();
    if label.is_empty() {
        return render_keys(&state, Some("a label is required."), None).await;
    }

    // The same token construction the CLI uses, so a key issued here is indistinguishable from one issued
    // over ssh — one code path decides what a credential is (`crate::auth`).
    let bytes = match crate::random_bytes() {
        Ok(bytes) => bytes,
        Err(e) => return failed("reading randomness for the new key", &e),
    };
    let token = crate::auth::Token::from_random(&bytes);
    let printed = token.to_secret_string();

    let db_path = state.config.database_path.clone();
    let (id, hash, name) = (token.id().to_owned(), token.secret_hash(), label.clone());
    let stored = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_write_existing(&db_path)?;
        crate::store::keys::insert(&conn, &id, &hash, &name, crate::now_unix_nanos())
    })
    .await;

    match stored {
        Ok(Ok(())) => {
            // The id is public and worth logging; the token is not, and is not (see `auth`'s redacted
            // Debug for the same rule).
            tracing::info!(key = %token.id(), label = %label, "API key issued from the web interface");
            render_keys(&state, None, Some(&printed)).await
        }
        Ok(Err(e)) => failed("storing the new API key", &e),
        Err(e) => failed("the API key creation task", &e),
    }
}

#[derive(Deserialize)]
pub struct TargetKey {
    id: String,
}

async fn delete_key(State(state): State<AppState>, Form(form): Form<TargetKey>) -> Response {
    let db_path = state.config.database_path.clone();
    let target = form.id.clone();
    let removed = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_write_existing(&db_path)?;
        crate::store::keys::delete(&conn, &target)
    })
    .await;

    match removed {
        Ok(Ok(existed)) => {
            // **No last-key guard, unlike users.** Revoking the last key stops devices delivering, which is
            // recoverable from this very page; deleting the last *user* would lock the operator out of the
            // page itself. Different failure, different answer.
            if existed {
                tracing::info!(key = %form.id, "API key revoked from the web interface");
            } else {
                tracing::warn!(key = %form.id, "revoke: no such API key");
            }
            see_other("/keys")
        }
        Ok(Err(e)) => failed("revoking the API key", &e),
        Err(e) => failed("the API key deletion task", &e),
    }
}

// ------------------------------------------------------------------------------------ sessions

async fn sessions(State(state): State<AppState>, Extension(identity): Extension<Identity>) -> Response {
    let db_path = state.config.database_path.clone();
    let listed = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_read(&db_path)?;
        crate::store::sessions::list(&conn)
    })
    .await;

    let listed = match listed {
        Ok(Ok(sessions)) => sessions,
        Ok(Err(e)) => return failed("reading the sessions", &e),
        Err(e) => return failed("the session query task", &e),
    };

    let now = crate::now_unix_nanos();
    let table = html::table(
        &["id", "user", "created", "expires", "", ""],
        &listed
            .iter()
            .map(|s| {
                let mut note = Vec::new();
                if s.id == identity.session_id {
                    note.push("this one");
                }
                if s.expires_at <= now {
                    note.push("expired");
                }
                vec![
                    html::escape(&s.id),
                    html::escape(&s.username),
                    html::escape(&format_nanos(s.created_at)),
                    html::escape(&format_nanos(s.expires_at)),
                    html::escape(&note.join(", ")),
                    html::post_button(
                        "/sessions/end",
                        "id",
                        &s.id,
                        if s.id == identity.session_id { "end (log out)" } else { "end" },
                        "link",
                    ),
                ]
            })
            .collect::<Vec<_>>(),
        "no sessions, which cannot happen while you are reading this page",
    );

    let body = format!(
        "{table}<p class=\"note\">Only the public half of each session id is stored; the secret is not in \
         the database at all, so nothing on this page can be replayed as a login.</p>\n"
    );

    html(StatusCode::OK, html::page("sessions", "/sessions", &body))
}

#[derive(Deserialize)]
pub struct TargetSession {
    id: String,
}

async fn end_session(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Form(form): Form<TargetSession>,
) -> Response {
    let db_path = state.config.database_path.clone();
    let target = form.id.clone();
    let ended = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_write_existing(&db_path)?;
        crate::store::sessions::delete(&conn, &target)
    })
    .await;

    match ended {
        Ok(Ok(_)) => {
            tracing::info!(session = %form.id, by = %identity.username, "session ended");
            // Ending your own is allowed, and is just logout by another route. Refusing it would be
            // surprising — it is on the list like any other, and it is the one a reader is most likely to
            // want gone.
            if form.id == identity.session_id {
                return logged_out();
            }
            see_other("/sessions")
        }
        Ok(Err(e)) => failed("ending the session", &e),
        Err(e) => failed("the session deletion task", &e),
    }
}

// ------------------------------------------------------------------------------------ logging in

async fn login_form() -> Response {
    html(StatusCode::OK, html::login(None))
}

/// The login form's fields.
///
/// `Form` comes from axum's default `form` feature, so this needs no new dependency. It percent-decodes and
/// handles `+`-as-space, which hand-rolled parsing of a password field would have to get right.
#[derive(Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

/// One message for every way a login can fail.
///
/// The same reasoning as [`crate::api::auth::refuse`]: distinguishing "no such user" from "wrong password"
/// turns the form into an oracle for which usernames exist. What is *not* defended is timing — an unknown
/// username returns before any hashing happens, so it is measurably faster. With one operator and a
/// username that is not secret, closing that would be machinery guarding nothing, and stating it is better
/// than implying it was handled.
const REFUSED: &str = "that username and password did not match.";

async fn login(State(state): State<AppState>, Form(credentials): Form<Credentials>) -> Response {
    let db_path = state.config.database_path.clone();
    let username = credentials.username.clone();
    let presented = crate::auth::hash_password(&credentials.password);

    let verified = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let conn = crate::store::open_read(&db_path)?;
        // `blake3::Hash`'s constant-time `PartialEq`, as everywhere else a secret is compared here.
        Ok(crate::store::users::password_hash(&conn, &username)?
            .is_some_and(|stored| stored == presented))
    })
    .await;

    match verified {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => {
            tracing::warn!(user = %credentials.username, "rejected: login did not match");
            return html(StatusCode::UNAUTHORIZED, html::login(Some(REFUSED)));
        }
        Ok(Err(e)) => return login_unavailable(&e),
        Err(e) => return login_unavailable(&e),
    }

    match establish(&state, &credentials.username) {
        Ok(cookie) => {
            tracing::info!(user = %credentials.username, "logged in");
            let mut response = see_other("/");
            session::set_cookie(&mut response, &cookie);
            response
        }
        Err(e) => login_unavailable(&e),
    }
}

/// A login that could not be *checked* is not a login that was wrong — the same distinction the API-key
/// layer draws to answer 503 rather than 401. Here it matters less (a browser will simply retry) but
/// reporting a database failure as a bad password would send the operator hunting for the wrong thing.
fn login_unavailable(error: &dyn std::fmt::Display) -> Response {
    tracing::error!(%error, "could not verify a login");
    html(
        StatusCode::SERVICE_UNAVAILABLE,
        html::login(Some("the login could not be checked right now; try again.")),
    )
}

/// Issues a session and returns the `Set-Cookie` value.
///
/// Synchronous and blocking, called from the async handler. Justified because it is bounded by two
/// statements against a local SQLite file and is on the login path, which happens about as often as the
/// operator opens a browser; wrapping it in `spawn_blocking` would be the tidier shape and is worth doing if
/// this ever stops being true.
fn establish(state: &AppState, username: &str) -> anyhow::Result<String> {
    let token = crate::auth::SessionToken::from_random(&crate::random_bytes()?);
    let now = crate::now_unix_nanos();
    let expires_at = now.saturating_add(session::TTL_NANOS);

    // `open_write_existing`, not `open_write`: a login must never be the thing that discovers the schema
    // needs migrating (SPEC §6.2).
    let conn = crate::store::open_write_existing(&state.config.database_path)?;

    // Opportunistic, and here rather than on a timer because a login is the only moment this table grows.
    // A failure to sweep must not fail the login — the rows it would have removed are inert.
    match crate::store::sessions::delete_expired(&conn, now) {
        Ok(0) => {}
        Ok(swept) => tracing::debug!(swept, "removed expired sessions"),
        Err(e) => tracing::warn!(error = %e, "could not sweep expired sessions"),
    }

    crate::store::sessions::insert(&conn, token.id(), &token.secret_hash(), username, now, expires_at)?;

    Ok(session::session_cookie(&token.to_secret_string(), session::TTL_NANOS))
}

/// Logging out: delete the row, clear the cookie.
///
/// **`POST`, never `GET`.** A `GET` that logs you out is a link a prefetcher or an `<img src>` can fire.
///
/// CSRF is covered by [`origin::guard`] rather than by the cookie's `SameSite` attribute alone — see SPEC
/// §14.3 for why `SameSite` is not sufficient on a loopback origin.
async fn logout(State(state): State<AppState>, Extension(identity): Extension<Identity>) -> Response {
    // The cookie is cleared whatever the database says. A logout that reported failure and left the browser
    // holding a working session would be the one failure mode a logout must not have.
    match crate::store::open_write_existing(&state.config.database_path)
        .and_then(|conn| crate::store::sessions::delete(&conn, &identity.session_id))
    {
        Ok(true) => tracing::info!(user = %identity.username, "logged out"),
        Ok(false) => tracing::warn!(
            user = %identity.username,
            "logged out, but the session row was already gone"
        ),
        Err(e) => tracing::error!(
            error = %e,
            user = %identity.username,
            "could not delete the session row; the cookie is cleared regardless, so the browser is logged \
             out, but the row remains until it expires"
        ),
    }

    logged_out()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(kvs: &[(&str, &str)]) -> Vec<(String, String)> {
        kvs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn the_default_range_is_used_when_none_is_given() {
        assert_eq!(parse_explore(&[]).range, DEFAULT_RANGE);
        assert!(RANGES.iter().any(|(id, _, _)| *id == DEFAULT_RANGE), "the default must be a real preset");
    }

    /// A `GET` form submits every control it holds, so an unset select arrives as `field=`. Reading that as
    /// a filter would make clearing one impossible.
    #[test]
    fn empty_values_are_not_filters() {
        let p =
            parse_explore(&pairs(&[("type", ""), ("field", ""), ("group", ""), ("attr.unit", "")]));
        assert!(p.kind.is_none());
        assert!(p.fields.is_empty());
        assert!(p.group.is_none());
        assert!(p.attrs.is_empty());
    }

    #[test]
    fn filters_are_parsed() {
        let p = parse_explore(&pairs(&[
            ("range", "6h"),
            ("type", "bms.status.cell"),
            ("t0", "bms.status.cell"),
            ("attr.record.attributes.cell", "3"),
            ("field", "voltage_volts"),
            ("group", "record.attributes.cell"),
        ]));
        assert_eq!(p.range, "6h");
        assert_eq!(p.kind.as_deref(), Some("bms.status.cell"));
        assert_eq!(p.attrs, vec![("record.attributes.cell".to_owned(), "3".to_owned())]);
        assert_eq!(p.fields, vec!["voltage_volts".to_owned()]);
        assert_eq!(p.group, Some(FieldRef::Attribute("record.attributes.cell".into())));
    }

    /// **Changing the type must clear what belonged to the old one.** The filter row is a single form, so
    /// switching types resubmits the previous type's attribute selects — keys the new type does not have,
    /// which would return an empty page with no explanation.
    #[test]
    fn changing_the_type_clears_the_previous_type_s_filters() {
        let p = parse_explore(&pairs(&[
            ("type", "system.sensor"),
            ("t0", "bms.status.cell"),
            ("attr.record.attributes.cell", "3"),
            ("field", "voltage_volts"),
            ("group", "record.attributes.cell"),
        ]));
        assert_eq!(p.kind.as_deref(), Some("system.sensor"));
        assert!(p.attrs.is_empty(), "the old type's attribute filter must not survive");
        assert!(p.fields.is_empty(), "nor its fields");
        assert!(p.group.is_none(), "nor its grouping");
    }

    /// ...but keeping the same type must keep them, or every "apply" would reset the form.
    #[test]
    fn keeping_the_type_keeps_its_filters() {
        let p = parse_explore(&pairs(&[
            ("type", "bms.status.cell"),
            ("t0", "bms.status.cell"),
            ("attr.record.attributes.cell", "3"),
            ("field", "voltage_volts"),
        ]));
        assert_eq!(p.attrs.len(), 1);
        assert_eq!(p.fields, vec!["voltage_volts".to_owned()]);
    }

    /// Clearing the type is also a change, so it clears too.
    #[test]
    fn clearing_the_type_clears_its_filters() {
        let p = parse_explore(&pairs(&[("t0", "bms.status.cell"), ("attr.x", "1")]));
        assert!(p.kind.is_none());
        assert!(p.attrs.is_empty());
    }

    /// A stale bookmark is a person's mistake, not a device's, so it renders a page rather than a 400 —
    /// unlike §7.1's read API, which rejects unknown parameters.
    #[test]
    fn unknown_parameters_are_ignored_rather_than_rejected() {
        let p = parse_explore(&pairs(&[("typo", "x"), ("range", "1h")]));
        assert_eq!(p.range, "1h");
    }

    #[test]
    fn instants_parse_in_both_accepted_forms() {
        assert_eq!(parse_instant("1785489242123456789"), Some(1_785_489_242_123_456_789));
        assert_eq!(parse_instant("2026-07-31T09:14:02.123456789Z"), Some(1_785_489_242_123_456_789));
        assert_eq!(parse_instant("yesterday"), None);
        assert_eq!(parse_instant(""), None);
    }

    #[test]
    fn attribute_keys_are_shortened_for_display_only() {
        assert_eq!(short_key("record.attributes.cell"), "cell");
        assert_eq!(short_key("resource.attributes.host.name"), "host.name");
        assert_eq!(short_key("scope.name"), "name");
        assert_eq!(short_key("unprefixed"), "unprefixed");
    }

    /// Pagination has to carry the whole filter state forward, or page two is a different query from page
    /// one.
    #[test]
    fn pagination_carries_every_filter() {
        let p = parse_explore(&pairs(&[
            ("range", "7d"),
            ("type", "t"),
            ("t0", "t"),
            ("attr.a", "1"),
            ("attr.b", "2"),
            ("field", "v"),
            ("group", "a"),
        ]));
        let carried = current_params(&p);
        for expected in [
            ("range", "7d"),
            ("type", "t"),
            ("field", "v"),
            ("group", "a"),
            ("attr.a", "1"),
            ("attr.b", "2"),
        ] {
            assert!(
                carried.iter().any(|(k, v)| k == expected.0 && v == expected.1),
                "{expected:?} was not carried: {carried:?}"
            );
        }
        // And `t0` must match the carried type, or following the link would clear every filter.
        assert!(carried.iter().any(|(k, v)| k == "t0" && v == "t"));
    }
}
