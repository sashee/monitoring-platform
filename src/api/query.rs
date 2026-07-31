//! `GET /v1/measurements` and `GET /healthz` (SPEC §7).
//!
//! Errors here are JSON, not protobuf: the read API is not an OTLP surface.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::model::StoredMeasurement;
use crate::store::read::{DEFAULT_LIMIT, MAX_LIMIT, QuerySpec};

pub async fn healthz() -> Response {
    (StatusCode::OK, axum::Json(json!({"status": "ok"}))).into_response()
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message: message.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, axum::Json(json!({"error": self.message}))).into_response()
    }
}

#[derive(Serialize)]
pub struct MeasurementJson {
    id: i64,
    event_time: String,
    /// A string, not a number: nanosecond values exceed 2^53 and would be silently rounded by any
    /// client whose JSON parser is backed by f64 (SPEC §5.5).
    event_time_unix_nano: String,
    processed_time: String,
    processed_time_unix_nano: String,
    #[serde(rename = "type")]
    kind: String,
    body: Value,
    attributes: Value,
}

#[derive(Serialize)]
pub struct Page {
    measurements: Vec<MeasurementJson>,
    next_cursor: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    Query(raw): Query<Vec<(String, String)>>,
) -> Result<Response, ApiError> {
    let spec = parse_query(&raw)?;
    let limit = spec.limit;

    let db_path = state.config.database_path.clone();
    let rows = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<StoredMeasurement>> {
        let conn = crate::store::open_read(&db_path)?;
        crate::store::query(&conn, &spec)
    })
    .await
    .map_err(|e| ApiError { status: StatusCode::INTERNAL_SERVER_ERROR, message: e.to_string() })?
    .map_err(|e| {
        tracing::error!(error = %e, "read query failed");
        ApiError { status: StatusCode::INTERNAL_SERVER_ERROR, message: format!("{e:#}") }
    })?;

    // A full page implies there may be more; a short one is definitively the last.
    let next_cursor = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|r| encode_cursor(r.event_time, r.id)))
        .flatten();

    let page = Page {
        measurements: rows.into_iter().map(to_json).collect(),
        next_cursor,
    };
    Ok((StatusCode::OK, axum::Json(page)).into_response())
}

fn to_json(m: StoredMeasurement) -> MeasurementJson {
    MeasurementJson {
        id: m.id,
        event_time: format_nanos(m.event_time),
        event_time_unix_nano: m.event_time.to_string(),
        processed_time: format_nanos(m.processed_time),
        processed_time_unix_nano: m.processed_time.to_string(),
        kind: m.kind,
        body: m.body.unwrap_or(Value::Null),
        attributes: m.attributes,
    }
}

/// RFC 3339 UTC with a fixed nine fractional digits, so output width does not vary with the value.
pub fn format_nanos(nanos: i64) -> String {
    use jiff::fmt::temporal::DateTimePrinter;
    match jiff::Timestamp::from_nanosecond(nanos as i128) {
        Ok(ts) => {
            let mut out = String::new();
            if DateTimePrinter::new()
                .precision(Some(9))
                .print_timestamp(&ts, &mut out)
                .is_ok()
            {
                out
            } else {
                nanos.to_string()
            }
        }
        // Out of Timestamp's supported range; the raw value is still in the *_unix_nano field.
        Err(_) => nanos.to_string(),
    }
}

pub fn encode_cursor(event_time: i64, id: i64) -> String {
    B64.encode(json!({"t": event_time, "i": id}).to_string())
}

pub fn decode_cursor(s: &str) -> Result<(i64, i64), String> {
    let bytes = B64.decode(s).map_err(|_| "cursor is not valid base64".to_owned())?;
    let v: Value =
        serde_json::from_slice(&bytes).map_err(|_| "cursor is not valid JSON".to_owned())?;
    let t = v.get("t").and_then(Value::as_i64).ok_or("cursor is missing 't'")?;
    let i = v.get("i").and_then(Value::as_i64).ok_or("cursor is missing 'i'")?;
    Ok((t, i))
}

/// Accepts RFC 3339, or an integer nanosecond count. An all-digit value cannot be RFC 3339, which
/// always contains separators, so the two are unambiguous.
fn parse_time(s: &str) -> Result<i64, String> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<i64>().map_err(|_| format!("{s:?} is not a valid nanosecond count"));
    }
    let ts: jiff::Timestamp =
        s.parse().map_err(|_| format!("{s:?} is neither RFC 3339 nor an integer nanosecond count"))?;
    i64::try_from(ts.as_nanosecond()).map_err(|_| format!("{s:?} is outside the representable range"))
}

/// Turns raw query pairs into a validated `QuerySpec`.
///
/// Unknown parameters are rejected rather than ignored: a typo in a filter name would otherwise
/// silently widen the result set instead of failing.
pub fn parse_query(raw: &[(String, String)]) -> Result<QuerySpec, ApiError> {
    let mut spec = QuerySpec { limit: DEFAULT_LIMIT, ..Default::default() };

    for (key, value) in raw {
        match key.as_str() {
            "type" => spec.types.push(value.clone()),
            "from" => spec.from = Some(parse_time(value).map_err(ApiError::bad_request)?),
            "to" => spec.to = Some(parse_time(value).map_err(ApiError::bad_request)?),
            "limit" => {
                let n: i64 = value
                    .parse()
                    .map_err(|_| ApiError::bad_request(format!("limit {value:?} is not an integer")))?;
                spec.limit = n.clamp(1, MAX_LIMIT);
            }
            "cursor" => {
                spec.cursor = Some(decode_cursor(value).map_err(ApiError::bad_request)?);
            }
            k if k.starts_with("attr.") => {
                let attr_key = &k["attr.".len()..];
                if attr_key.is_empty() {
                    return Err(ApiError::bad_request("attr. filter is missing a key"));
                }
                spec.attrs.push((attr_key.to_owned(), value.clone()));
            }
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown query parameter {other:?}; expected type, from, to, limit, cursor or attr.<key>"
                )));
            }
        }
    }

    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(kvs: &[(&str, &str)]) -> Vec<(String, String)> {
        kvs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn formats_nanoseconds_with_fixed_precision() {
        assert_eq!(format_nanos(1_785_489_242_123_456_789), "2026-07-31T09:14:02.123456789Z");
        // Trailing zeros are kept, so field width does not vary between rows.
        assert_eq!(format_nanos(1_785_489_242_170_000_000), "2026-07-31T09:14:02.170000000Z");
        assert_eq!(format_nanos(0), "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn cursor_round_trips() {
        let encoded = encode_cursor(1_785_489_242_123_456_789, 41);
        assert_eq!(decode_cursor(&encoded).unwrap(), (1_785_489_242_123_456_789, 41));
    }

    #[test]
    fn cursor_survives_a_query_string_without_escaping() {
        // URL-safe alphabet, no padding: nothing here needs percent-encoding.
        let encoded = encode_cursor(i64::MAX, i64::MAX);
        assert!(
            encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "cursor must be query-string safe: {encoded}"
        );
    }

    #[test]
    fn rejects_malformed_cursors() {
        assert!(decode_cursor("!!!not base64!!!").is_err());
        assert!(decode_cursor(&B64.encode("not json")).is_err());
        assert!(decode_cursor(&B64.encode(r#"{"t":1}"#)).is_err(), "missing 'i'");
    }

    #[test]
    fn parses_times_in_both_accepted_forms() {
        assert_eq!(parse_time("1785489242123456789").unwrap(), 1_785_489_242_123_456_789);
        assert_eq!(
            parse_time("2026-07-31T09:14:02.123456789Z").unwrap(),
            1_785_489_242_123_456_789
        );
        assert!(parse_time("yesterday").is_err());
        assert!(parse_time("").is_err());
    }

    #[test]
    fn collects_repeated_types_and_multiple_attrs() {
        let spec = parse_query(&pairs(&[
            ("type", "cpu"),
            ("type", "gps"),
            ("attr.record.attributes.unit", "celsius"),
            ("attr.resource.attributes.device.id", "dev-7"),
        ]))
        .unwrap();
        assert_eq!(spec.types, vec!["cpu", "gps"]);
        assert_eq!(
            spec.attrs,
            vec![
                ("record.attributes.unit".to_owned(), "celsius".to_owned()),
                ("resource.attributes.device.id".to_owned(), "dev-7".to_owned()),
            ]
        );
    }

    /// The attribute key keeps its dots: it is one literal key, never a path (SPEC §7.1).
    #[test]
    fn attr_key_is_not_split_on_dots() {
        let spec = parse_query(&pairs(&[("attr.a.b.c", "v")])).unwrap();
        assert_eq!(spec.attrs, vec![("a.b.c".to_owned(), "v".to_owned())]);
    }

    #[test]
    fn unknown_parameters_are_rejected() {
        let err = parse_query(&pairs(&[("typo", "cpu")])).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("typo"), "the offending name should be reported");
    }

    #[test]
    fn empty_attr_key_is_rejected() {
        assert!(parse_query(&pairs(&[("attr.", "v")])).is_err());
    }

    #[test]
    fn limit_defaults_and_clamps() {
        assert_eq!(parse_query(&[]).unwrap().limit, DEFAULT_LIMIT);
        assert_eq!(parse_query(&pairs(&[("limit", "99999")])).unwrap().limit, MAX_LIMIT);
        assert_eq!(parse_query(&pairs(&[("limit", "0")])).unwrap().limit, 1);
        assert!(parse_query(&pairs(&[("limit", "many")])).is_err());
    }
}
