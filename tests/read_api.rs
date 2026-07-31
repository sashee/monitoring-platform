//! Router-level integration tests for `GET /v1/measurements` (SPEC §7, §11).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use monitoring_platform::config::ServeArgs;
use monitoring_platform::model::Measurement;
use monitoring_platform::{AppState, Config, api, store};
use serde_json::{Value, json};
use std::collections::HashMap;
use tower::ServiceExt as _;

struct Harness {
    app: axum::Router,
    _dir: tempfile::TempDir,
}

fn harness(measurements: Vec<Measurement>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let args = ServeArgs {
        database: Some(dir.path().join("m.db")),
        socket: Some(dir.path().join("unused.sock")),
        ..Default::default()
    };
    let config = Config::resolve(&args, &HashMap::new());

    let mut conn = store::open_write(&config.database_path).unwrap();
    store::write::insert_batch(&mut conn, &measurements).unwrap();
    let (writer, done) = store::write::spawn(conn);
    std::mem::forget(done);

    Harness { app: api::app(AppState::new(config, writer)), _dir: dir }
}

impl Harness {
    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("{uri} did not return JSON ({e}): {:?}", String::from_utf8_lossy(&bytes)));
        (status, value)
    }
}

fn m(kind: &str, event_time: i64, attrs: Value, body: Value) -> Measurement {
    Measurement {
        event_time,
        processed_time: event_time + 1_000,
        kind: kind.to_owned(),
        body: Some(body),
        attributes: attrs.as_object().unwrap().clone(),
    }
}

fn fixtures() -> Vec<Measurement> {
    vec![
        m("gps", 1_000, json!({"resource.attributes.device.id": "dev-1", "record.attributes.unit": "wgs84"}), json!({"lat": 47.5})),
        m("cpu", 2_000, json!({"resource.attributes.device.id": "dev-1", "record.attributes.unit": "ratio"}), json!({"usage": 0.5})),
        m("cpu", 3_000, json!({"resource.attributes.device.id": "dev-2", "record.attributes.unit": "ratio"}), json!({"usage": 0.9})),
    ]
}

#[tokio::test]
async fn healthz_reports_ok() {
    let h = harness(vec![]);
    let (status, body) = h.get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"status": "ok"}));
}

#[tokio::test]
async fn lists_newest_first_with_the_documented_shape() {
    let h = harness(fixtures());
    let (status, body) = h.get("/v1/measurements").await;
    assert_eq!(status, StatusCode::OK);

    let rows = body["measurements"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows.iter().map(|r| r["type"].as_str().unwrap()).collect::<Vec<_>>(),
        vec!["cpu", "cpu", "gps"],
        "must be ordered newest first"
    );
    assert!(body["next_cursor"].is_null(), "a short page is the last page");

    let first = &rows[0];
    assert_eq!(first["event_time"], "1970-01-01T00:00:00.000003000Z");
    // A string, so a JSON parser backed by f64 cannot silently round it (SPEC §5.5).
    assert_eq!(first["event_time_unix_nano"], "3000");
    assert!(first["event_time_unix_nano"].is_string());
    assert!(first["processed_time_unix_nano"].is_string());
    assert_eq!(first["body"], json!({"usage": 0.9}));
    assert_eq!(first["attributes"]["resource.attributes.device.id"], "dev-2");
    assert!(first["id"].is_number());
}

#[tokio::test]
async fn filters_by_type_time_range_and_attribute() {
    let h = harness(fixtures());

    let (_, body) = h.get("/v1/measurements?type=cpu").await;
    assert_eq!(body["measurements"].as_array().unwrap().len(), 2);

    // Repeated `type` matches any of them.
    let (_, body) = h.get("/v1/measurements?type=cpu&type=gps").await;
    assert_eq!(body["measurements"].as_array().unwrap().len(), 3);

    // Inclusive lower bound, exclusive upper.
    let (_, body) = h.get("/v1/measurements?from=2000&to=3000").await;
    let rows = body["measurements"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["event_time_unix_nano"], "2000");

    // Attribute filters AND with each other and with `type`.
    let (_, body) =
        h.get("/v1/measurements?attr.resource.attributes.device.id=dev-1").await;
    assert_eq!(body["measurements"].as_array().unwrap().len(), 2);

    let (_, body) = h
        .get("/v1/measurements?type=cpu&attr.resource.attributes.device.id=dev-1")
        .await;
    assert_eq!(body["measurements"].as_array().unwrap().len(), 1);

    let (_, body) = h
        .get("/v1/measurements?type=gps&attr.resource.attributes.device.id=dev-2")
        .await;
    assert!(body["measurements"].as_array().unwrap().is_empty(), "filters must AND, not OR");
}

/// RFC 3339 and integer nanoseconds must be interchangeable.
#[tokio::test]
async fn accepts_both_time_formats() {
    let h = harness(fixtures());
    let (_, by_nanos) = h.get("/v1/measurements?from=2000").await;
    let (_, by_rfc) =
        h.get("/v1/measurements?from=1970-01-01T00:00:00.000002Z").await;
    assert_eq!(by_nanos["measurements"], by_rfc["measurements"]);
}

/// SPEC §7.1: nested values are returned in full but never match a filter.
#[tokio::test]
async fn nested_attributes_are_returned_but_not_filterable() {
    let h = harness(vec![m(
        "t",
        10,
        json!({"record.attributes.cfg": {"mode": "fast"}}),
        json!(null),
    )]);

    let (_, body) = h.get("/v1/measurements").await;
    assert_eq!(
        body["measurements"][0]["attributes"]["record.attributes.cfg"],
        json!({"mode": "fast"})
    );

    let (status, body) = h
        .get("/v1/measurements?attr.record.attributes.cfg=%7B%22mode%22%3A%22fast%22%7D")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["measurements"].as_array().unwrap().is_empty(),
        "a nested value must not be matchable by its serialized text"
    );
}

#[tokio::test]
async fn paginates_without_gaps_or_duplicates() {
    // All identical timestamps, the case that breaks naive pagination.
    let rows: Vec<Measurement> = (0..7).map(|_| m("t", 500, json!({}), json!(1))).collect();
    let h = harness(rows);

    let mut seen: Vec<i64> = Vec::new();
    let mut uri = "/v1/measurements?limit=3".to_owned();
    loop {
        let (_, body) = h.get(&uri).await;
        let page = body["measurements"].as_array().unwrap().clone();
        seen.extend(page.iter().map(|r| r["id"].as_i64().unwrap()));

        match body["next_cursor"].as_str() {
            Some(cursor) => uri = format!("/v1/measurements?limit=3&cursor={cursor}"),
            None => break,
        }
    }

    let mut unique = seen.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(seen.len(), 7, "a row was returned twice: {seen:?}");
    assert_eq!(unique.len(), 7, "a row was missed: {seen:?}");
}

#[tokio::test]
async fn rejects_unknown_parameters_and_bad_values_as_json() {
    let h = harness(fixtures());

    let (status, body) = h.get("/v1/measurements?typo=cpu").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("typo"), "should name the bad parameter");

    for uri in [
        "/v1/measurements?from=yesterday",
        "/v1/measurements?limit=lots",
        "/v1/measurements?cursor=!!!",
        "/v1/measurements?attr.=x",
    ] {
        let (status, body) = h.get(uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} should have been rejected");
        assert!(body["error"].is_string(), "{uri}: read API errors are JSON, not protobuf");
    }
}

#[tokio::test]
async fn limit_is_clamped_rather_than_rejected() {
    let h = harness(fixtures());
    let (status, body) = h.get("/v1/measurements?limit=999999").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["measurements"].as_array().unwrap().len(), 3);
}

/// SPEC §5.5: an integer beyond 2^53 must come back exactly, and be parseable as an i64.
#[tokio::test]
async fn large_integers_survive_the_read_api() {
    let big = 9_007_199_254_740_993i64;
    let h = harness(vec![m(
        "counter",
        10,
        json!({"record.attributes.serial": big}),
        json!({"n": i64::MAX}),
    )]);

    let (_, body) = h.get("/v1/measurements").await;
    let row = &body["measurements"][0];
    assert_eq!(row["body"]["n"].as_i64(), Some(i64::MAX));
    assert_eq!(row["attributes"]["record.attributes.serial"].as_i64(), Some(big));
}
