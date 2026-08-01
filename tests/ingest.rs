//! Router-level integration tests for `POST /v1/logs` (SPEC §11).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt as _;
use monitoring_platform::api::status::{PROTOBUF, Status};
use monitoring_platform::config::ServeArgs;
use monitoring_platform::otlp::test_support::*;
use monitoring_platform::{AppState, Config, api, store};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use prost::Message;
use rusqlite::Connection;
use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use tower::ServiceExt as _;

const T: i64 = 1_785_489_242_123_456_789;

struct Harness {
    app: axum::Router,
    db: PathBuf,
    _dir: tempfile::TempDir,
}

fn harness_with(mut args: ServeArgs) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("measurements.db");
    args.database = Some(db.clone());
    args.socket = Some(dir.path().join("unused.sock"));

    let config = Config::resolve(&args, &HashMap::new());
    let conn = store::open_write(&config.database_path).unwrap();
    let (writer, _done) = store::write::spawn(conn);
    // The writer handle is deliberately leaked for the test's lifetime; each test gets its own DB.
    std::mem::forget(_done);

    let app = api::app(AppState::new(config, writer));
    Harness { app, db, _dir: dir }
}

fn harness() -> Harness {
    harness_with(ServeArgs::default())
}

impl Harness {
    async fn post(&self, headers: Vec<(&str, &str)>, body: Vec<u8>) -> (StatusCode, Vec<u8>, Option<String>) {
        let mut req = Request::builder().method("POST").uri("/v1/logs");
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let response = self.app.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();

        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = response.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes, content_type)
    }

    /// Posts a protobuf payload with the correct content type.
    async fn ingest(&self, req: &ExportLogsServiceRequest) -> (StatusCode, ExportLogsServiceResponse) {
        let (status, body, ct) =
            self.post(vec![("content-type", PROTOBUF)], req.encode_to_vec()).await;
        assert_eq!(ct.as_deref(), Some(PROTOBUF));
        (status, ExportLogsServiceResponse::decode(body.as_slice()).unwrap())
    }

    fn conn(&self) -> Connection {
        store::open_read(&self.db).unwrap()
    }

    fn row_count(&self) -> i64 {
        self.conn().query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap()
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn sample() -> ExportLogsServiceRequest {
    request(
        vec![kv_str("device.id", "dev-7"), kv_str("service.name", "fleet-agent")],
        "sensors",
        "0.3.1",
        vec![],
        vec![record(
            "gps",
            T,
            0,
            Some(body_map(vec![
                ("lat", OtlpValue::DoubleValue(47.4979)),
                ("lon", OtlpValue::DoubleValue(19.0402)),
            ])),
            vec![kv_str("unit", "wgs84"), kv_int("sensor.index", 2)],
        )],
    )
}

#[tokio::test]
async fn stores_a_batch_and_reports_full_success() {
    let h = harness();
    let (status, response) = h.ingest(&sample()).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response.partial_success.is_none(), "full success must omit partial_success");
    assert_eq!(h.row_count(), 1);

    let (kind, event_time, body, attributes): (String, i64, String, String) = h
        .conn()
        .query_row(
            "SELECT type, event_time, body, attributes FROM measurement",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();

    assert_eq!(kind, "gps");
    assert_eq!(event_time, T);

    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["lat"], serde_json::json!(47.4979));

    let attrs: serde_json::Value = serde_json::from_str(&attributes).unwrap();
    assert_eq!(attrs["resource.attributes.device.id"], "dev-7");
    assert_eq!(attrs["scope.name"], "sensors");
    assert_eq!(attrs["scope.version"], "0.3.1");
    assert_eq!(attrs["record.attributes.unit"], "wgs84");
    assert_eq!(attrs["record.attributes.sensor.index"], 2);
}

#[tokio::test]
async fn processed_time_is_shared_across_a_batch_and_is_not_the_event_time() {
    let h = harness();
    let req = request(
        vec![],
        "",
        "",
        vec![],
        vec![record("a", T, 0, None, vec![]), record("b", T + 5, 0, vec![].into_iter().next(), vec![])],
    );
    h.ingest(&req).await;

    let distinct: i64 = h
        .conn()
        .query_row("SELECT count(DISTINCT processed_time) FROM measurement", [], |r| r.get(0))
        .unwrap();
    assert_eq!(distinct, 1, "one request must yield one processed_time");

    let same: i64 = h
        .conn()
        .query_row(
            "SELECT count(*) FROM measurement WHERE processed_time = event_time",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(same, 0, "processed_time must not be substituted for event_time");
}

/// SPEC §4.3: partial success reports the exact count, and the valid rows are still committed.
#[tokio::test]
async fn mixed_batch_commits_survivors_and_counts_rejections() {
    let h = harness();
    let req = request(
        vec![],
        "",
        "",
        vec![],
        vec![
            record("ok", T, 0, None, vec![]),
            record("", T, 0, None, vec![]),  // no event_name
            record("t", 0, 0, None, vec![]), // no timestamp
        ],
    );

    let (status, response) = h.ingest(&req).await;
    assert_eq!(status, StatusCode::OK, "partial success is still a 200");

    let partial = response.partial_success.expect("partial_success must be set");
    assert_eq!(partial.rejected_log_records, 2);
    assert!(!partial.error_message.is_empty(), "a human-readable reason is required");
    assert_eq!(h.row_count(), 1);
}

/// A wholly-rejected batch is still a 200, so clients do not retry data that can never be accepted.
#[tokio::test]
async fn fully_rejected_batch_is_a_200_with_a_full_count() {
    let h = harness();
    let req = request(vec![], "", "", vec![], vec![record("", T, 0, None, vec![])]);

    let (status, response) = h.ingest(&req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response.partial_success.unwrap().rejected_log_records, 1);
    assert_eq!(h.row_count(), 0);
}

/// SPEC §6.6: the retry-after-a-lost-acknowledgement case. The §4.1 `503` is deliberately
/// retryable so a device never discards its only copy, and the handler awaits the commit before
/// responding — so a broken connection between commit and response makes a device retry
/// *correctly*. That must be a no-op, not a second row.
#[tokio::test]
async fn re_uploading_a_batch_stores_nothing_and_reports_nothing() {
    let h = harness();
    let req = sample();

    let (status, response) = h.ingest(&req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(response.partial_success.is_none());
    assert_eq!(h.row_count(), 1);

    let (status, response) = h.ingest(&req).await;
    assert_eq!(status, StatusCode::OK, "a duplicate is accepted, not refused");
    assert!(
        response.partial_success.is_none(),
        "silently accepted: counting it as rejected would make every correct retry look like a \
         partial failure to the device"
    );
    assert_eq!(h.row_count(), 1, "the retry must not have stored a second row");
}

/// Deduplication must not swallow genuinely distinct data. One nanosecond is enough to separate
/// two measurements, and it is the narrowest case the scheme has to get right.
#[tokio::test]
async fn measurements_differing_by_one_nanosecond_are_both_stored() {
    let h = harness();
    let base = request(vec![], "", "", vec![], vec![record("cpu", T, 0, None, vec![])]);
    let shifted = request(vec![], "", "", vec![], vec![record("cpu", T + 1, 0, None, vec![])]);

    h.ingest(&base).await;
    h.ingest(&shifted).await;
    assert_eq!(h.row_count(), 2);
}

/// A batch that is partly new must store exactly the new part, and still report success for all
/// of it — the device sent nothing wrong.
#[tokio::test]
async fn a_partly_overlapping_batch_stores_only_the_new_records() {
    let h = harness();
    h.ingest(&request(vec![], "", "", vec![], vec![record("a", T, 0, None, vec![])])).await;

    let (status, response) = h
        .ingest(&request(
            vec![],
            "",
            "",
            vec![],
            vec![record("a", T, 0, None, vec![]), record("b", T, 0, None, vec![])],
        ))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(response.partial_success.is_none());
    assert_eq!(h.row_count(), 2, "only the unseen record should have been added");
}

/// Identity is content-based, so how the batch was framed on the wire is irrelevant: the same
/// measurements split across two requests are still the same measurements.
#[tokio::test]
async fn rebatching_the_same_measurements_does_not_duplicate_them() {
    let h = harness();
    let a = record("a", T, 0, None, vec![kv_str("unit", "x")]);
    let b = record("b", T + 1, 0, None, vec![kv_str("unit", "y")]);

    h.ingest(&request(vec![], "", "", vec![], vec![a.clone(), b.clone()])).await;
    assert_eq!(h.row_count(), 2);

    // Same two records, now one per request.
    h.ingest(&request(vec![], "", "", vec![], vec![a])).await;
    h.ingest(&request(vec![], "", "", vec![], vec![b])).await;
    assert_eq!(h.row_count(), 2, "re-framing must not create rows");
}

/// The stored row keeps the arrival time of the FIRST delivery: `processed_time` is not part of
/// identity, and `INSERT OR IGNORE` leaves the existing row alone.
#[tokio::test]
async fn a_duplicate_does_not_move_the_original_arrival_time() {
    let h = harness();
    let req = sample();

    h.ingest(&req).await;
    let first: i64 =
        h.conn().query_row("SELECT processed_time FROM measurement", [], |r| r.get(0)).unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    h.ingest(&req).await;

    let after: i64 =
        h.conn().query_row("SELECT processed_time FROM measurement", [], |r| r.get(0)).unwrap();
    assert_eq!(after, first, "first arrival wins");
}

#[tokio::test]
async fn gzip_and_identity_produce_identical_rows() {
    let payload = sample().encode_to_vec();

    let plain = harness();
    plain.post(vec![("content-type", PROTOBUF)], payload.clone()).await;

    let compressed = harness();
    let (status, _, _) = compressed
        .post(
            vec![("content-type", PROTOBUF), ("content-encoding", "gzip")],
            gzip(&payload),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let read = |h: &Harness| -> (String, String) {
        h.conn()
            .query_row("SELECT body, attributes FROM measurement", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    };
    assert_eq!(read(&plain), read(&compressed), "compression must not alter stored rows");
}

#[tokio::test]
async fn rejects_wrong_content_type_and_unknown_encoding() {
    let h = harness();
    let payload = sample().encode_to_vec();

    let (status, _, _) = h.post(vec![("content-type", "application/json")], payload.clone()).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let (status, _, _) = h.post(vec![], payload.clone()).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "missing content-type");

    let (status, body, _) = h
        .post(vec![("content-type", PROTOBUF), ("content-encoding", "zstd")], payload)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let decoded = Status::decode(body.as_slice()).unwrap();
    assert!(decoded.message.contains("zstd"), "the rejected encoding should be named");

    assert_eq!(h.row_count(), 0);
}

#[tokio::test]
async fn rejects_malformed_protobuf_and_invalid_gzip() {
    let h = harness();

    let (status, _, _) = h.post(vec![("content-type", PROTOBUF)], vec![0xff; 32]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "undecodable protobuf");

    let (status, _, _) = h
        .post(
            vec![("content-type", PROTOBUF), ("content-encoding", "gzip")],
            b"not gzip at all".to_vec(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "gzip declared but not gzip");
}

/// SPEC §4.2: the two limits are independent, and the decompressed one must stop a bomb.
#[tokio::test]
async fn enforces_both_size_limits_independently() {
    const WIRE: usize = 64 * 1024;
    const DECOMPRESSED: usize = 4096;
    let h = harness_with(ServeArgs {
        max_body_bytes: Some(WIRE),
        max_decompressed_bytes: Some(DECOMPRESSED),
        ..Default::default()
    });

    // Over the wire limit, uncompressed.
    let (status, _, _) = h.post(vec![("content-type", PROTOBUF)], vec![0u8; WIRE * 2]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Small on the wire, far too large expanded: must be refused by the *inner* limit, which is
    // the whole reason the two are separate.
    const EXPANDED: usize = 8 << 20;
    const _: () = assert!(EXPANDED > DECOMPRESSED, "bomb must exceed the decompressed limit");

    let bomb = gzip(&vec![0u8; EXPANDED]);
    assert!(
        bomb.len() < WIRE,
        "bomb must pass the wire limit to exercise the inner one (was {} bytes)",
        bomb.len()
    );
    let (status, body, ct) = h
        .post(vec![("content-type", PROTOBUF), ("content-encoding", "gzip")], bomb)
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(ct.as_deref(), Some(PROTOBUF));
    assert!(Status::decode(body.as_slice()).unwrap().message.contains("decompressed"));
}

/// SPEC §4.1.1: every failure carries a protobuf Status, including framework-generated ones.
#[tokio::test]
async fn every_error_response_is_a_protobuf_status() {
    let h = harness();
    let payload = sample().encode_to_vec();

    /// name, request headers, body
    type Case = (&'static str, Vec<(&'static str, &'static str)>, Vec<u8>);

    let cases: Vec<Case> = vec![
        ("wrong content-type", vec![("content-type", "text/plain")], payload.clone()),
        ("missing content-type", vec![], payload.clone()),
        ("unknown encoding", vec![("content-type", PROTOBUF), ("content-encoding", "br")], payload.clone()),
        ("malformed protobuf", vec![("content-type", PROTOBUF)], vec![0xff; 16]),
        ("invalid gzip", vec![("content-type", PROTOBUF), ("content-encoding", "gzip")], vec![1, 2, 3]),
    ];

    for (name, headers, body) in cases {
        let (status, body, ct) = h.post(headers, body).await;
        assert!(status.is_client_error() || status.is_server_error(), "{name} should have failed");
        assert_eq!(ct.as_deref(), Some(PROTOBUF), "{name}: wrong content type");
        let decoded = Status::decode(body.as_slice())
            .unwrap_or_else(|e| panic!("{name}: body is not a Status: {e}"));
        assert!(!decoded.message.is_empty(), "{name}: Status.message must not be empty");
    }
}

/// The framework-generated case: a 405 never reaches our handler, so it exercises the rewrite layer.
#[tokio::test]
async fn method_not_allowed_is_also_a_protobuf_status() {
    let h = harness();
    let response = h
        .app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/v1/logs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some(PROTOBUF),
        "middleware-generated errors must be rewritten to protobuf"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!Status::decode(body.as_ref()).unwrap().message.is_empty());
}

/// SPEC §4.1.1: omitting `code` and `details` must stay wire-compatible with the full definition.
#[test]
fn status_is_wire_compatible_with_the_full_google_rpc_status() {
    /// The full message, as a client library would define it.
    #[derive(Clone, PartialEq, Message)]
    struct FullStatus {
        #[prost(int32, tag = "1")]
        code: i32,
        #[prost(string, tag = "2")]
        message: String,
        #[prost(bytes, repeated, tag = "3")]
        details: Vec<Vec<u8>>,
    }

    let ours = Status { message: "something went wrong".to_owned() };
    let decoded = FullStatus::decode(ours.encode_to_vec().as_slice()).unwrap();

    assert_eq!(decoded.message, "something went wrong");
    assert_eq!(decoded.code, 0, "an omitted code decodes as the proto3 default");
    assert!(decoded.details.is_empty());
}

/// SPEC §5.5: values above 2^53 must survive ingestion intact, asserted on the integer.
#[tokio::test]
async fn large_integers_survive_the_full_ingest_path() {
    let h = harness();
    let req = request(
        vec![],
        "",
        "",
        vec![],
        vec![record(
            "counter",
            T,
            0,
            Some(body_map(vec![("n", OtlpValue::IntValue(i64::MAX))])),
            vec![kv_int("device.serial", 9_007_199_254_740_993)],
        )],
    );
    h.ingest(&req).await;

    let (body_n, attr_serial): (i64, i64) = h
        .conn()
        .query_row(
            "SELECT json_extract(body,'$.n'), \
                    json_extract(attributes,'$.\"record.attributes.device.serial\"') \
             FROM measurement",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(body_n, i64::MAX);
    assert_eq!(attr_serial, 9_007_199_254_740_993);
}

/// SPEC §5.4: non-finite doubles must arrive as sentinel strings, not as null.
#[tokio::test]
async fn non_finite_doubles_are_stored_as_sentinel_strings() {
    let h = harness();
    let req = request(
        vec![],
        "",
        "",
        vec![],
        vec![record(
            "odd",
            T,
            0,
            Some(body_map(vec![
                ("nan", OtlpValue::DoubleValue(f64::NAN)),
                ("inf", OtlpValue::DoubleValue(f64::INFINITY)),
                ("ninf", OtlpValue::DoubleValue(f64::NEG_INFINITY)),
            ])),
            vec![],
        )],
    );
    h.ingest(&req).await;

    let body: String =
        h.conn().query_row("SELECT body FROM measurement", [], |r| r.get(0)).unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["nan"], "NaN");
    assert_eq!(body["inf"], "Infinity");
    assert_eq!(body["ninf"], "-Infinity");
}
