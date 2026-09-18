//! Router-level tests for response compression (SPEC §8.3).
//!
//! The property is a pair, and neither half means much alone: a client that offers `gzip` gets a
//! gzipped body, and a client that offers nothing gets the bytes unchanged. Asserting only the first
//! would pass on a layer that compresses unconditionally — which is the failure that actually matters,
//! because a browser cannot read a body it did not ask to have encoded.
//!
//! So every case below checks the *decoded* body against the uncompressed one. That is what makes these
//! tests about the transport rather than about the page: whatever the explorer renders, both clients
//! must end up holding the same bytes.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use monitoring_platform::auth::hash_password;
use monitoring_platform::config::ServeArgs;
use monitoring_platform::model::Measurement;
use monitoring_platform::web::session::COOKIE;
use monitoring_platform::{AppState, Config, api, store};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Read as _;
use tower::ServiceExt as _;

const PASSWORD: &str = "a-high-entropy-password";
const USER: &str = "sashee";

struct Harness {
    app: axum::Router,
    authorization: String,
    _dir: tempfile::TempDir,
}

/// Everything these assertions care about: whether the body arrived encoded, and what it says once it
/// is not.
struct Reply {
    status: StatusCode,
    content_encoding: Option<String>,
    vary: Option<String>,
    /// Exactly what came off the wire.
    wire: Vec<u8>,
    /// `wire`, gunzipped if it was gzipped. What the browser ends up with either way.
    decoded: Vec<u8>,
}

impl Reply {
    fn is_gzipped(&self) -> bool {
        self.content_encoding.as_deref() == Some("gzip")
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.decoded).into_owned()
    }
}

/// Enough rows that the JSON read API's answer clears the compression threshold, and repetitive enough
/// that gzip has something to find — which is also what a real page of measurements looks like.
fn fixtures() -> Vec<Measurement> {
    (0..60)
        .map(|i| Measurement {
            event_time: 1_000 + i,
            processed_time: 2_000 + i,
            kind: "bms.status.cell".to_owned(),
            body: Some(json!({"voltage_mv": 3600 + i, "temperature_c": 21.5, "state": "discharge"})),
            attributes: json!({
                "resource.attributes.device.id": "pack-a",
                "record.attributes.cell.index": i % 16,
            })
            .as_object()
            .unwrap()
            .clone(),
        })
        .collect()
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let args = ServeArgs {
        database: Some(dir.path().join("m.db")),
        socket: Some(dir.path().join("unused.sock")),
        ..Default::default()
    };
    let config = Config::resolve(&args, &HashMap::new());

    // `issue_key` migrates the file, so it runs before anything else touches the tables.
    let authorization = common::issue_key(&config.database_path);
    let mut conn = store::open_write(&config.database_path).unwrap();
    store::users::insert(&conn, USER, &hash_password(PASSWORD), 0).unwrap();
    store::write::insert_batch(&mut conn, &fixtures()).unwrap();

    let (writer, done) = store::write::spawn(conn);
    std::mem::forget(done);

    Harness { app: api::app(AppState::new(config, writer)), authorization, _dir: dir }
}

impl Harness {
    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let header_of = |name: header::HeaderName| {
            response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
        };
        let content_encoding = header_of(header::CONTENT_ENCODING);
        let vary = header_of(header::VARY);
        let declared_length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());

        let wire = response.into_body().collect().await.unwrap().to_bytes().to_vec();

        // A `Content-Length` describing the body before encoding would desynchronise the connection,
        // and it is invisible in a test that only looks at the decoded text — so it is checked here,
        // once, for every request these tests make.
        if let Some(declared) = declared_length {
            assert_eq!(declared, wire.len(), "Content-Length does not describe the body sent");
        }

        let decoded = if content_encoding.as_deref() == Some("gzip") {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(&wire[..])
                .read_to_end(&mut out)
                .expect("the response claimed gzip but did not decode as gzip");
            out
        } else {
            wire.clone()
        };

        Reply { status, content_encoding, vary, wire, decoded }
    }

    /// A logged-in `GET` of the explorer. `accept_encoding` is `None` for a client that offers nothing
    /// at all.
    ///
    /// The window is pinned with explicit `from`/`to` rather than left to the default preset, because
    /// the default is measured from *now* and is printed on the page — so two requests milliseconds
    /// apart would render two different pages and the comparison below would be testing the clock.
    async fn get_page(&self, cookie: &str, accept_encoding: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .uri("/?from=0&to=10000&type=bms.status.cell&t0=bms.status.cell")
            .header(header::COOKIE, format!("{COOKIE}={cookie}"));
        if let Some(value) = accept_encoding {
            request = request.header(header::ACCEPT_ENCODING, value);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn get_json(&self, uri: &str, accept_encoding: Option<&str>) -> Reply {
        let mut request =
            Request::builder().uri(uri).header(header::AUTHORIZATION, &self.authorization);
        if let Some(value) = accept_encoding {
            request = request.header(header::ACCEPT_ENCODING, value);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    /// Logs in and returns the session cookie's value.
    async fn session(&self) -> String {
        let request = Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, "http://localhost")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("username={USER}&password={PASSWORD}")))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "the test login did not succeed");
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|c| c.strip_prefix(&format!("{COOKIE}=")))
            .map(|rest| rest.split(';').next().unwrap_or_default().to_owned())
            .expect("login did not set a session cookie")
    }
}

/// **The pair.** One page, two clients, and the difference is on the wire and nowhere else.
#[tokio::test]
async fn a_page_is_gzipped_for_a_client_that_accepts_it_and_not_for_one_that_does_not() {
    let h = harness();
    let cookie = h.session().await;

    let compressed = h.get_page(&cookie, Some("gzip, deflate, br, zstd")).await;
    let plain = h.get_page(&cookie, None).await;

    assert_eq!(compressed.status, StatusCode::OK);
    assert_eq!(plain.status, StatusCode::OK);

    assert!(compressed.is_gzipped(), "a client offering gzip was sent {:?}", compressed.content_encoding);
    assert_eq!(plain.content_encoding, None, "a client offering nothing was sent an encoded body");

    // The bytes on the wire differ; what the browser ends up holding does not.
    assert_ne!(compressed.wire, plain.wire);
    assert_eq!(compressed.decoded, plain.decoded);
    assert!(compressed.text().contains("<!doctype html>"), "the decoded body is not the page");

    // The point of the exercise: the encoded body is meaningfully smaller.
    assert!(
        compressed.wire.len() < plain.wire.len() / 2,
        "gzip saved little: {} -> {}",
        plain.wire.len(),
        compressed.wire.len()
    );
}

/// `Vary` is not optional once the answer depends on a request header, and it is owed to the client
/// that got the *uncompressed* body just as much as to the one that got the compressed one.
#[tokio::test]
async fn every_response_says_it_varies_on_accept_encoding() {
    let h = harness();
    let cookie = h.session().await;

    for reply in [h.get_page(&cookie, Some("gzip")).await, h.get_page(&cookie, None).await] {
        assert_eq!(reply.vary.as_deref(), Some("accept-encoding"));
    }
}

/// `q=0` is a refusal, not an offer. A layer that searched for the substring `gzip` would fail here and
/// send an unreadable body to a client that explicitly said it could not read one.
#[tokio::test]
async fn a_client_that_refuses_gzip_with_q0_is_not_sent_gzip() {
    let h = harness();
    let cookie = h.session().await;

    let refused = h.get_page(&cookie, Some("gzip;q=0, deflate")).await;
    assert_eq!(refused.content_encoding, None);
    assert!(refused.text().contains("<!doctype html>"));

    // An encoding this service does not speak is not a reason to encode with one it does.
    let other = h.get_page(&cookie, Some("br, zstd")).await;
    assert_eq!(other.content_encoding, None);
    assert!(other.text().contains("<!doctype html>"));
}

/// The read API is behind the same layer, and for the same reason: over iroh its rows travel the same
/// link the pages do.
#[tokio::test]
async fn the_json_read_api_is_compressed_on_the_same_terms() {
    let h = harness();

    let compressed = h.get_json("/v1/measurements?limit=60", Some("gzip")).await;
    let plain = h.get_json("/v1/measurements?limit=60", None).await;

    assert_eq!(compressed.status, StatusCode::OK);
    assert!(compressed.is_gzipped(), "a JSON client offering gzip was sent {:?}", compressed.content_encoding);
    assert_eq!(plain.content_encoding, None);
    assert_eq!(compressed.decoded, plain.decoded);

    // Still JSON once decoded — the layer must not have disturbed the body it re-wrapped.
    let parsed: Value = serde_json::from_slice(&compressed.decoded).expect("decoded body is not JSON");
    assert_eq!(parsed["measurements"].as_array().map(Vec::len), Some(60));
}

/// A body too small to repay gzip's envelope is sent as it is, even to a client that asked. The `303`
/// to the login form is the smallest thing this service returns: no body at all.
#[tokio::test]
async fn a_body_below_the_threshold_is_not_compressed() {
    let h = harness();

    let request = Request::builder()
        .uri("/")
        .header(header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .unwrap();
    let redirect = h.send(request).await;

    assert_eq!(redirect.status, StatusCode::SEE_OTHER);
    assert_eq!(redirect.content_encoding, None);
    assert!(redirect.wire.is_empty());
}

/// Ingest is deliberately outside the layer (SPEC §8.3): §4.1.1 pins that route's encoding for OTLP
/// conformance, and its bodies are tens of bytes either way.
#[tokio::test]
async fn the_ingest_route_is_left_alone() {
    use monitoring_platform::otlp::test_support::sample_request;
    use prost::Message as _;

    let h = harness();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/logs")
        .header(header::AUTHORIZATION, &h.authorization)
        .header(header::ACCEPT_ENCODING, "gzip")
        .header(header::CONTENT_TYPE, api::status::PROTOBUF)
        .body(Body::from(sample_request("dev-1", 1_000).encode_to_vec()))
        .unwrap();

    let reply = h.send(request).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.content_encoding, None);
    // No `Vary` either: the layer never saw this route, so nothing here depends on the request header.
    assert_eq!(reply.vary, None);
}
