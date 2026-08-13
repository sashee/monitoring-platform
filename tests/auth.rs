//! Router-level tests for API key enforcement (SPEC §13).
//!
//! Three things have to hold at once, and they are asserted together because it is the *combination*
//! that is the security property:
//!
//! - **A request without a valid key gets nowhere.** Not merely a 401 — the body must never be
//!   parsed and nothing may reach the database.
//! - **A refusal looks like the route it came from.** OTLP requires a protobuf `Status` on every 4xx;
//!   the read API answers JSON. A client that cannot decode the refusal cannot report it.
//! - **A key that could not be *checked* is not a key that was wrong.** That one answers 503, because
//!   401 is not retryable and the device may hold the only copy of the measurement.
//!
//! `/healthz` stays open, and is asserted here rather than assumed: it is the endpoint every readiness
//! probe and `ExecStartPre` depends on.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use monitoring_platform::api::auth::{Outcome, Shape, evaluate, refuse};
use monitoring_platform::api::status::{PROTOBUF, Status};
use monitoring_platform::auth::{Malformed, TOKEN_BYTES, Token};
use monitoring_platform::config::ServeArgs;
use monitoring_platform::otlp::test_support::sample_request;
use monitoring_platform::{AppState, Config, api, store};
use prost::Message;
use std::collections::HashMap;
use tower::ServiceExt as _;

const T: i64 = 1_785_489_242_123_456_789;

struct Harness {
    app: axum::Router,
    state: AppState,
    _dir: tempfile::TempDir,
}

/// A receiver with `issued` already in its key table.
fn harness(issued: &[(&Token, &str)]) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let args = ServeArgs {
        database: Some(dir.path().join("measurements.db")),
        socket: Some(dir.path().join("unused.sock")),
        ..Default::default()
    };
    let config = Config::resolve(&args, &HashMap::new());

    let conn = store::open_write(&config.database_path).unwrap();
    for (token, label) in issued {
        store::keys::insert(&conn, token.id(), &token.secret_hash(), label, T).unwrap();
    }
    let (writer, done) = store::write::spawn(conn);
    std::mem::forget(done);

    let state = AppState::new(config, writer);
    Harness { app: api::app(state.clone()), state, _dir: dir }
}

/// A token from fixed bytes, so the same one can be built twice without storing it.
fn token(seed: u8) -> Token {
    let mut bytes = [seed; TOKEN_BYTES];
    // Vary the id half too, so two seeds cannot collide on the primary key.
    bytes[0] = seed.wrapping_mul(31);
    Token::from_random(&bytes)
}

/// Everything about a response the assertions below care about.
struct Reply {
    status: StatusCode,
    content_type: Option<String>,
    challenge: Option<String>,
    body: Vec<u8>,
}

impl Harness {
    /// `POST /v1/logs` with a well-formed batch, optionally authenticated.
    async fn ingest(&self, authorization: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/logs")
            .header(header::CONTENT_TYPE, PROTOBUF);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let body = sample_request("dev-1", T).encode_to_vec();

        self.send(request.body(Body::from(body)).unwrap()).await
    }

    async fn get(&self, uri: &str, authorization: Option<&str>) -> Reply {
        let mut request = Request::builder().uri(uri);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let header_of = |name: header::HeaderName| {
            response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
        };
        let (status, content_type, challenge) = (
            response.status(),
            header_of(header::CONTENT_TYPE),
            header_of(header::WWW_AUTHENTICATE),
        );
        let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();

        Reply { status, content_type, challenge, body }
    }

    /// How many measurements actually landed — the check that "served" means served, not merely a
    /// 200 from a handler that was skipped.
    fn stored(&self) -> i64 {
        let conn = store::open_read(&self.state.config.database_path).unwrap();
        conn.query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap()
    }

    async fn outcome(&self, authorization: Option<&str>) -> Outcome {
        let value = authorization.map(|raw| header::HeaderValue::from_str(raw).unwrap());
        evaluate(&self.state, value.as_ref()).await
    }

    /// For the header values a `&str` cannot express.
    async fn outcome_of_bytes(&self, authorization: &[u8]) -> Outcome {
        let value = header::HeaderValue::from_bytes(authorization).unwrap();
        evaluate(&self.state, Some(&value)).await
    }
}

// ------------------------------------------------------------------------------- what gets through

#[tokio::test]
async fn a_valid_key_is_served() {
    let key = token(1);
    let harness = harness(&[(&key, "pi-7")]);
    let header = format!("Bearer {}", key.to_secret_string());

    assert_eq!(harness.ingest(Some(&header)).await.status, StatusCode::OK);
    assert_eq!(harness.get("/v1/measurements", Some(&header)).await.status, StatusCode::OK);
    assert!(harness.stored() > 0, "the batch must be stored, not merely acknowledged");
}

/// `/healthz` is outside the layer entirely, and has to answer for a caller holding no credential —
/// a deploy probe, an `ExecStartPre`, a human with curl.
#[tokio::test]
async fn healthz_is_reachable_with_and_without_a_key() {
    let key = token(2);
    let harness = harness(&[(&key, "pi-7")]);

    assert_eq!(harness.get("/healthz", None).await.status, StatusCode::OK);
    assert_eq!(
        harness.get("/healthz", Some("Bearer nonsense")).await.status,
        StatusCode::OK,
        "healthz must not care about a key it does not require"
    );
}

// ----------------------------------------------------------------------------- what does not

/// Every way of failing to present a key, on both routes.
fn unusable_keys() -> Vec<(&'static str, String)> {
    vec![
        ("malformed", "Bearer mpk_0000000000000000.0000".to_owned()),
        ("unknown id", format!("Bearer mpk_0000000000000000.{}", "ab".repeat(32))),
        ("not bearer", "Basic bXA6c2VjcmV0".to_owned()),
        ("empty header", String::new()),
    ]
}

#[tokio::test]
async fn ingest_without_a_key_is_refused_and_stores_nothing() {
    let harness = harness(&[]);

    let reply = harness.ingest(None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.stored(), 0, "a refused batch must not reach the database");
}

#[tokio::test]
async fn every_kind_of_unusable_key_is_refused_on_both_routes() {
    let harness = harness(&[(&token(3), "pi-7")]);

    for (name, presented) in unusable_keys() {
        assert_eq!(
            harness.ingest(Some(&presented)).await.status,
            StatusCode::UNAUTHORIZED,
            "ingest accepted a {name} key"
        );
        assert_eq!(
            harness.get("/v1/measurements", Some(&presented)).await.status,
            StatusCode::UNAUTHORIZED,
            "the read API accepted a {name} key"
        );
    }
    assert_eq!(harness.stored(), 0, "nothing may be stored by a refused request");
}

/// A known id with the wrong secret is the case the two-part token exists for, and it must be refused
/// exactly like an unknown one — from the client's side, indistinguishably so.
#[tokio::test]
async fn a_known_id_with_the_wrong_secret_is_refused() {
    let issued = token(4);
    let harness = harness(&[(&issued, "pi-7")]);
    let forged = format!("Bearer mpk_{}.{}", issued.id(), "cd".repeat(32));

    let reply = harness.ingest(Some(&forged)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    let unknown = harness.ingest(Some(&format!("Bearer {}", token(5).to_secret_string()))).await;
    assert_eq!(
        String::from_utf8_lossy(&reply.body),
        String::from_utf8_lossy(&unknown.body),
        "a wrong secret and an unissued id must be indistinguishable to the client, or the \
         response becomes an oracle for which ids exist"
    );
}

/// OTLP requires a protobuf `Status` body on every 4xx (SPEC §4.1.1). A refusal is no exception — a
/// client that cannot decode it cannot report why it was refused.
#[tokio::test]
async fn an_ingest_refusal_is_protobuf_with_a_challenge() {
    let reply = harness(&[]).ingest(None).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.content_type.as_deref(), Some(PROTOBUF));
    assert_eq!(reply.challenge.as_deref(), Some("Bearer"), "RFC 7235 requires the challenge");

    let status = Status::decode(reply.body.as_slice()).expect("a decodable google.rpc.Status");
    assert!(status.message.contains("API key"), "unhelpful message: {:?}", status.message);
}

#[tokio::test]
async fn a_read_refusal_is_json_with_a_challenge() {
    let reply = harness(&[]).get("/v1/measurements", None).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.content_type.as_deref(), Some("application/json"));
    assert_eq!(reply.challenge.as_deref(), Some("Bearer"));

    let json: serde_json::Value = serde_json::from_slice(&reply.body).expect("JSON body");
    assert!(json["error"].as_str().unwrap_or_default().contains("API key"), "{json}");
}

/// The asymmetry that matters most. A database that cannot be read is *our* failure, and `401` is not
/// retryable — answering it would tell a device to discard the only copy of a measurement.
#[tokio::test]
async fn a_key_that_cannot_be_checked_is_a_retryable_503() {
    let harness = harness(&[(&token(6), "pi-7")]);
    // Unlinked, so a fresh read-only connection cannot be opened. The writer's handle survives, which
    // is what keeps this a *verification* failure rather than a broken harness.
    std::fs::remove_file(&harness.state.config.database_path).unwrap();

    // A *well-formed* token, so verification actually reaches the lookup. A malformed one is refused
    // by parsing alone and never touches the database — correctly, and not what this is testing.
    let reply = harness.ingest(Some(&format!("Bearer {}", token(6).to_secret_string()))).await;
    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unverifiable key must be retryable, not a refusal"
    );
    assert_eq!(reply.content_type.as_deref(), Some(PROTOBUF));
    assert_eq!(reply.challenge, None, "503 is not a challenge to authenticate");
}

/// Revocation is deleting the row (SPEC §13.2), and it has to take effect on the next request. Keys
/// are looked up per request with no cache, so this passes today — and it is the test that would fail
/// if a cache were ever added without an invalidation path, which is exactly when a revoked key
/// quietly continuing to work would be a security bug rather than a curiosity.
#[tokio::test]
async fn a_deleted_key_stops_working_immediately() {
    let key = token(10);
    let harness = harness(&[(&key, "pi-7")]);
    let header = format!("Bearer {}", key.to_secret_string());

    assert_eq!(harness.ingest(Some(&header)).await.status, StatusCode::OK);

    let conn = store::open_write(&harness.state.config.database_path).unwrap();
    conn.execute("DELETE FROM api_key WHERE id = ?1", [key.id()]).unwrap();
    drop(conn);

    assert_eq!(
        harness.ingest(Some(&header)).await.status,
        StatusCode::UNAUTHORIZED,
        "a revoked key must stop working without a restart"
    );
}

/// Several devices, several keys. Trivial to get right and trivial to break: a lookup that fetched
/// "the" key rather than the one the id names would pass every other test in this file.
#[tokio::test]
async fn each_of_several_keys_works_on_its_own() {
    let (first, second) = (token(11), token(12));
    let harness = harness(&[(&first, "pi-7"), (&second, "pi-8")]);

    for key in [&first, &second] {
        let outcome = harness.outcome(Some(&format!("Bearer {}", key.to_secret_string()))).await;
        assert_eq!(outcome, Outcome::Valid { id: key.id().to_owned() });
    }
}

/// A header whose bytes are not text is *present*, and must not be reported as missing: an operator
/// reading "no API key presented" about a request that presented one is being told the wrong thing.
/// A `&str`-shaped signature could not express this case, which is why it went unnoticed.
#[tokio::test]
async fn an_unreadable_header_is_malformed_rather_than_absent() {
    let harness = harness(&[]);

    let outcome = harness.outcome_of_bytes(b"Bearer \xff\xfe not text").await;
    assert_eq!(outcome, Outcome::Malformed(Malformed::NotText));
    assert_ne!(outcome, Outcome::Absent, "it was presented, just not readably");
    assert_eq!(refuse(&outcome, Shape::Otlp).status(), StatusCode::UNAUTHORIZED);
}

/// Enforcement has to happen before the body is touched, not after. A 4 KiB payload that expands to
/// 64 MiB must be refused on the credential and never handed to the decompressor — otherwise an
/// unauthenticated caller can spend the receiver's memory at will.
#[tokio::test]
async fn an_unauthenticated_gzip_bomb_is_refused_without_being_decompressed() {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write as _;

    let harness = harness(&[]);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&vec![0u8; 64 << 20]).unwrap();
    let bomb = encoder.finish().unwrap();
    assert!(bomb.len() < 200_000, "the bomb should be small on the wire: {}", bomb.len());

    let reply = harness
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header(header::CONTENT_TYPE, PROTOBUF)
                .header(header::CONTENT_ENCODING, "gzip")
                .body(Body::from(bomb))
                .unwrap(),
        )
        .await;

    // 401 rather than the 413 a decompressed bomb would earn: the refusal came first.
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.stored(), 0);
}

/// `refuse` in isolation, over the whole matrix — the mapping from outcome to status is the part that
/// must not drift, and it is cheaper to pin here than through eight requests.
#[test]
fn every_outcome_maps_to_the_documented_status() {
    let unauthorized = [
        Outcome::Absent,
        Outcome::Malformed(Malformed::MissingPrefix),
        Outcome::Malformed(Malformed::NotText),
        Outcome::UnknownId,
        Outcome::WrongSecret,
    ];
    for outcome in unauthorized {
        for shape in [Shape::Otlp, Shape::Json] {
            assert_eq!(
                refuse(&outcome, shape).status(),
                StatusCode::UNAUTHORIZED,
                "{outcome:?} on {shape:?}"
            );
        }
    }
    for shape in [Shape::Otlp, Shape::Json] {
        assert_eq!(
            refuse(&Outcome::Unavailable, shape).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}

// --------------------------------------------------------------- but verification is real anyway

#[tokio::test]
async fn a_matching_key_verifies() {
    let key = token(3);
    let harness = harness(&[(&key, "pi-7")]);

    let outcome = harness.outcome(Some(&format!("Bearer {}", key.to_secret_string()))).await;
    assert_eq!(outcome, Outcome::Valid { id: key.id().to_owned() });
    assert!(outcome.is_authorized());
}

#[tokio::test]
async fn a_missing_header_is_absent_rather_than_invalid() {
    let outcome = harness(&[]).outcome(None).await;
    assert_eq!(outcome, Outcome::Absent);
    assert!(!outcome.is_authorized());
}

#[tokio::test]
async fn an_id_that_was_never_issued_is_unknown() {
    let harness = harness(&[(&token(4), "pi-7")]);
    let stranger = token(5);

    assert_eq!(
        harness.outcome(Some(&format!("Bearer {}", stranger.to_secret_string()))).await,
        Outcome::UnknownId
    );
}

/// The case the scheme exists to catch: the public half is right and the secret is not. It must be
/// distinguishable from an unknown id, because the two mean different things to whoever is reading
/// the journal — a stale key versus a guess.
#[tokio::test]
async fn a_known_id_with_the_wrong_secret_is_rejected_on_the_secret() {
    let issued = token(6);
    let harness = harness(&[(&issued, "pi-7")]);

    // Same id, a different secret: built by splicing, since a token cannot be constructed by hand.
    let other = token(7);
    let forged = format!(
        "Bearer mpk_{}.{}",
        issued.id(),
        other.to_secret_string().split_once('.').unwrap().1
    );

    let outcome = harness.outcome(Some(&forged)).await;
    assert_eq!(outcome, Outcome::WrongSecret);
    assert!(!outcome.is_authorized());
}

#[tokio::test]
async fn a_header_that_is_not_a_token_names_the_shape_that_was_wrong() {
    let harness = harness(&[]);

    assert_eq!(
        harness.outcome(Some("Bearer not-a-key")).await,
        Outcome::Malformed(Malformed::MissingPrefix)
    );
    assert_eq!(
        harness.outcome(Some("Bearer mpk_0001020304050607")).await,
        Outcome::Malformed(Malformed::NotTwoParts)
    );
    assert_eq!(
        harness.outcome(Some("Token abc")).await,
        Outcome::Malformed(Malformed::NotBearer)
    );
}

/// An unusable key must never be *reported* as valid, whatever the response ends up being. This is
/// the assertion that makes the journal trustworthy enough to enforce on.
#[tokio::test]
async fn nothing_short_of_a_matching_key_is_authorized() {
    let issued = token(8);
    let harness = harness(&[(&issued, "pi-7")]);

    for presented in [
        None,
        Some("Bearer nonsense".to_owned()),
        Some(format!("Bearer {}", token(9).to_secret_string())),
        Some(format!("Bearer mpk_{}.{}", issued.id(), "0".repeat(64))),
    ] {
        let outcome = harness.outcome(presented.as_deref()).await;
        assert!(!outcome.is_authorized(), "{outcome:?} must not count as authorized");
    }
}
