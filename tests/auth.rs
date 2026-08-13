//! Router-level tests for API key handling in its first, non-enforcing form (SPEC §13).
//!
//! Two properties matter here, and they pull in opposite directions, which is why they are asserted
//! together:
//!
//! - **Nothing is refused.** Every existing client sends no `Authorization` header at all, and must
//!   keep working across this deploy. Half the tests below exist only to prove that.
//! - **Verification is nonetheless real.** A key that matches is recognised as matching, and one that
//!   does not is recognised as not — so the journal can be trusted before enforcement is switched on.
//!
//! When phase 2 lands, the "still served" assertions become the ones that flip, and
//! [`Outcome::is_authorized`] is what decides them. It is asserted here already so the two cannot
//! disagree.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use monitoring_platform::api::auth::{Outcome, evaluate};
use monitoring_platform::api::status::PROTOBUF;
use monitoring_platform::auth::{Malformed, Token, TOKEN_BYTES};
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

impl Harness {
    /// `POST /v1/logs` with a well-formed batch, optionally authenticated.
    async fn ingest(&self, authorization: Option<&str>) -> StatusCode {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/logs")
            .header(header::CONTENT_TYPE, PROTOBUF);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let body = sample_request("dev-1", T).encode_to_vec();

        self.app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
            .status()
    }

    async fn get(&self, uri: &str, authorization: Option<&str>) -> StatusCode {
        let mut request = Request::builder().uri(uri);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        self.app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    /// How many measurements actually landed — the check that "served" means served, not merely a
    /// 200 from a handler that was skipped.
    fn stored(&self) -> i64 {
        let conn = store::open_read(&self.state.config.database_path).unwrap();
        conn.query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap()
    }

    async fn outcome(&self, authorization: Option<&str>) -> Outcome {
        evaluate(&self.state, authorization.map(str::to_owned)).await
    }
}

// ------------------------------------------------------- nothing is refused, whatever is presented

/// The property the whole first step exists for: a client that has never heard of API keys keeps
/// working, and its data still lands.
#[tokio::test]
async fn a_request_with_no_key_is_still_served() {
    let harness = harness(&[]);

    assert_eq!(harness.ingest(None).await, StatusCode::OK);
    assert_eq!(harness.get("/v1/measurements", None).await, StatusCode::OK);
    assert!(harness.stored() > 0, "the batch must have been stored, not merely acknowledged");
}

/// Nor is a *wrong* key refused yet. This is the one that would fail first if enforcement leaked in
/// ahead of schedule.
#[tokio::test]
async fn a_request_with_an_unusable_key_is_still_served() {
    let harness = harness(&[]);

    for presented in [
        "Bearer mpk_0000000000000000.0000",       // malformed
        "Bearer mpk_0000000000000000.00000000000000000000000000000000000000000000000000000000000000ff", // unknown id
        "Basic bXA6c2VjcmV0",                     // not even bearer
        "",                                       // present but empty
    ] {
        assert_eq!(
            harness.ingest(Some(presented)).await,
            StatusCode::OK,
            "ingest refused {presented:?} before enforcement exists"
        );
        assert_eq!(
            harness.get("/v1/measurements", Some(presented)).await,
            StatusCode::OK,
            "the read API refused {presented:?} before enforcement exists"
        );
    }
}

#[tokio::test]
async fn a_valid_key_is_served_too() {
    let key = token(1);
    let harness = harness(&[(&key, "pi-7")]);
    let header = format!("Bearer {}", key.to_secret_string());

    assert_eq!(harness.ingest(Some(&header)).await, StatusCode::OK);
    assert_eq!(harness.get("/v1/measurements", Some(&header)).await, StatusCode::OK);
}

/// `/healthz` is outside the layer entirely, and has to answer for a caller holding no credential —
/// a deploy probe, an `ExecStartPre`, a human with curl.
#[tokio::test]
async fn healthz_is_reachable_with_and_without_a_key() {
    let key = token(2);
    let harness = harness(&[(&key, "pi-7")]);

    assert_eq!(harness.get("/healthz", None).await, StatusCode::OK);
    assert_eq!(
        harness.get("/healthz", Some("Bearer nonsense")).await,
        StatusCode::OK,
        "healthz must not care about a key it does not require"
    );
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
