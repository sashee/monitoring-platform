//! Router-level tests for the web interface (SPEC §14).
//!
//! Four things have to hold at once, and they are asserted together because it is the *combination* that is
//! the security property:
//!
//! - **A page requires a session.** Not merely a redirect — the body must not contain the data the page
//!   would have shown.
//! - **A session is established only by a correct password**, and a wrong one is indistinguishable from an
//!   unknown user.
//! - **The two credentials do not cross.** A session cookie must not authenticate `/v1/*`, and an API key
//!   must not open a page. Both directions, because each is a separate mistake.
//! - **Device-supplied text cannot become markup.** A measurement whose `type` is `<script>` is stored
//!   verbatim by design (SPEC §5.2), so the rendering is the only thing standing between that and the
//!   browser.
//!
//! `/healthz` and `/login` stay open, and are asserted rather than assumed: a login form behind a login is a
//! locked door with the key inside.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use monitoring_platform::api::status::PROTOBUF;
use monitoring_platform::auth::{SessionToken, TOKEN_BYTES, hash_password};
use monitoring_platform::config::ServeArgs;
use monitoring_platform::otlp::test_support::sample_request;
use monitoring_platform::web::session::{COOKIE, TTL_NANOS};
use monitoring_platform::{AppState, Config, api, store};
use prost::Message;
use std::collections::HashMap;
use tower::ServiceExt as _;

const T: i64 = 1_785_489_242_123_456_789;
const PASSWORD: &str = "a-high-entropy-password";
const USER: &str = "sashee";

struct Harness {
    app: axum::Router,
    db: std::path::PathBuf,
    /// A valid API key, for the cross-credential assertions.
    authorization: String,
    _dir: tempfile::TempDir,
}

/// A receiver with one user and one API key already in it.
fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("measurements.db");
    let args = ServeArgs {
        database: Some(db.clone()),
        socket: Some(dir.path().join("unused.sock")),
        ..Default::default()
    };
    let config = Config::resolve(&args, &HashMap::new());

    // `issue_key` migrates the file, so this runs first and everything below sees the 3.1 tables.
    let authorization = common::issue_key(&db);
    let conn = store::open_write(&db).unwrap();
    store::users::insert(&conn, USER, &hash_password(PASSWORD), T).unwrap();

    let (writer, done) = store::write::spawn(conn);
    std::mem::forget(done);

    let app = api::app(AppState::new(config, writer));
    Harness { app, db, authorization, _dir: dir }
}

/// Everything about a response the assertions below care about.
struct Reply {
    status: StatusCode,
    location: Option<String>,
    set_cookie: Vec<String>,
    body: String,
}

impl Reply {
    /// The session cookie's value out of `Set-Cookie`, if this response establishes one.
    ///
    /// A clearing cookie (`Max-Age=0`) is deliberately *not* a session: a logout response also carries a
    /// `Set-Cookie` for the same name, and treating that as a login would make several assertions below
    /// silently vacuous.
    fn session(&self) -> Option<String> {
        self.set_cookie
            .iter()
            .filter(|c| !c.contains("Max-Age=0"))
            .find_map(|c| c.strip_prefix(&format!("{COOKIE}=")))
            .map(|rest| rest.split(';').next().unwrap_or_default().to_owned())
    }
}

impl Harness {
    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let location =
            response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let set_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_owned)
            .collect();
        let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();

        Reply { status, location, set_cookie, body: String::from_utf8_lossy(&body).into_owned() }
    }

    async fn get(&self, uri: &str, cookie: Option<&str>) -> Reply {
        let mut request = Request::builder().uri(uri);
        if let Some(value) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={value}"));
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    /// A `GET` carrying an API key and no cookie, for the cross-credential assertions.
    async fn get_with_key(&self, uri: &str) -> Reply {
        let request = Request::builder().uri(uri).header(header::AUTHORIZATION, &self.authorization);
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn post_form(&self, uri: &str, body: &str, cookie: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(value) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={value}"));
        }
        self.send(request.body(Body::from(body.to_owned())).unwrap()).await
    }

    /// Logs in and returns the cookie value.
    async fn login(&self) -> String {
        let reply = self
            .post_form("/login", &format!("username={USER}&password={PASSWORD}"), None)
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "precondition: login must succeed");
        reply.session().expect("login must set a session cookie")
    }

    fn read(&self) -> rusqlite::Connection {
        store::open_read(&self.db).unwrap()
    }

    fn session_count(&self) -> usize {
        store::sessions::list(&self.read()).unwrap().len()
    }
}

fn session_token(seed: u8) -> SessionToken {
    let mut bytes = [seed; TOKEN_BYTES];
    bytes[0] = seed.wrapping_mul(31);
    SessionToken::from_random(&bytes)
}

// ------------------------------------------------------------------------------------- what is open

/// A login form behind a login would be a locked door with the key inside.
#[tokio::test]
async fn the_login_form_is_reachable_without_a_session() {
    let harness = harness();
    let reply = harness.get("/login", None).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains(r#"name="password""#), "{}", reply.body);
}

/// `/healthz` is outside every layer, and must stay that way now that a second one exists.
#[tokio::test]
async fn healthz_needs_neither_a_key_nor_a_session() {
    let harness = harness();
    assert_eq!(harness.get("/healthz", None).await.status, StatusCode::OK);
    assert_eq!(harness.get("/healthz", Some("nonsense")).await.status, StatusCode::OK);
}

// ------------------------------------------------------------------------------------- logging in

#[tokio::test]
async fn a_correct_password_establishes_a_session() {
    let harness = harness();
    let reply =
        harness.post_form("/login", &format!("username={USER}&password={PASSWORD}"), None).await;

    // 303, so a reload of the resulting page does not re-submit the password.
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/"));
    assert!(reply.session().is_some(), "no session cookie in {:?}", reply.set_cookie);
    assert_eq!(harness.session_count(), 1, "and a row to go with it");
}

/// The attributes the browser actually depends on, asserted on the wire rather than on the builder that
/// produced them.
#[tokio::test]
async fn the_session_cookie_is_httponly_samesite_and_not_secure() {
    let harness = harness();
    let reply =
        harness.post_form("/login", &format!("username={USER}&password={PASSWORD}"), None).await;
    let cookie = reply.set_cookie.first().expect("a Set-Cookie header");

    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(cookie.contains("Path=/"), "{cookie}");
    assert!(cookie.contains(&format!("Max-Age={}", TTL_NANOS / 1_000_000_000)), "{cookie}");
    // Not an oversight: the browser reaches this over plain HTTP on loopback through the tunnel, so
    // `Secure` would make every request after login anonymous (SPEC §14).
    assert!(!cookie.contains("Secure"), "{cookie}");
}

/// The cookie must carry a session token, not something that could be confused with an API key.
#[tokio::test]
async fn the_cookie_carries_a_session_token_not_an_api_key() {
    let harness = harness();
    let cookie = harness.login().await;

    assert!(cookie.starts_with("mps_"), "{cookie}");
    assert!(!cookie.starts_with("mpk_"), "{cookie}");
}

#[tokio::test]
async fn a_wrong_password_establishes_nothing() {
    let harness = harness();
    let reply = harness.post_form("/login", &format!("username={USER}&password=wrong"), None).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.session().is_none(), "no cookie: {:?}", reply.set_cookie);
    assert_eq!(harness.session_count(), 0, "and no row either");
    assert!(reply.body.contains(r#"name="password""#), "the form comes back: {}", reply.body);
}

/// One message for both, or the form becomes an oracle for which usernames exist.
#[tokio::test]
async fn an_unknown_user_is_indistinguishable_from_a_wrong_password() {
    let harness = harness();

    let wrong_password =
        harness.post_form("/login", &format!("username={USER}&password=wrong"), None).await;
    let unknown_user =
        harness.post_form("/login", "username=nobody&password=wrong", None).await;

    assert_eq!(wrong_password.status, unknown_user.status);
    assert_eq!(wrong_password.body, unknown_user.body);
}

/// The password arrives percent-encoded, and `Form` is what decodes it. A password containing `&`, `+` or
/// `%` must survive the round trip — otherwise a login that works from `curl` fails from a browser.
#[tokio::test]
async fn a_password_with_form_metacharacters_still_matches() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("measurements.db");
    let args = ServeArgs {
        database: Some(db.clone()),
        socket: Some(dir.path().join("unused.sock")),
        ..Default::default()
    };
    let config = Config::resolve(&args, &HashMap::new());

    let awkward = "a&b+c%20d=e";
    let conn = store::open_write(&db).unwrap();
    store::users::insert(&conn, USER, &hash_password(awkward), T).unwrap();
    let (writer, done) = store::write::spawn(conn);
    std::mem::forget(done);
    let harness =
        Harness { app: api::app(AppState::new(config, writer)), db, authorization: String::new(), _dir: dir };

    // Percent-encoded exactly as a browser would send it.
    let reply = harness
        .post_form("/login", &format!("username={USER}&password=a%26b%2Bc%2520d%3De"), None)
        .await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER, "body was {}", reply.body);
}

// ------------------------------------------------------------------------------------- the guard

#[tokio::test]
async fn the_pages_are_served_with_a_session() {
    let harness = harness();
    let cookie = harness.login().await;

    for path in ["/", "/users", "/sessions"] {
        let reply = harness.get(path, Some(&cookie)).await;
        assert_eq!(reply.status, StatusCode::OK, "on {path}");
    }
    assert!(harness.get("/users", Some(&cookie)).await.body.contains(USER));
}

/// A redirect is not enough on its own: the body must not contain what the page would have shown.
#[tokio::test]
async fn the_pages_are_refused_without_a_session() {
    let harness = harness();
    // A user exists, so a leak would be visible.
    for path in ["/", "/users", "/sessions"] {
        let reply = harness.get(path, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "on {path}");
        assert_eq!(reply.location.as_deref(), Some("/login"), "on {path}");
        assert!(!reply.body.contains(USER), "{path} leaked the user list: {}", reply.body);
    }
}

#[tokio::test]
async fn a_cookie_naming_an_unissued_session_is_refused() {
    let harness = harness();
    let reply = harness.get("/", Some(&session_token(9).to_secret_string())).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
}

/// A cookie whose id exists but whose secret does not match must be refused — otherwise the public half
/// alone would be a credential, and it is on the sessions page.
#[tokio::test]
async fn a_cookie_with_the_right_id_and_the_wrong_secret_is_refused() {
    let harness = harness();
    let real = harness.login().await;
    let id = real.strip_prefix("mps_").unwrap().split_once('.').unwrap().0;

    let forged = format!("mps_{id}.{}", "f".repeat(64));
    let reply = harness.get("/", Some(&forged)).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn a_malformed_cookie_is_refused() {
    let harness = harness();
    for value in ["", "nonsense", "mps_short.short", "mpk_0001020304050607.0102"] {
        let reply = harness.get("/", Some(value)).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "on {value:?}");
    }
}

/// An expired session is not a session, even though its row is still there — the row is swept only at the
/// next login.
#[tokio::test]
async fn an_expired_session_is_refused() {
    let harness = harness();
    let cookie = harness.login().await;

    // Move the expiry into the past, as the passage of a month would.
    let conn = store::open_write_existing(&harness.db).unwrap();
    conn.execute("UPDATE web_session SET expires_at = 1", []).unwrap();

    let reply = harness.get("/", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
    assert_eq!(harness.session_count(), 1, "still on disk; expiry is checked, not enforced by deletion");
}

/// The next login sweeps what has expired, which is why no timer is needed.
#[tokio::test]
async fn logging_in_sweeps_expired_sessions() {
    let harness = harness();
    harness.login().await;
    let conn = store::open_write_existing(&harness.db).unwrap();
    conn.execute("UPDATE web_session SET expires_at = 1", []).unwrap();
    drop(conn);

    harness.login().await;

    assert_eq!(harness.session_count(), 1, "the expired row went, the new one stayed");
}

// ------------------------------------------------------------------------------------- logging out

#[tokio::test]
async fn logging_out_deletes_the_session_and_clears_the_cookie() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness.post_form("/logout", "", Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
    assert!(
        reply.set_cookie.iter().any(|c| c.contains("Max-Age=0")),
        "the cookie must be cleared: {:?}",
        reply.set_cookie
    );
    assert_eq!(harness.session_count(), 0, "and the row must be gone");

    // The cookie the browser was holding is now worthless.
    assert_eq!(harness.get("/", Some(&cookie)).await.status, StatusCode::SEE_OTHER);
}

/// Logging out is itself behind the guard: without it, `POST /logout` from anywhere would be a way to probe
/// whether the receiver is up.
#[tokio::test]
async fn logging_out_requires_a_session() {
    let harness = harness();
    let reply = harness.post_form("/logout", "", None).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
}

/// A `GET` that logs you out is a link a prefetcher can fire.
#[tokio::test]
async fn logout_is_not_reachable_by_get() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness.get("/logout", Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(harness.session_count(), 1, "the session must survive a GET");
}

// ------------------------------------------------- the two credentials must not cross (SPEC §13, §14)

/// A browser session must not authenticate the machine API. Both `/v1` routes, because they have separate
/// layers and so are separate mistakes.
#[tokio::test]
async fn a_session_cookie_does_not_authenticate_the_v1_api() {
    let harness = harness();
    let cookie = harness.login().await;

    let read = harness
        .send(
            Request::builder()
                .uri("/v1/measurements")
                .header(header::COOKIE, format!("{COOKIE}={cookie}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(read.status, StatusCode::UNAUTHORIZED, "session must not open the read API");

    let ingest = harness
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header(header::CONTENT_TYPE, PROTOBUF)
                .header(header::COOKIE, format!("{COOKIE}={cookie}"))
                .body(Body::from(sample_request("dev-1", T).encode_to_vec()))
                .unwrap(),
        )
        .await;
    assert_eq!(ingest.status, StatusCode::UNAUTHORIZED, "session must not open ingest");

    let stored: i64 =
        harness.read().query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap();
    assert_eq!(stored, 0, "and nothing may have been written");
}

/// And the other direction: a valid API key must not open the UI. It is a device credential, and a device
/// has no business reading the operator's pages.
#[tokio::test]
async fn an_api_key_does_not_open_the_web_interface() {
    let harness = harness();

    for path in ["/", "/users", "/sessions"] {
        let reply = harness.get_with_key(path).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "on {path}");
        assert_eq!(reply.location.as_deref(), Some("/login"), "on {path}");
        assert!(!reply.body.contains(USER), "{path} leaked to a key holder: {}", reply.body);
    }
}

/// The API key still works on its own surface — otherwise the test above could pass because the key was
/// simply invalid.
#[tokio::test]
async fn the_api_key_still_works_on_the_v1_api() {
    let harness = harness();
    assert_eq!(harness.get_with_key("/v1/measurements").await.status, StatusCode::OK);
}

// ------------------------------------------------------------------------------------- rendering

/// A device may send `<script>` as an event name and nothing before the rendering rejects it (SPEC §5.2
/// stores attribute keys and types verbatim). This is the end-to-end form of `html::escape`'s unit tests.
#[tokio::test]
async fn device_supplied_text_cannot_become_markup() {
    let harness = harness();
    let cookie = harness.login().await;

    let hostile = "<script>alert('x')</script>";
    let conn = store::open_write_existing(&harness.db).unwrap();
    // A full-width content id: the read path parses this column into a `ContentId` and errors on anything
    // that is not exactly `content_id::ID_LEN` bytes, so a token blob would fail the query rather than the
    // escaping.
    conn.execute(
        "INSERT INTO measurement (id, event_time, processed_time, type, body, attributes) \
         VALUES (x'0102030405060708090a0b0c0d0e0f10', ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![T, T, hostile, format!("\"{hostile}\""), format!("{{\"{hostile}\":1}}")],
    )
    .unwrap();
    drop(conn);

    let reply = harness.get("/", Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("&lt;script&gt;"), "the value must be shown, escaped");
    assert!(
        !reply.body.contains("<script>"),
        "an unescaped script tag reached the page: {}",
        reply.body
    );
}

/// The pages are HTML with an explicit charset. Without one, a browser guesses the encoding of a page that
/// contains device-supplied UTF-8, and can guess wrong.
#[tokio::test]
async fn the_pages_declare_html_and_a_charset() {
    let harness = harness();
    let cookie = harness.login().await;

    for (path, value) in [("/login", None), ("/", Some(cookie.as_str()))] {
        let response = harness
            .app
            .clone()
            .oneshot({
                let mut request = Request::builder().uri(path);
                if let Some(cookie) = value {
                    request = request.header(header::COOKIE, format!("{COOKIE}={cookie}"));
                }
                request.body(Body::empty()).unwrap()
            })
            .await
            .unwrap();

        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8",
            "on {path}"
        );
    }
}
