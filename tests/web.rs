//! Router-level tests for the web interface (SPEC §14).
//!
//! Four things have to hold at once, and they are asserted together because it is the *combination* that is
//! the security property:
//!
//! - **A page requires a session.** Not merely a redirect — the body must not contain the data the page
//!   would have shown.
//! - **A session is established only by a sign-in token that is still good**, once, or by a passkey.
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
use monitoring_platform::auth::{LoginToken, SessionToken, TOKEN_BYTES};
use monitoring_platform::config::ServeArgs;
use monitoring_platform::otlp::test_support::sample_request;
use monitoring_platform::web::session::{COOKIE, TTL_NANOS};
use monitoring_platform::{AppState, Config, api, store};
use prost::Message;
use std::collections::HashMap;
use tower::ServiceExt as _;

const T: i64 = 1_785_489_242_123_456_789;
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
    store::users::insert(&conn, USER, T).unwrap();

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

    /// A `POST` from the same origin it was sent to — what a browser does.
    async fn post_form(&self, uri: &str, body: &str, cookie: Option<&str>) -> Reply {
        self.post_from(uri, body, cookie, Some("http://localhost")).await
    }

    /// `origin` is `None` to simulate a client that sends none, which the check must refuse.
    async fn post_from(
        &self,
        uri: &str,
        body: &str,
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            // The origin check compares `Origin` against `Host`, so a test request needs both — a
            // relative URI carries no `Host` of its own.
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(value) = origin {
            request = request.header(header::ORIGIN, value);
        }
        if let Some(value) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={value}"));
        }
        self.send(request.body(Body::from(body.to_owned())).unwrap()).await
    }

    /// Ingests measurements directly, for the explorer tests.
    fn ingest(&self, measurements: &[monitoring_platform::model::Measurement]) {
        let mut conn = store::open_write(&self.db).unwrap();
        store::write::insert_batch(&mut conn, measurements).unwrap();
    }

    fn users(&self) -> Vec<String> {
        store::users::list(&self.read()).unwrap().into_iter().map(|u| u.username).collect()
    }

    /// Logs in with a fresh sign-in token and returns the cookie value.
    async fn login(&self) -> String {
        self.login_as(USER).await
    }

    async fn login_as(&self, username: &str) -> String {
        let token = self.issue_token(username);
        let reply = self.post_form("/login", &token_field(&token), None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "precondition: login must succeed: {}", reply.body);
        reply.session().expect("login must set a session cookie")
    }

    /// A sign-in token for `username`, issued as `create-login-token` issues one.
    fn issue_token(&self, username: &str) -> String {
        let conn = store::open_write_existing(&self.db).unwrap();
        let issued = monitoring_platform::web::login_token::issue(&conn, username, monitoring_platform::now_unix_nanos())
            .unwrap()
            .expect("the user exists");
        issued.token.to_secret_string()
    }

    fn token_count(&self) -> usize {
        store::login_tokens::list(&self.read()).unwrap().len()
    }

    fn read(&self) -> rusqlite::Connection {
        store::open_read(&self.db).unwrap()
    }

    fn session_count(&self) -> usize {
        store::sessions::list(&self.read()).unwrap().len()
    }
}

/// The login form's body for `token`, percent-encoded as a browser sends it.
fn token_field(token: &str) -> String {
    format!("token={}", monitoring_platform::web::html::percent_encode(token))
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
    assert!(reply.body.contains(r#"name="token""#), "{}", reply.body);
    assert!(!reply.body.contains("password"), "no password form any more: {}", reply.body);
}

/// `/healthz` is outside every layer, and must stay that way now that a second one exists.
#[tokio::test]
async fn healthz_needs_neither_a_key_nor_a_session() {
    let harness = harness();
    assert_eq!(harness.get("/healthz", None).await.status, StatusCode::OK);
    assert_eq!(harness.get("/healthz", Some("nonsense")).await.status, StatusCode::OK);
}

// ------------------------------------------------------------------------------------- logging in

/// A sign-in token starts a session and sends the browser to the account page, where a passkey is added.
#[tokio::test]
async fn a_sign_in_token_establishes_a_session() {
    let harness = harness();
    let token = harness.issue_token(USER);
    let reply = harness.post_form("/login", &token_field(&token), None).await;

    // 303, so a reload of the resulting page does not re-submit the token.
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.location.as_deref(), Some("/account"));
    assert!(reply.session().is_some(), "no session cookie in {:?}", reply.set_cookie);
    assert_eq!(harness.session_count(), 1, "and a row to go with it");
    assert_eq!(harness.token_count(), 0, "the token is used up");
}

/// The attributes the browser actually depends on, asserted on the wire rather than on the builder that
/// produced them.
#[tokio::test]
async fn the_session_cookie_is_httponly_samesite_and_not_secure() {
    let harness = harness();
    let token = harness.issue_token(USER);
    let reply = harness.post_form("/login", &token_field(&token), None).await;
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

/// **Single use**, through the form: the second attempt establishes nothing and says why.
#[tokio::test]
async fn a_sign_in_token_works_once() {
    let harness = harness();
    let token = harness.issue_token(USER);
    harness.post_form("/login", &token_field(&token), None).await;

    let again = harness.post_form("/login", &token_field(&token), None).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert!(again.session().is_none(), "no cookie: {:?}", again.set_cookie);
    assert_eq!(harness.session_count(), 1, "only the first sign-in's");
    assert!(again.body.contains("used already"), "{}", again.body);
    assert!(again.body.contains(r#"name="token""#), "the form comes back: {}", again.body);
}

/// A token nobody issued, of the right shape: nothing, and the user is not told whose it might have been.
#[tokio::test]
async fn an_unissued_token_establishes_nothing() {
    let harness = harness();
    let forged = LoginToken::from_random(&[9; TOKEN_BYTES]).to_secret_string();
    let reply = harness.post_form("/login", &token_field(&forged), None).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.session().is_none());
    assert_eq!(harness.session_count(), 0);
}

/// The right id with the wrong secret neither signs in nor voids the real token.
#[tokio::test]
async fn the_wrong_secret_does_not_spend_the_token() {
    let harness = harness();
    let token = harness.issue_token(USER);
    let (id, _) = token.split_once('.').unwrap();
    let wrong = format!("{id}.{}", "0".repeat(64));

    let reply = harness.post_form("/login", &token_field(&wrong), None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.token_count(), 1, "still usable");
    assert_eq!(harness.post_form("/login", &token_field(&token), None).await.status, StatusCode::SEE_OTHER);
}

/// An expired token says so, which tells its owner to issue another rather than retype this one.
#[tokio::test]
async fn an_expired_token_says_so() {
    let harness = harness();
    let token = LoginToken::from_random(&[3; TOKEN_BYTES]);
    // Issued and expired long before the clock this runs against.
    let conn = store::open_write_existing(&harness.db).unwrap();
    store::login_tokens::issue(&conn, token.id(), &token.secret_hash(), USER, T, T + 1).unwrap();

    let reply = harness.post_form("/login", &token_field(&token.to_secret_string()), None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.body.contains("expired"), "{}", reply.body);
    assert_eq!(harness.session_count(), 0);
}

/// Something that is not a sign-in token at all — a session cookie pasted by mistake, say — is refused by its
/// shape, before the database is asked.
#[tokio::test]
async fn something_other_than_a_token_is_refused_by_its_shape() {
    let harness = harness();
    for pasted in [session_token(1).to_secret_string(), "hunter2".to_owned(), String::new()] {
        let reply = harness.post_form("/login", &token_field(&pasted), None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "on {pasted:?}");
        assert!(reply.body.contains("not a sign-in token"), "on {pasted:?}: {}", reply.body);
    }
    assert_eq!(harness.session_count(), 0);
}

/// A paste picks up whitespace — a trailing newline from a terminal, most often. It still signs in.
#[tokio::test]
async fn a_pasted_token_with_surrounding_whitespace_still_signs_in() {
    let harness = harness();
    let token = harness.issue_token(USER);
    let reply = harness.post_form("/login", &token_field(&format!(" {token}\n")), None).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
}

// ------------------------------------------------------------------------------------- the guard

#[tokio::test]
async fn the_pages_are_served_with_a_session() {
    let harness = harness();
    let cookie = harness.login().await;

    for path in ["/", "/users", "/sessions", "/account"] {
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
    for path in ["/", "/users", "/sessions", "/account"] {
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

    for path in ["/", "/users", "/sessions", "/account"] {
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
    // Through the write path rather than raw SQL, which since §6.7 is the only way the row is visible at
    // all — the read path joins `series`, so a hand-inserted row with no `series_id` renders as nothing
    // and the test would pass by vacuum. It also puts the hostile text where the page now reads it
    // from: `series.type` and `series.attributes`, not the measurement's own copies.
    let mut conn = store::open_write_existing(&harness.db).unwrap();
    store::write::insert_batch(
        &mut conn,
        &[monitoring_platform::model::Measurement {
            event_time: T,
            processed_time: T,
            kind: hostile.to_owned(),
            body: Some(serde_json::json!(hostile)),
            attributes: serde_json::json!({ hostile: 1 }).as_object().unwrap().clone(),
        }],
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

// ------------------------------------------------------- the origin check (SPEC §14.3)

/// **The case the origin check exists for.** `SameSite` ignores the port, so another server on loopback
/// is same-site and its forged POST arrives *with* the session cookie. Only comparing `Origin` to `Host`
/// sees the difference.
#[tokio::test]
async fn a_post_from_another_port_on_the_same_host_is_refused() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness
        .post_from(
            "/users/create",
            "username=intruder",
            Some(&cookie),
            Some("http://localhost:3000"),
        )
        .await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(harness.users(), vec![USER.to_owned()], "nothing may have been written");
}

#[tokio::test]
async fn a_post_with_no_origin_is_refused() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply =
        harness.post_from("/users/create", "username=x", Some(&cookie), None).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(harness.users(), vec![USER.to_owned()]);
}

/// The check runs **before** the credentials are even looked at, which is what makes it a defence rather
/// than a second opinion: a forged login attempt is refused as forged, not as wrong.
#[tokio::test]
async fn login_itself_is_origin_checked() {
    let harness = harness();

    let token = harness.issue_token(USER);
    let reply = harness.post_from("/login", &token_field(&token), None, Some("http://evil.example")).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN, "not 303, and not 401");
    assert!(reply.session().is_none());
    assert_eq!(harness.session_count(), 0);
    assert_eq!(harness.token_count(), 1, "and the token is not spent");
}

/// Logging out is state-changing too, so it is checked — otherwise any local page could log you out.
#[tokio::test]
async fn logout_is_origin_checked() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness.post_from("/logout", "", Some(&cookie), Some("http://other:9")).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(harness.session_count(), 1, "the session must survive a forged logout");
}

/// Reads are not checked. A `GET` changes nothing, and requiring the header on every page load would
/// break following a bookmark, where a browser sends no `Origin`.
#[tokio::test]
async fn reads_are_not_origin_checked() {
    let harness = harness();
    let cookie = harness.login().await;
    assert_eq!(harness.get("/", Some(&cookie)).await.status, StatusCode::OK);
    assert_eq!(harness.get("/login", None).await.status, StatusCode::OK);
}

// ------------------------------------------------------- managing users

/// Creating a user shows their sign-in token once, and that token signs them in.
#[tokio::test]
async fn a_user_can_be_created_and_then_log_in() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness.post_form("/users/create", "username=second", Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(harness.users().contains(&"second".to_owned()));
    let token = issued_secret(&reply.body).expect("the new user's token, shown once");
    assert!(token.starts_with("mpl_"), "{token}");
    assert!(reply.body.contains("a sign-in token until"), "the table says so: {}", reply.body);

    let logged_in = harness.post_form("/login", &token_field(&token), None).await;
    assert_eq!(logged_in.status, StatusCode::SEE_OTHER);
    assert!(logged_in.session().is_some());
    let sessions = store::sessions::list(&harness.read()).unwrap();
    assert!(sessions.iter().any(|s| s.username == "second"), "signed in as the new user");

    // Not repeated on the next load: only its hash was stored.
    let users = harness.get("/users", Some(&cookie)).await;
    assert!(!users.body.contains(&token), "{}", users.body);
}

/// The secret in a page's shown-once block, if it has one.
fn issued_secret(body: &str) -> Option<String> {
    let (_, after) = body.split_once("class=\"issued\"")?;
    let (_, code) = after.split_once("<code>")?;
    Some(code.split_once("</code>")?.0.to_owned())
}

/// A duplicate is the operator's typo, so it is a message on the page rather than a 500.
#[tokio::test]
async fn a_duplicate_username_is_reported_not_crashed() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness.post_form("/users/create", &format!("username={USER}"), Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("already exists"), "{}", reply.body);
    assert!(issued_secret(&reply.body).is_none(), "no token for a user not created");
    assert_eq!(harness.users().len(), 1);
}

#[tokio::test]
async fn a_user_needs_a_name() {
    let harness = harness();
    let cookie = harness.login().await;

    for body in ["username=", "username=%20%20"] {
        let reply = harness.post_form("/users/create", body, Some(&cookie)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "on {body:?}");
        assert_eq!(harness.users().len(), 1, "on {body:?}");
    }
}

#[tokio::test]
async fn a_user_can_be_deleted_once_another_exists() {
    let harness = harness();
    let cookie = harness.login().await;
    harness.post_form("/users/create", "username=second", Some(&cookie)).await;

    let reply = harness.post_form("/users/delete", "username=second", Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(harness.users(), vec![USER.to_owned()]);
}

/// **A delete button that can lock you out is a footgun.** Refused in the handler, not merely hidden in
/// the rendering — the page whose button was pressed may be minutes old.
#[tokio::test]
async fn the_last_user_cannot_be_deleted() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness.post_form("/users/delete", &format!("username={USER}"), Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(harness.users(), vec![USER.to_owned()], "the only user must survive");
    assert!(reply.body.contains("only user"), "{}", reply.body);
}

/// Deleting yourself takes your sessions with you (`users::delete` cascades), so the response has to be
/// the login form — anything else would be a redirect to a page the browser can no longer load.
#[tokio::test]
async fn deleting_your_own_user_logs_you_out() {
    let harness = harness();
    let cookie = harness.login().await;
    harness.post_form("/users/create", "username=second", Some(&cookie)).await;

    let reply = harness.post_form("/users/delete", &format!("username={USER}"), Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
    assert!(reply.set_cookie.iter().any(|c| c.contains("Max-Age=0")), "{:?}", reply.set_cookie);
    assert_eq!(harness.session_count(), 0, "the cascade must have removed the session");
    assert_eq!(harness.get("/", Some(&cookie)).await.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn deleting_a_user_who_does_not_exist_is_reported() {
    let harness = harness();
    let cookie = harness.login().await;
    harness.post_form("/users/create", "username=second", Some(&cookie)).await;

    let reply = harness.post_form("/users/delete", "username=ghost", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("no such user"), "{}", reply.body);
}

// ------------------------------------------------------- ending sessions

#[tokio::test]
async fn another_session_can_be_ended_without_touching_your_own() {
    let harness = harness();
    let theirs = harness.login().await;
    let mine = harness.login().await;
    assert_eq!(harness.session_count(), 2);

    let theirs_id = theirs.strip_prefix("mps_").unwrap().split_once('.').unwrap().0.to_owned();
    let reply = harness.post_form("/sessions/end", &format!("id={theirs_id}"), Some(&mine)).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/sessions"));
    assert_eq!(harness.session_count(), 1);
    assert_eq!(harness.get("/", Some(&theirs)).await.status, StatusCode::SEE_OTHER, "ended");
    assert_eq!(harness.get("/", Some(&mine)).await.status, StatusCode::OK, "mine still works");
}

/// Ending your own is allowed — it is logout by another route, and it is the one a reader is most likely
/// to want gone.
#[tokio::test]
async fn ending_your_own_session_logs_you_out() {
    let harness = harness();
    let cookie = harness.login().await;
    let id = cookie.strip_prefix("mps_").unwrap().split_once('.').unwrap().0.to_owned();

    let reply = harness.post_form("/sessions/end", &format!("id={id}"), Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
    assert!(reply.set_cookie.iter().any(|c| c.contains("Max-Age=0")));
    assert_eq!(harness.session_count(), 0);
}

// ------------------------------------------------------- the explorer (SPEC §14.9)

use monitoring_platform::model::Measurement;
use serde_json::json;

/// Measurements shaped like the real `bms.status.cell` data: one numeric body leaf, split by an
/// attribute, one row per cell per bucket.
fn cells(count: i64, cells: i64) -> Vec<Measurement> {
    let mut out = Vec::new();
    for i in 0..count {
        for c in 1..=cells {
            out.push(Measurement {
                event_time: T + i * 1_000_000_000,
                processed_time: T,
                kind: "bms.status.cell".to_owned(),
                body: Some(json!({"voltage_volts": 3.29 + (c as f64) * 0.001})),
                attributes: json!({"record.attributes.cell": c.to_string()})
                    .as_object()
                    .unwrap()
                    .clone(),
            });
        }
    }
    out
}

/// The explorer's URL is its state, so a filter is exercised the way a reader reaches it.
async fn explore(harness: &Harness, cookie: &str, query: &str) -> Reply {
    harness.get(&format!("/?{query}"), Some(cookie)).await
}

#[tokio::test]
async fn the_explorer_offers_the_types_that_exist() {
    let harness = harness();
    harness.ingest(&cells(2, 2));
    let cookie = harness.login().await;

    let reply = explore(&harness, &cookie, "range=all").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("bms.status.cell"), "the type must be offered");
    assert!(reply.body.contains("Choose a type"), "and the hint shown until one is chosen");
}

#[tokio::test]
async fn an_attribute_filter_narrows_the_table() {
    let harness = harness();
    harness.ingest(&cells(3, 3));
    let cookie = harness.login().await;

    let all = explore(&harness, &cookie, "range=all&type=bms.status.cell&t0=bms.status.cell").await;
    let filtered = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&attr.record.attributes.cell=2",
    )
    .await;

    let rows = |b: &str| b.matches("<tr>").count();
    assert!(rows(&all.body) > rows(&filtered.body), "the filter must remove rows");
    assert!(filtered.body.contains("3.292"), "cell 2's value is 3.29 + 2*0.001");
    assert!(!filtered.body.contains("3.291"), "cell 1 must be gone: {}", filtered.body);
}

#[tokio::test]
async fn a_numeric_field_renders_a_value_chart() {
    let harness = harness();
    harness.ingest(&cells(5, 1));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts",
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("class=\"line\""), "a line must be drawn: {}", reply.body);
    assert!(reply.body.contains("var(--series-1)"), "in a palette slot, not a hex literal");
}

/// The timeline is always there, whatever the bodies contain — it is the only plot a text-bodied type can
/// have, and it is what answers "when did these arrive".
#[tokio::test]
async fn a_text_only_type_gets_a_timeline_and_no_value_chart() {
    let harness = harness();
    harness.ingest(&[Measurement {
        event_time: T,
        processed_time: T,
        kind: "system.unit".to_owned(),
        body: Some(json!({"active_state": "active"})),
        attributes: json!({"record.attributes.unit": "sshd"}).as_object().unwrap().clone(),
    }]);
    let cookie = harness.login().await;

    let reply = explore(&harness, &cookie, "range=all&type=system.unit&t0=system.unit").await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("measurements over time"), "the timeline is always shown");
    assert!(reply.body.contains("class=\"col\""), "with its columns: {}", reply.body);
    // `active_state` is text, so it must not be offered as a chart field...
    assert!(
        !reply.body.contains(r#"name="field" value="active_state""#),
        "a text leaf is not chartable: {}",
        reply.body
    );
    // ...but it is still worth a table column, since its values are the thing you came to read.
    assert!(reply.body.contains("<th>active_state</th>"), "{}", reply.body);
}

/// **All groups are plotted, not the first eight.** Past the palette's eight hues, identity is carried by
/// hue *and* line pattern together, so a ninth series is distinguishable without a ninth hue being invented.
#[tokio::test]
async fn every_group_is_plotted_past_the_palette() {
    let harness = harness();
    harness.ingest(&cells(2, 12));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts&group=record.attributes.cell",
    )
    .await;

    assert_eq!(reply.body.matches("class=\"line\"").count(), 12, "all twelve: {}", reply.body);
    assert!(!reply.body.contains("Showing 8 of"), "nothing is left out any more");
    assert!(!reply.body.contains("var(--series-9)"), "and never a ninth hue");
    // The four past the palette are dashed, which is what tells them from hues 1-4.
    assert_eq!(reply.body.matches("stroke-dasharray").count(), 4, "{}", reply.body);
    // Every group is in the legend.
    let legend = reply.body.split("<ul class=\"legend\">").nth(1).expect("a legend");
    for cell in 1..=12 {
        assert!(legend.contains(&format!(">{cell}</a>")), "cell {cell} missing: {legend}");
    }
}

/// Tapping a legend entry hides that line, and the link is how — there is no JavaScript.
#[tokio::test]
async fn a_legend_entry_toggles_its_series() {
    let harness = harness();
    harness.ingest(&cells(2, 3));
    let cookie = harness.login().await;

    let base = "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts\
&group=record.attributes.cell";
    let shown = explore(&harness, &cookie, base).await;
    assert_eq!(shown.body.matches("class=\"line\"").count(), 3);

    // Every entry offers a hide link...
    let legend = shown.body.split("<ul class=\"legend\">").nth(1).expect("a legend");
    assert!(legend.contains("hide=2"), "{legend}");

    // ...and following it removes exactly that line.
    let hidden = explore(&harness, &cookie, &format!("{base}&hide=2")).await;
    assert_eq!(hidden.body.matches("class=\"line\"").count(), 2, "one line fewer");

    // The hidden one is still listed, struck through, with a link that brings it back.
    let legend = hidden.body.split("<ul class=\"legend\">").nth(1).expect("a legend");
    assert!(legend.contains("class=\"off\""), "a hidden entry must still be listed: {legend}");
    let restore = legend.split("class=\"off\"").nth(1).expect("the hidden entry");
    assert!(!restore.split("</li>").next().unwrap().contains("hide=2"), "its link must un-hide it");
}

/// **Hiding must not repaint what remains.** A reader who learned that cell 3 is the aqua line has to find
/// it aqua after hiding cell 1.
#[tokio::test]
async fn hiding_a_series_does_not_recolour_the_others() {
    let harness = harness();
    harness.ingest(&cells(2, 4));
    let cookie = harness.login().await;

    let base = "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts\
&group=record.attributes.cell";
    let all = explore(&harness, &cookie, base).await;
    let hidden = explore(&harness, &cookie, &format!("{base}&hide=1")).await;

    // Cell 4 is the fourth group, so it holds slot 4's hue either way.
    assert!(all.body.contains("var(--series-4)"), "{}", all.body);
    assert!(hidden.body.contains("var(--series-4)"), "cell 4 was repainted: {}", hidden.body);
    // And the freed first hue is not handed to anyone else.
    assert!(!hidden.body.contains("stroke=\"var(--series-1)\""), "{}", hidden.body);
}

/// Past the hard bound a plot cannot distinguish them at all, so it says what it left out.
#[tokio::test]
async fn beyond_the_hard_bound_the_chart_says_so() {
    let harness = harness();
    // 30 groups, past 8 hues x 3 patterns.
    harness.ingest(&cells(1, 30));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts&group=record.attributes.cell",
    )
    .await;

    assert!(reply.body.contains("Showing 24 of 30 groups"), "{}", reply.body);
}

/// Groups are ordered — and coloured — by *sorted* value, numerically when they are numbers. Before the
/// cap was lifted this decided which eight you saw at all; it still decides which hue each one gets, and a
/// legend running 1, 10, 11, 2 is one nobody can scan.
#[tokio::test]
async fn numeric_groups_are_ordered_numerically() {
    let harness = harness();
    harness.ingest(&cells(2, 12));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts\
         &group=record.attributes.cell",
    )
    .await;

    // Numeric order, so cell 2 comes second rather than after cell 19.
    let legend = reply.body.split("<ul class=\"legend\">").nth(1).expect("a legend").to_owned();
    // The label is the text between the key span and the end of the anchor.
    let order: Vec<&str> = legend
        .split("</ul>")
        .next()
        .expect("the legend list")
        .split("</span>")
        .skip(1)
        .filter_map(|rest| rest.split("</a>").next())
        .collect();
    assert_eq!(
        order,
        vec!["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"],
        "the legend must read in numeric order: {legend}"
    );
}

/// Device-supplied text reaches the SVG through group labels. SVG is XML, so an unescaped `<` is as
/// dangerous there as in HTML.
#[tokio::test]
async fn device_supplied_group_labels_cannot_break_out_of_the_svg() {
    let harness = harness();
    let hostile = "<script>alert('x')</script>";
    harness.ingest(&[
        Measurement {
            event_time: T,
            processed_time: T,
            kind: "t".to_owned(),
            body: Some(json!({"v": 1.0})),
            attributes: json!({ "g": hostile }).as_object().unwrap().clone(),
        },
        Measurement {
            event_time: T + 1_000_000_000,
            processed_time: T,
            kind: "t".to_owned(),
            body: Some(json!({"v": 2.0})),
            attributes: json!({"g": "ordinary"}).as_object().unwrap().clone(),
        },
    ]);
    let cookie = harness.login().await;

    let reply = explore(&harness, &cookie, "range=all&type=t&t0=t&field=v&group=g").await;

    assert!(!reply.body.contains("<script>"), "unescaped markup: {}", reply.body);
    assert!(reply.body.contains("&lt;script&gt;"), "the label must still be shown, escaped");
}

/// Changing the type in the one filter form resubmits the previous type's attribute selects. They belong
/// to a type that no longer applies, so they must be dropped rather than return an empty page.
#[tokio::test]
async fn switching_type_drops_the_previous_type_s_filters() {
    let harness = harness();
    harness.ingest(&cells(3, 2));
    harness.ingest(&[Measurement {
        event_time: T,
        processed_time: T,
        kind: "system.unit".to_owned(),
        body: Some(json!({"n_restarts": 0})),
        attributes: json!({"record.attributes.unit": "sshd"}).as_object().unwrap().clone(),
    }]);
    let cookie = harness.login().await;

    // `t0` is the old type, `type` the new one, and the stale filter is for a key system.unit lacks.
    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=system.unit&t0=bms.status.cell&attr.record.attributes.cell=1",
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("sshd"), "the new type's rows must show: {}", reply.body);
}

/// **A filter must not be a one-way door.** With its own filter applied, a key's dropdown used to collapse
/// to the single value already chosen, so switching from cell 2 to cell 3 meant clearing the filter first.
#[tokio::test]
async fn a_filtered_attribute_still_offers_its_other_values() {
    let harness = harness();
    harness.ingest(&cells(2, 4));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&attr.record.attributes.cell=2",
    )
    .await;

    // The select for `cell` must still list every cell, with 2 marked.
    let select = reply
        .body
        .split(r#"name="attr.record.attributes.cell""#)
        .nth(1)
        .expect("the cell select")
        .split("</select>")
        .next()
        .expect("its end")
        .to_owned();
    for expected in ["1", "2", "3", "4"] {
        assert!(
            select.contains(&format!(r#"value="{expected}""#)),
            "cell {expected} is missing, so the filter is a one-way door: {select}"
        );
    }
    assert!(select.contains(r#"value="2" selected"#), "and 2 must be the current one: {select}");
}

/// Ticking two fields draws two plots — never two scales on one, which would invent a correlation.
#[tokio::test]
async fn two_chart_fields_render_two_plots() {
    let harness = harness();
    harness.ingest(&[
        Measurement {
            event_time: T,
            processed_time: T,
            kind: "c".to_owned(),
            body: Some(json!({"volts": 3.29, "ohms": 0.069})),
            attributes: json!({"cell": "1"}).as_object().unwrap().clone(),
        },
        Measurement {
            event_time: T + 1_000_000_000,
            processed_time: T,
            kind: "c".to_owned(),
            body: Some(json!({"volts": 3.30, "ohms": 0.070})),
            attributes: json!({"cell": "1"}).as_object().unwrap().clone(),
        },
    ]);
    let cookie = harness.login().await;

    let reply = explore(&harness, &cookie, "range=all&type=c&t0=c&field=volts&field=ohms").await;

    assert_eq!(reply.status, StatusCode::OK);
    // Two plots, each with its own heading and its own axis.
    assert!(reply.body.contains("<h2>volts</h2>"), "{}", reply.body);
    assert!(reply.body.contains("<h2>ohms</h2>"));
    assert_eq!(reply.body.matches("class=\"line\"").count(), 2, "one line per plot");
    // Three SVGs: the timeline plus one per field.
    assert_eq!(reply.body.matches("<svg").count(), 3);
}

/// The fields control is checkboxes, because a multi-select needs ctrl-click and a phone has none.
#[tokio::test]
async fn chart_fields_are_offered_as_checkboxes() {
    let harness = harness();
    harness.ingest(&cells(2, 1));
    let cookie = harness.login().await;

    let reply =
        explore(&harness, &cookie, "range=all&type=bms.status.cell&t0=bms.status.cell").await;

    assert!(reply.body.contains(r#"type="checkbox" name="field""#), "{}", reply.body);
    assert!(!reply.body.contains(r#"<select name="field""#));
}

/// "one line per" only appears when something is being charted — which is the clearest possible answer to
/// what it does — and it comes with a sentence saying so.
#[tokio::test]
async fn the_grouping_control_appears_only_when_it_would_do_something() {
    let harness = harness();
    harness.ingest(&cells(2, 3));
    let cookie = harness.login().await;

    let without =
        explore(&harness, &cookie, "range=all&type=bms.status.cell&t0=bms.status.cell").await;
    assert!(!without.body.contains(r#"name="group""#), "nothing to split yet: {}", without.body);

    let with = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts",
    )
    .await;
    assert!(with.body.contains(r#"name="group""#), "{}", with.body);
    assert!(with.body.contains("one line per"), "the label must say what it does");
    assert!(with.body.contains("class=\"hint\""), "and the hint must explain it");
}

/// With a type selected, each body leaf gets its own column and the attributes that are identical on every
/// row move out of the table — that restating of constants is what made the old table unreadable.
#[tokio::test]
async fn the_table_splits_body_leaves_into_columns_and_lifts_out_constants() {
    let harness = harness();
    harness.ingest(&cells(3, 2));
    let cookie = harness.login().await;

    let reply =
        explore(&harness, &cookie, "range=all&type=bms.status.cell&t0=bms.status.cell").await;

    // A column per body leaf, and the value in a plain cell rather than inside JSON.
    assert!(reply.body.contains("<th>voltage_volts</th>"), "{}", reply.body);
    assert!(!reply.body.contains(r#"{&quot;voltage_volts&quot;"#), "no raw JSON blob in a cell");
    // `cell` differs between rows, so it earns a column.
    assert!(reply.body.contains("<th>cell</th>"));

    // With one cell filtered, `cell` becomes constant and moves under the table instead.
    let filtered = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&attr.record.attributes.cell=1",
    )
    .await;
    assert!(filtered.body.contains("Same on every row shown"), "{}", filtered.body);
    assert!(filtered.body.contains("cell=1"));
    assert!(!filtered.body.contains("<th>cell</th>"), "a constant is not worth a column");
}

/// Without a type the rows are unrelated shapes, so a column per key would be mostly empty cells.
#[tokio::test]
async fn the_table_stays_compact_when_no_type_is_chosen() {
    let harness = harness();
    harness.ingest(&cells(2, 1));
    let cookie = harness.login().await;

    let reply = explore(&harness, &cookie, "range=all").await;
    assert!(reply.body.contains("<th>type</th>"), "{}", reply.body);
    assert!(reply.body.contains("<th>body</th>"));
}

/// The plots scroll rather than shrink, and the table labels its own cells — the two halves of being usable
/// on a phone.
#[tokio::test]
async fn the_page_carries_its_narrow_screen_affordances() {
    let harness = harness();
    harness.ingest(&cells(2, 1));
    let cookie = harness.login().await;

    let reply = explore(&harness, &cookie, "range=all").await;
    assert!(reply.body.contains(r#"name="viewport""#), "a viewport meta tag");
    assert!(reply.body.contains("class=\"plot-wrap\""), "a scrollable plot wrapper");
    assert!(reply.body.contains("data-label="), "cells that label themselves");
    assert!(reply.body.contains("@media(max-width:46rem)"), "and the card layout");
}

// ------------------------------------------------------- api keys (SPEC §13, §14.1)

#[tokio::test]
async fn the_keys_page_lists_and_issues() {
    let harness = harness();
    let cookie = harness.login().await;

    // The harness starts with one key, so it is already listed.
    let page = harness.get("/keys", Some(&cookie)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("<h2>issue a key</h2>"), "{}", page.body);
    assert!(page.body.contains("integration-test"), "the existing key's label: {}", page.body);

    let created = harness.post_form("/keys/create", "label=pi-7", Some(&cookie)).await;
    assert_eq!(created.status, StatusCode::OK, "the token is rendered, not redirected to");
    assert!(created.body.contains("mpk_"), "the token must be shown once: {}", created.body);
    assert!(created.body.contains("cannot be shown again"), "and said to be one-shot");
    assert!(created.body.contains("pi-7"));
}

/// **A token is shown once and never again.** Only its hash is stored, so a redirect would lose it — and a
/// token in a URL would land in history.
#[tokio::test]
async fn an_issued_token_is_not_repeated_on_the_next_load() {
    let harness = harness();
    let cookie = harness.login().await;

    let created = harness.post_form("/keys/create", "label=once", Some(&cookie)).await;
    let token = created
        .body
        .split("<code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("a token")
        .to_owned();
    assert!(token.starts_with("mpk_"), "{token}");

    let again = harness.get("/keys", Some(&cookie)).await;
    assert!(!again.body.contains(&token), "the token must not reappear: {}", again.body);
    assert!(!again.body.contains("cannot be shown again"));
}

/// The issued key must actually authenticate — a page that stored an unusable hash would look identical.
#[tokio::test]
async fn a_key_issued_from_the_page_works_on_the_v1_api() {
    let harness = harness();
    let cookie = harness.login().await;

    let created = harness.post_form("/keys/create", "label=device", Some(&cookie)).await;
    let token = created
        .body
        .split("<code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("a token")
        .to_owned();

    let reply = harness
        .send(
            Request::builder()
                .uri("/v1/measurements")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "the new key must be accepted");
}

/// Revoking deletes the row, so the next request carrying it is refused.
#[tokio::test]
async fn revoking_a_key_stops_it_working() {
    let harness = harness();
    let cookie = harness.login().await;
    let key_id = store::keys::list(&harness.read()).unwrap()[0].id.clone();

    let revoked = harness.post_form("/keys/delete", &format!("id={key_id}"), Some(&cookie)).await;
    assert_eq!(revoked.status, StatusCode::SEE_OTHER);
    assert!(store::keys::list(&harness.read()).unwrap().is_empty());

    // The harness's own key was the one revoked, so /v1 now refuses it.
    assert_eq!(harness.get_with_key("/v1/measurements").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_key_needs_a_label() {
    let harness = harness();
    let cookie = harness.login().await;
    let before = store::keys::list(&harness.read()).unwrap().len();

    for body in ["label=", "label=%20%20"] {
        let reply = harness.post_form("/keys/create", body, Some(&cookie)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "on {body:?}");
    }
    assert_eq!(store::keys::list(&harness.read()).unwrap().len(), before);
}

/// The keys pages are behind the session guard and the origin check like every other mutation.
#[tokio::test]
async fn the_keys_page_is_guarded() {
    let harness = harness();
    let cookie = harness.login().await;

    let anonymous = harness.get("/keys", None).await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(anonymous.location.as_deref(), Some("/login"));

    let forged = harness
        .post_from("/keys/create", "label=x", Some(&cookie), Some("http://localhost:3000"))
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert_eq!(store::keys::list(&harness.read()).unwrap().len(), 1, "nothing written");
}

// ------------------------------------------------------- fields in either half of the measurement

/// Measurements shaped like the real `detected-devices.wifi_bss`: the interesting identity (`ssid`) is a
/// body leaf, while `bssid` is an attribute.
fn wifi(rows: &[(&str, &str, f64)]) -> Vec<Measurement> {
    rows.iter()
        .enumerate()
        .map(|(i, (ssid, bssid, signal))| Measurement {
            event_time: T + i as i64 * 1_000_000_000,
            processed_time: T,
            kind: "detected-devices.wifi_bss".to_owned(),
            body: Some(json!({"ssid": ssid, "signal_dbm": signal, "security": "wpa3"})),
            attributes: json!({ "record.attributes.bssid": bssid }).as_object().unwrap().clone(),
        })
        .collect()
}

/// **The ask.** `ssid` lives in the body, so it used to be visible only in the table. It must be usable as
/// the series dimension, generically — nothing here is wifi-specific.
#[tokio::test]
async fn a_body_field_can_be_the_series_dimension() {
    let harness = harness();
    harness.ingest(&wifi(&[
        ("home", "aa", -60.0),
        ("cafe", "bb", -70.0),
        ("home", "cc", -50.0),
    ]));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=detected-devices.wifi_bss&t0=detected-devices.wifi_bss&field=signal_dbm&group=b:ssid",
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    // Two lines, labelled by SSID rather than by BSSID.
    assert_eq!(reply.body.matches("class=\"line\"").count(), 2, "{}", reply.body);
    let legend = reply.body.split("<ul class=\"legend\">").nth(1).expect("a legend");
    assert!(legend.contains(">cafe</a>"), "{legend}");
    assert!(legend.contains(">home</a>"), "{legend}");
}

/// The control offers both halves, so the reader never has to know which column a field sits in.
#[tokio::test]
async fn the_grouping_control_offers_body_leaves_and_attributes() {
    let harness = harness();
    harness.ingest(&wifi(&[("home", "aa", -60.0), ("cafe", "bb", -70.0)]));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=detected-devices.wifi_bss&t0=detected-devices.wifi_bss&field=signal_dbm",
    )
    .await;

    let select = reply.body.split(r#"name="group""#).nth(1).expect("the group select");
    assert!(select.contains(r#"value="b:ssid""#), "the body leaf: {select}");
    assert!(select.contains(r#"value="record.attributes.bssid""#), "the attribute: {select}");
}

/// Filtering by a body leaf, which is what makes the ">8 groups, narrow to see the rest" escape hatch work
/// for a body-grouped chart.
#[tokio::test]
async fn a_body_field_can_filter_the_view() {
    let harness = harness();
    harness.ingest(&wifi(&[("home", "aa", -60.0), ("cafe", "bb", -70.0)]));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=detected-devices.wifi_bss&t0=detected-devices.wifi_bss&body.ssid=home",
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("home"), "{}", reply.body);
    // `cafe` must be gone from the table. It is still offered in its own dropdown — that is the
    // one-way-door fix — so the check is on the row, not on the whole page.
    let rows = reply.body.split("<tbody>").nth(1).expect("a table body");
    assert!(!rows.contains("cafe"), "the filter must remove the other network: {rows}");
}

/// A body filter is offered as a control, and keeps offering its alternatives once applied.
#[tokio::test]
async fn a_filtered_body_field_still_offers_its_other_values() {
    let harness = harness();
    harness.ingest(&wifi(&[("home", "aa", -60.0), ("cafe", "bb", -70.0), ("work", "cc", -55.0)]));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=detected-devices.wifi_bss&t0=detected-devices.wifi_bss&body.ssid=cafe",
    )
    .await;

    let select = reply.body.split(r#"name="body.ssid""#).nth(1).expect("the ssid select");
    let select = select.split("</select>").next().expect("its end");
    for expected in ["home", "cafe", "work"] {
        assert!(select.contains(expected), "{expected} missing, so the filter is a one-way door: {select}");
    }
    assert!(select.contains(r#"value="cafe" selected"#), "{select}");
}

// ------------------------------------------------------- the full-page chart

/// The inline plot is a link to the readable version, which is what replaces horizontal scrolling in
/// portrait.
#[tokio::test]
async fn an_inline_chart_links_to_its_full_page_view() {
    let harness = harness();
    harness.ingest(&cells(4, 1));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts",
    )
    .await;

    assert!(reply.body.contains("/chart?"), "{}", reply.body);
    assert!(reply.body.contains("full size"), "and it says what it is for");
    // The filters travel with it, or the full view would show a different chart.
    assert!(reply.body.contains("field=voltage_volts"));
    assert!(reply.body.contains("type=bms.status.cell"));
}

/// The full-page view ships the same chart twice — one geometry for a phone, one for a desktop — because a
/// single `viewBox` cannot be legible at both widths.
#[tokio::test]
async fn the_full_page_chart_renders_both_geometries() {
    let harness = harness();
    harness.ingest(&cells(6, 1));
    let cookie = harness.login().await;

    let reply = harness
        .get(
            "/chart?range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts",
            Some(&cookie),
        )
        .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("class=\"plot wide\""), "{}", reply.body);
    assert!(reply.body.contains("class=\"plot narrow\""));
    assert_eq!(reply.body.matches("<svg").count(), 2, "exactly one pair, not one per breakpoint guess");
    assert!(reply.body.contains("back to the explorer"), "and a way back");
}

/// **Tapping a point shows the measurements behind it.** A point is an average over a bucket, so the link
/// carries that bucket's own window — not the whole visible range, which would be the same page again.
#[tokio::test]
async fn chart_points_link_to_the_rows_in_their_bucket() {
    let harness = harness();
    harness.ingest(&cells(6, 1));
    let cookie = harness.login().await;

    let reply = harness
        .get(
            "/chart?range=all&type=bms.status.cell&t0=bms.status.cell&field=voltage_volts",
            Some(&cookie),
        )
        .await;

    assert!(reply.body.contains("<a href=\"/?"), "the marks must be links: {}", reply.body);
    assert!(reply.body.contains("from="), "carrying a window");
    assert!(reply.body.contains("&amp;to="), "with both ends, xml-escaped");
    // `range=custom` so the explicit bounds decide the window rather than the preset overriding them.
    assert!(reply.body.contains("range=custom"), "{}", reply.body);

    // And following one actually reaches the table. Picked by `from=`, which only a mark link carries —
    // the nav and the back-link are also anchors, and grabbing the first one would test neither.
    let href = reply
        .body
        .split("<a href=\"")
        .find_map(|rest| {
            let href = rest.split('"').next()?;
            href.contains("from=").then(|| href.replace("&amp;", "&"))
        })
        .expect("a mark link carrying a bucket window");
    let followed = harness.get(&href, Some(&cookie)).await;
    assert_eq!(followed.status, StatusCode::OK, "the link must resolve: {href}");
    assert!(followed.body.contains("matching measurements"), "and land on the table: {href}");
}

/// With no field chosen the timeline is the chart, and it is just as clickable.
#[tokio::test]
async fn the_full_page_view_falls_back_to_the_timeline() {
    let harness = harness();
    harness.ingest(&cells(4, 1));
    let cookie = harness.login().await;

    let reply = harness.get("/chart?range=all", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("class=\"col\""), "columns, not a line: {}", reply.body);
}

/// The chart page is behind the session guard like every other page.
#[tokio::test]
async fn the_full_page_chart_requires_a_session() {
    let harness = harness();
    let reply = harness.get("/chart?range=all", None).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/login"));
}

/// Attribute keys and values go into a link's query string, and they are device-supplied — so they have to
/// be percent-encoded, or a key containing `&` would silently change what the link means.
#[tokio::test]
async fn link_parameters_are_percent_encoded() {
    let harness = harness();
    harness.ingest(&[Measurement {
        event_time: T,
        processed_time: T,
        kind: "t".to_owned(),
        body: Some(json!({"v": 1.0})),
        attributes: json!({"a&b=c": "x y"}).as_object().unwrap().clone(),
    }]);
    let cookie = harness.login().await;

    let reply =
        explore(&harness, &cookie, "range=all&type=t&t0=t&field=v&attr.a%26b%3Dc=x%20y").await;

    // The filter round-trips into the /chart link with its metacharacters encoded, not raw.
    let link = reply
        .body
        .split("href=\"/chart?")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a chart link")
        .to_owned();
    assert!(link.contains("a%26b%3Dc"), "the key must be encoded: {link}");
    assert!(!link.contains("a&b=c"), "raw metacharacters would change the link: {link}");
}

// ------------------------------------------------------- readability of the cells

/// Body and attributes render as indented `key: value` lines rather than stringified JSON.
#[tokio::test]
async fn structured_cells_render_as_yaml_not_json() {
    let harness = harness();
    harness.ingest(&cells(2, 1));
    let cookie = harness.login().await;

    // No type selected, so body and attributes are whole objects in one cell each.
    let reply = explore(&harness, &cookie, "range=all").await;

    assert!(reply.body.contains("class=\"yaml\""), "{}", reply.body);
    assert!(reply.body.contains("voltage_volts: 3.29"), "a key: value line: {}", reply.body);
    assert!(
        !reply.body.contains("{&quot;voltage_volts&quot;"),
        "no stringified JSON in a cell: {}",
        reply.body
    );
}

/// **Regression: `all` must include the newest row.** The window is applied as `event_time < to`, so a
/// window taken straight from the data's extent dropped the last row — every time, silently. With two rows
/// that is half the data; with a thousand it is invisible, which is the worse failure.
#[tokio::test]
async fn the_all_range_includes_the_newest_row() {
    let harness = harness();
    harness.ingest(&wifi(&[("first", "aa", -60.0), ("last", "bb", -70.0)]));
    let cookie = harness.login().await;

    let reply = explore(
        &harness,
        &cookie,
        "range=all&type=detected-devices.wifi_bss&t0=detected-devices.wifi_bss",
    )
    .await;

    let rows = reply.body.split("<tbody>").nth(1).expect("a table body");
    assert!(rows.contains("first"), "{rows}");
    assert!(rows.contains("last"), "the newest row must not be dropped: {rows}");
}

/// One measurement per day, told apart by its body, for the stepping tests.
fn days(markers: &[(&str, i64)]) -> Vec<Measurement> {
    markers
        .iter()
        .map(|(marker, event_time)| Measurement {
            event_time: *event_time,
            processed_time: *event_time,
            kind: "t".to_owned(),
            body: Some(json!({ "marker": marker })),
            attributes: serde_json::Map::new(),
        })
        .collect()
}

/// The `href` of the step link whose text is `text`, unescaped and ready to request.
fn step_link(body: &str, text: &str) -> Option<String> {
    let row = body.split("<p class=\"steps\">").nth(1)?.split("</p>").next()?;
    row.split("<a href=\"")
        .skip(1)
        .find(|link| link.contains(&format!(">{text}</a>")))
        .and_then(|link| link.split('"').next())
        .map(|href| href.replace("&amp;", "&"))
}

/// **Stepping back and forward through a 24-hour view**, end to end: the table under each step lists that
/// day's rows and only those, and a step forward from the day before returns to where it started.
#[tokio::test]
async fn the_window_steps_back_and_forward_a_day_at_a_time() {
    const DAY: i64 = 86_400_000_000_000;
    const HOUR: i64 = 3_600_000_000_000;
    let harness = harness();
    harness.ingest(&days(&[("today-row", T - 2 * HOUR), ("yesterday-row", T - DAY - 2 * HOUR)]));
    let cookie = harness.login().await;
    let table = |body: &str| body.split("<tbody>").nth(1).unwrap_or_default().to_owned();

    let today = explore(&harness, &cookie, &format!("range=24h&to={T}")).await;
    assert!(table(&today.body).contains("today-row"), "{}", today.body);
    assert!(!table(&today.body).contains("yesterday-row"), "{}", today.body);

    let back = step_link(&today.body, "← 24 hours earlier").expect("a step back");
    let yesterday = harness.get(&back, Some(&cookie)).await;
    assert_eq!(yesterday.status, StatusCode::OK);
    assert!(table(&yesterday.body).contains("yesterday-row"), "{}", yesterday.body);
    assert!(!table(&yesterday.body).contains("today-row"), "{}", yesterday.body);

    let forward = step_link(&yesterday.body, "24 hours later →").expect("a step forward");
    assert!(forward.contains(&format!("to={T}")), "back to where it started: {forward}");
    assert!(step_link(&yesterday.body, "latest").is_some(), "and a way back to now");
}

/// The live view has nothing later, so it offers only the step back.
#[tokio::test]
async fn the_live_view_offers_only_the_step_back() {
    let harness = harness();
    let cookie = harness.login().await;
    let reply = explore(&harness, &cookie, "range=24h").await;
    assert!(step_link(&reply.body, "← 24 hours earlier").is_some(), "{}", reply.body);
    assert!(step_link(&reply.body, "24 hours later →").is_none(), "{}", reply.body);
    assert!(step_link(&reply.body, "latest").is_none(), "{}", reply.body);
}

/// **Changing a filter keeps the window.** The filter row is a form, and before it carried the bounds,
/// ticking a field after stepping back two days jumped the reader to now.
#[tokio::test]
async fn the_filter_form_carries_the_window() {
    let harness = harness();
    let cookie = harness.login().await;
    let reply = explore(&harness, &cookie, &format!("range=24h&to={T}")).await;
    let form = reply.body.split("<form method=\"get\" action=\"/\" class=\"filters\">").nth(1).unwrap();
    let form = form.split("</form>").next().unwrap();
    assert!(form.contains(&format!("<input type=\"hidden\" name=\"to\" value=\"{T}\">")), "{form}");
}

/// The full-size chart steps too, and its links stay on the chart page.
#[tokio::test]
async fn the_full_size_chart_steps_on_its_own_page() {
    let harness = harness();
    let cookie = harness.login().await;
    let reply = harness.get(&format!("/chart?range=24h&to={T}"), Some(&cookie)).await;
    let back = step_link(&reply.body, "← 24 hours earlier").expect("a step back");
    assert!(back.starts_with("/chart?"), "{back}");
}

/// **Regression: the `all` window must not depend on the value filters.** If it did, filtering to one SSID
/// would shrink the window to that SSID's rows — rescaling the axis on every filter change, and closing the
/// one-way door again from behind, since a widened facet would have no other rows in range to offer.
#[tokio::test]
async fn the_all_window_does_not_shrink_when_a_value_filter_is_applied() {
    let harness = harness();
    harness.ingest(&wifi(&[("home", "aa", -60.0), ("cafe", "bb", -70.0), ("work", "cc", -50.0)]));
    let cookie = harness.login().await;

    let window_of = |body: &str| -> String {
        body.split("<h2>measurements over time — ")
            .nth(1)
            .and_then(|rest| rest.split("</h2>").next())
            .expect("the window heading")
            .to_owned()
    };

    let unfiltered =
        explore(&harness, &cookie, "range=all&type=detected-devices.wifi_bss&t0=detected-devices.wifi_bss")
            .await;
    let filtered = explore(
        &harness,
        &cookie,
        "range=all&type=detected-devices.wifi_bss&t0=detected-devices.wifi_bss&body.ssid=cafe",
    )
    .await;

    assert_eq!(
        window_of(&unfiltered.body),
        window_of(&filtered.body),
        "the window must be a property of the type and range, not of the filters"
    );
}

#[tokio::test]
async fn an_empty_range_says_so_rather_than_rendering_a_broken_plot() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = explore(&harness, &cookie, "range=1h").await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("no measurements in range"), "{}", reply.body);
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

// ------------------------------------------------------- passkeys (SPEC §14.10)

/// A software authenticator shaped like the phone app's (sashee/iroh-webview-app): an ES256 key, `none`
/// attestation, a sign counter that stays 0, user present and verified, and the full set of fields its
/// `toJSON` sends. The server is driven by the same thing the phone will drive it with.
mod authenticator {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use p256::pkcs8::EncodePublicKey as _;
    use sha2::{Digest, Sha256};

    pub struct Authenticator {
        key: SigningKey,
        pub credential_id: [u8; 16],
    }

    impl Authenticator {
        pub fn new(seed: u8) -> Self {
            Self::with_id(seed, [seed.wrapping_add(100); 16])
        }

        /// A key of its own presented under `credential_id` — for an impostor claiming a stored passkey.
        pub fn with_id(seed: u8, credential_id: [u8; 16]) -> Self {
            Self { key: SigningKey::from_bytes(&[seed; 32].into()).unwrap(), credential_id }
        }

        /// Answers sign-in `options` from a page at `origin`, signing for `rp_id` and naming `user_handle` —
        /// which the authenticator stored at registration, as base64url.
        pub fn sign(
            &self,
            options: &serde_json::Value,
            origin: &str,
            rp_id: &str,
            user_handle: &str,
        ) -> String {
            let client_data = serde_json::json!({
                "type": "webauthn.get",
                "challenge": options["challenge"],
                "origin": origin,
                "crossOrigin": false,
            })
            .to_string();
            let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
            auth_data.push(0x01 | 0x04); // user present, user verified
            auth_data.extend(0u32.to_be_bytes()); // the phone app's counter never moves
            let mut signed = auth_data.clone();
            signed.extend(Sha256::digest(client_data.as_bytes()));
            let signature: Signature = self.key.sign(&signed);

            serde_json::json!({
                "id": B64.encode(self.credential_id),
                "rawId": B64.encode(self.credential_id),
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "clientExtensionResults": {},
                "response": {
                    "clientDataJSON": B64.encode(&client_data),
                    "authenticatorData": B64.encode(&auth_data),
                    "signature": B64.encode(signature.to_der().as_bytes()),
                    "userHandle": user_handle,
                },
            })
            .to_string()
        }

        /// Answers creation `options` from a page at `origin`, signing for `rp_id` — as the page's script
        /// would post it. `rp_id` is a parameter so a test can sign for the wrong one.
        pub fn register(&self, options: &serde_json::Value, origin: &str, rp_id: &str) -> String {
            let client_data = serde_json::json!({
                "type": "webauthn.create",
                "challenge": options["challenge"],
                "origin": origin,
                "crossOrigin": false,
            })
            .to_string();
            let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
            auth_data.push(0x01 | 0x04 | 0x40); // user present, user verified, attested credential data
            auth_data.extend(0u32.to_be_bytes());
            auth_data.extend([0u8; 16]); // AAGUID
            auth_data.extend((self.credential_id.len() as u16).to_be_bytes());
            auth_data.extend(self.credential_id);
            auth_data.extend(self.cose_key());

            let mut attestation = Vec::new();
            head(&mut attestation, 5, 3);
            text(&mut attestation, "fmt");
            text(&mut attestation, "none");
            text(&mut attestation, "attStmt");
            head(&mut attestation, 5, 0);
            text(&mut attestation, "authData");
            bytes(&mut attestation, &auth_data);

            let public_key = self.key.verifying_key().to_public_key_der().unwrap();
            serde_json::json!({
                "id": B64.encode(self.credential_id),
                "rawId": B64.encode(self.credential_id),
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "clientExtensionResults": {},
                "response": {
                    "clientDataJSON": B64.encode(&client_data),
                    "attestationObject": B64.encode(&attestation),
                    "authenticatorData": B64.encode(&auth_data),
                    "publicKey": B64.encode(public_key.as_bytes()),
                    "publicKeyAlgorithm": -7,
                    "transports": ["internal"],
                },
            })
            .to_string()
        }

        /// The public key as COSE: EC2, ES256, P-256, x and y.
        fn cose_key(&self) -> Vec<u8> {
            let point = self.key.verifying_key().to_encoded_point(false);
            let mut out = Vec::new();
            head(&mut out, 5, 5);
            out.extend([0x01, 0x02, 0x03, 0x26, 0x20, 0x01]); // kty: EC2, alg: -7, crv: P-256
            out.push(0x21);
            bytes(&mut out, point.x().unwrap());
            out.push(0x22);
            bytes(&mut out, point.y().unwrap());
            out
        }
    }

    fn head(out: &mut Vec<u8>, major: u8, n: usize) {
        match n {
            0..=23 => out.push(major << 5 | n as u8),
            24..=0xff => out.extend([major << 5 | 24, n as u8]),
            _ => {
                out.push(major << 5 | 25);
                out.extend((n as u16).to_be_bytes());
            }
        }
    }

    fn text(out: &mut Vec<u8>, s: &str) {
        head(out, 3, s.len());
        out.extend(s.as_bytes());
    }

    fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        head(out, 2, b.len());
        out.extend(b);
    }
}

use authenticator::Authenticator;

/// The host and origin the phone app reaches this page at.
const PHONE_HOST: &str = "6c4b9e.localhost:24038";
const PHONE_ORIGIN: &str = "http://6c4b9e.localhost:24038";

impl Harness {
    /// A `GET` sent to `host`, as a browser at that address would send it.
    async fn get_at(&self, host: &str, uri: &str, cookie: &str) -> Reply {
        let request = Request::builder()
            .uri(uri)
            .header(header::HOST, host)
            .header(header::COOKIE, format!("{COOKIE}={cookie}"));
        self.send(request.body(Body::empty()).unwrap()).await
    }

    /// A same-origin form `POST` to `host`: `Origin` and `Host` agree, as the origin check requires.
    async fn post_at(&self, host: &str, uri: &str, fields: &[(&str, &str)], cookie: &str) -> Reply {
        let fields: Vec<(String, String)> =
            fields.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        let body = monitoring_platform::web::html::query_string("", &fields);
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, host)
            .header(header::ORIGIN, format!("http://{host}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("{COOKIE}={cookie}"));
        self.send(request.body(Body::from(body.trim_start_matches('?').to_owned())).unwrap()).await
    }

    fn passkey_count(&self) -> i64 {
        self.read().query_row("SELECT count(*) FROM web_passkey", [], |r| r.get(0)).unwrap()
    }

    /// Opens the account page at `host` and returns the registration options it embeds.
    async fn passkey_options(&self, host: &str, cookie: &str) -> serde_json::Value {
        let page = self.get_at(host, "/account", cookie).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let json = page
            .body
            .split("<script type=\"application/json\" id=\"passkey-options\">")
            .nth(1)
            .and_then(|rest| rest.split("</script>").next())
            .unwrap_or_else(|| panic!("no passkey options on the page: {}", page.body));
        serde_json::from_str(json).unwrap()
    }
}

/// **The whole registration, end to end.** The account page at the phone's address embeds options for
/// that address; an authenticator shaped like the phone app's answers them; the passkey is stored against
/// the phone's host and listed — and the users page counts it.
#[tokio::test]
async fn a_passkey_is_registered_from_the_account_page() {
    let harness = harness();
    let cookie = harness.login().await;
    let options = harness.passkey_options(PHONE_HOST, &cookie).await;
    assert_eq!(options["rp"]["id"], "6c4b9e.localhost", "the RP ID is the page's own host");

    let response = Authenticator::new(1).register(&options, PHONE_ORIGIN, "6c4b9e.localhost");
    let reply = harness
        .post_at(PHONE_HOST, "/account/passkeys/create", &[("label", "phone"), ("response", &response)], &cookie)
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.location.as_deref(), Some("/account"));

    let page = harness.get_at(PHONE_HOST, "/account", &cookie).await;
    assert!(page.body.contains("data-label=\"name\">phone</td>"), "{}", page.body);
    assert!(page.body.contains("6c4b9e.localhost"), "{}", page.body);
    let users = harness.get_at(PHONE_HOST, "/users", &cookie).await;
    assert!(users.body.contains("data-label=\"signs in with\">1 passkey</td>"), "{}", users.body);
}

/// A second registration from the same site sends the first passkey as `excludeCredentials`, so the
/// authenticator that holds it says so instead of quietly replacing it.
#[tokio::test]
async fn the_passkeys_already_on_a_site_are_excluded() {
    let harness = harness();
    let cookie = harness.login().await;
    let options = harness.passkey_options(PHONE_HOST, &cookie).await;
    let response = Authenticator::new(1).register(&options, PHONE_ORIGIN, "6c4b9e.localhost");
    harness
        .post_at(PHONE_HOST, "/account/passkeys/create", &[("label", "phone"), ("response", &response)], &cookie)
        .await;

    let again = harness.passkey_options(PHONE_HOST, &cookie).await;
    assert_eq!(again["excludeCredentials"].as_array().unwrap().len(), 1, "{again}");
    // Another site's passkey could never be on this authenticator, so it is not sent.
    let elsewhere = harness.passkey_options("localhost:8080", &cookie).await;
    assert!(elsewhere["excludeCredentials"].as_array().unwrap().is_empty(), "{elsewhere}");
}

/// The signed client data must name the page the form was posted from. A response produced for another
/// origin — or signed for another site's RP ID — is refused and stores nothing.
#[tokio::test]
async fn a_response_for_another_origin_or_site_is_refused() {
    let harness = harness();
    let cookie = harness.login().await;
    for (origin, rp_id) in [
        ("http://evil.localhost:24038", "6c4b9e.localhost"),
        (PHONE_ORIGIN, "evil.localhost"),
        ("http://6c4b9e.localhost:9999", "6c4b9e.localhost"),
    ] {
        let options = harness.passkey_options(PHONE_HOST, &cookie).await;
        let response = Authenticator::new(1).register(&options, origin, rp_id);
        let reply = harness
            .post_at(PHONE_HOST, "/account/passkeys/create", &[("label", "x"), ("response", &response)], &cookie)
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{origin} / {rp_id}: {}", reply.body);
        assert!(reply.body.contains("could not be verified"), "{}", reply.body);
    }
    assert_eq!(harness.passkey_count(), 0);
}

/// A challenge answers one registration. The same response posted twice adds one passkey.
#[tokio::test]
async fn a_registration_response_cannot_be_replayed() {
    let harness = harness();
    let cookie = harness.login().await;
    let options = harness.passkey_options(PHONE_HOST, &cookie).await;
    let response = Authenticator::new(1).register(&options, PHONE_ORIGIN, "6c4b9e.localhost");
    let fields = [("label", "phone"), ("response", response.as_str())];

    let first = harness.post_at(PHONE_HOST, "/account/passkeys/create", &fields, &cookie).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER);
    let second = harness.post_at(PHONE_HOST, "/account/passkeys/create", &fields, &cookie).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST, "{}", second.body);
    assert!(second.body.contains("expired or was already used"), "{}", second.body);
    assert_eq!(harness.passkey_count(), 1);
}

/// A ceremony started on one user's account cannot be finished on another's: the passkey would carry the
/// first user's handle, and sign them in rather than the account it was stored on.
#[tokio::test]
async fn a_ceremony_cannot_be_finished_by_another_user() {
    let harness = harness();
    let mine = harness.login().await;
    {
        let conn = store::open_write_existing(&harness.db).unwrap();
        store::users::insert(&conn, "other", T).unwrap();
    }
    let theirs = harness.login_as("other").await;

    let options = harness.passkey_options(PHONE_HOST, &mine).await;
    let response = Authenticator::new(1).register(&options, PHONE_ORIGIN, "6c4b9e.localhost");
    let reply = harness
        .post_at(PHONE_HOST, "/account/passkeys/create", &[("label", "x"), ("response", &response)], &theirs)
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(harness.passkey_count(), 0);
}

/// Browsers refuse WebAuthn on an IP address, so the page reached at `127.0.0.1` starts no ceremony and
/// links to the same page under `localhost` instead.
#[tokio::test]
async fn on_an_ip_address_the_page_points_to_localhost() {
    let harness = harness();
    let cookie = harness.login().await;
    let page = harness.get_at("127.0.0.1:8080", "/account", &cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains("passkey-options"), "{}", page.body);
    assert!(page.body.contains("href=\"http://localhost:8080/account\""), "{}", page.body);
}

/// One of two passkeys can be removed. (The last one cannot: see `the_last_passkey_is_kept`.)
#[tokio::test]
async fn a_passkey_can_be_removed() {
    let harness = harness();
    let cookie = harness.login().await;
    let authenticator = Authenticator::new(1);
    harness.register_passkey(PHONE_HOST, &cookie, &authenticator).await;
    harness.register_passkey(PHONE_HOST, &cookie, &Authenticator::new(2)).await;
    assert_eq!(harness.passkey_count(), 2);

    use base64::Engine as _;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(authenticator.credential_id);
    let reply =
        harness.post_at(PHONE_HOST, "/account/passkeys/delete", &[("credential", &id)], &cookie).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(harness.passkey_count(), 1);
}

/// The username lands in the page's embedded JSON. A `</script>` in it must not end the element early.
#[tokio::test]
async fn the_embedded_options_cannot_close_their_script_element() {
    let harness = harness();
    {
        let conn = store::open_write_existing(&harness.db).unwrap();
        store::users::insert(&conn, "a</script><b>", T).unwrap();
    }
    let cookie = harness.login_as("a</script><b>").await;
    // Still parses: nothing ended the JSON early.
    let options = harness.passkey_options(PHONE_HOST, &cookie).await;
    assert_eq!(options["user"]["name"], "a</script><b>");
}

/// Both passkey routes are behind the origin check like every other `POST`: a page on another port cannot
/// add a passkey to the signed-in account — which would be a way in that outlives the session — or remove
/// one.
#[tokio::test]
async fn the_passkey_routes_are_origin_checked() {
    let harness = harness();
    let cookie = harness.login().await;
    for (path, body) in
        [("/account/passkeys/create", "label=x&response=%7B%7D"), ("/account/passkeys/delete", "credential=AA")]
    {
        let forged = harness.post_from(path, body, Some(&cookie), Some("http://localhost:3000")).await;
        assert_eq!(forged.status, StatusCode::FORBIDDEN, "{path}");
    }
}

// ------------------------------------------------------- signing in with a passkey (SPEC §14.10)

impl Harness {
    /// Registers `authenticator`'s passkey on the account page at `host`, returning the user handle the
    /// authenticator stores with it.
    async fn register_passkey(&self, host: &str, cookie: &str, authenticator: &Authenticator) -> String {
        let options = self.passkey_options(host, cookie).await;
        let rp_id = host.split(':').next().unwrap();
        let response = authenticator.register(&options, &format!("http://{host}"), rp_id);
        let reply = self
            .post_at(host, "/account/passkeys/create", &[("label", "phone"), ("response", &response)], cookie)
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "precondition: registered: {}", reply.body);
        options["user"]["id"].as_str().unwrap().to_owned()
    }

    /// The login page at `host`, signed out.
    async fn login_page_at(&self, host: &str) -> Reply {
        let request = Request::builder().uri("/login").header(header::HOST, host);
        self.send(request.body(Body::empty()).unwrap()).await
    }

    /// The sign-in options the login page at `host` embeds.
    async fn sign_in_options(&self, host: &str) -> serde_json::Value {
        let page = self.login_page_at(host).await;
        let json = page
            .body
            .split("<script type=\"application/json\" id=\"passkey-options\">")
            .nth(1)
            .and_then(|rest| rest.split("</script>").next())
            .unwrap_or_else(|| panic!("no passkey options on the login page: {}", page.body));
        serde_json::from_str(json).unwrap()
    }

    /// Posts a passkey sign-in from the page at `host`, with no session.
    async fn passkey_sign_in(&self, host: &str, response: &str) -> Reply {
        let body = monitoring_platform::web::html::query_string("", &[("response".to_owned(), response.to_owned())]);
        let request = Request::builder()
            .method("POST")
            .uri("/login/passkey")
            .header(header::HOST, host)
            .header(header::ORIGIN, format!("http://{host}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.send(request.body(Body::from(body.trim_start_matches('?').to_owned())).unwrap()).await
    }
}

/// **The whole sign-in, end to end.** A passkey registered from the phone's address signs in there: the
/// login page offers a discoverable ceremony for that host, the authenticator answers it, and the response is
/// a session that opens the pages — while the account page records when the passkey was used.
#[tokio::test]
async fn a_registered_passkey_signs_in() {
    let harness = harness();
    let cookie = harness.login().await;
    let authenticator = Authenticator::new(1);
    let handle = harness.register_passkey(PHONE_HOST, &cookie, &authenticator).await;

    let options = harness.sign_in_options(PHONE_HOST).await;
    assert_eq!(options["rpId"], "6c4b9e.localhost");
    let response = authenticator.sign(&options, PHONE_ORIGIN, "6c4b9e.localhost", &handle);
    let reply = harness.passkey_sign_in(PHONE_HOST, &response).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.location.as_deref(), Some("/"));
    let session = reply.session().expect("a passkey sign-in sets a session cookie");

    let page = harness.get_at(PHONE_HOST, "/account", &session).await;
    assert_eq!(page.status, StatusCode::OK, "the new session opens the pages");
    assert!(!page.body.contains("never"), "the sign-in is recorded as the passkey's last use: {}", page.body);
}

/// Every way a sign-in can be wrong is refused with `401`, sets no cookie, and leaves the login page up.
#[tokio::test]
async fn a_passkey_sign_in_is_refused_when_anything_is_wrong() {
    let harness = harness();
    let cookie = harness.login().await;
    let authenticator = Authenticator::new(1);
    let handle = harness.register_passkey(PHONE_HOST, &cookie, &authenticator).await;
    let impostor = Authenticator::with_id(2, authenticator.credential_id);
    let stranger = Authenticator::new(3);
    let other_handle = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7u8; 64]);

    type Case<'a> = (&'a str, &'a Authenticator, &'a str, &'a str, &'a str, &'a str);
    let cases: [Case; 6] = [
        ("signed for another origin", &authenticator, "http://evil.localhost:24038", "6c4b9e.localhost", &handle, "could not be verified"),
        ("signed for another site", &authenticator, PHONE_ORIGIN, "evil.localhost", &handle, "could not be verified"),
        ("signed with another key", &impostor, PHONE_ORIGIN, "6c4b9e.localhost", &handle, "could not be verified"),
        ("under another user's handle", &authenticator, PHONE_ORIGIN, "6c4b9e.localhost", &other_handle, "could not be verified"),
        ("from a passkey never registered", &stranger, PHONE_ORIGIN, "6c4b9e.localhost", &handle, "not registered here"),
        ("from another port", &authenticator, "http://6c4b9e.localhost:9999", "6c4b9e.localhost", &handle, "could not be verified"),
    ];
    for (case, who, origin, rp_id, user_handle, message) in cases {
        let options = harness.sign_in_options(PHONE_HOST).await;
        let reply = harness.passkey_sign_in(PHONE_HOST, &who.sign(&options, origin, rp_id, user_handle)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{case}: {}", reply.body);
        assert!(reply.session().is_none(), "{case} set a cookie");
        assert!(reply.body.contains(message), "{case}: {}", reply.body);
    }
}

/// A passkey registered at one address is refused at another — here the laptop's `localhost` presenting the
/// phone's passkey, which the authenticator signed for the phone's host.
#[tokio::test]
async fn a_passkey_is_only_good_at_the_address_it_was_registered_from() {
    let harness = harness();
    let cookie = harness.login().await;
    let authenticator = Authenticator::new(1);
    let handle = harness.register_passkey(PHONE_HOST, &cookie, &authenticator).await;

    let options = harness.sign_in_options("localhost:8080").await;
    let response = authenticator.sign(&options, "http://localhost:8080", "6c4b9e.localhost", &handle);
    let reply = harness.passkey_sign_in("localhost:8080", &response).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert!(reply.body.contains("another address"), "{}", reply.body);
}

/// A challenge answers one sign-in. The same signed response posted twice signs in once.
#[tokio::test]
async fn a_sign_in_response_cannot_be_replayed() {
    let harness = harness();
    let cookie = harness.login().await;
    let authenticator = Authenticator::new(1);
    let handle = harness.register_passkey(PHONE_HOST, &cookie, &authenticator).await;

    let options = harness.sign_in_options(PHONE_HOST).await;
    let response = authenticator.sign(&options, PHONE_ORIGIN, "6c4b9e.localhost", &handle);
    assert_eq!(harness.passkey_sign_in(PHONE_HOST, &response).await.status, StatusCode::SEE_OTHER);
    let again = harness.passkey_sign_in(PHONE_HOST, &response).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{}", again.body);
    assert!(again.body.contains("expired or was already used"), "{}", again.body);
}

/// A passkey removed on the account page stops signing in, though the device still holds it — and says why.
#[tokio::test]
async fn a_removed_passkey_no_longer_signs_in() {
    let harness = harness();
    let cookie = harness.login().await;
    let authenticator = Authenticator::new(1);
    let handle = harness.register_passkey(PHONE_HOST, &cookie, &authenticator).await;
    harness.register_passkey(PHONE_HOST, &cookie, &Authenticator::new(2)).await;
    use base64::Engine as _;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(authenticator.credential_id);
    let removed = harness.post_at(PHONE_HOST, "/account/passkeys/delete", &[("credential", &id)], &cookie).await;
    assert_eq!(removed.status, StatusCode::SEE_OTHER, "precondition: removed");

    let options = harness.sign_in_options(PHONE_HOST).await;
    let reply = harness
        .passkey_sign_in(PHONE_HOST, &authenticator.sign(&options, PHONE_ORIGIN, "6c4b9e.localhost", &handle))
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.body.contains("not registered here"), "{}", reply.body);
}

/// The login page offers the passkey button at a loopback name and, at `127.0.0.1`, a link to one instead —
/// the sign-in token form being there either way.
#[tokio::test]
async fn the_login_page_offers_a_passkey_where_one_can_be_used() {
    let harness = harness();
    let here = harness.login_page_at(PHONE_HOST).await;
    assert!(here.body.contains("sign in with a passkey"), "{}", here.body);
    assert!(here.body.contains("name=\"token\""));

    let ip = harness.login_page_at("127.0.0.1:8080").await;
    assert!(!ip.body.contains("passkey-options"), "{}", ip.body);
    assert!(ip.body.contains("href=\"http://localhost:8080/login\""), "{}", ip.body);
    assert!(ip.body.contains("name=\"token\""));
}

/// The sign-in route is behind the origin check like `/login` itself: a page on another port cannot sign
/// the browser into this one.
#[tokio::test]
async fn the_passkey_sign_in_route_is_origin_checked() {
    let harness = harness();
    let forged = harness.post_from("/login/passkey", "response=%7B%7D", None, Some("http://localhost:3000")).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
}

// ------------------------------------------------------- the account's sign-in token (SPEC §14.7)

/// **A second device, end to end.** Signed in on one, the user issues a token, pastes it into the other, and
/// adds a passkey there.
#[tokio::test]
async fn a_token_issued_on_the_account_page_signs_in_another_device() {
    let harness = harness();
    let cookie = harness.login().await;

    let account = harness.post_at(PHONE_HOST, "/account/tokens/create", &[], &cookie).await;
    assert_eq!(account.status, StatusCode::OK, "{}", account.body);
    let token = issued_secret(&account.body).expect("the token, shown once");

    let other_device = harness.post_form("/login", &token_field(&token), None).await;
    assert_eq!(other_device.status, StatusCode::SEE_OTHER, "{}", other_device.body);
    assert_eq!(other_device.location.as_deref(), Some("/account"));
    let theirs = other_device.session().expect("a session for the new device");
    harness.register_passkey(PHONE_HOST, &theirs, &Authenticator::new(1)).await;
    assert_eq!(harness.passkey_count(), 1);
}

/// The page says a token is waiting, and until when, and offers to delete it; deleted, it signs nobody in.
#[tokio::test]
async fn a_waiting_token_is_shown_and_can_be_deleted() {
    let harness = harness();
    let cookie = harness.login().await;
    let none = harness.get_at(PHONE_HOST, "/account", &cookie).await;
    assert!(!none.body.contains("/account/tokens/delete"), "nothing to delete yet: {}", none.body);
    assert!(none.body.contains("issue a sign-in token"), "{}", none.body);

    let token = harness.issue_token(USER);
    let waiting = harness.get_at(PHONE_HOST, "/account", &cookie).await;
    assert!(waiting.body.contains("A sign-in token you issued works until"), "{}", waiting.body);
    assert!(!waiting.body.contains(&token), "only shown when issued: {}", waiting.body);

    let deleted = harness.post_at(PHONE_HOST, "/account/tokens/delete", &[], &cookie).await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert_eq!(harness.token_count(), 0);
    assert_eq!(harness.post_form("/login", &token_field(&token), None).await.status, StatusCode::UNAUTHORIZED);
}

/// Issuing again replaces the waiting token, so one that went astray is voided by issuing another.
#[tokio::test]
async fn issuing_again_voids_the_earlier_token() {
    let harness = harness();
    let cookie = harness.login().await;
    let first = issued_secret(&harness.post_at(PHONE_HOST, "/account/tokens/create", &[], &cookie).await.body).unwrap();
    let second = issued_secret(&harness.post_at(PHONE_HOST, "/account/tokens/create", &[], &cookie).await.body).unwrap();

    assert_eq!(harness.token_count(), 1);
    assert_eq!(harness.post_form("/login", &token_field(&first), None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.post_form("/login", &token_field(&second), None).await.status, StatusCode::SEE_OTHER);
}

/// The account page issues and deletes only its own user's token.
#[tokio::test]
async fn the_account_page_touches_only_your_own_token() {
    let harness = harness();
    {
        let conn = store::open_write_existing(&harness.db).unwrap();
        store::users::insert(&conn, "other", T).unwrap();
    }
    let theirs = harness.issue_token("other");
    let cookie = harness.login().await;

    harness.post_at(PHONE_HOST, "/account/tokens/create", &[], &cookie).await;
    harness.post_at(PHONE_HOST, "/account/tokens/delete", &[], &cookie).await;

    let left: Vec<String> =
        store::login_tokens::list(&harness.read()).unwrap().into_iter().map(|t| t.username).collect();
    assert_eq!(left, vec!["other".to_owned()]);
    assert_eq!(harness.post_form("/login", &token_field(&theirs), None).await.status, StatusCode::SEE_OTHER);
}

/// **The lockout guard, through the page.** The last passkey is the only way in from the page, and stays —
/// though one of two can go.
#[tokio::test]
async fn the_last_passkey_is_kept() {
    let harness = harness();
    let cookie = harness.login().await;
    let (first, second) = (Authenticator::new(1), Authenticator::new(2));
    harness.register_passkey(PHONE_HOST, &cookie, &first).await;
    harness.register_passkey(PHONE_HOST, &cookie, &second).await;

    use base64::Engine as _;
    let id = |a: &Authenticator| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(a.credential_id);
    let one = harness.post_at(PHONE_HOST, "/account/passkeys/delete", &[("credential", &id(&first))], &cookie).await;
    assert_eq!(one.status, StatusCode::SEE_OTHER);
    let account = harness.get_at(PHONE_HOST, "/account", &cookie).await;
    assert!(!account.body.contains("/account/passkeys/delete"), "the only way in has no remove button");

    let last =
        harness.post_at(PHONE_HOST, "/account/passkeys/delete", &[("credential", &id(&second))], &cookie).await;
    assert_eq!(last.status, StatusCode::BAD_REQUEST, "{}", last.body);
    assert!(last.body.contains("your only way to sign in"), "{}", last.body);
    assert_eq!(harness.passkey_count(), 1);
}

#[tokio::test]
async fn the_token_routes_are_origin_checked() {
    let harness = harness();
    let cookie = harness.login().await;
    for path in ["/account/tokens/create", "/account/tokens/delete"] {
        let forged = harness.post_from(path, "", Some(&cookie), Some("http://localhost:3000")).await;
        assert_eq!(forged.status, StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(harness.token_count(), 0, "nothing issued");
}
