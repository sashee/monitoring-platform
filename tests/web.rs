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
            "username=intruder&password=whatever",
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
        harness.post_from("/users/create", "username=x&password=y", Some(&cookie), None).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(harness.users(), vec![USER.to_owned()]);
}

/// The check runs **before** the credentials are even looked at, which is what makes it a defence rather
/// than a second opinion: a forged login attempt is refused as forged, not as wrong.
#[tokio::test]
async fn login_itself_is_origin_checked() {
    let harness = harness();

    let reply = harness
        .post_from(
            "/login",
            &format!("username={USER}&password={PASSWORD}"),
            None,
            Some("http://evil.example"),
        )
        .await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN, "not 303, and not 401");
    assert!(reply.session().is_none());
    assert_eq!(harness.session_count(), 0);
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

#[tokio::test]
async fn a_user_can_be_created_and_then_log_in() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply =
        harness.post_form("/users/create", "username=second&password=another-long-one", Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/users"));
    assert!(harness.users().contains(&"second".to_owned()));

    // The real check: the stored hash is one the login path accepts.
    let logged_in = harness
        .post_form("/login", "username=second&password=another-long-one", None)
        .await;
    assert_eq!(logged_in.status, StatusCode::SEE_OTHER);
    assert!(logged_in.session().is_some());
}

/// A duplicate is the operator's typo, so it is a message on the page rather than a 500.
#[tokio::test]
async fn a_duplicate_username_is_reported_not_crashed() {
    let harness = harness();
    let cookie = harness.login().await;

    let reply = harness
        .post_form("/users/create", &format!("username={USER}&password=x"), Some(&cookie))
        .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("already exists"), "{}", reply.body);
    assert_eq!(harness.users().len(), 1);
}

#[tokio::test]
async fn a_user_needs_both_a_name_and_a_password() {
    let harness = harness();
    let cookie = harness.login().await;

    for body in ["username=&password=x", "username=x&password=", "username=%20%20&password=x"] {
        let reply = harness.post_form("/users/create", body, Some(&cookie)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "on {body:?}");
        assert_eq!(harness.users().len(), 1, "on {body:?}");
    }
}

#[tokio::test]
async fn a_user_can_be_deleted_once_another_exists() {
    let harness = harness();
    let cookie = harness.login().await;
    harness.post_form("/users/create", "username=second&password=xxxxxxxxxxxx", Some(&cookie)).await;

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
    harness.post_form("/users/create", "username=second&password=xxxxxxxxxxxx", Some(&cookie)).await;

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
    harness.post_form("/users/create", "username=second&password=xxxxxxxxxxxx", Some(&cookie)).await;

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

/// Past the series cap the chart says how many groups it left out, rather than inventing more hues.
#[tokio::test]
async fn more_groups_than_the_cap_are_reported() {
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

    assert!(reply.body.contains("Showing 8 of 12 groups"), "{}", reply.body);
    assert!(reply.body.contains("var(--series-8)"), "eight slots used");
    assert!(!reply.body.contains("var(--series-9)"), "and never a ninth");
}

/// Groups are chosen and coloured by *sorted* value, and numerically when they are numbers — otherwise
/// "the first eight" of sixteen cells would be 1 and 10–16.
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

    // The legend lists the plotted groups in order: 1..8, not 1,10,11,12.
    let legend = reply.body.split("<ul class=\"legend\">").nth(1).expect("a legend").to_owned();
    for expected in 1..=8 {
        assert!(legend.contains(&format!(">{expected}</li>")), "cell {expected} missing: {legend}");
    }
    assert!(!legend.contains(">10</li>"), "cell 10 is past the cap: {legend}");
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
