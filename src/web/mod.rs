//! The browser-facing interface (SPEC §14): a login form, the measurements, and the two credential
//! tables.
//!
//! This is not a second API. It shares the router, the socket and the database with §7's JSON read API and
//! nothing else — in particular **not** the credential.
//! [`crate::api::app`] applies the session layer to these routes and the API-key layer to `/v1/*`, so a
//! cookie cannot reach an OTLP endpoint and a bearer token cannot open a page. That separation is asserted
//! in both directions in `tests/web.rs`, because it is true by construction today and would stop being true
//! the moment someone hoisted a layer out to wrap the merge.
//!
//! Everything is server-rendered, with no JavaScript and no static assets: the styling is inline (see
//! [`html`]) and the only interactive elements are two form submissions. A page that needs a build step
//! would need one on the Pi too.

pub mod html;
pub mod session;

use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Router};
use axum::routing::{get, post};
use serde::Deserialize;

use crate::AppState;
use crate::api::query::format_nanos;
use crate::store::read::QuerySpec;
use session::Identity;

/// How many measurements the front page shows.
///
/// Deliberately not paginated. §7.1's cursor pagination exists for a client walking the whole table; this
/// page answers "what is arriving", and the newest fifty answers it. A page that grows a cursor is a page
/// that needs its links to carry state, which is a lot of machinery for a view that is glanced at.
const RECENT_LIMIT: i64 = 50;

/// The routes requiring a session, and the login routes that must not.
///
/// Returned as two routers rather than one so the caller applies the guard to exactly the first — the same
/// arrangement, and for the same reason, as `/healthz` sitting outside the API-key layer.
pub fn routers(state: AppState) -> (Router<AppState>, Router<AppState>) {
    let guarded = Router::new()
        .route("/", get(index))
        .route("/users", get(users))
        .route("/sessions", get(sessions))
        .route("/logout", post(logout))
        .layer(axum::middleware::from_fn_with_state(state, session::guard));

    // No guard, by definition: this is how a request that has no session gets one. `GET` renders the form,
    // `POST` attempts a login.
    let open = Router::new().route("/login", get(login_form).post(login));

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
/// with a `GET`, which is what stops a reload of the login page from re-submitting the password.
fn see_other(location: &'static str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

// ------------------------------------------------------------------------------------------ the pages

/// The front page: the most recent measurements.
async fn index(State(state): State<AppState>) -> Response {
    // The §7 read path, unchanged — same `QuerySpec`, same query builder, same ordering. A second SQL path
    // for the same question would be a second thing to keep correct.
    let spec = QuerySpec { limit: RECENT_LIMIT, ..Default::default() };
    let db_path = state.config.database_path.clone();

    let rows = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_read(&db_path)?;
        crate::store::query(&conn, &spec)
    })
    .await;

    let rows = match rows {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return failed("reading the measurements", &e),
        Err(e) => return failed("the measurement query task", &e),
    };

    let table = html::table(
        &["event time", "type", "body", "attributes"],
        &rows
            .iter()
            .map(|m| {
                vec![
                    html::escape(&format_nanos(m.event_time)),
                    html::escape(&m.kind),
                    // Compact JSON, escaped: a body is arbitrary device-supplied JSON, and `to_string`
                    // on a `Value` is the same rendering §7.1 returns.
                    html::escape(&m.body.as_ref().map(|b| b.to_string()).unwrap_or_default()),
                    html::escape(&m.attributes.to_string()),
                ]
            })
            .collect::<Vec<_>>(),
        "no measurements yet",
    );

    html(StatusCode::OK, html::page("measurements", "/", &table))
}

/// The users table.
async fn users(State(state): State<AppState>) -> Response {
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

    let table = html::table(
        &["username", "created"],
        &listed
            .iter()
            .map(|u| {
                vec![html::escape(&u.username), html::escape(&format_nanos(u.created_at))]
            })
            .collect::<Vec<_>>(),
        "no users, which cannot happen while you are reading this page",
    );

    html(StatusCode::OK, html::page("users", "/users", &table))
}

/// The sessions table.
///
/// Shows the public id only. There is nothing else it *could* show — the secret half is not stored — and
/// saying so beside the table is worth more than leaving a reader to wonder whether a session can be read
/// off this page and replayed.
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
        &["id", "user", "created", "expires", ""],
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
                ]
            })
            .collect::<Vec<_>>(),
        "no sessions, which cannot happen while you are reading this page",
    );

    let body = format!(
        "{table}<p class=\"empty\">Only the public half of each session id is stored; the secret is \
         not in the database at all, so nothing on this page can be replayed as a login.</p>\n"
    );

    html(StatusCode::OK, html::page("sessions", "/sessions", &body))
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

// ------------------------------------------------------------------------------------------ logging in

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

    crate::store::sessions::insert(
        &conn,
        token.id(),
        &token.secret_hash(),
        username,
        now,
        expires_at,
    )?;

    Ok(session::session_cookie(&token.to_secret_string(), session::TTL_NANOS))
}

/// Logging out: delete the row, clear the cookie.
///
/// **`POST`, never `GET`.** A `GET` that logs you out is a link a prefetcher or a `<img src>` can fire, and
/// `SameSite=Strict` is not a defence against a same-site prefetch of your own page.
///
/// **No CSRF token.** `SameSite=Strict` means the cookie is not sent on any cross-site request at all, so a
/// forged submission from another origin arrives with no session and this handler has nothing to act on.
/// That is sufficient while login and logout are the only state-changing endpoints, and the honest note is
/// that it stops being sufficient the moment a page grows a form that changes something worth forging —
/// deleting a user, say. That is the point at which a token belongs here (SPEC §14).
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
            "could not delete the session row; the cookie is cleared regardless, so the browser is \
             logged out, but the row remains until it expires"
        ),
    }

    let mut response = see_other("/login");
    session::set_cookie(&mut response, &session::clearing_cookie());
    response
}
