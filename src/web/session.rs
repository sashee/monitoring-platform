//! Session cookies: the header format, and the middleware that turns one into an identity (SPEC §14).
//!
//! The parsing and serializing halves are pure functions over strings, so every attribute the browser
//! depends on is asserted directly rather than inferred from a live response.
//!
//! **No cookie crate.** One cookie is read and one is written, and RFC 6265's `name=value` pairs separated
//! by `; ` is the whole grammar involved. A dependency here would carry signing, jars and date formatting
//! for a `split_once('=')`.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::auth::{self, Malformed};
use crate::store::sessions::SessionRecord;

/// The cookie's name. Prefixed, so it cannot collide with anything else served from the same origin —
/// which matters because the browser reaches this through a local TCP shim on `127.0.0.1`, an origin
/// other things also use.
pub const COOKIE: &str = "mp_session";

/// How long a session lasts, in nanoseconds. Thirty days.
///
/// A constant rather than a module option: it is one operator's own convenience, nothing depends on the
/// value, and `nix/module.nix` gaining a knob nobody turns is a thing to explain later. If it ever needs
/// to vary per host, `sessionTtlDays` alongside `logLevel` is where it goes.
pub const TTL_NANOS: i64 = 30 * 24 * 60 * 60 * 1_000_000_000;

/// What the session layer concluded about one request.
///
/// Separate from the response it produces, exactly as [`crate::api::auth::Outcome`] is: what a request
/// *is* and what to tell it are different questions, and only the second is route-shaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No session cookie. The ordinary state of a browser that has not logged in.
    Absent,
    /// A cookie that is not a usable session token.
    Malformed(Malformed),
    /// Well formed, but no session with that id exists — logged out, swept, or never issued.
    UnknownId,
    /// The id exists; the secret presented for it does not match.
    WrongSecret,
    /// The id exists and the secret matches, but the session is past its expiry.
    Expired,
    /// The session could not be checked — the database was unreadable.
    Unavailable,
    /// Verified.
    Valid { id: String, username: String },
}

impl Outcome {
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

/// The signed-in identity, attached to the request by [`guard`] and read back by handlers.
///
/// Carries no secret — only the public id and the username — so it is safe to hold in a request extension
/// and safe to `Debug`.
#[derive(Debug, Clone)]
pub struct Identity {
    pub session_id: String,
    pub username: String,
}

/// Guards the pages that require a login.
///
/// **Answers `303 See Other` to `/login`, not `401`.** A browser is the only client here, and a 401 with a
/// `WWW-Authenticate` challenge would make it show the native basic-auth dialog — for a form-based login
/// that is a dead end. The API-key layer keeps its 401 precisely because its clients are not browsers
/// (SPEC §13); the divergence is deliberate rather than an inconsistency.
pub async fn guard(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let outcome = evaluate(&state, request.headers().get(header::COOKIE)).await;
    report(&outcome, request.method().as_str(), request.uri().path());

    match outcome {
        Outcome::Valid { id, username } => {
            request.extensions_mut().insert(Identity { session_id: id, username });
            next.run(request).await
        }
        // A database that cannot be read is not a request that is unauthenticated, and bouncing it to a
        // login form it also cannot serve would be a redirect loop. Say so instead.
        Outcome::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "the session could not be verified; try again\n",
        )
            .into_response(),
        // Everything else is "you are not logged in", including a session that expired one second ago.
        // Clearing the cookie on the way out means a stale one is not re-presented on every subsequent
        // request, which would keep producing warnings about a session that is never coming back.
        _ => redirect_to_login(),
    }
}

/// `303 See Other` to the login form, with any stale cookie cleared.
pub fn redirect_to_login() -> Response {
    let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")]).into_response();
    set_cookie(&mut response, &clearing_cookie());
    response
}

/// Verifies a `Cookie` header: parse, look the id up, compare hashes, check expiry.
///
/// Takes the header value rather than a `&str` for the reason [`crate::api::auth::evaluate`] documents:
/// header bytes are not guaranteed to be text, and a signature that could only accept text has to
/// collapse that case into "absent", which then makes the log say a request presented nothing when it
/// presented something unreadable.
pub async fn evaluate(state: &AppState, presented: Option<&HeaderValue>) -> Outcome {
    let Some(raw) = presented else {
        return Outcome::Absent;
    };
    let Ok(raw) = raw.to_str() else {
        return Outcome::Malformed(Malformed::NotText);
    };
    let Some(value) = cookie_value(raw, COOKIE) else {
        // A `Cookie` header with other cookies in it but not ours is the same situation as no header at
        // all: nothing about this request claims to be a session.
        return Outcome::Absent;
    };
    let token = match auth::parse_session(value) {
        Ok(token) => token,
        Err(reason) => return Outcome::Malformed(reason),
    };

    // A short-lived read connection per request, as the read API and the API-key layer both already do
    // (SPEC §6.4).
    let database_path = state.config.database_path.clone();
    let id = token.id().to_owned();
    let stored = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_read(&database_path)?;
        crate::store::sessions::lookup(&conn, &id)
    })
    .await;

    let record: SessionRecord = match stored {
        Ok(Ok(Some(record))) => record,
        Ok(Ok(None)) => return Outcome::UnknownId,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "could not read the session table");
            return Outcome::Unavailable;
        }
        Err(e) => {
            tracing::error!(error = %e, "the session lookup task failed");
            return Outcome::Unavailable;
        }
    };

    // `blake3::Hash`'s `PartialEq` is documented as constant-time, which is why this compares `Hash`
    // values rather than byte slices — the same reasoning as the API-key comparison.
    if token.secret_hash() != record.secret_hash {
        return Outcome::WrongSecret;
    }
    // Expiry is checked after the secret, so an expired id cannot be used to probe for which ids exist by
    // watching which ones report expiry rather than a mismatch.
    if !record.is_live(crate::now_unix_nanos()) {
        return Outcome::Expired;
    }

    Outcome::Valid { id: token.id().to_owned(), username: record.username }
}

/// One cookie's value out of a `Cookie` header.
///
/// RFC 6265 sends every cookie in one header separated by `; `, so this is a scan rather than a lookup.
/// Values are returned verbatim: a session token is hex and a `.`, so nothing here needs percent-decoding,
/// and inventing a decode step would mean a value that round-trips differently than it was set.
///
/// Whitespace around the separator is tolerated because clients vary, but not *inside* the name — a
/// cookie called `mp_session ` is a different cookie.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then_some(value)
    })
}

/// The `Set-Cookie` value that establishes a session.
///
/// The attributes, and why each is what it is:
///
/// - `HttpOnly` — script cannot read it, so an injection anywhere in these pages cannot exfiltrate the
///   session. [`super::html::escape`] is the first line of that defence; this is the second.
/// - `SameSite=Strict` — the cookie is not sent on any cross-site request, which is what makes a forged
///   `POST /logout` from another origin inert. It is also this application's entire CSRF story; see
///   [`super::logout`].
/// - `Path=/` — every page is under the root.
/// - `Max-Age` — matched to the row's `expires_at`, so the browser stops presenting a cookie at the same
///   moment the server stops accepting it. Without it the cookie is a session cookie in the browser's
///   sense and vanishes when the window closes, which is not the same lifetime at all.
/// - **No `Secure`, deliberately.** The browser reaches this over plain HTTP on loopback: the receiver
///   listens on a unix socket only, and the path to it is `socat` on `127.0.0.1` into an iroh tunnel
///   (SPEC §14). `Secure` would tell the browser to withhold the cookie from an `http://` origin, so
///   login would appear to succeed and every subsequent request would be anonymous. What stands in for it
///   is the shape of that path: the only network hop is iroh's QUIC, which is encrypted and authenticates
///   the far endpoint by its id, and either end of it is loopback or a unix socket inside a 0750
///   group-owned directory. **Adding `Secure` is what to do the day this is served over TLS, and not
///   before.**
pub fn session_cookie(token_value: &str, ttl_nanos: i64) -> String {
    format!(
        "{COOKIE}={token_value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        ttl_nanos / 1_000_000_000
    )
}

/// The `Set-Cookie` value that removes a session.
///
/// `Max-Age=0` with an empty value. The attributes are repeated because a browser matches a cookie for
/// replacement on name, domain and path — a clearing cookie sent without `Path=/` would create a second
/// cookie at the current path rather than remove the one that exists.
pub fn clearing_cookie() -> String {
    format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// Appends a `Set-Cookie` header.
///
/// `append` rather than `insert`: a response may legitimately carry more than one, and `insert` would
/// silently drop whichever came first.
pub fn set_cookie(response: &mut Response, value: &str) {
    match HeaderValue::from_str(value) {
        Ok(header) => {
            response.headers_mut().append(header::SET_COOKIE, header);
        }
        // Unreachable — the values are built from hex and fixed attributes — but a panic in a response
        // path would take the request down for a cookie, so it is reported instead.
        Err(e) => tracing::error!(error = %e, "could not build the Set-Cookie header"),
    }
}

fn report(outcome: &Outcome, method: &str, path: &str) {
    match outcome {
        // debug, not info: one line per page load at info would drown the handlers' own output, which is
        // the same reasoning the API-key layer records.
        Outcome::Valid { username, .. } => {
            tracing::debug!(user = %username, %method, %path, "request authenticated by session")
        }
        Outcome::Unavailable => tracing::error!(
            %method, %path,
            "could not verify a session; answering 503 rather than bouncing to a login form that \
             would fail the same way"
        ),
        // Absent is not a warning. Every first visit to any page looks like this, so at warn the log would
        // fill with the ordinary case — unlike a missing API key, which means a misconfigured device.
        Outcome::Absent => tracing::debug!(%method, %path, "no session presented"),
        Outcome::Malformed(reason) => {
            tracing::warn!(%method, %path, reason = reason.reason(), "rejected: unusable session cookie")
        }
        Outcome::UnknownId => {
            tracing::debug!(%method, %path, "rejected: session id is not in the table")
        }
        Outcome::WrongSecret => {
            tracing::warn!(%method, %path, "rejected: session secret does not match")
        }
        Outcome::Expired => tracing::debug!(%method, %path, "rejected: session has expired"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_cookie_among_others() {
        assert_eq!(cookie_value("mp_session=abc", COOKIE), Some("abc"));
        assert_eq!(cookie_value("a=1; mp_session=abc; b=2", COOKIE), Some("abc"));
        assert_eq!(cookie_value("mp_session=abc; b=2", COOKIE), Some("abc"));
    }

    /// Clients vary in whether they put a space after the separator, so both have to work.
    #[test]
    fn tolerates_whitespace_around_the_separator() {
        assert_eq!(cookie_value("a=1;mp_session=abc", COOKIE), Some("abc"));
        assert_eq!(cookie_value("a=1;   mp_session=abc", COOKIE), Some("abc"));
        assert_eq!(cookie_value(" mp_session=abc ", COOKIE), Some("abc "));
    }

    #[test]
    fn a_header_without_our_cookie_is_none() {
        assert_eq!(cookie_value("", COOKIE), None);
        assert_eq!(cookie_value("other=1", COOKIE), None);
        assert_eq!(cookie_value("nonsense", COOKIE), None, "no `=` at all");
    }

    /// A prefix or suffix of the name is a different cookie, or `mp_session_backup` would be read as the
    /// session.
    #[test]
    fn matches_the_whole_name_only() {
        assert_eq!(cookie_value("mp_session_backup=abc", COOKIE), None);
        assert_eq!(cookie_value("xmp_session=abc", COOKIE), None);
        assert_eq!(cookie_value("mp_session_backup=x; mp_session=abc", COOKIE), Some("abc"));
    }

    /// A token contains a `.` and nothing else exotic, but an empty value must not read as absent — it is a
    /// cookie that is present and unusable, which is a different outcome.
    #[test]
    fn an_empty_value_is_present_but_empty() {
        assert_eq!(cookie_value("mp_session=", COOKIE), Some(""));
    }

    /// The base64-ish and hex values in play never contain `=` inside, but a value that did must not be
    /// truncated at it — `split_once` rather than `split`.
    #[test]
    fn a_value_containing_equals_is_not_truncated() {
        assert_eq!(cookie_value("mp_session=ab=cd", COOKIE), Some("ab=cd"));
    }

    #[test]
    fn the_session_cookie_carries_the_attributes_the_browser_needs() {
        let cookie = session_cookie("mps_00.11", TTL_NANOS);
        assert!(cookie.starts_with("mp_session=mps_00.11;"), "{cookie}");
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Strict"), "{cookie}");
        assert!(cookie.contains("Path=/"), "{cookie}");
        assert!(cookie.contains("Max-Age=2592000"), "30 days in seconds: {cookie}");
    }

    /// Pinned, and the comment on [`session_cookie`] says why: the browser reaches this over plain HTTP on
    /// loopback, so `Secure` would silently make every request after login anonymous. This test is the
    /// thing that makes adding it a deliberate act.
    #[test]
    fn the_session_cookie_is_not_marked_secure() {
        assert!(!session_cookie("mps_00.11", TTL_NANOS).contains("Secure"));
        assert!(!clearing_cookie().contains("Secure"));
    }

    /// The clearing cookie has to repeat the path, or the browser adds a second cookie at the current path
    /// instead of replacing the one at the root.
    #[test]
    fn the_clearing_cookie_expires_immediately_at_the_same_path() {
        let cookie = clearing_cookie();
        assert!(cookie.starts_with("mp_session=;"), "{cookie}");
        assert!(cookie.contains("Max-Age=0"), "{cookie}");
        assert!(cookie.contains("Path=/"), "{cookie}");
    }

    #[test]
    fn only_a_verified_session_is_authorized() {
        assert!(
            Outcome::Valid { id: "00".into(), username: "sashee".into() }.is_authorized()
        );

        for denied in [
            Outcome::Absent,
            Outcome::Malformed(Malformed::MissingPrefix),
            Outcome::UnknownId,
            Outcome::WrongSecret,
            Outcome::Expired,
            Outcome::Unavailable,
        ] {
            assert!(!denied.is_authorized(), "{denied:?} must not be authorized");
        }
    }

    /// A browser with no session must be sent to the form, and the stale cookie cleared on the way so it is
    /// not re-presented on every subsequent request.
    #[test]
    fn the_redirect_clears_the_cookie_and_points_at_the_form() {
        let response = redirect_to_login();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
        assert!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
    }
}
