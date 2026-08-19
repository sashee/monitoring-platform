//! CSRF defence for state-changing requests (SPEC §14.3).
//!
//! **Why `SameSite=Strict` is not enough here, specifically.** SPEC §14.3 used to rest the whole CSRF
//! story on the session cookie's `SameSite=Strict`, on the grounds that a forged cross-site request
//! then arrives with no cookie at all. That reasoning holds on a normal domain. It does **not** hold
//! for how this service is actually reached.
//!
//! `SameSite` does not consider the port. The browser reaches these pages at `http://127.0.0.1:8080`
//! through the tunnel shim (§14.5), so *anything else* served from `127.0.0.1` — any port, any other
//! development server on the same laptop — is **same-site**. A page on `127.0.0.1:3000` can therefore
//! `POST /users/delete` and the browser will attach the session cookie. On a real domain this attack
//! needs control of a subdomain; on loopback it needs any local process that can serve a page. Adding
//! forms that create and delete users is what made that worth closing.
//!
//! **The check: every state-changing request must prove its origin.** `Origin` must be present and its
//! host:port must equal the `Host` header.
//!
//! **Why this rather than a synchronised token.** A token is the conventional answer, and here it
//! would be the *worse* one — not merely more code. There is no canonical origin to check against:
//! the receiver listens on a unix socket and is reached through whatever port the shim happens to
//! bind, so any expected origin baked into the configuration would be wrong for some legitimate way of
//! reaching it. Comparing `Origin` to `Host` needs no such constant — it is self-consistent however the
//! request arrived, because both headers describe the same hop — and it is sufficient, because an
//! attacker's page carries *its own* origin and cannot forge this one. It is also stateless: nothing to
//! mint, store, expire, or thread through every form.
//!
//! **Applied to every `POST`, including `/login` and `/logout`**, not only to the new mutations. Login
//! CSRF is a real if minor attack — an attacker can force you into a session they know the cookie of —
//! and "every state-changing request proves its origin" is a rule that stays true as routes are added,
//! where "the mutating ones do" is a rule someone has to remember to extend.
//!
//! The cost is that a command-line client must now send the header:
//!
//! ```sh
//! curl -H 'Origin: http://localhost' --unix-socket … -X POST …
//! ```
//!
//! Browsers always send `Origin` on `POST`, so nothing a browser does is affected.

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Whether a request's `Origin` matches the host it was sent to.
///
/// A pure function over the two header values, so every case below is testable without a server.
///
/// The scheme is deliberately ignored. `Host` does not carry one, so there is nothing to compare it
/// against, and requiring `https` would break the plain-HTTP loopback path this is reached over today
/// while requiring `http` would break TLS tomorrow. What matters for CSRF is the authority: an attacker
/// on another origin cannot spell ours whatever the scheme.
pub fn origin_matches(origin: Option<&str>, host: Option<&str>) -> bool {
    let (Some(origin), Some(host)) = (origin, host) else {
        // A missing `Origin` is a refusal, not a pass. Treating absence as "probably fine" is how this
        // kind of check ends up defending nothing: a browser always sends it on POST, so absence means
        // the request did not come from one.
        return false;
    };

    // `null` is what a browser sends for a sandboxed iframe or a `file://` document. It is never equal
    // to a host, but it is worth naming: it must not be allowed to match an empty or absent host.
    if origin == "null" || host.is_empty() {
        return false;
    }

    let authority = origin
        .split_once("://")
        .map(|(_scheme, rest)| rest)
        // No scheme separator means this is not a well-formed origin. Compared as-is rather than
        // rejected outright, so an exact match still passes and anything else still fails.
        .unwrap_or(origin);

    // No normalization of a default port: `http://localhost` and `localhost:80` are spelled
    // differently by definition, and a browser sends `Origin` and `Host` consistently with each other,
    // so an exact comparison is what pairs them. Inventing equivalences here would only widen what
    // counts as a match.
    authority == host
}

/// Refuses any state-changing request whose origin cannot be confirmed.
///
/// Only `POST` is checked. Every route that changes anything is a `POST` — `GET` handlers here read and
/// render, and a `GET` that changed something would be the bug (a link a prefetcher can fire), which is
/// why `/logout` is a form rather than an anchor.
pub async fn guard(request: Request, next: Next) -> Response {
    if request.method() != axum::http::Method::POST {
        return next.run(request).await;
    }

    // Owned copies, taken in statements that end before the `await` below. A `Request` carries a body
    // that is `Send` but not `Sync`, so any reference to it still alive across an await would make this
    // whole middleware's future non-`Send` and the router would refuse to accept the layer. A closure
    // capturing `&request` does exactly that, which is why these are two plain statements.
    let origin =
        request.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let host = request.headers().get(header::HOST).and_then(|v| v.to_str().ok()).map(str::to_owned);

    if origin_matches(origin.as_deref(), host.as_deref()) {
        return next.run(request).await;
    }

    // `warn`, and it names both values: the realistic cause is a `curl` without the header rather than
    // an attack, and an operator debugging that needs to see what did not match. Neither value is a
    // secret — they are addresses.
    tracing::warn!(
        method = %request.method(),
        path = %request.uri().path(),
        origin = origin.as_deref().unwrap_or("<absent>"),
        host = host.as_deref().unwrap_or("<absent>"),
        "rejected: the request's Origin does not match its Host (SPEC §14.3)"
    );

    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "this request's Origin does not match the host it was sent to, so it was refused.\n\
         A browser sends Origin automatically; a command-line client must pass \
         -H 'Origin: http://<host>' matching the Host header.\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_origin_passes() {
        assert!(origin_matches(Some("http://localhost"), Some("localhost")));
        assert!(origin_matches(Some("http://127.0.0.1:8080"), Some("127.0.0.1:8080")));
        assert!(origin_matches(Some("https://mp.example"), Some("mp.example")));
    }

    /// **The case this whole middleware exists for.** `SameSite` ignores the port, so another server on
    /// loopback is same-site and its forged POST would carry the cookie. Only the origin check sees the
    /// difference.
    #[test]
    fn a_different_port_on_the_same_host_is_refused() {
        assert!(!origin_matches(Some("http://127.0.0.1:3000"), Some("127.0.0.1:8080")));
        assert!(!origin_matches(Some("http://localhost:3000"), Some("localhost:8080")));
    }

    #[test]
    fn a_different_host_is_refused() {
        assert!(!origin_matches(Some("http://evil.example"), Some("127.0.0.1:8080")));
        assert!(!origin_matches(Some("http://127.0.0.1.evil.example"), Some("127.0.0.1")));
    }

    /// Absence is a refusal. A browser always sends `Origin` on POST, so a request without one did not
    /// come from a browser — and defaulting to "allow" would make the check defend nothing.
    #[test]
    fn an_absent_origin_or_host_is_refused() {
        assert!(!origin_matches(None, Some("localhost")));
        assert!(!origin_matches(Some("http://localhost"), None));
        assert!(!origin_matches(None, None));
    }

    /// A sandboxed iframe or a `file://` page sends `null`. It must not match anything, least of all an
    /// empty host.
    #[test]
    fn a_null_origin_is_refused() {
        assert!(!origin_matches(Some("null"), Some("localhost")));
        assert!(!origin_matches(Some("null"), Some("")));
        assert!(!origin_matches(Some("null"), Some("null")));
    }

    #[test]
    fn an_empty_host_matches_nothing() {
        assert!(!origin_matches(Some("http://"), Some("")));
        assert!(!origin_matches(Some(""), Some("")));
    }

    /// The scheme is not compared, so the same deployment works over the plain-HTTP loopback path today
    /// and over TLS later without this check needing to change.
    #[test]
    fn the_scheme_is_ignored() {
        assert!(origin_matches(Some("http://mp.example"), Some("mp.example")));
        assert!(origin_matches(Some("https://mp.example"), Some("mp.example")));
    }

    /// A default port is not silently equated with its absence: browsers spell the pair consistently,
    /// and inventing equivalences here would only widen what counts as a match.
    #[test]
    fn a_default_port_is_not_normalized_away() {
        assert!(!origin_matches(Some("http://localhost:80"), Some("localhost")));
        assert!(!origin_matches(Some("http://localhost"), Some("localhost:80")));
    }
}
