//! API key verification for the `/v1` endpoints (SPEC §13).
//!
//! Requests without a valid key are refused. There is no switch: a flag that could turn
//! authentication off would be one more thing that has to be right, and the rollout it would have
//! served is already over — the previous release verified without enforcing, which is what made this
//! one safe to ship.
//!
//! **This layer is for machine clients only, and knows nothing about browsers.** It reads
//! `Authorization` and never `Cookie`, so a browser session (SPEC §14) cannot authenticate an OTLP or
//! read-API request through it — which is half of the separation [`crate::api::app`] tabulates. The
//! endpoints outside it are `/healthz` (below) and the §14 pages, which carry their own session layer.
//!
//! [`evaluate`] and [`refuse`] stay separate all the same, because they answer different questions:
//! what a request *is*, and what to tell it. Only the second is route-shaped.
//!
//! The log remains the operational signal, at the levels the rollout established:
//!
//! - a refusal, or what would have been one, is a `warn` naming which way the key failed
//! - a key that verifies is `debug`, because one line per request at `info` would drown the
//!   handler's own
//! - a key that could not be *checked* is an `error`, and answers `503` rather than `401`
//!
//! Two asymmetries in [`refuse`] are load-bearing, and both are about what a client does next:
//!
//! - **An unverifiable key is not a wrong key.** A database that cannot be read answers `503`,
//!   which is retryable; `401` is not, and would tell a device holding the only copy of a
//!   measurement to give up on it because *our* storage was broken.
//! - **Every wrong key gets the same message.** The log distinguishes an unissued id from a bad
//!   secret; the response does not, so it cannot be used to discover which ids exist.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::status::IngestError;
use crate::AppState;
use crate::auth::{self, Malformed};

/// What verification concluded about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No `Authorization` header. Every client that predates this feature looks like this, which is
    /// exactly why phase 1 exists.
    Absent,
    /// A header that is not a usable token. Carries the shape of the problem, never the value.
    Malformed(Malformed),
    /// Well formed, but no key with that id was ever issued.
    UnknownId,
    /// The id exists; the secret presented for it does not match.
    WrongSecret,
    /// The key could not be checked — the database was unreadable.
    Unavailable,
    /// Verified. Carries the id, which is public and is what an operator needs to see.
    Valid { id: String },
}

impl Outcome {
    /// The one thing that lets a request through. Everything else — including a key that could not be
    /// checked — does not.
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

/// Which error shape a route speaks. Authentication is identical on both; only the body differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// OTLP: a protobuf `google.rpc.Status`, as §4.1.1 requires of every 4xx and 5xx.
    Otlp,
    /// The read API: JSON, matching its own errors.
    Json,
}

/// The guard for the OTLP ingest route.
pub async fn guard_otlp(State(state): State<AppState>, request: Request, next: Next) -> Response {
    guard(state, request, next, Shape::Otlp).await
}

/// The guard for the JSON read route.
pub async fn guard_json(State(state): State<AppState>, request: Request, next: Next) -> Response {
    guard(state, request, next, Shape::Json).await
}

async fn guard(state: AppState, request: Request, next: Next, shape: Shape) -> Response {
    let outcome = evaluate(&state, request.headers().get(header::AUTHORIZATION)).await;
    report(&outcome, request.method().as_str(), request.uri().path());

    if !outcome.is_authorized() {
        return refuse(&outcome, shape);
    }
    next.run(request).await
}

/// Turns a failed [`Outcome`] into a response.
///
/// Refuses before the handler runs, so a rejected batch is never parsed, never decompressed and never
/// stored — the body is dropped with the request.
pub fn refuse(outcome: &Outcome, shape: Shape) -> Response {
    let (status, message) = match outcome {
        // Not a wrong key: a key we could not check. `503` is retryable and `401` is not, so
        // answering `401` here would tell a device to discard the only copy of a measurement because
        // *our* database was unreadable.
        Outcome::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "the API key could not be verified; try again",
        ),
        // One message for every way a key can be wrong. The log tells them apart; the response must
        // not, or it becomes an oracle for which ids exist.
        _ => (StatusCode::UNAUTHORIZED, "a valid API key is required"),
    };

    let mut response = match shape {
        Shape::Otlp => IngestError::new(status, message).into_response(),
        Shape::Json => (status, axum::Json(json!({"error": message}))).into_response(),
    };

    // RFC 7235 requires a challenge on a 401, and RFC 6750 gives the scheme's form. A 401 without it
    // is a client's cue to retry the same way forever.
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

/// The verification itself: parse, look the id up, compare hashes.
///
/// Takes the header value rather than a `String` deliberately. The bytes of a header are not
/// guaranteed to be text, and a signature that could only accept a `String` had no way to express
/// that case — so it used to collapse into [`Outcome::Absent`], and the log said "no API key
/// presented" about a request that presented one.
pub async fn evaluate(state: &AppState, presented: Option<&HeaderValue>) -> Outcome {
    let Some(raw) = presented else {
        return Outcome::Absent;
    };
    let Ok(raw) = raw.to_str() else {
        return Outcome::Malformed(Malformed::NotText);
    };
    let token = match auth::from_authorization(raw) {
        Ok(token) => token,
        Err(reason) => return Outcome::Malformed(reason),
    };

    // A short-lived read connection per request, as the read API already does (SPEC §6.4). At PoC
    // rates that is a file open against a page cache; if it ever shows up in a profile, the answer
    // is a cache in `AppState` with an explicit invalidation, not a longer-lived connection.
    let database_path = state.config.database_path.clone();
    let id = token.id().to_owned();
    let stored = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_read(&database_path)?;
        crate::store::keys::secret_hash(&conn, &id)
    })
    .await;

    match stored {
        Ok(Ok(Some(stored))) => {
            // `blake3::Hash`'s `PartialEq` is documented as constant-time, which is why the
            // comparison is between `Hash` values rather than byte slices. It is cheap insurance
            // rather than the thing holding the scheme up — leaking a hash byte by byte still leaves
            // an attacker needing a preimage — but it costs nothing to get right.
            if token.secret_hash() == stored {
                Outcome::Valid { id: token.id().to_owned() }
            } else {
                Outcome::WrongSecret
            }
        }
        Ok(Ok(None)) => Outcome::UnknownId,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "could not read the api key table");
            Outcome::Unavailable
        }
        Err(e) => {
            tracing::error!(error = %e, "the api key lookup task failed");
            Outcome::Unavailable
        }
    }
}

fn report(outcome: &Outcome, method: &str, path: &str) {
    match outcome {
        Outcome::Valid { id } => tracing::debug!(key = %id, %method, %path, "request authenticated"),
        Outcome::Unavailable => tracing::error!(
            %method, %path,
            "could not verify an API key; answering 503 so the client retries rather than discards"
        ),
        Outcome::Absent => {
            tracing::warn!(%method, %path, "rejected: no API key presented")
        }
        Outcome::Malformed(reason) => {
            tracing::warn!(%method, %path, reason = reason.reason(), "rejected: unusable API key")
        }
        Outcome::UnknownId => {
            tracing::warn!(%method, %path, "rejected: API key id was never issued")
        }
        Outcome::WrongSecret => {
            tracing::warn!(%method, %path, "rejected: API key secret does not match")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only `Valid` is authorized. Asserted so that phase 2, which will branch on exactly this,
    /// cannot quietly start letting a near-miss through.
    #[test]
    fn only_a_verified_key_is_authorized() {
        assert!(Outcome::Valid { id: "0011223344556677".into() }.is_authorized());

        for denied in [
            Outcome::Absent,
            Outcome::Malformed(Malformed::MissingPrefix),
            Outcome::UnknownId,
            Outcome::WrongSecret,
            Outcome::Unavailable,
        ] {
            assert!(!denied.is_authorized(), "{denied:?} must not be authorized");
        }
    }
}
