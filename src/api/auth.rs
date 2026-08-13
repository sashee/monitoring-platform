//! API key verification for every endpoint except `/healthz` (SPEC §13).
//!
//! **Nothing is rejected here yet.** This is the first half of a two-step rollout: the receiver
//! learns to verify a key and says what it concluded, while still serving every request. Only once
//! the journal is quiet — every client presenting a key that verifies — does refusing become safe.
//! Shipping verification and enforcement together would mean discovering a misconfigured device by
//! losing its telemetry.
//!
//! So the log levels carry the whole signal, and are the thing to read during the rollout:
//!
//! - anything that **would be rejected** under enforcement is a `warn`, saying so in those words
//! - a key that verifies is `debug`, because one line per request at `info` would drown the
//!   handler's own
//! - a database failure is an `error`: under enforcement it must become a 503, never a refusal, and
//!   never a silent pass
//!
//! Enforcement is then this file and nothing else: turn [`Outcome`] into a response for everything
//! but [`Outcome::Valid`], choosing the shape per route — protobuf `Status` on the ingest side, JSON
//! on the read side — which is why the layer is applied to each router separately rather than once
//! around both.

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

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
    /// Whether enforcement would let this request through. Nothing reads it yet; it is the seam
    /// phase 2 turns into a response, and it is asserted in the tests so the two halves cannot
    /// disagree later.
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

/// Verifies the key, records what it found, and serves the request either way.
pub async fn observe(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let outcome = evaluate(&state, presented).await;
    report(&outcome, request.method().as_str(), request.uri().path());

    next.run(request).await
}

/// The verification itself: parse, look the id up, compare hashes.
pub async fn evaluate(state: &AppState, presented: Option<String>) -> Outcome {
    let Some(raw) = presented else {
        return Outcome::Absent;
    };
    let token = match auth::from_authorization(&raw) {
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
        Outcome::Unavailable => {
            tracing::error!(%method, %path, "serving a request whose key could not be checked")
        }
        Outcome::Absent => tracing::warn!(
            %method, %path,
            "no API key presented; this request would be rejected once enforcement is enabled"
        ),
        Outcome::Malformed(reason) => tracing::warn!(
            %method, %path, reason = reason.reason(),
            "unusable API key; this request would be rejected once enforcement is enabled"
        ),
        Outcome::UnknownId => tracing::warn!(
            %method, %path,
            "API key id was never issued; this request would be rejected once enforcement is enabled"
        ),
        Outcome::WrongSecret => tracing::warn!(
            %method, %path,
            "API key secret does not match; this request would be rejected once enforcement is enabled"
        ),
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
