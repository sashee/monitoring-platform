pub mod auth;
pub mod ingest;
pub mod query;
pub mod status;

use axum::Router;
use axum::routing::{get, post};

use crate::AppState;

/// Builds the router. Transport-agnostic by construction: it is served over whatever listener the
/// caller supplies, which is what lets iroh be added without touching this layer (SPEC §8.2).
///
/// The API key layer is applied to each protected router separately rather than once around the
/// merge, because the two refuse in different shapes — protobuf `Status` on the OTLP side, JSON on the
/// read side — and a rejection has to look like the route it came from.
pub fn app(state: AppState) -> Router {
    let ingest = Router::new()
        .route("/v1/logs", post(ingest::handler))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::guard_otlp))
        // Outermost, so it covers the auth layer's own responses too.
        .layer(axum::middleware::map_response(status::ensure_protobuf_errors));

    let measurements = Router::new()
        .route("/v1/measurements", get(query::list))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::guard_json));

    // Deliberately unprotected (SPEC §13): a health check has to answer before any key exists —
    // during a deploy, from an `ExecStartPre`, from a probe that holds no credential — and it
    // discloses nothing but liveness.
    let health = Router::new().route("/healthz", get(query::healthz));

    ingest.merge(measurements).merge(health).with_state(state)
}
