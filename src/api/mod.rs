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
/// merge, because the two answer errors in different shapes — protobuf `Status` on the OTLP side,
/// JSON on the read side — and phase 2 has to reject in the shape of the route it refused.
pub fn app(state: AppState) -> Router {
    let observe = axum::middleware::from_fn_with_state(state.clone(), auth::observe);

    let ingest = Router::new()
        .route("/v1/logs", post(ingest::handler))
        .layer(observe.clone())
        // Outermost, so it also covers responses the auth layer will produce under enforcement.
        .layer(axum::middleware::map_response(status::ensure_protobuf_errors));

    let measurements = Router::new().route("/v1/measurements", get(query::list)).layer(observe);

    // Deliberately unprotected (SPEC §13): a health check has to answer before any key exists —
    // during a deploy, from an `ExecStartPre`, from a probe that holds no credential — and it
    // discloses nothing but liveness.
    let health = Router::new().route("/healthz", get(query::healthz));

    ingest.merge(measurements).merge(health).with_state(state)
}
