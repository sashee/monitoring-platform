pub mod ingest;
pub mod query;
pub mod status;

use axum::Router;
use axum::routing::{get, post};

use crate::AppState;

/// Builds the router. Transport-agnostic by construction: it is served over whatever listener the
/// caller supplies, which is what lets iroh be added without touching this layer (SPEC §8.2).
pub fn app(state: AppState) -> Router {
    let ingest = Router::new()
        .route("/v1/logs", post(ingest::handler))
        // Applied only to the OTLP route, since the read API's errors are JSON by design.
        .layer(axum::middleware::map_response(status::ensure_protobuf_errors));

    let read = Router::new()
        .route("/v1/measurements", get(query::list))
        .route("/healthz", get(query::healthz));

    ingest.merge(read).with_state(state)
}
