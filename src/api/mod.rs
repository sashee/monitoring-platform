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
/// **Each protected group carries its own auth layer, and that is load-bearing rather than stylistic.**
/// There are now two credentials in play — the API key of §13 and the browser session of §14 — and four
/// groups that answer differently:
///
/// | routes | credential | a refusal looks like |
/// |---|---|---|
/// | `/v1/logs` | API key | protobuf `google.rpc.Status`, as §4.1.1 requires |
/// | `/v1/measurements` | API key | JSON, matching the read API's own errors |
/// | `/`, `/users`, `/sessions`, `/logout` | session cookie | `303` to the login form |
/// | `/login`, `/healthz` | none | — |
///
/// So a rejection looks like the route it came from, and — the security property — **a credential only
/// works on the surface it belongs to.** The session middleware never reads `Authorization` and the
/// API-key middleware never reads `Cookie`, so a cookie cannot reach an OTLP endpoint and a bearer token
/// cannot open a page. Hoisting either layer out to wrap the merge would quietly end that; `tests/web.rs`
/// asserts it in both directions.
pub fn app(state: AppState) -> Router {
    let ingest = Router::new()
        .route("/v1/logs", post(ingest::handler))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::guard_otlp))
        // Outermost, so it covers the auth layer's own responses too.
        .layer(axum::middleware::map_response(status::ensure_protobuf_errors));

    let measurements = Router::new()
        .route("/v1/measurements", get(query::list))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::guard_json));

    // The web interface (SPEC §14), already carrying its own session layer on the guarded half. `login` is
    // outside it by definition: it is how a request with no session acquires one.
    let (web_pages, web_login) = crate::web::routers(state.clone());

    // Deliberately unprotected (SPEC §13): a health check has to answer before any key exists —
    // during a deploy, from an `ExecStartPre`, from a probe that holds no credential — and it
    // discloses nothing but liveness.
    let health = Router::new().route("/healthz", get(query::healthz));

    ingest
        .merge(measurements)
        .merge(web_pages)
        .merge(web_login)
        .merge(health)
        .with_state(state)
}
