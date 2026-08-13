//! Monitoring platform: an OTLP/HTTP protobuf receiver for device measurements.
//!
//! See `SPEC.md`. Section references in comments point at it.

pub mod api;
pub mod auth;
pub mod clock;
pub mod config;
pub mod content_id;
pub mod model;
pub mod otlp;
pub mod store;
pub mod transport;

use std::sync::Arc;

pub use config::Config;
pub use store::Writer;

/// Shared handler state. Cheap to clone: a channel sender and an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub writer: Writer,
}

impl AppState {
    pub fn new(config: Config, writer: Writer) -> Self {
        Self { config: Arc::new(config), writer }
    }
}

/// The server clock, as nanoseconds since the Unix epoch.
///
/// Shared by ingest, which stamps `processed_time` (SPEC §5.1), and by key creation, which stamps
/// `created_at` — so both read the clock the same way. Both run only after the clock gate has passed
/// (SPEC §9.4), which is what makes the reading worth storing.
pub fn now_unix_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}
