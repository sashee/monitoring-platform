//! Monitoring platform: an OTLP/HTTP protobuf receiver for device measurements.
//!
//! See `SPEC.md`. Section references in comments point at it.

pub mod api;
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
