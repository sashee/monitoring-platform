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
pub mod web;

use anyhow::{Context, Result};
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

/// Secret bytes, straight from the kernel.
///
/// `/dev/urandom` rather than a `rand`/`getrandom` dependency: it is the same CSPRNG, this service is
/// Linux-only by construction (adjtimex, /proc, systemd credentials), and a credential is a poor
/// reason to widen the dependency graph. `read_exact` because a short read must be an error, never a
/// key with predictable tail bytes.
///
/// Lives here rather than in [`auth`] on purpose: that module documents itself as pure, with no I/O and
/// no randomness, which is what makes every property in it testable against fixed bytes. Both the API
/// key command and session creation need this, so it belongs where they can both reach it without
/// giving that up.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    use std::io::Read;

    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .context("opening /dev/urandom")?
        .read_exact(&mut bytes)
        .context("reading from /dev/urandom")?;
    Ok(bytes)
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
