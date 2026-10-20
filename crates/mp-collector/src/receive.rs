//! `POST /v1/logs` on the collector's own socket (design §4.5).
//!
//! Frame resolution happens **at receipt**, not at flush, while the things it depends on are still
//! available: the peer's credentials, and a `CLOCK_BOOTTIME` reading close to the moment the
//! record actually arrived. By flush time the connection is long gone.
//!
//! Body limits and decompression mirror `monitoring_platform::api::ingest`, because an application
//! must be able to point at either this or the receiver unchanged — that property is the reason
//! the design rejects a mandatory per-record attribute, and it would be lost just as thoroughly by
//! a collector that refused a gzipped body the receiver accepts.

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use flate2::read::GzDecoder;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use prost::Message;
use serde_json::json;
use std::io::Read;
use std::sync::Arc;
use tokio::net::UnixListener;

use crate::config::Config;
use crate::correct::{Receipt, resolve_request};
use crate::forward::PROTOBUF;
use crate::runtime::Handle;

/// Per-connection peer identity, resolved once at accept.
///
/// Once per connection rather than once per request is the point: `SO_PEERCRED` and the
/// `/proc/PID/stat` read are both cheap, but a long-lived OTLP exporter connection carries
/// thousands of batches and the sender's start time cannot change under it.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    /// `CLOCK_BOOTTIME` at which the sending process started, or 0 if it could not be determined.
    ///
    /// Zero is the safe fallback: it is the weakest possible lower bound, so resolution loses
    /// precision and may report `ambiguous`, but it never invents a tighter constraint than the
    /// evidence supports.
    pub started_at: i64,
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, UnixListener>>
    for Peer
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, UnixListener>) -> Self {
        let started_at = peer_start(stream.io()).unwrap_or_else(|e| {
            tracing::debug!(error = %e, "no peer start time; frame resolution loses its lower bound");
            0
        });
        Self { started_at }
    }
}

fn peer_start(stream: &tokio::net::UnixStream) -> anyhow::Result<i64> {
    let credentials = stream.peer_cred()?;
    let pid = credentials
        .pid()
        .ok_or_else(|| anyhow::anyhow!("SO_PEERCRED carried no pid"))?;
    crate::peer::started_at(u32::try_from(pid)?, crate::peer::ticks_per_second()?)
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub handle: Handle,
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/v1/logs", post(ingest))
        .route("/healthz", axum::routing::get(healthz))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Response {
    let status = state.handle.status();
    Json(json!({
        "status": "ok",
        "clock": {
            "synchronized": status.synchronized,
            "ever_synchronized": status.ever_synchronized,
            "disciplined": status.disciplined,
            "sync_source": status.sync_source.map(|s| s.label()),
            "epochs": status.epochs,
            "steps": status.steps,
        },
        "buffer": { "records": status.buffered_records },
    }))
    .into_response()
}

async fn ingest(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    require_protobuf_content_type(&headers)?;
    let gzipped = gzip_requested(&headers)?;

    let wire = axum::body::to_bytes(body, state.config.max_body_bytes).await.map_err(|_| {
        Error::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds max_body_bytes ({})", state.config.max_body_bytes),
        )
    })?;

    let payload = if gzipped {
        decompress_gzip(&wire, state.config.max_decompressed_bytes)?
    } else {
        wire.to_vec()
    };

    let mut request = ExportLogsServiceRequest::decode(payload.as_slice()).map_err(|e| {
        Error::new(StatusCode::BAD_REQUEST, format!("malformed ExportLogsServiceRequest: {e}"))
    })?;

    // Sampled here, as late as possible before resolution and as close as possible to the moment
    // the bytes arrived. This is the upper bound of the `[sender_started, received]` window.
    let received = mp_host::clock::now_boottime().map_err(|e| {
        Error::new(StatusCode::INTERNAL_SERVER_ERROR, format!("cannot read CLOCK_BOOTTIME: {e}"))
    })?;

    let table = state.handle.table();
    let tally = resolve_request(&mut request, &table, Receipt {
        sender_started: peer.started_at,
        received,
        tolerance: state.config.tolerance_nanos,
    });

    tracing::debug!(
        exact = tally.exact,
        ambiguous = tally.ambiguous,
        passthrough = tally.passthrough,
        authoritative = tally.authoritative,
        "resolved batch"
    );

    state
        .handle
        .accept(request, payload.len(), received, tally)
        .map_err(|e| Error::new(StatusCode::SERVICE_UNAVAILABLE, format!("cannot accept: {e}")))?;

    // A plain 200 with no partial success: the collector rejects no records. Anything it cannot
    // resolve is forwarded untouched, and whether the *receiver* accepts it is the receiver's
    // answer to give, on its own request.
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROTOBUF)],
        ExportLogsServiceResponse { partial_success: None }.encode_to_vec(),
    )
        .into_response())
}

/// An OTLP-shaped failure. The collector answers in the same currency the receiver does, so a
/// client cannot tell which of the two refused it — again, so pointing at either works unchanged.
#[derive(Debug)]
pub struct Error {
    pub status: StatusCode,
    pub message: String,
}

impl Error {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::warn!(status = %self.status, message = %self.message, "rejecting batch");
        (self.status, Json(json!({ "message": self.message }))).into_response()
    }
}

fn require_protobuf_content_type(headers: &HeaderMap) -> Result<(), Error> {
    let raw = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).ok_or_else(|| {
        Error::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "missing Content-Type; expected application/x-protobuf",
        )
    })?;

    // Tolerate parameters such as `; charset=utf-8`, which some HTTP clients append.
    let base = raw.split(';').next().unwrap_or("").trim();
    if !base.eq_ignore_ascii_case(PROTOBUF) {
        return Err(Error::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("unsupported Content-Type {raw:?}; expected application/x-protobuf"),
        ));
    }
    Ok(())
}

/// Unrecognised encodings are rejected rather than treated as `identity`, so a client configured
/// for `zstd` fails visibly instead of having its payload misread as corrupt protobuf.
fn gzip_requested(headers: &HeaderMap) -> Result<bool, Error> {
    let Some(raw) = headers.get(header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()) else {
        return Ok(false);
    };
    match raw.trim() {
        "" | "identity" => Ok(false),
        "gzip" => Ok(true),
        other => Err(Error::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("unsupported Content-Encoding {other:?}; only gzip and identity are accepted"),
        )),
    }
}

/// Decompresses with a hard ceiling, reading one byte past the limit to detect overrun without
/// materialising the whole stream.
fn decompress_gzip(input: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    GzDecoder::new(input)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::new(StatusCode::BAD_REQUEST, format!("body is not valid gzip: {e}")))?;

    if out.len() > limit {
        return Err(Error::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("decompressed body exceeds max_decompressed_bytes ({limit} bytes)"),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    /// The collector must accept exactly what the receiver accepts, or "point the application at
    /// either one unchanged" stops being true.
    #[test]
    fn content_type_accepts_parameters_but_not_other_types() {
        assert!(require_protobuf_content_type(&headers(&[("content-type", PROTOBUF)])).is_ok());
        assert!(
            require_protobuf_content_type(&headers(&[(
                "content-type",
                "application/x-protobuf; charset=utf-8"
            )]))
            .is_ok()
        );
        assert_eq!(
            require_protobuf_content_type(&headers(&[("content-type", "application/json")]))
                .unwrap_err()
                .status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            require_protobuf_content_type(&HeaderMap::new()).unwrap_err().status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn content_encoding_accepts_gzip_and_identity_only() {
        assert!(!gzip_requested(&HeaderMap::new()).unwrap());
        assert!(!gzip_requested(&headers(&[("content-encoding", "identity")])).unwrap());
        assert!(gzip_requested(&headers(&[("content-encoding", "gzip")])).unwrap());

        let err = gzip_requested(&headers(&[("content-encoding", "zstd")])).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(err.message.contains("zstd"), "the rejected encoding should be named");
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn round_trips_gzip_within_the_limit() {
        let payload = b"hello measurements".repeat(100);
        assert_eq!(decompress_gzip(&gzip(&payload), 1 << 20).unwrap(), payload);
    }

    #[test]
    fn invalid_gzip_is_a_bad_request_not_a_size_error() {
        assert_eq!(
            decompress_gzip(b"definitely not gzip", 1 << 20).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }

    /// A small compressed payload that expands past the ceiling must be refused, and refused
    /// without first materialising the whole expansion — the collector is the *first* thing a
    /// hostile local payload reaches, so it cannot lean on the receiver's limits.
    #[test]
    fn gzip_bomb_is_refused_at_the_decompressed_limit() {
        let bomb = gzip(&vec![0u8; 64 << 20]);
        assert!(bomb.len() < 200_000, "test bomb should be small on the wire: {}", bomb.len());
        assert_eq!(
            decompress_gzip(&bomb, 1 << 20).unwrap_err().status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn decompressed_limit_boundary_is_exact() {
        let exactly = vec![7u8; 1000];
        assert!(decompress_gzip(&gzip(&exactly), 1000).is_ok(), "at the limit must pass");
        assert_eq!(
            decompress_gzip(&gzip(&exactly), 999).unwrap_err().status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
