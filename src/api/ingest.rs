//! `POST /v1/logs` (SPEC §4).
//!
//! Body reading, size limits and decompression are done here rather than with middleware. That is
//! a deliberate departure from a `tower-http` layer stack: it makes the two independent limits
//! explicit instead of dependent on layer ordering, and it means every error originates in this
//! handler and is therefore already a protobuf `Status`.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use flate2::read::GzDecoder;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use prost::Message;
use std::io::Read;

use super::status::{IngestError, PROTOBUF};
use crate::otlp::to_measurements;
use crate::{AppState, now_unix_nanos};

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, IngestError> {
    // Captured once per request, shared by every measurement in it (SPEC §5.1).
    let processed_time = now_unix_nanos();

    require_protobuf_content_type(&headers)?;
    let gzipped = gzip_requested(&headers)?;

    // Limit 1: the wire body, i.e. bytes actually read from the socket.
    let wire = axum::body::to_bytes(body, state.config.max_body_bytes)
        .await
        .map_err(|_| {
            IngestError::payload_too_large(format!(
                "request body exceeds max_body_bytes ({} bytes)",
                state.config.max_body_bytes
            ))
        })?;

    // Limit 2: the decompressed stream. Enforced *during* decompression, so a bomb is abandoned
    // rather than buffered — the whole point of keeping the two limits separate (SPEC §4.2).
    let payload = if gzipped {
        decompress_gzip(&wire, state.config.max_decompressed_bytes)?
    } else {
        wire.to_vec()
    };

    let request = ExportLogsServiceRequest::decode(payload.as_slice())
        .map_err(|e| IngestError::bad_request(format!("malformed ExportLogsServiceRequest: {e}")))?;

    let (measurements, rejections) = to_measurements(&request, processed_time);
    let accepted = measurements.len();

    if !measurements.is_empty() {
        state
            .writer
            .write(measurements)
            .await
            .map_err(|e| IngestError::unavailable(format!("storage write failed: {e}")))?;
    }

    if rejections.is_empty() {
        tracing::info!(accepted, "ingested batch");
    } else {
        tracing::info!(accepted, rejected = rejections.total(), "ingested batch with rejections");
    }

    // Partial success is reported on a 200 even when every record was rejected: that is what OTLP
    // prescribes, and it stops clients retrying data that will never be accepted (SPEC §4.3).
    let response = ExportLogsServiceResponse {
        partial_success: (!rejections.is_empty()).then(|| ExportLogsPartialSuccess {
            rejected_log_records: rejections.total(),
            error_message: rejections.message(),
        }),
    };

    Ok((StatusCode::OK, [(header::CONTENT_TYPE, PROTOBUF)], response.encode_to_vec())
        .into_response())
}

fn require_protobuf_content_type(headers: &HeaderMap) -> Result<(), IngestError> {
    let raw = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| IngestError::unsupported_media_type("missing Content-Type; expected application/x-protobuf"))?;

    // Tolerate parameters such as `; charset=utf-8`, which some HTTP clients append.
    let base = raw.split(';').next().unwrap_or("").trim();
    if !base.eq_ignore_ascii_case(PROTOBUF) {
        return Err(IngestError::unsupported_media_type(format!(
            "unsupported Content-Type {raw:?}; expected application/x-protobuf"
        )));
    }
    Ok(())
}

/// Unrecognised encodings are rejected rather than treated as `identity`, so a client configured
/// for `zstd` fails visibly instead of having its payload misread as corrupt protobuf.
fn gzip_requested(headers: &HeaderMap) -> Result<bool, IngestError> {
    let Some(raw) = headers.get(header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()) else {
        return Ok(false);
    };
    match raw.trim() {
        "" | "identity" => Ok(false),
        "gzip" => Ok(true),
        other => Err(IngestError::unsupported_media_type(format!(
            "unsupported Content-Encoding {other:?}; only gzip and identity are accepted"
        ))),
    }
}

/// Decompresses with a hard ceiling, reading one byte past the limit to detect overrun without
/// materialising the whole stream.
fn decompress_gzip(input: &[u8], limit: usize) -> Result<Vec<u8>, IngestError> {
    let mut out = Vec::new();
    let mut decoder = GzDecoder::new(input).take(limit as u64 + 1);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| IngestError::bad_request(format!("body is not valid gzip: {e}")))?;

    if out.len() > limit {
        return Err(IngestError::payload_too_large(format!(
            "decompressed body exceeds max_decompressed_bytes ({limit} bytes)"
        )));
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
        let err = require_protobuf_content_type(&headers(&[("content-type", "application/json")]))
            .unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let err = require_protobuf_content_type(&HeaderMap::new()).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
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
        let err = decompress_gzip(b"definitely not gzip", 1 << 20).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    /// SPEC §4.2: a small compressed payload that expands past the ceiling must be refused, and
    /// refused without first materialising the whole expansion.
    #[test]
    fn gzip_bomb_is_refused_at_the_decompressed_limit() {
        let bomb = gzip(&vec![0u8; 64 << 20]); // 64 MiB of zeros
        assert!(bomb.len() < 200_000, "test bomb should be small on the wire: {}", bomb.len());

        let limit = 1 << 20;
        let err = decompress_gzip(&bomb, limit).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn decompressed_limit_boundary_is_exact() {
        let exactly = vec![7u8; 1000];
        assert!(decompress_gzip(&gzip(&exactly), 1000).is_ok(), "at the limit must pass");
        assert_eq!(
            decompress_gzip(&gzip(&exactly), 999).unwrap_err().status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "one byte over must fail"
        );
    }
}
