//! `Content-Encoding: gzip` on the way out, when the client asked for it (SPEC §8.3).
//!
//! The counterpart to §4.2's inbound decompression, and it exists for the same reason: iroh's QUIC
//! streams carry no transport-level compression, so this is the only lever on the bytes a phone has to
//! pull down. The explorer is what makes it worth having — one 30-day page with four grouped charts is
//! ~651 KB of inline SVG, and gzip takes that to ~141 KB.
//!
//! **Hand-rolled rather than `tower-http`'s `CompressionLayer`**, consistently with §10.2: `flate2` is
//! already a dependency for the ingest path, the policy below is three decisions long, and the crate
//! `CompressionLayer` lives in is the one §4.2 already declined for the size limits.
//!
//! **Not applied to ingest.** That route's responses are an empty protobuf on success and a
//! `google.rpc.Status` on failure — tens of bytes, below the threshold anyway — and §4.1.1 pins their
//! encoding for OTLP conformance. A `Content-Encoding` there would be a conformance question with no
//! payoff, so the layer is applied to the browser pages and the JSON read API only.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write as _;

/// Bodies below this are sent as they are.
///
/// gzip costs an 18-byte envelope plus deflate's own block overhead, so on a small body it can add
/// bytes rather than remove them — and every response under this size here is a redirect, a cleared
/// cookie or a one-line error, where the round trip is the cost and the payload is not.
pub const MIN_COMPRESS_BYTES: usize = 1024;

/// The ceiling on a response body this layer will buffer.
///
/// Compression needs the whole body, so it has to be collected before it can be encoded. Nothing in
/// this service streams — every handler builds a `String` or a `Vec<u8>` and hands it over complete, so
/// collecting is a move rather than a copy and this limit is unreachable today. It exists so that a
/// future streaming handler placed behind this layer fails visibly instead of buffering without bound.
pub const MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// Whether the client said it can decode gzip.
///
/// A pure function over the header value, so the parsing rules below are testable without a server.
///
/// `q=0` means "not acceptable" and is the one part of the grammar that must not be skipped: it is how
/// a client disables an encoding it would otherwise be offered, and reading it as mere presence would
/// send gzip to a client that explicitly refused it. A `*` stands in only when there is no explicit
/// `gzip` entry, since the specific entry is the one that speaks about gzip.
///
/// Only `gzip` is recognised, not the legacy `x-gzip` alias: browsers and the read API's clients send
/// `gzip`, and an alias no current client emits would be an untested branch.
pub fn accepts_gzip(accept_encoding: Option<&str>) -> bool {
    let Some(raw) = accept_encoding else {
        return false;
    };

    let mut wildcard = None;
    for entry in raw.split(',') {
        let mut parts = entry.split(';');
        let token = parts.next().unwrap_or_default().trim();

        // A malformed or absent `q` is q=1. RFC 9110 says an unparseable parameter is ignored, which
        // drops the parameter rather than the entry it was attached to.
        let acceptable = parts
            .map(str::trim)
            .find_map(|p| {
                let (key, value) = p.split_once('=')?;
                key.trim().eq_ignore_ascii_case("q").then(|| value.trim())
            })
            .is_none_or(|q| q.parse::<f32>().ok().is_none_or(|q| q > 0.0));

        if token.eq_ignore_ascii_case("gzip") {
            return acceptable;
        }
        if token == "*" {
            wildcard = Some(acceptable);
        }
    }
    wildcard.unwrap_or(false)
}

/// Whether a body is worth the CPU: a text media type, and big enough to repay the envelope.
///
/// An allow-list of types rather than a deny-list. What this service returns is HTML, JSON and
/// `text/plain`, all of which compress several-fold; anything else appearing here later is unknown to
/// this function and is better sent untouched than assumed compressible — re-compressing an already
/// compressed format spends CPU to add bytes.
pub fn worth_compressing(content_type: Option<&str>, body_len: usize) -> bool {
    if body_len < MIN_COMPRESS_BYTES {
        return false;
    }
    let Some(raw) = content_type else {
        return false;
    };
    // Media types are case-insensitive, and the parameters (`; charset=utf-8`) are not part of the
    // comparison.
    let essence = raw.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    essence.starts_with("text/") || essence == "application/json" || essence.ends_with("+json")
}

/// Compresses a response body when the client asked for gzip and the body is worth it.
///
/// `Vary: Accept-Encoding` goes on every response through this layer, compressed or not, because the
/// answer now depends on a request header: without it a cache between here and the browser could hand
/// a gzipped page to a client that never asked for one. Nothing in this service sets `Vary` elsewhere,
/// so this is the only writer of it.
pub async fn gzip_responses(request: Request, next: Next) -> Response {
    // Read before the await and owned, for the reason `web::origin::guard` spells out: a live borrow of
    // the request across the await makes this future non-`Send` and the router refuses the layer.
    let accepted =
        accepts_gzip(request.headers().get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()));

    let response = next.run(request).await;

    // A handler that encoded its own body owns that decision; double-encoding would corrupt it.
    let already_encoded = response.headers().contains_key(header::CONTENT_ENCODING);
    let content_type =
        response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_owned);

    let (mut parts, body) = response.into_parts();
    parts.headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));

    if !accepted || already_encoded {
        return Response::from_parts(parts, body);
    }

    // The body is consumed here, so every path below has to rebuild a response rather than return the
    // original — including the paths that decide not to compress.
    let bytes = match axum::body::to_bytes(body, MAX_BUFFER_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "could not collect a response body to compress it");
            return (StatusCode::INTERNAL_SERVER_ERROR, "response too large to encode\n")
                .into_response();
        }
    };

    if !worth_compressing(content_type.as_deref(), bytes.len()) {
        return Response::from_parts(parts, Body::from(bytes));
    }

    // `Compression::default()` is level 6. Measured on the 651 KB explorer page that motivated this:
    // level 1 gives 3.5x for 6 ms, level 6 gives 4.6x for 29 ms, level 9 gives 4.8x for 101 ms. The
    // default is the knee — level 9 more than triples the CPU for another 4%, and over a phone link the
    // 46 KB level 6 saves over level 1 is worth more than the 23 ms it costs.
    let compressed = match encode(&bytes) {
        Ok(compressed) => compressed,
        // Recoverable, because the uncompressed body is still in hand: a failure to compress is not a
        // reason to fail the request.
        Err(error) => {
            tracing::warn!(%error, "gzip encoding failed; sending the response uncompressed");
            return Response::from_parts(parts, Body::from(bytes));
        }
    };

    // Incompressible input can come out larger. Rare above the threshold for text, but the check is
    // cheaper than the bytes it saves in the case where it fires.
    if compressed.len() >= bytes.len() {
        return Response::from_parts(parts, Body::from(bytes));
    }

    parts.headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    // The inherited `Content-Length` describes the body we just replaced, so it must be restated rather
    // than left: a stale one desynchronises the connection.
    parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(compressed.len()));
    Response::from_parts(parts, Body::from(compressed))
}

fn encode(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    encoder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_gzip_offer_is_accepted() {
        assert!(accepts_gzip(Some("gzip")));
        assert!(accepts_gzip(Some("gzip, deflate")));
        assert!(accepts_gzip(Some("deflate, gzip, br")));
        // What a phone browser actually sends.
        assert!(accepts_gzip(Some("gzip, deflate, br, zstd")));
    }

    #[test]
    fn absence_means_no() {
        assert!(!accepts_gzip(None));
        assert!(!accepts_gzip(Some("")));
        assert!(!accepts_gzip(Some("deflate, br")));
    }

    /// The case that separates parsing the grammar from searching for a substring: `q=0` is how a
    /// client refuses an encoding, and sending gzip anyway would be sending it something it said it
    /// cannot read.
    #[test]
    fn a_zero_q_value_is_a_refusal() {
        assert!(!accepts_gzip(Some("gzip;q=0")));
        assert!(!accepts_gzip(Some("gzip;q=0.0")));
        assert!(!accepts_gzip(Some("deflate, gzip;q=0")));
        assert!(!accepts_gzip(Some("gzip; q=0")));
        assert!(accepts_gzip(Some("gzip;q=0.001")));
        assert!(accepts_gzip(Some("gzip;q=1.0")));
    }

    #[test]
    fn a_wildcard_stands_in_only_where_gzip_is_not_named() {
        assert!(accepts_gzip(Some("*")));
        assert!(accepts_gzip(Some("deflate, *")));
        assert!(!accepts_gzip(Some("*;q=0")));
        // The explicit entry wins over the wildcard, whichever order they arrive in.
        assert!(!accepts_gzip(Some("*, gzip;q=0")));
        assert!(!accepts_gzip(Some("gzip;q=0, *")));
    }

    /// Tokens are case-insensitive, and whitespace around them is not significant.
    #[test]
    fn tokens_are_matched_loosely() {
        assert!(accepts_gzip(Some("GZIP")));
        assert!(accepts_gzip(Some("  gzip  ,  deflate ")));
        assert!(accepts_gzip(Some("Deflate, GZip")));
    }

    /// An unparseable `q` drops the parameter, not the entry — so the default of q=1 applies.
    #[test]
    fn a_malformed_q_value_does_not_reject_the_entry() {
        assert!(accepts_gzip(Some("gzip;q=banana")));
        assert!(accepts_gzip(Some("gzip;level=9")));
    }

    #[test]
    fn only_text_types_above_the_threshold_are_compressed() {
        let big = MIN_COMPRESS_BYTES;
        assert!(worth_compressing(Some("text/html; charset=utf-8"), big));
        assert!(worth_compressing(Some("application/json"), big));
        assert!(worth_compressing(Some("text/plain; charset=utf-8"), big));
        assert!(worth_compressing(Some("application/problem+json"), big));
        // Case-insensitive, as media types are.
        assert!(worth_compressing(Some("TEXT/HTML"), big));
    }

    #[test]
    fn small_bodies_and_binary_types_are_left_alone() {
        assert!(!worth_compressing(Some("text/html"), MIN_COMPRESS_BYTES - 1));
        assert!(!worth_compressing(Some("application/x-protobuf"), MIN_COMPRESS_BYTES));
        assert!(!worth_compressing(Some("image/png"), MIN_COMPRESS_BYTES));
        assert!(!worth_compressing(None, MIN_COMPRESS_BYTES));
    }

    /// The round trip, so a mistake in the encoder shows up here rather than as an unreadable page.
    #[test]
    fn what_is_encoded_decodes_back_to_the_input() {
        use std::io::Read as _;

        let original = "<p>a repetitive little page</p>".repeat(200).into_bytes();
        let compressed = encode(&original).unwrap();
        assert!(compressed.len() < original.len(), "{} vs {}", compressed.len(), original.len());

        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..]).read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, original);
    }
}
