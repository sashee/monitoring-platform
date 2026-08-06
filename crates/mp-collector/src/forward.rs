//! Sending a corrected batch on (design §3). One connection per flush, no pool.
//!
//! `hyper`'s connection API directly over an already-connected stream, rather than a
//! `hyper-util` client with a connector: the two targets are a unix socket and a plain TCP socket,
//! both of which are one line to open, and writing a `tower::Service<Uri>` connector to reach the
//! former would be more code than the whole module.
//!
//! No pooling because flushes are seconds apart at their busiest and the local hop's connect cost
//! is a `connect(2)` on a socket in the same kernel.

use anyhow::{Context, Result, bail};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use crate::config::{LOGS_PATH, Target};

pub const PROTOBUF: &str = "application/x-protobuf";

/// Ships batches to the configured target.
#[derive(Debug, Clone)]
pub struct Forwarder {
    target: Target,
}

impl Forwarder {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Encodes and POSTs one batch.
    ///
    /// A non-2xx response is an error, so the caller keeps the batch and retries — which is safe
    /// precisely because the correction is frozen: the retry hashes identically at the receiver
    /// and deduplicates rather than landing as a second row (SPEC.md §6.6).
    pub async fn send(&self, request: &ExportLogsServiceRequest) -> Result<()> {
        let body = Bytes::from(request.encode_to_vec());
        match &self.target {
            Target::Unix(path) => {
                let stream = UnixStream::connect(path)
                    .await
                    .with_context(|| format!("connecting to {}", path.display()))?;
                // The authority is ignored over a unix socket but HTTP/1.1 requires a Host
                // header, and "localhost" is what every OTLP-over-UDS client sends.
                self.post(stream, "localhost", LOGS_PATH, body).await
            }
            Target::Http { authority, path } => {
                let stream = TcpStream::connect(authority)
                    .await
                    .with_context(|| format!("connecting to {authority}"))?;
                self.post(stream, authority, path, body).await
            }
        }
    }

    async fn post<S>(&self, stream: S, authority: &str, path: &str, body: Bytes) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .context("HTTP/1.1 handshake")?;

        // The connection task drives the socket while the request is in flight. It ends when the
        // response is complete, so nothing outlives this call.
        let pump = tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(error = %e, "forwarding connection closed");
            }
        });

        let request = Request::post(path)
            .header(HOST, authority)
            .header(CONTENT_TYPE, PROTOBUF)
            .body(Full::new(body))
            .context("building the forward request")?;

        let result = async {
            let response = sender.send_request(request).await.context("sending the batch")?;
            let status = response.status();
            // Read the body out even on success: leaving it unread makes the peer's close look
            // like an abort in its logs, and on failure it carries the receiver's protobuf
            // `Status`, which is the only explanation an operator gets.
            let body = response.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();

            if !status.is_success() {
                bail!("{} rejected the batch: {}", describe(&self.target), detail(status, &body));
            }
            Ok(())
        }
        .await;

        drop(sender);
        let _ = pump.await;
        result
    }
}

fn describe(target: &Target) -> String {
    match target {
        Target::Unix(path) => path.display().to_string(),
        Target::Http { authority, .. } => authority.clone(),
    }
}

/// The receiver answers errors with a protobuf `Status`, which is not worth a dependency to
/// decode here — but the printable runs in it carry the message, so a lossy rendering is far more
/// useful to an operator than the status code alone.
fn detail(status: StatusCode, body: &[u8]) -> String {
    let text: String = body
        .iter()
        .map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { ' ' })
        .collect();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() { status.to_string() } else { format!("{status} ({text})") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    fn batch(name: &str) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord { event_name: name.into(), ..Default::default() }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
    }

    /// A one-shot HTTP/1.1 server that records what it was sent and answers with `response`.
    async fn serve_once(path: PathBuf, response: &'static str) -> Arc<Mutex<Vec<u8>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let sink = Arc::clone(&seen);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            // One read is enough: the batches here are a few dozen bytes and arrive in one write.
            let n = stream.read(&mut buf).await.unwrap();
            sink.lock().await.extend_from_slice(&buf[..n]);
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        seen
    }

    #[tokio::test]
    async fn posts_protobuf_to_the_otlp_logs_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve_once(
            path.clone(),
            "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;

        Forwarder::new(Target::Unix(path)).send(&batch("cpu")).await.unwrap();

        let raw = String::from_utf8_lossy(&seen.lock().await.clone()).to_string();
        assert!(raw.starts_with("POST /v1/logs HTTP/1.1"), "unexpected request line: {raw:?}");
        assert!(raw.contains("content-type: application/x-protobuf"), "{raw:?}");
        assert!(raw.contains("host: localhost"), "HTTP/1.1 requires a Host header: {raw:?}");
        assert!(raw.contains("cpu"), "the encoded batch should be in the body: {raw:?}");
    }

    /// A rejection must be an error the caller can retry, and must name what went wrong: this is
    /// the only place an operator learns the receiver refused something.
    #[tokio::test]
    async fn a_rejection_is_an_error_carrying_the_receivers_explanation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        serve_once(
            path.clone(),
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 21\r\nconnection: close\r\n\r\nstorage write failed!",
        )
        .await;

        let err = Forwarder::new(Target::Unix(path.clone()))
            .send(&batch("cpu"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("503"), "the status must survive: {err}");
        assert!(err.contains("storage write failed"), "the message must survive: {err}");
        assert!(err.contains(&path.display().to_string()), "the target must be named: {err}");
    }

    /// The receiver being down is the ordinary case on a device that boots everything at once.
    /// It must be a plain error, not a panic, so the batch stays buffered for the next attempt.
    #[tokio::test]
    async fn an_unreachable_target_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let err = Forwarder::new(Target::Unix(dir.path().join("nothing-here.sock")))
            .send(&batch("cpu"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("connecting to"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn an_unresolvable_tcp_target_is_an_error() {
        let target = Target::Http { authority: "127.0.0.1:1".into(), path: LOGS_PATH.into() };
        assert!(Forwarder::new(target).send(&batch("cpu")).await.is_err());
    }

    #[test]
    fn a_binary_body_still_produces_a_readable_explanation() {
        assert_eq!(detail(StatusCode::BAD_REQUEST, b""), "400 Bad Request");
        assert_eq!(
            detail(StatusCode::BAD_REQUEST, b"\x08\x03\x12\x0bmalformed\x00\x00"),
            "400 Bad Request (malformed)",
            "protobuf framing bytes should collapse away, leaving the message"
        );
    }
}
