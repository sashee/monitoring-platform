//! Sending a corrected batch on (design §3). One connection, kept between flushes.
//!
//! `hyper`'s connection API directly over an already-connected stream, rather than a
//! `hyper-util` client with a connector: the two targets are a unix socket and a plain TCP socket,
//! both of which are one line to open, and writing a `tower::Service<Uri>` connector to reach the
//! former would be more code than the whole module.
//!
//! The connection is **kept** rather than reopened per batch. It was not always, and the reason it
//! changed is worth recording: while the only target was the receiver's own socket on the same host,
//! `connect` cost a `connect(2)` in the same kernel and holding one open would have bought nothing.
//! That stops being true the moment anything sits in the path. A tunnel's local socket accepts
//! instantly and hides a peer round trip behind it, and the cost is paid *per batch* — twice a
//! second at idle, and once per batch while draining a backlog one at a time.
//!
//! Still no pool, though: the flush task sends strictly one batch at a time, in order, so a second
//! connection would have nothing to carry.

use anyhow::{Context, Result, anyhow, bail};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use prost::Message;
use std::future::Future;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinHandle;

use crate::config::{LOGS_PATH, Target};

pub const PROTOBUF: &str = "application/x-protobuf";

/// A live HTTP/1.1 connection, held across flushes.
struct Conn {
    sender: SendRequest<Full<Bytes>>,
    /// Drives the socket for as long as the connection lives — it no longer ends with one exchange,
    /// so it belongs to the connection rather than to a request. The sender cannot make progress
    /// without it, so the two must not be separated.
    pump: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Ships batches to the configured target.
pub struct Forwarder {
    target: Target,
    timeout: Duration,
    /// The `Authorization` header, built once. `None` sends none at all, which is what an
    /// unconfigured collector does — and what the receiver tolerates until enforcement (SPEC §13).
    authorization: Option<HeaderValue>,
    /// Kept from the last successful send. `None` when there is nothing worth reusing, which is
    /// also the state after any failure — a failed connection is never cached.
    live: Option<Conn>,
}

impl Forwarder {
    pub fn new(target: Target, timeout: Duration, api_key: Option<&str>) -> Self {
        let authorization = api_key.and_then(|key| {
            match HeaderValue::from_str(&format!("Bearer {key}")) {
                Ok(mut value) => {
                    // So the `http` crate prints it as `Sensitive` rather than verbatim if a
                    // `HeaderMap` ever reaches a `{:?}`.
                    value.set_sensitive(true);
                    Some(value)
                }
                // Unreachable: `config::validate` has already refused anything that is not a legal
                // header value. It must still not be a panic in the delivery path, and it must not be
                // silent either — sending unauthenticated is a thing an operator needs told.
                Err(e) => {
                    tracing::error!(error = %e, "the API key is not a legal header value; forwarding unauthenticated");
                    None
                }
            }
        });

        Self { target, timeout, authorization, live: None }
    }

    /// Encodes and POSTs one batch, giving up after the configured timeout.
    ///
    /// A non-2xx response is an error, so the caller keeps the batch and retries — which is safe
    /// precisely because the correction is frozen: the retry hashes identically at the receiver
    /// and deduplicates rather than landing as a second row (SPEC.md §6.6).
    ///
    /// Connect and exchange are bounded together as one attempt, because which of the two stalls
    /// depends on what is in the path and neither is bounded by default.
    pub async fn send(&mut self, request: &ExportLogsServiceRequest) -> Result<()> {
        let request = self.request(Bytes::from(request.encode_to_vec()))?;
        let reused = self.take_live();

        // Reborrowed immutably so the attempt can be one `async move` block: the connection it
        // yields borrows nothing, which is what leaves `self` free to cache it below.
        let this = &*self;
        let conn = this
            .bounded(async move {
                let mut conn = match reused {
                    Some(conn) => conn,
                    None => this.connect().await?,
                };
                exchange(&mut conn, request, &this.target).await?;
                Ok(conn)
            })
            .await?;

        // Cached only on success, so a connection that failed is never handed to the next batch.
        self.live = Some(conn);
        Ok(())
    }

    /// The kept connection, unless the peer has closed it.
    ///
    /// Deciding this *before* a batch is committed to the connection is what makes the reuse safe.
    /// The tempting alternative — send, and reconnect and re-send if it fails — cannot tell a
    /// connection the peer reaped from a batch the receiver looked at and refused, so it would
    /// answer a rejection by delivering the batch a second time to be rejected again.
    ///
    /// A synchronous check is enough for the case that matters. A server giving up an idle
    /// connection either announces it with `Connection: close`, which hyper records as it parses the
    /// response, or closes the socket while it sits unused, which the pump task observes.
    ///
    /// What remains is the race where the close lands mid-exchange. That surfaces as an ordinary
    /// delivery failure and succeeds on the next cycle — the right price for never re-sending a
    /// batch the receiver may already have answered.
    fn take_live(&mut self) -> Option<Conn> {
        let conn = self.live.take()?;
        if conn.sender.is_closed() || conn.pump.is_finished() {
            tracing::debug!("the kept connection was closed by the peer; reconnecting");
            return None;
        }
        Some(conn)
    }

    /// The timeout, in one place. It is the only detector for a target that accepts a connection and
    /// then says nothing — which is what a proxy socket looks like when its far end is unreachable,
    /// and which without this would block the flush task indefinitely.
    async fn bounded<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::time::timeout(self.timeout, work).await.map_err(|_| {
            anyhow!("{} did not answer within {:?}", describe(&self.target), self.timeout)
        })?
    }

    fn request(&self, body: Bytes) -> Result<Request<Full<Bytes>>> {
        let (authority, path) = match &self.target {
            // The authority is ignored over a unix socket but HTTP/1.1 requires a Host header, and
            // "localhost" is what every OTLP-over-UDS client sends.
            Target::Unix(_) => ("localhost", LOGS_PATH),
            Target::Http { authority, path } => (authority.as_str(), path.as_str()),
        };

        let mut request = Request::post(path).header(HOST, authority).header(CONTENT_TYPE, PROTOBUF);
        if let Some(value) = &self.authorization {
            request = request.header(AUTHORIZATION, value.clone());
        }

        request.body(Full::new(body)).context("building the forward request")
    }

    async fn connect(&self) -> Result<Conn> {
        match &self.target {
            Target::Unix(path) => {
                let stream = UnixStream::connect(path)
                    .await
                    .with_context(|| format!("connecting to {}", path.display()))?;
                handshake(stream).await
            }
            Target::Http { authority, .. } => {
                let stream = TcpStream::connect(authority)
                    .await
                    .with_context(|| format!("connecting to {authority}"))?;
                handshake(stream).await
            }
        }
    }
}

/// Hands a connected stream to hyper and spawns the task that drives it.
async fn handshake<S>(stream: S) -> Result<Conn>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("HTTP/1.1 handshake")?;

    let pump = tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!(error = %e, "forwarding connection closed");
        }
    });

    Ok(Conn { sender, pump })
}

/// One request and its response over an existing connection.
async fn exchange(
    conn: &mut Conn,
    request: Request<Full<Bytes>>,
    target: &Target,
) -> Result<()> {
    conn.sender.ready().await.context("the connection is no longer usable")?;

    let response = conn.sender.send_request(request).await.context("sending the batch")?;
    let status = response.status();
    // Read the body out even on success: leaving it unread makes the peer's close look like an
    // abort in its logs, on failure it carries the receiver's protobuf `Status`, which is the only
    // explanation an operator gets — and now that the connection is kept, an unread body would
    // leave it mid-message and useless for the next batch.
    let body = response.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();

    if !status.is_success() {
        bail!("{} rejected the batch: {}", describe(target), detail(status, &body));
    }
    Ok(())
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    /// Long enough that it never fires on a local socket, so the tests that are not about the
    /// timeout are not racing it.
    const PATIENT: Duration = Duration::from_secs(10);

    const OK: &str = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
    /// Same, but asking for the connection back. A server reaping idle connections is ordinary, and
    /// this is how it says so.
    const OK_THEN_CLOSE: &str =
        "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

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

    /// What one fake server saw.
    struct Seen {
        raw: Arc<Mutex<Vec<u8>>>,
        /// Connections accepted. The whole point of keeping a connection is that this stops growing
        /// with the number of batches, so it has to be observable.
        accepts: Arc<AtomicUsize>,
    }

    impl Seen {
        async fn text(&self) -> String {
            String::from_utf8_lossy(&self.raw.lock().await.clone()).to_string()
        }

        fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }
    }

    /// An HTTP/1.1 server that answers **every** request on a connection with `response`, keeping
    /// the connection open unless the response asks to close it.
    ///
    /// Keep-alive is load-bearing in the fake, not incidental: the previous version answered one
    /// request per connection and closed, which would make every test here pass whether or not the
    /// forwarder reuses anything, and would hide a reuse regression completely.
    async fn serve(path: PathBuf, response: &'static str) -> Seen {
        let seen = Seen {
            raw: Arc::new(Mutex::new(Vec::new())),
            accepts: Arc::new(AtomicUsize::new(0)),
        };
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let sink = Arc::clone(&seen.raw);
        let accepts = Arc::clone(&seen.accepts);

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accepts.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(one_connection(stream, Arc::clone(&sink), response));
            }
        });
        seen
    }

    async fn one_connection(
        mut stream: tokio::net::UnixStream,
        sink: Arc<Mutex<Vec<u8>>>,
        response: &'static str,
    ) {
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 8192];

        loop {
            // Header first, then exactly `Content-Length` bytes. No pipelining to worry about: the
            // forwarder sends one batch at a time and waits for each response.
            let head = loop {
                if let Some(i) = position(&buf, b"\r\n\r\n") {
                    break i;
                }
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            let end = head + 4 + content_length(&buf[..head]);
            while buf.len() < end {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }

            sink.lock().await.extend_from_slice(&buf[..end]);
            buf.drain(..end);

            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
            if response.to_lowercase().contains("connection: close") {
                let _ = stream.shutdown().await;
                return;
            }
        }
    }

    fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn content_length(head: &[u8]) -> usize {
        String::from_utf8_lossy(head)
            .to_lowercase()
            .lines()
            .find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn posts_protobuf_to_the_otlp_logs_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve(path.clone(), OK).await;

        Forwarder::new(Target::Unix(path), PATIENT, None).send(&batch("cpu")).await.unwrap();

        let raw = seen.text().await;
        assert!(raw.starts_with("POST /v1/logs HTTP/1.1"), "unexpected request line: {raw:?}");
        assert!(raw.contains("content-type: application/x-protobuf"), "{raw:?}");
        assert!(raw.contains("host: localhost"), "HTTP/1.1 requires a Host header: {raw:?}");
        assert!(raw.contains("cpu"), "the encoded batch should be in the body: {raw:?}");
    }

    /// The key is presented as an RFC 6750 bearer token, on every batch (SPEC §13).
    #[tokio::test]
    async fn a_configured_key_is_sent_as_a_bearer_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve(path.clone(), OK).await;

        let key = "mpk_0001020304050607.\
                   808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0";
        Forwarder::new(Target::Unix(path), PATIENT, Some(key))
            .send(&batch("cpu"))
            .await
            .unwrap();

        let raw = seen.text().await;
        assert!(
            raw.to_lowercase().contains(&format!("authorization: bearer {key}")),
            "the key must reach the receiver: {raw:?}"
        );
    }

    /// And a collector with no key sends no header at all, rather than an empty or placeholder one —
    /// which the receiver would have to tell apart from a real attempt.
    #[tokio::test]
    async fn no_key_means_no_authorization_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve(path.clone(), OK).await;

        Forwarder::new(Target::Unix(path), PATIENT, None).send(&batch("cpu")).await.unwrap();

        assert!(
            !seen.text().await.to_lowercase().contains("authorization"),
            "an unconfigured collector must not mention authorization at all"
        );
    }

    /// The header is built once and reused, so it has to survive onto the second batch on a kept
    /// connection — the case where the request is constructed again but the forwarder is not.
    #[tokio::test]
    async fn the_key_is_sent_on_every_batch_over_a_kept_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve(path.clone(), OK).await;

        let key = "mpk_0001020304050607.\
                   808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0";
        let mut forwarder = Forwarder::new(Target::Unix(path), PATIENT, Some(key));
        forwarder.send(&batch("cpu")).await.unwrap();
        forwarder.send(&batch("mem")).await.unwrap();

        assert_eq!(seen.accepts(), 1, "the point is that this is one connection");
        assert_eq!(
            seen.text().await.to_lowercase().matches("authorization: bearer").count(),
            2,
            "both batches must carry the key"
        );
    }

    /// The point of workstream B: batch count and connection count are now decoupled.
    #[tokio::test]
    async fn several_batches_share_one_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve(path.clone(), OK).await;

        let mut forwarder = Forwarder::new(Target::Unix(path), PATIENT, None);
        for name in ["cpu", "mem", "disk"] {
            forwarder.send(&batch(name)).await.unwrap();
        }

        assert_eq!(seen.accepts(), 1, "three batches should have shared one connection");
        let raw = seen.text().await;
        for name in ["cpu", "mem", "disk"] {
            assert!(raw.contains(name), "{name} never arrived: {raw:?}");
        }
    }

    /// The common real failure once a connection is kept: the peer reaps it while it sits idle. It
    /// must cost a reconnect, not a reported failure — otherwise every idle timeout at the receiver
    /// would look like an outage and burn a backoff interval.
    #[tokio::test]
    async fn a_connection_the_peer_closed_is_replaced_without_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve(path.clone(), OK_THEN_CLOSE).await;

        let mut forwarder = Forwarder::new(Target::Unix(path), PATIENT, None);
        forwarder.send(&batch("cpu")).await.expect("the first batch");
        forwarder.send(&batch("mem")).await.expect("the second batch, after the peer closed");

        assert_eq!(seen.accepts(), 2, "the closed connection should have been replaced");
        let raw = seen.text().await;
        assert!(raw.contains("cpu") && raw.contains("mem"), "both batches must land: {raw:?}");
    }

    /// A rejection must be an error the caller can retry, and must name what went wrong: this is
    /// the only place an operator learns the receiver refused something.
    #[tokio::test]
    async fn a_rejection_is_an_error_carrying_the_receivers_explanation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        serve(
            path.clone(),
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 21\r\n\r\nstorage write failed!",
        )
        .await;

        let err = Forwarder::new(Target::Unix(path.clone()), PATIENT, None)
            .send(&batch("cpu"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("503"), "the status must survive: {err}");
        assert!(err.contains("storage write failed"), "the message must survive: {err}");
        assert!(err.contains(&path.display().to_string()), "the target must be named: {err}");
    }

    /// A rejection must not be cached as a usable connection, and must not be retried into a second
    /// delivery either: the receiver answered, so the answer stands.
    #[tokio::test]
    async fn a_rejection_is_reported_once_rather_than_retried_on_a_new_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let seen = serve(
            path.clone(),
            "HTTP/1.1 400 Bad Request\r\ncontent-length: 9\r\n\r\nmalformed",
        )
        .await;

        let mut forwarder = Forwarder::new(Target::Unix(path), PATIENT, None);
        assert!(forwarder.send(&batch("cpu")).await.is_err());

        assert_eq!(seen.accepts(), 1, "a rejection is not a stale connection; do not reconnect");
        assert_eq!(
            seen.text().await.matches("POST /v1/logs").count(),
            1,
            "the batch must not be delivered twice"
        );
    }

    /// The receiver being down is the ordinary case on a device that boots everything at once.
    /// It must be a plain error, not a panic, so the batch stays buffered for the next attempt.
    #[tokio::test]
    async fn an_unreachable_target_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let err = Forwarder::new(Target::Unix(dir.path().join("nothing-here.sock")), PATIENT, None)
            .send(&batch("cpu"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("connecting to"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn an_unresolvable_tcp_target_is_an_error() {
        let target = Target::Http { authority: "127.0.0.1:1".into(), path: LOGS_PATH.into() };
        assert!(Forwarder::new(target, PATIENT, None).send(&batch("cpu")).await.is_err());
    }

    /// A target that accepts and then says nothing. This is the failure a bare `connect` cannot
    /// see: put anything between the collector and the receiver — a tunnel, a proxy — and its local
    /// socket accepts whether or not the far end is reachable, so "the receiver is down" arrives as
    /// silence instead of `ECONNREFUSED`. Unbounded, it wedges the flush task forever.
    #[tokio::test]
    async fn a_silent_target_times_out_rather_than_hanging_forever() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            // Accepted and then held open, unanswered, for the life of the test.
            let (stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(stream);
        });

        let err = Forwarder::new(Target::Unix(path.clone()), Duration::from_millis(200), None)
            .send(&batch("cpu"))
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("did not answer"), "unexpected error: {err}");
        assert!(err.contains(&path.display().to_string()), "the target must be named: {err}");
    }

    /// The timeout must not fire on a receiver that answers promptly, which is every healthy local
    /// hop. A timeout tight enough to catch a slow write would make the collector re-send batches
    /// that already landed.
    #[tokio::test]
    async fn a_prompt_receiver_is_not_caught_by_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.sock");
        serve(path.clone(), OK).await;

        Forwarder::new(Target::Unix(path), Duration::from_millis(500), None)
            .send(&batch("cpu"))
            .await
            .unwrap();
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
