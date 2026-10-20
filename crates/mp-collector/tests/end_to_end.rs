//! End to end over real sockets, driving the compiled binary.
//!
//! The case worth proving is the one the whole design exists for: a record stamped from a clock
//! that is three days behind must arrive downstream with a correct timestamp. Reaching it needs no
//! privilege and no fake clock — **seeding the persisted epoch table is enough**. The collector
//! cannot tell a stale offset it read from disk from one it observed live, so a table saying "this
//! host's clock was three days behind until a moment ago" puts it in exactly the state a
//! Raspberry Pi is in after `fake-hwclock` and an NTP step.
//!
//! Everything here also covers what the unit tests structurally cannot: process startup, socket
//! lifecycle, readiness, peer credentials over a real connection, and the forwarding hop.

use mp_collector::correct::{
    ATTR_AUTHORITATIVE, ATTR_EVENT_BOOTTIME, ATTR_RECEIPT_BOOTTIME, ATTR_RESOLUTION,
};
use mp_collector::epoch::{Epoch, EpochTable, Source};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use prost::Message;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Every `mp.clock.*` attribute left on a record. An ordinary corrected record carries none: the
/// collector stamps by exception (design §9.1), so "this was fine" is said by absence.
fn clock_attrs(r: &opentelemetry_proto::tonic::logs::v1::LogRecord) -> Vec<&str> {
    r.attributes.iter().map(|kv| kv.key.as_str()).filter(|k| k.starts_with("mp.clock.")).collect()
}

const SEC: i64 = 1_000_000_000;
const THREE_DAYS: i64 = 3 * 86_400 * SEC;

/// Generous on purpose: these assert that things *happen*, not how fast. A dead child is detected
/// on every iteration, so a real fault still fails immediately rather than waiting this out.
fn budget() -> Duration {
    Duration::from_secs(
        std::env::var("MP_TEST_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60),
    )
}

// ---------------------------------------------------------------------------- the fake receiver

/// Stands in for `monitoring-platform`: accepts OTLP/HTTP protobuf and remembers it.
struct Sink {
    path: PathBuf,
    received: Arc<Mutex<Vec<ExportLogsServiceRequest>>>,
    /// Connections accepted. The collector keeps one open, so this must not grow with the number of
    /// batches — and it is the only thing here that would notice if the receiving side ever started
    /// closing after each response.
    accepts: Arc<AtomicUsize>,
}

impl Sink {
    fn start(path: PathBuf) -> Sink {
        let listener = UnixListener::bind(&path).expect("binding the sink socket");
        let received = Arc::new(Mutex::new(Vec::new()));
        let accepts = Arc::new(AtomicUsize::new(0));
        let sink = Arc::clone(&received);
        let counter = Arc::clone(&accepts);

        // A thread per connection rather than one accept loop handling them in turn: the collector
        // keeps its connection open now, so serving them serially would park the loop on the first
        // one and never notice a second.
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || serve_posts(stream, &sink));
            }
        });
        Sink { path, received, accepts }
    }

    /// Waits for a batch containing a record of this type, so the health events the collector
    /// emits on its own schedule cannot be mistaken for the batch under test.
    fn wait_for(&self, event_name: &str) -> LogRecord {
        let deadline = Instant::now() + budget();
        while Instant::now() < deadline {
            if let Some(record) = self.find(event_name) {
                return record;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("no {event_name:?} record arrived within {:?}", budget());
    }

    fn find(&self, event_name: &str) -> Option<LogRecord> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .flat_map(|r| &r.resource_logs)
            .flat_map(|r| &r.scope_logs)
            .flat_map(|s| &s.log_records)
            .find(|r| r.event_name == event_name)
            .cloned()
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn count(&self, event_name: &str) -> usize {
        self.received
            .lock()
            .unwrap()
            .iter()
            .flat_map(|r| &r.resource_logs)
            .flat_map(|r| &r.scope_logs)
            .flat_map(|s| &s.log_records)
            .filter(|r| r.event_name == event_name)
            .count()
    }
}

/// A sink whose *first* connection is accepted and then never answered, and whose later ones behave
/// normally.
///
/// This is the failure a bare `connect` cannot see, and the one the iroh tunnel will make ordinary:
/// put a proxy between the collector and the receiver and its local socket accepts whether or not
/// the far end is reachable, so an unreachable receiver arrives as silence rather than
/// `ECONNREFUSED`. Dropping the connection instead would test the refusal path, which already
/// worked.
fn start_sink_silent_once(path: &Path) -> Arc<Mutex<Vec<ExportLogsServiceRequest>>> {
    let listener = UnixListener::bind(path).expect("binding the sink socket");
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);

    std::thread::spawn(move || {
        for (n, stream) in listener.incoming().flatten().enumerate() {
            if n == 0 {
                // Parked on its own thread so the accept loop keeps serving the retry.
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(3600));
                    drop(stream);
                });
                continue;
            }
            serve_posts(stream, &sink);
        }
    });
    received
}

/// Answers every POST on one connection, keeping it open until the peer closes it.
///
/// Keep-alive here is load-bearing rather than incidental: the collector reuses its connection, so a
/// fake that closed after one request would put every test through the reconnect path instead of the
/// one written for it, and would make a reuse regression invisible from here.
fn serve_posts(mut stream: UnixStream, sink: &Mutex<Vec<ExportLogsServiceRequest>>) {
    while let Some(request) = read_one_post(&mut stream) {
        sink.lock().unwrap().push(request);
    }
}

fn read_one_post(stream: &mut UnixStream) -> Option<ExportLogsServiceRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok()?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut body_starts_at = None;
    let mut content_length = 0usize;

    loop {
        // Header first, then exactly `Content-Length` bytes. No pipelining to worry about: the
        // collector sends one batch at a time and waits for each response, so a read can never run
        // past the end of the request in hand.
        if body_starts_at.is_none()
            && let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n")
        {
            let head = String::from_utf8_lossy(&raw[..i]).to_lowercase();
            content_length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            body_starts_at = Some(i + 4);
        }
        if let Some(start) = body_starts_at
            && raw.len() >= start + content_length
        {
            let request = ExportLogsServiceRequest::decode(&raw[start..start + content_length]);
            // No `connection: close`: the connection goes back for the next batch.
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            let _ = stream.flush();
            return request.ok();
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
}

// -------------------------------------------------------------------------------- the collector

struct Collector {
    child: Child,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}

impl Collector {
    /// Starts the binary, optionally with an epoch table already on disk.
    /// Also returns `CLOCK_BOOTTIME` as it stood immediately before the spawn. That instant is
    /// the fixture's anchor: it is after this test process started and before the collector took
    /// its own first clock reading, which is exactly the window a pre-collector record occupies.
    fn start(seed: Option<&EpochTable>) -> (Collector, Sink, i64) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("c.sock");
        let state = dir.path().join("state");
        let sink = Sink::start(dir.path().join("sink.sock"));

        if let Some(table) = seed {
            let boot_id = mp_host::clock::boot_id().unwrap();
            mp_collector::state::save(&state.join("epochs.json"), &boot_id, table)
                .expect("seeding the epoch table");
        }

        let before_spawn = mp_host::clock::now_boottime().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_mp-collector"))
            .arg("--socket")
            .arg(&socket)
            .arg("--forward-to")
            .arg(&sink.path)
            .arg("--state-dir")
            .arg(&state)
            // Short, so the test is not waiting out a production batching window.
            .args(["--grace-millis", "100"])
            // The build sandbox has no journal, and seeding covers what it would have found.
            .args(["--journal-backfill", "false"])
            .args(["--log-level", "warn"])
            .spawn()
            .expect("spawning mp-collector");

        let mut collector = Collector { child, socket, _dir: dir };
        collector.wait_until_ready();
        (collector, sink, before_spawn)
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + budget();
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("the collector exited before becoming ready: {status}");
            }
            if let Ok((200, body)) = self.try_get("/healthz") {
                // Ready is not enough: the buffer is only released once the clock has been read
                // often enough to satisfy the hysteresis, and a test that posts before then is
                // testing the timeout path by accident.
                if String::from_utf8_lossy(&body).contains("\"ever_synchronized\":true") {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the collector did not report a synchronized clock within {:?}", budget());
    }

    fn try_get(&self, path: &str) -> std::io::Result<(u16, Vec<u8>)> {
        self.request(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .into_bytes(),
        )
    }

    fn post(&self, request: &ExportLogsServiceRequest) -> (u16, Vec<u8>) {
        let body = request.encode_to_vec();
        let mut raw = format!(
            "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/x-protobuf\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(&body);
        self.request(raw).expect("posting to the collector")
    }

    fn request(&self, raw: Vec<u8>) -> std::io::Result<(u16, Vec<u8>)> {
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(&raw)?;
        stream.flush()?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;

        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(response.len());
        let status = String::from_utf8_lossy(&response[..split])
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
            .unwrap_or(0);
        Ok((status, response[(split + 4).min(response.len())..].to_vec()))
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------------------------- fixtures

fn now_realtime() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64
}

/// The offset this host is actually running with.
fn true_offset() -> i64 {
    mp_host::clock::sample().unwrap().offset()
}

fn batch(event_name: &str, time: i64, attributes: Vec<KeyValue>) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: time as u64,
                    observed_time_unix_nano: time as u64,
                    event_name: event_name.to_owned(),
                    attributes,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn attr(record: &LogRecord, key: &str) -> Option<Value> {
    record.attributes.iter().rev().find(|kv| kv.key == key)?.value.clone()?.value
}

fn bool_attr(key: &str, value: bool) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue { value: Some(Value::BoolValue(value)) }),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------------------- tests

/// **The test this whole thing exists for.**
///
/// A record stamped by a clock three days behind goes in; a record stamped with the correct time
/// comes out. Nothing here fakes a clock: the seeded epoch table is the same evidence the
/// collector would have gathered from journald or from its own cancel-on-set watch.
#[test]
fn a_record_from_a_three_day_stale_clock_arrives_corrected() {
    let stale_offset = true_offset() - THREE_DAYS;
    // "The clock was three days behind from boot until now." The collector adds the step itself:
    // its own first reading sees the true offset and opens a second epoch, which is exactly the
    // shape journald leaves behind after `fake-hwclock` and an NTP correction.
    let seed = EpochTable::new(Epoch { boot_start: 0, offset: stale_offset, source: Source::Journal });

    let (collector, sink, before_spawn) = Collector::start(Some(&seed));

    // The record has to belong to the *stale* epoch, which ends where the collector's own first
    // reading begins. `before_spawn` is the last instant that is certainly inside it — and it is
    // certainly after this process started, so the `[sender_started, received]` window holds too.
    let stamped = before_spawn + stale_offset;
    assert_eq!(collector.post(&batch("cpu", stamped, vec![])).0, 200);

    let out = sink.wait_for("cpu");
    // Corrected exactly, from a synchronized clock: the record says nothing about it, because the
    // corrected timestamp is the output (design §9.1).
    assert!(clock_attrs(&out).is_empty(), "expected no clock attributes, got {:?}", clock_attrs(&out));

    let corrected = out.time_unix_nano as i64;
    let residual = (corrected - stamped - THREE_DAYS).abs();

    // Sub-microsecond rather than exact, and the residual is a fixture artefact rather than a
    // property of the collector: the seeded offset came from *this* process's clock read and the
    // collector projected with one taken in its own, so the two differ by the interleave between
    // two `clock_gettime` pairs. Roughly 500 ns, three orders of magnitude below the accuracy this
    // design targets, which is bounded by the application-to-collector delay.
    //
    // `a_correct_clock_round_trips_the_timestamp_exactly` is the exact version of this assertion:
    // within one process there is only one sample, and the round trip is the identity.
    assert!(
        residual < 10_000,
        "the correction should be the step to within a read interleave, but is off by {residual} ns \
         (stamped {stamped}, corrected {corrected})"
    );
    let drift = (corrected - now_realtime()).abs();
    assert!(drift < 60 * SEC, "the corrected timestamp should be near now, but is off by {drift} ns");

    // There was a third assertion here, reading `mp.clock.correction_ns` to check that the offset used
    // was the host's real one. That attribute is no longer stamped (design §9.1), and the check is not
    // worth reconstructing: it cannot be derived from the output — the record's boottime resolves
    // against the *stale* epoch, so `corrected - stamped` is the three-day step, not the offset — and
    // the two assertions above already pin the same behaviour more directly. `residual` says the
    // correction was the step, and `drift` says the result landed at the present moment; an offset that
    // was not the host's real one could satisfy neither.
}

/// The complement, and the stronger property: on a host whose clock is *right*, the round trip
/// through boottime and back must be the identity. Resolution and projection are separate pieces
/// of arithmetic, and this is what proves they agree.
#[test]
fn a_correct_clock_round_trips_the_timestamp_exactly() {
    let (collector, sink, _) = Collector::start(None);

    let stamped = now_realtime();
    assert_eq!(collector.post(&batch("exact_round_trip", stamped, vec![])).0, 200);

    let out = sink.wait_for("exact_round_trip");
    assert!(clock_attrs(&out).is_empty(), "expected no clock attributes, got {:?}", clock_attrs(&out));
    assert_eq!(
        out.time_unix_nano as i64, stamped,
        "resolve-then-project must be the identity when the offset has not moved"
    );
}

/// A timestamp from another frame — a remote server's `Date` header, a GPS fix, a replayed
/// archive — must survive untouched. This is the property that stops the collector corrupting
/// data it has no business rewriting.
#[test]
fn a_foreign_timestamp_passes_through_untouched() {
    let (collector, sink, _) = Collector::start(None);

    let historical = now_realtime() - 400 * 86_400 * SEC;
    assert_eq!(collector.post(&batch("historical", historical, vec![])).0, 200);

    let out = sink.wait_for("historical");
    assert_eq!(out.time_unix_nano as i64, historical, "a foreign frame was rewritten");
    // The exception that stays visible: a record that was NOT corrected keeps its resolution, so a
    // timestamp degrading to passthrough is detectable per row (design §4.2).
    assert_eq!(attr(&out, ATTR_RESOLUTION), Some(Value::StringValue("passthrough".into())));
    assert_eq!(clock_attrs(&out), vec!["mp.clock.resolution"], "and nothing besides");
}

/// Tier 2, over the wire. An application that knows better says so, and is believed.
#[test]
fn an_authoritative_record_is_not_touched() {
    let (collector, sink, _) = Collector::start(None);

    let stamped = now_realtime();
    let request = batch("authoritative", stamped, vec![bool_attr(ATTR_AUTHORITATIVE, true)]);
    assert_eq!(collector.post(&request).0, 200);

    let out = sink.wait_for("authoritative");
    assert_eq!(out.time_unix_nano as i64, stamped);
    assert_eq!(attr(&out, ATTR_RESOLUTION), Some(Value::StringValue("authoritative".into())));
    assert!(attr(&out, ATTR_AUTHORITATIVE).is_none(), "the hint must not reach the wire");
}

/// §6.1's cardinality hazard and the collector's own bookkeeping, checked on what actually
/// arrives rather than on an in-process value.
#[test]
fn no_internal_attribute_reaches_the_receiver() {
    let (collector, sink, _) = Collector::start(None);
    assert_eq!(collector.post(&batch("clean", now_realtime(), vec![])).0, 200);

    let out = sink.wait_for("clean");
    for internal in [ATTR_EVENT_BOOTTIME, ATTR_RECEIPT_BOOTTIME] {
        assert!(
            attr(&out, internal).is_none(),
            "{internal} escaped to the receiver: {:?}",
            out.attributes
        );
    }
}

/// The receiver deduplicates on a content hash over `event_time` and the attributes
/// (SPEC.md §6.6), so two deliveries of one batch must be byte-identical. This is what the frozen
/// correction buys, and the reason the design's "sample fresh at flush" had to change.
#[test]
fn the_same_batch_delivered_twice_is_identical() {
    let (collector, sink, _) = Collector::start(None);

    let request = batch("idempotent", now_realtime(), vec![]);
    assert_eq!(collector.post(&request).0, 200);
    let first = sink.wait_for("idempotent");

    assert_eq!(collector.post(&request).0, 200);
    let deadline = Instant::now() + budget();
    while Instant::now() < deadline && sink.count("idempotent") < 2 {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(sink.count("idempotent"), 2, "the second delivery never arrived");

    let both: Vec<LogRecord> = sink
        .received
        .lock()
        .unwrap()
        .iter()
        .flat_map(|r| &r.resource_logs)
        .flat_map(|r| &r.scope_logs)
        .flat_map(|s| &s.log_records)
        .filter(|r| r.event_name == "idempotent")
        .cloned()
        .collect();

    // Exactly the fields `content_id` hashes: `event_time`, `type`, `body` and the attributes
    // (SPEC.md §6.6). `observed_time_unix_nano` is deliberately *not* among them — it is the
    // collector's receipt time and differs per delivery by design, which is also why the receiver
    // excludes `processed_time` from the hash.
    assert_eq!(both[0].time_unix_nano, both[1].time_unix_nano, "event_time drifted between deliveries");
    assert_eq!(both[0].attributes, both[1].attributes, "an attribute drifted between deliveries");
    assert_eq!(both[0].body, both[1].body);
    assert_eq!(both[0].time_unix_nano, first.time_unix_nano);
    assert_ne!(
        both[0].observed_time_unix_nano, both[1].observed_time_unix_nano,
        "the receipt times should differ, or this test is not comparing two real deliveries"
    );
}

/// Startup, readiness and the health endpoint over a real socket.
#[test]
fn it_reports_its_clock_state() {
    let (collector, _sink, _) = Collector::start(None);
    let (status, body) = collector.try_get("/healthz").unwrap();
    let text = String::from_utf8_lossy(&body);

    assert_eq!(status, 200);
    assert!(text.contains("\"synchronized\":true"), "{text}");
    assert!(text.contains("\"sync_source\""), "{text}");
    assert!(text.contains("\"epochs\""), "{text}");
}

/// The collector must accept exactly what the receiver accepts, or "point an application at
/// either one unchanged" stops being true.
#[test]
fn it_refuses_what_the_receiver_refuses() {
    let (collector, _sink, _) = Collector::start(None);

    let body = batch("cpu", now_realtime(), vec![]).encode_to_vec();
    let mut raw = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(&body);
    assert_eq!(collector.request(raw).unwrap().0, 415, "wrong content type must be refused");

    let mut raw = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/x-protobuf\r\nContent-Encoding: zstd\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(&body);
    assert_eq!(collector.request(raw).unwrap().0, 415, "unknown encoding must be refused");
}

/// A batch the collector cannot forward stays in hand and goes out when the receiver returns.
/// Nothing is dropped for a receiver that was merely late to start.
#[test]
fn a_batch_survives_an_unreachable_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("c.sock");
    let sink_path = dir.path().join("sink.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_mp-collector"))
        .arg("--socket")
        .arg(&socket)
        .arg("--forward-to")
        .arg(&sink_path)
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .args(["--grace-millis", "100", "--journal-backfill", "false", "--log-level", "warn"])
        .spawn()
        .expect("spawning mp-collector");

    let collector = Collector { child: std::mem::replace(&mut child, dummy_child()), socket, _dir: dir };
    let mut collector = collector;
    collector.wait_until_ready();

    // Nothing is listening yet.
    assert_eq!(collector.post(&batch("late", now_realtime(), vec![])).0, 200);
    std::thread::sleep(Duration::from_millis(500));

    let sink = Sink::start(sink_path);
    sink.wait_for("late");
}

/// Batches delivered in separate flushes must share one connection.
///
/// Asserted end to end rather than only against the unit fake because the thing that would break it
/// is at the far end: a receiver answering `Connection: close` would silently put every batch back on
/// its own connection, and the collector would go on working — just paying a connect per batch, which
/// is free over a local socket and is not over a tunnel.
#[test]
fn separate_flushes_share_one_connection() {
    let (collector, sink, _) = Collector::start(None);

    // Separate flushes, not one batch: the grace period is 100 ms, so waiting for each to arrive
    // guarantees these are two delivery cycles rather than one coalesced write.
    for name in ["first", "second", "third"] {
        assert_eq!(collector.post(&batch(name, now_realtime(), vec![])).0, 200);
        sink.wait_for(name);
    }

    assert_eq!(sink.accepts(), 1, "each flush opened its own connection");
}

/// A delivery attempt that gets no answer must be abandoned and retried, not waited on forever.
///
/// Without the send timeout the flush task blocks inside the first attempt for as long as the peer
/// holds the connection open — it never returns to its inbox, and the batch never arrives even
/// though the receiver started answering seconds later. The retry is safe to make unconditionally
/// because the correction is frozen, so a batch that did land and lost its acknowledgement
/// deduplicates at the receiver rather than arriving twice.
#[test]
fn a_silent_receiver_is_abandoned_and_the_batch_arrives_on_the_retry() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("c.sock");
    let sink_path = dir.path().join("sink.sock");
    let received = start_sink_silent_once(&sink_path);

    let child = Command::new(env!("CARGO_BIN_EXE_mp-collector"))
        .arg("--socket")
        .arg(&socket)
        .arg("--forward-to")
        .arg(&sink_path)
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        // Short everything: the point is the transition, not production timings.
        .args(["--grace-millis", "100"])
        .args(["--forward-timeout-secs", "1"])
        .args(["--retry-max-secs", "1"])
        .args(["--journal-backfill", "false", "--log-level", "warn"])
        .spawn()
        .expect("spawning mp-collector");

    let mut collector = Collector { child, socket, _dir: dir };
    collector.wait_until_ready();

    assert_eq!(collector.post(&batch("after-silence", now_realtime(), vec![])).0, 200);

    let deadline = Instant::now() + budget();
    while Instant::now() < deadline {
        let arrived = received
            .lock()
            .unwrap()
            .iter()
            .flat_map(|r| &r.resource_logs)
            .flat_map(|r| &r.scope_logs)
            .flat_map(|s| &s.log_records)
            .any(|r| r.event_name == "after-silence");
        if arrived {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("the batch never arrived after the silent attempt should have timed out");
}

/// A placeholder `Child` so `Collector`'s `Drop` has something to own after the real one moves.
fn dummy_child() -> Child {
    Command::new("true").spawn().expect("spawning /bin/true")
}

/// Guards the assumption every fixture here rests on: the sink path is inside a temp directory
/// short enough for `sun_path`, which is 108 bytes and silently truncates.
#[test]
fn the_test_socket_paths_fit_in_sun_path() {
    let dir = tempfile::tempdir().unwrap();
    let longest = dir.path().join("sink.sock");
    assert!(
        longest.as_os_str().len() < 100,
        "TMPDIR is too deep for a unix socket path: {}",
        longest.display()
    );
    assert!(Path::new(dir.path()).exists());
}
