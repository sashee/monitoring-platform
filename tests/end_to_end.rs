//! End-to-end over a real Unix socket, driving the compiled binary (SPEC §11).
//!
//! This is the only test that covers process startup, socket lifecycle, readiness and the SIGTERM
//! shutdown path — everything `oneshot`-style router tests cannot reach.

use monitoring_platform::api::status::PROTOBUF;
use monitoring_platform::otlp::test_support::*;
use monitoring_platform::store::schema::{SCHEMA_VERSION, Version};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceResponse,
};
use prost::Message;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

mod common;

const T: i64 = 1_785_489_242_123_456_789;

/// How long the process-lifecycle waits below are allowed to take, overridable with
/// `MP_TEST_TIMEOUT_SECS`.
///
/// Deliberately generous, because both waits can be dominated by a single `fsync` and this is not
/// a latency test -- the assertions are that the server *does* become ready and *does* exit
/// cleanly. On a Raspberry Pi 5's SD card an ext4 `data=ordered` commit issued while a build's own
/// writeback is still draining was measured blocking for over 30 seconds, with the process parked
/// in state D on `do_get_write_access`; batches of 4 KiB O_DSYNC writes that take 25 ms on an idle
/// card took 154 s under that load. A fixed 20 s budget therefore failed `nix build` on that host
/// while the server was perfectly healthy and answered moments later. Failures that actually
/// matter -- a server that exits, or one that never binds -- are still caught: the loops check for
/// child exit on every iteration, so a real fault fails fast rather than waiting this out.
fn budget() -> Duration {
    const DEFAULT_SECS: u64 = 180;
    Duration::from_secs(
        std::env::var("MP_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SECS),
    )
}

struct Server {
    child: Child,
    socket: std::path::PathBuf,
    db: std::path::PathBuf,
    /// Presented on every request but `/healthz`, which requires none (SPEC §13).
    authorization: String,
    _dir: tempfile::TempDir,
}

impl Server {
    fn start() -> Server {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mp.sock");
        let db = dir.path().join("mp.db");
        // Before the server starts, so it finds the key already in the database it opens. Creating it
        // here also migrates the file, which the server then has nothing left to do.
        let authorization = common::issue_key(&db);

        let child = Command::new(env!("CARGO_BIN_EXE_monitoring-platform"))
            .args(["serve", "--socket"])
            .arg(&socket)
            .arg("--db")
            .arg(&db)
            .args(["--log-level", "warn"])
            .spawn()
            .expect("spawning the server binary");

        let mut server = Server { child, socket, db, authorization, _dir: dir };
        server.wait_until_ready();
        server
    }

    /// Polls `/healthz` rather than sleeping, so the test is not timing-dependent.
    ///
    /// A dead server can never become ready, so it is reported immediately with its exit status
    /// instead of burning the whole budget and then blaming a timeout.
    fn wait_until_ready(&mut self) {
        const PROBE: &str = "GET /healthz HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n";
        let deadline = Instant::now() + budget();
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("server exited before becoming ready: {status}");
            }
            if matches!(self.try_request(PROBE.as_bytes().to_vec()), Ok((200, _))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("server did not become ready within {:?}", budget());
    }

    fn try_request(&self, raw: Vec<u8>) -> std::io::Result<(u16, Vec<u8>)> {
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(&raw)?;
        stream.flush()?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(parse_response(&response))
    }

    fn request(&self, raw: Vec<u8>) -> (u16, Vec<u8>) {
        self.try_request(raw).expect("request over the unix socket")
    }

    fn get(&self, path: &str) -> (u16, Vec<u8>) {
        self.request(
            format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
                 Authorization: {}\r\n\r\n",
                self.authorization
            )
            .into_bytes(),
        )
    }

    fn post_protobuf(&self, path: &str, body: &[u8], encoding: Option<&str>) -> (u16, Vec<u8>) {
        let mut head = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Authorization: {}\r\nContent-Type: {PROTOBUF}\r\nContent-Length: {}\r\n",
            self.authorization,
            body.len()
        );
        if let Some(enc) = encoding {
            head.push_str(&format!("Content-Encoding: {enc}\r\n"));
        }
        head.push_str("\r\n");

        let mut raw = head.into_bytes();
        raw.extend_from_slice(body);
        self.request(raw)
    }

    /// Sends SIGTERM and waits for exit, returning whether it exited successfully.
    fn terminate(&mut self) -> bool {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        // Same budget as readiness, and for the same reason: the graceful path drains the storage
        // writer and checkpoints the WAL, so it ends in an fsync too.
        let deadline = Instant::now() + budget();
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.success();
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.kill();
        panic!("server did not exit within {:?} of SIGTERM", budget());
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Only if a test left it running; terminate() consumes the normal path.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Minimal HTTP response parser: status code and body, which is all these tests assert on.
fn parse_response(raw: &[u8]) -> (u16, Vec<u8>) {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response had no header terminator");
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("could not parse status line");
    (status, raw[split + 4..].to_vec())
}

/// Two records, at `at` and `at + 1000`. Calling this twice with the same `at` produces a
/// byte-identical payload, which is what makes the duplicate assertions below meaningful.
fn sample_batch_at(at: i64) -> Vec<u8> {
    request(
        vec![kv_str("device.id", "dev-7")],
        "sensors",
        "0.3.1",
        vec![],
        vec![
            record(
                "gps",
                at,
                0,
                Some(body_map(vec![("lat", OtlpValue::DoubleValue(47.4979))])),
                vec![kv_str("unit", "wgs84")],
            ),
            record(
                "cpu",
                at + 1_000,
                0,
                Some(body_map(vec![("usage", OtlpValue::DoubleValue(0.42))])),
                vec![kv_str("unit", "ratio")],
            ),
        ],
    )
    .encode_to_vec()
}

fn sample_batch() -> Vec<u8> {
    sample_batch_at(T)
}

/// The `partial_success` a request reported, if any.
fn partial_success(body: &[u8]) -> Option<ExportLogsPartialSuccess> {
    ExportLogsServiceResponse::decode(body).expect("response is not an OTLP response").partial_success
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn count_rows(db: &Path) -> i64 {
    let conn = monitoring_platform::store::open_read(db).unwrap();
    conn.query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap()
}

#[test]
fn full_lifecycle_over_a_real_socket() {
    let mut server = Server::start();

    // Readiness.
    let (status, body) = server.get("/healthz");
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["status"], "ok");

    // Ingest.
    let batch = sample_batch();
    let (status, body) = server.post_protobuf("/v1/logs", &batch, None);
    assert_eq!(status, 200);
    assert!(partial_success(&body).is_none(), "a clean batch reports nothing");
    assert_eq!(count_rows(&server.db), 2);

    // The same payload again, gzipped: this is exactly the retry-after-a-lost-acknowledgement case
    // that SPEC §4.1's retryable 503 invites. It must be silently accepted and store nothing —
    // proving both that gzip works over the socket and that identity is content-based, since the
    // wire bytes differ completely between the two requests (SPEC §6.6).
    let (status, body) = server.post_protobuf("/v1/logs", &gzip(&batch), Some("gzip"));
    assert_eq!(status, 200, "a duplicate is accepted, not refused");
    assert!(
        partial_success(&body).is_none(),
        "a duplicate must not be reported as rejected, or every correct retry looks like a failure"
    );
    assert_eq!(count_rows(&server.db), 2, "the re-upload must not have stored anything");

    // A genuinely different measurement still stores: deduplication must not swallow new data.
    let (status, _) = server.post_protobuf("/v1/logs", &sample_batch_at(T + 5_000_000), None);
    assert_eq!(status, 200);
    assert_eq!(count_rows(&server.db), 4, "distinct measurements must still be stored");

    // Read back.
    let (status, body) = server.get("/v1/measurements?type=gps&limit=5");
    assert_eq!(status, 200);
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rows = page["measurements"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "one gps per distinct batch, not per upload");
    assert_eq!(rows[0]["type"], "gps");
    assert_eq!(rows[0]["attributes"]["resource.attributes.device.id"], "dev-7");
    // Newest first, so this is the second batch.
    assert_eq!(rows[0]["event_time_unix_nano"], (T + 5_000_000).to_string());
    assert_eq!(rows[1]["event_time_unix_nano"], T.to_string());

    // Ids are the content hash: hex, fixed width, and distinct for distinct measurements.
    let id = rows[0]["id"].as_str().expect("id must be a string");
    assert_eq!(id.len(), 32, "128-bit id as hex");
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{id}");
    assert_ne!(id, rows[1]["id"].as_str().unwrap());

    // Attribute filtering over the wire.
    let (status, body) = server.get("/v1/measurements?attr.record.attributes.unit=ratio");
    assert_eq!(status, 200);
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["measurements"].as_array().unwrap().len(), 2, "both cpu records");

    // Graceful shutdown: exits cleanly, removes its socket, leaves committed data behind.
    assert!(server.terminate(), "server should exit successfully on SIGTERM");
    assert!(!server.socket.exists(), "the socket must be unlinked on shutdown");
    assert_eq!(count_rows(&server.db), 4, "committed rows must survive shutdown");
}

/// SPEC §8.1: a dead socket left by a crash must not wedge the next start.
#[test]
fn reclaims_a_stale_socket_left_by_a_previous_run() {
    let mut first = Server::start();
    let socket = first.socket.clone();

    // SIGKILL, so the graceful path does not run and the socket file is left behind.
    let _ = first.child.kill();
    let _ = first.child.wait();
    assert!(socket.exists(), "precondition: SIGKILL should leave the socket file");

    let second = Command::new(env!("CARGO_BIN_EXE_monitoring-platform"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .arg("--db")
        .arg(first.db.clone())
        .args(["--log-level", "warn"])
        .spawn()
        .unwrap();

    // Same database, so the key issued for `first` still applies.
    let mut replacement = Server {
        child: second,
        socket,
        db: first.db.clone(),
        authorization: first.authorization.clone(),
        _dir: tempfile::tempdir().unwrap(),
    };
    replacement.wait_until_ready();
    assert_eq!(replacement.get("/healthz").0, 200);
    assert!(replacement.terminate());
}

/// SPEC §8.1: startup must fail rather than delete something that is not ours.
#[test]
fn refuses_to_start_when_the_socket_path_is_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("occupied");
    std::fs::write(&path, b"not a socket").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_monitoring-platform"))
        .args(["serve", "--socket"])
        .arg(&path)
        .arg("--db")
        .arg(dir.path().join("m.db"))
        .output()
        .unwrap();

    assert!(!output.status.success(), "should have refused to start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is not a socket"), "unexpected stderr: {stderr}");
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket", "the file must be untouched");
}

/// SPEC §6.2: a database from a newer *major* is a startup failure, not a downgrade.
///
/// `user_version` is a packed `major.minor` (§6.2), so the value here is not a free choice: it used to
/// be `999`, which now denotes 0.999 — an *older* major, which would be migrated forward and start
/// happily. `Version::new(major + 1, 0).encode()` is derived from the constant instead, so bumping
/// SCHEMA_VERSION cannot leave this test silently asserting nothing.
#[test]
fn refuses_to_start_against_a_newer_major_schema() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("future.db");
    let newer = Version::new(SCHEMA_VERSION.major + 1, 0);
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.pragma_update(None, "user_version", newer.encode()).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_monitoring-platform"))
        .args(["serve", "--socket"])
        .arg(dir.path().join("m.sock"))
        .arg("--db")
        .arg(&db)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("newer than this binary"), "unexpected stderr: {stderr}");
}

/// SPEC §6.7: **startup fills in the series of measurements written without one.**
///
/// The end-to-end shape is the point, and a unit test on `backfill` cannot reach it: what is being
/// asserted is that `serve` actually *calls* the sweep. Unwired, every unit test still passes and the
/// deployed receiver quietly never converges.
///
/// The rows are inserted the way a 3.1 binary writes them — no `series_id` — which is exactly what a
/// nightly `system.autoUpgrade` revert leaves behind, and the reason the fill is a sweep rather than a
/// step in the migration.
#[test]
fn startup_assigns_a_series_to_measurements_that_have_none() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("mp.sock");
    let db = dir.path().join("mp.db");

    // Migrates, so `series` and the column exist — then rows arrive as an older binary writes them.
    let authorization = common::issue_key(&db);
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        for row in 0..3u8 {
            let mut id = [0u8; 16];
            id[0] = row;
            conn.execute(
                "INSERT INTO measurement (id, event_time, processed_time, type, body, attributes) \
                 VALUES (?1, ?2, ?2, 'cpu', '{}', '{\"record.attributes.core\":0}')",
                rusqlite::params![&id[..], 1_000 + i64::from(row)],
            )
            .unwrap();
        }
        let unassigned: i64 = conn
            .query_row("SELECT count(*) FROM measurement WHERE series_id IS NULL", [], |r| r.get(0))
            .unwrap();
        assert_eq!(unassigned, 3, "the older binary's insert must leave the column NULL");
    }

    let child = Command::new(env!("CARGO_BIN_EXE_monitoring-platform"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .arg("--db")
        .arg(&db)
        .args(["--log-level", "warn"])
        .spawn()
        .unwrap();

    let mut server = Server { child, socket, db: db.clone(), authorization, _dir: dir };
    server.wait_until_ready();
    assert!(server.terminate());

    let conn = rusqlite::Connection::open(&db).unwrap();
    let unassigned: i64 = conn
        .query_row("SELECT count(*) FROM measurement WHERE series_id IS NULL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(unassigned, 0, "startup must have filled them in");

    // One series for three rows of the same type and attributes, and its count is the three — the
    // property phase two's join depends on.
    let (series, added): (i64, i64) = conn
        .query_row("SELECT count(*), sum(added_measurements) FROM series", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((series, added), (1, 3));
}

/// SPEC §6.7: **a measurement that cannot be assigned a series stops the process**, rather than being
/// quietly omitted from every read.
///
/// The read path joins `series` for `type` and `attributes`, so an unassigned row is invisible. Being
/// loudly down beats under-reporting: an empty chart looks like "nothing happened", which is the one
/// answer a monitoring system must never give wrongly.
///
/// Forced with the only input that can do it — two spellings of one attribute object, which share a
/// series id so the second matches no `series.attributes`. Nothing this receiver writes can produce
/// that, which is why it is fatal rather than handled.
#[test]
fn refuses_to_start_when_a_measurement_cannot_be_assigned_a_series() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("mp.db");

    common::issue_key(&db);
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        for (row, attributes) in [(1u8, r#"{"a":1,"b":2}"#), (2u8, r#"{"b":2,"a":1}"#)] {
            let mut id = [0u8; 16];
            id[0] = row;
            conn.execute(
                "INSERT INTO measurement (id, event_time, processed_time, type, body, attributes) \
                 VALUES (?1, ?2, ?2, 'cpu', '{}', ?3)",
                rusqlite::params![&id[..], 1_000 + i64::from(row), attributes],
            )
            .unwrap();
        }
    }

    let output = Command::new(env!("CARGO_BIN_EXE_monitoring-platform"))
        .args(["serve", "--socket"])
        .arg(dir.path().join("mp.sock"))
        .arg("--db")
        .arg(&db)
        .output()
        .unwrap();

    assert!(!output.status.success(), "should have refused to start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not be matched to a series"),
        "the refusal must name the cause: {stderr}"
    );

    // And it changed nothing: the fill is one transaction, so the rows are still queued for a retry
    // once whatever wrote them is dealt with.
    let conn = rusqlite::Connection::open(&db).unwrap();
    let unassigned: i64 = conn
        .query_row("SELECT count(*) FROM measurement WHERE series_id IS NULL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(unassigned, 2);
}

/// SPEC §6.2: a newer *minor* must start, because a minor version only adds tables, indexes and
/// defaulted columns — so everything this binary knows about is still where it expects it.
///
/// The end-to-end shape matters here rather than only the unit test on `migrate`: this is the case a
/// reverted deployment lands in, and what has to hold is that the process comes up and serves, not
/// merely that one function returned `Ok`.
#[test]
fn starts_against_a_newer_minor_schema() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("mp.sock");
    let db = dir.path().join("mp.db");
    let future = Version::new(SCHEMA_VERSION.major, SCHEMA_VERSION.minor + 1);

    // Migrated and keyed by *this* binary first, so the tables it needs exist, and then moved forward
    // the way a newer one would have left it: an extra table, and a higher minor.
    let authorization = common::issue_key(&db);
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE from_the_future (x INTEGER) STRICT;").unwrap();
        conn.pragma_update(None, "user_version", future.encode()).unwrap();
    }

    let child = Command::new(env!("CARGO_BIN_EXE_monitoring-platform"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .arg("--db")
        .arg(&db)
        .args(["--log-level", "warn"])
        .spawn()
        .unwrap();

    let mut server = Server { child, socket, db: db.clone(), authorization, _dir: dir };
    server.wait_until_ready();
    assert_eq!(server.get("/healthz").0, 200);
    // Not just liveness: the routes that need the schema have to work too, since the point is that
    // this binary can still serve a database a newer one migrated.
    assert_eq!(server.get("/v1/measurements").0, 200);
    assert!(server.terminate());

    // Still untouched: writing our own version back would be a silent downgrade of the file.
    let conn = rusqlite::Connection::open(&db).unwrap();
    let stored: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
    assert_eq!(stored, future.encode());
}
