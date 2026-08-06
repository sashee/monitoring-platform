//! Writes a sample OTLP protobuf batch: three measurements (gps, cpu, heart_rate).
//!
//! A shipped binary rather than an example, because both the manual check in SPEC §11
//! and the NixOS VM tests need it from an installed package, and `cargo build` does
//! not install examples.
//!
//!     mp-make-sample sample-logs.pb                 # write it out
//!     mp-make-sample --device-id other-device theirs.pb
//!     mp-make-sample --post /run/…/mp.sock          # stamp and send in one process
//!
//! The batch itself lives in `otlp::test_support::sample_request`, so its shape — in
//! particular the `device.id` the VM harness scopes on — is covered by a unit test.
//!
//! `--post` exists for the collector's sake and is not a convenience. Frame resolution bounds an
//! event by `[sender_started, received]` (collector design §5.1), so a batch written to a file and
//! posted afterwards by `curl` is correctly classified `passthrough`: curl started *after* those
//! timestamps were taken and cannot have produced them. Testing the correction path therefore
//! needs one process that both stamps and sends, which is what this does.

use clap::Parser;
use monitoring_platform::otlp::test_support::{SAMPLE_DEVICE_ID, sample_request};
use prost::Message;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "mp-make-sample", about = "Writes a sample OTLP protobuf batch", version)]
struct Args {
    /// Where to write the encoded batch.
    #[arg(default_value = "sample-logs.pb")]
    path: PathBuf,

    /// The batch's resource-level device.id. The NixOS VM harness scopes every
    /// assertion to the default, so pass this to impersonate a second writer.
    #[arg(long, default_value = SAMPLE_DEVICE_ID)]
    device_id: String,

    /// Post the batch to this unix socket instead of writing it out. Mutually exclusive
    /// with a path: the point is that one process both stamps and sends (see above), so
    /// there is nothing to write.
    #[arg(long, conflicts_with = "path")]
    post: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    let bytes = sample_request(&args.device_id, now).encode_to_vec();

    match &args.post {
        Some(socket) => post(socket, &bytes, &args.device_id),
        None => write(&args.path, &bytes, &args.device_id),
    }
}

fn write(path: &Path, bytes: &[u8], device_id: &str) {
    std::fs::write(path, bytes).unwrap();
    println!(
        "wrote {} ({} bytes, 3 records, device.id={})",
        path.display(),
        bytes.len(),
        device_id
    );
}

/// Minimal HTTP/1.1 POST over a unix socket. Hand-rolled rather than pulling a client into the
/// binary: one request, one connection, `Connection: close`, and the status line is all it reads.
fn post(socket: &Path, bytes: &[u8], device_id: &str) {
    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .unwrap_or_else(|e| panic!("connecting to {}: {e}", socket.display()));

    let mut request = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/x-protobuf\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    )
    .into_bytes();
    request.extend_from_slice(bytes);

    stream.write_all(&request).expect("writing the request");
    stream.flush().expect("flushing the request");

    let mut response = String::new();
    stream.read_to_string(&mut response).expect("reading the response");

    let status = response.lines().next().unwrap_or("");
    println!("posted {} bytes, 3 records, device.id={device_id} -> {status}", bytes.len());
    if !status.contains(" 200 ") {
        eprintln!("{response}");
        std::process::exit(1);
    }
}
