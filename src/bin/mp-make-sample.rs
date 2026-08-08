//! Writes a sample OTLP protobuf batch: three measurements (gps, cpu, heart_rate).
//!
//! A shipped binary rather than an example, because both the manual check in SPEC §11
//! and the NixOS VM tests need it from an installed package, and `cargo build` does
//! not install examples.
//!
//!     mp-make-sample sample-logs.pb
//!     mp-make-sample --device-id other-device theirs.pb
//!
//! The batch itself lives in `otlp::test_support::sample_request`, so its shape — in
//! particular the `device.id` the VM harness scopes on — is covered by a unit test.

use clap::Parser;
use monitoring_platform::otlp::test_support::{SAMPLE_DEVICE_ID, sample_request};
use prost::Message;
use std::path::PathBuf;

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
}

fn main() {
    let args = Args::parse();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    let bytes = sample_request(&args.device_id, now).encode_to_vec();
    std::fs::write(&args.path, &bytes).unwrap();
    println!(
        "wrote {} ({} bytes, 3 records, device.id={})",
        args.path.display(),
        bytes.len(),
        args.device_id
    );
}
