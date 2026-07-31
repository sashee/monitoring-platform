//! Writes a sample OTLP protobuf batch: three measurements (gps, cpu, heart_rate).
//!
//! A shipped binary rather than an example, because both the manual check in SPEC §11
//! and the NixOS VM tests need it from an installed package, and `cargo build` does
//! not install examples.
//!
//!     mp-make-sample sample-logs.pb

use monitoring_platform::otlp::test_support::*;
use prost::Message;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "sample-logs.pb".to_owned());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    let batch = request(
        vec![kv_str("service.name", "fleet-agent"), kv_str("device.id", "dev-7")],
        "sensors",
        "0.3.1",
        vec![],
        vec![
            record("gps", now, 0, Some(body_map(vec![
                ("lat", OtlpValue::DoubleValue(47.4979)),
                ("lon", OtlpValue::DoubleValue(19.0402)),
                ("alt_m", OtlpValue::DoubleValue(105.2)),
            ])), vec![kv_str("unit", "wgs84"), kv_int("sensor.index", 0)]),
            record("cpu", now + 1_000_000, 0, Some(body_map(vec![
                ("usage", OtlpValue::DoubleValue(0.42)),
                ("temp_c", OtlpValue::DoubleValue(51.5)),
            ])), vec![kv_str("unit", "ratio"), kv_int("cpu.core", 0)]),
            record("heart_rate", now + 2_000_000, 0,
                Some(AnyValue { value: Some(OtlpValue::IntValue(72)) }),
                vec![kv_str("unit", "bpm"), kv_str("sensor.model", "polar-h10")]),
        ],
    );

    let bytes = batch.encode_to_vec();
    std::fs::write(&path, &bytes).unwrap();
    println!("wrote {} ({} bytes, 3 records)", path, bytes.len());
}
