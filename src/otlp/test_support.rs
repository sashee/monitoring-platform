//! Builders for OTLP log payloads, used by unit and integration tests.
//!
//! Compiled unconditionally so integration tests in `tests/` can use them too; nothing in the
//! serving path calls it, so it is dead-code-eliminated from release builds.

pub use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as OtlpValue};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::InstrumentationScope;
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;

pub fn kv(key: &str, value: OtlpValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue { value: Some(value) }),
        ..Default::default()
    }
}

/// An attribute whose value message is absent entirely.
pub fn kv_absent(key: &str) -> KeyValue {
    KeyValue { key: key.to_owned(), value: None, ..Default::default() }
}

pub fn kv_str(key: &str, value: &str) -> KeyValue {
    kv(key, OtlpValue::StringValue(value.to_owned()))
}

pub fn kv_int(key: &str, value: i64) -> KeyValue {
    kv(key, OtlpValue::IntValue(value))
}

pub fn kv_double(key: &str, value: f64) -> KeyValue {
    kv(key, OtlpValue::DoubleValue(value))
}

pub fn record(
    event_name: &str,
    time_unix_nano: i64,
    observed_time_unix_nano: i64,
    body: Option<AnyValue>,
    attributes: Vec<KeyValue>,
) -> LogRecord {
    LogRecord {
        time_unix_nano: time_unix_nano as u64,
        observed_time_unix_nano: observed_time_unix_nano as u64,
        event_name: event_name.to_owned(),
        body,
        attributes,
        ..Default::default()
    }
}

/// One resource, one scope, many records.
pub fn request(
    resource_attributes: Vec<KeyValue>,
    scope_name: &str,
    scope_version: &str,
    scope_attributes: Vec<KeyValue>,
    records: Vec<LogRecord>,
) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource { attributes: resource_attributes, ..Default::default() }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: scope_name.to_owned(),
                    version: scope_version.to_owned(),
                    attributes: scope_attributes,
                    ..Default::default()
                }),
                log_records: records,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

/// A body built from key/value pairs, as a device would send a structured measurement.
pub fn body_map(pairs: Vec<(&str, OtlpValue)>) -> AnyValue {
    use opentelemetry_proto::tonic::common::v1::KeyValueList;
    AnyValue {
        value: Some(OtlpValue::KvlistValue(KeyValueList {
            values: pairs.into_iter().map(|(k, v)| kv(k, v)).collect(),
        })),
    }
}

/// The `device.id` the sample batch is stamped with by default.
///
/// The NixOS VM harness scopes every assertion to this value, because the machine under
/// test is an input and usually runs producers of its own writing to the same receiver
/// (`nix/tests/lib.nix`). It hardcodes the literal, so the test below pins it: changing
/// it here must fail rather than silently unscope the harness.
pub const SAMPLE_DEVICE_ID: &str = "dev-7";

/// The batch `mp-make-sample` writes: three measurements (gps, cpu, heart_rate) from one
/// device. Pure in its inputs — the clock is the binary's business — so the shape the VM
/// tests depend on is unit-testable.
pub fn sample_request(device_id: &str, now_unix_nano: i64) -> ExportLogsServiceRequest {
    request(
        vec![kv_str("service.name", "fleet-agent"), kv_str("device.id", device_id)],
        "sensors",
        "0.3.1",
        vec![],
        vec![
            record(
                "gps",
                now_unix_nano,
                0,
                Some(body_map(vec![
                    ("lat", OtlpValue::DoubleValue(47.4979)),
                    ("lon", OtlpValue::DoubleValue(19.0402)),
                    ("alt_m", OtlpValue::DoubleValue(105.2)),
                ])),
                vec![kv_str("unit", "wgs84"), kv_int("sensor.index", 0)],
            ),
            record(
                "cpu",
                now_unix_nano + 1_000_000,
                0,
                Some(body_map(vec![
                    ("usage", OtlpValue::DoubleValue(0.42)),
                    ("temp_c", OtlpValue::DoubleValue(51.5)),
                ])),
                vec![kv_str("unit", "ratio"), kv_int("cpu.core", 0)],
            ),
            record(
                "heart_rate",
                now_unix_nano + 2_000_000,
                0,
                Some(AnyValue { value: Some(OtlpValue::IntValue(72)) }),
                vec![kv_str("unit", "bpm"), kv_str("sensor.model", "polar-h10")],
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otlp::to_measurements;
    use serde_json::json;

    const T: i64 = 1_785_489_242_123_456_789;
    const P: i64 = 1_785_489_242_170_000_000;

    /// The NixOS harness filters on the literal `dev-7`, both in SQL and as
    /// `attr.resource.attributes.device.id` (`nix/tests/lib.nix`). It cannot see this
    /// constant, so renaming the constant alone must break here — hence the literal on
    /// the right-hand side rather than `SAMPLE_DEVICE_ID`.
    #[test]
    fn the_sample_batch_is_stamped_with_the_sample_device_id() {
        let (ms, _) = to_measurements(&sample_request(SAMPLE_DEVICE_ID, T), P);
        assert_eq!(ms.len(), 3, "the harness asserts in multiples of 3");
        for m in &ms {
            assert_eq!(
                m.attributes["resource.attributes.device.id"],
                json!("dev-7"),
                "the harness scopes its assertions on this exact key and value"
            );
        }
    }

    /// `--device-id` is what lets the foreign-producer case impersonate a second writer.
    #[test]
    fn the_device_id_is_overridable() {
        let (ms, _) = to_measurements(&sample_request("other-device", T), P);
        assert_eq!(ms.len(), 3);
        for m in &ms {
            assert_eq!(m.attributes["resource.attributes.device.id"], json!("other-device"));
        }
    }
}
