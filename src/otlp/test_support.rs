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
