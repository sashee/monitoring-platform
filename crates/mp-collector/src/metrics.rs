//! Self-monitoring (design §9). Pure: builds a batch, sends nothing.
//!
//! Nearly free, and it turns a class of confusing incidents into an obvious one. "Every timestamp
//! from this device is three days old" is a mystery; "no daemon has disciplined this device's
//! clock since boot, and 4000 records are sitting in the buffer" is a work item.
//!
//! Emitted as an ordinary OTLP Event through the collector's own forwarder, so it lands in the
//! same table as everything else and needs no second transport. The values go in the **body**
//! rather than in attributes: attributes identify a measurement, and these are the measurement.

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, KeyValueList, any_value::Value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use std::time::Duration;

/// The measurement type these land under, and the `service.name` they carry.
pub const EVENT_NAME: &str = "mp.collector.health";
pub const SERVICE_NAME: &str = "mp-collector";

/// One reading of everything §9 asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Health {
    /// The kernel's own error bound, microseconds.
    pub max_error_micros: i64,
    /// Time since the last observed clock step. `None` if none has happened this boot.
    pub since_last_step: Option<Duration>,
    pub steps: u64,
    /// Whether *anything* is disciplining the clock. The single most useful bit here: a device
    /// whose answer is `false` an hour after boot has a configuration problem, not a clock problem.
    pub disciplined: bool,
    pub epochs: u64,
    pub resolved_exact: u64,
    pub resolved_ambiguous: u64,
    pub resolved_passthrough: u64,
    pub resolved_authoritative: u64,
    pub buffered_records: u64,
    pub oldest_buffered: Duration,
    pub forwarded_batches: u64,
    /// Batches dropped because the outbox filled while the receiver was unreachable. Reported
    /// rather than silent: durable retry toward the server is out of scope (design §3), so this
    /// is the one place the collector can lose data and it must say so.
    pub shed_batches: u64,
}

/// Builds the batch. `now_unix_nanos` is the corrected wall clock at emission — these are only
/// ever emitted once the clock is good, so there is nothing to resolve.
pub fn to_request(health: Health, now_unix_nanos: i64, boot_id: &str) -> ExportLogsServiceRequest {
    let body = kvlist(&[
        ("clock.max_error_micros", Value::IntValue(health.max_error_micros)),
        ("clock.disciplined", Value::BoolValue(health.disciplined)),
        ("clock.steps", Value::IntValue(health.steps as i64)),
        (
            "clock.seconds_since_last_step",
            match health.since_last_step {
                Some(d) => Value::IntValue(d.as_secs() as i64),
                // Explicitly null rather than absent or -1: "no step has happened" is a real
                // state, and a sentinel integer would be indistinguishable from a measurement.
                None => return_null(),
            },
        ),
        ("clock.epochs", Value::IntValue(health.epochs as i64)),
        ("resolved.exact", Value::IntValue(health.resolved_exact as i64)),
        ("resolved.ambiguous", Value::IntValue(health.resolved_ambiguous as i64)),
        ("resolved.passthrough", Value::IntValue(health.resolved_passthrough as i64)),
        ("resolved.authoritative", Value::IntValue(health.resolved_authoritative as i64)),
        ("buffer.records", Value::IntValue(health.buffered_records as i64)),
        ("buffer.oldest_seconds", Value::IntValue(health.oldest_buffered.as_secs() as i64)),
        ("forwarded.batches", Value::IntValue(health.forwarded_batches as i64)),
        ("shed.batches", Value::IntValue(health.shed_batches as i64)),
    ]);

    let record = LogRecord {
        time_unix_nano: now_unix_nanos.max(0) as u64,
        observed_time_unix_nano: now_unix_nanos.max(0) as u64,
        event_name: EVENT_NAME.to_owned(),
        body: Some(AnyValue { value: Some(body) }),
        ..Default::default()
    };

    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![
                    attr("service.name", Value::StringValue(SERVICE_NAME.to_owned())),
                    attr("boot.id", Value::StringValue(boot_id.to_owned())),
                ],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: SERVICE_NAME.to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    ..Default::default()
                }),
                log_records: vec![record],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

/// An `AnyValue` whose `value` is unset, which SPEC.md §5.4 maps to JSON `null`.
fn return_null() -> Value {
    // `KvlistValue` with no entries would be an empty object, not a null; the only representation
    // of null in `AnyValue` is an absent `value`, so this wraps one level down.
    Value::ArrayValue(opentelemetry_proto::tonic::common::v1::ArrayValue {
        values: vec![AnyValue { value: None }],
    })
}

fn attr(key: &str, value: Value) -> KeyValue {
    KeyValue { key: key.to_owned(), value: Some(AnyValue { value: Some(value) }), ..Default::default() }
}

fn kvlist(pairs: &[(&str, Value)]) -> Value {
    Value::KvlistValue(KeyValueList {
        values: pairs.iter().map(|(k, v)| attr(k, v.clone())).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(request: &ExportLogsServiceRequest) -> Vec<(String, Value)> {
        let record = &request.resource_logs[0].scope_logs[0].log_records[0];
        match record.body.as_ref().unwrap().value.as_ref().unwrap() {
            Value::KvlistValue(list) => list
                .values
                .iter()
                .map(|kv| (kv.key.clone(), kv.value.clone().unwrap().value.unwrap()))
                .collect(),
            other => panic!("expected a kvlist body, got {other:?}"),
        }
    }

    fn health() -> Health {
        Health {
            max_error_micros: 2_000,
            since_last_step: Some(Duration::from_secs(42)),
            steps: 1,
            disciplined: true,
            epochs: 2,
            resolved_exact: 100,
            resolved_ambiguous: 2,
            resolved_passthrough: 7,
            resolved_authoritative: 1,
            buffered_records: 0,
            oldest_buffered: Duration::ZERO,
            forwarded_batches: 33,
            shed_batches: 0,
        }
    }

    /// It has to be an *Event*, or the receiver rejects it: a record without `event_name` is not a
    /// measurement (SPEC.md §4.4), and self-metrics that silently fail to store would be worse
    /// than none.
    #[test]
    fn it_is_a_conforming_otlp_event() {
        let request = to_request(health(), 1_785_924_000_000_000_000, "boot-1");
        let record = &request.resource_logs[0].scope_logs[0].log_records[0];

        assert_eq!(record.event_name, EVENT_NAME);
        assert_ne!(record.time_unix_nano, 0, "SPEC.md §5.3 rejects a record with no timestamp");
        assert_ne!(record.observed_time_unix_nano, 0, "OTLP requires this to be set");
    }

    #[test]
    fn the_resource_names_the_collector_and_the_boot() {
        let request = to_request(health(), 1, "boot-7");
        let attrs = &request.resource_logs[0].resource.as_ref().unwrap().attributes;
        let get = |k: &str| {
            attrs.iter().find(|kv| kv.key == k).and_then(|kv| kv.value.clone()?.value)
        };
        assert_eq!(get("service.name"), Some(Value::StringValue(SERVICE_NAME.into())));
        assert_eq!(get("boot.id"), Some(Value::StringValue("boot-7".into())));
    }

    /// Every §9 bullet has to actually be in there. Asserted by name so removing one is a test
    /// failure rather than a quiet regression in what an operator can see.
    #[test]
    fn every_value_section_nine_asks_for_is_present() {
        let body = body_of(&to_request(health(), 1, "boot-1"));
        let keys: Vec<&str> = body.iter().map(|(k, _)| k.as_str()).collect();
        for expected in [
            "clock.max_error_micros",
            "clock.seconds_since_last_step",
            "clock.steps",
            "clock.disciplined",
            "resolved.exact",
            "resolved.ambiguous",
            "resolved.passthrough",
            "buffer.records",
            "buffer.oldest_seconds",
        ] {
            assert!(keys.contains(&expected), "§9 asks for {expected}, which is missing: {keys:?}");
        }
    }

    #[test]
    fn the_values_are_the_ones_it_was_given() {
        let body = body_of(&to_request(health(), 1, "boot-1"));
        let get = |k: &str| body.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());

        assert_eq!(get("clock.max_error_micros"), Some(Value::IntValue(2_000)));
        assert_eq!(get("clock.disciplined"), Some(Value::BoolValue(true)));
        assert_eq!(get("clock.seconds_since_last_step"), Some(Value::IntValue(42)));
        assert_eq!(get("resolved.exact"), Some(Value::IntValue(100)));
        assert_eq!(get("shed.batches"), Some(Value::IntValue(0)));
    }

    /// "No step has happened yet" is a state, not a zero and not a sentinel. A `-1` here would be
    /// indistinguishable from a measurement once it is a row in the database.
    #[test]
    fn no_step_yet_is_null_rather_than_a_sentinel() {
        let body = body_of(&to_request(
            Health { since_last_step: None, ..health() },
            1,
            "boot-1",
        ));
        let value = body
            .iter()
            .find(|(k, _)| k == "clock.seconds_since_last_step")
            .map(|(_, v)| v.clone())
            .unwrap();
        match value {
            Value::ArrayValue(a) => {
                assert_eq!(a.values.len(), 1);
                assert!(a.values[0].value.is_none(), "should be an unset AnyValue, i.e. JSON null");
            }
            other => panic!("expected a null-carrying value, got {other:?}"),
        }
    }

    /// A device that has never synchronized is exactly the case these metrics exist to make
    /// visible, so the all-zero reading must still produce a shippable event.
    #[test]
    fn a_never_synchronized_device_still_reports() {
        let never = Health {
            max_error_micros: 16_000_000,
            disciplined: false,
            buffered_records: 4_000,
            oldest_buffered: Duration::from_secs(280),
            ..Health::default()
        };
        let body = body_of(&to_request(never, 1, "boot-1"));
        let get = |k: &str| body.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());

        assert_eq!(get("clock.disciplined"), Some(Value::BoolValue(false)));
        assert_eq!(get("buffer.records"), Some(Value::IntValue(4_000)));
        assert_eq!(get("buffer.oldest_seconds"), Some(Value::IntValue(280)));
    }
}
