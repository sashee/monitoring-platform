//! `ExportLogsServiceRequest` → measurements, per SPEC §5. Pure; no I/O.

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::logs::v1::LogRecord;
use serde_json::{Map, Value};

use super::anyvalue::{any_value_to_json, opt_any_value_to_json};
use crate::model::{Measurement, Rejections};

const RESOURCE_PREFIX: &str = "resource.attributes.";
const SCOPE_PREFIX: &str = "scope.attributes.";
const RECORD_PREFIX: &str = "record.attributes.";

/// Walks `resource_logs[] → scope_logs[] → log_records[]` and converts every acceptable record.
///
/// `processed_time` is captured once per request by the caller and shared by every measurement in
/// it, so a batch is identifiable as one delivery (SPEC §5.1).
pub fn to_measurements(
    request: &ExportLogsServiceRequest,
    processed_time: i64,
) -> (Vec<Measurement>, Rejections) {
    let mut out = Vec::new();
    let mut rejections = Rejections::default();

    for resource_logs in &request.resource_logs {
        // Resource attributes are shared by every record under this resource, so build once.
        let mut resource_attrs = Map::new();
        if let Some(resource) = &resource_logs.resource {
            insert_prefixed(&mut resource_attrs, RESOURCE_PREFIX, &resource.attributes);
        }

        for scope_logs in &resource_logs.scope_logs {
            let mut base_attrs = resource_attrs.clone();
            if let Some(scope) = &scope_logs.scope {
                // Synthetic, and omitted when empty. These cannot collide with a scope attribute
                // named `name`, which lands under `scope.attributes.name` (SPEC §5.2).
                if !scope.name.is_empty() {
                    base_attrs.insert("scope.name".to_owned(), Value::String(scope.name.clone()));
                }
                if !scope.version.is_empty() {
                    base_attrs
                        .insert("scope.version".to_owned(), Value::String(scope.version.clone()));
                }
                insert_prefixed(&mut base_attrs, SCOPE_PREFIX, &scope.attributes);
            }

            for record in &scope_logs.log_records {
                match convert_record(record, &base_attrs, processed_time) {
                    Ok(m) => out.push(m),
                    Err(reason) => {
                        tracing::warn!(reason = reason.as_str(), "rejecting log record");
                        match reason {
                            Reason::MissingEventName => rejections.missing_event_name += 1,
                            Reason::MissingTimestamp => rejections.missing_timestamp += 1,
                        }
                    }
                }
            }
        }
    }

    (out, rejections)
}

enum Reason {
    MissingEventName,
    MissingTimestamp,
}

impl Reason {
    fn as_str(&self) -> &'static str {
        match self {
            Reason::MissingEventName => "event_name is empty; only OTLP Events are accepted",
            Reason::MissingTimestamp => "time_unix_nano and observed_time_unix_nano are both zero",
        }
    }
}

fn convert_record(
    record: &LogRecord,
    base_attrs: &Map<String, Value>,
    processed_time: i64,
) -> Result<Measurement, Reason> {
    // Checked first, so a record failing both checks is counted once (SPEC §4.4).
    if record.event_name.is_empty() {
        return Err(Reason::MissingEventName);
    }
    let event_time = event_time(record).ok_or(Reason::MissingTimestamp)?;

    let mut attributes = base_attrs.clone();
    insert_prefixed(&mut attributes, RECORD_PREFIX, &record.attributes);

    Ok(Measurement {
        event_time,
        processed_time,
        kind: record.event_name.clone(),
        body: record.body.as_ref().map(any_value_to_json),
        attributes,
    })
}

/// `time_unix_nano`, else `observed_time_unix_nano`, else nothing — the chain `logs.proto`
/// prescribes for recipients storing a single timestamp. There is deliberately no fall back to
/// the arrival time, which is already its own column (SPEC §5.3).
fn event_time(record: &LogRecord) -> Option<i64> {
    [record.time_unix_nano, record.observed_time_unix_nano]
        .into_iter()
        .find(|t| *t != 0)
        .map(|t| t as i64)
}

/// Inserts `<prefix><key>` for each attribute. Duplicate keys within one OTLP map are malformed
/// input; the last occurrence wins, which is the only place write order matters (SPEC §5.2).
fn insert_prefixed(into: &mut Map<String, Value>, prefix: &str, attrs: &[KeyValue]) {
    for kv in attrs {
        let mut key = String::with_capacity(prefix.len() + kv.key.len());
        key.push_str(prefix);
        key.push_str(&kv.key);
        into.insert(key, opt_any_value_to_json(kv.value.as_ref()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otlp::test_support::*;
    use serde_json::json;

    const T: i64 = 1_785_489_242_123_456_789;
    const P: i64 = 1_785_489_242_170_000_000;

    #[test]
    fn maps_a_minimal_record() {
        let req = request(vec![], "", "", vec![], vec![record("gps", T, 0, None, vec![])]);
        let (ms, rej) = to_measurements(&req, P);
        assert!(rej.is_empty());
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].kind, "gps");
        assert_eq!(ms[0].event_time, T);
        assert_eq!(ms[0].processed_time, P);
        assert_eq!(ms[0].body, None);
        assert!(ms[0].attributes.is_empty());
    }

    /// SPEC §5.2: each level gets its structural prefix.
    #[test]
    fn attributes_get_structural_prefixes() {
        let req = request(
            vec![kv_str("device.id", "dev-7")],
            "sensors",
            "0.3.1",
            vec![kv_str("lib", "s")],
            vec![record("cpu", T, 0, None, vec![kv_str("unit", "ratio")])],
        );
        let (ms, _) = to_measurements(&req, P);
        let a = &ms[0].attributes;
        assert_eq!(a["resource.attributes.device.id"], json!("dev-7"));
        assert_eq!(a["scope.name"], json!("sensors"));
        assert_eq!(a["scope.version"], json!("0.3.1"));
        assert_eq!(a["scope.attributes.lib"], json!("s"));
        assert_eq!(a["record.attributes.unit"], json!("ratio"));
    }

    #[test]
    fn empty_scope_name_and_version_are_omitted() {
        let req = request(vec![], "", "", vec![], vec![record("cpu", T, 0, None, vec![])]);
        let (ms, _) = to_measurements(&req, P);
        assert!(!ms[0].attributes.contains_key("scope.name"));
        assert!(!ms[0].attributes.contains_key("scope.version"));
    }

    /// SPEC §5.2: the property the `attributes.` segment exists to guarantee. Every input must
    /// survive distinctly even when device keys are chosen to collide with the synthetic ones.
    #[test]
    fn collisions_are_structurally_impossible() {
        let req = request(
            vec![kv_str("attributes", "r-attrs")],
            "real-scope",
            "1.0",
            vec![kv_str("name", "not-the-scope-name"), kv_str("version", "not-the-version")],
            vec![record("t", T, 0, None, vec![kv_str("attributes", "rec-attrs")])],
        );
        let (ms, _) = to_measurements(&req, P);
        let a = &ms[0].attributes;
        assert_eq!(a["scope.name"], json!("real-scope"));
        assert_eq!(a["scope.version"], json!("1.0"));
        assert_eq!(a["scope.attributes.name"], json!("not-the-scope-name"));
        assert_eq!(a["scope.attributes.version"], json!("not-the-version"));
        assert_eq!(a["resource.attributes.attributes"], json!("r-attrs"));
        assert_eq!(a["record.attributes.attributes"], json!("rec-attrs"));
        assert_eq!(a.len(), 6, "an input was lost or merged: {a:?}");
    }

    #[test]
    fn absent_attribute_value_becomes_null_and_keeps_the_key() {
        let req = request(
            vec![],
            "",
            "",
            vec![],
            vec![record("t", T, 0, None, vec![kv_absent("k")])],
        );
        let (ms, _) = to_measurements(&req, P);
        assert_eq!(ms[0].attributes["record.attributes.k"], Value::Null);
    }

    /// SPEC §5.3: the two-step chain, all branches.
    #[test]
    fn event_time_falls_back_to_observed_then_rejects() {
        let (ms, _) = to_measurements(
            &request(vec![], "", "", vec![], vec![record("t", T, 999, None, vec![])]),
            P,
        );
        assert_eq!(ms[0].event_time, T, "time_unix_nano must win when set");

        let (ms, _) = to_measurements(
            &request(vec![], "", "", vec![], vec![record("t", 0, 999, None, vec![])]),
            P,
        );
        assert_eq!(ms[0].event_time, 999, "must fall back to observed_time_unix_nano");

        let (ms, rej) = to_measurements(
            &request(vec![], "", "", vec![], vec![record("t", 0, 0, None, vec![])]),
            P,
        );
        assert!(ms.is_empty());
        assert_eq!(rej.missing_timestamp, 1);
        assert_ne!(ms.first().map(|m| m.event_time), Some(P), "must not fabricate from arrival time");
    }

    /// SPEC §4.4: rejections are counted once each, and survivors still convert.
    #[test]
    fn mixed_batch_rejects_selectively_and_counts_once() {
        let req = request(
            vec![],
            "",
            "",
            vec![],
            vec![
                record("ok", T, 0, None, vec![]),
                record("", T, 0, None, vec![]),   // no event_name
                record("t", 0, 0, None, vec![]),  // no timestamp
                record("", 0, 0, None, vec![]),   // both: counted once, as missing event_name
            ],
        );
        let (ms, rej) = to_measurements(&req, P);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].kind, "ok");
        assert_eq!(rej.missing_event_name, 2);
        assert_eq!(rej.missing_timestamp, 1);
        assert_eq!(rej.total(), 3, "a record failing both checks must count once");
    }

    #[test]
    fn absent_body_and_unset_body_are_distinguishable() {
        let unset = AnyValue { value: None };
        let req = request(
            vec![],
            "",
            "",
            vec![],
            vec![
                record("a", T, 0, None, vec![]),
                record("b", T, 0, Some(unset), vec![]),
            ],
        );
        let (ms, _) = to_measurements(&req, P);
        assert_eq!(ms[0].body, None, "no body message at all");
        assert_eq!(ms[1].body, Some(Value::Null), "body message present, value unset");
    }

    #[test]
    fn walks_multiple_resources_and_scopes() {
        let mut req = request(
            vec![kv_str("a", "1")],
            "s1",
            "",
            vec![],
            vec![record("x", T, 0, None, vec![])],
        );
        let second = request(
            vec![kv_str("a", "2")],
            "s2",
            "",
            vec![],
            vec![record("y", T, 0, None, vec![])],
        );
        req.resource_logs.extend(second.resource_logs);

        let (ms, _) = to_measurements(&req, P);
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].attributes["resource.attributes.a"], json!("1"));
        assert_eq!(ms[0].attributes["scope.name"], json!("s1"));
        assert_eq!(ms[1].attributes["resource.attributes.a"], json!("2"));
        assert_eq!(ms[1].attributes["scope.name"], json!("s2"));
    }
}
