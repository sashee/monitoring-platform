//! `AnyValue` → JSON, per SPEC §5.4. Pure; no I/O.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value::Value as OtlpValue};
use serde_json::{Map, Number, Value};

/// Maps an `AnyValue` to JSON. An `AnyValue` whose `value` oneof is unset maps to `null`.
pub fn any_value_to_json(v: &AnyValue) -> Value {
    match &v.value {
        None => Value::Null,
        Some(inner) => otlp_value_to_json(inner),
    }
}

/// Maps an optional `AnyValue` (an absent message) to `null` as well.
pub fn opt_any_value_to_json(v: Option<&AnyValue>) -> Value {
    v.map(any_value_to_json).unwrap_or(Value::Null)
}

fn otlp_value_to_json(v: &OtlpValue) -> Value {
    match v {
        OtlpValue::StringValue(s) => Value::String(s.clone()),
        OtlpValue::BoolValue(b) => Value::Bool(*b),
        OtlpValue::IntValue(i) => Value::Number(Number::from(*i)),
        OtlpValue::DoubleValue(d) => double_to_json(*d),
        OtlpValue::ArrayValue(a) => Value::Array(a.values.iter().map(any_value_to_json).collect()),
        OtlpValue::KvlistValue(kv) => {
            let mut map = Map::with_capacity(kv.values.len());
            for entry in &kv.values {
                map.insert(entry.key.clone(), opt_any_value_to_json(entry.value.as_ref()));
            }
            Value::Object(map)
        }
        OtlpValue::BytesValue(b) => Value::String(BASE64.encode(b)),
        // Profiling-signal field; the proto directs non-profiling receivers to treat it as absent.
        OtlpValue::StringValueStrindex(idx) => {
            tracing::warn!(
                strindex = idx,
                "ignoring string_value_strindex: profiling-signal field in a logs record"
            );
            Value::Null
        }
    }
}

/// Doubles that JSON cannot represent become sentinel strings rather than `null`.
///
/// `Number::from_f64` returns `None` for every non-finite input, which is the only reason this
/// is correct: `serde_json::json!(f64::NAN)` silently yields `null` instead (SPEC §5.4).
pub fn double_to_json(d: f64) -> Value {
    match Number::from_f64(d) {
        Some(n) => Value::Number(n),
        None if d.is_nan() => Value::String("NaN".to_owned()),
        None if d.is_sign_positive() => Value::String("Infinity".to_owned()),
        None => Value::String("-Infinity".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{ArrayValue, KeyValue, KeyValueList};
    use serde_json::json;

    fn av(v: OtlpValue) -> AnyValue {
        AnyValue { value: Some(v) }
    }

    #[test]
    fn scalars_map_directly() {
        assert_eq!(any_value_to_json(&av(OtlpValue::StringValue("x".into()))), json!("x"));
        assert_eq!(any_value_to_json(&av(OtlpValue::BoolValue(true))), json!(true));
        assert_eq!(any_value_to_json(&av(OtlpValue::DoubleValue(1.5))), json!(1.5));
    }

    #[test]
    fn unset_value_is_null() {
        assert_eq!(any_value_to_json(&AnyValue { value: None }), Value::Null);
        assert_eq!(opt_any_value_to_json(None), Value::Null);
    }

    /// SPEC §5.5: the full i64 range must survive, as integers rather than floats.
    #[test]
    fn int_values_are_exact_over_the_full_i64_range() {
        for n in [i64::MIN, i64::MAX, 9_007_199_254_740_993, -9_007_199_254_740_993, 0] {
            let v = any_value_to_json(&av(OtlpValue::IntValue(n)));
            assert!(v.is_i64(), "{n} did not map to an integer variant");
            assert!(!v.is_f64(), "{n} mapped to a float variant");
            assert_eq!(v.as_i64(), Some(n));
        }
    }

    /// SPEC §5.4: the regression test for the `json!(f64::NAN) == null` trap.
    #[test]
    fn non_finite_doubles_become_sentinel_strings_not_null() {
        assert_eq!(double_to_json(f64::NAN), json!("NaN"));
        assert_eq!(double_to_json(f64::INFINITY), json!("Infinity"));
        assert_eq!(double_to_json(f64::NEG_INFINITY), json!("-Infinity"));
        // The trap itself, asserted so the reason this function exists stays visible.
        assert_eq!(json!(f64::NAN), Value::Null);
    }

    #[test]
    fn finite_doubles_are_bit_exact() {
        for x in [0.1f64, 1e308, 5e-324, -0.0, f64::MAX, 0.333_333_333_333_333_3] {
            let got = double_to_json(x).as_f64().unwrap();
            assert_eq!(got.to_bits(), x.to_bits(), "{x} changed bits");
        }
    }

    #[test]
    fn bytes_become_padded_standard_base64() {
        assert_eq!(any_value_to_json(&av(OtlpValue::BytesValue(vec![0xff, 0x01]))), json!("/wE="));
    }

    #[test]
    fn strindex_is_treated_as_absent() {
        assert_eq!(any_value_to_json(&av(OtlpValue::StringValueStrindex(3))), Value::Null);
    }

    /// SPEC §5.2.1: values nest arbitrarily and nothing is flattened.
    #[test]
    fn nested_arrays_and_kvlists_are_preserved() {
        let inner = av(OtlpValue::KvlistValue(KeyValueList {
            values: vec![
                KeyValue {
                    key: "offset".into(),
                    value: Some(av(OtlpValue::DoubleValue(-0.5))),
                    ..Default::default()
                },
                KeyValue { key: "unset".into(), value: None, ..Default::default() },
            ],
        }));
        let nested = av(OtlpValue::ArrayValue(ArrayValue {
            values: vec![inner, av(OtlpValue::IntValue(7))],
        }));
        assert_eq!(any_value_to_json(&nested), json!([{ "offset": -0.5, "unset": null }, 7]));
    }
}
