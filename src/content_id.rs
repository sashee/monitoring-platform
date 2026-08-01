//! Content-addressed measurement identity (SPEC §6.6). Pure; no I/O.
//!
//! A measurement's id is a hash of everything the device sent — `event_time`, `type`, `body` and
//! `attributes` — and deliberately *not* `processed_time`, which differs per delivery. Excluding it
//! is precisely what makes a retry after a lost acknowledgement hash identically, so re-uploading
//! the same measurement is a no-op rather than a second row.
//!
//! The encoding is canonical by construction here rather than by relying on how `serde_json`
//! happens to order maps. That matters: `preserve_order` is an *additive* Cargo feature, so any
//! crate anywhere in the dependency graph could enable it, turn `Map` into an insertion-ordered
//! `IndexMap`, and silently change every hash — old rows would stop matching new ones and
//! deduplication would quietly stop working with no error anywhere.

use blake3::Hasher;
use serde_json::{Map, Number, Value};

use crate::model::Measurement;

/// 128 bits. With `INSERT OR IGNORE` a collision silently drops a distinct measurement, which is a
/// stronger requirement than ordinary hashing: at 128 bits, 10^9 rows give a collision probability
/// around 10^-21; at 64 bits, 10^8 rows give roughly 1 in 3700.
pub const ID_LEN: usize = 16;
pub type ContentId = [u8; ID_LEN];

/// Prefix so a future encoding change produces different ids rather than colliding with rows
/// written by an older version.
const DOMAIN: &[u8] = b"monitoring-platform/measurement/v1";

// Every node is type-tagged, so `1`, `1.0`, `"1"` and `[1]` cannot hash alike.
const TAG_NULL: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_I64: u8 = 2;
const TAG_U64: u8 = 3;
const TAG_F64: u8 = 4;
const TAG_STR: u8 = 5;
const TAG_ARRAY: u8 = 6;
const TAG_OBJECT: u8 = 7;
const TAG_BODY_ABSENT: u8 = 8;
const TAG_BODY_PRESENT: u8 = 9;

/// The identity of a measurement.
pub fn content_id(m: &Measurement) -> ContentId {
    let mut h = Hasher::new();
    h.update(DOMAIN);

    h.update(&m.event_time.to_be_bytes());
    put_bytes(&mut h, m.kind.as_bytes());

    // An absent body and a body whose value is unset are distinguishable (SPEC §5.4), so the hash
    // must keep them apart too.
    match &m.body {
        None => h.update(&[TAG_BODY_ABSENT]),
        Some(v) => {
            h.update(&[TAG_BODY_PRESENT]);
            put_value(&mut h, v);
            &mut h
        }
    };

    put_map(&mut h, &m.attributes);

    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&h.finalize().as_bytes()[..ID_LEN]);
    id
}

/// Length-prefixed, so concatenation is unambiguous: without this, `type="ab"` with `body="c"`
/// would hash identically to `type="a"` with `body="bc"`.
fn put_bytes(h: &mut Hasher, b: &[u8]) {
    h.update(&(b.len() as u64).to_be_bytes());
    h.update(b);
}

fn put_value(h: &mut Hasher, v: &Value) {
    match v {
        Value::Null => {
            h.update(&[TAG_NULL]);
        }
        Value::Bool(b) => {
            h.update(&[TAG_BOOL]);
            h.update(&[u8::from(*b)]);
        }
        Value::Number(n) => put_number(h, n),
        Value::String(s) => {
            h.update(&[TAG_STR]);
            put_bytes(h, s.as_bytes());
        }
        Value::Array(a) => {
            // Order is semantic for an array, so it is preserved rather than sorted.
            h.update(&[TAG_ARRAY]);
            h.update(&(a.len() as u64).to_be_bytes());
            for x in a {
                put_value(h, x);
            }
        }
        Value::Object(m) => put_map(h, m),
    }
}

/// Integers and floats are tagged apart, because OTLP's `int_value` and `double_value` are
/// different types and a device choosing one over the other is saying something different.
fn put_number(h: &mut Hasher, n: &Number) {
    if let Some(i) = n.as_i64() {
        h.update(&[TAG_I64]);
        h.update(&i.to_be_bytes());
    } else if let Some(u) = n.as_u64() {
        h.update(&[TAG_U64]);
        h.update(&u.to_be_bytes());
    } else {
        // `Number` cannot hold a non-finite value (`Number::from_f64` rejects them, and §5.4 maps
        // them to sentinel strings before they get here), so this is always a finite double.
        let f = n.as_f64().unwrap_or(0.0);
        // Normalise -0.0 to 0.0. They are numerically equal but have different bit patterns, and
        // Postgres `jsonb` collapses them (SPEC §6.5) — so hashing the raw bits would make an id
        // change under a backend migration.
        let f = if f == 0.0 { 0.0 } else { f };
        h.update(&[TAG_F64]);
        h.update(&f.to_bits().to_be_bytes());
    }
}

/// Keys are sorted here, explicitly. This is the guarantee that a client sending the same
/// attributes in a different order produces the same id — see the module comment for why it must
/// not be left to `serde_json`.
fn put_map(h: &mut Hasher, m: &Map<String, Value>) {
    h.update(&[TAG_OBJECT]);
    h.update(&(m.len() as u64).to_be_bytes());

    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    for k in keys {
        put_bytes(h, k.as_bytes());
        // Present by construction: the key came from this map.
        if let Some(v) = m.get(k) {
            put_value(h, v);
        }
    }
}

/// Lowercase hex. Chosen over base64 because it preserves byte ordering lexicographically, so a
/// hex id sorts the same way the underlying blob does in SQLite.
pub fn to_hex(id: &ContentId) -> String {
    let mut s = String::with_capacity(ID_LEN * 2);
    for b in id {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

pub fn from_hex(s: &str) -> Option<ContentId> {
    if s.len() != ID_LEN * 2 {
        return None;
    }
    let mut id = [0u8; ID_LEN];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(id)
}

/// Accepts a stored blob, rejecting anything that is not exactly an id.
pub fn from_bytes(b: &[u8]) -> Option<ContentId> {
    ContentId::try_from(b).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn measurement(kind: &str, event_time: i64, body: Option<Value>, attrs: Value) -> Measurement {
        Measurement {
            event_time,
            processed_time: 999,
            kind: kind.to_owned(),
            body,
            attributes: attrs.as_object().cloned().unwrap_or_default(),
        }
    }

    fn base() -> Measurement {
        measurement(
            "gps",
            1_785_489_242_123_456_789,
            Some(json!({"lat": 47.4979, "lon": 19.0402})),
            json!({"resource.attributes.device.id": "dev-7", "record.attributes.unit": "wgs84"}),
        )
    }

    /// The property the whole scheme rests on: a client may serialise its attributes in any order.
    #[test]
    fn attribute_order_does_not_change_the_id() {
        let mut a = base();
        let mut b = base();

        // Build the same map by inserting in opposite orders. If the implementation ever relied on
        // Map iteration order (e.g. under serde_json's `preserve_order`), this would diverge.
        a.attributes = Map::new();
        a.attributes.insert("z.last".into(), json!(1));
        a.attributes.insert("a.first".into(), json!(2));
        a.attributes.insert("m.middle".into(), json!(3));

        b.attributes = Map::new();
        b.attributes.insert("m.middle".into(), json!(3));
        b.attributes.insert("a.first".into(), json!(2));
        b.attributes.insert("z.last".into(), json!(1));

        assert_eq!(content_id(&a), content_id(&b));
    }

    #[test]
    fn nested_object_order_does_not_change_the_id() {
        let a = measurement("t", 1, Some(json!({"cfg": {"x": 1, "y": 2}})), json!({}));
        let b = measurement("t", 1, Some(json!({"cfg": {"y": 2, "x": 1}})), json!({}));
        assert_eq!(content_id(&a), content_id(&b));
    }

    /// Arrays are ordered data, not a set.
    #[test]
    fn array_order_does_change_the_id() {
        let a = measurement("t", 1, Some(json!({"tags": [1, 2]})), json!({}));
        let b = measurement("t", 1, Some(json!({"tags": [2, 1]})), json!({}));
        assert_ne!(content_id(&a), content_id(&b));
    }

    /// The whole point: a retry differs only in arrival time and must be the same measurement.
    #[test]
    fn processed_time_is_excluded() {
        let mut a = base();
        let mut b = base();
        a.processed_time = 1;
        b.processed_time = i64::MAX;
        assert_eq!(content_id(&a), content_id(&b));
    }

    #[test]
    fn every_hashed_field_changes_the_id() {
        let original = content_id(&base());

        let mut t = base();
        t.kind = "cpu".into();
        assert_ne!(content_id(&t), original, "type must matter");

        let mut e = base();
        e.event_time += 1;
        assert_ne!(content_id(&e), original, "event_time must matter, even by 1 ns");

        let mut b = base();
        b.body = Some(json!({"lat": 47.4979, "lon": 19.0403}));
        assert_ne!(content_id(&b), original, "body must matter");

        let mut a = base();
        a.attributes.insert("record.attributes.extra".into(), json!(1));
        assert_ne!(content_id(&a), original, "attributes must matter");
    }

    /// SPEC §5.4 keeps these distinguishable; the hash must not merge them.
    #[test]
    fn absent_body_differs_from_null_body() {
        let absent = measurement("t", 1, None, json!({}));
        let null = measurement("t", 1, Some(Value::Null), json!({}));
        assert_ne!(content_id(&absent), content_id(&null));
    }

    /// The regression test for length prefixing: without it these two would collide.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let a = measurement("ab", 1, Some(json!("c")), json!({}));
        let b = measurement("a", 1, Some(json!("bc")), json!({}));
        assert_ne!(content_id(&a), content_id(&b));

        // Same idea inside a map: {"ab":"c"} must not collide with {"a":"bc"}.
        let c = measurement("t", 1, None, json!({"ab": "c"}));
        let d = measurement("t", 1, None, json!({"a": "bc"}));
        assert_ne!(content_id(&c), content_id(&d));
    }

    /// OTLP's int_value and double_value are different types, so they must stay distinguishable.
    #[test]
    fn json_types_are_tagged_apart() {
        let ids: Vec<ContentId> = [json!(1), json!(1.0), json!("1"), json!([1]), json!(true), Value::Null]
            .into_iter()
            .map(|v| content_id(&measurement("t", 1, Some(v), json!({}))))
            .collect();

        for (i, a) in ids.iter().enumerate() {
            for (j, b) in ids.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "values {i} and {j} hashed alike");
                }
            }
        }
    }

    /// Postgres `jsonb` collapses -0.0 to 0.0 (SPEC §6.5), so hashing raw bits would make an id
    /// change under a backend migration.
    #[test]
    fn negative_zero_hashes_as_zero() {
        let neg = measurement("t", 1, Some(json!(-0.0)), json!({}));
        let pos = measurement("t", 1, Some(json!(0.0)), json!({}));
        assert_eq!(content_id(&neg), content_id(&pos));
    }

    /// The full i64 range must survive into the hash without being coerced through f64.
    #[test]
    fn large_integers_are_distinguished() {
        let a = measurement("t", 1, Some(json!(i64::MAX)), json!({}));
        let b = measurement("t", 1, Some(json!(i64::MAX - 1)), json!({}));
        assert_ne!(content_id(&a), content_id(&b));
    }

    #[test]
    fn ids_are_stable_across_runs() {
        // Pinned so an accidental change to the encoding is visible rather than silent. Update
        // this only together with the DOMAIN version.
        let m = measurement("gps", 42, Some(json!({"v": 1})), json!({"a": "b"}));
        assert_eq!(to_hex(&content_id(&m)), "039041fb15b6a5539cc42c9bd709363e");
    }

    #[test]
    fn hex_round_trips() {
        let id = content_id(&base());
        assert_eq!(from_hex(&to_hex(&id)), Some(id));
        assert_eq!(to_hex(&id).len(), ID_LEN * 2);
        assert!(to_hex(&id).bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn hex_rejects_malformed_input() {
        assert_eq!(from_hex(""), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex(&"a".repeat(ID_LEN * 2 - 1)), None, "too short");
        assert_eq!(from_hex(&"a".repeat(ID_LEN * 2 + 1)), None, "too long");
        assert_eq!(from_hex(&"gg".repeat(ID_LEN)), None, "not hex");
    }

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        assert!(from_bytes(&[0u8; ID_LEN]).is_some());
        assert!(from_bytes(&[0u8; ID_LEN - 1]).is_none());
        assert!(from_bytes(&[0u8; ID_LEN + 1]).is_none());
    }
}
