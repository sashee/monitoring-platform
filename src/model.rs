//! The one domain entity (SPEC §3).

use serde_json::{Map, Value};

use crate::content_id::ContentId;

/// A measurement ready to be stored. The id is *derived* from these fields rather than carried
/// here — see `crate::content_id` — so there is exactly one place that decides identity.
#[derive(Debug, Clone, PartialEq)]
pub struct Measurement {
    /// Nanoseconds since the Unix epoch, from the device (SPEC §5.3).
    pub event_time: i64,
    /// Nanoseconds since the Unix epoch, from the server clock (SPEC §5.1).
    pub processed_time: i64,
    /// From `LogRecord.event_name` (SPEC §4.4).
    pub kind: String,
    /// `None` when the record carried no body message at all; `Some(Value::Null)` when it
    /// carried one whose value was unset. The two are distinguishable (SPEC §5.4).
    pub body: Option<Value>,
    /// Merged resource/scope/record attributes, structurally prefixed (SPEC §5.2).
    pub attributes: Map<String, Value>,
}

/// A measurement read back out of the database.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredMeasurement {
    /// The content hash (SPEC §6.6): intrinsic, so the same measurement has this id on every
    /// machine, rather than one assigned by whichever server stored it first.
    pub id: ContentId,
    pub event_time: i64,
    pub processed_time: i64,
    pub kind: String,
    pub body: Option<Value>,
    pub attributes: Value,
}

/// Why records in a batch were skipped (SPEC §4.4). A record failing more than one check is
/// counted once, under the first check that rejected it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rejections {
    pub missing_event_name: i64,
    pub missing_timestamp: i64,
}

impl Rejections {
    pub fn total(&self) -> i64 {
        self.missing_event_name + self.missing_timestamp
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Human-readable summary for `ExportLogsServiceResponse.partial_success.error_message`.
    pub fn message(&self) -> String {
        let mut parts = Vec::new();
        if self.missing_event_name > 0 {
            parts.push(format!(
                "{} record(s) had no event_name (only OTLP Events are accepted)",
                self.missing_event_name
            ));
        }
        if self.missing_timestamp > 0 {
            parts.push(format!(
                "{} record(s) had neither time_unix_nano nor observed_time_unix_nano",
                self.missing_timestamp
            ));
        }
        parts.join("; ")
    }
}
