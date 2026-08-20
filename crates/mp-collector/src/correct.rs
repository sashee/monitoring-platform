//! Rewriting timestamps (design §5, §6). Pure: no clock, no I/O, no state.
//!
//! Two passes, and the split between them is the design:
//!
//! - [`resolve_request`] runs **at receipt**, while peer credentials and stream position are still
//!   available. It works out which boottime each wall-clock stamp denotes and writes that down.
//! - [`apply_correction`] runs **at flush**, projecting those boottimes back into wall-clock time
//!   with one freshly sampled offset.
//!
//! Between the two the record carries a boottime — a frame-invariant value that no subsequent
//! clock step can invalidate. That is the whole trick.
//!
//! **What the buffer remembers is the record itself.** The receipt pass writes its conclusions into
//! the record's own attributes rather than into a parallel array that could fall out of step with
//! the proto tree. `mp.clock.resolution` is emitted anyway (§6.3); the two boottime values are
//! internal and are consumed by the flush pass.
//!
//! **The original timestamp stays in place until the flush.** The resolved boottime rides
//! alongside it instead of replacing it, which buys the invariant that a buffered record is always
//! valid, shippable OTLP. That is what makes §8.4 trivial: records spooled across a reboot have
//! boottime values that mean nothing on the new boot, so the flush drops those attributes and
//! ships the original stamps — "pass them through uncorrected" with no special path.

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
use opentelemetry_proto::tonic::logs::v1::LogRecord;

use crate::epoch::{EpochTable, Query, Resolution};
use crate::sync::SyncSource;

/// A private namespace, so a future OTel semantic convention for boot-relative time cannot collide
/// with these. Note the receiver prefixes record attributes structurally (SPEC.md §5.2), so these
/// arrive in the database as `record.attributes.mp.clock.*`.
pub const NS: &str = "mp.clock.";

/// Tier 1 input: the sender's own `CLOCK_BOOTTIME` reading for this record. Immune to app-side
/// buffering, since it does not depend on when the collector saw the record.
pub const ATTR_BOOTTIME: &str = "mp.clock.boottime_ns";
/// Tier 2 input: the sender asserts this timestamp is already correct, or is not from this host's
/// clock at all. Opt-*out*, on rare records.
pub const ATTR_AUTHORITATIVE: &str = "mp.clock.authoritative";

/// Internal, and never reaches the wire: the resolved event boottime, carried from receipt to
/// flush on the record itself. [`apply_correction`] consumes it.
pub const ATTR_EVENT_BOOTTIME: &str = "mp.clock.internal.event_boottime_ns";
/// Internal: the collector's own `CLOCK_BOOTTIME` at receipt, which becomes
/// `observed_time_unix_nano` once there is an offset to project it with.
pub const ATTR_RECEIPT_BOOTTIME: &str = "mp.clock.internal.receipt_boottime_ns";

pub const ATTR_CORRECTED: &str = "mp.clock.corrected";
pub const ATTR_CORRECTION_NS: &str = "mp.clock.correction_ns";
pub const ATTR_RESOLUTION: &str = "mp.clock.resolution";
pub const ATTR_SPREAD_NS: &str = "mp.clock.ambiguity_spread_ns";
pub const ATTR_UNCERTAIN: &str = "mp.clock.uncertain";
pub const ATTR_SYNC_SOURCE: &str = "mp.clock.sync_source";

/// What the collector decided about one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The epoch table had an answer, good or otherwise.
    Resolved(Resolution),
    /// The application marked the record authoritative (Tier 2). Never touched.
    Authoritative,
}

impl Disposition {
    pub fn label(self) -> &'static str {
        match self {
            Disposition::Resolved(r) => r.label(),
            Disposition::Authoritative => "authoritative",
        }
    }

    /// Whether the record carries a boottime the flush pass can project.
    fn is_correctable(self) -> bool {
        matches!(self, Disposition::Resolved(r) if r.boottime().is_some())
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            "exact" => Some(Disposition::Resolved(Resolution::Exact { boottime: 0 })),
            "ambiguous" => {
                Some(Disposition::Resolved(Resolution::Ambiguous { boottime: 0, spread: 0 }))
            }
            "passthrough" => Some(Disposition::Resolved(Resolution::Passthrough)),
            "authoritative" => Some(Disposition::Authoritative),
            _ => None,
        }
    }
}

/// Hints an application may attach. All optional: Tier 0, a completely unmodified OTLP SDK, is
/// fully supported and is the case the `[sender_started, received]` window exists for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hints {
    pub boottime: Option<i64>,
    pub authoritative: bool,
}

/// Reads the hint attributes out of a record's attribute list, **removing them**.
///
/// Removal is not tidiness. Metric data point attributes are part of time series identity, so a
/// per-record boottime left in place would create a new series per point (§6.1). Making the read
/// consume the attributes means a caller cannot use a hint without also stripping it.
pub fn split_hints(attributes: Vec<KeyValue>) -> (Hints, Vec<KeyValue>) {
    let mut hints = Hints::default();
    let kept = attributes
        .into_iter()
        .filter(|kv| match kv.key.as_str() {
            ATTR_BOOTTIME => {
                hints.boottime = as_int(kv);
                false
            }
            ATTR_AUTHORITATIVE => {
                hints.authoritative = as_bool(kv).unwrap_or(false);
                false
            }
            _ => true,
        })
        .collect();
    (hints, kept)
}

/// What the receipt pass knows about the delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    /// `CLOCK_BOOTTIME` at which the sending process started (`peer::started_at`).
    pub sender_started: i64,
    /// `CLOCK_BOOTTIME` at which the collector dequeued the batch.
    pub received: i64,
    /// Slack for fuzzy epoch boundaries; `epoch::DEFAULT_TOLERANCE_NANOS`.
    pub tolerance: i64,
}

/// How many records went each way. Feeds the §9 self-metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tally {
    pub exact: u64,
    pub ambiguous: u64,
    pub passthrough: u64,
    pub authoritative: u64,
}

impl Tally {
    pub fn total(self) -> u64 {
        self.exact + self.ambiguous + self.passthrough + self.authoritative
    }

    /// Records still holding a boottime, i.e. those a flush will rewrite.
    pub fn correctable(self) -> u64 {
        self.exact + self.ambiguous
    }

    fn count(&mut self, d: Disposition) {
        match d {
            Disposition::Resolved(Resolution::Exact { .. }) => self.exact += 1,
            Disposition::Resolved(Resolution::Ambiguous { .. }) => self.ambiguous += 1,
            Disposition::Resolved(Resolution::Passthrough) => self.passthrough += 1,
            Disposition::Authoritative => self.authoritative += 1,
        }
    }
}

/// Receipt pass: work out each record's boottime and record the conclusion, or mark it untouchable.
///
/// Mutates in place. The request is a decoded protobuf the caller owns exclusively and may be
/// megabytes, so rebuilding the tree to return a copy would be a real cost for no property gained.
pub fn resolve_request(
    request: &mut ExportLogsServiceRequest,
    table: &EpochTable,
    receipt: Receipt,
) -> Tally {
    let mut tally = Tally::default();
    for resource_logs in &mut request.resource_logs {
        for scope_logs in &mut resource_logs.scope_logs {
            for record in &mut scope_logs.log_records {
                tally.count(resolve_record(record, table, receipt));
            }
        }
    }
    tally
}

fn resolve_record(record: &mut LogRecord, table: &EpochTable, receipt: Receipt) -> Disposition {
    let (hints, kept) = split_hints(std::mem::take(&mut record.attributes));
    record.attributes = kept;

    let disposition = decide(record, hints, table, receipt);

    // Timestamps are deliberately left as they arrived. The resolved boottime rides alongside
    // until a flush has an offset to project it with.
    if let Disposition::Resolved(resolution) = disposition
        && let Some(boottime) = resolution.boottime()
    {
        record.attributes.push(int_attr(ATTR_EVENT_BOOTTIME, boottime));
        record.attributes.push(int_attr(ATTR_RECEIPT_BOOTTIME, receipt.received));
        if let Resolution::Ambiguous { spread, .. } = resolution {
            record.attributes.push(int_attr(ATTR_SPREAD_NS, spread));
        }
    }

    record.attributes.push(string_attr(ATTR_RESOLUTION, disposition.label()));
    disposition
}

fn decide(
    record: &LogRecord,
    hints: Hints,
    table: &EpochTable,
    receipt: Receipt,
) -> Disposition {
    if hints.authoritative {
        return Disposition::Authoritative;
    }
    // Tier 1: the sender already did the hard part. No window, no ambiguity, and immune to
    // however long the SDK sat on the record before sending it.
    if let Some(boottime) = hints.boottime {
        return Disposition::Resolved(Resolution::Exact { boottime });
    }

    // `time_unix_nano`, else `observed_time_unix_nano` — the same chain the receiver applies when
    // storing a single timestamp (SPEC.md §5.3), so the field this corrects is the field that
    // becomes `event_time`.
    let stamped = match (record.time_unix_nano, record.observed_time_unix_nano) {
        (0, 0) => return Disposition::Resolved(Resolution::Passthrough),
        (0, observed) => observed,
        (time, _) => time,
    };
    let Ok(stamped) = i64::try_from(stamped) else {
        return Disposition::Resolved(Resolution::Passthrough);
    };

    let query = Query { stamped, sender_started: receipt.sender_started, received: receipt.received };
    Disposition::Resolved(table.resolve(query, receipt.tolerance))
}

/// The offset to project carried boottimes with: the **active epoch's**, not a fresh reading.
///
/// Taking it from the table rather than from the clock is what makes projection deterministic. A
/// record that resolved in the epoch still in force comes back out with the timestamp it went in
/// with, exactly; a record that resolved in an earlier epoch moves by precisely the size of the
/// step between them, which is the whole correction and nothing else.
///
/// The alternative — sampling `realtime − boottime` afresh at each flush — is what the design doc
/// prescribes, and it is wrong twice over. It perturbs every timestamp by the jitter between two
/// independent clock reads, and, worse, it makes two deliveries of one batch differ: the
/// receiver's measurement id is a content hash over `event_time` and the attributes
/// (SPEC.md §6.6), `mp.clock.correction_ns` is an attribute, so an application's ordinary retry
/// lands as a second row instead of deduplicating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Correction {
    /// `realtime − boottime` for the epoch in force at flush time.
    pub offset: i64,
}

/// The circumstances of a flush, recorded on every record so a bad correction is debuggable after
/// the fact rather than invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flush {
    /// True when the buffer timed out without the clock ever synchronizing. The data is preserved
    /// and marked, not dropped: a Pi that boots with no network may never sync.
    pub uncertain: bool,
    /// Which §4.4 condition said the clock was good, if any did.
    pub sync_source: Option<SyncSource>,
}

/// Flush pass: project every carried boottime into wall-clock time with one frozen offset, and
/// strip the internal attributes on the way out.
///
/// `correction` is `None` when there is nothing to project *with* — records spooled across a
/// reboot (§8.4), whose boottime values describe a machine that no longer exists. They ship with
/// their original stamps and `mp.clock.corrected=false`, which is the honest answer.
///
/// The correction is a uniform additive offset, so it goes on every timestamp field. Durations and
/// rates derived from them come out unchanged, which is why the design prefers reporting durations
/// over derived timestamps wherever an application has the choice.
pub fn apply_correction(
    request: &mut ExportLogsServiceRequest,
    correction: Option<Correction>,
    flush: Flush,
) -> u64 {
    let mut corrected = 0;
    for resource_logs in &mut request.resource_logs {
        for scope_logs in &mut resource_logs.scope_logs {
            for record in &mut scope_logs.log_records {
                if correct_record(record, correction, flush) {
                    corrected += 1;
                }
            }
        }
    }
    corrected
}

fn correct_record(record: &mut LogRecord, correction: Option<Correction>, flush: Flush) -> bool {
    // Read *and remove*. `resolution` is written by the receipt pass and read here, so it is a carrier
    // as much as a label — but whether it *stays* on the record is decided at the bottom of this
    // function, not by the pass that produced it.
    let label = take_string_attr(&mut record.attributes, ATTR_RESOLUTION);
    let correctable =
        label.as_deref().and_then(Disposition::from_label).is_some_and(Disposition::is_correctable);

    // Ambiguity was already marked at receipt, and that mark is what makes an ambiguous record
    // exceptional below. Peeked rather than taken: it belongs on the wire.
    let ambiguous = string_attr_value(&record.attributes, ATTR_SPREAD_NS).is_some()
        || record.attributes.iter().any(|kv| kv.key == ATTR_SPREAD_NS);

    // These two are internal bookkeeping and must not reach the wire whether or not there is an offset
    // to use them with.
    let event = take_int_attr(&mut record.attributes, ATTR_EVENT_BOOTTIME);
    let receipt = take_int_attr(&mut record.attributes, ATTR_RECEIPT_BOOTTIME);

    let applied = match (correctable, correction, event) {
        (true, Some(Correction { offset }), Some(event)) => {
            // Which field to write is derivable from the record itself: the receipt pass resolved
            // whichever of the two carried the stamp, following the same chain the receiver uses
            // when storing a single timestamp (SPEC.md §5.3).
            if record.time_unix_nano != 0 {
                record.time_unix_nano = project(event, offset);
                if let Some(receipt) = receipt {
                    record.observed_time_unix_nano = project(receipt, offset);
                }
            } else {
                record.observed_time_unix_nano = project(event, offset);
            }
            Some(offset)
        }
        _ => None,
    };

    // **Stamped by exception (design §9.1).** A record whose timestamp was corrected from a clock that
    // was synchronized, with no ambiguity, carries *no* clock attributes at all.
    //
    // These used to be unconditional — `corrected`, `correction_ns`, `resolution` and `sync_source` on
    // every record — and that was the wrong trade for two reasons. Cardinality: `correction_ns` is
    // effectively a new distinct value per boot, stored on every one of the millions of rows a year this
    // host produces, so it inflates the attribute index and clutters every filter dropdown with a value
    // nobody filters on. And redundancy: on the normal path they say the same thing on every row, and the
    // aggregate they add up to is already reported, once a minute, by the collector's own health event
    // (design §9) — which is the right place for "how is this host's clock doing".
    //
    // What is kept is the part no aggregate can reconstruct: **which individual records are not
    // ordinary.** A record that was not corrected keeps its `resolution`, so a timestamp that silently
    // degraded to `passthrough` is still visible per row — the exact failure this design exists to make
    // loud (design §4.2). Uncertainty and ambiguity keep their own markers for the same reason.
    //
    // The happy path is therefore identified by *absence*, which is the one reading that costs nothing to
    // store. `mp.collector.health` remains the place to look for rates and offsets.
    let exceptional = applied.is_none() || flush.uncertain || ambiguous;
    if exceptional && let Some(label) = label {
        record.attributes.push(string_attr(ATTR_RESOLUTION, &label));
    }
    if flush.uncertain {
        record.attributes.push(bool_attr(ATTR_UNCERTAIN, true));
    }

    applied.is_some()
}

/// Boottime plus offset, clamped into the unsigned range OTLP uses. A negative or overflowing
/// result would mean the offset and the boottime came from different boots, which the `boot_id`
/// guard already prevents; zero is the safe answer if it ever happens, since the receiver rejects
/// a record with no timestamp rather than storing a fabricated one (SPEC.md §5.3).
fn project(boottime: i64, offset: i64) -> u64 {
    boottime.checked_add(offset).and_then(|v| u64::try_from(v).ok()).unwrap_or(0)
}

/// Reads a string attribute and removes it, for the ones that carry state between the two passes.
fn take_string_attr(attributes: &mut Vec<KeyValue>, key: &str) -> Option<String> {
    let index = attributes.iter().position(|kv| kv.key == key)?;
    let removed = attributes.remove(index);
    match removed.value.and_then(|v| v.value) {
        Some(Value::StringValue(s)) => Some(s),
        _ => None,
    }
}

fn take_int_attr(attributes: &mut Vec<KeyValue>, key: &str) -> Option<i64> {
    let found = attributes.iter().rev().find(|kv| kv.key == key).and_then(as_int);
    attributes.retain(|kv| kv.key != key);
    found
}

fn as_int(kv: &KeyValue) -> Option<i64> {
    match kv.value.as_ref()?.value.as_ref()? {
        Value::IntValue(i) => Some(*i),
        _ => None,
    }
}

fn as_bool(kv: &KeyValue) -> Option<bool> {
    match kv.value.as_ref()?.value.as_ref()? {
        Value::BoolValue(b) => Some(*b),
        _ => None,
    }
}

fn string_attr_value<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a str> {
    attributes.iter().rev().find(|kv| kv.key == key).and_then(|kv| {
        match kv.value.as_ref()?.value.as_ref()? {
            Value::StringValue(s) => Some(s.as_str()),
            _ => None,
        }
    })
}

fn attr(key: &str, value: Value) -> KeyValue {
    // `..Default::default()` covers `key_strindex`, OTLP's string-table interning. The collector
    // writes plain keys and never populates a string table, so leaving it at zero is correct.
    KeyValue { key: key.to_owned(), value: Some(AnyValue { value: Some(value) }), ..Default::default() }
}

fn string_attr(key: &str, value: &str) -> KeyValue {
    attr(key, Value::StringValue(value.to_owned()))
}

fn int_attr(key: &str, value: i64) -> KeyValue {
    attr(key, Value::IntValue(value))
}

fn bool_attr(key: &str, value: bool) -> KeyValue {
    attr(key, Value::BoolValue(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::{DEFAULT_TOLERANCE_NANOS, Epoch, Source};
    use opentelemetry_proto::tonic::logs::v1::{ResourceLogs, ScopeLogs};

    const SEC: i64 = 1_000_000_000;
    const WALL: i64 = 1_785_924_000 * SEC;

    fn table(offset: i64) -> EpochTable {
        EpochTable::new(Epoch { boot_start: 0, offset, source: Source::Startup })
    }

    fn receipt() -> Receipt {
        Receipt { sender_started: 5 * SEC, received: 11 * SEC, tolerance: DEFAULT_TOLERANCE_NANOS }
    }

    fn request(records: Vec<LogRecord>) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs { log_records: records, ..Default::default() }],
                ..Default::default()
            }],
        }
    }

    fn record(time: i64, attributes: Vec<KeyValue>) -> LogRecord {
        LogRecord {
            time_unix_nano: time as u64,
            event_name: "cpu".to_owned(),
            attributes,
            ..Default::default()
        }
    }

    fn records(req: &ExportLogsServiceRequest) -> &[LogRecord] {
        &req.resource_logs[0].scope_logs[0].log_records
    }

    fn attr_of<'a>(r: &'a LogRecord, key: &str) -> Option<&'a Value> {
        r.attributes.iter().rev().find(|kv| kv.key == key)?.value.as_ref()?.value.as_ref()
    }

    /// Every `mp.clock.*` attribute left on a record, for asserting on the set rather than key by key.
    fn clock_attrs(r: &LogRecord) -> Vec<&str> {
        r.attributes.iter().map(|kv| kv.key.as_str()).filter(|k| k.starts_with(NS)).collect()
    }

    /// Whether the record carries none at all — the shape of an ordinary corrected record.
    fn no_clock_attrs(r: &LogRecord) -> bool {
        clock_attrs(r).is_empty()
    }

    /// The whole loop on the case the design exists for: a stamp from a stale clock goes in, a
    /// correct wall-clock time comes out.
    #[test]
    fn a_stale_stamp_survives_receipt_and_comes_out_corrected() {
        let stale = WALL - 3 * 86_400 * SEC;
        let mut req = request(vec![record(stale + 10 * SEC, vec![])]);

        let tally = resolve_request(&mut req, &table(stale), receipt());
        assert_eq!(tally.exact, 1);
        assert_eq!(
            records(&req)[0].time_unix_nano,
            (stale + 10 * SEC) as u64,
            "the arriving stamp stays put until a flush has an offset to project with"
        );
        assert_eq!(
            attr_of(&records(&req)[0], ATTR_EVENT_BOOTTIME),
            Some(&Value::IntValue(10 * SEC)),
            "the resolved boottime rides alongside"
        );

        // The clock has since been stepped; the flush samples the offset as it now stands.
        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: Some(SyncSource::MaxError),
        });

        let out = &records(&req)[0];
        assert_eq!(out.time_unix_nano, (WALL + 10 * SEC) as u64);
        // **Stamped by exception**: the correction happened, so the record says nothing about it. The
        // corrected timestamp *is* the output; a row asserting "yes, this is fine" on every record was
        // cardinality without information (design §9.1).
        assert!(
            no_clock_attrs(out),
            "an ordinary corrected record must carry no clock attributes: {:?}",
            clock_attrs(out)
        );
        // Named individually as well as by the set above, because each one was previously stamped here
        // and each is a separate decision to have stopped. `sync_source` in particular: which clock
        // source was trusted is a property of the *host at that moment*, not of the record, and the
        // health event reports it once a minute instead of once per row.
        for dropped in [ATTR_CORRECTED, ATTR_CORRECTION_NS, ATTR_RESOLUTION, ATTR_SYNC_SOURCE] {
            assert_eq!(attr_of(out, dropped), None, "{dropped} must not be stamped on a normal record");
        }
        assert!(attr_of(out, ATTR_UNCERTAIN).is_none(), "not a timeout flush");
    }

    /// The property that keeps retries idempotent. Two flushes of the same batch with the same
    /// frozen `Correction` must produce byte-identical timestamps — the receiver hashes
    /// `event_time` into the measurement id (SPEC.md §6.6), so a microsecond of slew between
    /// attempts would land as a duplicate row.
    #[test]
    fn a_frozen_correction_makes_a_retry_byte_identical() {
        let build = || {
            let mut req = request(vec![record(WALL + 10 * SEC, vec![])]);
            resolve_request(&mut req, &table(WALL), receipt());
            req
        };
        let frozen = Correction { offset: WALL + 1234 };
        let flush = Flush { uncertain: false, sync_source: Some(SyncSource::MaxError) };

        let (mut first, mut retry) = (build(), build());
        apply_correction(&mut first, Some(frozen), flush);
        apply_correction(&mut retry, Some(frozen), flush);
        assert_eq!(first, retry);

        // And the counter-example: re-sampling the offset, as the design doc originally said to,
        // shifts the timestamp and would produce a second measurement.
        let mut resampled = build();
        apply_correction(&mut resampled, Some(Correction { offset: frozen.offset + 5_000 }), flush);
        assert_ne!(
            records(&resampled)[0].time_unix_nano,
            records(&first)[0].time_unix_nano,
            "a re-sampled offset must be observably different, or this test proves nothing"
        );
    }

    /// A foreign timestamp is never touched, at either pass.
    #[test]
    fn a_passthrough_record_is_left_alone() {
        let historical = WALL - 400 * 86_400 * SEC;
        let mut req = request(vec![record(historical, vec![])]);

        let tally = resolve_request(&mut req, &table(WALL), receipt());
        assert_eq!(tally.passthrough, 1);
        assert_eq!(records(&req)[0].time_unix_nano, historical as u64);

        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: None,
        });

        let out = &records(&req)[0];
        assert_eq!(out.time_unix_nano, historical as u64, "a foreign frame must survive intact");
        // **The exception that must stay visible.** A record that was not corrected keeps its
        // resolution, so a timestamp silently degrading to passthrough is still detectable per row —
        // the failure mode design §4.2 exists to make loud.
        assert_eq!(
            attr_of(out, ATTR_RESOLUTION),
            Some(&Value::StringValue("passthrough".to_owned()))
        );
        // ...and nothing more than that.
        assert_eq!(attr_of(out, ATTR_CORRECTED), None);
        assert_eq!(attr_of(out, ATTR_CORRECTION_NS), None);
        assert_eq!(attr_of(out, ATTR_SYNC_SOURCE), None);
    }

    /// Tier 2: the application says it already knows. Even a timestamp that *would* have resolved
    /// must not be rewritten.
    #[test]
    fn an_authoritative_record_is_not_corrected_even_when_resolvable() {
        let mut req = request(vec![record(
            WALL + 10 * SEC,
            vec![bool_attr(ATTR_AUTHORITATIVE, true)],
        )]);

        let tally = resolve_request(&mut req, &table(WALL), receipt());
        assert_eq!(tally.authoritative, 1);

        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: None,
        });
        let out = &records(&req)[0];
        assert_eq!(out.time_unix_nano, (WALL + 10 * SEC) as u64);
        assert_eq!(
            attr_of(out, ATTR_RESOLUTION),
            Some(&Value::StringValue("authoritative".to_owned()))
        );
    }

    /// Tier 1 beats the window entirely — which is the point of it. This record's stamp is far
    /// outside `[sender_started, received]` and would otherwise pass through.
    #[test]
    fn a_boottime_hint_resolves_a_record_the_window_would_reject() {
        let mut req = request(vec![record(
            WALL - 900 * SEC,
            vec![int_attr(ATTR_BOOTTIME, 7 * SEC)],
        )]);

        let tally = resolve_request(&mut req, &table(WALL), receipt());
        assert_eq!(tally.exact, 1);
        assert_eq!(
            attr_of(&records(&req)[0], ATTR_EVENT_BOOTTIME),
            Some(&Value::IntValue(7 * SEC))
        );
    }

    /// §6.1's cardinality hazard. A per-record boottime left in the attributes would become part
    /// of time series identity, so reading a hint has to consume it.
    #[test]
    fn hint_attributes_never_reach_the_wire() {
        let mut req = request(vec![record(
            WALL + 10 * SEC,
            vec![
                int_attr(ATTR_BOOTTIME, 7 * SEC),
                bool_attr(ATTR_AUTHORITATIVE, false),
                string_attr("unit", "ratio"),
            ],
        )]);
        resolve_request(&mut req, &table(WALL), receipt());
        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: None,
        });

        let keys: Vec<&str> = records(&req)[0].attributes.iter().map(|kv| kv.key.as_str()).collect();
        assert!(!keys.contains(&ATTR_BOOTTIME), "the hint became series identity: {keys:?}");
        assert!(!keys.contains(&ATTR_AUTHORITATIVE), "{keys:?}");
        assert!(keys.contains(&"unit"), "an application attribute was lost: {keys:?}");
    }

    /// The collector's own bookkeeping is not the application's business, and would be one more
    /// per-record varying value in series identity if it escaped.
    #[test]
    fn internal_attributes_never_reach_the_wire() {
        for correction in [Some(Correction { offset: WALL }), None] {
            let mut req = request(vec![record(WALL + 10 * SEC, vec![])]);
            resolve_request(&mut req, &table(WALL), receipt());
            assert!(
                attr_of(&records(&req)[0], ATTR_EVENT_BOOTTIME).is_some(),
                "precondition: the receipt pass records a boottime"
            );

            apply_correction(&mut req, correction, Flush { uncertain: false, sync_source: None });

            let keys: Vec<&str> =
                records(&req)[0].attributes.iter().map(|kv| kv.key.as_str()).collect();
            assert!(!keys.contains(&ATTR_EVENT_BOOTTIME), "{correction:?}: {keys:?}");
            assert!(!keys.contains(&ATTR_RECEIPT_BOOTTIME), "{correction:?}: {keys:?}");
        }
    }

    /// §8.4. A record spooled to disk and read back after a reboot carries a boottime that
    /// describes a machine which no longer exists. There is nothing to project it with, so it
    /// ships with the stamp it arrived with — the property the "leave the original in place"
    /// invariant exists to make free.
    #[test]
    fn a_record_spooled_across_a_reboot_ships_with_its_original_stamp() {
        let stale = WALL - 3 * 86_400 * SEC;
        let mut req = request(vec![record(stale + 10 * SEC, vec![])]);
        resolve_request(&mut req, &table(stale), receipt());

        // No correction: the boot_id guard rejected the persisted epoch table.
        apply_correction(&mut req, None, Flush { uncertain: true, sync_source: None });

        let out = &records(&req)[0];
        assert_eq!(
            out.time_unix_nano,
            (stale + 10 * SEC) as u64,
            "the record must still be shippable OTLP, not a bare boottime"
        );
        assert_eq!(attr_of(out, ATTR_UNCERTAIN), Some(&Value::BoolValue(true)));
        assert!(
            attr_of(out, ATTR_RESOLUTION).is_some(),
            "an uncorrected record keeps its resolution"
        );
        assert_eq!(attr_of(out, ATTR_CORRECTED), None);
        assert_eq!(attr_of(out, ATTR_CORRECTION_NS), None);
    }

    /// The collector's receipt time becomes `observed_time_unix_nano` — but only once there is an
    /// offset to project it with, and only when it is not already carrying the event time.
    #[test]
    fn the_receipt_time_becomes_the_observed_time() {
        let mut req = request(vec![record(WALL + 10 * SEC, vec![])]);
        resolve_request(&mut req, &table(WALL), receipt());
        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: None,
        });

        // receipt().received is 11 s of boottime.
        assert_eq!(records(&req)[0].observed_time_unix_nano, (WALL + 11 * SEC) as u64);
    }

    #[test]
    fn split_hints_reads_and_removes_both_tiers() {
        let (hints, kept) = split_hints(vec![
            string_attr("unit", "ratio"),
            int_attr(ATTR_BOOTTIME, 42),
            bool_attr(ATTR_AUTHORITATIVE, true),
        ]);
        assert_eq!(hints, Hints { boottime: Some(42), authoritative: true });
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].key, "unit");

        // A hint of the wrong type is ignored rather than trusted, but still stripped.
        let (hints, kept) = split_hints(vec![string_attr(ATTR_BOOTTIME, "soon")]);
        assert_eq!(hints, Hints::default());
        assert!(kept.is_empty());
    }

    /// A record with only `observed_time_unix_nano` set: the receiver would store that as
    /// `event_time`, so it is the field that must be corrected — and `time_unix_nano` must stay
    /// zero rather than becoming the offset.
    #[test]
    fn an_observed_only_record_is_corrected_in_place() {
        let mut record = record(0, vec![]);
        record.observed_time_unix_nano = (WALL + 10 * SEC) as u64;
        let mut req = request(vec![record]);

        assert_eq!(resolve_request(&mut req, &table(WALL), receipt()).exact, 1);
        assert_eq!(
            attr_of(&records(&req)[0], ATTR_EVENT_BOOTTIME),
            Some(&Value::IntValue(10 * SEC))
        );

        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: None,
        });
        let out = &records(&req)[0];
        assert_eq!(out.observed_time_unix_nano, (WALL + 10 * SEC) as u64);
        assert_eq!(out.time_unix_nano, 0, "an unset field must not be fabricated from the offset");
    }

    /// Both stamps zero is malformed OTLP; the receiver rejects it (SPEC.md §5.3). The collector
    /// must not paper over that by inventing a time.
    #[test]
    fn a_record_with_no_timestamp_at_all_is_left_malformed() {
        let mut req = request(vec![record(0, vec![])]);
        assert_eq!(resolve_request(&mut req, &table(WALL), receipt()).passthrough, 1);
        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: None,
        });
        assert_eq!(records(&req)[0].time_unix_nano, 0);
        assert_eq!(records(&req)[0].observed_time_unix_nano, 0);
    }

    /// The timeout flush: no sync ever arrived, so the data ships marked rather than being
    /// dropped or held forever.
    #[test]
    fn a_timeout_flush_marks_every_record_uncertain() {
        let mut req = request(vec![record(WALL + 10 * SEC, vec![])]);
        resolve_request(&mut req, &table(WALL), receipt());
        apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: true,
            sync_source: None,
        });

        let out = &records(&req)[0];
        assert_eq!(attr_of(out, ATTR_UNCERTAIN), Some(&Value::BoolValue(true)));
        assert!(attr_of(out, ATTR_SYNC_SOURCE).is_none(), "nothing said the clock was good");
    }

    /// Ambiguity is reported, not hidden: the spread is the honest error bar. Same fixture as
    /// `epoch::tests::two_explanations_are_ambiguous_and_the_spread_is_reported` — the old offset
    /// puts the event at 5.5 s, the new one at 10 s, and both are inside their own epoch.
    #[test]
    fn ambiguity_carries_its_spread() {
        let half = SEC / 2;
        let table = table(WALL).with(Epoch {
            boot_start: 6 * SEC,
            offset: WALL - 4 * SEC - half,
            source: Source::Step,
        });
        let mut req = request(vec![record(WALL + 5 * SEC + half, vec![])]);

        let tally = resolve_request(&mut req, &table, Receipt { received: 13 * SEC, ..receipt() });
        assert_eq!(tally.ambiguous, 1);
        assert_eq!(
            attr_of(&records(&req)[0], ATTR_EVENT_BOOTTIME),
            Some(&Value::IntValue(10 * SEC)),
            "nearest to receipt wins"
        );
        assert_eq!(
            attr_of(&records(&req)[0], ATTR_SPREAD_NS),
            Some(&Value::IntValue(4 * SEC + half))
        );
    }

    /// Every record in a batch shares one offset. Sampling per record would let them drift
    /// relative to one another and break ordering within a burst.
    #[test]
    fn one_offset_covers_the_whole_batch() {
        let mut req = request(
            (0..5).map(|i| record(WALL + (6 + i) * SEC, vec![])).collect(),
        );
        resolve_request(&mut req, &table(WALL), receipt());
        apply_correction(&mut req, Some(Correction { offset: WALL + 77 }), Flush {
            uncertain: false,
            sync_source: None,
        });

        let times: Vec<u64> = records(&req).iter().map(|r| r.time_unix_nano).collect();
        let expected: Vec<u64> = (0..5).map(|i| (WALL + 77 + (6 + i) * SEC) as u64).collect();
        assert_eq!(times, expected);
        assert!(times.windows(2).all(|w| w[0] < w[1]), "burst ordering broke: {times:?}");
    }

    #[test]
    fn tallies_add_up_across_a_mixed_batch() {
        let mut req = request(vec![
            record(WALL + 10 * SEC, vec![]),
            record(WALL - 400 * 86_400 * SEC, vec![]),
            record(WALL + 9 * SEC, vec![bool_attr(ATTR_AUTHORITATIVE, true)]),
        ]);
        let tally = resolve_request(&mut req, &table(WALL), receipt());
        assert_eq!(tally, Tally { exact: 1, ambiguous: 0, passthrough: 1, authoritative: 1 });
        assert_eq!(tally.total(), 3);
        assert_eq!(tally.correctable(), 1);

        let corrected = apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
            uncertain: false,
            sync_source: None,
        });
        assert_eq!(corrected, 1);
    }

    #[test]
    fn an_empty_request_is_a_no_op() {
        let mut req = ExportLogsServiceRequest::default();
        assert_eq!(resolve_request(&mut req, &table(WALL), receipt()), Tally::default());
        assert_eq!(
            apply_correction(&mut req, Some(Correction { offset: WALL }), Flush {
                uncertain: false,
                sync_source: None
            }),
            0
        );
    }

    /// A projection that cannot land in range yields zero, which the receiver rejects outright
    /// (SPEC.md §5.3), rather than wrapping into a plausible-looking wrong instant.
    #[test]
    fn an_impossible_projection_yields_no_timestamp_rather_than_a_wrong_one() {
        assert_eq!(project(0, WALL), WALL as u64, "boottime zero is the moment of boot");
        assert_eq!(project(10 * SEC, WALL), (WALL + 10 * SEC) as u64);
        assert_eq!(project(10, -100), 0, "before the epoch is not representable");
        assert_eq!(project(i64::MAX, 1), 0, "overflow must not wrap");
    }

    #[test]
    fn dispositions_round_trip_through_their_label() {
        for d in [
            Disposition::Resolved(Resolution::Exact { boottime: 1 }),
            Disposition::Resolved(Resolution::Ambiguous { boottime: 1, spread: 2 }),
            Disposition::Resolved(Resolution::Passthrough),
            Disposition::Authoritative,
        ] {
            let back = Disposition::from_label(d.label()).expect("label should round-trip");
            assert_eq!(back.label(), d.label());
            assert_eq!(back.is_correctable(), d.is_correctable());
        }
        assert!(Disposition::from_label("nonsense").is_none());
    }

    /// The namespace exists so a future OTel convention cannot collide. Assert every emitted key
    /// is actually inside it, since a stray one would be the whole point missed.
    #[test]
    fn every_emitted_attribute_is_namespaced() {
        for key in [
            ATTR_BOOTTIME,
            ATTR_AUTHORITATIVE,
            ATTR_CORRECTED,
            ATTR_CORRECTION_NS,
            ATTR_RESOLUTION,
            ATTR_SPREAD_NS,
            ATTR_UNCERTAIN,
            ATTR_SYNC_SOURCE,
        ] {
            assert!(key.starts_with(NS), "{key} escapes the {NS} namespace");
        }
    }
}
