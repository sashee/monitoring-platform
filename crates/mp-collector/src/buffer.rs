//! The bounded pre-sync buffer (design §4.6). Pure: the caller does the disk I/O.
//!
//! Holds resolved batches — each one valid OTLP already, each one carrying the boottime it was
//! resolved to — until there is an offset worth projecting them with.
//!
//! Two rules the design is emphatic about, and this type enforces both structurally:
//!
//! - **Nothing is ever dropped.** Over the cap, the *oldest* batches come back out of [`push`] for
//!   the caller to spill to disk. They are not discarded, and they are not the newest ones either:
//!   flushing reads the spool before the queue, so shipping order is preserved.
//! - **Buffering is only for a clock that has never been set this boot.** Degradation *after* a
//!   good sync must not buffer (§8.2) — that would halt telemetry during a network outage,
//!   precisely when it is most wanted, to avoid an error smaller than the transmission delay. This
//!   type does not decide that; [`Decision`] does, and it is a pure function of two booleans and a
//!   duration so the rule is readable in one place.
//!
//! [`push`]: Buffer::push

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use std::collections::VecDeque;
use std::time::Duration;

use crate::correct::Tally;

/// One received batch, resolved and waiting.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub request: ExportLogsServiceRequest,
    /// Encoded size, for the byte cap. Recorded rather than recomputed: re-encoding a batch to
    /// measure it on every push would dominate the cost of buffering it.
    pub bytes: usize,
    /// `CLOCK_BOOTTIME` at which it entered the buffer, for the oldest-record-age metric (§9).
    pub queued_at: i64,
    /// What the receipt pass concluded about its records. Carries the depth too — the count is
    /// `tally.total()` rather than a second field that could disagree with it.
    pub tally: Tally,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_records: usize,
    pub max_bytes: usize,
}

/// A bounded FIFO of pending batches.
#[derive(Debug)]
pub struct Buffer {
    queue: VecDeque<Pending>,
    bytes: usize,
    records: usize,
    limits: Limits,
}

impl Buffer {
    pub fn new(limits: Limits) -> Self {
        Self { queue: VecDeque::new(), bytes: 0, records: 0, limits }
    }

    /// Adds a batch, returning any that no longer fit — oldest first, ready to spill.
    ///
    /// A single batch larger than the whole cap is kept rather than immediately evicted: evicting
    /// it would spill the thing just received while the buffer sat empty, which is churn with no
    /// benefit. It leaves the buffer over its cap until the next flush, which is bounded by the
    /// wire body limit.
    pub fn push(&mut self, pending: Pending) -> Vec<Pending> {
        self.bytes += pending.bytes;
        self.records += pending.tally.total() as usize;
        self.queue.push_back(pending);

        let mut spilled = Vec::new();
        while self.queue.len() > 1 && self.over_capacity() {
            let evicted = self.queue.pop_front().expect("len > 1");
            self.bytes -= evicted.bytes;
            self.records -= evicted.tally.total() as usize;
            spilled.push(evicted);
        }
        spilled
    }

    fn over_capacity(&self) -> bool {
        self.records > self.limits.max_records || self.bytes > self.limits.max_bytes
    }

    /// Empties the buffer.
    pub fn drain(&mut self) -> Vec<Pending> {
        self.bytes = 0;
        self.records = 0;
        self.queue.drain(..).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Records held, for the §9 depth metric.
    pub fn depth(&self) -> u64 {
        self.records as u64
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Age of the oldest batch at `now`, for the §9 metric. `None` when empty.
    pub fn oldest_age(&self, now_boottime: i64) -> Option<Duration> {
        let queued_at = self.queue.front()?.queued_at;
        Some(Duration::from_nanos(now_boottime.saturating_sub(queued_at).max(0) as u64))
    }
}

/// What to do with what is in hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Ship it, corrected.
    Flush,
    /// Ship it uncorrected and marked: the wait is over and the clock never arrived.
    FlushUncertain,
    /// Keep waiting.
    Hold,
}

/// The §4.6 / §8.2 rule, in one place.
///
/// `synchronized` is whether the clock is trustworthy *now*; `ever_synchronized` is whether it
/// ever was this boot. The asymmetry between them is the whole of §8.2: once the clock has been
/// set, a later loss of discipline is not a reason to withhold anything. maxerror climbs past any
/// threshold within an hour or two of chrony dying, but that is the conservative *bound* growing,
/// not the clock going bad — actual error stays in the milliseconds, far below the transmission
/// delay the correction is accurate to anyway.
pub fn decide(
    synchronized: bool,
    ever_synchronized: bool,
    waited: Duration,
    timeout: Duration,
) -> Decision {
    if synchronized || ever_synchronized {
        Decision::Flush
    } else if waited >= timeout {
        Decision::FlushUncertain
    } else {
        Decision::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

    const SEC: i64 = 1_000_000_000;

    fn pending(bytes: usize, records: u64, queued_at: i64) -> Pending {
        Pending {
            request: ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs {
                    scope_logs: vec![ScopeLogs {
                        log_records: vec![LogRecord::default(); records as usize],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            },
            bytes,
            queued_at,
            tally: Tally { exact: records, ..Tally::default() },
        }
    }

    fn limits(max_records: usize, max_bytes: usize) -> Limits {
        Limits { max_records, max_bytes }
    }

    #[test]
    fn holds_everything_under_the_cap() {
        let mut buffer = Buffer::new(limits(100, 10_000));
        for i in 0..5 {
            assert!(buffer.push(pending(100, 10, i * SEC)).is_empty());
        }
        assert_eq!(buffer.depth(), 50);
        assert_eq!(buffer.bytes(), 500);
        assert_eq!(buffer.drain().len(), 5);
        assert!(buffer.is_empty());
    }

    /// Over the record cap, the *oldest* comes out — not the newest, and not nothing. Shipping
    /// reads the spool before the queue, so oldest-first eviction is what preserves arrival order
    /// end to end.
    #[test]
    fn the_record_cap_spills_oldest_first() {
        let mut buffer = Buffer::new(limits(25, 1_000_000));
        let mut spilled = Vec::new();
        for i in 0..4 {
            spilled.extend(buffer.push(pending(10, 10, i * SEC)));
        }

        assert_eq!(
            spilled.iter().map(|p| p.queued_at).collect::<Vec<_>>(),
            vec![0, SEC],
            "the two oldest should have been shed, in order"
        );
        assert_eq!(buffer.depth(), 20, "and the buffer trimmed back under its cap");
    }

    #[test]
    fn the_byte_cap_spills_independently_of_the_record_cap() {
        let mut buffer = Buffer::new(limits(1_000_000, 250));
        for i in 0..2 {
            assert!(buffer.push(pending(100, 1, i * SEC)).is_empty());
        }
        let spilled = buffer.push(pending(100, 1, 2 * SEC));
        assert_eq!(spilled.len(), 1);
        assert_eq!(buffer.bytes(), 200);
    }

    /// Nothing is ever dropped: everything pushed comes back out of either `push` or `drain`.
    #[test]
    fn every_batch_comes_out_somewhere() {
        let mut buffer = Buffer::new(limits(30, 1_000_000));
        let mut seen = Vec::new();
        for i in 0..10 {
            seen.extend(buffer.push(pending(10, 10, i * SEC)).into_iter().map(|p| p.queued_at));
        }
        seen.extend(buffer.drain().into_iter().map(|p| p.queued_at));

        seen.sort_unstable();
        assert_eq!(seen, (0..10).map(|i| i * SEC).collect::<Vec<_>>(), "a batch went missing");
    }

    /// A single oversized batch is kept rather than spilled the instant it arrives. Evicting the
    /// only thing in the buffer is pure churn.
    #[test]
    fn one_oversized_batch_is_kept_rather_than_immediately_spilled() {
        let mut buffer = Buffer::new(limits(10, 100));
        assert!(buffer.push(pending(10_000, 5_000, 0)).is_empty());
        assert_eq!(buffer.depth(), 5_000);

        // The next arrival does push the oversized one out, which is correct: now there is
        // somewhere for it to go.
        let spilled = buffer.push(pending(10, 1, SEC));
        assert_eq!(spilled.len(), 1);
        assert_eq!(spilled[0].tally.total(), 5_000);
    }

    #[test]
    fn reports_the_age_of_the_oldest_batch() {
        let mut buffer = Buffer::new(limits(100, 10_000));
        assert_eq!(buffer.oldest_age(10 * SEC), None);

        buffer.push(pending(10, 1, 2 * SEC));
        buffer.push(pending(10, 1, 8 * SEC));
        assert_eq!(buffer.oldest_age(10 * SEC), Some(Duration::from_secs(8)));

        // A clock reading that went backwards must not produce a nonsense age.
        assert_eq!(buffer.oldest_age(0), Some(Duration::ZERO));
    }

    /// The pre-sync case the whole buffer exists for.
    #[test]
    fn an_unsynchronized_clock_holds() {
        assert_eq!(
            decide(false, false, Duration::from_secs(10), Duration::from_secs(300)),
            Decision::Hold
        );
    }

    /// §8.1: a Pi that boots with no network. The data ships marked, not dropped, and not held
    /// forever.
    #[test]
    fn the_timeout_flushes_marked_rather_than_dropping() {
        assert_eq!(
            decide(false, false, Duration::from_secs(300), Duration::from_secs(300)),
            Decision::FlushUncertain
        );
        assert_eq!(
            decide(false, false, Duration::from_secs(3000), Duration::from_secs(300)),
            Decision::FlushUncertain
        );
    }

    /// §8.2, and the reason `ever_synchronized` exists as a separate input. Buffering on a
    /// mid-run loss of discipline would halt telemetry during exactly the incident worth
    /// observing.
    #[test]
    fn losing_discipline_after_a_good_sync_does_not_re_arm_the_buffer() {
        assert_eq!(
            decide(false, true, Duration::from_secs(0), Duration::from_secs(300)),
            Decision::Flush,
            "a clock that was set stays trusted; only the error bound grows"
        );
        assert_eq!(
            decide(false, true, Duration::from_secs(86_400), Duration::from_secs(300)),
            Decision::Flush
        );
    }

    #[test]
    fn a_synchronized_clock_flushes_immediately() {
        assert_eq!(
            decide(true, true, Duration::ZERO, Duration::from_secs(300)),
            Decision::Flush
        );
        assert_eq!(
            decide(true, false, Duration::ZERO, Duration::from_secs(300)),
            Decision::Flush,
            "the first sync of the boot releases the buffer"
        );
    }
}
