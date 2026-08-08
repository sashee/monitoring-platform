//! The offset epoch table and frame resolution (design §4.1, §5.2). Pure; no I/O, no clock.
//!
//! An *epoch* is a stretch of boottime over which `realtime − boottime` held one value. Anything
//! that steps the realtime clock ends one and begins another. Given that history, a wall-clock
//! timestamp produced on this host can be mapped back to a boottime — frame-invariant, immune to
//! every subsequent step — and re-projected into the corrected frame later.
//!
//! **`boot_end` is not stored.** An epoch ends where the next one begins, and the last one has not
//! ended. Keeping both would be two facts for one boundary, which can disagree; the design doc's
//! struct had that field and this deliberately drops it.

/// Where a boundary came from. Emitted on the self-metrics, and the reason a table read back from
/// disk can be told from one reconstructed live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Source {
    /// Reconstructed at startup from journald's paired realtime/monotonic stamps (§4.2).
    Journal,
    /// Observed live: `TFD_TIMER_CANCEL_ON_SET` fired (§4.3).
    Step,
    /// Noticed by the periodic consistency check rather than by the watch — see
    /// [`DEFAULT_RESYNC_THRESHOLD_NANOS`].
    Resync,
    /// The collector's own first reading, with no history behind it.
    Startup,
}

/// One stretch of constant offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Epoch {
    /// `CLOCK_BOOTTIME` at which this offset became active, nanoseconds.
    pub boot_start: i64,
    /// `realtime − boottime`, nanoseconds. i64 spans ±292 years, which is not close.
    pub offset: i64,
    pub source: Source,
}

/// How far outside an epoch's nominal bounds a resolved value may still fall.
///
/// Boundaries are fuzzy: a step is *learned about* after it happens, by however long the collector
/// took to wake up. 50 ms is generous for an epoll wakeup and still far below the granularity any
/// of this claims to deliver.
pub const DEFAULT_TOLERANCE_NANOS: i64 = 50_000_000;

/// How far a freshly sampled offset may sit from the active epoch's before it is treated as a
/// boundary the watch did not report.
///
/// **This is not slew tracking.** Slewing cannot move this quantity: `CLOCK_REALTIME` and
/// `CLOCK_BOOTTIME` share one frequency adjustment, so a slewed correction shifts both by the same
/// amount and their difference is untouched. Measured under active NTP discipline the offset held
/// to ±500 ns over twelve seconds — read interleave, nothing more. The design doc's §6.2 says a
/// stored offset "goes stale" under slew; it does not.
///
/// What this catches is a genuine discontinuity that the cancel-on-set watch missed: a step
/// landing during a collector restart, or a `timerfd` that failed to re-arm. Rare, cheap to check
/// once a second, and the alternative is resolving every subsequent record against an offset the
/// machine no longer uses.
pub const DEFAULT_RESYNC_THRESHOLD_NANOS: i64 = 200_000_000;

/// Everything §5.2 needs to know about one incoming record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    /// The wall-clock timestamp the application wrote, nanoseconds since the Unix epoch.
    pub stamped: i64,
    /// `CLOCK_BOOTTIME` at which the sending process started. A hard lower bound on any timestamp
    /// that process could have read from a clock.
    pub sender_started: i64,
    /// `CLOCK_BOOTTIME` at which the collector dequeued the record. A hard upper bound.
    pub received: i64,
}

/// What the table could say about a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Exactly one epoch explains it. `boottime` is the event in the invariant frame.
    Exact { boottime: i64 },
    /// Several do. `boottime` is the candidate nearest receipt; `spread` is how far apart the
    /// candidates were, which is the honest error bar.
    Ambiguous { boottime: i64, spread: i64 },
    /// None do. A foreign frame — a remote server's `Date` header, GPS, a prior boot — or an
    /// epoch the table never learned. Either way the collector is not entitled to rewrite it.
    Passthrough,
}

impl Resolution {
    /// The boottime to correct at flush, if there is one.
    pub fn boottime(self) -> Option<i64> {
        match self {
            Resolution::Exact { boottime } | Resolution::Ambiguous { boottime, .. } => Some(boottime),
            Resolution::Passthrough => None,
        }
    }

    /// The `mp.clock.resolution` attribute value.
    pub fn label(self) -> &'static str {
        match self {
            Resolution::Exact { .. } => "exact",
            Resolution::Ambiguous { .. } => "ambiguous",
            Resolution::Passthrough => "passthrough",
        }
    }
}

/// The offset history for one boot, ordered by `boot_start`.
///
/// Values, not a mutable store: [`with`](Self::with) returns a new table. Steps happen a handful
/// of times per boot, so the clone is free and nothing shares state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTable {
    /// Non-empty and sorted ascending by `boot_start`, maintained by every constructor here.
    epochs: Vec<Epoch>,
}

impl EpochTable {
    /// A table with one epoch and no history behind it.
    pub fn new(first: Epoch) -> Self {
        Self { epochs: vec![first] }
    }

    /// Builds from an arbitrary set of epochs, sorting and collapsing.
    ///
    /// Two boundaries at the same boottime are the same boundary learned twice — the journal
    /// backfill and the live timerfd can both witness one step — and an epoch whose offset equals
    /// its predecessor's is not a boundary at all. Both are dropped, because either would show up
    /// later as a spurious `Ambiguous`: duplicate epochs produce duplicate candidates.
    pub fn from_epochs(mut epochs: Vec<Epoch>) -> Option<Self> {
        epochs.sort_by_key(|e| e.boot_start);
        epochs.dedup_by(|later, earlier| {
            later.boot_start == earlier.boot_start || later.offset == earlier.offset
        });
        (!epochs.is_empty()).then_some(Self { epochs })
    }

    /// This table plus one later boundary.
    ///
    /// A boundary at or before the current last one is dropped: history only extends forward, and
    /// accepting an out-of-order boundary would break the sort every lookup relies on.
    pub fn with(&self, epoch: Epoch) -> Self {
        let last = self.current();
        if epoch.boot_start <= last.boot_start || epoch.offset == last.offset {
            return self.clone();
        }
        let mut epochs = self.epochs.clone();
        epochs.push(epoch);
        Self { epochs }
    }

    /// The epoch in force now. Always present.
    pub fn current(&self) -> Epoch {
        *self.epochs.last().expect("EpochTable is never empty by construction")
    }

    /// Whether a freshly sampled offset disagrees with the active epoch by enough to be a
    /// boundary. See [`DEFAULT_RESYNC_THRESHOLD_NANOS`] for why any disagreement at all is
    /// suspicious.
    pub fn disagrees_with(&self, sampled_offset: i64, threshold: i64) -> bool {
        (sampled_offset - self.current().offset).abs() > threshold
    }

    /// How many epochs the table holds. Always at least one.
    pub fn len(&self) -> usize {
        self.epochs.len()
    }

    /// Never. Present because `len` is, and constant because every constructor here refuses to
    /// build an empty table — [`resolve`](Self::resolve) with no epochs could only ever return
    /// `Passthrough`, which is indistinguishable from "this timestamp is foreign" and would hide
    /// a collector that had silently lost its history.
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn epochs(&self) -> &[Epoch] {
        &self.epochs
    }

    /// §5.2. Which boottime, if any, this wall-clock timestamp denotes.
    ///
    /// The `[sender_started, received]` window is what makes this work without any application
    /// cooperation or configured constant: a process cannot have read a clock before it existed,
    /// and cannot have read one after the collector already had the record. It is far tighter than
    /// "within N seconds of now" and has no magic number in it.
    pub fn resolve(&self, q: Query, tolerance: i64) -> Resolution {
        let mut candidates: Vec<i64> = Vec::new();

        for (i, epoch) in self.epochs.iter().enumerate() {
            let boot_end = self.epochs.get(i + 1).map_or(i64::MAX, |next| next.boot_start);
            let Some(evt) = q.stamped.checked_sub(epoch.offset) else { continue };

            let within_epoch = evt >= epoch.boot_start.saturating_sub(tolerance)
                && evt < boot_end.saturating_add(tolerance);
            let within_window = evt >= q.sender_started.saturating_sub(tolerance)
                && evt <= q.received.saturating_add(tolerance);

            // Two epochs can carry offsets close enough that one timestamp lands in both windows
            // at almost the same boottime. Reporting that as ambiguous with a nanosecond spread
            // would be technically true and useless, so near-identical candidates collapse.
            if within_epoch && within_window && !candidates.iter().any(|c| (c - evt).abs() < tolerance) {
                candidates.push(evt);
            }
        }

        match candidates.len() {
            0 => Resolution::Passthrough,
            1 => Resolution::Exact { boottime: candidates[0] },
            _ => {
                // Nearest to receipt: of two frames that both explain the timestamp, the one
                // implying the shorter application-to-collector delay is the better bet. This is
                // the design's "fixed receipt-proximity window" surviving only as a tie-break.
                let boottime = *candidates
                    .iter()
                    .min_by_key(|c| (q.received - **c).abs())
                    .expect("len > 1");
                let lo = *candidates.iter().min().expect("len > 1");
                let hi = *candidates.iter().max().expect("len > 1");
                Resolution::Ambiguous { boottime, spread: hi - lo }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: i64 = 1_000_000_000;
    /// A plausible wall clock: 2026-08-06T10:00:00Z, near enough.
    const WALL: i64 = 1_785_924_000 * SEC;

    fn epoch(boot_start: i64, offset: i64) -> Epoch {
        Epoch { boot_start, offset, source: Source::Step }
    }

    /// The ordinary case: one epoch, a timestamp inside the window.
    #[test]
    fn a_single_epoch_resolves_exactly() {
        let table = EpochTable::new(epoch(0, WALL));
        let q = Query { stamped: WALL + 10 * SEC, sender_started: 5 * SEC, received: 11 * SEC };
        assert_eq!(table.resolve(q, DEFAULT_TOLERANCE_NANOS), Resolution::Exact { boottime: 10 * SEC });
    }

    /// The cold-boot case the whole design exists for. The clock is restored to days in the past,
    /// an application logs, then NTP steps it. The pre-step record must still resolve.
    #[test]
    fn a_record_from_before_the_step_resolves_against_the_old_epoch() {
        let stale = WALL - 3 * 86_400 * SEC; // fake-hwclock: roughly the last shutdown
        let table = EpochTable::new(epoch(0, stale)).with(epoch(30 * SEC, WALL));

        // Stamped at boottime 10 s, while the clock still read three days ago.
        let q = Query { stamped: stale + 10 * SEC, sender_started: 2 * SEC, received: 10 * SEC };
        assert_eq!(table.resolve(q, DEFAULT_TOLERANCE_NANOS), Resolution::Exact { boottime: 10 * SEC });
    }

    /// A timestamp no epoch explains is not the collector's to touch. This is the property that
    /// keeps a remote server's `Date` header or a GPS fix from being silently rewritten.
    #[test]
    fn a_foreign_timestamp_passes_through() {
        let table = EpochTable::new(epoch(0, WALL));
        let q = Query { stamped: WALL - 400 * 86_400 * SEC, sender_started: 5 * SEC, received: 11 * SEC };
        assert_eq!(table.resolve(q, DEFAULT_TOLERANCE_NANOS), Resolution::Passthrough);
    }

    /// The `[sender_started, received]` window, both ends. Neither bound is decorative: without
    /// the lower one a replayed historical value inside the epoch would be "corrected".
    #[test]
    fn the_process_window_bounds_the_answer_at_both_ends() {
        let table = EpochTable::new(epoch(0, WALL));

        let before_start =
            Query { stamped: WALL + SEC, sender_started: 5 * SEC, received: 11 * SEC };
        assert_eq!(table.resolve(before_start, 0), Resolution::Passthrough);

        let after_receipt =
            Query { stamped: WALL + 20 * SEC, sender_started: 5 * SEC, received: 11 * SEC };
        assert_eq!(table.resolve(after_receipt, 0), Resolution::Passthrough);
    }

    /// Boundaries are fuzzy by the collector's wakeup latency, so a record landing just outside
    /// one must still resolve rather than falling through to passthrough.
    #[test]
    fn the_tolerance_admits_a_record_just_outside_the_window() {
        let table = EpochTable::new(epoch(0, WALL));
        // Stamped 10 ms before the process was recorded as starting.
        let q = Query {
            stamped: WALL + 5 * SEC - 10_000_000,
            sender_started: 5 * SEC,
            received: 11 * SEC,
        };
        assert_eq!(table.resolve(q, 0), Resolution::Passthrough, "no slack, no match");
        assert!(matches!(
            table.resolve(q, DEFAULT_TOLERANCE_NANOS),
            Resolution::Exact { .. }
        ));
    }

    /// Two epochs can both explain one timestamp. The answer is the nearer to receipt, and the
    /// spread is reported rather than hidden.
    ///
    /// Constructing this takes care, which is itself reassuring: a candidate has to fall inside
    /// *its own* epoch's bounds as well as inside the process window, so most pairs of epochs
    /// cannot both explain the same stamp. Here the old offset puts the event at 5.5 s — inside
    /// [0, 6 s) — and the new one at 10 s, inside [6 s, ∞).
    #[test]
    fn two_explanations_are_ambiguous_and_the_spread_is_reported() {
        let half = SEC / 2;
        let table = EpochTable::new(epoch(0, WALL)).with(epoch(6 * SEC, WALL - 4 * SEC - half));

        let q = Query {
            stamped: WALL + 5 * SEC + half,
            sender_started: 5 * SEC,
            received: 13 * SEC,
        };
        assert_eq!(
            table.resolve(q, DEFAULT_TOLERANCE_NANOS),
            Resolution::Ambiguous { boottime: 10 * SEC, spread: 4 * SEC + half }
        );
    }

    /// The other half of the same point: an epoch's own bounds are a real constraint, so a stamp
    /// that would resolve under an earlier offset is rejected once that epoch has ended.
    #[test]
    fn an_ended_epoch_does_not_explain_a_later_event() {
        let table = EpochTable::new(epoch(0, WALL)).with(epoch(6 * SEC, WALL - 4 * SEC));

        // Under the old offset this is boottime 8 s, but that epoch ended at 6 s.
        let q = Query { stamped: WALL + 8 * SEC, sender_started: 5 * SEC, received: 13 * SEC };
        assert_eq!(
            table.resolve(q, DEFAULT_TOLERANCE_NANOS),
            Resolution::Exact { boottime: 12 * SEC }
        );
    }

    /// Duplicate offsets must not manufacture ambiguity: the same boundary seen by both the
    /// journal backfill and the live timerfd is one boundary.
    #[test]
    fn duplicate_boundaries_collapse_rather_than_becoming_ambiguous() {
        let table = EpochTable::from_epochs(vec![
            Epoch { boot_start: 0, offset: WALL, source: Source::Startup },
            Epoch { boot_start: 30 * SEC, offset: WALL + SEC, source: Source::Journal },
            Epoch { boot_start: 30 * SEC, offset: WALL + SEC, source: Source::Step },
        ])
        .unwrap();
        assert_eq!(table.len(), 2, "the same boundary was counted twice: {table:?}");

        let q = Query { stamped: WALL + 10 * SEC, sender_started: 0, received: 40 * SEC };
        assert!(matches!(table.resolve(q, DEFAULT_TOLERANCE_NANOS), Resolution::Exact { .. }));
    }

    /// A boundary that does not change the offset is not a boundary.
    #[test]
    fn a_boundary_with_no_offset_change_is_dropped() {
        let table = EpochTable::new(epoch(0, WALL)).with(epoch(10 * SEC, WALL));
        assert_eq!(table.len(), 1);
    }

    /// History extends forward only. An out-of-order push would corrupt the sort every lookup
    /// depends on, so it is refused rather than silently reordering the table.
    #[test]
    fn a_boundary_in_the_past_is_refused() {
        let table = EpochTable::new(epoch(50 * SEC, WALL)).with(epoch(10 * SEC, WALL + SEC));
        assert_eq!(table.len(), 1);
        assert_eq!(table.current().boot_start, 50 * SEC);
    }

    #[test]
    fn from_epochs_sorts_and_rejects_an_empty_history() {
        assert!(EpochTable::from_epochs(vec![]).is_none());

        let table = EpochTable::from_epochs(vec![
            epoch(30 * SEC, WALL + SEC),
            epoch(0, WALL),
            epoch(60 * SEC, WALL + 2 * SEC),
        ])
        .unwrap();
        assert_eq!(
            table.epochs().iter().map(|e| e.boot_start).collect::<Vec<_>>(),
            vec![0, 30 * SEC, 60 * SEC]
        );
        assert_eq!(table.current().offset, WALL + 2 * SEC);
    }

    /// A wildly out-of-range timestamp must not panic the resolver. `0` is the realistic form:
    /// an SDK that never set the field.
    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let table = EpochTable::new(epoch(0, WALL)).with(epoch(SEC, i64::MIN));
        for stamped in [0, i64::MIN, i64::MAX] {
            let q = Query { stamped, sender_started: 0, received: 10 * SEC };
            let _ = table.resolve(q, DEFAULT_TOLERANCE_NANOS);
        }
    }

    /// The safety net for a boundary the cancel-on-set watch missed. Exclusive at the threshold,
    /// and symmetric: a clock set backwards is as much a discontinuity as one set forwards.
    #[test]
    fn a_moved_offset_is_a_missed_boundary() {
        let table = EpochTable::new(epoch(0, WALL));
        let t = DEFAULT_RESYNC_THRESHOLD_NANOS;

        assert!(!table.disagrees_with(WALL, t), "the same offset is no disagreement");
        assert!(!table.disagrees_with(WALL + t, t), "the threshold is exclusive");
        assert!(!table.disagrees_with(WALL - t, t));
        assert!(table.disagrees_with(WALL + t + 1, t), "forwards");
        assert!(table.disagrees_with(WALL - t - 1, t), "backwards");
    }

    /// The constant's whole justification: slewing cannot move this quantity, so the threshold
    /// only has to clear measurement noise, not accumulated drift. Even a full day of the kernel's
    /// maximum 500 ppm — which would be 43 seconds if it *did* apply — is not what this sees; what
    /// it sees is the interleave between two `clock_gettime` calls, measured at under a microsecond.
    #[test]
    fn read_interleave_is_not_mistaken_for_a_boundary() {
        let table = EpochTable::new(epoch(0, WALL));
        for jitter in [-1_000, -500, 0, 500, 1_000] {
            assert!(
                !table.disagrees_with(WALL + jitter, DEFAULT_RESYNC_THRESHOLD_NANOS),
                "{jitter} ns of sampling noise must not manufacture an epoch"
            );
        }
    }

    /// It compares against the *active* epoch, not the first one — otherwise every reading after
    /// the first genuine step would look like a missed boundary, forever.
    #[test]
    fn the_comparison_is_against_the_current_epoch() {
        let table = EpochTable::new(epoch(0, WALL)).with(epoch(30 * SEC, WALL + 10 * SEC));

        assert!(!table.disagrees_with(WALL + 10 * SEC, DEFAULT_RESYNC_THRESHOLD_NANOS));
        assert!(
            table.disagrees_with(WALL, DEFAULT_RESYNC_THRESHOLD_NANOS),
            "the superseded offset must now read as a disagreement"
        );
    }

    #[test]
    fn resolution_exposes_its_boottime_and_label() {
        assert_eq!(Resolution::Exact { boottime: 7 }.boottime(), Some(7));
        assert_eq!(Resolution::Ambiguous { boottime: 7, spread: 1 }.boottime(), Some(7));
        assert_eq!(Resolution::Passthrough.boottime(), None);
        assert_eq!(Resolution::Exact { boottime: 7 }.label(), "exact");
        assert_eq!(Resolution::Ambiguous { boottime: 7, spread: 1 }.label(), "ambiguous");
        assert_eq!(Resolution::Passthrough.label(), "passthrough");
    }
}
