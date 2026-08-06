//! Deciding whether the clock is trustworthy yet (design §4.4). The decision is pure; the
//! syscall behind it is `mp_host::clock::read_timex`.
//!
//! This is the least clean part of the design, and the reason is worth stating: the three time
//! daemons write three *different quantities* into the same kernel field.
//!
//! | Daemon | Writes to `maxerror` |
//! |---|---|
//! | chrony | `root_delay/2 + root_dispersion` — the true root distance; pinned to 16 s unsynchronized |
//! | systemd-timesyncd | **zero** — `ADJ_MAXERROR` is set in `modes` but the field is never assigned |
//! | ntpd-rs | `root_delay`, from its Kalman filter |
//!
//! So the magnitude is not comparable across daemons. What the test reliably distinguishes is
//! *disciplined* from *never touched*, which is the question that actually matters here.

use mp_host::clock::{self, Timex};

/// Which condition said the clock was good. Recorded on every flushed record, because a bad
/// correction has to be debuggable after the fact rather than invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncSource {
    /// `maxerror` fell below the threshold. The primary signal.
    MaxError,
    /// The kernel cleared `STA_UNSYNC`. Secondary; see [`decide`].
    StatusFlag,
}

impl SyncSource {
    pub fn label(self) -> &'static str {
        match self {
            SyncSource::MaxError => "maxerror",
            SyncSource::StatusFlag => "sta_unsync_cleared",
        }
    }
}

/// Everything the decision looks at, gathered into plain data so the rule is testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reading {
    pub max_error_micros: i64,
    pub status: i32,
}

/// The threshold, in microseconds. **5 s, matching the receiver's boot gate.**
///
/// The design doc proposed 1–2 s. That is too tight for the same reason
/// `monitoring_platform::clock::DEFAULT_THRESHOLD_MICROS` documents: `maxerror` grows continuously
/// between successful updates at the kernel's 500 ppm tolerance — 500 µs per second of wall time —
/// so with chrony's default `maxpoll 10` (~1024 s between updates) it routinely reaches ~0.5 s in
/// entirely healthy operation. A 1 s threshold flaps against that sawtooth rather than detecting
/// anything, and here flapping would mean releasing the buffer and re-arming it repeatedly.
pub const DEFAULT_THRESHOLD_MICROS: i64 = 5_000_000;

/// Consecutive good readings required, as hysteresis against the same sawtooth. Mirrors
/// `monitoring_platform::clock::DEFAULT_CONSECUTIVE`.
pub const DEFAULT_CONSECUTIVE: u32 = 3;

/// The §4.4 disjunction: synchronized if *either* condition says so, in preference order.
///
/// A disjunction rather than a conjunction because both signals have a documented false-*negative*
/// mode and neither has a plausible false-positive one before a daemon has run: the kernel starts
/// at the 16 s ceiling with `STA_UNSYNC` set.
///
/// **Two conditions, not the three §4.4 originally listed.** The third was a direct daemon query
/// (`chronyc tracking`), and it is gone rather than unimplemented: `maxerror` already catches
/// chrony and ntpd-rs, the status flag catches systemd-timesyncd, and there is no daemon the pair
/// misses. Keeping it would have meant a chrony-specific socket protocol — with its own binary
/// dependency, timeout and failure handling — for a case that cannot arise.
///
/// Note this consults `STA_UNSYNC`, which the receiver's boot gate deliberately ignores
/// (`monitoring_platform::clock::clock_error_micros`). The reversal is intentional and the
/// asymmetry is in the cost of being wrong: the gate refuses to start a service, so a false
/// "synchronized" there admits silently bad rows forever, whereas here the worst case is flushing
/// a few seconds early with `mp.clock.sync_source` recording exactly which condition fired.
pub fn decide(reading: Reading, threshold_micros: i64) -> Option<SyncSource> {
    if reading.max_error_micros < threshold_micros {
        return Some(SyncSource::MaxError);
    }
    if !clock::is_unsynchronized(reading.status) {
        return Some(SyncSource::StatusFlag);
    }
    None
}

/// The kernel parks `maxerror` here when nothing has ever disciplined the clock, growing it from
/// the 16 s phase limit at 500 ppm. Only `ntp_adjtime(ADJ_MAXERROR)` brings it back down.
pub const KERNEL_UNSYNCHRONIZED_CEILING_MICROS: i64 = 16_000_000;

/// Whether *anything* is disciplining the clock, however badly.
///
/// Weaker than [`decide`] on purpose, and reported separately (§9): a device sitting at the
/// kernel ceiling an hour after boot has no time daemon running, which is a configuration problem
/// an operator can fix. A device with a large but moving `maxerror` has a network problem, which
/// is a different conversation.
pub fn is_disciplined(reading: Reading) -> bool {
    reading.max_error_micros < KERNEL_UNSYNCHRONIZED_CEILING_MICROS
        || !clock::is_unsynchronized(reading.status)
}

/// A single bad reading resets the run: the required good readings must be contiguous. Same rule
/// as the receiver's gate, for the same reason.
pub fn next_streak(streak: u32, good: bool) -> u32 {
    if good { streak.saturating_add(1) } else { 0 }
}

/// What one poll of the clock concludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poll {
    /// Consecutive good readings including this one; feed back into the next call.
    pub streak: u32,
    /// Which condition fired, if the streak is long enough to act on. `None` both when the clock
    /// is bad and when it is good but the hysteresis is not yet satisfied — the distinction is in
    /// `streak`, and callers only ever need "may I release the buffer".
    pub source: Option<SyncSource>,
    /// Whether the buffer may be released.
    pub released: bool,
}

/// The whole per-poll rule, pure, so the hysteresis is testable without a clock.
///
/// Extracted from the polling task rather than left inline because the interesting behaviour is
/// entirely in the sequence — a good reading part-way through a run, a bad one resetting it — and
/// none of it is reachable by waiting for a real clock to misbehave in the right order.
pub fn evaluate(reading: Reading, threshold_micros: i64, consecutive: u32, streak: u32) -> Poll {
    let good = decide(reading, threshold_micros);
    let streak = next_streak(streak, good.is_some());
    let released = streak >= consecutive;
    Poll { streak, source: released.then_some(good).flatten(), released }
}

/// One `adjtimex(2)` read, shaped for [`decide`].
pub fn read() -> std::io::Result<Reading> {
    let Timex { max_error_micros, status } = clock::read_timex()?;
    Ok(Reading { max_error_micros, status })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reading with `STA_UNSYNC` set — the kernel's own starting state.
    fn unsynced(max_error_micros: i64) -> Reading {
        Reading { max_error_micros, status: libc::STA_UNSYNC }
    }

    /// The kernel's cold-boot state: `maxerror` parked at the 16 s phase limit and `STA_UNSYNC`
    /// set. Nothing may call this synchronized — it is the exact state a Raspberry Pi is in when
    /// the whole design's problem occurs.
    #[test]
    fn a_cold_boot_is_not_synchronized() {
        assert_eq!(decide(unsynced(KERNEL_UNSYNCHRONIZED_CEILING_MICROS), DEFAULT_THRESHOLD_MICROS), None);
    }

    #[test]
    fn a_small_maxerror_is_the_primary_signal() {
        assert_eq!(decide(unsynced(2_000), DEFAULT_THRESHOLD_MICROS), Some(SyncSource::MaxError));
    }

    /// The disjunct that exists for systemd-timesyncd, which writes zero into `maxerror` and so
    /// carries recency but not accuracy — and for any daemon that clears the flag first.
    #[test]
    fn a_cleared_status_flag_suffices_when_maxerror_is_still_large() {
        let r = Reading { max_error_micros: KERNEL_UNSYNCHRONIZED_CEILING_MICROS, status: 0 };
        assert_eq!(decide(r, DEFAULT_THRESHOLD_MICROS), Some(SyncSource::StatusFlag));
    }

    /// The case that makes the flag unusable *alone*: chrony with `rtcfile` rather than `rtcsync`
    /// is fully synchronized and never clears `STA_UNSYNC`. Here `maxerror` carries the answer,
    /// which is why it is checked first.
    #[test]
    fn chrony_with_rtcfile_still_resolves_through_maxerror() {
        assert_eq!(decide(unsynced(300_000), DEFAULT_THRESHOLD_MICROS), Some(SyncSource::MaxError));
    }

    /// The threshold is exclusive, matching the receiver's gate and systemd's own `< 16 s` test.
    #[test]
    fn the_threshold_is_exclusive() {
        assert_eq!(decide(unsynced(DEFAULT_THRESHOLD_MICROS), DEFAULT_THRESHOLD_MICROS), None);
        assert_eq!(
            decide(unsynced(DEFAULT_THRESHOLD_MICROS - 1), DEFAULT_THRESHOLD_MICROS),
            Some(SyncSource::MaxError)
        );
    }

    /// `is_disciplined` is a *weaker* question than `decide`, and the gap between them is the
    /// point: a device can be disciplined and still not good enough to release the buffer.
    #[test]
    fn discipline_is_a_weaker_test_than_synchronization() {
        // Two seconds of error: disciplined by something, but over a one-second threshold.
        let sloppy = unsynced(2_000_000);
        assert!(is_disciplined(sloppy));
        assert_eq!(decide(sloppy, 1_000_000), None, "the two questions must be able to disagree");
    }

    /// The operationally important case, and the one the §9 metric exists to surface: nothing has
    /// ever touched this clock. Distinguishing it from "the network is down" is the difference
    /// between a configuration problem and an outage.
    #[test]
    fn nothing_disciplining_the_clock_is_visible() {
        assert!(!is_disciplined(unsynced(KERNEL_UNSYNCHRONIZED_CEILING_MICROS)));
        assert!(
            !is_disciplined(unsynced(KERNEL_UNSYNCHRONIZED_CEILING_MICROS + 1_000_000)),
            "the kernel grows maxerror past the ceiling at 500 ppm; still nothing disciplining it"
        );

        // Either signal moving is enough to say something is running.
        assert!(is_disciplined(unsynced(KERNEL_UNSYNCHRONIZED_CEILING_MICROS - 1)));
        assert!(is_disciplined(Reading {
            max_error_micros: KERNEL_UNSYNCHRONIZED_CEILING_MICROS,
            status: 0,
        }));
    }

    /// The sawtooth this guards against is real: at 500 ppm, `maxerror` crosses a 1 s threshold
    /// 2000 s after an update and a 5 s one only after 10000 s, which chrony's `maxpoll 10` never
    /// allows. Hysteresis covers the remainder.
    #[test]
    fn one_bad_reading_resets_the_streak() {
        let streak = [true, true, false].iter().fold(0, |s, &g| next_streak(s, g));
        assert_eq!(streak, 0, "a bad reading must not leave partial credit behind");
        assert_eq!(next_streak(streak, true), 1);
    }

    /// The buffer is released on the Nth consecutive good reading and not before. Driving the
    /// whole sequence rather than the rule in isolation, because the interesting part is the
    /// carry: `streak` has to survive from one call to the next.
    #[test]
    fn the_buffer_is_released_only_on_the_third_consecutive_good_reading() {
        let good = unsynced(2_000);
        let mut streak = 0;
        let mut released_at = None;

        for poll in 1..=4 {
            let outcome = evaluate(good, DEFAULT_THRESHOLD_MICROS, DEFAULT_CONSECUTIVE, streak);
            streak = outcome.streak;
            if outcome.released && released_at.is_none() {
                released_at = Some(poll);
                assert_eq!(outcome.source, Some(SyncSource::MaxError), "which condition fired must survive");
            }
        }
        assert_eq!(released_at, Some(3), "DEFAULT_CONSECUTIVE is 3, so the third poll releases");
    }

    /// A bad reading part-way through a run sends it back to zero, so three *more* good ones are
    /// needed. This is the whole reason the hysteresis exists, and it is not reachable by testing
    /// `decide` alone.
    #[test]
    fn a_bad_reading_part_way_through_costs_the_whole_run() {
        let good = unsynced(2_000);
        let bad = unsynced(KERNEL_UNSYNCHRONIZED_CEILING_MICROS);

        let mut streak = 0;
        let mut released = Vec::new();
        for reading in [good, good, bad, good, good, good] {
            let outcome = evaluate(reading, DEFAULT_THRESHOLD_MICROS, DEFAULT_CONSECUTIVE, streak);
            streak = outcome.streak;
            released.push(outcome.released);
        }
        assert_eq!(
            released,
            vec![false, false, false, false, false, true],
            "the run should restart after the bad reading, not resume from two"
        );
    }

    /// A good reading before the hysteresis is satisfied reports no source, because reporting one
    /// would put a `sync_source` on records the collector is not yet willing to release.
    #[test]
    fn a_good_reading_below_the_threshold_streak_names_no_source() {
        let outcome = evaluate(unsynced(2_000), DEFAULT_THRESHOLD_MICROS, DEFAULT_CONSECUTIVE, 0);
        assert_eq!(outcome.streak, 1);
        assert!(!outcome.released);
        assert_eq!(outcome.source, None);
    }

    #[test]
    fn sources_are_labelled_for_the_emitted_attribute() {
        assert_eq!(SyncSource::MaxError.label(), "maxerror");
        assert_eq!(SyncSource::StatusFlag.label(), "sta_unsync_cleared");
    }

    /// The same syscall the receiver's gate makes, through this crate's shape.
    #[test]
    fn reads_the_kernel_state() {
        let r = read().expect("adjtimex(2) should be readable");
        assert!(r.max_error_micros >= 0, "maxerror should not be negative: {r:?}");
    }
}
