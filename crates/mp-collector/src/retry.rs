//! When to attempt delivery again after it failed. Pure: the caller keeps the failure count and
//! reads the clock.
//!
//! This exists because a bounded send timeout is not on its own enough to keep an unreachable
//! receiver from stalling the collector. `FlushTask::cycle` runs once per *received* batch, so
//! without a backoff every arrival would pay the whole timeout, the inbox would fill, and the HTTP
//! layer would start answering 503 — an application blocked on its own telemetry, which is the one
//! outcome the buffer exists to prevent.

use std::time::Duration;

/// `base`, doubled once per consecutive failure, capped at `cap`.
///
/// `failures` counts what has already gone wrong, so `backoff(0, ..)` is zero — there is nothing to
/// wait out before the first failure — and `backoff(1, ..)` is `base`.
///
/// The cap is the load-bearing parameter, not the growth rate. It is the longest a delivery can be
/// delayed *after* the receiver comes back, so it bounds the cost of an ordinary `systemctl restart`
/// of the receiver. Uncapped doubling would make a device that was unreachable for an hour wait out
/// a delay computed from the outage rather than from the recovery.
pub fn backoff(failures: u32, base: Duration, cap: Duration) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    // Clamped before the shift, and saturating through it: a receiver down for a day at half a
    // second a try reaches a failure count that overflows the multiplier long before it overflows
    // the cap, and an unchecked `1 << n` is a panic in debug and nonsense in release.
    let doublings = failures.min(31) - 1;
    base.saturating_mul(2u32.saturating_pow(doublings)).min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Duration = Duration::from_millis(500);
    const CAP: Duration = Duration::from_secs(10);

    /// Nothing has failed, so there is nothing to wait for. Delivery on the first cycle after a
    /// batch arrives is the whole point of the grace period being short.
    #[test]
    fn no_failures_means_no_wait() {
        assert_eq!(backoff(0, BASE, CAP), Duration::ZERO);
    }

    #[test]
    fn the_first_retry_waits_one_base_interval() {
        assert_eq!(backoff(1, BASE, CAP), BASE);
    }

    #[test]
    fn it_doubles_per_consecutive_failure() {
        assert_eq!(backoff(2, BASE, CAP), Duration::from_secs(1));
        assert_eq!(backoff(3, BASE, CAP), Duration::from_secs(2));
        assert_eq!(backoff(4, BASE, CAP), Duration::from_secs(4));
        assert_eq!(backoff(5, BASE, CAP), Duration::from_secs(8));
    }

    /// The ceiling, and the reason it exists: a receiver that returns after a long outage must be
    /// noticed within the cap, not within a delay derived from how long it was gone.
    #[test]
    fn it_stops_doubling_at_the_cap() {
        assert_eq!(backoff(6, BASE, CAP), CAP);
        assert_eq!(backoff(7, BASE, CAP), CAP);
        assert_eq!(backoff(1_000, BASE, CAP), CAP);
    }

    /// A day-long outage at half a second a try is ~170 000 failures. The multiplier overflows;
    /// the answer must still be the cap.
    #[test]
    fn an_absurd_failure_count_neither_panics_nor_wraps() {
        assert_eq!(backoff(u32::MAX, BASE, CAP), CAP);
        assert_eq!(backoff(u32::MAX, Duration::MAX, CAP), CAP);
    }

    /// A zero cap is the documented way to opt out of backing off entirely, and it must mean
    /// "retry on the next cycle" rather than "wait one base interval".
    #[test]
    fn a_zero_cap_disables_the_backoff() {
        assert_eq!(backoff(9, BASE, Duration::ZERO), Duration::ZERO);
    }
}
