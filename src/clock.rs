//! The clock-synchronization boot gate (SPEC §9.4).
//!
//! The service must not store records stamped with a `processed_time` it cannot stand behind, so
//! it does not start until the system clock is verifiably synchronized. This module is the check
//! and the wait; `nix/module.nix` wires it in as `ExecStartPre`, whose failure fails the unit.
//!
//! The decision logic is pure and the effects (the syscall, the sleeping, the logging) are a thin
//! shell around it, so the hysteresis and give-up rules are testable without a clock.

use anyhow::{Context, Result, bail};
use std::io;
use std::time::Duration;

/// 5 s. Deliberately generous: `maxerror` grows continuously between successful NTP updates at
/// the kernel's 500 ppm tolerance — 500 µs per second of wall time — so with chrony's default
/// `maxpoll 10` (~1024 s between updates) it routinely reaches ~0.5 s in entirely healthy
/// operation. Tightening this to 1 s without also setting `maxpoll 9` on the host would make the
/// gate flap against that sawtooth rather than detect anything.
pub const DEFAULT_THRESHOLD_MICROS: i64 = 5_000_000;
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
/// 60 polls × 5 s ≈ 5 min.
pub const DEFAULT_MAX_POLLS: u32 = 60;
/// Hysteresis against the sawtooth described on `DEFAULT_THRESHOLD_MICROS`.
pub const DEFAULT_CONSECUTIVE: u32 = 3;

/// Resolved gate parameters. Plain data, no clap: `config::WaitForClockArgs` builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateSettings {
    pub threshold_micros: i64,
    pub poll_interval: Duration,
    pub max_polls: u32,
    pub consecutive: u32,
}

/// What to do after a poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ready,
    KeepWaiting,
    GiveUp,
}

/// The kernel's own estimate of how wrong the clock may be, in microseconds.
///
/// `adjtimex(2)` with `modes = 0` is a read. This is deliberately daemon-agnostic: it reflects
/// kernel state whichever NTP implementation set it, so the gate works identically under chrony,
/// systemd-timesyncd, ntpd-rs or NTPsec, and depends on none of them (SPEC §9.4).
///
/// `STA_UNSYNC` is deliberately not consulted. That bit gets set for reasons unrelated to clock
/// quality — notably to stop the kernel writing back to the RTC — so `maxerror` alone is the
/// test, which is also what systemd itself uses.
pub fn clock_error_micros() -> io::Result<i64> {
    // SAFETY: `timex` is a plain C struct of integers with no padding invariants, so an all-zero
    // value is valid and means "read only, change nothing". `adjtimex` writes through the pointer
    // and reads `modes`; the reference is valid and exclusive for the whole call.
    let (rc, tx) = unsafe {
        let mut tx: libc::timex = std::mem::zeroed();
        (libc::adjtimex(&mut tx), tx)
    };
    // Only a negative return is a failure. A *positive* one is the clock state — `TIME_ERROR` (5)
    // is what an unsynchronized clock reports, and that is the case this gate exists to wait out,
    // not an error to abort on.
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // `maxerror` is `__syscall_slong_t`: already i64 on the 64-bit targets this ships to, but
    // i32 on a 32-bit one, where the widening is real. Keep the conversion so both compile.
    #[allow(clippy::useless_conversion)]
    Ok(i64::from(tx.maxerror))
}

pub fn is_good(error_micros: i64, threshold_micros: i64) -> bool {
    error_micros < threshold_micros
}

/// A single bad poll resets the run: `consecutive` good readings must be contiguous.
pub fn next_streak(streak: u32, good: bool) -> u32 {
    if good { streak.saturating_add(1) } else { 0 }
}

/// `poll` is zero-based, so `poll + 1` is how many have been taken.
pub fn outcome(streak: u32, consecutive: u32, poll: u32, max_polls: u32) -> Outcome {
    if streak >= consecutive {
        Outcome::Ready
    } else if poll + 1 >= max_polls {
        Outcome::GiveUp
    } else {
        Outcome::KeepWaiting
    }
}

/// Blocks until the clock is good, or fails once the poll budget is spent (fail-closed).
///
/// The budget is **counted in iterations, never measured against the wall clock**. `SystemTime`,
/// `date` and the shell's `$SECONDS` all derive from the very clock being waited on: the first
/// successful sync steps it, and a deadline computed from it jumps unpredictably at exactly the
/// wrong moment. An iteration counter plus `thread::sleep` (which is `CLOCK_MONOTONIC`) cannot be
/// moved by a clock step.
pub fn wait_until_synchronized(settings: &GateSettings) -> Result<()> {
    let mut streak = 0;
    let mut last_error = None;
    for poll in 0..settings.max_polls {
        let error = clock_error_micros()
            .context("reading the kernel clock estimate with adjtimex(2)")
            // A seccomp denial arrives as SIGSYS rather than an error, so this is mostly about
            // non-Linux-ish kernels — but it must fail the gate either way, never pass it.
            .context("cannot determine clock quality; refusing to start")?;

        last_error = Some(error);
        streak = next_streak(streak, is_good(error, settings.threshold_micros));

        match outcome(streak, settings.consecutive, poll, settings.max_polls) {
            Outcome::Ready => {
                tracing::info!(clock_error_us = error, polls = poll + 1, "clock synchronized");
                return Ok(());
            }
            // Nothing to wait for on the last poll.
            Outcome::GiveUp => break,
            Outcome::KeepWaiting => {
                // Logged every poll on purpose: this is what an operator sees when a device that
                // booted without a network refuses to start monitoring.
                tracing::info!(
                    clock_error_us = error,
                    threshold_us = settings.threshold_micros,
                    poll = poll + 1,
                    of = settings.max_polls,
                    good_streak = streak,
                    "waiting for the clock to synchronize"
                );
                std::thread::sleep(settings.poll_interval);
            }
        }
    }

    // The measured value goes in the failure too, not just in the per-poll waiting lines: with
    // a small max_polls there may be no waiting line at all, and it is what distinguishes "no
    // NTP yet" (the kernel's 16 s ceiling) from "the threshold is set too tight".
    bail!(
        "clock not synchronized after {} polls ({}s): clock_error_us={} exceeds threshold_us={}; \
         refusing to start",
        settings.max_polls,
        u64::from(settings.max_polls) * settings.poll_interval.as_secs(),
        last_error.map_or_else(|| "unknown".to_owned(), |e: i64| e.to_string()),
        settings.threshold_micros
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The threshold is exclusive, matching systemd's own `maxerror < 16s` test.
    #[test]
    fn the_threshold_is_exclusive() {
        assert!(is_good(4_999_999, 5_000_000));
        assert!(!is_good(5_000_000, 5_000_000));
        assert!(!is_good(5_000_001, 5_000_000));
    }

    /// The kernel parks an unsynchronized clock at 16 s, which must not pass the default gate.
    #[test]
    fn the_kernels_unsynchronized_ceiling_is_not_good_enough() {
        assert!(!is_good(16_000_000, DEFAULT_THRESHOLD_MICROS));
    }

    #[test]
    fn one_bad_poll_resets_the_streak() {
        let streak = [true, true, false].iter().fold(0, |s, &g| next_streak(s, g));
        assert_eq!(streak, 0, "a bad reading must not leave partial credit behind");
        assert_eq!(next_streak(streak, true), 1);
    }

    #[test]
    fn ready_only_once_the_streak_is_long_enough() {
        assert_eq!(outcome(2, 3, 0, 60), Outcome::KeepWaiting);
        assert_eq!(outcome(3, 3, 0, 60), Outcome::Ready);
        // Overshooting still counts; the loop returns on the first Ready anyway.
        assert_eq!(outcome(4, 3, 0, 60), Outcome::Ready);
    }

    #[test]
    fn gives_up_on_the_last_poll_rather_than_after_it() {
        // poll is zero-based, so poll 2 of max_polls 3 is the final one.
        assert_eq!(outcome(0, 3, 1, 3), Outcome::KeepWaiting);
        assert_eq!(outcome(0, 3, 2, 3), Outcome::GiveUp);
    }

    /// The final poll can still succeed — giving up must not pre-empt a good reading.
    #[test]
    fn a_good_last_poll_wins_over_giving_up() {
        assert_eq!(outcome(1, 1, 2, 3), Outcome::Ready);
    }

    /// Reading the estimate must work in a plain test process, which is the same syscall the gate
    /// makes. The *value* is whatever the build machine's clock is doing, so it is not asserted.
    #[test]
    fn reads_the_kernel_estimate() {
        let error = clock_error_micros().expect("adjtimex(2) should be readable");
        assert!(error >= 0, "maxerror should not be negative, got {error}");
    }
}
