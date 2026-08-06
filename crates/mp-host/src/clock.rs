//! Reading the kernel's clocks and its own opinion of them.
//!
//! Two distinct jobs live here, and the distinction is the whole design of the collector:
//!
//! - **Quality** — `read_timex`, the kernel's error estimate and status bits. Used by the
//!   receiver's boot gate (SPEC.md §9.4) and the collector's sync detection.
//! - **Correspondence** — `sample`, a paired reading of `CLOCK_REALTIME` and `CLOCK_BOOTTIME`.
//!   Their difference is the offset that makes a wall-clock timestamp convertible into a
//!   frame-invariant one and back again.
//!
//! Nanoseconds and `i64` throughout, matching `measurements.event_time`. i64 nanoseconds since
//! the epoch runs out in 2262; boottime values are a few years at most.

use std::fs;
use std::io;

/// The fields of `struct timex` this codebase reads, taken in **one** `adjtimex(2)` call so the
/// error estimate and the status bits describe the same instant. Reading them separately lets a
/// sync land in between and produce a combination the kernel was never in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timex {
    /// The kernel's own bound on how wrong the clock may be, in microseconds. It grows at the
    /// 500 ppm frequency tolerance every second and is only ever reset by a daemon calling
    /// `ntp_adjtime()` with `ADJ_MAXERROR`.
    pub max_error_micros: i64,
    /// The `STA_*` bit field. Interpret with [`is_unsynchronized`] rather than by hand.
    pub status: i32,
}

/// One `adjtimex(2)` read.
///
/// `modes = 0` is a read. Deliberately daemon-agnostic: it reflects kernel state whichever NTP
/// implementation set it, so callers work identically under chrony, systemd-timesyncd, ntpd-rs
/// or NTPsec, and depend on none of them.
pub fn read_timex() -> io::Result<Timex> {
    // SAFETY: `timex` is a plain C struct of integers with no padding invariants, so an all-zero
    // value is valid and means "read only, change nothing". `adjtimex` writes through the pointer
    // and reads `modes`; the reference is valid and exclusive for the whole call.
    let (rc, tx) = unsafe {
        let mut tx: libc::timex = std::mem::zeroed();
        (libc::adjtimex(&mut tx), tx)
    };
    // Only a negative return is a failure. A *positive* one is the clock state — `TIME_ERROR` (5)
    // is what an unsynchronized clock reports, which is a state to observe, not an error.
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Timex {
        // `maxerror` is `__syscall_slong_t`: already i64 on the 64-bit targets this ships to, but
        // i32 on a 32-bit one, where the widening is real. Keep the conversion so both compile.
        #[allow(clippy::useless_conversion)]
        max_error_micros: i64::from(tx.maxerror),
        #[allow(clippy::useless_conversion)]
        status: i32::from(tx.status),
    })
}

/// Whether the kernel considers itself unsynchronized.
///
/// Pure, and separated from the read because the bit is *not* a straightforward quality signal:
/// chrony clears it only when `rtcsync` is enabled, since clearing it is what activates the
/// kernel's 11-minute RTC-write mode. A perfectly synchronized chrony host configured with
/// `rtcfile` instead reports unsynchronized indefinitely — the documented cause of `timedatectl`
/// saying "System clock synchronized: no" on healthy hosts. Never use this as the sole test.
pub fn is_unsynchronized(status: i32) -> bool {
    status & libc::STA_UNSYNC != 0
}

/// A paired reading of the two clocks that matter.
///
/// `CLOCK_BOOTTIME`, not `CLOCK_MONOTONIC`: monotonic stops during suspend and boottime does not,
/// so only boottime is a stable frame across a suspend/resume cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Nanoseconds since the Unix epoch, as the system clock currently believes.
    pub realtime: i64,
    /// Nanoseconds since boot, including time spent suspended.
    pub boottime: i64,
}

impl Sample {
    /// `realtime − boottime`: the quantity that converts between the two frames.
    ///
    /// Piecewise constant. It changes only when something steps the realtime clock, and drifts
    /// slowly under NTP slewing (bounded at the kernel's 500 ppm frequency tolerance).
    pub fn offset(self) -> i64 {
        self.realtime - self.boottime
    }
}

/// Reads both clocks back to back.
///
/// The two reads are not atomic, so the offset carries the interleave — tens of nanoseconds from
/// a vDSO `clock_gettime`. Irrelevant at this design's target accuracy, which is bounded by the
/// application-to-collector delay, several orders of magnitude larger.
pub fn sample() -> io::Result<Sample> {
    Ok(Sample { realtime: now(libc::CLOCK_REALTIME)?, boottime: now(libc::CLOCK_BOOTTIME)? })
}

/// Nanoseconds since boot, suspend included.
pub fn now_boottime() -> io::Result<i64> {
    now(libc::CLOCK_BOOTTIME)
}

/// `boottime − monotonic`: total time this host has spent suspended.
///
/// Needed to import journald's `__MONOTONIC_TIMESTAMP`, which is `CLOCK_MONOTONIC` and therefore
/// in a different frame from everything else here. On a host that never suspends this is zero and
/// the normalization is a no-op; on one that does, skipping it silently skews imported history.
///
/// **Monotonic is read first on purpose.** The two reads are not atomic, and the microsecond
/// between them advances both clocks. Reading monotonic first puts that interval on the boottime
/// side, so the result is `suspend + ε` and cannot come out negative — which it otherwise does on
/// a host that has never suspended, where the true answer is exactly zero. Clamping the wrong
/// order at zero would hide the same error rather than bound its sign.
pub fn suspended_nanos() -> io::Result<i64> {
    let monotonic = now(libc::CLOCK_MONOTONIC)?;
    Ok(now(libc::CLOCK_BOOTTIME)? - monotonic)
}

fn now(clock: libc::clockid_t) -> io::Result<i64> {
    // SAFETY: `timespec` is two integers; an all-zero value is valid. `clock_gettime` writes
    // through the pointer, which is valid and exclusive for the call.
    let (rc, ts) = unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        (libc::clock_gettime(clock, &mut ts), ts)
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(nanos(ts))
}

/// `timespec` → nanoseconds. Pure, and split out so the arithmetic is testable.
///
/// `tv_sec` is `time_t` and `tv_nsec` is `c_long`: both i64 on the 64-bit targets this ships to,
/// i32 on a 32-bit one. `i64::from` covers both, so the conversion is not useless everywhere.
#[allow(clippy::useless_conversion)]
fn nanos(ts: libc::timespec) -> i64 {
    i64::from(ts.tv_sec) * 1_000_000_000 + i64::from(ts.tv_nsec)
}

/// The kernel's identifier for this boot.
///
/// Boottime values are meaningless across a reboot, so anything persisted in that frame — the
/// offset epoch table, spooled records — is keyed by this and discarded when it changes.
pub fn boot_id() -> io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same syscall the boot gate makes, in a plain test process. The *value* is whatever the
    /// build machine's clock is doing, so only its sign is asserted.
    #[test]
    fn reads_the_kernel_estimate() {
        let tx = read_timex().expect("adjtimex(2) should be readable");
        assert!(tx.max_error_micros >= 0, "maxerror should not be negative, got {tx:?}");
    }

    #[test]
    fn decodes_the_unsync_bit() {
        assert!(is_unsynchronized(libc::STA_UNSYNC));
        assert!(is_unsynchronized(libc::STA_UNSYNC | libc::STA_PLL));
        assert!(!is_unsynchronized(0));
        assert!(!is_unsynchronized(libc::STA_PLL));
    }

    /// Both clocks must read plausibly and in the right relation: realtime is decades past the
    /// epoch on any machine that can build this, and boottime is small and positive.
    #[test]
    fn samples_both_clocks() {
        let s = sample().expect("clock_gettime should work");
        assert!(s.realtime > 1_600_000_000_000_000_000, "realtime looks wrong: {s:?}");
        assert!(s.boottime > 0, "boottime should be positive: {s:?}");
        assert!(s.boottime < s.realtime, "boottime should be far smaller than realtime: {s:?}");
        assert_eq!(s.offset(), s.realtime - s.boottime);
    }

    /// The read order is load-bearing, and this is what caught it: with boottime read first, a
    /// build machine that has never suspended returns the interleave as a *negative* suspend
    /// time. A negative value is not a small error, it is a sign error in a correction that gets
    /// added to every imported journal timestamp.
    #[test]
    fn suspend_time_is_never_negative() {
        for _ in 0..1000 {
            let d = suspended_nanos().expect("clock_gettime should work");
            assert!(d >= 0, "boottime is behind monotonic, which cannot happen: {d}");
        }
    }

    #[test]
    fn converts_a_timespec_to_nanoseconds() {
        assert_eq!(nanos(libc::timespec { tv_sec: 0, tv_nsec: 0 }), 0);
        assert_eq!(nanos(libc::timespec { tv_sec: 1, tv_nsec: 0 }), 1_000_000_000);
        assert_eq!(nanos(libc::timespec { tv_sec: 2, tv_nsec: 500_000_000 }), 2_500_000_000);
    }

    /// A UUID with dashes, and stable within one boot — the two properties anything keyed by it
    /// depends on.
    #[test]
    fn reads_a_stable_boot_id() {
        let id = boot_id().expect("/proc/sys/kernel/random/boot_id should be readable");
        assert_eq!(id.len(), 36, "not a dashed UUID: {id:?}");
        assert_eq!(id, boot_id().unwrap(), "boot_id changed within one boot");
    }
}
