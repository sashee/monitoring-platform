//! Who sent this, and when did they start (design §5.1).
//!
//! The sending process's start time is the lower bound in `[sender_started, received]`, the window
//! that makes frame resolution work with no application cooperation and no configured constant. It
//! comes from `SO_PEERCRED` → `/proc/PID/stat`, so the collector derives it rather than trusting
//! anything the application says.
//!
//! The parsing is pure and tested against real `/proc` layouts; only [`started_at`] touches the
//! filesystem.

use anyhow::{Context, Result, anyhow};
use std::fs;

/// Field 22 of `/proc/PID/stat`, in clock ticks since boot.
///
/// Field 2 is `comm`, which is parenthesised and may itself contain spaces *and* parentheses —
/// `(my (weird) proc)` is a legal process name — so the only safe split is at the **last** `)`.
/// Everything after it is field 3 onward, which puts field 22 at index 19.
///
/// Returns `None` on anything that does not look like a `stat` line, rather than guessing.
pub fn starttime_ticks(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Clock ticks to nanoseconds.
///
/// `u128` intermediate on purpose: at the usual 100 Hz, `ticks * 1_000_000_000` overflows `u64`
/// after about five and a half years of uptime, and a Raspberry Pi left running is exactly the
/// host this code exists for.
pub fn ticks_to_nanos(ticks: u64, ticks_per_second: i64) -> Option<i64> {
    let per_second = u128::try_from(ticks_per_second).ok().filter(|n| *n > 0)?;
    i64::try_from(u128::from(ticks) * 1_000_000_000 / per_second).ok()
}

/// `sysconf(_SC_CLK_TCK)`: the unit `/proc/PID/stat` counts in. Practically always 100.
pub fn ticks_per_second() -> Result<i64> {
    // SAFETY: `sysconf` reads a compile-time constant out of the C library and touches no memory
    // this side owns.
    let n = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if n <= 0 {
        return Err(anyhow!("sysconf(_SC_CLK_TCK) returned {n}; cannot convert process start times"));
    }
    Ok(n)
}

/// `CLOCK_BOOTTIME` at which `pid` started, nanoseconds.
///
/// Boottime, not monotonic: since Linux 5.5 the kernel derives this field from `start_boottime`,
/// which is the same frame the epoch table works in. On older kernels it is monotonic, and the two
/// differ by total suspend time — irrelevant on a host that has not suspended, and this design
/// targets kernels that have the boottime version.
///
/// **PID reuse is not guarded against, deliberately.** Between `SO_PEERCRED` and this read the
/// sender could in principle exit and its PID be recycled. The replacement necessarily started
/// *later*, so the bound comes out too tight and the record resolves to `Passthrough` — untouched
/// and counted. The failure mode is already fail-safe, so a `uid` cross-check would buy nothing
/// but a second syscall.
pub fn started_at(pid: u32, ticks_per_second: i64) -> Result<i64> {
    let path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let ticks = starttime_ticks(&stat)
        .ok_or_else(|| anyhow!("{path} has no parsable starttime field"))?;
    ticks_to_nanos(ticks, ticks_per_second)
        .ok_or_else(|| anyhow!("starttime {ticks} ticks does not fit in nanoseconds"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real line, trimmed to the fields that matter. starttime is field 22 = 4242.
    const STAT: &str = "1234 (bash) S 1 1234 1234 34816 1234 4194304 1000 2000 0 0 10 20 30 40 \
                        20 0 1 0 4242 12345678 900 18446744073709551615";

    #[test]
    fn reads_field_22() {
        assert_eq!(starttime_ticks(STAT), Some(4242));
    }

    /// The reason the split is on the *last* parenthesis. A process can be named anything, and
    /// splitting on whitespace or the first `)` silently shifts every field after it.
    #[test]
    fn a_process_name_containing_spaces_and_parens_does_not_shift_the_fields() {
        let weird = STAT.replace("(bash)", "(my (weird) proc)");
        assert_eq!(starttime_ticks(&weird), Some(4242));

        let spaced = STAT.replace("(bash)", "(Web Content)");
        assert_eq!(starttime_ticks(&spaced), Some(4242));
    }

    #[test]
    fn malformed_input_is_none_rather_than_a_guess() {
        assert_eq!(starttime_ticks(""), None);
        assert_eq!(starttime_ticks("no parens here at all"), None);
        assert_eq!(starttime_ticks("1234 (bash) S 1 2 3"), None, "too few fields");
        let not_a_number = STAT.replace(" 4242 ", " forty-two ");
        assert_eq!(starttime_ticks(&not_a_number), None);
    }

    #[test]
    fn converts_ticks_at_the_usual_hundred_hertz() {
        assert_eq!(ticks_to_nanos(0, 100), Some(0));
        assert_eq!(ticks_to_nanos(100, 100), Some(1_000_000_000));
        assert_eq!(ticks_to_nanos(4242, 100), Some(42_420_000_000));
        assert_eq!(ticks_to_nanos(1, 1000), Some(1_000_000));
    }

    /// The overflow the `u128` intermediate exists for: ten years of uptime at 100 Hz is about
    /// 3.2e10 ticks, and `3.2e10 * 1e9` does not fit in a `u64`.
    #[test]
    fn a_decade_of_uptime_does_not_overflow() {
        let ten_years_of_ticks = 10 * 365 * 86_400 * 100;
        assert_eq!(
            ticks_to_nanos(ten_years_of_ticks, 100),
            Some(10 * 365 * 86_400 * 1_000_000_000)
        );
    }

    #[test]
    fn a_nonsense_tick_rate_is_refused_rather_than_dividing_by_zero() {
        assert_eq!(ticks_to_nanos(100, 0), None);
        assert_eq!(ticks_to_nanos(100, -1), None);
    }

    /// The real thing, on this process. Its start time must be positive and no later than now.
    #[test]
    fn reads_this_processs_own_start_time() {
        let hz = ticks_per_second().expect("sysconf(_SC_CLK_TCK)");
        assert_eq!(hz, 100, "unexpected tick rate on this host; not fatal, but worth knowing");

        let started = started_at(std::process::id(), hz).expect("own /proc/self/stat");
        let now = mp_host::clock::now_boottime().unwrap();
        assert!(started > 0, "start time should be positive: {started}");
        assert!(started <= now, "a process cannot start after now: {started} > {now}");
    }

    #[test]
    fn a_missing_process_is_an_error_not_a_zero() {
        // PID 0 never has a /proc entry.
        assert!(started_at(0, 100).is_err());
    }
}
