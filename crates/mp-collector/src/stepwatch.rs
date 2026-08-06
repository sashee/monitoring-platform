//! Live step detection (design §4.3): a `timerfd` armed with `TFD_TIMER_CANCEL_ON_SET`.
//!
//! The timer's expiry is irrelevant — it is set as far in the future as the kernel will accept.
//! The *cancellation* is the notification: when anything steps `CLOCK_REALTIME`, the kernel
//! cancels the timer and the next `read()` fails with `ECANCELED`.
//!
//! Two things this depends on, both easy to get wrong:
//!
//! - **Re-arm after every cancellation**, or only the first step is ever seen. [`stepped`] does it
//!   before returning, so a caller cannot forget.
//! - **Only steps produce a notification.** A slewed correction does not — but it also does not
//!   need one. `CLOCK_REALTIME` and `CLOCK_BOOTTIME` are slewed by the *same* frequency
//!   adjustment, so `realtime − boottime` is unchanged by slewing. The offset moves only when
//!   something injects a discontinuity (`settimeofday`, `clock_settime`, `ADJ_SETOFFSET`,
//!   resume-from-suspend), and every one of those calls `clock_was_set()` and lands here.
//!
//!   Measured on a host under active NTP discipline, the offset held constant to within ±500 ns
//!   over twelve seconds — the read interleave and nothing else.
//!
//! [`stepped`]: StepWatch::stepped

use anyhow::{Context, Result};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

/// A registered interest in "something moved the wall clock".
pub struct StepWatch {
    fd: AsyncFd<OwnedFd>,
}

impl StepWatch {
    pub fn new() -> Result<Self> {
        // SAFETY: `timerfd_create` takes no pointers and returns a fresh descriptor or -1.
        let raw = unsafe {
            libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
        };
        if raw < 0 {
            return Err(io::Error::last_os_error()).context("timerfd_create(CLOCK_REALTIME)");
        }
        // SAFETY: `raw` is a fresh descriptor this call owns and nothing else holds.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        arm(fd.as_raw_fd()).context("arming the cancel-on-set timer")?;
        Ok(Self { fd: AsyncFd::new(fd).context("registering the timerfd with the reactor")? })
    }

    /// Resolves the next time the realtime clock is stepped, leaving the watch armed for the one
    /// after that.
    ///
    /// Cancel-safe: dropping the future loses nothing, because the cancellation is latched in the
    /// descriptor until it is read.
    pub async fn stepped(&self) -> Result<()> {
        loop {
            let mut guard = self.fd.readable().await.context("waiting on the cancel-on-set timer")?;

            // `try_io` turns a spurious readiness into `Err(WouldBlock)` at the outer level and
            // retries; anything else, including the ECANCELED this exists for, comes through.
            let Ok(result) = guard.try_io(|inner| read_expirations(inner.get_ref().as_raw_fd()))
            else {
                continue;
            };

            match result {
                Err(e) if e.raw_os_error() == Some(libc::ECANCELED) => {
                    // MANDATORY. Without this the descriptor stays cancelled, every subsequent
                    // read returns ECANCELED immediately, and the loop spins on the first step
                    // forever while never seeing the second.
                    arm(self.fd.get_ref().as_raw_fd()).context("re-arming after a clock step")?;
                    return Ok(());
                }
                // The far-future expiry actually fired, which needs a machine to still be up in
                // the year 292277026596. Re-arm and keep waiting rather than reporting a step
                // that did not happen.
                Ok(_) => arm(self.fd.get_ref().as_raw_fd()).context("re-arming after expiry")?,
                Err(e) => return Err(e).context("reading the cancel-on-set timer"),
            }
        }
    }
}

/// Arms the timer as far out as the kernel will take it, with `TFD_TIMER_CANCEL_ON_SET`.
///
/// The `i32::MAX` fallback mirrors systemd's `time_change_fd()`: on a system where `time_t` is 64
/// bits but the kernel has no 64-bit time support, the maximal value is refused, and a watch that
/// silently failed to arm would look exactly like a clock that never gets stepped.
fn arm(fd: RawFd) -> io::Result<()> {
    let candidates = [libc::time_t::MAX, libc::time_t::from(i32::MAX)];
    let mut last = None;
    for seconds in candidates {
        match set_far_future(fd, seconds) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("candidates is non-empty"))
}

fn set_far_future(fd: RawFd, seconds: libc::time_t) -> io::Result<()> {
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: seconds, tv_nsec: 0 },
    };
    // SAFETY: `spec` outlives the call and the kernel only reads it; the old-value pointer is
    // null, which the syscall accepts as "do not report".
    let rc = unsafe {
        libc::timerfd_settime(
            fd,
            libc::TFD_TIMER_ABSTIME | libc::TFD_TIMER_CANCEL_ON_SET,
            &spec,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn read_expirations(fd: RawFd) -> io::Result<u64> {
    let mut buf = 0u64;
    // SAFETY: an 8-byte read into a `u64` this frame owns, which is exactly the size timerfd
    // requires; a short read is impossible and a failure returns -1.
    let n = unsafe { libc::read(fd, std::ptr::from_mut(&mut buf).cast(), size_of::<u64>()) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(buf) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Creating and arming must work as an unprivileged user: the watch only *observes* clock
    /// changes, it never makes one, so it needs no capability. If this ever starts failing under
    /// the service sandbox, step detection has silently stopped and nothing else would say so.
    #[tokio::test]
    async fn arms_without_privileges() {
        StepWatch::new().expect("a cancel-on-set timerfd should be available to any user");
    }

    /// Nothing steps the clock here, so the watch must stay quiet. A watch that resolved
    /// immediately would flush the buffer on a clock nobody corrected.
    #[tokio::test]
    async fn stays_quiet_while_the_clock_is_untouched() {
        let watch = StepWatch::new().unwrap();
        let result = tokio::time::timeout(Duration::from_millis(250), watch.stepped()).await;
        assert!(result.is_err(), "reported a step that never happened: {result:?}");
    }

    /// Re-arming is idempotent and repeatable, which is what makes the `ECANCELED` path safe to
    /// take an unbounded number of times.
    #[tokio::test]
    async fn re_arming_is_repeatable() {
        let watch = StepWatch::new().unwrap();
        for _ in 0..100 {
            arm(watch.fd.get_ref().as_raw_fd()).expect("re-arm should always succeed");
        }
        let result = tokio::time::timeout(Duration::from_millis(100), watch.stepped()).await;
        assert!(result.is_err(), "re-arming must not itself look like a step");
    }

    /// The fallback path has to work on its own, since on the hosts that need it the maximal
    /// value is what fails.
    #[tokio::test]
    async fn the_thirty_two_bit_expiry_is_a_working_fallback() {
        let watch = StepWatch::new().unwrap();
        set_far_future(watch.fd.get_ref().as_raw_fd(), libc::time_t::from(i32::MAX))
            .expect("i32::MAX seconds should be armable");
    }

    /// A descriptor that is not a timer must fail loudly rather than arming nothing. A silently
    /// unarmed watch is indistinguishable from a clock that never gets stepped.
    #[test]
    fn arming_a_non_timer_is_an_error() {
        let file = tempfile::tempfile().unwrap();
        assert!(arm(file.as_raw_fd()).is_err());
    }
}
