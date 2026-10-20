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
use rustix::io::Errno;
use rustix::time::{
    Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec, timerfd_create,
    timerfd_settime,
};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use tokio::io::unix::AsyncFd;

/// A registered interest in "something moved the wall clock".
pub struct StepWatch {
    fd: AsyncFd<OwnedFd>,
}

impl StepWatch {
    pub fn new() -> Result<Self> {
        let flags = TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK;
        let fd = timerfd_create(TimerfdClockId::Realtime, flags)
            .context("timerfd_create(CLOCK_REALTIME)")?;

        arm(&fd).context("arming the cancel-on-set timer")?;
        // SAFETY: the reactor needs the descriptor open and unchanged for as long as the `AsyncFd`
        // holds it. An `OwnedFd` closes only on drop and always reports the same descriptor, and
        // `StepWatch` never takes it back out (`get_mut`, `into_inner`), so the two drop together.
        let registered = unsafe { AsyncFd::register(fd) };
        // Through `io::Error` first: the register error's `Display` already includes its cause and
        // `source()` returns it again, so `context` on it directly would print the errno twice.
        let fd = registered
            .map_err(io::Error::from)
            .context("registering the timerfd with the reactor")?;
        Ok(Self { fd })
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
            let Ok(result) = guard.try_io(|inner| read_expirations(inner.get_ref())) else {
                continue;
            };

            match result {
                Err(e) if Errno::from_io_error(&e) == Some(Errno::CANCELED) => {
                    // MANDATORY. Without this the descriptor stays cancelled, every subsequent
                    // read returns ECANCELED immediately, and the loop spins on the first step
                    // forever while never seeing the second.
                    arm(self.fd.get_ref()).context("re-arming after a clock step")?;
                    return Ok(());
                }
                // The far-future expiry actually fired, which needs a machine to still be up in
                // the year 292277026596. Re-arm and keep waiting rather than reporting a step
                // that did not happen.
                Ok(_) => arm(self.fd.get_ref()).context("re-arming after expiry")?,
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
fn arm(fd: impl AsFd) -> io::Result<()> {
    let candidates = [i64::MAX, i64::from(i32::MAX)];
    let mut last = None;
    for seconds in candidates {
        match set_far_future(&fd, seconds) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("candidates is non-empty"))
}

fn set_far_future(fd: impl AsFd, seconds: i64) -> io::Result<()> {
    let spec = Itimerspec {
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: Timespec { tv_sec: seconds, tv_nsec: 0 },
    };
    timerfd_settime(fd, TimerfdTimerFlags::ABSTIME | TimerfdTimerFlags::CANCEL_ON_SET, &spec)?;
    Ok(())
}

/// `io::Result` rather than rustix's own, because [`AsyncFdReadyGuard::try_io`] recognises a
/// spurious wakeup by `io::ErrorKind::WouldBlock`.
///
/// [`AsyncFdReadyGuard::try_io`]: tokio::io::unix::AsyncFdReadyGuard::try_io
fn read_expirations(fd: impl AsFd) -> io::Result<u64> {
    // Exactly the 8 bytes timerfd hands out, so a short read is impossible.
    let mut buf = [0u8; size_of::<u64>()];
    rustix::io::read(fd, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
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
            arm(watch.fd.get_ref()).expect("re-arm should always succeed");
        }
        let result = tokio::time::timeout(Duration::from_millis(100), watch.stepped()).await;
        assert!(result.is_err(), "re-arming must not itself look like a step");
    }

    /// The fallback path has to work on its own, since on the hosts that need it the maximal
    /// value is what fails.
    #[tokio::test]
    async fn the_thirty_two_bit_expiry_is_a_working_fallback() {
        let watch = StepWatch::new().unwrap();
        set_far_future(watch.fd.get_ref(), i64::from(i32::MAX))
            .expect("i32::MAX seconds should be armable");
    }

    /// A descriptor that is not a timer must fail loudly rather than arming nothing. A silently
    /// unarmed watch is indistinguishable from a clock that never gets stepped.
    #[test]
    fn arming_a_non_timer_is_an_error() {
        let file = tempfile::tempfile().unwrap();
        assert!(arm(&file).is_err());
    }
}
