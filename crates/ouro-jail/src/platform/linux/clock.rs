//! `CLOCK_BOOTTIME` and deadlines.
//!
//! jail-v1 §6.4: Linux measures execution wall, preparation, gate and stop
//! budgets with `CLOCK_BOOTTIME`, so suspend counts against a deadline and a
//! wall-clock adjustment does not move it.

use std::io;
use std::time::Duration;

/// Read a POSIX clock as nanoseconds.
///
/// # Errors
///
/// The errno from `clock_gettime`, which is `EINVAL` for a clock id the
/// kernel does not know.
pub fn clock_gettime_ns(clock: libc::clockid_t) -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live, writable `timespec`; clock_gettime writes into
    // it and returns -1 without touching it on an unknown clock id.
    let rc = unsafe { libc::clock_gettime(clock, &raw mut ts) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let secs = u64::try_from(ts.tv_sec).map_err(|_| io::Error::other("negative clock seconds"))?;
    let nanos =
        u64::try_from(ts.tv_nsec).map_err(|_| io::Error::other("negative clock nanoseconds"))?;
    Ok(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
}

/// Nanoseconds since boot, including time spent suspended.
///
/// # Panics
///
/// `CLOCK_BOOTTIME` has existed since Linux 2.6.39 and `clock_gettime` cannot
/// fail for it; a failure here means the kernel is not the one this code was
/// built for, and guessing a time would be worse than stopping.
#[must_use]
pub fn boottime_ns() -> u64 {
    clock_gettime_ns(libc::CLOCK_BOOTTIME).expect("CLOCK_BOOTTIME is always readable on Linux")
}

/// The instant this supervisor started, on the boot clock.
///
/// jail-v1 §13.1: every `monotonic_ns` in the trace, from every source,
/// counts from this one base, so wrapper events, audit events and gap
/// intervals can be correlated (§6.4 makes the base `CLOCK_BOOTTIME`, so
/// suspend counts and clock adjustments do not move it).
static SUPERVISOR_EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Record the supervisor's start if it was not recorded yet.
#[must_use]
pub fn mark_supervisor_start() -> u64 {
    *SUPERVISOR_EPOCH.get_or_init(boottime_ns)
}

/// Nanoseconds since the supervisor started, suspend included.
#[must_use]
pub fn supervisor_elapsed_ns() -> u64 {
    boottime_ns().saturating_sub(mark_supervisor_start())
}

/// A point on the boot clock.
///
/// Every arithmetic operation saturates: a deadline can be in the past, but it
/// can never wrap into the future.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline {
    end_ns: u64,
}

impl Deadline {
    /// A deadline `after` from now.
    #[must_use]
    pub fn after(duration: Duration) -> Self {
        Self {
            end_ns: boottime_ns().saturating_add(nanos_of(duration)),
        }
    }

    /// A deadline at an absolute boot-clock nanosecond.
    #[must_use]
    pub const fn at_ns(end_ns: u64) -> Self {
        Self { end_ns }
    }

    /// A deadline that has already passed.
    #[must_use]
    pub const fn immediate() -> Self {
        Self { end_ns: 0 }
    }

    /// The absolute boot-clock nanosecond this deadline ends at.
    #[must_use]
    pub const fn end_ns(self) -> u64 {
        self.end_ns
    }

    /// Time left, zero once expired.
    #[must_use]
    pub fn remaining(self) -> Duration {
        Duration::from_nanos(self.end_ns.saturating_sub(boottime_ns()))
    }

    /// Whether the deadline has passed.
    #[must_use]
    pub fn expired(self) -> bool {
        boottime_ns() >= self.end_ns
    }

    /// Time left in milliseconds, clamped to `cap`, for `poll(2)`.
    ///
    /// Rounds up, so a deadline with 100 microseconds left yields 1 rather
    /// than a busy zero-timeout spin.
    #[must_use]
    pub fn remaining_millis_capped(self, cap: i32) -> i32 {
        let left = self.remaining().as_nanos();
        if left == 0 {
            return 0;
        }
        let millis = left.div_ceil(1_000_000);
        let cap_u = u128::try_from(cap.max(0)).unwrap_or(0);
        i32::try_from(millis.min(cap_u)).unwrap_or(cap.max(0))
    }
}

fn nanos_of(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boottime_does_not_go_backwards() {
        let first = boottime_ns();
        let mut spins = 0u64;
        // Busy-wait rather than sleep: this is a clock test, not a timing one.
        let second = loop {
            let now = boottime_ns();
            if now != first || spins > 5_000_000 {
                break now;
            }
            spins += 1;
        };
        assert!(second >= first, "{second} < {first}");
        assert!(second > first, "the boot clock never advanced");
    }

    #[test]
    fn boottime_is_not_the_realtime_clock() {
        // CLOCK_BOOTTIME counts from boot, CLOCK_REALTIME from 1970. On any
        // host that has been up for less than 50 years they differ hugely.
        let boot = boottime_ns();
        let real = clock_gettime_ns(libc::CLOCK_REALTIME).unwrap();
        assert!(
            real > boot,
            "boot {boot} should be far below realtime {real}"
        );
    }

    #[test]
    fn an_unknown_clock_id_is_an_error_not_a_zero() {
        let err = clock_gettime_ns(1_000_000).expect_err("clock id 1000000 does not exist");
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn an_immediate_deadline_is_expired_and_has_no_time_left() {
        let d = Deadline::immediate();
        assert!(d.expired());
        assert_eq!(d.remaining(), Duration::ZERO);
        assert_eq!(d.remaining_millis_capped(5_000), 0);
    }

    #[test]
    fn a_future_deadline_is_not_expired_and_is_capped() {
        let d = Deadline::after(Duration::from_secs(3600));
        assert!(!d.expired());
        assert!(d.remaining() > Duration::from_secs(3500));
        assert_eq!(d.remaining_millis_capped(250), 250);
    }

    #[test]
    fn a_huge_duration_saturates_instead_of_wrapping() {
        let d = Deadline::after(Duration::from_secs(u64::MAX / 2));
        assert_eq!(d.end_ns(), u64::MAX);
        assert!(!d.expired());
    }

    #[test]
    fn sub_millisecond_remainder_rounds_up_to_one() {
        let d = Deadline::at_ns(boottime_ns() + 1000);
        assert!(d.remaining_millis_capped(5_000) <= 1);
    }
}
