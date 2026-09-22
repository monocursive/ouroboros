//! `CLOCK_BOOTTIME` in nanoseconds.
//!
//! Every observer timestamp comes from here. `CLOCK_BOOTTIME` is the clock
//! jail-v1 §6.4 calls elapsed continuous time: monotonic and, unlike
//! `CLOCK_MONOTONIC`, it keeps counting across suspend, so a wall deadline
//! measured with it cannot be extended by suspending the host.
//!
//! The linux slice may move this file; the observer only needs the one
//! function.

/// Nanoseconds since boot, including time spent suspended.
///
/// Returns 0 if the kernel refuses the clock, which it does not do for
/// `CLOCK_BOOTTIME` on any kernel that can run this crate; a 0 is visible as
/// a timestamp that cannot move forward rather than as an invented value.
#[must_use]
pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes exactly one `timespec` through the
    // pointer; `ts` is a live, correctly aligned `timespec` owned by this
    // frame and outlives the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::boottime_ns;

    #[test]
    fn boottime_is_nonzero_and_monotonic() {
        let a = boottime_ns();
        assert!(a > 0, "CLOCK_BOOTTIME must be available on a Linux host");
        let b = boottime_ns();
        assert!(
            b >= a,
            "CLOCK_BOOTTIME must not run backwards: {a} then {b}"
        );
    }

    #[test]
    fn boottime_advances_over_a_sleep() {
        let a = boottime_ns();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = boottime_ns();
        assert!(
            b - a >= 1_000_000,
            "expected at least 1 ms of progress, got {} ns",
            b - a
        );
    }
}
