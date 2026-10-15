//! The portable system calls std does not wrap, each with its safety
//! argument: this process's ids (those only Linux code asks for compiled
//! there only), `poll(2)` and `O_NONBLOCK`. The Linux
//! platform's helpers (`platform::linux::sys`), the proxy's (`proxy::sys`)
//! and `state` re-export these rather than keep copies, so each call has one
//! implementation.
//!
//! [`poll`] and [`set_nonblocking`] take descriptors as [`BorrowedFd`], so
//! every call sees descriptors that are open for its whole duration;
//! [`poll_fds`] takes the `pollfd` entries its caller built from descriptors
//! it holds.

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::time::Duration;

/// This process's effective uid.
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no argument, touches no memory and cannot fail.
    unsafe { libc::geteuid() }
}

/// This process's real uid.
#[must_use]
pub fn real_uid() -> u32 {
    // SAFETY: `getuid` takes no argument, touches no memory and cannot fail.
    unsafe { libc::getuid() }
}

/// This process's effective gid.
#[must_use]
pub fn effective_gid() -> u32 {
    // SAFETY: `getegid` takes no argument, touches no memory and cannot fail.
    unsafe { libc::getegid() }
}

/// This process's pid, as the kernel's `pid_t`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn own_pid() -> libc::pid_t {
    // SAFETY: `getpid` takes no argument, touches no memory and cannot fail.
    unsafe { libc::getpid() }
}

/// The parent's pid. Async-signal-safe, so a forked child may call it
/// before its `exec`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn parent_pid() -> libc::pid_t {
    // SAFETY: `getppid` takes no argument, touches no memory and cannot
    // fail.
    unsafe { libc::getppid() }
}

/// One `poll(2)` entry: a descriptor and the events wanted from it, or
/// `None`, a placeholder poll skips (its `revents` stay 0), which keeps the
/// entries' indexes stable when a side has nothing asked of it.
pub(crate) type Interest<'a> = Option<(BorrowedFd<'a>, libc::c_short)>;

/// `poll(2)` on each interest; returns each one's `revents`.
///
/// `None` waits without a timeout; a timeout is rounded up to whole
/// milliseconds and clamped to `i32::MAX` of them. An interrupted call
/// returns [`io::ErrorKind::Interrupted`].
///
/// # Errors
/// The `poll` error.
pub(crate) fn poll(
    interests: &[Interest<'_>],
    timeout: Option<Duration>,
) -> io::Result<Vec<libc::c_short>> {
    let mut entries: Vec<libc::pollfd> = interests
        .iter()
        .map(|interest| match interest {
            Some((fd, events)) => libc::pollfd {
                fd: fd.as_raw_fd(),
                events: *events,
                revents: 0,
            },
            // poll(2) ignores a negative descriptor and reports nothing for it.
            None => libc::pollfd {
                fd: -1,
                events: 0,
                revents: 0,
            },
        })
        .collect();
    let timeout: libc::c_int = match timeout {
        None => -1,
        Some(duration) => {
            // Round up so a short positive timeout never becomes a busy 0.
            let millis = duration.as_nanos().div_ceil(1_000_000);
            libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX)
        }
    };
    poll_fds(&mut entries, timeout)?;
    Ok(entries.iter().map(|entry| entry.revents).collect())
}

/// Whether `fd` has `events` pending right now, without waiting.
///
/// # Errors
/// The `poll` error.
pub(crate) fn ready(fd: BorrowedFd<'_>, events: libc::c_short) -> io::Result<bool> {
    Ok(poll(&[Some((fd, events))], Some(Duration::ZERO))?
        .first()
        .is_some_and(|&revents| revents != 0))
}

/// `poll(2)` over `fds` for at most `timeout_ms` (negative: no bound): how
/// many have events. Every non-negative descriptor in `fds` must be one the
/// caller holds open until this returns.
///
/// # Errors
/// The errno of a failed `poll`; `Interrupted` for a signal, which a caller
/// may treat as nothing ready only if it asks again.
pub(crate) fn poll_fds(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    let count = libc::nfds_t::try_from(fds.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many descriptors"))?;
    // SAFETY: `fds` holds `count` initialized pollfds and outlives the call;
    // poll writes only their `revents`. A descriptor that is not open is
    // reported as `POLLNVAL`, never dereferenced.
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), count, timeout_ms) };
    usize::try_from(ready).map_err(|_| io::Error::last_os_error())
}

/// Sets `O_NONBLOCK` on `fd`, keeping its other status flags.
///
/// # Errors
/// The errno from `fcntl`.
pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL take scalars and dereference nothing; the
    // descriptor is live for the borrow.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn poll_reports_readiness_per_descriptor_and_handles_edges() {
        let (mut a, b) = UnixStream::pair().expect("a pair");
        let (c, _d) = UnixStream::pair().expect("a pair");
        fn both<'a>(b: &'a UnixStream, c: &'a UnixStream) -> [Interest<'a>; 2] {
            [
                Some((b.as_fd(), libc::POLLIN)),
                Some((c.as_fd(), libc::POLLIN)),
            ]
        }
        // Nothing to read: a zero timeout returns at once.
        let revents = poll(&both(&b, &c), Some(Duration::ZERO)).expect("polls");
        assert_eq!(revents, vec![0, 0]);
        assert!(!ready(b.as_fd(), libc::POLLIN).expect("polls"));
        a.write_all(b"x").expect("writes");
        let revents = poll(&both(&b, &c), None).expect("polls");
        assert!(revents[0] & libc::POLLIN != 0);
        assert_eq!(revents[1], 0);
        assert!(ready(b.as_fd(), libc::POLLIN).expect("polls"));
        // Each entry asks for its own events: c is writable, b readable.
        let revents = poll(
            &[
                Some((b.as_fd(), libc::POLLIN)),
                Some((c.as_fd(), libc::POLLOUT)),
            ],
            None,
        )
        .expect("polls");
        assert!(revents[0] & libc::POLLIN != 0 && revents[1] & libc::POLLOUT != 0);
        // A placeholder keeps its index and reports nothing.
        let revents = poll(&[None, Some((b.as_fd(), libc::POLLIN))], None).expect("polls");
        assert_eq!(revents[0], 0);
        assert!(revents[1] & libc::POLLIN != 0);
        // An empty set with a timeout is a sleep, not an error.
        assert_eq!(
            poll(&[], Some(Duration::from_millis(1))).ok(),
            Some(Vec::new())
        );
        // A timeout beyond i32 milliseconds is clamped, not wrapped negative
        // (which would mean "forever"): the ready descriptor returns at once.
        let revents = poll(&[Some((b.as_fd(), libc::POLLIN))], Some(Duration::MAX)).expect("polls");
        assert!(revents[0] & libc::POLLIN != 0);
    }

    #[test]
    fn set_nonblocking_keeps_the_other_flags() {
        let (a, _b) = UnixStream::pair().expect("a pair");
        // SAFETY: F_GETFL reads the flags of a descriptor this test holds.
        let before = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_GETFL) };
        set_nonblocking(a.as_fd()).expect("sets");
        // SAFETY: as above.
        let after = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(after, before | libc::O_NONBLOCK);
        let mut buffer = [0u8; 1];
        let error = std::io::Read::read(&mut &a, &mut buffer).expect_err("nothing to read");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }
}
