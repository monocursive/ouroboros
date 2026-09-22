//! The system calls the proxy needs and std does not wrap: `poll(2)` and the
//! `RLIMIT_NOFILE` pair. Every `unsafe` block is here, each with its safety
//! argument; the tests at the bottom exercise each boundary.
//!
//! Descriptors cross this boundary only as [`BorrowedFd`], so every call
//! sees descriptors that are open for its whole duration.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// `poll(2)` on each descriptor for `events`; returns each one's `revents`.
///
/// `None` waits without a timeout; a timeout is clamped to `i32::MAX`
/// milliseconds. An interrupted call returns [`io::ErrorKind::Interrupted`].
///
/// # Errors
/// The `poll` error.
pub(super) fn poll(
    fds: &[BorrowedFd<'_>],
    events: libc::c_short,
    timeout: Option<Duration>,
) -> io::Result<Vec<libc::c_short>> {
    let mut entries: Vec<libc::pollfd> = fds
        .iter()
        .map(|fd| libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
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
    let count = libc::nfds_t::try_from(entries.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `entries` is a live, initialized array of exactly `count`
    // `pollfd` values that outlives the call, and poll(2) only writes the
    // `revents` fields inside it. Every `fd` comes from a `BorrowedFd`, so it
    // stays open until the call returns.
    let rc = unsafe { libc::poll(entries.as_mut_ptr(), count, timeout) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(entries.iter().map(|entry| entry.revents).collect())
}

/// Whether `revents` says the descriptor hung up, failed or is invalid.
fn hung_up(revents: libc::c_short) -> bool {
    revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

/// Blocks until the peer of a stream socket has closed completely (not just
/// its sending side), until this side is shut down, or until `finished`.
///
/// A half-closed client of a tunnel may still read; one that closed
/// completely cannot, and holding its slot for a silent destination would
/// be a leak. On Linux `POLLHUP` with no requested events reports exactly
/// that, including this side's own `shutdown`, and the wait blocks. macOS
/// reports `POLLHUP` for a closed stream peer only together with `POLLOUT`
/// interest, which is also satisfied by a merely writable socket, so there
/// the wait probes every 100 ms and also watches `finished`.
pub(super) fn wait_peer_closed(fd: BorrowedFd<'_>, finished: &AtomicBool) {
    loop {
        if finished.load(Ordering::SeqCst) {
            return;
        }
        if cfg!(target_os = "linux") {
            match poll(&[fd], 0, None) {
                Ok(revents) if revents.first().copied().is_some_and(hung_up) => return,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        } else {
            // A timed wait; nothing is requested, so it returns on timeout.
            let _ = poll(&[fd], 0, Some(Duration::from_millis(100)));
            match poll(&[fd], libc::POLLOUT, Some(Duration::ZERO)) {
                Ok(revents) if revents.first().copied().is_some_and(hung_up) => return,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    }
}

/// Converts `rlim_t`, mapping `RLIM_INFINITY` to `u64::MAX`. (`rlim_t` is
/// `u64` on the supported targets, not on every target.)
#[allow(clippy::useless_conversion)]
fn from_rlim(value: libc::rlim_t) -> u64 {
    if value == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        u64::try_from(value).unwrap_or(u64::MAX)
    }
}

fn get_nofile() -> io::Result<libc::rlimit> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` that outlives the call;
    // getrlimit(2) writes exactly one `rlimit` through the pointer.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(limit)
}

/// The `RLIMIT_NOFILE` (soft, hard) pair; `u64::MAX` means unlimited.
///
/// # Errors
/// The `getrlimit` error.
pub fn nofile_limits() -> io::Result<(u64, u64)> {
    let limit = get_nofile()?;
    Ok((from_rlim(limit.rlim_cur), from_rlim(limit.rlim_max)))
}

/// Raises this process's soft `RLIMIT_NOFILE` to its hard limit, and returns
/// the (soft, hard) pair in force afterwards.
///
/// Only this process is affected, and only up to the limit its operator
/// already allows. macOS refuses an unlimited soft value, so smaller values
/// are tried in turn; if none is accepted the soft limit stays as it was,
/// and the caller's budget check decides.
///
/// # Errors
/// The `getrlimit` error.
pub fn raise_nofile_soft_to_hard() -> io::Result<(u64, u64)> {
    let current = get_nofile()?;
    let candidates = [
        current.rlim_max,
        1 << 20,
        1 << 16,
        // OPEN_MAX on macOS.
        10_240,
    ];
    for candidate in candidates {
        if candidate <= current.rlim_cur || candidate > current.rlim_max {
            continue;
        }
        let raised = libc::rlimit {
            rlim_cur: candidate,
            rlim_max: current.rlim_max,
        };
        // SAFETY: `raised` is a valid `rlimit` that outlives the call;
        // setrlimit(2) only reads it. It keeps the hard limit and raises the
        // soft limit within it, which needs no privilege.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) };
        if rc == 0 {
            break;
        }
    }
    nofile_limits()
}

/// The number of descriptors this process has open, from `/proc/self/fd`
/// (Linux) or `/dev/fd` (macOS). The directory handle used to count is
/// included, so the count is one high, never low.
///
/// # Errors
/// When neither directory can be read.
pub fn open_descriptor_count() -> io::Result<usize> {
    let directory = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    Ok(std::fs::read_dir(directory)?.count())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn poll_reports_readiness_per_descriptor_and_handles_edges() {
        let (mut a, b) = UnixStream::pair().expect("a pair");
        let (c, _d) = UnixStream::pair().expect("a pair");
        // Nothing to read: a zero timeout returns at once.
        let revents =
            poll(&[b.as_fd(), c.as_fd()], libc::POLLIN, Some(Duration::ZERO)).expect("polls");
        assert_eq!(revents, vec![0, 0]);
        a.write_all(b"x").expect("writes");
        let revents = poll(&[b.as_fd(), c.as_fd()], libc::POLLIN, None).expect("polls");
        assert!(revents[0] & libc::POLLIN != 0);
        assert_eq!(revents[1], 0);
        // An empty set with a timeout is a sleep, not an error.
        assert_eq!(
            poll(&[], libc::POLLIN, Some(Duration::from_millis(1))).ok(),
            Some(Vec::new())
        );
        // A timeout beyond i32 milliseconds is clamped, not wrapped negative
        // (which would mean "forever"): the ready descriptor returns at once.
        let revents = poll(&[b.as_fd()], libc::POLLIN, Some(Duration::MAX)).expect("polls");
        assert!(revents[0] & libc::POLLIN != 0);
    }

    #[test]
    fn wait_peer_closed_ignores_a_half_close_and_returns_on_close() {
        let (a, b) = UnixStream::pair().expect("a pair");
        let finished = Arc::new(AtomicBool::new(false));
        a.shutdown(std::net::Shutdown::Write).expect("half-closes");
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = {
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                wait_peer_closed(b.as_fd(), &finished);
                let _ = tx.send(Instant::now());
            })
        };
        // A half-close is not a close: the waiter must still be waiting.
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        drop(a);
        assert!(
            rx.recv_timeout(Duration::from_secs(10)).is_ok(),
            "the close wakes it"
        );
        waiter.join().expect("the waiter ran");
        // `finished` alone ends a wait too.
        let (_a, b) = UnixStream::pair().expect("a pair");
        finished.store(true, Ordering::SeqCst);
        wait_peer_closed(b.as_fd(), &finished);
    }

    #[test]
    fn the_descriptor_limit_is_readable_and_raising_it_is_idempotent() {
        let (soft, hard) = nofile_limits().expect("readable");
        assert!(soft <= hard);
        let (raised, same_hard) = raise_nofile_soft_to_hard().expect("readable");
        assert_eq!(same_hard, hard, "the hard limit never changes");
        assert!(raised >= soft, "the soft limit never goes down");
        assert_eq!(
            raise_nofile_soft_to_hard().expect("readable"),
            (raised, hard)
        );
        assert!(open_descriptor_count().expect("countable") >= 3);
    }
}
