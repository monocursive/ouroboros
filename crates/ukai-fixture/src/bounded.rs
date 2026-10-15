//! Bounded descriptor I/O for the network and Unix-socket modes.
//!
//! Every wait goes through `poll` with the time left before one deadline, so
//! a peer that never answers costs at most the mode's `--timeout-ms`. A
//! deadline that passes is reported as `ETIMEDOUT` with
//! `"errno_source":"fixture_deadline"`: the kernel did not return that errno,
//! the fixture stopped waiting, and the line says so.

use std::ffi::c_int;
use std::time::{Duration, Instant};

use crate::report::OpReport;

/// One deadline for a whole mode.
#[derive(Copy, Clone, Debug)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    #[must_use]
    pub fn after_ms(ms: u64) -> Deadline {
        Deadline {
            at: Instant::now() + Duration::from_millis(ms),
        }
    }

    #[must_use]
    pub fn expired(&self) -> bool {
        Instant::now() >= self.at
    }

    /// Milliseconds left, clamped to what `poll` takes; 0 once expired.
    #[must_use]
    pub fn remaining_ms(&self) -> c_int {
        let left = self.at.saturating_duration_since(Instant::now());
        // Round up so a sub-millisecond remainder still waits once.
        let ms = left.as_micros().div_ceil(1000);
        c_int::try_from(ms).unwrap_or(c_int::MAX)
    }
}

/// Why a bounded operation stopped.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoFail {
    /// The deadline passed first.
    Timeout,
    /// A syscall failed with this raw errno.
    Errno(c_int),
}

impl IoFail {
    /// Put this failure on a report line: `ret` -1 and the errno, with a
    /// timeout marked as the fixture's own.
    pub fn apply(self, report: &mut OpReport) {
        match self {
            IoFail::Timeout => mark_timeout(report),
            IoFail::Errno(e) => report.result(-1, Some(e)),
        }
    }
}

/// A deadline expiry on a report line.
pub fn mark_timeout(report: &mut OpReport) {
    report.set("timed_out", true);
    report.set("errno_source", "fixture_deadline");
    report.result(-1, Some(libc::ETIMEDOUT));
}

fn errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Wait until `fd` reports one of `events` (or an error/hang-up, which the
/// next read or write turns into its own result).
pub fn wait_for(fd: c_int, events: libc::c_short, deadline: Deadline) -> Result<(), IoFail> {
    loop {
        if deadline.expired() {
            return Err(IoFail::Timeout);
        }
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: `pfd` is one live pollfd and the count passed is 1.
        let r = unsafe { libc::poll(&raw mut pfd, 1, deadline.remaining_ms()) };
        if r < 0 {
            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(IoFail::Errno(e));
        }
        if r == 0 {
            continue; // the loop head decides whether the deadline passed
        }
        if pfd.revents & (events | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(());
        }
    }
}

/// Read what is available, waiting at most until the deadline. `Ok(0)` is
/// end of stream.
pub fn read_some(fd: c_int, buf: &mut [u8], deadline: Deadline) -> Result<usize, IoFail> {
    loop {
        wait_for(fd, libc::POLLIN, deadline)?;
        // SAFETY: `buf` is a live, exclusively borrowed slice and the kernel
        // writes at most `buf.len()` bytes into it.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n < 0 {
            let e = errno();
            if e == libc::EINTR || e == libc::EAGAIN {
                continue;
            }
            return Err(IoFail::Errno(e));
        }
        return Ok(n as usize);
    }
}

/// Write every byte, waiting at most until the deadline.
pub fn write_all(fd: c_int, mut buf: &[u8], deadline: Deadline) -> Result<(), IoFail> {
    while !buf.is_empty() {
        wait_for(fd, libc::POLLOUT, deadline)?;
        // SAFETY: `buf` is a live slice; the kernel reads at most its length.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if n < 0 {
            let e = errno();
            if e == libc::EINTR || e == libc::EAGAIN {
                continue;
            }
            return Err(IoFail::Errno(e));
        }
        if n == 0 {
            return Err(IoFail::Errno(libc::EPIPE));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Set `O_NONBLOCK`. Returns the raw errno on failure.
pub fn set_nonblocking(fd: c_int) -> Result<(), c_int> {
    // SAFETY: flag reads and writes on a descriptor number; no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Set `FD_CLOEXEC`, for the platform that cannot ask for it atomically.
pub fn set_cloexec(fd: c_int) -> Result<(), c_int> {
    // SAFETY: flag write on a descriptor number; no pointers.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// `getsockopt(SOL_SOCKET, SO_ERROR)`: the pending error of a socket, 0 when
/// none. `Err` carries the errno of `getsockopt` itself.
pub fn so_error(fd: c_int) -> Result<c_int, c_int> {
    let mut value: c_int = 0;
    let mut len = size_of::<c_int>() as libc::socklen_t;
    // SAFETY: `value` is a live int and `len` says exactly its size, so the
    // kernel writes at most that many bytes.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if r < 0 {
        return Err(errno());
    }
    Ok(value)
}

/// Close a descriptor this process owns. Negative numbers are ignored.
pub fn close(fd: c_int) {
    if fd >= 0 {
        // SAFETY: the caller owns `fd` and never uses it afterwards.
        unsafe { libc::close(fd) };
    }
}

/// `byte i = i % 256`, the payload pattern the byte-stream modes use.
#[must_use]
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// At most `max` bytes of `bytes` as lossy UTF-8, for a report line.
#[must_use]
pub fn preview(bytes: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(max)]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe() -> (c_int, c_int) {
        let mut fds = [0 as c_int; 2];
        // SAFETY: `fds` is a live array of two ints.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    #[test]
    fn a_read_with_nothing_to_read_stops_at_the_deadline() {
        let (r, w) = pipe();
        let started = Instant::now();
        let mut buf = [0u8; 8];
        let got = read_some(r, &mut buf, Deadline::after_ms(50));
        assert_eq!(got, Err(IoFail::Timeout));
        assert!(started.elapsed() >= Duration::from_millis(45));
        assert!(started.elapsed() < Duration::from_secs(5), "bounded");
        close(r);
        close(w);
    }

    #[test]
    fn a_read_never_writes_past_the_buffer_it_was_given() {
        // The precondition of the `read` in `read_some`: the kernel may write
        // at most `buf.len()` bytes. Offer far more than fits.
        let (r, w) = pipe();
        let big = pattern(4096);
        assert!(write_all(w, &big, Deadline::after_ms(1000)).is_ok());
        let mut guard = [0xAAu8; 32];
        let (buf, tail) = guard.split_at_mut(16);
        let n = read_some(r, buf, Deadline::after_ms(1000)).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf, &big[..16]);
        assert!(tail.iter().all(|b| *b == 0xAA), "nothing beyond the slice");
        close(r);
        close(w);
    }

    #[test]
    fn end_of_stream_is_zero_and_a_closed_descriptor_is_an_errno() {
        let (r, w) = pipe();
        close(w);
        let mut buf = [0u8; 4];
        assert_eq!(read_some(r, &mut buf, Deadline::after_ms(1000)), Ok(0));
        close(r);
        // A descriptor number that is not open: poll reports POLLNVAL and the
        // read turns it into EBADF rather than a hang.
        let bad = read_some(9_999, &mut buf, Deadline::after_ms(1000));
        assert_eq!(bad, Err(IoFail::Errno(libc::EBADF)));
    }

    #[test]
    fn a_timeout_is_marked_as_the_fixtures_own() {
        let mut r = OpReport::new("recvfrom");
        IoFail::Timeout.apply(&mut r);
        assert_eq!(r.ret, -1);
        assert_eq!(r.errno.as_deref(), Some("ETIMEDOUT"));
        assert_eq!(r.args["errno_source"], "fixture_deadline");
        let mut r = OpReport::new("connect");
        IoFail::Errno(libc::ECONNREFUSED).apply(&mut r);
        assert_eq!(r.errno.as_deref(), Some("ECONNREFUSED"));
        assert!(!r.args.contains_key("errno_source"));
    }

    #[test]
    fn the_preview_is_bounded() {
        assert_eq!(preview(b"abcdef", 3), "abc");
        assert_eq!(preview(b"ab", 3), "ab");
    }
}
