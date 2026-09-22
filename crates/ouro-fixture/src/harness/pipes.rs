//! Private pipes between the test process and `ouro-jail`.
//!
//! Both ends are created close-on-exec, so nothing leaks into any other child
//! the test process spawns. Only the jail's end is made inheritable, and only
//! inside the forked child, by `dup2`-ing it onto a descriptor number chosen
//! in the parent (`dup2` clears close-on-exec on the new descriptor). The
//! target numbers are picked so that no target collides with any source, which
//! makes the order of the `dup2` calls irrelevant — the child runs nothing but
//! `dup2`, which is async-signal-safe.

use std::ffi::c_int;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// Create a pipe whose two ends are both close-on-exec.
///
/// Linux gets it atomically from `pipe2`. macOS has no `pipe2`, so the flag is
/// set right after `pipe`; a concurrent `fork` in the window could inherit the
/// descriptors. That is recorded as a deviation rather than hidden: on macOS
/// the jail refuses before executing anything, so no channel is used there.
pub fn cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    #[cfg(target_os = "linux")]
    // SAFETY: `fds` is a live array of two ints, which is what `pipe2` writes.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: as above, for `pipe`.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(not(target_os = "linux"))]
    for fd in fds {
        // SAFETY: `fd` was just returned by `pipe` and is owned here.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let e = io::Error::last_os_error();
            // SAFETY: both descriptors are owned here and dropped on error.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(e);
        }
    }
    // SAFETY: both descriptors were just created and are not owned elsewhere.
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// Which way a channel runs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The jail writes, the test reads (control, trace).
    JailWrites,
    /// The jail reads, the test writes (gate).
    JailReads,
}

/// One plumbed channel, before the spawn.
pub struct Channel {
    /// The end the test keeps.
    pub ours: OwnedFd,
    /// The end the jail must inherit; closed in the parent after the spawn.
    pub theirs: OwnedFd,
    /// The descriptor number the jail sees, passed on its command line.
    pub target: RawFd,
}

impl Channel {
    pub fn new(direction: Direction) -> io::Result<Channel> {
        let (read, write) = cloexec_pipe()?;
        let (ours, theirs) = match direction {
            Direction::JailWrites => (read, write),
            Direction::JailReads => (write, read),
        };
        Ok(Channel {
            ours,
            theirs,
            target: -1,
        })
    }
}

/// Assign target descriptor numbers that collide with no source descriptor, so
/// the child's `dup2` calls are order independent.
pub fn assign_targets(channels: &mut [Channel]) {
    let sources: Vec<RawFd> = channels
        .iter()
        .flat_map(|c| [c.ours.as_raw_fd(), c.theirs.as_raw_fd()])
        .collect();
    let mut next: RawFd = 3;
    for c in channels.iter_mut() {
        while sources.contains(&next) || next <= 2 {
            next += 1;
        }
        c.target = next;
        next += 1;
    }
}

/// Move each channel's descriptor onto its target number. Runs in the forked
/// child before `exec`: `dup2` and `fcntl` are the only calls, both
/// async-signal-safe, and neither allocates.
///
/// # Safety
///
/// `plan` must outlive the call and the targets must not collide with any
/// source, which [`assign_targets`] guarantees.
pub unsafe fn place_in_child(plan: &[(RawFd, RawFd)]) -> io::Result<()> {
    for (src, target) in plan {
        if src == target {
            // SAFETY: clearing close-on-exec on a descriptor this child owns.
            if unsafe { libc::fcntl(*src, libc::F_SETFD, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
        // SAFETY: both numbers are valid; `dup2` clears close-on-exec on the
        // new descriptor, which is exactly what the jail must inherit.
        } else if unsafe { libc::dup2(*src, *target) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A blocking NDJSON reader with a bounded wait, so a test fails instead of
/// hanging. The bound catches hangs; it is never used to order events.
pub struct LineReader {
    fd: OwnedFd,
    buf: Vec<u8>,
    eof: bool,
    pub timeout: Duration,
}

impl LineReader {
    #[must_use]
    pub fn new(fd: OwnedFd) -> LineReader {
        LineReader {
            fd,
            buf: Vec::new(),
            eof: false,
            timeout: Duration::from_secs(30),
        }
    }

    /// The next complete line without its terminator, or `None` at EOF.
    pub fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let line = self.buf.drain(..=i).take(i).collect();
                return Ok(Some(line));
            }
            if self.eof {
                return Ok(if self.buf.is_empty() {
                    None
                } else {
                    Some(std::mem::take(&mut self.buf))
                });
            }
            self.fill(deadline)?;
        }
    }

    /// Everything still readable, up to EOF.
    pub fn drain(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        while let Some(line) = self.next_line()? {
            out.push(line);
        }
        Ok(out)
    }

    fn fill(&mut self, deadline: Instant) -> io::Result<()> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no line within the harness timeout",
            ));
        }
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd; the descriptor is owned by this reader.
        let r = unsafe {
            libc::poll(
                &raw mut pfd,
                1,
                i32::try_from(left.as_millis()).unwrap_or(i32::MAX),
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(e);
        }
        if r == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no line within the harness timeout",
            ));
        }
        let mut chunk = [0u8; 8192];
        // SAFETY: `chunk` is live and `read` writes at most its length.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                chunk.as_mut_ptr().cast::<libc::c_void>(),
                chunk.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(e);
        }
        if n == 0 {
            self.eof = true;
        } else {
            self.buf.extend_from_slice(&chunk[..n as usize]);
        }
        Ok(())
    }
}

/// The writing end of the gate. Dropping it closes the gate.
pub struct GateWriter {
    fd: OwnedFd,
}

impl GateWriter {
    #[must_use]
    pub fn new(fd: OwnedFd) -> GateWriter {
        GateWriter { fd }
    }

    /// Write exactly these bytes. A short write is an error, not a retry loop
    /// that could reorder against the close.
    pub fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            // SAFETY: `buf` is live and the descriptor is owned here.
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    buf.as_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    /// Close the gate. Equivalent to dropping it, but explicit at the call site.
    pub fn close(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn both_ends_of_a_new_pipe_are_close_on_exec() {
        let (r, w) = cloexec_pipe().unwrap();
        for fd in [r.as_raw_fd(), w.as_raw_fd()] {
            // SAFETY: reading the descriptor flags of an owned descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0);
            assert!(flags & libc::FD_CLOEXEC != 0, "fd {fd} leaked across exec");
        }
    }

    #[test]
    fn targets_never_collide_with_a_source_or_with_stdio() {
        let mut channels = vec![
            Channel::new(Direction::JailWrites).unwrap(),
            Channel::new(Direction::JailReads).unwrap(),
            Channel::new(Direction::JailWrites).unwrap(),
        ];
        assign_targets(&mut channels);
        let sources: Vec<RawFd> = channels
            .iter()
            .flat_map(|c| [c.ours.as_raw_fd(), c.theirs.as_raw_fd()])
            .collect();
        let targets: Vec<RawFd> = channels.iter().map(|c| c.target).collect();
        for t in &targets {
            assert!(*t >= 3, "target {t} collides with stdio");
            assert!(!sources.contains(t), "target {t} collides with a source");
        }
        let mut sorted = targets.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), targets.len(), "targets must be distinct");
    }

    #[test]
    fn the_line_reader_splits_on_lf_and_reports_eof() {
        let (r, w) = cloexec_pipe().unwrap();
        let mut writer = GateWriter::new(w);
        writer.write_all(b"one\ntwo\npartial").unwrap();
        writer.close();
        let mut reader = LineReader::new(r);
        assert_eq!(reader.next_line().unwrap().unwrap(), b"one");
        assert_eq!(reader.next_line().unwrap().unwrap(), b"two");
        assert_eq!(
            reader.next_line().unwrap().unwrap(),
            b"partial",
            "trailing bytes without LF are still surfaced, not dropped"
        );
        assert_eq!(reader.next_line().unwrap(), None);
    }

    #[test]
    fn the_reader_times_out_rather_than_hanging() {
        let (r, _w) = cloexec_pipe().unwrap();
        let mut reader = LineReader::new(r);
        reader.timeout = Duration::from_millis(120);
        let err = reader.next_line().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn an_empty_writer_close_reads_as_immediate_eof() {
        let (r, w) = cloexec_pipe().unwrap();
        drop(w);
        let mut reader = LineReader::new(r);
        assert_eq!(reader.next_line().unwrap(), None);
    }
}
