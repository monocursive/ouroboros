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

/// What [`LineReader::drain`] read, and why it stopped.
///
/// `error` is `None` when the channel reached EOF, which is the only way a
/// transcript is known to be complete.
pub struct Drained {
    pub lines: Vec<Vec<u8>>,
    pub error: Option<io::Error>,
}

impl Drained {
    /// True when the channel did not reach EOF, so `lines` may be short.
    #[must_use]
    pub fn incomplete(&self) -> bool {
        self.error.is_some()
    }
}

/// A blocking NDJSON reader with a bounded wait, so a test fails instead of
/// hanging. The bound catches hangs; it is never used to order events.
pub struct LineReader {
    lines: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    deadline: Option<Instant>,
    pub timeout: Duration,
}

impl LineReader {
    #[must_use]
    pub fn new(fd: OwnedFd) -> LineReader {
        let (sender, lines) = std::sync::mpsc::channel();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut buf = Vec::new();
            while !stopped.load(std::sync::atomic::Ordering::Acquire) {
                let mut pfd = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one live pollfd; the worker exclusively owns its fd.
                let ready = unsafe { libc::poll(&raw mut pfd, 1, 50) };
                if ready == 0 {
                    continue;
                }
                if ready < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    let _ = sender.send(Err(err));
                    break;
                }
                let mut chunk = [0u8; 8192];
                // SAFETY: live buffer and readable descriptor owned by this worker.
                let n =
                    unsafe { libc::read(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    let _ = sender.send(Err(err));
                    break;
                }
                if n == 0 {
                    if !buf.is_empty() {
                        let _ = sender.send(Ok(buf));
                    }
                    break;
                }
                buf.extend_from_slice(&chunk[..n as usize]);
                while let Some(end) = buf.iter().position(|b| *b == b'\n') {
                    let line = buf.drain(..=end).take(end).collect();
                    if sender.send(Ok(line)).is_err() {
                        return;
                    }
                }
                if buf.len() > 1024 * 1024 {
                    let _ = sender.send(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "channel line exceeds harness bound",
                    )));
                    break;
                }
            }
        });
        LineReader {
            lines,
            stop,
            worker: Some(worker),
            deadline: None,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }

    /// The next complete line without its terminator, or `None` at EOF.
    pub fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        let wait = self.deadline.map_or(self.timeout, |at| {
            at.saturating_duration_since(Instant::now())
                .min(self.timeout)
        });
        match self.lines.recv_timeout(wait) {
            Ok(line) => line.map(Some),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "channel exceeded the harness deadline",
            )),
        }
    }

    /// Everything still readable, up to EOF.
    ///
    /// A timeout does NOT discard what was already read. A jail whose
    /// descendant still holds the inherited channel end never reaches EOF, and
    /// returning `Err` with the lines thrown away turned every
    /// "no `refused` message" assertion into a vacuous pass sixty seconds
    /// late. The caller gets the partial transcript and an explicit flag.
    pub fn drain(&mut self) -> Drained {
        let mut lines = Vec::new();
        loop {
            match self.next_line() {
                Ok(Some(line)) => lines.push(line),
                Ok(None) => return Drained { lines, error: None },
                Err(e) => {
                    return Drained {
                        lines,
                        error: Some(e),
                    };
                }
            }
        }
    }
}

impl Drop for LineReader {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
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
            if n == 0 {
                // A blocking write returning 0 with bytes left would spin
                // forever; report it instead.
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the gate accepted no bytes",
                ));
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
    fn a_drain_that_times_out_keeps_every_line_it_already_read() {
        // The H2 probe: the writer stays open, exactly like a jail whose
        // descendant still holds the inherited channel end.
        let (r, w) = cloexec_pipe().unwrap();
        let mut writer = GateWriter::new(w);
        writer
            .write_all(b"{\"kind\":\"prepared\"}\n{\"kind\":\"settled\"}\n")
            .unwrap();

        let mut reader = LineReader::new(r);
        reader.timeout = Duration::from_millis(150);
        let drained = reader.drain();

        assert!(drained.incomplete(), "the channel never reached EOF");
        assert_eq!(
            drained.error.as_ref().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            drained.lines.len(),
            2,
            "both complete lines must survive the timeout"
        );
        assert_eq!(drained.lines[0], b"{\"kind\":\"prepared\"}");
        assert_eq!(drained.lines[1], b"{\"kind\":\"settled\"}");
        drop(writer);
    }

    #[test]
    fn a_drain_that_reaches_eof_is_complete() {
        let (r, w) = cloexec_pipe().unwrap();
        let mut writer = GateWriter::new(w);
        writer.write_all(b"one\ntwo\n").unwrap();
        writer.close();
        let mut reader = LineReader::new(r);
        reader.timeout = Duration::from_millis(500);
        let drained = reader.drain();
        assert!(!drained.incomplete());
        assert_eq!(drained.lines.len(), 2);
    }

    #[test]
    fn an_empty_writer_close_reads_as_immediate_eof() {
        let (r, w) = cloexec_pipe().unwrap();
        drop(w);
        let mut reader = LineReader::new(r);
        assert_eq!(reader.next_line().unwrap(), None);
    }
}
