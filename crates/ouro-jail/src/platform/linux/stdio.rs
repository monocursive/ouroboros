//! Stdio validation and the relays for regular-file and socket streams (§8.3).

use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::Duration;

use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

use super::clock::{self};
use super::exec::{self, FdMap};
use super::platform::error;
use super::sys::set_nonblocking;

/// §8.3 and §9.2: reject directory and anonymous-inode stdio, and
/// regular-file stdio that resolves into protected supervisor state or the
/// operator's trusted config directory (audit 2026-10-08 H1). Every other
/// regular file, and every socket, is relayed through a supervisor-owned
/// pipe; everything else passes through untouched.
///
/// `state_root` is the whole runtime state directory, not just this attempt's
/// own: a redirect into a sibling attempt's receipts is the same disclosure.
/// `config_dir` holds `config.toml` and `launch/`, the trusted widening
/// inputs: a redirect of any of the three streams there would have the
/// supervisor itself copy child bytes into (or out of) files later runs
/// trust, so it refuses like the state root even under the relay.
///
/// The relay (audit 2026-10-08 H1 follow-up) closes the reopen hole: the
/// sandbox has its own `/proc`, and a regular file inherited directly is
/// reopenable through `/dev/stdin` against the inode's permission bits and
/// the host mount — never the descriptor's open mode — which is
/// write-and-truncate authority outside every grant (§9.1's closed view,
/// §6.4's uncharged write). A pipe end is not reopenable at all, so the
/// child never learns the file, its path, or its permissions; the
/// supervisor's copies run on the operator's own descriptor, preserving its
/// open mode and offset.
///
/// A descriptor that cannot be inspected refuses rather than passing, because
/// "I could not tell what this is" is not a reason to hand it to the child.
pub(super) fn validate_stdio(
    state_root: &Path,
    config_dir: &Path,
) -> Result<[StdioPlan; 3], JailError> {
    let state_root = state_root.canonicalize();
    let config_dir = config_dir.canonicalize();
    let mut plans = [StdioPlan::Pass, StdioPlan::Pass, StdioPlan::Pass];
    for fd in [0, 1, 2] {
        let name = match fd {
            0 => "stdin",
            1 => "stdout",
            _ => "stderr",
        };
        let refuse = |message: String| {
            Err(error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                message,
            ))
        };
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `st` is writable storage for a stat buffer; fstat
        // dereferences nothing else.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            let errno = super::sys::last_errno();
            return refuse(format!(
                "{name} cannot be inspected ({}), so what the child would inherit is unknown",
                super::sys::errno_name(errno)
            ));
        }
        // SAFETY: fstat returned 0, so it filled the buffer.
        let kind = unsafe { st.assume_init() }.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            return refuse(format!(
                "{name} is a directory, which a contained run refuses"
            ));
        }
        // A socket is bridged through a supervisor-owned pipe (issue draft
        // 11): socketpairs are how supervisors, systemd units and test
        // harnesses hand a child its stdio, and the pipe keeps the child
        // from using the socket for anything but byte I/O (no recvmsg, no
        // descriptor passing) exactly as for a regular file.
        if kind == libc::S_IFSOCK {
            plans[fd as usize] = StdioPlan::Relay { socket: true };
        }
        // An inherited io_uring ring can issue operations through the ring
        // even when the child's io_uring syscalls are blocked. All Linux
        // anonymous inodes are private supervisor handles, never stdio.
        let fd_target = std::fs::read_link(format!("/proc/self/fd/{fd}")).map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("{name} descriptor target cannot be inspected: {err}"),
            )
        })?;
        if fd_target.as_os_str().as_bytes().starts_with(b"anon_inode:") {
            return refuse(format!(
                "{name} is an anonymous inode and cannot be inherited"
            ));
        }
        if kind == libc::S_IFREG {
            let target = fd_target.canonicalize().unwrap_or(fd_target);
            if let Ok(state_root) = state_root.as_ref()
                && target.starts_with(state_root)
            {
                return refuse(format!("{name} resolves into the runtime state root"));
            }
            if let Ok(config_dir) = config_dir.as_ref()
                && target.starts_with(config_dir)
            {
                return refuse(format!(
                    "{name} resolves into the trusted config directory (config.toml and \
                     launch profiles are trusted input)"
                ));
            }
            plans[fd as usize] = StdioPlan::Relay { socket: false };
        }
    }
    Ok(plans)
}

/// What the child inherits on one stdio stream (audit 2026-10-08 H1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StdioPlan {
    /// Passed through untouched: a tty, a pipe, `/dev/null`.
    Pass,
    /// A regular file or socket, relayed through a supervisor-owned pipe.
    Relay { socket: bool },
}

/// One relayed stdio stream (audit 2026-10-08 H1 follow-up): the child holds
/// one end of a supervisor-owned pipe; the supervisor copies between the
/// pipe and the operator's original descriptor, which keeps its open mode
/// and offset. The child never owns a reopenable handle on the file.
pub(super) struct StdioRelay {
    /// A duplicate of the operator's original descriptor, taken at spawn:
    /// the supervisor later points its own stdout elsewhere (§8.3,
    /// revision 19), and the relay must keep copying into what the
    /// operator actually opened.
    pub(super) origin: OwnedFd,
    /// Sockets use per-call nonblocking I/O without changing the shared
    /// descriptor's flags.
    pub(super) origin_socket: bool,
    /// This side of the pipe, non-blocking; `None` once closed.
    pub(super) ours: Option<OwnedFd>,
    /// `true` for stdin (origin → child); `false` for stdout/stderr
    /// (child → origin).
    pub(super) to_child: bool,
    /// Staged bytes between the two sides, bounded by [`RELAY_BUFFER`].
    pub(super) buffer: Vec<u8>,
    /// The origin reached end-of-file (stdin direction).
    pub(super) origin_eof: bool,
    /// The child's side closed (output directions), or the child's end was
    /// delivered (stdin direction): nothing more to move.
    pub(super) finished: bool,
}

/// The staging bound per relayed stream: one pipe capacity, so a slow
/// consumer never grows supervisor memory.
pub(super) const RELAY_BUFFER: usize = 1 << 16;

impl StdioRelay {
    /// Create the pipe for one stream and hand the child its end through the
    /// fixed descriptor map. The operator's descriptor is
    /// duplicated immediately, before the supervisor redirects its own
    /// copies (§8.3, revision 19).
    pub(super) fn attach(
        fd: RawFd,
        to_child: bool,
        socket: bool,
        descriptors: &mut FdMap,
    ) -> Result<Self, JailError> {
        let (read_end, write_end) = exec::pipe().map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("a stdio stream could not be relayed through a pipe: {err}"),
            )
        })?;
        let (child_end, ours) = if to_child {
            (read_end, write_end)
        } else {
            (write_end, read_end)
        };
        // SAFETY: dup returns a newly owned descriptor, or -1 on failure
        // which is checked before it is owned.
        let duped = unsafe { libc::dup(fd) };
        if duped < 0 {
            return Err(error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                "the operator's stdio descriptor could not be kept for the relay".to_owned(),
            ));
        }
        // SAFETY: `duped` was just created and is owned here.
        let origin = unsafe { OwnedFd::from_raw_fd(duped) };
        descriptors.add(child_end, fd).map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("a stdio relay descriptor could not be mapped: {err}"),
            )
        })?;
        set_nonblocking(ours.as_fd()).map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("a stdio relay pipe could not be made non-blocking: {err}"),
            )
        })?;
        Ok(Self {
            origin,
            origin_socket: socket,
            ours: Some(ours),
            to_child,
            buffer: Vec::with_capacity(RELAY_BUFFER),
            origin_eof: false,
            finished: false,
        })
    }

    /// Move as much as both sides accept right now. Returns `true` while
    /// progress was made, so the caller can shorten its sleep. Regular-file
    /// reads and writes block until complete, so each call is bounded by the
    /// buffer; pipe and socket operations are non-blocking.
    pub(super) fn pump(&mut self) -> std::io::Result<bool> {
        let mut progress = false;
        if self.to_child {
            while !self.origin_eof && self.buffer.len() < RELAY_BUFFER {
                if !origin_ready(self.origin.as_fd(), true) {
                    // A socket origin never blocks the pump loop (issue
                    // draft 11); a regular file is always ready.
                    break;
                }
                let mut chunk = [0u8; RELAY_BUFFER];
                let read = match relay_read(
                    self.origin.as_raw_fd(),
                    &mut chunk[..RELAY_BUFFER - self.buffer.len()],
                    self.origin_socket,
                ) {
                    Ok(read) => read,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err),
                };
                if read == 0 {
                    self.origin_eof = true;
                    break;
                }
                self.buffer.extend_from_slice(&chunk[..read]);
                progress = true;
            }
            if !self.buffer.is_empty()
                && let Some(ours) = self.ours.as_ref()
            {
                match relay_write(ours.as_raw_fd(), &self.buffer, false) {
                    Ok(written) => {
                        self.buffer.drain(..written);
                        progress = true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {
                        // A child may legitimately stop consuming stdin.
                        self.buffer.clear();
                        self.origin_eof = true;
                    }
                    Err(err) => return Err(err),
                }
            }
            if self.origin_eof && self.buffer.is_empty() {
                // Closing this side gives the child its end-of-file.
                self.ours = None;
                self.finished = true;
            }
        } else {
            while let Some(ours) = self.ours.as_ref() {
                if self.buffer.len() >= RELAY_BUFFER {
                    break;
                }
                let mut chunk = [0u8; RELAY_BUFFER];
                let read = match relay_read(
                    ours.as_raw_fd(),
                    &mut chunk[..RELAY_BUFFER - self.buffer.len()],
                    false,
                ) {
                    Ok(read) => read,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err),
                };
                if read > 0 {
                    self.buffer.extend_from_slice(&chunk[..read]);
                    progress = true;
                } else {
                    self.ours = None;
                    self.finished = true;
                    break;
                }
            }
            if !self.buffer.is_empty() && origin_ready(self.origin.as_fd(), false) {
                match relay_write(self.origin.as_raw_fd(), &self.buffer, self.origin_socket) {
                    Ok(written) => {
                        self.buffer.drain(..written);
                        progress = true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(progress)
    }

    /// Whether both sides are done and nothing is staged.
    pub(super) fn done(&self) -> bool {
        self.finished && self.buffer.is_empty()
    }
}

/// Whether a relay origin is ready to read (`for_read`) or write right now,
/// asked with a zero-timeout poll so a socket origin never blocks the pump
/// loop (issue draft 11). A regular file is always ready; a socket that
/// would block is simply visited again on a later pump.
pub(super) fn origin_ready(fd: BorrowedFd<'_>, for_read: bool) -> bool {
    let events = if for_read {
        libc::POLLIN
    } else {
        libc::POLLOUT
    };
    super::sys::poll_one(fd, events, 0).is_ok_and(|revents| {
        revents & (libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0
    })
}

pub(super) fn relay_read(fd: RawFd, buffer: &mut [u8], socket: bool) -> std::io::Result<usize> {
    loop {
        // SAFETY: read writes only into this live writable slice.
        let read = unsafe {
            if socket {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            } else {
                libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len())
            }
        };
        if read >= 0 {
            return Ok(read as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

pub(super) fn relay_write(fd: RawFd, buffer: &[u8], socket: bool) -> std::io::Result<usize> {
    loop {
        // SAFETY: write reads only from this live slice.
        let written = unsafe {
            if socket {
                libc::send(
                    fd,
                    buffer.as_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            } else {
                libc::write(fd, buffer.as_ptr().cast(), buffer.len())
            }
        };
        if written > 0 {
            return Ok(written as usize);
        }
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// How long relayed output gets, once the target has ended, to reach the
/// operator's descriptors before the outcome is recorded.
pub(super) const OUTPUT_DRAIN_BUDGET: Duration = Duration::from_millis(250);

/// Delivers what the child wrote through the output relays, within
/// `budget`. Only output relays are waited for: a stdin relay finishes only
/// at its origin's end-of-file or a broken pipe, which the target's end does
/// not bring, so waiting for it would spend the whole budget on nothing. A
/// pass that moves nothing waits in `poll` for a relay to have something to
/// move, rather than spin.
pub(super) fn drain_output_relays(
    relays: &mut [StdioRelay],
    budget: Duration,
) -> std::io::Result<()> {
    let deadline = clock::Deadline::after(budget);
    loop {
        let progress = pump_stdio_relays(relays)?;
        let mut waits = output_waits(relays);
        if waits.is_empty() || deadline.expired() {
            return Ok(());
        }
        if !progress {
            match super::sys::poll(&mut waits, deadline.remaining_millis_capped(i32::MAX)) {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
    }
}

/// What an unfinished output relay waits for: its pipe to be readable while
/// there is room to stage, and its origin to be writable while bytes are
/// staged. A closed pipe end reports `POLLHUP`, which wakes the wait too.
fn output_waits(relays: &[StdioRelay]) -> Vec<libc::pollfd> {
    let mut waits = Vec::new();
    for relay in relays
        .iter()
        .filter(|relay| !relay.to_child && !relay.done())
    {
        if let Some(ours) = relay.ours.as_ref()
            && relay.buffer.len() < RELAY_BUFFER
        {
            waits.push(libc::pollfd {
                fd: ours.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if !relay.buffer.is_empty() {
            waits.push(libc::pollfd {
                fd: relay.origin.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
        }
    }
    waits
}

/// Visit every stream, including when an earlier stream made progress.
pub(super) fn pump_stdio_relays(relays: &mut [StdioRelay]) -> std::io::Result<bool> {
    let mut progress = false;
    let mut failure = None;
    for relay in relays {
        match relay.pump() {
            Ok(active) => progress |= active,
            Err(err) => {
                failure.get_or_insert(err);
            }
        }
    }
    failure.map_or(Ok(progress), Err)
}

#[cfg(test)]
mod tests {
    fn output_relay(origin: std::fs::File) -> (super::StdioRelay, std::os::fd::OwnedFd) {
        let (ours, child) = super::exec::pipe().unwrap();
        use std::os::fd::AsFd as _;
        super::set_nonblocking(ours.as_fd()).unwrap();
        (
            super::StdioRelay {
                origin: origin.into(),
                origin_socket: false,
                ours: Some(ours),
                to_child: false,
                buffer: Vec::new(),
                origin_eof: false,
                finished: false,
            },
            child,
        )
    }

    #[test]
    fn blocking_socket_output_retains_backpressure_without_blocking_the_relay() {
        use std::io::Read as _;
        use std::os::fd::{AsRawFd as _, OwnedFd};
        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: a live socket and a correctly sized, initialized option.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const size).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        let (mut relay, writer) = output_relay(std::fs::File::from(OwnedFd::from(socket)));
        relay.origin_socket = true;
        relay.buffer = vec![b'x'; super::RELAY_BUFFER];
        drop(writer);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            tx.send((relay.pump(), relay)).unwrap();
        });
        let (result, mut relay) = match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(result) => result,
            Err(error) => {
                drop(peer);
                worker.join().unwrap();
                panic!("a socket write must not block supervision: {error}");
            }
        };
        worker.join().unwrap();
        assert!(result.unwrap());
        assert!(
            !relay.buffer.is_empty(),
            "backpressure retains undelivered output"
        );
        // SAFETY: querying flags on the live origin descriptor.
        let flags = unsafe { libc::fcntl(relay.origin.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            flags & libc::O_NONBLOCK,
            0,
            "shared origin flags stay unchanged"
        );
        peer.set_nonblocking(true).unwrap();
        let mut delivered = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while delivered.len() < super::RELAY_BUFFER {
            let mut chunk = [0u8; 8192];
            match peer.read(&mut chunk) {
                Ok(read) => delivered.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("socket delivery failed: {error}"),
            }
            relay.pump().unwrap();
            assert!(std::time::Instant::now() < deadline, "output did not drain");
        }
        assert_eq!(delivered, vec![b'x'; super::RELAY_BUFFER]);
        assert!(relay.done());
    }

    #[test]
    fn relay_batch_services_stderr_while_stdout_is_active() {
        use std::io::{Read as _, Seek as _};
        use std::os::fd::AsRawFd as _;
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let (out, out_writer) = output_relay(stdout.try_clone().unwrap());
        let (err, err_writer) = output_relay(stderr.try_clone().unwrap());
        super::relay_write(out_writer.as_raw_fd(), b"stdout remains active", false).unwrap();
        super::relay_write(err_writer.as_raw_fd(), b"stderr must arrive now", false).unwrap();
        let mut relays = [out, err];
        assert!(super::pump_stdio_relays(&mut relays).unwrap());
        let mut text = String::new();
        stderr.rewind().unwrap();
        stderr.read_to_string(&mut text).unwrap();
        assert_eq!(text, "stderr must arrive now");
        text.clear();
        stdout.rewind().unwrap();
        stdout.read_to_string(&mut text).unwrap();
        assert_eq!(text, "stdout remains active");
    }

    #[test]
    fn the_output_drain_waits_for_output_only() {
        use std::io::{Read as _, Seek as _};
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let mut stdout = tempfile::tempfile().unwrap();
        let (out, writer) = output_relay(stdout.try_clone().unwrap());
        super::relay_write(writer.as_raw_fd(), b"last words", false).unwrap();
        drop(writer);
        // A stdin origin that never reaches end-of-file while its peer lives.
        let (origin, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (child_end, ours) = super::exec::pipe().unwrap();
        super::set_nonblocking(ours.as_fd()).unwrap();
        let stdin = super::StdioRelay {
            origin: origin.into(),
            origin_socket: true,
            ours: Some(ours),
            to_child: true,
            buffer: Vec::new(),
            origin_eof: false,
            finished: false,
        };
        let mut relays = [out, stdin];
        let started = std::time::Instant::now();
        super::drain_output_relays(&mut relays, std::time::Duration::from_secs(5)).unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the drain waited for a stdin relay the target's end cannot finish"
        );
        assert!(relays[0].done());
        assert!(!relays[1].done(), "stdin stays open, unwaited for");
        let mut text = String::new();
        stdout.rewind().unwrap();
        stdout.read_to_string(&mut text).unwrap();
        assert_eq!(text, "last words");
        drop(child_end);
    }

    /// The drain waits on the relays themselves: output written while it
    /// waits, and then the writer's close, each end the wait at once rather
    /// than at the budget.
    #[test]
    fn the_output_drain_wakes_for_late_output_and_the_close() {
        use std::io::{Read as _, Seek as _};
        use std::os::fd::AsRawFd as _;
        let mut stdout = tempfile::tempfile().unwrap();
        let (out, writer) = output_relay(stdout.try_clone().unwrap());
        let late = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            super::relay_write(writer.as_raw_fd(), b"late words", false).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(writer);
        });
        let mut relays = [out];
        let started = std::time::Instant::now();
        super::drain_output_relays(&mut relays, std::time::Duration::from_secs(10)).unwrap();
        let spent = started.elapsed();
        late.join().unwrap();
        assert!(
            spent < std::time::Duration::from_secs(5),
            "the drain did not wake for the writer's close ({spent:?})"
        );
        assert!(relays[0].done());
        let mut text = String::new();
        stdout.rewind().unwrap();
        stdout.read_to_string(&mut text).unwrap();
        assert_eq!(text, "late words");
    }

    #[test]
    fn relay_output_errors_preserve_undelivered_bytes() {
        use std::os::fd::AsRawFd as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-only");
        std::fs::write(&path, b"original").unwrap();
        let (mut relay, writer) = output_relay(std::fs::File::open(&path).unwrap());
        super::relay_write(writer.as_raw_fd(), b"undelivered", false).unwrap();
        drop(writer);
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(relay.buffer, b"undelivered");
        assert!(!relay.done());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        let (mut relay, writer) = output_relay(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        );
        super::relay_write(writer.as_raw_fd(), b"disk full", false).unwrap();
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(relay.buffer, b"disk full");
    }

    #[test]
    fn relay_input_errors_are_not_eof() {
        use std::os::fd::AsFd as _;
        let dir = tempfile::tempdir().unwrap();
        let origin = std::fs::File::create(dir.path().join("write-only")).unwrap();
        let (read, write) = super::exec::pipe().unwrap();
        super::set_nonblocking(write.as_fd()).unwrap();
        let mut relay = super::StdioRelay {
            origin: origin.into(),
            origin_socket: false,
            ours: Some(write),
            to_child: true,
            buffer: Vec::new(),
            origin_eof: false,
            finished: false,
        };
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert!(!relay.origin_eof);
        drop(read);
    }
}
