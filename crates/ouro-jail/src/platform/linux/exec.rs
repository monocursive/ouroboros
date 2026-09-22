//! Spawning with a chosen file-descriptor layout, and waiting with a deadline.
//!
//! jail-v1 §8.3: everything but validated stdio closes before exec, and the
//! descriptors that must survive get fixed numbers the inside launcher is told
//! about by number. The work after `fork` is three `dup2` calls, which are
//! async-signal-safe; nothing else runs in that window.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};

use super::clock::Deadline;
use super::identity::{pidfd_open, pidfd_send_signal};

/// Descriptors the parent holds are first duplicated above this number, so
/// that the `dup2` calls in the child can never overwrite a source.
const RESERVE_BASE: RawFd = 20;

/// A pipe with both ends close-on-exec.
///
/// # Errors
///
/// The errno from `pipe2`.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1i32; 2];
    // SAFETY: `fds` is a two-element array of the right type; pipe2 writes
    // exactly two descriptors into it or returns -1.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Descriptors to install at fixed numbers in a child.
///
/// The map owns its sources, so they stay open until it is dropped; the caller
/// keeps it alive across `spawn` and drops it afterwards to give the child's
/// peer its EOF.
#[derive(Debug, Default)]
pub struct FdMap {
    moves: Vec<(OwnedFd, RawFd)>,
}

impl FdMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install `fd` as descriptor `target` in the child.
    ///
    /// Takes ownership: the source is duplicated above [`RESERVE_BASE`] if
    /// needed and the original is closed, so the only copies left in the
    /// parent are the ones this map holds.
    ///
    /// # Errors
    ///
    /// The errno from `fcntl`.
    ///
    /// # Panics
    ///
    /// If `target` is negative or not below [`RESERVE_BASE`]; the reserved
    /// range is what makes the child's `dup2` sequence collision-free.
    pub fn add(&mut self, fd: OwnedFd, target: RawFd) -> io::Result<()> {
        assert!(
            (0..RESERVE_BASE).contains(&target),
            "target fd {target} must be in 0..{RESERVE_BASE}"
        );
        assert!(
            !self.moves.iter().any(|(_, t)| *t == target),
            "fd {target} assigned twice"
        );
        let raw = fd.as_raw_fd();
        let high = if raw >= RESERVE_BASE {
            fd
        } else {
            // SAFETY: `raw` is a live descriptor owned by `fd`; F_DUPFD_CLOEXEC
            // returns a new owned descriptor at or above RESERVE_BASE.
            let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, RESERVE_BASE) };
            if dup < 0 {
                return Err(io::Error::last_os_error());
            }
            drop(fd);
            // SAFETY: `dup` was just created by fcntl and is owned here.
            unsafe { OwnedFd::from_raw_fd(dup) }
        };
        self.moves.push((high, target));
        Ok(())
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.moves.is_empty()
    }

    /// Arrange for this layout to be installed in `command`'s child.
    ///
    /// The closure runs after `fork` and before `exec` and calls nothing but
    /// `close_range` and `dup2`, both async-signal-safe. Every descriptor
    /// above stdio is first marked close-on-exec, so nothing the supervisor
    /// happens to hold — the gate, control and trace channels among them —
    /// survives into the child (§8.3). The `dup2` calls then clear that flag
    /// on exactly the descriptors this map names. Every source is at or above
    /// [`RESERVE_BASE`] and every target below it, so no `dup2` can clobber a
    /// later source.
    pub fn apply(&self, command: &mut Command) {
        let moves: Vec<(RawFd, RawFd)> = self
            .moves
            .iter()
            .map(|(fd, target)| (fd.as_raw_fd(), *target))
            .collect();
        // SAFETY: the closure performs only `close_range` and `dup2` over a
        // `Vec` of plain integers built before the fork, and constructs an
        // `io::Error` from an errno, which does not allocate.
        unsafe {
            command.pre_exec(move || {
                close_range_cloexec()?;
                for (source, target) in &moves {
                    if libc::dup2(*source, *target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
}

/// `CLOSE_RANGE_CLOEXEC` from `linux/close_range.h`.
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;

/// Mark every descriptor above stdio close-on-exec.
///
/// Async-signal-safe: one syscall, no allocation. Used between `fork` and
/// `exec` so that only the descriptors the caller re-installs with `dup2`
/// reach the child.
fn close_range_cloexec() -> io::Result<()> {
    // SAFETY: close_range takes three scalars and dereferences nothing.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3,
            libc::c_uint::MAX,
            CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// How a waited-for process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The process exited on its own before the deadline.
    Exited,
    /// The deadline passed first and the process was killed.
    TimedOut,
}

/// Wait for `pid` until `deadline`, using a pidfd so that a reused pid cannot
/// be mistaken for the one being waited on.
///
/// # Errors
///
/// The errno from `pidfd_open` or `poll`.
pub fn wait_until(pid: libc::pid_t, deadline: Deadline) -> io::Result<WaitOutcome> {
    let pidfd = pidfd_open(pid)?;
    loop {
        let timeout = deadline.remaining_millis_capped(i32::MAX);
        let mut poll_fd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll_fd` is one live pollfd and the count matches.
        let rc = unsafe { libc::poll(&raw mut poll_fd, 1, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Ok(WaitOutcome::TimedOut);
        }
        return Ok(WaitOutcome::Exited);
    }
}

/// What a bounded run produced.
#[derive(Debug)]
pub struct Captured {
    /// The process's exit status.
    pub status: ExitStatus,
    /// Standard output, lossily decoded.
    pub stdout: String,
    /// Standard error, lossily decoded.
    pub stderr: String,
    /// Whether the deadline, rather than the process, ended the run.
    pub timed_out: bool,
}

impl Captured {
    /// The exit code, or `None` when a signal ended the process.
    #[must_use]
    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }

    /// Value of a `key=value` line in the captured stdout.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&str> {
        self.stdout
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
    }
}

/// Run `command` with its output captured and a hard deadline.
///
/// On expiry the process is killed through its pidfd, so the signal cannot
/// land on a pid the kernel has already reused.
///
/// # Errors
///
/// A failure to spawn, poll or reap.
pub fn run_captured(command: &mut Command, deadline: Deadline) -> io::Result<Captured> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn()?;
    finish_captured(child, deadline)
}

/// Wait for an already-spawned child with a deadline and capture its output.
///
/// # Errors
///
/// A failure to poll or reap.
pub fn finish_captured(child: Child, deadline: Deadline) -> io::Result<Captured> {
    let pid =
        libc::pid_t::try_from(child.id()).map_err(|_| io::Error::other("pid out of range"))?;
    let pidfd = pidfd_open(pid)?;
    let outcome = wait_until(pid, deadline)?;
    let timed_out = outcome == WaitOutcome::TimedOut;
    if timed_out {
        // Ignore the error: the process may have exited between the poll
        // timing out and this call, which is not a failure of the run.
        let _ = pidfd_send_signal(pidfd.as_raw_fd(), libc::SIGKILL);
    }
    let output = child.wait_with_output()?;
    Ok(Captured {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        timed_out,
    })
}
