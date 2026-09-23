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
use std::time::Duration;

use super::clock::Deadline;
use super::identity::{pidfd_open, pidfd_send_signal};

/// Default start of the source-descriptor range. Large mount plans raise it
/// above their last target, so the child's `dup2` calls cannot overwrite a
/// source, including when there are more than 256 pinned mounts.
const RESERVE_BASE: RawFd = 256;

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
#[derive(Debug)]
pub struct FdMap {
    moves: Vec<(OwnedFd, RawFd)>,
    reserve_base: RawFd,
}

impl Default for FdMap {
    fn default() -> Self {
        Self::with_target_limit(RESERVE_BASE)
    }
}

impl FdMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve enough target slots for this mount plan. Source duplicates live
    /// above every target, so large plans remain collision-free without a fixed
    /// protected-bind cap. Descriptor exhaustion is an error before spawn.
    pub fn with_target_limit(limit: RawFd) -> Self {
        Self {
            moves: Vec::new(),
            reserve_base: limit.max(RESERVE_BASE),
        }
    }

    /// Install `fd` as descriptor `target` in the child.
    ///
    /// Takes ownership: the source is duplicated above the target range if
    /// needed and the original is closed, so the only copies left in the
    /// parent are the ones this map holds.
    ///
    /// # Errors
    ///
    /// The errno from `fcntl`.
    ///
    /// # Panics
    ///
    /// If `target` is negative or outside the configured target range; the reserved
    /// range is what makes the child's `dup2` sequence collision-free.
    pub fn add(&mut self, fd: OwnedFd, target: RawFd) -> io::Result<()> {
        assert!(
            (0..self.reserve_base).contains(&target),
            "target fd {target} must be in 0..{}",
            self.reserve_base
        );
        assert!(
            !self.moves.iter().any(|(_, t)| *t == target),
            "fd {target} assigned twice"
        );
        let raw = fd.as_raw_fd();
        let high = if raw >= self.reserve_base {
            fd
        } else {
            // SAFETY: `raw` is a live descriptor owned by `fd`; F_DUPFD_CLOEXEC
            // returns a new owned descriptor above every target in this map.
            let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, self.reserve_base) };
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
    /// `prctl`, `getppid`, `close_range` and `dup2`, all async-signal-safe.
    ///
    /// It starts by tying the child's life to this process with
    /// `PR_SET_PDEATHSIG` (§8.2), and re-reads the parent pid immediately
    /// afterwards, because the death that signal must catch can happen in the
    /// window between `fork` and the `prctl` itself and is not resent. That
    /// closes the fork-to-exec window.
    ///
    /// It does not close all of it, and the measurement says why. On this host
    /// bubblewrap **clears the inherited parent-death signal**: a child that
    /// arms `SIGKILL` and execs `/usr/bin/sleep` dies with its parent, and the
    /// same child execing `bwrap` — with or without `--unshare-user` — does
    /// not. Bubblewrap arms its own for `--die-with-parent`, which this plan
    /// always passes and which works once it is armed. What remains is the
    /// window inside bubblewrap's startup between clearing ours and arming its
    /// own: a supervisor killed in that instant still leaves an orphan on pid
    /// 1 holding this run's descriptors. The production platform closes that
    /// window with [`super::watch`]'s blocked bootstrap and outside pidfd watcher.
    ///
    /// Then every descriptor above stdio is marked close-on-exec, so nothing
    /// the supervisor happens to hold — the gate, control and trace channels
    /// among them — survives into the child (§8.3). The `dup2` calls clear
    /// that flag on exactly the descriptors this map names. Every source is at
    /// or above the configured reserve base and every target below it, so no `dup2` can
    /// clobber a later source.
    pub fn apply(&self, command: &mut Command) {
        self.apply_with_parent_death(command, true);
    }

    /// Only for the outside lifetime watcher: it must survive its parent long
    /// enough to kill the backend through the inherited pidfd.
    pub(crate) fn apply_watcher(&self, command: &mut Command) {
        self.apply_with_parent_death(command, false);
    }

    fn apply_with_parent_death(&self, command: &mut Command, parent_death: bool) {
        let moves: Vec<(RawFd, RawFd)> = self
            .moves
            .iter()
            .map(|(fd, target)| (fd.as_raw_fd(), *target))
            .collect();
        // SAFETY: getppid cannot fail and is async-signal-safe; the value is
        // read before the fork so the child can compare against it.
        let supervisor = unsafe { libc::getpid() };
        // SAFETY: the closure performs only async-signal-safe calls over a
        // `Vec` of plain integers built before the fork, and constructs an
        // `io::Error` from an errno, which does not allocate.
        unsafe {
            command.pre_exec(move || {
                // SAFETY: PR_SET_PDEATHSIG takes scalars and dereferences
                // nothing.
                if parent_death && libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: getppid takes no arguments and cannot fail.
                if parent_death && libc::getppid() != supervisor {
                    // The supervisor died in the fork window, so the signal
                    // this child just armed will never arrive. Leave before
                    // becoming the orphan that holds the run's descriptors.
                    libc::_exit(EXIT_SUPERVISOR_GONE);
                }
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

/// Exit status of a child that found its supervisor already gone.
///
/// It is never observed through a receipt — the supervisor that would read it
/// is the one that died — but it keeps the reason out of the range an ordinary
/// program uses.
pub const EXIT_SUPERVISOR_GONE: i32 = 123;

/// In the child of a `fork`: die with the process that forked it.
///
/// Arms `PR_SET_PDEATHSIG` and then re-reads the parent pid, because a parent
/// that died between the `fork` and the `prctl` sends no signal; such a child
/// leaves at once instead of becoming an orphan on pid 1. The signal follows
/// the forking *thread*, so the forking thread must outlive the child (every
/// caller kills and reaps its child before returning).
///
/// # Safety
///
/// Call only in the child of a `fork`, first. It calls only `prctl`,
/// `getppid` and `_exit`, which are async-signal-safe; `parent` must be the
/// forking process's pid, read before the fork.
pub unsafe fn die_with_parent_after_fork(parent: libc::pid_t) {
    // SAFETY: prctl and getppid take scalars and dereference nothing; _exit
    // does not return.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0
            || libc::getppid() != parent
        {
            libc::_exit(EXIT_SUPERVISOR_GONE);
        }
    }
}

/// Make `command`'s child die with this process (§14.1: a probe owns its
/// fixtures), closing the fork-to-`prctl` window as
/// [`die_with_parent_after_fork`] does. For children that need no descriptor
/// layout; [`FdMap::apply`] already does this for the ones that do.
pub fn die_with_parent(command: &mut Command) {
    // SAFETY: getpid takes no arguments and cannot fail.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the closure calls only async-signal-safe functions over an
    // integer copied before the fork.
    unsafe {
        command.pre_exec(move || {
            die_with_parent_after_fork(parent);
            Ok(())
        });
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

/// Reap `child` if it ends before `deadline`, without ever blocking on it.
///
/// Every caller has already asked the child to die or knows it is dying, so
/// the wait is bounded; on expiry the child is left to its owner. Not for use
/// while a tracer thread owns this process's `waitpid`.
pub fn reap_until(child: &mut Child, deadline: Deadline) {
    while matches!(child.try_wait(), Ok(None)) && !deadline.expired() {
        std::thread::sleep(REAP_STEP);
    }
}

/// The poll interval of [`reap_until`].
const REAP_STEP: Duration = Duration::from_millis(1);

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
