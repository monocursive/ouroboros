//! Spawning with a chosen file-descriptor layout, and waiting with a deadline.
//!
//! jail-v1 §8.3: everything but validated stdio closes before exec, and the
//! descriptors that must survive get fixed numbers the inside launcher is told
//! about by number. The work after `fork` is `prctl`, `getppid`,
//! `close_range` and one `dup2` per mapped descriptor, all async-signal-safe;
//! nothing else runs in that window.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use super::clock::Deadline;
use super::identity::{pidfd_open, pidfd_send_signal};

mod bootstrap;
pub(crate) use bootstrap::{BootstrapChild, BootstrapSpawn, KillOnDrop, spawn_bootstrap};

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
        let high = self.reserve(fd)?;
        self.moves.push((high, target));
        Ok(())
    }

    /// Keep an internal spawn descriptor above every mapped target. It stays
    /// close-on-exec and is never added to the child's surviving layout.
    fn reserve(&self, fd: OwnedFd) -> io::Result<OwnedFd> {
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
        Ok(high)
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
    /// window with [`super::watch`]'s blocked bootstrap and outside pidfd
    /// watcher, fully only where the attempt has an execution cgroup the
    /// watcher can kill (jail-v1 §9.3).
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
        // SAFETY: getpid takes no arguments and cannot fail; the value is
        // read before the fork so the child can compare its getppid with it.
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
/// A failure to spawn, poll, read or reap.
pub fn run_captured(command: &mut Command, deadline: Deadline) -> io::Result<Captured> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn()?;
    finish_captured(child, deadline)
}

/// After a timeout kill, how long the pipes are still read for what the
/// process wrote before it died; a descendant that holds them open cannot
/// stretch the run past this.
const CAPTURE_TAIL: Duration = Duration::from_millis(100);

/// Wait for an already-spawned child with a deadline and capture its output.
///
/// Its pipes are read while it runs: a child that writes more than a pipe
/// holds blocks until someone reads, so waiting for its exit first would
/// turn every large output into a timeout. After the exit they are read to
/// end-of-file, or until the deadline when a descendant still holds them.
///
/// # Errors
///
/// A failure to poll, read or reap.
pub fn finish_captured(mut child: Child, deadline: Deadline) -> io::Result<Captured> {
    let pid =
        libc::pid_t::try_from(child.id()).map_err(|_| io::Error::other("pid out of range"))?;
    let pidfd = pidfd_open(pid)?;
    let mut pipes = [
        CapturePipe::new(child.stdout.take().map(OwnedFd::from)),
        CapturePipe::new(child.stderr.take().map(OwnedFd::from)),
    ];
    let mut exited = false;
    while !(exited && pipes.iter().all(CapturePipe::is_closed)) && !deadline.expired() {
        let timeout = deadline.remaining_millis_capped(i32::MAX);
        exited |= capture_step(&pidfd, exited, &mut pipes, timeout)?.0;
    }
    let timed_out = !exited;
    if timed_out {
        // Ignore the error: the process may have exited between the last
        // poll and this call, which is not a failure of the run.
        let _ = pidfd_send_signal(pidfd.as_raw_fd(), libc::SIGKILL);
    }
    let status = child.wait()?;
    let tail = Deadline::after(CAPTURE_TAIL);
    while !pipes.iter().all(CapturePipe::is_closed)
        && !tail.expired()
        && capture_step(&pidfd, true, &mut pipes, 0)?.1
    {}
    let [stdout, stderr] = pipes;
    Ok(Captured {
        status,
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        timed_out,
    })
}

/// One captured pipe: open until it reads end-of-file.
struct CapturePipe {
    file: Option<std::fs::File>,
    bytes: Vec<u8>,
}

impl CapturePipe {
    fn new(pipe: Option<OwnedFd>) -> Self {
        Self {
            file: pipe.map(std::fs::File::from),
            bytes: Vec::new(),
        }
    }

    fn is_closed(&self) -> bool {
        self.file.is_none()
    }

    /// One read, after `poll` said the pipe is readable or hung up, so it
    /// does not block; end-of-file closes the pipe.
    fn read_ready(&mut self) -> io::Result<()> {
        use std::io::Read as _;
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        let mut buffer = [0u8; 16384];
        match file.read(&mut buffer) {
            Ok(0) => self.file = None,
            Ok(read) => self.bytes.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

/// One `poll` of the open pipes and, until the process has `exited`, its
/// pidfd, then one read of each pipe that is ready. Returns whether the
/// process has now exited and whether any pipe was ready.
fn capture_step(
    pidfd: &OwnedFd,
    exited: bool,
    pipes: &mut [CapturePipe; 2],
    timeout_ms: i32,
) -> io::Result<(bool, bool)> {
    let ready = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
    let mut fds = Vec::with_capacity(3);
    for pipe in pipes.iter() {
        if let Some(file) = &pipe.file {
            fds.push(libc::pollfd {
                fd: file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
    }
    if !exited {
        fds.push(libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    let count = libc::nfds_t::try_from(fds.len()).unwrap_or(0);
    // SAFETY: `fds` holds `count` initialized pollfds and outlives the call.
    if unsafe { libc::poll(fds.as_mut_ptr(), count, timeout_ms) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok((exited, false));
        }
        return Err(error);
    }
    let mut any_ready = false;
    let mut polled = fds.iter();
    for pipe in pipes.iter_mut() {
        if pipe.file.is_some() && polled.next().is_some_and(|fd| fd.revents & ready != 0) {
            any_ready = true;
            pipe.read_ready()?;
        }
    }
    let now_exited = exited || polled.next().is_some_and(|fd| fd.revents & ready != 0);
    Ok((now_exited, any_ready))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child that writes more than a pipe holds finishes on its own: the
    /// output is read while it runs, not after an exit it cannot reach.
    /// Several MiB, beyond the largest pipe a host allows by default
    /// (`/proc/sys/fs/pipe-max-size`, 1 MiB).
    #[test]
    fn output_beyond_a_pipe_capacity_is_captured_whole_and_in_time() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "yes | head -c 4194304; yes | head -c 2097152 >&2"]);
        let captured =
            run_captured(&mut command, Deadline::after(Duration::from_secs(20))).unwrap();
        assert!(!captured.timed_out, "a large writer was reported timed out");
        assert!(captured.status.success());
        assert_eq!(captured.stdout.len(), 4_194_304);
        assert_eq!(captured.stderr.len(), 2_097_152);
    }

    #[test]
    fn a_process_past_its_deadline_is_killed_and_reported_timed_out() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "echo started; exec sleep 30"]);
        let started = std::time::Instant::now();
        let captured =
            run_captured(&mut command, Deadline::after(Duration::from_millis(300))).unwrap();
        assert!(captured.timed_out);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(captured.status.code(), None, "ended by the kill");
        assert_eq!(captured.stdout, "started\n");
    }
}
