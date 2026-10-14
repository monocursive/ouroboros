//! Close bubblewrap's startup parent-death window with an outside pidfd watcher.
//!
//! The backend first re-execs a trusted bootstrap, which retains PDEATHSIG and
//! blocks on a private pipe. Only after a watcher owns both pidfds and confirms
//! readiness can the bootstrap exec bubblewrap. The watcher inherits no stdio or
//! policy/evidence descriptors and stays outside the execution cgroup. If the
//! watcher dies, the live supervisor stops the boundary; if the supervisor dies,
//! the watcher kills the whole execution cgroup through the leaf's
//! `cgroup.kill` when the attempt has one, then the backend through its pidfd.
//! Without a leaf only the backend can be killed, and a namespace init still
//! waiting on bubblewrap's startup event outlives it (jail-v1 §9.3 limit).
//!
//! The supervisor releases the watcher (one byte on a private pipe) as soon as
//! it sees the backend's end, which also proves the supervisor was alive
//! then. The supervisor's death shows as its pidfd or as end-of-file on that
//! pipe. The backend's end without a release starts a short grace instead of
//! an exit: bubblewrap's parent-death signal follows the supervisor *thread*
//! that started it, which can die before the rest of a dying supervisor, so
//! bubblewrap can end while the supervisor still looks alive (measured with an
//! instrumented watcher). A supervisor still alive when the grace ends owns
//! what is left, and the watcher leaves. The observer does not wait for the
//! watcher: the supervisor reaps it itself once the observer is done.
//!
//! Killing only the backend is not enough (measured 2026-09-23):
//! bubblewrap's namespace init arms its own parent-death signal late in its
//! startup and before that waits on an eventfd only the outer process writes,
//! so an outer process killed in that window left the init alive on pid 1.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::{clock::Deadline, exec, identity};

// The descriptors each helper inherits, at fixed numbers on both sides.
/// Where the bootstrap receives the read end of its start pipe: one
/// [`RELEASED`] byte lets it exec the backend, anything else ends it.
pub const START_FD: RawFd = super::fds::START;
/// Pinned backend, closed atomically on successful exec.
pub const BACKEND_FD: RawFd = super::fds::BACKEND;
/// Where the watcher receives a pidfd of the supervisor that started it.
const SUPERVISOR_PIDFD_FD: RawFd = super::fds::WATCHER_SUPERVISOR;
/// Where the watcher receives a pidfd of the backend it guards.
const BACKEND_PIDFD_FD: RawFd = super::fds::WATCHER_BACKEND;
/// Where the watcher receives the write end of its ready pipe, on which it
/// writes [`RELEASED`] once it holds everything it needs.
const READY_FD: RawFd = super::fds::WATCHER_READY;
/// Where the watcher receives the leaf's `cgroup.kill`, when there is a leaf.
pub const CGROUP_KILL_FD: RawFd = super::fds::WATCHER_CGROUP_KILL;
const CGROUP_KILL_ARG: &str = "--cgroup-kill-fd";
/// Where the watcher receives the read end of its release pipe.
pub const RELEASE_FD: RawFd = super::fds::WATCHER_RELEASE;
const RELEASE_ARG: &str = "--release-fd";
/// The byte that releases the reader of a release, ready or start pipe;
/// end-of-file means the writer is gone.
pub const RELEASED: u8 = 1;
/// How long the watcher waits, after the backend ended unreleased, for a
/// dying supervisor's death to show. A supervisor killed with SIGKILL exits
/// within this on the reference host under load; a live one releases the
/// watcher within one loop step.
const UNRELEASED_GRACE: Duration = Duration::from_millis(500);

pub struct Watcher {
    child: Child,
    fd: OwnedFd,
    /// The release pipe's write end; dropping it unreleased means "kill".
    release: Option<OwnedFd>,
}

impl Watcher {
    /// `cgroup_kill` is the execution leaf's `cgroup.kill`
    /// ([`super::cgroup::ExecutionCgroup::kill_handle`]); the backend must
    /// already be placed in that leaf.
    pub fn start(
        exe: &Path,
        backend: i32,
        cgroup_kill: Option<OwnedFd>,
        deadline: Deadline,
    ) -> io::Result<Self> {
        // SAFETY: getpid takes no arguments and cannot fail.
        let supervisor = identity::pidfd_open(unsafe { libc::getpid() })?;
        let backend = identity::pidfd_open(backend)?;
        let (ready_r, ready_w) = exec::pipe()?;
        let (release_r, release_w) = exec::pipe()?;
        let mut fds = exec::FdMap::new();
        fds.add(supervisor, SUPERVISOR_PIDFD_FD)?;
        fds.add(backend, BACKEND_PIDFD_FD)?;
        fds.add(ready_w, READY_FD)?;
        fds.add(release_r, RELEASE_FD)?;
        let mut command = Command::new(exe);
        command
            .arg("__watch")
            .arg(RELEASE_ARG)
            .arg(RELEASE_FD.to_string());
        if let Some(kill) = cgroup_kill {
            fds.add(kill, CGROUP_KILL_FD)?;
            command.arg(CGROUP_KILL_ARG).arg(CGROUP_KILL_FD.to_string());
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        fds.apply_watcher(&mut command);
        let mut child = command.spawn()?;
        drop(fds);
        let result = (|| {
            let fd = identity::pidfd_open(child.id() as i32)?;
            if !read_release(ready_r.as_fd(), deadline) {
                // A wait the deadline ended is a timeout, which the caller
                // reports as the preparation budget's, not as a host failure.
                let kind = if deadline.expired() {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::Other
                };
                return Err(io::Error::new(
                    kind,
                    "lifetime watcher did not become ready",
                ));
            }
            Ok(fd)
        })();
        match result {
            Ok(fd) => Ok(Self {
                child,
                fd,
                release: Some(release_w),
            }),
            Err(err) => {
                let _ = child.kill();
                exec::reap_until(&mut child, deadline);
                Err(err)
            }
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn ended(&self) -> bool {
        is_readable(self.fd.as_fd())
    }
    pub fn reap(&mut self) {
        let _ = self.child.try_wait();
    }
    /// Let the watcher leave without killing anything. Only once the backend
    /// has ended: until then, the watcher is what ends the tree if this
    /// supervisor dies. Idempotent.
    pub fn release(&mut self) {
        if let Some(fd) = self.release.take() {
            // SAFETY: a one-byte write from a live byte to an owned pipe; if
            // it fails, dropping the pipe below still ends the watcher (it
            // then kills the leaf, which is normally empty once the backend has ended).
            unsafe { libc::write(fd.as_raw_fd(), [RELEASED].as_ptr().cast(), 1) };
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // Normal settlement has released and reaped it. Otherwise closing the
        // release pipe unreleased makes it kill the leaf and the backend,
        // which is what an early preparation error needs too.
        drop(self.release.take());
        exec::reap_until(&mut self.child, Deadline::after(Duration::from_millis(100)));
    }
}

/// Whether `fd` has something to read now. A pidfd is readable on process
/// exit, including while its zombie is waiting for this supervisor's tracer
/// thread to reap it. Only `POLLIN` says so: an invalid descriptor
/// (`POLLNVAL`) or an error is not an exit.
pub fn is_readable(fd: BorrowedFd<'_>) -> bool {
    super::sys::poll_one(fd, libc::POLLIN, 0).is_ok_and(|revents| revents & libc::POLLIN != 0)
}

/// [`is_readable`] for a caller that holds only the descriptor's number.
/// `poll` takes the number as it is: one that is not open answers
/// `POLLNVAL`, which is not readable, and one that names another object
/// answers for that object.
pub fn readable(fd: RawFd) -> bool {
    let mut waits = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    super::sys::poll_fds(&mut waits, 0).is_ok_and(|_| waits[0].revents & libc::POLLIN != 0)
}

/// Waits until `deadline` for one byte on `fd`: true only for [`RELEASED`].
fn read_release(fd: BorrowedFd<'_>, deadline: Deadline) -> bool {
    loop {
        match super::sys::poll_one(fd, libc::POLLIN, deadline.remaining_millis_capped(1000)) {
            Ok(revents) if revents != 0 => {
                let mut byte = 0u8;
                // SAFETY: a one-byte read into a live byte from a descriptor
                // the caller holds open.
                let n = unsafe { libc::read(fd.as_raw_fd(), (&raw mut byte).cast(), 1) };
                return n == 1 && byte == RELEASED;
            }
            Ok(_) if !deadline.expired() => {}
            _ => return false,
        }
    }
}

/// Takes the descriptor the supervisor installed at `fd` for this helper,
/// or `None` when nothing is open there.
fn inherited(fd: RawFd) -> Option<OwnedFd> {
    // SAFETY: F_GETFD takes a scalar and dereferences nothing.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    // SAFETY: the descriptor is open (just checked) and was installed at this
    // number for this helper process alone; nothing else in it owns it.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn bootstrap_main(args: &[OsString]) -> ! {
    let Some(start) = inherited(START_FD) else {
        std::process::exit(125);
    };
    if args.is_empty() || !read_release(start.as_fd(), Deadline::after(Duration::from_secs(30))) {
        std::process::exit(125);
    }
    drop(start);
    use std::os::unix::ffi::OsStrExt as _;
    let argv: Vec<_> = args
        .iter()
        .map(|a| std::ffi::CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|_| std::process::exit(125));
    let env: Vec<_> = std::env::vars_os()
        .map(|(k, v)| {
            let mut bytes = k.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(v.as_bytes());
            std::ffi::CString::new(bytes).unwrap_or_else(|_| std::process::exit(125))
        })
        .collect();
    let argv_ptrs: Vec<_> = argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_ptrs: Vec<_> = env
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // The descriptor, not args[0], identifies the executable. No pathname fallback.
    // SAFETY: F_SETFD takes scalars; fexecve reads the NUL-terminated argv
    // and environment arrays, built above and alive for the call, and returns
    // only on failure.
    unsafe {
        if libc::fcntl(BACKEND_FD, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            std::process::exit(125);
        }
        libc::fexecve(BACKEND_FD, argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    let error = io::Error::last_os_error();
    // The supervisor reads the backend's status pipe while it waits for the
    // namespace init, so the reason the backend never started goes there and
    // reaches the refusal; stderr alone is not read back.
    let note = serde_json::json!({ "ouro-bootstrap": format!("backend exec failed: {error}") })
        .to_string()
        + "\n";
    // SAFETY: a live buffer of the stated length. The descriptor may be
    // closed, in which case the write fails and the note is only on stderr.
    unsafe {
        libc::write(super::platform::STATUS_FD, note.as_ptr().cast(), note.len());
    }
    crate::diag!("ouro-jail: backend exec failed: {error}");
    std::process::exit(125);
}

pub fn watcher_main(args: &[OsString]) -> ! {
    // Malformed direct invocations refuse rather than busy-looping or
    // signalling a numeric pid.
    let mut release = None;
    let mut cgroup_kill = None;
    for pair in args.chunks(2) {
        match pair {
            [flag, fd] if flag == RELEASE_ARG && fd.to_str() == Some(&RELEASE_FD.to_string()) => {
                release = inherited(RELEASE_FD);
            }
            [flag, fd]
                if flag == CGROUP_KILL_ARG && fd.to_str() == Some(&CGROUP_KILL_FD.to_string()) =>
            {
                let Some(kill) = inherited(CGROUP_KILL_FD) else {
                    std::process::exit(125);
                };
                cgroup_kill = Some(kill);
            }
            _ => std::process::exit(125),
        }
    }
    let (Some(release), Some(supervisor), Some(backend), Some(ready)) = (
        release,
        inherited(SUPERVISOR_PIDFD_FD),
        inherited(BACKEND_PIDFD_FD),
        inherited(READY_FD),
    ) else {
        std::process::exit(125);
    };
    // SAFETY: a one-byte write from a live byte to the inherited ready pipe.
    if unsafe { libc::write(ready.as_raw_fd(), [RELEASED].as_ptr().cast(), 1) } != 1 {
        std::process::exit(125);
    }
    drop(ready);
    // The whole leaf first: it also holds what the backend started, including
    // a namespace init whose own parent-death signal is not armed yet. Then
    // the backend, in case it never reached the leaf.
    let end_the_tree = || -> ! {
        if let Some(kill) = cgroup_kill.as_ref() {
            // SAFETY: a one-byte write from a live byte to an inherited
            // descriptor; a failure leaves the pidfd kill below.
            unsafe { libc::write(kill.as_raw_fd(), b"1".as_ptr().cast(), 1) };
        }
        let _ = identity::pidfd_send_signal(backend.as_raw_fd(), libc::SIGKILL);
        std::process::exit(0);
    };
    let mut fds = [
        libc::pollfd {
            fd: supervisor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: backend.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: release.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut grace: Option<std::time::Instant> = None;
    loop {
        let timeout = grace.map_or(1000, |until| {
            i32::try_from(
                until
                    .saturating_duration_since(std::time::Instant::now())
                    .as_millis(),
            )
            .unwrap_or(0)
        });
        match super::sys::poll_fds(&mut fds, timeout) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => std::process::exit(125),
        }
        if fds
            .iter()
            .any(|fd| fd.revents & (libc::POLLNVAL | libc::POLLERR) != 0)
        {
            std::process::exit(125);
        }
        // A dead supervisor decides, whatever else happened.
        if fds[0].revents & libc::POLLIN != 0 {
            end_the_tree();
        }
        if fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut byte = 0u8;
            // SAFETY: a one-byte read into a live byte from an inherited pipe.
            let n = unsafe { libc::read(release.as_raw_fd(), (&raw mut byte).cast(), 1) };
            if n == 1 && byte == RELEASED {
                std::process::exit(0);
            }
            // End-of-file: the supervisor's descriptors are gone.
            end_the_tree();
        }
        if grace.is_none() && fds[1].revents & libc::POLLIN != 0 {
            grace = Some(std::time::Instant::now() + UNRELEASED_GRACE);
            // A pidfd stays readable; poll it no more.
            fds[1].fd = -1;
        }
        if grace.is_some_and(|until| std::time::Instant::now() >= until) {
            // The supervisor outlived the grace: it is alive and owns what is
            // left of the tree.
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `readable` is "the process exited" for a pidfd, so only `POLLIN`
    /// counts: a hang-up with nothing to read is not it.
    #[test]
    fn only_pollin_is_readable() {
        let (read, write) = exec::pipe().expect("pipe");
        assert!(!is_readable(read.as_fd()), "an empty pipe");
        drop(write);
        assert!(
            !is_readable(read.as_fd()),
            "POLLHUP alone: the writer left nothing to read"
        );
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("a child to watch");
        let pidfd = identity::pidfd_open(i32::try_from(child.id()).unwrap()).expect("pidfd");
        assert!(!is_readable(pidfd.as_fd()), "a live process");
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
        assert!(is_readable(pidfd.as_fd()), "an exited process");
    }

    /// By number, a pipe with bytes in it is readable, and a number that is
    /// no longer open is not: `poll` answers it `POLLNVAL`.
    #[test]
    fn a_descriptor_number_is_readable_only_while_open_with_input() {
        let (read, write) = exec::pipe().expect("pipe");
        let number = read.as_raw_fd();
        assert!(!readable(number), "an empty pipe");
        std::io::Write::write_all(&mut std::fs::File::from(write), b"x").unwrap();
        assert!(readable(number), "a pipe with a byte in it");
        drop(read);
        assert!(!readable(number), "a closed number");
    }

    #[test]
    fn a_release_is_exactly_the_released_byte() {
        let deadline = || Deadline::after(Duration::from_secs(5));
        for (byte, released) in [(RELEASED, true), (RELEASED + 1, false)] {
            let (read, write) = exec::pipe().expect("pipe");
            std::io::Write::write_all(&mut std::fs::File::from(write), &[byte]).unwrap();
            assert_eq!(read_release(read.as_fd(), deadline()), released, "{byte}");
        }
        let (read, write) = exec::pipe().expect("pipe");
        drop(write);
        assert!(!read_release(read.as_fd(), deadline()), "end-of-file");
    }
}
