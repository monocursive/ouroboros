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
//! instrumented watcher, J4). A supervisor still alive when the grace ends
//! owns what is left, and the watcher leaves. The observer does not wait for
//! the watcher (J5-T): the supervisor reaps it itself once the observer is
//! done.
//!
//! Killing only the backend is not enough (J4, measured 2026-09-23):
//! bubblewrap's namespace init arms its own parent-death signal late in its
//! startup and before that waits on an eventfd only the outer process writes,
//! so an outer process killed in that window left the init alive on pid 1.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::{clock::Deadline, exec, identity};

pub const START_FD: i32 = 15;
/// Where the watcher receives the leaf's `cgroup.kill`, when there is a leaf.
pub const CGROUP_KILL_FD: i32 = 6;
const CGROUP_KILL_ARG: &str = "--cgroup-kill-fd";
/// Where the watcher receives the read end of its release pipe.
pub const RELEASE_FD: i32 = 7;
const RELEASE_ARG: &str = "--release-fd";
/// The byte that releases the watcher; end-of-file means the supervisor is gone.
const RELEASED: u8 = 1;
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
        let supervisor = identity::pidfd_open(unsafe { libc::getpid() })?;
        let backend = identity::pidfd_open(backend)?;
        let (ready_r, ready_w) = exec::pipe()?;
        let (release_r, release_w) = exec::pipe()?;
        let mut fds = exec::FdMap::new();
        fds.add(supervisor, 3)?;
        fds.add(backend, 4)?;
        fds.add(ready_w, 5)?;
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
            if !read_release(ready_r.as_raw_fd(), deadline) {
                return Err(io::Error::other("lifetime watcher did not become ready"));
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
        readable(self.fd.as_raw_fd())
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

/// A pidfd is readable on process exit, including while its zombie is waiting
/// for this supervisor's tracer thread to reap it.
pub fn readable(fd: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&raw mut pfd, 1, 0) > 0 }
}

fn read_release(fd: i32, deadline: Deadline) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let rc = unsafe { libc::poll(&raw mut pfd, 1, deadline.remaining_millis_capped(1000)) };
        if rc > 0 {
            let mut byte = 0u8;
            return unsafe { libc::read(fd, (&raw mut byte).cast(), 1) } == 1 && byte == 1;
        }
        if deadline.expired()
            || (rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
        {
            return false;
        }
    }
}

pub fn bootstrap_main(args: &[OsString]) -> ! {
    if args.is_empty() || !read_release(START_FD, Deadline::after(Duration::from_secs(30))) {
        std::process::exit(125);
    }
    unsafe {
        libc::close(START_FD);
    }
    let error = Command::new(&args[0]).args(&args[1..]).exec();
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
    // pidfd validity is checked by poll below; malformed direct invocations
    // refuse rather than busy-looping or signalling a numeric pid.
    let open = |fd: i32| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
    let mut release = false;
    let mut cgroup_kill = None;
    for pair in args.chunks(2) {
        match pair {
            [flag, fd] if flag == RELEASE_ARG && fd.to_str() == Some(&RELEASE_FD.to_string()) => {
                release = open(RELEASE_FD);
            }
            [flag, fd]
                if flag == CGROUP_KILL_ARG
                    && fd.to_str() == Some(&CGROUP_KILL_FD.to_string())
                    && open(CGROUP_KILL_FD) =>
            {
                cgroup_kill = Some(CGROUP_KILL_FD);
            }
            _ => std::process::exit(125),
        }
    }
    if !release {
        std::process::exit(125);
    }
    let byte = 1u8;
    if unsafe { libc::write(5, (&raw const byte).cast(), 1) } != 1 {
        std::process::exit(125);
    }
    unsafe {
        libc::close(5);
    }
    // The whole leaf first: it also holds what the backend started, including
    // a namespace init whose own parent-death signal is not armed yet. Then
    // the backend, in case it never reached the leaf.
    let end_the_tree = || -> ! {
        if let Some(fd) = cgroup_kill {
            // SAFETY: a one-byte write from a live byte to an inherited
            // descriptor; a failure leaves the pidfd kill below.
            unsafe { libc::write(fd, b"1".as_ptr().cast(), 1) };
        }
        let _ = identity::pidfd_send_signal(4, libc::SIGKILL);
        std::process::exit(0);
    };
    let mut fds = [
        libc::pollfd {
            fd: 3,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: 4,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: RELEASE_FD,
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
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 3, timeout) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            std::process::exit(125);
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
            let n = unsafe { libc::read(RELEASE_FD, (&raw mut byte).cast(), 1) };
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
