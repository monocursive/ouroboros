//! The live half of the unix-peer mediator: the syscalls and the mediation
//! thread. Linux-only; the pure logic and the filter live in the parent module.

use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::sync::Arc;
use std::thread::JoinHandle;

use super::{
    MediationRecord, MediationSink, NON_UNIX_NOTE, PeerAddr, Verdict, base_for, classify,
    mediation_program, relative_bytes,
};
use crate::platform::linux::identity::pidfd_open;
use crate::platform::linux::sockdiag::{SockDiag, VfsId};

// ---- constants not in this libc ------------------------------------------
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
pub const FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
/// `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`.
pub const FLAG_WAIT_KILLABLE_RECV: libc::c_ulong = 1 << 5;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

// ---------------------------------------------------------------------------
// Step 1/2: the launcher installs the filter and opens sock_diag
// ---------------------------------------------------------------------------

/// The fd numbers the launcher hands to the supervisor.
///
/// They are numbers in the *launcher's* descriptor table; the supervisor takes
/// the objects behind them with `pidfd_getfd`. The launcher keeps
/// [`LauncherSetup`] alive until the supervisor confirms the handover, then
/// drops it (closing the fds), before it execs the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LauncherFds {
    /// The seccomp notification listener.
    pub listener: RawFd,
    /// The `NETLINK_SOCK_DIAG` socket, bound to the attempt's netns.
    pub sockdiag: RawFd,
}

/// What the launcher holds between installing the filter and exec.
pub struct LauncherSetup {
    /// The numbers to communicate to the supervisor.
    pub fds: LauncherFds,
    _listener: OwnedFd,
    _sockdiag: OwnedFd,
}

// J3-agent begin: the launcher places both at fixed numbers
impl LauncherSetup {
    /// The listener and the sock_diag socket, so the launcher can place them
    /// at the descriptor numbers the supervisor expects.
    #[must_use]
    pub fn into_fds(self) -> (OwnedFd, OwnedFd) {
        (self._listener, self._sockdiag)
    }
}
// J3-agent end

/// Open a `NETLINK_SOCK_DIAG` socket in this netns, then install the agent
/// mediation filter with a new user-notification listener and
/// `WAIT_KILLABLE_RECV` (the filter refuses netlink sockets from then on).
///
/// Runs in the trusted launcher, inside the attempt's namespaces, while it is
/// blocked before exec (§3.4 step 2). `WAIT_KILLABLE_RECV` is set so an
/// ordinary caught signal does not turn every mediated connect into `EINTR`
/// (spike §5/Q4).
///
/// # Errors
///
/// The errno of `prctl`, `seccomp` or `socket`.
pub fn launcher_setup() -> io::Result<LauncherSetup> {
    // The sock_diag socket first: the mediation filter refuses every netlink
    // socket once it is installed, so nothing after it (the bridge, the
    // target) can open one.
    let sockdiag = SockDiag::open()?;
    let listener = install_filter(FLAG_NEW_LISTENER | FLAG_WAIT_KILLABLE_RECV)?;
    // Extract the netlink fd as an OwnedFd guard alongside its number.
    let sockdiag_no = sockdiag.as_raw_fd();
    // SAFETY: `sockdiag` owns the fd; we borrow its number for the handover and
    // keep the object alive by moving it into the guard below via into_owned.
    let sockdiag_owned = sockdiag.into_owned();
    Ok(LauncherSetup {
        fds: LauncherFds {
            listener: listener.as_raw_fd(),
            sockdiag: sockdiag_no,
        },
        _listener: listener,
        _sockdiag: sockdiag_owned,
    })
}

/// Install the mediation filter on the calling thread and return the listener.
///
/// `flags` must include `FLAG_NEW_LISTENER`. The caller must already hold
/// `no_new_privs` (set here) — the agent's outer setup does, and it is set
/// again for safety.
///
/// # Errors
///
/// The errno of `prctl` or `seccomp`.
pub fn install_filter(flags: libc::c_ulong) -> io::Result<OwnedFd> {
    install_program(&mediation_program(), flags)
}

// J3-agent begin: installing an already-built program, for a caller that
// must not allocate between fork and the install (the doctor probe)
/// [`install_filter`] for a program built by the caller.
///
/// Allocates nothing: `prctl` and `seccomp` only, so it may run between
/// `fork` and `_exit` in a multithreaded process.
///
/// # Errors
///
/// The errno of `prctl` or `seccomp`.
pub fn install_program(
    program: &crate::platform::linux::bpf::Program,
    flags: libc::c_ulong,
) -> io::Result<OwnedFd> {
    let fprog = program.sock_fprog();
    // SAFETY: PR_SET_NO_NEW_PRIVS takes scalars and dereferences nothing.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fprog` points at `program`'s instructions, both live for the call;
    // with FLAG_NEW_LISTENER the syscall returns a new fd (>= 0) owned here.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            std::ptr::from_ref(&fprog),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // A listener descriptor always fits a RawFd; `rc` comes from the kernel.
    #[allow(clippy::cast_possible_truncation)]
    let fd = rc as RawFd;
    // SAFETY: `fd` was just returned by seccomp(NEW_LISTENER) and is owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
// J3-agent end

// ---------------------------------------------------------------------------
// Step 2: the supervisor takes the listener and sock_diag fds
// ---------------------------------------------------------------------------

/// The mediator's authority: the notification listener and a `sock_diag` socket
/// bound to the attempt's netns, both taken from the blocked launcher.
pub struct PeerAuthority {
    listener: OwnedFd,
    sockdiag: SockDiag,
    // J3-agent begin: the authorized proxy (jail-v1 §10)
    authorized: Option<(u64, u64)>,
    // J3-agent end
}

// J3-agent begin: "deny access to host peers except the authorized proxy"
impl PeerAuthority {
    /// Also allow a pathname connect that reaches exactly this node, by its
    /// full `(st_dev, st_ino)`: the attempt's proxy socket, which lives in
    /// the host network namespace and so is never in the attempt's sock_diag
    /// view (jail-v1 §10). The supervisor keeps the node pinned for the whole
    /// run, so the number cannot be reused by another object, and a
    /// replacement bound at the same path has a different identity and is
    /// refused like any other host peer.
    #[must_use]
    pub fn authorize_peer(mut self, identity: (u64, u64)) -> Self {
        self.authorized = Some(identity);
        self
    }
}
// J3-agent end

/// Take the listener and sock_diag fds from the blocked launcher with
/// `pidfd_getfd` (§3.4 step 2).
///
/// The launcher is a same-uid descendant of the supervisor, so Yama scope 1
/// permits `pidfd_getfd`. The taken fds are the same kernel objects; the
/// sock_diag socket keeps the launcher's netns.
///
/// # Errors
///
/// The errno of `pidfd_getfd` (e.g. `EPERM` if the target is not a permitted
/// descendant, `EBADF` if a number is stale).
pub fn take_from_launcher(launcher: BorrowedFd<'_>, fds: LauncherFds) -> io::Result<PeerAuthority> {
    let listener = pidfd_getfd(launcher, fds.listener)?;
    let sockdiag = pidfd_getfd(launcher, fds.sockdiag)?;
    Ok(PeerAuthority {
        listener,
        sockdiag: SockDiag::from_fd(sockdiag),
        authorized: None,
    })
}

/// `pidfd_getfd(pidfd, targetfd, 0)`.
///
/// # Errors
/// The errno of `pidfd_getfd`.
pub fn pidfd_getfd(pidfd: BorrowedFd<'_>, target: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_getfd takes three scalars and dereferences nothing; the
    // returned fd (>= 0) is a new descriptor owned by this process.
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(rc).map_err(|_| io::Error::other("pidfd_getfd returned a huge fd"))?;
    // SAFETY: `fd` was just created by pidfd_getfd and is owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ---------------------------------------------------------------------------
// Step 3: the mediation thread
// ---------------------------------------------------------------------------

/// Number of mediation worker threads. A small bounded pool so one slow
/// connect cannot starve every other request (review fix 2). Each worker calls
/// `SECCOMP_IOCTL_NOTIF_RECV` on the shared listener; the kernel hands each a
/// distinct pending notification.
const WORKERS: usize = 4;

/// Bound on any single connect the mediator performs, in milliseconds. Every
/// connect is non-blocking and polled to this deadline (or until stop), so no
/// request can wedge a worker, and `stop()` returns within about this bound.
const CONNECT_DEADLINE_MS: libc::c_int = 2000;

/// Bound on a `poll` wait between stop checks.
const POLL_TICK_MS: libc::c_int = 500;

/// A running mediation pool. Dropping it, or calling [`MediatorHandle::stop`],
/// stops every worker within a bounded time (in-flight connects fail closed)
/// and closes the listener; the supervisor must keep it alive for the whole
/// run, because closing the listener makes the child's `connect` fail `ENOSYS`
/// (fail-closed, spike §5/Q5).
pub struct MediatorHandle {
    // Held so the listener stays open until every worker has joined; then its
    // drop closes the listener, which is the fail-closed teardown.
    _listener: OwnedFd,
    stop_w: OwnedFd,
    joins: Vec<JoinHandle<()>>,
}

impl MediatorHandle {
    /// Stop every worker and wait for them, within a bounded time.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.signal_stop();
        for join in self.joins.drain(..) {
            let _ = join.join();
        }
    }

    fn signal_stop(&self) {
        // One byte is enough: the workers poll the same read end level-triggered
        // and none consumes it, so every worker sees POLLIN and exits.
        // SAFETY: writing one byte to the stop pipe's write end, which is owned.
        let _ = unsafe { libc::write(self.stop_w.as_raw_fd(), b"x".as_ptr().cast(), 1) };
    }
}

impl Drop for MediatorHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// State shared by the mediation workers.
struct Workers {
    listener: RawFd,
    stop_r: RawFd,
    // One `NETLINK_SOCK_DIAG` socket, serialized: the netns lookup is fast and
    // the slow part (connect) is outside the lock, so this does not serialize
    // whole requests.
    sockdiag: std::sync::Mutex<SockDiag>,
    sink: Arc<dyn MediationSink>,
    // J3-agent begin
    authorized: Option<(u64, u64)>,
    /// Held while a worker checks for a pending notification and receives
    /// it. `SECCOMP_IOCTL_NOTIF_RECV` ignores `O_NONBLOCK`: with nothing
    /// pending it waits for the next request, so a worker woken by `poll`
    /// together with others, that lost the race for the one notification,
    /// would sleep inside RECV where the stop pipe cannot reach it, and
    /// `stop()` would wait for it for ever (measured on the reference host:
    /// a live test hung joining `ouro-unixpeer-1`). Under this lock a worker
    /// receives only after a zero-timeout `poll` shows a notification still
    /// pending, and only lock holders receive, so RECV finds it (or `ENOENT`
    /// if its task died meanwhile) and never waits. The slow part of a
    /// mediation runs outside the lock.
    recv: std::sync::Mutex<()>,
    // J3-agent end
    // Kept alive so the stop pipe read end outlives every worker.
    _stop_r_owned: OwnedFd,
}

/// Start the mediation pool (§3.4 step 3).
///
/// # Errors
///
/// The errno of `pipe2`.
pub fn spawn(authority: PeerAuthority, sink: Arc<dyn MediationSink>) -> io::Result<MediatorHandle> {
    let PeerAuthority {
        listener,
        sockdiag,
        authorized,
    } = authority;
    let mut pipe = [0i32; 2];
    // SAFETY: `pipe` is a two-element array; pipe2 writes two fds or returns -1.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both fds were just created by pipe2 and are owned here.
    let (stop_r, stop_w) =
        unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
    let listener_raw = listener.as_raw_fd();
    let stop_r_raw = stop_r.as_raw_fd();
    // Non-blocking: after a poll wakeup the RECV must never block a worker, or a
    // stop request would not be seen and the fail-closed teardown would hang.
    // SAFETY: fcntl on a live owned fd with scalar arguments.
    unsafe {
        let flags = libc::fcntl(listener_raw, libc::F_GETFL);
        libc::fcntl(listener_raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let workers = Arc::new(Workers {
        listener: listener_raw,
        stop_r: stop_r_raw,
        sockdiag: std::sync::Mutex::new(sockdiag),
        sink,
        authorized,
        recv: std::sync::Mutex::new(()),
        _stop_r_owned: stop_r,
    });
    let mut joins = Vec::with_capacity(WORKERS);
    for i in 0..WORKERS {
        let w = Arc::clone(&workers);
        joins.push(
            std::thread::Builder::new()
                .name(format!("ouro-unixpeer-{i}"))
                .spawn(move || worker_loop(&w))?,
        );
    }
    Ok(MediatorHandle {
        _listener: listener,
        stop_w,
        joins,
    })
}

fn worker_loop(w: &Workers) {
    loop {
        let mut pfds = [
            libc::pollfd {
                fd: w.listener,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: w.stop_r,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `pfds` is a live two-element array; poll writes revents only.
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, POLL_TICK_MS) };
        if rc < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if pfds[1].revents != 0 {
            break; // stop requested
        }
        if pfds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            break; // listener closed elsewhere
        }
        if pfds[0].revents & libc::POLLIN != 0 {
            match service_one(w) {
                Ok(()) => {}
                Err(_) => break, // listener gone => fail closed
            }
        }
    }
}

/// Service exactly one notification. Returns `Err` only when the listener is
/// gone (the loop then exits and the child's connects fail `ENOSYS`).
fn service_one(w: &Workers) -> io::Result<()> {
    let listener = w.listener;
    let sink = w.sink.as_ref();
    // J3-agent begin: receive only what is still pending (see `Workers::recv`)
    let received = {
        let _guard = w
            .recv
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending(listener) {
            Some(notif_recv(listener))
        } else {
            None
        }
    };
    let Some(received) = received else {
        return Ok(());
    };
    // J3-agent end
    let notif = match received {
        Ok(n) => n,
        // A stale notification (the task went away) or a spurious poll wakeup on
        // the non-blocking listener is not fatal: skip and return to poll, where
        // the stop request is seen. Never let a RECV block the thread.
        // EAGAIN == EWOULDBLOCK on Linux, so one arm covers the non-blocking
        // "nothing pending" case.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::EAGAIN)) => {
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let id = notif.id;
    let pid = notif.pid as libc::pid_t;
    let sockfd = notif.data.args[0] as RawFd;
    let uaddr = notif.data.args[1];
    let ualen = notif.data.args[2] as usize;

    // Test-only: widen the task-death / pid-reuse window the id revalidation
    // guards. Zero in production.
    let delay = super::MEDIATION_TEST_DELAY_MS.load(std::sync::atomic::Ordering::Relaxed);
    if delay > 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }

    // Re-validate before touching the child (TOCTOU guard, spike §Q dead-task).
    if !notif_id_valid(listener, id) {
        return Ok(());
    }
    // J3-agent begin: read while the task is parked in its notification, so
    // the thread group named is the one that asked (validated again below).
    let tgid = task_tgid(pid);
    let mut facts = Facts {
        pid,
        tgid,
        tgid_start: tgid
            .and_then(|tgid| crate::platform::linux::identity::start_time_ticks(tgid).ok()),
        family: None,
        address_complete: false,
    };
    // J3-agent end
    let Ok(child_pidfd) = open_notifying_thread(pid, tgid) else {
        deny(listener, id, libc::ESRCH);
        record(sink, &facts, "task_gone", Verdict::Denied(libc::ESRCH));
        return Ok(());
    };
    let dup = match pidfd_getfd(child_pidfd.as_fd(), sockfd) {
        Ok(fd) => fd,
        Err(_) => {
            deny(listener, id, libc::EBADF);
            record(sink, &facts, "fd_unavailable", Verdict::Denied(libc::EBADF));
            return Ok(());
        }
    };
    let sockaddr = read_child_mem(pid, uaddr, ualen.min(256)).unwrap_or_default();
    // Re-validate again after the reads, before acting.
    if !notif_id_valid(listener, id) {
        return Ok(());
    }
    // J3-agent begin
    facts.family = (sockaddr.len() >= 2).then(|| u16::from_ne_bytes([sockaddr[0], sockaddr[1]]));
    facts.address_complete = ualen <= 256 && sockaddr.len() == ualen;
    // J3-agent end

    let (verdict, reason) = decide(w, pid, &dup, &sockaddr, ualen);
    match verdict {
        Ok(()) => {
            notif_send(listener, id, 0, 0);
            record(sink, &facts, reason, Verdict::Allowed);
        }
        Err(errno) => {
            notif_send(listener, id, 0, -errno);
            record(sink, &facts, reason, Verdict::Denied(errno));
        }
    }
    Ok(())
}

/// The §3.4 decision on a duplicated socket and the address the child named.
/// `Ok(())` means "connected"; `Err(errno)` means "denied/failed with errno".
fn decide(
    w: &Workers,
    pid: libc::pid_t,
    dup: &OwnedFd,
    sockaddr: &[u8],
    ualen: usize,
) -> (Result<(), i32>, &'static str) {
    let domain = getsockopt_domain(dup.as_raw_fd()).unwrap_or(-1);
    if domain != libc::AF_UNIX {
        // Non-AF_UNIX: the mediator performs the connect on the duplicate. The
        // socket keeps the child's netns, so this cannot escape it; it does run
        // in the mediator's LSM context (see NON_UNIX_NOTE).
        let _ = NON_UNIX_NOTE;
        return (
            bounded_connect(dup.as_raw_fd(), sockaddr, ualen, w.stop_r),
            "non_unix",
        );
    }
    match classify(sockaddr) {
        PeerAddr::Abstract(_) | PeerAddr::Unnamed => {
            // Abstract names are netns-scoped; connect the duplicate directly.
            (
                bounded_connect(dup.as_raw_fd(), sockaddr, ualen, w.stop_r),
                "abstract",
            )
        }
        PeerAddr::NonUnix(_) => (Err(libc::EAFNOSUPPORT), "family_mismatch"),
        PeerAddr::Pathname(path) => mediate_pathname(w, pid, dup, &path),
    }
}

fn mediate_pathname(
    w: &Workers,
    pid: libc::pid_t,
    dup: &OwnedFd,
    path: &[u8],
) -> (Result<(), i32>, &'static str) {
    let base = base_for(pid, path);
    let Ok(base_fd) = open_o_path(&base) else {
        return (Err(libc::EACCES), "base_unopenable");
    };
    let rel = relative_bytes(path);
    // Pin the node without escaping the child's view.
    let node = match openat2_in_root(base_fd.as_raw_fd(), &rel) {
        Ok(fd) => fd,
        Err(_) => return (Err(libc::EACCES), "path_unresolved"),
    };
    let st = match fstat(node.as_raw_fd()) {
        Ok(st) => st,
        Err(_) => return (Err(libc::EACCES), "stat_failed"),
    };
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return (Err(libc::ECONNREFUSED), "not_a_socket");
    }
    // J3-agent begin: the authorized proxy, by its full pinned identity. It
    // is bound in the host network namespace, so sock_diag in the attempt's
    // namespace never lists it; nothing else from the host is let through.
    if w.authorized == Some((st.st_dev, st.st_ino)) {
        return match connect_pinned(dup, &node, w.stop_r) {
            Ok(()) => (Ok(()), "authorized_proxy"),
            Err(errno) => (Err(errno), "proxy_connect_failed"),
        };
    }
    // J3-agent end
    // Filesystem identity; refuse a node too wide for the sock_diag interface.
    let Some(want) = VfsId::from_stat(st.st_ino, st.st_dev) else {
        return (Err(libc::EACCES), "inode_too_wide");
    };
    // The netns lookup is serialized (one sock_diag socket) but bounded; the
    // slow connect below is outside the lock.
    let listener_present = {
        let Ok(mut sd) = w.sockdiag.lock() else {
            return (Err(libc::EACCES), "sock_diag_poisoned");
        };
        sd.has_listener_for(want)
    };
    match listener_present {
        Ok(true) => {}
        Ok(false) => return (Err(libc::EACCES), "no_attempt_listener"),
        Err(_) => return (Err(libc::EACCES), "sock_diag_failed"),
    }
    match connect_pinned(dup, &node, w.stop_r) {
        Ok(()) => (Ok(()), "attempt_listener"),
        Err(e) => (Err(e), "connect_failed"),
    }
}

/// Connects the duplicate through the pinned node, so the kernel reaches
/// exactly the checked inode and not a path the child could swap.
fn connect_pinned(dup: &OwnedFd, node: &OwnedFd, stop_r: RawFd) -> Result<(), i32> {
    let procpath = format!("/proc/self/fd/{}", node.as_raw_fd());
    let (addr, addr_len) = sockaddr_un(procpath.as_bytes());
    // SAFETY: `addr` is a live sockaddr_un; view its exact bytes as a slice for
    // the bounded connect helper.
    let addr_bytes = unsafe {
        std::slice::from_raw_parts(std::ptr::from_ref(&addr).cast::<u8>(), addr_len as usize)
    };
    bounded_connect(dup.as_raw_fd(), addr_bytes, addr_len as usize, stop_r)
}

/// Perform a connect on `fd` without ever blocking a worker.
///
/// The socket is put non-blocking for the duration (the child is parked in the
/// notify wait, so this is invisible to it, and the flag is restored). A
/// connect that returns `EINPROGRESS` (TCP, or a Unix connect that is queued)
/// is polled to [`CONNECT_DEADLINE_MS`] or until stop; a Unix connect to a full
/// listener backlog returns `EAGAIN` immediately and becomes the child's
/// result — either way one slow or hostile peer cannot wedge the mediator
/// (review fix 2). A stop mid-connect fails the request closed.
fn bounded_connect(fd: RawFd, sockaddr: &[u8], ualen: usize, stop_r: RawFd) -> Result<(), i32> {
    let len = u32::try_from(ualen.min(sockaddr.len())).unwrap_or(0);
    // SAFETY: fcntl with scalar arguments on a live fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let restore = flags >= 0 && (flags & libc::O_NONBLOCK) == 0;
    if restore {
        // SAFETY: as above.
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    // SAFETY: `sockaddr` is a live slice of at least `len` bytes; connect copies
    // it and returns before it is dropped.
    let rc = unsafe { libc::connect(fd, sockaddr.as_ptr().cast::<libc::sockaddr>(), len) };
    let result = if rc == 0 {
        Ok(())
    } else {
        let e = last_errno();
        if e == libc::EINPROGRESS {
            let mut pfds = [
                libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stop_r,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: live two-element pollfd array.
            let p = unsafe { libc::poll(pfds.as_mut_ptr(), 2, CONNECT_DEADLINE_MS) };
            if p <= 0 {
                Err(libc::ETIMEDOUT)
            } else if pfds[1].revents != 0 {
                Err(libc::ECONNABORTED) // stop: fail closed
            } else {
                match so_error(fd) {
                    0 => Ok(()),
                    err => Err(err),
                }
            }
        } else {
            Err(e)
        }
    };
    if restore {
        // SAFETY: restore the original flags on the shared file description.
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    }
    result
}

/// `SO_ERROR` of a socket, or `EIO` if it cannot be read.
fn so_error(fd: RawFd) -> i32 {
    let mut val: libc::c_int = 0;
    let mut len = u32::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
    // SAFETY: `val`/`len` are live and correctly sized for SO_ERROR.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            std::ptr::from_mut(&mut val).cast(),
            &raw mut len,
        )
    };
    if rc < 0 { libc::EIO } else { val }
}

// ---- syscall helpers ------------------------------------------------------

// J3-agent begin: the facts a record carries beside its verdict
struct Facts {
    pid: libc::pid_t,
    tgid: Option<libc::pid_t>,
    tgid_start: Option<u64>,
    family: Option<u16>,
    address_complete: bool,
}

/// `Tgid:` of a task in `/proc/<tid>/status`, or `None`.
fn task_tgid(tid: libc::pid_t) -> Option<libc::pid_t> {
    let text = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|value| value.trim().parse().ok())
}
// J3-agent end

fn record(sink: &dyn MediationSink, facts: &Facts, reason: &'static str, verdict: Verdict) {
    sink.record(MediationRecord {
        pid: facts.pid,
        tgid: facts.tgid,
        tgid_start: facts.tgid_start,
        family: facts.family,
        address_complete: facts.address_complete,
        reason,
        verdict,
    });
}

fn deny(listener: RawFd, id: u64, errno: i32) {
    notif_send(listener, id, 0, -errno);
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn notif_recv(listener: RawFd) -> io::Result<libc::seccomp_notif> {
    // SAFETY: `n` is a live, zeroed seccomp_notif the ioctl fills in.
    let mut n: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::ioctl(
            listener,
            libc::SECCOMP_IOCTL_NOTIF_RECV,
            std::ptr::from_mut(&mut n),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n)
}

// J3-agent begin: a notification is pending on the listener right now
/// Whether a notification is waiting to be received, by a `poll` that does
/// not wait. A closed or broken listener counts as pending, so the caller's
/// RECV reports the failure instead of this hiding it.
fn pending(listener: RawFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: listener,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pollfd; a zero timeout never waits.
    let rc = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    rc > 0 && pfd.revents != 0
}
// J3-agent end

/// A pidfd whose descriptor table is the notifying thread's own.
///
/// `seccomp_notif.pid` names the thread that made the call, and a
/// multi-threaded runtime connects from worker threads. `pidfd_open` refuses a
/// thread that is not its group's leader unless it is asked for that thread
/// (`PIDFD_THREAD`, Linux 6.9). On an older kernel the leader's pidfd is used
/// only when `kcmp` shows the parked thread shares the leader's descriptor
/// table; otherwise the connect is refused rather than resolved against the
/// wrong table. The parked thread cannot change its own table while it waits.
fn open_notifying_thread(tid: libc::pid_t, tgid: Option<libc::pid_t>) -> io::Result<OwnedFd> {
    match crate::platform::linux::identity::pidfd_open_thread(tid) {
        Ok(fd) => return Ok(fd),
        Err(error) if error.raw_os_error() != Some(libc::EINVAL) => return Err(error),
        Err(_) => {}
    }
    let Some(tgid) = tgid else {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    };
    if tgid != tid && !crate::platform::linux::identity::same_descriptor_table(tid, tgid) {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    pidfd_open(tgid)
}

fn notif_id_valid(listener: RawFd, id: u64) -> bool {
    let mut id = id;
    // SAFETY: the ioctl reads one u64 through the pointer; `id` is live.
    unsafe {
        libc::ioctl(
            listener,
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            std::ptr::from_mut(&mut id),
        ) == 0
    }
}

fn notif_send(listener: RawFd, id: u64, val: i64, error: i32) {
    let mut resp = libc::seccomp_notif_resp {
        id,
        val,
        error,
        flags: 0,
    };
    // SAFETY: `resp` is a live seccomp_notif_resp the ioctl reads.
    unsafe {
        libc::ioctl(
            listener,
            libc::SECCOMP_IOCTL_NOTIF_SEND,
            std::ptr::from_mut(&mut resp),
        );
    }
}

fn read_child_mem(pid: libc::pid_t, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: `local` addresses `buf`'s live bytes; `remote` names the child's
    // address range; process_vm_readv copies at most `len` bytes into `buf`.
    let n = unsafe { libc::process_vm_readv(pid, &raw const local, 1, &raw const remote, 1, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(n).unwrap_or(0));
    Ok(buf)
}

fn getsockopt_domain(fd: RawFd) -> io::Result<libc::c_int> {
    let mut val: libc::c_int = 0;
    let mut len = u32::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
    // SAFETY: `val`/`len` are live and correctly sized for SO_DOMAIN.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            std::ptr::from_mut(&mut val).cast(),
            &raw mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(val)
}

fn open_o_path(path: &str) -> io::Result<OwnedFd> {
    let c =
        std::ffi::CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `c` is a live NUL-terminated string; open dereferences it and
    // returns a new fd owned here or -1.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created by open and is owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `openat2(base, rel, O_PATH, RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`.
///
/// `RESOLVE_IN_ROOT` treats `base` as the root, so `..` and absolute symlinks
/// cannot escape the child's view — the mediator can never be walked out of the
/// attempt through a crafted path (§3.4 step 3).
fn openat2_in_root(base: RawFd, rel: &[u8]) -> io::Result<OwnedFd> {
    let c =
        std::ffi::CString::new(rel).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // `open_how` is #[non_exhaustive]; build it zeroed and set the fields.
    // SAFETY: open_how is plain data; all-zero is a valid "no flags" request.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    // SAFETY: `c` is a live NUL-terminated path; `how` is a live open_how of the
    // size passed; openat2 returns a new fd owned here or -1.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            base,
            c.as_ptr(),
            std::ptr::from_ref(&how),
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(rc).map_err(|_| io::Error::other("openat2 returned a huge fd"))?;
    // SAFETY: `fd` was just created by openat2 and is owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: `st` is a live, zeroed stat the syscall fills in on success.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, std::ptr::from_mut(&mut st)) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// Build a `sockaddr_un` for a pathname (used for `/proc/self/fd/<n>`).
fn sockaddr_un(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    // SAFETY: sockaddr_un is plain data; all-zero is a valid empty address.
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let n = name.len().min(a.sun_path.len() - 1);
    for (slot, byte) in a.sun_path.iter_mut().zip(&name[..n]) {
        *slot = *byte as libc::c_char;
    }
    let len = u32::try_from(2 + n + 1).unwrap_or(2);
    (a, len)
}
