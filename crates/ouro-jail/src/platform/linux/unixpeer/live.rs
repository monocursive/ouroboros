//! The live half of the unix-peer mediator: the syscalls and the mediation
//! thread. Linux-only; the pure logic and the filter live in the parent module.

use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::sync::Arc;
use std::thread::JoinHandle;

use super::{
    ConnectFacts, Decision, Delivery, MediationRecord, MediationSink, NON_UNIX_NOTE, Peer,
    PeerAddr, base_for, classify, mediation_program, peer_of, relative_bytes,
};
use crate::platform::linux::identity::{self, pidfd_open};
use crate::platform::linux::sockdiag::{SockDiag, VfsId};
use crate::platform::linux::sys::last_errno;

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
    listener: OwnedFd,
    sockdiag: OwnedFd,
}

// The launcher places both at fixed numbers
impl LauncherSetup {
    /// The listener and the sock_diag socket, so the launcher can place them
    /// at the descriptor numbers the supervisor expects.
    #[must_use]
    pub fn into_fds(self) -> (OwnedFd, OwnedFd) {
        (self.listener, self.sockdiag)
    }
}

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
    Ok(LauncherSetup {
        listener,
        sockdiag: sockdiag.into_owned(),
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

// Installing an already-built program, for a caller that
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

// ---------------------------------------------------------------------------
// Step 2: the supervisor takes the listener and sock_diag fds
// ---------------------------------------------------------------------------

/// The mediator's authority: the notification listener and a `sock_diag` socket
/// bound to the attempt's netns, both taken from the blocked launcher.
pub struct PeerAuthority {
    listener: OwnedFd,
    sockdiag: SockDiag,
    // The authorized proxy (jail-v1 §10)
    authorized: Option<(u64, u64)>,
}

// "deny access to host peers except the authorized proxy"
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

/// Number of mediation worker threads. A small bounded pool so one slow connect
/// cannot starve every other request. Each worker calls
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
    stop_w: OwnedFd,
    // The workers own the listener: it closes when the last of them and
    // this handle let go, which is after every worker has joined.
    workers: Arc<Workers>,
    joins: Vec<JoinHandle<()>>,
}

impl MediatorHandle {
    /// Stop every worker and wait for them, within a bounded time.
    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Wake workers before other shutdown work consumes the stop budget.
    pub fn request_stop(&self) {
        self.signal_stop();
    }

    /// Pin the only thread group whose connects to the authorized proxy node
    /// the mediation will perform. Called by the supervisor once the bridge is
    /// discovered and its identity pinned; until then the authorized node is
    /// refused for everyone, and the target has not been released.
    pub fn restrict_authorized_connector(&self, identity: Option<(libc::pid_t, u64)>) {
        *crate::sync::lock(&self.workers.authorized_connector) = identity;
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

/// State shared by the mediation workers. It owns the listener and the stop
/// pipe's read end, so neither number can be closed, or reused, under a
/// worker still polling it.
struct Workers {
    listener: OwnedFd,
    stop_r: OwnedFd,
    // One `NETLINK_SOCK_DIAG` socket, serialized: the netns lookup is fast and
    // the slow part (connect) is outside the lock, so this does not serialize
    // whole requests.
    sockdiag: std::sync::Mutex<SockDiag>,
    sink: Arc<dyn MediationSink>,
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
    /// if its task died meanwhile: the kernel counts every queued request,
    /// so the receive does not wait for a new one) and never waits. This
    /// lock, not a descriptor flag, is the guarantee that RECV never blocks
    /// a worker. The slow part of a mediation runs outside the lock.
    recv: std::sync::Mutex<()>,
    // The authorized proxy socket is connectable through the mediation only by
    // the bridge itself. The inode check alone admitted any process in the
    // sandbox, which made the bridge's accounting and the bridge's fail-closed
    // budget skippable by the target. `None` until the supervisor has
    // discovered and pinned the bridge's identity; before that every connect to
    // the authorized node is refused (fail closed; the target is not released
    // yet).
    authorized_connector: std::sync::Mutex<Option<(libc::pid_t, u64)>>,
}

/// Start the mediation pool (§3.4 step 3).
///
/// The listener stays as the launcher made it: RECV ignores `O_NONBLOCK`, so
/// what keeps a worker from blocking in it is [`Workers::recv`].
///
/// # Errors
///
/// The errno of `pipe2`, or of a worker thread that could not be started
/// (the workers already started are stopped and joined first).
pub fn spawn(authority: PeerAuthority, sink: Arc<dyn MediationSink>) -> io::Result<MediatorHandle> {
    let PeerAuthority {
        listener,
        sockdiag,
        authorized,
    } = authority;
    let (stop_r, stop_w) = crate::platform::linux::exec::pipe()?;
    let mut handle = MediatorHandle {
        stop_w,
        workers: Arc::new(Workers {
            listener,
            stop_r,
            sockdiag: std::sync::Mutex::new(sockdiag),
            sink,
            authorized,
            authorized_connector: std::sync::Mutex::new(None),
            recv: std::sync::Mutex::new(()),
        }),
        joins: Vec::with_capacity(WORKERS),
    };
    for i in 0..WORKERS {
        let w = Arc::clone(&handle.workers);
        // On failure `handle` drops: it stops and joins the workers already
        // running before the listener can close.
        let join = std::thread::Builder::new()
            .name(format!("ouro-unixpeer-{i}"))
            .spawn(move || worker_loop(&w))?;
        handle.joins.push(join);
    }
    Ok(handle)
}

fn worker_loop(w: &Workers) {
    loop {
        let mut pfds = [
            libc::pollfd {
                fd: w.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: w.stop_r.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        match crate::platform::linux::sys::poll_fds(&mut pfds, POLL_TICK_MS) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
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
    let listener = w.listener.as_fd();
    let sink = w.sink.as_ref();
    // Receive only what is still pending (see `Workers::recv`)
    let received = {
        let _guard = crate::sync::lock(&w.recv);
        if pending(listener) {
            Some(notif_recv(listener))
        } else {
            None
        }
    };
    let Some(received) = received else {
        return Ok(());
    };
    let notif = match received {
        Ok(n) => n,
        // The notification `pending` saw was withdrawn because its task died
        // before this receive: not fatal; return to poll, where a stop
        // request is seen.
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(e) => return Err(e),
    };
    let id = notif.id;
    let tid = notif.pid as libc::pid_t;
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
    // Read while the task is parked in its notification, so
    // the thread group named is the one that asked (validated again below).
    let tgid = task_tgid(tid);
    let mut facts = ConnectFacts {
        tid,
        tgid,
        tgid_start: tgid.and_then(|tgid| identity::start_time_ticks(tgid).ok()),
        family: None,
        address_complete: false,
        peer: None,
    };
    let Ok(child_pidfd) = open_notifying_thread(tid, tgid) else {
        respond_and_record(
            listener,
            id,
            sink,
            facts,
            "task_gone",
            Decision::Denied(libc::ESRCH),
        );
        return Ok(());
    };
    let dup = match pidfd_getfd(child_pidfd.as_fd(), sockfd) {
        Ok(fd) => fd,
        Err(_) => {
            respond_and_record(
                listener,
                id,
                sink,
                facts,
                "fd_unavailable",
                Decision::Denied(libc::EBADF),
            );
            return Ok(());
        }
    };
    let sockaddr = read_child_mem(tid, uaddr, ualen.min(256)).unwrap_or_default();
    // Re-validate again after the reads, before acting.
    if !notif_id_valid(listener, id) {
        return Ok(());
    }
    facts.family = (sockaddr.len() >= 2).then(|| u16::from_ne_bytes([sockaddr[0], sockaddr[1]]));
    facts.address_complete = ualen <= 256 && sockaddr.len() == ualen;
    facts.peer = peer_of(&sockaddr);

    let origin = match (&facts.peer, facts.tgid, facts.tgid_start) {
        (Some(Peer::Internet { port, address }), Some(pid), Some(start)) => {
            sink.connecting(pid, start, std::net::SocketAddr::new(*address, *port))
        }
        _ => None,
    };
    // Another thread's exec can cancel the notifying task during executable
    // capture. Never attach the successor's identity to a stale notification.
    if !notif_id_valid(listener, id) {
        return Ok(());
    }
    let (result, reason) = decide(w, &facts, &dup, &sockaddr, ualen);
    if result.is_ok()
        && let Some(origin) = origin
    {
        origin.connected(dup.as_fd());
    }
    let decision = match result {
        Ok(()) => Decision::Allowed,
        Err(errno) => Decision::Denied(errno),
    };
    respond_and_record(listener, id, sink, facts, reason, decision);
    Ok(())
}

/// Which §3.4 branch a duplicated socket takes, by its own `SO_DOMAIN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// An AF_UNIX socket: the address is classified.
    Unix,
    /// Any other family: the mediator connects the duplicate.
    NonUnix,
    /// Refused before any connect: the child's errno and the reason.
    Refuse(i32, &'static str),
}

/// The branch for a socket whose `SO_DOMAIN` read gave `domain`. Only a
/// domain the kernel reported may lead to the mediator's own connect: one
/// that could not be read refuses like every other uncertain branch.
fn route(domain: io::Result<libc::c_int>) -> Route {
    match domain {
        Ok(libc::AF_UNIX) => Route::Unix,
        Ok(_) => Route::NonUnix,
        // The kernel's own answer to a connect on a descriptor that is not a
        // socket.
        Err(error) if error.raw_os_error() == Some(libc::ENOTSOCK) => {
            Route::Refuse(libc::ENOTSOCK, "fd_not_a_socket")
        }
        Err(_) => Route::Refuse(libc::EACCES, "domain_unreadable"),
    }
}

/// The §3.4 decision on a duplicated socket and the address the child named.
/// `Ok(())` means "connected"; `Err(errno)` means "denied/failed with errno".
fn decide(
    w: &Workers,
    facts: &ConnectFacts,
    dup: &OwnedFd,
    sockaddr: &[u8],
    ualen: usize,
) -> (Result<(), i32>, &'static str) {
    match route(getsockopt_domain(dup.as_fd())) {
        Route::Unix => {}
        Route::NonUnix => {
            // Non-AF_UNIX: the mediator performs the connect on the
            // duplicate. The socket keeps the child's netns, so this cannot
            // escape it; it does run in the mediator's LSM context (see
            // NON_UNIX_NOTE).
            let _ = NON_UNIX_NOTE;
            let result = bounded_connect(dup.as_fd(), sockaddr, ualen, w.stop_r.as_fd());
            return (result, "non_unix");
        }
        Route::Refuse(errno, reason) => return (Err(errno), reason),
    }
    // An address longer than the `sockaddr_un` layout is one the kernel itself
    // would refuse at `connect`; classifying its bytes (a pathname truncated
    // into whatever follows) would mediate an address that cannot exist. Refuse
    // it with the kernel's own answer, `EINVAL`.
    if ualen > std::mem::size_of::<libc::sockaddr_un>() {
        return (Err(libc::EINVAL), "addr_overlong");
    }
    match classify(sockaddr) {
        PeerAddr::Abstract(_) | PeerAddr::Unnamed => {
            // Abstract names are netns-scoped; connect the duplicate directly.
            (
                bounded_connect(dup.as_fd(), sockaddr, ualen, w.stop_r.as_fd()),
                "abstract",
            )
        }
        PeerAddr::NonUnix(_) => (Err(libc::EAFNOSUPPORT), "family_mismatch"),
        PeerAddr::Pathname(path) => mediate_pathname(w, facts, dup, &path),
    }
}

fn mediate_pathname(
    w: &Workers,
    facts: &ConnectFacts,
    dup: &OwnedFd,
    path: &[u8],
) -> (Result<(), i32>, &'static str) {
    let pid = facts.tid;
    let root = base_for(pid, path);
    let Ok(root_fd) = open_o_path(&root) else {
        return (Err(libc::EACCES), "base_unopenable");
    };
    let Ok(rel) = path_beneath_child_root(pid, root_fd.as_fd(), path) else {
        return (Err(libc::EACCES), "cwd_unresolved");
    };
    // Pin the node without escaping the child's view. A path that does not
    // exist in the child's own view gets the kernel's own answer, ENOENT;
    // anything that cannot be resolved at all refuses closed with EACCES.
    let node = match openat2_in_root(root_fd.as_fd(), &rel) {
        Ok(fd) => fd,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (Err(libc::ENOENT), "path_absent");
        }
        Err(_) => return (Err(libc::EACCES), "path_unresolved"),
    };
    let st = match fstat(node.as_raw_fd()) {
        Ok(st) => st,
        Err(_) => return (Err(libc::EACCES), "stat_failed"),
    };
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return (Err(libc::ECONNREFUSED), "not_a_socket");
    }
    // The authorized proxy, by its full pinned identity. It is bound in the
    // host network namespace, so sock_diag in the attempt's namespace never
    // lists it; nothing else from the host is let through. The inode match
    // alone is not enough: every process in the sandbox could name the node,
    // skipping the bridge and its accounting. Only the bridge's pinned (tgid,
    // start ticks) may connect here; before the supervisor pins it, and for any
    // other connector, the node is refused.
    if w.authorized == Some((st.st_dev, st.st_ino)) {
        let connector = crate::sync::lock(&w.authorized_connector);
        let admitted = matches!(
            (facts.tgid, facts.tgid_start, &*connector),
            (Some(tgid), Some(ticks), Some((want_tgid, want_ticks)))
                if tgid == *want_tgid && ticks == *want_ticks
        );
        if !admitted {
            return (Err(libc::EACCES), "proxy_bridge_only");
        }
        drop(connector);
        return match connect_pinned(dup, &node, w.stop_r.as_fd()) {
            Ok(()) => (Ok(()), "authorized_proxy"),
            Err(errno) => (Err(errno), "proxy_connect_failed"),
        };
    }
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
        sd.has_listener_for(want, w.stop_r.as_fd())
    };
    match listener_present {
        Ok(true) => {}
        Ok(false) => return (Err(libc::EACCES), "no_attempt_listener"),
        Err(_) => return (Err(libc::EACCES), "sock_diag_failed"),
    }
    match connect_pinned(dup, &node, w.stop_r.as_fd()) {
        Ok(()) => (Ok(()), "attempt_listener"),
        Err(e) => (Err(e), "connect_failed"),
    }
}

/// Connects the duplicate through the pinned node, so the kernel reaches
/// exactly the checked inode and not a path the child could swap.
fn connect_pinned(dup: &OwnedFd, node: &OwnedFd, stop_r: BorrowedFd<'_>) -> Result<(), i32> {
    let procpath = format!("/proc/self/fd/{}", node.as_raw_fd());
    let (addr, addr_len) = sockaddr_un(procpath.as_bytes());
    // SAFETY: `addr` is a live sockaddr_un; view its exact bytes as a slice for
    // the bounded connect helper.
    let addr_bytes = unsafe {
        std::slice::from_raw_parts(std::ptr::from_ref(&addr).cast::<u8>(), addr_len as usize)
    };
    bounded_connect(dup.as_fd(), addr_bytes, addr_len as usize, stop_r)
}

/// Perform a connect on `fd` without ever blocking a worker.
///
/// The socket is put non-blocking for the duration (the child is parked in the
/// notify wait, so this is invisible to it, and the flag is restored). A
/// connect that returns `EINPROGRESS` (TCP, or a Unix connect that is queued)
/// is polled to [`CONNECT_DEADLINE_MS`] or until stop; a Unix connect to a full
/// listener backlog returns `EAGAIN` immediately and becomes the child's result
/// — either way one slow or hostile peer cannot wedge the mediator. A stop
/// mid-connect fails the request closed.
fn bounded_connect(
    fd: BorrowedFd<'_>,
    sockaddr: &[u8],
    ualen: usize,
    stop_r: BorrowedFd<'_>,
) -> Result<(), i32> {
    let (fd, stop_r) = (fd.as_raw_fd(), stop_r.as_raw_fd());
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
            let polled = crate::platform::linux::sys::poll_fds(&mut pfds, CONNECT_DEADLINE_MS);
            if !polled.is_ok_and(|ready| ready > 0) {
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

/// `Tgid:` of a task in `/proc/<tid>/status`, or `None`.
fn task_tgid(tid: libc::pid_t) -> Option<libc::pid_t> {
    identity::status_field(tid, "Tgid").ok()?.parse().ok()
}

/// Sends `decision` as the child's `connect` return and records it with what
/// became of it: only a response the listener accepted is a known return.
fn respond_and_record(
    listener: BorrowedFd<'_>,
    id: u64,
    sink: &dyn MediationSink,
    facts: ConnectFacts,
    reason: &'static str,
    decision: Decision,
) {
    let error = match decision {
        Decision::Allowed => 0,
        Decision::Denied(errno) => -errno,
    };
    let delivery = match notif_send(listener, id, 0, error) {
        Ok(()) => Delivery::Delivered(decision),
        Err(_) => Delivery::Undelivered,
    };
    sink.record(MediationRecord {
        facts,
        reason,
        delivery,
    });
}

fn notif_recv(listener: BorrowedFd<'_>) -> io::Result<libc::seccomp_notif> {
    // SAFETY: `n` is a live, zeroed seccomp_notif the ioctl fills in.
    let mut n: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: `listener` is a live descriptor and `n` a live seccomp_notif
    // of the size SECCOMP_IOCTL_NOTIF_RECV writes.
    let rc = unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_RECV,
            std::ptr::from_mut(&mut n),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n)
}

// A notification is pending on the listener right now
/// Whether a notification is waiting to be received, by a `poll` that does
/// not wait. A closed or broken listener counts as pending, so the caller's
/// RECV reports the failure instead of this hiding it.
fn pending(listener: BorrowedFd<'_>) -> bool {
    crate::platform::linux::sys::poll_one(listener, libc::POLLIN, 0)
        .is_ok_and(|revents| revents != 0)
}

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

fn notif_id_valid(listener: BorrowedFd<'_>, id: u64) -> bool {
    let mut id = id;
    // SAFETY: the ioctl reads one u64 through the pointer; `id` is live.
    unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            std::ptr::from_mut(&mut id),
        ) == 0
    }
}

fn notif_send(listener: BorrowedFd<'_>, id: u64, val: i64, error: i32) -> io::Result<()> {
    let mut resp = libc::seccomp_notif_resp {
        id,
        val,
        error,
        flags: 0,
    };
    // SAFETY: `resp` is a live seccomp_notif_resp the ioctl reads.
    let rc = unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_SEND,
            std::ptr::from_mut(&mut resp),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

fn getsockopt_domain(fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
    let mut val: libc::c_int = 0;
    let mut len = u32::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
    // SAFETY: `val`/`len` are live and correctly sized for SO_DOMAIN.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
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

/// Resolve metadata in a stopped task's filesystem view without acquiring I/O authority.
pub(super) fn path_identity(pid: libc::pid_t, path: &[u8]) -> io::Result<(u64, u64)> {
    let root = open_o_path(&format!("/proc/{pid}/root"))?;
    let path = path_beneath_child_root(pid, root.as_fd(), path)?;
    let fd = openat2_in_root(root.as_fd(), &path)?;
    let stat = fstat(fd.as_raw_fd())?;
    Ok((stat.st_dev, stat.st_ino))
}

/// Express a relative address from the child's cwd beneath its *root*, not
/// beneath the cwd as a new root. `RESOLVE_IN_ROOT` then gives `..` and absolute
/// symlinks the same root boundary as the child has. The proc links supply only
/// a candidate prefix: reopening it beneath the pinned root and comparing both
/// the inode and mount ID to the pinned cwd rejects stale or aliased paths.
fn path_beneath_child_root(
    pid: libc::pid_t,
    root: BorrowedFd<'_>,
    path: &[u8],
) -> io::Result<Vec<u8>> {
    if path.first() == Some(&b'/') {
        return Ok(relative_bytes(path));
    }
    let cwd = open_o_path(&format!("/proc/{pid}/cwd"))?;
    let root_link = std::fs::read_link(format!("/proc/{pid}/root"))?;
    let cwd_link = std::fs::read_link(format!("/proc/{pid}/cwd"))?;
    if !root_link.is_absolute() || !cwd_link.is_absolute() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let prefix = cwd_link
        .strip_prefix(&root_link)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
        .as_os_str()
        .as_bytes();
    let same = if prefix.is_empty() {
        same_location(root.as_raw_fd(), cwd.as_raw_fd())?
    } else {
        let reopened = openat2_in_root(root, prefix)?;
        same_location(reopened.as_raw_fd(), cwd.as_raw_fd())?
    };
    if !same {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut full = Vec::with_capacity(prefix.len() + 1 + path.len());
    full.extend_from_slice(prefix);
    if !full.is_empty() {
        full.push(b'/');
    }
    full.extend_from_slice(path);
    Ok(full)
}

fn same_location(left: RawFd, right: RawFd) -> io::Result<bool> {
    fn identity(fd: RawFd) -> io::Result<(u64, u64)> {
        // SAFETY: statx is plain data; all-zero is a valid value.
        let mut st: libc::statx = unsafe { std::mem::zeroed() };
        // SAFETY: `statx` writes only to the live result, and AT_EMPTY_PATH
        // describes the supplied O_PATH directory descriptor itself.
        let rc = unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_INO | libc::STATX_MNT_ID,
                &raw mut st,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if st.stx_mask & (libc::STATX_INO | libc::STATX_MNT_ID)
            != libc::STATX_INO | libc::STATX_MNT_ID
        {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        Ok((st.stx_mnt_id, st.stx_ino))
    }
    Ok(identity(left)? == identity(right)?)
}

/// `openat2(base, rel, O_PATH, RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`
/// ([`fs::openat2`](crate::platform::linux::fs::openat2)).
///
/// `base` is always the child's root, so `..` and absolute symlinks cannot
/// escape the child's view (§3.4 step 3). An empty `rel` gets the kernel's
/// own answer, `ENOENT`, which `fs::openat2` gives no empty path the chance
/// to reach.
fn openat2_in_root(base: BorrowedFd<'_>, rel: &[u8]) -> io::Result<OwnedFd> {
    if rel.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    crate::platform::linux::fs::openat2(
        Some(base),
        std::path::Path::new(std::ffi::OsStr::from_bytes(rel)),
        libc::O_PATH | libc::O_CLOEXEC,
        libc::RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    )
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: stat is plain data; all-zero is a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a live stat the syscall fills in on success.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::unixpeer::CollectingSink;

    #[test]
    fn a_failed_notification_send_never_records_a_delivered_return() {
        let sink = CollectingSink::default();
        let facts = ConnectFacts {
            tid: 1,
            tgid: Some(1),
            tgid_start: None,
            family: Some(libc::AF_UNIX as u16),
            address_complete: true,
            peer: None,
        };
        // Not a notification listener: the send fails (ENOTTY).
        let not_a_listener = std::fs::File::open("/dev/null").unwrap();
        respond_and_record(
            not_a_listener.as_fd(),
            1,
            &sink,
            facts.clone(),
            "attempt_listener",
            Decision::Allowed,
        );
        let records = sink.drain();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].delivery, Delivery::Undelivered);
        assert_eq!(records[0].facts, facts);
    }

    /// Only a domain the kernel reported may reach the mediator's own
    /// connect; an unreadable one is refused like any uncertain branch.
    #[test]
    fn an_unreadable_socket_domain_refuses_and_never_connects() {
        assert_eq!(route(Ok(libc::AF_UNIX)), Route::Unix);
        assert_eq!(route(Ok(libc::AF_INET)), Route::NonUnix);
        assert_eq!(route(Ok(libc::AF_INET6)), Route::NonUnix);
        assert_eq!(
            route(Err(io::Error::from_raw_os_error(libc::ENOTSOCK))),
            Route::Refuse(libc::ENOTSOCK, "fd_not_a_socket")
        );
        for errno in [libc::EBADF, libc::ENOPROTOOPT, libc::EINVAL] {
            assert_eq!(
                route(Err(io::Error::from_raw_os_error(errno))),
                Route::Refuse(libc::EACCES, "domain_unreadable"),
                "errno {errno}"
            );
        }
    }
}
