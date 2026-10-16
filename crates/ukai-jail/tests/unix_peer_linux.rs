#![cfg(target_os = "linux")]
//! Live N05 for the unix-peer mediator, plus unit tests of its pure logic.
//!
//! jail-v1 §10, §15 N05/S03, CONTRACT §3.4. The mechanism was proved in the
//! unix-peer spike (`unixpeer-spike-2026-09-22-ouro-ci.txt`); these tests
//! exercise the *shipped module* — the real [`filter_bytes`],
//! [`take_from_launcher`] and [`spawn`] — rather than a reimplementation. A
//! small C program (`fixtures/unix_peer.c`) stands in for the trusted
//! launcher: it installs the filter
//! this crate produces (read from a file, never a second copy), opens a
//! `NETLINK_SOCK_DIAG` socket in the attempt's netns, hands both to the
//! supervisor, and connects on command. The supervisor is this test process,
//! running the module's mediator.
//!
//! One bubblewrap layer provides the namespaces (an unconfined process cannot
//! make its own on the reference host — the same AppArmor policy that denies
//! nesting). Tests skip with a reason when the backend is missing; under
//! `UKAI_CONFORMANCE=1` a skip is a failure.
//!
//! Nested cases (bwrap-in-bwrap IPC, proxy replacement in a nested netns) are
//! host-conditional: a user-namespace inner sandbox is EPERM on the reference
//! host, under Ubuntu's AppArmor userns restriction (CONTRACT §3.5).
//! [`nested_user_namespace_is_unavailable_here`] asserts that measurement
//! where it is a claim, on the reference host under `UKAI_CONFORMANCE=1`.

mod common;

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::observer::Fixture;

use ukai_jail::platform::linux::identity::pidfd_open;
use ukai_jail::platform::linux::unixpeer::{
    CollectingSink, Decision, Delivery, LauncherFds, filter_bytes, spawn, take_from_launcher,
};

// ---------------------------------------------------------------- unit tests

use ukai_jail::platform::linux::sockdiag::{Entry, SS_LISTEN, VfsId, has_listener_for, parse_dump};
use ukai_jail::platform::linux::unixpeer::{
    PeerAddr, base_for, classify, filter_digest, relative_bytes,
};

#[test]
fn pathname_and_abstract_addresses_classify() {
    let mut a = vec![1u8, 0];
    a.extend_from_slice(b"/attempt/x.sock\0");
    assert_eq!(
        classify(&a),
        PeerAddr::Pathname(b"/attempt/x.sock".to_vec())
    );

    let mut b = vec![1u8, 0, 0];
    b.extend_from_slice(b"scoped");
    assert_eq!(classify(&b), PeerAddr::Abstract(b"scoped".to_vec()));

    assert_eq!(classify(&[2u8, 0]), PeerAddr::NonUnix(2));
    assert_eq!(base_for(9, b"/a"), "/proc/9/root");
    assert_eq!(base_for(9, b"a"), "/proc/9/root");
    assert_eq!(relative_bytes(b"/a/b"), b"a/b");
}

#[test]
fn a_wide_inode_has_no_vfs_identity_and_is_denied() {
    assert!(VfsId::from_stat(u64::from(u32::MAX) + 1, 2049).is_none());
    assert_eq!(
        VfsId::from_stat(2534, 2049),
        Some(VfsId {
            ino: 2534,
            dev: 8_388_609
        })
    );
}

#[test]
fn the_parser_finds_only_a_matching_listener() {
    // one listening socket, VFS (2534, 8388609)
    let mut buf = Vec::new();
    buf.extend(unix_diag_msg(3, SS_LISTEN, 100, Some((2534, 8_388_609))));
    buf.extend(nlmsg_done(3));
    let mut out: Vec<Entry> = Vec::new();
    assert!(parse_dump(&buf, 3, &mut out).unwrap());
    assert!(has_listener_for(
        &out,
        VfsId {
            ino: 2534,
            dev: 8_388_609
        }
    ));
    assert!(!has_listener_for(&out, VfsId { ino: 1, dev: 1 }));
}

#[test]
fn the_filter_digest_is_stable() {
    assert!(filter_digest().starts_with("sha256:"));
    assert_eq!(filter_digest(), filter_digest());
    assert_eq!(filter_bytes().len() % 8, 0);
}

fn unix_diag_msg(seq: u32, state: u8, ino: u32, vfs: Option<(u32, u32)>) -> Vec<u8> {
    let mut body = vec![0u8; 16];
    body[0] = 1;
    body[1] = 1;
    body[2] = state;
    body[4..8].copy_from_slice(&ino.to_ne_bytes());
    if let Some((vino, vdev)) = vfs {
        body.extend_from_slice(&12u16.to_ne_bytes());
        body.extend_from_slice(&1u16.to_ne_bytes()); // UNIX_DIAG_VFS
        body.extend_from_slice(&vino.to_ne_bytes());
        body.extend_from_slice(&vdev.to_ne_bytes());
    }
    let total = 16 + body.len();
    let mut msg = Vec::new();
    msg.extend_from_slice(&u32::try_from(total).unwrap().to_ne_bytes());
    msg.extend_from_slice(&20u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    msg.extend_from_slice(&0u16.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&body);
    while msg.len() % 4 != 0 {
        msg.push(0);
    }
    msg
}

fn nlmsg_done(seq: u32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&16u32.to_ne_bytes());
    msg.extend_from_slice(&3u16.to_ne_bytes());
    msg.extend_from_slice(&0u16.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg
}

// ---------------------------------------------------------------- the launcher

/// The trusted-launcher stand-in (`fixtures/unix_peer.c`). It installs the
/// filter this crate produces (from a file), opens `NETLINK_SOCK_DIAG` in
/// this netns, binds the attempt's listeners, announces the two fd numbers,
/// then connects on command.
static FIXTURE: Fixture = Fixture {
    name: "unix_peer",
    source: include_str!("fixtures/unix_peer.c"),
    pthread: false,
    filter: filter_bytes,
};

// ---------------------------------------------------------------- the harness

/// One running sandbox: the launcher inside bwrap and the mediator in-process.
struct Rig {
    /// The coordination connection to the launcher, open until the rig is
    /// dropped.
    coord: Option<OwnedFd>,
    // bwrap's --info-fd read end, held open for bwrap's lifetime: bwrap keeps
    // writing its info JSON after the child pid, and closing the read end
    // early would make those writes fail EPIPE and bwrap exit 1 before the
    // launcher connected.
    _info: File,
    _coord_listener: OwnedFd,
    _host_listeners: Vec<OwnedFd>,
    child: libc::pid_t,
    _mediator: Option<ukai_jail::platform::linux::unixpeer::MediatorHandle>,
    sink: Arc<CollectingSink>,
    tmp: tempfile::TempDir,
    /// The abstract name this rig's host listener is bound to, in the host
    /// netns ([`host_abstract_name`]).
    host_abstract: String,
    tcp_port: u16,
    ia32_ok: bool,
}

impl Rig {
    /// Host-side path inside the attempt dir (bind-mounted at `/attempt`).
    fn attempt_host(&self, name: &str) -> std::path::PathBuf {
        self.tmp.path().join("attempt").join(name)
    }

    fn coord(&self) -> BorrowedFd<'_> {
        self.coord
            .as_ref()
            .expect("open until the rig is dropped")
            .as_fd()
    }
}

impl Rig {
    /// Connect (mediated) and return the child's observed errno string.
    fn run(&self, t: char, path: &str) -> String {
        self.run_raw(&format!("C {t} {path}"))
    }

    /// Send a raw coordination command (e.g. `L 300`, `F 40`) and read the reply.
    fn run_raw(&self, cmd: &str) -> String {
        send(self.coord(), cmd).expect("send a command to the launcher");
        recv(self.coord())
    }

    fn deliveries(&self) -> Vec<Delivery> {
        self.sink.drain().into_iter().map(|r| r.delivery).collect()
    }

    /// The next `count` records. A worker records after the kernel took its
    /// response, so the child can report its result first: wait a bounded
    /// time for the record to land.
    fn records(&self, count: usize) -> Vec<ukai_jail::platform::linux::unixpeer::MediationRecord> {
        /// How long a worker may take to record once the kernel took its
        /// response.
        const RECORD_BOUND: Duration = Duration::from_secs(5);
        let mut records = Vec::new();
        let _ = common::within(RECORD_BOUND, || {
            records.extend(self.sink.drain());
            records.len() >= count
        });
        records
    }
}

/// SIGKILLs and reaps a forked child on drop unless disarmed.
struct KillOnDrop(Option<libc::pid_t>);

impl KillOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // SAFETY: kill and waitpid take scalars and a pointer to a live
            // local. `pid` is the bwrap child this test forked and has not
            // reaped (whatever reaps it disarms the guard first), so the
            // number is still that child's. Nothing is left to do about a
            // failure in a drop on a failure path, so the results are not
            // read.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                let mut st = 0;
                libc::waitpid(pid, &raw mut st, 0);
            }
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        /// How long the launcher gets to act on "Q".
        const QUIT_GRACE: Duration = Duration::from_secs(3);
        // "Q" asks the launcher to exit, and closing the connection tells one
        // that missed it. A launcher already gone makes the send EPIPE, and
        // there is nothing to ask.
        if let Some(coord) = self.coord.take() {
            let _ = send(coord.as_fd(), "Q");
        }
        // Reap bwrap (the child this test started). A helper stuck in a
        // blocked syscall would never read "Q", so give it a short grace and
        // then SIGKILL bwrap (--die-with-parent takes the sandbox with it)
        // rather than block the test forever.
        let mut st = 0;
        let ended = common::within(QUIT_GRACE, || {
            // SAFETY: a non-blocking waitpid on the child this test forked,
            // with a pointer to a live local.
            let reaped = unsafe { libc::waitpid(self.child, &raw mut st, libc::WNOHANG) };
            // Reaped, or not this process's child to wait for at all (-1):
            // either way, signalling the number now could reach a stranger.
            reaped != 0
        });
        if !ended {
            // SAFETY: as above, and the last waitpid said the child is not
            // reaped, so the number is still its. As in `KillOnDrop`, a drop
            // has nothing to do about a failure, so the results are not read.
            unsafe {
                libc::kill(self.child, libc::SIGKILL);
                libc::waitpid(self.child, &raw mut st, 0);
            }
        }
    }
}

/// Send one coordination message: a SEQPACKET record, sent whole or not at
/// all.
fn send(fd: BorrowedFd<'_>, s: &str) -> std::io::Result<()> {
    // SAFETY: `fd` is a live socket for the call, and the buffer is `s`,
    // valid for `s.len()` bytes. MSG_NOSIGNAL: a peer that is gone is EPIPE
    // here, never a SIGPIPE.
    let sent = unsafe {
        libc::send(
            fd.as_raw_fd(),
            s.as_ptr().cast(),
            s.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if usize::try_from(sent).ok() != Some(s.len()) {
        return Err(std::io::Error::other(format!(
            "sent {sent} of {} bytes",
            s.len()
        )));
    }
    Ok(())
}

/// The next coordination message, or an empty string once the launcher hung
/// up. Fails the test after fifteen seconds of silence.
fn recv(fd: BorrowedFd<'_>) -> String {
    let mut b = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, and a count of one.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 500) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            assert_eq!(
                error.raw_os_error(),
                Some(libc::EINTR),
                "poll the launcher: {error}"
            );
        }
        if rc <= 0 {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for a launcher reply"
            );
            continue;
        }
        // SAFETY: `fd` is a live socket for the call, and `b` a live buffer of
        // `b.len()` bytes.
        let n = unsafe { libc::recv(fd.as_raw_fd(), b.as_mut_ptr().cast(), b.len(), 0) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        let Ok(n @ 1..) = usize::try_from(n) else {
            return String::new();
        };
        return String::from_utf8_lossy(&b[..n]).into_owned();
    }
}

/// Start the sandbox and the mediator. Returns `None` only on a genuine setup
/// failure (reported), never to hide a missing capability.
fn start_rig() -> Option<Rig> {
    let built = FIXTURE
        .build()
        .unwrap_or_else(|e| panic!("build helper: {e}"));
    let (helper, filter) = (&built.helper, &built.filter);
    let tmp = common::private_tempdir();
    let host_dir = tmp.path().join("host");
    let attempt_dir = tmp.path().join("attempt");
    let coord_dir = tmp.path().join("coord");
    for d in [&host_dir, &attempt_dir, &coord_dir] {
        std::fs::create_dir_all(d).unwrap();
    }

    // Host-netns sockets, bound by this process (the supervisor). Kept alive in
    // the Rig for the whole run so a real listener is present in the host netns.
    let host_sock = host_dir.join("host.sock");
    let mut host_listeners =
        vec![bind_listen(host_sock.to_str().unwrap(), false).expect("bind the host socket")];
    // Its hardlink alias. Without it that case would connect to a missing
    // path, which is denied too, and say nothing about aliases.
    std::fs::hard_link(&host_sock, host_dir.join("host-hardlink.sock"))
        .expect("hardlink the host socket");
    let host_abstract = host_abstract_name();
    host_listeners.push(bind_listen(&host_abstract, true).expect("bind the host abstract socket"));

    // Coordination socket (SEQPACKET, to match the launcher), bind-mounted
    // read-only into the sandbox at /coord.
    let coord_path = coord_dir.join("coord.sock");
    let coord_listener =
        bind_listen_ty(coord_path.to_str().unwrap(), false, libc::SOCK_SEQPACKET).expect("coord");

    let mut info = [0i32; 2];
    // SAFETY: pipe2 writes two descriptors into the two-element array it is
    // given, and reads nothing.
    let rc = unsafe { libc::pipe2(info.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2: {}", std::io::Error::last_os_error());
    // SAFETY: pipe2 just created both descriptors; nothing else owns them.
    let (info_r, info_w) =
        unsafe { (OwnedFd::from_raw_fd(info[0]), OwnedFd::from_raw_fd(info[1])) };
    let (info_r_raw, info_w_raw) = (info_r.as_raw_fd(), info_w.as_raw_fd());

    // Build the argv before forking: after fork() in this multi-threaded test
    // process, only async-signal-safe calls are allowed, so no allocation.
    let args = bwrap_args(
        helper,
        &host_dir,
        &attempt_dir,
        &coord_dir,
        filter,
        info_w_raw,
    );
    let cargs: Vec<std::ffi::CString> = args.iter().map(|a| cstr(a)).collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: fork has no memory preconditions; what the child may do after
    // it in a multi-threaded process is the block below.
    let child = unsafe { libc::fork() };
    // Before any guard holds it: a guard of -1 would SIGKILL every process
    // this user may signal.
    assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
    if child == 0 {
        // SAFETY: only async-signal-safe calls (close, fcntl, execv, _exit),
        // on descriptors and a NUL-terminated argv prepared before the fork;
        // the child never returns to Rust, so no destructor runs here.
        // Clearing FD_CLOEXEC hands bwrap the write end for --info-fd; a
        // child that cannot do that exits instead of running bwrap blind.
        unsafe {
            libc::close(info_r_raw);
            if libc::fcntl(info_w_raw, libc::F_SETFD, 0) != 0 {
                libc::_exit(126);
            }
            libc::execv(cargs[0].as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    // The parent's copy of the write end: bwrap holds its own.
    drop(info_w);

    // Kill and reap bwrap if anything below panics before the Rig (whose
    // Drop does the orderly shutdown) exists; otherwise a failed setup leaves
    // bwrap and its sandbox running with the helper waiting for "GO".
    let mut setup_guard = KillOnDrop(Some(child));
    let info = File::from(info_r);
    let init_pid = read_child_pid(&info);

    // Accept the launcher's coordination connection.
    accept_with_timeout(coord_listener.as_fd(), &mut setup_guard);
    // SAFETY: accept4 on a listening socket we own, with null address
    // pointers: the peer's address is not wanted.
    let coord = unsafe {
        libc::accept4(
            coord_listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    assert!(
        coord >= 0,
        "accept coord: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: accept4 just created this descriptor; nothing else owns it.
    let coord = unsafe { OwnedFd::from_raw_fd(coord) };

    let hello = recv(coord.as_fd());
    let parts: Vec<&str> = hello.split_whitespace().collect();
    if parts.first() != Some(&"HELLO") {
        panic!("launcher did not announce itself: {hello:?}");
    }
    let lfd: RawFd = parts[1].parse().unwrap();
    let dfd: RawFd = parts[2].parse().unwrap();
    let tcp_port: u16 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let ia32_ok: bool = parts.get(4).map(|s| *s == "1").unwrap_or(false);
    let lpid = find_launcher(init_pid, helper.to_str().unwrap());
    let pidfd = pidfd_open(lpid).expect("pidfd_open launcher");
    let authority = take_from_launcher(
        pidfd.as_fd(),
        LauncherFds {
            listener: lfd,
            sockdiag: dfd,
        },
    )
    .expect("take_from_launcher");
    let sink = Arc::new(CollectingSink::default());
    let mediator = spawn(authority, sink.clone() as Arc<_>).expect("spawn mediator");
    send(coord.as_fd(), "GO").expect("release the launcher");
    setup_guard.disarm();

    Some(Rig {
        coord: Some(coord),
        _info: info,
        _coord_listener: coord_listener,
        _host_listeners: host_listeners,
        child,
        _mediator: Some(mediator),
        sink,
        tmp,
        host_abstract,
        tcp_port,
        ia32_ok,
    })
}

/// An abstract name for one rig's host listener that no other rig holds.
/// Abstract names are one namespace per netns, and every rig binds its host
/// listener in the host netns while the tests of this binary run in parallel
/// in one process: a shared name made every rig but the first fail its bind
/// (EADDRINUSE). The pid keeps apart test processes running side by side.
fn host_abstract_name() -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!(
        "ukai-host-abstract-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn bwrap_args(
    helper: &std::path::Path,
    host_dir: &std::path::Path,
    attempt_dir: &std::path::Path,
    coord_dir: &std::path::Path,
    filter: &std::path::Path,
    info_fd: RawFd,
) -> Vec<String> {
    let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
    vec![
        common::bwrap_path().to_string_lossy().into_owned(),
        "--unshare-user".into(),
        "--unshare-ipc".into(),
        "--unshare-pid".into(),
        "--unshare-uts".into(),
        "--unshare-net".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        "--symlink".into(),
        "usr/bin".into(),
        "/bin".into(),
        "--symlink".into(),
        "usr/lib".into(),
        "/lib".into(),
        "--symlink".into(),
        "usr/lib64".into(),
        "/lib64".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--ro-bind".into(),
        s(helper),
        "/helper".into(),
        "--ro-bind".into(),
        s(filter),
        "/filter.bin".into(),
        "--bind".into(),
        s(host_dir),
        "/shared".into(),
        "--bind".into(),
        s(host_dir),
        "/shared2".into(),
        "--bind".into(),
        s(attempt_dir),
        "/attempt".into(),
        "--ro-bind".into(),
        s(coord_dir),
        "/coord".into(),
        "--info-fd".into(),
        info_fd.to_string(),
        "--die-with-parent".into(),
        "/helper".into(),
        "/coord/coord.sock".into(),
        "/attempt".into(),
        "/filter.bin".into(),
    ]
}

/// Poll for the coord connection, and if bwrap dies first, reap it and report
/// its status so a startup failure is a clear panic, not an accept() hang.
fn accept_with_timeout(listener: BorrowedFd<'_>, guard: &mut KillOnDrop) {
    let child = guard.0.expect("armed guard");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut pfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, and a count of one.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 200) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR), "poll: {error}");
        }
        if rc > 0 && pfd.revents & libc::POLLIN != 0 {
            return;
        }
        let mut st = 0;
        // SAFETY: a non-blocking waitpid on the child this test forked, with
        // a pointer to a live local.
        let w = unsafe { libc::waitpid(child, &raw mut st, libc::WNOHANG) };
        if w != 0 {
            // Reaped, or no child of ours to wait for: either way the guard
            // must not signal a number that may be someone else's now.
            guard.0 = None;
            assert!(
                w == child,
                "waitpid bwrap: {}",
                std::io::Error::last_os_error()
            );
            panic!(
                "bwrap exited before the launcher connected (status {st:#x}); \
                 no coordination connection"
            );
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the launcher to connect"
        );
    }
}

/// The pid of bwrap's child, from the JSON bwrap writes on `--info-fd`; 0
/// when none arrived within ten seconds.
fn read_child_pid(info: &File) -> libc::pid_t {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = Vec::new();
    let mut b = [0u8; 4096];
    while Instant::now() < deadline {
        match (&*info).read(&mut b) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&b[..n]);
                let s = String::from_utf8_lossy(&buf);
                if let Some(p) = s.find("\"child-pid\":") {
                    let num: String = s[p + 12..]
                        .chars()
                        .skip_while(|c| !c.is_ascii_digit())
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if let Ok(v) = num.parse() {
                        return v;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("read bwrap's info: {error}"),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    0
}

fn find_launcher(init_pid: libc::pid_t, helper: &str) -> libc::pid_t {
    let search = || {
        let mut stack = vec![init_pid];
        let mut seen = std::collections::HashSet::new();
        while let Some(p) = stack.pop() {
            if !seen.insert(p) {
                continue;
            }
            if let Ok(cmd) = std::fs::read(format!("/proc/{p}/cmdline")) {
                let argv0 = cmd.split(|c| *c == 0).next().unwrap_or(b"");
                // inside the sandbox the launcher's argv0 is "/helper"; the exe
                // link still points at the bound host path.
                if argv0 == b"/helper" || argv0 == helper.as_bytes() {
                    return Some(p);
                }
            }
            if let Ok(kids) = std::fs::read_to_string(format!("/proc/{p}/task/{p}/children")) {
                stack.extend(
                    kids.split_whitespace()
                        .filter_map(|t| t.parse::<libc::pid_t>().ok()),
                );
            }
        }
        None
    };
    let mut found = None;
    let _ = common::within(common::STEP_BOUND, || {
        found = search();
        found.is_some()
    });
    found.unwrap_or(0)
}

fn bind_listen(name: &str, abstract_: bool) -> Option<OwnedFd> {
    bind_listen_ty(name, abstract_, libc::SOCK_STREAM)
}

fn bind_listen_ty(name: &str, abstract_: bool, ty: libc::c_int) -> Option<OwnedFd> {
    // SAFETY: socket takes three scalars and returns a new descriptor or -1.
    let s = unsafe { libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0) };
    if s < 0 {
        return None;
    }
    // SAFETY: socket just created this descriptor; nothing else owns it.
    let s = unsafe { OwnedFd::from_raw_fd(s) };
    // SAFETY: sockaddr_un is plain data, and all zeroes is a valid value
    // (AF_UNSPEC, an empty path) that the lines below fill in.
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = name.as_bytes();
    let len = if abstract_ {
        for (i, b) in bytes.iter().enumerate() {
            a.sun_path[i + 1] = *b as libc::c_char;
        }
        2 + 1 + bytes.len()
    } else {
        // A socket left by an earlier run would make the bind EADDRINUSE;
        // none is the usual answer.
        let _ = std::fs::remove_file(name);
        for (i, b) in bytes.iter().enumerate() {
            a.sun_path[i] = *b as libc::c_char;
        }
        2 + bytes.len() + 1
    };
    assert!(
        len <= std::mem::size_of::<libc::sockaddr_un>(),
        "{name:?} does not fit a sockaddr_un"
    );
    // SAFETY: `a` is a live sockaddr_un and the kernel reads `len` bytes of
    // it, at most its size (asserted above).
    let bound = unsafe { libc::bind(s.as_raw_fd(), (&raw const a).cast(), len as libc::socklen_t) };
    // SAFETY: listen takes two scalars.
    if bound != 0 || unsafe { libc::listen(s.as_raw_fd(), 64) } != 0 {
        return None;
    }
    Some(s)
}

fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("no interior NUL")
}

// ---------------------------------------------------------------- live tests

#[test]
fn host_pathname_sockets_and_aliases_are_unreachable_but_attempt_sockets_work() {
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");

    // attempt-bound pathname listener: allowed.
    assert_eq!(
        rig.run('p', "/attempt/attempt.sock"),
        "0",
        "attempt pathname"
    );
    // attempt seqpacket: allowed.
    assert_eq!(
        rig.run('s', "/attempt/attempt_seq.sock"),
        "0",
        "attempt seqpacket"
    );
    // attempt abstract: allowed (netns-scoped).
    assert_eq!(
        rig.run('a', "ukai-attempt-abstract"),
        "0",
        "attempt abstract"
    );

    // host pathname (pre-existing), and its hardlink and bind-mount aliases:
    // all denied (host netns, no attempt listener) with EACCES.
    let eacces = libc::EACCES.to_string();
    assert_eq!(
        rig.run('p', "/shared/host.sock"),
        eacces,
        "host pre-existing"
    );
    assert_eq!(
        rig.run('p', "/shared/host-hardlink.sock"),
        eacces,
        "host hardlink"
    );
    assert_eq!(
        rig.run('p', "/shared2/host.sock"),
        eacces,
        "host bind-mount alias"
    );

    // late-created host socket, seen through the bound dir: still denied.
    let _late = bind_listen(
        rig.tmp
            .path()
            .join("host")
            .join("host-late.sock")
            .to_str()
            .unwrap(),
        false,
    );
    assert_eq!(
        rig.run('p', "/shared/host-late.sock"),
        eacces,
        "host late-created"
    );

    // host abstract: unreachable from the attempt netns (ECONNREFUSED, the
    // duplicate cannot find it, not an EACCES from the identity gate).
    assert_eq!(
        rig.run('a', &rig.host_abstract),
        libc::ECONNREFUSED.to_string(),
        "host abstract"
    );

    // AF_UNIX SOCK_DGRAM / SOCK_RAW creation: refused by the filter.
    assert_eq!(rig.run('d', "-"), libc::EPERM.to_string(), "dgram create");
    assert_eq!(rig.run('r', "-"), libc::EPERM.to_string(), "raw create");

    // The mediator recorded a delivered decision per mediated connect: the
    // allowed ones Allowed, the denied ones Denied(EACCES) for pathname
    // identity failures.
    let deliveries = rig.deliveries();
    assert!(
        deliveries.contains(&Delivery::Delivered(Decision::Allowed)),
        "expected at least one delivered Allowed: {deliveries:?}"
    );
    assert!(
        deliveries.contains(&Delivery::Delivered(Decision::Denied(libc::EACCES))),
        "expected a delivered Denied(EACCES) for a host pathname: {deliveries:?}"
    );
}

#[test]
fn relative_parent_and_absolute_symlink_reach_the_same_attempt_socket() {
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");
    std::fs::create_dir(rig.attempt_host("sub")).unwrap();
    std::os::unix::fs::symlink(
        "/attempt/attempt.sock",
        rig.attempt_host("sub/absolute.sock"),
    )
    .unwrap();

    assert_eq!(
        rig.run('w', "../attempt.sock"),
        "0",
        "relative .. must ascend from cwd within the child root"
    );
    assert_eq!(
        rig.run('w', "absolute.sock"),
        "0",
        "an absolute symlink must restart at the child root"
    );
}

#[test]
fn a_connect_fails_closed_when_the_mediator_stops() {
    if !common::live() {
        return;
    }
    let mut rig = start_rig().expect("rig");
    // A baseline mediated connect works.
    assert_eq!(rig.run('p', "/attempt/attempt.sock"), "0");
    // Stop the mediator: the listener closes, so the next connect gets ENOSYS
    // (USER_NOTIF with no listener), never proceeds unmediated.
    if let Some(m) = rig._mediator.take() {
        m.stop();
    }
    assert_eq!(
        rig.run('p', "/attempt/attempt.sock"),
        libc::ENOSYS.to_string(),
        "fail-closed"
    );
}

/// `stop()` is bounded however the pool was woken. RECV ignores
/// `O_NONBLOCK`, so a worker that lost the race for a notification can
/// sleep inside it where the stop pipe cannot reach it, and joining it would
/// hang (the binary hung in the test above when it did). Attempted: bursts of
/// concurrent mediated connects, which wake several workers per
/// notification, then `stop()` on its own thread. Verdict: every connect is
/// answered, and `stop()` returns within a few seconds every time.
#[test]
fn stop_returns_after_bursts_of_concurrent_connects() {
    if !common::live() {
        return;
    }
    for round in 0..5 {
        let mut rig = start_rig().expect("rig");
        for _ in 0..8 {
            assert_eq!(rig.run_raw("F 16"), "done 16", "round {round}");
        }
        let mediator = rig._mediator.take().expect("a mediator");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            mediator.stop();
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(10)).is_ok(),
            "round {round}: stop() did not return: a worker is stuck in NOTIF_RECV"
        );
    }
}

/// Review fix 1: the filter is safe on its own — a connect issued through a
/// non-native ABI (x32, and i386 int-0x80 where the kernel offers it) is
/// refused, never allowed through unmediated. `EPERM` is the filter's denial;
/// `ENOSYS` means the kernel does not offer that ABI, which is also a refusal.
/// The old filter allowed non-native architectures, so a connect through them
/// reached the peer unmediated: this test caught that.
#[test]
fn non_native_abi_connects_are_refused() {
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");
    let refused = |r: &str| {
        let e: i32 = r.trim().parse().unwrap_or(0);
        e == libc::EPERM || e == libc::ENOSYS
    };
    // x32 shares the x86_64 audit arch; the filter must deny it via the x32 bit.
    let x32 = rig.run('x', "/attempt/attempt.sock");
    assert!(
        refused(&x32),
        "x32 connect must be refused (EPERM/ENOSYS), got {x32:?}"
    );
    // i386 int-0x80, only where the kernel offers the ABI.
    if rig.ia32_ok {
        let i386 = rig.run('i', "/attempt/attempt.sock");
        assert!(
            refused(&i386),
            "i386 connect must be refused (EPERM/ENOSYS), got {i386:?}"
        );
    }
    // Sanity: the native ABI is still mediated and allowed for the attempt sock.
    assert_eq!(
        rig.run('p', "/attempt/attempt.sock"),
        "0",
        "native still works"
    );
}

/// A connect on a descriptor that is not a socket: its `SO_DOMAIN` cannot be
/// read, which says nothing about the family, so the mediator refuses with
/// the kernel's own answer and a named reason instead of performing a
/// connect of its own on the duplicate, as an unknown domain otherwise
/// would.
#[test]
fn a_connect_on_a_non_socket_is_refused_before_any_mediated_connect() {
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");
    let _ = rig.sink.drain();
    assert_eq!(
        rig.run('n', "/attempt/attempt.sock"),
        libc::ENOTSOCK.to_string()
    );
    let records = rig.records(1);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].reason, "fd_not_a_socket");
    assert_eq!(
        records[0].delivery,
        Delivery::Delivered(Decision::Denied(libc::ENOTSOCK))
    );
}

/// Review fix 3, mutation M9 (domain check): a TCP connect is decided by the
/// socket's `SO_DOMAIN`, not the address bytes. Removing that check routes a
/// TCP connect down the AF_UNIX classifier, which reports `EAFNOSUPPORT`; with
/// the check it is a real connect result. Assert it is never `EAFNOSUPPORT`.
#[test]
fn mutation_domain_check_a_tcp_connect_is_not_family_mismatched() {
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");
    let r = rig.run('t', &rig.tcp_port.to_string());
    let e: i32 = r.trim().parse().unwrap_or(-1);
    assert_ne!(
        e,
        libc::EAFNOSUPPORT,
        "a TCP connect must be handled by the domain check, not the unix classifier: {r:?}"
    );
}

/// Review fix 3, mutation M3 (S_ISSOCK) and M7 (listener state) and M2/M10
/// (RESOLVE_IN_ROOT / RESOLVE_NO_MAGICLINKS): each guard produces a distinct
/// errno for a crafted node, so removing it changes the observed result.
#[test]
fn mutation_pathname_guards_each_produce_their_distinct_denial() {
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");

    // M3 S_ISSOCK: a regular file is ECONNREFUSED (not_a_socket); without the
    // check it would fall through to the sock_diag lookup and be EACCES.
    std::fs::write(rig.attempt_host("regfile"), b"x").unwrap();
    assert_eq!(
        rig.run('p', "/attempt/regfile"),
        libc::ECONNREFUSED.to_string(),
        "M3: a non-socket node must be ECONNREFUSED"
    );

    // M7 listener state: a bound-but-not-listening socket has a VFS identity but
    // is not SS_LISTEN, so it is EACCES (no listener); without the state check
    // it would match and be connected (ECONNREFUSED).
    assert_eq!(
        rig.run('b', "/attempt/bound_nolisten.sock"),
        "0",
        "bind (no listen) should succeed"
    );
    assert_eq!(
        rig.run('p', "/attempt/bound_nolisten.sock"),
        libc::EACCES.to_string(),
        "M7: a bound-but-not-listening socket must be EACCES"
    );

    // Magic links must not be traversed during resolution: a symlink to a /proc
    // magic link resolves to EACCES (path_unresolved). This is enforced jointly
    // by RESOLVE_IN_ROOT (which per openat2(2) itself blocks magic-link jumps)
    // and RESOLVE_NO_MAGICLINKS. Dropping the whole resolve safety (both flags)
    // is caught by the `absroot` case above (M2); dropping NO_MAGICLINKS alone
    // is a benign no-op here because RESOLVE_IN_ROOT already blocks magic links.
    let _ = std::fs::remove_file(rig.attempt_host("maglink"));
    std::os::unix::fs::symlink("/proc/1/cwd", rig.attempt_host("maglink")).unwrap();
    assert_eq!(
        rig.run('p', "/attempt/maglink"),
        libc::EACCES.to_string(),
        "a magic-link symlink must not be traversed"
    );

    // M2 RESOLVE_IN_ROOT: an absolute symlink whose target is a host-side path
    // resolves inside the child's root, where that path does not exist -> EACCES
    // (path_unresolved). Without RESOLVE_IN_ROOT the absolute target would be
    // followed in the supervisor's root and reach the attempt socket (allowed),
    // a different result the mutation would produce.
    let abs_host = rig.attempt_host("attempt.sock");
    let _ = std::fs::remove_file(rig.attempt_host("absroot"));
    std::os::unix::fs::symlink(&abs_host, rig.attempt_host("absroot")).unwrap();
    assert_eq!(
        rig.run('p', "/attempt/absroot"),
        libc::ENOENT.to_string(),
        "M2: an absolute symlink must resolve inside the child's root"
    );
}

/// Review fix 2: a full listener backlog cannot wedge the mediator. The
/// attempt listener has a backlog of 64 and is never accepted; the child issues
/// far more connects than that. With a blocking mediator the connect on the
/// duplicate would block once the backlog filled and stall every request; the
/// non-blocking bounded connect returns promptly for each.
#[test]
fn a_full_backlog_does_not_wedge_the_mediator() {
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");
    // 300 sequential connects (>> the backlog of 64). The helper replies "done"
    // only after all of them return; `recv` bounds the wait, so a wedge fails
    // the test rather than hanging.
    assert_eq!(
        rig.run_raw("L 300"),
        "done",
        "the mediator serviced a full backlog"
    );
    // The mediator is still responsive afterwards: a connect to a *different*
    // listener with an empty backlog succeeds promptly (the attempt.sock backlog
    // is now full, so a connect to it would return EAGAIN — also a prompt,
    // non-wedged reply, not a hang).
    assert_eq!(
        rig.run('s', "/attempt/attempt_seq.sock"),
        "0",
        "mediator still responsive"
    );
}

/// Review fix 2: many concurrent connects are all serviced (the worker pool),
/// and `stop()` returns within a bound even with requests in flight (the
/// outstanding ones fail closed).
#[test]
fn concurrent_connects_are_serviced_and_stop_is_bounded() {
    if !common::live() {
        return;
    }
    let mut rig = start_rig().expect("rig");
    // 40 concurrent connects to the never-accepted attempt listener.
    assert_eq!(
        rig.run_raw("F 40"),
        "done 40",
        "all concurrent children completed"
    );

    // Fire another wave and stop the mediator while it is in flight; stop() must
    // return within a bound. The helper reply for the wave may or may not
    // arrive; we only require the stop to be prompt.
    send(rig.coord(), "F 40").expect("send the second wave");
    let m = rig._mediator.take().expect("mediator");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        m.stop();
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(8)).is_ok(),
        "stop() must return within a bound even with connects in flight"
    );
    // Drain whatever the helper replied so Drop's teardown is clean.
    let _ = recv(rig.coord());
}

/// Review fix 3, mutation M1 (notification-id revalidation). A forked child
/// connects a host socket and is killed while a worker is deliberately delayed
/// mid-mediation (the delay knob widens the task-death window). With the id
/// revalidation the worker sees the notification is stale and drops it
/// silently, so the sink stays empty; removing the revalidation makes the
/// worker act on the dead task and emit a record, turning this test red.
#[test]
fn mutation_id_revalidation_drops_a_stale_notification() {
    use std::sync::atomic::Ordering;
    if !common::live() {
        return;
    }
    let rig = start_rig().expect("rig");
    let _ = rig.sink.drain();
    // Hold each mediation for 300ms so the child can be killed (at ~50ms) before
    // the worker acts on its notification.
    ukai_jail::platform::linux::unixpeer::MEDIATION_TEST_DELAY_MS.store(300, Ordering::Relaxed);
    assert_eq!(rig.run_raw("K /shared/host.sock"), "killed");
    // Let the delayed worker finish and revalidate.
    std::thread::sleep(Duration::from_millis(500));
    ukai_jail::platform::linux::unixpeer::MEDIATION_TEST_DELAY_MS.store(0, Ordering::Relaxed);
    let records = rig.sink.drain();
    assert!(
        records.is_empty(),
        "a stale notification (killed task) must be dropped without a record: {records:?}"
    );
}

/// The reference host's measurement (CONTRACT §3.5): a user-namespace inner
/// sandbox (bwrap-in-bwrap) is EPERM there, under Ubuntu's AppArmor
/// restriction of unprivileged user namespaces, so nested-userns IPC and
/// proxy replacement in a nested netns are host-conditional. That is a
/// property of the provisioned host, not of Linux, so it is judged under
/// `UKAI_CONFORMANCE=1` and skipped elsewhere, whatever the measurement would
/// say there. A host that permits nested user namespaces leaves the nested
/// cases to the `agent` end-to-end tests, which own the inner sandbox.
#[test]
fn nested_user_namespace_is_unavailable_here() {
    if !common::live() || !common::reference_host("Ubuntu's AppArmor userns restriction") {
        return;
    }
    match measure_nested_userns() {
        // The inner sandbox's failure is visible, never hidden or claimed as
        // running.
        NestedUserns::Denied => {}
        NestedUserns::Works => panic!(
            "a nested user namespace works on the reference host: its AppArmor \
             userns restriction is not in force, so the nested IPC and \
             proxy-replacement cases are not host-conditional there"
        ),
        NestedUserns::Unknown(reason) => panic!("could not measure nested userns: {reason}"),
    }
}

enum NestedUserns {
    Denied,
    Works,
    Unknown(String),
}

/// Measure whether a *usable* user namespace can be created inside one bwrap
/// layer — the capability a bwrap-in-bwrap inner sandbox (nested IPC, proxy
/// replacement in a nested netns) actually needs. A capability-less nested
/// userns is not enough: it must map a uid and create a mount+net namespace,
/// which is `unshare -Urmn`. On a stock host with
/// `apparmor_restrict_unprivileged_userns=1` this is EPERM; on a permissive
/// host it succeeds, and the nested cases become live (owned by the `agent`
/// end-to-end tests).
fn measure_nested_userns() -> NestedUserns {
    let bwrap = common::bwrap_path();
    let out = Command::new(bwrap)
        .args([
            "--unshare-user",
            "--unshare-net",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "/usr/bin/unshare",
            "-U",
            "-r",
            "-m",
            "-n",
            "/bin/true",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => NestedUserns::Works,
        Ok(_) => NestedUserns::Denied,
        Err(e) => NestedUserns::Unknown(e.to_string()),
    }
}
