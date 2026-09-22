#![cfg(target_os = "linux")]
//! Live N05 for the unix-peer mediator, plus unit tests of its pure logic.
//!
//! jail-v1 §10, §15 N05/S03, CONTRACT §3.4. The mechanism was proved in the
//! J3 spike (`unixpeer-spike-2026-09-2x-ouro-ci.txt`); these tests exercise the
//! *shipped module* — the real [`filter_bytes`], [`take_from_launcher`] and
//! [`spawn`] — rather than a reimplementation. A small C program stands in for
//! the trusted launcher: it installs the filter this crate produces (read from
//! a file, never a second copy), opens a `NETLINK_SOCK_DIAG` socket in the
//! attempt's netns, hands both to the supervisor, and connects on command. The
//! supervisor is this test process, running the module's mediator.
//!
//! One bubblewrap layer provides the namespaces (an unconfined process cannot
//! make its own on the reference host — the same AppArmor policy that denies
//! nesting). Tests skip with a reason when the backend is missing; under
//! `OURO_CONFORMANCE=1` a skip is a failure.
//!
//! Nested cases (bwrap-in-bwrap IPC, proxy replacement in a nested netns) are
//! host-conditional: a user-namespace inner sandbox is EPERM on a stock host
//! (CONTRACT §3.5). [`nested_user_namespace_is_unavailable_here`] asserts that
//! honest measurement rather than skipping, and is written so a host that does
//! permit nested userns would exercise the real nested path.

mod common;

use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ouro_fixture::harness;
use ouro_jail::platform::linux::identity::pidfd_open;
use ouro_jail::platform::linux::unixpeer::{
    CollectingSink, LauncherFds, Verdict, filter_bytes, spawn, take_from_launcher,
};

// ---------------------------------------------------------------- unit tests

use ouro_jail::platform::linux::sockdiag::{Entry, SS_LISTEN, VfsId, has_listener_for, parse_dump};
use ouro_jail::platform::linux::unixpeer::{
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
    assert_eq!(base_for(9, b"a"), "/proc/9/cwd");
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

/// The trusted-launcher stand-in. It installs the filter this crate produces
/// (from a file), opens `NETLINK_SOCK_DIAG` in this netns, binds the attempt's
/// listeners, announces the two fd numbers, then connects on command.
const HELPER_C: &str = r##"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL<<3)
#endif
#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL<<5)
#endif
#define NETLINK_SOCK_DIAG 4

static int connect_un_type(int type, const char *name, int abstract) {
    int s = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
    if (s < 0) return errno;
    struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
    size_t n = strlen(name);
    socklen_t len;
    if (abstract) { a.sun_path[0]=0; memcpy(a.sun_path+1,name,n); len=2+1+n; }
    else { memcpy(a.sun_path,name,n); len=2+n+1; }
    int r = connect(s,(void*)&a,len);
    int e = r==0?0:errno;
    close(s);
    return e;
}

static int bind_listen(int type, const char *name, int abstract) {
    int s = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
    size_t n = strlen(name);
    socklen_t len;
    if (abstract) { a.sun_path[0]=0; memcpy(a.sun_path+1,name,n); len=2+1+n; }
    else { unlink(name); memcpy(a.sun_path,name,n); len=2+n+1; }
    if (bind(s,(void*)&a,len)) return -1;
    if (listen(s,64)) return -1;
    return s;
}

int main(int argc, char **argv) {
    const char *coord_path = argv[1];
    const char *attempt_dir = argv[2];
    const char *filter_file = argv[3];

    int coord = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
    struct sockaddr_un ca; memset(&ca,0,sizeof ca); ca.sun_family=AF_UNIX;
    strncpy(ca.sun_path, coord_path, sizeof(ca.sun_path)-1);
    if (connect(coord,(void*)&ca,sizeof ca)) { return 3; }

    char p[512];
    snprintf(p,sizeof p,"%s/attempt.sock",attempt_dir);
    if (bind_listen(SOCK_STREAM,p,0) < 0) { dprintf(coord,"FATAL bind attempt"); return 1; }
    snprintf(p,sizeof p,"%s/attempt_seq.sock",attempt_dir);
    if (bind_listen(SOCK_SEQPACKET,p,0) < 0) { dprintf(coord,"FATAL bind seq"); return 1; }
    if (bind_listen(SOCK_STREAM,"ouro-attempt-abstract",1) < 0) { dprintf(coord,"FATAL bind abs"); return 1; }

    /* read the filter file into a sock_filter array */
    FILE *f = fopen(filter_file,"rb");
    if (!f) { dprintf(coord,"FATAL open filter"); return 1; }
    static struct sock_filter prog[256];
    size_t got = fread(prog,8,256,f); fclose(f);
    struct sock_fprog fp = { (unsigned short)got, prog };
    prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    long listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER|SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, &fp);
    if (listener < 0) { dprintf(coord,"FATAL seccomp %d", errno); return 1; }
    int diag = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG);

    dprintf(coord,"HELLO %ld %d", listener, diag);

    char buf[512];
    for (;;) {
        ssize_t k = read(coord, buf, sizeof(buf)-1);
        if (k <= 0) return 0;
        buf[k]=0;
        if (buf[0]=='Q') return 0;
        /* GO: the supervisor has taken both fds with pidfd_getfd, so close our
           copies (as the real launcher closes them before exec). Only then does
           the supervisor closing its copy fully close the listener, which is
           what makes a later connect fail ENOSYS (fail-closed). */
        if (!strncmp(buf,"GO",2)) { close((int)listener); close(diag); continue; }
        /* "C <t> <path>" : t in p(stream path) s(seqpacket) a(abstract) d(dgram-create) t(tcp) */
        char t=buf[2];
        char *path = buf+4;
        int e;
        if (t=='d') { int s=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0); e=s<0?errno:0; if(s>=0)close(s); }
        else if (t=='r') { int s=socket(AF_UNIX,SOCK_RAW|SOCK_CLOEXEC,0); e=s<0?errno:0; if(s>=0)close(s); }
        else if (t=='a') e=connect_un_type(SOCK_STREAM,path,1);
        else if (t=='s') e=connect_un_type(SOCK_SEQPACKET,path,0);
        else e=connect_un_type(SOCK_STREAM,path,0);
        dprintf(coord,"%d", e);
    }
}
"##;

fn build() -> Result<&'static (PathBuf, PathBuf), String> {
    static BUILD: OnceLock<Result<(PathBuf, PathBuf), String>> = OnceLock::new();
    BUILD
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("ouro-j3-unixpeer-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            let source = dir.join("helper.c");
            std::fs::write(&source, HELPER_C).map_err(|e| format!("write helper.c: {e}"))?;
            let helper = dir.join("helper");
            let out = Command::new("/usr/bin/gcc")
                .args(["-O1", "-Wall", "-B/usr/bin", "-o"])
                .arg(&helper)
                .arg(&source)
                .output()
                .map_err(|e| format!("run gcc: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "gcc failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            let filter = dir.join("filter.bin");
            std::fs::write(&filter, filter_bytes())
                .map_err(|e| format!("write filter.bin: {e}"))?;
            Ok((helper, filter))
        })
        .as_ref()
        .map_err(Clone::clone)
}

// ---------------------------------------------------------------- the harness

/// One running sandbox: the launcher inside bwrap and the mediator in-process.
struct Rig {
    coord: RawFd,
    _coord_listener: OwnedFd,
    _host_listeners: Vec<OwnedFd>,
    child: libc::pid_t,
    _mediator: Option<ouro_jail::platform::linux::unixpeer::MediatorHandle>,
    sink: Arc<CollectingSink>,
    tmp: tempfile::TempDir,
}

impl Rig {
    /// Connect (mediated) and return the child's observed errno string.
    fn run(&self, t: char, path: &str) -> String {
        send(self.coord, &format!("C {t} {path}"));
        recv(self.coord)
    }

    fn verdicts(&self) -> Vec<Verdict> {
        self.sink.drain().into_iter().map(|r| r.verdict).collect()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        send(self.coord, "Q");
        // SAFETY: closing our coord fd, then reaping bwrap (the child we
        // started). A helper stuck in a blocked syscall would never read "Q",
        // so give it a short grace and then SIGKILL bwrap (--die-with-parent
        // takes the sandbox with it) rather than block the test forever.
        unsafe {
            libc::close(self.coord);
            let mut st = 0;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if libc::waitpid(self.child, &raw mut st, libc::WNOHANG) == self.child {
                    break;
                }
                if Instant::now() >= deadline {
                    libc::kill(self.child, libc::SIGKILL);
                    libc::waitpid(self.child, &raw mut st, 0);
                    break;
                }
                libc::usleep(20_000);
            }
        }
        let _ = &self.tmp;
    }
}

fn send(fd: RawFd, s: &str) {
    // SAFETY: writing a byte slice to a connected socket fd.
    unsafe {
        libc::send(fd, s.as_ptr().cast(), s.len(), 0);
    }
}

fn recv(fd: RawFd) -> String {
    let mut b = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: single live pollfd.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 500) };
        if rc == 0 {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for a launcher reply"
            );
            continue;
        }
        // SAFETY: reading into a live buffer of known length.
        let n = unsafe { libc::recv(fd, b.as_mut_ptr().cast(), b.len(), 0) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return String::new();
        }
        return String::from_utf8_lossy(&b[..n as usize]).into_owned();
    }
}

/// Start the sandbox and the mediator. Returns `None` only on a genuine setup
/// failure (reported), never to hide a missing capability.
fn start_rig() -> Option<Rig> {
    let (helper, filter) = build().unwrap_or_else(|e| panic!("build helper: {e}"));
    let tmp = common::private_tempdir();
    let host_dir = tmp.path().join("host");
    let attempt_dir = tmp.path().join("attempt");
    let coord_dir = tmp.path().join("coord");
    for d in [&host_dir, &attempt_dir, &coord_dir] {
        std::fs::create_dir_all(d).unwrap();
    }

    // Host-netns sockets, bound by this process (the supervisor). Kept alive in
    // the Rig for the whole run so a real listener is present in the host netns.
    let mut host_listeners = Vec::new();
    let host_sock = host_dir.join("host.sock");
    if let Some(l) = bind_listen(host_sock.to_str().unwrap(), false) {
        host_listeners.push(l);
    }
    let host_hardlink = host_dir.join("host-hardlink.sock");
    // SAFETY: link() of two live C strings. A failure here just means the
    // hardlink case resolves to a missing path (still denied), so it is not
    // fatal to the test.
    {
        let a = cstr(host_sock.to_str().unwrap());
        let b = cstr(host_hardlink.to_str().unwrap());
        unsafe { libc::link(a.as_ptr(), b.as_ptr()) };
    }
    if let Some(l) = bind_listen("ouro-host-abstract", true) {
        host_listeners.push(l);
    }

    // Coordination socket (SEQPACKET, to match the launcher), bind-mounted
    // read-only into the sandbox at /coord.
    let coord_path = coord_dir.join("coord.sock");
    let coord_listener =
        bind_listen_ty(coord_path.to_str().unwrap(), false, libc::SOCK_SEQPACKET).expect("coord");

    let mut info = [0i32; 2];
    // SAFETY: two-element array for pipe2.
    assert_eq!(
        unsafe { libc::pipe2(info.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let (info_r, info_w) = (info[0], info[1]);

    // Build the argv before forking: after fork() in this multi-threaded test
    // process, only async-signal-safe calls are allowed, so no allocation.
    let args = bwrap_args(helper, &host_dir, &attempt_dir, &coord_dir, filter, info_w);
    let cargs: Vec<std::ffi::CString> = args.iter().map(|a| cstr(a)).collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: fork; the child execs bwrap and never returns to Rust on success.
    // Everything after fork is async-signal-safe (close, fcntl, execv).
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(info_r);
            libc::fcntl(info_w, libc::F_SETFD, 0);
            libc::execv(cargs[0].as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    // SAFETY: closing the write end we own in the parent.
    unsafe { libc::close(info_w) };

    let init_pid = read_child_pid(info_r);
    // SAFETY: closing the read end we own.
    unsafe { libc::close(info_r) };

    // Accept the launcher's coordination connection.
    accept_with_timeout(coord_listener.as_raw_fd(), child);
    // SAFETY: accept on a listening socket we own; readiness confirmed above.
    let coord = unsafe {
        libc::accept(
            coord_listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(
        coord >= 0,
        "accept coord: {}",
        std::io::Error::last_os_error()
    );

    let hello = recv(coord);
    let parts: Vec<&str> = hello.split_whitespace().collect();
    if parts.first() != Some(&"HELLO") {
        panic!("launcher did not announce itself: {hello:?}");
    }
    let lfd: RawFd = parts[1].parse().unwrap();
    let dfd: RawFd = parts[2].parse().unwrap();
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
    send(coord, "GO");

    Some(Rig {
        coord,
        _coord_listener: coord_listener,
        _host_listeners: host_listeners,
        child,
        _mediator: Some(mediator),
        sink,
        tmp,
    })
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
fn accept_with_timeout(listener: RawFd, child: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut pfd = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: single live pollfd.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 200) };
        if rc > 0 && pfd.revents & libc::POLLIN != 0 {
            return;
        }
        let mut st = 0;
        // SAFETY: waitpid on the child we started, non-blocking.
        let w = unsafe { libc::waitpid(child, &raw mut st, libc::WNOHANG) };
        if w == child {
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

fn read_child_pid(fd: RawFd) -> libc::pid_t {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = Vec::new();
    let mut b = [0u8; 4096];
    while Instant::now() < deadline {
        // SAFETY: reading into a live buffer.
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), b.len()) };
        if n > 0 {
            buf.extend_from_slice(&b[..n as usize]);
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
        } else if n == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    0
}

fn find_launcher(init_pid: libc::pid_t, helper: &str) -> libc::pid_t {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
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
                    return p;
                }
            }
            if let Ok(kids) = std::fs::read_to_string(format!("/proc/{p}/task/{p}/children")) {
                stack.extend(
                    kids.split_whitespace()
                        .filter_map(|t| t.parse::<libc::pid_t>().ok()),
                );
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    0
}

fn bind_listen(name: &str, abstract_: bool) -> Option<OwnedFd> {
    bind_listen_ty(name, abstract_, libc::SOCK_STREAM)
}

fn bind_listen_ty(name: &str, abstract_: bool, ty: libc::c_int) -> Option<OwnedFd> {
    // SAFETY: socket()/bind()/listen() with a locally-built sockaddr_un.
    unsafe {
        let s = libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return None;
        }
        let mut a: libc::sockaddr_un = std::mem::zeroed();
        a.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = name.as_bytes();
        let len = if abstract_ {
            for (i, b) in bytes.iter().enumerate() {
                a.sun_path[i + 1] = *b as libc::c_char;
            }
            2 + 1 + bytes.len()
        } else {
            let _ = libc::unlink(cstr(name).as_ptr());
            for (i, b) in bytes.iter().enumerate() {
                a.sun_path[i] = *b as libc::c_char;
            }
            2 + bytes.len() + 1
        };
        if libc::bind(s, (&raw const a).cast(), len as libc::socklen_t) != 0
            || libc::listen(s, 64) != 0
        {
            libc::close(s);
            return None;
        }
        Some(OwnedFd::from_raw_fd(s))
    }
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
        rig.run('a', "ouro-attempt-abstract"),
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
        rig.run('a', "ouro-host-abstract"),
        libc::ECONNREFUSED.to_string(),
        "host abstract"
    );

    // AF_UNIX SOCK_DGRAM / SOCK_RAW creation: refused by the filter.
    assert_eq!(rig.run('d', "-"), libc::EPERM.to_string(), "dgram create");
    assert_eq!(rig.run('r', "-"), libc::EPERM.to_string(), "raw create");

    // The mediator recorded a verdict per mediated connect: the allowed ones
    // Allowed, the denied ones Denied(EACCES) for pathname identity failures.
    let verdicts = rig.verdicts();
    assert!(
        verdicts.contains(&Verdict::Allowed),
        "expected at least one Allowed verdict: {verdicts:?}"
    );
    assert!(
        verdicts.contains(&Verdict::Denied(libc::EACCES)),
        "expected a Denied(EACCES) for a host pathname: {verdicts:?}"
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

/// The stock-host measurement (CONTRACT §3.5): a user-namespace inner sandbox
/// (bwrap-in-bwrap) is EPERM here, so nested-userns IPC and proxy replacement
/// in a nested netns are host-conditional. This asserts the honest measurement
/// and is gated on the capability, not on a skip: a host that permits nested
/// user namespaces would take the `else` branch and exercise the real nested
/// path (left to wave 2's `agent` end-to-end, which owns the inner sandbox).
#[test]
fn nested_user_namespace_is_unavailable_here() {
    if !common::live() {
        return;
    }
    match measure_nested_userns() {
        NestedUserns::Denied => {
            // The expected result on a stock host; the inner sandbox's failure
            // must be visible, never hidden or claimed as running.
        }
        NestedUserns::Works => {
            harness::skip_or_fail(
                "this host permits nested user namespaces; the nested IPC and \
                 proxy-replacement cases belong to wave 2's agent end-to-end",
            );
        }
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
/// host it succeeds, and the nested cases become live (owned by wave 2).
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
