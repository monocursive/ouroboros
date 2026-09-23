//! AF_UNIX modes: pathname and abstract connects, a listener that echoes,
//! datagram socket creation, and descriptor passing with SCM_RIGHTS.
//!
//! These are the operations N05 is about: a host socket reached by path, an
//! abstract name scoped by the network namespace, a datagram socket (whose
//! sends can name a peer a `connect` filter never sees), and a descriptor
//! handed across a connection. Every socket-level call goes through
//! [`crate::raw`] with its own report line; the bytes exchanged afterwards
//! are summarised.
//!
//! An address is built by [`crate::sockaddr::SockAddr`] *before* the socket
//! is created, so a path that does not fit is refused with no syscall at all.
//! SOCK_SEQPACKET for AF_UNIX and abstract names are Linux features and
//! report `unsupported` elsewhere.

use std::ffi::{OsStr, OsString, c_int};
use std::os::unix::ffi::OsStrExt;

use serde_json::Value;

use crate::bounded::{self, Deadline, IoFail};
use crate::cli::{ExecVia, UnixLen};
use crate::net::open_socket;
use crate::ops::{Usage, finish, image, open_keep, spawn_exec, wait_report};
use crate::raw;
use crate::report::{Emitted, Expect, OpReport, Reporter, path_value};
use crate::sockaddr::SockAddr;

/// Most descriptors one `scm-recv` makes room for. More are cut by the
/// kernel (`MSG_CTRUNC`) and closed by it, never written past the buffer.
pub const MAX_FDS: usize = 4;
/// Longest line the echo reads before answering.
pub const MAX_LINE: usize = 4096;

fn unsupported(rep: &Reporter, op: &str, what: &str) -> bool {
    let mut report = OpReport::new(op);
    report.set(
        "unsupported",
        format!(
            "{what} is a Linux feature; unsupported on this platform ({})",
            std::env::consts::OS
        ),
    );
    report.result(-1, None);
    let e = Emitted::unusable(report);
    rep.emit(&e.report);
    false
}

fn refused(rep: &Reporter, op: &str, key: &str, value: &OsStr, reason: &str) -> bool {
    let mut report = OpReport::new(op);
    path_value(&mut report.args, key, value);
    report.set("refused", reason);
    report.result(-1, None);
    let e = Emitted::unusable(report);
    rep.emit(&e.report);
    false
}

const fn stream_type(seqpacket: bool) -> (c_int, &'static str) {
    if seqpacket {
        (libc::SOCK_SEQPACKET, "SOCK_SEQPACKET")
    } else {
        (libc::SOCK_STREAM, "SOCK_STREAM")
    }
}

const fn len_name(len: UnixLen) -> &'static str {
    match len {
        UnixLen::Exact => "exact",
        UnixLen::Nul => "nul",
        UnixLen::Full => "full",
    }
}

// ---------------------------------------------------------------- connecting

/// Where a connect goes.
pub(crate) enum Target<'a> {
    Path(&'a OsStr, UnixLen),
    Abstract(&'a OsStr),
}

/// Send one line and read it back. Stream: up to a newline; seqpacket: one
/// record. Reported on one `exchange` line.
fn exchange(rep: &Reporter, fd: c_int, seqpacket: bool, deadline: Deadline) -> bool {
    let line = format!("ouro-fixture exchange {}\n", std::process::id());
    let mut report = OpReport::new("exchange");
    report.set("sent", line.len());
    if let Err(f) = bounded::write_all(fd, line.as_bytes(), deadline) {
        report.set("failed_step", "write");
        f.apply(&mut report);
        rep.emit(&report);
        return false;
    }
    let got = read_line(fd, seqpacket, deadline);
    let ok = match got {
        Ok(bytes) => {
            let echoed = bytes == line.as_bytes();
            report.set("received", bytes.len());
            report.set("echoed", echoed);
            report.result(bytes.len() as i64, None);
            echoed
        }
        Err(f) => {
            report.set("failed_step", "read");
            f.apply(&mut report);
            false
        }
    };
    rep.emit(&report);
    ok
}

/// One line (stream) or one record (seqpacket), at most [`MAX_LINE`] bytes.
/// End of stream before a newline returns what arrived.
fn read_line(fd: c_int, seqpacket: bool, deadline: Deadline) -> Result<Vec<u8>, IoFail> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = bounded::read_some(fd, &mut chunk, deadline)?;
        out.extend_from_slice(&chunk[..n]);
        if n == 0 || seqpacket || out.contains(&b'\n') || out.len() >= MAX_LINE {
            out.truncate(MAX_LINE);
            return Ok(out);
        }
    }
}

pub(crate) fn unix_connect(
    rep: &Reporter,
    target: &Target<'_>,
    seqpacket: bool,
    do_exchange: bool,
    timeout_ms: u64,
    expect: &Expect,
) -> bool {
    if seqpacket && !cfg!(target_os = "linux") {
        return unsupported(rep, "socket", "SOCK_SEQPACKET for AF_UNIX");
    }
    if matches!(target, Target::Abstract(_)) && !cfg!(target_os = "linux") {
        return unsupported(rep, "connect", "the abstract AF_UNIX namespace");
    }
    let addr = match target {
        Target::Path(p, len) => SockAddr::unix_path(p.as_bytes(), *len),
        Target::Abstract(n) => SockAddr::unix_abstract(n.as_bytes()),
    };
    let addr = match addr {
        Ok(a) => a,
        Err(e) => {
            let (key, value) = match target {
                Target::Path(p, _) => ("path", *p),
                Target::Abstract(n) => ("name", *n),
            };
            return refused(rep, "connect", key, value, e.reason);
        }
    };
    let deadline = Deadline::after_ms(timeout_ms);
    let (ty, type_name) = stream_type(seqpacket);
    let Ok(fd) = open_socket(rep, libc::AF_UNIX, "AF_UNIX", ty, type_name, true) else {
        return false;
    };

    let mut report = OpReport::new("connect");
    match target {
        Target::Path(p, len) => {
            path_value(&mut report.args, "path", p);
            report.set("abstract", false);
            report.set("len_variant", len_name(*len));
        }
        Target::Abstract(n) => {
            path_value(&mut report.args, "name", n);
            report.set("abstract", true);
        }
    }
    report.set("addrlen", addr.len());
    report.set("family", "AF_UNIX");
    report.set("type", type_name);
    report.set("mechanism", raw::mechanism());
    let emitted = finish(report, raw::connect(fd, addr.as_ptr(), addr.len()));
    rep.emit(&emitted.report);
    let mut ok = emitted.satisfies(expect);
    if ok && do_exchange && emitted.report.ret >= 0 {
        ok &= exchange(rep, fd, seqpacket, deadline);
    }
    bounded::close(fd);
    ok
}

// ----------------------------------------------------------------- listening

/// A bound, listening socket, and the child started once it listened.
struct Listening {
    fd: c_int,
    child: Option<(libc::pid_t, bool)>,
}

/// socket, bind, listen, and the optional spawn. `Err(ok)` ends the mode
/// early with its result (a bind expected to fail that did is `Err(true)`).
fn listen_on(
    rep: &Reporter,
    path: &OsStr,
    seqpacket: bool,
    backlog: c_int,
    expect: &Expect,
    spawn: &[OsString],
) -> Result<Result<Listening, bool>, Usage> {
    if seqpacket && !cfg!(target_os = "linux") {
        return Ok(Err(unsupported(
            rep,
            "socket",
            "SOCK_SEQPACKET for AF_UNIX",
        )));
    }
    let img = if spawn.is_empty() {
        None
    } else {
        Some(image(spawn)?)
    };
    let addr = match SockAddr::unix_path(path.as_bytes(), UnixLen::Nul) {
        Ok(a) => a,
        Err(e) => return Ok(Err(refused(rep, "bind", "path", path, e.reason))),
    };
    let (ty, type_name) = stream_type(seqpacket);
    let Ok(fd) = open_socket(rep, libc::AF_UNIX, "AF_UNIX", ty, type_name, true) else {
        return Ok(Err(false));
    };

    let mut report = OpReport::new("bind");
    path_value(&mut report.args, "path", path);
    report.set("addrlen", addr.len());
    report.set("type", type_name);
    report.set("mechanism", raw::mechanism());
    let bound = finish(report, raw::bind(fd, &addr));
    rep.emit(&bound.report);
    let satisfied = bound.satisfies(expect);
    if bound.report.ret < 0 || !satisfied {
        bounded::close(fd);
        return Ok(Err(satisfied && bound.report.ret < 0));
    }

    let mut report = OpReport::new("listen");
    report.set("backlog", backlog);
    report.set("mechanism", raw::mechanism());
    let listened = finish(report, raw::listen(fd, backlog));
    // This line is the readiness signal: it is written, unbuffered, before
    // the first accept and before any client is started.
    rep.emit(&listened.report);
    if listened.report.ret < 0 {
        bounded::close(fd);
        return Ok(Err(false));
    }

    let child = match &img {
        None => None,
        Some(img) => {
            let s = spawn_exec(img, ExecVia::Execve)?;
            rep.emit(&s.report(spawn, ExecVia::Execve));
            Some((s.pid, s.exec_failed()))
        }
    };
    Ok(Ok(Listening { fd, child }))
}

/// Wait for and accept one connection. `None` after reporting a failure.
fn accept_one(rep: &Reporter, listener: c_int, index: u32, deadline: Deadline) -> Option<c_int> {
    let mut report = OpReport::new(raw::ACCEPT_OP);
    report.set("index", index);
    report.set("mechanism", raw::mechanism());
    if let Err(f) = bounded::wait_for(listener, libc::POLLIN, deadline) {
        f.apply(&mut report);
        rep.emit(&report);
        return None;
    }
    let emitted = finish(report, raw::accept(listener));
    let fd = emitted.report.ret;
    let mut report = emitted.report;
    #[cfg(not(target_os = "linux"))]
    let how = if fd >= 0 && bounded::set_cloexec(fd as c_int).is_ok() {
        "fcntl"
    } else {
        "failed"
    };
    #[cfg(target_os = "linux")]
    let how = "SOCK_CLOEXEC";
    if fd >= 0 {
        report.set("cloexec", how);
    }
    rep.emit(&report);
    (fd >= 0).then_some(fd as c_int)
}

fn finish_listening(rep: &Reporter, l: &Listening, deadline: Deadline) -> bool {
    bounded::close(l.fd);
    match l.child {
        None => true,
        Some((pid, exec_failed)) => {
            let w = wait_report(pid, Some(deadline));
            let clean = w.args.get("code") == Some(&Value::from(0));
            rep.emit(&w);
            !exec_failed && clean
        }
    }
}

pub(crate) fn unix_listen(
    rep: &Reporter,
    path: &OsStr,
    seqpacket: bool,
    accept: u32,
    timeout_ms: u64,
    expect: &Expect,
    spawn: &[OsString],
) -> Result<bool, Usage> {
    let backlog = c_int::try_from(accept.clamp(16, 4096)).unwrap_or(16);
    let deadline = Deadline::after_ms(timeout_ms);
    let l = match listen_on(rep, path, seqpacket, backlog, expect, spawn)? {
        Ok(l) => l,
        Err(done) => return Ok(done),
    };
    let mut ok = !matches!(l.child, Some((_, true)));
    let mut served = 0u32;
    if ok {
        for index in 0..accept {
            let Some(conn) = accept_one(rep, l.fd, index, deadline) else {
                ok = false;
                break;
            };
            let mut report = OpReport::new("echo");
            report.set("index", index);
            match read_line(conn, seqpacket, deadline) {
                Err(f) => {
                    report.set("failed_step", "read");
                    f.apply(&mut report);
                    ok = false;
                }
                Ok(bytes) => {
                    report.set("line_bytes", bytes.len());
                    report.set("line", bounded::preview(&bytes, 128));
                    match bounded::write_all(conn, &bytes, deadline) {
                        Ok(()) => {
                            report.result(bytes.len() as i64, None);
                            served += 1;
                        }
                        Err(f) => {
                            report.set("failed_step", "write");
                            f.apply(&mut report);
                            ok = false;
                        }
                    }
                }
            }
            rep.emit(&report);
            bounded::close(conn);
        }
    }
    ok &= finish_listening(rep, &l, deadline);
    Ok(ok && served == accept)
}

// ------------------------------------------------------------------ datagram

fn dgram_type(raw: bool, cloexec: bool, nonblock: bool, report: &mut OpReport) -> c_int {
    let base = if raw {
        libc::SOCK_RAW
    } else {
        libc::SOCK_DGRAM
    };
    report.set("type", if raw { "SOCK_RAW" } else { "SOCK_DGRAM" });
    #[cfg(target_os = "linux")]
    let (ty, flags) = {
        let mut ty = base;
        let mut flags: Vec<&str> = Vec::new();
        if cloexec {
            ty |= libc::SOCK_CLOEXEC;
            flags.push("SOCK_CLOEXEC");
        }
        if nonblock {
            ty |= libc::SOCK_NONBLOCK;
            flags.push("SOCK_NONBLOCK");
        }
        (ty, flags)
    };
    #[cfg(not(target_os = "linux"))]
    let (ty, flags): (c_int, Vec<&str>) = {
        // The caller refused these flags on this platform already.
        let _ = (cloexec, nonblock);
        (base, Vec::new())
    };
    report.set(
        "type_flags",
        Value::Array(flags.into_iter().map(Value::from).collect()),
    );
    report.set("type_arg", ty);
    ty
}

fn flags_unsupported(rep: &Reporter, op: &str, cloexec: bool, nonblock: bool) -> Option<bool> {
    (!cfg!(target_os = "linux") && (cloexec || nonblock))
        .then(|| unsupported(rep, op, "OR-ing SOCK_CLOEXEC/SOCK_NONBLOCK into the type"))
}

pub(crate) fn unix_socket_dgram(
    rep: &Reporter,
    raw_type: bool,
    cloexec: bool,
    nonblock: bool,
    expect: &Expect,
) -> bool {
    if let Some(r) = flags_unsupported(rep, "socket", cloexec, nonblock) {
        return r;
    }
    let mut report = OpReport::new("socket");
    report.set("family", "AF_UNIX");
    let ty = dgram_type(raw_type, cloexec, nonblock, &mut report);
    report.set("mechanism", raw::mechanism());
    let emitted = finish(report, raw::socket(libc::AF_UNIX, ty, 0));
    crate::ops::close_fd(emitted.report.ret);
    crate::ops::check(rep, emitted, expect)
}

pub(crate) fn unix_socketpair_dgram(
    rep: &Reporter,
    raw_type: bool,
    cloexec: bool,
    nonblock: bool,
    expect: &Expect,
) -> bool {
    if let Some(r) = flags_unsupported(rep, "socketpair", cloexec, nonblock) {
        return r;
    }
    let mut report = OpReport::new("socketpair");
    report.set("family", "AF_UNIX");
    let ty = dgram_type(raw_type, cloexec, nonblock, &mut report);
    report.set("mechanism", raw::mechanism());
    let mut sv: [c_int; 2] = [-1, -1];
    let mut emitted = finish(report, raw::socketpair(libc::AF_UNIX, ty, 0, &mut sv));
    if emitted.report.ret >= 0 {
        emitted.report.set(
            "fds",
            Value::Array(sv.iter().map(|f| Value::from(*f)).collect()),
        );
        bounded::close(sv[0]);
        bounded::close(sv[1]);
    }
    crate::ops::check(rep, emitted, expect)
}

// -------------------------------------------------------------- SCM_RIGHTS

/// Control-buffer storage: `u64` elements so the buffer is aligned for
/// `cmsghdr` on every supported platform, and large enough for
/// `CMSG_SPACE(MAX_FDS * sizeof(int))` (checked by `control_space`).
type Control = [u64; 16];

/// `CMSG_SPACE` for `fds` descriptors, checked against [`Control`].
fn control_space(fds: usize) -> usize {
    let payload = (fds * size_of::<c_int>()) as u32;
    // SAFETY: `CMSG_SPACE` is arithmetic on its argument; it dereferences
    // nothing.
    let space = unsafe { libc::CMSG_SPACE(payload) } as usize;
    assert!(
        space <= size_of::<Control>(),
        "control buffer too small for {fds} descriptors"
    );
    space
}

fn send_fd(sock: c_int, fd: c_int) -> raw::Attempt {
    let data = *b"F";
    let mut control: Control = [0; 16];
    let space = control_space(1);
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    // SAFETY: `msghdr` is plain old data; zero is a valid value (no name, no
    // iovecs, no control) and every field used is set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = space as _;
    // SAFETY: `msg_control` points to `space` live, aligned bytes, at least
    // `CMSG_SPACE(sizeof(int))`, so the first header exists and its data
    // area holds one int. `write_unaligned` does not assume the data area's
    // alignment.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        assert!(!cmsg.is_null(), "the control buffer holds one header");
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<c_int>(), fd);
    }
    // SAFETY: `iov` points at `data` (1 live byte) and `msg_control` at
    // `space` live bytes; all of them outlive the call.
    unsafe { raw::sendmsg(sock, &raw const msg, 0) }
}

/// What one `recvmsg` delivered.
pub(crate) struct Received {
    pub(crate) attempt: raw::Attempt,
    pub(crate) fds: Vec<c_int>,
    pub(crate) ctrunc: bool,
    pub(crate) trunc: bool,
}

/// Receive one message with room for [`MAX_FDS`] descriptors. Descriptors
/// are collected only from headers that lie wholly inside the bytes the
/// kernel reported, so a lying length cannot move a read out of the buffer.
pub(crate) fn recv_fds(sock: c_int) -> Received {
    let mut data = [0u8; 64];
    let mut control: Control = [0; 16];
    let space = control_space(MAX_FDS);
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    // SAFETY: plain old data; zero is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = space as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: `iov` points at `data` and `msg_control` at `space` bytes of
    // `control`, all live and writable for the call.
    let attempt = unsafe { raw::recvmsg(sock, &raw mut msg, flags) };
    let mut fds = Vec::new();
    if let raw::Attempt::Performed { ret, .. } = &attempt
        && *ret >= 0
    {
        let base = control.as_ptr() as usize;
        let limit = base + (msg.msg_controllen as usize).min(space);
        // SAFETY: the kernel wrote `msg_controllen` bytes of well-formed
        // headers into `control`; `CMSG_FIRSTHDR`/`CMSG_NXTHDR` stay within
        // `msg_controllen` and return NULL past it. Each header is checked
        // to lie inside `limit` before its data is read, and every int is
        // read unaligned from inside that span.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                let start = cmsg as usize;
                let len = (*cmsg).cmsg_len as usize;
                if start + len > limit || len < libc::CMSG_LEN(0) as usize {
                    break;
                }
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    let payload = len - (data_ptr as usize - start);
                    for i in 0..payload / size_of::<c_int>() {
                        fds.push(std::ptr::read_unaligned(
                            data_ptr.add(i * size_of::<c_int>()).cast::<c_int>(),
                        ));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    for fd in &fds {
        let _ = bounded::set_cloexec(*fd);
    }
    Received {
        attempt,
        fds,
        ctrunc: msg.msg_flags & libc::MSG_CTRUNC != 0,
        trunc: msg.msg_flags & libc::MSG_TRUNC != 0,
    }
}

/// `fstat` a descriptor and name its file type.
pub(crate) fn file_kind(fd: c_int) -> Result<&'static str, c_int> {
    // SAFETY: `st` is a live stat struct written by `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(fd, &raw mut st) } != 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    Ok(match st.st_mode & libc::S_IFMT {
        libc::S_IFIFO => "fifo",
        libc::S_IFCHR => "character",
        libc::S_IFDIR => "directory",
        libc::S_IFBLK => "block",
        libc::S_IFREG => "regular",
        libc::S_IFLNK => "symlink",
        libc::S_IFSOCK => "socket",
        _ => "unknown",
    })
}

pub(crate) fn scm_send(rep: &Reporter, socket: &OsStr, fd_path: &OsStr, expect: &Expect) -> bool {
    let addr = match SockAddr::unix_path(socket.as_bytes(), UnixLen::Nul) {
        Ok(a) => a,
        Err(e) => return refused(rep, "connect", "path", socket, e.reason),
    };
    let opened = open_keep(
        fd_path,
        crate::cli::OpenVia::Openat,
        false,
        false,
        false,
        false,
        0,
    );
    rep.emit(&opened.report);
    if opened.unusable || opened.report.ret < 0 {
        return false;
    }
    let passed = opened.report.ret as c_int;
    let Ok(sock) = open_socket(
        rep,
        libc::AF_UNIX,
        "AF_UNIX",
        libc::SOCK_STREAM,
        "SOCK_STREAM",
        true,
    ) else {
        bounded::close(passed);
        return false;
    };
    let mut report = OpReport::new("connect");
    path_value(&mut report.args, "path", socket);
    report.set("addrlen", addr.len());
    report.set("family", "AF_UNIX");
    report.set("type", "SOCK_STREAM");
    report.set("mechanism", raw::mechanism());
    let connected = finish(report, raw::connect(sock, addr.as_ptr(), addr.len()));
    rep.emit(&connected.report);
    let mut ok = connected.satisfies(expect);
    if ok && connected.report.ret >= 0 {
        let mut report = OpReport::new("sendmsg");
        report.set("fd", passed);
        report.set("fds", 1);
        report.set("data_bytes", 1);
        report.set("control", "SCM_RIGHTS");
        report.set("mechanism", raw::mechanism());
        let sent = finish(report, send_fd(sock, passed));
        rep.emit(&sent.report);
        ok &= sent.satisfies(&Expect::Ok);
    }
    bounded::close(sock);
    bounded::close(passed);
    ok
}

pub(crate) fn scm_recv(
    rep: &Reporter,
    path: &OsStr,
    timeout_ms: u64,
    expect: &Expect,
    spawn: &[OsString],
) -> Result<bool, Usage> {
    let deadline = Deadline::after_ms(timeout_ms);
    let l = match listen_on(rep, path, false, 16, expect, spawn)? {
        Ok(l) => l,
        Err(done) => return Ok(done),
    };
    let mut ok = !matches!(l.child, Some((_, true)));
    if ok {
        match accept_one(rep, l.fd, 0, deadline) {
            None => ok = false,
            Some(conn) => {
                let mut report = OpReport::new("recvmsg");
                report.set("control_room_fds", MAX_FDS);
                report.set("mechanism", raw::mechanism());
                if let Err(f) = bounded::wait_for(conn, libc::POLLIN, deadline) {
                    f.apply(&mut report);
                    rep.emit(&report);
                    ok = false;
                } else {
                    let got = recv_fds(conn);
                    let mut emitted = finish(report, got.attempt);
                    emitted.report.set("fds_received", got.fds.len());
                    emitted.report.set("ctrunc", got.ctrunc);
                    emitted.report.set("trunc", got.trunc);
                    rep.emit(&emitted.report);
                    ok &= emitted.satisfies(&Expect::Ok) && !got.fds.is_empty();
                    for fd in got.fds {
                        let mut r = OpReport::new("fstat");
                        r.set("fd", fd);
                        match file_kind(fd) {
                            Ok(kind) => {
                                r.set("kind", kind);
                                r.result(0, None);
                            }
                            Err(e) => {
                                r.result(-1, Some(e));
                                ok = false;
                            }
                        }
                        rep.emit(&r);
                        bounded::close(fd);
                    }
                }
                bounded::close(conn);
            }
        }
    }
    ok &= finish_listening(rep, &l, deadline);
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_buffer_holds_the_descriptors_it_promises() {
        // The precondition of both `sendmsg` and `recvmsg` blocks: the
        // control length handed to the kernel never exceeds the buffer.
        assert!(control_space(1) <= size_of::<Control>());
        assert!(control_space(MAX_FDS) <= size_of::<Control>());
        assert!(control_space(MAX_FDS) >= MAX_FDS * size_of::<c_int>());
        let r = std::panic::catch_unwind(|| control_space(64));
        assert!(
            r.is_err(),
            "a request beyond the buffer panics instead of overrunning"
        );
    }

    fn pair() -> [c_int; 2] {
        let mut sv = [-1; 2];
        // SAFETY: `sv` is a live array of two ints.
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(r, 0);
        sv
    }

    #[test]
    fn a_descriptor_crosses_a_socket_pair_and_keeps_its_kind() {
        let sv = pair();
        let dir = std::fs::File::open(std::env::temp_dir()).unwrap();
        use std::os::fd::AsRawFd;
        let sent = send_fd(sv[0], dir.as_raw_fd());
        assert!(matches!(sent, raw::Attempt::Performed { ret: 1, .. }));
        let got = recv_fds(sv[1]);
        assert_eq!(got.fds.len(), 1);
        assert!(!got.ctrunc);
        assert_eq!(file_kind(got.fds[0]), Ok("directory"));
        for fd in got.fds {
            bounded::close(fd);
        }
        bounded::close(sv[0]);
        bounded::close(sv[1]);
    }

    #[test]
    fn more_descriptors_than_fit_are_cut_by_the_kernel_not_written_past_the_buffer() {
        // Try to violate the receive buffer's bound: send far more
        // descriptors than it has room for.
        let sv = pair();
        let many = 3 * MAX_FDS;
        let files: Vec<std::fs::File> = (0..many)
            .map(|_| std::fs::File::open("/dev/null").unwrap())
            .collect();
        use std::os::fd::AsRawFd;
        let raw_fds: Vec<c_int> = files.iter().map(AsRawFd::as_raw_fd).collect();
        let payload = std::mem::size_of_val(raw_fds.as_slice()) as u32;
        let mut control = [0u64; 32];
        // SAFETY: arithmetic only.
        let space = unsafe { libc::CMSG_SPACE(payload) } as usize;
        assert!(space <= size_of_val(&control));
        let data = *b"M";
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: 1,
        };
        // SAFETY: plain old data.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // SAFETY: the control buffer holds `space` bytes, enough for one
        // header carrying every descriptor; each int is written unaligned
        // inside that span.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&raw const msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(payload) as _;
            let d = libc::CMSG_DATA(c).cast::<c_int>();
            for (i, fd) in raw_fds.iter().enumerate() {
                std::ptr::write_unaligned(d.add(i), *fd);
            }
            assert_eq!(libc::sendmsg(sv[0], &raw const msg, 0), 1);
        }
        let got = recv_fds(sv[1]);
        assert!(got.ctrunc, "the kernel must report the cut");
        assert!(
            got.fds.len() <= MAX_FDS,
            "received {} descriptors into room for {MAX_FDS}",
            got.fds.len()
        );
        // Linux delivers what fits; Darwin drops the cut message's
        // descriptors altogether. Either way nothing lands past the buffer.
        #[cfg(target_os = "linux")]
        assert_eq!(got.fds.len(), MAX_FDS);
        for fd in got.fds {
            assert_eq!(file_kind(fd), Ok("character"));
            bounded::close(fd);
        }
        bounded::close(sv[0]);
        bounded::close(sv[1]);
    }

    #[test]
    fn a_message_without_descriptors_yields_none() {
        let sv = pair();
        assert!(bounded::write_all(sv[0], b"x", Deadline::after_ms(1000)).is_ok());
        let got = recv_fds(sv[1]);
        assert!(got.fds.is_empty());
        assert!(!got.ctrunc);
        bounded::close(sv[0]);
        bounded::close(sv[1]);
    }
}
