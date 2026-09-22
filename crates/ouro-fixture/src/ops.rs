//! The operation modes.
//!
//! Every filesystem, network and process operation goes through [`crate::raw`]
//! so the syscall a test names is the syscall a tracer sees. Each operation
//! emits exactly one report line; a mode that performs several operations
//! emits several lines, in the order they ran.

use std::ffi::{CString, OsStr, OsString, c_char, c_int};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use serde_json::Value;

use crate::cli::{
    ExecVia, LinkVia, MkdirVia, MknodVia, Mode, OpenVia, RenameVia, RmdirVia, Step, SymlinkVia,
    UnlinkVia, parse_mode,
};
use crate::raw::{self, Attempt};
use crate::report::{Emitted, Expect, OpReport, Reporter, path_value, write_all};

/// A pipe whose two ends are both close-on-exec.
pub(crate) fn cloexec_pipe() -> Result<(c_int, c_int), std::io::Error> {
    let mut fds = [0 as c_int; 2];
    #[cfg(target_os = "linux")]
    // SAFETY: `fds` is a live array of two ints, which is what `pipe2` writes.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: as above, for `pipe`; Darwin has no `pipe2`.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(not(target_os = "linux"))]
    for fd in fds {
        // SAFETY: `fd` was just returned by `pipe` and is owned here.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: both descriptors are owned here.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(e);
        }
    }
    Ok((fds[0], fds[1]))
}

/// This thread's errno, read without allocating: safe to call after `fork`.
pub(crate) fn raw_errno() -> c_int {
    #[cfg(target_os = "linux")]
    // SAFETY: `__errno_location` returns a valid pointer to this thread's errno.
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: `__error` returns a valid pointer to this thread's errno.
    unsafe {
        *libc::__error()
    }
}

/// A usage error: the fixture refuses before doing anything. Exit code 2.
pub type Usage = String;

/// State shared by every step of one fixture process.
///
/// It exists for one reason: `exit` and a successful `exec-replace` end the
/// process, so a `script` whose last step is `exit 0` used to discard every
/// earlier failed expectation and report success.
pub struct Session<'a> {
    pub(crate) rep: &'a Reporter,
    failed: std::cell::Cell<bool>,
    in_script: std::cell::Cell<bool>,
}

impl<'a> Session<'a> {
    #[must_use]
    pub fn new(rep: &'a Reporter) -> Session<'a> {
        Session {
            rep,
            failed: std::cell::Cell::new(false),
            in_script: std::cell::Cell::new(false),
        }
    }

    fn record(&self, ok: bool) -> bool {
        if !ok {
            self.failed.set(true);
        }
        ok
    }

    /// True when some earlier operation in this process did not meet its
    /// expectation.
    #[must_use]
    pub fn failed_earlier(&self) -> bool {
        self.failed.get()
    }
}

pub(crate) fn finish(mut report: OpReport, attempt: Attempt) -> Emitted {
    match attempt {
        Attempt::Performed { ret, errno } => {
            report.result(ret, errno);
            Emitted::done(report)
        }
        Attempt::Absent(reason) => {
            report.set("unsupported", reason);
            report.result(-1, None);
            Emitted::unusable(report)
        }
    }
}

fn refuse_path(mut report: OpReport, key: &str, p: &OsStr, reason: &'static str) -> Emitted {
    path_value(&mut report.args, key, p);
    report.set("refused", reason);
    report.result(-1, None);
    Emitted::unusable(report)
}

pub(crate) fn close_fd(ret: i64) {
    if ret >= 0 {
        // SAFETY: `ret` is a descriptor this process just opened and has not
        // handed to anything else.
        unsafe { libc::close(ret as c_int) };
    }
}

/// Run one mode. `Ok(true)` when every expectation in it held.
pub fn run(mode: Mode, rep: &Reporter) -> Result<bool, Usage> {
    let session = Session::new(rep);
    let ok = run_in(&session, mode)?;
    Ok(ok && !session.failed_earlier())
}

/// Run one mode inside an existing session.
pub fn run_in(session: &Session<'_>, mode: Mode) -> Result<bool, Usage> {
    let rep = session.rep;
    let ok = run_mode(session, rep, mode)?;
    Ok(session.record(ok))
}

fn run_mode(session: &Session<'_>, rep: &Reporter, mode: Mode) -> Result<bool, Usage> {
    match mode {
        Mode::Open {
            path,
            via,
            create,
            trunc,
            write,
            rdwr,
            mode,
            expect,
        } => {
            let mode = parse_mode(&mode)?;
            Ok(check(
                rep,
                open(&path, via, create, trunc, write, rdwr, mode),
                &expect,
            ))
        }
        Mode::Mkdir {
            path,
            via,
            mode,
            expect,
        } => {
            let mode = parse_mode(&mode)?;
            Ok(check(rep, mkdir(&path, via, mode), &expect))
        }
        Mode::Rename {
            from,
            to,
            via,
            noreplace,
            expect,
        } => Ok(check(rep, rename(&from, &to, via, noreplace), &expect)),
        Mode::Unlink { path, via, expect } => Ok(check(rep, unlink(&path, via), &expect)),
        Mode::Rmdir { path, via, expect } => Ok(check(rep, rmdir(&path, via), &expect)),
        Mode::Link {
            from,
            to,
            via,
            expect,
        } => Ok(check(rep, link(&from, &to, via), &expect)),
        Mode::Symlink {
            target,
            linkpath,
            via,
            expect,
        } => Ok(check(rep, symlink(&target, &linkpath, via), &expect)),
        Mode::Mknod {
            path,
            via,
            fifo,
            regular,
            mode,
            expect,
        } => {
            let _ = fifo; // the default kind; `--regular` is what changes it
            let perm = parse_mode(&mode)?;
            Ok(check(rep, mknod(&path, via, regular, perm), &expect))
        }
        Mode::Truncate {
            path,
            length,
            expect,
        } => Ok(check(rep, truncate(&path, length), &expect)),
        Mode::Ftruncate {
            path,
            length,
            expect,
        } => Ok(ftruncate(rep, &path, length, &expect)),
        Mode::Connect { addr, udp, expect } => connect(rep, &addr, udp, &expect),
        Mode::UdpSendto {
            addr,
            bytes,
            expect,
        } => crate::net::udp_sendto(rep, &addr, bytes, &expect),
        Mode::DnsQuery {
            resolver,
            name,
            timeout_ms,
            expect,
        } => crate::net::dns_query(rep, &resolver, &name, timeout_ms, &expect),
        Mode::HttpGet {
            url,
            no_proxy,
            host_header,
            timeout_ms,
            expect,
        } => crate::net::http_get(
            rep,
            &url,
            no_proxy,
            host_header.as_deref(),
            timeout_ms,
            &expect,
        ),
        Mode::HttpConnect {
            authority,
            then_get,
            host_header,
            timeout_ms,
            expect,
        } => crate::net::http_connect(
            rep,
            &authority,
            then_get.as_deref(),
            host_header.as_deref(),
            timeout_ms,
            &expect,
        ),
        Mode::UnixConnect {
            path,
            seqpacket,
            len,
            exchange,
            timeout_ms,
            expect,
        } => Ok(crate::unix::unix_connect(
            rep,
            &crate::unix::Target::Path(&path, len),
            seqpacket,
            exchange,
            timeout_ms,
            &expect,
        )),
        Mode::UnixAbstractConnect {
            name,
            seqpacket,
            exchange,
            timeout_ms,
            expect,
        } => Ok(crate::unix::unix_connect(
            rep,
            &crate::unix::Target::Abstract(&name),
            seqpacket,
            exchange,
            timeout_ms,
            &expect,
        )),
        Mode::UnixListen {
            path,
            seqpacket,
            accept,
            timeout_ms,
            expect,
            spawn,
        } => crate::unix::unix_listen(rep, &path, seqpacket, accept, timeout_ms, &expect, &spawn),
        Mode::UnixSocketDgram {
            raw,
            cloexec,
            nonblock,
            expect,
        } => Ok(crate::unix::unix_socket_dgram(
            rep, raw, cloexec, nonblock, &expect,
        )),
        Mode::UnixSocketpairDgram {
            raw,
            cloexec,
            nonblock,
            expect,
        } => Ok(crate::unix::unix_socketpair_dgram(
            rep, raw, cloexec, nonblock, &expect,
        )),
        Mode::ScmSend {
            socket,
            fd_path,
            expect,
        } => Ok(crate::unix::scm_send(rep, &socket, &fd_path, &expect)),
        Mode::ScmRecv {
            path,
            timeout_ms,
            expect,
            spawn,
        } => crate::unix::scm_recv(rep, &path, timeout_ms, &expect, &spawn),
        Mode::SandboxExec {
            landlock_rw,
            landlock_ro,
            landlock_deny_tcp,
            seccomp_errno,
            argv,
        } => crate::sandbox::sandbox_exec(
            session,
            rep,
            &crate::sandbox::Request {
                rw: &landlock_rw,
                ro: &landlock_ro,
                deny_tcp: landlock_deny_tcp,
                seccomp: &seccomp_errno,
                argv: &argv,
            },
        ),
        Mode::Exec { via, expect, argv } => exec_and_wait(rep, via, &argv, &expect),
        Mode::ExecReplace { via, expect, argv } => exec_replace(session, rep, via, &argv, &expect),
        Mode::Sleep { ms } => {
            let mut r = OpReport::new("sleep");
            r.set("ms", ms);
            rep.emit(&r);
            sleep_ms(ms);
            Ok(true)
        }
        Mode::Spin { ms } => {
            let mut r = OpReport::new("spin");
            r.set("ms", ms);
            rep.emit(&r);
            spin_ms(ms);
            Ok(true)
        }
        Mode::Background { ms, argv } => background(rep, ms, &argv),
        Mode::IgnoreTerm { ms } => {
            ignore_term();
            let mut r = OpReport::new("ignore-term");
            r.set("ms", ms);
            r.set("signal", "SIGTERM");
            rep.emit(&r);
            sleep_ms(ms);
            Ok(true)
        }
        Mode::ForkStorm { count } => Ok(fork_storm(rep, count)),
        Mode::EchoArgs { argv } => {
            echo_args(rep, &argv);
            Ok(true)
        }
        Mode::StdoutBytes { count } => Ok(stream_bytes(rep, 1, count, "stdout-bytes")),
        Mode::StderrBytes { count } => Ok(stream_bytes(rep, 2, count, "stderr-bytes")),
        Mode::Env => {
            env_names(rep);
            Ok(true)
        }
        Mode::Fds => Ok(fds(rep)),
        Mode::Status => Ok(status(rep)),
        Mode::WriteMmap { path } => Ok(write_mmap(rep, &path)),
        Mode::Thread => Ok(thread(rep)),
        Mode::Exit { code } => {
            // An `exit` step used to discard every earlier failed expectation
            // in a `script`. It cannot report success over one now, and the
            // line says why the code changed.
            let earlier = session.failed_earlier();
            let actual = if earlier {
                crate::EXIT_EXPECTATION_FAILED
            } else {
                code
            };
            let mut r = OpReport::new("exit");
            r.set("code", code);
            r.set("earlier_expectation_failed", earlier);
            r.set("exit_code", actual);
            r.result(i64::from(actual), None);
            rep.emit(&r);
            std::process::exit(actual);
        }
        Mode::Raise { signal } => raise(rep, &signal),
        Mode::Script { file } => script(session, &file),
    }
}

pub(crate) fn check(rep: &Reporter, emitted: Emitted, expect: &Expect) -> bool {
    rep.emit(&emitted.report);
    emitted.satisfies(expect)
}

// ---------------------------------------------------------------- filesystem

/// Open, and close the descriptor again. Most modes only want the result.
fn open(
    path: &OsStr,
    via: OpenVia,
    create: bool,
    trunc: bool,
    write: bool,
    rdwr: bool,
    mode: u32,
) -> Emitted {
    let emitted = open_keep(path, via, create, trunc, write, rdwr, mode);
    close_fd(emitted.report.ret);
    emitted
}

/// Open and hand the descriptor back in `report.ret`. The caller closes it.
pub(crate) fn open_keep(
    path: &OsStr,
    via: OpenVia,
    create: bool,
    trunc: bool,
    write: bool,
    rdwr: bool,
    mode: u32,
) -> Emitted {
    let name = match via {
        OpenVia::Openat => "openat",
        OpenVia::Open => "open",
        OpenVia::Creat => "creat",
        OpenVia::Openat2 => "openat2",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }

    let access = if rdwr {
        libc::O_RDWR
    } else if write {
        libc::O_WRONLY
    } else {
        libc::O_RDONLY
    };
    let mut flags = access;
    if create {
        flags |= libc::O_CREAT;
    }
    if trunc {
        flags |= libc::O_TRUNC;
    }
    if via == OpenVia::Creat {
        flags = libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC;
        report.set("implied_flags", true);
    }

    path_value(&mut report.args, "path", path);
    report.set("flags", flags);
    report.set("mode", format!("{mode:o}"));
    report.set("mechanism", raw::mechanism());
    if via != OpenVia::Open && via != OpenVia::Creat {
        report.set("dirfd", "AT_FDCWD");
    }

    let attempt = match via {
        OpenVia::Openat => raw::openat(libc::AT_FDCWD, c.as_ptr(), flags, mode),
        OpenVia::Open => raw::open(c.as_ptr(), flags, mode),
        OpenVia::Creat => raw::creat(c.as_ptr(), mode),
        OpenVia::Openat2 => raw::openat2(libc::AT_FDCWD, c.as_ptr(), flags, mode),
    };
    finish(report, attempt)
}

fn mkdir(path: &OsStr, via: MkdirVia, mode: u32) -> Emitted {
    let name = match via {
        MkdirVia::Mkdir => "mkdir",
        MkdirVia::Mkdirat => "mkdirat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "path", path);
    report.set("mode", format!("{mode:o}"));
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        MkdirVia::Mkdir => raw::mkdir(c.as_ptr(), mode),
        MkdirVia::Mkdirat => {
            report.set("dirfd", "AT_FDCWD");
            raw::mkdirat(libc::AT_FDCWD, c.as_ptr(), mode)
        }
    };
    finish(report, attempt)
}

fn rename(from: &OsStr, to: &OsStr, via: RenameVia, noreplace: bool) -> Emitted {
    let name = match via {
        RenameVia::Rename => "rename",
        RenameVia::Renameat => "renameat",
        RenameVia::Renameat2 => "renameat2",
    };
    let mut report = OpReport::new(name);
    let (cf, ct) = match (raw::cpath(from), raw::cpath(to)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return refuse_path(report, "from", from, e.reason),
        (_, Err(e)) => return refuse_path(report, "to", to, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "from", from);
        path_value(&mut report.args, "to", to);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "from", from);
    path_value(&mut report.args, "to", to);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        RenameVia::Rename => raw::rename(cf.as_ptr(), ct.as_ptr()),
        RenameVia::Renameat => {
            report.set("dirfd", "AT_FDCWD");
            report.set("dirfd2", "AT_FDCWD");
            raw::renameat(libc::AT_FDCWD, cf.as_ptr(), libc::AT_FDCWD, ct.as_ptr())
        }
        RenameVia::Renameat2 => {
            let flags = if noreplace { rename_noreplace() } else { 0 };
            report.set("dirfd", "AT_FDCWD");
            report.set("dirfd2", "AT_FDCWD");
            report.set("flags", flags);
            raw::renameat2(
                libc::AT_FDCWD,
                cf.as_ptr(),
                libc::AT_FDCWD,
                ct.as_ptr(),
                flags,
            )
        }
    };
    finish(report, attempt)
}

const fn rename_noreplace() -> u32 {
    // RENAME_NOREPLACE, uapi/linux/fs.h. Only reaches the kernel on Linux.
    1
}

fn unlink(path: &OsStr, via: UnlinkVia) -> Emitted {
    let name = match via {
        UnlinkVia::Unlink => "unlink",
        UnlinkVia::Unlinkat => "unlinkat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "path", path);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        UnlinkVia::Unlink => raw::unlink(c.as_ptr()),
        UnlinkVia::Unlinkat => {
            report.set("dirfd", "AT_FDCWD");
            report.set("flags", 0);
            raw::unlinkat(libc::AT_FDCWD, c.as_ptr(), 0)
        }
    };
    finish(report, attempt)
}

fn rmdir(path: &OsStr, via: RmdirVia) -> Emitted {
    let name = match via {
        RmdirVia::Rmdir => "rmdir",
        RmdirVia::Unlinkat => "unlinkat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "path", path);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        RmdirVia::Rmdir => raw::rmdir(c.as_ptr()),
        RmdirVia::Unlinkat => {
            report.set("dirfd", "AT_FDCWD");
            report.set("flags", libc::AT_REMOVEDIR);
            raw::unlinkat(libc::AT_FDCWD, c.as_ptr(), libc::AT_REMOVEDIR)
        }
    };
    finish(report, attempt)
}

fn link(from: &OsStr, to: &OsStr, via: LinkVia) -> Emitted {
    let name = match via {
        LinkVia::Link => "link",
        LinkVia::Linkat => "linkat",
    };
    let mut report = OpReport::new(name);
    let (cf, ct) = match (raw::cpath(from), raw::cpath(to)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return refuse_path(report, "from", from, e.reason),
        (_, Err(e)) => return refuse_path(report, "to", to, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "from", from);
        path_value(&mut report.args, "to", to);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "from", from);
    path_value(&mut report.args, "to", to);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        LinkVia::Link => raw::link(cf.as_ptr(), ct.as_ptr()),
        LinkVia::Linkat => {
            report.set("dirfd", "AT_FDCWD");
            report.set("dirfd2", "AT_FDCWD");
            report.set("flags", 0);
            raw::linkat(libc::AT_FDCWD, cf.as_ptr(), libc::AT_FDCWD, ct.as_ptr(), 0)
        }
    };
    finish(report, attempt)
}

fn symlink(target: &OsStr, linkpath: &OsStr, via: SymlinkVia) -> Emitted {
    let name = match via {
        SymlinkVia::Symlink => "symlink",
        SymlinkVia::Symlinkat => "symlinkat",
    };
    let mut report = OpReport::new(name);
    let (ctarget, clink) = match (raw::cpath(target), raw::cpath(linkpath)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return refuse_path(report, "target", target, e.reason),
        (_, Err(e)) => return refuse_path(report, "linkpath", linkpath, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "target", target);
        path_value(&mut report.args, "linkpath", linkpath);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "target", target);
    path_value(&mut report.args, "linkpath", linkpath);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        SymlinkVia::Symlink => raw::symlink(ctarget.as_ptr(), clink.as_ptr()),
        SymlinkVia::Symlinkat => {
            report.set("dirfd2", "AT_FDCWD");
            raw::symlinkat(ctarget.as_ptr(), libc::AT_FDCWD, clink.as_ptr())
        }
    };
    finish(report, attempt)
}

/// The `S_IF*` file-type bits, widened once.
///
/// They are `u32` on Linux and `mode_t` (`u16`) on Darwin, so a cast that is
/// necessary on one platform is a lint on the other. Both cfg arms are kept
/// here rather than at every use.
#[cfg(target_os = "linux")]
const fn file_type_bits(regular: bool) -> u32 {
    if regular {
        libc::S_IFREG
    } else {
        libc::S_IFIFO
    }
}

#[cfg(not(target_os = "linux"))]
const fn file_type_bits(regular: bool) -> u32 {
    (if regular {
        libc::S_IFREG
    } else {
        libc::S_IFIFO
    }) as u32
}

/// The `S_IFMT` mask, widened the same way. Only a test needs it.
#[cfg(all(test, target_os = "linux"))]
const fn file_type_mask() -> u32 {
    libc::S_IFMT
}

#[cfg(all(test, not(target_os = "linux")))]
const fn file_type_mask() -> u32 {
    libc::S_IFMT as u32
}

fn mknod(path: &OsStr, via: MknodVia, regular: bool, perm: u32) -> Emitted {
    let name = match via {
        MknodVia::Mknod => "mknod",
        MknodVia::Mknodat => "mknodat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }

    // The file-type bits are part of `mode`, not a separate argument. Only
    // S_IFIFO and S_IFREG are offered: S_IFCHR and S_IFBLK need CAP_MKNOD, and
    // a fixture that always fails would prove nothing.
    let mode = file_type_bits(regular) | (perm & 0o7777);
    let dev: u64 = 0;

    path_value(&mut report.args, "path", path);
    report.set("mode", format!("{mode:o}"));
    report.set("dev", dev);
    report.set("kind", if regular { "S_IFREG" } else { "S_IFIFO" });
    report.set("mechanism", raw::mechanism());

    let attempt = match via {
        MknodVia::Mknod => raw::mknod(c.as_ptr(), mode, dev),
        MknodVia::Mknodat => {
            report.set("dirfd", "AT_FDCWD");
            raw::mknodat(libc::AT_FDCWD, c.as_ptr(), mode, dev)
        }
    };
    finish(report, attempt)
}

fn truncate(path: &OsStr, length: i64) -> Emitted {
    let mut report = OpReport::new("truncate");
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    path_value(&mut report.args, "path", path);
    report.set("length", length);
    report.set("mechanism", raw::mechanism());
    finish(report, raw::truncate(c.as_ptr(), length))
}

/// Open the path, then truncate through the descriptor.
///
/// Both lines are emitted: the `openat` that names a path, and the
/// `ftruncate` that names only a descriptor. A tracer that reports paths can
/// attribute the first and not the second, which is the distinction this mode
/// exists to make visible. `--expect` applies to the `ftruncate`.
fn ftruncate(rep: &Reporter, path: &OsStr, length: i64, expect: &Expect) -> bool {
    let opened = open_keep(path, OpenVia::Openat, false, false, false, true, 0o600);
    rep.emit(&opened.report);
    if opened.unusable || opened.report.ret < 0 {
        return false;
    }
    let fd = opened.report.ret as c_int;

    let mut report = OpReport::new("ftruncate");
    path_value(&mut report.args, "path", path);
    report.set("fd", fd);
    report.set("length", length);
    report.set("mechanism", raw::mechanism());
    report.set("path_named_to_the_kernel", false);
    let emitted = finish(report, raw::ftruncate(fd, length));
    close_fd(i64::from(fd));
    rep.emit(&emitted.report);
    emitted.satisfies(expect)
}

/// Why a named syscall cannot run in this build, or `None` when it can.
fn unavailable(name: &str) -> Option<String> {
    let legacy = matches!(
        name,
        "open" | "creat" | "mkdir" | "rename" | "unlink" | "rmdir" | "link" | "symlink" | "mknod"
    );
    if legacy && !raw::has_legacy_syscalls() {
        return Some(format!(
            "{name} has no syscall number on {}/{}; use the *at variant",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
    }
    // `mknodat` is here rather than in the legacy set: Darwin has no such
    // syscall at all, while Linux has it on every architecture.
    let linux_only = matches!(name, "openat2" | "renameat2" | "execveat" | "mknodat");
    if linux_only && !cfg!(target_os = "linux") {
        return Some(format!(
            "{name} is a Linux syscall; unsupported on this platform ({})",
            std::env::consts::OS
        ));
    }
    None
}

// ------------------------------------------------------------------- network

fn connect(rep: &Reporter, addr: &str, udp: bool, expect: &Expect) -> Result<bool, Usage> {
    let sock: std::net::SocketAddr = addr.parse().map_err(|_| {
        format!(
            "`{addr}` is not a numeric ADDR:PORT. The fixture refuses names on purpose: \
             resolving one would issue its own connects and pollute the trace."
        )
    })?;

    let (family, ty) = (
        if sock.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        },
        if udp {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_STREAM
        },
    );

    let mut sreport = OpReport::new("socket");
    sreport.set(
        "family",
        if sock.is_ipv4() {
            "AF_INET"
        } else {
            "AF_INET6"
        },
    );
    sreport.set("type", if udp { "SOCK_DGRAM" } else { "SOCK_STREAM" });
    // SAFETY: plain integer arguments; the call allocates a descriptor or fails.
    let fd = unsafe { libc::socket(family, ty, 0) };
    let serrno = if fd < 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    sreport.result(i64::from(fd), serrno);
    rep.emit(&sreport);
    if fd < 0 {
        // Without a socket there is no connect to expect anything of.
        return Ok(false);
    }

    let mut report = OpReport::new("connect");
    report.set("addr", addr);
    report.set(
        "family",
        if sock.is_ipv4() {
            "AF_INET"
        } else {
            "AF_INET6"
        },
    );
    report.set("type", if udp { "SOCK_DGRAM" } else { "SOCK_STREAM" });
    report.set("mechanism", raw::mechanism());

    let attempt = match sock {
        std::net::SocketAddr::V4(v4) => {
            // SAFETY: `sockaddr_in` is plain data; zeroing it is a valid value.
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            raw::connect(
                fd,
                std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        std::net::SocketAddr::V6(v6) => {
            // SAFETY: `sockaddr_in6` is plain data; zeroing it is a valid value.
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            sa.sin6_scope_id = v6.scope_id();
            raw::connect(
                fd,
                std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    let emitted = finish(report, attempt);
    // SAFETY: `fd` is the descriptor this function created and still owns.
    unsafe { libc::close(fd) };
    rep.emit(&emitted.report);
    Ok(emitted.satisfies(expect))
}

// ------------------------------------------------------------------ processes

/// Argv/envp kept alive for the duration of an exec, with their pointer arrays.
pub(crate) struct Image {
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_ptrs: Vec<*const c_char>,
    envp_ptrs: Vec<*const c_char>,
    path: CString,
}

pub(crate) fn image(argv: &[OsString]) -> Result<Image, Usage> {
    let path = raw::cpath(&argv[0])
        .map_err(|e| format!("argv[0] cannot be a syscall argument: {}", e.reason))?;
    let mut cargv = Vec::with_capacity(argv.len());
    for a in argv {
        cargv.push(
            CString::new(a.as_bytes())
                .map_err(|_| "an argument contains an interior NUL".to_string())?,
        );
    }
    let mut cenvp = Vec::new();
    for (k, v) in std::env::vars_os() {
        let mut joined = k.into_vec();
        joined.push(b'=');
        joined.extend_from_slice(v.as_bytes());
        if let Ok(c) = CString::new(joined) {
            cenvp.push(c);
        }
    }
    let mut argv_ptrs: Vec<*const c_char> = cargv.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const c_char> = cenvp.iter().map(|c| c.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());
    Ok(Image {
        _argv: cargv,
        _envp: cenvp,
        argv_ptrs,
        envp_ptrs,
        path,
    })
}

pub(crate) fn exec_name(via: ExecVia) -> &'static str {
    match via {
        ExecVia::Execve => "execve",
        ExecVia::Execveat => "execveat",
    }
}

pub(crate) fn do_exec(img: &Image, via: ExecVia) -> Attempt {
    match via {
        ExecVia::Execve => raw::execve(
            img.path.as_ptr(),
            img.argv_ptrs.as_ptr(),
            img.envp_ptrs.as_ptr(),
        ),
        ExecVia::Execveat => raw::execveat(
            libc::AT_FDCWD,
            img.path.as_ptr(),
            img.argv_ptrs.as_ptr(),
            img.envp_ptrs.as_ptr(),
            0,
        ),
    }
}

pub(crate) fn argv_report(name: &str, argv: &[OsString], via: ExecVia) -> OpReport {
    let mut report = OpReport::new(name);
    path_value(&mut report.args, "path", &argv[0]);
    report.set("argc", argv.len());
    report.set("mechanism", raw::mechanism());
    if via == ExecVia::Execveat {
        report.set("dirfd", "AT_FDCWD");
        report.set("flags", 0);
    }
    report
}

fn exec_replace(
    session: &Session<'_>,
    rep: &Reporter,
    via: ExecVia,
    argv: &[OsString],
    expect: &Expect,
) -> Result<bool, Usage> {
    let name = exec_name(via);
    if session.failed_earlier() {
        // A successful exec replaces this image, so the accumulated failure
        // would be lost. Refuse rather than hand the exit code to a program
        // that knows nothing about it.
        let mut report = argv_report(name, argv, via);
        report.set("refused", "earlier_expectation_failed");
        report.result(-1, None);
        let e = Emitted::unusable(report);
        rep.emit(&e.report);
        return Ok(false);
    }
    if let Some(reason) = unavailable(name) {
        let mut report = argv_report(name, argv, via);
        report.set("unsupported", reason);
        report.result(-1, None);
        let e = Emitted::unusable(report);
        rep.emit(&e.report);
        return Ok(false);
    }
    let img = image(argv)?;
    let report = argv_report(name, argv, via);
    // On success this call does not return: the image is gone and there is
    // nothing left to report. That absence is the evidence.
    let emitted = finish(report, do_exec(&img, via));
    rep.emit(&emitted.report);
    Ok(emitted.satisfies(expect))
}

fn exec_and_wait(
    rep: &Reporter,
    via: ExecVia,
    argv: &[OsString],
    expect: &Expect,
) -> Result<bool, Usage> {
    let name = exec_name(via);
    if let Some(reason) = unavailable(name) {
        let mut report = argv_report(name, argv, via);
        report.set("unsupported", reason);
        report.result(-1, None);
        let e = Emitted::unusable(report);
        rep.emit(&e.report);
        return Ok(false);
    }
    let img = image(argv)?;
    let spawned = spawn_exec(&img, via)?;
    let emitted = Emitted::done(spawned.report(argv, via));
    rep.emit(&emitted.report);
    let exec_ok = emitted.satisfies(expect);
    rep.emit(&wait_report(spawned.pid, None));
    Ok(exec_ok)
}

/// A child forked and exec'd by [`spawn_exec`].
pub(crate) struct Spawned {
    pub(crate) pid: libc::pid_t,
    /// The descriptor number the child used to report an exec failure.
    error_pipe_fd: c_int,
    /// The exec's errno when it failed; `None` once the image was replaced.
    exec_errno: Option<c_int>,
}

impl Spawned {
    /// The `execve`/`execveat` line for this spawn.
    pub(crate) fn report(&self, argv: &[OsString], via: ExecVia) -> OpReport {
        let mut report = argv_report(exec_name(via), argv, via);
        report.set("pid", self.pid);
        // The descriptor the child used to report an exec failure. It is
        // close-on-exec, so a successful exec closes it; naming it lets a test
        // assert its absence in the target exactly, instead of guessing which
        // of the descriptors the environment supplied is ours.
        report.set("error_pipe_fd", self.error_pipe_fd);
        match self.exec_errno {
            Some(e) => report.result(-1, Some(e)),
            None => report.result(0, None),
        }
        report
    }

    pub(crate) fn exec_failed(&self) -> bool {
        self.exec_errno.is_some()
    }
}

/// Fork, exec IMG in the child, and return once the exec has happened or
/// failed. Never waits for the child to exit.
pub(crate) fn spawn_exec(img: &Image, via: ExecVia) -> Result<Spawned, Usage> {
    // Both ends are close-on-exec. The write end MUST be: it used to survive
    // the target's `execve`, which handed a harness-private descriptor to the
    // target (the thing X06 rules out) and made the parent's read wait for
    // every descendant to die instead of for the exec.
    let (pr, pw) =
        cloexec_pipe().map_err(|e| format!("could not create the exec error pipe: {e}"))?;

    // SAFETY: this process is single-threaded at this point; the child runs
    // only async-signal-safe calls (`close`, the exec syscall, `write`,
    // `_exit`) and every buffer it touches was built before the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: both descriptors are owned by this process.
        unsafe {
            libc::close(pr);
            libc::close(pw);
        }
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: async-signal-safe only, on descriptors this child owns.
        unsafe { libc::close(pr) };
        let _ = do_exec(img, via);
        let e = raw_errno();
        let bytes = e.to_ne_bytes();
        // SAFETY: `bytes` is live for the call; short writes are irrelevant
        // because the parent treats any error byte count as a failed exec.
        unsafe {
            libc::write(pw, bytes.as_ptr().cast::<libc::c_void>(), bytes.len());
            libc::_exit(127)
        };
    }

    // The parent closes its write end; the child's copy closes on `exec`, so
    // the read below sees EOF exactly when the target image is established,
    // and never waits for a descendant.
    // SAFETY: the parent owns this descriptor.
    unsafe { libc::close(pw) };
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    loop {
        // SAFETY: `buf` is live and the offset stays inside it.
        let n = unsafe {
            libc::read(
                pr,
                buf.as_mut_ptr().add(got).cast::<libc::c_void>(),
                buf.len() - got,
            )
        };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            break;
        }
        got += n as usize;
        if got == buf.len() {
            break;
        }
    }
    // SAFETY: the parent owns the read end.
    unsafe { libc::close(pr) };

    Ok(Spawned {
        pid,
        error_pipe_fd: pw,
        exec_errno: (got == buf.len()).then(|| c_int::from_ne_bytes(buf)),
    })
}

/// Wait for this process's own child `pid` and describe its status.
///
/// With a deadline the wait is bounded: a child still running when it passes
/// is killed with SIGKILL, reaped, and the line says so. Without one the wait
/// blocks, as the `exec` mode always has.
pub(crate) fn wait_report(
    pid: libc::pid_t,
    deadline: Option<crate::bounded::Deadline>,
) -> OpReport {
    let mut status: c_int = 0;
    let mut killed = false;
    let waited = match deadline {
        None => {
            // SAFETY: `status` is a live int; `pid` is this process's own child.
            unsafe { libc::waitpid(pid, &raw mut status, 0) }
        }
        Some(deadline) => loop {
            // SAFETY: as above, without blocking.
            let w = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if w != 0 {
                break w;
            }
            if deadline.expired() {
                // SAFETY: `pid` is this process's own unreaped child, so the
                // number cannot have been reused by another process.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                killed = true;
                // SAFETY: as above; the child is dying, so this returns.
                break unsafe { libc::waitpid(pid, &raw mut status, 0) };
            }
            // A bound on a child that should already be finishing, not a
            // synchronisation: nothing is ordered by this sleep.
            sleep_ms(5);
        },
    };
    let mut wreport = OpReport::new("wait");
    wreport.set("pid", pid);
    if deadline.is_some() {
        wreport.set("killed_at_deadline", killed);
    }
    if waited < 0 {
        wreport.result(-1, std::io::Error::last_os_error().raw_os_error());
    } else {
        wreport.set("exited", libc::WIFEXITED(status));
        wreport.set(
            "code",
            if libc::WIFEXITED(status) {
                Value::from(libc::WEXITSTATUS(status))
            } else {
                Value::Null
            },
        );
        wreport.set(
            "signal",
            if libc::WIFSIGNALED(status) {
                Value::from(libc::WTERMSIG(status))
            } else {
                Value::Null
            },
        );
        wreport.result(i64::from(status), None);
    }
    wreport
}

fn background(rep: &Reporter, ms: u64, argv: &[OsString]) -> Result<bool, Usage> {
    let img = if argv.is_empty() {
        None
    } else {
        Some(image(argv)?)
    };

    // The child reports whether `setsid` succeeded, so `detached` is a
    // measurement rather than an assumption. One byte, no sleep.
    let (sr, sw) = cloexec_pipe().map_err(|e| format!("could not create the detach pipe: {e}"))?;

    // SAFETY: single-threaded at this point; the child runs only `setsid`,
    // `write`, `close`, `nanosleep`, the exec syscall and `_exit`, all
    // async-signal-safe, over buffers built before the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: both descriptors are owned here.
        unsafe {
            libc::close(sr);
            libc::close(sw);
        }
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: async-signal-safe; detaches the descendant from this session.
        let sid = unsafe { libc::setsid() };
        // SAFETY: the child owns the read end and writes one byte of result
        // through the write end; `close` and `write` are async-signal-safe.
        unsafe {
            libc::close(sr);
            let byte = [u8::from(sid >= 0)];
            libc::write(sw, byte.as_ptr().cast::<libc::c_void>(), 1);
            libc::close(sw);
        }
        sleep_ms(ms);
        if let Some(img) = &img {
            let _ = do_exec(img, ExecVia::Execve);
        }
        // SAFETY: the only correct exit from a forked child that did not exec.
        unsafe { libc::_exit(0) };
    }

    // SAFETY: the parent owns the write end and closes it so the read ends.
    unsafe { libc::close(sw) };
    let mut byte = [0u8; 1];
    // SAFETY: `byte` is live; the child writes exactly one byte right after
    // `setsid`, so this returns immediately and never sleeps.
    let got = unsafe { libc::read(sr, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
    // SAFETY: the parent owns the read end.
    unsafe { libc::close(sr) };
    let detached = got == 1 && byte[0] == 1;

    let mut report = OpReport::new("background");
    report.set("pid", pid);
    report.set("delay_ms", ms);
    report.set("argc", argv.len());
    report.set("detached", detached);
    report.result(i64::from(pid), None);
    rep.emit(&report);
    Ok(detached)
}

fn fork_storm(rep: &Reporter, count: u32) -> bool {
    let mut forked = 0u32;
    // Reserve for what a process could plausibly fork, not for what was
    // asked: `fork-storm 4000000000` reserved about 16 GB before forking once.
    let mut pids: Vec<libc::pid_t> = Vec::with_capacity(std::cmp::min(count, 4096) as usize);
    for _ in 0..count {
        // SAFETY: single-threaded; the child only calls `_exit`.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            break;
        }
        if pid == 0 {
            // SAFETY: the only correct exit from a forked child.
            unsafe { libc::_exit(0) };
        }
        forked += 1;
        pids.push(pid);
    }
    let mut reaped = 0u32;
    for pid in pids {
        let mut status: c_int = 0;
        // SAFETY: `status` is live; `pid` is this process's own child.
        if unsafe { libc::waitpid(pid, &raw mut status, 0) } == pid {
            reaped += 1;
        }
    }
    let mut report = OpReport::new("fork-storm");
    report.set("requested", count);
    report.set("forked", forked);
    report.set("reaped", reaped);
    report.result(i64::from(reaped), None);
    rep.emit(&report);
    forked == count && reaped == count
}

fn thread(rep: &Reporter) -> bool {
    let handle = std::thread::spawn(|| {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `gettid` takes no arguments and only reads kernel state.
            unsafe { libc::syscall(libc::SYS_gettid) }
        }
        #[cfg(not(target_os = "linux"))]
        {
            -1i64
        }
    });
    let mut report = OpReport::new("thread");
    match handle.join() {
        Ok(tid) => {
            report.set(
                "tid",
                if tid >= 0 {
                    Value::from(tid)
                } else {
                    Value::Null
                },
            );
            report.set("joined", true);
            report.result(0, None);
            rep.emit(&report);
            true
        }
        Err(_) => {
            report.set("joined", false);
            report.result(-1, None);
            rep.emit(&report);
            false
        }
    }
}

fn raise(rep: &Reporter, signal: &str) -> Result<bool, Usage> {
    let sig = parse_signal(signal)?;
    let mut report = OpReport::new("raise");
    report.set("signal", signal.to_uppercase());
    report.set("signum", sig);
    // SAFETY: restoring the default disposition of a valid signal number.
    unsafe { libc::signal(sig, libc::SIG_DFL) };
    report.result(0, None);
    rep.emit(&report);
    // SAFETY: sending a signal to this very process.
    let r = unsafe { libc::kill(libc::getpid(), sig) };
    Ok(r == 0)
}

fn parse_signal(s: &str) -> Result<c_int, Usage> {
    if let Ok(n) = s.parse::<c_int>() {
        if n > 0 && n < 64 {
            return Ok(n);
        }
        return Err(format!("`{s}` is not a signal number in 1..63"));
    }
    let upper = s.to_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let sig = match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ILL" => libc::SIGILL,
        "ABRT" => libc::SIGABRT,
        "FPE" => libc::SIGFPE,
        "KILL" => libc::SIGKILL,
        "SEGV" => libc::SIGSEGV,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "CHLD" => libc::SIGCHLD,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        _ => return Err(format!("unknown signal `{s}`")),
    };
    Ok(sig)
}

fn ignore_term() {
    // SAFETY: setting SIG_IGN for a valid signal number.
    unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
}

// ------------------------------------------------------------------ reporting

fn echo_args(rep: &Reporter, argv: &[OsString]) {
    let mut report = OpReport::new("echo-args");
    report.set("count", argv.len());
    let items: Vec<Value> = argv
        .iter()
        .map(|a| {
            let bytes = a.as_bytes();
            let mut m = serde_json::Map::new();
            m.insert("len".into(), Value::from(bytes.len()));
            m.insert(
                "bytes".into(),
                Value::Array(bytes.iter().map(|b| Value::from(*b)).collect()),
            );
            m.insert(
                "lossy".into(),
                Value::String(String::from_utf8_lossy(bytes).into_owned()),
            );
            Value::Object(m)
        })
        .collect();
    report.set("argv", Value::Array(items));
    report.result(argv.len() as i64, None);
    rep.emit(&report);
}

/// Byte `i` of the stream is `i % 256`, so every byte value including NUL
/// appears and any truncation or re-encoding is visible.
fn stream_bytes(rep: &Reporter, fd: c_int, count: u64, name: &str) -> bool {
    const CHUNK: usize = 64 * 1024; // a multiple of 256, so chunks tile exactly
    let pattern: Vec<u8> = (0..CHUNK).map(|i| (i % 256) as u8).collect();
    let mut left = count;
    let mut ok = true;
    while left > 0 {
        let n = std::cmp::min(left, CHUNK as u64) as usize;
        if !write_all(fd, &pattern[..n]) {
            ok = false;
            break;
        }
        left -= n as u64;
    }
    let mut report = OpReport::new(name);
    report.set("fd", fd);
    report.set("requested", count);
    report.set("written", count - left);
    report.set("pattern", "byte i = i % 256");
    report.result((count - left) as i64, None);
    rep.emit(&report);
    ok
}

fn env_names(rep: &Reporter) {
    let mut names: Vec<String> = Vec::new();
    let mut non_utf8 = 0usize;
    for (k, _value) in std::env::vars_os() {
        if std::str::from_utf8(k.as_bytes()).is_err() {
            non_utf8 += 1;
        }
        names.push(String::from_utf8_lossy(k.as_bytes()).into_owned());
    }
    names.sort();
    let mut report = OpReport::new("env");
    report.set("count", names.len());
    report.set("non_utf8_names", non_utf8);
    report.set(
        "names",
        Value::Array(names.into_iter().map(Value::from).collect()),
    );
    report.set("values_reported", false);
    report.result(0, None);
    rep.emit(&report);
}

/// The kernel's own list of this process's open descriptors.
///
/// `/proc/self/fd` on Linux and `/dev/fd` on Darwin are the authoritative
/// enumerations. Probing a range instead used to stop at 4096, so a leaked
/// descriptor numbered above that was invisible and X06 ("no private
/// authority reaches it") could pass with the leak in place.
fn fd_directory() -> &'static str {
    if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    }
}

/// Descriptor numbers the kernel says are open, or `None` when the directory
/// could not be listed. The directory's own descriptor is excluded: it is
/// closed before the numbers are confirmed.
fn open_fd_numbers() -> Option<Vec<c_int>> {
    let entries = std::fs::read_dir(fd_directory()).ok()?;
    let mut numbers: Vec<c_int> = Vec::new();
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && let Ok(n) = name.parse::<c_int>()
        {
            numbers.push(n);
        }
    }
    // `entries` is dropped here, closing the descriptor the listing used, so
    // the confirmation pass below drops it from the result.
    numbers.sort_unstable();
    Some(numbers)
}

fn soft_fd_limit() -> u64 {
    // SAFETY: `rl` is a live rlimit struct, which is what `getrlimit` writes.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) } == 0 {
        rl.rlim_cur as u64
    } else {
        0
    }
}

fn describe_fd(fd: c_int) -> Option<Value> {
    // SAFETY: `F_GETFD` only reads the descriptor flags and is safe for any
    // integer; a closed descriptor returns -1 with EBADF.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return None;
    }
    // SAFETY: `st` is a live stat struct for an open descriptor.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let kind = if unsafe { libc::fstat(fd, &raw mut st) } == 0 {
        match st.st_mode & libc::S_IFMT {
            libc::S_IFIFO => "fifo",
            libc::S_IFCHR => "character",
            libc::S_IFDIR => "directory",
            libc::S_IFBLK => "block",
            libc::S_IFREG => "regular",
            libc::S_IFLNK => "symlink",
            libc::S_IFSOCK => "socket",
            _ => "unknown",
        }
    } else {
        "unreadable"
    };
    let mut m = serde_json::Map::new();
    m.insert("fd".into(), Value::from(fd));
    m.insert("kind".into(), Value::from(kind));
    m.insert("cloexec".into(), Value::from(flags & libc::FD_CLOEXEC != 0));
    Some(Value::Object(m))
}

fn fds(rep: &Reporter) -> bool {
    let limit = soft_fd_limit();
    let (numbers, source, complete) = match open_fd_numbers() {
        Some(n) => (n, fd_directory().to_string(), true),
        None => {
            // Fall back to probing the whole soft limit rather than a fixed
            // slice of it, and say that is what happened.
            let cap = c_int::try_from(limit).unwrap_or(c_int::MAX);
            (
                (0..cap).collect(),
                format!("scan 0..{cap}"),
                cap as u64 >= limit,
            )
        }
    };

    let open: Vec<Value> = numbers.into_iter().filter_map(describe_fd).collect();

    let mut report = OpReport::new("fds");
    report.set("source", source);
    report.set("soft_limit", limit);
    report.set("complete", complete);
    report.set("count", open.len());
    report.set("fds", Value::Array(open));
    report.set("paths_reported", false);
    report.result(0, None);
    rep.emit(&report);
    // An enumeration that could have missed a descriptor is not a result.
    complete
}

fn status(rep: &Reporter) -> bool {
    let mut report = OpReport::new("status");
    #[cfg(target_os = "linux")]
    {
        const WANTED: &[&str] = &[
            "Uid",
            "Gid",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
            "Seccomp",
            "Seccomp_filters",
            "NSpid",
            "TracerPid",
        ];
        match std::fs::read_to_string("/proc/self/status") {
            Ok(text) => {
                let mut found = serde_json::Map::new();
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && WANTED.contains(&k)
                    {
                        found.insert(k.to_string(), Value::from(v.trim()));
                    }
                }
                let missing: Vec<&&str> =
                    WANTED.iter().filter(|k| !found.contains_key(**k)).collect();
                report.set("fields", Value::Object(found));
                report.set(
                    "missing",
                    Value::Array(missing.into_iter().map(|k| Value::from(*k)).collect()),
                );
                report.set("source", "/proc/self/status");
                report.result(0, None);
                rep.emit(&report);
                true
            }
            Err(e) => {
                report.set("source", "/proc/self/status");
                report.result(-1, e.raw_os_error());
                rep.emit(&report);
                false
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        report.set(
            "unsupported",
            format!(
                "/proc/self/status is a Linux interface; unsupported on this platform ({})",
                std::env::consts::OS
            ),
        );
        report.result(-1, None);
        let e = Emitted::unusable(report);
        rep.emit(&e.report);
        false
    }
}

fn write_mmap(rep: &Reporter, path: &OsStr) -> bool {
    const LEN: usize = 4096;
    // One open, one reported line: reopening silently would put a second
    // `openat` in a tracer's view that no report line accounts for.
    let opened = open_keep(path, OpenVia::Openat, true, true, false, true, 0o600);
    rep.emit(&opened.report);
    if opened.unusable || opened.report.ret < 0 {
        return false;
    }
    let fd = opened.report.ret as c_int;

    let mut ok = true;
    let tr = match raw::ftruncate(fd, LEN as i64) {
        Attempt::Performed { ret, .. } => ret,
        Attempt::Absent(_) => -1,
    };
    let mut r = OpReport::new("ftruncate");
    r.set("len", LEN);
    r.set("closed_set", false);
    r.result(
        tr,
        if tr < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
    );
    ok &= tr == 0;
    rep.emit(&r);

    let payload = b"ouro-fixture:write\n";
    // SAFETY: `payload` is live; `fd` is open for writing.
    let wn = unsafe { libc::write(fd, payload.as_ptr().cast::<libc::c_void>(), payload.len()) };
    let mut r = OpReport::new("write");
    r.set("len", payload.len());
    r.set("closed_set", false);
    r.result(
        wn as i64,
        if wn < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
    );
    ok &= wn == payload.len() as isize;
    rep.emit(&r);

    // SAFETY: `fd` is an open regular file of at least LEN bytes; the kernel
    // chooses the address and the mapping is unmapped below.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    let mut r = OpReport::new("mmap");
    r.set("len", LEN);
    r.set("closed_set", false);
    if addr == libc::MAP_FAILED {
        r.result(-1, std::io::Error::last_os_error().raw_os_error());
        rep.emit(&r);
        // SAFETY: `fd` is owned here.
        unsafe { libc::close(fd) };
        return false;
    }
    r.result(0, None);
    rep.emit(&r);

    let stored = b"ouro-fixture:mmap\n";
    // SAFETY: the mapping is LEN bytes of writable memory and `stored` is
    // much shorter than LEN.
    unsafe {
        std::ptr::copy_nonoverlapping(stored.as_ptr(), addr.cast::<u8>(), stored.len());
    }
    // SAFETY: `addr`/`LEN` are exactly the mapping created above.
    let sy = unsafe { libc::msync(addr, LEN, libc::MS_SYNC) };
    let mut r = OpReport::new("msync");
    r.set("stored_through_mapping", stored.len());
    r.set("closed_set", false);
    r.result(
        i64::from(sy),
        if sy < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
    );
    ok &= sy == 0;
    rep.emit(&r);

    // SAFETY: `addr`/`LEN` are exactly the mapping created above.
    let un = unsafe { libc::munmap(addr, LEN) };
    let mut r = OpReport::new("munmap");
    r.set("closed_set", false);
    r.result(i64::from(un), None);
    ok &= un == 0;
    rep.emit(&r);

    // SAFETY: `fd` is owned here and used nowhere else afterwards.
    unsafe { libc::close(fd) };
    ok
}

// -------------------------------------------------------------------- script

/// Does this mode end the process, so that nothing after it can run?
fn terminates_the_process(mode: &Mode) -> Option<&'static str> {
    match mode {
        Mode::Exit { .. } => Some("exit"),
        Mode::ExecReplace { .. } => Some("exec-replace"),
        Mode::SandboxExec { .. } => Some("sandbox-exec"),
        Mode::Raise { .. } => Some("raise"),
        _ => None,
    }
}

fn script(session: &Session<'_>, file: &OsStr) -> Result<bool, Usage> {
    let text = std::fs::read_to_string(std::path::Path::new(file))
        .map_err(|e| format!("cannot read script {}: {e}", file.to_string_lossy()))?;
    let steps: Vec<Vec<String>> = serde_json::from_str(&text)
        .map_err(|e| format!("script must be a JSON array of argv arrays: {e}"))?;
    let count = steps.len();
    session.in_script.set(true);
    let mut all_ok = true;
    for (i, argv) in steps.into_iter().enumerate() {
        if argv.is_empty() {
            return Err(format!("script step {i} is empty"));
        }
        let step = Step::try_parse_from(std::iter::once("ouro-fixture".to_string()).chain(argv))
            .map_err(|e| format!("script step {i}: {e}"))?;
        if let Some(name) = terminates_the_process(&step.mode)
            && i + 1 != count
        {
            return Err(format!(
                "script step {i} is `{name}`, which ends the process: \
                 the {} step(s) after it could never run",
                count - i - 1
            ));
        }
        all_ok &= run_in(session, step.mode)?;
    }
    Ok(all_ok)
}

// --------------------------------------------------------------------- timing

pub(crate) fn sleep_ms(ms: u64) {
    let mut req = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as _,
    };
    loop {
        // SAFETY: both arguments are live timespec values.
        let mut rem: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let r = unsafe { libc::nanosleep(&raw const req, &raw mut rem) };
        if r == 0 {
            return;
        }
        if raw_errno() != libc::EINTR {
            return;
        }
        req = rem;
    }
}

fn spin_ms(ms: u64) {
    let start = std::time::Instant::now();
    let target = std::time::Duration::from_millis(ms);
    let mut acc: u64 = 0;
    while start.elapsed() < target {
        for i in 0..10_000u64 {
            acc = acc.wrapping_add(i).wrapping_mul(2_654_435_761);
        }
    }
    std::hint::black_box(acc);
}

use clap::Parser as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_names_only_what_this_build_lacks() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(unavailable("openat2"), None);
            assert_eq!(unavailable("renameat2"), None);
            assert_eq!(unavailable("execveat"), None);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let r = unavailable("openat2").expect("openat2 is Linux-only");
            assert!(r.contains("unsupported on this platform"), "{r}");
            assert!(unavailable("renameat2").is_some());
            assert!(unavailable("execveat").is_some());
        }
        assert_eq!(unavailable("openat"), None);
        assert_eq!(unavailable("unlinkat"), None);
    }

    #[test]
    fn legacy_variants_track_the_architecture() {
        let expected_absent = !raw::has_legacy_syscalls();
        assert_eq!(unavailable("open").is_some(), expected_absent);
        assert_eq!(unavailable("rmdir").is_some(), expected_absent);
        assert_eq!(
            unavailable("mknod").is_some(),
            expected_absent,
            "mknod is one of the numbers aarch64 dropped"
        );
    }

    #[test]
    fn mknodat_is_linux_only_while_truncation_is_portable() {
        // Darwin has `mknod` but no `mknodat`, so the two are classified
        // differently even though they are the same operation.
        assert_eq!(unavailable("mknodat").is_some(), !cfg!(target_os = "linux"));
        assert_eq!(unavailable("truncate"), None);
        assert_eq!(unavailable("ftruncate"), None);
    }

    #[test]
    fn a_mknod_mode_carries_the_file_type_bits_with_the_permissions() {
        // `mknod` takes one `mode`; getting the type bits wrong silently
        // creates the wrong kind of node.
        //
        // `mknod` rather than `mknodat` so this runs on both platforms: the
        // mode is computed and reported before the syscall, so a Darwin EPERM
        // does not hide it.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("f");
        let e = mknod(fifo.as_os_str(), MknodVia::Mknod, false, 0o600);
        if e.unusable {
            // An architecture without the legacy number; it says so and the
            // `unavailable` tests above cover that classification.
            assert!(e.report.args.contains_key("unsupported"));
            return;
        }
        let mode = e.report.args.get("mode").unwrap().as_str().unwrap();
        let mode = u32::from_str_radix(mode, 8).unwrap();
        assert_eq!(mode & 0o7777, 0o600);
        assert_eq!(mode & file_type_mask(), file_type_bits(false));
        assert_ne!(file_type_bits(true), file_type_bits(false));
        assert_eq!(e.report.args.get("dev").unwrap(), 0);
        assert_eq!(e.report.args.get("kind").unwrap(), "S_IFIFO");
    }

    #[test]
    fn signals_parse_by_name_number_and_sig_prefix() {
        assert_eq!(parse_signal("TERM").unwrap(), libc::SIGTERM);
        assert_eq!(parse_signal("sigterm").unwrap(), libc::SIGTERM);
        assert_eq!(parse_signal("9").unwrap(), 9);
        assert!(parse_signal("NOPE").is_err());
        assert!(parse_signal("0").is_err());
        assert!(parse_signal("999").is_err());
    }

    #[test]
    fn an_interior_nul_path_never_reaches_a_syscall() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = dir.path().join("boundary").into_os_string().into_vec();
        bytes.extend_from_slice(b"\0ignored");
        let bad = OsString::from_vec(bytes);

        let e = open(&bad, OpenVia::Openat, true, false, true, false, 0o600);
        assert!(e.unusable, "a refused path must satisfy nothing");
        assert_eq!(e.report.args.get("refused").unwrap(), "interior_nul");
        assert_eq!(e.report.ret, -1);
        assert!(e.report.errno.is_none());
        assert!(
            !dir.path().join("boundary").exists(),
            "the truncated path must not have been created"
        );
        assert!(!e.satisfies(&Expect::Ok));
        assert!(!e.satisfies(&Expect::Any));
    }

    #[test]
    fn an_image_refuses_an_argument_with_an_interior_nul() {
        use std::os::unix::ffi::OsStringExt;
        let argv = vec![
            OsString::from("/bin/true"),
            OsString::from_vec(b"a\0b".to_vec()),
        ];
        let err = match image(&argv) {
            Err(e) => e,
            Ok(_) => panic!("an interior NUL in argv must be refused"),
        };
        assert!(err.contains("interior NUL"), "{err}");
    }

    #[test]
    fn the_byte_pattern_covers_every_byte_value() {
        let pattern: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let mut seen = [false; 256];
        for b in &pattern[..256] {
            seen[*b as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert_eq!(pattern[0], 0, "NUL is in the stream");
        assert_eq!(pattern[256], pattern[0], "chunks of 64 KiB tile exactly");
    }
}
