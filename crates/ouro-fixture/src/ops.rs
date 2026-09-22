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
    ExecVia, LinkVia, MkdirVia, Mode, OpenVia, RenameVia, RmdirVia, Step, SymlinkVia, UnlinkVia,
    parse_mode,
};
use crate::raw::{self, Attempt};
use crate::report::{Emitted, Expect, OpReport, Reporter, path_value, write_all};

/// This thread's errno, read without allocating: safe to call after `fork`.
fn raw_errno() -> c_int {
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

fn finish(mut report: OpReport, attempt: Attempt) -> Emitted {
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

fn close_fd(ret: i64) {
    if ret >= 0 {
        // SAFETY: `ret` is a descriptor this process just opened and has not
        // handed to anything else.
        unsafe { libc::close(ret as c_int) };
    }
}

/// Run one mode. `Ok(true)` when every expectation in it held.
pub fn run(mode: Mode, rep: &Reporter) -> Result<bool, Usage> {
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
        Mode::Connect { addr, udp, expect } => connect(rep, &addr, udp, &expect),
        Mode::Exec { via, expect, argv } => exec_and_wait(rep, via, &argv, &expect),
        Mode::ExecReplace { via, expect, argv } => exec_replace(rep, via, &argv, &expect),
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
        Mode::Fds => {
            fds(rep);
            Ok(true)
        }
        Mode::Status => Ok(status(rep)),
        Mode::WriteMmap { path } => Ok(write_mmap(rep, &path)),
        Mode::Thread => Ok(thread(rep)),
        Mode::Exit { code } => {
            let mut r = OpReport::new("exit");
            r.set("code", code);
            rep.emit(&r);
            std::process::exit(code);
        }
        Mode::Raise { signal } => raise(rep, &signal),
        Mode::Script { file } => script(rep, &file),
    }
}

fn check(rep: &Reporter, emitted: Emitted, expect: &Expect) -> bool {
    rep.emit(&emitted.report);
    emitted.satisfies(expect)
}

// ---------------------------------------------------------------- filesystem

fn open(
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
    let emitted = finish(report, attempt);
    close_fd(emitted.report.ret);
    emitted
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

/// Why a named syscall cannot run in this build, or `None` when it can.
fn unavailable(name: &str) -> Option<String> {
    let legacy = matches!(
        name,
        "open" | "creat" | "mkdir" | "rename" | "unlink" | "rmdir" | "link" | "symlink"
    );
    if legacy && !raw::has_legacy_syscalls() {
        return Some(format!(
            "{name} has no syscall number on {}/{}; use the *at variant",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
    }
    let linux_only = matches!(name, "openat2" | "renameat2" | "execveat");
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
struct Image {
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_ptrs: Vec<*const c_char>,
    envp_ptrs: Vec<*const c_char>,
    path: CString,
}

fn image(argv: &[OsString]) -> Result<Image, Usage> {
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

fn exec_name(via: ExecVia) -> &'static str {
    match via {
        ExecVia::Execve => "execve",
        ExecVia::Execveat => "execveat",
    }
}

fn do_exec(img: &Image, via: ExecVia) -> Attempt {
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

fn argv_report(name: &str, argv: &[OsString], via: ExecVia) -> OpReport {
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

    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` is a live array of two ints, which is what `pipe` writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!(
            "could not create the exec error pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    let (pr, pw) = (fds[0], fds[1]);

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
        let _ = do_exec(&img, via);
        let e = raw_errno();
        let bytes = e.to_ne_bytes();
        // SAFETY: `bytes` is live for the call; short writes are irrelevant
        // because the parent treats any error byte count as a failed exec.
        unsafe {
            libc::write(pw, bytes.as_ptr().cast::<libc::c_void>(), bytes.len());
            libc::_exit(127)
        };
    }

    // SAFETY: the parent owns the write end and closes it so the read below
    // sees EOF when the child execs (the descriptor is close-on-exec free but
    // the child closed it by exec'ing... it is closed here explicitly).
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

    let mut report = argv_report(name, argv, via);
    report.set("pid", pid);
    if got == buf.len() {
        report.result(-1, Some(c_int::from_ne_bytes(buf)));
    } else {
        report.result(0, None);
    }
    let emitted = Emitted::done(report);
    rep.emit(&emitted.report);
    let exec_ok = emitted.satisfies(expect);

    let mut status: c_int = 0;
    // SAFETY: `status` is a live int; `pid` is this process's own child.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let mut wreport = OpReport::new("wait");
    wreport.set("pid", pid);
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
    rep.emit(&wreport);
    Ok(exec_ok)
}

fn background(rep: &Reporter, ms: u64, argv: &[OsString]) -> Result<bool, Usage> {
    let img = if argv.is_empty() {
        None
    } else {
        Some(image(argv)?)
    };

    // SAFETY: single-threaded at this point; the child runs only `setsid`,
    // `nanosleep`, the exec syscall and `_exit`, all async-signal-safe, over
    // buffers built before the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: async-signal-safe; detaches the descendant from this session.
        unsafe { libc::setsid() };
        sleep_ms(ms);
        if let Some(img) = &img {
            let _ = do_exec(img, ExecVia::Execve);
        }
        // SAFETY: the only correct exit from a forked child that did not exec.
        unsafe { libc::_exit(0) };
    }

    let mut report = OpReport::new("background");
    report.set("pid", pid);
    report.set("delay_ms", ms);
    report.set("argc", argv.len());
    report.set("detached", true);
    report.result(i64::from(pid), None);
    rep.emit(&report);
    Ok(true)
}

fn fork_storm(rep: &Reporter, count: u32) -> bool {
    let mut forked = 0u32;
    let mut pids = Vec::with_capacity(count as usize);
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

fn fds(rep: &Reporter) {
    // SAFETY: `rl` is a live rlimit struct, which is what `getrlimit` writes.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let limit = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) } == 0 {
        std::cmp::min(rl.rlim_cur, 4096) as c_int
    } else {
        4096
    };
    let mut open = Vec::new();
    for fd in 0..limit {
        // SAFETY: `F_GETFD` only reads the descriptor flags and is safe for
        // any integer; a closed descriptor returns -1 with EBADF.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            continue;
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
        open.push(Value::Object(m));
    }
    let mut report = OpReport::new("fds");
    report.set("scanned_to", limit);
    report.set("count", open.len());
    report.set("fds", Value::Array(open));
    report.set("paths_reported", false);
    report.result(0, None);
    rep.emit(&report);
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
    let opened = open(path, OpenVia::Openat, true, true, false, true, 0o600);
    rep.emit(&opened.report);
    if opened.report.ret < 0 {
        return false;
    }
    // `open()` closed its descriptor, so reopen and keep this one.
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let fd = match raw::openat(libc::AT_FDCWD, c.as_ptr(), libc::O_RDWR, 0) {
        Attempt::Performed { ret, .. } if ret >= 0 => ret as c_int,
        _ => return false,
    };

    let mut ok = true;
    // SAFETY: `fd` is an open regular file this process owns.
    let tr = unsafe { libc::ftruncate(fd, LEN as libc::off_t) };
    let mut r = OpReport::new("ftruncate");
    r.set("len", LEN);
    r.result(
        i64::from(tr),
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

fn script(rep: &Reporter, file: &OsStr) -> Result<bool, Usage> {
    let text = std::fs::read_to_string(std::path::Path::new(file))
        .map_err(|e| format!("cannot read script {}: {e}", file.to_string_lossy()))?;
    let steps: Vec<Vec<String>> = serde_json::from_str(&text)
        .map_err(|e| format!("script must be a JSON array of argv arrays: {e}"))?;
    let mut all_ok = true;
    for (i, argv) in steps.into_iter().enumerate() {
        if argv.is_empty() {
            return Err(format!("script step {i} is empty"));
        }
        let step = Step::try_parse_from(std::iter::once("ouro-fixture".to_string()).chain(argv))
            .map_err(|e| format!("script step {i}: {e}"))?;
        all_ok &= run(step.mode, rep)?;
    }
    Ok(all_ok)
}

// --------------------------------------------------------------------- timing

fn sleep_ms(ms: u64) {
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
