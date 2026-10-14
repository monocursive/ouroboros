//! Running a program: the image an exec takes, the exec itself, a child
//! forked and exec'd, and its wait status.

use std::ffi::{CString, OsString, c_char, c_int};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use serde_json::Value;

use crate::cli::ExecVia;
use crate::raw::{self, Attempt};
use crate::report::{Emitted, Expect, OpReport, Reporter, path_value};

use super::process::sleep_ms;
use super::{Session, Usage, cloexec_pipe, finish, raw_errno, unavailable};

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

pub(crate) fn exec_replace(
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

pub(crate) fn exec_and_wait(
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
    pub(crate) exec_errno: Option<c_int>,
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
        // SAFETY: `bytes` is live for the call. A four-byte write to a pipe
        // is atomic (PIPE_BUF is at least 512), so the parent reads either
        // nothing (the image was replaced) or all four bytes.
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
    // A partial errno is a failed exec whose errno was cut: never success.
    if got != 0 && got != buf.len() {
        return Err(format!(
            "the exec error pipe returned {got} of {} bytes",
            buf.len()
        ));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_refuses_an_argument_with_an_interior_nul() {
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
}
