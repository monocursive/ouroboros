//! The operation modes.
//!
//! Every filesystem, network and process operation goes through [`crate::raw`]
//! so the syscall a test names is the syscall a tracer sees. Each operation
//! emits exactly one report line; a mode that performs several operations
//! emits several lines, in the order they ran.
//!
//! [`run`] hands each group of modes to the module that holds it: the
//! filesystem modes (`fs`), the process and lifetime modes (`process`, with
//! the exec machinery in `exec`), the introspection modes (`introspect`),
//! `script`, and the network, Unix-socket, inner-sandbox and performance
//! modes in their own crate modules.

use std::ffi::{OsStr, c_int};

use crate::cli::Mode;
use crate::raw::{self, Attempt};
use crate::report::{Emitted, Expect, OpReport, Reporter, path_value};

pub(crate) mod exec;
pub(crate) mod fs;
mod introspect;
pub(crate) mod process;
mod script;

pub use introspect::open_fd_numbers;

/// A pipe whose two ends are both close-on-exec ([`crate::harness::pipes::cloexec_pipe`]),
/// as raw numbers: the callers hand them across a `fork`.
pub(crate) fn cloexec_pipe() -> Result<(c_int, c_int), std::io::Error> {
    use std::os::fd::IntoRawFd as _;
    let (read, write) = crate::harness::pipes::cloexec_pipe()?;
    Ok((read.into_raw_fd(), write.into_raw_fd()))
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

/// Why a mode stopped without its result. Neither is the outcome of the
/// operation under test, so neither is an expectation that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The invocation is wrong (an argument, a flag combination or a script
    /// the fixture refuses), found before anything ran.
    /// Exit [`crate::EXIT_USAGE`].
    Usage(String),
    /// The fixture stopped after something ran: an operation it needed for
    /// itself failed (a directory descriptor, a pipe, a fork, writing its
    /// result file), after the report line of whatever it attempted, or a
    /// script step was refused after earlier steps had acted.
    /// Exit [`crate::EXIT_FIXTURE_FAILED`].
    Failed(String),
}

impl Stop {
    /// The exit code the fixture ends with.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Stop::Usage(_) => crate::EXIT_USAGE,
            Stop::Failed(_) => crate::EXIT_FIXTURE_FAILED,
        }
    }
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stop::Usage(why) | Stop::Failed(why) => f.write_str(why),
        }
    }
}

/// State shared by every step of one fixture process.
///
/// It exists because `exit` and a successful `exec-replace` end the process:
/// without it, a `script` whose last step is `exit 0` would discard every
/// earlier failed expectation and report success.
pub struct Session<'a> {
    pub(crate) rep: &'a Reporter,
    failed: std::cell::Cell<bool>,
}

impl<'a> Session<'a> {
    #[must_use]
    pub fn new(rep: &'a Reporter) -> Session<'a> {
        Session {
            rep,
            failed: std::cell::Cell::new(false),
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

pub(crate) fn refuse_path(
    mut report: OpReport,
    key: &str,
    p: &OsStr,
    reason: &'static str,
) -> Emitted {
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
pub fn run(mode: Mode, rep: &Reporter) -> Result<bool, Stop> {
    let session = Session::new(rep);
    let ok = run_in(&session, mode)?;
    Ok(ok && !session.failed_earlier())
}

/// Run one mode inside an existing session.
pub fn run_in(session: &Session<'_>, mode: Mode) -> Result<bool, Stop> {
    let rep = session.rep;
    let ok = run_mode(session, rep, mode)?;
    Ok(session.record(ok))
}

/// Hand one mode to the module of its group.
fn run_mode(session: &Session<'_>, rep: &Reporter, mode: Mode) -> Result<bool, Stop> {
    match mode {
        Mode::Fs(mode) => fs::run(rep, mode),
        Mode::Net(mode) => crate::net::run(rep, mode),
        Mode::Unix(mode) => crate::unix::run(rep, mode),
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
        Mode::Process(mode) => process::run(session, rep, mode),
        Mode::Introspect(mode) => Ok(introspect::run(rep, mode)),
        Mode::Script { file } => script::run(session, &file),
        Mode::Perf(mode) => crate::perf::run(rep, mode),
    }
}

pub(crate) fn check(rep: &Reporter, emitted: Emitted, expect: &Expect) -> bool {
    rep.emit(&emitted.report);
    emitted.satisfies(expect)
}

/// Why `name` cannot be called on this build (the raw layer's own list), so
/// a mode can say so before preparing anything for it; `None` when it can.
pub(crate) fn unavailable(name: &str) -> Option<String> {
    raw::absent(name)
}

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
}
