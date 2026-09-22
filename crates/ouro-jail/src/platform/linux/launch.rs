//! The inside launcher: `ouro-jail __launch`.
//!
//! jail-v1 §8.3 and CONTRACT §3.6. This is the process bubblewrap starts
//! inside the namespaces. It is the jail's own binary, bound read-only at
//! `/run/ouro/jail`, re-executed with a hidden subcommand — a re-exec rather
//! than work in `pre_exec`, so that nothing but the target's own code runs
//! after the boundary is closed.
//!
//! It does three things, in this order:
//!
//! 1. installs the narrowing filter, when observation is on;
//! 2. blocks reading one byte from the release pipe;
//! 3. `execvp`s the target.
//!
//! The blocking read is the gate: until the supervisor writes that byte, no
//! user code has run, and if the supervisor dies instead the read returns EOF
//! and the launcher exits 124 without ever executing the target. An exec that
//! fails writes its errno to a close-on-exec error pipe, so the supervisor
//! distinguishes "exec failed with ENOENT" from "exec succeeded", which is
//! EOF with no bytes.
//!
//! The narrowing filter it installs is the observer's own
//! ([`tracer::install_narrowing_filter`](super::tracer::install_narrowing_filter)),
//! so the syscalls the launcher narrows to and the syscalls the tracer
//! expects to be stopped on cannot drift apart.

use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt as _;

use super::sys::{PathError, cstring_from_os};

/// The hidden subcommand token.
pub const SUBCOMMAND: &str = "__launch";

/// Release pipe closed without a byte: the supervisor never released, so the
/// target was never executed.
pub const EXIT_NO_RELEASE: i32 = 124;
/// The launcher was invoked with arguments it cannot act on.
pub const EXIT_USAGE: i32 = 125;
/// The launcher failed before exec for a reason of its own (filter install,
/// read error). Fail-closed: the target did not run.
pub const EXIT_INTERNAL: i32 = 126;
/// `execvp` failed; the errno is on the error pipe.
pub const EXIT_EXEC_FAILED: i32 = 127;

/// Parsed `__launch` arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchArgs {
    /// Descriptor the supervisor writes one byte to in order to release.
    pub release_fd: RawFd,
    /// Descriptor the launcher writes a failed exec's errno to.
    pub error_fd: RawFd,
    /// Whether to install the narrowing filter before releasing.
    pub narrow: bool,
    /// The target's argv; element 0 is also the program to execute.
    pub argv: Vec<OsString>,
}

/// Why `__launch` cannot proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchUsage {
    /// An option that takes a value had none.
    MissingValue(&'static str),
    /// A descriptor number did not parse or was negative.
    BadFd(&'static str),
    /// An option the launcher does not know.
    UnknownOption(String),
    /// No `--` separator.
    MissingSeparator,
    /// `--` was present but nothing followed it.
    EmptyArgv,
    /// A required option was not given.
    Missing(&'static str),
    /// The program name or an argument cannot be passed to a syscall.
    Path(PathError),
    /// A descriptor number does not refer to an open descriptor.
    ClosedFd(&'static str, RawFd),
}

impl fmt::Display for LaunchUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue(o) => write!(f, "{o} needs a value"),
            Self::BadFd(o) => write!(f, "{o} needs a non-negative descriptor number"),
            Self::UnknownOption(o) => write!(f, "unknown option {o}"),
            Self::MissingSeparator => write!(f, "expected `--` before the program"),
            Self::EmptyArgv => write!(f, "no program after `--`"),
            Self::Missing(o) => write!(f, "{o} is required"),
            Self::Path(e) => write!(f, "{e}"),
            Self::ClosedFd(o, fd) => write!(f, "{o} {fd} is not open"),
        }
    }
}

impl std::error::Error for LaunchUsage {}

/// Parse `--release-fd N --error-fd M [--narrow] -- PROGRAM ARG...`.
///
/// # Errors
///
/// [`LaunchUsage`] for any malformed or missing argument.
pub fn parse(args: &[OsString]) -> Result<LaunchArgs, LaunchUsage> {
    let mut release_fd: Option<RawFd> = None;
    let mut error_fd: Option<RawFd> = None;
    let mut narrow = false;
    let mut index = 0usize;
    let mut argv: Option<Vec<OsString>> = None;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            argv = Some(args[index + 1..].to_vec());
            break;
        }
        let name = arg.to_string_lossy().into_owned();
        match name.as_str() {
            "--release-fd" => {
                release_fd = Some(fd_value(args.get(index + 1), "--release-fd")?);
                index += 2;
            }
            "--error-fd" => {
                error_fd = Some(fd_value(args.get(index + 1), "--error-fd")?);
                index += 2;
            }
            "--narrow" => {
                narrow = true;
                index += 1;
            }
            _ => return Err(LaunchUsage::UnknownOption(name)),
        }
    }

    let argv = argv.ok_or(LaunchUsage::MissingSeparator)?;
    if argv.is_empty() {
        return Err(LaunchUsage::EmptyArgv);
    }
    // Refuse a program name the kernel would silently truncate, before any
    // syscall sees it.
    for part in &argv {
        cstring_from_os(part).map_err(LaunchUsage::Path)?;
    }
    Ok(LaunchArgs {
        release_fd: release_fd.ok_or(LaunchUsage::Missing("--release-fd"))?,
        error_fd: error_fd.ok_or(LaunchUsage::Missing("--error-fd"))?,
        narrow,
        argv,
    })
}

fn fd_value(raw: Option<&OsString>, option: &'static str) -> Result<RawFd, LaunchUsage> {
    let raw = raw.ok_or(LaunchUsage::MissingValue(option))?;
    let text = raw.to_str().ok_or(LaunchUsage::BadFd(option))?;
    let value: RawFd = text.parse().map_err(|_| LaunchUsage::BadFd(option))?;
    if value < 0 {
        return Err(LaunchUsage::BadFd(option));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// The launcher itself
// ---------------------------------------------------------------------------

/// Run the inside launcher. Never returns.
///
/// Everything that allocates happens before the filter is installed. After
/// that point the only calls are `fcntl`, `read`, `close`, `write`, `execvp`
/// and `_exit`.
pub fn launch_main(args: &[OsString]) -> ! {
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("ouro-jail {SUBCOMMAND}: {err}");
            std::process::exit(EXIT_USAGE);
        }
    };

    for (fd, option) in [
        (parsed.release_fd, "--release-fd"),
        (parsed.error_fd, "--error-fd"),
    ] {
        // SAFETY: F_GETFD takes a descriptor number and dereferences nothing.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            eprintln!(
                "ouro-jail {SUBCOMMAND}: {}",
                LaunchUsage::ClosedFd(option, fd)
            );
            std::process::exit(EXIT_USAGE);
        }
    }

    // Build the exec arguments now: after the filter, allocation is forbidden.
    let argv_c: Vec<CString> = parsed
        .argv
        .iter()
        .map(|part| cstring_from_os(part).expect("parse() already refused interior NUL"))
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|part| part.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let program = argv_c[0].clone();
    // Resolved here, before the narrowing filter is installed, because after
    // it nothing may allocate. The supervisor is told which path was resolved
    // so that it can hold the observer's exec snapshot against it.
    let candidates = exec_candidates(&program, std::env::var_os("PATH").as_deref());

    // The target must not inherit the error pipe: EOF with no bytes is how the
    // supervisor learns the exec succeeded.
    // SAFETY: F_SETFD takes scalars and dereferences nothing.
    if unsafe { libc::fcntl(parsed.error_fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        let errno = errno();
        report_and_exit(parsed.error_fd, errno, EXIT_INTERNAL);
    }

    if parsed.narrow {
        // The observer's own filter, so the numbers the launcher narrows to
        // and the numbers the tracer expects to be stopped on are one table.
        // It sets no_new_privs and loads the program without allocating.
        if let Err(errno) = super::tracer::install_narrowing_filter() {
            report_and_exit(parsed.error_fd, errno, EXIT_INTERNAL);
        }
    }
    drop(parsed.argv);

    // ---- no allocation past this line ----

    let mut byte = [0u8; 1];
    let released = loop {
        // SAFETY: the buffer is one live byte and the length matches.
        let n = unsafe {
            libc::read(
                parsed.release_fd,
                byte.as_mut_ptr().cast::<libc::c_void>(),
                1,
            )
        };
        if n == 1 {
            break true;
        }
        if n == 0 {
            break false;
        }
        let errno = errno();
        if errno == libc::EINTR {
            continue;
        }
        report_and_exit(parsed.error_fd, errno, EXIT_INTERNAL);
    };

    if !released {
        // SAFETY: _exit takes a scalar and never returns.
        unsafe { libc::_exit(EXIT_NO_RELEASE) };
    }

    // SAFETY: closing a descriptor this process owns; the target must not see
    // the release pipe.
    unsafe { libc::close(parsed.release_fd) };

    // `execve`, never `execvp`. On `ENOEXEC` the library call re-executes the
    // file through `/bin/sh`, so a file that is neither ELF nor a script with
    // a shebang would run as a shell script nobody asked for, and the receipt
    // would say the named program executed successfully. §6.1 admits no
    // implicit shell, and X04 wants `ENOEXEC` to be its own distinct outcome,
    // so the error reaches the error pipe as itself.
    let mut last_errno = libc::ENOENT;
    for candidate in &candidates {
        // SAFETY: `candidate` and `argv_ptrs` are NUL-terminated C strings and
        // a NULL-terminated pointer array, all live for the call, and
        // `environ` is this process's own. execve only returns on failure.
        unsafe { libc::execve(candidate.as_ptr(), argv_ptrs.as_ptr(), environ()) };
        last_errno = errno();
        // The search continues only where a PATH search is defined to: a
        // component that is not there, or not a directory. Anything else — a
        // file that exists and cannot be executed, a file that is not an
        // executable format — is the answer.
        if !matches!(last_errno, libc::ENOENT | libc::ENOTDIR) {
            break;
        }
    }
    report_and_exit(parsed.error_fd, last_errno, EXIT_EXEC_FAILED);
}

/// The same list as [`exec_candidates`], as raw bytes.
///
/// # Errors
///
/// [`PathError`] when the program name cannot be handed to a syscall.
pub fn exec_candidate_bytes(
    program: &OsStr,
    path: Option<&OsStr>,
) -> Result<Vec<Vec<u8>>, PathError> {
    let program = cstring_from_os(program)?;
    Ok(exec_candidates(&program, path)
        .into_iter()
        .map(|candidate| candidate.into_bytes())
        .collect())
}

/// This process's environment, for `execve`.
fn environ() -> *const *const libc::c_char {
    unsafe extern "C" {
        static environ: *const *const libc::c_char;
    }
    // SAFETY: `environ` is the C runtime's own pointer, valid for the life of
    // the process and not modified by this program after startup.
    unsafe { environ }
}

/// The paths an `execve` should be attempted at, in order.
///
/// Public because the supervisor derives the same list from the same inputs:
/// the pathname the observer reports for the target's exec transition must be
/// one of these, or the transition is not this launcher's exec of this target
/// and does not confirm it.
///
/// A name containing a slash is used as given, exactly as `execvp` defines it.
/// Otherwise the `PATH` this process was handed is searched; an empty element
/// means the current directory, as POSIX says. The search is done here, in
/// code that can be read, rather than in a library call whose failure mode is
/// to invent a shell.
pub fn exec_candidates(program: &CString, path: Option<&OsStr>) -> Vec<CString> {
    if program.as_bytes().contains(&b'/') {
        return vec![program.clone()];
    }
    let mut out = Vec::new();
    let raw = path.map_or_else(Vec::new, |value| value.as_bytes().to_vec());
    for element in raw.split(|byte| *byte == b':') {
        let mut candidate: Vec<u8> = if element.is_empty() {
            b".".to_vec()
        } else {
            element.to_vec()
        };
        if candidate.last() != Some(&b'/') {
            candidate.push(b'/');
        }
        candidate.extend_from_slice(program.as_bytes());
        if let Ok(candidate) = CString::new(candidate) {
            out.push(candidate);
        }
    }
    if out.is_empty() {
        out.push(program.clone());
    }
    out
}

/// Write `errno` as four little-endian bytes to `fd` and exit with `code`.
///
/// Async-signal-safe: `write` and `_exit` only.
fn report_and_exit(fd: RawFd, errno: i32, code: i32) -> ! {
    let bytes = errno.to_le_bytes();
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: the pointer and length address the remaining bytes of a live
        // stack array.
        let n = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(written).cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if n <= 0 {
            if n < 0 && errno_raw() == libc::EINTR {
                continue;
            }
            break;
        }
        written += n as usize;
    }
    // SAFETY: _exit takes a scalar and never returns.
    unsafe { libc::_exit(code) }
}

fn errno() -> i32 {
    errno_raw()
}

fn errno_raw() -> i32 {
    // SAFETY: __errno_location returns a pointer to this thread's errno, valid
    // for the thread's lifetime.
    unsafe { *libc::__errno_location() }
}

/// Decode the four bytes the launcher writes on a failed exec.
#[must_use]
pub fn decode_error_report(bytes: &[u8]) -> Option<i32> {
    let four: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(i32::from_le_bytes(four))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    fn osv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_complete_invocation_parses() {
        let parsed = parse(&osv(&[
            "--release-fd",
            "12",
            "--error-fd",
            "13",
            "--narrow",
            "--",
            "/bin/sh",
            "-c",
            "echo ok",
        ]))
        .unwrap();
        assert_eq!(parsed.release_fd, 12);
        assert_eq!(parsed.error_fd, 13);
        assert!(parsed.narrow);
        assert_eq!(parsed.argv.len(), 3);
        assert_eq!(parsed.argv[0], OsString::from("/bin/sh"));
    }

    #[test]
    fn narrow_is_off_by_default() {
        let parsed = parse(&osv(&[
            "--release-fd",
            "3",
            "--error-fd",
            "4",
            "--",
            "/bin/true",
        ]))
        .unwrap();
        assert!(!parsed.narrow);
    }

    #[test]
    fn everything_after_the_separator_is_argv_even_when_it_looks_like_an_option() {
        let parsed = parse(&osv(&[
            "--release-fd",
            "3",
            "--error-fd",
            "4",
            "--",
            "/bin/echo",
            "--narrow",
            "--release-fd",
        ]))
        .unwrap();
        assert_eq!(parsed.argv, osv(&["/bin/echo", "--narrow", "--release-fd"]));
    }

    #[test]
    fn missing_pieces_are_usage_errors() {
        assert_eq!(
            parse(&osv(&["--release-fd", "3", "--", "/bin/true"])),
            Err(LaunchUsage::Missing("--error-fd"))
        );
        assert_eq!(
            parse(&osv(&["--release-fd", "3", "--error-fd", "4"])),
            Err(LaunchUsage::MissingSeparator)
        );
        assert_eq!(
            parse(&osv(&["--release-fd", "3", "--error-fd", "4", "--"])),
            Err(LaunchUsage::EmptyArgv)
        );
        assert_eq!(
            parse(&osv(&["--release-fd", "-1", "--error-fd", "4", "--", "x"])),
            Err(LaunchUsage::BadFd("--release-fd"))
        );
        assert_eq!(
            parse(&osv(&["--nope", "--", "x"])),
            Err(LaunchUsage::UnknownOption("--nope".to_owned()))
        );
    }

    #[test]
    fn a_program_name_with_an_interior_nul_is_refused_before_any_syscall() {
        let mut args = osv(&["--release-fd", "3", "--error-fd", "4", "--"]);
        args.push(OsStr::from_bytes(b"/bin/sh\0extra").to_owned());
        assert_eq!(
            parse(&args),
            Err(LaunchUsage::Path(PathError::InteriorNul { offset: 7 }))
        );
    }

    #[test]
    fn a_non_utf8_argument_survives_parsing() {
        let mut args = osv(&["--release-fd", "3", "--error-fd", "4", "--", "/bin/echo"]);
        args.push(OsStr::from_bytes(b"\xff\xfe").to_owned());
        let parsed = parse(&args).unwrap();
        assert_eq!(parsed.argv[1].as_bytes(), b"\xff\xfe");
    }

    #[test]
    fn error_reports_round_trip() {
        assert_eq!(
            decode_error_report(&libc::ENOENT.to_le_bytes()),
            Some(libc::ENOENT)
        );
        assert_eq!(decode_error_report(&[1, 2]), None);
        assert_eq!(decode_error_report(&[]), None);
    }
}
