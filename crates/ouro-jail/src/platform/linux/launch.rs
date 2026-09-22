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

use std::ffi::{CString, OsString};
use std::fmt;
use std::os::fd::RawFd;

use super::bpf::{BpfError, Program};
use super::seccomp;
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
// The narrowing filter placeholder
// ---------------------------------------------------------------------------

/// x86_64 numbers of the `linux-closed-v1` closed set (jail-v1 §11.2).
pub const CLOSED_SET_NRS: &[(&str, u32)] = &[
    ("execve", 59),
    ("execveat", 322),
    ("open", 2),
    ("openat", 257),
    ("openat2", 437),
    ("creat", 85),
    ("rename", 82),
    ("renameat", 264),
    ("renameat2", 316),
    ("unlink", 87),
    ("unlinkat", 263),
    ("rmdir", 84),
    ("mkdir", 83),
    ("mkdirat", 258),
    ("link", 86),
    ("linkat", 265),
    ("symlink", 88),
    ("symlinkat", 266),
    ("connect", 42),
];

/// The filter that sends the closed set to the tracer and allows everything
/// else.
///
/// Replaced by `tracer::narrowing_filter` at integration; the observer agent
/// owns the real one. This copy exists so that phase 1 can demonstrate the
/// property the supervisor depends on: with the filter installed and no
/// tracer attached, a closed-set syscall fails with `ENOSYS` rather than
/// succeeding unobserved.
///
/// # Errors
///
/// [`BpfError`] only if the closed set grows past what classic BPF can encode.
pub fn narrowing_filter() -> Result<Program, BpfError> {
    use super::bpf::Asm;
    let mut asm = Asm::new();
    asm.ld_w_abs(seccomp::SD_ARCH)
        .jeq(seccomp::AUDIT_ARCH_X86_64, None, Some("allow"));
    asm.ld_w_abs(seccomp::SD_NR)
        // x32 passes through to the baseline, which denies it. The narrowing
        // filter's job is observation, not enforcement.
        .jset(seccomp::X32_SYSCALL_BIT, Some("allow"), None);
    for (_, nr) in CLOSED_SET_NRS {
        asm.jeq(*nr, Some("trace"), None);
    }
    asm.label("allow").ret(seccomp::SECCOMP_RET_ALLOW);
    asm.label("trace").ret(seccomp::SECCOMP_RET_TRACE);
    asm.assemble()
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

    let filter = if parsed.narrow {
        match narrowing_filter() {
            Ok(program) => Some(program),
            Err(err) => {
                eprintln!("ouro-jail {SUBCOMMAND}: narrowing filter: {err}");
                std::process::exit(EXIT_INTERNAL);
            }
        }
    } else {
        None
    };

    // The target must not inherit the error pipe: EOF with no bytes is how the
    // supervisor learns the exec succeeded.
    // SAFETY: F_SETFD takes scalars and dereferences nothing.
    if unsafe { libc::fcntl(parsed.error_fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        let errno = errno();
        report_and_exit(parsed.error_fd, errno, EXIT_INTERNAL);
    }

    if let Some(filter) = filter.as_ref() {
        if let Err(err) = seccomp::set_no_new_privs() {
            report_and_exit(
                parsed.error_fd,
                err.raw_os_error().unwrap_or(libc::EINVAL),
                EXIT_INTERNAL,
            );
        }
        if let Err(err) = seccomp::install(filter) {
            report_and_exit(
                parsed.error_fd,
                err.raw_os_error().unwrap_or(libc::EINVAL),
                EXIT_INTERNAL,
            );
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

    // SAFETY: `program` and `argv_ptrs` are NUL-terminated C strings and a
    // NULL-terminated pointer array, both live for the call. execvp only
    // returns on failure.
    unsafe { libc::execvp(program.as_ptr(), argv_ptrs.as_ptr()) };
    let errno = errno();
    report_and_exit(parsed.error_fd, errno, EXIT_EXEC_FAILED);
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
    fn the_narrowing_filter_traces_exactly_the_closed_set() {
        let program = narrowing_filter().unwrap();
        let text = program.disassemble().join("\n");
        assert_eq!(CLOSED_SET_NRS.len(), 19);
        for (name, nr) in CLOSED_SET_NRS {
            assert!(
                text.contains(&format!("#0x{nr:08x}")),
                "{name} ({nr}) missing from the narrowing filter"
            );
        }
        let insns = program.insns();
        let last = insns.len() - 1;
        assert_eq!(insns[last].k, seccomp::SECCOMP_RET_TRACE);
        assert_eq!(insns[last - 1].k, seccomp::SECCOMP_RET_ALLOW);
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
