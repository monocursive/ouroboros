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
// J3-agent begin: the agent launcher's own setup failures
/// The unix-peer mediation (filter with its own listener, sock_diag socket)
/// could not be set up; the errno is on the error pipe. The target did not
/// run.
pub const EXIT_MEDIATION_FAILED: i32 = 120;
/// The in-namespace bridge could not be started; the errno is on the error
/// pipe. The target did not run.
pub const EXIT_BRIDGE_FAILED: i32 = 121;
// J3-agent end

/// Parsed `__launch` arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchArgs {
    /// Descriptor the supervisor writes one byte to in order to release.
    pub release_fd: RawFd,
    /// Descriptor the launcher writes a failed exec's errno to.
    pub error_fd: RawFd,
    /// Whether to install the narrowing filter before releasing.
    pub narrow: bool,
    // J3-agent begin: mediation and bridge (jail-v1 §10)
    /// Install the unix-peer mediation filter with its own listener and open
    /// a `NETLINK_SOCK_DIAG` socket, placing them at these two descriptor
    /// numbers for the supervisor to take before release.
    pub mediate: Option<(RawFd, RawFd)>,
    /// Start the loopback bridge before blocking, and place the read end of
    /// its report pipe (one byte per client it turned away at capacity) at
    /// this descriptor number for the supervisor to take before release.
    pub bridge: Option<RawFd>,
    /// The signal mask the supervisor inherited (bit `n - 1` for signal
    /// `n`), which the target gets instead of what bubblewrap left: it
    /// blocks SIGCHLD for itself and unblocks it in its child, so an
    /// inherited blocked SIGCHLD would otherwise be lost. `None` leaves the
    /// mask as inherited (`none`, where nothing in between changes it).
    pub sigmask: Option<u64>,
    // J3-agent end
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

/// Parse `--release-fd N --error-fd M [--narrow] [--mediate L,S] [--bridge R]
/// [--sigmask HEX] -- PROGRAM ARG...`.
///
/// # Errors
///
/// [`LaunchUsage`] for any malformed or missing argument.
pub fn parse(args: &[OsString]) -> Result<LaunchArgs, LaunchUsage> {
    let mut release_fd: Option<RawFd> = None;
    let mut error_fd: Option<RawFd> = None;
    let mut narrow = false;
    let mut mediate: Option<(RawFd, RawFd)> = None;
    let mut bridge: Option<RawFd> = None;
    let mut sigmask: Option<u64> = None;
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
            // J3-agent begin
            "--mediate" => {
                mediate = Some(fd_pair(args.get(index + 1), "--mediate")?);
                index += 2;
            }
            "--bridge" => {
                let fd = fd_value(args.get(index + 1), "--bridge")?;
                if fd < 3 {
                    return Err(LaunchUsage::BadFd("--bridge"));
                }
                bridge = Some(fd);
                index += 2;
            }
            "--sigmask" => {
                let raw = args
                    .get(index + 1)
                    .ok_or(LaunchUsage::MissingValue("--sigmask"))?;
                let text = raw.to_str().ok_or(LaunchUsage::BadFd("--sigmask"))?;
                sigmask = Some(
                    u64::from_str_radix(text, 16).map_err(|_| LaunchUsage::BadFd("--sigmask"))?,
                );
                index += 2;
            }
            // J3-agent end
            _ => return Err(LaunchUsage::UnknownOption(name)),
        }
    }

    // J3-agent begin: the three placed descriptors are three numbers
    if let (Some(report), Some((listener, sockdiag))) = (bridge, mediate)
        && (report == listener || report == sockdiag)
    {
        return Err(LaunchUsage::BadFd("--bridge"));
    }
    // J3-agent end
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
        mediate,
        bridge,
        sigmask,
        argv,
    })
}

// J3-agent begin: `--mediate L,S`
fn fd_pair(raw: Option<&OsString>, option: &'static str) -> Result<(RawFd, RawFd), LaunchUsage> {
    let raw = raw.ok_or(LaunchUsage::MissingValue(option))?;
    let text = raw.to_str().ok_or(LaunchUsage::BadFd(option))?;
    let (left, right) = text.split_once(',').ok_or(LaunchUsage::BadFd(option))?;
    let parse = |part: &str| -> Result<RawFd, LaunchUsage> {
        let value: RawFd = part.parse().map_err(|_| LaunchUsage::BadFd(option))?;
        // Below 3 would replace stdio; the two must differ.
        if value < 3 {
            return Err(LaunchUsage::BadFd(option));
        }
        Ok(value)
    };
    let pair = (parse(left)?, parse(right)?);
    if pair.0 == pair.1 {
        return Err(LaunchUsage::BadFd(option));
    }
    Ok(pair)
}
// J3-agent end

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

    // J3-agent begin: mediation, then the bridge, both before the narrowing
    // filter. The bridge must exist before it: an untraced process that
    // meets the narrowing filter's SECCOMP_RET_TRACE gets ENOSYS, and the
    // bridge is never traced (it is a helper, not a descendant of the
    // target). It must come after the mediation filter, so its connect to
    // the proxy is mediated like the target's.
    if let Some((listener_fd, sockdiag_fd)) = parsed.mediate
        && let Err(errno) = mediate(listener_fd, sockdiag_fd)
    {
        report_and_exit(parsed.error_fd, errno, EXIT_MEDIATION_FAILED);
    }
    if let Some(report_fd) = parsed.bridge
        && let Err(errno) = spawn_bridge(report_fd)
    {
        report_and_exit(parsed.error_fd, errno, EXIT_BRIDGE_FAILED);
    }
    // J3-agent end

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
    // J3-agent begin: undo what the jail itself changed in the signal state
    // the target inherits. The Rust runtime set SIGPIPE to ignored in this
    // process (and a raw execve keeps an ignored disposition), and
    // bubblewrap unblocked SIGCHLD for its child; the target gets SIGPIPE's
    // default and, when given, the supervisor's own inherited mask. Every
    // other disposition is left exactly as inherited, so an operator's
    // `nohup` still reaches the target. Async-signal-safe calls only.
    // SAFETY: `action` and `set` are plain stack data; sigaction,
    // sigemptyset, sigaddset and sigprocmask read or fill them only.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&raw mut action.sa_mask);
        if libc::sigaction(libc::SIGPIPE, &raw const action, std::ptr::null_mut()) != 0 {
            report_and_exit(parsed.error_fd, errno(), EXIT_INTERNAL);
        }
        if let Some(mask) = parsed.sigmask {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            for signal in 1..=64 {
                if mask & (1u64 << (signal - 1)) != 0 {
                    libc::sigaddset(&raw mut set, signal);
                }
            }
            if libc::sigprocmask(libc::SIG_SETMASK, &raw const set, std::ptr::null_mut()) != 0 {
                report_and_exit(parsed.error_fd, errno(), EXIT_INTERNAL);
            }
        }
    }
    // J3-agent end

    // J3-agent begin: the supervisor took these objects before release; the
    // target never holds the listener, the sock_diag socket or the bridge's
    // report pipe (X06). This close is the only thing that keeps them from
    // it (see `mediate` and `spawn_bridge`).
    if let Some((listener_fd, sockdiag_fd)) = parsed.mediate {
        // SAFETY: closing descriptors this process placed itself.
        unsafe {
            libc::close(listener_fd);
            libc::close(sockdiag_fd);
        }
    }
    if let Some(report_fd) = parsed.bridge {
        // SAFETY: closing a descriptor this process placed itself.
        unsafe { libc::close(report_fd) };
    }
    // J3-agent end

    // `execve`, never `execvp`. On `ENOEXEC` the library call re-executes the
    // file through `/bin/sh`, so a file that is neither ELF nor a script with
    // a shebang would run as a shell script nobody asked for, and the receipt
    // would say the named program executed successfully. §6.1 admits no
    // implicit shell, and X04 wants `ENOEXEC` to be its own distinct outcome,
    // so the error reaches the error pipe as itself.
    let mut last_errno = libc::ENOENT;
    // J5-B1 begin: X04 — ENOENT for a file that exists
    let mut interpreter_missing = false;
    // J5-B1 end
    for candidate in &candidates {
        // SAFETY: `candidate` and `argv_ptrs` are NUL-terminated C strings and
        // a NULL-terminated pointer array, all live for the call, and
        // `environ` is this process's own. execve only returns on failure.
        unsafe { libc::execve(candidate.as_ptr(), argv_ptrs.as_ptr(), environ()) };
        last_errno = errno();
        // J5-B1 begin: X04 — the kernel answers ENOENT both for a program
        // that is not there and for one whose `#!` interpreter or ELF loader
        // is not there. A candidate that exists tells the two apart; the
        // errno stays the kernel's own.
        if last_errno == libc::ENOENT && exists(candidate) {
            interpreter_missing = true;
        }
        // J5-B1 end
        // The search continues only where a PATH search is defined to: a
        // component that is not there, or not a directory. Anything else — a
        // file that exists and cannot be executed, a file that is not an
        // executable format — is the answer.
        if !matches!(last_errno, libc::ENOENT | libc::ENOTDIR) {
            break;
        }
    }
    // J5-B1 begin: X04
    let detail = if last_errno == libc::ENOENT && interpreter_missing {
        DETAIL_INTERPRETER_MISSING
    } else {
        0
    };
    report_exec_failure_and_exit(parsed.error_fd, last_errno, detail, EXIT_EXEC_FAILED);
    // J5-B1 end
}

// J5-B1 begin: X04 — what an exec failure's errno does not say
/// The launcher's detail code for an `ENOENT` from a file that exists: what
/// is missing is the interpreter its `#!` line names, or its ELF loader.
pub const DETAIL_INTERPRETER_MISSING: u32 = 1;

/// Whether `path` names an existing object. Async-signal-safe: one
/// `faccessat` on a string built before the fork-free no-allocation point.
fn exists(path: &CString) -> bool {
    // SAFETY: `path` is a live NUL-terminated string; F_OK checks existence
    // only and dereferences nothing else.
    unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::F_OK, 0) == 0 }
}

/// A failed target exec as the launcher reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecFailure {
    /// The kernel's errno for the last exec attempted.
    pub errno: i32,
    /// The file named exists, and `errno` is `ENOENT`: its interpreter or
    /// loader is what was not found.
    pub interpreter_missing: bool,
}

impl ExecFailure {
    /// The errno name, which is what a receipt's `outcome.cause` holds.
    #[must_use]
    pub fn errno_name(&self) -> &'static str {
        super::sys::errno_name(self.errno)
    }

    /// What the errno alone does not say; `None` when it says everything
    /// the launcher knows.
    #[must_use]
    pub fn detail(&self) -> Option<crate::platform::ExecFailureDetail> {
        self.interpreter_missing
            .then_some(crate::platform::ExecFailureDetail::InterpreterMissing)
    }
}

/// Decode an exec failure report: the errno, then an optional detail code.
/// A report of any other length after the errno carries no detail.
#[must_use]
pub fn decode_exec_failure(bytes: &[u8]) -> Option<ExecFailure> {
    let errno = decode_error_report(bytes)?;
    let detail = bytes
        .get(4..8)
        .and_then(|four| <[u8; 4]>::try_from(four).ok())
        .map(u32::from_le_bytes);
    Some(ExecFailure {
        errno,
        interpreter_missing: errno == libc::ENOENT
            && bytes.len() == 8
            && detail == Some(DETAIL_INTERPRETER_MISSING),
    })
}

/// The errno name and the detail of a failed exec's report, as a platform
/// hands them to the supervisor: `("unknown", None)` for a report that does
/// not decode.
#[must_use]
pub fn exec_failure_parts(bytes: &[u8]) -> (String, Option<crate::platform::ExecFailureDetail>) {
    decode_exec_failure(bytes).map_or_else(
        || ("unknown".to_owned(), None),
        |failure| (failure.errno_name().to_owned(), failure.detail()),
    )
}

/// Write `errno`, and `detail` when it is not zero, as little-endian words in
/// one `write`, and exit with `code`. Async-signal-safe: `write` and `_exit`.
fn report_exec_failure_and_exit(fd: RawFd, errno: i32, detail: u32, code: i32) -> ! {
    if detail == 0 {
        report_and_exit(fd, errno, code);
    }
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&errno.to_le_bytes());
    bytes[4..].copy_from_slice(&detail.to_le_bytes());
    write_fully(fd, &bytes);
    // SAFETY: _exit takes a scalar and never returns.
    unsafe { libc::_exit(code) }
}
// J5-B1 end

// J3-agent begin: the signal mask the jail hands the target
/// The calling thread's blocked signals as a bitmask (bit `n - 1` for signal
/// `n`, `1..=64`). The supervisor calls it on its main thread, which never
/// changes its mask, so it is the mask the supervisor inherited.
#[must_use]
pub fn blocked_mask() -> u64 {
    // SAFETY: `set` is plain stack data that pthread_sigmask fills; a null
    // new-mask pointer only reads the current one.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &raw mut set) != 0 {
            return 0;
        }
        (1..=64).fold(0u64, |mask, signal| {
            if libc::sigismember(&raw const set, signal) == 1 {
                mask | (1u64 << (signal - 1))
            } else {
                mask
            }
        })
    }
}
// J3-agent end

// J3-agent begin: the launcher's agent setup
/// Installs the unix-peer mediation filter with its own listener and opens a
/// `NETLINK_SOCK_DIAG` socket in this network namespace, then places them at
/// `listener_fd` and `sockdiag_fd` for the supervisor to take with
/// `pidfd_getfd` while this process is blocked. They are deliberately not
/// close-on-exec: the explicit close after release is the one thing that
/// keeps them from the target (X06 goes red without it), rather than two
/// overlapping mechanisms neither of which a test could fail alone. The
/// bridge's own `close_range` keeps them from the bridge.
///
/// Refuses (`EEXIST`) if either number is already open: `dup3` would
/// silently close whatever held it.
fn mediate(listener_fd: RawFd, sockdiag_fd: RawFd) -> Result<(), i32> {
    use std::os::fd::AsRawFd as _;
    for target in [listener_fd, sockdiag_fd] {
        // SAFETY: F_GETFD takes a descriptor number and dereferences nothing.
        if unsafe { libc::fcntl(target, libc::F_GETFD) } >= 0 {
            return Err(libc::EEXIST);
        }
    }
    let setup = super::unixpeer::launcher_setup()
        .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
    let (listener, sockdiag) = setup.into_fds();
    for (source, target) in [
        (listener.as_raw_fd(), listener_fd),
        (sockdiag.as_raw_fd(), sockdiag_fd),
    ] {
        // SAFETY: both descriptors are live; dup2 places a copy at a number
        // checked to be free above.
        if unsafe { libc::dup2(source, target) } < 0 {
            return Err(errno());
        }
    }
    // The originals close here; the placed copies stay open.
    drop((listener, sockdiag));
    Ok(())
}

/// Starts `/run/ouro/jail __bridge` with a double fork, so the bridge is
/// reparented to the namespace init and is never a child of the target: a
/// target that waits for every child it has must not find one it did not
/// start, and Yama's descendant rule keeps the target from attaching to it.
///
/// The bridge gets `/dev/null` as stdin and stdout, the write end of its
/// report pipe as stderr, no other descriptor, an empty environment and a
/// session of its own, so no terminal or process-group signal aimed at the
/// target reaches it. Between each fork and `execve` only async-signal-safe
/// calls run.
///
/// The pipe's read end is placed at `report_fd` for the supervisor to take
/// while this process is blocked; like the mediation descriptors it is not
/// close-on-exec, and the explicit close after release keeps it from the
/// target. Refuses (`EEXIST`) if `report_fd` is already open.
fn spawn_bridge(report_fd: RawFd) -> Result<(), i32> {
    let path = CString::new(super::bwrap::JAIL_INSIDE_PATH).map_err(|_| libc::EINVAL)?;
    let subcommand = CString::new(super::bridge::SUBCOMMAND).map_err(|_| libc::EINVAL)?;
    let argv: [*const libc::c_char; 3] = [path.as_ptr(), subcommand.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let devnull = c"/dev/null";
    // SAFETY: F_GETFD takes a descriptor number and dereferences nothing.
    if unsafe { libc::fcntl(report_fd, libc::F_GETFD) } >= 0 {
        return Err(libc::EEXIST);
    }
    let mut report = [-1 as RawFd; 2];
    // SAFETY: pipe2 fills the two-element array it is given. Nonblocking on
    // both ends: a bridge whose reader is slow drops a report byte rather
    // than stall its relays, and the supervisor drains without waiting.
    if unsafe { libc::pipe2(report.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(errno());
    }
    let close_report = || {
        // SAFETY: closing the two descriptors pipe2 just created here.
        unsafe {
            libc::close(report[0]);
            libc::close(report[1]);
        }
    };
    // SAFETY: this process is single-threaded here (nothing has spawned a
    // thread), and both children call only async-signal-safe functions.
    let first = unsafe { libc::fork() };
    if first < 0 {
        let e = errno();
        close_report();
        return Err(e);
    }
    if first == 0 {
        // SAFETY: async-signal-safe calls only, then `_exit` or `execve`.
        unsafe {
            let second = libc::fork();
            if second != 0 {
                libc::_exit(i32::from(second < 0));
            }
            libc::setsid();
            let null = libc::open(devnull.as_ptr(), libc::O_RDWR);
            if null < 0 {
                libc::_exit(EXIT_BRIDGE_FAILED);
            }
            for (source, stdio) in [(null, 0), (null, 1), (report[1], 2)] {
                if libc::dup2(source, stdio) < 0 {
                    libc::_exit(EXIT_BRIDGE_FAILED);
                }
            }
            // Nothing above stdio: not the release or error pipe, not the
            // mediation listener, not the sock_diag socket, not the report
            // pipe's read end.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) < 0 {
                libc::_exit(EXIT_BRIDGE_FAILED);
            }
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(EXIT_BRIDGE_FAILED);
        }
    }
    let mut status = 0;
    loop {
        // SAFETY: `first` is this process's own child; `status` is writable.
        let rc = unsafe { libc::waitpid(first, &raw mut status, 0) };
        if rc == first {
            break;
        }
        let e = errno();
        if e != libc::EINTR {
            close_report();
            return Err(e);
        }
    }
    if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
        close_report();
        return Err(libc::ECHILD);
    }
    // The write end lives on only in the bridge; the read end moves to its
    // agreed number (dup2 leaves the copy without close-on-exec).
    // SAFETY: both descriptors are this process's own; dup2 places a copy
    // at a number checked to be free above.
    let placed = unsafe { libc::dup2(report[0], report_fd) };
    let e = errno();
    close_report();
    if placed < 0 { Err(e) } else { Ok(()) }
}
// J3-agent end

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
    write_fully(fd, &errno.to_le_bytes());
    // SAFETY: _exit takes a scalar and never returns.
    unsafe { libc::_exit(code) }
}

/// Write `bytes` to `fd`, retrying a short or interrupted write, and give up
/// silently on any other failure. Async-signal-safe: `write` only.
fn write_fully(fd: RawFd, bytes: &[u8]) {
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

    // J3-agent begin
    #[test]
    fn the_agent_options_parse_and_bad_pairs_refuse() {
        let parsed = parse(&osv(&[
            "--release-fd",
            "12",
            "--error-fd",
            "13",
            "--mediate",
            "18,19",
            "--bridge",
            "20",
            "--",
            "/bin/true",
        ]))
        .unwrap();
        assert_eq!(parsed.mediate, Some((18, 19)));
        assert_eq!(parsed.bridge, Some(20));
        assert_eq!(parsed.sigmask, None);
        let masked = parse(&osv(&[
            "--release-fd",
            "3",
            "--error-fd",
            "4",
            "--sigmask",
            "201",
            "--",
            "x",
        ]))
        .unwrap();
        assert_eq!(masked.sigmask, Some(0x201), "SIGHUP and SIGUSR1");
        assert_eq!(
            parse(&osv(&[
                "--release-fd",
                "3",
                "--error-fd",
                "4",
                "--sigmask",
                "zz",
                "--",
                "x"
            ])),
            Err(LaunchUsage::BadFd("--sigmask"))
        );
        let plain = parse(&osv(&["--release-fd", "3", "--error-fd", "4", "--", "x"])).unwrap();
        assert_eq!(plain.mediate, None);
        assert_eq!(plain.bridge, None);
        for bad in ["2", "x", "19"] {
            assert_eq!(
                parse(&osv(&[
                    "--release-fd",
                    "3",
                    "--error-fd",
                    "4",
                    "--mediate",
                    "18,19",
                    "--bridge",
                    bad,
                    "--",
                    "x"
                ])),
                Err(LaunchUsage::BadFd("--bridge")),
                "{bad}"
            );
        }
        for bad in ["18", "18,18", "2,19", "a,b", "18,19,20", "-1,4"] {
            assert_eq!(
                parse(&osv(&[
                    "--release-fd",
                    "3",
                    "--error-fd",
                    "4",
                    "--mediate",
                    bad,
                    "--",
                    "x"
                ])),
                Err(LaunchUsage::BadFd("--mediate")),
                "{bad}"
            );
        }
    }
    // J3-agent end

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

    // J5-B1 begin: X04
    #[test]
    fn an_exec_failure_report_carries_the_interpreter_detail_only_for_enoent() {
        let report = |errno: i32, detail: Option<u32>| {
            let mut bytes = errno.to_le_bytes().to_vec();
            if let Some(detail) = detail {
                bytes.extend_from_slice(&detail.to_le_bytes());
            }
            decode_exec_failure(&bytes)
        };
        let plain = report(libc::ENOENT, None).unwrap();
        assert_eq!(plain.errno_name(), "ENOENT");
        assert!(!plain.interpreter_missing);
        assert_eq!(plain.detail(), None);

        let interpreter = report(libc::ENOENT, Some(DETAIL_INTERPRETER_MISSING)).unwrap();
        assert_eq!(
            interpreter.errno_name(),
            "ENOENT",
            "the errno stays the kernel's"
        );
        assert!(interpreter.interpreter_missing);
        assert_eq!(
            interpreter.detail(),
            Some(crate::platform::ExecFailureDetail::InterpreterMissing)
        );

        // The detail means nothing beside another errno, an unknown code or
        // a report of the wrong length.
        assert!(
            !report(libc::EACCES, Some(DETAIL_INTERPRETER_MISSING))
                .unwrap()
                .interpreter_missing
        );
        assert!(!report(libc::ENOENT, Some(7)).unwrap().interpreter_missing);
        let mut long = libc::ENOENT.to_le_bytes().to_vec();
        long.extend_from_slice(&DETAIL_INTERPRETER_MISSING.to_le_bytes());
        long.push(0);
        assert!(!decode_exec_failure(&long).unwrap().interpreter_missing);
        assert_eq!(decode_exec_failure(&[1, 2]), None);
    }

    #[test]
    fn an_existing_path_is_told_apart_from_a_missing_one() {
        let dir = std::env::temp_dir();
        let present = CString::new(dir.as_os_str().as_bytes()).unwrap();
        assert!(exists(&present));
        let absent = CString::new(
            dir.join(format!("ouro-launch-absent-{}", std::process::id()))
                .as_os_str()
                .as_bytes(),
        )
        .unwrap();
        assert!(!exists(&absent));
    }
    // J5-B1 end
}
