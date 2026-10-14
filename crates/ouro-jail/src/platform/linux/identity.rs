//! Process identity: which process a pid is, and whether it is still that one.
//!
//! jail-v1 §9.3: "never signal a PID recovered from a file without
//! revalidating its identity". A pid alone is a number the kernel reuses. The
//! triple recorded here — pid, the boot id, and the process's birth time in
//! clock ticks — names one process on one boot, and [`ProcessIdentity::is_live`]
//! re-reads it rather than trusting it.
//!
//! The `/proc` reads that the observer also needs — `children`, `descendants`,
//! `cmdline`, `nspid` — live in [`tracer::proc`](super::tracer) and are used
//! from there, so there is one implementation of each and not two that can
//! disagree.

use std::fs;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

/// Path of the kernel's boot id.
pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// The current boot's identifier.
///
/// # Errors
///
/// Any failure reading `/proc/sys/kernel/random/boot_id`.
pub fn boot_id() -> io::Result<String> {
    Ok(fs::read_to_string(BOOT_ID_PATH)?.trim().to_owned())
}

/// Field 22 of `/proc/<pid>/stat`: the process's start time, in clock ticks
/// since boot.
///
/// The comm field (field 2) is in parentheses and may itself contain spaces
/// and parentheses, so parsing starts after the *last* `)`.
///
/// # Errors
///
/// `ENOENT` when the process is gone, or [`io::ErrorKind::InvalidData`] when
/// the line does not have the shape `/proc/<pid>/stat` is documented to have.
pub fn start_time_ticks(pid: libc::pid_t) -> io::Result<u64> {
    let raw = fs::read_to_string(stat_path(pid))?;
    parse_start_time_ticks(&raw)
}

/// `PF_EXITING` in the `flags` field of `/proc/<pid>/stat`: set at the very
/// start of the task's exit, before a namespace init kills the rest of its
/// namespace, and never cleared.
pub const PF_EXITING: u64 = 0x4;

/// Whether `pid` has begun to exit (field 9, `flags`, holds
/// [`PF_EXITING`]).
///
/// # Errors
/// The read or parse error; a pid that is gone reads as an error.
pub fn exiting(pid: libc::pid_t) -> io::Result<bool> {
    let raw = fs::read_to_string(stat_path(pid))?;
    Ok(parse_flags(&raw)? & PF_EXITING != 0)
}

/// Parse field 9 (`flags`) out of the contents of a `/proc/<pid>/stat` file.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] when the field is missing or not a number.
pub fn parse_flags(raw: &str) -> io::Result<u64> {
    let close = raw
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat has no comm field"))?;
    // After ")" the next field is field 3 (state), so field 9 is index 6.
    let field = raw[close + 1..]
        .split_ascii_whitespace()
        .nth(6)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "stat has fewer than 9 fields")
        })?;
    field
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("flags: {e}")))
}

// A dead-but-unreaped owner is not alive (`gc`, jail-v1 §14.2)
/// Field 3 (`state`) of a `/proc/<pid>/stat` line: `R`, `S`, `D`, `Z` (a
/// zombie: exited, not yet reaped), `X` (dead) and so on.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] when the comm field or the state is missing.
pub fn parse_state(raw: &str) -> io::Result<char> {
    let close = raw
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat has no comm field"))?;
    raw[close + 1..]
        .split_ascii_whitespace()
        .next()
        .and_then(|field| field.chars().next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat has no state field"))
}

// P1 (c), a zombie leader is not a dead thread group
/// The thread ids of the thread group led by `pid` other than `pid` itself,
/// from `/proc/<pid>/task`: a leader that has exited is a zombie (`Z`) for
/// as long as any of these lives, and each of them may still be inside a
/// system call (a D-state `fsync` or `rename`) that completes.
///
/// # Errors
/// `ENOENT` when the thread group is gone; any other listing failure.
pub fn other_threads(pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        names.push(entry?.file_name());
    }
    Ok(threads_besides(pid, &names))
}

/// The numeric names in `names` other than `pid` (a `/proc/<pid>/task`
/// listing).
#[must_use]
pub fn threads_besides(pid: libc::pid_t, names: &[std::ffi::OsString]) -> Vec<libc::pid_t> {
    names
        .iter()
        .filter_map(|name| name.to_str()?.parse::<libc::pid_t>().ok())
        .filter(|tid| *tid != pid)
        .collect()
}

fn stat_path(pid: libc::pid_t) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/stat"))
}

/// Parse field 22 out of the contents of a `/proc/<pid>/stat` file.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] when the closing parenthesis or the field is
/// missing, or the field is not a number.
pub fn parse_start_time_ticks(raw: &str) -> io::Result<u64> {
    let close = raw
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat has no comm field"))?;
    // After ")" the next field is field 3 (state), so field 22 is index 19.
    let field = raw[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "stat has fewer than 22 fields")
        })?;
    field
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("starttime: {e}")))
}

/// A process, named in a way that survives pid reuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// The process id.
    pub pid: libc::pid_t,
    /// The boot this pid belongs to.
    pub boot_id: String,
    /// The birth time from `/proc/<pid>/stat` field 22.
    pub start_time_ticks: u64,
}

impl ProcessIdentity {
    /// Record the identity of a process that exists now.
    ///
    /// # Errors
    ///
    /// `ENOENT` when the pid does not exist, or a failure reading the boot id.
    pub fn capture(pid: libc::pid_t) -> io::Result<Self> {
        Ok(Self {
            pid,
            boot_id: boot_id()?,
            start_time_ticks: start_time_ticks(pid)?,
        })
    }

    /// Record this process's own identity.
    ///
    /// # Errors
    ///
    /// As [`ProcessIdentity::capture`].
    pub fn own() -> io::Result<Self> {
        // SAFETY: getpid takes no arguments and cannot fail.
        Self::capture(unsafe { libc::getpid() })
    }

    /// Whether the pid still names the process that was recorded.
    ///
    /// Returns false when the pid is gone, when the boot changed, and — the
    /// case a bare pid check misses — when the pid exists but was born at a
    /// different moment, meaning the kernel has reused it.
    #[must_use]
    pub fn is_live(&self) -> bool {
        let Ok(current_boot) = boot_id() else {
            return false;
        };
        if current_boot != self.boot_id {
            return false;
        }
        match start_time_ticks(self.pid) {
            Ok(ticks) => ticks == self.start_time_ticks,
            Err(_) => false,
        }
    }
}

/// Open a pidfd for `pid` (`pidfd_open`, syscall 434).
///
/// A pidfd, unlike a pid, cannot come to refer to a different process.
///
/// # Errors
///
/// `ESRCH` when the process does not exist, `EINVAL` for a bad pid.
pub fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes two scalars and dereferences nothing; flags 0
    // is the documented default (a blocking pidfd).
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(rc).map_err(|_| io::Error::other("pidfd_open returned a huge fd"))?;
    // SAFETY: `fd` was just created by pidfd_open and is owned by this
    // process; wrapping it transfers that ownership exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `PIDFD_THREAD` (Linux 6.9): a pidfd for one thread rather than its thread
/// group. The kernel defines it as `O_EXCL`.
pub const PIDFD_THREAD: libc::c_int = libc::O_EXCL;

/// Open a pidfd for the thread `tid` itself (`pidfd_open` with
/// [`PIDFD_THREAD`]), so that descriptor operations through it use that
/// thread's own descriptor table.
///
/// # Errors
///
/// `EINVAL` on a kernel older than 6.9, which rejects the flag; `ESRCH` when
/// the thread does not exist.
pub fn pidfd_open_thread(tid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes two scalars and dereferences nothing;
    // PIDFD_THREAD is a documented flag (a kernel that lacks it says EINVAL).
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, PIDFD_THREAD) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(rc).map_err(|_| io::Error::other("pidfd_open returned a huge fd"))?;
    // SAFETY: `fd` was just created by pidfd_open and is owned by this
    // process; wrapping it transfers that ownership exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether threads `a` and `b` share one descriptor table (`kcmp` with
/// `KCMP_FILES`). `false` covers "different tables" and "cannot tell".
#[must_use]
pub fn same_descriptor_table(a: libc::pid_t, b: libc::pid_t) -> bool {
    const KCMP_FILES: libc::c_long = 2;
    // SAFETY: kcmp takes five scalars and dereferences nothing for
    // KCMP_FILES; the last two arguments are ignored for that type.
    let rc = unsafe { libc::syscall(libc::SYS_kcmp, a, b, KCMP_FILES, 0, 0) };
    rc == 0
}

/// Send a signal through a pidfd (`pidfd_send_signal`, syscall 424).
///
/// # Errors
///
/// `ESRCH` when the process has already been reaped, `EPERM` when signalling
/// is not permitted.
pub fn pidfd_send_signal(pidfd: RawFd, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: passing a null siginfo pointer is documented as "as if by
    // kill()"; the flags argument must be zero, which it is.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Namespace identities of a process, as inode numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NsIds {
    /// `/proc/<pid>/ns/pid`.
    pub pid: Option<u64>,
    /// `/proc/<pid>/ns/mnt`.
    pub mnt: Option<u64>,
    /// `/proc/<pid>/ns/net`.
    pub net: Option<u64>,
    /// `/proc/<pid>/ns/user`.
    pub user: Option<u64>,
    /// `/proc/<pid>/ns/cgroup`.
    pub cgroup: Option<u64>,
}

/// Read the five namespace ids this project cares about.
///
/// A namespace whose link cannot be read is `None`, never zero: an unreadable
/// namespace is unknown, not "the same as ours".
#[must_use]
pub fn ns_ids(pid: libc::pid_t) -> NsIds {
    NsIds {
        pid: ns_id(pid, "pid"),
        mnt: ns_id(pid, "mnt"),
        net: ns_id(pid, "net"),
        user: ns_id(pid, "user"),
        cgroup: ns_id(pid, "cgroup"),
    }
}

fn ns_id(pid: libc::pid_t, kind: &str) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{pid}/ns/{kind}")).ok()?;
    parse_ns_link(link.to_str()?)
}

/// Parse `pid:[4026531836]` into its inode number.
#[must_use]
pub fn parse_ns_link(link: &str) -> Option<u64> {
    let open = link.find('[')?;
    let close = link.find(']')?;
    link.get(open + 1..close)?.parse().ok()
}

/// A named field of `/proc/<pid>/status`, trimmed.
///
/// # Errors
///
/// Any failure reading the file, or [`io::ErrorKind::InvalidData`] when the
/// key is absent.
pub fn status_field(pid: libc::pid_t, key: &str) -> io::Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/status"))?;
    status_value(&raw, key).map(str::to_owned).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no {key} line in status of {pid}"),
        )
    })
}

/// The value of the `key:` line of a `/proc/<pid>/status` text, trimmed;
/// `None` when there is no such line.
#[must_use]
pub fn status_value<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .map(str::trim)
}

/// What one `/proc/<pid>/status` snapshot says about a process's privilege
/// and its syscall filters.
///
/// One read, so every fact is of the same moment. A line the privilege
/// checks rest on that is missing, empty or malformed is an error, never a
/// default: `"".chars().all(|c| c == '0')` is true, and "the capability set
/// could not be read" must not pass for "it holds none".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Privilege {
    /// `NoNewPrivs` is `1`.
    pub no_new_privs: bool,
    /// `CapEff`, the effective capability set.
    pub cap_eff: u64,
    /// `Seccomp`, the seccomp mode as the kernel writes it (`0`, `1`, `2`),
    /// or `None` when the kernel has no such line.
    pub seccomp: Option<String>,
    /// `Seccomp_filters`, the number of filters in force as the kernel writes
    /// it, or `None` when the kernel has no such line.
    pub seccomp_filters: Option<String>,
}

impl Privilege {
    /// Read `/proc/<pid>/status` once and parse it.
    ///
    /// # Errors
    /// Any failure reading the file, or [`io::ErrorKind::InvalidData`] as
    /// [`Privilege::parse`] returns it.
    pub fn read(pid: libc::pid_t) -> io::Result<Self> {
        Self::parse(&fs::read_to_string(format!("/proc/{pid}/status"))?)
    }

    /// Parse the contents of a `/proc/<pid>/status` file.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidData`] when `NoNewPrivs` is missing or neither
    /// `0` nor `1`, or `CapEff` is missing or not a hexadecimal mask.
    pub fn parse(status: &str) -> io::Result<Self> {
        let field = |key: &str| status_value(status, key);
        let invalid = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
        let no_new_privs = match field("NoNewPrivs") {
            Some("1") => true,
            Some("0") => false,
            other => return Err(invalid(format!("NoNewPrivs is {other:?}"))),
        };
        let cap_eff = field("CapEff")
            .filter(|mask| !mask.is_empty())
            .and_then(|mask| u64::from_str_radix(mask, 16).ok())
            .ok_or_else(|| invalid(format!("CapEff is {:?}", field("CapEff"))))?;
        Ok(Self {
            no_new_privs,
            cap_eff,
            seccomp: field("Seccomp").map(str::to_owned),
            seccomp_filters: field("Seccomp_filters").map(str::to_owned),
        })
    }

    /// No new privileges can be gained and no capability is in effect.
    #[must_use]
    pub fn unprivileged(&self) -> bool {
        self.no_new_privs && self.cap_eff == 0
    }
}

/// Whether `pid` is blocked in `read(2)` on descriptor `fd`, from
/// `/proc/<pid>/syscall`.
///
/// The descriptor is part of the answer: a launcher reads other descriptors
/// before it blocks on its release pipe (the narrowing trace data, for one),
/// and a gate that took any `read` for the release would pass early.
///
/// # Errors
/// Any failure reading the file.
pub fn blocked_in_read(pid: libc::pid_t, fd: RawFd) -> io::Result<bool> {
    Ok(parse_blocked_in_read(
        &fs::read_to_string(format!("/proc/{pid}/syscall"))?,
        fd,
    ))
}

/// Why a launcher was not seen blocked on its release descriptor.
#[derive(Debug)]
pub enum NotBlocked {
    /// The launcher, or what holds it, ended first.
    Ended,
    /// The deadline passed first; the last read of `/proc/<pid>/syscall`,
    /// when that read failed.
    TimedOut(Option<io::Error>),
}

impl NotBlocked {
    /// What the timeout's refusal adds to its message: why the syscall could
    /// not be read, when it could not.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            NotBlocked::TimedOut(Some(error)) => {
                format!(" (its syscall could not be read: {error})")
            }
            NotBlocked::TimedOut(None) | NotBlocked::Ended => String::new(),
        }
    }
}

/// Waits until `pid` is blocked in `read(2)` on `fd`: the gate every
/// launcher passes before the observer may attach and the release may be
/// written, the one place it is checked. Read from `/proc/<pid>/syscall`
/// with the descriptor ([`blocked_in_read`]): the launcher reads its
/// trace-data descriptor before it blocks, and that read is not the gate. A
/// read of the file that fails is not "blocked"; it is asked again, and the
/// last failure is reported with the timeout. `ended` is asked between
/// reads, before the deadline: the launcher's end is the more telling
/// cause.
///
/// # Errors
/// [`NotBlocked`].
pub fn wait_blocked_in_read(
    pid: libc::pid_t,
    fd: RawFd,
    deadline: super::clock::Deadline,
    mut ended: impl FnMut() -> bool,
) -> Result<(), NotBlocked> {
    loop {
        let unreadable = match blocked_in_read(pid, fd) {
            Ok(true) => return Ok(()),
            Ok(false) => None,
            Err(error) => Some(error),
        };
        if ended() {
            return Err(NotBlocked::Ended);
        }
        if deadline.expired() {
            return Err(NotBlocked::TimedOut(unreadable));
        }
        super::sys::nap();
    }
}

/// Whether a `/proc/<pid>/syscall` line (the number, then the arguments in
/// hexadecimal) is a `read(2)` on `fd`.
#[must_use]
pub fn parse_blocked_in_read(raw: &str, fd: RawFd) -> bool {
    let mut fields = raw.split_whitespace();
    fields
        .next()
        .and_then(|number| number.parse::<libc::c_long>().ok())
        == Some(libc::SYS_read)
        && fields
            .next()
            .and_then(|arg| arg.strip_prefix("0x"))
            .and_then(|hex| i64::from_str_radix(hex, 16).ok())
            == Some(i64::from(fd))
}

/// The environment names the launcher actually has, read from `/proc`.
///
/// I09: names only, never values.
///
/// # Errors
/// The read's error: an unreadable environment is not an empty one.
pub fn read_environment_names(pid: libc::pid_t) -> std::io::Result<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/environ"))?;
    let mut names: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            let at = entry.iter().position(|byte| *byte == b'=')?;
            Some(String::from_utf8_lossy(&entry[..at]).into_owned())
        })
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_field_nine_even_after_a_comm_with_spaces_and_parentheses() {
        let raw = "77 (a) b (c) R 1 77 77 0 -1 4194564 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0";
        assert_eq!(parse_flags(raw).unwrap(), 4_194_564);
        assert_eq!(parse_flags(raw).unwrap() & PF_EXITING, 4);
        assert!(parse_flags("77 (x) R 1 2").is_err());
        let live = fs::read_to_string(stat_path(std::process::id().cast_signed())).unwrap();
        assert_eq!(
            parse_flags(&live).unwrap() & PF_EXITING,
            0,
            "this process is not exiting"
        );
    }

    #[test]
    fn start_time_is_parsed_after_the_last_parenthesis() {
        // A comm field containing spaces and parentheses is the case that
        // breaks a naive split.
        let mut fields = String::from("1234 (weird ) name) S");
        for n in 4..=21 {
            fields.push_str(&format!(" {n}"));
        }
        fields.push_str(" 987654"); // field 22
        fields.push_str(" 23 24\n");
        assert_eq!(parse_start_time_ticks(&fields).unwrap(), 987_654);
    }

    #[test]
    fn the_state_is_the_field_after_the_last_parenthesis() {
        assert_eq!(parse_state("42 (a) b) Z 1 42").unwrap(), 'Z');
        assert_eq!(parse_state("42 (sleep) S 1 42").unwrap(), 'S');
        assert!(parse_state("42 (sleep)").is_err());
        assert!(parse_state("no comm").is_err());
    }

    #[test]
    fn a_stat_line_without_a_comm_field_is_invalid_data() {
        let err = parse_start_time_ticks("nonsense").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_short_stat_line_is_invalid_data() {
        let err = parse_start_time_ticks("1 (x) S 4 5 6").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn status(no_new_privs: Option<&str>, cap_eff: Option<&str>) -> String {
        let mut text = String::from("Name:\tlauncher\nUmask:\t0022\n");
        if let Some(value) = cap_eff {
            text.push_str(&format!("CapEff:\t{value}\n"));
        }
        if let Some(value) = no_new_privs {
            text.push_str(&format!("NoNewPrivs:\t{value}\n"));
        }
        text.push_str("Seccomp:\t2\nSeccomp_filters:\t3\n");
        text
    }

    #[test]
    fn privilege_is_read_from_one_status_and_an_unreadable_line_refuses() {
        let clean = Privilege::parse(&status(Some("1"), Some("0000000000000000"))).unwrap();
        assert!(clean.unprivileged());
        assert_eq!(clean.seccomp.as_deref(), Some("2"));
        assert_eq!(clean.seccomp_filters.as_deref(), Some("3"));

        let capable = Privilege::parse(&status(Some("1"), Some("0000000000200000"))).unwrap();
        assert_eq!(capable.cap_eff, 0x20_0000);
        assert!(!capable.unprivileged());
        assert!(
            !Privilege::parse(&status(Some("0"), Some("0")))
                .unwrap()
                .unprivileged()
        );

        // Missing, empty or malformed: an error, never "no capabilities".
        for (no_new_privs, cap_eff) in [
            (Some("1"), None),
            (Some("1"), Some("")),
            (Some("1"), Some("zz")),
            (None, Some("0")),
            (Some(""), Some("0")),
            (Some("yes"), Some("0")),
        ] {
            let error = Privilege::parse(&status(no_new_privs, cap_eff)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        let own = Privilege::read(std::process::id().cast_signed()).unwrap();
        assert!(own.seccomp.is_some(), "{own:?}");
    }

    /// The gate passes only on a read of the named descriptor; any other
    /// state waits out the deadline, and the launcher's end ends the wait
    /// first.
    #[test]
    fn the_launcher_gate_waits_for_a_read_on_its_own_descriptor() {
        use std::process::{Command, Stdio};
        use std::time::Duration;
        let mut reader = Command::new("/bin/sh")
            .args(["-c", "read line"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = libc::pid_t::try_from(reader.id()).unwrap();
        let soon = || super::super::clock::Deadline::after(Duration::from_secs(10));
        assert!(wait_blocked_in_read(pid, 0, soon(), || false).is_ok());
        let started = std::time::Instant::now();
        let brief = super::super::clock::Deadline::after(Duration::from_millis(50));
        assert!(matches!(
            wait_blocked_in_read(pid, 7, brief, || false),
            Err(NotBlocked::TimedOut(None))
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(matches!(
            wait_blocked_in_read(pid, 7, soon(), || true),
            Err(NotBlocked::Ended)
        ));
        drop(reader.stdin.take());
        reader.wait().unwrap();
    }

    #[test]
    fn only_a_read_on_the_named_descriptor_is_blocked_in_read() {
        let read = libc::SYS_read;
        assert!(parse_blocked_in_read(
            &format!("{read} 0x3 0x7ffd 0x1 0x0 0x0 0x0 0x7ffd 0x7f"),
            3
        ));
        assert!(parse_blocked_in_read(&format!("{read} 0xc 0x7ffd 0x1"), 12));
        // The launcher's read of its trace-data descriptor is not the gate.
        assert!(!parse_blocked_in_read(
            &format!("{read} 0x9 0x7ffd 0x2"),
            12
        ));
        assert!(!parse_blocked_in_read(
            &format!("{read} 0x5 0x7ffd 0x1 0x0"),
            3
        ));
        assert!(!parse_blocked_in_read("running", 3));
        assert!(!parse_blocked_in_read(
            &format!("{} 0x3", libc::SYS_write),
            3
        ));
        assert!(!parse_blocked_in_read("", 3));
    }

    #[test]
    fn namespace_links_parse() {
        assert_eq!(parse_ns_link("pid:[4026531836]"), Some(4_026_531_836));
        assert_eq!(parse_ns_link("mnt:[1]"), Some(1));
        assert_eq!(parse_ns_link("garbage"), None);
    }
}
