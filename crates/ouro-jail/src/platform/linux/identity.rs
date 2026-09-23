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
use std::path::{Path, PathBuf};

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

/// Read the four namespace ids this project cares about.
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
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix(key)
            && let Some(value) = rest.strip_prefix(':')
        {
            return Ok(value.trim().to_owned());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("no {key} line in status of {pid}"),
    ))
}

/// Whether a path is a directory owned by this process's uid.
#[must_use]
pub fn is_own_directory(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt as _;
            // SAFETY: getuid takes no arguments and cannot fail.
            meta.is_dir() && meta.uid() == unsafe { libc::getuid() }
        }
        Err(_) => false,
    }
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
    fn a_stat_line_without_a_comm_field_is_invalid_data() {
        let err = parse_start_time_ticks("nonsense").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_short_stat_line_is_invalid_data() {
        let err = parse_start_time_ticks("1 (x) S 4 5 6").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn namespace_links_parse() {
        assert_eq!(parse_ns_link("pid:[4026531836]"), Some(4_026_531_836));
        assert_eq!(parse_ns_link("mnt:[1]"), Some(1));
        assert_eq!(parse_ns_link("garbage"), None);
    }
}
