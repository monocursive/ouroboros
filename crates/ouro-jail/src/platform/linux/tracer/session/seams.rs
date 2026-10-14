//! Where the session meets the world outside the tracee's stops: every
//! `/proc` read it makes ([`ProcView`]), and the test seams that
//! manufacture a gap the tracer already records on a marked path.

use libc::pid_t;

use crate::platform::linux::tracer::proc;
use crate::platform::linux::tracer::{KernelImage, PathSnapshot, ShebangImage};

/// Every `/proc` read the session makes.
///
/// A seam, so a unit test can play what the kernel will not hand an
/// unprivileged test on the reference host — a tid recycled for a new task, a
/// reused backend pid, a raced exec image — and so that what a stop reads can
/// be counted. The live implementation is [`LiveProc`]; the trait has no
/// defaults, so a fake answers every read itself and never falls through to the
/// real `/proc`.
pub(super) trait ProcView: Send {
    /// The thread group `tid` belongs to, in this process's pid namespace.
    fn tgid(&self, tid: pid_t) -> Option<pid_t>;
    /// Field 22 of `/proc/<tid>/stat`: the task's start time in clock ticks
    /// since boot.
    fn start_ticks(&self, tid: pid_t) -> Option<u64>;
    /// The parent `pid` currently reports.
    fn ppid(&self, pid: pid_t) -> Option<pid_t>;
    /// The direct children of every thread of `pid`.
    fn children(&self, pid: pid_t) -> Vec<pid_t>;
    /// The raw `/proc/<tid>/cmdline` bytes.
    fn cmdline(&self, tid: pid_t) -> Option<Vec<u8>>;
    /// The image the kernel loaded for `tid` (`/proc/<tid>/exe`, raw, with its
    /// identity) and each of `images`' identity in the tracee's root.
    fn kernel_image(&self, tid: pid_t, images: &[Vec<u8>]) -> Option<KernelImage>;
    /// The `#!` or `binfmt_misc` interpreter a target candidate would load.
    fn script_image(&self, tid: pid_t, candidate: &[u8]) -> Option<ShebangImage>;
    /// The raw `/proc/<tid>/cwd` link bytes (§11.3).
    fn cwd(&self, tid: pid_t) -> Option<Vec<u8>>;
    /// The raw `/proc/<tid>/fd/<fd>` link bytes.
    fn fd_link(&self, tid: pid_t, fd: i64) -> Option<Vec<u8>>;
    /// The link count of the file `/proc/<tid>/fd/<fd>` resolves to: 0 once the
    /// file is unlinked. `None` when it cannot be read.
    fn fd_nlink(&self, tid: pid_t, fd: i64) -> Option<u64>;
}

/// `/proc`, read now.
pub(super) struct LiveProc;

impl ProcView for LiveProc {
    fn tgid(&self, tid: pid_t) -> Option<pid_t> {
        proc::tgid(tid)
    }

    fn start_ticks(&self, tid: pid_t) -> Option<u64> {
        proc::start_ticks(tid)
    }

    fn ppid(&self, pid: pid_t) -> Option<pid_t> {
        proc::ppid(pid)
    }

    fn children(&self, pid: pid_t) -> Vec<pid_t> {
        proc::children(pid)
    }

    fn cmdline(&self, tid: pid_t) -> Option<Vec<u8>> {
        proc::cmdline_bytes(tid)
    }

    fn kernel_image(&self, tid: pid_t, images: &[Vec<u8>]) -> Option<KernelImage> {
        proc::kernel_exe(tid, images)
    }

    fn script_image(&self, tid: pid_t, candidate: &[u8]) -> Option<ShebangImage> {
        proc::shebang_image(tid, candidate).or_else(|| proc::binfmt_image(tid, candidate))
    }

    fn cwd(&self, tid: pid_t) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStringExt as _;
        std::fs::read_link(format!("/proc/{tid}/cwd"))
            .ok()
            .map(|link| link.into_os_string().into_vec())
    }

    fn fd_link(&self, tid: pid_t, fd: i64) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStringExt as _;
        std::fs::read_link(format!("/proc/{tid}/fd/{fd}"))
            .ok()
            .map(|link| link.into_os_string().into_vec())
    }

    fn fd_nlink(&self, tid: pid_t, fd: i64) -> Option<u64> {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(format!("/proc/{tid}/fd/{fd}"))
            .ok()
            .map(|meta| meta.nlink())
    }
}

// O03 test seams: tracer gaps manufactured on a marked path.
/// `OURO_JAIL_TEST_TRACER_TRUNCATE_PATH=<substring>`: every covered non-exec
/// call whose path contains `<substring>` reports "the kernel accepted the
/// call but the tracer could not read the path" — the truncation case O03
/// names — so that call, when it succeeds, becomes a `path_unreadable` gap
/// rather than a result.
///
/// The substring gates the seam to the test's own target path so the observer
/// capability probe (whose paths never match) is untouched. A test seam (S9):
/// read once when the session starts, empty/unset leaves the tracer unchanged
/// (the release binary is unaffected), and, like every `OURO_JAIL_TEST_*`
/// variable, it is recorded in jail state and in every receipt with native
/// details (`state::persist::test_seams`). It can only MANUFACTURE a gap the
/// tracer already records for real truncation — never hide a result or widen
/// authority — so a run under it ends exactly as a run with that real loss would.
pub const TRUNCATE_PATH_SEAM: &str = "OURO_JAIL_TEST_TRACER_TRUNCATE_PATH";

/// `OURO_JAIL_TEST_TRACER_UNMATCHED_EXIT=<substring>`: every covered non-exec
/// entry whose path contains `<substring>` is followed to its exit stop
/// without being recorded, so its exit has no entry to pair with and is an
/// `unmatched_exit` gap. A path-gated test seam (S9), read once when the
/// session starts, recorded like every `OURO_JAIL_TEST_*` variable; it
/// manufactures only a gap the tracer already records.
pub const UNMATCHED_EXIT_SEAM: &str = "OURO_JAIL_TEST_TRACER_UNMATCHED_EXIT";

pub(super) fn seam_marker(name: &str) -> Option<Vec<u8>> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map(String::into_bytes)
}

pub(super) fn path_has_marker(snapshot: Option<&PathSnapshot>, marker: &[u8]) -> bool {
    snapshot.is_some_and(|snapshot| {
        snapshot
            .bytes
            .windows(marker.len())
            .any(|window| window == marker)
    })
}
