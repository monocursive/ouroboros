//! The performance workloads and the per-launch launcher of `cargo xtask
//! perf` (jail-v1 §5).
//!
//! `fileops` and `spawn-tree` are workloads: they run as the measured
//! command (inside the jail or directly) and print their own clock readings.
//! `perf-launch` runs outside the jail, as the parent of the measured command:
//! it reads the clock around the launch, samples memory, reaps, harvests the
//! attempt directory, and writes one [`PerfLaunchResult`], the type `cargo
//! xtask perf` reads back.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString, c_int};
use std::fs::File;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};

use crate::cli::{ExecVia, PerfMode};
use crate::ops::exec::{do_exec, image, spawn_exec};
use crate::ops::process::sleep_ms;
use crate::ops::{Usage, close_fd, raw_errno};
use crate::raw::{self, Attempt};
use crate::report::{OpReport, Reporter, path_value};

/// The identifier of a [`PerfLaunchResult`].
pub const PERF_LAUNCH_SCHEMA: &str = "ouro.fixture.perf-launch/2";

/// Run one performance mode.
pub(crate) fn run(rep: &Reporter, mode: PerfMode) -> Result<bool, Usage> {
    match mode {
        PerfMode::Fileops { rounds, dir } => fileops(rep, rounds, &dir),
        PerfMode::SpawnTree { count, argv } => spawn_tree(rep, count, &argv),
        PerfMode::PerfLaunch {
            out,
            data_dir,
            sample_ms,
            deadline_ms,
            argv,
        } => perf_launch(&out, data_dir.as_deref(), sample_ms, deadline_ms, &argv),
    }
}

/// An `Option` that must be present, as `null` or a value: serde otherwise
/// reads a missing `Option` field as `None`, so a renamed key would read as
/// "no exec error" or "no wait error".
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// What `perf-launch` writes for one launch, and what `cargo xtask perf`
/// reads back: one type on both sides, every field required, nothing
/// unknown accepted, so a renamed or missing key is a parse error there and
/// never a default in the §5 evidence.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerfLaunchResult {
    /// [`PERF_LAUNCH_SCHEMA`].
    pub schema: String,
    /// The launched command, lossily as text.
    pub argv: Vec<String>,
    pub pid: i32,
    /// `CLOCK_MONOTONIC` just before `fork`.
    pub t0_ns: u64,
    /// The same clock once the child's exec is known to have happened (or
    /// failed).
    pub exec_ns: u64,
    /// The same clock once the child was reaped.
    pub t1_ns: u64,
    /// `readlink /proc/self/ns/time` of the launcher.
    #[serde(deserialize_with = "present")]
    pub timens: Option<String>,
    /// The errno of a failed exec, by name.
    #[serde(deserialize_with = "present")]
    pub exec_errno: Option<String>,
    /// The deadline passed and the child was signalled.
    pub timed_out: bool,
    /// The errno of a failed `wait4`, by name.
    #[serde(deserialize_with = "present")]
    pub wait_errno: Option<String>,
    pub waited_via: WaitedVia,
    /// The launcher's own cgroup, which a direct target inherits.
    #[serde(deserialize_with = "present")]
    pub cgroup: Option<String>,
    pub status: LaunchStatus,
    pub rusage: LaunchRusage,
    pub sampling: Sampling,
    /// Every attempt directory the launch left, when a data directory was
    /// named.
    #[serde(deserialize_with = "present")]
    pub attempts: Option<Vec<HarvestedAttempt>>,
}

impl PerfLaunchResult {
    /// Parse a result file, refusing any other schema.
    ///
    /// # Errors
    /// Bytes that are not a [`PERF_LAUNCH_SCHEMA`] result.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        match value.get("schema").and_then(Value::as_str) {
            Some(PERF_LAUNCH_SCHEMA) => {}
            other => {
                return Err(format!(
                    "the schema is {other:?}, not {PERF_LAUNCH_SCHEMA:?}"
                ));
            }
        }
        serde_json::from_value(value).map_err(|e| e.to_string())
    }
}

/// How the launcher saw its child exit.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WaitedVia {
    /// A pidfd: the exit is seen at once.
    Pidfd,
    /// `wait4(WNOHANG)` between samples: within one interval.
    Wnohang,
}

impl WaitedVia {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WaitedVia::Pidfd => "pidfd",
            WaitedVia::Wnohang => "wnohang",
        }
    }
}

/// The child's wait status.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchStatus {
    /// The raw `wait4` status.
    pub raw: i32,
    pub exited: bool,
    #[serde(deserialize_with = "present")]
    pub code: Option<i32>,
    #[serde(deserialize_with = "present")]
    pub signal: Option<i32>,
}

/// `wait4`'s resource usage of the child.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchRusage {
    /// The largest resident set of the launched process and every
    /// descendant it (transitively) reaped.
    pub maxrss_kib: u64,
    pub utime_us: u64,
    pub stime_us: u64,
}

/// What the sampler saw while the child ran. Both peaks are high-water
/// marks read at the last sample, so each is a lower bound.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sampling {
    pub interval_ms: u64,
    pub samples: u64,
    /// The launched process's own `VmHWM`.
    #[serde(deserialize_with = "present")]
    pub hwm_kib: Option<u64>,
    /// The execution leaf the attempt's receipt named.
    #[serde(deserialize_with = "present")]
    pub leaf_path: Option<String>,
    /// That leaf's `memory.peak`.
    #[serde(deserialize_with = "present")]
    pub leaf_peak_bytes: Option<u64>,
    pub leaf_samples: u64,
    /// Why the leaf could not be sampled.
    #[serde(deserialize_with = "present")]
    pub leaf_note: Option<String>,
}

/// One attempt directory the launch left.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HarvestedAttempt {
    /// The directory's name, the attempt id.
    #[serde(deserialize_with = "present")]
    pub id: Option<String>,
    pub dir: String,
    /// Whether it holds a final receipt (`jail.json`).
    pub receipt: bool,
    pub trace: TraceHarvest,
}

/// The attempt's trace, read back, or why it could not be read.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TraceHarvest {
    Read(TraceCounts),
    Unreadable(String),
}

/// Counts over a trace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TraceCounts {
    pub bytes: u64,
    pub state: TraceCompleteness,
    pub frames: u64,
    /// Why the trace is not a complete transcript ending on the note of the
    /// final receipt (§13.3), or `None` when it is one.
    #[serde(deserialize_with = "present")]
    pub guard: Option<String>,
    pub by_source: BTreeMap<String, u64>,
    pub by_operation: BTreeMap<String, u64>,
    /// Wrapper notes by kind.
    pub notes: BTreeMap<String, u64>,
}

/// How a trace's frames end (the harness's [`crate::harness::TraceState`]).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TraceCompleteness {
    Complete,
    Incomplete,
    Corrupt,
}

impl TraceCompleteness {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TraceCompleteness::Complete => "complete",
            TraceCompleteness::Incomplete => "incomplete",
            TraceCompleteness::Corrupt => "corrupt",
        }
    }
}

impl From<crate::harness::TraceState> for TraceCompleteness {
    fn from(state: crate::harness::TraceState) -> Self {
        match state {
            crate::harness::TraceState::Complete => TraceCompleteness::Complete,
            crate::harness::TraceState::Incomplete => TraceCompleteness::Incomplete,
            crate::harness::TraceState::Corrupt => TraceCompleteness::Corrupt,
        }
    }
}

/// The default child of `spawn-tree`. This path exists on the
/// usr-merged reference host and on macOS alike.
pub(crate) const DEFAULT_CHILD: &str = "/usr/bin/true";

/// How long `perf-launch` waits after SIGTERM before SIGKILL.
const KILL_GRACE: Duration = Duration::from_secs(10);

/// `CLOCK_MONOTONIC` in nanoseconds: the clock `perf-launch` and the
/// workloads share. Bubblewrap enters no time namespace, and the start
/// line names this process's one so the harness can check that.
pub(crate) fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live timespec that the call only writes.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    u64::try_from(ts.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(ts.tv_nsec).unwrap_or(0))
}

/// The unified cgroup of this process, or `None` without one.
fn own_cgroup() -> Option<String> {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)
}

/// `readlink /proc/self/ns/time`, or `None` without a `/proc`.
pub(crate) fn time_namespace() -> Option<String> {
    std::fs::read_link("/proc/self/ns/time")
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// `getrusage(who).ru_maxrss` in KiB (Linux reports KiB, macOS bytes).
fn peak_rss_kib(who: c_int) -> u64 {
    // SAFETY: a zeroed `rusage` is a valid value for the call to fill.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` is live and writable for the call.
    if unsafe { libc::getrusage(who, &raw mut ru) } != 0 {
        return 0;
    }
    maxrss_kib(&ru)
}

fn maxrss_kib(ru: &libc::rusage) -> u64 {
    let raw = u64::try_from(ru.ru_maxrss).unwrap_or(0);
    if cfg!(target_os = "linux") {
        raw
    } else {
        raw / 1024
    }
}

fn micros(tv: libc::timeval) -> u64 {
    u64::try_from(tv.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(tv.tv_usec).unwrap_or(0))
}

/// The first line of every workload: its own clock reading, taken
/// before anything else it does.
fn perf_start(rep: &Reporter, mode: &str) -> u64 {
    let now = monotonic_ns();
    let mut r = OpReport::new("perf-start");
    r.set("mode", mode);
    r.set("monotonic_ns", now);
    r.set("pid", std::process::id());
    r.set("timens", time_namespace());
    rep.emit(&r);
    now
}

fn finish_line(r: &mut OpReport, start: u64, ok: bool) {
    r.set("start_ns", start);
    r.set("end_ns", monotonic_ns());
    r.set("maxrss_kib", peak_rss_kib(libc::RUSAGE_SELF));
    r.set("children_maxrss_kib", peak_rss_kib(libc::RUSAGE_CHILDREN));
    r.set("ok", ok);
}

fn succeeded(attempt: &Attempt) -> bool {
    matches!(attempt, Attempt::Performed { ret, .. } if *ret >= 0)
}

fn keep_first(first: &mut Option<(&'static str, String)>, op: &'static str, a: &Attempt) {
    if first.is_some() {
        return;
    }
    let errno = match a {
        Attempt::Performed { errno: Some(e), .. } => crate::errno::spelling(*e),
        Attempt::Performed { errno: None, .. } => "none".to_owned(),
        Attempt::Absent(_) => "absent".to_owned(),
    };
    *first = Some((op, errno));
}

pub(crate) fn fileops(rep: &Reporter, rounds: u32, dir: &OsStr) -> Result<bool, Usage> {
    let name = |leaf: &[u8]| {
        let mut bytes = dir.as_bytes().to_vec();
        bytes.push(b'/');
        bytes.extend_from_slice(leaf);
        raw::cpath(&OsString::from_vec(bytes))
            .map_err(|e| format!("fileops DIR cannot be a syscall argument: {}", e.reason))
    };
    let (a, b) = (name(b"w")?, name(b"x")?);
    let legacy = raw::has_legacy_syscalls();
    let (rename_via, unlink_via) = if legacy {
        ("rename", "unlink")
    } else {
        ("renameat", "unlinkat")
    };

    let start = perf_start(rep, "fileops");
    let (mut created, mut renamed, mut unlinked) = (0u32, 0u32, 0u32);
    let mut first: Option<(&'static str, String)> = None;
    for _ in 0..rounds {
        let opened = raw::openat(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if let Attempt::Performed { ret, .. } = opened
            && ret >= 0
        {
            created += 1;
            close_fd(ret);
        } else {
            keep_first(&mut first, "openat", &opened);
        }
        let moved = if legacy {
            raw::rename(a.as_ptr(), b.as_ptr())
        } else {
            raw::renameat(libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr())
        };
        if succeeded(&moved) {
            renamed += 1;
        } else {
            keep_first(&mut first, rename_via, &moved);
        }
        let removed = if legacy {
            raw::unlink(b.as_ptr())
        } else {
            raw::unlinkat(libc::AT_FDCWD, b.as_ptr(), 0)
        };
        if succeeded(&removed) {
            unlinked += 1;
        } else {
            keep_first(&mut first, unlink_via, &removed);
        }
    }
    let ok = created == rounds && renamed == rounds && unlinked == rounds;
    let mut r = OpReport::new("fileops");
    r.set("rounds", rounds);
    path_value(&mut r.args, "dir", dir);
    r.set("open_via", "openat");
    r.set("rename_via", rename_via);
    r.set("unlink_via", unlink_via);
    r.set("created", created);
    r.set("renamed", renamed);
    r.set("unlinked", unlinked);
    r.set(
        "first_error",
        first.map_or(Value::Null, |(op, errno)| json!({"op": op, "errno": errno})),
    );
    finish_line(&mut r, start, ok);
    r.result(i64::from(created.min(renamed).min(unlinked)), None);
    rep.emit(&r);
    Ok(ok)
}

pub(crate) fn spawn_tree(rep: &Reporter, count: u32, argv: &[OsString]) -> Result<bool, Usage> {
    let default = [OsString::from(DEFAULT_CHILD)];
    let argv = if argv.is_empty() { &default[..] } else { argv };
    let img = image(argv)?;

    let start = perf_start(rep, "spawn-tree");
    let (mut forked, mut exited_zero, mut failed) = (0u32, 0u32, 0u32);
    let mut fork_errno = None;
    for _ in 0..count {
        // SAFETY: this process is single-threaded; the child runs only
        // the exec syscall and `_exit`, over an image built before.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            fork_errno = Some(crate::errno::spelling(raw_errno()));
            break;
        }
        if pid == 0 {
            let _ = do_exec(&img, ExecVia::Execve);
            // SAFETY: the only correct exit from a child whose exec failed.
            unsafe { libc::_exit(127) };
        }
        forked += 1;
        let mut status: c_int = 0;
        let waited = loop {
            // SAFETY: `status` is live; `pid` is this process's own child.
            let w = unsafe { libc::waitpid(pid, &raw mut status, 0) };
            if w < 0 && raw_errno() == libc::EINTR {
                continue;
            }
            break w;
        };
        if waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            exited_zero += 1;
        } else {
            failed += 1;
        }
    }
    let ok = forked == count && exited_zero == count;
    let mut r = OpReport::new("spawn-tree");
    r.set("count", count);
    path_value(&mut r.args, "argv0", &argv[0]);
    r.set("forked", forked);
    r.set("exited_zero", exited_zero);
    r.set("failed", failed);
    r.set("fork_errno", fork_errno);
    finish_line(&mut r, start, ok);
    r.result(i64::from(exited_zero), None);
    rep.emit(&r);
    Ok(ok)
}

// ------------------------------------------------------------ perf-launch

/// `VmHWM` from the text of `/proc/<pid>/status`, in KiB.
pub(crate) fn vm_hwm_kib(status: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let mut words = line["VmHWM:".len()..].split_whitespace();
    let value = words.next()?.parse().ok()?;
    (words.next() == Some("kB")).then_some(value)
}

/// A cgroup counter file's single decimal value.
pub(crate) fn counter(text: &[u8]) -> Option<u64> {
    std::str::from_utf8(text).ok()?.trim().parse().ok()
}

/// What `perf-launch` samples while the launched process runs. Both
/// values are high-water marks, so the last sample is a lower bound of
/// the true peak that misses only growth after it.
struct Sampler {
    interval_ms: u64,
    pid: libc::pid_t,
    samples: u64,
    hwm_kib: Option<u64>,
    data_dir: Option<PathBuf>,
    leaf_path: Option<PathBuf>,
    leaf_file: Option<File>,
    leaf_peak: Option<u64>,
    leaf_samples: u64,
    leaf_note: Option<String>,
}

impl Sampler {
    fn sample(&mut self) {
        self.samples += 1;
        if let Ok(text) = std::fs::read_to_string(format!("/proc/{}/status", self.pid))
            && let Some(kib) = vm_hwm_kib(&text)
        {
            self.hwm_kib = Some(self.hwm_kib.map_or(kib, |h| h.max(kib)));
        }
        if self.leaf_path.is_none() && self.leaf_note.is_none() {
            self.find_leaf();
        }
        if let Some(file) = &self.leaf_file {
            let mut buf = [0u8; 64];
            match file
                .read_at(&mut buf, 0)
                .ok()
                .and_then(|n| counter(&buf[..n]))
            {
                Some(bytes) => {
                    self.leaf_samples += 1;
                    self.leaf_peak = Some(self.leaf_peak.map_or(bytes, |p| p.max(bytes)));
                }
                // Removed with its leaf at settlement: nothing more to read.
                None => self.leaf_file = None,
            }
        }
    }

    /// The leaf the attempt's receipt names. The receipt is replaced
    /// atomically, so a read sees a whole one or none.
    fn find_leaf(&mut self) {
        let Some(data) = &self.data_dir else { return };
        let Ok(entries) = std::fs::read_dir(data.join("attempts")) else {
            return;
        };
        let dirs: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        if dirs.len() > 1 {
            self.leaf_note = Some(format!(
                "{} attempt directories under the data directory: the leaf is ambiguous",
                dirs.len()
            ));
            return;
        }
        let Some(dir) = dirs.first() else { return };
        let Some(receipt) = std::fs::read(dir.join("jail.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            return;
        };
        let Some(path) = receipt
            .pointer("/lifetime/native/details/execution_cgroup/path")
            .and_then(Value::as_str)
        else {
            return;
        };
        let path = PathBuf::from(path);
        match File::open(path.join("memory.peak")) {
            Ok(file) => self.leaf_file = Some(file),
            Err(e) => self.leaf_note = Some(format!("memory.peak: {e}")),
        }
        self.leaf_path = Some(path);
    }
}

struct Waited {
    status: c_int,
    rusage: libc::rusage,
    wait_errno: Option<c_int>,
    timed_out: bool,
    via: WaitedVia,
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: libc::pid_t) -> c_int {
    // SAFETY: plain integers; the kernel returns a new descriptor or fails.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    c_int::try_from(fd).unwrap_or(-1)
}

#[cfg(not(target_os = "linux"))]
fn open_pidfd(_pid: libc::pid_t) -> c_int {
    -1
}

/// Did the pidfd become readable (the process exited) within `ms`?
fn exited_within(pidfd: c_int, ms: u64) -> bool {
    let mut p = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = c_int::try_from(ms).unwrap_or(c_int::MAX);
    // SAFETY: one live pollfd for the call.
    let n = unsafe { libc::poll(&raw mut p, 1, timeout) };
    n > 0
}

fn reap(pid: libc::pid_t, flags: c_int, w: &mut Waited) -> bool {
    loop {
        // SAFETY: `status` and `rusage` are live and writable; `pid` is
        // this process's own unreaped child.
        let r = unsafe { libc::wait4(pid, &raw mut w.status, flags, &raw mut w.rusage) };
        if r == pid {
            return true;
        }
        if r < 0 && raw_errno() == libc::EINTR {
            continue;
        }
        if r < 0 {
            w.wait_errno = Some(raw_errno());
            return true;
        }
        return false;
    }
}

/// Wait for `pid`, sampling between wake-ups, SIGTERM at the deadline and
/// SIGKILL after the grace. The pidfd path never reaps early; without a
/// pidfd, a non-blocking `wait4` between samples does.
fn wait_sampling(pid: libc::pid_t, sampler: &mut Sampler, deadline_ms: u64) -> Waited {
    let mut w = Waited {
        status: 0,
        // SAFETY: a zeroed `rusage` is a valid value.
        rusage: unsafe { std::mem::zeroed() },
        wait_errno: None,
        timed_out: false,
        via: WaitedVia::Wnohang,
    };
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let mut term_at: Option<Instant> = None;
    let mut killed = false;
    let pidfd = open_pidfd(pid);
    if pidfd >= 0 {
        w.via = WaitedVia::Pidfd;
    }
    let tick = if sampler.interval_ms == 0 {
        if pidfd >= 0 { 1000 } else { 1 }
    } else {
        sampler.interval_ms
    };
    loop {
        if pidfd >= 0 {
            if exited_within(pidfd, tick) {
                reap(pid, 0, &mut w);
                break;
            }
        } else {
            if reap(pid, libc::WNOHANG, &mut w) {
                break;
            }
            sleep_ms(tick);
            if reap(pid, libc::WNOHANG, &mut w) {
                break;
            }
        }
        let now = Instant::now();
        if term_at.is_none() && now >= deadline {
            w.timed_out = true;
            term_at = Some(now);
            // SAFETY: `pid` is this process's own unreaped child.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        if !killed && term_at.is_some_and(|at| now >= at + KILL_GRACE) {
            killed = true;
            // SAFETY: as above.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        if sampler.interval_ms > 0 {
            sampler.sample();
        }
    }
    if pidfd >= 0 {
        // SAFETY: the pidfd was opened here and is closed once.
        unsafe { libc::close(pidfd) };
    }
    w
}

/// Counts over a trace, and whether it is a complete transcript that ends
/// on the note of the attempt's final receipt (`trace_guard`, §13.3).
pub(crate) fn trace_facts(bytes: &[u8], receipt: Option<&[u8]>) -> TraceCounts {
    let readback = crate::harness::read_frames(bytes);
    let guard = crate::harness::trace_guard(Some(&readback), receipt).err();
    let mut by_source: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_operation: BTreeMap<String, u64> = BTreeMap::new();
    let mut notes: BTreeMap<String, u64> = BTreeMap::new();
    let text = |f: &Value, k: &str| f.get(k).and_then(Value::as_str).map(str::to_owned);
    for frame in &readback.frames {
        let source = text(frame, "source").unwrap_or_default();
        let operation = text(frame, "operation").unwrap_or_default();
        if source == "wrapper" && operation == "note" {
            let kind = frame
                .pointer("/fields/kind")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            *notes.entry(kind).or_default() += 1;
        }
        *by_source.entry(source).or_default() += 1;
        *by_operation.entry(operation).or_default() += 1;
    }
    TraceCounts {
        bytes: bytes.len() as u64,
        state: readback.state.into(),
        frames: readback.frames.len() as u64,
        guard,
        by_source,
        by_operation,
        notes,
    }
}

/// Every attempt directory the launch left, in name order.
fn harvest(data: &Path) -> Vec<HarvestedAttempt> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(data.join("attempts"))
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs.iter()
        .map(|dir| {
            let receipt = std::fs::read(dir.join("jail.json")).ok();
            let trace = match std::fs::read(dir.join("trace.ndjson")) {
                Ok(bytes) => TraceHarvest::Read(trace_facts(&bytes, receipt.as_deref())),
                Err(e) => TraceHarvest::Unreadable(e.to_string()),
            };
            HarvestedAttempt {
                id: dir.file_name().map(|n| n.to_string_lossy().into_owned()),
                dir: dir.to_string_lossy().into_owned(),
                receipt: receipt.is_some(),
                trace,
            }
        })
        .collect()
}

pub(crate) fn perf_launch(
    out: &OsStr,
    data_dir: Option<&OsStr>,
    sample_ms: u64,
    deadline_ms: u64,
    argv: &[OsString],
) -> Result<bool, Usage> {
    let img = image(argv)?;
    let out = PathBuf::from(out);
    let data_dir = data_dir.map(PathBuf::from);
    let timens = time_namespace();
    let mut sampler = Sampler {
        interval_ms: sample_ms,
        pid: 0,
        samples: 0,
        hwm_kib: None,
        data_dir: data_dir.clone(),
        leaf_path: None,
        leaf_file: None,
        leaf_peak: None,
        leaf_samples: 0,
        leaf_note: None,
    };

    // Start: just before fork. `spawn_exec` returns once the child has
    // exec'd (or failed to), so no sample can see this process's image.
    let t0 = monotonic_ns();
    let spawned = spawn_exec(&img, ExecVia::Execve)?;
    // Once the child's exec is known to have happened (or failed).
    let exec_ns = monotonic_ns();
    sampler.pid = spawned.pid;
    let waited = wait_sampling(spawned.pid, &mut sampler, deadline_ms);
    let t1 = monotonic_ns();

    let attempts = data_dir.as_deref().map(harvest);
    let s = waited.status;
    let exited = waited.wait_errno.is_none() && libc::WIFEXITED(s);
    let signaled = waited.wait_errno.is_none() && libc::WIFSIGNALED(s);
    let result = PerfLaunchResult {
        schema: PERF_LAUNCH_SCHEMA.to_owned(),
        argv: argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
        pid: spawned.pid,
        t0_ns: t0,
        exec_ns,
        t1_ns: t1,
        timens,
        exec_errno: spawned.exec_errno.map(crate::errno::spelling),
        timed_out: waited.timed_out,
        wait_errno: waited.wait_errno.map(crate::errno::spelling),
        waited_via: waited.via,
        cgroup: own_cgroup(),
        status: LaunchStatus {
            raw: s,
            exited,
            code: exited.then(|| libc::WEXITSTATUS(s)),
            signal: signaled.then(|| libc::WTERMSIG(s)),
        },
        rusage: LaunchRusage {
            maxrss_kib: maxrss_kib(&waited.rusage),
            utime_us: micros(waited.rusage.ru_utime),
            stime_us: micros(waited.rusage.ru_stime),
        },
        sampling: Sampling {
            interval_ms: sample_ms,
            samples: sampler.samples,
            hwm_kib: sampler.hwm_kib,
            leaf_path: sampler
                .leaf_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            leaf_peak_bytes: sampler.leaf_peak,
            leaf_samples: sampler.leaf_samples,
            leaf_note: sampler.leaf_note,
        },
        attempts,
    };
    let bytes = serde_json::to_vec_pretty(&result)
        .map_err(|e| format!("the perf-launch result cannot be serialized: {e}"))?;
    std::fs::write(&out, bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_high_water_mark_is_read_in_kib_from_its_own_line() {
        let status = "Name:\tx\nVmPeak:\t  9999 kB\nVmHWM:\t    4321 kB\nVmRSS:\t 12 kB\n";
        assert_eq!(vm_hwm_kib(status), Some(4321));
        assert_eq!(
            vm_hwm_kib("VmRSS:\t 12 kB\n"),
            None,
            "a zombie has no VmHWM"
        );
        assert_eq!(
            vm_hwm_kib("VmHWM:\t 12 MB\n"),
            None,
            "only kB is understood"
        );
        assert_eq!(vm_hwm_kib("VmHWM:\t\n"), None);
    }

    #[test]
    fn a_counter_is_one_decimal_value() {
        assert_eq!(counter(b"123456\n"), Some(123_456));
        assert_eq!(counter(b"0"), Some(0));
        assert_eq!(counter(b"max\n"), None);
        assert_eq!(counter(b""), None);
    }

    fn result() -> PerfLaunchResult {
        PerfLaunchResult {
            schema: PERF_LAUNCH_SCHEMA.to_owned(),
            argv: vec!["/usr/bin/true".to_owned()],
            pid: 42,
            t0_ns: 1,
            exec_ns: 2,
            t1_ns: 3,
            timens: None,
            exec_errno: None,
            timed_out: false,
            wait_errno: None,
            waited_via: WaitedVia::Pidfd,
            cgroup: None,
            status: LaunchStatus {
                raw: 0,
                exited: true,
                code: Some(0),
                signal: None,
            },
            rusage: LaunchRusage {
                maxrss_kib: 1,
                utime_us: 0,
                stime_us: 0,
            },
            sampling: Sampling {
                interval_ms: 5,
                samples: 0,
                hwm_kib: None,
                leaf_path: None,
                leaf_peak_bytes: None,
                leaf_samples: 0,
                leaf_note: None,
            },
            attempts: Some(vec![HarvestedAttempt {
                id: Some("att_x".to_owned()),
                dir: "/d/att_x".to_owned(),
                receipt: true,
                trace: TraceHarvest::Unreadable("gone".to_owned()),
            }]),
        }
    }

    /// Review FX1: a renamed or missing key is a parse error, never a
    /// default (`timed_out: false`, `exec_errno: None`) in the evidence.
    #[test]
    fn a_result_is_read_back_strictly() {
        let good = serde_json::to_value(result()).unwrap();
        let bytes = |v: &Value| serde_json::to_vec(v).unwrap();
        assert_eq!(PerfLaunchResult::parse(&bytes(&good)), Ok(result()));
        type Break = fn(&mut Value);
        let broken: [(&str, Break); 6] = [
            ("another schema", |v| {
                v["schema"] = "ouro.fixture.perf-launch/1".into()
            }),
            ("no schema", |v| {
                drop(v.as_object_mut().unwrap().remove("schema"))
            }),
            ("a missing Option", |v| {
                drop(v.as_object_mut().unwrap().remove("exec_errno"));
            }),
            ("a renamed key", |v| {
                let o = v.as_object_mut().unwrap();
                let t = o.remove("timed_out").unwrap();
                o.insert("timedout".to_owned(), t);
            }),
            ("a nested missing Option", |v| {
                drop(v["status"].as_object_mut().unwrap().remove("code"));
            }),
            ("an unknown nested key", |v| {
                v["sampling"]["extra"] = 1.into()
            }),
        ];
        for (label, change) in broken {
            let mut v = good.clone();
            change(&mut v);
            assert!(PerfLaunchResult::parse(&bytes(&v)).is_err(), "{label}");
        }
    }

    #[test]
    fn the_workload_clock_moves_forward() {
        let a = monotonic_ns();
        let b = monotonic_ns();
        assert!(a > 0 && b >= a, "{a} {b}");
    }
}
