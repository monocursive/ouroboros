//! Doctor probes.
//!
//! jail-v1 §14.1: each probe runs a short, isolated command with its own
//! resources and a five-second deadline, and reports a structured result. A
//! probe that could not run says `skipped` or `error`; it never says
//! `available`, because "a skipped check cannot satisfy a requirement"
//! (jail-v1 §3.1).
//!
//! The command run inside the sandbox is this binary itself, bound read-only
//! at `/run/ouro/jail` and re-executed with the hidden `__probe-inside`
//! subcommand. That keeps the probes free of any dependency on what happens
//! to be installed on the host, and it exercises the same read-only bind of
//! our own executable that a real run uses.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::bwrap::{self, BwrapPlan};
use super::cgroup;
use super::clock::Deadline;
use super::exec::{self, Captured, FdMap};
use super::identity::{self, ns_ids};
use super::seccomp;
use super::sys::{empty_stat, errno_name};

/// The hidden subcommand the probes run inside the sandbox.
pub const INSIDE_SUBCOMMAND: &str = "__probe-inside";

/// Every probe this implementation knows, in report order.
pub const PROBE_NAMES: [&str; 10] = [
    "bwrap_present",
    "user_namespace",
    "pid_namespace",
    "network_namespace",
    "mount_readonly_bind",
    "seccomp_filter_load",
    "ptrace_seize_descendant",
    "cgroup_delegated_leaf",
    "apparmor_userns_restriction",
    "nested_user_namespace",
];

/// Per-probe deadline (jail-v1 §14.1).
pub const PROBE_DEADLINE: Duration = Duration::from_secs(5);

/// The five statuses of jail-v1 §3.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The probe ran on this host with this identity and succeeded.
    Available,
    /// The implementation exists but a prerequisite is missing.
    Unavailable,
    /// This implementation does not have the mechanism at all.
    Unsupported,
    /// The probe could not complete.
    Error,
    /// The probe was not run.
    Skipped,
}

impl fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::Error => "error",
            Self::Skipped => "skipped",
        })
    }
}

/// One probe's result. The portable `Capability` of jail-v1 §3.1 is core's
/// type; this is the Linux-local shape phase 2 converts into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// The probe's name, from [`PROBE_NAMES`].
    pub name: &'static str,
    /// What was established.
    pub status: ProbeStatus,
    /// The mechanism that was exercised.
    pub mechanism: &'static str,
    /// A stable machine-readable reason.
    pub reason_code: &'static str,
    /// What was actually observed, for a human reading the report.
    pub evidence: String,
}

impl ProbeResult {
    fn new(
        name: &'static str,
        status: ProbeStatus,
        mechanism: &'static str,
        reason_code: &'static str,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status,
            mechanism,
            reason_code,
            evidence: evidence.into(),
        }
    }

    fn error(name: &'static str, mechanism: &'static str, evidence: impl Into<String>) -> Self {
        Self::new(
            name,
            ProbeStatus::Error,
            mechanism,
            "probe_failed",
            evidence,
        )
    }
}

/// Run every probe.
#[must_use]
pub fn run_all(jail_exe: &Path, bwrap: &Path) -> Vec<ProbeResult> {
    PROBE_NAMES
        .iter()
        .map(|name| run_one(name, jail_exe, bwrap))
        .collect()
}

/// Run one probe by name. An unknown name is `skipped`, never a silent pass.
#[must_use]
pub fn run_one(name: &str, jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    match name {
        "bwrap_present" => probe_bwrap_present(bwrap),
        "user_namespace" => probe_namespace("user_namespace", jail_exe, bwrap),
        "pid_namespace" => probe_namespace("pid_namespace", jail_exe, bwrap),
        "network_namespace" => probe_network_namespace(jail_exe, bwrap),
        "mount_readonly_bind" => probe_readonly_bind(jail_exe, bwrap),
        "seccomp_filter_load" => probe_seccomp(jail_exe, bwrap),
        "ptrace_seize_descendant" => probe_ptrace_seize(),
        "cgroup_delegated_leaf" => probe_cgroup_leaf(),
        "apparmor_userns_restriction" => probe_apparmor(),
        "nested_user_namespace" => probe_nested_userns(jail_exe, bwrap),
        _ => ProbeResult::new(
            "unknown",
            ProbeStatus::Skipped,
            "none",
            "unknown_probe",
            format!("no probe named {name}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Probes that need a sandbox
// ---------------------------------------------------------------------------

/// A temporary directory this process owns, removed on drop.
struct OwnedTempDir {
    path: PathBuf,
}

impl OwnedTempDir {
    fn new(tag: &str) -> io::Result<Self> {
        // SAFETY: getpid and gettid take no arguments and cannot fail.
        let pid = unsafe { libc::getpid() };
        let nanos = super::clock::boottime_ns();
        let path = std::env::temp_dir().join(format!("ouro-{tag}-{pid}-{nanos}"));
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for OwnedTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct SandboxRun {
    captured: Captured,
    /// Kept alive for the duration of the run.
    _workspace: OwnedTempDir,
    _scratch: OwnedTempDir,
}

fn run_inside(
    jail_exe: &Path,
    bwrap: &Path,
    checks: &[&str],
    extra_ro_binds: Vec<(PathBuf, PathBuf)>,
    with_seccomp: bool,
) -> io::Result<SandboxRun> {
    let mut inner = vec![
        OsString::from(bwrap::JAIL_INSIDE_PATH),
        OsString::from(INSIDE_SUBCOMMAND),
    ];
    inner.extend(checks.iter().map(OsString::from));
    run_inside_raw(jail_exe, bwrap, inner, extra_ro_binds, with_seccomp)
}

fn run_inside_raw(
    jail_exe: &Path,
    bwrap: &Path,
    inner: Vec<OsString>,
    extra_ro_binds: Vec<(PathBuf, PathBuf)>,
    with_seccomp: bool,
) -> io::Result<SandboxRun> {
    let workspace = OwnedTempDir::new("probe-ws")?;
    let scratch = OwnedTempDir::new("probe-scratch")?;
    let mut plan = BwrapPlan::tool(&workspace.path, &scratch.path, jail_exe);
    plan.bwrap = bwrap.to_owned();
    plan.extra_ro_binds = extra_ro_binds;
    plan.inner = inner;

    let mut fds = FdMap::new();
    if with_seccomp {
        let program = seccomp::tool_baseline().map_err(|e| io::Error::other(e.to_string()))?;
        let fd = seccomp::program_pipe(&program)?;
        plan.seccomp_fd = Some(10);
        fds.add(fd, 10)?;
    }

    let rendered = plan.render().map_err(|e| io::Error::other(e.to_string()))?;
    let mut command = Command::new(&rendered.argv[0]);
    command.args(&rendered.argv[1..]);
    fds.apply(&mut command);
    let captured = exec::run_captured(&mut command, Deadline::after(PROBE_DEADLINE))?;
    drop(fds);
    Ok(SandboxRun {
        captured,
        _workspace: workspace,
        _scratch: scratch,
    })
}

fn probe_bwrap_present(bwrap: &Path) -> ProbeResult {
    match bwrap::bwrap_version(bwrap) {
        Ok(version) => ProbeResult::new(
            "bwrap_present",
            ProbeStatus::Available,
            "bubblewrap",
            "ok",
            version.raw,
        ),
        Err(e) => ProbeResult::new(
            "bwrap_present",
            ProbeStatus::Unavailable,
            "bubblewrap",
            "backend_unavailable",
            format!("{}: {e}", bwrap.display()),
        ),
    }
}

fn probe_namespace(name: &'static str, jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    let kind = if name == "user_namespace" {
        "user"
    } else {
        "pid"
    };
    let mechanism = if kind == "user" {
        "user-namespace"
    } else {
        "pid-namespace"
    };
    let outside = ns_ids(own_pid());
    let outside_id = if kind == "user" {
        outside.user
    } else {
        outside.pid
    };
    let run = match run_inside(jail_exe, bwrap, &["status"], Vec::new(), false) {
        Ok(run) => run,
        Err(e) => return ProbeResult::error(name, mechanism, e.to_string()),
    };
    if run.captured.timed_out {
        return ProbeResult::error(name, mechanism, "probe exceeded its 5 second deadline");
    }
    let key = format!("ns_{kind}");
    let Some(inside_id) = run.captured.field(&key) else {
        return ProbeResult::error(
            name,
            mechanism,
            format!(
                "sandbox reported no {key}: status {:?}, stderr {}",
                run.captured.code(),
                run.captured.stderr.trim()
            ),
        );
    };
    let outside_text = outside_id.map_or_else(|| "unknown".to_owned(), |v| v.to_string());
    if outside_id.is_none() || Some(inside_id.to_owned()) == outside_id.map(|v| v.to_string()) {
        return ProbeResult::new(
            name,
            ProbeStatus::Unavailable,
            mechanism,
            "namespace_not_created",
            format!("outside {outside_text}, inside {inside_id}"),
        );
    }
    let mut evidence = format!("outside {outside_text}, inside {inside_id}");
    if kind == "pid" {
        if let Some(nspid) = run.captured.field("nspid") {
            evidence.push_str(&format!("; NSpid {nspid}"));
        }
        if let Some(pids) = run.captured.field("proc_pids") {
            evidence.push_str(&format!("; /proc shows {pids}"));
        }
    }
    ProbeResult::new(name, ProbeStatus::Available, mechanism, "ok", evidence)
}

fn probe_network_namespace(jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    const NAME: &str = "network_namespace";
    const MECHANISM: &str = "network-namespace";
    let run = match run_inside(jail_exe, bwrap, &["status"], Vec::new(), false) {
        Ok(run) => run,
        Err(e) => return ProbeResult::error(NAME, MECHANISM, e.to_string()),
    };
    let Some(devices) = run.captured.field("netdev") else {
        return ProbeResult::error(
            NAME,
            MECHANISM,
            format!("sandbox reported no netdev: {}", run.captured.stderr.trim()),
        );
    };
    if devices == "lo" {
        ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            format!("interfaces inside: {devices}"),
        )
    } else {
        ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "network_visible",
            format!("interfaces inside: {devices}"),
        )
    }
}

fn probe_readonly_bind(jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    const NAME: &str = "mount_readonly_bind";
    const MECHANISM: &str = "bubblewrap-binds";
    let source = match OwnedTempDir::new("probe-ro") {
        Ok(dir) => dir,
        Err(e) => return ProbeResult::error(NAME, MECHANISM, e.to_string()),
    };
    let binds = vec![(source.path.clone(), PathBuf::from("/probe-ro"))];
    let run = match run_inside(
        jail_exe,
        bwrap,
        &["ro=write:/probe-ro/probe.txt"],
        binds,
        false,
    ) {
        Ok(run) => run,
        Err(e) => return ProbeResult::error(NAME, MECHANISM, e.to_string()),
    };
    match run.captured.field("ro") {
        Some("EROFS") => ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            "write into a read-only bind failed EROFS",
        ),
        Some(other) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "bind_not_readonly",
            format!("write into a read-only bind gave {other}"),
        ),
        None => ProbeResult::error(
            NAME,
            MECHANISM,
            format!("sandbox reported nothing: {}", run.captured.stderr.trim()),
        ),
    }
}

fn probe_seccomp(jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    const NAME: &str = "seccomp_filter_load";
    const MECHANISM: &str = "seccomp-bpf";
    let run = match run_inside(
        jail_exe,
        bwrap,
        &[
            "status",
            "afunix=socket-afunix",
            "allowed=write:/tmp/probe.txt",
        ],
        Vec::new(),
        true,
    ) {
        Ok(run) => run,
        Err(e) => return ProbeResult::error(NAME, MECHANISM, e.to_string()),
    };
    let mode = run.captured.field("seccomp").unwrap_or("?");
    let denied = run.captured.field("afunix").unwrap_or("?");
    let allowed = run.captured.field("allowed").unwrap_or("?");
    let digest = seccomp::tool_baseline()
        .map(|p| p.digest())
        .unwrap_or_else(|_| "unavailable".to_owned());
    if mode == "2" && denied == "EPERM" && allowed == "ok" {
        ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            format!(
                "Seccomp mode {mode}, AF_UNIX socket {denied}, allowed write {allowed}, filter {digest}"
            ),
        )
    } else {
        ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "filter_not_enforced",
            format!(
                "Seccomp mode {mode}, AF_UNIX socket {denied}, allowed write {allowed}, filter {digest}"
            ),
        )
    }
}

/// The argv of a second bubblewrap, run inside the first.
///
/// north-star §4.3: "A namespace-creation probe by itself is not evidence of
/// working nesting." So this probe runs a whole inner sandbox, with its own
/// user, pid and mount namespaces and its own root, and asks whether it can
/// run a command — which is what the `agent` profile needs and a bare
/// `unshare` does not establish.
fn nested_bwrap_argv() -> Vec<OsString> {
    let mut argv = vec![
        OsString::from("/usr/bin/bwrap"),
        OsString::from("--unshare-user"),
        OsString::from("--unshare-pid"),
    ];
    for root in bwrap::RUNTIME_ROOTS
        .iter()
        .filter_map(|p| super::fs::resolve_runtime_root(Path::new(p)))
    {
        match root {
            super::fs::RootSpec::RoBind(path) => {
                argv.push(OsString::from("--ro-bind"));
                argv.push(path.as_os_str().to_owned());
                argv.push(path.as_os_str().to_owned());
            }
            super::fs::RootSpec::Symlink { path, target } => {
                argv.push(OsString::from("--symlink"));
                argv.push(target.as_os_str().to_owned());
                argv.push(path.as_os_str().to_owned());
            }
        }
    }
    argv.push(OsString::from("--"));
    argv.push(OsString::from("/usr/bin/true"));
    argv
}

fn probe_nested_userns(jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    const NAME: &str = "nested_user_namespace";
    const MECHANISM: &str = "nested-bubblewrap";
    // Deliberately without the baseline filter: the filter denies `unshare`
    // itself, and this probe must measure the host's policy, not our own.
    let bare = match run_inside(
        jail_exe,
        bwrap,
        &["nested=unshare-userns"],
        Vec::new(),
        false,
    ) {
        Ok(run) => run
            .captured
            .field("nested")
            .unwrap_or("unreported")
            .to_owned(),
        Err(e) => return ProbeResult::error(NAME, MECHANISM, e.to_string()),
    };
    let run = match run_inside_raw(jail_exe, bwrap, nested_bwrap_argv(), Vec::new(), false) {
        Ok(run) => run,
        Err(e) => return ProbeResult::error(NAME, MECHANISM, e.to_string()),
    };
    if run.captured.timed_out {
        return ProbeResult::error(NAME, MECHANISM, "nested sandbox exceeded its deadline");
    }
    let detail = run
        .captured
        .stderr
        .lines()
        .next()
        .unwrap_or("(no diagnostic)")
        .to_owned();
    let bare_note = format!("bare unshare(CLONE_NEWUSER) inside: {bare}");
    if run.captured.code() == Some(0) {
        ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            format!("a nested bubblewrap ran a command; {bare_note}"),
        )
    } else {
        ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "nested_sandbox_denied",
            format!(
                "a nested bubblewrap exited {:?}: {detail}; {bare_note}",
                run.captured.code()
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Probes that need no sandbox
// ---------------------------------------------------------------------------

fn own_pid() -> libc::pid_t {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}

fn probe_ptrace_seize() -> ProbeResult {
    const NAME: &str = "ptrace_seize_descendant";
    const MECHANISM: &str = "ptrace";
    // SAFETY: fork in a process that may be multithreaded; the child below
    // calls only `pause`, which is async-signal-safe, and never returns.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        loop {
            // SAFETY: pause takes no arguments and is async-signal-safe.
            unsafe { libc::pause() };
        }
    }
    if pid < 0 {
        return ProbeResult::error(NAME, MECHANISM, format!("fork: {}", errno_name(last())));
    }

    let result = seize_and_release(pid);
    // SAFETY: `pid` is this process's own child; killing and reaping it is
    // the cleanup this probe owes.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
    }
    match result {
        Ok(evidence) => ProbeResult::new(NAME, ProbeStatus::Available, MECHANISM, "ok", evidence),
        Err(evidence) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "ptrace_denied",
            evidence,
        ),
    }
}

fn seize_and_release(pid: libc::pid_t) -> Result<String, String> {
    const PTRACE_SEIZE: libc::c_uint = 0x4206;
    const PTRACE_INTERRUPT: libc::c_uint = 0x4207;
    // SAFETY: ptrace with PTRACE_SEIZE takes a pid and two scalars; no
    // pointer is dereferenced.
    if unsafe { libc::ptrace(PTRACE_SEIZE, pid, 0, 0) } < 0 {
        return Err(format!("PTRACE_SEIZE: {}", errno_name(last())));
    }
    // SAFETY: as above.
    if unsafe { libc::ptrace(PTRACE_INTERRUPT, pid, 0, 0) } < 0 {
        return Err(format!("PTRACE_INTERRUPT: {}", errno_name(last())));
    }
    let deadline = Deadline::after(PROBE_DEADLINE);
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a live writable int; WNOHANG makes the call
        // return immediately.
        let rc = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG | libc::WUNTRACED) };
        if rc == pid && libc::WIFSTOPPED(status) {
            let signal = libc::WSTOPSIG(status);
            // SAFETY: detaching from a tracee this process seized.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
            return Ok(format!(
                "seized pid {pid}, stopped with signal {signal}, detached"
            ));
        }
        if deadline.expired() {
            return Err(format!("no ptrace-stop within {PROBE_DEADLINE:?}"));
        }
        nap();
    }
}

/// A 200 microsecond pause, used only where the kernel gives no descriptor to
/// wait on. A ptrace-stop is not observable through a pidfd.
fn nap() {
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 200_000,
    };
    // SAFETY: `ts` is a live timespec and the second argument may be null.
    unsafe { libc::nanosleep(&raw const ts, std::ptr::null_mut()) };
}

fn last() -> i32 {
    super::sys::last_errno()
}

fn probe_cgroup_leaf() -> ProbeResult {
    const NAME: &str = "cgroup_delegated_leaf";
    const MECHANISM: &str = "cgroup-v2-delegated";
    // SAFETY: fork; the child calls only `pause`, which is
    // async-signal-safe, and never returns.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        loop {
            // SAFETY: pause takes no arguments and is async-signal-safe.
            unsafe { libc::pause() };
        }
    }
    if pid < 0 {
        return ProbeResult::error(NAME, MECHANISM, format!("fork: {}", errno_name(last())));
    }

    let attempt = cgroup::try_leaf(&format!("ouro-probe-{}.leaf", own_pid()), pid, "pids");
    // SAFETY: `pid` is this process's own child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
    }
    let cleanup = cgroup::remove_leaf(&attempt);

    let mut evidence = format!(
        "own cgroup {}, delegated root {}, common-ancestor rule {}: {}",
        attempt.own_cgroup.as_deref().unwrap_or("unknown"),
        attempt
            .delegated_root
            .as_ref()
            .map_or_else(|| "none".to_owned(), |p| p.display().to_string()),
        if attempt.common_ancestor_ok {
            "permits the move"
        } else {
            "forbids the move"
        },
        attempt.status
    );
    if let Err(e) = cleanup {
        evidence.push_str(&format!("; cleanup failed: {e}"));
    }
    let status = if attempt.moved() {
        ProbeStatus::Available
    } else {
        ProbeStatus::Unavailable
    };
    let reason = if attempt.moved() {
        "ok"
    } else {
        "cgroup_move_refused"
    };
    ProbeResult::new(NAME, status, MECHANISM, reason, evidence)
}

/// Path of the Ubuntu sysctl that restricts unprivileged user namespaces.
pub const APPARMOR_USERNS_SYSCTL: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

fn probe_apparmor() -> ProbeResult {
    const NAME: &str = "apparmor_userns_restriction";
    const MECHANISM: &str = "apparmor";
    match std::fs::read_to_string(APPARMOR_USERNS_SYSCTL) {
        Ok(raw) => {
            let value = raw.trim().to_owned();
            // `available` here means the restriction is in force, which is
            // what the conformance manifest expects on Ubuntu 24.04 and later.
            let status = if value == "0" {
                ProbeStatus::Unavailable
            } else {
                ProbeStatus::Available
            };
            ProbeResult::new(
                NAME,
                status,
                MECHANISM,
                if value == "0" {
                    "restriction_off"
                } else {
                    "restriction_on"
                },
                format!("{APPARMOR_USERNS_SYSCTL} = {value}"),
            )
        }
        Err(e) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "sysctl_absent",
            format!("{APPARMOR_USERNS_SYSCTL}: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// The inside helper
// ---------------------------------------------------------------------------

/// Run the checks named on the command line and print one `label=value` line
/// each. Never returns.
///
/// Each argument is `LABEL=CHECK[:ARGUMENT]`, except the bare word `status`,
/// which prints a fixed set of keys describing the sandbox it finds itself in.
pub fn probe_inside_main(args: &[OsString]) -> ! {
    use std::io::Write as _;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for arg in args {
        let text = arg.to_string_lossy().into_owned();
        if text == "status" {
            write_status(&mut out);
            continue;
        }
        let Some((label, rest)) = text.split_once('=') else {
            let _ = writeln!(out, "error=unparsed_check:{text}");
            continue;
        };
        let (check, argument) = rest.split_once(':').map_or((rest, ""), |(c, a)| (c, a));
        let value = match check {
            "write" => check_write(argument),
            "mkdir" => check_mkdir(argument),
            "stat" => check_stat(argument),
            "listdir" => check_listdir(argument),
            "unshare-userns" => check_unshare_userns(),
            "socket-afunix" => check_socket_afunix(),
            _ => format!("unknown_check:{check}"),
        };
        let _ = writeln!(out, "{label}={value}");
    }
    let _ = out.flush();
    std::process::exit(0);
}

fn write_status(out: &mut impl std::io::Write) {
    let pid = own_pid();
    let ns = ns_ids(pid);
    let _ = writeln!(out, "ns_user={}", option(ns.user));
    let _ = writeln!(out, "ns_pid={}", option(ns.pid));
    let _ = writeln!(out, "ns_net={}", option(ns.net));
    let _ = writeln!(out, "ns_mnt={}", option(ns.mnt));
    let _ = writeln!(
        out,
        "nspid={}",
        super::tracer::nspid(pid).map_or_else(
            || "unknown".to_owned(),
            |v| v
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    );
    for key in ["CapEff", "CapPrm", "NoNewPrivs", "Seccomp"] {
        let value = identity::status_field(pid, key).unwrap_or_else(|_| "unknown".to_owned());
        let _ = writeln!(out, "{}={value}", key.to_lowercase());
    }
    let mut pids: Vec<String> = std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
                .collect()
        })
        .unwrap_or_default();
    pids.sort_by_key(|p| p.parse::<u64>().unwrap_or(u64::MAX));
    let _ = writeln!(out, "proc_pids={}", pids.join(","));

    let mut devices: Vec<String> = std::fs::read_to_string("/proc/net/dev")
        .map(|raw| {
            raw.lines()
                .skip(2)
                .filter_map(|line| line.split(':').next())
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default();
    devices.sort();
    let _ = writeln!(out, "netdev={}", devices.join(","));
    let _ = writeln!(out, "jail_exec={}", access_x(bwrap::JAIL_INSIDE_PATH));
    let _ = writeln!(
        out,
        "cwd={}",
        std::env::current_dir().map_or_else(|_| "unknown".to_owned(), |p| p.display().to_string())
    );
    let mut env: Vec<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    env.sort();
    let _ = writeln!(out, "env_names={}", env.join(","));
}

fn option(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |v| v.to_string())
}

fn access_x(path: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(path) else {
        return false;
    };
    // SAFETY: `c` is a NUL-terminated path that outlives the call.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

fn outcome(rc: i64) -> String {
    if rc >= 0 {
        "ok".to_owned()
    } else {
        errno_name(last()).to_owned()
    }
}

fn check_write(path: &str) -> String {
    let Ok(c) = std::ffi::CString::new(path) else {
        return "invalid_path".to_owned();
    };
    // SAFETY: `c` is a NUL-terminated path that outlives the call; the
    // variadic mode argument is required because O_CREAT is set.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` was just opened by this call and is closed once.
        unsafe { libc::close(fd) };
        return "ok".to_owned();
    }
    errno_name(last()).to_owned()
}

fn check_mkdir(path: &str) -> String {
    let Ok(c) = std::ffi::CString::new(path) else {
        return "invalid_path".to_owned();
    };
    // SAFETY: `c` is a NUL-terminated path that outlives the call.
    outcome(i64::from(unsafe { libc::mkdir(c.as_ptr(), 0o700) }))
}

fn check_stat(path: &str) -> String {
    let Ok(c) = std::ffi::CString::new(path) else {
        return "invalid_path".to_owned();
    };
    let mut st = empty_stat();
    // SAFETY: `c` is NUL-terminated and `st` is a writable stat buffer.
    outcome(i64::from(unsafe { libc::stat(c.as_ptr(), &raw mut st) }))
}

fn check_listdir(path: &str) -> String {
    match std::fs::read_dir(path) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names.join(",")
        }
        Err(e) => errno_name(e.raw_os_error().unwrap_or(libc::EIO)).to_owned(),
    }
}

fn check_unshare_userns() -> String {
    const CLONE_NEWUSER: libc::c_int = 0x1000_0000;
    // SAFETY: unshare takes a flags word and dereferences nothing. On success
    // this process gains a new user namespace, which is fine: it exits
    // immediately afterwards.
    outcome(i64::from(unsafe { libc::unshare(CLONE_NEWUSER) }))
}

fn check_socket_afunix() -> String {
    // SAFETY: socket takes three scalars and dereferences nothing.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        // SAFETY: `fd` was just created by this call and is closed once.
        unsafe { libc::close(fd) };
        return "ok".to_owned();
    }
    errno_name(last()).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_has_a_probe() {
        for name in PROBE_NAMES {
            let result = run_one(name, Path::new("/nonexistent"), Path::new("/nonexistent"));
            assert_eq!(result.name, name, "{name} fell through to the unknown arm");
        }
    }

    #[test]
    fn an_unknown_name_is_skipped_not_available() {
        let result = run_one(
            "no_such_probe",
            Path::new("/bin/true"),
            Path::new("/bin/true"),
        );
        assert_eq!(result.status, ProbeStatus::Skipped);
        assert_eq!(result.reason_code, "unknown_probe");
    }

    #[test]
    fn a_missing_backend_is_unavailable_with_a_reason() {
        let result = probe_bwrap_present(Path::new("/nonexistent/bwrap"));
        assert_eq!(result.status, ProbeStatus::Unavailable);
        assert_eq!(result.reason_code, "backend_unavailable");
    }

    #[test]
    fn statuses_render_as_the_spec_spells_them() {
        assert_eq!(ProbeStatus::Available.to_string(), "available");
        assert_eq!(ProbeStatus::Unavailable.to_string(), "unavailable");
        assert_eq!(ProbeStatus::Unsupported.to_string(), "unsupported");
        assert_eq!(ProbeStatus::Error.to_string(), "error");
        assert_eq!(ProbeStatus::Skipped.to_string(), "skipped");
    }
}
