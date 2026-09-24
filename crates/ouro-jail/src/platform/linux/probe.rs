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

// J3-agent begin: the agent probes
pub mod agent;
// J3-agent end

/// The hidden subcommand the probes run inside the sandbox.
pub const INSIDE_SUBCOMMAND: &str = "__probe-inside";

/// Every probe this implementation knows, in report order.
pub const PROBE_NAMES: [&str; 19] = [
    "bwrap_present",
    "user_namespace",
    "pid_namespace",
    "network_namespace",
    "mount_readonly_bind",
    "seccomp_filter_load",
    "ptrace_seize_descendant",
    "observer_closed_set",
    // J4 autoscope: what this process's own scope step did (§9.3), before
    // the leaf probes that depend on it
    "supervisor_scope",
    "cgroup_delegated_leaf",
    "cgroup_pids",
    "cgroup_memory",
    "cgroup_cpu",
    "apparmor_userns_restriction",
    "nested_user_namespace",
    // J3-agent begin: the unix-peer mediation's kernel mechanism (§10), and
    // the three `agent` rows of §14.1, read from one real agent run
    "seccomp_user_notification",
    "agent_proxy_bridge",
    "agent_unix_peer_mediation",
    "agent_inner_sandbox",
    // J3-agent end
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

/// The backend a probe runs: the resolved bubblewrap (an absolute, canonical
/// path), or why none was resolved (`platform::resolved_bwrap`).
pub type Backend<'a> = Result<&'a Path, &'a str>;

/// Run every probe.
#[must_use]
pub fn run_all(jail_exe: &Path, bwrap: &Path) -> Vec<ProbeResult> {
    PROBE_NAMES
        .iter()
        .map(|name| run_one(name, jail_exe, bwrap))
        .collect()
}

/// Run one probe by name. An unknown name is `skipped`, never a silent pass.
///
/// `bwrap` is executed only when it is absolute; a bare or relative name
/// would be looked up again through `PATH`, so it counts as no backend.
#[must_use]
pub fn run_one(name: &str, jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    let backend = if bwrap.is_absolute() {
        Ok(bwrap)
    } else {
        Err("bubblewrap was named by a relative path, which is never executed")
    };
    run_one_backend(name, jail_exe, backend)
}

/// [`run_one`] with the backend as the platform resolved it.
#[must_use]
pub fn run_one_backend(name: &str, jail_exe: &Path, bwrap: Backend<'_>) -> ProbeResult {
    // J5-D: the test seam can only add an architecture refusal, never lift
    // one; the refusal's evidence names the seam.
    if let Some(refusal) = seam_architecture_refusal(name) {
        return refusal;
    }
    run_one_for(name, std::env::consts::ARCH, jail_exe, bwrap)
}

// J5-D begin: probes that execute bubblewrap (review F1)
/// The probes that execute bubblewrap, with the mechanism each names. With
/// no resolved backend they report `unavailable` with `backend_unavailable`
/// and execute nothing: a bare name would be looked up again, and an empty
/// `PATH` entry would find whatever `bwrap` the working directory holds.
pub const BACKEND_PROBES: [(&str, &str); 10] = [
    ("bwrap_present", "bubblewrap"),
    ("user_namespace", "user-namespace"),
    ("pid_namespace", "pid-namespace"),
    ("network_namespace", "network-namespace"),
    ("mount_readonly_bind", "bubblewrap-binds"),
    ("seccomp_filter_load", "seccomp-bpf"),
    ("nested_user_namespace", "nested-bubblewrap"),
    ("agent_proxy_bridge", "outside-http-proxy+loopback-bridge"),
    ("agent_unix_peer_mediation", "seccomp-user-notification"),
    ("agent_inner_sandbox", "landlock+seccomp"),
];

/// The result of a backend probe when no backend was resolved.
#[must_use]
pub fn backend_refusal(name: &str, bwrap: Backend<'_>) -> Option<ProbeResult> {
    let reason = bwrap.err()?;
    let (name, mechanism) = BACKEND_PROBES.iter().find(|(probe, _)| *probe == name)?;
    Some(ProbeResult::new(
        name,
        ProbeStatus::Unavailable,
        mechanism,
        "backend_unavailable",
        format!("bubblewrap is not available: {reason}"),
    ))
}

/// The architecture test seam (`OURO_JAIL_TEST_ARCH`): a stated architecture
/// the table-bound probes are refused for, as they would be on a build for
/// it. It only ever adds a refusal: on an architecture the tables do not
/// cover, the real refusal applies whatever the seam says.
pub const ARCH_SEAM: &str = "OURO_JAIL_TEST_ARCH";

fn seam_architecture_refusal(name: &str) -> Option<ProbeResult> {
    seam_refusal_for(name, std::env::var(ARCH_SEAM).ok().as_deref())
}

/// [`seam_architecture_refusal`] for a stated seam value. `None` whenever
/// the value is unset, empty or an architecture the tables cover, so the
/// real check that follows it in [`run_one_backend`] always decides.
fn seam_refusal_for(name: &str, seam: Option<&str>) -> Option<ProbeResult> {
    let seam = seam.filter(|value| !value.is_empty())?;
    let mut refusal = architecture_refusal(name, seam)?;
    refusal.evidence = format!("{} (test seam {ARCH_SEAM}={seam})", refusal.evidence);
    Some(refusal)
}
// J5-D end

// J5-D begin: the architecture refusal (§3.2)
/// The probes whose mechanism is one of this implementation's x86_64
/// syscall tables, with the mechanism each one names: the `tool` and `agent`
/// filters, the observer's closed set and narrowing filter, and the
/// unix-peer mediation filter the `agent` rows run under.
pub const TABLE_BOUND_PROBES: [(&str, &str); 6] = [
    ("seccomp_filter_load", "seccomp-bpf"),
    ("observer_closed_set", "ptrace-seccomp"),
    ("seccomp_user_notification", "seccomp-user-notification"),
    ("agent_proxy_bridge", "outside-http-proxy+loopback-bridge"),
    ("agent_unix_peer_mediation", "seccomp-user-notification"),
    ("agent_inner_sandbox", "landlock+seccomp"),
];

/// The result a table-bound probe has on an architecture the tables do not
/// cover: `unsupported` (the implementation lacks it, §3.1), measured by
/// nothing. `None` when the probe runs as usual.
#[must_use]
pub fn architecture_refusal(name: &str, arch: &str) -> Option<ProbeResult> {
    if seccomp::tables_cover(arch) {
        return None;
    }
    let (name, mechanism) = TABLE_BOUND_PROBES
        .iter()
        .find(|(bound, _)| *bound == name)?;
    Some(ProbeResult::new(
        name,
        ProbeStatus::Unsupported,
        mechanism,
        seccomp::REASON_UNSUPPORTED_ARCHITECTURE,
        format!(
            "this build is for {arch}; the syscall tables this mechanism rests on are {} only \
             (Linux {arch} is a later lane, jail-v1 §3.2)",
            seccomp::TABLE_ARCH
        ),
    ))
}

/// [`run_one`] for a stated architecture, so the refusal is testable on the
/// architecture the tests run on.
#[must_use]
pub fn run_one_for(name: &str, arch: &str, jail_exe: &Path, bwrap: Backend<'_>) -> ProbeResult {
    if let Some(refusal) = architecture_refusal(name, arch) {
        return refusal;
    }
    if let Some(refusal) = backend_refusal(name, bwrap) {
        return refusal;
    }
    // Every probe that uses `bwrap` is in BACKEND_PROBES, so from here on it
    // is the resolved path whenever one of them reads it.
    let bwrap = bwrap.unwrap_or(Path::new("/nonexistent/unresolved-bwrap"));
    match name {
        "bwrap_present" => probe_bwrap_present(bwrap),
        "user_namespace" => probe_namespace("user_namespace", jail_exe, bwrap),
        "pid_namespace" => probe_namespace("pid_namespace", jail_exe, bwrap),
        "network_namespace" => probe_network_namespace(jail_exe, bwrap),
        "mount_readonly_bind" => probe_readonly_bind(jail_exe, bwrap),
        "seccomp_filter_load" => probe_seccomp(jail_exe, bwrap),
        "ptrace_seize_descendant" => probe_ptrace_seize(),
        "observer_closed_set" => probe_observer(jail_exe),
        "supervisor_scope" => probe_supervisor_scope(),
        "cgroup_delegated_leaf" => probe_cgroup_leaf("cgroup_delegated_leaf", None),
        "cgroup_pids" => probe_cgroup_leaf("cgroup_pids", Some("pids")),
        "cgroup_memory" => probe_cgroup_leaf("cgroup_memory", Some("mem")),
        "cgroup_cpu" => probe_cgroup_leaf("cgroup_cpu", Some("cpu")),
        "apparmor_userns_restriction" => probe_apparmor(),
        "nested_user_namespace" => probe_nested_userns(jail_exe, bwrap),
        // J3-agent begin
        "seccomp_user_notification" => probe_user_notification(),
        "agent_proxy_bridge" => agent::proxy_bridge(jail_exe),
        "agent_unix_peer_mediation" => agent::unix_peer(jail_exe),
        "agent_inner_sandbox" => agent::inner_sandbox(jail_exe),
        // J3-agent end
        _ => ProbeResult::new(
            "unknown",
            ProbeStatus::Skipped,
            "none",
            "unknown_probe",
            format!("no probe named {name}"),
        ),
    }
}
// J5-D end

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
        // Explicit mode: `create_dir` applies the umask, and on a host with
        // umask 002 that leaves a probe's directory group-writable in a
        // directory everyone shares.
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
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
fn nested_bwrap_argv(bwrap: &Path) -> Vec<OsString> {
    // J5-D: the same resolved file, as the sandbox sees it through the
    // read-only runtime roots (review F1: nothing but it runs).
    let mut argv = vec![
        bwrap.as_os_str().to_owned(),
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
    let run = match run_inside_raw(jail_exe, bwrap, nested_bwrap_argv(bwrap), Vec::new(), false) {
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

// J3-agent begin: the mediation's own mechanism, measured
/// `seccomp_user_notification`: an unprivileged child installs the agent's
/// mediation filter with its own notification listener, and this process
/// takes that listener from it with `pidfd_getfd` — the two steps the
/// `agent` launcher and supervisor perform (§10). Whether a connect is then
/// mediated is the agent probes' and the conformance suite's question.
fn probe_user_notification() -> ProbeResult {
    const NAME: &str = "seccomp_user_notification";
    const MECHANISM: &str = "seccomp-user-notification";
    // Built before the fork: the child only makes syscalls.
    let program = super::unixpeer::mediation_program();
    let mut pipe = [0i32; 2];
    // SAFETY: `pipe` is a two-element array; pipe2 writes two fds or fails.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return ProbeResult::error(NAME, MECHANISM, format!("pipe2: {}", errno_name(last())));
    }
    let parent = own_pid();
    // SAFETY: fork; the child calls only async-signal-safe functions
    // (prctl, getppid, seccomp, write, pause, _exit) over data built before
    // the fork.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: as above; `program` is live and never freed in the child.
        unsafe {
            exec::die_with_parent_after_fork(parent);
            libc::close(pipe[0]);
            let listener =
                super::unixpeer::install_program(&program, super::unixpeer::FLAG_NEW_LISTENER)
                    .map_or(-1, std::os::fd::IntoRawFd::into_raw_fd);
            let report = listener.to_le_bytes();
            libc::write(pipe[1], report.as_ptr().cast(), report.len());
            loop {
                libc::pause();
            }
        }
    }
    // SAFETY: closing this process's copy of the write end.
    unsafe { libc::close(pipe[1]) };
    if pid < 0 {
        // SAFETY: the read end is still owned here.
        unsafe { libc::close(pipe[0]) };
        return ProbeResult::error(NAME, MECHANISM, format!("fork: {}", errno_name(last())));
    }
    let mut report = [0u8; 4];
    let mut got = 0usize;
    let deadline = Deadline::after(PROBE_DEADLINE);
    while got < report.len() && !deadline.expired() {
        let mut pfd = libc::pollfd {
            fd: pipe[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, bounded by the deadline.
        if unsafe { libc::poll(&raw mut pfd, 1, deadline.remaining_millis_capped(100)) } <= 0 {
            continue;
        }
        // SAFETY: the buffer is live and the length matches.
        let n = unsafe {
            libc::read(
                pipe[0],
                report[got..].as_mut_ptr().cast(),
                report.len() - got,
            )
        };
        if n <= 0 {
            break;
        }
        got += usize::try_from(n).unwrap_or(0);
    }
    let listener = (got == report.len()).then(|| i32::from_le_bytes(report));
    let taken = match (listener, identity::pidfd_open(pid)) {
        (Some(fd), Ok(pidfd)) if fd >= 0 => {
            super::unixpeer::pidfd_getfd(std::os::fd::AsFd::as_fd(&pidfd), fd).map(|_| fd)
        }
        (Some(_), _) | (None, _) => Err(io::Error::from_raw_os_error(libc::ENOSYS)),
    };
    // SAFETY: `pid` is this process's own child; killing and reaping it is
    // the cleanup this probe owes, and the read end is closed once.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
        libc::close(pipe[0]);
    }
    match (listener, taken) {
        (Some(fd), Ok(_)) if fd >= 0 => ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            format!(
                "an unprivileged child installed the mediation filter ({}) with a listener, \
                 and pidfd_getfd took it",
                super::unixpeer::filter_digest()
            ),
        ),
        (Some(fd), _) if fd < 0 => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "listener_refused",
            "seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER) failed in an unprivileged child",
        ),
        (Some(_), Err(error)) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "listener_not_transferable",
            format!("pidfd_getfd of the child's listener failed: {error}"),
        ),
        _ => ProbeResult::error(NAME, MECHANISM, "the child reported nothing"),
    }
}
// J3-agent end

fn own_pid() -> libc::pid_t {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}

fn probe_ptrace_seize() -> ProbeResult {
    const NAME: &str = "ptrace_seize_descendant";
    const MECHANISM: &str = "ptrace";
    let parent = own_pid();
    // SAFETY: fork in a process that may be multithreaded; the child below
    // calls only prctl, getppid and `pause`, which are async-signal-safe, and
    // never returns.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: first call in the forked child; `parent` was read before
        // the fork. The probe must not leave a fixture on doctor death.
        unsafe { exec::die_with_parent_after_fork(parent) };
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

// J4 autoscope begin
/// The supervisor scope step's record (§9.3), as a row: `available` when
/// this process is inside the delegated subtree (`already_delegated` or
/// `entered`), `unavailable` with the step's reason otherwise. It runs
/// nothing: the step ran once, before anything else, and this reports it.
fn probe_supervisor_scope() -> ProbeResult {
    const NAME: &str = "supervisor_scope";
    const MECHANISM: &str = "systemd-user-transient-scope";
    let outcome = super::scope::current();
    let (status, reason_code) = match (outcome.state, outcome.reason) {
        (super::scope::State::Unavailable, reason) => (
            ProbeStatus::Unavailable,
            reason.map_or("unavailable", super::scope::Reason::code),
        ),
        (state, _) => (ProbeStatus::Available, state.as_str()),
    };
    ProbeResult::new(NAME, status, MECHANISM, reason_code, outcome.summary())
}
// J4 autoscope end

fn probe_cgroup_leaf(name: &'static str, controller: Option<&str>) -> ProbeResult {
    const MECHANISM: &str = "cgroup-v2-delegated";
    let mut limits = crate::policy::LimitsSnapshot {
        wall: None,
        pids: None,
        mem: None,
        cpu: None,
    };
    let ceiling = |value: &str| {
        Some(crate::policy::LimitCeiling {
            value: value.to_owned(),
            required: true,
        })
    };
    match controller {
        Some("pids") => limits.pids = ceiling("16"),
        Some("mem") => limits.mem = ceiling("67108864"),
        Some("cpu") => limits.cpu = ceiling("100"),
        _ => {}
    }
    let mut leaf = match cgroup::ExecutionCgroup::create(&limits) {
        Ok(leaf) => leaf,
        Err(err) => {
            return ProbeResult::new(
                name,
                ProbeStatus::Unavailable,
                MECHANISM,
                "cgroup_unavailable",
                err.to_string(),
            );
        }
    };
    let parent = own_pid();
    // SAFETY: fork; the child calls only prctl, getppid and `pause`, which
    // are async-signal-safe, and never returns.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: first call in the forked child; `parent` was read before
        // the fork. The probe must not leave a fixture on doctor death.
        unsafe { exec::die_with_parent_after_fork(parent) };
        loop {
            // SAFETY: pause takes no arguments and is async-signal-safe.
            unsafe { libc::pause() };
        }
    }
    if pid < 0 {
        return ProbeResult::error(name, MECHANISM, format!("fork: {}", errno_name(last())));
    }

    let deadline = Deadline::after(PROBE_DEADLINE);
    let measured = (|| -> io::Result<()> {
        leaf.place(pid)?;
        if !leaf.populated()? {
            return Err(io::Error::other("placement was not populated"));
        }
        leaf.kill()?;
        while leaf.populated()? {
            if deadline.expired() {
                return Err(io::Error::other("cgroup.kill exceeded probe deadline"));
            }
            nap();
        }
        Ok(())
    })();
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if rc == pid || rc < 0 {
            break;
        }
        if deadline.expired() {
            return ProbeResult::error(name, MECHANISM, "probe child could not be reaped");
        }
        nap();
    }
    match measured.and_then(|()| leaf.remove()) {
        Ok(()) => ProbeResult::new(
            name,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            "created pinned leaf, configured/read back ceiling, placed fixture, cgroup.kill, populated=0, reaped and removed",
        ),
        Err(err) => ProbeResult::new(
            name,
            ProbeStatus::Unavailable,
            MECHANISM,
            "cgroup_probe_failed",
            err.to_string(),
        ),
    }
}

fn probe_observer(jail_exe: &Path) -> ProbeResult {
    use super::tracer::{ClosedOp, Tracer, TracerConfig, TracerEvent};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::process::Stdio;
    const NAME: &str = "observer_closed_set";
    let deadline = Deadline::after(PROBE_DEADLINE);
    let measured = (|| -> io::Result<()> {
        let temp = OwnedTempDir::new("observer-probe")?;
        let target = temp.path.join("created");
        let (release_r, release_w) = exec::pipe()?;
        let (_error_r, error_w) = exec::pipe()?;
        let mut fds = FdMap::new();
        fds.add(release_r, 12)?;
        fds.add(error_w, 13)?;
        let mut command = Command::new(jail_exe);
        command
            .args([
                "__launch",
                "--release-fd",
                "12",
                "--error-fd",
                "13",
                "--narrow",
                "--",
            ])
            .arg(jail_exe)
            .arg(INSIDE_SUBCOMMAND)
            .arg(format!("create=write:{}", target.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        fds.apply(&mut command);
        let mut child = command.spawn()?;
        drop(fds);
        let pid = child.id() as i32;
        let pidfd = match identity::pidfd_open(pid) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = child.kill();
                exec::reap_until(&mut child, deadline);
                return Err(error);
            }
        };
        let measured = (|| -> io::Result<()> {
            loop {
                let syscall = std::fs::read_to_string(format!("/proc/{pid}/syscall"))?;
                if syscall
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<i64>().ok())
                    == Some(libc::SYS_read)
                {
                    break;
                }
                if deadline.expired() {
                    return Err(io::Error::other("observer launcher did not block"));
                }
                nap();
            }
            let tracer = Tracer::attach(pid, TracerConfig::default()).map_err(io::Error::other)?;
            std::fs::File::from(release_w).write_all(&[1])?;
            let mut matched = 0;
            let mut exited = false;
            let mut observe =
                |event: TracerEvent| match event {
                    TracerEvent::Syscall {
                        op: ClosedOp::Open,
                        args,
                        ret,
                        ..
                    } if args.path.as_ref().is_some_and(|path| {
                        path.bytes == target.as_os_str().as_encoded_bytes()
                    }) && ret >= 0 =>
                    {
                        matched += 1
                    }
                    TracerEvent::Exit { pid: seen, .. } if seen == pid => exited = true,
                    _ => {}
                };
            while !deadline.expired() {
                match tracer.events().recv_timeout(Duration::from_millis(10)) {
                    Ok(TracerEvent::Finished) => break,
                    Ok(event) => observe(event),
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(_) => {}
                }
            }
            let summary = tracer.finish_within_draining(deadline.remaining(), observe);
            if matched != 1 || !exited || summary.loss.total() != 0 || !target.exists() {
                return Err(io::Error::other(
                    "observer did not pair the fixture result without loss",
                ));
            }
            Ok(())
        })();
        // The tracer normally reaps it; if attachment failed, clean it here.
        let _ = identity::pidfd_send_signal(pidfd.as_raw_fd(), libc::SIGKILL);
        exec::reap_until(&mut child, deadline);
        measured
    })();
    match measured {
        Ok(()) => ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            "ptrace-seccomp",
            "ok",
            "attached blocked launcher; one successful create matched the fixture, final exit observed, zero loss",
        ),
        Err(err) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            "ptrace-seccomp",
            "observer_probe_failed",
            err.to_string(),
        ),
    }
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
            // J3-agent begin: the agent probe's inside checks
            "http" => agent::check_http(argument),
            "tcp" => agent::check_tcp(argument),
            "unix" => agent::check_unix(argument),
            "unix-self" => agent::check_unix_self(argument),
            "inner" => agent::check_inner(argument),
            // J3-agent end
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

    // J4 autoscope begin
    #[test]
    fn the_scope_row_never_claims_a_step_that_did_not_run() {
        // No test in this binary runs the step, so the row reports the
        // process as it is, unavailable, whatever its cgroup.
        let result = run_one(
            "supervisor_scope",
            Path::new("/nonexistent"),
            Path::new("/nonexistent"),
        );
        assert_eq!(result.status, ProbeStatus::Unavailable, "{result:?}");
        assert_eq!(result.reason_code, "not_attempted");
        assert!(result.evidence.starts_with("unavailable"), "{result:?}");
    }
    // J4 autoscope end

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

    // J5-D begin: the architecture refusal (§3.2; gap analysis §2.3b)
    /// The rows whose mechanism is one of this implementation's x86_64
    /// syscall tables. Written out, so a probe that drops out of the refusal
    /// is a failing test, not a silent change.
    const TABLE_BOUND: [&str; 6] = [
        "seccomp_filter_load",
        "observer_closed_set",
        "seccomp_user_notification",
        "agent_proxy_bridge",
        "agent_unix_peer_mediation",
        "agent_inner_sandbox",
    ];

    #[test]
    fn off_x86_64_the_table_bound_probes_are_unsupported_before_running() {
        for arch in ["aarch64", "riscv64", "x86", "powerpc64"] {
            for name in PROBE_NAMES {
                let Some(refusal) = architecture_refusal(name, arch) else {
                    assert!(
                        !TABLE_BOUND.contains(&name),
                        "{arch}: {name} rests on a syscall table and was not refused"
                    );
                    continue;
                };
                assert!(TABLE_BOUND.contains(&name), "{arch}: {name} was refused");
                assert_eq!(refusal.name, name);
                assert_eq!(refusal.status, ProbeStatus::Unsupported, "{arch} {name}");
                assert_eq!(refusal.reason_code, "unsupported_architecture");
                assert!(refusal.evidence.contains(arch), "{refusal:?}");
                // `run_one` consults the refusal before it runs anything:
                // these paths do not exist, so a probe that ran would say
                // `error` or `unavailable`, never `unsupported`.
                assert_eq!(
                    run_one_for(
                        name,
                        arch,
                        Path::new("/nonexistent"),
                        Ok(Path::new("/nonexistent"))
                    ),
                    refusal
                );
            }
        }
        // On the architecture the tables cover, nothing is refused.
        for name in PROBE_NAMES {
            assert_eq!(architecture_refusal(name, "x86_64"), None, "{name}");
        }
    }

    #[test]
    fn the_arch_seam_only_adds_a_refusal_and_names_itself() {
        for (name, _) in TABLE_BOUND_PROBES {
            for seam in [None, Some(""), Some("x86_64")] {
                assert_eq!(seam_refusal_for(name, seam), None, "{name} {seam:?}");
            }
            let refusal = seam_refusal_for(name, Some("aarch64")).expect("refused");
            assert_eq!(refusal.status, ProbeStatus::Unsupported);
            assert!(refusal.evidence.contains("OURO_JAIL_TEST_ARCH=aarch64"));
        }
        assert_eq!(seam_refusal_for("bwrap_present", Some("aarch64")), None);
    }

    /// The capability mapping: on a build the tables do not cover, the
    /// syscall filter and the closed-set observer derive `unsupported` with
    /// the architecture's reason, which no requirement accepts, so `doctor`
    /// is not ready and `run` refuses with 125 before preparation.
    #[test]
    fn off_x86_64_the_filter_and_observer_capabilities_refuse() {
        use crate::capability::{CapabilityScope, CapabilityStatus};
        // Every other probe as if it had succeeded, so the refusal is the
        // architecture's alone.
        let results: Vec<ProbeResult> = PROBE_NAMES
            .iter()
            .map(|name| {
                architecture_refusal(name, "aarch64").unwrap_or_else(|| {
                    ProbeResult::new(name, ProbeStatus::Available, "test", "ok", "")
                })
            })
            .collect();
        for (requirement, probes, scope) in [
            (
                crate::capability::REQ_SYSCALL_FILTER,
                &["seccomp_filter_load"][..],
                CapabilityScope::Process,
            ),
            (
                crate::capability::REQ_CLOSED_SET_OBSERVATION,
                &["ptrace_seize_descendant", "observer_closed_set"][..],
                CapabilityScope::Tree,
            ),
            (
                crate::capability::REQ_NETWORK_PROXY,
                &[
                    "bwrap_present",
                    "network_namespace",
                    "seccomp_user_notification",
                ][..],
                CapabilityScope::Tree,
            ),
        ] {
            let capability = super::super::platform::shared::capability_from(
                requirement,
                probes,
                "test",
                scope,
                &results,
                "2026-09-24T00:00:00Z",
            );
            assert_eq!(
                capability.status,
                CapabilityStatus::Unsupported,
                "{requirement}"
            );
            assert_eq!(
                capability.reason_code.as_deref(),
                Some("unsupported_architecture"),
                "{requirement}"
            );
            assert!(!capability.satisfies(), "{requirement}");
        }
    }
    // J5-D end

    #[test]
    fn statuses_render_as_the_spec_spells_them() {
        assert_eq!(ProbeStatus::Available.to_string(), "available");
        assert_eq!(ProbeStatus::Unavailable.to_string(), "unavailable");
        assert_eq!(ProbeStatus::Unsupported.to_string(), "unsupported");
        assert_eq!(ProbeStatus::Error.to_string(), "error");
        assert_eq!(ProbeStatus::Skipped.to_string(), "skipped");
    }
}
