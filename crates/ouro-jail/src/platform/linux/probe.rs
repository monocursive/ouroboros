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
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::bwrap::{self, BwrapPlan};
use super::cgroup;
use super::clock::Deadline;
use super::exec::{self, Captured, FdMap};
use super::identity::{self, NsIds, ns_ids};
use super::seccomp;
use super::sys::{errno_name, last_errno, nap};

pub(crate) mod agent;

/// The hidden subcommand the probes run inside the sandbox.
pub const INSIDE_SUBCOMMAND: &str = "__probe-inside";

/// One doctor probe (jail-v1 §14.1). Its name, the mechanism it exercises,
/// whether it executes bubblewrap and whether it rests on a native syscall
/// table are all here, so a probe cannot be listed in one place and missing
/// from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    BwrapPresent,
    UserNamespace,
    PidNamespace,
    NetworkNamespace,
    MountReadonlyBind,
    SeccompFilterLoad,
    PtraceSeizeDescendant,
    ObserverClosedSet,
    /// What this process's own scope step did (§9.3), before the leaf probes
    /// that depend on it.
    SupervisorScope,
    CgroupDelegatedLeaf,
    CgroupPids,
    CgroupMemory,
    CgroupSwap,
    CgroupCpu,
    /// The §6.4 storage ceilings: the host prerequisite a `--limit
    /// storage`/`--limit inodes` run refuses without, measured the way
    /// admission measures a writable mount.
    StorageCeiling,
    ApparmorUsernsRestriction,
    NestedUserNamespace,
    /// The unix-peer mediation's kernel mechanism (§10).
    SeccompUserNotification,
    UnixSocketDiagnostics,
    /// The three `agent` rows of §14.1, read from one real agent run.
    AgentProxyBridge,
    AgentUnixPeerMediation,
    AgentInnerSandbox,
    /// Issue draft 15: whether a GPU can be passed through to a contained
    /// profile (informational; no requirement demands it).
    GpuPassthrough,
}

impl Probe {
    /// Every probe, in report order.
    pub const ALL: [Probe; 23] = [
        Probe::BwrapPresent,
        Probe::UserNamespace,
        Probe::PidNamespace,
        Probe::NetworkNamespace,
        Probe::MountReadonlyBind,
        Probe::SeccompFilterLoad,
        Probe::PtraceSeizeDescendant,
        Probe::ObserverClosedSet,
        Probe::SupervisorScope,
        Probe::CgroupDelegatedLeaf,
        Probe::CgroupPids,
        Probe::CgroupMemory,
        Probe::CgroupSwap,
        Probe::CgroupCpu,
        Probe::StorageCeiling,
        Probe::ApparmorUsernsRestriction,
        Probe::NestedUserNamespace,
        Probe::SeccompUserNotification,
        Probe::UnixSocketDiagnostics,
        Probe::AgentProxyBridge,
        Probe::AgentUnixPeerMediation,
        Probe::AgentInnerSandbox,
        Probe::GpuPassthrough,
    ];

    /// The probe's name in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Probe::BwrapPresent => "bwrap_present",
            Probe::UserNamespace => "user_namespace",
            Probe::PidNamespace => "pid_namespace",
            Probe::NetworkNamespace => "network_namespace",
            Probe::MountReadonlyBind => "mount_readonly_bind",
            Probe::SeccompFilterLoad => "seccomp_filter_load",
            Probe::PtraceSeizeDescendant => "ptrace_seize_descendant",
            Probe::ObserverClosedSet => "observer_closed_set",
            Probe::SupervisorScope => "supervisor_scope",
            Probe::CgroupDelegatedLeaf => "cgroup_delegated_leaf",
            Probe::CgroupPids => "cgroup_pids",
            Probe::CgroupMemory => "cgroup_memory",
            Probe::CgroupSwap => "cgroup_swap",
            Probe::CgroupCpu => "cgroup_cpu",
            Probe::StorageCeiling => "storage_ceiling",
            Probe::ApparmorUsernsRestriction => "apparmor_userns_restriction",
            Probe::NestedUserNamespace => "nested_user_namespace",
            Probe::SeccompUserNotification => "seccomp_user_notification",
            Probe::UnixSocketDiagnostics => "unix_socket_diagnostics",
            Probe::AgentProxyBridge => "agent_proxy_bridge",
            Probe::AgentUnixPeerMediation => "agent_unix_peer_mediation",
            Probe::AgentInnerSandbox => "agent_inner_sandbox",
            Probe::GpuPassthrough => "gpu_passthrough",
        }
    }

    /// The mechanism the probe exercises, as every result of it names it.
    #[must_use]
    pub const fn mechanism(self) -> &'static str {
        match self {
            Probe::BwrapPresent => "bubblewrap",
            Probe::UserNamespace => "user-namespace",
            Probe::PidNamespace => "pid-namespace",
            Probe::NetworkNamespace => "network-namespace",
            Probe::MountReadonlyBind => "bubblewrap-binds",
            Probe::SeccompFilterLoad => "seccomp-bpf",
            Probe::PtraceSeizeDescendant => "ptrace",
            Probe::ObserverClosedSet => "ptrace-seccomp",
            Probe::SupervisorScope => "systemd-user-transient-scope",
            Probe::CgroupDelegatedLeaf
            | Probe::CgroupPids
            | Probe::CgroupMemory
            | Probe::CgroupSwap
            | Probe::CgroupCpu => "cgroup-v2-delegated",
            Probe::StorageCeiling => "bounded-tmpfs-or-user-quota",
            Probe::ApparmorUsernsRestriction => "apparmor",
            Probe::NestedUserNamespace => "nested-bubblewrap",
            Probe::SeccompUserNotification | Probe::AgentUnixPeerMediation => {
                "seccomp-user-notification"
            }
            Probe::UnixSocketDiagnostics => "netlink-sock-diag",
            Probe::AgentProxyBridge => "outside-http-proxy+loopback-bridge",
            Probe::AgentInnerSandbox => "landlock+seccomp",
            Probe::GpuPassthrough => "devices",
        }
    }

    /// Whether the probe executes bubblewrap (review F1). With no resolved
    /// backend it reports `unavailable` with `backend_unavailable` and
    /// executes nothing: a bare name would be looked up again, and an empty
    /// `PATH` entry would find whatever `bwrap` the working directory holds.
    #[must_use]
    pub const fn needs_backend(self) -> bool {
        matches!(
            self,
            Probe::BwrapPresent
                | Probe::UserNamespace
                | Probe::PidNamespace
                | Probe::NetworkNamespace
                | Probe::MountReadonlyBind
                | Probe::SeccompFilterLoad
                | Probe::NestedUserNamespace
                | Probe::AgentProxyBridge
                | Probe::AgentUnixPeerMediation
                | Probe::AgentInnerSandbox
        )
    }

    /// Whether the probe's mechanism is one of this implementation's native
    /// syscall tables (§3.2): the `tool` and `agent` filters, the observer's
    /// closed set and narrowing filter, and the unix-peer mediation filter
    /// the `agent` rows run under.
    #[must_use]
    pub const fn table_bound(self) -> bool {
        matches!(
            self,
            Probe::SeccompFilterLoad
                | Probe::ObserverClosedSet
                | Probe::SeccompUserNotification
                | Probe::AgentProxyBridge
                | Probe::AgentUnixPeerMediation
                | Probe::AgentInnerSandbox
        )
    }

    /// The probe named `name`, if this implementation has one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Probe> {
        Probe::ALL.into_iter().find(|probe| probe.name() == name)
    }

    /// Runs the probe. `bwrap` is the resolved backend; only the probes that
    /// [need one](Probe::needs_backend) read it.
    fn run(self, jail_exe: &Path, bwrap: &Path) -> ProbeResult {
        match self {
            Probe::BwrapPresent => probe_bwrap_present(bwrap),
            Probe::UserNamespace | Probe::PidNamespace => probe_namespace(self, jail_exe, bwrap),
            Probe::NetworkNamespace => probe_network_namespace(jail_exe, bwrap),
            Probe::MountReadonlyBind => probe_readonly_bind(jail_exe, bwrap),
            Probe::SeccompFilterLoad => probe_seccomp(jail_exe, bwrap),
            Probe::PtraceSeizeDescendant => probe_ptrace_seize(),
            Probe::ObserverClosedSet => probe_observer(jail_exe),
            Probe::SupervisorScope => probe_supervisor_scope(),
            Probe::CgroupDelegatedLeaf => probe_cgroup_leaf(self, None),
            Probe::CgroupPids => probe_cgroup_leaf(self, Some("pids")),
            Probe::CgroupMemory => probe_cgroup_leaf(self, Some("mem")),
            Probe::CgroupSwap => probe_cgroup_leaf(self, Some("swap")),
            Probe::CgroupCpu => probe_cgroup_leaf(self, Some("cpu")),
            Probe::StorageCeiling => probe_storage_ceiling(),
            Probe::ApparmorUsernsRestriction => probe_apparmor(),
            Probe::NestedUserNamespace => probe_nested_userns(jail_exe, bwrap),
            Probe::SeccompUserNotification => probe_user_notification(),
            Probe::UnixSocketDiagnostics => probe_unix_socket_diagnostics(),
            Probe::AgentProxyBridge => agent::proxy_bridge(jail_exe),
            Probe::AgentUnixPeerMediation => agent::unix_peer(jail_exe),
            Probe::AgentInnerSandbox => agent::inner_sandbox(jail_exe),
            Probe::GpuPassthrough => probe_gpu_passthrough(),
        }
    }
}

/// Every probe's name, in report order.
pub const PROBE_NAMES: [&str; Probe::ALL.len()] = {
    let mut names = [""; Probe::ALL.len()];
    let mut i = 0;
    while i < names.len() {
        names[i] = Probe::ALL[i].name();
        i += 1;
    }
    names
};

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
    // The test seam can only add an architecture refusal, never lift one;
    // the refusal's evidence names the seam.
    if let Some(refusal) = seam_architecture_refusal(name) {
        return refusal;
    }
    run_one_for(name, std::env::consts::ARCH, jail_exe, bwrap)
}

/// Fresh probes for one preparation. Namespace, read-only bind and baseline
/// filter checks share a successful sandbox without changing any validator.
/// No result survives this call; refusals and deadlines still apply per run.
#[must_use]
pub fn run_selected(names: &[&str], jail_exe: &Path, bwrap: Backend<'_>) -> Vec<ProbeResult> {
    let shared_check = |name: &str| {
        matches!(
            Probe::from_name(name),
            Some(
                Probe::UserNamespace
                    | Probe::PidNamespace
                    | Probe::NetworkNamespace
                    | Probe::MountReadonlyBind
            )
        )
    };
    // A working baseline filter leaves each namespace and EROFS check intact.
    // Only use the combined answer when every requested validator succeeds;
    // otherwise retain the unfiltered/individual probes below so a failed
    // filter or bind does not turn another host capability into a guess.
    let filtered = if names.contains(&"seccomp_filter_load")
        && names.iter().any(|name| shared_check(name))
        && seam_architecture_refusal("seccomp_filter_load").is_none()
        && architecture_refusal("seccomp_filter_load", std::env::consts::ARCH).is_none()
    {
        bwrap
            .ok()
            .filter(|path| path.is_absolute())
            .and_then(|path| {
                let outside = ns_ids(own_pid());
                let run =
                    run_status_checks(jail_exe, path, names.contains(&"mount_readonly_bind"), true)
                        .ok()?;
                let results: Vec<_> = names
                    .iter()
                    .filter_map(|name| match Probe::from_name(name)? {
                        probe @ (Probe::UserNamespace | Probe::PidNamespace) => Some(
                            namespace_result(probe, namespace_id(probe, &outside), &run.captured),
                        ),
                        Probe::NetworkNamespace => Some(network_namespace_result(&run.captured)),
                        Probe::MountReadonlyBind => Some(readonly_bind_result(&run.captured)),
                        Probe::SeccompFilterLoad => Some(seccomp_result(&run.captured)),
                        _ => None,
                    })
                    .collect();
                results
                    .iter()
                    .all(|result| result.status == ProbeStatus::Available)
                    .then_some(results)
            })
    } else {
        None
    };
    // Keep failed RO setup independent of namespace capability results.
    // The fallback shares only the original namespace status sandbox;
    // read-only and filter probes retain their individual setup paths.
    let namespace = |name: &str| {
        matches!(
            Probe::from_name(name),
            Some(Probe::UserNamespace | Probe::PidNamespace | Probe::NetworkNamespace)
        )
    };
    let shared = if filtered.is_none() && names.iter().filter(|name| namespace(name)).count() > 1 {
        bwrap.ok().filter(|path| path.is_absolute()).map(|path| {
            let outside = ns_ids(own_pid());
            (
                outside,
                run_inside(jail_exe, path, &["status"], Vec::new(), false),
            )
        })
    } else {
        None
    };
    names
        .iter()
        .map(|name| {
            if let Some(result) = filtered
                .as_ref()
                .and_then(|results| results.iter().find(|result| result.name == *name))
            {
                return result.clone();
            }
            if let Some((outside, run)) = &shared
                && let Some(probe) = Probe::from_name(name)
            {
                let result = match (probe, run) {
                    (Probe::UserNamespace | Probe::PidNamespace, Ok(run)) => Some(
                        namespace_result(probe, namespace_id(probe, outside), &run.captured),
                    ),
                    (Probe::NetworkNamespace, Ok(run)) => {
                        Some(network_namespace_result(&run.captured))
                    }
                    (
                        Probe::UserNamespace | Probe::PidNamespace | Probe::NetworkNamespace,
                        Err(error),
                    ) => Some(ProbeResult::error(
                        probe.name(),
                        probe.mechanism(),
                        error.to_string(),
                    )),
                    _ => None,
                };
                if let Some(result) = result {
                    return result;
                }
            }
            run_one_backend(name, jail_exe, bwrap)
        })
        .collect()
}

fn run_status_checks(
    jail_exe: &Path,
    bwrap: &Path,
    readonly: bool,
    with_seccomp: bool,
) -> io::Result<SandboxRun> {
    let source = readonly
        .then(|| OwnedTempDir::new("probe-ro"))
        .transpose()?;
    let mut checks = vec!["status"];
    let mut binds = Vec::new();
    if let Some(source) = &source {
        checks.push("ro=write:/probe-ro/probe.txt");
        binds.push((source.path.clone(), PathBuf::from("/probe-ro")));
    }
    if with_seccomp {
        checks.extend(["afunix=socket-afunix", "allowed=write:/tmp/probe.txt"]);
    }
    run_inside(jail_exe, bwrap, &checks, binds, with_seccomp)
}

/// The probes that [execute bubblewrap](Probe::needs_backend), with the
/// mechanism each names.
pub const BACKEND_PROBES: [(&str, &str); 10] = {
    let mut probes = [("", ""); 10];
    let (mut i, mut n) = (0, 0);
    while i < Probe::ALL.len() {
        let probe = Probe::ALL[i];
        if probe.needs_backend() {
            probes[n] = (probe.name(), probe.mechanism());
            n += 1;
        }
        i += 1;
    }
    assert!(
        n == probes.len(),
        "BACKEND_PROBES' length is the backend probe count"
    );
    probes
};

/// The result of a backend probe when no backend was resolved.
#[must_use]
pub fn backend_refusal(name: &str, bwrap: Backend<'_>) -> Option<ProbeResult> {
    let reason = bwrap.err()?;
    let probe = Probe::from_name(name).filter(|probe| probe.needs_backend())?;
    Some(ProbeResult::new(
        probe.name(),
        ProbeStatus::Unavailable,
        probe.mechanism(),
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

/// The result a [table-bound](Probe::table_bound) probe has on an
/// architecture the tables do not cover: `unsupported` (the implementation
/// lacks it, §3.1), measured by nothing. `None` when the probe runs as usual.
#[must_use]
pub fn architecture_refusal(name: &str, arch: &str) -> Option<ProbeResult> {
    if seccomp::tables_cover(arch) {
        return None;
    }
    let probe = Probe::from_name(name).filter(|probe| probe.table_bound())?;
    Some(ProbeResult::new(
        probe.name(),
        ProbeStatus::Unsupported,
        probe.mechanism(),
        seccomp::REASON_UNSUPPORTED_ARCHITECTURE,
        format!(
            "this build is for {arch}; this mechanism implements Linux x86_64 and aarch64 \
             syscall tables only (jail-v1 §3.2)"
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
    let Some(probe) = Probe::from_name(name) else {
        return ProbeResult::new(
            "unknown",
            ProbeStatus::Skipped,
            "none",
            "unknown_probe",
            format!("no probe named {name}"),
        );
    };
    // Every probe that reads `bwrap` needs a backend, so from here on it is
    // the resolved path whenever one of them reads it.
    probe.run(
        jail_exe,
        bwrap.unwrap_or(Path::new("/nonexistent/unresolved-bwrap")),
    )
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
        let pid = own_pid();
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
    const NAME: &str = Probe::BwrapPresent.name();
    const MECHANISM: &str = Probe::BwrapPresent.mechanism();
    match bwrap::bwrap_version(bwrap, Deadline::after(PROBE_DEADLINE)) {
        Ok(version) if version.at_least(bwrap::MINIMUM_VERSION) => {
            ProbeResult::new(NAME, ProbeStatus::Available, MECHANISM, "ok", version.raw)
        }
        Ok(version) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "bwrap_too_old",
            format!(
                "{} reports {}; fd binds need >= 0.10.0",
                bwrap.display(),
                version.raw
            ),
        ),
        Err(e) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "backend_unavailable",
            format!("{}: {e}", bwrap.display()),
        ),
    }
}

/// Issue draft 15: whether the host has the NVIDIA device nodes a contained
/// GPU grant binds. Informational — no requirement demands a GPU, so it
/// never affects readiness; a grant of a missing node still refuses at the
/// mount itself, naming the node.
fn probe_gpu_passthrough() -> ProbeResult {
    const NAME: &str = Probe::GpuPassthrough.name();
    const MECHANISM: &str = Probe::GpuPassthrough.mechanism();
    let present: Vec<&'static str> = ["/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia0"]
        .into_iter()
        .filter(|node| std::path::Path::new(node).exists())
        .collect();
    if present.is_empty() {
        ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "no_nvidia_devices",
            "no NVIDIA device nodes under /dev; a GPU grant (--rw /dev/nvidia*) \
             needs the driver's nodes"
                .to_owned(),
        )
    } else {
        ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            format!("NVIDIA nodes present: {}", present.join(", ")),
        )
    }
}

/// The namespace a [`Probe::UserNamespace`] or [`Probe::PidNamespace`] row
/// measures, as `status` names it (`ns_<kind>`).
fn namespace_kind(probe: Probe) -> &'static str {
    if probe == Probe::UserNamespace {
        "user"
    } else {
        "pid"
    }
}

/// This process's own id of the namespace `probe` measures.
fn namespace_id(probe: Probe, outside: &NsIds) -> Option<u64> {
    if probe == Probe::UserNamespace {
        outside.user
    } else {
        outside.pid
    }
}

fn probe_namespace(probe: Probe, jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    let outside = ns_ids(own_pid());
    let run = match run_inside(jail_exe, bwrap, &["status"], Vec::new(), false) {
        Ok(run) => run,
        Err(e) => return ProbeResult::error(probe.name(), probe.mechanism(), e.to_string()),
    };
    namespace_result(probe, namespace_id(probe, &outside), &run.captured)
}

fn namespace_result(
    probe: Probe,
    outside_id: Option<u64>,
    captured: &exec::Captured,
) -> ProbeResult {
    let (name, kind, mechanism) = (probe.name(), namespace_kind(probe), probe.mechanism());
    if captured.timed_out {
        return ProbeResult::error(name, mechanism, "probe exceeded its 5 second deadline");
    }
    let key = format!("ns_{kind}");
    let Some(inside_id) = captured.field(&key) else {
        return ProbeResult::error(
            name,
            mechanism,
            format!(
                "sandbox reported no {key}: status {:?}, stderr {}",
                captured.code(),
                captured.stderr.trim()
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
        if let Some(nspid) = captured.field("nspid") {
            evidence.push_str(&format!("; NSpid {nspid}"));
        }
        if let Some(pids) = captured.field("proc_pids") {
            evidence.push_str(&format!("; /proc shows {pids}"));
        }
    }
    ProbeResult::new(name, ProbeStatus::Available, mechanism, "ok", evidence)
}

fn probe_network_namespace(jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    const NAME: &str = Probe::NetworkNamespace.name();
    const MECHANISM: &str = Probe::NetworkNamespace.mechanism();
    let run = match run_inside(jail_exe, bwrap, &["status"], Vec::new(), false) {
        Ok(run) => run,
        Err(e) => return ProbeResult::error(NAME, MECHANISM, e.to_string()),
    };
    network_namespace_result(&run.captured)
}

fn network_namespace_result(captured: &exec::Captured) -> ProbeResult {
    const NAME: &str = Probe::NetworkNamespace.name();
    const MECHANISM: &str = Probe::NetworkNamespace.mechanism();
    if captured.timed_out {
        return ProbeResult::error(NAME, MECHANISM, "probe exceeded its 5 second deadline");
    }
    let Some(devices) = captured.field("netdev") else {
        return ProbeResult::error(
            NAME,
            MECHANISM,
            format!("sandbox reported no netdev: {}", captured.stderr.trim()),
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
    const NAME: &str = Probe::MountReadonlyBind.name();
    const MECHANISM: &str = Probe::MountReadonlyBind.mechanism();
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
    readonly_bind_result(&run.captured)
}

fn readonly_bind_result(captured: &exec::Captured) -> ProbeResult {
    const NAME: &str = Probe::MountReadonlyBind.name();
    const MECHANISM: &str = Probe::MountReadonlyBind.mechanism();
    if captured.timed_out {
        return ProbeResult::error(NAME, MECHANISM, "probe exceeded its 5 second deadline");
    }
    match captured.field("ro") {
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
            format!("sandbox reported nothing: {}", captured.stderr.trim()),
        ),
    }
}

fn probe_seccomp(jail_exe: &Path, bwrap: &Path) -> ProbeResult {
    const NAME: &str = Probe::SeccompFilterLoad.name();
    const MECHANISM: &str = Probe::SeccompFilterLoad.mechanism();
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
    seccomp_result(&run.captured)
}

fn seccomp_result(captured: &exec::Captured) -> ProbeResult {
    const NAME: &str = Probe::SeccompFilterLoad.name();
    const MECHANISM: &str = Probe::SeccompFilterLoad.mechanism();
    if captured.timed_out {
        return ProbeResult::error(NAME, MECHANISM, "probe exceeded its 5 second deadline");
    }
    let mode = captured.field("seccomp").unwrap_or("?");
    let denied = captured.field("afunix").unwrap_or("?");
    let allowed = captured.field("allowed").unwrap_or("?");
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
    // The same resolved file, as the sandbox sees it through the read-only
    // runtime roots (review F1: nothing but it runs).
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
    const NAME: &str = Probe::NestedUserNamespace.name();
    const MECHANISM: &str = Probe::NestedUserNamespace.mechanism();
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

/// Opening NETLINK_SOCK_DIAG alone succeeds even on a kernel built without
/// CONFIG_UNIX_DIAG. The mediator needs an actual AF_UNIX dump to prove that
/// a pathname listener belongs to the attempt's network namespace.
fn probe_unix_socket_diagnostics() -> ProbeResult {
    const NAME: &str = Probe::UnixSocketDiagnostics.name();
    const MECHANISM: &str = Probe::UnixSocketDiagnostics.mechanism();
    let result = super::sockdiag::SockDiag::open().and_then(|mut socket| {
        // No stop channel: the dump's own deadline and datagram bound apply.
        socket.dump(super::sockdiag::UDIAG_SHOW_VFS, None)
    });
    match result {
        Ok(_) => ProbeResult::new(
            NAME,
            ProbeStatus::Available,
            MECHANISM,
            "ok",
            "an AF_UNIX sock_diag dump with UDIAG_SHOW_VFS completed",
        ),
        Err(error) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "unix_socket_diagnostics_unavailable",
            format!(
                "AF_UNIX sock_diag dump failed: {error}; agent pathname mediation requires kernel CONFIG_UNIX_DIAG support"
            ),
        ),
    }
}

/// `seccomp_user_notification`: an unprivileged child installs the agent's
/// mediation filter with its own notification listener, and this process
/// takes that listener from it with `pidfd_getfd` — the two steps the
/// `agent` launcher and supervisor perform (§10). Whether a connect is then
/// mediated is the agent probes' and the conformance suite's question.
fn probe_user_notification() -> ProbeResult {
    const NAME: &str = Probe::SeccompUserNotification.name();
    const MECHANISM: &str = Probe::SeccompUserNotification.mechanism();
    // Built before the fork: the child only makes syscalls.
    let program = super::unixpeer::mediation_program();
    let (report_r, report_w) = match exec::pipe() {
        Ok(pipe) => pipe,
        Err(error) => return ProbeResult::error(NAME, MECHANISM, format!("pipe2: {error}")),
    };
    // Plain numbers for the child, which must not run destructors.
    let (read_fd, write_fd) = (report_r.as_raw_fd(), report_w.as_raw_fd());
    let parent = own_pid();
    // SAFETY: fork; the child calls only async-signal-safe functions
    // (prctl, getppid, seccomp, write, pause, _exit) over data built before
    // the fork.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: as above; `program` is live and never freed in the child.
        unsafe {
            exec::die_with_parent_after_fork(parent);
            libc::close(read_fd);
            let listener =
                super::unixpeer::install_program(&program, super::unixpeer::FLAG_NEW_LISTENER)
                    .map_or(-1, std::os::fd::IntoRawFd::into_raw_fd);
            let report = listener.to_le_bytes();
            libc::write(write_fd, report.as_ptr().cast(), report.len());
            loop {
                libc::pause();
            }
        }
    }
    // This process's copy of the write end: the child holds its own.
    drop(report_w);
    if pid < 0 {
        return ProbeResult::error(
            NAME,
            MECHANISM,
            format!("fork: {}", errno_name(last_errno())),
        );
    }
    let mut report = [0u8; 4];
    let mut got = 0usize;
    let deadline = Deadline::after(PROBE_DEADLINE);
    while got < report.len() && !deadline.expired() {
        let ready = super::sys::poll_one(
            report_r.as_fd(),
            libc::POLLIN,
            deadline.remaining_millis_capped(100),
        );
        if !ready.is_ok_and(|revents| revents != 0) {
            continue;
        }
        // SAFETY: the buffer is live and the length matches.
        let n = unsafe {
            libc::read(
                read_fd,
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
    // the cleanup this probe owes.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
    }
    drop(report_r);
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

fn own_pid() -> libc::pid_t {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}

fn probe_ptrace_seize() -> ProbeResult {
    const NAME: &str = Probe::PtraceSeizeDescendant.name();
    const MECHANISM: &str = Probe::PtraceSeizeDescendant.mechanism();
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
        return ProbeResult::error(
            NAME,
            MECHANISM,
            format!("fork: {}", errno_name(last_errno())),
        );
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
    // SAFETY: ptrace with PTRACE_SEIZE takes a pid and two scalars; no
    // pointer is dereferenced.
    if unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0) } < 0 {
        return Err(format!("PTRACE_SEIZE: {}", errno_name(last_errno())));
    }
    // SAFETY: as above.
    if unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0) } < 0 {
        return Err(format!("PTRACE_INTERRUPT: {}", errno_name(last_errno())));
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

/// The supervisor scope step's record (§9.3), as a row: `available` when
/// this process is inside the delegated subtree (`already_delegated` or
/// `entered`), `unavailable` with the step's reason otherwise. It runs
/// nothing: the step ran once, before anything else, and this reports it.
fn probe_supervisor_scope() -> ProbeResult {
    const NAME: &str = Probe::SupervisorScope.name();
    const MECHANISM: &str = Probe::SupervisorScope.mechanism();
    let outcome = super::scope::current();
    let (status, reason_code) = match (outcome.state(), outcome.reason()) {
        (super::scope::State::Unavailable, reason) => (
            ProbeStatus::Unavailable,
            reason.map_or("unavailable", super::scope::Reason::code),
        ),
        (state, _) => (ProbeStatus::Available, state.as_str()),
    };
    ProbeResult::new(NAME, status, MECHANISM, reason_code, outcome.summary())
}

fn probe_cgroup_leaf(probe: Probe, controller: Option<&str>) -> ProbeResult {
    let (name, mechanism) = (probe.name(), probe.mechanism());
    let mut limits = crate::policy::LimitsSnapshot {
        wall: None,
        pids: None,
        mem: None,
        swap: None,
        storage: None,
        inodes: None,
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
        Some("swap") => limits.swap = ceiling("0"),
        Some("cpu") => limits.cpu = ceiling("100"),
        _ => {}
    }
    let mut leaf = match cgroup::ExecutionCgroup::create(&limits) {
        Ok(leaf) => leaf,
        Err(err) => {
            return ProbeResult::new(
                name,
                ProbeStatus::Unavailable,
                mechanism,
                "cgroup_unavailable",
                err.to_string(),
            );
        }
    };
    // What creation configured and read back (a required ceiling that
    // fails either makes `create` fail): the evidence names exactly that.
    let applied = leaf.limits();
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
        return ProbeResult::error(
            name,
            mechanism,
            format!("fork: {}", errno_name(last_errno())),
        );
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
    // SAFETY: `pid` is this process's own unreaped child; killing it is the
    // cleanup this probe owes.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    loop {
        let mut status = 0;
        // SAFETY: `status` is a live writable int; WNOHANG never waits.
        let rc = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if rc == pid || rc < 0 {
            break;
        }
        if deadline.expired() {
            return ProbeResult::error(name, mechanism, "probe child could not be reaped");
        }
        nap();
    }
    match measured.and_then(|()| leaf.remove()) {
        Ok(()) => ProbeResult::new(
            name,
            ProbeStatus::Available,
            mechanism,
            "ok",
            leaf_evidence(&applied),
        ),
        Err(err) => ProbeResult::new(
            name,
            ProbeStatus::Unavailable,
            mechanism,
            "cgroup_probe_failed",
            err.to_string(),
        ),
    }
}

/// What a successful leaf probe did, step by step: a ceiling is named only
/// when one was configured and read back.
fn leaf_evidence(applied: &[crate::records::AppliedLimit]) -> String {
    let mut steps = vec!["created pinned leaf".to_owned()];
    steps.extend(
        applied
            .iter()
            .filter_map(|limit| limit.mechanism.as_deref())
            .map(|control| format!("configured/read back {control}")),
    );
    steps.extend(
        [
            "placed fixture",
            "cgroup.kill",
            "populated=0",
            "reaped and removed",
        ]
        .map(str::to_owned),
    );
    steps.join(", ")
}

fn probe_observer(jail_exe: &Path) -> ProbeResult {
    use super::tracer::{ClosedOp, Tracer, TracerConfig, TracerEvent};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::process::Stdio;
    const NAME: &str = Probe::ObserverClosedSet.name();
    const MECHANISM: &str = Probe::ObserverClosedSet.mechanism();
    use super::platform::{ERROR_FD, RELEASE_FD};
    let deadline = Deadline::after(PROBE_DEADLINE);
    let measured = (|| -> io::Result<()> {
        let temp = OwnedTempDir::new("observer-probe")?;
        let target = temp.path.join("created");
        let (release_r, release_w) = exec::pipe()?;
        let (_error_r, error_w) = exec::pipe()?;
        let mut fds = FdMap::new();
        fds.add(release_r, RELEASE_FD)?;
        fds.add(error_w, ERROR_FD)?;
        let launch = super::launch::LaunchArgs {
            release_fd: RELEASE_FD,
            error_fd: ERROR_FD,
            narrow: true,
            read_open_fast_path: false,
            trace_data_fd: None,
            mediate: None,
            bridge: None,
            sigmask: None,
            nofile_soft: None,
            argv: vec![
                jail_exe.into(),
                INSIDE_SUBCOMMAND.into(),
                format!("create=write:{}", target.display()).into(),
            ],
        };
        let mut command = Command::new(jail_exe);
        command
            .arg(super::launch::SUBCOMMAND)
            .args(launch.to_argv())
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
            // Blocked on the `--release-fd` above, not on an earlier read.
            match identity::wait_blocked_in_read(pid, RELEASE_FD, deadline, || {
                super::watch::is_readable(pidfd.as_fd())
            }) {
                Ok(()) => {}
                Err(identity::NotBlocked::Ended) => {
                    return Err(io::Error::other(
                        "observer launcher exited before it blocked",
                    ));
                }
                Err(timeout) => {
                    return Err(io::Error::other(format!(
                        "observer launcher did not block{}",
                        timeout.detail()
                    )));
                }
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
            MECHANISM,
            "ok",
            "attached blocked launcher; one successful create matched the fixture, final exit observed, zero loss",
        ),
        Err(err) => ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "observer_probe_failed",
            err.to_string(),
        ),
    }
}

/// Path of the Ubuntu sysctl that restricts unprivileged user namespaces.
pub const APPARMOR_USERNS_SYSCTL: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

fn probe_apparmor() -> ProbeResult {
    const NAME: &str = Probe::ApparmorUsernsRestriction.name();
    const MECHANISM: &str = Probe::ApparmorUsernsRestriction.mechanism();
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

/// Whether this host gives a writable filesystem a hard ceiling at all —
/// bounded tmpfs capacity, or the calling user's ext4/XFS hard quota (§6.4)
/// — which `--limit storage`/`--limit inodes` runs refuse without. Samples
/// a scratch directory this process owns, the way admission samples a
/// run's writable mounts.
fn probe_storage_ceiling() -> ProbeResult {
    const NAME: &str = Probe::StorageCeiling.name();
    const MECHANISM: &str = Probe::StorageCeiling.mechanism();
    let temp = match OwnedTempDir::new("storage-ceiling-probe") {
        Ok(temp) => temp,
        Err(err) => return ProbeResult::error(NAME, MECHANISM, format!("temp dir: {err}")),
    };
    match super::storage::probe_ceiling(&temp.path) {
        super::storage::CeilingProbe::Bounded { evidence } => {
            ProbeResult::new(NAME, ProbeStatus::Available, MECHANISM, "ok", evidence)
        }
        super::storage::CeilingProbe::Unbounded { reason, evidence } => {
            ProbeResult::new(NAME, ProbeStatus::Unavailable, MECHANISM, reason, evidence)
        }
        super::storage::CeilingProbe::Failed(evidence) => {
            ProbeResult::error(NAME, MECHANISM, evidence)
        }
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
            "http" => agent::check_http(argument),
            "tcp" => agent::check_tcp(argument),
            "unix" => agent::check_unix(argument),
            "unix-self" => agent::check_unix_self(argument),
            "inner" => agent::check_inner(argument),
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
        errno_name(last_errno()).into_owned()
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
    errno_name(last_errno()).into_owned()
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
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `c` is NUL-terminated and `st` is writable storage for a stat
    // buffer, which nothing reads: only the call's result matters.
    outcome(i64::from(unsafe {
        libc::stat(c.as_ptr(), st.as_mut_ptr())
    }))
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
        Err(e) => errno_name(e.raw_os_error().unwrap_or(libc::EIO)).into_owned(),
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
    errno_name(last_errno()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_namespace_results_keep_each_failure_independent() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut captured = exec::Captured {
            status: std::process::ExitStatus::from_raw(0),
            stdout: "ns_user=11\nns_pid=22\nnetdev=lo\n".into(),
            stderr: String::new(),
            timed_out: false,
        };
        assert_eq!(
            namespace_result(Probe::UserNamespace, Some(10), &captured).status,
            ProbeStatus::Available
        );
        assert_eq!(
            namespace_result(Probe::PidNamespace, Some(22), &captured).status,
            ProbeStatus::Unavailable
        );
        assert_eq!(
            network_namespace_result(&captured).status,
            ProbeStatus::Available
        );
        captured.stdout = "ns_user=11\nns_pid=22\nnetdev=eth0,lo\nro=ok\n".into();
        assert_eq!(
            network_namespace_result(&captured).status,
            ProbeStatus::Unavailable
        );
        assert_eq!(
            readonly_bind_result(&captured).status,
            ProbeStatus::Unavailable
        );
        captured.timed_out = true;
        assert_eq!(
            namespace_result(Probe::UserNamespace, Some(10), &captured).status,
            ProbeStatus::Error
        );
        assert_eq!(
            network_namespace_result(&captured).status,
            ProbeStatus::Error
        );
        assert_eq!(readonly_bind_result(&captured).status, ProbeStatus::Error);
        captured.timed_out = false;
        captured.stdout.clear();
        assert_eq!(
            namespace_result(Probe::UserNamespace, Some(10), &captured).status,
            ProbeStatus::Error
        );
        assert_eq!(
            network_namespace_result(&captured).status,
            ProbeStatus::Error
        );
    }

    #[test]
    fn namespace_batch_uses_one_fresh_sandbox_on_every_call() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = OwnedTempDir::new("namespace-batch-test").unwrap();
        let backend = temp.path.join("bwrap");
        let calls = temp.path.join("calls");
        std::fs::write(
            &backend,
            format!(
                "#!/bin/sh\nprintf x >> '{}'\nprintf '%s\\n' ns_user=1 ns_pid=2 netdev=lo ro=EROFS\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&backend, std::fs::Permissions::from_mode(0o700)).unwrap();
        let names = ["user_namespace", "pid_namespace", "network_namespace"];
        for expected in [1, 2] {
            let results = run_selected(&names, Path::new("/unused-jail"), Ok(&backend));
            assert_eq!(results.iter().map(|r| r.name).collect::<Vec<_>>(), names);
            assert!(
                results.iter().all(|r| r.status == ProbeStatus::Available),
                "{results:?}"
            );
            assert_eq!(std::fs::read(&calls).unwrap().len(), expected);
        }
        let unavailable = run_selected(&names, Path::new("/unused-jail"), Err("missing backend"));
        assert!(unavailable.iter().all(
            |r| r.status == ProbeStatus::Unavailable && r.reason_code == "backend_unavailable"
        ));
        assert_eq!(std::fs::read(&calls).unwrap().len(), 2);
    }

    #[test]
    fn combined_filter_checks_fall_back_without_poisoning_other_capabilities() {
        use std::os::unix::fs::PermissionsExt as _;
        let names = [
            "user_namespace",
            "pid_namespace",
            "network_namespace",
            "mount_readonly_bind",
            "seccomp_filter_load",
        ];
        for fail_combination in [false, true] {
            let temp = OwnedTempDir::new("combined-check-test").unwrap();
            let backend = temp.path.join("bwrap");
            let calls = temp.path.join("calls");
            let failure = if fail_combination {
                "case \"$*\" in *ro=write:*afunix=socket-afunix*) ro=EPERM;; esac\n"
            } else {
                ""
            };
            std::fs::write(
                &backend,
                format!(
                    "#!/bin/sh\nprintf x >> '{}'\nro=EROFS\n{failure}printf '%s\\n' \
                     ns_user=1 ns_pid=2 netdev=lo seccomp=2 afunix=EPERM allowed=ok ro=$ro\n",
                    calls.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&backend, std::fs::Permissions::from_mode(0o700)).unwrap();
            let results = run_selected(&names, Path::new("/unused-jail"), Ok(&backend));
            assert_eq!(results.iter().map(|r| r.name).collect::<Vec<_>>(), names);
            assert!(
                results.iter().all(|r| r.status == ProbeStatus::Available),
                "{results:?}"
            );
            assert_eq!(
                std::fs::read(&calls).unwrap().len(),
                if fail_combination { 4 } else { 1 }
            );
        }
    }

    #[test]
    fn readonly_setup_failure_does_not_poison_namespace_capabilities() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = OwnedTempDir::new("readonly-setup-fallback").unwrap();
        let backend = temp.path.join("bwrap");
        std::fs::write(
            &backend,
            "#!/bin/sh\ncase \"$*\" in *ro=write:*) exit 1;; esac\n\
             printf '%s\\n' ns_user=1 ns_pid=2 netdev=lo seccomp=2 afunix=EPERM allowed=ok\n",
        )
        .unwrap();
        std::fs::set_permissions(&backend, std::fs::Permissions::from_mode(0o700)).unwrap();
        let names = [
            "user_namespace",
            "pid_namespace",
            "network_namespace",
            "mount_readonly_bind",
            "seccomp_filter_load",
        ];
        let results = run_selected(&names, Path::new("/unused-jail"), Ok(&backend));
        for result in results {
            assert_eq!(
                result.status,
                if result.name == "mount_readonly_bind" {
                    ProbeStatus::Error
                } else {
                    ProbeStatus::Available
                },
                "{result:?}"
            );
        }
    }

    #[test]
    fn every_name_is_one_probe_and_the_derived_lists_agree() {
        for (index, probe) in Probe::ALL.into_iter().enumerate() {
            assert_eq!(PROBE_NAMES[index], probe.name());
            assert_eq!(Probe::from_name(probe.name()), Some(probe));
            assert_eq!(
                BACKEND_PROBES.contains(&(probe.name(), probe.mechanism())),
                probe.needs_backend(),
                "{probe:?}"
            );
        }
        let mut names = PROBE_NAMES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PROBE_NAMES.len(), "a name is listed twice");
        assert_eq!(Probe::from_name("no_such_probe"), None);
    }

    /// A leaf probe's evidence names a ceiling only when creation configured
    /// and read one back: the delegated-leaf row configures none.
    #[test]
    fn leaf_evidence_names_only_the_ceiling_that_was_configured() {
        assert_eq!(
            leaf_evidence(&[]),
            "created pinned leaf, placed fixture, cgroup.kill, populated=0, reaped and removed"
        );
        let pids = crate::records::AppliedLimit {
            key: "pids".to_owned(),
            requested: "16".to_owned(),
            required: true,
            applied: true,
            mechanism: Some("pids.max".to_owned()),
            scope: Some("tree".to_owned()),
            hit: Some(false),
        };
        assert_eq!(
            leaf_evidence(&[pids]),
            "created pinned leaf, configured/read back pids.max, placed fixture, cgroup.kill, \
             populated=0, reaped and removed"
        );
    }

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

    #[test]
    fn the_storage_ceiling_probe_reports_a_known_status_and_reason() {
        let result = run_one(
            "storage_ceiling",
            Path::new("/nonexistent"),
            Path::new("/nonexistent"),
        );
        assert!(
            matches!(
                result.status,
                ProbeStatus::Available | ProbeStatus::Unavailable
            ),
            "{result:?}"
        );
        assert!(
            matches!(
                result.reason_code,
                "ok" | "unbounded_filesystem" | "tmpfs_unbounded" | "no_user_hard_quota"
            ),
            "{result:?}"
        );
        assert!(!result.evidence.is_empty(), "{result:?}");
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

    // The architecture refusal (§3.2; gap analysis §2.3b)
    /// The rows whose mechanism is one of this implementation's native
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
    fn unsupported_architectures_the_table_bound_probes_are_unsupported_before_running() {
        for arch in ["riscv64", "arm", "x86", "powerpc64"] {
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
        for name in Probe::ALL
            .into_iter()
            .filter(|probe| probe.table_bound())
            .map(Probe::name)
        {
            for seam in [None, Some(""), Some("x86_64")] {
                assert_eq!(seam_refusal_for(name, seam), None, "{name} {seam:?}");
            }
            let refusal = seam_refusal_for(name, Some("riscv64")).expect("refused");
            assert_eq!(refusal.status, ProbeStatus::Unsupported);
            assert!(refusal.evidence.contains("OURO_JAIL_TEST_ARCH=riscv64"));
        }
        assert_eq!(seam_refusal_for("bwrap_present", Some("riscv64")), None);
    }

    /// The capability mapping: on a build the tables do not cover, the
    /// syscall filter and the closed-set observer derive `unsupported` with
    /// the architecture's reason, which no requirement accepts, so `doctor`
    /// is not ready and `run` refuses with 125 before preparation.
    #[test]
    fn unsupported_architectures_the_filter_and_observer_capabilities_refuse() {
        use crate::capability::{CapabilityScope, CapabilityStatus};
        // Every other probe as if it had succeeded, so the refusal is the
        // architecture's alone.
        let results: Vec<ProbeResult> = PROBE_NAMES
            .iter()
            .map(|name| {
                architecture_refusal(name, "riscv64").unwrap_or_else(|| {
                    ProbeResult::new(name, ProbeStatus::Available, "test", "ok", "")
                })
            })
            .collect();
        for (requirement, probes, scope) in [
            (
                crate::capability::Requirement::SyscallFilter,
                &["seccomp_filter_load"][..],
                CapabilityScope::Process,
            ),
            (
                crate::capability::Requirement::ClosedSetObservation,
                &["ptrace_seize_descendant", "observer_closed_set"][..],
                CapabilityScope::Tree,
            ),
            (
                crate::capability::Requirement::NetworkProxy,
                &[
                    "bwrap_present",
                    "network_namespace",
                    "seccomp_user_notification",
                    "unix_socket_diagnostics",
                ][..],
                CapabilityScope::Tree,
            ),
        ] {
            let capability = super::super::requirements::capability_from(
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

    #[test]
    fn statuses_render_as_the_spec_spells_them() {
        assert_eq!(ProbeStatus::Available.to_string(), "available");
        assert_eq!(ProbeStatus::Unavailable.to_string(), "unavailable");
        assert_eq!(ProbeStatus::Unsupported.to_string(), "unsupported");
        assert_eq!(ProbeStatus::Error.to_string(), "error");
        assert_eq!(ProbeStatus::Skipped.to_string(), "skipped");
    }
}
