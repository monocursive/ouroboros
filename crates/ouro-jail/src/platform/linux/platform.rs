//! The Linux platform: probing, preparation, release, lifetime.
//!
//! This is the seam of jail-v1 §4 filled in with the mechanisms of §9. The
//! supervisor owns every lifecycle transition and every receipt; this file
//! owns the boundary, the blocked launcher, the observer's attachment and the
//! verification of tree death, and it reports back only what it read from the
//! kernel.
//!
//! The process tree is supervisor → `bwrap` → namespace init → inside
//! launcher → target. The launcher is this same binary, bound read-only at
//! `/run/ouro/jail` and re-executed with the hidden `__launch` subcommand, so
//! nothing but the target's own code runs after the boundary is closed.
//! An outside watcher is a sibling of bubblewrap; its pidfds close the backend's
//! startup parent-death window. A resource leaf includes bubblewrap, namespace
//! init and the target tree, while the supervisor/observer/watcher stay outside.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::capability::{
    Capability, CapabilityScope, CapabilityStatus, REQ_CLOSED_SET_OBSERVATION,
    REQ_EXECUTION_CGROUP, REQ_FILESYSTEM_CONTAINMENT, REQ_NETWORK_NONE, REQ_NETWORK_PROXY,
    REQ_SYSCALL_FILTER, REQ_TREE_TERMINATION,
};
use crate::observer::CoverageSummary;
use crate::platform::{
    BoundaryIdentity, Deadline as PortableDeadline, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation, kernel_release,
};
use crate::policy::{
    EnvValue, PathRef, PolicySnapshot, ProfileName, ProtectedCoverage, RootToken, ScratchRoot,
};
use crate::records::{
    Applied, AppliedFilesystem, AppliedLimit, AppliedMount, AppliedNetwork, AppliedSyscalls,
    ErrorCode, ErrorStage, JailError, NativeLifetime, NativeString, ObserveMode, Os,
    ProcessIdentity as RecordIdentity, ProcessRecord, Remediation, rfc3339_utc,
};
use crate::supervisor::TREE_BUDGET;

use super::audit::AuditWriter;
use super::bwrap::{self, BwrapPlan, Placeholder, PlaceholderOutcome, PlaceholderSet};
use super::cgroup::ExecutionCgroup;
use super::clock::{self, boottime_ns};
use super::exec::{self, BootstrapChild, BootstrapSpawn, FdMap};
use super::fs as jfs;
use super::identity;
use super::probe::{self, ProbeResult, ProbeStatus};
use super::seccomp;
use super::tracer::{Tracer, TracerEvent, TracerSummary};

// Fixed descriptor numbers (§8.3). The backend's descriptor map installs
// the channels below `PINNED_FD_BASE`, beside `watch::BACKEND_FD` (8),
// `watch::START_FD` (15) and `agent::PROXY_DIR_FD` (17), and the pinned binds
// and credential views from `PINNED_FD_BASE` up. Bubblewrap consumes the
// binds before it runs the launcher, which keeps `RELEASE_FD`, `ERROR_FD`
// and `TRACE_DATA_FD` and places the `agent` descriptors (18 to 20) itself,
// refusing any number still open. `agent::BRIDGE_REPORT_FD` therefore shares
// 20 with `PINNED_FD_BASE` in a different table; the numbers that share a
// table are checked distinct by a test.

/// Where the attempt's narrowing `SECCOMP_RET_DATA` reaches the launcher:
/// two bytes, written before the spawn.
const TRACE_DATA_FD: RawFd = 9;
/// Descriptor the seccomp program is handed to bubblewrap on.
pub(crate) const SECCOMP_FD: RawFd = 10;
/// Descriptor bubblewrap writes its JSON status to.
pub(crate) const STATUS_FD: RawFd = 11;
/// Descriptor the launcher blocks reading.
const RELEASE_FD: RawFd = 12;
/// Descriptor the launcher writes a failed exec's errno to.
const ERROR_FD: RawFd = 13;
/// Descriptor a long argument list is handed over.
pub(crate) const ARGS_FD: RawFd = 14;
/// Descriptor the vendor-state directory is handed to bubblewrap on
/// (`--bind-fd`). The `bind_ro` credential views follow the pinned binds.
pub(crate) const VENDOR_STATE_FD: RawFd = 16;
/// First descriptor of the pinned binds (`--ro-bind-fd`, `--bind-fd`); every
/// fixed channel of the backend's map is below it.
const PINNED_FD_BASE: RawFd = 20;

/// Audit 2026-09-25-2, S14; reworded by audit 3 (A5): a per-attempt value for
/// the narrowing filter's `SECCOMP_RET_DATA`, unpredictable to the child. The
/// kernel's data field is sixteen bits, so this is a speed bump rather than a
/// wall. What a guess costs: a stop carrying this attempt's data on a number
/// the narrowing filter does not trace is a visible `unexpected_trace_stop`
/// gap, so forging our verdict costs the receipt its evidence one gap at a
/// time, and strict evidence fails on the first — while a stop carrying other
/// data is another filter's own request, continued and counted in
/// `requested_by_other_filters`, which the receipt's
/// `lifetime.native.details` carries. Guessing is therefore never silent:
/// every stop lands in the receipt as a gap or as a count.
fn random_trace_data() -> u16 {
    use std::hash::{BuildHasher, Hasher as _};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(u64::from(std::process::id()));
    match (hasher.finish() & 0xffff) as u16 {
        // Zero would collide with a child filter that sets no data.
        0 => super::tracer::filter::NARROWING_TRACE_DATA,
        value => value,
    }
}

/// Preparation budget (§8.2).
const PREPARE_BUDGET: Duration = Duration::from_secs(30);
/// Cooperative termination grace (§9.3).
const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long a natural finish is awaited before the tree is terminated.
const SETTLE_GRACE: Duration = Duration::from_millis(500);
/// Longest single block inside `wait`, so every source is re-checked often.
const WAIT_STEP: Duration = Duration::from_millis(10);
/// The most a stop gives the proxy to drain its last results (§10).
const AGENT_STOP_BUDGET: Duration = Duration::from_secs(2);
/// How often the execution cgroup's counters are read while the target runs;
/// they are always read once more before an outcome is classified.
const LIMIT_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// The Linux platform.
#[derive(Clone, Debug)]
pub struct LinuxPlatform {
    // J5-D: the resolved backend, or why none was (review F1/F2)
    bwrap: Result<PathBuf, String>,
    backend_pin: Result<std::sync::Arc<jfs::PinnedPath>, String>,
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPlatform {
    /// The platform with the bubblewrap this process resolved once from the
    /// operator's `PATH` ([`resolved_bwrap`]).
    #[must_use]
    pub fn new() -> Self {
        let backend_pin = resolved_bwrap().map_err(str::to_owned).and_then(|path| {
            jfs::PinnedPath::open(path)
                .map(std::sync::Arc::new)
                .map_err(|e| e.to_string())
        });
        LinuxPlatform {
            backend_pin,
            bwrap: resolved_bwrap()
                .map(Path::to_path_buf)
                .map_err(str::to_owned),
        }
    }

    /// The bubblewrap binary this platform executes: an absolute, canonical
    /// path, or `None` when the operator's `PATH` provides none.
    #[must_use]
    pub fn bwrap(&self) -> Option<&Path> {
        self.bwrap.as_deref().ok()
    }

    /// The backend as the probes take it: the path, or why there is none.
    fn backend(&self) -> Result<&Path, &str> {
        self.bwrap.as_deref().map_err(String::as_str)
    }
}

// Bubblewrap, resolved once (review F1, F2)
/// The backend, resolved from a `PATH` value.
///
/// The first *absolute* entry that holds an executable regular file named
/// `bwrap`, canonicalized, so the path recorded is the file that runs. An
/// empty entry (which a shell-style lookup reads as the current directory)
/// and a relative entry are skipped: either would let the working directory
/// pick the backend. There is no fallback to a well-known location, and an
/// unset `PATH` is not replaced by the C library's default search path: an
/// operator whose `PATH` does not name bubblewrap has not provisioned it,
/// and `doctor` says the backend is unavailable rather than reach past what
/// they configured (§3.2).
///
/// # Errors
/// Why no backend was found, for the `bwrap_present` evidence.
pub fn resolve_bwrap(path: Option<&std::ffi::OsStr>) -> Result<PathBuf, String> {
    let Some(path) = path else {
        return Err("PATH is unset, so no bubblewrap is provisioned for this process".to_owned());
    };
    let mut skipped = Vec::new();
    for dir in std::env::split_paths(path) {
        if dir.as_os_str().is_empty() || !dir.is_absolute() {
            skipped.push(format!("{:?}", dir.display().to_string()));
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(dir.join("bwrap")) else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(&canonical) else {
            continue;
        };
        let Ok(c_path) = std::ffi::CString::new(canonical.as_os_str().as_bytes()) else {
            continue;
        };
        // SAFETY: `c_path` is a live NUL-terminated string; access reads it.
        let executable = unsafe { libc::access(c_path.as_ptr(), libc::X_OK) } == 0;
        if meta.is_file() && executable {
            return Ok(canonical);
        }
    }
    let mut reason = "no executable `bwrap` in any absolute PATH entry".to_owned();
    if !skipped.is_empty() {
        reason.push_str(&format!(
            " (empty or relative entries are never searched: {})",
            skipped.join(", ")
        ));
    }
    Err(reason)
}

/// [`resolve_bwrap`] of this process's `PATH`, computed once: every probe,
/// every run and `doctor`'s record use this one path.
///
/// # Errors
/// Why no backend was found.
pub fn resolved_bwrap() -> Result<&'static Path, &'static str> {
    static RESOLVED: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    RESOLVED
        .get_or_init(|| resolve_bwrap(std::env::var_os("PATH").as_deref()))
        .as_deref()
        .map_err(String::as_str)
}

/// Whether the resolved bubblewrap is new enough for the rendered argv,
/// computed once per process from the backend every run resolves anyway:
/// `Ok(())`, or a message naming the version it reports and the floor it
/// misses.
static BWRAP_MEETS_MINIMUM: std::sync::LazyLock<Result<(), String>> =
    std::sync::LazyLock::new(|| {
        let bwrap = resolved_bwrap().map_err(str::to_owned)?;
        match bwrap::bwrap_version(bwrap) {
            Ok(version) if version.at_least(bwrap::MINIMUM_VERSION) => Ok(()),
            Ok(version) => Err(format!(
                "the resolved bubblewrap ({}) reports {}; every contained run renders \
                 --bind-fd/--ro-bind-fd, which need bubblewrap >= 0.10.0",
                bwrap.display(),
                version.raw
            )),
            Err(e) => Err(format!(
                "the resolved bubblewrap ({}) could not be asked for its version: {e}",
                bwrap.display()
            )),
        }
    });

/// The named roots the audit path classification knows besides the workspace
/// and scratch (issue draft 10): every operator grant by its in-jail
/// spelling, and the system read-only roots, so exec paths like
/// `/usr/bin/git` and writes under a `--ro` grant are named instead of
/// digested.
fn audit_named_roots(bplan: &bwrap::BwrapPlan) -> Vec<(Vec<u8>, String)> {
    let mut roots = Vec::new();
    for (_, dest) in bplan
        .extra_ro_binds
        .iter()
        .chain(bplan.extra_rw_binds.iter())
        .chain(bplan.extra_dev_binds.iter())
    {
        roots.push((
            dest.as_os_str().as_bytes().to_vec(),
            dest.display().to_string(),
        ));
    }
    for path in bwrap::RUNTIME_ROOTS.iter().chain(std::iter::once(&"/etc")) {
        roots.push((path.as_bytes().to_vec(), "system".to_owned()));
    }
    roots
}

/// Whether `path` is one of the device nodes a contained run may bind
/// individually (issue draft 15): the NVIDIA class an ML workload needs —
/// `nvidia[0-9]*`, `nvidiactl`, `nvidia-uvm`, `nvidia-uvm-tools`,
/// `nvidia-modeset` — directly under `/dev`, and really a character device.
/// Anything else under `/dev` keeps the §9.1 pseudo-filesystem refusal:
/// `/dev/kvm`, `/dev/fuse` and devtmpfs itself are host surfaces this
/// allowlist does not vouch for.
pub(crate) fn is_allowed_device_node(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    if path.parent() != Some(Path::new("/dev")) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let named = matches!(
        name,
        "nvidiactl" | "nvidia-uvm" | "nvidia-uvm-tools" | "nvidia-modeset"
    ) || name
        .strip_prefix("nvidia")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
    named
        && std::fs::metadata(path)
            .map(|meta| meta.file_type().is_char_device())
            .unwrap_or(false)
}

fn error(
    code: ErrorCode,
    stage: ErrorStage,
    remediation: Remediation,
    message: String,
) -> JailError {
    JailError::new(code, stage, remediation, message)
}

fn preparing(code: ErrorCode, message: impl Into<String>) -> JailError {
    error(
        code,
        ErrorStage::Preparing,
        Remediation::HostSetup,
        message.into(),
    )
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

fn status_of(result: &ProbeResult) -> CapabilityStatus {
    match result.status {
        ProbeStatus::Available => CapabilityStatus::Available,
        ProbeStatus::Unavailable => CapabilityStatus::Unavailable,
        ProbeStatus::Unsupported => CapabilityStatus::Unsupported,
        ProbeStatus::Error => CapabilityStatus::Error,
        ProbeStatus::Skipped => CapabilityStatus::Skipped,
    }
}

/// Which probes establish a requirement, and the mechanism it names.
fn inputs_for(
    requirement: &str,
) -> Option<(&'static [&'static str], &'static str, CapabilityScope)> {
    match requirement {
        REQ_TREE_TERMINATION => Some((
            &["bwrap_present", "pid_namespace"],
            "pid-namespace",
            CapabilityScope::Tree,
        )),
        REQ_CLOSED_SET_OBSERVATION => Some((
            &["ptrace_seize_descendant", "observer_closed_set"],
            "ptrace",
            CapabilityScope::Tree,
        )),
        REQ_FILESYSTEM_CONTAINMENT => Some((
            &["bwrap_present", "user_namespace", "mount_readonly_bind"],
            "bubblewrap-binds",
            CapabilityScope::Tree,
        )),
        REQ_SYSCALL_FILTER => Some((
            &["seccomp_filter_load"],
            "seccomp-bpf",
            CapabilityScope::Process,
        )),
        REQ_NETWORK_NONE => Some((
            &["network_namespace"],
            "network-namespace",
            CapabilityScope::Tree,
        )),
        // The agent network rests on the empty network
        // namespace and the unix-peer mediation's kernel mechanism; the proxy
        // and the bridge are this implementation's own, and preparation
        // refuses naming either one it cannot establish (§10).
        REQ_NETWORK_PROXY => Some((
            &[
                "bwrap_present",
                "network_namespace",
                "seccomp_user_notification",
                "unix_socket_diagnostics",
            ],
            "network-namespace+outside-http-proxy+loopback-bridge+unix-peer-mediation",
            CapabilityScope::Tree,
        )),
        REQ_EXECUTION_CGROUP => Some((
            &["cgroup_delegated_leaf"],
            "cgroup-v2-delegated",
            CapabilityScope::Tree,
        )),
        // Credential staging is anchored copies into vendor
        // state plus read-only descriptor binds, which rest on the backend and
        // on its read-only bind holding.
        crate::capability::REQ_CREDENTIAL_STAGING => Some((
            &["bwrap_present", "mount_readonly_bind"],
            "anchored-copy+bubblewrap-bind-fd",
            CapabilityScope::Tree,
        )),
        _ => None,
    }
}

/// The probes one requirement's capability is derived from. A run measures
/// only these; `doctor` measures every probe.
fn probes_for(requirement: &str) -> &'static [&'static str] {
    if requirement.starts_with("protected_coverage:") {
        return inputs_for(REQ_FILESYSTEM_CONTAINMENT).map_or(&[], |(probes, _, _)| probes);
    }
    match requirement {
        "limit:wall" => &[],
        "limit:pids" => &["cgroup_pids"],
        "limit:mem" => &["cgroup_memory"],
        "limit:swap" => &["cgroup_swap"],
        "limit:storage" | "limit:inodes" => &["storage_ceiling"],
        "limit:cpu" => &["cgroup_cpu"],
        other if other.starts_with("limit:") => &["cgroup_delegated_leaf"],
        other => inputs_for(other).map_or(&[], |(probes, _, _)| probes),
    }
}

fn capability_for(requirement: &str, results: &[ProbeResult], measured_at: &str) -> Capability {
    // Protected coverage rests on the same binds the filesystem boundary does.
    let normalised = if requirement.starts_with("protected_coverage:") {
        REQ_FILESYSTEM_CONTAINMENT
    } else {
        requirement
    };

    if requirement == "limit:wall" {
        // The wall is this supervisor's own CLOCK_BOOTTIME deadline; no host
        // mechanism has to provide it.
        return Capability {
            name: requirement.to_owned(),
            status: CapabilityStatus::Available,
            scope: CapabilityScope::Tree,
            mechanism: Some("boottime-deadline".to_owned()),
            reason_code: Some("ok".to_owned()),
            measured_at: Some(measured_at.to_owned()),
            evidence_ref: Some("supervisor".to_owned()),
        };
    }
    if requirement.starts_with("limit:") && requirement != "limit:wall" {
        return capability_from(
            requirement,
            probes_for(requirement),
            if matches!(requirement, "limit:storage" | "limit:inodes") {
                "bounded-tmpfs-or-user-quota"
            } else {
                "cgroup-v2-delegated"
            },
            CapabilityScope::Tree,
            results,
            measured_at,
        );
    }

    let Some((probes, mechanism, scope)) = inputs_for(normalised) else {
        return Capability {
            name: requirement.to_owned(),
            status: CapabilityStatus::Unsupported,
            scope: CapabilityScope::Tree,
            mechanism: None,
            reason_code: Some("requirement_not_implemented".to_owned()),
            measured_at: None,
            evidence_ref: None,
        };
    };
    capability_from(requirement, probes, mechanism, scope, results, measured_at)
}

fn capability_from(
    requirement: &str,
    probes: &[&str],
    mechanism: &str,
    scope: CapabilityScope,
    results: &[ProbeResult],
    measured_at: &str,
) -> Capability {
    let mut status = CapabilityStatus::Available;
    let mut reason = "ok".to_owned();
    for name in probes {
        let Some(result) = results.iter().find(|item| item.name == *name) else {
            status = CapabilityStatus::Skipped;
            reason = "probe_not_run".to_owned();
            break;
        };
        if result.status != ProbeStatus::Available {
            status = status_of(result);
            reason = result.reason_code.to_owned();
            break;
        }
    }
    Capability {
        name: requirement.to_owned(),
        status,
        scope,
        mechanism: Some(mechanism.to_owned()),
        reason_code: Some(reason),
        measured_at: Some(measured_at.to_owned()),
        evidence_ref: Some(probes.join(",")),
    }
}

impl LinuxPlatform {
    /// Runs the probes `wanted` selects, in report order, and derives the
    /// plan's capabilities from them.
    fn measure(&self, plan: &PlanRequest, wanted: impl Fn(&str) -> bool) -> Vec<Capability> {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
        let names: Vec<&str> = probe::PROBE_NAMES
            .iter()
            .filter(|name| wanted(name))
            .copied()
            .collect();
        let results = probe::run_selected(&names, &exe, self.backend());
        derive(plan, &results, &rfc3339_utc(SystemTime::now()))
    }
}

// J5-D: the derivation apart from the probing, so the requirement→probe
// mapping is testable with stated results (review F12).
/// The plan's capabilities from the probe results: one row per requirement
/// (through [`inputs_for`] and `none`'s own mapping), then the probe rows.
fn derive(plan: &PlanRequest, results: &[ProbeResult], measured_at: &str) -> Vec<Capability> {
    // `none` terminates its tree through the delegated leaf (§9.3)
    // Shadows the fn for this call only; the closure falls back to it.
    let capability_for = |requirement: &str, results: &[ProbeResult], measured_at: &str| {
        super::uncontained::capability_for(plan.profile, requirement, results, measured_at)
            .unwrap_or_else(|| capability_for(requirement, results, measured_at))
    };
    let mut out: Vec<Capability> = plan
        .requirements
        .iter()
        .map(|requirement| capability_for(requirement, results, measured_at))
        .collect();
    // The probe rows themselves, so `doctor --json` reports what was
    // measured and not only what the plan happened to ask for (§14.1).
    for result in results {
        out.push(Capability {
            name: result.name.to_owned(),
            status: status_of(result),
            scope: CapabilityScope::Host,
            mechanism: Some(result.mechanism.to_owned()),
            reason_code: Some(result.reason_code.to_owned()),
            measured_at: Some(measured_at.to_owned()),
            evidence_ref: Some(result.evidence.clone()),
        });
    }
    out
}

impl Platform for LinuxPlatform {
    fn owner_identity(&self) -> Option<crate::platform::OwnerIdentity> {
        let identity = identity::ProcessIdentity::own().ok()?;
        Some(crate::platform::OwnerIdentity {
            pid: identity.pid as u32,
            boot_id: identity.boot_id,
            start_time_ticks: identity.start_time_ticks,
        })
    }
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Linux,
            arch: std::env::consts::ARCH.to_owned(),
            kernel: kernel_release(),
        }
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        // A run measures what its plan asks about: every probe is a real
        // sandbox, fork or ptrace session, and the leaf and observer probes
        // are not free. `doctor` runs them all through `probe_all`.
        // `none` terminates its tree through the delegated leaf (§9.3)
        // Shadows the fn for this call only; the closure falls back to it.
        let probes_for = |requirement: &str| {
            super::uncontained::probes_for(plan.profile, requirement)
                .unwrap_or_else(|| probes_for(requirement))
        };
        let wanted: std::collections::BTreeSet<&str> = plan
            .requirements
            .iter()
            .flat_map(|requirement| probes_for(requirement).iter().copied())
            .collect();
        self.measure(plan, |name| wanted.contains(name))
    }

    fn probe_all(&self, plan: &PlanRequest) -> Vec<Capability> {
        self.measure(plan, |_| true)
    }

    fn prepare(
        &self,
        plan: PreparedPlan,
        sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        let deadline = clock::Deadline::after(PREPARE_BUDGET);
        // The uncontained profile has its own registered boundary (§9.3)
        if plan.request.snapshot.profile == ProfileName::None {
            return super::uncontained::prepare(plan, sinks, deadline);
        }
        // J5-D: never a bare name, so nothing but the resolved file runs.
        let bwrap = self.backend().map_err(|reason| {
            error(
                ErrorCode::BackendUnavailable,
                ErrorStage::Preparing,
                Remediation::HostSetup,
                format!("bubblewrap is not available: {reason}"),
            )
        })?;
        // A backend too old for the rendered argv (`--bind-fd` and
        // `--ro-bind-fd` arrived in 0.10.0) refuses here with the version it
        // reports, instead of exiting 125 during setup behind an empty
        // diagnostic.
        if let Err(reason) = BWRAP_MEETS_MINIMUM.clone() {
            return Err(error(
                ErrorCode::BackendUnavailable,
                ErrorStage::Preparing,
                Remediation::HostSetup,
                reason,
            ));
        }
        let pin = self
            .backend_pin
            .as_ref()
            .map_err(|e| preparing(ErrorCode::BackendUnavailable, e.clone()))?;
        let prepared = Boundary::create(bwrap, pin, plan, sinks, deadline)?;
        Ok(Box::new(LinuxPrepared { boundary: prepared }))
    }
}

// ---------------------------------------------------------------------------
// Preparation
// ---------------------------------------------------------------------------

/// bubblewrap's JSON status documents, read incrementally.
struct StatusReader {
    fd: OwnedFd,
    text: String,
    eof: bool,
}

impl StatusReader {
    fn new(fd: OwnedFd) -> Self {
        StatusReader {
            fd,
            text: String::new(),
            eof: false,
        }
    }

    /// Reads whatever is available without blocking.
    fn pump(&mut self) {
        if self.eof {
            return;
        }
        let mut buffer = [0u8; 4096];
        loop {
            // SAFETY: the buffer is live and the length matches; the
            // descriptor is owned and non-blocking.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if n > 0 {
                let read = usize::try_from(n).unwrap_or(0);
                self.text
                    .push_str(&String::from_utf8_lossy(&buffer[..read]));
                continue;
            }
            if n == 0 {
                self.eof = true;
            }
            return;
        }
    }

    fn parsed(&self) -> bwrap::BwrapStatus {
        bwrap::parse_json_status(&self.text)
    }

    fn namespace(&self, key: &str) -> Option<u64> {
        let at = self.text.find(&format!("\"{key}\""))?;
        let rest = &self.text[at..];
        let colon = rest.find(':')?;
        let digits: String = rest[colon + 1..]
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }
}

/// Everything the boundary owns, from preparation through settlement.
struct Boundary {
    snapshot: PolicySnapshot,
    workspace: PathBuf,
    child: Option<BootstrapChild>,
    bootstrap_spawn: BootstrapSpawn,
    bwrap_pid: libc::pid_t,
    /// A descriptor for bubblewrap, taken while it was this process's
    /// unreaped child. A pid number can come to mean another process; a
    /// pidfd cannot (§9.3).
    bwrap_fd: OwnedFd,
    init_pid: libc::pid_t,
    /// The same, for the namespace init. Discovery refuses without it, so it
    /// is missing only before discovery.
    init_fd: Option<OwnedFd>,
    launcher: identity::ProcessIdentity,
    /// The launcher's own descriptor, for the cooperative stop. Discovery
    /// refuses without it, so it is missing only before discovery.
    launcher_fd: Option<OwnedFd>,
    launcher_argv: Vec<Vec<u8>>,
    /// The paths the launcher will try to `execve`, derived from the same
    /// program name and `PATH` the launcher itself uses. The observer's exec
    /// snapshot must be one of them.
    target_images: Vec<Vec<u8>>,
    release: Option<OwnedFd>,
    error: OwnedFd,
    error_bytes: Vec<u8>,
    error_eof: bool,
    status: StatusReader,
    tracer: Option<Tracer>,
    tracer_summary: Option<TracerSummary>,
    audit: AuditWriter,
    placeholders: Vec<Placeholder>,
    placeholder_outcomes: Vec<PlaceholderOutcome>,
    applied: Applied,
    backend_version: String,
    resolv_sanitization: &'static str,
    observe_on: bool,
    /// The §11.4 bounds the observer runs with, decided once; `None` with
    /// observation off.
    observer_plan: Option<super::observed::ObserverPlan>,
    /// Audit 2026-09-25-2, S14: the narrowing filter's per-attempt
    /// `SECCOMP_RET_DATA`, shared only with the launcher (through the
    /// trace-data pipe) and the tracer.
    trace_data: u16,
    ns_ids: identity::NsIds,
    cgroup: Option<ExecutionCgroup>,
    storage: Option<super::storage::Storage>,
    cgroup_lost: bool,
    /// Why no execution cgroup exists, when preferred ceilings run unenforced.
    cgroup_unavailable: Option<String>,
    /// Audit 2026-10-08 H1 follow-up: the regular-file stdio streams,
    /// relayed through supervisor-owned pipes so the child holds no
    /// reopenable handle on any file.
    stdio_relays: Vec<StdioRelay>,
    watcher: super::watch::Watcher,
    // The agent network, and the filter count read back
    /// The proxy, mediator and bridge of an `agent` attempt.
    agent: Option<super::agent::AgentNet>,
    /// Set before this boundary kills anything: what dies after it did not
    /// die on its own.
    killing: std::sync::atomic::AtomicBool,
    /// `Seccomp_filters` of the blocked launcher, read back and checked
    /// against what this boundary installs.
    seccomp_filters: Option<u32>,
}
impl Boundary {
    /// Whether the backend's pidfd reports its exit, independent of whether
    /// its status has been collected yet.
    fn backend_exited(&self) -> bool {
        super::watch::readable(self.bwrap_fd.as_raw_fd())
    }
    /// The watcher stays until released or until this supervisor is gone
    /// (§9.3). It is released only once the backend has ended, so its end
    /// still means the backend's end to the verdicts that wait for it.
    fn release_watcher_after_backend(&mut self) {
        if self.backend_exited() {
            self.watcher.release();
        }
    }
    fn cgroup_empty(&self) -> bool {
        !self.cgroup_lost
            && self
                .cgroup
                .as_ref()
                .is_none_or(|leaf| matches!(leaf.populated(), Ok(false)))
    }
    #[allow(clippy::too_many_lines)]
    fn create(
        bwrap_path: &Path,
        backend_pin: &jfs::PinnedPath,
        plan: PreparedPlan,
        sinks: Sinks,
        deadline: clock::Deadline,
    ) -> Result<Boundary, JailError> {
        let snapshot = plan.request.snapshot.clone();
        shared::refuse_privileged_supervisor()?;
        if !snapshot.profile.is_contained() {
            // `prepare` hands `none` to its own boundary before this point.
            return Err(error(
                ErrorCode::InternalError,
                ErrorStage::Preparing,
                Remediation::InspectState,
                "the contained boundary was asked to run the uncontained `none` profile".to_owned(),
            ));
        }
        let observe_on = snapshot.observation.mode == ObserveMode::On;
        let exe = std::env::current_exe().map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("this binary's own path cannot be read: {err}"),
            )
        })?;

        // `<data>/attempts/<id>` is the attempt; the state root is two levels
        // up, and everything under it is supervisor state (§7).
        let state_root = plan
            .attempt_dir
            .parent()
            .and_then(Path::parent)
            .unwrap_or(plan.attempt_dir.as_path());
        let stdio_plans = validate_stdio(state_root, &plan.config_dir)?;

        // The scratch directory the child sees as /tmp. A managed one is
        // supervisor state and gets the private identity; an operator's
        // `--scratch` is the operator's own directory (resolved and checked
        // against the state root at resolving), whose mode is theirs.
        let scratch = match &snapshot.roots.scratch {
            ScratchRoot::Managed => {
                let scratch = plan.attempt_dir.join("scratch");
                crate::state::create_private_dir(&scratch)?;
                scratch
            }
            ScratchRoot::Host { path } => {
                let scratch = PathBuf::from(OsString::from_vec(path.as_bytes().to_vec()));
                ensure_dir(&scratch)?;
                scratch
            }
        };

        let cgroup_required = [
            &snapshot.limits.pids,
            &snapshot.limits.mem,
            &snapshot.limits.swap,
            &snapshot.limits.cpu,
        ]
        .into_iter()
        .flatten()
        .any(|limit| limit.required);
        let mut cgroup_unavailable = None;
        // J4 W2-S: N7 — registered in jail state before `mkdir` and before
        // anything is placed in it; a failed registration refuses (S5).
        let created = ExecutionCgroup::create_for_attempt(&snapshot.limits, &plan.attempt_dir)?;
        let cgroup = match created {
            Ok(leaf) => Some(leaf),
            Err(err) if cgroup_required => {
                return Err(preparing(
                    ErrorCode::MissingCapability,
                    format!("required execution cgroup could not be configured: {err}"),
                ));
            }
            // Preferred ceilings run unenforced, and the record says why
            // (§6.4): the reason reaches the native details and a wrapper note.
            Err(err) => {
                cgroup_unavailable = Some(err.to_string());
                None
            }
        };

        // north-star §4.4 / jail-v1 §9.1: Linux cannot enforce
        // all_descendants; a profile that requires it refuses (125) rather
        // than underclaim.
        if snapshot.filesystem.protected_coverage == ProtectedCoverage::AllDescendants {
            return Err(error(
                ErrorCode::MissingCapability,
                ErrorStage::Preparing,
                Remediation::Unsupported,
                "the all_descendants protected-path coverage cannot be enforced on Linux; \
                 it refuses rather than underclaim (north-star §4.4)"
                    .to_owned(),
            ));
        }

        // Protected segments. A bound reached is a refusal, never a shorter
        // answer (§9.1). The walk's names are the snapshot's own segments:
        // every contained baseline carries exactly its literals (`tool` the
        // built-in `.git`/`.ouroboros`, `agent` — audit 2026-10-08 M5 — only
        // `.git/hooks` and `.git/config`, so the rest of Git metadata stays
        // writable), so merging the built-ins in again here would protect
        // more than the profile asked for.
        let mut names: Vec<String> = snapshot.filesystem.protected_segments.clone();
        names.sort_unstable();
        names.dedup();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut bplan = BwrapPlan::tool(&plan.workspace, &scratch, &exe);
        bplan.bounded_storage = super::storage::requested(&snapshot.limits);
        bplan.workspace_access = None;
        if snapshot.filesystem.read_write.iter().any(|reference| {
            host_path_of(reference, &plan.workspace, &scratch)
                .is_ok_and(|path| path == plan.workspace)
        }) {
            bplan.workspace_access = Some(true);
        }
        if snapshot.filesystem.read_only.iter().any(|reference| {
            host_path_of(reference, &plan.workspace, &scratch)
                .is_ok_and(|path| path == plan.workspace)
        }) {
            bplan.workspace_access = Some(false);
        }
        bplan.bwrap = bwrap_path.to_path_buf();
        bplan.env = environment_for(&snapshot, &plan.workspace)?;
        // §10 — the proxy socket in its registered directory,
        // bound read-only by descriptor, and the proxy variables.
        let mut agent = if snapshot.profile == ProfileName::Agent {
            let Some(handoff) = plan.proxy.as_ref() else {
                return Err(preparing(
                    ErrorCode::MissingCapability,
                    "the `agent` proxy could not be established: no proxy directory was prepared",
                ));
            };
            let agent = super::agent::AgentNet::prepare(
                &plan.attempt_id,
                sinks.trace.clone(),
                &snapshot,
                handoff,
                &exe,
                bwrap_path,
                bplan.bounded_storage,
            )?;
            bplan.proxy_dir = Some(agent.dir_path().to_path_buf());
            bplan.proxy_dir_fd = Some(super::agent::PROXY_DIR_FD);
            for (name, value) in super::bridge::proxy_environment() {
                bplan
                    .env
                    .push((OsString::from(name), OsString::from(value)));
            }
            Some(agent)
        } else {
            None
        };
        if let Some(handoff) = &plan.launch
            && !handoff.vault.is_empty()
        {
            use std::os::fd::AsFd as _;
            let vault_io = |e| {
                preparing(
                    ErrorCode::CredentialUnavailable,
                    format!("vault public CA cannot be staged: {e}"),
                )
            };
            let vault = std::sync::Arc::new(
                crate::vault::Vault::new(&plan.attempt_id, handoff.vault.clone())
                    .map_err(|e| preparing(ErrorCode::CredentialUnavailable, e))?,
            );
            let vendor = handoff
                .vendor_state
                .as_ref()
                .ok_or_else(|| preparing(ErrorCode::InternalError, "vault has no private state"))?;
            let dir = crate::state::anchored::Dir::from_owned(
                vendor.fd.as_fd().try_clone_to_owned().map_err(vault_io)?,
            );
            let name =
                crate::state::anchored::Name::new(b".ouro-vault-ca.pem").map_err(vault_io)?;
            let mut cert = dir.create_file_at(&name, 0o600).map_err(vault_io)?;
            use std::io::Write as _;
            cert.write_all(vault.ca_pem().as_bytes())
                .map_err(vault_io)?;
            let destination = PathBuf::from("/run/ouro/vault-ca.pem");
            bplan.extra_ro_binds.push((
                vendor.host_path.join(".ouro-vault-ca.pem"),
                destination.clone(),
            ));
            for (name, value) in vault.environment() {
                bplan.env.push((name.into(), value.into()));
            }
            for name in ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"] {
                bplan.env.retain(|(key, _)| key != name);
                bplan
                    .env
                    .push((name.into(), destination.clone().into_os_string()));
            }
            agent
                .as_mut()
                .ok_or_else(|| preparing(ErrorCode::InvalidConfig, "vault requires agent network"))?
                .configure_vault(vault);
        }
        // The staged vendor state and bind_ro sources, bound
        // by the descriptors staging examined (§9.1, §12).
        let staged = staged_mounts(&snapshot, plan.launch.as_ref())?;
        if staged.vendor.is_some() {
            bplan.vendor_state = plan
                .launch
                .as_ref()
                .and_then(|handoff| handoff.vendor_state.as_ref())
                .map(|vendor| vendor.host_path.clone());
            bplan.vendor_state_fd = Some(VENDOR_STATE_FD);
        }
        bplan.credential_binds = staged
            .credentials
            .iter()
            .map(|(_, destination)| bwrap::CredentialBind {
                fd: None,
                destination: destination.clone(),
            })
            .collect();

        // Operator grants are enforced, not merely recorded (I02, north-star
        // §4.2): read-only grants become additional ro-binds at their
        // resolved paths, host-rooted writable grants become binds, and
        // denied paths are masked with a sealed directory or file. Grants under
        // the workspace or scratch are covered by the base binds and layered
        for reference in &snapshot.filesystem.read_write {
            if let Ok(host) = host_path_of(reference, &plan.workspace, &scratch) {
                // Issue draft 15: an allowlisted device node (the NVIDIA
                // class) binds individually with `--dev-bind`, never as a
                // devtmpfs surface.
                if is_allowed_device_node(&host) {
                    let destination = resolve_path_ref(reference, &plan.workspace)?;
                    bplan
                        .extra_dev_binds
                        .push((host, PathBuf::from(destination)));
                    continue;
                }
                if (bplan.workspace_access == Some(true) && host.starts_with(&plan.workspace))
                    || host.starts_with(&scratch)
                {
                    // Inside a base writable bind already; layering an extra
                    // bind of the same content would add nothing.
                    continue;
                }
                let destination = resolve_path_ref(reference, &plan.workspace)?;
                bplan
                    .extra_rw_binds
                    .push((host, PathBuf::from(destination)));
            }
        }
        for reference in &snapshot.filesystem.read_only {
            if let Ok(host) = host_path_of(reference, &plan.workspace, &scratch) {
                // The runtime plan already renders merged-/usr aliases as
                // symlinks and pins their real roots. Do not reopen /bin or
                // /lib as an operator bind (or mount over those aliases).
                // Baseline runtime candidates are optional distribution
                // paths: ARM64 Debian, for example, has /lib but no /lib64.
                // BwrapPlan already discovers and records the roots that
                // exist. Do not turn an absent default into a required bind.
                // Errors other than absence still reach pinning and refuse.
                if absent_runtime_candidate(reference, &host)
                    || bplan.etc_paths.contains(&host)
                    || bplan.roots.iter().any(|root| match root {
                        jfs::RootSpec::RoBind(path) | jfs::RootSpec::Symlink { path, .. } => {
                            path == &host
                        }
                    })
                {
                    continue;
                }
                if is_allowed_device_node(&host) {
                    return Err(error(
                        ErrorCode::InvalidConfig,
                        ErrorStage::Preparing,
                        Remediation::Configuration,
                        format!(
                            "the device grant {} binds only read-write (--rw): bubblewrap has \
                             no read-only device bind",
                            host.display()
                        ),
                    ));
                }
                let destination = resolve_path_ref(reference, &plan.workspace)?;
                bplan
                    .extra_ro_binds
                    .push((host, PathBuf::from(destination)));
            }
        }
        for reference in &snapshot.filesystem.deny_read {
            let destination = resolve_path_ref(reference, &plan.workspace)?;
            let path = PathBuf::from(destination);
            // Classification changes only the overlay's type, never grants
            // access to the denied object. A type swap before mounting fails
            // setup rather than releasing an unmasked target.
            let host = host_path_of(reference, &plan.workspace, &scratch)?;
            let mask = match std::fs::metadata(&host) {
                Ok(metadata) if !metadata.is_dir() => bwrap::Mask::File(path),
                Ok(_) => bwrap::Mask::Directory(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    bwrap::Mask::Directory(path)
                }
                Err(error) => {
                    return Err(preparing(
                        ErrorCode::BackendUnavailable,
                        format!("cannot classify denied path {}: {error}", host.display()),
                    ));
                }
            };
            bplan.masked.push(mask);
        }

        // J5-B1-w3: §9.1 — an operator grant may not expose host /proc, /sys
        // or cgroupfs. Checked here, before any mount, on the resolved source
        // by filesystem type and mount topology (never by spelling), so it
        // refuses before exec. The baseline runtime roots are on the root
        // filesystem and pass; the child's private /proc and /dev are made by
        // bubblewrap, not bound from these sources.
        // Security 2026-09-25 (audit F5): bind a sanitized resolver view.
        // The host's `/etc/resolv.conf` can carry the operator's search
        // domains — host facts the child has no grant for. The child's
        // resolver is unreachable inside its network namespace either way;
        // the copy keeps the nameservers and drops `search`/`domain` lines.
        let (resolv_source, resolv_sanitization) = stage_sanitized_resolv_conf(&plan.attempt_dir)?;
        bplan.resolv_source = Some(resolv_source);

        refuse_pseudo_fs_grants(
            &[(plan.workspace.clone(), plan.workspace.clone())],
            "workspace",
        )?;
        if let crate::policy::ScratchRoot::Host { path } = &plan.request.snapshot.roots.scratch {
            let source = PathBuf::from(std::ffi::OsString::from_vec(path.as_bytes().to_vec()));
            refuse_pseudo_fs_grants(&[(source.clone(), source)], "scratch")?;
        }
        refuse_pseudo_fs_grants(&bplan.extra_ro_binds, "filesystem.read_only")?;
        refuse_pseudo_fs_grants(&bplan.extra_rw_binds, "filesystem.read_write")?;

        // Until the boundary owns them, every refusal drops `placeholders`,
        // which removes the directories it made in the operator's workspace.
        let (scan, pins, pinned_fds, placeholders) = prepare_mounts(
            &mut bplan,
            &plan.attempt_dir,
            &name_refs,
            snapshot.filesystem.protected_coverage,
        )?;
        // Credential views take the slots after the pins
        let credential_base = PINNED_FD_BASE + pinned_fds.len() as RawFd;
        for (index, view) in bplan.credential_binds.iter_mut().enumerate() {
            view.fd = Some(credential_base + index as RawFd);
        }

        // A storage ceiling rests on a filter that denies new mounts, which
        // the `NamespaceInner` agent variant permits.
        if bplan.bounded_storage
            && agent
                .as_ref()
                .is_some_and(|agent| agent.variant() == seccomp::AgentVariant::NamespaceInner)
        {
            return Err(preparing(
                ErrorCode::MissingCapability,
                "storage ceilings require a profile that cannot create new mounts",
            ));
        }
        // `agent` installs the baseline its network built once, in the variant
        // the measured nested-namespace capability selected (§9.2), so the
        // digest its receipt detail names is the digest of what runs.
        let filter = match agent.as_ref() {
            Some(agent) => agent.baseline().clone(),
            None => seccomp::tool_baseline_with_storage(bplan.bounded_storage).map_err(|err| {
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!("the syscall filter could not be built: {err}"),
                )
            })?,
        };
        let filter_digest = filter.digest();

        let target: Vec<OsString> = plan
            .argv
            .iter()
            .map(|bytes| OsString::from_vec(bytes.clone()))
            .collect();
        // The agent launcher mediates and starts the bridge
        let trace_data = if observe_on {
            Some(random_trace_data())
        } else {
            None
        };
        bplan.inner = bwrap::inner_launch_command_with(
            RELEASE_FD,
            ERROR_FD,
            observe_on,
            agent.is_some().then_some((
                super::agent::LISTENER_FD,
                super::agent::SOCKDIAG_FD,
                super::agent::BRIDGE_REPORT_FD,
            )),
            // bubblewrap unblocks SIGCHLD in its child: the launcher puts
            // back the mask this supervisor inherited.
            Some(super::launch::blocked_mask()),
            trace_data.map(|_| TRACE_DATA_FD),
            &target,
        );
        if observe_on && !snapshot.observation.learning {
            bplan
                .inner
                .insert(2, OsString::from("--read-open-fast-path"));
        }
        bplan.seccomp_fd = Some(SECCOMP_FD);
        bplan.json_status_fd = Some(STATUS_FD);
        bplan.args_fd = Some(ARGS_FD);
        let launcher_argv: Vec<Vec<u8>> = bplan
            .inner
            .iter()
            .map(|part| part.as_bytes().to_vec())
            .collect();
        let child_path = bplan
            .env
            .iter()
            .find(|(name, _)| name == "PATH")
            .map(|(_, value)| value.clone());
        let target_images = super::launch::exec_candidate_bytes(
            target.first().map_or(OsStr::new(""), OsString::as_os_str),
            child_path.as_deref(),
        )
        .map_err(|err| {
            error(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                err.to_string(),
            )
        })?;

        let rendered = bplan.render().map_err(|err| {
            error(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                err.to_string(),
            )
        })?;

        // Room for the credential views after the pins
        let mut fds = FdMap::with_target_limit(
            PINNED_FD_BASE + pinned_fds.len() as RawFd + staged.credentials.len() as RawFd,
        );
        // §8.2: a wait that the preparation budget ended (the watcher's
        // readiness, the arguments' write) refuses as the budget's timeout,
        // with remediation `retry`, not as a host failure of the step that
        // happened to be waiting.
        let io = |err: std::io::Error| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                return prepare_timeout(&format!(
                    "preparation did not complete within its budget: {err}"
                ));
            }
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the boundary's channels could not be created: {err}"),
            )
        };
        fds.add(seccomp::program_pipe(&filter).map_err(io)?, SECCOMP_FD)
            .map_err(io)?;
        let (release_r, release_w) = exec::pipe().map_err(io)?;
        let (error_r, error_w) = exec::pipe().map_err(io)?;
        let (status_r, status_w) = exec::pipe().map_err(io)?;
        let (start_r, start_w) = exec::pipe().map_err(io)?;
        fds.add(start_r, super::watch::START_FD).map_err(io)?;
        fds.add(
            backend_pin.borrow_fd().try_clone_to_owned().map_err(io)?,
            super::watch::BACKEND_FD,
        )
        .map_err(io)?;
        fds.add(release_r, RELEASE_FD).map_err(io)?;
        fds.add(error_w, ERROR_FD).map_err(io)?;
        // Audit 2026-09-25-2, S14: the narrowing data is already in the pipe
        // before the spawn, so the launcher's blocking read always completes;
        // the descriptor closes in the launcher and never reaches the target.
        if let Some(data) = trace_data {
            let (trace_r, trace_w) = exec::pipe().map_err(io)?;
            // Two bytes always fit the pipe's capacity, so the write
            // completes before any reader exists.
            write_all(trace_w.as_raw_fd(), &super::sys::trace_data_bytes(data)).map_err(io)?;
            fds.add(trace_r, TRACE_DATA_FD).map_err(io)?;
        }
        fds.add(status_w, STATUS_FD).map_err(io)?;
        for (copy, target) in pinned_fds {
            fds.add(copy, target).map_err(io)?;
        }
        // Hand the staged descriptors to bubblewrap
        if let Some(vendor) = staged.vendor {
            fds.add(vendor, VENDOR_STATE_FD).map_err(io)?;
        }
        // The proxy directory, bound read-only by descriptor
        if let Some(agent) = agent.as_ref() {
            fds.add(agent.dir_fd().map_err(io)?, super::agent::PROXY_DIR_FD)
                .map_err(io)?;
        }
        for ((source, _), view) in staged.credentials.into_iter().zip(&bplan.credential_binds) {
            let Some(target) = view.fd else {
                return Err(preparing(
                    ErrorCode::InternalError,
                    "a credential view has no descriptor slot",
                ));
            };
            fds.add(source, target).map_err(io)?;
        }
        // jail-v1 §2 I07 (every wait bounded): the `--args` payload can exceed
        // the pipe's capacity, so it must be written while the reader exists.
        // bwrap is spawned below first and blocks reading ARGS_FD; writing
        // before the spawn deadlocked the supervisor on a full pipe with no
        // reader. If bwrap dies before consuming the payload, the write fails
        // with EPIPE instead of hanging. `exec::pipe` is close-on-exec on both
        // ends, so the parent's write end never reaches bwrap and its EOF is
        // seen as soon as this side closes.
        let mut args_writer = None;
        if rendered.args_payload.is_some() {
            let (args_r, args_w) = exec::pipe().map_err(io)?;
            fds.add(args_r, ARGS_FD).map_err(io)?;
            args_writer = Some(args_w);
        }
        set_nonblocking(error_r.as_raw_fd()).map_err(io)?;
        set_nonblocking(status_r.as_raw_fd()).map_err(io)?;

        let arguments: Vec<OsString> = std::iter::once(OsString::from("__backend"))
            .chain(rendered.argv.iter().cloned())
            .collect();
        // J5-B2 seam: give a test a deterministic window between pinning and
        // the mount-handoff verification below to replace a pinned source, so
        // the source-identity-swap refusal (F04) can be proved through the CLI.
        mount_swap_rendezvous();
        // §9.1 mount-handoff verification: the workspace and every pinned
        // protected segment must still resolve to the objects that were
        // scanned, or the run refuses rather than bind a replacement.
        for directory in &scan.directories {
            directory
                .verify()
                .map_err(|e| preparing(ErrorCode::MissingCapability, e.to_string()))?;
        }
        backend_pin.verify_executable().map_err(|e| {
            preparing(
                ErrorCode::InternalError,
                format!("the pinned backend changed before spawn: {e}"),
            )
        })?;
        for pin in &pins {
            pin.verify().map_err(|err| {
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!("a protected path changed during preparation: {err}"),
                )
            })?;
        }
        // §8.3: stdio passes through without capture except regular files and sockets,
        // which are relayed through supervisor-owned pipes (audit
        // 2026-10-08 H1): the child gets a pipe end here and never the
        // file, so no `/dev/stdin` reopen can reach the host mount. Every
        // other descriptor the supervisor holds is closed on exec.
        let mut stdio_relays = Vec::new();
        for (fd, plan) in stdio_plans.into_iter().enumerate() {
            if let StdioPlan::Relay { socket } = plan {
                stdio_relays.push(StdioRelay::attach(
                    i32::try_from(fd).unwrap_or(-1),
                    fd == 0,
                    socket,
                    &mut fds,
                )?);
            }
        }
        let spawn_cgroup = cgroup
            .as_ref()
            .map(ExecutionCgroup::spawn_handle)
            .transpose()
            .map_err(io)?;
        let child = exec::spawn_bootstrap(&exe, &arguments, &fds, spawn_cgroup.as_ref(), deadline)
            .map_err(|err| {
                // The exec handshake spends the same preparation budget.
                if err.kind() == std::io::ErrorKind::TimedOut {
                    return io(err);
                }
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!(
                        "the backend bootstrap ({}) could not be started: {err}",
                        exe.display()
                    ),
                )
            })?;
        // Until the boundary owns it, every refusal below kills and reaps the
        // backend, within a fresh tree budget (§8.1: a pre-exec failure
        // refuses and leaves no orphan).
        let child = exec::KillOnDrop::new(child);
        let bootstrap_spawn = child.spawn();
        // In particular close our duplicate of ARGS_FD before streaming: if
        // the backend exits there must be no reader left to suppress EPIPE.
        drop(fds);
        let bwrap_pid = libc::pid_t::try_from(child.id()).map_err(|_| {
            preparing(
                ErrorCode::InternalError,
                format!("the backend's pid {} does not fit a pid_t", child.id()),
            )
        })?;
        // Taken while the backend is this process's unreaped child, so the
        // descriptor names it; every later signal and exit check uses it.
        let bwrap_fd = identity::pidfd_open(bwrap_pid).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the backend's pidfd could not be opened: {err}"),
            )
        })?;
        // Root the cgroup namespace in this attempt's leaf. Moving only the
        // target after bubblewrap unshares exposes a /../../host-leaf path in
        // /proc/self/cgroup. Direct creation still requires the same parent
        // readback; the compatibility path moves the blocked bootstrap first.
        if let Some(leaf) = &cgroup {
            if child.created_in_cgroup() {
                leaf.verify_member(bwrap_pid)
            } else {
                leaf.place(bwrap_pid)
            }
            .map_err(io)?;
        }
        let cgroup_kill = cgroup
            .as_ref()
            .map(ExecutionCgroup::kill_handle)
            .transpose()
            .map_err(io)?;
        let watcher =
            super::watch::Watcher::start(&exe, bwrap_pid, cgroup_kill, deadline).map_err(io)?;
        write_all(start_w.as_raw_fd(), &[1]).map_err(io)?;
        drop(start_w);
        // The payload write happens with bwrap already blocked on ARGS_FD, so
        // a payload larger than the pipe's capacity flows through instead of
        // deadlocking. A failure here means bwrap died reading.
        if let (Some(args_w), Some(payload)) =
            (args_writer.as_ref(), rendered.args_payload.as_ref())
        {
            write_until(args_w.as_raw_fd(), payload, deadline).map_err(io)?;
        }
        drop(args_writer);

        let workspace_path = plan.workspace.clone();
        let mut boundary = Boundary {
            audit: AuditWriter::new(
                &plan.attempt_id,
                sinks.trace.clone(),
                plan.workspace.as_os_str().as_bytes(),
                bwrap::SCRATCH_INSIDE_PATH.as_bytes(),
            )
            .with_learning(snapshot.observation.learning)
            .with_roots(audit_named_roots(&bplan)),
            snapshot,
            workspace: workspace_path,
            child: Some(child.hand_over()),
            bootstrap_spawn,
            bwrap_pid,
            bwrap_fd,
            init_pid: -1,
            init_fd: None,
            launcher: identity::ProcessIdentity {
                pid: -1,
                boot_id: String::new(),
                start_time_ticks: 0,
            },
            launcher_fd: None,
            launcher_argv,
            target_images,
            release: Some(release_w),
            error: error_r,
            error_bytes: Vec::new(),
            error_eof: false,
            status: StatusReader::new(status_r),
            tracer: None,
            tracer_summary: None,
            placeholders: placeholders.hand_over(),
            placeholder_outcomes: Vec::new(),
            applied: Applied {
                filesystem: None,
                network: AppliedNetwork {
                    mode: "pending".to_owned(),
                    mechanism: None,
                    allowed_hosts: Vec::new(),
                },
                syscalls: None,
                limits: Vec::new(),
                environment_names: Vec::new(),
                removed_environment_names: Vec::new(),
            },
            backend_version: String::new(),
            resolv_sanitization,
            observe_on,
            observer_plan: observe_on.then(super::observed::ObserverPlan::from_env),
            trace_data: trace_data.unwrap_or(super::tracer::filter::NARROWING_TRACE_DATA),
            ns_ids: identity::NsIds::default(),
            cgroup,
            cgroup_lost: false,
            cgroup_unavailable,
            storage: None,
            stdio_relays,
            watcher,
            agent: agent.take(),
            killing: std::sync::atomic::AtomicBool::new(false),
            seccomp_filters: None,
        };
        // The proxy starts only now that the backend exists,
        // so the descriptor limit it raises never reaches the child.
        if let Some(agent) = boundary.agent.as_mut()
            && let Err(err) = agent.start_proxy()
        {
            boundary.teardown();
            return Err(err);
        }
        if let Some(reason) = boundary.cgroup_unavailable.clone() {
            for (key, ceiling) in [
                ("pids", &boundary.snapshot.limits.pids),
                ("mem", &boundary.snapshot.limits.mem),
                ("swap", &boundary.snapshot.limits.swap),
                ("cpu", &boundary.snapshot.limits.cpu),
            ] {
                if ceiling.is_some() {
                    boundary.audit.record_limit_unapplied(key, &reason);
                }
            }
        }

        if let Err(err) = boundary.discover(bwrap_path, deadline, &filter_digest, &scan) {
            boundary.teardown();
            return Err(err);
        }
        // Audit 2026-10-08 M2: storage and inode ceilings expose occupancy,
        // not refusal counters — their hit evidence is positive-only
        // saturation sampling (§11.4), so the `limits` class starts degraded
        // with a null count and names its gap.
        if boundary
            .storage
            .as_ref()
            .is_some_and(|storage| storage.limits().iter().any(|limit| limit.hit.is_none()))
        {
            boundary
                .audit
                .record_limit_evidence_missing("storage_hit_evidence_positive_only");
        }
        if let Some(leaf) = boundary.cgroup.as_mut()
            && let Err(err) = leaf
                .verify_member(boundary.launcher.pid)
                .and_then(|()| leaf.verify_member(boundary.bwrap_pid))
                .and_then(|()| leaf.verify_member(boundary.init_pid))
                .and_then(|()| leaf.arm())
        {
            // Placement can have succeeded before read-back failed. Never
            // discard that leaf and claim the target has no resource boundary.
            boundary.teardown();
            return Err(preparing(
                ErrorCode::MissingCapability,
                format!("target cgroup placement failed: {err}"),
            ));
        }
        if let Some(plan) = boundary.observer_plan.as_ref() {
            // §13.1: gap intervals count from supervisor start on the same
            // CLOCK_BOOTTIME base as every other monotonic_ns. §11.4: the
            // bounds are the plan's, which the receipt records.
            let mut config = plan.tracer_config(clock::mark_supervisor_start());
            // Audit 2026-09-25-2, S14: the tracer expects exactly the data
            // this attempt's narrowing filter carries.
            config.trace_data = boundary.trace_data;
            config.learning = boundary.snapshot.observation.learning;
            config.commands = boundary.snapshot.commands.clone();
            config.target = Some((boundary.launcher.pid, boundary.target_images.clone()));
            match Tracer::attach(boundary.launcher.pid, config) {
                Ok(tracer) => boundary.tracer = Some(tracer),
                Err(err) => {
                    boundary.teardown();
                    // §11.4: an observer that cannot attach refuses before
                    // exec, whatever the evidence mode says.
                    return Err(error(
                        ErrorCode::ObserverUnavailable,
                        ErrorStage::Preparing,
                        Remediation::HostSetup,
                        format!("the closed-set observer could not attach: {err}"),
                    ));
                }
            }
        }
        Ok(boundary)
    }

    /// Finds the namespace init and the launcher, and reads back what the
    /// boundary actually applied.
    fn discover(
        &mut self,
        bwrap_path: &Path,
        deadline: clock::Deadline,
        filter_digest: &str,
        scan: &jfs::ProtectedScan,
    ) -> Result<(), JailError> {
        // bubblewrap reports the namespace init's host pid as soon as the
        // namespaces exist. Waiting on that document is the synchronisation
        // point; nothing here guesses a delay.
        let init_pid = loop {
            self.status.pump();
            if let Some(pid) = self.status.parsed().child_pid {
                break pid;
            }
            if self.status.eof || self.exited() {
                let diagnostic = self.diagnostic().trim().to_owned();
                let detail = if diagnostic.is_empty() {
                    // bwrap's own message (for example "Unknown option")
                    // went to this console's stderr, which the supervisor
                    // passes through untouched; the error must still say
                    // something useful instead of ending on a colon.
                    let status = self
                        .child
                        .as_mut()
                        .and_then(|child| child.try_wait().ok().flatten())
                        .and_then(|wait| wait.code().map(|code| format!("exit {code}")))
                        .unwrap_or_else(|| "no wait status".to_owned());
                    format!(
                        "bubblewrap exited during setup ({status}) without a status \
                         document; its own stderr on this console names the cause"
                    )
                } else {
                    format!("bubblewrap exited during setup: {diagnostic}")
                };
                return Err(preparing(ErrorCode::BackendUnavailable, detail));
            }
            if deadline.expired() {
                return Err(prepare_timeout(
                    "bubblewrap did not report a namespace init",
                ));
            }
            nap();
        };
        self.init_pid = init_pid;
        // Taken now, while the kernel has just named this pid as the
        // namespace init: every later signal and liveness check goes through
        // the descriptor, so neither can reach a process that merely
        // inherited the number. Without it the tree's death could not be
        // verified, so its absence refuses.
        self.init_fd = Some(identity::pidfd_open(init_pid).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the namespace init's pidfd could not be opened: {err}"),
            )
        })?);

        // The launcher is the init's child whose argv is the one we asked for.
        let launcher = loop {
            if let Some(pid) = super::tracer::children(init_pid)
                .into_iter()
                .find(|pid| super::tracer::cmdline(*pid).as_ref() == Some(&self.launcher_argv))
            {
                break pid;
            }
            if deadline.expired() {
                return Err(prepare_timeout("the inside launcher never appeared"));
            }
            if self.exited() {
                return Err(self.launcher_setup_failure());
            }
            nap();
        };

        // Wait until it is blocked in read(2) on its release descriptor,
        // which is what the observer's attach contract requires.
        // `/proc/<pid>/syscall` names the call and its first argument, so
        // this is a read-back and not an assumption. The descriptor is part
        // of the check: the launcher reads its trace-data descriptor before
        // it installs the narrowing filter, and that read is not the gate.
        loop {
            if matches!(identity::blocked_in_read(launcher, RELEASE_FD), Ok(true)) {
                break;
            }
            if deadline.expired() {
                return Err(prepare_timeout(
                    "the inside launcher did not block on its release pipe",
                ));
            }
            if self.exited() {
                return Err(self.launcher_setup_failure());
            }
            nap();
        }

        self.launcher = identity::ProcessIdentity::capture(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's identity could not be recorded: {err}"),
            )
        })?;
        // The cooperative stop and the `agent` mediation hand-off go through
        // this descriptor; without it neither could, so its absence refuses.
        let launcher_fd = identity::pidfd_open(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's pidfd could not be opened: {err}"),
            )
        })?;
        // bubblewrap reports the namespace ids it created; `/proc` says which
        // namespaces the launcher is actually in. Recording the first without
        // checking the second would be taking the backend's word for the
        // boundary, so both are read and they must agree.
        self.ns_ids = identity::ns_ids(launcher);
        // Every namespace the plan asked for has to be one the launcher is
        // actually in, and a different one from this process's.
        // SAFETY: getpid takes no arguments and cannot fail.
        let own = identity::ns_ids(unsafe { libc::getpid() });
        for (name, inside, outside) in [
            ("pid", self.ns_ids.pid, own.pid),
            ("mnt", self.ns_ids.mnt, own.mnt),
            ("net", self.ns_ids.net, own.net),
            ("user", self.ns_ids.user, own.user),
            ("cgroup", self.ns_ids.cgroup, own.cgroup),
        ] {
            match (inside, outside) {
                (Some(inside), Some(outside)) if inside == outside => {
                    return Err(preparing(
                        ErrorCode::BackendUnavailable,
                        format!("the launcher shares this process's {name} namespace"),
                    ));
                }
                (None, _) => {
                    return Err(preparing(
                        ErrorCode::BackendUnavailable,
                        format!("the launcher's {name} namespace could not be read"),
                    ));
                }
                _ => {}
            }
        }
        for (key, seen) in [
            ("pid-namespace", self.ns_ids.pid),
            ("mnt-namespace", self.ns_ids.mnt),
            ("net-namespace", self.ns_ids.net),
        ] {
            let reported = self.status.namespace(key);
            if let (Some(reported), Some(seen)) = (reported, seen)
                && reported != seen
            {
                return Err(preparing(
                    ErrorCode::BackendUnavailable,
                    format!("the backend reports {key} {reported} but the launcher is in {seen}"),
                ));
            }
        }

        // Read back the boundary rather than trusting the flags we passed.
        // The launcher is blocked: these facts come from one kernel status
        // snapshot rather than reopening the same file for every field.
        let privilege = identity::Privilege::read(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's privilege cannot be read back: {err}"),
            )
        })?;
        if !privilege.no_new_privs {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                "no_new_privs is not set inside the boundary",
            ));
        }
        if privilege.cap_eff != 0 {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!(
                    "the boundary retains capabilities: CapEff {:016x}",
                    privilege.cap_eff
                ),
            ));
        }
        if privilege.seccomp.as_deref() != Some("2") {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!(
                    "the syscall filter is not in force: Seccomp {:?}",
                    privilege.seccomp
                ),
            ));
        }
        // The J2 gap — `Seccomp: 2` says a filter is in
        // force, not that every filter this boundary installs is: a missing
        // narrowing or mediation filter leaves the mode at 2. The count is
        // read back and must be exactly the number installed.
        let expected =
            super::agent::expected_launcher_filters(self.agent.is_some(), self.observe_on);
        self.seccomp_filters = Some(
            super::agent::verify_filter_count(
                privilege.seccomp_filters.as_deref().unwrap_or_default(),
                expected,
            )
            .map_err(|mut error| {
                error.message = format!("the launcher: {}", error.message);
                error
            })?,
        );
        let nspid = super::tracer::nspid(launcher).unwrap_or_default();
        if nspid.len() < 2 {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher is not inside a pid namespace: NSpid {nspid:?}"),
            ));
        }

        // While the launcher is blocked, take its mediation
        // listener and sock_diag socket, start the mediator, and read back
        // the bridge it started (§10). Either one missing refuses, naming it.
        if let Some(agent) = self.agent.as_mut() {
            agent.take_mediation(std::os::fd::AsFd::as_fd(&launcher_fd))?;
            let bridge = agent.discover_bridge(self.init_pid, self.ns_ids, &deadline)?;
            if let Some(leaf) = self.cgroup.as_ref() {
                // Charged to the attempt (§9.3): the bridge is in the leaf.
                leaf.verify_member(bridge).map_err(|err| {
                    preparing(
                        ErrorCode::MissingCapability,
                        format!(
                            "the `agent` bridge could not be established: it is not in the \
                             attempt's cgroup: {err}"
                        ),
                    )
                })?;
            }
        }
        self.launcher_fd = Some(launcher_fd);

        // Keep this fresh readback: a process can create a new platform after
        // a backend upgrade, while its minimum-version decision is cached.
        self.backend_version = bwrap::bwrap_version(bwrap_path)
            .map(|version| version.raw)
            .unwrap_or_default();

        if super::storage::requested(&self.snapshot.limits) {
            self.storage = Some(
                super::storage::Storage::admit(launcher, &self.snapshot.limits, deadline).map_err(
                    |err| {
                        preparing(
                            ErrorCode::MissingCapability,
                            format!("storage ceiling unavailable: {err}"),
                        )
                    },
                )?,
            );
        }
        self.applied = self.read_applied(launcher, filter_digest, scan)?;
        Ok(())
    }

    // Why the launcher ended before it blocked
    /// The refusal for a backend that ended before the launcher blocked.
    /// The agent launcher's own setup failures carry their exit status and
    /// errno, so the refusal names the mechanism that could not be
    /// established instead of a generic backend failure.
    fn launcher_setup_failure(&mut self) -> JailError {
        self.status.pump();
        let (mut errno_bytes, mut eof) = (Vec::new(), false);
        shared::drain_error_pipe(&self.error, &mut errno_bytes, &mut eof);
        launcher_failure(
            self.status.parsed().exit_code,
            &errno_bytes,
            self.diagnostic().trim(),
        )
    }

    /// The `applied` group, read back from the boundary that exists. A
    /// read-back that fails refuses: an empty mount table or environment in
    /// the receipt would be a claim about the child's view nothing measured.
    fn read_applied(
        &self,
        launcher: libc::pid_t,
        filter_digest: &str,
        scan: &jfs::ProtectedScan,
    ) -> Result<Applied, JailError> {
        let mounts = read_mount_table(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's mount table cannot be read back: {err}"),
            )
        })?;
        let environment_names = read_environment_names(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's environment cannot be read back: {err}"),
            )
        })?;
        let mut limits = Vec::new();
        if let Some(storage) = &self.storage {
            limits.extend(storage.limits());
        }
        limits.extend(shared::ceiling_rows(
            &self.snapshot.limits,
            self.cgroup.as_ref(),
        ));
        let mut mounts = mounts;
        // A protected name the walk refused to follow is authority this plan
        // did not apply. The mount table is where §13.2 lists what the child's
        // view is, and `hidden` is the mode the schema has for a path that is
        // named and not granted, so each one appears there rather than being
        // left out of the record entirely.
        for name in skipped_protected_names(scan) {
            let path = self.workspace_bytes_joined(&name);
            if let Ok(native) = NativeString::from_bytes(path) {
                mounts.push(AppliedMount {
                    path: native,
                    mode: "hidden".to_owned(),
                });
            }
        }
        Ok(Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "bubblewrap-binds".to_owned(),
                protected_coverage: if self.snapshot.filesystem.protected_coverage
                    == ProtectedCoverage::None
                {
                    // Audit 2026-09-25-2, S5: nothing was requested or
                    // scanned, so the walk's vacuous pass must not be
                    // reported as existing-and-covered.
                    "none".to_owned()
                } else {
                    scan_coverage(scan)
                },
                mounts,
            }),
            // The agent network and its two stacked filters
            network: self.agent.as_ref().map_or_else(
                || AppliedNetwork {
                    mode: "none".to_owned(),
                    mechanism: Some("network-namespace".to_owned()),
                    allowed_hosts: Vec::new(),
                },
                super::agent::AgentNet::applied_network,
            ),
            syscalls: Some(AppliedSyscalls {
                mechanism: if self.agent.is_some() {
                    "seccomp-bpf+seccomp-user-notification".to_owned()
                } else {
                    "seccomp-bpf".to_owned()
                },
                digest: filter_digest.to_owned(),
            }),
            limits,
            environment_names,
            removed_environment_names: Vec::new(),
        })
    }

    /// A workspace-relative name as the absolute bytes the child sees.
    fn workspace_bytes_joined(&self, relative: &str) -> Vec<u8> {
        let mut out = self.workspace.as_os_str().as_bytes().to_vec();
        if out.last() != Some(&b'/') {
            out.push(b'/');
        }
        out.extend_from_slice(relative.as_bytes());
        out
    }

    fn diagnostic(&self) -> String {
        self.status.text.clone()
    }

    /// Whether the backend has exited, collecting its status. Only for
    /// discovery: from the observer's attach on, its thread owns every
    /// `waitpid` in this process.
    fn exited(&mut self) -> bool {
        debug_assert!(self.tracer.is_none(), "the observer owns waitpid");
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    }

    /// Kills and reaps everything this boundary owns.
    fn teardown(&mut self) {
        let deadline = clock::Deadline::after(TREE_BUDGET);
        self.kill_boundary();
        self.stop_observer(deadline.remaining());
        if let Some(mut child) = self.child.take() {
            child.reap_until(deadline);
        }
        while !self.watcher.ended() && !deadline.expired() {
            self.release_watcher_after_backend();
            std::thread::sleep(WAIT_STEP);
        }
        self.watcher.reap();
        self.remove_placeholders();
        self.stop_agent(deadline.remaining());
    }

    // The agent network ends after the tree it served
    /// Stops the proxy and the mediator, draining what they last reported.
    /// Called once the tree is dead or given up on: until then the proxy and
    /// the mediator are part of the boundary the child relies on.
    fn stop_agent(&mut self, budget: Duration) {
        if let Some(agent) = self.agent.as_mut() {
            agent.stop(
                &mut self.audit,
                self.observe_on,
                budget.min(AGENT_STOP_BUDGET),
            );
        }
    }

    /// Mediated connects and helper facts, while the target runs; the
    /// reason of a new evidence loss, when there is one.
    fn pump_agent(&mut self) -> Option<String> {
        let (init_pid, init_fd, killing) = (self.init_pid, self.init_fd.as_ref(), &self.killing);
        // Asked only once the bridge is seen dead: the boundary was up after
        // the bridge died, so the bridge did not die with it. A namespace
        // init sets PF_EXITING before it kills its namespace, and this
        // supervisor sets `killing` before it kills anything.
        let boundary_up = || {
            super::agent::boundary_up(
                killing.load(std::sync::atomic::Ordering::SeqCst),
                &|| init_fd.is_none_or(|fd| super::watch::readable(fd.as_raw_fd())),
                &|| identity::exiting(init_pid),
            )
        };
        let agent = self.agent.as_mut()?;
        agent.pump(&mut self.audit, self.observe_on, &boundary_up)
    }

    /// Kills the namespace init and the backend through their descriptors.
    ///
    /// §9.3: never signal a pid without revalidating its identity. A pidfd
    /// taken at discovery is that revalidation made permanent — the kernel
    /// refuses to deliver through it once the process is gone, so no signal of
    /// this attempt's can land on whatever later holds the number. Killing the
    /// init makes the kernel kill the namespace; the backend outside it goes
    /// too.
    fn kill_boundary(&self) {
        self.killing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(leaf) = &self.cgroup {
            let _ = leaf.kill();
        }
        for fd in self.init_fd.iter().chain([&self.bwrap_fd]) {
            let _ = identity::pidfd_send_signal(fd.as_raw_fd(), libc::SIGKILL);
        }
    }

    /// Stops the observer within `budget` and keeps its account.
    ///
    /// `finish_within` always returns: it interrupts the tracer thread, gives
    /// a live tree up to `budget` to end, and on expiry kills what is left
    /// and says how much it had to kill. Draining the channel first matters
    /// because finishing drops the receiver with whatever is still in it.
    fn stop_observer(&mut self, budget: Duration) {
        let Some(tracer) = self.tracer.take() else {
            return;
        };
        let target = super::observed::Target {
            launcher: self.launcher.pid,
            images: &self.target_images,
        };
        // Late facts change nothing here: the run loop has already ended.
        let summary = super::observed::stop(tracer, budget, &mut self.audit, &target, |_| {});
        self.tracer_summary = Some(summary);
    }

    /// Whether the observer's own account permits a claim of tree death.
    fn observer_verified_the_tree(&self) -> bool {
        observer_verdict(self.tracer_summary.as_ref())
    }

    fn remove_placeholders(&mut self) {
        if init_alive(self.init_fd.as_ref(), self.init_pid)
            || !self.observer_verified_the_tree()
            || !self.cgroup_empty()
        {
            return;
        }
        if self.placeholder_outcomes.is_empty() {
            self.placeholder_outcomes = self
                .placeholders
                .iter()
                .map(Placeholder::remove_if_unchanged)
                .collect();
        }
    }

    // A verified teardown for a boundary whose target never
    // ran (abort, failed release; §13.2 row 4)
    /// Kills the boundary and reports whether its death was verified.
    ///
    /// Verified means exactly what settlement requires, without the target:
    /// the namespace init's pidfd reports its death (PID-namespace semantics:
    /// every other member, the blocked launcher included, died first); the
    /// backend (this supervisor's child) and the outside watcher are dead and
    /// reaped; the execution cgroup, when one exists, was observed
    /// unpopulated and its identity was never lost; and the observer, when
    /// attached, finished without abandoning a tracee or losing a child's
    /// status. Everything is polled within one tree budget; whatever is still
    /// unknown at its end leaves the tree `pending` and `tree_empty` null.
    /// "The trusted launcher died" is not on the list: it is implied by the
    /// init's death and proves nothing without it.
    fn verified_teardown(&mut self) -> TreeObservation {
        let deadline = clock::Deadline::after(TREE_BUDGET);
        self.kill_boundary();
        // The observer is stopped first, so after this nothing but this
        // thread waits for children; its account is kept for the verdict.
        self.stop_observer(deadline.remaining());
        // The target never ran; nothing is left to serve
        self.stop_agent(deadline.remaining());
        let backend_reaped = match self.child.take() {
            Some(mut child) => {
                child.reap_until(deadline);
                match child.try_wait() {
                    Ok(Some(_)) => true,
                    // The tracer's `waitpid(-1)` reaped it before it was
                    // stopped. Nothing else in this process waits, so an
                    // exited backend whose status is gone was reaped here.
                    Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                        self.backend_exited()
                    }
                    _ => false,
                }
            }
            None => false,
        };
        let init_dead = || {
            self.init_fd
                .as_ref()
                .is_some_and(|fd| super::watch::readable(fd.as_raw_fd()))
        };
        loop {
            // As release_watcher_after_backend, by field: `init_dead` holds
            // a borrow of the init's pidfd.
            if super::watch::readable(self.bwrap_fd.as_raw_fd()) {
                self.watcher.release();
            }
            let settled = init_dead() && self.watcher.ended() && self.cgroup_empty();
            if settled || deadline.expired() {
                break;
            }
            std::thread::sleep(WAIT_STEP);
        }
        self.watcher.reap();
        let watcher_reaped = self.watcher.ended();
        // The observer's own account, with one difference from settlement:
        // its "unreaped children" are this supervisor's own children (the
        // backend and the watcher) that were still exiting when it stopped.
        // Here they were reaped above, by this thread, so that loss has a
        // route after all. Any other unreaped child, an abandoned tracee or
        // a panicked observer still refuses the verdict.
        let verified = abort_verdict(&AbortInputs {
            backend_reaped,
            watcher_reaped,
            init_dead: init_dead(),
            cgroup_empty: self.cgroup_empty(),
            abandoned_tracees: self
                .tracer_summary
                .as_ref()
                .map_or(0, |summary| summary.loss.abandoned_tracees),
            observer_panicked: self
                .tracer_summary
                .as_ref()
                .is_some_and(|summary| summary.thread_panicked),
            unreaped_children: self
                .tracer_summary
                .as_ref()
                .map(|summary| summary.unreaped_children.clone())
                .unwrap_or_default(),
            // Security 2026-09-27 (audit 3 A5): carried for the receipt; never a
            // verdict input, because the stop was continued and nothing was
            // lost.
            requested_by_other_filters: self
                .tracer_summary
                .as_ref()
                .map_or(0, |summary| summary.requested_by_other_filters),
            backend_pid: self.bwrap_pid,
            watcher_pid: i32::try_from(self.watcher.pid()).unwrap_or(-1),
        });
        // Placeholders go only once the tree is known dead, and on this
        // verdict rather than the settlement-time one, whose observer check
        // would count the children reaped above as lost.
        if verified && self.placeholder_outcomes.is_empty() {
            self.placeholder_outcomes = self
                .placeholders
                .iter()
                .map(Placeholder::remove_if_unchanged)
                .collect();
        }
        if verified {
            TreeObservation {
                tree_empty: Some(true),
                verified_at: Some(SystemTime::now()),
                verification_scope: "attempt_tree".to_owned(),
                integrity: "verified".to_owned(),
            }
        } else {
            TreeObservation {
                tree_empty: None,
                verified_at: None,
                verification_scope: "attempt_tree".to_owned(),
                integrity: if self.cgroup_lost { "lost" } else { "pending" }.to_owned(),
            }
        }
    }

    fn boundary_identity(&self) -> BoundaryIdentity {
        let mut details = Map::new();
        if self
            .snapshot
            .launch
            .as_ref()
            .is_some_and(|l| l.credentials.iter().any(|c| c.mode == "vault"))
        {
            details.insert("credential_injection".into(), Value::from("mitm_ca"));
        }
        details.insert("backend_exec_by".to_owned(), Value::from("descriptor"));
        details.insert(
            "command_rules".into(),
            serde_json::json!({
                "deny": self.snapshot.commands.deny.len(),
                "forbid": self.snapshot.commands.forbid.len(),
            }),
        );
        details.insert(
            "resolv_sanitization".to_owned(),
            Value::from(self.resolv_sanitization),
        );
        details.insert("watcher_pid".to_owned(), Value::from(self.watcher.pid()));
        // J4 autoscope: §9.3 — where the supervisor stood when the leaf was
        // made: already delegated, entered a scope of its own, or why not.
        details.insert("supervisor_scope".to_owned(), super::scope::details());
        details.insert(
            "bootstrap_spawn".to_owned(),
            self.bootstrap_spawn.evidence(),
        );
        details.insert(
            "execution_cgroup".to_owned(),
            match &self.cgroup {
                // The bridge is a helper charged to the leaf
                Some(leaf) => {
                    let mut registration = leaf.registration(self.bwrap_pid, self.init_pid);
                    if let Some(bridge) = self
                        .agent
                        .as_ref()
                        .and_then(super::agent::AgentNet::bridge_pid)
                        && let Some(helpers) = registration
                            .get_mut("charged_helpers")
                            .and_then(Value::as_array_mut)
                    {
                        helpers.push(serde_json::json!({"role": "bridge", "pid": bridge}));
                    }
                    registration
                }
                None => serde_json::json!({
                    "unavailable": self
                        .cgroup_unavailable
                        .as_deref()
                        .unwrap_or("not attempted"),
                }),
            },
        );
        details.insert(
            "bwrap_pid".to_owned(),
            Value::from(i64::from(self.bwrap_pid)),
        );
        if let Some(storage) = &self.storage {
            details.insert("storage_ceiling".to_owned(), storage.evidence());
        }
        details.insert(
            "readonly_open_fast_path".to_owned(),
            Value::from(self.observe_on && !self.snapshot.observation.learning),
        );
        details.insert(
            "namespace_init_pid".to_owned(),
            Value::from(i64::from(self.init_pid)),
        );
        details.insert(
            "launcher_pid".to_owned(),
            Value::from(i64::from(self.launcher.pid)),
        );
        // Two filters are in force and they are not the same program: the
        // baseline bubblewrap loads, recorded in `applied.syscalls`, and the
        // observer's narrowing filter the launcher installs. The receipt names
        // both, by the digest each of them reports for itself. Security
        // 2026-09-27 (audit 4 B9): `narrowing_filter_digest` names the
        // canonical program the published table freezes, and
        // `narrowing_filter_digest_installed` names the bytes this attempt
        // **installed** — the launcher installs the filter carrying the
        // per-attempt trace data (audit 2026-09-25-2, S14), so the canonical
        // digest alone no longer identifies the running program.
        details.insert(
            "narrowing_filter_digest".to_owned(),
            if self.observe_on {
                Value::from(super::tracer::narrowing_filter_digest())
            } else {
                Value::Null
            },
        );
        details.insert(
            "narrowing_filter_digest_installed".to_owned(),
            if self.observe_on {
                Value::from(super::tracer::filter::narrowing_filter_digest_for(
                    self.trace_data,
                    self.snapshot.observation.learning,
                ))
            } else {
                Value::Null
            },
        );
        // §11.4: "Record actual values in the observer plan."
        details.insert(
            "observer_plan".to_owned(),
            self.observer_plan
                .as_ref()
                .map_or(Value::Null, super::observed::ObserverPlan::details),
        );
        // The filter count read back, and the agent network
        details.insert(
            "seccomp_filters".to_owned(),
            self.seccomp_filters.map_or(Value::Null, |count| {
                serde_json::json!({
                    "expected": super::agent::expected_launcher_filters(
                        self.agent.is_some(),
                        self.observe_on,
                    ),
                    "observed": count,
                })
            }),
        );
        if let Some(agent) = self.agent.as_ref() {
            let (agent_details, helpers) = agent.details();
            details.insert("agent".to_owned(), agent_details);
            details.insert("helpers".to_owned(), helpers);
        }
        for (key, value) in [
            ("pid_namespace", self.ns_ids.pid),
            ("mnt_namespace", self.ns_ids.mnt),
            ("net_namespace", self.ns_ids.net),
            ("user_namespace", self.ns_ids.user),
            ("cgroup_namespace", self.ns_ids.cgroup),
        ] {
            details.insert(key.to_owned(), value.map_or(Value::Null, Value::from));
        }
        let mut identity_value = Map::new();
        identity_value.insert("pid".to_owned(), Value::from(i64::from(self.launcher.pid)));
        identity_value.insert(
            "boot_id".to_owned(),
            Value::from(self.launcher.boot_id.clone()),
        );
        identity_value.insert(
            "start_time_ticks".to_owned(),
            Value::from(self.launcher.start_time_ticks),
        );
        BoundaryIdentity {
            boundary: "pid_namespace".to_owned(),
            verification_scope: "attempt_tree".to_owned(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details,
            }),
            process: Some(ProcessRecord {
                pid: u32::try_from(self.launcher.pid).unwrap_or(0),
                identity: RecordIdentity {
                    kind: "linux_boot_start".to_owned(),
                    value: identity_value,
                },
            }),
            backend: Some("bubblewrap".to_owned()),
            backend_version: (!self.backend_version.is_empty())
                .then(|| self.backend_version.clone()),
        }
    }
}

fn prepare_timeout(message: &str) -> JailError {
    error(
        ErrorCode::PrepareTimeout,
        ErrorStage::Preparing,
        Remediation::Retry,
        message.to_owned(),
    )
}

/// A 200 microsecond pause between polls that have no one descriptor to
/// wait on: a `/proc` read, or several sources checked together (the
/// backend's status pipe and its exit). Every such loop is bounded by a
/// deadline.
fn nap() {
    std::thread::sleep(Duration::from_micros(200));
}

// Naming the mechanism a launcher could not establish
/// The refusal for a launcher that ended before it blocked, from its exit
/// status (as bubblewrap reported it) and the errno it wrote: the agent
/// launcher's mediation and bridge failures name themselves; anything else
/// is the backend's.
fn launcher_failure(exit_code: Option<i32>, errno_bytes: &[u8], diagnostic: &str) -> JailError {
    let errno = super::launch::decode_error_report(errno_bytes)
        .map_or("no errno reported".into(), super::sys::errno_name);
    match exit_code {
        Some(super::launch::EXIT_MEDIATION_FAILED) => preparing(
            ErrorCode::MissingCapability,
            format!(
                "the `agent` unix-peer mediation could not be established: the launcher could \
                 not install the mediation filter with its listener or open sock_diag ({errno})"
            ),
        ),
        Some(super::launch::EXIT_BRIDGE_FAILED) => preparing(
            ErrorCode::MissingCapability,
            format!(
                "the `agent` bridge could not be established: the launcher could not start it \
                 ({errno})"
            ),
        ),
        _ => preparing(
            ErrorCode::BackendUnavailable,
            format!("bubblewrap exited before the launcher blocked: {diagnostic}"),
        ),
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL take scalars and dereference nothing.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_all(fd: RawFd, bytes: &[u8]) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: the pointer and length address the remaining bytes of a live
        // slice.
        let n = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(written).cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        written += usize::try_from(n).unwrap_or(0);
    }
    Ok(())
}

/// Setup channels obey the preparation deadline even if a helper stops
/// reading while retaining its descriptor.
fn write_until(fd: RawFd, bytes: &[u8], deadline: clock::Deadline) -> std::io::Result<()> {
    set_nonblocking(fd)?;
    let mut remaining = bytes;
    while !remaining.is_empty() {
        if deadline.expired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "backend argument delivery timed out",
            ));
        }
        // SAFETY: the descriptor is owned by the caller, and this slice is live.
        let n = unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if n > 0 {
            remaining = &remaining[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one initialized pollfd, bounded by the deadline.
                unsafe {
                    libc::poll(&raw mut pfd, 1, deadline.remaining_millis_capped(10));
                }
            }
            _ => return Err(error),
        }
    }
    Ok(())
}

/// Accepts an existing directory as it is, or creates it (and its missing
/// parents) private. Only for directories that are not supervisor state:
/// [`crate::state::create_private_dir`] checks those, ancestors included.
fn ensure_dir(path: &Path) -> Result<(), JailError> {
    use std::os::unix::fs::DirBuilderExt as _;
    if path.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|err| {
            error(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("{} could not be created: {err}", path.display()),
            )
        })
}

/// §8.3 and §9.2: reject socket, directory and anonymous-inode stdio, and
/// regular-file stdio that resolves into protected supervisor state or the
/// operator's trusted config directory (audit 2026-10-08 H1). Every other
/// regular file is relayed through a supervisor-owned pipe; everything else
/// passes through untouched.
///
/// `state_root` is the whole runtime state directory, not just this attempt's
/// own: a redirect into a sibling attempt's receipts is the same disclosure.
/// `config_dir` holds `config.toml` and `launch/`, the trusted widening
/// inputs: a redirect of any of the three streams there would have the
/// supervisor itself copy child bytes into (or out of) files later runs
/// trust, so it refuses like the state root even under the relay.
///
/// The relay (audit 2026-10-08 H1 follow-up) closes the reopen hole: the
/// sandbox has its own `/proc`, and a regular file inherited directly is
/// reopenable through `/dev/stdin` against the inode's permission bits and
/// the host mount — never the descriptor's open mode — which is
/// write-and-truncate authority outside every grant (§9.1's closed view,
/// §6.4's uncharged write). A pipe end is not reopenable at all, so the
/// child never learns the file, its path, or its permissions; the
/// supervisor's copies run on the operator's own descriptor, preserving its
/// open mode and offset.
///
/// A descriptor that cannot be inspected refuses rather than passing, because
/// "I could not tell what this is" is not a reason to hand it to the child.
fn validate_stdio(state_root: &Path, config_dir: &Path) -> Result<[StdioPlan; 3], JailError> {
    let state_root = state_root.canonicalize();
    let config_dir = config_dir.canonicalize();
    let mut plans = [StdioPlan::Pass, StdioPlan::Pass, StdioPlan::Pass];
    for fd in [0, 1, 2] {
        let name = match fd {
            0 => "stdin",
            1 => "stdout",
            _ => "stderr",
        };
        let refuse = |message: String| {
            Err(error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                message,
            ))
        };
        let mut st = super::sys::empty_stat();
        // SAFETY: `st` is a writable stat buffer; fstat dereferences nothing
        // else.
        if unsafe { libc::fstat(fd, &raw mut st) } != 0 {
            let errno = super::sys::last_errno();
            return refuse(format!(
                "{name} cannot be inspected ({}), so what the child would inherit is unknown",
                super::sys::errno_name(errno)
            ));
        }
        let kind = st.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            return refuse(format!(
                "{name} is a directory, which a contained run refuses"
            ));
        }
        // A socket is bridged through a supervisor-owned pipe (issue draft
        // 11): socketpairs are how supervisors, systemd units and test
        // harnesses hand a child its stdio, and the pipe keeps the child
        // from using the socket for anything but byte I/O (no recvmsg, no
        // descriptor passing) exactly as for a regular file.
        if kind == libc::S_IFSOCK {
            plans[fd as usize] = StdioPlan::Relay { socket: true };
        }
        // An inherited io_uring ring can issue operations through the ring
        // even when the child's io_uring syscalls are blocked. All Linux
        // anonymous inodes are private supervisor handles, never stdio.
        let fd_target = std::fs::read_link(format!("/proc/self/fd/{fd}")).map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("{name} descriptor target cannot be inspected: {err}"),
            )
        })?;
        if fd_target.as_os_str().as_bytes().starts_with(b"anon_inode:") {
            return refuse(format!(
                "{name} is an anonymous inode and cannot be inherited"
            ));
        }
        if kind == libc::S_IFREG {
            let target = fd_target.canonicalize().unwrap_or(fd_target);
            if let Ok(state_root) = state_root.as_ref()
                && target.starts_with(state_root)
            {
                return refuse(format!("{name} resolves into the runtime state root"));
            }
            if let Ok(config_dir) = config_dir.as_ref()
                && target.starts_with(config_dir)
            {
                return refuse(format!(
                    "{name} resolves into the trusted config directory (config.toml and \
                     launch profiles are trusted input)"
                ));
            }
            plans[fd as usize] = StdioPlan::Relay { socket: false };
        }
    }
    Ok(plans)
}

/// What the child inherits on one stdio stream (audit 2026-10-08 H1).
#[derive(Clone, Copy, PartialEq, Eq)]
enum StdioPlan {
    /// Passed through untouched: a tty, a pipe, `/dev/null`.
    Pass,
    /// A regular file or socket, relayed through a supervisor-owned pipe.
    Relay { socket: bool },
}

/// One relayed stdio stream (audit 2026-10-08 H1 follow-up): the child holds
/// one end of a supervisor-owned pipe; the supervisor copies between the
/// pipe and the operator's original descriptor, which keeps its open mode
/// and offset. The child never owns a reopenable handle on the file.
struct StdioRelay {
    /// A duplicate of the operator's original descriptor, taken at spawn:
    /// the supervisor later points its own stdout elsewhere (§8.3,
    /// revision 19), and the relay must keep copying into what the
    /// operator actually opened.
    origin: OwnedFd,
    /// Sockets use per-call nonblocking I/O without changing the shared
    /// descriptor's flags.
    origin_socket: bool,
    /// This side of the pipe, non-blocking; `None` once closed.
    ours: Option<OwnedFd>,
    /// `true` for stdin (origin → child); `false` for stdout/stderr
    /// (child → origin).
    to_child: bool,
    /// Staged bytes between the two sides, bounded by [`RELAY_BUFFER`].
    buffer: Vec<u8>,
    /// The origin reached end-of-file (stdin direction).
    origin_eof: bool,
    /// The child's side closed (output directions), or the child's end was
    /// delivered (stdin direction): nothing more to move.
    finished: bool,
}

/// The staging bound per relayed stream: one pipe capacity, so a slow
/// consumer never grows supervisor memory.
const RELAY_BUFFER: usize = 1 << 16;

impl StdioRelay {
    /// Create the pipe for one stream and hand the child its end through the
    /// fixed descriptor map. The operator's descriptor is
    /// duplicated immediately, before the supervisor redirects its own
    /// copies (§8.3, revision 19).
    fn attach(
        fd: RawFd,
        to_child: bool,
        socket: bool,
        descriptors: &mut FdMap,
    ) -> Result<Self, JailError> {
        let (read_end, write_end) = exec::pipe().map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("a stdio stream could not be relayed through a pipe: {err}"),
            )
        })?;
        let (child_end, ours) = if to_child {
            (read_end, write_end)
        } else {
            (write_end, read_end)
        };
        // SAFETY: dup returns a newly owned descriptor, or -1 on failure
        // which is checked before it is owned.
        let duped = unsafe { libc::dup(fd) };
        if duped < 0 {
            return Err(error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                "the operator's stdio descriptor could not be kept for the relay".to_owned(),
            ));
        }
        // SAFETY: `duped` was just created and is owned here.
        let origin = unsafe { OwnedFd::from_raw_fd(duped) };
        descriptors.add(child_end, fd).map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("a stdio relay descriptor could not be mapped: {err}"),
            )
        })?;
        set_nonblocking(ours.as_raw_fd()).map_err(|err| {
            error(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("a stdio relay pipe could not be made non-blocking: {err}"),
            )
        })?;
        Ok(Self {
            origin,
            origin_socket: socket,
            ours: Some(ours),
            to_child,
            buffer: Vec::with_capacity(RELAY_BUFFER),
            origin_eof: false,
            finished: false,
        })
    }

    /// Move as much as both sides accept right now. Returns `true` while
    /// progress was made, so the caller can shorten its sleep. Regular-file
    /// reads and writes block until complete, so each call is bounded by the
    /// buffer; pipe and socket operations are non-blocking.
    fn pump(&mut self) -> std::io::Result<bool> {
        let mut progress = false;
        if self.to_child {
            while !self.origin_eof && self.buffer.len() < RELAY_BUFFER {
                if !origin_ready(self.origin.as_raw_fd(), true) {
                    // A socket origin never blocks the pump loop (issue
                    // draft 11); a regular file is always ready.
                    break;
                }
                let mut chunk = [0u8; RELAY_BUFFER];
                let read = match relay_read(
                    self.origin.as_raw_fd(),
                    &mut chunk[..RELAY_BUFFER - self.buffer.len()],
                    self.origin_socket,
                ) {
                    Ok(read) => read,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err),
                };
                if read == 0 {
                    self.origin_eof = true;
                    break;
                }
                self.buffer.extend_from_slice(&chunk[..read]);
                progress = true;
            }
            if !self.buffer.is_empty()
                && let Some(ours) = self.ours.as_ref()
            {
                match relay_write(ours.as_raw_fd(), &self.buffer, false) {
                    Ok(written) => {
                        self.buffer.drain(..written);
                        progress = true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {
                        // A child may legitimately stop consuming stdin.
                        self.buffer.clear();
                        self.origin_eof = true;
                    }
                    Err(err) => return Err(err),
                }
            }
            if self.origin_eof && self.buffer.is_empty() {
                // Closing this side gives the child its end-of-file.
                self.ours = None;
                self.finished = true;
            }
        } else {
            while let Some(ours) = self.ours.as_ref() {
                if self.buffer.len() >= RELAY_BUFFER {
                    break;
                }
                let mut chunk = [0u8; RELAY_BUFFER];
                let read = match relay_read(
                    ours.as_raw_fd(),
                    &mut chunk[..RELAY_BUFFER - self.buffer.len()],
                    false,
                ) {
                    Ok(read) => read,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err),
                };
                if read > 0 {
                    self.buffer.extend_from_slice(&chunk[..read]);
                    progress = true;
                } else {
                    self.ours = None;
                    self.finished = true;
                    break;
                }
            }
            if !self.buffer.is_empty() && origin_ready(self.origin.as_raw_fd(), false) {
                match relay_write(self.origin.as_raw_fd(), &self.buffer, self.origin_socket) {
                    Ok(written) => {
                        self.buffer.drain(..written);
                        progress = true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(progress)
    }

    /// Whether both sides are done and nothing is staged.
    fn done(&self) -> bool {
        self.finished && self.buffer.is_empty()
    }
}

/// Whether a relay origin is ready to read (`for_read`) or write right now,
/// asked with a zero-timeout poll so a socket origin never blocks the pump
/// loop (issue draft 11). A regular file is always ready; a socket that
/// would block is simply visited again on a later pump.
fn origin_ready(fd: RawFd, for_read: bool) -> bool {
    let mut pollfd = libc::pollfd {
        fd,
        events: if for_read {
            libc::POLLIN
        } else {
            libc::POLLOUT
        },
        revents: 0,
    };
    // SAFETY: `pollfd` is a live, correctly sized struct; the timeout is
    // zero, so the call cannot block.
    let ready = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
    ready > 0
        && pollfd.revents & (libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0
}

fn relay_read(fd: RawFd, buffer: &mut [u8], socket: bool) -> std::io::Result<usize> {
    loop {
        // SAFETY: read writes only into this live writable slice.
        let read = unsafe {
            if socket {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            } else {
                libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len())
            }
        };
        if read >= 0 {
            return Ok(read as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn relay_write(fd: RawFd, buffer: &[u8], socket: bool) -> std::io::Result<usize> {
    loop {
        // SAFETY: write reads only from this live slice.
        let written = unsafe {
            if socket {
                libc::send(
                    fd,
                    buffer.as_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            } else {
                libc::write(fd, buffer.as_ptr().cast(), buffer.len())
            }
        };
        if written > 0 {
            return Ok(written as usize);
        }
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// How long relayed output gets, once the target has ended, to reach the
/// operator's descriptors before the outcome is recorded.
const OUTPUT_DRAIN_BUDGET: Duration = Duration::from_millis(250);
/// The pause between drain passes that moved nothing.
const OUTPUT_DRAIN_STEP: Duration = Duration::from_millis(1);

/// Delivers what the child wrote through the output relays, within
/// `budget`. Only output relays are waited for: a stdin relay finishes only
/// at its origin's end-of-file or a broken pipe, which the target's end does
/// not bring, so waiting for it would spend the whole budget on nothing. A
/// pass that moves nothing sleeps a step rather than spin.
fn drain_output_relays(relays: &mut [StdioRelay], budget: Duration) -> std::io::Result<()> {
    let deadline = clock::Deadline::after(budget);
    while relays.iter().any(|relay| !relay.to_child && !relay.done()) && !deadline.expired() {
        if !pump_stdio_relays(relays)? {
            std::thread::sleep(OUTPUT_DRAIN_STEP);
        }
    }
    Ok(())
}

/// Visit every stream, including when an earlier stream made progress.
fn pump_stdio_relays(relays: &mut [StdioRelay]) -> std::io::Result<bool> {
    let mut progress = false;
    let mut failure = None;
    for relay in relays {
        match relay.pump() {
            Ok(active) => progress |= active,
            Err(err) => {
                failure.get_or_insert(err);
            }
        }
    }
    failure.map_or(Ok(progress), Err)
}

/// The coverage the plan actually obtained, derived from the walk.
///
/// `existing_and_root` means every protected segment that existed at launch is
/// covered, plus the root-level literals. The walk earns that claim only if it
/// finished inside its bounds and skipped no protected name: a `.git` that was
/// a symlink is not followed and not covered, so a scan that met one has not
/// covered everything that existed and says `none` instead of overstating.
/// A segment created later, deeper in the tree, is outside the claim either
/// way (north-star §4.4).
// Vendor state is not a scanned root
/// The claim covers the scanned writable roots (the workspace, scratch and
/// operator `--rw` grants). Vendor state is attempt-private, removed at
/// settlement and never scanned, so it is outside the claim: a protected name
/// the child creates there protects nothing and is claimed by nothing.
fn scan_coverage(scan: &jfs::ProtectedScan) -> String {
    let within_bounds = scan.entries_seen <= jfs::ScanLimits::DEFAULT.max_entries
        && scan.max_depth_seen <= jfs::ScanLimits::DEFAULT.max_depth;
    if within_bounds && scan.skipped_symlinks.is_empty() {
        "existing_and_root".to_owned()
    } else {
        "none".to_owned()
    }
}

/// The protected names the walk would not follow, as workspace-relative
/// strings for the receipt.
fn skipped_protected_names(scan: &jfs::ProtectedScan) -> Vec<String> {
    scan.skipped_symlinks
        .iter()
        .filter_map(|path| path.strip_prefix(&scan.root).ok())
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

/// The most rows a receipt's mount table records. A boundary with more is
/// refused rather than recorded in part: a shortened table would still read
/// as the child's whole view (§13.2).
const MOUNT_TABLE_ROWS_MAX: usize = 1024;

/// The mount table the launcher actually sees, from `/proc/<pid>/mountinfo`
/// read as bytes (P01.8): one mount point that is not UTF-8 must not cost
/// the whole table.
///
/// # Errors
/// The read's error, or [`parse_mount_table`]'s.
fn read_mount_table(pid: libc::pid_t) -> std::io::Result<Vec<AppliedMount>> {
    parse_mount_table(&std::fs::read(format!("/proc/{pid}/mountinfo"))?)
}

/// The `(mount point, mode)` rows of a `mountinfo` file's bytes. Fields are
/// separated by single spaces; a space, tab, newline or backslash inside a
/// path is an octal escape, so splitting on the byte is exact.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidData`] for a row without a mount point and
/// options, a mount point holding a NUL, or more than
/// [`MOUNT_TABLE_ROWS_MAX`] rows: the table is read whole or not at all.
fn parse_mount_table(raw: &[u8]) -> std::io::Result<Vec<AppliedMount>> {
    let invalid = |what: String| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
    let mut out = Vec::new();
    for line in raw
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<&[u8]> = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect();
        let (Some(point), Some(options)) = (fields.get(4), fields.get(5)) else {
            return Err(invalid(format!(
                "a mountinfo row has {} fields, not a mount point and options",
                fields.len()
            )));
        };
        let mode = if options
            .split(|byte| *byte == b',')
            .any(|item| item == b"ro")
        {
            "ro"
        } else {
            "rw"
        };
        let native = NativeString::from_bytes(decode_mountinfo_path(point))
            .map_err(|_| invalid("a mount point holds a NUL byte".to_owned()))?;
        if out.len() == MOUNT_TABLE_ROWS_MAX {
            return Err(invalid(format!(
                "the boundary has more than {MOUNT_TABLE_ROWS_MAX} mounts, more than a \
                 receipt records"
            )));
        }
        out.push(AppliedMount {
            path: native,
            mode: mode.to_owned(),
        });
    }
    Ok(out)
}

/// `mountinfo` escapes space, tab, newline and backslash as octal.
pub(super) fn decode_mountinfo_path(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && let Some(value) = std::str::from_utf8(&bytes[index + 1..index + 4])
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 8).ok())
        {
            out.push(value);
            index += 4;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The environment names the launcher actually has, read from `/proc`.
///
/// I09: names only, never values.
///
/// # Errors
/// The read's error: an unreadable environment is not an empty one.
fn read_environment_names(pid: libc::pid_t) -> std::io::Result<Vec<String>> {
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

/// The environment bindings of the snapshot, resolved to the paths the child
/// will see.
fn environment_for(
    snapshot: &PolicySnapshot,
    workspace: &Path,
) -> Result<Vec<(OsString, OsString)>, JailError> {
    let mut out = Vec::new();
    for binding in &snapshot.environment.bindings {
        let value = match &binding.value {
            EnvValue::Native(native) => OsString::from_vec(native.as_bytes().to_vec()),
            EnvValue::Path(reference) => resolve_path_ref(reference, workspace)?,
        };
        out.push((OsString::from(binding.name.clone()), value));
    }
    Ok(out)
}

fn resolve_path_ref(reference: &PathRef, workspace: &Path) -> Result<OsString, JailError> {
    let base: PathBuf = match reference.root {
        RootToken::Workspace => workspace.to_path_buf(),
        RootToken::Scratch => PathBuf::from(bwrap::SCRATCH_INSIDE_PATH),
        RootToken::Host => PathBuf::from("/"),
        // Vendor state as the child sees it
        RootToken::VendorState => PathBuf::from(bwrap::VENDOR_STATE_INSIDE_PATH),
    };
    let suffix = reference.path.as_bytes();
    if suffix.is_empty() {
        return Ok(base.into_os_string());
    }
    Ok(base.join(OsStr::from_bytes(suffix)).into_os_string())
}

/// The host-side path a reference names, for binding as a mount source.
/// Unlike [`resolve_path_ref`], which produces the destination the child
/// sees, this resolves the scratch token to the supervisor's scratch
/// directory rather than `/tmp`.
fn host_path_of(
    reference: &PathRef,
    workspace: &Path,
    scratch: &Path,
) -> Result<PathBuf, JailError> {
    match reference.root {
        RootToken::Workspace => Ok(join_suffix(workspace, reference)),
        RootToken::Scratch => Ok(join_suffix(scratch, reference)),
        RootToken::Host => Ok(join_suffix(Path::new("/"), reference)),
        // Vendor state has no host path a grant may bind; it
        // is bound only by the descriptor the supervisor created it with.
        RootToken::VendorState => Err(error(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            "vendor state is bound by descriptor, never as a path grant".to_owned(),
        )),
    }
}

// Checking and duplicating the staged hand-off
/// The staged objects bubblewrap binds by descriptor.
struct StagedMounts {
    /// A duplicate of the vendor-state directory descriptor.
    vendor: Option<OwnedFd>,
    /// Each `bind_ro` source descriptor and its in-sandbox destination.
    credentials: Vec<(OwnedFd, PathBuf)>,
}

/// Checks the supervisor's hand-off against the policy and duplicates it.
///
/// The policy is the authority: vendor state is bound exactly when the
/// snapshot has a managed vendor-state root, and exactly the snapshot's
/// `bind_ro` declarations are bound, each by a descriptor whose object is
/// still the regular file staging identified. Anything else refuses; nothing
/// is ever bound by path. `tool` and `build` never bind a credential (§6.1).
fn staged_mounts(
    snapshot: &PolicySnapshot,
    handoff: Option<&crate::credentials::LaunchHandoff>,
) -> Result<StagedMounts, JailError> {
    use crate::state::anchored::{Kind, fstat};
    use std::os::fd::AsFd as _;
    let refuse = |message: &str| {
        error(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            message.to_owned(),
        )
    };
    let declared: Vec<&crate::policy::CredentialDecl> = snapshot
        .launch
        .iter()
        .flat_map(|launch| launch.credentials.iter())
        .collect();
    if !declared.is_empty() && snapshot.profile != ProfileName::Agent {
        return Err(refuse(
            "only the `agent` profile stages launch credentials (jail-v1 §6.1)",
        ));
    }
    let wants_vendor = snapshot.roots.vendor_state.is_some();
    let Some(handoff) = handoff else {
        if wants_vendor || !declared.is_empty() {
            return Err(refuse(
                "the policy has managed vendor state or credentials but nothing was staged",
            ));
        }
        return Ok(StagedMounts {
            vendor: None,
            credentials: Vec::new(),
        });
    };
    let vendor = match (&handoff.vendor_state, wants_vendor) {
        (Some(vendor), true) => vendor,
        (None, false) if handoff.binds.is_empty() => {
            return Ok(StagedMounts {
                vendor: None,
                credentials: Vec::new(),
            });
        }
        _ => {
            return Err(refuse(
                "the staged vendor state does not match the policy's vendor-state root",
            ));
        }
    };
    let stat = fstat(vendor.fd.as_fd()).map_err(|err| refuse(&err.to_string()))?;
    if stat.kind != Kind::Directory || stat.identity() != vendor.identity {
        return Err(refuse(
            "the staged vendor-state descriptor is not the registered directory",
        ));
    }
    let binds: Vec<&&crate::policy::CredentialDecl> = declared
        .iter()
        .filter(|declaration| declaration.mode == crate::credentials::MODE_BIND_RO)
        .collect();
    if binds.len() != handoff.binds.len() {
        return Err(refuse(
            "the staged read-only credentials do not match the policy's declarations",
        ));
    }
    let mut credentials = Vec::with_capacity(binds.len());
    for handle in &handoff.binds {
        if !binds
            .iter()
            .any(|declaration| declaration.id == handle.id && declaration.dest == handle.dest)
        {
            return Err(refuse(
                "a staged read-only credential is not one the policy declares",
            ));
        }
        let source = fstat(handle.fd.as_fd()).map_err(|err| refuse(&err.to_string()))?;
        if source.kind != Kind::Regular || source.identity() != handle.identity {
            return Err(refuse(
                "a staged read-only credential descriptor is not the object staging examined",
            ));
        }
        let destination = Path::new(bwrap::VENDOR_STATE_INSIDE_PATH)
            .join(OsStr::from_bytes(handle.dest.as_bytes()));
        let duplicate = handle
            .fd
            .try_clone()
            .map_err(|err| refuse(&err.to_string()))?;
        credentials.push((duplicate, destination));
    }
    let vendor = vendor
        .fd
        .try_clone()
        .map_err(|err| refuse(&err.to_string()))?;
    Ok(StagedMounts {
        vendor: Some(vendor),
        credentials,
    })
}

type MountPreparation = (
    jfs::ProtectedScan,
    Vec<jfs::PinnedPath>,
    Vec<(OwnedFd, RawFd)>,
    PlaceholderSet,
);

/// `OURO_JAIL_TEST_MOUNT_SWAP=<dir>`: a test seam (J5-B2) that opens a
/// deterministic window at the §9.1 mount handoff. When the variable names a
/// directory, the supervisor writes `<dir>/pinned` once every mount source has
/// been pinned and then waits (bounded, 10 s) for `<dir>/go` before running the
/// handoff verification. A test replaces a pinned object in that window to
/// prove the verification refuses the replacement (F04 source-identity swap).
///
/// Test-only. It can only delay the verification that is already there — never
/// widen anything — and, like every `OURO_JAIL_TEST_*` variable, it is recorded
/// in jail state and in every receipt with native details
/// (`state::persist::test_seams`, S9). A value that is not a usable directory
/// makes the write and the poll no-ops, so a stray setting cannot hang a run.
pub const MOUNT_SWAP_SEAM: &str = "OURO_JAIL_TEST_MOUNT_SWAP";

fn mount_swap_rendezvous() {
    let Some(dir) = std::env::var_os(MOUNT_SWAP_SEAM) else {
        return;
    };
    let dir = PathBuf::from(dir);
    if std::fs::write(dir.join("pinned"), b"1").is_err() {
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !dir.join("go").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
}

// §9.1 pseudo-filesystem guard
/// Refuses any operator grant in `binds` whose resolved source exposes host
/// `/proc`, `/sys`, cgroupfs, devtmpfs or the `/run` runtime tree (jail-v1
/// §9.1), keyed by `key` (`filesystem.read_only` or `filesystem.read_write`).
/// A policy refusal (`policy_widening`, remediation `configuration`) before
/// any mount; a mount table that cannot be read refuses too (`host_setup`),
/// since without it no grant can be shown to be clear.
pub(crate) fn refuse_pseudo_fs_grants(
    binds: &[(PathBuf, PathBuf)],
    key: &str,
) -> Result<(), JailError> {
    if binds.is_empty() {
        return Ok(());
    }
    refuse_pseudo_fs_grants_among(binds, key, pseudo_fs_mount_points())
}

/// [`refuse_pseudo_fs_grants`] against a given read of the mount points.
fn refuse_pseudo_fs_grants_among(
    binds: &[(PathBuf, PathBuf)],
    key: &str,
    mounts: std::io::Result<Vec<PathBuf>>,
) -> Result<(), JailError> {
    let mounts = mounts.map_err(|err| {
        error(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            format!(
                "this process's mount table cannot be read, so no grant can be shown to stay \
                 clear of host /proc, /sys, cgroupfs, devtmpfs and the /run runtime tree: {err}"
            ),
        )
        .with_key_path(key)
    })?;
    for (source, _destination) in binds {
        // Issue draft 15: an allowlisted device node is exactly the narrow
        // exception — one character device under /dev, never devtmpfs.
        if is_allowed_device_node(source) {
            continue;
        }
        // The check follows symlinks to the real object (`--ro <link>` where
        // the link resolves onto a pseudo filesystem must refuse); the later
        // pin opens with RESOLVE_NO_SYMLINKS for race safety.
        let resolved = std::fs::canonicalize(source).unwrap_or_else(|_| source.clone());
        let on_pseudo = source_on_pseudo_fs(&resolved);
        if crate::policy::grant_exposes_pseudo_fs(&resolved, on_pseudo, &mounts) {
            return Err(error(
                ErrorCode::PolicyWidening,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!(
                    "the grant {} exposes host /proc, /sys, cgroupfs, devtmpfs or the /run \
                     runtime tree, which a contained profile never binds (jail-v1 §9.1)",
                    source.display()
                ),
            )
            .with_key_path(key));
        }
    }
    Ok(())
}

/// Whether the object at `resolved` is on a proc, sysfs, cgroup or devtmpfs
/// filesystem, by `fstatfs` on an `O_PATH` handle. A path that cannot be
/// opened is not treated as pseudo here; the ancestor check and the later pin
/// catch the rest.
fn source_on_pseudo_fs(resolved: &Path) -> bool {
    let Ok(c) = super::sys::cstring_from_path(resolved) else {
        return false;
    };
    // SAFETY: `c` is a NUL-terminated path that outlives the call; O_PATH
    // acquires no I/O authority.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    // SAFETY: `fd` was just opened and is owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fd` is live; `buf` is a writable statfs the call fills.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), buf.as_mut_ptr()) } < 0 {
        return false;
    }
    // SAFETY: fstatfs returned 0, so the struct is initialised.
    // SAFETY: fstatfs returned 0, so the struct is initialised.
    let f_type = unsafe { buf.assume_init() }.f_type;
    crate::policy::is_pseudo_fs_magic(f_type)
}

/// Security 2026-09-27 (audit 3 A3): the mount points of every proc, sysfs or
/// cgroup (v1 or v2) mount, every devtmpfs mount, and every tmpfs mounted at
/// or beneath `/run` (the operator's runtime tree — `/run` alone, nowhere
/// else, so a tmpfs-backed `/tmp` or scratch stays grantable), from
/// `/proc/self/mountinfo` read as bytes. The fstype is the field after the
/// ` - ` separator.
///
/// # Errors
/// The read's error: an unreadable table is not one without such mounts.
fn pseudo_fs_mount_points() -> std::io::Result<Vec<PathBuf>> {
    Ok(parse_pseudo_fs_mount_points(&std::fs::read(
        "/proc/self/mountinfo",
    )?))
}

/// The pseudo-filesystem mount points of a `mountinfo` file's bytes, `/run`
/// always among them.
fn parse_pseudo_fs_mount_points(raw: &[u8]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in raw.split(|byte| *byte == b'\n') {
        let Some(separator) = line.windows(3).position(|w| w == b" - ") else {
            continue;
        };
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        let Some(point) = fields.get(4) else { continue };
        let fstype = line[separator + 3..]
            .split(|byte| *byte == b' ')
            .next()
            .unwrap_or_default();
        let point = decode_mountinfo_path(point);
        let matches = match fstype {
            b"proc" | b"sysfs" | b"cgroup" | b"cgroup2" | b"devtmpfs" => true,
            // `/run` and its submounts only: a tmpfs anywhere else is an
            // ordinary place for a grant (tests use /tmp tempdirs).
            b"tmpfs" => point == b"/run" || point.starts_with(b"/run/"),
            _ => false,
        };
        if matches {
            out.push(PathBuf::from(std::ffi::OsStr::from_bytes(&point)));
        }
    }
    // Security 2026-09-27 (audit 4 B7): the runtime tree is refused by its
    // path as well, not only by the tmpfs fstype — a host whose `/run` (or a
    // subtree of it) is not tmpfs would otherwise slip the fstype branch
    // above, and `grant_exposes_pseudo_fs` refuses an entry however the
    // overlap runs (ancestor, equal or beneath).
    if !out.iter().any(|point| point == Path::new("/run")) {
        out.push(PathBuf::from("/run"));
    }
    out
}

/// Security 2026-09-25 (audit F5): write the sanitized `/etc/resolv.conf`
/// the child will be bound, and return its path.
///
/// The host file's `search`/`domain` lines name the operator's networks;
/// they are host facts no grant covers, and nothing in the child's network
/// namespace can use the resolver anyway, so the copy keeps the nameservers
/// only, with numeric addresses, and drops all other directives. The file
/// lives in the attempt's private state, is created fresh with mode 0600,
/// and is removed with the attempt by the existing state cleanup.
///
/// # Errors
///
/// [`JailError`] (`state_write_failed` at preparing) when the attempt state
/// cannot hold the copy; a host `/etc/resolv.conf` that cannot be read
/// produces an empty resolver file, never the unsanitized host file.
fn stage_sanitized_resolv_conf(attempt_dir: &Path) -> Result<(PathBuf, &'static str), JailError> {
    const SOURCE: &str = "/etc/resolv.conf";
    use std::io::Read as _;
    let mut bytes = Vec::new();
    let host = std::fs::File::open(SOURCE).and_then(|f| f.take(65537).read_to_end(&mut bytes));
    let (sanitized, status) = sanitize_resolv_conf(host.is_ok().then_some(bytes.as_slice()));
    let dest = attempt_dir.join("resolv.conf");
    let write = || -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dest)?;
        file.write_all(sanitized.as_bytes())?;
        if !sanitized.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        Ok(())
    };
    write().map_err(|error| {
        preparing(
            ErrorCode::StateWriteFailed,
            format!("the sanitized resolver view could not be staged: {error}"),
        )
    })?;
    Ok((dest, status))
}

fn sanitize_resolv_conf(bytes: Option<&[u8]>) -> (String, &'static str) {
    let text = bytes
        .filter(|b| b.len() <= 65536)
        .and_then(|b| std::str::from_utf8(b).ok());
    let Some(text) = text else {
        return (String::new(), "failed_closed");
    };
    let mut sanitized = String::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() == Some("nameserver") {
            let Some(ip) = words
                .next()
                .and_then(|v| v.parse::<std::net::IpAddr>().ok())
            else {
                return (String::new(), "failed_closed");
            };
            sanitized.push_str(&format!("nameserver {ip}\n"));
        }
    }
    (sanitized, "nameservers_only")
}

/// Pin every source once, scan the pinned writable roots, then give each bind
/// its own descriptor. Bubblewrap validates the mounted inode against that fd.
fn prepare_mounts(
    plan: &mut BwrapPlan,
    attempt_dir: &Path,
    names: &[&str],
    coverage: ProtectedCoverage,
) -> Result<MountPreparation, JailError> {
    use std::collections::BTreeMap;
    let failure = |err: std::io::Error| {
        preparing(
            ErrorCode::BackendUnavailable,
            format!("mount source pinning failed: {err}"),
        )
    };
    let mut pins = BTreeMap::<PathBuf, jfs::PinnedPath>::new();
    let mut roots: Vec<(PathBuf, PathBuf)> = plan
        .extra_rw_binds
        .iter()
        .chain(plan.extra_dev_binds.iter())
        .cloned()
        .collect();
    if plan.workspace_access == Some(true) {
        roots.push((plan.workspace.clone(), plan.workspace.clone()));
    }
    roots.push((
        plan.scratch.clone(),
        PathBuf::from(bwrap::SCRATCH_INSIDE_PATH),
    ));
    roots.sort();
    roots.dedup();
    let mut aggregate = jfs::ProtectedScan {
        root: PathBuf::from("/"),
        directories: Vec::new(),
        segments: Vec::new(),
        skipped_symlinks: Vec::new(),
        root_literals: Vec::new(),
        entries_seen: 0,
        max_depth_seen: 0,
    };
    // Every refusal below drops the set, which removes what it created.
    let mut placeholders = PlaceholderSet::default();
    for (root_index, (source, destination)) in roots.iter().enumerate() {
        let pin = jfs::PinnedPath::open(source).map_err(failure)?;
        if !pin.is_dir().map_err(failure)? {
            pins.insert(source.clone(), pin);
            continue;
        }
        if coverage == ProtectedCoverage::None {
            pins.insert(source.clone(), pin);
            continue;
        }
        let mut scan = jfs::scan_pinned(
            &pin,
            names,
            jfs::ScanLimits {
                max_entries: jfs::ScanLimits::DEFAULT
                    .max_entries
                    .saturating_sub(aggregate.entries_seen),
                ..jfs::ScanLimits::DEFAULT
            },
        )
        .map_err(|err| preparing(ErrorCode::MissingCapability, err.to_string()))?;
        pins.insert(source.clone(), pin);
        if coverage == ProtectedCoverage::ExistingAndRoot && !scan.skipped_symlinks.is_empty() {
            return Err(preparing(
                ErrorCode::MissingCapability,
                "existing_and_root coverage cannot cover protected symlinks",
            ));
        }
        for segment in &scan.segments {
            let pinned = jfs::PinnedPath::open(&segment.path).map_err(failure)?;
            if pinned.identity() != (segment.dev, segment.ino) {
                return Err(preparing(
                    ErrorCode::BackendUnavailable,
                    "a protected object changed between scan and pin",
                ));
            }
            pins.insert(segment.path.clone(), pinned);
            plan.extra_ro_binds.push((
                segment.path.clone(),
                destination.join(
                    segment
                        .path
                        .strip_prefix(source)
                        .expect("scan beneath root"),
                ),
            ));
        }
        for directory in &scan.directories {
            directory
                .verify()
                .map_err(|e| preparing(ErrorCode::MissingCapability, e.to_string()))?;
        }
        let added_placeholders = !scan.absent_root_literals().is_empty();
        for literal in scan.absent_root_literals() {
            let holders = attempt_dir.join("placeholders");
            crate::state::create_private_dir(&holders)?;
            let holder = holders.join(format!("holder-{root_index}-{}", placeholders.len()));
            let placeholder = Placeholder::create(&holder, &source.join(&literal))
                .map_err(|err| preparing(ErrorCode::BackendUnavailable, err.to_string()))?;
            let mut mount = placeholder.mount().clone();
            mount.destination = destination.join(&literal);
            plan.placeholders.push(mount);
            placeholders.push(placeholder);
        }
        // Our placeholders mutate the root. Re-scan, rather than merely
        // accepting a new timestamp that could hide a concurrent mutation.
        if added_placeholders {
            let checked = jfs::scan_pinned(
                &pins[source],
                names,
                jfs::ScanLimits {
                    // The placeholders this pass just created add one
                    // entry each inside the root; the re-scan must be
                    // able to see them without tripping the bound a
                    // first scan at the cap would trip.
                    max_entries: jfs::ScanLimits::DEFAULT
                        .max_entries
                        .saturating_sub(aggregate.entries_seen)
                        .saturating_add(scan.absent_root_literals().len()),
                    ..jfs::ScanLimits::DEFAULT
                },
            )
            .map_err(|e| preparing(ErrorCode::MissingCapability, e.to_string()))?;
            let expected: std::collections::BTreeSet<_> = scan
                .absent_root_literals()
                .iter()
                .map(|name| source.join(name))
                .collect();
            let remaining: std::collections::BTreeSet<_> = checked
                .segments
                .iter()
                .filter(|s| !expected.contains(&s.path))
                .map(|s| (&s.path, s.dev, s.ino))
                .collect();
            if remaining
                != scan
                    .segments
                    .iter()
                    .map(|s| (&s.path, s.dev, s.ino))
                    .collect()
                || checked
                    .skipped_symlinks
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    != scan.skipped_symlinks.iter().collect()
            {
                return Err(preparing(
                    ErrorCode::MissingCapability,
                    "protected paths changed while placeholders were prepared",
                ));
            }
            scan.directories = checked.directories;
        }
        aggregate.directories.extend(scan.directories);
        aggregate.entries_seen += scan.entries_seen;
        aggregate.max_depth_seen = aggregate.max_depth_seen.max(scan.max_depth_seen);
        aggregate.segments.extend(scan.segments);
        aggregate.skipped_symlinks.extend(scan.skipped_symlinks);
    }
    // Bind ancestors before descendants, and never expose a second writable
    // alias of a protected source after applying its protection.
    let mut fds = Vec::new();
    for row in plan.mount_table() {
        if row.kind == "file-mask" {
            // EOF supplies an empty file to bubblewrap; no host content
            // or writable source descriptor is exposed to the child.
            let (reader, writer) = exec::pipe().map_err(failure)?;
            drop(writer);
            let target = PINNED_FD_BASE + fds.len() as RawFd;
            fds.push((reader, target));
            plan.mount_fds.push(Some(target));
            continue;
        }
        if !matches!(row.kind, "bind" | "ro-bind" | "ro-bind-fd" | "placeholder") {
            plan.mount_fds.push(None);
            continue;
        }
        let source = PathBuf::from(row.source.expect("bind source"));
        if !pins.contains_key(&source) {
            // Distribution-owned runtime aliases may be resolved here;
            // workspace/operator sources must never follow symlinks.
            let runtime = plan.etc_paths.contains(&source)
                || plan
                    .roots
                    .iter()
                    .any(|r| matches!(r, jfs::RootSpec::RoBind(p) if p == &source))
                || source == plan.jail_exe;
            let path = if runtime {
                std::fs::canonicalize(&source).map_err(failure)?
            } else {
                source.clone()
            };
            pins.insert(
                source.clone(),
                jfs::PinnedPath::open(&path).map_err(failure)?,
            );
        }
        let target = PINNED_FD_BASE + fds.len() as RawFd;
        fds.push((pins[&source].try_clone_fd().map_err(failure)?, target));
        plan.mount_fds.push(Some(target));
    }
    Ok((aggregate, pins.into_values().collect(), fds, placeholders))
}

fn absent_runtime_candidate(reference: &PathRef, host: &Path) -> bool {
    reference.root == RootToken::Host
        && crate::profiles::LINUX_RUNTIME_ROOTS
            .iter()
            .any(|candidate| host == Path::new(candidate))
        && std::fs::metadata(host).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Join a root with a reference's native-byte suffix.
fn join_suffix(base: &Path, reference: &PathRef) -> PathBuf {
    let suffix = reference.path.as_bytes();
    if suffix.is_empty() {
        return base.to_path_buf();
    }
    base.join(OsStr::from_bytes(suffix))
}

// ---------------------------------------------------------------------------
// Prepared
// ---------------------------------------------------------------------------

struct LinuxPrepared {
    boundary: Boundary,
}

impl PreparedExecution for LinuxPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        self.boundary.boundary_identity()
    }

    fn applied(&self) -> Option<Applied> {
        Some(self.boundary.applied.clone())
    }

    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError> {
        // One implementation, which also reports teardown
        self.release_reporting_teardown()
            .map_err(|failure| failure.error)
    }

    // A failed release runs the verified teardown and says
    // what it established, instead of tearing down without a verdict.
    fn release_reporting_teardown(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, Box<crate::platform::ReleaseFailure>> {
        let mut boundary = self.boundary;
        if boundary.watcher.ended()
            || boundary
                .storage
                .as_mut()
                .is_some_and(|storage| storage.sample().is_err())
            || boundary
                .cgroup
                .as_ref()
                .is_some_and(|leaf| leaf.verify().is_err())
        {
            let tree = boundary.verified_teardown();
            return Err(Box::new(crate::platform::ReleaseFailure {
                error: preparing(
                    ErrorCode::BackendUnavailable,
                    "lifetime resources were lost before release",
                ),
                teardown: Some(Teardown { tree: Some(tree) }),
            }));
        }
        // Parsed once, before the release: an unparseable ceiling refuses
        // with the launcher still blocked, rather than after the target was
        // released without the deadline the receipt's limit row claims.
        let wall = match clock::wall_ceiling(&boundary.snapshot.limits) {
            Ok(wall) => wall,
            Err(what) => {
                let tree = boundary.verified_teardown();
                return Err(Box::new(crate::platform::ReleaseFailure {
                    error: preparing(
                        ErrorCode::InternalError,
                        format!("the wall limit cannot be enforced: {what}"),
                    ),
                    teardown: Some(Teardown { tree: Some(tree) }),
                }));
            }
        };
        let Some(release) = boundary.release.take() else {
            let tree = boundary.verified_teardown();
            return Err(Box::new(crate::platform::ReleaseFailure {
                error: preparing(
                    ErrorCode::BackendUnavailable,
                    "the release pipe is already closed",
                ),
                teardown: Some(Teardown { tree: Some(tree) }),
            }));
        };
        if let Err(err) = write_all(release.as_raw_fd(), &[1]) {
            let tree = boundary.verified_teardown();
            return Err(Box::new(crate::platform::ReleaseFailure {
                error: preparing(
                    ErrorCode::BackendUnavailable,
                    format!("the release byte could not be written: {err}"),
                ),
                teardown: Some(Teardown { tree: Some(tree) }),
            }));
        }
        // Closing it makes a second release impossible (X03).
        drop(release);
        Ok(Box::new(LinuxRunning {
            boundary,
            // The wall runs from the release.
            wall: wall.map(clock::Deadline::after),
            wall_reported: false,
            exec_confirmed: false,
            target_outcome: None,
            pending: VecDeque::new(),
            stop_requested: None,
            stop_at: None,
            hard_killed: false,
            hard_deadline: None,
            bwrap_status: None,
            finished: false,
            evidence_reported: false,
            sampled_at_ns: 0,
            storage_lost_live: false,
        }))
    }

    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        let mut boundary = self.boundary;
        // The target never ran, but the boundary existed, and
        // whether its teardown completed is a measured fact, established by
        // the same facts settlement requires (see `verified_teardown`).
        Ok(Teardown {
            tree: Some(boundary.verified_teardown()),
        })
    }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

struct LinuxRunning {
    boundary: Boundary,
    wall: Option<clock::Deadline>,
    wall_reported: bool,
    exec_confirmed: bool,
    target_outcome: Option<RunEvent>,
    pending: VecDeque<RunEvent>,
    stop_requested: Option<StopReason>,
    stop_at: Option<u64>,
    hard_killed: bool,
    hard_deadline: Option<clock::Deadline>,
    bwrap_status: Option<i32>,
    finished: bool,
    evidence_reported: bool,
    /// Boot-clock time of the last counter sample.
    sampled_at_ns: u64,
    /// Audit 2026-10-08 L2: storage enforcement was found lost while the
    /// target still ran — the only timing that may make it `outcome.cause`
    /// (§6.4). A loss first seen after the target's own end never does.
    storage_lost_live: bool,
}

impl LinuxRunning {
    fn pump_stdio(&mut self) -> bool {
        match pump_stdio_relays(&mut self.boundary.stdio_relays) {
            Ok(active) => active,
            Err(err) => {
                self.pending.push_back(RunEvent::StdioFailed {
                    reason: format!("a stdio relay failed: {err}"),
                    after_target_end: self.target_outcome.is_some() || self.bwrap_status.is_some(),
                });
                // Failed streams cannot deliver more. Close them once and
                // let the supervisor record the error and stop a live tree.
                self.boundary.stdio_relays.clear();
                false
            }
        }
    }

    fn sample_limits(&mut self, force: bool) {
        if !shared::sample_due(&mut self.sampled_at_ns, force) {
            return;
        }
        if let Some(storage) = self.boundary.storage.as_mut() {
            match storage.sample() {
                Ok(hits) => {
                    for _ in hits {
                        self.boundary.audit.record_limit_hit();
                    }
                }
                Err(_) => {
                    // Audit 2026-10-08 L1: the loss is sticky (`Storage::sample`
                    // replays it every call), and losing the storage read must
                    // not also blind the cgroup ceilings — the sample used to
                    // return before `leaf.sample()`, dropping later
                    // mem/swap/pids/cpu hits while their rows said `hit: false`.
                    self.storage_lost_live |= self.target_outcome.is_none();
                    self.boundary
                        .audit
                        .record_limit_evidence_missing("storage_enforcement_lost");
                    self.hard_kill();
                }
            }
        }
        let Some(leaf) = self.boundary.cgroup.as_mut() else {
            return;
        };
        match shared::sample_counters(leaf, &mut self.boundary.audit) {
            shared::Counters::Read { oom_killed } => {
                if oom_killed {
                    self.hard_kill();
                }
            }
            shared::Counters::Lost => {
                self.boundary.cgroup_lost = true;
                self.hard_kill();
            }
        }
    }
    /// Reads whatever the launcher wrote about a failed exec.
    fn pump_error(&mut self) {
        let boundary = &mut self.boundary;
        shared::drain_error_pipe(
            &boundary.error,
            &mut boundary.error_bytes,
            &mut boundary.error_eof,
        );
    }

    /// Drains the tracer channel into audit events and run events.
    ///
    /// `block` is how long to wait for the first event. Every event taken from
    /// the channel is handled here; nothing reads that channel elsewhere,
    /// because an event read and dropped would be evidence silently lost.
    fn pump_tracer(&mut self, block: Duration) {
        let Some(tracer) = self.boundary.tracer.as_ref() else {
            return;
        };
        for event in super::observed::drain(tracer, block) {
            self.handle_tracer_event(&event);
        }
    }

    fn handle_tracer_event(&mut self, event: &TracerEvent) {
        use super::observed::Fact;
        let target = super::observed::Target {
            launcher: self.boundary.launcher.pid,
            images: &self.boundary.target_images,
        };
        match super::observed::record(&mut self.boundary.audit, &target, event) {
            Fact::CommandForbidden(pattern) => self
                .pending
                .push_back(RunEvent::CommandForbidden { pattern }),
            Fact::TargetExec if !self.exec_confirmed => {
                self.exec_confirmed = true;
                self.pending.push_back(RunEvent::ExecConfirmed);
            }
            Fact::TargetExit(status) if self.target_outcome.is_none() => {
                self.target_outcome = Some(outcome_from_status(status));
            }
            Fact::UntracedExit { pid, status } if pid == self.boundary.bwrap_pid => {
                self.bwrap_status = Some(status);
            }
            Fact::CoverageLost(reason) if !self.evidence_reported => {
                self.evidence_reported = true;
                self.pending.push_back(RunEvent::EvidenceLost {
                    reason: format!("the closed-set observer lost coverage: {}", reason.as_str()),
                    // J4 W2-S: R-2 — the target's exit is held back until the
                    // backend ends too, so a loss in the teardown after it
                    // (a call the namespace's end interrupted) is queued
                    // ahead of the exit although it came after it.
                    after_target_end: self.target_outcome.is_some(),
                });
            }
            Fact::Finished => self.finished = true,
            _ => {}
        }
    }

    /// With observation off, bubblewrap's own status is the only fact.
    fn pump_status(&mut self) {
        self.boundary.status.pump();
        if self.boundary.tracer.is_some() {
            return;
        }
        if let Some(child) = self.boundary.child.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            use std::os::unix::process::ExitStatusExt as _;
            self.bwrap_status = Some(status.into_raw());
        }
    }

    /// Exec confirmation with no observer ([`shared::exec_without_observer`]).
    fn check_exec_without_tracer(&mut self) {
        let boundary = &self.boundary;
        if shared::exec_without_observer(
            boundary.observe_on || self.exec_confirmed,
            &boundary.error_bytes,
            boundary.error_eof,
            &boundary.launcher,
        ) {
            self.exec_confirmed = true;
            self.pending.push_back(RunEvent::ExecConfirmed);
        }
    }

    fn check_wall(&mut self) {
        if let Some(event) =
            shared::check_wall(self.wall, &mut self.wall_reported, &mut self.boundary.audit)
        {
            self.pending.push_back(event);
        }
    }

    /// Escalates a cooperative stop to a hard one once the grace has passed.
    fn check_grace(&mut self) {
        if shared::grace_spent(
            self.hard_killed,
            self.stop_requested.is_some(),
            self.stop_at,
        ) {
            self.hard_kill();
        }
    }

    fn hard_kill(&mut self) {
        if shared::arm_hard_kill(&mut self.hard_killed, &mut self.hard_deadline) {
            self.boundary.kill_boundary();
        }
    }

    /// The outcome once no more facts can arrive.
    fn terminal_event(&mut self) -> Option<RunEvent> {
        if let Some(event) = shared::observed_outcome(
            &mut self.target_outcome,
            &mut self.exec_confirmed,
            &mut self.pending,
        ) {
            return Some(event);
        }
        // Without an observer the target's own status is not visible, so the
        // backend's report is all there is.
        let status = self.bwrap_status?;
        if !self.boundary.error_bytes.is_empty() {
            let (errno, detail) = super::launch::exec_failure_parts(&self.boundary.error_bytes);
            return Some(RunEvent::ExecError { errno, detail });
        }
        if !self.exec_confirmed {
            // J5-B1: §6.4 — a coded error, not a bare unknown.
            return Some(RunEvent::ExecUnconfirmed {
                reason: "the backend ended without independent evidence of target exec".to_owned(),
            });
        }
        Some(self.status_outcome(status))
    }

    fn status_outcome(&self, bwrap_status: i32) -> RunEvent {
        let code = self
            .boundary
            .status
            .parsed()
            .exit_code
            .or_else(|| libc::WIFEXITED(bwrap_status).then(|| libc::WEXITSTATUS(bwrap_status)));
        match code {
            // Measured on bubblewrap 0.11.1: a child killed by a signal is
            // reported as 128 + signal, indistinguishable from an exit with
            // that code. Without an observer the two cannot be told apart, so
            // the ambiguous range stays unknown rather than being claimed.
            Some(value) if (0..128).contains(&value) => RunEvent::TargetExited {
                code: u8::try_from(value).unwrap_or(0),
            },
            Some(value) => RunEvent::Unknown {
                reason: format!(
                    "with observation off the backend reports a signal death as 128+signal, \
                     so exit code {value} is ambiguous"
                ),
            },
            None => RunEvent::Unknown {
                reason: "the backend reported no exit code for the target".to_owned(),
            },
        }
    }
}

fn outcome_from_status(status: i32) -> RunEvent {
    if libc::WIFEXITED(status) {
        RunEvent::TargetExited {
            code: u8::try_from(libc::WEXITSTATUS(status)).unwrap_or(0),
        }
    } else if libc::WIFSIGNALED(status) {
        RunEvent::TargetSignaled {
            signal: u32::try_from(libc::WTERMSIG(status)).unwrap_or(0),
        }
    } else {
        RunEvent::Unknown {
            reason: format!("the target's wait status {status} is neither an exit nor a signal"),
        }
    }
}

impl RunningExecution for LinuxRunning {
    fn wait(&mut self, deadline: PortableDeadline) -> RunEvent {
        if let Some(event) = self.pending.pop_front() {
            return event;
        }
        self.pump_error();
        self.pump_tracer(Duration::ZERO);
        // Mediated connects, helper facts, and a loss of
        // mediation or proxy evidence, which strict evidence stops for
        if let Some(reason) = self.boundary.pump_agent() {
            // J4 W2-S: R-2 — the target's end as this loop knows it:
            // the observer's exit, or without one the backend's.
            let after_target_end = self.target_outcome.is_some()
                || (self.boundary.tracer.is_none() && self.bwrap_status.is_some());
            self.pending.push_back(RunEvent::EvidenceLost {
                reason,
                after_target_end,
            });
        }
        self.pump_status();
        // Audit 2026-10-08 H1: move relayed stdio while the run is
        // live; a relay making progress keeps the loop spinning fast so
        // a chatty child is not throttled to the poll cadence.
        let relay_active = self.pump_stdio();
        self.boundary.release_watcher_after_backend();
        self.sample_limits(false);
        self.check_exec_without_tracer();
        self.check_wall();
        self.check_grace();
        // The watcher follows the backend out, and its exit can be seen
        // before the backend's status has been pumped; only a watcher
        // gone while the backend still runs is a lost helper.
        if self.boundary.watcher.ended()
            && self.bwrap_status.is_none()
            && !self.boundary.backend_exited()
        {
            self.hard_kill();
        }
        if let Some(event) = self.pending.pop_front() {
            return event;
        }
        if !self.boundary.error_bytes.is_empty() && self.exec_confirmed {
            // Bytes after a confirmed exec cannot happen; keep them out of
            // the way rather than reporting a second event.
            self.boundary.error_bytes.clear();
        }
        if !self.boundary.error_bytes.is_empty() {
            let (errno, detail) = super::launch::exec_failure_parts(&self.boundary.error_bytes);
            self.boundary.error_bytes.clear();
            return RunEvent::ExecError { errno, detail };
        }
        let done = self.bwrap_status.is_some()
            && (self.boundary.tracer.is_none() || self.finished || self.target_outcome.is_some());
        if done {
            // The counters must be in hand before the outcome is
            // classified: an OOM kill is attributed from them.
            self.sample_limits(true);
            // The child's end has closed by now; deliver what it wrote
            // through the relays before the outcome is recorded.
            if let Err(err) =
                drain_output_relays(&mut self.boundary.stdio_relays, OUTPUT_DRAIN_BUDGET)
            {
                self.pending.push_back(RunEvent::StdioFailed {
                    reason: format!("a stdio relay failed: {err}"),
                    after_target_end: true,
                });
                self.boundary.stdio_relays.clear();
            }
            if self
                .boundary
                .stdio_relays
                .iter()
                .any(|relay| !relay.to_child && !relay.buffer.is_empty())
            {
                self.pending.push_back(RunEvent::StdioFailed {
                    reason: "a stdio relay could not drain its output within the delivery budget"
                        .to_owned(),
                    after_target_end: true,
                });
                self.boundary.stdio_relays.clear();
            }
            if let Some(event) = self.pending.pop_front() {
                return event;
            }
        }
        if done && let Some(event) = self.terminal_event() {
            return event;
        }
        if self.hard_deadline.is_some_and(clock::Deadline::expired) {
            return RunEvent::Unknown {
                reason: "termination could not be observed within the tree budget".to_owned(),
            };
        }
        let step = if relay_active {
            std::cmp::min(step_for(deadline), Duration::from_millis(2))
        } else {
            step_for(deadline)
        };
        if self.boundary.tracer.is_some() {
            self.pump_tracer(step);
        } else {
            std::thread::sleep(step);
        }
        RunEvent::Poll
    }

    fn request_stop(&mut self, reason: StopReason) {
        if self.stop_requested.is_some() {
            return;
        }
        self.stop_requested = Some(reason);
        self.stop_at = Some(boottime_ns());
        // Measured on this host: a SIGTERM sent to the outer bubblewrap kills
        // bubblewrap itself and never reaches the target, while a SIGTERM to
        // the target's own host pid runs its handler. So the cooperative stop
        // goes to the target, through the pidfd discovery required.
        if let Some(fd) = self.boundary.launcher_fd.as_ref() {
            let _ = identity::pidfd_send_signal(fd.as_raw_fd(), libc::SIGTERM);
        }
    }

    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        let deadline = self
            .hard_deadline
            .unwrap_or_else(|| clock::Deadline::after(budget));
        let settle = clock::Deadline::after(SETTLE_GRACE.min(budget));
        let mut natural = false;
        loop {
            self.pump_error();
            self.pump_tracer(Duration::ZERO);
            self.pump_status();
            // The observer finishes once every tracee and the backend are
            // reaped (J5-T); the watcher, released here, is reaped below.
            self.boundary.release_watcher_after_backend();
            let tracer_done = self.boundary.tracer.is_none() || self.finished;
            if tracer_done
                && self.bwrap_status.is_some()
                && !init_alive(self.boundary.init_fd.as_ref(), self.boundary.init_pid)
                && self.boundary.cgroup_empty()
            {
                natural = true;
                break;
            }
            if settle.expired() {
                // §9.3: target exit is itself a termination trigger.
                self.hard_kill();
            }
            if deadline.expired() {
                break;
            }
            if self.boundary.tracer.is_some() {
                self.pump_tracer(WAIT_STEP);
            } else {
                std::thread::sleep(WAIT_STEP);
            }
        }

        // Whatever the loop concluded, the observer is stopped inside what is
        // left of the budget and its account decides. It is the only witness
        // to whether every tracee really ended.
        self.pump_tracer(Duration::ZERO);
        self.boundary.stop_observer(deadline.remaining());
        // The tree is dead or given up on; the proxy drains
        // its last results and the mediator stops
        self.boundary.stop_agent(deadline.remaining());
        self.sample_limits(true);
        while !self.boundary.watcher.ended() && !deadline.expired() {
            self.boundary.release_watcher_after_backend();
            std::thread::sleep(WAIT_STEP);
        }
        self.boundary.watcher.reap();
        self.boundary.remove_placeholders();

        let mut tree = verdict(&TreeInputs {
            init_alive: init_alive(self.boundary.init_fd.as_ref(), self.boundary.init_pid),
            backend_reaped: self.bwrap_status.is_some() && self.boundary.watcher.ended(),
            tracer_finished: self.boundary.tracer.is_none() || self.finished,
            natural_end: natural,
            abandoned_tracees: self
                .boundary
                .tracer_summary
                .as_ref()
                .map_or(0, |summary| summary.loss.abandoned_tracees),
            unreaped_children: self
                .boundary
                .tracer_summary
                .as_ref()
                .map_or(0, |summary| summary.unreaped_children.len()),
            observer_panicked: self
                .boundary
                .tracer_summary
                .as_ref()
                .is_some_and(|summary| summary.thread_panicked),
            // Security 2026-09-27 (audit 3 A5): carried for the receipt; never a
            // verdict input, because the stop was continued and nothing was
            // lost.
            requested_by_other_filters: self
                .boundary
                .tracer_summary
                .as_ref()
                .map_or(0, |summary| summary.requested_by_other_filters),
        });
        if !self.boundary.cgroup_empty() {
            tree.tree_empty = None;
            tree.verified_at = None;
            tree.integrity = if self.boundary.cgroup_lost {
                "lost"
            } else {
                "pending"
            }
            .to_owned();
        }
        tree
    }

    fn final_limits(&self) -> Vec<AppliedLimit> {
        let mut limits = self
            .boundary
            .cgroup
            .as_ref()
            .map_or_else(Vec::new, ExecutionCgroup::limits);
        if let Some(storage) = &self.boundary.storage {
            limits.extend(storage.limits());
        }
        limits
    }

    fn limit_cause(&self) -> Option<String> {
        // Audit 2026-10-08 L2 (§6.4): a storage enforcement loss becomes the
        // cause only when it was found while the target still ran. A loss
        // discovered after the target's own end — including the settlement
        // sample below — is recorded in `errors[]` but is never the cause.
        if self.storage_lost_live
            && self
                .boundary
                .storage
                .as_ref()
                .is_some_and(super::storage::Storage::lost)
        {
            return Some("storage_enforcement_lost".to_owned());
        }
        self.boundary
            .cgroup
            .as_ref()
            .is_some_and(ExecutionCgroup::oom_killed)
            .then(|| "memory_oom".to_owned())
    }

    /// The storage enforcement loss's own message, for the receipt's
    /// `errors[]` (audit 2026-10-08 L2); `None` while enforcement holds.
    fn storage_loss(&self) -> Option<String> {
        self.boundary.storage.as_ref()?.loss().map(str::to_owned)
    }

    // The bridge's counts, once it and the mediator stopped
    fn final_native_details(&self) -> serde_json::Map<String, Value> {
        let mut details = serde_json::Map::new();
        if let Some(storage) = &self.boundary.storage {
            details.insert("storage_ceiling".to_owned(), storage.evidence());
        }
        if let Some(agent) = self.boundary.agent.as_ref() {
            details.insert("helpers".to_owned(), agent.details().1);
        }
        // Security 2026-09-27 (audit 4 B9): the honest count of read-only
        // open verdicts the observer certified (register-sourced flags, and
        // the memory-sourced ones every `memory_flags_unverified` gap
        // already names). Audit 3 A1 asked for it to be surfaced; a count
        // that never leaves the tracer is unauditable.
        details.insert(
            "filtered_readonly_opens".to_owned(),
            self.boundary
                .tracer_summary
                .as_ref()
                .map_or(Value::Null, |summary| {
                    Value::from(summary.filtered_readonly_opens)
                }),
        );
        // Security 2026-09-29 (audit 6 N1): open events delivered with their
        // pathname claim downgraded because the descriptor link did not
        // corroborate it. Not loss, so no class counts it; the receipt does.
        details.insert(
            "path_claims_unverified".to_owned(),
            self.boundary
                .tracer_summary
                .as_ref()
                .map_or(Value::Null, |summary| {
                    Value::from(summary.path_claims_unverified)
                }),
        );
        // Security 2026-09-27 (audit 3 A5): wrong-guess trace stops are counted
        // in the receipt, so a child probing the trace-data space shows up in
        // `lifetime.native.details` instead of continuing silently.
        details.insert(
            "requested_by_other_filters".to_owned(),
            wrong_guess_stops_detail(self.boundary.tracer_summary.as_ref()),
        );
        details
    }

    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        // `wait_tree` already stopped the observer inside its budget; this
        // only covers a caller that skipped it.
        self.boundary.stop_observer(TREE_BUDGET);
        if self.boundary.tracer.is_none()
            && let Some(mut child) = self.boundary.child.take()
        {
            let _ = child.try_wait();
        }
        // `proxy.net` is the proxy's own class, with or
        // without the observer (§11.4)
        self.boundary.stop_agent(TREE_BUDGET);
        let mut summary = if self.boundary.observe_on {
            let tracer = shared::observer_account(self.boundary.tracer_summary.as_ref());
            self.boundary.audit.summary(&tracer, true)
        } else {
            // §11.4: observation off makes every audit class unsupported
            // with a null count. The wrapper's own `limits` class still
            // exists.
            let mut summary = CoverageSummary::unobserved();
            summary.classes.insert(
                crate::observer::CoverageClass::Limits,
                self.boundary.audit.limits_class(),
            );
            summary
        };
        if let Some(agent) = self.boundary.agent.as_ref() {
            agent.apply_coverage(&mut summary);
        }
        Some(summary)
    }
}

/// Whether an observer's account permits a claim that the tree died.
///
/// A tracee it had to kill on the way out, or a direct child whose exit status
/// now has no route to this process, means the tree's end was not observed.
/// §9.3: that is `tree_empty = null` and `tree_unknown`, never a claim of
/// emptiness. With no observer there is nothing here to object.
fn observer_verdict(summary: Option<&TracerSummary>) -> bool {
    match summary {
        Some(summary) => {
            summary.loss.abandoned_tracees == 0
                && summary.unreaped_children.is_empty()
                && !summary.thread_panicked
        }
        None => true,
    }
}

/// What is known about the tree when its budget is spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeInputs {
    /// The namespace init still has an entry in `/proc`.
    pub init_alive: bool,
    /// The backend's exit was seen.
    pub backend_reaped: bool,
    /// The observer said it was done, or there was no observer.
    pub tracer_finished: bool,
    /// The loop saw the tree end on its own rather than running out of time.
    pub natural_end: bool,
    /// Tracees the observer had to kill on the way out.
    pub abandoned_tracees: u64,
    /// Direct children whose exit status no longer has a route here.
    pub unreaped_children: usize,
    /// Stops another filter asked for — a child's own `SECCOMP_RET_TRACE`
    /// with its own trace data, on a call outside the closed set. Surfaced
    /// for the receipt (audit 3 A5); never a verdict input,
    /// because the stop was continued and nothing was lost.
    pub requested_by_other_filters: u64,
    /// The observer's thread panicked, so its counters mean nothing.
    pub observer_panicked: bool,
}

/// The tree observation those facts justify (§9.3, §13.2).
///
/// `tree_empty = Some(true)` needs every one of them to say the tree ended and
/// that the ending was seen. Anything unknown — an init still there, a backend
/// whose exit was never collected, an observer that gave up on a tracee or
/// lost a child's status — is `None` and `pending`, which the supervisor turns
/// into `tree_unknown`. There is no input combination that produces `false`:
/// this code either watched the tree end or does not know.
#[must_use]
pub fn verdict(inputs: &TreeInputs) -> TreeObservation {
    let verified = inputs.natural_end
        && !inputs.init_alive
        && inputs.backend_reaped
        && inputs.tracer_finished
        && inputs.abandoned_tracees == 0
        && inputs.unreaped_children == 0
        && !inputs.observer_panicked;
    if verified {
        TreeObservation {
            tree_empty: Some(true),
            verified_at: Some(SystemTime::now()),
            verification_scope: "attempt_tree".to_owned(),
            integrity: "verified".to_owned(),
        }
    } else {
        TreeObservation {
            tree_empty: None,
            verified_at: None,
            verification_scope: "attempt_tree".to_owned(),
            integrity: "pending".to_owned(),
        }
    }
}

// The verdict of a teardown whose target never ran
/// What a teardown after an abort or a failed release established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortInputs {
    /// The backend, this supervisor's child, is dead and reaped.
    pub backend_reaped: bool,
    /// The outside watcher is dead and reaped.
    pub watcher_reaped: bool,
    /// The namespace init's pidfd reports its death.
    pub init_dead: bool,
    /// The execution cgroup, if any, was observed unpopulated with its
    /// identity intact (true when there is no cgroup).
    pub cgroup_empty: bool,
    /// Tracees the observer had to kill on the way out.
    pub abandoned_tracees: u64,
    /// The observer's thread panicked.
    pub observer_panicked: bool,
    /// This process's children the observer left unreaped when it stopped.
    pub unreaped_children: Vec<libc::pid_t>,
    /// Stops another filter asked for, continued unobserved. Surfaced for the
    /// receipt (audit 3 A5); never a verdict input, because
    /// the stop was continued and nothing was lost.
    pub requested_by_other_filters: u64,
    /// The backend's pid.
    pub backend_pid: libc::pid_t,
    /// The watcher's pid.
    pub watcher_pid: libc::pid_t,
}

/// Whether a teardown whose target never ran verified the tree's death.
///
/// The settlement facts without the target: the init's death (which the PID
/// namespace makes the death of every member), the backend and the watcher
/// reaped, the leaf empty, and an observer account with nothing abandoned.
/// The observer's "unreaped children" are forgiven only when they are exactly
/// the backend and the watcher and this thread reaped them afterwards; any
/// other child is a process this verdict knows nothing about.
#[must_use]
pub fn abort_verdict(inputs: &AbortInputs) -> bool {
    let children_accounted = inputs.unreaped_children.iter().all(|pid| {
        (*pid == inputs.backend_pid && inputs.backend_reaped)
            || (*pid == inputs.watcher_pid && inputs.watcher_reaped)
    });
    inputs.backend_reaped
        && inputs.watcher_reaped
        && inputs.init_dead
        && inputs.cgroup_empty
        && inputs.abandoned_tracees == 0
        && !inputs.observer_panicked
        && children_accounted
}

/// Security 2026-09-27 (audit 3 A5): the receipt's account of stops another
/// filter asked for — a child's own `SECCOMP_RET_TRACE` on a call outside the
/// closed set, carrying its own trace data, not this attempt's. Each is
/// continued unobserved: not a result, not a loss, never a
/// `unexpected_trace_stop` gap. The count is what makes the guessing visible,
/// so it is carried in `lifetime.native.details`; null when no observer ran,
/// because a detail must not claim a count nothing read.
fn wrong_guess_stops_detail(summary: Option<&TracerSummary>) -> Value {
    summary.map_or(Value::Null, |summary| {
        Value::from(summary.requested_by_other_filters)
    })
}

/// Whether the namespace init is still running: from its pidfd once
/// discovery took one, which turns readable at its exit and cannot come to
/// name another process; before that, whether bubblewrap named an init whose
/// `/proc` entry is still there.
fn init_alive(init_fd: Option<&OwnedFd>, init_pid: libc::pid_t) -> bool {
    match init_fd {
        Some(fd) => !super::watch::readable(fd.as_raw_fd()),
        None => init_pid > 0 && Path::new(&format!("/proc/{init_pid}")).exists(),
    }
}

fn image_changed(pid: libc::pid_t) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(launcher) = std::fs::metadata("/proc/self/exe") else {
        return false;
    };
    let Ok(target) = std::fs::metadata(format!("/proc/{pid}/exe")) else {
        return false;
    };
    (launcher.dev(), launcher.ino()) != (target.dev(), target.ino())
}

/// How long the loop may block before re-checking every source.
///
/// A deadline that has already passed does not shorten the step: the wall is
/// reported once, and after that the loop is waiting for the tree to die, not
/// for the clock.
fn step_for(deadline: PortableDeadline) -> Duration {
    let Some(at) = deadline.at else {
        return WAIT_STEP;
    };
    let remaining = at
        .checked_duration_since(std::time::Instant::now())
        .unwrap_or_default();
    if remaining.is_zero() {
        return WAIT_STEP;
    }
    remaining.min(WAIT_STEP).max(Duration::from_micros(200))
}

/// What the contained boundary and `super::uncontained` share: the rules
/// both run loops apply, each written once in this module, and delegations
/// to helpers above. A fix to one of these rules (an evidence gap, a stop, a
/// refusal) reaches both boundaries; what still differs between them is the
/// state each keeps, not these rules.
pub(super) mod shared {
    use std::collections::VecDeque;
    use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
    use std::time::Duration;

    use crate::capability::{Capability, CapabilityScope};
    use crate::platform::{Deadline, RunEvent};
    use crate::policy::LimitsSnapshot;
    use crate::records::{AppliedLimit, ErrorCode, ErrorStage, JailError, Remediation};
    use crate::supervisor::TREE_BUDGET;

    use super::super::audit::AuditWriter;
    use super::super::cgroup::ExecutionCgroup;
    use super::super::clock;
    use super::super::identity::ProcessIdentity;
    use super::super::probe::ProbeResult;
    use super::super::tracer::TracerSummary;

    pub(in crate::platform::linux) const STOP_GRACE: Duration = super::STOP_GRACE;
    pub(in crate::platform::linux) const SETTLE_GRACE: Duration = super::SETTLE_GRACE;
    pub(in crate::platform::linux) const WAIT_STEP: Duration = super::WAIT_STEP;
    pub(in crate::platform::linux) const LIMIT_SAMPLE_INTERVAL: Duration =
        super::LIMIT_SAMPLE_INTERVAL;

    pub(in crate::platform::linux) fn capability_from(
        requirement: &str,
        probes: &[&str],
        mechanism: &str,
        scope: CapabilityScope,
        results: &[ProbeResult],
        measured_at: &str,
    ) -> Capability {
        super::capability_from(requirement, probes, mechanism, scope, results, measured_at)
    }
    pub(in crate::platform::linux) fn outcome_from_status(status: i32) -> RunEvent {
        super::outcome_from_status(status)
    }
    pub(in crate::platform::linux) fn observer_verdict(summary: Option<&TracerSummary>) -> bool {
        super::observer_verdict(summary)
    }
    pub(in crate::platform::linux) fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
        super::set_nonblocking(fd)
    }
    pub(in crate::platform::linux) fn write_all(fd: RawFd, bytes: &[u8]) -> std::io::Result<()> {
        super::write_all(fd, bytes)
    }
    pub(in crate::platform::linux) fn read_environment_names(
        pid: libc::pid_t,
    ) -> std::io::Result<Vec<String>> {
        super::read_environment_names(pid)
    }
    pub(in crate::platform::linux) fn step_for(deadline: Deadline) -> Duration {
        super::step_for(deadline)
    }
    pub(in crate::platform::linux) fn nap() {
        super::nap();
    }

    /// §5.2, for every profile: v1 refuses a privileged or setuid
    /// supervisor rather than model that boundary; a child-side capability
    /// read-back is no substitute for not being privileged in the first
    /// place. (Untestable on the reference host: the conformance account has
    /// no privilege to gain.)
    ///
    /// # Errors
    /// `unsupported_platform` when the effective uid is 0 or differs from the
    /// real one.
    pub(in crate::platform::linux) fn refuse_privileged_supervisor() -> Result<(), JailError> {
        // SAFETY: getuid and geteuid take no arguments and cannot fail.
        let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        if euid == 0 || ruid != euid {
            return Err(JailError::new(
                ErrorCode::UnsupportedPlatform,
                ErrorStage::Preparing,
                Remediation::HostSetup,
                format!(
                    "v1 refuses a privileged or setuid supervisor: real uid {ruid}, effective \
                     uid {euid} (jail-v1 §5.2)"
                ),
            ));
        }
        Ok(())
    }

    /// The `applied.limits` rows of the wall and the cgroup ceilings, in
    /// snapshot order: the leaf's own row for a cgroup ceiling it holds, the
    /// supervisor's boot-clock deadline for the wall, and an unapplied row
    /// for anything else. An applied ceiling not yet hit says `false`; a
    /// null `hit` means unknown or unapplied (§6.4). The supervisor flips
    /// the wall's to `true` when the deadline expires.
    pub(in crate::platform::linux) fn ceiling_rows(
        limits: &LimitsSnapshot,
        leaf: Option<&ExecutionCgroup>,
    ) -> Vec<AppliedLimit> {
        let mut rows = Vec::new();
        for (key, ceiling) in [
            ("wall", limits.wall.as_ref()),
            ("pids", limits.pids.as_ref()),
            ("mem", limits.mem.as_ref()),
            ("swap", limits.swap.as_ref()),
            ("cpu", limits.cpu.as_ref()),
        ] {
            let Some(ceiling) = ceiling else { continue };
            if key != "wall"
                && let Some(limit) =
                    leaf.and_then(|leaf| leaf.limits().into_iter().find(|limit| limit.key == key))
            {
                rows.push(limit);
                continue;
            }
            let applied = key == "wall";
            rows.push(AppliedLimit {
                key: key.to_owned(),
                requested: ceiling.value.clone(),
                required: ceiling.required,
                applied,
                mechanism: applied.then(|| "boottime-deadline".to_owned()),
                scope: applied.then(|| "tree".to_owned()),
                hit: applied.then_some(false),
            });
        }
        rows
    }

    /// Reads whatever the launcher wrote to its error pipe (a failed exec's
    /// report, or a setup failure's errno) without blocking; `eof` is set
    /// once the pipe has closed.
    pub(in crate::platform::linux) fn drain_error_pipe(
        fd: &OwnedFd,
        bytes: &mut Vec<u8>,
        eof: &mut bool,
    ) {
        if *eof {
            return;
        }
        let mut buffer = [0u8; 64];
        loop {
            // SAFETY: the buffer is live, the length matches and the
            // descriptor is owned and non-blocking.
            let n = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if n > 0 {
                bytes.extend_from_slice(&buffer[..usize::try_from(n).unwrap_or(0)]);
                continue;
            }
            if n == 0 {
                *eof = true;
            }
            return;
        }
    }

    /// Whether the counters are due: always when `force`, otherwise once per
    /// [`LIMIT_SAMPLE_INTERVAL`]. A due sample moves `sampled_at_ns` to now.
    pub(in crate::platform::linux) fn sample_due(sampled_at_ns: &mut u64, force: bool) -> bool {
        let now = clock::boottime_ns();
        let interval = u64::try_from(LIMIT_SAMPLE_INTERVAL.as_nanos()).unwrap_or(u64::MAX);
        if !force && now.saturating_sub(*sampled_at_ns) < interval {
            return false;
        }
        *sampled_at_ns = now;
        true
    }

    /// Exec confirmation without an observer (§8.1 step 7). `settled` means
    /// there is nothing to decide here: an observer was attached (it is the
    /// witness), or the exec is already confirmed.
    ///
    /// The launcher sets the error pipe close-on-exec before it blocks, and
    /// measured on the reference host the only holder of that descriptor is
    /// the launcher itself (in a contained run, neither bubblewrap nor its
    /// reaper keeps a copy). So end-of-file with no bytes means the launcher
    /// closed it, by execing or by dying. A changed executable image is
    /// required too: a zombie keeps its birth identity, and even pidfd
    /// readiness can lag the descriptor's close during exit. If the image is
    /// unreadable or unchanged, exec stays unknown.
    pub(in crate::platform::linux) fn exec_without_observer(
        settled: bool,
        error_bytes: &[u8],
        error_eof: bool,
        launcher: &ProcessIdentity,
    ) -> bool {
        !settled
            && error_bytes.is_empty()
            && error_eof
            && launcher.is_live()
            && super::image_changed(launcher.pid)
    }

    /// The wall, reported once when it has passed: the hit is counted in the
    /// `limits` class, and the returned `WallExpired` asks the supervisor to
    /// stop the run.
    pub(in crate::platform::linux) fn check_wall(
        wall: Option<clock::Deadline>,
        reported: &mut bool,
        audit: &mut AuditWriter,
    ) -> Option<RunEvent> {
        if *reported || !wall.is_some_and(clock::Deadline::expired) {
            return None;
        }
        *reported = true;
        audit.record_limit_hit();
        Some(RunEvent::WallExpired)
    }

    /// Whether a requested cooperative stop has had its [`STOP_GRACE`]
    /// (§9.3) and must become a forced one.
    pub(in crate::platform::linux) fn grace_spent(
        hard_killed: bool,
        stop_requested: bool,
        stop_at: Option<u64>,
    ) -> bool {
        let grace = u64::try_from(STOP_GRACE.as_nanos()).unwrap_or(u64::MAX);
        !hard_killed
            && stop_requested
            && stop_at.is_some_and(|at| clock::boottime_ns().saturating_sub(at) >= grace)
    }

    /// Arms the forced stop, once: `true` the first time, when the caller
    /// kills its tree and the tree budget (§9.3) for seeing it die starts.
    pub(in crate::platform::linux) fn arm_hard_kill(
        hard_killed: &mut bool,
        hard_deadline: &mut Option<clock::Deadline>,
    ) -> bool {
        if *hard_killed {
            return false;
        }
        *hard_killed = true;
        *hard_deadline = Some(clock::Deadline::after(TREE_BUDGET));
        true
    }

    /// The target's outcome as the observer reported it, taken once. The
    /// observer's final status of the target also confirms its exec: when
    /// nothing confirmed the exec yet, `ExecConfirmed` comes first and the
    /// outcome is queued behind it.
    pub(in crate::platform::linux) fn observed_outcome(
        target_outcome: &mut Option<RunEvent>,
        exec_confirmed: &mut bool,
        pending: &mut VecDeque<RunEvent>,
    ) -> Option<RunEvent> {
        let outcome = target_outcome.take()?;
        if *exec_confirmed {
            return Some(outcome);
        }
        *exec_confirmed = true;
        pending.push_back(outcome);
        Some(RunEvent::ExecConfirmed)
    }

    /// The observer's account for the coverage summary of an observed run.
    /// Every such run stops its observer and keeps the account before it is
    /// summarized, so a missing one is a defect, and it reads as
    /// [`missing_account`], never as a clean, loss-free one.
    pub(in crate::platform::linux) fn observer_account(
        summary: Option<&TracerSummary>,
    ) -> TracerSummary {
        debug_assert!(
            summary.is_some(),
            "an observed run was summarized without its observer's account"
        );
        summary.cloned().unwrap_or_else(missing_account)
    }

    /// What a missing observer account stands for: no account at all, which
    /// is a panicked observer's (every field unreliable, so every audit
    /// class degraded, with a gap and a null count).
    pub(in crate::platform::linux) fn missing_account() -> TracerSummary {
        TracerSummary {
            thread_panicked: true,
            ..TracerSummary::default()
        }
    }

    /// What one read of the execution cgroup's counters established.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::platform::linux) enum Counters {
        /// Read, with every newly hit ceiling counted. `oom_killed`: the
        /// kernel's OOM killer has run in the leaf.
        Read { oom_killed: bool },
        /// The read failed, and [`counters_lost`] recorded it.
        Lost,
    }

    /// Reads the leaf's counters once and counts every newly hit ceiling in
    /// the `limits` class. A failed read is [`counters_lost`].
    pub(in crate::platform::linux) fn sample_counters(
        leaf: &mut ExecutionCgroup,
        audit: &mut AuditWriter,
    ) -> Counters {
        match leaf.sample() {
            Ok(hits) => {
                for _ in 0..hits {
                    audit.record_limit_hit();
                }
                Counters::Read {
                    oom_killed: leaf.oom_killed(),
                }
            }
            Err(_) => {
                counters_lost(leaf, audit, "cgroup_counters_unreadable");
                Counters::Lost
            }
        }
    }

    /// Counter evidence the leaf can no longer give (§11.4): every `hit`
    /// not yet seen becomes null, and the `limits` class records a gap
    /// naming `reason`, so it reads degraded with a null count instead of
    /// active with a count nothing supports.
    pub(in crate::platform::linux) fn counters_lost(
        leaf: &mut ExecutionCgroup,
        audit: &mut AuditWriter,
        reason: &str,
    ) {
        leaf.invalidate_hits();
        audit.record_limit_evidence_missing(reason);
    }
}

impl Drop for Boundary {
    fn drop(&mut self) {
        if self.child.is_some() || self.tracer.is_some() {
            self.teardown();
        } else {
            self.remove_placeholders();
        }
    }
}

#[cfg(test)]
mod tests {

    /// Issue draft 15: only the NVIDIA class under `/dev` is allowlisted,
    /// and only as a real character device.
    #[test]
    fn only_nvidia_device_nodes_are_allowlisted() {
        for refused in [
            "/dev/kvm",
            "/dev/fuse",
            "/dev/nvidia0/inner",
            "/dev/nvidia",
            "/dev/nvidia-uvm-extra",
            "/usr/bin/nvidia0",
            "/dev",
        ] {
            assert!(
                !is_allowed_device_node(Path::new(refused)),
                "{refused} is not an allowlisted device node"
            );
        }
        // On a GPU host the nodes themselves qualify; where they are absent
        // the metadata check keeps the answer false.
        let on_gpu_host = Path::new("/dev/nvidiactl").exists();
        assert_eq!(
            is_allowed_device_node(Path::new("/dev/nvidiactl")),
            on_gpu_host
        );
    }
    fn output_relay(origin: std::fs::File) -> (super::StdioRelay, std::os::fd::OwnedFd) {
        let (ours, child) = super::exec::pipe().unwrap();
        use std::os::fd::AsRawFd as _;
        super::set_nonblocking(ours.as_raw_fd()).unwrap();
        (
            super::StdioRelay {
                origin: origin.into(),
                origin_socket: false,
                ours: Some(ours),
                to_child: false,
                buffer: Vec::new(),
                origin_eof: false,
                finished: false,
            },
            child,
        )
    }

    #[test]
    fn blocking_socket_output_retains_backpressure_without_blocking_the_relay() {
        use std::io::Read as _;
        use std::os::fd::{AsRawFd as _, OwnedFd};
        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: a live socket and a correctly sized, initialized option.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const size).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        let (mut relay, writer) = output_relay(std::fs::File::from(OwnedFd::from(socket)));
        relay.origin_socket = true;
        relay.buffer = vec![b'x'; super::RELAY_BUFFER];
        drop(writer);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            tx.send((relay.pump(), relay)).unwrap();
        });
        let (result, mut relay) = match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(result) => result,
            Err(error) => {
                drop(peer);
                worker.join().unwrap();
                panic!("a socket write must not block supervision: {error}");
            }
        };
        worker.join().unwrap();
        assert!(result.unwrap());
        assert!(
            !relay.buffer.is_empty(),
            "backpressure retains undelivered output"
        );
        // SAFETY: querying flags on the live origin descriptor.
        let flags = unsafe { libc::fcntl(relay.origin.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            flags & libc::O_NONBLOCK,
            0,
            "shared origin flags stay unchanged"
        );
        peer.set_nonblocking(true).unwrap();
        let mut delivered = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while delivered.len() < super::RELAY_BUFFER {
            let mut chunk = [0u8; 8192];
            match peer.read(&mut chunk) {
                Ok(read) => delivered.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("socket delivery failed: {error}"),
            }
            relay.pump().unwrap();
            assert!(std::time::Instant::now() < deadline, "output did not drain");
        }
        assert_eq!(delivered, vec![b'x'; super::RELAY_BUFFER]);
        assert!(relay.done());
    }

    #[test]
    fn relay_batch_services_stderr_while_stdout_is_active() {
        use std::io::{Read as _, Seek as _};
        use std::os::fd::AsRawFd as _;
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let (out, out_writer) = output_relay(stdout.try_clone().unwrap());
        let (err, err_writer) = output_relay(stderr.try_clone().unwrap());
        super::relay_write(out_writer.as_raw_fd(), b"stdout remains active", false).unwrap();
        super::relay_write(err_writer.as_raw_fd(), b"stderr must arrive now", false).unwrap();
        let mut relays = [out, err];
        assert!(super::pump_stdio_relays(&mut relays).unwrap());
        let mut text = String::new();
        stderr.rewind().unwrap();
        stderr.read_to_string(&mut text).unwrap();
        assert_eq!(text, "stderr must arrive now");
        text.clear();
        stdout.rewind().unwrap();
        stdout.read_to_string(&mut text).unwrap();
        assert_eq!(text, "stdout remains active");
    }

    #[test]
    fn the_output_drain_waits_for_output_only() {
        use std::io::{Read as _, Seek as _};
        use std::os::fd::AsRawFd as _;
        let mut stdout = tempfile::tempfile().unwrap();
        let (out, writer) = output_relay(stdout.try_clone().unwrap());
        super::relay_write(writer.as_raw_fd(), b"last words", false).unwrap();
        drop(writer);
        // A stdin origin that never reaches end-of-file while its peer lives.
        let (origin, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (child_end, ours) = super::exec::pipe().unwrap();
        super::set_nonblocking(ours.as_raw_fd()).unwrap();
        let stdin = super::StdioRelay {
            origin: origin.into(),
            origin_socket: true,
            ours: Some(ours),
            to_child: true,
            buffer: Vec::new(),
            origin_eof: false,
            finished: false,
        };
        let mut relays = [out, stdin];
        let started = std::time::Instant::now();
        super::drain_output_relays(&mut relays, std::time::Duration::from_secs(5)).unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the drain waited for a stdin relay the target's end cannot finish"
        );
        assert!(relays[0].done());
        assert!(!relays[1].done(), "stdin stays open, unwaited for");
        let mut text = String::new();
        stdout.rewind().unwrap();
        stdout.read_to_string(&mut text).unwrap();
        assert_eq!(text, "last words");
        drop(child_end);
    }

    #[test]
    fn relay_output_errors_preserve_undelivered_bytes() {
        use std::os::fd::AsRawFd as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-only");
        std::fs::write(&path, b"original").unwrap();
        let (mut relay, writer) = output_relay(std::fs::File::open(&path).unwrap());
        super::relay_write(writer.as_raw_fd(), b"undelivered", false).unwrap();
        drop(writer);
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(relay.buffer, b"undelivered");
        assert!(!relay.done());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        let (mut relay, writer) = output_relay(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        );
        super::relay_write(writer.as_raw_fd(), b"disk full", false).unwrap();
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(relay.buffer, b"disk full");
    }

    #[test]
    fn relay_input_errors_are_not_eof() {
        use std::os::fd::AsRawFd as _;
        let dir = tempfile::tempdir().unwrap();
        let origin = std::fs::File::create(dir.path().join("write-only")).unwrap();
        let (read, write) = super::exec::pipe().unwrap();
        super::set_nonblocking(write.as_raw_fd()).unwrap();
        let mut relay = super::StdioRelay {
            origin: origin.into(),
            origin_socket: false,
            ours: Some(write),
            to_child: true,
            buffer: Vec::new(),
            origin_eof: false,
            finished: false,
        };
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert!(!relay.origin_eof);
        drop(read);
    }

    // Bubblewrap resolution (review F1, F2)
    fn executable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Security 2026-09-27 (audit 4 B7): the runtime tree is in the refused
    /// set by its path, whatever fstype carries it — a host whose `/run` is
    /// not tmpfs would otherwise slip the fstype branch.
    #[test]
    fn audit4_run_is_refused_by_path_whatever_its_fstype() {
        for mounts in [
            super::pseudo_fs_mount_points().unwrap(),
            super::parse_pseudo_fs_mount_points(b"22 1 0:1 / / rw - ext4 /dev/vda1 rw\n"),
        ] {
            assert!(
                mounts
                    .iter()
                    .any(|point| point == std::path::Path::new("/run")),
                "the /run entry is unconditional: {mounts:?}"
            );
        }
    }

    /// A mount table that cannot be read is no proof that a grant stays
    /// clear of the pseudo filesystems: the guard refuses, it never passes.
    #[test]
    fn an_unreadable_mount_table_refuses_every_grant() {
        let grant = [(PathBuf::from("/srv/data"), PathBuf::from("/srv/data"))];
        let error = super::refuse_pseudo_fs_grants_among(
            &grant,
            "filesystem.read_only",
            Err(std::io::Error::from_raw_os_error(libc::EACCES)),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(
            error.message.contains("mount table cannot be read"),
            "{}",
            error.message
        );
        assert!(
            super::refuse_pseudo_fs_grants_among(&grant, "filesystem.read_only", Ok(Vec::new()))
                .is_ok()
        );
    }

    #[test]
    fn resolver_sanitizer_never_falls_back_to_host_bytes() {
        for input in [
            None,
            Some(b"nameserver invalid".as_slice()),
            Some(b"nameserver 1.1.1.1\n\xff".as_slice()),
        ] {
            assert_eq!(
                super::sanitize_resolv_conf(input),
                (String::new(), "failed_closed")
            );
        }
        assert_eq!(
            super::sanitize_resolv_conf(Some(&vec![b'x'; 65537])).1,
            "failed_closed"
        );
        assert_eq!(
            super::sanitize_resolv_conf(Some(
                b"search private.example\nnameserver 1.1.1.1 # comment\noptions edns0\n"
            )),
            ("nameserver 1.1.1.1\n".into(), "nameservers_only")
        );
    }

    #[test]
    fn bubblewrap_resolves_only_from_absolute_entries_to_a_canonical_file() {
        use std::ffi::OsStr;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let first = root.join("first");
        let second = root.join("second");
        let link = root.join("link");
        for d in [&first, &second, &link] {
            std::fs::create_dir(d).unwrap();
        }
        executable(&second.join("bwrap"));
        let second_s = second.to_str().unwrap().to_owned();

        // An empty, a `.` and a relative entry are never searched, even
        // listed first; the first absolute entry holding one wins.
        for path in [
            format!(":{second_s}"),
            format!(".:{second_s}"),
            format!("rel:{second_s}"),
            format!("{}:{second_s}", first.display()),
        ] {
            assert_eq!(
                super::resolve_bwrap(Some(OsStr::new(&path))).unwrap(),
                second.join("bwrap"),
                "{path}"
            );
        }
        // A symlink is recorded as the file it names.
        std::os::unix::fs::symlink(second.join("bwrap"), link.join("bwrap")).unwrap();
        assert_eq!(
            super::resolve_bwrap(Some(OsStr::new(link.to_str().unwrap()))).unwrap(),
            second.join("bwrap")
        );
        // Not executable, or not a regular file: skipped.
        std::fs::write(first.join("bwrap"), b"").unwrap();
        std::fs::set_permissions(first.join("bwrap"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::create_dir(root.join("dir-named")).unwrap();
        std::fs::create_dir(root.join("dir-named").join("bwrap")).unwrap();
        let path = format!(
            "{}:{}:{second_s}",
            first.display(),
            root.join("dir-named").display()
        );
        assert_eq!(
            super::resolve_bwrap(Some(OsStr::new(&path))).unwrap(),
            second.join("bwrap")
        );
        // Nothing absolute holds one: refused, with the reason.
        for path in ["", ":", ".", "rel:.:"] {
            let reason = super::resolve_bwrap(Some(OsStr::new(path))).unwrap_err();
            assert!(reason.contains("no executable `bwrap`"), "{path}: {reason}");
            assert!(reason.contains("never searched"), "{path}: {reason}");
        }
        let reason = super::resolve_bwrap(Some(OsStr::new(first.to_str().unwrap()))).unwrap_err();
        assert!(!reason.contains("never searched"), "{reason}");
        // No PATH at all: refused, never the C library's default path.
        assert!(
            super::resolve_bwrap(None)
                .unwrap_err()
                .contains("PATH is unset")
        );
    }

    #[test]
    fn a_probe_never_executes_a_relative_or_missing_backend() {
        use super::super::probe::{self, ProbeStatus};
        let exe = std::path::Path::new("/nonexistent/ouro-jail");
        for (name, _) in probe::BACKEND_PROBES {
            for result in [
                probe::run_one(name, exe, std::path::Path::new("bwrap")),
                probe::run_one_backend(name, exe, Err("PATH is unset")),
            ] {
                // A table-bound probe is refused first off x86_64.
                if result.status == ProbeStatus::Unsupported {
                    continue;
                }
                assert_eq!(result.status, ProbeStatus::Unavailable, "{name}");
                assert_eq!(result.reason_code, "backend_unavailable", "{name}");
            }
        }
    }

    fn plan_for(profile: crate::policy::ProfileName, observe_off: bool) -> super::PlanRequest {
        let baseline = crate::profiles::baseline(profile, crate::records::Os::Linux, &|_| None);
        let inputs = crate::policy::ResolveInputs {
            platform: crate::records::Os::Linux,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: b"/work".to_vec(),
            scratch: crate::policy::ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        let mut snapshot = crate::policy::resolve(&inputs)
            .expect("the built-in baseline resolves")
            .snapshot;
        if observe_off {
            snapshot.observation.mode = crate::records::ObserveMode::Off;
        }
        let requirements = crate::capability::requirements(&snapshot);
        super::PlanRequest {
            snapshot,
            profile,
            requirements,
        }
    }

    /// Review F12: through the real requirement→probe mapping, a build for
    /// an architecture the tables do not cover leaves the filter, observer
    /// and proxy requirements unsupported (so `run` refuses before
    /// preparation), and nothing else: `none` with observation off still
    /// derives every requirement it needs.
    #[test]
    fn unsupported_architectures_the_real_mapping_refuses_exactly_the_table_bound_requirements() {
        use super::super::probe::{self, ProbeResult, ProbeStatus};
        use crate::capability::{
            CapabilityStatus, REQ_CLOSED_SET_OBSERVATION, REQ_NETWORK_PROXY, REQ_SYSCALL_FILTER,
        };
        use crate::policy::ProfileName;
        let results: Vec<ProbeResult> = probe::PROBE_NAMES
            .iter()
            .map(|name| {
                probe::architecture_refusal(name, "riscv64").unwrap_or_else(|| ProbeResult {
                    name,
                    status: ProbeStatus::Available,
                    mechanism: "test",
                    reason_code: "ok",
                    evidence: String::new(),
                })
            })
            .collect();
        let refused = [
            REQ_SYSCALL_FILTER,
            REQ_CLOSED_SET_OBSERVATION,
            REQ_NETWORK_PROXY,
        ];
        for (profile, observe_off, expected) in [
            (
                ProfileName::Tool,
                false,
                &[REQ_SYSCALL_FILTER, REQ_CLOSED_SET_OBSERVATION][..],
            ),
            (ProfileName::Tool, true, &[REQ_SYSCALL_FILTER][..]),
            (
                ProfileName::Build,
                false,
                &[REQ_SYSCALL_FILTER, REQ_CLOSED_SET_OBSERVATION][..],
            ),
            (
                ProfileName::Agent,
                false,
                &[
                    REQ_SYSCALL_FILTER,
                    REQ_CLOSED_SET_OBSERVATION,
                    REQ_NETWORK_PROXY,
                ][..],
            ),
            (ProfileName::None, false, &[REQ_CLOSED_SET_OBSERVATION][..]),
            (ProfileName::None, true, &[][..]),
        ] {
            let plan = plan_for(profile, observe_off);
            let capabilities = super::derive(&plan, &results, "2026-09-24T00:00:00Z");
            let mut unsatisfied = Vec::new();
            for requirement in &plan.requirements {
                let row = capabilities
                    .iter()
                    .find(|row| &row.name == requirement)
                    .unwrap_or_else(|| panic!("{profile:?}: no row for {requirement}"));
                if row.satisfies() {
                    continue;
                }
                assert_eq!(
                    row.status,
                    CapabilityStatus::Unsupported,
                    "{profile:?} {requirement}"
                );
                assert_eq!(
                    row.reason_code.as_deref(),
                    Some("unsupported_architecture"),
                    "{profile:?} {requirement}"
                );
                assert!(refused.contains(&requirement.as_str()), "{requirement}");
                unsatisfied.push(requirement.clone());
            }
            let mut expected: Vec<&str> = expected.to_vec();
            expected.sort_unstable();
            unsatisfied.sort();
            assert_eq!(
                unsatisfied, expected,
                "{profile:?} observe_off={observe_off}"
            );
        }
    }

    /// The fixed descriptors that share a table are distinct (see the
    /// layout note at the constants). The backend's map: stdio and every
    /// channel below `PINNED_FD_BASE`. The launcher's: the channels it keeps
    /// and the `agent` descriptors it places. `agent::BRIDGE_REPORT_FD` and
    /// `PINNED_FD_BASE` are both 20, in different tables.
    #[test]
    fn fixed_descriptors_that_share_a_table_are_distinct() {
        use super::super::{agent, watch};
        let backend = [
            watch::BACKEND_FD,
            TRACE_DATA_FD,
            SECCOMP_FD,
            STATUS_FD,
            RELEASE_FD,
            ERROR_FD,
            ARGS_FD,
            watch::START_FD,
            VENDOR_STATE_FD,
            agent::PROXY_DIR_FD,
        ];
        let launcher = [
            RELEASE_FD,
            ERROR_FD,
            TRACE_DATA_FD,
            agent::LISTENER_FD,
            agent::SOCKDIAG_FD,
            agent::BRIDGE_REPORT_FD,
        ];
        for (table, fds) in [("backend", &backend[..]), ("launcher", &launcher[..])] {
            let mut sorted = fds.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), fds.len(), "{table}: {fds:?}");
            assert!(fds.iter().all(|fd| *fd > 2), "{table} spares stdio");
        }
        assert!(backend.iter().all(|fd| *fd < PINNED_FD_BASE));
    }

    #[test]
    fn stalled_backend_argument_delivery_has_a_deadline() {
        use std::os::fd::AsRawFd;
        let (_reader, writer) = super::exec::pipe().unwrap();
        let deadline = super::clock::Deadline::after(std::time::Duration::from_millis(20));
        let error =
            super::write_until(writer.as_raw_fd(), &vec![0; 1024 * 1024], deadline).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
    #[test]
    fn a_run_probes_only_what_its_requirements_name() {
        assert!(super::probes_for("limit:wall").is_empty());
        // J3-agent: the agent network is measured, never granted for free.
        assert_eq!(
            super::probes_for(super::REQ_NETWORK_PROXY),
            [
                "bwrap_present",
                "network_namespace",
                "seccomp_user_notification",
                "unix_socket_diagnostics"
            ]
        );
        assert_eq!(super::probes_for("limit:pids"), ["cgroup_pids"]);
        assert_eq!(super::probes_for("limit:mem"), ["cgroup_memory"]);
        assert_eq!(super::probes_for("limit:storage"), ["storage_ceiling"]);
        assert_eq!(super::probes_for("limit:inodes"), ["storage_ceiling"]);
        assert_eq!(super::probes_for("limit:cpu"), ["cgroup_cpu"]);
        assert_eq!(
            super::probes_for("protected_coverage:existing_and_root"),
            super::probes_for(super::REQ_FILESYSTEM_CONTAINMENT)
        );
        assert!(
            super::probes_for(super::REQ_CLOSED_SET_OBSERVATION).contains(&"observer_closed_set")
        );
        assert!(super::probes_for("unknown:requirement").is_empty());
    }
    use super::*;

    fn mount_plan(root: &Path) -> BwrapPlan {
        for name in ["workspace", "scratch", "external", "attempt"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let mut plan = BwrapPlan::tool(
            &root.join("workspace"),
            &root.join("scratch"),
            &std::env::current_exe().unwrap(),
        );
        plan.roots.clear();
        plan.etc_paths.clear();
        plan.extra_rw_binds
            .push((root.join("external"), root.join("external")));
        plan
    }

    #[test]
    fn all_writable_roots_are_scanned_and_every_bind_is_pinned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        for name in ["workspace", "scratch", "external"] {
            std::fs::create_dir(root.join(name).join(".git")).unwrap();
        }
        let (scan, _pins, fds, placeholders) = prepare_mounts(
            &mut plan,
            &root.join("attempt"),
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        )
        .unwrap();
        assert_eq!(scan.segments.len(), 3);
        assert_eq!(placeholders.len(), 3);
        let rows = plan.mount_table();
        for dest in [
            root.join("workspace/.git"),
            root.join("external/.git"),
            PathBuf::from("/tmp/.git"),
        ] {
            assert!(
                rows.iter()
                    .any(|row| row.destination == dest && row.kind == "ro-bind")
            );
        }
        assert_eq!(
            fds.len(),
            rows.iter().filter(|row| row.source.is_some()).count()
        );
        for (row, fd) in rows.iter().zip(&plan.mount_fds) {
            if matches!(row.kind, "bind" | "ro-bind" | "placeholder") {
                assert!(fd.is_some());
            }
        }
        drop(placeholders);
    }

    #[test]
    fn a_missing_root_ouroboros_gets_a_real_placeholder_from_the_scan() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        std::fs::create_dir(root.join("workspace/.git")).unwrap();
        let attempt = root.join("attempt");
        let (_scan, _pins, _fds, placeholders) = prepare_mounts(
            &mut plan,
            &attempt,
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        )
        .unwrap();
        // The real scan/placeholder path: `prepare_mounts` creates the holder
        // under the attempt directory and the placeholder object at the root,
        // and the plan mounts it there. (The returned aggregate scan carries
        // segments, not per-root literal states — the placeholder count and
        // the mount row are the observable facts.)
        assert!(!placeholders.is_empty());
        let rows = plan.mount_table();
        let row = rows
            .iter()
            .find(|row| {
                row.kind == "placeholder" && row.destination == root.join("workspace/.ouroboros")
            })
            .expect("a placeholder mount for the absent workspace literal");
        assert!(
            Path::new(row.source.as_ref().expect("a holder source"))
                .starts_with(attempt.join("placeholders")),
            "the holder is not the attempt's placeholder directory: {row:?}"
        );
        assert!(
            root.join("workspace/.ouroboros").is_dir(),
            "the placeholder does not exist at the root"
        );
        drop(placeholders);
        assert!(
            !root.join("workspace/.ouroboros").exists(),
            "placeholder removal left the literal behind"
        );
    }

    /// The placeholders' holder is supervisor state, created through the
    /// state module's check (§6.2): under an ancestor anyone can replace
    /// entries in, it refuses, and leaves no placeholder behind.
    #[test]
    fn placeholder_holders_are_checked_like_all_supervisor_state() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mut plan = mount_plan(&root);
        let open = root.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let attempt = open.join("attempt");
        std::fs::create_dir(&attempt).unwrap();
        let Err(error) = prepare_mounts(
            &mut plan,
            &attempt,
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        ) else {
            panic!("a holder under a world-writable ancestor refuses");
        };
        assert_eq!(error.code, ErrorCode::UnsafeStatePath, "{}", error.message);
        for literal in [".git", ".ouroboros"] {
            assert!(!root.join("workspace").join(literal).exists(), "{literal}");
        }
    }

    #[test]
    fn protected_symlinks_in_extra_roots_refuse_before_launch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        std::os::unix::fs::symlink("elsewhere", root.join("external/.git")).unwrap();
        assert!(
            prepare_mounts(
                &mut plan,
                &root.join("attempt"),
                &jfs::PROTECTED_LITERALS,
                ProtectedCoverage::ExistingAndRoot
            )
            .is_err()
        );
    }

    #[test]
    fn large_protected_sets_keep_descriptor_backed_sources() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        for index in 0..240 {
            std::fs::create_dir_all(root.join(format!("workspace/repo-{index}/.git"))).unwrap();
        }
        let (_, _pins, fds, placeholders) = prepare_mounts(
            &mut plan,
            &root.join("attempt"),
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        )
        .unwrap();
        assert!(fds.len() > 240);
        let mut map = FdMap::with_target_limit(PINNED_FD_BASE + fds.len() as RawFd);
        for (fd, target) in fds {
            map.add(fd, target).unwrap();
        }
        drop(placeholders);
    }

    #[test]
    fn mountinfo_paths_decode_their_octal_escapes() {
        assert_eq!(
            decode_mountinfo_path(b"/work/a\\040b"),
            b"/work/a b".to_vec()
        );
        assert_eq!(decode_mountinfo_path(b"/plain"), b"/plain".to_vec());
    }

    // P01.8
    #[test]
    fn a_mount_point_that_is_not_utf8_keeps_the_whole_table() {
        let raw: &[u8] = b"22 1 0:1 / / ro,nosuid - tmpfs tmpfs ro\n\
            23 22 0:2 / /work/sec\xffret rw,nosuid - tmpfs tmpfs rw\n\
            24 22 0:3 / /work/a\\040b ro - tmpfs tmpfs ro\n";
        let table = parse_mount_table(raw).unwrap();
        let rows: Vec<(Vec<u8>, &str)> = table
            .iter()
            .map(|mount| (mount.path.as_bytes().to_vec(), mount.mode.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![
                (b"/".to_vec(), "ro"),
                (b"/work/sec\xffret".to_vec(), "rw"),
                (b"/work/a b".to_vec(), "ro"),
            ]
        );
    }

    /// The table is read whole or not at all: a row the parser cannot read,
    /// or more rows than a receipt records, refuses instead of shortening.
    #[test]
    fn a_mount_table_is_never_recorded_in_part() {
        assert!(parse_mount_table(b"22 1 0:1 / / ro - tmpfs tmpfs ro\n\n").is_ok());
        assert!(parse_mount_table(b"22 1 0:1\n").is_err(), "a short row");
        assert!(parse_mount_table(b"22 1 0:1 / /a\\000b ro - tmpfs t ro\n").is_err());
        let row = |index: usize| format!("{index} 1 0:1 / /m{index} ro - tmpfs tmpfs ro\n");
        let full: String = (0..MOUNT_TABLE_ROWS_MAX).map(row).collect();
        assert_eq!(
            parse_mount_table(full.as_bytes()).unwrap().len(),
            MOUNT_TABLE_ROWS_MAX
        );
        let over = format!("{full}{}", row(MOUNT_TABLE_ROWS_MAX));
        let error = parse_mount_table(over.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("more than"), "{error}");
    }

    #[test]
    fn an_unreadable_environment_is_not_an_empty_one() {
        // SAFETY: getpid takes no arguments and cannot fail.
        let own = unsafe { libc::getpid() };
        assert!(!read_environment_names(own).unwrap().is_empty());
        // No process has this pid: pid_max is far below it.
        assert!(read_environment_names(libc::pid_t::MAX).is_err());
        assert!(read_mount_table(libc::pid_t::MAX).is_err());
    }

    #[test]
    fn a_requirement_with_no_probe_is_never_available() {
        let capability = capability_for("something_new", &[], "2026-09-22T00:00:00Z");
        assert_eq!(capability.status, CapabilityStatus::Unsupported);
        assert!(!capability.satisfies());
    }

    #[test]
    fn a_missing_probe_makes_the_requirement_skipped_not_available() {
        let capability = capability_for(REQ_SYSCALL_FILTER, &[], "2026-09-22T00:00:00Z");
        assert_eq!(capability.status, CapabilityStatus::Skipped);
        assert_eq!(capability.reason_code.as_deref(), Some("probe_not_run"));
        assert!(!capability.satisfies());
    }

    #[test]
    fn the_wall_is_the_supervisors_own_mechanism() {
        let capability = capability_for("limit:wall", &[], "2026-09-22T00:00:00Z");
        assert!(capability.satisfies());
        assert_eq!(capability.mechanism.as_deref(), Some("boottime-deadline"));
    }

    #[test]
    fn storage_ceilings_rest_on_the_storage_ceiling_probe() {
        // L6: the rows no longer claim the filesystem-containment probes.
        let unmeasured = capability_for("limit:storage", &[], "2026-09-22T00:00:00Z");
        assert_eq!(unmeasured.status, CapabilityStatus::Skipped);
        assert_eq!(
            unmeasured.mechanism.as_deref(),
            Some("bounded-tmpfs-or-user-quota")
        );
        let probe = |status, reason: &'static str| ProbeResult {
            name: "storage_ceiling",
            status,
            mechanism: "bounded-tmpfs-or-user-quota",
            reason_code: reason,
            evidence: String::new(),
        };
        let refused = capability_for(
            "limit:storage",
            &[probe(ProbeStatus::Unavailable, "no_user_hard_quota")],
            "2026-09-22T00:00:00Z",
        );
        assert_eq!(refused.status, CapabilityStatus::Unavailable);
        assert_eq!(refused.reason_code.as_deref(), Some("no_user_hard_quota"));
        let unbounded = capability_for(
            "limit:inodes",
            &[probe(ProbeStatus::Unavailable, "tmpfs_unbounded")],
            "2026-09-22T00:00:00Z",
        );
        assert_eq!(unbounded.status, CapabilityStatus::Unavailable);
        assert!(
            capability_for(
                "limit:inodes",
                &[probe(ProbeStatus::Available, "ok")],
                "2026-09-22T00:00:00Z"
            )
            .satisfies()
        );
    }

    #[test]
    fn a_tracee_the_observer_had_to_kill_means_the_tree_is_unverified() {
        // Nothing to object to when no observer ran.
        assert!(observer_verdict(None));
        assert!(observer_verdict(Some(&TracerSummary::default())));

        let mut abandoned = TracerSummary::default();
        abandoned.loss.abandoned_tracees = 1;
        assert!(
            !observer_verdict(Some(&abandoned)),
            "a tracee killed on the way out is not an observed death"
        );

        let unreaped = TracerSummary {
            unreaped_children: vec![4242],
            ..TracerSummary::default()
        };
        assert!(
            !observer_verdict(Some(&unreaped)),
            "a child whose exit status has no route left is not an observed death"
        );

        let panicked = TracerSummary {
            thread_panicked: true,
            ..TracerSummary::default()
        };
        assert!(
            !observer_verdict(Some(&panicked)),
            "a panicked observer's counters cannot verify anything"
        );
    }

    #[test]
    fn wrong_guess_trace_stops_are_counted_in_the_receipts_native_details() {
        // Security 2026-09-27 (audit 3 A5): the receipt carries the counter, or
        // null when no observer ran, so a detail never claims a count nothing
        // read.
        assert_eq!(super::wrong_guess_stops_detail(None), Value::Null);
        let mut summary = TracerSummary::default();
        assert_eq!(
            super::wrong_guess_stops_detail(Some(&summary)),
            serde_json::json!(0)
        );
        summary.requested_by_other_filters = 10;
        assert_eq!(
            super::wrong_guess_stops_detail(Some(&summary)),
            serde_json::json!(10)
        );
    }

    #[test]
    fn a_tree_is_only_empty_when_every_fact_says_its_end_was_seen() {
        let seen = TreeInputs {
            init_alive: false,
            backend_reaped: true,
            tracer_finished: true,
            natural_end: true,
            abandoned_tracees: 0,
            unreaped_children: 0,
            requested_by_other_filters: 0,
            observer_panicked: false,
        };
        let verified = verdict(&seen);
        assert_eq!(verified.tree_empty, Some(true));
        assert_eq!(verified.integrity, "verified");
        assert!(verified.verified_at.is_some());

        // Security 2026-09-27 (audit 3 A5): wrong-guess trace stops are carried
        // for the receipt, and because each was continued they are not loss:
        // they never unverify the tree.
        let guessed = TreeInputs {
            requested_by_other_filters: 15,
            ..seen
        };
        assert_eq!(guessed.requested_by_other_filters, 15);
        assert_eq!(
            verdict(&guessed).tree_empty,
            Some(true),
            "a continued wrong-guess stop is not an unobserved death"
        );

        // Each fact on its own is enough to withhold the claim, and none of
        // them turns it into a claim that the tree is NOT empty: unknown is
        // unknown.
        let doubts = [
            (
                "the init is still there",
                TreeInputs {
                    init_alive: true,
                    ..seen
                },
            ),
            (
                "the backend was never reaped",
                TreeInputs {
                    backend_reaped: false,
                    ..seen
                },
            ),
            (
                "the observer did not finish",
                TreeInputs {
                    tracer_finished: false,
                    ..seen
                },
            ),
            (
                "the budget ran out",
                TreeInputs {
                    natural_end: false,
                    ..seen
                },
            ),
            (
                "a tracee had to be killed",
                TreeInputs {
                    abandoned_tracees: 1,
                    ..seen
                },
            ),
            (
                "a child's status was lost",
                TreeInputs {
                    unreaped_children: 1,
                    ..seen
                },
            ),
            (
                "the observer panicked",
                TreeInputs {
                    observer_panicked: true,
                    ..seen
                },
            ),
        ];
        for (why, inputs) in doubts {
            let observation = verdict(&inputs);
            assert_eq!(observation.tree_empty, None, "{why}");
            assert_eq!(observation.verified_at, None, "{why}");
            assert_ne!(observation.integrity, "verified", "{why}");
            assert_eq!(observation.verification_scope, "attempt_tree", "{why}");
        }
    }

    #[test]
    fn a_proxy_requirement_rests_on_measured_probes_and_never_on_a_skip() {
        // J3-agent: no longer unsupported; derived from what was measured.
        let unmeasured = capability_for(REQ_NETWORK_PROXY, &[], "2026-09-22T00:00:00Z");
        assert_eq!(unmeasured.status, CapabilityStatus::Skipped);
        let ok = |name: &'static str| ProbeResult {
            name,
            status: ProbeStatus::Available,
            mechanism: "m",
            reason_code: "ok",
            evidence: String::new(),
        };
        let all = [
            ok("bwrap_present"),
            ok("network_namespace"),
            ok("seccomp_user_notification"),
            ok("unix_socket_diagnostics"),
        ];
        let measured = capability_for(REQ_NETWORK_PROXY, &all, "2026-09-22T00:00:00Z");
        assert_eq!(measured.status, CapabilityStatus::Available);
        let mut no_diag = all.clone();
        no_diag[3].status = ProbeStatus::Unavailable;
        no_diag[3].reason_code = "unix_socket_diagnostics_unavailable";
        let no_diag = capability_for(REQ_NETWORK_PROXY, &no_diag, "2026-09-22T00:00:00Z");
        assert_eq!(no_diag.status, CapabilityStatus::Unavailable);
        assert_eq!(
            no_diag.reason_code.as_deref(),
            Some("unix_socket_diagnostics_unavailable")
        );
        let mut refused = all.clone();
        refused[2].status = ProbeStatus::Unavailable;
        refused[2].reason_code = "listener_refused";
        let refused = capability_for(REQ_NETWORK_PROXY, &refused, "2026-09-22T00:00:00Z");
        assert_eq!(refused.status, CapabilityStatus::Unavailable);
        assert_eq!(refused.reason_code.as_deref(), Some("listener_refused"));
        assert_eq!(
            probes_for(REQ_NETWORK_PROXY),
            &[
                "bwrap_present",
                "network_namespace",
                "seccomp_user_notification",
                "unix_socket_diagnostics"
            ]
        );
    }

    #[test]
    fn a_launcher_setup_failure_names_the_mechanism_it_could_not_establish() {
        let busy = libc::EBUSY.to_le_bytes();
        let mediation =
            launcher_failure(Some(super::super::launch::EXIT_MEDIATION_FAILED), &busy, "");
        assert_eq!(mediation.code, ErrorCode::MissingCapability);
        assert_eq!(mediation.exit_code(), 125);
        assert!(
            mediation.message.contains("unix-peer mediation"),
            "{}",
            mediation.message
        );
        assert!(mediation.message.contains("EBUSY"), "{}", mediation.message);
        let bridge = launcher_failure(Some(super::super::launch::EXIT_BRIDGE_FAILED), &[], "");
        assert!(
            bridge.message.contains("`agent` bridge"),
            "{}",
            bridge.message
        );
        assert!(bridge.message.contains("no errno reported"));
        let other = launcher_failure(Some(1), &[], "{\"exit-code\": 1}");
        assert_eq!(other.code, ErrorCode::BackendUnavailable);
        assert!(!other.message.contains("agent"));
    }

    // The staged hand-off is checked against the policy
    fn launch_snapshot(profile: ProfileName, bind_ro: bool) -> PolicySnapshot {
        use crate::policy::{
            CredentialDecl, LaunchSnapshot, ResolveInputs, ScratchRoot, VendorStateRoot,
        };
        let inputs = ResolveInputs {
            platform: Os::Linux,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline: crate::profiles::baseline(profile, Os::Linux, &|_| None),
            workspace: b"/work".to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        let mut snapshot = crate::policy::resolve(&inputs).unwrap().snapshot;
        snapshot.roots.vendor_state = Some(VendorStateRoot::Managed);
        snapshot.launch = Some(LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: Vec::new(),
            credentials: if bind_ro {
                vec![CredentialDecl {
                    vault: None,
                    id: "c".to_owned(),
                    source: NativeString::Text("/src/c".to_owned()),
                    dest: NativeString::Text("c".to_owned()),
                    mode: "bind_ro".to_owned(),
                }]
            } else {
                Vec::new()
            },
        });
        snapshot
    }

    fn handoff(root: &std::path::Path, bind: bool) -> crate::credentials::LaunchHandoff {
        use crate::credentials::{BindHandle, LaunchHandoff, VendorStateHandle};
        use crate::state::anchored::{Dir, Name, fstat};
        use std::os::fd::AsFd as _;
        use std::sync::Arc;
        let dir = Dir::open_trusted(root).unwrap();
        let vendor = dir.mkdir_at(&Name::new(b"v").unwrap(), 0o700).unwrap();
        std::fs::write(root.join("c"), b"c").unwrap();
        let source = dir.open_path_at(&Name::new(b"c").unwrap()).unwrap();
        let source_identity = fstat(source.as_fd()).unwrap().identity();
        let vendor_identity = vendor.stat().unwrap().identity();
        LaunchHandoff {
            vault: Vec::new(),
            vendor_state: Some(VendorStateHandle {
                host_path: root.join("v"),
                fd: Arc::new(vendor.into_fd()),
                identity: vendor_identity,
            }),
            binds: if bind {
                vec![BindHandle {
                    id: "c".to_owned(),
                    fd: Arc::new(source),
                    dest: NativeString::Text("c".to_owned()),
                    identity: source_identity,
                }]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn a_matching_hand_off_is_bound_and_every_mismatch_refuses() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        let good = handoff(&path, true);
        let staged = super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&good))
            .expect("a matching hand-off");
        assert!(staged.vendor.is_some());
        assert_eq!(staged.credentials.len(), 1);
        assert_eq!(
            staged.credentials[0].1,
            std::path::Path::new("/run/ouro/state/c")
        );

        // Credentials under `tool` (§6.1), even with a matching hand-off.
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Tool, true), Some(&good)).is_err()
        );
        // Managed vendor state with nothing staged, and credentials with no
        // vendor state at all.
        assert!(super::staged_mounts(&launch_snapshot(ProfileName::Agent, false), None).is_err());
        let mut stateless = launch_snapshot(ProfileName::Agent, true);
        stateless.roots.vendor_state = None;
        assert!(super::staged_mounts(&stateless, None).is_err());
        // A bind the policy does not declare.
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, false), Some(&good)).is_err()
        );
        // A declared bind that was not staged.
        let other = tempfile::tempdir().unwrap();
        let unbound = handoff(&other.path().canonicalize().unwrap(), false);
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&unbound))
                .is_err()
        );
        // A bind whose id or destination the policy does not declare, with
        // the count right (J3 review RM36).
        let mut renamed = good.clone();
        renamed.binds[0].dest = NativeString::Text("elsewhere".to_owned());
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&renamed))
                .is_err()
        );
        let mut relabelled = good.clone();
        relabelled.binds[0].id = "other".to_owned();
        assert!(
            super::staged_mounts(
                &launch_snapshot(ProfileName::Agent, true),
                Some(&relabelled)
            )
            .is_err()
        );
        // A descriptor that is not the object staging recorded.
        let mut swapped = good.clone();
        swapped.binds[0].identity = (0, 0);
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&swapped))
                .is_err()
        );
        let mut moved = good;
        if let Some(vendor) = moved.vendor_state.as_mut() {
            vendor.identity = (0, 0);
        }
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&moved)).is_err()
        );
    }
    /// Unreadable counters leave every `hit: false` unsupported (§11.4). The
    /// sample both boundaries take records the `limits` gap, so the class
    /// reads degraded with a null count in a contained run exactly as in
    /// `none`, instead of active with a count nothing supports.
    #[test]
    fn lost_counters_degrade_the_limits_class() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("leaf");
        std::fs::create_dir(&path).unwrap();
        for (name, value) in [
            ("cgroup.kill", ""),
            ("cgroup.procs", ""),
            ("cgroup.events", "populated 0\n"),
            ("pids.max", ""),
            ("pids.events", "max 0\n"),
        ] {
            std::fs::write(path.join(name), value).unwrap();
        }
        let limits = crate::policy::LimitsSnapshot {
            wall: None,
            pids: Some(crate::policy::LimitCeiling {
                value: "64".to_owned(),
                required: true,
            }),
            mem: None,
            swap: None,
            storage: None,
            inodes: None,
            cpu: None,
        };
        let mut leaf = ExecutionCgroup::open_for_test_with(&path, &limits).unwrap();
        let mut audit = AuditWriter::new(
            "att_00000000-0000-4000-8000-000000000001",
            None,
            b"/work",
            b"/tmp",
        );
        assert_eq!(
            shared::sample_counters(&mut leaf, &mut audit),
            shared::Counters::Read { oom_killed: false }
        );
        assert_eq!(
            audit.limits_class().status,
            crate::records::SourceStatus::Active
        );
        assert_eq!(leaf.limits()[0].hit, Some(false));

        std::fs::remove_file(path.join("pids.events")).unwrap();
        assert_eq!(
            shared::sample_counters(&mut leaf, &mut audit),
            shared::Counters::Lost
        );
        let class = audit.limits_class();
        assert_eq!(class.status, crate::records::SourceStatus::Degraded);
        assert_eq!(class.observed_count, None);
        assert!(
            class
                .gaps
                .iter()
                .any(|gap| gap.reason == "cgroup_counters_unreadable"),
            "{class:?}"
        );
        assert_eq!(
            leaf.limits()[0].hit,
            None,
            "an unread counter claims no `false`"
        );
    }

    /// A missing observer account is no account: every audit class of an
    /// observed run reads degraded with a null count, never active and
    /// loss-free.
    #[test]
    fn a_missing_observer_account_degrades_every_audit_class() {
        use crate::observer::CoverageClass;
        let audit = AuditWriter::new(
            "att_00000000-0000-4000-8000-000000000001",
            None,
            b"/work",
            b"/tmp",
        );
        let summary = audit.summary(&shared::missing_account(), true);
        for class in [
            CoverageClass::Exec,
            CoverageClass::FsWrite,
            CoverageClass::FsDeny,
            CoverageClass::Net,
        ] {
            let row = &summary.classes[&class];
            assert_eq!(
                row.status,
                crate::records::SourceStatus::Degraded,
                "{class:?}"
            );
            assert_eq!(row.observed_count, None, "{class:?}");
            assert!(!row.gaps.is_empty(), "{class:?} names no gap");
        }
        let clean = audit.summary(&TracerSummary::default(), true);
        assert_eq!(
            clean.classes[&CoverageClass::Exec].status,
            crate::records::SourceStatus::Active
        );
    }

    #[test]
    #[should_panic(expected = "without its observer's account")]
    fn summarizing_an_observed_run_without_its_account_is_a_defect() {
        let _ = shared::observer_account(None);
    }

    /// The init's liveness comes from its pidfd once one is held: a zombie
    /// has exited although its `/proc` entry is still there, and a pid
    /// number can come to name another process, while the descriptor
    /// cannot.
    #[test]
    fn init_liveness_is_read_from_its_pidfd() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let fd = identity::pidfd_open(pid).unwrap();
        assert!(init_alive(Some(&fd), pid));
        child.kill().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !super::super::watch::readable(fd.as_raw_fd()) {
            assert!(
                std::time::Instant::now() < deadline,
                "SIGKILL not delivered"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            Path::new(&format!("/proc/{pid}")).exists(),
            "the unreaped zombie keeps its /proc entry"
        );
        assert!(!init_alive(Some(&fd), pid), "an exited init is not alive");
        child.wait().unwrap();
        assert!(!init_alive(None, -1), "no init named: none alive");
    }

    /// A storage ceiling adds the hard-link denials to the `agent` baseline
    /// bubblewrap installs. The receipt's agent detail names that program —
    /// the one `applied.syscalls.digest` names — never the plain baseline,
    /// which does not run.
    #[test]
    fn the_agent_detail_names_the_installed_baseline_with_its_storage_rules() {
        use super::super::agent::AgentNet;
        use super::super::seccomp::{AgentVariant, agent_baseline_with_storage};
        let snapshot = plan_for(ProfileName::Agent, false).snapshot;
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        for bounded_storage in [false, true] {
            let proxy = root.join(format!("proxy-{bounded_storage}"));
            std::fs::create_dir(&proxy).unwrap();
            let dir = crate::state::anchored::Dir::open_trusted(&proxy).unwrap();
            let identity = dir.stat().unwrap().identity();
            let handoff = crate::platform::ProxyDirHandoff {
                host_path: proxy,
                fd: std::sync::Arc::new(dir.into_fd()),
                identity,
                socket: std::sync::Arc::new(std::sync::OnceLock::new()),
            };
            // A relative backend is never executed, so nesting measures
            // unavailable and the variant is the unprivileged one.
            let agent = AgentNet::prepare(
                "att_00000000-0000-4000-8000-000000000001",
                None,
                &snapshot,
                &handoff,
                Path::new("/nonexistent/ouro-jail"),
                Path::new("bwrap"),
                bounded_storage,
            )
            .unwrap();
            assert_eq!(agent.variant(), AgentVariant::UnprivilegedInner);
            let installed =
                agent_baseline_with_storage(AgentVariant::UnprivilegedInner, bounded_storage)
                    .unwrap();
            assert_eq!(agent.baseline(), &installed);
            assert_eq!(
                agent.details().0["baseline_filter_digest"],
                installed.digest().as_str(),
                "storage {bounded_storage}"
            );
        }
        assert_ne!(
            agent_baseline_with_storage(AgentVariant::UnprivilegedInner, true)
                .unwrap()
                .digest(),
            agent_baseline_with_storage(AgentVariant::UnprivilegedInner, false)
                .unwrap()
                .digest(),
            "the storage rules change the installed program"
        );
    }

    #[test]
    fn an_abort_is_verified_only_by_every_settlement_fact() {
        use super::{AbortInputs, abort_verdict};
        let good = AbortInputs {
            backend_reaped: true,
            watcher_reaped: true,
            init_dead: true,
            cgroup_empty: true,
            abandoned_tracees: 0,
            observer_panicked: false,
            unreaped_children: vec![10, 11],
            requested_by_other_filters: 0,
            backend_pid: 10,
            watcher_pid: 11,
        };
        assert!(abort_verdict(&good));
        assert!(abort_verdict(&AbortInputs {
            unreaped_children: Vec::new(),
            ..good.clone()
        }));
        // Security 2026-09-27 (audit 3 A5): wrong-guess trace stops ride in the
        // inputs for the receipt and never unverify the abort, because each
        // was continued and nothing was lost.
        let guessed = AbortInputs {
            requested_by_other_filters: 10,
            ..good.clone()
        };
        assert_eq!(guessed.requested_by_other_filters, 10);
        assert!(
            abort_verdict(&guessed),
            "a continued wrong-guess stop is not an unobserved death"
        );
        for broken in [
            AbortInputs {
                backend_reaped: false,
                ..good.clone()
            },
            AbortInputs {
                watcher_reaped: false,
                ..good.clone()
            },
            AbortInputs {
                init_dead: false,
                ..good.clone()
            },
            AbortInputs {
                cgroup_empty: false,
                ..good.clone()
            },
            AbortInputs {
                abandoned_tracees: 1,
                ..good.clone()
            },
            AbortInputs {
                observer_panicked: true,
                ..good.clone()
            },
            AbortInputs {
                unreaped_children: vec![10, 11, 12],
                ..good.clone()
            },
        ] {
            assert!(!abort_verdict(&broken), "{broken:?}");
        }
    }
}
