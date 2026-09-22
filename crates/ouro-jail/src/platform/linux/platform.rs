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

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
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
use super::bwrap::{self, BwrapPlan, Placeholder, PlaceholderOutcome};
use super::cgroup::ExecutionCgroup;
use super::clock::{self, boottime_ns};
use super::exec::{self, FdMap, reap_until};
use super::fs as jfs;
use super::identity;
use super::probe::{self, ProbeResult, ProbeStatus};
use super::seccomp;
use super::tracer::{Tracer, TracerConfig, TracerEvent, TracerSummary};

/// Descriptor the seccomp program is handed to bubblewrap on.
const SECCOMP_FD: RawFd = 10;
/// Descriptor bubblewrap writes its JSON status to.
pub(crate) const STATUS_FD: RawFd = 11;
/// Descriptor the launcher blocks reading.
const RELEASE_FD: RawFd = 12;
/// Descriptor the launcher writes a failed exec's errno to.
const ERROR_FD: RawFd = 13;
/// Descriptor a long argument list is handed over.
const ARGS_FD: RawFd = 14;
/// First fixed descriptor number used for pinned protected binds
/// (`--ro-bind-fd`); the fixed channel descriptors live below it.
const PINNED_FD_BASE: RawFd = 20;

/// Preparation budget (§8.2).
const PREPARE_BUDGET: Duration = Duration::from_secs(30);
/// Cooperative termination grace (§9.3).
const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long a natural finish is awaited before the tree is terminated.
const SETTLE_GRACE: Duration = Duration::from_millis(500);
/// Longest single block inside `wait`, so every source is re-checked often.
const WAIT_STEP: Duration = Duration::from_millis(10);
/// How often the execution cgroup's counters are read while the target runs;
/// they are always read once more before an outcome is classified.
const LIMIT_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// The Linux platform.
#[derive(Clone, Debug)]
pub struct LinuxPlatform {
    bwrap: PathBuf,
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPlatform {
    /// The platform with bubblewrap looked up on `PATH`.
    #[must_use]
    pub fn new() -> Self {
        LinuxPlatform {
            bwrap: find_bwrap(),
        }
    }

    /// The bubblewrap binary this platform will use.
    #[must_use]
    pub fn bwrap(&self) -> &Path {
        &self.bwrap
    }
}

/// The backend, looked up on the operator's `PATH`.
///
/// There is no fallback to a well-known location. An operator whose `PATH`
/// does not contain bubblewrap has not provisioned this host for the backend,
/// and `doctor` should say the backend is unavailable rather than reach past
/// what they configured and report a capability they did not offer.
fn find_bwrap() -> PathBuf {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("bwrap");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("bwrap")
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
        REQ_EXECUTION_CGROUP => Some((
            &["cgroup_delegated_leaf"],
            "cgroup-v2-delegated",
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
        "limit:wall" | REQ_NETWORK_PROXY => &[],
        "limit:pids" => &["cgroup_pids"],
        "limit:mem" => &["cgroup_memory"],
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
    if requirement == REQ_NETWORK_PROXY {
        return Capability {
            name: requirement.to_owned(),
            status: CapabilityStatus::Unsupported,
            scope: CapabilityScope::Tree,
            mechanism: None,
            reason_code: Some("proxy_not_implemented".to_owned()),
            measured_at: None,
            evidence_ref: None,
        };
    }
    if requirement.starts_with("limit:") && requirement != "limit:wall" {
        return capability_from(
            requirement,
            probes_for(requirement),
            "cgroup-v2-delegated",
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
        let results: Vec<ProbeResult> = probe::PROBE_NAMES
            .iter()
            .filter(|name| wanted(name))
            .map(|name| probe::run_one(name, &exe, &self.bwrap))
            .collect();
        let measured_at = rfc3339_utc(SystemTime::now());

        let mut out: Vec<Capability> = plan
            .requirements
            .iter()
            .map(|requirement| capability_for(requirement, &results, &measured_at))
            .collect();
        // The probe rows themselves, so `doctor --json` reports what was
        // measured and not only what the plan happened to ask for (§14.1).
        for result in &results {
            out.push(Capability {
                name: result.name.to_owned(),
                status: status_of(result),
                scope: CapabilityScope::Host,
                mechanism: Some(result.mechanism.to_owned()),
                reason_code: Some(result.reason_code.to_owned()),
                measured_at: Some(measured_at.clone()),
                evidence_ref: Some(result.evidence.clone()),
            });
        }
        out
    }
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
        let prepared = Boundary::create(&self.bwrap, plan, sinks, deadline)?;
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
    child: Option<Child>,
    bwrap_pid: libc::pid_t,
    /// A descriptor for bubblewrap, taken while it was known to be itself. A
    /// pid number can come to mean another process; a pidfd cannot (§9.3).
    bwrap_fd: Option<OwnedFd>,
    init_pid: libc::pid_t,
    /// The same, for the namespace init.
    init_fd: Option<OwnedFd>,
    launcher: identity::ProcessIdentity,
    /// The launcher's own descriptor, for the cooperative stop.
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
    observe_on: bool,
    ns_ids: identity::NsIds,
    cgroup: Option<ExecutionCgroup>,
    cgroup_lost: bool,
    /// Why no execution cgroup exists, when preferred ceilings run unenforced.
    cgroup_unavailable: Option<String>,
    watcher: super::watch::Watcher,
}
impl Boundary {
    /// Whether the backend's pidfd reports its exit, independent of whether
    /// its status has been collected yet.
    fn backend_exited(&self) -> bool {
        self.bwrap_fd
            .as_ref()
            .is_some_and(|fd| super::watch::readable(fd.as_raw_fd()))
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
        plan: PreparedPlan,
        sinks: Sinks,
        deadline: clock::Deadline,
    ) -> Result<Boundary, JailError> {
        let snapshot = plan.request.snapshot.clone();
        // §5.2: effective UID 0 and mismatched real/effective UIDs refuse in
        // v1 — a privileged supervisor is a boundary this slice does not
        // model, and the child-side capability readback is not a substitute
        // for refusing to be privileged in the first place.
        let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        if euid == 0 || ruid != euid {
            return Err(error(
                ErrorCode::UnsupportedPlatform,
                ErrorStage::Preparing,
                Remediation::HostSetup,
                format!(
                    "this slice refuses a privileged or setuid supervisor: real uid {ruid}, \
                     effective uid {euid} (jail-v1 §5.2)"
                ),
            ));
        }
        if snapshot.profile == ProfileName::Agent {
            return Err(error(
                ErrorCode::NestingFailed,
                ErrorStage::Preparing,
                Remediation::HostSetup,
                "the `agent` profile needs a nested sandbox, which this host denies".to_owned(),
            ));
        }
        if !snapshot.profile.is_contained() {
            return Err(error(
                ErrorCode::UnsupportedPlatform,
                ErrorStage::Preparing,
                Remediation::Unsupported,
                "the uncontained `none` profile is not implemented in this slice".to_owned(),
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
        validate_stdio(state_root)?;

        // The scratch directory the child sees as /tmp.
        let scratch = match &snapshot.roots.scratch {
            ScratchRoot::Managed => plan.attempt_dir.join("scratch"),
            ScratchRoot::Host { path } => {
                PathBuf::from(OsString::from_vec(path.as_bytes().to_vec()))
            }
        };
        create_private_dir(&scratch)?;

        let cgroup_required = [
            &snapshot.limits.pids,
            &snapshot.limits.mem,
            &snapshot.limits.cpu,
        ]
        .into_iter()
        .flatten()
        .any(|limit| limit.required);
        let mut cgroup_unavailable = None;
        let cgroup = match ExecutionCgroup::create(&snapshot.limits) {
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
        // answer (§9.1). Operator-configured protected_segments extend the
        // built-in literals for the walk (§6.3).
        let mut names: Vec<String> = jfs::PROTECTED_LITERALS
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        for extra in &snapshot.filesystem.protected_segments {
            if !names.iter().any(|name| name == extra) {
                names.push(extra.clone());
            }
        }
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut bplan = BwrapPlan::tool(&plan.workspace, &scratch, &exe);
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

        // Operator grants are enforced, not merely recorded (I02, north-star
        // §4.2): read-only grants become additional ro-binds at their
        // resolved paths, host-rooted writable grants become binds, and
        // denied subtrees are masked with a tmpfs over the path. Grants under
        // the workspace or scratch are covered by the base binds and layered
        // by mount order.
        for reference in &snapshot.filesystem.read_only {
            if let Ok(host) = host_path_of(reference, &plan.workspace, &scratch) {
                // The runtime plan already renders merged-/usr aliases as
                // symlinks and pins their real roots. Do not reopen /bin or
                // /lib as an operator bind (or mount over those aliases).
                if bplan.etc_paths.contains(&host)
                    || bplan.roots.iter().any(|root| match root {
                        jfs::RootSpec::RoBind(path) | jfs::RootSpec::Symlink { path, .. } => {
                            path == &host
                        }
                    })
                {
                    continue;
                }
                let destination = resolve_path_ref(reference, &plan.workspace)?;
                bplan
                    .extra_ro_binds
                    .push((host, PathBuf::from(destination)));
            }
        }
        for reference in &snapshot.filesystem.read_write {
            if let Ok(host) = host_path_of(reference, &plan.workspace, &scratch) {
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
        for reference in &snapshot.filesystem.deny_read {
            let destination = resolve_path_ref(reference, &plan.workspace)?;
            bplan.masked.push(PathBuf::from(destination));
        }

        let (scan, pins, pinned_fds, placeholders) = prepare_mounts(
            &mut bplan,
            &plan.attempt_dir,
            &name_refs,
            snapshot.filesystem.protected_coverage,
        )?;

        let filter = seccomp::tool_baseline().map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the syscall filter could not be built: {err}"),
            )
        })?;
        let filter_digest = filter.digest();

        let target: Vec<OsString> = plan
            .argv
            .iter()
            .map(|bytes| OsString::from_vec(bytes.clone()))
            .collect();
        bplan.inner = bwrap::inner_launch_command(RELEASE_FD, ERROR_FD, observe_on, &target);
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

        let mut fds = FdMap::with_target_limit(PINNED_FD_BASE + pinned_fds.len() as RawFd);
        let io = |err: std::io::Error| {
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
        fds.add(release_r, RELEASE_FD).map_err(io)?;
        fds.add(error_w, ERROR_FD).map_err(io)?;
        fds.add(status_w, STATUS_FD).map_err(io)?;
        for (copy, target) in pinned_fds {
            fds.add(copy, target).map_err(io)?;
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

        let mut command = Command::new(&exe);
        command.arg("__backend").args(&rendered.argv);
        // §9.1 mount-handoff verification: the workspace and every pinned
        // protected segment must still resolve to the objects that were
        // scanned, or the run refuses rather than bind a replacement.
        for pin in &pins {
            pin.verify().map_err(|err| {
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!("a protected path changed during preparation: {err}"),
                )
            })?;
        }
        // §8.3: stdio is inherited without capture; every other descriptor the
        fds.apply(&mut command);
        let mut child = command.spawn().map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!(
                    "the backend bootstrap ({}) could not be started: {err}",
                    exe.display()
                ),
            )
        })?;
        // In particular close our duplicate of ARGS_FD before streaming: if
        // the backend exits there must be no reader left to suppress EPIPE.
        drop(fds);
        // Root the cgroup namespace in this attempt's leaf. Moving only the
        // target after bubblewrap unshares exposes a /../../host-leaf path in
        // /proc/self/cgroup. The blocked bootstrap cannot fork or exec yet.
        if let Some(leaf) = &cgroup
            && let Err(err) = leaf.place(child.id() as i32)
        {
            let _ = child.kill();
            reap_until(&mut child, deadline);
            return Err(io(err));
        }
        let watcher = match super::watch::Watcher::start(&exe, child.id() as i32, deadline) {
            Ok(watcher) => watcher,
            Err(err) => {
                let _ = child.kill();
                reap_until(&mut child, deadline);
                return Err(io(err));
            }
        };
        if let Err(err) = write_all(start_w.as_raw_fd(), &[1]) {
            let _ = child.kill();
            reap_until(&mut child, deadline);
            return Err(io(err));
        }
        drop(start_w);
        // The payload write happens with bwrap already blocked on ARGS_FD, so
        // a payload larger than the pipe's capacity flows through instead of
        // deadlocking. A failure here means bwrap died reading: tear it down
        // rather than leak an orphan (§8.1 pre-exec failure refuses).
        if let (Some(args_w), Some(payload)) =
            (args_writer.as_ref(), rendered.args_payload.as_ref())
            && let Err(err) = write_until(args_w.as_raw_fd(), payload, deadline)
        {
            let _ = child.kill();
            reap_until(&mut child, clock::Deadline::after(TREE_BUDGET));
            return Err(io(err));
        }
        drop(args_writer);
        let bwrap_pid = libc::pid_t::try_from(child.id()).unwrap_or(-1);

        let workspace_path = plan.workspace.clone();
        let mut boundary = Boundary {
            audit: AuditWriter::new(
                &plan.attempt_id,
                sinks.trace.clone(),
                plan.workspace.as_os_str().as_bytes(),
                bwrap::SCRATCH_INSIDE_PATH.as_bytes(),
            ),
            snapshot,
            workspace: workspace_path,
            child: Some(child),
            bwrap_pid,
            bwrap_fd: identity::pidfd_open(bwrap_pid).ok(),
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
            placeholders,
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
            observe_on,
            ns_ids: identity::NsIds::default(),
            cgroup,
            cgroup_lost: false,
            cgroup_unavailable,
            watcher,
        };
        if let Some(reason) = boundary.cgroup_unavailable.clone() {
            for (key, ceiling) in [
                ("pids", &boundary.snapshot.limits.pids),
                ("mem", &boundary.snapshot.limits.mem),
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
        if observe_on {
            // §13.1: gap intervals count from supervisor start on the same
            // CLOCK_BOOTTIME base as every other monotonic_ns.
            match Tracer::attach(
                boundary.launcher.pid,
                TracerConfig {
                    epoch_boottime_ns: clock::mark_supervisor_start(),
                    ..TracerConfig::default()
                },
            ) {
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
                return Err(preparing(
                    ErrorCode::BackendUnavailable,
                    format!(
                        "bubblewrap exited during setup: {}",
                        self.diagnostic().trim()
                    ),
                ));
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
        // namespace init: every later signal goes through the descriptor, so
        // it cannot reach a process that merely inherited the number.
        self.init_fd = identity::pidfd_open(init_pid).ok();

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
                return Err(preparing(
                    ErrorCode::BackendUnavailable,
                    format!(
                        "bubblewrap exited before the launcher blocked: {}",
                        self.diagnostic().trim()
                    ),
                ));
            }
            nap();
        };

        // Wait until it is actually blocked in read(2), which is what the
        // observer's attach contract requires. `/proc/<pid>/syscall` names the
        // call it is in, so this is a read-back and not an assumption.
        loop {
            if current_syscall(launcher) == Some(libc::SYS_read) {
                break;
            }
            if deadline.expired() {
                return Err(prepare_timeout(
                    "the inside launcher did not block on its release pipe",
                ));
            }
            nap();
        }

        self.launcher = identity::ProcessIdentity::capture(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's identity could not be recorded: {err}"),
            )
        })?;
        // bubblewrap reports the namespace ids it created; `/proc` says which
        // namespaces the launcher is actually in. Recording the first without
        // checking the second would be taking the backend's word for the
        // boundary, so both are read and they must agree.
        self.launcher_fd = identity::pidfd_open(launcher).ok();
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
        let status_field = |key: &str| identity::status_field(launcher, key).unwrap_or_default();
        let no_new_privs = status_field("NoNewPrivs");
        let cap_eff = status_field("CapEff");
        let seccomp_mode = status_field("Seccomp");
        if no_new_privs != "1" {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("no_new_privs is {no_new_privs:?} inside the boundary, not 1"),
            ));
        }
        if !cap_eff.chars().all(|character| character == '0') {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("the boundary retains capabilities: CapEff {cap_eff}"),
            ));
        }
        if seccomp_mode != "2" {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("the syscall filter is not in force: Seccomp {seccomp_mode}"),
            ));
        }
        let nspid = super::tracer::nspid(launcher).unwrap_or_default();
        if nspid.len() < 2 {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher is not inside a pid namespace: NSpid {nspid:?}"),
            ));
        }

        self.backend_version = bwrap::bwrap_version(bwrap_path)
            .map(|version| version.raw)
            .unwrap_or_default();

        self.applied = self.read_applied(launcher, filter_digest, scan);
        Ok(())
    }

    /// The `applied` group, read back from the boundary that exists.
    fn read_applied(
        &self,
        launcher: libc::pid_t,
        filter_digest: &str,
        scan: &jfs::ProtectedScan,
    ) -> Applied {
        let mounts = read_mount_table(launcher);
        let environment_names = read_environment_names(launcher);
        let mut limits = Vec::new();
        for (key, ceiling) in [
            ("wall", self.snapshot.limits.wall.as_ref()),
            ("pids", self.snapshot.limits.pids.as_ref()),
            ("mem", self.snapshot.limits.mem.as_ref()),
            ("cpu", self.snapshot.limits.cpu.as_ref()),
        ] {
            let Some(ceiling) = ceiling else { continue };
            if key != "wall"
                && let Some(limit) = self
                    .cgroup
                    .as_ref()
                    .and_then(|leaf| leaf.limits().into_iter().find(|limit| limit.key == key))
            {
                limits.push(limit);
                continue;
            }
            let applied = key == "wall";
            limits.push(AppliedLimit {
                key: key.to_owned(),
                requested: ceiling.value.clone(),
                required: ceiling.required,
                applied,
                mechanism: applied.then(|| "boottime-deadline".to_owned()),
                scope: applied.then(|| "tree".to_owned()),
                // An applied ceiling that has not been hit says so; a null hit
                // means unknown or unapplied (§6.4). The supervisor flips this
                // to true when the deadline expires.
                hit: applied.then_some(false),
            });
        }
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
        Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "bubblewrap-binds".to_owned(),
                protected_coverage: scan_coverage(scan),
                mounts,
            }),
            network: AppliedNetwork {
                mode: "none".to_owned(),
                mechanism: Some("network-namespace".to_owned()),
                allowed_hosts: Vec::new(),
            },
            syscalls: Some(AppliedSyscalls {
                mechanism: "seccomp-bpf".to_owned(),
                digest: filter_digest.to_owned(),
            }),
            limits,
            environment_names,
            removed_environment_names: Vec::new(),
        }
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

    fn exited(&mut self) -> bool {
        if self.tracer.is_some() {
            // The tracer thread owns every waitpid in this process.
            return !std::path::Path::new(&format!("/proc/{}", self.bwrap_pid)).exists();
        }
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
            reap_until(&mut child, deadline);
        }
        while !self.watcher.ended() && !deadline.expired() {
            sleep_for(WAIT_STEP);
        }
        self.watcher.reap();
        self.remove_placeholders();
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
        if let Some(leaf) = &self.cgroup {
            let _ = leaf.kill();
        }
        for fd in [self.init_fd.as_ref(), self.bwrap_fd.as_ref()]
            .into_iter()
            .flatten()
        {
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
        let summary = tracer.finish_within_draining(budget, |event| match event {
            TracerEvent::Exec {
                pid, path, dirfd, ..
            } => self.audit.record_exec(pid, path.as_ref(), dirfd),
            TracerEvent::Syscall {
                pid,
                tid,
                op,
                syscall,
                args,
                ret,
                ..
            } => self.audit.record_syscall(pid, tid, op, syscall, &args, ret),
            TracerEvent::Exit { pid, status, .. } => self.audit.record_exit(pid, status),
            TracerEvent::Gap {
                reason,
                ops,
                from_ns,
                to_ns,
                count,
            } => self.audit.record_gap(reason, ops, from_ns, to_ns, count),
            _ => {}
        });
        if summary.loss.abandoned_tracees > 0
            && !self
                .audit
                .gaps()
                .iter()
                .any(|gap| gap.reason == super::tracer::GapReason::TraceesAbandoned.as_str())
        {
            self.audit.record_gap(
                super::tracer::GapReason::TraceesAbandoned,
                super::tracer::OpSet::ALL,
                0,
                0,
                Some(summary.loss.abandoned_tracees),
            );
        }
        if !summary.unreaped_children.is_empty()
            && !self
                .audit
                .gaps()
                .iter()
                .any(|gap| gap.reason == super::tracer::GapReason::UnreapedChildren.as_str())
        {
            self.audit.record_gap(
                super::tracer::GapReason::UnreapedChildren,
                super::tracer::OpSet::EMPTY,
                0,
                0,
                u64::try_from(summary.unreaped_children.len()).ok(),
            );
        }
        if summary.loss.lifecycle_dropped > 0
            || (summary.loss.total() > 0 && !self.audit.has_gaps())
        {
            self.audit.record_gap(
                super::tracer::GapReason::QueueFull,
                super::tracer::OpSet::ALL,
                0,
                crate::platform::elapsed_since_start_ns() as u64,
                None,
            );
        }
        self.tracer_summary = Some(summary);
    }

    /// Whether the observer's own account permits a claim of tree death.
    fn observer_verified_the_tree(&self) -> bool {
        observer_verdict(self.tracer_summary.as_ref())
    }

    fn remove_placeholders(&mut self) {
        if init_alive(self.init_pid) || !self.observer_verified_the_tree() || !self.cgroup_empty() {
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

    fn boundary_identity(&self) -> BoundaryIdentity {
        let mut details = Map::new();
        details.insert("watcher_pid".to_owned(), Value::from(self.watcher.pid()));
        details.insert(
            "execution_cgroup".to_owned(),
            match &self.cgroup {
                Some(leaf) => leaf.registration(self.bwrap_pid, self.init_pid),
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
        // both, by the digest each of them reports for itself.
        details.insert(
            "narrowing_filter_digest".to_owned(),
            if self.observe_on {
                Value::from(super::tracer::narrowing_filter_digest())
            } else {
                Value::Null
            },
        );
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

/// A 200 microsecond pause between polls of `/proc`, which offers no
/// descriptor to wait on. Every such loop is bounded by a deadline.
fn nap() {
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 200_000,
    };
    // SAFETY: `ts` is a live timespec and the second argument may be null.
    unsafe { libc::nanosleep(&raw const ts, std::ptr::null_mut()) };
}

fn current_syscall(pid: libc::pid_t) -> Option<libc::c_long> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/syscall")).ok()?;
    raw.split_whitespace().next()?.parse().ok()
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

fn create_private_dir(path: &Path) -> Result<(), JailError> {
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

/// §8.3: reject socket or directory stdio, and regular-file stdio that
/// resolves into protected supervisor state.
///
/// `state_root` is the whole runtime state directory, not just this attempt's
/// own: a redirect into a sibling attempt's receipts is the same disclosure.
/// A descriptor that cannot be inspected refuses rather than passing, because
/// "I could not tell what this is" is not a reason to hand it to the child.
fn validate_stdio(state_root: &Path) -> Result<(), JailError> {
    let state_root = state_root.canonicalize();
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
        if kind == libc::S_IFSOCK || kind == libc::S_IFDIR {
            return refuse(format!(
                "{name} is a socket or a directory, which a contained run refuses"
            ));
        }
        if kind == libc::S_IFREG {
            let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{fd}")) else {
                return refuse(format!(
                    "{name} is a regular file whose path cannot be read, so it cannot be \
                     shown to lie outside the state root"
                ));
            };
            let target = target.canonicalize().unwrap_or(target);
            if let Ok(state_root) = state_root.as_ref()
                && target.starts_with(state_root)
            {
                return refuse(format!("{name} resolves into the runtime state root"));
            }
        }
    }
    Ok(())
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

/// The mount table the launcher actually sees, from `/proc/<pid>/mountinfo`.
fn read_mount_table(pid: libc::pid_t) -> Vec<AppliedMount> {
    let Ok(raw) = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(point) = fields.get(4) else { continue };
        let Some(options) = fields.get(5) else {
            continue;
        };
        let mode = if options.split(',').any(|item| item == "ro") {
            "ro"
        } else {
            "rw"
        };
        let decoded = decode_mountinfo_path(point);
        let Ok(native) = NativeString::from_bytes(decoded) else {
            continue;
        };
        out.push(AppliedMount {
            path: native,
            mode: mode.to_owned(),
        });
        if out.len() >= 1024 {
            break;
        }
    }
    out
}

/// `mountinfo` escapes space, tab, newline and backslash as octal.
fn decode_mountinfo_path(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = &text[index + 1..index + 4];
            if let Ok(value) = u8::from_str_radix(digits, 8) {
                out.push(value);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The environment names the launcher actually has, read from `/proc`.
///
/// I09: names only, never values.
fn read_environment_names(pid: libc::pid_t) -> Vec<String> {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return Vec::new();
    };
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
    names
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
        RootToken::VendorState => {
            return Err(error(
                ErrorCode::CredentialUnavailable,
                ErrorStage::Preparing,
                Remediation::Unsupported,
                "vendor state is a launch-profile feature this slice does not implement".to_owned(),
            ));
        }
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
        RootToken::VendorState => Err(error(
            ErrorCode::CredentialUnavailable,
            ErrorStage::Preparing,
            Remediation::Unsupported,
            "vendor state is a launch-profile feature this slice does not implement".to_owned(),
        )),
    }
}

type MountPreparation = (
    jfs::ProtectedScan,
    Vec<jfs::PinnedPath>,
    Vec<(OwnedFd, RawFd)>,
    Vec<Placeholder>,
);

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
    let mut roots = plan.extra_rw_binds.clone();
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
        segments: Vec::new(),
        skipped_symlinks: Vec::new(),
        root_literals: Vec::new(),
        entries_seen: 0,
        max_depth_seen: 0,
    };
    let mut placeholders = Vec::new();
    let result = (|| {
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
            let scan = jfs::scan_pinned(
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
            for literal in scan.absent_root_literals() {
                let holders = attempt_dir.join("placeholders");
                create_private_dir(&holders)?;
                let holder = holders.join(format!("holder-{root_index}-{}", placeholders.len()));
                let placeholder = Placeholder::create(&holder, &source.join(&literal))
                    .map_err(|err| preparing(ErrorCode::BackendUnavailable, err.to_string()))?;
                let mut mount = placeholder.mount().clone();
                mount.destination = destination.join(&literal);
                plan.placeholders.push(mount);
                placeholders.push(placeholder);
            }
            aggregate.entries_seen += scan.entries_seen;
            aggregate.max_depth_seen = aggregate.max_depth_seen.max(scan.max_depth_seen);
            aggregate.segments.extend(scan.segments);
            aggregate.skipped_symlinks.extend(scan.skipped_symlinks);
        }
        // Bind ancestors before descendants, and never expose a second writable
        // alias of a protected source after applying its protection.
        let mut fds = Vec::new();
        for row in plan.mount_table() {
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
        Ok(fds)
    })();
    match result {
        Ok(fds) => Ok((aggregate, pins.into_values().collect(), fds, placeholders)),
        Err(err) => {
            for placeholder in &placeholders {
                let _ = placeholder.remove_if_unchanged();
            }
            Err(err)
        }
    }
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
        let mut boundary = self.boundary;
        if boundary.watcher.ended()
            || boundary
                .cgroup
                .as_ref()
                .is_some_and(|leaf| leaf.verify().is_err())
        {
            boundary.teardown();
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                "lifetime resources were lost before release",
            ));
        }
        let Some(release) = boundary.release.take() else {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                "the release pipe is already closed",
            ));
        };
        if let Err(err) = write_all(release.as_raw_fd(), &[1]) {
            boundary.teardown();
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("the release byte could not be written: {err}"),
            ));
        }
        // Closing it makes a second release impossible (X03).
        drop(release);
        let wall = boundary
            .snapshot
            .limits
            .wall
            .as_ref()
            .and_then(|ceiling| ceiling.value.parse::<u64>().ok())
            .map(|ms| clock::Deadline::after(Duration::from_millis(ms)));
        Ok(Box::new(LinuxRunning {
            boundary,
            wall,
            wall_reported: false,
            exec_confirmed: false,
            target_outcome: None,
            pending: Vec::new(),
            stop_requested: None,
            stop_at: None,
            hard_killed: false,
            hard_deadline: None,
            bwrap_status: None,
            finished: false,
            evidence_reported: false,
            sampled_at_ns: 0,
        }))
    }

    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        let mut boundary = self.boundary;
        boundary.teardown();
        // The target never ran, but the boundary existed, and whether its
        // teardown was observed to complete is still a measured fact.
        let verified = boundary.observer_verified_the_tree()
            && !init_alive(boundary.init_pid)
            && boundary.cgroup_empty();
        Ok(Teardown {
            tree: Some(if verified {
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
            }),
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
    pending: Vec<RunEvent>,
    stop_requested: Option<StopReason>,
    stop_at: Option<u64>,
    hard_killed: bool,
    hard_deadline: Option<clock::Deadline>,
    bwrap_status: Option<i32>,
    finished: bool,
    evidence_reported: bool,
    /// Boot-clock time of the last counter sample.
    sampled_at_ns: u64,
}

impl LinuxRunning {
    fn sample_limits(&mut self, force: bool) {
        let now = boottime_ns();
        let interval = u64::try_from(LIMIT_SAMPLE_INTERVAL.as_nanos()).unwrap_or(u64::MAX);
        if !force && now.saturating_sub(self.sampled_at_ns) < interval {
            return;
        }
        self.sampled_at_ns = now;
        let Some(leaf) = self.boundary.cgroup.as_mut() else {
            return;
        };
        match leaf.sample() {
            Ok(hits) => {
                for _ in 0..hits {
                    self.boundary.audit.record_limit_hit();
                }
                if leaf.oom_killed() {
                    self.hard_kill();
                }
            }
            Err(_) => {
                leaf.invalidate_hits();
                self.boundary.cgroup_lost = true;
                self.hard_kill();
            }
        }
    }
    /// Reads whatever the launcher wrote about a failed exec.
    fn pump_error(&mut self) {
        if self.boundary.error_eof {
            return;
        }
        let mut buffer = [0u8; 64];
        loop {
            // SAFETY: the buffer is live, the length matches and the
            // descriptor is owned and non-blocking.
            let n = unsafe {
                libc::read(
                    self.boundary.error.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if n > 0 {
                let read = usize::try_from(n).unwrap_or(0);
                self.boundary.error_bytes.extend_from_slice(&buffer[..read]);
                continue;
            }
            if n == 0 {
                self.boundary.error_eof = true;
            }
            return;
        }
    }

    /// Whether an observed exec transition is the launcher executing the
    /// program the operator named.
    ///
    /// A transition with no pathname is one whose entry the observer did not
    /// witness. A transition whose pathname is not one the launcher would have
    /// tried is some other image: the launcher resolves `PATH` itself and
    /// finishes with `execve`, so the set is small, known and derived from the
    /// same inputs on both sides. Neither confirms the target ran.
    fn image_is_the_target(&self, path: Option<&super::tracer::PathSnapshot>) -> bool {
        let Some(path) = path else { return false };
        if !path.complete {
            return false;
        }
        self.boundary
            .target_images
            .iter()
            .any(|candidate| candidate.as_slice() == path.bytes.as_slice())
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
        let launcher = self.boundary.launcher.pid;
        let mut events = Vec::new();
        if !block.is_zero()
            && let Ok(event) = tracer.events().recv_timeout(block)
        {
            events.push(event);
        }
        for _ in 0..256 {
            match tracer.events().try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        for event in events {
            self.handle_tracer_event(&event, launcher);
        }
    }

    fn handle_tracer_event(&mut self, event: &TracerEvent, launcher: libc::pid_t) {
        match event {
            TracerEvent::Exec {
                pid, path, dirfd, ..
            } => {
                self.boundary.audit.record_exec(*pid, path.as_ref(), *dirfd);
                // A transition with no pathname is one whose entry the
                // observer did not witness, which is what seizing a process
                // that is already inside its own `execve` produces. The
                // launcher is seized while blocked in `read(2)`, so its
                // target exec is witnessed and carries a path; requiring one
                // here means a transition we cannot attribute never becomes
                // exec confirmation.
                if *pid == launcher
                    && !self.exec_confirmed
                    && self.image_is_the_target(path.as_ref())
                {
                    self.exec_confirmed = true;
                    self.pending.push(RunEvent::ExecConfirmed);
                }
            }
            TracerEvent::Syscall {
                pid,
                tid,
                op,
                syscall,
                args,
                ret,
                ..
            } => {
                self.boundary
                    .audit
                    .record_syscall(*pid, *tid, *op, syscall, args, *ret);
            }
            TracerEvent::Exit { pid, status, .. } => {
                self.boundary.audit.record_exit(*pid, *status);
                if *pid == launcher && self.target_outcome.is_none() {
                    self.target_outcome = Some(outcome_from_status(*status));
                }
            }
            TracerEvent::UntracedChildExit { pid, status } => {
                if *pid == self.boundary.bwrap_pid {
                    self.bwrap_status = Some(*status);
                }
            }
            TracerEvent::Gap {
                reason,
                ops,
                from_ns,
                to_ns,
                count,
            } => {
                self.boundary
                    .audit
                    .record_gap(*reason, *ops, *from_ns, *to_ns, *count);
                // §11.4 counts a hole only where a result went missing. A gap
                // whose operation set is empty is bookkeeping — an argument
                // the observer could not read and the kernel rejected for the
                // same reason, say — and stopping a strict run for it would
                // let a tracee deny service to its own supervisor by passing
                // pointers that cannot work.
                if !ops.is_empty() && !self.evidence_reported {
                    self.evidence_reported = true;
                    self.pending.push(RunEvent::EvidenceLost {
                        reason: format!(
                            "the closed-set observer lost coverage: {}",
                            reason.as_str()
                        ),
                    });
                }
            }
            TracerEvent::Finished => self.finished = true,
            // §11.2 keeps fork out of the public audit set, and a thread is
            // not a process: every count this consumer keeps is per thread
            // group, which is what the observer's `pid` already is. Neither
            // event adds a fact the receipt states.
            TracerEvent::Attached { .. } | TracerEvent::Fork { .. } => {}
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

    /// Exec confirmation with no observer.
    ///
    /// The launcher sets the error pipe close-on-exec before it blocks, and
    /// measured on this host the only holder of that descriptor inside the
    /// sandbox is the launcher itself: neither bubblewrap nor its reaper keeps
    /// a copy. So EOF means the launcher closed it, which it does either by
    /// execing or by dying. Require a changed executable inode too: a zombie
    /// retains its birth identity, and even pidfd readiness can lag fd closure
    /// during exit. If the kernel image is unreadable or unchanged, exec stays
    /// unknown unless the observer independently witnessed it.
    fn check_exec_without_tracer(&mut self) {
        if self.exec_confirmed || self.boundary.tracer.is_some() {
            return;
        }
        if !self.boundary.error_bytes.is_empty() || !self.boundary.error_eof {
            return;
        }
        if self.boundary.launcher.is_live() && image_changed(self.boundary.launcher.pid) {
            self.exec_confirmed = true;
            self.pending.push(RunEvent::ExecConfirmed);
        }
    }

    fn check_wall(&mut self) {
        if self.wall_reported {
            return;
        }
        if self.wall.is_some_and(clock::Deadline::expired) {
            self.wall_reported = true;
            self.boundary.audit.record_limit_hit();
            self.pending.push(RunEvent::WallExpired);
        }
    }

    /// Escalates a cooperative stop to a hard one once the grace has passed.
    fn check_grace(&mut self) {
        if self.hard_killed || self.stop_requested.is_none() {
            return;
        }
        let Some(at) = self.stop_at else { return };
        if boottime_ns().saturating_sub(at)
            < u64::try_from(STOP_GRACE.as_nanos()).unwrap_or(u64::MAX)
        {
            return;
        }
        self.hard_kill();
    }

    fn hard_kill(&mut self) {
        if self.hard_killed {
            return;
        }
        self.hard_killed = true;
        self.hard_deadline = Some(clock::Deadline::after(TREE_BUDGET));
        self.boundary.kill_boundary();
    }

    /// The outcome once no more facts can arrive.
    fn terminal_event(&mut self) -> Option<RunEvent> {
        if let Some(outcome) = self.target_outcome.take() {
            if !self.exec_confirmed {
                self.exec_confirmed = true;
                self.pending.push(outcome);
                return Some(RunEvent::ExecConfirmed);
            }
            return Some(outcome);
        }
        // Without an observer the target's own status is not visible, so the
        // backend's report is all there is.
        let status = self.bwrap_status?;
        if !self.boundary.error_bytes.is_empty() {
            let errno = super::launch::decode_error_report(&self.boundary.error_bytes).map_or_else(
                || "unknown".to_owned(),
                |code| super::sys::errno_name(code).to_owned(),
            );
            return Some(RunEvent::ExecError { errno });
        }
        if !self.exec_confirmed {
            return Some(RunEvent::Unknown {
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
        {
            if !self.pending.is_empty() {
                return self.pending.remove(0);
            }
            self.pump_error();
            self.pump_tracer(Duration::ZERO);
            self.pump_status();
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
            if !self.pending.is_empty() {
                return self.pending.remove(0);
            }
            if !self.boundary.error_bytes.is_empty() && self.exec_confirmed {
                // Bytes after a confirmed exec cannot happen; keep them out of
                // the way rather than reporting a second event.
                self.boundary.error_bytes.clear();
            }
            if !self.boundary.error_bytes.is_empty() {
                let errno = super::launch::decode_error_report(&self.boundary.error_bytes)
                    .map_or_else(
                        || "unknown".to_owned(),
                        |code| super::sys::errno_name(code).to_owned(),
                    );
                self.boundary.error_bytes.clear();
                return RunEvent::ExecError { errno };
            }
            let done = self.bwrap_status.is_some()
                && (self.boundary.tracer.is_none()
                    || self.finished
                    || self.target_outcome.is_some());
            if done {
                // The counters must be in hand before the outcome is
                // classified: an OOM kill is attributed from them.
                self.sample_limits(true);
            }
            if done && let Some(event) = self.terminal_event() {
                return event;
            }
            if self.hard_deadline.is_some_and(clock::Deadline::expired) {
                return RunEvent::Unknown {
                    reason: "termination could not be observed within the tree budget".to_owned(),
                };
            }
            let step = step_for(deadline);
            if self.boundary.tracer.is_some() {
                self.pump_tracer(step);
            } else {
                sleep_for(step);
            }
            RunEvent::Poll
        }
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
        // goes to the target.
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
            let tracer_done = self.boundary.tracer.is_none() || self.finished;
            if tracer_done
                && self.bwrap_status.is_some()
                && !init_alive(self.boundary.init_pid)
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
                sleep_for(WAIT_STEP);
            }
        }

        // Whatever the loop concluded, the observer is stopped inside what is
        // left of the budget and its account decides. It is the only witness
        // to whether every tracee really ended.
        self.pump_tracer(Duration::ZERO);
        self.boundary.stop_observer(deadline.remaining());
        self.sample_limits(true);
        while !self.boundary.watcher.ended() && !deadline.expired() {
            sleep_for(WAIT_STEP);
        }
        self.boundary.watcher.reap();
        self.boundary.remove_placeholders();

        let mut tree = verdict(&TreeInputs {
            init_alive: init_alive(self.boundary.init_pid),
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
        self.boundary
            .cgroup
            .as_ref()
            .map_or_else(Vec::new, ExecutionCgroup::limits)
    }

    fn limit_cause(&self) -> Option<String> {
        self.boundary
            .cgroup
            .as_ref()
            .is_some_and(ExecutionCgroup::oom_killed)
            .then(|| "memory_oom".to_owned())
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
        if self.boundary.observe_on {
            let summary = self.boundary.tracer_summary.clone().unwrap_or_default();
            return Some(self.boundary.audit.summary(&summary, true));
        }
        // §11.4: observation off makes every audit class unsupported with a
        // null count. The wrapper's own `limits` class still exists.
        let mut summary = CoverageSummary::unobserved();
        summary.classes.insert(
            crate::observer::CoverageClass::Limits,
            self.boundary.audit.limits_class(),
        );
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

fn init_alive(init: libc::pid_t) -> bool {
    init > 0 && Path::new(&format!("/proc/{init}")).exists()
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

fn sleep_for(step: Duration) {
    if step.is_zero() {
        return;
    }
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: i64::try_from(step.as_nanos()).unwrap_or(1_000_000),
    };
    // SAFETY: `ts` is a live timespec and the second argument may be null.
    unsafe { libc::nanosleep(&raw const ts, std::ptr::null_mut()) };
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
        assert!(super::probes_for(super::REQ_NETWORK_PROXY).is_empty());
        assert_eq!(super::probes_for("limit:pids"), ["cgroup_pids"]);
        assert_eq!(super::probes_for("limit:mem"), ["cgroup_memory"]);
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
        for placeholder in placeholders {
            let _ = placeholder.remove_if_unchanged();
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
        for placeholder in placeholders {
            let _ = placeholder.remove_if_unchanged();
        }
    }

    #[test]
    fn mountinfo_paths_decode_their_octal_escapes() {
        assert_eq!(
            decode_mountinfo_path("/work/a\\040b"),
            b"/work/a b".to_vec()
        );
        assert_eq!(decode_mountinfo_path("/plain"), b"/plain".to_vec());
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
    fn a_tree_is_only_empty_when_every_fact_says_its_end_was_seen() {
        let seen = TreeInputs {
            init_alive: false,
            backend_reaped: true,
            tracer_finished: true,
            natural_end: true,
            abandoned_tracees: 0,
            unreaped_children: 0,
            observer_panicked: false,
        };
        let verified = verdict(&seen);
        assert_eq!(verified.tree_empty, Some(true));
        assert_eq!(verified.integrity, "verified");
        assert!(verified.verified_at.is_some());

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
    fn a_proxy_requirement_is_unsupported_in_this_slice() {
        let capability = capability_for(REQ_NETWORK_PROXY, &[], "2026-09-22T00:00:00Z");
        assert_eq!(capability.status, CapabilityStatus::Unsupported);
        assert_eq!(capability.measured_at, None);
    }
}
