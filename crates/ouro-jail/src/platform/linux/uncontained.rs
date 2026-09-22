//! The uncontained `none` profile (jail-v1 §§3.1, 6.1, 9.3, 12, 13.2).
//!
//! `none` is explicit (`--profile none` is the only way to select it), real,
//! observed by default and unprotected. It mounts nothing, installs no
//! containment filter and keeps the host network: the child sees what the
//! operator sees. What it keeps from the contained profiles is lifetime:
//!
//! * a supervisor-owned execution cgroup, required even with observation off,
//!   made by J2's [`ExecutionCgroup`] with the same identity pinning, limits,
//!   counters and `cgroup.kill`;
//! * the same trusted launcher (`ouro-jail __launch`), started directly on the
//!   host, placed in that leaf while it blocks and before release, with the
//!   observer attached to it exactly as in a contained run;
//! * the same wall deadline, cooperative grace and forced stop.
//!
//! There is no bubblewrap and no outside watcher. §8.2: "In `none`,
//! owner/supervisor loss preserves the accepted unknown lifetime limit; there
//! is no new watchdog"; north star §4.9: "The supervisor is the only killer."
//! The launcher carries the parent-death signal every spawn here arms; a
//! target can clear it, and its descendants never inherit it.
//!
//! What the receipt may say (§9.3, §13.2):
//!
//! * `child_protection: unprotected`, always; clean evidence never upgrades
//!   it (I08). `jail.backend` is `none`.
//! * `lifetime.verification_scope = registered_boundary`. `tree_empty = true`
//!   only when the identity-checked leaf was observed unpopulated, the target
//!   was reaped and no integrity loss was detected. It does not certify that
//!   every process ever descended from the target is gone.
//! * Target exit is the wait status (observation off) or the observer's final
//!   status (observation on), never population: an empty leaf with a live
//!   target is a live target.
//! * A detected membership escape (the target or a descendant outside the
//!   leaf), identity replacement (the path no longer names the pinned inode)
//!   or failed verification makes `lifetime.integrity = lost` for the rest of
//!   the attempt: no `tree_empty`, no `verified_at`, retained state, and one
//!   wrapper `lifetime` note per distinct loss. The target's own outcome is
//!   still reported from its independent source. Detection does not stop the
//!   attempt by itself: an uncontained child moving between its own user's
//!   cgroups is the same-UID interference `none` does not claim to prevent
//!   (§6.4); target exit, stop and the wall still end it, and the stop kills
//!   the leaf, the target and every escaped process that is provably ours.
//!
//! How escapes are seen. The supervisor becomes a child subreaper, so a
//! descendant whose parent exits is reparented to it, not to init, and stays
//! enumerable. The target's cgroup is read on every poll; every descendant's
//! at the counter cadence, at a stop request and throughout tree
//! verification; with observation off an exited child's zombie, which still
//! names the cgroup it died in, is checked before it is reaped. This is
//! detection, not a promise (§9.3): a descendant that migrates and exits
//! between two reads while observation is on, or a process another service
//! starts on the operator's behalf, is not seen.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::capability::{
    Capability, CapabilityScope, REASON_NOT_APPLIED_BY_NONE, REQ_FILESYSTEM_CONTAINMENT,
    REQ_NETWORK_NONE, REQ_NETWORK_PROXY, REQ_SYSCALL_FILTER, REQ_TREE_TERMINATION,
};
use crate::environment;
use crate::observer::{CoverageClass, CoverageSummary};
use crate::platform::{
    BoundaryIdentity, Deadline as PortableDeadline, PreparedExecution, PreparedPlan, RunEvent,
    RunningExecution, Sinks, StopReason, Teardown, TreeObservation,
};
use crate::policy::{EnvValue, PolicySnapshot, ProfileName, ProtectedCoverage};
use crate::records::{
    Applied, AppliedLimit, AppliedNetwork, ErrorCode, ErrorStage, Event, JailError, NativeLifetime,
    ObserveMode, Os, ProcessIdentity as RecordIdentity, ProcessRecord, Remediation,
};
use crate::supervisor::TREE_BUDGET;
use crate::trace::{Priority, SharedTrace};

use super::audit::AuditWriter;
use super::cgroup::{self, ExecutionCgroup};
use super::clock::{self, boottime_ns};
use super::exec::{self, FdMap, reap_until};
use super::identity;
use super::launch;
use super::platform::shared;
use super::probe::ProbeResult;
use super::tracer::{self, GapReason, OpSet, Tracer, TracerConfig, TracerEvent, TracerSummary};
use super::watch;

/// The descriptor the launcher blocks reading.
const RELEASE_FD: RawFd = 3;
/// The descriptor the launcher writes a failed exec's errno to.
const ERROR_FD: RawFd = 4;
/// The mechanism `none`'s tree termination names: the leaf's `cgroup.kill`,
/// followed by the population check (§9.3), never a pid namespace.
pub const TREE_MECHANISM: &str = "cgroup-kill";
/// The one verification scope a `none` receipt can carry (§13.2).
const SCOPE: &str = "registered_boundary";

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// Requirements `none` can never satisfy: it mounts, filters and isolates
/// nothing, so a policy that narrowed it into asking for any of these
/// refuses (§3.1, I02) instead of running with the restriction dropped.
fn never_applied(requirement: &str) -> bool {
    matches!(
        requirement,
        REQ_FILESYSTEM_CONTAINMENT | REQ_SYSCALL_FILTER | REQ_NETWORK_NONE | REQ_NETWORK_PROXY
    ) || requirement.starts_with("protected_coverage:")
}

/// The probes a `none` requirement is derived from, where they differ from a
/// contained profile's. Tree termination: `none` has no pid namespace, and
/// its tree kill is the delegated leaf's `cgroup.kill`, which the
/// `cgroup_delegated_leaf` probe exercises end to end (create, place, kill,
/// empty, reap, remove). A restriction `none` never applies needs no probe:
/// no host can make it available. `None` means "the contained mapping
/// applies".
#[must_use]
pub fn probes_for(profile: ProfileName, requirement: &str) -> Option<&'static [&'static str]> {
    if profile != ProfileName::None {
        return None;
    }
    if requirement == REQ_TREE_TERMINATION {
        return Some(&["cgroup_delegated_leaf"]);
    }
    never_applied(requirement).then_some(&[][..])
}

/// The capability a `none` requirement derives from the probe results, where
/// it differs from a contained profile's (see [`probes_for`]).
#[must_use]
pub fn capability_for(
    profile: ProfileName,
    requirement: &str,
    results: &[ProbeResult],
    measured_at: &str,
) -> Option<Capability> {
    if profile == ProfileName::None && never_applied(requirement) {
        return Some(Capability::unsupported(
            requirement,
            CapabilityScope::Tree,
            REASON_NOT_APPLIED_BY_NONE,
        ));
    }
    let probes = probes_for(profile, requirement)?;
    Some(shared::capability_from(
        requirement,
        probes,
        TREE_MECHANISM,
        CapabilityScope::Tree,
        results,
        measured_at,
    ))
}

/// The first restriction in a `none` snapshot this boundary would not apply,
/// as the key path that asks for it. The capability check refuses these
/// before preparation; this keeps the boundary itself from ever running
/// with one dropped.
fn unapplied_restriction(snapshot: &PolicySnapshot) -> Option<&'static str> {
    if !snapshot.filesystem.deny_read.is_empty() {
        Some("filesystem.deny_read")
    } else if !snapshot.filesystem.read_only.is_empty() {
        Some("filesystem.read_only")
    } else if snapshot.filesystem.protected_coverage != ProtectedCoverage::None {
        Some("filesystem.protected_coverage")
    } else if snapshot.network.mode != "host" {
        Some("network.mode")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tree verdict
// ---------------------------------------------------------------------------

/// What is known about a `none` tree when verification ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoneTreeInputs {
    /// A membership escape, identity replacement or failed verification was
    /// detected at any point of the attempt.
    pub integrity_lost: bool,
    /// The loop saw the boundary empty on its own, not at a spent budget.
    pub natural_end: bool,
    /// The target's final status was collected (it is not a live process and
    /// not an unreaped zombie).
    pub target_reaped: bool,
    /// The leaf still names the pinned inode and reads unpopulated.
    pub leaf_verified_empty: bool,
    /// The observer's account objects to nothing (or there was no observer).
    pub observer_clean: bool,
}

/// The tree observation those facts justify (§9.3, §13.2).
///
/// A detected loss wins over everything: `lost`, and neither a tree result
/// nor a time. Otherwise `tree_empty = true` needs every fact; anything short
/// of that is unknown (`pending`), never `false`.
#[must_use]
pub fn verdict(inputs: &NoneTreeInputs) -> TreeObservation {
    if inputs.integrity_lost {
        return TreeObservation {
            tree_empty: None,
            verified_at: None,
            verification_scope: SCOPE.to_owned(),
            integrity: "lost".to_owned(),
        };
    }
    if inputs.natural_end
        && inputs.target_reaped
        && inputs.leaf_verified_empty
        && inputs.observer_clean
    {
        return TreeObservation {
            tree_empty: Some(true),
            verified_at: Some(SystemTime::now()),
            verification_scope: SCOPE.to_owned(),
            integrity: "verified".to_owned(),
        };
    }
    TreeObservation {
        tree_empty: None,
        verified_at: None,
        verification_scope: SCOPE.to_owned(),
        integrity: "pending".to_owned(),
    }
}

/// What lost the boundary's integrity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Subject {
    /// The target process itself.
    Target,
    /// A descendant of the target.
    Descendant,
    /// The leaf.
    Boundary,
}

impl Subject {
    fn as_str(self) -> &'static str {
        match self {
            Subject::Target => "target",
            Subject::Descendant => "descendant",
            Subject::Boundary => "boundary",
        }
    }
}

/// How it was lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Loss {
    /// A process of the attempt was observed outside the leaf.
    MembershipEscape,
    /// The leaf's path no longer names the inode pinned at creation.
    IdentityReplaced,
    /// A read the verification needs failed.
    VerificationFailed,
}

impl Loss {
    fn as_str(self) -> &'static str {
        match self {
            Loss::MembershipEscape => "membership_escape",
            Loss::IdentityReplaced => "identity_replaced",
            Loss::VerificationFailed => "verification_failed",
        }
    }
}

// ---------------------------------------------------------------------------
// Preparation
// ---------------------------------------------------------------------------

fn refusal(code: ErrorCode, remediation: Remediation, message: impl Into<String>) -> JailError {
    JailError::new(code, ErrorStage::Preparing, remediation, message.into())
}

fn host_setup(code: ErrorCode, message: impl Into<String>) -> JailError {
    refusal(code, Remediation::HostSetup, message)
}

/// Creates the `none` boundary and its blocked launcher.
///
/// # Errors
/// A typed refusal (§6.4): `missing_capability`/`host_setup` when no usable
/// delegated cgroup exists or placement cannot be read back,
/// `observer_unavailable` when observation is on and cannot attach, and the
/// preparation errors of the launcher.
pub fn prepare(
    plan: PreparedPlan,
    sinks: Sinks,
    deadline: clock::Deadline,
) -> Result<Box<dyn PreparedExecution>, JailError> {
    let boundary = Uncontained::create(plan, sinks, deadline)?;
    Ok(Box::new(Prepared { boundary }))
}

/// Everything the `none` boundary owns, from preparation through settlement.
struct Uncontained {
    snapshot: PolicySnapshot,
    attempt_id: String,
    trace: Option<SharedTrace>,
    observe_on: bool,
    /// The launcher's pid: the target's once it execs.
    pid: libc::pid_t,
    /// The launcher as a child, for the wait status when no observer owns
    /// this process's waits.
    child: Option<Child>,
    launcher: identity::ProcessIdentity,
    /// Taken while it was this process's unreaped child, so it names it.
    launcher_fd: OwnedFd,
    /// The paths the launcher will try to `execve` (see `platform.rs`).
    target_images: Vec<Vec<u8>>,
    release: Option<OwnedFd>,
    error: OwnedFd,
    error_bytes: Vec<u8>,
    error_eof: bool,
    tracer: Option<Tracer>,
    /// Set once the observer attached: from then on it owns every `waitpid`.
    tracer_attached: bool,
    tracer_summary: Option<TracerSummary>,
    audit: AuditWriter,
    applied: Applied,
    leaf: ExecutionCgroup,
    /// The leaf as `/proc/<pid>/cgroup` names it.
    leaf_relative: String,
    /// Every distinct integrity loss detected, in order.
    losses: Vec<(Subject, Loss)>,
    /// Escaped processes that are this supervisor's own children, so their
    /// pidfds provably name attempt processes and may be signalled.
    escaped: Vec<(libc::pid_t, OwnedFd)>,
    wall: Option<clock::Deadline>,
    wall_reported: bool,
    exec_confirmed: bool,
    target_outcome: Option<RunEvent>,
    /// The observer reported the target's final status.
    target_exit_seen: bool,
    /// The target's raw wait status, when this process collected it.
    target_status: Option<i32>,
    pending: Vec<RunEvent>,
    stop_requested: Option<StopReason>,
    stop_at: Option<u64>,
    hard_killed: bool,
    hard_deadline: Option<clock::Deadline>,
    finished: bool,
    evidence_reported: bool,
    sampled_at_ns: u64,
}

impl Uncontained {
    #[allow(clippy::too_many_lines)]
    fn create(
        plan: PreparedPlan,
        sinks: Sinks,
        deadline: clock::Deadline,
    ) -> Result<Uncontained, JailError> {
        let snapshot = plan.request.snapshot.clone();
        if snapshot.profile != ProfileName::None {
            return Err(refusal(
                ErrorCode::InternalError,
                Remediation::InspectState,
                "the uncontained boundary was asked to run a contained profile",
            ));
        }
        // §5.2, as for every profile: v1 refuses a privileged or setuid
        // supervisor rather than model that boundary.
        // SAFETY: getuid and geteuid take no arguments and cannot fail.
        let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        if euid == 0 || ruid != euid {
            return Err(refusal(
                ErrorCode::UnsupportedPlatform,
                Remediation::HostSetup,
                format!(
                    "this slice refuses a privileged or setuid supervisor: real uid {ruid}, \
                     effective uid {euid} (jail-v1 §5.2)"
                ),
            ));
        }
        if let Some(key) = unapplied_restriction(&snapshot) {
            return Err(refusal(
                ErrorCode::MissingCapability,
                Remediation::Configuration,
                format!(
                    "the uncontained profile applies no filesystem or network restriction, \
                     and the policy asks for `{key}`"
                ),
            )
            .with_key_path(key));
        }
        let observe_on = snapshot.observation.mode == ObserveMode::On;
        let exe = std::env::current_exe().map_err(|err| {
            host_setup(
                ErrorCode::BackendUnavailable,
                format!("this binary's own path cannot be read: {err}"),
            )
        })?;

        // §12: the host environment minus every reserved name; the receipt
        // lists the removed names, never a value.
        let (mut env, removed) = if snapshot.environment.inherit_host {
            environment::strip_reserved(std::env::vars_os())
        } else {
            (Vec::new(), Vec::new())
        };
        for binding in &snapshot.environment.bindings {
            let name = OsString::from(&binding.name);
            if environment::is_reserved(&name) {
                return Err(refusal(
                    ErrorCode::InvalidConfig,
                    Remediation::Configuration,
                    format!(
                        "the environment binding {} uses a reserved name",
                        binding.name
                    ),
                ));
            }
            let EnvValue::Native(value) = &binding.value else {
                return Err(refusal(
                    ErrorCode::InvalidConfig,
                    Remediation::Unsupported,
                    format!(
                        "the uncontained profile binds no path-valued environment ({})",
                        binding.name
                    ),
                ));
            };
            env.retain(|(existing, _)| existing != &name);
            env.push((name, OsString::from_vec(value.as_bytes().to_vec())));
        }

        let argv: Vec<OsString> = plan
            .argv
            .iter()
            .map(|bytes| OsString::from_vec(bytes.clone()))
            .collect();
        let Some(program) = argv.first() else {
            return Err(refusal(
                ErrorCode::InvalidConfig,
                Remediation::Configuration,
                "a program to run is required",
            ));
        };
        let child_path = env
            .iter()
            .find(|(name, _)| name == "PATH")
            .map(|(_, value)| value.clone());
        let target_images =
            launch::exec_candidate_bytes(program, child_path.as_deref()).map_err(|err| {
                refusal(
                    ErrorCode::InvalidConfig,
                    Remediation::Configuration,
                    err.to_string(),
                )
            })?;

        // §9.3: the supervisor-owned execution cgroup is required, observation
        // on or off. No fallback to a process-group kill (north star §4.2).
        let leaf = ExecutionCgroup::create(&snapshot.limits).map_err(|err| {
            host_setup(
                ErrorCode::MissingCapability,
                format!(
                    "the uncontained profile requires a delegated execution cgroup, with \
                     observation on or off, and none could be configured: {err}"
                ),
            )
        })?;
        let Some(leaf_relative) = leaf.relative_path() else {
            return Err(host_setup(
                ErrorCode::MissingCapability,
                "the execution cgroup does not lie under the cgroup v2 root, so membership \
                 cannot be read back",
            ));
        };

        // Orphans of the target come to this process rather than to init, so
        // a descendant that outlives its parent stays enumerable.
        // SAFETY: PR_SET_CHILD_SUBREAPER takes scalars and dereferences nothing.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(host_setup(
                ErrorCode::BackendUnavailable,
                format!(
                    "the supervisor could not become a child subreaper, so an escaped \
                     descendant would be invisible: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }

        let io = |err: std::io::Error| {
            host_setup(
                ErrorCode::BackendUnavailable,
                format!("the launcher's channels could not be created: {err}"),
            )
        };
        let (release_r, release_w) = exec::pipe().map_err(io)?;
        let (error_r, error_w) = exec::pipe().map_err(io)?;
        shared::set_nonblocking(error_r.as_raw_fd()).map_err(io)?;
        let mut fds = FdMap::new();
        fds.add(release_r, RELEASE_FD).map_err(io)?;
        fds.add(error_w, ERROR_FD).map_err(io)?;

        let mut command = Command::new(&exe);
        command
            .arg(launch::SUBCOMMAND)
            .arg("--release-fd")
            .arg(RELEASE_FD.to_string())
            .arg("--error-fd")
            .arg(ERROR_FD.to_string());
        if observe_on {
            command.arg("--narrow");
        }
        command
            .arg("--")
            .args(&argv)
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .current_dir(&plan.workspace);
        // §8.3: every descriptor above stdio closes before exec, the channels
        // above are installed at fixed numbers, and the parent-death signal
        // is armed and rechecked.
        fds.apply(&mut command);
        // §8.3: the command runs in a new session.
        // SAFETY: runs between fork and exec and calls only setsid, which is
        // async-signal-safe; the error is built from errno without allocating.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|err| {
            host_setup(
                ErrorCode::BackendUnavailable,
                format!(
                    "the launcher ({}) could not be started: {err}",
                    exe.display()
                ),
            )
        })?;
        drop(fds);
        let pid = libc::pid_t::try_from(child.id()).unwrap_or(-1);
        // Opened while the launcher is this process's unreaped child, so the
        // descriptor names it and nothing that inherits the number later.
        let launcher_fd = match identity::pidfd_open(pid) {
            Ok(fd) => fd,
            Err(err) => {
                let _ = child.kill();
                reap_until(&mut child, clock::Deadline::after(TREE_BUDGET));
                return Err(io(err));
            }
        };

        let mut boundary = Uncontained {
            audit: AuditWriter::new(
                &plan.attempt_id,
                sinks.trace.clone(),
                plan.workspace.as_os_str().as_bytes(),
                // No scratch: a path is workspace-relative or a digest.
                b"",
            ),
            snapshot,
            attempt_id: plan.attempt_id,
            trace: sinks.trace,
            observe_on,
            pid,
            child: Some(child),
            launcher: identity::ProcessIdentity {
                pid,
                boot_id: String::new(),
                start_time_ticks: 0,
            },
            launcher_fd,
            target_images,
            release: Some(release_w),
            error: error_r,
            error_bytes: Vec::new(),
            error_eof: false,
            tracer: None,
            tracer_attached: false,
            tracer_summary: None,
            applied: Applied {
                filesystem: None,
                network: AppliedNetwork {
                    mode: "host".to_owned(),
                    mechanism: None,
                    allowed_hosts: Vec::new(),
                },
                syscalls: None,
                limits: Vec::new(),
                environment_names: Vec::new(),
                removed_environment_names: Vec::new(),
            },
            leaf,
            leaf_relative,
            losses: Vec::new(),
            escaped: Vec::new(),
            wall: None,
            wall_reported: false,
            exec_confirmed: false,
            target_outcome: None,
            target_exit_seen: false,
            target_status: None,
            pending: Vec::new(),
            stop_requested: None,
            stop_at: None,
            hard_killed: false,
            hard_deadline: None,
            finished: false,
            evidence_reported: false,
            sampled_at_ns: 0,
        };
        if let Err(err) = boundary.establish(deadline, removed) {
            boundary.teardown();
            return Err(err);
        }
        Ok(boundary)
    }

    /// Places the blocked launcher, reads everything back and attaches the
    /// observer. Any failure refuses; the caller tears down.
    fn establish(
        &mut self,
        deadline: clock::Deadline,
        removed: Vec<String>,
    ) -> Result<(), JailError> {
        let pid = self.pid;
        // §9.3: in the identity-pinned leaf before release, confirmed by the
        // leaf's own member list and by the process's own cgroup file, the
        // second being how every later membership check reads.
        self.leaf.place(pid).map_err(|err| {
            host_setup(
                ErrorCode::MissingCapability,
                format!("launcher placement in the execution cgroup failed: {err}"),
            )
        })?;
        if !cgroup::process_cgroup(pid).is_ok_and(|path| path == self.leaf_relative) {
            return Err(host_setup(
                ErrorCode::MissingCapability,
                "the launcher's own cgroup does not read back as the execution cgroup, so \
                 membership could not be verified",
            ));
        }

        // Blocked in read(2) on the release descriptor, which is what the
        // observer's attach contract requires and what makes the release the
        // only way forward.
        loop {
            if blocked_on_release(pid) {
                break;
            }
            if watch::readable(self.launcher_fd.as_raw_fd()) {
                return Err(host_setup(
                    ErrorCode::BackendUnavailable,
                    "the launcher exited before it blocked on its release pipe",
                ));
            }
            if deadline.expired() {
                return Err(JailError::new(
                    ErrorCode::PrepareTimeout,
                    ErrorStage::Preparing,
                    Remediation::Retry,
                    "the launcher did not block on its release pipe".to_owned(),
                ));
            }
            shared::nap();
        }

        // With observation on, the narrowing filter must be in force before
        // the seize: without it the observer would see nothing and say so
        // nowhere. One more filter than this process has is the read-back;
        // a filter inherited from the operator's own session is not ours.
        if self.observe_on {
            let filters = |target: libc::pid_t| {
                identity::status_field(target, "Seccomp_filters")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
            };
            // SAFETY: getpid takes no arguments and cannot fail.
            let own = filters(unsafe { libc::getpid() });
            let launcher = filters(pid);
            let no_new_privs = identity::status_field(pid, "NoNewPrivs").unwrap_or_default();
            if own.is_none() || launcher != own.map(|count| count + 1) || no_new_privs != "1" {
                return Err(host_setup(
                    ErrorCode::ObserverUnavailable,
                    format!(
                        "the observer's narrowing filter is not in force in the launcher \
                         (filters {launcher:?} against {own:?} here, NoNewPrivs {no_new_privs:?})"
                    ),
                ));
            }
        }

        self.launcher = identity::ProcessIdentity::capture(pid).map_err(|err| {
            host_setup(
                ErrorCode::BackendUnavailable,
                format!("the launcher's identity could not be recorded: {err}"),
            )
        })?;
        self.applied = self.read_applied(removed);
        self.leaf
            .verify_member(pid)
            .and_then(|()| self.leaf.arm())
            .map_err(|err| {
                host_setup(
                    ErrorCode::MissingCapability,
                    format!("the launcher's execution cgroup could not be read back: {err}"),
                )
            })?;

        if self.observe_on {
            // §13.1: gap intervals count from supervisor start on the same
            // CLOCK_BOOTTIME base as every other monotonic_ns.
            let tracer = Tracer::attach(
                pid,
                TracerConfig {
                    epoch_boottime_ns: clock::mark_supervisor_start(),
                    ..TracerConfig::default()
                },
            )
            .map_err(|err| {
                // §11.4: an observer that cannot attach refuses before exec,
                // whatever the evidence mode says.
                host_setup(
                    ErrorCode::ObserverUnavailable,
                    format!("the closed-set observer could not attach: {err}"),
                )
            })?;
            self.tracer = Some(tracer);
            self.tracer_attached = true;
        }
        Ok(())
    }

    /// The `applied` group: nothing but the leaf's limits, the wall and the
    /// environment, which is read back from the launcher.
    fn read_applied(&self, removed: Vec<String>) -> Applied {
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
                    .leaf
                    .limits()
                    .into_iter()
                    .find(|limit| limit.key == key)
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
                hit: applied.then_some(false),
            });
        }
        Applied {
            filesystem: None,
            network: AppliedNetwork {
                mode: "host".to_owned(),
                mechanism: None,
                allowed_hosts: Vec::new(),
            },
            syscalls: None,
            limits,
            environment_names: shared::read_environment_names(self.pid),
            removed_environment_names: removed,
        }
    }

    fn boundary_identity(&self) -> BoundaryIdentity {
        let (device, inode) = self.leaf.identity();
        let mut details = Map::new();
        details.insert(
            "execution_cgroup".to_owned(),
            serde_json::json!({
                "path": self.leaf.path(),
                "device": device,
                "inode": inode,
                // The launcher occupies the target slot; nothing else is charged.
                "charged_helpers": [],
                "scope": "target_descendants_and_listed_helpers",
            }),
        );
        details.insert("launcher_pid".to_owned(), Value::from(i64::from(self.pid)));
        // Observation, not containment: the observer's filter is in the
        // target, and the receipt names it by the digest it reports.
        details.insert(
            "narrowing_filter_digest".to_owned(),
            if self.observe_on {
                Value::from(tracer::narrowing_filter_digest())
            } else {
                Value::Null
            },
        );
        details.insert("child_subreaper".to_owned(), Value::from(true));
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
            boundary: "supervisor_cgroup".to_owned(),
            verification_scope: SCOPE.to_owned(),
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
            backend: Some("none".to_owned()),
            backend_version: None,
        }
    }

    // -----------------------------------------------------------------------
    // Integrity
    // -----------------------------------------------------------------------

    /// Records a detected loss once per kind, retains the leaf and writes the
    /// wrapper note. It never clears: integrity does not come back (§9.3).
    fn lose(&mut self, subject: Subject, loss: Loss) {
        if self.losses.contains(&(subject, loss)) {
            return;
        }
        self.losses.push((subject, loss));
        self.leaf.retain();
        if let Some(trace) = self.trace.as_ref() {
            let event = Event::lifetime_note(
                &self.attempt_id,
                0, // assigned by the shared wrapper stream writer
                SystemTime::now(),
                crate::platform::elapsed_since_start_ns(),
                subject.as_str(),
                loss.as_str(),
            );
            if let Ok(mut sink) = trace.lock() {
                // A frame that cannot be written is the sink's own recorded
                // loss; the receipt still says `lost`.
                let _ = sink.write_event(&event, Priority::Normal);
            }
        }
    }

    fn target_exited(&self) -> bool {
        watch::readable(self.launcher_fd.as_raw_fd())
    }

    /// Whether the target's final status has been collected.
    fn target_reaped(&self) -> bool {
        if self.tracer_attached {
            // The observer reaps what it traces. Its Exit event is the reap of
            // an exec'd target; a clean finish is the reap of everything.
            self.target_exit_seen
                || (self.tracer.is_none()
                    && self
                        .tracer_summary
                        .as_ref()
                        .is_some_and(|summary| shared::observer_verdict(Some(summary))))
        } else {
            self.target_status.is_some()
        }
    }

    /// The live target's membership, read from its own cgroup file and
    /// confirmed alive afterwards, so the read was of the target.
    fn scan_target(&mut self) {
        if self.target_exited() {
            return;
        }
        let read = cgroup::process_cgroup(self.pid);
        if self.target_exited() {
            return;
        }
        match read {
            Ok(path) if cgroup::within(&path, &self.leaf_relative) => {}
            Ok(_) => self.lose(Subject::Target, Loss::MembershipEscape),
            Err(_) => self.lose(Subject::Target, Loss::VerificationFailed),
        }
    }

    /// The leaf's identity and population: `Some(populated)` when both could
    /// be read, `None` after recording why not.
    fn scan_leaf(&mut self) -> Option<bool> {
        if self.leaf.verify().is_err() {
            self.lose(Subject::Boundary, Loss::IdentityReplaced);
            return None;
        }
        match self.leaf.populated() {
            Ok(populated) => Some(populated),
            Err(_) => {
                let loss = if self.leaf.verify().is_err() {
                    Loss::IdentityReplaced
                } else {
                    Loss::VerificationFailed
                };
                self.lose(Subject::Boundary, loss);
                None
            }
        }
    }

    /// Every live descendant of this supervisor, checked against the leaf.
    ///
    /// A process counts only when its parent is this supervisor or one of the
    /// walked descendants, and it is still alive (its pidfd not readable)
    /// after its cgroup was read, so neither a reused pid nor a process that
    /// died mid-read is attributed. An escaped process that is this
    /// supervisor's own child — an orphan reparented here — is kept with its
    /// pidfd for termination; a deeper one is recorded and becomes ours when
    /// its parent dies.
    fn scan_descendants(&mut self) {
        // SAFETY: getpid takes no arguments and cannot fail.
        let own = unsafe { libc::getpid() };
        let walked = tracer::descendants(own);
        let ours: BTreeSet<libc::pid_t> = walked.iter().copied().chain([own]).collect();
        for pid in walked {
            if pid == self.pid {
                continue;
            }
            let Ok(fd) = identity::pidfd_open(pid) else {
                continue;
            };
            if watch::readable(fd.as_raw_fd()) {
                continue;
            }
            let Some(parent) = tracer::ppid(pid) else {
                continue;
            };
            if !ours.contains(&parent) {
                continue;
            }
            let Ok(path) = cgroup::process_cgroup(pid) else {
                continue;
            };
            if watch::readable(fd.as_raw_fd()) || cgroup::within(&path, &self.leaf_relative) {
                continue;
            }
            self.lose(Subject::Descendant, Loss::MembershipEscape);
            if parent == own && !self.escaped.iter().any(|(known, _)| *known == pid) {
                self.escaped.push((pid, fd));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Waits (observation off only: otherwise the observer owns every waitpid)
    // -----------------------------------------------------------------------

    /// Collects the target's wait status, reading the cgroup its zombie
    /// died in first.
    fn collect_target(&mut self) {
        if self.tracer_attached || self.target_status.is_some() || !peek_exited(self.pid) {
            return;
        }
        // An unreaped zombie keeps its pid, so this read is of the target.
        match cgroup::process_cgroup(self.pid) {
            Ok(path) if cgroup::within(&path, &self.leaf_relative) => {}
            Ok(_) => self.lose(Subject::Target, Loss::MembershipEscape),
            Err(_) => self.lose(Subject::Target, Loss::VerificationFailed),
        }
        if let Some(child) = self.child.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            self.target_status = Some(status.into_raw());
        }
    }

    /// Reaps exited orphans that were reparented here, checking where each
    /// zombie died before it goes.
    fn reap_orphans(&mut self) {
        if self.tracer_attached {
            return;
        }
        // SAFETY: getpid takes no arguments and cannot fail.
        let own = unsafe { libc::getpid() };
        for pid in tracer::children(own) {
            if pid == self.pid || !peek_exited(pid) {
                continue;
            }
            if cgroup::process_cgroup(pid)
                .is_ok_and(|path| !cgroup::within(&path, &self.leaf_relative))
            {
                self.lose(Subject::Descendant, Loss::MembershipEscape);
            }
            let mut status = 0;
            // SAFETY: `pid` is this process's own exited child; reaping it
            // releases only that zombie, and no other waiter exists here.
            unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        }
    }

    // -----------------------------------------------------------------------
    // Channels and the observer
    // -----------------------------------------------------------------------

    /// Reads whatever the launcher wrote about a failed exec.
    fn pump_error(&mut self) {
        if self.error_eof {
            return;
        }
        let mut buffer = [0u8; 64];
        loop {
            // SAFETY: the buffer is live, the length matches and the
            // descriptor is owned and non-blocking.
            let n = unsafe {
                libc::read(
                    self.error.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if n > 0 {
                let read = usize::try_from(n).unwrap_or(0);
                self.error_bytes.extend_from_slice(&buffer[..read]);
                continue;
            }
            if n == 0 {
                self.error_eof = true;
            }
            return;
        }
    }

    fn image_is_the_target(&self, path: Option<&tracer::PathSnapshot>) -> bool {
        path.is_some_and(|path| {
            path.complete
                && self
                    .target_images
                    .iter()
                    .any(|candidate| candidate.as_slice() == path.bytes.as_slice())
        })
    }

    fn pump_tracer(&mut self, block: Duration) {
        let Some(tracer) = self.tracer.as_ref() else {
            return;
        };
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
            self.handle_tracer_event(event);
        }
    }

    fn handle_tracer_event(&mut self, event: TracerEvent) {
        match event {
            TracerEvent::Exec {
                pid, path, dirfd, ..
            } => {
                self.audit.record_exec(pid, path.as_ref(), dirfd);
                if pid == self.pid
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
            } => self.audit.record_syscall(pid, tid, op, syscall, &args, ret),
            TracerEvent::Exit { pid, status, .. } => {
                self.audit.record_exit(pid, status);
                if pid == self.pid {
                    self.target_exit_seen = true;
                    if self.target_outcome.is_none() {
                        self.target_outcome = Some(shared::outcome_from_status(status));
                    }
                }
            }
            TracerEvent::Gap {
                reason,
                ops,
                from_ns,
                to_ns,
                count,
            } => {
                self.audit.record_gap(reason, ops, from_ns, to_ns, count);
                // §11.4: only a hole where a result went missing stops a
                // strict run, exactly as for the contained profiles.
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
            // Every child of this subreaper is a tracee, and fork is internal
            // bookkeeping (§11.2).
            TracerEvent::UntracedChildExit { .. }
            | TracerEvent::Attached { .. }
            | TracerEvent::Fork { .. } => {}
        }
    }

    /// Stops the observer within `budget` and keeps its account, with the
    /// gap bookkeeping of the contained profiles' `stop_observer`.
    fn stop_observer(&mut self, budget: Duration) {
        let Some(tracer) = self.tracer.take() else {
            return;
        };
        let launcher = self.pid;
        let audit = &mut self.audit;
        let exit_seen = &mut self.target_exit_seen;
        let finished = &mut self.finished;
        let summary = tracer.finish_within_draining(budget, |event| match event {
            TracerEvent::Exec {
                pid, path, dirfd, ..
            } => audit.record_exec(pid, path.as_ref(), dirfd),
            TracerEvent::Syscall {
                pid,
                tid,
                op,
                syscall,
                args,
                ret,
                ..
            } => audit.record_syscall(pid, tid, op, syscall, &args, ret),
            TracerEvent::Exit { pid, status, .. } => {
                audit.record_exit(pid, status);
                if pid == launcher {
                    *exit_seen = true;
                }
            }
            TracerEvent::Gap {
                reason,
                ops,
                from_ns,
                to_ns,
                count,
            } => audit.record_gap(reason, ops, from_ns, to_ns, count),
            TracerEvent::Finished => *finished = true,
            _ => {}
        });
        let recorded = |audit: &AuditWriter, reason: GapReason| {
            audit.gaps().iter().any(|gap| gap.reason == reason.as_str())
        };
        if summary.loss.abandoned_tracees > 0 && !recorded(&self.audit, GapReason::TraceesAbandoned)
        {
            self.audit.record_gap(
                GapReason::TraceesAbandoned,
                OpSet::ALL,
                0,
                0,
                Some(summary.loss.abandoned_tracees),
            );
        }
        if !summary.unreaped_children.is_empty()
            && !recorded(&self.audit, GapReason::UnreapedChildren)
        {
            self.audit.record_gap(
                GapReason::UnreapedChildren,
                OpSet::EMPTY,
                0,
                0,
                u64::try_from(summary.unreaped_children.len()).ok(),
            );
        }
        if summary.loss.lifecycle_dropped > 0
            || (summary.loss.total() > 0 && !self.audit.has_gaps())
        {
            self.audit.record_gap(
                GapReason::QueueFull,
                OpSet::ALL,
                0,
                u64::try_from(crate::platform::elapsed_since_start_ns()).unwrap_or(u64::MAX),
                None,
            );
        }
        self.tracer_summary = Some(summary);
    }

    // -----------------------------------------------------------------------
    // Limits, deadlines and termination
    // -----------------------------------------------------------------------

    /// Counters, the leaf's identity and every descendant's membership, at
    /// the contained profiles' counter cadence (and always when `force`).
    fn sample(&mut self, force: bool) {
        let now = boottime_ns();
        let interval = u64::try_from(shared::LIMIT_SAMPLE_INTERVAL.as_nanos()).unwrap_or(u64::MAX);
        if !force && now.saturating_sub(self.sampled_at_ns) < interval {
            return;
        }
        self.sampled_at_ns = now;
        if self.scan_leaf().is_some() {
            match self.leaf.sample() {
                Ok(hits) => {
                    for _ in 0..hits {
                        self.audit.record_limit_hit();
                    }
                    if self.leaf.oom_killed() {
                        self.hard_kill();
                    }
                }
                Err(_) => {
                    self.leaf.invalidate_hits();
                    self.lose(Subject::Boundary, Loss::VerificationFailed);
                }
            }
        } else {
            self.leaf.invalidate_hits();
        }
        self.scan_descendants();
    }

    /// Exec confirmation with no observer while the target lives: the error
    /// pipe at EOF with no bytes and a changed image (see `platform.rs`).
    fn check_exec_without_tracer(&mut self) {
        if self.exec_confirmed || self.tracer_attached {
            return;
        }
        if !self.error_bytes.is_empty() || !self.error_eof {
            return;
        }
        if self.launcher.is_live() && shared::image_changed(self.pid) {
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
            self.audit.record_limit_hit();
            self.pending.push(RunEvent::WallExpired);
        }
    }

    fn check_grace(&mut self) {
        if self.hard_killed || self.stop_requested.is_none() {
            return;
        }
        let Some(at) = self.stop_at else { return };
        if boottime_ns().saturating_sub(at)
            < u64::try_from(shared::STOP_GRACE.as_nanos()).unwrap_or(u64::MAX)
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
        self.kill_all();
    }

    /// `cgroup.kill` on the identity-checked leaf (never on a replacement:
    /// the control is opened only after the path check), SIGKILL to the
    /// target through its pidfd wherever it is, and to every escaped process
    /// that is provably this attempt's.
    fn kill_all(&mut self) {
        self.scan_descendants();
        let _ = self.leaf.kill();
        let _ = identity::pidfd_send_signal(self.launcher_fd.as_raw_fd(), libc::SIGKILL);
        self.kill_escaped();
    }

    fn kill_escaped(&self) {
        for (_, fd) in &self.escaped {
            let _ = identity::pidfd_send_signal(fd.as_raw_fd(), libc::SIGKILL);
        }
    }

    /// Kills and reaps everything this boundary owns, within the tree budget.
    fn teardown(&mut self) {
        let deadline = clock::Deadline::after(TREE_BUDGET);
        self.kill_all();
        self.stop_observer(deadline.remaining());
        if !self.tracer_attached
            && let Some(child) = self.child.as_mut()
        {
            reap_until(child, deadline);
            if let Ok(Some(status)) = child.try_wait() {
                self.target_status = Some(status.into_raw());
            }
        }
        self.reap_orphans();
    }

    /// The outcome once no more facts about the target can arrive.
    ///
    /// Observation off, the exit status is this process's own wait status of
    /// the target, which is exact. Exec is confirmed without an observer by
    /// the launcher's protocol: after it was seen blocked on the release
    /// descriptor and released, its only ways to end before exec are an exec
    /// failure, which writes the errno first, or a signal. So an exit with no
    /// errno bytes is the target's own exit (§8.1 step 7: "EOF alone is
    /// insufficient if launcher death could also have closed that fd" — a
    /// signal death stays unknown).
    fn terminal_event(&mut self) -> Option<RunEvent> {
        if let Some(outcome) = self.target_outcome.take() {
            if !self.exec_confirmed {
                self.exec_confirmed = true;
                self.pending.push(outcome);
                return Some(RunEvent::ExecConfirmed);
            }
            return Some(outcome);
        }
        if self.tracer_attached {
            return self.finished.then(|| RunEvent::Unknown {
                reason: "the observer ended without the target's final status".to_owned(),
            });
        }
        let status = self.target_status?;
        self.pump_error();
        if !self.error_bytes.is_empty() {
            let errno = launch::decode_error_report(&self.error_bytes).map_or_else(
                || "unknown".to_owned(),
                |code| super::sys::errno_name(code).to_owned(),
            );
            return Some(RunEvent::ExecError { errno });
        }
        let outcome = shared::outcome_from_status(status);
        if !self.exec_confirmed {
            if libc::WIFEXITED(status) && self.error_eof {
                self.exec_confirmed = true;
                self.pending.push(outcome);
                return Some(RunEvent::ExecConfirmed);
            }
            return Some(RunEvent::Unknown {
                reason: "the target ended by a signal before its exec was independently \
                         confirmed"
                    .to_owned(),
            });
        }
        Some(outcome)
    }
}

/// Whether `pid`, a child of this process, has exited, without reaping it.
fn peek_exited(pid: libc::pid_t) -> bool {
    let Ok(id) = libc::id_t::try_from(pid) else {
        return false;
    };
    // SAFETY: siginfo_t is plain data and all-zero is a valid value for
    // waitid to overwrite.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a live siginfo_t. WNOWAIT leaves the child waitable
    // and WNOHANG never blocks.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            id,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // SAFETY: after a successful waitid, si_pid is initialized, and zero
    // when no child changed state.
    rc == 0 && unsafe { info.si_pid() } != 0
}

/// Whether `pid` is blocked in `read(2)` on the release descriptor, from
/// `/proc/<pid>/syscall` (the number, then the arguments in hex). Checking
/// the descriptor too means a transient read elsewhere during the launcher's
/// startup cannot pass for the gate.
fn blocked_on_release(pid: libc::pid_t) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/syscall"))
        .is_ok_and(|raw| parse_blocked_on(&raw, RELEASE_FD))
}

fn parse_blocked_on(raw: &str, fd: RawFd) -> bool {
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

// ---------------------------------------------------------------------------
// The platform traits
// ---------------------------------------------------------------------------

struct Prepared {
    boundary: Uncontained,
}

impl PreparedExecution for Prepared {
    fn boundary(&self) -> BoundaryIdentity {
        self.boundary.boundary_identity()
    }

    fn applied(&self) -> Option<Applied> {
        Some(self.boundary.applied.clone())
    }

    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError> {
        let mut boundary = self.boundary;
        // The blocked launcher must still be the only thing in the pinned
        // leaf. A same-UID process can have changed either since prepared.
        boundary.scan_target();
        let populated = boundary.scan_leaf();
        boundary.scan_descendants();
        if !boundary.losses.is_empty() || boundary.target_exited() || populated != Some(true) {
            boundary.teardown();
            return Err(host_setup(
                ErrorCode::BackendUnavailable,
                "the registered boundary or the blocked launcher was lost before release",
            ));
        }
        let Some(release) = boundary.release.take() else {
            return Err(host_setup(
                ErrorCode::BackendUnavailable,
                "the release pipe is already closed",
            ));
        };
        if let Err(err) = shared::write_all(release.as_raw_fd(), &[1]) {
            boundary.teardown();
            return Err(host_setup(
                ErrorCode::BackendUnavailable,
                format!("the release byte could not be written: {err}"),
            ));
        }
        // Closing it makes a second release impossible (X03).
        drop(release);
        boundary.wall = boundary
            .snapshot
            .limits
            .wall
            .as_ref()
            .and_then(|ceiling| ceiling.value.parse::<u64>().ok())
            .map(|ms| clock::Deadline::after(Duration::from_millis(ms)));
        Ok(Box::new(boundary))
    }

    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        let mut boundary = self.boundary;
        boundary.teardown();
        let populated = boundary.scan_leaf();
        let reaped = boundary.target_reaped();
        Ok(Teardown {
            tree: Some(verdict(&NoneTreeInputs {
                integrity_lost: !boundary.losses.is_empty(),
                natural_end: reaped,
                target_reaped: reaped,
                leaf_verified_empty: populated == Some(false),
                observer_clean: shared::observer_verdict(boundary.tracer_summary.as_ref()),
            })),
        })
    }
}

impl RunningExecution for Uncontained {
    fn final_limits(&self) -> Vec<AppliedLimit> {
        self.leaf.limits()
    }

    fn limit_cause(&self) -> Option<String> {
        self.leaf.oom_killed().then(|| "memory_oom".to_owned())
    }

    fn integrity_lost(&self) -> bool {
        !self.losses.is_empty()
    }

    fn wait(&mut self, deadline: PortableDeadline) -> RunEvent {
        if !self.pending.is_empty() {
            return self.pending.remove(0);
        }
        self.pump_error();
        self.pump_tracer(Duration::ZERO);
        self.collect_target();
        self.reap_orphans();
        self.sample(false);
        self.scan_target();
        self.check_exec_without_tracer();
        self.check_wall();
        self.check_grace();
        if !self.pending.is_empty() {
            return self.pending.remove(0);
        }
        if !self.error_bytes.is_empty() && self.exec_confirmed {
            // Bytes after a confirmed exec cannot happen; keep them out of
            // the way rather than reporting a second event.
            self.error_bytes.clear();
        }
        if !self.error_bytes.is_empty() {
            let errno = launch::decode_error_report(&self.error_bytes).map_or_else(
                || "unknown".to_owned(),
                |code| super::sys::errno_name(code).to_owned(),
            );
            self.error_bytes.clear();
            return RunEvent::ExecError { errno };
        }
        let done = if self.tracer_attached {
            self.target_outcome.is_some() || self.finished
        } else {
            self.target_status.is_some()
        };
        if done {
            // The counters must be in hand before the outcome is classified:
            // an OOM kill is attributed from them.
            self.sample(true);
            if let Some(event) = self.terminal_event() {
                return event;
            }
        }
        if self.hard_deadline.is_some_and(clock::Deadline::expired) {
            return RunEvent::Unknown {
                reason: "termination could not be observed within the tree budget".to_owned(),
            };
        }
        let step = shared::step_for(deadline);
        if self.tracer.is_some() {
            self.pump_tracer(step);
        } else {
            shared::sleep_for(step);
        }
        RunEvent::Poll
    }

    fn request_stop(&mut self, reason: StopReason) {
        if self.stop_requested.is_some() {
            return;
        }
        self.stop_requested = Some(reason);
        self.stop_at = Some(boottime_ns());
        // Where everything is, read before anything is signalled: a target
        // that left the leaf is still stopped through its pidfd, and the
        // record says it left.
        self.scan_target();
        let _ = self.scan_leaf();
        self.scan_descendants();
        let _ = identity::pidfd_send_signal(self.launcher_fd.as_raw_fd(), libc::SIGTERM);
    }

    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        let deadline = self
            .hard_deadline
            .unwrap_or_else(|| clock::Deadline::after(budget));
        let settle = clock::Deadline::after(shared::SETTLE_GRACE.min(budget));
        let mut natural = false;
        loop {
            self.pump_error();
            self.pump_tracer(Duration::ZERO);
            self.collect_target();
            self.reap_orphans();
            self.scan_target();
            let populated = self.scan_leaf();
            self.scan_descendants();
            if self.hard_killed {
                // Orphans reparented here by the kill are ours to end too.
                self.kill_escaped();
            }
            let tracer_done = self.tracer.is_none() || self.finished;
            let escaped_alive = self
                .escaped
                .iter()
                .any(|(_, fd)| !watch::readable(fd.as_raw_fd()));
            // An unreadable leaf after a recorded loss has nothing more to
            // say; a readable one must be seen empty.
            let leaf_done =
                populated == Some(false) || (populated.is_none() && !self.losses.is_empty());
            if tracer_done && self.target_reaped() && leaf_done && !escaped_alive {
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
            if self.tracer.is_some() {
                self.pump_tracer(shared::WAIT_STEP);
            } else {
                shared::sleep_for(shared::WAIT_STEP);
            }
        }
        self.pump_tracer(Duration::ZERO);
        self.stop_observer(deadline.remaining());
        self.sample(true);
        let populated = self.scan_leaf();
        verdict(&NoneTreeInputs {
            integrity_lost: !self.losses.is_empty(),
            natural_end: natural,
            target_reaped: self.target_reaped(),
            leaf_verified_empty: populated == Some(false),
            observer_clean: shared::observer_verdict(self.tracer_summary.as_ref()),
        })
    }

    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        // `wait_tree` already stopped the observer inside its budget; this
        // only covers a caller that skipped it.
        self.stop_observer(TREE_BUDGET);
        if self.observe_on {
            let summary = self.tracer_summary.clone().unwrap_or_default();
            return Some(self.audit.summary(&summary, true));
        }
        // §11.4: observation off makes every audit class unsupported with a
        // null count; the wrapper's own `limits` class still exists.
        let mut summary = CoverageSummary::unobserved();
        summary
            .classes
            .insert(CoverageClass::Limits, self.audit.limits_class());
        Some(summary)
    }
}

impl Drop for Uncontained {
    fn drop(&mut self) {
        if self.tracer.is_some() || !self.target_reaped() {
            self.teardown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_keeps_the_contained_probes_for_what_it_shares() {
        assert_eq!(
            probes_for(ProfileName::None, REQ_TREE_TERMINATION),
            Some(&["cgroup_delegated_leaf"][..])
        );
        for profile in [ProfileName::Tool, ProfileName::Build, ProfileName::Agent] {
            assert_eq!(probes_for(profile, REQ_TREE_TERMINATION), None);
        }
        for requirement in [
            crate::capability::REQ_EXECUTION_CGROUP,
            crate::capability::REQ_CLOSED_SET_OBSERVATION,
            "limit:wall",
            "limit:pids",
        ] {
            assert_eq!(probes_for(ProfileName::None, requirement), None);
        }
    }

    #[test]
    fn restrictions_none_cannot_apply_are_never_available() {
        for requirement in [
            REQ_FILESYSTEM_CONTAINMENT,
            REQ_SYSCALL_FILTER,
            REQ_NETWORK_NONE,
            REQ_NETWORK_PROXY,
            "protected_coverage:existing_and_root",
        ] {
            assert_eq!(
                probes_for(ProfileName::None, requirement),
                Some(&[][..]),
                "{requirement}: no host probe can make it available"
            );
            let capability =
                capability_for(ProfileName::None, requirement, &[], "2026-09-22T00:00:00Z")
                    .unwrap();
            assert!(!capability.satisfies(), "{requirement}");
            assert_eq!(
                capability.reason_code.as_deref(),
                Some(REASON_NOT_APPLIED_BY_NONE)
            );
            assert_eq!(probes_for(ProfileName::Tool, requirement), None);
            assert!(
                capability_for(ProfileName::Tool, requirement, &[], "2026-09-22T00:00:00Z")
                    .is_none()
            );
        }
    }

    #[test]
    fn the_boundary_names_the_restriction_it_would_not_apply() {
        let inputs = crate::policy::ResolveInputs {
            platform: Os::Linux,
            base_profile: ProfileName::None,
            policy_name: "none".to_owned(),
            baseline: crate::profiles::baseline(ProfileName::None, Os::Linux, &|_| None),
            workspace: b"/work".to_vec(),
            scratch: crate::policy::ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        let bare = crate::policy::resolve(&inputs).unwrap().snapshot;
        assert_eq!(unapplied_restriction(&bare), None);
        let reference = crate::policy::PathRef {
            root: crate::policy::RootToken::Workspace,
            path: crate::records::NativeString::Text("x".to_owned()),
        };
        let mut denied = bare.clone();
        denied.filesystem.deny_read.push(reference.clone());
        assert_eq!(unapplied_restriction(&denied), Some("filesystem.deny_read"));
        let mut read_only = bare.clone();
        read_only.filesystem.read_only.push(reference);
        assert_eq!(
            unapplied_restriction(&read_only),
            Some("filesystem.read_only")
        );
        let mut covered = bare.clone();
        covered.filesystem.protected_coverage = ProtectedCoverage::ExistingAndRoot;
        assert_eq!(
            unapplied_restriction(&covered),
            Some("filesystem.protected_coverage")
        );
        let mut isolated = bare;
        isolated.network.mode = "none".to_owned();
        assert_eq!(unapplied_restriction(&isolated), Some("network.mode"));
    }

    #[test]
    fn none_tree_termination_is_the_leaf_kill_and_needs_its_probe() {
        assert!(
            capability_for(
                ProfileName::Tool,
                REQ_TREE_TERMINATION,
                &[],
                "2026-09-22T00:00:00Z"
            )
            .is_none()
        );
        let skipped = capability_for(
            ProfileName::None,
            REQ_TREE_TERMINATION,
            &[],
            "2026-09-22T00:00:00Z",
        )
        .unwrap();
        assert!(!skipped.satisfies(), "an unrun probe cannot satisfy it");
        assert_eq!(skipped.mechanism.as_deref(), Some(TREE_MECHANISM));
    }

    fn clean() -> NoneTreeInputs {
        NoneTreeInputs {
            integrity_lost: false,
            natural_end: true,
            target_reaped: true,
            leaf_verified_empty: true,
            observer_clean: true,
        }
    }

    #[test]
    fn a_clean_none_tree_is_empty_only_in_the_registered_scope() {
        let observed = verdict(&clean());
        assert_eq!(observed.tree_empty, Some(true));
        assert!(observed.verified_at.is_some());
        assert_eq!(observed.integrity, "verified");
        assert_eq!(observed.verification_scope, "registered_boundary");
    }

    #[test]
    fn a_detected_loss_wins_over_every_other_fact() {
        let observed = verdict(&NoneTreeInputs {
            integrity_lost: true,
            ..clean()
        });
        assert_eq!(observed.tree_empty, None);
        assert_eq!(observed.verified_at, None);
        assert_eq!(observed.integrity, "lost");
        assert_eq!(observed.verification_scope, "registered_boundary");
    }

    #[test]
    fn any_missing_fact_is_unknown_never_false() {
        for (why, inputs) in [
            (
                "the budget ran out",
                NoneTreeInputs {
                    natural_end: false,
                    ..clean()
                },
            ),
            (
                "the target was not reaped",
                NoneTreeInputs {
                    target_reaped: false,
                    ..clean()
                },
            ),
            (
                "the leaf was not seen empty",
                NoneTreeInputs {
                    leaf_verified_empty: false,
                    ..clean()
                },
            ),
            (
                "the observer objected",
                NoneTreeInputs {
                    observer_clean: false,
                    ..clean()
                },
            ),
        ] {
            let observed = verdict(&inputs);
            assert_eq!(observed.tree_empty, None, "{why}");
            assert_eq!(observed.verified_at, None, "{why}");
            assert_eq!(observed.integrity, "pending", "{why}");
        }
    }

    #[test]
    fn only_a_read_on_the_release_descriptor_is_the_gate() {
        let read = libc::SYS_read;
        assert!(parse_blocked_on(
            &format!("{read} 0x3 0x7ffd 0x1 0x0 0x0 0x0 0x7ffd 0x7f"),
            3
        ));
        assert!(!parse_blocked_on(&format!("{read} 0x5 0x7ffd 0x1 0x0"), 3));
        assert!(!parse_blocked_on("running", 3));
        assert!(!parse_blocked_on(&format!("{} 0x3", libc::SYS_write), 3));
        assert!(!parse_blocked_on("", 3));
    }

    #[test]
    fn loss_names_are_the_documented_reason_codes() {
        assert_eq!(Loss::MembershipEscape.as_str(), "membership_escape");
        assert_eq!(Loss::IdentityReplaced.as_str(), "identity_replaced");
        assert_eq!(Loss::VerificationFailed.as_str(), "verification_failed");
        assert_eq!(Subject::Target.as_str(), "target");
        assert_eq!(Subject::Descendant.as_str(), "descendant");
        assert_eq!(Subject::Boundary.as_str(), "boundary");
    }
}
