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
use crate::platform::ReleaseFailure;
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
use super::observed::{self, Fact};
use super::platform::shared;
use super::probe::ProbeResult;
use super::tracer::{self, Tracer, TracerEvent, TracerSummary};
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
    // J3 integration begin: resolution refuses `--launch` with `none`
    // (launch_profile.rs); a launch hand-off reaching this boundary would be
    // dropped silently, so refuse it here too.
    if plan.launch.is_some() {
        return Err(JailError::new(
            ErrorCode::PolicyWidening,
            ErrorStage::Preparing,
            Remediation::Configuration,
            "the uncontained `none` boundary stages no vendor state or credentials".to_owned(),
        ));
    }
    // J3 integration end
    let boundary = Uncontained::create(plan, sinks, deadline)?;
    Ok(Box::new(Prepared { boundary }))
}

/// Everything the `none` boundary owns, from preparation through settlement.
struct Uncontained {
    snapshot: PolicySnapshot,
    attempt_id: String,
    trace: Option<SharedTrace>,
    observe_on: bool,
    /// The §11.4 bounds the observer runs with, decided once; `None` with
    /// observation off.
    observer_plan: Option<observed::ObserverPlan>,
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
    /// How a process's cgroup is read: [`cgroup::process_cgroup`]. A field
    /// so an in-process test can make the read fail with the leaf intact,
    /// which no live fixture can do deterministically.
    cgroup_of: fn(libc::pid_t) -> std::io::Result<String>,
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
        // supervisor rather than model that boundary. (Untestable on the
        // reference host: the conformance account has no privilege to gain.)
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
            observer_plan: observe_on.then(observed::ObserverPlan::from_env),
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
            cgroup_of: cgroup::process_cgroup,
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
        // Defence in depth, redundant on every host this build admits:
        // `place` above already read the pid back from the leaf's own member
        // list, and `ExecutionCgroup::create` refuses a supervisor whose
        // `/proc/self/cgroup` does not lie in the delegated subtree, so the
        // two spellings cannot disagree. It stays because every later
        // membership check trusts this spelling; no fixture can reach it.
        if !(self.cgroup_of)(pid).is_ok_and(|path| path == self.leaf_relative) {
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

        if let Some(plan) = self.observer_plan.as_ref() {
            // §13.1: gap intervals count from supervisor start on the same
            // CLOCK_BOOTTIME base as every other monotonic_ns. §11.4: the
            // bounds are the plan's, which the receipt records.
            let tracer = Tracer::attach(pid, plan.tracer_config(clock::mark_supervisor_start()))
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
        // §11.4: "Record actual values in the observer plan."
        details.insert(
            "observer_plan".to_owned(),
            self.observer_plan
                .as_ref()
                .map_or(Value::Null, observed::ObserverPlan::details),
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
        let fd = self.launcher_fd.as_raw_fd();
        let (cgroup_of, pid) = (self.cgroup_of, self.pid);
        let Some(read) = read_while_alive(|| !watch::readable(fd), || cgroup_of(pid)) else {
            return;
        };
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
        self.scan_walked(own, tracer::descendants(own));
    }

    /// [`Uncontained::scan_descendants`] over a given walk of `own`'s tree.
    fn scan_walked(&mut self, own: libc::pid_t, walked: Vec<libc::pid_t>) {
        let ours: BTreeSet<libc::pid_t> = walked.iter().copied().chain([own]).collect();
        for pid in walked {
            if pid == self.pid {
                continue;
            }
            let Ok(fd) = identity::pidfd_open(pid) else {
                continue;
            };
            let raw = fd.as_raw_fd();
            let cgroup_of = self.cgroup_of;
            let Some((parent, cgroup)) = read_while_alive(
                || !watch::readable(raw),
                || (tracer::ppid(pid), cgroup_of(pid).ok()),
            ) else {
                continue;
            };
            match classify(own, &ours, parent, cgroup.as_deref(), &self.leaf_relative) {
                Walked::Unattributed | Walked::Inside => {}
                Walked::Unreadable => self.lose(Subject::Descendant, Loss::VerificationFailed),
                Walked::EscapedDeeper => self.lose(Subject::Descendant, Loss::MembershipEscape),
                Walked::EscapedChild => {
                    self.lose(Subject::Descendant, Loss::MembershipEscape);
                    if !self.escaped.iter().any(|(known, _)| *known == pid) {
                        self.escaped.push((pid, fd));
                    }
                }
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
        // An unreaped zombie keeps its pid, so this read is of the target. A
        // read that fails is a failed verification, never a pass: without it
        // an escaped target that exited would settle as verified.
        match (self.cgroup_of)(self.pid) {
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
        self.reap_exited_children(tracer::children(own));
    }

    /// [`Uncontained::reap_orphans`] over a given list of this process's
    /// children.
    fn reap_exited_children(&mut self, children: Vec<libc::pid_t>) {
        for pid in children {
            if pid == self.pid || !peek_exited(pid) {
                continue;
            }
            match (self.cgroup_of)(pid) {
                Ok(path) if cgroup::within(&path, &self.leaf_relative) => {}
                Ok(_) => self.lose(Subject::Descendant, Loss::MembershipEscape),
                Err(_) => self.lose(Subject::Descendant, Loss::VerificationFailed),
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

    fn pump_tracer(&mut self, block: Duration) {
        let Some(tracer) = self.tracer.as_ref() else {
            return;
        };
        for event in observed::drain(tracer, block) {
            self.handle_tracer_event(&event);
        }
    }

    fn handle_tracer_event(&mut self, event: &TracerEvent) {
        let target = observed::Target {
            launcher: self.pid,
            images: &self.target_images,
        };
        match observed::record(&mut self.audit, &target, event) {
            Fact::TargetExec if !self.exec_confirmed => {
                self.exec_confirmed = true;
                self.pending.push(RunEvent::ExecConfirmed);
            }
            Fact::TargetExit(status) => {
                self.target_exit_seen = true;
                if self.target_outcome.is_none() {
                    self.target_outcome = Some(shared::outcome_from_status(status));
                }
            }
            // §11.4: only a hole where a result went missing stops a strict
            // run, exactly as for the contained profiles.
            Fact::CoverageLost(reason) if !self.evidence_reported => {
                self.evidence_reported = true;
                self.pending.push(RunEvent::EvidenceLost {
                    reason: format!("the closed-set observer lost coverage: {}", reason.as_str()),
                });
            }
            Fact::Finished => self.finished = true,
            // Every child of this subreaper is a tracee; nothing else is a
            // fact about this attempt's lifecycle.
            _ => {}
        }
    }

    /// Stops the observer within `budget` and keeps its account; a late
    /// target exit or the end still delivered counts as seen.
    fn stop_observer(&mut self, budget: Duration) {
        let Some(tracer) = self.tracer.take() else {
            return;
        };
        let target = observed::Target {
            launcher: self.pid,
            images: &self.target_images,
        };
        let exit_seen = &mut self.target_exit_seen;
        let finished = &mut self.finished;
        let summary = observed::stop(
            tracer,
            budget,
            &mut self.audit,
            &target,
            |fact| match fact {
                Fact::TargetExit(_) => *exit_seen = true,
                Fact::Finished => *finished = true,
                _ => {}
            },
        );
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

/// `read` of one process, kept only when `alive` holds both before and after
/// it. A process still alive after the read still holds its pid, so a
/// `/proc` read in between was of it, not of a process that reused the
/// number after an exit between the two checks.
fn read_while_alive<T>(alive: impl Fn() -> bool, read: impl FnOnce() -> T) -> Option<T> {
    if !alive() {
        return None;
    }
    let value = read();
    alive().then_some(value)
}

/// What one walked process is to the attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Walked {
    /// Its parent is not this supervisor or a walked descendant: a pid
    /// reused by an unrelated process, never attributed or signalled.
    Unattributed,
    /// In the leaf or a cgroup beneath it.
    Inside,
    /// Alive and ours, but its cgroup could not be read.
    Unreadable,
    /// Outside the leaf, and its parent is another descendant: recorded, not
    /// signalled; it becomes this supervisor's child when its parent dies.
    EscapedDeeper,
    /// Outside the leaf and this supervisor's own child (an orphan the
    /// subreaper adopted), so its pidfd provably names an attempt process.
    EscapedChild,
}

/// Classifies one walked process from its parent and cgroup, both read
/// while it was alive (see [`read_while_alive`]).
fn classify(
    own: libc::pid_t,
    ours: &BTreeSet<libc::pid_t>,
    parent: Option<libc::pid_t>,
    cgroup: Option<&str>,
    leaf: &str,
) -> Walked {
    let Some(parent) = parent.filter(|parent| ours.contains(parent)) else {
        return Walked::Unattributed;
    };
    match cgroup {
        None => Walked::Unreadable,
        Some(cgroup) if cgroup::within(cgroup, leaf) => Walked::Inside,
        Some(_) if parent == own => Walked::EscapedChild,
        Some(_) => Walked::EscapedDeeper,
    }
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
        self.release_reporting_teardown()
            .map_err(|failure| failure.error)
    }

    fn release_reporting_teardown(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, Box<ReleaseFailure>> {
        let mut boundary = self.boundary;
        // The blocked launcher must still be the only thing in the pinned
        // leaf. A same-UID process can have changed either since prepared;
        // the refusal then carries the teardown, `lost` included (§13.2).
        boundary.scan_target();
        let populated = boundary.scan_leaf();
        boundary.scan_descendants();
        if !boundary.losses.is_empty() || boundary.target_exited() || populated != Some(true) {
            return Err(boundary.fail_release(host_setup(
                ErrorCode::BackendUnavailable,
                "the registered boundary or the blocked launcher was lost before release",
            )));
        }
        let Some(release) = boundary.release.take() else {
            return Err(boundary.fail_release(host_setup(
                ErrorCode::BackendUnavailable,
                "the release pipe is already closed",
            )));
        };
        if let Err(err) = shared::write_all(release.as_raw_fd(), &[1]) {
            return Err(boundary.fail_release(host_setup(
                ErrorCode::BackendUnavailable,
                format!("the release byte could not be written: {err}"),
            )));
        }
        // X03 does not rest on this: the launcher reads exactly one byte and
        // this descriptor would close at the end of the function anyway.
        // Closing it here only makes the single release visible at a glance
        // (an equivalent mutant; nothing can test it).
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
        Ok(boundary.torn_down())
    }
}

impl Uncontained {
    /// Tears everything down and says what that established (§13.2 row 4):
    /// verified only on a reaped launcher, an empty identity-checked leaf and
    /// a clean observer; `lost` after any detected loss.
    fn torn_down(&mut self) -> Teardown {
        self.teardown();
        let populated = self.scan_leaf();
        let reaped = self.target_reaped();
        Teardown {
            tree: Some(verdict(&NoneTreeInputs {
                integrity_lost: !self.losses.is_empty(),
                natural_end: reaped,
                target_reaped: reaped,
                leaf_verified_empty: populated == Some(false),
                observer_clean: shared::observer_verdict(self.tracer_summary.as_ref()),
            })),
        }
    }

    /// A refused release, with the teardown it ran.
    fn fail_release(mut self, error: JailError) -> Box<ReleaseFailure> {
        let teardown = self.torn_down();
        Box::new(ReleaseFailure {
            error,
            teardown: Some(teardown),
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
        // record says it left. Defence in depth: `wait` checks the target on
        // every step and `wait_tree` scans everything on every iteration, and
        // an escaped descendant stays alive until it is killed. The only
        // window this closes is an observed target that migrates and dies of
        // this very signal within one wait step, which the observer reaps
        // before any zombie check; no fixture can hit it deterministically.
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
    fn a_read_is_kept_only_while_the_process_lives_on_both_sides() {
        use std::cell::Cell;
        let reads = Cell::new(0);
        assert_eq!(
            read_while_alive(|| true, || reads.set(reads.get() + 1)),
            Some(())
        );
        assert_eq!(
            read_while_alive(|| false, || reads.set(reads.get() + 1)),
            None
        );
        assert_eq!(reads.get(), 1, "a process dead before the read is not read");
        // An exit injected between the two checks: the pid may already name
        // another process, so what was read is not attributed.
        let checks = Cell::new(0);
        let exits_after_the_read = || {
            checks.set(checks.get() + 1);
            checks.get() == 1
        };
        assert_eq!(
            read_while_alive(exits_after_the_read, || "/elsewhere"),
            None
        );
        assert_eq!(checks.get(), 2);
    }

    #[test]
    fn only_processes_of_this_tree_are_attributed_and_only_children_signalled() {
        let leaf = "/u/ouro-att_x.leaf";
        let (own, child, grandchild, foreign) = (100, 200, 300, 999);
        let ours: BTreeSet<libc::pid_t> = [own, child, grandchild].into_iter().collect();
        let outside = Some("/u/elsewhere");
        // A reused pid whose parent is not ours: never a loss, never killed.
        assert_eq!(
            classify(own, &ours, Some(foreign), outside, leaf),
            Walked::Unattributed
        );
        assert_eq!(
            classify(own, &ours, None, outside, leaf),
            Walked::Unattributed
        );
        // Ours and inside, including a cgroup the child made beneath the leaf.
        assert_eq!(
            classify(own, &ours, Some(child), Some(leaf), leaf),
            Walked::Inside
        );
        assert_eq!(
            classify(
                own,
                &ours,
                Some(child),
                Some("/u/ouro-att_x.leaf/made"),
                leaf
            ),
            Walked::Inside
        );
        // Ours and outside: recorded; killable only as this process's child.
        assert_eq!(
            classify(own, &ours, Some(own), outside, leaf),
            Walked::EscapedChild
        );
        assert_eq!(
            classify(own, &ours, Some(child), outside, leaf),
            Walked::EscapedDeeper
        );
        // Ours and alive, cgroup unreadable: a failed verification.
        assert_eq!(
            classify(own, &ours, Some(child), None, leaf),
            Walked::Unreadable
        );
    }

    // -----------------------------------------------------------------------
    // Single integrity checks driven in process (A14, A15). The boundary
    // holds a real child that has already exited and a leaf on an ordinary
    // directory; it is never scanned for descendants or torn down, which
    // would walk this test process's children, and those belong to other
    // tests.
    // -----------------------------------------------------------------------

    const FAKE_LEAF: &str = "/fake/ouro-att_x.leaf";

    fn read_inside(_pid: libc::pid_t) -> std::io::Result<String> {
        Ok(FAKE_LEAF.to_owned())
    }

    fn read_fails(_pid: libc::pid_t) -> std::io::Result<String> {
        Err(std::io::Error::other(
            "injected: the cgroup file cannot be read",
        ))
    }

    fn fake_leaf(root: &std::path::Path) -> std::path::PathBuf {
        let path = root.join("leaf");
        std::fs::create_dir(&path).unwrap();
        for (name, value) in [
            ("cgroup.kill", ""),
            ("cgroup.procs", ""),
            ("cgroup.events", "populated 0\n"),
        ] {
            std::fs::write(path.join(name), value).unwrap();
        }
        path
    }

    fn exited_child_boundary(
        leaf: &std::path::Path,
        cgroup_of: fn(libc::pid_t) -> std::io::Result<String>,
    ) -> Uncontained {
        let child = Command::new("/bin/true").spawn().expect("/bin/true runs");
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let launcher_fd = identity::pidfd_open(pid).expect("a pidfd of the child");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !peek_exited(pid) {
            assert!(
                std::time::Instant::now() < deadline,
                "/bin/true never exited"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let (error, _writer) = exec::pipe().unwrap();
        let snapshot = crate::policy::resolve(&crate::policy::ResolveInputs {
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
        })
        .unwrap()
        .snapshot;
        Uncontained {
            snapshot,
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            trace: None,
            observe_on: false,
            observer_plan: None,
            pid,
            child: Some(child),
            launcher: identity::ProcessIdentity {
                pid,
                boot_id: String::new(),
                start_time_ticks: 0,
            },
            launcher_fd,
            target_images: Vec::new(),
            release: None,
            error,
            error_bytes: Vec::new(),
            error_eof: true,
            tracer: None,
            tracer_attached: false,
            tracer_summary: None,
            audit: AuditWriter::new(
                "att_00000000-0000-4000-8000-000000000001",
                None,
                b"/work",
                b"",
            ),
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
            leaf: ExecutionCgroup::open_for_test(leaf).unwrap(),
            leaf_relative: FAKE_LEAF.to_owned(),
            cgroup_of,
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
        }
    }

    fn final_integrity(boundary: &Uncontained, leaf_empty: bool) -> String {
        verdict(&NoneTreeInputs {
            integrity_lost: boundary.integrity_lost(),
            natural_end: true,
            target_reaped: boundary.target_reaped(),
            leaf_verified_empty: leaf_empty,
            observer_clean: true,
        })
        .integrity
    }

    /// A15: a target zombie whose cgroup cannot be read is a failed
    /// verification. Without the loss the run would settle as verified.
    #[test]
    fn an_unreadable_target_zombie_loses_integrity_instead_of_verifying() {
        let root = tempfile::tempdir().unwrap();
        let leaf = fake_leaf(root.path());

        let mut control = exited_child_boundary(&leaf, read_inside);
        control.collect_target();
        assert!(control.target_reaped());
        assert!(control.losses.is_empty());
        assert_eq!(control.scan_leaf(), Some(false));
        assert_eq!(final_integrity(&control, true), "verified");

        let mut failing = exited_child_boundary(&leaf, read_fails);
        failing.collect_target();
        assert!(failing.target_reaped(), "the status is still collected");
        assert_eq!(
            failing.losses,
            vec![(Subject::Target, Loss::VerificationFailed)]
        );
        assert!(failing.integrity_lost());
        assert_eq!(final_integrity(&failing, true), "lost");
    }

    fn read_outside(_pid: libc::pid_t) -> std::io::Result<String> {
        Ok("/fake/elsewhere".to_owned())
    }

    fn spawn_sleeper() -> std::process::Child {
        Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("/bin/sleep runs")
    }

    fn end(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// G5-G7 at the call site: a walked process is attributed only through
    /// a parent in the walk, recorded when outside, and kept for signalling
    /// only when it is this process's own child. The walk is given, so no
    /// other test's children are ever looked at.
    #[test]
    fn walked_processes_are_attributed_before_they_are_recorded_or_signalled() {
        let root = tempfile::tempdir().unwrap();
        let leaf = fake_leaf(root.path());
        // SAFETY: getpid takes no arguments and cannot fail.
        let own = unsafe { libc::getpid() };

        // Our child, outside the leaf: a loss, and signallable.
        let child = spawn_sleeper();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let mut boundary = exited_child_boundary(&leaf, read_outside);
        boundary.collect_target();
        boundary.losses.clear();
        boundary.scan_walked(own, vec![pid]);
        assert_eq!(
            boundary.losses,
            vec![(Subject::Descendant, Loss::MembershipEscape)]
        );
        assert_eq!(
            boundary
                .escaped
                .iter()
                .map(|(known, _)| *known)
                .collect::<Vec<_>>(),
            vec![pid]
        );

        // The same process in a walk that does not contain its parent is a
        // reused pid as far as this boundary can tell: nothing recorded.
        let mut foreign = exited_child_boundary(&leaf, read_outside);
        foreign.collect_target();
        foreign.losses.clear();
        foreign.scan_walked(1, vec![pid]);
        assert!(foreign.losses.is_empty());
        assert!(foreign.escaped.is_empty());

        // Alive, ours, and its cgroup unreadable: a failed verification.
        let mut unreadable = exited_child_boundary(&leaf, read_fails);
        unreadable.collect_target();
        unreadable.losses.clear();
        unreadable.scan_walked(own, vec![pid]);
        assert_eq!(
            unreadable.losses,
            vec![(Subject::Descendant, Loss::VerificationFailed)]
        );
        assert!(unreadable.escaped.is_empty());
        end(child);

        // A grandchild outside the leaf: recorded, never signalled.
        let shell = Command::new("/bin/sh")
            .args(["-c", "sleep 30 & wait"])
            .spawn()
            .expect("/bin/sh runs");
        let shell_pid = libc::pid_t::try_from(shell.id()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let grandchild = loop {
            if let Some(found) = tracer::children(shell_pid).first().copied() {
                break found;
            }
            assert!(std::time::Instant::now() < deadline, "no grandchild");
            std::thread::sleep(Duration::from_millis(2));
        };
        let mut deeper = exited_child_boundary(&leaf, read_outside);
        deeper.collect_target();
        deeper.losses.clear();
        deeper.scan_walked(own, vec![shell_pid, grandchild]);
        assert_eq!(
            deeper.losses,
            vec![(Subject::Descendant, Loss::MembershipEscape)]
        );
        assert_eq!(
            deeper
                .escaped
                .iter()
                .map(|(known, _)| *known)
                .collect::<Vec<_>>(),
            vec![shell_pid],
            "only this process's own child may be signalled"
        );
        // SAFETY: the grandchild is alive and this test's; its pid cannot be
        // reused while its parent, our child, has not reaped it.
        unsafe { libc::kill(grandchild, libc::SIGKILL) };
        end(shell);
    }

    /// An exited orphan whose zombie cannot be read is a failed verification,
    /// as for the target (A15); it is still reaped.
    #[test]
    fn an_unreadable_orphan_zombie_loses_integrity_and_is_reaped() {
        let root = tempfile::tempdir().unwrap();
        let leaf = fake_leaf(root.path());
        let mut boundary = exited_child_boundary(&leaf, read_fails);
        let orphan = Command::new("/bin/true").spawn().expect("/bin/true runs");
        let pid = libc::pid_t::try_from(orphan.id()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !peek_exited(pid) {
            assert!(
                std::time::Instant::now() < deadline,
                "/bin/true never exited"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        boundary.reap_exited_children(vec![pid]);
        assert_eq!(
            boundary.losses,
            vec![(Subject::Descendant, Loss::VerificationFailed)]
        );
        assert!(!peek_exited(pid), "the zombie was reaped");
        // The target's own collection is untouched by the orphan's.
        boundary.collect_target();
        assert!(boundary.target_reaped());
        drop(orphan);
    }

    /// A14: a population read that fails while the leaf's identity is intact
    /// is a failed verification, not an unknown that could pass later.
    #[test]
    fn an_unreadable_population_with_the_identity_intact_loses_integrity() {
        let root = tempfile::tempdir().unwrap();
        let leaf = fake_leaf(root.path());
        let mut boundary = exited_child_boundary(&leaf, read_inside);
        boundary.collect_target();
        assert_eq!(boundary.scan_leaf(), Some(false), "the control reads");
        assert!(boundary.losses.is_empty());

        std::fs::write(leaf.join("cgroup.events"), "populated maybe\n").unwrap();
        assert!(boundary.leaf.verify().is_ok(), "the identity is intact");
        assert_eq!(boundary.scan_leaf(), None);
        assert_eq!(
            boundary.losses,
            vec![(Subject::Boundary, Loss::VerificationFailed)]
        );
        assert_eq!(final_integrity(&boundary, false), "lost");

        // A replaced directory at the same path is the other loss.
        std::fs::rename(&leaf, root.path().join("moved")).unwrap();
        fake_leaf(root.path());
        assert_eq!(boundary.scan_leaf(), None);
        assert!(
            boundary
                .losses
                .contains(&(Subject::Boundary, Loss::IdentityReplaced))
        );
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
