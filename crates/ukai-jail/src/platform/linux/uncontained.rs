//! The uncontained `none` profile (jail-v1 §§3.1, 6.1, 9.3, 12, 13.2).
//!
//! `none` is explicit (`--profile none` is the only way to select it), real,
//! observed by default and unprotected. It mounts nothing, installs no
//! containment filter and keeps the host network: the child sees what the
//! operator sees. What it keeps from the contained profiles is lifetime:
//!
//! * a supervisor-owned execution cgroup, required even with observation off,
//!   made by the same [`ExecutionCgroup`] with its identity pinning, limits,
//!   counters and `cgroup.kill`;
//! * the same trusted launcher (`ukai-jail __launch`), started directly on the
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
//!
//! What this supervisor already had below it before it started the launcher is
//! not the attempt: a child it was exec'd beside — a shell's process
//! substitution reading `--trace-fd`, a background job — and that child's
//! descendants are recorded by birth identity then, and never walked, reaped,
//! recorded as an escape or signalled. One such process born after that
//! snapshot and orphaned here is indistinguishable from an escaped attempt
//! process and is treated as one (a recorded limit).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::Path;
use std::process::{Child, Command};
use std::time::SystemTime;

use serde_json::{Map, Value};

use crate::capability::{Capability, CapabilityScope, REASON_NOT_APPLIED_BY_NONE, Requirement};
use crate::environment;
use crate::lifecycle::{BoundaryKind, VerificationScope};
use crate::platform::{
    BoundaryIdentity, LimitCause, PreparedExecution, PreparedPlan, RunEvent, Sinks, TreeObservation,
};
use crate::policy::{EnvValue, LimitKey, PolicySnapshot, ProfileName, ProtectedCoverage};
use crate::records::{
    Applied, AppliedLimit, AppliedNetwork, ErrorCode, ErrorStage, Event, JailError, NativeLifetime,
    ObserveMode, Os, ProcessIdentity as RecordIdentity, ProcessRecord, Remediation,
};
use crate::supervisor::TREE_BUDGET;
use crate::trace::{Priority, SharedTrace};

use super::audit::AuditWriter;
use super::cgroup::{self, ExecutionCgroup};
use super::clock;
use super::exec::{self, FdMap, reap_until};
use super::identity;
use super::launch;
use super::observed;
use super::probe::ProbeResult;
use super::requirements::capability_from;
use super::running::{
    Counters, ErrorPipe, Launched, Run, RunState, Tree, ceiling_rows, counters_lost,
    outcome_from_status, refuse_privileged_supervisor, sample_counters,
};
use super::sys::set_nonblocking;
use super::tracer::{self, Tracer};
use super::verdict::{NoneTreeInputs, none_verdict, observer_verdict};
use super::watch;

/// The descriptor the launcher blocks reading.
const RELEASE_FD: RawFd = super::fds::NONE_RELEASE;
/// The descriptor the launcher writes a failed exec's errno to.
const ERROR_FD: RawFd = super::fds::NONE_ERROR;
/// The mechanism `none`'s tree termination names: the leaf's `cgroup.kill`,
/// followed by the population check (§9.3), never a pid namespace.
pub const TREE_MECHANISM: &str = "cgroup-kill";

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// Requirements `none` can never satisfy: it mounts, filters and isolates
/// nothing, so a policy that narrowed it into asking for any of these
/// refuses (§3.1, I02) instead of running with the restriction dropped.
fn never_applied(requirement: Requirement) -> bool {
    matches!(
        requirement,
        Requirement::FilesystemContainment
            | Requirement::SyscallFilter
            | Requirement::NetworkNone
            | Requirement::NetworkProxy
            | Requirement::Limit(LimitKey::Storage | LimitKey::Inodes)
            | Requirement::ProtectedCoverage(_)
    )
}

/// The probes a `none` requirement is derived from, where they differ from a
/// contained profile's. Tree termination: `none` has no pid namespace, and
/// its tree kill is the delegated leaf's `cgroup.kill`, which the
/// `cgroup_delegated_leaf` probe exercises end to end (create, place, kill,
/// empty, reap, remove). A restriction `none` never applies needs no probe:
/// no host can make it available. `None` means "the contained mapping
/// applies".
#[must_use]
pub fn probes_for(
    profile: ProfileName,
    requirement: Requirement,
) -> Option<&'static [&'static str]> {
    if profile != ProfileName::None {
        return None;
    }
    if requirement == Requirement::TreeTermination {
        return Some(&["cgroup_delegated_leaf"]);
    }
    never_applied(requirement).then_some(&[][..])
}

/// The capability a `none` requirement derives from the probe results, where
/// it differs from a contained profile's (see [`probes_for`]).
#[must_use]
pub fn capability_for(
    profile: ProfileName,
    requirement: Requirement,
    results: &[ProbeResult],
    measured_at: &str,
) -> Option<Capability> {
    if profile == ProfileName::None && never_applied(requirement) {
        return Some(Capability::unsupported(
            requirement.to_string(),
            CapabilityScope::Tree,
            REASON_NOT_APPLIED_BY_NONE,
        ));
    }
    let probes = probes_for(profile, requirement)?;
    Some(capability_from(
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
    } else if snapshot.network.mode != crate::network::NetworkMode::Host {
        Some("network.mode")
    } else {
        None
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
    Ok(Box::new(Uncontained::create(plan, sinks, deadline)?))
}

/// The processes below this supervisor before it started the launcher, by pid
/// and birth, so a pid reused later is not mistaken for one.
#[derive(Debug, Default)]
struct Inherited(Vec<(libc::pid_t, u64)>);

impl Inherited {
    /// Every descendant of `own` now.
    fn below(own: libc::pid_t) -> Inherited {
        Inherited(
            tracer::descendants(own)
                .into_iter()
                .filter_map(|pid| {
                    identity::start_time_ticks(pid)
                        .ok()
                        .map(|birth| (pid, birth))
                })
                .collect(),
        )
    }

    /// Whether `pid` is still the process recorded under that number.
    fn contains(&self, pid: libc::pid_t) -> bool {
        self.0.iter().any(|(known, birth)| {
            *known == pid && identity::start_time_ticks(pid).ok() == Some(*birth)
        })
    }
}

/// Everything the `none` boundary owns besides the run's own state.
struct Uncontained {
    snapshot: PolicySnapshot,
    attempt_id: String,
    trace: Option<SharedTrace>,
    /// The §11.4 bounds the observer runs with, decided once; `None` with
    /// observation off.
    observer_plan: Option<observed::ObserverPlan>,
    /// The launcher's pid: the target's once it execs.
    pid: libc::pid_t,
    /// The launcher as a child, for the wait status when no observer owns
    /// this process's waits.
    child: Option<Child>,
    /// Taken while it was this process's unreaped child, so it names it.
    launcher_fd: OwnedFd,
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
    /// What was below this supervisor before the launcher existed.
    inherited: Inherited,
    /// The target's raw wait status, when this process collected it.
    target_status: Option<i32>,
}

/// The launcher, started and still blocked, with its two channels.
struct SpawnedLauncher {
    child: Child,
    pid: libc::pid_t,
    /// Opened while the launcher was this process's unreaped child.
    pidfd: OwnedFd,
    /// The release pipe's write end.
    release: OwnedFd,
    /// The error pipe's read end, non-blocking.
    error: OwnedFd,
}

/// What the blocked launcher was read back as.
struct Established {
    launcher: identity::ProcessIdentity,
    applied: Applied,
    tracer: Option<Tracer>,
}

/// The launcher's environment.
struct LaunchEnvironment {
    vars: Vec<(OsString, OsString)>,
    /// The reserved names removed from the host's; the receipt lists them,
    /// never a value.
    removed: Vec<String>,
}

/// §12: the host environment minus every reserved name, plus the snapshot's
/// own bindings.
///
/// # Errors
/// A binding with a reserved name or a path value.
fn launch_environment(snapshot: &PolicySnapshot) -> Result<LaunchEnvironment, JailError> {
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
    Ok(LaunchEnvironment { vars: env, removed })
}

/// Makes this supervisor a child subreaper, so orphans of the target come to
/// it rather than to init and a descendant that outlives its parent stays
/// enumerable.
///
/// # Errors
/// The refusal when the kernel does not allow it.
fn become_subreaper() -> Result<(), JailError> {
    // SAFETY: PR_SET_CHILD_SUBREAPER takes scalars and dereferences nothing.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(host_setup(
            ErrorCode::BackendUnavailable,
            format!(
                "the supervisor could not become a child subreaper, so an escaped descendant \
                 would be invisible: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

/// Starts the trusted launcher on the host, in a new session, with its
/// release and error pipes at their fixed numbers.
///
/// # Errors
/// A refusal naming the channel or the start that failed; a launcher started
/// but not opened by pidfd is killed and reaped first.
fn spawn_launcher(
    exe: &Path,
    argv: &[OsString],
    pins: &[crate::platform::ExecPin],
    env: &[(OsString, OsString)],
    workspace: &Path,
    observe_on: bool,
) -> Result<SpawnedLauncher, JailError> {
    let io = |err: std::io::Error| {
        host_setup(
            ErrorCode::BackendUnavailable,
            format!("the launcher's channels could not be created: {err}"),
        )
    };
    let (release_r, release_w) = exec::pipe().map_err(io)?;
    let (error_r, error_w) = exec::pipe().map_err(io)?;
    set_nonblocking(error_r.as_fd()).map_err(io)?;
    let mut fds = FdMap::new();
    fds.add(release_r, RELEASE_FD).map_err(io)?;
    fds.add(error_w, ERROR_FD).map_err(io)?;

    let mut command = Command::new(exe);
    command
        .arg(launch::SUBCOMMAND)
        .args(
            launch::LaunchArgs {
                release_fd: RELEASE_FD,
                error_fd: ERROR_FD,
                narrow: observe_on,
                read_open_fast_path: false,
                trace_data_fd: None,
                mediate: None,
                bridge: None,
                sigmask: None,
                // The supervisor may have raised its own soft limit to hand
                // descriptors on (`exec::FdMap`); the target gets the
                // operator's back.
                nofile_soft: exec::operator_nofile_soft(),
                // Review F5: checked immediately before the exec.
                pins: pins.to_vec(),
                argv: argv.to_vec(),
            }
            .to_argv(),
        )
        .env_clear()
        .envs(env.iter().map(|(name, value)| (name, value)))
        .current_dir(workspace);
    // §8.3: every descriptor above stdio closes before exec, the channels
    // above are installed at fixed numbers, and the parent-death signal is
    // armed and rechecked.
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
    // Opened while the launcher is this process's unreaped child, so the
    // descriptor names it and nothing that inherits the number later. A pid
    // that does not fit `pid_t` names no process: refuse, never a stand-in
    // number.
    let opened = libc::pid_t::try_from(child.id())
        .map_err(|_| std::io::Error::other("the launcher's pid does not fit pid_t"))
        .and_then(|pid| identity::pidfd_open(pid).map(|fd| (pid, fd)));
    match opened {
        Ok((pid, pidfd)) => Ok(SpawnedLauncher {
            child,
            pid,
            pidfd,
            release: release_w,
            error: error_r,
        }),
        Err(err) => {
            let _ = child.kill();
            reap_until(&mut child, clock::Deadline::after(TREE_BUDGET));
            Err(io(err))
        }
    }
}

/// The refusal for a launcher that exited, with `exit_code` when its status
/// was collected, before it blocked on its release pipe: the target never
/// ran either way.
fn launcher_ended_before_blocking(exit_code: Option<i32>) -> JailError {
    if exit_code == Some(launch::EXIT_NOFILE_FAILED) {
        return host_setup(
            ErrorCode::InternalError,
            "the launcher could not put the operator's soft RLIMIT_NOFILE back for the target, \
             so it refused before the release; the target never ran",
        );
    }
    host_setup(
        ErrorCode::BackendUnavailable,
        "the launcher exited before it blocked on its release pipe",
    )
}

impl Uncontained {
    /// Creates the boundary and its blocked launcher, read back and, with
    /// observation on, observed: the run the supervisor releases.
    fn create(
        plan: PreparedPlan,
        sinks: Sinks,
        deadline: clock::Deadline,
    ) -> Result<Run<Uncontained>, JailError> {
        let snapshot = plan.request.snapshot.clone();
        if snapshot.profile != ProfileName::None {
            return Err(refusal(
                ErrorCode::InternalError,
                Remediation::InspectState,
                "the uncontained boundary was asked to run a contained profile",
            ));
        }
        refuse_privileged_supervisor()?;
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
        let LaunchEnvironment { vars: env, removed } = launch_environment(&snapshot)?;
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
        // N7: registered in jail state before `mkdir` and before anything is
        // placed in it; a failed registration refuses (S5).
        let created = ExecutionCgroup::create_for_attempt(&snapshot.limits, &plan.attempt_dir)?;
        let leaf = created.map_err(|err| {
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
        become_subreaper()?;
        // Before the launcher exists, everything below this process is
        // something it was started beside, not the attempt.
        let inherited = Inherited::below(crate::sys::own_pid());

        // J12 §3.2 step 4: the child starts where the snapshot says.
        let start = super::mounts::join_native(&plan.workspace, &snapshot.roots.cwd);
        let spawned = spawn_launcher(&exe, &argv, &plan.exec_pins, &env, &start, observe_on)?;
        let audit = AuditWriter::new(
            &plan.attempt_id,
            sinks.trace.clone(),
            plan.workspace.as_os_str().as_bytes(),
            // No scratch: a path is workspace-relative or a digest.
            b"",
        );
        let mut boundary = Uncontained {
            snapshot,
            attempt_id: plan.attempt_id.clone(),
            trace: sinks.trace,
            observer_plan: observe_on.then(observed::ObserverPlan::from_env),
            pid: spawned.pid,
            child: Some(spawned.child),
            launcher_fd: spawned.pidfd,
            leaf,
            leaf_relative,
            cgroup_of: cgroup::process_cgroup,
            losses: Vec::new(),
            escaped: Vec::new(),
            inherited,
            target_status: None,
        };
        let established = match boundary.establish(deadline, removed, &target_images) {
            Ok(established) => established,
            Err(err) => {
                boundary.shut_down(None);
                return Err(err);
            }
        };
        let state = RunState::new(Launched {
            launcher: established.launcher,
            target_images,
            pinned_image: super::launch::pinned_image(&plan.exec_pins),
            release: spawned.release,
            error: ErrorPipe::new(spawned.error),
            audit,
            observe_on,
            tracer: established.tracer,
            applied: established.applied,
        });
        Ok(Run::new(state, boundary))
    }

    /// Places the blocked launcher, reads everything back and attaches the
    /// observer. Any failure refuses; the caller shuts the boundary down.
    fn establish(
        &mut self,
        deadline: clock::Deadline,
        removed: Vec<String>,
        target_images: &[Vec<u8>],
    ) -> Result<Established, JailError> {
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
        let launcher_fd = self.launcher_fd.as_fd();
        match identity::wait_blocked_in_read(pid, RELEASE_FD, deadline, || {
            watch::is_readable(launcher_fd)
        }) {
            Ok(()) => {}
            Err(identity::NotBlocked::Ended) => {
                let code = self
                    .child
                    .as_mut()
                    .and_then(|child| child.try_wait().ok().flatten())
                    .and_then(|status| status.code());
                return Err(launcher_ended_before_blocking(code));
            }
            Err(timeout) => {
                return Err(JailError::new(
                    ErrorCode::PrepareTimeout,
                    ErrorStage::Preparing,
                    Remediation::Retry,
                    format!(
                        "the launcher did not block on its release pipe{}",
                        timeout.detail()
                    ),
                ));
            }
        }

        // With observation on, the narrowing filter must be in force before
        // the seize: without it the observer would see nothing and say so
        // nowhere. One more filter than this process has is the read-back;
        // a filter inherited from the operator's own session is not ours.
        if self.observer_plan.is_some() {
            // One status snapshot per process, parsed as every other
            // privilege read-back parses it: the launcher's filter count and
            // its NoNewPrivs come from the same read.
            let status = |target: libc::pid_t, whose: &str| {
                identity::Privilege::read(target).map_err(|err| {
                    host_setup(
                        ErrorCode::ObserverUnavailable,
                        format!("{whose} status cannot be read back: {err}"),
                    )
                })
            };
            let filters = |privilege: &identity::Privilege| {
                privilege
                    .seccomp_filters
                    .as_deref()
                    .and_then(|value| value.parse::<u64>().ok())
            };
            let own = filters(&status(crate::sys::own_pid(), "this process's")?);
            let launcher_status = status(pid, "the launcher's")?;
            let launcher = filters(&launcher_status);
            let no_new_privs = launcher_status.no_new_privs;
            if own.is_none() || launcher != own.map(|count| count + 1) || !no_new_privs {
                return Err(host_setup(
                    ErrorCode::ObserverUnavailable,
                    format!(
                        "the observer's narrowing filter is not in force in the launcher \
                         (filters {launcher:?} against {own:?} here, NoNewPrivs {no_new_privs})"
                    ),
                ));
            }
        }

        let launcher = identity::ProcessIdentity::capture(pid).map_err(|err| {
            host_setup(
                ErrorCode::BackendUnavailable,
                format!("the launcher's identity could not be recorded: {err}"),
            )
        })?;
        let applied = self.read_applied(removed)?;
        self.leaf
            .verify_member(pid)
            .and_then(|()| self.leaf.arm())
            .map_err(|err| {
                host_setup(
                    ErrorCode::MissingCapability,
                    format!("the launcher's execution cgroup could not be read back: {err}"),
                )
            })?;

        let tracer = match self.observer_plan.as_ref() {
            Some(plan) => {
                // §13.1: gap intervals count from supervisor start on the same
                // CLOCK_BOOTTIME base as every other monotonic_ns. §11.4: the
                // bounds are the plan's, which the receipt records.
                let mut config = plan.tracer_config(clock::mark_supervisor_start());
                config.target = Some((pid, target_images.to_vec()));
                Some(Tracer::attach(pid, config).map_err(|err| {
                    // §11.4: an observer that cannot attach refuses before
                    // exec, whatever the evidence mode says.
                    host_setup(
                        ErrorCode::ObserverUnavailable,
                        format!("the closed-set observer could not attach: {err}"),
                    )
                })?)
            }
            None => None,
        };
        Ok(Established {
            launcher,
            applied,
            tracer,
        })
    }

    /// The `applied` group: nothing but the leaf's limits, the wall and the
    /// environment, which is read back from the launcher; a read-back that
    /// fails refuses rather than record an empty environment.
    fn read_applied(&self, removed: Vec<String>) -> Result<Applied, JailError> {
        let limits = ceiling_rows(&self.snapshot.limits, Some(&self.leaf));
        let environment_names = identity::read_environment_names(self.pid).map_err(|err| {
            host_setup(
                ErrorCode::BackendUnavailable,
                format!("the launcher's environment cannot be read back: {err}"),
            )
        })?;
        Ok(Applied {
            filesystem: None,
            network: AppliedNetwork {
                mode: "host".to_owned(),
                mechanism: None,
                allowed_hosts: Vec::new(),
                tls_only: Vec::new(),
            },
            syscalls: None,
            limits,
            environment_names,
            removed_environment_names: removed,
        })
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
        watch::is_readable(self.launcher_fd.as_fd())
    }

    /// Whether the target's final status has been collected.
    fn target_reaped(&self, run: &RunState) -> bool {
        if run.tracer_attached {
            // The observer reaps what it traces. Its Exit event is the reap of
            // an exec'd target; a clean finish is the reap of everything.
            run.target_exit_seen
                || (run.tracer.is_none()
                    && run
                        .tracer_summary
                        .as_ref()
                        .is_some_and(|summary| observer_verdict(Some(summary))))
        } else {
            self.target_status.is_some()
        }
    }

    /// The live target's membership, read from its own cgroup file and
    /// confirmed alive afterwards, so the read was of the target.
    fn scan_target(&mut self) {
        let fd = self.launcher_fd.as_fd();
        let (cgroup_of, pid) = (self.cgroup_of, self.pid);
        let Some(read) = read_while_alive(|| !watch::is_readable(fd), || cgroup_of(pid)) else {
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
        let own = crate::sys::own_pid();
        self.scan_children(own, tracer::children(own));
    }

    /// [`Uncontained::scan_descendants`] over a given list of `own`'s children.
    /// An inherited child and everything below it are left out, so none of them
    /// can be attributed through it either.
    fn scan_children(&mut self, own: libc::pid_t, children: Vec<libc::pid_t>) {
        let mut walked = Vec::new();
        for child in children {
            if !self.inherited.contains(child) {
                walked.push(child);
                walked.extend(tracer::descendants(child));
            }
        }
        self.scan_walked(own, walked);
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
            let borrowed = fd.as_fd();
            let cgroup_of = self.cgroup_of;
            let Some((parent, cgroup)) = read_while_alive(
                || !watch::is_readable(borrowed),
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
    fn collect_target(&mut self, observer_attached: bool) {
        if observer_attached || self.target_status.is_some() || !peek_exited(self.pid) {
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
    fn reap_orphans(&mut self, observer_attached: bool) {
        if observer_attached {
            return;
        }
        let own = crate::sys::own_pid();
        // An inherited child's status is its owner's, not the attempt's.
        let children = tracer::children(own)
            .into_iter()
            .filter(|pid| !self.inherited.contains(*pid))
            .collect();
        self.reap_exited_children(children);
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
    // Termination
    // -----------------------------------------------------------------------

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

    /// Kills and reaps everything this boundary owns, within one tree budget.
    /// `run` is the run's state once there is one: its observer is stopped
    /// inside the same budget, and owns the waits it attached for.
    fn shut_down(&mut self, run: Option<&mut RunState>) {
        let deadline = clock::Deadline::after(TREE_BUDGET);
        self.kill_all();
        let attached = run.is_some_and(|run| {
            run.stop_observer(deadline.remaining());
            run.tracer_attached
        });
        if !attached && let Some(child) = self.child.as_mut() {
            reap_until(child, deadline);
            if let Ok(Some(status)) = child.try_wait() {
                self.target_status = Some(status.into_raw());
            }
        }
        self.reap_orphans(attached);
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

impl Tree for Uncontained {
    fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    fn boundary_identity(&self, run: &RunState) -> BoundaryIdentity {
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
        // §9.3 — where the supervisor stood when the leaf was made: already
        // delegated, entered a scope of its own, or why not.
        details.insert("supervisor_scope".to_owned(), super::scope::details());
        // Observation, not containment: the observer's filter is in the
        // target, and the receipt names it by the digest it reports.
        details.insert(
            "narrowing_filter_digest".to_owned(),
            if run.observe_on {
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
        identity_value.insert("pid".to_owned(), Value::from(i64::from(run.launcher.pid)));
        identity_value.insert(
            "boot_id".to_owned(),
            Value::from(run.launcher.boot_id.clone()),
        );
        identity_value.insert(
            "start_time_ticks".to_owned(),
            Value::from(run.launcher.start_time_ticks),
        );
        BoundaryIdentity {
            boundary: BoundaryKind::SupervisorCgroup,
            verification_scope: VerificationScope::RegisteredBoundary,
            native: Some(NativeLifetime {
                os: Os::Linux,
                details,
            }),
            process: Some(ProcessRecord {
                pid: u32::try_from(run.launcher.pid).unwrap_or(0),
                identity: RecordIdentity {
                    kind: "linux_boot_start".to_owned(),
                    value: identity_value,
                },
            }),
            backend: Some("none".to_owned()),
            backend_version: None,
        }
    }

    fn check_before_release(&mut self, _run: &mut RunState) -> Result<(), JailError> {
        // The blocked launcher must still be the only thing in the pinned
        // leaf. A same-UID process can have changed either since prepared;
        // the refusal then carries the teardown, `lost` included (§13.2).
        self.scan_target();
        let populated = self.scan_leaf();
        self.scan_descendants();
        if !self.losses.is_empty() || self.target_exited() || populated != Some(true) {
            return Err(host_setup(
                ErrorCode::BackendUnavailable,
                "the registered boundary or the blocked launcher was lost before release",
            ));
        }
        Ok(())
    }

    /// Verified only on a reaped launcher, an empty identity-checked leaf and
    /// a clean observer; `lost` after any detected loss (§13.2 row 4).
    fn tear_down(&mut self, run: &mut RunState) -> TreeObservation {
        self.shut_down(Some(run));
        let populated = self.scan_leaf();
        let reaped = self.target_reaped(run);
        none_verdict(&NoneTreeInputs {
            integrity_lost: !self.losses.is_empty(),
            natural_end: reaped,
            target_reaped: reaped,
            leaf_verified_empty: populated == Some(false),
            observer_clean: observer_verdict(run.tracer_summary.as_ref()),
        })
    }

    fn poll(&mut self, run: &mut RunState) -> bool {
        self.collect_target(run.tracer_attached);
        self.reap_orphans(run.tracer_attached);
        self.scan_target();
        false
    }

    /// Counters, the leaf's identity and every descendant's membership.
    fn sample(&mut self, run: &mut RunState) {
        if self.scan_leaf().is_some() {
            match sample_counters(&mut self.leaf, &mut run.audit) {
                Counters::Read { oom_killed } => {
                    if oom_killed {
                        self.hard_kill(run);
                    }
                }
                Counters::Lost => self.lose(Subject::Boundary, Loss::VerificationFailed),
            }
        } else {
            // The leaf cannot even be scanned, so no counter claim stands.
            counters_lost(&mut self.leaf, &mut run.audit, "cgroup_leaf_scan_failed");
        }
        self.scan_descendants();
    }

    fn kill(&mut self, _run: &mut RunState) {
        self.kill_all();
    }

    /// The observer's final status or its end with observation on, the wait
    /// status with it off: never population, since an empty leaf with a
    /// live target is a live target.
    fn target_done(&self, run: &RunState) -> bool {
        if run.tracer_attached {
            run.target_exit_seen || run.finished
        } else {
            self.target_status.is_some()
        }
    }

    /// Observation off, the exit status is this process's own wait status of
    /// the target, which is exact. Exec is confirmed without an observer by
    /// the launcher's protocol: after it was seen blocked on the release
    /// descriptor and released, its only ways to end before exec are an exec
    /// failure, which writes the errno first, or a signal. So an exit with no
    /// errno bytes is the target's own exit (§8.1 step 7: "EOF alone is
    /// insufficient if launcher death could also have closed that fd" — a
    /// signal death stays unknown).
    fn unobserved_outcome(&mut self, run: &mut RunState) -> Option<RunEvent> {
        if run.tracer_attached {
            return run.finished.then(|| RunEvent::Unknown {
                reason: "the observer ended without the target's final status".to_owned(),
            });
        }
        let status = self.target_status?;
        run.error.drain();
        if !run.error.bytes.is_empty() {
            let (errno, detail) = launch::exec_failure_parts(&run.error.bytes);
            return Some(RunEvent::ExecError { errno, detail });
        }
        let outcome = outcome_from_status(status);
        if !run.exec_confirmed {
            if libc::WIFEXITED(status) && run.error.eof {
                run.exec_confirmed = true;
                run.pending.push_back(outcome);
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

    fn cooperative_stop(&mut self, _run: &mut RunState) {
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

    fn tree_ended(&mut self, run: &mut RunState) -> bool {
        self.collect_target(run.tracer_attached);
        self.reap_orphans(run.tracer_attached);
        self.scan_target();
        let populated = self.scan_leaf();
        self.scan_descendants();
        if run.hard_killed {
            // Orphans reparented here by the kill are ours to end too.
            self.kill_escaped();
        }
        let escaped_alive = self
            .escaped
            .iter()
            .any(|(_, fd)| !watch::is_readable(fd.as_fd()));
        // An unreadable leaf after a recorded loss has nothing more to say; a
        // readable one must be seen empty.
        let leaf_done =
            populated == Some(false) || (populated.is_none() && !self.losses.is_empty());
        self.target_reaped(run) && leaf_done && !escaped_alive
    }

    fn settle(
        &mut self,
        run: &mut RunState,
        _deadline: clock::Deadline,
        natural: bool,
    ) -> TreeObservation {
        self.sample(run);
        let populated = self.scan_leaf();
        none_verdict(&NoneTreeInputs {
            integrity_lost: !self.losses.is_empty(),
            natural_end: natural,
            target_reaped: self.target_reaped(run),
            leaf_verified_empty: populated == Some(false),
            observer_clean: observer_verdict(run.tracer_summary.as_ref()),
        })
    }

    fn final_limits(&self) -> Vec<AppliedLimit> {
        self.leaf.limits()
    }

    fn limit_cause(&self) -> Option<LimitCause> {
        self.leaf.oom_killed().then_some(LimitCause::MemoryOom)
    }

    fn integrity_lost(&self) -> bool {
        !self.losses.is_empty()
    }

    fn dropped(&mut self, run: &mut RunState) {
        if run.tracer.is_some() || !self.target_reaped(run) {
            self.shut_down(Some(run));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::none_verdict as verdict;
    use super::*;
    use crate::lifecycle::Integrity;
    use std::time::Duration;

    #[test]
    fn none_keeps_the_contained_probes_for_what_it_shares() {
        assert_eq!(
            probes_for(ProfileName::None, Requirement::TreeTermination),
            Some(&["cgroup_delegated_leaf"][..])
        );
        for profile in [ProfileName::Tool, ProfileName::Build, ProfileName::Agent] {
            assert_eq!(probes_for(profile, Requirement::TreeTermination), None);
        }
        for requirement in [
            Requirement::ExecutionBoundary,
            Requirement::ClosedSetObservation,
            Requirement::Limit(LimitKey::Wall),
            Requirement::Limit(LimitKey::Pids),
        ] {
            assert_eq!(probes_for(ProfileName::None, requirement), None);
        }
    }

    #[test]
    fn restrictions_none_cannot_apply_are_never_available() {
        for requirement in [
            Requirement::FilesystemContainment,
            Requirement::SyscallFilter,
            Requirement::NetworkNone,
            Requirement::NetworkProxy,
            Requirement::ProtectedCoverage(ProtectedCoverage::ExistingAndRoot),
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
        isolated.network.mode = crate::network::NetworkMode::None;
        assert_eq!(unapplied_restriction(&isolated), Some("network.mode"));
    }

    #[test]
    fn none_tree_termination_is_the_leaf_kill_and_needs_its_probe() {
        assert!(
            capability_for(
                ProfileName::Tool,
                Requirement::TreeTermination,
                &[],
                "2026-09-22T00:00:00Z"
            )
            .is_none()
        );
        let skipped = capability_for(
            ProfileName::None,
            Requirement::TreeTermination,
            &[],
            "2026-09-22T00:00:00Z",
        )
        .unwrap();
        assert!(!skipped.satisfies(), "an unrun probe cannot satisfy it");
        assert_eq!(skipped.mechanism.as_deref(), Some(TREE_MECHANISM));
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
        let leaf = "/u/ukai-att_x.leaf";
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
                Some("/u/ukai-att_x.leaf/made"),
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

    const FAKE_LEAF: &str = "/fake/ukai-att_x.leaf";

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
    ) -> Run<Uncontained> {
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
        let (_reader, release) = exec::pipe().unwrap();
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
        let mut state = RunState::new(Launched {
            launcher: identity::ProcessIdentity {
                pid,
                boot_id: String::new(),
                start_time_ticks: 0,
            },
            target_images: Vec::new(),
            pinned_image: None,
            release,
            error: ErrorPipe::new(error),
            audit: AuditWriter::new(
                "att_00000000-0000-4000-8000-000000000001",
                None,
                b"/work",
                b"",
            ),
            observe_on: false,
            tracer: None,
            applied: Applied {
                filesystem: None,
                network: AppliedNetwork {
                    mode: "host".to_owned(),
                    mechanism: None,
                    allowed_hosts: Vec::new(),
                    tls_only: Vec::new(),
                },
                syscalls: None,
                limits: Vec::new(),
                environment_names: Vec::new(),
                removed_environment_names: Vec::new(),
            },
        });
        state.error.eof = true;
        let tree = Uncontained {
            snapshot,
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            trace: None,
            observer_plan: None,
            pid,
            child: Some(child),
            launcher_fd,
            leaf: ExecutionCgroup::open_for_test(leaf).unwrap(),
            leaf_relative: FAKE_LEAF.to_owned(),
            cgroup_of,
            losses: Vec::new(),
            escaped: Vec::new(),
            inherited: Inherited::default(),
            target_status: None,
        };
        Run::new(state, tree)
    }

    fn final_integrity(boundary: &Run<Uncontained>, leaf_empty: bool) -> Integrity {
        verdict(&NoneTreeInputs {
            integrity_lost: boundary.tree.integrity_lost(),
            natural_end: true,
            target_reaped: boundary.tree.target_reaped(&boundary.state),
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
        control.tree.collect_target(false);
        assert!(control.tree.target_reaped(&control.state));
        assert!(control.tree.losses.is_empty());
        assert_eq!(control.tree.scan_leaf(), Some(false));
        assert_eq!(final_integrity(&control, true), Integrity::Verified);

        let mut failing = exited_child_boundary(&leaf, read_fails);
        failing.tree.collect_target(false);
        assert!(
            failing.tree.target_reaped(&failing.state),
            "the status is still collected"
        );
        assert_eq!(
            failing.tree.losses,
            vec![(Subject::Target, Loss::VerificationFailed)]
        );
        assert!(failing.tree.integrity_lost());
        assert_eq!(final_integrity(&failing, true), Integrity::Lost);
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

    /// An inherited record names a process only with its birth. The same pid
    /// under another start time is a number the kernel reused after the
    /// inherited process ended — possibly for an escaped attempt process — so
    /// it is not inherited and is scanned like any child. The kernel will not
    /// reuse a live pid on demand, so the record's birth is made to differ
    /// instead.
    #[test]
    fn j5t_an_inherited_record_names_a_process_only_with_its_birth() {
        let root = tempfile::tempdir().unwrap();
        let leaf = fake_leaf(root.path());
        let own = crate::sys::own_pid();
        let child = spawn_sleeper();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let birth = identity::start_time_ticks(pid).expect("the sleeper's start time");

        assert!(Inherited(vec![(pid, birth)]).contains(pid));
        assert!(
            !Inherited(vec![(pid, birth + 1)]).contains(pid),
            "the same pid born at another time is not the inherited process"
        );
        assert!(!Inherited(vec![(pid + 1, birth)]).contains(pid));

        // Inherited, with its own birth: never walked, nothing recorded.
        let mut kept = exited_child_boundary(&leaf, read_outside);
        kept.tree.collect_target(false);
        kept.tree.losses.clear();
        kept.tree.inherited = Inherited(vec![(pid, birth)]);
        kept.tree.scan_children(own, vec![pid]);
        assert!(kept.tree.losses.is_empty(), "{:?}", kept.tree.losses);
        assert!(kept.tree.escaped.is_empty());

        // The record's birth is not this process's: it is this supervisor's
        // child outside the leaf, an escape, and kept for signalling.
        let mut reused = exited_child_boundary(&leaf, read_outside);
        reused.tree.collect_target(false);
        reused.tree.losses.clear();
        reused.tree.inherited = Inherited(vec![(pid, birth + 1)]);
        reused.tree.scan_children(own, vec![pid]);
        assert_eq!(
            reused.tree.losses,
            vec![(Subject::Descendant, Loss::MembershipEscape)]
        );
        assert_eq!(
            reused
                .tree
                .escaped
                .iter()
                .map(|(known, _)| *known)
                .collect::<Vec<_>>(),
            vec![pid]
        );
        end(child);
    }

    /// G5-G7 at the call site: a walked process is attributed only through
    /// a parent in the walk, recorded when outside, and kept for signalling
    /// only when it is this process's own child. The walk is given, so no
    /// other test's children are ever looked at.
    #[test]
    fn walked_processes_are_attributed_before_they_are_recorded_or_signalled() {
        let root = tempfile::tempdir().unwrap();
        let leaf = fake_leaf(root.path());
        let own = crate::sys::own_pid();

        // Our child, outside the leaf: a loss, and signallable.
        let child = spawn_sleeper();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let mut boundary = exited_child_boundary(&leaf, read_outside);
        boundary.tree.collect_target(false);
        boundary.tree.losses.clear();
        boundary.tree.scan_walked(own, vec![pid]);
        assert_eq!(
            boundary.tree.losses,
            vec![(Subject::Descendant, Loss::MembershipEscape)]
        );
        assert_eq!(
            boundary
                .tree
                .escaped
                .iter()
                .map(|(known, _)| *known)
                .collect::<Vec<_>>(),
            vec![pid]
        );

        // The same process in a walk that does not contain its parent is a
        // reused pid as far as this boundary can tell: nothing recorded.
        let mut foreign = exited_child_boundary(&leaf, read_outside);
        foreign.tree.collect_target(false);
        foreign.tree.losses.clear();
        foreign.tree.scan_walked(1, vec![pid]);
        assert!(foreign.tree.losses.is_empty());
        assert!(foreign.tree.escaped.is_empty());

        // Alive, ours, and its cgroup unreadable: a failed verification.
        let mut unreadable = exited_child_boundary(&leaf, read_fails);
        unreadable.tree.collect_target(false);
        unreadable.tree.losses.clear();
        unreadable.tree.scan_walked(own, vec![pid]);
        assert_eq!(
            unreadable.tree.losses,
            vec![(Subject::Descendant, Loss::VerificationFailed)]
        );
        assert!(unreadable.tree.escaped.is_empty());
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
        deeper.tree.collect_target(false);
        deeper.tree.losses.clear();
        deeper.tree.scan_walked(own, vec![shell_pid, grandchild]);
        assert_eq!(
            deeper.tree.losses,
            vec![(Subject::Descendant, Loss::MembershipEscape)]
        );
        assert_eq!(
            deeper
                .tree
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
        boundary.tree.reap_exited_children(vec![pid]);
        assert_eq!(
            boundary.tree.losses,
            vec![(Subject::Descendant, Loss::VerificationFailed)]
        );
        assert!(!peek_exited(pid), "the zombie was reaped");
        // The target's own collection is untouched by the orphan's.
        boundary.tree.collect_target(false);
        assert!(boundary.tree.target_reaped(&boundary.state));
        drop(orphan);
    }

    /// A14: a population read that fails while the leaf's identity is intact
    /// is a failed verification, not an unknown that could pass later.
    #[test]
    fn an_unreadable_population_with_the_identity_intact_loses_integrity() {
        let root = tempfile::tempdir().unwrap();
        let leaf = fake_leaf(root.path());
        let mut boundary = exited_child_boundary(&leaf, read_inside);
        boundary.tree.collect_target(false);
        assert_eq!(boundary.tree.scan_leaf(), Some(false), "the control reads");
        assert!(boundary.tree.losses.is_empty());

        std::fs::write(leaf.join("cgroup.events"), "populated maybe\n").unwrap();
        assert!(
            boundary.tree.leaf.verify().is_ok(),
            "the identity is intact"
        );
        assert_eq!(boundary.tree.scan_leaf(), None);
        assert_eq!(
            boundary.tree.losses,
            vec![(Subject::Boundary, Loss::VerificationFailed)]
        );
        assert_eq!(final_integrity(&boundary, false), Integrity::Lost);

        // A replaced directory at the same path is the other loss.
        std::fs::rename(&leaf, root.path().join("moved")).unwrap();
        fake_leaf(root.path());
        assert_eq!(boundary.tree.scan_leaf(), None);
        assert!(
            boundary
                .tree
                .losses
                .contains(&(Subject::Boundary, Loss::IdentityReplaced))
        );
    }

    /// A launcher that could not restore the descriptor limit says so; any
    /// other early end stays the generic refusal.
    #[test]
    fn an_early_launcher_end_names_a_descriptor_limit_it_could_not_restore() {
        let nofile = launcher_ended_before_blocking(Some(launch::EXIT_NOFILE_FAILED));
        assert_eq!(nofile.code, ErrorCode::InternalError);
        assert!(
            nofile.message.contains("RLIMIT_NOFILE") && nofile.message.contains("never ran"),
            "{}",
            nofile.message
        );
        for code in [None, Some(launch::EXIT_INTERNAL)] {
            let other = launcher_ended_before_blocking(code);
            assert_eq!(other.code, ErrorCode::BackendUnavailable);
            assert!(
                other.message.contains("before it blocked"),
                "{}",
                other.message
            );
        }
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
