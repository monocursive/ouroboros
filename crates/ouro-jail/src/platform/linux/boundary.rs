//! The contained boundary: preparation, discovery, release and teardown.
//!
//! Preparation runs in typed phases, each holding only facts that exist by
//! then: the [`Planned`] mount plan, the [`Channels`] to the backend, the
//! [`Started`] backend (and everything that ends with it), and the
//! [`Discovered`] namespace init and launcher. The [`Boundary`] the run
//! drives is built from them once discovery read everything back, so none of
//! its fields stands for a value not known yet. A refusal before the spawn
//! drops what the earlier phases hold (the placeholder set, the bootstrap
//! child's kill guard, the watcher); one from the spawn on runs the one
//! teardown, [`Started::tear_down`], which the release and the abort share.

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::observer::CoverageSummary;
use crate::platform::{BoundaryIdentity, PreparedPlan, RunEvent, Sinks, TreeObservation};
use crate::policy::{PolicySnapshot, ProfileName, ProtectedCoverage, ScratchRoot};
use crate::records::{
    Applied, AppliedFilesystem, AppliedLimit, AppliedMount, AppliedNetwork, AppliedSyscalls,
    ErrorCode, ErrorStage, JailError, NativeLifetime, NativeString, ObserveMode, Os,
    ProcessIdentity as RecordIdentity, ProcessRecord, Remediation,
};
use crate::supervisor::TREE_BUDGET;

use super::agent::AgentNet;
use super::audit::AuditWriter;
use super::bpf::Program;
use super::bwrap::{self, BwrapPlan, Placeholder, PlaceholderOutcome, PlaceholderSet, Rendered};
use super::cgroup::ExecutionCgroup;
use super::clock;
use super::exec::{self, BootstrapChild, BootstrapSpawn, FdMap};
use super::fs as jfs;
use super::identity::{self, read_environment_names};
use super::mounts::{
    PlanPaths, StagedMounts, absent_runtime_candidate, host_path_of, is_allowed_device_node,
    mount_swap_rendezvous, plan_for, prepare_mounts, read_mount_table, recordable_mounts,
    refuse_pseudo_fs_grants, refuse_unrecordable_mounts, resolve_path_ref, scan_coverage,
    skipped_protected_names, stage_sanitized_resolv_conf, staged_mounts,
};
use super::platform::{
    ARGS_FD, ERROR_FD, PINNED_FD_BASE, RELEASE_FD, SECCOMP_FD, STATUS_FD, TRACE_DATA_FD,
    VENDOR_STATE_FD, error, preparing,
};
use super::running::{
    Counters, ErrorPipe, Launched, Run, RunState, Tree, WAIT_STEP, ceiling_rows,
    refuse_privileged_supervisor, sample_counters, wrong_guess_stops_detail,
};
use super::seccomp;
use super::stdio::{
    OUTPUT_DRAIN_BUDGET, StdioPlan, StdioRelay, drain_output_relays, pump_stdio_relays,
    validate_stdio,
};
use super::sys::{nap, set_nonblocking, write_all, write_until};
use super::tracer::Tracer;
use super::verdict::{AbortInputs, TreeInputs, abort_verdict, observer_verdict, verdict};
use super::watch::{self, Watcher};

/// The most a stop gives the proxy to drain its last results (§10).
const AGENT_STOP_BUDGET: Duration = Duration::from_secs(2);

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

pub(super) fn prepare_timeout(message: &str) -> JailError {
    error(
        ErrorCode::PrepareTimeout,
        ErrorStage::Preparing,
        Remediation::Retry,
        message.to_owned(),
    )
}

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

/// Whether `filter`, the baseline bubblewrap installs, denies `link` and
/// `linkat`, read from the program itself: it is matched against its
/// profile's baseline (`tool`'s, or `agent`'s in `variant`) built with and
/// without the storage rules.
///
/// # Errors
/// Why the answer is unknown: a baseline that cannot be built, or a program
/// that is neither of the two, which no preparation installs.
fn installed_hard_link_rule(
    filter: &Program,
    variant: Option<seccomp::AgentVariant>,
) -> Result<bool, String> {
    let baseline = |storage| {
        match variant {
            Some(variant) => seccomp::agent_baseline_with_storage(variant, storage),
            None => seccomp::tool_baseline_with_storage(storage),
        }
        .map_err(|err| format!("its baseline cannot be built: {err}"))
    };
    if *filter == baseline(true)? {
        Ok(true)
    } else if *filter == baseline(false)? {
        Ok(false)
    } else {
        Err("it is not its profile's baseline".to_owned())
    }
}

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
}

/// The namespace init: the host pid bubblewrap reported, and a pidfd opened
/// right then. Every later signal and liveness check goes through the
/// descriptor, so neither can reach a process that merely inherited the
/// number.
struct Init {
    pid: libc::pid_t,
    fd: OwnedFd,
}

impl Init {
    /// Whether the init is still running: its pidfd turns readable at its
    /// exit, a zombie's included, and cannot come to name another process.
    fn alive(&self) -> bool {
        !watch::readable(self.fd.as_raw_fd())
    }
}

/// What the spawn started, and how all of it ends: the backend with its
/// status pipe and its watcher, the execution leaf, the placeholders, the
/// `agent` network and the stdio relays.
struct Started {
    /// The backend, while this process may still collect its status.
    child: Option<BootstrapChild>,
    bootstrap_spawn: BootstrapSpawn,
    bwrap_pid: libc::pid_t,
    /// A descriptor for bubblewrap, taken while it was this process's
    /// unreaped child. A pid number can come to mean another process; a
    /// pidfd cannot (§9.3).
    bwrap_fd: OwnedFd,
    status: StatusReader,
    watcher: Watcher,
    cgroup: Option<ExecutionCgroup>,
    /// The leaf's identity or counters were lost while the target ran.
    cgroup_lost: bool,
    /// Why no execution cgroup exists, when preferred ceilings run
    /// unenforced.
    cgroup_unavailable: Option<String>,
    placeholders: Vec<Placeholder>,
    placeholder_outcomes: Vec<PlaceholderOutcome>,
    /// The proxy, mediator and bridge of an `agent` attempt.
    agent: Option<AgentNet>,
    /// Audit 2026-10-08 H1 follow-up: the regular-file and socket stdio
    /// streams, relayed through supervisor-owned pipes so the child holds no
    /// reopenable handle on any file.
    stdio_relays: Vec<StdioRelay>,
    /// Set before this boundary kills anything: what dies after it did not
    /// die on its own.
    killing: AtomicBool,
}

impl Started {
    /// Whether the backend's pidfd reports its exit, independent of whether
    /// its status has been collected yet.
    fn backend_exited(&self) -> bool {
        watch::readable(self.bwrap_fd.as_raw_fd())
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

    /// Whether the backend has exited, collecting its status. Only for
    /// discovery: from the observer's attach on, its thread owns every
    /// `waitpid` in this process.
    fn exited(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    }

    fn diagnostic(&self) -> String {
        self.status.text.clone()
    }

    /// Kills the namespace init, when it was named, and the backend through
    /// their descriptors, and the leaf through `cgroup.kill`.
    ///
    /// §9.3: never signal a pid without revalidating its identity. A pidfd
    /// is that revalidation made permanent — the kernel refuses to deliver
    /// through it once the process is gone, so no signal of this attempt's
    /// can land on whatever later holds the number. Killing the init makes
    /// the kernel kill the namespace; the backend outside it goes too.
    fn kill(&self, init: Option<&Init>) {
        self.killing.store(true, Ordering::SeqCst);
        if let Some(leaf) = &self.cgroup {
            let _ = leaf.kill();
        }
        for fd in init
            .map(|init| &init.fd)
            .into_iter()
            .chain([&self.bwrap_fd])
        {
            let _ = identity::pidfd_send_signal(fd.as_raw_fd(), libc::SIGKILL);
        }
    }

    /// Stops the proxy and the mediator, draining what they last reported.
    /// Called once the tree is dead or given up on: until then the proxy and
    /// the mediator are part of the boundary the child relies on.
    fn stop_agent(&mut self, audit: &mut AuditWriter, observe_on: bool, budget: Duration) {
        if let Some(agent) = self.agent.as_mut() {
            agent.stop(audit, observe_on, budget.min(AGENT_STOP_BUDGET));
        }
    }

    /// The one teardown of a boundary whose target never ran: a refusal,
    /// a failed release or an abort (§13.2 row 4). Kills the boundary, stops
    /// the observer (`run`, once there is one) and the `agent` network, and
    /// reports whether the tree's death was verified.
    ///
    /// Verified means exactly what settlement requires, without the target:
    /// the namespace init's pidfd reports its death (PID-namespace semantics:
    /// every other member, the blocked launcher included, died first); the
    /// backend (this supervisor's child) and the outside watcher are dead and
    /// reaped; the execution cgroup, when one exists, was observed
    /// unpopulated and its identity was never lost; and the observer, when
    /// attached, finished without abandoning a tracee or losing a child's
    /// status. Everything is polled within one fresh tree budget; whatever is
    /// still unknown at its end leaves the tree `pending` and `tree_empty`
    /// null. "The trusted launcher died" is not on the list: it is implied by
    /// the init's death and proves nothing without it. Before bubblewrap
    /// named an init there is none to wait for: the backend's own end, the
    /// watcher's and an empty leaf are then what is left to see.
    fn tear_down(&mut self, init: Option<&Init>, witness: Witness<'_>) -> TreeObservation {
        let deadline = clock::Deadline::after(TREE_BUDGET);
        self.kill(init);
        // The observer is stopped first, so after this nothing but this
        // thread waits for children; its account is kept for the verdict.
        let (audit, observe_on, observer) = match witness {
            Witness::Run(run) => {
                run.stop_observer(deadline.remaining());
                (&mut run.audit, run.observe_on, run.tracer_summary.as_ref())
            }
            Witness::Audit { audit, observe_on } => (audit, observe_on, None),
        };
        // The target never ran; nothing is left to serve.
        self.stop_agent(audit, observe_on, deadline.remaining());
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
        let init_dead = || init.is_none_or(|init| !init.alive());
        loop {
            self.release_watcher_after_backend();
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
            abandoned_tracees: observer.map_or(0, |summary| summary.loss.abandoned_tracees),
            observer_panicked: observer.is_some_and(|summary| summary.thread_panicked),
            unreaped_children: observer
                .map(|summary| summary.unreaped_children.clone())
                .unwrap_or_default(),
            // Security 2026-09-27 (audit 3 A5): carried for the receipt;
            // never a verdict input, because the stop was continued and
            // nothing was lost.
            requested_by_other_filters: observer
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

    /// Tears the boundary down after a refusal before the run exists and
    /// returns `refusal`, which then also says which placeholders it leaves
    /// in the operator's workspace and why, when it leaves any.
    fn refuse(
        &mut self,
        mut refusal: JailError,
        init: Option<&Init>,
        audit: &mut AuditWriter,
        observe_on: bool,
    ) -> JailError {
        self.tear_down(init, Witness::Audit { audit, observe_on });
        if let Some(left) = self.placeholders_left() {
            refusal.message = format!("{}; {left}", refusal.message);
            // What the record says is left stays left: nothing removes them
            // after the refusal named them.
            self.placeholders.clear();
        }
        refusal
    }

    /// The placeholders a teardown did not remove, for a refusal's message;
    /// `None` when every one is gone.
    fn placeholders_left(&self) -> Option<String> {
        if self.placeholder_outcomes.is_empty() {
            if self.placeholders.is_empty() {
                return None;
            }
            let paths: Vec<String> = self
                .placeholders
                .iter()
                .map(|placeholder| placeholder.destination().display().to_string())
                .collect();
            return Some(format!(
                "the placeholder directories {} are left in the workspace: the boundary's tree \
                 was not shown dead within its budget",
                paths.join(", ")
            ));
        }
        let kept: Vec<String> = self
            .placeholder_outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                PlaceholderOutcome::Removed(_) | PlaceholderOutcome::AlreadyGone(_) => None,
                PlaceholderOutcome::KeptChanged(path, reason) => {
                    Some(format!("{} ({reason})", path.display()))
                }
                PlaceholderOutcome::KeptNotEmpty(path) => {
                    Some(format!("{} (not empty)", path.display()))
                }
                PlaceholderOutcome::KeptError(path, errno) => Some(format!(
                    "{} ({})",
                    path.display(),
                    super::sys::errno_name(*errno)
                )),
            })
            .collect();
        (!kept.is_empty()).then(|| {
            format!(
                "the placeholder directories {} are kept in the workspace",
                kept.join(", ")
            )
        })
    }
}

/// Whose account a teardown records into: the run's, which also has an
/// observer to stop first, or before the run exists the audit preparation
/// holds.
enum Witness<'a> {
    Run(&'a mut RunState),
    Audit {
        audit: &'a mut AuditWriter,
        observe_on: bool,
    },
}

/// Creates the contained boundary and its blocked launcher, read back and,
/// with observation on, observed: the run the supervisor releases.
///
/// # Errors
/// A typed refusal (§6.4) naming the step that failed; whatever the earlier
/// steps made is torn down first.
pub(super) fn create(
    bwrap_path: &Path,
    backend_pin: &jfs::PinnedPath,
    plan: PreparedPlan,
    sinks: Sinks,
    deadline: clock::Deadline,
) -> Result<Run<Boundary>, JailError> {
    let snapshot = plan.request.snapshot.clone();
    refuse_privileged_supervisor()?;
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
    // Read before the mount preparation raises it.
    let nofile_soft = operator_nofile_soft();

    // `<data>/attempts/<id>` is the attempt; the state root is two levels
    // up, and everything under it is supervisor state (§7).
    let state_root = plan
        .attempt_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(plan.attempt_dir.as_path());
    let stdio_plans = validate_stdio(state_root, &plan.config_dir)?;
    let scratch = scratch_directory(&snapshot, &plan.attempt_dir)?;
    let (cgroup, cgroup_unavailable) = execution_cgroup(&snapshot, &plan.attempt_dir)?;

    // north-star §4.4 / jail-v1 §9.1: Linux cannot enforce all_descendants;
    // a profile that requires it refuses (125) rather than underclaim.
    if snapshot.filesystem.protected_coverage == ProtectedCoverage::AllDescendants {
        return Err(error(
            ErrorCode::MissingCapability,
            ErrorStage::Preparing,
            Remediation::Unsupported,
            "the all_descendants protected-path coverage cannot be enforced on Linux; it refuses \
             rather than underclaim (north-star §4.4)"
                .to_owned(),
        ));
    }

    let mut planned = Planned::new(
        &snapshot,
        &plan,
        &sinks,
        Launcher {
            bwrap_path,
            exe: &exe,
            observe_on,
            nofile_soft,
        },
        &scratch,
    )?;
    let mut channels = Channels::open(&mut planned, backend_pin)?;
    planned.verify_before_spawn(backend_pin)?;
    let stdio_relays = attach_stdio(stdio_plans, &mut channels.fds)?;
    let (mut started, release, mut launcher_error) = spawn(
        &exe,
        &mut planned,
        channels,
        stdio_relays,
        (cgroup, cgroup_unavailable),
        deadline,
    )?;

    let mut audit = AuditWriter::new(
        &plan.attempt_id,
        sinks.trace.clone(),
        plan.workspace.as_os_str().as_bytes(),
        bwrap::SCRATCH_INSIDE_PATH.as_bytes(),
    )
    .with_learning(snapshot.observation.learning)
    .with_roots(audit_named_roots(&planned.bplan));
    // The proxy starts only now that the backend exists, so the descriptor
    // limit it raises never reaches the child.
    if let Some(agent) = started.agent.as_mut()
        && let Err(err) = agent.start_proxy()
    {
        return Err(started.refuse(err, None, &mut audit, observe_on));
    }
    if let Some(reason) = started.cgroup_unavailable.clone() {
        for (key, ceiling) in [
            ("pids", &snapshot.limits.pids),
            ("mem", &snapshot.limits.mem),
            ("swap", &snapshot.limits.swap),
            ("cpu", &snapshot.limits.cpu),
        ] {
            if ceiling.is_some() {
                audit.record_limit_unapplied(key, &reason);
            }
        }
    }

    let inputs = DiscoveryInputs {
        bwrap_path,
        deadline,
        snapshot: &snapshot,
        workspace: &plan.workspace,
        launcher_argv: &planned.launcher_argv,
        filter_digest: &planned.filter_digest,
        scan: &planned.scan,
        observe_on,
    };
    let discovered = match discover(&mut started, &mut launcher_error, &inputs) {
        Ok(discovered) => discovered,
        Err(Refused { error, init }) => {
            return Err(started.refuse(error, init.as_ref(), &mut audit, observe_on));
        }
    };
    let Discovered {
        init,
        launcher,
        launcher_fd,
        ns_ids,
        seccomp_filters,
        backend_version,
        storage,
        applied,
    } = discovered;
    // Audit 2026-10-08 M2: storage and inode ceilings expose occupancy, not
    // refusal counters — their hit evidence is positive-only saturation
    // sampling (§11.4), so the `limits` class starts degraded with a null
    // count and names its gap.
    if storage
        .as_ref()
        .is_some_and(|storage| storage.limits().iter().any(|limit| limit.hit.is_none()))
    {
        audit.record_limit_evidence_missing("storage_hit_evidence_positive_only");
    }
    if let Some(leaf) = started.cgroup.as_mut()
        && let Err(err) = leaf
            .verify_member(launcher.pid)
            .and_then(|()| leaf.verify_member(started.bwrap_pid))
            .and_then(|()| leaf.verify_member(init.pid))
            .and_then(|()| leaf.arm())
    {
        // Placement can have succeeded before read-back failed. Never
        // discard that leaf and claim the target has no resource boundary.
        let refusal = preparing(
            ErrorCode::MissingCapability,
            format!("target cgroup placement failed: {err}"),
        );
        return Err(started.refuse(refusal, Some(&init), &mut audit, observe_on));
    }
    let trace_data = planned
        .trace_data
        .unwrap_or(super::tracer::filter::NARROWING_TRACE_DATA);
    let observer_plan = observe_on.then(super::observed::ObserverPlan::from_env);
    let tracer = match observer_plan.as_ref() {
        Some(observer) => match attach_observer(
            observer,
            &snapshot,
            trace_data,
            launcher.pid,
            &planned.target_images,
        ) {
            Ok(tracer) => Some(tracer),
            Err(refusal) => {
                return Err(started.refuse(refusal, Some(&init), &mut audit, observe_on));
            }
        },
        None => None,
    };
    let state = RunState::new(Launched {
        launcher,
        target_images: std::mem::take(&mut planned.target_images),
        release,
        error: launcher_error,
        audit,
        observe_on,
        tracer,
        applied,
    });
    let boundary = Boundary {
        started,
        init,
        launcher_fd,
        snapshot,
        ns_ids,
        seccomp_filters,
        backend_version,
        storage,
        hard_links_denied: planned.hard_links_denied,
        resolv_sanitization: planned.resolv_sanitization,
        observer_plan,
        trace_data,
        bwrap_status: None,
        storage_lost_live: false,
    };
    Ok(Run::new(state, boundary))
}

/// The scratch directory the child sees as /tmp. A managed one is
/// supervisor state and gets the private identity; an operator's
/// `--scratch` is the operator's own directory (resolved and checked against
/// the state root at resolving), whose mode is theirs.
fn scratch_directory(snapshot: &PolicySnapshot, attempt_dir: &Path) -> Result<PathBuf, JailError> {
    match &snapshot.roots.scratch {
        ScratchRoot::Managed => {
            let scratch = attempt_dir.join("scratch");
            crate::state::create_private_dir(&scratch)?;
            Ok(scratch)
        }
        ScratchRoot::Host { path } => {
            let scratch = PathBuf::from(OsString::from_vec(path.as_bytes().to_vec()));
            ensure_dir(&scratch)?;
            Ok(scratch)
        }
    }
}

/// The attempt's execution cgroup, or why there is none when every ceiling
/// that needs one is preferred: those then run unenforced, and the record
/// says why (§6.4), in the native details and a wrapper note.
///
/// # Errors
/// A failed registration, or no leaf for a required ceiling.
fn execution_cgroup(
    snapshot: &PolicySnapshot,
    attempt_dir: &Path,
) -> Result<(Option<ExecutionCgroup>, Option<String>), JailError> {
    let required = [
        &snapshot.limits.pids,
        &snapshot.limits.mem,
        &snapshot.limits.swap,
        &snapshot.limits.cpu,
    ]
    .into_iter()
    .flatten()
    .any(|limit| limit.required);
    // N7: registered in jail state before `mkdir` and before anything is
    // placed in it; a failed registration refuses (S5).
    match ExecutionCgroup::create_for_attempt(&snapshot.limits, attempt_dir)? {
        Ok(leaf) => Ok((Some(leaf), None)),
        Err(err) if required => Err(preparing(
            ErrorCode::MissingCapability,
            format!("required execution cgroup could not be configured: {err}"),
        )),
        Err(err) => Ok((None, Some(err.to_string()))),
    }
}

/// What runs the target: the backend, this binary as the launcher, and what
/// the launcher restores before the exec.
struct Launcher<'a> {
    bwrap_path: &'a Path,
    exe: &'a Path,
    observe_on: bool,
    /// The operator's soft `RLIMIT_NOFILE`, which the target gets back.
    nofile_soft: Option<u64>,
}

/// The soft `RLIMIT_NOFILE` this process had before it raised its own: the
/// mount preparation raises it so bubblewrap can receive every pinned source
/// above it, and the launcher puts it back for the target. Read once per
/// process, at its first preparation.
fn operator_nofile_soft() -> Option<u64> {
    static SOFT: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *SOFT.get_or_init(|| crate::proxy::nofile_limits().ok().map(|(soft, _)| soft))
}

/// The mount plan and everything decided with it, before any descriptor is
/// handed over.
struct Planned {
    bplan: BwrapPlan,
    rendered: Rendered,
    scan: jfs::ProtectedScan,
    /// Held until the handoff verification just before the spawn.
    pins: Vec<jfs::PinnedPath>,
    /// The descriptors bubblewrap binds from, at their numbers.
    pinned_fds: Vec<(OwnedFd, RawFd)>,
    /// Until the spawn takes them, dropping the set removes every
    /// placeholder it made in the operator's workspace.
    placeholders: PlaceholderSet,
    staged: StagedMounts,
    filter: Program,
    filter_digest: String,
    /// Whether the installed baseline denies `link` and `linkat`, read from
    /// the program itself; the storage ceiling's evidence states it.
    hard_links_denied: bool,
    /// Audit 2026-09-25-2, S14: the narrowing filter's per-attempt
    /// `SECCOMP_RET_DATA`, with observation on; shared only with the
    /// launcher (through the trace-data pipe) and the tracer.
    trace_data: Option<u16>,
    /// The launcher's argv, by which discovery finds it.
    launcher_argv: Vec<Vec<u8>>,
    /// The paths the launcher will try to `execve`, derived from the same
    /// program name and `PATH` the launcher itself uses.
    target_images: Vec<Vec<u8>>,
    resolv_sanitization: &'static str,
    agent: Option<AgentNet>,
}

impl Planned {
    /// The plan of a contained snapshot, made concrete for this attempt:
    /// grants, staged hand-offs, the sanitized resolver, pinned sources and
    /// placeholders, the installed filter and the launcher's command line.
    fn new(
        snapshot: &PolicySnapshot,
        plan: &PreparedPlan,
        sinks: &Sinks,
        launcher: Launcher<'_>,
        scratch: &Path,
    ) -> Result<Planned, JailError> {
        let Launcher {
            bwrap_path,
            exe,
            observe_on,
            nofile_soft,
        } = launcher;
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
        let mut bplan = plan_for(
            snapshot,
            &PlanPaths {
                bwrap: bwrap_path,
                workspace: &plan.workspace,
                scratch,
                jail_exe: exe,
                proxy_dir: plan
                    .proxy
                    .as_ref()
                    .map(|handoff| handoff.host_path.as_path()),
            },
        )?;
        let mut agent = agent_network(snapshot, plan, sinks, exe, bwrap_path)?;
        if let Some(handoff) = &plan.launch
            && !handoff.vault.is_empty()
        {
            stage_vault(&mut bplan, agent.as_mut(), &plan.attempt_id, handoff)?;
        }
        // The staged vendor state and bind_ro sources, bound by the
        // descriptors staging examined (§9.1, §12).
        let staged = staged_mounts(snapshot, plan.launch.as_ref())?;
        if staged.vendor.is_some() {
            bplan.vendor_state = plan
                .launch
                .as_ref()
                .and_then(|handoff| handoff.vendor_state.as_ref())
                .map(|vendor| bwrap::Staged {
                    host: vendor.host_path.clone(),
                    fd: VENDOR_STATE_FD,
                });
        }
        bplan.credential_binds = staged
            .credentials
            .iter()
            .map(|(_, destination)| bwrap::CredentialBind {
                fd: None,
                destination: destination.clone(),
            })
            .collect();
        bind_grants(&mut bplan, snapshot, &plan.workspace, scratch)?;

        // Security 2026-09-25 (audit F5): bind a sanitized resolver view.
        // The host's `/etc/resolv.conf` can carry the operator's search
        // domains — host facts the child has no grant for. The child's
        // resolver is unreachable inside its network namespace either way;
        // the copy keeps the nameservers and drops `search`/`domain` lines.
        let (resolv_source, resolv_sanitization) = stage_sanitized_resolv_conf(&plan.attempt_dir)?;
        bplan.resolv_source = Some(resolv_source);
        refuse_pseudo_fs_sources(snapshot, &plan.workspace, &bplan)?;

        // Until the boundary owns them, every refusal drops `placeholders`,
        // which removes the directories it made in the operator's workspace.
        let (scan, pins, pinned_fds, placeholders) = prepare_mounts(
            &mut bplan,
            &plan.attempt_dir,
            &name_refs,
            snapshot.filesystem.protected_coverage,
        )?;
        // Credential views take the slots after the pins.
        let credential_base = PINNED_FD_BASE + pinned_fds.len() as RawFd;
        for (index, view) in bplan.credential_binds.iter_mut().enumerate() {
            view.fd = Some(credential_base + index as RawFd);
        }

        let (filter, hard_links_denied) = installed_filter(&bplan, agent.as_ref())?;
        let filter_digest = filter.digest();
        let target: Vec<OsString> = plan
            .argv
            .iter()
            .map(|bytes| OsString::from_vec(bytes.clone()))
            .collect();
        let trace_data = observe_on.then(random_trace_data);
        // The agent launcher mediates and starts the bridge.
        bplan.inner = super::launch::LaunchArgs {
            release_fd: RELEASE_FD,
            error_fd: ERROR_FD,
            narrow: observe_on,
            read_open_fast_path: observe_on && !snapshot.observation.learning,
            trace_data_fd: trace_data.map(|_| TRACE_DATA_FD),
            mediate: agent
                .is_some()
                .then_some((super::agent::LISTENER_FD, super::agent::SOCKDIAG_FD)),
            bridge: agent.is_some().then_some(super::agent::BRIDGE_REPORT_FD),
            // bubblewrap unblocks SIGCHLD in its child: the launcher puts
            // back the mask this supervisor inherited.
            sigmask: Some(super::launch::blocked_mask()),
            nofile_soft,
            argv: target.clone(),
        }
        .command_line(OsStr::new(bwrap::JAIL_INSIDE_PATH));
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

        // A guard: `prepare_mounts` refused before pinning anything a plan
        // whose binds no receipt can record, and nothing since adds a bind.
        // A bind added here later is still refused before the spawn.
        refuse_unrecordable_mounts(
            &bplan,
            0,
            scan.segments.len() + bplan.placeholders.len(),
            skipped_protected_names(&scan).len(),
        )?;
        let rendered = bplan.render().map_err(|err| {
            error(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                err.to_string(),
            )
        })?;
        Ok(Planned {
            bplan,
            rendered,
            scan,
            pins,
            pinned_fds,
            placeholders,
            staged,
            filter,
            filter_digest,
            hard_links_denied,
            trace_data,
            launcher_argv,
            target_images,
            resolv_sanitization,
            agent,
        })
    }

    /// §9.1 mount-handoff verification: the workspace and every pinned
    /// protected segment must still resolve to the objects that were
    /// scanned, and the backend must still be the pinned file, or the run
    /// refuses rather than bind a replacement.
    fn verify_before_spawn(&self, backend_pin: &jfs::PinnedPath) -> Result<(), JailError> {
        // A test seam: a deterministic window between pinning and this
        // verification, so the source-identity-swap refusal (F04) can be
        // proved through the CLI.
        mount_swap_rendezvous();
        for directory in &self.scan.directories {
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
        for pin in &self.pins {
            pin.verify().map_err(|err| {
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!("a protected path changed during preparation: {err}"),
                )
            })?;
        }
        Ok(())
    }
}

/// The `agent` network, prepared from the attempt's proxy directory; `None`
/// for every other profile.
///
/// # Errors
/// `agent` without a prepared proxy directory, or the network's own
/// refusal.
fn agent_network(
    snapshot: &PolicySnapshot,
    plan: &PreparedPlan,
    sinks: &Sinks,
    exe: &Path,
    bwrap_path: &Path,
) -> Result<Option<AgentNet>, JailError> {
    if snapshot.profile != ProfileName::Agent {
        return Ok(None);
    }
    let Some(handoff) = plan.proxy.as_ref() else {
        return Err(preparing(
            ErrorCode::MissingCapability,
            "the `agent` proxy could not be established: no proxy directory was prepared",
        ));
    };
    AgentNet::prepare(
        &plan.attempt_id,
        sinks.trace.clone(),
        snapshot,
        handoff,
        exe,
        bwrap_path,
    )
    .map(Some)
}

/// Stages the vault's public CA in the vendor state, binds it read-only and
/// points the CA variables at it, and hands the vault to the `agent` proxy.
///
/// # Errors
/// A vault that cannot be built or staged, or no `agent` network to run it.
fn stage_vault(
    bplan: &mut BwrapPlan,
    agent: Option<&mut AgentNet>,
    attempt_id: &str,
    handoff: &crate::credentials::LaunchHandoff,
) -> Result<(), JailError> {
    let vault_io = |e| {
        preparing(
            ErrorCode::CredentialUnavailable,
            format!("vault public CA cannot be staged: {e}"),
        )
    };
    let vault = std::sync::Arc::new(
        crate::vault::Vault::new(attempt_id, handoff.vault.clone())
            .map_err(|e| preparing(ErrorCode::CredentialUnavailable, e))?,
    );
    let vendor = handoff
        .vendor_state
        .as_ref()
        .ok_or_else(|| preparing(ErrorCode::InternalError, "vault has no private state"))?;
    let dir = crate::state::anchored::Dir::from_owned(
        vendor.fd.as_fd().try_clone_to_owned().map_err(vault_io)?,
    );
    let name = crate::state::anchored::Name::new(b".ouro-vault-ca.pem").map_err(vault_io)?;
    let mut cert = dir.create_file_at(&name, 0o600).map_err(vault_io)?;
    std::io::Write::write_all(&mut cert, vault.ca_pem().as_bytes()).map_err(vault_io)?;
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
        .ok_or_else(|| preparing(ErrorCode::InvalidConfig, "vault requires agent network"))?
        .configure_vault(vault);
    Ok(())
}

/// Operator grants are enforced, not merely recorded (I02, north-star §4.2):
/// read-only grants become additional ro-binds at their resolved paths,
/// host-rooted writable grants become binds, and denied paths are masked
/// with a sealed directory or file. A writable grant inside the writable
/// workspace or the scratch is covered by their base binds already; a
/// read-only grant there is layered over them.
///
/// # Errors
/// A grant that does not resolve, a device granted read-only, or a denied
/// path that cannot be classified.
fn bind_grants(
    bplan: &mut BwrapPlan,
    snapshot: &PolicySnapshot,
    workspace: &Path,
    scratch: &Path,
) -> Result<(), JailError> {
    for reference in &snapshot.filesystem.read_write {
        if let Ok(host) = host_path_of(reference, workspace, scratch) {
            // Issue draft 15: an allowlisted device node (the NVIDIA class)
            // binds individually with `--dev-bind`, never as a devtmpfs
            // surface.
            if is_allowed_device_node(&host) {
                let destination = resolve_path_ref(reference, workspace)?;
                bplan
                    .extra_dev_binds
                    .push((host, PathBuf::from(destination)));
                continue;
            }
            if (bplan.workspace_access == bwrap::WorkspaceAccess::Writable
                && host.starts_with(workspace))
                || host.starts_with(scratch)
            {
                // Inside a base writable bind already; layering an extra
                // bind of the same content would add nothing.
                continue;
            }
            let destination = resolve_path_ref(reference, workspace)?;
            bplan
                .extra_rw_binds
                .push((host, PathBuf::from(destination)));
        }
    }
    for reference in &snapshot.filesystem.read_only {
        if let Ok(host) = host_path_of(reference, workspace, scratch) {
            // The runtime plan already renders merged-/usr aliases as
            // symlinks and pins their real roots. Do not reopen /bin or
            // /lib as an operator bind (or mount over those aliases).
            // Baseline runtime candidates are optional distribution paths:
            // ARM64 Debian, for example, has /lib but no /lib64. BwrapPlan
            // already discovers and records the roots that exist. Do not
            // turn an absent default into a required bind. Errors other
            // than absence still reach pinning and refuse.
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
                        "the device grant {} binds only read-write (--rw): bubblewrap has no \
                         read-only device bind",
                        host.display()
                    ),
                ));
            }
            let destination = resolve_path_ref(reference, workspace)?;
            bplan
                .extra_ro_binds
                .push((host, PathBuf::from(destination)));
        }
    }
    for reference in &snapshot.filesystem.deny_read {
        let destination = resolve_path_ref(reference, workspace)?;
        let path = PathBuf::from(destination);
        // Classification changes only the overlay's type, never grants
        // access to the denied object. A type swap before mounting fails
        // setup rather than releasing an unmasked target.
        let host = host_path_of(reference, workspace, scratch)?;
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
    Ok(())
}

/// §9.1: an operator grant may not expose host /proc, /sys or cgroupfs.
/// Checked before any mount, on the resolved source by filesystem type and
/// mount topology (never by spelling), so it refuses before exec. The
/// baseline runtime roots are on the root filesystem and pass; the child's
/// private /proc and /dev are made by bubblewrap, not bound from these
/// sources.
fn refuse_pseudo_fs_sources(
    snapshot: &PolicySnapshot,
    workspace: &Path,
    bplan: &BwrapPlan,
) -> Result<(), JailError> {
    refuse_pseudo_fs_grants(
        &[(workspace.to_path_buf(), workspace.to_path_buf())],
        "workspace",
    )?;
    if let ScratchRoot::Host { path } = &snapshot.roots.scratch {
        let source = PathBuf::from(OsString::from_vec(path.as_bytes().to_vec()));
        refuse_pseudo_fs_grants(&[(source.clone(), source)], "scratch")?;
    }
    refuse_pseudo_fs_grants(&bplan.extra_ro_binds, "filesystem.read_only")?;
    refuse_pseudo_fs_grants(&bplan.extra_rw_binds, "filesystem.read_write")
}

/// The baseline bubblewrap installs and whether it denies hard links. A
/// storage ceiling rests on a filter that denies new mounts, which the
/// `NamespaceInner` agent variant permits, and on the hard-link denials (a
/// link could charge a foreign inode to the bounded tree); both are read
/// from the program that is installed, so neither can claim a rule it lacks.
/// `agent` installs the baseline its network built once, in the variant the
/// measured nested-namespace capability selected (§9.2), so the digest its
/// receipt detail names is the digest of what runs.
///
/// # Errors
/// A storage ceiling the variant cannot hold, or a filter that cannot be
/// built or read.
fn installed_filter(
    bplan: &BwrapPlan,
    agent: Option<&AgentNet>,
) -> Result<(Program, bool), JailError> {
    if bplan.bounded_storage
        && agent.is_some_and(|agent| agent.variant() == seccomp::AgentVariant::NamespaceInner)
    {
        return Err(preparing(
            ErrorCode::MissingCapability,
            "storage ceilings require a profile that cannot create new mounts",
        ));
    }
    let filter = match agent {
        Some(agent) => agent.baseline().clone(),
        None => seccomp::tool_baseline_with_storage(bplan.bounded_storage).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the syscall filter could not be built: {err}"),
            )
        })?,
    };
    let variant = agent.map(AgentNet::variant);
    match installed_hard_link_rule(&filter, variant) {
        Ok(denied) if denied == bplan.bounded_storage => Ok((filter, denied)),
        Ok(denied) => Err(preparing(
            ErrorCode::InternalError,
            format!(
                "the syscall filter {} hard links while a storage ceiling is {}",
                if denied { "denies" } else { "permits" },
                if denied { "not requested" } else { "requested" }
            ),
        )),
        Err(reason) => Err(preparing(
            ErrorCode::InternalError,
            format!("the syscall filter's hard-link rule cannot be read: {reason}"),
        )),
    }
}

/// §8.2: a wait that the preparation budget ended (the watcher's readiness,
/// the arguments' write) refuses as the budget's timeout, with remediation
/// `retry`, not as a host failure of the step that happened to be waiting.
fn channel_failure(err: std::io::Error) -> JailError {
    if err.kind() == std::io::ErrorKind::TimedOut {
        return prepare_timeout(&format!(
            "preparation did not complete within its budget: {err}"
        ));
    }
    preparing(
        ErrorCode::BackendUnavailable,
        format!("the boundary's channels could not be created: {err}"),
    )
}

/// The backend's descriptor map and this side of each channel.
struct Channels {
    fds: FdMap,
    /// The release pipe's write end, which the run writes the release to.
    release: OwnedFd,
    /// The launcher's error pipe, non-blocking.
    error: OwnedFd,
    /// bubblewrap's JSON status, non-blocking.
    status: OwnedFd,
    /// The bootstrap's start pipe, written once the watcher is ready.
    start: OwnedFd,
    /// The `--args` payload's write end, when the options go by descriptor.
    args: Option<OwnedFd>,
}

impl Channels {
    /// Opens every channel at its fixed number in the backend's map
    /// (§8.3), and moves the pinned sources and staged descriptors into it.
    fn open(planned: &mut Planned, backend_pin: &jfs::PinnedPath) -> Result<Channels, JailError> {
        // Room for the credential views after the pins.
        let mut fds = FdMap::with_target_limit(
            PINNED_FD_BASE
                + planned.pinned_fds.len() as RawFd
                + planned.staged.credentials.len() as RawFd,
        );
        let io = channel_failure;
        fds.add(
            seccomp::program_pipe(&planned.filter).map_err(io)?,
            SECCOMP_FD,
        )
        .map_err(io)?;
        let (release_r, release_w) = exec::pipe().map_err(io)?;
        let (error_r, error_w) = exec::pipe().map_err(io)?;
        let (status_r, status_w) = exec::pipe().map_err(io)?;
        let (start_r, start_w) = exec::pipe().map_err(io)?;
        fds.add(start_r, watch::START_FD).map_err(io)?;
        fds.add(
            backend_pin.borrow_fd().try_clone_to_owned().map_err(io)?,
            watch::BACKEND_FD,
        )
        .map_err(io)?;
        fds.add(release_r, RELEASE_FD).map_err(io)?;
        fds.add(error_w, ERROR_FD).map_err(io)?;
        // Audit 2026-09-25-2, S14: the narrowing data is already in the pipe
        // before the spawn, so the launcher's blocking read always
        // completes; the descriptor closes in the launcher and never
        // reaches the target.
        if let Some(data) = planned.trace_data {
            let (trace_r, trace_w) = exec::pipe().map_err(io)?;
            // Two bytes always fit the pipe's capacity, so the write
            // completes before any reader exists.
            write_all(trace_w.as_raw_fd(), &super::sys::trace_data_bytes(data)).map_err(io)?;
            fds.add(trace_r, TRACE_DATA_FD).map_err(io)?;
        }
        fds.add(status_w, STATUS_FD).map_err(io)?;
        for (copy, target) in std::mem::take(&mut planned.pinned_fds) {
            fds.add(copy, target).map_err(io)?;
        }
        // Hand the staged descriptors to bubblewrap.
        if let Some(vendor) = planned.staged.vendor.take() {
            fds.add(vendor, VENDOR_STATE_FD).map_err(io)?;
        }
        // The proxy directory, bound read-only by descriptor.
        if let Some(agent) = planned.agent.as_ref() {
            fds.add(agent.dir_fd().map_err(io)?, super::agent::PROXY_DIR_FD)
                .map_err(io)?;
        }
        let credentials = std::mem::take(&mut planned.staged.credentials);
        for ((source, _), view) in credentials.into_iter().zip(&planned.bplan.credential_binds) {
            let Some(target) = view.fd else {
                return Err(preparing(
                    ErrorCode::InternalError,
                    "a credential view has no descriptor slot",
                ));
            };
            fds.add(source, target).map_err(io)?;
        }
        // jail-v1 §2 I07 (every wait bounded): the `--args` payload can
        // exceed the pipe's capacity, so it is written while the reader
        // exists, after the spawn: bwrap blocks reading ARGS_FD, and if it
        // dies before consuming the payload the write fails with EPIPE
        // instead of hanging. `exec::pipe` is close-on-exec on both ends, so
        // the parent's write end never reaches bwrap and its EOF is seen as
        // soon as this side closes.
        let mut args = None;
        if planned.rendered.args_payload.is_some() {
            let (args_r, args_w) = exec::pipe().map_err(io)?;
            fds.add(args_r, ARGS_FD).map_err(io)?;
            args = Some(args_w);
        }
        set_nonblocking(error_r.as_raw_fd()).map_err(io)?;
        set_nonblocking(status_r.as_raw_fd()).map_err(io)?;
        Ok(Channels {
            fds,
            release: release_w,
            error: error_r,
            status: status_r,
            start: start_w,
            args,
        })
    }
}

/// §8.3: stdio passes through without capture except regular files and
/// sockets, which are relayed through supervisor-owned pipes (audit
/// 2026-10-08 H1): the child gets a pipe end here and never the file, so no
/// `/dev/stdin` reopen can reach the host mount. Every other descriptor the
/// supervisor holds is closed on exec.
fn attach_stdio(plans: [StdioPlan; 3], fds: &mut FdMap) -> Result<Vec<StdioRelay>, JailError> {
    let mut relays = Vec::new();
    for (fd, plan) in plans.into_iter().enumerate() {
        if let StdioPlan::Relay { socket } = plan {
            relays.push(StdioRelay::attach(
                i32::try_from(fd).unwrap_or(-1),
                fd == 0,
                socket,
                fds,
            )?);
        }
    }
    Ok(relays)
}

/// Starts the backend through the trusted bootstrap, in the attempt's leaf
/// when there is one, starts the outside watcher, releases the bootstrap and
/// streams the backend's options: the [`Started`] boundary, the release
/// pipe's write end and the launcher's error pipe.
///
/// Until the boundary owns it, a refusal here kills and reaps the backend
/// within a fresh tree budget ([`exec::KillOnDrop`]; §8.1: a pre-exec
/// failure refuses and leaves no orphan), and the placeholders stay with
/// `planned`, which removes them when it is dropped.
fn spawn(
    exe: &Path,
    planned: &mut Planned,
    channels: Channels,
    stdio_relays: Vec<StdioRelay>,
    (cgroup, cgroup_unavailable): (Option<ExecutionCgroup>, Option<String>),
    deadline: clock::Deadline,
) -> Result<(Started, OwnedFd, ErrorPipe), JailError> {
    let io = channel_failure;
    let Channels {
        fds,
        release,
        error,
        status,
        start,
        args,
    } = channels;
    let arguments: Vec<OsString> = std::iter::once(OsString::from("__backend"))
        .chain(planned.rendered.argv.iter().cloned())
        .collect();
    let spawn_cgroup = cgroup
        .as_ref()
        .map(ExecutionCgroup::spawn_handle)
        .transpose()
        .map_err(io)?;
    let child = exec::spawn_bootstrap(exe, &arguments, &fds, spawn_cgroup.as_ref(), deadline)
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
    let child = exec::KillOnDrop::new(child);
    let bootstrap_spawn = child.spawn();
    // In particular close our duplicate of ARGS_FD before streaming: if the
    // backend exits there must be no reader left to suppress EPIPE.
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
    let watcher = Watcher::start(exe, bwrap_pid, cgroup_kill, deadline).map_err(io)?;
    write_all(start.as_raw_fd(), &[watch::RELEASED]).map_err(io)?;
    drop(start);
    // The payload write happens with bwrap already blocked on ARGS_FD, so a
    // payload larger than the pipe's capacity flows through instead of
    // deadlocking. A failure here means bwrap died reading.
    if let (Some(args), Some(payload)) = (args.as_ref(), planned.rendered.args_payload.as_ref()) {
        write_until(args.as_raw_fd(), payload, deadline).map_err(io)?;
    }
    drop(args);
    let started = Started {
        child: Some(child.hand_over()),
        bootstrap_spawn,
        bwrap_pid,
        bwrap_fd,
        status: StatusReader::new(status),
        watcher,
        cgroup,
        cgroup_lost: false,
        cgroup_unavailable,
        placeholders: std::mem::take(&mut planned.placeholders).hand_over(),
        placeholder_outcomes: Vec::new(),
        agent: planned.agent.take(),
        stdio_relays,
        killing: AtomicBool::new(false),
    };
    Ok((started, release, ErrorPipe::new(error)))
}

/// The observer, attached to the blocked launcher (§11.4): with the bounds
/// of its plan, the attempt's trace data and the operator's command rules.
///
/// # Errors
/// Rules that no longer compile, or an observer that cannot attach: both
/// refuse before exec, whatever the evidence mode says.
fn attach_observer(
    plan: &super::observed::ObserverPlan,
    snapshot: &PolicySnapshot,
    trace_data: u16,
    launcher: libc::pid_t,
    target_images: &[Vec<u8>],
) -> Result<Tracer, JailError> {
    // §13.1: gap intervals count from supervisor start on the same
    // CLOCK_BOOTTIME base as every other monotonic_ns. §11.4: the bounds are
    // the plan's, which the receipt records.
    let mut config = plan.tracer_config(clock::mark_supervisor_start());
    // Audit 2026-09-25-2, S14: the tracer expects exactly the data this
    // attempt's narrowing filter carries.
    config.trace_data = trace_data;
    config.learning = snapshot.observation.learning;
    // Resolution validated these rules; rules that no longer compile are
    // refused, never matched in part.
    config.commands = snapshot.commands.compile().map_err(|reason| {
        error(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            format!("the command rules do not compile: {reason}"),
        )
        .with_key_path("jail.commands")
    })?;
    config.target = Some((launcher, target_images.to_vec()));
    Tracer::attach(launcher, config).map_err(|err| {
        error(
            ErrorCode::ObserverUnavailable,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            format!("the closed-set observer could not attach: {err}"),
        )
    })
}

/// What discovery reads besides the started boundary.
struct DiscoveryInputs<'a> {
    bwrap_path: &'a Path,
    deadline: clock::Deadline,
    snapshot: &'a PolicySnapshot,
    workspace: &'a Path,
    launcher_argv: &'a [Vec<u8>],
    filter_digest: &'a str,
    scan: &'a jfs::ProtectedScan,
    observe_on: bool,
}

/// The namespace init and the blocked launcher, and what the boundary
/// actually applied, all read back.
struct Discovered {
    init: Init,
    launcher: identity::ProcessIdentity,
    /// The launcher's own descriptor, for the cooperative stop and the
    /// `agent` mediation hand-off.
    launcher_fd: OwnedFd,
    ns_ids: identity::NsIds,
    /// `Seccomp_filters` of the blocked launcher, checked against what this
    /// boundary installs.
    seccomp_filters: u32,
    /// What the backend reported, read again for this attempt; `None` when it
    /// could not be asked.
    backend_version: Option<String>,
    storage: Option<super::storage::Storage>,
    applied: Applied,
}

/// A refused discovery, with the init when bubblewrap had named one: the
/// teardown kills and waits for it.
struct Refused {
    error: JailError,
    init: Option<Init>,
}

/// Finds the namespace init and the launcher, and reads back what the
/// boundary actually applied.
fn discover(
    started: &mut Started,
    launcher_error: &mut ErrorPipe,
    inputs: &DiscoveryInputs<'_>,
) -> Result<Discovered, Refused> {
    let init =
        find_init(started, inputs.deadline).map_err(|error| Refused { error, init: None })?;
    match read_back(started, launcher_error, &init, inputs) {
        Ok(found) => Ok(found.with_init(init)),
        Err(error) => Err(Refused {
            error,
            init: Some(init),
        }),
    }
}

/// bubblewrap reports the namespace init's host pid as soon as the
/// namespaces exist. Waiting on that document is the synchronisation point;
/// nothing here guesses a delay.
fn find_init(started: &mut Started, deadline: clock::Deadline) -> Result<Init, JailError> {
    let pid = loop {
        started.status.pump();
        if let Some(pid) = started.status.parsed().child_pid {
            break pid;
        }
        if started.status.eof || started.exited() {
            let diagnostic = started.diagnostic().trim().to_owned();
            let detail = if diagnostic.is_empty() {
                // bwrap's own message (for example "Unknown option") went to
                // this console's stderr, which the supervisor passes through
                // untouched; the error must still say something useful
                // instead of ending on a colon.
                let status = started
                    .child
                    .as_mut()
                    .and_then(|child| child.try_wait().ok().flatten())
                    .and_then(|wait| wait.code().map(|code| format!("exit {code}")))
                    .unwrap_or_else(|| "no wait status".to_owned());
                format!(
                    "bubblewrap exited during setup ({status}) without a status document; its \
                     own stderr on this console names the cause"
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
    // Taken now, while the kernel has just named this pid as the namespace
    // init. Without it the tree's death could not be verified, so its
    // absence refuses.
    let fd = identity::pidfd_open(pid).map_err(|err| {
        preparing(
            ErrorCode::BackendUnavailable,
            format!("the namespace init's pidfd could not be opened: {err}"),
        )
    })?;
    Ok(Init { pid, fd })
}

/// [`Discovered`] before the init joins it.
struct ReadBack {
    launcher: identity::ProcessIdentity,
    launcher_fd: OwnedFd,
    ns_ids: identity::NsIds,
    seccomp_filters: u32,
    backend_version: Option<String>,
    storage: Option<super::storage::Storage>,
    applied: Applied,
}

impl ReadBack {
    fn with_init(self, init: Init) -> Discovered {
        Discovered {
            init,
            launcher: self.launcher,
            launcher_fd: self.launcher_fd,
            ns_ids: self.ns_ids,
            seccomp_filters: self.seccomp_filters,
            backend_version: self.backend_version,
            storage: self.storage,
            applied: self.applied,
        }
    }
}

/// The refusal for a backend that ended before the launcher blocked. The
/// agent launcher's own setup failures carry their exit status and errno, so
/// the refusal names the mechanism that could not be established instead of
/// a generic backend failure.
fn launcher_setup_failure(started: &mut Started, launcher_error: &mut ErrorPipe) -> JailError {
    started.status.pump();
    launcher_error.drain();
    launcher_failure(
        started.status.parsed().exit_code,
        &launcher_error.bytes,
        started.diagnostic().trim(),
    )
}

/// The launcher found under the init, blocked on its release pipe, and the
/// boundary read back from it.
fn read_back(
    started: &mut Started,
    launcher_error: &mut ErrorPipe,
    init: &Init,
    inputs: &DiscoveryInputs<'_>,
) -> Result<ReadBack, JailError> {
    let deadline = inputs.deadline;
    let launcher = find_blocked_launcher(started, launcher_error, init, inputs)?;
    let identity = identity::ProcessIdentity::capture(launcher).map_err(|err| {
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
    let ns_ids = launcher_namespaces(launcher, &started.status)?;
    let seccomp_filters = launcher_privilege(launcher, started.agent.is_some(), inputs.observe_on)?;
    if let Some(agent) = started.agent.as_mut() {
        connect_agent(
            agent,
            started.cgroup.as_ref(),
            init,
            &launcher_fd,
            ns_ids,
            deadline,
        )?;
    }
    // Keep this fresh readback: a process can create a new platform after
    // a backend upgrade, while its minimum-version decision is cached.
    let backend_version = bwrap::bwrap_version(inputs.bwrap_path, deadline)
        .ok()
        .map(|version| version.raw);

    let storage = if super::storage::requested(&inputs.snapshot.limits) {
        Some(
            super::storage::Storage::admit(launcher, &inputs.snapshot.limits, deadline).map_err(
                |err| {
                    preparing(
                        ErrorCode::MissingCapability,
                        format!("storage ceiling unavailable: {err}"),
                    )
                },
            )?,
        )
    } else {
        None
    };
    let applied = read_applied(
        launcher,
        inputs,
        storage.as_ref(),
        started.cgroup.as_ref(),
        started.agent.as_ref(),
    )?;
    Ok(ReadBack {
        launcher: identity,
        launcher_fd,
        ns_ids,
        seccomp_filters,
        backend_version,
        storage,
        applied,
    })
}

/// The launcher: the init's child whose argv is the one asked for, once it
/// is blocked on its release pipe.
fn find_blocked_launcher(
    started: &mut Started,
    launcher_error: &mut ErrorPipe,
    init: &Init,
    inputs: &DiscoveryInputs<'_>,
) -> Result<libc::pid_t, JailError> {
    let deadline = inputs.deadline;
    // The launcher is the init's child whose argv is the one we asked for.
    let launcher = loop {
        if let Some(pid) = super::tracer::children(init.pid)
            .into_iter()
            .find(|pid| super::tracer::cmdline(*pid).as_deref() == Some(inputs.launcher_argv))
        {
            break pid;
        }
        if deadline.expired() {
            return Err(prepare_timeout("the inside launcher never appeared"));
        }
        if started.exited() {
            return Err(launcher_setup_failure(started, launcher_error));
        }
        nap();
    };

    // Wait until it is blocked in read(2) on its release descriptor, which
    // is what the observer's attach contract requires. `/proc/<pid>/syscall`
    // names the call and its first argument, so this is a read-back and not
    // an assumption. The descriptor is part of the check: the launcher reads
    // its trace-data descriptor before it installs the narrowing filter, and
    // that read is not the gate.
    loop {
        if matches!(identity::blocked_in_read(launcher, RELEASE_FD), Ok(true)) {
            break;
        }
        if deadline.expired() {
            return Err(prepare_timeout(
                "the inside launcher did not block on its release pipe",
            ));
        }
        if started.exited() {
            return Err(launcher_setup_failure(started, launcher_error));
        }
        nap();
    }

    Ok(launcher)
}

/// The launcher's namespaces, each one the plan asked for and none this
/// process's own, and agreeing with what bubblewrap reports.
fn launcher_namespaces(
    launcher: libc::pid_t,
    status: &StatusReader,
) -> Result<identity::NsIds, JailError> {
    // bubblewrap reports the namespace ids it created; `/proc` says which
    // namespaces the launcher is actually in. Recording the first without
    // checking the second would be taking the backend's word for the
    // boundary, so both are read and they must agree.
    let ns_ids = identity::ns_ids(launcher);
    // Every namespace the plan asked for has to be one the launcher is
    // actually in, and a different one from this process's.
    // SAFETY: getpid takes no arguments and cannot fail.
    let own = identity::ns_ids(unsafe { libc::getpid() });
    for (name, inside, outside) in [
        ("pid", ns_ids.pid, own.pid),
        ("mnt", ns_ids.mnt, own.mnt),
        ("net", ns_ids.net, own.net),
        ("user", ns_ids.user, own.user),
        ("cgroup", ns_ids.cgroup, own.cgroup),
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
    let status = status.parsed();
    for (key, reported, seen) in [
        ("pid-namespace", status.pid_namespace, ns_ids.pid),
        ("mnt-namespace", status.mnt_namespace, ns_ids.mnt),
        ("net-namespace", status.net_namespace, ns_ids.net),
    ] {
        if let (Some(reported), Some(seen)) = (reported, seen)
            && reported != seen
        {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("the backend reports {key} {reported} but the launcher is in {seen}"),
            ));
        }
    }

    Ok(ns_ids)
}

/// The launcher's privilege, read back: no new privileges, no capability,
/// every filter this boundary installs in force and inside a pid namespace;
/// the number of filters it found.
fn launcher_privilege(
    launcher: libc::pid_t,
    agent: bool,
    observe_on: bool,
) -> Result<u32, JailError> {
    // Read back the boundary rather than trusting the flags we passed. The
    // launcher is blocked: these facts come from one kernel status snapshot
    // rather than reopening the same file for every field.
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
    // `Seccomp: 2` says a filter is in force, not that every filter this
    // boundary installs is: a missing narrowing or mediation filter leaves
    // the mode at 2. The count is read back and must be exactly the number
    // installed.
    let expected = super::agent::expected_launcher_filters(agent, observe_on);
    let seccomp_filters = super::agent::verify_filter_count(
        privilege.seccomp_filters.as_deref().unwrap_or_default(),
        expected,
    )
    .map_err(|mut error| {
        error.message = format!("the launcher: {}", error.message);
        error
    })?;
    let nspid = super::tracer::nspid(launcher).unwrap_or_default();
    if nspid.len() < 2 {
        return Err(preparing(
            ErrorCode::BackendUnavailable,
            format!("the launcher is not inside a pid namespace: NSpid {nspid:?}"),
        ));
    }

    Ok(seccomp_filters)
}

/// While the launcher is blocked, takes its mediation listener and
/// sock_diag socket, starts the mediator, and reads back the bridge it
/// started (§10). Either one missing refuses, naming it.
fn connect_agent(
    agent: &mut AgentNet,
    cgroup: Option<&ExecutionCgroup>,
    init: &Init,
    launcher_fd: &OwnedFd,
    ns_ids: identity::NsIds,
    deadline: clock::Deadline,
) -> Result<(), JailError> {
    agent.take_mediation(launcher_fd.as_fd())?;
    let bridge = agent.discover_bridge(init.pid, ns_ids, &deadline)?;
    if let Some(leaf) = cgroup {
        // Charged to the attempt (§9.3): the bridge is in the leaf.
        leaf.verify_member(bridge).map_err(|err| {
            preparing(
                ErrorCode::MissingCapability,
                format!(
                    "the `agent` bridge could not be established: it is not in the attempt's \
                     cgroup: {err}"
                ),
            )
        })?;
    }
    Ok(())
}

/// The `applied` group, read back from the boundary that exists. A read-back
/// that fails refuses: an empty mount table or environment in the receipt
/// would be a claim about the child's view nothing measured.
fn read_applied(
    launcher: libc::pid_t,
    inputs: &DiscoveryInputs<'_>,
    storage: Option<&super::storage::Storage>,
    cgroup: Option<&ExecutionCgroup>,
    agent: Option<&AgentNet>,
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
    if let Some(storage) = storage {
        limits.extend(storage.limits());
    }
    limits.extend(ceiling_rows(&inputs.snapshot.limits, cgroup));
    let mut mounts = mounts;
    // A protected name the walk refused to follow is authority this plan did
    // not apply. The mount table is where §13.2 lists what the child's view
    // is, and `hidden` is the mode the schema has for a path that is named
    // and not granted, so each one appears there rather than being left out
    // of the record entirely.
    for name in skipped_protected_names(inputs.scan) {
        let path = workspace_bytes_joined(inputs.workspace, &name);
        if let Ok(native) = NativeString::from_bytes(path) {
            mounts.push(AppliedMount {
                path: native,
                mode: "hidden".to_owned(),
            });
        }
    }
    let mounts = recordable_mounts(mounts)?;
    Ok(Applied {
        filesystem: Some(AppliedFilesystem {
            mechanism: "bubblewrap-binds".to_owned(),
            protected_coverage: if inputs.snapshot.filesystem.protected_coverage
                == ProtectedCoverage::None
            {
                // Audit 2026-09-25-2, S5: nothing was requested or scanned,
                // so the walk's vacuous pass must not be reported as
                // existing-and-covered.
                "none".to_owned()
            } else {
                scan_coverage(inputs.scan)
            },
            mounts,
        }),
        // The agent network and its two stacked filters.
        network: agent.map_or_else(
            || AppliedNetwork {
                mode: "none".to_owned(),
                mechanism: Some("network-namespace".to_owned()),
                allowed_hosts: Vec::new(),
                tls_only: Vec::new(),
            },
            AgentNet::applied_network,
        ),
        syscalls: Some(AppliedSyscalls {
            mechanism: if agent.is_some() {
                "seccomp-bpf+seccomp-user-notification".to_owned()
            } else {
                "seccomp-bpf".to_owned()
            },
            digest: inputs.filter_digest.to_owned(),
        }),
        limits,
        environment_names,
        removed_environment_names: Vec::new(),
    })
}

/// A workspace-relative name as the absolute bytes the child sees.
fn workspace_bytes_joined(workspace: &Path, relative: &str) -> Vec<u8> {
    let mut out = workspace.as_os_str().as_bytes().to_vec();
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(relative.as_bytes());
    out
}

/// The contained boundary, as the run drives it: what the spawn started,
/// and what discovery read back.
pub(super) struct Boundary {
    started: Started,
    init: Init,
    /// The launcher's own descriptor, for the cooperative stop.
    launcher_fd: OwnedFd,
    snapshot: PolicySnapshot,
    ns_ids: identity::NsIds,
    /// `Seccomp_filters` of the blocked launcher, read back and checked
    /// against what this boundary installs.
    seccomp_filters: u32,
    /// What the backend reported, read again for this attempt; `None` when
    /// it could not be asked.
    backend_version: Option<String>,
    storage: Option<super::storage::Storage>,
    /// Whether the installed baseline denies `link` and `linkat`, read from
    /// the program itself; the storage ceiling's evidence states it.
    hard_links_denied: bool,
    resolv_sanitization: &'static str,
    /// The §11.4 bounds the observer runs with, decided once; `None` with
    /// observation off.
    observer_plan: Option<super::observed::ObserverPlan>,
    /// Audit 2026-09-25-2, S14: the narrowing filter's per-attempt
    /// `SECCOMP_RET_DATA`.
    trace_data: u16,
    /// bubblewrap's raw wait status, once collected (from the observer, or
    /// with observation off from this process's own wait).
    bwrap_status: Option<i32>,
    /// Audit 2026-10-08 L2: storage enforcement was found lost while the
    /// target still ran — the only timing that may make it `outcome.cause`
    /// (§6.4). A loss first seen after the target's own end never does.
    storage_lost_live: bool,
}

impl Boundary {
    /// Mediated connects and helper facts, while the target runs; the reason
    /// of a new evidence loss, when there is one.
    fn pump_agent(&mut self, run: &mut RunState) -> Option<String> {
        let (init, killing) = (&self.init, &self.started.killing);
        // Asked only once the bridge is seen dead: the boundary was up after
        // the bridge died, so the bridge did not die with it. A namespace
        // init sets PF_EXITING before it kills its namespace, and this
        // supervisor sets `killing` before it kills anything.
        let boundary_up = || {
            super::agent::boundary_up(killing.load(Ordering::SeqCst), &|| !init.alive(), &|| {
                identity::exiting(init.pid)
            })
        };
        let agent = self.started.agent.as_mut()?;
        agent.pump(&mut run.audit, run.observe_on, &boundary_up)
    }

    /// bubblewrap's status document, and with observation off its exit,
    /// which is then the only fact about the target's end.
    fn pump_status(&mut self, run: &RunState) {
        self.started.status.pump();
        if run.tracer.is_some() {
            return;
        }
        if let Some(child) = self.started.child.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            use std::os::unix::process::ExitStatusExt as _;
            self.bwrap_status = Some(status.into_raw());
        }
    }

    /// Moves relayed stdio while the run is live (audit 2026-10-08 H1);
    /// `true` while a relay made progress.
    fn pump_stdio(&mut self, run: &mut RunState) -> bool {
        match pump_stdio_relays(&mut self.started.stdio_relays) {
            Ok(active) => active,
            Err(err) => {
                run.pending.push_back(RunEvent::StdioFailed {
                    reason: format!("a stdio relay failed: {err}"),
                    after_target_end: self.target_ended(run),
                });
                // Failed streams cannot deliver more. Close them once and let
                // the supervisor record the error and stop a live tree.
                self.started.stdio_relays.clear();
                false
            }
        }
    }

    /// Whether the target's end is known: the observer reported it, or the
    /// backend's status was collected.
    fn target_ended(&self, run: &RunState) -> bool {
        run.target_exit_seen || self.bwrap_status.is_some()
    }

    fn stop_agent(&mut self, run: &mut RunState, budget: Duration) {
        self.started
            .stop_agent(&mut run.audit, run.observe_on, budget);
    }

    /// Whether the tree's death can still be shown: the observer's account
    /// does not object and the leaf's identity was never lost.
    fn tree_death_provable(&self, run: &RunState) -> bool {
        observer_verdict(run.tracer_summary.as_ref()) && !self.started.cgroup_lost
    }

    /// Whether the tree is seen dead now: the namespace init has ended and
    /// the leaf, when there is one, is unpopulated.
    fn tree_dead(&self) -> bool {
        !self.init.alive() && self.started.cgroup_empty()
    }

    fn remove_placeholders(&mut self, run: &RunState) {
        if !(self.tree_death_provable(run) && self.tree_dead()) {
            return;
        }
        if self.started.placeholder_outcomes.is_empty() {
            self.started.placeholder_outcomes = self
                .started
                .placeholders
                .iter()
                .map(Placeholder::remove_if_unchanged)
                .collect();
        }
    }

    fn status_outcome(&self, bwrap_status: i32) -> RunEvent {
        let code = self
            .started
            .status
            .parsed()
            .exit_code
            .or_else(|| libc::WIFEXITED(bwrap_status).then(|| libc::WEXITSTATUS(bwrap_status)));
        match code {
            // Measured on bubblewrap 0.11.1: a child killed by a signal is
            // reported as 128 + signal, indistinguishable from an exit with
            // that code. Without an observer the two cannot be told apart,
            // so the ambiguous range stays unknown rather than being claimed.
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

/// What the backend's end says when the observer reported no final status:
/// a failed exec's errno first; then, when nothing confirmed the exec,
/// ExecUnconfirmed without an observer (§6.4) — with one attached, its end
/// without having witnessed the exec is an unknown, not the observation-off
/// error; otherwise the backend's own report.
fn backend_outcome(
    exec_confirmed: bool,
    observer_attached: bool,
    error_bytes: &[u8],
    outcome: impl FnOnce() -> RunEvent,
) -> RunEvent {
    if !error_bytes.is_empty() {
        let (errno, detail) = super::launch::exec_failure_parts(error_bytes);
        return RunEvent::ExecError { errno, detail };
    }
    if !exec_confirmed {
        if observer_attached {
            return RunEvent::Unknown {
                reason: "the observer ended without witnessing the target's exec".to_owned(),
            };
        }
        return RunEvent::ExecUnconfirmed {
            reason: "the backend ended without independent evidence of target exec".to_owned(),
        };
    }
    outcome()
}

impl Tree for Boundary {
    fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    fn boundary_identity(&self, run: &RunState) -> BoundaryIdentity {
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
        details.insert(
            "watcher_pid".to_owned(),
            Value::from(self.started.watcher.pid()),
        );
        // J4 autoscope: §9.3 — where the supervisor stood when the leaf was
        // made: already delegated, entered a scope of its own, or why not.
        details.insert("supervisor_scope".to_owned(), super::scope::details());
        details.insert(
            "bootstrap_spawn".to_owned(),
            self.started.bootstrap_spawn.evidence(),
        );
        details.insert(
            "execution_cgroup".to_owned(),
            match &self.started.cgroup {
                // The bridge is a helper charged to the leaf
                Some(leaf) => {
                    let mut registration = leaf.registration(self.started.bwrap_pid, self.init.pid);
                    if let Some(bridge) = self
                        .started
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
                        .started
                        .cgroup_unavailable
                        .as_deref()
                        .unwrap_or("not attempted"),
                }),
            },
        );
        details.insert(
            "bwrap_pid".to_owned(),
            Value::from(i64::from(self.started.bwrap_pid)),
        );
        if let Some(storage) = &self.storage {
            details.insert(
                "storage_ceiling".to_owned(),
                storage.evidence(self.hard_links_denied),
            );
        }
        details.insert(
            "readonly_open_fast_path".to_owned(),
            Value::from(run.observe_on && !self.snapshot.observation.learning),
        );
        details.insert(
            "namespace_init_pid".to_owned(),
            Value::from(i64::from(self.init.pid)),
        );
        details.insert(
            "launcher_pid".to_owned(),
            Value::from(i64::from(run.launcher.pid)),
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
            if run.observe_on {
                Value::from(super::tracer::narrowing_filter_digest())
            } else {
                Value::Null
            },
        );
        details.insert(
            "narrowing_filter_digest_installed".to_owned(),
            if run.observe_on {
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
            serde_json::json!({
                "expected": super::agent::expected_launcher_filters(
                    self.started.agent.is_some(),
                    run.observe_on,
                ),
                "observed": self.seccomp_filters,
            }),
        );
        if let Some(agent) = self.started.agent.as_ref() {
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
            boundary: "pid_namespace".to_owned(),
            verification_scope: "attempt_tree".to_owned(),
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
            backend: Some("bubblewrap".to_owned()),
            backend_version: self.backend_version.clone(),
        }
    }

    fn check_before_release(&mut self, _run: &mut RunState) -> Result<(), JailError> {
        let started = &mut self.started;
        if started.watcher.ended()
            || self
                .storage
                .as_mut()
                .is_some_and(|storage| storage.sample().is_err())
            || started
                .cgroup
                .as_ref()
                .is_some_and(|leaf| leaf.verify().is_err())
        {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                "lifetime resources were lost before release",
            ));
        }
        Ok(())
    }

    fn tear_down(&mut self, run: &mut RunState) -> TreeObservation {
        self.started.tear_down(Some(&self.init), Witness::Run(run))
    }

    /// Mediated connects and a loss of mediation or proxy evidence (which
    /// strict evidence stops for), bubblewrap's status, the stdio relays and
    /// the watcher, which must outlive a backend that still runs.
    fn poll(&mut self, run: &mut RunState) -> bool {
        if let Some(reason) = self.pump_agent(run) {
            // R-2: the target's end as this loop knows it: the observer's
            // exit, or without one the backend's.
            let after_target_end =
                run.target_exit_seen || (run.tracer.is_none() && self.bwrap_status.is_some());
            run.pending.push_back(RunEvent::EvidenceLost {
                reason,
                after_target_end,
            });
        }
        self.pump_status(run);
        let relay_active = self.pump_stdio(run);
        self.started.release_watcher_after_backend();
        // The watcher follows the backend out, and its exit can be seen
        // before the backend's status has been pumped; only a watcher gone
        // while the backend still runs is a lost helper.
        if self.started.watcher.ended()
            && self.bwrap_status.is_none()
            && !self.started.backend_exited()
        {
            self.hard_kill(run);
        }
        relay_active
    }

    fn sample(&mut self, run: &mut RunState) {
        if let Some(storage) = self.storage.as_mut() {
            match storage.sample() {
                Ok(hits) => {
                    for _ in hits {
                        run.audit.record_limit_hit();
                    }
                }
                Err(_) => {
                    // Audit 2026-10-08 L1: the loss is sticky (`Storage::sample`
                    // replays it every call), and losing the storage read must
                    // not also blind the cgroup ceilings. L2: only a loss found
                    // before the target's end may become the cause, and that
                    // end stays known after its outcome was reported.
                    self.storage_lost_live |= !self.target_ended(run);
                    run.audit
                        .record_limit_evidence_missing("storage_enforcement_lost");
                    self.hard_kill(run);
                }
            }
        }
        let Some(leaf) = self.started.cgroup.as_mut() else {
            return;
        };
        match sample_counters(leaf, &mut run.audit) {
            Counters::Read { oom_killed } => {
                if oom_killed {
                    self.hard_kill(run);
                }
            }
            Counters::Lost => {
                self.started.cgroup_lost = true;
                self.hard_kill(run);
            }
        }
    }

    fn kill(&mut self, _run: &mut RunState) {
        self.started.kill(Some(&self.init));
    }

    fn untraced_exit(&mut self, pid: libc::pid_t, status: i32) {
        if pid == self.started.bwrap_pid {
            self.bwrap_status = Some(status);
        }
    }

    /// The backend's end, and with an observer its account of the target:
    /// the observer's final status, or its own end.
    fn target_done(&self, run: &RunState) -> bool {
        self.bwrap_status.is_some()
            && (run.tracer.is_none() || run.finished || run.target_exit_seen)
    }

    /// The child's end has closed by now; what it wrote through the relays
    /// reaches the operator before the outcome is recorded.
    fn deliver_output(&mut self, run: &mut RunState) {
        let relays = &mut self.started.stdio_relays;
        if let Err(err) = drain_output_relays(relays, OUTPUT_DRAIN_BUDGET) {
            run.pending.push_back(RunEvent::StdioFailed {
                reason: format!("a stdio relay failed: {err}"),
                after_target_end: true,
            });
            relays.clear();
        }
        if relays
            .iter()
            .any(|relay| !relay.to_child && !relay.buffer.is_empty())
        {
            run.pending.push_back(RunEvent::StdioFailed {
                reason: "a stdio relay could not drain its output within the delivery budget"
                    .to_owned(),
                after_target_end: true,
            });
            relays.clear();
        }
    }

    /// Without the observer's final status, the backend's report is all
    /// there is.
    fn unobserved_outcome(&mut self, run: &mut RunState) -> Option<RunEvent> {
        let status = self.bwrap_status?;
        Some(backend_outcome(
            run.exec_confirmed,
            run.tracer_attached,
            &run.error.bytes,
            || self.status_outcome(status),
        ))
    }

    fn cooperative_stop(&mut self, _run: &mut RunState) {
        // Measured on the reference host: a SIGTERM sent to the outer
        // bubblewrap kills bubblewrap itself and never reaches the target,
        // while a SIGTERM to the target's own host pid runs its handler. So
        // the cooperative stop goes to the target, through the pidfd
        // discovery took.
        let _ = identity::pidfd_send_signal(self.launcher_fd.as_raw_fd(), libc::SIGTERM);
    }

    fn tree_ended(&mut self, run: &mut RunState) -> bool {
        self.pump_status(run);
        // The observer finishes once every tracee and the backend are reaped
        // (J5-T); the watcher, released here, is reaped at settlement.
        self.started.release_watcher_after_backend();
        self.bwrap_status.is_some() && !self.init.alive() && self.started.cgroup_empty()
    }

    fn settle(
        &mut self,
        run: &mut RunState,
        deadline: clock::Deadline,
        natural: bool,
    ) -> TreeObservation {
        // The tree is dead or given up on; the proxy drains its last results
        // and the mediator stops.
        self.stop_agent(run, deadline.remaining());
        self.sample(run);
        while !self.started.watcher.ended() && !deadline.expired() {
            self.started.release_watcher_after_backend();
            std::thread::sleep(WAIT_STEP);
        }
        self.started.watcher.reap();
        self.remove_placeholders(run);
        let observer = run.tracer_summary.as_ref();
        let mut tree = verdict(&TreeInputs {
            init_alive: self.init.alive(),
            backend_reaped: self.bwrap_status.is_some() && self.started.watcher.ended(),
            tracer_finished: run.tracer.is_none() || run.finished,
            natural_end: natural,
            abandoned_tracees: observer.map_or(0, |summary| summary.loss.abandoned_tracees),
            unreaped_children: observer.map_or(0, |summary| summary.unreaped_children.len()),
            observer_panicked: observer.is_some_and(|summary| summary.thread_panicked),
            // Security 2026-09-27 (audit 3 A5): carried for the receipt;
            // never a verdict input, because the stop was continued and
            // nothing was lost.
            requested_by_other_filters: observer
                .map_or(0, |summary| summary.requested_by_other_filters),
        });
        if !self.started.cgroup_empty() {
            tree.tree_empty = None;
            tree.verified_at = None;
            tree.integrity = if self.started.cgroup_lost {
                "lost"
            } else {
                "pending"
            }
            .to_owned();
        }
        tree
    }

    /// The backend's status, which no observer collects any more, and the
    /// `agent` network: `proxy.net` is the proxy's own class, with or
    /// without the observer (§11.4).
    fn before_summary(&mut self, run: &mut RunState) {
        if run.tracer.is_none()
            && let Some(mut child) = self.started.child.take()
        {
            let _ = child.try_wait();
        }
        self.stop_agent(run, TREE_BUDGET);
    }

    fn supply_coverage(&self, summary: &mut CoverageSummary) {
        if let Some(agent) = self.started.agent.as_ref() {
            agent.apply_coverage(summary);
        }
    }

    fn final_limits(&self) -> Vec<AppliedLimit> {
        let mut limits = self
            .started
            .cgroup
            .as_ref()
            .map_or_else(Vec::new, ExecutionCgroup::limits);
        if let Some(storage) = &self.storage {
            limits.extend(storage.limits());
        }
        limits
    }

    fn limit_cause(&self) -> Option<String> {
        // Audit 2026-10-08 L2 (§6.4): a storage enforcement loss becomes the
        // cause only when it was found while the target still ran. A loss
        // discovered after the target's own end — including the settlement
        // sample — is recorded in `errors[]` but is never the cause.
        if self.storage_lost_live
            && self
                .storage
                .as_ref()
                .is_some_and(super::storage::Storage::lost)
        {
            return Some("storage_enforcement_lost".to_owned());
        }
        self.started
            .cgroup
            .as_ref()
            .is_some_and(ExecutionCgroup::oom_killed)
            .then(|| "memory_oom".to_owned())
    }

    /// The storage enforcement loss's own message, for the receipt's
    /// `errors[]` (audit 2026-10-08 L2); `None` while enforcement holds.
    fn storage_loss(&self) -> Option<String> {
        self.storage.as_ref()?.loss().map(str::to_owned)
    }

    /// The bridge's counts, once it and the mediator stopped, and the
    /// observer's counts the receipt carries.
    fn final_native_details(&self, run: &RunState) -> Map<String, Value> {
        let mut details = Map::new();
        if let Some(storage) = &self.storage {
            details.insert(
                "storage_ceiling".to_owned(),
                storage.evidence(self.hard_links_denied),
            );
        }
        if let Some(agent) = self.started.agent.as_ref() {
            details.insert("helpers".to_owned(), agent.details().1);
        }
        let observer = run.tracer_summary.as_ref();
        // Security 2026-09-27 (audit 4 B9): the honest count of read-only
        // open verdicts the observer certified (register-sourced flags, and
        // the memory-sourced ones every `memory_flags_unverified` gap already
        // names). A count that never leaves the tracer is unauditable.
        details.insert(
            "filtered_readonly_opens".to_owned(),
            observer.map_or(Value::Null, |summary| {
                Value::from(summary.filtered_readonly_opens)
            }),
        );
        // Security 2026-09-29 (audit 6 N1): open events delivered with their
        // pathname claim downgraded because the descriptor link did not
        // corroborate it. Not loss, so no class counts it; the receipt does.
        details.insert(
            "path_claims_unverified".to_owned(),
            observer.map_or(Value::Null, |summary| {
                Value::from(summary.path_claims_unverified)
            }),
        );
        // Security 2026-09-27 (audit 3 A5): wrong-guess trace stops are
        // counted in the receipt, so a child probing the trace-data space
        // shows up in `lifetime.native.details` instead of continuing
        // silently.
        details.insert(
            "requested_by_other_filters".to_owned(),
            wrong_guess_stops_detail(observer),
        );
        details
    }

    fn dropped(&mut self, run: &mut RunState) {
        if self.started.child.is_some() || run.tracer.is_some() {
            self.tear_down(run);
        } else {
            self.remove_placeholders(run);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::platform::tests::plan_request;
    use super::*;

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
        let init = Init {
            pid,
            fd: identity::pidfd_open(pid).unwrap(),
        };
        assert!(init.alive());
        child.kill().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !super::super::watch::readable(init.fd.as_raw_fd()) {
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
        assert!(!init.alive(), "an exited init is not alive");
        child.wait().unwrap();
    }

    /// A storage or inode ceiling in the snapshot adds the hard-link denials
    /// to the `agent` baseline bubblewrap installs: the network reads the
    /// ceiling from the snapshot itself, so no caller can build it without
    /// them. The receipt's agent detail names that program — the one
    /// `applied.syscalls.digest` names — never the plain baseline, which does
    /// not run.
    #[test]
    fn the_agent_detail_names_the_installed_baseline_with_its_storage_rules() {
        use super::super::agent::AgentNet;
        use super::super::seccomp::{AgentVariant, agent_baseline_with_storage};
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let ceiling = || {
            Some(crate::policy::LimitCeiling {
                value: "1048576".to_owned(),
                required: true,
            })
        };
        for (name, storage, inodes) in [
            ("unbounded", None, None),
            ("storage", ceiling(), None),
            ("inodes", None, ceiling()),
        ] {
            let mut snapshot = plan_request(ProfileName::Agent, false).snapshot;
            snapshot.limits.storage = storage;
            snapshot.limits.inodes = inodes;
            let bounded_storage = name != "unbounded";
            let proxy = root.join(format!("proxy-{name}"));
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
            )
            .unwrap();
            assert_eq!(agent.variant(), AgentVariant::UnprivilegedInner);
            let installed =
                agent_baseline_with_storage(AgentVariant::UnprivilegedInner, bounded_storage)
                    .unwrap();
            assert_eq!(agent.baseline(), &installed, "{name}");
            assert_eq!(
                agent.details().0["baseline_filter_digest"],
                installed.digest().as_str(),
                "{name}"
            );
            assert_eq!(
                super::installed_hard_link_rule(agent.baseline(), Some(agent.variant())),
                Ok(bounded_storage),
                "{name}"
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

    /// The storage evidence's hard-link claim is read from the installed
    /// program: each profile's baseline says whether it carries the storage
    /// rules, and a program that is not its profile's baseline has no answer.
    #[test]
    fn the_hard_link_rule_is_read_from_the_installed_program() {
        use super::super::seccomp::{
            AgentVariant, agent_baseline_with_storage, tool_baseline_with_storage,
        };
        for storage in [false, true] {
            assert_eq!(
                super::installed_hard_link_rule(
                    &tool_baseline_with_storage(storage).unwrap(),
                    None
                ),
                Ok(storage)
            );
            for variant in [
                AgentVariant::UnprivilegedInner,
                AgentVariant::NamespaceInner,
            ] {
                assert_eq!(
                    super::installed_hard_link_rule(
                        &agent_baseline_with_storage(variant, storage).unwrap(),
                        Some(variant)
                    ),
                    Ok(storage),
                    "{variant:?}"
                );
            }
        }
        // `tool`'s program is no `agent` baseline, and the reverse.
        assert!(
            super::installed_hard_link_rule(
                &tool_baseline_with_storage(true).unwrap(),
                Some(AgentVariant::UnprivilegedInner)
            )
            .is_err()
        );
        assert!(
            super::installed_hard_link_rule(
                &agent_baseline_with_storage(AgentVariant::NamespaceInner, true).unwrap(),
                None
            )
            .is_err()
        );
    }

    /// Without an observer's final status the backend's report decides; an
    /// exec nothing confirmed is the observation-off error only without an
    /// observer, and an unknown with one, which is not that error.
    #[test]
    fn an_unconfirmed_exec_is_the_observation_off_error_only_without_an_observer() {
        let exited = || RunEvent::TargetExited { code: 3 };
        assert!(matches!(
            backend_outcome(false, false, &[], exited),
            RunEvent::ExecUnconfirmed { .. }
        ));
        let RunEvent::Unknown { reason } = backend_outcome(false, true, &[], exited) else {
            panic!("an observed run reports no ExecUnconfirmed");
        };
        assert!(reason.contains("observer"), "{reason}");
        assert_eq!(
            backend_outcome(true, true, &[], exited),
            RunEvent::TargetExited { code: 3 }
        );
        assert!(matches!(
            backend_outcome(false, true, &libc::ENOENT.to_le_bytes(), exited),
            RunEvent::ExecError { .. }
        ));
    }
}
