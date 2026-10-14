//! The run loop both Linux boundaries drive (§8.1 steps 7 to 9, §9.3, §11).
//!
//! A boundary is a [`Tree`]: how its own sources are read, how its counters
//! are sampled, how it is killed, how its end is seen and what its teardown
//! and settlement establish. Everything else a run does is written once, in
//! [`Run`] and [`RunState`]: the observer's facts and its account, the
//! launcher's error pipe, exec confirmation without an observer, the wall,
//! the cooperative grace and the forced stop, the order of a run's events,
//! the release and the observer summary. The contained boundary
//! ([`super::boundary`]) and `none` ([`super::uncontained`]) both run as a
//! [`Run`], so a fix to any of these reaches both.

use std::collections::VecDeque;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::time::Duration;

use serde_json::{Map, Value};

use crate::observer::{CoverageClass, CoverageSummary};
use crate::platform::{
    BoundaryIdentity, Deadline as PortableDeadline, PreparedExecution, ReleaseFailure, RunEvent,
    RunningExecution, StopReason, Teardown, TreeObservation,
};
use crate::policy::{LimitsSnapshot, PolicySnapshot};
use crate::records::{Applied, AppliedLimit, ErrorCode, ErrorStage, JailError, Remediation};
use crate::supervisor::TREE_BUDGET;

use super::audit::AuditWriter;
use super::cgroup::ExecutionCgroup;
use super::clock::{self, boottime_ns};
use super::identity::ProcessIdentity;
use super::launch;
use super::observed::{self, Fact};
use super::sys::write_all;
use super::tracer::{Tracer, TracerEvent, TracerSummary};
use super::watch;

/// Cooperative termination grace (§9.3).
pub(super) const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long a natural finish is awaited before the tree is terminated.
pub(super) const SETTLE_GRACE: Duration = Duration::from_millis(500);
/// Longest single block inside `wait`, so every source is re-checked often.
pub(super) const WAIT_STEP: Duration = Duration::from_millis(10);
/// How often the counters are read while the target runs; they are always
/// read once more before an outcome is classified.
pub(super) const LIMIT_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// What the launcher wrote to its error pipe: a failed exec's report, or a
/// setup failure's errno. Read without blocking; `eof` once the pipe closed.
pub(super) struct ErrorPipe {
    fd: OwnedFd,
    /// Every byte read so far.
    pub(super) bytes: Vec<u8>,
    /// The pipe has closed: every holder of its write end is gone.
    pub(super) eof: bool,
}

impl ErrorPipe {
    /// The read end, which must be non-blocking.
    pub(super) fn new(fd: OwnedFd) -> Self {
        ErrorPipe {
            fd,
            bytes: Vec::new(),
            eof: false,
        }
    }

    /// Reads whatever the launcher wrote, without blocking.
    pub(super) fn drain(&mut self) {
        if self.eof {
            return;
        }
        let mut buffer = [0u8; 64];
        loop {
            // SAFETY: the buffer is live, the length matches and the
            // descriptor is owned and non-blocking.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if n > 0 {
                self.bytes
                    .extend_from_slice(&buffer[..usize::try_from(n).unwrap_or(0)]);
                continue;
            }
            if n == 0 {
                self.eof = true;
            }
            return;
        }
    }
}

/// What preparation hands the run once the launcher is blocked and read back.
pub(super) struct Launched {
    /// The launcher's birth identity, taken while it was blocked.
    pub(super) launcher: ProcessIdentity,
    /// The paths the launcher will try to `execve`, derived from the same
    /// program name and `PATH` the launcher itself uses. The observer's exec
    /// snapshot must be one of them.
    pub(super) target_images: Vec<Vec<u8>>,
    /// The write end of the release pipe the launcher blocks reading.
    pub(super) release: OwnedFd,
    /// The read end of the launcher's error pipe.
    pub(super) error: ErrorPipe,
    pub(super) audit: AuditWriter,
    /// Observation is on (§11): an observer attached during preparation.
    pub(super) observe_on: bool,
    /// The observer, attached to the blocked launcher.
    pub(super) tracer: Option<Tracer>,
    /// What the boundary applied, read back from the blocked launcher.
    pub(super) applied: Applied,
}

/// The run's own state, whichever boundary it runs in.
pub(super) struct RunState {
    /// The launcher: the target once it execs.
    pub(super) launcher: ProcessIdentity,
    pub(super) target_images: Vec<Vec<u8>>,
    /// `None` once the release byte is written: a second release is
    /// impossible (X03).
    release: Option<OwnedFd>,
    pub(super) error: ErrorPipe,
    pub(super) audit: AuditWriter,
    pub(super) observe_on: bool,
    /// What the boundary applied (§13.2), for the receipt's `applied` group.
    applied: Applied,
    pub(super) tracer: Option<Tracer>,
    /// Set when the observer attached: from then on it owns every `waitpid`
    /// of this process.
    pub(super) tracer_attached: bool,
    /// The observer's account, once it stopped.
    pub(super) tracer_summary: Option<TracerSummary>,
    /// The wall, armed at the release.
    wall: Option<clock::Deadline>,
    wall_reported: bool,
    pub(super) exec_confirmed: bool,
    /// The observer's final status of the target, until the run reports it.
    target_outcome: Option<RunEvent>,
    /// The observer reported the target's final status; unlike
    /// `target_outcome` it stays set once the outcome is reported.
    pub(super) target_exit_seen: bool,
    pub(super) pending: VecDeque<RunEvent>,
    stop_requested: Option<StopReason>,
    stop_at: Option<u64>,
    pub(super) hard_killed: bool,
    pub(super) hard_deadline: Option<clock::Deadline>,
    /// The observer's thread stopped.
    pub(super) finished: bool,
    evidence_reported: bool,
    /// Boot-clock time of the last counter sample.
    sampled_at_ns: u64,
}

impl RunState {
    pub(super) fn new(launched: Launched) -> Self {
        let tracer_attached = launched.tracer.is_some();
        RunState {
            launcher: launched.launcher,
            target_images: launched.target_images,
            release: Some(launched.release),
            error: launched.error,
            audit: launched.audit,
            observe_on: launched.observe_on,
            applied: launched.applied,
            tracer: launched.tracer,
            tracer_attached,
            tracer_summary: None,
            wall: None,
            wall_reported: false,
            exec_confirmed: false,
            target_outcome: None,
            target_exit_seen: false,
            pending: VecDeque::new(),
            stop_requested: None,
            stop_at: None,
            hard_killed: false,
            hard_deadline: None,
            finished: false,
            evidence_reported: false,
            sampled_at_ns: 0,
        }
    }

    /// Records one observer event and acts on the lifecycle fact it
    /// establishes; a direct child that was never a tracee is the boundary's
    /// to interpret, so its exit is returned.
    fn record(&mut self, event: &TracerEvent) -> Option<(libc::pid_t, i32)> {
        let target = observed::Target {
            launcher: self.launcher.pid,
            images: &self.target_images,
        };
        match observed::record(&mut self.audit, &target, event) {
            Fact::CommandForbidden(pattern) => {
                self.pending
                    .push_back(RunEvent::CommandForbidden { pattern });
            }
            Fact::TargetExec if !self.exec_confirmed => {
                self.exec_confirmed = true;
                self.pending.push_back(RunEvent::ExecConfirmed);
            }
            Fact::TargetExit(status) => {
                self.target_exit_seen = true;
                if self.target_outcome.is_none() {
                    self.target_outcome = Some(outcome_from_status(status));
                }
            }
            // §11.4: only a hole where a result went missing stops a strict
            // run.
            Fact::CoverageLost(reason) if !self.evidence_reported => {
                self.evidence_reported = true;
                self.pending.push_back(RunEvent::EvidenceLost {
                    reason: format!("the closed-set observer lost coverage: {}", reason.as_str()),
                    // R-2: a loss the teardown after the target's own exit
                    // caused (a call the end of its tree interrupted) can be
                    // queued ahead of that exit although it came after it.
                    after_target_end: self.target_exit_seen,
                });
            }
            Fact::Finished => self.finished = true,
            Fact::UntracedExit { pid, status } => return Some((pid, status)),
            _ => {}
        }
        None
    }

    /// Stops the observer within `budget` and keeps its account.
    ///
    /// `finish_within` always returns: it interrupts the tracer thread, gives
    /// a live tree up to `budget` to end, and on expiry kills what is left
    /// and says how much it had to kill. A target exit or the observer's end
    /// still delivered counts as seen.
    pub(super) fn stop_observer(&mut self, budget: Duration) {
        let Some(tracer) = self.tracer.take() else {
            return;
        };
        let target = observed::Target {
            launcher: self.launcher.pid,
            images: &self.target_images,
        };
        let (exit_seen, finished) = (&mut self.target_exit_seen, &mut self.finished);
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

    /// Exec confirmation without an observer (§8.1 step 7): see
    /// [`exec_without_observer`].
    fn check_exec_without_tracer(&mut self) {
        if exec_without_observer(
            self.tracer_attached || self.exec_confirmed,
            &self.error.bytes,
            self.error.eof,
            &self.launcher,
        ) {
            self.exec_confirmed = true;
            self.pending.push_back(RunEvent::ExecConfirmed);
        }
    }

    /// The wall, reported once when it has passed: the hit is counted in the
    /// `limits` class, and the `WallExpired` it queues asks the supervisor to
    /// stop the run.
    fn check_wall(&mut self) {
        if self.wall_reported || !self.wall.is_some_and(clock::Deadline::expired) {
            return;
        }
        self.wall_reported = true;
        self.audit.record_limit_hit();
        self.pending.push_back(RunEvent::WallExpired);
    }

    /// Whether a requested cooperative stop has had its [`STOP_GRACE`]
    /// (§9.3) and must become a forced one.
    fn grace_spent(&self) -> bool {
        let grace = u64::try_from(STOP_GRACE.as_nanos()).unwrap_or(u64::MAX);
        !self.hard_killed
            && self.stop_requested.is_some()
            && self
                .stop_at
                .is_some_and(|at| clock::boottime_ns().saturating_sub(at) >= grace)
    }

    /// Arms the forced stop, once: `true` the first time, when the caller
    /// kills its tree and the tree budget (§9.3) for seeing it die starts.
    pub(super) fn arm_hard_kill(&mut self) -> bool {
        if self.hard_killed {
            return false;
        }
        self.hard_killed = true;
        self.hard_deadline = Some(clock::Deadline::after(TREE_BUDGET));
        true
    }

    /// Whether the counters are due: always when `force`, otherwise once per
    /// [`LIMIT_SAMPLE_INTERVAL`]. A due sample moves the cadence to now.
    fn sample_due(&mut self, force: bool) -> bool {
        let now = clock::boottime_ns();
        let interval = u64::try_from(LIMIT_SAMPLE_INTERVAL.as_nanos()).unwrap_or(u64::MAX);
        if !force && now.saturating_sub(self.sampled_at_ns) < interval {
            return false;
        }
        self.sampled_at_ns = now;
        true
    }

    /// A failed exec the launcher reported, once: bytes after a confirmed
    /// exec cannot happen, and are dropped rather than reported as a second
    /// event.
    fn exec_error(&mut self) -> Option<RunEvent> {
        if self.exec_confirmed {
            self.error.bytes.clear();
        }
        if self.error.bytes.is_empty() {
            return None;
        }
        let (errno, detail) = launch::exec_failure_parts(&self.error.bytes);
        self.error.bytes.clear();
        Some(RunEvent::ExecError { errno, detail })
    }

    /// The target's outcome as the observer reported it, taken once. The
    /// observer's final status of the target also confirms its exec: when
    /// nothing confirmed the exec yet, `ExecConfirmed` comes first and the
    /// outcome is queued behind it.
    fn observed_outcome(&mut self) -> Option<RunEvent> {
        let outcome = self.target_outcome.take()?;
        if self.exec_confirmed {
            return Some(outcome);
        }
        self.exec_confirmed = true;
        self.pending.push_back(outcome);
        Some(RunEvent::ExecConfirmed)
    }
}

/// What a boundary adds to the run: everything [`Run`] does not do the same
/// way for both of them.
pub(super) trait Tree: 'static {
    /// The snapshot the attempt runs under.
    fn snapshot(&self) -> &PolicySnapshot;

    /// The boundary's identity, as the receipts record it.
    fn boundary_identity(&self, run: &RunState) -> BoundaryIdentity;

    /// Whether the boundary is still whole at the release; the refusal when
    /// it is not.
    ///
    /// # Errors
    /// The refusal the release fails with.
    fn check_before_release(&mut self, run: &mut RunState) -> Result<(), JailError>;

    /// Tears down a boundary whose target never ran and says what that
    /// established (§13.2 row 4).
    fn tear_down(&mut self, run: &mut RunState) -> TreeObservation;

    /// Reads the boundary's own sources once per wait step: `true` while
    /// relayed stdio made progress, so the step is kept short.
    fn poll(&mut self, run: &mut RunState) -> bool;

    /// Reads the counters (and whatever else the boundary checks at their
    /// cadence).
    fn sample(&mut self, run: &mut RunState);

    /// Kills everything the boundary can reach.
    fn kill(&mut self, run: &mut RunState);

    /// The forced stop, armed once (§9.3).
    fn hard_kill(&mut self, run: &mut RunState) {
        if run.arm_hard_kill() {
            self.kill(run);
        }
    }

    /// A direct child of this process that was never a tracee exited.
    fn untraced_exit(&mut self, _pid: libc::pid_t, _status: i32) {}

    /// Whether the target's end is in hand, so its outcome can be classified.
    fn target_done(&self, run: &RunState) -> bool;

    /// What the target's end owes the operator before its outcome is
    /// recorded.
    fn deliver_output(&mut self, _run: &mut RunState) {}

    /// The outcome when the observer reported none.
    fn unobserved_outcome(&mut self, run: &mut RunState) -> Option<RunEvent>;

    /// Asks the target to stop (§9.3).
    fn cooperative_stop(&mut self, run: &mut RunState);

    /// Reads the boundary's sources once while the tree is verified, and
    /// says whether its end is seen.
    fn tree_ended(&mut self, run: &mut RunState) -> bool;

    /// Settles the tree after the observer stopped: what its end
    /// established, within what is left of `deadline`.
    fn settle(
        &mut self,
        run: &mut RunState,
        deadline: clock::Deadline,
        natural: bool,
    ) -> TreeObservation;

    /// What the boundary still has to stop before its coverage is summed.
    fn before_summary(&mut self, _run: &mut RunState) {}

    /// The coverage classes the boundary's own evidence sources own.
    fn supply_coverage(&self, _summary: &mut CoverageSummary) {}

    fn final_limits(&self) -> Vec<AppliedLimit>;

    fn limit_cause(&self) -> Option<String>;

    fn storage_loss(&self) -> Option<String> {
        None
    }

    fn integrity_lost(&self) -> bool {
        false
    }

    fn final_native_details(&self, _run: &RunState) -> Map<String, Value> {
        Map::new()
    }

    /// Releases what a dropped run still holds: a run dropped unsettled is
    /// torn down.
    fn dropped(&mut self, run: &mut RunState);
}

/// A prepared and then released boundary: the run's state and the boundary
/// it runs in.
pub(super) struct Run<T: Tree> {
    pub(super) state: RunState,
    pub(super) tree: T,
}

impl<T: Tree> Run<T> {
    pub(super) fn new(state: RunState, tree: T) -> Self {
        Run { state, tree }
    }

    /// Drains the tracer channel into audit events and run events.
    ///
    /// `block` is how long to wait for the first event. Every event taken
    /// from the channel is recorded here; nothing reads that channel
    /// elsewhere, because an event read and dropped would be evidence
    /// silently lost.
    fn pump_tracer(&mut self, block: Duration) {
        let Some(tracer) = self.state.tracer.as_ref() else {
            return;
        };
        for event in observed::drain(tracer, block) {
            if let Some((pid, status)) = self.state.record(&event) {
                self.tree.untraced_exit(pid, status);
            }
        }
    }

    fn sample(&mut self, force: bool) {
        if self.state.sample_due(force) {
            self.tree.sample(&mut self.state);
        }
    }

    /// Escalates a cooperative stop to a forced one once the grace passed.
    fn check_grace(&mut self) {
        if self.state.grace_spent() {
            self.tree.hard_kill(&mut self.state);
        }
    }

    /// The outcome once no more facts can arrive.
    fn terminal_event(&mut self) -> Option<RunEvent> {
        if let Some(event) = self.state.observed_outcome() {
            return Some(event);
        }
        self.tree.unobserved_outcome(&mut self.state)
    }

    /// A refused release, with the teardown it ran.
    fn fail_release(mut self, error: JailError) -> Box<ReleaseFailure> {
        let tree = self.tree.tear_down(&mut self.state);
        Box::new(ReleaseFailure {
            error,
            teardown: Some(Teardown { tree: Some(tree) }),
        })
    }
}

/// A refusal at the release, with the launcher still blocked.
fn release_refusal(code: ErrorCode, message: impl Into<String>) -> JailError {
    JailError::new(
        code,
        ErrorStage::Preparing,
        Remediation::HostSetup,
        message.into(),
    )
}

impl<T: Tree> PreparedExecution for Run<T> {
    fn boundary(&self) -> BoundaryIdentity {
        self.tree.boundary_identity(&self.state)
    }

    fn applied(&self) -> Option<Applied> {
        Some(self.state.applied.clone())
    }

    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, Box<ReleaseFailure>> {
        let mut run = *self;
        // The boundary must still be what preparation read back; a refusal
        // carries the teardown it ran (§13.2).
        if let Err(error) = run.tree.check_before_release(&mut run.state) {
            return Err(run.fail_release(error));
        }
        // Parsed once, before the release: an unparseable ceiling refuses
        // with the launcher still blocked, rather than after the target was
        // released without the deadline the receipt's limit row claims.
        let wall = match clock::wall_ceiling(&run.tree.snapshot().limits) {
            Ok(wall) => wall,
            Err(what) => {
                return Err(run.fail_release(release_refusal(
                    ErrorCode::InternalError,
                    format!("the wall limit cannot be enforced: {what}"),
                )));
            }
        };
        let Some(release) = run.state.release.take() else {
            return Err(run.fail_release(release_refusal(
                ErrorCode::BackendUnavailable,
                "the release pipe is already closed",
            )));
        };
        if let Err(err) = write_all(release.as_raw_fd(), &[watch::RELEASED]) {
            return Err(run.fail_release(release_refusal(
                ErrorCode::BackendUnavailable,
                format!("the release byte could not be written: {err}"),
            )));
        }
        // The launcher reads exactly one byte; closing the write end here
        // makes the single release visible at a glance (X03).
        drop(release);
        // The wall runs from the release.
        run.state.wall = wall.map(clock::Deadline::after);
        Ok(Box::new(run))
    }

    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        let mut run = *self;
        // The target never ran, but the boundary existed, and whether its
        // teardown completed is a measured fact.
        Ok(Teardown {
            tree: Some(run.tree.tear_down(&mut run.state)),
        })
    }
}

impl<T: Tree> RunningExecution for Run<T> {
    fn final_limits(&self) -> Vec<AppliedLimit> {
        self.tree.final_limits()
    }

    fn limit_cause(&self) -> Option<String> {
        self.tree.limit_cause()
    }

    fn storage_loss(&self) -> Option<String> {
        self.tree.storage_loss()
    }

    fn integrity_lost(&self) -> bool {
        self.tree.integrity_lost()
    }

    fn final_native_details(&self) -> Map<String, Value> {
        self.tree.final_native_details(&self.state)
    }

    fn wait(&mut self, deadline: PortableDeadline) -> RunEvent {
        if let Some(event) = self.state.pending.pop_front() {
            return event;
        }
        self.state.error.drain();
        self.pump_tracer(Duration::ZERO);
        let relay_active = self.tree.poll(&mut self.state);
        self.sample(false);
        self.state.check_exec_without_tracer();
        self.state.check_wall();
        self.check_grace();
        if let Some(event) = self.state.pending.pop_front() {
            return event;
        }
        if let Some(event) = self.state.exec_error() {
            return event;
        }
        if self.tree.target_done(&self.state) {
            // The counters must be in hand before the outcome is
            // classified: an OOM kill is attributed from them.
            self.sample(true);
            self.tree.deliver_output(&mut self.state);
            if let Some(event) = self.state.pending.pop_front() {
                return event;
            }
            if let Some(event) = self.terminal_event() {
                return event;
            }
        }
        if self
            .state
            .hard_deadline
            .is_some_and(clock::Deadline::expired)
        {
            return RunEvent::Unknown {
                reason: "termination could not be observed within the tree budget".to_owned(),
            };
        }
        // A relay making progress keeps the loop fast, so a chatty child is
        // not throttled to the poll cadence.
        let step = if relay_active {
            step_for(deadline).min(Duration::from_millis(2))
        } else {
            step_for(deadline)
        };
        if self.state.tracer.is_some() {
            self.pump_tracer(step);
        } else {
            std::thread::sleep(step);
        }
        RunEvent::Poll
    }

    fn request_stop(&mut self, reason: StopReason) {
        if self.state.stop_requested.is_some() {
            return;
        }
        self.state.stop_requested = Some(reason);
        self.state.stop_at = Some(boottime_ns());
        self.tree.cooperative_stop(&mut self.state);
    }

    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        let deadline = self
            .state
            .hard_deadline
            .unwrap_or_else(|| clock::Deadline::after(budget));
        let settle = clock::Deadline::after(SETTLE_GRACE.min(budget));
        let mut natural = false;
        loop {
            self.state.error.drain();
            self.pump_tracer(Duration::ZERO);
            let ended = self.tree.tree_ended(&mut self.state);
            let tracer_done = self.state.tracer.is_none() || self.state.finished;
            if tracer_done && ended {
                natural = true;
                break;
            }
            if settle.expired() {
                // §9.3: target exit is itself a termination trigger.
                self.tree.hard_kill(&mut self.state);
            }
            if deadline.expired() {
                break;
            }
            if self.state.tracer.is_some() {
                self.pump_tracer(WAIT_STEP);
            } else {
                std::thread::sleep(WAIT_STEP);
            }
        }
        // Whatever the loop concluded, the observer is stopped inside what
        // is left of the budget and its account decides: it is the only
        // witness to whether every tracee really ended.
        self.pump_tracer(Duration::ZERO);
        self.state.stop_observer(deadline.remaining());
        self.tree.settle(&mut self.state, deadline, natural)
    }

    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        // `wait_tree` already stopped the observer inside its budget; this
        // only covers a caller that skipped it.
        self.state.stop_observer(TREE_BUDGET);
        self.tree.before_summary(&mut self.state);
        let state = &mut self.state;
        let mut known = if state.observe_on {
            // The observer attached during preparation exactly when
            // observation is on; stopping it is what leaves its account here.
            CoverageSummary::applied(state.tracer_attached)
        } else {
            // §11.4: observation off makes every audit class unsupported
            // with a null count. The wrapper's own `limits` class still
            // exists.
            let mut summary = CoverageSummary::unobserved();
            summary
                .classes
                .insert(CoverageClass::Limits, state.audit.limits_class());
            summary
        };
        // The boundary's own evidence sources state their classes before the
        // audit's account joins them; nothing is patched in afterwards.
        self.tree.supply_coverage(&mut known);
        Some(if state.observe_on {
            state.audit.summary(state.tracer_summary.as_ref(), known)
        } else {
            known
        })
    }
}

impl<T: Tree> Drop for Run<T> {
    fn drop(&mut self) {
        self.tree.dropped(&mut self.state);
    }
}

pub(super) fn outcome_from_status(status: i32) -> RunEvent {
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

/// Security 2026-09-27 (audit 3 A5): the receipt's account of stops another
/// filter asked for — a child's own `SECCOMP_RET_TRACE` on a call outside the
/// closed set, carrying its own trace data, not this attempt's. Each is
/// continued unobserved: not a result, not a loss, never a
/// `unexpected_trace_stop` gap. The count is what makes the guessing visible,
/// so it is carried in `lifetime.native.details`; null when no observer ran,
/// because a detail must not claim a count nothing read.
pub(super) fn wrong_guess_stops_detail(summary: Option<&TracerSummary>) -> Value {
    summary.map_or(Value::Null, |summary| {
        Value::from(summary.requested_by_other_filters)
    })
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

/// §5.2, for every profile: v1 refuses a privileged or setuid supervisor
/// rather than model that boundary; a child-side capability read-back is no
/// substitute for not being privileged in the first place. (Untestable on
/// the reference host: the conformance account has no privilege to gain.)
///
/// # Errors
/// `unsupported_platform` when the effective uid is 0 or differs from the
/// real one.
pub(super) fn refuse_privileged_supervisor() -> Result<(), JailError> {
    // SAFETY: getuid and geteuid take no arguments and cannot fail.
    let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if euid == 0 || ruid != euid {
        return Err(JailError::new(
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            format!(
                "v1 refuses a privileged or setuid supervisor: real uid {ruid}, effective uid \
                 {euid} (jail-v1 §5.2)"
            ),
        ));
    }
    Ok(())
}

/// The `applied.limits` rows of the wall and the cgroup ceilings, in
/// snapshot order: the leaf's own row for a cgroup ceiling it holds, the
/// supervisor's boot-clock deadline for the wall, and an unapplied row for
/// anything else. An applied ceiling not yet hit says `false`; a null `hit`
/// means unknown or unapplied (§6.4). The supervisor flips the wall's to
/// `true` when the deadline expires.
pub(super) fn ceiling_rows(
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

/// Exec confirmation without an observer (§8.1 step 7). `settled` means
/// there is nothing to decide here: an observer was attached (it is the
/// witness), or the exec is already confirmed.
///
/// The launcher sets the error pipe close-on-exec before it blocks, and
/// measured on the reference host the only holder of that descriptor is the
/// launcher itself (in a contained run, neither bubblewrap nor its reaper
/// keeps a copy). So end-of-file with no bytes means the launcher closed it,
/// by execing or by dying. A changed executable image is required too: a
/// zombie keeps its birth identity, and even pidfd readiness can lag the
/// descriptor's close during exit. If the image is unreadable or unchanged,
/// exec stays unknown.
fn exec_without_observer(
    settled: bool,
    error_bytes: &[u8],
    error_eof: bool,
    launcher: &ProcessIdentity,
) -> bool {
    !settled
        && error_bytes.is_empty()
        && error_eof
        && launcher.is_live()
        && image_changed(launcher.pid)
}

/// What one read of the execution cgroup's counters established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Counters {
    /// Read, with every newly hit ceiling counted. `oom_killed`: the kernel's
    /// OOM killer has run in the leaf.
    Read { oom_killed: bool },
    /// The read failed, and [`counters_lost`] recorded it.
    Lost,
}

/// Reads the leaf's counters once and counts every newly hit ceiling in the
/// `limits` class. A failed read is [`counters_lost`].
pub(super) fn sample_counters(leaf: &mut ExecutionCgroup, audit: &mut AuditWriter) -> Counters {
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

/// Counter evidence the leaf can no longer give (§11.4): every `hit` not yet
/// seen becomes null, and the `limits` class records a gap naming `reason`,
/// so it reads degraded with a null count instead of active with a count
/// nothing supports.
pub(super) fn counters_lost(leaf: &mut ExecutionCgroup, audit: &mut AuditWriter, reason: &str) {
    leaf.invalidate_hits();
    audit.record_limit_evidence_missing(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run with no observer over a launcher that is this process.
    fn run_state() -> RunState {
        let (error, _writer) = super::super::exec::pipe().unwrap();
        let (_reader, release) = super::super::exec::pipe().unwrap();
        RunState::new(Launched {
            launcher: ProcessIdentity::own().unwrap(),
            target_images: Vec::new(),
            release,
            error: ErrorPipe::new(error),
            audit: AuditWriter::new(
                "att_00000000-0000-4000-8000-000000000001",
                None,
                b"/work",
                b"",
            ),
            observe_on: true,
            tracer: None,
            applied: Applied {
                filesystem: None,
                network: crate::records::AppliedNetwork {
                    mode: "none".to_owned(),
                    mechanism: None,
                    allowed_hosts: Vec::new(),
                    tls_only: Vec::new(),
                },
                syscalls: None,
                limits: Vec::new(),
                environment_names: Vec::new(),
                removed_environment_names: Vec::new(),
            },
        })
    }

    /// The observer's final status of the target is reported once, but the
    /// fact that the target ended stays: what is found after the run took
    /// the outcome (a storage loss in the settlement sample, an evidence
    /// loss in the teardown) is after the target's end.
    #[test]
    fn the_target_end_stays_known_after_its_outcome_is_reported() {
        let mut run = run_state();
        assert!(!run.target_exit_seen);
        let exit = TracerEvent::Exit {
            pid: run.launcher.pid,
            start_ticks: None,
            status: 0,
        };
        assert_eq!(run.record(&exit), None);
        assert!(run.target_exit_seen);
        // The observer's status also confirms the exec: that comes first.
        assert_eq!(run.observed_outcome(), Some(RunEvent::ExecConfirmed));
        assert_eq!(
            run.pending.pop_front(),
            Some(RunEvent::TargetExited { code: 0 })
        );
        assert_eq!(run.observed_outcome(), None, "reported once");
        assert!(run.target_exit_seen, "the end is still known");
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
            sample_counters(&mut leaf, &mut audit),
            Counters::Read { oom_killed: false }
        );
        assert_eq!(
            audit.limits_class().status,
            crate::records::SourceStatus::Active
        );
        assert_eq!(leaf.limits()[0].hit, Some(false));

        std::fs::remove_file(path.join("pids.events")).unwrap();
        assert_eq!(sample_counters(&mut leaf, &mut audit), Counters::Lost);
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
}
