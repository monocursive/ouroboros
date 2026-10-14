//! The contained run loop, and the rules both run loops share.

use std::collections::VecDeque;
use std::os::fd::AsRawFd as _;
use std::time::Duration;

use serde_json::Value;

use crate::observer::CoverageSummary;
use crate::platform::{
    Deadline as PortableDeadline, RunEvent, RunningExecution, StopReason, TreeObservation,
};
use crate::records::AppliedLimit;
use crate::supervisor::TREE_BUDGET;

use super::boundary::{Boundary, init_alive};
use super::cgroup::ExecutionCgroup;
use super::clock::{self, boottime_ns};
use super::identity;
use super::identity::read_environment_names;
use super::requirements::capability_from;
use super::stdio::{OUTPUT_DRAIN_BUDGET, drain_output_relays, pump_stdio_relays};
use super::sys::{nap, set_nonblocking, write_all};
use super::tracer::{TracerEvent, TracerSummary};
use super::verdict::{TreeInputs, observer_verdict, verdict};

/// Cooperative termination grace (§9.3).
pub(super) const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long a natural finish is awaited before the tree is terminated.
pub(super) const SETTLE_GRACE: Duration = Duration::from_millis(500);
/// Longest single block inside `wait`, so every source is re-checked often.
pub(super) const WAIT_STEP: Duration = Duration::from_millis(10);

/// How often the execution cgroup's counters are read while the target runs;
/// they are always read once more before an outcome is classified.
pub(super) const LIMIT_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

pub(super) struct LinuxRunning {
    pub(super) boundary: Boundary,
    pub(super) wall: Option<clock::Deadline>,
    pub(super) wall_reported: bool,
    pub(super) exec_confirmed: bool,
    pub(super) target_outcome: Option<RunEvent>,
    pub(super) pending: VecDeque<RunEvent>,
    pub(super) stop_requested: Option<StopReason>,
    pub(super) stop_at: Option<u64>,
    pub(super) hard_killed: bool,
    pub(super) hard_deadline: Option<clock::Deadline>,
    pub(super) bwrap_status: Option<i32>,
    pub(super) finished: bool,
    pub(super) evidence_reported: bool,
    /// Boot-clock time of the last counter sample.
    pub(super) sampled_at_ns: u64,
    /// Audit 2026-10-08 L2: storage enforcement was found lost while the
    /// target still ran — the only timing that may make it `outcome.cause`
    /// (§6.4). A loss first seen after the target's own end never does.
    pub(super) storage_lost_live: bool,
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
            details.insert(
                "storage_ceiling".to_owned(),
                storage.evidence(self.boundary.hard_links_denied),
            );
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
            // The observer attached during preparation exactly when a tracer
            // was kept; stopping it is what leaves its account here.
            let tracer = self.boundary.tracer_summary.as_ref();
            self.boundary
                .audit
                .summary(tracer, CoverageSummary::applied(tracer.is_some()))
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

pub(super) fn image_changed(pid: libc::pid_t) -> bool {
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
pub(super) fn step_for(deadline: PortableDeadline) -> Duration {
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

/// What the contained boundary and `super::uncontained` share, each written
/// once: the privileged-supervisor refusal, the ceiling rows, the error-pipe
/// drain, the counter sample and its loss, the sample cadence, the wall and
/// grace checks, the hard-kill arming, the exec evidence without an
/// observer, the order of an observed outcome, the observer's verdict, and
/// delegations to helpers above. A fix to one of these reaches both
/// boundaries.
///
/// The run loops themselves are still written twice, because each keeps its
/// own state: `pump_tracer`, `handle_tracer_event` and `stop_observer` (the
/// contained loop also takes the backend's untraced exit and command-rule
/// hits; `none` tracks a late target exit), and the methods that apply the
/// shared rules to that state — the limit sample, `hard_kill`,
/// `terminal_event`, `request_stop`, `wait_tree` and `observer_summary`. A
/// fix to any of those must be made in both.
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

#[cfg(test)]
mod tests {
    use super::super::audit::AuditWriter;
    use super::*;

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
}
