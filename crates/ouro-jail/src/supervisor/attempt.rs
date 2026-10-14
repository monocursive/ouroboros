//! One claimed attempt, from its claim to its last receipt (§8.1).
//!
//! I01 by construction. [`Attempt::claim`] is the last step that may fail
//! without a receipt: it fails before the claim exists or with nothing
//! claimed. From the claim on, [`Attempt::run`] returns a report, never an
//! error, and each phase hands its failure back to it: one before the
//! boundary exists ([`Attempt::prepare`]) ends in [`Attempt::refuse`], one
//! while the boundary waits for release ([`Attempt::register`],
//! [`Attempt::gate`]) in [`Attempt::abort_and_refuse`], a failed release or
//! a failed target exec in [`Attempt::refuse`] with what the platform's
//! teardown established, and an attempt whose target ran in
//! [`Attempt::settle`].

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use super::{
    Budget, Context, ControlSink, GATE_WAIT, InFlight, Journal, Plan, RELEASE_STDOUT_AFTER_PREPARE,
    RunReport, TREE_BUDGET, apply_boundary, await_release, claim_attempt, degrade_trace_coverage,
    finish_control, first_unsatisfied, interrupted, merge_wall_limit, open_control, open_trace,
    pending_applied, persist_terminal, persistence_failed, persistence_failed_after,
    platform_record, prepare_launch, prepare_proxy_dir, record_teardown, record_tree,
    refuse_vendor_state, register_boundary_in_state, release_own_stdout, remove_managed_scratch,
    remove_proxy_directory, retain_vendor_state, send_control, settle_in_flight, settlement_loss,
    signals, stop, storage_loss_error, stream_classes, submit_receipt, unrecorded, wall_deadline,
    write_policy_file,
};
use crate::cleanup;
use crate::cli::RunArgs;
use crate::observer::CoverageSummary;
use crate::platform::{
    Deadline, PlanRequest, PreparedExecution, PreparedPlan, ProxyDirHandoff, ReleaseFailure,
    RunEvent, RunningExecution, Sinks, StopReason,
};
use crate::policy::ProfileName;
use crate::records::{
    AttemptRecord, Containment, ControlKind, ErrorCode, ErrorStage, EvidenceMode, GateExpectation,
    JailError, JailRecord, Lifetime, Outcome, OutcomeKind, Phase, PolicyRecord, Receipt,
    Remediation, StateCleanup,
};
use crate::state::{self, AttemptDir, AttemptId};
use crate::trace::TraceSink as _;

/// A claimed attempt: the state every phase shares, and the only place its
/// refused receipt is written.
///
/// Fields drop in declaration order, which is the order the run's end needs:
/// the uncontained-run guard settles its markers after the run's tree (a
/// local of [`Attempt::run`], so gone before any field) and through the
/// persistence seam; the trace and control channels close before the
/// persistence worker is waited for; the worker outlives every write.
pub(super) struct Attempt<'a> {
    /// The uncontained-run markers of a `none` run, armed just before
    /// release (audit 6 F1); they settle when this drops.
    uncontained: Option<state::UncontainedRun>,
    ctx: &'a Context,
    args: &'a RunArgs,
    plan: Plan,
    attempt_id: AttemptId,
    attempt_dir: AttemptDir,
    /// The §8.2 preparation budget, running since before the claim.
    budget: Budget,
    record: AttemptRecord,
    journal: Journal,
    control: Option<ControlSink>,
    /// Every `OURO_JAIL_TEST_*` variable in force, read once at the claim
    /// and recorded in jail state and in every receipt with native details.
    test_seams: Option<serde_json::Value>,
    /// This thread's persistence seam, forwarding to `persister` until it
    /// drops.
    _forwarding: state::Installed,
    /// The worker every durable write runs on (§13.3); it holds the lease.
    persister: state::Persister,
    signals: Option<signals::SignalPipe>,
}

/// What [`Attempt::prepare`] made: the boundary with the target blocked, and
/// the proxy directory the platform bound its socket in.
struct Prepared {
    execution: Box<dyn PreparedExecution>,
    proxy: Option<ProxyDirHandoff>,
}

/// What the supervision loop carries from release to settlement.
struct Supervision {
    /// The wall deadline handed to every wait (§6.4).
    wall: Option<Instant>,
    /// The first error after release, which the report names (the first
    /// cause wins).
    outcome_error: Option<JailError>,
    /// Whether the platform reported an evidence loss while the loop ran; a
    /// class degraded at settlement without one is reported there.
    platform_loss_reported: bool,
    /// Receipts with the persistence worker, acknowledged in order once
    /// durable (§13.3).
    in_flight: VecDeque<InFlight>,
}

/// What one run event asks of the loop.
enum Step {
    /// Wait for the next event.
    Wait,
    /// The target's end is known: settle.
    Ended,
    /// The target exec failed: refuse (§8.1).
    Refused(JailError),
}

impl<'a> Attempt<'a> {
    /// §8.1 step 1 up to the claim: allocates and locks private state, opens
    /// the channels that carry a refusal, and claims the attempt.
    ///
    /// The channels are opened before the claim (I01), so once an attempt is
    /// claimed every exit can write its receipt.
    ///
    /// # Errors
    /// Whatever stops the claim. Nothing is claimed then, so there is no
    /// attempt to write a refused receipt for.
    pub(super) fn claim(
        ctx: &'a Context,
        args: &'a RunArgs,
        plan: Plan,
        attempt_id: AttemptId,
        budget: Budget,
        signals: Option<signals::SignalPipe>,
        argv_digest: Option<String>,
    ) -> Result<Self, JailError> {
        let attempt_dir = AttemptDir::new(&plan.data_dir, &attempt_id);
        attempt_dir.create(&plan.data_dir)?;
        // §7: an existing attempt root holds no jail-owned artifact at all.
        // Checked before the lease, so a `jail.lock` found here is not this
        // supervisor's.
        state::check_fresh_attempt(&attempt_dir)?;
        let Some(lease) = state::Lease::acquire(&attempt_dir.lock_path())? else {
            return Err(JailError::new(
                ErrorCode::AttemptExists,
                ErrorStage::Resolving,
                Remediation::InspectState,
                "another live supervisor holds this attempt's lease".to_owned(),
            ));
        };
        // §13.3: from here on every durable write runs on the persistence
        // worker, and this thread waits for each step within its progress
        // budget: a stalled disk ends a wait, it never holds the supervisor.
        let mut persister = state::Persister::start().map_err(|error| {
            JailError::new(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::Retry,
                format!("the persistence worker could not be started: {error}"),
            )
        })?;
        // The lease lives as long as persistence work may: when the run
        // returns with a write stalled in the kernel, it is not released
        // (only the end of the whole process frees it), so no `gc` can write
        // the attempt's records under a rename that may still land.
        persister.hold_lease(lease);
        let forwarding = state::install(persister.forwarding());
        let control = open_control(args)?;
        let trace = open_trace(ctx, args, &attempt_dir)?;
        // A loss note names the classes this attempt covers.
        if let Ok(mut writer) = trace.lock() {
            writer.set_stream_classes(&stream_classes(&plan));
        }
        let journal = Journal::new(attempt_id.as_str(), trace);
        let test_seams = state::test_seams();
        claim_attempt(&attempt_dir, &attempt_id, ctx, test_seams.as_ref())?;
        let record = first_record(ctx, &plan, &attempt_id, argv_digest);
        Ok(Attempt {
            uncontained: None,
            ctx,
            args,
            plan,
            attempt_id,
            attempt_dir,
            budget,
            record,
            journal,
            control,
            test_seams,
            _forwarding: forwarding,
            persister,
            signals,
        })
    }

    /// Runs the claimed attempt to its last receipt and reports it.
    ///
    /// A report, never an error: every failure from here on is written into
    /// a receipt (I01), through [`Attempt::refuse`] before the target runs
    /// and through [`Attempt::settle`] after.
    pub(super) fn run(mut self, request: PlanRequest, argv: Vec<Vec<u8>>) -> RunReport {
        let prepared = match self.prepare(request, argv) {
            Ok(prepared) => prepared,
            Err(error) => return self.refuse(&error),
        };
        // §8.1 step 5 is the last point at which nothing has been created:
        // from here on a refusal tears the boundary down first.
        if let Err(error) = self.register(&prepared).and_then(|()| self.gate()) {
            return self.abort_and_refuse(prepared, &error);
        }
        let mut running = match self.release(prepared) {
            Ok(running) => running,
            Err(error) => return self.refuse(&error),
        };
        let mut supervision = Supervision {
            wall: wall_deadline(&self.plan),
            outcome_error: None,
            platform_loss_reported: false,
            in_flight: VecDeque::new(),
        };
        // `running` outlives the refused receipt: it is dropped only once
        // this function returns.
        if let Err(error) = self.supervise(running.as_mut(), &mut supervision) {
            return self.refuse(&error);
        }
        self.settle(running.as_mut(), supervision)
    }

    // -----------------------------------------------------------------------
    // Before release
    // -----------------------------------------------------------------------

    /// §8.1 steps 2 to 5: probes, stages vendor state and the proxy
    /// directory, and has the platform create the boundary and the blocked
    /// launcher, its last step. Nothing exists to tear down when this fails.
    ///
    /// # Errors
    /// The refusal of the step that failed.
    fn prepare(&mut self, request: PlanRequest, argv: Vec<Vec<u8>>) -> Result<Prepared, JailError> {
        // A failed policy.json write is a refusal like every other failure
        // before exec.
        write_policy_file(&self.attempt_dir, &self.plan)?;
        // Step 2: probe the selected mechanisms.
        self.checkpoint(ErrorStage::Probing)?;
        let capabilities = self.ctx.platform.probe(&request);
        if let Some(error) = first_unsatisfied(&self.plan.resolved.requirements, &capabilities) {
            return Err(error);
        }
        // §8.1 step 2 and §12: register vendor state before creating it,
        // then stage credentials into it, before any boundary.
        self.checkpoint(ErrorStage::Preparing)?;
        let launch = prepare_launch(
            &self.attempt_dir,
            &self.plan,
            &mut self.record,
            self.budget.deadline,
        )?;
        // §10: the proxy directory is registered before it is created,
        // outside every shared root, for a proxy-mode profile only.
        let proxy = prepare_proxy_dir(&self.attempt_dir, &self.plan)?;
        // Steps 3 to 5: create the boundary and the blocked launcher.
        let execution = self.ctx.platform.prepare(
            PreparedPlan {
                attempt_id: self.attempt_id.as_str().to_owned(),
                attempt_dir: self.attempt_dir.root().to_path_buf(),
                request,
                argv,
                prepare_deadline: self.budget.deadline,
                workspace: self.plan.workspace.clone(),
                config_dir: self.plan.config_dir.clone(),
                // The staged objects, bound by descriptor.
                launch,
                proxy: proxy.clone(),
            },
            Sinks {
                trace: Some(Arc::clone(&self.journal.trace)),
            },
        )?;
        Ok(Prepared { execution, proxy })
    }

    /// Refuses when the preparation budget is spent or a signal asked this
    /// supervisor to stop (§8.2, §8.3). Both are checked, so the signal pipe
    /// is drained either way.
    fn checkpoint(&self, stage: ErrorStage) -> Result<(), JailError> {
        self.budget
            .check(stage)
            .and(interrupted(self.signals.as_ref(), stage))
    }

    /// Records the boundary that now exists and announces `prepared`: the
    /// boundary's facts and what it applied, the proxy socket and the
    /// boundary in jail state (§7), then the prepared receipt and its control
    /// message (§8.2). A failure is refused after the boundary's teardown, and
    /// the refused receipt reports what was actually applied (§13.2 row 4).
    ///
    /// # Errors
    /// The refusal of the step that failed.
    fn register(&mut self, prepared: &Prepared) -> Result<(), JailError> {
        // §8.3 "The supervisor must not retain writable copies that postpone
        // EOF": every process that needs the caller's stdout has it by now,
        // so the binary, whose `run` never writes stdout, lets its copy go.
        // Only the binary opts in: an in-process caller keeps its stdout.
        if RELEASE_STDOUT_AFTER_PREPARE.load(std::sync::atomic::Ordering::SeqCst) {
            release_own_stdout();
        }
        let boundary = prepared.execution.boundary();
        apply_boundary(&mut self.record, &boundary, self.plan.profile());
        if let Some(applied) = prepared.execution.applied() {
            self.record.applied = applied;
        }
        // The test seams in force are recorded in every receipt that has
        // native details (a receipt before any boundary has none; jail state
        // records them from the claim on).
        if let (Some(seams), Some(native)) = (
            self.test_seams.as_ref(),
            self.record.lifetime.native.as_mut(),
        ) {
            native
                .details
                .insert("test_seams".to_owned(), seams.clone());
        }
        // The proxy socket node the platform bound, recorded so `gc` can
        // remove exactly it after a crash (§14.2).
        if let Some(socket) = prepared
            .proxy
            .as_ref()
            .and_then(|handoff| handoff.socket.get())
        {
            state::record_proxy_socket(&self.attempt_dir, socket)?;
        }
        // §7: the state file names the registered execution boundary, so
        // crash reconciliation and GC can identify resources without parsing
        // a receipt.
        register_boundary_in_state(&self.attempt_dir, &boundary)?;
        // §8.2: the preparation budget covers steps 1 to 5. An owner is never
        // told an attempt is ready after its preparation ran out of time.
        self.budget.check(ErrorStage::Preparing)?;
        merge_wall_limit(&mut self.record, &self.plan);
        self.journal.lifecycle("prepared");
        let receipt = self.persist(state::Site::PreparedReceipt, Phase::Prepared)?;
        send_control(self.control.as_mut(), ControlKind::Prepared, &receipt);
        Ok(())
    }

    /// Step 6 (§8.2): waits for a valid external release, or releases
    /// locally, then readies the supervisor for an untrusted target. A
    /// failure is refused after the boundary's teardown.
    ///
    /// # Errors
    /// The gate's refusal, or a `none` run's markers that cannot be armed.
    fn gate(&mut self) -> Result<(), JailError> {
        self.budget.check(ErrorStage::Prepared)?;
        match self.args.gate_fd {
            None => interrupted(self.signals.as_ref(), ErrorStage::Prepared)?,
            Some(fd) => {
                let expectation = GateExpectation {
                    attempt_id: self.attempt_id.as_str().to_owned(),
                    policy_digest: self.plan.resolved.digest.clone(),
                };
                await_release(fd, &expectation, GATE_WAIT, self.signals.as_ref())?;
            }
        }
        // §9.3 / X06: before the untrusted target execs, the supervisor makes
        // itself non-dumpable so a same-uid peer that can address it (a
        // `none` child, whose target shares the host pid namespace) cannot
        // read its /proc/<pid>/{fd,environ,mem} (its live trace and control
        // channels and the operator environment) nor `ptrace` it. The lock is
        // the kernel's dumpable check, not host Yama (which a peer can waive
        // with PR_SET_PTRACER). It is set after the capability probes and the
        // observer's attach to the (execve-reset, dumpable) backend and
        // before release, so no probe fork and no observer attach is
        // affected; children reset dumpable on execve. `doctor`/`gc` exec no
        // untrusted target.
        #[cfg(target_os = "linux")]
        // SAFETY: prctl(PR_SET_DUMPABLE, 0, ...) takes scalars only and cannot fail.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        // Audit 6 F1: an uncontained run makes everything on this host
        // indistinguishable from something its child wrote, from the moment
        // of release. Its live markers go down before release (a run that
        // cannot write them does not start), so concurrent runs refuse every
        // trusted file while it lives; they settle when this attempt drops,
        // after the run's tree is gone, and every later run refuses trusted
        // files that do not postdate that (`refuse_stale_trusted_file`).
        if self.plan.profile() == ProfileName::None {
            self.uncontained = Some(state::UncontainedRun::arm(
                &[&self.plan.data_dir, &self.plan.config_dir],
                self.attempt_id.as_str(),
            )?);
        }
        Ok(())
    }

    /// Step 7: the launcher execs the exact target argv.
    ///
    /// # Errors
    /// The release's refusal. What the platform's teardown after it
    /// established is already in the record (§13.2 row 4), so the refused
    /// receipt carries the verified tree and vendor state can be removed
    /// rather than retained.
    fn release(&mut self, prepared: Prepared) -> Result<Box<dyn RunningExecution>, JailError> {
        prepared.execution.release().map_err(|failure| {
            let ReleaseFailure { error, teardown } = *failure;
            if let Some(teardown) = teardown {
                record_teardown(&mut self.record, &Ok(teardown));
            }
            error
        })
    }

    // -----------------------------------------------------------------------
    // The refusal path
    // -----------------------------------------------------------------------

    /// Writes the `refused` receipt of §13.2 and returns the report for it.
    fn refuse(&mut self, error: &JailError) -> RunReport {
        let record = &mut self.record;
        // A proved exec failure keeps its own kind (§13.2); everything else
        // that reaches here refused before the target ran.
        record.outcome = if record.outcome.kind == OutcomeKind::ExecError {
            Outcome {
                error: Some(error.to_object()),
                ..record.outcome.clone()
            }
        } else {
            Outcome::refused(error)
        };
        record.errors.push(error.to_object());
        record.exec_observed = false;
        self.journal.lifecycle("refused");
        // §12 vendor state on a pre-exec refusal
        refuse_vendor_state(
            &self.attempt_dir,
            &mut self.record,
            self.args,
            &mut self.journal,
        );
        // The proxy stopped with the boundary's teardown.
        let _ = remove_proxy_directory(&self.attempt_dir, &mut self.record);
        let receipt = self.persist_terminal(state::Site::RefusedReceipt, Phase::Refused);
        // Everything that reaches here refused before the target executed,
        // so a persistence failure exits 125 like the refusal itself.
        let exit_code = error.refusal_exit_code();
        match receipt {
            Ok(receipt) => {
                send_control(self.control.as_mut(), ControlKind::Refused, &receipt);
                RunReport {
                    exit_code,
                    receipt: Some(receipt),
                    error: Some(error.clone()),
                    receipt_path: Some(self.attempt_dir.receipt_path()),
                    trace_error: self.journal.loss.clone(),
                    control_dropped: finish_control(self.control.as_mut()),
                    ..RunReport::default()
                }
            }
            // The refusal is still the cause (the first cause wins); the
            // report says the refused receipt did not persist, and no
            // `refused` message acknowledges it.
            Err(write_error) => {
                let mut reported = error.clone();
                reported.message = format!(
                    "{}; the refused receipt was not persisted: {}",
                    reported.message, write_error.message
                );
                let trace_error = self.journal.loss.clone();
                // The refusal and the failed write are in `error`; any other
                // error no durable receipt carries reaches stderr too.
                let unrecorded = unrecorded(
                    &self.record,
                    &self.journal,
                    &[Some(error), trace_error.as_ref()],
                );
                RunReport {
                    exit_code,
                    error: Some(reported),
                    receipt_path: Some(self.attempt_dir.receipt_path()),
                    trace_error,
                    control_dropped: finish_control(self.control.as_mut()),
                    unrecorded,
                    ..RunReport::default()
                }
            }
        }
    }

    /// [`Attempt::refuse`] once a boundary exists: tears it down without
    /// running the target and records what the teardown established
    /// (§13.2 row 4), then refuses.
    fn abort_and_refuse(&mut self, prepared: Prepared, error: &JailError) -> RunReport {
        let teardown = prepared.execution.abort();
        record_teardown(&mut self.record, &teardown);
        self.refuse(error)
    }

    // -----------------------------------------------------------------------
    // While the target runs
    // -----------------------------------------------------------------------

    /// §8.1 step 8: waits for the target's end while enforcing the wall,
    /// signals and evidence; the receipts written meanwhile persist on the
    /// worker and are acknowledged once durable (§13.3).
    ///
    /// # Errors
    /// A target exec that failed, which is refused (§8.1).
    fn supervise(
        &mut self,
        running: &mut dyn RunningExecution,
        run: &mut Supervision,
    ) -> Result<(), JailError> {
        loop {
            self.between_waits(running, run);
            let event = running.wait(Deadline { at: run.wall });
            match self.on_event(running, run, event) {
                Step::Wait => {}
                Step::Ended => return Ok(()),
                Step::Refused(error) => return Err(error),
            }
        }
    }

    /// What every loop iteration checks before it waits again.
    fn between_waits(&mut self, running: &mut dyn RunningExecution, run: &mut Supervision) {
        // Whatever the control reader has room for now.
        if let Some(control) = self.control.as_mut() {
            control.poll();
        }
        if let Some(error) = settle_in_flight(
            &mut run.in_flight,
            false,
            self.control.as_mut(),
            &mut self.journal,
        ) {
            persistence_failed(running, &mut self.record, &mut run.outcome_error, error);
        }
        // §13.3 + I07: a trace-sink failure (budget exhausted, external
        // consumer stalled past its deadline) is evidence loss, and under
        // strict it stops the attempt exactly like the tracer-queue path
        // does. Checking here means the stop does not wait for the next event
        // to notice it.
        if let Some(error) = self.journal.take_new_loss() {
            let stop = self.strict().then_some(StopReason::EvidenceLoss);
            self.running_error(running, run, error, stop);
        }
        if self
            .signals
            .as_ref()
            .is_some_and(signals::SignalPipe::triggered)
        {
            stop(running, &mut self.record, StopReason::OperatorSignal);
        }
        // A detected integrity loss reaches the receipt now, not only at the
        // end.
        if self.record.lifetime.integrity != "lost" && running.integrity_lost() {
            self.record.lifetime.integrity = "lost".to_owned();
            self.record.lifetime.tree_empty = None;
            self.record.lifetime.verified_at = None;
            let phase = if self.record.exec_observed {
                Phase::Enforced
            } else {
                Phase::Prepared
            };
            // Persisted by the worker; a failure, or no progress within the
            // budget, stops the tree (§7) when the loop sees it.
            match self.submit(state::Site::IntegrityReceipt, phase) {
                Ok(write) => run.in_flight.push_back(write),
                Err(error) => {
                    persistence_failed(running, &mut self.record, &mut run.outcome_error, error);
                }
            }
        }
    }

    /// Records one run event and says what the loop does next.
    fn on_event(
        &mut self,
        running: &mut dyn RunningExecution,
        run: &mut Supervision,
        event: RunEvent,
    ) -> Step {
        match event {
            RunEvent::Poll => {}
            RunEvent::StdioFailed {
                reason,
                after_target_end,
            } => {
                let error = JailError::new(
                    ErrorCode::StdioFailed,
                    ErrorStage::Running,
                    Remediation::Configuration,
                    reason,
                );
                let stop = (!after_target_end).then_some(StopReason::StdioFailure);
                self.running_error(running, run, error, stop);
            }
            RunEvent::ExecConfirmed => self.exec_confirmed(running, run),
            // §6.4: "Deadline or requested termination preserves the observed
            // code/signal and records its cause." Only the fields this event
            // establishes are written; `cause` and `error` were set by
            // whatever asked for the termination and must survive it.
            RunEvent::TargetExited { code } => {
                self.record.outcome.kind = OutcomeKind::Exited;
                self.record.outcome.code = Some(code);
                self.record.outcome.signal = None;
                return Step::Ended;
            }
            RunEvent::TargetSignaled { signal } => {
                self.record.outcome.kind = OutcomeKind::Signaled;
                self.record.outcome.code = None;
                self.record.outcome.signal = Some(signal);
                return Step::Ended;
            }
            RunEvent::ExecError { errno, detail } => {
                return Step::Refused(self.exec_failed(running, run, &errno, detail));
            }
            RunEvent::CommandForbidden { pattern } => {
                let error = JailError::new(
                    ErrorCode::CommandForbidden,
                    ErrorStage::Running,
                    Remediation::Configuration,
                    format!("command matched forbidden pattern: {pattern}"),
                );
                self.running_error(running, run, error, Some(StopReason::CommandForbidden));
            }
            RunEvent::WallExpired => self.wall_expired(running),
            RunEvent::EvidenceLost {
                reason,
                after_target_end,
            } => {
                let error = JailError::new(
                    ErrorCode::EvidenceLost,
                    ErrorStage::Running,
                    Remediation::InspectState,
                    reason,
                );
                run.platform_loss_reported = true;
                // A loss after the target's own end is recorded (the error,
                // and exit 1) but it is not a stop the supervisor acted on:
                // the target's end already was the termination trigger
                // (§9.3), so it never becomes the cause.
                let stop = (self.strict() && !after_target_end).then_some(StopReason::EvidenceLoss);
                self.running_error(running, run, error, stop);
            }
            // §6.4: the same honest unknown, and a coded error.
            RunEvent::ExecUnconfirmed { reason } => {
                self.ended_unknown(running, reason);
                let error = JailError::new(
                    ErrorCode::ExecUnconfirmed,
                    ErrorStage::Running,
                    Remediation::Configuration,
                    "with observation off the target's exec could not be confirmed: it ended \
                     before the supervisor saw its new image, so whether it ran is unknown; \
                     run with --observe on to confirm it"
                        .to_owned(),
                );
                self.running_error(running, run, error, None);
                return Step::Ended;
            }
            RunEvent::Unknown { reason } => {
                self.ended_unknown(running, reason);
                return Step::Ended;
            }
        }
        Step::Wait
    }

    /// Records an error raised while the target runs: in `errors[]`, as the
    /// reported error unless one came first, and, with `stop`, as the stop
    /// the supervisor asks for (whose cause the first stop keeps).
    fn running_error(
        &mut self,
        running: &mut dyn RunningExecution,
        run: &mut Supervision,
        error: JailError,
        stop_for: Option<StopReason>,
    ) {
        self.record.errors.push(error.to_object());
        if let Some(reason) = stop_for {
            stop(running, &mut self.record, reason);
        }
        run.outcome_error.get_or_insert(error);
    }

    /// §13.2: "Limits report hits in `applied.limits[].hit` with
    /// `outcome.cause`". The expiry is the platform's report of the wall it
    /// enforces (on Linux its own boot-clock deadline, armed at release), so
    /// the `wall` row it applied is hit. The first stop wins (see `stop`): an
    /// expiry during another stop's grace is the limit's hit, not the cause.
    fn wall_expired(&mut self, running: &mut dyn RunningExecution) {
        if let Some(wall) = self
            .record
            .applied
            .limits
            .iter_mut()
            .find(|limit| limit.key == "wall" && limit.applied)
        {
            wall.hit = Some(true);
        }
        stop(running, &mut self.record, StopReason::WallExpiry);
    }

    /// §11.2: the one confirmed exec of the attempt. Its enforced receipt is
    /// persisted by the worker while the loop keeps running, and
    /// `exec_confirmed` is sent once it is durable, never before. §7:
    /// "Failed/ambiguous persistence ... after exec it stops the tree and
    /// leaves an incomplete receipt if necessary": a failure, or no progress
    /// within the budget, stops the tree unacknowledged.
    fn exec_confirmed(&mut self, running: &mut dyn RunningExecution, run: &mut Supervision) {
        // A repeat would advance the receipt revision and publish a second
        // `exec_confirmed` for the same fact.
        if self.record.exec_observed {
            return;
        }
        self.record.exec_observed = true;
        self.journal.lifecycle("exec_confirmed");
        match self.submit(state::Site::EnforcedReceipt, Phase::Enforced) {
            Ok(mut write) => {
                write.ack = Some(ControlKind::ExecConfirmed);
                run.in_flight.push_back(write);
            }
            Err(error) => {
                persistence_failed(running, &mut self.record, &mut run.outcome_error, error);
            }
        }
    }

    /// §8.1: an unsuccessful target exec is a pre-exec failure with its own
    /// outcome kind (§13.2). It is not a refusal of the attempt: release
    /// happened and the kernel answered. Returns the error it is refused
    /// with.
    fn exec_failed(
        &mut self,
        running: &mut dyn RunningExecution,
        run: &mut Supervision,
        errno: &str,
        detail: Option<crate::platform::ExecFailureDetail>,
    ) -> JailError {
        self.record.outcome = Outcome::exec_error(errno);
        // §13.2 row 4, "true / timestamp only after teardown verification":
        // every contained attempt verifies the teardown of a failed exec, so
        // the refused receipt says what it established and vendor state can
        // be removed.
        if self.plan.profile().is_contained() {
            let tree = running.wait_tree(TREE_BUDGET);
            record_tree(&mut self.record, &tree);
        }
        // X04: the errno stays in `cause`; a missing interpreter, which the
        // kernel reports as ENOENT like a missing program, takes its own code
        // so the two differ in a machine field.
        let error = JailError::new(
            detail.map_or(
                ErrorCode::ExecFailed,
                crate::platform::ExecFailureDetail::error_code,
            ),
            ErrorStage::Released,
            Remediation::Configuration,
            match detail {
                Some(detail) => format!(
                    "the target exec failed with {errno}: {}",
                    detail.explanation()
                ),
                None => format!("the target exec failed with {errno}"),
            },
        );
        // A receipt still with the worker lands (or is given up on) before
        // the refused one.
        if let Some(failure) = settle_in_flight(
            &mut run.in_flight,
            true,
            self.control.as_mut(),
            &mut self.journal,
        ) {
            self.record.errors.push(failure.to_object());
        }
        error
    }

    /// An end whose outcome is unknown (§6.4). A resource event the
    /// supervisor itself acted on is the cause even when the target's own
    /// end is not observable: the ambiguity is the outcome's kind, not its
    /// cause.
    fn ended_unknown(&mut self, running: &mut dyn RunningExecution, reason: String) {
        let outcome = &mut self.record.outcome;
        outcome.kind = OutcomeKind::Unknown;
        outcome.code = None;
        outcome.signal = None;
        if let Some(cause) = running.limit_cause() {
            outcome.cause.get_or_insert(cause);
        }
        outcome.cause.get_or_insert(reason);
    }

    // -----------------------------------------------------------------------
    // Settlement
    // -----------------------------------------------------------------------

    /// §8.1 step 9: verifies tree death, drains observations, cleans what
    /// the tree's end permits and persists the terminal receipt.
    fn settle(&mut self, running: &mut dyn RunningExecution, mut run: Supervision) -> RunReport {
        // §8.1 step 8: "Target exit triggers termination of remaining attempt
        // descendants", and §13.3: "Do not wait forever for a writer while
        // descendants continue running": the rest of the tree is ended before
        // the receipts still with the worker are waited for.
        let tree = running.wait_tree(TREE_BUDGET);
        // What the worker still holds is waited for within its budget and
        // acknowledged in order before any terminal message. The loop is
        // over, so a failure here stopped nothing: it is a tool error, not a
        // stop cause.
        if let Some(error) = settle_in_flight(
            &mut run.in_flight,
            true,
            self.control.as_mut(),
            &mut self.journal,
        ) {
            persistence_failed_after(&mut self.record, &mut run.outcome_error, error);
        }
        self.record_final_facts(running, &mut run);
        // The last nonsettled phase without a confirmed exec is prepared
        // (§8.1).
        let prepared_integrity = self.record.lifetime.integrity.clone();
        record_tree(&mut self.record, &tree);
        let settled = tree.tree_empty == Some(true) && self.record.lifetime.integrity == "verified";
        // §13.2: "If tree death itself is unknown, retain the last nonsettled
        // phase and update its outcome/coverage/error as unknown." `enforced`
        // is the phase after a confirmed target exec (§8.1).
        let phase = if settled {
            Phase::Settled
        } else if self.record.exec_observed {
            Phase::Enforced
        } else {
            // Without a confirmed exec the last nonsettled phase is
            // `prepared`. Its integrity stays the prepared one unless a loss
            // was detected: an unknown tree end does not unmake the verified
            // boundary.
            if self.record.lifetime.integrity == "pending" {
                self.record.lifetime.integrity = prepared_integrity;
            }
            Phase::Prepared
        };
        self.clean_up(settled, phase, &mut run.outcome_error);
        let tree_error = (!settled).then(|| {
            let error = tree_unknown(&self.record);
            self.record.errors.push(error.to_object());
            error
        });
        if let Some(error) = remove_proxy_directory(&self.attempt_dir, &mut self.record) {
            // Its state record is persistence after exec.
            run.outcome_error
                .get_or_insert(error.in_stage(ErrorStage::Reconciling));
        }
        // §13.3 terminal drain, before the settled receipt is written:
        // whatever the external trace consumer has not accepted within the
        // no-progress deadline is evidence loss, and that loss belongs in the
        // receipt that summarizes what was lost. (The receipt's own final
        // note is drained once more after it is sent.)
        if let Ok(mut sink) = self.journal.trace.lock() {
            sink.finish();
        }
        if let Some(error) = self.journal.take_new_loss() {
            self.record.errors.push(error.to_object());
            run.outcome_error.get_or_insert(error);
        }
        if self.journal.loss.is_some() {
            degrade_trace_coverage(&mut self.record, &self.journal);
        }
        let receipt = match self.persist_terminal(state::Site::TerminalReceipt, phase) {
            Ok(receipt) => receipt,
            Err(error) => return self.terminal_unpersisted(error, tree_error, run.outcome_error),
        };
        if let Some(error) = self.journal.loss.clone() {
            run.outcome_error.get_or_insert(error);
        }
        // §8.1: nothing after release is a refusal. An unverified tree is
        // `unsettled`: the target did run, and saying otherwise would tell an
        // owner that no command executed.
        let kind = if settled {
            ControlKind::Settled
        } else {
            ControlKind::Unsettled
        };
        send_control(self.control.as_mut(), kind, &receipt);
        let exit_code = settled_exit_code(
            &self.record,
            self.plan.resolved.snapshot.observation.evidence,
            tree_error.as_ref(),
            run.outcome_error.as_ref(),
        );
        RunReport {
            exit_code,
            receipt: Some(receipt),
            error: tree_error.or(run.outcome_error),
            receipt_path: Some(self.attempt_dir.receipt_path()),
            trace_error: self.journal.loss.clone(),
            // A bounded final drain, then an honest count.
            control_dropped: finish_control(self.control.as_mut()),
            ..RunReport::default()
        }
    }

    /// What the platform knows only once the target ended: a storage
    /// enforcement loss, the final limits and cause, the observer's account
    /// and what the helpers did.
    fn record_final_facts(&mut self, running: &mut dyn RunningExecution, run: &mut Supervision) {
        // Audit 2026-10-08 L2: a storage enforcement loss is recorded in
        // `errors[]`; the applied rows it held no longer claim `applied:
        // true` (see `Storage::limits`), and whether it is `outcome.cause` is
        // decided by when it was found (`limit_cause`, §6.4).
        if let Some(reason) = running.storage_loss() {
            self.record
                .errors
                .push(storage_loss_error(reason).to_object());
        }
        for limit in running.final_limits() {
            if let Some(recorded) = self
                .record
                .applied
                .limits
                .iter_mut()
                .find(|row| row.key == limit.key)
            {
                *recorded = limit;
            }
        }
        if let Some(cause) = running.limit_cause() {
            self.record.outcome.cause.get_or_insert(cause);
        }
        let summary = running.observer_summary();
        // A sink loss that arrived after the last loop iteration, including
        // one the observer's own drain caused while the tree was verified,
        // still belongs in the settled receipt's errors (§13.3: the receipt is
        // the bounded summary of what was lost). Taken after the observer
        // stopped, so the check below knows about it.
        if let Some(error) = self.journal.take_new_loss() {
            self.record.errors.push(error.to_object());
            run.outcome_error.get_or_insert(error);
        }
        if let Some(summary) = summary {
            self.record.observer = summary.to_observer_record();
            self.record.coverage = summary.to_coverage();
            // A loss the platform queued while the tree was being verified,
            // or found only when its observer stopped, never reached the
            // loop. Any evidence class degraded at settlement is an
            // `evidence_lost` error and exit 1, whatever the loss's timing;
            // it is never a cause, because nothing was stopped for it. A
            // trace-sink loss the journal reported is not reported again: the
            // classes whose frames the lost sink refused are degraded by that
            // same loss.
            if !run.platform_loss_reported
                && self.journal.loss.is_none()
                && let Some(error) = settlement_loss(&summary)
            {
                self.record.errors.push(error.to_object());
                run.outcome_error.get_or_insert(error);
            }
        }
        // What the helpers did, known now that they stopped.
        if let Some(native) = self.record.lifetime.native.as_mut() {
            native.details.extend(running.final_native_details());
        }
    }

    /// Vendor state and managed scratch at settlement (§8.1 step 9, §12,
    /// §14.2): removed only after verified tree death, since until then the
    /// child could still be writing to them, and after an unverified one
    /// something may still hold them; retained otherwise, with the receipt
    /// saying the cleanup did not complete. With vendor state, the settled
    /// receipt is persisted as `pending` first, then cleaned, then the result
    /// recorded.
    fn clean_up(&mut self, settled: bool, phase: Phase, outcome_error: &mut Option<JailError>) {
        if !matches!(state::vendor_registration(&self.attempt_dir), Ok(Some(_))) {
            if settled {
                match remove_managed_scratch(
                    &self.attempt_dir,
                    &self.plan,
                    cleanup::Limits::DEFAULT,
                ) {
                    Ok(status) => self.record.state_cleanup = status,
                    Err(reason) => {
                        self.record.state_cleanup = StateCleanup::Pending;
                        self.record.cleanup_error = Some(reason);
                    }
                }
            }
            return;
        }
        if !settled {
            if let Some(error) = retain_vendor_state(&self.attempt_dir, &mut self.record) {
                persistence_failed_after(
                    &mut self.record,
                    outcome_error,
                    error.in_stage(ErrorStage::Reconciling),
                );
            }
            return;
        }
        self.record.state_cleanup = StateCleanup::Pending;
        self.record.cleanup_error = None;
        if let Err(error) = self.persist(state::Site::PendingReceipt, phase) {
            // No durable settled receipt, so nothing would permit a later
            // `gc` to finish a removal started now. A persistence failure
            // after exec is a tool error (exit 1), recorded but not a stop
            // cause.
            self.record.cleanup_error = Some("state_write_failed".to_owned());
            persistence_failed_after(
                &mut self.record,
                outcome_error,
                error.in_stage(ErrorStage::Reconciling),
            );
            return;
        }
        let vendor = cleanup::remove_vendor_state(&self.attempt_dir, cleanup::Limits::DEFAULT);
        // The cleanup record is persistence after exec.
        if let Some(error) = vendor.record_error.clone() {
            persistence_failed_after(
                &mut self.record,
                outcome_error,
                error.in_stage(ErrorStage::Settled),
            );
        }
        let scratch =
            remove_managed_scratch(&self.attempt_dir, &self.plan, cleanup::Limits::DEFAULT);
        match (vendor.status, scratch) {
            (StateCleanup::Complete, Ok(_)) => {
                self.record.state_cleanup = StateCleanup::Complete;
            }
            (StateCleanup::Complete, Err(reason)) => {
                self.record.state_cleanup = StateCleanup::Pending;
                self.record.cleanup_error = Some(reason);
            }
            (status, _) => {
                self.record.state_cleanup = status;
                self.record.cleanup_error = vendor.reason;
            }
        }
    }

    /// The report when the terminal receipt did not persist: the transition
    /// is not acknowledged and the receipt on disk stays the last one that
    /// did. A tool error after exec, and the first cause is the reported
    /// error; the failure, and every error the last durable receipt does not
    /// carry, reach stderr instead.
    fn terminal_unpersisted(
        &mut self,
        error: JailError,
        tree_error: Option<JailError>,
        outcome_error: Option<JailError>,
    ) -> RunReport {
        let error = error.in_stage(ErrorStage::Reconciling);
        self.record.errors.push(error.to_object());
        let reported = tree_error.or(outcome_error).unwrap_or(error);
        let trace_error = self.journal.loss.clone();
        let unrecorded = unrecorded(
            &self.record,
            &self.journal,
            &[Some(&reported), trace_error.as_ref()],
        );
        RunReport {
            exit_code: 1,
            error: Some(reported),
            receipt_path: Some(self.attempt_dir.receipt_path()),
            trace_error,
            control_dropped: finish_control(self.control.as_mut()),
            unrecorded,
            ..RunReport::default()
        }
    }

    // -----------------------------------------------------------------------
    // Receipts
    // -----------------------------------------------------------------------

    fn strict(&self) -> bool {
        self.plan.resolved.snapshot.observation.evidence == EvidenceMode::Strict
    }

    /// Persists the receipt for `phase` on this thread (§13.2).
    fn persist(&mut self, site: state::Site, phase: Phase) -> Result<Receipt, JailError> {
        super::persist(
            site,
            &self.attempt_dir,
            &mut self.record,
            phase,
            self.args,
            &mut self.journal,
        )
    }

    /// Persists the attempt's final receipt (§13.3: its note may use the
    /// reserve).
    fn persist_terminal(&mut self, site: state::Site, phase: Phase) -> Result<Receipt, JailError> {
        persist_terminal(
            site,
            &self.attempt_dir,
            &mut self.record,
            phase,
            self.args,
            &mut self.journal,
        )
    }

    /// Hands the receipt for `phase` to the persistence worker (§13.3).
    fn submit(&mut self, site: state::Site, phase: Phase) -> Result<InFlight, JailError> {
        submit_receipt(
            &self.persister,
            site,
            &self.attempt_dir,
            &mut self.record,
            phase,
            self.args,
            &self.journal,
        )
    }
}

/// The record a claimed attempt starts from: nothing applied, nothing
/// observed, every lifecycle fact pending.
fn first_record(
    ctx: &Context,
    plan: &Plan,
    attempt_id: &AttemptId,
    argv_digest: Option<String>,
) -> AttemptRecord {
    let now = SystemTime::now();
    let containment = if plan.profile().is_contained() {
        Containment::Pending
    } else {
        // I08: `none` is unprotected in every receipt, including a refusal.
        Containment::None
    };
    AttemptRecord {
        attempt_id: attempt_id.as_str().to_owned(),
        revision: 1,
        platform: platform_record(ctx),
        jail: JailRecord {
            component: "ouro-jail".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            backend: None,
            backend_version: None,
        },
        policy: PolicyRecord {
            name: plan.resolved.policy_name.clone(),
            digest: plan.resolved.digest.clone(),
            observe: plan.resolved.snapshot.observation.mode,
            evidence: plan.resolved.snapshot.observation.evidence,
            requirements: plan.resolved.requirements.clone(),
            // §13.2: the receipt's grants are the explicit operator grants,
            // not the profile baseline every `tool` run gets.
            grants: plan.resolved.grants.clone(),
        },
        containment,
        exec_observed: false,
        argv_digest,
        applied: pending_applied(plan),
        observer: CoverageSummary::unobserved().to_observer_record(),
        coverage: CoverageSummary::unobserved().to_coverage(),
        process: None,
        lifetime: Lifetime::pending(),
        outcome: Outcome::pending(),
        state_cleanup: cleanup::not_needed(),
        cleanup_error: None,
        created_at: now,
        updated_at: now,
        errors: Vec::new(),
        credentials: Vec::new(),
    }
}

/// The error an unverified tree end records (§9.3): a detected integrity
/// loss is not a budget overrun.
fn tree_unknown(record: &AttemptRecord) -> JailError {
    let message = if record.lifetime.integrity == "lost" {
        "the lifetime boundary's integrity was lost (a membership escape, a replaced \
         identity or a failed verification was detected), so tree death is unknown"
    } else {
        "tree death could not be verified within its budget"
    };
    JailError::new(
        ErrorCode::TreeUnknown,
        ErrorStage::Reconciling,
        Remediation::InspectState,
        message.to_owned(),
    )
}

/// The exit status of an attempt whose terminal receipt persisted (§6.4).
///
/// In best-effort mode it is the child's own when the child ended
/// naturally: the evidence gap stays in the receipt's errors, in the
/// degraded coverage and on stderr, but a wrapper that trusts the exit code
/// sees the child's status, not `evidence_lost`'s 1. Strict mode keeps
/// failing loudly, as does any other error.
fn settled_exit_code(
    record: &AttemptRecord,
    evidence: EvidenceMode,
    tree_error: Option<&JailError>,
    outcome_error: Option<&JailError>,
) -> i32 {
    let best_effort_natural_end = evidence == EvidenceMode::BestEffort
        && record.outcome.kind == OutcomeKind::Exited
        && record.outcome.cause.as_deref() != Some(StopReason::EvidenceLoss.cause())
        && outcome_error.is_none_or(|error| error.code == ErrorCode::EvidenceLost)
        && record
            .errors
            .iter()
            .all(|error| error.code == ErrorCode::EvidenceLost.as_str());
    if let Some(error) = tree_error {
        error.exit_code()
    } else if let Some(error) = outcome_error
        && !best_effort_natural_end
    {
        error.exit_code()
    } else {
        match record.outcome.kind {
            OutcomeKind::Exited => i32::from(record.outcome.code.unwrap_or(0)),
            OutcomeKind::Signaled => {
                128 + i32::try_from(record.outcome.signal.unwrap_or(0)).unwrap_or(0)
            }
            _ => 1,
        }
    }
}
