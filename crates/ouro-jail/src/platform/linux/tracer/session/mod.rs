//! The tracer thread: one `waitpid(-1, __WALL)` loop that owns every child
//! and every tracee of the process, and the §11 bookkeeping that turns its
//! stops into the events of [`super::TracerEvent`]. It ends on its own
//! account of what it answers for ([`Owed`]), not when no child is left.
//!
//! Everything the spec calls a semantic lives here as code:
//!
//! * `Exit` is emitted once, when the last thread of a thread group that was
//!   seen to exec is reaped, and only if that thread is the group leader.
//!   A worker exit is a decrement; a leader that calls `pthread_exit` while
//!   workers live is a zombie the kernel will not report until the group is
//!   empty; a fork child that never execs is tracked and reaped but emits no
//!   `Exit` (§11.2).
//! * `Exec` is emitted only on `PTRACE_EVENT_EXEC`, the confirmed kernel
//!   transition, and carries the pathname snapshot of the entry it was paired
//!   with. A failed `execve` never reaches that event and comes out as
//!   `Syscall { op: Exec, ret: -errno }`. A non-leader exec is followed: the
//!   thread's id becomes the leader's, the in-flight entry moves with it, and
//!   the process keeps the identity it was born with. Whatever the leader
//!   itself had in flight can no longer return: it is abandoned, a gap of its
//!   own classes, and never paired with the exec's syscall exit.
//! * Entry and exit are paired per thread. An exit with no entry is a gap. A
//!   kernel restart code at the exit (`ERESTARTSYS` and its family) is not a
//!   result yet: the kernel decides afterwards whether to re-enter the call
//!   or to return `EINTR`, and the call stays in flight until the
//!   observer has seen that decision — see [`RestartWait`]. A re-entry
//!   produces the one result; an `EINTR` is the result; emitting the code
//!   itself would be the duplicate §11.2 forbids, and dropping it would be
//!   the silence §11.4 forbids. A restart read from a handler's frame, which
//!   the program can rewrite, is believed only when the re-entry is seen.
//! * A read-only open never becomes an event, never takes an in-flight slot
//!   and so is never refused one, and never even costs a second
//!   stop: the tracee is continued from the seccomp stop instead of being
//!   stepped to the syscall exit.
//! * A tracee killed at its seccomp entry stop before the observer resumed
//!   it made no call: the kernel skips a call whose thread has a fatal signal
//!   pending after the trace event (`__seccomp_filter`), so it is neither a
//!   result nor a loss. A call the observer had already let run
//!   when the kill came may have had its effect and stays a gap.
//! * Nothing observed is ever replaced by a guess. Unreadable argument
//!   memory, an undecodable `open_how`, an untracked task and a final status
//!   that cannot be attributed each become a `Gap` with its own reason, its
//!   own counter and the set of operations it affected.
//!
//! The session is one [`Session`] whose handlers live beside what they
//! handle: [`outbox`] delivers events and coalesces loss, [`tasks`] keeps
//! the traced threads and their calls in flight, [`entry`] and [`exit`]
//! pair a call's two stops, [`exec`] confirms a transition, [`restart`]
//! follows a call to the kernel's restart decision, [`args`] snapshots the
//! arguments, [`evidence`] holds the kernel's own facts that corroborate or
//! refute those snapshots, [`owed`] says which children the tracer answers
//! for, and [`seams`] is every `/proc` read and test seam.

mod args;
mod entry;
mod evidence;
mod exec;
mod exit;
mod outbox;
mod owed;
mod restart;
mod seams;
mod tasks;
#[cfg(test)]
mod testkit;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, SyncSender};
use std::time::{Duration, Instant};

use libc::pid_t;

use super::closed_set::ClosedOp;
use super::proc;
use super::sys::{self, Wait};
use super::{
    GapReason, OpSet, TracerConfig, TracerError, TracerEvent, TracerSummary, elapsed_since,
    event_bytes,
};
use crate::platform::linux::seccomp;

use outbox::{CoalescedGap, Queued};
use owed::Owed;
use restart::{Awaiting, RestartWait};
use seams::{LiveProc, ProcView, TRUNCATE_PATH_SEAM, UNMATCHED_EXIT_SEAM, seam_marker};
use tasks::{Process, Task, TaskState, Tasks};

/// How long the tracer keeps trying to hand over the terminal gap and
/// `Finished` after the tree is dead. Nothing is stopped behind them, so this
/// is generous; `finish` ends it immediately by setting the stop flag.
const TERMINAL_DRAIN: Duration = Duration::from_secs(30);

const TERMINAL_POLL: Duration = Duration::from_millis(5);

/// How long a killed tree is given to be reaped before the remaining tracees
/// are recorded as abandoned.
const KILL_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for `/proc/<pid>/status` to show this thread as the
/// tracer after a successful `PTRACE_SEIZE`.
const SEIZE_CONFIRM: Duration = Duration::from_millis(500);

/// What the supervisor shares with the tracer thread.
pub(super) struct Handles {
    pub stop: Arc<AtomicBool>,
    pub shutdown_ns: Arc<AtomicU64>,
    pub tid: Arc<AtomicI32>,
    /// Bytes handed to the channel and not yet taken by the consumer.
    pub handed: Arc<AtomicUsize>,
}

pub(super) fn run(
    launcher: pid_t,
    config: TracerConfig,
    tx: SyncSender<TracerEvent>,
    ready: Sender<Result<(), TracerError>>,
    handles: Handles,
) -> TracerSummary {
    handles.tid.store(sys::gettid(), Ordering::Release);
    let epoch_boottime_ns = config.epoch_boottime_ns;
    let mut session = Session::new(
        config,
        tx,
        Arc::clone(&handles.handed),
        epoch_boottime_ns,
        Box::new(LiveProc),
    );
    match seize_and_confirm(launcher, ensure_wake_handler) {
        Ok(()) => {
            if ready.send(Ok(())).is_err() {
                // The caller went away between spawning and confirming.
                let _ = sys::detach(launcher);
                return session.summary;
            }
        }
        Err(err) => {
            let _ = ready.send(Err(err));
            return session.summary;
        }
    }
    // Attached is the first event, before any bookkeeping that could itself
    // produce one.
    let start_ticks = session.procfs.start_ticks(launcher);
    session.emit(TracerEvent::Attached {
        pid: launcher,
        start_ticks,
    });
    session.register(launcher);
    session.owed = Owed::toward(crate::sys::own_pid(), launcher, &*session.procfs);
    session.beside = session
        .procfs
        .children(crate::sys::own_pid())
        .into_iter()
        .filter_map(|pid| session.procfs.start_ticks(pid).map(|birth| (pid, birth)))
        .collect();
    session.run_loop(&handles);
    session.finish(&handles)
}

/// Install the handler that lets `finish` interrupt a blocking `waitpid`.
/// Process-global; the handler does nothing at all, so installing it again
/// is harmless, and a failed install is retried by the next attach rather
/// than remembered.
fn ensure_wake_handler() -> std::io::Result<()> {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if !INSTALLED.load(Ordering::Acquire) {
        sys::install_wake_handler()?;
        INSTALLED.store(true, Ordering::Release);
    }
    Ok(())
}

/// Seize `launcher` once the wake handler is in place. Shutdown interrupts
/// the tracer thread's `waitpid` with the wake signal every few
/// milliseconds; with no handler that signal's default action would end the
/// whole supervisor, so no tracee is taken on without one.
fn seize_and_confirm(
    launcher: pid_t,
    wake_handler: impl FnOnce() -> std::io::Result<()>,
) -> Result<(), TracerError> {
    // The one statement of which architecture the tables cover, so the tracer
    // refuses exactly where `doctor` reports it unsupported.
    if !seccomp::tables_cover(std::env::consts::ARCH) {
        return Err(TracerError::UnsupportedArch);
    }
    wake_handler().map_err(|err| TracerError::WakeHandler {
        errno: err.raw_os_error().unwrap_or(0),
    })?;
    sys::seize(launcher, sys::SEIZE_OPTIONS).map_err(|err| TracerError::Seize {
        pid: launcher,
        errno: err.raw_os_error().unwrap_or(0),
    })?;
    // PTRACE_SEIZE does not stop the tracee, so the seize is confirmed from
    // the kernel's own view of it: `TracerPid` names the tracing *thread*,
    // which is this one.
    let me = sys::gettid();
    let deadline = Instant::now() + SEIZE_CONFIRM;
    loop {
        match proc::tracer_pid(launcher) {
            Some(tracer) if tracer == me => return Ok(()),
            Some(tracer) => {
                return Err(TracerError::SeizedByAnotherThread {
                    pid: launcher,
                    tracer,
                });
            }
            None => {
                if Instant::now() >= deadline {
                    return Err(TracerError::SeizeUnconfirmed { pid: launcher });
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// The tracer thread's state: the outbox, the traced threads and processes
/// with the calls they have in flight, and the account the thread ends on.
struct Session {
    config: TracerConfig,
    tx: SyncSender<TracerEvent>,
    /// Bytes of events handed to the channel that the consumer has not taken
    /// yet: part of the budget, given back by [`super::Events`].
    handed: Arc<AtomicUsize>,
    /// Events not yet handed to the channel, oldest first.
    pending: VecDeque<Queued>,
    pending_bytes: usize,
    lifecycle_pending: usize,
    /// The byte ceiling the outbox admits against: buffered and handed-over
    /// bytes together ([`super::QueueBounds::bytes_max`]).
    bytes_max: usize,
    /// The byte ceiling results admit against: `bytes_max` short of the
    /// lifecycle reserve, so the reserve stays free for lifecycle facts
    /// ([`super::QueueBounds::result_bytes_max`]).
    result_bytes_max: usize,
    /// True while the consumer is behind: results are dropped without
    /// waiting another second to find out again.
    stalled: bool,
    disconnected: bool,
    /// The loss being coalesced, one summary per reason, per §11.4
    /// ("Coalesce repeated losses into bounded interval summaries"). At most
    /// one entry per [`GapReason`], so it is bounded whatever the child does.
    coalesced: Vec<CoalescedGap>,
    /// The `CLOCK_BOOTTIME` reading at supervisor start. Gap endpoints are
    /// elapsed time since it, not time since boot (§11.4).
    epoch_boottime_ns: u64,
    /// The last moment an event reached the consumer. A gap bounds itself
    /// from here, which is what §11.4 means by the last known healthy point.
    last_healthy_ns: u64,
    summary: TracerSummary,
    tasks: Tasks,
    procs: HashMap<pid_t, Process>,
    /// Threads the kernel destroyed for a reason we saw, with the moment we
    /// may stop expecting their notification. Bounded, and pruned, so a
    /// recycled pid cannot be swallowed by a stale entry.
    retired: HashMap<pid_t, Instant>,
    /// Tracees whose death was reported before their fork event arrived,
    /// with the moment the late fork event can no longer follow. Fork-order
    /// races: the child stopped nothing, ran nothing, and is not loss.
    tracee_deaths: HashMap<pid_t, Instant>,
    scratch: Vec<u8>,
    /// Where task identity comes from: `/proc`, or a test's script.
    procfs: Box<dyn ProcView>,
    // O03 seams: the path substrings that mark a covered call whose path
    // read is forced unreadable, or whose entry is dropped so its exit is
    // unmatched. `None` in the release binary unless the seam is set.
    force_truncate_marker: Option<Vec<u8>>,
    force_unmatched_marker: Option<Vec<u8>>,
    /// Which children, besides the tracees, the tracer answers for.
    owed: Owed,
    /// The children this process had when the tracer attached, by birth. Any
    /// other child that is not a tracee came after — an orphan a subreaper
    /// supervisor adopted from the traced tree — and is owed.
    beside: Vec<(pid_t, u64)>,
}

impl Session {
    fn new(
        config: TracerConfig,
        tx: SyncSender<TracerEvent>,
        handed: Arc<AtomicUsize>,
        epoch_boottime_ns: u64,
        procfs: Box<dyn ProcView>,
    ) -> Self {
        let scratch = vec![0u8; config.path_snapshot_max.max(128)];
        // §11.4 budgets the whole user-space queue: the buffer and what was
        // handed to the channel and not taken yet are admitted against it
        // together. The bounds are the ones the observer plan records.
        let bounds = config.queue_bounds();
        Session {
            config,
            tx,
            handed,
            pending: VecDeque::new(),
            pending_bytes: 0,
            lifecycle_pending: 0,
            bytes_max: bounds.bytes_max,
            result_bytes_max: bounds.result_bytes_max,
            stalled: false,
            disconnected: false,
            coalesced: Vec::new(),
            epoch_boottime_ns,
            last_healthy_ns: elapsed_since(epoch_boottime_ns),
            summary: TracerSummary::default(),
            tasks: Tasks::default(),
            procs: HashMap::new(),
            retired: HashMap::new(),
            tracee_deaths: HashMap::new(),
            scratch,
            procfs,
            force_truncate_marker: seam_marker(TRUNCATE_PATH_SEAM),
            force_unmatched_marker: seam_marker(UNMATCHED_EXIT_SEAM),
            // `run` reads the real one once the launcher is seized; a session
            // built without it owes every child.
            owed: Owed::Every,
            beside: Vec::new(),
        }
    }

    /// Now, as elapsed time since the supervisor started: the base every gap
    /// endpoint is reported on. §11.4 bounds a gap from the last known
    /// healthy point, which is an age and not an instant on the boot clock.
    fn now_ns(&self) -> u64 {
        elapsed_since(self.epoch_boottime_ns)
    }

    fn run_loop(&mut self, handles: &Handles) {
        let mut shutdown: Option<Instant> = None;
        loop {
            if shutdown.is_none() && handles.stop.load(Ordering::Acquire) {
                let budget = Duration::from_nanos(handles.shutdown_ns.load(Ordering::Acquire));
                shutdown = Some(Instant::now() + budget);
            }
            if let Some(deadline) = shutdown {
                if self.tasks.is_empty() {
                    break;
                }
                if Instant::now() >= deadline {
                    self.force_stop();
                    break;
                }
            }
            // Done on its own account. Past this point a blocking wait could
            // only be for a child the tracer does not answer for.
            if self.accounted_for() {
                break;
            }
            // About to block: hand the consumer whatever is still buffered,
            // so a backlog never waits on the tree making its next call.
            self.flush();
            // Blocking, so a stop costs nothing while the tree is busy. The
            // supervisor interrupts it with the wake signal; `EINTR` comes
            // back as `Interrupted` and the loop looks at the flag again.
            match sys::wait_any(0) {
                Wait::Interrupted | Wait::Nothing => continue,
                // Every child and every tracee is gone. Nothing else can
                // arrive, so the tracer is done whether or not it was asked.
                Wait::NoChildren => break,
                Wait::Status { pid, status } => self.handle(pid, status),
            }
        }
    }

    /// The shutdown budget expired with tracees still alive. End them rather
    /// than leave them stopped at a ptrace stop nobody will answer.
    fn force_stop(&mut self) {
        let alive: Vec<pid_t> = self.tasks.tids();
        if alive.is_empty() {
            return;
        }
        // Whatever these tracees were about to do is unobserved, whether or
        // not the kill and the reap below succeed. That is the loss, and it
        // is recorded before anything is attempted. With live tasks beyond
        // the observation boundary, loss is not limited to in-flight calls.
        self.summary.loss.abandoned_tracees += alive.len() as u64;
        self.gap(
            GapReason::TraceesAbandoned,
            OpSet::ALL,
            Some(alive.len() as u64),
        );
        for pid in &alive {
            let _ = sys::kill(*pid, libc::SIGKILL);
            let _ = sys::restart(*pid, sys::PTRACE_CONT, libc::SIGKILL);
        }
        let deadline = Instant::now() + KILL_GRACE;
        while !self.tasks.is_empty() && Instant::now() < deadline {
            match sys::wait_any(libc::WNOHANG) {
                Wait::Status { pid, status } => self.handle(pid, status),
                Wait::NoChildren => break,
                Wait::Nothing | Wait::Interrupted => {
                    std::thread::sleep(TERMINAL_POLL);
                }
            }
        }
        let left = self.tasks.len() as u64;
        if left > 0 {
            // Killed but not even reaped: the kernel will reparent them to
            // init, and their statuses are gone for good.
            self.summary.loss.death_unattributed += left;
            self.gap(GapReason::DeathUnattributed, OpSet::EMPTY, Some(left));
        }
    }

    fn handle(&mut self, pid: pid_t, status: libc::c_int) {
        self.summary.stops += 1;
        // Expired retirements and fork-race ghosts are dropped on every
        // stop, not only when a death is delivered: a clone-and-exec loop
        // can run for a long time without reporting a single one.
        self.prune_retired();
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.handle_death(pid, status);
            return;
        }
        if !libc::WIFSTOPPED(status) {
            return;
        }
        let signal = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xff;
        // A stop from a task we have not seen is the fork ordering race: the
        // child stopped before its parent reported the event that created it.
        self.register(pid);

        if self.tasks.wait(pid).is_some()
            && let Some(inject) = self.handle_restart_stop(pid, signal, event)
        {
            self.restart(pid, inject);
            return;
        }

        let mut inject = 0;
        match event {
            sys::PTRACE_EVENT_SECCOMP => self.handle_entry(pid),
            sys::PTRACE_EVENT_EXEC => self.handle_exec(pid),
            sys::PTRACE_EVENT_FORK | sys::PTRACE_EVENT_VFORK | sys::PTRACE_EVENT_CLONE => {
                self.handle_fork(pid);
            }
            // The thread is about to die. The death itself is reported by
            // `waitpid`, with the status the consumer needs; nothing is
            // emitted here.
            sys::PTRACE_EVENT_EXIT | sys::PTRACE_EVENT_VFORK_DONE => {}
            sys::PTRACE_EVENT_STOP => {
                // Two different stops share this event. `PTRACE_GETSIGINFO`
                // is the documented way to tell them apart: it fails with
                // EINVAL only for a group-stop.
                if sys::is_group_stop(pid) {
                    // Leave it stopped, as whoever sent the signal intended,
                    // and stay its tracer.
                    if let Err(err) = sys::listen(pid) {
                        self.restart_failed(pid, &err);
                    }
                    return;
                }
                // The initial stop of a newly attached child, or a
                // PTRACE_INTERRUPT. Nothing to deliver.
            }
            _ => {
                if signal == sys::SYSCALL_STOP_SIG {
                    self.handle_syscall_stop(pid);
                } else {
                    // An ordinary signal on its way to the tracee.
                    inject = signal;
                }
            }
        }
        self.restart(pid, inject);
    }

    fn restart(&mut self, pid: pid_t, signal: libc::c_int) {
        // A call waiting for the kernel's restart decision is followed one
        // instruction at a time, so that decision is a stop (`RestartWait`);
        // a call in flight is stepped to its syscall exit; anything else
        // runs to its next traced event.
        let request = match self.tasks.get(pid).map(Task::state) {
            Some(TaskState::Restarting(RestartWait {
                awaiting: Awaiting::Decision,
                ..
            })) => sys::PTRACE_SINGLESTEP,
            Some(TaskState::InFlight { .. }) => sys::PTRACE_SYSCALL,
            _ => sys::PTRACE_CONT,
        };
        let fresh = self.tasks.take_fresh(pid);
        match sys::restart(pid, request, signal) {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {
                if fresh {
                    // The entry was taken at this very stop, and the tracee was
                    // killed before it could be resumed from it (at an
                    // unresumed stop only SIGKILL makes the resume fail with
                    // ESRCH). The kernel skips a call whose thread has a fatal
                    // signal pending after the trace event, so this one never
                    // ran: no result, and no loss.
                    self.entry_never_ran(pid);
                }
            }
            Err(err) => self.restart_failed(pid, &err),
        }
    }

    /// Forget the entry of a thread killed at its seccomp stop.
    fn entry_never_ran(&mut self, tid: pid_t) {
        if self.tasks.take_call(tid).is_some() {
            self.summary.killed_at_entry += 1;
        }
    }

    /// A stopped tracee that cannot be restarted would stay stopped forever,
    /// and nothing else in the tree could make progress past it. ESRCH means
    /// it died between its stop and the call, which the next wait reports;
    /// anything else is recorded, and the tracee is killed rather than left.
    fn restart_failed(&mut self, pid: pid_t, err: &std::io::Error) {
        if err.raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        self.summary.loss.restart_failed += 1;
        self.gap(GapReason::RestartFailed, OpSet::EMPTY, Some(1));
        let _ = sys::kill(pid, libc::SIGKILL);
    }

    /// `SIGKILL` a tracee held at a stop this observer has not resumed, so
    /// that what it would do next — the call at an entry stop, the new image
    /// at an exec stop — never runs. `ESRCH` means it is already gone, the
    /// same outcome. False when the signal could not reach a live task.
    fn kill_tracee(tid: pid_t) -> bool {
        match sys::kill(tid, libc::SIGKILL) {
            Ok(()) => true,
            Err(err) => err.raw_os_error() == Some(libc::ESRCH),
        }
    }

    /// An exec whose command-rule verdict could not be enforced the way the
    /// observer enforces it ([`GapReason::ExecDenialFailed`]).
    fn exec_denial_failed(&mut self) {
        self.summary.loss.exec_denials_failed += 1;
        self.gap(
            GapReason::ExecDenialFailed,
            OpSet::of(ClosedOp::Exec),
            Some(1),
        );
    }

    /// The register rewrite that denies an exec failed: the process is
    /// killed instead. One gap whatever the kill does — if it fails too, the
    /// exec it names may run, and that is the same one call.
    fn deny_by_kill(&mut self, tid: pid_t) {
        self.exec_denial_failed();
        let _ = Self::kill_tracee(tid);
    }

    fn finish(mut self, handles: &Handles) -> TracerSummary {
        // Direct children that were never reaped have no route left for their
        // exit status: the supervisor was told not to wait for its own children
        // while a tracer is attached. Only those it answers for count — the
        // backend and any child gained after it attached; a child it was
        // attached beside is its owner's to wait for once this ends.
        let unreaped = self.unreaped();
        if !unreaped.is_empty() {
            self.summary.loss.unreaped_children += unreaped.len() as u64;
            self.gap(
                GapReason::UnreapedChildren,
                OpSet::EMPTY,
                Some(unreaped.len() as u64),
            );
            self.summary.unreaped_children = unreaped;
        }
        self.materialise_gap();
        let finished = TracerEvent::Finished;
        let bytes = event_bytes(&finished);
        self.enqueue(finished, bytes, true);

        // Hand over the backlog. Nothing is stopped behind it, so this waits
        // for a consumer that is slow; `finish` ends it at once by setting
        // the stop flag, and what is still undelivered is in the summary.
        let deadline = Instant::now() + TERMINAL_DRAIN;
        loop {
            self.flush();
            if self.pending.is_empty() || self.disconnected {
                break;
            }
            if Instant::now() >= deadline || handles.stop.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(TERMINAL_POLL);
        }
        // What is still undelivered is lost with the tracer: a result is a
        // dropped result, as a full queue's is; anything else a lifecycle
        // fact.
        for queued in &self.pending {
            if queued.lifecycle {
                self.summary.loss.lifecycle_dropped += 1;
            } else {
                self.summary.loss.queue_dropped += 1;
            }
        }
        self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::{Args, ClosedOp};

    /// Shutdown signals the tracer thread with the wake signal, so a tracer
    /// whose handler could not be installed must refuse before it seizes
    /// anything, rather than attach and later kill the supervisor.
    #[test]
    fn no_tracee_is_seized_without_the_wake_handler() {
        let refused = || Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        // pid 0 is never a task: a seize would fail with its own error.
        match seize_and_confirm(0, refused) {
            Err(TracerError::UnsupportedArch)
                if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) => {}
            other => assert_eq!(
                other,
                Err(TracerError::WakeHandler {
                    errno: libc::EINVAL
                })
            ),
        }
        assert!(matches!(
            seize_and_confirm(0, || Ok(())),
            Err(TracerError::Seize { pid: 0, .. } | TracerError::UnsupportedArch)
        ));
    }

    /// What `finish` cannot deliver is counted by its kind: an undelivered
    /// result is a dropped result, not a lifecycle fact.
    #[test]
    fn undelivered_events_at_the_end_are_counted_by_their_kind() {
        // A consumer that never reads, and no children to owe.
        let (mut session, _rx) = new_session(TracerConfig::default(), FakeProc::default(), 1);
        // The handoff takes the first; the other two stay buffered.
        for _ in 0..3 {
            session.emit(TracerEvent::Syscall {
                pid: 1,
                start_ticks: None,
                tid: 1,
                op: ClosedOp::Mkdir,
                syscall: "mkdirat",
                args: Args::default(),
                ret: 0,
            });
        }
        assert_eq!(session.pending.len(), 2);
        // Nothing is owed, and the stop flag ends the terminal drain at once.
        session.owed = Owed::Nothing;
        let handles = stopped(&session);
        let summary = session.finish(&handles);
        assert_eq!(summary.loss.queue_dropped, 2, "the two results");
        assert_eq!(summary.loss.lifecycle_dropped, 1, "`Finished`");
    }

    /// The control for the two checks below: not killed, the child's
    /// `mkdir` runs and is one result. The harness is sound, so an absent
    /// directory below is the kernel skipping the call, not a child that
    /// never tried.
    #[test]
    fn j4_o3_control_an_unkilled_entry_runs_and_is_one_result() {
        let dir = tempfile::tempdir().unwrap();
        let (target, c) = target_path(dir.path());
        let Some(child) = Mkdirer::start(&c) else {
            return;
        };
        let (mut session, rx) = new_session(TracerConfig::default(), LiveProc, 1024);
        let status = child.release();
        assert!(is_seccomp_stop(status), "status {status:#x}");
        session.handle(child.pid, status);
        child.reap_into(&mut session);
        let events = drained(&rx, &mut session);
        assert!(target.is_dir(), "the call ran");
        assert!(
            events.iter().any(|event| matches!(
                event,
                TracerEvent::Syscall {
                    op: ClosedOp::Mkdir,
                    ret: 0,
                    ..
                }
            )),
            "{events:?}"
        );
        assert_eq!(gaps_of(&events), vec![]);
    }

    /// The first window: the tracee is killed after the tracer has taken its
    /// seccomp entry stop from `waitpid` and before the tracer reads it.
    /// `PTRACE_GET_SYSCALL_INFO` then fails with `ESRCH` — and the kernel skips
    /// the call, because a fatal signal is pending after the trace event
    /// (`__seccomp_filter`). The directory is never made: the call had no
    /// effect, so it is not loss.
    #[test]
    fn j4_o3_a_tracee_killed_before_its_entry_is_read_made_no_call() {
        let dir = tempfile::tempdir().unwrap();
        let (target, c) = target_path(dir.path());
        let Some(child) = Mkdirer::start(&c) else {
            return;
        };
        let (mut session, rx) = new_session(TracerConfig::default(), LiveProc, 1024);
        let status = child.release();
        assert!(is_seccomp_stop(status), "status {status:#x}");
        child.kill();
        session.handle(child.pid, status);
        child.reap_into(&mut session);
        let events = drained(&rx, &mut session);
        assert!(!target.exists(), "the kernel skipped the call");
        assert_eq!(
            gaps_of(&events),
            vec![],
            "a call the kernel provably did not execute is not a loss"
        );
        assert_eq!(
            session.summary.loss.total(),
            0,
            "{:?}",
            session.summary.loss
        );
        assert_eq!(session.summary.killed_at_entry, 1, "{:?}", session.summary);
        assert_eq!(session.tasks.in_flight(), 0);
    }

    /// The second window: the entry was read (the tracer holds it) and the
    /// tracee is killed before the tracer resumes it. The resume fails with
    /// `ESRCH`, and the kernel skips the call for the same reason. The entry is
    /// not abandoned: it never ran.
    ///
    /// The kill has to reach the tracee before the resume does. A tracee
    /// fast enough to get to its exit notification first is resumed from
    /// there — the resume succeeds, the observer cannot tell that stop from
    /// a call that ran and was then killed, and the entry stays an
    /// `entry_abandoned` gap (uncertain, so a gap). That branch is checked
    /// too, and the attempt repeated until the first branch is met, which on
    /// the reference host is the first try.
    #[test]
    fn j4_o3_a_tracee_killed_before_its_entry_is_resumed_made_no_call() {
        for _ in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let (target, c) = target_path(dir.path());
            let Some(child) = Mkdirer::start(&c) else {
                return;
            };
            let (mut session, rx) = new_session(TracerConfig::default(), LiveProc, 1024);
            let status = child.release();
            assert!(is_seccomp_stop(status), "status {status:#x}");
            session.register(child.pid);
            session.handle_entry(child.pid);
            assert_eq!(session.tasks.in_flight(), 1, "the entry is in hand");
            child.kill();
            session.restart(child.pid, 0);
            let met_the_killed_stop = session.summary.killed_at_entry == 1;
            child.reap_into(&mut session);
            let events = drained(&rx, &mut session);
            assert!(!target.exists(), "the kernel skipped the call");
            assert_eq!(session.tasks.in_flight(), 0);
            if !met_the_killed_stop {
                assert_eq!(
                    gaps_of(&events),
                    vec![(
                        GapReason::EntryAbandoned,
                        OpSet::of(ClosedOp::Mkdir),
                        Some(1)
                    )],
                    "resumed from somewhere it cannot tell: uncertain, so a gap"
                );
                continue;
            }
            assert_eq!(
                gaps_of(&events),
                vec![],
                "a call the kernel provably did not execute is not a loss"
            );
            assert_eq!(
                session.summary.loss.total(),
                0,
                "{:?}",
                session.summary.loss
            );
            return;
        }
        panic!("the resume never met the killed stop in 20 attempts");
    }

    /// The exit window: the tracee is killed after its call ran and stopped at
    /// its syscall exit, before the tracer read the return. The call did run
    /// (the directory exists), and its result can no longer be read: that is a
    /// loss, and exactly one — of the call's own classes (`entry_abandoned`
    /// naming `mkdir`), not a second gap in every class.
    #[test]
    fn j4_o3_a_tracee_killed_at_its_exit_stop_is_one_loss_of_its_own_classes() {
        let dir = tempfile::tempdir().unwrap();
        let (target, c) = target_path(dir.path());
        let Some(child) = Mkdirer::start(&c) else {
            return;
        };
        let (mut session, rx) = new_session(TracerConfig::default(), LiveProc, 1024);
        let status = child.release();
        assert!(is_seccomp_stop(status), "status {status:#x}");
        session.handle(child.pid, status);
        let status = child.wait();
        assert!(
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == sys::SYSCALL_STOP_SIG,
            "the exit stop: {status:#x}"
        );
        child.kill();
        session.handle(child.pid, status);
        child.reap_into(&mut session);
        let events = drained(&rx, &mut session);
        assert!(target.is_dir(), "the call ran");
        assert_eq!(
            gaps_of(&events),
            vec![(
                GapReason::EntryAbandoned,
                OpSet::of(ClosedOp::Mkdir),
                Some(1)
            )],
            "one lost result, of the call's classes"
        );
        assert_eq!(
            session.summary.loss.total(),
            1,
            "{:?}",
            session.summary.loss
        );
        assert_eq!(session.tasks.in_flight(), 0);
    }
}
