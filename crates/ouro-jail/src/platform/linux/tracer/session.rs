//! The tracer thread: one `waitpid(-1, __WALL)` loop that owns every child
//! and every tracee of the process, and the §11 bookkeeping that turns its
//! stops into the events of [`super::TracerEvent`].
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
//!   the process keeps the identity it was born with.
//! * Entry and exit are paired per thread. An exit with no entry is a gap. A
//!   result in the `ERESTARTSYS` family is not a result at all: the kernel
//!   re-enters the syscall, so emitting one would be the duplicate §11.2
//!   forbids.
//! * A read-only open never becomes an event, and never even costs a second
//!   stop: the tracee is continued from the seccomp stop instead of being
//!   stepped to the syscall exit.
//! * Nothing observed is ever replaced by a guess. Unreadable argument
//!   memory, an undecodable `open_how`, an untracked task and a final status
//!   that cannot be attributed each become a `Gap` with its own reason, its
//!   own counter and the set of operations it affected.
//!
//! Three properties of the outbox are worth stating separately, because they
//! are what a consumer's loss looks like:
//!
//! * Results are droppable, lifecycle facts are not. A consumer that stops
//!   reading loses `Syscall` events after a bounded stall; the `Exec`,
//!   `Exit`, `UntracedChildExit`, `Gap` and `Finished` events queue in the
//!   tracer's own buffer and are delivered when the consumer returns. A
//!   supervisor never loses the exit status it exists to report.
//! * The buffer is bounded in bytes, not in events, because §11.4 budgets
//!   bytes and two four-kilobyte pathnames per event make a count meaningless.
//! * Nothing is ever delivered with a bare `try_send`. Every send has a
//!   deadline, and what misses it is counted.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use libc::pid_t;

use super::closed_set::{self, ClosedOp, Entry, FlagSource};
use super::proc;
use super::sys::{self, Wait};
use super::{
    Args, EVENT_FIXED_BYTES, GapReason, OpSet, PathSnapshot, SockaddrSnapshot, TracerConfig,
    TracerError, TracerEvent, TracerSummary, clock,
};

/// How long a tracee may be held at a stop by a consumer that is not reading.
/// After this the result is dropped and counted; the tree keeps moving.
const QUEUE_BLOCK: Duration = Duration::from_secs(1);

/// How often a full outbox is retried inside that second.
const QUEUE_POLL: Duration = Duration::from_micros(200);

/// How long the tracer keeps trying to hand over the terminal gap and
/// `Finished` after the tree is dead. Nothing is stopped behind them, so this
/// is generous; `finish` ends it immediately by setting the stop flag.
const TERMINAL_DRAIN: Duration = Duration::from_secs(30);

const TERMINAL_POLL: Duration = Duration::from_millis(5);

/// Most lifecycle events the tracer will hold for a consumer that is not
/// reading. They are tiny and bounded by the number of tasks; past this the
/// backlog itself is the problem and is reported as one.
const LIFECYCLE_MAX: usize = 16_384;

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
}

/// A traced thread.
struct Task {
    tgid: pid_t,
    start_ticks: Option<u64>,
    pending: Option<Pending>,
}

/// A traced thread group.
struct Process {
    threads: HashSet<pid_t>,
    /// Set by `PTRACE_EVENT_EXEC`. §11.2 ties `proc.exit` to a witnessed
    /// exec, so a fork child that never execs emits none.
    witnessed_exec: bool,
    /// False when `/proc` would not say which thread group this task belongs
    /// to. Such a group never gets an `Exit`: the gap was already recorded.
    identity_known: bool,
}

/// A closed-set call that has entered the kernel and not yet returned.
struct Pending {
    entry: &'static Entry,
    args: Args,
    /// `PTRACE_EVENT_EXEC` arrived for this entry, so the syscall exit that
    /// follows is the transition already reported and not a second result.
    exec_confirmed: bool,
    /// Arguments that could not be read. Which of these is loss and which is
    /// a tracee passing a pointer that never could have worked is decided at
    /// the syscall exit, from the kernel's own return.
    path_unreadable: bool,
    path2_unreadable: bool,
    sockaddr_unreadable: bool,
    flags_unavailable: bool,
}

pub(super) fn run(
    launcher: pid_t,
    config: TracerConfig,
    tx: SyncSender<TracerEvent>,
    ready: Sender<Result<(), TracerError>>,
    handles: Handles,
) -> TracerSummary {
    handles.tid.store(sys::gettid(), Ordering::Release);
    let mut session = Session::new(config, tx);
    match seize_and_confirm(launcher) {
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
    session.emit(TracerEvent::Attached {
        pid: launcher,
        start_ticks: proc::start_ticks(launcher),
        monotonic_ns: clock::boottime_ns(),
    });
    session.register(launcher);
    session.run_loop(&handles);
    session.finish(&handles)
}

/// Install the handler that lets `finish` interrupt a blocking `waitpid`.
/// Process-global and installed once; the handler does nothing at all.
fn ensure_wake_handler() -> bool {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    *INSTALLED.get_or_init(|| sys::install_wake_handler().is_ok())
}

fn seize_and_confirm(launcher: pid_t) -> Result<(), TracerError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(TracerError::UnsupportedArch);
    }
    ensure_wake_handler();
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

/// One event waiting to be handed to the consumer.
struct Queued {
    event: TracerEvent,
    bytes: usize,
    lifecycle: bool,
}

struct CoalescedGap {
    reason: GapReason,
    ops: OpSet,
    from_ns: u64,
    to_ns: u64,
    count: u64,
}

struct Session {
    config: TracerConfig,
    tx: SyncSender<TracerEvent>,
    /// Events the consumer has not taken yet, oldest first.
    pending: VecDeque<Queued>,
    pending_bytes: usize,
    lifecycle_pending: usize,
    /// The byte ceiling the outbox admits against.
    bytes_max: usize,
    /// True while the consumer is behind: results are dropped without
    /// waiting another second to find out again.
    stalled: bool,
    disconnected: bool,
    /// The loss being coalesced into a single `Gap`, per §11.4 ("Coalesce
    /// repeated losses into bounded interval summaries").
    coalesced: Option<CoalescedGap>,
    /// The last moment an event reached the consumer. A gap bounds itself
    /// from here, which is what §11.4 means by the last known healthy point.
    last_healthy_ns: u64,
    summary: TracerSummary,
    tasks: HashMap<pid_t, Task>,
    procs: HashMap<pid_t, Process>,
    /// Threads the kernel destroyed for a reason we saw, with the moment we
    /// may stop expecting their notification. Bounded, and pruned, so a
    /// recycled pid cannot be swallowed by a stale entry.
    retired: HashMap<pid_t, Instant>,
    inflight: usize,
    scratch: Vec<u8>,
}

impl Session {
    fn new(config: TracerConfig, tx: SyncSender<TracerEvent>) -> Self {
        let scratch = vec![0u8; config.path_snapshot_max.max(128)];
        // §11.4 budgets the whole user-space queue. What the consumer has
        // already taken from the channel, and what the allocator rounded up,
        // are part of that budget too, so the buffer admits against three
        // quarters of it.
        let bytes_max = config.queue_bytes_max - config.queue_bytes_max / 4;
        Session {
            config,
            tx,
            pending: VecDeque::new(),
            pending_bytes: 0,
            lifecycle_pending: 0,
            bytes_max: bytes_max.max(EVENT_FIXED_BYTES),
            stalled: false,
            disconnected: false,
            coalesced: None,
            last_healthy_ns: clock::boottime_ns(),
            summary: TracerSummary::default(),
            tasks: HashMap::new(),
            procs: HashMap::new(),
            retired: HashMap::new(),
            inflight: 0,
            scratch,
        }
    }

    // ---------------------------------------------------------- the outbox

    /// What an event costs the budget: its snapshots plus a fixed charge for
    /// the enum, the buffer slot and the allocator's rounding.
    fn event_bytes(event: &TracerEvent) -> usize {
        let snapshots = match event {
            TracerEvent::Syscall { args, .. } => {
                args.path.as_ref().map_or(0, |p| p.bytes.len())
                    + args.path2.as_ref().map_or(0, |p| p.bytes.len())
                    + args.sockaddr.as_ref().map_or(0, |s| s.bytes.len())
            }
            TracerEvent::Exec { path, .. } => path.as_ref().map_or(0, |p| p.bytes.len()),
            _ => 0,
        };
        EVENT_FIXED_BYTES + snapshots
    }

    /// Whether an event is a lifecycle fact rather than an audit result.
    /// Lifecycle facts are not subject to result backpressure.
    fn is_lifecycle(event: &TracerEvent) -> bool {
        !matches!(event, TracerEvent::Syscall { .. })
    }

    /// The closed-set operations a lost event would have carried, so a gap
    /// can name exactly the classes it affected (§11.4).
    fn ops_of(event: &TracerEvent) -> OpSet {
        match event {
            TracerEvent::Syscall { op, .. } => OpSet::of(*op),
            // §11.4 assigns proc.exec and proc.exit to the same class.
            TracerEvent::Exec { .. } | TracerEvent::Exit { .. } => OpSet::of(ClosedOp::Exec),
            _ => OpSet::EMPTY,
        }
    }

    /// Hand as much of the backlog to the consumer as it will take.
    fn flush(&mut self) {
        while let Some(front) = self.pending.pop_front() {
            let lifecycle = front.lifecycle;
            let bytes = front.bytes;
            match self.tx.try_send(front.event) {
                Ok(()) => {
                    self.pending_bytes -= bytes;
                    if lifecycle {
                        self.lifecycle_pending -= 1;
                    }
                    self.summary.emitted += 1;
                    self.last_healthy_ns = clock::boottime_ns();
                }
                Err(TrySendError::Full(event)) => {
                    self.pending.push_front(Queued {
                        event,
                        bytes,
                        lifecycle,
                    });
                    return;
                }
                Err(TrySendError::Disconnected(event)) => {
                    self.pending.push_front(Queued {
                        event,
                        bytes,
                        lifecycle,
                    });
                    self.disconnected = true;
                    return;
                }
            }
        }
        self.stalled = false;
    }

    fn room_for(&self, bytes: usize) -> bool {
        self.pending.len() < self.config.queue_max.max(1)
            && self.pending_bytes + bytes <= self.bytes_max
    }

    fn enqueue(&mut self, event: TracerEvent, bytes: usize, lifecycle: bool) {
        if lifecycle {
            self.lifecycle_pending += 1;
        }
        self.pending_bytes += bytes;
        self.summary.queue_bytes_peak = self.summary.queue_bytes_peak.max(self.pending_bytes);
        self.pending.push_back(Queued {
            event,
            bytes,
            lifecycle,
        });
    }

    /// Put the coalesced gap in front of whatever comes next, so the loss is
    /// never hidden behind the event that followed it.
    fn materialise_gap(&mut self) {
        let Some(gap) = self.coalesced.take() else {
            return;
        };
        let event = TracerEvent::Gap {
            reason: gap.reason,
            ops: gap.ops,
            from_ns: gap.from_ns,
            to_ns: gap.to_ns,
            count: Some(gap.count),
        };
        let bytes = Session::event_bytes(&event);
        self.summary.gaps += 1;
        self.enqueue(event, bytes, true);
    }

    fn emit(&mut self, event: TracerEvent) {
        self.flush();
        let lifecycle = Session::is_lifecycle(&event);
        let bytes = Session::event_bytes(&event);
        let ops = Session::ops_of(&event);

        if lifecycle {
            if self.lifecycle_pending >= LIFECYCLE_MAX {
                self.summary.loss.lifecycle_dropped += 1;
                self.note_drop(GapReason::LifecycleDropped, ops);
                return;
            }
            self.materialise_gap();
            self.enqueue(event, bytes, true);
            self.flush();
            return;
        }

        if self.room_for(bytes) {
            self.materialise_gap();
            self.enqueue(event, bytes, false);
            self.flush();
            return;
        }
        if self.stalled || self.disconnected {
            // The consumer already failed to keep up once. Do not hold a
            // tracee at a stop for another second to find out again.
            self.summary.loss.queue_dropped += 1;
            self.note_drop(GapReason::QueueFull, ops);
            return;
        }
        // Bounded backpressure: wait, but never longer than this (§11.4).
        let deadline = Instant::now() + QUEUE_BLOCK;
        loop {
            self.flush();
            if self.room_for(bytes) {
                self.materialise_gap();
                self.enqueue(event, bytes, false);
                self.flush();
                return;
            }
            if self.disconnected || Instant::now() >= deadline {
                self.stalled = true;
                self.summary.loss.queue_dropped += 1;
                self.note_drop(GapReason::QueueFull, ops);
                return;
            }
            std::thread::sleep(QUEUE_POLL);
        }
    }

    /// Record loss into the coalesced gap. A gap of a different reason is
    /// materialised first rather than merged into one that would misname it.
    fn note_drop(&mut self, reason: GapReason, ops: OpSet) {
        let now = clock::boottime_ns();
        match &mut self.coalesced {
            Some(gap) if gap.reason == reason => {
                gap.to_ns = now;
                gap.count += 1;
                gap.ops = gap.ops.union(ops);
                return;
            }
            Some(_) => self.materialise_gap(),
            None => {}
        }
        self.coalesced = Some(CoalescedGap {
            reason,
            ops,
            from_ns: self.last_healthy_ns,
            to_ns: now,
            count: 1,
        });
    }

    /// Record a gap that is not queue loss. It is a lifecycle event, so it
    /// is never dropped to make room for a result.
    fn gap(&mut self, reason: GapReason, ops: OpSet, count: Option<u64>) {
        let event = TracerEvent::Gap {
            reason,
            ops,
            from_ns: self.last_healthy_ns,
            to_ns: clock::boottime_ns(),
            count,
        };
        self.summary.gaps += 1;
        self.emit(event);
    }

    // ---------------------------------------------------------- the loop

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
        let alive: Vec<pid_t> = self.tasks.keys().copied().collect();
        if alive.is_empty() {
            return;
        }
        // Whatever these tracees were about to do is unobserved, whether or
        // not the kill and the reap below succeed. That is the loss, and it
        // is recorded before anything is attempted.
        self.summary.loss.abandoned_tracees += alive.len() as u64;
        self.gap(
            GapReason::TraceesAbandoned,
            OpSet::EMPTY,
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
        let stepping = self
            .tasks
            .get(&pid)
            .is_some_and(|task| task.pending.is_some());
        let request = if stepping {
            sys::PTRACE_SYSCALL
        } else {
            sys::PTRACE_CONT
        };
        if let Err(err) = sys::restart(pid, request, signal) {
            self.restart_failed(pid, &err);
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

    // ---------------------------------------------------------- identity

    /// Make sure `tid` is tracked, learning its thread group and birth from
    /// `/proc`.
    fn register(&mut self, tid: pid_t) {
        if self.tasks.contains_key(&tid) {
            return;
        }
        self.summary.tracees += 1;
        let start_ticks = proc::start_ticks(tid);
        let (tgid, identity_known) = match proc::tgid(tid) {
            Some(tgid) => (tgid, true),
            None => {
                self.summary.loss.identity_unavailable += 1;
                self.gap(GapReason::IdentityUnavailable, OpSet::EMPTY, Some(1));
                (tid, false)
            }
        };
        self.tasks.insert(
            tid,
            Task {
                tgid,
                start_ticks,
                pending: None,
            },
        );
        let process = self.procs.entry(tgid).or_insert_with(|| Process {
            threads: HashSet::new(),
            witnessed_exec: false,
            identity_known,
        });
        process.identity_known &= identity_known;
        process.threads.insert(tid);
    }

    fn tgid_of(&self, tid: pid_t) -> pid_t {
        self.tasks.get(&tid).map_or(tid, |task| task.tgid)
    }

    /// Forget retired tids once no notification for them can still arrive.
    fn prune_retired(&mut self) {
        let now = Instant::now();
        self.retired.retain(|_, deadline| *deadline > now);
    }

    // ---------------------------------------------------------- events

    fn handle_fork(&mut self, parent_tid: pid_t) {
        let Ok(child) = sys::event_msg(parent_tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::EMPTY, Some(1));
            return;
        };
        let child = child as pid_t;
        self.register(child);
        let parent = self.tgid_of(parent_tid);
        let child_tgid = self.tgid_of(child);
        let child_start_ticks = self.tasks.get(&child).and_then(|task| task.start_ticks);
        self.emit(TracerEvent::Fork {
            parent,
            parent_tid,
            child,
            // A CLONE_THREAD child lands in the thread group that made the
            // call; a new process starts its own.
            is_thread: child_tgid == parent,
            child_start_ticks,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    fn handle_exec(&mut self, tid: pid_t) {
        self.summary.exec_transitions += 1;
        // After execve the thread group has exactly one thread and its id is
        // the leader's, which is the id this stop was reported under. If a
        // worker did the exec, PTRACE_GETEVENTMSG names the id it had before.
        let former = sys::event_msg(tid)
            .map(|value| value as pid_t)
            .unwrap_or(tid);
        let mut carried: Option<Pending> = None;
        if former != tid
            && former > 0
            && let Some(task) = self.tasks.remove(&former)
        {
            carried = task.pending;
            // That task did not die: it is this one now, under the leader's
            // id. Nothing will ever report it, so it is not retired — a
            // recycled pid with this number must not be swallowed.
            self.summary.tasks_destroyed_by_exec += 1;
            if let Some(process) = self.procs.get_mut(&task.tgid) {
                process.threads.remove(&former);
            }
        }
        let tgid = self.tgid_of(tid);
        let mut destroyed = Vec::new();
        if let Some(process) = self.procs.get_mut(&tgid) {
            for other in process.threads.iter().copied() {
                if other != tid {
                    destroyed.push(other);
                }
            }
            process.threads.retain(|thread| *thread == tid);
            process.threads.insert(tid);
            process.witnessed_exec = true;
        }
        for thread in destroyed {
            // The kernel destroys the other threads without reporting them,
            // so their entry is retired for a bounded time in case one was
            // already on its way.
            self.retired.insert(thread, Instant::now() + KILL_GRACE);
            self.summary.tasks_destroyed_by_exec += 1;
            if let Some(task) = self.tasks.remove(&thread)
                && task.pending.is_some()
            {
                self.inflight = self.inflight.saturating_sub(1);
                self.summary.loss.abandoned_entries += 1;
                self.gap(GapReason::EntryAbandoned, OpSet::EMPTY, Some(1));
            }
        }
        if carried.is_some() && self.tasks.get(&tid).is_some_and(|t| t.pending.is_some()) {
            // Both the leader and the thread that execed had a call in
            // flight; the leader's can no longer return.
            self.inflight = self.inflight.saturating_sub(1);
            self.summary.loss.abandoned_entries += 1;
            self.gap(GapReason::EntryAbandoned, OpSet::EMPTY, Some(1));
        }
        let mut path = None;
        if let Some(task) = self.tasks.get_mut(&tid) {
            if let Some(pending) = carried {
                task.pending = Some(pending);
            }
            if let Some(pending) = task.pending.as_mut()
                && pending.entry.op == ClosedOp::Exec
            {
                pending.exec_confirmed = true;
                path = pending.args.path.clone();
            }
        }
        self.emit(TracerEvent::Exec {
            pid: tgid,
            path,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    /// A `PTRACE_EVENT_SECCOMP` stop: the tracee is at the entry of a
    /// closed-set call and the syscall has not run.
    fn handle_entry(&mut self, tid: pid_t) {
        let Some(info) = sys::syscall_info(tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::EMPTY, Some(1));
            return;
        };
        if info.op != sys::SYSCALL_INFO_SECCOMP && info.op != sys::SYSCALL_INFO_ENTRY {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::EMPTY, Some(1));
            return;
        }
        // jail-v1 §9.2: validate the architecture before the syscall number.
        // A compat or x32 entry carries a number from a different table, and
        // naming it from this one would mislabel the call.
        if info.arch != sys::AUDIT_ARCH_X86_64 {
            self.summary.loss.unexpected_trace_stops += 1;
            self.gap(GapReason::UnexpectedTraceStop, OpSet::EMPTY, Some(1));
            return;
        }
        let Some(entry) = closed_set::lookup(info.nr) else {
            // The filter stopped a number this table does not name, so the
            // filter the launcher installed is not this module's. Say so.
            self.summary.loss.unexpected_trace_stops += 1;
            self.gap(GapReason::UnexpectedTraceStop, OpSet::EMPTY, Some(1));
            return;
        };
        if self.inflight >= self.config.inflight_max {
            self.summary.loss.inflight_rejected += 1;
            self.gap(GapReason::InflightExhausted, OpSet::of(entry.op), Some(1));
            return;
        }
        // Flags first: they decide whether this call is in the closed set at
        // all, and one that is not must cost neither a read of the tracee's
        // memory nor a mark in the loss counters.
        let (flags, flags_unavailable) = self.capture_flags(tid, entry, &info.args);
        if entry.op == ClosedOp::Open
            && let Some(flags) = flags
            && !closed_set::open_is_covered(flags)
        {
            // A read-only open is outside `linux-closed-v1`. It is not a
            // loss, it is not an event, and the tracee is continued from
            // here rather than stepped to a syscall exit nobody reads.
            self.summary.filtered_readonly_opens += 1;
            return;
        }
        let mut pending = self.capture_paths(tid, entry, &info.args);
        pending.args.flags = flags;
        pending.flags_unavailable = flags_unavailable;

        let replaced = self
            .tasks
            .get(&tid)
            .is_some_and(|task| task.pending.is_some());
        if replaced {
            // The previous entry for this thread never returned.
            self.summary.loss.abandoned_entries += 1;
            self.inflight = self.inflight.saturating_sub(1);
            self.gap(GapReason::EntryAbandoned, OpSet::EMPTY, Some(1));
        }
        if let Some(task) = self.tasks.get_mut(&tid) {
            task.pending = Some(pending);
            self.inflight += 1;
        }
    }

    /// A `SIGTRAP | 0x80` stop: the syscall entry or exit of a call whose
    /// entry we recorded.
    fn handle_syscall_stop(&mut self, tid: pid_t) {
        let Some(info) = sys::syscall_info(tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::EMPTY, Some(1));
            return;
        };
        match info.op {
            // With the narrowing filter the entry is reported as a seccomp
            // stop, so this is the entry of a call already recorded there.
            sys::SYSCALL_INFO_ENTRY => {}
            sys::SYSCALL_INFO_EXIT => self.handle_exit(tid, info.rval),
            // The tracee is not in a syscall. Nothing to pair, nothing lost.
            sys::SYSCALL_INFO_NONE => {}
            _ => {
                self.summary.loss.syscall_info_unavailable += 1;
                self.gap(GapReason::SyscallInfoUnavailable, OpSet::EMPTY, Some(1));
            }
        }
    }

    fn handle_exit(&mut self, tid: pid_t, rval: i64) {
        let tgid = self.tgid_of(tid);
        let Some(pending) = self
            .tasks
            .get_mut(&tid)
            .and_then(|task| task.pending.take())
        else {
            // A syscall exit with no entry to pair it with: either the entry
            // was never seen or this thread is not one we track.
            self.summary.loss.unmatched_exits += 1;
            self.gap(GapReason::UnmatchedExit, OpSet::EMPTY, Some(1));
            return;
        };
        self.inflight = self.inflight.saturating_sub(1);
        if sys::is_restart(rval) {
            // The kernel will re-enter this syscall. Its entry stops again
            // and produces the one result the call actually has.
            self.summary.restarts += 1;
            return;
        }
        if pending.exec_confirmed {
            // `Exec` was already emitted for this call at the confirmed
            // transition; the zero that follows is the same event.
            return;
        }
        let op = pending.entry.op;
        // An argument the observer could not read is only a hole in coverage
        // when the kernel could read it. When the kernel rejected the same
        // pointer or structure, there was no covered operation to miss, and
        // counting it as loss would let a tracee manufacture loss at will by
        // passing addresses that can never work.
        let rejected = rval == -i64::from(libc::EFAULT) || rval == -i64::from(libc::EINVAL);
        let mut unreadable = 0u64;
        if pending.path_unreadable {
            unreadable += 1;
        }
        if pending.path2_unreadable {
            unreadable += 1;
        }
        if unreadable > 0 {
            if rejected {
                self.summary.argument_invalid += unreadable;
            } else {
                self.summary.loss.path_unreadable += unreadable;
                self.gap(GapReason::PathUnreadable, OpSet::of(op), Some(unreadable));
            }
        }
        if pending.sockaddr_unreadable {
            if rejected {
                self.summary.argument_invalid += 1;
            } else {
                self.summary.loss.sockaddr_unreadable += 1;
                self.gap(GapReason::SockaddrUnreadable, OpSet::of(op), Some(1));
            }
        }
        if pending.flags_unavailable {
            // Without the flags, membership of the mutation set was never
            // established, so this must not be delivered as a covered open.
            // A rejected call had no covered effect to miss either.
            if rejected {
                self.summary.argument_invalid += 1;
            } else {
                self.summary.loss.flags_unavailable += 1;
                self.gap(GapReason::FlagsUnavailable, OpSet::of(op), Some(1));
            }
            return;
        }
        self.summary.ops.bump(op);
        self.emit(TracerEvent::Syscall {
            pid: tgid,
            tid,
            op,
            syscall: pending.entry.name,
            args: pending.args,
            ret: rval,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    fn handle_death(&mut self, pid: pid_t, status: libc::c_int) {
        self.prune_retired();
        let Some(task) = self.tasks.remove(&pid) else {
            if self.retired.remove(&pid).is_some() {
                // A thread the kernel destroyed at a non-leader exec.
                return;
            }
            self.summary.untraced_child_exits += 1;
            self.emit(TracerEvent::UntracedChildExit { pid, status });
            return;
        };
        self.summary.reaped_tasks += 1;
        if task.pending.is_some() {
            self.inflight = self.inflight.saturating_sub(1);
            self.summary.loss.abandoned_entries += 1;
            self.gap(GapReason::EntryAbandoned, OpSet::EMPTY, Some(1));
        }
        let Some(process) = self.procs.get_mut(&task.tgid) else {
            // A task whose thread group we no longer hold: its death cannot
            // be attributed, so it is a hole rather than a silent drop.
            self.summary.loss.death_unattributed += 1;
            self.gap(
                GapReason::DeathUnattributed,
                OpSet::of(ClosedOp::Exec),
                Some(1),
            );
            return;
        };
        process.threads.remove(&pid);
        if !process.threads.is_empty() {
            // A worker thread exited. That is not the death of a process.
            return;
        }
        let process = self.procs.remove(&task.tgid).expect("just borrowed");
        if !process.witnessed_exec {
            // §11.2: a fork child that never execs is tracked for scope and
            // lifetime and emits no public `proc.exit`.
            return;
        }
        if !process.identity_known {
            self.summary.loss.death_unattributed += 1;
            self.gap(
                GapReason::DeathUnattributed,
                OpSet::of(ClosedOp::Exec),
                Some(1),
            );
            return;
        }
        if pid != task.tgid {
            // Invariant: the kernel delays a group leader's report until its
            // last thread is gone (`delay_group_leader`), so the last reap in
            // a thread group is always the leader's. Reaching this branch
            // would mean that guarantee did not hold, and §11.2 forbids
            // presenting a worker's status as the process's.
            self.summary.loss.final_status_unknown += 1;
            self.gap(
                GapReason::FinalStatusUnknown,
                OpSet::of(ClosedOp::Exec),
                None,
            );
            return;
        }
        self.summary.exits += 1;
        self.emit(TracerEvent::Exit {
            pid: task.tgid,
            status,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    // ---------------------------------------------------------- arguments

    /// The flags word of a row, and whether flags the consumer needs for
    /// classification could not be decoded.
    fn capture_flags(
        &mut self,
        tid: pid_t,
        entry: &'static Entry,
        raw: &[u64; 6],
    ) -> (Option<u64>, bool) {
        match entry.flags {
            FlagSource::None => (None, false),
            FlagSource::Arg(index) => (Some(raw[index as usize]), false),
            FlagSource::ImpliedCreat => (Some(closed_set::implied_creat_flags()), false),
            FlagSource::OpenHow { ptr, size } => {
                // `open_how` is { u64 flags; u64 mode; u64 resolve; }. A
                // caller that passes a smaller size gets EINVAL from the
                // kernel and gives us nothing to decode.
                const OPEN_HOW_VER0: u64 = 24;
                if raw[size as usize] < OPEN_HOW_VER0 {
                    return (None, true);
                }
                let mut word = [0u8; 8];
                if sys::read_remote(tid, raw[ptr as usize], &mut word) == 8 {
                    (Some(u64::from_ne_bytes(word)), false)
                } else {
                    (None, true)
                }
            }
        }
    }

    /// Read the pathnames, directory fds and socket address the row names.
    fn capture_paths(&mut self, tid: pid_t, entry: &'static Entry, raw: &[u64; 6]) -> Pending {
        let mut args = Args::default();
        let mut path_unreadable = false;
        let mut path2_unreadable = false;
        let mut sockaddr_unreadable = false;
        if let Some(index) = entry.path {
            let (snapshot, unreadable) = self.read_path(tid, raw[index as usize]);
            args.path = snapshot;
            path_unreadable = unreadable;
        }
        if let Some(index) = entry.path2 {
            let (snapshot, unreadable) = self.read_path(tid, raw[index as usize]);
            args.path2 = snapshot;
            path2_unreadable = unreadable;
        }
        if let Some(index) = entry.dirfd {
            args.dirfd = Some(raw[index as usize] as i32);
        }
        if let Some(index) = entry.dirfd2 {
            args.dirfd2 = Some(raw[index as usize] as i32);
        }
        if let Some((ptr, len)) = entry.sockaddr {
            let (snapshot, unreadable) =
                self.read_sockaddr(tid, raw[ptr as usize], raw[len as usize]);
            args.sockaddr = snapshot;
            sockaddr_unreadable = unreadable;
        }
        Pending {
            entry,
            args,
            exec_confirmed: false,
            path_unreadable,
            path2_unreadable,
            sockaddr_unreadable,
            flags_unavailable: false,
        }
    }

    /// A NUL-terminated pathname argument, bounded by `path_snapshot_max`.
    ///
    /// `complete` is false when the bytes ran out before a NUL or when the
    /// tracee's memory could not be read: §11.3 wants the weaker assertion
    /// carried in band, not a shorter path presented as the whole one. The
    /// second return says nothing was readable at all, which the syscall exit
    /// classifies once the kernel's own verdict on the same pointer is known.
    fn read_path(&mut self, tid: pid_t, addr: u64) -> (Option<PathSnapshot>, bool) {
        if addr == 0 {
            return (None, false);
        }
        let max = self.config.path_snapshot_max;
        let mut bytes: Vec<u8> = Vec::new();
        while bytes.len() < max {
            let offset = bytes.len();
            let want = (max - offset).min(self.scratch.len());
            let at = addr.wrapping_add(offset as u64);
            let mut read = sys::read_remote(tid, at, &mut self.scratch[..want]);
            if read == 0 {
                // The range may cross into an unmapped page. Retry bounded to
                // the end of the page the address is in.
                let page = 4096u64;
                let to_page = (page - (at % page)) as usize;
                if to_page < want {
                    read = sys::read_remote(tid, at, &mut self.scratch[..to_page]);
                }
            }
            if read == 0 {
                if bytes.is_empty() {
                    return (
                        Some(PathSnapshot {
                            bytes,
                            complete: false,
                        }),
                        true,
                    );
                }
                self.summary.loss.path_truncated += 1;
                return (
                    Some(PathSnapshot {
                        bytes,
                        complete: false,
                    }),
                    false,
                );
            }
            let chunk = &self.scratch[..read];
            if let Some(end) = chunk.iter().position(|b| *b == 0) {
                bytes.extend_from_slice(&chunk[..end]);
                return (
                    Some(PathSnapshot {
                        bytes,
                        complete: true,
                    }),
                    false,
                );
            }
            bytes.extend_from_slice(chunk);
        }
        self.summary.loss.path_truncated += 1;
        (
            Some(PathSnapshot {
                bytes,
                complete: false,
            }),
            false,
        )
    }

    /// The `sockaddr` of a `connect`, as far as the closed set describes it.
    ///
    /// The retained bytes are the family's own size, never the length the
    /// caller declared: `addrlen` is the caller's claim, and a `sockaddr_in`
    /// announced as 128 bytes would otherwise pull 112 bytes of unrelated
    /// tracee memory into the observer (§11.1: read only the arguments the
    /// closed set needs). For a family the set does not name, nothing but the
    /// family is kept.
    fn read_sockaddr(
        &mut self,
        tid: pid_t,
        addr: u64,
        len: u64,
    ) -> (Option<SockaddrSnapshot>, bool) {
        if addr == 0 {
            return (None, false);
        }
        let declared_len = u32::try_from(len).unwrap_or(u32::MAX);
        let unknown = SockaddrSnapshot {
            family: None,
            bytes: Vec::new(),
            declared_len,
            complete: false,
        };
        if len < 2 {
            // The kernel rejects this too; there is no family to read.
            return (Some(unknown), false);
        }
        if sys::read_remote(tid, addr, &mut self.scratch[..2]) < 2 {
            return (Some(unknown), true);
        }
        let family = u16::from_ne_bytes([self.scratch[0], self.scratch[1]]);
        let Some(family_len) = sockaddr_len(family, len) else {
            return (
                Some(SockaddrSnapshot {
                    family: Some(family),
                    bytes: Vec::new(),
                    declared_len,
                    complete: false,
                }),
                false,
            );
        };
        let want = family_len.min(self.scratch.len());
        let read = sys::read_remote(tid, addr, &mut self.scratch[..want]);
        (
            Some(SockaddrSnapshot {
                family: Some(family),
                bytes: self.scratch[..read].to_vec(),
                declared_len,
                // Complete means the whole address of this family was read
                // and the caller declared at least that much.
                complete: read == want && u64::try_from(family_len).unwrap_or(u64::MAX) <= len,
            }),
            read == 0,
        )
    }

    // ---------------------------------------------------------- shutdown

    fn finish(mut self, handles: &Handles) -> TracerSummary {
        // Direct children that were never reaped have no route left for
        // their exit status: the supervisor was told not to wait for its own
        // children while a tracer is attached.
        let unreaped: Vec<pid_t> = proc::children(sys::getpid())
            .into_iter()
            .filter(|pid| !self.tasks.contains_key(pid))
            .collect();
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
        let bytes = Session::event_bytes(&finished);
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
        if !self.pending.is_empty() {
            self.summary.loss.lifecycle_dropped += self.pending.len() as u64;
        }
        self.summary
    }
}

/// How many bytes of a `sockaddr` belong to its family, bounded by what the
/// caller declared. `None` for a family the closed set does not name.
fn sockaddr_len(family: u16, declared: u64) -> Option<usize> {
    let size = match i32::from(family) {
        libc::AF_INET => 16,
        libc::AF_INET6 => 28,
        // `sockaddr_un` is 110 bytes; an abstract or short name uses less,
        // and only the caller's length says how much of it is the name.
        libc::AF_UNIX => 110,
        _ => return None,
    };
    Some(size.min(usize::try_from(declared).unwrap_or(usize::MAX)))
}

#[cfg(test)]
mod tests {
    use super::sockaddr_len;

    #[test]
    fn a_sockaddr_is_clamped_to_its_family_not_the_callers_claim() {
        // A sockaddr_in announced as 128 bytes is still 16 bytes of address.
        assert_eq!(sockaddr_len(libc::AF_INET as u16, 128), Some(16));
        assert_eq!(sockaddr_len(libc::AF_INET as u16, 0x7fff_ffff), Some(16));
        // A claim shorter than the family's size bounds it further: the
        // kernel would reject the call, and nothing beyond the claim is ours.
        assert_eq!(sockaddr_len(libc::AF_INET as u16, 8), Some(8));
        assert_eq!(sockaddr_len(libc::AF_INET6 as u16, 128), Some(28));
        assert_eq!(sockaddr_len(libc::AF_UNIX as u16, 128), Some(110));
        assert_eq!(sockaddr_len(libc::AF_UNIX as u16, 20), Some(20));
        // A family the closed set does not name keeps no bytes at all.
        assert_eq!(sockaddr_len(libc::AF_NETLINK as u16, 128), None);
        assert_eq!(sockaddr_len(libc::AF_PACKET as u16, 128), None);
        assert_eq!(sockaddr_len(0xffff, 128), None);
    }
}
