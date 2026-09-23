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
//!   reading loses `Syscall` events after a bounded stall; the lifecycle
//!   facts queue in the tracer's own buffer and are delivered when the
//!   consumer returns. The §11.4 byte budget and a count bound them too — an
//!   `Exec` carries a child-chosen pathname, so it is dropped with a gap when
//!   either is full — but the critical facts, `Exit`, `UntracedChildExit`,
//!   `Gap` and `Finished`, are exempt from every cap (J4 D6). The first
//!   three are fixed-size and bounded by the tasks that exist; a `Gap` past a
//!   cap is merged into the one summary per reason that is delivered ahead of
//!   the next fact, so its reason, classes, count and interval survive while
//!   the backlog stays bounded. A supervisor never loses the exit status it
//!   exists to report, nor the record of what it could not see.
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
/// backlog itself is the problem and is reported as one. The critical facts
/// are exempt ([`Session::is_critical`]): a gap past it is coalesced, an
/// exit is admitted.
const LIFECYCLE_MAX: usize = 16_384;

/// Bytes of the §11.4 queue budget that results may not consume, so the
/// lifecycle facts a supervisor must never lose — `Exit`, `Gap`, `Finished`
/// — always have room to land behind them. Generous against their fixed
/// [`EVENT_FIXED_BYTES`] size.
const LIFECYCLE_RESERVE: usize = 64 * 1024;

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
    pending: Option<InFlight>,
}

/// A call that stopped at its entry and has not yet returned.
enum InFlight {
    /// A closed-set call, with the arguments read at its entry.
    Closed(Pending),
    /// A syscall under another ABI (J4 D2): never decoded, so its return is
    /// the one thing the observer learns about it.
    Foreign,
    /// `seccomp(2)` asking for a notification listener (J4 D1): its return
    /// says whether the child now holds one.
    Listener,
}

impl InFlight {
    /// The operations a hole left by this call could have held: the row's
    /// own for a closed-set call, all of them for a call nothing decoded or
    /// a listener that could hide any of them.
    fn ops(&self) -> OpSet {
        match self {
            InFlight::Closed(pending) => OpSet::of(pending.entry.op),
            InFlight::Foreign | InFlight::Listener => OpSet::ALL,
        }
    }
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
    let epoch_boottime_ns = config.epoch_boottime_ns;
    let mut session = Session::new(config, tx, epoch_boottime_ns);
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
    /// `None` once any merged gap had an unknown size.
    count: Option<u64>,
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
    /// The byte ceiling results admit against: `bytes_max` short of the
    /// lifecycle reserve, so the reserve stays free for lifecycle facts.
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
    tasks: HashMap<pid_t, Task>,
    procs: HashMap<pid_t, Process>,
    /// Threads the kernel destroyed for a reason we saw, with the moment we
    /// may stop expecting their notification. Bounded, and pruned, so a
    /// recycled pid cannot be swallowed by a stale entry.
    retired: HashMap<pid_t, Instant>,
    /// Tracees whose death was reported before their fork event arrived,
    /// with the moment the late fork event can no longer follow. Fork-order
    /// races: the child stopped nothing, ran nothing, and is not loss.
    tracee_deaths: HashMap<pid_t, Instant>,
    inflight: usize,
    scratch: Vec<u8>,
}

impl Session {
    fn new(config: TracerConfig, tx: SyncSender<TracerEvent>, epoch_boottime_ns: u64) -> Self {
        let scratch = vec![0u8; config.path_snapshot_max.max(128)];
        // §11.4 budgets the whole user-space queue. What the consumer has
        // already taken from the channel, and what the allocator rounded up,
        // are part of that budget too, so the buffer admits against three
        // quarters of it.
        let bytes_max =
            (config.queue_bytes_max - config.queue_bytes_max / 4).max(EVENT_FIXED_BYTES);
        // Results stop short of the reserve, so the reserve stays free for
        // the lifecycle facts a supervisor must never lose.
        let result_bytes_max = bytes_max
            .saturating_sub(LIFECYCLE_RESERVE)
            .max(EVENT_FIXED_BYTES);
        Session {
            config,
            tx,
            pending: VecDeque::new(),
            pending_bytes: 0,
            lifecycle_pending: 0,
            bytes_max,
            result_bytes_max,
            stalled: false,
            disconnected: false,
            coalesced: Vec::new(),
            epoch_boottime_ns,
            last_healthy_ns: clock::boottime_ns().saturating_sub(epoch_boottime_ns),
            summary: TracerSummary::default(),
            tasks: HashMap::new(),
            procs: HashMap::new(),
            retired: HashMap::new(),
            tracee_deaths: HashMap::new(),
            inflight: 0,
            scratch,
        }
    }

    /// Now, as elapsed time since the supervisor started: the base every gap
    /// endpoint is reported on. §11.4 bounds a gap from the last known
    /// healthy point, which is an age and not an instant on the boot clock.
    fn now_ns(&self) -> u64 {
        clock::boottime_ns().saturating_sub(self.epoch_boottime_ns)
    }

    // ---------------------------------------------------------- the outbox

    /// What an event costs the budget: its snapshots plus a fixed charge for
    /// the enum, the buffer slot and the allocator's rounding.
    fn event_bytes(event: &TracerEvent) -> usize {
        let snapshots = match event {
            TracerEvent::Syscall { args, .. } => {
                args.path.as_ref().map_or(0, |p| p.bytes.len())
                    + args.path2.as_ref().map_or(0, |p| p.bytes.len())
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

    /// Whether the event is a lifecycle fact a supervisor must never lose.
    /// These are fixed-size, so admitting them whatever the byte budget can
    /// overshoot it only by their own small size — the alternative is a
    /// supervisor without the exit status it exists to report.
    fn is_critical(event: &TracerEvent) -> bool {
        matches!(
            event,
            TracerEvent::Exit { .. }
                | TracerEvent::Gap { .. }
                | TracerEvent::Finished
                | TracerEvent::UntracedChildExit { .. }
        )
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
                    self.last_healthy_ns = self.now_ns();
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
            && self.pending_bytes + bytes <= self.result_bytes_max
    }

    fn enqueue(&mut self, event: TracerEvent, bytes: usize, lifecycle: bool) {
        if lifecycle {
            self.lifecycle_pending += 1;
        }
        if matches!(event, TracerEvent::Gap { .. }) {
            self.summary.gaps += 1;
        }
        self.pending_bytes += bytes;
        self.summary.queue_bytes_peak = self.summary.queue_bytes_peak.max(self.pending_bytes);
        self.pending.push_back(Queued {
            event,
            bytes,
            lifecycle,
        });
    }

    /// Put the coalesced gaps in front of whatever comes next, so the loss
    /// is never hidden behind the event that followed it. They are critical
    /// facts, so no cap applies to them.
    fn materialise_gap(&mut self) {
        for gap in std::mem::take(&mut self.coalesced) {
            let event = TracerEvent::Gap {
                reason: gap.reason,
                ops: gap.ops,
                from_ns: gap.from_ns,
                to_ns: gap.to_ns,
                count: gap.count,
            };
            let bytes = Session::event_bytes(&event);
            self.enqueue(event, bytes, true);
        }
    }

    fn emit(&mut self, event: TracerEvent) {
        self.flush();
        let lifecycle = Session::is_lifecycle(&event);
        let bytes = Session::event_bytes(&event);
        let ops = Session::ops_of(&event);

        if lifecycle {
            // Two caps bound the lifecycle backlog: a count, and the §11.4
            // byte budget, lifecycle events included — an `Exec` carries a
            // child-chosen pathname of up to `path_snapshot_max` bytes, so
            // without the budget the backlog alone could exceed it many times
            // over. Results stop short of [`LIFECYCLE_RESERVE`], so a dropped
            // `Exec` means the budget was full of evidence, not that the
            // reserve failed.
            let over = self.lifecycle_pending >= LIFECYCLE_MAX
                || self.pending_bytes + bytes > self.bytes_max;
            if over {
                // J4 D6: the critical facts are exempt from every cap, both
                // of them. Checking the count first, as this used to, dropped
                // a target's `Exit` behind a backlog of fork facts.
                if !Session::is_critical(&event) {
                    self.summary.loss.lifecycle_dropped += 1;
                    self.note_drop(GapReason::LifecycleDropped, ops);
                    return;
                }
                if let TracerEvent::Gap {
                    reason,
                    ops,
                    from_ns,
                    to_ns,
                    count,
                } = event
                {
                    // Not dropped: merged into this reason's summary, which
                    // is delivered ahead of the next fact. A child that can
                    // cause a gap per syscall cannot grow the backlog past
                    // one entry per reason this way.
                    self.coalesce(reason, ops, from_ns, to_ns, count);
                    return;
                }
                // `Exit`, `UntracedChildExit` and `Finished` are fixed-size
                // and bounded by the tasks that exist: past every cap.
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

    /// Record one dropped event into its reason's coalesced gap.
    fn note_drop(&mut self, reason: GapReason, ops: OpSet) {
        let now = self.now_ns();
        let from = self.last_healthy_ns;
        self.coalesce(reason, ops, from, now, Some(1));
    }

    /// Merge a gap into the summary for its reason, or open one. Reasons are
    /// never merged into each other, so no summary misnames its loss.
    fn coalesce(
        &mut self,
        reason: GapReason,
        ops: OpSet,
        from_ns: u64,
        to_ns: u64,
        count: Option<u64>,
    ) {
        if let Some(gap) = self.coalesced.iter_mut().find(|gap| gap.reason == reason) {
            gap.from_ns = gap.from_ns.min(from_ns);
            gap.to_ns = gap.to_ns.max(to_ns);
            gap.ops = gap.ops.union(ops);
            gap.count = gap.count.zip(count).and_then(|(a, b)| a.checked_add(b));
            return;
        }
        self.coalesced.push(CoalescedGap {
            reason,
            ops,
            from_ns,
            to_ns,
            count,
        });
    }

    /// Record a gap that is not queue loss. It is a lifecycle event, so it
    /// is never dropped to make room for a result.
    fn gap(&mut self, reason: GapReason, ops: OpSet, count: Option<u64>) {
        let event = TracerEvent::Gap {
            reason,
            ops,
            from_ns: self.last_healthy_ns,
            to_ns: self.now_ns(),
            count,
        };
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

    /// Forget expired retirement and fork-race entries. Both are time-bounded,
    /// so a recycled pid cannot be swallowed by a stale one for longer than
    /// the grace period.
    fn prune_retired(&mut self) {
        let now = Instant::now();
        self.retired.retain(|_, deadline| *deadline > now);
        self.tracee_deaths.retain(|_, deadline| *deadline > now);
    }

    // ---------------------------------------------------------- events

    fn handle_fork(&mut self, parent_tid: pid_t) {
        let Ok(child) = sys::event_msg(parent_tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
            return;
        };
        let child = child as pid_t;
        // Fork-ordering race: the child died before its first stop, so this
        // late event names a task that no longer exists and never executed
        // anything observable. No task entry, no identity gap, no `Fork` —
        // recording the dead pid would be false loss plus an entry nothing
        // would ever reap (§11.4: only what was seen is ever claimed).
        let raced_death = self.tracee_deaths.remove(&child).is_some();
        if proc::tgid(child).is_none() {
            if !raced_death {
                self.summary.late_fork_races += 1;
            }
            return;
        }
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
        let mut carried: Option<InFlight> = None;
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
                && let Some(pending) = task.pending
            {
                // The entry is in hand: the gap names the call it would have
                // reported, not an anonymous hole (§11.4).
                self.inflight = self.inflight.saturating_sub(1);
                self.summary.loss.abandoned_entries += 1;
                self.gap(GapReason::EntryAbandoned, pending.ops(), Some(1));
            }
        }
        if carried.is_some()
            && let Some(ops) = self
                .tasks
                .get(&tid)
                .and_then(|t| t.pending.as_ref().map(InFlight::ops))
        {
            // Both the leader and the thread that execed had a call in
            // flight; the leader's can no longer return, and the gap names
            // it because the entry is in hand.
            self.inflight = self.inflight.saturating_sub(1);
            self.summary.loss.abandoned_entries += 1;
            self.gap(GapReason::EntryAbandoned, ops, Some(1));
        }
        let mut path = None;
        let mut dirfd = None;
        if let Some(task) = self.tasks.get_mut(&tid) {
            if let Some(pending) = carried {
                task.pending = Some(pending);
            }
            if let Some(InFlight::Closed(pending)) = task.pending.as_mut()
                && pending.entry.op == ClosedOp::Exec
            {
                pending.exec_confirmed = true;
                path = pending.args.path.clone();
                dirfd = pending.args.dirfd;
            }
        }
        self.emit(TracerEvent::Exec {
            pid: tgid,
            path,
            dirfd,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    /// A `PTRACE_EVENT_SECCOMP` stop: the tracee is at the entry of a call
    /// the narrowing filter traces, and the syscall has not run.
    fn handle_entry(&mut self, tid: pid_t) {
        let Some(info) = sys::syscall_info(tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
            return;
        };
        if info.op != sys::SYSCALL_INFO_SECCOMP && info.op != sys::SYSCALL_INFO_ENTRY {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
            return;
        }
        // jail-v1 §9.2: validate the architecture before the syscall number.
        // A compat or x32 entry carries a number from a different table, and
        // naming it from this one would mislabel the call (J4 D2): it is
        // foreign, followed to its return and never decoded.
        if info.arch != sys::AUDIT_ARCH_X86_64 || info.nr & u64::from(sys::X32_SYSCALL_BIT) != 0 {
            if self.admit(OpSet::ALL) {
                self.begin(tid, InFlight::Foreign);
            }
            return;
        }
        // J4 D1: a child asking for its own notification listener. The flags
        // are the register the kernel will read, not memory the child could
        // change behind this stop.
        if info.nr == u64::from(super::filter::LISTENER_SYSCALL.1)
            && info.args[1] & u64::from(super::filter::SECCOMP_FILTER_FLAG_NEW_LISTENER) != 0
        {
            if self.admit(OpSet::ALL) {
                self.begin(tid, InFlight::Listener);
            }
            return;
        }
        let Some(entry) = closed_set::lookup(info.nr) else {
            self.stop_not_ours(tid);
            return;
        };
        if !self.admit(OpSet::of(entry.op)) {
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
        self.begin(tid, InFlight::Closed(pending));
    }

    /// Whether another call may be followed to its return. When the
    /// in-flight bound is reached the entry is refused, and the gap names
    /// what that call could have been.
    fn admit(&mut self, ops: OpSet) -> bool {
        if self.inflight >= self.config.inflight_max {
            self.summary.loss.inflight_rejected += 1;
            self.gap(GapReason::InflightExhausted, ops, Some(1));
            return false;
        }
        true
    }

    /// Record `call` as this thread's call in flight.
    fn begin(&mut self, tid: pid_t, call: InFlight) {
        let replaced = self
            .tasks
            .get(&tid)
            .and_then(|task| task.pending.as_ref().map(InFlight::ops));
        if let Some(ops) = replaced {
            // The previous entry for this thread never returned, and the gap
            // names the call it was (§11.4).
            self.summary.loss.abandoned_entries += 1;
            self.inflight = self.inflight.saturating_sub(1);
            self.gap(GapReason::EntryAbandoned, ops, Some(1));
        }
        if let Some(task) = self.tasks.get_mut(&tid) {
            task.pending = Some(call);
            self.inflight += 1;
        }
    }

    /// A stop for a number the narrowing filter never traces. The trace
    /// data says whose it is: a stop carrying other data was asked for by
    /// another filter — a child's own `SECCOMP_RET_TRACE` — on a call outside
    /// the closed set, and is continued untouched (not a result, not a loss,
    /// and never decoded). One carrying this filter's own data means the
    /// program the launcher installed is not this module's, which is a gap.
    fn stop_not_ours(&mut self, tid: pid_t) {
        match sys::event_msg(tid) {
            Ok(data)
                if data & u64::from(sys::SECCOMP_RET_DATA)
                    != u64::from(super::filter::NARROWING_TRACE_DATA) =>
            {
                self.summary.requested_by_other_filters += 1;
            }
            Ok(_) => {
                self.summary.loss.unexpected_trace_stops += 1;
                self.gap(GapReason::UnexpectedTraceStop, OpSet::ALL, Some(1));
            }
            Err(_) => {
                self.summary.loss.syscall_info_unavailable += 1;
                self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
            }
        }
    }

    /// A `SIGTRAP | 0x80` stop: the syscall entry or exit of a call whose
    /// entry we recorded.
    fn handle_syscall_stop(&mut self, tid: pid_t) {
        let Some(info) = sys::syscall_info(tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
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
                self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
            }
        }
    }

    fn handle_exit(&mut self, tid: pid_t, rval: i64) {
        let tgid = self.tgid_of(tid);
        let Some(call) = self
            .tasks
            .get_mut(&tid)
            .and_then(|task| task.pending.take())
        else {
            // A syscall exit with no entry to pair it with: either the entry
            // was never seen or this thread is not one we track.
            self.summary.loss.unmatched_exits += 1;
            self.gap(GapReason::UnmatchedExit, OpSet::ALL, Some(1));
            return;
        };
        self.inflight = self.inflight.saturating_sub(1);
        if sys::is_restart(rval) {
            // The kernel will re-enter this syscall. Its entry stops again
            // and produces the one result the call actually has.
            self.summary.restarts += 1;
            return;
        }
        let pending = match call {
            InFlight::Closed(pending) => pending,
            InFlight::Foreign => {
                if rval == -i64::from(libc::ENOSYS) {
                    // No such call in its table, or an ABI this kernel lacks
                    // (x32 on the reference host): it had no effect, and a
                    // tracee must not be able to manufacture loss by naming
                    // a call nothing has.
                    self.summary.foreign_rejected += 1;
                } else {
                    self.summary.loss.foreign_abi += 1;
                    self.gap(GapReason::ForeignAbi, OpSet::ALL, Some(1));
                }
                return;
            }
            InFlight::Listener => {
                if rval >= 0 {
                    // The return is the listener's descriptor. From here on
                    // any closed-set call may be continued with no stop, for
                    // as long as anyone holds it: every class, no count.
                    self.summary.loss.notification_listeners += 1;
                    self.gap(GapReason::ChildNotificationListener, OpSet::ALL, None);
                } else {
                    // Refused (EBUSY under the `agent` mediation listener,
                    // EINVAL, EACCES): no listener exists, nothing is hidden.
                    self.summary.listener_refused += 1;
                }
                return;
            }
        };
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
        let Some(task) = self.tasks.remove(&pid) else {
            if self.retired.remove(&pid).is_some() {
                // A thread the kernel destroyed at a non-leader exec.
                return;
            }
            if proc::tgid(pid).is_some() {
                // A tracee reported dead before its first stop: under ptrace
                // it stays in /proc as a zombie only its real parent can
                // reap, while a genuinely untraced direct child was reaped
                // by this very wait and is already gone. The fork event that
                // names it is still in flight; nothing it did was observed
                // to be lost, so this is a race to count, not a child exit
                // to report and not a gap (§11.4).
                self.summary.late_fork_races += 1;
                self.tracee_deaths.insert(pid, Instant::now() + KILL_GRACE);
                return;
            }
            self.summary.untraced_child_exits += 1;
            self.emit(TracerEvent::UntracedChildExit { pid, status });
            return;
        };
        self.summary.reaped_tasks += 1;
        if let Some(pending) = task.pending {
            // The entry can no longer return, and the gap names the call it
            // was, because the entry is in hand (§11.4).
            self.inflight = self.inflight.saturating_sub(1);
            self.summary.loss.abandoned_entries += 1;
            self.gap(GapReason::EntryAbandoned, pending.ops(), Some(1));
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
    /// The address bytes are read — the family's own size, never the length
    /// the caller declared, which is a claim and not a fact — only to decide
    /// whether the whole address was readable, and are not retained: the
    /// record names the family and the completeness of the claim, and §11.1
    /// forbids collecting argument memory nothing downstream will ever see.
    /// For a family the set does not name, only the family is read.
    fn read_sockaddr(
        &mut self,
        tid: pid_t,
        addr: u64,
        len: u64,
    ) -> (Option<SockaddrSnapshot>, bool) {
        if addr == 0 {
            return (None, false);
        }
        let unknown = SockaddrSnapshot {
            family: None,
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
                // Complete means the whole address of this family was read
                // and the caller declared at least that much, which
                // `sockaddr_len` has already bounded by the claim.
                complete: read == want,
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
/// caller declared. This is what is read to decide whether the whole address
/// was readable, and no more than that is ever touched. `None` for a family
/// the closed set does not name.
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
    use super::*;

    /// A session whose consumer never reads: the handoff holds one event.
    fn stalled_session() -> (Session, std::sync::mpsc::Receiver<TracerEvent>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let config = TracerConfig {
            queue_bytes_max: 64 * 1024 * 1024,
            ..TracerConfig::default()
        };
        (Session::new(config, tx, 0), rx)
    }

    fn fork(child: pid_t) -> TracerEvent {
        TracerEvent::Fork {
            parent: 1,
            parent_tid: 1,
            child,
            is_thread: false,
            child_start_ticks: None,
            monotonic_ns: 0,
        }
    }

    /// J4 D6, at the unit level: with the lifecycle count full, a gap is not
    /// dropped but merged into its reason's summary (so a child that causes
    /// one per syscall cannot grow the backlog), an exit is admitted past
    /// the cap, and the summaries are delivered ahead of it.
    #[test]
    fn j4_d6_gaps_past_the_caps_are_coalesced_and_exits_admitted() {
        let (mut session, rx) = stalled_session();
        let mut child = 2;
        while session.lifecycle_pending < LIFECYCLE_MAX {
            session.emit(fork(child));
            child += 1;
        }
        let queued = session.pending.len();
        session.emit(fork(child));
        assert_eq!(
            session.summary.loss.lifecycle_dropped, 1,
            "a fork is not critical"
        );
        for i in 0..10_000u64 {
            let reason = if i % 2 == 0 {
                GapReason::UnexpectedTraceStop
            } else {
                GapReason::PathUnreadable
            };
            session.gap(reason, OpSet::ALL, Some(1));
        }
        assert_eq!(
            session.pending.len(),
            queued,
            "gaps past the cap wait in their summaries, not in the backlog"
        );
        assert_eq!(
            session.summary.loss.lifecycle_dropped, 1,
            "no gap was dropped"
        );
        session.emit(TracerEvent::Exit {
            pid: 1,
            status: 0,
            monotonic_ns: 0,
        });
        let tail: Vec<&TracerEvent> = session
            .pending
            .iter()
            .skip(queued)
            .map(|queued| &queued.event)
            .collect();
        assert_eq!(tail.len(), 4, "{tail:?}");
        let counts: Vec<(GapReason, Option<u64>)> = tail
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Gap { reason, count, .. } => Some((*reason, *count)),
                _ => None,
            })
            .collect();
        assert!(counts.contains(&(GapReason::UnexpectedTraceStop, Some(5_000))));
        assert!(counts.contains(&(GapReason::PathUnreadable, Some(5_000))));
        assert!(matches!(tail[3], TracerEvent::Exit { pid: 1, .. }));
        assert_eq!(
            session.summary.loss.lifecycle_dropped, 1,
            "the exit was admitted"
        );
        drop(rx);
    }

    /// The byte budget is a cap too: with it full, an exit is still admitted
    /// and a gap still coalesced.
    #[test]
    fn j4_d6_the_byte_budget_does_not_drop_critical_facts_either() {
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        let config = TracerConfig {
            queue_bytes_max: 4 * EVENT_FIXED_BYTES,
            ..TracerConfig::default()
        };
        let mut session = Session::new(config, tx, 0);
        for child in 2..100 {
            session.emit(fork(child));
        }
        assert!(
            session.summary.loss.lifecycle_dropped > 0,
            "the budget is full"
        );
        let dropped = session.summary.loss.lifecycle_dropped;
        session.gap(GapReason::UnexpectedTraceStop, OpSet::ALL, Some(1));
        session.emit(TracerEvent::Exit {
            pid: 1,
            status: 0,
            monotonic_ns: 0,
        });
        assert_eq!(session.summary.loss.lifecycle_dropped, dropped);
        assert!(session.pending.iter().any(|queued| matches!(
            queued.event,
            TracerEvent::Gap {
                reason: GapReason::UnexpectedTraceStop,
                ..
            }
        )));
        assert!(
            session
                .pending
                .iter()
                .any(|queued| matches!(queued.event, TracerEvent::Exit { pid: 1, .. }))
        );
    }

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
