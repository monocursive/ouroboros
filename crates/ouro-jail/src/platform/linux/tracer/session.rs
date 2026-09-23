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
//!   kernel restart code at the exit (`ERESTARTSYS` and its family) is not a
//!   result yet: the kernel decides afterwards whether to re-enter the call
//!   or to return `EINTR` (J4 O-2), and the call stays in flight until the
//!   observer has seen that decision — see [`RestartWait`]. A re-entry
//!   produces the one result; an `EINTR` is the result; emitting the code
//!   itself would be the duplicate §11.2 forbids, and dropping it would be
//!   the silence §11.4 forbids.
//! * A read-only open never becomes an event, never takes an in-flight slot
//!   and so is never refused one (J4 O-1), and never even costs a second
//!   stop: the tracee is continued from the seccomp stop instead of being
//!   stepped to the syscall exit.
//! * A tracee killed at its seccomp entry stop before the observer resumed
//!   it made no call: the kernel skips a call whose thread has a fatal signal
//!   pending after the trace event (`__seccomp_filter`), so it is neither a
//!   result nor a loss (J4 O-3). A call the observer had already let run
//!   when the kill came may have had its effect and stays a gap.
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

/// The two `/proc` reads that name a task: its thread group and its birth.
///
/// A seam, so a unit test can play what the kernel will not hand an
/// unprivileged test on the reference host: a tid recycled for a new task
/// (J4 S1). The live implementation is [`LiveProc`].
pub(super) trait ProcView: Send {
    /// The thread group `tid` belongs to, in this process's pid namespace.
    fn tgid(&self, tid: pid_t) -> Option<pid_t>;
    /// Field 22 of `/proc/<tid>/stat`: the task's start time in clock ticks
    /// since boot.
    fn start_ticks(&self, tid: pid_t) -> Option<u64>;
}

/// `/proc`, read now.
pub(super) struct LiveProc;

impl ProcView for LiveProc {
    fn tgid(&self, tid: pid_t) -> Option<pid_t> {
        proc::tgid(tid)
    }

    fn start_ticks(&self, tid: pid_t) -> Option<u64> {
        proc::start_ticks(tid)
    }
}

/// A traced thread.
struct Task {
    tgid: pid_t,
    start_ticks: Option<u64>,
    pending: Option<InFlight>,
    /// Where `pending` entered the kernel.
    site: Site,
    /// `pending` was taken at the stop not yet resumed: a resume that fails
    /// with `ESRCH` means the kernel will skip it (J4 O-3).
    entry_fresh: bool,
    /// A call whose exit carried a restart code, waiting for the kernel's
    /// decision. While it is set the thread is single-stepped.
    restart: Option<RestartWait>,
}

/// Where a call entered the kernel: its ABI, its number and the user
/// instruction pointer just past the instruction that made it. A kernel
/// restart re-executes that instruction with the same number, so a re-entry
/// stops here again (J4 O-2).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Site {
    arch: u32,
    nr: u64,
    ip: u64,
}

/// A call whose syscall exit carried a kernel restart code (J4 O-2).
///
/// The code is not the call's result. When the thread next heads for user
/// space the kernel delivers any pending signal and then either re-enters
/// the call or returns `EINTR` (the table on [`sys::ERESTARTSYS`]). The
/// observer steps the thread (`PTRACE_SINGLESTEP`), which makes every way
/// out a stop:
///
/// * the entry stop of the re-entered call, at the same [`Site`], before any
///   user instruction has run: restarted;
/// * the notification the kernel gives a single-stepped tracee at a signal
///   handler's entry, after it has settled the call and written the frame:
///   `EINTR` or restarted, from the restart code and, for `ERESTARTSYS`
///   (whose outcome depends on `SA_RESTART`, which a tracer cannot read),
///   from the `rax` and `rip` the kernel saved in that frame;
/// * a death, or the thread's destruction by another's `execve`: the call
///   did nothing and nothing was returned — neither a result nor a loss;
/// * anything else — a step trap in user space (the continuation ran through
///   `restart_syscall`, which is not traced), an unreadable or unrecognised
///   frame, a stop out of this sequence: [`GapReason::RestartUnresolved`].
///
/// The call keeps its in-flight slot until then.
struct RestartWait {
    call: InFlight,
    /// The positive restart code.
    code: i64,
    site: Site,
    /// The last signal delivered to the thread since the exit, if any. The
    /// kernel notifies a handler's entry only after a signal was delivered.
    delivered: Option<libc::c_int>,
}

/// What the kernel did with a call whose exit carried a restart code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Re-entered: the re-entered call produces the one result.
    Restarted,
    /// `EINTR` was returned to the program: that is the call's result.
    Interrupted,
    /// Not established: a [`GapReason::RestartUnresolved`] gap.
    Unknown,
}

/// The kernel's decision at a signal handler's entry (`handle_signal` in
/// `arch/x86/kernel/signal.c`). `ERESTARTNOHAND` and `ERESTART_RESTARTBLOCK`
/// become `EINTR` and `ERESTARTNOINTR` is re-entered, whatever the handler.
/// `ERESTARTSYS` is re-entered only under `SA_RESTART`, which is read from
/// what the kernel saved in the frame: `rax = -EINTR` with `rip` unchanged,
/// or `rax` = the call's number with `rip` rewound over the two-byte
/// `syscall` (or `int 0x80`) instruction. Anything else is not a frame this
/// call produced.
fn verdict_at_handler(code: i64, frame: Option<(u64, u64)>, site: Site) -> Verdict {
    match code {
        sys::ERESTARTNOINTR => Verdict::Restarted,
        sys::ERESTARTNOHAND | sys::ERESTART_RESTARTBLOCK => Verdict::Interrupted,
        sys::ERESTARTSYS => match frame {
            Some((ax, ip)) if ax == (-i64::from(libc::EINTR)) as u64 && ip == site.ip => {
                Verdict::Interrupted
            }
            Some((ax, ip)) if ax == site.nr && ip == site.ip.wrapping_sub(2) => Verdict::Restarted,
            _ => Verdict::Unknown,
        },
        _ => Verdict::Unknown,
    }
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
    /// `clone(2)` with `CLONE_UNTRACED` (J4 S4): its return says whether a
    /// task now exists that the kernel did not attach to this tracer.
    Untraced,
}

impl InFlight {
    /// The operations a hole left by this call could have held: the row's
    /// own for a closed-set call, all of them for a call nothing decoded or
    /// a listener that could hide any of them.
    fn ops(&self) -> OpSet {
        match self {
            InFlight::Closed(pending) => OpSet::of(pending.entry.op),
            InFlight::Foreign | InFlight::Listener | InFlight::Untraced => OpSet::ALL,
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
    /// The process's birth: its leader's start time, read when the group was
    /// first registered (§11.3). Every event about the group carries it, so
    /// a later process given the same number is never confused with it.
    birth: Option<u64>,
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
    let mut session = Session::new(config, tx, epoch_boottime_ns, Box::new(LiveProc));
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
    let start_ticks = session.procfs.start_ticks(launcher);
    session.emit(TracerEvent::Attached {
        pid: launcher,
        start_ticks,
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
    /// Where task identity comes from: `/proc`, or a test's script.
    procfs: Box<dyn ProcView>,
}

impl Session {
    fn new(
        config: TracerConfig,
        tx: SyncSender<TracerEvent>,
        epoch_boottime_ns: u64,
        procfs: Box<dyn ProcView>,
    ) -> Self {
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
            procfs,
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

        if self
            .tasks
            .get(&pid)
            .is_some_and(|task| task.restart.is_some())
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
        let (request, fresh) = match self.tasks.get(&pid) {
            Some(task) if task.restart.is_some() => (sys::PTRACE_SINGLESTEP, false),
            Some(task) if task.pending.is_some() => (sys::PTRACE_SYSCALL, task.entry_fresh),
            _ => (sys::PTRACE_CONT, false),
        };
        let result = sys::restart(pid, request, signal);
        if let Some(task) = self.tasks.get_mut(&pid) {
            task.entry_fresh = false;
        }
        match result {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {
                if fresh {
                    // J4 O-3: the entry was taken at this very stop, and the
                    // tracee was killed before it could be resumed from it
                    // (at an unresumed stop only SIGKILL makes the resume
                    // fail with ESRCH). The kernel skips a call whose thread
                    // has a fatal signal pending after the trace event, so
                    // this one never ran: no result, and no loss.
                    self.entry_never_ran(pid);
                }
            }
            Err(err) => self.restart_failed(pid, &err),
        }
    }

    /// J4 O-3: forget the entry of a thread killed at its seccomp stop.
    fn entry_never_ran(&mut self, tid: pid_t) {
        if self
            .tasks
            .get_mut(&tid)
            .and_then(|task| task.pending.take())
            .is_some()
        {
            self.inflight = self.inflight.saturating_sub(1);
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

    // ---------------------------------------------------------- identity

    /// Make sure `tid` is tracked, learning its thread group and birth from
    /// `/proc`.
    fn register(&mut self, tid: pid_t) {
        if self.tasks.contains_key(&tid) {
            return;
        }
        self.summary.tracees += 1;
        let start_ticks = self.procfs.start_ticks(tid);
        let (tgid, identity_known) = match self.procfs.tgid(tid) {
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
                site: Site::default(),
                entry_fresh: false,
                restart: None,
            },
        );
        // A new group's birth is its leader's start time: the task itself
        // when it is the leader (a fork child), else the leader read now.
        // An existing group keeps the birth it was registered with.
        if !self.procs.contains_key(&tgid) {
            let birth = if tgid == tid {
                start_ticks
            } else {
                self.procfs.start_ticks(tgid)
            };
            self.procs.insert(
                tgid,
                Process {
                    threads: HashSet::new(),
                    witnessed_exec: false,
                    identity_known,
                    birth,
                },
            );
        }
        let process = self.procs.get_mut(&tgid).expect("just inserted");
        process.identity_known &= identity_known;
        process.threads.insert(tid);
    }

    fn tgid_of(&self, tid: pid_t) -> pid_t {
        self.tasks.get(&tid).map_or(tid, |task| task.tgid)
    }

    /// The birth of the process `tgid` names now.
    fn birth_of(&self, tgid: pid_t) -> Option<u64> {
        self.procs.get(&tgid).and_then(|process| process.birth)
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
        if self.procfs.tgid(child).is_none() {
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
        let mut carried: Option<(InFlight, Site)> = None;
        if former != tid
            && former > 0
            && let Some(task) = self.tasks.remove(&former)
        {
            carried = task.pending.map(|pending| (pending, task.site));
            if task.restart.is_some() {
                // Not reachable: the thread that execs is in its `execve`,
                // not waiting for a restart decision. Kept exact anyway.
                self.restart_unfinished();
            }
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
            let Some(task) = self.tasks.remove(&thread) else {
                continue;
            };
            if let Some(pending) = task.pending {
                // The entry is in hand: the gap names the call it would have
                // reported, not an anonymous hole (§11.4).
                self.inflight = self.inflight.saturating_sub(1);
                self.summary.loss.abandoned_entries += 1;
                self.gap(GapReason::EntryAbandoned, pending.ops(), Some(1));
            }
            if task.restart.is_some() {
                // Destroyed between a restart code and the kernel's
                // decision: the call did nothing and returned nothing.
                self.restart_unfinished();
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
        let mut syscall = None;
        if let Some(task) = self.tasks.get_mut(&tid) {
            if let Some((pending, site)) = carried {
                task.pending = Some(pending);
                task.site = site;
            }
            if let Some(InFlight::Closed(pending)) = task.pending.as_mut()
                && pending.entry.op == ClosedOp::Exec
            {
                pending.exec_confirmed = true;
                path = pending.args.path.clone();
                dirfd = pending.args.dirfd;
                syscall = Some(pending.entry.name);
            }
        }
        let start_ticks = self.birth_of(tgid);
        self.emit(TracerEvent::Exec {
            pid: tgid,
            start_ticks,
            syscall,
            path,
            dirfd,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    /// A `PTRACE_EVENT_SECCOMP` stop: the tracee is at the entry of a call
    /// the narrowing filter traces, and the syscall has not run.
    fn handle_entry(&mut self, tid: pid_t) {
        let info = match sys::syscall_info(tid) {
            Ok(info)
                if info.op == sys::SYSCALL_INFO_SECCOMP || info.op == sys::SYSCALL_INFO_ENTRY =>
            {
                info
            }
            // J4 O-3: the tracee left this stop without being resumed, which
            // only a SIGKILL does — it is either on its way out (`ESRCH`) or
            // already stopped at its exit notification. The kernel skips a
            // call whose thread has a fatal signal pending after the trace
            // event (`__seccomp_filter`), so whatever it was, it never ran.
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {
                self.summary.killed_at_entry += 1;
                return;
            }
            Ok(_) if Self::at_exit_notification(tid) => {
                self.summary.killed_at_entry += 1;
                return;
            }
            _ => {
                self.summary.loss.syscall_info_unavailable += 1;
                self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
                return;
            }
        };
        let site = Site {
            arch: info.arch,
            nr: info.nr,
            ip: info.ip,
        };
        // jail-v1 §9.2: validate the architecture before the syscall number.
        // A compat or x32 entry carries a number from a different table, and
        // naming it from this one would mislabel the call (J4 D2): it is
        // foreign, followed to its return and never decoded.
        if info.arch != sys::AUDIT_ARCH_X86_64 || info.nr & u64::from(sys::X32_SYSCALL_BIT) != 0 {
            if self.admit(OpSet::ALL) {
                self.begin(tid, InFlight::Foreign, site);
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
                self.begin(tid, InFlight::Listener, site);
            }
            return;
        }
        // J4 S4: a clone the kernel will not attach to this tracer. The flags
        // are the register the kernel reads. Contained baselines refuse the
        // flag (EPERM outranks the trace), so only `none` stops here.
        if info.nr == u64::from(super::filter::CLONE_SYSCALL.1)
            && info.args[0] & u64::from(super::filter::CLONE_UNTRACED) != 0
        {
            if self.admit(OpSet::ALL) {
                self.begin(tid, InFlight::Untraced, site);
            }
            return;
        }
        let Some(entry) = closed_set::lookup(info.nr) else {
            self.stop_not_ours(tid);
            return;
        };
        // Flags first: they decide whether this call is in the closed set at
        // all, and one that is not must cost neither a read of the tracee's
        // memory, nor an in-flight slot, nor a mark in the loss counters.
        let (flags, flags_unavailable) = self.capture_flags(tid, entry, &info.args);
        if entry.op == ClosedOp::Open
            && let Some(flags) = flags
            && !closed_set::open_is_covered(flags)
        {
            // A read-only open is outside `linux-closed-v1`. It is not a
            // loss, it is not an event, and the tracee is continued from
            // here rather than stepped to a syscall exit nobody reads. It is
            // filtered before the in-flight bound is consulted (J4 O-1):
            // with the table full it is still not a call the observer had to
            // follow, so refusing it would record a read as lost evidence.
            self.summary.filtered_readonly_opens += 1;
            return;
        }
        if !self.admit(OpSet::of(entry.op)) {
            return;
        }
        let mut pending = self.capture_paths(tid, entry, &info.args);
        pending.args.flags = flags;
        pending.flags_unavailable = flags_unavailable;
        self.begin(tid, InFlight::Closed(pending), site);
    }

    /// Whether a tracee is stopped at its `PTRACE_EVENT_EXIT` notification:
    /// where a thread killed at another stop stops next (J4 O-3).
    fn at_exit_notification(tid: pid_t) -> bool {
        matches!(
            sys::siginfo(tid),
            Ok((libc::SIGTRAP, code)) if code == libc::SIGTRAP | (sys::PTRACE_EVENT_EXIT << 8)
        )
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

    /// Record `call`, which entered the kernel at `site`, as this thread's
    /// call in flight.
    fn begin(&mut self, tid: pid_t, call: InFlight, site: Site) {
        if self
            .tasks
            .get(&tid)
            .is_some_and(|task| task.restart.is_some())
        {
            // A new entry while a restart decision is still owed: the entry
            // stop that could have been the re-entry was judged in
            // `handle_restart_stop`, so this is out of sequence.
            self.settle_restart(tid, Verdict::Unknown);
        }
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
            task.site = site;
            task.entry_fresh = true;
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
            // J4 O-3: killed at this seccomp stop; the kernel skips the call.
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {
                self.summary.killed_at_entry += 1;
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
        let info = match sys::syscall_info(tid) {
            Ok(info) => info,
            Err(err)
                if err.raw_os_error() == Some(libc::ESRCH)
                    && self
                        .tasks
                        .get(&tid)
                        .is_some_and(|task| task.pending.is_some()) =>
            {
                // J4 O-3, at the exit: killed after its call ran, before the
                // return could be read. The result is lost, and the entry in
                // hand is what names it: the death that follows records it
                // once, as `entry_abandoned` of that call's own classes —
                // not a second gap in every class.
                return;
            }
            Err(_) => {
                self.summary.loss.syscall_info_unavailable += 1;
                self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
                return;
            }
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
        if sys::is_restart(rval) {
            // Not a result yet (J4 O-2): the kernel decides after this stop
            // whether to re-enter the call or to return EINTR, and the call
            // stays in flight until the observer has seen which.
            if let Some(task) = self.tasks.get_mut(&tid) {
                task.restart = Some(RestartWait {
                    call,
                    code: -rval,
                    site: task.site,
                    delivered: None,
                });
            }
            return;
        }
        self.inflight = self.inflight.saturating_sub(1);
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
            InFlight::Untraced => {
                if rval > 0 {
                    // The return is the new task's id. Nothing traces it: not
                    // its calls (they fail with ENOSYS, a trace stop with no
                    // tracer), not its lifetime. §11.2 makes an untracked
                    // descendant a gap; how much it hides is unknown and the
                    // interval has no end.
                    self.summary.loss.untraced_descendants += 1;
                    self.gap(GapReason::UntracedDescendant, OpSet::ALL, None);
                } else {
                    self.summary.untraced_clone_refused += 1;
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
        let start_ticks = self.birth_of(tgid);
        self.emit(TracerEvent::Syscall {
            pid: tgid,
            start_ticks,
            tid,
            op,
            syscall: pending.entry.name,
            args: pending.args,
            ret: rval,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    // ------------------------------------------------ restart decisions (O-2)

    /// A stop of a thread whose last call exited with a restart code and is
    /// waiting for the kernel's decision ([`RestartWait`]). Returns the
    /// signal to deliver when this stop is fully handled here; `None` hands
    /// it on to the ordinary handling, after settling the wait if the stop
    /// settles it.
    fn handle_restart_stop(
        &mut self,
        tid: pid_t,
        signal: libc::c_int,
        event: libc::c_int,
    ) -> Option<libc::c_int> {
        let (code, site, delivered) = {
            let wait = self.tasks.get(&tid)?.restart.as_ref()?;
            (wait.code, wait.site, wait.delivered)
        };
        match event {
            sys::PTRACE_EVENT_SECCOMP => {
                // The thread's next entry. It was single-stepped since the
                // exit, so no user instruction ran before this one: an entry
                // of the same call at the same instruction is the kernel's
                // re-entry, and anything else is not.
                match sys::syscall_info(tid) {
                    Ok(info)
                        if info.arch == site.arch && info.nr == site.nr && info.ip == site.ip =>
                    {
                        self.settle_restart(tid, Verdict::Restarted);
                    }
                    // Killed at this stop: the death ends the wait, and the
                    // entry is judged (and skipped) by `handle_entry`.
                    Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {}
                    Ok(_) if Self::at_exit_notification(tid) => {}
                    _ => self.settle_restart(tid, Verdict::Unknown),
                }
                None
            }
            // A group-stop, or the thread's exit: the decision is still
            // ahead, or never comes. Handled as ever; the thread keeps
            // stepping.
            sys::PTRACE_EVENT_STOP | sys::PTRACE_EVENT_EXIT => None,
            0 if signal != sys::SYSCALL_STOP_SIG => {
                if signal == libc::SIGTRAP {
                    if let Some(uc) = delivered.and_then(|sig| self.handler_entry(tid, sig)) {
                        // The kernel has set up a handler and settled the
                        // call. This notification is not a signal: nothing
                        // is delivered for it.
                        let frame = Self::read_frame(tid, uc);
                        self.settle_restart(tid, verdict_at_handler(code, frame, site));
                        return Some(0);
                    }
                    if Self::is_step_trap(tid) {
                        // A step that ended in user space without a re-entry
                        // or a handler: the continuation ran through
                        // `restart_syscall`, or a code reached user space.
                        // The trap is this observer's own, not the tracee's.
                        self.settle_restart(tid, Verdict::Unknown);
                        return Some(0);
                    }
                }
                // A signal on its way: deliver it, still stepping, so the
                // handler it may run announces itself.
                if let Some(wait) = self.tasks.get_mut(&tid).and_then(|t| t.restart.as_mut()) {
                    wait.delivered = Some(signal);
                }
                Some(signal)
            }
            // A syscall stop, a fork or an exec: not a stop this sequence
            // produces. Settled as unknown, then handled as ever.
            _ => {
                self.settle_restart(tid, Verdict::Unknown);
                None
            }
        }
    }

    /// The `ucontext` of the signal frame the kernel has just set up, when
    /// the stop is the notification of a handler's entry to a single-stepped
    /// tracee: `si_code` is the notification's own, and the registers are
    /// the ones `__setup_rt_frame` loads — `rdi` the signal delivered, `rax`
    /// zero, `rsp` the frame and `rdx` its `ucontext`, one word above it. At
    /// a signal-delivery stop inside the same sequence `rax` still holds the
    /// restart code, so a `SIGTRAP` sent by anyone is not mistaken for it.
    fn handler_entry(&mut self, tid: pid_t, delivered: libc::c_int) -> Option<u64> {
        let (signo, code) = sys::siginfo(tid).ok()?;
        if signo != libc::SIGTRAP || code != sys::SI_CODE_HANDLER_ENTRY {
            return None;
        }
        let regs = sys::regs(tid).ok()?;
        let delivered = u64::try_from(delivered).ok()?;
        (regs.rax == 0 && regs.rdi == delivered && regs.rsp.checked_add(8) == Some(regs.rdx))
            .then_some(regs.rdx)
    }

    /// The interrupted `rax` and `rip` the kernel saved in the frame whose
    /// `ucontext` is at `uc`.
    fn read_frame(tid: pid_t, uc: u64) -> Option<(u64, u64)> {
        let mut word = [0u8; 8];
        let mut read = |offset: u64| {
            (sys::read_remote(tid, uc.checked_add(offset)?, &mut word) == 8)
                .then(|| u64::from_ne_bytes(word))
        };
        let ax = read(sys::FRAME_RAX)?;
        let ip = read(sys::FRAME_RIP)?;
        Some((ax, ip))
    }

    /// Whether a `SIGTRAP` stop is a trap this observer's stepping raised.
    fn is_step_trap(tid: pid_t) -> bool {
        matches!(
            sys::siginfo(tid),
            Ok((libc::SIGTRAP, sys::TRAP_TRACE | sys::TRAP_BRKPT))
        )
    }

    /// Settle a thread's restart wait with `verdict`.
    fn settle_restart(&mut self, tid: pid_t, verdict: Verdict) {
        let Some(wait) = self
            .tasks
            .get_mut(&tid)
            .and_then(|task| task.restart.take())
        else {
            return;
        };
        match verdict {
            Verdict::Restarted => {
                // The re-entered call is a new entry with its own slot.
                self.inflight = self.inflight.saturating_sub(1);
                self.summary.restarts += 1;
            }
            Verdict::Interrupted => {
                // The call's result is EINTR, delivered as any other result
                // (which also releases its slot).
                self.summary.interrupted += 1;
                if let Some(task) = self.tasks.get_mut(&tid) {
                    task.pending = Some(wait.call);
                    task.site = wait.site;
                }
                self.handle_exit(tid, -i64::from(libc::EINTR));
            }
            Verdict::Unknown => {
                self.inflight = self.inflight.saturating_sub(1);
                self.summary.loss.restart_unresolved += 1;
                self.gap(GapReason::RestartUnresolved, wait.call.ops(), Some(1));
            }
        }
    }

    /// A restart wait whose thread ended before the kernel decided.
    fn restart_unfinished(&mut self) {
        self.inflight = self.inflight.saturating_sub(1);
        self.summary.restarts_unfinished += 1;
    }

    fn handle_death(&mut self, pid: pid_t, status: libc::c_int) {
        let Some(task) = self.tasks.remove(&pid) else {
            if self.retired.remove(&pid).is_some() {
                // A thread the kernel destroyed at a non-leader exec.
                return;
            }
            if self.procfs.tgid(pid).is_some() {
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
        if task.restart.is_some() {
            // Died between a restart code and the kernel's decision (a fatal
            // signal's delivery is exactly such a decision point): the call
            // did nothing, and no result was ever returned.
            self.restart_unfinished();
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
            start_ticks: process.birth,
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
        (Session::new(config, tx, 0, Box::new(LiveProc)), rx)
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
            start_ticks: None,
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
        let mut session = Session::new(config, tx, 0, Box::new(LiveProc));
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
            start_ticks: None,
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

    /// `/proc` as a test scripts it: `tid -> (tgid, start ticks)`.
    struct ScriptedProc(std::sync::Arc<std::sync::Mutex<HashMap<pid_t, (pid_t, u64)>>>);

    impl ProcView for ScriptedProc {
        fn tgid(&self, tid: pid_t) -> Option<pid_t> {
            self.0.lock().unwrap().get(&tid).map(|(tgid, _)| *tgid)
        }
        fn start_ticks(&self, tid: pid_t) -> Option<u64> {
            self.0.lock().unwrap().get(&tid).map(|(_, ticks)| *ticks)
        }
    }

    /// A pid no real task can have (above `PID_MAX_LIMIT`), so the ptrace
    /// calls the handlers make on it fail with ESRCH and touch nothing.
    const RECYCLED: pid_t = 5_000_001;
    const WORKER: pid_t = 5_000_002;

    fn pend(session: &mut Session, tid: pid_t, nr: u64, path: &str) {
        let entry = closed_set::lookup(nr).expect("a closed-set row");
        let task = session.tasks.get_mut(&tid).expect("a registered task");
        task.pending = Some(InFlight::Closed(Pending {
            entry,
            args: Args {
                path: Some(PathSnapshot {
                    bytes: path.as_bytes().to_vec(),
                    complete: true,
                }),
                ..Args::default()
            },
            exec_confirmed: false,
            path_unreadable: false,
            path2_unreadable: false,
            sockaddr_unreadable: false,
            flags_unavailable: false,
        }));
        session.inflight += 1;
    }

    fn drained(
        rx: &std::sync::mpsc::Receiver<TracerEvent>,
        session: &mut Session,
    ) -> Vec<TracerEvent> {
        session.flush();
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            out.push(event);
            session.flush();
        }
        out
    }

    /// J4 O02, S1: a tid the kernel recycles for a new task after the old
    /// one was reaped. The stock reference host will not let an
    /// unprivileged test choose a pid (`ns_last_pid`, `clone3 set_tid` and a
    /// namespace's `pid_max` all need `CAP_SYS_ADMIN` there), so the seam
    /// over the two `/proc` reads plays it. Every event names the birth its
    /// process had when the tracer took it on: a worker's result names its
    /// leader's birth, not the worker's own, even when the worker is the
    /// first task of the group the tracer sees; the old process's exec, result
    /// and exit name the old birth; the new task under the same number names
    /// its own, inherits no witnessed exec (so its death is no `Exit`) and
    /// no entry in flight.
    #[test]
    fn j4_o02_recycled_tid_carries_nothing_over() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (tx, rx) = std::sync::mpsc::sync_channel(1024);
        let mut session = Session::new(
            TracerConfig::default(),
            tx,
            0,
            Box::new(ScriptedProc(std::sync::Arc::clone(&table))),
        );
        table.lock().unwrap().insert(RECYCLED, (RECYCLED, 1000));
        table.lock().unwrap().insert(WORKER, (RECYCLED, 1500));
        // The worker's first stop arrives before anything of its leader's:
        // the group is taken on through the worker, and is still named by
        // its leader's birth, not by the worker's own.
        session.register(WORKER);
        session.register(RECYCLED);
        pend(&mut session, WORKER, 83, "/w/by-worker");
        session.handle_exit(WORKER, 0);
        session.handle_death(WORKER, 0);
        session.handle_exec(RECYCLED);
        pend(&mut session, RECYCLED, 83, "/w/old");
        session.handle_exit(RECYCLED, 0);
        session.handle_death(RECYCLED, 0);
        // Reaped: the kernel may now give the number to a new task.
        table.lock().unwrap().insert(RECYCLED, (RECYCLED, 2000));
        session.register(RECYCLED);
        pend(&mut session, RECYCLED, 87, "/w/new");
        session.handle_exit(RECYCLED, -i64::from(libc::ENOENT));
        session.handle_death(RECYCLED, libc::SIGKILL);
        let events = drained(&rx, &mut session);
        let seen: Vec<(String, Option<u64>)> = events
            .iter()
            .map(|event| match event {
                TracerEvent::Exec {
                    pid, start_ticks, ..
                } => (format!("exec {pid}"), *start_ticks),
                TracerEvent::Syscall {
                    pid,
                    tid,
                    syscall,
                    start_ticks,
                    ..
                } => (format!("{syscall} {pid}/{tid}"), *start_ticks),
                TracerEvent::Exit {
                    pid, start_ticks, ..
                } => (format!("exit {pid}"), *start_ticks),
                other => (format!("{other:?}"), None),
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                (format!("mkdir {RECYCLED}/{WORKER}"), Some(1000)),
                (format!("exec {RECYCLED}"), Some(1000)),
                (format!("mkdir {RECYCLED}/{RECYCLED}"), Some(1000)),
                (format!("exit {RECYCLED}"), Some(1000)),
                (format!("unlink {RECYCLED}/{RECYCLED}"), Some(2000)),
            ],
            "the new task under the old number never execed: no second exit"
        );
        assert_eq!(
            session.summary.loss.total(),
            0,
            "{:?}",
            session.summary.loss
        );
        assert_eq!(session.inflight, 0, "no entry carried over");
        assert!(session.tasks.is_empty() && session.procs.is_empty());
    }

    /// J4 S4 at the session: a `clone(CLONE_UNTRACED)` that created a task
    /// is a gap in every class with no count; one that failed is nothing.
    #[test]
    fn j4_s4_an_untraced_descendant_is_a_gap_and_a_failed_clone_is_not() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        table.lock().unwrap().insert(RECYCLED, (RECYCLED, 1000));
        let (tx, rx) = std::sync::mpsc::sync_channel(64);
        let mut session = Session::new(
            TracerConfig::default(),
            tx,
            0,
            Box::new(ScriptedProc(std::sync::Arc::clone(&table))),
        );
        session.register(RECYCLED);
        session.begin(RECYCLED, InFlight::Untraced, Site::default());
        session.handle_exit(RECYCLED, -i64::from(libc::EPERM));
        assert_eq!(session.summary.untraced_clone_refused, 1);
        session.begin(RECYCLED, InFlight::Untraced, Site::default());
        session.handle_exit(RECYCLED, 4242);
        let gaps: Vec<(GapReason, OpSet, Option<u64>)> = drained(&rx, &mut session)
            .into_iter()
            .filter_map(|event| match event {
                TracerEvent::Gap {
                    reason, ops, count, ..
                } => Some((reason, ops, count)),
                _ => None,
            })
            .collect();
        assert_eq!(
            gaps,
            vec![(GapReason::UntracedDescendant, OpSet::ALL, None)]
        );
        assert_eq!(session.summary.loss.untraced_descendants, 1);
        assert!(GapReason::UntracedDescendant.is_open_ended());
        assert_eq!(
            GapReason::UntracedDescendant.as_str(),
            "untraced_descendant"
        );
    }

    // ------------------------------------------------ O-2, the decision

    /// J4 O-2: the kernel's rule at a handler's entry, for every restart
    /// code. Only `ERESTARTSYS` depends on the frame, and only the two frames
    /// the kernel writes for it are accepted.
    #[test]
    fn j4_o2_the_verdict_at_a_handler_follows_the_kernel_for_every_code() {
        let site = Site {
            arch: sys::AUDIT_ARCH_X86_64,
            nr: 257,
            ip: 0x40_1002,
        };
        let eintr = (-i64::from(libc::EINTR)) as u64;
        let restarted = Some((257, 0x40_1000));
        let interrupted = Some((eintr, 0x40_1002));
        for frame in [None, restarted, interrupted] {
            assert_eq!(
                verdict_at_handler(sys::ERESTARTNOINTR, frame, site),
                Verdict::Restarted,
                "ERESTARTNOINTR is re-entered whatever the handler"
            );
            for code in [sys::ERESTARTNOHAND, sys::ERESTART_RESTARTBLOCK] {
                assert_eq!(
                    verdict_at_handler(code, frame, site),
                    Verdict::Interrupted,
                    "{code} becomes EINTR under any handler"
                );
            }
        }
        assert_eq!(
            verdict_at_handler(sys::ERESTARTSYS, interrupted, site),
            Verdict::Interrupted,
            "no SA_RESTART"
        );
        assert_eq!(
            verdict_at_handler(sys::ERESTARTSYS, restarted, site),
            Verdict::Restarted,
            "SA_RESTART"
        );
        for frame in [
            None,
            Some((257, 0x40_1002)),
            Some((eintr, 0x40_1000)),
            Some((0, 0x40_1002)),
            Some((258, 0x40_1000)),
            Some((eintr, 0x40_2002)),
        ] {
            assert_eq!(
                verdict_at_handler(sys::ERESTARTSYS, frame, site),
                Verdict::Unknown,
                "{frame:x?} is not a frame the kernel wrote for this call"
            );
        }
        assert_eq!(
            verdict_at_handler(515, interrupted, site),
            Verdict::Unknown,
            "515 is not a restart code"
        );
    }

    fn waiting(session: &mut Session, tid: pid_t, nr: u64, path: &str) {
        pend(session, tid, nr, path);
        session.handle_exit(tid, -sys::ERESTARTSYS);
    }

    /// J4 O-2 at the session: a restart code keeps the call in flight; each
    /// way the wait ends gives exactly what it should — `EINTR` one result,
    /// a re-entry nothing (the re-entered call is its own entry), an
    /// unresolved decision one gap naming the call's classes, a death
    /// nothing — and every one releases the slot.
    #[test]
    fn j4_o2_each_end_of_a_restart_wait_is_exact() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        table.lock().unwrap().insert(RECYCLED, (RECYCLED, 1000));
        let (tx, rx) = std::sync::mpsc::sync_channel(64);
        let mut session = Session::new(
            TracerConfig::default(),
            tx,
            0,
            Box::new(ScriptedProc(std::sync::Arc::clone(&table))),
        );
        session.register(RECYCLED);

        waiting(&mut session, RECYCLED, 257, "/w/interrupted");
        assert_eq!(session.inflight, 1, "still in flight while waiting");
        assert!(drained(&rx, &mut session).is_empty(), "no result yet");
        session.settle_restart(RECYCLED, Verdict::Interrupted);
        let events = drained(&rx, &mut session);
        assert!(
            matches!(
                events.as_slice(),
                [TracerEvent::Syscall { op: ClosedOp::Open, ret, .. }] if *ret == -i64::from(libc::EINTR)
            ),
            "{events:?}"
        );
        assert_eq!(session.inflight, 0);

        waiting(&mut session, RECYCLED, 83, "/w/restarted");
        session.settle_restart(RECYCLED, Verdict::Restarted);
        assert!(drained(&rx, &mut session).is_empty());
        assert_eq!(session.inflight, 0);

        waiting(&mut session, RECYCLED, 83, "/w/unknown");
        session.settle_restart(RECYCLED, Verdict::Unknown);
        let events = drained(&rx, &mut session);
        assert!(
            matches!(
                events.as_slice(),
                [TracerEvent::Gap { reason: GapReason::RestartUnresolved, ops, count: Some(1), .. }]
                    if *ops == OpSet::of(ClosedOp::Mkdir)
            ),
            "{events:?}"
        );
        assert_eq!(session.inflight, 0);

        waiting(&mut session, RECYCLED, 83, "/w/died");
        session.handle_death(RECYCLED, libc::SIGKILL);
        assert!(drained(&rx, &mut session).is_empty(), "no result, no gap");
        assert_eq!(session.inflight, 0);

        assert_eq!(session.summary.interrupted, 1);
        assert_eq!(session.summary.restarts, 1);
        assert_eq!(session.summary.restarts_unfinished, 1);
        assert_eq!(session.summary.loss.restart_unresolved, 1);
        assert_eq!(
            session.summary.loss.total(),
            1,
            "{:?}",
            session.summary.loss
        );
        assert_eq!(GapReason::RestartUnresolved.as_str(), "restart_unresolved");
        assert!(!GapReason::RestartUnresolved.is_open_ended());
    }

    // ------------------------------------------------ O-3, with a real kernel

    /// A child of this test, seized by the calling thread, that has the
    /// narrowing filter installed and makes one `mkdir` of `path` when
    /// released: its first stop is that call's seccomp entry stop.
    struct Mkdirer {
        pid: pid_t,
        go: libc::c_int,
    }

    impl Mkdirer {
        /// `None` when this host will not let a test trace its own child.
        fn start(path: &std::ffi::CStr) -> Option<Mkdirer> {
            let mut fds: [libc::c_int; 2] = [0; 2];
            // SAFETY: `pipe2` writes two descriptors into the live array.
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            // SAFETY: the child runs only async-signal-safe code — `close`,
            // the allocation-free filter install, `read`, one raw syscall
            // with a pointer prepared before the fork, and `_exit` — so the
            // other threads of this test process cannot matter to it.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // SAFETY: as above; every pointer is live in the child's copy
                // of this address space.
                unsafe {
                    libc::close(fds[1]);
                    if super::super::install_narrowing_filter().is_err() {
                        libc::_exit(3);
                    }
                    let mut byte = 0u8;
                    libc::read(fds[0], (&raw mut byte).cast::<libc::c_void>(), 1);
                    libc::syscall(libc::SYS_mkdir, path.as_ptr(), 0o700);
                    libc::_exit(0);
                }
            }
            assert!(pid > 0, "fork: {}", std::io::Error::last_os_error());
            // SAFETY: the read end belongs to the child now.
            unsafe { libc::close(fds[0]) };
            let child = Mkdirer { pid, go: fds[1] };
            if let Err(err) = sys::seize(pid, sys::SEIZE_OPTIONS) {
                ouro_fixture::harness::skip_or_fail(&format!(
                    "this host will not let a test trace its own child: {err}"
                ));
                return None;
            }
            Some(child)
        }

        /// Release the child and return the status of its first stop.
        fn release(&self) -> libc::c_int {
            // SAFETY: one byte from a live buffer to a descriptor we own.
            assert_eq!(
                unsafe { libc::write(self.go, b"g".as_ptr().cast::<libc::c_void>(), 1) },
                1
            );
            self.wait()
        }

        /// The next status of this child only: never `waitpid(-1)`, which
        /// would take another test's children.
        fn wait(&self) -> libc::c_int {
            let mut status = 0;
            // SAFETY: `waitpid` writes one int through a live pointer.
            let got = unsafe { libc::waitpid(self.pid, &raw mut status, libc::__WALL) };
            assert_eq!(got, self.pid, "{}", std::io::Error::last_os_error());
            status
        }

        fn kill(&self) {
            // SAFETY: a pid this test created, and a valid signal.
            assert_eq!(unsafe { libc::kill(self.pid, libc::SIGKILL) }, 0);
        }

        /// Hand every remaining status to the session until the child is
        /// reaped.
        fn reap_into(&self, session: &mut Session) {
            loop {
                let status = self.wait();
                session.handle(self.pid, status);
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    return;
                }
            }
        }
    }

    impl Drop for Mkdirer {
        fn drop(&mut self) {
            // SAFETY: our own pid and descriptor; both calls tolerate either
            // being already gone.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                libc::close(self.go);
            }
        }
    }

    fn live_session() -> (Session, std::sync::mpsc::Receiver<TracerEvent>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(1024);
        (
            Session::new(TracerConfig::default(), tx, 0, Box::new(LiveProc)),
            rx,
        )
    }

    fn is_seccomp_stop(status: libc::c_int) -> bool {
        libc::WIFSTOPPED(status) && (status >> 16) & 0xff == sys::PTRACE_EVENT_SECCOMP
    }

    fn gaps_of(events: &[TracerEvent]) -> Vec<(GapReason, OpSet, Option<u64>)> {
        events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Gap {
                    reason, ops, count, ..
                } => Some((*reason, *ops, *count)),
                _ => None,
            })
            .collect()
    }

    fn target_path(dir: &std::path::Path) -> (std::path::PathBuf, std::ffi::CString) {
        let target = dir.join("made");
        let c = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
        (target, c)
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
        let (mut session, rx) = live_session();
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

    /// J4 O-3, the first window: the tracee is killed after the tracer has
    /// taken its seccomp entry stop from `waitpid` and before the tracer
    /// reads it. `PTRACE_GET_SYSCALL_INFO` then fails with `ESRCH` — and the
    /// kernel skips the call, because a fatal signal is pending after the
    /// trace event (`__seccomp_filter`). The directory is never made: the
    /// call had no effect, so it is not loss.
    #[test]
    fn j4_o3_a_tracee_killed_before_its_entry_is_read_made_no_call() {
        let dir = tempfile::tempdir().unwrap();
        let (target, c) = target_path(dir.path());
        let Some(child) = Mkdirer::start(&c) else {
            return;
        };
        let (mut session, rx) = live_session();
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
        assert_eq!(session.inflight, 0);
    }

    /// J4 O-3, the second window: the entry was read (the tracer holds it)
    /// and the tracee is killed before the tracer resumes it. The resume
    /// fails with `ESRCH`, and the kernel skips the call for the same
    /// reason. The entry is not abandoned: it never ran.
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
            let (mut session, rx) = live_session();
            let status = child.release();
            assert!(is_seccomp_stop(status), "status {status:#x}");
            session.register(child.pid);
            session.handle_entry(child.pid);
            assert_eq!(session.inflight, 1, "the entry is in hand");
            child.kill();
            session.restart(child.pid, 0);
            let met_the_killed_stop = session.summary.killed_at_entry == 1;
            child.reap_into(&mut session);
            let events = drained(&rx, &mut session);
            assert!(!target.exists(), "the kernel skipped the call");
            assert_eq!(session.inflight, 0);
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

    /// J4 O-3, the exit window: the tracee is killed after its call ran and
    /// stopped at its syscall exit, before the tracer read the return. The
    /// call did run (the directory exists), and its result can no longer be
    /// read: that is a loss, and exactly one — of the call's own classes
    /// (`entry_abandoned` naming `mkdir`), not a second gap in every class.
    #[test]
    fn j4_o3_a_tracee_killed_at_its_exit_stop_is_one_loss_of_its_own_classes() {
        let dir = tempfile::tempdir().unwrap();
        let (target, c) = target_path(dir.path());
        let Some(child) = Mkdirer::start(&c) else {
            return;
        };
        let (mut session, rx) = live_session();
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
        assert_eq!(session.inflight, 0);
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
