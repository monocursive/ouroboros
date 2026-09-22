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
//!   transition. A failed `execve` never reaches that event and comes out as
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
//!   that cannot be attributed each become a `Gap` with its own reason and
//!   its own counter.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use libc::pid_t;

use super::closed_set::{self, ClosedOp, Entry, FlagSource};
use super::proc;
use super::sys::{self, Wait};
use super::{
    Args, GapReason, PathSnapshot, SockaddrSnapshot, TracerConfig, TracerError, TracerEvent,
    TracerSummary, clock,
};

/// How long a tracee may be held at a stop by a consumer that is not reading.
/// After this the event is dropped and counted; the tree keeps moving.
const QUEUE_BLOCK: Duration = Duration::from_secs(1);

/// How often the full queue is retried inside that second. `SyncSender` has
/// no stable blocking send with a deadline, so the wait is a bounded poll;
/// it only runs when the queue is already full, which is the case the
/// deadline exists for.
const QUEUE_POLL: Duration = Duration::from_micros(200);

/// After the last tracee is reaped, how long to keep collecting the exits of
/// children that were never tracees — bubblewrap itself, which by design
/// outlives the namespace it built. Nothing is stopped during this window.
const DRAIN_AFTER_LAST_TRACEE: Duration = Duration::from_secs(1);

/// Poll interval inside that window.
const DRAIN_POLL: Duration = Duration::from_millis(2);

/// How long to wait for `/proc/<pid>/status` to show this thread as the
/// tracer after a successful `PTRACE_SEIZE`.
const SEIZE_CONFIRM: Duration = Duration::from_millis(500);

/// A traced thread.
struct Task {
    tgid: pid_t,
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
}

pub(super) fn run(
    launcher: pid_t,
    config: TracerConfig,
    tx: SyncSender<TracerEvent>,
    ready: Sender<Result<(), TracerError>>,
    stop: Arc<AtomicBool>,
) -> TracerSummary {
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
    // Attached is the first event, before any bookkeeping that could
    // itself produce one.
    session.emit(TracerEvent::Attached { pid: launcher });
    session.register(launcher);
    session.run_loop(&stop);
    session.finish()
}

fn seize_and_confirm(launcher: pid_t) -> Result<(), TracerError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(TracerError::UnsupportedArch);
    }
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

struct Session {
    config: TracerConfig,
    tx: SyncSender<TracerEvent>,
    /// True while the consumer is not keeping up: events are dropped without
    /// blocking until one gets through again.
    stalled: bool,
    /// The loss being coalesced into a single `Gap`, per §11.4 ("Coalesce
    /// repeated losses into bounded interval summaries").
    coalesced: Option<CoalescedGap>,
    summary: TracerSummary,
    tasks: HashMap<pid_t, Task>,
    procs: HashMap<pid_t, Process>,
    /// Threads the kernel destroyed for a reason we saw (a non-leader exec).
    /// Their wait notification, if it comes, is not an untraced child.
    retired: HashSet<pid_t>,
    inflight: usize,
    scratch: Vec<u8>,
}

struct CoalescedGap {
    reason: GapReason,
    from_ns: u64,
    to_ns: u64,
    count: u64,
}

impl Session {
    fn new(config: TracerConfig, tx: SyncSender<TracerEvent>) -> Self {
        let scratch = vec![0u8; config.path_snapshot_max.max(1)];
        Session {
            config,
            tx,
            stalled: false,
            coalesced: None,
            summary: TracerSummary::default(),
            tasks: HashMap::new(),
            procs: HashMap::new(),
            retired: HashSet::new(),
            inflight: 0,
            scratch,
        }
    }

    // ---------------------------------------------------------- emission

    /// Returns whether the event reached the queue.
    fn emit(&mut self, event: TracerEvent) -> bool {
        if self.coalesced.is_some() && !self.flush_gap() {
            // The queue is still full: this event joins the gap rather than
            // jumping ahead of the loss it would otherwise hide.
            self.record_drop();
            return false;
        }
        self.send(event)
    }

    fn send(&mut self, event: TracerEvent) -> bool {
        if self.stalled {
            // The consumer already failed to keep up once. Do not hold a
            // tracee at a stop for another second to find out again.
            return match self.tx.try_send(event) {
                Ok(()) => {
                    self.stalled = false;
                    self.summary.emitted += 1;
                    true
                }
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    self.record_drop();
                    false
                }
            };
        }
        let deadline = Instant::now() + QUEUE_BLOCK;
        let mut event = event;
        loop {
            match self.tx.try_send(event) {
                Ok(()) => {
                    self.summary.emitted += 1;
                    return true;
                }
                Err(TrySendError::Full(returned)) => {
                    if Instant::now() >= deadline {
                        // A tracee is stopped behind this event. Bounded
                        // backpressure: drop it, count it, keep the tree
                        // moving (§11.4).
                        self.stalled = true;
                        self.record_drop();
                        return false;
                    }
                    event = returned;
                    std::thread::sleep(QUEUE_POLL);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.stalled = true;
                    self.record_drop();
                    return false;
                }
            }
        }
    }

    /// Try to put the coalesced gap on the queue. Returns false while the
    /// queue is still full.
    fn flush_gap(&mut self) -> bool {
        let Some(gap) = self.coalesced.take() else {
            return true;
        };
        let event = TracerEvent::Gap {
            reason: gap.reason,
            from_ns: gap.from_ns,
            to_ns: gap.to_ns,
            count: Some(gap.count),
        };
        match self.tx.try_send(event) {
            Ok(()) => {
                self.stalled = false;
                self.summary.gaps += 1;
                self.summary.emitted += 1;
                true
            }
            Err(TrySendError::Full(event) | TrySendError::Disconnected(event)) => {
                let TracerEvent::Gap {
                    reason,
                    from_ns,
                    to_ns,
                    count,
                } = event
                else {
                    unreachable!("the event just built is a Gap")
                };
                self.coalesced = Some(CoalescedGap {
                    reason,
                    from_ns,
                    to_ns,
                    count: count.unwrap_or(0),
                });
                false
            }
        }
    }

    fn record_drop(&mut self) {
        let now = clock::boottime_ns();
        self.summary.loss.queue_dropped += 1;
        match &mut self.coalesced {
            Some(gap) => {
                gap.to_ns = now;
                gap.count += 1;
            }
            None => {
                self.coalesced = Some(CoalescedGap {
                    reason: GapReason::QueueFull,
                    from_ns: now,
                    to_ns: now,
                    count: 1,
                });
            }
        }
    }

    /// Record a gap that is not queue loss. The per-reason counters in the
    /// summary are authoritative; the event itself is best effort, exactly
    /// like every other event.
    fn gap(&mut self, reason: GapReason, count: Option<u64>) {
        let now = clock::boottime_ns();
        if self.emit(TracerEvent::Gap {
            reason,
            from_ns: now,
            to_ns: now,
            count,
        }) {
            self.summary.gaps += 1;
        }
    }

    // ---------------------------------------------------------- the loop

    fn run_loop(&mut self, stop: &Arc<AtomicBool>) {
        let mut drain_until: Option<Instant> = None;
        loop {
            if stop.load(Ordering::Acquire) && self.tasks.is_empty() {
                break;
            }
            let blocking = !self.tasks.is_empty();
            let wait = sys::wait_any(if blocking { 0 } else { libc::WNOHANG });
            match wait {
                Wait::Interrupted => continue,
                Wait::NoChildren => break,
                Wait::Nothing => {
                    // No tracees left. Keep collecting the exits of children
                    // that were never tracees for a bounded window, then stop.
                    let deadline = *drain_until
                        .get_or_insert_with(|| Instant::now() + DRAIN_AFTER_LAST_TRACEE);
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(DRAIN_POLL);
                }
                Wait::Status { pid, status } => {
                    drain_until = None;
                    self.handle(pid, status);
                }
            }
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
                if matches!(
                    signal,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                ) {
                    // A real group-stop. Leave it stopped, as whoever sent
                    // the signal intended, and stay its tracer.
                    let _ = sys::listen(pid);
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
        // ESRCH here means the tracee died between its stop and this call,
        // which the next wait reports; there is nothing to record.
        let _ = sys::restart(pid, request, signal);
    }

    // ---------------------------------------------------------- identity

    /// Make sure `tid` is tracked, learning its thread group from `/proc`.
    fn register(&mut self, tid: pid_t) {
        if self.tasks.contains_key(&tid) {
            return;
        }
        self.summary.tracees += 1;
        let (tgid, identity_known) = match proc::tgid(tid) {
            Some(tgid) => (tgid, true),
            None => {
                self.summary.loss.identity_unavailable += 1;
                self.gap(GapReason::IdentityUnavailable, Some(1));
                (tid, false)
            }
        };
        self.tasks.insert(
            tid,
            Task {
                tgid,
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

    // ---------------------------------------------------------- events

    fn handle_fork(&mut self, parent: pid_t) {
        let Ok(child) = sys::event_msg(parent) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, Some(1));
            return;
        };
        let child = child as pid_t;
        self.register(child);
        self.emit(TracerEvent::Fork {
            parent,
            child,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    fn handle_exec(&mut self, tid: pid_t) {
        self.summary.exec_transitions += 1;
        // After execve the thread group has exactly one thread and its id is
        // the leader's, which is the id this stop was reported under. If a
        // worker did the exec, PTRACE_GETEVENTMSG names the id it had before.
        let former = sys::event_msg(tid).map(|v| v as pid_t).unwrap_or(tid);
        let mut carried: Option<Pending> = None;
        if former != tid
            && former > 0
            && let Some(task) = self.tasks.remove(&former)
        {
            carried = task.pending;
            self.retired.insert(former);
            if let Some(process) = self.procs.get_mut(&task.tgid) {
                process.threads.remove(&former);
            }
        }
        let tgid = self.tgid_of(tid);
        let mut abandoned = Vec::new();
        if let Some(process) = self.procs.get_mut(&tgid) {
            for other in process.threads.iter().copied() {
                if other != tid {
                    abandoned.push(other);
                }
            }
            process.threads.retain(|thread| *thread == tid);
            process.threads.insert(tid);
            process.witnessed_exec = true;
        }
        for thread in abandoned {
            self.retired.insert(thread);
            if let Some(task) = self.tasks.remove(&thread)
                && task.pending.is_some()
            {
                self.inflight = self.inflight.saturating_sub(1);
                self.summary.loss.abandoned_entries += 1;
                self.gap(GapReason::EntryAbandoned, Some(1));
            }
        }
        if carried.is_some() && self.tasks.get(&tid).is_some_and(|t| t.pending.is_some()) {
            // Both the leader and the thread that execed had a call in
            // flight; the leader's can no longer return.
            self.inflight = self.inflight.saturating_sub(1);
            self.summary.loss.abandoned_entries += 1;
            self.gap(GapReason::EntryAbandoned, Some(1));
        }
        if let Some(task) = self.tasks.get_mut(&tid) {
            if let Some(pending) = carried {
                task.pending = Some(pending);
            }
            if let Some(pending) = task.pending.as_mut()
                && pending.entry.op == ClosedOp::Exec
            {
                pending.exec_confirmed = true;
            }
        }
        self.emit(TracerEvent::Exec {
            pid: tgid,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    /// A `PTRACE_EVENT_SECCOMP` stop: the tracee is at the entry of a
    /// closed-set call and the syscall has not run.
    fn handle_entry(&mut self, tid: pid_t) {
        let Some(info) = sys::syscall_info(tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, Some(1));
            return;
        };
        if info.op != sys::SYSCALL_INFO_SECCOMP && info.op != sys::SYSCALL_INFO_ENTRY {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, Some(1));
            return;
        }
        // jail-v1 §9.2: validate the architecture before the syscall number.
        // A compat or x32 entry carries a number from a different table, and
        // naming it from this one would mislabel the call.
        if info.arch != sys::AUDIT_ARCH_X86_64 {
            self.summary.loss.unexpected_trace_stops += 1;
            self.gap(GapReason::UnexpectedTraceStop, Some(1));
            return;
        }
        let Some(entry) = closed_set::lookup(info.nr) else {
            // The filter stopped a number this table does not name, so the
            // filter the launcher installed is not this module's. Say so.
            self.summary.loss.unexpected_trace_stops += 1;
            self.gap(GapReason::UnexpectedTraceStop, Some(1));
            return;
        };
        if self.inflight >= self.config.inflight_max {
            self.summary.loss.inflight_rejected += 1;
            self.gap(GapReason::InflightExhausted, Some(1));
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
        if flags_unavailable {
            self.summary.loss.flags_unavailable += 1;
            self.gap(GapReason::FlagsUnavailable, Some(1));
        }
        let mut args = self.capture_paths(tid, entry, &info.args);
        args.flags = flags;
        let replaced = self
            .tasks
            .get(&tid)
            .is_some_and(|task| task.pending.is_some());
        if replaced {
            // The previous entry for this thread never returned.
            self.summary.loss.abandoned_entries += 1;
            self.inflight = self.inflight.saturating_sub(1);
            self.gap(GapReason::EntryAbandoned, Some(1));
        }
        if let Some(task) = self.tasks.get_mut(&tid) {
            task.pending = Some(Pending {
                entry,
                args,
                exec_confirmed: false,
            });
            self.inflight += 1;
        }
    }

    /// A `SIGTRAP | 0x80` stop: the syscall entry or exit of a call whose
    /// entry we recorded.
    fn handle_syscall_stop(&mut self, tid: pid_t) {
        let Some(info) = sys::syscall_info(tid) else {
            self.summary.loss.syscall_info_unavailable += 1;
            self.gap(GapReason::SyscallInfoUnavailable, Some(1));
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
                self.gap(GapReason::SyscallInfoUnavailable, Some(1));
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
            self.gap(GapReason::UnmatchedExit, Some(1));
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
        self.summary.ops.bump(pending.entry.op);
        self.emit(TracerEvent::Syscall {
            pid: tgid,
            tid,
            op: pending.entry.op,
            syscall: pending.entry.name,
            args: pending.args,
            ret: rval,
            monotonic_ns: clock::boottime_ns(),
        });
    }

    fn handle_death(&mut self, pid: pid_t, status: libc::c_int) {
        let Some(task) = self.tasks.remove(&pid) else {
            if self.retired.remove(&pid) {
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
            self.gap(GapReason::EntryAbandoned, Some(1));
        }
        let Some(process) = self.procs.get_mut(&task.tgid) else {
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
            return;
        }
        if pid != task.tgid {
            // The kernel delays a group leader's report until its last
            // thread is gone, so the last reap is the leader's. If it is
            // not, the final status is a worker's and §11.2 forbids
            // presenting it as the process's.
            self.summary.loss.final_status_unknown += 1;
            self.gap(GapReason::FinalStatusUnknown, None);
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
    fn capture_paths(&mut self, tid: pid_t, entry: &'static Entry, raw: &[u64; 6]) -> Args {
        let mut args = Args::default();
        if let Some(index) = entry.path {
            args.path = self.read_path(tid, raw[index as usize]);
        }
        if let Some(index) = entry.path2 {
            args.path2 = self.read_path(tid, raw[index as usize]);
        }
        if let Some(index) = entry.dirfd {
            args.dirfd = Some(raw[index as usize] as i32);
        }
        if let Some(index) = entry.dirfd2 {
            args.dirfd2 = Some(raw[index as usize] as i32);
        }
        if let Some((ptr, len)) = entry.sockaddr {
            args.sockaddr = self.read_sockaddr(tid, raw[ptr as usize], raw[len as usize]);
        }
        args
    }

    /// A NUL-terminated pathname argument, bounded by `path_snapshot_max`.
    ///
    /// `complete` is false when the bytes ran out before a NUL or when the
    /// tracee's memory could not be read: §11.3 wants the weaker assertion
    /// carried in band, not a shorter path presented as the whole one.
    fn read_path(&mut self, tid: pid_t, addr: u64) -> Option<PathSnapshot> {
        if addr == 0 {
            return None;
        }
        let max = self.config.path_snapshot_max;
        let mut bytes: Vec<u8> = Vec::new();
        while bytes.len() < max {
            let offset = bytes.len();
            let want = max - offset;
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
                    self.summary.loss.path_unreadable += 1;
                    self.gap(GapReason::PathUnreadable, Some(1));
                    return Some(PathSnapshot {
                        bytes,
                        complete: false,
                    });
                }
                self.summary.loss.path_truncated += 1;
                return Some(PathSnapshot {
                    bytes,
                    complete: false,
                });
            }
            let chunk = &self.scratch[..read];
            if let Some(end) = chunk.iter().position(|b| *b == 0) {
                bytes.extend_from_slice(&chunk[..end]);
                return Some(PathSnapshot {
                    bytes,
                    complete: true,
                });
            }
            bytes.extend_from_slice(chunk);
        }
        self.summary.loss.path_truncated += 1;
        Some(PathSnapshot {
            bytes,
            complete: false,
        })
    }

    /// The `sockaddr` of a `connect`, as far as the closed set describes it.
    ///
    /// The address bytes are kept for `AF_INET`, `AF_INET6` and `AF_UNIX`,
    /// the three families §11.2 names. For any other family only the family
    /// and the length the caller declared are recorded: §11.1 forbids
    /// streaming argument memory that the closed set does not need.
    fn read_sockaddr(&mut self, tid: pid_t, addr: u64, len: u64) -> Option<SockaddrSnapshot> {
        if addr == 0 {
            return None;
        }
        let declared_len = u32::try_from(len).unwrap_or(u32::MAX);
        let want = (len as usize).min(128).min(self.scratch.len());
        if want < 2 {
            return Some(SockaddrSnapshot {
                family: None,
                bytes: Vec::new(),
                declared_len,
                complete: false,
            });
        }
        let read = sys::read_remote(tid, addr, &mut self.scratch[..want]);
        if read < 2 {
            self.summary.loss.path_unreadable += 1;
            self.gap(GapReason::PathUnreadable, Some(1));
            return Some(SockaddrSnapshot {
                family: None,
                bytes: Vec::new(),
                declared_len,
                complete: false,
            });
        }
        let family = u16::from_ne_bytes([self.scratch[0], self.scratch[1]]);
        let keep = matches!(
            i32::from(family),
            libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX
        );
        let bytes = if keep {
            self.scratch[..read].to_vec()
        } else {
            Vec::new()
        };
        Some(SockaddrSnapshot {
            family: Some(family),
            bytes,
            declared_len,
            complete: keep && read == want && want == len as usize,
        })
    }

    // ---------------------------------------------------------- shutdown

    fn finish(mut self) -> TracerSummary {
        let abandoned: Vec<pid_t> = self.tasks.keys().copied().collect();
        if !abandoned.is_empty() {
            // The loop stopped while tracees were alive. They keep the
            // narrowing filter, so their closed-set calls now fail with
            // ENOSYS: fail-closed, and recorded as the loss it is.
            self.summary.loss.abandoned_tracees += abandoned.len() as u64;
            for pid in abandoned {
                let _ = sys::detach(pid);
            }
            self.gap(
                GapReason::TraceesAbandoned,
                Some(self.summary.loss.abandoned_tracees),
            );
        }
        let _ = self.flush_gap();
        self.send(TracerEvent::Finished);
        self.summary
    }
}
