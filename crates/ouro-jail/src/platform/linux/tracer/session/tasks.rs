//! The traced threads and processes: who a task is, the one call it has in
//! flight, and what its birth and death mean for the events (§11.2, §11.3).

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use libc::pid_t;

use super::owed::Owed;
use super::restart::{Awaiting, RestartWait, Site};
use super::{KILL_GRACE, Session};
use crate::platform::linux::tracer::closed_set::{ClosedOp, Entry};
use crate::platform::linux::tracer::sys;
use crate::platform::linux::tracer::{Args, GapReason, OpSet, TracerEvent};

/// A traced thread.
pub(super) struct Task {
    pub(super) tgid: pid_t,
    pub(super) start_ticks: Option<u64>,
    /// Changed only by [`Tasks`], which keeps the in-flight count with it.
    state: TaskState,
}

impl Task {
    pub(super) fn state(&self) -> &TaskState {
        &self.state
    }

    /// The state of a task no longer in the table, whose slot the table
    /// already released.
    pub(super) fn into_state(self) -> TaskState {
        self.state
    }
}

/// Where a traced thread is in the one call the observer follows for it at
/// a time.
pub(super) enum TaskState {
    /// Between calls: nothing of this thread's is in flight.
    Idle,
    /// A call entered the kernel at `site` and has not returned.
    InFlight {
        call: Call,
        site: Site,
        /// The call was taken at the stop not yet resumed: a resume that
        /// fails with `ESRCH` means the kernel will skip it (J4 O-3).
        fresh: bool,
    },
    /// A call whose exit carried a restart code, waiting for the kernel's
    /// decision ([`RestartWait`]). While it waits for the decision itself
    /// the thread is single-stepped.
    Restarting(RestartWait),
}

impl TaskState {
    /// Whether the thread holds one of the `inflight_max` slots: from a
    /// call's entry until its result, its loss or its end is settled.
    fn holds_slot(&self) -> bool {
        !matches!(self, TaskState::Idle)
    }
}

/// The traced threads by tid, and how many of them hold an in-flight slot.
///
/// A thread holds a slot exactly while its state is not
/// [`TaskState::Idle`]. A state is changed or dropped only here, by a named
/// transition that keeps the count with it, so the count cannot drift from
/// the states it counts: a slot is taken in one place,
/// [`Tasks::begin_call`], and released in one, [`Tasks::release`]. No
/// transition puts one call or wait in the place of another: the only moves
/// between the two states that hold a slot carry the same call
/// ([`Tasks::start_wait`], [`Tasks::end_wait_into_call`]), and a call is
/// begun only on a thread between calls.
#[derive(Default)]
pub(super) struct Tasks {
    map: HashMap<pid_t, Task>,
    in_flight: usize,
}

impl Tasks {
    pub(super) fn get(&self, tid: pid_t) -> Option<&Task> {
        self.map.get(&tid)
    }

    pub(super) fn contains(&self, tid: pid_t) -> bool {
        self.map.contains_key(&tid)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    pub(super) fn tids(&self) -> Vec<pid_t> {
        self.map.keys().copied().collect()
    }

    /// How many threads hold an in-flight slot.
    pub(super) fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Track `tid`, a thread of `tgid` born at `start_ticks`, between calls.
    /// A tid already tracked keeps its task and whatever it has in flight:
    /// registering a thread twice is the caller's mistake, never a new
    /// thread that could hide the old one's call.
    pub(super) fn insert(&mut self, tid: pid_t, tgid: pid_t, start_ticks: Option<u64>) {
        debug_assert!(!self.map.contains_key(&tid), "tid {tid} is already tracked");
        self.map.entry(tid).or_insert(Task {
            tgid,
            start_ticks,
            state: TaskState::Idle,
        });
    }

    /// Stop tracking `tid`, releasing the slot its state held.
    #[must_use]
    pub(super) fn remove(&mut self, tid: pid_t) -> Option<Task> {
        let task = self.map.remove(&tid)?;
        if task.state.holds_slot() {
            self.release();
        }
        Some(task)
    }

    /// Put `call`, which entered the kernel at `site`, in flight for `tid`,
    /// taking its slot; `fresh` when it was taken at the stop not yet
    /// resumed.
    ///
    /// Only a thread between calls begins one. A thread that still has a
    /// call or a restart wait is refused and keeps it — the callers end
    /// either first, and refusing is what keeps an unended one from
    /// vanishing without the gap its end records — so the refused call is
    /// never paired, and its exit is an `unmatched_exit` gap.
    pub(super) fn begin_call(&mut self, tid: pid_t, call: Call, site: Site, fresh: bool) {
        let Some(task) = self.map.get_mut(&tid) else {
            return;
        };
        debug_assert!(
            matches!(task.state, TaskState::Idle),
            "tid {tid} begins a call with one in flight or a restart owed"
        );
        if matches!(task.state, TaskState::Idle) {
            task.state = TaskState::InFlight { call, site, fresh };
            self.in_flight += 1;
        }
    }

    /// Turn the call `tid` has in flight into a wait for the kernel's
    /// decision on the restart `code` (J4 O-2). The wait keeps the call, the
    /// site it entered at — where a re-entry stops again — and its slot.
    /// False, with nothing changed, when `tid` has no call in flight.
    #[must_use]
    pub(super) fn start_wait(&mut self, tid: pid_t, code: i64) -> bool {
        let Some(task) = self.map.get_mut(&tid) else {
            return false;
        };
        match std::mem::replace(&mut task.state, TaskState::Idle) {
            TaskState::InFlight { call, site, .. } => {
                task.state = TaskState::Restarting(RestartWait {
                    call,
                    code,
                    site,
                    delivered: None,
                    awaiting: Awaiting::Decision,
                });
                true
            }
            other => {
                task.state = other;
                false
            }
        }
    }

    /// End the restart wait of `tid` with its call back in flight, keeping
    /// its slot: the kernel returned `EINTR`, which is the call's result.
    /// False, with nothing changed, when `tid` has no wait.
    #[must_use]
    pub(super) fn end_wait_into_call(&mut self, tid: pid_t) -> bool {
        let Some(task) = self.map.get_mut(&tid) else {
            return false;
        };
        match std::mem::replace(&mut task.state, TaskState::Idle) {
            TaskState::Restarting(wait) => {
                task.state = TaskState::InFlight {
                    call: wait.call,
                    site: wait.site,
                    fresh: false,
                };
                true
            }
            other => {
                task.state = other;
                false
            }
        }
    }

    fn release(&mut self) {
        debug_assert!(self.in_flight > 0, "a slot released that was never taken");
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Whatever `tid` had — a call in flight, a restart wait, or nothing —
    /// leaving it between calls; `None` when `tid` is not tracked.
    #[must_use]
    pub(super) fn take_state(&mut self, tid: pid_t) -> Option<TaskState> {
        let task = self.map.get_mut(&tid)?;
        let left = std::mem::replace(&mut task.state, TaskState::Idle);
        if left.holds_slot() {
            self.release();
        }
        Some(left)
    }

    /// The call `tid` has in flight, leaving the thread between calls;
    /// `None`, with nothing changed, when it has none.
    #[must_use]
    pub(super) fn take_call(&mut self, tid: pid_t) -> Option<Call> {
        let task = self.map.get_mut(&tid)?;
        match std::mem::replace(&mut task.state, TaskState::Idle) {
            TaskState::InFlight { call, .. } => {
                self.release();
                Some(call)
            }
            other => {
                task.state = other;
                None
            }
        }
    }

    /// The restart wait of `tid`, leaving the thread between calls; `None`,
    /// with nothing changed, when it has none.
    #[must_use]
    pub(super) fn take_restart(&mut self, tid: pid_t) -> Option<RestartWait> {
        let task = self.map.get_mut(&tid)?;
        match std::mem::replace(&mut task.state, TaskState::Idle) {
            TaskState::Restarting(wait) => {
                self.release();
                Some(wait)
            }
            other => {
                task.state = other;
                None
            }
        }
    }

    /// The call `tid` has in flight, to amend in place.
    pub(super) fn call_mut(&mut self, tid: pid_t) -> Option<&mut Call> {
        match &mut self.map.get_mut(&tid)?.state {
            TaskState::InFlight { call, .. } => Some(call),
            _ => None,
        }
    }

    /// The restart wait of `tid`.
    pub(super) fn wait(&self, tid: pid_t) -> Option<&RestartWait> {
        match &self.map.get(&tid)?.state {
            TaskState::Restarting(wait) => Some(wait),
            _ => None,
        }
    }

    /// The restart wait of `tid`, to amend in place.
    pub(super) fn wait_mut(&mut self, tid: pid_t) -> Option<&mut RestartWait> {
        match &mut self.map.get_mut(&tid)?.state {
            TaskState::Restarting(wait) => Some(wait),
            _ => None,
        }
    }

    /// Whether the call `tid` has in flight was taken at the stop it is now
    /// being resumed from. Once asked, it no longer is.
    pub(super) fn take_fresh(&mut self, tid: pid_t) -> bool {
        match self.map.get_mut(&tid).map(|task| &mut task.state) {
            Some(TaskState::InFlight { fresh, .. }) => std::mem::take(fresh),
            _ => false,
        }
    }
}

/// A call the observer follows from its entry stop to its return: what the
/// entry said it was.
///
/// One exists per in-flight syscall, so the variants' size difference (the
/// closed-set call's captured arguments) costs at most a few hundred bytes
/// per stopped task.
#[allow(clippy::large_enum_variant)]
pub(super) enum Call {
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

impl Call {
    /// The operations a hole left by this call could have held: the row's
    /// own for a closed-set call, all of them for a call nothing decoded or
    /// a listener that could hide any of them.
    pub(super) fn ops(&self) -> OpSet {
        match self {
            Call::Closed(pending) => OpSet::of(pending.entry.op),
            Call::Foreign | Call::Listener | Call::Untraced => OpSet::ALL,
        }
    }
}

/// A traced thread group.
pub(super) struct Process {
    pub(super) threads: HashSet<pid_t>,
    /// Set by `PTRACE_EVENT_EXEC`. §11.2 ties `proc.exit` to a witnessed
    /// exec, so a fork child that never execs emits none.
    pub(super) witnessed_exec: bool,
    /// False when `/proc` would not say which thread group this task belongs
    /// to. Such a group never gets an `Exit`: the gap was already recorded.
    identity_known: bool,
    /// The process's birth: its leader's start time, read when the group was
    /// first registered (§11.3). Every event about the group carries it, so
    /// a later process given the same number is never confused with it.
    birth: Option<u64>,
}

#[derive(Clone)]
/// A closed-set call that has entered the kernel and not yet returned.
pub(super) struct Pending {
    pub(super) entry: &'static Entry,
    pub(super) args: Args,
    /// `PTRACE_EVENT_EXEC` arrived for this entry, so the syscall exit that
    /// follows is the transition already reported and not a second result.
    pub(super) exec_confirmed: bool,
    /// Arguments that could not be read. Which of these is loss and which is
    /// a tracee passing a pointer that never could have worked is decided at
    /// the syscall exit, from the kernel's own return.
    pub(super) path_unreadable: bool,
    pub(super) path2_unreadable: bool,
    pub(super) sockaddr_unreadable: bool,
    pub(super) flags_unavailable: bool,
    /// The entry-stop register arguments, kept so the exit can re-read the
    /// memory the kernel re-reads after the stop and prove the snapshot
    /// stable. Registers cannot change between the stops; only pointed
    /// memory can.
    pub(super) raw: [u64; 6],
    /// The argv the command rules judged at an exec's entry stop, kept for
    /// the re-check against the kernel's own copy at the exec event
    /// ([`exec_recheck`]). `None` for every other call, and whenever no
    /// command rules are configured.
    pub(super) entry_argv: Option<Vec<Vec<u8>>>,
}

impl Pending {
    /// The call of row `entry`, entered with the registers `raw` and the
    /// arguments `args` read from them: every argument readable, nothing
    /// confirmed and no argv judged until a step says otherwise.
    pub(super) fn new(entry: &'static Entry, args: Args, raw: [u64; 6]) -> Pending {
        Pending {
            entry,
            args,
            exec_confirmed: false,
            path_unreadable: false,
            path2_unreadable: false,
            sockaddr_unreadable: false,
            flags_unavailable: false,
            raw,
            entry_argv: None,
        }
    }
}

impl Session {
    /// Make sure `tid` is tracked, learning its thread group and birth from
    /// `/proc`.
    pub(super) fn register(&mut self, tid: pid_t) {
        if self.tasks.contains(tid) {
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
        self.tasks.insert(tid, tgid, start_ticks);
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

    pub(super) fn tgid_of(&self, tid: pid_t) -> pid_t {
        self.tasks.get(tid).map_or(tid, |task| task.tgid)
    }

    /// The birth of the process `tgid` names now.
    pub(super) fn birth_of(&self, tgid: pid_t) -> Option<u64> {
        self.procs.get(&tgid).and_then(|process| process.birth)
    }

    /// Forget expired retirement and fork-race entries. Both are time-bounded,
    /// so a recycled pid cannot be swallowed by a stale one for longer than
    /// the grace period.
    pub(super) fn prune_retired(&mut self) {
        let now = Instant::now();
        self.retired.retain(|_, deadline| *deadline > now);
        self.tracee_deaths.retain(|_, deadline| *deadline > now);
    }

    pub(super) fn handle_fork(&mut self, parent_tid: pid_t) {
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
        let child_start_ticks = self.tasks.get(child).and_then(|task| task.start_ticks);
        self.emit(TracerEvent::Fork {
            parent,
            parent_tid,
            child,
            // A CLONE_THREAD child lands in the thread group that made the
            // call; a new process starts its own.
            is_thread: child_tgid == parent,
            child_start_ticks,
        });
    }

    pub(super) fn handle_death(&mut self, pid: pid_t, status: libc::c_int) {
        let Some(task) = self.tasks.remove(pid) else {
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
            // J5-T: the backend's exit is the one the tracer owes; any other
            // child's is delivered all the same, and is not the tree's.
            if let Owed::Backend {
                pid: backend,
                reaped,
                ..
            } = &mut self.owed
                && *backend == pid
            {
                *reaped = true;
            }
            self.summary.untraced_child_exits += 1;
            self.emit(TracerEvent::UntracedChildExit { pid, status });
            return;
        };
        self.summary.reaped_tasks += 1;
        match task.state {
            TaskState::InFlight { call, .. } => {
                // The entry can no longer return, and the gap names the call
                // it was, because the entry is in hand (§11.4).
                self.summary.loss.abandoned_entries += 1;
                self.gap(GapReason::EntryAbandoned, call.ops(), Some(1));
            }
            // Died while its restart was owed (a fatal signal's delivery is
            // exactly such a decision point).
            TaskState::Restarting(wait) => self.restart_ended(wait),
            TaskState::Idle => {}
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
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::TracerConfig;

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
        let proc = FakeProc::default()
            .task(RECYCLED, RECYCLED, 1000)
            .task(WORKER, RECYCLED, 1500);
        let (mut session, rx) = new_session(TracerConfig::default(), proc.clone(), 1024);
        // The worker's first stop arrives before anything of its leader's:
        // the group is taken on through the worker, and is still named by
        // its leader's birth, not by the worker's own.
        session.register(WORKER);
        session.register(RECYCLED);
        pend(
            &mut session,
            WORKER,
            u64::from(crate::platform::linux::abi::nr(83, 34)),
            "/w/by-worker",
        );
        session.handle_exit(WORKER, 0);
        session.handle_death(WORKER, 0);
        session.handle_exec(RECYCLED);
        pend(
            &mut session,
            RECYCLED,
            u64::from(crate::platform::linux::abi::nr(83, 34)),
            "/w/old",
        );
        session.handle_exit(RECYCLED, 0);
        session.handle_death(RECYCLED, 0);
        // Reaped: the kernel may now give the number to a new task.
        proc.edit(|script| {
            script.tasks.insert(RECYCLED, (RECYCLED, 2000));
        });
        session.register(RECYCLED);
        pend(
            &mut session,
            RECYCLED,
            u64::from(crate::platform::linux::abi::nr(87, 35)),
            "/w/new",
        );
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
        let mkdir = if cfg!(target_arch = "aarch64") {
            "mkdirat"
        } else {
            "mkdir"
        };
        let unlink = if cfg!(target_arch = "aarch64") {
            "unlinkat"
        } else {
            "unlink"
        };
        assert_eq!(
            seen,
            vec![
                (format!("{mkdir} {RECYCLED}/{WORKER}"), Some(1000)),
                (format!("exec {RECYCLED}"), Some(1000)),
                (format!("{mkdir} {RECYCLED}/{RECYCLED}"), Some(1000)),
                (format!("exit {RECYCLED}"), Some(1000)),
                (format!("{unlink} {RECYCLED}/{RECYCLED}"), Some(2000)),
            ],
            "the new task under the old number never execed: no second exit"
        );
        assert_eq!(
            session.summary.loss.total(),
            0,
            "{:?}",
            session.summary.loss
        );
        assert_eq!(session.tasks.in_flight(), 0, "no entry carried over");
        assert!(session.tasks.is_empty() && session.procs.is_empty());
    }
}
