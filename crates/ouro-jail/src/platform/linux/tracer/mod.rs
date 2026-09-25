//! The Linux observer: a ptrace tracer for the closed set `linux-closed-v1`.
//!
//! This is the ptrace backend of jail-v1 §5.2 — the one that runs on any
//! host with nothing installed, under the default Yama scope every major
//! distribution ships. It implements the observer interface of the J1
//! contract §3.5 and the event semantics of §11, and it depends on `std` and
//! `libc` and nothing else.
//!
//! # How it is used
//!
//! The supervisor builds a process tree in which the target is launched by an
//! inside launcher that installs [`narrowing_filter`] and then blocks reading
//! the release pipe. While it is blocked, the supervisor calls
//! [`Tracer::attach`] with its host pid. Attach seizes it from a dedicated
//! thread, and that thread from then on owns every `waitpid` in the process:
//! the supervisor must not call `waitpid` itself while a tracer is attached,
//! and gets the exits of its own untraced children — bubblewrap — as
//! [`TracerEvent::UntracedChildExit`]. The supervisor then releases the
//! launcher, which execs the target.
//!
//! The thread ends on its own account (J5-T): when every tracee has been
//! reaped, the child the launcher descends through — bubblewrap, when the
//! launcher is not itself a child — has had its exit delivered, and every
//! child this process gained after the attach (an orphan of the traced tree
//! that a subreaper supervisor adopted, often already a zombie) has been
//! reaped. It never waits for a child this process already had when it
//! attached, such as a shell's process substitution the supervisor
//! inherited when that shell `exec`ed it: one that exits while the thread
//! runs is reaped and delivered like any untraced child, and one still alive
//! at the end is left to its owner.
//!
//! ```no_run
//! # use ouro_jail::platform::linux::tracer::{Tracer, TracerConfig, TracerEvent};
//! # fn example(launcher_pid: i32) -> Result<(), Box<dyn std::error::Error>> {
//! let tracer = Tracer::attach(launcher_pid, TracerConfig::default())?;
//! // ... release the launcher, then read until the tree is done ...
//! while let Ok(event) = tracer.events().recv() {
//!     if matches!(event, TracerEvent::Finished) {
//!         break;
//!     }
//! }
//! let summary = tracer.finish();
//! assert_eq!(summary.loss.total(), 0);
//! # Ok(())
//! # }
//! ```
//!
//! # What it claims
//!
//! Only what it saw. A result is emitted when the kernel reported that
//! syscall's return for a thread whose entry was paired with it. Anything
//! else — an unreadable pathname, an `open_how` the kernel version does not
//! let us decode, a syscall exit with no entry, a consumer too slow to drain
//! the queue, a final status that would have to be a worker thread's — is a
//! [`TracerEvent::Gap`] with a reason and, when it is known, a count. There
//! is no path in this module that invents a return value, a path or a status.

pub mod clock;
mod closed_set;
mod digest;
mod filter;
mod proc;
mod session;
mod sys;
mod table;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{
    Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, sync_channel,
};
use std::thread::JoinHandle;
use std::time::Duration;

use libc::pid_t;

pub use closed_set::ClosedOp;
pub use filter::{
    CLONE_SYSCALL, CLONE_UNTRACED, CLONE3_SYSCALL, LISTENER_SYSCALL, NARROWING_TRACE_DATA,
    SECCOMP_FILTER_FLAG_NEW_LISTENER, install_narrowing_filter, narrowing_filter,
    narrowing_filter_bytes, narrowing_filter_digest,
};
pub use proc::{children, cmdline, descendants, nspid, ppid, start_ticks, tgid, tracer_pid};
pub use table::closed_set_table;

/// Bounds on what the observer will hold, from jail-v1 §11.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TracerConfig {
    /// Most bytes of a pathname argument to snapshot. Beyond it the snapshot
    /// is marked incomplete rather than silently shortened.
    pub path_snapshot_max: usize,
    /// Most closed-set calls that may be in flight (entered, not returned)
    /// at once. Beyond it an entry is refused and counted as loss instead of
    /// growing without bound.
    pub inflight_max: usize,
    /// Most events buffered for a consumer that is not reading. A secondary
    /// cap: [`TracerConfig::queue_bytes_max`] is the budget §11.4 states, and
    /// whichever is reached first stops the queue growing.
    pub queue_max: usize,
    /// The §11.4 user-space event queue budget, in bytes.
    ///
    /// It covers everything the observer holds on the consumer's behalf:
    /// the buffered events and their pathname snapshots, and the events
    /// handed to the channel that the consumer has not taken yet. Each event
    /// is charged a fixed [`EVENT_FIXED_BYTES`] — the enum, its slot and the
    /// allocator's rounding — on top of the bytes its snapshots hold. The
    /// bounds this puts in force are [`TracerConfig::queue_bounds`].
    pub queue_bytes_max: usize,
    /// The `CLOCK_BOOTTIME` reading, in nanoseconds, at which the supervisor
    /// started. Gap endpoints are reported as elapsed time since this epoch
    /// rather than as time since boot (§11.4 bounds every gap from "the last
    /// known healthy point", which is an age, not an instant on the boot
    /// clock). Zero leaves the raw boottime readings in place.
    pub epoch_boottime_ns: u64,
}

/// What one queued event costs besides its snapshots: the enum itself, the
/// buffer slot, and the allocator's rounding of two small allocations.
pub const EVENT_FIXED_BYTES: usize = 256;

/// Bytes of the §11.4 queue budget that results may not consume, so the
/// lifecycle facts — an `Exec`, a `Fork` — have room to land behind them.
/// The critical facts (`Exit`, `Gap`, `Finished`) need no reserve: they are
/// exempt from every bound (J4 D6).
const LIFECYCLE_RESERVE: usize = 64 * 1024;

/// What an event costs the queue budget: its snapshots plus
/// [`EVENT_FIXED_BYTES`]. The tracer charges it when an event is buffered
/// or handed over, and [`Events`] gives it back when the consumer takes it.
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

/// The queue bounds a [`TracerConfig`] puts in force (§11.4, "Record actual
/// values in the observer plan"). Computed here once, for the tracer that
/// applies them and for the observer plan that records them, so the record
/// cannot drift from what is in force (J4 W3, loss review finding 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueBounds {
    /// Most bytes held for the consumer — buffered, or handed to the channel
    /// and not yet taken — by every event except the critical facts, which
    /// §11.4 exempts. `queue_bytes_max`, and never less than one fixed-size
    /// event, or nothing could ever be delivered.
    pub bytes_max: usize,
    /// Most bytes a result may bring that total to: `bytes_max` short of the
    /// lifecycle reserve, and never less than one fixed-size event. Below a
    /// budget of about 64 KiB that admits a result with no pathname and
    /// none with one.
    pub result_bytes_max: usize,
    /// The part of `bytes_max` results may not use.
    pub lifecycle_reserve: usize,
    /// Most events in the handoff channel at once (their bytes are inside
    /// `bytes_max`).
    pub handoff_events: usize,
}

impl TracerConfig {
    /// The queue bounds this configuration puts in force.
    #[must_use]
    pub fn queue_bounds(&self) -> QueueBounds {
        let bytes_max = self.queue_bytes_max.max(EVENT_FIXED_BYTES);
        QueueBounds {
            bytes_max,
            result_bytes_max: bytes_max
                .saturating_sub(LIFECYCLE_RESERVE)
                .max(EVENT_FIXED_BYTES),
            lifecycle_reserve: LIFECYCLE_RESERVE,
            handoff_events: HANDOFF_DEPTH.min(self.queue_max.max(1)) + TERMINAL_RESERVE,
        }
    }
}

/// Slots above the handoff depth kept for the terminal gap and `Finished`.
const TERMINAL_RESERVE: usize = 2;

/// How many events the channel between the tracer thread and the consumer
/// holds.
///
/// It is a handoff, not the queue: the queue is the tracer's own buffer,
/// which is bounded in bytes ([`TracerConfig::queue_bytes_max`]) because a
/// count cannot bound two four-kilobyte pathnames per event. What sits in
/// the channel is inside that byte budget too: the tracer charges an event
/// when it hands it over and [`Events`] credits it back when the consumer
/// takes it, so a small budget is a small queue however deep the channel.
const HANDOFF_DEPTH: usize = 64;

impl Default for TracerConfig {
    fn default() -> Self {
        TracerConfig {
            path_snapshot_max: 4096,
            inflight_max: 16_384,
            queue_max: 16_384,
            queue_bytes_max: 4 * 1024 * 1024,
            epoch_boottime_ns: 0,
        }
    }
}

/// A pathname argument as it was in the tracee's memory at the syscall entry.
///
/// §11.3: this is an `argument_snapshot`, not a kernel-resolved path. It is
/// not combined with the supervisor's cwd, and a symlink is not followed
/// after the fact to name a target that was not observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSnapshot {
    pub bytes: Vec<u8>,
    /// False when the NUL was not reached inside `path_snapshot_max` or the
    /// tracee's memory could not be read.
    pub complete: bool,
}

/// The socket address of a `connect`, as far as the closed set describes it.
///
/// The address bytes are read only to decide whether the whole address of
/// the family was readable, and are not retained: the audit record of a
/// `connect` names the family and the completeness of the claim, and §11.1
/// forbids collecting argument memory nothing downstream will ever see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockaddrSnapshot {
    /// `sa_family`, when at least two bytes could be read.
    pub family: Option<u16>,
    /// True when the whole address of the family was readable and the
    /// caller declared at least that much.
    pub complete: bool,
}

/// The arguments of a closed-set call that the observer reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    pub path: Option<PathSnapshot>,
    /// The second pathname of a two-path call. §11.3: the two are
    /// independent evidence.
    pub path2: Option<PathSnapshot>,
    /// The directory fd `path` is resolved against, for an `*at` call.
    pub dirfd: Option<i32>,
    pub dirfd2: Option<i32>,
    /// The flags word, where the call has one. For `creat` it is the
    /// `O_CREAT|O_WRONLY|O_TRUNC` the syscall is defined as; for `openat2`
    /// it is `open_how.flags` and is `None` when that could not be decoded.
    /// `mkdir` and `mkdirat` have no flags: their numeric argument is a mode.
    pub flags: Option<u64>,
    pub sockaddr: Option<SockaddrSnapshot>,
}

/// A set of closed-set operations, small enough to pass by value.
///
/// A gap carries one so the consumer can degrade exactly the coverage
/// classes it affected, which §11.4 requires: "A gap names the affected
/// classes explicitly".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpSet(u16);

impl OpSet {
    /// A gap that affects no closed-set operation: the loss was bookkeeping,
    /// not a result.
    pub const EMPTY: OpSet = OpSet(0);
    /// Unknown result loss may affect any class in the closed set.
    pub const ALL: OpSet = OpSet(u16::MAX);

    #[must_use]
    pub fn of(op: ClosedOp) -> OpSet {
        OpSet(op.bit())
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub fn contains(self, op: ClosedOp) -> bool {
        self.0 & op.bit() != 0
    }

    pub fn insert(&mut self, op: ClosedOp) {
        self.0 |= op.bit();
    }

    #[must_use]
    pub fn union(self, other: OpSet) -> OpSet {
        OpSet(self.0 | other.0)
    }

    /// The operations in the set, in the order of [`ClosedOp::ALL`].
    pub fn iter(self) -> impl Iterator<Item = ClosedOp> {
        ClosedOp::ALL
            .into_iter()
            .filter(move |op| self.contains(*op))
    }
}

/// Why coverage has a hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    /// The consumer did not drain the queue and events were dropped.
    QueueFull,
    /// A seccomp notification response was not accepted by the kernel.
    MediationResponseUndelivered,
    /// A syscall return arrived for a thread with no matching entry.
    UnmatchedExit,
    /// An entry can no longer return: the thread was destroyed by another
    /// thread's `execve`, or died, or issued a second entry.
    EntryAbandoned,
    /// `inflight_max` was reached, so an entry was not recorded.
    InflightExhausted,
    /// A pathname argument could not be read from the tracee at all.
    PathUnreadable,
    /// A `connect` address could not be read from the tracee at all.
    SockaddrUnreadable,
    /// `openat2`'s `open_how` could not be decoded, so the call cannot be
    /// classified as create or write.
    FlagsUnavailable,
    /// The kernel would not describe a stop.
    SyscallInfoUnavailable,
    /// `/proc` would not say which thread group a task belongs to.
    IdentityUnavailable,
    /// A thread group ended without its leader being the last thread reaped,
    /// so its final status would have to be a worker's.
    FinalStatusUnknown,
    /// The filter stopped a syscall number that is not in this closed set,
    /// so the installed filter is not this module's.
    UnexpectedTraceStop,
    /// The tracer stopped while tracees were still alive; they were killed.
    TraceesAbandoned,
    /// The tracer stopped while a direct child of this process it answers
    /// for — the backend the launcher descends through, or one gained after
    /// the attach — had not been reaped, so its exit status had no delivery
    /// route left (J5-T).
    UnreapedChildren,
    /// A stopped tracee could not be restarted, so it was killed rather than
    /// left stopped forever.
    RestartFailed,
    /// A lifecycle event — an exec, an exit, a gap — was dropped. Lifecycle
    /// events are not subject to result backpressure; this means the backlog
    /// itself overflowed.
    LifecycleDropped,
    /// A tracee died and could not be attributed to a thread group.
    DeathUnattributed,
    /// A syscall under another ABI — a non-native architecture or the x32
    /// bit — ran, and this observer decodes only the native table, so it
    /// cannot say which operation, if any, it was (J4 D2). One the kernel
    /// refused as nonexistent (`ENOSYS`) had no effect and is not this.
    ForeignAbi,
    /// A child installed a seccomp filter with its own notification
    /// listener (J4 D1). The listener can answer `CONTINUE`, which runs the
    /// call with no trace stop, so from then on any closed-set call may be
    /// unobserved; how many is unknown and the interval has no end.
    ChildNotificationListener,
    /// A tracee created a task with `clone(CLONE_UNTRACED)` (J4 S4), which
    /// the kernel does not attach to this tracer. §11.2: an untracked
    /// descendant is a coverage gap. Its own closed-set calls fail with
    /// `ENOSYS` (a trace stop with no tracer), but nothing about it is
    /// observed — not its calls, not its lifetime — so the count is unknown
    /// and the interval has no end.
    UntracedDescendant,
    /// A covered call's syscall exit carried a kernel restart code, and the
    /// observer could not establish what the kernel then did with it —
    /// re-entered it, or returned `EINTR` (J4 O-2). Its one result is
    /// unknown, so it is a hole naming that call's classes. The observer
    /// follows the call to the kernel's decision, so this is only for a
    /// decision it could not read: an unreadable or unrecognised signal
    /// frame, a continuation through `restart_syscall`, which is outside the
    /// traced set, or a stop out of the sequence the kernel produces.
    RestartUnresolved,
    /// A covered call's pointed argument — `openat2`'s `open_how.flags`, a
    /// pathname, or a socket address family — read at the entry stop no
    /// longer read the same at the syscall exit: a thread of the tracee
    /// rewrote the memory between the observer's snapshot and the kernel's
    /// own copy. The event the snapshot would have carried can neither be
    /// delivered (its classification may be false) nor dropped silently, so
    /// it is this gap, naming the call's classes. Register arguments cannot
    /// drift this way; only memory the kernel re-reads after the stop can.
    ArgumentSnapshotUnstable,
}

impl GapReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GapReason::QueueFull => "queue_full",
            GapReason::MediationResponseUndelivered => "mediation_response_undelivered",
            GapReason::UnmatchedExit => "unmatched_exit",
            GapReason::EntryAbandoned => "entry_abandoned",
            GapReason::InflightExhausted => "inflight_exhausted",
            GapReason::PathUnreadable => "path_unreadable",
            GapReason::SockaddrUnreadable => "sockaddr_unreadable",
            GapReason::FlagsUnavailable => "flags_unavailable",
            GapReason::SyscallInfoUnavailable => "syscall_info_unavailable",
            GapReason::IdentityUnavailable => "identity_unavailable",
            GapReason::FinalStatusUnknown => "final_status_unknown",
            GapReason::UnexpectedTraceStop => "unexpected_trace_stop",
            GapReason::TraceesAbandoned => "tracees_abandoned",
            GapReason::UnreapedChildren => "unreaped_children",
            GapReason::RestartFailed => "restart_failed",
            GapReason::LifecycleDropped => "lifecycle_dropped",
            GapReason::DeathUnattributed => "death_unattributed",
            GapReason::ForeignAbi => "foreign_abi",
            GapReason::ChildNotificationListener => "child_notification_listener",
            GapReason::UntracedDescendant => "untraced_descendant",
            GapReason::RestartUnresolved => "restart_unresolved",
            GapReason::ArgumentSnapshotUnstable => "argument_snapshot_unstable",
        }
    }

    /// A gap that lasts from where it starts to the end of the attempt: the
    /// condition that opened it is never observed to end. A child's
    /// notification listener lives as long as some process holds it.
    #[must_use]
    pub fn is_open_ended(self) -> bool {
        matches!(
            self,
            GapReason::ChildNotificationListener | GapReason::UntracedDescendant
        )
    }
}

/// What the observer saw. Pids are host pids, in the supervisor's namespace;
/// a process inside a pid namespace sees a different number for itself, and
/// [`nspid`] is how the two are related (§11.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracerEvent {
    /// The seize is confirmed. Always the first event.
    Attached {
        pid: pid_t,
        /// The launcher's birth identity, so a later task that is given this
        /// pid number can be told apart from it (§11.3).
        start_ticks: Option<u64>,
        monotonic_ns: u64,
    },
    /// A new task was born and is now traced. Internal bookkeeping: §11.2
    /// keeps fork out of the public syscall audit set, so this is not an
    /// audit event and does not expand it.
    Fork {
        /// The thread group that created it, which is what every other
        /// event's `pid` is.
        parent: pid_t,
        /// The thread inside that group that made the call. Equal to
        /// `parent` for a single-threaded process.
        parent_tid: pid_t,
        /// The new task id.
        child: pid_t,
        /// True when the new task is a thread of `parent` rather than a new
        /// process: it landed in the same thread group.
        is_thread: bool,
        /// The new task's birth identity.
        child_start_ticks: Option<u64>,
        monotonic_ns: u64,
    },
    /// A confirmed exec transition. Never inferred from a syscall entry.
    Exec {
        pid: pid_t,
        /// The birth of process `pid`: the start time the kernel recorded for
        /// its thread-group leader (field 22 of `/proc/<pid>/stat`, clock
        /// ticks since boot), read when the tracer first took the process
        /// on. `None` when `/proc` would not say. See [`TracerEvent::Syscall`].
        start_ticks: Option<u64>,
        /// The call whose entry this transition was paired with, `execve` or
        /// `execveat`; `None` when the entry was not witnessed.
        syscall: Option<&'static str>,
        /// The pathname argument of the `execve`/`execveat` that produced
        /// this transition, snapshotted at its entry. Descendant argv
        /// digests stay null in J1, so this snapshot is the only way to name
        /// the image, and §11.3 makes it an argument snapshot rather than a
        /// resolved path.
        ///
        /// `None` means the tracer did not witness the entry of this exec.
        /// The case that matters is the first transition after
        /// [`TracerEvent::Attached`]: seizing a process that is still inside
        /// the `execve` that created it makes the kernel report that
        /// transition to the new tracer, and there is no entry to pair it
        /// with. A consumer that uses `Exec` as exec confirmation must
        /// require a path, or attach only after the launcher has said it is
        /// past its own exec.
        path: Option<PathSnapshot>,
        /// The directory fd the pathname was resolved against, when the
        /// witnessed entry was an `execveat` with one. §11.3: `dirfd` is
        /// accounted, never silently replaced by a cwd. `None` for a plain
        /// `execve` and for a transition whose entry was not seen.
        dirfd: Option<i32>,
        monotonic_ns: u64,
    },
    /// One completed closed-set call. `ret` is the signed raw return, so a
    /// failure is `-errno`.
    Syscall {
        /// The thread group, which is the process the consumer attributes to.
        pid: pid_t,
        /// The birth of process `pid` (§11.3, "internal attribution includes
        /// boot/birth identity"): the start time of its thread-group leader,
        /// field 22 of `/proc/<pid>/stat` in clock ticks since boot, read
        /// when the tracer first took the process on — at its fork event,
        /// while it was an unreaped tracee whose number the kernel could not
        /// yet give to anyone else. A non-leader exec keeps it (the kernel
        /// gives the exec'ing thread the leader's start time). A task that
        /// later receives the same number is registered afresh, with its own
        /// birth: nothing is keyed by the number alone across a death. `None`
        /// when `/proc` would not say.
        start_ticks: Option<u64>,
        /// The thread that made the call.
        tid: pid_t,
        op: ClosedOp,
        syscall: &'static str,
        args: Args,
        ret: i64,
        monotonic_ns: u64,
    },
    /// A thread group that was seen to exec has died. `status` is the raw
    /// wait status, so the consumer derives code or signal from it.
    Exit {
        pid: pid_t,
        /// The birth of process `pid`. See [`TracerEvent::Syscall`].
        start_ticks: Option<u64>,
        status: i32,
        monotonic_ns: u64,
    },
    /// A child of this process that was never a tracee has exited —
    /// bubblewrap, which lives outside the namespaces it creates, or any
    /// other child that ended while the tracer owned every `waitpid` (J5-T).
    UntracedChildExit { pid: pid_t, status: i32 },
    /// Coverage has a hole. `count` is `None` when the size of the hole
    /// cannot be established; `ops` names the closed-set operations it
    /// affected, so the consumer degrades exactly those classes and no
    /// others (§11.4), and is empty when the loss was bookkeeping rather
    /// than a result. `from_ns` is the last point at which coverage was
    /// known healthy, which is what §11.4 asks a gap to bound itself from.
    Gap {
        reason: GapReason,
        ops: OpSet,
        from_ns: u64,
        to_ns: u64,
        count: Option<u64>,
    },
    /// The tracer thread has stopped. Always the last event.
    Finished,
}

/// One counter per closed-set operation, counting emitted results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpCounts {
    pub exec: u64,
    pub open: u64,
    pub truncate: u64,
    pub rename: u64,
    pub unlink: u64,
    pub rmdir: u64,
    pub mkdir: u64,
    pub mknod: u64,
    pub link: u64,
    pub symlink: u64,
    pub connect: u64,
}

impl OpCounts {
    #[must_use]
    pub fn get(&self, op: ClosedOp) -> u64 {
        match op {
            ClosedOp::Exec => self.exec,
            ClosedOp::Open => self.open,
            ClosedOp::Truncate => self.truncate,
            ClosedOp::Rename => self.rename,
            ClosedOp::Unlink => self.unlink,
            ClosedOp::Rmdir => self.rmdir,
            ClosedOp::Mkdir => self.mkdir,
            ClosedOp::Mknod => self.mknod,
            ClosedOp::Link => self.link,
            ClosedOp::Symlink => self.symlink,
            ClosedOp::Connect => self.connect,
        }
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        ClosedOp::ALL.iter().map(|op| self.get(*op)).sum()
    }

    fn bump(&mut self, op: ClosedOp) {
        let slot = match op {
            ClosedOp::Exec => &mut self.exec,
            ClosedOp::Open => &mut self.open,
            ClosedOp::Truncate => &mut self.truncate,
            ClosedOp::Rename => &mut self.rename,
            ClosedOp::Unlink => &mut self.unlink,
            ClosedOp::Rmdir => &mut self.rmdir,
            ClosedOp::Mkdir => &mut self.mkdir,
            ClosedOp::Mknod => &mut self.mknod,
            ClosedOp::Link => &mut self.link,
            ClosedOp::Symlink => &mut self.symlink,
            ClosedOp::Connect => &mut self.connect,
        };
        *slot += 1;
    }
}

/// Independent loss counters, one per failure mode, as §11.4 requires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LossCounters {
    /// Events the consumer was too slow to take.
    pub queue_dropped: u64,
    pub unmatched_exits: u64,
    pub abandoned_entries: u64,
    pub inflight_rejected: u64,
    /// Argument memory — a pathname or a socket address — that could not be
    /// read from the tracee at all, so the event carries no such argument.
    pub path_unreadable: u64,
    /// Snapshots that reached `path_snapshot_max` or stopped at an unmapped
    /// page. These carry `complete = false` and are not a hole in the result
    /// stream, only a weaker path assertion (§11.3).
    pub path_truncated: u64,
    /// A `connect` address that could not be read at all.
    pub sockaddr_unreadable: u64,
    pub flags_unavailable: u64,
    pub syscall_info_unavailable: u64,
    pub identity_unavailable: u64,
    pub final_status_unknown: u64,
    pub unexpected_trace_stops: u64,
    /// Tracees still alive when the tracer was told to stop. They were
    /// killed and reaped; anything they were about to do is unobserved.
    pub abandoned_tracees: u64,
    /// Children the tracer answers for (the backend, and any gained after the
    /// attach), never reaped, so their exit statuses have no route left to
    /// the supervisor (J5-T).
    pub unreaped_children: u64,
    /// Stopped tracees that could not be restarted and were killed.
    pub restart_failed: u64,
    /// Lifecycle events dropped because their own backlog overflowed.
    pub lifecycle_dropped: u64,
    /// Task deaths that could not be attributed to a thread group.
    pub death_unattributed: u64,
    /// Syscalls under another ABI that ran and could not be attributed.
    pub foreign_abi: u64,
    /// Notification listeners a child installed for itself.
    pub notification_listeners: u64,
    /// Tasks a tracee created with `CLONE_UNTRACED`, which nothing traces.
    pub untraced_descendants: u64,
    /// Restart-coded syscall exits whose outcome could not be established.
    pub restart_unresolved: u64,
    /// Covered calls whose pointed arguments — `open_how.flags`, a pathname,
    /// a socket address family — changed between the entry snapshot and the
    /// exit re-read. The event was dropped and a gap recorded instead,
    /// because the tracee can rewrite memory the kernel re-reads after the
    /// entry stop, which would falsify the snapshot's classification.
    pub argument_snapshot_unstable: u64,
}

impl LossCounters {
    /// Every counter that means a result is missing. `path_truncated` is not
    /// one: the result is there and says its path is incomplete.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.queue_dropped
            + self.unmatched_exits
            + self.abandoned_entries
            + self.inflight_rejected
            + self.path_unreadable
            + self.sockaddr_unreadable
            + self.flags_unavailable
            + self.syscall_info_unavailable
            + self.identity_unavailable
            + self.final_status_unknown
            + self.unexpected_trace_stops
            + self.abandoned_tracees
            + self.unreaped_children
            + self.restart_failed
            + self.lifecycle_dropped
            + self.death_unattributed
            + self.foreign_abi
            + self.notification_listeners
            + self.untraced_descendants
            + self.restart_unresolved
            + self.argument_snapshot_unstable
    }
}

/// What the tracer thread did, read once it has stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TracerSummary {
    /// Every `waitpid` return the thread handled.
    pub stops: u64,
    /// Distinct tasks tracked, threads included.
    pub tracees: u64,
    /// `Exit` events emitted: thread-group deaths after a witnessed exec.
    pub exits: u64,
    /// Tracee terminations reaped, threads included. Higher than `exits`
    /// whenever a process had more than one thread or never execed.
    pub reaped_tasks: u64,
    pub untraced_child_exits: u64,
    /// Fork-ordering races in which a tracee died before its first stop and
    /// its death and its fork event arrived in that order. Not loss: the
    /// child never executed anything observable, so no gap is recorded, and
    /// this does not feed [`LossCounters::total`].
    pub late_fork_races: u64,
    /// `PTRACE_EVENT_EXEC` transitions.
    pub exec_transitions: u64,
    /// `Gap` events queued for the consumer. Gaps merged into one
    /// coalesced summary count once.
    pub gaps: u64,
    /// Events of any kind that reached the consumer.
    pub emitted: u64,
    /// Open-family calls that asked for read-only access. Not loss: §11.2
    /// puts them outside the closed set.
    pub filtered_readonly_opens: u64,
    /// Arguments the observer could not read *and the kernel rejected too*:
    /// an `EFAULT` pathname, an `EINVAL` `open_how`. The call had no valid
    /// argument to observe, so this is not a hole in coverage and does not
    /// feed [`LossCounters::total`] — otherwise a tracee could manufacture
    /// unlimited "loss" by passing pointers that cannot work.
    pub argument_invalid: u64,
    /// Tasks the kernel destroyed as part of another thread's `execve`,
    /// which it does not report. `tracees` equals `reaped_tasks` plus this.
    pub tasks_destroyed_by_exec: u64,
    /// The most bytes the observer ever held on the consumer's behalf.
    pub queue_bytes_peak: usize,
    /// Direct children of this process the tracer answers for (the backend,
    /// and any gained after the attach) that were still unreaped when it
    /// stopped. Children it was attached beside are not the tracer's (J5-T).
    pub unreaped_children: Vec<pid_t>,
    /// Syscall exits with a kernel restart code that the kernel then
    /// re-entered: seen re-entered at the same instruction, or decided at a
    /// handler's entry (`ERESTARTNOINTR`, or `ERESTARTSYS` under
    /// `SA_RESTART`). Not loss and not results: the re-entered call produces
    /// its one result.
    pub restarts: u64,
    /// Syscall exits with a kernel restart code that the kernel turned into
    /// `EINTR` at a handler's entry (J4 O-2). Each is a result, `-EINTR`, and
    /// is counted in [`TracerSummary::ops`] like any other.
    pub interrupted: u64,
    /// Syscall exits with a kernel restart code whose thread ended before
    /// the kernel decided — a fatal signal, or another thread's `execve`. A
    /// restart code means the call did nothing, and no result was ever
    /// returned: not a result and not loss.
    pub restarts_unfinished: u64,
    /// Entries whose thread was killed at its seccomp stop before the
    /// observer resumed it (J4 O-3): the stop could not be read, or the
    /// resume failed with `ESRCH`, which at an unresumed stop only a
    /// `SIGKILL` causes. The kernel skips a call when a fatal signal is
    /// pending after the trace event (`__seccomp_filter`), so the call had
    /// no effect: not loss.
    pub killed_at_entry: u64,
    /// Syscalls under another ABI the kernel refused as nonexistent
    /// (`ENOSYS`): stopped and labelled foreign, but with no effect, so not
    /// loss — a tracee cannot manufacture a gap by naming a call no table has.
    pub foreign_rejected: u64,
    /// Stops another filter asked for — a child's own `SECCOMP_RET_TRACE`,
    /// recognised by trace data that is not
    /// [`NARROWING_TRACE_DATA`] — on calls outside the closed set. Continued
    /// untouched: not a result and not loss.
    pub requested_by_other_filters: u64,
    /// Notification-listener requests the kernel refused (`EBUSY` under the
    /// `agent` mediation listener, for one): no listener, nothing hidden.
    pub listener_refused: u64,
    /// `clone(CLONE_UNTRACED)` calls that created no task: no descendant,
    /// nothing untraced.
    pub untraced_clone_refused: u64,
    pub loss: LossCounters,
    pub ops: OpCounts,
    /// The tracer thread panicked. Every other field is then unreliable.
    pub thread_panicked: bool,
}

/// Why a tracer could not be attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracerError {
    /// This module's syscall table is x86_64's. On another architecture it
    /// would label calls it cannot name, so it refuses instead.
    UnsupportedArch,
    /// `PTRACE_SEIZE` failed. `ESRCH` means no such task; `EPERM` means the
    /// Yama scope or an LSM refused, usually because the target is not a
    /// descendant of this process.
    Seize { pid: pid_t, errno: i32 },
    /// The seize returned success but the kernel does not show this thread
    /// as the tracer.
    SeizeUnconfirmed { pid: pid_t },
    /// Something else is already tracing the target.
    SeizedByAnotherThread { pid: pid_t, tracer: pid_t },
    /// The tracer thread could not be spawned.
    ThreadSpawn { message: String },
}

impl fmt::Display for TracerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TracerError::UnsupportedArch => {
                write!(
                    f,
                    "the ptrace observer implements the x86_64 closed set only"
                )
            }
            TracerError::Seize { pid, errno } => write!(
                f,
                "PTRACE_SEIZE of pid {pid} failed: {}",
                std::io::Error::from_raw_os_error(*errno)
            ),
            TracerError::SeizeUnconfirmed { pid } => {
                write!(f, "PTRACE_SEIZE of pid {pid} was not confirmed by /proc")
            }
            TracerError::SeizedByAnotherThread { pid, tracer } => {
                write!(f, "pid {pid} is already traced by task {tracer}")
            }
            TracerError::ThreadSpawn { message } => {
                write!(f, "the tracer thread could not be spawned: {message}")
            }
        }
    }
}

impl std::error::Error for TracerError {}

/// The consumer's end of the event stream.
///
/// A receiver that gives each event's bytes back to the queue budget as it
/// is taken (J4 W3, loss review finding 4): the tracer counts what it has
/// handed over and not seen taken, so the §11.4 budget bounds the channel
/// as well as the tracer's own buffer. The three methods are
/// [`Receiver`]'s own.
pub struct Events {
    rx: Receiver<TracerEvent>,
    handed: Arc<AtomicUsize>,
}

impl Events {
    fn new(rx: Receiver<TracerEvent>, handed: Arc<AtomicUsize>) -> Events {
        Events { rx, handed }
    }

    fn taken(&self, event: TracerEvent) -> TracerEvent {
        // The tracer added these bytes before the send this event came
        // through, so the subtraction never passes zero.
        self.handed
            .fetch_sub(event_bytes(&event), Ordering::Relaxed);
        event
    }

    /// [`Receiver::recv`].
    ///
    /// # Errors
    /// [`RecvError`] once the tracer is gone and nothing is left.
    pub fn recv(&self) -> Result<TracerEvent, RecvError> {
        self.rx.recv().map(|event| self.taken(event))
    }

    /// [`Receiver::recv_timeout`].
    ///
    /// # Errors
    /// [`RecvTimeoutError`] on timeout or once the tracer is gone.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<TracerEvent, RecvTimeoutError> {
        self.rx.recv_timeout(timeout).map(|event| self.taken(event))
    }

    /// [`Receiver::try_recv`].
    ///
    /// # Errors
    /// [`TryRecvError`] when nothing is waiting or the tracer is gone.
    pub fn try_recv(&self) -> Result<TracerEvent, TryRecvError> {
        self.rx.try_recv().map(|event| self.taken(event))
    }
}

/// A running observer. Dropping it stops the tracer thread and joins it.
pub struct Tracer {
    launcher: pid_t,
    events: Events,
    handle: Option<JoinHandle<TracerSummary>>,
    stop: Arc<AtomicBool>,
    /// How long the thread may take to end a live tree once told to stop.
    shutdown_ns: Arc<AtomicU64>,
    /// The tracer thread's task id, so its `waitpid` can be interrupted.
    tid: Arc<AtomicI32>,
}

impl Tracer {
    /// Seize `launcher` and start observing it and every descendant.
    ///
    /// `launcher` must be a host pid of a descendant of this process that is
    /// currently blocked — the design is that it is blocked reading the
    /// release pipe — and it must already have installed
    /// [`narrowing_filter`]. The seize does not stop it and it does not
    /// learn that it happened; the caller releases it afterwards by its own
    /// mechanism.
    ///
    /// Returns once the seize is confirmed against `/proc`, so a caller that
    /// releases the launcher after this returns cannot lose the first exec.
    ///
    /// From here until the tracer stops, the tracer thread owns every
    /// `waitpid` in this process. The caller must not wait on its own
    /// children; their exits arrive as
    /// [`TracerEvent::UntracedChildExit`]. The thread finishes once every
    /// tracee is reaped, the child `launcher` descends through has exited
    /// and every child gained since the attach is reaped, whatever other
    /// children this process already had (J5-T).
    ///
    /// # Errors
    /// [`TracerError`], which distinguishes a refused seize from one that
    /// could not be confirmed.
    pub fn attach(launcher: pid_t, config: TracerConfig) -> Result<Tracer, TracerError> {
        // A shallow handoff plus two slots for the terminal gap and
        // `Finished`, so they have somewhere to land the moment the consumer
        // reads anything at all. Everything else waits in the tracer's own
        // byte-bounded buffer.
        let depth = config.queue_bounds().handoff_events;
        let (tx, rx): (SyncSender<TracerEvent>, Receiver<TracerEvent>) = sync_channel(depth);
        let handed = Arc::new(AtomicUsize::new(0));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), TracerError>>();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown_ns = Arc::new(AtomicU64::new(
            u64::try_from(Tracer::DEFAULT_SHUTDOWN.as_nanos()).unwrap_or(u64::MAX),
        ));
        let tid = Arc::new(AtomicI32::new(0));
        let thread = session::Handles {
            stop: Arc::clone(&stop),
            shutdown_ns: Arc::clone(&shutdown_ns),
            tid: Arc::clone(&tid),
            handed: Arc::clone(&handed),
        };
        let handle = std::thread::Builder::new()
            .name("ouro-jail-tracer".to_string())
            .spawn(move || session::run(launcher, config, tx, ready_tx, thread))
            .map_err(|err| TracerError::ThreadSpawn {
                message: err.to_string(),
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Tracer {
                launcher,
                events: Events::new(rx, handed),
                handle: Some(handle),
                stop,
                shutdown_ns,
                tid,
            }),
            Ok(Err(err)) => {
                let _ = handle.join();
                Err(err)
            }
            Err(_) => {
                let _ = handle.join();
                Err(TracerError::ThreadSpawn {
                    message: "the tracer thread ended before confirming the seize".to_string(),
                })
            }
        }
    }

    /// The pid that was seized.
    #[must_use]
    pub fn launcher(&self) -> pid_t {
        self.launcher
    }

    /// The event stream. Read it until [`TracerEvent::Finished`]; events
    /// still queued when [`Tracer::finish`] consumes the tracer are lost with
    /// it.
    #[must_use]
    pub fn events(&self) -> &Events {
        &self.events
    }

    /// The filter the launcher must install. See [`narrowing_filter`].
    #[must_use]
    pub fn narrowing_filter() -> Vec<libc::sock_filter> {
        filter::narrowing_filter()
    }

    /// `sha256:<hex>` of the bytes of [`Tracer::narrowing_filter`].
    #[must_use]
    pub fn narrowing_filter_digest() -> String {
        filter::narrowing_filter_digest()
    }

    /// Stop the tracer thread, join it and take its counters, within
    /// [`Tracer::DEFAULT_SHUTDOWN`].
    ///
    /// The intended sequence is to read [`Tracer::events`] until
    /// [`TracerEvent::Finished`] and then call this. It is safe to call at
    /// any time: see [`Tracer::finish_within`] for what happens when the
    /// tree is still alive.
    #[must_use]
    pub fn finish(self) -> TracerSummary {
        self.finish_within(Tracer::DEFAULT_SHUTDOWN)
    }

    /// How long [`Tracer::finish`] and `Drop` give a live tree to end. It is
    /// the tree-death budget of jail-v1 §9.3.
    pub const DEFAULT_SHUTDOWN: Duration = Duration::from_secs(5);

    /// Stop the tracer thread within `budget`, join it and take its counters.
    ///
    /// This always returns. If tracees are still alive it interrupts the
    /// thread's `waitpid`, lets the tree end for up to `budget`, and on
    /// expiry kills every remaining tracee, reaps it, and records the loss as
    /// [`GapReason::TraceesAbandoned`] with a count. A child it answers for
    /// (the backend, or one gained since the attach) that was never reaped
    /// is listed in [`TracerSummary::unreaped_children`] and reported as
    /// [`GapReason::UnreapedChildren`]: its exit status had exactly one route
    /// to the supervisor and it is now closed.
    #[must_use]
    pub fn finish_within(self, budget: Duration) -> TracerSummary {
        self.finish_within_draining(budget, |_| {})
    }

    /// Stop while delivering the final events, including shutdown loss notes.
    pub fn finish_within_draining(
        mut self,
        budget: Duration,
        mut consume: impl FnMut(TracerEvent),
    ) -> TracerSummary {
        self.shutdown_ns.store(
            u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
        self.stop.store(true, Ordering::Release);
        let Some(handle) = self.handle.take() else {
            return TracerSummary::default();
        };
        // The thread may be inside a blocking `waitpid`. Keep interrupting it
        // until it is gone: a single signal could arrive in the window
        // between its stop-flag check and the wait it is about to enter.
        while !handle.is_finished() {
            while let Ok(event) = self.events.try_recv() {
                consume(event);
            }
            let target = self.tid.load(Ordering::Acquire);
            if target > 0 {
                let _ = sys::tgkill(target, sys::wake_signal());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        while let Ok(event) = self.events.try_recv() {
            consume(event);
        }
        handle.join().unwrap_or(TracerSummary {
            thread_panicked: true,
            ..TracerSummary::default()
        })
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if self.handle.is_none() {
            return;
        }
        // Dropping must never hang, including when the consumer is
        // panicking, so it is the same bounded shutdown as `finish`.
        let taken = Tracer {
            launcher: self.launcher,
            events: std::mem::replace(
                &mut self.events,
                Events::new(sync_channel(1).1, Arc::default()),
            ),
            handle: self.handle.take(),
            stop: Arc::clone(&self.stop),
            shutdown_ns: Arc::clone(&self.shutdown_ns),
            tid: Arc::clone(&self.tid),
        };
        let _ = taken.finish_within(Tracer::DEFAULT_SHUTDOWN);
    }
}

impl fmt::Debug for Tracer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tracer")
            .field("launcher", &self.launcher)
            .field("running", &self.handle.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_config_is_the_spec_bound() {
        let config = TracerConfig::default();
        assert_eq!(
            config.path_snapshot_max, 4096,
            "jail-v1 §11.4: 4 KiB path snapshots"
        );
        assert_eq!(
            config.inflight_max, 16_384,
            "jail-v1 §11.4: 16,384 in-flight entries"
        );
        assert_eq!(
            config.queue_max, 16_384,
            "jail-v1 §11.4: a bounded user-space queue"
        );
        assert_eq!(
            config.epoch_boottime_ns, 0,
            "with no epoch supplied the gap endpoints are raw boottime readings"
        );
    }

    #[test]
    fn attaching_to_a_task_that_does_not_exist_fails_and_leaves_no_thread() {
        // pid 0 is never a task. The error must name the refusal, and the
        // tracer thread must be joined rather than left behind. Counting
        // threads by name rather than by total keeps this correct while the
        // rest of the suite runs in parallel.
        let before = tracer_threads();
        match Tracer::attach(0, TracerConfig::default()) {
            Err(TracerError::UnsupportedArch) if !cfg!(target_arch = "x86_64") => {}
            Err(TracerError::Seize { pid, errno }) => {
                assert_eq!(pid, 0);
                assert!(
                    errno == libc::ESRCH || errno == libc::EPERM,
                    "unexpected errno {errno}"
                );
            }
            Err(other) => panic!("expected a refused seize, got {other}"),
            Ok(_) => panic!("seizing pid 0 must not succeed"),
        }
        assert_eq!(
            tracer_threads(),
            before,
            "a failed attach must not leave a tracer thread running"
        );
    }

    /// Tasks of this process whose name is the tracer thread's.
    fn tracer_threads() -> usize {
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            return 0;
        };
        tasks
            .flatten()
            .filter(|task| {
                std::fs::read_to_string(task.path().join("comm"))
                    .is_ok_and(|name| name.trim() == "ouro-jail-tracer")
            })
            .count()
    }

    #[test]
    fn attaching_to_a_process_we_do_not_own_is_refused() {
        // pid 1 is not a descendant of this process, so Yama at scope 1 and
        // the ordinary permission check both refuse it.
        match Tracer::attach(1, TracerConfig::default()) {
            Err(TracerError::UnsupportedArch) if !cfg!(target_arch = "x86_64") => {}
            Err(TracerError::Seize { pid: 1, errno }) => {
                assert!(
                    errno == libc::EPERM || errno == libc::ESRCH,
                    "errno {errno}"
                );
            }
            Err(other) => panic!("expected a refused seize, got {other}"),
            Ok(_) => panic!("seizing pid 1 must not succeed as an unprivileged user"),
        }
    }

    /// J4 W3 (loss review finding 4): the bounds in force, including for a
    /// budget too small to hold a pathname or even one event.
    #[test]
    fn j4_w3_queue_bounds_are_the_budget_with_a_floor_of_one_event() {
        let bounds = |queue_bytes_max| {
            TracerConfig {
                queue_bytes_max,
                ..TracerConfig::default()
            }
            .queue_bounds()
        };
        let default = TracerConfig::default().queue_bounds();
        assert_eq!(default.bytes_max, 4 * 1024 * 1024);
        assert_eq!(default.result_bytes_max, 4 * 1024 * 1024 - 64 * 1024);
        assert_eq!(default.lifecycle_reserve, 64 * 1024);
        assert_eq!(default.handoff_events, 66);
        assert_eq!(bounds(65_536 + 256).result_bytes_max, 256);
        assert_eq!(bounds(65_536 + 4096).result_bytes_max, 4096);
        assert_eq!(bounds(16_384).bytes_max, 16_384);
        assert_eq!(bounds(16_384).result_bytes_max, EVENT_FIXED_BYTES);
        assert_eq!(bounds(1).bytes_max, EVENT_FIXED_BYTES);
        assert_eq!(bounds(1).result_bytes_max, EVENT_FIXED_BYTES);
        let shallow = TracerConfig {
            queue_max: 3,
            ..TracerConfig::default()
        };
        assert_eq!(shallow.queue_bounds().handoff_events, 5);
    }

    #[test]
    fn loss_total_counts_missing_results_and_not_weak_paths() {
        let mut loss = LossCounters {
            path_truncated: 7,
            ..LossCounters::default()
        };
        assert_eq!(
            loss.total(),
            0,
            "a truncated path is a weaker claim, not a lost result"
        );
        loss.queue_dropped = 3;
        loss.unmatched_exits = 1;
        assert_eq!(loss.total(), 4);
    }

    #[test]
    fn op_counts_address_every_operation() {
        let mut counts = OpCounts::default();
        for op in ClosedOp::ALL {
            counts.bump(op);
        }
        for op in ClosedOp::ALL {
            assert_eq!(counts.get(op), 1, "{}", op.as_str());
        }
        assert_eq!(counts.total(), ClosedOp::ALL.len() as u64);
    }

    #[test]
    fn gap_reasons_have_distinct_names() {
        let reasons = [
            GapReason::QueueFull,
            GapReason::SockaddrUnreadable,
            GapReason::UnreapedChildren,
            GapReason::RestartFailed,
            GapReason::LifecycleDropped,
            GapReason::DeathUnattributed,
            GapReason::UnmatchedExit,
            GapReason::EntryAbandoned,
            GapReason::InflightExhausted,
            GapReason::PathUnreadable,
            GapReason::FlagsUnavailable,
            GapReason::SyscallInfoUnavailable,
            GapReason::IdentityUnavailable,
            GapReason::FinalStatusUnknown,
            GapReason::UnexpectedTraceStop,
            GapReason::TraceesAbandoned,
            GapReason::MediationResponseUndelivered,
            GapReason::ForeignAbi,
            GapReason::ChildNotificationListener,
            GapReason::UntracedDescendant,
            GapReason::RestartUnresolved,
            GapReason::ArgumentSnapshotUnstable,
        ];
        let names: std::collections::BTreeSet<&str> = reasons.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), reasons.len());
    }
}
