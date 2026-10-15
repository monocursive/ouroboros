//! A call's syscall exit: pairing it with its entry, and turning the pair
//! into one result, one gap, or a restart wait.

use libc::pid_t;

use super::Session;
use super::evidence::path_corroborated;
use super::seams::path_has_marker;
use super::tasks::{Call, Pending, TaskState};
use crate::platform::linux::tracer::closed_set::{self, ClosedOp, FlagSource};
use crate::platform::linux::tracer::{GapReason, OpSet, TracerEvent, sys};

impl Session {
    /// A `SIGTRAP | 0x80` stop: the syscall entry or exit of a call whose
    /// entry we recorded.
    pub(super) fn handle_syscall_stop(&mut self, tid: pid_t) {
        let info = match sys::syscall_info(tid) {
            Ok(info) => info,
            Err(err)
                if err.raw_os_error() == Some(libc::ESRCH)
                    && self
                        .tasks
                        .get(tid)
                        .is_some_and(|task| matches!(task.state(), TaskState::InFlight { .. })) =>
            {
                // Killed at the exit, after its call ran, before the return
                // could be read. The result is lost, and the entry in hand is
                // what names it: the death that follows records it once, as
                // `entry_abandoned` of that call's own classes — not a second
                // gap in every class.
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

    /// A syscall exit of `tid`: the end of the call its entry stop put in
    /// flight, which becomes one result or one gap — or, with a kernel
    /// restart code, a wait for the kernel's decision.
    pub(super) fn handle_exit(&mut self, tid: pid_t, rval: i64) {
        // A restart code is not a result yet: the kernel decides after this
        // stop whether to re-enter the call or to return EINTR, and the call
        // stays in flight until the observer has seen which.
        if sys::is_restart(rval) && self.tasks.start_wait(tid, -rval) {
            return;
        }
        let Some(call) = self.tasks.take_call(tid) else {
            // A syscall exit with no entry to pair it with: either the entry
            // was never seen or this thread is not one we track.
            self.unmatched_exit();
            return;
        };
        match call {
            Call::Closed(pending) => self.closed_returned(tid, pending, rval),
            Call::Foreign => self.foreign_returned(rval),
            Call::Listener => self.listener_returned(rval),
            Call::Untraced => self.untraced_returned(rval),
        }
    }

    /// A syscall exit with no entry to pair it with.
    fn unmatched_exit(&mut self) {
        self.summary.loss.unmatched_exits += 1;
        self.gap(GapReason::UnmatchedExit, OpSet::ALL, Some(1));
    }

    /// A call under another ABI returned: never decoded, so its return is all
    /// the observer learns of it.
    fn foreign_returned(&mut self, rval: i64) {
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
    }

    /// A request for a notification listener returned.
    fn listener_returned(&mut self, rval: i64) {
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
    }

    /// A `clone(CLONE_UNTRACED)` returned.
    fn untraced_returned(&mut self, rval: i64) {
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
    }

    /// A closed-set call returned `rval`. It is one result unless a step
    /// below finds that the result cannot be delivered as observed, which
    /// makes it a gap of the call's own classes instead.
    fn closed_returned(&mut self, tid: pid_t, mut pending: Pending, rval: i64) {
        let Some(rval) = self.denial_written(tid, &pending, rval) else {
            return;
        };
        if pending.exec_confirmed {
            // `Exec` was already emitted for this call at the confirmed
            // transition; the zero that follows is the same event.
            return;
        }
        if self.forced_unmatched(&pending) || !self.unreadable_accounted(&pending, rval) {
            return;
        }
        let op = pending.entry.op;
        // The entry snapshot of pointed arguments is only an assertion while
        // the same bytes still read at the exit. A thread of the tracee can
        // rewrite `open_how.flags`, a pathname or an address family between the
        // entry stop and the kernel's own copy after it, which would falsify
        // this event's classification — a mutation recorded as a read, or a
        // path that was never used. Re-read and compare; on any disagreement
        // the event is dropped and the call becomes a gap of its own classes,
        // so the receipt can never present a falsified snapshot as observed
        // fact. Register arguments need no re-read: the kernel consumes the
        // saved pt_regs, which this stop pair already saw.
        if !self.arguments_stable(tid, &pending) {
            self.summary.loss.argument_snapshot_unstable += 1;
            self.gap(GapReason::ArgumentSnapshotUnstable, OpSet::of(op), Some(1));
            return;
        }
        if self.readonly_open_unverified(&pending) {
            return;
        }
        self.corroborate_open_path(tid, &mut pending, rval);
        self.summary.ops.bump(op);
        let tgid = self.tgid_of(tid);
        let start_ticks = self.birth_of(tgid);
        self.emit(TracerEvent::Syscall {
            pid: tgid,
            start_ticks,
            tid,
            op,
            syscall: pending.entry.name,
            args: pending.args,
            ret: rval,
        });
    }

    /// The result the call returns: its own, or the `EPERM` a command-rule
    /// denial writes over it. `None` when that `EPERM` could not be written
    /// and the process is killed instead.
    fn denial_written(&mut self, tid: pid_t, pending: &Pending, rval: i64) -> Option<i64> {
        if pending.args.command.is_none() {
            return Some(rval);
        }
        if sys::deny_exec(tid, false).is_err() {
            // The entry rewrite already skipped the call; only its
            // `EPERM` could not be written, so the verdict's result is
            // what is missing.
            self.deny_by_kill(tid);
            return None;
        }
        Some(-i64::from(libc::EPERM))
    }

    /// O03 seam: when this covered call's path matches the seam marker,
    /// treat its exit as unmatched — the entry might never have been seen
    /// — so it becomes an `unmatched_exit` gap, never a result. The
    /// in-flight slot is already released, so this matches a genuinely
    /// unmatched exit. Gated to a non-exec op.
    fn forced_unmatched(&mut self, pending: &Pending) -> bool {
        if pending.entry.op != ClosedOp::Exec
            && let Some(marker) = &self.force_unmatched_marker
            && path_has_marker(pending.args.path.as_ref(), marker)
        {
            self.unmatched_exit();
            return true;
        }
        false
    }

    /// Account for the arguments the entry stop could not read, and say
    /// whether the call can still be delivered: not when its flags are
    /// unknown.
    ///
    /// An argument the observer could not read is only a hole in coverage
    /// when the kernel could read it. When the kernel rejected the same
    /// pointer or structure, there was no covered operation to miss, and
    /// counting it as loss would let a tracee manufacture loss at will by
    /// passing addresses that can never work.
    fn unreadable_accounted(&mut self, pending: &Pending, rval: i64) -> bool {
        let op = pending.entry.op;
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
            return false;
        }
        true
    }

    /// Whether the call is a read-only open whose verdict rests on flags in
    /// memory, counted and named by its gap.
    ///
    /// A memory-sourced read-only `openat2` followed for verification: the exit
    /// re-read agreeing with the entry snapshot does NOT prove the kernel
    /// applied these flags — a thread of the tracee can flip `open_how.flags`
    /// for the kernel's own copy and restore them before this stop (an A-B-A
    /// rewrite), which this observer cannot tell apart. The verdict is
    /// therefore not certifiable: the call is counted, but it is also a gap of
    /// its own classes, never a silent filter. Register-sourced flags are
    /// immune (the kernel consumes the saved `pt_regs`) and keep their
    /// entry-time read-only skip.
    fn readonly_open_unverified(&mut self, pending: &Pending) -> bool {
        let op = pending.entry.op;
        if op == ClosedOp::Open
            && (!self.config.learning || matches!(pending.entry.flags, FlagSource::OpenHow { .. }))
            && let Some(flags) = pending.args.flags
            && !closed_set::open_is_covered(flags)
        {
            self.summary.filtered_readonly_opens += 1;
            self.summary.loss.memory_flags_unverified += 1;
            self.gap(GapReason::MemoryFlagsUnverified, OpSet::of(op), Some(1));
            return true;
        }
        false
    }

    /// Weaken a successful open's pathname claim the kernel does not
    /// corroborate.
    ///
    /// Byte stability is not certification for a pathname either — a sibling
    /// thread can rewrite the buffer for the kernel's own copy and restore it
    /// before the exit re-read, the same A-B-A rewrite the flags gap names. A
    /// successful open hands the observer one kernel fact: the descriptor's own
    /// `/proc/<tid>/fd/<ret>` link, resolved by the kernel for the file it
    /// actually opened. When it corroborates the snapshot
    /// ([`path_corroborated`]) the claim stands; otherwise (an unreadable link,
    /// or a disagreement a symlink, a pipe or a rename could also explain) the
    /// claim is downgraded to an incomplete path, counted, and named by a
    /// bookkeeping gap, so a receipt never certifies a pathname the kernel may
    /// not have used. The call and its event are kept — no result is missing —
    /// so this never degrades a class or stops a strict run: failures of this
    /// check only weaken, never accuse.
    fn corroborate_open_path(&mut self, tid: pid_t, pending: &mut Pending, rval: i64) {
        if pending.entry.op == ClosedOp::Open
            && rval >= 0
            && let Some(snapshot) = pending.args.path.as_mut()
            && snapshot.complete
        {
            let tmpfile = pending
                .args
                .flags
                .is_some_and(|flags| flags & (libc::O_TMPFILE as u64) == libc::O_TMPFILE as u64);
            let corroborated = self.procfs.fd_link(tid, rval).is_some_and(|resolved| {
                // The kernel's ` (deleted)` annotation can also be a live
                // file's literal name, so when the raw link carries it the
                // descriptor's link count — read while the tracee is stopped —
                // must agree the file is truly unlinked.
                let nlink = if resolved.ends_with(b" (deleted)") {
                    self.procfs.fd_nlink(tid, rval)
                } else {
                    None
                };
                path_corroborated(&snapshot.bytes, &resolved, tmpfile, nlink)
            });
            if !corroborated {
                self.summary.path_claims_unverified += 1;
                self.gap(GapReason::PathClaimUnverified, OpSet::EMPTY, Some(1));
                snapshot.complete = false;
            }
        }
    }

    /// Whether the pointed arguments this event asserts still read at the
    /// syscall exit as they read at the entry stop.
    ///
    /// The kernel consumes pointed arguments *after* the entry stop resumes,
    /// re-reading the same user memory the observer snapshotted; a thread of
    /// the tracee can rewrite it in that window. At the exit stop the kernel
    /// has finished with the memory, so a re-read that agrees with the entry
    /// snapshot is the strongest check a passive observer can make, and any
    /// disagreement — including memory that can no longer be read — means the
    /// snapshot may not be what the kernel applied. Only what the event
    /// asserts is checked: register arguments (immutable between the stops),
    /// incomplete path snapshots (already carried as weaker assertions) and
    /// addresses whose family was never read need no re-read.
    fn arguments_stable(&mut self, tid: pid_t, pending: &Pending) -> bool {
        let raw = pending.raw;
        if let FlagSource::OpenHow { ptr, .. } = pending.entry.flags {
            let mut word = [0u8; 8];
            if sys::read_remote(tid, raw[ptr as usize], &mut word) != 8 {
                return false;
            }
            if pending.args.flags != Some(u64::from_ne_bytes(word)) {
                return false;
            }
        }
        for (index, snapshot) in [
            pending.entry.path.map(|i| (i, pending.args.path.as_ref())),
            pending
                .entry
                .path2
                .map(|i| (i, pending.args.path2.as_ref())),
        ]
        .into_iter()
        .flatten()
        {
            let Some(snapshot) = snapshot else { continue };
            if !snapshot.complete || raw[index as usize] == 0 {
                // An incomplete snapshot already carries its weaker claim,
                // and no complete snapshot was ever read from a null pointer.
                continue;
            }
            if !self.path_unchanged(tid, raw[index as usize], &snapshot.bytes) {
                return false;
            }
        }
        if let Some((ptr, _len)) = pending.entry.sockaddr
            && let Some(snapshot) = pending.args.sockaddr.as_ref()
            && snapshot.complete
            && let Some(family) = snapshot.family
        {
            let mut word = [0u8; 2];
            if sys::read_remote(tid, raw[ptr as usize], &mut word) != 2 {
                return false;
            }
            if family != u16::from_ne_bytes(word) {
                return false;
            }
        }
        true
    }

    /// Compare exactly the captured bytes and their terminating NUL. No
    /// allocation or read of unrelated bytes beyond that terminator is needed.
    /// Partial reads are retried; an unreadable byte or changed terminator is
    /// still instability, including a formerly empty pathname becoming nonempty.
    pub(super) fn path_unchanged(&mut self, tid: pid_t, addr: u64, expected: &[u8]) -> bool {
        if addr == 0 || expected.len() >= self.config.path_snapshot_max {
            return false;
        }
        let length = expected.len() + 1;
        let mut offset = 0;
        while offset < length {
            let Some(at) = addr.checked_add(offset as u64) else {
                return false;
            };
            let want = (length - offset)
                .min(self.scratch.len())
                .min(4096 - (at % 4096) as usize);
            let read = sys::read_remote(tid, at, &mut self.scratch[..want]);
            if read == 0 {
                return false;
            }
            for (index, byte) in self.scratch[..read].iter().enumerate() {
                if *byte != expected.get(offset + index).copied().unwrap_or(0) {
                    return false;
                }
            }
            offset += read;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::restart::Site;
    use super::super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::{Args, TracerConfig};

    /// The exit re-read of pointed arguments. A snapshot that still reads at
    /// the exit is stable; one whose memory changed (or can no longer be read)
    /// is not, and its event must become an `argument_snapshot_unstable` gap.
    /// Verified against this very process's memory, which `read_remote` can
    /// read.
    #[test]
    fn pointed_arguments_are_reverified_at_the_exit() {
        let (mut session, _rx) = stalled_session();
        let entry = closed_set::lookup(u64::from(crate::platform::linux::abi::nr(257, 56)))
            .expect("openat");
        let mut path = b"/workspace/file.txt\0".to_vec();
        let addr = path.as_ptr() as u64;
        let mut raw = [0u64; 6];
        raw[1] = addr; // pathname
        raw[2] = 0; // O_RDONLY, as a register argument
        let pending = Pending::new(
            entry,
            Args {
                path: Some(snapshot(b"/workspace/file.txt")),
                flags: Some(0),
                ..Args::default()
            },
            raw,
        );
        let self_pid = std::process::id() as pid_t;
        assert!(
            session.arguments_stable(self_pid, &pending),
            "unchanged memory is stable"
        );
        path[4] = b'X';
        assert!(
            !session.arguments_stable(self_pid, &pending),
            "a rewritten pathname is unstable"
        );
        path[4] = b's';
        raw[1] = 1; // an address nothing can read
        let mut unreadable = pending.clone();
        unreadable.raw = raw;
        assert!(
            !session.arguments_stable(self_pid, &unreadable),
            "unreadable memory is unstable"
        );
        let zero = Pending {
            raw: [0; 6],
            ..pending
        };
        assert!(
            session.arguments_stable(self_pid, &zero),
            "a null pointer asserted nothing to re-read"
        );
    }

    /// An `openat2` classified read-only at its entry is followed to its exit,
    /// where the flags are re-read. Even stable read-only flags cannot be
    /// certified — an A-B-A rewrite satisfies both reads — so the call is
    /// counted AND recorded as a `memory_flags_unverified` gap of its classes,
    /// never a silent filter; flags rewritten between the two kernel reads
    /// remain an `argument_snapshot_unstable` gap.
    #[test]
    fn a_readonly_openat2_is_reverified_at_its_exit() {
        let self_pid = std::process::id() as pid_t;
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(self_pid, self_pid, 1000),
        );
        let entry = closed_set::lookup(437).expect("openat2");
        let mut how: u64 = 0; // O_RDONLY, as the kernel would read it
        let mut raw = [0u64; 6];
        raw[1] = c"path".as_ptr() as u64;
        raw[2] = &mut how as *const u64 as u64; // struct open_how *
        raw[3] = 24; // size
        let pending = Pending::new(
            entry,
            Args {
                flags: Some(0),
                ..Args::default()
            },
            raw,
        );
        plant(&mut session, self_pid, pending.clone());
        session.handle_exit(self_pid, 3);
        assert_eq!(
            session.summary.filtered_readonly_opens, 1,
            "stable read-only flags are counted"
        );
        assert_eq!(
            session.summary.loss.memory_flags_unverified, 1,
            "a stable verdict on memory flags is still uncertifiable"
        );
        match rx.try_recv() {
            Ok(TracerEvent::Gap {
                reason: GapReason::MemoryFlagsUnverified,
                ..
            }) => {}
            other => panic!("expected a memory_flags_unverified gap, got {other:?}"),
        }
        how = libc::O_WRONLY as u64 | libc::O_CREAT as u64;
        assert_ne!(how, 0, "the raced value is what the kernel will apply");
        plant(&mut session, self_pid, pending);
        session.handle_exit(self_pid, 3);
        assert_eq!(
            session.summary.loss.argument_snapshot_unstable, 1,
            "rewritten flags are an unstable gap"
        );
        assert_eq!(
            session.summary.filtered_readonly_opens, 1,
            "the raced call never counts as filtered"
        );
    }

    /// The real unmatched-exit branch of `handle_exit` — a syscall exit with no
    /// entry to pair (the O03.2 seam's manufactured gap is this same shape, but
    /// the branch here is reached without the seam) — counts the loss and
    /// records one `unmatched_exit` gap over every class. Both shapes reach it:
    /// a thread this tracer tracks whose entry was never seen, and one it does
    /// not track at all.
    #[test]
    fn an_exit_with_no_entry_is_one_unmatched_exit_gap() {
        // A tracked thread whose pending entry is gone: the entry was
        // never seen for this exit.
        let pid = std::process::id() as pid_t;
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(pid, pid, 1000),
        );
        session.handle_exit(pid, 0);
        assert_eq!(
            session.summary.loss.unmatched_exits, 1,
            "the tracked-but-unentered exit is counted"
        );
        match rx.try_recv() {
            Ok(TracerEvent::Gap {
                reason: GapReason::UnmatchedExit,
                count: Some(1),
                ..
            }) => {}
            other => panic!("expected one unmatched_exit gap, got {other:?}"),
        }
        // A thread this tracer does not track at all: the same branch, and
        // the count and the gap are not swallowed by the first.
        session.handle_exit(pid.wrapping_add(1 << 20), 0);
        assert_eq!(
            session.summary.loss.unmatched_exits, 2,
            "the untracked exit is counted too"
        );
        match rx.try_recv() {
            Ok(TracerEvent::Gap {
                reason: GapReason::UnmatchedExit,
                count: Some(1),
                ..
            }) => {}
            other => panic!("expected a second unmatched_exit gap, got {other:?}"),
        }
    }

    /// At the session, a `clone(CLONE_UNTRACED)` that created a task is a gap
    /// in every class with no count; one that failed is nothing.
    #[test]
    fn j4_s4_an_untraced_descendant_is_a_gap_and_a_failed_clone_is_not() {
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(RECYCLED, RECYCLED, 1000),
        );
        session.begin(RECYCLED, Call::Untraced, Site::default());
        session.handle_exit(RECYCLED, -i64::from(libc::EPERM));
        assert_eq!(session.summary.untraced_clone_refused, 1);
        session.begin(RECYCLED, Call::Untraced, Site::default());
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

    /// A claim the descriptor does not corroborate is downgraded and named by a
    /// bookkeeping gap — never loss, never a degraded class — so ordinary
    /// `O_TMPFILE` and `/dev/stderr` opens cannot stop a strict run, while a
    /// bare relative name is checked like any other. Verified against this
    /// process's own memory, which the exit's stability re-read can read.
    #[test]
    fn an_open_claim_the_descriptor_does_not_corroborate_is_downgraded_not_lost() {
        let self_pid = std::process::id() as pid_t;
        let write = (libc::O_WRONLY | libc::O_CREAT) as u64;
        let cases: [(&[u8], u64, &[u8], bool); 5] = [
            (b"/w/out.txt\0", write, b"/w/out.txt", true),
            (
                b"/tmp\0",
                (libc::O_RDWR | libc::O_TMPFILE) as u64,
                b"/tmp/#77 (deleted)",
                true,
            ),
            (
                b"/dev/stderr\0",
                libc::O_WRONLY as u64,
                b"pipe:[4242]",
                false,
            ),
            (b"a\0", write, b"/w/b", false),
            (b"/w/public/x\0", write, b"/w/secret/x", false),
        ];
        for (path, flags, link, corroborated) in cases {
            let proc = FakeProc::default().task(self_pid, self_pid, 1000);
            proc.edit(|script| {
                script.fds.insert((self_pid, 5), (link.to_vec(), None));
            });
            let (mut session, rx) = traced(TracerConfig::default(), &proc);
            let mut raw = [0u64; 6];
            raw[1] = path.as_ptr() as u64;
            raw[2] = flags;
            let openat = closed_set::lookup(u64::from(crate::platform::linux::abi::nr(257, 56)))
                .expect("openat");
            let args = Args {
                path: Some(snapshot(&path[..path.len() - 1])),
                flags: Some(flags),
                ..Args::default()
            };
            plant(&mut session, self_pid, Pending::new(openat, args, raw));
            session.handle_exit(self_pid, 5);
            let events = drained(&rx, &mut session);
            let delivered = events
                .iter()
                .find_map(|event| match event {
                    TracerEvent::Syscall { args, .. } => args.path.clone(),
                    _ => None,
                })
                .expect("the call is delivered either way");
            let name = String::from_utf8_lossy(path);
            assert_eq!(delivered.complete, corroborated, "{name}");
            assert_eq!(
                gaps_of(&events),
                if corroborated {
                    Vec::new()
                } else {
                    vec![(GapReason::PathClaimUnverified, OpSet::EMPTY, Some(1))]
                },
                "{name}"
            );
            assert_eq!(
                session.summary.path_claims_unverified,
                u64::from(!corroborated),
                "{name}"
            );
            assert_eq!(session.summary.loss.total(), 0, "{name}: never loss");
        }
    }

    /// A denied exec whose `EPERM` cannot be written at its exit is killed,
    /// and the missing verdict is one exec-class gap with its own counter —
    /// not a `foreign_abi` gap over every class with no count, which would
    /// name another ABI and a hole of unknown size.
    #[test]
    fn a_denial_that_cannot_be_written_is_one_exec_gap() {
        // No real task has this pid: the register write fails with ESRCH,
        // and the kill finds it already gone.
        const EXECER: pid_t = RECYCLED;
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(EXECER, EXECER, 1000),
        );
        let execve = closed_set::lookup(libc::SYS_execve as u64).expect("execve");
        let args = Args {
            command: Some(Box::new(crate::commands::Hit {
                pattern: "git push".to_owned(),
                digest: None,
                forbidden: true,
            })),
            ..Args::default()
        };
        plant(&mut session, EXECER, Pending::new(execve, args, [0; 6]));
        session.handle_exit(EXECER, -i64::from(libc::ENOSYS));
        let events = drained(&rx, &mut session);
        assert_eq!(
            gaps_of(&events),
            vec![(
                GapReason::ExecDenialFailed,
                OpSet::of(ClosedOp::Exec),
                Some(1)
            )]
        );
        assert_eq!(session.summary.loss.exec_denials_failed, 1);
        assert_eq!(session.summary.loss.total(), 1);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, TracerEvent::Syscall { .. })),
            "no result is invented for a call whose return was never written"
        );
    }
}
