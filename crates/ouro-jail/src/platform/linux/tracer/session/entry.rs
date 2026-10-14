//! A call's entry stop: what the call is, whether the observer follows it,
//! and the in-flight bound that decides whether it can.

use libc::pid_t;

use super::Session;
use super::restart::{Site, Verdict};
use super::tasks::{Call, Pending};
use crate::platform::linux::tracer::closed_set::{self, ClosedOp, Entry, FlagSource};
use crate::platform::linux::tracer::{Args, GapReason, OpSet, filter, sys};
use crate::platform::linux::{abi, seccomp};

impl Session {
    /// Security 2026-09-27 (audit 4 B2): whether a *foreign-ABI* entry is one of
    /// the two special calls anyway — a `seccomp` asking for its own
    /// notification listener, or a `clone` the kernel will not attach to this
    /// tracer — or a `clone3`, whose flags no filter can read.
    ///
    /// Three compat ABIs carry them: i386 (`int 0x80` on x86_64: `seccomp`
    /// 354, `clone` 120), x32 (the x86_64 numbers 317 and 56 with the x32 bit
    /// set) and AArch32 on arm64 (`seccomp` 383, `clone` 120). `seccomp`'s
    /// flags are in `args[1]` and `clone`'s in `args[0]` in all of them, so the
    /// same flag tests decide. The reference host does accept `int 0x80`, and
    /// under `none` a listener created through it can pass any syscall with
    /// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and no trace stop at all — which is
    /// the open-ended [`GapReason::ChildNotificationListener`] gap, not the
    /// bounded `foreign_abi` interval a plain foreign call costs.
    fn compat_special(info: &sys::SyscallInfo) -> Option<Call> {
        use crate::platform::linux::tracer::filter::{
            ARM_CLONE_SYSCALL, ARM_LISTENER_SYSCALL, CLONE_UNTRACED, CLONE3_SYSCALL,
            I386_CLONE_SYSCALL, I386_LISTENER_SYSCALL, SECCOMP_FILTER_FLAG_NEW_LISTENER,
            X32_CLONE_SYSCALL, X32_LISTENER_SYSCALL,
        };
        let x32_bit = u64::from(seccomp::X32_SYSCALL_BIT);
        let nr = info.nr & !x32_bit;
        let (listener, clone) = match info.arch {
            abi::AUDIT_ARCH_I386 => (I386_LISTENER_SYSCALL, I386_CLONE_SYSCALL),
            abi::AUDIT_ARCH_ARM => (ARM_LISTENER_SYSCALL, ARM_CLONE_SYSCALL),
            abi::AUDIT_ARCH_X86_64 if info.nr & x32_bit != 0 => {
                (X32_LISTENER_SYSCALL, X32_CLONE_SYSCALL)
            }
            _ => return None,
        };
        if nr == u64::from(listener)
            && info.args[1] & u64::from(SECCOMP_FILTER_FLAG_NEW_LISTENER) != 0
        {
            return Some(Call::Listener);
        }
        if nr == u64::from(CLONE3_SYSCALL.1)
            || (nr == u64::from(clone) && info.args[0] & u64::from(CLONE_UNTRACED) != 0)
        {
            return Some(Call::Untraced);
        }
        None
    }

    /// Whether a covered, register-sourced read-only open is filtered at
    /// its entry (`--read-open-fast-path`), counted as such. An `openat2`
    /// never is: its flags live in tracee memory the kernel re-reads after
    /// this stop (audit 2026-09-25-2, S1), so a read-only verdict there is
    /// only an assertion until the exit re-read confirms it, and the call
    /// is followed to its exit. Filtered at entry, a sibling flipping
    /// `open_how.flags` between the two kernel reads could perform a
    /// covered mutation with no event and no gap.
    fn filter_readonly_open_at_entry(&mut self, entry: &'static Entry) -> bool {
        if matches!(entry.flags, FlagSource::OpenHow { .. }) {
            return false;
        }
        // A read-only open is outside `linux-closed-v1`. It is not a loss,
        // it is not an event, and the tracee is continued from here rather
        // than stepped to a syscall exit nobody reads. It is filtered before
        // the in-flight bound is consulted (J4 O-1): with the table full it
        // is still not a call the observer had to follow, so refusing it
        // would record a read as lost evidence.
        self.summary.filtered_readonly_opens += 1;
        true
    }

    /// A `PTRACE_EVENT_SECCOMP` stop: the tracee is at the entry of a call
    /// the narrowing filter traces, and the syscall has not run.
    pub(super) fn handle_entry(&mut self, tid: pid_t) {
        let Some(info) = self.entry_info(tid) else {
            return;
        };
        let site = Site {
            arch: info.arch,
            nr: info.nr,
            ip: info.ip,
            arg0: info.args[0],
        };
        if self.follow_special(tid, &info, site) {
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
        if !self.config.learning
            && entry.op == ClosedOp::Open
            && let Some(flags) = flags
            && !closed_set::open_is_covered(flags)
        {
            self.enter_uncovered_open(tid, entry, (flags, flags_unavailable), &info, site);
            return;
        }
        self.enter_closed(tid, entry, (flags, flags_unavailable), &info, site);
    }

    /// The entry stop's syscall info, or `None` once the stop is accounted
    /// for without it.
    fn entry_info(&mut self, tid: pid_t) -> Option<sys::SyscallInfo> {
        match sys::syscall_info(tid) {
            Ok(info)
                if info.op == sys::SYSCALL_INFO_SECCOMP || info.op == sys::SYSCALL_INFO_ENTRY =>
            {
                Some(info)
            }
            // J4 O-3: the tracee left this stop without being resumed, which
            // only a SIGKILL does — it is either on its way out (`ESRCH`) or
            // already stopped at its exit notification. The kernel skips a
            // call whose thread has a fatal signal pending after the trace
            // event (`__seccomp_filter`), so whatever it was, it never ran.
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {
                self.summary.killed_at_entry += 1;
                None
            }
            Ok(_) if Self::at_exit_notification(tid) => {
                self.summary.killed_at_entry += 1;
                None
            }
            _ => {
                self.summary.loss.syscall_info_unavailable += 1;
                self.gap(GapReason::SyscallInfoUnavailable, OpSet::ALL, Some(1));
                None
            }
        }
    }

    /// Follows the calls classified before the closed-set table is
    /// consulted: a foreign-ABI entry, a listener request and an untraced
    /// clone. Returns whether `info` was one of them.
    fn follow_special(&mut self, tid: pid_t, info: &sys::SyscallInfo, site: Site) -> bool {
        // jail-v1 §9.2: validate the architecture before the syscall number.
        // A compat or x32 entry carries a number from a different table, and
        // naming it from this one would mislabel the call (J4 D2): it is
        // foreign, followed to its return and never decoded.
        if info.arch != abi::AUDIT_ARCH || info.nr & u64::from(seccomp::X32_SYSCALL_BIT) != 0 {
            // Security 2026-09-27 (audit 4 B2): the two calls whose *native*
            // forms carry their own classification — a listener hides every
            // later syscall for as long as it is held, and an untraced
            // descendant is never seen again, so both are open-ended gaps,
            // not closed intervals — reach those classifications through a
            // compat ABI too. Only `none` stops here (contained baselines
            // EPERM the foreign arch before the trace), but its receipt must
            // not present a live listener channel as an ended interval.
            let call = Session::compat_special(info).unwrap_or(Call::Foreign);
            self.follow(tid, call, site);
            return true;
        }
        // J4 D1: a child asking for its own notification listener. The flags
        // are the register the kernel will read, not memory the child could
        // change behind this stop.
        if info.nr == u64::from(filter::LISTENER_SYSCALL.1)
            && info.args[1] & u64::from(filter::SECCOMP_FILTER_FLAG_NEW_LISTENER) != 0
        {
            self.follow(tid, Call::Listener, site);
            return true;
        }
        // J4 S4: a clone the kernel will not attach to this tracer. The flags
        // are the register the kernel reads. Contained baselines refuse the
        // flag (EPERM outranks the trace), so only `none` stops here.
        if info.nr == u64::from(filter::CLONE_SYSCALL.1)
            && info.args[0] & u64::from(filter::CLONE_UNTRACED) != 0
        {
            self.follow(tid, Call::Untraced, site);
            return true;
        }
        false
    }

    /// An open whose flags say it is outside the closed set: filtered here
    /// when its verdict is final at entry, otherwise followed to its exit,
    /// where the flags are read again.
    fn enter_uncovered_open(
        &mut self,
        tid: pid_t,
        entry: &'static Entry,
        (flags, flags_unavailable): (u64, bool),
        info: &sys::SyscallInfo,
        site: Site,
    ) {
        // Register-sourced flags are the kernel's own saved pt_regs, so
        // an entry-time read-only verdict is final. `openat2`'s verdict
        // never is — see [`Session::filter_readonly_open_at_entry`].
        if self.filter_readonly_open_at_entry(entry) {
            return;
        }
        // The verification follow costs an in-flight slot like any
        // followed call; refused one, the call runs unfollowed, which is
        // a hole the receipt must name.
        if !self.admit(OpSet::of(entry.op)) {
            return;
        }
        let pending = Pending {
            flags_unavailable,
            ..Pending::new(
                entry,
                Args {
                    flags: Some(flags),
                    ..Args::default()
                },
                info.args,
            )
        };
        self.begin(tid, Call::Closed(pending), site);
    }

    /// A closed-set call: admitted to the in-flight table, its paths
    /// captured and, for an exec under command rules, judged before it
    /// runs.
    fn enter_closed(
        &mut self,
        tid: pid_t,
        entry: &'static Entry,
        (flags, flags_unavailable): (Option<u64>, bool),
        info: &sys::SyscallInfo,
        site: Site,
    ) {
        if !self.admit(OpSet::of(entry.op)) {
            // With command rules configured, an exec refused its in-flight
            // slot would resume unfollowed, with no argv read and no verdict
            // at all. The refusal already recorded its gap; the process dies
            // rather than run an unjudged exec (the `deny_exec` failure path
            // in `judge_exec` makes the same call).
            if entry.op == ClosedOp::Exec
                && !self.config.commands.is_empty()
                && !Self::kill_tracee(tid)
            {
                self.exec_denial_failed();
            }
            return;
        }
        let mut pending = self.capture_paths(tid, entry, &info.args);
        pending.args.flags = flags;
        pending.flags_unavailable = flags_unavailable;
        if entry.op == ClosedOp::Exec
            && !self.config.commands.is_empty()
            && !self.judge_exec(tid, entry, info, &mut pending)
        {
            return;
        }
        self.begin(tid, Call::Closed(pending), site);
    }

    /// Checks an exec against the command rules at its entry, denying it
    /// there when a rule matched. Returns `false` when the denial failed
    /// and the tracee was killed instead, so the call is not followed.
    fn judge_exec(
        &mut self,
        tid: pid_t,
        entry: &'static Entry,
        info: &sys::SyscallInfo,
        pending: &mut Pending,
    ) -> bool {
        let argv = entry
            .argv
            .and_then(|index| sys::argv(tid, info.args[usize::from(index)]));
        pending.args.command = self
            .config
            .commands
            .check(
                argv.as_deref(),
                pending.args.path.as_ref().map(|p| p.bytes.as_slice()),
            )
            .map(Box::new);
        pending.entry_argv = argv;
        if pending.args.command.is_some() && sys::deny_exec(tid, true).is_err() {
            // The call has not run, and the kill keeps it from running.
            // It still costs a gap: the verdict — a `forbid` stops the
            // run — rides only on the denied call's result, which a
            // killed tracee never produces.
            self.deny_by_kill(tid);
            return false;
        }
        true
    }

    /// Whether a tracee is stopped at its `PTRACE_EVENT_EXIT` notification:
    /// where a thread killed at another stop stops next (J4 O-3).
    pub(super) fn at_exit_notification(tid: pid_t) -> bool {
        matches!(
            sys::siginfo(tid),
            Ok((libc::SIGTRAP, code)) if code == libc::SIGTRAP | (sys::PTRACE_EVENT_EXIT << 8)
        )
    }

    /// Whether another call may be followed to its return. When the
    /// in-flight bound is reached the entry is refused, and the gap names
    /// what that call could have been.
    fn admit(&mut self, ops: OpSet) -> bool {
        if self.tasks.in_flight() >= self.config.inflight_max {
            self.summary.loss.inflight_rejected += 1;
            self.gap(GapReason::InflightExhausted, ops, Some(1));
            return false;
        }
        true
    }

    /// Follow `call`, which is not a closed-set call but decides what the
    /// observer can see from here on, or record what refusing it costs.
    ///
    /// Refused an in-flight slot, it runs unfollowed, and its return is the
    /// one fact that would have said whether it did anything. So the refusal
    /// costs what success would (J4 W3, loss review finding 3): a listener
    /// request is the open-ended `child_notification_listener` gap, and a
    /// `clone(CLONE_UNTRACED)` the open-ended `untraced_descendant` gap —
    /// never a one-count `inflight_exhausted` gap with an end, which would
    /// claim coverage back that the listener or the descendant can take. A
    /// foreign call is one call: `inflight_exhausted`, as for any other.
    fn follow(&mut self, tid: pid_t, call: Call, site: Site) {
        if self.tasks.in_flight() < self.config.inflight_max {
            self.begin(tid, call, site);
            return;
        }
        self.summary.loss.inflight_rejected += 1;
        match call {
            Call::Listener => {
                self.gap(GapReason::ChildNotificationListener, OpSet::ALL, None);
            }
            Call::Untraced => {
                self.gap(GapReason::UntracedDescendant, OpSet::ALL, None);
            }
            Call::Foreign | Call::Closed(_) => {
                self.gap(GapReason::InflightExhausted, call.ops(), Some(1));
            }
        }
    }

    /// Record `call`, which entered the kernel at `site`, as this thread's
    /// call in flight.
    pub(super) fn begin(&mut self, tid: pid_t, call: Call, site: Site) {
        if self.tasks.wait(tid).is_some() {
            // A new entry while a restart decision is still owed: the entry
            // stop that could have been the re-entry was judged in
            // `handle_restart_stop`, so this is out of sequence.
            self.settle_restart(tid, Verdict::Unknown);
        }
        if let Some(replaced) = self.tasks.take_call(tid) {
            // The previous entry for this thread never returned, and the gap
            // names the call it was (§11.4).
            self.summary.loss.abandoned_entries += 1;
            self.gap(GapReason::EntryAbandoned, replaced.ops(), Some(1));
        }
        self.tasks.begin_call(tid, call, site, true);
    }

    /// A stop for a number the narrowing filter never traces. The trace
    /// data says whose it is: a stop carrying other data was asked for by
    /// another filter — a child's own `SECCOMP_RET_TRACE` — on a call outside
    /// the closed set, and is continued untouched (not a result, not a loss,
    /// and never decoded). One carrying this filter's own data means the
    /// program the launcher installed is not the tracer's own, which is a
    /// gap.
    fn stop_not_ours(&mut self, tid: pid_t) {
        match sys::event_msg(tid) {
            // Audit 2026-09-25-2, S14: the expected data is this attempt's
            // own, not the public constant a child filter could echo.
            Ok(data)
                if data & u64::from(sys::SECCOMP_RET_DATA) != u64::from(self.config.trace_data) =>
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
}

#[cfg(test)]
mod tests {
    use super::super::tasks::{Task, TaskState};
    use super::super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::TracerConfig;

    /// A new entry is the thread's next call, so whatever it still owed is
    /// over first: a restart decision never seen is one unresolved gap of
    /// its call's classes, and a call that never returned is one abandoned
    /// entry. Only then does the new call take the thread's one slot.
    #[test]
    fn a_new_entry_ends_what_its_thread_still_owed_before_it_begins() {
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(RECYCLED, RECYCLED, 1000),
        );
        let in_flight = |session: &Session| {
            session
                .tasks
                .get(RECYCLED)
                .map(Task::state)
                .and_then(|state| match state {
                    TaskState::InFlight { call, .. } => Some(call.ops()),
                    _ => None,
                })
        };
        waiting(&mut session, RECYCLED, libc::SYS_openat as u64, "/w/fifo");
        session.begin(RECYCLED, Call::Untraced, Site::default());
        assert_eq!(
            gaps_of(&drained(&rx, &mut session)),
            vec![(
                GapReason::RestartUnresolved,
                OpSet::of(ClosedOp::Open),
                Some(1)
            )]
        );
        assert_eq!(in_flight(&session), Some(OpSet::ALL), "the new call");
        assert_eq!(session.tasks.in_flight(), 1);
        pend_instead(&mut session);
        assert_eq!(
            gaps_of(&drained(&rx, &mut session)),
            vec![(GapReason::EntryAbandoned, OpSet::ALL, Some(1))]
        );
        assert_eq!(
            in_flight(&session),
            Some(OpSet::of(ClosedOp::Mkdir)),
            "the call that replaced it"
        );
        assert_eq!(session.tasks.in_flight(), 1);
        assert_eq!(session.summary.loss.restart_unresolved, 1);
        assert_eq!(session.summary.loss.abandoned_entries, 1);
    }

    /// A `mkdirat` entered while the untraced clone is still in flight.
    fn pend_instead(session: &mut Session) {
        let mkdirat = closed_set::lookup(u64::from(abi::nr(258, 34))).expect("mkdirat");
        let call = Call::Closed(Pending::new(mkdirat, Args::default(), [0; 6]));
        session.begin(RECYCLED, call, Site::default());
    }

    /// Security 2026-09-25-2 (audit S1), mutation-B10 guard: the entry
    /// filter never takes an `openat2`, whatever its flags claim — its
    /// verdict is memory-sourced and only the exit re-read may certify it —
    /// while a read-only `open`/`openat` (register-sourced) is the entry
    /// fast path and is counted as filtered.
    #[test]
    fn the_entry_filter_never_takes_a_readonly_openat2() {
        let (mut session, _rx) = stalled_session();
        let openat2 = closed_set::lookup(437).expect("openat2");
        let openat = closed_set::lookup(u64::from(crate::platform::linux::abi::nr(257, 56)))
            .expect("openat");
        assert!(
            !session.filter_readonly_open_at_entry(openat2),
            "an openat2 is always followed to its exit (audit 2026-09-25-2 S1)"
        );
        assert_eq!(
            session.summary.filtered_readonly_opens, 0,
            "the followed call is not counted as filtered either"
        );
        assert!(
            session.filter_readonly_open_at_entry(openat),
            "a register-sourced read-only open is the entry fast path"
        );
        assert_eq!(session.summary.filtered_readonly_opens, 1);
    }

    /// Security 2026-09-27 (audit 4 B2): the compat-ABI spellings of the
    /// listener and untraced-clone requests reach their own classifications,
    /// and everything else foreign stays `None` (the plain foreign path).
    #[test]
    fn audit4_compat_abi_listener_and_untraced_clone_route_to_their_gaps() {
        use crate::platform::linux::tracer::filter as tfilter;
        let kind = |of: Option<Call>| match of {
            Some(Call::Listener) => "listener",
            Some(Call::Untraced) => "untraced",
            Some(Call::Foreign) => "foreign",
            Some(Call::Closed(_)) => "closed",
            None => "none",
        };
        let info = |arch: u32, nr: u64, a0: u64, a1: u64| sys::SyscallInfo {
            op: sys::SYSCALL_INFO_SECCOMP,
            arch,
            nr,
            ip: 0,
            args: [a0, a1, 0, 0, 0, 0],
            rval: 0,
        };
        let flag = u64::from(tfilter::SECCOMP_FILTER_FLAG_NEW_LISTENER);
        let untraced = u64::from(tfilter::CLONE_UNTRACED);
        // i386 int 0x80 seccomp(354) with NEW_LISTENER.
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_I386,
                354,
                0,
                flag
            ))),
            "listener"
        );
        // The same call without the flag is ordinary foreign.
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_I386,
                354,
                0,
                0
            ))),
            "none"
        );
        // i386 clone(120) with CLONE_UNTRACED.
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_I386,
                120,
                untraced,
                0
            ))),
            "untraced"
        );
        // x32 seccomp (317 | bit) and clone (56 | bit).
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_X86_64,
                317u64 | u64::from(seccomp::X32_SYSCALL_BIT),
                0,
                flag
            ))),
            "listener"
        );
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_X86_64,
                56u64 | u64::from(seccomp::X32_SYSCALL_BIT),
                untraced,
                0
            ))),
            "untraced"
        );
        // A native number under the i386 arch is a *different* call: 317 is
        // not i386 seccomp.
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_I386,
                317,
                0,
                flag
            ))),
            "none"
        );
        // AArch32 EABI has its own seccomp number. It can create the same
        // open-ended listener/untraced-child gaps as x86 compatibility ABIs.
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_ARM,
                383,
                0,
                flag
            ))),
            "listener"
        );
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_ARM,
                120,
                untraced,
                0
            ))),
            "untraced"
        );
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_ARM,
                354,
                0,
                flag
            ))),
            "none"
        );
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_ARM,
                383,
                0,
                0
            ))),
            "none"
        );
        // Another foreign architecture entirely.
        assert_eq!(
            kind(Session::compat_special(&info(
                abi::AUDIT_ARCH_AARCH64,
                354,
                0,
                flag
            ))),
            "none"
        );
    }

    /// J4 W3, loss review finding 3, at the session: refused an in-flight
    /// slot, a listener request and an untraced clone cost the open-ended
    /// gap of their kind; a foreign call is one call.
    #[test]
    fn j4_w3_a_refused_listener_or_untraced_clone_is_the_open_ended_gap_of_its_kind() {
        let (mut session, rx) = traced(
            TracerConfig {
                inflight_max: 1,
                ..TracerConfig::default()
            },
            &leader_and_peer(),
        );
        pend(&mut session, LEADER, libc::SYS_openat as u64, "/w/fifo");
        session.follow(PEER, Call::Listener, Site::default());
        session.follow(PEER, Call::Untraced, Site::default());
        session.follow(PEER, Call::Foreign, Site::default());
        assert_eq!(
            gaps_of(&drained(&rx, &mut session)),
            vec![
                (GapReason::ChildNotificationListener, OpSet::ALL, None),
                (GapReason::UntracedDescendant, OpSet::ALL, None),
                (GapReason::InflightExhausted, OpSet::ALL, Some(1)),
            ]
        );
        assert_eq!(session.summary.loss.inflight_rejected, 3);
        assert!(idle(&session, PEER));
        assert_eq!(session.tasks.in_flight(), 1);
    }
}
