//! Restart decisions: a call whose syscall exit carried a kernel restart code
//! is followed to what the kernel then did with it.

use libc::pid_t;

use super::Session;
use super::tasks::Call;
use crate::platform::linux::abi;
use crate::platform::linux::tracer::{GapReason, sys};

/// Where a call entered the kernel: its ABI, its number and the user
/// instruction pointer just past the instruction that made it. A kernel restart
/// re-executes that instruction with the same number, so a re-entry stops here
/// again.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Site {
    pub(super) arch: u32,
    pub(super) nr: u64,
    pub(super) ip: u64,
    /// arm64 restores the original x0 argument before restarting; x86_64
    /// restores the syscall number in rax. Keep the entry value to verify it.
    pub(super) arg0: u64,
}

impl Site {
    /// The address of the syscall instruction itself, where the kernel
    /// rewinds the PC to restart the call: `ip` is just past it. The
    /// instruction is four bytes on arm64 (`svc #0`), and two on x86_64 and
    /// under its compat ABIs, where the kernel always rewinds two (`syscall`,
    /// `int 0x80`, `sysenter`).
    ///
    /// `None` for an AArch32 task, which an arm64 kernel runs under
    /// `AUDIT_ARCH_ARM` and which can reach this as a foreign call under
    /// `none`: its `svc` is four bytes in ARM state and two in Thumb state
    /// (`compat_thumb_mode`), and the entry stop does not say which. Nothing
    /// is lost by not guessing: the native register reader refuses such a
    /// task's register set (it is not arm64's size), so no handler frame of
    /// it is ever located and its restart is settled by what follows.
    fn restart_ip(self) -> Option<u64> {
        let width = match self.arch {
            abi::AUDIT_ARCH_AARCH64 => 4,
            abi::AUDIT_ARCH_X86_64 | abi::AUDIT_ARCH_I386 => 2,
            _ => return None,
        };
        Some(self.ip.wrapping_sub(width))
    }
}

/// A call whose syscall exit carried a kernel restart code.
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
///   from the result register and PC the kernel saved in that frame;
/// * a death, or the thread's destruction by another's `execve`: the call
///   did nothing and nothing was returned — neither a result nor a loss;
/// * anything else — a step trap in user space (the continuation ran through
///   `restart_syscall`, which is not traced), an unreadable or unrecognised
///   frame, a stop out of this sequence: [`GapReason::RestartUnresolved`].
///
/// "Restarted" at a handler's entry is not yet the end. The re-entry comes only
/// after the handler returns, through `rt_sigreturn`, which restores the frame
/// — and the frame is the program's memory: the handler, or a sibling thread
/// before the observer reads it, can rewrite it, so the program sees `EINTR`
/// from a call the observer read as restarted. The thread is then let run
/// ([`Awaiting::Reentry`]) and the wait is settled by what follows:
///
/// * its next entry stop at the same [`Site`]: the re-entry, restarted;
/// * its next entry stop anywhere else: [`GapReason::RestartUnresolved`] —
///   a call inside the handler cannot be told from one after a rewritten
///   frame, so a covered call made by an `SA_RESTART` handler costs a gap;
/// * its end first: nothing when the kernel decided the restart whatever the
///   frame (`ERESTARTNOINTR`, so there is no `EINTR` it could have hidden),
///   [`GapReason::RestartUnresolved`] when the frame decided it.
///
/// The call keeps its in-flight slot until then.
pub(super) struct RestartWait {
    pub(super) call: Call,
    /// The positive restart code.
    pub(super) code: i64,
    pub(super) site: Site,
    /// The last signal delivered to the thread since the exit, if any. The
    /// kernel notifies a handler's entry only after a signal was delivered.
    pub(super) delivered: Option<libc::c_int>,
    pub(super) awaiting: Awaiting,
}

/// What a [`RestartWait`] is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Awaiting {
    /// The kernel's decision. The thread is single-stepped.
    Decision,
    /// The re-entry a handler's entry announced. The thread runs freely.
    Reentry {
        /// The restart code alone decided it (`ERESTARTNOINTR`), not the
        /// frame the program can rewrite.
        by_kernel: bool,
    },
}

/// What an entry stop of a thread owing a restart decision showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryStop {
    /// Stopped at the entry of the call made at this site.
    At(Site),
    /// Killed at this stop before it was resumed: the kernel skips the call,
    /// and which call it was can no longer be read.
    Killed,
    /// Not describable.
    Unreadable,
}

/// What the kernel did with a call whose exit carried a restart code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Re-entered: the re-entered call produces the one result.
    Restarted,
    /// `EINTR` was returned to the program: that is the call's result.
    Interrupted,
    /// Not established: a [`GapReason::RestartUnresolved`] gap.
    Unknown,
}

/// The kernel's decision at a signal handler's entry
/// (`arch/{x86,arm64}/kernel/signal.c`). `ERESTARTNOHAND` and `ERESTART_RESTARTBLOCK`
/// become `EINTR` and `ERESTARTNOINTR` is re-entered, whatever the handler.
/// `ERESTARTSYS` is re-entered only under `SA_RESTART`, which is read from
/// what the kernel saved in the frame: the result register is `-EINTR`
/// with the PC unchanged, or the PC is rewound over the syscall instruction.
/// For a restart, x86_64 restores the syscall number in rax and rewinds two
/// bytes; arm64 restores the original x0 argument and rewinds four bytes.
/// Anything else is not a frame this call produced.
fn verdict_at_handler(code: i64, frame: Option<(u64, u64)>, site: Site) -> Verdict {
    match code {
        sys::ERESTARTNOINTR => Verdict::Restarted,
        sys::ERESTARTNOHAND | sys::ERESTART_RESTARTBLOCK => Verdict::Interrupted,
        sys::ERESTARTSYS => match frame {
            Some((ax, ip)) if ax == (-i64::from(libc::EINTR)) as u64 && ip == site.ip => {
                Verdict::Interrupted
            }
            Some((ax, ip))
                if ax
                    == if site.arch == abi::AUDIT_ARCH_AARCH64 {
                        site.arg0
                    } else {
                        site.nr
                    }
                    && Some(ip) == site.restart_ip() =>
            {
                Verdict::Restarted
            }
            _ => Verdict::Unknown,
        },
        _ => Verdict::Unknown,
    }
}

impl Session {
    /// A stop of a thread whose last call exited with a restart code and is
    /// waiting for the kernel's decision ([`RestartWait`]). Returns the
    /// signal to deliver when this stop is fully handled here; `None` hands
    /// it on to the ordinary handling, after settling the wait if the stop
    /// settles it.
    pub(super) fn handle_restart_stop(
        &mut self,
        tid: pid_t,
        signal: libc::c_int,
        event: libc::c_int,
    ) -> Option<libc::c_int> {
        let (code, site, delivered, awaiting) = {
            let wait = self.tasks.wait(tid)?;
            (wait.code, wait.site, wait.delivered, wait.awaiting)
        };
        if event == sys::PTRACE_EVENT_SECCOMP {
            // The thread's next entry. Stepped since the exit, no user
            // instruction ran before it, so only the kernel's re-entry can
            // be here; let run since a handler's entry, it is the re-entry
            // only if it is at the call's own site. Either way it is judged
            // here, and then handled as ever.
            let seen = Self::entry_stop(tid);
            self.judge_entry_stop(tid, seen);
            return None;
        }
        if awaiting != Awaiting::Decision {
            // Waiting for the re-entry while the handler runs: signals,
            // group-stops, forks and the thread's exit are handled as ever,
            // and the wait goes on.
            return None;
        }
        match event {
            // A group-stop, or the thread's exit: the decision is still
            // ahead, or never comes. Handled as ever; the thread keeps
            // stepping. An exec reported under this id is another thread's,
            // which destroyed this one: `exec_transition` ends the wait.
            sys::PTRACE_EVENT_STOP | sys::PTRACE_EVENT_EXIT | sys::PTRACE_EVENT_EXEC => None,
            0 if signal != sys::SYSCALL_STOP_SIG => {
                if signal == libc::SIGTRAP {
                    if let Some(uc) = delivered.and_then(|sig| self.handler_entry(tid, sig, site)) {
                        // The kernel has set up a handler and settled the
                        // call. This notification is not a signal: nothing
                        // is delivered for it.
                        let frame = Self::read_frame(tid, uc);
                        match verdict_at_handler(code, frame, site) {
                            Verdict::Restarted => {
                                // Believed at the re-entry itself (R1).
                                if let Some(wait) = self.tasks.wait_mut(tid) {
                                    wait.awaiting = Awaiting::Reentry {
                                        by_kernel: code == sys::ERESTARTNOINTR,
                                    };
                                }
                            }
                            verdict => self.settle_restart(tid, verdict),
                        }
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
                if let Some(wait) = self.tasks.wait_mut(tid) {
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
    /// tracee: `si_code` is the notification's own, then the native register
    /// reader verifies the delivered signal and locates the kernel frame.
    /// An ordinary signal-delivery stop is not this handler-entry stop.
    fn handler_entry(&mut self, tid: pid_t, delivered: libc::c_int, site: Site) -> Option<u64> {
        let restart_ip = site.restart_ip()?;
        let (signo, code) = sys::siginfo(tid).ok()?;
        if signo != libc::SIGTRAP || code != sys::SI_CODE_HANDLER_ENTRY {
            return None;
        }
        // The PC of a handler's entry is neither the call's own instruction,
        // where the kernel rewinds it to restart, nor the one after it.
        sys::handler_ucontext(tid, u64::try_from(delivered).ok()?, restart_ip, site.ip).ok()?
    }

    /// The interrupted result register and PC the kernel saved in the frame
    /// whose `ucontext` is at `uc`.
    fn read_frame(tid: pid_t, uc: u64) -> Option<(u64, u64)> {
        let mut word = [0u8; 8];
        let mut read = |offset: u64| {
            (sys::read_remote(tid, uc.checked_add(offset)?, &mut word) == 8)
                .then(|| u64::from_ne_bytes(word))
        };
        let ax = read(sys::FRAME_RESULT)?;
        let ip = read(sys::FRAME_IP)?;
        Some((ax, ip))
    }

    /// Whether a `SIGTRAP` stop is a trap this observer's stepping raised.
    fn is_step_trap(tid: pid_t) -> bool {
        matches!(
            sys::siginfo(tid),
            Ok((libc::SIGTRAP, sys::TRAP_TRACE | sys::TRAP_BRKPT))
        )
    }

    /// What the entry stop `tid` is at shows.
    fn entry_stop(tid: pid_t) -> EntryStop {
        match sys::syscall_info(tid) {
            Ok(info)
                if info.op == sys::SYSCALL_INFO_SECCOMP || info.op == sys::SYSCALL_INFO_ENTRY =>
            {
                EntryStop::At(Site {
                    arch: info.arch,
                    nr: info.nr,
                    ip: info.ip,
                    arg0: info.args[0],
                })
            }
            // Left this stop without being resumed, which only a SIGKILL does:
            // on its way out, or already at its exit notification.
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => EntryStop::Killed,
            Ok(_) if Self::at_exit_notification(tid) => EntryStop::Killed,
            _ => EntryStop::Unreadable,
        }
    }

    /// Judge an entry stop of a thread whose restart wait is still open.
    fn judge_entry_stop(&mut self, tid: pid_t, seen: EntryStop) {
        let Some((site, awaiting)) = self.tasks.wait(tid).map(|wait| (wait.site, wait.awaiting))
        else {
            return;
        };
        match (seen, awaiting) {
            (EntryStop::At(at), _) if at == site => self.settle_restart(tid, Verdict::Restarted),
            // Killed at the re-entry, which the kernel now skips: stepped here,
            // it can only be the re-entry; let run, it is taken as one only
            // when the kernel alone decided the restart. The call is counted
            // once, as killed at its entry, by `handle_entry` — not a second
            // time as a restart that never finished.
            (EntryStop::Killed, Awaiting::Decision | Awaiting::Reentry { by_kernel: true }) => {
                let _ = self.tasks.take_restart(tid);
            }
            _ => self.settle_restart(tid, Verdict::Unknown),
        }
    }

    /// Settle a thread's restart wait with `verdict`.
    pub(super) fn settle_restart(&mut self, tid: pid_t, verdict: Verdict) {
        match verdict {
            Verdict::Restarted => {
                // The re-entered call is a new entry with its own slot.
                if self.tasks.take_restart(tid).is_some() {
                    self.summary.restarts += 1;
                }
            }
            Verdict::Interrupted => {
                // The call's result is EINTR, delivered as any other result:
                // back in flight, to its exit.
                if self.tasks.end_wait_into_call(tid) {
                    self.summary.interrupted += 1;
                    self.handle_exit(tid, -i64::from(libc::EINTR));
                }
            }
            Verdict::Unknown => {
                if let Some(wait) = self.tasks.take_restart(tid) {
                    self.summary.loss.restart_unresolved += 1;
                    self.gap(GapReason::RestartUnresolved, wait.call.ops(), Some(1));
                }
            }
        }
    }

    /// A restart wait whose thread ended — died, or was destroyed by another
    /// thread's `execve` — before the wait was settled, and that has already
    /// left its thread. Before the kernel's decision the call did nothing and
    /// returned nothing, and so after a restart the kernel alone decided:
    /// neither a result nor a loss. After a restart read from the frame, the
    /// `EINTR` the program may have seen was never observed: a gap.
    pub(super) fn restart_ended(&mut self, wait: RestartWait) {
        match wait.awaiting {
            Awaiting::Decision | Awaiting::Reentry { by_kernel: true } => {
                self.summary.restarts_unfinished += 1;
            }
            Awaiting::Reentry { by_kernel: false } => {
                self.summary.loss.restart_unresolved += 1;
                self.gap(GapReason::RestartUnresolved, wait.call.ops(), Some(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::super::seams::LiveProc;
    use super::super::tasks::Pending;
    use super::super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::{
        Args, ClosedOp, OpSet, TracerConfig, TracerEvent, closed_set,
    };

    /// The wait keeps the site its call entered at, which is where the
    /// kernel's re-entry stops again: a re-entry there settles the wait as
    /// restarted, with no result and no loss, and releases the slot.
    #[test]
    fn a_wait_keeps_the_site_its_call_entered_at() {
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(RECYCLED, RECYCLED, 1000),
        );
        let site = Site {
            arch: abi::AUDIT_ARCH,
            nr: libc::SYS_openat as u64,
            ip: 0x40_1004,
            arg0: 7,
        };
        assert_ne!(site, Site::default());
        let openat = closed_set::lookup(libc::SYS_openat as u64).expect("openat");
        let call = Call::Closed(Pending::new(openat, Args::default(), [7, 0, 0, 0, 0, 0]));
        session.begin(RECYCLED, call, site);
        session.handle_exit(RECYCLED, -sys::ERESTARTSYS);
        assert_eq!(
            session.tasks.wait(RECYCLED).map(|wait| wait.site),
            Some(site)
        );
        session.judge_entry_stop(RECYCLED, EntryStop::At(site));
        assert_eq!(session.summary.restarts, 1);
        assert_eq!(session.summary.loss.total(), 0);
        assert!(drained(&rx, &mut session).is_empty());
        assert_eq!(session.tasks.in_flight(), 0);
    }

    /// The kernel's rule at a handler's entry, for every restart code. Only
    /// `ERESTARTSYS` depends on the frame, and only the two frames the kernel
    /// writes for it are accepted.
    #[test]
    fn j4_o2_the_verdict_at_a_handler_follows_the_kernel_for_every_code() {
        let site = Site {
            arch: abi::AUDIT_ARCH,
            nr: 257,
            ip: 0x40_1002,
            arg0: 257,
        };
        let eintr = (-i64::from(libc::EINTR)) as u64;
        let restarted = Some((
            257,
            site.ip - if cfg!(target_arch = "aarch64") { 4 } else { 2 },
        ));
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

    /// The restart address is the syscall instruction itself, one instruction
    /// before the `ip` the entry stop reports.
    #[test]
    fn the_restart_address_is_the_syscall_instruction_before_the_reported_ip() {
        let at = |arch| Site {
            arch,
            nr: 0,
            ip: 0x40_1004,
            arg0: 0,
        };
        assert_eq!(
            at(abi::AUDIT_ARCH_AARCH64).restart_ip(),
            Some(0x40_1000),
            "svc #0"
        );
        assert_eq!(
            at(abi::AUDIT_ARCH_X86_64).restart_ip(),
            Some(0x40_1002),
            "syscall"
        );
        assert_eq!(
            at(abi::AUDIT_ARCH_I386).restart_ip(),
            Some(0x40_1002),
            "int 0x80"
        );
        assert_eq!(at(0).restart_ip(), None, "an ABI the tracer does not know");
        // AArch32's `svc` is four bytes in ARM state and two in Thumb state,
        // which the entry stop does not show: no address, so no frame can
        // decide a restart either way.
        let arm = at(abi::AUDIT_ARCH_ARM);
        assert_eq!(arm.restart_ip(), None);
        for ip in [arm.ip - 2, arm.ip - 4] {
            assert_eq!(
                verdict_at_handler(sys::ERESTARTSYS, Some((arm.nr, ip)), arm),
                Verdict::Unknown,
                "{ip:#x}"
            );
        }
    }

    /// At the session, a restart code keeps the call in flight; each way the
    /// wait ends gives exactly what it should — `EINTR` one result, a re-entry
    /// nothing (the re-entered call is its own entry), an unresolved decision
    /// one gap naming the call's classes, a death nothing — and every one
    /// releases the slot.
    #[test]
    fn j4_o2_each_end_of_a_restart_wait_is_exact() {
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(RECYCLED, RECYCLED, 1000),
        );

        waiting(
            &mut session,
            RECYCLED,
            libc::SYS_openat as u64,
            "/w/interrupted",
        );
        assert_eq!(
            session.tasks.in_flight(),
            1,
            "still in flight while waiting"
        );
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
        assert_eq!(session.tasks.in_flight(), 0);

        waiting(
            &mut session,
            RECYCLED,
            u64::from(crate::platform::linux::abi::nr(83, 34)),
            "/w/restarted",
        );
        session.settle_restart(RECYCLED, Verdict::Restarted);
        assert!(drained(&rx, &mut session).is_empty());
        assert_eq!(session.tasks.in_flight(), 0);

        waiting(
            &mut session,
            RECYCLED,
            u64::from(crate::platform::linux::abi::nr(83, 34)),
            "/w/unknown",
        );
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
        assert_eq!(session.tasks.in_flight(), 0);

        waiting(
            &mut session,
            RECYCLED,
            u64::from(crate::platform::linux::abi::nr(83, 34)),
            "/w/died",
        );
        session.handle_death(RECYCLED, libc::SIGKILL);
        assert!(drained(&rx, &mut session).is_empty(), "no result, no gap");
        assert_eq!(session.tasks.in_flight(), 0);

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

    /// At the session, a restart read at a handler's entry is settled by what
    /// the thread does next. Its re-entry at the same site: restarted, no
    /// result of its own and no loss. Any other entry: one `restart_unresolved`
    /// gap of the call's classes. Its end: nothing when the restart code alone
    /// decided (`ERESTARTNOINTR`), a gap when the frame did. Killed at an entry
    /// stop that cannot be read: taken as the re-entry only when the code
    /// decided. Every end releases the slot.
    #[test]
    fn j4_w3_r1_a_restart_read_at_a_handler_is_settled_by_what_follows() {
        let open = OpSet::of(ClosedOp::Open);
        type Step = fn(&mut Session);
        let die: Step = |session| session.handle_death(RECYCLED, 0);
        let reenter: Step =
            |session| session.judge_entry_stop(RECYCLED, EntryStop::At(Site::default()));
        let other: Step = |session| {
            session.judge_entry_stop(
                RECYCLED,
                EntryStop::At(Site {
                    nr: 83,
                    ..Site::default()
                }),
            );
        };
        let killed: Step = |session| session.judge_entry_stop(RECYCLED, EntryStop::Killed);
        let unreadable: Step = |session| session.judge_entry_stop(RECYCLED, EntryStop::Unreadable);
        let gap = vec![(GapReason::RestartUnresolved, open, Some(1))];
        type Gaps = Vec<(GapReason, OpSet, Option<u64>)>;
        // (label, decided by the code alone, what follows, the gaps, restarts,
        // restarts unfinished)
        type Case = (&'static str, bool, Step, Gaps, u64, u64);
        let cases: [Case; 10] = [
            ("frame, re-entry", false, reenter, vec![], 1, 0),
            ("code, re-entry", true, reenter, vec![], 1, 0),
            ("frame, another entry", false, other, gap.clone(), 0, 0),
            ("code, another entry", true, other, gap.clone(), 0, 0),
            (
                "frame, unreadable entry",
                false,
                unreadable,
                gap.clone(),
                0,
                0,
            ),
            ("frame, death", false, die, gap.clone(), 0, 0),
            ("code, death", true, die, vec![], 0, 1),
            (
                "frame, killed at an entry",
                false,
                killed,
                gap.clone(),
                0,
                0,
            ),
            ("code, killed at an entry", true, killed, vec![], 0, 0),
            (
                "code, killed then death",
                true,
                |session| {
                    session.judge_entry_stop(RECYCLED, EntryStop::Killed);
                    session.handle_death(RECYCLED, 0);
                },
                vec![],
                0,
                0,
            ),
        ];
        for (label, by_kernel, step, gaps, restarts, unfinished) in cases {
            let (mut session, rx) = traced(
                TracerConfig::default(),
                &FakeProc::default().task(RECYCLED, RECYCLED, 1000),
            );
            announced(&mut session, RECYCLED, by_kernel);
            assert_eq!(session.tasks.in_flight(), 1, "{label}: still in flight");
            step(&mut session);
            let events = drained(&rx, &mut session);
            assert_eq!(gaps_of(&events), gaps, "{label}: {events:?}");
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, TracerEvent::Syscall { .. })),
                "{label}: never a result: {events:?}"
            );
            assert_eq!(session.summary.restarts, restarts, "{label}");
            assert_eq!(session.summary.restarts_unfinished, unfinished, "{label}");
            assert_eq!(
                session.tasks.in_flight(),
                0,
                "{label}: the slot is released"
            );
        }
    }

    /// R1 through the stepping phase is unchanged: a re-entry seen while
    /// stepping — no handler ran — is the kernel's own, and a kill there
    /// counts the call once (R2), as killed at its entry.
    #[test]
    fn j4_w3_r2_a_kill_at_a_stepped_reentry_ends_the_wait_without_a_count() {
        let (mut session, rx) = traced(
            TracerConfig::default(),
            &FakeProc::default().task(RECYCLED, RECYCLED, 1000),
        );
        waiting(&mut session, RECYCLED, libc::SYS_openat as u64, "/w/fifo");
        session.judge_entry_stop(RECYCLED, EntryStop::Killed);
        session.handle_death(RECYCLED, libc::SIGKILL);
        assert!(drained(&rx, &mut session).is_empty());
        assert_eq!(session.summary.restarts_unfinished, 0);
        assert_eq!(session.summary.restarts, 0);
        assert_eq!(session.tasks.in_flight(), 0);
    }

    /// Whether `pid` is asleep inside syscall `nr`, by `/proc`.
    fn sleeping_in(pid: pid_t, nr: libc::c_long) -> bool {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.chars().next());
        let syscall = std::fs::read_to_string(format!("/proc/{pid}/syscall")).unwrap_or_default();
        state == Some('S')
            && syscall
                .split_whitespace()
                .next()
                .and_then(|first| first.parse::<libc::c_long>().ok())
                == Some(nr)
    }

    /// A SIGKILL exactly at the re-entry of a restarted call. The child sleeps
    /// in `openat` of a FIFO, a default- ignored signal interrupts it
    /// (`-ERESTARTSYS` at the exit), the kernel re-enters the call, and the
    /// child is killed at that re-entry's seccomp stop. The kernel skips the
    /// re-entered call, so it is neither a result nor a loss — and it is one
    /// call, counted once. On the base it was counted twice, as
    /// `killed_at_entry` and `restarts_unfinished`.
    #[test]
    fn j4_w3_r2_a_kill_at_the_reentry_of_a_restarted_call_is_counted_once() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path and a mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let Some(child) = Mkdirer::start_open(&c) else {
            return;
        };
        let (mut session, rx) = new_session(TracerConfig::default(), LiveProc, 1024);
        let status = child.release();
        assert!(is_seccomp_stop(status), "the open's entry: {status:#x}");
        session.handle(child.pid, status);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !sleeping_in(child.pid, libc::SYS_openat) {
            assert!(
                Instant::now() < deadline,
                "the child never slept in its open"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // SAFETY: a pid this test created, and a valid signal.
        assert_eq!(unsafe { libc::kill(child.pid, libc::SIGWINCH) }, 0);
        let status = child.wait();
        assert!(
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == sys::SYSCALL_STOP_SIG,
            "the restart-coded exit: {status:#x}"
        );
        session.handle(child.pid, status);
        let status = child.wait();
        assert!(
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGWINCH,
            "the signal's delivery: {status:#x}"
        );
        session.handle(child.pid, status);
        let status = child.wait();
        assert!(is_seccomp_stop(status), "the re-entry: {status:#x}");
        child.kill();
        session.handle(child.pid, status);
        child.reap_into(&mut session);
        let events = drained(&rx, &mut session);
        assert_eq!(gaps_of(&events), vec![], "{events:?}");
        assert_eq!(
            session.summary.killed_at_entry + session.summary.restarts_unfinished,
            1,
            "one call, counted once: {:?}",
            session.summary
        );
        assert_eq!(
            session.summary.loss.total(),
            0,
            "{:?}",
            session.summary.loss
        );
        assert_eq!(session.tasks.in_flight(), 0);
    }
}
