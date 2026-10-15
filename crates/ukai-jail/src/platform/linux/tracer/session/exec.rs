//! The confirmed exec transition (`PTRACE_EVENT_EXEC`): the threads it
//! destroys, the entry it confirms, and the command rules' re-check.

use std::time::Instant;

use libc::pid_t;

use super::evidence::{ExecEvidence, exec_recheck};
use super::restart::Site;
use super::tasks::{Call, Task, TaskState};
use super::{KILL_GRACE, Session};
use crate::platform::linux::tracer::closed_set::ClosedOp;
use crate::platform::linux::tracer::{GapReason, PathSnapshot, TracerEvent, sys};

/// What the exec's own entry says about the transition, when the observer
/// followed that entry.
#[derive(Default)]
struct ExecEntry {
    /// `execve` or `execveat`.
    syscall: Option<&'static str>,
    /// The pathname snapshot taken at the entry.
    path: Option<PathSnapshot>,
    dirfd: Option<i32>,
    /// The argv the entry-stop check judged, when the command rules
    /// re-judge the exec here.
    rejudge: Option<Vec<Vec<u8>>>,
}

impl Session {
    pub(super) fn handle_exec(&mut self, tid: pid_t) {
        // After execve the thread group has exactly one thread and its id is
        // the leader's, which is the id this stop was reported under. If a
        // worker did the exec, PTRACE_GETEVENTMSG names the id it had before.
        let former = sys::event_msg(tid)
            .map(|value| value as pid_t)
            .unwrap_or(tid);
        self.exec_transition(tid, former);
    }

    /// The exec transition reported under `tid`, made by the thread that had
    /// the id `former` before it (`tid` itself for a leader exec).
    fn exec_transition(&mut self, tid: pid_t, former: pid_t) {
        self.summary.exec_transitions += 1;
        let non_leader = former != tid && former > 0;
        let carried = if non_leader {
            self.renamed_thread(former)
        } else {
            None
        };
        self.end_leaders_flight(tid, non_leader);
        let tgid = self.tgid_of(tid);
        self.destroy_other_threads(tgid, tid);
        let entry = self.confirm_entry(tid, carried);
        // The kernel has already installed the new image at this stop, so
        // `/proc/<tid>/exe` names what actually runs, whatever the tracee did
        // to the pathname between the entry snapshot and the kernel's own copy.
        // A read that fails keeps the event (the snapshot's claim stands, as
        // before) without the corroboration.
        let images = self
            .config
            .target
            .as_ref()
            .filter(|(pid, _)| *pid == tgid)
            .map_or(&[][..], |(_, images)| images.as_slice());
        let evidence = ExecEvidence::read(&*self.procfs, tid, images, entry.rejudge.is_some());
        let command = self.recheck_command(tid, &entry, &evidence);
        let kernel_argv = evidence.event_argv();
        let start_ticks = self.birth_of(tgid);
        self.emit(TracerEvent::Exec {
            pid: tgid,
            start_ticks,
            syscall: entry.syscall,
            path: entry.path,
            kernel_image: evidence.image,
            dirfd: entry.dirfd,
            command,
            shebangs: evidence.scripts,
            kernel_argv,
        });
    }

    /// The thread that execed under the id `former`, which it no longer
    /// has: its task is gone, and the call it had in flight — its `execve`
    /// — moves with it to the leader's id.
    fn renamed_thread(&mut self, former: pid_t) -> Option<(Call, Site)> {
        let task = self.tasks.remove(former)?;
        let tgid = task.tgid;
        let carried = match task.into_state() {
            TaskState::InFlight { call, site, .. } => Some((call, site)),
            // Not reachable: the thread that execs is in its `execve`,
            // not waiting for a restart decision. Kept exact anyway.
            TaskState::Restarting(wait) => {
                self.restart_ended(wait);
                None
            }
            TaskState::Idle => None,
        };
        // That task did not die: it is this one now, under the leader's
        // id. Nothing will ever report it, so it is not retired — a
        // recycled pid with this number must not be swallowed.
        self.summary.tasks_destroyed_by_exec += 1;
        if let Some(process) = self.procs.get_mut(&tgid) {
            process.threads.remove(&former);
        }
        carried
    }

    /// End whatever the task registered under `tid` had in flight before
    /// this exec.
    ///
    /// It was the leader until now. After a non-leader exec that thread is
    /// gone: the kernel destroyed it, and the thread that execed took its id.
    /// Whatever it had in flight can no longer return, and the syscall exit
    /// that follows is the exec's own — whether or not the exec's entry was
    /// followed: when it was refused an in-flight slot, pairing the leader's
    /// stale entry with that exit would invent a result. The gap names the
    /// call, because the entry is in hand.
    fn end_leaders_flight(&mut self, tid: pid_t, non_leader: bool) {
        if non_leader {
            match self.tasks.take_state(tid) {
                Some(TaskState::InFlight { call, .. }) => {
                    self.summary.loss.abandoned_entries += 1;
                    self.gap(GapReason::EntryAbandoned, call.ops(), Some(1));
                }
                Some(TaskState::Restarting(wait)) => self.restart_ended(wait),
                Some(TaskState::Idle) | None => {}
            }
        } else if let Some(wait) = self.tasks.take_restart(tid) {
            // A leader's own exec: a wait would have been settled at its
            // `execve` entry, so one here is out of sequence.
            self.summary.loss.restart_unresolved += 1;
            self.gap(GapReason::RestartUnresolved, wait.call.ops(), Some(1));
        }
    }

    /// The other threads of `tgid`, which the exec of `tid` destroyed, and
    /// the exec the process is now seen to have made.
    fn destroy_other_threads(&mut self, tgid: pid_t, tid: pid_t) {
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
            match self.tasks.remove(thread).map(Task::into_state) {
                Some(TaskState::InFlight { call, .. }) => {
                    // The entry is in hand: the gap names the call it would
                    // have reported, not an anonymous hole (§11.4).
                    self.summary.loss.abandoned_entries += 1;
                    self.gap(GapReason::EntryAbandoned, call.ops(), Some(1));
                }
                // Destroyed while its restart was owed: as a death.
                Some(TaskState::Restarting(wait)) => self.restart_ended(wait),
                Some(TaskState::Idle) | None => {}
            }
        }
    }

    /// Put the `carried` call in flight under `tid`, and confirm the exec
    /// entry `tid` now has in flight, if any: its syscall exit is this
    /// transition's, not a second result.
    fn confirm_entry(&mut self, tid: pid_t, carried: Option<(Call, Site)>) -> ExecEntry {
        if let Some((call, site)) = carried {
            self.tasks.begin_call(tid, call, site, false);
        }
        let rules = !self.config.commands.is_empty();
        let Some(Call::Closed(pending)) = self.tasks.call_mut(tid) else {
            return ExecEntry::default();
        };
        if pending.entry.op != ClosedOp::Exec {
            return ExecEntry::default();
        }
        pending.exec_confirmed = true;
        ExecEntry {
            syscall: Some(pending.entry.name),
            path: pending.args.path.clone(),
            dirfd: pending.args.dirfd,
            // The argv the entry-stop check judged is tracee memory, which a
            // sibling thread can rewrite for the kernel's own copy. The image
            // is installed here and has run nothing, so the kernel's own copy
            // of the argv and of the image are re-checked ([`exec_recheck`]).
            // An entry the rules already denied never reaches this stop.
            rejudge: (rules && pending.args.command.is_none())
                .then(|| pending.entry_argv.clone().unwrap_or_default()),
        }
    }

    /// The command rules' verdict on the exec the kernel installed, and its
    /// enforcement: a hit kills the process before its image runs.
    fn recheck_command(
        &mut self,
        tid: pid_t,
        entry: &ExecEntry,
        evidence: &ExecEvidence,
    ) -> Option<Box<crate::commands::Hit>> {
        let entry_argv = entry.rejudge.as_ref()?;
        let command = Box::new(exec_recheck(
            &self.config.commands,
            entry_argv,
            evidence.argv.as_deref(),
            entry.path.as_ref().map(|p| p.bytes.as_slice()),
            evidence.image.as_ref().map(|image| image.path.as_slice()),
        )?);
        // The exec was observed whole and its event carries the verdict,
        // so its entry leaves flight here, with nothing to account for: the
        // death that follows has no call to abandon.
        let _ = self.tasks.take_call(tid);
        if !Self::kill_tracee(tid) {
            // The hit is live: the process dies before its image runs an
            // instruction — after `evidence` was read, so the event keeps
            // it — and the event records the verdict and stops the run
            // for a `forbid`. A kill that could not be sent leaves the
            // image free to run, which the gap says.
            self.exec_denial_failed();
        }
        Some(command)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::tasks::Pending;
    use super::super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::closed_set;
    use crate::platform::linux::tracer::{Args, OpSet, ShebangImage, TracerConfig};

    /// At the session, after a non-leader exec the leader's entry is abandoned
    /// — a gap of its own classes — whether the thread that execed carried its
    /// own entry or had none (refused an in-flight slot), and nothing is left
    /// on the leader's id that the exec's syscall exit could be paired with. A
    /// restart the leader owed ends as its death would.
    #[test]
    fn j4_w3_a_non_leader_exec_abandons_the_leaders_entry_whatever_was_carried() {
        for carried in [false, true] {
            let (mut session, rx) = traced(TracerConfig::default(), &leader_and_peer());
            pend(&mut session, LEADER, libc::SYS_openat as u64, "/w/fifo");
            if carried {
                pend(&mut session, PEER, libc::SYS_execve as u64, "/bin/image");
            }
            session.exec_transition(LEADER, PEER);
            let events = drained(&rx, &mut session);
            assert_eq!(
                gaps_of(&events),
                vec![(
                    GapReason::EntryAbandoned,
                    OpSet::of(ClosedOp::Open),
                    Some(1)
                )],
                "carried {carried}: {events:?}"
            );
            let exec_path = events.iter().find_map(|event| match event {
                TracerEvent::Exec { pid, path, .. } => Some((*pid, path.clone())),
                _ => None,
            });
            let leader = session.tasks.get(LEADER).expect("the leader's id lives on");
            if carried {
                assert!(
                    matches!(
                        leader.state(),
                        TaskState::InFlight {
                            call: Call::Closed(Pending {
                                exec_confirmed: true,
                                ..
                            }),
                            ..
                        }
                    ),
                    "the carried execve is the one entry left"
                );
                assert_eq!(session.tasks.in_flight(), 1);
                assert_eq!(
                    exec_path.map(|(pid, path)| (pid, path.map(|p| p.bytes))),
                    Some((LEADER, Some(b"/bin/image".to_vec())))
                );
            } else {
                assert!(idle(&session, LEADER), "nothing to pair the exit with");
                assert_eq!(session.tasks.in_flight(), 0);
                assert_eq!(exec_path, Some((LEADER, None)));
            }
            assert!(!session.tasks.contains(PEER));
            assert_eq!(session.summary.loss.abandoned_entries, 1);
        }
        for (by_kernel, gaps) in [
            (
                false,
                vec![(
                    GapReason::RestartUnresolved,
                    OpSet::of(ClosedOp::Open),
                    Some(1),
                )],
            ),
            (true, vec![]),
        ] {
            let (mut session, rx) = traced(TracerConfig::default(), &leader_and_peer());
            announced(&mut session, LEADER, by_kernel);
            session.exec_transition(LEADER, PEER);
            let events = drained(&rx, &mut session);
            assert_eq!(gaps_of(&events), gaps, "by kernel {by_kernel}: {events:?}");
            assert_eq!(session.tasks.in_flight(), 0);
            assert!(idle(&session, LEADER));
        }
    }

    /// The exec stop reads the kernel's evidence once, through the `/proc`
    /// seam: the command rules' re-check and the `#!` confirmation share
    /// one read of the image link and one of the argv, and the event carries
    /// what they were judged on.
    #[test]
    fn the_exec_evidence_is_read_once_and_carried_whole() {
        const EXECER: pid_t = RECYCLED;
        let script = ShebangImage {
            interpreter: b"/bin/sh".to_vec(),
            argument: None,
            identity: None,
        };
        let proc = FakeProc::default().task(EXECER, EXECER, 1000);
        proc.edit(|kernel| {
            kernel
                .cmdline
                .insert(EXECER, b"/bin/sh\0/w/build.sh\0".to_vec());
            kernel.exe.insert(EXECER, b"/usr/bin/dash".to_vec());
            kernel
                .scripts
                .insert(b"/w/build.sh".to_vec(), script.clone());
        });
        let (mut session, rx) = traced(
            TracerConfig {
                target: Some((EXECER, vec![b"/w/build.sh".to_vec()])),
                commands: crate::commands::Rules {
                    deny: vec!["git push".into()],
                    forbid: Vec::new(),
                }
                .compile()
                .unwrap(),
                ..TracerConfig::default()
            },
            &proc,
        );
        let execve = closed_set::lookup(libc::SYS_execve as u64).expect("execve");
        let args = Args {
            path: Some(snapshot(b"/w/build.sh")),
            ..Args::default()
        };
        let pending = Pending {
            entry_argv: Some(vec![b"/w/build.sh".to_vec()]),
            ..Pending::new(execve, args, [0; 6])
        };
        plant(&mut session, EXECER, pending);
        proc.edit(|kernel| kernel.reads.clear());
        session.exec_transition(EXECER, EXECER);
        assert_eq!(
            proc.reads(),
            HashMap::from([("exe", 1), ("cmdline", 1), ("script", 1)]),
            "each file read once at the stop, and nothing else read"
        );
        let events = drained(&rx, &mut session);
        let Some(TracerEvent::Exec {
            kernel_image,
            command,
            shebangs,
            kernel_argv,
            ..
        }) = events
            .iter()
            .find(|event| matches!(event, TracerEvent::Exec { .. }))
        else {
            panic!("the exec event: {events:?}");
        };
        assert_eq!(
            kernel_image.as_ref().map(|image| image.path.as_slice()),
            Some(&b"/usr/bin/dash"[..])
        );
        assert_eq!(shebangs, &vec![Some(script)]);
        assert_eq!(
            kernel_argv.as_deref(),
            Some(&[b"/bin/sh".to_vec(), b"/w/build.sh".to_vec()][..])
        );
        assert!(command.is_none(), "a script rewrite is not a hit");
        assert_eq!(
            session.tasks.in_flight(),
            1,
            "the exec's own exit is still owed"
        );
    }

    /// The process an exec-time hit kills leaves flight at its exec event,
    /// which carries the verdict, so the death that follows has no entry to
    /// abandon — no invented `entry_abandoned` loss.
    #[test]
    fn an_exec_the_recheck_kills_leaves_flight_with_its_event_and_no_abandoned_gap() {
        // No real task has this pid, so the SIGKILL touches nothing.
        const EXECER: pid_t = RECYCLED;
        let proc = FakeProc::default().task(EXECER, EXECER, 1000);
        proc.edit(|kernel| {
            kernel
                .cmdline
                .insert(EXECER, b"git\0push\0--force\0".to_vec());
            kernel.exe.insert(EXECER, b"/usr/bin/git".to_vec());
        });
        let (mut session, rx) = traced(
            TracerConfig {
                commands: crate::commands::Rules {
                    deny: vec!["git push --force".into()],
                    forbid: Vec::new(),
                }
                .compile()
                .unwrap(),
                ..TracerConfig::default()
            },
            &proc,
        );
        let execve = closed_set::lookup(libc::SYS_execve as u64).expect("execve");
        let args = Args {
            path: Some(snapshot(b"/usr/bin/git")),
            ..Args::default()
        };
        let pending = Pending {
            entry_argv: Some(vec![b"git".to_vec(), b"status".to_vec()]),
            ..Pending::new(execve, args, [0; 6])
        };
        plant(&mut session, EXECER, pending);
        session.exec_transition(EXECER, EXECER);
        assert!(idle(&session, EXECER));
        assert_eq!(session.tasks.in_flight(), 0);
        session.handle_death(EXECER, libc::SIGKILL);
        let events = drained(&rx, &mut session);
        assert!(gaps_of(&events).is_empty(), "{events:?}");
        assert_eq!(session.summary.loss.abandoned_entries, 0);
        let command = events
            .iter()
            .find_map(|event| match event {
                TracerEvent::Exec { command, .. } => Some(command.clone()),
                _ => None,
            })
            .expect("the exec event");
        assert_eq!(
            command.map(|hit| (hit.pattern, hit.forbidden)),
            Some(("git push --force".to_owned(), false))
        );
    }
}
