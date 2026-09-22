//! Consuming the observer's event stream.
//!
//! The one place a [`TracerEvent`] becomes an audit record and, for the
//! attempt's target, a lifecycle fact (§11). The contained boundary
//! (`platform.rs`) and the uncontained one (`uncontained.rs`) both call it,
//! so what counts as exec confirmation, a target exit or a coverage loss, and
//! the gap bookkeeping when the observer stops, cannot drift apart between
//! them. Each caller decides what a fact means for its own lifecycle.

use std::time::Duration;

use libc::pid_t;

use super::audit::AuditWriter;
use super::tracer::{GapReason, OpSet, PathSnapshot, Tracer, TracerEvent, TracerSummary};

/// Whose events these are.
pub struct Target<'a> {
    /// The launcher's host pid: the target's once it execs.
    pub launcher: pid_t,
    /// The paths the launcher will try to `execve`, derived from the same
    /// program name and `PATH` it uses itself.
    pub images: &'a [Vec<u8>],
}

/// What one event establishes beyond its audit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fact {
    /// Nothing the lifecycle acts on.
    Nothing,
    /// The launcher's witnessed exec transition into one of the target's
    /// images: exec confirmation.
    TargetExec,
    /// The target's final status (the observer emits exits only after a
    /// witnessed exec).
    TargetExit(i32),
    /// A direct child that was never a tracee exited.
    UntracedExit {
        /// Its pid.
        pid: pid_t,
        /// Its raw wait status.
        status: i32,
    },
    /// Coverage lost at least one result (§11.4); bookkeeping gaps with an
    /// empty operation set are not this.
    CoverageLost(GapReason),
    /// The tracer thread stopped.
    Finished,
}

/// Whether an observed exec transition is the launcher executing the program
/// the operator named.
///
/// A transition with no pathname is one whose entry the observer did not
/// witness, which is what seizing a process already inside its own `execve`
/// produces; the launcher is seized while blocked in `read(2)`, so its target
/// exec is witnessed and carries a path. A pathname that is not one the
/// launcher would have tried is some other image. Neither confirms the
/// target ran.
#[must_use]
pub fn is_target_image(images: &[Vec<u8>], path: Option<&PathSnapshot>) -> bool {
    path.is_some_and(|path| {
        path.complete
            && images
                .iter()
                .any(|candidate| candidate.as_slice() == path.bytes.as_slice())
    })
}

/// Records `event` in `audit` and returns the fact it establishes.
pub fn record(audit: &mut AuditWriter, target: &Target<'_>, event: &TracerEvent) -> Fact {
    match event {
        TracerEvent::Exec {
            pid, path, dirfd, ..
        } => {
            audit.record_exec(*pid, path.as_ref(), *dirfd);
            if *pid == target.launcher && is_target_image(target.images, path.as_ref()) {
                Fact::TargetExec
            } else {
                Fact::Nothing
            }
        }
        TracerEvent::Syscall {
            pid,
            tid,
            op,
            syscall,
            args,
            ret,
            ..
        } => {
            audit.record_syscall(*pid, *tid, *op, syscall, args, *ret);
            Fact::Nothing
        }
        TracerEvent::Exit { pid, status, .. } => {
            audit.record_exit(*pid, *status);
            if *pid == target.launcher {
                Fact::TargetExit(*status)
            } else {
                Fact::Nothing
            }
        }
        TracerEvent::UntracedChildExit { pid, status } => Fact::UntracedExit {
            pid: *pid,
            status: *status,
        },
        TracerEvent::Gap {
            reason,
            ops,
            from_ns,
            to_ns,
            count,
        } => {
            audit.record_gap(*reason, *ops, *from_ns, *to_ns, *count);
            // §11.4 counts a hole only where a result went missing. A gap
            // whose operation set is empty is bookkeeping — an argument the
            // observer could not read and the kernel rejected for the same
            // reason, say — and stopping a strict run for it would let a
            // tracee deny service to its own supervisor by passing pointers
            // that cannot work.
            if ops.is_empty() {
                Fact::Nothing
            } else {
                Fact::CoverageLost(*reason)
            }
        }
        TracerEvent::Finished => Fact::Finished,
        // §11.2 keeps fork out of the public audit set, and a thread is not
        // a process: every count kept here is per thread group, which is
        // what the observer's `pid` already is.
        TracerEvent::Attached { .. } | TracerEvent::Fork { .. } => Fact::Nothing,
    }
}

/// Takes what the tracer has delivered: waits up to `block` for the first
/// event, then takes at most 256 more without waiting. Every event taken
/// must be handed to [`record`]; one read and dropped would be evidence
/// silently lost.
#[must_use]
pub fn drain(tracer: &Tracer, block: Duration) -> Vec<TracerEvent> {
    let mut events = Vec::new();
    if !block.is_zero()
        && let Ok(event) = tracer.events().recv_timeout(block)
    {
        events.push(event);
    }
    for _ in 0..256 {
        match tracer.events().try_recv() {
            Ok(event) => events.push(event),
            Err(_) => break,
        }
    }
    events
}

/// Stops the observer within `budget` and returns its account.
///
/// `finish_within` always returns: it interrupts the tracer thread, gives a
/// live tree up to `budget` to end, and on expiry kills what is left and
/// says how much it had to kill. Every event still delivered is recorded and
/// its fact handed to `on_fact`. Then the losses only the account shows are
/// recorded as gaps once each: tracees it had to abandon, direct children
/// whose status no longer has a route here, and lifecycle facts or results
/// dropped without a gap of their own.
pub fn stop(
    tracer: Tracer,
    budget: Duration,
    audit: &mut AuditWriter,
    target: &Target<'_>,
    mut on_fact: impl FnMut(Fact),
) -> TracerSummary {
    let summary = tracer.finish_within_draining(budget, |event| {
        on_fact(record(audit, target, &event));
    });
    let recorded = |audit: &AuditWriter, reason: GapReason| {
        audit.gaps().iter().any(|gap| gap.reason == reason.as_str())
    };
    if summary.loss.abandoned_tracees > 0 && !recorded(audit, GapReason::TraceesAbandoned) {
        audit.record_gap(
            GapReason::TraceesAbandoned,
            OpSet::ALL,
            0,
            0,
            Some(summary.loss.abandoned_tracees),
        );
    }
    if !summary.unreaped_children.is_empty() && !recorded(audit, GapReason::UnreapedChildren) {
        audit.record_gap(
            GapReason::UnreapedChildren,
            OpSet::EMPTY,
            0,
            0,
            u64::try_from(summary.unreaped_children.len()).ok(),
        );
    }
    if summary.loss.lifecycle_dropped > 0 || (summary.loss.total() > 0 && !audit.has_gaps()) {
        audit.record_gap(
            GapReason::QueueFull,
            OpSet::ALL,
            0,
            u64::try_from(crate::platform::elapsed_since_start_ns()).unwrap_or(u64::MAX),
            None,
        );
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::CoverageClass;
    use crate::platform::linux::tracer::{Args, ClosedOp};

    const LAUNCHER: pid_t = 4242;

    fn images() -> Vec<Vec<u8>> {
        vec![b"/usr/bin/target".to_vec()]
    }

    fn snapshot(bytes: &[u8], complete: bool) -> Option<PathSnapshot> {
        Some(PathSnapshot {
            bytes: bytes.to_vec(),
            complete,
        })
    }

    fn exec(pid: pid_t, path: Option<PathSnapshot>) -> TracerEvent {
        TracerEvent::Exec {
            pid,
            path,
            dirfd: None,
            monotonic_ns: 1,
        }
    }

    #[test]
    fn only_the_launchers_witnessed_exec_of_a_target_image_confirms() {
        let images = images();
        let target = Target {
            launcher: LAUNCHER,
            images: &images,
        };
        let mut audit = AuditWriter::new("att_x", None, b"/work", b"");
        for (event, expected) in [
            (
                exec(LAUNCHER, snapshot(b"/usr/bin/target", true)),
                Fact::TargetExec,
            ),
            (exec(LAUNCHER, None), Fact::Nothing),
            (
                exec(LAUNCHER, snapshot(b"/usr/bin/target", false)),
                Fact::Nothing,
            ),
            (
                exec(LAUNCHER, snapshot(b"/usr/bin/other", true)),
                Fact::Nothing,
            ),
            (exec(7, snapshot(b"/usr/bin/target", true)), Fact::Nothing),
        ] {
            assert_eq!(record(&mut audit, &target, &event), expected, "{event:?}");
        }
        // Every exec was recorded, confirming or not.
        assert_eq!(audit.count(CoverageClass::Exec), 5);
    }

    #[test]
    fn exits_gaps_and_the_end_are_facts_and_bookkeeping_is_not_a_loss() {
        let images = images();
        let target = Target {
            launcher: LAUNCHER,
            images: &images,
        };
        let mut audit = AuditWriter::new("att_x", None, b"/work", b"");
        let exit = |pid| TracerEvent::Exit {
            pid,
            status: 3 << 8,
            monotonic_ns: 1,
        };
        assert_eq!(
            record(&mut audit, &target, &exit(LAUNCHER)),
            Fact::TargetExit(3 << 8)
        );
        assert_eq!(record(&mut audit, &target, &exit(9)), Fact::Nothing);
        let gap = |ops| TracerEvent::Gap {
            reason: GapReason::QueueFull,
            ops,
            from_ns: 0,
            to_ns: 1,
            count: None,
        };
        assert_eq!(
            record(&mut audit, &target, &gap(OpSet::ALL)),
            Fact::CoverageLost(GapReason::QueueFull)
        );
        assert_eq!(
            record(&mut audit, &target, &gap(OpSet::EMPTY)),
            Fact::Nothing
        );
        assert_eq!(
            record(
                &mut audit,
                &target,
                &TracerEvent::UntracedChildExit { pid: 5, status: 0 }
            ),
            Fact::UntracedExit { pid: 5, status: 0 }
        );
        assert_eq!(
            record(&mut audit, &target, &TracerEvent::Finished),
            Fact::Finished
        );
        let syscall = TracerEvent::Syscall {
            pid: LAUNCHER,
            tid: LAUNCHER,
            op: ClosedOp::Open,
            syscall: "openat",
            args: Args::default(),
            ret: 3,
            monotonic_ns: 1,
        };
        assert_eq!(record(&mut audit, &target, &syscall), Fact::Nothing);
    }
}
