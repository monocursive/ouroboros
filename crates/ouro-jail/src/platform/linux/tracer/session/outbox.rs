//! The outbox: every event on its way to the consumer, and the loss
//! coalesced when it cannot get there.
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
//!   The budget covers what was handed to the channel and not yet taken as
//!   well ([`Events`](crate::platform::linux::tracer::Events) gives the bytes back), so the figure the
//!   observer plan records is the bound in force (J4 W3).
//! * Nothing is ever delivered with a bare `try_send`. Every send has a
//!   deadline, and what misses it is counted.
use std::sync::atomic::Ordering;
use std::sync::mpsc::TrySendError;
use std::time::{Duration, Instant};

use super::Session;
use crate::platform::linux::tracer::closed_set::ClosedOp;
use crate::platform::linux::tracer::{GapReason, OpSet, TracerEvent, event_bytes};

/// How long a tracee may be held at a stop by a consumer that is not reading.
/// After this the result is dropped and counted; the tree keeps moving.
const QUEUE_BLOCK: Duration = Duration::from_secs(1);

/// How often a full outbox is retried inside that second.
const QUEUE_POLL: Duration = Duration::from_micros(200);

/// Most lifecycle events the tracer will hold for a consumer that is not
/// reading. They are tiny and bounded by the number of tasks; past this the
/// backlog itself is the problem and is reported as one. The critical facts
/// are exempt ([`Session::is_critical`]): a gap past it is coalesced, an
/// exit is admitted.
const LIFECYCLE_MAX: usize = 16_384;

/// One event waiting to be handed to the consumer.
pub(super) struct Queued {
    event: TracerEvent,
    bytes: usize,
    pub(super) lifecycle: bool,
}

pub(super) struct CoalescedGap {
    reason: GapReason,
    ops: OpSet,
    from_ns: u64,
    to_ns: u64,
    /// `None` once any merged gap had an unknown size.
    count: Option<u64>,
}

impl Session {
    /// Everything held for the consumer: buffered, or handed over and not
    /// yet taken. The handed-over part can only be smaller by the time it is
    /// used, so admitting against it errs towards less.
    fn held(&self) -> usize {
        self.pending_bytes + self.handed.load(Ordering::Relaxed)
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
    ///
    /// Audit 7 L10: an `Exec` that carries a command hit is critical too.
    /// The kill itself happens at the exec stop, but the `command_rule` note
    /// rides on this event, and a best-effort `forbid` needs the
    /// `Fact::CommandForbidden` it carries to stop the run; a verdict lost
    /// to queue pressure would leave a forbidden command unreported.
    fn is_critical(event: &TracerEvent) -> bool {
        match event {
            TracerEvent::Exec { command, .. } => command.is_some(),
            event => matches!(
                event,
                TracerEvent::Exit { .. }
                    | TracerEvent::Gap { .. }
                    | TracerEvent::Finished
                    | TracerEvent::UntracedChildExit { .. }
            ),
        }
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
    pub(super) fn flush(&mut self) {
        while let Some(front) = self.pending.pop_front() {
            let lifecycle = front.lifecycle;
            let bytes = front.bytes;
            // Charged before the send, so the consumer's credit, which comes
            // after the receive, can never run ahead of it.
            self.handed.fetch_add(bytes, Ordering::Relaxed);
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
                    self.handed.fetch_sub(bytes, Ordering::Relaxed);
                    self.pending.push_front(Queued {
                        event,
                        bytes,
                        lifecycle,
                    });
                    return;
                }
                Err(TrySendError::Disconnected(event)) => {
                    self.handed.fetch_sub(bytes, Ordering::Relaxed);
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
            && self.held() + bytes <= self.result_bytes_max
    }

    pub(super) fn enqueue(&mut self, event: TracerEvent, bytes: usize, lifecycle: bool) {
        if lifecycle {
            self.lifecycle_pending += 1;
        }
        if matches!(event, TracerEvent::Gap { .. }) {
            self.summary.gaps += 1;
        }
        self.pending_bytes += bytes;
        self.summary.queue_bytes_peak = self.summary.queue_bytes_peak.max(self.held());
        self.pending.push_back(Queued {
            event,
            bytes,
            lifecycle,
        });
    }

    /// Put the coalesced gaps in front of whatever comes next, so the loss
    /// is never hidden behind the event that followed it. They are critical
    /// facts, so no cap applies to them.
    pub(super) fn materialise_gap(&mut self) {
        for gap in std::mem::take(&mut self.coalesced) {
            let event = TracerEvent::Gap {
                reason: gap.reason,
                ops: gap.ops,
                from_ns: gap.from_ns,
                to_ns: gap.to_ns,
                count: gap.count,
            };
            let bytes = event_bytes(&event);
            self.enqueue(event, bytes, true);
        }
    }

    pub(super) fn emit(&mut self, event: TracerEvent) {
        self.flush();
        let lifecycle = Session::is_lifecycle(&event);
        let bytes = event_bytes(&event);
        let ops = Session::ops_of(&event);

        if lifecycle {
            // Two caps bound the lifecycle backlog: a count, and the §11.4
            // byte budget, lifecycle events included — an `Exec` carries a
            // child-chosen pathname of up to `path_snapshot_max` bytes, so
            // without the budget the backlog alone could exceed it many times
            // over. Results stop short of [`LIFECYCLE_RESERVE`], so a dropped
            // `Exec` means the budget was full of evidence, not that the
            // reserve failed.
            let over =
                self.lifecycle_pending >= LIFECYCLE_MAX || self.held() + bytes > self.bytes_max;
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
    pub(super) fn gap(&mut self, reason: GapReason, ops: OpSet, count: Option<u64>) {
        let event = TracerEvent::Gap {
            reason,
            ops,
            from_ns: self.last_healthy_ns,
            to_ns: self.now_ns(),
            count,
        };
        self.emit(event);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libc::pid_t;

    use super::super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::{Args, EVENT_FIXED_BYTES, Events, TracerConfig};

    fn fork(child: pid_t) -> TracerEvent {
        TracerEvent::Fork {
            parent: 1,
            parent_tid: 1,
            child,
            is_thread: false,
            child_start_ticks: None,
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
        let config = TracerConfig {
            queue_bytes_max: 4 * EVENT_FIXED_BYTES,
            ..TracerConfig::default()
        };
        let (mut session, _rx) = new_session(config, FakeProc::default(), 1);
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

    /// J4 W3, loss review finding 4, at the session: what was handed to the
    /// channel and not taken counts against the budget, and taking it gives
    /// the bytes back.
    #[test]
    fn j4_w3_the_handoff_channel_is_inside_the_byte_budget() {
        let config = TracerConfig {
            queue_bytes_max: 4 * EVENT_FIXED_BYTES,
            ..TracerConfig::default()
        };
        let (mut session, rx) = new_session(config, FakeProc::default(), 64);
        let handed = Arc::clone(&session.handed);
        for child in 2..20 {
            session.emit(fork(child));
        }
        assert_eq!(
            handed.load(Ordering::Relaxed),
            4 * EVENT_FIXED_BYTES,
            "four events fit, all of them already in the channel"
        );
        assert_eq!(session.pending.len(), 0);
        assert_eq!(session.summary.loss.lifecycle_dropped, 14);
        assert!(session.summary.queue_bytes_peak <= 4 * EVENT_FIXED_BYTES);
        let events = Events::new(rx, Arc::clone(&handed));
        while events.try_recv().is_ok() {}
        assert_eq!(handed.load(Ordering::Relaxed), 0, "taken, and given back");
        session.emit(fork(99));
        assert_eq!(session.summary.loss.lifecycle_dropped, 14, "room again");
    }

    #[test]
    fn relative_syscall_cwd_counts_against_admission_and_handoff_credit() {
        let charge = EVENT_FIXED_BYTES + 512;
        let config = TracerConfig {
            queue_bytes_max: 64 * 1024 + 2 * charge,
            ..TracerConfig::default()
        };
        let (mut session, rx) = new_session(config, FakeProc::default(), 64);
        let handed = Arc::clone(&session.handed);
        let syscall = || TracerEvent::Syscall {
            pid: 1,
            start_ticks: None,
            tid: 1,
            op: ClosedOp::Open,
            syscall: "openat",
            args: Args {
                cwd: Some(vec![b'x'; 512].into_boxed_slice()),
                ..Default::default()
            },
            ret: 3,
        };
        session.emit(syscall());
        session.emit(syscall());
        assert_eq!(handed.load(Ordering::Relaxed), 2 * charge);
        // Skip the already-tested backpressure wait: a stalled consumer
        // must immediately refuse the third retained working directory.
        session.stalled = true;
        session.emit(syscall());
        assert_eq!(session.summary.loss.queue_dropped, 1);
        assert_eq!(handed.load(Ordering::Relaxed), 2 * charge);
        let events = Events::new(rx, Arc::clone(&handed));
        assert!(matches!(
            events.try_recv().unwrap(),
            TracerEvent::Syscall { .. }
        ));
        assert_eq!(handed.load(Ordering::Relaxed), charge);
        assert!(matches!(
            events.try_recv().unwrap(),
            TracerEvent::Syscall { .. }
        ));
        assert_eq!(handed.load(Ordering::Relaxed), 0);
        session.emit(syscall());
        assert_eq!(
            session.summary.loss.queue_dropped, 1,
            "credit frees room again"
        );
        while events.try_recv().is_ok() {}
        assert_eq!(handed.load(Ordering::Relaxed), 0);
    }
}
