//! Consuming the observer's event stream.
//!
//! The one place a [`TracerEvent`] becomes an audit record and, for the
//! attempt's target, a lifecycle fact (§11). The contained boundary
//! (`platform.rs`) and the uncontained one (`uncontained.rs`) both call it,
//! so what counts as exec confirmation, a target exit or a coverage loss, and
//! the gap bookkeeping when the observer stops, cannot drift apart between
//! them. Each caller decides what a fact means for its own lifecycle.

use std::ffi::OsString;
use std::time::Duration;

use libc::pid_t;
use serde_json::{Map, Value};

use super::audit::AuditWriter;
use super::tracer::{
    GapReason, OpSet, PathSnapshot, Tracer, TracerConfig, TracerEvent, TracerSummary,
};

/// Test seam (J4 decision S9): a smaller in-flight bound, so a live test can
/// reach map exhaustion through the product. Shrink-only.
pub const INFLIGHT_SEAM: &str = "OURO_JAIL_TEST_TRACER_INFLIGHT";

/// Test seam (J4 decision S9): a smaller user-space event queue budget, in
/// bytes, so a live test can reach ring loss through the product.
/// Shrink-only.
pub const QUEUE_BYTES_SEAM: &str = "OURO_JAIL_TEST_TRACER_QUEUE_BYTES";

/// The §11.4 bounds an attempt's observer runs with: its "observer plan".
///
/// §11.4 names the initial bounds and says "Record actual values in the
/// observer plan"; this is where they are decided, once per attempt, and
/// [`ObserverPlan::details`] is what the receipt records. The two test seams
/// can only lower a bound, which can only lose more evidence — and that loss
/// is then reported like any other. They never widen authority, leave the
/// policy digest alone, and each one set is named in the receipt with the
/// value it took, or `null` when it was set but not a shrink and so ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverPlan {
    config: TracerConfig,
    /// Every seam that was set: its name and the bound it applied, or `None`
    /// when its value was not a shrink of the default.
    seams: Vec<(&'static str, Option<u64>)>,
}

impl ObserverPlan {
    /// The plan for this process's environment.
    #[must_use]
    pub fn from_env() -> ObserverPlan {
        ObserverPlan::with_lookup(|name| std::env::var_os(name))
    }

    /// The plan, reading the seams through `lookup`.
    #[must_use]
    pub fn with_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> ObserverPlan {
        let mut config = TracerConfig::default();
        let mut seams = Vec::new();
        let mut shrink = |name: &'static str, bound: &mut usize| {
            let Some(value) = lookup(name) else {
                return;
            };
            let applied = shrunk(&value, *bound);
            if let Some(value) = applied {
                *bound = value;
            }
            seams.push((name, applied.and_then(|value| u64::try_from(value).ok())));
        };
        shrink(INFLIGHT_SEAM, &mut config.inflight_max);
        shrink(QUEUE_BYTES_SEAM, &mut config.queue_bytes_max);
        ObserverPlan { config, seams }
    }

    /// The tracer's configuration, with gap intervals counted from
    /// `epoch_boottime_ns` (§13.1).
    #[must_use]
    pub fn tracer_config(&self, epoch_boottime_ns: u64) -> TracerConfig {
        TracerConfig {
            epoch_boottime_ns,
            ..self.config
        }
    }

    /// The receipt's record of the plan (`lifetime.native.details.observer_plan`).
    ///
    /// The ptrace observer has no kernel ring: the §11.4 ring bound is
    /// recorded as `null`, and its two user-space counterparts are the
    /// in-flight bound ("map exhaustion") and the queue ("ring loss").
    #[must_use]
    pub fn details(&self) -> Value {
        let mut plan = Map::new();
        plan.insert("backend".to_owned(), Value::from("ptrace"));
        plan.insert("kernel_ring_bytes".to_owned(), Value::Null);
        plan.insert(
            "in_flight_max".to_owned(),
            Value::from(self.config.inflight_max),
        );
        plan.insert(
            "queue_bytes_max".to_owned(),
            Value::from(self.config.queue_bytes_max),
        );
        plan.insert(
            "queue_events_max".to_owned(),
            Value::from(self.config.queue_max),
        );
        plan.insert(
            "path_snapshot_max".to_owned(),
            Value::from(self.config.path_snapshot_max),
        );
        plan.insert(
            "event_bytes_max".to_owned(),
            Value::from(crate::trace::EVENT_MAX),
        );
        plan.insert(
            "test_seams".to_owned(),
            Value::Object(
                self.seams
                    .iter()
                    .map(|(name, applied)| {
                        ((*name).to_owned(), applied.map_or(Value::Null, Value::from))
                    })
                    .collect(),
            ),
        );
        Value::Object(plan)
    }
}

/// `value` as a bound in `1..=bound`, or `None`: a seam only ever shrinks.
fn shrunk(value: &OsString, bound: usize) -> Option<usize> {
    let text = value.to_str()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<usize>()
        .ok()
        .filter(|value| (1..=bound).contains(value))
}

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
        // J4-O begin: the birth identity and the exec's own call (slice O)
        TracerEvent::Exec {
            pid,
            start_ticks,
            syscall,
            path,
            dirfd,
            ..
        } => {
            audit.record_exec(*pid, *start_ticks, *syscall, path.as_ref(), *dirfd);
            // J4-O end
            if *pid == target.launcher && is_target_image(target.images, path.as_ref()) {
                Fact::TargetExec
            } else {
                Fact::Nothing
            }
        }
        // J4-O begin: the birth identity (slice O)
        TracerEvent::Syscall {
            pid,
            start_ticks,
            tid,
            op,
            syscall,
            args,
            ret,
            ..
        } => {
            audit.record_syscall(*pid, *start_ticks, *tid, *op, syscall, args, *ret);
            Fact::Nothing
        }
        TracerEvent::Exit {
            pid,
            start_ticks,
            status,
            ..
        } => {
            audit.record_exit(*pid, *start_ticks, *status);
            // J4-O end
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
            // J4-O begin
            start_ticks: None,
            syscall: None,
            // J4-O end
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
            start_ticks: None, // J4-O
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
            start_ticks: None, // J4-O
            tid: LAUNCHER,
            op: ClosedOp::Open,
            syscall: "openat",
            args: Args::default(),
            ret: 3,
            monotonic_ns: 1,
        };
        assert_eq!(record(&mut audit, &target, &syscall), Fact::Nothing);
    }

    fn plan_with(pairs: &[(&str, &str)]) -> ObserverPlan {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
            .collect();
        ObserverPlan::with_lookup(|name| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        })
    }

    /// J4 S9: the seams only ever shrink a bound, and every one that is set
    /// is named in the plan, with the bound it applied or `null`.
    #[test]
    fn j4_the_tracer_seams_only_shrink_and_are_always_recorded() {
        let defaults = TracerConfig::default();
        let plan = plan_with(&[]);
        assert_eq!(plan.tracer_config(0), defaults);
        assert_eq!(plan.details()["test_seams"], serde_json::json!({}));
        assert_eq!(plan.details()["in_flight_max"], 16_384);
        assert_eq!(plan.details()["queue_bytes_max"], 4 * 1024 * 1024);
        assert_eq!(plan.details()["kernel_ring_bytes"], Value::Null);

        let plan = plan_with(&[(INFLIGHT_SEAM, "1"), (QUEUE_BYTES_SEAM, "16384")]);
        let config = plan.tracer_config(99);
        assert_eq!(config.inflight_max, 1);
        assert_eq!(config.queue_bytes_max, 16_384);
        assert_eq!(config.epoch_boottime_ns, 99);
        assert_eq!(config.path_snapshot_max, defaults.path_snapshot_max);
        assert_eq!(
            plan.details()["test_seams"],
            serde_json::json!({INFLIGHT_SEAM: 1, QUEUE_BYTES_SEAM: 16_384})
        );

        for ignored in [
            "0",
            "16385",
            "-1",
            "+1",
            " 1",
            "1k",
            "",
            "99999999999999999999999",
        ] {
            let plan = plan_with(&[(INFLIGHT_SEAM, ignored)]);
            assert_eq!(
                plan.tracer_config(0).inflight_max,
                defaults.inflight_max,
                "{ignored:?} must not change the bound"
            );
            assert_eq!(
                plan.details()["test_seams"],
                serde_json::json!({INFLIGHT_SEAM: null}),
                "{ignored:?} is recorded as set and ignored"
            );
        }
        let plan = plan_with(&[(QUEUE_BYTES_SEAM, "4194305")]);
        assert_eq!(
            plan.tracer_config(0).queue_bytes_max,
            defaults.queue_bytes_max
        );
        let plan = plan_with(&[(QUEUE_BYTES_SEAM, "4194304")]);
        assert_eq!(
            plan.details()["test_seams"],
            serde_json::json!({QUEUE_BYTES_SEAM: 4_194_304}),
            "the default itself is a (null) shrink"
        );
        use std::os::unix::ffi::OsStringExt as _;
        let plan = ObserverPlan::with_lookup(|name| {
            (name == INFLIGHT_SEAM).then(|| OsString::from_vec(vec![b'1', 0xff]))
        });
        assert_eq!(plan.tracer_config(0).inflight_max, defaults.inflight_max);
    }

    fn syscall(op: ClosedOp, name: &'static str, path: &[u8], ret: i64) -> TracerEvent {
        TracerEvent::Syscall {
            pid: LAUNCHER,
            tid: LAUNCHER,
            op,
            syscall: name,
            args: Args {
                path: snapshot(path, true),
                ..Args::default()
            },
            ret,
            monotonic_ns: 1,
            start_ticks: None,
        }
    }

    fn gap(reason: GapReason, ops: OpSet) -> TracerEvent {
        TracerEvent::Gap {
            reason,
            ops,
            from_ns: 10,
            to_ns: 20,
            count: Some(1),
        }
    }

    /// J4 O05: "Directory-operation losses degrade fs.write". Every
    /// directory-entry operation of the closed set — and the two mutations
    /// of an existing file — lost to the observer is a loss of `fs.write`
    /// (and of `fs.deny`, which its result could also have been), a fact
    /// strict evidence stops for, and nothing else: `exec` and `net` keep
    /// their exact counts.
    #[test]
    fn j4_o05_every_directory_operation_loss_degrades_fs_write() {
        let images = images();
        let target = Target {
            launcher: LAUNCHER,
            images: &images,
        };
        for op in [
            ClosedOp::Open,
            ClosedOp::Truncate,
            ClosedOp::Rename,
            ClosedOp::Unlink,
            ClosedOp::Rmdir,
            ClosedOp::Mkdir,
            ClosedOp::Mknod,
            ClosedOp::Link,
            ClosedOp::Symlink,
        ] {
            let mut audit = AuditWriter::new("att_x", None, b"/work", b"");
            record(
                &mut audit,
                &target,
                &exec(LAUNCHER, snapshot(b"/usr/bin/target", true)),
            );
            record(
                &mut audit,
                &target,
                &syscall(ClosedOp::Connect, "connect", b"", -111),
            );
            let fact = record(
                &mut audit,
                &target,
                &gap(GapReason::InflightExhausted, OpSet::of(op)),
            );
            assert_eq!(
                fact,
                Fact::CoverageLost(GapReason::InflightExhausted),
                "{op:?}"
            );
            let summary = audit.summary(&TracerSummary::default(), true);
            for class in [CoverageClass::FsWrite, CoverageClass::FsDeny] {
                let entry = &summary.classes[&class];
                assert_eq!(
                    entry.status,
                    crate::records::SourceStatus::Degraded,
                    "{op:?}: {class:?}"
                );
                assert_eq!(entry.observed_count, None, "{op:?}: {class:?}");
                assert_eq!(entry.gaps.len(), 1, "{op:?}: {class:?}");
                assert_eq!(entry.gaps[0].reason, "inflight_exhausted");
            }
            for (class, count) in [(CoverageClass::Exec, 1), (CoverageClass::Net, 1)] {
                let entry = &summary.classes[&class];
                assert_eq!(
                    entry.status,
                    crate::records::SourceStatus::Active,
                    "{op:?}: {class:?}"
                );
                assert_eq!(entry.observed_count, Some(count), "{op:?}: {class:?}");
            }
        }
    }

    /// J4 O03: "Coverage cannot return to fully active for the entire run
    /// after a historical gap." One early loss, then a thousand clean
    /// results of the same class: still degraded, still no count.
    #[test]
    fn j4_o03_a_class_never_returns_to_active_after_an_early_gap() {
        let images = images();
        let target = Target {
            launcher: LAUNCHER,
            images: &images,
        };
        let mut audit = AuditWriter::new("att_x", None, b"/work", b"");
        record(
            &mut audit,
            &target,
            &gap(GapReason::EntryAbandoned, OpSet::of(ClosedOp::Open)),
        );
        for _ in 0..500 {
            record(
                &mut audit,
                &target,
                &syscall(ClosedOp::Mkdir, "mkdir", b"/work/d", 0),
            );
            record(
                &mut audit,
                &target,
                &syscall(ClosedOp::Rmdir, "rmdir", b"/work/d", 0),
            );
        }
        assert_eq!(audit.count(CoverageClass::FsWrite), 1000, "all observed");
        let summary = audit.summary(&TracerSummary::default(), true);
        let entry = &summary.classes[&CoverageClass::FsWrite];
        assert_eq!(entry.status, crate::records::SourceStatus::Degraded);
        assert_eq!(entry.observed_count, None);
        assert_eq!(entry.gaps.len(), 1);
        assert_eq!(entry.gaps[0].end_ns.as_deref(), Some("20"));
        assert_eq!(
            summary.sources.audit,
            crate::records::SourceStatus::Degraded
        );
        let coverage = summary.to_coverage();
        assert_eq!(coverage.fs_write.observed_count, None);
    }
}
