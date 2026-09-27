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
    GapReason, KernelImage, OpSet, PathSnapshot, Tracer, TracerConfig, TracerEvent, TracerSummary,
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
    ///
    /// The queue's figures are the bounds in force, from the same
    /// [`TracerConfig::queue_bounds`] the tracer applies (J4 W3, loss review
    /// finding 4): `queue_bytes_max` bounds everything held for the
    /// consumer, the handoff channel included, and is never below one
    /// fixed-size event; `queue_result_bytes_max` is what results may bring
    /// it to, short of `queue_lifecycle_reserve_bytes`.
    #[must_use]
    pub fn details(&self) -> Value {
        let bounds = self.config.queue_bounds();
        let mut plan = Map::new();
        plan.insert("backend".to_owned(), Value::from("ptrace"));
        plan.insert("kernel_ring_bytes".to_owned(), Value::Null);
        plan.insert(
            "in_flight_max".to_owned(),
            Value::from(self.config.inflight_max),
        );
        plan.insert("queue_bytes_max".to_owned(), Value::from(bounds.bytes_max));
        plan.insert(
            "queue_result_bytes_max".to_owned(),
            Value::from(bounds.result_bytes_max),
        );
        plan.insert(
            "queue_lifecycle_reserve_bytes".to_owned(),
            Value::from(bounds.lifecycle_reserve),
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

/// Whether an exec event establishes that one of `images` — the resolved
/// absolute paths the platform prepared as the target's — actually ran.
///
/// A transition with no pathname is one whose entry the observer did not
/// witness, which is what seizing a process already inside its own `execve`
/// produces; the launcher is seized while blocked in `read(2)`, so its target
/// exec is witnessed and carries a path. A pathname that is not one the
/// launcher would have tried is some other image. Neither confirms the
/// target ran on its own.
///
/// Security 2026-09-27 (audit 3 A1): `kernel_image`, read from
/// `/proc/<tid>/exe` at the exec-event stop, is what the kernel itself
/// loaded and outranks the pathname snapshot, which a thread of the tracee
/// can rewrite for the kernel's copy. When it is present it decides, and it
/// can confirm an image even against a snapshot that was raced into naming
/// something else; when it is absent the snapshot stands as before, the
/// weaker claim §11.3 documents.
///
/// Security 2026-09-27 (audit 4 B3): the kernel bytes are the link's raw
/// form and travel with the image's own inode. A link that matches a
/// candidate only after stripping the kernel's ` (deleted)` annotation is
/// ambiguous — the image may be a legitimately unlinked target (audit 3
/// confirmed those), or a decoy genuinely *named* `tool (deleted)`. The
/// inode separates them: a candidate that still exists and is **not** the
/// image contradicts the match, and identity agreement confirms outright.
#[must_use]
pub fn is_target_image(
    images: &[Vec<u8>],
    path: Option<&PathSnapshot>,
    kernel_image: Option<&KernelImage>,
) -> bool {
    if let Some(kernel) = kernel_image {
        return kernel_confirms(images, kernel);
    }
    path.is_some_and(|path| {
        path.complete
            && images
                .iter()
                .any(|candidate| candidate.as_slice() == path.bytes.as_slice())
    })
}

/// Whether the kernel's own image record confirms one of `images` (audit 4
/// B3). Confirmation needs either the inode's agreement or raw bytes no live
/// file contradicts; the deleted-suffix form only confirms when nothing
/// living under the stripped name is a *different* file.
fn kernel_confirms(images: &[Vec<u8>], kernel: &KernelImage) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let stat_of = |candidate: &[u8]| -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(std::ffi::OsStr::from_bytes(candidate))
            .ok()
            .map(|meta| (meta.dev(), meta.ino()))
    };
    // The inode decides first: a prepared spelling that resolves to the
    // image's own inode is the image, whatever the link's bytes say.
    if let Some(identity) = kernel.identity {
        for candidate in images {
            if stat_of(candidate) == Some(identity) {
                return true;
            }
        }
    }
    // Raw bytes: exact, and not contradicted by a live different file at
    // that spelling (the tracee is stopped, but a sibling thread may have
    // replaced the name's file before the stop).
    for candidate in images {
        if candidate.as_slice() == kernel.path.as_slice()
            && !kernel
                .identity
                .is_some_and(|identity| stat_of(candidate).is_some_and(|found| found != identity))
        {
            return true;
        }
    }
    // The deleted-suffix form: the kernel's annotation for an unlinked
    // image. Audit 3 confirmed the stripped match; audit 4 B3 keeps that
    // for images whose candidates are gone or agree, and refuses it when a
    // live file under the stripped name is a different file than the image
    // — the decoy named `tool (deleted)` beside the real `tool`.
    if kernel.path.ends_with(b" (deleted)") {
        let stripped = &kernel.path[..kernel.path.len() - b" (deleted)".len()];
        for candidate in images {
            if candidate.as_slice() == stripped
                && !kernel.identity.is_some_and(|identity| {
                    stat_of(candidate).is_some_and(|found| found != identity)
                })
            {
                return true;
            }
        }
    }
    false
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
            kernel_image,
            dirfd,
            ..
        } => {
            audit.record_exec(*pid, *start_ticks, *syscall, path.as_ref(), *dirfd);
            // J4-O end
            if *pid != target.launcher {
                return Fact::Nothing;
            }
            // Security 2026-09-27 (audit 3 A1): the kernel's own image, when
            // it was read, decides the confirmation. A snapshot that names a
            // target image while the kernel loaded another is an A-B-A
            // rewrite of the pathname: the confirmation is refused and the
            // contradiction is a gap of the exec class, so no receipt can
            // certify a spoofed confirmation. Audit 4 B3: the decision is
            // [`kernel_confirms`]'s — inode first, raw bytes second, the
            // deleted-suffix form only when no live candidate contradicts.
            if let Some(kernel) = kernel_image.as_ref() {
                if kernel_confirms(target.images, kernel) {
                    return Fact::TargetExec;
                }
                if is_target_image(target.images, path.as_ref(), None) {
                    let now = super::clock::boottime_ns();
                    audit.record_gap(
                        super::tracer::GapReason::ExecImageMismatch,
                        super::tracer::OpSet::of(super::tracer::ClosedOp::Exec),
                        now,
                        now,
                        Some(1),
                    );
                    return Fact::CoverageLost(super::tracer::GapReason::ExecImageMismatch);
                }
                return Fact::Nothing;
            }
            if is_target_image(target.images, path.as_ref(), None) {
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
        exec_with_kernel(pid, path, None)
    }

    fn exec_with_kernel(
        pid: pid_t,
        path: Option<PathSnapshot>,
        kernel_image: Option<KernelImage>,
    ) -> TracerEvent {
        TracerEvent::Exec {
            pid,
            // J4-O begin
            start_ticks: None,
            syscall: None,
            // J4-O end
            path,
            kernel_image,
            dirfd: None,
            monotonic_ns: 1,
        }
    }

    fn kernel_with(path: &[u8], identity: Option<(u64, u64)>) -> Option<KernelImage> {
        Some(KernelImage {
            path: path.to_vec(),
            identity,
        })
    }

    fn kernel(path: &[u8]) -> Option<KernelImage> {
        Some(KernelImage {
            path: path.to_vec(),
            identity: None,
        })
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

    /// Security 2026-09-27 (audit 3 A1): the kernel's own image decides the
    /// confirmation. It confirms a target image even against a snapshot that
    /// was raced into naming another path, it refuses a snapshot that names
    /// the target while the kernel loaded something else — recording an
    /// `exec_image_mismatch` gap so no receipt certifies the spoof — and a
    /// kernel image naming a non-target refuses without any gap.
    #[test]
    fn the_kernel_image_decides_the_exec_confirmation() {
        let images = images();
        let target = Target {
            launcher: LAUNCHER,
            images: &images,
        };
        let mut audit = AuditWriter::new("att_x", None, b"/work", b"");
        // Kernel and snapshot agree on the target.
        assert_eq!(
            record(
                &mut audit,
                &target,
                &exec_with_kernel(
                    LAUNCHER,
                    snapshot(b"/usr/bin/target", true),
                    kernel(b"/usr/bin/target"),
                ),
            ),
            Fact::TargetExec
        );
        // The snapshot was raced onto another name; the kernel still loaded
        // the target: the kernel decides, and confirms.
        assert_eq!(
            record(
                &mut audit,
                &target,
                &exec_with_kernel(
                    LAUNCHER,
                    snapshot(b"/usr/bin/impostor", true),
                    kernel(b"/usr/bin/target"),
                ),
            ),
            Fact::TargetExec
        );
        // The snapshot names the target, the kernel loaded another image:
        // no confirmation, and the contradiction is a gap of the exec class.
        assert_eq!(
            record(
                &mut audit,
                &target,
                &exec_with_kernel(
                    LAUNCHER,
                    snapshot(b"/usr/bin/target", true),
                    kernel(b"/usr/bin/impostor"),
                ),
            ),
            Fact::CoverageLost(GapReason::ExecImageMismatch)
        );
        assert!(audit.has_gaps());
        // A kernel image naming a non-target is an ordinary inner exec.
        let mut quiet = AuditWriter::new("att_y", None, b"/work", b"");
        assert_eq!(
            record(
                &mut quiet,
                &target,
                &exec_with_kernel(LAUNCHER, None, kernel(b"/bin/false")),
            ),
            Fact::Nothing
        );
        assert!(!quiet.has_gaps(), "a non-target image is not a mismatch");
    }

    /// Security 2026-09-27 (audit 4 B3): the raw link plus the image inode
    /// separate an unlinked target (confirm) from a decoy genuinely named
    /// `tool (deleted)` (refuse, and contradict a snapshot that names the
    /// target), and a spelling that resolves to the image's own inode
    /// confirms through a symlink.
    #[test]
    fn the_inode_separates_an_unlinked_target_from_a_deleted_named_decoy() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("tool");
        let decoy_path = dir.path().join("tool (deleted)");
        std::fs::write(&target_path, b"#!/bin/sh\n").unwrap();
        std::fs::write(&decoy_path, b"#!/bin/sh\n").unwrap();
        let symlink_path = dir.path().join("spell");
        std::os::unix::fs::symlink(&target_path, &symlink_path).unwrap();
        let identity_of = |path: &std::path::Path| {
            let meta = std::fs::metadata(path).unwrap();
            (meta.dev(), meta.ino())
        };
        let images = vec![
            target_path.as_os_str().as_bytes().to_vec(),
            symlink_path.as_os_str().as_bytes().to_vec(),
        ];
        let target = Target {
            launcher: LAUNCHER,
            images: &images,
        };
        let raw = |path: &std::path::Path| {
            use std::os::unix::ffi::OsStrExt as _;
            path.as_os_str().as_bytes().to_vec()
        };
        // A spelling that resolves to the image's own inode confirms, even
        // through a symlink and even when the link's bytes name the decoy.
        let mut audit = AuditWriter::new("att_i", None, b"/work", b"");
        assert_eq!(
            record(
                &mut audit,
                &target,
                &exec_with_kernel(
                    LAUNCHER,
                    None,
                    kernel_with(&raw(&decoy_path), Some(identity_of(&target_path))),
                ),
            ),
            Fact::TargetExec
        );
        // An image whose kernel link carries the deleted annotation for the
        // target, with the target's own inode: the audit-3 rule keeps
        // confirming it (the file is gone; only the name matched).
        let deleted_link = [raw(&target_path), b" (deleted)".to_vec()].concat();
        let mut audit = AuditWriter::new("att_u", None, b"/work", b"");
        assert_eq!(
            record(
                &mut audit,
                &target,
                &exec_with_kernel(
                    LAUNCHER,
                    snapshot(&raw(&target_path), true),
                    kernel_with(&deleted_link, Some(identity_of(&target_path))),
                ),
            ),
            Fact::TargetExec
        );
        // The decoy: the kernel link names `tool (deleted)` and the image's
        // inode is the decoy's, while the live `tool` is another file. The
        // stripped match confirms nothing, and a snapshot naming the target
        // is contradicted with an `exec_image_mismatch` gap.
        let decoy_link = raw(&decoy_path);
        let mut audit = AuditWriter::new("att_d", None, b"/work", b"");
        assert_eq!(
            record(
                &mut audit,
                &target,
                &exec_with_kernel(
                    LAUNCHER,
                    snapshot(&raw(&target_path), true),
                    kernel_with(&decoy_link, Some(identity_of(&decoy_path))),
                ),
            ),
            Fact::CoverageLost(GapReason::ExecImageMismatch)
        );
        assert!(audit.has_gaps());
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

    /// J4 W3 (loss review finding 4): the plan records the queue bounds in
    /// force, not the figure they were derived from. The byte budget bounds
    /// everything the observer holds for its consumer, the handoff channel
    /// included, and cannot be smaller than one fixed-size event; results
    /// stop short of the lifecycle reserve, which below about 64 KiB leaves
    /// them room for one fixed-size event and no pathname — and the plan
    /// says so rather than leave it to be inferred.
    #[test]
    fn j4_w3_the_plan_records_the_queue_bounds_in_force() {
        for (value, bytes, results) in [
            (None, 4 * 1024 * 1024, 4 * 1024 * 1024 - 64 * 1024),
            (Some("1048576"), 1024 * 1024, 1024 * 1024 - 64 * 1024),
            (Some("65536"), 65_536, 256),
            (Some("16384"), 16_384, 256),
            (Some("1"), 256, 256),
        ] {
            let plan = match value {
                Some(value) => plan_with(&[(QUEUE_BYTES_SEAM, value)]),
                None => plan_with(&[]),
            };
            let details = plan.details();
            assert_eq!(details["queue_bytes_max"], bytes, "{value:?}: {details:#}");
            assert_eq!(
                details["queue_result_bytes_max"], results,
                "{value:?}: {details:#}"
            );
            assert_eq!(
                details["queue_lifecycle_reserve_bytes"],
                64 * 1024,
                "{value:?}: {details:#}"
            );
            let bounds = plan.tracer_config(0).queue_bounds();
            assert_eq!(details["queue_bytes_max"], bounds.bytes_max);
            assert_eq!(details["queue_result_bytes_max"], bounds.result_bytes_max);
        }
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
