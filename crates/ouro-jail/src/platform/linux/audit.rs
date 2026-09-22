//! Tracer events become audit events.
//!
//! jail-v1 §11.2 fixes which operation a closed-set call is reported as, §11.3
//! fixes what may be said about its pathname arguments, and §11.4 fixes how
//! results are counted. This module is that translation and nothing else: it
//! adds no fact the tracer did not establish, and where the tracer could not
//! establish one it says so with a reason rather than filling it in.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Instant, SystemTime};

use serde_json::{Map, Value};

use crate::observer::{ClassSummary, CoverageClass, CoverageSummary};
use crate::records::{
    CLOSED_SET_LINUX_V1, Completion, Event, EventOutcome, Gap, SourceHealth, SourceStatus,
};
use crate::trace::{Priority, SharedTrace};

use super::tracer::{Args, ClosedOp, GapReason, OpSet, PathSnapshot, TracerSummary};

/// `O_CREAT` on Linux.
const O_CREAT: u64 = 0o100;
/// `AT_FDCWD`.
const AT_FDCWD: i32 = -100;

/// The observer backend name recorded in the receipt.
pub const OBSERVER_BACKEND: &str = "ptrace";

/// What a pathname argument could be said to be (§11.3).
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathClass {
    /// Its relationship to the workspace is established.
    WorkspaceRelative(Vec<u8>),
    /// Its relationship to the scratch directory is established.
    ScratchRelative(Vec<u8>),
    /// Neither, so only a digest of the snapshot is emitted.
    Digest(String, &'static str),
    /// Nothing can be said about it, with a reason.
    Unavailable(&'static str),
}

/// Turns tracer events into audit events and counts what it emitted.
pub struct AuditWriter {
    attempt_id: String,
    trace: Option<SharedTrace>,
    seq: u64,
    started: Instant,
    workspace: Vec<u8>,
    scratch_inside: Vec<u8>,
    counts: BTreeMap<CoverageClass, u64>,
    degraded: BTreeSet<CoverageClass>,
    gaps: Vec<Gap>,
    /// Applied ceilings whose hit became proven true (§11.4, `limits` class).
    limit_hits: u64,
    /// True once a frame could not be written; recorded, never ignored.
    lost_frames: u64,
}

impl AuditWriter {
    /// A writer for one attempt.
    #[must_use]
    pub fn new(
        attempt_id: &str,
        trace: Option<SharedTrace>,
        workspace: &[u8],
        scratch_inside: &[u8],
    ) -> Self {
        AuditWriter {
            attempt_id: attempt_id.to_owned(),
            trace,
            seq: 0,
            started: Instant::now(),
            workspace: workspace.to_vec(),
            scratch_inside: scratch_inside.to_vec(),
            counts: BTreeMap::new(),
            degraded: BTreeSet::new(),
            gaps: Vec::new(),
            limit_hits: 0,
            lost_frames: 0,
        }
    }

    /// Records that an applied ceiling was proven hit (§11.4).
    pub fn record_limit_hit(&mut self) {
        self.limit_hits += 1;
    }

    /// Events emitted for one coverage class so far.
    #[must_use]
    pub fn count(&self, class: CoverageClass) -> u64 {
        self.counts.get(&class).copied().unwrap_or(0)
    }

    fn emit(&mut self, event: &Event) {
        let Some(trace) = self.trace.as_ref() else {
            return;
        };
        let Ok(frame) = serde_json::to_vec(event) else {
            self.lost_frames += 1;
            return;
        };
        let written = match trace.lock() {
            Ok(mut sink) => sink.write_frame(&frame, Priority::Normal),
            Err(_) => {
                self.lost_frames += 1;
                return;
            }
        };
        if written.is_err() {
            self.lost_frames += 1;
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn bump(&mut self, class: CoverageClass) {
        *self.counts.entry(class).or_insert(0) += 1;
    }

    /// One completed closed-set call.
    ///
    /// `ret` is the signed raw return, so a failure is `-errno`.
    pub fn record_syscall(
        &mut self,
        pid: libc::pid_t,
        tid: libc::pid_t,
        op: ClosedOp,
        syscall: &str,
        args: &Args,
        ret: i64,
    ) {
        let errno = if ret < 0 {
            i32::try_from(-ret).ok()
        } else {
            None
        };
        let denied = matches!(errno, Some(libc::EACCES | libc::EPERM));
        let base = base_operation(op, args.flags);
        let operation = if denied { "fs.deny" } else { base };

        let mut fields = Map::new();
        fields.insert("syscall".to_owned(), Value::from(syscall.to_owned()));
        fields.insert("pid".to_owned(), Value::from(i64::from(pid)));
        fields.insert("tid".to_owned(), Value::from(i64::from(tid)));
        // §11.3: the snapshot is the argument as it was in the tracee's memory,
        // never a kernel-resolved path.
        fields.insert(
            "path_basis".to_owned(),
            Value::from("argument_snapshot".to_owned()),
        );
        self.describe_path(&mut fields, "path", args.path.as_ref(), args.dirfd);
        if args.path2.is_some() {
            self.describe_path(&mut fields, "path2", args.path2.as_ref(), args.dirfd2);
        }
        if denied {
            fields.insert(
                "attempted_operation".to_owned(),
                Value::from(base.to_owned()),
            );
        } else if operation == "fs.write" {
            // §11.2: a field named `fs.write` always carries its precise
            // action, so a consumer cannot present it as a content diff. An
            // open says it was opened for mutation; a `truncate` says the
            // length was set, which is a different fact about the same class.
            let action = if op == ClosedOp::Truncate {
                "truncated"
            } else {
                "opened_for_mutation"
            };
            fields.insert("action".to_owned(), Value::from(action.to_owned()));
        }
        if op == ClosedOp::Open && args.flags.is_none() {
            // The create/write distinction could not be made, so the weaker
            // claim is the one that is emitted.
            fields.insert("flags_available".to_owned(), Value::from(false));
        }
        if let Some(address) = args.sockaddr.as_ref() {
            fields.insert(
                "address_family".to_owned(),
                address
                    .family
                    .map_or(Value::Null, |family| Value::from(i64::from(family))),
            );
            fields.insert("address_complete".to_owned(), Value::from(address.complete));
        }

        let outcome = EventOutcome {
            ok: Some(ret >= 0),
            return_value: Some(ret),
            errno: errno.map(|code| super::sys::errno_name(code).to_owned()),
            completion: Completion::SyscallReturn,
            bytes_in: None,
            bytes_out: None,
            duration_ms: None,
        };
        let seq = self.next_seq();
        let event = Event::audit_result(
            &self.attempt_id,
            seq,
            SystemTime::now(),
            self.started.elapsed().as_nanos(),
            operation,
            outcome,
            fields,
        );
        self.emit(&event);
        self.bump(class_of(operation));
    }

    /// A confirmed exec transition (`PTRACE_EVENT_EXEC`).
    ///
    /// `image` is the pathname argument of the `execve` that produced the
    /// transition, when the observer witnessed that entry. `None` means it
    /// did not, and the event says so rather than naming an image it never
    /// saw.
    pub fn record_exec(&mut self, pid: libc::pid_t, image: Option<&PathSnapshot>) {
        let mut fields = Map::new();
        fields.insert("pid".to_owned(), Value::from(i64::from(pid)));
        // §11.3: a descendant's argv is only digested when every byte was
        // captured; this observer captures none, so it says so.
        fields.insert("argv_digest".to_owned(), Value::Null);
        fields.insert(
            "argv_digest_reason".to_owned(),
            Value::from("descendant_argv_not_captured".to_owned()),
        );
        fields.insert(
            "path_basis".to_owned(),
            Value::from("argument_snapshot".to_owned()),
        );
        self.describe_path(&mut fields, "path", image, None);
        let outcome = EventOutcome {
            ok: Some(true),
            return_value: None,
            errno: None,
            completion: Completion::ExecTransition,
            bytes_in: None,
            bytes_out: None,
            duration_ms: None,
        };
        let seq = self.next_seq();
        let event = Event::audit_result(
            &self.attempt_id,
            seq,
            SystemTime::now(),
            self.started.elapsed().as_nanos(),
            "proc.exec",
            outcome,
            fields,
        );
        self.emit(&event);
        self.bump(CoverageClass::Exec);
    }

    /// Final thread-group death of a process that was seen to exec.
    pub fn record_exit(&mut self, pid: libc::pid_t, status: i32) {
        let exited = libc::WIFEXITED(status);
        let signaled = libc::WIFSIGNALED(status);
        let mut fields = Map::new();
        fields.insert("pid".to_owned(), Value::from(i64::from(pid)));
        fields.insert(
            "termination".to_owned(),
            Value::from(if signaled {
                "signaled".to_owned()
            } else if exited {
                "exited".to_owned()
            } else {
                "unknown".to_owned()
            }),
        );
        fields.insert(
            "exit_code".to_owned(),
            if exited {
                Value::from(i64::from(libc::WEXITSTATUS(status)))
            } else {
                Value::Null
            },
        );
        fields.insert(
            "signal".to_owned(),
            if signaled {
                Value::from(i64::from(libc::WTERMSIG(status)))
            } else {
                Value::Null
            },
        );
        let outcome = EventOutcome {
            ok: Some(exited && libc::WEXITSTATUS(status) == 0),
            return_value: Some(i64::from(status)),
            errno: None,
            completion: Completion::ProcessExit,
            bytes_in: None,
            bytes_out: None,
            duration_ms: None,
        };
        let seq = self.next_seq();
        let event = Event::audit_result(
            &self.attempt_id,
            seq,
            SystemTime::now(),
            self.started.elapsed().as_nanos(),
            "proc.exit",
            outcome,
            fields,
        );
        self.emit(&event);
        self.bump(CoverageClass::Exec);
    }

    /// A hole in coverage. The affected classes are named explicitly (§11.4).
    ///
    /// `ops` is the observer's own account of which closed-set operations the
    /// hole swallowed. An empty set means the loss was bookkeeping rather than
    /// a result, and degrades nothing.
    pub fn record_gap(
        &mut self,
        reason: GapReason,
        ops: OpSet,
        from_ns: u64,
        to_ns: u64,
        count: Option<u64>,
    ) {
        let classes = classes_for(ops);
        for class in &classes {
            self.degraded.insert(*class);
        }
        let gap = Gap {
            classes: classes
                .iter()
                .map(|class| class.as_str().to_owned())
                .collect(),
            source: "audit".to_owned(),
            start_ns: from_ns.to_string(),
            end_ns: Some(to_ns.to_string()),
            reason: reason.as_str().to_owned(),
            lost_count: count,
        };
        let seq = self.next_seq();
        let event = Event::coverage_gap_note(
            &self.attempt_id,
            seq,
            SystemTime::now(),
            self.started.elapsed().as_nanos(),
            &gap,
        );
        // A gap note may use the reserve: it is the record of what was lost.
        if let Some(trace) = self.trace.as_ref()
            && let Ok(frame) = serde_json::to_vec(&event)
        {
            let written = match trace.lock() {
                Ok(mut sink) => sink.write_frame(&frame, Priority::Reserve),
                Err(_) => Ok(()),
            };
            if written.is_err() {
                self.lost_frames += 1;
            }
        }
        self.gaps.push(gap);
    }

    /// Whether any gap has been recorded.
    #[must_use]
    pub fn has_gaps(&self) -> bool {
        !self.gaps.is_empty()
    }

    /// The gaps recorded so far.
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    /// The coverage summary for an attempt this writer observed.
    #[must_use]
    pub fn summary(&self, tracer: &TracerSummary, attached: bool) -> CoverageSummary {
        let audit_status = if self.degraded.is_empty() && !tracer.thread_panicked {
            SourceStatus::Active
        } else {
            SourceStatus::Degraded
        };
        let mut classes = BTreeMap::new();
        for class in [
            CoverageClass::Exec,
            CoverageClass::FsWrite,
            CoverageClass::FsDeny,
            CoverageClass::Net,
        ] {
            let status = if self.degraded.contains(&class) || tracer.thread_panicked {
                SourceStatus::Degraded
            } else {
                SourceStatus::Active
            };
            classes.insert(
                class,
                ClassSummary {
                    status,
                    observed_count: Some(self.count(class)),
                    gaps: self
                        .gaps
                        .iter()
                        .filter(|gap| gap.classes.iter().any(|name| name == class.as_str()))
                        .cloned()
                        .collect(),
                },
            );
        }
        classes.insert(CoverageClass::ProxyNet, ClassSummary::unsupported());
        classes.insert(CoverageClass::Limits, self.limits_class());
        CoverageSummary {
            backend: Some(OBSERVER_BACKEND.to_owned()),
            set: Some(CLOSED_SET_LINUX_V1.to_owned()),
            attached,
            sources: SourceHealth {
                wrapper: SourceStatus::Active,
                audit: audit_status,
                proxy: SourceStatus::Unsupported,
            },
            gaps: self.gaps.clone(),
            classes,
        }
    }

    /// The `limits` class, which is a wrapper fact and exists with observation
    /// off as well (§11.4).
    #[must_use]
    pub fn limits_class(&self) -> ClassSummary {
        ClassSummary {
            status: SourceStatus::Active,
            observed_count: Some(self.limit_hits),
            gaps: Vec::new(),
        }
    }

    fn describe_path(
        &self,
        fields: &mut Map<String, Value>,
        key: &str,
        snapshot: Option<&PathSnapshot>,
        dirfd: Option<i32>,
    ) {
        let complete = snapshot.is_some_and(|snap| snap.complete);
        fields.insert(format!("{key}_complete"), Value::from(complete));
        if let Some(fd) = dirfd
            && fd != AT_FDCWD
        {
            fields.insert(format!("{key}_dirfd"), Value::from(i64::from(fd)));
        }
        match self.classify(snapshot, dirfd) {
            PathClass::WorkspaceRelative(bytes) => {
                fields.insert(format!("{key}_kind"), Value::from("workspace_relative"));
                fields.insert(key.to_owned(), native_value(&bytes));
            }
            PathClass::ScratchRelative(bytes) => {
                fields.insert(format!("{key}_kind"), Value::from("scratch_relative"));
                fields.insert(key.to_owned(), native_value(&bytes));
            }
            PathClass::Digest(digest, reason) => {
                fields.insert(format!("{key}_kind"), Value::from("digest"));
                fields.insert(format!("{key}_digest"), Value::from(digest));
                fields.insert(format!("{key}_reason"), Value::from(reason));
            }
            PathClass::Unavailable(reason) => {
                fields.insert(format!("{key}_kind"), Value::from("unavailable"));
                fields.insert(format!("{key}_reason"), Value::from(reason));
            }
        }
    }

    fn classify(&self, snapshot: Option<&PathSnapshot>, dirfd: Option<i32>) -> PathClass {
        let Some(snapshot) = snapshot else {
            return PathClass::Unavailable("argument_not_read");
        };
        if !snapshot.complete {
            // A prefix is not the path. §11.3 forbids a stronger assertion.
            return PathClass::Unavailable("path_truncated");
        }
        let bytes = snapshot.bytes.as_slice();
        if bytes.is_empty() {
            return PathClass::Unavailable("empty_path");
        }
        if bytes[0] != b'/' {
            // §11.3: a relative path is never appended to a host cwd.
            return match dirfd {
                Some(fd) if fd != AT_FDCWD => PathClass::Unavailable("relative_to_dirfd"),
                _ => PathClass::Unavailable("relative_to_unobserved_cwd"),
            };
        }
        if let Some(rest) = strip_root(bytes, &self.workspace) {
            return PathClass::WorkspaceRelative(rest);
        }
        if let Some(rest) = strip_root(bytes, &self.scratch_inside) {
            return PathClass::ScratchRelative(rest);
        }
        PathClass::Digest(
            crate::canonical::sha256_prefixed(bytes),
            "outside_known_roots",
        )
    }
}

/// A native value for the event: a string when the bytes are UTF-8, the
/// base64 object of the native-string codec otherwise.
fn native_value(bytes: &[u8]) -> Value {
    crate::records::NativeString::from_bytes(bytes.to_vec())
        .ok()
        .and_then(|native| serde_json::to_value(native).ok())
        .unwrap_or(Value::Null)
}

/// The suffix of `path` below `root`, component-wise so that `/w/ab` is not
/// inside `/w/a`. The root itself yields an empty suffix.
fn strip_root(path: &[u8], root: &[u8]) -> Option<Vec<u8>> {
    let root = root.strip_suffix(b"/").unwrap_or(root);
    if root.is_empty() {
        return None;
    }
    if path == root {
        return Some(Vec::new());
    }
    let rest = path.strip_prefix(root)?;
    if rest.first() == Some(&b'/') {
        Some(rest[1..].to_vec())
    } else {
        None
    }
}

/// The operation a successful closed-set call is reported as (§11.2).
fn base_operation(op: ClosedOp, flags: Option<u64>) -> &'static str {
    match op {
        ClosedOp::Exec => "proc.exec",
        // An O_CREAT open emits one `fs.create`, otherwise a mutation open
        // emits one `fs.write`; never both. With the flags undecodable the
        // weaker of the two claims is the one that is made.
        ClosedOp::Open => {
            if flags.is_some_and(|value| value & O_CREAT != 0) {
                "fs.create"
            } else {
                "fs.write"
            }
        }
        // §11.2 revision 8: a truncation by path is a mutation of an
        // existing file, so it is `fs.write` with its own action. `ftruncate`
        // names a descriptor rather than a path and stays outside the set.
        ClosedOp::Truncate => "fs.write",
        ClosedOp::Rename => "fs.rename",
        ClosedOp::Unlink | ClosedOp::Rmdir => "fs.unlink",
        ClosedOp::Mkdir | ClosedOp::Mknod | ClosedOp::Link | ClosedOp::Symlink => "fs.create",
        ClosedOp::Connect => "net.connect",
    }
}

/// The coverage class an emitted operation is counted under (§11.4).
fn class_of(operation: &str) -> CoverageClass {
    match operation {
        "proc.exec" | "proc.exit" => CoverageClass::Exec,
        "fs.deny" => CoverageClass::FsDeny,
        "net.connect" => CoverageClass::Net,
        _ => CoverageClass::FsWrite,
    }
}

/// The classes a gap affects, from the operations it swallowed.
///
/// §11.4: "A gap names the affected classes explicitly". The observer knows
/// which operations were lost, so the consumer degrades exactly the classes
/// those operations are counted under. A lost result could also have been a
/// denial, which is a different class from the operation's own, so both are
/// named; nothing else is.
fn classes_for(ops: OpSet) -> Vec<CoverageClass> {
    let mut classes: BTreeSet<CoverageClass> = BTreeSet::new();
    for op in ops.iter() {
        classes.insert(class_of(base_operation(op, None)));
        classes.insert(CoverageClass::FsDeny);
    }
    classes.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer() -> AuditWriter {
        AuditWriter::new("att_x", None, b"/work/space", b"/tmp")
    }

    fn snap(path: &str) -> PathSnapshot {
        PathSnapshot {
            bytes: path.as_bytes().to_vec(),
            complete: true,
        }
    }

    #[test]
    fn a_create_open_is_fs_create_and_a_mutating_open_is_fs_write() {
        assert_eq!(
            base_operation(ClosedOp::Open, Some(O_CREAT | 1)),
            "fs.create"
        );
        assert_eq!(base_operation(ClosedOp::Open, Some(1)), "fs.write");
        assert_eq!(base_operation(ClosedOp::Open, None), "fs.write");
    }

    #[test]
    fn every_directory_entry_creation_is_fs_create() {
        for op in [ClosedOp::Mkdir, ClosedOp::Link, ClosedOp::Symlink] {
            assert_eq!(base_operation(op, None), "fs.create");
        }
        for op in [ClosedOp::Unlink, ClosedOp::Rmdir] {
            assert_eq!(base_operation(op, None), "fs.unlink");
        }
        assert_eq!(base_operation(ClosedOp::Rename, None), "fs.rename");
        assert_eq!(base_operation(ClosedOp::Connect, None), "net.connect");
    }

    #[test]
    fn a_denied_connect_counts_under_fs_deny_only() {
        assert_eq!(class_of("fs.deny"), CoverageClass::FsDeny);
        assert_eq!(class_of("net.connect"), CoverageClass::Net);
        assert_eq!(class_of("fs.create"), CoverageClass::FsWrite);
        assert_eq!(class_of("proc.exit"), CoverageClass::Exec);
    }

    #[test]
    fn a_workspace_path_is_reported_relative_to_the_workspace() {
        let writer = writer();
        assert_eq!(
            writer.classify(Some(&snap("/work/space/src/lib.rs")), Some(AT_FDCWD)),
            PathClass::WorkspaceRelative(b"src/lib.rs".to_vec())
        );
        assert_eq!(
            writer.classify(Some(&snap("/work/space")), None),
            PathClass::WorkspaceRelative(Vec::new())
        );
        assert_eq!(
            writer.classify(Some(&snap("/tmp/scratch.txt")), None),
            PathClass::ScratchRelative(b"scratch.txt".to_vec())
        );
    }

    #[test]
    fn a_sibling_of_the_workspace_is_not_inside_it() {
        let writer = writer();
        // `/work/spacex` shares a byte prefix with `/work/space` and is not
        // inside it.
        match writer.classify(Some(&snap("/work/spacex/f")), None) {
            PathClass::Digest(digest, reason) => {
                assert!(digest.starts_with("sha256:"));
                assert_eq!(reason, "outside_known_roots");
            }
            other => panic!("expected a digest, got {other:?}"),
        }
    }

    #[test]
    fn a_relative_path_is_never_joined_to_a_guessed_cwd() {
        let writer = writer();
        assert_eq!(
            writer.classify(Some(&snap("relative/file")), Some(AT_FDCWD)),
            PathClass::Unavailable("relative_to_unobserved_cwd")
        );
        assert_eq!(
            writer.classify(Some(&snap("relative/file")), Some(7)),
            PathClass::Unavailable("relative_to_dirfd")
        );
    }

    #[test]
    fn a_truncated_snapshot_makes_no_path_claim() {
        let writer = writer();
        let truncated = PathSnapshot {
            bytes: b"/work/space/very-long".to_vec(),
            complete: false,
        };
        assert_eq!(
            writer.classify(Some(&truncated), None),
            PathClass::Unavailable("path_truncated")
        );
        assert_eq!(
            writer.classify(None, None),
            PathClass::Unavailable("argument_not_read")
        );
    }

    #[test]
    fn a_gap_degrades_only_the_classes_its_own_operations_belong_to() {
        // A lost exec result is an exec-class hole; it says nothing about
        // whether a filesystem or network result was also lost.
        assert_eq!(
            classes_for(OpSet::of(ClosedOp::Exec)),
            vec![CoverageClass::Exec, CoverageClass::FsDeny]
        );
        assert_eq!(
            classes_for(OpSet::of(ClosedOp::Connect)),
            vec![CoverageClass::FsDeny, CoverageClass::Net]
        );
        assert_eq!(
            classes_for(OpSet::of(ClosedOp::Truncate)),
            vec![CoverageClass::FsWrite, CoverageClass::FsDeny]
        );
        // A gap that swallowed no result degrades nothing.
        assert!(classes_for(OpSet::EMPTY).is_empty());
    }

    #[test]
    fn the_two_operations_revision_eight_added_are_classified() {
        assert_eq!(base_operation(ClosedOp::Mknod, None), "fs.create");
        assert_eq!(base_operation(ClosedOp::Truncate, None), "fs.write");
        assert_eq!(
            base_operation(ClosedOp::Truncate, None),
            base_operation(ClosedOp::Open, Some(1)),
            "both are mutations of an existing file; their actions differ"
        );
    }

    #[test]
    fn a_gap_degrades_its_classes_and_nulls_their_counts() {
        let mut writer = writer();
        writer.record_syscall(
            10,
            10,
            ClosedOp::Open,
            "openat",
            &Args {
                path: Some(snap("/work/space/a")),
                flags: Some(O_CREAT),
                ..Args::default()
            },
            3,
        );
        assert_eq!(writer.count(CoverageClass::FsWrite), 1);
        writer.record_gap(
            GapReason::QueueFull,
            OpSet::of(ClosedOp::Open),
            1,
            2,
            Some(4),
        );
        let summary = writer.summary(&TracerSummary::default(), true);
        let coverage = summary.to_coverage();
        assert_eq!(coverage.fs_write.status, SourceStatus::Degraded);
        assert_eq!(coverage.fs_write.observed_count, None);
        assert_eq!(coverage.fs_write.gaps.len(), 1);
        assert_eq!(coverage.fs_write.gaps[0].lost_count, Some(4));
        // The classes that gap did not touch keep their counts.
        assert_eq!(coverage.exec.status, SourceStatus::Active);
        assert_eq!(coverage.net.status, SourceStatus::Active);
    }

    #[test]
    fn counts_follow_the_class_assignment() {
        let mut writer = writer();
        let args = Args {
            path: Some(snap("/work/space/a")),
            flags: Some(O_CREAT),
            ..Args::default()
        };
        writer.record_syscall(10, 10, ClosedOp::Open, "openat", &args, 3);
        writer.record_syscall(
            10,
            10,
            ClosedOp::Open,
            "openat",
            &args,
            -i64::from(libc::EROFS),
        );
        writer.record_syscall(
            10,
            10,
            ClosedOp::Open,
            "openat",
            &args,
            -i64::from(libc::EACCES),
        );
        writer.record_exec(10, Some(&snap("/work/space/tool")));
        writer.record_exit(10, 0);
        assert_eq!(
            writer.count(CoverageClass::FsWrite),
            2,
            "EROFS stays an fs event"
        );
        assert_eq!(writer.count(CoverageClass::FsDeny), 1);
        assert_eq!(writer.count(CoverageClass::Exec), 2);
    }

    #[test]
    fn a_truncation_by_path_says_which_mutation_it_was() {
        let mut writer = writer();
        writer.record_syscall(
            10,
            10,
            ClosedOp::Truncate,
            "truncate",
            &Args {
                path: Some(snap("/work/space/a")),
                ..Args::default()
            },
            0,
        );
        assert_eq!(writer.count(CoverageClass::FsWrite), 1);
    }

    #[test]
    fn observation_off_still_reports_the_wrapper_limits_class() {
        let mut writer = writer();
        writer.record_limit_hit();
        let class = writer.limits_class();
        assert_eq!(class.status, SourceStatus::Active);
        assert_eq!(class.observed_count, Some(1));
    }
}
