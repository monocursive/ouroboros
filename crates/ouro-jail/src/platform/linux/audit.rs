//! Tracer events become audit events.
//!
//! jail-v1 §11.2 fixes which operation a closed-set call is reported as, §11.3
//! fixes what may be said about its pathname arguments, and §11.4 fixes how
//! results are counted. This module is that translation and nothing else: it
//! adds no fact the tracer did not establish, and where the tracer could not
//! establish one it says so with a reason rather than filling it in.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use serde_json::{Map, Value};

use crate::observer::{ClassSummary, CoverageClass, CoverageSummary};
use crate::records::{
    CLOSED_SET_LINUX_V1, Completion, Event, EventOutcome, Gap, SourceHealth, SourceStatus,
};
use crate::trace::{Priority, SharedTrace};

use super::tracer::{Args, ClosedOp, GapReason, OpSet, PathSnapshot, TracerSummary};

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

// J3-agent begin: one mediated connect, as the audit writer needs it
/// One `connect` whose mediated response the kernel accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediatedConnect {
    /// The connecting thread.
    pub tid: libc::pid_t,
    /// Its thread group, when `/proc` said.
    pub tgid: Option<libc::pid_t>,
    /// That thread group's birth (field 22 of `/proc/<tgid>/stat`), read in
    /// the same window as `tgid`: with it, the process's name (§11.3).
    pub tgid_start: Option<u64>,
    /// The address family the child named.
    pub family: Option<u16>,
    /// Whether the whole address was read.
    pub address_complete: bool,
    /// The value accepted as the child's `connect` response: 0 or `-errno`.
    pub ret: i64,
    /// The mediator's safe reason code.
    pub reason: &'static str,
}
// J3-agent end

/// Turns tracer events into audit events and counts what it emitted.
pub struct AuditWriter {
    attempt_id: String,
    trace: Option<SharedTrace>,
    seq: u64,
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

    /// Records why a requested ceiling stays unapplied: the explanatory
    /// wrapper note §6.4 asks for when a preferred controller is missing.
    pub fn record_limit_unapplied(&mut self, key: &str, reason: &str) {
        let event = Event::limit_note(
            &self.attempt_id,
            0, // assigned by the shared wrapper stream writer
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            key,
            reason,
        );
        if let Some(trace) = self.trace.as_ref() {
            let written = match trace.lock() {
                Ok(mut sink) => sink.write_event(&event, Priority::Normal),
                Err(_) => Ok(()),
            };
            if written.is_err() {
                self.lost_frames += 1;
            }
        }
    }

    /// Events emitted for one coverage class so far.
    #[must_use]
    pub fn count(&self, class: CoverageClass) -> u64 {
        self.counts.get(&class).copied().unwrap_or(0)
    }

    /// Write one event frame; a frame that never reached a trace degrades the
    /// class it would have been counted under, because §13.2 makes the count
    /// a claim about delivered evidence ("every observation count is null
    /// when ... incomplete") and §11.4 makes an undelivered result a loss.
    fn emit(&mut self, event: &Event, class: CoverageClass) -> bool {
        let Some(trace) = self.trace.as_ref() else {
            // No trace configured (observation off): nothing is lost that
            // anyone claimed to collect.
            return true;
        };
        let written = match trace.lock() {
            Ok(mut sink) => sink.write_event(event, Priority::Normal),
            Err(_) => {
                self.lost_frames += 1;
                self.degraded.insert(class);
                return false;
            }
        };
        if written.is_err() {
            self.lost_frames += 1;
            self.degraded.insert(class);
            false
        } else {
            true
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
    /// `pid_start_ticks` is the birth of process `pid` (§11.3): with the
    /// receipt's `boot_id` it names the process where `pid` alone would
    /// name whichever process holds that number now.
    #[allow(clippy::too_many_arguments)]
    pub fn record_syscall(
        &mut self,
        pid: libc::pid_t,
        pid_start_ticks: Option<u64>,
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
        let base = op.audit_operation(args.flags);
        let operation = if denied { "fs.deny" } else { base };

        let mut fields = Map::new();
        fields.insert("syscall".to_owned(), Value::from(syscall.to_owned()));
        fields.insert("pid".to_owned(), Value::from(i64::from(pid)));
        insert_birth(&mut fields, pid_start_ticks);
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
            crate::platform::elapsed_since_start_ns(),
            operation,
            outcome,
            fields,
        );
        // An undelivered frame is not an observed result (§13.2): it
        // degrades the class and adds nothing to its count.
        if self.emit(&event, class_of(operation)) {
            self.bump(class_of(operation));
        }
    }

    // J3-agent begin: mediated connects are audit-source results (§10, §11.4)
    /// One `connect` the unix-peer mediator decided (jail-v1 §10).
    ///
    /// A mediated connect is not a ptrace stop — `SECCOMP_RET_USER_NOTIF`
    /// outranks the observer's `SECCOMP_RET_TRACE` — so for `agent` the
    /// mediator is the witness of every native `connect` in the attempt's
    /// tree, and this is the audit source's `net.connect` result for it, with
    /// the return value the kernel accepted for the child's `connect`. It follows the
    /// closed set's classification exactly: an `EACCES`/`EPERM` result is one
    /// `fs.deny` with `attempted_operation = net.connect`, counted under
    /// `fs.deny` only. `fields.observation` says which mechanism saw it; the
    /// mediator's safe reason code is recorded as `mediator_reason`, and the
    /// audit `decision` stays null (§13.1). Proxy-source facts are never
    /// merged into it: the proxy emits its own `net.connect` results.
    pub fn record_mediated_connect(&mut self, record: &MediatedConnect) {
        let errno = (record.ret < 0)
            .then(|| i32::try_from(-record.ret).ok())
            .flatten();
        let denied = matches!(errno, Some(libc::EACCES | libc::EPERM));
        let operation = if denied { "fs.deny" } else { "net.connect" };
        let mut fields = Map::new();
        fields.insert("syscall".to_owned(), Value::from("connect"));
        fields.insert(
            "pid".to_owned(),
            record
                .tgid
                .map_or(Value::Null, |pid| Value::from(i64::from(pid))),
        );
        insert_birth(&mut fields, record.tgid.and(record.tgid_start));
        fields.insert("tid".to_owned(), Value::from(i64::from(record.tid)));
        fields.insert(
            "path_basis".to_owned(),
            Value::from("argument_snapshot".to_owned()),
        );
        self.describe_path(&mut fields, "path", None, None);
        fields.insert(
            "address_family".to_owned(),
            record
                .family
                .map_or(Value::Null, |family| Value::from(i64::from(family))),
        );
        fields.insert(
            "address_complete".to_owned(),
            Value::from(record.address_complete),
        );
        fields.insert(
            "observation".to_owned(),
            Value::from("seccomp_user_notification"),
        );
        fields.insert("mediator_reason".to_owned(), Value::from(record.reason));
        if denied {
            fields.insert(
                "attempted_operation".to_owned(),
                Value::from("net.connect".to_owned()),
            );
        }
        let outcome = EventOutcome {
            ok: Some(record.ret >= 0),
            return_value: Some(record.ret),
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
            crate::platform::elapsed_since_start_ns(),
            operation,
            outcome,
            fields,
        );
        if self.emit(&event, class_of(operation)) {
            self.bump(class_of(operation));
        }
    }

    /// Mediation records that never reached this writer (the bounded queue
    /// between the mediator and the supervision loop overflowed): a hole in
    /// `net` and `fs.deny`, with a known count.
    pub fn record_mediation_loss(&mut self, lost: u64, from_ns: u64, to_ns: u64) {
        if lost == 0 {
            return;
        }
        let mut ops = OpSet::EMPTY;
        ops.insert(ClosedOp::Connect);
        self.record_gap(GapReason::QueueFull, ops, from_ns, to_ns, Some(lost));
    }

    /// A mediated result that was decided but whose seccomp response the
    /// kernel did not accept. No child syscall return is established, so this
    /// is a gap in both possible connect-result classes, not an audit result.
    pub fn record_mediation_response_loss(&mut self, at_ns: u64) {
        let mut ops = OpSet::EMPTY;
        ops.insert(ClosedOp::Connect);
        self.record_gap(
            GapReason::MediationResponseUndelivered,
            ops,
            at_ns,
            at_ns,
            Some(1),
        );
    }
    // J3-agent end

    /// A confirmed exec transition (`PTRACE_EVENT_EXEC`).
    ///
    /// `image` is the pathname argument of the `execve` that produced the
    /// transition, when the observer witnessed that entry. `None` means it
    /// did not, and the event says so rather than naming an image it never
    /// saw. `syscall` names that entry's call (`execve` or `execveat`), so
    /// the two successful variants stay distinguishable (O01); it is absent
    /// when the entry was not witnessed.
    pub fn record_exec(
        &mut self,
        pid: libc::pid_t,
        pid_start_ticks: Option<u64>,
        syscall: Option<&str>,
        image: Option<&PathSnapshot>,
        dirfd: Option<i32>,
    ) {
        let mut fields = Map::new();
        if let Some(syscall) = syscall {
            fields.insert("syscall".to_owned(), Value::from(syscall.to_owned()));
        }
        fields.insert("pid".to_owned(), Value::from(i64::from(pid)));
        insert_birth(&mut fields, pid_start_ticks);
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
        self.describe_path(&mut fields, "path", image, dirfd);
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
            crate::platform::elapsed_since_start_ns(),
            "proc.exec",
            outcome,
            fields,
        );
        if self.emit(&event, CoverageClass::Exec) {
            self.bump(CoverageClass::Exec);
        }
    }

    /// Final thread-group death of a process that was seen to exec.
    pub fn record_exit(&mut self, pid: libc::pid_t, pid_start_ticks: Option<u64>, status: i32) {
        let exited = libc::WIFEXITED(status);
        let signaled = libc::WIFSIGNALED(status);
        let mut fields = Map::new();
        fields.insert("pid".to_owned(), Value::from(i64::from(pid)));
        insert_birth(&mut fields, pid_start_ticks);
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
            crate::platform::elapsed_since_start_ns(),
            "proc.exit",
            outcome,
            fields,
        );
        if self.emit(&event, CoverageClass::Exec) {
            self.bump(CoverageClass::Exec);
        }
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
            // A hole whose cause is never observed to end — a child's own
            // notification listener — has no end the observer can state:
            // `null`, not the moment it was noticed (§13.1 lets it be).
            end_ns: (!reason.is_open_ended()).then(|| to_ns.to_string()),
            reason: reason.as_str().to_owned(),
            lost_count: count,
        };
        // Keep bounded interval summaries; repeated losses extend an interval.
        if let Some(existing) = self
            .gaps
            .iter_mut()
            .find(|existing| existing.reason == gap.reason && existing.classes == gap.classes)
        {
            extend_gap_interval(existing, from_ns, to_ns);
            existing.lost_count = existing
                .lost_count
                .zip(gap.lost_count)
                .and_then(|(a, b)| a.checked_add(b));
            return;
        }
        if self.gaps.len() >= 64 {
            let existing = self.gaps.last_mut().expect("nonempty bounded gaps");
            existing.reason = "coalesced_losses".to_owned();
            extend_gap_interval(existing, from_ns, to_ns);
            existing.lost_count = None;
            existing.classes.extend(gap.classes);
            existing.classes.sort();
            existing.classes.dedup();
            return;
        }
        let event = Event::coverage_gap_note(
            &self.attempt_id,
            0, // assigned by the shared wrapper stream writer
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            &gap,
        );
        // A gap note may use the reserve: it is the record of what was lost.
        if let Some(trace) = self.trace.as_ref() {
            let written = match trace.lock() {
                Ok(mut sink) => sink.write_event(&event, Priority::Reserve),
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
                    // §11.4: "Unsupported and degraded counts are null."
                    observed_count: if status == SourceStatus::Degraded {
                        None
                    } else {
                        Some(self.count(class))
                    },
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
        // The nested {kind, value} shape is the documented contract
        // (examples/event-open.json): a consumer reads fields.path.kind and
        // gets the classification, not a flat key it has to know about.
        let complete = snapshot.is_some_and(|snap| snap.complete);
        fields.insert(format!("{key}_complete"), Value::from(complete));
        if let Some(fd) = dirfd
            && fd != AT_FDCWD
        {
            fields.insert(format!("{key}_dirfd"), Value::from(i64::from(fd)));
        }
        let path = match self.classify(snapshot, dirfd) {
            PathClass::WorkspaceRelative(bytes) => serde_json::json!({
                "kind": "workspace_relative",
                "value": native_value(&bytes),
            }),
            PathClass::ScratchRelative(bytes) => serde_json::json!({
                "kind": "scratch_relative",
                "value": native_value(&bytes),
            }),
            PathClass::Digest(digest, reason) => serde_json::json!({
                "kind": "digest",
                "digest": digest,
                "reason": reason,
            }),
            PathClass::Unavailable(reason) => serde_json::json!({
                "kind": "unavailable",
                "reason": reason,
            }),
        };
        fields.insert(key.to_owned(), path);
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
        if bytes
            .split(|b| *b == b'/')
            .any(|part| part == b".." || part == b".")
        {
            return PathClass::Digest(
                crate::canonical::sha256_prefixed(bytes),
                "ambiguous_path_components",
            );
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

/// `fields.pid_start_ticks`: the birth of the process `fields.pid` names —
/// the start time of its thread-group leader, field 22 of `/proc/<pid>/stat`
/// in clock ticks since boot, the same reading the receipt's
/// `linux_boot_start` identity uses. `null` when `/proc` would not say.
fn insert_birth(fields: &mut Map<String, Value>, start_ticks: Option<u64>) {
    fields.insert(
        "pid_start_ticks".to_owned(),
        start_ticks.map_or(Value::Null, Value::from),
    );
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

/// The operation a successful closed-set call is reported as (§11.2): the
/// observer's own mapping, which the published table uses too.
fn base_operation(op: ClosedOp, flags: Option<u64>) -> &'static str {
    op.audit_operation(flags)
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

fn extend_gap_interval(gap: &mut Gap, from: u64, to: u64) {
    gap.start_ns = gap
        .start_ns
        .parse::<u64>()
        .unwrap_or(from)
        .min(from)
        .to_string();
    // An open interval stays open: merging a later loss into it cannot give
    // it an end.
    if let Some(end) = gap.end_ns.as_deref() {
        gap.end_ns = Some(end.parse::<u64>().unwrap_or(to).max(to).to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `O_CREAT` on Linux.
    const O_CREAT: u64 = 0o100;

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
    fn an_undelivered_response_is_a_gap_without_a_syscall_result() {
        let mut writer = writer();
        writer.record_mediation_response_loss(17);
        assert_eq!(writer.count(CoverageClass::Net), 0);
        assert_eq!(writer.count(CoverageClass::FsDeny), 0);
        assert_eq!(writer.gaps().len(), 1);
        assert_eq!(writer.gaps()[0].reason, "mediation_response_undelivered");
        assert_eq!(writer.gaps()[0].lost_count, Some(1));
        let summary = writer.summary(&TracerSummary::default(), true);
        for class in [CoverageClass::Net, CoverageClass::FsDeny] {
            assert_eq!(summary.classes[&class].status, SourceStatus::Degraded);
            assert_eq!(summary.classes[&class].observed_count, None);
        }
        for class in [CoverageClass::Exec, CoverageClass::FsWrite] {
            assert_eq!(summary.classes[&class].status, SourceStatus::Active);
        }
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
    fn dot_components_never_reveal_a_raw_outside_suffix() {
        for path in [
            "/work/space/../private/token",
            "/tmp/../private/token",
            "/work/space/link/../../token",
        ] {
            assert!(matches!(
                writer().classify(Some(&snap(path)), None),
                PathClass::Digest(_, _)
            ));
        }
    }

    #[test]
    fn repeated_unknown_result_loss_is_bounded_and_degrades_every_audit_class() {
        let mut writer = writer();
        for time in 1..10_001 {
            writer.record_gap(
                GapReason::UnmatchedExit,
                OpSet::ALL,
                time - 1,
                time,
                Some(1),
            );
        }
        assert_eq!(writer.gaps().len(), 1);
        assert_eq!(writer.gaps()[0].lost_count, Some(10_000));
        assert_eq!(writer.gaps()[0].end_ns.as_deref(), Some("10000"));
        let summary = writer.summary(&TracerSummary::default(), true);
        for class in [
            CoverageClass::Exec,
            CoverageClass::FsWrite,
            CoverageClass::FsDeny,
            CoverageClass::Net,
        ] {
            assert_eq!(summary.classes[&class].status, SourceStatus::Degraded);
            assert_eq!(summary.classes[&class].observed_count, None);
        }
    }

    #[test]
    fn gap_notes_share_wrapper_sequences_without_consuming_audit_sequences() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = crate::trace::shared(crate::trace::FileSink::new(file.reopen().unwrap()));
        let mut writer = AuditWriter::new("att_test", Some(trace.clone()), b"/work/space", b"/tmp");
        let note = Event::lifecycle_note("att_test", 99, SystemTime::now(), 0, "prepared");
        trace
            .lock()
            .unwrap()
            .write_event(&note, Priority::Normal)
            .unwrap();
        writer.record_exec(
            10,
            Some(1),
            Some("execve"),
            Some(&snap("/work/space/tool")),
            None,
        );
        writer.record_gap(GapReason::UnmatchedExit, OpSet::ALL, 0, 1, Some(1));
        writer.record_exit(10, Some(1), 0);
        trace
            .lock()
            .unwrap()
            .write_event(&note, Priority::Normal)
            .unwrap();
        let events: Vec<Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for (source, expected) in [("wrapper", vec![1, 2, 3]), ("audit", vec![1, 2])] {
            let seqs: Vec<_> = events
                .iter()
                .filter(|e| e["source"] == source)
                .map(|e| e["source_seq"].as_u64().unwrap())
                .collect();
            assert_eq!(seqs, expected);
        }
    }

    #[test]
    fn an_unapplied_ceiling_leaves_an_explanatory_wrapper_note() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = crate::trace::shared(crate::trace::FileSink::new(file.reopen().unwrap()));
        let mut writer = AuditWriter::new("att_test", Some(trace), b"/work/space", b"/tmp");
        writer.record_limit_unapplied("pids", "no delegated cgroup");
        let events: Vec<Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 1);
        let note = &events[0];
        assert_eq!(note["source"], "wrapper");
        assert_eq!(note["operation"], "note");
        assert_eq!(note["fields"]["kind"], "limit");
        assert_eq!(note["fields"]["key"], "pids");
        assert_eq!(note["fields"]["applied"], false);
        assert_eq!(note["fields"]["reason"], "no delegated cgroup");
        // A wrapper note consumes no audit sequence and counts in no class.
        assert_eq!(writer.count(CoverageClass::Exec), 0);
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
            Some(1),
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
        writer.record_syscall(10, Some(1), 10, ClosedOp::Open, "openat", &args, 3);
        writer.record_syscall(
            10,
            Some(1),
            10,
            ClosedOp::Open,
            "openat",
            &args,
            -i64::from(libc::EROFS),
        );
        writer.record_syscall(
            10,
            Some(1),
            10,
            ClosedOp::Open,
            "openat",
            &args,
            -i64::from(libc::EACCES),
        );
        writer.record_exec(
            10,
            Some(1),
            Some("execve"),
            Some(&snap("/work/space/tool")),
            None,
        );
        writer.record_exit(10, Some(1), 0);
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
            Some(1),
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

    /// J4 D1: a child's notification listener degrades every audit class,
    /// with no count and no end — the listener can continue calls unseen
    /// for as long as anyone holds it — and a merged repeat keeps it open.
    #[test]
    fn j4_d1_a_listener_gap_degrades_every_class_and_has_no_end() {
        let mut writer = writer();
        writer.record_gap(GapReason::ChildNotificationListener, OpSet::ALL, 5, 9, None);
        writer.record_gap(
            GapReason::ChildNotificationListener,
            OpSet::ALL,
            3,
            20,
            None,
        );
        assert_eq!(writer.gaps().len(), 1);
        let gap = &writer.gaps()[0];
        assert_eq!(gap.reason, "child_notification_listener");
        assert_eq!(gap.end_ns, None, "the interval has no end");
        assert_eq!(gap.start_ns, "3");
        assert_eq!(gap.lost_count, None);
        let summary = writer.summary(&TracerSummary::default(), true);
        for class in [
            CoverageClass::Exec,
            CoverageClass::FsWrite,
            CoverageClass::FsDeny,
            CoverageClass::Net,
        ] {
            assert_eq!(summary.classes[&class].status, SourceStatus::Degraded);
            assert_eq!(summary.classes[&class].observed_count, None);
        }
        // A foreign-ABI gap is per call: it has an end.
        writer.record_gap(GapReason::ForeignAbi, OpSet::ALL, 1, 2, Some(1));
        let foreign = writer
            .gaps()
            .iter()
            .find(|gap| gap.reason == "foreign_abi")
            .unwrap();
        assert_eq!(foreign.end_ns.as_deref(), Some("2"));
    }

    /// J4 O02: every audit result names its process by pid and birth, and
    /// a confirmed exec names the call it was.
    #[test]
    fn j4_o02_every_result_carries_the_birth_it_was_given() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = crate::trace::shared(crate::trace::FileSink::new(file.reopen().unwrap()));
        let mut writer = AuditWriter::new("att_test", Some(trace), b"/work/space", b"/tmp");
        writer.record_exec(
            10,
            Some(4242),
            Some("execveat"),
            Some(&snap("/work/space/t")),
            Some(3),
        );
        writer.record_syscall(
            10,
            Some(4242),
            11,
            ClosedOp::Mkdir,
            "mkdir",
            &Args {
                path: Some(snap("/work/space/d")),
                ..Args::default()
            },
            0,
        );
        writer.record_exit(10, None, 0);
        writer.record_mediated_connect(&MediatedConnect {
            tid: 12,
            tgid: Some(12),
            tgid_start: Some(4343),
            family: Some(2),
            address_complete: true,
            ret: 0,
            reason: "non_unix",
        });
        writer.record_mediated_connect(&MediatedConnect {
            tid: 13,
            tgid: None,
            tgid_start: Some(1),
            family: Some(2),
            address_complete: true,
            ret: 0,
            reason: "non_unix",
        });
        let events: Vec<Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let births: Vec<&Value> = events
            .iter()
            .map(|e| &e["fields"]["pid_start_ticks"])
            .collect();
        assert_eq!(
            births,
            [
                &Value::from(4242),
                &Value::from(4242),
                &Value::Null,
                &Value::from(4343),
                // A birth without the group it belongs to names nothing.
                &Value::Null,
            ]
        );
        assert_eq!(events[0]["fields"]["syscall"], "execveat");
        assert_eq!(events[0]["fields"]["path_dirfd"], 3);
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
