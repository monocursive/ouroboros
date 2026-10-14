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

use crate::observer::{ClassSummary, ClosedOperation, CoverageClass, CoverageSummary};
use crate::records::{CLOSED_SET_LINUX_V1, Completion, Event, EventOutcome, Gap, SourceStatus};
use crate::trace::{Priority, SharedTrace};

use super::tracer::{Args, ClosedOp, GapReason, OpSet, PathSnapshot, TracerSummary};
use super::unixpeer::{ConnectFacts, Decision, Peer};

/// The observer backend name recorded in the receipt.
pub const OBSERVER_BACKEND: &str = "ptrace";

/// What a pathname argument could be said to be (§11.3).
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathClass {
    /// Its relationship to the workspace is established.
    WorkspaceRelative(Vec<u8>),
    /// Its relationship to the scratch directory is established.
    ScratchRelative(Vec<u8>),
    /// Its relationship to a named root (an operator grant, or a system
    /// read-only root) is established (issue draft 10).
    RootRelative { root: String, rest: Vec<u8> },
    /// Neither, so only a digest of the snapshot is emitted.
    Digest(String, &'static str),
    /// Nothing can be said about it, with a reason.
    Unavailable(&'static str),
}

/// One named root a classified path can be relative to (issue draft 10).
struct NamedRoot {
    bytes: Vec<u8>,
    label: String,
}

/// One completed closed-set call, as the observer witnessed it.
#[derive(Clone, Copy, Debug)]
pub struct SyscallResult<'a> {
    /// The calling process.
    pub pid: libc::pid_t,
    /// The birth of process `pid` (§11.3): with the receipt's `boot_id` it
    /// names the process where `pid` alone would name whichever process
    /// holds that number now.
    pub pid_start_ticks: Option<u64>,
    /// The calling thread.
    pub tid: libc::pid_t,
    /// The call's family in the closed set.
    pub op: ClosedOp,
    /// The call's name (`openat`, `renameat2`, ...).
    pub syscall: &'a str,
    /// The arguments the observer read at the entry stop.
    pub args: &'a Args,
    /// The signed raw return, so a failure is `-errno`.
    pub ret: i64,
}

/// A complete path snapshot over raw bytes.
fn snap_bytes(bytes: &[u8]) -> super::tracer::PathSnapshot {
    super::tracer::PathSnapshot {
        bytes: bytes.to_vec(),
        complete: true,
    }
}

/// How a command-rule hit was enforced ([`AuditWriter::record_command_rule`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandEnforcement {
    /// At the exec entry stop: the exec was rewritten to fail with `EPERM`.
    EntryDenied,
    /// At the exec event, against the kernel's own argv and image: the
    /// process was killed before its new image ran.
    KilledAtExec,
}

/// Turns tracer events into audit events and counts what it emitted.
///
/// Frames that never reach the trace are the stream's loss, and the stream's
/// single writer accounts for them (§13.1, §13.3): the trace writer notes a
/// refused frame itself, and the supervisor gives every evidence class the
/// stream carries a `trace_transport_loss` gap once its journal sees any
/// loss, a poisoned trace lock included. This writer accounts only for its
/// own counts: an undelivered result is never counted and degrades its class
/// (§13.2). A result a poisoned lock refused is also a counted
/// `trace_writer_poisoned` gap of its class, so the class names its gap in
/// this writer's own summary (§11.4) even before the supervisor's stream gap
/// joins it; the two are different facts (results of one class, counted;
/// the stream's interval, uncounted), not one loss told twice.
pub struct AuditWriter {
    learning: bool,
    attempt_id: String,
    trace: Option<SharedTrace>,
    seq: u64,
    workspace: Vec<u8>,
    scratch_inside: Vec<u8>,
    /// Named roots a path can be relative to (issue draft 10), most
    /// specific first.
    roots: Vec<NamedRoot>,
    counts: BTreeMap<CoverageClass, u64>,
    degraded: BTreeSet<CoverageClass>,
    gaps: Vec<Gap>,
    /// Applied ceilings whose hit became proven true (§11.4, `limits` class).
    limit_hits: u64,
    /// When this writer was made, before the observer attached: the last
    /// point nothing can have been lost, where a loss of unknown start begins.
    created_ns: u64,
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
            learning: false,
            attempt_id: attempt_id.to_owned(),
            trace,
            seq: 0,
            workspace: workspace.to_vec(),
            scratch_inside: scratch_inside.to_vec(),
            roots: Vec::new(),
            counts: BTreeMap::new(),
            degraded: BTreeSet::new(),
            gaps: Vec::new(),
            limit_hits: 0,
            created_ns: now_ns(),
        }
    }

    /// Names additional roots a classified path can be relative to (issue
    /// draft 10): operator grants by their in-jail spelling, and the system
    /// read-only roots. More specific roots are matched first.
    #[must_use]
    pub fn with_roots(mut self, roots: Vec<(Vec<u8>, String)>) -> Self {
        let mut roots: Vec<NamedRoot> = roots
            .into_iter()
            .map(|(bytes, label)| NamedRoot { bytes, label })
            .collect();
        roots.sort_by_key(|root| std::cmp::Reverse(root.bytes.len()));
        self.roots = roots;
        self
    }
    /// Learning is explicit because absolute read-path snapshots may disclose host paths.
    pub fn with_learning(mut self, learning: bool) -> Self {
        self.learning = learning;
        self
    }

    /// Records that an applied ceiling was proven hit (§11.4).
    pub fn record_limit_hit(&mut self) {
        self.limit_hits += 1;
    }

    /// Records that an applied ceiling's hit evidence is missing or was
    /// lost (audit 2026-10-08 M2): storage and inode ceilings sample
    /// saturation positively only, and unreadable cgroup counters leave
    /// their `false` claims unsupported. §11.4: missing hit evidence makes
    /// coverage degraded and the count null, and a degraded class names
    /// its gap.
    pub fn record_limit_evidence_missing(&mut self, reason: &str) {
        // Nothing observes the evidence to come back: the hole stays
        // open-ended, like a child's own lost notifications (§13.1).
        self.push_gap(
            vec![CoverageClass::Limits.as_str().to_owned()],
            reason,
            now_ns(),
            None,
            None,
        );
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
        // A note the trace did not take is the stream's loss (see
        // [`AuditWriter`]); it counts in no class.
        let _ = self.write_frame(&event, Priority::Normal);
    }

    /// Offers one frame to the trace.
    fn write_frame(&self, event: &Event, priority: Priority) -> Frame {
        let Some(trace) = self.trace.as_ref() else {
            return Frame::NoTrace;
        };
        match trace.lock() {
            Ok(mut sink) => {
                if sink.write_event(event, priority).is_ok() {
                    Frame::Delivered
                } else {
                    Frame::Refused
                }
            }
            Err(_) => Frame::Poisoned,
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
        match self.write_frame(event, Priority::Normal) {
            // No trace configured (observation off): nothing is lost that
            // anyone claimed to collect.
            Frame::Delivered | Frame::NoTrace => true,
            Frame::Refused => {
                self.degraded.insert(class);
                false
            }
            Frame::Poisoned => {
                // A trace whose lock a panicking thread held can take no
                // frame, not even the sink's own loss note: this result is a
                // gap of its class, with a count of one (see [`AuditWriter`]).
                let now = now_ns();
                self.push_gap(
                    vec![class.as_str().to_owned()],
                    TRACE_WRITER_POISONED,
                    now,
                    Some(now),
                    Some(1),
                );
                false
            }
        }
    }

    /// Emits one audit result under the next audit sequence number, and
    /// counts it in its operation's class (§11.4) once the trace took it: an
    /// undelivered frame is not an observed result (§13.2), so it degrades
    /// the class and adds nothing to its count.
    fn emit_result(
        &mut self,
        operation: ClosedOperation,
        outcome: EventOutcome,
        fields: Map<String, Value>,
    ) {
        self.seq += 1;
        let event = Event::audit_result(
            &self.attempt_id,
            self.seq,
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            operation.as_str(),
            outcome,
            fields,
        );
        let class = operation.coverage_class();
        if self.emit(&event, class) {
            *self.counts.entry(class).or_insert(0) += 1;
        }
    }

    /// The `command_rule` note of one command-rule hit (jail-v2 §7.2):
    /// pattern, argv digest, pid, and how the hit was enforced.
    ///
    /// Security 2026-09-29 (audit 6 N2, review fixes): a hit found at the
    /// exec event, re-checked against the kernel's own argv, is recorded like
    /// one found at the entry stop. The process was killed there, not failed
    /// with `EPERM`, so the note says so instead of carrying an `errno`: a
    /// `deny` or unreadable-argv hit at that stop kills the process without
    /// stopping the run, and this note is its only account.
    pub fn record_command_rule(
        &mut self,
        pid: libc::pid_t,
        hit: &crate::commands::Hit,
        enforcement: CommandEnforcement,
    ) {
        let mut event = Event::lifecycle_note(
            &self.attempt_id,
            0,
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            "command_rule",
        );
        event.fields.insert(
            "kind".into(),
            Value::from(if hit.forbidden {
                "command_forbidden"
            } else {
                "command_denied"
            }),
        );
        event
            .fields
            .insert("pattern".into(), Value::from(hit.pattern.clone()));
        // §11.3: the receipt's argv digest, or null with a reason when the
        // argv was not read whole.
        match &hit.digest {
            Some(digest) => {
                event
                    .fields
                    .insert("argv_digest".into(), Value::from(digest.clone()));
            }
            None => {
                event.fields.insert("argv_digest".into(), Value::Null);
                event.fields.insert(
                    "argv_digest_reason".into(),
                    Value::from(crate::commands::UNREADABLE_ARGV_REASON),
                );
            }
        }
        event.fields.insert("pid".into(), Value::from(pid));
        match enforcement {
            CommandEnforcement::EntryDenied => {
                event.fields.insert("errno".into(), Value::from("EPERM"));
            }
            CommandEnforcement::KilledAtExec => {
                event
                    .fields
                    .insert("enforcement".into(), Value::from("killed_at_exec"));
                event.fields.insert("signal".into(), Value::from("SIGKILL"));
            }
        }
        self.emit(&event, CoverageClass::Exec);
    }

    /// One completed closed-set call.
    pub fn record_syscall(&mut self, call: &SyscallResult<'_>) {
        let SyscallResult {
            pid,
            pid_start_ticks,
            tid,
            op,
            syscall,
            args,
            ret,
        } = *call;
        let errno = errno_of(ret);
        if let Some(hit) = &args.command {
            self.record_command_rule(pid, hit, CommandEnforcement::EntryDenied);
        }
        let learning_read = self.learning
            && op == ClosedOp::Open
            && args.flags.is_some_and(|f| {
                f & (libc::O_ACCMODE as u64 | libc::O_CREAT as u64 | libc::O_TRUNC as u64) == 0
            });
        if learning_read {
            let Some(path) = args
                .path
                .as_ref()
                .filter(|p| p.complete && p.bytes.starts_with(b"/"))
            else {
                return;
            };
            let mut fields = Map::new();
            fields.insert("kind".into(), Value::from("learning_read"));
            fields.insert("path".into(), native_value(&path.bytes));
            fields.insert(
                "errno".into(),
                errno.map_or(Value::Null, |e| Value::from(super::sys::errno_name(e))),
            );
            fields.insert("syscall".into(), Value::from(syscall));
            fields.insert("path_basis".into(), Value::from("argument_snapshot"));
            let mut event = Event::lifecycle_note(
                &self.attempt_id,
                0,
                SystemTime::now(),
                crate::platform::elapsed_since_start_ns(),
                "learning",
            );
            event.fields = fields;
            // Failure still degrades evidence; these notes add no closed-set observation count.
            self.emit(&event, CoverageClass::FsDeny);
            return;
        }
        let base = op.audit_operation(args.flags);
        // A write refused by the filesystem itself — EROFS on a read-only
        // grant, EBUSY on a rename or unlink across one — is a denial of a
        // mutation just like EACCES/EPERM (issue draft 09); the receipt's
        // fs.deny must not read 0 while the trace shows refused writes.
        let denied = matches!(errno, Some(libc::EACCES | libc::EPERM))
            || (base.coverage_class() == CoverageClass::FsWrite
                && matches!(errno, Some(libc::EROFS | libc::EBUSY)));
        let operation = if denied {
            ClosedOperation::FsDeny
        } else {
            base
        };

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
        self.describe_path_in(
            &mut fields,
            "path",
            args.path.as_ref(),
            args.dirfd,
            args.cwd.as_deref(),
        );
        if args.path2.is_some() {
            self.describe_path_in(
                &mut fields,
                "path2",
                args.path2.as_ref(),
                args.dirfd2,
                args.cwd.as_deref(),
            );
        }
        if denied {
            fields.insert("attempted_operation".to_owned(), Value::from(base.as_str()));
        } else if operation == ClosedOperation::FsWrite {
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

        self.emit_result(operation, syscall_outcome(ret), fields);
    }

    // Mediated connects are audit-source results (§10, §11.4)
    /// One `connect` the unix-peer mediator decided (jail-v1 §10).
    ///
    /// A mediated connect is not a ptrace stop — `SECCOMP_RET_USER_NOTIF`
    /// outranks the observer's `SECCOMP_RET_TRACE` — so for `agent` the
    /// mediator is the witness of every native `connect` in the attempt's
    /// tree, and this is the audit source's `net.connect` result for it, with
    /// the return value the kernel accepted for the child's `connect`.
    /// Whatever its verdict it is network evidence (issue draft 13: a
    /// refused AF_UNIX connect is not a "denied write"); the socket path or
    /// internet address the child named is reported (issue drafts 13/14), the
    /// mediator's safe reason code is recorded as `mediator_reason`, and a
    /// failed direct internet connect is marked `egress: blocked` (issue
    /// draft 14). The audit `decision` stays null (§13.1). Proxy-source
    /// facts are never merged into it: the proxy emits its own `net.connect`
    /// results.
    ///
    /// Only a decision the kernel accepted as the child's response is a
    /// result; an undelivered one is [`AuditWriter::record_mediation_response_loss`].
    pub fn record_mediated_connect(
        &mut self,
        facts: &ConnectFacts,
        decision: Decision,
        reason: &str,
    ) {
        let ret = decision.ret();
        let errno = errno_of(ret);
        let mut fields = Map::new();
        fields.insert("syscall".to_owned(), Value::from("connect"));
        fields.insert(
            "pid".to_owned(),
            facts
                .tgid
                .map_or(Value::Null, |pid| Value::from(i64::from(pid))),
        );
        insert_birth(&mut fields, facts.tgid.and(facts.tgid_start));
        fields.insert("tid".to_owned(), Value::from(i64::from(facts.tid)));
        fields.insert(
            "path_basis".to_owned(),
            Value::from("argument_snapshot".to_owned()),
        );
        let unix_path = facts.peer.as_ref().and_then(|peer| match peer {
            Peer::UnixPath(bytes) => Some(snap_bytes(bytes)),
            _ => None,
        });
        if facts
            .peer
            .as_ref()
            .is_some_and(|peer| matches!(peer, Peer::Abstract(_)))
        {
            let mut abstracted = Map::new();
            abstracted.insert("kind".to_owned(), Value::from("unavailable"));
            abstracted.insert(
                "reason".to_owned(),
                Value::from("abstract_socket".to_owned()),
            );
            fields.insert("path".to_owned(), Value::Object(abstracted));
            fields.insert("path_complete".to_owned(), Value::from(false));
        } else {
            self.describe_path(&mut fields, "path", unix_path.as_ref(), None);
        }
        if let Some(Peer::Internet { port, address }) = facts.peer.as_ref() {
            fields.insert(
                "address".to_owned(),
                Value::from(format!("{address}:{port}")),
            );
            // A direct connect that failed in the empty network namespace is
            // a blocked egress attempt (issue draft 14): exactly the case an
            // operator most wants named.
            if matches!(errno, Some(libc::ENETUNREACH | libc::ECONNREFUSED)) {
                fields.insert("egress".to_owned(), Value::from("blocked"));
            }
        }
        fields.insert(
            "address_family".to_owned(),
            facts
                .family
                .map_or(Value::Null, |family| Value::from(i64::from(family))),
        );
        fields.insert(
            "address_complete".to_owned(),
            Value::from(facts.address_complete),
        );
        fields.insert(
            "observation".to_owned(),
            Value::from("seccomp_user_notification"),
        );
        fields.insert("mediator_reason".to_owned(), Value::from(reason));
        self.emit_result(ClosedOperation::NetConnect, syscall_outcome(ret), fields);
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
        // An exec transition has no return value: the call never returned.
        self.emit_result(
            ClosedOperation::ProcExec,
            audit_outcome(true, None, None, Completion::ExecTransition),
            fields,
        );
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
        self.emit_result(
            ClosedOperation::ProcExit,
            audit_outcome(
                exited && libc::WEXITSTATUS(status) == 0,
                Some(i64::from(status)),
                None,
                Completion::ProcessExit,
            ),
            fields,
        );
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
        let classes = classes_for(ops)
            .iter()
            .map(|class| class.as_str().to_owned())
            .collect();
        // A hole whose cause is never observed to end — a child's own
        // notification listener — has no end the observer can state:
        // `null`, not the moment it was noticed (§13.1 lets it be).
        let to_ns = (!reason.is_open_ended()).then_some(to_ns);
        self.push_gap(classes, reason.as_str(), from_ns, to_ns, count);
    }

    /// Records one gap of `reason` over `classes`, from `from_ns` to `to_ns`
    /// (`None` when its end is never observed): degrades the classes it
    /// names, coalesces it with a gap of the same reason and classes, bounds
    /// the summaries, and writes its note. The summary keeps the gap whether
    /// or not the trace took its note; a note it did not take is the
    /// stream's loss.
    fn push_gap(
        &mut self,
        classes: Vec<String>,
        reason: &str,
        from_ns: u64,
        to_ns: Option<u64>,
        lost_count: Option<u64>,
    ) {
        let gap = Gap {
            classes,
            source: "audit".to_owned(),
            start_ns: from_ns.to_string(),
            end_ns: to_ns.map(|to| to.to_string()),
            reason: reason.to_owned(),
            lost_count,
        };
        for class in CoverageClass::ALL {
            if gap.classes.iter().any(|name| name == class.as_str()) {
                self.degraded.insert(class);
            }
        }
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
        let _ = self.write_frame(&event, Priority::Reserve);
        self.gaps.push(gap);
    }

    /// Whether any gap has been recorded.
    #[must_use]
    pub fn has_gaps(&self) -> bool {
        !self.gaps.is_empty()
    }

    /// Whether any recorded gap accounts for counted loss. Every gap does
    /// except `path_claim_unverified`, which downgrades a delivered result
    /// and feeds no loss counter (audit 6 N1), so it never stands in for the
    /// account of loss whose own gaps were dropped.
    #[must_use]
    pub fn has_loss_gaps(&self) -> bool {
        self.gaps
            .iter()
            .any(|gap| gap.reason != GapReason::PathClaimUnverified.as_str())
    }

    /// The gaps recorded so far.
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    /// The coverage summary for an attempt this writer observed.
    ///
    /// `known` is what the caller states and this writer cannot: whether the
    /// observer attached, the wrapper's health, and the proxy source with
    /// its `proxy.net` class (see [`CoverageSummary::applied`]). This writer
    /// fills in the observer backend and set, the audit source and its four
    /// classes, the `limits` class it accumulates, and its gaps.
    ///
    /// `tracer` is the observer's own account. Without one, or with a tracer
    /// thread that panicked, nothing says what the observer lost: the loss
    /// is a gap in every audit class from before attachment (this writer's
    /// creation) to now, with no count, so each degraded class names its
    /// missing interval (§11.4).
    #[must_use]
    pub fn summary(
        &self,
        tracer: Option<&TracerSummary>,
        known: CoverageSummary,
    ) -> CoverageSummary {
        let mut gaps = self.gaps.clone();
        let account_lost = match tracer {
            None => Some(OBSERVER_ACCOUNT_MISSING),
            Some(tracer) if tracer.thread_panicked => Some(OBSERVER_PANICKED),
            Some(_) => None,
        };
        if let Some(reason) = account_lost {
            gaps.push(Gap {
                classes: CoverageClass::AUDIT
                    .iter()
                    .map(|class| class.as_str().to_owned())
                    .collect(),
                source: "audit".to_owned(),
                start_ns: self.created_ns.to_string(),
                end_ns: Some(now_ns().max(self.created_ns).to_string()),
                reason: reason.to_owned(),
                lost_count: None,
            });
        }
        // Audit 2026-10-08 M2: the `limits` class degrades on missing hit
        // evidence too, but it is the wrapper's own class (§11.4) — its
        // degradation says nothing about the audit source's health.
        let audit_source_degraded = self
            .degraded
            .iter()
            .any(|class| *class != CoverageClass::Limits);
        let CoverageSummary {
            attached,
            mut sources,
            gaps: mut summary_gaps,
            mut classes,
            ..
        } = known;
        sources.audit = if audit_source_degraded || account_lost.is_some() {
            SourceStatus::Degraded
        } else {
            SourceStatus::Active
        };
        for class in CoverageClass::AUDIT {
            let status = if self.degraded.contains(&class) || account_lost.is_some() {
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
                    gaps: gaps
                        .iter()
                        .filter(|gap| gap.classes.iter().any(|name| name == class.as_str()))
                        .cloned()
                        .collect(),
                    resolver_refused: 0,
                },
            );
        }
        classes.insert(CoverageClass::Limits, self.limits_class());
        summary_gaps.extend(gaps);
        CoverageSummary {
            backend: Some(OBSERVER_BACKEND.to_owned()),
            set: Some(CLOSED_SET_LINUX_V1.to_owned()),
            attached,
            sources,
            gaps: summary_gaps,
            classes,
        }
    }

    /// The `limits` class, which is a wrapper fact and exists with observation
    /// off as well (§11.4). Hit evidence that is missing — positive-only
    /// sampling, or counters that became unreadable — degrades it and nulls
    /// its count, and the degraded class names its gap (§11.4).
    #[must_use]
    pub fn limits_class(&self) -> ClassSummary {
        let degraded = self.degraded.contains(&CoverageClass::Limits);
        ClassSummary {
            status: if degraded {
                SourceStatus::Degraded
            } else {
                SourceStatus::Active
            },
            // §11.4: "Unsupported and degraded counts are null."
            observed_count: if degraded {
                None
            } else {
                Some(self.limit_hits)
            },
            gaps: self
                .gaps
                .iter()
                .filter(|gap| {
                    gap.classes
                        .iter()
                        .any(|name| name == CoverageClass::Limits.as_str())
                })
                .cloned()
                .collect(),
            resolver_refused: 0,
        }
    }

    fn describe_path(
        &self,
        fields: &mut Map<String, Value>,
        key: &str,
        snapshot: Option<&PathSnapshot>,
        dirfd: Option<i32>,
    ) {
        self.describe_path_in(fields, key, snapshot, dirfd, None);
    }

    /// [`describe_path`] with the thread's observed working directory, which
    /// a relative pathname is resolved against (issue draft 12).
    fn describe_path_in(
        &self,
        fields: &mut Map<String, Value>,
        key: &str,
        snapshot: Option<&PathSnapshot>,
        dirfd: Option<i32>,
        cwd: Option<&[u8]>,
    ) {
        // The nested {kind, value} shape is the documented contract
        // (examples/event-open.json): a consumer reads fields.path.kind and
        // gets the classification, not a flat key it has to know about.
        let complete = snapshot.is_some_and(|snap| snap.complete);
        fields.insert(format!("{key}_complete"), Value::from(complete));
        if let Some(fd) = dirfd
            && fd != libc::AT_FDCWD
        {
            fields.insert(format!("{key}_dirfd"), Value::from(i64::from(fd)));
        }
        let path = match self.classify(snapshot, dirfd, cwd) {
            PathClass::WorkspaceRelative(bytes) => serde_json::json!({
                "kind": "workspace_relative",
                "value": native_value(&bytes),
            }),
            PathClass::ScratchRelative(bytes) => serde_json::json!({
                "kind": "scratch_relative",
                "value": native_value(&bytes),
            }),
            PathClass::RootRelative { root, rest } => serde_json::json!({
                "kind": "root_relative",
                "root": root,
                "value": native_value(&rest),
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

    fn classify(
        &self,
        snapshot: Option<&PathSnapshot>,
        dirfd: Option<i32>,
        cwd: Option<&[u8]>,
    ) -> PathClass {
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
            // Issue draft 12: a relative pathname the kernel resolves
            // against the thread's own cwd is resolved against that cwd,
            // observed at the syscall stop. Only the true dirfd cases (and a
            // cwd that could not be read or named) keep their distinct
            // reasons.
            let at_cwd = dirfd.is_none_or(|fd| fd == libc::AT_FDCWD);
            if at_cwd && cwd.is_some_and(|cwd| cwd.ends_with(DELETED_MARK)) {
                // The kernel names a removed directory by its old path plus
                // this mark: no path names it now, and a directory whose own
                // name ends that way cannot be told from one. Either way the
                // joined path would be a claim about a name, not the cwd.
                return PathClass::Unavailable("relative_to_unresolved_cwd");
            }
            if at_cwd
                && let Some(cwd) = cwd
                && cwd.first() == Some(&b'/')
            {
                let mut joined = cwd.to_vec();
                joined.push(b'/');
                joined.extend_from_slice(bytes);
                return self.classify(
                    Some(&PathSnapshot {
                        bytes: joined,
                        complete: true,
                    }),
                    None,
                    None,
                );
            }
            return match dirfd {
                Some(fd) if fd != libc::AT_FDCWD => PathClass::Unavailable("relative_to_dirfd"),
                _ => PathClass::Unavailable("relative_to_unobserved_cwd"),
            };
        }
        if let Some(rest) = strip_root(bytes, &self.workspace) {
            return PathClass::WorkspaceRelative(rest);
        }
        if let Some(rest) = strip_root(bytes, &self.scratch_inside) {
            return PathClass::ScratchRelative(rest);
        }
        for root in &self.roots {
            if let Some(rest) = strip_root(bytes, &root.bytes) {
                return PathClass::RootRelative {
                    root: root.label.clone(),
                    rest,
                };
            }
        }
        PathClass::Digest(
            crate::canonical::sha256_prefixed(bytes),
            "outside_known_roots",
        )
    }
}

/// What became of a frame offered to the trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    /// The sink took it.
    Delivered,
    /// No trace is configured (observation off): nothing was expected.
    NoTrace,
    /// The sink refused it, and recorded the loss itself.
    Refused,
    /// The trace lock was poisoned by a panicking thread: nothing can be
    /// written, the sink's own loss note included.
    Poisoned,
}

/// What the kernel appends to `/proc/<tid>/cwd` when the directory was
/// removed (`d_path`).
const DELETED_MARK: &[u8] = b" (deleted)";

/// The gap reason of a result a poisoned trace lock could not take.
const TRACE_WRITER_POISONED: &str = "trace_writer_poisoned";
/// The gap reason of an observer whose tracer thread panicked.
const OBSERVER_PANICKED: &str = "observer_panicked";
/// The gap reason of an observed attempt whose observer left no account.
const OBSERVER_ACCOUNT_MISSING: &str = "observer_account_missing";

/// The errno a signed raw return carries: `Some` only for a failure
/// (`-errno`) whose magnitude is an errno at all.
fn errno_of(ret: i64) -> Option<i32> {
    (ret < 0)
        .then(|| ret.checked_neg().and_then(|code| i32::try_from(code).ok()))
        .flatten()
}

/// An audit result's outcome. Proxy byte counts and durations belong to
/// proxy results only.
fn audit_outcome(
    ok: bool,
    return_value: Option<i64>,
    errno: Option<i32>,
    completion: Completion,
) -> EventOutcome {
    EventOutcome {
        ok: Some(ok),
        return_value,
        errno: errno.map(|code| super::sys::errno_name(code).into_owned()),
        completion,
        bytes_in: None,
        bytes_out: None,
        duration_ms: None,
    }
}

/// The outcome of a syscall that returned `ret` (`-errno` on failure).
fn syscall_outcome(ret: i64) -> EventOutcome {
    audit_outcome(
        ret >= 0,
        Some(ret),
        errno_of(ret),
        Completion::SyscallReturn,
    )
}

/// Now, in the gap intervals' unit: nanoseconds since supervisor start.
fn now_ns() -> u64 {
    u64::try_from(crate::platform::elapsed_since_start_ns()).unwrap_or(u64::MAX)
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
        classes.insert(op.audit_operation(None).coverage_class());
        classes.insert(CoverageClass::FsDeny);
    }
    classes.into_iter().collect()
}

/// Widen `gap`'s interval to cover a loss from `from` to `to` (`None` when
/// that loss is never observed to end). The bounds read back are the ones
/// [`AuditWriter::push_gap`] wrote from numbers.
///
/// An open interval stays open, and audit 7 L13: an open-ended loss merged
/// into a closed interval leaves it open — only a presented or written end
/// bounds an interval, never a merge.
fn extend_gap_interval(gap: &mut Gap, from: u64, to: Option<u64>) {
    gap.start_ns = gap
        .start_ns
        .parse::<u64>()
        .map_or(from, |start| start.min(from))
        .to_string();
    let end = gap
        .end_ns
        .as_deref()
        .and_then(|end| end.parse::<u64>().ok());
    gap.end_ns = end.zip(to).map(|(end, to)| end.max(to).to_string());
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

    /// What a platform states for an attempt whose observer attached.
    fn applied() -> CoverageSummary {
        CoverageSummary::applied(true)
    }

    /// One call by thread 10 of process 10, born at tick 1.
    fn call<'a>(op: ClosedOp, syscall: &'a str, args: &'a Args, ret: i64) -> SyscallResult<'a> {
        SyscallResult {
            pid: 10,
            pid_start_ticks: Some(1),
            tid: 10,
            op,
            syscall,
            args,
            ret,
        }
    }

    /// Every event written to the trace file at `path`, in order.
    fn trace_events(path: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn a_create_open_is_fs_create_and_a_mutating_open_is_fs_write() {
        assert_eq!(
            ClosedOp::Open.audit_operation(Some(O_CREAT | 1)),
            ClosedOperation::FsCreate
        );
        assert_eq!(
            ClosedOp::Open.audit_operation(Some(1)),
            ClosedOperation::FsWrite
        );
        assert_eq!(
            ClosedOp::Open.audit_operation(None),
            ClosedOperation::FsWrite
        );
    }

    #[test]
    fn every_directory_entry_creation_is_fs_create() {
        for op in [ClosedOp::Mkdir, ClosedOp::Link, ClosedOp::Symlink] {
            assert_eq!(op.audit_operation(None), ClosedOperation::FsCreate);
        }
        for op in [ClosedOp::Unlink, ClosedOp::Rmdir] {
            assert_eq!(op.audit_operation(None), ClosedOperation::FsUnlink);
        }
        assert_eq!(
            ClosedOp::Rename.audit_operation(None),
            ClosedOperation::FsRename
        );
        assert_eq!(
            ClosedOp::Connect.audit_operation(None),
            ClosedOperation::NetConnect
        );
    }

    #[test]
    fn a_denied_connect_counts_under_fs_deny_only() {
        let mut writer = writer();
        let connect = |writer: &mut AuditWriter, ret: i64| {
            writer.record_syscall(&call(ClosedOp::Connect, "connect", &Args::default(), ret));
        };
        connect(&mut writer, -i64::from(libc::EACCES));
        assert_eq!(writer.count(CoverageClass::FsDeny), 1);
        assert_eq!(writer.count(CoverageClass::Net), 0);
        connect(&mut writer, 0);
        assert_eq!(writer.count(CoverageClass::FsDeny), 1);
        assert_eq!(writer.count(CoverageClass::Net), 1);
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
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        for class in [CoverageClass::Net, CoverageClass::FsDeny] {
            assert_eq!(summary.classes[&class].status, SourceStatus::Degraded);
            assert_eq!(summary.classes[&class].observed_count, None);
        }
        for class in [CoverageClass::Exec, CoverageClass::FsWrite] {
            assert_eq!(summary.classes[&class].status, SourceStatus::Active);
        }
    }

    /// Issue drafts 13/14: a mediated connect is network evidence whatever
    /// its verdict, names the socket path or internet address, and a failed
    /// direct internet connect is marked blocked egress.
    #[test]
    fn mediated_connects_are_net_evidence_with_their_address_named() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = crate::trace::shared(crate::trace::FileSink::new(file.reopen().unwrap()));
        let mut writer = AuditWriter::new("att_test", Some(trace), b"/work/space", b"/tmp");
        writer.record_mediated_connect(
            &ConnectFacts {
                tid: 12,
                tgid: Some(12),
                tgid_start: Some(99),
                family: Some(1),
                address_complete: true,
                peer: Some(Peer::UnixPath(b"/work/space/run/nscd".to_vec())),
            },
            Decision::Denied(libc::EACCES),
            "path_unresolved",
        );
        assert_eq!(writer.count(CoverageClass::Net), 1);
        assert_eq!(writer.count(CoverageClass::FsDeny), 0);

        writer.record_mediated_connect(
            &ConnectFacts {
                tid: 13,
                tgid: Some(12),
                tgid_start: Some(99),
                family: Some(2),
                address_complete: true,
                peer: Some(Peer::Internet {
                    port: 80,
                    address: "169.254.169.254".parse().unwrap(),
                }),
            },
            Decision::Denied(libc::ENETUNREACH),
            "non_unix",
        );
        let events = trace_events(file.path());
        let unix_deny = events
            .iter()
            .find(|event| event["fields"]["mediator_reason"] == "path_unresolved")
            .expect("the refused pathname connect");
        assert_eq!(unix_deny["operation"], "net.connect");
        assert_eq!(unix_deny["outcome"]["errno"], "EACCES");
        assert_eq!(unix_deny["fields"]["path"]["kind"], "workspace_relative");
        assert_eq!(unix_deny["fields"]["path"]["value"], "run/nscd");
        let blocked = events
            .iter()
            .find(|event| event["fields"]["mediator_reason"] == "non_unix")
            .expect("the direct connect");
        assert_eq!(blocked["operation"], "net.connect");
        assert_eq!(blocked["fields"]["address"], "169.254.169.254:80");
        assert_eq!(blocked["fields"]["egress"], "blocked");
        assert_eq!(blocked["outcome"]["errno"], "ENETUNREACH");

        writer.record_mediated_connect(
            &ConnectFacts {
                tid: 14,
                tgid: Some(12),
                tgid_start: Some(99),
                family: Some(1),
                address_complete: true,
                peer: Some(Peer::Abstract(b"ouro".to_vec())),
            },
            Decision::Allowed,
            "abstract",
        );
        let events = trace_events(file.path());
        let abstracted = events
            .iter()
            .find(|event| event["fields"]["mediator_reason"] == "abstract")
            .expect("the abstract connect");
        assert_eq!(abstracted["fields"]["path"]["reason"], "abstract_socket");
        assert_eq!(abstracted["fields"]["path_complete"], false);
    }

    #[test]
    fn a_workspace_path_is_reported_relative_to_the_workspace() {
        let writer = writer();
        assert_eq!(
            writer.classify(
                Some(&snap("/work/space/src/lib.rs")),
                Some(libc::AT_FDCWD),
                None
            ),
            PathClass::WorkspaceRelative(b"src/lib.rs".to_vec())
        );
        assert_eq!(
            writer.classify(Some(&snap("/work/space")), None, None),
            PathClass::WorkspaceRelative(Vec::new())
        );
        assert_eq!(
            writer.classify(Some(&snap("/tmp/scratch.txt")), None, None),
            PathClass::ScratchRelative(b"scratch.txt".to_vec())
        );
    }

    #[test]
    fn a_sibling_of_the_workspace_is_not_inside_it() {
        let writer = writer();
        // `/work/spacex` shares a byte prefix with `/work/space` and is not
        // inside it.
        match writer.classify(Some(&snap("/work/spacex/f")), None, None) {
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
                writer().classify(Some(&snap(path)), None, None),
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
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        for class in CoverageClass::AUDIT {
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
        let events = trace_events(file.path());
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
        let events = trace_events(file.path());
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

    // Audit 2026-10-08 M2: missing hit evidence degrades the `limits` class.
    #[test]
    fn missing_limit_hit_evidence_degrades_the_limits_class() {
        let mut writer = writer();
        writer.record_limit_hit();
        writer.record_limit_evidence_missing("storage_hit_evidence_positive_only");
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        assert_degraded_classes_name_their_gaps(&summary);
        let limits = &summary.classes[&CoverageClass::Limits];
        assert_eq!(limits.status, SourceStatus::Degraded);
        // §11.4: the count is null, not the hits that were still proven.
        assert_eq!(limits.observed_count, None);
        assert_eq!(limits.gaps.len(), 1, "{limits:?}");
        assert_eq!(limits.gaps[0].reason, "storage_hit_evidence_positive_only");
        assert_eq!(limits.gaps[0].source, "audit");
        assert!(limits.gaps[0].end_ns.is_none(), "nothing ends the hole");
        // A second, different reason adds its own gap; the same reason
        // coalesces into the first.
        writer.record_limit_evidence_missing("storage_hit_evidence_positive_only");
        writer.record_limit_evidence_missing("cgroup_counters_unreadable");
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        assert_degraded_classes_name_their_gaps(&summary);
        let limits = &summary.classes[&CoverageClass::Limits];
        assert_eq!(limits.gaps.len(), 2, "{limits:?}");
        // Without missing evidence the class stays active with its count.
        let mut clean = AuditWriter::new("att_x", None, b"/work/space", b"/tmp");
        clean.record_limit_hit();
        let summary = clean.summary(Some(&TracerSummary::default()), applied());
        let limits = &summary.classes[&CoverageClass::Limits];
        assert_eq!(limits.status, SourceStatus::Active);
        assert_eq!(limits.observed_count, Some(1));
        assert!(limits.gaps.is_empty());
    }

    /// A trace whose lock a panicking thread held: every later `lock()` is
    /// `Err(PoisonError)`.
    fn poisoned_trace() -> crate::trace::SharedTrace {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = crate::trace::shared(crate::trace::FileSink::new(file.reopen().unwrap()));
        let held = std::sync::Arc::clone(&trace);
        let _ = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            panic!("poison the trace lock (test)");
        })
        .join();
        assert!(trace.lock().is_err(), "the trace lock is poisoned");
        trace
    }

    /// Every degraded class of `summary` names at least one gap, and every
    /// gap it lists names it (§11.4; the receipt schema's frozen rule).
    fn assert_degraded_classes_name_their_gaps(summary: &CoverageSummary) {
        for (class, entry) in &summary.classes {
            if entry.status == SourceStatus::Degraded {
                assert!(!entry.gaps.is_empty(), "{class:?} is degraded with no gap");
            }
            for gap in &entry.gaps {
                assert!(
                    gap.classes.iter().any(|name| name == class.as_str()),
                    "{class:?} lists a gap that does not name it: {gap:?}"
                );
            }
        }
    }

    #[test]
    fn a_panicked_observer_is_a_gap_in_every_audit_class() {
        let writer = writer();
        let summary = writer.summary(
            Some(&TracerSummary {
                thread_panicked: true,
                ..TracerSummary::default()
            }),
            applied(),
        );
        assert_degraded_classes_name_their_gaps(&summary);
        for class in CoverageClass::AUDIT {
            let entry = &summary.classes[&class];
            assert_eq!(entry.status, SourceStatus::Degraded, "{class:?}");
            assert_eq!(entry.observed_count, None, "{class:?}");
            let gap = &entry.gaps[0];
            assert_eq!(gap.reason, "observer_panicked");
            assert_eq!(gap.source, "audit");
            assert_eq!(gap.lost_count, None, "nothing says how much was lost");
            let (start, end) = (
                gap.start_ns.parse::<u64>().unwrap(),
                gap.end_ns.as_deref().unwrap().parse::<u64>().unwrap(),
            );
            assert!(start <= end, "{gap:?}");
        }
        assert_eq!(summary.sources.audit, SourceStatus::Degraded);
        assert!(
            summary
                .gaps
                .iter()
                .any(|gap| gap.reason == "observer_panicked"),
            "the observer's own gap summary says so too"
        );
    }

    /// An observed attempt with no observer account claims nothing: every
    /// audit class is degraded by a gap with no count, never active with a
    /// count of zero, and the caller's attachment state is what it reports.
    #[test]
    fn a_missing_observer_account_is_a_gap_in_every_audit_class() {
        let mut writer = writer();
        writer.record_exec(
            10,
            Some(1),
            Some("execve"),
            Some(&snap("/work/space/t")),
            None,
        );
        let summary = writer.summary(None, CoverageSummary::applied(false));
        assert_degraded_classes_name_their_gaps(&summary);
        assert!(
            !summary.attached,
            "the caller said the observer never attached"
        );
        assert_eq!(summary.sources.audit, SourceStatus::Degraded);
        for class in CoverageClass::AUDIT {
            let entry = &summary.classes[&class];
            assert_eq!(entry.status, SourceStatus::Degraded, "{class:?}");
            assert_eq!(entry.observed_count, None, "{class:?}");
            assert_eq!(entry.gaps[0].reason, "observer_account_missing");
            assert_eq!(entry.gaps[0].lost_count, None);
        }
    }

    /// The sources this writer does not own come from the caller: the
    /// wrapper's health and the proxy's class pass through untouched.
    #[test]
    fn the_callers_sources_pass_through_the_summary() {
        let writer = writer();
        let mut known = CoverageSummary::applied(true);
        known.sources.wrapper = SourceStatus::Degraded;
        known.sources.proxy = SourceStatus::Active;
        let proxy = ClassSummary {
            status: SourceStatus::Active,
            observed_count: Some(3),
            gaps: Vec::new(),
            resolver_refused: 1,
        };
        known.classes.insert(CoverageClass::ProxyNet, proxy.clone());
        let summary = writer.summary(Some(&TracerSummary::default()), known);
        assert!(summary.attached);
        assert_eq!(summary.sources.wrapper, SourceStatus::Degraded);
        assert_eq!(summary.sources.proxy, SourceStatus::Active);
        assert_eq!(summary.sources.audit, SourceStatus::Active);
        assert_eq!(summary.classes[&CoverageClass::ProxyNet], proxy);
        assert_eq!(
            summary.classes[&CoverageClass::Exec].observed_count,
            Some(0)
        );
    }

    #[test]
    fn a_result_a_poisoned_trace_cannot_take_is_a_gap_of_its_class() {
        let mut writer =
            AuditWriter::new("att_test", Some(poisoned_trace()), b"/work/space", b"/tmp");
        writer.record_syscall(&call(
            ClosedOp::Open,
            "openat",
            &Args {
                path: Some(snap("/work/space/f")),
                flags: Some(1),
                ..Args::default()
            },
            3,
        ));
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        assert_degraded_classes_name_their_gaps(&summary);
        let entry = &summary.classes[&CoverageClass::FsWrite];
        assert_eq!(entry.status, SourceStatus::Degraded);
        assert_eq!(entry.gaps.len(), 1, "{entry:?}");
        assert_eq!(entry.gaps[0].reason, "trace_writer_poisoned");
        assert_eq!(entry.gaps[0].lost_count, Some(1));
        assert_eq!(
            writer.count(CoverageClass::FsWrite),
            0,
            "not delivered, not counted"
        );
        // A second lost result in the same class extends the same gap.
        writer.record_syscall(&call(
            ClosedOp::Open,
            "openat",
            &Args {
                path: Some(snap("/work/space/g")),
                flags: Some(1),
                ..Args::default()
            },
            4,
        ));
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        let entry = &summary.classes[&CoverageClass::FsWrite];
        assert_eq!(entry.gaps.len(), 1, "coalesced: {entry:?}");
        assert_eq!(entry.gaps[0].lost_count, Some(2));
    }

    #[test]
    fn a_gap_whose_note_a_poisoned_trace_refuses_stays_in_the_summary() {
        let mut writer =
            AuditWriter::new("att_test", Some(poisoned_trace()), b"/work/space", b"/tmp");
        writer.record_gap(
            GapReason::QueueFull,
            OpSet::of(ClosedOp::Open),
            1,
            2,
            Some(1),
        );
        writer.record_limit_unapplied("pids", "no delegated cgroup");
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        assert_degraded_classes_name_their_gaps(&summary);
        let entry = &summary.classes[&CoverageClass::FsWrite];
        assert_eq!(entry.status, SourceStatus::Degraded);
        assert_eq!(entry.gaps.len(), 1, "{entry:?}");
        assert_eq!(entry.gaps[0].reason, "queue_full");
    }

    #[test]
    fn a_relative_path_is_never_joined_to_a_guessed_cwd() {
        let writer = writer();
        assert_eq!(
            writer.classify(Some(&snap("relative/file")), Some(libc::AT_FDCWD), None),
            PathClass::Unavailable("relative_to_unobserved_cwd")
        );
        assert_eq!(
            writer.classify(Some(&snap("relative/file")), Some(7), None),
            PathClass::Unavailable("relative_to_dirfd")
        );
    }

    /// A relative path opened from a removed directory: `/proc/<tid>/cwd`
    /// reads `<old path> (deleted)`, which is not a path, so nothing may be
    /// joined to it (it would claim `build (deleted)/x` in the workspace).
    #[test]
    fn a_relative_path_is_never_joined_to_a_deleted_cwd() {
        let writer = writer();
        assert_eq!(
            writer.classify(
                Some(&snap("x")),
                Some(libc::AT_FDCWD),
                Some(b"/work/space/build (deleted)")
            ),
            PathClass::Unavailable("relative_to_unresolved_cwd")
        );
        assert_eq!(
            writer.classify(Some(&snap("x")), None, Some(b"/work/space/build")),
            PathClass::WorkspaceRelative(b"build/x".to_vec())
        );
        // An absolute path does not consult the cwd at all.
        assert_eq!(
            writer.classify(Some(&snap("/work/space/x")), None, Some(b"/gone (deleted)")),
            PathClass::WorkspaceRelative(b"x".to_vec())
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
            writer.classify(Some(&truncated), None, None),
            PathClass::Unavailable("path_truncated")
        );
        assert_eq!(
            writer.classify(None, None, None),
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
        assert_eq!(
            ClosedOp::Mknod.audit_operation(None),
            ClosedOperation::FsCreate
        );
        assert_eq!(
            ClosedOp::Truncate.audit_operation(None),
            ClosedOperation::FsWrite
        );
        assert_eq!(
            ClosedOp::Truncate.audit_operation(None),
            ClosedOp::Open.audit_operation(Some(1)),
            "both are mutations of an existing file; their actions differ"
        );
    }

    #[test]
    fn a_gap_degrades_its_classes_and_nulls_their_counts() {
        let mut writer = writer();
        writer.record_syscall(&call(
            ClosedOp::Open,
            "openat",
            &Args {
                path: Some(snap("/work/space/a")),
                flags: Some(O_CREAT),
                ..Args::default()
            },
            3,
        ));
        assert_eq!(writer.count(CoverageClass::FsWrite), 1);
        writer.record_gap(
            GapReason::QueueFull,
            OpSet::of(ClosedOp::Open),
            1,
            2,
            Some(4),
        );
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
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
        writer.record_syscall(&call(ClosedOp::Open, "openat", &args, 3));
        writer.record_syscall(&call(
            ClosedOp::Open,
            "openat",
            &args,
            -i64::from(libc::EROFS),
        ));
        writer.record_syscall(&call(
            ClosedOp::Open,
            "openat",
            &args,
            -i64::from(libc::EACCES),
        ));
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
            1,
            "only the successful open counts as fs.write"
        );
        assert_eq!(
            writer.count(CoverageClass::FsDeny),
            2,
            "EROFS on a write-class open is a denied mutation (issue draft 09), \
             like EACCES"
        );
        assert_eq!(writer.count(CoverageClass::Exec), 2);
    }

    #[test]
    fn a_truncation_by_path_says_which_mutation_it_was() {
        let mut writer = writer();
        writer.record_syscall(&call(
            ClosedOp::Truncate,
            "truncate",
            &Args {
                path: Some(snap("/work/space/a")),
                ..Args::default()
            },
            0,
        ));
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
        let summary = writer.summary(Some(&TracerSummary::default()), applied());
        for class in CoverageClass::AUDIT {
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

    /// One rule widens every merged interval: the earliest start, the latest
    /// end, and no end once either side has none.
    #[test]
    fn a_merged_interval_covers_both_and_ends_only_if_both_end() {
        let gap = |start: u64, end: Option<u64>| Gap {
            classes: Vec::new(),
            source: "audit".to_owned(),
            start_ns: start.to_string(),
            end_ns: end.map(|end| end.to_string()),
            reason: "queue_full".to_owned(),
            lost_count: Some(1),
        };
        let merged = |mut into: Gap, from: u64, to: Option<u64>| {
            extend_gap_interval(&mut into, from, to);
            (into.start_ns, into.end_ns)
        };
        let closed = |start: &str, end: &str| (start.to_owned(), Some(end.to_owned()));
        assert_eq!(merged(gap(5, Some(9)), 2, Some(7)), closed("2", "9"));
        assert_eq!(merged(gap(5, Some(9)), 6, Some(12)), closed("5", "12"));
        assert_eq!(merged(gap(5, Some(9)), 7, None), ("5".to_owned(), None));
        assert_eq!(merged(gap(5, None), 1, Some(3)), ("1".to_owned(), None));
    }

    /// Audit 7 L13: at the 64-gap bound, an open-ended loss merged into the
    /// closed `coalesced_losses` interval leaves it open — a merge never
    /// gives the loss an end.
    #[test]
    fn an_open_ended_loss_merged_at_the_gap_bound_leaves_the_interval_open() {
        let mut writer = writer();
        // Distinct (reason, classes) keys, so none coalesces with another:
        // every reason with an end, under each of three class sets, which
        // is more than the bound holds.
        let ops = [
            OpSet::of(ClosedOp::Exec),
            OpSet::of(ClosedOp::Open),
            OpSet::of(ClosedOp::Connect),
        ];
        let keys: Vec<(GapReason, OpSet)> = GapReason::ALL
            .into_iter()
            .filter(|reason| !reason.is_open_ended())
            .flat_map(|reason| ops.map(|ops| (reason, ops)))
            .collect();
        for reason in GapReason::ALL {
            let driven = keys.iter().filter(|(key, _)| *key == reason).count();
            let expected = if reason.is_open_ended() { 0 } else { ops.len() };
            assert_eq!(driven, expected, "{reason:?}");
        }
        assert!(keys.len() > 64, "past the bound: {}", keys.len());
        for (i, (reason, ops)) in keys.iter().enumerate() {
            writer.record_gap(*reason, *ops, i as u64, i as u64 + 1, Some(1));
        }
        assert_eq!(writer.gaps().len(), 64, "the bound holds");
        // The first 63 losses keep their own summaries; the 64th and every
        // one past the bound share the last, closed through the last loss,
        // with no count and every class they named.
        let bounded = writer.gaps().last().unwrap();
        assert_eq!(bounded.reason, "coalesced_losses");
        assert_eq!(bounded.start_ns, "63");
        assert_eq!(
            bounded.end_ns.as_deref(),
            Some(keys.len().to_string().as_str())
        );
        assert_eq!(bounded.lost_count, None);
        for class in CoverageClass::AUDIT {
            assert!(bounded.classes.iter().any(|name| name == class.as_str()));
        }
        writer.record_gap(
            GapReason::ChildNotificationListener,
            OpSet::ALL,
            30,
            99,
            None,
        );
        assert_eq!(
            writer.gaps().len(),
            64,
            "the bound merges instead of growing"
        );
        let merged = writer.gaps().last().unwrap();
        assert_eq!(merged.reason, "coalesced_losses");
        assert_eq!(
            merged.end_ns, None,
            "the open-ended loss keeps the interval open"
        );
        assert_eq!(
            merged.start_ns, "30",
            "the interval covers the union, from the earliest loss merged in"
        );
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
        writer.record_syscall(&SyscallResult {
            pid: 10,
            pid_start_ticks: Some(4242),
            tid: 11,
            ..call(
                ClosedOp::Mkdir,
                "mkdir",
                &Args {
                    path: Some(snap("/work/space/d")),
                    ..Args::default()
                },
                0,
            )
        });
        writer.record_exit(10, None, 0);
        writer.record_mediated_connect(
            &ConnectFacts {
                tid: 12,
                tgid: Some(12),
                tgid_start: Some(4343),
                family: Some(2),
                address_complete: true,
                peer: None,
            },
            Decision::Allowed,
            "non_unix",
        );
        writer.record_mediated_connect(
            &ConnectFacts {
                tid: 13,
                tgid: None,
                tgid_start: Some(1),
                family: Some(2),
                address_complete: true,
                peer: None,
            },
            Decision::Allowed,
            "non_unix",
        );
        let events = trace_events(file.path());
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

    /// A command hit whose argv could not be read whole names no digest:
    /// the digest is null and the note says why (§11.3), never a
    /// placeholder value.
    #[test]
    fn a_command_hit_without_an_argv_digest_names_the_reason() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = crate::trace::shared(crate::trace::FileSink::new(file.reopen().unwrap()));
        let mut writer = AuditWriter::new("att_test", Some(trace), b"/work/space", b"/tmp");
        let hit = crate::commands::Hit {
            pattern: "<unreadable-or-oversized-argv>".to_owned(),
            digest: None,
            forbidden: false,
        };
        writer.record_command_rule(10, &hit, CommandEnforcement::EntryDenied);
        let events = trace_events(file.path());
        assert_eq!(events.len(), 1, "{events:?}");
        let fields = &events[0]["fields"];
        assert_eq!(fields["kind"], "command_denied");
        assert_eq!(fields["argv_digest"], Value::Null, "{fields}");
        assert_eq!(fields["argv_digest_reason"], "argv_unreadable_or_oversized");
        assert_eq!(fields["errno"], "EPERM");
    }
}
