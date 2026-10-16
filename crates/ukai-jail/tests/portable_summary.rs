//! J13, the end-of-run summary (`docs/specs/jail-launch-and-summary.md` §4),
//! rows K45–K48 and K50–K54 of its §6.2 wherever they hold on every
//! platform: the pure function over receipts and journals built here, and
//! the binary's terminal-only printing, `--quiet`, `[jail] summary = false`
//! and `tail --summary [--json]`.
//!
//! A journal built here is written as the supervisor writes one: per-source
//! sequence numbers, one supervisor clock, and, when it is complete, a last
//! frame that is the `jail.receipt` note naming the receipt's canonical
//! digest. The receipts start from the checked-in examples, so they keep the
//! receipt schema's shape. K49 (X05 and the order of a real run's output on a
//! pseudo-terminal) needs a contained run and lives in `j13_summary_linux.rs`.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use ukai_jail::summary::{self, Journal, JournalState, Summary};

const ATTEMPT: &str = "att_00000000-0000-4000-8000-000000000001";

fn specs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1")
}

fn example(name: &str) -> Value {
    let path = specs().join("examples").join(name);
    serde_json::from_slice(&std::fs::read(&path).expect("the example is checked in"))
        .expect("the example is JSON")
}

/// `sha256:` over the receipt's RFC 8785 bytes: the name the supervisor's
/// receipt notes carry.
fn digest(receipt: &Value) -> String {
    ukai_jail::canonical::sha256_prefixed(
        &ukai_jail::canonical::to_jcs(receipt).expect("a receipt canonicalizes"),
    )
}

/// The class a frame counts under, written out here independently of the
/// product's mapping (jail-v1 §11.4).
fn class_of(event: &Value) -> Option<&'static str> {
    match (
        event["source"].as_str().unwrap_or(""),
        event["operation"].as_str().unwrap_or(""),
    ) {
        ("audit", "proc.exec" | "proc.exit") => Some("exec"),
        ("audit", "fs.create" | "fs.write" | "fs.rename" | "fs.unlink") => Some("fs.write"),
        ("audit", "fs.deny") => Some("fs.deny"),
        ("audit", "net.connect") => Some("net"),
        ("proxy", "net.connect") => Some("proxy.net"),
        _ => None,
    }
}

/// A recorded attempt under construction: a receipt and its journal.
#[derive(Clone)]
struct Fixture {
    receipt: Value,
    events: Vec<Value>,
    seq: BTreeMap<String, u64>,
    ns: u64,
}

impl Fixture {
    fn from(receipt: Value) -> Self {
        Fixture {
            receipt,
            events: Vec::new(),
            seq: BTreeMap::new(),
            ns: 100_000_000,
        }
    }

    /// `receipt-tool.json` as an `agent` run: a proxy network, all six
    /// classes active, every ceiling applied and none hit.
    fn agent() -> Self {
        let mut receipt = example("receipt-tool.json");
        receipt["applied"]["network"] = json!({
            "mode": "proxy",
            "mechanism": "fixture-proxy",
            "allowed_hosts": ["api.example.test:443"],
        });
        receipt["observer"]["sources"]["proxy"] = json!("active");
        receipt["coverage"]["proxy.net"] = json!({
            "status": "active", "sources": ["proxy"], "observed_count": 0, "gaps": [],
        });
        receipt["applied"]["limits"] = json!([{
            "key": "wall", "requested": "30m", "required": true, "applied": true,
            "mechanism": "monotonic-deadline", "scope": "tree", "hit": false,
        }]);
        Fixture::from(receipt)
    }

    /// The clock of the next frame.
    fn at(&mut self, ns: u64) -> &mut Self {
        self.ns = ns;
        self
    }

    fn push(
        &mut self,
        source: &str,
        operation: &str,
        decision: Value,
        outcome: Value,
        fields: Value,
    ) -> &mut Self {
        let seq = self.seq.entry(source.to_owned()).or_insert(0);
        *seq += 1;
        self.events.push(json!({
            "schema": "ukai.event/1",
            "attempt_id": ATTEMPT,
            "source": source,
            "source_seq": *seq,
            "observed_at": "2026-09-21T12:00:00Z",
            "monotonic_ns": self.ns.to_string(),
            "operation": operation,
            "stage": "result",
            "decision": decision,
            "outcome": outcome,
            "fields": fields,
        }));
        self.ns += 1_000_000;
        self
    }

    fn wrapper_outcome() -> Value {
        json!({"ok": true, "return_value": null, "errno": null, "completion": "wrapper"})
    }

    fn lifecycle(&mut self, transition: &str) -> &mut Self {
        self.push(
            "wrapper",
            "note",
            Value::Null,
            Self::wrapper_outcome(),
            json!({"kind": "lifecycle", "transition": transition}),
        )
    }

    fn credential_note(&mut self, id: &str, transition: &str, marked: bool) -> &mut Self {
        let mut fields = json!({
            "kind": "credential", "transition": transition, "credential_id": id, "generation": 1,
        });
        if marked {
            fields["uses_recorded"] = json!(true);
        }
        self.push(
            "wrapper",
            "note",
            Value::Null,
            Self::wrapper_outcome(),
            fields,
        )
    }

    fn audit(&mut self, operation: &str, ok: bool, mut fields: Value) -> &mut Self {
        fields["syscall"] = json!("openat");
        fields["pid"] = json!(1234);
        fields["pid_start_ticks"] = json!(1);
        fields["tid"] = json!(1234);
        fields["path_basis"] = json!("argument_snapshot");
        let outcome = if ok {
            json!({"ok": true, "return_value": 0, "errno": null, "completion": "syscall_return"})
        } else {
            json!({"ok": false, "return_value": -13, "errno": "EACCES", "completion": "syscall_return"})
        };
        self.push("audit", operation, Value::Null, outcome, fields)
    }

    fn named(path: &str) -> Value {
        json!({"kind": "workspace_relative", "value": path})
    }

    fn exec(&mut self) -> &mut Self {
        self.audit(
            "proc.exec",
            true,
            json!({"path": {"kind": "root_relative", "root": "system", "value": "bin/true"}}),
        )
    }

    fn exit(&mut self) -> &mut Self {
        self.audit("proc.exit", true, json!({}))
    }

    fn create(&mut self, path: &str) -> &mut Self {
        self.audit("fs.create", true, json!({"path": Self::named(path)}))
    }

    fn open_write(&mut self, path: &str) -> &mut Self {
        self.audit(
            "fs.write",
            true,
            json!({"path": Self::named(path), "action": "opened_for_mutation"}),
        )
    }

    fn truncate(&mut self, path: &str) -> &mut Self {
        self.audit(
            "fs.write",
            true,
            json!({"path": Self::named(path), "action": "truncated"}),
        )
    }

    fn rename(&mut self, from: &str, to: &str) -> &mut Self {
        self.audit(
            "fs.rename",
            true,
            json!({"path": Self::named(from), "path2": Self::named(to)}),
        )
    }

    fn unlink(&mut self, path: &str) -> &mut Self {
        self.audit("fs.unlink", true, json!({"path": Self::named(path)}))
    }

    /// A write-class result whose path the observer could not name.
    fn unnamed_write(&mut self) -> &mut Self {
        self.audit(
            "fs.write",
            true,
            json!({
                "path": {"kind": "unavailable", "reason": "dirfd_unresolved"},
                "action": "opened_for_mutation",
            }),
        )
    }

    /// A refused write outside every known root: a digest, never a name.
    fn refused_write(&mut self) -> &mut Self {
        self.audit(
            "fs.deny",
            false,
            json!({
                "path": {
                    "kind": "digest",
                    "digest": format!("sha256:{}", "d".repeat(64)),
                    "reason": "outside_known_roots",
                },
                "attempted_operation": "fs.write",
            }),
        )
    }

    fn audit_connect(&mut self) -> &mut Self {
        self.audit("net.connect", true, json!({"path": Self::named("sock")}))
    }

    fn proxy(
        &mut self,
        destination: Option<&str>,
        allow: bool,
        connected: bool,
        reason: &str,
        credentials: &[&str],
    ) -> &mut Self {
        let mut fields = json!({
            "transport": "http",
            "origin": null,
            "origin_verification": null,
            "request_id": self.seq.get("proxy").copied().unwrap_or(0) + 1,
            "kind": "connect",
            "destination": destination,
            "reason": reason,
            "connected_address": if connected { json!("192.0.2.10:443") } else { Value::Null },
            "discarded_bytes": 0,
            "end": if connected { json!("upstream_closed") } else { Value::Null },
        });
        if !credentials.is_empty() {
            fields["credentials"] = json!(credentials);
        }
        self.push(
            "proxy",
            "net.connect",
            json!(if allow { "allow" } else { "deny" }),
            json!({
                "ok": connected, "return_value": null, "errno": null,
                "completion": "proxy_close", "bytes_in": 0, "bytes_out": 0, "duration_ms": 1,
            }),
            fields,
        )
    }

    fn vault(&mut self, id: &str) -> &mut Self {
        let credentials = self.receipt["credentials"]
            .as_array_mut()
            .expect("a credentials list");
        credentials.push(json!({
            "id": id, "mode": "vault", "digest": null,
            "digest_unavailable_reason": "never_staged", "never_staged": true,
        }));
        self
    }

    /// Frames per class in this journal.
    fn class_counts(&self) -> BTreeMap<&'static str, u64> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            if let Some(class) = class_of(event) {
                *counts.entry(class).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Sets every active class's `observed_count` to the journal's count,
    /// as the producer's delivered-frame counts are.
    fn sync(&mut self) -> &mut Self {
        let counts = self.class_counts();
        for class in ["exec", "fs.write", "fs.deny", "net", "proxy.net"] {
            if self.receipt["coverage"][class]["status"] == "active" {
                self.receipt["coverage"][class]["observed_count"] =
                    json!(counts.get(class).copied().unwrap_or(0));
            }
        }
        self
    }

    fn lines_of(events: &[Value]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for event in events {
            bytes.extend(serde_json::to_vec(event).expect("serializes"));
            bytes.push(b'\n');
        }
        bytes
    }

    /// The final receipt note, at the current clock.
    fn final_note(&self) -> Value {
        let seq = self.seq.get("wrapper").copied().unwrap_or(0) + 1;
        json!({
            "schema": "ukai.event/1",
            "attempt_id": ATTEMPT,
            "source": "wrapper",
            "source_seq": seq,
            "observed_at": "2026-09-21T12:00:00Z",
            "monotonic_ns": self.ns.to_string(),
            "operation": "jail.receipt",
            "stage": "result",
            "decision": null,
            "outcome": Self::wrapper_outcome(),
            "fields": {"phase": self.receipt["phase"], "receipt_digest": digest(&self.receipt)},
        })
    }

    /// The complete journal: every frame, then the final receipt's note.
    fn journal(&self) -> Vec<u8> {
        let mut events = self.events.clone();
        events.push(self.final_note());
        Self::lines_of(&events)
    }

    /// The journal without its final note: incomplete, every line whole.
    fn journal_without_note(&self) -> Vec<u8> {
        Self::lines_of(&self.events)
    }

    fn summary(&self) -> Summary {
        summary::summary(&self.receipt, Journal::Bytes(&self.journal()))
    }

    fn summary_of(&self, journal: &[u8]) -> Summary {
        summary::summary(&self.receipt, Journal::Bytes(journal))
    }
}

fn texts(summary: &Summary) -> Vec<String> {
    summary.lines.iter().map(|line| line.text.clone()).collect()
}

#[track_caller]
fn assert_lines(summary: &Summary, expected: &[&str]) {
    let actual = texts(summary);
    assert_eq!(
        actual,
        expected,
        "\nactual:\n{}\nexpected:\n{}",
        actual.join("\n"),
        expected.join("\n")
    );
}

fn facts<'a>(summary: &'a Summary, line: &str) -> &'a Value {
    &summary
        .lines
        .iter()
        .find(|candidate| candidate.line == line)
        .unwrap_or_else(|| panic!("no {line} line in {:#?}", texts(summary)))
        .facts
}

/// The A01-style clean run every golden case below varies.
fn clean_agent() -> Fixture {
    let mut fixture = Fixture::agent();
    fixture.vault("api");
    fixture.lifecycle("prepared").at(2_000_000_000);
    fixture.lifecycle("exec_confirmed");
    fixture.credential_note("api", "loaded", true);
    fixture.exec();
    fixture
        .create("src/a.rs")
        .open_write("src/a.rs")
        .open_write("src/b.rs")
        .truncate("c.txt")
        .rename("tmp", "d.txt")
        .unlink("old.txt")
        .refused_write();
    for _ in 0..3 {
        fixture.proxy(
            Some("api.example.test:443"),
            true,
            true,
            "relayed",
            &["api"],
        );
    }
    fixture.proxy(
        Some("github.com:443"),
        false,
        false,
        "host_not_allowed",
        &[],
    );
    fixture.exit();
    fixture.sync();
    fixture.at(223_000_000_000);
    fixture
}

// ===========================================================================
// K45: golden fixtures, receipt plus journal to exact lines
// ===========================================================================

#[test]
fn k45_a_clean_settled_run() {
    let fixture = clean_agent();
    let summary = fixture.summary();
    assert_eq!(summary.journal, JournalState::Complete);
    assert_lines(
        &summary,
        &[
            "settled · exited 0 · 3m41s exec→settled · survivors: none (verified)",
            "workspace: 3 paths opened for writing, 2 in renames, 1 removed · 1 refused write",
            "network: allowed api.example.test:443 (3) · denied github.com:443 (1)",
            "credential api: vault, never staged · used on 3 proxy results · 0 credential refusals",
            "evidence: 6/6 classes active, no gaps · reads and file contents are not observed",
        ],
    );
    assert_eq!(summary.receipt_digest, Some(digest(&fixture.receipt)));
}

#[test]
fn k45_observation_off() {
    let mut fixture = Fixture::from(example("receipt-agent-proxy-only.json"));
    fixture.lifecycle("exec_confirmed");
    fixture.proxy(Some("api.example.test:443"), true, true, "relayed", &[]);
    fixture.sync();
    fixture.at(63_100_000_000);
    assert_lines(
        &fixture.summary(),
        &[
            "settled · exited 0 · 1m03s exec→settled · survivors: none (verified)",
            "workspace: not observed (--observe off)",
            "network: allowed api.example.test:443 (1)",
            "credentials fixture.auth: copy_rw, staged (readable by the agent); \
             fixture.config: bind_ro, staged (readable by the agent)",
            "evidence: observation off: exec, file and connect classes not observed",
            "limits: not applied: pids (512)",
        ],
    );
}

#[test]
fn k45_degraded_with_gaps() {
    let mut fixture = Fixture::from(example("receipt-settled-unknown.json"));
    fixture.lifecycle("exec_confirmed");
    fixture.exec().open_write("a.txt").open_write("b.txt");
    let summary = fixture.summary();
    assert_eq!(summary.journal, JournalState::Complete);
    assert_lines(
        &summary,
        &[
            "settled · outcome unknown · 4ms exec→settled · survivors: none (verified) · \
             errors: evidence_lost",
            "workspace: at least 2 paths opened for writing",
            "network: none",
            "evidence: 1/6 classes active · exec degraded (fixture_exec_confirmation_lost, \
             lost unknown) · fs.write degraded (fixture_exec_confirmation_lost, lost unknown) · \
             fs.deny degraded (fixture_exec_confirmation_lost, lost unknown) · net degraded \
             (fixture_exec_confirmation_lost, lost unknown) · proxy.net not observed · reads \
             and file contents are not observed",
            "limits: not applied: pids (256)",
        ],
    );
    assert_eq!(facts(&summary, "workspace")["bound"], "at_least");
}

#[test]
fn k45_refused_before_exec() {
    // The platform refusal: no boundary, no journal.
    let receipt = example("receipt-macos-refused.json");
    assert_lines(
        &summary::summary(&receipt, Journal::Absent),
        &[
            "NOT settled (refused) · 0ms attempt (wall clock) · survivors: NOT verified · \
             errors: unsupported_platform",
            "workspace: not observed",
            "network: not applied",
            "evidence: observer not attached · 0/6 classes active · exec, fs.write, fs.deny, \
             net, proxy.net, limits not observed · journal absent",
        ],
    );
    // An exec that failed after release: the tree was verified empty.
    let mut fixture = Fixture::from(example("receipt-exec-refused.json"));
    fixture.exec();
    fixture.sync();
    assert_lines(
        &fixture.summary(),
        &[
            "NOT settled (refused) · exec failed · survivors: none (verified) · errors: \
             exec_failed",
            "workspace: 0 paths opened for writing",
            "network: none",
            "evidence: 5/6 classes active · proxy.net not observed · reads and file contents \
             are not observed",
            "limits: not applied: pids (256)",
        ],
    );
}

/// The receipt-tool example, left enforced with its tree unverifiable.
fn tree_unknown() -> Fixture {
    let mut fixture = Fixture::from(example("receipt-tool.json"));
    fixture.receipt["phase"] = json!("enforced");
    fixture.receipt["outcome"] = json!({
        "kind": "unknown", "code": null, "signal": null, "cause": null, "error": null,
    });
    fixture.receipt["lifetime"]["tree_empty"] = Value::Null;
    fixture.receipt["lifetime"]["verified_at"] = Value::Null;
    fixture.receipt["lifetime"]["integrity"] = json!("pending");
    fixture.receipt["errors"] = json!([{
        "code": "tree_unknown", "stage": "reconciling", "message": "fixture",
        "key_path": null, "remediation_category": "inspect_state",
    }]);
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        fixture.receipt["coverage"][class] = json!({
            "status": "degraded", "sources": ["audit"], "observed_count": null,
            "gaps": [{
                "classes": [class], "source": "audit", "start_ns": "0", "end_ns": null,
                "reason": "trace_transport_loss", "lost_count": null,
            }],
        });
    }
    fixture.receipt["observer"]["sources"]["audit"] = json!("degraded");
    fixture.lifecycle("exec_confirmed");
    fixture
        .exec()
        .open_write("a.txt")
        .open_write("b.txt")
        .open_write("c.txt");
    fixture
}

#[test]
fn k45_unsettled_with_tree_unknown() {
    let fixture = tree_unknown();
    // The run never settled: no final note names this receipt.
    let summary = fixture.summary_of(&fixture.journal_without_note());
    assert_eq!(summary.journal, JournalState::Incomplete);
    assert_lines(
        &summary,
        &[
            "NOT settled (enforced) · outcome unknown · survivors: NOT verified · errors: \
             tree_unknown: run ukai-jail gc",
            "workspace: at least 3 paths opened for writing",
            "network: none",
            "evidence: 1/6 classes active · exec degraded (trace_transport_loss, lost unknown) \
             · fs.write degraded (trace_transport_loss, lost unknown) · fs.deny degraded \
             (trace_transport_loss, lost unknown) · net degraded (trace_transport_loss, lost \
             unknown) · proxy.net not observed · journal incomplete: counts above are lower \
             bounds · reads and file contents are not observed",
            "limits: not applied: pids (256)",
        ],
    );
}

#[test]
fn k45_none() {
    let mut fixture = Fixture::from(example("receipt-none.json"));
    fixture.lifecycle("exec_confirmed");
    fixture.exec().create("out.txt");
    fixture.sync();
    fixture.at(4_300_000_000);
    assert_lines(
        &fixture.summary(),
        &[
            "settled · exited 0 · 4.2s exec→settled · survivors: none (verified, registered \
             cgroup only)",
            "workspace: 1 path opened for writing",
            "network: host, not observed",
            "evidence: 5/6 classes active · proxy.net not observed · reads and file contents \
             are not observed",
            "uncontained (none): nothing above was enforced",
        ],
    );
}

#[test]
fn k45_trace_fd_streams_the_journal() {
    let fixture = clean_agent();
    let summary = summary::summary(&fixture.receipt, Journal::Streamed(5));
    assert_eq!(summary.journal, JournalState::Streamed(5));
    assert_lines(
        &summary,
        &[
            "settled · exited 0 · 1.0s attempt (wall clock) · survivors: none (verified)",
            "workspace: journal streamed to fd 5",
            "network: proxy, journal streamed to fd 5",
            "credential api: vault, never staged · uses: journal streamed to fd 5",
            "evidence: 6/6 classes active · journal streamed to fd 5 · reads and file contents \
             are not observed",
        ],
    );
}

#[test]
fn k45_an_incomplete_journal_makes_every_count_a_lower_bound() {
    let fixture = clean_agent();
    // A torn final frame: the writer stopped mid-frame.
    let mut torn = fixture.journal_without_note();
    torn.extend_from_slice(b"{\"schema\":\"ukai.event/1\",\"source\":\"au");
    let summary = fixture.summary_of(&torn);
    assert_eq!(summary.journal, JournalState::Incomplete);
    assert_lines(
        &summary,
        &[
            "settled · exited 0 · survivors: none (verified)",
            "workspace: at least 3 paths opened for writing, at least 2 in renames, at least 1 \
             removed · at least 1 refused write",
            "network: allowed api.example.test:443 (at least 3) · denied github.com:443 (at \
             least 1)",
            "credential api: vault, never staged · used on at least 3 proxy results",
            "evidence: 6/6 classes active · journal incomplete: counts above are lower bounds · \
             reads and file contents are not observed",
        ],
    );
}

#[test]
fn k45_best_effort_after_a_loss() {
    let mut fixture = clean_agent();
    fixture.receipt["policy"]["evidence"] = json!("best-effort");
    fixture.receipt["observer"]["sources"]["wrapper"] = json!("degraded");
    for class in ["exec", "fs.write", "fs.deny", "net", "proxy.net"] {
        let source = if class == "proxy.net" {
            "proxy"
        } else {
            "audit"
        };
        fixture.receipt["coverage"][class] = json!({
            "status": "degraded", "sources": [source], "observed_count": null,
            "gaps": [{
                "classes": [class], "source": source, "start_ns": "150000000",
                "end_ns": null, "reason": "trace_transport_loss", "lost_count": 7,
            }],
        });
    }
    // The sink kept a prefix, its loss note and the final receipt note.
    fixture.events.truncate(6);
    fixture.push(
        "wrapper",
        "note",
        Value::Null,
        Fixture::wrapper_outcome(),
        json!({
            "kind": "coverage_gap", "classes": ["exec", "fs.write", "fs.deny", "net", "proxy.net"],
            "source": "wrapper", "start_ns": "150000000", "end_ns": null,
            "reason": "trace_transport_loss", "lost_count": 7,
        }),
    );
    fixture.at(223_000_000_000);
    let summary = fixture.summary();
    assert_eq!(summary.journal, JournalState::Complete);
    assert_lines(
        &summary,
        &[
            "settled · exited 0 · 3m41s exec→settled · survivors: none (verified)",
            "workspace: at least 1 path opened for writing",
            "network: proxy, none recorded (a lower bound)",
            "credential api: vault, never staged · used on at least 0 proxy results",
            "evidence: 1/6 classes active · exec degraded (trace_transport_loss, lost 7) · \
             fs.write degraded (trace_transport_loss, lost 7) · fs.deny degraded \
             (trace_transport_loss, lost 7) · net degraded (trace_transport_loss, lost 7) · \
             proxy.net degraded (trace_transport_loss, lost 7) · reads and file contents are not \
             observed",
        ],
    );
}

// ===========================================================================
// K46: never overclaims (a property over generated journals)
// ===========================================================================

/// A small deterministic generator (xorshift64*), so the property needs no
/// new dependency and every failure names a reproducible case.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[usize::try_from(self.below(items.len() as u64)).unwrap_or(0)]
    }
}

/// What really happened, computed from every frame the run produced, by
/// this test's own reading of §4.2.
#[derive(Debug, Default)]
struct Truth {
    opened: BTreeSet<String>,
    renamed: BTreeSet<String>,
    removed: BTreeSet<String>,
    unnamed: u64,
    refused: u64,
    allowed: BTreeMap<String, (u64, u64)>,
    denied: BTreeMap<(String, String), u64>,
    uses: u64,
    refusals: u64,
}

fn truth_of(events: &[Value]) -> Truth {
    let mut truth = Truth::default();
    let named =
        |path: &Value| (path["kind"] == "workspace_relative").then(|| path["value"].to_string());
    for event in events {
        let fields = &event["fields"];
        let ok = event["outcome"]["ok"] == true;
        match (
            event["source"].as_str().unwrap_or(""),
            event["operation"].as_str().unwrap_or(""),
        ) {
            ("audit", operation @ ("fs.create" | "fs.write" | "fs.rename" | "fs.unlink")) if ok => {
                if operation == "fs.write"
                    && !matches!(
                        fields["action"].as_str(),
                        Some("opened_for_mutation" | "truncated")
                    )
                {
                    continue;
                }
                let paths = [&fields["path"], &fields["path2"]];
                if paths
                    .iter()
                    .any(|path| matches!(path["kind"].as_str(), Some("unavailable" | "digest")))
                {
                    truth.unnamed += 1;
                }
                for path in paths {
                    if let Some(key) = named(path) {
                        match operation {
                            "fs.rename" => truth.renamed.insert(key),
                            "fs.unlink" => truth.removed.insert(key),
                            _ => truth.opened.insert(key),
                        };
                    }
                }
            }
            ("audit", "fs.deny") => {
                if matches!(
                    fields["attempted_operation"].as_str(),
                    Some("fs.create" | "fs.write" | "fs.rename" | "fs.unlink")
                ) {
                    truth.refused += 1;
                }
            }
            ("proxy", "net.connect") => {
                let destination = fields["destination"].as_str().unwrap_or("").to_owned();
                let reason = fields["reason"].as_str().unwrap_or("").to_owned();
                if event["decision"] == "allow" {
                    let entry = truth.allowed.entry(destination).or_default();
                    entry.0 += 1;
                    if !ok {
                        entry.1 += 1;
                    }
                } else {
                    *truth
                        .denied
                        .entry((destination, reason.clone()))
                        .or_default() += 1;
                }
                if reason.starts_with("credential_") {
                    truth.refusals += 1;
                }
                if fields["credentials"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id == "api"))
                {
                    truth.uses += 1;
                }
            }
            _ => {}
        }
    }
    truth
}

/// One count of a summary's facts against the truth: an exact count equals
/// it, a lower bound does not exceed it, and every other bound has no
/// number at all.
#[track_caller]
fn check_count(context: &str, bound: &Value, count: &Value, truth: u64) {
    match bound.as_str() {
        Some("exact") => assert_eq!(count.as_u64(), Some(truth), "{context}: exact"),
        Some("at_least") => assert!(
            count.as_u64().is_some_and(|n| n <= truth),
            "{context}: at least {count} of {truth}"
        ),
        _ => assert!(count.is_null(), "{context}: {bound} with a number {count}"),
    }
}

/// Every maximal run of digits in `text` that is a count is preceded by
/// `at least `. A port (after `:`), a list's `+N more` and a digit inside a
/// name are not counts of evidence.
fn every_number_is_a_lower_bound(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let before = index.checked_sub(1).map(|at| bytes[at]);
            let counted = !matches!(before, Some(b':' | b'+'))
                && !before.is_some_and(|byte| byte.is_ascii_alphanumeric());
            if counted && !text[..index].ends_with("at least ") {
                return false;
            }
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    true
}

#[test]
fn k46_the_summary_never_claims_more_than_the_evidence() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let paths = ["a", "b", "c", "dir/d", "e.txt"];
    let hosts = ["a.test:443", "b.test:443", "c.test:80"];
    // How often each bound was reached, so the property cannot pass on
    // cases that never claimed anything.
    let mut reached: BTreeMap<String, u64> = BTreeMap::new();
    for case in 0..600 {
        // 1. The run as it happened.
        let mut run = Fixture::agent();
        run.vault("api");
        run.lifecycle("exec_confirmed");
        run.credential_note("api", "loaded", true);
        for _ in 0..rng.below(40) {
            match rng.below(12) {
                0 => {
                    run.exec();
                }
                1 => {
                    let path = rng.pick(&paths);
                    run.create(path);
                }
                2 => {
                    let path = rng.pick(&paths);
                    run.open_write(path);
                }
                3 => {
                    let path = rng.pick(&paths);
                    run.truncate(path);
                }
                4 => {
                    let (from, to) = (rng.pick(&paths), rng.pick(&paths));
                    run.rename(from, to);
                }
                5 => {
                    let path = rng.pick(&paths);
                    run.unlink(path);
                }
                6 => {
                    run.unnamed_write();
                }
                7 => {
                    run.refused_write();
                }
                8 => {
                    run.audit_connect();
                }
                9 => {
                    let host = rng.pick(&hosts);
                    let connected = rng.chance(80);
                    run.proxy(Some(host), true, connected, "relayed", &["api"]);
                }
                10 => {
                    let host = rng.pick(&hosts);
                    run.proxy(Some(host), false, false, "host_not_allowed", &[]);
                }
                _ => {
                    run.proxy(
                        Some("a.test:443"),
                        false,
                        false,
                        "credential_placement_denied",
                        &[],
                    );
                }
            }
        }
        run.sync();
        let truth = truth_of(&run.events);

        // 2. What the receipt says about each class's evidence.
        let mut evidence = run.clone();
        let statuses = [
            "active",
            "active",
            "active",
            "degraded",
            "unsupported",
            "supported",
        ];
        let mut status_of = BTreeMap::new();
        for class in ["exec", "fs.write", "fs.deny", "net", "proxy.net"] {
            let status = rng.pick(&statuses);
            status_of.insert(class, status);
            let source = if class == "proxy.net" {
                "proxy"
            } else {
                "audit"
            };
            evidence.receipt["coverage"][class] = match status {
                "active" => evidence.receipt["coverage"][class].clone(),
                "degraded" => json!({
                    "status": "degraded", "sources": [source], "observed_count": null,
                    "gaps": [{"classes": [class], "source": source, "start_ns": "0",
                              "end_ns": null, "reason": "queue_full", "lost_count": null}],
                }),
                other => json!({
                    "status": other,
                    "sources": if other == "supported" { json!([source]) } else { json!([]) },
                    "observed_count": null, "gaps": [],
                }),
            };
        }

        // 3. The journal the reader gets: a degraded class may have lost
        // frames; the sink may stop early, tear its last frame, lose its
        // final note, or (a defect) drop or repeat a frame of an active class.
        let mut kept: Vec<Value> = evidence
            .events
            .iter()
            .filter(|event| {
                class_of(event).is_none_or(|class| status_of[class] != "degraded") || rng.chance(60)
            })
            .cloned()
            .collect();
        let shape = rng.below(6);
        let mut journal = match shape {
            0 => {
                // Complete.
                evidence.events = kept;
                evidence.journal()
            }
            1 => {
                // A prefix: the sink stopped, no final note.
                let len = usize::try_from(rng.below(kept.len() as u64 + 1)).unwrap_or(0);
                kept.truncate(len);
                Fixture::lines_of(&kept)
            }
            2 => {
                // A torn final frame.
                evidence.events = kept;
                let mut bytes = evidence.journal();
                bytes.truncate(bytes.len().saturating_sub(7));
                bytes
            }
            3 => {
                // A frame dropped, the final note kept.
                if !kept.is_empty() {
                    let index = usize::try_from(rng.below(kept.len() as u64)).unwrap_or(0);
                    kept.remove(index);
                }
                evidence.events = kept;
                evidence.journal()
            }
            4 => {
                // A frame repeated, the final note kept.
                if !kept.is_empty() {
                    let index = usize::try_from(rng.below(kept.len() as u64)).unwrap_or(0);
                    kept.insert(index, kept[index].clone());
                }
                evidence.events = kept;
                evidence.journal()
            }
            _ => {
                // A corrupt line in the middle.
                evidence.events = kept;
                let bytes = evidence.journal();
                let mut lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
                let index = usize::try_from(rng.below(lines.len() as u64)).unwrap_or(0);
                lines.insert(index, b"not a frame\n");
                lines.concat()
            }
        };
        if journal.is_empty() && rng.chance(50) {
            journal.clear();
        }
        let summary = summary::summary(&evidence.receipt, Journal::Bytes(&journal));
        let context = format!("case {case} shape {shape} statuses {status_of:?}");

        // 4. Every count against the truth.
        let complete = summary.journal == JournalState::Complete;
        let workspace = facts(&summary, "workspace");
        for bound in [&workspace["bound"], &facts(&summary, "network")["bound"]] {
            *reached
                .entry(bound.as_str().unwrap_or("").to_owned())
                .or_default() += 1;
        }
        let write_bound = &workspace["bound"];
        for (key, value) in [
            ("opened_for_writing", truth.opened.len() as u64),
            ("renamed", truth.renamed.len() as u64),
            ("removed", truth.removed.len() as u64),
            ("unnamed", truth.unnamed),
        ] {
            check_count(
                &format!("{context} {key}"),
                write_bound,
                &workspace[key],
                value,
            );
        }
        check_count(
            &format!("{context} refused"),
            &workspace["refused_bound"],
            &workspace["refused"],
            truth.refused,
        );
        for (class, bound) in [
            ("fs.write", write_bound),
            ("fs.deny", &workspace["refused_bound"]),
        ] {
            match status_of[class] {
                "degraded" => assert_ne!(bound, "exact", "{context}: {class} degraded"),
                "unsupported" | "supported" => {
                    assert_eq!(bound, "not_observed", "{context}: {class} unobserved");
                }
                _ => {}
            }
            if !complete {
                assert_ne!(bound, "exact", "{context}: incomplete journal");
            }
        }
        let network = facts(&summary, "network");
        let proxy_bound = &network["bound"];
        if !complete || status_of["proxy.net"] == "degraded" {
            assert_ne!(proxy_bound, "exact", "{context}: proxy.net");
        }
        if matches!(status_of["proxy.net"], "unsupported" | "supported") {
            assert_eq!(proxy_bound, "not_observed", "{context}: proxy.net");
        }
        for entry in network["allowed"].as_array().expect("a list") {
            let destination = entry["destination"].as_str().unwrap_or("");
            let (results, failed) = truth.allowed.get(destination).copied().unwrap_or_default();
            check_count(&context, proxy_bound, &entry["results"], results);
            check_count(&context, proxy_bound, &entry["connect_failed"], failed);
        }
        for entry in network["denied"].as_array().expect("a list") {
            let key = (
                entry["destination"].as_str().unwrap_or("").to_owned(),
                entry["reason"].as_str().unwrap_or("").to_owned(),
            );
            let results = truth.denied.get(&key).copied().unwrap_or_default();
            check_count(&context, proxy_bound, &entry["results"], results);
        }
        let credentials = facts(&summary, "credentials");
        let api = &credentials["credentials"][0];
        check_count(
            &format!("{context} uses"),
            &api["uses_bound"],
            &api["uses"],
            truth.uses,
        );
        check_count(
            &format!("{context} refusals"),
            &credentials["refusals_bound"],
            &credentials["refusals"],
            truth.refusals,
        );

        // 5. The text: lower bounds say so, unobserved classes print no
        // number, and nothing about reads is ever counted.
        let lines = texts(&summary);
        let line = |name: &str| {
            summary
                .lines
                .iter()
                .find(|candidate| candidate.line == name)
                .map(|candidate| candidate.text.clone())
                .unwrap_or_default()
        };
        if write_bound == "at_least"
            && (workspace["refused_bound"] == "at_least" || workspace["refused"] == 0)
        {
            assert!(
                every_number_is_a_lower_bound(&line("workspace")),
                "{context}: {}",
                line("workspace")
            );
        }
        if write_bound != "exact" && write_bound != "at_least" {
            assert!(
                !line("workspace").contains("opened for writing"),
                "{context}: {}",
                line("workspace")
            );
        }
        if proxy_bound == "at_least" {
            assert!(
                every_number_is_a_lower_bound(&line("network")),
                "{context}: {}",
                line("network")
            );
        }
        if proxy_bound == "exact" {
            assert!(!line("network").contains("at least"), "{context}");
        }
        for text in &lines {
            let rest = text.replace("reads and file contents are not observed", "");
            assert!(
                !rest.to_lowercase().contains("read"),
                "{context}: a read is mentioned: {text}"
            );
        }
    }
    // A dropped frame of an active class is the one way to a disagreement
    // here (a repeat now ends the count), so it is rarer; K47 seeds it.
    for (bound, least) in [
        ("exact", 20),
        ("at_least", 20),
        ("not_observed", 20),
        ("disagree", 1),
    ] {
        assert!(
            reached.get(bound).copied().unwrap_or(0) >= least,
            "too few cases reached {bound}: {reached:?}"
        );
    }
}

// ===========================================================================
// K47: per-class totals equal the receipt's counts
// ===========================================================================

/// The clean run with one result in every journaled class.
fn every_class() -> Fixture {
    let mut fixture = clean_agent();
    fixture.at(3_000_000_000).audit_connect();
    fixture.sync();
    fixture.at(223_000_000_000);
    fixture
}

#[test]
fn k47_class_totals_equal_the_receipt_counts() {
    let fixture = every_class();
    let counts = fixture.class_counts();
    for class in ["exec", "fs.write", "fs.deny", "net", "proxy.net"] {
        assert!(counts[class] > 0, "{class} has frames");
        assert_eq!(
            fixture.receipt["coverage"][class]["observed_count"],
            json!(counts[class]),
            "{class}"
        );
    }
    let summary = fixture.summary();
    assert_eq!(summary.journal, JournalState::Complete);
    assert_eq!(facts(&summary, "evidence")["disagree"], json!([]));
    assert_eq!(facts(&summary, "workspace")["bound"], "exact");
    assert_eq!(facts(&summary, "network")["bound"], "exact");
}

/// Adds one frame of a class to a fixture's journal.
type Seed = fn(&mut Fixture);

#[test]
fn k47_a_seeded_disagreement_prints_the_disagreement_and_no_number() {
    let extra: [(&str, Seed); 5] = [
        ("exec", |f| {
            f.exec();
        }),
        ("fs.write", |f| {
            f.open_write("extra");
        }),
        ("fs.deny", |f| {
            f.refused_write();
        }),
        ("net", |f| {
            f.audit_connect();
        }),
        ("proxy.net", |f| {
            f.proxy(
                Some("api.example.test:443"),
                true,
                true,
                "relayed",
                &["api"],
            );
        }),
    ];
    for (class, add) in extra {
        let mut fixture = every_class();
        // The receipt keeps its counts; the journal gains one frame.
        add(&mut fixture);
        fixture.at(223_000_000_000);
        let summary = fixture.summary();
        assert_eq!(summary.journal, JournalState::Complete, "{class}");
        assert_eq!(facts(&summary, "evidence")["disagree"], json!([class]));
        let text = texts(&summary).join("\n");
        assert!(
            text.contains(&format!("journal and receipt disagree on {class}")),
            "{class}: {text}"
        );
        assert!(text.contains("5/6 classes active"), "{class}: {text}");
        let workspace = facts(&summary, "workspace");
        let network = facts(&summary, "network");
        let credentials = facts(&summary, "credentials");
        match class {
            "fs.write" => {
                assert_eq!(workspace["bound"], "disagree");
                assert!(workspace["opened_for_writing"].is_null());
                assert!(!text.contains("opened for writing"), "{text}");
            }
            "fs.deny" => {
                assert_eq!(workspace["refused_bound"], "disagree");
                assert!(workspace["refused"].is_null());
                assert!(!text.contains("refused write "), "{text}");
            }
            "proxy.net" => {
                assert_eq!(network["bound"], "disagree");
                assert_eq!(network["allowed"], json!([]));
                assert!(credentials["credentials"][0]["uses"].is_null());
                assert!(credentials["refusals"].is_null());
                assert!(!text.contains("used on"), "{text}");
                assert!(!text.contains("allowed "), "{text}");
            }
            _ => {
                assert_eq!(workspace["bound"], "exact", "{class}");
                assert_eq!(network["bound"], "exact", "{class}");
            }
        }
    }
}

/// The recorded benchmark attempts checked into the tree: real receipts and
/// journals, whose per-class totals agree (no disagreement is printed and
/// their numbers are exact).
#[test]
fn k47_recorded_attempts_agree_with_their_receipts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/benchmarks");
    for attempt in [
        "credentials/2026-10-13-next/validation/oauth-auto-ouro-01",
        "jail/results/release-preview-2026-10-10/public-install",
        "credentials/2026-10-13-next/validation/pi-clone3-pilot-fixed-02/31-vault-before",
    ] {
        let directory = root.join(attempt);
        let receipt: Value =
            serde_json::from_slice(&std::fs::read(directory.join("jail.json")).unwrap()).unwrap();
        let journal = std::fs::read(directory.join("trace.ndjson")).unwrap();
        let summary = summary::summary(&receipt, Journal::Bytes(&journal));
        assert_eq!(summary.journal, JournalState::Complete, "{attempt}");
        assert_eq!(
            facts(&summary, "evidence")["disagree"],
            json!([]),
            "{attempt}"
        );
        assert_eq!(facts(&summary, "workspace")["bound"], "exact", "{attempt}");
        // Built before proxy results named their credentials: a vault
        // credential's uses are not recorded, never zero.
        let credentials = summary
            .lines
            .iter()
            .find(|line| line.line == "credentials")
            .map(|line| line.facts["credentials"].clone())
            .unwrap_or_default();
        for credential in credentials.as_array().into_iter().flatten() {
            assert_eq!(credential["uses_bound"], "not_recorded", "{attempt}");
            assert!(credential["uses"].is_null(), "{attempt}");
        }
    }
}

// ===========================================================================
// K48: escaping, list caps and the line bound
// ===========================================================================

/// No terminal-addressing character survives into a line.
#[track_caller]
fn assert_inert(line: &str) {
    for character in line.chars() {
        let code = u32::from(character);
        assert!(
            !(character.is_control()
                || matches!(code, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F | 0x061C)),
            "U+{code:04X} reached a terminal line: {line:?}"
        );
    }
}

#[test]
fn k48_child_chosen_strings_are_escaped() {
    let mut fixture = Fixture::agent();
    fixture.vault("api");
    fixture.credential_note("api", "loaded", true);
    let hostile = [
        "osc\u{1b}]52;c;AAAA\u{7}.test:443",
        "csi\u{9b}2J.test:443",
        "bidi\u{202e}txt.test:443",
        "line\nbreak.test:443",
        "del\u{7f}.test:443",
    ];
    for host in hostile {
        fixture.proxy(Some(host), true, true, "relayed", &[]);
        fixture.proxy(Some(host), false, false, "host_\u{1b}[31mred", &[]);
    }
    fixture.receipt["outcome"]["cause"] = json!("cause\u{1b}[2J");
    fixture.receipt["errors"] = json!([{
        "code": "code\u{7}\nforged", "stage": "running", "message": "m",
        "key_path": null, "remediation_category": "retry",
    }]);
    fixture.receipt["credentials"][0]["id"] = json!("id\u{1b}]0;title\u{7}");
    fixture.open_write("path\u{1b}[2Jname");
    fixture.sync();
    fixture.at(223_000_000_000);
    let summary = fixture.summary();
    let terminal = summary.terminal(Path::new("/state/attempts/att_x/jail\u{1b}[0m.json"));
    for line in &terminal {
        assert_inert(line);
    }
    let all = terminal.join("\n");
    assert!(
        all.contains("osc<U+001B>]52;c;AAAA<U+0007>.test:443"),
        "{all}"
    );
    assert!(all.contains("csi<U+009B>2J.test:443"), "{all}");
    assert!(all.contains("bidi<U+202E>txt.test:443"), "{all}");
    assert!(all.contains("cause<U+001B>[2J"), "{all}");
    assert!(all.contains("id<U+001B>]0;title<U+0007>"), "{all}");
    assert!(all.contains("jail<U+001B>[0m.json"), "{all}");
    // The JSON form keeps every value and spells no control character raw.
    let rendered = summary::json_text(&summary.to_json());
    assert_inert(&rendered.replace('\n', " "));
    let reparsed: Value = serde_json::from_str(&rendered).expect("the rendering is JSON");
    assert_eq!(reparsed, summary.to_json(), "escaping changed a value");
}

#[test]
fn k48_lists_truncate_and_the_terminal_form_has_at_most_eight_lines() {
    let mut fixture = every_class();
    for index in 0..7 {
        fixture.proxy(
            Some(&format!("h{index}.test:443")),
            true,
            true,
            "relayed",
            &[],
        );
        fixture.proxy(
            Some(&format!("d{index}.test:443")),
            false,
            false,
            "host_not_allowed",
            &[],
        );
    }
    for index in 0..6 {
        fixture.vault(&format!("extra{index}"));
    }
    fixture.receipt["errors"] = json!(
        (0..7)
            .map(|index| json!({
                "code": format!("error_{index}"), "stage": "running", "message": "m",
                "key_path": null, "remediation_category": "retry",
            }))
            .collect::<Vec<_>>()
    );
    fixture.receipt["applied"]["limits"] = json!([
        {"key": "wall", "requested": "1m", "required": true, "applied": true,
         "mechanism": "monotonic-deadline", "scope": "tree", "hit": true},
        {"key": "pids", "requested": "64", "required": false, "applied": false,
         "mechanism": null, "scope": null, "hit": null},
    ]);
    fixture.receipt["state_cleanup"] = json!("pending");
    fixture.receipt["child_protection"] = json!("unprotected");
    fixture.sync();
    fixture.at(223_000_000_000);
    let summary = fixture.summary();
    let terminal = summary.terminal(Path::new("/r/jail.json"));
    assert_eq!(terminal.len(), summary::MAX_TERMINAL_LINES, "{terminal:#?}");
    assert!(terminal.last().unwrap().starts_with("ukai-jail: receipt "));
    let network = &texts(&summary)[2];
    assert_eq!(network.matches(" +").count(), 2, "{network}");
    // Eight allowed destinations and eight denied ones: five each, then the
    // count of the rest.
    assert_eq!(network.matches("+3 more").count(), 2, "{network}");
    let status = &texts(&summary)[0];
    assert!(status.contains("+2 more"), "{status}");
    let credentials = &texts(&summary)[3];
    assert!(credentials.contains("+2 more"), "{credentials}");
    assert_lines(
        &Summary {
            lines: summary.lines[5..].to_vec(),
            ..summary.clone()
        },
        &[
            "limits: hit wall (1m) · not applied: pids (64)",
            "vendor state cleanup pending: run ukai-jail gc · uncontained (none): nothing above \
             was enforced",
        ],
    );
}

// ===========================================================================
// K53, the summary's side: use counts from `fields.credentials`
// ===========================================================================

#[test]
fn k53_uses_count_the_results_that_carried_the_credential() {
    let mut fixture = clean_agent();
    fixture.vault("other");
    fixture.credential_note("other", "loaded", true);
    // A request whose head reached the upstream before the credential was
    // revoked: a use and a refusal at once.
    fixture.proxy(
        Some("api.example.test:443"),
        false,
        true,
        "credential_revoked",
        &["api", "other"],
    );
    fixture.credential_note("api", "revoked", true);
    // A refused placement: no use.
    fixture.proxy(
        Some("api.example.test:443"),
        false,
        false,
        "credential_placement_denied",
        &[],
    );
    fixture.sync();
    fixture.at(223_000_000_000);
    let summary = fixture.summary();
    let credentials = facts(&summary, "credentials");
    assert_eq!(credentials["credentials"][0]["uses"], 4);
    assert_eq!(credentials["credentials"][0]["uses_bound"], "exact");
    assert_eq!(
        credentials["credentials"][0]["transitions"],
        json!(["loaded", "revoked"])
    );
    assert_eq!(credentials["credentials"][1]["uses"], 1);
    assert_eq!(credentials["refusals"], 2);
    assert_eq!(
        texts(&summary)[3],
        "credentials api: vault, never staged · used on 4 proxy results · revoked; other: \
         vault, never staged · used on 1 proxy result · 2 credential refusals"
    );

    // A journal whose credential notes lack the mark predates the field: its
    // silence is not a zero.
    let mut old = clean_agent();
    for event in &mut old.events {
        if let Some(fields) = event["fields"].as_object_mut() {
            fields.remove("uses_recorded");
            fields.remove("credentials");
        }
    }
    let summary = old.summary();
    assert!(
        texts(&summary)[3].contains("uses not recorded"),
        "{:?}",
        texts(&summary)
    );
    assert_eq!(
        facts(&summary, "credentials")["credentials"][0]["uses"],
        Value::Null
    );
}

// ===========================================================================
// The binary: a private state root, and a pseudo-terminal for stderr
// ===========================================================================

/// A private state root, configuration directory and workspace for the
/// built binary, with a cleared environment.
struct Bin {
    temp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

impl Bin {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = common::private_tempdir();
        let make = |name: &str, mode: u32| {
            let path = temp.path().join(name);
            std::fs::create_dir(&path).expect("a directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
            path
        };
        Bin {
            data: make("data", 0o700),
            config: make("config", 0o700),
            work: make("work", 0o755),
            temp,
        }
    }

    fn command(&self, arguments: &[&str]) -> std::process::Command {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ukai-jail"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.path())
            .env("UKAI_DATA_DIR", &self.data)
            .env("UKAI_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .stdin(std::process::Stdio::null())
            .args(arguments);
        command
    }

    fn output(&self, arguments: &[&str]) -> std::process::Output {
        self.command(arguments).output().expect("the binary runs")
    }

    /// Runs with stderr on a pseudo-terminal and stdout on a pipe: the exit
    /// code, what the terminal showed (CR removed), and stdout.
    fn on_terminal(&self, arguments: &[&str]) -> (Option<i32>, String, Vec<u8>) {
        use std::io::Read as _;
        use std::os::fd::{FromRawFd as _, OwnedFd};
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: both pointers are to live integers the call fills; the
        // name, termios and window size arguments may be null.
        let rc = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: openpty returned two fresh descriptors this test now owns.
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let mut command = self.command(arguments);
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::from(slave));
        let child = command.spawn().expect("the binary starts");
        // The command holds the parent's copy of the terminal's slave side
        // until it is dropped; the reader sees the end only after that.
        drop(command);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut terminal = std::fs::File::from(master);
            let mut seen = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                match terminal.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buffer[..n]),
                }
            }
            let _ = sender.send(seen);
        });
        let output = child.wait_with_output().expect("the binary ends");
        let seen = receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the terminal reaches its end");
        let text = String::from_utf8(seen)
            .expect("the terminal shows UTF-8")
            .replace('\r', "");
        (output.status.code(), text, output.stdout)
    }

    /// The single attempt directory a run made.
    fn attempts(&self) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(self.data.join("attempts"))
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default();
        found.sort();
        found
    }

    /// Writes a fixture as a recorded attempt.
    fn record(&self, fixture: &Fixture, journal: Option<&[u8]>) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let id = fixture.receipt["attempt_id"]
            .as_str()
            .expect("an attempt id")
            .to_owned();
        let attempts = self.data.join("attempts");
        std::fs::create_dir_all(&attempts).unwrap();
        std::fs::set_permissions(&attempts, std::fs::Permissions::from_mode(0o700)).unwrap();
        let attempt = attempts.join(&id);
        std::fs::create_dir_all(&attempt).unwrap();
        std::fs::set_permissions(&attempt, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            attempt.join("jail.json"),
            serde_json::to_vec_pretty(&fixture.receipt).unwrap(),
        )
        .unwrap();
        if let Some(journal) = journal {
            std::fs::write(attempt.join("trace.ndjson"), journal).unwrap();
        }
        attempt
    }
}

/// The `tail --summary` lines of the most recent attempt.
fn tail_summary(bin: &Bin, extra: &[&str]) -> (Option<i32>, String) {
    let mut arguments = vec!["tail", "--summary"];
    arguments.extend(extra);
    let output = bin.output(&arguments);
    (
        output.status.code(),
        String::from_utf8(output.stdout).expect("UTF-8"),
    )
}

/// What a run printed besides its summary: `printed` without the summary
/// lines, which must be its last lines.
#[track_caller]
fn without_summary(printed: &str, summary: &str) -> String {
    assert!(
        printed.ends_with(summary),
        "the summary is not the run's last output:\n--- printed\n{printed}--- summary\n{summary}"
    );
    printed[..printed.len() - summary.len()].to_owned()
}

/// A run whose target fails in a way every host reports with a receipt and
/// an error: macOS refuses execution, a Linux host either runs the shell or
/// refuses before exec.
const TARGET: [&str; 4] = [
    "--",
    "/bin/sh",
    "-c",
    "printf 'child-last-bytes\\n' >&2; exit 3",
];

// ===========================================================================
// K49/K50/K52: terminal-only printing, --quiet, config, and tail --summary
// ===========================================================================

#[test]
fn k50_k52_the_summary_prints_on_a_terminal_and_quiet_or_config_turns_it_off() {
    // The default: the summary and the receipt line, last, on the terminal,
    // and exactly the lines `tail --summary` prints for the same attempt.
    let bin = Bin::new();
    let mut run = vec!["run", "--workspace"];
    let work = bin.work.to_str().unwrap().to_owned();
    run.push(&work);
    run.extend(TARGET);
    let (code, printed, stdout) = bin.on_terminal(&run);
    let (tail_code, tailed) = tail_summary(&bin, &[]);
    assert_eq!(tail_code, Some(0));
    assert!(tailed.starts_with("ukai-jail: "), "{tailed}");
    let last = tailed.lines().last().expect("a receipt line");
    let attempt = bin.attempts().pop().expect("an attempt");
    assert_eq!(
        last,
        format!("ukai-jail: receipt {}", attempt.join("jail.json").display())
    );
    let rest = without_summary(&printed, &tailed);
    assert!(
        !String::from_utf8_lossy(&stdout).contains("ukai-jail:"),
        "the summary went to stdout"
    );
    assert!(tailed.lines().count() <= summary::MAX_TERMINAL_LINES);
    // K49: where the target ran, its last bytes precede the summary.
    if cfg!(target_os = "linux") && common::live() {
        assert!(rest.contains("child-last-bytes"), "{printed}");
    }

    // `--quiet`: neither summary nor receipt line; everything else the same.
    let quiet = Bin::new();
    let mut quiet_run = run.clone();
    quiet_run.insert(1, "--quiet");
    let quiet_work = quiet.work.to_str().unwrap().to_owned();
    quiet_run[3] = &quiet_work;
    let (quiet_code, quiet_printed, _) = quiet.on_terminal(&quiet_run);
    assert_eq!(quiet_code, code, "--quiet changed the exit code");
    assert_eq!(quiet_printed, rest, "--quiet changed what else was printed");
    assert!(
        !quiet_printed.contains("ukai-jail: receipt"),
        "{quiet_printed}"
    );

    // `[jail] summary = false` in config.toml: the same as --quiet.
    let configured = Bin::new();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = configured.config.join("config.toml");
        std::fs::write(&path, "[jail]\nsummary = false\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut configured_run = run.clone();
    let configured_work = configured.work.to_str().unwrap().to_owned();
    configured_run[2] = &configured_work;
    let (configured_code, configured_printed, _) = configured.on_terminal(&configured_run);
    assert_eq!(
        configured_code, code,
        "summary = false changed the exit code"
    );
    assert_eq!(configured_printed, rest);
    // ...and tail --summary still prints it on request.
    assert_eq!(tail_summary(&configured, &[]).0, Some(0));

    // An error the run raised still prints in every mode.
    if cfg!(target_os = "macos") {
        for shown in [&printed, &quiet_printed, &configured_printed] {
            assert!(shown.contains("unsupported_platform"), "{shown}");
        }
    }
}

#[test]
fn k49_k50_with_stderr_off_a_terminal_the_jail_adds_no_byte() {
    let bin = Bin::new();
    let work = bin.work.to_str().unwrap().to_owned();
    let mut run = vec!["run", "--workspace", &work];
    run.extend(TARGET);
    let jailed = bin.output(&run);
    assert!(
        !String::from_utf8_lossy(&jailed.stderr).contains("ukai-jail: receipt"),
        "{}",
        String::from_utf8_lossy(&jailed.stderr)
    );
    for line in String::from_utf8_lossy(&jailed.stderr).lines() {
        for name in ["settled", "workspace:", "network:", "evidence:"] {
            assert!(
                !line.contains(name),
                "a summary line reached a pipe: {line}"
            );
        }
    }
}

#[test]
fn k54_tail_summary_refuses_follow_and_since_and_a_missing_attempt_exits_1() {
    let bin = Bin::new();
    for extra in [&["--follow"][..], &["--since", "2026-09-21T12:00:00Z"][..]] {
        let (code, _) = tail_summary(&bin, extra);
        assert_eq!(code, Some(2), "{extra:?}");
    }
    let (code, printed) = tail_summary(&bin, &["--attempt", ATTEMPT]);
    assert_eq!(code, Some(1));
    assert!(printed.is_empty());
}

#[test]
fn k52_k54_tail_summary_renders_one_value_two_ways() {
    let bin = Bin::new();
    let fixture = every_class();
    let attempt = bin.record(&fixture, Some(&fixture.journal()));
    let (code, terminal) = tail_summary(&bin, &["--attempt", ATTEMPT]);
    assert_eq!(code, Some(0));
    let (code, json) = tail_summary(&bin, &["--attempt", ATTEMPT, "--json"]);
    assert_eq!(code, Some(0));
    let value: Value = serde_json::from_str(&json).expect("one JSON object");
    let errors: Vec<String> = common::validators()["jail-summary"]
        .iter_errors(&value)
        .map(|error| format!("{error} at {}", error.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}\n{value:#}");
    // The text fields are the terminal lines without their prefix, byte for
    // byte, and the receipt line becomes the attempt and its digest.
    let mut lines: Vec<&str> = terminal.lines().collect();
    assert_eq!(
        lines.pop(),
        Some(format!("ukai-jail: receipt {}", attempt.join("jail.json").display()).as_str())
    );
    let texts: Vec<String> = value["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| format!("ukai-jail: {}", line["text"].as_str().unwrap()))
        .collect();
    assert_eq!(texts, lines);
    assert_eq!(value["attempt_id"], ATTEMPT);
    assert_eq!(value["receipt_digest"], json!(digest(&fixture.receipt)));
    assert_eq!(value["journal"], "complete");
    // The same value the library computes.
    assert_eq!(value, fixture.summary().to_json());
    recompute(&attempt, &value);
}

/// K52: `summary_check.py` recomputes every number from the archived
/// receipt and journal, independently of this crate.
fn recompute(attempt: &Path, summary: &Value) {
    if !common::python() {
        return;
    }
    let script = specs().join("summary_check.py");
    let json = attempt.with_extension("summary.json");
    std::fs::write(&json, serde_json::to_vec(summary).unwrap()).unwrap();
    let output = Command::new(common::PYTHON)
        .arg("-I")
        .arg(&script)
        .arg(attempt)
        .arg(&json)
        .output()
        .expect("python runs");
    assert!(
        output.status.success(),
        "summary_check.py disagrees:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn k52_an_independent_script_recomputes_the_numbers() {
    let cases: Vec<(&str, Fixture, Vec<u8>)> = {
        let clean = every_class();
        let clean_journal = clean.journal();
        let unknown = tree_unknown();
        let unknown_journal = unknown.journal_without_note();
        let mut lossy = clean_agent();
        lossy.receipt["coverage"]["proxy.net"] = json!({
            "status": "degraded", "sources": ["proxy"], "observed_count": null,
            "gaps": [{"classes": ["proxy.net"], "source": "proxy", "start_ns": "0",
                      "end_ns": null, "reason": "proxy_drain_incomplete", "lost_count": 2}],
        });
        let lossy_journal = lossy.journal();
        let mut disagreeing = every_class();
        disagreeing.open_write("extra");
        disagreeing.at(223_000_000_000);
        let disagreeing_journal = disagreeing.journal();
        vec![
            ("clean", clean, clean_journal),
            ("unknown", unknown, unknown_journal),
            ("lossy", lossy, lossy_journal),
            ("disagreeing", disagreeing, disagreeing_journal),
        ]
    };
    for (name, fixture, journal) in cases {
        let bin = Bin::new();
        let attempt = bin.record(&fixture, Some(&journal));
        let (code, json) = tail_summary(&bin, &["--attempt", ATTEMPT, "--json"]);
        assert_eq!(code, Some(0), "{name}");
        recompute(&attempt, &serde_json::from_str(&json).expect(name));
    }
}

#[test]
fn k54_bounds_and_list_caps_in_the_json_form() {
    let mut fixture = every_class();
    for index in 0..70 {
        fixture.open_write(&format!("many/{index:03}"));
        fixture.proxy(
            Some(&format!("h{index:03}.test:443")),
            true,
            true,
            "relayed",
            &[],
        );
    }
    fixture.sync();
    fixture.at(223_000_000_000);
    let value = fixture.summary().to_json();
    let errors: Vec<String> = common::validators()["jail-summary"]
        .iter_errors(&value)
        .map(|error| format!("{error} at {}", error.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
    let workspace = &value["lines"][1]["facts"];
    assert_eq!(workspace["paths"].as_array().unwrap().len(), 64);
    // The clean run's six named paths and the seventy added, less 64 listed.
    assert_eq!(workspace["omitted"], 6 + 70 - 64);
    let network = &value["lines"][2]["facts"];
    assert_eq!(network["allowed"].as_array().unwrap().len(), 64);
    assert_eq!(network["omitted"], 71 - 64);

    // Degraded: every count at_least. Unobserved: null with not_observed.
    let mut degraded = tree_unknown();
    degraded.sync();
    let value = degraded
        .summary_of(&degraded.journal_without_note())
        .to_json();
    assert!(common::validators()["jail-summary"].is_valid(&value));
    let workspace = &value["lines"][1]["facts"];
    assert_eq!(workspace["bound"], "at_least");
    assert_eq!(workspace["opened_for_writing"], 3);
    let observation_off = Fixture::from(example("receipt-agent-proxy-only.json"));
    let value = observation_off.summary().to_json();
    assert!(common::validators()["jail-summary"].is_valid(&value));
    let workspace = &value["lines"][1]["facts"];
    assert_eq!(workspace["bound"], "not_observed");
    for key in [
        "opened_for_writing",
        "renamed",
        "removed",
        "unnamed",
        "refused",
    ] {
        assert!(workspace[key].is_null(), "{key}");
    }
}

// ===========================================================================
// K51: cost, and the scan cap
// ===========================================================================

/// An A01-sized journal: the milestone A01 receipt counted 13,091 `fs.write`
/// events.
fn a01_sized() -> Fixture {
    let mut fixture = clean_agent();
    for index in 0..13_091 {
        fixture.open_write(&format!(
            "node_modules/.cache/pkg-{}/file-{index}.js",
            index % 97
        ));
    }
    fixture.sync();
    fixture.at(900_000_000_000);
    fixture
}

#[test]
fn k51_an_a01_sized_journal_is_summarized_within_the_budget() {
    let bin = Bin::new();
    let fixture = a01_sized();
    let journal = fixture.journal();
    let attempt = bin.record(&fixture, Some(&journal));
    // The cold read and parse, as `run` does it after settling.
    let started = std::time::Instant::now();
    let summary = summary::summarize_attempt(&attempt, None).expect("summarized");
    let took = started.elapsed();
    println!(
        "K51: {} bytes, {} frames summarized in {took:?} ({} build)",
        journal.len(),
        fixture.events.len() + 1,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    assert_eq!(summary.journal, JournalState::Complete);
    assert_eq!(facts(&summary, "workspace")["bound"], "exact");
    // The budget is a release-build claim on the reference host (§4.1); a
    // debug build reports its time and is held to nothing.
    if !cfg!(debug_assertions) {
        assert!(
            took < std::time::Duration::from_millis(50),
            "{took:?} is over the 50 ms budget"
        );
    }
}

#[test]
fn k51_a_journal_past_the_scan_cap_prints_the_receipt_only_lines() {
    let bin = Bin::new();
    let fixture = clean_agent();
    let mut journal = fixture.journal();
    // Pad past 16 MiB with whole frames of the same attempt.
    let mut pad = Fixture::agent();
    pad.seq.insert("audit".to_owned(), 1_000);
    let long = "p".repeat(400);
    while journal.len() as u64 <= summary::SCAN_CAP {
        pad.events.clear();
        for _ in 0..1_000 {
            pad.open_write(&long);
        }
        journal.extend(Fixture::lines_of(&pad.events));
    }
    let attempt = bin.record(&fixture, Some(&journal));
    let summary = summary::summarize_attempt(&attempt, None).expect("summarized");
    let size = journal.len().div_ceil(1024 * 1024);
    assert_eq!(
        summary.journal,
        JournalState::NotScanned(journal.len() as u64)
    );
    assert_lines(
        &summary,
        &[
            "settled · exited 0 · 1.0s attempt (wall clock) · survivors: none (verified)",
            &format!("workspace: journal not scanned ({size} MiB)"),
            &format!("network: proxy, journal not scanned ({size} MiB)"),
            &format!(
                "credential api: vault, never staged · uses: journal not scanned ({size} MiB)"
            ),
            &format!(
                "evidence: 6/6 classes active · journal not scanned ({size} MiB) · reads and \
                 file contents are not observed"
            ),
        ],
    );
}
