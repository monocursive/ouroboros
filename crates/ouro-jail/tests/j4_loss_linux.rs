#![cfg(target_os = "linux")]
//! Loss handling end to end (jail-v1 §11.4, §15 O03, O05, R04, §16 "loss
//! handling").
//!
//! What is checked, live on the reference host:
//!
//! - R04: a real ptrace-observer loss — a thread parked in
//!   `openat(FIFO, O_WRONLY)` destroyed by a sibling's `execve`, which the
//!   observer can only report as `entry_abandoned` — stops a strict attempt
//!   (cause `evidence_loss`, exit 1) and lets a best-effort one run to its
//!   own end (its exit preserved, the loss an error of the run), in `tool`
//!   and `none`. The classes the
//!   lost open belongs to are degraded with null counts; the classes it does
//!   not belong to keep counts equal to what the fixture did; the protection
//!   label is the profile's; the trace carries the gap note.
//! - O03: a class never returns to active after an early gap, however much
//!   clean activity follows; an exit is never unmatched, because the observer
//!   steps a tracee to a syscall exit only with its entry in hand (checked at
//!   the tracer seam, where a mutation of that rule is visible); map
//!   exhaustion (the in-flight bound) and ring loss (the tracer queue) reached
//!   through the product with the shrink-only test seams.
//! - O05: an observer that cannot attach refuses before exec in best-effort
//!   too, whichever step notices; every directory-entry operation lost to the
//!   in-flight bound degrades `fs.write`; a denied connect counts only under
//!   `fs.deny`, for the ptrace observer and for the `agent` mediator.
//! - §11.4 "Record actual values in the observer plan": the bounds in force,
//!   and any test seam that shrank them, are in the receipt.
//!
//! The fixture is a C program built at test time (`fixtures/loss.c`, through
//! `common/observer.rs`). Every process signalled is one these tests
//! started; every file is under a private temporary directory.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, TracerConfig, TracerEvent, narrowing_filter_bytes,
};
use ouro_jail::policy::ProfileName;
use serde_json::Value;

mod common;

use common::observer::{
    Case, Fixture, Observed, Report, assert_active, attach, audit_events, collect, mkfifo,
    native_expectation, serial, spawn_launcher,
};

static FIXTURE: Fixture = Fixture {
    name: "loss",
    source: include_str!("fixtures/loss.c"),
    pthread: true,
    filter: narrowing_filter_bytes,
};

/// Whether this host can run a live check of `profile`.
fn live(profile: &str) -> bool {
    let profile = ProfileName::parse(profile).expect("a built-in profile");
    common::profile_live(profile)
}

/// A [`Case`] of `profile` and `evidence` on a fresh harness.
fn case(profile: &str, evidence: &str) -> Option<Case> {
    FIXTURE.case_on(Jail::new().unwrap(), profile, evidence)
}

fn details(receipt: &Value) -> &Value {
    &receipt["lifetime"]["native"]["details"]
}

/// Audit results naming this workspace-relative path, as either path.
fn results_on<'a>(run: &'a Run, relative: &str) -> Vec<&'a Value> {
    audit_events(run)
        .into_iter()
        .filter(|event| {
            ["path", "path2"].iter().any(|key| {
                event["fields"][key]["kind"] == "workspace_relative"
                    && event["fields"][key]["value"] == relative
            })
        })
        .collect()
}

fn gap_notes<'a>(run: &'a Run, reason: &str) -> Vec<&'a Value> {
    run.trace_events()
        .iter()
        .filter(|event| {
            event["source"] == "wrapper"
                && event["fields"]["kind"] == "coverage_gap"
                && event["fields"]["reason"] == reason
        })
        .collect()
}

fn error_codes(receipt: &Value) -> Vec<String> {
    receipt["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|error| error["code"].as_str().map(str::to_owned))
        .collect()
}

/// The class entry, asserted degraded with a null count and a gap of
/// `reason` naming it; returns that gap.
fn assert_degraded<'a>(receipt: &'a Value, class: &str, reason: &str) -> &'a Value {
    let entry = &receipt["coverage"][class];
    assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
    assert_eq!(
        entry["observed_count"],
        Value::Null,
        "{class}: a degraded class has no count: {entry:#}"
    );
    assert_eq!(entry["sources"], serde_json::json!(["audit"]), "{class}");
    entry["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gap| {
            gap["reason"] == reason
                && gap["classes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == class)
        })
        .unwrap_or_else(|| panic!("{class}: no {reason} gap naming it: {entry:#}"))
}

/// Connect results the fixture reported, split into denials (EACCES,
/// EPERM: `fs.deny`) and the rest (`net`). `-2` is a socket the profile
/// refused, which made no connect at all.
fn connects(lines: &[Report]) -> (u64, u64) {
    let mut denied = 0;
    let mut other = 0;
    for line in lines.iter().filter(|line| line.label.ends_with("connect")) {
        if line.raw == -2 {
            continue;
        }
        if line.raw < 0 && (line.errno == libc::EACCES || line.errno == libc::EPERM) {
            denied += 1;
        } else {
            other += 1;
        }
    }
    (denied, other)
}

// ===========================================================================
// R04: a real ptrace-observer loss, strict and best-effort, tool and none
// ===========================================================================

/// Loopback connects the R04 fixture makes before its loss.
const R04_CONNECTS: usize = 3;

/// The exec-class results of every R04 run: the target's exec, its re-exec,
/// its exit.
const R04_EXEC_RESULTS: u64 = 3;

fn r04(profile: &str, evidence: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = case(profile, evidence) else {
        return;
    };
    let strict = evidence == "strict";
    // Strict must stop a target that would sleep far longer than the check
    // takes; best-effort lets a short sleep run out.
    let sleep_ms = if strict { "30000" } else { "300" };
    let connect_count = R04_CONNECTS.to_string();
    let argv = c.argv("r04", &[&c.fifo, &c.helper, &connect_count, &sleep_ms]);
    let started = Instant::now();
    let run = c
        .jail
        .timeout(Duration::from_secs(90))
        .target(argv)
        .run()
        .unwrap();
    let elapsed = started.elapsed();
    let label = format!("{profile}/{evidence}");
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);

    // The fixture did lose one open, and nothing else. (That the re-exec
    // ran is the exec count below: under strict, the stop can end the new
    // image before it says anything.)
    assert_eq!(Report::find(&out, "parked").raw, 0, "{label}: {out:#?}");
    let (denied, other) = connects(&out);
    assert_eq!(denied, 0, "{label}: {out:#?}");
    assert_eq!(other, R04_CONNECTS as u64, "{label}: {out:#?}");

    // Strict fails for the loss; best-effort preserves the child's exit.
    assert_eq!(
        run.code(),
        Some(if strict { 1 } else { 0 }),
        "{label}: stderr {}",
        run.stderr_text()
    );
    assert!(
        error_codes(&settled).contains(&"evidence_lost".to_owned()),
        "{label}: {:#}",
        settled["errors"]
    );
    let outcome = &settled["outcome"];
    if strict {
        assert_eq!(outcome["cause"], "evidence_loss", "{label}: {outcome:#}");
        assert_eq!(outcome["kind"], "signaled", "{label}: {outcome:#}");
        assert!(
            out.iter().all(|line| line.label != "done"),
            "{label}: the target was stopped before its end: {out:#?}"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "{label}: stopped for the loss, not at the end of its sleep ({elapsed:?})"
        );
    } else {
        assert_eq!(outcome["kind"], "exited", "{label}: {outcome:#}");
        assert_eq!(outcome["code"], 0, "{label}: {outcome:#}");
        assert_eq!(outcome["cause"], Value::Null, "{label}: {outcome:#}");
        Report::find(&out, "sleeping");
        Report::find(&out, "done");
    }

    // Exactly the lost call's classes are degraded; the others are exact.
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "entry_abandoned");
        assert_eq!(gap["lost_count"], 1, "{label}: {gap:#}");
    }
    assert_active(&settled, "exec", R04_EXEC_RESULTS);
    assert_active(&settled, "net", R04_CONNECTS as u64);
    assert_eq!(settled["observer"]["sources"]["audit"], "degraded");
    assert_eq!(settled["observer"]["attached"], true);
    // The label is the profile's, loss or not.
    let (containment, protection) = if profile == "none" {
        ("none", "unprotected")
    } else {
        ("enforced", "enforced")
    };
    assert_eq!(settled["containment"], containment, "{label}");
    assert_eq!(settled["child_protection"], protection, "{label}");
    // The trace says what was lost, in a gap note.
    let notes = gap_notes(&run, "entry_abandoned");
    assert_eq!(notes.len(), 1, "{label}: one gap note: {notes:#?}");
    // And never invents the lost call's result: no result names the FIFO.
    assert!(
        results_on(&run, "fifo").is_empty(),
        "{label}: no result for the abandoned open: {:#?}",
        results_on(&run, "fifo")
    );
}

#[test]
fn j4_r04_ptrace_loss_strict_tool() {
    r04("tool", "strict");
}

#[test]
fn j4_r04_ptrace_loss_strict_none() {
    r04("none", "strict");
}

#[test]
fn j4_r04_ptrace_loss_best_effort_tool() {
    r04("tool", "best-effort");
}

#[test]
fn j4_r04_ptrace_loss_best_effort_none() {
    r04("none", "best-effort");
}

/// R04, the settlement case: a call still in flight when the tree is torn
/// down after the target's exit (X07) is a loss too. The kill interrupts it
/// after the observer let it run, so whether it had its effect is unknown
/// (for an `O_CREAT` open it may well have); the result is not invented and
/// its classes are degraded. Here a background child's thread is parked in
/// `openat(FIFO)` when the target exits.
///
/// The loss is always an `evidence_lost` error and the jail exits 1 under
/// strict, while best-effort preserves the child's exit, whenever the
/// supervisor reads it — in the run loop, while it verifies the tree, or
/// only from the observer's final account; which one varies from run to run.
/// The loss came after the target's own end, so it is never the cause: the
/// outcome is the target's exit 0 with a null cause, under strict evidence
/// as under best-effort.
fn teardown_loss(profile: &str, evidence: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = case(profile, evidence) else {
        return;
    };
    let label = format!("{profile}/{evidence}");
    let argv = c.argv("bg-park", &[&c.fifo]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(Report::find(&out, "parked").raw, 0, "{label}: {out:#?}");
    assert_eq!(settled["outcome"]["kind"], "exited", "{label}");
    assert_eq!(settled["outcome"]["code"], 0, "{label}");
    assert_eq!(settled["lifetime"]["tree_empty"], true, "{label}: X07");
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "entry_abandoned");
        assert_eq!(gap["lost_count"], 1, "{label}: {gap:#}");
    }
    // The target's exec and exit; the child never execs.
    assert_active(&settled, "exec", 2);
    assert_active(&settled, "net", 0);
    assert_eq!(gap_notes(&run, "entry_abandoned").len(), 1, "{label}");
    assert!(
        results_on(&run, "fifo").is_empty(),
        "{label}: no result for the interrupted open"
    );
    // Reported, whatever its timing.
    let losses = error_codes(&settled)
        .iter()
        .filter(|code| *code == "evidence_lost")
        .count();
    assert_eq!(
        losses, 1,
        "{label}: one evidence_lost error: {:#}",
        settled["errors"]
    );
    assert_eq!(
        run.code(),
        Some(if evidence == "strict" { 1 } else { 0 }),
        "{label}: settlement loss preserves best-effort exit: stderr {}",
        run.stderr_text()
    );
    // After the target's own end, so never its cause.
    assert_eq!(
        settled["outcome"]["cause"],
        Value::Null,
        "{label}: {:#}",
        settled["outcome"]
    );
}

#[test]
fn j4_r04_a_call_in_flight_at_teardown_is_loss_tool() {
    teardown_loss("tool", "strict");
}

#[test]
fn j4_r04_a_call_in_flight_at_teardown_is_loss_none() {
    teardown_loss("none", "strict");
}

#[test]
fn j4_r04_a_call_in_flight_at_teardown_is_loss_best_effort_tool() {
    teardown_loss("tool", "best-effort");
}

#[test]
fn j4_r04_a_call_in_flight_at_teardown_is_loss_best_effort_none() {
    teardown_loss("none", "best-effort");
}

// ===========================================================================
// O03: no return to active; no unmatched exit; exhaustion via the seams
// ===========================================================================

/// §11.4: "Coverage cannot return to fully active for the entire run after
/// a historical gap." One open lost first, then two hundred rounds of clean
/// `fs.write` results that the observer does see: the class stays degraded
/// with no count, and the gap's interval ends before them.
#[test]
fn j4_o03_a_class_never_returns_to_active_after_an_early_gap() {
    let _serial = serial();
    if !live("tool") {
        return;
    }
    let Some(c) = case("tool", "best-effort") else {
        return;
    };
    let argv = c.argv("early-loss", &[&c.fifo, &c.helper, &c.ops, &"200"]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(Report::find(&out, "results").raw, 800, "{out:#?}");
    let gap = assert_degraded(&settled, "fs.write", "entry_abandoned").clone();
    // The observer saw every later result...
    let ops = c.ops.to_string_lossy().into_owned();
    let later: Vec<&Value> = audit_events(&run)
        .into_iter()
        .filter(|event| {
            matches!(
                event["operation"].as_str(),
                Some("fs.create" | "fs.unlink" | "fs.write")
            )
        })
        .collect();
    assert!(
        later.len() >= 800,
        "the clean results after the gap were observed: {} events (ops dir {ops})",
        later.len()
    );
    // ...after the gap closed, and still the class is not active again.
    let end: u64 = gap["end_ns"].as_str().unwrap().parse().unwrap();
    let after = later
        .iter()
        .filter(|event| {
            event["monotonic_ns"]
                .as_str()
                .and_then(|ns| ns.parse::<u64>().ok())
                .is_some_and(|ns| ns > end)
        })
        .count();
    assert!(after >= 800, "{after} results after the gap's end {end}");
    assert_eq!(settled["observer"]["sources"]["audit"], "degraded");
    assert_active(&settled, "net", 0);
}

/// Launch `argv` under the observer's filter and trace it with `config`,
/// the way the product does: attach while the launcher is blocked, release,
/// read until the observer finishes.
fn observe(argv: &[&dyn AsRef<std::ffi::OsStr>], config: TracerConfig) -> (Vec<Report>, Observed) {
    let built = FIXTURE.build().expect("built");
    let mut command = built.launcher();
    command.args(argv);
    let mut run = spawn_launcher(command);
    let tracer = attach(run.pid, config);
    run.release();
    let out = run.lines();
    (out, collect(tracer, Duration::from_secs(60)))
}

fn unmatched(observed: &Observed) -> Vec<String> {
    let mut found: Vec<String> = observed
        .events
        .iter()
        .filter(|event| {
            matches!(event, TracerEvent::Gap { reason, .. } if *reason == GapReason::UnmatchedExit)
        })
        .map(|event| format!("{event:?}"))
        .collect();
    if observed.summary.loss.unmatched_exits > 0 {
        found.push(format!(
            "unmatched_exits = {}",
            observed.summary.loss.unmatched_exits
        ));
    }
    found
}

/// S2: "unmatched exit" is unreachable by construction, because the observer
/// steps a tracee to its syscall exit (`PTRACE_SYSCALL`) only when it holds
/// that tracee's entry, and continues it (`PTRACE_CONT`) otherwise. Checked
/// at the tracer seam over every way a tracee can reach — or must not reach
/// — an exit stop: calls outside the set, read-only opens filtered at their
/// entry, covered calls, an interrupted call restarted under `SA_RESTART`,
/// one interrupted for good, a non-leader `execve` with a sibling's call in
/// flight, `vfork`; and, under an in-flight bound of one, entries the
/// observer refused to follow. A rule that stepped any of those to an exit
/// without its entry shows here as `unmatched_exit`.
#[test]
fn j4_o03_unmatched_exit_is_unreachable() {
    let _serial = serial();
    if !common::live() {
        return;
    }
    let Some(built) = FIXTURE.built() else {
        return;
    };
    let helper = &built.helper;
    let dir = common::private_tempdir();
    let fifo = dir.path().join("fifo");
    mkfifo(&fifo);
    let (out, observed) = observe(
        &[helper, &"pairing", &fifo, helper, &dir.path()],
        TracerConfig::default(),
    );
    let summary = &observed.summary;
    assert_eq!(Report::find(&out, "parked").raw, 0, "{out:#?}");
    assert_eq!(Report::find(&out, "reparked").raw, 0, "{out:#?}");
    assert_eq!(
        Report::find(&out, "interrupted").errno,
        libc::EINTR,
        "{out:#?}"
    );
    assert_eq!(Report::find(&out, "non_leader_exec").raw, 0, "{out:#?}");
    assert_eq!(Report::find(&out, "vfork_exec").raw, 0, "{out:#?}");
    // Every path was taken.
    assert!(summary.filtered_readonly_opens >= 100, "{summary:?}");
    // The table without a legacy `rmdir` reports it as the `unlinkat` it is.
    let (_, rmdir) = native_expectation("rmdir", ClosedOp::Rmdir);
    assert!(
        summary.ops.get(ClosedOp::Mkdir) >= 50 && summary.ops.get(rmdir) >= 50,
        "{summary:?}"
    );
    assert!(summary.restarts >= 1, "the SA_RESTART restart: {summary:?}");
    assert!(summary.loss.abandoned_entries >= 1, "{summary:?}");
    assert!(summary.tasks_destroyed_by_exec >= 1, "{summary:?}");
    assert_eq!(
        unmatched(&observed),
        Vec::<String>::new(),
        "an exit stop without its entry: {summary:?}"
    );

    let (out, observed) = observe(
        &[helper, &"pairing-inflight", &fifo, &dir.path()],
        TracerConfig {
            inflight_max: 1,
            ..TracerConfig::default()
        },
    );
    let summary = &observed.summary;
    assert_eq!(Report::find(&out, "parked").raw, 0, "{out:#?}");
    assert_eq!(Report::find(&out, "after").raw, 0, "{out:#?}");
    // Exactly the twenty covered calls: the twenty read-only opens made
    // meanwhile are outside the closed set and never take or are refused a
    // slot.
    assert_eq!(
        summary.loss.inflight_rejected, 20,
        "the bound refused the covered entries and nothing else: {summary:?}"
    );
    assert_eq!(
        unmatched(&observed),
        Vec::<String>::new(),
        "an exit stop for an entry the observer refused: {summary:?}"
    );
}

/// O03 through the product: map exhaustion (the in-flight bound) and ring
/// loss (the tracer queue), reached with the shrink-only seams. Each one
/// degrades exactly the classes of the calls it swallowed, with null
/// counts, and never reports a result for them.
#[test]
fn j4_o03_exhaustion_through_the_product() {
    let _serial = serial();
    if !live("tool") {
        return;
    }
    // Map exhaustion: one in-flight slot, held by a parked open; the mkdir
    // made meanwhile cannot be followed.
    let Some(c) = FIXTURE.case_on(
        Jail::new()
            .unwrap()
            .env("OURO_JAIL_TEST_TRACER_INFLIGHT", "1"),
        "tool",
        "best-effort",
    ) else {
        return;
    };
    let argv = c.argv("inflight", &[&c.fifo, &c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(Report::find(&out, "parked").raw, 0, "{out:#?}");
    assert_eq!(
        details(&settled)["observer_plan"]["in_flight_max"],
        1,
        "the seam took effect: {:#}",
        details(&settled)
    );
    let gap = assert_degraded(&settled, "fs.write", "inflight_exhausted");
    assert_eq!(
        gap["lost_count"], 20,
        "the twenty directory-entry calls made while the slot was held: {gap:#}"
    );
    // A call that was not followed could have been a denial too,
    // so the same gap degrades `fs.deny` (audit.rs `classes_for`); and a
    // best-effort loss is still recorded in the receipt.
    let deny = assert_degraded(&settled, "fs.deny", "inflight_exhausted");
    assert_eq!(deny["lost_count"], 20, "the same twenty calls: {deny:#}");
    assert_active(&settled, "net", 1);
    assert_active(&settled, "exec", 2);
    assert_eq!(Report::find(&out, "mkdir").raw, 0, "{out:#?}");
    assert!(
        results_on(&run, "ops/a").is_empty(),
        "no result for a call the observer could not follow: {:#?}",
        results_on(&run, "ops/a")
    );
    assert_eq!(
        run.code(),
        Some(0),
        "best-effort preserves the child's exit despite the loss: {}",
        run.stderr_text()
    );

    // Ring loss: a queue budget too small for any result that carries a
    // path, big enough for the lifecycle facts. The mkdir is dropped after
    // the bounded wait; the connect, which carries no path, is not.
    let Some(c) = FIXTURE.case_on(
        Jail::new()
            .unwrap()
            .env("OURO_JAIL_TEST_TRACER_QUEUE_BYTES", "16384"),
        "tool",
        "best-effort",
    ) else {
        return;
    };
    let argv = c.argv("queue", &[&c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(
        Report::find(&out, "mkdir").raw,
        0,
        "the mkdir ran: {out:#?}"
    );
    assert_eq!(
        details(&settled)["observer_plan"]["queue_bytes_max"],
        16384,
        "the seam took effect: {:#}",
        details(&settled)
    );
    let gap = assert_degraded(&settled, "fs.write", "queue_full");
    assert_eq!(gap["lost_count"], 1, "{gap:#}");
    assert_degraded(&settled, "fs.deny", "queue_full");
    assert_active(&settled, "net", 1);
    assert_active(&settled, "exec", 2);
    assert!(
        !audit_events(&run)
            .iter()
            .any(|event| event["operation"] == "fs.create"),
        "the dropped mkdir has no result: {:#?}",
        audit_events(&run)
    );
    assert_eq!(
        run.code(),
        Some(0),
        "best-effort preserves the child's exit despite the loss"
    );
}

/// A seam set twice in the jail's environment. `getenv`, and so the tracer
/// that applies the seam, takes the first entry; a record that took the last
/// would say 16384 while one in-flight slot is in force. The record names
/// what the consumers read.
#[test]
fn j4_w3_a_seam_set_twice_is_recorded_as_applied() {
    let _serial = serial();
    if !live("tool") {
        return;
    }
    let Some(built) = FIXTURE.built() else {
        return;
    };
    let jail = Jail::with_program(&built.helper)
        .unwrap()
        .arg("dupenv")
        .arg(harness::jail_path());
    let Some(c) = FIXTURE.case_on(jail, "tool", "strict") else {
        return;
    };
    let argv = c.argv("exit0", &[]);
    let run = c.jail.target(argv).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let settled = common::settled(&run);
    let details = details(&settled);
    assert_eq!(
        details["observer_plan"]["in_flight_max"], 1,
        "getenv applied the first entry: {details:#}"
    );
    assert_eq!(
        details["test_seams"],
        serde_json::json!({"OURO_JAIL_TEST_TRACER_INFLIGHT": "1"}),
        "the record names the value in force, not the second entry: {details:#}"
    );
    assert_eq!(
        details["observer_plan"]["test_seams"]["OURO_JAIL_TEST_TRACER_INFLIGHT"], 1,
        "{details:#}"
    );
}

// ===========================================================================
// O05
// ===========================================================================

/// O05: "unavailable attachment refuses even in best-effort". A ptrace
/// wrapper of the test's own runs the jail. Traced whole (`wrap-all`), every
/// child the jail makes is already traced, so the jail's own probe of the
/// observer notices first; traced selectively (`wrap-launcher`: the
/// probes' children are let go, the real launcher is kept), the probes pass
/// and the seize at the attach site fails `EPERM`. Either way: best-effort,
/// and still a refusal before exec — exit 125, a refused receipt, and the
/// target never ran.
fn attach_failure(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(built) = FIXTURE.built() else {
        return;
    };
    for (mode, stage, code, says) in [
        (
            "wrap-all",
            "probing",
            "missing_capability",
            "closed_set_observation",
        ),
        (
            "wrap-launcher",
            "preparing",
            "observer_unavailable",
            "could not attach",
        ),
    ] {
        let jail = Jail::with_program(&built.helper)
            .unwrap()
            .arg(mode)
            .arg(harness::jail_path());
        let Some(c) = FIXTURE.case_on(jail, profile, "best-effort") else {
            return;
        };
        let marker = c.workspace.join("marker");
        let run = c
            .jail
            .target([
                OsString::from("/usr/bin/touch"),
                marker.clone().into_os_string(),
            ])
            .run()
            .unwrap();
        let label = format!("{profile}/{mode}");
        assert_eq!(
            run.code(),
            Some(125),
            "{label}: stderr {}",
            run.stderr_text()
        );
        let refused = common::phase_receipt(&run, "refused");
        let error = &refused["outcome"]["error"];
        assert_eq!(error["code"], code, "{label}: {error:#}");
        assert_eq!(error["stage"], stage, "{label}: {error:#}");
        assert!(
            error["message"].as_str().unwrap_or("").contains(says),
            "{label}: {error:#}"
        );
        assert_eq!(refused["policy"]["evidence"], "best-effort", "{label}");
        assert_eq!(refused["exec_observed"], false, "{label}");
        assert!(!marker.exists(), "{label}: the target never ran");
        assert!(
            audit_events(&run).is_empty(),
            "{label}: nothing was observed"
        );
    }
}

#[test]
fn j4_o05_attach_failure_refuses_in_best_effort_tool() {
    attach_failure("tool");
}

#[test]
fn j4_o05_attach_failure_refuses_in_best_effort_none() {
    attach_failure("none");
}

/// O05: "Directory-operation losses degrade fs.write." Every directory-entry
/// variant of the closed set, made while a parked open holds the only
/// in-flight slot the seam leaves: each one ran, none could be followed,
/// and each is a loss of `fs.write` (and of `fs.deny`, which a lost result
/// could also have been) — not of `exec` or `net`, whose counts stay exact.
#[test]
fn j4_o05_directory_operation_losses_degrade_fs_write() {
    let _serial = serial();
    for profile in ["tool", "none"] {
        if !live(profile) {
            return;
        }
        let Some(c) = FIXTURE.case_on(
            Jail::new()
                .unwrap()
                .env("OURO_JAIL_TEST_TRACER_INFLIGHT", "1"),
            profile,
            "best-effort",
        ) else {
            return;
        };
        let argv = c.argv("inflight", &[&c.fifo, &c.ops]);
        let run = c.jail.target(argv).run().unwrap();
        let out = Report::parse_all(&run.stdout_text());
        let settled = common::settled(&run);
        assert_eq!(Report::find(&out, "parked").raw, 0, "{profile}: {out:#?}");
        let lost: Vec<&Report> = out
            .iter()
            .take_while(|line| line.label != "released")
            .filter(|line| line.label != "parked")
            .collect();
        assert_eq!(lost.len(), 20, "{profile}: {lost:#?}");
        for line in &lost {
            assert!(line.raw >= 0, "{profile}: every call ran: {line:?}");
        }
        assert_eq!(
            Report::find(&out, "released").errno,
            libc::EINTR,
            "{profile}"
        );
        for class in ["fs.write", "fs.deny"] {
            let gap = assert_degraded(&settled, class, "inflight_exhausted");
            assert_eq!(
                gap["lost_count"], 20,
                "{profile}/{class}: one per call made while the slot was held: {gap:#}"
            );
        }
        assert_active(&settled, "exec", 2);
        assert_active(&settled, "net", 1);
        // None of the twenty is a result; the mkdir made after the release
        // is.
        for line in &lost {
            let relative = Path::new(&line.path)
                .strip_prefix(&c.workspace)
                .unwrap_or_else(|_| panic!("{profile}: {line:?}"))
                .to_string_lossy()
                .into_owned();
            let invented = results_on(&run, &relative);
            assert!(
                invented.is_empty(),
                "{profile}: a result for {} that the observer could not follow: {invented:#?}",
                line.label
            );
        }
        assert_eq!(
            results_on(&run, "ops/after").len(),
            1,
            "{profile}: the call after the release is observed"
        );
    }
}

/// O05: "denied connect counts only in fs.deny." Connects the kernel denies
/// (a mode-000 AF_UNIX socket, a UDP broadcast address without
/// `SO_BROADCAST`) are `fs.deny` results with `attempted_operation =
/// net.connect` and never `net` ones; the other connects are `net`. The
/// receipt's counts equal what the fixture did, class by class. `agent`
/// takes its connects through the unix-peer mediator, and the same holds.
fn denied_connect(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = case(profile, "strict") else {
        return;
    };
    let argv = c.argv("deny-connect", &[&c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
    let (denied, other) = connects(&out);
    assert!(
        denied >= 1,
        "{profile}: the fixture must have made a denied connect: {out:#?}"
    );
    // Issue draft 13: the agent profile's mediated connects are network
    // evidence whatever their verdict; only the directly traced profiles
    // classify an EACCES/EPERM connect under fs.deny.
    let (denied_fs, denied_net) = if profile == "agent" {
        (0, denied)
    } else {
        (denied, 0)
    };
    assert_active(&settled, "fs.deny", denied_fs);
    assert_active(&settled, "net", other + denied_net);
    let audit = audit_events(&run);
    let denials: Vec<&&Value> = audit
        .iter()
        .filter(|event| event["operation"] == "fs.deny")
        .collect();
    assert_eq!(denials.len() as u64, denied_fs, "{profile}: {denials:#?}");
    for event in &denials {
        assert_eq!(
            event["fields"]["attempted_operation"], "net.connect",
            "{profile}: {event:#}"
        );
    }
    let refused: Vec<&&Value> = audit
        .iter()
        .filter(|event| {
            event["operation"] == "net.connect"
                && matches!(
                    event["outcome"]["errno"].as_str(),
                    Some("EACCES") | Some("EPERM")
                )
        })
        .collect();
    assert_eq!(refused.len() as u64, denied_net, "{profile}: {refused:#?}");
    for event in &refused {
        assert_eq!(
            event["fields"]["observation"], "seccomp_user_notification",
            "{profile}: {event:#}"
        );
    }
    let nets: Vec<&&Value> = audit
        .iter()
        .filter(|event| event["operation"] == "net.connect")
        .collect();
    assert_eq!(
        nets.len() as u64,
        other + denied_net,
        "{profile}: {nets:#?}"
    );
}

#[test]
fn j4_o05_denied_connect_counts_only_in_fs_deny_tool() {
    denied_connect("tool");
}

#[test]
fn j4_o05_denied_connect_counts_only_in_fs_deny_none() {
    denied_connect("none");
}

#[test]
fn j4_o05_denied_connect_counts_only_in_fs_deny_agent() {
    denied_connect("agent");
}

// ===========================================================================
// The observer plan (§11.4 "Record actual values in the observer plan")
// ===========================================================================

/// The bounds in force are in the receipt's native details, before the
/// target runs (prepared) and at the end (settled): the §11.4 defaults with
/// no seam; exactly the shrunk value, named, with one; and a seam that
/// would widen a bound is ignored and says so.
///
/// The prepared receipt is read for real: the run is gated, the owner reads
/// the `--receipt` copy when `prepared` arrives (the receipt the gate owner
/// decides on), and only then releases it.
#[test]
fn j4_observer_plan_is_recorded() {
    let _serial = serial();
    for profile in ["tool", "none"] {
        if !live(profile) {
            return;
        }
        for (seams, inflight, queue) in [
            (&[][..], 16_384, 4_194_304),
            (
                &[
                    ("OURO_JAIL_TEST_TRACER_INFLIGHT", "7"),
                    ("OURO_JAIL_TEST_TRACER_QUEUE_BYTES", "65536"),
                ][..],
                7,
                65_536,
            ),
            (
                &[
                    ("OURO_JAIL_TEST_TRACER_INFLIGHT", "16385"),
                    ("OURO_JAIL_TEST_TRACER_QUEUE_BYTES", "0"),
                ][..],
                16_384,
                4_194_304,
            ),
        ] {
            let mut jail = Jail::new().unwrap();
            for (name, value) in seams {
                jail = jail.env(name, value);
            }
            let Some(c) = FIXTURE.case_on(jail, profile, "strict") else {
                return;
            };
            let argv = c.argv("exit0", &[]);
            let label = format!("{profile} {seams:?}");
            let mut spawned = c.jail.gate().receipt().target(argv).spawn().unwrap();
            let control = spawned
                .owner()
                .await_prepared()
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            let prepared = spawned
                .receipt_value()
                .expect("the prepared receipt is on disk when `prepared` arrives");
            assert_eq!(prepared["phase"], "prepared", "{label}: {prepared:#}");
            let attempt_id = control["attempt_id"].as_str().unwrap().to_owned();
            let policy_digest = prepared["policy"]["digest"].as_str().unwrap().to_owned();
            spawned
                .owner()
                .release(&harness::gate::Release::Valid, &attempt_id, &policy_digest)
                .unwrap_or_else(|error| panic!("{label}: the release: {error}"));
            let run = spawned.wait().unwrap();
            let settled = common::settled(&run);
            assert_eq!(run.code(), Some(0), "{label}: {}", run.stderr_text());
            for (phase, receipt) in [("prepared", &prepared), ("settled", &settled)] {
                let label = format!("{label} {phase}");
                let plan = &details(receipt)["observer_plan"];
                assert_eq!(plan["backend"], "ptrace", "{label}: {plan:#}");
                assert_eq!(plan["in_flight_max"], inflight, "{label}: {plan:#}");
                assert_eq!(plan["queue_bytes_max"], queue, "{label}: {plan:#}");
                assert_eq!(plan["queue_events_max"], 16_384, "{label}: {plan:#}");
                assert_eq!(plan["path_snapshot_max"], 4096, "{label}: {plan:#}");
                assert_eq!(plan["event_bytes_max"], 65_536, "{label}: {plan:#}");
                assert_eq!(
                    plan["kernel_ring_bytes"],
                    Value::Null,
                    "{label}: the ptrace observer has no kernel ring: {plan:#}"
                );
                let recorded = plan["test_seams"].as_object().unwrap();
                assert_eq!(
                    recorded.len(),
                    seams.len(),
                    "{label}: every seam set is named: {plan:#}"
                );
                for (name, value) in seams {
                    let applied: u64 = value.parse().unwrap();
                    let widening = !(1..=if name.ends_with("INFLIGHT") {
                        16_384
                    } else {
                        4_194_304
                    })
                        .contains(&applied);
                    assert_eq!(
                        recorded[*name],
                        if widening {
                            Value::Null
                        } else {
                            Value::from(applied)
                        },
                        "{label}: {plan:#}"
                    );
                }
            }
            assert_eq!(
                details(&prepared)["observer_plan"],
                details(&settled)["observer_plan"],
                "{label}: the plan the gate owner saw is the one in force"
            );
            assert_eq!(
                settled["coverage"]["exec"]["status"], "active",
                "{label}: nothing was lost"
            );
        }
    }
}
