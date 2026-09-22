//! The harness, proved against a stand-in for `ouro-jail`.
//!
//! `crates/ouro-jail` does not exist in this worktree: the core and linux
//! slices own it. So the pipe plumbing, the gate owner and the frame variants
//! are proved here against `stand-in-jail`, a test binary that writes a
//! prepared receipt, announces `prepared`, reads the gate to EOF, validates it
//! against jail-v1 §8.2 and execs the target.
//!
//! What this proves: the harness passes descriptor numbers with the right
//! direction, only the jail inherits them, the target inherits only stdio, the
//! owner reads `prepared` and compares the receipt bindings with its plan, and
//! each `Release` variant is genuinely rejectable by a conforming parser.
//!
//! What this does NOT prove: anything about `ouro-jail`'s own gate parser,
//! containment, observation or receipts. The stand-in's parser is part of this
//! crate, not the product.

use std::path::{Path, PathBuf};

use ouro_fixture::harness::{ExpectedPlan, Jail, Release, Run, TempDir};
use serde_json::Value;

const EXIT_REFUSED: i32 = 125;

fn stand_in() -> &'static str {
    env!("CARGO_BIN_EXE_stand-in-jail")
}

struct Case {
    _dir: TempDir,
    marker: PathBuf,
}

impl Case {
    fn new() -> Case {
        let dir = TempDir::new("ouro-harness-gate").unwrap();
        let marker = dir.path().join("target-ran");
        Case { _dir: dir, marker }
    }

    /// A jail whose target creates the marker file, with all three channels.
    fn jail(&self) -> Jail {
        Jail::with_program(stand_in())
            .unwrap()
            .control()
            .gate()
            .trace()
            .receipt()
            .target_fixture([
                "open",
                &self.marker.display().to_string(),
                "--create",
                "--write",
            ])
    }

    fn marker_exists(&self) -> bool {
        self.marker.exists()
    }
}

/// Run to completion, releasing with the chosen variant after checking the
/// plan. Returns the run and whatever the owner objected to.
fn release_with(case: &Case, variant: &Release, plan: &ExpectedPlan) -> (Run, Vec<String>) {
    let mut spawned = case.jail().spawn().expect("the stand-in must start");
    let (attempt_id, digest, problems) = {
        let mut owner = spawned.owner();
        let prepared = owner.await_prepared().expect("`prepared` must arrive");
        assert_eq!(prepared["kind"], "prepared");
        assert_eq!(prepared["schema"], "ouro.jail.control/1");
        let receipt = spawned_receipt(&spawned);
        let mut owner = spawned.owner();
        let (attempt_id, digest) = (
            receipt["attempt_id"].as_str().unwrap().to_string(),
            receipt["policy"]["digest"].as_str().unwrap().to_string(),
        );
        let problems = match owner.authorise(&prepared, Some(&receipt), plan) {
            Ok(_) => Vec::new(),
            Err((_, problems)) => problems,
        };
        if problems.is_empty() {
            owner.release(variant, &attempt_id, &digest).unwrap();
        } else {
            owner.withhold();
        }
        (attempt_id, digest, problems)
    };
    let _ = (attempt_id, digest);
    (spawned.wait().expect("the stand-in must exit"), problems)
}

fn spawned_receipt(spawned: &ouro_fixture::harness::Spawned) -> Value {
    spawned
        .receipt_value()
        .expect("the stand-in writes the prepared receipt before `prepared`")
}

fn plan_matching(case: &Case) -> ExpectedPlan {
    let _ = case;
    // The stand-in's defaults are the plan the owner authorised.
    ExpectedPlan::new()
        .attempt_id("att_00000000-0000-4000-8000-000000000001")
        .policy_digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .argv_digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
}

#[test]
fn a_valid_release_runs_the_target_exactly_once() {
    let case = Case::new();
    let (run, problems) = release_with(&case, &Release::Valid, &plan_matching(&case));
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    assert!(case.marker_exists(), "the target did not run");

    // One target exec: exactly one fixture line, and one `exec_confirmed`.
    let lines = run.fixture_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["op"], "openat");
    assert_eq!(lines[0]["errno"], Value::Null);
    assert_eq!(run.control_kind("exec_confirmed").len(), 1);
    assert_eq!(run.control_kind("prepared").len(), 1);
    assert!(run.control_kind("refused").is_empty());
}

#[test]
fn the_run_exposes_the_receipt_the_trace_and_the_private_state() {
    let case = Case::new();
    let (run, _) = release_with(&case, &Release::Valid, &plan_matching(&case));

    let receipts = run.receipts();
    assert!(
        receipts.len() >= 2,
        "one from --receipt and one from jail.json: {receipts:?}"
    );
    let prepared = run
        .receipt_phase("prepared")
        .expect("a prepared receipt must be readable");
    assert_eq!(prepared["schema"], "ouro.jail.receipt/1");
    assert!(prepared["argv_digest"].is_string());

    assert_eq!(run.trace_events.len(), 1, "{:?}", run.trace_events);
    assert_eq!(run.trace_events[0]["schema"], "ouro.event/1");

    assert!(run.data_dir.join("attempts").is_dir());
    assert!(
        run.data_dir.starts_with(std::env::temp_dir()),
        "state must be private to the run: {}",
        run.data_dir.display()
    );
}

#[test]
fn a_withheld_gate_refuses_and_the_target_never_runs() {
    let case = Case::new();
    let mut spawned = case.jail().spawn().unwrap();
    {
        let mut owner = spawned.owner();
        owner.await_prepared().unwrap();
        owner.withhold();
    }
    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(EXIT_REFUSED), "{}", run.stderr_text());
    assert!(
        !case.marker_exists(),
        "no target marker after a withheld gate"
    );
    assert_eq!(run.control_kind("refused").len(), 1);
    let refused = run.control_kind("refused")[0];
    assert_eq!(refused["error"]["code"], "gate_closed");
}

#[test]
fn every_malformed_release_refuses_and_leaves_no_marker() {
    let variants: Vec<(&str, Release)> = vec![
        ("empty EOF", Release::EmptyEof),
        ("duplicated frame", Release::Duplicated),
        ("missing LF", Release::MissingLf),
        ("CRLF", Release::Crlf),
        ("trailing bytes", Release::TrailingBytes),
        ("leading blank line", Release::LeadingBlankLine),
        ("oversized", Release::Oversized),
        (
            "wrong schema",
            Release::WrongSchema("ouro.jail.gate/999".into()),
        ),
        ("wrong action", Release::WrongAction("abort".into())),
        (
            "wrong attempt id",
            Release::WrongAttemptId("att_00000000-0000-4000-8000-000000000002".into()),
        ),
        (
            "wrong digest",
            Release::WrongDigest(
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            ),
        ),
        ("malformed JSON", Release::MalformedJson),
        ("duplicate keys", Release::DuplicateKeys),
        ("not a frame at all", Release::Raw(b"release\n".to_vec())),
    ];

    for (name, variant) in variants {
        let case = Case::new();
        let (run, problems) = release_with(&case, &variant, &plan_matching(&case));
        assert!(problems.is_empty(), "{name}: the plan itself matched");
        assert_eq!(
            run.code(),
            Some(EXIT_REFUSED),
            "{name} was accepted; stderr: {}",
            run.stderr_text()
        );
        assert!(!case.marker_exists(), "{name} let the target run");
        assert_eq!(
            run.control_kind("refused").len(),
            1,
            "{name} produced no refusal message"
        );
        assert!(
            run.fixture_lines().is_empty(),
            "{name}: the target produced output"
        );
    }
}

#[test]
fn the_owner_withholds_when_a_binding_does_not_match_its_plan() {
    // I03 in miniature: the owner compares the prepared policy and argv
    // bindings with the plan it authorised, and a mismatch closes the gate.
    for (field, plan) in [
        (
            "attempt_id",
            plan_matching(&Case::new()).attempt_id("att_00000000-0000-4000-8000-0000000000ff"),
        ),
        (
            "policy_digest",
            plan_matching(&Case::new()).policy_digest("sha256:deadbeef"),
        ),
        (
            "argv_digest",
            plan_matching(&Case::new()).argv_digest("sha256:deadbeef"),
        ),
    ] {
        let case = Case::new();
        let (run, problems) = release_with(&case, &Release::Valid, &plan);
        assert_eq!(problems.len(), 1, "{field}: {problems:?}");
        assert!(problems[0].starts_with(field), "{problems:?}");
        assert_eq!(run.code(), Some(EXIT_REFUSED));
        assert!(!case.marker_exists(), "{field} mismatch let the target run");
    }
}

#[test]
fn the_target_inherits_only_stdio_and_no_channel_descriptor() {
    // X06 in miniature. The fixture enumerates its own descriptors; the
    // control, gate and trace ends must all be gone by the time it runs.
    let dir = TempDir::new("ouro-harness-fds").unwrap();
    let _ = dir.path();
    let mut spawned = Jail::with_program(stand_in())
        .unwrap()
        .control()
        .gate()
        .trace()
        .receipt()
        .target_fixture(["fds"])
        .spawn()
        .unwrap();
    {
        let mut owner = spawned.owner();
        let prepared = owner.await_prepared().unwrap();
        let id = prepared["attempt_id"].as_str().unwrap().to_string();
        owner
            .release(
                &Release::Valid,
                &id,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
    }
    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());

    let lines = run.fixture_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let fds: Vec<i64> = lines[0]["args"]["fds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["fd"].as_i64().unwrap())
        .collect();
    assert_eq!(
        fds,
        vec![0, 1, 2],
        "a channel descriptor reached the target: {fds:?}"
    );
}

#[test]
fn the_harness_closes_a_gate_the_test_forgot_and_says_so() {
    // Guard against a test that silently hangs or silently releases.
    let case = Case::new();
    let run = case.jail().run().unwrap();
    assert!(run.gate_closed_by_harness);
    assert_eq!(run.code(), Some(EXIT_REFUSED));
    assert!(!case.marker_exists());
}

#[test]
fn a_run_without_channels_still_works_and_keeps_its_state_private() {
    let dir = TempDir::new("ouro-harness-plain").unwrap();
    let marker = dir.path().join("plain");
    let run = Jail::with_program(stand_in())
        .unwrap()
        .target_fixture(["open", &marker.display().to_string(), "--create", "--write"])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(marker.exists());
    assert!(run.control_messages.is_empty());
    assert!(run.trace_events.is_empty());
}

#[test]
fn the_builder_gives_the_jail_the_environment_and_target_argv_it_was_given() {
    let dir = TempDir::new("ouro-harness-env").unwrap();
    let hostile = "a b\tc\nd'e\"f$(g)";
    let run = Jail::with_program(stand_in())
        .unwrap()
        .env("OURO_FIXTURE_HARNESS_MARK", "1")
        .target_fixture(["echo-args", "--", hostile])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let lines = run.fixture_lines();
    let bytes: Vec<u8> = lines[0]["args"]["argv"][0]["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| u8::try_from(b.as_u64().unwrap()).unwrap())
        .collect();
    assert_eq!(bytes, hostile.as_bytes(), "argv was altered in transit");
    let _ = dir.path();
}

#[test]
fn a_run_that_fails_to_start_is_an_error_not_a_pass() {
    let err = match Jail::with_program(Path::new("/nonexistent/ouro-jail"))
        .unwrap()
        .run()
    {
        Err(e) => e,
        Ok(_) => panic!("a missing jail binary must be an error, not a pass"),
    };
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
