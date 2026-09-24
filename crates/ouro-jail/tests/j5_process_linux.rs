#![cfg(target_os = "linux")]
//! J5 milestone proof: the process, gate-protocol and lifetime clauses that
//! J1 and J2 left without a live test (gap analysis §1.2, slice J5-B1).
//!
//! Each test names the §15 row and clause it closes and drives the real
//! `ouro-jail` binary on the reference host through the harness. Every run
//! uses private state; every process a test signals is one it started (the
//! jail it spawned, or a pid the jail's own receipt names for that attempt).
//! Live tests need `OURO_CONFORMANCE=1` on the reference host.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_fixture::harness::gate::{ExpectedPlan, Release};
use ouro_fixture::harness::{self, Jail, Run, Spawned};
use serde_json::Value;

mod common;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// A workspace holding a copy of the fixture, which must sit inside a
/// declared root to be executable in a contained profile.
fn workspace_with_fixture(root: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace");
    let inside = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &inside).expect("the fixture is copied in");
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o755))
        .expect("the fixture is executable");
    (workspace, inside)
}

struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
}

/// `run --profile <profile> --workspace <ws>` with trace and control.
fn case(profile: &str) -> Case {
    let jail = Jail::new().expect("a private jail harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let jail = jail
        .arg("run")
        .args(["--profile", profile])
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control();
    Case {
        jail,
        workspace,
        fixture,
    }
}

/// Every receipt the run left, each checked against the schema and the rules
/// it cannot state.
fn checked(run: &Run) -> Vec<Value> {
    assert!(
        run.receipt_errors().is_empty(),
        "{:?}",
        run.receipt_errors()
    );
    run.receipts()
        .into_iter()
        .map(common::checked_receipt)
        .collect()
}

/// The receipt with the highest revision.
fn last(run: &Run) -> Value {
    checked(run)
        .into_iter()
        .max_by_key(|receipt| receipt["revision"].as_u64().unwrap_or(0))
        .unwrap_or_else(|| panic!("no receipt; stderr: {}", run.stderr_text()))
}

fn settled(run: &Run) -> Value {
    let _ = checked(run);
    run.receipt_phase("settled").unwrap_or_else(|| {
        panic!(
            "no settled receipt (exit {:?}): {}",
            run.code(),
            run.stderr_text()
        )
    })
}

fn write_script(path: &Path, steps: &Value) {
    std::fs::write(path, serde_json::to_vec(steps).expect("JSON")).expect("the script");
}

/// A gated `tool` run whose target opens `marker`, with control and a gate.
/// Returns the spawned jail and the marker path the target would create.
fn gated_case() -> (Spawned, PathBuf) {
    let c = case("tool");
    let marker = c.workspace.join("target-ran");
    let spawned = c
        .jail
        .gate()
        .receipt()
        .target([
            c.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .spawn()
        .expect("the jail starts");
    (spawned, marker)
}

/// The prepared receipt's attempt id and policy digest, read from the
/// `prepared` control message and the durable prepared receipt.
fn prepared_binding(spawned: &mut Spawned) -> (String, String) {
    let control = spawned
        .owner()
        .await_prepared()
        .expect("a prepared message");
    let attempt = control["attempt_id"]
        .as_str()
        .expect("an attempt id")
        .to_owned();
    let receipt = common::checked_receipt(
        spawned
            .receipt_value()
            .expect("the prepared receipt is durable when `prepared` arrives"),
    );
    let digest = receipt["policy"]["digest"]
        .as_str()
        .expect("a digest")
        .to_owned();
    (attempt, digest)
}

/// The first error code among a run's receipts' errors.
fn error_code(run: &Run) -> Option<String> {
    for receipt in checked(run) {
        if let Some(errors) = receipt["errors"].as_array() {
            for error in errors {
                if let Some(code) = error["code"].as_str() {
                    return Some(code.to_owned());
                }
            }
        }
        if let Some(code) = receipt["outcome"]["error"]["code"].as_str() {
            return Some(code.to_owned());
        }
    }
    None
}

// ===========================================================================
// X04: exec failures and a child exit 125 have distinct outcomes
// ===========================================================================

/// One X04 case: its label, the settled or refused receipt's outcome, the
/// receipt's phase and the process exit code.
struct ExecCase {
    label: &'static str,
    outcome: Value,
    phase: String,
    code: Option<i32>,
    terminal_control: Vec<String>,
}

fn exec_case(
    profile: &str,
    label: &'static str,
    build: impl FnOnce(&Path) -> Vec<String>,
) -> ExecCase {
    let c = case(profile);
    let argv = build(&c.workspace);
    let run = c.jail.target(&argv).run().expect("the jail runs");
    let receipt = last(&run);
    let terminal_control = run
        .control_messages()
        .iter()
        .filter_map(|message| message["kind"].as_str())
        .filter(|kind| matches!(*kind, "refused" | "settled" | "unsettled"))
        .map(ToOwned::to_owned)
        .collect();
    ExecCase {
        label,
        outcome: receipt["outcome"].clone(),
        phase: receipt["phase"].as_str().unwrap_or("?").to_owned(),
        code: run.code(),
        terminal_control,
    }
}

fn x04_cases(profile: &str) -> Vec<ExecCase> {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = |ws: &Path| ws.join("ouro-fixture").display().to_string();
    vec![
        exec_case(profile, "missing executable", |ws| {
            vec![ws.join("no-such-program").display().to_string()]
        }),
        exec_case(profile, "missing interpreter", |ws| {
            let script = ws.join("needs-an-interpreter");
            std::fs::write(&script, b"#!/no/such/interpreter\nexit 0\n").unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            vec![script.display().to_string()]
        }),
        exec_case(profile, "permission error", |ws| {
            let file = ws.join("not-executable");
            std::fs::write(&file, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
            vec![file.display().to_string()]
        }),
        exec_case(profile, "child exit 125", |ws| {
            vec![fixture(ws), "exit".to_owned(), "125".to_owned()]
        }),
    ]
}

fn assert_x04(profile: &str) {
    let cases = x04_cases(profile);
    for case in &cases {
        eprintln!(
            "{profile} {}: exit={:?} phase={} outcome={} control={:?}",
            case.label, case.code, case.phase, case.outcome, case.terminal_control
        );
    }
    let [missing, interpreter, permission, exit125] = cases.as_slice() else {
        unreachable!()
    };
    // The three exec failures are proved exec errors, refused with 125, and
    // each is told apart by two stable machine fields, never by message text:
    // `outcome.cause` is the kernel's errno name (§13.2), which is ENOENT
    // for a missing program and for a missing interpreter alike, and
    // `outcome.error.code` separates those two (spec-proposal.md, X04).
    for (failure, cause, error_code) in [
        (missing, "ENOENT", "exec_failed"),
        (interpreter, "ENOENT", "exec_interpreter_missing"),
        (permission, "EACCES", "exec_failed"),
    ] {
        let label = failure.label;
        assert_eq!(failure.phase, "refused", "{profile} {label}");
        assert_eq!(failure.outcome["kind"], "exec_error", "{profile} {label}");
        assert_eq!(failure.outcome["cause"], cause, "{profile} {label}");
        assert_eq!(
            failure.outcome["error"]["code"], error_code,
            "{profile} {label}"
        );
        assert_eq!(failure.code, Some(125), "{profile} {label}");
        assert_eq!(failure.terminal_control, ["refused"], "{profile} {label}");
    }
    let machine = |case: &ExecCase| {
        (
            case.outcome["kind"].clone(),
            case.outcome["cause"].clone(),
            case.outcome["code"].clone(),
            case.outcome["error"]["code"].clone(),
        )
    };
    // A child that exits 125 exited: it is settled, never a refusal.
    assert_eq!(exit125.phase, "settled", "{profile}");
    assert_eq!(exit125.outcome["kind"], "exited");
    assert_eq!(exit125.outcome["code"], 125);
    assert_eq!(exit125.code, Some(125));
    assert_eq!(exit125.terminal_control, ["settled"]);
    // X04 itself: four distinct outcomes in their machine fields alone
    // (kind, cause, exit code, error code), messages left out.
    for (i, a) in cases.iter().enumerate() {
        for b in &cases[i + 1..] {
            assert_ne!(
                machine(a),
                machine(b),
                "{profile}: `{}` and `{}` share every machine field of their outcome",
                a.label,
                b.label
            );
        }
    }
    // And the missing interpreter says what is missing, so an operator is
    // not sent looking for a program that is there.
    let message = interpreter.outcome["error"]["message"]
        .as_str()
        .unwrap_or("");
    assert!(
        message.contains("interpreter"),
        "{profile}: the missing-interpreter outcome does not name the interpreter: {message}"
    );
    let message = missing.outcome["error"]["message"].as_str().unwrap_or("");
    assert!(
        !message.contains("interpreter"),
        "{profile}: a missing program is reported as a missing interpreter: {message}"
    );
}

#[test]
fn x04_missing_program_missing_interpreter_permission_and_exit_125_are_distinct_in_tool() {
    if !common::live() {
        return;
    }
    assert_x04("tool");
}

#[test]
fn x04_missing_program_missing_interpreter_permission_and_exit_125_are_distinct_in_none() {
    if !common::live() {
        return;
    }
    assert_x04("none");
}

// ===========================================================================
// X02: malformed and absent releases refuse with the target marker absent
// ===========================================================================

/// Every malformed release variant, live, refuses with the target's marker
/// absent — the clause the parser-only tests could not reach, because they
/// have no target to leave a marker (gap analysis §1.2, X02). Extra LF, which
/// the parser rejected but no live test exercised, is among them.
#[test]
fn x02_every_malformed_release_refuses_without_running_the_target() {
    if !common::live() {
        return;
    }
    let big = "sha256:".to_string() + &"0".repeat(64);
    let variants: Vec<(&str, Release)> = vec![
        ("extra LF", Release::ExtraLf),
        ("missing LF", Release::MissingLf),
        ("CRLF", Release::Crlf),
        ("trailing bytes", Release::TrailingBytes),
        ("leading blank line", Release::LeadingBlankLine),
        ("oversized", Release::Oversized),
        ("duplicate JSON keys", Release::DuplicateKeys),
        ("malformed JSON", Release::MalformedJson),
        (
            "wrong schema",
            Release::WrongSchema("ouro.jail.gate/999".into()),
        ),
        ("wrong action", Release::WrongAction("abort".into())),
        (
            "wrong attempt",
            Release::WrongAttemptId("att_00000000-0000-4000-8000-000000000000".into()),
        ),
        ("wrong digest", Release::WrongDigest(big)),
    ];
    for (label, variant) in variants {
        let (mut spawned, marker) = gated_case();
        let (attempt, digest) = prepared_binding(&mut spawned);
        spawned
            .owner()
            .release(&variant, &attempt, &digest)
            .expect("the frame is written");
        let run = spawned.wait().expect("the jail finishes");
        assert_eq!(run.code(), Some(125), "{label}: {}", run.stderr_text());
        assert!(
            !marker.exists(),
            "{label}: the target ran on a malformed release"
        );
        let refused = common::checked_receipt(
            run.receipt_phase("refused")
                .unwrap_or_else(|| panic!("{label}: no refused receipt")),
        );
        assert_eq!(refused["exec_observed"], false, "{label}");
        assert_eq!(refused["outcome"]["kind"], "refused", "{label}");
        // Not one target exec reached the trace.
        let execs = run
            .trace_events()
            .iter()
            .filter(|event| event["operation"] == "proc.exec")
            .count();
        assert_eq!(execs, 0, "{label}: a target exec happened");
    }
}

/// X02.1/X02.2/X02.5: a closed gate and a withheld gate put different
/// bytes on the wire and end differently, and neither runs the target. The
/// owner that closes says no at once: EOF with no frame, `gate_closed`,
/// within seconds. The owner that withholds says nothing and keeps the gate
/// open: no byte and no EOF, so the jail can only reach its 60-second gate
/// budget and refuse `prepare_timeout`. This is the slow X02 leg (it waits
/// the real budget once).
#[test]
fn x02_a_closed_and_a_withheld_gate_differ_and_neither_runs_the_target() {
    if !common::live() {
        return;
    }
    // Closed: EOF with nothing written.
    let (mut spawned, marker) = gated_case();
    let (attempt, digest) = prepared_binding(&mut spawned);
    let asked = Instant::now();
    spawned
        .owner()
        .release(&Release::EmptyEof, &attempt, &digest)
        .expect("the gate is closed");
    let closed = spawned.wait().expect("the jail finishes");
    let closed_after = asked.elapsed();
    assert_eq!(closed.code(), Some(125), "{}", closed.stderr_text());
    assert!(!marker.exists(), "the target ran after a closed gate");
    assert_eq!(error_code(&closed).as_deref(), Some("gate_closed"));
    assert!(
        closed_after < Duration::from_secs(10),
        "closed took {closed_after:?}"
    );

    // Withheld: the gate stays open with nothing written, past the budget.
    let c = case("tool");
    let marker = c.workspace.join("target-ran");
    let mut spawned = c
        .jail
        .timeout(Duration::from_secs(90))
        .gate()
        .receipt()
        .target([
            c.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .spawn()
        .expect("the jail starts");
    let held = {
        let mut owner = spawned.owner();
        owner.await_prepared().expect("a prepared message");
        owner.hold().expect("the gate is open")
    };
    let asked = Instant::now();
    let withheld = spawned
        .wait()
        .expect("the jail finishes at its gate budget");
    let withheld_after = asked.elapsed();
    drop(held);
    assert_eq!(withheld.code(), Some(125), "{}", withheld.stderr_text());
    assert!(!marker.exists(), "the target ran without a release");
    assert_eq!(error_code(&withheld).as_deref(), Some("prepare_timeout"));
    assert!(
        withheld_after >= Duration::from_secs(55),
        "a withheld gate ended after {withheld_after:?}, before the 60 s budget"
    );
}

// ===========================================================================
// I03: the real jail against an owner whose plan is its own
// ===========================================================================

/// A fresh attempt id the owner allocates itself (§7: UUIDv4, RFC 9562
/// variant, lowercase, `att_` prefix), so the attempt binding does not come
/// from the proposal being judged.
fn owner_attempt_id() -> String {
    use std::io::Read as _;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .expect("random bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "att_{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The owner's expected plan, computed from the owner's own operator inputs
/// and never from the prepared receipt it will judge (review H3): the policy
/// digest and requirements from `ouro-jail explain --json` over the profile,
/// workspace and state it will hand the jail (§6.1: explain resolves without
/// probing or executing), the argv digest from the argv it asked for through
/// the canonical argv framing, and the attempt id it allocated.
fn owner_plan(
    jail: &Jail,
    profile: &str,
    workspace: &Path,
    argv: &[&OsStr],
    attempt: &str,
) -> ExpectedPlan {
    use std::os::unix::ffi::OsStrExt as _;
    let output = std::process::Command::new(harness::jail_path())
        .args(["explain", "--json", "--profile", profile, "--workspace"])
        .arg(workspace)
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .output()
        .expect("explain runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "explain: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let explained: Value = serde_json::from_slice(&output.stdout).expect("explain --json");
    let digest = explained["policy"]["digest"]
        .as_str()
        .expect("a policy digest")
        .to_owned();
    let requirements: Vec<String> = explained["requirements"]
        .as_array()
        .expect("requirements")
        .iter()
        .map(|requirement| requirement["name"].as_str().expect("a name").to_owned())
        .collect();
    assert!(
        !requirements.is_empty(),
        "the operator inputs imply requirements"
    );
    let framed: Vec<Vec<u8>> = argv.iter().map(|part| part.as_bytes().to_vec()).collect();
    ExpectedPlan::complete(
        attempt,
        digest,
        ouro_jail::canonical::argv_digest(&framed),
        requirements,
    )
}

/// One managed `tool` run whose owner planned `plan_tail` and whose jail is
/// launched with `launch_tail` (the same unless a test models a request
/// changed after it was authorised). `late_project` is untrusted workspace
/// data (`ouro.toml`) written after the owner planned, as a submitter could.
/// Both tails get the fixture path in front and see the target's marker.
struct Owned {
    spawned: Spawned,
    marker: PathBuf,
    plan: ExpectedPlan,
    attempt: String,
}

fn owned_run(
    tails: impl FnOnce(&Path) -> (Vec<String>, Vec<String>),
    late_project: Option<&str>,
) -> Owned {
    let jail = Jail::new().expect("a private jail harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let marker = workspace.join("target-ran");
    let (plan_tail, launch_tail) = tails(&marker);
    let full = |tail: &[String]| -> Vec<std::ffi::OsString> {
        std::iter::once(fixture.clone().into_os_string())
            .chain(tail.iter().map(std::ffi::OsString::from))
            .collect()
    };
    let plan_argv = full(&plan_tail);
    let launch_argv = full(&launch_tail);
    let attempt = owner_attempt_id();
    let plan_refs: Vec<&OsStr> = plan_argv
        .iter()
        .map(std::ffi::OsString::as_os_str)
        .collect();
    let plan = owner_plan(&jail, "tool", &workspace, &plan_refs, &attempt);
    if let Some(text) = late_project {
        std::fs::write(workspace.join("ouro.toml"), text).expect("the late project file");
    }
    let spawned = jail
        .arg("run")
        .args(["--profile", "tool", "--workspace"])
        .arg(&workspace)
        .args(["--attempt-id", &attempt])
        .trace()
        .control()
        .gate()
        .receipt()
        .target(&launch_argv)
        .spawn()
        .expect("the jail starts");
    Owned {
        spawned,
        marker,
        plan,
        attempt,
    }
}

fn open_marker(marker: &Path) -> Vec<String> {
    vec![
        "open".to_owned(),
        marker.display().to_string(),
        "--create".to_owned(),
        "--write".to_owned(),
    ]
}

/// The owner judges the proposal against its own plan and, on any mismatch,
/// closes the gate. Returns the mismatches it found (empty: it released).
fn owner_decides(owned: &mut Owned) -> Vec<String> {
    let control = owned.spawned.owner().await_prepared().expect("prepared");
    let receipt = common::checked_receipt(owned.spawned.receipt_value().expect("a receipt"));
    match owned
        .spawned
        .owner()
        .authorise(&control, Some(&receipt), &owned.plan)
    {
        Ok(proposal) => {
            let digest = proposal.policy_digest.expect("a policy digest");
            owned
                .spawned
                .owner()
                .release(&Release::Valid, &owned.attempt, &digest)
                .expect("release");
            Vec::new()
        }
        Err((_, problems)) => {
            owned.spawned.owner().withhold();
            problems
        }
    }
}

/// I03.2 and I03.3: the owner compares the prepared attempt, policy digest,
/// argv digest and requirements with a plan it computed from its own inputs
/// (review H3: the plan used to be read from the receipt it judged, so a
/// product writing a wrong argv digest or dropping a requirement passed).
/// A matching plan releases the real jail exactly once; a request whose argv
/// changed after the owner authorised it is not released and runs nothing.
#[test]
fn i03_an_independent_full_plan_releases_once_and_a_mismatch_closes_the_gate() {
    if !common::live() {
        return;
    }
    let mut owned = owned_run(|marker| (open_marker(marker), open_marker(marker)), None);
    assert!(
        owned.plan.unbound().is_empty(),
        "the plan binds every field"
    );
    let problems = owner_decides(&mut owned);
    assert!(
        problems.is_empty(),
        "the owner's own plan did not match: {problems:?}"
    );
    let marker = owned.marker.clone();
    let run = owned.spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(marker.is_file(), "the released target did not run");
    let execs = run
        .trace_events()
        .iter()
        .filter(|event| event["operation"] == "proc.exec")
        .count();
    assert_eq!(execs, 1, "one release, one exec");

    // The request changed after authorisation: one more argument reached the
    // jail than the owner asked for. The argv digest differs, the owner
    // closes the gate, and nothing runs.
    let mut owned = owned_run(
        |marker| {
            let asked = open_marker(marker);
            let mut launched = asked.clone();
            launched.push("--trunc".to_owned());
            (asked, launched)
        },
        None,
    );
    let problems = owner_decides(&mut owned);
    assert!(
        problems
            .iter()
            .any(|problem| problem.starts_with("argv_digest:")),
        "{problems:?}"
    );
    let marker = owned.marker.clone();
    let run = owned.spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(!marker.exists(), "the target ran on a closed gate");
    assert_eq!(error_code(&run).as_deref(), Some("gate_closed"));
}

/// I03.4: the fields of the untrusted request — its argv and the project file
/// in its workspace (§6.2: steps 1-4 are the operator's; the workspace-root
/// `ouro.toml` is the contained party's) — cannot mutate the owner's operator
/// inputs. Operator-flag look-alikes in the argv stay literal and the policy
/// is exactly the owner's; a project file that selects a profile refuses
/// before anything is prepared; one that only narrows is still a change the
/// owner did not authorise, so its plan catches it and nothing runs.
#[test]
fn i03_untrusted_request_fields_cannot_mutate_the_owners_operator_inputs() {
    if !common::live() {
        return;
    }
    const LOOK_ALIKES: [&str; 6] = ["--profile", "none", "--rw", "/", "--observe", "off"];

    // (a) The request's argv carries operator flags after `--`.
    let mut owned = owned_run(
        |_| {
            let tail: Vec<String> = std::iter::once("echo-args".to_owned())
                .chain(std::iter::once("--".to_owned()))
                .chain(LOOK_ALIKES.iter().map(|part| (*part).to_owned()))
                .collect();
            (tail.clone(), tail)
        },
        None,
    );
    let problems = owner_decides(&mut owned);
    assert!(
        problems.is_empty(),
        "argv look-alikes changed the policy away from the owner's plan: {problems:?}"
    );
    let run = owned.spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let settled = settled(&run);
    assert_eq!(settled["policy"]["name"], "tool");
    assert_eq!(settled["policy"]["observe"], "on");
    assert_eq!(settled["policy"]["grants"], serde_json::json!([]));
    let echoed = run
        .fixture_lines()
        .into_iter()
        .find(|line| line["op"] == "echo-args")
        .expect("the target echoed its argv");
    assert_eq!(
        echoed["args"]["count"],
        LOOK_ALIKES.len(),
        "the look-alikes reached the target literally: {echoed}"
    );

    // (b) The request's project file tries to select a profile.
    let mut owned = owned_run(
        |marker| (open_marker(marker), open_marker(marker)),
        Some("[jail]\nprofile = \"none\"\n"),
    );
    let refused = owned.spawned.owner().await_prepared();
    assert!(
        refused.is_err(),
        "a project file selecting a profile was prepared"
    );
    let marker = owned.marker.clone();
    let run = owned.spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(!marker.exists());
    assert!(
        run.stderr_text().contains("policy_widening") && run.stderr_text().contains("jail.profile"),
        "{}",
        run.stderr_text()
    );

    // (c) The request's project file only narrows; the owner did not plan it.
    let mut owned = owned_run(
        |marker| (open_marker(marker), open_marker(marker)),
        Some("[jail.filesystem]\nread_only = [\"./ouro-fixture\"]\n"),
    );
    let problems = owner_decides(&mut owned);
    assert!(
        problems
            .iter()
            .any(|problem| problem.starts_with("policy_digest:")),
        "{problems:?}"
    );
    let marker = owned.marker.clone();
    let run = owned.spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(!marker.exists(), "the target ran on a closed gate");
}

// ===========================================================================
// X03: owner death before or during release never causes a second exec
// ===========================================================================

/// The owner of a managed run: a real process that holds the gate, so its
/// death is a real process death and a real gate close — the case the
/// launcher-kill test (`conformance_j1::x03_observation_off...`) does not
/// reach, because it kills the launcher, not the owner (gap analysis §1.2).
///
/// It is a subprocess so the driver can let it die at a chosen point. It
/// spawns `ouro-jail` in a process group of its own (so the owner's death
/// does not signal it), records the jail pid, waits for the prepared
/// receipt, then either exits without releasing (`before`) or writes one
/// valid frame and exits (`during`). Exiting closes the gate, which is
/// exactly what the kernel does to an owner's descriptors when it dies.
#[test]
#[ignore = "subprocess owner invoked by the X03 driver tests"]
fn j5_x03_owner_helper() {
    use std::os::unix::process::CommandExt as _;

    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is set"));
    let data = PathBuf::from(var("OURO_J5_X03_DATA"));
    let config = PathBuf::from(var("OURO_J5_X03_CONFIG"));
    let workspace = PathBuf::from(var("OURO_J5_X03_WORKSPACE"));
    let fixture = PathBuf::from(var("OURO_J5_X03_FIXTURE"));
    let marker = PathBuf::from(var("OURO_J5_X03_MARKER"));
    let pidfile = PathBuf::from(var("OURO_J5_X03_PIDFILE"));
    let mode = var("OURO_J5_X03_MODE");
    let jail_bin = PathBuf::from(var("OURO_J5_X03_JAIL"));

    // The gate: the read end goes to the jail as fd 3, the write end stays
    // here and closes when this process exits.
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let (gate_read, gate_write) = (fds[0], fds[1]);

    let mut command = std::process::Command::new(&jail_bin);
    command
        .args(["run", "--profile", "tool", "--workspace"])
        .arg(&workspace)
        .args(["--gate-fd", "3", "--"])
        .arg(&fixture)
        .args(["open"])
        .arg(&marker)
        .args(["--create", "--write"])
        .env("OURO_DATA_DIR", &data)
        .env("OURO_CONFIG_DIR", &config)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    // SAFETY: the closure runs between fork and exec and calls only dup2 and
    // fcntl over a descriptor built before the fork.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(gate_read, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Clear close-on-exec on fd 3 so the jail inherits the gate.
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("ouro-jail starts");
    std::fs::write(&pidfile, child.id().to_string()).expect("the pid file");
    // The read end belongs to the jail now.
    unsafe { libc::close(gate_read) };

    // Wait for the durable prepared receipt of this attempt.
    let attempts = data.join("attempts");
    let deadline = Instant::now() + Duration::from_secs(30);
    let prepared = loop {
        if Instant::now() >= deadline {
            std::process::exit(3);
        }
        if let Some(receipt) = read_only_prepared(&attempts) {
            break receipt;
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    if mode == "during" || mode == "mid-frame" {
        let attempt = prepared["attempt_id"].as_str().unwrap();
        let digest = prepared["policy"]["digest"].as_str().unwrap();
        let frame = ouro_fixture::harness::gate::frame_body(attempt, digest) + "\n";
        // `mid-frame`: the owner dies having written only the first half.
        let frame = if mode == "mid-frame" {
            frame[..frame.len() / 2].to_owned()
        } else {
            frame
        };
        let bytes = frame.as_bytes();
        let mut written = 0;
        while written < bytes.len() {
            let n = unsafe {
                libc::write(
                    gate_write,
                    bytes[written..].as_ptr().cast::<libc::c_void>(),
                    bytes.len() - written,
                )
            };
            assert!(n > 0, "the gate write failed");
            written += n as usize;
        }
    }
    // Exit now: the gate write end closes with us. In `before` mode nothing
    // was written, so the jail sees an empty EOF; in `during` mode it sees
    // the one frame and then EOF. Either way the owner is gone.
    let _ = gate_write;
    std::process::exit(0);
}

/// The prepared receipt of the one attempt under `attempts`, or `None` until
/// it is durable. Read-only: never signals or removes anything.
fn read_only_prepared(attempts: &Path) -> Option<Value> {
    let entries = std::fs::read_dir(attempts).ok()?;
    for entry in entries.flatten() {
        let path = entry.path().join("jail.json");
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(value) = serde_json::from_str::<Value>(&text)
            && value["phase"] == "prepared"
        {
            return Some(value);
        }
    }
    None
}

/// Run the owner helper in `mode`, let it die, and return the terminal
/// receipt the reparented jail left, the marker path and the count of target
/// execs in the local trace.
fn x03_owner_run(mode: &str) -> (Value, bool, usize) {
    let root = common::private_tempdir();
    let data = root.path().join("data");
    let config = root.path().join("config");
    let workspace = root.path().join("workspace");
    for dir in [&data, &config, &workspace] {
        std::fs::create_dir_all(dir).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let fixture = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    let marker = workspace.join("target-ran");
    let pidfile = root.path().join("jail.pid");

    let mut owner = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "j5_x03_owner_helper"])
        .env("OURO_J5_X03_DATA", &data)
        .env("OURO_J5_X03_CONFIG", &config)
        .env("OURO_J5_X03_WORKSPACE", &workspace)
        .env("OURO_J5_X03_FIXTURE", &fixture)
        .env("OURO_J5_X03_MARKER", &marker)
        .env("OURO_J5_X03_PIDFILE", &pidfile)
        .env("OURO_J5_X03_MODE", mode)
        .env("OURO_J5_X03_JAIL", harness::jail_path())
        .env("OURO_CONFORMANCE", "1")
        .spawn()
        .expect("the owner starts");
    let owner_status = owner.wait().expect("the owner exits");
    assert!(
        owner_status.success(),
        "the owner did not exit cleanly: {owner_status:?}"
    );

    // The jail was reparented when its owner died; wait for it to finish by
    // its recorded pid (a pid we started, whose cwd is our own workspace).
    let jail_pid: i32 = std::fs::read_to_string(&pidfile)
        .expect("the owner recorded the jail pid")
        .trim()
        .parse()
        .expect("a pid");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Path::new(&format!("/proc/{jail_pid}")).exists() {
        if Instant::now() >= deadline {
            // SAFETY: `jail_pid` is the process this test's own owner started,
            // recorded in our pid file, with its cwd inside our workspace.
            unsafe { libc::kill(jail_pid, libc::SIGKILL) };
            panic!("the reparented jail did not finish");
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // The terminal receipt of the one attempt.
    let attempts = data.join("attempts");
    let attempt_dir = std::fs::read_dir(&attempts)
        .expect("an attempt directory")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("one attempt");
    let receipt: Value = serde_json::from_str(
        &std::fs::read_to_string(attempt_dir.join("jail.json")).expect("the terminal receipt"),
    )
    .expect("valid JSON");
    common::assert_semantic_receipt(&receipt);
    let execs = std::fs::read_to_string(attempt_dir.join("trace.ndjson"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["operation"] == "proc.exec")
        .count();
    (receipt, marker.exists(), execs)
}

/// The owner dies after `prepared` but before writing any release: the jail
/// refuses, no target runs, and no exec ever reaches the trace.
#[test]
fn x03_owner_death_before_release_runs_no_target() {
    if !common::live() {
        return;
    }
    let (receipt, marker, execs) = x03_owner_run("before");
    assert_eq!(receipt["phase"], "refused", "{receipt:#}");
    assert_eq!(receipt["exec_observed"], false);
    assert!(
        !marker,
        "the target ran after the owner died before releasing"
    );
    assert_eq!(execs, 0, "an exec happened with no release");
}

/// The owner dies halfway through writing its frame: what reached the gate
/// is a torn frame and EOF, so the jail refuses and no target runs.
#[test]
fn x03_owner_death_mid_frame_runs_no_target() {
    if !common::live() {
        return;
    }
    let (receipt, marker, execs) = x03_owner_run("mid-frame");
    assert_eq!(receipt["phase"], "refused", "{receipt:#}");
    assert_eq!(receipt["exec_observed"], false);
    assert_eq!(
        receipt["outcome"]["error"]["code"], "gate_invalid",
        "{receipt:#}"
    );
    assert!(!marker, "the target ran on a torn frame");
    assert_eq!(execs, 0, "an exec happened on a torn frame");
}

/// The owner writes exactly one valid frame and dies: the jail releases once,
/// the target runs once, and the owner's death causes no second exec.
#[test]
fn x03_owner_death_during_release_execs_exactly_once() {
    if !common::live() {
        return;
    }
    let (receipt, marker, execs) = x03_owner_run("during");
    assert_eq!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(receipt["exec_observed"], true);
    assert_eq!(receipt["outcome"]["kind"], "exited");
    assert_eq!(receipt["outcome"]["code"], 0);
    assert!(marker, "the released target did not run");
    assert_eq!(execs, 1, "the owner's death caused a second exec");
}

// ===========================================================================
// X06: no capability set reaches the target
// ===========================================================================

/// Every contained profile hands the target an empty capability set — not
/// just `CapEff` (which `conformance_j1::x06` checks) but `CapInh`, `CapPrm`,
/// `CapBnd` and `CapAmb` too (gap analysis §1.2). An inheritable or bounding
/// bit left set would let a later `execve` of a file with capabilities raise
/// privilege inside the sandbox; the whole set is zero.
#[test]
fn x06_every_contained_profile_hands_the_target_an_empty_capability_set() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "agent", "build"] {
        let c = case(profile);
        let script = c.workspace.join("status.json");
        write_script(&script, &serde_json::json!([["status"]]));
        let mut jail = c.jail;
        if profile == "build" {
            // §6.4: `build` requires an explicit memory ceiling, and its
            // baseline makes the workspace neither read-write nor read-only,
            // so the fixture and its script are exposed read-only.
            jail = jail
                .args(["--limit", "mem=64MiB", "--ro"])
                .arg(&c.workspace);
        }
        let run = jail
            .target([
                c.fixture.as_os_str(),
                OsStr::new("script"),
                script.as_os_str(),
            ])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let status = run
            .fixture_lines()
            .into_iter()
            .find(|line| line["op"] == "status")
            .unwrap_or_else(|| panic!("{profile}: no status line: {}", run.stdout_text()));
        for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let value = status["args"]["fields"][field]
                .as_str()
                .unwrap_or_else(|| panic!("{profile}: {field} absent: {status:#}"));
            assert!(
                value.chars().all(|c| c == '0'),
                "{profile}: {field} is {value}, not empty"
            );
        }
    }
}

// ===========================================================================
// P03: an edit the child itself makes cannot widen the running attempt
// ===========================================================================

/// P03.2: after release the child itself truncates both files its run was
/// resolved from — the operator profile file selected with `--profile` (it
/// sits in the child's writable workspace) and the project `ouro.toml` — and
/// the run's authority does not move: the settled digest and mounts equal
/// the prepared ones, and the denials both files set still hold at run time.
/// (Review MEDIUM: the earlier test edited a profile look-alike the run never
/// loaded.)
#[test]
fn p03_the_child_truncating_its_selected_profile_and_project_file_does_not_widen_the_run() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().expect("a private jail harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    for dir in ["by-profile", "by-project"] {
        std::fs::create_dir_all(workspace.join(dir)).unwrap();
        std::fs::write(workspace.join(dir).join("classified"), b"classified\n").unwrap();
    }
    let profile = workspace.join("profile.toml");
    std::fs::write(
        &profile,
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n\n[filesystem]\ndeny_read = [\"./by-profile\"]\n",
    )
    .unwrap();
    let project = workspace.join("ouro.toml");
    std::fs::write(
        &project,
        "[jail.filesystem]\ndeny_read = [\"./by-project\"]\n",
    )
    .unwrap();
    let script = workspace.join("attack.json");
    write_script(
        &script,
        &serde_json::json!([
            ["open", "by-profile/classified", "--expect", "ENOENT"],
            ["open", "by-project/classified", "--expect", "ENOENT"],
            [
                "open",
                profile.to_str().unwrap(),
                "--create",
                "--write",
                "--trunc"
            ],
            [
                "open",
                project.to_str().unwrap(),
                "--create",
                "--write",
                "--trunc"
            ],
            ["open", "by-profile/classified", "--expect", "ENOENT"],
            ["open", "by-project/classified", "--expect", "ENOENT"],
        ]),
    );
    let mut spawned = jail
        .arg("run")
        .arg("--profile")
        .arg(&profile)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control()
        .gate()
        .receipt()
        .target([
            fixture.as_os_str(),
            OsStr::new("script"),
            script.as_os_str(),
        ])
        .spawn()
        .expect("the jail starts");
    let (attempt, prepared_digest) = prepared_binding(&mut spawned);
    let prepared = spawned.receipt_value().expect("a prepared receipt");
    let prepared_mounts = prepared["applied"]["filesystem"]["mounts"].clone();
    assert_eq!(
        prepared["policy"]["name"], "profile",
        "the run loaded the selected file"
    );
    spawned
        .owner()
        .release(&Release::Valid, &attempt, &prepared_digest)
        .expect("release");
    let run = spawned.wait().expect("the jail finishes");
    // Every expectation held, including both ENOENT reads after the edits.
    assert_eq!(
        run.code(),
        Some(0),
        "a denial did not hold: {}",
        run.stdout_text()
    );
    let settled = settled(&run);
    assert_eq!(
        settled["policy"]["digest"].as_str(),
        Some(prepared_digest.as_str())
    );
    assert_eq!(settled["applied"]["filesystem"]["mounts"], prepared_mounts);
    // The child really emptied both files it was resolved from.
    assert_eq!(std::fs::metadata(&profile).unwrap().len(), 0);
    assert_eq!(std::fs::metadata(&project).unwrap().len(), 0);
}

// ===========================================================================
// P04: a scratch root that overlaps the state directory refuses before exec
// ===========================================================================

/// An explicit `--scratch` that overlaps the private state root refuses
/// before the target runs. `child_visible_roots` includes a host scratch, so
/// the state-isolation check (§7: "outside every child-visible grant") must
/// catch it, not only the workspace and host grants the existing P04 tests
/// use (gap analysis §1.2, P04).
#[test]
fn p04_a_scratch_root_overlapping_the_state_directory_refuses() {
    if !common::live() {
        return;
    }
    // The scratch is the data directory itself: a child-writable scratch that
    // contains the attempts, receipts and policy snapshots.
    let c = case("tool");
    let data = c.jail.data_dir();
    std::fs::create_dir_all(&data).unwrap();
    let marker = c.workspace.join("target-ran");
    let run = c
        .jail
        .arg("--scratch")
        .arg(&data)
        .target([
            c.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(!marker.exists(), "the target ran before the refusal");
    assert!(
        run.stderr_text().contains("unsafe_state_path"),
        "the refusal is not the state-overlap one: {}",
        run.stderr_text()
    );
}

// ===========================================================================
// §6.4: an exec that observation-off cannot confirm is a coded tool error
// ===========================================================================

/// One `--observe off` run of `target` under `profile`: exit code, stderr
/// lines, the last receipt.
fn observe_off_run(profile: &str, target: &[&str]) -> (Option<i32>, Vec<String>, Value) {
    let c = case(profile);
    let run = c
        .jail
        .args(["--observe", "off"])
        .target(target)
        .run()
        .expect("the jail runs");
    let lines = run
        .stderr_text()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect();
    (run.code(), lines, last(&run))
}

/// With observation off, a target that ends before the supervisor can see
/// its new image leaves exec unconfirmed: the outcome stays an honest
/// `unknown`, and §6.4 makes the exit 1 a tool error with a stable code and
/// one stderr line — not a bare exit 1 with an empty `errors[]` and nothing
/// on stderr (found by the J5-C and J5-E reviews). A target that lives long
/// enough to be seen still exits 0 with no error.
#[test]
fn observe_off_an_unconfirmed_fast_exec_is_the_coded_error_exec_unconfirmed() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "agent"] {
        // `/bin/true` ends within microseconds; a few tries make sure the
        // unconfirmed branch is actually reached, and every unconfirmed run
        // must carry the code.
        let mut unconfirmed = 0;
        for _ in 0..5 {
            let (code, stderr, receipt) = observe_off_run(profile, &["/bin/true"]);
            if receipt["exec_observed"] == true {
                assert_eq!(code, Some(0), "{profile}: a confirmed exec of true");
                continue;
            }
            unconfirmed += 1;
            assert_eq!(
                receipt["outcome"]["kind"], "unknown",
                "{profile}: {receipt:#}"
            );
            assert_eq!(code, Some(1), "{profile}: exit 1 is a tool error");
            let errors = receipt["errors"].as_array().expect("errors[]");
            assert_eq!(
                errors.first().map(|error| error["code"].clone()),
                Some(Value::from("exec_unconfirmed")),
                "{profile}: {receipt:#}"
            );
            assert_eq!(errors[0]["stage"], "running", "{profile}");
            assert_eq!(errors[0]["remediation_category"], "configuration");
            assert!(
                errors[0]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("--observe on")),
                "{profile}: the message does not say how to confirm the exec: {}",
                errors[0]
            );
            assert_eq!(stderr.len(), 1, "{profile}: one stderr line: {stderr:?}");
            assert!(stderr[0].contains("exec_unconfirmed"), "{stderr:?}");
        }
        assert!(
            unconfirmed > 0,
            "{profile}: never reached the unconfirmed branch"
        );

        // A target that lives long enough to be seen is confirmed and clean.
        let (code, stderr, receipt) = observe_off_run(profile, &["/bin/sh", "-c", "sleep 0.3"]);
        assert_eq!(receipt["exec_observed"], true, "{profile}: {receipt:#}");
        assert_eq!(code, Some(0), "{profile}: {stderr:?}");
        assert_eq!(receipt["errors"], serde_json::json!([]), "{profile}");
    }
}

// ===========================================================================
// P02.8: a project file selecting or extending a profile refuses, via `run`
// ===========================================================================

/// Through `ouro-jail run`, a workspace `ouro.toml` that selects a profile or
/// extends one refuses before anything is prepared, with the exact key path.
/// The portable P02 test injects the forbidden key into a delta directly, so
/// deleting the detection in `resolve_plan` left it green (rev-A H5).
#[test]
fn p02_a_project_file_selecting_or_extending_a_profile_refuses_through_run() {
    if !common::live() {
        return;
    }
    for (text, key) in [
        ("[jail]\nprofile = \"tool\"\n", "jail.profile"),
        ("[jail]\nextends = \"tool\"\n", "jail.extends"),
    ] {
        let c = case("tool");
        std::fs::write(c.workspace.join("ouro.toml"), text).expect("the project file");
        let marker = c.workspace.join("target-ran");
        let run = c
            .jail
            .target([
                c.fixture.as_os_str(),
                OsStr::new("open"),
                marker.as_os_str(),
                OsStr::new("--create"),
                OsStr::new("--write"),
            ])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(125), "{key}: {}", run.stderr_text());
        assert!(!marker.exists(), "{key}: the target ran");
        let stderr = run.stderr_text();
        assert!(
            stderr.contains("policy_widening") && stderr.contains(&format!("(key: {key})")),
            "{key}: {stderr}"
        );
        assert!(
            run.control_kind("prepared").is_empty(),
            "{key}: it was prepared"
        );
    }
}

// ===========================================================================
// P01.8: a non-UTF-8 policy path survives execution into the receipt
// ===========================================================================

/// A `--deny-read` whose name is not UTF-8 is enforced and recorded losslessly:
/// the run executes, the child cannot see the file beneath it, and the
/// receipt's grant and applied mask carry the exact bytes as the base64
/// native-string object (canonicalization.md), not a lossy string.
#[test]
fn p01_a_non_utf8_policy_path_survives_execution_into_the_receipt() {
    if !common::live() {
        return;
    }
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    let c = case("tool");
    let name: &[u8] = b"sec\xffret";
    let denied = c.workspace.join(OsStr::from_bytes(name));
    std::fs::create_dir(&denied).expect("the non-UTF-8 directory");
    std::fs::write(denied.join("file"), b"hidden\n").expect("a file inside");
    let inside = denied.join("file");
    let run = c
        .jail
        .arg("--deny-read")
        .arg(&denied)
        .target([
            c.fixture.as_os_str(),
            OsStr::new("open"),
            inside.as_os_str(),
            OsStr::new("--expect"),
            OsStr::new("ENOENT"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(
        run.code(),
        Some(0),
        "the masked read was not ENOENT: {}",
        run.stdout_text()
    );
    let receipt = settled(&run);
    let want = denied.clone().into_os_string().into_vec();
    let decodes_to =
        |value: &Value| common::native_bytes(value).ok().as_deref() == Some(want.as_slice());
    let grants = receipt["policy"]["grants"].as_array().expect("grants");
    assert!(
        grants.iter().any(|grant| decodes_to(&grant["value"])),
        "the grant does not carry the exact bytes: {grants:#?}"
    );
    let mounts = receipt["applied"]["filesystem"]["mounts"]
        .as_array()
        .expect("mounts");
    assert!(
        mounts.iter().any(|mount| decodes_to(&mount["path"])),
        "no applied mount carries the exact bytes: {mounts:#?}"
    );
}

// ===========================================================================
// P04: overlaps, symlinks and unsafe state roots refuse before exec, via run
// ===========================================================================

/// One `tool` run whose target would create a marker, with the harness's
/// state root replaced by `data` (when given) and `extra` jail arguments.
/// Returns the exit code, stderr and whether the target ran.
fn p04_run(data: Option<&Path>, extra: &[&OsStr]) -> (Option<i32>, String, bool) {
    let c = case("tool");
    let marker = c.workspace.join("target-ran");
    let mut jail = c.jail.args(extra.iter().copied());
    if let Some(data) = data {
        jail = jail.env("OURO_DATA_DIR", data);
    }
    let run = jail
        .target([
            c.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .run()
        .expect("the jail runs");
    (run.code(), run.stderr_text(), marker.exists())
}

/// P04 (state/scratch/receipt overlap, the scratch-receipt pair): a
/// `--receipt` path inside the `--scratch` root, which the child can write,
/// refuses before exec as a usage error naming `--receipt`.
#[test]
fn p04_a_receipt_path_inside_the_scratch_root_refuses() {
    if !common::live() {
        return;
    }
    let outer = common::private_tempdir();
    let scratch = outer.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let receipt = scratch.join("receipt.json");
    let (code, stderr, ran) = p04_run(
        None,
        &[
            OsStr::new("--scratch"),
            scratch.as_os_str(),
            OsStr::new("--receipt"),
            receipt.as_os_str(),
        ],
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!ran, "the target ran");
    assert!(
        stderr.contains("invalid_config") && stderr.contains("(key: --receipt)"),
        "{stderr}"
    );
    assert!(
        !receipt.exists(),
        "a receipt was written inside the scratch"
    );
}

/// P04.6: the state root overlapping an operator grant refuses before exec,
/// in both directions: an `--ro` grant of the state root's parent (the root
/// is beneath the grant) and an `--rw` grant beneath the state root.
#[test]
fn p04_a_state_root_overlapping_an_ro_or_rw_grant_refuses() {
    if !common::live() {
        return;
    }
    let outer = common::private_tempdir();
    let data = outer.path().join("state");
    std::fs::create_dir(&data).unwrap();
    let inner = data.join("inner");
    std::fs::create_dir(&inner).unwrap();
    for (label, extra) in [
        (
            "--ro over the state root",
            vec![OsStr::new("--ro"), outer.path().as_os_str()],
        ),
        (
            "--rw beneath the state root",
            vec![OsStr::new("--rw"), inner.as_os_str()],
        ),
    ] {
        let (code, stderr, ran) = p04_run(Some(&data), &extra);
        assert_eq!(code, Some(125), "{label}: {stderr}");
        assert!(!ran, "{label}: the target ran");
        assert!(stderr.contains("unsafe_state_path"), "{label}: {stderr}");
    }
}

/// P04.7: a state root reached through a symlink refuses before exec.
#[test]
fn p04_a_symlinked_state_root_refuses_through_run() {
    if !common::live() {
        return;
    }
    let outer = common::private_tempdir();
    let real = outer.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = outer.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (code, stderr, ran) = p04_run(Some(&link), &[]);
    assert_eq!(code, Some(125), "{stderr}");
    assert!(!ran, "the target ran");
    assert!(stderr.contains("unsafe_state_path"), "{stderr}");
}

/// P04.8: a `--receipt` path that is a symlink refuses before exec, and the
/// symlink's target is not written.
#[test]
fn p04_a_symlinked_receipt_path_refuses() {
    if !common::live() {
        return;
    }
    let outer = common::private_tempdir();
    let target = outer.path().join("elsewhere.json");
    let link = outer.path().join("receipt.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (code, stderr, ran) = p04_run(None, &[OsStr::new("--receipt"), link.as_os_str()]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!ran, "the target ran");
    assert!(
        stderr.contains("invalid_config") && stderr.contains("--receipt"),
        "{stderr}"
    );
    assert!(!target.exists(), "the symlink's target was written");
}

/// P04.9: through `run`, a state root with an unsafe mode (writable by
/// others) or a foreign owner (root's) refuses before exec.
#[test]
fn p04_an_unsafe_state_root_mode_or_owner_refuses_through_run() {
    if !common::live() {
        return;
    }
    use std::os::unix::fs::PermissionsExt as _;
    let outer = common::private_tempdir();
    let open = outer.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (code, stderr, ran) = p04_run(Some(&open), &[]);
    assert_eq!(code, Some(125), "mode 0777: {stderr}");
    assert!(!ran);
    assert!(stderr.contains("unsafe_state_path"), "mode 0777: {stderr}");
    // A directory owned by root with mode 0700, so only the owner rule can
    // refuse it (a 0755 one would also fail the mode rule).
    let foreign = Path::new("/root");
    let metadata = std::fs::symlink_metadata(foreign).unwrap();
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&metadata), 0);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    let (code, stderr, ran) = p04_run(Some(foreign), &[]);
    assert_eq!(code, Some(125), "foreign owner: {stderr}");
    assert!(!ran);
    assert!(
        stderr.contains("unsafe_state_path"),
        "foreign owner: {stderr}"
    );
}

// ===========================================================================
// X02.8: an attempt id with a wrong RFC 9562 variant or uppercase hex
// ===========================================================================

/// `--attempt-id` must be a lowercase UUIDv4 with the RFC 9562 variant. A
/// wrong variant nibble and uppercase hex are usage errors (exit 2) before
/// anything is allocated, with the gate never read.
#[test]
fn x02_an_attempt_id_with_a_wrong_variant_or_uppercase_hex_is_a_usage_error() {
    if !common::live() {
        return;
    }
    for (label, id) in [
        ("variant 0", "att_00000000-0000-4000-0000-000000000001"),
        (
            "variant c (Microsoft)",
            "att_00000000-0000-4000-c000-000000000001",
        ),
        (
            "variant e (future)",
            "att_00000000-0000-4000-e000-000000000001",
        ),
        ("uppercase hex", "att_0000000A-0000-4000-8000-00000000000B"),
    ] {
        let c = case("tool");
        let marker = c.workspace.join("target-ran");
        let run = c
            .jail
            .args(["--attempt-id", id])
            .gate()
            .target([
                c.fixture.as_os_str(),
                OsStr::new("open"),
                marker.as_os_str(),
                OsStr::new("--create"),
                OsStr::new("--write"),
            ])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(2), "{label}: {}", run.stderr_text());
        assert!(!marker.exists(), "{label}");
        assert!(
            run.stderr_text().contains("--attempt-id"),
            "{label}: {}",
            run.stderr_text()
        );
        assert!(run.control_kind("prepared").is_empty(), "{label}");
        assert!(
            !run.data_dir.join("attempts").exists()
                || std::fs::read_dir(run.data_dir.join("attempts"))
                    .unwrap()
                    .next()
                    .is_none(),
            "{label}: an attempt directory was allocated"
        );
    }
}

// ===========================================================================
// X05.3: EOF reaches the caller when the target closes its stdout
// ===========================================================================

/// When `argv` closes its stdout and then lives for three seconds, how long
/// after the start the caller saw EOF on stdout and how long until the
/// process it started exited.
fn stdout_eof_and_exit(
    program: &Path,
    args: &[&OsStr],
    data: Option<(&Path, &Path)>,
) -> (Duration, Duration) {
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    if let Some((data, config)) = data {
        command
            .env("OURO_DATA_DIR", data)
            .env("OURO_CONFIG_DIR", config);
    }
    let start = Instant::now();
    let mut child = command.spawn().expect("the command starts");
    let mut stdout = child.stdout.take().expect("a stdout pipe");
    let reader = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = stdout.read_to_end(&mut sink);
        start.elapsed()
    });
    let deadline = start + Duration::from_secs(30);
    let exited = loop {
        if child.try_wait().expect("wait").is_some() {
            break start.elapsed();
        }
        assert!(Instant::now() < deadline, "the command did not end");
        std::thread::sleep(Duration::from_millis(5));
    };
    let eof = reader.join().expect("the reader");
    (eof, exited)
}

/// X05.3 under `none` (§8.3: "The supervisor must not retain writable copies
/// that postpone EOF"): a target that closes its stdout and keeps running
/// delivers EOF to the caller at once, as it does run directly, long before
/// the target and the jail end. The supervisor used to keep its own copy of
/// stdout for the whole run. Under the contained profiles bubblewrap's outer
/// process and namespace init still hold the stdio they hand the child, so
/// the same test there is a recorded finding, not a claim (notes, X05.3).
#[test]
fn x05_under_none_eof_reaches_the_caller_when_the_target_closes_its_stdout() {
    if !common::live() {
        return;
    }
    let script = "exec >&-; sleep 3";
    let (direct_eof, direct_exit) = stdout_eof_and_exit(
        Path::new("/bin/sh"),
        &[OsStr::new("-c"), OsStr::new(script)],
        None,
    );
    assert!(
        direct_exit >= Duration::from_secs(3) && direct_eof < Duration::from_secs(1),
        "direct: eof {direct_eof:?} exit {direct_exit:?}"
    );
    let jail = Jail::new().expect("a private jail harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let (eof, exit) = stdout_eof_and_exit(
        &harness::jail_path(),
        &[
            OsStr::new("run"),
            OsStr::new("--profile"),
            OsStr::new("none"),
            OsStr::new("--workspace"),
            workspace.as_os_str(),
            OsStr::new("--"),
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new(script),
        ],
        Some((&jail.data_dir(), &jail.config_dir())),
    );
    assert!(
        exit >= Duration::from_secs(3),
        "the jail ended early: {exit:?}"
    );
    assert!(
        eof + Duration::from_secs(2) < exit,
        "stdout EOF at {eof:?} waited for the jail's exit at {exit:?}"
    );
}
