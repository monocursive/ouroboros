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

/// "Withheld" (the owner closes the gate with nothing) and "timed out" (the
/// owner holds the gate open and never releases) are the two no-release
/// outcomes, and they are distinct: withheld reaches EOF and refuses
/// `gate_closed`; the timeout refuses `prepare_timeout` after the 60-second
/// gate budget. Both leave the target unrun. This is the slow X02 leg (it
/// waits the real gate budget once), so it is one test.
#[test]
fn x02_withheld_is_gate_closed_and_a_never_delivered_gate_times_out() {
    if !common::live() {
        return;
    }
    // Withheld: the owner closes the gate with no frame.
    let (mut spawned, marker) = gated_case();
    prepared_binding(&mut spawned);
    spawned.owner().withhold();
    let withheld = spawned.wait().expect("the jail finishes");
    assert_eq!(withheld.code(), Some(125), "{}", withheld.stderr_text());
    assert!(!marker.exists(), "the target ran after a withheld gate");
    assert_eq!(error_code(&withheld).as_deref(), Some("gate_closed"));

    // Timed out: the owner keeps the gate open and never writes. The jail
    // refuses at its 60-second gate budget, so the harness deadline is set
    // above it.
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
        // Take the gate writer and keep it open past `wait`, so the jail
        // sees neither a frame nor EOF and must reach its own budget.
        owner.hold().expect("the gate is open")
    };
    let timed_out = spawned
        .wait()
        .expect("the jail finishes at its gate budget");
    drop(held);
    assert_eq!(timed_out.code(), Some(125), "{}", timed_out.stderr_text());
    assert!(!marker.exists(), "the target ran without a release");
    assert_eq!(error_code(&timed_out).as_deref(), Some("prepare_timeout"));
    // The two no-release outcomes are distinguishable.
    assert_ne!(error_code(&withheld), error_code(&timed_out));
}

// ===========================================================================
// I03: the real jail against an owner that binds the full plan
// ===========================================================================

/// The scripted owner binds the attempt, policy digest, argv digest and the
/// applied requirements, and only a matching plan releases the real jail
/// once; a plan that disagrees on any of them closes the gate with no marker.
/// This is I03 against `ouro-jail` itself, not the harness stand-in.
#[test]
fn i03_a_full_plan_releases_once_and_any_mismatch_closes_the_gate() {
    if !common::live() {
        return;
    }
    // The plan the owner authorises: read the prepared proposal and bind
    // every field, so the owner is comparing against a real, complete plan.
    let (mut spawned, marker) = gated_case();
    let control = spawned.owner().await_prepared().expect("prepared");
    let receipt = common::checked_receipt(spawned.receipt_value().expect("a prepared receipt"));
    let attempt = control["attempt_id"].as_str().unwrap().to_owned();
    let digest = receipt["policy"]["digest"].as_str().unwrap().to_owned();
    let argv_digest = receipt["argv_digest"]
        .as_str()
        .expect("an argv digest")
        .to_owned();
    let requirements: Vec<String> = receipt["policy"]["requirements"]
        .as_array()
        .expect("the requirements")
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect();
    assert!(!requirements.is_empty(), "a tool attempt has requirements");
    let plan = ExpectedPlan::complete(&attempt, &digest, &argv_digest, requirements.clone());
    let proposal = spawned
        .owner()
        .authorise(&control, Some(&receipt), &plan)
        .unwrap_or_else(|(_, problems)| panic!("the full plan did not match: {problems:?}"));
    assert_eq!(
        proposal.requirements,
        Some({
            let mut sorted = requirements.clone();
            sorted.sort();
            sorted.dedup();
            sorted
        })
    );
    spawned
        .owner()
        .release(&Release::Valid, &attempt, &digest)
        .expect("release");
    let run = spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(marker.is_file(), "the released target did not run");
    let execs = run
        .trace_events()
        .iter()
        .filter(|event| event["operation"] == "proc.exec")
        .count();
    assert_eq!(execs, 1, "one release, one exec");

    // A plan that disagrees on the requirements would not authorise this
    // proposal, and an owner that withholds on that mismatch runs no target.
    let dropped = requirements.last().cloned().unwrap();
    let widened: Vec<String> = requirements
        .iter()
        .filter(|name| **name != dropped)
        .cloned()
        .collect();
    let (mut spawned, marker) = gated_case();
    let control = spawned.owner().await_prepared().expect("prepared");
    let receipt = common::checked_receipt(spawned.receipt_value().expect("a prepared receipt"));
    let attempt = control["attempt_id"].as_str().unwrap().to_owned();
    let digest = receipt["policy"]["digest"].as_str().unwrap().to_owned();
    let argv_digest = receipt["argv_digest"].as_str().unwrap().to_owned();
    let mismatch = ExpectedPlan::complete(&attempt, &digest, &argv_digest, widened);
    let refused = spawned
        .owner()
        .authorise(&control, Some(&receipt), &mismatch);
    assert!(
        refused.is_err(),
        "a requirements mismatch must not authorise"
    );
    spawned.owner().withhold();
    let run = spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(125));
    assert!(
        !marker.exists(),
        "the target ran despite the owner's mismatch"
    );
}

/// A release frame carrying an injected field beyond the four §8.2 names is
/// rejected, and a valid release leaves the applied policy exactly as the
/// operator's inputs resolved it: an untrusted request field cannot mutate
/// the owner's operator inputs (I03, last clause).
#[test]
fn i03_an_untrusted_release_field_cannot_change_the_resolved_policy() {
    if !common::live() {
        return;
    }
    // An injected key on an otherwise valid frame refuses, and no target runs.
    let (mut spawned, marker) = gated_case();
    let (attempt, digest) = prepared_binding(&mut spawned);
    let injected = format!(
        "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":{attempt:?},\
         \"policy_digest\":{digest:?},\"grants\":[{{\"path\":\"/etc\"}}]}}\n"
    );
    spawned
        .owner()
        .release(&Release::Raw(injected.into_bytes()), &attempt, &digest)
        .expect("the frame is written");
    let run = spawned.wait().expect("the jail finishes");
    assert_eq!(
        run.code(),
        Some(125),
        "an injected field must refuse: {}",
        run.stderr_text()
    );
    assert!(!marker.exists(), "the injected frame released the target");
    assert_eq!(error_code(&run).as_deref(), Some("gate_invalid"));

    // A valid release: the applied policy is the resolved one, unchanged by
    // anything the frame carried. The settled digest equals the prepared one.
    let (mut spawned, marker) = gated_case();
    let (attempt, digest) = prepared_binding(&mut spawned);
    spawned
        .owner()
        .release(&Release::Valid, &attempt, &digest)
        .expect("release");
    let run = spawned.wait().expect("the jail finishes");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(marker.is_file());
    let settled = settled(&run);
    assert_eq!(
        settled["policy"]["digest"].as_str(),
        Some(digest.as_str()),
        "the release changed the resolved policy digest"
    );
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

    if mode == "during" {
        let attempt = prepared["attempt_id"].as_str().unwrap();
        let digest = prepared["policy"]["digest"].as_str().unwrap();
        let frame = ouro_fixture::harness::gate::frame_body(attempt, digest) + "\n";
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

/// The child rewrites the project file (and a would-be profile file) in its
/// own workspace after release, and the run's authority does not move: the
/// settled digest equals the prepared one, and the run-time denial the
/// project file set still holds — the child cannot read the denied file even
/// after emptying the file that denied it. The existing P03 test edited
/// `ouro.toml` from the harness between prepared and release and compared
/// only the digest; here the child makes the edit and the denial is retested
/// live (gap analysis §1.2, P03).
#[test]
fn p03_a_child_edit_of_its_project_or_profile_file_does_not_widen_the_run() {
    if !common::live() {
        return;
    }
    let c = case("tool");
    std::fs::create_dir_all(c.workspace.join("secret")).unwrap();
    std::fs::write(c.workspace.join("secret/classified"), b"classified\n").unwrap();
    std::fs::write(
        c.workspace.join("ouro.toml"),
        "[jail.filesystem]\ndeny_read = [\"./secret\"]\n",
    )
    .unwrap();
    // A file shaped like an operator profile, planted in the workspace. It is
    // never loaded (profiles live in the operator config dir, I02), so the
    // child editing it changes nothing — the point of testing it.
    std::fs::write(
        c.workspace.join("profile.toml"),
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n",
    )
    .unwrap();
    let script = c.workspace.join("attack.json");
    write_script(
        &script,
        &serde_json::json!([
            // The denial is in force before the child touches anything.
            ["open", "secret/classified", "--expect", "ENOENT"],
            // The child empties both the project file and the profile look-alike.
            ["open", "ouro.toml", "--create", "--write", "--trunc"],
            ["open", "profile.toml", "--create", "--write", "--trunc"],
            // The denial still holds at run time.
            ["open", "secret/classified", "--expect", "ENOENT"],
        ]),
    );
    let mut spawned = c
        .jail
        .gate()
        .receipt()
        .target([
            c.fixture.as_os_str(),
            OsStr::new("script"),
            script.as_os_str(),
        ])
        .spawn()
        .expect("the jail starts");
    let (attempt, prepared_digest) = prepared_binding(&mut spawned);
    let prepared = spawned.receipt_value().expect("a prepared receipt");
    let prepared_mounts = prepared["applied"]["filesystem"]["mounts"].clone();
    spawned
        .owner()
        .release(&Release::Valid, &attempt, &prepared_digest)
        .expect("release");
    let run = spawned.wait().expect("the jail finishes");
    // Every fixture expectation was met, including the two ENOENT reads.
    assert_eq!(
        run.code(),
        Some(0),
        "the run-time denial did not hold: {}",
        run.stderr_text()
    );
    let settled = settled(&run);
    assert_eq!(
        settled["policy"]["digest"].as_str(),
        Some(prepared_digest.as_str()),
        "the child's edit changed the active digest"
    );
    assert_eq!(
        settled["applied"]["filesystem"]["mounts"], prepared_mounts,
        "the child's edit changed the applied mounts"
    );
    // The workspace file really was emptied, so the denial held despite it.
    assert_eq!(
        std::fs::read_to_string(c.workspace.join("ouro.toml")).unwrap(),
        "",
        "the child never actually truncated the project file"
    );
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
