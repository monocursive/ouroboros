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
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_fixture::harness::gate::{ExpectedPlan, Release};
use ouro_fixture::harness::{self, Jail, Run, Spawned};
use ouro_jail::platform::linux::{identity, watch};
use serde_json::Value;

mod common;

const PYTHON: &str = "/usr/bin/python3";

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

fn wait_for(what: &str, within: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
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
    // The three exec failures are proved exec errors, refused with 125.
    for failure in [missing, interpreter, permission] {
        assert_eq!(failure.phase, "refused", "{profile} {}", failure.label);
        assert_eq!(
            failure.outcome["kind"], "exec_error",
            "{profile} {}",
            failure.label
        );
        assert_eq!(
            failure.outcome["error"]["code"], "exec_failed",
            "{}",
            failure.label
        );
        assert_eq!(failure.code, Some(125), "{profile} {}", failure.label);
        assert_eq!(failure.terminal_control, ["refused"], "{}", failure.label);
    }
    // §13.2: the errno name in its own field. The kernel answers ENOENT for a
    // missing program and for a missing interpreter alike; EACCES for the
    // permission error.
    assert_eq!(missing.outcome["cause"], "ENOENT");
    assert_eq!(interpreter.outcome["cause"], "ENOENT");
    assert_eq!(permission.outcome["cause"], "EACCES");
    // A child that exits 125 exited: it is settled, never a refusal.
    assert_eq!(exit125.phase, "settled", "{profile}");
    assert_eq!(exit125.outcome["kind"], "exited");
    assert_eq!(exit125.outcome["code"], 125);
    assert_eq!(exit125.code, Some(125));
    assert_eq!(exit125.terminal_control, ["settled"]);
    // X04 itself: four distinct outcomes, compared as whole objects.
    for (i, a) in cases.iter().enumerate() {
        for b in &cases[i + 1..] {
            assert_ne!(
                a.outcome, b.outcome,
                "{profile}: `{}` and `{}` have the same outcome",
                a.label, b.label
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
// X06: no capability set and no tracing reach of the supervisor or observer
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

/// From inside a contained profile the supervisor and observer (the
/// `ouro-jail` process on the host, which is both) are in another pid
/// namespace, so the target cannot address them: their host pid is absent
/// from the target's `/proc`, and `pidfd_open` and `ptrace` against it fail.
/// The pid is delivered while the target is still gate-blocked, so the target
/// attacks the real supervisor pid rather than a guess (gap analysis §1.2).
#[test]
fn x06_the_target_cannot_pidfd_or_ptrace_the_supervisor() {
    if !common::live() {
        return;
    }
    if !Path::new(PYTHON).is_file() {
        harness::skip_or_fail("this X06 case is a python3 script");
        return;
    }
    for profile in ["tool", "agent"] {
        let jail = Jail::new().expect("a private jail harness");
        let (workspace, _) = workspace_with_fixture(jail.root());
        let pidfile = workspace.join("supervisor.pid");
        let report = workspace.join("reach.json");
        let code = format!(
            "import os, ctypes, json\n\
             libc = ctypes.CDLL(None, use_errno=True)\n\
             pid = int(open({pidfile:?}).read())\n\
             def call(nr, *args):\n\
             \x20   ctypes.set_errno(0)\n\
             \x20   rc = libc.syscall(nr, *[ctypes.c_long(a) for a in args])\n\
             \x20   return rc, ctypes.get_errno()\n\
             visible = os.path.isdir('/proc/%d' % pid)\n\
             pidfd = call(434, pid, 0)\n\
             pt = call(101, 0x4206, pid, 0, 0)\n\
             open({report:?}, 'w').write(json.dumps({{\n\
             \x20   'target': pid, 'visible': visible,\n\
             \x20   'pidfd_ret': pidfd[0], 'pidfd_errno': pidfd[1],\n\
             \x20   'ptrace_ret': pt[0], 'ptrace_errno': pt[1]}}))\n",
            pidfile = pidfile.to_str().unwrap(),
            report = report.to_str().unwrap(),
        );
        let mut spawned = jail
            .arg("run")
            .args(["--profile", profile, "--workspace"])
            .arg(&workspace)
            .gate()
            .receipt()
            .control()
            .target([PYTHON, "-c", &code])
            .spawn()
            .expect("the jail starts");
        let control = spawned.owner().await_prepared().expect("prepared");
        // The target is blocked at the gate; deliver the real supervisor pid.
        std::fs::write(&pidfile, spawned.pid().to_string()).expect("the pid file");
        let attempt = control["attempt_id"].as_str().unwrap().to_owned();
        // The supervisor's own digest, from its prepared receipt.
        let digest = spawned.receipt_value().map_or_else(
            || panic!("no prepared receipt"),
            |receipt| receipt["policy"]["digest"].as_str().unwrap().to_owned(),
        );
        spawned
            .owner()
            .release(&Release::Valid, &attempt, &digest)
            .expect("release");
        let run = spawned.wait().expect("the jail finishes");
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let report: Value =
            serde_json::from_str(&std::fs::read_to_string(&report).expect("the reach report"))
                .expect("JSON");
        assert_eq!(
            report["visible"], false,
            "{profile}: the supervisor pid is in the child's /proc"
        );
        assert!(
            report["pidfd_ret"].as_i64().unwrap() < 0,
            "{profile}: pidfd_open reached the supervisor: {report}"
        );
        assert!(
            report["ptrace_ret"].as_i64().unwrap() < 0,
            "{profile}: ptrace reached the supervisor: {report}"
        );
    }
}

// ===========================================================================
// L01: operator signals and a fork storm end at verified tree death
// ===========================================================================

/// A pidfd for the launcher a receipt names, so a test can watch the tree
/// die. The launcher pid is in the native details from the prepared receipt
/// on, before the gate is released.
fn launcher_pidfd(receipt: &Value) -> std::os::fd::OwnedFd {
    let launcher = receipt["lifetime"]["native"]["details"]["launcher_pid"]
        .as_i64()
        .expect("a launcher pid") as i32;
    identity::pidfd_open(launcher).expect("the live launcher")
}

/// Each of the operator's termination signals — INT, TERM and HUP — delivered
/// to the supervisor of a running contained attempt ends the tree at verified
/// death. J1/J2 sent TERM and wall expiry only; INT and HUP were never sent
/// to a contained supervisor (gap analysis §1.2, L01).
#[test]
fn l01_operator_int_term_and_hup_each_end_the_contained_tree() {
    if !common::live() {
        return;
    }
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let c = case("tool");
        let running = c.workspace.join("running");
        let script = c.workspace.join("wait.json");
        write_script(
            &script,
            &serde_json::json!([
                ["open", running.to_str().unwrap(), "--create", "--write"],
                ["sleep", "30000"],
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
        let (attempt, digest) = prepared_binding(&mut spawned);
        let launcher = launcher_pidfd(&spawned.receipt_value().expect("a prepared receipt"));
        spawned
            .owner()
            .release(&Release::Valid, &attempt, &digest)
            .expect("release");
        wait_for("the target to run", Duration::from_secs(20), || {
            running.exists()
        });
        // SAFETY: the supervisor is this test's own unreaped child.
        assert_eq!(unsafe { libc::kill(spawned.pid() as i32, signal) }, 0);
        let run = spawned.wait().expect("the jail finishes");
        let settled = settled(&run);
        assert_eq!(
            settled["lifetime"]["tree_empty"], true,
            "signal {signal}: the tree was not verified empty"
        );
        assert_eq!(
            settled["outcome"]["cause"], "operator_signal",
            "signal {signal}"
        );
        // The whole tree, launcher included, is dead.
        wait_for("the launcher to die", Duration::from_secs(10), || {
            watch::readable(launcher.as_raw_fd())
        });
    }
}

/// A contained descendant that ignores SIGTERM is still ended at settlement,
/// and a fork storm launched inside the sandbox is stopped and fully reaped
/// (L01's "SIGTERM-ignoring descendant and fork storm"). Unlike J2's
/// `r4_a_fork_burst_is_fully_reaped`, which lets the burst reap itself, this
/// storm keeps forking until the jail stops it.
#[test]
fn l01_a_sigterm_ignoring_descendant_and_a_live_fork_storm_are_ended() {
    if !common::live() {
        return;
    }
    if !Path::new(PYTHON).is_file() {
        harness::skip_or_fail("this L01 case is a python3 script");
        return;
    }
    let c = case("tool");
    let running = c.workspace.join("running");
    // A descendant that ignores SIGTERM and never exits, plus a child that
    // forks without end. The wall stop must reach all of them.
    let code = format!(
        "import os, signal, time\n\
         if os.fork() == 0:\n\
         \x20   signal.signal(signal.SIGTERM, signal.SIG_IGN)\n\
         \x20   open({running:?}, 'w').close()\n\
         \x20   time.sleep(300)\n\
         \x20   os._exit(0)\n\
         while True:\n\
         \x20   try:\n\
         \x20       pid = os.fork()\n\
         \x20   except OSError:\n\
         \x20       time.sleep(0.02)\n\
         \x20       continue\n\
         \x20   if pid == 0:\n\
         \x20       time.sleep(300)\n\
         \x20       os._exit(0)\n\
         \x20   time.sleep(0.02)\n",
        running = running.to_str().unwrap(),
    );
    let run = c
        .jail
        .args(["--limit", "wall=1500ms", "--limit", "pids=64"])
        .target([PYTHON, "-c", &code])
        .run()
        .expect("the jail runs");
    let settled = settled(&run);
    assert_eq!(settled["outcome"]["cause"], "wall_expiry");
    assert_eq!(settled["lifetime"]["tree_empty"], true, "{settled:#}");
    assert_eq!(settled["lifetime"]["integrity"], "verified");
    // The namespace init is gone, so no forked child of the storm survived.
    let init = settled["lifetime"]["native"]["details"]["namespace_init_pid"]
        .as_i64()
        .expect("the namespace init pid");
    assert!(
        !Path::new(&format!("/proc/{init}")).exists(),
        "the namespace init survived the stop"
    );
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

// ===========================================================================
// R05: forging the receipt, trace or state is outside local evidence assurance
// ===========================================================================

/// A clean `none` run settles unprotected, and afterwards a same-UID party
/// (this test) forges its receipt, its trace and its jail state at will. The
/// run ended exactly as it would have; the forgery is undetectable because a
/// `none` receipt never claims protection over these files (§13.2, R05). The
/// existing R05 forges only `policy.json`, and only from inside the child;
/// this extends it to the evidence artifacts (gap analysis §1.2, R05).
#[test]
fn r05_forging_the_receipt_trace_or_state_is_outside_local_evidence_assurance() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().expect("a private jail harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let written = workspace.join("written.txt");
    // No `--trace-fd`: the bounded local `trace.ndjson` is written to the
    // attempt directory, which is one of the artifacts R05 forges.
    let run = jail
        .arg("run")
        .args(["--profile", "none", "--observe", "on", "--workspace"])
        .arg(&workspace)
        .target([
            fixture.as_os_str(),
            OsStr::new("open"),
            written.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .run()
        .expect("the jail runs");
    // The run ends as it would: settled, unprotected, verified boundary.
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let settled = settled(&run);
    assert_eq!(settled["containment"], "none");
    assert_eq!(settled["child_protection"], "unprotected");
    assert_eq!(settled["lifetime"]["integrity"], "verified");

    // The attempt's own evidence files, all owned by this uid.
    let attempt_dir = std::fs::read_dir(run.data_dir.join("attempts"))
        .expect("the attempts directory")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("one attempt");
    for (name, forged) in [
        ("jail.json", "{\"forged\":\"receipt\"}"),
        ("trace.ndjson", "{\"forged\":\"trace\"}\n"),
        ("jail-state.json", "{\"forged\":\"state\"}"),
    ] {
        let path = attempt_dir.join(name);
        assert!(path.exists(), "the run left no {name} to forge");
        std::fs::write(&path, forged).unwrap_or_else(|e| panic!("{name} is not writable: {e}"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            forged,
            "{name} did not accept the forgery"
        );
    }
    // Nothing in the product prevents or detects this: the same uid owns the
    // files, and `none` upgrades no protection over them (§9.3). The receipt
    // the run produced already said so.
    assert_eq!(
        settled["observer"]["attached"], true,
        "the run itself was observed"
    );
}

// ===========================================================================
// L02: killing an actual helper of `agent` or `build` ends the tree
// ===========================================================================

/// Start a gated run of `profile` whose target writes `running` then sleeps,
/// release it, and hand back the spawned jail and its prepared receipt (which
/// already names every helper, §8.1 step 5). `extra` carries any profile
/// requirement (a build memory ceiling).
fn l02_started(profile: &str, extra: &[&str]) -> (Spawned, Value) {
    let c = case(profile);
    // `/bin/sleep` lives in the read-only runtime roots every contained
    // profile mounts, so the target needs no writable workspace (which
    // `build` does not grant) and no marker file (which `build` could not
    // write): exec confirmation on the control channel is the synchronisation.
    let mut spawned = c
        .jail
        .args(extra.iter().copied())
        .gate()
        .receipt()
        .target(["/bin/sleep", "30"])
        .spawn()
        .expect("the jail starts");
    let (attempt, digest) = prepared_binding(&mut spawned);
    let prepared = spawned.receipt_value().expect("a prepared receipt");
    spawned
        .owner()
        .release(&Release::Valid, &attempt, &digest)
        .expect("release");
    spawned
        .owner()
        .await_kind("exec_confirmed")
        .expect("control readable")
        .expect("the target execs");
    (spawned, prepared)
}

/// Under `agent`, killing the loopback bridge — a helper `agent` has and
/// `tool` does not — ends the whole tree, and so does killing the backend.
/// J3/J2 enumerated helper kills for `tool`; `agent`'s own helper had no
/// live L02 (gap analysis §1.2, L02).
#[test]
fn l02_agent_bridge_and_backend_kills_end_the_tree() {
    if !common::live() {
        return;
    }
    for helper in ["bridge", "bwrap_pid"] {
        let (spawned, prepared) = l02_started("agent", &[]);
        let details = &prepared["lifetime"]["native"]["details"];
        let helper_pid = if helper == "bridge" {
            details["helpers"]
                .as_array()
                .and_then(|helpers| helpers.iter().find(|h| h["kind"] == "bridge"))
                .and_then(|h| h["pid"].as_i64())
                .expect("the agent run has a bridge helper") as i32
        } else {
            details[helper].as_i64().expect("the backend pid") as i32
        };
        let launcher =
            identity::pidfd_open(details["launcher_pid"].as_i64().expect("a launcher pid") as i32)
                .expect("the live launcher");
        let killed = identity::pidfd_open(helper_pid).expect("the live helper");
        identity::pidfd_send_signal(killed.as_raw_fd(), libc::SIGKILL)
            .expect("the helper is killed");
        let run = spawned.wait().expect("the jail finishes");
        wait_for(
            &format!("the target to die after the {helper} loss"),
            Duration::from_secs(10),
            || watch::readable(launcher.as_raw_fd()),
        );
        assert_eq!(
            settled(&run)["lifetime"]["tree_empty"],
            true,
            "{helper}: the tree was not verified empty: {}",
            run.stderr_text()
        );
    }
}

/// Under `build`, killing the backend or the supervisor ends the tree, the
/// same death chain `tool` proves but exercised on `build`'s own run
/// (gap analysis §1.2, L02).
#[test]
fn l02_build_backend_and_supervisor_kills_end_the_tree() {
    if !common::live() {
        return;
    }
    for helper in ["bwrap_pid", "supervisor"] {
        let (spawned, prepared) = l02_started("build", &["--limit", "mem=64MiB"]);
        let details = &prepared["lifetime"]["native"]["details"];
        let launcher =
            identity::pidfd_open(details["launcher_pid"].as_i64().expect("a launcher pid") as i32)
                .expect("the live launcher");
        let target_pid = if helper == "supervisor" {
            spawned.pid() as i32
        } else {
            details[helper].as_i64().expect("the backend pid") as i32
        };
        let killed = identity::pidfd_open(target_pid).expect("the live helper");
        identity::pidfd_send_signal(killed.as_raw_fd(), libc::SIGKILL).expect("the kill");
        let run = spawned.wait().expect("the jail finishes");
        wait_for(
            &format!("the target to die after the {helper} loss"),
            Duration::from_secs(10),
            || watch::readable(launcher.as_raw_fd()),
        );
        // The supervisor-death case cannot itself write a settled receipt;
        // the tree still dies, which is what L02 asserts.
        if helper != "supervisor" {
            assert_eq!(
                settled(&run)["lifetime"]["tree_empty"],
                true,
                "{helper}: {}",
                run.stderr_text()
            );
        }
    }
}

// ===========================================================================
// R06: an unobserved migrated descendant is not certified dead
// ===========================================================================

/// A sibling cgroup under the delegated root — a migration destination an
/// uncontained child can create and move itself into. Removed on drop, after
/// emptying it.
struct Destination {
    path: PathBuf,
}

impl Destination {
    fn new(tag: &str) -> Destination {
        // SAFETY: getuid takes no arguments and cannot fail.
        let root = ouro_jail::platform::linux::cgroup::delegated_root(unsafe { libc::getuid() })
            .expect("a delegated subtree");
        let path = root.join(format!("ouro-j5b1-{tag}-{}", std::process::id()));
        std::fs::create_dir(&path).expect("the destination cgroup");
        Destination { path }
    }

    fn populated(&self) -> bool {
        std::fs::read_to_string(self.path.join("cgroup.events"))
            .unwrap_or_default()
            .lines()
            .any(|line| line == "populated 1")
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        if self.path.exists() {
            if self.populated() {
                let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
                let deadline = Instant::now() + Duration::from_secs(5);
                while self.populated() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

/// With observation off, a descendant that migrates out of the registered
/// boundary and stays alive after the target exits is not certified dead by
/// the empty-leaf check: the receipt never says `tree_empty = true`, its
/// integrity is `lost`, and the migrated descendant is demonstrably still
/// running. The existing R06 tests assert the scope label; this asserts the
/// "not certified dead" itself, with the descendant unobserved
/// (gap analysis §1.2, R06).
#[test]
fn r06_an_unobserved_migrated_descendant_is_not_certified_dead() {
    if !common::live() {
        return;
    }
    if !Path::new(PYTHON).is_file() {
        harness::skip_or_fail("this R06 case is a python3 script");
        return;
    }
    let destination = Destination::new("r06");
    let jail = Jail::new().expect("a private jail harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let moved = workspace.join("descendant.pid");
    // `none` has the host filesystem view, so the child writes its pid to the
    // destination's `cgroup.procs` directly, then reports and sleeps. The
    // target waits until the descendant has migrated, then exits.
    let code = format!(
        "import os, time\n\
         dest = {dest:?}\n\
         pid = os.fork()\n\
         if pid == 0:\n\
         \x20   open(os.path.join(dest, 'cgroup.procs'), 'w').write(str(os.getpid()))\n\
         \x20   open({moved:?}, 'w').write(str(os.getpid()))\n\
         \x20   time.sleep(120)\n\
         \x20   os._exit(0)\n\
         while not os.path.exists({moved:?}):\n\
         \x20   time.sleep(0.01)\n\
         os._exit(0)\n",
        dest = destination.path.to_str().unwrap(),
        moved = moved.to_str().unwrap(),
    );
    let mut spawned = jail
        .arg("run")
        .args(["--profile", "none", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .gate()
        .receipt()
        .control()
        .target([PYTHON, "-c", &code])
        .spawn()
        .expect("the jail starts");
    let (attempt, digest) = prepared_binding(&mut spawned);
    spawned
        .owner()
        .release(&Release::Valid, &attempt, &digest)
        .expect("release");
    // The descendant migrates out of the registered boundary and reports.
    wait_for("the descendant to migrate", Duration::from_secs(20), || {
        moved.exists()
    });
    let descendant: i32 = std::fs::read_to_string(&moved)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let descendant_fd = identity::pidfd_open(descendant).expect("the live descendant");
    // At this point the leaf holds neither the target nor the descendant, so
    // the empty-leaf reading alone would say the tree is dead. It is not.
    let run = spawned.wait().expect("the jail finishes");
    let receipt = last(&run);
    // The registered-boundary verification does not certify the tree dead: the
    // receipt never settles, the integrity is lost, there is no tree result,
    // and the scope stays the registered boundary. The descendant was
    // unobserved (observe off), so only the boundary check and the subreaper,
    // never the observer, had anything to say about it.
    assert_ne!(
        receipt["phase"], "settled",
        "an escaped descendant settled the attempt: {receipt:#}"
    );
    assert_eq!(receipt["lifetime"]["integrity"], "lost", "{receipt:#}");
    assert_ne!(
        receipt["lifetime"]["tree_empty"], true,
        "the empty leaf falsely certified death"
    );
    assert_eq!(
        receipt["lifetime"]["verification_scope"],
        "registered_boundary"
    );
    assert_eq!(
        receipt["observer"]["attached"], false,
        "the descendant must be unobserved"
    );
    let has_tree_unknown = receipt["errors"]
        .as_array()
        .is_some_and(|errors| errors.iter().any(|e| e["code"] == "tree_unknown"));
    assert!(has_tree_unknown, "no tree_unknown error: {receipt:#}");
    // The escaped descendant, reparented to the subreaper supervisor, is ended
    // by it rather than left running — detection, then reach where it exists.
    wait_for(
        "the reparented descendant to be ended",
        Duration::from_secs(10),
        || watch::readable(descendant_fd.as_raw_fd()),
    );
    // Cleanup: ensure nothing of the test's fixture lingers in the destination.
    let _ = identity::pidfd_send_signal(descendant_fd.as_raw_fd(), libc::SIGKILL);
}
