//! J4 autoscope (jail-v1 §9.3): a supervisor started outside the delegated
//! cgroup subtree enters a transient user scope of its own, without being
//! re-executed, so its attempt gets an execution leaf.
//!
//! Measured on the reference host before the change (2026-09-24, a plain SSH
//! session, no `systemd-run` wrapper): a `run --profile tool` recorded its
//! execution cgroup `unavailable` ("supervisor is outside the delegated
//! subtree") and left the `pids` ceiling unapplied; killing `run --profile
//! agent` the moment bubblewrap's namespace init existed left the init and
//! its bridge alive on pid 1 in 20 of 20 runs; `r7` failed 2 of 25.
//!
//! These tests run inside the conformance scope, where the product sees
//! itself delegated already. The `OURO_JAIL_TEST_SUPERVISOR_SCOPE` seam makes
//! it take the branch it takes outside a scope, so the move itself is proved
//! here; the proof from a plain login session is the kill sweep in the
//! report, which no test driver can run from inside a scope.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::{cgroup, probe};
use serde_json::Value;

mod common;

/// The seam, spelled as the specification names it (the product's constant
/// is `platform::linux::scope::SEAM`; these tests pin the name and build
/// against a product that does not have it).
const SEAM: &str = "OURO_JAIL_TEST_SUPERVISOR_SCOPE";
/// The first component of every unit the step asks for.
const UNIT_PREFIX: &str = "ouro-jail-";

fn live() -> bool {
    if !common::live() {
        return false;
    }
    let leaf = probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "the scope tests run inside a delegated user scope with a usable leaf: {}",
            leaf.evidence
        ));
        return false;
    }
    true
}

fn uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// The delegated subtree, relative to the v2 root.
fn delegated() -> String {
    let root = cgroup::delegated_root(uid()).expect("a delegated subtree");
    format!(
        "/{}",
        root.strip_prefix(cgroup::CGROUP_ROOT).unwrap().display()
    )
}

fn cgroup_of(pid: u32) -> Option<String> {
    cgroup::process_cgroup(i32::try_from(pid).ok()?).ok()
}

/// Field 22 of `/proc/<pid>/stat`, the start time in clock ticks.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 2..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Field 4 of `/proc/<pid>/stat`, the parent pid.
fn parent_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 2..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// A `run` under `profile` with the seam set to `seam` (or removed), a
/// receipt, and `target`.
fn jail(profile: &str, seam: Option<&str>, target: &[&str]) -> Jail {
    let jail = Jail::new().expect("a private jail harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let jail = jail
        .arg("run")
        .args(["--profile", profile, "--workspace"])
        .arg(&workspace);
    let jail = match seam {
        Some(value) => jail.env(SEAM, value),
        None => jail.env_remove(SEAM),
    };
    jail.receipt().target(target)
}

/// Every receipt the run left, each checked against the schema and the
/// semantic rules, and the settled one.
fn settled(run: &Run) -> Value {
    for receipt in run.receipts() {
        let _ = common::checked_receipt(receipt);
    }
    assert!(
        run.receipt_errors().is_empty(),
        "{:?}",
        run.receipt_errors()
    );
    run.receipt_phase("settled").unwrap_or_else(|| {
        panic!(
            "a settled receipt (exit {:?}): {}",
            run.code(),
            run.stderr_text()
        )
    })
}

fn details(receipt: &Value) -> &Value {
    &receipt["lifetime"]["native"]["details"]
}

/// The supervisor scope record of every receipt that has native details:
/// one and the same in each.
fn scope_record(run: &Run) -> Value {
    let records: Vec<Value> = run
        .receipts()
        .iter()
        .filter(|receipt| !receipt["lifetime"]["native"].is_null())
        .map(|receipt| details(receipt)["supervisor_scope"].clone())
        .collect();
    assert!(!records.is_empty(), "no receipt has native details");
    for record in &records {
        assert_eq!(
            record, &records[0],
            "every receipt records the same step: {records:#?}"
        );
    }
    records[0].clone()
}

/// The leaf a receipt names, asserting that there is one, that it lies
/// directly under the delegated root (never inside the supervisor's scope),
/// and that the `pids` ceiling was applied in it.
fn assert_leaf(receipt: &Value) {
    let path = details(receipt)["execution_cgroup"]["path"]
        .as_str()
        .unwrap_or_else(|| panic!("the attempt has an execution leaf: {receipt:#}"));
    assert_eq!(
        Path::new(path).parent(),
        Some(Path::new(&format!(
            "{}{}",
            cgroup::CGROUP_ROOT,
            delegated()
        ))),
        "the leaf is made under the delegated root: {path}"
    );
    let pids = receipt["applied"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|limit| limit["key"] == "pids")
        .expect("the tool profile's pids ceiling");
    assert_eq!(pids["applied"], true, "{pids}");
    assert_eq!(pids["mechanism"], "pids.max", "{pids}");
}

/// Watch `pid`'s cgroup until it is `<delegated>/app.slice/<unit>` for a unit
/// this step names for that pid, or `within` passes.
fn wait_for_scope(pid: u32, within: Duration) -> Option<String> {
    let prefix = format!("{}/app.slice/{}{pid}-", delegated(), UNIT_PREFIX);
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(now) = cgroup_of(pid)
            && now.starts_with(&prefix)
            && now.ends_with(".scope")
        {
            return Some(now);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    None
}

fn last_component(cgroup: &str) -> &str {
    cgroup.rsplit('/').next().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The move
// ---------------------------------------------------------------------------

/// Outside a scope (the seam), the supervisor moves into a transient scope
/// of its own with the same pid, start time, parent and stdio; the attempt
/// gets its execution leaf under the delegated root; every receipt says
/// `entered` with the unit; and the scope is gone once the supervisor is.
#[test]
fn j4_scope_the_supervisor_enters_its_own_scope_and_its_attempt_gets_a_leaf() {
    if !live() {
        return;
    }
    let ours = cgroup_of(std::process::id()).expect("the test's own cgroup");
    let spawned = jail(
        "tool",
        Some("assume-outside"),
        &["/bin/sh", "-c", "sleep 1; echo scoped"],
    )
    .spawn()
    .expect("the jail starts");
    let pid = spawned.pid();
    let born = start_time(pid).expect("the supervisor's start time");
    let moved = wait_for_scope(pid, Duration::from_secs(3));
    // Read while the supervisor still runs its target.
    let after = (start_time(pid), parent_of(pid));
    let members = moved.as_ref().map(|cgroup| {
        std::fs::read_to_string(format!("{}{cgroup}/cgroup.procs", cgroup::CGROUP_ROOT))
            .unwrap_or_default()
    });
    let run = spawned.wait().expect("the jail finishes");
    let moved = moved.unwrap_or_else(|| {
        panic!(
            "the supervisor (pid {pid}) was never seen in a scope of its own; it started in \
             {ours}: {}",
            run.stderr_text()
        )
    });
    assert_eq!(
        after,
        (Some(born), Some(std::process::id())),
        "the same process, with the same parent, after the move: never re-executed or \
         re-parented"
    );
    assert!(
        members
            .unwrap_or_default()
            .lines()
            .any(|line| line == pid.to_string()),
        "the scope's cgroup.procs holds the supervisor itself"
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert_eq!(
        run.stdout_text(),
        "scoped\n",
        "the target's stdout still reaches the supervisor's own stdout"
    );
    let receipt = settled(&run);
    assert_leaf(&receipt);
    let record = scope_record(&run);
    assert_eq!(record["state"], "entered", "{record:#}");
    assert_eq!(record["unit"], last_component(&moved), "{record:#}");
    assert_eq!(record["cgroup"], moved.as_str(), "{record:#}");
    assert_eq!(record["reason_code"], Value::Null, "{record:#}");
    assert_eq!(record["test_seam"], "assume-outside", "{record:#}");
    assert_eq!(
        details(&receipt)["test_seams"][SEAM],
        "assume-outside",
        "the seam is recorded like every OURO_JAIL_TEST_* variable"
    );
    // The transient scope ends with its last process.
    let gone = Instant::now() + Duration::from_secs(3);
    let directory = PathBuf::from(format!("{}{moved}", cgroup::CGROUP_ROOT));
    while directory.exists() && Instant::now() < gone {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !directory.exists(),
        "the scope {moved} outlived its supervisor"
    );
}

/// `none`'s boundary records the step as well (the uncontained receipt).
#[test]
fn j4_scope_the_uncontained_boundary_records_the_step() {
    if !live() {
        return;
    }
    let run = jail("none", Some("assume-outside"), &["/usr/bin/true"])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let receipt = settled(&run);
    assert!(
        details(&receipt)["execution_cgroup"]["path"].is_string(),
        "{receipt:#}"
    );
    let record = scope_record(&run);
    assert_eq!(record["state"], "entered", "{record:#}");
    let unit = record["unit"].as_str().expect("a unit");
    assert_eq!(
        record["cgroup"],
        format!("{}/app.slice/{unit}", delegated()),
        "{record:#}"
    );
}

// ---------------------------------------------------------------------------
// No action, and failures that change nothing
// ---------------------------------------------------------------------------

/// Inside the delegated subtree already, nothing is asked for and the
/// supervisor stays where it was started.
#[test]
fn j4_scope_already_delegated_takes_no_action() {
    if !live() {
        return;
    }
    let ours = cgroup_of(std::process::id()).expect("the test's own cgroup");
    let spawned = jail("tool", None, &["/bin/sh", "-c", "sleep 1"])
        .spawn()
        .expect("the jail starts");
    let pid = spawned.pid();
    std::thread::sleep(Duration::from_millis(500));
    let during = cgroup_of(pid);
    let run = spawned.wait().expect("the jail finishes");
    assert_eq!(
        during.as_deref(),
        Some(ours.as_str()),
        "the supervisor moved"
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert_leaf(&settled(&run));
    let record = scope_record(&run);
    assert_eq!(
        record,
        serde_json::json!({
            "state": "already_delegated",
            "unit": null,
            "reason_code": null,
            "reason": null,
            "cgroup": ours,
        }),
        "no seam key when the seam is not set"
    );
}

/// A failure is recorded with its reason and changes nothing else: the
/// supervisor stays where it was and the attempt runs as without the step.
fn assert_unchanged(seam: &str, reason_code: &str, requested: bool) -> Value {
    let ours = cgroup_of(std::process::id()).expect("the test's own cgroup");
    let spawned = jail("tool", Some(seam), &["/bin/sh", "-c", "sleep 1; echo same"])
        .spawn()
        .expect("the jail starts");
    let pid = spawned.pid();
    std::thread::sleep(Duration::from_millis(500));
    let during = cgroup_of(pid);
    let run = spawned.wait().expect("the jail finishes");
    assert_eq!(
        during.as_deref(),
        Some(ours.as_str()),
        "the supervisor moved"
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert_eq!(run.stdout_text(), "same\n");
    let receipt = settled(&run);
    // Inside the conformance scope the leaf is still there: the step's
    // failure did not change what the attempt got.
    assert_leaf(&receipt);
    let record = scope_record(&run);
    assert_eq!(record["state"], "unavailable", "{record:#}");
    assert_eq!(record["reason_code"], reason_code, "{record:#}");
    assert!(
        record["reason"]
            .as_str()
            .is_some_and(|text| !text.is_empty()),
        "{record:#}"
    );
    assert_eq!(record["cgroup"], ours.as_str(), "{record:#}");
    assert_eq!(record["test_seam"], seam, "{record:#}");
    let unit = record["unit"].as_str();
    assert_eq!(unit.is_some(), requested, "{record:#}");
    if let Some(unit) = unit {
        assert!(
            unit.starts_with(&format!("{}{pid}-", UNIT_PREFIX)),
            "{record:#}"
        );
    }
    record
}

/// No user bus: the call fails, the reason names `busctl`'s own message.
#[test]
fn j4_scope_an_unreachable_bus_leaves_the_attempt_unchanged() {
    if !live() {
        return;
    }
    let record = assert_unchanged("assume-outside-no-bus", "scope_call_failed", true);
    let reason = record["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("/usr/bin/busctl exited with exit status: 1")
            || reason.starts_with("/bin/busctl exited with exit status: 1"),
        "{reason}"
    );
}

/// No `busctl`: nothing is run and the attempt is the same.
#[test]
fn j4_scope_a_missing_busctl_leaves_the_attempt_unchanged() {
    if !live() {
        return;
    }
    assert_unchanged("assume-outside-no-busctl", "busctl_missing", false);
}

/// Lingering off: the user manager would stop at the last logout and take a
/// moved supervisor with it, so no scope is requested and the attempt is the
/// same (the reference host lingers, so the seam stands in for a host that
/// does not).
#[test]
fn j4_scope_without_lingering_the_supervisor_stays_put() {
    if !live() {
        return;
    }
    let record = assert_unchanged("assume-outside-no-linger", "no_linger", false);
    let reason = record["reason"].as_str().unwrap();
    assert!(reason.contains("enable-linger"), "{reason}");
}

/// A seam value the product does not know is ignored and says so.
#[test]
fn j4_scope_an_unknown_seam_value_is_ignored_and_recorded() {
    if !live() {
        return;
    }
    let run = jail("tool", Some("outside"), &["/usr/bin/true"])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let receipt = settled(&run);
    let record = scope_record(&run);
    assert_eq!(record["state"], "already_delegated", "{record:#}");
    assert!(
        record.get("test_seam").is_some_and(Value::is_null),
        "{record:#}"
    );
    assert_eq!(details(&receipt)["test_seams"][SEAM], "outside");
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

fn doctor(seam: Option<&str>) -> (Value, Option<i32>) {
    let jail = Jail::new().expect("a private jail harness");
    let mut command = std::process::Command::new(harness::jail_path());
    command
        .args(["doctor", "--json"])
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .stdin(std::process::Stdio::null());
    match seam {
        Some(value) => command.env(SEAM, value),
        None => command.env_remove(SEAM),
    };
    let output = command.output().expect("doctor runs");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "doctor --json prints one document ({error}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (report, output.status.code())
}

fn row<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("no {name} row: {report:#}"))
}

/// `doctor` runs the same step first and reports it twice: the
/// `supervisor_scope` row and the full record.
#[test]
fn j4_scope_doctor_reports_the_step() {
    if !live() {
        return;
    }
    let (inside, inside_code) = doctor(None);
    let scope_row = row(&inside, "supervisor_scope");
    assert_eq!(scope_row["status"], "available", "{scope_row:#}");
    assert_eq!(scope_row["reason_code"], "already_delegated");
    assert_eq!(inside["supervisor_scope"]["state"], "already_delegated");

    let (entered, entered_code) = doctor(Some("assume-outside"));
    let scope_row = row(&entered, "supervisor_scope");
    assert_eq!(scope_row["status"], "available", "{scope_row:#}");
    assert_eq!(scope_row["reason_code"], "entered");
    let record = &entered["supervisor_scope"];
    assert_eq!(record["state"], "entered", "{record:#}");
    let unit = record["unit"].as_str().expect("a unit");
    assert!(
        scope_row["evidence_ref"]
            .as_str()
            .is_some_and(|evidence| evidence.contains(unit)),
        "{scope_row:#}"
    );
    assert_eq!(
        row(&entered, "cgroup_delegated_leaf")["status"],
        "available",
        "the leaf probe runs from the scope doctor entered"
    );

    let (failed, failed_code) = doctor(Some("assume-outside-no-bus"));
    let scope_row = row(&failed, "supervisor_scope");
    assert_eq!(scope_row["status"], "unavailable", "{scope_row:#}");
    assert_eq!(scope_row["reason_code"], "scope_call_failed");
    assert_eq!(failed["supervisor_scope"]["state"], "unavailable");
    // The row is not a requirement: readiness is what it was.
    assert_eq!(failed["ready"], inside["ready"]);
    assert_eq!(entered["ready"], inside["ready"]);
    assert_eq!(failed_code, inside_code);
    assert_eq!(entered_code, inside_code);
}
