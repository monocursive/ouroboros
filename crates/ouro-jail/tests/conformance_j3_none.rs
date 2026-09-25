//! J3 `none`: the explicit uncontained profile, live on the reference host.
//!
//! jail-v1 §9.3, §12, §13.2 and the rows R05, R06, L02 (none's unknown
//! case), L03 (none without a usable cgroup) and X06 (for none). Every run
//! uses private state; every cgroup a test creates is named
//! `ouro-j3none-*` under the operator's delegated subtree and removed by the
//! test; an attempt leaf the jail retains is removed only after its inode is
//! checked against the receipt.
//!
//! Migration destinations. Under `user@<uid>.service` the delegated user can
//! write `cgroup.procs` of any cgroup that holds no controllers for its
//! children: a sibling it creates directly under the service, a transient
//! scope in `app.slice`, another attempt's leaf. It cannot write
//! `app.slice` or the service itself (EBUSY, no internal processes), and
//! cgroup v2 refuses `rename` (EPERM), so replacing a leaf means emptying it,
//! `rmdir` and `mkdir` (measured 2026-09-22, see the J3 none report). The
//! fixtures below use a sibling the test creates, which is exactly what an
//! uncontained child can create for itself.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use jsonschema::{Registry, Resource, Validator};
use ouro_fixture::harness::{self, Jail, Run, Spawned};
use ouro_jail::platform::linux::{cgroup, identity, probe, watch};
use serde_json::Value;

mod common;

const PYTHON: &str = "/usr/bin/python3";

// ---------------------------------------------------------------------------
// Preconditions and shared helpers
// ---------------------------------------------------------------------------

/// The delegated-scope precondition every live `none` case shares: the leaf
/// probe `none`'s tree termination rests on, plus the interpreter the
/// fixtures are written in.
fn live() -> bool {
    let leaf = probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "J3 none needs a delegated user scope with a usable leaf: {}",
            leaf.evidence
        ));
        return false;
    }
    if !Path::new(PYTHON).is_file() {
        harness::skip_or_fail("the none fixtures are python3 scripts");
        return false;
    }
    true
}

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

/// One validator per checked-in schema, registered by `$id`.
fn validators() -> BTreeMap<String, Validator> {
    let mut schemas: BTreeMap<String, Value> = BTreeMap::new();
    for entry in std::fs::read_dir(specs_dir()).expect("the specification directory") {
        let path = entry.expect("an entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(".schema.json") {
            let text = std::fs::read_to_string(&path).expect("a readable schema");
            schemas.insert(stem.to_owned(), serde_json::from_str(&text).expect("JSON"));
        }
    }
    let pairs: Vec<(String, Resource)> = schemas
        .values()
        .map(|schema| {
            let id = schema["$id"].as_str().expect("an $id").to_owned();
            (id, Resource::from_contents(schema.clone()))
        })
        .collect();
    let registry: Registry = Registry::new()
        .extend(pairs)
        .expect("valid identifiers")
        .prepare()
        .expect("a resolvable registry");
    let registry: &'static Registry = Box::leak(Box::new(registry));
    schemas
        .into_iter()
        .map(|(name, schema)| {
            let validator = jsonschema::options()
                .with_registry(registry)
                .should_validate_formats(true)
                .build(&schema)
                .unwrap_or_else(|error| panic!("compiling {name}: {error}"));
            (name, validator)
        })
        .collect()
}

/// Every receipt and trace event of the run validates against its schema,
/// and every receipt keeps the rules the schema cannot state
/// (`common::semantic_receipt`). The trace is read through the guarded
/// accessor, so it must also be complete (§13.3).
fn validate(run: &Run) {
    validate_receipts(run);
    validate_events(run.trace_events());
    // J5-C: the trace as a stream and the control transcript too.
    common::assert_run_records(run);
}

fn validate_receipts(run: &Run) {
    let validators = validators();
    for receipt in run.receipts() {
        validators["jail-receipt"]
            .validate(&receipt)
            .unwrap_or_else(|error| panic!("a receipt fails its schema: {error}\n{receipt:#}"));
        common::assert_semantic_receipt(&receipt);
    }
}

fn validate_events(events: &[Value]) {
    let validators = validators();
    for event in events {
        validators["jail-event"]
            .validate(event)
            .unwrap_or_else(|error| panic!("an event fails its schema: {error}\n{event:#}"));
    }
}

/// A `none` invocation over a private workspace, with trace and control.
fn none_case(observe: &str) -> (Jail, PathBuf) {
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    let jail = jail
        .arg("run")
        .arg("--profile")
        .arg("none")
        .arg("--observe")
        .arg(observe)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control();
    (jail, workspace)
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The latest `--receipt` copy once it reaches `phase`.
fn receipt_in_phase(spawned: &Spawned, phase: &str) -> Value {
    let mut latest = Value::Null;
    wait_for(&format!("a {phase} receipt"), || {
        latest = spawned.receipt_value().unwrap_or(Value::Null);
        latest["phase"] == phase
    });
    common::checked_receipt(latest)
}

/// The latest `--receipt` copy once its lifetime integrity reads `integrity`.
fn receipt_in_integrity(spawned: &Spawned, integrity: &str) -> Value {
    let mut latest = Value::Null;
    wait_for(&format!("a receipt with integrity {integrity}"), || {
        latest = spawned.receipt_value().unwrap_or(Value::Null);
        latest["lifetime"]["integrity"] == integrity
    });
    common::checked_receipt(latest)
}

/// The last receipt the run left in its canonical location.
fn last_receipt(run: &Run) -> Value {
    run.receipts()
        .into_iter()
        .max_by_key(|receipt| receipt["revision"].as_u64().unwrap_or(0))
        .unwrap_or_else(|| panic!("no receipt; stderr: {}", run.stderr_text()))
}

fn populated(cgroup_dir: &Path) -> bool {
    std::fs::read_to_string(cgroup_dir.join("cgroup.events"))
        .expect("cgroup.events is readable")
        .lines()
        .any(|line| line == "populated 1")
}

fn members(cgroup_dir: &Path) -> Vec<i32> {
    std::fs::read_to_string(cgroup_dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.parse().ok())
        .collect()
}

/// The leaf a receipt registered: its path and pinned inode.
fn leaf_of(receipt: &Value) -> (PathBuf, u64) {
    let leaf = &receipt["lifetime"]["native"]["details"]["execution_cgroup"];
    (
        PathBuf::from(leaf["path"].as_str().expect("a leaf path")),
        leaf["inode"].as_u64().expect("a leaf inode"),
    )
}

/// Empties and removes a cgroup this test's own attempt left behind: the
/// retained leaf (checked by inode) or a look-alike the fixture made at its
/// path. Never anything else.
fn remove_cgroup(dir: &Path) {
    if !dir.exists() {
        return;
    }
    if populated(dir) {
        std::fs::write(dir.join("cgroup.kill"), "1").expect("cgroup.kill");
        wait_for("the cgroup to empty", || !populated(dir));
    }
    std::fs::remove_dir(dir).expect("an empty cgroup is removed");
}

/// A migration destination the test creates beside the attempt leaves, the
/// same kind of cgroup an uncontained child can create for itself.
struct Destination {
    path: PathBuf,
}

impl Destination {
    fn new(tag: &str) -> Destination {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        // SAFETY: getuid takes no arguments and cannot fail.
        let root = cgroup::delegated_root(unsafe { libc::getuid() })
            .expect("the delegated subtree exists");
        let path = root.join(format!(
            "ouro-j3none-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("a destination cgroup");
        Destination { path }
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        // Only processes the attempt moved here: the test made this cgroup.
        if self.path.exists() && populated(&self.path) {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            let deadline = Instant::now() + Duration::from_secs(5);
            while populated(&self.path) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn lifetime_notes(run: &Run) -> Vec<Value> {
    run.trace_events()
        .iter()
        .filter(|event| event["source"] == "wrapper" && event["fields"]["kind"] == "lifetime")
        .map(|event| event["fields"].clone())
        .collect()
}

/// The §13.2 `none` tuple every receipt of these runs carries.
fn assert_unprotected(receipt: &Value) {
    assert_eq!(receipt["containment"], "none", "{receipt:#}");
    assert_eq!(receipt["child_protection"], "unprotected", "{receipt:#}");
    assert_eq!(receipt["applied"]["filesystem"], Value::Null);
    assert_eq!(receipt["applied"]["syscalls"], Value::Null);
    assert_eq!(receipt["applied"]["network"]["mode"], "host");
    assert_eq!(receipt["applied"]["network"]["mechanism"], Value::Null);
}

/// §9.3's lost tuple: no tree result, no time, the registered scope.
fn assert_lost(receipt: &Value) {
    assert_unprotected(receipt);
    assert_ne!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(receipt["lifetime"]["boundary"], "supervisor_cgroup");
    assert_eq!(
        receipt["lifetime"]["verification_scope"],
        "registered_boundary"
    );
    assert_eq!(receipt["lifetime"]["integrity"], "lost", "{receipt:#}");
    assert_eq!(receipt["lifetime"]["tree_empty"], Value::Null);
    assert_eq!(receipt["lifetime"]["verified_at"], Value::Null);
    let tree_unknown = receipt["errors"]
        .as_array()
        .and_then(|errors| errors.iter().find(|error| error["code"] == "tree_unknown"))
        .unwrap_or_else(|| panic!("no tree_unknown: {receipt:#}"));
    assert!(
        tree_unknown["message"]
            .as_str()
            .is_some_and(|message| message.contains("integrity was lost")),
        "a detected loss is not reported as a budget overrun: {tree_unknown}"
    );
    assert_ne!(receipt["state_cleanup"], "complete");
}

fn fixture_op(run: &Run, op: &str) -> Value {
    run.fixture_lines()
        .into_iter()
        .find(|line| line["op"] == op)
        .unwrap_or_else(|| panic!("the fixture never reported {op}: {}", run.stdout_text()))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item.as_str().expect("a string").to_owned())
        .collect()
}

fn own_status_field(key: &str) -> String {
    identity::status_field(std::process::id() as i32, key).expect("own status")
}

// ===========================================================================
// R05: clean evidence stays unprotected; same-UID tampering is outside it
// ===========================================================================

#[test]
fn r05_clean_none_evidence_stays_unprotected() {
    if !live() {
        return;
    }
    let (jail, workspace) = none_case("on");
    let written = workspace.join("written.txt");
    let run = jail
        .target([
            harness::fixture_path().into_os_string(),
            OsString::from("open"),
            written.clone().into_os_string(),
            OsString::from("--create"),
            OsString::from("--write"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    validate(&run);
    assert!(written.exists());
    let receipt = run
        .receipt_phase("settled")
        .unwrap_or_else(|| panic!("{}", run.stderr_text()));
    assert_unprotected(&receipt);
    assert_eq!(receipt["jail"]["backend"], "none");
    assert_eq!(receipt["exec_observed"], true);
    assert_eq!(receipt["outcome"]["kind"], "exited");
    assert_eq!(receipt["outcome"]["code"], 0);
    assert_eq!(receipt["errors"], serde_json::json!([]));
    // The evidence is as clean as a run's can be...
    assert_eq!(receipt["observer"]["attached"], true);
    assert_eq!(receipt["observer"]["gaps"], serde_json::json!([]));
    for class in ["exec", "fs.write", "fs.deny", "net", "limits"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "active", "{class}: {receipt:#}");
        assert_eq!(entry["gaps"], serde_json::json!([]), "{class}");
    }
    assert!(receipt["coverage"]["exec"]["observed_count"].as_u64() >= Some(1));
    assert!(receipt["coverage"]["fs.write"]["observed_count"].as_u64() >= Some(1));
    // ...and the verified boundary is the registered one, not the tree.
    assert_eq!(receipt["lifetime"]["boundary"], "supervisor_cgroup");
    assert_eq!(
        receipt["lifetime"]["verification_scope"],
        "registered_boundary"
    );
    assert_eq!(receipt["lifetime"]["integrity"], "verified");
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
    // The observer's filter is in the child and the receipt says so.
    let details = &receipt["lifetime"]["native"]["details"];
    assert!(
        details["narrowing_filter_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );
    let (leaf, _) = leaf_of(&receipt);
    assert!(!leaf.exists(), "a verified empty leaf is removed");
    // The whole lifecycle ran: prepared, exec confirmed, settled.
    let kinds: Vec<&str> = run
        .control_messages()
        .iter()
        .filter_map(|message| message["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["prepared", "exec_confirmed", "settled"]);
}

#[test]
fn r05_same_uid_tampering_is_outside_local_evidence_assurance() {
    if !live() {
        return;
    }
    let (jail, _) = none_case("on");
    // The child's own environment carries no reserved name, and it writes
    // the attempt's records anyway, because nothing separates two processes
    // of one user: hygiene is not protection (§12). It is handed the state
    // root's path: since J5 the supervisor is not dumpable, so its
    // environment is no longer a way to learn it (§9.3), and in a real
    // deployment the default state root is at a predictable per-user path.
    let data_dir = jail.data_dir().to_path_buf();
    let code = r#"
import json, os, sys
own = sorted(name for name in os.environ if name.startswith('OURO_'))
data = os.fsencode(sys.argv[1])
attempts = os.path.join(data, b'attempts')
(attempt,) = [name for name in os.listdir(attempts) if name.startswith(b'att_')]
policy = os.path.join(attempts, attempt, b'policy.json')
with open(policy, 'wb') as out:
    out.write(b'{"forged": "by the uncontained child"}')
print(json.dumps({'own_reserved': own, 'found_state_root': True,
                  'session_leader': os.getsid(0) == os.getpid()}))
"#;
    let run = jail
        .target([
            PYTHON.as_ref(),
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new(code),
            data_dir.as_os_str(),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    validate(&run);
    let report: Value = serde_json::from_str(run.stdout_text().trim()).expect("a report");
    assert_eq!(report["own_reserved"], serde_json::json!([]));
    assert_eq!(report["found_state_root"], true);
    // §8.3: the command runs in a new session, uncontained or not.
    assert_eq!(report["session_leader"], true);
    let receipt = run
        .receipt_phase("settled")
        .unwrap_or_else(|| panic!("{}", run.stderr_text()));
    // The run settles cleanly by every local measure, and its receipt still
    // makes no protection claim.
    assert_unprotected(&receipt);
    assert_eq!(receipt["lifetime"]["integrity"], "verified");
    assert!(
        strings(&receipt["applied"]["removed_environment_names"])
            .contains(&"OURO_DATA_DIR".to_owned())
    );
    // The attempt's immutable policy snapshot is not immutable to this child.
    let attempt = receipt["attempt_id"].as_str().unwrap();
    let stored = std::fs::read_to_string(
        run.data_dir
            .join("attempts")
            .join(attempt)
            .join("policy.json"),
    )
    .expect("the stored policy");
    assert!(
        stored.contains("forged"),
        "the same-UID child rewrote local evidence and nothing detected it: {stored}"
    );
}

// ===========================================================================
// R06: migration never fabricates exit, settlement or tree_empty
// ===========================================================================

/// The target moves itself out of the leaf, ignores SIGTERM and stays alive.
/// The leaf reads empty while the target runs; only an operator stop ends the
/// run, the leaf's `cgroup.kill` cannot reach the target, and the stop still
/// does, through its pidfd. The outcome is the target's own wait status, not
/// an exit inferred from population.
#[test]
fn r06_a_target_that_leaves_the_leaf_while_live_is_never_settled() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let destination = Destination::new("target");
        let (jail, _) = none_case(observe);
        let moved = jail.root().join("moved");
        let code = format!(
            "import os, signal, time\n\
             signal.signal(signal.SIGTERM, signal.SIG_IGN)\n\
             open({dest:?}, 'w').write('0')\n\
             open({moved:?}, 'w').write(str(os.getpid()))\n\
             time.sleep(60)\n",
            dest = destination.path.join("cgroup.procs").to_str().unwrap(),
            moved = moved.to_str().unwrap(),
        );
        let spawned = jail
            .receipt()
            .target([PYTHON, "-c", &code])
            .spawn()
            .expect("the jail starts");
        let target = written_pid("the target to move", &moved);
        let enforced = receipt_in_phase(&spawned, "enforced");
        let (leaf, inode) = leaf_of(&enforced);
        // The registered boundary is empty and the target is alive.
        assert!(
            !populated(&leaf),
            "{observe}: the leaf still has the target"
        );
        assert!(members(&destination.path).contains(&target));
        let target_fd = identity::pidfd_open(target).expect("the live target");
        assert!(!watch::readable(target_fd.as_raw_fd()));
        // The detected escape reaches the receipt while the target runs, so a
        // supervisor lost from here on leaves `lost`, not `verified`, behind.
        let running = receipt_in_integrity(&spawned, "lost");
        assert_eq!(
            running["phase"], "enforced",
            "{observe}: an empty leaf settled the attempt"
        );
        assert_eq!(running["lifetime"]["tree_empty"], Value::Null);
        assert_eq!(running["outcome"]["kind"], "pending");
        // SAFETY: the harness's own unreaped child.
        assert_eq!(
            unsafe { libc::kill(spawned.pid() as i32, libc::SIGTERM) },
            0
        );
        let run = spawned.wait().expect("the jail ends");
        validate(&run);
        assert_eq!(run.code(), Some(1), "{observe}: {}", run.stderr_text());
        let receipt = last_receipt(&run);
        assert_lost(&receipt);
        assert_eq!(receipt["phase"], "enforced");
        assert_eq!(receipt["exec_observed"], true);
        // The target's own end, from its own source: it ignored the
        // cooperative stop and the forced one reached it outside the leaf.
        assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
        assert_eq!(receipt["outcome"]["signal"], libc::SIGKILL);
        assert_eq!(receipt["outcome"]["cause"], "operator_signal");
        assert!(watch::readable(target_fd.as_raw_fd()));
        assert!(!populated(&destination.path));
        assert!(run.control_kind("settled").is_empty());
        assert_eq!(run.control_kind("unsettled").len(), 1);
        let notes = lifetime_notes(&run);
        assert!(
            notes
                .iter()
                .any(|note| note["subject"] == "target" && note["reason"] == "membership_escape"),
            "{observe}: {notes:?}"
        );
        // State is retained: the leaf is still there, still the pinned one.
        assert_eq!(std::fs::metadata(&leaf).expect("retained").ino(), inode);
        remove_cgroup(&leaf);
    }
}

/// A descendant waits for the target to exit, then moves itself out and
/// stays alive. The target's exit is preserved; the boundary empties; the
/// escape is detected, so there is no settlement and no tree result, and the
/// escaped orphan (reparented to the subreaper supervisor) is ended.
#[test]
fn r06_a_descendant_that_leaves_after_the_target_exits_loses_integrity() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let destination = Destination::new("descendant");
        let (jail, _) = none_case(observe);
        let moved = jail.root().join("moved");
        let code = format!(
            "import os, time\n\
             r, w = os.pipe()\n\
             if os.fork() == 0:\n\
             \x20   os.close(w)\n\
             \x20   null = os.open('/dev/null', os.O_RDWR)\n\
             \x20   for fd in (0, 1, 2): os.dup2(null, fd)\n\
             \x20   os.read(r, 1)\n\
             \x20   open({dest:?}, 'w').write('0')\n\
             \x20   open({moved:?}, 'w').write(str(os.getpid()))\n\
             \x20   time.sleep(60)\n\
             \x20   os._exit(0)\n\
             os.close(r)\n",
            dest = destination.path.join("cgroup.procs").to_str().unwrap(),
            moved = moved.to_str().unwrap(),
        );
        let run = jail
            .target([PYTHON, "-c", &code])
            .run()
            .expect("the jail runs");
        validate(&run);
        assert_eq!(run.code(), Some(1), "{observe}: {}", run.stderr_text());
        assert!(moved.exists(), "{observe}: the descendant never moved");
        let receipt = last_receipt(&run);
        assert_lost(&receipt);
        assert_eq!(receipt["phase"], "enforced");
        // The target's own exit is independent of what its descendant did.
        assert_eq!(receipt["outcome"]["kind"], "exited", "{receipt:#}");
        assert_eq!(receipt["outcome"]["code"], 0);
        assert!(run.control_kind("settled").is_empty());
        let notes = lifetime_notes(&run);
        assert!(
            notes.iter().any(
                |note| note["subject"] == "descendant" && note["reason"] == "membership_escape"
            ),
            "{observe}: {notes:?}"
        );
        // The escaped orphan was this attempt's and was ended.
        assert!(
            !populated(&destination.path),
            "{observe}: the escaped descendant survived its attempt"
        );
        let (leaf, inode) = leaf_of(&receipt);
        assert!(!populated(&leaf));
        assert_eq!(std::fs::metadata(&leaf).expect("retained").ino(), inode);
        remove_cgroup(&leaf);
    }
}

/// Observation off, a target that moves out and exits at once is caught by
/// the cgroup its zombie still names, before this supervisor reaps it: no
/// poll has to see it alive outside the leaf.
#[test]
fn r06_a_target_that_leaves_and_exits_at_once_is_caught_by_its_zombie() {
    if !live() {
        return;
    }
    let destination = Destination::new("target-exit");
    let (jail, _) = none_case("off");
    let code = format!(
        "import os\n\
         open({dest:?}, 'w').write('0')\n\
         os._exit(5)\n",
        dest = destination.path.join("cgroup.procs").to_str().unwrap(),
    );
    let run = jail
        .target([PYTHON, "-c", &code])
        .run()
        .expect("the jail runs");
    validate(&run);
    assert_eq!(run.code(), Some(1), "{}", run.stderr_text());
    let receipt = last_receipt(&run);
    assert_lost(&receipt);
    assert_eq!(receipt["outcome"]["kind"], "exited", "{receipt:#}");
    assert_eq!(receipt["outcome"]["code"], 5);
    assert!(
        lifetime_notes(&run)
            .iter()
            .any(|note| note["subject"] == "target" && note["reason"] == "membership_escape")
    );
    let (leaf, _) = leaf_of(&receipt);
    remove_cgroup(&leaf);
}

/// Observation off, a descendant that moves out after the target exits and
/// then exits at once is caught the same way: the subreaper supervisor is
/// its parent by then and reads where its zombie died before reaping it.
#[test]
fn r06_a_descendant_that_leaves_and_exits_at_once_is_caught_by_its_zombie() {
    if !live() {
        return;
    }
    let destination = Destination::new("descendant-exit");
    let (jail, _) = none_case("off");
    let code = format!(
        "import os\n\
         r, w = os.pipe()\n\
         if os.fork() == 0:\n\
         \x20   os.close(w)\n\
         \x20   os.read(r, 1)\n\
         \x20   open({dest:?}, 'w').write('0')\n\
         \x20   os._exit(0)\n\
         os.close(r)\n",
        dest = destination.path.join("cgroup.procs").to_str().unwrap(),
    );
    let run = jail
        .target([PYTHON, "-c", &code])
        .run()
        .expect("the jail runs");
    validate(&run);
    assert_eq!(run.code(), Some(1), "{}", run.stderr_text());
    let receipt = last_receipt(&run);
    assert_lost(&receipt);
    assert_eq!(receipt["outcome"]["kind"], "exited", "{receipt:#}");
    assert_eq!(receipt["outcome"]["code"], 0);
    assert!(
        lifetime_notes(&run)
            .iter()
            .any(|note| note["subject"] == "descendant" && note["reason"] == "membership_escape")
    );
    let (leaf, _) = leaf_of(&receipt);
    remove_cgroup(&leaf);
}

/// The target empties the leaf, replaces it with a look-alike at the same
/// path and moves back in. By path it is "inside"; by the pinned inode the
/// registered boundary is gone, and the look-alike is never signalled or
/// removed by the jail.
#[test]
fn r06_a_replaced_leaf_loses_integrity_and_is_never_touched() {
    if !live() {
        return;
    }
    let destination = Destination::new("replace");
    let (jail, _) = none_case("on");
    let replaced = jail.root().join("replaced");
    let code = format!(
        "import os, time\n\
         leaf = '/sys/fs/cgroup' + open('/proc/self/cgroup').read().split('::', 1)[1].strip()\n\
         open({dest:?}, 'w').write('0')\n\
         os.rmdir(leaf)\n\
         os.mkdir(leaf)\n\
         open(leaf + '/cgroup.procs', 'w').write('0')\n\
         open({replaced:?}, 'w').write(str(os.getpid()))\n\
         time.sleep(60)\n",
        dest = destination.path.join("cgroup.procs").to_str().unwrap(),
        replaced = replaced.to_str().unwrap(),
    );
    let spawned = jail
        .receipt()
        .target([PYTHON, "-c", &code])
        .spawn()
        .expect("the jail starts");
    let target = written_pid("the leaf to be replaced", &replaced);
    let (leaf, inode) = leaf_of(&receipt_in_phase(&spawned, "enforced"));
    assert_ne!(std::fs::metadata(&leaf).unwrap().ino(), inode);
    assert!(
        members(&leaf).contains(&target),
        "the look-alike holds the target"
    );
    // By path the target is "inside"; the pinned inode says otherwise, and
    // the receipt says so while the target still runs.
    let running = receipt_in_integrity(&spawned, "lost");
    assert_eq!(running["phase"], "enforced");
    // SAFETY: the harness's own unreaped child.
    assert_eq!(
        unsafe { libc::kill(spawned.pid() as i32, libc::SIGTERM) },
        0
    );
    let run = spawned.wait().expect("the jail ends");
    validate(&run);
    assert_eq!(run.code(), Some(1), "{}", run.stderr_text());
    let receipt = last_receipt(&run);
    assert_lost(&receipt);
    assert_eq!(receipt["outcome"]["kind"], "signaled");
    assert_eq!(receipt["outcome"]["signal"], libc::SIGTERM);
    let notes = lifetime_notes(&run);
    assert!(
        notes
            .iter()
            .any(|note| note["subject"] == "boundary" && note["reason"] == "identity_replaced"),
        "{notes:?}"
    );
    // The jail neither killed through nor removed the replacement.
    assert!(leaf.exists(), "the jail removed a cgroup it does not own");
    assert_ne!(std::fs::metadata(&leaf).unwrap().ino(), inode);
    remove_cgroup(&leaf);
}

// ===========================================================================
// L02: none's specified unknown case
// ===========================================================================

/// §8.2 / north star §4.9: when the supervisor dies, `none` has no second
/// watchdog. The last receipt stays nonsettled with no tree result and the
/// leaf is retained. With observation off a descendant is left running in
/// it: exactly the accepted unknown, which nothing reports as settled. With
/// observation on the kernel ends the traced tree with its tracer, which
/// changes nothing in the record.
#[test]
fn l02_none_supervisor_death_leaves_the_specified_unknown() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = none_case(observe);
        let descendant = jail.root().join("descendant");
        let running = jail.root().join("running");
        let code = format!(
            "import os, time\n\
             if os.fork() == 0:\n\
             \x20   null = os.open('/dev/null', os.O_RDWR)\n\
             \x20   for fd in (0, 1, 2): os.dup2(null, fd)\n\
             \x20   open({descendant:?}, 'w').write(str(os.getpid()))\n\
             \x20   time.sleep(60)\n\
             \x20   os._exit(0)\n\
             while not os.path.exists({descendant:?}): time.sleep(0.01)\n\
             open({running:?}, 'w').write(str(os.getpid()))\n\
             time.sleep(60)\n",
            descendant = descendant.to_str().unwrap(),
            running = running.to_str().unwrap(),
        );
        let spawned = jail
            .receipt()
            .target([PYTHON, "-c", &code])
            .spawn()
            .expect("the jail starts");
        wait_for("the target", || running.exists());
        let enforced = receipt_in_phase(&spawned, "enforced");
        let (leaf, inode) = leaf_of(&enforced);
        let pid: i32 = std::fs::read_to_string(&descendant)
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            members(&leaf).contains(&pid),
            "the descendant is in the leaf"
        );
        let descendant_fd = identity::pidfd_open(pid).expect("the live descendant");
        let supervisor = identity::pidfd_open(spawned.pid() as i32).unwrap();
        identity::pidfd_send_signal(supervisor.as_raw_fd(), libc::SIGKILL).unwrap();
        let run = spawned
            .wait()
            .expect("the harness collects the dead supervisor");
        assert_eq!(run.signal(), Some(libc::SIGKILL));
        // The trace ends wherever the kill found the supervisor, not on the
        // note of a final receipt (§13.3), so the guarded accessor rightly
        // refuses it: its complete frames are validated from the readback.
        validate_receipts(&run);
        validate_events(
            &run.trace_readback
                .as_ref()
                .expect("a trace was requested")
                .frames,
        );
        let last = last_receipt(&run);
        assert_unprotected(&last);
        assert_eq!(last["phase"], "enforced", "{observe}: {last:#}");
        assert_eq!(last["lifetime"]["tree_empty"], Value::Null);
        assert_eq!(last["lifetime"]["verified_at"], Value::Null);
        assert!(run.receipt_phase("settled").is_none());
        assert!(run.control_kind("settled").is_empty());
        assert!(run.control_kind("unsettled").is_empty());
        // The leaf that registered the tree is retained for GC to identify.
        assert_eq!(std::fs::metadata(&leaf).unwrap().ino(), inode);
        if observe == "on" {
            // The observer seized every descendant with PTRACE_O_EXITKILL, so
            // the kernel kills the traced tree when its tracer dies. That is
            // the observer's attachment, not a lifetime claim: the record
            // above stays unknown all the same.
            wait_for("the traced descendant to die with its tracer", || {
                watch::readable(descendant_fd.as_raw_fd())
            });
        } else {
            // Nothing ended the descendant: no watchdog exists (§8.2), the
            // unknown is real, and the retained leaf still holds it.
            assert!(
                !watch::readable(descendant_fd.as_raw_fd()),
                "a watchdog nobody specified killed the descendant"
            );
            assert!(members(&leaf).contains(&pid));
        }
        remove_cgroup(&leaf);
        assert!(watch::readable(descendant_fd.as_raw_fd()));
    }
}

// ===========================================================================
// L03: none without a usable cgroup refuses
// ===========================================================================

/// §9.3 / north star §4.2: "If the cgroup cannot be created, the run exits
/// 125. It does not fall back to a process-group kill." Outside the delegated
/// subtree (a plain login session) this runs the jail directly, with the
/// supervisor scope step held to the no-lingering branch: where the user
/// manager lingers the step would otherwise move the supervisor into a
/// delegated scope, and the cgroup would be usable after all. Inside it,
/// where the driver runs every test, the jail runs in a fresh cgroup
/// namespace rooted at the test's own scope (one bubblewrap user namespace,
/// host view otherwise): the delegated subtree is then outside its
/// namespace, which is the same "supervisor outside the delegation" refusal
/// the kernel's migration rules impose on a login session.
#[test]
fn l03_none_without_a_usable_cgroup_refuses() {
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let inside = cgroup::delegated_root(uid).is_some_and(|root| {
        let relative = format!(
            "/{}",
            root.strip_prefix(cgroup::CGROUP_ROOT).unwrap().display()
        );
        cgroup::own_cgroup().is_ok_and(|own| cgroup::common_ancestor_ok(&own, &relative))
    });
    if inside && !common::live() {
        return;
    }
    eprintln!(
        "L03 none: {}",
        if inside {
            "inside the delegated scope; the jail runs in its own cgroup namespace"
        } else {
            "outside the delegated scope; the jail runs directly"
        }
    );
    for observe in ["on", "off"] {
        let jail = if inside {
            Jail::with_program(common::bwrap_path())
                .expect("a private harness")
                .args([
                    "--unshare-user",
                    "--unshare-cgroup",
                    "--dev-bind",
                    "/",
                    "/",
                    "--",
                ])
                .arg(harness::jail_path())
        } else {
            Jail::new().expect("a private harness").env(
                "OURO_JAIL_TEST_SUPERVISOR_SCOPE",
                "assume-outside-no-linger",
            )
        };
        let workspace = jail.root().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let marker = jail.root().join("target-ran");
        let run = jail
            .arg("run")
            .arg("--profile")
            .arg("none")
            .arg("--observe")
            .arg(observe)
            .arg("--workspace")
            .arg(&workspace)
            .control()
            .target(["/bin/sh", "-c", &format!("touch {}", marker.display())])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(125), "{observe}: {}", run.stderr_text());
        assert!(!marker.exists(), "{observe}: the target ran");
        validate(&run);
        let receipt = run
            .receipt_phase("refused")
            .unwrap_or_else(|| panic!("{observe}: {}", run.stderr_text()));
        assert_unprotected(&receipt);
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(receipt["outcome"]["kind"], "refused");
        assert_eq!(receipt["outcome"]["error"]["code"], "missing_capability");
        assert_eq!(
            receipt["outcome"]["error"]["remediation_category"],
            "host_setup"
        );
        assert_eq!(receipt["lifetime"]["boundary"], "pending");
        assert!(
            strings(&receipt["policy"]["requirements"]).contains(&"execution_boundary".to_owned())
        );
    }
}

// ===========================================================================
// X06 for none, and the backend it does not need
// ===========================================================================

#[test]
fn x06_none_reserved_names_and_private_channels_do_not_reach_the_child() {
    if !live() {
        return;
    }
    let secret = "j3-none-secret-value-7f3a";
    for observe in ["on", "off"] {
        let (jail, workspace) = none_case(observe);
        let script = workspace.join("script.json");
        std::fs::write(&script, br#"[["fds"],["status"],["env"]]"#).unwrap();
        let mut spawned = jail
            .gate()
            .receipt()
            .env("OURO_J3_TOKEN", secret)
            .env("J3_NONE_KEEP", "kept")
            .env("ouro_lowercase_is_not_reserved", "kept")
            .target([
                harness::fixture_path().into_os_string(),
                OsString::from("script"),
                script.into_os_string(),
            ])
            .spawn()
            .expect("the jail starts");
        let prepared = spawned.owner().await_prepared().expect("prepared");
        let receipt =
            common::checked_receipt(spawned.receipt_value().expect("the prepared receipt"));
        spawned
            .owner()
            .release(
                &harness::gate::Release::Valid,
                prepared["attempt_id"].as_str().unwrap(),
                receipt["policy"]["digest"].as_str().unwrap(),
            )
            .expect("released");
        let run = spawned.wait().expect("the jail ends");
        assert_eq!(run.code(), Some(0), "{observe}: {}", run.stderr_text());
        validate(&run);

        // Exactly validated stdio: gate, control, trace, state, pidfds and
        // the launcher's own channels all closed before exec.
        let fds: Vec<i64> = fixture_op(&run, "fds")["args"]["fds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry["fd"].as_i64())
            .collect();
        assert_eq!(fds, vec![0, 1, 2], "{observe}");

        // Reserved names are gone, case-sensitively; everything else stays.
        let names = strings(&fixture_op(&run, "env")["args"]["names"]);
        assert!(
            names.iter().all(|name| !name.starts_with("OURO_")),
            "{names:?}"
        );
        for kept in ["J3_NONE_KEEP", "ouro_lowercase_is_not_reserved", "PATH"] {
            assert!(
                names.contains(&kept.to_owned()),
                "{observe}: {kept} missing"
            );
        }
        let settled = run
            .receipt_phase("settled")
            .unwrap_or_else(|| panic!("{}", run.stderr_text()));
        assert_unprotected(&settled);
        let mut recorded = strings(&settled["applied"]["environment_names"]);
        recorded.sort();
        let mut seen = names.clone();
        seen.sort();
        assert_eq!(recorded, seen, "the receipt lists what the child has");
        // The removed list is exactly this supervisor's reserved names.
        let mut expected: Vec<String> = std::env::vars()
            .map(|(name, _)| name)
            .filter(|name| name.starts_with("OURO_"))
            .chain(["OURO_DATA_DIR", "OURO_CONFIG_DIR", "OURO_J3_TOKEN"].map(ToOwned::to_owned))
            .collect();
        expected.sort();
        expected.dedup();
        assert_eq!(
            strings(&settled["applied"]["removed_environment_names"]),
            expected
        );
        // Names, never values.
        let everything = format!(
            "{}{}{}",
            serde_json::to_string(&run.receipts()).unwrap(),
            serde_json::to_string(run.trace_events()).unwrap(),
            serde_json::to_string(run.control_messages()).unwrap()
        );
        assert!(!everything.contains(secret), "{observe}: a value leaked");

        // No capability reaches it, and the only filter is the observer's.
        let status = &fixture_op(&run, "status")["args"]["fields"];
        for key in ["CapEff", "CapPrm", "CapAmb"] {
            let value = status[key].as_str().unwrap();
            assert!(value.chars().all(|c| c == '0'), "{key} {value}");
        }
        if observe == "on" {
            assert_eq!(status["NoNewPrivs"], "1");
            assert_eq!(status["Seccomp"], "2");
        } else {
            assert_eq!(status["NoNewPrivs"], own_status_field("NoNewPrivs"));
            assert_eq!(status["Seccomp"], own_status_field("Seccomp"));
        }
    }
}

/// North star §4.9: "`none` does not require the enforcement backend."
#[test]
fn none_runs_without_the_enforcement_backend_on_path() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = none_case(observe);
        let run = jail
            .env("PATH", "/nonexistent-j3-none")
            .target(["/usr/bin/true"])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(0), "{observe}: {}", run.stderr_text());
        validate(&run);
        let receipt = run
            .receipt_phase("settled")
            .unwrap_or_else(|| panic!("{observe}: {}", run.stderr_text()));
        assert_eq!(receipt["jail"]["backend"], "none");
        assert_eq!(receipt["exec_observed"], true);
        assert_eq!(receipt["outcome"]["kind"], "exited");
        assert_eq!(receipt["outcome"]["code"], 0);
    }
}

// ===========================================================================
// What `none` cannot apply, and the lifecycle it shares with contained runs
// ===========================================================================

/// §3.1 / I02 / rule "nothing silently degrades": a narrowing layer may ask
/// `none` for a restriction (§6.3), and `none` applies none. Each such
/// request refuses before exec, naming the requirement, instead of running
/// with the restriction dropped.
#[test]
fn none_refuses_restrictions_it_cannot_apply() {
    if !live() {
        return;
    }
    type Cli = fn(&Path) -> Vec<OsString>;
    let no_cli: Cli = |_| Vec::new();
    let cases: [(&str, Option<&str>, Cli, &str); 5] = [
        (
            "--deny-read",
            None,
            |ws| vec!["--deny-read".into(), ws.join("secret").into_os_string()],
            "filesystem_containment",
        ),
        (
            "--ro",
            None,
            |ws| vec!["--ro".into(), ws.join("secret").into_os_string()],
            "filesystem_containment",
        ),
        (
            "project deny_read",
            Some(
                "[jail]\nschema = \"ouro.jail.policy/1\"\n[jail.filesystem]\ndeny_read = [\"./secret\"]\n",
            ),
            no_cli,
            "filesystem_containment",
        ),
        (
            "project network none",
            Some("[jail]\nschema = \"ouro.jail.policy/1\"\n[jail.network]\nmode = \"none\"\n"),
            no_cli,
            "network_none",
        ),
        (
            "project protected coverage",
            Some(
                "[jail]\nschema = \"ouro.jail.policy/1\"\n[jail.filesystem]\nprotected_coverage = \"existing_and_root\"\n",
            ),
            no_cli,
            "protected_coverage:existing_and_root",
        ),
    ];
    for (label, project, cli, requirement) in cases {
        let (jail, workspace) = none_case("off");
        std::fs::create_dir(workspace.join("secret")).unwrap();
        if let Some(text) = project {
            std::fs::write(workspace.join("ouro.toml"), text).unwrap();
        }
        let marker = jail.root().join("target-ran");
        let run = jail
            .args(cli(&workspace))
            .target(["/bin/sh", "-c", &format!("touch {}", marker.display())])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(125), "{label}: {}", run.stderr_text());
        assert!(!marker.exists(), "{label}: the target ran unrestricted");
        validate(&run);
        let receipt = run
            .receipt_phase("refused")
            .unwrap_or_else(|| panic!("{label}: {}", run.stderr_text()));
        assert_unprotected(&receipt);
        assert!(
            strings(&receipt["policy"]["requirements"]).contains(&requirement.to_owned()),
            "{label}: {receipt:#}"
        );
        let error = &receipt["outcome"]["error"];
        assert_eq!(error["code"], "missing_capability", "{label}");
        assert_eq!(error["stage"], "probing", "{label}");
        assert_eq!(error["remediation_category"], "configuration", "{label}");
        assert!(
            error["message"].as_str().unwrap().contains(requirement),
            "{label}: {error}"
        );
    }
}

/// §8.1 / X04 for `none`: a target exec that fails is a proved exec error
/// reported through the launcher's error channel, in both observation modes.
#[test]
fn none_exec_failure_is_a_proved_exec_error() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = none_case(observe);
        let run = jail
            .target(["/nonexistent-j3-none/program"])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(125), "{observe}: {}", run.stderr_text());
        validate(&run);
        let receipt = run.receipt_phase("refused").expect("a refused receipt");
        assert_unprotected(&receipt);
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(receipt["outcome"]["kind"], "exec_error", "{receipt:#}");
        assert_eq!(receipt["outcome"]["cause"], "ENOENT");
        assert_eq!(receipt["lifetime"]["boundary"], "supervisor_cgroup");
    }
}

/// §8.2 / X02 for `none`: a gate closed without a release refuses; the
/// blocked launcher never execs, and the teardown of the registered leaf is
/// verified before the refusal claims it (§13.2, refusal after setup).
#[test]
fn none_gate_closed_refuses_after_a_verified_teardown() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = none_case(observe);
        let marker = jail.root().join("target-ran");
        let mut spawned = jail
            .gate()
            .receipt()
            .target(["/bin/sh", "-c", &format!("touch {}", marker.display())])
            .spawn()
            .expect("the jail starts");
        spawned.owner().await_prepared().expect("prepared");
        let prepared =
            common::checked_receipt(spawned.receipt_value().expect("a prepared receipt"));
        assert_eq!(prepared["phase"], "prepared");
        assert_unprotected(&prepared);
        assert_eq!(prepared["lifetime"]["integrity"], "verified");
        let (leaf, _) = leaf_of(&prepared);
        let launcher = prepared["lifetime"]["native"]["details"]["launcher_pid"]
            .as_i64()
            .unwrap() as i32;
        assert_eq!(
            members(&leaf),
            vec![launcher],
            "{observe}: placed before release"
        );
        let run = spawned.wait().expect("the jail ends");
        assert!(run.gate_closed_by_harness);
        assert_eq!(run.code(), Some(125), "{observe}: {}", run.stderr_text());
        assert!(!marker.exists());
        validate(&run);
        let receipt = run.receipt_phase("refused").expect("a refused receipt");
        assert_unprotected(&receipt);
        assert_eq!(receipt["outcome"]["error"]["code"], "gate_closed");
        assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt:#}");
        assert_eq!(receipt["lifetime"]["integrity"], "verified");
        assert_eq!(
            receipt["lifetime"]["verification_scope"],
            "registered_boundary"
        );
        assert!(!leaf.exists(), "{observe}: the torn-down leaf is removed");
    }
}

/// §9.3 for `none`: "the same deadline logic". The wall expires, the target
/// gets its cooperative stop, a descendant that ignores it dies with the
/// leaf's `cgroup.kill`, and the registered boundary is verified empty. An
/// explicit pids ceiling applies to that same leaf.
#[test]
fn none_wall_expiry_ends_the_tree_through_the_leaf() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = none_case(observe);
        let stubborn = jail.root().join("stubborn");
        let code = format!(
            "import os, signal, time\n\
             if os.fork() == 0:\n\
             \x20   signal.signal(signal.SIGTERM, signal.SIG_IGN)\n\
             \x20   open({stubborn:?}, 'w').write(str(os.getpid()))\n\
             \x20   time.sleep(60)\n\
             \x20   os._exit(0)\n\
             time.sleep(60)\n",
            stubborn = stubborn.to_str().unwrap(),
        );
        let run = jail
            .args(["--limit", "wall=1s", "--limit", "pids=64"])
            .target([PYTHON, "-c", &code])
            .run()
            .expect("the jail runs");
        validate(&run);
        let receipt = run
            .receipt_phase("settled")
            .unwrap_or_else(|| panic!("{observe}: {}", run.stderr_text()));
        assert_unprotected(&receipt);
        assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
        assert_eq!(receipt["outcome"]["signal"], libc::SIGTERM);
        assert_eq!(receipt["outcome"]["cause"], "wall_expiry");
        let limits = receipt["applied"]["limits"].as_array().unwrap();
        let wall = limits.iter().find(|row| row["key"] == "wall").unwrap();
        assert_eq!(wall["hit"], true);
        assert_eq!(wall["mechanism"], "boottime-deadline");
        let pids = limits.iter().find(|row| row["key"] == "pids").unwrap();
        assert_eq!(pids["applied"], true);
        assert_eq!(pids["mechanism"], "pids.max");
        assert_eq!(pids["scope"], "tree");
        assert_eq!(receipt["lifetime"]["tree_empty"], true);
        assert_eq!(receipt["lifetime"]["integrity"], "verified");
        // The descendant existed, ignored the cooperative stop, and the
        // leaf that held it was still verified empty.
        assert!(stubborn.exists(), "{observe}: the descendant never started");
        let (leaf, _) = leaf_of(&receipt);
        assert!(!leaf.exists());
    }
}

/// Behind the capability refusal, the boundary itself never runs a `none`
/// snapshot carrying a restriction it would not apply: called directly, it
/// refuses before creating a leaf or starting a process.
#[test]
fn the_boundary_itself_refuses_a_restriction_it_would_not_apply() {
    use ouro_jail::platform::{PlanRequest, PreparedPlan, Sinks};
    use ouro_jail::policy::{PathRef, ProfileName, ResolveInputs, RootToken, ScratchRoot};
    use ouro_jail::records::{NativeString, Os};

    let root = common::private_tempdir();
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let marker = root.path().join("target-ran");
    let resolved = ouro_jail::policy::resolve(&ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::None,
        policy_name: "none".to_owned(),
        baseline: ouro_jail::profiles::baseline(ProfileName::None, Os::Linux, &|_| None),
        workspace: workspace.as_os_str().as_encoded_bytes().to_vec(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: Vec::new(),
    })
    .expect("the bare none baseline resolves");
    type Restrict = fn(&mut ouro_jail::policy::PolicySnapshot);
    let restrictions: [(&str, Restrict); 4] = [
        ("filesystem.deny_read", |snapshot| {
            snapshot.filesystem.deny_read.push(PathRef {
                root: RootToken::Workspace,
                path: NativeString::Text("secret".to_owned()),
            });
        }),
        ("filesystem.read_only", |snapshot| {
            snapshot.filesystem.read_only.push(PathRef {
                root: RootToken::Workspace,
                path: NativeString::Text("fixtures".to_owned()),
            });
        }),
        ("network.mode", |snapshot| {
            snapshot.network.mode = "none".to_owned();
        }),
        ("filesystem.protected_coverage", |snapshot| {
            snapshot.filesystem.protected_coverage =
                ouro_jail::policy::ProtectedCoverage::ExistingAndRoot;
        }),
    ];
    for (key, restrict) in restrictions {
        let mut snapshot = resolved.snapshot.clone();
        restrict(&mut snapshot);
        let plan = PreparedPlan {
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            attempt_dir: root.path().join("attempt"),
            request: PlanRequest {
                requirements: ouro_jail::capability::requirements(&snapshot),
                snapshot,
                profile: ProfileName::None,
            },
            argv: vec![
                b"/bin/sh".to_vec(),
                b"-c".to_vec(),
                format!("touch {}", marker.display()).into_bytes(),
            ],
            workspace: workspace.clone(),
            launch: None,
            proxy: None,
        };
        let deadline = ouro_jail::platform::linux::clock::Deadline::after(Duration::from_secs(10));
        let Err(error) =
            ouro_jail::platform::linux::uncontained::prepare(plan, Sinks { trace: None }, deadline)
        else {
            panic!("{key}: the uncontained boundary prepared a restriction it cannot apply");
        };
        assert_eq!(
            error.code,
            ouro_jail::records::ErrorCode::MissingCapability,
            "{key}"
        );
        assert_eq!(error.key_path.as_deref(), Some(key));
        assert!(!marker.exists(), "{key}: a process ran");
    }
}

// ===========================================================================
// The review's survivors, live (G1, A13)
// ===========================================================================

/// G1: the re-check in `release`. Between `prepared` and the gate's release a
/// same-UID process moves the blocked launcher out of the leaf, or also
/// replaces the emptied leaf. The release refuses, the target never runs,
/// and the refused receipt carries the teardown: integrity `lost`.
#[test]
fn g1_tampering_between_prepared_and_release_refuses_with_integrity_lost() {
    if !live() {
        return;
    }
    for (label, replace) in [("migrated launcher", false), ("replaced leaf", true)] {
        for observe in ["on", "off"] {
            let destination = Destination::new("prerelease");
            let (jail, _) = none_case(observe);
            let marker = jail.root().join("target-ran");
            let mut spawned = jail
                .gate()
                .receipt()
                .target(["/bin/sh", "-c", &format!("touch {}", marker.display())])
                .spawn()
                .expect("the jail starts");
            let prepared = spawned.owner().await_prepared().expect("prepared");
            let receipt =
                common::checked_receipt(spawned.receipt_value().expect("a prepared receipt"));
            let (leaf, inode) = leaf_of(&receipt);
            let launcher = receipt["lifetime"]["native"]["details"]["launcher_pid"]
                .as_i64()
                .unwrap() as i32;
            assert_eq!(members(&leaf), vec![launcher]);
            std::fs::write(destination.path.join("cgroup.procs"), launcher.to_string())
                .expect("the blocked launcher is moved out");
            if replace {
                std::fs::remove_dir(&leaf).expect("the emptied leaf is removed");
                std::fs::create_dir(&leaf).expect("a look-alike at the same path");
            }
            spawned
                .owner()
                .release(
                    &harness::gate::Release::Valid,
                    prepared["attempt_id"].as_str().unwrap(),
                    receipt["policy"]["digest"].as_str().unwrap(),
                )
                .expect("released");
            let run = spawned.wait().expect("the jail ends");
            assert_eq!(
                run.code(),
                Some(125),
                "{label}/{observe}: {}",
                run.stderr_text()
            );
            assert!(!marker.exists(), "{label}/{observe}: the target ran");
            validate(&run);
            let refused = run
                .receipt_phase("refused")
                .unwrap_or_else(|| panic!("{label}/{observe}: {}", run.stderr_text()));
            assert_unprotected(&refused);
            assert_eq!(refused["exec_observed"], false);
            assert_eq!(refused["outcome"]["kind"], "refused");
            assert!(
                refused["outcome"]["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("lost before release"),
                "{refused:#}"
            );
            assert_eq!(
                refused["lifetime"]["integrity"], "lost",
                "{label}/{observe}"
            );
            assert_eq!(refused["lifetime"]["tree_empty"], Value::Null);
            let reason = if replace {
                "identity_replaced"
            } else {
                "membership_escape"
            };
            assert!(
                lifetime_notes(&run)
                    .iter()
                    .any(|note| note["reason"] == reason),
                "{label}/{observe}: {:?}",
                lifetime_notes(&run)
            );
            // The moved launcher was ended through its pidfd.
            assert!(!populated(&destination.path), "{label}/{observe}");
            if replace {
                assert_ne!(std::fs::metadata(&leaf).unwrap().ino(), inode);
            } else {
                assert_eq!(std::fs::metadata(&leaf).unwrap().ino(), inode);
            }
            remove_cgroup(&leaf);
        }
    }
}

/// A13: an OOM kill in the leaf ends the whole tree at once, as for the
/// contained profiles. The allocation happens in a descendant; the target
/// itself only sleeps, so nothing but that forced stop ends it before the
/// wall, and the cause is the memory event, not the deadline.
#[test]
fn a13_an_oom_kill_in_the_leaf_ends_the_tree() {
    if !live() {
        return;
    }
    let (jail, _) = none_case("on");
    let code = "import os, time\n\
                if os.fork() == 0:\n\
                \x20   x = bytearray(512 * 1024 * 1024)\n\
                \x20   os._exit(0)\n\
                time.sleep(60)\n";
    let mut spawned = jail
        .args(["--limit", "mem=64MiB", "--limit", "wall=30s"])
        .gate()
        .receipt()
        .target([PYTHON, "-c", code])
        .spawn()
        .expect("the jail starts");
    let prepared = spawned.owner().await_prepared().expect("prepared");
    let receipt = common::checked_receipt(spawned.receipt_value().expect("a prepared receipt"));
    let (leaf, _) = leaf_of(&receipt);
    // memory.max bounds resident memory; the host has swap. Disable swap in
    // this leaf only, so the allocation deterministically reaches OOM.
    std::fs::write(leaf.join("memory.swap.max"), "0").unwrap();
    let started = Instant::now();
    spawned
        .owner()
        .release(
            &harness::gate::Release::Valid,
            prepared["attempt_id"].as_str().unwrap(),
            receipt["policy"]["digest"].as_str().unwrap(),
        )
        .expect("released");
    let run = spawned.wait().expect("the jail ends");
    validate(&run);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the tree ran on toward the wall after the OOM kill"
    );
    let settled = run
        .receipt_phase("settled")
        .unwrap_or_else(|| panic!("{}", run.stderr_text()));
    assert_unprotected(&settled);
    assert_eq!(settled["outcome"]["kind"], "signaled", "{settled:#}");
    assert_eq!(settled["outcome"]["signal"], libc::SIGKILL);
    assert_eq!(settled["outcome"]["cause"], "memory_oom");
    let mem = settled["applied"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == "mem")
        .unwrap();
    assert_eq!(mem["hit"], true);
}

// ===========================================================================
// §8.1: `enforced` is the phase after a confirmed exec
// ===========================================================================

/// Observation off, the target is this jail's own binary blocked on its
/// stdin, so its image never differs from the supervisor's and its exec is
/// never independently confirmed. It moves itself out of the leaf and is
/// killed by a signal. The run ends unsettled without a confirmed exec, so
/// every receipt it leaves, mid-run and final, is `prepared`, never
/// `enforced`, with the loss recorded.
#[test]
fn an_unconfirmed_target_that_escapes_and_is_killed_stays_prepared() {
    use std::process::{Command, Stdio};
    if !live() {
        return;
    }
    let validators = validators();
    let root = common::private_tempdir();
    for name in ["data", "config", "workspace"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
    }
    for name in ["data", "config"] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            root.path().join(name),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let destination = Destination::new("unconfirmed");
    let receipt_copy = root.path().join("receipt.json");
    let jail = harness::jail_path();
    let target: Vec<OsString> = vec![
        jail.clone().into_os_string(),
        "__launch".into(),
        "--release-fd".into(),
        "0".into(),
        "--error-fd".into(),
        "2".into(),
        "--".into(),
        "/bin/true".into(),
    ];
    let mut supervisor = Command::new(&jail)
        .args([
            "run",
            "--profile",
            "none",
            "--observe",
            "off",
            "--workspace",
        ])
        .arg(root.path().join("workspace"))
        .arg("--receipt")
        .arg(&receipt_copy)
        .arg("--")
        .args(&target)
        .env("OURO_DATA_DIR", root.path().join("data"))
        .env("OURO_CONFIG_DIR", root.path().join("config"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the jail starts");
    let current = || -> Value {
        std::fs::read_to_string(&receipt_copy)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Value::Null)
    };
    wait_for("a prepared receipt", || current()["phase"] == "prepared");
    let prepared = current();
    let (leaf, _) = leaf_of(&prepared);
    let pid = prepared["lifetime"]["native"]["details"]["launcher_pid"]
        .as_i64()
        .unwrap() as i32;
    let expected: Vec<Vec<u8>> = target
        .iter()
        .map(|part| part.as_encoded_bytes().to_vec())
        .collect();
    wait_for("the target image", || {
        std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|raw| {
            raw.split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
                == expected
        })
    });
    let target_fd = identity::pidfd_open(pid).expect("the live target");
    std::fs::write(destination.path.join("cgroup.procs"), pid.to_string())
        .expect("the target is moved out");
    wait_for("the loss in the receipt", || {
        current()["lifetime"]["integrity"] == "lost"
    });
    let mid_run = current();
    validators["jail-receipt"]
        .validate(&mid_run)
        .unwrap_or_else(|error| panic!("{error}\n{mid_run:#}"));
    common::assert_semantic_receipt(&mid_run);
    assert_eq!(mid_run["phase"], "prepared", "{mid_run:#}");
    assert_eq!(mid_run["exec_observed"], false);

    identity::pidfd_send_signal(target_fd.as_raw_fd(), libc::SIGKILL).unwrap();
    drop(supervisor.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = supervisor.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the jail did not end");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.code(), Some(1));
    let last = current();
    validators["jail-receipt"]
        .validate(&last)
        .unwrap_or_else(|error| panic!("{error}\n{last:#}"));
    common::assert_semantic_receipt(&last);
    assert_unprotected(&last);
    assert_eq!(last["phase"], "prepared", "{last:#}");
    assert_eq!(last["exec_observed"], false);
    assert_eq!(last["outcome"]["kind"], "unknown");
    assert_eq!(last["lifetime"]["integrity"], "lost");
    assert_eq!(last["lifetime"]["tree_empty"], Value::Null);
    assert!(
        last["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["code"] == "tree_unknown")
    );
    remove_cgroup(&leaf);
}

// ===========================================================================
// The review's adversary
// ===========================================================================

/// The review's adversary (adv2.sh): the target ignores SIGTERM, creates two
/// cgroups of its own under the delegated service, forks a grandchild that
/// moves into one, moves itself into the other, and both stay alive. The
/// wall ends the run. The record is honest (lost, no tree result, never
/// settled, the target's forced end as its outcome) and both escapees die:
/// the target through its pidfd, the grandchild once the subreaper adopts it.
#[test]
fn adversary_target_and_grandchild_both_escape_alive() {
    if !live() {
        return;
    }
    for observe in ["off", "on"] {
        // The fixture makes these itself; the guards only remove them.
        let target_cgroup = ChildMade::new("adv-t");
        let grand_cgroup = ChildMade::new("adv-g");
        let (jail, _) = none_case(observe);
        let pids = jail.root().join("pids");
        let code = format!(
            "import os, time, signal, json\n\
             signal.signal(signal.SIGTERM, signal.SIG_IGN)\n\
             d1, d2 = {d1:?}, {d2:?}\n\
             for d in (d1, d2): os.mkdir(d)\n\
             r, w = os.pipe()\n\
             pid = os.fork()\n\
             if pid == 0:\n\
             \x20   null = os.open('/dev/null', os.O_RDWR)\n\
             \x20   for fd in (0, 1, 2): os.dup2(null, fd)\n\
             \x20   open(os.path.join(d2, 'cgroup.procs'), 'w').write('0')\n\
             \x20   os.write(w, b'g')\n\
             \x20   time.sleep(120)\n\
             \x20   os._exit(0)\n\
             os.read(r, 1)\n\
             open(os.path.join(d1, 'cgroup.procs'), 'w').write('0')\n\
             open({pids:?}, 'w').write(json.dumps({{'target': os.getpid(), 'grand': pid}}))\n\
             time.sleep(120)\n",
            d1 = target_cgroup.path.to_str().unwrap(),
            d2 = grand_cgroup.path.to_str().unwrap(),
            pids = pids.to_str().unwrap(),
        );
        let run = jail
            .args(["--limit", "wall=2s"])
            .target([PYTHON, "-c", &code])
            .run()
            .expect("the jail runs");
        validate(&run);
        assert_eq!(run.code(), Some(1), "{observe}: {}", run.stderr_text());
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&pids).unwrap()).unwrap();
        let receipt = last_receipt(&run);
        assert_lost(&receipt);
        assert_eq!(receipt["phase"], "enforced", "{observe}: {receipt:#}");
        assert_eq!(receipt["exec_observed"], true);
        assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
        assert_eq!(receipt["outcome"]["signal"], libc::SIGKILL);
        assert_eq!(receipt["outcome"]["cause"], "wall_expiry");
        assert!(run.receipt_phase("settled").is_none());
        let notes = lifetime_notes(&run);
        for subject in ["target", "descendant"] {
            assert!(
                notes
                    .iter()
                    .any(|note| note["subject"] == subject && note["reason"] == "membership_escape"),
                "{observe}: {subject}: {notes:?}"
            );
        }
        // Both escapees are dead, by the jail's hand, and the cgroups they
        // fled to are empty.
        for key in ["target", "grand"] {
            let pid = written[key].as_i64().unwrap();
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists()
                    || std::fs::read_to_string(format!("/proc/{pid}/stat"))
                        .is_ok_and(|stat| stat.contains(") Z")),
                "{observe}: the escaped {key} survived its attempt"
            );
        }
        assert!(!populated(&target_cgroup.path), "{observe}");
        assert!(!populated(&grand_cgroup.path), "{observe}");
        let (leaf, _) = leaf_of(&receipt);
        remove_cgroup(&leaf);
    }
}

/// A cgroup path under the delegated service that a fixture creates itself;
/// the guard only empties and removes it afterwards.
struct ChildMade {
    path: PathBuf,
}

impl ChildMade {
    fn new(tag: &str) -> ChildMade {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        // SAFETY: getuid takes no arguments and cannot fail.
        let root = cgroup::delegated_root(unsafe { libc::getuid() })
            .expect("the delegated subtree exists");
        ChildMade {
            path: root.join(format!(
                "ouro-j3none-{tag}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )),
        }
    }
}

impl Drop for ChildMade {
    fn drop(&mut self) {
        if self.path.exists() {
            if populated(&self.path) {
                let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
                let deadline = Instant::now() + Duration::from_secs(5);
                while populated(&self.path) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

/// The pid a fixture wrote to `path`, once the whole number is there.
///
/// Python's `open(p, 'w').write(s)` creates the file before it writes, so a
/// test that only waits for the file to exist can read it empty on a busy
/// host (seen once on the reference host, 2026-09-23).
fn written_pid(what: &str, path: &std::path::Path) -> i32 {
    let mut pid = None;
    wait_for(what, || {
        pid = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok());
        pid.is_some()
    });
    pid.expect("wait_for returns only once the pid parsed")
}
