#![cfg(target_os = "linux")]
//! The first executable slice, end to end on a provisioned Linux host.
//!
//! jail-v1 §1.1: policy resolution, capability probes, observer attach,
//! prepared receipt, release, command, tree termination, settled receipt.
//! Each test is named after the acceptance row it covers and asserts the
//! fixture's own syscall results, the audit events, all three receipt phases
//! against the checked-in schema, the exit status and tree emptiness.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use jsonschema::{Registry, Resource, Validator};
use serde_json::Value;

use ouro_fixture::harness::gate::{ExpectedPlan, GateOwner, Release};
use ouro_fixture::harness::{self, Jail, Run};

// ---------------------------------------------------------------------------
// Fixtures shared by every test
// ---------------------------------------------------------------------------

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

/// One validator per checked-in schema, registered by `$id` so that the jail
/// producer schema can `$ref` the shared envelope.
fn validators() -> BTreeMap<String, Validator> {
    let mut schemas: BTreeMap<String, Value> = BTreeMap::new();
    for entry in std::fs::read_dir(specs_dir()).expect("the specification directory is readable") {
        let path = entry.expect("a directory entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(".schema.json") {
            let text = std::fs::read_to_string(&path).expect("a readable schema");
            schemas.insert(
                stem.to_owned(),
                serde_json::from_str(&text).expect("valid JSON"),
            );
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
        .expect("valid schema identifiers")
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

mod common;
use common::live;

/// A workspace with the conformance fixture copied inside it.
///
/// The fixture runs inside the jail, where only the declared roots exist, so
/// the binary has to be inside one of them. The workspace is the writable
/// root, and the copy keeps its host path, which is where it is bind-mounted.
fn workspace_with_fixture(root: &Path) -> (PathBuf, PathBuf) {
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace is created");
    let inside = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &inside).expect("the fixture is copied in");
    let mut permissions = std::fs::metadata(&inside).expect("metadata").permissions();
    use std::os::unix::fs::PermissionsExt as _;
    permissions.set_mode(0o755);
    std::fs::set_permissions(&inside, permissions).expect("the fixture is executable");
    (workspace, inside)
}

/// A jail invocation over a workspace holding the fixture.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
}

fn case() -> Case {
    let jail = Jail::new().expect("a private jail harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let jail = jail
        .arg("run")
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

// ---------------------------------------------------------------------------
// Assertions over one run
// ---------------------------------------------------------------------------

/// Every receipt the run produced, from the trace's `jail.receipt` notes and
/// from `jail.json`, each validated against the checked-in schema.
struct Receipts {
    by_phase: BTreeMap<String, Value>,
    phases_seen: Vec<String>,
}

fn receipts_of(run: &Run, validators: &BTreeMap<String, Validator>) -> Receipts {
    let receipt_schema = &validators["jail-receipt"];
    let event_schema = &validators["jail-event"];
    let mut by_phase = BTreeMap::new();
    for receipt in run.receipts() {
        receipt_schema
            .validate(&receipt)
            .unwrap_or_else(|error| panic!("a receipt fails its schema: {error}\n{receipt:#}"));
        let phase = receipt
            .get("phase")
            .and_then(Value::as_str)
            .expect("every receipt names its phase")
            .to_owned();
        by_phase.insert(phase, receipt);
    }
    let mut phases_seen = Vec::new();
    for event in run.trace_events() {
        event_schema
            .validate(event)
            .unwrap_or_else(|error| panic!("an event fails its schema: {error}\n{event:#}"));
        if event.get("operation").and_then(Value::as_str) == Some("jail.receipt")
            && let Some(phase) = event.pointer("/fields/phase").and_then(Value::as_str)
        {
            phases_seen.push(phase.to_owned());
        }
    }
    Receipts {
        by_phase,
        phases_seen,
    }
}

impl Receipts {
    fn phase(&self, phase: &str) -> &Value {
        self.by_phase
            .get(phase)
            .unwrap_or_else(|| panic!("no {phase} receipt; saw {:?}", self.by_phase.keys()))
    }

    /// The receipt of the latest phase this attempt reached.
    fn last(&self) -> Option<&Value> {
        for phase in ["settled", "enforced", "refused", "prepared"] {
            if let Some(receipt) = self.by_phase.get(phase) {
                return Some(receipt);
            }
        }
        None
    }

    fn saw(&self, phase: &str) -> bool {
        self.phases_seen.iter().any(|item| item == phase)
    }
}

/// The audit events of the run, in order.
fn audit_events(run: &Run) -> Vec<&Value> {
    run.trace_events()
        .iter()
        .filter(|event| event.get("source").and_then(Value::as_str) == Some("audit"))
        .collect()
}

fn operations(run: &Run) -> Vec<String> {
    audit_events(run)
        .iter()
        .filter_map(|event| event.get("operation").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

/// The fixture's own report for one operation name.
fn fixture_op(run: &Run, op: &str) -> Value {
    run.fixture_lines()
        .into_iter()
        .find(|line| line.get("op").and_then(Value::as_str) == Some(op))
        .unwrap_or_else(|| panic!("the fixture never reported {op}: {}", run.stdout_text()))
}

fn field<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value
        .pointer(pointer)
        .unwrap_or_else(|| panic!("{pointer} is absent from {value:#}"))
}

// ===========================================================================
// §1.1: the first executable slice
// ===========================================================================

#[test]
fn s11_allowed_write() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let target = case.workspace.join("allowed.txt");
    let run = case
        .jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("open"),
            target.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .run()
        .expect("the jail runs");

    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    // The fixture's own syscall result.
    let report = fixture_op(&run, "openat");
    assert!(
        field(&report, "/ret").as_i64().unwrap_or(-1) >= 0,
        "the open failed: {report}"
    );
    assert!(target.is_file(), "the file is not on the host");

    // Exactly one fs.create naming the path relative to the workspace.
    let events = audit_events(&run);
    let creates: Vec<&&Value> = events
        .iter()
        .filter(|event| event.get("operation").and_then(Value::as_str) == Some("fs.create"))
        .collect();
    assert_eq!(creates.len(), 1, "operations: {:?}", operations(&run));
    let create = creates[0];
    assert_eq!(field(create, "/fields/path/kind"), "workspace_relative");
    assert_eq!(field(create, "/fields/path/value"), "allowed.txt");
    assert_eq!(field(create, "/fields/path_basis"), "argument_snapshot");
    assert_eq!(field(create, "/fields/path_complete"), true);
    assert_eq!(field(create, "/outcome/ok"), true);

    let receipts = receipts_of(&run, &validators);
    assert!(receipts.saw("prepared"), "no prepared receipt note");
    assert!(receipts.saw("enforced"), "no enforced receipt note");
    let settled = receipts.phase("settled");
    assert_eq!(field(settled, "/containment"), "enforced");
    assert_eq!(field(settled, "/child_protection"), "enforced");
    assert_eq!(field(settled, "/exec_observed"), true);
    assert_eq!(field(settled, "/observer/backend"), "ptrace");
    assert_eq!(field(settled, "/observer/set"), "linux-closed-v1");
    assert_eq!(field(settled, "/observer/attached"), true);
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);
    assert_eq!(field(settled, "/lifetime/boundary"), "pid_namespace");
    assert_eq!(
        field(settled, "/lifetime/verification_scope"),
        "attempt_tree"
    );
    assert_eq!(field(settled, "/outcome/kind"), "exited");
    assert_eq!(field(settled, "/outcome/code"), 0);
    assert_eq!(field(settled, "/jail/backend"), "bubblewrap");
    assert_eq!(field(settled, "/applied/syscalls/mechanism"), "seccomp-bpf");
    assert_eq!(
        field(settled, "/applied/network/mechanism"),
        "network-namespace"
    );
    assert_eq!(
        field(settled, "/applied/filesystem/mechanism"),
        "bubblewrap-binds"
    );
    // Two filters are in force and the receipt names both: the baseline
    // bubblewrap loaded, and the observer's narrowing filter the launcher
    // installed, each by the digest it reports for itself.
    assert_eq!(
        field(settled, "/applied/syscalls/digest"),
        &Value::from(
            ouro_jail::platform::linux::seccomp::tool_baseline()
                .expect("the baseline assembles")
                .digest()
        )
    );
    assert_eq!(
        field(settled, "/lifetime/native/details/narrowing_filter_digest"),
        &Value::from(ouro_jail::platform::linux::tracer::narrowing_filter_digest())
    );
}

#[test]
fn s11_protected_access_fails() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    std::fs::create_dir_all(case.workspace.join(".git")).expect("a repository in the workspace");
    std::fs::write(case.workspace.join(".git/config"), b"[core]\n").expect("a git file");
    let denied = case.workspace.join(".git/x");

    let run = case
        .jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("open"),
            denied.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
            OsStr::new("--expect"),
            OsStr::new("EROFS"),
        ])
        .run()
        .expect("the jail runs");

    assert_eq!(
        run.code(),
        Some(0),
        "the expectation held: {}",
        run.stderr_text()
    );
    let report = fixture_op(&run, "openat");
    assert_eq!(field(&report, "/errno"), "EROFS");
    assert!(!denied.exists(), "the protected write left a file behind");

    // §11.2: EROFS stays a failed result of the original operation. It is not
    // a `fs.deny`, which is reserved for EACCES and EPERM.
    let ops = operations(&run);
    assert!(
        !ops.iter().any(|op| op == "fs.deny"),
        "EROFS must not be reported as a denial: {ops:?}"
    );
    let create = audit_events(&run)
        .into_iter()
        .find(|event| event.get("operation").and_then(Value::as_str) == Some("fs.create"))
        .unwrap_or_else(|| panic!("no fs.create for the refused open: {ops:?}"));
    assert_eq!(field(create, "/outcome/ok"), false);
    assert_eq!(field(create, "/outcome/errno"), "EROFS");
    assert_eq!(field(create, "/fields/path/kind"), "workspace_relative");
    assert_eq!(field(create, "/fields/path/value"), ".git/x");

    let receipts = receipts_of(&run, &validators);
    let settled = receipts.phase("settled");
    assert_eq!(field(settled, "/containment"), "enforced");
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);
    assert_eq!(
        field(settled, "/applied/filesystem/protected_coverage"),
        "existing_and_root"
    );
}

#[test]
fn s11_exec_descendant() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let run = case
        .jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("exec"),
            OsStr::new("--"),
            OsStr::new("/usr/bin/true"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());

    let ops = operations(&run);
    let execs = ops.iter().filter(|op| *op == "proc.exec").count();
    let exits = ops.iter().filter(|op| *op == "proc.exit").count();
    assert_eq!(execs, 2, "the fixture and its child each exec: {ops:?}");
    assert_eq!(exits, 2, "both processes end: {ops:?}");
    for event in audit_events(&run) {
        if event.get("operation").and_then(Value::as_str) == Some("proc.exec") {
            assert_eq!(field(event, "/outcome/completion"), "exec_transition");
            // The observer witnessed the entry, so the transition names the
            // image it established. A transition with no path is one whose
            // entry was not seen, and exec confirmation refuses to use it.
            assert_eq!(field(event, "/fields/path_basis"), "argument_snapshot");
            assert_ne!(
                field(event, "/fields/path/kind"),
                "unavailable",
                "an exec transition with no witnessed image: {event:#}"
            );
        }
    }

    let receipts = receipts_of(&run, &validators);
    let settled = receipts.phase("settled");
    // §11.4: the exec class counts proc.exec and proc.exit results.
    assert_eq!(
        field(settled, "/coverage/exec/observed_count")
            .as_u64()
            .unwrap_or(0),
        u64::try_from(execs + exits).unwrap_or(0)
    );
    assert_eq!(field(settled, "/coverage/exec/status"), "active");
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);
}

#[test]
fn s11_wall_expiry_separate_run() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let run = case
        .jail
        .args(["--limit", "wall=500ms"])
        .target([
            case.fixture.as_os_str(),
            OsStr::new("sleep"),
            OsStr::new("5000"),
        ])
        .run()
        .expect("the jail runs");

    let receipts = receipts_of(&run, &validators);
    let settled = receipts.phase("settled");
    assert_eq!(field(settled, "/outcome/kind"), "signaled");
    assert_eq!(field(settled, "/outcome/cause"), "wall_expiry");
    // §9.3: the stop is cooperative first. Measured on this host, a SIGTERM
    // to the outer bubblewrap never reaches the target, so this signal number
    // is the evidence that the supervisor signalled the target's own host pid:
    // a stop that skipped that step would end in the forced SIGKILL below
    // instead.
    let signal = field(settled, "/outcome/signal").as_i64().unwrap_or(0);
    assert_eq!(
        signal,
        i64::from(libc::SIGTERM),
        "the target did not die of the cooperative stop"
    );
    assert_eq!(run.code(), Some(128 + i32::try_from(signal).unwrap_or(0)));
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);

    let wall = field(settled, "/applied/limits")
        .as_array()
        .expect("a limits table")
        .iter()
        .find(|limit| limit.get("key").and_then(Value::as_str) == Some("wall"))
        .expect("the wall is in the limits table")
        .clone();
    assert_eq!(field(&wall, "/applied"), true);
    assert_eq!(field(&wall, "/mechanism"), "boottime-deadline");
    assert_eq!(field(&wall, "/scope"), "tree");
    assert_eq!(field(&wall, "/hit"), true);
    // §11.4: the limits class counts ceilings whose hit became proven true.
    assert_eq!(
        field(settled, "/coverage/limits/observed_count")
            .as_u64()
            .unwrap_or(0),
        1
    );

    // §6.4: a preferred ceiling with no mechanism is recorded requested and
    // unapplied rather than refusing the run.
    let pids = field(settled, "/applied/limits")
        .as_array()
        .expect("a limits table")
        .iter()
        .find(|limit| limit.get("key").and_then(Value::as_str) == Some("pids"))
        .expect("the preferred pids ceiling is listed")
        .clone();
    assert_eq!(field(&pids, "/required"), false);
    let available = ouro_jail::platform::linux::probe::run_one(
        "cgroup_pids",
        &harness::jail_path(),
        Path::new("bwrap"),
    )
    .status
        == ouro_jail::platform::linux::probe::ProbeStatus::Available;
    assert_eq!(field(&pids, "/applied"), available);
    if available {
        assert_eq!(field(&pids, "/mechanism"), "pids.max");
        assert_eq!(field(&pids, "/hit"), false);
    } else {
        assert_eq!(field(&pids, "/mechanism"), &Value::Null);
        assert_eq!(field(&pids, "/hit"), &Value::Null);
    }
}

#[test]
fn s11_observe_off() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let target = case.workspace.join("allowed.txt");
    // Keep the image alive long enough for the observation-off backend to
    // independently read back the exec transition. A fast exit may honestly
    // remain unknown when no tracer witnesses it.
    let script = case.workspace.join("observe-off.json");
    std::fs::write(
        &script,
        serde_json::to_vec(&serde_json::json!([
            ["open", target.to_str().unwrap(), "--create", "--write"],
            ["sleep", "200"]
        ]))
        .unwrap(),
    )
    .unwrap();
    let run = case
        .jail
        .args(["--observe", "off"])
        .target([
            case.fixture.as_os_str(),
            OsStr::new("script"),
            script.as_os_str(),
        ])
        .run()
        .expect("the jail runs");

    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    assert!(target.is_file());
    assert!(
        audit_events(&run).is_empty(),
        "observation off emits no audit source: {:?}",
        operations(&run)
    );

    let receipts = receipts_of(&run, &validators);
    let settled = receipts.phase("settled");
    assert_eq!(field(settled, "/observer/backend"), &Value::Null);
    assert_eq!(field(settled, "/observer/attached"), false);
    // No observer, so no narrowing filter was installed and the receipt says
    // so rather than naming one.
    assert_eq!(
        field(settled, "/lifetime/native/details/narrowing_filter_digest"),
        &Value::Null
    );
    assert_eq!(field(settled, "/containment"), "enforced");
    assert_eq!(field(settled, "/exec_observed"), true);
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = field(settled, &format!("/coverage/{class}"));
        assert_eq!(field(entry, "/status"), "unsupported", "class {class}");
        assert_eq!(
            field(entry, "/observed_count"),
            &Value::Null,
            "class {class}"
        );
        assert_eq!(
            field(entry, "/sources").as_array().map(Vec::len),
            Some(0),
            "class {class}"
        );
    }
}

/// The x86_64 syscall numbers this kernel's headers declare.
fn kernel_syscall_numbers() -> BTreeMap<String, u32> {
    const HEADER: &str = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h";
    let raw = std::fs::read_to_string(HEADER).unwrap_or_else(|error| {
        panic!("{HEADER}: {error}; install libc6-dev so the closed set can be checked")
    });
    let mut table = BTreeMap::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("#define __NR_") {
            let mut parts = rest.split_ascii_whitespace();
            if let (Some(name), Some(number)) = (parts.next(), parts.next())
                && let Ok(number) = number.parse::<u32>()
            {
                table.insert(name.to_owned(), number);
            }
        }
    }
    table
}

/// Whether the observer's narrowing filter actually traces this syscall.
///
/// Read from the filter that is installed rather than from a restatement of
/// the closed set, so a test's expectation follows the set as it grows
/// instead of pinning a number that will change under it.
fn closed_set_traces(name: &str) -> bool {
    let Some(number) = kernel_syscall_numbers().get(name).copied() else {
        panic!("{name} is not in this kernel's syscall table");
    };
    ouro_jail::platform::linux::tracer::narrowing_filter()
        .iter()
        .any(|insn| insn.code == 0x15 && insn.k == number)
}

/// Audit events whose recorded path is this workspace-relative name.
fn events_for_path<'a>(run: &'a Run, relative: &str) -> Vec<&'a Value> {
    audit_events(run)
        .into_iter()
        .filter(|event| {
            event.pointer("/fields/path/kind").and_then(Value::as_str) == Some("workspace_relative")
                && event.pointer("/fields/path/value").and_then(Value::as_str) == Some(relative)
        })
        .collect()
}

#[test]
fn s11_mknod_is_one_fs_create() {
    if !live() {
        return;
    }
    let case = case();
    let node = case.workspace.join("fifo");
    let run = case
        .jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("mknod"),
            node.as_os_str(),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());

    // The fixture's own result first: a FIFO is the one node an unprivileged
    // user may create, and it is on the host afterwards.
    let report = fixture_op(&run, "mknodat");
    assert_eq!(field(&report, "/ret"), 0, "{report:#}");
    let kind = std::fs::metadata(&node)
        .expect("the node is on the host")
        .file_type();
    use std::os::unix::fs::FileTypeExt as _;
    assert!(
        kind.is_fifo(),
        "the fixture made something other than a FIFO"
    );

    // §11.2 revision 8 put `mknod`/`mknodat` in the closed set, and the
    // filter that is installed is what settles it.
    assert!(
        closed_set_traces("mknodat"),
        "the narrowing filter no longer traces mknodat"
    );
    let named = events_for_path(&run, "fifo");
    assert_eq!(
        named.len(),
        1,
        "a traced operation owes exactly one event: {:?}",
        operations(&run)
    );
    assert_eq!(field(named[0], "/operation"), "fs.create");
    assert_eq!(field(named[0], "/fields/syscall"), "mknodat");
    assert_eq!(field(named[0], "/fields/path/kind"), "workspace_relative");
    assert_eq!(field(named[0], "/fields/path_basis"), "argument_snapshot");
    assert_eq!(field(named[0], "/outcome/ok"), true);
}

#[test]
fn s11_truncate_is_one_fs_write_that_says_it_truncated() {
    if !live() {
        return;
    }
    let case = case();
    let file = case.workspace.join("shrink.txt");
    std::fs::write(&file, vec![b'x'; 4096]).expect("a file to shorten");
    let run = case
        .jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("truncate"),
            file.as_os_str(),
            OsStr::new("0"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());

    let report = fixture_op(&run, "truncate");
    assert_eq!(field(&report, "/ret"), 0, "{report:#}");
    assert_eq!(
        std::fs::metadata(&file)
            .expect("the file is still there")
            .len(),
        0,
        "the truncate did not take effect on the host"
    );

    assert!(
        closed_set_traces("truncate"),
        "the narrowing filter no longer traces truncate"
    );
    let named = events_for_path(&run, "shrink.txt");
    assert_eq!(
        named.len(),
        1,
        "a traced operation owes exactly one event: {:?}",
        operations(&run)
    );
    assert_eq!(field(named[0], "/operation"), "fs.write");
    assert_eq!(field(named[0], "/fields/syscall"), "truncate");
    // §11.2: an `fs.write` always carries its precise action, and a
    // truncation is not an open.
    assert_eq!(field(named[0], "/fields/action"), "truncated");
    assert_eq!(field(named[0], "/outcome/ok"), true);
}

#[test]
fn s11_ftruncate_names_no_path_and_is_not_covered() {
    if !live() {
        return;
    }
    let case = case();
    let file = case.workspace.join("by-descriptor.txt");
    std::fs::write(&file, vec![b'x'; 4096]).expect("a file to shorten");
    let run = case
        .jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("ftruncate"),
            file.as_os_str(),
            OsStr::new("0"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());

    // The fixture reports both halves: the open that names a path, and the
    // descriptor-based mutation that does not.
    let opened = fixture_op(&run, "openat");
    assert!(
        field(&opened, "/ret").as_i64().unwrap_or(-1) >= 0,
        "{opened:#}"
    );
    let shortened = fixture_op(&run, "ftruncate");
    assert_eq!(field(&shortened, "/ret"), 0, "{shortened:#}");
    assert_eq!(field(&shortened, "/args/path_named_to_the_kernel"), false);
    assert_eq!(
        std::fs::metadata(&file)
            .expect("the file is still there")
            .len(),
        0,
        "the ftruncate did not take effect on the host"
    );

    // §11.2 observes the calls that name a path. The open is one of them; the
    // mutation through the descriptor is not, and no event pretends otherwise.
    // This is the permanent half of the contrast: `truncate` may join the
    // closed set, `ftruncate` cannot, because it never names the object.
    assert!(
        !closed_set_traces("ftruncate"),
        "ftruncate names a descriptor, not a path; it cannot be in the closed set"
    );
    let named = events_for_path(&run, "by-descriptor.txt");
    assert_eq!(
        named.len(),
        1,
        "the open names the path exactly once: {:?}",
        operations(&run)
    );
    assert_eq!(field(named[0], "/operation"), "fs.write");
    assert_eq!(field(named[0], "/fields/syscall"), "openat");
    assert_eq!(field(named[0], "/fields/action"), "opened_for_mutation");
    for event in audit_events(&run) {
        assert_ne!(
            event.pointer("/fields/syscall").and_then(Value::as_str),
            Some("ftruncate"),
            "a descriptor-based mutation was reported as an observed operation"
        );
    }
}

/// Two hundred `openat` calls whose pathname argument points at a page with
/// no access at all.
///
/// The observer cannot read the argument and the kernel rejects the call for
/// the same reason, so there is no result to lose. §11.4 counts a hole only
/// where a result went missing; if a tracee could manufacture loss by passing
/// pointers that cannot work, strict evidence mode would be a denial of
/// service against its own supervisor.
const UNREADABLE_PATH_FIXTURE: &str = r#"
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.syscall.restype = ctypes.c_long
PROT_NONE = 0
MAP_PRIVATE_ANON = 0x22
page = libc.mmap(None, 4096, PROT_NONE, MAP_PRIVATE_ANON, -1, 0)
assert page not in (None, -1, ctypes.c_void_p(-1).value), "the page was not mapped"
AT_FDCWD = -100
NR_OPENAT = 257
faults = 0
other = 0
for _ in range(200):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(NR_OPENAT), ctypes.c_long(AT_FDCWD),
                     ctypes.c_void_p(page), ctypes.c_long(0o101), ctypes.c_long(0o600))
    if r < 0 and ctypes.get_errno() == errno.EFAULT:
        faults += 1
    else:
        other += 1
        if r >= 0:
            os.close(r)
print("faults=%d" % faults)
print("other=%d" % other)
"#;

#[test]
fn o03_an_unreadable_argument_is_not_a_hole_in_coverage() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let run = case
        .jail
        .args(["--evidence", "strict"])
        .target([
            OsStr::new("/usr/bin/python3"),
            OsStr::new("-c"),
            OsStr::new(UNREADABLE_PATH_FIXTURE),
        ])
        .run()
        .expect("the jail runs");

    // The fixture really made the calls, and the kernel really refused them.
    assert!(
        run.stdout_text().contains("faults=200"),
        "the fixture did not make 200 refused calls: {}",
        run.stdout_text()
    );
    assert!(
        run.stdout_text().contains("other=0"),
        "{}",
        run.stdout_text()
    );

    // Strict evidence did not stop the attempt, and nothing claimed a loss.
    assert_eq!(
        run.code(),
        Some(0),
        "strict evidence stopped a run that lost nothing: {}",
        run.stderr_text()
    );
    let receipts = receipts_of(&run, &validators);
    let settled = receipts.phase("settled");
    assert_eq!(field(settled, "/outcome/kind"), "exited");
    assert_eq!(field(settled, "/outcome/code"), 0);
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);
    assert_eq!(
        field(settled, "/observer/gaps").as_array().map(Vec::len),
        Some(0),
        "an unreadable argument was recorded as a gap"
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        assert_eq!(
            field(field(settled, &format!("/coverage/{class}")), "/status"),
            "active",
            "class {class} was degraded by a call that had nothing to observe"
        );
    }
    for error in settled
        .get("errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        assert_ne!(
            error.get("code").and_then(Value::as_str),
            Some("evidence_lost"),
            "{error:#}"
        );
    }
    assert!(
        !run.trace_events().iter().any(|event| {
            event.pointer("/fields/kind").and_then(Value::as_str) == Some("coverage_gap")
        }),
        "a coverage gap was written for a call that lost no result"
    );
}

#[test]
fn o02_a_thread_is_not_a_process() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let run = case
        .jail
        .target([case.fixture.as_os_str(), OsStr::new("thread")])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());

    // The fixture really started and joined a thread.
    let report = fixture_op(&run, "thread");
    assert_eq!(field(&report, "/ret"), 0, "{report:#}");

    // §11.2: one exec transition and one thread-group death. A worker thread
    // is neither a process that execs nor a process that exits, and the
    // observer's fork bookkeeping never becomes a public event.
    let ops = operations(&run);
    assert_eq!(
        ops.iter().filter(|op| *op == "proc.exec").count(),
        1,
        "{ops:?}"
    );
    assert_eq!(
        ops.iter().filter(|op| *op == "proc.exit").count(),
        1,
        "a thread was counted as a process ending: {ops:?}"
    );
    let receipts = receipts_of(&run, &validators);
    assert_eq!(
        field(receipts.phase("settled"), "/coverage/exec/observed_count")
            .as_u64()
            .unwrap_or(0),
        2
    );
}

// ===========================================================================
// Execution surface
// ===========================================================================

#[test]
fn x01_literal_argv() {
    if !live() {
        return;
    }
    let case = case();
    let awkward: Vec<OsString> = vec![
        OsString::from("plain"),
        OsString::from("two words"),
        OsString::from("quo'te\"s"),
        OsString::from("new\nline"),
        OsString::from("$HOME `id` ; rm -rf / | cat & echo"),
        OsString::from("tab\there"),
        OsString::from_vec(b"non\xffutf8".to_vec()),
    ];
    let mut argv: Vec<OsString> = vec![
        case.fixture.clone().into_os_string(),
        OsString::from("echo-args"),
    ];
    argv.extend(awkward.iter().cloned());
    let run = case.jail.target(argv).run().expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());

    let report = fixture_op(&run, "echo-args");
    let seen = field(&report, "/args/argv")
        .as_array()
        .expect("the fixture reports its argv")
        .clone();
    // `echo-args` reports the trailing arguments, which are the ones under
    // test.
    assert_eq!(seen.len(), awkward.len(), "{report:#}");
    for (index, expected) in awkward.iter().enumerate() {
        let entry = &seen[index];
        let bytes = decode_argument(entry);
        assert_eq!(
            bytes,
            expected.as_bytes(),
            "argument {index} arrived as {entry:?}"
        );
    }
}

/// The fixture reports each argument as its exact bytes, so the comparison
/// is over bytes and never over a lossy rendering.
fn decode_argument(entry: &Value) -> Vec<u8> {
    let bytes = entry
        .get("bytes")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("an argument arrived as {entry:?}"));
    bytes
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().unwrap_or(256)).expect("a byte value"))
        .collect()
}

#[test]
fn x05_streams() {
    if !live() {
        return;
    }
    const COUNT: u64 = 300_000;
    for stream in ["stdout-bytes", "stderr-bytes"] {
        let case = case();
        let run = case
            .jail
            .target([
                case.fixture.as_os_str(),
                OsStr::new(stream),
                OsStr::new(&COUNT.to_string()),
                OsStr::new("--no-report"),
            ])
            .run()
            .expect("the jail runs");
        assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
        let bytes = if stream == "stdout-bytes" {
            &run.stdout
        } else {
            &run.stderr
        };
        // Byte-exact against the same pattern run outside the jail.
        let direct = std::process::Command::new(harness::fixture_path())
            .args([stream, &COUNT.to_string(), "--no-report"])
            .output()
            .expect("the fixture runs directly");
        let expected = if stream == "stdout-bytes" {
            direct.stdout
        } else {
            direct.stderr
        };
        assert_eq!(
            expected.len(),
            usize::try_from(COUNT).unwrap_or(0),
            "the fixture itself did not produce {COUNT} bytes"
        );
        assert_eq!(bytes, &expected, "{stream} differs from direct execution");
        // Nothing from the control or trace channels leaked into either.
        for stream_bytes in [&run.stdout, &run.stderr] {
            assert!(
                !stream_bytes
                    .windows(12)
                    .any(|window| window == b"ouro.event/1"),
                "trace frames leaked into a standard stream"
            );
            assert!(
                !stream_bytes
                    .windows(19)
                    .any(|window| window == b"ouro.jail.control/1"),
                "control frames leaked into a standard stream"
            );
        }
    }
}

#[test]
fn x06_no_private_authority() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let script = case.workspace.join("script.json");
    std::fs::write(&script, br#"[["fds"],["status"],["env"]]"#).expect("the script is written");
    let run = case
        .jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("script"),
            script.as_os_str(),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());

    let fds = fixture_op(&run, "fds");
    let numbers: Vec<i64> = field(&fds, "/args/fds")
        .as_array()
        .expect("the fixture lists its descriptors")
        .iter()
        .filter_map(|entry| entry.get("fd").and_then(Value::as_i64))
        .collect();
    assert_eq!(
        numbers,
        vec![0, 1, 2],
        "the target inherited more than validated stdio: {fds:#}"
    );

    let status = fixture_op(&run, "status");
    assert_eq!(field(&status, "/args/fields/NoNewPrivs"), "1");
    assert_eq!(field(&status, "/args/fields/Seccomp"), "2");
    assert_eq!(
        field(&status, "/args/fields/TracerPid"),
        "0",
        "the target must not see the observer as its tracer"
    );
    let cap_eff = field(&status, "/args/fields/CapEff")
        .as_str()
        .expect("CapEff is reported");
    assert!(
        cap_eff.chars().all(|character| character == '0'),
        "the target holds capabilities: {cap_eff}"
    );

    let env = fixture_op(&run, "env");
    let names: Vec<String> = field(&env, "/args/names")
        .as_array()
        .expect("the fixture lists environment names")
        .iter()
        .filter_map(|entry| entry.as_str().map(ToOwned::to_owned))
        .collect();
    let receipts = receipts_of(&run, &validators);
    let settled = receipts.phase("settled");
    let recorded: Vec<String> = field(settled, "/applied/environment_names")
        .as_array()
        .expect("the receipt lists environment names")
        .iter()
        .filter_map(|entry| entry.as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        names, recorded,
        "the receipt's environment names are not the ones the target has"
    );
    assert!(
        names.iter().any(|name| name == "PWD"),
        "bubblewrap sets PWD under --chdir and the receipt says so: {names:?}"
    );
    assert!(names.iter().any(|name| name == "TMPDIR"));
    for forbidden in ["OURO_DATA_DIR", "OURO_CONFIG_DIR"] {
        assert!(
            !names.iter().any(|name| name == forbidden),
            "{forbidden} reached the target"
        );
    }
}

#[test]
fn x07_background_descendant_is_terminated() {
    if !live() {
        return;
    }
    let validators = validators();
    // Both termination paths: with the observer attached and without it.
    //
    // This proves the descendant does not outlive settlement. It does not
    // isolate WHICH mechanism ended it: the tracer's PTRACE_O_EXITKILL,
    // bubblewrap's parent-death chain through the pid namespace, and this
    // code's own kill of the namespace init are all in force, and any of them
    // is sufficient. A mutation that made `wait_tree` claim emptiness without
    // verifying it still passes here for exactly that reason.
    for observe in [None, Some("off")] {
        x07_case(&validators, observe);
    }
}

fn x07_case(validators: &BTreeMap<String, Validator>, observe: Option<&str>) {
    let case = case();
    // The descendant proves whether it is still alive by writing a marker two
    // seconds after the target has already exited. Tree termination happens
    // long before that, so the marker's absence is the observation; asserting
    // `tree_empty` alone would accept a receipt that simply claimed it.
    let survived = case.workspace.join("descendant-survived");
    let script = format!("sleep 2; : > {}", survived.display());
    let mut jail = case.jail;
    if let Some(mode) = observe {
        jail = jail.args(["--observe", mode]);
    }
    let run = jail
        .target([
            case.fixture.as_os_str(),
            OsStr::new("background"),
            OsStr::new("5000"),
            OsStr::new("--"),
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new(&script),
        ])
        .run()
        .expect("the jail runs");

    let receipts = receipts_of(&run, validators);
    let settled = receipts.phase("settled");
    // The target's own outcome is preserved; the descendant does not become it.
    if observe == Some("off") && field(settled, "/exec_observed") == false {
        // This short-lived target can exit before image read-back. Boundary
        // death is still provable; target exec must not be invented from it.
        assert_eq!(field(settled, "/outcome/kind"), "unknown");
        assert_eq!(field(settled, "/outcome/code"), &Value::Null);
        assert_eq!(run.code(), Some(1));
    } else {
        assert_eq!(field(settled, "/outcome/kind"), "exited");
        assert_eq!(field(settled, "/outcome/code"), 0);
        assert_eq!(run.code(), Some(0));
    }
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);
    assert_eq!(field(settled, "/lifetime/integrity"), "verified");
    assert_eq!(
        field(settled, "/lifetime/verification_scope"),
        "attempt_tree"
    );
    // Give the descendant more than its own delay to show itself.
    std::thread::sleep(std::time::Duration::from_millis(3500));
    assert!(
        !survived.exists(),
        "the background descendant outlived settlement and wrote {}",
        survived.display()
    );

    // And the namespace itself is gone, so nothing of the tree can remain.
    let init = field(settled, "/lifetime/native/details/namespace_init_pid")
        .as_i64()
        .expect("the namespace init pid is recorded");
    assert!(
        !Path::new(&format!("/proc/{init}")).exists(),
        "the namespace init is still alive"
    );
}

#[test]
fn l01_a_target_that_ignores_the_cooperative_stop_dies_of_the_forced_one() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    // The other half of the stop sequence: this target sets SIGTERM to
    // SIG_IGN, so the cooperative signal arrives and does nothing, and only
    // the forced kill of the namespace init ends it. Together with the wall
    // test — where the same deadline produces SIGTERM — this shows the two
    // steps happen in that order and that the grace is real.
    let run = case
        .jail
        .args(["--limit", "wall=500ms"])
        .target([
            case.fixture.as_os_str(),
            OsStr::new("ignore-term"),
            OsStr::new("30000"),
        ])
        .run()
        .expect("the jail runs");

    let receipts = receipts_of(&run, &validators);
    let settled = receipts.phase("settled");
    assert_eq!(field(settled, "/outcome/kind"), "signaled");
    assert_eq!(field(settled, "/outcome/cause"), "wall_expiry");
    assert_eq!(
        field(settled, "/outcome/signal"),
        i64::from(libc::SIGKILL),
        "a target that ignores SIGTERM must still be stopped"
    );
    assert_eq!(field(settled, "/lifetime/tree_empty"), true);
    assert_eq!(run.code(), Some(128 + libc::SIGKILL));
}

#[test]
fn x03_observation_off_does_not_confirm_an_exec_that_never_happened() {
    if !live() {
        return;
    }
    let validators = validators();
    let case = case();
    let marker = case.workspace.join("marker.txt");
    let mut spawned = case
        .jail
        .args(["--observe", "off"])
        .gate()
        .target([
            case.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .spawn()
        .expect("the jail starts");

    let attempt_id = {
        let mut owner = spawned.owner();
        let control = owner.await_prepared().expect("a prepared message");
        control
            .get("attempt_id")
            .and_then(Value::as_str)
            .expect("an attempt id")
            .to_owned()
    };

    // With observation off, exec confirmation rests on the error pipe reaching
    // EOF with no bytes. A launcher that was killed closes that pipe the same
    // way a launcher that exec'd does. Killing it here makes the two look
    // alike on that channel alone, so anything that still says "exec
    // confirmed" is reading EOF as proof rather than as an absence.
    let launcher = launcher_pid_of(spawned.pid()).expect("the launcher is running");
    // SAFETY: the launcher is a descendant of this test's own jail process.
    unsafe { libc::kill(launcher, libc::SIGKILL) };
    while Path::new(&format!("/proc/{launcher}")).exists() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    {
        let mut owner = spawned.owner();
        // The release may fail outright now: its reader is gone.
        let _ = owner.release(&Release::Valid, &attempt_id, "");
    }
    let run = spawned.wait().expect("the jail finishes");

    assert!(!marker.exists(), "the target ran after its launcher died");
    let receipts = receipts_of(&run, &validators);
    let last = receipts
        .last()
        .expect("the attempt persisted at least one receipt");
    assert_ne!(
        field(last, "/exec_observed"),
        true,
        "a dead launcher was taken for a confirmed exec: {last:#}"
    );
    assert_ne!(
        field(last, "/outcome/kind"),
        "exited",
        "an exit was invented for a target that never ran: {last:#}"
    );
    assert!(
        matches!(run.code(), Some(1 | 125)),
        "unexpected exit {:?}: {}",
        run.code(),
        run.stderr_text()
    );
}

/// The host pid of the `__launch` process beneath a running `ouro-jail`.
fn launcher_pid_of(jail: u32) -> Option<libc::pid_t> {
    fn children(pid: libc::pid_t) -> Vec<libc::pid_t> {
        let mut out = Vec::new();
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            return out;
        };
        for task in tasks.flatten() {
            let Ok(raw) = std::fs::read_to_string(task.path().join("children")) else {
                continue;
            };
            out.extend(
                raw.split_ascii_whitespace()
                    .filter_map(|token| token.parse::<libc::pid_t>().ok()),
            );
        }
        out
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let jail = libc::pid_t::try_from(jail).ok()?;
    while std::time::Instant::now() < deadline {
        let mut frontier = vec![jail];
        for _ in 0..4 {
            let mut next = Vec::new();
            for pid in frontier {
                for child in children(pid) {
                    if std::fs::read(format!("/proc/{child}/cmdline")).is_ok_and(|raw| {
                        raw.split(|b| *b == 0).nth(1) == Some(b"__launch".as_slice())
                    }) {
                        return Some(child);
                    }
                    next.push(child);
                }
            }
            frontier = next;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    None
}

#[test]
fn m03_doctor_refuses_when_the_backend_is_not_on_the_operators_path() {
    if !live() {
        return;
    }
    // §14.1: doctor reports what it measured, and §6.4 gives it 125 when the
    // selected plan is unavailable. A host whose PATH has no bubblewrap has
    // not provisioned the backend, and saying so is the whole point of the
    // command; reaching past PATH to a well-known location would report a
    // capability the operator did not offer.
    let empty = harness::fixture_path()
        .parent()
        .expect("the fixture has a directory")
        .join("no-backend-here");
    std::fs::create_dir_all(&empty).expect("an empty directory");
    let output = std::process::Command::new(harness::jail_path())
        .args(["doctor", "--json"])
        .env("PATH", &empty)
        .env(
            "OURO_DATA_DIR",
            std::env::temp_dir().join("ouro-doctor-nobwrap-data"),
        )
        .env(
            "OURO_CONFIG_DIR",
            std::env::temp_dir().join("ouro-doctor-nobwrap-cfg"),
        )
        .output()
        .expect("doctor runs");
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON document");
    let status = report["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .find(|capability| capability["name"] == "bwrap_present")
        .map(|capability| capability["status"].clone())
        .expect("the backend probe is reported");
    assert_eq!(
        status, "unavailable",
        "an absent backend must be unavailable, never skipped: {report:#}"
    );
    assert_eq!(report["ready"], Value::Bool(false));
    assert_eq!(
        output.status.code(),
        Some(125),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ===========================================================================
// Composition and state
// ===========================================================================

#[test]
fn i03_gate() {
    if !live() {
        return;
    }
    let validators = validators();

    // A matching plan releases once, and exactly one target exec happens.
    {
        let case = case();
        let marker = case.workspace.join("released.txt");
        let mut spawned = case
            .jail
            .gate()
            .receipt()
            .target([
                case.fixture.as_os_str(),
                OsStr::new("open"),
                marker.as_os_str(),
                OsStr::new("--create"),
                OsStr::new("--write"),
            ])
            .spawn()
            .expect("the jail starts");
        let control = {
            let mut owner: GateOwner<'_> = spawned.owner();
            owner.await_prepared().expect("a prepared message")
        };
        // The prepared receipt is durable before the control message is sent,
        // so the owner reads the plan it is being asked to authorise.
        let receipt = spawned
            .receipt_value()
            .expect("the prepared receipt is on disk when `prepared` arrives");
        let attempt_id = control
            .get("attempt_id")
            .and_then(Value::as_str)
            .expect("the proposal names its attempt")
            .to_owned();
        assert!(
            control
                .pointer("/receipt_digest")
                .and_then(Value::as_str)
                .is_some(),
            "the proposal carries a receipt digest"
        );
        assert_eq!(
            receipt.pointer("/phase").and_then(Value::as_str),
            Some("prepared")
        );
        let plan = ExpectedPlan::new().attempt_id(attempt_id.clone());
        let mut owner: GateOwner<'_> = spawned.owner();
        let proposal = owner
            .authorise(&control, Some(&receipt), &plan)
            .unwrap_or_else(|(proposal, problems)| {
                panic!("the owner's plan did not match: {problems:?} {proposal:?}")
            });
        let policy_digest = proposal
            .policy_digest
            .clone()
            .expect("the proposal names its policy digest");
        // The owner compares the argv digest with the one it authorised too.
        assert!(
            proposal.argv_digest.is_some(),
            "the proposal names the argv digest the owner must authorise"
        );
        owner
            .release(&Release::Valid, &attempt_id, &policy_digest)
            .expect("the gate is released");
        let run = spawned.wait().expect("the jail finishes");
        assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
        assert!(marker.is_file(), "the released target did not run");
        let receipts = receipts_of(&run, &validators);
        assert_eq!(field(receipts.phase("settled"), "/exec_observed"), true);
        // Exactly one exec of the target, so one release cannot become two.
        let execs = operations(&run)
            .iter()
            .filter(|op| *op == "proc.exec")
            .count();
        assert_eq!(execs, 1, "the target was executed more than once");
        assert_eq!(run.control_kind("exec_confirmed").len(), 1);
    }

    // A withheld gate: no target, a refused receipt, exit 125.
    {
        let case = case();
        let marker = case.workspace.join("never.txt");
        let mut spawned = case
            .jail
            .gate()
            .receipt()
            .target([
                case.fixture.as_os_str(),
                OsStr::new("open"),
                marker.as_os_str(),
                OsStr::new("--create"),
                OsStr::new("--write"),
            ])
            .spawn()
            .expect("the jail starts");
        {
            let mut owner = spawned.owner();
            owner.await_prepared().expect("a prepared message");
            owner.withhold();
        }
        let run = spawned.wait().expect("the jail finishes");
        assert_eq!(run.code(), Some(125), "stderr: {}", run.stderr_text());
        assert!(!marker.exists(), "the target ran without a release");
        let receipts = receipts_of(&run, &validators);
        let refused = receipts.phase("refused");
        assert_eq!(field(refused, "/exec_observed"), false);
        assert_eq!(field(refused, "/outcome/kind"), "refused");
    }

    // A release naming the wrong policy digest: the same refusal.
    {
        let case = case();
        let marker = case.workspace.join("wrong.txt");
        let mut spawned = case
            .jail
            .gate()
            .receipt()
            .target([
                case.fixture.as_os_str(),
                OsStr::new("open"),
                marker.as_os_str(),
                OsStr::new("--create"),
                OsStr::new("--write"),
            ])
            .spawn()
            .expect("the jail starts");
        {
            let mut owner = spawned.owner();
            let control = owner.await_prepared().expect("a prepared message");
            let attempt_id = control
                .get("attempt_id")
                .and_then(Value::as_str)
                .expect("an attempt id")
                .to_owned();
            owner
                .release(
                    &Release::Valid,
                    &attempt_id,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .expect("the frame is written");
        }
        let run = spawned.wait().expect("the jail finishes");
        assert_eq!(run.code(), Some(125));
        assert!(!marker.exists(), "a mismatched digest released the target");
        let receipts = receipts_of(&run, &validators);
        assert_eq!(field(receipts.phase("refused"), "/exec_observed"), false);
    }
}

#[test]
fn p04_receipt_and_state_overlap_refuse() {
    if !live() {
        return;
    }
    // A receipt path inside the workspace: the target could rewrite it.
    {
        let jail = Jail::new().expect("a private jail harness");
        let (workspace, fixture) = workspace_with_fixture(jail.root());
        let marker = workspace.join("marker.txt");
        let run = jail
            .arg("run")
            .arg("--workspace")
            .arg(&workspace)
            .arg("--receipt")
            .arg(workspace.join("receipt.json"))
            .target([
                fixture.as_os_str(),
                OsStr::new("open"),
                marker.as_os_str(),
                OsStr::new("--create"),
                OsStr::new("--write"),
            ])
            .run()
            .expect("the jail runs");
        // §6.4: a flag whose value is unusable is a usage error, exit 2. What
        // P04 pins is that it refuses before the target runs, which it does.
        assert_eq!(run.code(), Some(2), "stderr: {}", run.stderr_text());
        assert!(!marker.exists(), "the target ran before the refusal");
        assert!(
            run.stderr_text().contains("invalid_config") && run.stderr_text().contains("--receipt"),
            "stderr was {}",
            run.stderr_text()
        );
    }

    // A data directory inside the workspace: the same refusal.
    {
        let jail = Jail::new().expect("a private jail harness");
        let (workspace, fixture) = workspace_with_fixture(jail.root());
        let marker = workspace.join("marker.txt");
        let data = workspace.join("state");
        std::fs::create_dir_all(&data).expect("the data directory is created");
        let run = jail
            .arg("run")
            .arg("--workspace")
            .arg(&workspace)
            .env("OURO_DATA_DIR", &data)
            .target([
                fixture.as_os_str(),
                OsStr::new("open"),
                marker.as_os_str(),
                OsStr::new("--create"),
                OsStr::new("--write"),
            ])
            .run()
            .expect("the jail runs");
        // A state root the child can reach is a refusal, not a usage error.
        assert_eq!(run.code(), Some(125), "stderr: {}", run.stderr_text());
        assert!(!marker.exists(), "the target ran before the refusal");
        assert!(
            run.stderr_text().contains("unsafe_state_path"),
            "stderr was {}",
            run.stderr_text()
        );
    }
}

// ===========================================================================
// Doctor and evidence
// ===========================================================================

#[test]
fn doctor_reports_every_probe_and_the_manifest_agrees() {
    if !live() {
        return;
    }
    let output = std::process::Command::new(harness::jail_path())
        .args(["doctor", "--json"])
        .env(
            "OURO_DATA_DIR",
            std::env::temp_dir().join("ouro-doctor-data"),
        )
        .env(
            "OURO_CONFIG_DIR",
            std::env::temp_dir().join("ouro-doctor-cfg"),
        )
        .output()
        .expect("doctor runs");
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("doctor --json prints one JSON document");
    let mut statuses: BTreeMap<String, String> = BTreeMap::new();
    for capability in report["capabilities"]
        .as_array()
        .expect("doctor lists capabilities")
    {
        let name = capability["name"].as_str().expect("a name").to_owned();
        let status = capability["status"].as_str().expect("a status").to_owned();
        statuses.insert(name, status);
    }

    let manifest_text = std::fs::read_to_string(specs_dir().join("conformance-manifest.toml"))
        .expect("the manifest is checked in");
    for line in manifest_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((name, expected)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let expected = expected.trim().trim_matches('"');
        assert_eq!(
            statuses.get(name).map(String::as_str),
            Some(expected),
            "doctor reports {name} as {:?}, the manifest pins {expected}",
            statuses.get(name)
        );
    }

    // Every requirement of the selected profile is reported too.
    for requirement in report["requirements"]
        .as_array()
        .expect("doctor lists requirements")
    {
        let name = requirement.as_str().expect("a requirement name");
        assert!(
            statuses.contains_key(name),
            "doctor reports no capability for its own requirement {name}"
        );
    }
    assert_eq!(report["ready"], Value::Bool(true), "{report:#}");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn the_checked_in_seccomp_table_is_the_one_this_build_produces() {
    let path = specs_dir().join("evidence/seccomp-table-tool-x86_64.txt");
    let checked_in = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is missing: {error}", path.display()));
    let generated = ouro_jail::platform::linux::seccomp::tool_baseline_table();
    assert_eq!(
        generated, checked_in,
        "the evidence file has drifted from the filter this build installs; \
         regenerate it with `ouro-jail __seccomp-table`"
    );
}
