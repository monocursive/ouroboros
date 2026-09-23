#![cfg(target_os = "linux")]
#![allow(clippy::too_many_lines)]
//! J4 slice O, end to end: the observer's closed set and its attribution
//! (jail-v1 §15 O01, O02, O04, O06 and the §16 "closed set" exit).
//!
//! Every test drives the real `ouro-jail run` over the conformance fixture
//! and compares what the fixture says the kernel returned with the audit
//! events the jail wrote to its trace and the counts its receipt claims. The
//! fixture performs one named raw syscall per operation, so the comparison is
//! result by result: operation, `fields.syscall`, raw return, errno name and
//! `attempted_operation`.
//!
//! Which rows apply where. `tool`, `build` and `none` observe all 22 x86_64
//! rows through the ptrace observer; `connect` is an AF_INET connect there,
//! because `tool` and `build` refuse AF_UNIX sockets outright (§9.2) and a
//! connect needs a socket first. `agent` observes the same 21 filesystem and
//! exec rows through the ptrace observer and every `connect` through the
//! unix-peer mediator (`fields.observation = seccomp_user_notification`,
//! §11.4). No baseline refuses any of the variants used here, so none of
//! them is compared as a refusal; the variants a baseline does refuse
//! (`clone(CLONE_UNTRACED)`, S4) have their own tests below.
//!
//! Every process these tests start is their own; nothing on the host is
//! changed. Live: `OURO_CONFORMANCE=1` on the reference host.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use jsonschema::{Registry, Resource, Validator};
use ouro_fixture::harness::{self, Jail, Run};
use serde_json::Value;

mod common;

// ---------------------------------------------------------------------------
// Schemas, cases, runs
// ---------------------------------------------------------------------------

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

/// One validator per checked-in schema, by stem.
fn validators() -> &'static BTreeMap<String, Validator> {
    static ONCE: std::sync::OnceLock<BTreeMap<String, Validator>> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let mut schemas: BTreeMap<String, Value> = BTreeMap::new();
        for entry in std::fs::read_dir(specs_dir()).unwrap() {
            let path = entry.unwrap().path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Some(stem) = name.strip_suffix(".schema.json") {
                let text = std::fs::read_to_string(&path).unwrap();
                schemas.insert(stem.to_owned(), serde_json::from_str(&text).unwrap());
            }
        }
        let pairs: Vec<(String, Resource)> = schemas
            .values()
            .map(|schema| {
                (
                    schema["$id"].as_str().unwrap().to_owned(),
                    Resource::from_contents(schema.clone()),
                )
            })
            .collect();
        let registry: Registry = Registry::new().extend(pairs).unwrap().prepare().unwrap();
        let registry: &'static Registry = Box::leak(Box::new(registry));
        schemas
            .into_iter()
            .map(|(name, schema)| {
                let validator = jsonschema::options()
                    .with_registry(registry)
                    .should_validate_formats(true)
                    .build(&schema)
                    .unwrap();
                (name, validator)
            })
            .collect()
    })
}

/// The profiles this file runs. `none` needs a delegated leaf (§9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Tool,
    Build,
    None,
    Agent,
}

impl Profile {
    fn name(self) -> &'static str {
        match self {
            Profile::Tool => "tool",
            Profile::Build => "build",
            Profile::None => "none",
            Profile::Agent => "agent",
        }
    }

    /// Whether this host can run the profile; prints or fails the reason
    /// when it cannot (a skip is a failure under `OURO_CONFORMANCE=1`).
    fn available(self) -> bool {
        if !common::live() {
            return false;
        }
        if self != Profile::None {
            return true;
        }
        let leaf = ouro_jail::platform::linux::probe::run_one(
            "cgroup_delegated_leaf",
            &harness::jail_path(),
            Path::new("bwrap"),
        );
        if leaf.status != ouro_jail::platform::linux::probe::ProbeStatus::Available {
            harness::skip_or_fail(&format!(
                "the none profile needs a delegated user scope: {}",
                leaf.evidence
            ));
            return false;
        }
        true
    }
}

/// A run of `ouro-jail run --profile <profile>` over a private workspace
/// holding the fixture at `<workspace>/ouro-fixture`, trace and control on.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
    /// `build` exposes no workspace (§3.1: a package build reads declared
    /// inputs and writes scratch), so the fixture and its script are
    /// declared read-only inputs and the operations run under `/tmp`.
    build: bool,
}

fn case(profile: Profile, evidence: &str) -> Case {
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut jail = jail
        .arg("run")
        .arg("--profile")
        .arg(profile.name())
        .arg("--evidence")
        .arg(evidence)
        .arg("--workspace")
        .arg(&workspace);
    if profile == Profile::Build {
        // `build` requires an explicit memory ceiling (§6.4).
        jail = jail.args(["--limit", "mem=512MiB"]);
    }
    Case {
        jail: jail.trace().control(),
        workspace,
        fixture,
        build: profile == Profile::Build,
    }
}

impl Case {
    fn ws(&self, name: &str) -> String {
        self.workspace.join(name).to_str().unwrap().to_owned()
    }

    fn fixture_s(&self) -> String {
        self.fixture.to_str().unwrap().to_owned()
    }

    /// Run a fixture `script` of `steps` written into the workspace.
    fn script(self, name: &str, steps: &Value) -> Run {
        let path = self.workspace.join(format!("{name}.json"));
        std::fs::write(&path, serde_json::to_vec(steps).unwrap()).unwrap();
        let argv = vec![
            self.fixture.clone().into_os_string(),
            OsString::from("script"),
            path.clone().into_os_string(),
        ];
        self.run_with_inputs(argv, &[path])
    }

    /// Run `argv`; under `build` the fixture and `inputs` are declared.
    fn run_with_inputs(self, argv: Vec<OsString>, inputs: &[PathBuf]) -> Run {
        let mut jail = self.jail;
        if self.build {
            jail = jail.arg("--ro").arg(&self.fixture);
            for input in inputs {
                jail = jail.arg("--ro").arg(input);
            }
        }
        jail.target(argv).run().expect("the jail runs")
    }

    /// The directory the operations run in, and the roots §11.3 reports
    /// paths below it against: `(base, workspace root, scratch root)`.
    fn base(&self) -> String {
        if self.build {
            "/tmp/o01".to_owned()
        } else {
            self.workspace.to_str().unwrap().to_owned()
        }
    }
}

/// The receipt's own name for the target: pid and `linux_boot_start` ticks.
fn target_identity(receipt: &Value) -> (i64, u64) {
    let process = &receipt["process"];
    assert_eq!(
        process["identity"]["kind"], "linux_boot_start",
        "{process:#}"
    );
    let ticks = &process["identity"]["value"]["start_time_ticks"];
    let ticks = ticks
        .as_u64()
        .or_else(|| ticks.as_str().and_then(|t| t.parse().ok()))
        .unwrap_or_else(|| panic!("no start_time_ticks: {process:#}"));
    (process["pid"].as_i64().unwrap(), ticks)
}

/// Every receipt and event validated against the checked-in schemas, and
/// every receipt against the rules they cannot state
/// (`common::semantic_receipt`); the settled receipt.
fn settled(run: &Run) -> Value {
    run.assert_channels_complete();
    assert!(
        run.receipt_errors().is_empty(),
        "{:?}",
        run.receipt_errors()
    );
    for receipt in run.receipts() {
        validators()["jail-receipt"]
            .validate(&receipt)
            .unwrap_or_else(|error| panic!("a receipt fails its schema: {error}\n{receipt:#}"));
        common::assert_semantic_receipt(&receipt);
    }
    for event in run.trace_events() {
        validators()["jail-event"]
            .validate(event)
            .unwrap_or_else(|error| panic!("an event fails its schema: {error}\n{event:#}"));
    }
    run.receipt_phase("settled").unwrap_or_else(|| {
        panic!(
            "no settled receipt: exit {:?}, stderr {}",
            run.code(),
            run.stderr_text()
        )
    })
}

/// The audit source's results, in trace order.
fn audit_results(run: &Run) -> Vec<&Value> {
    run.trace_events()
        .iter()
        .filter(|event| event["source"] == "audit" && event["stage"] == "result")
        .collect()
}

fn gap_reasons(receipt: &Value) -> Vec<String> {
    receipt["coverage"]
        .as_object()
        .into_iter()
        .flat_map(|classes| classes.values())
        .flat_map(|class| class["gaps"].as_array().cloned().unwrap_or_default())
        .filter_map(|gap| gap["reason"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn dump(run: &Run) -> String {
    let mut out = String::new();
    out.push_str("fixture lines:\n");
    for line in run.fixture_lines() {
        out.push_str(&format!("  {line}\n"));
    }
    out.push_str("audit results:\n");
    for event in audit_results(run) {
        out.push_str(&format!(
            "  {} {} ret={} errno={} fields={}\n",
            event["operation"],
            event["outcome"]["completion"],
            event["outcome"]["return_value"],
            event["outcome"]["errno"],
            event["fields"]
        ));
    }
    out.push_str(&format!("stderr: {}\n", run.stderr_text()));
    out
}

// ---------------------------------------------------------------------------
// The closed set, as the fixture reports it
// ---------------------------------------------------------------------------

/// The 22 x86_64 rows of `linux-closed-v1` (§11.2).
const ROWS: [&str; 22] = [
    "execve",
    "execveat",
    "open",
    "openat",
    "openat2",
    "creat",
    "truncate",
    "rename",
    "renameat",
    "renameat2",
    "unlink",
    "unlinkat",
    "rmdir",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "connect",
];

const O_ACCMODE: i64 = 0o3;
const O_CREAT: i64 = 0o100;
const O_TRUNC: i64 = 0o1000;

/// The §11.2 operation a fixture line's call is reported as when it
/// succeeds, or `None` when the call is outside the set (a read-only open).
fn base_operation(line: &Value) -> Option<&'static str> {
    let op = line["op"].as_str()?;
    Some(match op {
        "execve" | "execveat" => "proc.exec",
        "creat" => "fs.create",
        "open" | "openat" | "openat2" => {
            let flags = line["args"]["flags"].as_i64()?;
            if flags & O_CREAT != 0 {
                "fs.create"
            } else if flags & O_ACCMODE == 0 && flags & O_TRUNC == 0 {
                return None;
            } else {
                "fs.write"
            }
        }
        "truncate" => "fs.write",
        "rename" | "renameat" | "renameat2" => "fs.rename",
        "unlink" | "unlinkat" | "rmdir" => "fs.unlink",
        "mkdir" | "mkdirat" | "mknod" | "mknodat" | "link" | "linkat" | "symlink" | "symlinkat" => {
            "fs.create"
        }
        "connect" => "net.connect",
        _ => return None,
    })
}

/// The class an audit operation is counted under (§11.4).
fn class_of(operation: &str) -> &'static str {
    match operation {
        "proc.exec" | "proc.exit" => "exec",
        "fs.deny" => "fs.deny",
        "net.connect" => "net",
        _ => "fs.write",
    }
}

/// Which fixture argument each event path stands for.
fn path_keys(op: &str) -> (Option<&'static str>, Option<&'static str>) {
    match op {
        "rename" | "renameat" | "renameat2" | "link" | "linkat" => (Some("from"), Some("to")),
        "symlink" | "symlinkat" => (Some("linkpath"), Some("target")),
        "connect" => (None, None),
        _ => (Some("path"), None),
    }
}

/// What §11.3 lets an event say about a pathname the fixture passed with
/// `AT_FDCWD`: relative to the workspace or the scratch below either,
/// unavailable when relative, a digest anywhere else.
fn expected_path(arg: &str, roots: &Roots) -> Value {
    for (root, kind) in [
        (Some(roots.workspace.as_str()), "workspace_relative"),
        (roots.scratch.as_deref(), "scratch_relative"),
    ] {
        if let Some(root) = root
            && let Some(rest) = arg.strip_prefix(root)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return serde_json::json!({
                "kind": kind,
                "value": rest.trim_start_matches('/'),
            });
        }
    }
    if !arg.starts_with('/') {
        return serde_json::json!({"kind": "unavailable", "reason": "relative_to_unobserved_cwd"});
    }
    serde_json::json!({"kind": "digest"})
}

/// The two roots a contained attempt reports paths against.
struct Roots {
    workspace: String,
    /// `/tmp` inside a contained profile; `none` uses only the workspace here.
    scratch: Option<String>,
}

fn path_matches(event_path: &Value, expected: &Value) -> bool {
    if expected["kind"] == "digest" {
        return event_path["kind"] == "digest";
    }
    event_path == expected
}

/// Whether `event` is the one audit result `line` stands for.
fn matches(line: &Value, event: &Value, roots: &Roots) -> bool {
    let Some(base) = base_operation(line) else {
        return false;
    };
    let op = line["op"].as_str().unwrap_or_default();
    let errno = line["errno"].as_str();
    let denied = matches!(errno, Some("EACCES" | "EPERM"));
    let operation = if denied { "fs.deny" } else { base };
    if event["operation"] != operation || event["fields"]["syscall"] != op {
        return false;
    }
    if denied && event["fields"]["attempted_operation"] != base {
        return false;
    }
    if !denied && event["fields"].get("attempted_operation").is_some() {
        return false;
    }
    let exec_success = base == "proc.exec" && errno.is_none();
    if exec_success {
        // A successful exec never returns to its caller: its evidence is the
        // confirmed transition, with no return value (§11.2).
        if event["outcome"]["completion"] != "exec_transition"
            || !event["outcome"]["return_value"].is_null()
        {
            return false;
        }
    } else if event["outcome"]["completion"] != "syscall_return"
        || event["outcome"]["return_value"].as_i64()
            != line["ret"].as_i64().map(|ret| {
                // The fixture reports -1 and the errno, as libc does; the event
                // carries the raw kernel return, -errno.
                if ret < 0 {
                    -i64::from(errno_value(errno.unwrap_or_default()))
                } else {
                    ret
                }
            })
        || event["outcome"]["errno"].as_str() != errno
    {
        return false;
    }
    let (first, second) = path_keys(op);
    for (key, field) in [(first, "path"), (second, "path2")] {
        if let Some(key) = key {
            let Some(arg) = line["args"][key].as_str() else {
                return false;
            };
            if !path_matches(&event["fields"][field], &expected_path(arg, roots)) {
                return false;
            }
        }
    }
    true
}

fn errno_value(name: &str) -> i32 {
    match name {
        "EPERM" => libc::EPERM,
        "ENOENT" => libc::ENOENT,
        "EACCES" => libc::EACCES,
        "EEXIST" => libc::EEXIST,
        "EXDEV" => libc::EXDEV,
        "ENOSYS" => libc::ENOSYS,
        "ECONNREFUSED" => libc::ECONNREFUSED,
        "ENETUNREACH" => libc::ENETUNREACH,
        "EROFS" => libc::EROFS,
        other => panic!("errno {other} is not in this test's table"),
    }
}

/// The O01 steps: every one of the 22 rows at least once, a success and a
/// failure where both are cheap, one denial per operation family that has
/// an easy one, a read-only open that must produce nothing, and two
/// successful execs whose children exit.
fn o01_steps(c: &Case) -> Value {
    let base = c.base();
    let w = |name: &str| format!("{base}/{name}");
    let fixture = c.fixture_s();
    serde_json::json!([
        ["mkdir", base.clone(), "--expect", "any"],
        [
            "open",
            w("denied.txt"),
            "--create",
            "--write",
            "--mode",
            "000"
        ],
        ["open", w("o-openat.txt"), "--create", "--write"],
        [
            "open",
            w("o-open.txt"),
            "--via",
            "open",
            "--create",
            "--write"
        ],
        ["open", w("o-creat.txt"), "--via", "creat"],
        [
            "open",
            w("o-openat2.txt"),
            "--via",
            "openat2",
            "--create",
            "--write"
        ],
        ["open", w("o-openat.txt"), "--write"],
        ["open", w("o-openat.txt"), "--via", "open", "--rdwr"],
        ["open", w("o-openat.txt")],
        ["open", w("denied.txt"), "--write", "--expect", "EACCES"],
        [
            "open",
            w("absent/x"),
            "--create",
            "--write",
            "--expect",
            "ENOENT"
        ],
        ["truncate", w("o-openat.txt"), "0"],
        ["truncate", w("absent/y"), "0", "--expect", "ENOENT"],
        ["mkdir", w("d-mkdir"), "--via", "mkdir"],
        ["mkdir", w("d-mkdirat"), "--via", "mkdirat"],
        [
            "mkdir",
            w("d-mkdir"),
            "--via",
            "mkdir",
            "--expect",
            "EEXIST"
        ],
        [
            "rename",
            w("o-open.txt"),
            w("r-rename.txt"),
            "--via",
            "rename"
        ],
        [
            "rename",
            w("r-rename.txt"),
            w("r-renameat.txt"),
            "--via",
            "renameat"
        ],
        [
            "rename",
            w("r-renameat.txt"),
            w("r-renameat2.txt"),
            "--via",
            "renameat2"
        ],
        [
            "rename",
            w("absent-a"),
            w("absent-b"),
            "--via",
            "renameat",
            "--expect",
            "ENOENT"
        ],
        [
            "link",
            w("r-renameat2.txt"),
            w("l-link.txt"),
            "--via",
            "link"
        ],
        [
            "link",
            w("r-renameat2.txt"),
            w("l-linkat.txt"),
            "--via",
            "linkat"
        ],
        ["symlink", "target", w("s-symlink"), "--via", "symlink"],
        ["symlink", "target", w("s-symlinkat"), "--via", "symlinkat"],
        ["mknod", w("n-mknod"), "--via", "mknod"],
        ["mknod", w("n-mknodat"), "--via", "mknodat"],
        ["unlink", w("l-link.txt"), "--via", "unlink"],
        ["unlink", w("l-linkat.txt"), "--via", "unlinkat"],
        [
            "unlink",
            w("l-link.txt"),
            "--via",
            "unlink",
            "--expect",
            "ENOENT"
        ],
        ["rmdir", w("d-mkdir"), "--via", "rmdir"],
        ["rmdir", w("d-mkdirat"), "--via", "unlinkat"],
        ["connect", "127.0.0.1:9", "--udp"],
        ["connect", "127.0.0.1:1", "--expect", "ECONNREFUSED"],
        [
            "exec",
            "--via",
            "execve",
            "--expect",
            "ENOENT",
            "--",
            "/nonexistent-ouro-j4"
        ],
        [
            "exec",
            "--via",
            "execveat",
            "--expect",
            "ENOENT",
            "--",
            "/nonexistent-ouro-j4"
        ],
        [
            "exec",
            "--via",
            "execve",
            "--expect",
            "EACCES",
            "--",
            w("denied.txt")
        ],
        ["exec", "--via", "execve", "--", fixture, "exit", "0"],
        ["exec", "--via", "execveat", "--", fixture, "exit", "0"]
    ])
}

/// O01 for one profile: every fixture line of a closed-set call matches
/// exactly one audit result on operation, `fields.syscall`, raw return,
/// errno and `attempted_operation` (and on both path classifications); the
/// only audit results left over are the target's own exec and one exit per
/// process that execed; every class count equals the results in that class,
/// including a class with none; every `fs.write` names its action; no audit
/// outcome carries a byte count.
fn o01_matrix(profile: Profile) {
    if !profile.available() {
        return;
    }
    let c = case(profile, "strict");
    let roots = Roots {
        workspace: c.workspace.to_str().unwrap().to_owned(),
        scratch: (profile != Profile::None).then(|| "/tmp".to_owned()),
    };
    let steps = o01_steps(&c);
    let run = c.script("o01", &steps);
    let receipt = settled(&run);
    let lines = run.fixture_lines();
    let events = audit_results(&run);
    let context = dump(&run);

    // Every row was exercised, by the fixture's own account.
    let exercised: BTreeSet<&str> = lines.iter().filter_map(|l| l["op"].as_str()).collect();
    for row in ROWS {
        assert!(
            exercised.contains(row),
            "{profile:?}: row {row} never ran\n{context}"
        );
    }
    // The script's own verdict: every expectation held.
    assert_eq!(
        run.code(),
        Some(0),
        "{profile:?}: the fixture exited non-zero\n{context}"
    );

    let mut used = vec![false; events.len()];
    // The target's own exec is not a fixture line: the launcher made it. It
    // looks exactly like the fixture's own `execve` of the same binary, so
    // it is set aside first, by the pid the receipt names the target with.
    let target = target_identity(&receipt).0;
    let own = events
        .iter()
        .position(|e| {
            e["operation"] == "proc.exec"
                && e["outcome"]["completion"] == "exec_transition"
                && e["fields"]["pid"].as_i64() == Some(target)
        })
        .unwrap_or_else(|| panic!("{profile:?}: the target's own exec is missing\n{context}"));
    used[own] = true;
    let mut matched_lines = 0usize;
    let mut excluded = 0usize;
    for line in &lines {
        let Some(op) = line["op"].as_str() else {
            continue;
        };
        if !ROWS.contains(&op) {
            continue;
        }
        if base_operation(line).is_none() {
            // A read-only open: outside the set, so no event at all.
            excluded += 1;
            continue;
        }
        let found: Vec<usize> = (0..events.len())
            .filter(|i| !used[*i] && matches(line, events[*i], &roots))
            .collect();
        let Some(first) = found.first() else {
            panic!("{profile:?}: no audit result for {line}\n{context}");
        };
        used[*first] = true;
        matched_lines += 1;
    }
    assert!(excluded >= 1, "{profile:?}: the read-only open was not run");

    // What is left is the exits of the processes that execed: the target and
    // the two children that ran `exit 0`.
    let leftover: Vec<&Value> = events
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|(event, _)| *event)
        .collect();
    let leftover_ops: Vec<&str> = leftover
        .iter()
        .map(|e| e["operation"].as_str().unwrap_or_default())
        .collect();
    let execs = leftover_ops.iter().filter(|op| **op == "proc.exec").count();
    let exits = leftover_ops.iter().filter(|op| **op == "proc.exit").count();
    assert_eq!(
        (execs, exits, leftover.len()),
        (0, 3, 3),
        "{profile:?}: audit results no fixture line accounts for: {leftover_ops:?}\n{context}"
    );
    for event in &leftover {
        assert_eq!(event["outcome"]["ok"], true, "{profile:?}: {event}");
    }
    assert!(
        leftover
            .iter()
            .any(|e| e["fields"]["pid"].as_i64() == Some(target)),
        "{profile:?}: the target's own exit is missing\n{context}"
    );

    // Class counts are the results per class, and every audit class is
    // active with a number.
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for event in &events {
        *counts
            .entry(class_of(event["operation"].as_str().unwrap_or_default()))
            .or_default() += 1;
    }
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "active", "{profile:?} {class}: {entry:#}");
        assert_eq!(
            entry["observed_count"].as_u64(),
            Some(counts.get(class).copied().unwrap_or(0)),
            "{profile:?} {class}: the count is not the number of results\n{context}"
        );
    }
    assert_eq!(gap_reasons(&receipt), Vec::<String>::new(), "{profile:?}");

    for event in &events {
        // No outcome asserts a byte count (O01).
        let outcome = event["outcome"].as_object().unwrap();
        assert!(
            !outcome.keys().any(|key| key.starts_with("bytes_")),
            "{profile:?}: {event}"
        );
        // A field named fs.write names its action (§11.2).
        if event["operation"] == "fs.write" {
            let action = event["fields"]["action"].as_str();
            assert!(
                matches!(action, Some("opened_for_mutation" | "truncated")),
                "{profile:?}: an fs.write without its action: {event}"
            );
        }
        // Only a mediated connect says it was one, and in `agent` every
        // connect result is one.
        let connect = event["fields"]["syscall"] == "connect";
        let mediated = event["fields"]["observation"] == "seccomp_user_notification";
        if profile == Profile::Agent {
            assert_eq!(connect, mediated, "{profile:?}: {event}");
        } else {
            assert!(!mediated, "{profile:?}: {event}");
        }
    }
    eprintln!(
        "{profile:?}: {matched_lines} fixture results matched one-to-one, {excluded} read-only \
         open(s) produced nothing, counts {counts:?}"
    );

    // Zero counts are zero, not absent: a target that only exits.
    let c = case(profile, "strict");
    let fixture = c.fixture.clone().into_os_string();
    let run = c.run_with_inputs(vec![fixture, "exit".into(), "0".into()], &[]);
    let receipt = settled(&run);
    let events = audit_results(&run);
    let ops: Vec<&str> = events
        .iter()
        .map(|e| e["operation"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        ops,
        ["proc.exec", "proc.exit"],
        "{profile:?}\n{}",
        dump(&run)
    );
    for (class, count) in [("exec", 2), ("fs.write", 0), ("fs.deny", 0), ("net", 0)] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "active", "{profile:?} {class}: {entry:#}");
        assert_eq!(
            entry["observed_count"],
            Value::from(count),
            "{profile:?} {class}: {entry:#}"
        );
    }
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_tool() {
    o01_matrix(Profile::Tool);
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_build() {
    o01_matrix(Profile::Build);
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_none() {
    o01_matrix(Profile::None);
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_agent() {
    o01_matrix(Profile::Agent);
}

// ---------------------------------------------------------------------------
// O02: attribution by birth identity
// ---------------------------------------------------------------------------

/// Every audit result names its process by host pid and birth: the start
/// time of that process (field 22 of `/proc/<pid>/stat`, clock ticks since
/// boot) as `fields.pid_start_ticks`. With the receipt's `boot_id` that is a
/// name no later process given the same number can share (§11.3).
fn assert_births(run: &Run, receipt: &Value, profile: Profile) -> BTreeMap<i64, u64> {
    let context = dump(run);
    let mut births: BTreeMap<i64, u64> = BTreeMap::new();
    for event in audit_results(run) {
        let pid = event["fields"]["pid"]
            .as_i64()
            .unwrap_or_else(|| panic!("{profile:?}: an audit result without its pid: {event}"));
        let ticks = event["fields"]["pid_start_ticks"]
            .as_u64()
            .unwrap_or_else(|| {
                panic!(
                    "{profile:?}: an audit result without its process's birth: {event}\n{context}"
                )
            });
        let seen = *births.entry(pid).or_insert(ticks);
        assert_eq!(
            seen, ticks,
            "{profile:?}: pid {pid} named with two births\n{context}"
        );
    }
    // The target's birth is the one the receipt records for it.
    let (target, ticks) = target_identity(receipt);
    assert_eq!(
        births.get(&target).copied(),
        Some(ticks),
        "{profile:?}: the target's audit birth is not the receipt's\n{context}"
    );
    births
}

#[test]
fn j4_o02_every_audit_event_names_the_birth_of_its_process() {
    for profile in [Profile::Tool, Profile::Agent] {
        if !profile.available() {
            return;
        }
        let c = case(profile, "strict");
        let fixture = c.fixture_s();
        let child = c.workspace.join("child.json");
        std::fs::write(
            &child,
            serde_json::to_vec(&serde_json::json!([
                ["identity"],
                ["mkdir", c.ws("by-child")],
                ["connect", "127.0.0.1:9", "--udp"]
            ]))
            .unwrap(),
        )
        .unwrap();
        let steps = serde_json::json!([
            ["identity"],
            ["mkdir", c.ws("by-target")],
            ["connect", "127.0.0.1:9", "--udp"],
            ["thread"],
            ["exec", "--expect", "ENOENT", "--", "/nonexistent-ouro-j4"],
            ["exec", "--", fixture, "script", child.to_str().unwrap()]
        ]);
        let run = c.script("births", &steps);
        let receipt = settled(&run);
        let context = dump(&run);
        let births = assert_births(&run, &receipt, profile);
        let lines = run.fixture_lines();
        let identities: Vec<&Value> = lines.iter().filter(|l| l["op"] == "identity").collect();
        assert_eq!(identities.len(), 2, "{profile:?}\n{context}");
        // Each process names itself with the birth the audit gives it: the
        // target and the exec'd child, which in the contained profiles see
        // themselves under a namespace pid the events never use. Births are
        // clock ticks (10 ms here), so two processes may share one; the name
        // is the pair, and each pair is checked against its own process.
        let target = target_identity(&receipt).0;
        let events = audit_results(&run);
        let by_path = |value: &str| -> i64 {
            events
                .iter()
                .find(|e| e["fields"]["path"]["value"] == value)
                .and_then(|e| e["fields"]["pid"].as_i64())
                .unwrap_or_else(|| panic!("{profile:?}: no result for {value}\n{context}"))
        };
        let child = by_path("by-child");
        assert_eq!(by_path("by-target"), target, "{profile:?}");
        assert_ne!(child, target, "{profile:?}");
        for (identity, pid) in identities.iter().zip([target, child]) {
            assert_eq!(
                births.get(&pid).copied(),
                identity["args"]["start_ticks"].as_u64(),
                "{profile:?}: pid {pid} is named with another birth than {identity}\n{context}"
            );
        }
        // The failed-exec child never execs: its one result still names it,
        // with a pid of its own and a birth no earlier than the target's.
        // (The fixture reports that child's pid as it sees it, which in a
        // contained profile is a namespace pid; the event carries the host
        // one, so the two are tied by the call, not by the number.)
        let failed: Vec<&&Value> = events
            .iter()
            .filter(|e| e["fields"]["syscall"] == "execve" && e["outcome"]["errno"] == "ENOENT")
            .collect();
        assert_eq!(failed.len(), 1, "{profile:?}\n{context}");
        let failed_pid = failed[0]["fields"]["pid"].as_i64().unwrap();
        assert!(failed_pid != target && failed_pid != child, "{profile:?}");
        assert!(births[&failed_pid] >= births[&target], "{profile:?}");
        assert!(births[&child] >= births[&failed_pid], "{profile:?}");
        // Threads are not processes: every pid named is a thread group this
        // run created (target, the failed-exec child, the exec'd child).
        assert_eq!(births.len(), 3, "{profile:?}: {births:?}\n{context}");
    }
}

/// O02 with a nested pid namespace, as far as the stock host allows (S10):
/// `none` runs the host's bubblewrap as its target, which puts the fixture
/// in a new user and pid namespace one layer down, traced through it. The
/// fixture sees itself under its namespace pid; every audit result names
/// the host pid, and its birth is the one the fixture reads for itself.
#[test]
fn j4_o02_a_nested_pid_namespace_under_none_keeps_host_attribution() {
    if !Profile::None.available() {
        return;
    }
    let c = case(Profile::None, "strict");
    let workspace = c.workspace.to_str().unwrap().to_owned();
    let script = c.workspace.join("nested.json");
    std::fs::write(
        &script,
        serde_json::to_vec(&serde_json::json!([
            ["identity"],
            ["mkdir", c.ws("nested-dir")],
            ["open", c.ws("nested-file"), "--create", "--write"]
        ]))
        .unwrap(),
    )
    .unwrap();
    let mut argv: Vec<OsString> = vec![
        common::bwrap_path().into_os_string(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--die-with-parent".into(),
    ];
    for root in ouro_jail::platform::linux::bwrap::RUNTIME_ROOTS
        .iter()
        .filter_map(|path| ouro_jail::platform::linux::fs::resolve_runtime_root(Path::new(path)))
    {
        match root {
            ouro_jail::platform::linux::fs::RootSpec::RoBind(path) => {
                argv.extend(["--ro-bind".into(), path.clone().into(), path.into()]);
            }
            ouro_jail::platform::linux::fs::RootSpec::Symlink { path, target } => {
                argv.extend(["--symlink".into(), target.into(), path.into()]);
            }
        }
    }
    argv.extend([
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--bind".into(),
        workspace.clone().into(),
        workspace.clone().into(),
        "--chdir".into(),
        workspace.clone().into(),
        "--".into(),
        c.fixture.clone().into_os_string(),
        "script".into(),
        script.into_os_string(),
    ]);
    let run = c.jail.target(argv).run().expect("the jail runs");
    let receipt = settled(&run);
    let context = dump(&run);
    let lines = run.fixture_lines();
    let identity = lines
        .iter()
        .find(|l| l["op"] == "identity")
        .unwrap_or_else(|| panic!("the fixture never ran inside bwrap\n{context}"));
    let inner_pid = identity["args"]["pid"].as_i64().unwrap();
    let inner_ticks = identity["args"]["start_ticks"].as_u64().unwrap();
    let nspid = identity["args"]["nspid"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let events = audit_results(&run);
    let mkdir = events
        .iter()
        .find(|e| {
            e["fields"]["syscall"] == "mkdirat" && e["fields"]["path"]["value"] == "nested-dir"
        })
        .unwrap_or_else(|| panic!("no audit result for the nested mkdir\n{context}"));
    let host_pid = mkdir["fields"]["pid"].as_i64().unwrap();
    assert_ne!(
        host_pid, inner_pid,
        "the event must carry the host pid, not the namespace pid {inner_pid} ({nspid})\n{context}"
    );
    assert_eq!(
        mkdir["fields"]["pid_start_ticks"].as_u64(),
        Some(inner_ticks),
        "the host-attributed result names the birth the process reads for itself\n{context}"
    );
    // The same process, the same name, for every one of its results.
    let mine: Vec<&&Value> = events
        .iter()
        .filter(|e| e["fields"]["pid"].as_i64() == Some(host_pid))
        .collect();
    let ops: BTreeSet<&str> = mine
        .iter()
        .filter_map(|e| e["operation"].as_str())
        .collect();
    assert!(
        ops.contains("proc.exec") && ops.contains("proc.exit") && ops.contains("fs.create"),
        "{ops:?}\n{context}"
    );
    for event in mine {
        assert_eq!(
            event["fields"]["pid_start_ticks"].as_u64(),
            Some(inner_ticks),
            "{event}"
        );
    }
    assert_eq!(receipt["outcome"]["kind"], "exited", "{context}");
    assert_eq!(gap_reasons(&receipt), Vec::<String>::new(), "{context}");
}

// ---------------------------------------------------------------------------
// O04: unrelated host processes
// ---------------------------------------------------------------------------

/// A process on the host that is not part of the attempt keeps making
/// closed-set calls for the whole run. `none` shares the host's view, which
/// makes it the profile where such a process is most visible; none of its
/// calls may appear, by pid or by path.
#[test]
fn j4_o04_an_unrelated_host_process_is_never_observed() {
    if !Profile::None.available() {
        return;
    }
    let c = case(Profile::None, "strict");
    let outside = c.jail.root().join("unrelated");
    std::fs::create_dir_all(&outside).unwrap();
    let a = outside.join("race-a");
    let b = outside.join("race-b");
    let mut unrelated = std::process::Command::new(harness::fixture_path())
        .args(["--no-report", "race-mkdir"])
        .arg(&a)
        .arg(&b)
        .arg("100000000")
        .spawn()
        .expect("the unrelated process starts");
    // Synchronised on the process's own first effect, not on a sleep.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !a.exists() && !b.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the unrelated process never ran"
        );
        std::thread::yield_now();
    }
    let steps = serde_json::json!([
        ["mkdir", c.ws("mine")],
        ["open", c.ws("mine/file"), "--create", "--write"],
        ["rmdir", c.ws("absent"), "--expect", "ENOENT"]
    ]);
    let run = c.script("o04", &steps);
    let still_running = unrelated.try_wait().expect("try_wait").is_none();
    let _ = unrelated.kill();
    let _ = unrelated.wait();
    assert!(still_running, "the unrelated process must outlive the run");
    let receipt = settled(&run);
    let context = dump(&run);
    let target = target_identity(&receipt).0;
    let digests: Vec<String> = [&a, &b]
        .iter()
        .map(|p| ouro_jail::canonical::sha256_prefixed(p.as_os_str().as_bytes()))
        .collect();
    let events = audit_results(&run);
    for event in &events {
        assert_eq!(
            event["fields"]["pid"].as_i64(),
            Some(target),
            "only the target made calls in this run: {event}\n{context}"
        );
        assert_ne!(
            event["fields"]["pid"].as_i64(),
            Some(i64::from(unrelated.id())),
            "{event}"
        );
        let text = event.to_string();
        for digest in &digests {
            assert!(!text.contains(digest.as_str()), "{event}");
        }
        assert!(
            !text.contains("race-a") && !text.contains("race-b"),
            "{event}"
        );
    }
    let fs: Vec<&&Value> = events
        .iter()
        .filter(|e| class_of(e["operation"].as_str().unwrap_or_default()) == "fs.write")
        .collect();
    assert_eq!(fs.len(), 3, "exactly the target's three calls\n{context}");
    assert_eq!(receipt["coverage"]["fs.write"]["observed_count"], 3);
}

// ---------------------------------------------------------------------------
// O06: paths never falsely resolved
// ---------------------------------------------------------------------------

fn event_for<'a>(events: &[&'a Value], syscall: &str, n: usize) -> &'a Value {
    events
        .iter()
        .filter(|e| e["fields"]["syscall"] == syscall)
        .nth(n)
        .copied()
        .unwrap_or_else(|| panic!("no {n}th {syscall} result"))
}

/// A relative name resolved against a working directory that was renamed
/// after the `chdir`. A sensor that joined the name to the cwd it last knew
/// would name a directory that no longer exists.
#[test]
fn j4_o06_renamed_cwd() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, "strict");
    let workspace = c.workspace.clone();
    let steps = serde_json::json!([
        ["mkdir", c.ws("cwd-a")],
        ["chdir", c.ws("cwd-a")],
        ["rename", c.ws("cwd-a"), c.ws("cwd-b"), "--via", "rename"],
        ["mkdir", "made", "--via", "mkdir"],
        ["open", "file.txt", "--create", "--write"]
    ]);
    let run = c.script("cwd", &steps);
    let _ = settled(&run);
    let context = dump(&run);
    assert!(workspace.join("cwd-b/made").is_dir(), "{context}");
    assert!(!workspace.join("cwd-a").exists(), "{context}");
    let events = audit_results(&run);
    let rename = event_for(&events, "rename", 0);
    assert_eq!(rename["fields"]["path"]["value"], "cwd-a", "{context}");
    assert_eq!(rename["fields"]["path2"]["value"], "cwd-b", "{context}");
    let unavailable =
        serde_json::json!({"kind": "unavailable", "reason": "relative_to_unobserved_cwd"});
    // `cwd-a` itself was made with `mkdirat`; the relative one with `mkdir`.
    let made = event_for(&events, "mkdir", 0);
    assert_eq!(made["fields"]["path"], unavailable, "{context}");
    let file = events
        .iter()
        .find(|e| e["fields"]["syscall"] == "openat" && e["operation"] == "fs.create")
        .unwrap();
    assert_eq!(file["fields"]["path"], unavailable, "{context}");
    for event in &events {
        let text = event["fields"].to_string();
        for guess in [
            "cwd-a/made",
            "cwd-b/made",
            "cwd-a/file.txt",
            "cwd-b/file.txt",
        ] {
            assert!(!text.contains(guess), "a resolved guess {guess}: {event}");
        }
    }
    assert_eq!(made["fields"]["path_basis"], "argument_snapshot");
}

/// A relative name resolved against a directory descriptor: the event
/// records the descriptor and says the path is relative to it, never the
/// workspace path the kernel actually resolved. An absolute name ignores the
/// descriptor, and is reported as what it is.
#[test]
fn j4_o06_foreign_dirfd() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, "strict");
    std::fs::create_dir_all(c.workspace.join("sub")).unwrap();
    let workspace = c.workspace.clone();
    let steps = serde_json::json!([
        ["mkdir", "made", "--via", "mkdirat", "--dirfd", c.ws("sub")],
        [
            "mkdir",
            c.ws("abs-made"),
            "--via",
            "mkdirat",
            "--dirfd",
            c.ws("sub")
        ]
    ]);
    let run = c.script("dirfd", &steps);
    let _ = settled(&run);
    let context = dump(&run);
    assert!(workspace.join("sub/made").is_dir(), "{context}");
    let lines = run.fixture_lines();
    let mkdirs: Vec<&Value> = lines.iter().filter(|l| l["op"] == "mkdirat").collect();
    let fd = mkdirs[0]["args"]["dirfd"].as_i64().unwrap();
    let events = audit_results(&run);
    let relative = event_for(&events, "mkdirat", 0);
    assert_eq!(
        relative["fields"]["path"],
        serde_json::json!({"kind": "unavailable", "reason": "relative_to_dirfd"}),
        "{context}"
    );
    assert_eq!(
        relative["fields"]["path_dirfd"].as_i64(),
        Some(fd),
        "{context}"
    );
    assert_eq!(relative["fields"]["path_complete"], true);
    assert_eq!(relative["outcome"]["return_value"], 0);
    let absolute = event_for(&events, "mkdirat", 1);
    assert_eq!(
        absolute["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "abs-made"}),
        "{context}"
    );
    for event in &events {
        assert!(
            !event["fields"].to_string().contains("sub/made"),
            "the descriptor was resolved: {event}"
        );
    }
    // The directory's own open is read-only: outside the set.
    assert!(
        events.iter().all(|e| e["fields"]["syscall"] != "openat"),
        "{context}"
    );
}

/// §11.3: "Two-path operations treat both paths independently." Each side
/// is classified on its own evidence: one established, the other relative
/// to a descriptor, in both orders; and a scratch path beside a workspace
/// path.
#[test]
fn j4_o06_two_paths_independent() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, "strict");
    std::fs::create_dir_all(c.workspace.join("sub")).unwrap();
    std::fs::write(c.workspace.join("two-a"), b"a").unwrap();
    let steps = serde_json::json!([
        [
            "rename",
            c.ws("two-a"),
            "two-b",
            "--via",
            "renameat",
            "--dirfd2",
            c.ws("sub")
        ],
        [
            "rename",
            "two-b",
            c.ws("two-c"),
            "--via",
            "renameat2",
            "--dirfd",
            c.ws("sub")
        ],
        [
            "link",
            c.ws("two-c"),
            "/tmp/two-d",
            "--via",
            "linkat",
            "--expect",
            "any"
        ]
    ]);
    let run = c.script("two", &steps);
    let _ = settled(&run);
    let context = dump(&run);
    let events = audit_results(&run);
    let lines = run.fixture_lines();
    let renames: Vec<&Value> = lines
        .iter()
        .filter(|l| l["op"] == "renameat" || l["op"] == "renameat2")
        .collect();
    let first = event_for(&events, "renameat", 0);
    assert_eq!(
        first["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "two-a"}),
        "{context}"
    );
    assert_eq!(
        first["fields"]["path2"],
        serde_json::json!({"kind": "unavailable", "reason": "relative_to_dirfd"}),
        "{context}"
    );
    assert_eq!(
        first["fields"]["path2_dirfd"].as_i64(),
        renames[0]["args"]["dirfd2"].as_i64()
    );
    assert!(first["fields"].get("path_dirfd").is_none(), "{first}");
    let second = event_for(&events, "renameat2", 0);
    assert_eq!(
        second["fields"]["path"],
        serde_json::json!({"kind": "unavailable", "reason": "relative_to_dirfd"}),
        "{context}"
    );
    assert_eq!(
        second["fields"]["path_dirfd"].as_i64(),
        renames[1]["args"]["dirfd"].as_i64()
    );
    assert_eq!(
        second["fields"]["path2"],
        serde_json::json!({"kind": "workspace_relative", "value": "two-c"}),
        "{context}"
    );
    let link = event_for(&events, "linkat", 0);
    assert_eq!(
        link["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "two-c"}),
        "{context}"
    );
    assert_eq!(
        link["fields"]["path2"],
        serde_json::json!({"kind": "scratch_relative", "value": "two-d"}),
        "{context}"
    );
}

/// A name that is not UTF-8 is carried as its bytes (the base64 form of the
/// native-string codec) and decodes to exactly what the fixture passed.
#[test]
fn j4_o06_non_utf8_round_trip() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, "strict");
    let name: &[u8] = b"caf\xe9-\xff\xfe";
    let mut path = c.workspace.as_os_str().as_bytes().to_vec();
    path.push(b'/');
    path.extend_from_slice(name);
    let path = OsString::from_vec(path);
    let run = c
        .jail
        .target([
            c.fixture.clone().into_os_string(),
            OsString::from("mkdir"),
            path.clone(),
        ])
        .run()
        .expect("the jail runs");
    let _ = settled(&run);
    let context = dump(&run);
    assert!(Path::new(&path).is_dir(), "{context}");
    let events = audit_results(&run);
    let mkdir = event_for(&events, "mkdirat", 0);
    assert_eq!(
        mkdir["fields"]["path"]["kind"], "workspace_relative",
        "{context}"
    );
    let value = &mkdir["fields"]["path"]["value"];
    assert_eq!(value["encoding"], "base64", "{context}");
    let decoded: ouro_jail::records::NativeString =
        serde_json::from_value(value.clone()).expect("a native string");
    assert_eq!(decoded.as_bytes(), name, "{context}");
    assert_eq!(mkdir["fields"]["path_complete"], true);
    let _ = OsStr::from_bytes(name);
}

/// A pathname another thread keeps rewriting while the call runs. The
/// observer snapshots the argument at the entry; the kernel reads it again.
/// Every event must be one of the two literal names the buffer ever held,
/// labelled `argument_snapshot`: the documented limit of §11.3, never a
/// resolved or blended path. Results stay one per call.
#[test]
fn j4_o06_racing_pathname_is_only_a_literal_snapshot() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, "strict");
    const CALLS: usize = 300;
    let steps = serde_json::json!([[
        "race-mkdir",
        c.ws("race-a"),
        c.ws("race-b"),
        CALLS.to_string()
    ]]);
    let workspace = c.workspace.clone();
    let run = c.script("race", &steps);
    let receipt = settled(&run);
    let context = dump(&run);
    let lines: Vec<Value> = run
        .fixture_lines()
        .into_iter()
        .filter(|l| l["op"] == "mkdir")
        .collect();
    assert_eq!(lines.len(), CALLS, "{context}");
    let events: Vec<&Value> = audit_results(&run)
        .into_iter()
        .filter(|e| e["fields"]["syscall"] == "mkdir")
        .collect();
    assert_eq!(events.len(), CALLS, "one result per call\n{context}");
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut created = 0;
    for (line, event) in lines.iter().zip(&events) {
        let ret = line["ret"].as_i64().unwrap();
        let raw = if ret < 0 {
            -i64::from(errno_value(line["errno"].as_str().unwrap()))
        } else {
            ret
        };
        assert_eq!(
            event["outcome"]["return_value"].as_i64(),
            Some(raw),
            "{event}"
        );
        if ret == 0 {
            created += 1;
        }
        assert_eq!(
            event["fields"]["path_basis"], "argument_snapshot",
            "{event}"
        );
        let value = event["fields"]["path"]["value"]
            .as_str()
            .unwrap_or_default();
        assert!(
            event["fields"]["path"]["kind"] == "workspace_relative"
                && (value == "race-a" || value == "race-b"),
            "a snapshot that is neither literal name: {event}"
        );
        *seen.entry(value.to_owned()).or_default() += 1;
    }
    assert!(created <= 2, "each name can be created once");
    let on_disk = ["race-a", "race-b"]
        .iter()
        .filter(|n| workspace.join(n).is_dir())
        .count();
    assert_eq!(on_disk, created, "{context}");
    assert_eq!(receipt["coverage"]["fs.write"]["status"], "active");
    eprintln!("racing snapshots: {seen:?}, directories created: {created}");
}

// ---------------------------------------------------------------------------
// S4: CLONE_UNTRACED
// ---------------------------------------------------------------------------

/// `clone(CLONE_UNTRACED)` would create a descendant the observer never
/// attaches to. Every contained baseline refuses it with EPERM, and the
/// ordinary ways of creating tasks keep working.
#[test]
fn j4_clone_untraced_refused_in_contained() {
    for profile in [Profile::Tool, Profile::Build, Profile::Agent] {
        if !profile.available() {
            return;
        }
        let c = case(profile, "strict");
        let untraced = c.workspace.join("untraced");
        let fixture = c.fixture_s();
        let steps = serde_json::json!([
            [
                "clone-untraced",
                untraced.to_str().unwrap(),
                "--expect",
                "EPERM"
            ],
            ["thread"],
            ["exec", "--", fixture, "exit", "0"]
        ]);
        let run = c.script("untraced", &steps);
        let receipt = settled(&run);
        let context = dump(&run);
        let lines = run.fixture_lines();
        let clone = lines.iter().find(|l| l["op"] == "clone").unwrap();
        assert_eq!(clone["errno"], "EPERM", "{profile:?}\n{context}");
        assert!(
            lines.iter().all(|l| l["op"] != "untraced-mkdir"),
            "{profile:?}: a child ran\n{context}"
        );
        assert!(!untraced.exists(), "{profile:?}");
        assert_eq!(
            run.code(),
            Some(0),
            "{profile:?}: threads and fork still work\n{context}"
        );
        assert_eq!(gap_reasons(&receipt), Vec::<String>::new(), "{profile:?}");
    }
}

/// In `none` nothing refuses the flag. The observer stops on it, and a
/// descendant it can never attach to is a gap in every class: coverage
/// cannot be `active`, strict evidence stops the attempt. The descendant's
/// own closed-set calls fail closed (ENOSYS: a trace stop with no tracer).
/// `clone3`, whose flags seccomp cannot read, is refused with ENOSYS so that
/// glibc falls back to `clone`, and threads keep working.
#[test]
fn j4_clone_untraced_is_a_gap_in_none() {
    if !Profile::None.available() {
        return;
    }
    let c = case(Profile::None, "best-effort");
    let untraced = c.workspace.join("untraced");
    let steps = serde_json::json!([
        ["clone3", "--expect", "ENOSYS"],
        ["thread"],
        ["clone-untraced", untraced.to_str().unwrap()]
    ]);
    let run = c.script("untraced-none", &steps);
    let receipt = settled(&run);
    let context = dump(&run);
    let lines = run.fixture_lines();
    let clone3 = lines.iter().find(|l| l["op"] == "clone3").unwrap();
    assert_eq!(clone3["errno"], "ENOSYS", "{context}");
    let thread = lines.iter().find(|l| l["op"] == "thread").unwrap();
    assert_eq!(thread["args"]["joined"], true, "{context}");
    let clone = lines.iter().find(|l| l["op"] == "clone").unwrap();
    assert!(clone["ret"].as_i64().unwrap() > 0, "{context}");
    let child = lines.iter().find(|l| l["op"] == "untraced-mkdir").unwrap();
    assert_eq!(
        child["errno"], "ENOSYS",
        "the untraced child fails closed\n{context}"
    );
    assert!(!untraced.exists());
    assert!(
        gap_reasons(&receipt)
            .iter()
            .any(|r| r == "untraced_descendant"),
        "{:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
        assert_eq!(entry["observed_count"], Value::Null, "{class}");
        let gap = entry["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["reason"] == "untraced_descendant")
            .unwrap_or_else(|| panic!("{class}: {entry:#}"));
        assert_eq!(
            gap["end_ns"],
            Value::Null,
            "{class}: its lifetime is not observed"
        );
    }
    assert_eq!(
        receipt["outcome"]["kind"], "exited",
        "{:#}",
        receipt["outcome"]
    );

    // Strict: the same gap stops the attempt.
    let c = case(Profile::None, "strict");
    let untraced = c.workspace.join("untraced");
    let steps = serde_json::json!([
        ["clone-untraced", untraced.to_str().unwrap()],
        ["sleep", "10000"]
    ]);
    let run = c.script("untraced-strict", &steps);
    let receipt = settled(&run);
    assert_eq!(
        receipt["outcome"]["cause"], "evidence_loss",
        "{:#}",
        receipt["outcome"]
    );
}

// ---------------------------------------------------------------------------
// §16 closed set: the published table
// ---------------------------------------------------------------------------

fn published_table_path() -> PathBuf {
    specs_dir().join("evidence/closed-set-x86_64.txt")
}

/// §11.2: "The implementation must publish its exact hook/syscall table."
/// The table is generated from the observer's own rows and by running the
/// installed program; the checked-in evidence must be exactly it, and the
/// narrowing-filter digest it publishes must be the one a live receipt of
/// this build reads back — for a contained profile and for `none`, which
/// install the same program.
#[test]
fn j4_closed_set_the_published_table_is_the_one_this_build_traces() {
    let generated = ouro_jail::platform::linux::tracer::closed_set_table();
    let checked_in = std::fs::read_to_string(published_table_path())
        .unwrap_or_else(|e| panic!("{}: {e}", published_table_path().display()));
    assert_eq!(
        generated, checked_in,
        "the published closed-set table has drifted from what this build traces; \
         regenerate it with the ignored `bless_the_published_closed_set_table`"
    );
    let published = checked_in
        .lines()
        .find_map(|line| line.strip_prefix("narrowing filter digest: "))
        .expect("the table publishes the filter digest")
        .to_owned();
    for profile in [Profile::Tool, Profile::None] {
        if !profile.available() {
            return;
        }
        let c = case(profile, "strict");
        let fixture = c.fixture.clone().into_os_string();
        let run = c.run_with_inputs(vec![fixture, "exit".into(), "0".into()], &[]);
        let receipt = settled(&run);
        assert_eq!(
            receipt["lifetime"]["native"]["details"]["narrowing_filter_digest"].as_str(),
            Some(published.as_str()),
            "{profile:?}: the receipt reads back another filter"
        );
        eprintln!("{profile:?}: receipt narrowing_filter_digest = {published}");
    }
}

/// Writes the published table from this build. Run by hand, on Linux,
/// after a deliberate change to the closed set or the narrowing filter.
#[test]
#[ignore = "writes the evidence file; run deliberately"]
fn bless_the_published_closed_set_table() {
    std::fs::write(
        published_table_path(),
        ouro_jail::platform::linux::tracer::closed_set_table(),
    )
    .unwrap();
}
