//! J5-C, R01 and O01 live: every record the real jail writes, under every
//! profile, passes the frozen contract, and the live output carries each kind
//! of event the examples freeze.
//!
//! jail-v1 §17 "Before J5" asks to "finish the executable schema constraints,
//! verify all source-specific event semantics and freeze the wire versions".
//! The frozen schemas and `ouro_jail::records::semantic` state those rules and
//! the examples show one instance of each kind of record. This file runs the
//! real `ouro-jail` on the reference host, releases each attempt through the
//! managed gate (§8.2) like an owner would, and holds every receipt, the trace
//! and the control transcript to the whole contract
//! (`common::assert_run_records`: schemas, receipt rules, `source_seq` per
//! source, receipt notes in lifecycle order, the trace ending on the final
//! receipt's note, control messages in order). Each run is built to produce a
//! known set of event kinds, and the test asserts the trace carries them, so a
//! kind the product writes in a shape the schema rejects cannot hide behind a
//! run that never produced it.
//!
//! The note kinds a normal run does not write are held to the same contract
//! where they are produced: `coverage_gap` in `j4_loss_linux.rs` (whose
//! helper runs these checks since J5-C), `lifetime` in the R06 tests, `limit`
//! only on a host without a delegated pids controller, `helper` only when an
//! `agent` helper dies.
//!
//! Every process these tests start is their own jail's; nothing on the host
//! is inspected or changed.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use ouro_fixture::harness::{self, HttpServer, Jail, Release, Run};
use serde_json::Value;

mod common;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Profile {
    Tool,
    Build,
    Agent,
    None,
}

impl Profile {
    fn name(self) -> &'static str {
        match self {
            Profile::Tool => "tool",
            Profile::Build => "build",
            Profile::Agent => "agent",
            Profile::None => "none",
        }
    }

    /// Whether this host can run the profile; a skip is a failure under
    /// `OURO_CONFORMANCE=1`.
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

/// One gated `ouro-jail run --profile <profile>` over a private workspace
/// holding the fixture, with trace, control, gate and `--receipt` plumbed.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
    profile: Profile,
}

fn case(profile: Profile, extra: &[&str]) -> Case {
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
        .arg("strict")
        .arg("--workspace")
        .arg(&workspace);
    if profile == Profile::Build {
        // `build` requires an explicit memory ceiling (§6.4) and exposes no
        // workspace, so the fixture is a declared read-only input.
        jail = jail
            .args(["--limit", "mem=512MiB"])
            .arg("--ro")
            .arg(&fixture);
    }
    for arg in extra {
        jail = jail.arg(arg);
    }
    Case {
        jail: jail.trace().control().gate().receipt(),
        workspace,
        fixture,
        profile,
    }
}

impl Case {
    /// Where the script's operations run: the workspace, or scratch under
    /// `build` (§3.1: a build reads declared inputs and writes scratch).
    fn base(&self) -> String {
        if self.profile == Profile::Build {
            "/tmp/j5c".to_owned()
        } else {
            self.workspace.to_str().unwrap().to_owned()
        }
    }

    fn fixture_s(&self) -> String {
        self.fixture.to_str().unwrap().to_owned()
    }

    /// Runs a fixture script of `steps` and releases the gate once the
    /// prepared receipt names the attempt and policy the owner reads, as a
    /// managed owner does (§8.2). `release` is the frame the owner sends.
    fn run(self, steps: &Value, release: &Release) -> Run {
        let script = self.workspace.join("j5c.json");
        std::fs::write(&script, serde_json::to_vec(steps).unwrap()).unwrap();
        let mut jail = self.jail;
        if self.profile == Profile::Build {
            jail = jail.arg("--ro").arg(&script);
        }
        let mut spawned = jail
            .target([
                self.fixture.clone().into_os_string(),
                OsString::from("script"),
                script.into_os_string(),
            ])
            .spawn()
            .expect("the jail starts");
        let control = spawned
            .owner()
            .await_prepared()
            .expect("a prepared message");
        // The prepared receipt is durable before `prepared` is sent (§8.2).
        let prepared = common::checked_receipt(
            spawned
                .receipt_value()
                .expect("the prepared receipt is on disk when `prepared` arrives"),
        );
        let attempt = control["attempt_id"]
            .as_str()
            .expect("an attempt")
            .to_owned();
        let digest = prepared["policy"]["digest"]
            .as_str()
            .expect("a policy digest")
            .to_owned();
        spawned
            .owner()
            .release(release, &attempt, &digest)
            .expect("the owner releases");
        spawned.wait().expect("the jail finishes")
    }
}

/// The kind of each trace event: source, operation, completion, and the
/// decision (proxy), `fields.kind` (wrapper note) or `attempted_operation`
/// (`fs.deny`), in the key form `portable_records.rs` gives the examples.
fn kinds(run: &Run) -> BTreeSet<String> {
    let text = |value: &Value| value.as_str().unwrap_or("-").to_owned();
    run.trace_events()
        .iter()
        .map(|event| {
            let detail = match event["source"].as_str() {
                Some("proxy") => text(&event["decision"]),
                Some("wrapper") if event["operation"] == "note" => text(&event["fields"]["kind"]),
                Some("audit") if event["operation"] == "fs.deny" => {
                    text(&event["fields"]["attempted_operation"])
                }
                _ => "-".to_owned(),
            };
            format!(
                "{} {} {} {}",
                text(&event["source"]),
                text(&event["operation"]),
                text(&event["outcome"]["completion"]),
                detail
            )
        })
        .collect()
}

fn assert_kinds(run: &Run, profile: Profile, expected: &[&str]) {
    let found = kinds(run);
    for kind in expected {
        assert!(
            found.contains(*kind),
            "{profile:?}: the live trace has no `{kind}`; it has {found:#?}"
        );
    }
}

/// What a failed exit-code assertion needs: stderr, the last receipt's
/// outcome and errors, and the fixture's last lines.
fn explain(run: &Run) -> String {
    let last = run.receipts().last().cloned().unwrap_or(Value::Null);
    let stdout = run.stdout_text();
    let tail: Vec<&str> = stdout.lines().rev().take(4).collect();
    format!(
        "stderr {:?}; receipt phase {} outcome {} errors {}; fixture tail {tail:?}",
        run.stderr_text(),
        last["phase"],
        last["outcome"],
        last["errors"]
    )
}

fn control_kinds(run: &Run) -> Vec<String> {
    run.control_messages()
        .iter()
        .map(|message| message["kind"].as_str().unwrap_or("-").to_owned())
        .collect()
}

/// The closed-set operations every contained or `none` run makes: a create,
/// a write, a truncation, a rename, a removal, a directory, a DAC denial of a
/// write, a connect, a failed exec, and an exec whose process then exits.
fn steps(case: &Case) -> Vec<Value> {
    let base = case.base();
    let at = |name: &str| format!("{base}/{name}");
    let mut steps = Vec::new();
    if case.profile == Profile::Build {
        steps.push(serde_json::json!(["mkdir", base]));
    }
    steps.extend([
        serde_json::json!(["open", at("created.txt"), "--create", "--write"]),
        serde_json::json!(["open", at("created.txt"), "--write"]),
        serde_json::json!(["truncate", at("created.txt"), "0"]),
        serde_json::json!(["rename", at("created.txt"), at("renamed.txt")]),
        serde_json::json!(["mkdir", at("dir")]),
        serde_json::json!(["symlink", "renamed.txt", at("link")]),
        serde_json::json!(["unlink", at("link")]),
        serde_json::json!([
            "open",
            at("readonly.txt"),
            "--create",
            "--write",
            "--mode",
            "400"
        ]),
        serde_json::json!(["open", at("readonly.txt"), "--write", "--expect", "EACCES"]),
        serde_json::json!(["connect", "127.0.0.1:1", "--expect", "any"]),
        serde_json::json!([
            "exec",
            "--via",
            "execve",
            "--expect",
            "ENOENT",
            "--",
            "/nonexistent-ouro-j5c"
        ]),
        serde_json::json!([
            "exec",
            "--via",
            "execve",
            "--",
            case.fixture_s(),
            "exit",
            "0"
        ]),
    ]);
    steps
}

/// What every observed run above writes, whatever the profile.
const OBSERVED_KINDS: &[&str] = &[
    "audit fs.create syscall_return -",
    "audit fs.write syscall_return -",
    "audit fs.rename syscall_return -",
    "audit fs.unlink syscall_return -",
    "audit fs.deny syscall_return fs.write",
    "audit net.connect syscall_return -",
    "audit proc.exec syscall_return -",
    "audit proc.exec exec_transition -",
    "audit proc.exit process_exit -",
    "wrapper note wrapper lifecycle",
    "wrapper jail.receipt wrapper -",
];

fn observed_profile(profile: Profile) {
    if !profile.available() {
        return;
    }
    let c = case(profile, &[]);
    let steps = Value::from(steps(&c));
    let run = c.run(&steps, &Release::Valid);
    assert_eq!(
        run.code(),
        Some(0),
        "{profile:?}: the fixture's expectations held: {}",
        explain(&run)
    );
    common::assert_run_records(&run);
    assert_kinds(&run, profile, OBSERVED_KINDS);
    assert_eq!(
        control_kinds(&run),
        ["prepared", "exec_confirmed", "settled"],
        "{profile:?}"
    );
}

#[test]
fn j5_tool_records_pass_the_frozen_contract() {
    observed_profile(Profile::Tool);
}

#[test]
fn j5_build_records_pass_the_frozen_contract() {
    observed_profile(Profile::Build);
}

#[test]
fn j5_none_records_pass_the_frozen_contract() {
    observed_profile(Profile::None);
}

/// `agent` adds the proxy source (an allowed and a denied request, §10) and
/// the mediator's audit results: a connect to a host Unix socket in the
/// workspace, refused as an `fs.deny` of `net.connect` (§11.2, §11.4).
#[test]
fn j5_agent_records_pass_the_frozen_contract() {
    if !Profile::Agent.available() {
        return;
    }
    let allowed = HttpServer::start(b"allowed".to_vec()).expect("an allowed origin");
    let refused = HttpServer::start(b"never".to_vec()).expect("a refused origin");
    let (a, r) = (allowed.addr().port(), refused.addr().port());
    let allow = format!("127.0.0.1:{a}");
    let c = case(Profile::Agent, &["--allow-host", &allow]);
    let host_socket = c.workspace.join("host.sock");
    let listener = std::os::unix::net::UnixListener::bind(&host_socket).expect("a host socket");
    let mut steps = steps(&c);
    steps.extend([
        serde_json::json!(["http-get", format!("http://127.0.0.1:{a}/allowed")]),
        serde_json::json!([
            "http-get",
            format!("http://127.0.0.1:{r}/refused"),
            "--expect",
            "any"
        ]),
        serde_json::json!([
            "unix-connect",
            host_socket.to_str().unwrap(),
            "--expect",
            "EACCES"
        ]),
    ]);
    let run = c.run(&Value::from(steps), &Release::Valid);
    drop(listener);
    assert_eq!(
        run.code(),
        Some(0),
        "the fixture's expectations held: {}",
        explain(&run)
    );
    assert_eq!(refused.stop().len(), 0, "the refused origin saw nothing");
    let _ = allowed.stop();
    common::assert_run_records(&run);
    assert_kinds(&run, Profile::Agent, OBSERVED_KINDS);
    assert_kinds(
        &run,
        Profile::Agent,
        &[
            "proxy net.connect proxy_close allow",
            "proxy net.connect proxy_close deny",
            "audit fs.deny syscall_return net.connect",
        ],
    );
    assert_eq!(
        control_kinds(&run),
        ["prepared", "exec_confirmed", "settled"]
    );
}

/// A gate the owner answers with the wrong policy digest refuses (§8.2): the
/// refused receipt, the trace ending on its note and the transcript
/// `prepared, refused` pass the same contract, and the target never ran.
#[test]
fn j5_a_refused_release_writes_records_that_pass_the_frozen_contract() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, &[]);
    let marker = format!("{}/ran.txt", c.base());
    let steps = serde_json::json!([["open", marker, "--create", "--write"]]);
    let run = c.run(
        &steps,
        &Release::WrongDigest(format!("sha256:{}", "0".repeat(64))),
    );
    assert_eq!(
        run.code(),
        Some(125),
        "a gate refusal: {}",
        run.stderr_text()
    );
    assert!(!Path::new(&marker).exists(), "the target never ran");
    common::assert_run_records(&run);
    assert_eq!(control_kinds(&run), ["prepared", "refused"]);
    let refused = run.receipt_phase("refused").expect("a refused receipt");
    assert_eq!(refused["outcome"]["error"]["code"], "gate_invalid");
    assert!(
        kinds(&run).iter().all(|kind| !kind.starts_with("audit ")),
        "nothing ran, so nothing was observed: {:#?}",
        kinds(&run)
    );
}

/// `--observe off` (O05): no audit source at all, and what the wrapper and
/// the receipt say still passes the contract. The fixture ends within
/// milliseconds, so without an observer its exec is sometimes confirmed and
/// sometimes not (measured on the reference host: unconfirmed in each of 8
/// runs after the other tests of this file, confirmed in the one run alone);
/// both are valid records.
#[test]
fn j5_observation_off_records_pass_the_frozen_contract() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, &["--observe", "off"]);
    let steps = Value::from(steps(&c));
    let run = c.run(&steps, &Release::Valid);
    common::assert_run_records(&run);
    // Without an observer a target that ends quickly can end before its exec
    // is confirmed: the outcome is then `unknown` and the run exits 1 (§6.4, a
    // post-launch tool failure), which the records must say consistently.
    let settled = run.receipt_phase("settled").expect("a settled receipt");
    match settled["outcome"]["kind"].as_str() {
        Some("exited") => assert_eq!(run.code(), Some(0), "{}", explain(&run)),
        Some("unknown") => assert_eq!(run.code(), Some(1), "{}", explain(&run)),
        other => panic!("an unexpected outcome {other:?}: {}", explain(&run)),
    }
    let found = kinds(&run);
    assert!(
        found.iter().all(|kind| !kind.starts_with("audit ")),
        "observation off emits no audit source: {found:#?}"
    );
    assert_kinds(
        &run,
        Profile::Tool,
        &[
            "wrapper note wrapper lifecycle",
            "wrapper jail.receipt wrapper -",
        ],
    );
}
