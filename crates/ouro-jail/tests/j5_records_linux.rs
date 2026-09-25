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

use ouro_fixture::harness::{self, HttpServer, Jail, Release, Run, TraceConsumer};
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
    case_with(profile, "strict", extra)
}

fn case_with(profile: Profile, evidence: &str, extra: &[&str]) -> Case {
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

/// J5-C review item 15, live: a real trace transport loss. The consumer reads
/// at most a pipeful at a time and pauses past the one-second no-progress
/// deadline (§13.3), so the stream loses frames; best-effort lets the target
/// finish, and the consumer comes back for the reserve notes. The loss note names the classes
/// this `tool` attempt covers (no `proxy.net`), and the settled receipt
/// records the same loss from the same start as a wrapper loss: the whole
/// contract, `trace_loss_recorded` included, holds on the live records.
#[test]
fn j5_a_trace_loss_note_and_its_receipt_agree() {
    if !Profile::Tool.available() {
        return;
    }
    let mut c = case_with(Profile::Tool, "best-effort", &[]);
    let base = c.base();
    // About 80 KB of results: more than the 64 KiB pipe, so frames wait in
    // the queue while the consumer pauses past the deadline; few enough that
    // its next read takes the rest, loss note included, long before the
    // target's end, so the terminal drain finds nothing queued and the final
    // receipt note completes the stream.
    let mut steps: Vec<Value> = (0..150)
        .map(|index| serde_json::json!(["open", format!("{base}/f{index}"), "--create", "--write"]))
        .collect();
    steps.push(serde_json::json!(["sleep", "3000"]));
    c.jail = c.jail.trace_consumer(TraceConsumer::Slow {
        chunk: 64 * 1024,
        pause: std::time::Duration::from_millis(1500),
    });
    let run = c.run(&Value::from(steps), &Release::Valid);
    assert_eq!(
        run.code(),
        Some(1),
        "evidence loss is a tool error: {}",
        explain(&run)
    );
    common::assert_run_records(&run);
    let note = run
        .trace_events()
        .iter()
        .find(|event| event["fields"]["reason"] == "trace_transport_loss")
        .unwrap_or_else(|| panic!("no loss note: {}", explain(&run)))
        .clone();
    assert_eq!(
        note["fields"]["classes"],
        serde_json::json!(["exec", "fs.write", "fs.deny", "net"]),
        "the note names what this attempt covers"
    );
    let settled = run.receipt_phase("settled").expect("a settled receipt");
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let gap = settled["coverage"][class]["gaps"]
            .as_array()
            .and_then(|gaps| {
                gaps.iter()
                    .find(|gap| gap["reason"] == "trace_transport_loss")
            })
            .unwrap_or_else(|| panic!("{class}: no loss gap: {:#}", settled["coverage"]));
        assert_eq!(gap["source"], "wrapper", "{class}: {gap}");
        assert_eq!(
            gap["start_ns"], note["fields"]["start_ns"],
            "{class}: {gap}"
        );
    }
}

/// J5-C wave 3, R03.5 "Trace partial writes ... cannot block deadline
/// enforcement", one run with a consumer that reads 4 KiB and then pauses
/// `pause_ms`: every trace frame reaches the consumer in several partial
/// writes (the test seam `OURO_JAIL_TEST_TRACE_FD_WRITE_MAX=64` caps each
/// `write(2)` of the `--trace-fd` sink at 64 bytes, and every frame is longer),
/// the target produces results for longer than its 2 s wall and then sleeps
/// 30 s, and the consumer is slow but live (its pause stays inside the sink's
/// one-second no-progress deadline). The wall still fires on time:
/// the run ends within seconds, the receipt's cause is `wall_expiry` with the
/// wall's `hit` recorded, and, when the stream is complete, the target's own
/// `proc.exit` lies within 3.5 s of its exec on the product's clock. The trace
/// is every frame reassembled from its pieces (the whole contract holds), or,
/// when the terminal drain could not deliver the backlog within its budget,
/// visibly incomplete with the loss in the receipt; never corrupt.
/// Seconds since the epoch of an RFC 3339 UTC time as the product writes it
/// (`YYYY-MM-DDThh:mm:ssZ`, `records::rfc3339_utc`).
fn rfc3339_seconds(text: &str) -> i64 {
    let number = |range: std::ops::Range<usize>| -> i64 {
        text.get(range)
            .and_then(|part| part.parse().ok())
            .unwrap_or_else(|| panic!("not an RFC 3339 UTC time: {text}"))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    // Howard Hinnant's days_from_civil.
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days * 86_400 + number(11..13) * 3600 + number(14..16) * 60 + number(17..19)
}

#[test]
fn rfc3339_seconds_matches_known_times() {
    assert_eq!(rfc3339_seconds("1970-01-01T00:00:00Z"), 0);
    assert_eq!(rfc3339_seconds("2000-02-29T23:59:59Z"), 951_868_799);
    assert_eq!(rfc3339_seconds("2026-09-25T00:15:36Z"), 1_790_295_336);
}

/// Returns the trace's state and how many whole frames reached the consumer.
fn wall_under_partial_writes(pause_ms: u64) -> (ouro_fixture::harness::TraceState, usize) {
    const WRITE_MAX: usize = 64;
    let mut c = case_with(Profile::Tool, "best-effort", &["--limit", "wall=2s"]);
    let base = c.base();
    let mut steps: Vec<Value> = Vec::new();
    for batch in 0..40 {
        for index in 0..30 {
            steps.push(serde_json::json!([
                "open",
                format!("{base}/b{batch}-{index}"),
                "--create",
                "--write"
            ]));
        }
        steps.push(serde_json::json!(["sleep", "100"]));
    }
    steps.push(serde_json::json!(["sleep", "30000"]));
    c.jail = c
        .jail
        .env(ouro_jail::trace::TRACE_FD_WRITE_SEAM, WRITE_MAX.to_string())
        .trace_consumer(TraceConsumer::Slow {
            chunk: 4096,
            pause: std::time::Duration::from_millis(pause_ms),
        });
    let run = c.run(&Value::from(steps), &Release::Valid);
    let receipts = run.receipts();
    for receipt in &receipts {
        common::check_receipt(receipt).unwrap_or_else(|error| panic!("{error}\n{receipt:#}"));
    }
    let last = receipts.last().expect("a receipt");
    assert_eq!(
        last["outcome"]["cause"], "wall_expiry",
        "{:#}",
        last["outcome"]
    );
    let wall = last["applied"]["limits"]
        .as_array()
        .and_then(|limits| limits.iter().find(|limit| limit["key"] == "wall"))
        .expect("the wall limit");
    assert_eq!(
        wall["hit"], true,
        "the receipt records the wall's hit: {wall}"
    );
    // On the product's own clock (the harness's elapsed time also counts its
    // slow consumer reading what the pipe still holds after the jail exits):
    // the tree was verified dead soon after the 2 s wall, and the final
    // receipt, written after the terminal drain's one-second budget, soon
    // after that. Whole seconds, so the bounds carry a second of rounding.
    assert_eq!(
        last["phase"], "settled",
        "the wall's stop ended the tree and it was verified dead: {:#}",
        last["lifetime"]
    );
    let seconds = |pointer: &str| {
        rfc3339_seconds(
            last.pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{pointer}: {last:#}")),
        )
    };
    let created = seconds("/created_at");
    assert!(
        seconds("/lifetime/verified_at") - created <= 4,
        "the tree died {} s after the attempt began: the wall was late",
        seconds("/lifetime/verified_at") - created
    );
    assert!(
        seconds("/updated_at") - created <= 6,
        "the final receipt came {} s after the attempt began",
        seconds("/updated_at") - created
    );
    assert_eq!(
        last["lifetime"]["native"]["details"]["test_seams"][ouro_jail::trace::TRACE_FD_WRITE_SEAM],
        WRITE_MAX.to_string(),
        "the seam is recorded in the receipt"
    );
    let readback = run.trace_readback.as_ref().expect("a trace fd was used");
    // Every frame the consumer got was longer than one write: each was
    // reassembled from its pieces at their offsets.
    for frame in &readback.frames {
        let length = serde_json::to_vec(frame).expect("serializes").len();
        assert!(length > WRITE_MAX, "a {length}-byte frame fits one write");
    }
    match readback.state {
        ouro_fixture::harness::TraceState::Complete => {
            common::assert_run_records(&run);
            let events = run.trace_events();
            let lost = events
                .iter()
                .any(|event| event["fields"]["reason"] == "trace_transport_loss");
            if lost {
                // A complete stream that records its own loss (the loss note
                // and the final notes came through; frames in between did
                // not, and `trace_loss_recorded` held): the receipt says so.
                assert!(
                    last["errors"].as_array().is_some_and(|errors| errors
                        .iter()
                        .any(|error| error["code"] == "evidence_lost")),
                    "a recorded trace loss is an evidence_lost error: {:#}",
                    last["errors"]
                );
                eprintln!(
                    "complete with a recorded loss: {} frames",
                    readback.frames.len()
                );
                return (readback.state, readback.frames.len());
            }
            let at = |pick: &dyn Fn(&Value) -> bool| -> u128 {
                events
                    .iter()
                    .find(|event| pick(event))
                    .and_then(|event| event["monotonic_ns"].as_str())
                    .and_then(|ns| ns.parse().ok())
                    .unwrap_or_else(|| panic!("the event is missing from the trace"))
            };
            let target = last["process"]["pid"].as_i64().expect("the target's pid");
            let exec = at(&|event| event["fields"]["transition"] == "exec_confirmed");
            let exit = at(&|event| {
                event["operation"] == "proc.exit" && event["fields"]["pid"].as_i64() == Some(target)
            });
            assert!(
                exit.saturating_sub(exec) < 3_500_000_000,
                "the target ended {} ms after its exec: the wall was late",
                exit.saturating_sub(exec) / 1_000_000
            );
            eprintln!(
                "complete: {} frames, target lifetime {} ms",
                readback.frames.len(),
                exit.saturating_sub(exec) / 1_000_000
            );
        }
        ouro_fixture::harness::TraceState::Incomplete => {
            // Honestly marked: a visibly incomplete tail, and the loss in the
            // receipt, never a silent one.
            assert!(
                last["errors"].as_array().is_some_and(|errors| errors
                    .iter()
                    .any(|error| error["code"] == "evidence_lost")),
                "an incomplete trace is an evidence_lost error: {:#}",
                last["errors"]
            );
            assert_eq!(last["observer"]["sources"]["wrapper"], "degraded");
            for frame in &readback.frames {
                let errors: Vec<String> = common::validators()["jail-event"]
                    .iter_errors(frame)
                    .map(|error| error.to_string())
                    .collect();
                assert!(
                    errors.is_empty(),
                    "a delivered frame is a valid event: {errors:?}"
                );
            }
            eprintln!(
                "incomplete (the drain budget ran out): {} frames delivered",
                readback.frames.len()
            );
        }
        other => panic!("the trace is {other:?}"),
    }
    (readback.state, readback.frames.len())
}

/// The consumer keeps up (a 4 KiB read every 20 ms): the backlog is small,
/// the terminal drain delivers it, and the trace is every frame reassembled
/// from its pieces, with the target's own end 2 s after its exec.
#[test]
fn j5_r03_a_wall_fires_on_time_while_every_trace_frame_is_written_in_pieces() {
    if !Profile::Tool.available() {
        return;
    }
    assert_eq!(
        wall_under_partial_writes(20).0,
        ouro_fixture::harness::TraceState::Complete,
        "a consumer that keeps up gets every frame"
    );
}

/// The consumer stalls but stays live (a 4 KiB read every 700 ms, inside the
/// one-second no-progress deadline): the pipe stays full, so the writer waits
/// with a frame partly written while the wall comes due. The wall fires on
/// time all the same; the backlog cannot be delivered within the terminal
/// drain's budget, so the trace ends visibly incomplete (or complete with its
/// loss recorded) and the receipt says so, after a prefix of whole frames. A
/// writer that blocked on its consumer would hold the supervisor for as long
/// as the consumer stalls (the mutation replay's M4: the wall came 40 s late
/// and the tree was never verified).
#[test]
fn j5_r03_a_wall_fires_on_time_while_a_stalled_consumer_holds_a_partial_frame() {
    if !Profile::Tool.available() {
        return;
    }
    let (state, frames) = wall_under_partial_writes(700);
    assert_ne!(state, ouro_fixture::harness::TraceState::Corrupt);
    // At least half a pipe of frames reached the consumer intact: an
    // incomplete tail is honest only after a prefix of whole frames.
    assert!(frames >= 64, "only {frames} whole frames were delivered");
}

// ===========================================================================
// J5-C, R01.5: the integrity (pending, lost) and unknown-exec settlement
// tuples, as the real jail writes them
// ===========================================================================
//
// jail-v1 §13.2: "`lifetime.integrity` is `pending` before a boundary is
// validated, `verified` when its identity and the claimed scope have been
// checked, or `lost` after detected tampering/escape"; "Lost integrity
// requires null tree result/time and forbids settlement/cleanup"; "Verified
// settlement with unknown exec evidence is valid". The corpus (R01.1) shows
// the schema accepts those tuples; these runs show the real jail writes them,
// each held to the whole frozen contract.

const PYTHON: &str = "/usr/bin/python3";

fn error_codes(receipt: &Value) -> Vec<String> {
    receipt["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .filter_map(|error| error["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A private workspace in `jail`'s root.
fn private_workspace(jail: &Jail) -> PathBuf {
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    workspace
}

/// R01.5, integrity pending: §13.2's "Refusal before boundary creation" row.
/// stdin is a directory, which a contained run refuses in preparation
/// (§8.3), before any boundary exists: phase `refused`, containment and
/// protection `pending`, no exec, boundary `pending` with no native identity,
/// no scope, no tree result or time, and integrity `pending`.
#[test]
fn j5_r01_a_refusal_before_the_boundary_carries_integrity_pending() {
    if !Profile::Tool.available() {
        return;
    }
    let jail = Jail::with_program("/bin/sh")
        .expect("a private harness")
        .args(["-c", "exec \"$0\" \"$@\" </"])
        .arg(harness::jail_path());
    let workspace = private_workspace(&jail);
    let marker = jail.root().join("target-ran");
    let run = jail
        .arg("run")
        .args(["--profile", "tool", "--workspace"])
        .arg(&workspace)
        .trace()
        .control()
        .receipt()
        .target(["/bin/sh", "-c", &format!("touch {}", marker.display())])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(125), "{}", explain(&run));
    assert!(!marker.exists(), "the target ran");
    common::assert_run_records(&run);
    let receipts = run.receipts();
    assert!(
        receipts.len() >= 2,
        "the canonical receipt and the --receipt copy: {receipts:#?}"
    );
    for receipt in &receipts {
        assert_eq!(receipt["phase"], "refused", "{receipt:#}");
        assert_eq!(receipt["containment"], "pending", "{receipt:#}");
        assert_eq!(receipt["child_protection"], "pending", "{receipt:#}");
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(
            receipt["lifetime"],
            serde_json::json!({
                "boundary": "pending",
                "native": null,
                "tree_empty": null,
                "verified_at": null,
                "verification_scope": null,
                "integrity": "pending",
            }),
            "{receipt:#}"
        );
        assert_eq!(receipt["applied"]["network"]["mode"], "pending");
        assert_eq!(receipt["outcome"]["kind"], "refused");
        assert_eq!(receipt["outcome"]["error"]["code"], "invalid_fd");
        assert_eq!(receipt["outcome"]["error"]["stage"], "preparing");
    }
    let refused = run.control_kind("refused");
    assert_eq!(refused.len(), 1, "{:?}", control_kinds(&run));
    assert_eq!(refused[0]["receipt_phase"], "refused");
}

/// A cgroup this test creates beside the attempt leaves under the operator's
/// delegated subtree: the kind of cgroup an uncontained child can create for
/// itself and move into. Removed with the test; only the attempt's own target
/// is ever in it.
struct Destination {
    path: PathBuf,
}

impl Destination {
    fn new(tag: &str) -> Destination {
        // SAFETY: getuid takes no arguments and cannot fail.
        let root = ouro_jail::platform::linux::cgroup::delegated_root(unsafe { libc::getuid() })
            .expect("the delegated subtree exists");
        let path = root.join(format!("ouro-j5c-{tag}-{}", std::process::id()));
        std::fs::create_dir(&path).expect("a destination cgroup");
        Destination { path }
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        // Only the attempt's own target can be here: the test made this cgroup.
        if populated(&self.path) {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while populated(&self.path) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn populated(cgroup: &Path) -> bool {
    std::fs::read_to_string(cgroup.join("cgroup.events"))
        .is_ok_and(|events| events.lines().any(|line| line == "populated 1"))
}

/// The attempt leaf a receipt registered, removed once it is checked to be
/// that leaf (its pinned inode) and empty: the jail retains it after a loss
/// (§14.2), so the test that caused the loss removes it.
fn remove_retained_leaf(receipt: &Value) {
    use std::os::unix::fs::MetadataExt as _;
    let leaf = &receipt["lifetime"]["native"]["details"]["execution_cgroup"];
    let path = PathBuf::from(leaf["path"].as_str().expect("a leaf path"));
    let inode = leaf["inode"].as_u64().expect("a leaf inode");
    if std::fs::metadata(&path).is_ok_and(|meta| meta.ino() == inode) && !populated(&path) {
        std::fs::remove_dir(&path).expect("the empty retained leaf is removed");
    }
}

/// The §13.2 lost tuple: no tree result or time, never settled, cleanup never
/// complete, and the unknown tree reported.
fn assert_lost_tuple(receipt: &Value) {
    assert_ne!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(receipt["containment"], "none");
    assert_eq!(receipt["child_protection"], "unprotected");
    let lifetime = &receipt["lifetime"];
    assert_eq!(lifetime["integrity"], "lost", "{receipt:#}");
    assert_eq!(lifetime["boundary"], "supervisor_cgroup");
    assert_eq!(lifetime["verification_scope"], "registered_boundary");
    assert_eq!(lifetime["tree_empty"], Value::Null);
    assert_eq!(lifetime["verified_at"], Value::Null);
    assert_ne!(receipt["state_cleanup"], "complete");
}

/// R01.5, integrity lost: a `none` target moves itself out of its leaf into a
/// cgroup of its own and stays alive until the test lets it exit 7. The
/// escape reaches the receipt while it runs (§9.3, P7), and the final receipt
/// keeps the lost tuple with the target's own exit.
#[test]
fn j5_r01_a_detected_escape_carries_integrity_lost() {
    if !Profile::None.available() {
        return;
    }
    let destination = Destination::new("escape");
    let jail = Jail::new().expect("a private harness");
    let workspace = private_workspace(&jail);
    let moved = jail.root().join("moved");
    let go = jail.root().join("go");
    let code = format!(
        "import os, time\n\
         open({dest:?}, 'w').write('0')\n\
         open({moved:?}, 'w').write(str(os.getpid()))\n\
         for _ in range(3000):\n\
         \x20   if os.path.exists({go:?}): break\n\
         \x20   time.sleep(0.01)\n\
         os._exit(7)\n",
        dest = destination.path.join("cgroup.procs").to_str().unwrap(),
        moved = moved.to_str().unwrap(),
        go = go.to_str().unwrap(),
    );
    let spawned = jail
        .arg("run")
        .args(["--profile", "none", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .trace()
        .control()
        .receipt()
        .target([PYTHON, "-c", &code])
        .spawn()
        .expect("the jail starts");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let running = loop {
        let latest = spawned.receipt_value().unwrap_or(Value::Null);
        if latest["lifetime"]["integrity"] == "lost" {
            break latest;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no receipt recorded the escape; the latest: {latest:#}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    // While the target runs, from the receipt written when the loss was seen.
    let running = common::checked_receipt(running);
    assert!(moved.exists() && !go.exists());
    assert_lost_tuple(&running);
    assert_eq!(running["phase"], "enforced", "{running:#}");
    assert_eq!(running["outcome"]["kind"], "pending", "{running:#}");
    std::fs::write(&go, b"").unwrap();
    let run = spawned.wait().expect("the jail ends");
    common::assert_run_records(&run);
    assert_eq!(run.code(), Some(1), "{}", explain(&run));
    let last = run
        .receipts()
        .into_iter()
        .max_by_key(|receipt| receipt["revision"].as_u64().unwrap_or(0))
        .expect("a receipt");
    assert_lost_tuple(&last);
    assert_eq!(last["phase"], "enforced");
    assert_eq!(last["exec_observed"], true);
    assert_eq!(last["outcome"]["kind"], "exited", "{last:#}");
    assert_eq!(last["outcome"]["code"], 7);
    assert!(
        error_codes(&last).iter().any(|code| code == "tree_unknown"),
        "{last:#}"
    );
    assert!(run.control_kind("settled").is_empty());
    assert_eq!(run.control_kind("unsettled").len(), 1);
    remove_retained_leaf(&last);
}

/// R01.5, verified settlement with unknown exec evidence. With observation
/// off, exec is confirmed only by the target's executable image differing
/// from the launcher's (§11.2; `check_exec_without_tracer`). The target here
/// is the jail's own binary as bound into the sandbox for the launcher, so
/// the image never differs and nothing independent saw the exec: the tree's
/// end is verified, the attempt settles, `exec_observed` stays false, and the
/// outcome is the coded unknown (§6.4 `exec_unconfirmed`).
#[test]
fn j5_r01_an_exec_the_jail_cannot_confirm_settles_with_exec_unknown() {
    if !Profile::Tool.available() {
        return;
    }
    let jail = Jail::new().expect("a private harness");
    let workspace = private_workspace(&jail);
    let run = jail
        .arg("run")
        .args(["--profile", "tool", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .trace()
        .control()
        .receipt()
        .target([
            ouro_jail::platform::linux::bwrap::JAIL_INSIDE_PATH,
            "version",
        ])
        .run()
        .expect("the jail runs");
    common::assert_run_records(&run);
    assert_eq!(run.code(), Some(1), "{}", explain(&run));
    let receipts = run.receipts();
    assert!(receipts.len() >= 2, "{receipts:#?}");
    for settled in &receipts {
        assert_eq!(settled["phase"], "settled", "{settled:#}");
        assert_eq!(settled["exec_observed"], false, "{settled:#}");
        assert_eq!(settled["containment"], "enforced");
        assert_eq!(settled["child_protection"], "enforced");
        assert_eq!(settled["outcome"]["kind"], "unknown", "{settled:#}");
        assert_eq!(settled["outcome"]["code"], Value::Null);
        assert_eq!(settled["outcome"]["signal"], Value::Null);
        assert!(
            error_codes(settled)
                .iter()
                .any(|code| code == "exec_unconfirmed"),
            "{settled:#}"
        );
        let lifetime = &settled["lifetime"];
        assert_eq!(lifetime["boundary"], "pid_namespace");
        assert_eq!(lifetime["verification_scope"], "attempt_tree");
        assert_eq!(lifetime["integrity"], "verified");
        assert_eq!(lifetime["tree_empty"], true);
        assert!(lifetime["verified_at"].is_string(), "{settled:#}");
    }
    let kinds = control_kinds(&run);
    assert!(
        kinds.iter().any(|kind| kind == "settled"),
        "the attempt settled: {kinds:?}"
    );
    assert!(
        !kinds.iter().any(|kind| kind == "exec_confirmed"),
        "nothing confirmed the exec: {kinds:?}"
    );
    assert!(
        !run.trace_events()
            .iter()
            .any(|event| event["fields"]["transition"] == "exec_confirmed"),
        "the trace confirms no exec"
    );
}
