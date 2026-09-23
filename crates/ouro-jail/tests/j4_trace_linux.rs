//! J4 slice T, live: R03's trace half on the reference host.
//!
//! jail-v1 §15 R03: "Trace partial writes, consumer disconnect, saturation and
//! control backpressure cannot block deadline enforcement." §13.3: broken
//! pipe, partial-record write followed by failure, queue overflow or deadline
//! expiry is evidence loss; strict mode stops the tree, best-effort continues
//! with the sink marked lost; the local trace is capped and payload exhaustion
//! is evidence loss; a truncated last frame is recognisable at readback.
//!
//! Every test runs the real jail around the real fixture under `tool`, with
//! the trace consumer played by the harness: one that never reads, one that
//! leaves mid-frame, the local file under a shrunk cap (the S9 seam
//! `OURO_JAIL_TEST_TRACE_CAP`), and the local file under `RLIMIT_FSIZE`.
//! Run with `--test-threads=1`: the ptrace observer owns `waitpid(-1)`.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_fixture::harness::{Jail, Run, TraceConsumer, TraceState, read_frames};
use serde_json::Value;

mod common;
use common::live;

/// A workspace holding a copy of the fixture, which must live inside a
/// declared root to run in the jail.
fn workspace_with_fixture(root: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace is created");
    let inside = workspace.join("ouro-fixture");
    std::fs::copy(ouro_fixture::harness::fixture_path(), &inside).expect("the fixture is copied");
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o755))
        .expect("the fixture is executable");
    (workspace, inside)
}

/// A run that makes `opens` closed-set events (one `fs.create` each, with a
/// long path so that each frame is several hundred bytes), then sleeps.
struct Case {
    jail: Jail,
    argv: Vec<OsString>,
}

fn case(evidence: &str, opens: usize, sleep_ms: u64) -> Case {
    let jail = Jail::new().expect("a private jail harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let long = "n".repeat(160);
    let mut steps: Vec<Value> = (0..opens)
        .map(|index| {
            let path = workspace.join(format!("{long}{index}"));
            serde_json::json!(["open", path.to_str().unwrap(), "--create", "--write"])
        })
        .collect();
    steps.push(serde_json::json!(["sleep", sleep_ms.to_string()]));
    let script = workspace.join("pressure.json");
    std::fs::write(&script, serde_json::to_vec(&steps).unwrap()).expect("the script");
    let jail = jail
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .args(["--evidence", evidence])
        .control();
    Case {
        jail,
        argv: vec![fixture.into(), "script".into(), script.into()],
    }
}

impl Case {
    fn run(self, configure: impl FnOnce(Jail) -> Jail) -> (Run, Duration) {
        let started = Instant::now();
        let run = configure(self.jail)
            .timeout(Duration::from_secs(90))
            .target(self.argv)
            .run()
            .expect("the jail runs");
        let elapsed = started.elapsed();
        eprintln!(
            "j4-trace: exit {:?} after {elapsed:?}; fd trace {} bytes {:?}; local traces {:?}",
            run.code(),
            run.trace_bytes.len(),
            run.trace_readback
                .as_ref()
                .map(|readback| (readback.state, readback.frames.len())),
            run.local_traces()
                .iter()
                .map(|(path, readback)| (
                    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0),
                    readback.state,
                    readback.frames.len()
                ))
                .collect::<Vec<_>>()
        );
        (run, elapsed)
    }
}

/// The receipt the attempt ended with (`jail.json` holds the latest),
/// checked against the schema and the rules it cannot state
/// (`common::check_receipt`), as every receipt of the run is.
fn last_receipt(run: &Run) -> Value {
    let mut receipts: Vec<Value> = run
        .receipts()
        .into_iter()
        .map(common::checked_receipt)
        .collect();
    receipts
        .pop()
        .unwrap_or_else(|| panic!("no receipt; stderr: {}", run.stderr_text()))
}

fn field<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value
        .pointer(pointer)
        .unwrap_or_else(|| panic!("{pointer} is absent from {value:#}"))
}

fn evidence_errors(receipt: &Value) -> Vec<String> {
    field(receipt, "/errors")
        .as_array()
        .unwrap()
        .iter()
        .filter(|error| error["code"] == "evidence_lost")
        .map(|error| error["message"].as_str().unwrap_or("").to_owned())
        .collect()
}

fn is_transport_gap(frame: &Value) -> bool {
    frame.pointer("/fields/kind").and_then(Value::as_str) == Some("coverage_gap")
        && frame.pointer("/fields/reason").and_then(Value::as_str) == Some("trace_transport_loss")
}

/// The stop was the evidence loss, early, not the target's own end.
fn assert_strict_stop(run: &Run, elapsed: Duration, what: &str) {
    let receipt = last_receipt(run);
    assert_eq!(
        field(&receipt, "/outcome/cause"),
        "evidence_loss",
        "{what}: strict must stop on the loss: {receipt:#}"
    );
    assert!(
        !evidence_errors(&receipt).is_empty(),
        "{what}: the loss is in the receipt: {receipt:#}"
    );
    assert_eq!(
        field(&receipt, "/coverage/fs.write/status"),
        "degraded",
        "{what}: {receipt:#}"
    );
    assert_eq!(
        run.code(),
        Some(1),
        "{what}: a post-exec loss is a tool error"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "{what}: the 30 s target was stopped, not waited for ({elapsed:?})"
    );
    assert_eq!(field(&receipt, "/lifetime/tree_empty"), true, "{what}");
}

/// Best-effort let the target finish on its own and reported the loss.
fn assert_best_effort_continued(run: &Run, what: &str) {
    let receipt = last_receipt(run);
    assert_eq!(field(&receipt, "/phase"), "settled", "{what}: {receipt:#}");
    assert_eq!(field(&receipt, "/outcome/kind"), "exited", "{what}");
    assert_eq!(field(&receipt, "/outcome/code"), 0, "{what}");
    assert_eq!(
        field(&receipt, "/outcome/cause"),
        &Value::Null,
        "{what}: nothing stopped the target: {receipt:#}"
    );
    assert!(
        !evidence_errors(&receipt).is_empty(),
        "{what}: the loss is in the receipt: {receipt:#}"
    );
    assert_eq!(field(&receipt, "/coverage/fs.write/status"), "degraded");
    assert_eq!(
        field(&receipt, "/coverage/fs.write/observed_count"),
        &Value::Null,
        "{what}: a degraded count is null, never a partial number"
    );
    assert_eq!(
        run.code(),
        Some(1),
        "{what}: evidence loss is still a tool error"
    );
    let fixture_ok = run
        .fixture_lines()
        .iter()
        .filter(|line| line["op"] == "sleep")
        .count();
    assert_eq!(fixture_ok, 1, "{what}: the target reached its last step");
}

/// Whatever the consumer took is a prefix of frames, possibly with a torn
/// last line, and never a torn frame followed by more.
fn assert_recognisable(run: &Run, what: &str) {
    let readback = run.trace_readback.as_ref().expect("a trace fd was used");
    assert_ne!(
        readback.state,
        TraceState::Corrupt,
        "{what}: a torn frame was followed by more bytes"
    );
    assert!(!readback.frames.is_empty(), "{what}: the prefix is there");
}

// ------------------------------------------------------------- saturation

#[test]
fn j4_r03_saturation_strict_stops() {
    if !live() {
        return;
    }
    let (run, elapsed) =
        case("strict", 400, 30_000).run(|jail| jail.trace_consumer(TraceConsumer::Never));
    assert_strict_stop(&run, elapsed, "a consumer that never reads");
    assert_recognisable(&run, "saturation");
}

#[test]
fn j4_r03_saturation_best_effort_continues() {
    if !live() {
        return;
    }
    // The target outlives the one-second no-progress deadline.
    let (run, _) =
        case("best-effort", 400, 2_500).run(|jail| jail.trace_consumer(TraceConsumer::Never));
    assert_best_effort_continued(&run, "a consumer that never reads");
    assert_recognisable(&run, "saturation");
}

// ------------------------------------------------------------- disconnect

/// Mid-frame for any frame longer than a few bytes: the consumer takes the
/// first 5000 bytes and closes its end.
const LEAVE_AFTER: usize = 5_000;

#[test]
fn j4_r03_disconnect_strict_stops() {
    if !live() {
        return;
    }
    let (run, elapsed) = case("strict", 400, 30_000)
        .run(|jail| jail.trace_consumer(TraceConsumer::CloseAfter(LEAVE_AFTER)));
    assert_strict_stop(&run, elapsed, "a consumer that left");
    assert_eq!(run.trace_bytes.len(), LEAVE_AFTER);
    assert_recognisable(&run, "disconnect");
}

#[test]
fn j4_r03_disconnect_best_effort_continues() {
    if !live() {
        return;
    }
    let (run, _) = case("best-effort", 400, 500)
        .run(|jail| jail.trace_consumer(TraceConsumer::CloseAfter(LEAVE_AFTER)));
    assert_best_effort_continued(&run, "a consumer that left");
    assert_eq!(run.trace_bytes.len(), LEAVE_AFTER);
    assert_recognisable(&run, "disconnect");
}

// ------------------------------------------------- deadline under pressure

#[test]
fn j4_r03_the_wall_is_enforced_while_the_trace_is_saturated() {
    if !live() {
        return;
    }
    // Best-effort, so the saturation itself does not stop the attempt: only
    // the wall can, and it must not wait for the trace.
    let (run, elapsed) = case("best-effort", 400, 30_000).run(|jail| {
        jail.trace_consumer(TraceConsumer::Never)
            .args(["--limit", "wall=2s"])
    });
    let receipt = last_receipt(&run);
    assert_eq!(
        field(&receipt, "/outcome/cause"),
        "wall_expiry",
        "{receipt:#}"
    );
    assert_eq!(field(&receipt, "/outcome/kind"), "signaled");
    assert_eq!(
        field(&receipt, "/outcome/signal"),
        i64::from(libc::SIGTERM),
        "the cooperative stop reached the target"
    );
    assert!(
        !evidence_errors(&receipt).is_empty(),
        "the trace was saturated before the wall fired: {receipt:#}"
    );
    // Startup, a 2 s wall, the stop and settlement. A supervisor waiting on
    // the trace would sit here until the target's own 30 s end.
    assert!(
        elapsed < Duration::from_secs(8),
        "the wall fired late under trace saturation: {elapsed:?}"
    );
    assert_eq!(field(&receipt, "/lifetime/tree_empty"), true);
    assert_recognisable(&run, "saturation under the wall");
}

#[test]
fn j4_r03_the_wall_is_enforced_while_the_trace_queue_is_full() {
    if !live() {
        return;
    }
    // Enough events (~630 bytes each) to fill the pipe and then the whole
    // 4 MiB external queue behind it, so every flush the supervision loop
    // makes finds the most bytes it can ever find queued (N3).
    let (run, elapsed) = case("best-effort", 8_000, 30_000).run(|jail| {
        jail.trace_consumer(TraceConsumer::Never)
            .args(["--limit", "wall=3s"])
    });
    let receipt = last_receipt(&run);
    assert_eq!(
        field(&receipt, "/outcome/cause"),
        "wall_expiry",
        "{receipt:#}"
    );
    assert!(!evidence_errors(&receipt).is_empty(), "{receipt:#}");
    assert!(
        elapsed < Duration::from_secs(9),
        "the wall fired late behind a full trace queue: {elapsed:?}"
    );
    assert_recognisable(&run, "a full queue under the wall");
}

// ------------------------------------------------------- local trace, S9 cap

/// A local cap small enough for 400 events to exhaust its payload.
const SHRUNK_CAP: u64 = 16 * 1024;

fn local_trace(run: &Run) -> (PathBuf, ouro_fixture::harness::Readback, u64) {
    let mut traces = run.local_traces();
    assert_eq!(traces.len(), 1, "one attempt, one local trace");
    let (path, readback) = traces.remove(0);
    let size = std::fs::metadata(&path).unwrap().len();
    (path, readback, size)
}

/// The local trace is a prefix of ordinary frames, then only reserve notes:
/// the transport gap note first, the final receipt note last.
fn assert_prefix_then_notes(readback: &ouro_fixture::harness::Readback, what: &str) {
    assert_eq!(readback.state, TraceState::Complete, "{what}");
    let gap = readback
        .frames
        .iter()
        .position(is_transport_gap)
        .unwrap_or_else(|| panic!("{what}: no transport gap note"));
    assert_eq!(
        readback
            .frames
            .iter()
            .filter(|frame| is_transport_gap(frame))
            .count(),
        1,
        "{what}: one note for the loss"
    );
    for frame in &readback.frames[gap + 1..] {
        let reserve = frame["operation"] == "jail.receipt"
            || frame.pointer("/fields/kind").and_then(Value::as_str) == Some("coverage_gap");
        assert!(
            reserve,
            "{what}: an ordinary frame followed the loss note: {frame}"
        );
    }
    assert_eq!(
        readback.last_receipt_note().map(|(phase, _)| phase),
        Some("settled"),
        "{what}: the final receipt note used the reserve"
    );
}

#[test]
fn j4_r03_local_cap_strict_stops() {
    if !live() {
        return;
    }
    let (run, elapsed) = case("strict", 400, 30_000)
        .run(|jail| jail.env("OURO_JAIL_TEST_TRACE_CAP", SHRUNK_CAP.to_string()));
    assert_strict_stop(&run, elapsed, "the local cap");
    let receipt = last_receipt(&run);
    assert!(
        evidence_errors(&receipt)
            .iter()
            .any(|message| message.contains("OURO_JAIL_TEST_TRACE_CAP")
                && message.contains(&SHRUNK_CAP.to_string())),
        "S9: the receipt names the seam that shrank the cap: {receipt:#}"
    );
    let (_, readback, size) = local_trace(&run);
    assert!(size <= SHRUNK_CAP, "the cap held: {size} bytes");
    assert_prefix_then_notes(&readback, "strict local cap");
}

#[test]
fn j4_r03_local_cap_best_effort_keeps_a_prefix_and_reserve_notes() {
    if !live() {
        return;
    }
    let (run, _) = case("best-effort", 400, 200)
        .run(|jail| jail.env("OURO_JAIL_TEST_TRACE_CAP", SHRUNK_CAP.to_string()));
    assert_best_effort_continued(&run, "the local cap");
    let (_, readback, size) = local_trace(&run);
    assert!(size <= SHRUNK_CAP, "the cap held: {size} bytes");
    assert!(
        size > SHRUNK_CAP / 2,
        "the payload half was used before the loss: {size} bytes"
    );
    assert_prefix_then_notes(&readback, "best-effort local cap");
    let audit = readback
        .frames
        .iter()
        .filter(|frame| frame["source"] == "audit")
        .count();
    assert!(
        audit > 0 && audit < 400,
        "a prefix of the audit events: {audit}"
    );
}

// -------------------------------------------- local trace, a real write failure

#[test]
fn j4_r03_a_local_write_failure_is_loss_and_never_tears_the_trace() {
    if !live() {
        return;
    }
    // RLIMIT_FSIZE with SIGXFSZ ignored: the trace write that crosses the
    // limit is short and the next fails with EFBIG. Receipts are separate,
    // smaller files and stay under the limit.
    let limit = 64 * 1024;
    for evidence in ["strict", "best-effort"] {
        let sleep = if evidence == "strict" { 30_000 } else { 200 };
        let (run, elapsed) = case(evidence, 400, sleep).run(|jail| jail.file_size_limit(limit));
        if evidence == "strict" {
            assert_strict_stop(&run, elapsed, "a failed local write");
        } else {
            assert_best_effort_continued(&run, "a failed local write");
        }
        let receipt = last_receipt(&run);
        assert!(
            evidence_errors(&receipt)
                .iter()
                .any(|message| message.contains("local trace write failed")),
            "{evidence}: the write failure is the recorded loss: {receipt:#}"
        );
        let (_, readback, size) = local_trace(&run);
        assert!(size <= limit, "{evidence}: {size} bytes");
        assert_ne!(
            readback.state,
            TraceState::Corrupt,
            "{evidence}: a torn frame in the middle of the trace"
        );
        assert_eq!(
            readback.state,
            TraceState::Complete,
            "{evidence}: the failed write was cut back to its frame boundary"
        );
        assert!(readback.frames.len() > 10, "{evidence}: the prefix is kept");
    }
}

// ---------------------------------------------------- no local duplicate

#[test]
fn j4_r03_a_trace_fd_is_not_duplicated_locally() {
    if !live() {
        return;
    }
    let (run, _) = case("strict", 20, 0).run(Jail::trace);
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let audit = run
        .trace_events()
        .iter()
        .filter(|event| event["source"] == "audit")
        .count();
    assert!(audit >= 20, "the fd carried the audit events: {audit}");
    assert!(
        run.local_traces().is_empty(),
        "§13.3: with --trace-fd there is no local trace.ndjson"
    );
    // Nor any other local file holding the stream.
    let mut stack = vec![run.data_dir.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                assert!(
                    read_frames(&bytes)
                        .frames
                        .iter()
                        .all(|frame| frame["source"] != "audit"),
                    "{} holds audit frames",
                    path.display()
                );
            }
        }
    }
}
