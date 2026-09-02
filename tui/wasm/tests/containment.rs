//! What `ouro-wasm` actually contains, observed by driving the real binary over a real pipe.
//!
//! Everything here spawns `ouro-wasm serve`, speaks the line protocol to it, and asserts on
//! what came back — never on what the code says it would do. The unit tests already cover the
//! shaping; a helper whose limits parse beautifully and contain nothing is exactly the failure
//! this file exists to catch.
//!
//! Each containment property is its own test, and each one is written to fail loudly rather
//! than quietly: a guest that was supposed to be stopped and was not shows up as a hang against
//! [`REPLY_TIMEOUT`], not as a pass.

mod support;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const HELPER: &str = env!("CARGO_BIN_EXE_ouro-wasm");

/// Generous enough that a debug-build compile of a component is never the reason a test fails,
/// and short enough that a guest which escaped its deadline is reported as a failure rather than
/// hanging the suite until CI's own timeout.
const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Bounds every guest here runs under unless a test is specifically about one of them.
const FUEL: u64 = 1_000_000_000;
const MEMORY_BYTES: u64 = 4 * 1024 * 1024;
const DEADLINE_MS: u64 = 10_000;
/// One wasm page: the smallest grant the helper accepts.
const MIN_MEMORY_BYTES: u64 = 64 * 1024;

// ------------------------------------------------------------------------------- scaffolding

struct Helper {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<String>,
    stderr: Arc<Mutex<String>>,
    next_id: i64,
}

impl Helper {
    fn spawn(extra: &[&str]) -> Helper {
        let mut child = Command::new(HELPER)
            .arg("serve")
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("ouro-wasm starts");

        let stdin = child.stdin.take().expect("stdin is a pipe");
        let stdout = child.stdout.take().expect("stdout is a pipe");
        let stderr = child.stderr.take().expect("stderr is a pipe");

        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    return;
                }
            }
        });

        let log = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                sink.lock().expect("stderr lock").push_str(&line);
                sink.lock().expect("stderr lock").push('\n');
            }
        });

        Helper {
            child,
            stdin,
            replies,
            stderr: log,
            next_id: 1,
        }
    }

    fn send_raw(&mut self, line: &str) {
        self.stdin.write_all(line.as_bytes()).expect("write");
        self.stdin.write_all(b"\n").expect("write newline");
        self.stdin.flush().expect("flush");
    }

    fn read_reply(&self) -> Value {
        match self.replies.recv_timeout(REPLY_TIMEOUT) {
            Ok(line) => serde_json::from_str(&line).expect("the helper answers with JSON"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("no answer within {REPLY_TIMEOUT:?}: the helper is stuck")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the helper closed its stdout"),
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let line = serde_json::to_string(
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )
        .expect("request encodes");
        self.send_raw(&line);
        let reply = self.read_reply();
        assert_eq!(reply["id"], id, "answers are in order: {reply}");
        reply
    }

    /// The `result` object, or a panic naming the refusal that arrived instead.
    fn ok(&mut self, method: &str, params: Value) -> Value {
        let reply = self.request(method, params);
        assert!(
            reply.get("error").is_none(),
            "{method} was refused: {}",
            reply["error"]
        );
        reply["result"].clone()
    }

    /// The `data.refusal` name, or a panic naming the result that arrived instead.
    fn refusal(&mut self, method: &str, params: Value) -> (String, String) {
        let reply = self.request(method, params);
        let error = reply.get("error").unwrap_or_else(|| {
            panic!("{method} was expected to refuse, and answered: {reply}");
        });
        let code = error["code"].as_i64().expect("a numeric code");
        assert!(
            (-32099..=-32001).contains(&code),
            "{method} refused with {code}, outside the private band"
        );
        (
            error["data"]["refusal"]
                .as_str()
                .expect("a refusal name")
                .to_string(),
            error["message"].as_str().unwrap_or_default().to_string(),
        )
    }

    /// Waits up to two seconds for `needle` to appear on the helper's stderr. Buffering means
    /// the line the guest wrote during a call may land just after the answer to it.
    fn wait_for_stderr(&self, needle: &str) -> String {
        self.wait_for_stderr_lines(needle, 1)
    }

    /// The same, for a needle that is expected more than once: waiting for the first occurrence
    /// would race the second one onto the pipe.
    fn wait_for_two_markers(&self, needle: &str) -> String {
        self.wait_for_stderr_lines(needle, 2)
    }

    fn wait_for_stderr_lines(&self, needle: &str, times: usize) -> String {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let seen = self.stderr.lock().expect("stderr lock").clone();
            let count = seen.lines().filter(|line| line.contains(needle)).count();
            if count >= times || Instant::now() > deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A component written to a temp file, with the sha the helper must recompute for itself.
struct Fixture {
    path: String,
    sha256: String,
}

fn fixture(tag: &str, bytes: &[u8]) -> Fixture {
    let path = std::env::temp_dir().join(format!(
        "ouro-wasm-it-{tag}-{}-{}.wasm",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos()
    ));
    std::fs::write(&path, bytes).expect("the fixture is written");

    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut sha256 = String::new();
    for byte in Sha256::digest(bytes) {
        sha256.push(DIGITS[(byte >> 4) as usize] as char);
        sha256.push(DIGITS[(byte & 0x0f) as usize] as char);
    }

    Fixture {
        path: path.to_string_lossy().into_owned(),
        sha256,
    }
}

fn limits(fuel: u64, memory_bytes: u64, deadline_ms: u64) -> Value {
    json!({ "fuel": fuel, "memory_bytes": memory_bytes, "deadline_ms": deadline_ms })
}

/// `load` a fixture and hand back the helper's answer.
fn load(helper: &mut Helper, fixture: &Fixture) -> Value {
    helper.ok(
        "load",
        json!({ "sha256": fixture.sha256, "path": fixture.path }),
    )
}

/// `instantiate` a loaded fixture as `name`, under the smallest grant the helper accepts.
fn instantiate(helper: &mut Helper, name: &str, fixture: &Fixture) -> Value {
    helper.ok(
        "instantiate",
        json!({
            "instance": name,
            "sha256": fixture.sha256,
            "config": "",
            "limits": limits(FUEL, MIN_MEMORY_BYTES, DEADLINE_MS),
        }),
    )
}

/// The shas a `load` answer or a `doctor` census says were evicted.
fn evicted(answer: &Value) -> Vec<String> {
    answer["evicted"]
        .as_array()
        .expect("evicted is always a list")
        .iter()
        .map(|sha| sha.as_str().expect("a sha").to_string())
        .collect()
}

/// Load a guest and stand one instance of it up, under the given bounds.
fn stand_up(helper: &mut Helper, tag: &str, bytes: &[u8], limits: Value) -> Fixture {
    let fixture = fixture(tag, bytes);
    helper.ok(
        "load",
        json!({ "sha256": fixture.sha256, "path": fixture.path }),
    );
    helper.ok(
        "instantiate",
        json!({
            "instance": tag,
            "sha256": fixture.sha256,
            "config": "CFG",
            "limits": limits,
        }),
    );
    fixture
}

// ------------------------------------------------------------------------------- the proofs

/// A component that wants anything beyond `log` never reaches an instance. `load` refuses it by
/// name, so the sha is never admitted to the cache and `instantiate` has nothing to work with.
///
/// This is the *policy* half of D5 and the only half observable through the six methods: the
/// structural half — the linker having nothing to bind an undeclared import to — is behind it,
/// and is proved directly by `host::tests::the_linker_refuses_an_import_it_does_not_define`,
/// which bypasses this check to get at it.
#[test]
fn an_undeclared_import_never_reaches_an_instance() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("clock", &support::undeclared_import());

    let inspected = helper.ok("inspect", json!({ "path": fixture.path }));
    assert_eq!(
        inspected["world"], "unknown",
        "a component wanting a clock is not in this world"
    );
    assert!(inspected["imports"]
        .as_array()
        .expect("imports")
        .contains(&json!("now")));

    let (refusal, message) = helper.refusal(
        "load",
        json!({ "sha256": fixture.sha256, "path": fixture.path }),
    );
    assert_eq!(refusal, "undefined_import");
    assert!(
        message.contains("now"),
        "the refusal must name the import: {message}"
    );

    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "clock",
            "sha256": fixture.sha256,
            "config": "",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "unknown_component");
}

/// A guest that computes forever burns its fuel and stops, and the instance it burned it in is
/// gone: a guest halted mid-message has state nobody can reason about.
#[test]
fn fuel_runs_out_and_poisons_the_instance() {
    let mut helper = Helper::spawn(&[]);
    // Small fuel, a long deadline: whatever stops this guest, it is not the clock.
    stand_up(
        &mut helper,
        "spin",
        &support::spin(),
        limits(100_000, MEMORY_BYTES, 30_000),
    );

    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "spin", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(refusal, "fuel_exhausted");

    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "spin", "export": "describe", "payload": "" }),
    );
    assert_eq!(
        refusal, "unknown_instance",
        "a trapped instance must not answer again"
    );
}

/// A guest that computes forever with more fuel than it can spend is stopped by the wall clock.
/// This is the bound that does not depend on the guest executing anything in particular.
#[test]
fn the_epoch_deadline_interrupts_an_endless_guest() {
    let mut helper = Helper::spawn(&[]);
    let deadline_ms = 250;
    stand_up(
        &mut helper,
        "endless",
        &support::spin(),
        limits(1_000_000_000_000, MEMORY_BYTES, deadline_ms),
    );

    let started = Instant::now();
    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "endless", "export": "handle-message", "payload": "{}" }),
    );
    let elapsed = started.elapsed();

    assert_eq!(refusal, "deadline_exceeded");
    assert!(
        elapsed >= Duration::from_millis(deadline_ms),
        "interrupted after {elapsed:?}, before the deadline it was given"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the deadline was {deadline_ms}ms and the call took {elapsed:?}"
    );

    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "endless", "export": "describe", "payload": "" }),
    );
    assert_eq!(refusal, "unknown_instance");
}

/// A guest that asks for more memory than its ceiling is refused the growth, and the refusal it
/// gets back names the ceiling rather than the `unreachable` the guest reached afterwards. The
/// guest trapped, so it is poisoned like any other trap.
#[test]
fn memory_growth_past_the_ceiling_is_refused() {
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "grow",
        &support::grow(),
        limits(FUEL, 1024 * 1024, DEADLINE_MS),
    );

    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "grow", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(refusal, "memory_limit");

    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "grow", "export": "describe", "payload": "" }),
    );
    assert_eq!(
        refusal, "unknown_instance",
        "a guest that trapped on a denied allocation must not answer again"
    );
}

/// The ceiling is on the store's memories *together*. Four memories of a megabyte each are four
/// megabytes however they are declared, and a one-megabyte grant has to say so — otherwise a
/// component declares as many small memories as it likes and multiplies its own grant.
#[test]
fn the_memory_ceiling_is_summed_across_memories() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("wide", &support::bulk(3, 16, 0));
    helper.ok(
        "load",
        json!({ "sha256": fixture.sha256, "path": fixture.path }),
    );

    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "wide",
            "sha256": fixture.sha256,
            "config": "",
            // Three extra memories of 16 pages each, plus the guest's own: four memories, which
            // is exactly the count cap, so what must refuse this is the byte ceiling.
            "limits": limits(FUEL, 1024 * 1024, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "memory_limit");

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["usable"], true);
    assert_eq!(report["held"]["instances"], 0);
}

/// Resource *counts* are bounded too. A component may be entirely in-world and still be shaped
/// to cost the host gigabytes of runtime bookkeeping under a 64 KiB memory grant, because that
/// bookkeeping is not the guest's memory and no memory grant is charged for it.
#[test]
fn hostile_resource_counts_are_refused() {
    let mut helper = Helper::spawn(&[]);

    for (tag, bytes) in [
        // More core instances than any real guest needs.
        ("many-instances", support::bulk(64, 0, 0)),
        // More tables, each large, than any real guest needs.
        ("many-tables", support::bulk(8, 0, 100_000)),
        // More memories than the count cap allows, before their bytes are even considered.
        ("many-memories", support::bulk(32, 1, 0)),
    ] {
        let fixture = fixture(tag, &bytes);
        helper.ok(
            "load",
            json!({ "sha256": fixture.sha256, "path": fixture.path }),
        );

        let (refusal, _) = helper.refusal(
            "instantiate",
            json!({
                "instance": tag,
                "sha256": fixture.sha256,
                "config": "",
                "limits": limits(FUEL, MIN_MEMORY_BYTES, DEADLINE_MS),
            }),
        );
        assert!(
            refusal == "instantiate_failed" || refusal == "memory_limit",
            "{tag} was refused as `{refusal}`, which is neither of the two honest answers"
        );
    }

    // The helper is still here, and still holding nothing.
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["usable"], true);
    assert_eq!(report["held"]["instances"], 0);
}

/// `init` is guest code, so `init` is bounded. Without this the helper could arm nothing at
/// instantiate and every other test would still pass.
#[test]
fn init_runs_under_the_same_deadline_a_message_does() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("spin-init", &support::spin_init());
    helper.ok(
        "load",
        json!({ "sha256": fixture.sha256, "path": fixture.path }),
    );

    let request = json!({
        "instance": "spin-init",
        "sha256": fixture.sha256,
        "config": "{}",
        "limits": limits(1_000_000_000_000u64, MEMORY_BYTES, 250),
    });

    let started = Instant::now();
    let (refusal, _) = helper.refusal("instantiate", request.clone());
    let elapsed = started.elapsed();
    assert_eq!(refusal, "deadline_exceeded");
    assert!(
        elapsed < Duration::from_secs(10),
        "init ran for {elapsed:?} against a 250ms deadline"
    );

    // Nothing was retained: the name is free, and there is no half-built instance to call.
    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "spin-init", "export": "describe", "payload": "" }),
    );
    assert_eq!(refusal, "unknown_instance");

    let (refusal, _) = helper.refusal("instantiate", request);
    assert_eq!(
        refusal, "deadline_exceeded",
        "a failed instantiate must leave the name free, not claimed"
    );
}

/// A guest cannot write until the pipe blocks. Neither fuel nor the epoch deadline is checked
/// while a guest is inside a host call, so the only thing between a `log` loop and a wedged
/// helper is the per-call budget — and the proof that the budget works is that this call
/// returns at all.
#[test]
fn the_log_budget_bounds_one_call() {
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "chatty",
        &support::chatty(),
        limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
    );

    let answered = helper.ok(
        "call",
        json!({ "instance": "chatty", "export": "handle-message", "payload": "x" }),
    );
    assert_eq!(answered["payload"], "ouroboros:capability@0.1.0 echo");

    let logged = helper.wait_for_stderr("log budget");
    let lines = logged
        .lines()
        .filter(|line| line.contains("guest chatty"))
        .count();
    assert!(
        lines <= 20,
        "a guest asking for a thousand log lines got {lines} of them:\n{logged}"
    );
    assert!(
        logged.contains("log budget"),
        "the guest must be told once that the rest were dropped: {logged}"
    );

    // A fresh call gets a fresh budget, and the helper is still answering.
    let again = helper.ok(
        "call",
        json!({ "instance": "chatty", "export": "handle-message", "payload": "y" }),
    );
    assert_eq!(again["payload"], "ouroboros:capability@0.1.0 echo");
}

/// Content addressing is recomputed, never taken on trust. A `load` whose bytes do not hash to
/// the sha it named is refused before anything is compiled.
#[test]
fn a_sha_mismatch_is_refused() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("echo", &support::echo());
    let wrong = "0".repeat(64);

    let (refusal, message) =
        helper.refusal("load", json!({ "sha256": wrong, "path": fixture.path }));
    assert_eq!(refusal, "sha_mismatch");
    assert!(
        message.contains(&fixture.sha256),
        "the refusal must say what the bytes actually hash to: {message}"
    );

    // Nothing was admitted, so nothing can be instantiated from it.
    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "echo",
            "sha256": wrong,
            "config": "",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "unknown_component");
}

/// A line longer than the frame cap is reported and the connection carries on. The cap is the
/// real 8 MiB default, and the line is written whole: the point is that the helper never
/// buffers it, which a smaller `--max-frame-bytes` would not demonstrate.
#[test]
fn an_oversize_frame_is_reported_and_the_pipe_survives() {
    let mut helper = Helper::spawn(&[]);
    helper.send_raw(&"x".repeat(9 * 1024 * 1024));

    let reply = helper.read_reply();
    assert_eq!(reply["id"], Value::Null);
    assert_eq!(reply["error"]["code"], -32600);
    assert!(reply["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("max_frame_bytes"));

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["usable"], true);
}

/// The whole world, once through: describe, init with a config the guest keeps, a message
/// answered from that config, fuel accounted for, and the one import reaching the helper's
/// stderr without failing the call.
#[test]
fn the_happy_path_answers_and_logs() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("echo", &support::echo());

    let inspected = helper.ok("inspect", json!({ "path": fixture.path }));
    assert_eq!(inspected["world"], "ouroboros:capability@0.1.0");
    assert_eq!(inspected["sha256"], fixture.sha256);
    assert_eq!(inspected["imports"], json!(["log"]));
    assert_eq!(
        inspected["exports"],
        json!(["describe", "init", "handle-message"])
    );
    assert!(inspected["size"].as_u64().expect("a size") > 0);

    let loaded = helper.ok(
        "load",
        json!({ "sha256": fixture.sha256, "path": fixture.path }),
    );
    assert_eq!(loaded["world"], "ouroboros:capability@0.1.0");
    assert_eq!(loaded["cached"], false);

    let stood_up = helper.ok(
        "instantiate",
        json!({
            "instance": "echo-1",
            "sha256": fixture.sha256,
            "config": "hello",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    assert_eq!(stood_up["instance"], "echo-1");

    let described = helper.ok(
        "call",
        json!({ "instance": "echo-1", "export": "describe", "payload": "" }),
    );
    assert_eq!(described["payload"], "ouroboros:capability@0.1.0 echo");
    assert!(described["fuel_used"].as_u64().expect("fuel") > 0);

    let answered = helper.ok(
        "call",
        json!({ "instance": "echo-1", "export": "handle-message", "payload": "world" }),
    );
    assert_eq!(
        answered["payload"], "hello|world",
        "the reply proves init's config survived into the message"
    );
    assert!(answered["fuel_used"].as_u64().expect("fuel") > 0);

    let logged = helper.wait_for_stderr("handle-message");
    assert!(
        logged.contains("ouro-wasm: guest echo-1 [info] handle-message"),
        "the guest's log import must reach stderr: {logged:?}"
    );

    // The instance holds its own state, so a second message still sees the config.
    let again = helper.ok(
        "call",
        json!({ "instance": "echo-1", "export": "handle-message", "payload": "again" }),
    );
    assert_eq!(again["payload"], "hello|again");

    // `init` is not a message, and nothing outside the world is callable.
    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "echo-1", "export": "init", "payload": "{}" }),
    );
    assert_eq!(refusal, "unknown_export");

    let dropped = helper.ok("drop", json!({ "instance": "echo-1" }));
    assert_eq!(dropped["dropped"], true);
    let again = helper.ok("drop", json!({ "instance": "echo-1" }));
    assert_eq!(again["dropped"], false, "drop is idempotent");
}

/// A guest may return more than a frame can carry. It is refused by size, and — unlike a trap —
/// it keeps its instance: returning a large string is an answer, not a loss of control.
#[test]
fn an_oversize_result_is_refused_without_poisoning_the_instance() {
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "big",
        &support::oversize(2 * 1024 * 1024),
        limits(FUEL, 32 * 1024 * 1024, DEADLINE_MS),
    );

    let (refusal, message) = helper.refusal(
        "call",
        json!({ "instance": "big", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(refusal, "oversize_result");
    assert!(
        message.contains(&(2 * 1024 * 1024).to_string()),
        "the refusal must say how big the reply was: {message}"
    );

    let described = helper.ok(
        "call",
        json!({ "instance": "big", "export": "describe", "payload": "" }),
    );
    assert_eq!(described["payload"], "oversize");
}

/// The three bounds are mandatory and bounded. Asked for the moon, the helper refuses; asked for
/// nothing at all, it says the request is malformed rather than picking a default.
#[test]
fn instantiate_will_not_default_or_exceed_its_limits() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("echo", &support::echo());
    helper.ok(
        "load",
        json!({ "sha256": fixture.sha256, "path": fixture.path }),
    );

    let base = json!({ "instance": "echo-2", "sha256": fixture.sha256, "config": "" });

    let mut without = base.clone();
    without["limits"] = json!({ "fuel": FUEL, "memory_bytes": MEMORY_BYTES });
    let reply = helper.request("instantiate", without);
    assert_eq!(reply["error"]["code"], -32602);
    assert_eq!(reply["error"]["data"]["refusal"], "invalid_params");

    for excessive in [
        limits(FUEL, 8 * 1024 * 1024 * 1024, DEADLINE_MS),
        limits(FUEL, MEMORY_BYTES, 600_000),
    ] {
        let mut request = base.clone();
        request["limits"] = excessive;
        let (refusal, _) = helper.refusal("instantiate", request);
        assert_eq!(refusal, "limits_out_of_range");
    }
}

/// One instance name, one instance. Standing a second one up over a live name is refused rather
/// than silently leaking the first.
#[test]
fn an_instance_name_is_not_reused_while_it_is_live() {
    let mut helper = Helper::spawn(&[]);
    let fixture = stand_up(
        &mut helper,
        "echo",
        &support::echo(),
        limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
    );

    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "echo",
            "sha256": fixture.sha256,
            "config": "other",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "instance_exists");

    helper.ok("drop", json!({ "instance": "echo" }));
    helper.ok(
        "instantiate",
        json!({
            "instance": "echo",
            "sha256": fixture.sha256,
            "config": "other",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    let answered = helper.ok(
        "call",
        json!({ "instance": "echo", "export": "handle-message", "payload": "x" }),
    );
    assert_eq!(answered["payload"], "other|x", "the new instance is new");
}

/// A second `load` of a sha already held is free and says so, and the answer still carries the
/// facts the owner cross-checks against the signed manifest.
#[test]
fn loading_the_same_component_twice_is_idempotent() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("echo", &support::echo());
    let params = json!({ "sha256": fixture.sha256, "path": fixture.path });

    let first = helper.ok("load", params.clone());
    assert_eq!(first["cached"], false);
    let second = helper.ok("load", params);
    assert_eq!(second["cached"], true);
    assert_eq!(first["sha256"], second["sha256"]);
    assert_eq!(first["imports"], second["imports"]);
    assert_eq!(first["exports"], second["exports"]);
    assert_eq!(first["size"], second["size"]);
}

/// A path that is not there is a refusal like any other, not a crash and not a hang.
#[test]
fn an_unreadable_component_is_refused() {
    let mut helper = Helper::spawn(&[]);
    let missing = std::env::temp_dir().join("ouro-wasm-it-does-not-exist.wasm");
    let (refusal, _) = helper.refusal("inspect", json!({ "path": missing.to_string_lossy() }));
    assert_eq!(refusal, "unreadable_component");
}

/// A path is a peer-supplied string, and a named pipe is a path. Opening one with no writer
/// blocks in the kernel — no deadline reaches that — so the check is on the metadata, before
/// the open.
#[cfg(unix)]
#[test]
fn a_named_pipe_is_refused_rather_than_waited_on() {
    let path = std::env::temp_dir().join(format!("ouro-wasm-it-fifo-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let made = Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo could not create {path:?}");

    let mut helper = Helper::spawn(&[]);
    let started = Instant::now();
    let (refusal, message) = helper.refusal("inspect", json!({ "path": path.to_string_lossy() }));
    let elapsed = started.elapsed();
    let _ = std::fs::remove_file(&path);

    assert_eq!(refusal, "unreadable_component");
    assert!(
        message.contains("not a regular file"),
        "the refusal should say what was wrong: {message}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "opening the fifo blocked for {elapsed:?}"
    );
}

/// A refusal quotes back what the peer sent, and a peer can send a great deal. Without a bound
/// on that quoting a seven-megabyte path becomes a refusal too large for the frame that has to
/// carry it — a peer breaking its own pipe through this helper's politeness.
#[test]
fn a_huge_peer_string_comes_back_small() {
    let mut helper = Helper::spawn(&[]);
    let path = "/nonexistent/".to_string() + &"p".repeat(7 * 1024 * 1024);

    let (refusal, message) = helper.refusal("inspect", json!({ "path": path }));
    assert_eq!(refusal, "unreadable_component");
    assert!(
        message.len() < 4096,
        "a 7 MiB path came back as a {} byte message",
        message.len()
    );

    // Same for a result rather than a refusal: `drop` echoes the name it was given.
    let dropped = helper.ok("drop", json!({ "instance": "i".repeat(7 * 1024 * 1024) }));
    assert!(
        dropped["instance"].as_str().expect("a name").len() < 4096,
        "drop echoed the whole name back"
    );
}

/// Both tables have a ceiling, and both are reached as a typed answer rather than as a helper
/// that grows until the node notices. They differ in what the ceiling *does*. The component
/// table is a cache and evicts at it — the least recently used sha no live instance holds — so
/// the 65th load succeeds and names what it let go, and `doctor` keeps a bounded log of the
/// same. The instance table is not a cache, and the 257th instance is refused.
#[test]
fn the_component_and_instance_tables_are_bounded() {
    let mut helper = Helper::spawn(&[]);

    // 64 components fit without evicting anything. Each is a distinct guest, so each is a
    // distinct sha.
    let mut fixtures = Vec::new();
    for n in 0..64 {
        let fixture = fixture("many", &support::oversize(n + 1));
        let loaded = load(&mut helper, &fixture);
        assert_eq!(loaded["cached"], false);
        assert!(
            evicted(&loaded).is_empty(),
            "load {n} evicted from a cache that was not full: {loaded}"
        );
        fixtures.push(fixture);
    }

    // The 65th evicts the first — the least recently used — and says so.
    let mut last = fixture("many", &support::oversize(65));
    let loaded = load(&mut helper, &last);
    assert_eq!(loaded["cached"], false);
    assert_eq!(evicted(&loaded), vec![fixtures[0].sha256.clone()]);

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);
    assert_eq!(report["held"]["evictions"], 1);
    assert_eq!(evicted(&report["held"]), vec![fixtures[0].sha256.clone()]);

    // Nineteen more: each takes the next-oldest, in the order they were loaded. The log is
    // itself bounded — after twenty evictions it holds the last sixteen, oldest first — while
    // the count keeps counting.
    let mut victims = evicted(&loaded);
    for n in 66..85 {
        last = fixture("many", &support::oversize(n));
        victims.extend(evicted(&load(&mut helper, &last)));
    }
    let expected: Vec<String> = fixtures[..20].iter().map(|f| f.sha256.clone()).collect();
    assert_eq!(
        victims, expected,
        "eviction is least recently used, in load order"
    );

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);
    assert_eq!(report["held"]["evictions"], 20);
    assert_eq!(report["limits"]["max_eviction_log"], 16);
    assert_eq!(evicted(&report["held"]), victims[4..].to_vec());

    // 256 instances of the newest one fit; the 257th does not, and nothing is evicted to make
    // room for it.
    for n in 0..256 {
        instantiate(&mut helper, &format!("i{n}"), &last);
    }
    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "one-too-many",
            "sha256": last.sha256,
            "config": "",
            "limits": limits(FUEL, MIN_MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "too_many_instances");

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);
    assert_eq!(report["held"]["instances"], 256);
    assert_eq!(
        report["held"]["evictions"], 20,
        "a refused instantiate evicts nothing"
    );
}

/// A component with a live instance is never evicted, however old it is. The instance would
/// keep working either way — it holds its own handle on the compiled code — but its owner is
/// plainly still using that component, and a cache that forgot what its callers hold would be
/// lying to `doctor`. When every held component is pinned the cache refuses rather than
/// evicts, and dropping one instance is exactly what makes room again.
#[test]
fn eviction_never_touches_a_component_with_live_instances() {
    let mut helper = Helper::spawn(&[]);

    // The oldest thing in the table, and the one thing with a live instance.
    let pinned = stand_up(
        &mut helper,
        "pinned",
        &support::echo(),
        limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
    );

    // Fill the rest of the table behind it.
    let mut fillers = Vec::new();
    for n in 0..63 {
        let filler = fixture("filler", &support::oversize(n + 1));
        assert!(evicted(&load(&mut helper, &filler)).is_empty());
        fillers.push(filler);
    }
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);

    // Full. The least recently used sha is `pinned`'s, and it is passed over for the oldest
    // sha nothing holds.
    let newcomer = fixture("newcomer", &support::oversize(100));
    assert_eq!(
        evicted(&load(&mut helper, &newcomer)),
        vec![fillers[0].sha256.clone()]
    );

    // The live instance is untouched, and its component is still instantiable without a
    // reload — it was never let go.
    let answer = helper.ok(
        "call",
        json!({ "instance": "pinned", "export": "handle-message", "payload": "still here" }),
    );
    assert_eq!(answer["payload"], "CFG|still here");
    helper.ok(
        "instantiate",
        json!({
            "instance": "pinned-2",
            "sha256": pinned.sha256,
            "config": "CFG",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );

    // Pin everything else: one instance of each of the 63 other components now held.
    for (n, filler) in fillers.iter().enumerate().skip(1) {
        instantiate(&mut helper, &format!("f{n}"), filler);
    }
    instantiate(&mut helper, "newcomer", &newcomer);

    // Every held component has a live instance, so the cache refuses rather than evicts, and
    // the refusal says what would make room.
    let refused = fixture("refused", &support::oversize(101));
    let (refusal, message) = helper.refusal(
        "load",
        json!({ "sha256": refused.sha256, "path": refused.path }),
    );
    assert_eq!(refusal, "too_many_components");
    assert!(
        message.contains("live instance"),
        "the refusal should name the reason nothing can go: {message}"
    );

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);
    assert_eq!(report["held"]["instances"], 65);
    assert_eq!(
        report["held"]["evictions"], 1,
        "a refused load evicts nothing"
    );

    // Drop exactly one instance and the next load evicts exactly that component — not the far
    // older `pinned`, which is still held.
    helper.ok("drop", json!({ "instance": "f7" }));
    assert_eq!(
        evicted(&load(&mut helper, &refused)),
        vec![fillers[7].sha256.clone()]
    );

    // Through all of it `pinned` was never let go, and its instances still answer.
    let report = helper.ok("doctor", Value::Null);
    assert!(
        !evicted(&report["held"]).contains(&pinned.sha256),
        "a component with live instances was evicted: {}",
        report["held"]
    );
    let answer = helper.ok(
        "call",
        json!({ "instance": "pinned-2", "export": "handle-message", "payload": "and here" }),
    );
    assert_eq!(answer["payload"], "CFG|and here");
}

/// The cross-lane defect eviction exists for. A hook is loaded on every invocation and every
/// edit of it is a new sha, so a long-lived helper sees an unbounded procession of hook
/// components that are each used once and dropped. With no eviction, the 64th of them made
/// every later load on the node — the next hook, and the capability lane's next rollout — fail
/// `too_many_components` until the helper was respawned. Now the 65th load evicts the oldest
/// hook nobody holds, and the capability loads, instantiates and answers.
#[test]
fn a_capability_load_succeeds_after_64_hook_loads() {
    let mut helper = Helper::spawn(&[]);

    // Sixty-four distinct hooks, each used the way `Hooks.run_component/4` uses one: load,
    // instantiate, drop. A dropped instance holds nothing, so none of these stays pinned.
    let mut hooks = Vec::new();
    for n in 0..64 {
        let hook = fixture("hook", &support::oversize(n + 1));
        assert!(evicted(&load(&mut helper, &hook)).is_empty());
        instantiate(&mut helper, "hook", &hook);
        let dropped = helper.ok("drop", json!({ "instance": "hook" }));
        assert_eq!(dropped["dropped"], true);
        hooks.push(hook);
    }
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);
    assert_eq!(report["held"]["instances"], 0);
    assert_eq!(report["held"]["evictions"], 0);

    // The capability lane's load: admitted, at the cost of the oldest hook.
    let capability = fixture("capability", &support::echo());
    let loaded = load(&mut helper, &capability);
    assert_eq!(loaded["cached"], false);
    assert_eq!(evicted(&loaded), vec![hooks[0].sha256.clone()]);

    helper.ok(
        "instantiate",
        json!({
            "instance": "capability",
            "sha256": capability.sha256,
            "config": "CFG",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    let answer = helper.ok(
        "call",
        json!({ "instance": "capability", "export": "handle-message", "payload": "hello" }),
    );
    assert_eq!(answer["payload"], "CFG|hello");

    // The evicted hook is simply unknown again: instantiating it is refused by name, and
    // loading it again compiles it again — at the cost of the next-oldest hook, never of the
    // capability, which is both newer and held.
    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "stale",
            "sha256": hooks[0].sha256,
            "config": "",
            "limits": limits(FUEL, MIN_MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "unknown_component");

    let reloaded = load(&mut helper, &hooks[0]);
    assert_eq!(
        reloaded["cached"], false,
        "an evicted sha is compiled again"
    );
    assert_eq!(evicted(&reloaded), vec![hooks[1].sha256.clone()]);

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);
    assert_eq!(report["held"]["evictions"], 2);
    assert_eq!(
        evicted(&report["held"]),
        vec![hooks[0].sha256.clone(), hooks[1].sha256.clone()]
    );
}

/// Recency is the last time a sha was *wanted*, not the time it was compiled: a repeat `load`
/// of a held sha — which is what every hook invocation is — is a cache hit that moves it to
/// the back of the queue, so what a full cache lets go is the component nobody has asked for
/// longest.
#[test]
fn a_cache_hit_counts_as_recent_use() {
    let mut helper = Helper::spawn(&[]);

    let first = fixture("first", &support::oversize(1));
    let second = fixture("second", &support::oversize(2));
    let third = fixture("third", &support::oversize(3));
    load(&mut helper, &first);
    load(&mut helper, &second);
    load(&mut helper, &third);
    for n in 4..=64 {
        load(&mut helper, &fixture("rest", &support::oversize(n)));
    }

    // Ask for `first` again: a hit, which evicts nothing and makes it the most recently
    // wanted sha in the table.
    let hit = load(&mut helper, &first);
    assert_eq!(hit["cached"], true);
    assert!(evicted(&hit).is_empty());

    // The next admission takes `second` — the oldest sha nobody has wanted since — and the
    // one after that takes `third`. `first` is at the back of the queue.
    let loaded = load(&mut helper, &fixture("next", &support::oversize(65)));
    assert_eq!(evicted(&loaded), vec![second.sha256.clone()]);
    let loaded = load(&mut helper, &fixture("next", &support::oversize(66)));
    assert_eq!(evicted(&loaded), vec![third.sha256.clone()]);

    let again = load(&mut helper, &first);
    assert_eq!(again["cached"], true, "`first` was never let go");
}

/// The reply cap has to be a bound on what the *host* allocates, not just on what it sends, and
/// it has to leave in-contract traffic alone. A reply just under the cap comes back; one over it
/// is refused by size and named as such, never as a trap.
#[test]
fn the_reply_cap_bounds_allocation_without_touching_in_contract_traffic() {
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "just-under",
        &support::oversize(1_000_000),
        limits(FUEL, 32 * 1024 * 1024, DEADLINE_MS),
    );

    let answered = helper.ok(
        "call",
        json!({ "instance": "just-under", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(
        answered["payload"].as_str().expect("a payload").len(),
        1_000_000,
        "a reply just under the cap must come back whole"
    );

    // And one over the cap is refused as oversize — the word for it — rather than as a trap.
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "just-over",
        &support::oversize(2 * 1024 * 1024),
        limits(FUEL, 32 * 1024 * 1024, DEADLINE_MS),
    );
    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "just-over", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(refusal, "oversize_result");
}

/// Where the two refusals meet, stated as a test so the boundary is a decision rather than an
/// accident.
///
/// A reply is refused by size *after* the host has lifted it, so without a budget on that lift
/// the cap is a rule about the wire and not about memory: a hundred-megabyte reply is refused
/// correctly and costs two hundred megabytes to refuse, over and over. The helper therefore
/// arms wasmtime's per-hostcall byte budget at four times the reply cap, and this test is what
/// says so — a reply past *that* is stopped by the runtime before the allocation happens, and
/// arrives as a trap rather than as `oversize_result`. Delete the arming line and this test
/// goes green the wrong way, reporting `oversize_result` after allocating the whole thing.
#[test]
fn a_reply_far_past_the_cap_is_stopped_before_it_is_allocated() {
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "far-over",
        &support::oversize(6 * 1024 * 1024),
        limits(FUEL, 32 * 1024 * 1024, DEADLINE_MS),
    );

    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "far-over", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(
        refusal, "trapped",
        "past the hostcall budget the runtime refuses the transfer, and that is not an \
         `oversize_result` — if this says `oversize_result`, the budget is not armed and the \
         host allocated the whole reply to measure it"
    );

    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "far-over", "export": "describe", "payload": "" }),
    );
    assert_eq!(refusal, "unknown_instance");
}

// ------------------------------------------------- the bound in front of the compiler (F1)

/// The structural bound, exactly as the helper reports it. Kept here rather than read from the
/// crate because these tests drive the *binary*: a bound the test and the helper disagreed about
/// would be a bound nobody was checking.
const MAX_FUNCTIONS: usize = 20_000;
const MAX_NESTING_DEPTH: usize = 8;

/// The functions the reference guests' own core module declares — `realloc`, `describe`, `init`
/// and `handle_message` — which [`support::dense`] adds to.
const GUEST_FUNCTIONS: usize = 4;

/// Compilation is bounded, and the bound is reachable.
///
/// This is the finding this whole file was reopened for. `Component::new` was called under no
/// fuel, no deadline and no structural bound: a *valid, in-world* component of 145 000 trivial
/// functions took 28.9 seconds to compile on the release build, and this helper answers one
/// request at a time, so that is 28.9 seconds in which every hook and every capability on the
/// node waits — long enough for the daemon's 30-second `load` deadline to break the pool and
/// drop every live instance with it. A watchdog could not have fixed it: cranelift cannot be
/// interrupted, so the thread burns to the end whatever the timer says. The only bound that
/// costs nothing is one taken before the compiler starts.
///
/// So: a component at both bounds at once — 20 000 functions *and* just under 4 MiB of code — is
/// admitted, compiles, instantiates and answers. That is the worst case this helper will hand to
/// cranelift, and on the release build it takes **1.19 s**. One function past the bound is
/// refused `component_too_complex` in **0.14 s**, which is the time to read 4 MiB off disk and
/// walk its section headers; nothing is compiled.
///
/// The assertion below is on the refusal and the admission, not on the clock: this suite is
/// built with `cargo test`, and a debug wasmtime compiles the same bytes in 27 s. `REPLY_TIMEOUT`
/// is the only wall-clock claim that survives both profiles.
#[test]
fn the_worst_component_this_helper_will_compile_is_bounded_and_reachable() {
    let mut helper = Helper::spawn(&[]);

    // Just past the function bound: refused without being compiled.
    let over = fixture(
        "over-functions",
        &support::dense(MAX_FUNCTIONS - GUEST_FUNCTIONS + 1, 18),
    );
    let (refusal, message) = helper.refusal("inspect", json!({ "path": over.path }));
    assert_eq!(refusal, "component_too_complex");
    assert!(
        message.contains("20001") && message.contains("functions"),
        "the refusal must say which bound and by how much: {message}"
    );

    // A `load` of the same bytes is refused the same way, and admits nothing.
    let (refusal, _) = helper.refusal("load", json!({ "sha256": over.sha256, "path": over.path }));
    assert_eq!(refusal, "component_too_complex");
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 0);

    // Exactly at the bound: admitted, compiled, and it works. A bound that refused this would
    // be a bound no real guest could reach either.
    let at = fixture(
        "at-the-bound",
        &support::dense(MAX_FUNCTIONS - GUEST_FUNCTIONS, 18),
    );
    let loaded = load(&mut helper, &at);
    assert_eq!(loaded["world"], "ouroboros:capability@0.1.0");
    instantiate(&mut helper, "at-the-bound", &at);
    let answered = helper.ok(
        "call",
        json!({ "instance": "at-the-bound", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(answered["payload"], "ok");
}

/// The other dimensions of the same bound, each refused by name so an owner reading a refusal
/// learns which ceiling they hit rather than only that they hit one.
#[test]
fn each_structural_bound_refuses_before_the_compiler_runs() {
    let mut helper = Helper::spawn(&[]);

    // Bytes of code, with few enough functions that the function bound is not what fires:
    // 400 functions of 1 200 instructions is roughly 5 MiB against a 4 MiB ceiling.
    let fat = fixture("fat", &support::dense(400, 1_200));
    let (refusal, message) = helper.refusal("inspect", json!({ "path": fat.path }));
    assert_eq!(refusal, "component_too_complex");
    assert!(
        message.contains("bytes of code"),
        "a component over the code ceiling must be told which ceiling: {message}"
    );

    // Nesting, which is a handful of bytes to write and a recursion for anything that walks it.
    let deep = fixture("deep", &support::deeply_nested(MAX_NESTING_DEPTH + 2));
    let (refusal, message) = helper.refusal("inspect", json!({ "path": deep.path }));
    assert_eq!(refusal, "component_too_complex");
    assert!(
        message.contains("nesting"),
        "a component nested too deeply must be told so: {message}"
    );

    // And the helper is unharmed by all of it, still holding nothing.
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["usable"], true);
    assert_eq!(report["held"]["components"], 0);
    assert!(report["limits"]["max_functions"].as_u64().expect("a bound") > 0);
}

// --------------------------------------------------- the engine's feature set (F2)

/// The engine speaks the smallest dialect the world needs, and the two proposals worth naming
/// are refused at compile.
///
/// wasmtime 48 turns on every proposal it considers stable, which is a reasonable default for a
/// host running code it wrote and the wrong one for a host running code nobody trusts. Two of
/// them are worth a test of their own. **Relaxed SIMD** is nondeterministic *by design* —
/// `f32x4.relaxed_madd` may fuse the multiply and add or not, depending on the host CPU — so a
/// capability that used it could answer differently on two nodes of one fleet, which is exactly
/// what D4 forbids. **Tail calls** are deterministic but are a whole extra lowering path in
/// cranelift for a world whose guests are three functions over strings.
#[test]
fn the_engine_refuses_proposals_this_world_does_not_need() {
    let mut helper = Helper::spawn(&[]);

    for (tag, bytes) in [
        ("relaxed-simd", support::relaxed_simd()),
        ("tail-call", support::tail_call()),
    ] {
        let fixture = fixture(tag, &bytes);
        let (refusal, _) = helper.refusal("inspect", json!({ "path": fixture.path }));
        assert_eq!(
            refusal, "compile_failed",
            "a component using {tag} must not compile on this engine"
        );

        let (refusal, _) = helper.refusal(
            "load",
            json!({ "sha256": fixture.sha256, "path": fixture.path }),
        );
        assert_eq!(refusal, "compile_failed");
    }

    // And the dialect that is left is still enough to run the world: a guest that uses plain
    // SIMD and bulk memory — what a real toolchain emits — loads and answers.
    let echo = stand_up(
        &mut helper,
        "still-works",
        &support::echo(),
        limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
    );
    let answered = helper.ok(
        "call",
        json!({ "instance": "still-works", "export": "handle-message", "payload": "x" }),
    );
    assert_eq!(answered["payload"], "CFG|x");
    assert!(!echo.sha256.is_empty());
}

// ------------------------------------------------- enforcement nobody was holding (F3/F4)

/// A component that is not read is not compiled. The byte cap is checked against what was
/// actually read, one byte past the cap, so an over-cap file is refused without being held.
#[test]
fn the_component_byte_cap_is_enforced_on_what_is_read() {
    const CAP: u64 = 64 * 1024 * 1024;
    let mut helper = Helper::spawn(&[]);

    // Sparse, so this costs an inode rather than 64 MiB of disk.
    let over = std::env::temp_dir().join(format!("ouro-wasm-it-overcap-{}", std::process::id()));
    let file = std::fs::File::create(&over).expect("the over-cap fixture is created");
    file.set_len(CAP + 1).expect("a sparse file of cap + 1");
    drop(file);

    let (refusal, message) = helper.refusal("inspect", json!({ "path": over.to_string_lossy() }));
    let _ = std::fs::remove_file(&over);
    assert_eq!(refusal, "unreadable_component");
    assert!(
        message.contains("cap"),
        "the refusal must say the file was over the cap: {message}"
    );

    // A file of exactly the cap is read, and then refused for what it *is* rather than for its
    // size — which is what says the boundary sits where it claims to.
    let at = std::env::temp_dir().join(format!("ouro-wasm-it-atcap-{}", std::process::id()));
    let file = std::fs::File::create(&at).expect("the at-cap fixture is created");
    file.set_len(CAP).expect("a sparse file of exactly the cap");
    drop(file);

    let (refusal, _) = helper.refusal("inspect", json!({ "path": at.to_string_lossy() }));
    let _ = std::fs::remove_file(&at);
    assert_eq!(
        refusal, "compile_failed",
        "a file at the cap must be read and judged as bytes, not refused for its size"
    );
}

/// Tables are bounded the way memories are. A guest that asks to grow one past the ceiling is
/// refused the growth — and, having no plan for that, traps. A guest that asks for less than the
/// ceiling gets it and answers, so the test cannot pass by the growth failing for some other
/// reason.
#[test]
fn table_growth_past_the_ceiling_is_refused() {
    let mut helper = Helper::spawn(&[]);

    stand_up(
        &mut helper,
        "table-ok",
        &support::table_grower(50_000),
        limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
    );
    let answered = helper.ok(
        "call",
        json!({ "instance": "table-ok", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(
        answered["payload"], "ok",
        "growth under the ceiling must be allowed, or this test proves nothing"
    );

    stand_up(
        &mut helper,
        "table-over",
        &support::table_grower(200_000),
        limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
    );
    let (refusal, _) = helper.refusal(
        "call",
        json!({ "instance": "table-over", "export": "handle-message", "payload": "{}" }),
    );
    assert_eq!(
        refusal, "trapped",
        "a table grown past the ceiling must be refused the growth"
    );
}

/// The *count* of memories is capped, separately from their bytes. Five memories under a four
/// mebibyte grant is 320 KiB of guest memory — far under the ceiling — so the only thing that
/// can refuse it is the count.
#[test]
fn the_memory_count_cap_is_enforced_on_its_own() {
    let mut helper = Helper::spawn(&[]);

    // Four memories: the guest's own plus three. Exactly at the cap, and admitted.
    let at = fixture("memories-at", &support::bulk(3, 1, 0));
    load(&mut helper, &at);
    helper.ok(
        "instantiate",
        json!({
            "instance": "memories-at",
            "sha256": at.sha256,
            "config": "",
            "limits": limits(FUEL, 4 * 1024 * 1024, DEADLINE_MS),
        }),
    );

    // Five. Their bytes together are 320 KiB against a 4 MiB grant, so nothing but the count
    // can be what refuses this.
    let over = fixture("memories-over", &support::bulk(4, 1, 0));
    load(&mut helper, &over);
    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "memories-over",
            "sha256": over.sha256,
            "config": "",
            "limits": limits(FUEL, 4 * 1024 * 1024, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "instantiate_failed");
}

/// The world's import check has two halves, and one artifact cannot test both.
///
/// A component wanting a clock fails the name check *and* the signature check, so
/// `an_undeclared_import_never_reaches_an_instance` stays green with either one deleted. These
/// two fail exactly one each: `notify` has `log`'s signature and the wrong name, and `log` has
/// the right name and the wrong signature.
#[test]
fn the_import_check_holds_by_name_and_by_signature() {
    let mut helper = Helper::spawn(&[]);

    let misnamed = fixture("misnamed", &support::misnamed_import());
    let (refusal, message) = helper.refusal(
        "load",
        json!({ "sha256": misnamed.sha256, "path": misnamed.path }),
    );
    assert_eq!(refusal, "undefined_import");
    assert!(
        message.contains("notify"),
        "the refusal must name the import the world does not declare: {message}"
    );

    let mistyped = fixture("mistyped", &support::mistyped_log());
    let (refusal, message) = helper.refusal(
        "load",
        json!({ "sha256": mistyped.sha256, "path": mistyped.path }),
    );
    assert_eq!(refusal, "undefined_import");
    assert!(
        message.contains("signature"),
        "an import with the right name and the wrong shape must be refused as such: {message}"
    );

    // Neither was admitted.
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 0);
}

/// A sha is a hex digest, and hex has two spellings. Both name the same component: the helper
/// case-folds before it compares, so a peer that upper-cased its digest gets a cache hit rather
/// than a `sha_mismatch` for bytes that are exactly right.
#[test]
fn a_sha_is_matched_without_regard_to_hex_case() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("echo", &support::echo());
    let shouted = fixture.sha256.to_ascii_uppercase();
    assert_ne!(
        shouted, fixture.sha256,
        "the digest must contain hex letters"
    );

    let loaded = helper.ok("load", json!({ "sha256": shouted, "path": fixture.path }));
    assert_eq!(loaded["cached"], false);
    assert_eq!(
        loaded["sha256"], fixture.sha256,
        "the answer names the digest in the one spelling this helper uses"
    );

    // And the cache, and `instantiate`, agree with it.
    let again = helper.ok("load", json!({ "sha256": shouted, "path": fixture.path }));
    assert_eq!(again["cached"], true);
    helper.ok(
        "instantiate",
        json!({
            "instance": "shouted",
            "sha256": shouted,
            "config": "CFG",
            "limits": limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    let answered = helper.ok(
        "call",
        json!({ "instance": "shouted", "export": "handle-message", "payload": "x" }),
    );
    assert_eq!(answered["payload"], "CFG|x");
}

/// The log budget is per *call*, and the proof is the second call.
///
/// `the_log_budget_bounds_one_call` cannot see the refill: a guest past its budget still returns,
/// so the second call answers whether or not `arm` reset anything. This counts the lines. A
/// guest asking for a thousand a message gets sixteen and one marker each time, twice — delete
/// either reset in `arm` and the second call is silent.
#[test]
fn the_log_budget_is_refilled_for_each_call() {
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "refill",
        &support::chatty(),
        limits(FUEL, MEMORY_BYTES, DEADLINE_MS),
    );

    for _ in 0..2 {
        helper.ok(
            "call",
            json!({ "instance": "refill", "export": "handle-message", "payload": "x" }),
        );
    }

    // Two markers means the budget was spent twice, which means it was refilled once.
    let logged = helper.wait_for_two_markers("log budget");
    let markers = logged
        .lines()
        .filter(|line| line.contains("log budget"))
        .count();
    assert_eq!(
        markers, 2,
        "each call gets its own budget and its own one marker line:\n{logged}"
    );

    let content = logged
        .lines()
        .filter(|line| line.contains("guest refill") && !line.contains("log budget"))
        .count();
    assert_eq!(
        content, 32,
        "sixteen lines a call, twice — got {content}:\n{logged}"
    );
}

/// A method with effects cannot be asked for unobserved.
///
/// JSON-RPC says an object with no `id` gets no reply. Running `load`, `instantiate`, `call` or
/// `drop` under that rule means doing work whose refusals go nowhere and whose failures the peer
/// cannot see. So they are refused: the refusal goes to stderr, and nothing happens.
#[test]
fn a_notification_is_refused_rather_than_run() {
    let mut helper = Helper::spawn(&[]);
    let fixture = fixture("echo", &support::echo());

    helper.send_raw(
        &serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "load",
            "params": { "sha256": fixture.sha256, "path": fixture.path },
        }))
        .expect("the notification encodes"),
    );

    // Nothing was loaded, and the next answer on the wire is the answer to *this* request —
    // which is also how we know the notification produced no frame of its own.
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(
        report["held"]["components"], 0,
        "a notification must not admit a component"
    );

    let logged = helper.wait_for_stderr("refused notification");
    assert!(
        logged.contains("refused notification `load`"),
        "the refusal belongs in the owner's log: {logged}"
    );

    // `doctor` is the carve-out, because it does nothing: still unanswered, still harmless.
    helper.send_raw(
        &serde_json::to_string(&json!({ "jsonrpc": "2.0", "method": "doctor" })).expect("encodes"),
    );
    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["usable"], true);
}

/// The hostcall budget meters the guest-to-host direction only. A payload of several megabytes
/// — well within the 8 MiB frame a peer may legitimately send — still reaches the guest, and the
/// guest still answers.
#[test]
fn a_several_megabyte_payload_still_reaches_the_guest() {
    let mut helper = Helper::spawn(&[]);
    stand_up(
        &mut helper,
        "sink",
        &support::sink(),
        limits(FUEL, 32 * 1024 * 1024, DEADLINE_MS),
    );

    let payload = "p".repeat(5 * 1024 * 1024);
    let answered = helper.ok(
        "call",
        json!({ "instance": "sink", "export": "handle-message", "payload": payload }),
    );
    assert_eq!(answered["payload"], "ok");
}
