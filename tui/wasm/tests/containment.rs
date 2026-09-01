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
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let seen = self.stderr.lock().expect("stderr lock").clone();
            if seen.contains(needle) || Instant::now() > deadline {
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

/// Neither map evicts anything, so both need a ceiling, and hitting it is a typed refusal
/// rather than a helper that grows until the node notices.
#[test]
fn the_component_and_instance_tables_are_bounded() {
    let mut helper = Helper::spawn(&[]);

    // 64 components fit; the 65th does not. Each is a distinct guest, so each is a distinct sha.
    let mut last = None;
    for n in 0..64 {
        let fixture = fixture("many", &support::oversize(n + 1));
        helper.ok(
            "load",
            json!({ "sha256": fixture.sha256, "path": fixture.path }),
        );
        last = Some(fixture);
    }
    let overflow = fixture("many", &support::oversize(65));
    let (refusal, _) = helper.refusal(
        "load",
        json!({ "sha256": overflow.sha256, "path": overflow.path }),
    );
    assert_eq!(refusal, "too_many_components");

    // 256 instances of the last one fit; the 257th does not.
    let held = last.expect("a component was loaded");
    for n in 0..256 {
        helper.ok(
            "instantiate",
            json!({
                "instance": format!("i{n}"),
                "sha256": held.sha256,
                "config": "",
                "limits": limits(FUEL, MIN_MEMORY_BYTES, DEADLINE_MS),
            }),
        );
    }
    let (refusal, _) = helper.refusal(
        "instantiate",
        json!({
            "instance": "one-too-many",
            "sha256": held.sha256,
            "config": "",
            "limits": limits(FUEL, MIN_MEMORY_BYTES, DEADLINE_MS),
        }),
    );
    assert_eq!(refusal, "too_many_instances");

    let report = helper.ok("doctor", Value::Null);
    assert_eq!(report["held"]["components"], 64);
    assert_eq!(report["held"]["instances"], 256);
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
