//! What a component built on `tui/wasm/guest` actually is, observed by building one with a
//! real toolchain and driving the real helper against it.
//!
//! `containment.rs` proves what `ouro-wasm` refuses, against guests written as WAT so the suite
//! needs no wasm toolchain at all. This file asks the other question, the one W9 exists for: an
//! author who writes nothing but their own logic and calls one macro — do they get a component
//! in this world, and is its whole authority still one import?
//!
//! Five artifacts, each built from source that ships in this repository:
//!
//!   * `guest/examples/counter` — a `Capability`, with a `describe` carrying every optional
//!     field of contract C1.
//!   * `guest/examples/deny-writes` — a `Hook`, whose verdict is the stdout contract
//!     `provider/native/hooks.ex` reads back.
//!   * `guest/examples/lintcheck` — a `Check`, whose contract runs the other way: an empty
//!     reply is the **pass**.
//!   * `guest/examples/verdicts` — every `Verdict` variant, selected by config.
//!   * `guest/template` — the scaffold `ouro wasm new` will write (W10), with its placeholders
//!     substituted here exactly as that command will substitute them. A template that does not
//!     compile is a `new` command that hands somebody a broken project, and nothing else in
//!     this repository would have noticed.
//!
//! # What this file cannot prove
//!
//! That the node *reads* any of it. Everything here asserts on the reply text against keys this
//! repository also wrote, so a rename on the `hooks.ex` side leaves all of it green.
//! `test/wasm/sdk_acceptance_test.exs` is the other half: it runs these same built components
//! through `Hooks.pre_tool_use/4` and `Hooks.run_checks/2` and asserts the decision, the
//! labelling and the untrusted narrowing. Neither file is sufficient alone.
//!
//! # When this file does not run
//!
//! Building any of them needs `rustup target add wasm32-wasip2`, which the containment suite
//! deliberately does not. So each test says loudly what it did not check and returns — unless
//! `OUROBOROS_REQUIRE_WASM` is set, which is what CI sets and which turns the skip into the
//! failure it should be there. Same switch, same rule, and the same reason as
//! `test/support/wasm_live_fixture.ex`: a green run that checked nothing should say so, and a
//! run that was supposed to check should fail rather than say so.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const HELPER: &str = env!("CARGO_BIN_EXE_ouro-wasm");

/// The world these components must be in, spelled out rather than imported: this file is the
/// outside view, and a test that read the constant it is checking would prove nothing.
const WORLD: &str = "ouroboros:capability@0.1.0";

/// The target a component is built for. `wasm32-wasip2` emits a component straight from
/// `cargo build`; the `p2` in the name is the target's ABI and not a WASI grant — the world
/// declares one import and the helper's linker defines exactly it.
const TARGET: &str = "wasm32-wasip2";

/// The switch that makes a skip a failure. Same name and same truthiness rule as the Elixir
/// side's.
const REQUIRE: &str = "OUROBOROS_REQUIRE_WASM";

/// As `containment.rs`: long enough that a debug-build compile is never the reason a test
/// fails, short enough that a stuck helper is a failure rather than a hang.
const REPLY_TIMEOUT: Duration = Duration::from_secs(120);

/// A guest here answers a handful of small messages; these are the smallest grants the helper
/// accepts that leave the answer's size out of the question.
const FUEL: u64 = 1_000_000_000;
const MEMORY_BYTES: u64 = 4 * 1024 * 1024;
const DEADLINE_MS: u64 = 30_000;

// ------------------------------------------------------------------------------- the toolchain

/// Whether this machine can build a guest, having said what it cannot do otherwise.
///
/// Asks `rustup` about the toolchain that is *actually selected*, which under `cargo +1.95
/// test` is 1.95 and not the default — so a machine whose default has the target and whose
/// pinned toolchain does not is reported as missing it, which is the truth about the build this
/// test would run.
fn toolchain_ready(what: &str) -> bool {
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();

    let reason = match installed {
        Err(error) => format!("rustup is not runnable here ({error})"),
        Ok(output) if !output.status.success() => {
            format!("`rustup target list --installed` failed: {}", output.status)
        }
        Ok(output) => {
            if String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim() == TARGET)
            {
                return true;
            }
            format!("the selected toolchain has no {TARGET} target (rustup target add {TARGET})")
        }
    };

    let message = format!("SKIPPED {what}: {reason}");

    if required() {
        panic!("{message}\n{REQUIRE} is set, so this is a failure and not a skip");
    }

    shout(&format!(
        "=== {message}\n=== nothing about the SDK's build was checked by that test"
    ));
    false
}

/// Says something that survives a *passing* test.
///
/// `eprintln!` would not: libtest installs an output capture that the `print!` family consults,
/// and a captured stream is only replayed for a test that failed. A skip announced that way is
/// invisible on exactly the run it exists to warn about — which is the silence W7 found in the
/// Elixir suite, reproduced. `io::stderr()` does not consult the capture.
fn shout(message: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{message}");
}

fn required() -> bool {
    match std::env::var(REQUIRE) {
        Ok(value) => !matches!(value.trim(), "" | "0" | "false" | "no"),
        Err(_unset) => false,
    }
}

// ---------------------------------------------------------------------------------- building

/// `tui/wasm`, from which every path below is relative.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Builds a guest project with a plain `cargo build --release --target wasm32-wasip2` and hands
/// back the component it emitted.
///
/// The same cargo that is running this test, so the toolchain the check above asked about is
/// the toolchain that builds. No shared target directory and no extra flags: each of these
/// projects is a standalone workspace, and the claim under test is that an author's own
/// `cargo build` produces an admissible component.
fn build(project: &Path, artifact: &str) -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_unset| "cargo".to_string());

    let output = Command::new(cargo)
        .args(["build", "--release", "--target", TARGET])
        .current_dir(project)
        .output()
        .unwrap_or_else(|error| panic!("cargo does not start: {error}"));

    assert!(
        output.status.success(),
        "{} does not build:\n{}",
        project.display(),
        String::from_utf8_lossy(&output.stderr)
    );

    let component = project
        .join("target")
        .join(TARGET)
        .join("release")
        .join(format!("{artifact}.wasm"));

    assert!(
        component.is_file(),
        "the build succeeded and produced no {}",
        component.display()
    );

    component
}

/// The three files a scaffolded project is made of. `PLACEHOLDERS.md` beside them documents the
/// template for whoever substitutes it and is deliberately not one of them.
const SCAFFOLD_FILES: [&str; 3] = ["Cargo.toml", "README.md", "src/lib.rs"];

/// `tui/wasm/guest/template`.
fn template() -> PathBuf {
    root().join("guest").join("template")
}

/// The scaffold template, substituted into a temporary directory exactly as `ouro wasm new`
/// will substitute it, and the directory it landed in.
///
/// `{{name_snake}}` is replaced before `{{name}}`, because a plain textual pass in the other
/// order turns the first into `<name>_snake`. That ordering is the template's contract and
/// `PLACEHOLDERS.md` says so.
fn scaffold(name: &str, type_name: &str) -> PathBuf {
    let sdk = root().join("guest");
    let substitutions = [
        ("{{name_snake}}", name.replace('-', "_")),
        ("{{name}}", name.to_string()),
        ("{{Name}}", type_name.to_string()),
        ("{{summary}}", "A scaffolded capability.".to_string()),
        ("{{sdk_path}}", sdk.to_string_lossy().into_owned()),
    ];

    // A fixed path under the SDK's own (gitignored, CI-cached) build directory rather than a
    // fresh temp directory per run. Scaffolding into `temp_dir()` meant this test compiled
    // serde_json, dlmalloc and wit-bindgen from scratch on every single run and on every CI
    // job, because nothing could cache a directory whose name carried a nanosecond. The three
    // files are rewritten each time, so a change to the template is still picked up; only
    // `target/` survives.
    let target = root()
        .join("guest")
        .join("target")
        .join("template-scaffold");

    std::fs::create_dir_all(target.join("src")).expect("the scaffold directory is created");

    for relative in SCAFFOLD_FILES {
        let mut written = std::fs::read_to_string(template().join(relative))
            .unwrap_or_else(|error| panic!("the template is missing {relative}: {error}"));

        for (placeholder, value) in &substitutions {
            written = written.replace(placeholder, value);
        }

        assert!(
            !written.contains("{{"),
            "{relative} still holds an unsubstituted placeholder after scaffolding:\n{written}"
        );

        std::fs::write(target.join(relative), written).expect("the scaffold file is written");
    }

    target
}

// ------------------------------------------------------------------------------ the helper

struct Helper {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<String>,
    next_id: i64,
}

impl Helper {
    fn spawn() -> Helper {
        let mut child = Command::new(HELPER)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("ouro-wasm starts");

        let stdin = child.stdin.take().expect("stdin is a pipe");
        let stdout = child.stdout.take().expect("stdout is a pipe");

        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    return;
                }
            }
        });

        Helper {
            child,
            stdin,
            replies,
            next_id: 1,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;

        let line = serde_json::to_string(
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )
        .expect("request encodes");

        self.stdin.write_all(line.as_bytes()).expect("write");
        self.stdin.write_all(b"\n").expect("write newline");
        self.stdin.flush().expect("flush");

        match self.replies.recv_timeout(REPLY_TIMEOUT) {
            Ok(line) => serde_json::from_str(&line).expect("the helper answers with JSON"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("no answer within {REPLY_TIMEOUT:?}: the helper is stuck")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the helper closed its stdout"),
        }
    }

    fn ok(&mut self, method: &str, params: Value) -> Value {
        let reply = self.request(method, params);
        assert!(
            reply.get("error").is_none(),
            "{method} was refused: {}",
            reply["error"]
        );
        reply["result"].clone()
    }

    /// The `data.refusal` name and the message, or a panic naming the result that arrived.
    fn refusal(&mut self, method: &str, params: Value) -> (String, String) {
        let reply = self.request(method, params);
        let error = reply
            .get("error")
            .unwrap_or_else(|| panic!("{method} was expected to refuse, and answered: {reply}"));

        (
            error["data"]["refusal"]
                .as_str()
                .expect("a refusal name")
                .to_string(),
            error["message"].as_str().unwrap_or_default().to_string(),
        )
    }

    /// `inspect`, `load` and `instantiate` a component under one name, and hand back what
    /// `inspect` said about it. The three together are the admission path: a component that
    /// gets an instance is one the world check, the shape pass and the linker all accepted.
    fn admit(&mut self, name: &str, component: &Path, config: &str) -> Value {
        let path = component.to_string_lossy().into_owned();
        let bytes = std::fs::read(component).expect("the component is readable");
        let sha256 = hex(&Sha256::digest(&bytes));

        let inspected = self.ok("inspect", json!({ "path": path }));

        self.ok("load", json!({ "sha256": sha256, "path": path }));
        self.ok(
            "instantiate",
            json!({
                "instance": name,
                "sha256": sha256,
                "config": config,
                "limits": {
                    "fuel": FUEL,
                    "memory_bytes": MEMORY_BYTES,
                    "deadline_ms": DEADLINE_MS,
                },
            }),
        );

        inspected
    }

    /// One message, and the guest's reply as text.
    fn send(&mut self, instance: &str, payload: &str) -> String {
        self.ok(
            "call",
            json!({ "instance": instance, "export": "handle-message", "payload": payload }),
        )["payload"]
            .as_str()
            .expect("a string payload")
            .to_string()
    }

    /// One message, and the guest's reply parsed as JSON.
    fn send_json(&mut self, instance: &str, payload: Value) -> Value {
        let reply = self.send(instance, &payload.to_string());
        serde_json::from_str(&reply)
            .unwrap_or_else(|error| panic!("the guest's reply is not JSON ({error}): {reply}"))
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// The assertion every one of these components has to pass, and the one W9 is judged by: the
/// SDK owns the ceremony, and the import list is still the claim.
fn in_this_world_with_only_log(inspected: &Value, what: &str) {
    assert_eq!(
        inspected["world"], WORLD,
        "{what} is not in this world: {inspected}"
    );

    assert_eq!(
        inspected["imports"],
        json!(["log"]),
        "{what}'s authority is not one log line: {inspected}"
    );

    let mut exports: Vec<&str> = inspected["exports"]
        .as_array()
        .expect("exports is a list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    exports.sort_unstable();

    assert_eq!(
        exports,
        ["describe", "handle-message", "init"],
        "{what} does not export the world: {inspected}"
    );
}

// ------------------------------------------------------------------------------- the proofs

/// The `Capability` seam, end to end: an author writes a struct and three methods, and what
/// comes out is a component in this world whose whole authority is `log`.
///
/// The state assertions are the ones that would survive a rewrite of the glue: a second message
/// answering `messages: 2` can only happen if the SDK's cell held the same value across two
/// calls, and a message *after* a refused one answering at all can only happen if a guest's
/// `Err` left the instance live.
#[test]
fn a_capability_written_on_the_sdk_is_admitted_and_keeps_its_state() {
    if !toolchain_ready("the counter example") {
        return;
    }

    let component = build(&root().join("guest/examples/counter"), "counter");
    let mut helper = Helper::spawn();

    let inspected = helper.admit("counter", &component, r#"{"step": 3}"#);
    in_this_world_with_only_log(&inspected, "the counter example");

    // The configured step, then an explicit amount: both land on one running total.
    assert_eq!(
        helper.send_json("counter", json!({})),
        json!({ "count": 3, "messages": 1 })
    );
    assert_eq!(
        helper.send_json("counter", json!({ "add": 4 })),
        json!({ "count": 7, "messages": 2 })
    );

    // A body the guest cannot use is an `err(string)` the helper classifies, never a trap.
    let (refusal, message) = helper.refusal(
        "call",
        json!({
            "instance": "counter",
            "export": "handle-message",
            "payload": r#"{"add": "seven"}"#,
        }),
    );
    assert_eq!(refusal, "guest_error", "a refused body must not be a trap");
    assert!(
        message.contains("`add` must be"),
        "the guest's own words must reach the host: {message}"
    );

    // And a body that is not JSON at all, which is the SDK's parse and not the author's.
    let (refusal, message) = helper.refusal(
        "call",
        json!({ "instance": "counter", "export": "handle-message", "payload": "not json" }),
    );
    assert_eq!(refusal, "guest_error");
    assert!(
        message.contains("body is not JSON"),
        "the SDK's parse failure must say what it was: {message}"
    );

    // Still live, and still counting from where it was: two refusals cost the instance nothing.
    assert_eq!(
        helper.send_json("counter", json!({ "add": 1 })),
        json!({ "count": 8, "messages": 3 })
    );
}

/// `describe`, on contract C1. The SDK fills `world` in; the author fills in the rest, and the
/// three optional fields are all reachable through the builder.
#[test]
fn a_capability_describes_itself_on_the_shared_contract() {
    if !toolchain_ready("the counter example's describe") {
        return;
    }

    let component = build(&root().join("guest/examples/counter"), "counter");
    let mut helper = Helper::spawn();
    helper.admit("describing", &component, "{}");

    let text = helper.ok(
        "call",
        json!({ "instance": "describing", "export": "describe", "payload": "" }),
    )["payload"]
        .as_str()
        .expect("a string payload")
        .to_string();

    let document: Value = serde_json::from_str(&text).expect("describe answers with JSON");

    assert_eq!(document["name"], "counter");
    assert_eq!(
        document["world"], WORLD,
        "the SDK fills the world in, not the author"
    );
    assert!(
        document["version"].as_str().is_some_and(|v| !v.is_empty()),
        "a version is required: {document}"
    );
    assert!(
        document["summary"]
            .as_str()
            .is_some_and(|summary| summary.len() <= 200),
        "the summary is present and bounded: {document}"
    );
    assert!(
        document["input_schema"].is_object(),
        "an input schema is a JSON Schema: {document}"
    );

    let examples = document["examples"].as_array().expect("examples is a list");
    assert!(
        !examples.is_empty() && examples.len() <= 4,
        "C1 admits one to four examples: {document}"
    );
    assert!(
        examples[0]["message"].is_object() && examples[0]["reply"].is_object(),
        "an example is a message and a reply: {document}"
    );
}

/// The `Hook` seam, against the verdict vocabulary `provider/native/hooks.ex` reads back.
///
/// Every assertion here is on the *reply text*, because that is the whole of what the node
/// parses: `hookSpecificOutput.permissionDecision` and `permissionDecisionReason` for a
/// decision, `additionalContext` for a line with no decision in it, and the empty string for
/// silence. A hook that answered `{}` where it meant silence would be indistinguishable here
/// and materially different there — the empty reply is what `parse_output/1` reads as nothing
/// having happened.
#[test]
fn a_hook_written_on_the_sdk_denies_asks_and_stays_silent() {
    if !toolchain_ready("the deny-writes example") {
        return;
    }

    let component = build(&root().join("guest/examples/deny-writes"), "deny_writes");
    let mut helper = Helper::spawn();

    let inspected = helper.admit("deny-writes", &component, r#"{"root": "src/"}"#);
    in_this_world_with_only_log(&inspected, "the deny-writes example");

    let pre_tool_use = |tool: &str, path: &str| {
        json!({
            "session_id": "sess-sdk",
            "cwd": "/tmp/workspace",
            "workspace_trusted": false,
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": { "path": path, "content": "whatever" },
        })
    };

    // Outside the configured root: a deny, with the reason that becomes the line a human reads.
    let verdict = helper.send_json("deny-writes", pre_tool_use("write", "lib/a.ex"));
    assert_eq!(verdict["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = verdict["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("a deny carries its reason");
    assert!(
        reason.contains("lib/a.ex") && reason.contains("src/"),
        "the reason names the path and the root: {reason}"
    );

    // `..` is refused rather than resolved: a component has no filesystem to resolve it against.
    let verdict = helper.send_json("deny-writes", pre_tool_use("edit", "src/../etc/passwd"));
    assert_eq!(
        verdict["hookSpecificOutput"]["permissionDecision"], "deny",
        "a traversal that begins under the root is still a traversal"
    );

    // Inside it: no decision at all, one context line. Not an `allow` — an untrusted workspace's
    // `allow` is read as silence, so a hook that meant "fine by me" and said `allow` would be
    // saying nothing there and resolving a human's prompt here.
    let verdict = helper.send_json("deny-writes", pre_tool_use("Write", "src/main.rs"));
    assert!(
        verdict["hookSpecificOutput"]["permissionDecision"].is_null(),
        "an allowed write states no decision: {verdict}"
    );
    let context = verdict["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("a context line");
    assert!(
        context.contains("src/main.rs"),
        "the context line names what it checked: {context}"
    );

    // A tool this hook has no opinion about, and an event it has no opinion about: both are the
    // empty reply, which is the only thing `parse_output/1` reads as silence.
    assert_eq!(
        helper.send(
            "deny-writes",
            &pre_tool_use("bash", "src/main.rs").to_string()
        ),
        ""
    );
    assert_eq!(
        helper.send(
            "deny-writes",
            &json!({ "hook_event_name": "Stop", "session_id": "sess-sdk" }).to_string()
        ),
        ""
    );
}

/// The `Check` seam, whose contract is the one that is easiest to get backwards: **an empty
/// reply is a pass**, and the failure is the text itself.
///
/// Both directions are asserted here, and both matter in the same way: a `Fail` arm that
/// returned the empty string turns a failing check into a silent pass, and a `Pass` arm that
/// returned anything at all turns a passing check into a permanent failure injected into every
/// turn. Neither shows up in a reply this file did not look at.
///
/// The reply is also *not JSON* — a `[checks]` failure is plain text — which is the other half
/// of why `Check` is its own seam and not `Capability` with a convention.
#[test]
fn a_check_written_on_the_sdk_is_silent_on_a_pass_and_text_on_a_failure() {
    if !toolchain_ready("the lintcheck example") {
        return;
    }

    let component = build(&root().join("guest/examples/lintcheck"), "lintcheck");
    let mut helper = Helper::spawn();

    let inspected = helper.admit("failing", &component, r#"{"fail": true}"#);
    in_this_world_with_only_log(&inspected, "the lintcheck example");

    // The payload `hooks.ex` sends a check: an event and the key it was declared under, and
    // nothing about the session at all.
    let check = |name: &str| json!({ "event": "check", "name": name }).to_string();

    let failure = helper.send("failing", &check("lint"));
    assert!(
        !failure.is_empty(),
        "a failing check's reply is its failure text, and an empty reply is a PASS"
    );
    assert!(
        failure.contains("check `lint` says no"),
        "the check is told the key it was declared under: {failure}"
    );
    assert!(
        failure.lines().count() > 1,
        "the failure is multi-line, which is what the node's per-line labelling is for: {failure}"
    );

    // A second instance of the same component, configured the other way. One artifact, both
    // directions, so nothing here can pass because two different builds disagreed.
    let sha256 = hex(&Sha256::digest(
        std::fs::read(&component).expect("the component is readable"),
    ));
    helper.ok(
        "instantiate",
        json!({
            "instance": "passing",
            "sha256": sha256,
            "config": r#"{"fail": false}"#,
            "limits": { "fuel": FUEL, "memory_bytes": MEMORY_BYTES, "deadline_ms": DEADLINE_MS },
        }),
    );

    assert_eq!(
        helper.send("passing", &check("typecheck")),
        "",
        "a passing check is the empty reply, and nothing else is"
    );
}

/// Every [`Verdict`] variant, as the reply text the node parses.
///
/// The narrowing itself — `allow` read as silence, `updatedInput` dropped — is enforced in
/// `hooks.ex` and is proved in `test/wasm/sdk_acceptance_test.exs`, which runs this same
/// component through it. What is proved *here* is the other half: that the reply carries the
/// key at all, so that when the Elixir test sees `allow` disappear it is seeing the narrowing
/// and not a fixture that never said `allow`.
#[test]
fn the_whole_verdict_vocabulary_survives_the_round_trip() {
    if !toolchain_ready("the verdicts example") {
        return;
    }

    let component = build(&root().join("guest/examples/verdicts"), "verdicts");
    let sha256 = hex(&Sha256::digest(
        std::fs::read(&component).expect("the component is readable"),
    ));

    let mut helper = Helper::spawn();
    let inspected = helper.admit("silent", &component, r#"{"say": "silent"}"#);
    in_this_world_with_only_log(&inspected, "the verdicts example");

    let mut say = |name: &str, verdict: &str| {
        helper.ok(
            "instantiate",
            json!({
                "instance": name,
                "sha256": sha256,
                "config": format!(r#"{{"say": "{verdict}"}}"#),
                "limits": {
                    "fuel": FUEL, "memory_bytes": MEMORY_BYTES, "deadline_ms": DEADLINE_MS,
                },
            }),
        );
        helper.send(
            name,
            &json!({ "hook_event_name": "PreToolUse" }).to_string(),
        )
    };

    assert_eq!(say("s", "silent"), "", "silence is the empty reply");

    let allow: Value = serde_json::from_str(&say("a", "allow")).expect("JSON");
    assert_eq!(allow["hookSpecificOutput"]["permissionDecision"], "allow");

    let deny: Value = serde_json::from_str(&say("d", "deny")).expect("JSON");
    assert_eq!(deny["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(deny["hookSpecificOutput"]["permissionDecisionReason"].is_string());

    let ask: Value = serde_json::from_str(&say("k", "ask")).expect("JSON");
    assert_eq!(ask["hookSpecificOutput"]["permissionDecision"], "ask");

    let context: Value = serde_json::from_str(&say("c", "context")).expect("JSON");
    let lines = context["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("a context string");
    assert_eq!(
        lines.lines().count(),
        3,
        "three lines in one string: {lines}"
    );

    let rewrite: Value = serde_json::from_str(&say("u", "updated_input")).expect("JSON");
    assert_eq!(
        rewrite["hookSpecificOutput"]["updatedInput"]["path"],
        "somewhere/else.txt"
    );

    // A `say` this fixture does not know is refused at `instantiate`, so a typo in a test's
    // config can never quietly become silence — which would make every assertion above it
    // vacuous.
    let (refusal, message) = helper.refusal(
        "instantiate",
        json!({
            "instance": "nonsense",
            "sha256": sha256,
            "config": r#"{"say": "maybe"}"#,
            "limits": { "fuel": FUEL, "memory_bytes": MEMORY_BYTES, "deadline_ms": DEADLINE_MS },
        }),
    );
    assert_eq!(refusal, "guest_error");
    assert!(message.contains("maybe"), "the refusal names it: {message}");
}

/// A hook whose config it cannot use refuses at `instantiate`, which is where the node can still
/// do something about it — and it refuses rather than trapping.
#[test]
fn a_hook_that_cannot_use_its_config_says_so_at_instantiate() {
    if !toolchain_ready("the deny-writes example's config") {
        return;
    }

    let component = build(&root().join("guest/examples/deny-writes"), "deny_writes");
    let path = component.to_string_lossy().into_owned();
    let sha256 = hex(&Sha256::digest(
        std::fs::read(&component).expect("the component is readable"),
    ));

    let mut helper = Helper::spawn();
    helper.ok("load", json!({ "sha256": sha256, "path": path }));

    let (refusal, message) = helper.refusal(
        "instantiate",
        json!({
            "instance": "rootless",
            "sha256": sha256,
            "config": "{}",
            "limits": { "fuel": FUEL, "memory_bytes": MEMORY_BYTES, "deadline_ms": DEADLINE_MS },
        }),
    );

    assert_eq!(refusal, "guest_error", "a refused config is not a trap");
    assert!(
        message.contains("`root`"),
        "the guest says which config it wanted: {message}"
    );
}

/// The scaffold `ouro wasm new` will write (W10), substituted and built here so that command
/// cannot ship a template that does not compile.
///
/// It also answers, because a template that compiles and cannot hold a message would be a
/// worked example of nothing.
#[test]
fn the_scaffold_template_builds_into_a_component_in_this_world() {
    if !toolchain_ready("the scaffold template") {
        return;
    }

    let project = scaffold("my-capability", "MyCapability");
    let component = build(&project, "my_capability");

    let mut helper = Helper::spawn();
    let inspected = helper.admit("scaffolded", &component, "{}");
    in_this_world_with_only_log(&inspected, "the scaffold template");

    let reply = helper.send_json("scaffolded", json!({ "hello": "world" }));
    assert_eq!(reply["echo"], json!({ "hello": "world" }));
    assert_eq!(reply["messages"], 1);
}

/// Every placeholder the template actually uses is one `PLACEHOLDERS.md` documents.
///
/// W10 reads that table to write `ouro wasm new`, so a placeholder added to a template file and
/// not to the table is a substitution that command will not make — and the scaffolded project
/// would carry a literal `{{…}}` into somebody's `Cargo.toml`. This test needs no toolchain: it
/// is the one thing here a machine without `wasm32-wasip2` still checks.
#[test]
fn every_placeholder_the_template_uses_is_documented() {
    let table = std::fs::read_to_string(template().join("PLACEHOLDERS.md"))
        .expect("the template documents its own placeholders");

    for relative in SCAFFOLD_FILES {
        let source = std::fs::read_to_string(template().join(relative))
            .unwrap_or_else(|error| panic!("the template is missing {relative}: {error}"));

        let mut rest = source.as_str();
        while let Some(open) = rest.find("{{") {
            let after = &rest[open..];
            let close = after
                .find("}}")
                .unwrap_or_else(|| panic!("{relative} opens a placeholder it never closes"));
            let placeholder = &after[..close + 2];

            assert!(
                table.contains(placeholder),
                "{relative} uses {placeholder}, which PLACEHOLDERS.md does not document"
            );

            rest = &after[close + 2..];
        }
    }
}
