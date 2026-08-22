//! `ouro hook post-tool-use`, driven as the two contracts it sits between.
//!
//! One half is Claude Code's `PostToolUse` shape — a JSON object on stdin, a JSON object
//! on stdout — and the tests for it assert on bytes, because "additionalContext" arriving
//! under a different key is a hook that silently does nothing.
//!
//! The other half is the gateway, and it runs against `support::Peer`, the same scripted
//! peer every other client test uses, so the announce/wait/diff sequence exercised here is
//! the real one.
//!
//! The property under all of it: whatever happens, the edit stands. There is no input to
//! this module that produces a refusal, and no failure that produces one either.

mod support;

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use ouro::hook::{
    additional_context, frame, PostToolUse, APPLIED, EDIT_TOOLS, HOOK_EVENT, NO_DATA, NO_NEW,
};
use ouro::mcp_serve::{Bridge, PostEdit, Server, DIAGNOSTICS_METHOD, INFO_METHOD, TOUCH_METHOD};

use support::{listener, Peer, TOKEN};

const SESSION: &str = "s-hook-1";
const WORKSPACE: &str = "/work/repo";

static TOKEN_FILES: AtomicU32 = AtomicU32::new(0);

fn token_file() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ouro-hook-token-{}-{}",
        std::process::id(),
        TOKEN_FILES.fetch_add(1, Ordering::Relaxed)
    ));

    fs::write(&path, TOKEN).expect("a writable temp dir");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("a chmodable file");

    path
}

fn server(addr: SocketAddr) -> Server {
    Server::new(Ok(Bridge {
        addr,
        token_file: token_file(),
        session_id: SESSION.to_string(),
        node: Some("ouroboros@host".to_string()),
        timeout: Duration::from_secs(5),
    }))
}

fn diagnostic(signature: &str, severity: &str, line: u64, message: &str) -> Value {
    json!({
        "signature": signature,
        "severity": severity,
        "code": "E001",
        "source": "fake",
        "message": message,
        "tags": [],
        "range": {
            "start": {"line": line, "character": 4},
            "end": {"line": line, "character": 9}
        }
    })
}

async fn answer(peer: &mut Peer, method: &str, result: Value) -> Value {
    let request = peer.request_for(method).await;
    peer.result(&request["id"], result).await;

    request
}

async fn answer_info(peer: &mut Peer) {
    answer(
        peer,
        INFO_METHOD,
        json!({"id": SESSION, "workspace": WORKSPACE, "status": "idle"}),
    )
    .await;
}

// ---------------------------------------------------------------------------
// The stdin shape
// ---------------------------------------------------------------------------

#[test]
fn the_payload_shapes_claude_code_sends() {
    let edit = PostToolUse::parse(
        &json!({
            "session_id": "claude-session-9",
            "transcript_path": "/tmp/t.jsonl",
            "cwd": "/work/repo",
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "/work/repo/lib/a.ex", "old_string": "a", "new_string": "b"},
            "tool_response": {"success": true}
        })
        .to_string(),
    );

    assert_eq!(edit.tool_name.as_deref(), Some("Edit"));
    assert_eq!(edit.path.as_deref(), Some("/work/repo/lib/a.ex"));
    // Claude's session id, kept apart from Ouroboros's: this one names nothing here.
    assert_eq!(edit.session_id.as_deref(), Some("claude-session-9"));
    assert_eq!(edit.absolute_path().as_deref(), Some("/work/repo/lib/a.ex"));

    // NotebookEdit names the file differently, and a relative path is relative to the
    // directory the tool ran in.
    let notebook = PostToolUse::parse(
        &json!({
            "cwd": "/work/repo",
            "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": "notes/a.ipynb"}
        })
        .to_string(),
    );

    assert_eq!(
        notebook.absolute_path().as_deref(),
        Some("/work/repo/notes/a.ipynb")
    );

    // Everything that is not a payload is an empty one, never an error.
    for input in ["", "   ", "not json", "[]", "{\"tool_input\": 4}"] {
        let event = PostToolUse::parse(input);
        assert_eq!(event.absolute_path(), None, "{input:?}");
    }

    // A tool call with no file in it has nothing to say about a file.
    let bash = PostToolUse::parse(
        &json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}).to_string(),
    );
    assert_eq!(bash.absolute_path(), None);
}

// ---------------------------------------------------------------------------
// The stdout shape, byte for byte
// ---------------------------------------------------------------------------

#[test]
fn the_output_is_the_contract_and_nothing_else() {
    let encoded = frame("Edit applied.\nNo new diagnostics.");

    // One object, two keys, and the newline escaped rather than written: a hook's stdout
    // is read as JSON, so the multi-line context has to survive being one line of bytes.
    assert_eq!(
        encoded,
        r#"{"hookSpecificOutput":{"additionalContext":"Edit applied.\nNo new diagnostics.","hookEventName":"PostToolUse"}}"#
    );
    assert!(!encoded.contains('\n'));

    // Decodable, and under the keys Claude Code reads.
    let value: Value = serde_json::from_str(&encoded).expect("a JSON object");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], HOOK_EVENT);
    assert_eq!(
        value["hookSpecificOutput"]["additionalContext"],
        "Edit applied.\nNo new diagnostics."
    );
}

#[test]
fn the_success_line_comes_first_in_every_shape() {
    // OpenCode #9102: diagnostics without an explicit success line made agents retry
    // edits that had worked. There is no branch here that omits it.
    for outcome in [
        PostEdit::NoData,
        PostEdit::Fresh(vec![]),
        PostEdit::Fresh(vec![diagnostic("a", "error", 0, "boom")]),
    ] {
        let text = additional_context("lib/a.ex", &outcome);
        assert!(text.starts_with(APPLIED), "{text}");
        assert!(text.lines().next() == Some(APPLIED), "{text}");
    }

    assert_eq!(
        additional_context("lib/a.ex", &PostEdit::NoData),
        format!("{APPLIED}\n{NO_DATA}")
    );
    assert_eq!(
        additional_context("lib/a.ex", &PostEdit::Fresh(vec![])),
        format!("{APPLIED}\n{NO_NEW}")
    );
}

#[test]
fn one_new_error_reads_as_one_line_under_a_count() {
    let text = additional_context(
        "lib/a.ex",
        &PostEdit::Fresh(vec![diagnostic("a", "error", 11, "undefined variable")]),
    );

    assert_eq!(
        text,
        "Edit applied.\nFound 1 new diagnostic issue in lib/a.ex:\n  error 12:5 [E001] undefined variable"
    );
}

#[test]
fn errors_are_never_dropped_and_warnings_and_length_are_bounded() {
    let mut found: Vec<Value> = (0..30)
        .map(|index| diagnostic(&format!("e{index}"), "error", index, "boom"))
        .collect();

    found.extend((0..10).map(|index| diagnostic(&format!("w{index}"), "warning", index, "style")));

    // Two hints, which are below the severity gate entirely.
    found.push(diagnostic("h1", "hint", 1, "consider"));
    found.push(diagnostic("h2", "information", 2, "note"));

    let text = additional_context("lib/a.ex", &PostEdit::Fresh(found));
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines[0], APPLIED);
    assert_eq!(lines[1], "Found 42 new diagnostic issues in lib/a.ex:");

    // Twenty item lines, then one line accounting for everything not shown.
    assert_eq!(lines.len(), 2 + 20 + 1);
    assert_eq!(lines[lines.len() - 1], "  +22 more");
    assert!(lines[2..22].iter().all(|line| line.contains("error")));
}

#[test]
fn at_most_three_warnings_reach_the_model() {
    let found: Vec<Value> = (0..8)
        .map(|index| diagnostic(&format!("w{index}"), "warning", index, "style"))
        .collect();

    let text = additional_context("lib/a.ex", &PostEdit::Fresh(found));
    let warnings = text.lines().filter(|line| line.contains("warning")).count();

    assert_eq!(warnings, 3, "{text}");
    assert!(text.contains("+5 more"), "{text}");
}

#[test]
fn the_matcher_names_the_four_edit_tools_the_adapter_installs_it_for() {
    // The adapter writes this string into `--settings`; the two must not drift.
    assert_eq!(EDIT_TOOLS, "Edit|Write|MultiEdit|NotebookEdit");
}

// ---------------------------------------------------------------------------
// The gateway half
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_hook_reports_what_the_edit_added_and_nothing_it_found() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, TOUCH_METHOD, DIAGNOSTICS_METHOD])
            .await;
        answer_info(&mut peer).await;

        let touched = answer(
            &mut peer,
            TOUCH_METHOD,
            json!({
                "version": 3,
                "baseline": {"fresh?": true, "version": 2, "truncated": 0,
                             "signatures": ["was-here-before"], "counts": {"error": 1}}
            }),
        )
        .await;

        answer(
            &mut peer,
            DIAGNOSTICS_METHOD,
            json!({
                "status": "ok",
                "version": 3,
                "truncated": 0,
                "items": [
                    diagnostic("was-here-before", "error", 1, "pre-existing"),
                    diagnostic("brand-new", "error", 11, "undefined variable")
                ]
            }),
        )
        .await;

        touched
    });

    let mut server = server(address);
    let outcome = server
        .post_edit_diagnostics("/work/repo/lib/a.ex")
        .await
        .expect("an outcome");

    let text = additional_context("lib/a.ex", &outcome);
    assert!(text.contains("Found 1 new diagnostic issue"), "{text}");
    assert!(text.contains("undefined variable"), "{text}");
    assert!(!text.contains("pre-existing"), "{text}");

    let touched = script.await.expect("the script");
    assert_eq!(touched["params"]["workspace"], WORKSPACE);
    assert_eq!(touched["params"]["path"], "/work/repo/lib/a.ex");
    assert_eq!(touched["params"]["action"], "changed");
}

#[tokio::test]
async fn a_runtime_that_never_answers_is_no_lsp_data_and_not_a_failure() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, TOUCH_METHOD, DIAGNOSTICS_METHOD])
            .await;
        answer_info(&mut peer).await;
        answer(&mut peer, TOUCH_METHOD, json!({"version": 2})).await;
        // The push that would describe the new content never arrives.
        answer(
            &mut peer,
            DIAGNOSTICS_METHOD,
            json!({"status": "pending", "version": 1}),
        )
        .await
    });

    let mut server = server(address);
    let outcome = server
        .post_edit_diagnostics("/work/repo/lib/a.ex")
        .await
        .expect("an outcome");

    assert!(matches!(outcome, PostEdit::NoData));
    assert_eq!(
        additional_context("lib/a.ex", &outcome),
        format!("{APPLIED}\n{NO_DATA}")
    );

    script.await.expect("the script");
}

#[tokio::test]
async fn a_runtime_that_refuses_is_still_an_applied_edit() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, TOUCH_METHOD]).await;
        answer_info(&mut peer).await;

        let asked = peer.request_for(TOUCH_METHOD).await;
        peer.error(&asked["id"], -32003, "scope denied", None).await;
    });

    let mut server = server(address);
    let refusal = server.post_edit_diagnostics("/work/repo/lib/a.ex").await;

    // The refusal reaches the caller as an error; `ouro hook post-tool-use` turns every
    // one of them into `NoData`, which is the shape the model reads.
    assert!(refusal.is_err(), "{refusal:?}");
    assert_eq!(
        additional_context("lib/a.ex", &PostEdit::NoData),
        format!("{APPLIED}\n{NO_DATA}")
    );

    script.await.expect("the script");
}

#[tokio::test]
async fn no_runtime_at_all_is_no_lsp_data() {
    // A bridge whose environment is absent: the shape a hook run by hand would take.
    let mut server = Server::new(Err("OUROBOROS_GATEWAY_ADDR is not set".to_string()));

    assert!(server
        .post_edit_diagnostics("/work/repo/lib/a.ex")
        .await
        .is_err());
}

// ---------------------------------------------------------------------------
// The process
// ---------------------------------------------------------------------------

/// The binary itself, with no bridge in its environment and a real payload on stdin: it
/// must exit 0 and say the edit applied, because by the time a `PostToolUse` hook runs the
/// edit already has.
#[test]
fn the_subcommand_exits_zero_with_no_runtime_to_ask() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let payload = json!({
        "session_id": "claude-session-1",
        "cwd": "/work/repo",
        "tool_name": "Write",
        "tool_input": {"file_path": "/work/repo/lib/a.ex", "content": "x"}
    })
    .to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_ouro"))
        .args(["hook", "post-tool-use"])
        .env_remove("OUROBOROS_GATEWAY_ADDR")
        .env_remove("OUROBOROS_GATEWAY_TOKEN_FILE")
        .env_remove("OUROBOROS_SESSION_ID")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ouro binary");

    child
        .stdin
        .as_mut()
        .expect("a stdin")
        .write_all(payload.as_bytes())
        .expect("a writable stdin");

    let output = child.wait_with_output().expect("an exit");

    assert!(output.status.success(), "{:?}", output.status);

    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let value: Value = serde_json::from_str(stdout.trim()).expect("one JSON object");

    assert_eq!(value["hookSpecificOutput"]["hookEventName"], HOOK_EVENT);
    assert_eq!(
        value["hookSpecificOutput"]["additionalContext"],
        format!("{APPLIED}\n{NO_DATA}")
    );
}

/// A tool call with no file in it produces no output at all: an empty stdout is a hook
/// that ran and had nothing to add, and it costs the turn no tokens.
#[test]
fn a_tool_call_with_no_file_says_nothing() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let payload =
        json!({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/work"}).to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_ouro"))
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ouro binary");

    child
        .stdin
        .as_mut()
        .expect("a stdin")
        .write_all(payload.as_bytes())
        .expect("a writable stdin");

    let output = child.wait_with_output().expect("an exit");

    assert!(output.status.success(), "{:?}", output.status);
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
}

/// Nothing on stdin at all — a harness that closed the pipe, or a person who ran this by
/// mistake. Still zero, still nothing to say.
#[test]
fn an_empty_stdin_is_not_a_failure() {
    use std::process::{Command, Stdio};

    let output = Command::new(env!("CARGO_BIN_EXE_ouro"))
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the ouro binary");

    assert!(output.status.success(), "{:?}", output.status);
    assert!(output.stdout.is_empty());
}
