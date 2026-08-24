#![cfg(feature = "desktop")]

//! The native window is intentionally thin. These tests pin the semantic seam beneath it:
//! a desktop control must produce the same reducer calls and transcript/approval meaning as
//! the terminal client, without needing a window server in CI.

mod support;

use ouro::model::{ApprovalDecision, ApprovalScope, Plane};
use ouro::proto::Notification;
use ouro::transport::ClientError;
use ouro::ui::app::{App, DesktopCellKind, DesktopTone, Mode, Msg, Tag};
use serde_json::{json, Value};

use support::full_hello;

const SESSION: &str = "session-desktop-1";

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn notify(app: &mut App, sequence: u64, kind: &str, payload: Value) {
    app.apply(Msg::Notification(Notification {
        method: "interactive.event".into(),
        params: json!({
            "id": SESSION,
            "event": {
                "_struct": "Ouroboros.Interactive.Event",
                "id": format!("evt-{sequence}"),
                "session_id": SESSION,
                "sequence": sequence,
                "type": kind,
                "timestamp": "2026-01-01T00:00:00.000000Z",
                "turn_id": "turn-desktop-1",
                "request_id": payload.get("request_id").cloned().unwrap_or(Value::Null),
                "payload": payload
            }
        }),
    }));
}

fn opened() -> App {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": SESSION,
            "node": "ouroboros@golden",
            "provider": "native",
            "model": "openai_codex:gpt-5.6-sol",
            "workspace": "/tmp/desktop-workspace",
            "status": "running",
            "options": { "approval_mode": "prompt", "sandbox_mode": "workspace_write" },
            "created_at": "2026-01-01T00:00:00.000000Z",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    app.open_session(Plane::Interactive, SESSION.into());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes");
    answer(&mut app, subscribe.tag, json!([]));
    app.drain();
    app
}

#[test]
fn desktop_session_and_transcript_are_reducer_projections() {
    let mut app = opened();
    notify(
        &mut app,
        1,
        "input_accepted",
        json!({ "text": "Inspect the seam." }),
    );
    notify(
        &mut app,
        2,
        "output_text_final",
        json!({ "text": "The seam is shared." }),
    );

    let sessions = app.desktop_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, SESSION);
    assert!(sessions[0].selected);
    assert_eq!(sessions[0].provider.as_deref(), Some("native"));

    let cells = app.desktop_transcript();
    assert_eq!(cells.len(), 2);
    assert_eq!(cells[0].kind, DesktopCellKind::Message);
    assert_eq!(cells[0].label, "You");
    assert_eq!(cells[0].body, "Inspect the seam.");
    assert_eq!(cells[0].tone, DesktopTone::Accent);
    assert_eq!(cells[1].label, "Agent");
    assert_eq!(cells[1].body, "The seam is shared.");
}

#[test]
fn desktop_send_uses_the_existing_follow_up_reconciliation() {
    let mut app = opened();
    app.desktop_submit_message("Run the focused checks.\n")
        .expect("an open interactive session accepts a message");

    let calls = app.drain();
    let send = calls
        .iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("desktop send uses the TUI follow-up path");
    assert_eq!(send.params["id"], SESSION);
    assert_eq!(send.params["input"], "Run the focused checks.");
    assert!(send.params["turn_id"].as_str().is_some());
}

#[test]
fn desktop_send_never_overwrites_a_restored_terminal_draft() {
    let mut app = opened();
    app.desktop_submit_message("Keep this draft.")
        .expect("the first draft is submitted");
    let send = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first draft reaches reconciliation");
    app.apply(Msg::Answer {
        tag: send.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    let error = app
        .desktop_submit_message("Replace it invisibly.")
        .expect_err("a desktop draft must not erase restored TUI work");
    assert!(error.contains("restored terminal draft"));
    assert!(app.drain().is_empty());
}

#[test]
fn desktop_approval_is_complete_and_rejects_a_stale_button() {
    let mut app = opened();
    notify(
        &mut app,
        1,
        "approval_requested",
        json!({
            "request_id": "req-desktop-9",
            "kind": "sandbox_escalation",
            "reason": "the command writes outside the workspace",
            "suggested_rule": "Bash(cargo test *)",
            "diff": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n",
            "tool_call": {
                "name": "exec_command",
                "command": "cargo test --all",
                "cwd": "/tmp/desktop-workspace",
                "locations": [{ "path": "/tmp/shared-cache" }]
            }
        }),
    );

    let approval = app.desktop_approval().expect("a pending desktop approval");
    assert_eq!(approval.request_id, "req-desktop-9");
    assert_eq!(approval.kind.as_deref(), Some("sandbox escalation"));
    assert_eq!(approval.command.as_deref(), Some("cargo test --all"));
    assert_eq!(approval.cwd.as_deref(), Some("/tmp/desktop-workspace"));
    assert_eq!(approval.locations, ["/tmp/shared-cache"]);
    assert_eq!(
        approval.suggested_rule.as_deref(),
        Some("Bash(cargo test *)")
    );
    let diff = approval
        .diff
        .as_ref()
        .expect("the pending diff remains visible");
    assert!(diff.label.contains("+1 −1"));
    assert!(diff.text.contains("+new"));
    assert_eq!(approval.choices.len(), 4);

    let error = app
        .desktop_respond_approval("req-stale", ApprovalDecision::Approve, ApprovalScope::Once)
        .expect_err("a stale native button must not answer a newer approval");
    assert!(error.contains("approval changed"));
    assert!(app.drain().is_empty());

    app.desktop_respond_approval(
        "req-desktop-9",
        ApprovalDecision::Approve,
        ApprovalScope::Once,
    )
    .expect("the reviewed request is answerable");
    let response = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("the approval response is routed through the reducer");
    assert_eq!(response.params["id"], SESSION);
    assert_eq!(response.params["request_id"], "req-desktop-9");
}

#[test]
fn desktop_new_session_keeps_operator_choices_explicit() {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);
    app.drain();

    let id = app
        .desktop_start_session(
            "native".into(),
            Some("openai_codex:gpt-5.6-sol".into()),
            "/tmp/desktop-workspace".into(),
        )
        .expect("the operate-capable gateway can start a session");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("the native form emits an interactive.start call");
    assert_eq!(start.params["id"], id);
    assert_eq!(start.params["provider"], "native");
    assert_eq!(start.params["model"], "openai_codex:gpt-5.6-sol");
    assert_eq!(start.params["workspace"], "/tmp/desktop-workspace");
}
