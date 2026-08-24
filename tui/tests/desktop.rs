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
            "title": "Investigate the desktop seam",
            "node": "ouroboros@golden",
            "provider": "native",
            "workspace": "/tmp/desktop-workspace",
            "status": "running",
            "options": {
                "model": "openai_codex:gpt-5.6-sol",
                "approval_mode": "prompt",
                "sandbox_mode": "workspace_write"
            },
            "created_at": "2026-01-01T00:00:00.000000Z",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    answer(
        &mut app,
        Tag::Account,
        json!({
            "account": Value::Null,
            "requiresOpenaiAuth": false,
            "login": { "status": "idle" }
        }),
    );
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

    let waiting = app.desktop_transcript();
    assert_eq!(waiting.len(), 2);
    assert_eq!(waiting[0].kind, DesktopCellKind::Message);
    assert_eq!(waiting[0].label, "You");
    assert_eq!(waiting[0].tone, DesktopTone::Neutral);
    assert_eq!(waiting[1].kind, DesktopCellKind::Activity);
    assert_eq!(waiting[1].label, "Agent is working");
    assert!(waiting[1].streaming);

    notify(
        &mut app,
        2,
        "output_text_final",
        json!({ "text": "The seam is shared." }),
    );

    let sessions = app.desktop_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, SESSION);
    assert_eq!(
        sessions[0].title.as_deref(),
        Some("Investigate the desktop seam")
    );
    assert!(sessions[0].selected);
    assert!(sessions[0].can_rename);
    assert!(!sessions[0].can_delete);
    assert_eq!(sessions[0].provider.as_deref(), Some("native"));
    assert_eq!(
        sessions[0].model.as_deref(),
        Some("openai_codex:gpt-5.6-sol")
    );

    let cells = app.desktop_transcript();
    assert_eq!(cells.len(), 2);
    assert_eq!(cells[0].kind, DesktopCellKind::Message);
    assert_eq!(cells[0].label, "You");
    assert_eq!(cells[0].body, "Inspect the seam.");
    assert_eq!(cells[0].tone, DesktopTone::Neutral);
    assert_eq!(cells[1].label, "Agent");
    assert_eq!(cells[1].body, "The seam is shared.");
    assert_eq!(cells[1].tone, DesktopTone::Accent);
    assert!(!cells[1].streaming);
}

#[test]
fn desktop_keeps_agent_metadata_visible_without_promoting_it_over_the_answer() {
    let mut app = opened();
    notify(
        &mut app,
        1,
        "input_accepted",
        json!({ "text": "Check the focused suite." }),
    );
    notify(
        &mut app,
        2,
        "thinking_delta",
        json!({ "text": "Finding the narrowest useful test." }),
    );
    notify(
        &mut app,
        3,
        "tool_call",
        json!({
            "call_id": "desktop-tool-1",
            "name": "exec_command",
            "input": { "cmd": "cargo test --test desktop" }
        }),
    );
    notify(
        &mut app,
        4,
        "tool_result",
        json!({
            "call_id": "desktop-tool-1",
            "output": "9 passed; 0 failed",
            "is_error": false
        }),
    );

    let cells = app.desktop_transcript();
    let thinking = cells
        .iter()
        .find(|cell| cell.kind == DesktopCellKind::Thinking)
        .expect("reasoning remains inspectable in the desktop transcript");
    assert_eq!(thinking.tone, DesktopTone::Muted);
    assert_eq!(thinking.body, "Finding the narrowest useful test.");

    let tool = cells
        .iter()
        .find(|cell| cell.kind == DesktopCellKind::Tool)
        .expect("tool metadata remains visible in the desktop transcript");
    assert_eq!(tool.tone, DesktopTone::Muted);
    assert!(tool.label.contains("cargo test --test desktop"));
    assert!(tool.body.contains("9 passed; 0 failed"));

    assert_eq!(
        cells.last().map(|cell| cell.kind),
        Some(DesktopCellKind::Activity),
        "the loader stays in the conversation after metadata until visible agent text arrives"
    );
}

#[test]
fn desktop_attaches_passive_bookkeeping_to_the_agent_reply() {
    let mut app = opened();
    notify(
        &mut app,
        1,
        "input_accepted",
        json!({ "text": "Report the result." }),
    );
    notify(
        &mut app,
        2,
        "output_text_final",
        json!({ "text": "The focused check passed." }),
    );
    notify(&mut app, 3, "usage", json!({ "total_tokens": 3953 }));
    notify(&mut app, 4, "turn_completed", json!({}));
    notify(&mut app, 5, "session_idle", json!({}));

    let cells = app.desktop_transcript();
    assert_eq!(cells.len(), 2, "passive metadata must not create chat rows");
    assert!(cells.iter().all(|cell| !matches!(
        cell.kind,
        DesktopCellKind::Status | DesktopCellKind::Divider
    )));

    let agent = cells
        .iter()
        .find(|cell| cell.kind == DesktopCellKind::Message && cell.label == "Agent")
        .expect("the agent reply remains in the conversation");
    assert_eq!(
        agent.metadata,
        [
            "Usage · 3953 tokens",
            "turn complete",
            "Note · session idle"
        ]
    );
}

#[test]
fn desktop_session_management_uses_durable_rename_and_terminal_delete() {
    let mut app = opened();

    app.desktop_rename_session(Plane::Interactive, SESSION, "  Focused desktop work  ")
        .expect("an interactive session can be renamed");
    let rename = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.rename")
        .expect("rename uses the runtime-owned title field");
    assert_eq!(rename.params["id"], SESSION);
    assert_eq!(rename.params["title"], "Focused desktop work");

    let error = app
        .desktop_delete_session(Plane::Interactive, SESSION)
        .expect_err("a live session must not be deleted");
    assert!(error.contains("finish or stop"));
    assert!(app.drain().is_empty());

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": SESSION,
            "title": "Focused desktop work",
            "node": "ouroboros@golden",
            "provider": "native",
            "workspace": "/tmp/desktop-workspace",
            "status": "closed",
            "options": { "model": "openai_codex:gpt-5.6-sol" },
            "updated_at": "2026-01-01T00:01:00.000000Z"
        }]),
    );

    let row = app
        .desktop_sessions()
        .into_iter()
        .find(|session| session.id == SESSION)
        .expect("the completed session remains listed");
    assert!(row.terminal);
    assert!(row.can_delete);

    app.desktop_delete_session(Plane::Interactive, SESSION)
        .expect("a terminal session can be deleted");
    let delete = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.delete")
        .expect("delete uses the plane's durable delete method");
    assert_eq!(delete.params["id"], SESSION);
}

#[test]
fn desktop_rename_rejects_names_the_sidebar_cannot_safely_draw() {
    let mut app = opened();

    assert!(app
        .desktop_rename_session(Plane::Interactive, SESSION, "   ")
        .expect_err("blank titles are not useful")
        .contains("enter a session name"));
    assert!(app
        .desktop_rename_session(Plane::Interactive, SESSION, &"x".repeat(121))
        .expect_err("the runtime title bound is enforced before dispatch")
        .contains("120"));
    assert!(app
        .desktop_rename_session(Plane::Interactive, SESSION, "clear\u{1b}[2J")
        .expect_err("control characters must never reach a one-line row")
        .contains("control characters"));
    assert!(app.drain().is_empty());
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
fn desktop_blocks_codex_send_until_the_runtime_reports_oauth_ready() {
    let mut app = opened();
    answer(
        &mut app,
        Tag::Account,
        json!({
            "account": Value::Null,
            "requiresOpenaiAuth": true,
            "login": { "status": "idle" }
        }),
    );
    app.drain();

    let error = app
        .desktop_submit_message("Do not dispatch this yet.")
        .expect_err("the direct model cannot run without OAuth");
    assert!(error.contains("connect ChatGPT"));
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.follow_up"));
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
    answer(
        &mut app,
        Tag::Account,
        json!({
            "account": Value::Null,
            "requiresOpenaiAuth": false,
            "login": { "status": "idle" }
        }),
    );
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

#[test]
fn desktop_gates_codex_work_and_uses_the_runtime_owned_login_flow() {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);
    app.data_dir = Some("/tmp/ouroboros-desktop".into());
    answer(
        &mut app,
        Tag::Account,
        json!({
            "account": Value::Null,
            "requiresOpenaiAuth": true,
            "login": { "status": "idle" }
        }),
    );
    app.drain();

    let error = app
        .desktop_start_session(
            "native".into(),
            Some("openai_codex:gpt-5.6-sol".into()),
            "/tmp/desktop-workspace".into(),
        )
        .expect_err("an OAuth-backed model cannot start before sign-in");
    assert!(error.contains("connect ChatGPT"));
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.start"));

    let account = app.desktop_account();
    assert!(account.resolved);
    assert!(!account.usable);
    app.desktop_start_chatgpt_login(true)
        .expect("the local desktop can start browser PKCE");
    let login = app
        .drain()
        .into_iter()
        .find(|call| call.method == "account.login.start")
        .expect("the desktop emits the managed login call");
    assert_eq!(login.params, json!({ "flow": "browser" }));

    answer(
        &mut app,
        Tag::AccountLogin,
        json!({
            "type": "chatgpt",
            "loginId": "desktop-login-1",
            "authUrl": "https://chatgpt.com/auth/ouroboros"
        }),
    );
    let pending = app.desktop_account();
    assert!(pending.pending);
    assert_eq!(
        pending.url.as_deref(),
        Some("https://chatgpt.com/auth/ouroboros")
    );
    assert_eq!(
        app.take_open_url().as_deref(),
        Some("https://chatgpt.com/auth/ouroboros")
    );

    app.desktop_cancel_chatgpt_login();
    let cancel = app
        .drain()
        .into_iter()
        .find(|call| call.method == "account.login.cancel")
        .expect("cancelling the card cancels the runtime login");
    assert_eq!(cancel.params["login_id"], "desktop-login-1");
}
