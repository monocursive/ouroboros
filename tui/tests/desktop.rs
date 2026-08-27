#![cfg(feature = "desktop")]

//! The native window is intentionally thin. These tests pin the semantic seam beneath it:
//! a desktop control must produce the same reducer calls and transcript/approval meaning as
//! the terminal client, without needing a window server in CI.

mod support;

use ouro::model::{ApprovalDecision, ApprovalScope, Effort, Plane};
use ouro::proto::{ErrorCode, Notification, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{App, DesktopCellKind, DesktopTone, Mode, Msg, Tag};
use serde_json::{json, Value};

use support::{full_hello, hello};

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

/// A connected window with nothing open: the state the quick-start composer is drawn in.
fn no_session_open() -> App {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
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
    app.config.defaults.workspace = Some("/tmp/desktop-workspace".into());
    app.drain();
    app
}

/// The no-session composer starts a session on the stored defaults and sends what was
/// typed as its first message — the same two steps in the same order as the terminal home.
#[test]
fn desktop_quick_start_uses_the_stored_defaults_and_sends_the_typed_prompt() {
    let mut app = no_session_open();

    let context = app.desktop_quick_start_context();
    assert!(context.ready, "an operate listener serving start is ready");
    assert!(!context.pending);
    assert_eq!(context.provider, "native");
    assert_eq!(context.model, "openai_codex:gpt-5.6-sol");
    assert_eq!(context.workspace, "/tmp/desktop-workspace");

    app.desktop_quick_start("  Inspect the seam.  ")
        .expect("a connected operate listener takes a quick start");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("the quick start emits an interactive.start call");
    assert_eq!(start.params["provider"], context.provider);
    assert_eq!(start.params["model"], context.model);
    assert_eq!(start.params["workspace"], context.workspace);
    let id = start.params["id"]
        .as_str()
        .expect("the client mints the session id")
        .to_string();
    assert!(
        app.desktop_quick_start_context().pending,
        "the context says a start is in flight"
    );

    // `interactive.start` waits for provider readiness, so the prompt is dispatched on its
    // answer rather than beside it.
    answer(
        &mut app,
        start.tag,
        json!({ "id": id, "node": "ouroboros@golden" }),
    );
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the typed prompt becomes the session's first message");
    assert_eq!(first.params["id"], id);
    assert_eq!(first.params["input"], "Inspect the seam.");
    assert!(first.params["turn_id"].as_str().is_some());
    assert!(
        app.desktop_take_restored_draft().is_none(),
        "a start that succeeded hands nothing back"
    );
}

/// A quick start is a start, not a command line: a slash prompt is sent as text.
#[test]
fn desktop_quick_start_refuses_an_empty_prompt_and_never_runs_a_slash_command() {
    let mut app = no_session_open();

    let error = app
        .desktop_quick_start("   \n  ")
        .expect_err("there is nothing to start a session for");
    assert!(error.contains("type what you want"), "{error}");
    assert!(app.drain().is_empty());

    app.desktop_quick_start("/settings")
        .expect("a window has no command grammar to swallow this");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("the prompt starts a session like any other");
    assert!(start.params["id"].as_str().is_some());
}

/// Scope and capability are two gates, and the context reports the same answer the seam
/// enforces.
#[test]
fn desktop_quick_start_needs_operate_scope() {
    let mut app = no_session_open();
    app.hello.scope = "read".into();

    assert!(!app.desktop_quick_start_context().ready);
    let error = app
        .desktop_quick_start("Inspect the seam.")
        .expect_err("a read listener refuses every start");
    assert!(error.contains("scope `read`"), "{error}");
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.start"));
}

/// The OAuth-backed default model needs an account. The refusal names the fix, and the
/// composer stays live: the account card that grants it is on the same screen.
#[test]
fn desktop_quick_start_waits_for_the_account_the_default_model_needs() {
    let mut app = no_session_open();
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
        .desktop_quick_start("Inspect the seam.")
        .expect_err("the direct model cannot start without OAuth");
    assert!(error.contains("connect ChatGPT"), "{error}");
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.start"));
    assert!(
        app.desktop_quick_start_context().ready,
        "the gateway would still take a start; the account is the obstacle"
    );
}

/// A start refused after the window cleared its box must not cost the typing.
#[test]
fn desktop_quick_start_hands_a_refused_prompt_back_to_the_window() {
    let mut app = no_session_open();
    app.desktop_quick_start("Inspect the seam.")
        .expect("a connected operate listener takes a quick start");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("the quick start emits an interactive.start call");
    assert!(
        app.desktop_take_restored_draft().is_none(),
        "nothing is handed back while the start is still in flight"
    );

    app.apply(Msg::Answer {
        tag: start.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "the runtime refused these start parameters".into(),
            data: None,
        })),
    });

    assert_eq!(
        app.desktop_take_restored_draft().as_deref(),
        Some("Inspect the seam."),
        "the refused prompt comes back through the desktop seam"
    );
    assert!(
        app.desktop_take_restored_draft().is_none(),
        "it is handed back once, not on every tick"
    );
    assert!(
        !app.desktop_quick_start_context().pending,
        "a definite refusal releases the composer"
    );

    // A definite refusal cannot become a session, so the next attempt mints a fresh id.
    app.desktop_quick_start("Inspect the seam.")
        .expect("the composer is usable again");
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a second interactive.start call");
    assert_ne!(retry.params["id"], start.params["id"]);
}

/// A start whose outcome nobody knows keeps its id. The prompt comes back so resubmitting
/// it unchanged reconciles that same session rather than minting a second billable one.
#[test]
fn desktop_quick_start_replays_one_id_when_the_start_outcome_is_unknown() {
    let mut app = no_session_open();
    app.desktop_quick_start("Inspect the seam.")
        .expect("a connected operate listener takes a quick start");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("the quick start emits an interactive.start call");

    app.apply(Msg::Answer {
        tag: start.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    assert_eq!(
        app.desktop_take_restored_draft().as_deref(),
        Some("Inspect the seam.")
    );
    assert!(
        !app.desktop_quick_start_context().pending,
        "reconciling is the operator's move, so the composer stays live for it"
    );

    let error = app
        .desktop_quick_start("Something else entirely.")
        .expect_err("a changed prompt would mint a second id for the same work");
    assert!(error.contains("may already exist"), "{error}");
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.start"));

    app.desktop_quick_start("Inspect the seam.")
        .expect("the same prompt reconciles the same id");
    let replay = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("the replay is a start call");
    assert_eq!(
        replay.params["id"], start.params["id"],
        "reconciliation reuses the id whose outcome is unknown"
    );
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
fn desktop_fetches_artifact_bytes_and_overlays_them_on_the_transcript() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;

    let mut app = opened();
    let png = {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes
    };
    let digest = ring::digest::digest(&ring::digest::SHA256, &png);
    let sha: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();

    notify(
        &mut app,
        1,
        "tool_result",
        json!({
            "call_id": "d1",
            "name": "desktop_state",
            "output": "Calculator",
            "is_error": false,
            "artifacts": [{
                "kind": "image",
                "sha256": sha,
                "media_type": "image/png",
                "bytes": png.len(),
                "width": 8,
                "height": 8
            }]
        }),
    );

    let fetch = app
        .drain()
        .into_iter()
        .find(|call| call.method == "computer_use.artifact")
        .expect("a screenshot on the transcript is fetched by sha");
    assert_eq!(fetch.params["sha256"], sha);
    assert!(matches!(fetch.tag, Tag::Artifact { sha: ref got } if *got == sha));

    answer(
        &mut app,
        fetch.tag,
        json!({ "bytes": BASE64.encode(&png), "media_type": "image/png" }),
    );

    let cells = app.desktop_transcript();
    let image = cells
        .iter()
        .find(|cell| matches!(cell.kind, DesktopCellKind::Image { .. }))
        .expect("the artifact is an Image cell");
    match &image.kind {
        DesktopCellKind::Image {
            bytes,
            sha: cell_sha,
            ..
        } => {
            assert_eq!(cell_sha.as_deref(), Some(sha.as_str()));
            assert_eq!(bytes.as_deref().map(Vec::as_slice), Some(png.as_slice()));
        }
        other => panic!("expected Image, got {other:?}"),
    }
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
        cells.last().map(|cell| &cell.kind),
        Some(&DesktopCellKind::Activity),
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
    assert!(
        approval.subagent.is_none(),
        "an approval the session asked for itself is attributed to nobody else"
    );

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

/// `Native.Loop.subagent_approval/2` forwards the child's payload whole and adds one
/// `subagent` object. The card must say which child is asking, and — because this session
/// runs on `ouroboros@golden` — that the answer authorizes work on `ouro-2@fleet`.
#[test]
fn a_subagent_relayed_approval_reaches_the_desktop_with_its_asker_and_machine() {
    let mut app = opened();
    notify(
        &mut app,
        1,
        "approval_requested",
        json!({
            "request_id": "req-child-1",
            "kind": "tool",
            "tool_call": { "name": "exec_command", "command": "cargo build", "cwd": "/tmp/wt" },
            "subagent": {
                "task_id": "task-a",
                "description": "audit the parser",
                "provider_session_id": "sess-child",
                "node": "ouro-2@fleet"
            }
        }),
    );

    let approval = app.desktop_approval().expect("a pending desktop approval");
    assert_eq!(
        approval.subagent.as_deref(),
        Some("asked by subagent audit the parser (task-a) on ouro-2@fleet")
    );
}

/// A child on the session's own node is named without a machine — its node is not news —
/// and a payload that says `remote` outright is believed even with no node to compare.
#[test]
fn a_subagent_attribution_draws_the_machine_only_where_it_is_elsewhere() {
    let mut app = opened();
    notify(
        &mut app,
        1,
        "approval_requested",
        json!({
            "request_id": "req-child-2",
            "kind": "tool",
            "tool_call": { "name": "exec_command", "command": "cargo build" },
            "subagent": {
                "task_id": "task-b",
                "description": "tidy the docs",
                "node": "ouroboros@golden"
            }
        }),
    );

    let local = app.desktop_approval().expect("a pending desktop approval");
    assert_eq!(
        local.subagent.as_deref(),
        Some("asked by subagent tidy the docs (task-b)")
    );

    app.desktop_respond_approval("req-child-2", ApprovalDecision::Deny, ApprovalScope::Once)
        .expect("the local child's request is answerable");
    app.drain();

    notify(
        &mut app,
        2,
        "approval_requested",
        json!({
            "request_id": "req-child-3",
            "kind": "tool",
            "tool_call": { "name": "exec_command", "command": "cargo build" },
            "subagent": { "task_id": "task-c", "remote": true }
        }),
    );

    let marked = app.desktop_approval().expect("a pending desktop approval");
    assert_eq!(
        marked.subagent.as_deref(),
        Some("asked by subagent (task-c) on another machine")
    );
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
            None,
            Some(Effort::High),
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
    assert_eq!(start.params["reasoning_effort"], "high");
    assert!(
        start.params.get("sandbox_mode").is_none(),
        "an untouched form with no stored default states no posture: {}",
        start.params
    );
}

/// The wire meaning of the form's "Runtime default" row: the key is absent, not `null` and
/// not empty.
///
/// The whole row rests on this. It tells an operator the request carries no model option
/// and that the runtime will apply whatever it configured — which is only true if the
/// client genuinely omits the key rather than sending something the runtime must interpret.
#[test]
fn desktop_new_session_omits_the_model_key_when_no_model_was_chosen() {
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

    app.desktop_start_session(
        "claude".into(),
        None,
        "/tmp/desktop-workspace".into(),
        None,
        None,
    )
    .expect("the operate-capable gateway can start a session");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("the native form emits an interactive.start call");

    assert!(
        start.params.get("model").is_none(),
        "\"Runtime default\" must leave the key out entirely: {}",
        start.params
    );
    assert_eq!(start.params["provider"], "claude");

    // And a model that is only whitespace is the same statement, not a model named " ".
    app.desktop_start_session(
        "claude".into(),
        Some("   ".into()),
        "/tmp/desktop-workspace".into(),
        None,
        None,
    )
    .expect("a session still starts");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a second interactive.start call");
    assert!(
        start.params.get("model").is_none(),
        "a blank model is no model: {}",
        start.params
    );
}

/// The native form's file-access answer reaches the wire, and beats the config file.
///
/// The stored default is where the control *starts*; what an operator picked in the form
/// is what gets sent. Full access is the case worth pinning, because it is the one whose
/// wire word (`unrestricted`) and operator word ("Full access — no sandbox") differ.
#[test]
fn desktop_new_session_sends_the_chosen_sandbox_over_the_stored_default() {
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
    app.config.defaults.sandbox_mode = Some("read_only".into());
    app.drain();

    // Untouched, the stored default is what the form sends.
    app.desktop_start_session(
        "native".into(),
        None,
        "/tmp/desktop-workspace".into(),
        None,
        None,
    )
    .expect("the operate-capable gateway can start a session");
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("an interactive.start call");
    assert_eq!(start.params["sandbox_mode"], "read_only");

    for mode in App::desktop_sandbox_choices() {
        app.desktop_start_session(
            "native".into(),
            None,
            "/tmp/desktop-workspace".into(),
            Some(mode),
            None,
        )
        .expect("the operate-capable gateway can start a session");
        let start = app
            .drain()
            .into_iter()
            .find(|call| call.method == "interactive.start")
            .expect("an interactive.start call");
        assert_eq!(
            start.params["sandbox_mode"],
            mode.as_str(),
            "the operator's choice outranks defaults.sandbox_mode"
        );
    }
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
            None,
            None,
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

/// The auto-approve toggle is one reducer call: turning it on answers the backlog —
/// the card the window is showing included — and every later request before a card can
/// render, always as `approve, once, actor: automation`.
#[test]
fn desktop_auto_approve_toggles_and_answers_the_backlog() {
    let mut app = opened();
    assert_eq!(
        app.desktop_auto_approve(),
        Some(false),
        "an open session starts in ask-first"
    );

    notify(
        &mut app,
        1,
        "approval_requested",
        json!({
            "request_id": "req-desktop-9",
            "kind": "sandbox_escalation",
            "tool_call": { "name": "exec_command", "command": "cargo test --all" }
        }),
    );
    assert!(app.desktop_approval().is_some());

    app.desktop_set_auto_approve(true)
        .expect("a session is open");
    assert_eq!(app.desktop_auto_approve(), Some(true));

    let answer = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("the pending card is answered by the toggle");
    assert_eq!(answer.params["request_id"], "req-desktop-9");
    assert_eq!(answer.params["response"]["decision"], "approve");
    assert_eq!(answer.params["response"]["scope"], "once");
    assert_eq!(
        answer.params["response"]["actor"], "automation",
        "the ledger must not credit a person who never saw the request"
    );
    assert!(
        app.desktop_approval().is_none(),
        "an answered request renders no card"
    );

    notify(
        &mut app,
        2,
        "approval_requested",
        json!({
            "request_id": "req-desktop-10",
            "tool_call": { "name": "exec_command", "command": "cargo build" }
        }),
    );
    assert!(
        app.desktop_approval().is_none(),
        "a request on an auto-approve session never becomes a card"
    );
    let answer = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("it is answered instead");
    assert_eq!(answer.params["request_id"], "req-desktop-10");

    app.desktop_set_auto_approve(false)
        .expect("a session is open");
    assert_eq!(app.desktop_auto_approve(), Some(false));
}

/// With no session open there is nothing to toggle, and the picker knows it.
#[test]
fn desktop_auto_approve_needs_an_open_session() {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);

    assert_eq!(app.desktop_auto_approve(), None);
    let error = app
        .desktop_set_auto_approve(true)
        .expect_err("no session, no toggle");
    assert!(error.contains("no session is open"), "{error}");
}

/// The composer footer's posture picker: it reads the session row the runtime published,
/// and changing it is one `interactive.configure` with the wire's own word.
#[test]
fn desktop_sandbox_picker_reads_the_runtimes_posture_and_configures_it() {
    let mut app = opened();
    assert_eq!(
        app.desktop_sandbox_mode(),
        Some(ouro::model::SandboxMode::WorkspaceWrite),
        "the opened session was listed as workspace_write"
    );

    app.desktop_set_sandbox_mode(ouro::model::SandboxMode::Unrestricted)
        .expect("a session is open on a gateway that serves interactive.configure");
    let configure = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.configure")
        .expect("the picker issues the runtime's own configure verb");
    assert_eq!(configure.params["id"], SESSION);
    assert_eq!(
        configure.params["sandbox_mode"], "unrestricted",
        "the wire keeps the schema's word; only the labels say full access"
    );

    // Until the runtime answers and the row is re-listed, the label is still what the
    // runtime last published: the picker never shows a posture nobody confirmed.
    assert_eq!(
        app.desktop_sandbox_mode(),
        Some(ouro::model::SandboxMode::WorkspaceWrite)
    );

    answer(
        &mut app,
        configure.tag,
        json!({ "id": SESSION, "applies": "now" }),
    );
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": SESSION,
            "node": "ouroboros@golden",
            "provider": "native",
            "workspace": "/tmp/desktop-workspace",
            "status": "running",
            "options": { "sandbox_mode": "unrestricted" },
            "updated_at": "2026-01-01T00:02:00.000000Z"
        }]),
    );
    assert_eq!(
        app.desktop_sandbox_mode(),
        Some(ouro::model::SandboxMode::Unrestricted)
    );

    // The mode it is already on is refused rather than sent again.
    let error = app
        .desktop_set_sandbox_mode(ouro::model::SandboxMode::Unrestricted)
        .expect_err("a no-op configure is not a call");
    assert!(error.contains("already on full access"), "{error}");
}

/// With no session open, and with a session whose row names no posture, the control has
/// nothing to draw — and says so by being absent rather than by guessing a default.
#[test]
fn desktop_sandbox_picker_is_absent_where_no_posture_was_stated() {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);
    assert_eq!(app.desktop_sandbox_mode(), None);
    let error = app
        .desktop_set_sandbox_mode(ouro::model::SandboxMode::ReadOnly)
        .expect_err("no session, no posture to change");
    assert!(error.contains("open a session"), "{error}");

    let mut app = opened();
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": SESSION,
            "node": "ouroboros@golden",
            "provider": "native",
            "workspace": "/tmp/desktop-workspace",
            "status": "running",
            "options": { "model": "openai_codex:gpt-5.6-sol" },
            "updated_at": "2026-01-01T00:02:00.000000Z"
        }]),
    );
    assert_eq!(
        app.desktop_sandbox_mode(),
        None,
        "a row with no sandbox_mode leaves the picker off rather than inventing one"
    );
}

/// The runtime half's `sandbox_escalation` payload, exactly as it arrives: the card has to
/// carry the kind, the command, the cwd, the reason the command was stopped, and the rule
/// a "don't ask again" would write.
#[test]
fn desktop_sandbox_escalation_card_carries_the_reason_the_command_was_stopped() {
    let mut app = opened();
    notify(
        &mut app,
        1,
        "approval_requested",
        json!({
            "request_id": "req-desktop-12",
            "kind": "sandbox_escalation",
            "reason": "the sandbox refused a write outside the workspace",
            "suggested_rule": "Bash(cargo test *)",
            "tool_call": {
                "name": "exec_command",
                "command": "cargo test --all",
                "cwd": "/tmp/desktop-workspace"
            }
        }),
    );

    let approval = app.desktop_approval().expect("a pending desktop approval");
    assert_eq!(approval.kind.as_deref(), Some("sandbox escalation"));
    assert_eq!(approval.command.as_deref(), Some("cargo test --all"));
    assert_eq!(approval.cwd.as_deref(), Some("/tmp/desktop-workspace"));
    assert_eq!(
        approval.reason.as_deref(),
        Some("the sandbox refused a write outside the workspace"),
        "the provider's own reason is carried, not summarised away"
    );
    assert_eq!(
        approval.suggested_rule.as_deref(),
        Some("Bash(cargo test *)")
    );
    assert!(
        !approval.question,
        "an escalation is a permission, so auto-approve may answer it"
    );
}

/// Composition: `sandbox_escalation` is a permission, not a question, so the client-side
/// auto-approve mode answers it — full access and auto-approve are separate decisions and
/// an operator can hold both.
#[test]
fn desktop_auto_approve_answers_a_sandbox_escalation() {
    let mut app = opened();
    app.desktop_set_auto_approve(true)
        .expect("a session is open");
    app.drain();

    notify(
        &mut app,
        1,
        "approval_requested",
        json!({
            "request_id": "req-desktop-13",
            "kind": "sandbox_escalation",
            "reason": "the sandbox refused a write outside the workspace",
            "suggested_rule": "Bash(cargo test *)",
            "tool_call": {
                "name": "exec_command",
                "command": "cargo test --all",
                "cwd": "/tmp/desktop-workspace"
            }
        }),
    );

    assert!(
        app.desktop_approval().is_none(),
        "an escalation on an auto-approve session never becomes a card"
    );
    let calls = app.drain();
    let answered = calls
        .iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("it is answered instead");
    assert_eq!(answered.params["request_id"], "req-desktop-13");
    assert_eq!(answered.params["response"]["decision"], "approve");
    assert_eq!(answered.params["response"]["scope"], "once");
    assert_eq!(answered.params["response"]["actor"], "automation");
    assert!(
        calls.iter().all(|call| call.method != "permissions.add"),
        "auto-approve answers one request; it never writes the durable rule"
    );
}

/// An `ask_user` question on an auto-approve session still becomes a card — a robot
/// `approve` would reach the agent as "acknowledged without an answer" — and the card
/// does not offer the mode that skipped it.
#[test]
fn desktop_auto_approve_leaves_ask_user_questions_for_the_person() {
    let mut app = opened();
    app.desktop_set_auto_approve(true)
        .expect("a session is open");
    app.drain();

    notify(
        &mut app,
        1,
        "approval_requested",
        json!({
            "request_id": "req-desktop-11",
            "kind": "question",
            "header": "Commit blocked",
            "question": "The sandbox forbids writes to `.git`. Commit yourself, or grant it?",
            "options": [
                {"optionId": "self", "name": "I'll commit it myself", "kind": "reject_once"},
                {"optionId": "grant", "name": "Grant the session permission", "kind": "allow_once"}
            ]
        }),
    );

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.respond_approval"),
        "the question is not auto-answered"
    );

    let approval = app
        .desktop_approval()
        .expect("the question still renders as a card");
    assert_eq!(approval.request_id, "req-desktop-11");
    assert!(approval.question, "and the card knows it is a question");
}

/// One `runtime.models` answer, shaped as `Ouroboros.Models.list/0` encodes it.
fn models_catalogue() -> Value {
    json!({
        "source": "llm_db",
        "epoch": 41,
        "limit": 40,
        "providers": [
            {
                "provider": "native",
                "catalog": "openai",
                "default": "openai_codex:gpt-5.6-sol",
                "model_option": true,
                "total": 1,
                "models": [{
                    "id": "openai_codex:gpt-5.6-sol",
                    "name": "GPT-5.6 Sol",
                    "context_window": 400000,
                    "max_output_tokens": 128000,
                    "release_date": "2026-05-14",
                    "pricing": {"currency": "USD", "input_per_mtok": 1.25, "output_per_mtok": 10.0}
                }]
            }
        ]
    })
}

fn methods(app: &mut App) -> Vec<String> {
    app.drain()
        .into_iter()
        .map(|call| call.method.to_string())
        .collect()
}

/// The new-session form's two lists are one seam, and it is safe to call every time the
/// form opens: a question already outstanding is not asked twice.
#[test]
fn desktop_pickers_ask_for_providers_and_models_once() {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);
    app.drain();

    app.desktop_fetch_pickers();
    let asked = methods(&mut app);
    assert!(
        asked.contains(&"runtime.providers".to_string())
            && asked.contains(&"runtime.models".to_string()),
        "opening the form asks for both lists: {asked:?}"
    );

    app.desktop_fetch_pickers();
    assert!(
        methods(&mut app).is_empty(),
        "reopening the form while both answers are outstanding asks nothing again"
    );

    answer(&mut app, Tag::Models, models_catalogue());
    answer(&mut app, Tag::Providers, json!([]));
    app.drain();

    app.desktop_fetch_pickers();
    assert!(
        methods(&mut app).is_empty(),
        "and an answer already held is not re-fetched either"
    );
}

#[test]
fn a_models_answer_lands_in_the_catalogue_the_picker_reads() {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);
    app.drain();
    app.desktop_fetch_pickers();
    app.drain();

    answer(&mut app, Tag::Models, models_catalogue());

    let catalogue = app.models.value.as_ref().expect("a decoded catalogue");
    assert!(!app.models.pending);
    assert!(app.models.error.is_none());

    let native = catalogue.provider("native").expect("the native row");
    assert!(native.model_option);
    assert_eq!(native.default.as_deref(), Some("openai_codex:gpt-5.6-sol"));
    assert_eq!(
        native.models[0].id, "openai_codex:gpt-5.6-sol",
        "ids arrive already prefixed for the model option a native session takes"
    );
    assert_eq!(
        native.models[0].detail().as_deref(),
        Some("GPT-5.6 Sol · 400K context")
    );
}

/// A gateway that predates `runtime.models` is not a broken one. Nothing is asked, nothing
/// is recorded as failed, and the form's model field stays the text input it always was.
#[test]
fn a_gateway_without_runtime_models_is_not_asked_and_reports_no_failure() {
    let mut app = App::new(
        Mode::Attached,
        "127.0.0.1:4560".into(),
        hello(&["runtime.providers", "interactive.start", "interactive.list"]),
        None,
    );
    app.drain();

    app.desktop_fetch_pickers();

    assert_eq!(
        methods(&mut app),
        ["runtime.providers"],
        "the verb this gateway does not serve is never sent"
    );
    assert!(app.models.value.is_none());
    assert!(
        app.models.error.is_none(),
        "an unserved verb is a gap in the gateway, not an error to show where models go"
    );
    assert!(!app.models.pending);
}
