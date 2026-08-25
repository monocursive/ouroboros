//! A feature that names a child on one surface and not the other is a lie to the operator.
//!
//! The TUI and the native window share `App` and `ApprovalSubagent::line`. That is not
//! enough: presentation can still diverge because the TUI suite (`approvals.rs`) and the
//! desktop suite (`desktop.rs`, behind `--features desktop`) never look at each other. A
//! payload that lands only in `view.rs` or only in `desktop.rs` fails one suite and ships
//! on the other. These tests feed the *same* bytes into both projections and require the
//! same words, so the next approval or child-agent row cannot land on only one client.
//!
//! This file is not behind `desktop`. `App::desktop_approval` and `App::desktop_transcript`
//! are always compiled; gating the lock on a feature the default `cargo test` does not
//! pass would recreate the hole it exists to close.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;

use ouro::model::Plane;
use ouro::ui::app::{App, DesktopCellKind, Msg, Tag};

use support::{full_hello, render};

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn answer(app: &mut App, tag: Tag, value: serde_json::Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn notify(app: &mut App, frame: serde_json::Value) {
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: frame["method"].as_str().expect("a method").to_string(),
        params: frame["params"].clone(),
    }));
}

/// A session open on the Sessions tab, on a gateway that serves `hello` methods.
fn opened(hello: ouro::proto::Hello) -> App {
    let mut app = App::new(
        ouro::ui::app::Mode::Spawned { pid: 4242 },
        "127.0.0.1:4560".into(),
        hello,
        None,
    );

    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": SESSION,
            "node": "ouroboros@golden",
            "provider": "claude_code",
            "workspace": "/tmp/w",
            "status": "running",
            "options": { "approval_mode": "prompt", "sandbox_mode": null },
            "created_at": "2026-01-01T00:00:00.000000Z",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, SESSION.to_string());

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!([])),
    });

    app
}

fn approve(app: &mut App, payload: serde_json::Value) {
    notify(
        app,
        json!({
            "jsonrpc": "2.0",
            "method": "interactive.event",
            "params": {
                "id": SESSION,
                "event": {
                    "_struct": "Ouroboros.Interactive.Event",
                    "id": "evt-9",
                    "session_id": SESSION,
                    "sequence": 9,
                    "type": "approval_requested",
                    "timestamp": "2026-01-01T00:00:00.000000Z",
                    "request_id": "req-17",
                    "turn_id": "turn-1",
                    "payload": payload
                }
            }
        }),
    );
}

/// `Native.Loop.subagent_approval/2` for a child placed on another fleet node: the
/// child's own payload, whole, plus the `subagent` object naming the asker.
///
/// Same shape as `a_subagent_relayed_approval_names_the_asker_and_the_machine_it_runs_on`
/// in `approvals.rs` and `a_subagent_relayed_approval_reaches_the_desktop_with_its_asker_and_machine`
/// in `desktop.rs`.
#[test]
fn a_remote_subagent_approval_names_the_asker_and_the_machine_on_both_surfaces() {
    let mut app = opened(full_hello());
    approve(
        &mut app,
        json!({
            "tool_call": {
                "name": "exec_command",
                "command": "cargo build",
                "cwd": "/tmp/child-worktree"
            },
            "kind": "tool",
            "subagent": {
                "task_id": "task-a",
                "description": "audit the parser",
                "provider_session_id": "sess-child",
                "node": "ouro-2@fleet"
            }
        }),
    );

    let desktop = app.desktop_approval().expect("a pending desktop approval");
    let line = desktop
        .subagent
        .as_deref()
        .expect("a relayed request names which child is asking");

    assert_eq!(
        line, "asked by subagent audit the parser (task-a) on ouro-2@fleet",
        "the desktop line is the asker plus the machine the answer authorizes"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains(line),
        "the TUI must draw the same line the desktop card carries, not a subset:\n{}",
        screen.text()
    );
}

/// A child on the session's own node (`ouroboros@golden`) still names itself, but its
/// node is not news — every child runs somewhere, and a machine on every relayed request
/// would hide the one case where the answer crosses to another one.
#[test]
fn a_local_subagent_approval_names_the_asker_without_a_machine_on_both_surfaces() {
    let mut app = opened(full_hello());
    approve(
        &mut app,
        json!({
            "tool_call": { "name": "exec_command", "command": "cargo build", "cwd": "/tmp/w" },
            "kind": "tool",
            "subagent": {
                "task_id": "task-b",
                "description": "tidy the docs",
                "node": "ouroboros@golden"
            }
        }),
    );

    let desktop = app.desktop_approval().expect("a pending desktop approval");
    let line = desktop
        .subagent
        .as_deref()
        .expect("a local child is still named");

    assert_eq!(
        line, "asked by subagent tidy the docs (task-b)",
        "the session's own node is not drawn as if it were elsewhere"
    );
    assert!(
        !line.contains("on "),
        "desktop must not suffix a local child with a machine: {line}"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains(line),
        "the TUI must carry the same attribution the desktop card does:\n{}",
        screen.text()
    );
    assert!(
        !screen.text().contains("on ouroboros@golden"),
        "the TUI must not invent a machine the desktop correctly omitted:\n{}",
        screen.text()
    );
}

/// `subagent_approval/2`'s fallback for a child whose payload was unreadable carries only
/// the task id. A payload that says `remote` outright is believed even with no node to
/// compare — both surfaces must name that machine the same way.
#[test]
fn a_partial_remote_subagent_approval_names_another_machine_on_both_surfaces() {
    let mut app = opened(full_hello());
    approve(
        &mut app,
        json!({
            "kind": "tool",
            "subagent": { "task_id": "task-c", "remote": true }
        }),
    );

    let desktop = app.desktop_approval().expect("a pending desktop approval");
    let line = desktop
        .subagent
        .as_deref()
        .expect("a remote flag with only a task id is still an asker");

    assert_eq!(
        line, "asked by subagent (task-c) on another machine",
        "no node to spell, so both surfaces fall back to the same words"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains(line),
        "the TUI must name another machine the same way the desktop card does:\n{}",
        screen.text()
    );
}

/// One child-agent transcript event, as `transcript_cells` tests emit it. The desktop
/// projection and the pane must both name the child: an edit that only updates `view.rs`
/// or only `desktop.rs` fails here.
#[test]
fn a_child_agent_transcript_row_reaches_both_surfaces() {
    let mut app = opened(full_hello());
    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "interactive.event",
            "params": {
                "id": SESSION,
                "event": {
                    "_struct": "Ouroboros.Interactive.Event",
                    "id": "evt-1",
                    "session_id": SESSION,
                    "sequence": 1,
                    "type": "provider_event",
                    "timestamp": "2026-01-01T00:00:00.000000Z",
                    "payload": {
                        "kind": "subagent",
                        "phase": "spawned",
                        "task_id": "task-a",
                        "description": "audit the parser",
                        "provider_session_id": "sess-child",
                        "workspace": "/repo",
                        "worktree": true,
                        "tools": ["read", "edit"],
                        "background": true,
                        "depth": 2,
                        "max_turns": 40,
                        "deadline_ms": 600_000
                    }
                }
            }
        }),
    );

    let cell = app
        .desktop_transcript()
        .into_iter()
        .find(|cell| cell.kind == DesktopCellKind::Subagent)
        .expect("a spawned child reaches the desktop as its own kind");

    let screen = render(&mut app, 120, 30);

    assert!(
        !cell.label.is_empty(),
        "the desktop row names the child: {cell:#?}"
    );
    assert!(
        screen.contains(&cell.label),
        "the TUI must draw the desktop label, not a parallel wording:\n{}\nlabel={:?}",
        screen.text(),
        cell.label
    );
    assert!(
        cell.body.contains("session sess-child"),
        "the desktop leads to the child's own transcript: {cell:#?}"
    );
    assert!(
        screen.contains("session sess-child"),
        "the TUI must name the same child session the desktop body does:\n{}",
        screen.text()
    );
}
