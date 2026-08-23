//! The client halves of D9, D6, B7 and G1: `/compact`, `/handoff`, `/context`, `/rewind`,
//! `!cmd`, and `/delegate`.
//!
//! Every test here names both halves of the gate, because that is the whole discipline of
//! this slice: `hello.methods` says whether the gateway serves the verb, and the session's
//! declared transport says whether *this* conversation can honour it. A verb offered where
//! either is false is a key that always fails, which is the failure D14 exists to name.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::Plane;
use ouro::proto::{ErrorCode, Hello, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{App, Call, Msg, Overlay, Tag};

use support::{app, full_hello, render, Screen};

// ---------------------------------------------------------------------------------------
// scaffolding
// ---------------------------------------------------------------------------------------

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn modified(code: KeyCode, modifiers: KeyModifiers) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn type_text(app: &mut App, text: &str) {
    for character in text.chars() {
        app.apply(key(KeyCode::Char(character)));
    }
}

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn refuse(app: &mut App, tag: Tag, data: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "the runtime refused the call".to_string(),
            data: Some(data),
        })),
    });
}

/// The transport that holds its own conversation, and is therefore the only one that can
/// fold it, hand it over, or put it back.
fn native_capabilities() -> Value {
    json!({
        "transport": "native",
        "process": "persistent",
        "multi_turn": "native",
        "follow_up": "native",
        "interrupt": "native",
        "approvals": "native",
        "steer": "native",
        "multimodal": "native",
        "fork": "native",
        "dynamic_model": "native",
        "dynamic_configuration": "native"
    })
}

/// A managed vendor CLI: one process per turn, and no conversation this runtime holds.
fn managed_capabilities() -> Value {
    json!({
        "transport": "managed",
        "process": "per_turn",
        "multi_turn": "managed",
        "follow_up": "managed",
        "interrupt": "process",
        "approvals": false,
        "steer": false,
        "multimodal": false,
        "fork": false,
        "dynamic_model": "managed",
        "dynamic_configuration": "managed"
    })
}

fn session(capabilities: Value, approval_mode: &str) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.State",
        "id": "session-d9",
        "status": "idle",
        "provider": "native",
        "node": "ouroboros@alpha",
        "workspace": "/Users/operator/code/ouroboros",
        "updated_at": "2026-01-01T00:00:00.000000Z",
        "children": [],
        "options": {
            "approval_mode": approval_mode,
            "sandbox_mode": "workspace_write",
            "model": "gpt-5-codex",
            "capabilities": capabilities,
        },
    })
}

fn event(sequence: u64, kind: &str, payload: Value) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.Event",
        "id": format!("evt-{sequence}"),
        "sequence": sequence,
        "type": kind,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "payload": payload,
        "turn_id": Value::Null,
        "request_id": Value::Null,
        "provider": "native"
    })
}

fn opened(capabilities: Value) -> App {
    opened_with(full_hello(), capabilities, "auto_approve", Vec::new())
}

fn opened_at(capabilities: Value, approval_mode: &str) -> App {
    opened_with(full_hello(), capabilities, approval_mode, Vec::new())
}

fn opened_holding(capabilities: Value, events: Vec<Value>) -> App {
    opened_with(full_hello(), capabilities, "auto_approve", events)
}

/// An older gateway: one that does not serve `missing`. The golden `hello` lists every
/// verb this checkout serves, so "not served" has to be stated rather than relied on.
fn opened_without(capabilities: Value, missing: &[&str]) -> App {
    let mut hello = full_hello();
    hello
        .methods
        .retain(|method| !missing.contains(&method.as_str()));

    opened_with(hello, capabilities, "auto_approve", Vec::new())
}

fn opened_with(hello: Hello, capabilities: Value, approval_mode: &str, events: Vec<Value>) -> App {
    let mut app = app(hello);
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([session(capabilities, approval_mode)]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, "session-d9".into());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");
    answer(&mut app, subscribe.tag, json!(events));

    app.apply(Msg::Tick);
    app
}

fn compose(app: &mut App) {
    if app.sessions.composer.is_none() {
        app.apply(key(KeyCode::Char('i')));
    }
}

/// Types `text` into the composer and presses Enter, returning the calls it produced.
fn send(app: &mut App, text: &str) -> Vec<Call> {
    compose(app);
    type_text(app, text);
    app.apply(key(KeyCode::Enter));
    app.drain()
}

fn call_named<'a>(calls: &'a [Call], method: &str) -> Option<&'a Call> {
    calls.iter().find(|call| call.method == method)
}

fn screen(app: &mut App) -> Screen {
    render(app, 180, 48)
}

// ---------------------------------------------------------------------------------------
// (a) D9 — /compact
// ---------------------------------------------------------------------------------------

#[test]
fn compact_is_refused_locally_by_the_method_gate_and_by_the_transport() {
    // Half one: an older gateway. Nothing is sent, and the sentence names the method.
    let mut older = opened_without(native_capabilities(), &["interactive.compact"]);
    let calls = send(&mut older, "/compact");

    assert!(
        call_named(&calls, "interactive.compact").is_none(),
        "nothing is sent to a gateway that does not serve it"
    );
    assert!(
        screen(&mut older)
            .text()
            .contains("does not serve interactive.compact"),
        "{}",
        screen(&mut older).text()
    );

    // Half two: a gateway that serves it, on a transport that cannot honour it. Also
    // refused here, because only a native session holds a conversation to fold.
    let mut managed = opened(managed_capabilities());
    let calls = send(&mut managed, "/compact");

    assert!(
        call_named(&calls, "interactive.compact").is_none(),
        "a managed session is refused before the wire"
    );
    assert!(
        screen(&mut managed)
            .text()
            .contains("not the native transport"),
        "{}",
        screen(&mut managed).text()
    );
}

#[test]
fn compact_sends_the_session_and_carries_a_focus_only_when_one_was_typed() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/compact");
    let bare = call_named(&calls, "interactive.compact").expect("the fold is issued");

    assert_eq!(bare.params["id"], "session-d9");
    assert!(
        bare.params.get("focus").is_none(),
        "an unfocused fold sends no focus: {}",
        bare.params
    );

    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/compact the auth refactor");
    let focused = call_named(&calls, "interactive.compact").expect("the fold is issued");

    assert_eq!(focused.params["focus"], "the auth refactor");
}

#[test]
fn a_compaction_report_becomes_a_transcript_note_and_re_reads_the_meter() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/compact");
    let tag = call_named(&calls, "interactive.compact")
        .expect("the fold is issued")
        .tag
        .clone();

    answer(
        &mut app,
        tag,
        json!({
            "trigger": "manual",
            "turn": 12,
            "archived_messages": 40,
            "archive_id": "arch-7",
            "elided_tool_results": 6,
            "summary_tokens": 812,
            "before_tokens": 91234,
            "after_tokens": 12045,
            "summarised": true
        }),
    );

    let text = screen(&mut app).text();
    assert!(text.contains("Compacted, at your request"), "{text}");
    assert!(text.contains("archived 40 messages"), "{text}");
    assert!(text.contains("91234 → 12045 tokens"), "{text}");
    assert!(text.contains("archive arch-7"), "{text}");

    // The meter is stale the moment a fold lands, so the report is followed by a fresh
    // read rather than by an inferred number.
    let refresh = app.drain();
    assert!(
        call_named(&refresh, "interactive.context").is_some(),
        "a fold re-reads the context it just changed"
    );
}

/// The runtime writes its own `compaction` event as well. It is drawn where this client
/// has only that — and never beside the reply's own note, which carries more.
#[test]
fn a_durable_compaction_event_is_drawn_alone_and_deduped_against_the_reply() {
    let fold = json!({
        "kind": "compaction",
        "trigger": "automatic",
        "archived_messages": 12,
        "archive_id": "arch-9",
        "before_tokens": 80000,
        "after_tokens": 9000
    });

    // Only the durable event: it is the record, so it is drawn.
    let mut alone = opened_holding(
        native_capabilities(),
        vec![event(1, "provider_event", fold.clone())],
    );
    let text = screen(&mut alone).text();
    assert!(text.contains("Compacted automatically"), "{text}");
    assert!(text.contains("archive arch-9"), "{text}");

    // Both: the reply drew it first, keyed on the same archive id, so the event does not
    // draw a second copy underneath.
    let mut both = opened(native_capabilities());
    let calls = send(&mut both, "/compact");
    let tag = call_named(&calls, "interactive.compact")
        .unwrap()
        .tag
        .clone();
    answer(&mut both, tag, fold.clone());

    app_notify(&mut both, event(9, "provider_event", fold));

    let text = screen(&mut both).text();
    assert_eq!(
        text.matches("archive arch-9").count(),
        1,
        "one act, one cell: {text}"
    );
}

/// One live `interactive.event` frame, as the gateway pushes it.
fn app_notify(app: &mut App, event: Value) {
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: "interactive.event".to_string(),
        params: json!({ "id": "session-d9", "event": event }),
    }));
    app.apply(Msg::Tick);
}

// ---------------------------------------------------------------------------------------
// (a) D9 — /handoff
// ---------------------------------------------------------------------------------------

#[test]
fn handoff_mints_its_own_child_id_and_opens_what_the_runtime_named() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/handoff finish the auth refactor");
    let handoff = call_named(&calls, "interactive.handoff").expect("the handoff is issued");

    assert_eq!(handoff.params["id"], "session-d9");
    assert_eq!(handoff.params["prompt"], "finish the auth refactor");
    assert!(
        handoff.params["handoff_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "the child's id is caller-owned so a fired ceiling is still reconcilable: {}",
        handoff.params
    );

    answer(
        &mut app,
        handoff.tag.clone(),
        json!({"id": "session-child", "node": "ouroboros@alpha", "outcome": "created", "ready": true}),
    );

    assert_eq!(
        app.sessions.open,
        Some((Plane::Interactive, "session-child".to_string())),
        "the child is opened the moment the runtime names it"
    );
    assert!(
        screen(&mut app)
            .text()
            .contains("handed off from session-d9"),
        "{}",
        screen(&mut app).text()
    );
}

#[test]
fn a_handoff_whose_ceiling_fired_still_opens_the_child_and_says_so() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/handoff carry on");
    let handoff = call_named(&calls, "interactive.handoff")
        .unwrap()
        .tag
        .clone();

    answer(
        &mut app,
        handoff,
        json!({"id": "session-child", "outcome": "unknown", "ready": false}),
    );

    let text = screen(&mut app).text();
    assert!(text.contains("not ready yet"), "{text}");
    assert_eq!(
        app.sessions.open,
        Some((Plane::Interactive, "session-child".to_string()))
    );
}

// ---------------------------------------------------------------------------------------
// (a) D9 — /context
// ---------------------------------------------------------------------------------------

fn native_context() -> Value {
    json!({
        "source": "native",
        "session_id": "session-d9",
        "provider": "native",
        "transport": "native",
        "model": "gpt-5-codex",
        "context_window": 200000,
        "context_used": 50000,
        "total_tokens": 91234,
        "prefix_fingerprint": "9f2c1ab4de55071122334455",
        "compact_at": 0.8,
        "keep_recent_tokens": 20000,
        "messages": 48,
        "compaction_thrashing": false,
        "compactions": [
            {"trigger": "automatic", "archived_messages": 12, "archive_id": "arch-1",
             "before_tokens": 80000, "after_tokens": 9000}
        ],
        "archive_ids": ["arch-1"],
        "instruction_files": ["/Users/operator/code/ouroboros/AGENTS.md"],
        "instruction_files_dropped": [
            {"path": "/Users/operator/.config/ouroboros/AGENTS.md", "bytes": 40960,
             "reason": "over_budget"}
        ],
        "instruction_bytes": 8192,
        "tools": ["read", "edit", "bash"],
        "handed_off_to": Value::Null
    })
}

#[test]
fn context_is_gated_on_the_method_alone_because_it_answers_for_every_transport() {
    let mut older = opened_without(native_capabilities(), &["interactive.context"]);
    let calls = send(&mut older, "/context");

    assert!(call_named(&calls, "interactive.context").is_none());
    assert!(
        screen(&mut older)
            .text()
            .contains("does not serve interactive.context"),
        "{}",
        screen(&mut older).text()
    );

    // A managed session is *not* refused: it gets the subset its own usage events reported.
    let mut managed = opened(managed_capabilities());
    let calls = send(&mut managed, "/context");

    assert!(
        call_named(&calls, "interactive.context").is_some(),
        "every transport can answer this one"
    );
}

#[test]
fn the_context_overlay_reads_at_eighty_and_at_a_hundred_and_twenty_columns() {
    for width in [80u16, 120] {
        let mut app = opened(native_capabilities());
        let calls = send(&mut app, "/context");
        let tag = call_named(&calls, "interactive.context")
            .unwrap()
            .tag
            .clone();
        answer(&mut app, tag, native_context());

        assert!(matches!(app.overlay, Some(Overlay::Context { .. })));

        let text = render(&mut app, width, 48).text();

        assert!(
            text.contains("source  native"),
            "at {width} columns: {text}"
        );
        assert!(text.contains("25%"), "at {width} columns: {text}");
        assert!(text.contains("COMPACTIONS"), "at {width} columns: {text}");
        assert!(text.contains("INSTRUCTIONS"), "at {width} columns: {text}");
    }
}

/// The subset a vendor session can honestly report, labelled as a subset.
#[test]
fn a_usage_context_says_which_answer_it_is_and_does_not_pad_the_shape() {
    let mut app = opened(managed_capabilities());
    let calls = send(&mut app, "/context");
    let tag = call_named(&calls, "interactive.context")
        .unwrap()
        .tag
        .clone();

    answer(
        &mut app,
        tag,
        json!({
            "source": "usage",
            "session_id": "session-d9",
            "transport": "managed",
            "context_window": Value::Null,
            "context_used": Value::Null,
            "total_tokens": 4200
        }),
    );

    let text = screen(&mut app).text();
    assert!(text.contains("source  usage"), "{text}");
    assert!(
        text.contains("named no context window"),
        "an absent window is stated, never drawn as zero: {text}"
    );
    assert!(
        text.contains("the subset this one knows"),
        "the page says it is a subset: {text}"
    );
    assert!(
        !text.contains("COMPACTIONS"),
        "a managed session is not given native headings with nothing under them: {text}"
    );
}

// ---------------------------------------------------------------------------------------
// (a) D6 — /rewind
// ---------------------------------------------------------------------------------------

fn rewind_points() -> Value {
    json!([
        {"turn_id": "t1", "at": "2026-01-01T00:01:00Z", "files": 2, "paths": ["a.rs", "b.rs"],
         "commands": 0, "restorable": 2, "dropped_turns": 0},
        {"turn_id": "t2", "at": "2026-01-01T00:02:00Z", "files": 3, "paths": ["c.rs"],
         "commands": 2, "restorable": 1, "dropped_turns": 0}
    ])
}

#[test]
fn the_rewind_menu_warns_before_the_choice_and_the_chooser_offers_exactly_three() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/rewind");
    let tag = call_named(&calls, "interactive.rewind_points")
        .expect("the menu is fetched")
        .tag
        .clone();

    answer(&mut app, tag, rewind_points());

    let text = screen(&mut app).text();
    assert!(text.contains("t1"), "{text}");
    assert!(text.contains("t2"), "{text}");
    // The warning is on the row, before anything is chosen — both halves of it.
    assert!(text.contains("2 shell commands ran in it"), "{text}");
    assert!(text.contains("2 of 3 files have no snapshot"), "{text}");

    // Enter opens the chooser rather than acting.
    app.apply(key(KeyCode::Enter));
    assert!(
        app.drain().is_empty(),
        "the first Enter chooses what to restore; it does not rewind"
    );

    let text = screen(&mut app).text();
    assert!(text.contains("RESTORE"), "{text}");
    assert!(text.contains("both"), "{text}");
    assert!(text.contains("files"), "{text}");
    assert!(text.contains("conversation"), "{text}");
    assert!(
        text.contains("not checkpointed"),
        "the warning is repeated on the screen the choice is made on: {text}"
    );
}

#[test]
fn the_rewind_sends_the_turns_position_and_the_chosen_what() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/rewind");
    let tag = call_named(&calls, "interactive.rewind_points")
        .unwrap()
        .tag
        .clone();
    answer(&mut app, tag, rewind_points());

    // Newest is selected; move up to `t1`, then choose "files".
    app.apply(key(KeyCode::Up));
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    let calls = app.drain();
    let rewind = call_named(&calls, "interactive.rewind").expect("the rewind is issued");

    assert_eq!(rewind.params["id"], "session-d9");
    assert_eq!(rewind.params["what"], "files");
    // The 1-based position of the turn in the list just fetched, which is what
    // `InteractiveSession.rewind/3`'s integer guard accepts.
    assert_eq!(rewind.params["to_turn"], 1);
}

#[test]
fn a_rewind_reports_what_it_restored_and_what_it_skipped() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/rewind");
    let tag = call_named(&calls, "interactive.rewind_points")
        .unwrap()
        .tag
        .clone();
    answer(&mut app, tag, rewind_points());

    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));

    let calls = app.drain();
    let tag = call_named(&calls, "interactive.rewind")
        .unwrap()
        .tag
        .clone();

    answer(
        &mut app,
        tag,
        json!({
            "restored": [
                {"path": "/w/a.rs", "action": "restored"},
                {"path": "/w/new.rs", "action": "deleted"}
            ],
            "unrestorable": [
                {"path": Value::Null, "turn_id": "t2",
                 "reason": "2 shell commands ran in this turn (make; ./deploy). Whatever they changed is not checkpointed and cannot be restored."}
            ],
            "turns": ["t2"],
            "messages": 18
        }),
    );

    let text = screen(&mut app).text();
    assert!(text.contains("Rewound to t2"), "{text}");
    assert!(text.contains("restored 2 files"), "{text}");
    assert!(text.contains("skipped 1"), "{text}");
    assert!(text.contains("could not be restored:"), "{text}");
    assert!(text.contains("turn t2"), "{text}");
}

/// D6 in the menu that asks the same question. Offered only where the transport is the one
/// that keeps the checkpoints a rewind restores from.
#[test]
fn the_backtrack_menu_offers_a_rewind_only_on_the_transport_that_checkpoints() {
    let events = vec![event(
        1,
        "input_accepted",
        json!({"text": "make the tests pass"}),
    )];

    let mut native = opened_holding(native_capabilities(), events.clone());
    native.apply(key(KeyCode::Esc));
    native.apply(key(KeyCode::Esc));
    let text = screen(&mut native).text();
    assert!(text.contains("r rewinds"), "{text}");

    let mut managed = opened_with(
        full_hello(),
        managed_capabilities(),
        "auto_approve",
        events.clone(),
    );
    managed.apply(key(KeyCode::Esc));
    managed.apply(key(KeyCode::Esc));
    let text = screen(&mut managed).text();
    assert!(
        !text.contains("r rewinds"),
        "a managed session keeps no checkpoints: {text}"
    );

    // And `r` does nothing there, rather than opening a menu that would always refuse.
    let mut older = opened_without(native_capabilities(), &["interactive.rewind_points"]);
    older.apply(key(KeyCode::Esc));
    older.apply(key(KeyCode::Esc));
    assert!(!screen(&mut older).text().contains("r rewinds"));
}

// ---------------------------------------------------------------------------------------
// (b) B7 — !cmd
// ---------------------------------------------------------------------------------------

#[test]
fn a_bang_draft_states_where_it_runs_before_it_is_sent() {
    let mut app = opened(native_capabilities());
    compose(&mut app);
    type_text(&mut app, "!mix test --stale");

    let text = screen(&mut app).text();
    assert!(
        text.contains("runs on ouroboros@alpha in /Users/operator/code/ouroboros"),
        "the composer names the node and the directory before Enter: {text}"
    );
}

#[test]
fn a_bang_draft_sends_the_rest_to_workspace_exec() {
    let mut older = opened_without(native_capabilities(), &["workspace.exec"]);
    let calls = send(&mut older, "!mix test");
    assert!(call_named(&calls, "workspace.exec").is_none());
    assert!(
        screen(&mut older)
            .text()
            .contains("does not serve workspace.exec"),
        "{}",
        screen(&mut older).text()
    );

    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "!mix test --stale");
    let exec = call_named(&calls, "workspace.exec").expect("the command is issued");

    assert_eq!(exec.params["id"], "session-d9");
    assert_eq!(exec.params["command"], "mix test --stale");
    assert!(
        call_named(&calls, "interactive.send_message").is_none(),
        "a `!` line is the operator's own act, never a turn"
    );
}

#[test]
fn a_command_reply_becomes_one_note_and_the_runtimes_own_event_does_not_repeat_it() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "!mix test --stale");
    let tag = call_named(&calls, "workspace.exec").unwrap().tag.clone();

    answer(
        &mut app,
        tag,
        json!({
            "effect_id": "shell-abc",
            "command_digest": "d1ge57",
            "cwd": "/Users/operator/code/ouroboros",
            "exit_status": 1,
            "timed_out": false,
            "duration_ms": 4200,
            "output": "compiling\nrunning\n1 test, 1 failure",
            "output_bytes": 41234,
            "excerpt": "1 test, 1 failure",
            "spilled": "/data/session-d9/exec/out.txt",
            "spill_error": Value::Null
        }),
    );

    let text = screen(&mut app).text();
    assert!(text.contains("$ mix test --stale"), "{text}");
    assert!(text.contains("exit 1"), "{text}");
    assert!(text.contains("4s"), "{text}");
    assert!(text.contains("41234 bytes"), "{text}");
    assert!(
        text.contains("full output at /data/session-d9/exec/out.txt"),
        "{text}"
    );
    assert!(text.contains("1 test, 1 failure"), "{text}");

    // The runtime writes its own `provider_event` for the same command. Same digest, so
    // it is deduped against the fuller note rather than drawn underneath it.
    app_notify(
        &mut app,
        event(
            9,
            "provider_event",
            json!({
                "kind": "operator_shell",
                "effect_id": "shell-abc",
                "command_digest": "d1ge57",
                "exit_status": 1,
                "duration_ms": 4200,
                "timed_out": false,
                "output_bytes": 41234,
                "output_excerpt": "1 test, 1 failure"
            }),
        ),
    );

    let text = screen(&mut app).text();
    assert_eq!(
        text.matches("exit 1").count(),
        1,
        "one command, one cell: {text}"
    );
}

/// The durable event alone — a second client watching, or a session reopened after a
/// restart. It is the only copy, so it is drawn, and it names the digest because the
/// ledger deliberately never records the command's words.
#[test]
fn a_command_this_client_did_not_send_is_drawn_from_the_runtimes_own_record() {
    let mut app = opened_holding(
        native_capabilities(),
        vec![event(
            1,
            "provider_event",
            json!({
                "kind": "operator_shell",
                "effect_id": "shell-xyz",
                "command_digest": "0123456789abcdef0123",
                "exit_status": 0,
                "duration_ms": 120,
                "output_bytes": 12,
                "output_excerpt": "ok"
            }),
        )],
    );

    let text = screen(&mut app).text();
    assert!(text.contains("$ command 0123456789ab"), "{text}");
    assert!(text.contains("exit 0"), "{text}");
    assert!(text.contains("ok"), "{text}");
}

#[test]
fn a_refused_command_names_the_rule_and_offers_the_one_key_that_writes_it() {
    let mut app = opened_at(native_capabilities(), "prompt");
    let calls = send(&mut app, "!rm -rf /");
    let tag = call_named(&calls, "workspace.exec").unwrap().tag.clone();

    refuse(
        &mut app,
        tag,
        json!([
            "shell_refused",
            {
                "reason": "no_rule",
                "session_id": "session-d9",
                "workspace": "/Users/operator/code/ouroboros",
                "approval_mode": "prompt",
                "denied_by": Value::Null,
                "suggested_rule": "Bash(rm *)",
                "message": "workspace.exec runs a command as your own act, so it needs the session to be at approval_mode auto_approve or a permission rule that allows it."
            }
        ]),
    );

    let text = screen(&mut app).text();
    assert!(text.contains("runs a command as your own act"), "{text}");
    assert!(
        text.contains("saves the rule Bash(rm *)"),
        "the exact rule is named before it is written: {text}"
    );

    // `ctrl+x r` writes it, as `permissions.add`, scoped to this session's workspace.
    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    app.apply(key(KeyCode::Char('r')));

    let calls = app.drain();
    let rule = call_named(&calls, "permissions.add").expect("the rule is written");

    assert_eq!(rule.params["pattern"], "Bash(rm *)");
    assert_eq!(rule.params["scope"], "workspace");
    assert_eq!(rule.params["workspace"], "/Users/operator/code/ouroboros");
}

#[test]
fn a_refusal_this_client_cannot_honour_still_prints_the_rule_and_offers_no_key() {
    let mut app = opened_without(native_capabilities(), &["permissions.add"]);
    let calls = send(&mut app, "!rm -rf /");
    let tag = call_named(&calls, "workspace.exec").unwrap().tag.clone();

    refuse(
        &mut app,
        tag,
        json!([
            "shell_refused",
            {"reason": "no_rule", "suggested_rule": "Bash(rm *)",
             "message": "a permission rule would be needed"}
        ]),
    );

    let text = screen(&mut app).text();
    assert!(
        text.contains("the rule Bash(rm *) would allow it; this client cannot save it"),
        "an offer that could not be kept is not made, and the pattern is printed anyway: {text}"
    );
}

/// A refusal that is not about permissions must not grow a permissions offer.
#[test]
fn another_refusal_shape_does_not_borrow_the_add_rule_offer() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "!mix test");
    let tag = call_named(&calls, "workspace.exec").unwrap().tag.clone();

    refuse(
        &mut app,
        tag,
        json!(["session_not_executable", {"status": "closed"}]),
    );

    let text = screen(&mut app).text();
    assert!(!text.contains("saves the rule"), "{text}");
    assert!(text.contains("session_not_executable"), "{text}");
}

// ---------------------------------------------------------------------------------------
// (c) G1 — /delegate
// ---------------------------------------------------------------------------------------

#[test]
fn delegate_mints_its_own_id_and_shows_a_chip_while_the_call_is_in_flight() {
    let mut older = opened_without(native_capabilities(), &["interactive.delegate"]);
    let calls = send(&mut older, "/delegate port the auth module");
    assert!(call_named(&calls, "interactive.delegate").is_none());
    assert!(
        screen(&mut older)
            .text()
            .contains("does not serve interactive.delegate"),
        "{}",
        screen(&mut older).text()
    );

    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/delegate port the auth module");
    let delegate = call_named(&calls, "interactive.delegate").expect("the delegation is issued");

    assert_eq!(delegate.params["id"], "session-d9");
    assert_eq!(delegate.params["objective"], "port the auth module");
    assert!(
        delegate.params["delegation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "caller-owned, so a fired ceiling answers with the same child: {}",
        delegate.params
    );

    assert!(
        screen(&mut app).text().contains("delegating…"),
        "{}",
        screen(&mut app).text()
    );

    answer(
        &mut app,
        delegate.tag.clone(),
        json!({
            "delegation_id": "d-1", "team_id": "alpha:workspace-team:ab",
            "task_id": "task-7", "task_node": "ouroboros@alpha",
            "plane": "coding", "status": "starting"
        }),
    );

    let text = screen(&mut app).text();
    assert!(!text.contains("delegating…"), "the chip clears: {text}");
    assert!(text.contains("delegated to task-7"), "{text}");
}

#[test]
fn a_delegation_event_is_a_cell_in_the_parents_transcript() {
    let mut app = opened_holding(
        native_capabilities(),
        vec![
            event(
                1,
                "delegation",
                json!({
                    "delegation_id": "d-1", "team_id": "alpha:workspace-team:ab",
                    "task_id": "task-7", "task_node": "ouroboros@alpha",
                    "objective_digest": "9ab1", "status": "started"
                }),
            ),
            event(
                2,
                "delegation",
                json!({
                    "delegation_id": "d-1", "task_id": "task-7",
                    "task_node": "ouroboros@alpha", "objective_digest": "9ab1",
                    "status": "completed", "result_digest": "c0ffee"
                }),
            ),
        ],
    );

    let text = screen(&mut app).text();
    assert!(text.contains("Delegated to a coding task"), "{text}");
    assert!(text.contains("task task-7"), "{text}");
    assert!(text.contains("Delegation completed"), "{text}");
    assert!(
        text.contains("result digest c0ffee"),
        "a digest, never the result: {text}"
    );
}

#[test]
fn the_delegations_list_opens_the_childs_own_transcript() {
    let mut app = opened(native_capabilities());
    let calls = send(&mut app, "/delegations");
    let tag = call_named(&calls, "interactive.delegations")
        .expect("the list is fetched")
        .tag
        .clone();

    answer(
        &mut app,
        tag,
        json!([
            {"delegation_id": "d-1", "team_id": "t", "task_id": "task-7",
             "task_node": "ouroboros@alpha", "plane": "coding",
             "objective_digest": "9ab1", "status": "running",
             "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:01:00Z",
             "source": "team"},
            {"delegation_id": "d-2", "team_id": "t", "task_id": "task-8",
             "task_node": "ouroboros@beta", "plane": "coding",
             "objective_digest": "77aa", "status": "completed",
             "result_digest": "beef", "created_at": "2026-01-01T00:02:00Z",
             "updated_at": "2026-01-01T00:03:00Z", "source": "session"}
        ]),
    );

    assert!(matches!(app.overlay, Some(Overlay::Delegations { .. })));

    let text = screen(&mut app).text();
    assert!(text.contains("task-7"), "{text}");
    assert!(text.contains("task-8"), "{text}");
    assert!(
        text.contains("as this conversation last heard"),
        "a status read from the session rather than the team says so: {text}"
    );

    app.apply(key(KeyCode::Enter));

    assert_eq!(
        app.sessions.open,
        Some((Plane::Coding, "task-7".to_string())),
        "Enter opens the child on the plane it actually runs on"
    );
}

/// The child sits under its parent in the rail — and only within a group, because "what
/// needs me" and "who started this" are different questions and the first one wins.
#[test]
fn a_delegated_task_nests_under_the_conversation_that_started_it() {
    let mut app = app(full_hello());
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": "parent-1",
            "status": "running",
            "provider": "native",
            "node": "ouroboros@alpha",
            "workspace": "/w",
            "objective": "The conversation",
            "children": ["task-7"],
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );
    answer(
        &mut app,
        Tag::Sessions(Plane::Coding),
        json!([
            {
                "_struct": "Ouroboros.Coding.TaskState",
                "id": "task-7",
                "status": "running",
                "provider": "codex",
                "node": "ouroboros@alpha",
                "workspace": "/w",
                "objective": "The child",
                "parent": {"plane": "interactive", "id": "parent-1"},
                "updated_at": "2020-01-01T00:00:00.000000Z"
            },
            {
                "_struct": "Ouroboros.Coding.TaskState",
                "id": "task-alone",
                "status": "running",
                "provider": "codex",
                "node": "ouroboros@alpha",
                "workspace": "/w",
                "objective": "Nobody's child",
                "updated_at": "2026-01-01T00:00:05.000000Z"
            }
        ]),
    );
    app.apply(Msg::Tick);

    let rows = app.sessions.triaged();
    let ids: Vec<(&str, usize)> = rows
        .iter()
        .map(|row| (row.session.id.as_str(), row.depth))
        .collect();

    // Recency still orders the top level — `task-alone` is the newest row — and the child
    // follows its own parent however old it is, at depth one.
    assert_eq!(
        ids,
        vec![("task-alone", 0), ("parent-1", 0), ("task-7", 1)],
        "the child follows its parent; an unrelated task keeps its own place"
    );
}

/// `Ctrl+T` reads them, and the panel lists them beside the plan.
#[test]
fn the_plan_panel_lists_the_conversations_children() {
    let mut app = opened(native_capabilities());
    app.apply(modified(KeyCode::Char('t'), KeyModifiers::CONTROL));

    let calls = app.drain();
    let tag = call_named(&calls, "interactive.delegations")
        .expect("opening the panel reads them")
        .tag
        .clone();

    answer(
        &mut app,
        tag,
        json!([
            {"delegation_id": "d-1", "task_id": "task-7", "task_node": "ouroboros@alpha",
             "plane": "coding", "status": "running", "source": "team"}
        ]),
    );

    let text = screen(&mut app).text();
    assert!(text.contains("Delegations"), "{text}");
    assert!(text.contains("task-7"), "{text}");
}
