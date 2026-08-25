//! What the approval modal draws, and what answering it puts on the wire.
//!
//! X11's complaint was a modal that had the diff and the provider's own options in the
//! payload and drew neither. Every payload below is one of the two dialects' real shapes —
//! `Ouroboros.Provider.Session.Dialect.Codex.approval_payload/2` and
//! `Dialect.ACP.permission_payload/1`, plus the `suggested_rule` that
//! `Control.Permissions.Seam` adds on `:ask` — so a test that passes here is a test about
//! the bytes a provider actually sends.
//!
//! The honesty assertions are the point of the file: a request with no diff must *say* it
//! has no diff, an excerpted diff must be labelled an excerpt, and the "don't ask again"
//! answer must name the exact pattern and scope it will write before it can be chosen.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;

use ouro::model::Plane;
use ouro::ui::app::{App, Msg, Tag};
use ouro::ui::transcript::Watch;

use support::{full_hello, render};

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ctrl(c: char) -> Msg {
    Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
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

/// `Dialect.Codex.approval_payload/2` for `item/execCommand/requestApproval`, with the
/// `suggested_rule` the permission seam adds on `:ask`.
fn codex_sandbox_escalation() -> serde_json::Value {
    json!({
        "tool_call": {
            "name": "exec_command",
            "command": "cargo test --all",
            "cwd": "/tmp/w"
        },
        "reason": "the sandbox refused a write outside the workspace",
        "kind": "sandbox_escalation",
        "suggested_rule": "Bash(cargo test *)"
    })
}

#[test]
fn a_sandbox_escalation_shows_its_kind_command_cwd_and_the_reason_the_provider_gave() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("approval requested — sandbox escalation"),
        "the kind is the headline:\n{}",
        screen.text()
    );
    assert!(screen.contains("cargo test --all"), "{}", screen.text());
    assert!(screen.contains("cwd /tmp/w"), "{}", screen.text());
    assert!(
        screen.contains("the sandbox refused a write outside the workspace"),
        "the provider's own reason is shown, not summarised away:\n{}",
        screen.text()
    );
    assert!(
        screen.contains("this request carries no diff"),
        "a payload with no diff says so rather than drawing nothing:\n{}",
        screen.text()
    );
}

#[test]
fn a_file_change_approval_draws_its_diff_expanded_while_the_answer_is_pending() {
    let mut app = opened(full_hello());
    approve(
        &mut app,
        json!({
            "tool_call": { "name": "file_change", "command": "apply patch", "cwd": "/tmp/w" },
            "kind": "file_change",
            "diff": "--- a/src/lex.rs\n+++ b/src/lex.rs\n@@ -1,3 +1,3 @@\n ok\n-old line\n+new line\n"
        }),
    );

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("approval requested — file change"),
        "{}",
        screen.text()
    );
    // Warp's rule: the patch is open while the approval is pending.
    assert!(screen.contains("@@ -1,3 +1,3 @@"), "{}", screen.text());
    assert!(screen.contains("-old line"), "{}", screen.text());
    assert!(screen.contains("+new line"), "{}", screen.text());
    assert!(
        screen.contains("+1") && screen.contains("-1"),
        "the per-file counts are drawn:\n{}",
        screen.text()
    );
}

#[test]
fn an_excerpted_diff_is_labelled_an_excerpt_so_its_counts_are_not_read_as_a_diffstat() {
    let mut app = opened(full_hello());
    approve(
        &mut app,
        json!({
            "tool_call": { "name": "file_change", "cwd": "/tmp/w" },
            "kind": "file_change",
            // `Gateway.Wire`'s per-leaf marker, exactly as
            // `interactive_event_excerpt_notification.json` pins it.
            "diff": { "_excerpt": "--- a/big.rs\n+++ b/big.rs\n+one\n", "_bytes": 4096 }
        }),
    );

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("in excerpt"),
        "an excerpted patch must not present its counts as a diffstat:\n{}",
        screen.text()
    );
}

#[test]
fn an_acp_approval_carries_the_providers_own_option_labels_on_the_answers_they_map_to() {
    let mut app = opened(full_hello());
    approve(
        &mut app,
        json!({
            "tool_call": {
                "kind": "execute",
                "title": "Run the test suite",
                "rawInput": { "command": "cargo test" },
                "locations": [{ "path": "/tmp/w/src/lex.rs" }]
            },
            "options": [
                { "optionId": "o1", "name": "Allow once", "kind": "allow_once" },
                { "optionId": "o2", "name": "Always allow", "kind": "allow_always" },
                { "optionId": "o3", "name": "Reject", "kind": "reject_once" },
                { "optionId": "o4", "name": "Ask me something else", "kind": "cancel" }
            ]
        }),
    );

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("approval requested — execute"),
        "the ACP tool kind is the headline:\n{}",
        screen.text()
    );
    assert!(screen.contains("Run the test suite"), "{}", screen.text());
    assert!(
        screen.contains("path /tmp/w/src/lex.rs"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("approve (once) — Allow once"),
        "the vendor label rides the answer it maps to, beside what will be sent:\n{}",
        screen.text()
    );
    assert!(
        screen.contains("approve (session) — Always allow"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("deny (once) — Reject"), "{}", screen.text());
    assert!(
        screen.contains("Ask me something else"),
        "an option this build cannot map is still shown, in the provider's words:\n{}",
        screen.text()
    );
    assert!(
        screen.contains("cannot map onto an answer"),
        "and it says it cannot map it:\n{}",
        screen.text()
    );
}

#[test]
fn an_acp_diff_content_block_is_named_rather_than_diffed_by_this_client() {
    let mut app = opened(full_hello());
    approve(
        &mut app,
        json!({
            "tool_call": {
                "kind": "edit",
                "title": "Rewrite the lexer",
                "content": [{
                    "type": "diff",
                    "path": "/tmp/w/src/lex.rs",
                    "oldText": "one\ntwo\n",
                    "newText": "one\ntwo\nthree\n"
                }]
            },
            "options": []
        }),
    );

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("edit /tmp/w/src/lex.rs"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("update") && screen.contains("8 → 14 bytes"),
        "the two sizes are facts the payload carries:\n{}",
        screen.text()
    );
    assert!(
        screen.contains("not a patch"),
        "this client does not invent a unified diff the runtime never produced:\n{}",
        screen.text()
    );
}

#[test]
fn the_fifth_answer_names_the_exact_pattern_and_scope_it_would_write() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("approve, and don't ask again for Bash(cargo test *)"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("as a workspace allow rule in /tmp/w"),
        "the scope is named before the answer can be chosen:\n{}",
        screen.text()
    );
}

#[test]
fn the_fifth_answer_is_absent_and_says_why_when_the_gateway_cannot_save_a_rule() {
    let mut app = opened(support::hello(&[
        "hello",
        "interactive.list",
        "coding.list",
        "interactive.subscribe",
        "interactive.replay",
        "interactive.respond_approval",
    ]));
    approve(&mut app, codex_sandbox_escalation());

    let screen = render(&mut app, 120, 30);

    assert!(
        !screen.contains("don't ask again"),
        "an answer this gateway could not honour is absent, not broken:\n{}",
        screen.text()
    );
    assert!(
        screen.contains("does not serve permissions.add"),
        "and the modal says which of the two reasons applies:\n{}",
        screen.text()
    );

    // Nothing is attempted either.
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    assert!(
        app.drain()
            .iter()
            .all(|call| call.method != "permissions.add"),
        "hello.methods is the feature gate and the only one"
    );
}

#[test]
fn choosing_the_fifth_answer_sends_the_approval_first_and_the_rule_second() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());

    // Four answers plus the fifth: four downs land on it, and a fifth does not run past it.
    for _ in 0..5 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));

    let calls = app.drain();
    let methods: Vec<&str> = calls.iter().map(|call| call.method.as_str()).collect();

    let approval = methods
        .iter()
        .position(|method| *method == "interactive.respond_approval")
        .expect("the approval is answered");
    let rule = methods
        .iter()
        .position(|method| *method == "permissions.add")
        .expect("the rule is written");

    assert!(
        approval < rule,
        "the provider is waiting on the answer; a rule written first would outlive a \
         refused approval: {methods:?}"
    );

    let approval = &calls[approval];
    assert_eq!(approval.params["request_id"], "req-17");
    assert_eq!(approval.params["response"]["decision"], "approve");
    assert_eq!(
        approval.params["response"]["scope"], "session",
        "there is no scope: always — the durable half is the rule below"
    );

    let rule = &calls[rule];
    assert_eq!(rule.params["scope"], "workspace");
    assert_eq!(rule.params["pattern"], "Bash(cargo test *)");
    assert_eq!(rule.params["decision"], "allow");
    assert_eq!(rule.params["workspace"], "/tmp/w");
    assert_eq!(
        rule.params.as_object().expect("an object").len(),
        4,
        "permissions.add refuses an option outside its allowlist naming it: {}",
        rule.params
    );
    assert!(matches!(
        rule.tag,
        Tag::PermissionRule { ref pattern } if pattern == "Bash(cargo test *)"
    ));
}

#[test]
fn a_permissions_request_is_its_own_kind_and_carries_the_root_it_asks_for() {
    let mut app = opened(full_hello());
    // `Dialect.Codex.approval_payload/2` for `item/permissions/requestApproval`: the
    // command text is the `grantRoot` the app server asked for.
    approve(
        &mut app,
        json!({
            "tool_call": { "name": "permissions", "command": "/tmp/w/vendor", "cwd": "/tmp/w" },
            "kind": "permissions",
            "reason": "the model asked to read outside the workspace"
        }),
    );

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("approval requested — permissions"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("/tmp/w/vendor"), "{}", screen.text());
    assert!(
        screen.contains("the model asked to read outside the workspace"),
        "{}",
        screen.text()
    );
    assert!(
        !screen.contains("don't ask again"),
        "no rule was suggested for this one, so nothing is offered and nothing is \
         explained away:\n{}",
        screen.text()
    );
}

#[test]
fn the_reason_prompt_never_returns_a_cursor_to_a_row_that_stopped_existing() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());

    // Land on the fifth row, then take the reason detour and come back.
    for _ in 0..4 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Tab));
    for character in "with a note".chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));

    let calls = app.drain();
    let approval = calls
        .iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("the approval is answered");

    assert_eq!(approval.params["response"]["decision"], "approve");
    assert_eq!(approval.params["response"]["scope"], "session");
    assert_eq!(approval.params["response"]["reason"], "with a note");
    assert!(
        calls.iter().any(|call| call.method == "permissions.add"),
        "the row the cursor was on is the row that was answered"
    );
}

#[test]
fn tab_opens_the_reason_field_the_same_way_r_does() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Tab));

    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("approval reason"), "{}", screen.text());

    for character in "not on this branch".chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("an approval answer");

    assert_eq!(call.params["response"]["decision"], "deny");
    assert_eq!(call.params["response"]["scope"], "once");
    assert_eq!(call.params["response"]["reason"], "not on this branch");
}

#[test]
fn ctrl_o_raises_the_diff_ceiling_inside_the_modal() {
    let mut app = opened(full_hello());

    let mut diff = String::from("--- a/long.rs\n+++ b/long.rs\n@@ -1,40 +1,40 @@\n");
    for index in 0..40 {
        diff.push_str(&format!("+line {index}\n"));
    }

    approve(
        &mut app,
        json!({
            "tool_call": { "name": "file_change", "cwd": "/tmp/w" },
            "kind": "file_change",
            "diff": diff
        }),
    );

    let screen = render(&mut app, 120, 24);
    assert!(
        screen.contains("… +") && screen.contains("ctrl+o"),
        "a bounded diff names how much it withheld and where the rest is:\n{}",
        screen.text()
    );
    assert!(!screen.contains("+line 39"), "{}", screen.text());

    app.apply(ctrl('o'));
    let screen = render(&mut app, 120, 60);
    assert!(
        screen.contains("+line 39"),
        "ctrl+o expands it in place:\n{}",
        screen.text()
    );
}

#[test]
fn a_pending_approval_keeps_a_bar_above_the_composer_that_cannot_scroll_away() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());

    // The modal opened itself; the bar is what remains once it is dismissed, and it is
    // the reason a question asked fifty events ago is still visible.
    app.apply(key(KeyCode::Esc));

    let screen = render(&mut app, 120, 30);

    assert!(screen.contains("⏸ approval needed"), "{}", screen.text());
    assert!(screen.contains("cargo test --all"), "{}", screen.text());
    assert!(
        screen.contains("ctrl+x a to answer"),
        "the bar names the key that works from the composer, not the one that types a \
         letter into the draft:\n{}",
        screen.text()
    );

    // And it is that key.
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char('a')));
    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("approval requested"), "{}", screen.text());
}

#[test]
fn the_bar_is_gone_once_nothing_is_pending() {
    let mut app = opened(full_hello());
    let screen = render(&mut app, 120, 30);

    assert!(
        !screen.contains("approval needed"),
        "a bar with nothing behind it would be chrome that lies:\n{}",
        screen.text()
    );
    assert!(app
        .sessions
        .open_watch()
        .and_then(Watch::next_approval)
        .is_none());
}

// ---------------------------------------------------------------- auto-approve

/// The composer types a slash verb; this is the whole path an operator takes.
fn compose(app: &mut App, text: &str) {
    for character in text.chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));
}

/// The mode's whole contract on the wire: an approval that arrives on an auto-approve
/// session is answered `approve, once` with `actor: automation` — the ledger must not
/// credit a person who never saw the request — and no modal opens over it.
#[test]
fn auto_approve_answers_an_incoming_approval_as_automation_and_opens_no_modal() {
    let mut app = opened(full_hello());
    compose(&mut app, "/auto-approve on");
    app.drain();

    approve(&mut app, codex_sandbox_escalation());

    let calls = app.drain();
    let answer = calls
        .iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("the approval is answered without a keypress");
    assert_eq!(
        answer.params,
        json!({
            "id": SESSION,
            "request_id": "req-17",
            "response": { "decision": "approve", "scope": "once", "actor": "automation" }
        }),
        "the answer says a robot pressed the button"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        !screen.contains("approve (once)"),
        "an answered request raises no modal:\n{}",
        screen.text()
    );

    // The toggle's notice owns the footer row until it expires; the badge is what stays.
    for _ in 0..64 {
        app.apply(Msg::Tick);
    }
    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("AUTO-APPROVE"),
        "the footer wears the mode while it is on:\n{}",
        screen.text()
    );
}

/// Turning the mode on answers the backlog: the request the modal was showing included.
#[test]
fn turning_auto_approve_on_answers_the_pending_backlog() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());
    app.drain();

    // The modal owns the keys while it is open; the operator leaves it first.
    app.apply(key(KeyCode::Esc));
    compose(&mut app, "/auto-approve on");

    let calls = app.drain();
    let answer = calls
        .iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("the backlog is answered the moment the mode turns on");
    assert_eq!(answer.params["request_id"], "req-17");
    assert_eq!(answer.params["response"]["actor"], "automation");
}

/// B2. The plan-exit question is never auto-answered: leaving plan mode changes what
/// every later turn may do, and `--approve-all` already settled that "answer the
/// approvals" is not "reconfigure the session". The modal still opens for it.
#[test]
fn auto_approve_never_answers_a_plan_exit() {
    let mut app = opened(full_hello());
    compose(&mut app, "/auto-approve on");
    app.drain();

    approve(
        &mut app,
        json!({
            "kind": "plan_exit",
            "header": "Plan ready",
            "question": "Ready to build it?",
            "options": [
                {"optionId": "auto_edit", "name": "Yes, auto-accept edits", "kind": "allow_always"},
                {"optionId": "prompt", "name": "Yes, manual approvals", "kind": "allow_once"},
                {"optionId": "keep_planning", "name": "No, keep planning", "kind": "reject_once"}
            ]
        }),
    );

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.respond_approval"),
        "a plan exit is a question only a person answers"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("keep planning"),
        "the plan-exit modal opens as it always did:\n{}",
        screen.text()
    );
}

/// Replay overlap re-inserts a pending request until its `approval_resolved` lands; the
/// in-flight mark is what keeps the robot from answering it twice.
#[test]
fn a_replayed_approval_is_not_answered_twice() {
    let mut app = opened(full_hello());
    compose(&mut app, "/auto-approve on");
    app.drain();

    approve(&mut app, codex_sandbox_escalation());
    assert_eq!(
        app.drain()
            .iter()
            .filter(|call| call.method == "interactive.respond_approval")
            .count(),
        1
    );

    // The same frame again — the overlap a resync can deliver.
    approve(&mut app, codex_sandbox_escalation());
    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.respond_approval"),
        "an answer already in flight is not sent again"
    );
}

/// `/auto-approve off` hands the next request back to the modal.
#[test]
fn auto_approve_off_asks_again() {
    let mut app = opened(full_hello());
    compose(&mut app, "/auto-approve on");
    compose(&mut app, "/auto-approve off");
    app.drain();

    approve(&mut app, codex_sandbox_escalation());

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.respond_approval"),
        "with the mode off nothing is answered for anyone"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("approve (once)"),
        "the modal is back:\n{}",
        screen.text()
    );
    assert!(
        !screen.contains("AUTO-APPROVE"),
        "and the footer no longer wears the mode:\n{}",
        screen.text()
    );
}

/// `ctrl+x A` — the capital sibling of `ctrl+x a`: one answers the approval that is
/// asking, the other answers everything the session will ask.
#[test]
fn the_leader_chord_toggles_auto_approve() {
    let mut app = opened(full_hello());

    app.apply(ctrl('x'));
    app.apply(Msg::Key(KeyEvent::new(
        KeyCode::Char('A'),
        KeyModifiers::SHIFT,
    )));

    for _ in 0..64 {
        app.apply(Msg::Tick);
    }
    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("AUTO-APPROVE"),
        "the chord flips the mode:\n{}",
        screen.text()
    );

    approve(&mut app, codex_sandbox_escalation());
    assert!(
        app.drain()
            .iter()
            .any(|call| call.method == "interactive.respond_approval"),
        "and the mode it flipped is the real one"
    );
}

/// The native agent's `ask_user` tool rides the approval channel with `kind:
/// "question"`. A robot `approve` carries no `choice`, which the runtime reports to the
/// agent as "acknowledged without an answer" — so auto-approve leaves the question for
/// the person, modal and all.
#[test]
fn auto_approve_never_answers_an_ask_user_question() {
    let mut app = opened(full_hello());
    compose(&mut app, "/auto-approve on");
    app.drain();

    approve(
        &mut app,
        json!({
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
        "a question the agent asked a person is not answered by a robot"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("Commit blocked"),
        "the question modal opens as it always did:\n{}",
        screen.text()
    );
}

/// Composition: full access and auto-approve are two separate decisions, and an operator
/// can hold both.
///
/// A `sandbox_escalation` is a **permission** — `kind` is not `"question"` — so the mode
/// answers it like any other, `approve, once, actor: automation`. What it does *not* do is
/// write the durable rule the modal's fifth answer would: a standing yes for this session
/// is not consent to a workspace allow rule that outlives it, and `scope: once` is the
/// whole of what the robot grants.
#[test]
fn auto_approve_answers_a_sandbox_escalation_without_writing_its_rule() {
    let mut app = opened(full_hello());
    compose(&mut app, "/auto-approve on");
    app.drain();

    // The exact payload the runtime raises when a command is stopped by the sandbox: the
    // kind, the command and cwd it stopped, the reason, and the rule that would end it.
    approve(&mut app, codex_sandbox_escalation());

    let calls = app.drain();
    let answered = calls
        .iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("an escalation is a permission, so the mode answers it");

    assert_eq!(
        answered.params,
        json!({
            "id": SESSION,
            "request_id": "req-17",
            "response": { "decision": "approve", "scope": "once", "actor": "automation" }
        })
    );
    assert!(
        calls.iter().all(|call| call.method != "permissions.add"),
        "the durable rule belongs to the fifth answer a person chooses, not to the mode"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        !screen.contains("sandbox escalation"),
        "an answered escalation raises no modal:\n{}",
        screen.text()
    );
}

/// The escalation modal a person *does* see states every field the payload carries — the
/// command that was stopped, where it ran, and the reason the sandbox gave — beside the
/// fifth answer that would stop it being asked again.
#[test]
fn the_escalation_modal_states_the_command_the_cwd_the_reason_and_the_rule() {
    let mut app = opened(full_hello());
    approve(&mut app, codex_sandbox_escalation());

    let screen = render(&mut app, 120, 30);

    assert!(screen.contains("approval requested — sandbox escalation"));
    assert!(screen.contains("cargo test --all"), "{}", screen.text());
    assert!(screen.contains("cwd /tmp/w"), "{}", screen.text());
    assert!(
        screen.contains("the sandbox refused a write outside the workspace"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("approve, and don't ask again for Bash(cargo test *)"),
        "the fifth answer is present where a rule can actually be saved:\n{}",
        screen.text()
    );
}
