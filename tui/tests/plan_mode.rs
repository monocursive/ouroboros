//! B2, the client half: the plan-exit modal, `/plan`, and the `PLANNING` badge.
//!
//! Every payload below is the runtime's own. The `approval_requested` shape is
//! `Ouroboros.Provider.Native.Session.plan_exit_payload/1` — three options carrying
//! `allow_always`/`allow_once`/`reject_once` so a client that never heard of plan mode
//! still reaches all three answers — and the `provider_event` is `settle_plan_exit/3`'s.
//! The three `optionId`s are the literals `Gateway.Methods` `@plan_exit_choices` matches
//! against, so a test that passes here is a test about bytes the gateway accepts.
//!
//! The honesty assertions are the point of the file:
//!
//! * every row's words are the payload's `name`, and every row sends that row's
//!   `optionId` — a modal whose rows said one thing and sent another is the one mistake
//!   here that cannot be undone;
//! * the fallback answer on a gateway that refuses `provider_options` reaches the *same*
//!   three answers, and says out loud that the follow-up did not survive;
//! * the `PLANNING` badge is raised only where the runtime said the session is planning,
//!   never inferred from a start flag this client sent.

mod support;

use std::sync::{Mutex, MutexGuard};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::Plane;
use ouro::proto::{ErrorCode, RpcError};
use ouro::transport::ClientError;
use ouro::ui::access::{self, Settings};
use ouro::ui::app::{App, Msg, Tag};

use support::{full_hello, render};

/// `access::install` is process-wide, so the one test that flips it holds this while it
/// runs and puts the default back on the way out.
static MODE: Mutex<()> = Mutex::new(());

struct Held<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        access::install(Settings::default());
    }
}

fn screen_reader() -> Held<'static> {
    let guard = MODE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    access::install(Settings {
        screen_reader: true,
        reduced_motion: true,
    });

    Held { _guard: guard }
}

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn notify(app: &mut App, frame: Value) {
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: frame["method"].as_str().expect("a method").to_string(),
        params: frame["params"].clone(),
    }));
}

/// One session row, with whatever `options` the caller wants on it.
fn session_row(options: Value) -> Value {
    json!([{
        "_struct": "Ouroboros.Interactive.State",
        "id": SESSION,
        "node": "ouroboros@golden",
        "provider": "native",
        "workspace": "/tmp/w",
        "status": "running",
        "options": options,
        "created_at": "2026-01-01T00:00:00.000000Z",
        "updated_at": "2026-01-01T00:00:00.000000Z"
    }])
}

fn opened_with(hello: ouro::proto::Hello, options: Value) -> App {
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
        session_row(options),
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

fn opened() -> App {
    opened_with(full_hello(), json!({"approval_mode": "prompt"}))
}

/// `Provider.Native.Session.plan_exit_payload/1`, the `plan_tool` form.
fn plan_exit_payload() -> Value {
    json!({
        "kind": "plan_exit",
        "header": "Plan ready",
        "question": "This session has been planning. Ready to build it?\n\
                     · Yes, auto-accept edits — edits inside the workspace apply without \
                     asking; commands still ask.\n\
                     · Yes, manual approvals — every write and command is put to you.\n\
                     · No, keep planning — nothing changes and the session stays read-only.",
        "plan_source": "plan_tool",
        "plan": {
            "plan": [
                {"step": "read the existing greeter", "status": "completed"},
                {"step": "add a name argument", "status": "in_progress"},
                {"step": "cover it with a test", "status": "pending"}
            ]
        },
        "options": [
            {"optionId": "auto_edit", "name": "Yes, auto-accept edits", "kind": "allow_always"},
            {"optionId": "prompt", "name": "Yes, manual approvals", "kind": "allow_once"},
            {"optionId": "keep_planning", "name": "No, keep planning", "kind": "reject_once"}
        ]
    })
}

/// The prose form: a model that planned in its final message rather than through the tool.
fn plan_exit_message_payload() -> Value {
    let mut payload = plan_exit_payload();
    payload["plan_source"] = json!("message");
    payload.as_object_mut().expect("an object").remove("plan");
    payload["message"] = json!(
        "I would start by reading the greeter, then thread a name \
                                argument through it, and finally cover the new branch."
    );
    payload
}

fn raise(app: &mut App, payload: Value) {
    raise_as(app, "plan_exit_abc", payload);
}

/// The same, for a second question on one session: `next_approval` skips a request whose
/// answer is still in flight, so a test that raises two must name them apart exactly as
/// the runtime does.
fn raise_as(app: &mut App, request_id: &str, payload: Value) {
    notify(
        app,
        json!({
            "jsonrpc": "2.0",
            "method": "interactive.event",
            "params": {
                "id": SESSION,
                "event": {
                    "_struct": "Ouroboros.Interactive.Event",
                    "id": format!("evt-{request_id}"),
                    "session_id": SESSION,
                    "sequence": 9 + u64::from(request_id.len() as u32),
                    "type": "approval_requested",
                    "timestamp": "2026-01-01T00:00:00.000000Z",
                    "request_id": request_id,
                    "turn_id": "turn-1",
                    "payload": payload
                }
            }
        }),
    );
}

/// The one call the modal put on the wire, with its tag.
fn sent(app: &mut App, method: &str) -> (Tag, Value) {
    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == method)
        .unwrap_or_else(|| panic!("a {method} call"));

    (call.tag, call.params)
}

// ---------------------------------------------------------------- the modal

/// The plan, the three answers in the runtime's own words, and the follow-up line — at
/// the two widths the rest of this suite pins.
#[test]
fn the_plan_exit_modal_draws_the_plan_and_the_three_answers_at_both_widths() {
    for (width, height) in [(80u16, 40u16), (120, 40)] {
        let mut app = opened();
        raise(&mut app, plan_exit_payload());

        let screen = render(&mut app, width, height);
        let text = screen.text();

        // The heading is the runtime's own, not "approval requested — plan exit".
        assert!(text.contains("plan ready"), "{width}\n{text}");
        assert!(
            !text.contains("approval requested"),
            "a plan exit is not drawn as the ordinary approval\n{width}\n{text}"
        );

        // The question is quoted: it is the only place the consequences are stated.
        assert!(text.contains("Ready to build it?"), "{width}\n{text}");

        // The plan, labelled with where it came from.
        assert!(text.contains("PLAN"), "{width}\n{text}");
        assert!(text.contains("from the plan tool"), "{width}\n{text}");
        assert!(text.contains("add a name argument"), "{width}\n{text}");

        // The three rows carry the payload's own names *and* the id each one sends.
        for (name, id) in [
            ("Yes, auto-accept edits", "auto_edit"),
            ("Yes, manual approvals", "prompt"),
            ("No, keep planning", "keep_planning"),
        ] {
            assert!(text.contains(name), "{width} missing {name}\n{text}");
            assert!(text.contains(id), "{width} missing {id}\n{text}");
        }

        // The fourth fixed answer must not appear: the payload never offered it.
        assert!(
            !text.contains("deny (session)"),
            "a plan exit offers three answers, not four\n{width}\n{text}"
        );

        // The follow-up field is advertised even when empty.
        assert!(text.contains("no follow-up prompt"), "{width}\n{text}");
        assert!(
            text.contains("what to do first"),
            "the key that writes one is named\n{width}\n{text}"
        );
    }
}

/// A plan the model wrote in prose is labelled as prose rather than passed off as a step
/// list.
#[test]
fn a_plan_from_the_final_message_says_it_came_from_the_message() {
    let mut app = opened();
    raise(&mut app, plan_exit_message_payload());

    let text = render(&mut app, 100, 40).text();

    assert!(
        text.contains("from the final message, not the plan tool"),
        "{text}"
    );
    assert!(text.contains("thread a name"), "{text}");
}

/// Screen-reader mode: every row is numbered text, and the number picks it.
#[test]
fn the_plan_exit_modal_is_numbered_text_for_a_screen_reader() {
    let _held = screen_reader();

    let mut app = opened();
    raise(&mut app, plan_exit_payload());

    let text = render(&mut app, 100, 40).text();

    for (number, name) in [
        ("1.", "Yes, auto-accept edits"),
        ("2.", "Yes, manual approvals"),
        ("3.", "No, keep planning"),
    ] {
        assert!(
            text.contains(number) && text.contains(name),
            "{number} {name}\n{text}"
        );
    }

    // The number picks the row: `3` then Enter answers `keep_planning`.
    app.apply(key(KeyCode::Char('3')));
    app.apply(key(KeyCode::Enter));

    let (_tag, params) = sent(&mut app, "interactive.respond_approval");

    assert_eq!(
        params["response"]["provider_options"]["choice"], "keep_planning",
        "{params}"
    );
}

/// An option whose `optionId` this build cannot map is reported, never drawn as a row.
#[test]
fn an_option_this_build_cannot_send_is_a_note_and_not_a_row() {
    let mut app = opened();
    let mut payload = plan_exit_payload();
    payload["options"]
        .as_array_mut()
        .expect("options")
        .push(json!({
            "optionId": "yolo_mode",
            "name": "Yes, and never ask again",
            "kind": "allow_always"
        }));
    raise(&mut app, payload);

    let text = render(&mut app, 100, 40).text();

    assert!(
        text.contains("cannot send the option"),
        "an unmappable option is named\n{text}"
    );

    // And selecting past the three real rows still answers one of the three.
    for _ in 0..6 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));

    let (_tag, params) = sent(&mut app, "interactive.respond_approval");
    let choice = params["response"]["provider_options"]["choice"]
        .as_str()
        .expect("a choice");

    assert!(
        ["auto_edit", "prompt", "keep_planning"].contains(&choice),
        "{choice} is not one of the three the payload offered"
    );
}

// ---------------------------------------------------------------- the answer

/// The exact params for each choice, byte for byte.
#[test]
fn each_row_sends_its_own_option_id_with_the_matching_decision_and_scope() {
    let expected = [
        (0usize, "approve", "session", "auto_edit"),
        (1, "approve", "once", "prompt"),
        (2, "deny", "once", "keep_planning"),
    ];

    for (row, decision, scope, id) in expected {
        let mut app = opened();
        raise(&mut app, plan_exit_payload());

        for _ in 0..row {
            app.apply(key(KeyCode::Down));
        }
        app.apply(key(KeyCode::Enter));

        let (_tag, params) = sent(&mut app, "interactive.respond_approval");

        assert_eq!(
            params,
            json!({
                "id": SESSION,
                "request_id": "plan_exit_abc",
                "response": {
                    "decision": decision,
                    "scope": scope,
                    "provider_options": {"choice": id},
                },
            }),
            "row {row}"
        );
    }
}

/// A follow-up written on the modal rides along under the one key the gateway admits.
#[test]
fn a_follow_up_is_carried_on_the_answer_that_leaves_plan_mode() {
    let mut app = opened();
    raise(&mut app, plan_exit_payload());

    // `r` opens the composer, the text is typed, Enter attaches it and returns to the
    // modal — the question is still open at that point, not answered.
    app.apply(key(KeyCode::Char('r')));
    for character in "start with the parser".chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.respond_approval"),
        "attaching a follow-up does not answer the question"
    );

    let text = render(&mut app, 100, 40).text();
    assert!(text.contains("FIRST, DO THIS"), "{text}");
    assert!(text.contains("start with the parser"), "{text}");

    app.apply(key(KeyCode::Enter));

    let (_tag, params) = sent(&mut app, "interactive.respond_approval");

    assert_eq!(
        params["response"]["provider_options"],
        json!({"choice": "auto_edit", "follow_up": "start with the parser"}),
        "{params}"
    );
}

/// A gateway that refuses `provider_options` gets the four-way answer instead, and the
/// operator is told once — including whether anything was lost.
#[test]
fn a_gateway_that_refuses_provider_options_falls_back_and_says_so_once() {
    let mut app = opened();
    raise(&mut app, plan_exit_payload());

    app.apply(key(KeyCode::Char('r')));
    for character in "run the tests".chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));

    let (tag, first) = sent(&mut app, "interactive.respond_approval");

    assert!(
        first["response"].get("provider_options").is_some(),
        "the first attempt carries the explicit choice\n{first}"
    );

    // The refusal an older gateway gives: a bare -32602 with a generic sentence.
    app.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "params.response must be approve, deny, or an object".into(),
            data: None,
        })),
    });

    let (_tag, second) = sent(&mut app, "interactive.respond_approval");

    // The retry reaches the same answer the explicit choice would have.
    assert_eq!(
        second,
        json!({
            "id": SESSION,
            "request_id": "plan_exit_abc",
            "response": {"decision": "approve", "scope": "session"},
        }),
        "{second}"
    );

    let text = render(&mut app, 100, 40).text();
    assert!(
        text.contains("does not take a plan-exit choice"),
        "the fallback is stated, not silent\n{text}"
    );
    assert!(
        text.contains("follow-up"),
        "and it says the follow-up was dropped\n{text}"
    );

    // Said once: the next plan exit on this connection goes straight to the fallback.
    // A fresh request id, because the first one's answer is still in flight and
    // `next_approval` deliberately skips those.
    raise_as(&mut app, "plan_exit_def", plan_exit_payload());
    app.apply(key(KeyCode::Enter));

    let (tag, third) = sent(&mut app, "interactive.respond_approval");

    assert!(
        third["response"].get("provider_options").is_none(),
        "a gateway already known to refuse the key is not asked twice\n{third}"
    );
    assert!(
        matches!(tag, Tag::Approval { .. }),
        "and the call is tagged as an ordinary approval, with nothing left to fall back to"
    );
}

/// A refusal that is *not* about `provider_options` is reported as itself, and the answer
/// is not silently downgraded.
#[test]
fn an_unrelated_refusal_is_not_treated_as_a_missing_provider_options() {
    let mut app = opened();
    raise(&mut app, plan_exit_payload());
    app.apply(key(KeyCode::Enter));

    let (tag, _first) = sent(&mut app, "interactive.respond_approval");

    app.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::Other(-32000),
            message: "the session is no longer running".into(),
            data: None,
        })),
    });

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.respond_approval"),
        "a refusal this client cannot fix is not retried"
    );

    // Wide enough that the notice row is not itself the thing doing the truncating.
    let text = render(&mut app, 160, 40).text();
    assert!(text.contains("the session is no longer running"), "{text}");
}
