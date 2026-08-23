//! G2: the rail, the picker and `ouro agents` all answer one question first — is anything
//! waiting on me — and they answer it from declared state rather than from a guess.
//!
//! The fixture below is deliberately two nodes with one of each kind on it, because the
//! acceptance for this slice is exactly that: "two machines, one waiting on approval: it
//! is first in the list".

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::agents;
use ouro::model::{Plane, SessionInfo, Triage};
use ouro::ui::app::{App, Msg, Overlay, Tag};

use support::{app, full_hello, render, Screen};

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

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

/// Two nodes, four sessions: one waiting on an approval, one working, one done, and one
/// whose owner is offline.
fn interactive_rows() -> Value {
    json!([
        {
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-waiting",
            "status": "awaiting_approval",
            "provider": "native",
            "node": "ouroboros@beta",
            "workspace": "/w/two",
            "objective": "Waiting on a write",
            "updated_at": "2020-01-01T00:00:00.000000Z"
        },
        {
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-working",
            "status": "running",
            "provider": "codex",
            "node": "ouroboros@alpha",
            "workspace": "/w/one",
            "objective": "Porting the auth module",
            "updated_at": "2026-01-01T00:00:09.000000Z"
        },
        {
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-done",
            "status": "completed",
            "provider": "codex",
            "node": "ouroboros@alpha",
            "workspace": "/w/one",
            "objective": "Yesterday's fix",
            "updated_at": "2026-01-01T00:00:08.000000Z"
        }
    ])
}

fn coding_rows() -> Value {
    json!([
        {
            "_struct": "Ouroboros.Coding.TaskState",
            "id": "task-offline",
            "status": "running",
            "provider": "codex",
            "node": "ouroboros@gamma",
            "workspace": "/w/three",
            "objective": "On a machine nobody can reach",
            "updated_at": "2026-01-01T00:00:07.000000Z"
        }
    ])
}

fn fleet() -> App {
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
        interactive_rows(),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), coding_rows());
    app.apply(Msg::Tick);

    app
}

fn screen(app: &mut App) -> Screen {
    render(app, 180, 48)
}

// ---------------------------------------------------------------------------------------
// the grouping itself
// ---------------------------------------------------------------------------------------

#[test]
fn the_row_waiting_on_a_human_is_first_however_old_it_is() {
    let app = fleet();
    let rows = app.sessions.triaged();

    assert_eq!(rows[0].0, Triage::NeedsInput);
    assert_eq!(
        rows[0].1.id, "session-waiting",
        "the oldest row in the fixture, and still first: the group decides the order"
    );

    let groups: Vec<Triage> = rows.iter().map(|(group, _session)| *group).collect();
    assert!(
        groups.windows(2).all(|pair| pair[0] <= pair[1]),
        "needs input, then working, then done: {groups:?}"
    );

    assert_eq!(app.sessions.triage_counts(), [1, 2, 1]);
}

/// A pending approval this client is holding promotes a row that the runtime still calls
/// `running`, because from the operator's side those are the same fact.
#[test]
fn an_approval_this_client_is_holding_moves_its_row_into_needs_input() {
    let mut app = fleet();
    app.open_session(Plane::Interactive, "session-working".into());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening subscribes");

    answer(
        &mut app,
        subscribe.tag,
        json!([{
            "_struct": "Ouroboros.Interactive.Event",
            "id": "evt-1",
            "sequence": 1,
            "type": "approval_requested",
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "payload": {"tool": "write", "command": "write lib/a.ex"},
            "request_id": "req-1",
            "provider": "codex"
        }]),
    );
    app.apply(Msg::Tick);

    let rows = app.sessions.triaged();
    let working = rows
        .iter()
        .find(|(_group, session)| session.id == "session-working")
        .expect("the row is still listed");

    assert_eq!(working.0, Triage::NeedsInput);
    assert_eq!(app.sessions.triage_counts()[Triage::NeedsInput as usize], 2);
}

/// An offline owner is a fact about the *observation*, not about the session, so a
/// last-known row keeps its group and carries the mark the rail already had.
#[test]
fn an_offline_owners_rows_stay_in_their_group_and_keep_the_unavailable_mark() {
    let mut app = fleet();

    // The owner drops off the fleet: `runtime.status` no longer reports it, so the row is
    // retained from the previous complete list rather than deleted.
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouroboros@alpha",
            "role": "core",
            "connected_nodes": ["ouroboros@beta"],
            "availability": {}
        }),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    app.apply(Msg::Tick);

    let rows = app.sessions.triaged();
    let offline = rows
        .iter()
        .find(|(_group, session)| session.id == "task-offline");

    if let Some((group, session)) = offline {
        assert!(
            session.last_known,
            "a retained row says it is a retained row"
        );
        assert_eq!(
            *group,
            Triage::Working,
            "unreachable is not the same claim as needs-input"
        );
    }
}

// ---------------------------------------------------------------------------------------
// the surfaces
// ---------------------------------------------------------------------------------------

#[test]
fn the_rail_draws_the_groups_in_order_with_their_counts() {
    let mut app = fleet();
    app.open_session(Plane::Interactive, "session-working".into());
    let _ = app.drain();
    app.apply(Msg::Tick);

    let text = screen(&mut app).text();

    assert!(text.contains("NEEDS INPUT"), "{text}");
    assert!(text.contains("WORKING"), "{text}");

    let needs = text.find("NEEDS INPUT").expect("a needs-input heading");
    let working = text.find("WORKING").expect("a working heading");
    assert!(needs < working, "needs input is drawn first: {text}");

    // The node each row is on, because the rail lists every machine's sessions — and
    // dropped whole rather than clipped where a card is too narrow to hold it.
    assert!(text.contains("RUNNING · codex · alpha"), "{text}");
}

#[test]
fn the_footer_counts_what_is_waiting_across_the_fleet() {
    let mut app = fleet();
    app.open_session(Plane::Interactive, "session-working".into());
    let _ = app.drain();
    app.apply(Msg::Tick);

    let text = screen(&mut app).text();
    assert!(
        text.contains("1 waiting · 2 working"),
        "the footer states the fleet's own counts: {text}"
    );
}

#[test]
fn space_peeks_the_last_agent_message_and_r_replies_on_that_session() {
    let mut app = fleet();
    app.open_session(Plane::Interactive, "session-working".into());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening subscribes");

    answer(
        &mut app,
        subscribe.tag,
        json!([{
            "_struct": "Ouroboros.Interactive.Event",
            "id": "evt-1",
            "sequence": 1,
            "type": "output_text_final",
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "payload": {"text": "I have finished the first half and need a decision."},
            "turn_id": "turn-1",
            "provider": "codex"
        }]),
    );
    app.apply(Msg::Tick);

    // Open the picker, move to the working row, and peek.
    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    app.apply(key(KeyCode::Char('l')));
    let _ = app.drain();

    for _ in 0..4 {
        if matches!(
            app.overlay,
            Some(Overlay::SessionPicker {
                selected: Some((_, ref id))
            }) if id == "session-working"
        ) {
            break;
        }
        app.apply(key(KeyCode::Down));
    }

    app.apply(key(KeyCode::Char(' ')));
    assert!(matches!(app.overlay, Some(Overlay::Peek { .. })));

    let text = screen(&mut app).text();
    assert!(
        text.contains("I have finished the first half"),
        "the peek shows what the agent last said: {text}"
    );

    // `r` from the peek opens that session with the composer ready.
    app.apply(key(KeyCode::Char('r')));

    assert!(app.overlay.is_none());
    assert_eq!(
        app.sessions.open,
        Some((Plane::Interactive, "session-working".to_string()))
    );
    assert!(
        app.sessions.composer.is_some(),
        "r puts the cursor where the reply goes"
    );
}

/// A row this client never subscribed to has no last message *here*, and the peek says so
/// rather than showing an empty box that reads as "the agent said nothing".
#[test]
fn a_peek_at_an_unwatched_session_says_it_holds_no_transcript() {
    let mut app = fleet();

    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    app.apply(key(KeyCode::Char('l')));
    let _ = app.drain();
    app.apply(key(KeyCode::Char(' ')));

    let text = screen(&mut app).text();
    assert!(
        text.contains("not holding this session's transcript"),
        "{text}"
    );
}

#[test]
fn the_picker_labels_every_row_with_its_group_and_its_node() {
    let mut app = fleet();

    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    app.apply(key(KeyCode::Char('l')));
    let _ = app.drain();

    let text = screen(&mut app).text();
    assert!(text.contains("1 need input"), "{text}");
    assert!(text.contains("2 working"), "{text}");
    assert!(text.contains("1 done"), "{text}");
    assert!(text.contains("needs input"), "{text}");
    assert!(text.contains("ouroboros@beta"), "{text}");
    assert!(text.contains("space peek · r reply"), "{text}");
}

// ---------------------------------------------------------------------------------------
// `ouro agents`
// ---------------------------------------------------------------------------------------

fn agents_rows() -> (Vec<SessionInfo>, Vec<SessionInfo>) {
    agents::decode(&interactive_rows(), &coding_rows())
}

#[test]
fn ouro_agents_prints_the_same_grouping_byte_for_byte() {
    let (interactive, coding) = agents_rows();
    let rows = agents::group(&interactive, &coding);

    assert_eq!(
        agents::render(&rows),
        concat!(
            "NEEDS INPUT (1)\n",
            "  int    session-waiting                    awaiting_approval  ouroboros@beta           Waiting on a write\n",
            "\n",
            "WORKING (2)\n",
            "  int    session-working                    running            ouroboros@alpha          Porting the auth module\n",
            "  code   task-offline                       running            ouroboros@gamma          On a machine nobody can reach\n",
            "\n",
            "DONE (1)\n",
            "  int    session-done                       completed          ouroboros@alpha          Yesterday's fix\n",
            "\n",
        )
    );
}

#[test]
fn ouro_agents_json_carries_the_counts_and_the_runtimes_own_rows() {
    let (interactive, coding) = agents_rows();
    let value = agents::render_json(&agents::group(&interactive, &coding));

    assert_eq!(value["counts"]["needs_input"], 1);
    assert_eq!(value["counts"]["working"], 2);
    assert_eq!(value["counts"]["done"], 1);

    assert_eq!(value["groups"]["needs_input"][0]["id"], "session-waiting");
    assert_eq!(value["groups"]["needs_input"][0]["node"], "ouroboros@beta");
    assert_eq!(value["groups"]["working"][1]["plane"], "coding");
    assert_eq!(
        value["groups"]["done"][0]["session"]["_struct"], "Ouroboros.Interactive.State",
        "the runtime's own row travels whole"
    );
}

#[test]
fn ouro_agents_says_so_when_there_is_nothing_to_report() {
    let (interactive, coding) = agents::decode(&json!([]), &json!([]));

    assert_eq!(
        agents::render(&agents::group(&interactive, &coding)),
        "no sessions on any node this runtime can see\n"
    );
}
