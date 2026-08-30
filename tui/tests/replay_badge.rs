//! D10: the replay badge — the one thing this client says about a session's replayability.
//!
//! A badge is a *positive* claim: "this conversation can be re-run against its record".
//! No client can make that true on its own, so it is drawn only where the runtime declared
//! the capability. Which puts it on the opposite side of `Capability::offered()` from every
//! *control* in this client: hiding a working control on silence would invent a ceiling,
//! and raising a badge on silence would invent a promise.
//!
//! Four answers and three outcomes: `true` draws it, `"degraded"` draws the dimmed bounded
//! form, and an explicit `false` and a silence both draw nothing — different facts
//! everywhere else in this client, and the same badge here, because neither is a yes.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::{Capabilities, Capability, Plane, ReplayPosture, SessionInfo};
use ouro::ui::app::{App, Msg, Tag};

use support::{app, full_hello, render, Screen};

fn capabilities(replay: Option<Value>) -> Value {
    let mut map = json!({"transport": "native", "fork": true});

    if let Some(replay) = replay {
        map["replay"] = replay;
    }

    map
}

fn posture(replay: Option<Value>) -> Option<ReplayPosture> {
    Capabilities::decode(Some(&capabilities(replay))).replay_posture()
}

/// The three-state decode, at the level the badge reads it.
#[test]
fn the_badge_is_raised_only_where_the_runtime_declared_it() {
    assert_eq!(posture(Some(json!(true))), Some(ReplayPosture::Whole));
    assert_eq!(
        posture(Some(json!("degraded"))),
        Some(ReplayPosture::Degraded)
    );

    // Declared false — what the runtime sends for every vendor transport, precisely
    // because absence would be read as offered elsewhere in this client.
    assert_eq!(posture(Some(json!(false))), None);
    assert_eq!(
        Capabilities::decode(Some(&capabilities(Some(json!(false))))).replay,
        Capability::No
    );

    // Silence. Different from `false` as a *fact* — and the same as `false` as a *badge*,
    // because neither is the runtime saying yes.
    assert_eq!(posture(None), None);
    assert_eq!(
        Capabilities::decode(Some(&capabilities(None))).replay,
        Capability::Unknown
    );

    // A mechanism a later runtime invents is still a positive declaration.
    assert_eq!(posture(Some(json!("native"))), Some(ReplayPosture::Whole));
}

/// One rail row. The short `objective` is not decoration: the card is 24 columns wide
/// whatever the terminal is, and D7's rule is that a badge is drawn whole or not at all —
/// so a card whose title already fills it wears no badge, worktree or replay. These rows
/// leave the room a badge needs, which is the case worth asserting about.
fn session_row(id: &str, replay: Option<Value>) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.State",
        "id": id,
        "status": "idle",
        "provider": "native",
        "node": "ouroboros@alpha",
        "workspace": "/w",
        "objective": id.trim_start_matches("s-"),
        "updated_at": "2026-01-01T00:00:00.000000Z",
        "options": {"capabilities": capabilities(replay)}
    })
}

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
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

/// The rail, with four sessions that answered the capability four different ways, and one
/// of them open so the conversation surface — and therefore the rail — is what draws.
fn railed(open: &str) -> App {
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
        json!([
            session_row("s-whole", Some(json!(true))),
            session_row("s-gappy", Some(json!("degraded"))),
            session_row("s-vendor", Some(json!(false))),
            session_row("s-silent", None),
        ]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, open.to_string());
    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening subscribes");
    answer(&mut app, subscribe.tag, json!([]));
    app.apply(Msg::Tick);

    app
}

fn screen(app: &mut App) -> Screen {
    render(app, 180, 48)
}

/// Four cards, exactly two badges — and the session open on the right is the one the
/// runtime said cannot be replayed, so every glyph counted here came from the rail.
#[test]
fn the_rail_draws_the_badge_for_a_declared_session_and_for_no_other() {
    let mut app = railed("s-vendor");
    let text = screen(&mut app).text();

    assert_eq!(
        text.matches('\u{27f2}').count(),
        2,
        "only the two declared sessions get a badge:\n{text}"
    );
    assert!(text.contains("\u{27f2} partial"), "{text}");
}

/// The card is the unit that fits or does not, and D7's rule is that a badge is drawn
/// whole or not at all — `⟲ repl…` would read as a different word.
///
/// A rail card is 24 columns whatever the terminal is, so a session whose own title fills
/// it keeps the title and loses the badge. That is a real limit of this surface rather than
/// a bug: the conversation header, which has the room, still says it.
#[test]
fn a_card_whose_title_fills_it_drops_the_badge_whole() {
    let mut app = app(full_hello());

    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));

    let mut wordy = session_row("s-whole", Some(json!(true)));
    wordy["objective"] = json!("teach the parser about raw string literals");

    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([wordy]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, "s-whole".into());
    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening subscribes");
    answer(&mut app, subscribe.tag, json!([]));
    app.apply(Msg::Tick);

    let text = screen(&mut app).text();

    // Exactly one: the header's. The card's was dropped rather than truncated, and there
    // is no `⟲ repl` anywhere to prove it.
    assert_eq!(text.matches('\u{27f2}').count(), 1, "{text}");
    assert!(!text.contains("\u{27f2} repl\u{2026}"), "{text}");
}

/// The conversation header carries the same short form, beside the worktree badge.
#[test]
fn the_conversation_header_names_the_replayable_session() {
    let mut app = railed("s-whole");
    let text = screen(&mut app).text();

    // Three: two rail cards and the header of the session that is open.
    assert_eq!(text.matches('\u{27f2}').count(), 3, "{text}");
}

/// And a vendor session's header does not, because the runtime said it cannot. The row
/// that names the open session carries no claim about replaying it.
#[test]
fn a_vendor_session_header_makes_no_replay_claim() {
    let mut app = railed("s-vendor");
    let text = screen(&mut app).text();

    let header = text
        .lines()
        .find(|line| line.contains("s-vendor") && line.contains("native"))
        .unwrap_or_default();

    assert!(!header.contains('\u{27f2}'), "{text}");
}

/// The badge helper itself, so the two render sites above are reading one decision.
#[test]
fn the_badge_helper_answers_for_a_decoded_row() {
    let whole = SessionInfo::decode(Plane::Interactive, &session_row("s", Some(json!(true))))
        .expect("a session");
    assert_eq!(
        whole.capabilities.replay_posture(),
        Some(ReplayPosture::Whole)
    );

    let vendor = SessionInfo::decode(Plane::Interactive, &session_row("s", Some(json!(false))))
        .expect("a session");
    assert_eq!(vendor.capabilities.replay_posture(), None);
}
