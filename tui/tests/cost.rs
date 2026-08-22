//! I2: what a session has spent, where it is stated, and the one thing this client will
//! not claim about it.
//!
//! The overlay draws two accounts side by side because they answer different questions:
//! what the *runtime* folded over the whole session (`interactive.info`'s `usage`), and
//! what *this transcript* folds over the events it still holds. The second is labelled
//! partial the moment the window stops covering the session, because a total built from a
//! pruned window is a lower bound.
//!
//! `[budget] max_cost_usd` is a soft limit and the tests say so in as many words: the cell
//! turns `WARN`, one notice is said, and nothing is stopped. A client cannot refuse a turn
//! the runtime runs, and the runtime's own budgets are a later slice.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::Plane;
use ouro::ui::app::{App, Msg, Overlay, Tag};

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

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

/// `Interactive.State.public/1`'s `usage`, as the runtime folds it.
fn usage() -> Value {
    json!({
        "input_tokens": 40_000,
        "output_tokens": 2_500,
        "cache_read_tokens": 1_200,
        "cache_creation_tokens": 300,
        "total_tokens": 42_500,
        "cost_usd": 0.42,
        "turns_with_usage": 3
    })
}

fn session(id: &str, usage: Value) -> Value {
    let mut row = json!({
        "_struct": "Ouroboros.Interactive.State",
        "id": id,
        "status": "idle",
        "provider": "codex",
        "workspace": "/w",
        "updated_at": "2026-01-01T00:00:00.000000Z",
        "options": {
            "model": "gpt-5-codex",
            "capabilities": { "transport": "app_server", "interrupt": "native" }
        },
    });

    if !usage.is_null() {
        row["usage"] = usage;
    }

    row
}

fn event(sequence: u64, kind: &str, payload: Value) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.Event",
        "id": format!("evt-{sequence}"),
        "sequence": sequence,
        "type": kind,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "payload": payload,
        "turn_id": "turn-1",
        "provider": "codex"
    })
}

/// One open interactive session with `rows` in the list and `events` in its transcript.
fn opened(rows: Vec<Value>, events: Vec<Value>) -> App {
    let mut app = app(full_hello());
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));

    answer(&mut app, Tag::Sessions(Plane::Interactive), json!(rows));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    app.open_session(Plane::Interactive, "session-a7".into());

    if let Some(subscribe) = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
    {
        answer(&mut app, subscribe.tag, json!(events));
    }

    app.sessions.composer = None;
    app.apply(Msg::Tick);
    app
}

fn one_session() -> App {
    opened(vec![session("session-a7", usage())], Vec::new())
}

/// Typed into the composer and submitted, which is how an operator reaches a `/` verb.
fn slash(app: &mut App, command: &str) {
    if app.sessions.composer.is_none() {
        app.apply(key(KeyCode::Enter));
    }

    for character in command.chars() {
        app.apply(key(KeyCode::Char(character)));
    }

    app.apply(key(KeyCode::Enter));
}

fn screen(app: &mut App, width: u16) -> Screen {
    render(app, width, 40)
}

// ---------------------------------------------------------------------------------------
// (a) the overlay
// ---------------------------------------------------------------------------------------

/// `/cost` and `/usage` are the same page, because they are the same question.
#[test]
fn cost_and_usage_open_one_overlay() {
    let mut app = one_session();

    slash(&mut app, "/cost");
    assert!(
        matches!(app.overlay, Some(Overlay::Cost { .. })),
        "{:?}",
        app.overlay
    );
    app.apply(key(KeyCode::Esc));

    slash(&mut app, "/usage");
    assert!(
        matches!(app.overlay, Some(Overlay::Cost { .. })),
        "{:?}",
        app.overlay
    );
}

/// Every number the runtime reported, drawn, at the two widths a footer test uses.
#[test]
fn the_overlay_states_every_reported_number_at_eighty_and_a_hundred_and_twenty_columns() {
    for width in [80, 120] {
        let mut app = one_session();
        slash(&mut app, "/cost");

        let text = screen(&mut app, width).text();

        assert!(
            text.contains("AS THE RUNTIME REPORTS IT"),
            "{width}\n{text}"
        );
        assert!(text.contains("input tokens"), "{width}\n{text}");
        assert!(text.contains("output tokens"), "{width}\n{text}");
        assert!(text.contains("cache read"), "{width}\n{text}");
        assert!(text.contains("cache creation"), "{width}\n{text}");
        assert!(text.contains("total tokens"), "{width}\n{text}");
        assert!(text.contains("turns with usage"), "{width}\n{text}");
        assert!(
            text.contains("$0.42"),
            "the cost, to the cent\n{width}\n{text}"
        );
        assert!(text.contains("42.5k"), "{width}\n{text}");
        // The exact count beside the short form: a footer rounds, a cost page does not.
        assert!(text.contains("42500"), "{width}\n{text}");
        assert!(text.contains("gpt-5-codex"), "{width}\n{text}");
    }
}

/// A provider that reports no cost is said to report none. It is never drawn as `$0.00`,
/// which reads as a free session.
#[test]
fn a_cost_the_provider_never_reported_is_named_rather_than_shown_as_zero() {
    let mut usage = usage();
    usage["cost_usd"] = Value::Null;

    let mut app = opened(vec![session("session-a7", usage)], Vec::new());
    slash(&mut app, "/cost");

    let text = screen(&mut app, 120).text();
    assert!(text.contains("not reported by this provider"), "{text}");
    assert!(!text.contains("$0.00"), "{text}");
}

/// A session whose `usage` the runtime has not reported at all says so, and does not
/// invent a row of zeroes.
#[test]
fn a_session_with_no_reported_usage_says_so() {
    let mut app = opened(vec![session("session-a7", Value::Null)], Vec::new());
    slash(&mut app, "/cost");

    let text = screen(&mut app, 120).text();
    assert!(text.contains("has not been reported"), "{text}");
}

/// The transcript's own fold is drawn beside the runtime's, and is labelled *partial* the
/// moment the retained window stops covering the session.
#[test]
fn the_transcript_fold_is_labelled_partial_once_the_window_no_longer_covers_the_session() {
    let complete = opened(
        vec![session("session-a7", usage())],
        vec![event(
            1,
            "usage",
            json!({ "input_tokens": 10, "output_tokens": 2, "cost_usd": 0.01 }),
        )],
    );
    let mut complete = complete;
    slash(&mut complete, "/cost");

    let text = screen(&mut complete, 120).text();
    assert!(text.contains("AS THIS TRANSCRIPT FOLDS"), "{text}");
    assert!(
        !text.contains("PARTIAL"),
        "a whole window is not partial\n{text}"
    );
    assert!(text.contains("usage events"), "{text}");

    // A raised floor is what `cursor_pruned` leaves behind: history that will never
    // arrive, so every total below is a lower bound.
    let mut partial = opened(
        vec![session("session-a7", usage())],
        vec![event(
            50,
            "usage",
            json!({ "input_tokens": 10, "output_tokens": 2 }),
        )],
    );
    partial
        .sessions
        .watches
        .get_mut(&(Plane::Interactive, "session-a7".to_string()))
        .expect("an open watch")
        .raise_floor(49);
    slash(&mut partial, "/cost");

    let text = screen(&mut partial, 120).text();
    assert!(
        text.contains("PARTIAL"),
        "a pruned window is a lower bound and says so\n{text}"
    );
}

/// With no session open there is nothing spent to report, and the page says that rather
/// than drawing an empty table.
#[test]
fn the_overlay_without_a_session_says_there_is_nothing_to_report() {
    let mut app = app(full_hello());
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.open_cost();

    let text = screen(&mut app, 120).text();
    assert!(text.contains("nothing spent to report"), "{text}");
}

// ---------------------------------------------------------------------------------------
// (b) the soft budget
// ---------------------------------------------------------------------------------------

/// Past `[budget] max_cost_usd` the footer's cost cell turns `WARN`, and under it does not.
#[test]
fn the_footer_cost_cell_turns_warn_once_the_reported_cost_passes_the_limit() {
    let mut under = one_session();
    under.config.budget.max_cost_usd = Some(5.0);
    let drawn = screen(&mut under, 120);
    assert_ne!(
        drawn.colour_of("OWN RUNTIME", "$0.42"),
        ouro::ui::theme::warn(),
        "under the limit the cell is ordinary\n{}",
        drawn.text()
    );

    let mut over = one_session();
    over.config.budget.max_cost_usd = Some(0.25);
    let drawn = screen(&mut over, 120);
    assert_eq!(
        drawn.colour_of("OWN RUNTIME", "$0.42"),
        ouro::ui::theme::warn(),
        "past it the cell says so\n{}",
        drawn.text()
    );
}

/// The notice is said once. The condition does not un-happen, and a notice on every tick
/// would own the one row a refusal has to fit on.
#[test]
fn the_budget_notice_is_said_once_and_never_claims_to_have_stopped_anything() {
    let mut app = one_session();
    app.config.budget.max_cost_usd = Some(0.25);

    app.apply(Msg::Tick);
    let first = app.notice.as_ref().map(|notice| notice.text.clone());
    let first = first.expect("the limit produced a notice");

    assert!(first.contains("max_cost_usd"), "{first}");
    assert!(first.contains("$0.42"), "{first}");
    assert!(first.contains("$0.25"), "{first}");
    assert!(
        first.contains("does not stop anything"),
        "the notice must not imply a halt this client cannot perform\n{first}"
    );

    // Cleared, then ticked again: nothing comes back.
    app.notice = None;

    for _ in 0..40 {
        app.apply(Msg::Tick);
    }

    assert!(
        app.notice.is_none(),
        "said once: {:?}",
        app.notice.as_ref().map(|notice| notice.text.clone())
    );
}

/// No limit, no warning — and a limit a provider that reports no cost can never reach is
/// said to be unreachable rather than left looking satisfied.
#[test]
fn a_provider_that_reports_no_cost_can_never_cross_a_limit() {
    let mut usage = usage();
    usage["cost_usd"] = Value::Null;

    let mut app = opened(vec![session("session-a7", usage)], Vec::new());
    app.config.budget.max_cost_usd = Some(0.01);
    app.apply(Msg::Tick);

    assert!(app.notice.is_none(), "{:?}", app.notice);

    slash(&mut app, "/cost");
    let text = screen(&mut app, 120).text();
    assert!(text.contains("cannot be reached"), "{text}");
    assert!(text.contains("never stops a turn"), "{text}");
}

/// With nothing configured the page says the client is not watching a limit, rather than
/// leaving a reader to guess whether one exists.
#[test]
fn no_budget_is_stated_as_no_budget() {
    let mut app = one_session();
    slash(&mut app, "/cost");

    let text = screen(&mut app, 120).text();
    assert!(text.contains("not watching a limit"), "{text}");
}

/// `[budget]` survives the settings overlay's whole-file rewrite, so a limit an operator
/// set does not quietly disappear the next time they press `,`.
#[test]
fn a_saved_budget_round_trips_through_the_file() {
    let dir = std::env::temp_dir().join("ouro-budget-round-trip");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("config.toml");

    let mut config = ouro::config::Config::default();
    config.budget.max_cost_usd = Some(5.0);
    config.save(&path).expect("a saved config");

    let loaded = ouro::config::load(path);
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
    assert_eq!(loaded.config, config);
    assert_eq!(loaded.config.budget.max_cost_usd(), Some(5.0));

    // And an absent table is an absent limit, not a zero one.
    assert_eq!(ouro::config::Config::default().budget.max_cost_usd(), None);

    std::fs::remove_dir_all(&dir).ok();
}

/// `max_cost_usd = 0` and a negative are both "no limit", not "everything is over budget".
#[test]
fn a_zero_or_negative_limit_is_no_limit() {
    for limit in [0.0, -1.0] {
        let mut app = one_session();
        app.config.budget.max_cost_usd = Some(limit);
        app.apply(Msg::Tick);

        assert!(app.notice.is_none(), "{limit}: {:?}", app.notice);
        assert_eq!(app.config.budget.max_cost_usd(), None, "{limit}");
    }
}

// ---------------------------------------------------------------------------------------
// (c) the list column
// ---------------------------------------------------------------------------------------

/// The picker carries `tokens · cost` where the runtime reported one.
#[test]
fn the_session_picker_carries_a_usage_column_where_there_is_one() {
    let mut app = opened(
        vec![
            session("session-a7", usage()),
            session("session-b2", usage()),
        ],
        Vec::new(),
    );
    // `ctrl+x l`, which is what an operator presses.
    app.apply(Msg::Key(KeyEvent {
        code: KeyCode::Char('x'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }));
    app.apply(key(KeyCode::Char('l')));

    let text = screen(&mut app, 120).text();
    assert!(text.contains("42.5k"), "{text}");
    assert!(text.contains("$0.42"), "{text}");
}

/// A row the runtime reported no usage for shows nothing at all. `interactive.list` does
/// not carry `usage` on every gateway, and a `0` standing in for silence would read as a
/// session that cost nothing.
#[test]
fn a_row_without_usage_shows_no_column_rather_than_a_zero() {
    let mut app = opened(
        vec![
            session("session-a7", usage()),
            session("session-b2", Value::Null),
        ],
        Vec::new(),
    );
    // `ctrl+x l`, which is what an operator presses.
    app.apply(Msg::Key(KeyEvent {
        code: KeyCode::Char('x'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }));
    app.apply(key(KeyCode::Char('l')));

    let drawn = screen(&mut app, 120);
    // `int   <id>` is the picker's own row; the rail draws the same id on a card.
    let row = drawn.row("int   session-b2");

    assert!(!row.contains("$"), "{row}");
    // And the row beside it, which does have usage, still carries it.
    assert!(
        drawn.row("int   session-a7").contains("42.5k"),
        "{}",
        drawn.text()
    );
}

/// A usage map with a zero total and no cost is silence too: nothing was spent that the
/// runtime could name, so nothing is drawn.
#[test]
fn a_usage_map_with_nothing_in_it_draws_nothing() {
    let mut app = opened(
        vec![session(
            "session-a7",
            json!({ "input_tokens": 0, "output_tokens": 0, "total_tokens": 0 }),
        )],
        Vec::new(),
    );
    // `ctrl+x l`, which is what an operator presses.
    app.apply(Msg::Key(KeyEvent {
        code: KeyCode::Char('x'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }));
    app.apply(key(KeyCode::Char('l')));

    let drawn = screen(&mut app, 120);
    let row = drawn.row("int   session-a7");
    assert!(!row.contains("$"), "{row}");
}

/// The rail's card carries the cell that fits, and drops the half that does not.
///
/// The card is twenty columns of a hundred-and-twenty-column frame, which holds
/// `IDLE · codex` and the cost and not the token count as well. Asserted against the
/// *card's own row*, not the frame: the footer states the same numbers, and a `contains`
/// over the whole screen would pass without the rail drawing anything.
#[test]
fn the_rail_card_carries_the_cell_that_fits_and_drops_the_rest() {
    let mut app = one_session();
    let drawn = screen(&mut app, 120);
    let card = drawn.row("IDLE · codex");

    assert!(card.contains("$0.42"), "the cost fits\n{}", drawn.text());
    assert!(
        !card.contains("42.5k"),
        "and the token count is dropped rather than truncated\n{card}"
    );
}

/// A card whose session has no reported usage carries neither half.
#[test]
fn a_rail_card_without_usage_carries_nothing() {
    let mut app = opened(vec![session("session-a7", Value::Null)], Vec::new());
    let drawn = screen(&mut app, 120);
    let card = drawn.row("IDLE · codex");

    assert!(!card.contains("$"), "{card}");
}

/// The overlay scrolls rather than silently ending, exactly as `?` does.
#[test]
fn the_overlay_scrolls_on_a_short_terminal() {
    let mut app = one_session();
    slash(&mut app, "/cost");

    let short = render(&mut app, 120, 12);
    assert!(short.contains("more row"), "{}", short.text());

    app.apply(key(KeyCode::Char('j')));
    assert!(
        matches!(app.overlay, Some(Overlay::Cost { scroll: 1 })),
        "{:?}",
        app.overlay
    );

    app.apply(key(KeyCode::Esc));
    assert!(app.overlay.is_none());
}

/// The default colour helpers agree with the footer's, so the two surfaces cannot render
/// the same spend differently.
#[test]
fn the_page_and_the_footer_format_the_same_numbers_the_same_way() {
    assert_eq!(ouro::ui::view::money(0.42), "$0.42");
    assert_eq!(ouro::ui::view::money(0.001), "<$0.01");
    assert_eq!(ouro::ui::view::tokens(42_500), "42.5k");
    assert_eq!(ouro::ui::view::tokens(999), "999");
}
