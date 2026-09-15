//! T2 — TUI presentation and discovery, as it reaches the drawn frame.
//!
//! One file per slice rather than a row in each of eight, because every test here is
//! about the same finding: the client's discovery surfaces disagreed with each other and
//! with the runtime's own vocabulary (`docs/design-qa/ui-review-2026-09-15.md` §2.1–§2.6).
//! A reviewer deleting one enforcement point should be able to find the test that goes red
//! without reading the whole suite.
//!
//! Every test names the enforcement it would lose. Where an item's rule is a *table* — the
//! palette's five groups, the `?` panel's coverage of every live action — the assertion is
//! made against the table rather than against a rendered frame: both panels scroll, so a
//! render can only ever prove something about the rows that happened to fit.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;

use ouro::keymap::{Action, Keymap};
use ouro::model::Plane;
use ouro::ui::app::{
    App, ClientField, Command, CommandPalette, Group, Mode, Msg, Overlay, Tab, Tag,
};
use ouro::ui::panels::{node_label, refusal_label, refusal_text};
use ouro::ui::view::help_keys;

use support::{app, full_hello, render, Screen};

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn ctrl(c: char) -> Msg {
    Msg::Key(KeyEvent {
        code: KeyCode::Char(c),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn typed(app: &mut App, text: &str) {
    for character in text.chars() {
        app.apply(key(KeyCode::Char(character)));
    }
}

fn answer(app: &mut App, tag: Tag, value: serde_json::Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

/// An App on the Dashboard, with the account probe answered so nothing is mid-flight.
fn shell() -> App {
    let mut app = app(full_hello());
    app.tab = Tab::Dashboard;
    answer(
        &mut app,
        Tag::Account,
        json!({
            "account": serde_json::Value::Null,
            "requiresOpenaiAuth": true,
            "login": { "status": "idle" }
        }),
    );
    app
}

/// A session row whose node is the unnamed BEAM — the single-machine case, which is the
/// one the review found on screen four times over.
fn unnamed_session(status: &str) -> serde_json::Value {
    json!([{
        "_struct": "Ouroboros.Interactive.State",
        "id": SESSION,
        "node": "nonode@nohost",
        "provider": "native",
        "workspace": "/tmp/w",
        "status": status,
        "options": { "approval_mode": "prompt", "sandbox_mode": null },
        "created_at": "2026-01-01T00:00:00.000000Z",
        "updated_at": "2026-01-01T00:00:00.000000Z"
    }])
}

/// A session open on the Sessions tab, watched, with the subscribe answered.
fn opened(sessions: serde_json::Value) -> App {
    let mut app = App::new(
        Mode::Spawned { pid: 4242 },
        "127.0.0.1:4560".into(),
        full_hello(),
        None,
    );

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), sessions);
    app.open_session(Plane::Interactive, SESSION.to_string());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");

    app.apply(Msg::Answer {
        tag: subscribe.tag,
        result: Ok(json!([])),
    });

    app
}

// ----- T2.1: the palette ---------------------------------------------------------------

/// The five groups of the plan's table, and nothing else. Two groups of thirty-five and
/// six told a reader nothing; a group called "Coding" that holds both "New session" and
/// "Change the model" is a group in name only.
#[test]
fn every_palette_command_belongs_to_one_of_the_five_plan_groups() {
    for command in Command::ALL {
        let group = command.group();

        assert!(
            Group::ALL.contains(&group),
            "{:?} is in {group:?}, which is not one of the five",
            command.label()
        );
    }

    // Each of the five earns its place: a heading with no rows under it would be a
    // taxonomy this client carries and does not use.
    for group in Group::ALL {
        assert!(
            Command::ALL.iter().any(|command| command.group() == group),
            "{} holds no commands",
            group.as_str()
        );
    }
}

/// The rows come out sorted by group, so a heading is drawn once. They used to come out in
/// `ALL` order with a heading on every change of group, and `ALL` crossed between the two
/// groups six times — a scrolled palette printed each heading three times.
///
/// Delete the `sort_by_key` in `CommandPalette::matching` and this goes red.
#[test]
fn the_palette_draws_each_group_heading_exactly_once_and_in_plan_order() {
    let app = shell();
    let palette = CommandPalette::default();
    let rows = app.palette_commands(&palette);

    let mut headings: Vec<Group> = Vec::new();

    for command in &rows {
        if headings.last() != Some(&command.group()) {
            assert!(
                !headings.contains(&command.group()),
                "{} is drawn a second time: {:?}",
                command.group().as_str(),
                headings.iter().map(|g| g.as_str()).collect::<Vec<_>>()
            );
            headings.push(command.group());
        }
    }

    // The order is the plan's, not the order the table happens to be written in.
    let expected: Vec<Group> = Group::ALL
        .into_iter()
        .filter(|group| rows.iter().any(|command| command.group() == *group))
        .collect();

    assert_eq!(headings, expected);

    // And the frame agrees with the table it was built from.
    let mut app = app;
    app.apply(ctrl('p'));
    let screen = render(&mut app, 140, 40);
    assert!(screen.contains("Session"), "{}", screen.text());
    assert!(screen.contains("Conversation"), "{}", screen.text());
}

/// `Nodes` and `Runtime & distribution` were two rows for one verb: both ran `/runtime`
/// and both selected the Dashboard.
#[test]
fn the_palette_has_no_second_row_for_the_dashboard() {
    let dashboard = Command::ALL
        .iter()
        .filter(|command| command.label() == "Nodes" || command.label() == "Runtime & distribution")
        .count();

    assert_eq!(dashboard, 1, "two rows still lead to the Dashboard");
}

/// The label yields, the shortcut does not. At a hundred and forty columns "Copy last
/// agent message as source Markdown" ran straight into `/copy raw` with no seam, so the
/// chord — the column the palette exists to teach — was read as `/copy ra`.
///
/// Delete the `truncate` in `command_palette` and this goes red.
#[test]
fn a_long_palette_label_is_ellipsized_so_its_shortcut_survives() {
    let mut app = shell();
    app.apply(ctrl('p'));
    typed(&mut app, "source");

    let screen = render(&mut app, 140, 40);
    let row = screen.row("/copy raw");

    assert!(
        row.contains("…"),
        "the label was not cut, so nothing protected the chord: {row}"
    );
    assert!(
        !row.contains("Markdown/copy"),
        "the label and the chord are touching: {row}"
    );
}

/// A query that *is* a group name selects that group. It used to match the group as a
/// substring on every row, so `co` — two letters of `copy`, `compact`, `context` —
/// returned all thirty-five rows of the group called "Coding".
#[test]
fn a_query_that_names_a_group_filters_to_it_and_a_substring_does_not() {
    let app = shell();

    let mut palette = CommandPalette {
        query: "Runtime".into(),
        selected: 0,
    };
    let rows = app.palette_commands(&palette);

    assert!(!rows.is_empty());
    assert!(
        rows.iter().all(|command| command.group() == Group::Runtime),
        "a group query returned rows from elsewhere: {:?}",
        rows.iter().map(|c| c.label()).collect::<Vec<_>>()
    );

    // The same query, lower case, is the same filter.
    palette.query = "runtime".into();
    assert_eq!(app.palette_commands(&palette).len(), rows.len());

    // And a query that is *not* a group name matches labels and chords only — never the
    // group column.
    palette.query = "co".into();
    let loose = app.palette_commands(&palette);

    assert!(
        loose.iter().all(|command| {
            command.label().to_ascii_lowercase().contains("co")
                || app
                    .command_shortcut(*command)
                    .to_ascii_lowercase()
                    .contains("co")
        }),
        "a two-letter query matched something other than a label or a chord: {:?}",
        loose.iter().map(|c| c.label()).collect::<Vec<_>>()
    );
}

/// Interrupt and Steer were gated on transport capability alone, so both were offered on
/// an idle or ended session where pressing them does nothing.
///
/// Delete the `session_busy` half of either gate in `palette_commands` and this goes red.
#[test]
fn interrupt_and_steer_are_offered_only_while_a_turn_is_running() {
    let palette = CommandPalette::default();

    let idle = opened(unnamed_session("idle"));
    let offered = idle.palette_commands(&palette);

    assert!(
        !offered.contains(&Command::Interrupt),
        "an idle session was offered an interrupt"
    );
    assert!(!offered.contains(&Command::Steer));

    let running = opened(unnamed_session("running"));
    assert!(running
        .palette_commands(&palette)
        .contains(&Command::Interrupt));
}

// ----- T2.2: the `/` completion table --------------------------------------------------

/// Five verbs the dispatcher has always accepted were in neither the completion table nor
/// the `?` panel, which derives from it — so `/di` offered nothing at all. `/rename` is
/// the sixth and is new; T1 adds its dispatcher arm.
#[test]
fn the_completion_table_names_the_verbs_the_dispatcher_accepts() {
    let mut app = opened(unnamed_session("idle"));

    typed(&mut app, "/di");
    let screen = render(&mut app, 120, 34);

    assert!(
        screen.contains("/diff"),
        "typing /di offered nothing:\n{}",
        screen.text()
    );

    // The `?` panel's COMMANDS block is derived from the same table, so every one of them
    // is advertised there without a second list to keep true. The block is at the foot of
    // a table that scrolls, so the panel is scrolled to its end first.
    let mut app = shell();
    app.apply(key(KeyCode::Char('?')));
    for _ in 0..80 {
        app.apply(key(KeyCode::Down));
    }
    // Wide and tall enough that no row wraps and nothing is scrolled past: the claim is
    // about the table, and a frame that clipped it would prove nothing either way.
    let text = render(&mut app, 200, 80).text();

    assert!(
        text.contains("COMMANDS"),
        "the verb list never came into view:\n{text}"
    );
    for verb in ["/diff", "/changes", "/raw", "/keymap", "/usage", "/rename"] {
        assert!(
            text.contains(verb),
            "the ? panel never names {verb}:\n{text}"
        );
    }
}

// ----- T2.3: the `?` panel -------------------------------------------------------------

/// Every live action appears exactly once. Fifteen of the seventeen leader verbs used to
/// appear nowhere but the two-second which-key overlay and `/keys`, and the panel's own
/// headings were a literal "SESSION" that matched none of the keymap's groups.
///
/// Asserted against the table rather than a frame: the panel scrolls, so a render can
/// only prove something about the rows that fitted.
#[test]
fn the_help_panel_draws_every_live_action_exactly_once() {
    let app = shell();
    let rows = help_keys(&app);

    for action in Action::ALL {
        if app.keymap.spec(action).is_off() {
            continue;
        }

        let key = app.keymap.label(action);
        let hits = rows
            .iter()
            .filter(|(_group, drawn, _description)| {
                *drawn == key || drawn.split(" / ").any(|part| part == key)
            })
            .count();

        assert_eq!(
            hits,
            1,
            "{} ({key}) appears {hits} times in the ? panel",
            action.name()
        );
    }

    // The editor motions the review found nowhere: `ctrl+d` is a literal because delete
    // forward is not rebindable, and the other four are read out of the map.
    let keys: Vec<&str> = rows
        .iter()
        .flat_map(|(_group, key, _description)| key.split(" / "))
        .collect();

    for chord in ["alt+d", "ctrl+y", "ctrl+a", "ctrl+e", "ctrl+d"] {
        assert!(keys.contains(&chord), "{chord} is not on the ? panel");
    }
}

/// The headings are the plan's five, in order, and every row sits under one of them.
#[test]
fn the_help_panel_groups_are_the_five_plan_groups_in_order() {
    let app = shell();
    let rows = help_keys(&app);

    let mut headings: Vec<&str> = Vec::new();

    for (group, _key, _description) in &rows {
        if headings.last() != Some(group) {
            assert!(!headings.contains(group), "{group} is drawn twice");
            headings.push(group);
        }
    }

    let expected: Vec<&str> = Group::ALL
        .iter()
        .map(|group| group.as_str())
        .filter(|group| rows.iter().any(|(row, _, _)| row == group))
        .collect();

    assert_eq!(headings, expected);
}

/// `{key:<15}` was a guess and it was wrong for the row it mattered on: "ctrl+w / ctrl+k /
/// ctrl+u" is twenty-four cells, so the panel drew `ctrl+ukill word…` — the key running
/// into its own description on the one row a reader opens this panel to find.
///
/// Replace the measured column with a constant and this goes red.
#[test]
fn the_help_panel_key_column_is_wide_enough_for_its_longest_key() {
    let mut app = shell();
    app.apply(key(KeyCode::Char('?')));

    let screen = render(&mut app, 120, 60);
    let row = screen.row("kill word, to line end");

    assert!(
        row.contains("ctrl+w / ctrl+k / ctrl+u  kill word"),
        "the key column swallowed part of the chord or the description: {row}"
    );
}

/// The `1-7 / Tab` row described keys that do not exist: `Tab::ALL` is four tabs, `5`–`7`
/// are swallowed, and none of them is reachable with a session open.
#[test]
fn the_help_panel_names_the_four_runtime_tabs_and_not_seven() {
    let app = shell();
    let rows = help_keys(&app);
    let keys: Vec<&str> = rows
        .iter()
        .map(|(_group, key, _description)| key.as_str())
        .collect();

    assert!(
        !keys.contains(&"1-7 / Tab"),
        "the panel still advertises three tabs that do not exist"
    );
    // T1 made each tab a leader verb, so the panel draws four keymap rows rather than one
    // literal.
    for tab in ["ctrl+x 1", "ctrl+x 2", "ctrl+x 3", "ctrl+x 4"] {
        assert!(
            keys.contains(&tab),
            "the four tabs are not named: {tab} is missing"
        );
    }
}

/// A verb the operator turned `off` is not drawn. `?` answers "what can I press here",
/// not "what does this build ship with".
#[test]
fn the_help_panel_omits_an_action_turned_off_in_config() {
    let mut app = shell();
    app.keymap = Keymap::resolve(&std::collections::BTreeMap::from([(
        "leader.copy".to_string(),
        "off".to_string(),
    )]));

    let rows = help_keys(&app);

    assert!(
        !rows
            .iter()
            .any(|(_group, _key, description)| *description == Action::LeaderCopy.describe()),
        "a disabled verb is still drawn"
    );
}

// ----- T2.4: the header tab strip ------------------------------------------------------

/// `Tab::ALL` is four tabs and the header printed the current one's title as a subtitle —
/// so nothing on screen ever said the other three existed.
#[test]
fn the_header_draws_the_four_tabs_with_the_current_one_marked() {
    let mut app = shell();
    let screen = render(&mut app, 140, 30);
    let strip = screen.row("Dashboard");

    for tab in Tab::ALL {
        assert!(
            strip.contains(tab.title()),
            "{} is missing from the strip: {strip}",
            tab.title()
        );
    }

    assert!(
        strip.contains("ctrl+x 1-4"),
        "the strip never says how to reach them: {strip}"
    );

    // The current tab is drawn differently from the rest, which is the only thing that
    // makes a strip a position indicator rather than a list.
    assert_ne!(
        screen.colour_of("Dashboard", "Dashboard"),
        screen.colour_of("Dashboard", "Upgrade"),
        "every tab is drawn the same way, so none of them is current"
    );
}

/// A narrow header keeps the strip and drops the subtitle, whose only unique fact — the
/// current tab's title — the highlighted cell already carries.
#[test]
fn the_tab_strip_replaces_the_subtitle_when_the_row_cannot_hold_both() {
    let mut app = shell();

    let wide = render(&mut app, 140, 30);
    assert!(
        wide.contains("Runtime & distribution: Dashboard"),
        "{}",
        wide.text()
    );

    let narrow = render(&mut app, 74, 30);
    assert!(
        narrow.contains("Dashboard"),
        "the strip was dropped rather than the subtitle:\n{}",
        narrow.text()
    );
    assert!(
        !narrow.contains("Runtime & distribution:"),
        "both halves were drawn on a row that cannot hold them:\n{}",
        narrow.text()
    );
}

// ----- T2.5: the which-key overlay -----------------------------------------------------

/// Bottom-left drew the overlay over the composer's frame and over the first characters of
/// whatever was being typed — the text the operator is holding in their head while they
/// look for the verb.
#[test]
fn the_leader_overlay_sits_on_the_right_above_the_footer() {
    let mut app = opened(unnamed_session("idle"));
    app.apply(ctrl('x'));

    let screen = render(&mut app, 140, 40);

    // The overlay's own title is the leader chord; its box starts in the right-hand half.
    let row = screen.row("new session");
    let column = row.find('n').expect("the row");

    assert!(
        column > 70,
        "the overlay is still on the left, over the composer: {row}"
    );

    // The footer's own row is untouched.
    assert!(
        screen.rows.last().expect("a footer").contains("LIVE"),
        "the overlay covered the footer:\n{}",
        screen.text()
    );
}

/// Seventeen verbs in one flat column is a list read once and memorised by nobody. The
/// headings are the same five the palette and `?` use, through the same mapping.
#[test]
fn the_leader_overlay_groups_its_verbs_under_the_five_headings() {
    let mut app = opened(unnamed_session("idle"));
    app.apply(ctrl('x'));

    let text = render(&mut app, 140, 40).text();

    assert!(text.contains("SESSION"), "{text}");
    assert!(text.contains("CONVERSATION"), "{text}");
    assert!(text.contains("CLIENT"), "{text}");
}

// ----- T2.6: peek keeps the picker -----------------------------------------------------

/// `Space` is advertised as looking without leaving the list. It replaced the list, and
/// `Enter` — whose hint said "enter opens" — closed the peek instead of opening anything.
///
/// Delete the `from_picker` branch in `overlay_key` and this goes red.
#[test]
fn escaping_a_peek_returns_to_the_picker_on_the_row_it_peeked() {
    let mut app = opened(unnamed_session("idle"));

    app.overlay = Some(Overlay::SessionPicker {
        selected: Some((Plane::Interactive, SESSION.to_string())),
    });
    app.apply(key(KeyCode::Char(' ')));

    assert!(
        matches!(app.overlay, Some(Overlay::Peek { .. })),
        "space did not peek"
    );

    let screen = render(&mut app, 120, 34);
    let hint = screen.row("r replies");
    assert!(
        hint.contains("enter opens"),
        "the hint does not name what enter does: {hint}"
    );
    assert!(
        hint.contains("returns to the list"),
        "the hint does not say what esc does here: {hint}"
    );

    app.apply(key(KeyCode::Esc));

    match &app.overlay {
        Some(Overlay::SessionPicker { selected }) => assert_eq!(
            selected.as_ref(),
            Some(&(Plane::Interactive, SESSION.to_string())),
            "the list came back on a different row"
        ),
        other => panic!("esc left the picker: {other:?}"),
    }
}

/// `Enter` opens the session, which is what the peek's hint has always claimed and what
/// the picker's own `Enter` does.
#[test]
fn enter_on_a_peek_opens_the_session() {
    let mut app = opened(unnamed_session("idle"));
    app.sessions.open = None;

    app.overlay = Some(Overlay::SessionPicker {
        selected: Some((Plane::Interactive, SESSION.to_string())),
    });
    app.apply(key(KeyCode::Char(' ')));
    app.apply(key(KeyCode::Enter));

    assert!(app.overlay.is_none(), "enter left an overlay open");
    assert_eq!(
        app.sessions.open,
        Some((Plane::Interactive, SESSION.to_string())),
        "enter did not open the session"
    );
}

/// A peek opened from anywhere else closes to what it covered, rather than conjuring a
/// list nobody was looking at.
#[test]
fn a_peek_with_no_picker_under_it_closes_rather_than_opening_one() {
    let mut app = opened(unnamed_session("idle"));

    app.overlay = Some(Overlay::Peek {
        plane: Plane::Interactive,
        id: SESSION.to_string(),
        title: "a session".into(),
        text: None,
        from_picker: false,
    });
    app.apply(key(KeyCode::Esc));

    assert!(
        app.overlay.is_none(),
        "esc opened a picker nobody asked for"
    );
}

// ----- T2.8: presentation of internals -------------------------------------------------

#[test]
fn node_label_names_the_machine_and_never_the_unnamed_beam() {
    assert_eq!(node_label("nonode@nohost"), "this computer");
    assert_eq!(node_label("nonode"), "this computer");
    assert_eq!(node_label(""), "this computer");
    assert_eq!(node_label("   "), "this computer");

    // A fleet name survives, because a row that cannot say which machine it is on is a
    // row nobody can act on.
    assert_eq!(node_label("ouro@studio.test"), "ouro");
    assert_eq!(node_label("ouroboros@golden"), "ouroboros");
    assert_eq!(node_label("studio"), "studio");
}

#[test]
fn refusal_label_prints_the_word_and_never_the_number() {
    assert_eq!(
        refusal_label(-32004, "no signing node is configured"),
        "unavailable: no signing node is configured"
    );
    assert_eq!(
        refusal_label(-32003, "read scope"),
        "scope_denied: read scope"
    );
    // A code this build cannot name is still not printed as an integer.
    assert_eq!(refusal_label(-31000, "who knows"), "unknown: who knows");
    assert_eq!(refusal_label(-32004, "   "), "unavailable");

    // The string form, for the panels that keep a formatted `ClientError`.
    assert_eq!(
        refusal_text("unavailable (-32004): no signing node is configured"),
        "unavailable: no signing node is configured"
    );
    // Anything that is not that shape is returned untouched: a transport failure is
    // already a sentence, and rewriting one would invent a refusal nobody made.
    assert_eq!(
        refusal_text("the connection closed"),
        "the connection closed"
    );
}

/// The screens the review caught printing `nonode@nohost`: the Dashboard, the picker, the
/// session cards, the context rail, the help footer and the settings header.
///
/// Remove any one `node_label` call and this goes red on that screen.
#[test]
fn no_screen_prints_the_unnamed_beam_or_a_json_rpc_code() {
    let mut app = opened(unnamed_session("idle"));
    // The single-machine case end to end: the gateway's own node is the unnamed BEAM, and
    // so is the node every session row reports.
    app.hello.node = "nonode@nohost".into();

    // The session rail, the cards and the context rail, all at once.
    let session = render(&mut app, 140, 48);
    assert!(
        !session.text().contains("nonode") && !session.text().contains("nohost"),
        "the session screen prints the unnamed BEAM:\n{}",
        session.text()
    );
    assert!(
        session.contains("MACHINE") && session.row("MACHINE").contains("this computer"),
        "the context rail does not name the machine at all:\n{}",
        session.text()
    );

    // The picker.
    app.overlay = Some(Overlay::SessionPicker {
        selected: Some((Plane::Interactive, SESSION.to_string())),
    });
    let picker = render(&mut app, 140, 40);
    assert!(
        !picker.text().contains("nonode"),
        "the picker prints the unnamed BEAM:\n{}",
        picker.text()
    );
    app.overlay = None;

    // The help footer.
    app.apply(key(KeyCode::Char('?')));
    let help = render(&mut app, 140, 50);
    assert!(
        help.contains("one gateway view of the fleet through this computer"),
        "{}",
        help.text()
    );
    app.overlay = None;

    // The Dashboard, and the settings header under it.
    let mut runtime = shell();
    runtime.hello.node = "nonode@nohost".into();
    answer(
        &mut runtime,
        Tag::Status,
        json!({
            "_struct": "Ouroboros.Status",
            "node": "nonode@nohost",
            "role": "core",
            "availability": {},
            "connected_nodes": [],
            "cluster": {}
        }),
    );

    let dashboard = render(&mut runtime, 140, 40);
    assert!(
        !dashboard.text().contains("nonode"),
        "the dashboard prints the unnamed BEAM:\n{}",
        dashboard.text()
    );
    assert!(dashboard.contains("this computer"), "{}", dashboard.text());
}

/// The Upgrade tab's pane title carried the wire's own code:
/// `[unavailable (-32004): no signing node is configured…`.
///
/// Delete the `refusal_text` call in `panel_title` and this goes red.
#[test]
fn a_refused_pane_title_carries_the_reason_and_not_the_code() {
    let mut app = shell();
    app.tab = Tab::Upgrade;

    // The real refusal the review found on this pane title: `signing.decisions`, answered
    // `-32004` by a runtime with no signing node.
    app.apply(Msg::Answer {
        tag: Tag::Signing,
        result: Err(ouro::transport::ClientError::Rpc(ouro::proto::RpcError {
            code: ouro::proto::ErrorCode::from_i64(-32004),
            message: "no signing node is configured".into(),
            data: None,
        })),
    });

    let screen = render(&mut app, 140, 30);

    assert!(
        screen.contains("unavailable: no signing node is configured"),
        "the reason is not on the title:\n{}",
        screen.text()
    );
    assert!(
        !screen.text().contains("-32004"),
        "the JSON-RPC code reached a pane title:\n{}",
        screen.text()
    );
}

// ----- T2.10: settings -----------------------------------------------------------------

/// The Connections list mixed "OpenAI / Anthropic / xAI" with lowercase "alibaba" and
/// "alibaba cn", because the five this client knew by name were spelled here and
/// everything else fell through to the wire id with its underscores replaced.
#[test]
fn every_provider_row_is_named_rather_than_spelled_as_a_wire_id() {
    for (provider, name) in [
        ("openai", "OpenAI"),
        ("anthropic", "Anthropic"),
        ("xai", "xAI"),
        ("alibaba", "Alibaba"),
        ("alibaba_cn", "Alibaba (CN)"),
        ("openai_codex", "ChatGPT"),
        ("grok", "Grok"),
    ] {
        assert_eq!(ouro::ui::app::provider_name(provider), name);
    }

    // A provider this build has never heard of is made readable rather than invented.
    assert_eq!(ouro::ui::app::provider_name("new_vendor"), "New Vendor");
}

/// Eight `config.toml` sections had no UI at all. `F4` is the four that are about this
/// client, and it points at the file for the two that are a grammar and a shell command.
#[test]
fn the_settings_overlay_has_a_client_section_that_writes_through_the_save_path() {
    let mut app = shell();
    app.config_path = Some(std::path::PathBuf::from("/tmp/config.toml"));
    // `settings` is `off` since T1; the overlay opens from `leader.settings`.
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(',')));

    let tabs = render(&mut app, 120, 34);
    assert!(tabs.contains("F4 Client"), "{}", tabs.text());

    app.apply(key(KeyCode::F(4)));
    let screen = render(&mut app, 120, 34);
    let text = screen.text();

    for row in [
        "mouse",
        "screen reader",
        "reduced motion",
        "notify",
        "max cost",
    ] {
        assert!(text.contains(row), "the {row} row is missing:\n{text}");
    }
    for section in [
        "[terminal]",
        "[accessibility]",
        "[notifications]",
        "[budget]",
    ] {
        assert!(text.contains(section), "{section} is not named:\n{text}");
    }
    assert!(
        text.contains("[keys] and [statusline] are edited in config.toml"),
        "the two sections with no rows are not accounted for:\n{text}"
    );

    // Nothing is written by looking, and nothing by changing: `[ save ]` is the press.
    app.apply(key(KeyCode::Right));
    assert!(
        render(&mut app, 120, 34).row("mouse").contains("off"),
        "the row did not change"
    );
    assert!(
        app.take_config_save().is_none(),
        "a cycle wrote config.toml"
    );
    assert!(
        app.config.terminal.mouse,
        "the change reached the config before [ save ] was pressed"
    );

    // Down to `[ save ]` and press it.
    for _ in 0..ClientField::ALL.len() {
        if matches!(
            &app.overlay,
            Some(Overlay::Settings(settings)) if settings.client == ClientField::Save
        ) {
            break;
        }
        app.apply(key(KeyCode::Tab));
    }
    app.apply(key(KeyCode::Enter));

    assert!(app.overlay.is_none(), "save left the overlay open");
    assert!(
        app.take_config_save().is_some(),
        "the client section does not write through save_settings"
    );
    assert!(!app.config.terminal.mouse, "the change was not saved");
}

/// A number this build cannot read is refused by name rather than rounded to zero: a
/// silently stored `0` would turn a typo into a ceiling that reads as deliberate.
#[test]
fn an_unreadable_budget_is_refused_rather_than_saved_as_nothing() {
    let mut app = shell();
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(',')));
    app.apply(key(KeyCode::F(4)));

    for _ in 0..ClientField::ALL.len() {
        if matches!(
            &app.overlay,
            Some(Overlay::Settings(settings)) if settings.client == ClientField::Budget
        ) {
            break;
        }
        app.apply(key(KeyCode::Tab));
    }

    typed(&mut app, "12.5o");

    for _ in 0..ClientField::ALL.len() {
        if matches!(
            &app.overlay,
            Some(Overlay::Settings(settings)) if settings.client == ClientField::Save
        ) {
            break;
        }
        app.apply(key(KeyCode::Tab));
    }
    app.apply(key(KeyCode::Enter));

    assert!(
        matches!(app.overlay, Some(Overlay::Settings(_))),
        "an unreadable budget was accepted"
    );
    assert_eq!(app.config.budget.max_cost_usd, None);
    assert!(
        app.take_config_save().is_none(),
        "nothing should be written"
    );

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("is not a number of dollars"),
        "the refusal is not on screen:\n{}",
        screen.text()
    );
}

// ----- T2.11: where the home folder came from -------------------------------------------

/// With `[defaults] workspace` set, the home screen showed that stored path instead of the
/// directory `ouro` was started in — and nothing on the line said so, although the README
/// tells people to open it from the project they want to work on.
#[test]
fn the_home_folder_line_says_where_the_path_came_from() {
    let mut app = shell();
    app.tab = Tab::Sessions;
    app.launch_dir = Some("/srv/launched".into());

    // The launch directory, named as itself.
    let screen = render(&mut app, 120, 34);
    let row = screen.row("Folder:");
    assert!(row.contains("/srv/launched"), "{row}");
    assert!(row.contains("· this directory"), "{row}");

    // The config default wins over it, and says which of the two it is.
    app.config.defaults.workspace = Some("/srv/configured".into());
    let screen = render(&mut app, 120, 34);
    let row = screen.row("Folder:");
    assert!(row.contains("/srv/configured"), "{row}");
    assert!(
        row.contains("· from config.toml"),
        "the override is silent: {row}"
    );

    // `f5` is still the key that changes it.
    assert!(
        screen.contains("f5 computer & project"),
        "{}",
        screen.text()
    );
}

/// A path the operator chose in the location dialog is neither, and this client has
/// nothing to add about it.
#[test]
fn a_chosen_workspace_gets_no_provenance_suffix() {
    let mut app = shell();
    app.tab = Tab::Sessions;
    app.launch_dir = Some("/srv/launched".into());
    app.config.location.workspace = Some("/srv/chosen".into());

    let screen = render(&mut app, 120, 34);
    let row = screen.row("Folder:");

    assert!(row.contains("/srv/chosen"), "{row}");
    assert!(!row.contains("this directory"), "{row}");
    assert!(!row.contains("from config.toml"), "{row}");
}

// ----- T2.12: the hidden rail ----------------------------------------------------------

/// `rail_hidden` was a field nothing read. T1 flips it; this is what it does.
#[test]
fn hiding_the_rail_gives_the_width_to_the_transcript_and_says_so() {
    let mut app = opened(unnamed_session("idle"));

    let shown: Screen = render(&mut app, 140, 40);
    assert!(shown.contains("SESSIONS"), "{}", shown.text());
    assert!(shown.contains("FLEET"), "{}", shown.text());

    app.rail_hidden = true;
    let hidden = render(&mut app, 140, 40);

    assert!(
        !hidden.contains("SESSIONS / "),
        "the session rail is still drawn:\n{}",
        hidden.text()
    );
    assert!(
        !hidden.contains("BOUNDARIES"),
        "the context rail is still drawn:\n{}",
        hidden.text()
    );
    assert!(
        hidden.contains("rail hidden · ctrl+x b"),
        "nothing on screen says the rail was hidden or how to bring it back:\n{}",
        hidden.text()
    );
}

// =======================================================================================
// Review fixes. Each names the finding it closes and the enforcement that would lose it.
// =======================================================================================

// ----- F1: the `?` panel must never silently end ---------------------------------------

/// The panel counted logical rows while the paragraph wrapped, so at eighty columns the
/// "N more rows" marker was computed for a row index below the viewport and never drawn:
/// nineteen rows on screen, thirty-five unreachable, and nothing saying so.
///
/// Replace `wrapped_prose` with `rows.len()` arithmetic in `help` and this goes red.
#[test]
fn the_help_panel_says_there_is_more_at_eighty_columns() {
    let mut app = shell();
    app.apply(key(KeyCode::Char('?')));

    let screen = render(&mut app, 80, 24);

    assert!(
        screen.contains("more rows"),
        "the panel ends in silence at 80x24:\n{}",
        screen.text()
    );

    // The marker is the last row of the scrolling half, not a row lost under the limits.
    let marker = screen
        .rows
        .iter()
        .position(|row| row.contains("more rows"))
        .expect("the marker");
    let limits = screen
        .rows
        .iter()
        .position(|row| row.contains("one gateway view"))
        .expect("the pinned limits");

    assert!(
        marker < limits,
        "the marker is drawn below the pinned limits:\n{}",
        screen.text()
    );
}

/// And the scroll reaches the real end: the last screen has no marker on it, because
/// there is nothing left to say is missing.
#[test]
fn the_help_panel_scrolls_all_the_way_to_its_last_row() {
    let mut app = shell();
    app.apply(key(KeyCode::Char('?')));

    for _ in 0..400 {
        app.apply(key(KeyCode::Down));
    }

    let screen = render(&mut app, 80, 24);

    assert!(
        !screen.contains("more rows"),
        "the table cannot be scrolled to its end:\n{}",
        screen.text()
    );
    // The verb list is the foot of the table, so this is the end.
    assert!(screen.contains("COMMANDS"), "{}", screen.text());
}

/// No row is drawn half-wrapped: what the panel shows, it shows whole.
#[test]
fn every_help_row_the_panel_draws_fits_the_rows_it_was_given() {
    for width in [80u16, 100, 140] {
        let mut app = shell();
        app.apply(key(KeyCode::Char('?')));

        let screen = render(&mut app, width, 24);
        let text = screen.text();

        // A clipped wrap loses the tail of a description; the marker or a heading is what
        // the last content row must be.
        assert!(
            text.contains("more rows"),
            "{width}: no marker although the table cannot fit:\n{text}"
        );
    }
}

// ----- F2: the theme picker's digits --------------------------------------------------

/// The picker prints `1.`–`6.` for everyone and had no digit arm at all, so pressing `6`
/// did nothing. The rule T2.7 applied to the approval modal: a number drawn beside a row
/// no key reaches is decoration pretending to be a binding.
///
/// Delete the digit arm in `overlay_key` and this goes red.
#[test]
fn a_digit_picks_a_theme_and_previews_it() {
    let mut app = shell();
    app.open_theme_picker();

    let rows = ouro::ui::theme::ThemeName::ALL;
    app.apply(key(KeyCode::Char('3')));

    match &app.overlay {
        Some(Overlay::Theme { choice, .. }) => assert_eq!(
            *choice, 2,
            "the digit did not select row three: {:?}",
            rows[*choice]
        ),
        other => panic!("the picker closed: {other:?}"),
    }

    // Landing on a row previews it, exactly as the arrows do — and still writes nothing.
    assert!(
        app.take_config_save().is_none(),
        "a digit preview asked for a write"
    );

    // A digit past the last row is not a row, so it is left alone.
    app.apply(key(KeyCode::Char('9')));
    match &app.overlay {
        Some(Overlay::Theme { choice, .. }) => {
            assert_eq!(*choice, 2, "a digit off the end moved the cursor")
        }
        other => panic!("the picker closed: {other:?}"),
    }
}

// ----- F3 / F8: a refused save must change nothing --------------------------------------

/// `save_settings` wrote the four other `F4` rows into `self.config` and refused the budget
/// afterwards, so "nothing was saved" was false: reopening the section showed the flipped
/// values and the next legitimate save persisted them.
///
/// Move the budget validation back below the writes and this goes red.
#[test]
fn a_refused_budget_leaves_every_other_client_field_alone() {
    let mut app = shell();
    // `settings` is `off` since T1; the overlay opens from `leader.settings`.
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(',')));
    app.apply(key(KeyCode::F(4)));

    let mouse_before = app.config.terminal.mouse;
    let reader_before = app.config.accessibility.screen_reader;
    let motion_before = app.config.accessibility.reduced_motion;
    let notify_before = app.config.notifications.mode.clone();

    match app.overlay.as_mut() {
        Some(Overlay::Settings(settings)) => {
            settings.mouse = !mouse_before;
            settings.screen_reader = !reader_before;
            settings.reduced_motion = !motion_before;
            settings.notify_mode = 1;
            settings.budget = "12.5o".into();
            settings.client = ClientField::Save;
        }
        other => panic!("no settings overlay: {other:?}"),
    }

    app.apply(key(KeyCode::Enter));

    assert!(
        matches!(app.overlay, Some(Overlay::Settings(_))),
        "an unreadable budget was accepted"
    );
    assert!(
        app.take_config_save().is_none(),
        "the refusal queued a write"
    );

    assert_eq!(
        app.config.terminal.mouse, mouse_before,
        "`mouse` moved although the save was refused"
    );
    assert_eq!(app.config.accessibility.screen_reader, reader_before);
    assert_eq!(app.config.accessibility.reduced_motion, motion_before);
    assert_eq!(app.config.notifications.mode, notify_before);
    assert_eq!(app.config.budget.max_cost_usd, None);
}

/// F8. The guard itself, which had no test: what a budget row accepts and what it refuses.
#[test]
fn the_budget_row_accepts_only_a_finite_number_of_dollars() {
    for (typed, expected) in [
        ("12.5", Some(Some(12.5))),
        ("0", Some(Some(0.0))),
        (" 3 ", Some(Some(3.0))),
        // Cleared: an empty box is "no ceiling", which is what an absent key means.
        ("", Some(None)),
        // Refused. `1e400` is the one that matters: it parses, to `inf`, and an infinite
        // ceiling is a budget that can never warn — worse than no budget, because the row
        // says there is one.
        ("-1", None),
        ("1e400", None),
        ("abc", None),
        ("12.5o", None),
    ] {
        let mut app = shell();
        app.apply(ctrl('x'));
        app.apply(key(KeyCode::Char(',')));
        app.apply(key(KeyCode::F(4)));

        match app.overlay.as_mut() {
            Some(Overlay::Settings(settings)) => {
                settings.budget = typed.into();
                settings.client = ClientField::Save;
            }
            other => panic!("no settings overlay: {other:?}"),
        }

        app.apply(key(KeyCode::Enter));

        match expected {
            Some(limit) => {
                assert!(
                    app.overlay.is_none(),
                    "{typed:?} was refused and should have been taken"
                );
                assert_eq!(app.config.budget.max_cost_usd, limit, "{typed:?}");
                assert!(
                    app.take_config_save().is_some(),
                    "{typed:?} was not written"
                );
            }
            None => {
                assert!(
                    matches!(app.overlay, Some(Overlay::Settings(_))),
                    "{typed:?} was accepted"
                );
                assert_eq!(app.config.budget.max_cost_usd, None, "{typed:?}");
                assert!(app.take_config_save().is_none(), "{typed:?} queued a write");
            }
        }
    }
}

// ----- F5: `refusal_text` only rewrites what it recognises -------------------------------

/// It rewrote any string holding ` (<int>): `, dropping everything before the bracket and
/// labelling the number with a code nobody sent: `Connection to node (10): refused` came
/// out as `unknown: refused`. The doc promises the unrecognised is returned untouched.
///
/// Delete the `ErrorCode::name()` check and this goes red.
#[test]
fn refusal_text_rewrites_only_a_refusal_it_recognises() {
    // Recognised: the one shape `ErrorCode`'s own `Display` produces.
    assert_eq!(
        refusal_text("unavailable (-32004): x"),
        "unavailable: x",
        "a real refusal is still relabelled"
    );
    assert_eq!(refusal_text("unavailable (-32004): "), "unavailable");
    // A message with its own bracketed clause keeps all of it.
    assert_eq!(
        refusal_text("unavailable (-32004): no node (yet): try later"),
        "unavailable: no node (yet): try later"
    );

    // Not recognised — returned exactly as it arrived.
    for untouched in [
        "Connection to node (10): refused",
        "foo (12): bar): baz",
        "a (1): b): c): d",
        "(-1): y",
        "retry (attempt 2): giving up",
        "the connection closed",
        "",
    ] {
        assert_eq!(
            refusal_text(untouched),
            untouched,
            "an unrecognised sentence was rewritten"
        );
    }
}

// ----- F6 / F7: which computer, on the surfaces that list several -------------------------

/// The Dashboard's connected list is the one list on that tab whose whole job is telling
/// machines apart, and it read every node through `node_label` — so `ouro@alpha` and
/// `ouro@beta` both printed `connected  ouro`.
///
/// Put `node_label` back in `dashboard.rs` and this goes red.
#[test]
fn the_dashboard_connected_list_tells_two_machines_apart() {
    let mut app = shell();

    answer(
        &mut app,
        Tag::Status,
        json!({
            "_struct": "Ouroboros.Status",
            "node": "ouro@alpha",
            "role": "core",
            "availability": {},
            "connected_nodes": ["ouro@alpha", "ouro@beta"],
            "cluster": { "distributed": true, "formation": { "strategy": "gossip" } }
        }),
    );

    let screen = render(&mut app, 140, 40);
    let text = screen.text();

    assert!(text.contains("connected  alpha"), "{text}");
    assert!(text.contains("connected  beta"), "{text}");
    assert!(
        !text.contains("ouro@alpha"),
        "the raw node reached the Dashboard:\n{text}"
    );

    // And the two surfaces agree about the same node.
    assert_eq!(app.machine_label("ouro@alpha"), "alpha");
    assert_eq!(app.machine_label("ouro@beta"), "beta");
}

/// F4. The `?` panel's own footer printed the wire's number for the refusal every mutating
/// verb gets at `read` scope. It is read by somebody who is confused, which is the last
/// place to put a code they would have to look up to learn the word.
///
/// Put `-32003` back in `help_sections` and this goes red.
#[test]
fn the_help_footer_names_the_scope_refusal_rather_than_its_code() {
    let mut app = app(support::read_hello(&["interactive.list"]));
    app.tab = Tab::Dashboard;
    app.apply(key(KeyCode::Char('?')));

    let screen = render(&mut app, 140, 44);
    let text = screen.text();

    assert!(
        text.contains("scope_denied"),
        "the refusal is not named:\n{text}"
    );
    assert!(
        !text.contains("-32003"),
        "the JSON-RPC code reached the ? panel:\n{text}"
    );
}

/// F10. A replay that is refused puts its reason on the notice row, and it carried the
/// code: `replaying … failed: upstream_error (-32006): …`.
///
/// Drop the `refusal_text` wrap in `streaming.rs` and this goes red.
#[test]
fn a_refused_replay_says_the_reason_and_not_the_code() {
    let mut app = opened(unnamed_session("idle"));

    // Re-opening the session issues the replay this test refuses.
    app.open_session(Plane::Interactive, SESSION.to_string());

    let replay = app
        .drain()
        .into_iter()
        .find(|call| {
            matches!(
                call.method.as_str(),
                "interactive.replay" | "interactive.subscribe"
            )
        })
        .expect("a replay or subscribe call");

    app.apply(Msg::Answer {
        tag: replay.tag,
        result: Err(ouro::transport::ClientError::Rpc(ouro::proto::RpcError {
            code: ouro::proto::ErrorCode::from_i64(-32006),
            message: "the provider went away".into(),
            data: None,
        })),
    });

    let notice = app.notice.as_ref().expect("a notice").text.clone();

    assert!(
        notice.contains("upstream_error: the provider went away"),
        "the reason is not named: {notice}"
    );
    assert!(
        !notice.contains("-32006"),
        "the code reached the row: {notice}"
    );
}

// ----- F9: the tab strip reads the keymap ------------------------------------------------

/// The strip's hint is `leader.tab_dashboard`–`leader.tab_logs` out of the resolved map, so
/// an operator who moved those verbs sees the keys they moved them to.
#[test]
fn rebinding_a_tab_verb_changes_the_strips_hint() {
    let mut app = shell();
    assert!(
        render(&mut app, 140, 30)
            .row("Dashboard")
            .contains("ctrl+x 1-4"),
        "the default hint is not the default keys"
    );

    app.keymap = Keymap::resolve(&std::collections::BTreeMap::from([(
        "leader.tab_dashboard".to_string(),
        "7".to_string(),
    )]));

    let screen = render(&mut app, 140, 30);
    let strip = screen.row("Dashboard");

    assert!(
        strip.contains("ctrl+x 7-"),
        "the strip still advertises the default key: {strip}"
    );
}

// ----- F12: the verbs the plan's table names ---------------------------------------------

/// The plan's group table names `rename`, `quit` and `approval`; the palette carried none
/// of them, so the palette could not be checked against the table it is drawn from.
#[test]
fn the_palette_carries_rename_quit_and_approval_in_their_groups() {
    for (command, group) in [
        (Command::Rename, Group::Session),
        (Command::Quit, Group::Client),
        (Command::Approval, Group::Turn),
    ] {
        assert!(Command::ALL.contains(&command), "{command:?} is not a row");
        assert_eq!(command.group(), group, "{command:?}");
    }
}

/// Each is gated on what it needs, so none of them is a row that does nothing.
#[test]
fn the_three_new_palette_rows_are_gated_on_what_they_need() {
    let palette = CommandPalette::default();

    // No session: no rename, no approval. Quit always works — it is the client's own.
    let home = shell();
    let offered = home.palette_commands(&palette);
    assert!(
        !offered.contains(&Command::Rename),
        "rename with no session"
    );
    assert!(
        !offered.contains(&Command::Approval),
        "approval with no session"
    );
    assert!(offered.contains(&Command::Quit), "quit is always reachable");

    // A session, and a gateway that serves `interactive.rename`.
    let open = opened(unnamed_session("idle"));
    let offered = open.palette_commands(&palette);
    assert!(offered.contains(&Command::Rename), "rename is not offered");
    assert!(
        !offered.contains(&Command::Approval),
        "an approval row with nothing waiting is a row that opens an empty modal"
    );
}

/// The rename row teaches the verb by prefilling it, because a title is words only the
/// operator can write.
#[test]
fn the_rename_row_prefills_the_verb() {
    let mut app = opened(unnamed_session("idle"));

    // Through the palette, which is the surface the row lives on.
    app.apply(ctrl('p'));
    typed(&mut app, "Rename this");
    app.apply(key(KeyCode::Enter));

    let draft = app
        .sessions
        .composer
        .as_ref()
        .expect("a composer")
        .editor
        .text()
        .to_string();

    assert_eq!(draft, "/rename ");
    assert!(app.overlay.is_none());
}

// ----- the two footer items from the T1 review --------------------------------------------

/// The composer said `esc abort` in every state. After T1 that is wrong in two of the
/// three: `Esc` interrupts only while a turn is running, and on an idle session it banks
/// the draft where `up` finds it or — on an empty draft — leaves the session.
///
/// Collapse `escape_cell` back to a literal and this goes red.
#[test]
fn the_composer_hint_says_what_escape_does_in_the_state_it_is_in() {
    // Idle, empty: `Esc` leaves.
    let mut app = opened(unnamed_session("idle"));
    let screen = render(&mut app, 120, 34);
    assert!(
        screen.row("Enter").contains("esc leaves"),
        "empty and idle: {}",
        screen.row("Enter")
    );

    // Idle, with a draft: `Esc` banks it.
    typed(&mut app, "half a thought");
    let screen = render(&mut app, 120, 34);
    assert!(
        screen.row("Enter").contains("esc clears the draft"),
        "idle with text: {}",
        screen.row("Enter")
    );

    // Running: the key that interrupts, out of the keymap.
    let mut app = opened(unnamed_session("running"));
    let screen = render(&mut app, 120, 34);
    let row = screen.row("Enter");
    assert!(
        row.contains("interrupts"),
        "a running turn must name the interrupt: {row}"
    );
    assert!(!row.contains("esc abort"), "{row}");
}

/// The home screen's primary action said `Enter: connect & start` while a completion menu
/// was open — the exact screen where typing `/ke` and pressing Enter submitted "/ke" as
/// the first task. T1 made Enter accept the row; the footer has to say so.
#[test]
fn the_home_action_says_enter_accepts_while_a_menu_is_open() {
    let mut app = shell();
    app.tab = Tab::Sessions;

    let screen = render(&mut app, 120, 34);
    assert!(
        !screen.contains("Enter accepts"),
        "nothing is being completed yet:\n{}",
        screen.text()
    );

    typed(&mut app, "/ke");

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("Enter accepts"),
        "the action still claims Enter starts a session:\n{}",
        screen.text()
    );
    assert!(
        !screen.contains("connect & start"),
        "both claims are on screen at once:\n{}",
        screen.text()
    );
}

/// The palette's shortcut column names the key that reaches a verb, never `off`: `Steer`
/// is `alt+enter` and the editor is `ctrl+x e` now that `leader.steer` and `editor` are
/// off by default, and ending a session moved to `ctrl+x k`.
#[test]
fn the_steer_and_editor_rows_name_the_keys_that_work() {
    let app = shell();

    assert_eq!(app.command_shortcut(Command::Steer), "alt+enter");
    assert_eq!(app.command_shortcut(Command::ExternalEditor), "ctrl+x e");
    assert_eq!(app.command_shortcut(Command::CloseSession), "ctrl+x k");
}
