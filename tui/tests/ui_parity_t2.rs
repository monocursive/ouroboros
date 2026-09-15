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
use ouro::ui::app::{App, ClientField, Command, CommandPalette, Group, Mode, Msg, Overlay, Tab, Tag};
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
                || app.command_shortcut(*command).to_ascii_lowercase().contains("co")
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

    assert!(text.contains("COMMANDS"), "the verb list never came into view:\n{text}");
    for verb in ["/diff", "/changes", "/raw", "/keymap", "/usage", "/rename"] {
        assert!(text.contains(verb), "the ? panel never names {verb}:\n{text}");
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
        assert!(keys.contains(&tab), "the four tabs are not named: {tab} is missing");
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

    assert!(app.overlay.is_none(), "esc opened a picker nobody asked for");
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
    assert_eq!(refusal_label(-32003, "read scope"), "scope_denied: read scope");
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
    assert_eq!(refusal_text("the connection closed"), "the connection closed");
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

    for row in ["mouse", "screen reader", "reduced motion", "notify", "max cost"] {
        assert!(text.contains(row), "the {row} row is missing:\n{text}");
    }
    for section in ["[terminal]", "[accessibility]", "[notifications]", "[budget]"] {
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
    assert!(app.take_config_save().is_none(), "a cycle wrote config.toml");
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
    assert!(app.take_config_save().is_none(), "nothing should be written");

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
