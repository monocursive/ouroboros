//! B8: every chord this client binds is data, and the map is the only authority on it.
//!
//! Three things are pinned here, and they are the three that make the feature real rather
//! than decorative:
//!
//! 1. **The grammar reads what it documents, and refuses the rest by name.** Every form in
//!    `docs/TUI.md` parses; an unknown action, an unreadable spec, and a collision are each
//!    reported and ignored, never silently applied to something else.
//! 2. **The defaults are exactly what this client bound before `[keys]` existed.** A table
//!    over *every* action, so a default that drifts is a test failure and not a bug report.
//! 3. **A rebound key is what the UI says.** `?`, the footer, the `ctrl+x` overlay, and the
//!    palette all read the map, so the assertion is that all four change together (D14).

mod support;

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::keymap::{Action, Keymap, Scope, Source, Spec};
use ouro::model::Plane;
use ouro::ui::app::{App, Msg, Overlay, Tab, Tag};

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

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn overrides(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, spec)| (name.to_string(), spec.to_string()))
        .collect()
}

#[test]
fn home_starter_hints_and_actions_follow_remapping_and_unbinding() {
    let mut app = configured(&[("starter_explore", "f6"), ("starter_review", "off")]);
    app.open_home();
    let text = render(&mut app, 80, 24).text();
    assert!(text.contains("f6  Understand this project"), "{text}");
    assert!(!text.contains("Review my local changes"), "{text}");
    app.apply(key(KeyCode::F(2)));
    app.apply(key(KeyCode::F(3)));
    assert!(app.home_draft.is_empty());
    app.apply(key(KeyCode::F(6)));
    assert!(app.home_draft.text().contains("Explore this project"));
}

/// An App with the given `[keys]` table already resolved.
fn configured(pairs: &[(&str, &str)]) -> App {
    let mut app = app(full_hello());

    for (name, spec) in pairs {
        if *name == "backtrack" {
            app.config.keys.backtrack = Some((*spec).to_string());
        } else {
            app.config.keys.bindings.insert(
                (*name).to_string(),
                toml::Value::String((*spec).to_string()),
            );
        }
    }

    app.reload_keymap();
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app
}

/// The same App with one open interactive session, so the session surfaces draw.
fn opened(pairs: &[(&str, &str)]) -> App {
    let mut app = configured(pairs);
    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-a7",
            "status": "idle",
            "provider": "native",
            "workspace": "/w",
            "updated_at": "2026-01-01T00:00:00.000000Z",
            "options": { "capabilities": { "transport": "app_server", "interrupt": "native" } },
        }]),
    );
    app.open_session(Plane::Interactive, "session-a7".into());

    if let Some(subscribe) = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
    {
        answer(&mut app, subscribe.tag, json!([]));
    }

    // The composer owns every printable key while it is open, and these tests press `?`.
    app.sessions.composer = None;
    app.apply(Msg::Tick);
    app
}

fn screen(app: &mut App) -> Screen {
    render(app, 120, 40)
}

/// `/keys` lists every action and needs the rows for them; a short terminal scrolls, which
/// its own assertion below covers. Sized off the table so the page cannot outgrow it
/// silently the way it did when the `ui-parity` realignment added fifteen verbs.
fn tall(app: &mut App) -> Screen {
    // Sized off the table rather than typed, so the page cannot outgrow the terminal
    // silently the way it did when the `ui-parity` realignment added fifteen verbs. Wide
    // as well as tall: the popup is a percentage of the terminal and its rows wrap, and a
    // wrapped row costs a line the page's own scroll arithmetic did not count.
    render(app, 200, Action::ALL.len() as u16 + 24)
}

/// Typed into the composer and submitted, which is how an operator reaches a `/` verb.
fn slash(app: &mut App, command: &str) {
    // Enter on an open session with no composer is what opens one.
    if app.sessions.composer.is_none() {
        app.apply(key(KeyCode::Enter));
    }

    for character in command.chars() {
        app.apply(key(KeyCode::Char(character)));
    }

    app.apply(key(KeyCode::Enter));
}

// ---------------------------------------------------------------------------------------
// (1) the grammar
// ---------------------------------------------------------------------------------------

/// Every form `docs/TUI.md` documents, read back as the chord it names.
#[test]
fn the_spec_grammar_reads_every_documented_form() {
    let map = Keymap::resolve(&overrides(&[
        ("verbose", "ctrl+o"),
        ("steer", "alt+enter"),
        ("backtrack", "esc esc"),
        ("leader.details", "ctrl+x d"),
        ("plan_panel", "off"),
        ("help", "f1"),
        ("settings", "alt+shift+s"),
    ]));

    assert!(map.problems().is_empty(), "{:?}", map.problems());
    assert_eq!(map.spec(Action::Verbose).to_string(), "ctrl+o");
    assert_eq!(map.spec(Action::Steer).to_string(), "alt+enter");
    assert_eq!(map.spec(Action::Backtrack).to_string(), "esc esc");
    // Written long, stored short: a leader verb is one key, and the long form is only the
    // way the `?` panel spells it back.
    assert_eq!(map.spec(Action::LeaderDetails).to_string(), "d");
    assert_eq!(map.label(Action::LeaderDetails), "ctrl+x d");
    assert!(map.spec(Action::PlanPanel).is_off());
    assert_eq!(map.spec(Action::Help).to_string(), "f1");
    // `shift` on a letter *is* the letter's case: crossterm reports `Char('S')` on some
    // terminals and `Char('s')` with SHIFT on others, so the modifier normalises away
    // rather than becoming a chord half the field cannot send.
    assert_eq!(map.spec(Action::Settings).to_string(), "alt+s");
}

/// An action this build does not bind is named and skipped. It never lands on something
/// else, and the map it produced is otherwise the map it would have produced anyway.
#[test]
fn an_unknown_action_is_reported_and_the_rest_of_the_file_still_applies() {
    let map = Keymap::resolve(&overrides(&[
        ("telepathy", "ctrl+z"),
        ("verbose", "ctrl+b"),
    ]));

    assert_eq!(map.problems().len(), 1, "{:?}", map.problems());
    assert!(
        map.problems()[0].contains("telepathy") && map.problems()[0].contains("ignored"),
        "{:?}",
        map.problems()
    );
    assert_eq!(map.spec(Action::Verbose).to_string(), "ctrl+b");
}

/// A spec this build cannot read keeps the default *and* says so. It is never turned into
/// `off`: silently disabling a key because a file had a typo in it is the same failure as
/// silently rebinding one.
#[test]
fn an_unreadable_spec_keeps_the_default_and_is_never_turned_off() {
    let map = Keymap::resolve(&overrides(&[
        ("verbose", "hyper+z"),
        ("plan_panel", "esc esc esc"),
    ]));

    assert_eq!(map.problems().len(), 2, "{:?}", map.problems());
    assert_eq!(map.spec(Action::Verbose).to_string(), "ctrl+o");
    assert_eq!(map.spec(Action::PlanPanel).to_string(), "ctrl+t");
    assert!(!map.spec(Action::Verbose).is_off());
    assert!(!map.spec(Action::PlanPanel).is_off());
    assert!(map
        .problems()
        .iter()
        .all(|problem| problem.contains("keeping")));
}

/// Two actions on one key: the later one is reported and ignored, so the map never has a
/// chord whose meaning depends on which handler happens to be checked first.
#[test]
fn a_conflict_is_reported_and_the_later_action_is_ignored() {
    // `verbose` is ctrl+o by default; asking `plan_panel` for it too is the collision.
    let map = Keymap::resolve(&overrides(&[("plan_panel", "ctrl+o")]));

    assert_eq!(map.problems().len(), 1, "{:?}", map.problems());
    assert!(
        map.problems()[0].contains("plan_panel") && map.problems()[0].contains("verbose"),
        "{:?}",
        map.problems()
    );
    assert_eq!(map.spec(Action::Verbose).to_string(), "ctrl+o");
    assert_eq!(map.spec(Action::PlanPanel).to_string(), "ctrl+t");
}

/// Scopes collide separately. `ctrl+k` is a composer motion and nothing global; a leader
/// verb `k` and a global `k` are not the same key to anybody pressing them.
#[test]
fn a_key_shared_across_scopes_is_not_a_conflict() {
    let map = Keymap::resolve(&overrides(&[
        ("leader.copy", "o"),
        ("editor.yank", "ctrl+o"),
    ]));

    assert!(map.problems().is_empty(), "{:?}", map.problems());
    assert_eq!(map.spec(Action::LeaderCopy).to_string(), "o");
    assert_eq!(map.spec(Action::EditorYank).to_string(), "ctrl+o");
}

/// `off` disables, and it disables *only* the action it names.
#[test]
fn off_removes_a_key_and_nothing_else() {
    let map = Keymap::resolve(&overrides(&[("plan_panel", "off"), ("leader.quit", "off")]));

    assert!(map.problems().is_empty(), "{:?}", map.problems());
    assert!(map.spec(Action::PlanPanel).is_off());
    assert!(map.spec(Action::LeaderQuit).is_off());
    assert_eq!(map.label(Action::PlanPanel), "off");
    assert!(!map.hits(
        Action::PlanPanel,
        KeyEvent {
            code: KeyCode::Char('t'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    ));
    // Two actions may be `off` at once: `off` is the absence of a key, not a key.
    assert!(!map.live(Scope::Leader).contains(&Action::LeaderQuit));
}

/// Two actions turned `off` are not a conflict with each other.
#[test]
fn two_actions_turned_off_do_not_collide() {
    let map = Keymap::resolve(&overrides(&[("verbose", "off"), ("plan_panel", "off")]));
    assert!(map.problems().is_empty(), "{:?}", map.problems());
}

/// A `[keys]` line whose value is not a string cannot be a spec. It is dropped and named
/// by [`ouro::config::load`], and the file it is in still loads.
#[test]
fn a_key_whose_value_is_not_a_string_is_named_rather_than_refusing_the_file() {
    let dir = std::env::temp_dir().join(format!("ouro-keys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("config.toml");
    // The canary is a `[defaults]` value this build still reads, so a dropped `[keys]`
    // line is visibly the only thing the file lost.
    std::fs::write(
        &path,
        "[defaults]\nmodel = \"openai_codex:gpt-5.6-sol\"\n\
         [keys]\nverbose = true\nplan_panel = \"ctrl+y\"\n",
    )
    .expect("a config");

    let loaded = ouro::config::load(path);

    assert_eq!(
        loaded.config.defaults.model.as_deref(),
        Some("openai_codex:gpt-5.6-sol")
    );
    assert_eq!(loaded.problems.len(), 1, "{:?}", loaded.problems);
    assert!(
        loaded.problems[0].contains("keys.verbose"),
        "{:?}",
        loaded.problems
    );

    let map = Keymap::resolve(&loaded.config.keys.overrides());
    assert_eq!(map.spec(Action::Verbose).to_string(), "ctrl+o");
    assert_eq!(map.spec(Action::PlanPanel).to_string(), "ctrl+y");

    std::fs::remove_dir_all(&dir).ok();
}

/// A terminal that reports `Shift+N` as a lowercase `n` with the modifier still reaches
/// `leader.new_options`, because the case is what distinguishes the two verbs and
/// crossterm does not agree with itself across terminals about which form to send.
#[test]
fn a_shifted_leader_key_reaches_the_uppercase_verb() {
    let map = Keymap::builtin();
    let shifted = KeyEvent {
        code: KeyCode::Char('n'),
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    };

    assert_eq!(map.leader_verb(shifted), Some(Action::LeaderNewOptions));
    assert_eq!(
        map.leader_verb(KeyEvent {
            code: KeyCode::Char('N'),
            ..shifted
        }),
        Some(Action::LeaderNewOptions)
    );
    assert_eq!(
        map.leader_verb(KeyEvent {
            code: KeyCode::Char('n'),
            modifiers: KeyModifiers::NONE,
            ..shifted
        }),
        Some(Action::LeaderNew)
    );
}

/// `[keys]` survives the settings overlay's whole-file rewrite.
///
/// The flattened bindings and the `backtrack` field share one TOML table, which is exactly
/// the arrangement serde is fussiest about: a save that dropped half of it would silently
/// un-rebind every chord the next time an operator pressed `,`.
#[test]
fn a_saved_keys_table_round_trips_through_the_file() {
    let dir = std::env::temp_dir().join("ouro-keys-round-trip");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("config.toml");

    let mut config = ouro::config::Config::default();
    config.keys.backtrack = Some("alt+up".into());
    config
        .keys
        .bindings
        .insert("verbose".into(), toml::Value::String("ctrl+b".into()));
    config.save(&path).expect("a saved config");

    let loaded = ouro::config::load(path);
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
    assert_eq!(loaded.config, config);

    let map = Keymap::resolve(&loaded.config.keys.overrides());
    assert_eq!(map.label(Action::Backtrack), "alt+up");
    assert_eq!(map.label(Action::Verbose), "ctrl+b");
    assert_eq!(map.source(Action::Verbose), Source::File);

    std::fs::remove_dir_all(&dir).ok();
}

/// The `[keys] backtrack` this client shipped with keeps working, spelling for spelling.
#[test]
fn the_backtrack_setting_that_predates_the_map_still_means_what_it_meant() {
    for (written, expected) in [("esc esc", "esc esc"), ("alt+up", "alt+up"), ("off", "off")] {
        let map = Keymap::resolve(&overrides(&[("backtrack", written)]));
        assert!(map.problems().is_empty(), "{written}: {:?}", map.problems());
        assert_eq!(map.label(Action::Backtrack), expected, "{written}");
    }
}

// ---------------------------------------------------------------------------------------
// (2) the defaults
// ---------------------------------------------------------------------------------------

/// Every action's default, written out, so a drift is a diff a reviewer reads rather than
/// a regression an operator finds.
///
/// This is the table B8's acceptance names: "the default map equals today's bindings
/// exactly". The right-hand column moved once, at the `ui-parity` realignment (T1.4/T1.5):
/// `editor`, `settings`, `quit_empty` and `leader.steer` gave their keys up, `leader.end`
/// moved off `x` so export could have it, and fifteen verbs arrived.
#[test]
fn the_default_map_is_exactly_what_this_client_bound_before_it_had_one() {
    let expected: &[(Action, &str)] = &[
        (Action::ChooseLocation, "f5"),
        (Action::StarterExplore, "f2"),
        (Action::StarterReview, "f3"),
        (Action::StarterPlan, "f4"),
        (Action::Send, "enter"),
        (Action::Steer, "alt+enter"),
        (Action::Newline, "ctrl+j"),
        (Action::QueueRetract, "up"),
        (Action::PasteImage, "ctrl+v"),
        (Action::Editor, "off"),
        (Action::Interrupt, "esc"),
        (Action::Backtrack, "esc esc"),
        (Action::Cancel, "ctrl+c"),
        (Action::Verbose, "ctrl+o"),
        (Action::PlanPanel, "ctrl+t"),
        (Action::Rename, "ctrl+r"),
        (Action::Suspend, "ctrl+z"),
        (Action::TranscriptTop, "home"),
        (Action::TranscriptBottom, "end"),
        (Action::Palette, "ctrl+p"),
        (Action::Leader, "ctrl+x"),
        (Action::Help, "?"),
        (Action::Settings, "off"),
        (Action::Quit, "ctrl+q"),
        (Action::QuitEmpty, "off"),
        (Action::LeaderNew, "n"),
        (Action::LeaderNewOptions, "N"),
        (Action::LeaderSessions, "l"),
        (Action::LeaderWritable, "w"),
        (Action::LeaderEditor, "e"),
        (Action::LeaderCopy, "y"),
        (Action::LeaderScrollback, "["),
        (Action::LeaderEditorView, "v"),
        (Action::LeaderOpenImage, "i"),
        (Action::LeaderSteer, "off"),
        (Action::LeaderApproval, "a"),
        (Action::LeaderAutoApprove, "A"),
        (Action::LeaderShellRule, "r"),
        (Action::LeaderEnd, "k"),
        (Action::LeaderDetails, "d"),
        (Action::LeaderSettings, ","),
        (Action::LeaderTheme, "t"),
        (Action::LeaderExport, "x"),
        (Action::LeaderCompact, "c"),
        (Action::LeaderModel, "m"),
        (Action::LeaderBacktrack, "g"),
        (Action::LeaderStatus, "s"),
        (Action::LeaderRail, "b"),
        (Action::LeaderTabDashboard, "1"),
        (Action::LeaderTabSessions, "2"),
        (Action::LeaderTabUpgrade, "3"),
        (Action::LeaderTabLogs, "4"),
        (Action::LeaderQuit, "q"),
        (Action::LeaderHelp, "?"),
        (Action::EditorWordBack, "alt+b"),
        (Action::EditorWordForward, "alt+f"),
        (Action::EditorKillWordBack, "ctrl+w"),
        (Action::EditorKillWordForward, "alt+d"),
        (Action::EditorKillLine, "ctrl+k"),
        (Action::EditorKillToStart, "ctrl+u"),
        (Action::EditorYank, "ctrl+y"),
        (Action::EditorLineStart, "ctrl+a"),
        (Action::EditorLineEnd, "ctrl+e"),
    ];

    let map = Keymap::builtin();

    assert_eq!(
        expected.len(),
        Action::ALL.len(),
        "every action has a row in this table"
    );

    for (action, spec) in expected {
        assert_eq!(
            map.spec(*action).to_string(),
            *spec,
            "{} moved",
            action.name()
        );
        assert_eq!(map.source(*action), Source::Builtin, "{}", action.name());
    }

    // And every one of them is reachable by name from `[keys]`, which is the other half of
    // "rebindable": a default nobody can name is a default nobody can change.
    for action in Action::ALL {
        assert_eq!(Action::parse(action.name()), Some(action));
        assert!(
            Spec::parse(action.default_spec()).is_ok(),
            "{}",
            action.name()
        );
    }
}

/// An empty `[keys]` is the built-in map, with nothing marked as coming from a file.
#[test]
fn an_empty_keys_table_is_the_built_in_map() {
    let map = Keymap::resolve(&BTreeMap::new());
    assert_eq!(map, Keymap::builtin());
    assert!(map.problems().is_empty());
    assert!(Action::ALL
        .into_iter()
        .all(|action| map.source(action) == Source::Builtin));
}

// ---------------------------------------------------------------------------------------
// (3) a rebound key is what the UI says
// ---------------------------------------------------------------------------------------

/// The four surfaces D14 names, all reading the same map.
///
/// `verbose` moves from `ctrl+o` to `ctrl+b`, `leader` from `ctrl+x` to `ctrl+b`… no: from
/// `ctrl+x` to `ctrl+s`, and the `?` panel, the footer, the which-key overlay, and the
/// palette all have to say the new key rather than the old one.
#[test]
fn a_rebound_chord_is_what_the_help_footer_leader_and_palette_all_show() {
    let rebound = &[
        ("verbose", "ctrl+b"),
        ("leader", "ctrl+s"),
        ("palette", "alt+p"),
        ("leader.details", "ctrl+s o"),
    ];

    // `?`, read as the table it is generated from rather than as one frame: the panel is
    // longer than any terminal and scrolls, so a rendered assertion would be a claim about
    // whichever rows happened to fit (F1). The frame's own job — saying that the rest is
    // reachable — is asserted in `input_grammar.rs`.
    let mut app = opened(rebound);
    app.apply(key(KeyCode::Char('?')));
    let help = ouro::ui::view::help_keys(&app)
        .into_iter()
        .map(|(_group, key, description)| format!("{key}  {description}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        help.contains("ctrl+b"),
        "the help panel names the new key\n{help}"
    );
    assert!(!help.contains("ctrl+o"), "and not the old one\n{help}");
    assert!(help.contains("ctrl+s"), "{help}");
    assert!(help.contains("alt+p"), "{help}");
    app.apply(key(KeyCode::Esc));

    // The footer's own hints.
    let footer = screen(&mut app).rows.last().cloned().unwrap_or_default();
    assert!(footer.contains("alt+p commands"), "{footer}");
    assert!(footer.contains("ctrl+s leader"), "{footer}");
    assert!(!footer.contains("ctrl+x leader"), "{footer}");

    // The which-key overlay, titled with the leader it is actually under.
    app.apply(modified(KeyCode::Char('s'), KeyModifiers::CONTROL));
    let leader = screen(&mut app).text();
    assert!(
        leader.contains("ctrl+s"),
        "the overlay is titled by the leader\n{leader}"
    );
    assert!(
        leader.contains(" o ") || leader.contains("o    event details"),
        "and the rebound verb is drawn on its new key\n{leader}"
    );
    app.apply(key(KeyCode::Esc));

    // The palette's shortcut column.
    app.apply(modified(KeyCode::Char('p'), KeyModifiers::ALT));
    let palette = screen(&mut app).text();
    assert!(
        palette.contains("ctrl+s o"),
        "the palette names the rebound leader verb\n{palette}"
    );
    assert!(
        !palette.contains("ctrl+x d"),
        "and not the one it replaced\n{palette}"
    );
}

/// The rebound chord does not only *read* differently — it works, and the old one does not.
#[test]
fn a_rebound_chord_is_the_one_that_acts() {
    let mut app = opened(&[("palette", "alt+p")]);

    app.apply(modified(KeyCode::Char('p'), KeyModifiers::CONTROL));
    assert!(
        app.overlay.is_none(),
        "the old key is no longer the palette"
    );

    app.apply(modified(KeyCode::Char('p'), KeyModifiers::ALT));
    assert!(
        matches!(app.overlay, Some(ouro::ui::app::Overlay::Commands(_))),
        "{:?}",
        app.overlay
    );
}

/// A verb turned `off` loses its key everywhere it was advertised, and keeps its `/` verb.
#[test]
fn a_key_turned_off_is_not_advertised_anywhere() {
    let mut app = opened(&[("leader.quit", "off"), ("quit", "off")]);

    let footer = screen(&mut app).rows.last().cloned().unwrap_or_default();
    assert!(
        !footer.contains("quit"),
        "the footer drops the hint\n{footer}"
    );

    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    let leader = screen(&mut app).text();
    assert!(
        !leader.contains("q    quit"),
        "and the which-key overlay drops the row\n{leader}"
    );

    // The dialog is still one command away, which is what `off` promises.
    app.apply(key(KeyCode::Esc));
    slash(&mut app, "/quit");
    assert!(matches!(app.overlay, Some(Overlay::Quit { .. })));
}

// ---------------------------------------------------------------------------------------
// (4) `/keys`
// ---------------------------------------------------------------------------------------

/// The page names every action, its effective key, and which of them came from the file.
#[test]
fn slash_keys_shows_the_effective_map_and_where_each_row_came_from() {
    let mut app = opened(&[("verbose", "ctrl+b"), ("plan_panel", "off")]);
    slash(&mut app, "/keys");

    let text = tall(&mut app).text();

    assert!(text.contains("verbose"), "{text}");
    assert!(text.contains("ctrl+b"), "the effective key\n{text}");
    assert!(text.contains("config"), "marked as the file's\n{text}");
    assert!(
        text.contains("default"),
        "beside the ones that are not\n{text}"
    );
    assert!(text.contains("plan_panel"), "{text}");
    assert!(
        text.contains("off"),
        "a disabled action still has a row\n{text}"
    );
    assert!(
        text.contains("every line of [keys] was used"),
        "a clean file says so\n{text}"
    );
    for heading in ["GLOBAL", "LEADER", "COMPOSER"] {
        assert!(text.contains(heading), "missing {heading}\n{text}");
    }
}

/// A `[keys]` line this build could not act on is named on the page, not only at startup.
#[test]
fn slash_keys_names_the_lines_it_could_not_use() {
    let mut app = opened(&[("telepathy", "ctrl+z"), ("plan_panel", "ctrl+o")]);
    slash(&mut app, "/keys");

    // The problems are drawn first, so this one is legible on an ordinary terminal.
    let text = screen(&mut app).text();

    assert!(text.contains("NOT USED"), "{text}");
    assert!(text.contains("telepathy"), "{text}");
    assert!(text.contains("plan_panel"), "{text}");
    // And the action it collided with kept its key.
    assert!(text.contains("ctrl+t"), "{text}");
}

/// The `?` panel says the map ran with lines it could not use, so a mistyped chord is
/// discovered by reading the page rather than by pressing the key.
#[test]
fn the_help_panel_says_when_a_keys_line_was_not_used() {
    let mut app = opened(&[("telepathy", "ctrl+z")]);
    app.apply(key(KeyCode::Char('?')));

    let text = screen(&mut app).text();
    assert!(
        text.contains("could not be used") && text.contains("/keys"),
        "{text}"
    );
}

// ---------------------------------------------------------------------------------------
// (5) the composer motions
// ---------------------------------------------------------------------------------------

/// A rebound composer motion runs on its new chord, and the old one falls back to being
/// text — the editor is a text field first.
#[test]
fn a_rebound_composer_motion_moves_with_its_key() {
    use ouro::ui::editor::{CompletionCatalog, Editor};

    let catalog = CompletionCatalog::default();
    let map = Keymap::resolve(&overrides(&[("editor.kill_line", "ctrl+b")]));

    let mut editor = Editor::default();
    editor.paste("hello world", &catalog);
    for _ in 0..6 {
        editor.handle_key_with(
            KeyEvent {
                code: KeyCode::Left,
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                state: crossterm::event::KeyEventState::NONE,
            },
            &catalog,
            &map,
        );
    }

    editor.handle_key_with(
        KeyEvent {
            code: KeyCode::Char('b'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        },
        &catalog,
        &map,
    );

    assert_eq!(editor.text(), "hello");

    // And `ctrl+k`, which used to do this, no longer does anything at all.
    let mut untouched = Editor::default();
    untouched.paste("hello world", &catalog);
    untouched.handle_key_with(
        KeyEvent {
            code: KeyCode::Char('k'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        },
        &catalog,
        &map,
    );
    assert_eq!(untouched.text(), "hello world");
}

// ---------------------------------------------------------------------------------------
// (6) ui-parity T1 — the layer under the composer, and the two chords that changed shape
// ---------------------------------------------------------------------------------------

/// T1.6. The single-letter layer of the three list tabs, with the dead arms gone.
///
/// `i`, `s`, `a` and `,` were unreachable by construction: every one of their handlers
/// returns unless `tab == Sessions`, and this match is only reached when the composer is
/// not claiming the keyboard — which on the Sessions tab it always is (R1 §2.1). They
/// were not documentation of a state that existed; they were four keys that did nothing.
#[test]
fn the_list_layer_keeps_the_keys_that_work_and_has_dropped_the_ones_that_never_did() {
    // On a list tab, which is the only place this layer is reached: the Sessions tab's
    // composer owns every printable key, which is the whole finding.
    let mut app = configured(&[]);
    app.tab = Tab::Dashboard;

    for dead in ['i', 's', 'a', ','] {
        let before = app.tab;
        app.apply(key(KeyCode::Char(dead)));
        assert!(
            app.overlay.is_none(),
            "{dead:?} opened something: {:?}",
            app.overlay
        );
        assert_eq!(app.tab, before, "{dead:?} moved the tab");
        assert!(
            app.sessions.composer.is_none(),
            "{dead:?} opened a composer"
        );
    }

    // `x` with no session open used to open the picker and say "press x to end or remove
    // it" — advice that was wrong the moment `leader.end` moved to `k`.
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-a7",
            "status": "idle",
            "provider": "native",
            "workspace": "/w",
            "updated_at": "2026-01-01T00:00:00.000000Z",
            "options": { "capabilities": { "transport": "app_server" } },
        }]),
    );
    assert!(app.sessions.open.is_none());
    app.apply(key(KeyCode::Char('x')));
    assert!(app.overlay.is_none(), "{:?}", app.overlay);

    // The keys that do work still do.
    app.apply(key(KeyCode::Char('r')));
    app.apply(key(KeyCode::Tab));
    assert_eq!(app.tab, Tab::Sessions);
    app.apply(key(KeyCode::BackTab));
    assert_eq!(app.tab, Tab::Dashboard);
    app.apply(key(KeyCode::Char('q')));
    assert!(
        matches!(app.overlay, Some(Overlay::Quit { .. })),
        "{:?}",
        app.overlay
    );
}

/// A digit past the last tab falls through instead of being claimed and dropped. `5`, `6`
/// and `7` used to be swallowed by a literal range that agreed with `Tab::ALL` by
/// accident, so a build with fewer tabs kept eating them.
#[test]
fn a_digit_past_the_last_tab_is_not_claimed() {
    let mut app = configured(&[]);

    for digit in '1'..='9' {
        // From a list tab every time: landing on Sessions hands the keyboard to the
        // composer, which is the state this whole layer is unreachable from.
        app.tab = Tab::Upgrade;
        app.apply(key(KeyCode::Char(digit)));

        let index = digit.to_digit(10).expect("a digit") as usize - 1;

        match Tab::ALL.get(index) {
            Some(tab) => assert_eq!(app.tab, *tab, "{digit} is {tab:?}"),
            None => assert_eq!(
                app.tab,
                Tab::Upgrade,
                "{digit} is past the last tab and moved somewhere"
            ),
        }
    }
}

/// `q` on a list is the field's convention and stays a letter — but `[keys] quit = off`
/// turns it off too, so "off" means off wherever quitting is offered.
#[test]
fn the_lists_bare_q_is_silenced_by_turning_quit_off() {
    let mut app = configured(&[("quit", "off")]);
    app.tab = Tab::Dashboard;
    app.apply(key(KeyCode::Char('q')));

    assert!(app.overlay.is_none(), "{:?}", app.overlay);
}

/// T1.4. The `?` chord carried a `!shift` guard the map's own `Chord::hit` deliberately
/// does not have, so on every terminal that reports `?` with the modifier — which is most
/// of them, since `?` *is* shift-`/` — the help panel was unreachable.
#[test]
fn the_help_chord_is_reachable_on_a_terminal_that_reports_the_shift() {
    // On the home screen, where the chord is the only thing that can answer: the list
    // tabs carry a literal `?` arm as well, and it would hide the guard rather than
    // prove it gone.
    let mut app = configured(&[]);

    app.apply(modified(KeyCode::Char('?'), KeyModifiers::SHIFT));

    assert!(
        matches!(app.overlay, Some(Overlay::Help)),
        "{:?}",
        app.overlay
    );
    assert!(
        app.home_draft.is_empty(),
        "the chord was typed into the draft instead: {:?}",
        app.home_draft.text()
    );
}

/// T1.5. Every action added by the realignment is nameable from `[keys]`, rebindable, and
/// listed by `/keys` — which is the whole of what "rebindable" is worth.
#[test]
fn the_new_actions_are_rebindable_and_listed() {
    let added = [
        Action::Rename,
        Action::Suspend,
        Action::TranscriptTop,
        Action::TranscriptBottom,
        Action::LeaderSettings,
        Action::LeaderTheme,
        Action::LeaderExport,
        Action::LeaderCompact,
        Action::LeaderModel,
        Action::LeaderBacktrack,
        Action::LeaderStatus,
        Action::LeaderRail,
        Action::LeaderTabDashboard,
        Action::LeaderTabSessions,
        Action::LeaderTabUpgrade,
        Action::LeaderTabLogs,
    ];

    let mut app = opened(&[("rename", "ctrl+b"), ("leader.rail", "B")]);
    slash(&mut app, "/keys");
    let text = tall(&mut app).text();

    for action in added {
        assert!(
            text.contains(action.name()),
            "{} has no row\n{text}",
            action.name()
        );
        assert!(!action.describe().is_empty(), "{}", action.name());
    }

    assert_eq!(app.keymap.label(Action::Rename), "ctrl+b");
    assert_eq!(app.keymap.label(Action::LeaderRail), "ctrl+x B");
    assert!(
        app.keymap.problems().is_empty(),
        "{:?}",
        app.keymap.problems()
    );
}

// ---------------------------------------------------------------------------------------
// (7) ui-parity T1 fix wave — the reviewer's probes over the map itself
// ---------------------------------------------------------------------------------------

/// F9. The list tabs' bare `q` follows `[keys] quit`'s on/off and not its *chord*: moving
/// the chord leaves the letter alone, turning it off takes the letter with it.
#[test]
fn the_lists_bare_q_follows_whether_quit_is_bound_and_not_where() {
    let mut app = configured(&[("quit", "ctrl+w")]);
    app.tab = Tab::Dashboard;
    app.apply(key(KeyCode::Char('q')));
    assert!(
        matches!(app.overlay, Some(Overlay::Quit { .. })),
        "a rebound chord took the letter with it: {:?}",
        app.overlay
    );

    let mut app = configured(&[("quit", "off")]);
    app.tab = Tab::Dashboard;
    app.apply(key(KeyCode::Char('q')));
    assert!(app.overlay.is_none(), "{:?}", app.overlay);
}

/// And `describe()` says so, because `/keys` and the `?` panel are where somebody looks
/// when a letter they pressed did nothing.
#[test]
fn the_quit_description_names_the_letter_it_gates() {
    let described = Action::Quit.describe();
    assert!(described.contains('q'), "{described}");
    assert!(described.contains("list"), "{described}");
}

/// F10b. `interrupt = off` leaves the verb and nothing else — an action turned off keeps
/// its `/` spelling, which is the whole promise of `off`.
#[test]
fn an_interrupt_turned_off_leaves_only_its_verb() {
    let mut app = opened(&[("interrupt", "off")]);
    assert!(!app.bound(Action::Interrupt));

    app.apply(key(KeyCode::Enter));
    for character in "x".chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Esc));
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.interrupt"));

    slash(&mut app, "/interrupt");
    assert!(
        app.drain()
            .iter()
            .any(|call| call.method == "interactive.interrupt"),
        "`/interrupt` is what `off` leaves behind"
    );
}

/// F10c. An interrupt bound over `send` is a collision the map must report rather than
/// apply — two actions on one key in one scope is a chord whose meaning depends on which
/// handler is checked first.
#[test]
fn an_interrupt_bound_over_send_is_reported_and_ignored() {
    let map = Keymap::resolve(&overrides(&[("interrupt", "enter")]));

    assert_eq!(map.problems().len(), 1, "{:?}", map.problems());
    assert!(
        map.problems()[0].contains("interrupt") && map.problems()[0].contains("send"),
        "{:?}",
        map.problems()
    );
    assert_eq!(map.spec(Action::Interrupt).to_string(), "esc");
    assert_eq!(map.spec(Action::Send).to_string(), "enter");
}

/// F15. `ctrl+q` closes nothing, and the keys that are meant to still do.
#[test]
fn ctrl_q_closes_no_overlay_and_esc_still_does() {
    let mut app = opened(&[]);

    app.apply(modified(KeyCode::Char('p'), KeyModifiers::CONTROL));
    assert!(app.overlay.is_some(), "the palette did not open");

    app.apply(modified(KeyCode::Char('q'), KeyModifiers::CONTROL));
    assert!(
        matches!(app.overlay, Some(ouro::ui::app::Overlay::Commands(_))),
        "ctrl+q replaced the palette: {:?}",
        app.overlay
    );

    app.apply(key(KeyCode::Esc));
    assert!(app.overlay.is_none(), "{:?}", app.overlay);
}

/// F17. Suspend is a global chord and carries the same overlay guard as the rest.
#[test]
fn suspend_is_not_claimed_over_an_overlay_and_is_taken_once() {
    let mut app = opened(&[]);
    app.apply(modified(KeyCode::Char('p'), KeyModifiers::CONTROL));
    app.apply(modified(KeyCode::Char('z'), KeyModifiers::CONTROL));
    assert!(!app.take_suspend(), "suspended out from under an overlay");

    let mut app = opened(&[]);
    app.apply(modified(KeyCode::Char('z'), KeyModifiers::CONTROL));
    assert!(app.take_suspend());
    assert!(!app.take_suspend(), "drained more than once");
}

/// F19. The leader never arms over an overlay, so its digits cannot move a tab out from
/// under a dialog somebody is reading.
#[test]
fn the_leader_does_not_arm_over_an_overlay() {
    let mut app = opened(&[]);
    let before = app.tab;

    app.apply(modified(KeyCode::Char('p'), KeyModifiers::CONTROL));
    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    app.apply(key(KeyCode::Char('1')));

    assert_eq!(
        app.tab, before,
        "a leader digit moved the tab under the palette"
    );
}

/// F20. The arming notice names only keys that exist. It used to print `off`.
#[test]
fn the_arming_notice_names_only_bound_keys() {
    let mut app = opened(&[("interrupt", "off"), ("quit", "off")]);
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));

    let line = app.notice.as_ref().expect("an arming notice").text.clone();
    assert!(line.contains("ctrl+c again to quit"), "{line}");
    assert!(!line.contains("off"), "{line}");
    assert!(!line.contains("aborts"), "{line}");
    assert!(!line.contains("quit dialog"), "{line}");
}

/// F13. The table is the map's own census: every action round-trips through `[keys]`, and
/// the count is stated so a verb added without a name, a default or a description is a
/// failure here rather than a hole somebody finds later.
#[test]
fn every_action_round_trips_and_the_table_is_complete() {
    for action in Action::ALL {
        assert_eq!(
            Action::parse(action.name()),
            Some(action),
            "{}",
            action.name()
        );
        assert!(!action.describe().is_empty(), "{}", action.name());
        assert!(
            Spec::parse(action.default_spec()).is_ok(),
            "{}",
            action.name()
        );
    }

    assert_eq!(
        Action::ALL.len(),
        63,
        "an action arrived without a row here"
    );
}
