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
use ouro::ui::app::{App, Msg, Tag};

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
            "provider": "codex",
            "workspace": "/w",
            "updated_at": "2026-01-01T00:00:00.000000Z",
            "options": { "capabilities": { "transport": "app_server", "interrupt": "native" } },
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
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

/// `/keys` lists forty actions and needs the rows for them; a short terminal scrolls, which
/// its own assertion below covers.
fn tall(app: &mut App) -> Screen {
    render(app, 120, 60)
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
    // `claude`, not `codex`: an explicit codex default is migrated to native by
    // `config::normalise`, and this test's canary must be a value that survives loading.
    std::fs::write(
        &path,
        "[defaults]\nprovider = \"claude\"\n[keys]\nverbose = true\nplan_panel = \"ctrl+y\"\n",
    )
    .expect("a config");

    let loaded = ouro::config::load(path);

    assert_eq!(loaded.config.defaults.provider.as_deref(), Some("claude"));
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
/// exactly". The right-hand column is what this client bound before `[keys]` covered more
/// than one chord.
#[test]
fn the_default_map_is_exactly_what_this_client_bound_before_it_had_one() {
    let expected: &[(Action, &str)] = &[
        (Action::StarterExplore, "f2"),
        (Action::StarterReview, "f3"),
        (Action::StarterPlan, "f4"),
        (Action::Send, "enter"),
        (Action::Steer, "alt+enter"),
        (Action::Newline, "ctrl+j"),
        (Action::QueueRetract, "up"),
        (Action::PasteImage, "ctrl+v"),
        (Action::Editor, "ctrl+g"),
        (Action::Interrupt, "esc"),
        (Action::Backtrack, "esc esc"),
        (Action::Cancel, "ctrl+c"),
        (Action::Verbose, "ctrl+o"),
        (Action::PlanPanel, "ctrl+t"),
        (Action::Palette, "ctrl+p"),
        (Action::Leader, "ctrl+x"),
        (Action::Help, "?"),
        (Action::Settings, ","),
        (Action::Quit, "ctrl+q"),
        (Action::QuitEmpty, "ctrl+d"),
        (Action::LeaderNew, "n"),
        (Action::LeaderNewOptions, "N"),
        (Action::LeaderSessions, "l"),
        (Action::LeaderWritable, "w"),
        (Action::LeaderEditor, "e"),
        (Action::LeaderCopy, "y"),
        (Action::LeaderScrollback, "["),
        (Action::LeaderEditorView, "v"),
        (Action::LeaderOpenImage, "i"),
        (Action::LeaderSteer, "s"),
        (Action::LeaderApproval, "a"),
        (Action::LeaderAutoApprove, "A"),
        (Action::LeaderShellRule, "r"),
        (Action::LeaderEnd, "x"),
        (Action::LeaderDetails, "d"),
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

    // `?`, which is generated from the map.
    let mut app = opened(rebound);
    app.apply(key(KeyCode::Char('?')));
    let help = screen(&mut app).text();
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
    assert!(matches!(
        app.overlay,
        Some(ouro::ui::app::Overlay::Quit { .. })
    ));
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
    assert!(text.contains("GLOBAL") && text.contains("LEADER") && text.contains("COMPOSER"));
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
