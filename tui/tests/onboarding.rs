//! What a first run shows, what the settings overlay writes, and what the config file
//! prefills.
//!
//! Driven the way `tests/ui.rs` drives everything else: messages in, rendered frames out,
//! no terminal and no socket. The one exception is [`ouro::ui::persist`], which is the
//! driver's file write and is exercised here against a scratch directory — the App itself
//! only ever *asks* for a save, and that asking is what most of these tests read.
//!
//! Nothing below touches the real home. Every path is under the OS temp root, and the
//! config file location is passed to the App explicitly rather than discovered, so a test
//! run cannot write into the machine it runs on.

mod support;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;

use ouro::config::{self, Config, Defaults, Onboarding};
use ouro::model::{ApprovalMode, Plane};
use ouro::ui::app::{
    approval_at, approval_index, provider_choices, App, Msg, NewField, Overlay, ProviderChoice, Tag,
};

use support::{app, full_hello, render};

static SCRATCH: AtomicU32 = AtomicU32::new(0);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ouro-onboarding-{name}-{}-{}",
        std::process::id(),
        SCRATCH.fetch_add(1, Ordering::Relaxed)
    ));

    fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

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

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        app.apply(key(KeyCode::Char(c)));
    }
}

fn answer(app: &mut App, tag: Tag, value: serde_json::Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

/// The two providers every test below picks from: one the probe found, one it did not.
fn providers() -> serde_json::Value {
    json!([
        {
            "provider": "claude_code",
            "spec": {},
            "status": {
                "installed": true, "compatible": true, "authenticated": true,
                "version": "1.2.3", "executable": "/usr/bin/claude"
            },
            "error": null
        },
        {
            "provider": "gemini",
            "spec": {},
            "status": {
                "installed": false, "compatible": false, "authenticated": "unknown",
                "executable": "gemini"
            },
            "error": null
        }
    ])
}

/// An App that has connected, knows where its own files are, and has been told which
/// providers this runtime serves.
fn connected(defaults: Defaults, welcomed: bool) -> App {
    let mut app = app(full_hello());

    app.launch_dir = Some("/home/operator/project".into());
    app.data_dir = Some("/home/operator/.local/share/ouroboros".into());
    app.config_path = Some(PathBuf::from(
        "/home/operator/.config/ouroboros/config.toml",
    ));
    app.config = Config {
        defaults,
        onboarding: Onboarding { welcomed },
    };

    answer(&mut app, Tag::Providers, providers());
    let _ = app.drain();

    app
}

// ----- the welcome panel ---------------------------------------------------------------

#[test]
fn the_first_run_panel_states_where_things_are_and_asks_nothing() {
    let mut app = connected(Defaults::default(), false);
    app.welcome();

    assert!(matches!(app.overlay, Some(Overlay::Welcome)));

    let screen = render(&mut app, 120, 30);

    // The runtime's answers, labelled as the runtime's.
    assert!(
        screen.contains("as the runtime reports it"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("ouroboros@golden"), "{}", screen.text());
    assert!(screen.contains("operate"), "{}", screen.text());

    // This client's paths, labelled as this client's.
    assert!(
        screen.contains("this client's own paths"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("/home/operator/.local/share/ouroboros"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("/home/operator/.config/ouroboros/config.toml"),
        "{}",
        screen.text()
    );

    // The probe, with the available one marked and the missing one naming what was looked
    // for.
    assert!(
        screen.contains("providers, as this runtime probed them"),
        "{}",
        screen.text()
    );
    assert!(
        screen.row("claude_code").contains("1.2.3"),
        "{}",
        screen.text()
    );
    assert!(
        screen
            .row("gemini")
            .contains("no gemini on the runtime's PATH"),
        "{}",
        screen.text()
    );

    // The keys that matter, and nothing that reads as a question.
    let text = screen.text();
    assert!(text.contains("start a session"), "{text}");
    assert!(text.contains("settings"), "{text}");
    assert!(text.contains("quit"), "{text}");
    assert!(
        !text.contains('?') || text.contains("? keys"),
        "the only `?` on the panel is the key legend: {text}"
    );

    // Opening it asks the runtime nothing but the provider list it is showing.
    let asked: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert!(
        asked.iter().all(|method| method == "runtime.providers"),
        "{asked:?}"
    );
}

#[test]
fn an_operator_who_has_seen_it_does_not_see_it_again() {
    let mut app = connected(Defaults::default(), true);
    app.welcome();

    assert!(
        app.overlay.is_none(),
        "the marker in the config file is the whole of the decision"
    );

    // And nothing is queued to be written, because nothing changed.
    assert!(app.take_config_save().is_none());
}

#[test]
fn any_key_closes_the_panel_and_asks_for_the_marker_to_be_written() {
    for code in [
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::Char(' '),
        KeyCode::Char('n'),
        KeyCode::Char('q'),
        KeyCode::Down,
    ] {
        let mut app = connected(Defaults::default(), false);
        app.welcome();
        app.apply(key(code));

        assert!(app.overlay.is_none(), "{code:?} must close the panel");
        assert!(app.config.onboarding.welcomed, "{code:?} must mark it seen");

        let pending = app
            .take_config_save()
            .unwrap_or_else(|| panic!("{code:?} must queue the marker for writing"));

        assert!(pending.onboarding.welcomed);
        assert!(
            app.take_config_save().is_none(),
            "and queue it exactly once: {code:?}"
        );
    }
}

#[test]
fn ctrl_c_closes_it_too_and_still_writes_the_marker() {
    let mut app = connected(Defaults::default(), false);
    app.welcome();

    // ctrl-c is intercepted before the overlay dispatch, so it is its own way out — and a
    // panel that came back after being dismissed the "wrong" way would be a client that
    // did not believe the operator the first time.
    app.apply(ctrl('c'));

    assert!(app.overlay.is_none());
    assert!(app.config.onboarding.welcomed);
    assert!(app.take_config_save().is_some());
}

#[test]
fn a_dismissed_panel_does_not_reopen_within_the_same_session() {
    let mut app = connected(Defaults::default(), false);

    app.welcome();
    app.apply(key(KeyCode::Enter));
    app.welcome();

    assert!(app.overlay.is_none());
}

#[test]
fn no_provider_at_all_is_said_plainly_and_blocks_nothing() {
    let mut app = app(full_hello());
    app.config_path = Some(PathBuf::from("/tmp/config.toml"));

    answer(
        &mut app,
        Tag::Providers,
        json!([
            {
                "provider": "claude_code",
                "spec": {},
                "status": {
                    "installed": false, "compatible": false, "authenticated": "unknown",
                    "executable": "claude"
                },
                "error": null
            }
        ]),
    );

    app.welcome();

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("no claude on the runtime's PATH"),
        "the executable the probe looked for is named: {}",
        screen.text()
    );
    assert!(
        screen.contains("none of them found an executable"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("the runtime decides, not this client"),
        "the probe is a heuristic and the panel says so: {}",
        screen.text()
    );

    // Nothing is blocked: the panel closes and `n` still opens the start dialog.
    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Char('2')));
    app.apply(key(KeyCode::Char('n')));

    assert!(matches!(app.overlay, Some(Overlay::New(_))));
}

#[test]
fn a_gateway_that_will_not_list_providers_is_said_rather_than_drawn_as_silence() {
    // A `read` listener serves no `runtime.providers`, so the call is answered locally with
    // -32601 rather than sent — and the panel says which method, where the list would be.
    let mut app = app(support::hello(&["hello", "runtime.status"]));
    app.config_path = Some(PathBuf::from("/tmp/config.toml"));

    app.welcome();

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("runtime.providers was refused"),
        "{}",
        screen.text()
    );
    // Wrapped across two rows at this width, so the sentence is asserted in the pieces a
    // reader actually sees rather than as one string no row contains.
    assert!(
        screen.contains("method_not_found (-32601)") && screen.contains("does not serve"),
        "the refusal names the code and the method: {}",
        screen.text()
    );
}

#[test]
fn an_attached_client_does_not_claim_to_know_the_runtimes_data_directory() {
    let mut app = connected(Defaults::default(), false);
    app.data_dir = None;

    app.welcome();

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("with whoever started this runtime"),
        "a client that did not spawn it does not know where its files are: {}",
        screen.text()
    );
}

// ----- the settings overlay ------------------------------------------------------------

#[test]
fn comma_opens_settings_from_any_tab_and_keeps_the_two_kinds_of_fact_apart() {
    for tab in ['1', '2', '3', '4', '5', '6', '7'] {
        let mut app = connected(Defaults::default(), true);

        app.apply(key(KeyCode::Char(tab)));
        app.apply(key(KeyCode::Char(',')));

        assert!(
            matches!(app.overlay, Some(Overlay::Settings(_))),
            "`,` must open settings on tab {tab}"
        );
    }

    let mut app = connected(Defaults::default(), true);
    app.apply(key(KeyCode::Char(',')));

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("as reported by the runtime"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("ouroboros@golden"), "{}", screen.text());
    assert!(screen.contains("127.0.0.1:4560"), "{}", screen.text());
    assert!(
        screen.contains("defaults this client remembers"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("they prefill `n`, nothing more"),
        "the overlay says what a default is and is not: {}",
        screen.text()
    );
    assert!(
        screen.contains("/home/operator/.config/ouroboros/config.toml"),
        "the file it writes is named on the screen that writes it: {}",
        screen.text()
    );
    assert!(screen.contains("[ save ]"), "{}", screen.text());
}

#[test]
fn settings_start_unset_and_a_save_writes_exactly_what_the_rows_read() {
    let dir = scratch("save");
    let path = dir.join(config::CONFIG_FILE);

    let mut app = connected(Defaults::default(), true);
    app.config_path = Some(path.clone());

    app.apply(key(KeyCode::Char(',')));

    // Nothing stored, so the picker starts on "unset" — a default is something an operator
    // states, not something a first open invents.
    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("unset — stated per session"),
        "{}",
        screen.text()
    );

    // provider: unset -> claude_code
    app.apply(key(KeyCode::Right));

    // workspace: clear the prefilled launch dir and type one
    app.apply(key(KeyCode::Down));
    for _ in 0..60 {
        app.apply(key(KeyCode::Backspace));
    }
    type_text(&mut app, "/srv/work");

    // approval: unset -> default -> prompt
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Right));

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("prompt — ask before every action"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("changed, and not written yet"),
        "an unwritten edit says so: {}",
        screen.text()
    );

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    assert!(app.overlay.is_none(), "saving closes the overlay");

    // The App asks; the driver writes. This is that driver step, run against a scratch
    // file rather than anyone's home.
    ouro::ui::persist(&mut app);

    let loaded = config::load(path.clone());

    assert_eq!(
        loaded.config.defaults.provider.as_deref(),
        Some("claude_code")
    );
    assert_eq!(
        loaded.config.defaults.workspace.as_deref(),
        Some("/srv/work")
    );
    assert_eq!(
        loaded.config.defaults.approval_mode(),
        Some(ApprovalMode::Prompt)
    );
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);

    // And the operator is told where it went, by name.
    let notice = app.notice.as_ref().expect("a confirmation");
    assert!(
        notice.text.contains(&path.display().to_string()),
        "{}",
        notice.text
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn esc_closes_settings_without_writing_anything() {
    let dir = scratch("discard");
    let path = dir.join(config::CONFIG_FILE);

    let mut app = connected(Defaults::default(), true);
    app.config_path = Some(path.clone());

    app.apply(key(KeyCode::Char(',')));
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Esc));

    assert!(app.overlay.is_none());
    assert!(
        app.take_config_save().is_none(),
        "Esc is not a save, and nothing was queued"
    );

    ouro::ui::persist(&mut app);
    assert!(!path.exists(), "and nothing was written");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn enter_on_a_field_row_moves_rather_than_saving() {
    let mut app = connected(Defaults::default(), true);

    app.apply(key(KeyCode::Char(',')));
    app.apply(key(KeyCode::Enter));

    assert!(
        matches!(app.overlay, Some(Overlay::Settings(_))),
        "finishing a sentence in a text box is not a decision to write a file"
    );
    assert!(app.take_config_save().is_none());
}

#[test]
fn settings_open_on_whatever_the_file_already_said() {
    let mut app = connected(
        Defaults {
            provider: Some("gemini".into()),
            workspace: Some("/srv/stored".into()),
            approval_mode: Some("auto_edit".into()),
        },
        true,
    );

    app.apply(key(KeyCode::Char(',')));

    let screen = render(&mut app, 130, 30);

    assert!(screen.row("gemini").contains("(3/3)"), "{}", screen.text());
    assert!(screen.contains("/srv/stored"), "{}", screen.text());
    assert!(
        screen.contains("auto_edit — edit files without asking"),
        "{}",
        screen.text()
    );
}

#[test]
fn a_stored_provider_this_runtime_does_not_serve_is_shown_rather_than_dropped() {
    let mut app = connected(
        Defaults {
            provider: Some("codex".into()),
            ..Defaults::default()
        },
        true,
    );

    app.apply(key(KeyCode::Char(',')));

    let screen = render(&mut app, 140, 30);

    assert!(
        screen
            .row("codex")
            .contains("from the config file; this runtime does not report it"),
        "a default written on another machine is a fact, not a value to silently discard: {}",
        screen.text()
    );

    // Still savable as itself: the runtime is the authority on whether a start works, and
    // this client does not overrule a file the operator wrote.
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    let pending = app.take_config_save().expect("a save");
    assert_eq!(pending.defaults.provider.as_deref(), Some("codex"));
}

#[test]
fn the_provider_rows_are_unset_then_the_probe_then_an_unserved_default() {
    let entries = ouro::model::ProviderEntry::decode_list(&providers());

    let plain = provider_choices(&entries, None);
    assert_eq!(
        plain,
        vec![
            ProviderChoice::Unset,
            ProviderChoice::Probed {
                name: "claude_code".into(),
                ready: true
            },
            ProviderChoice::Probed {
                name: "gemini".into(),
                ready: false
            },
        ]
    );

    // A stored default the runtime already reports does not get a second row.
    assert_eq!(provider_choices(&entries, Some("gemini")), plain);

    let unserved = provider_choices(&entries, Some("codex"));
    assert_eq!(unserved.len(), 4);
    assert_eq!(
        unserved[3],
        ProviderChoice::Unserved {
            name: "codex".into()
        }
    );

    assert_eq!(plain[0].name(), None);
    assert_eq!(plain[1].name(), Some("claude_code"));

    // Whitespace is not a stored default.
    assert_eq!(provider_choices(&entries, Some("  ")), plain);
}

#[test]
fn the_approval_cycler_agrees_with_itself_in_both_directions() {
    assert_eq!(approval_at(0), None);
    assert_eq!(approval_index(None), 0);

    for mode in ApprovalMode::ALL {
        let index = approval_index(Some(mode));
        assert_eq!(approval_at(index), Some(mode), "{mode:?}");
    }

    assert_eq!(approval_at(99), None);
}

// ----- prefilling the start dialog -----------------------------------------------------

fn field(app: &App) -> Option<NewField> {
    match &app.overlay {
        Some(Overlay::New(dialog)) => Some(dialog.field),
        _ => None,
    }
}

fn focus(app: &mut App, target: NewField) {
    for _ in 0..12 {
        if field(app) == Some(target) {
            return;
        }

        app.apply(key(KeyCode::Down));
    }

    panic!("the form never reached {target:?}");
}

#[test]
fn the_start_dialog_opens_on_the_defaults_the_file_states() {
    let mut app = connected(
        Defaults {
            provider: Some("gemini".into()),
            workspace: Some("/srv/stored".into()),
            approval_mode: Some("auto_edit".into()),
        },
        true,
    );

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    let _ = app.drain();

    app.apply(key(KeyCode::Char('n')));

    let screen = render(&mut app, 130, 30);

    assert!(screen.row("gemini").contains("(2/2)"), "{}", screen.text());
    assert!(
        screen.contains("/srv/stored"),
        "the stored workspace beats the launch directory: {}",
        screen.text()
    );
    assert!(
        !screen.contains("/home/operator/project"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("auto_edit — edit files without asking"),
        "{}",
        screen.text()
    );

    // Prefill, not decision: everything is still editable, and the start carries whatever
    // the rows read at the moment it is pressed.
    focus(&mut app, NewField::Provider);
    app.apply(key(KeyCode::Left));

    focus(&mut app, NewField::Workspace);
    for _ in 0..60 {
        app.apply(key(KeyCode::Backspace));
    }
    type_text(&mut app, "/elsewhere");

    focus(&mut app, NewField::ApprovalMode);
    app.apply(key(KeyCode::Left));

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a start");

    assert_eq!(call.params["provider"], "claude_code");
    assert_eq!(call.params["workspace"], "/elsewhere");
    assert_eq!(call.params["approval_mode"], "prompt");
}

#[test]
fn with_no_file_the_dialog_is_exactly_what_it_was() {
    let mut app = connected(Defaults::default(), true);

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    let _ = app.drain();

    app.apply(key(KeyCode::Char('n')));

    let screen = render(&mut app, 130, 30);

    assert!(
        screen.row("claude_code").contains("(1/2)"),
        "no stored default means the first entry, as before: {}",
        screen.text()
    );
    assert!(
        screen.contains("/home/operator/project"),
        "and the launch directory is still the workspace guess: {}",
        screen.text()
    );
    assert!(
        screen.contains("unset — the plane's own default"),
        "{}",
        screen.text()
    );
}

#[test]
fn a_provider_list_that_arrives_after_the_dialog_still_places_the_cursor() {
    let mut app = app(full_hello());
    app.launch_dir = Some("/home/operator/project".into());
    app.config.defaults.provider = Some("gemini".into());
    app.config.onboarding.welcomed = true;

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    // Opened before `runtime.providers` has answered: the dialog holds a name it cannot
    // point at yet.
    app.apply(key(KeyCode::Char('n')));

    let asked = app.drain();
    assert!(
        asked.iter().any(|call| call.method == "runtime.providers"),
        "the dialog asks for the list it is about to draw: {asked:?}"
    );

    answer(&mut app, Tag::Providers, providers());

    let screen = render(&mut app, 130, 30);
    assert!(screen.row("gemini").contains("(2/2)"), "{}", screen.text());
}

#[test]
fn a_late_provider_list_does_not_move_a_cursor_the_operator_already_moved() {
    let mut app = app(full_hello());
    app.config.defaults.provider = Some("gemini".into());
    app.config.onboarding.welcomed = true;

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    app.apply(key(KeyCode::Char('n')));
    let _ = app.drain();

    // The list arrives, the cursor lands on the stored default, and then the operator
    // moves it themselves.
    answer(&mut app, Tag::Providers, providers());
    app.apply(key(KeyCode::Right)); // gemini -> claude_code, wrapping

    // A refresh answering the same list must not put the cursor back on the default.
    answer(&mut app, Tag::Providers, providers());

    let screen = render(&mut app, 130, 30);
    assert!(
        screen.row("claude_code").contains("(1/2)"),
        "a default is applied once; the cursor is the operator's afterwards: {}",
        screen.text()
    );
}

#[test]
fn a_default_provider_this_runtime_does_not_serve_is_said_rather_than_guessed_at() {
    let mut app = connected(
        Defaults {
            provider: Some("codex".into()),
            ..Defaults::default()
        },
        true,
    );

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    let _ = app.drain();

    app.apply(key(KeyCode::Char('n')));

    let notice = app
        .notice
        .as_ref()
        .expect("a notice about the missing default");

    assert!(notice.text.contains("codex"), "{}", notice.text);
    assert!(
        notice.text.contains("this runtime reports"),
        "{}",
        notice.text
    );

    // The cursor stays where the list starts rather than pointing at nothing.
    let screen = render(&mut app, 130, 30);
    assert!(
        screen.row("claude_code").contains("(1/2)"),
        "{}",
        screen.text()
    );
}
