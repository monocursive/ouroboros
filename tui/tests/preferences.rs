//! The settings overlay, the file it writes, and what the config prefills into a start.
//!
//! Driven the way `tests/ui.rs` drives everything else: messages in, rendered frames out,
//! no terminal and no socket. The one exception is [`ouro::ui::persist`], which is the
//! driver's file write and is exercised here against a scratch directory — the App itself
//! only ever *asks* for a save, and that asking is what most of these tests read.
//!
//! Nothing below touches the real home. Every path is under the OS temp root, and the
//! config file location is passed to the App explicitly rather than discovered, so a test
//! run cannot write into the machine it runs on.
//!
//! These cover live code that lost its tests when the quick-start screen's test file was
//! rewritten for the coding-first shell: the overlay itself, `ui::persist`,
//! `App::take_config_save`, the approval cycler, and the `n` dialog's prefill.

mod support;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;

use ouro::config::{self, Config, Defaults, Onboarding};
use ouro::model::{ApprovalMode, Plane, SandboxMode};
use ouro::ui::app::{
    approval_at, approval_index, sandbox_at, sandbox_index, App, Msg, NewField, Overlay,
    SettingsField, Tab, Tag,
};

use support::{app, full_hello, render};

static SCRATCH: AtomicU32 = AtomicU32::new(0);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ouro-preferences-{name}-{}-{}",
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

fn apply_leader(app: &mut App, c: char) {
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(c)));
}

fn answer(app: &mut App, tag: Tag, value: serde_json::Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

/// `runtime.providers`, which now answers with the one provider this runtime serves.
fn providers() -> serde_json::Value {
    json!([
        {
            "provider": "native",
            "spec": {},
            "status": {
                "installed": true, "compatible": true, "authenticated": true,
                "version": "1.2.3", "executable": "/usr/bin/ouro"
            },
            "error": null
        }
    ])
}

/// An App that has connected, knows where its own files are, and has had `account.read`
/// answered — without which the coding home buffers every keystroke into its composer.
fn connected(defaults: Defaults) -> App {
    let mut app = app(full_hello());

    app.launch_dir = Some("/home/operator/project".into());
    app.data_dir = Some("/home/operator/.local/share/ouroboros".into());
    app.config_path = Some(PathBuf::from(
        "/home/operator/.config/ouroboros/config.toml",
    ));
    app.config = Config {
        defaults,
        onboarding: Onboarding {
            welcomed: true,
            mouse_hint_shown: true,
            ..Onboarding::default()
        },
        terminal: config::Terminal::default(),
        ..Config::default()
    };

    answer(
        &mut app,
        Tag::Account,
        json!({ "account": serde_json::Value::Null, "requiresOpenaiAuth": true }),
    );

    // Away from the coding home, where printable keys belong to the composer. `,` is a
    // global binding everywhere else; from the home it is reached through `ctrl+p`.
    app.tab = Tab::Dashboard;

    app
}

/// The same, with the provider list already answered.
fn with_providers(defaults: Defaults) -> App {
    let mut app = connected(defaults);

    answer(&mut app, Tag::Providers, providers());
    let _ = app.drain();

    app
}

// ----- the settings overlay -------------------------------------------------------------

#[test]
fn settings_open_from_anywhere_and_keep_the_two_kinds_of_fact_apart() {
    // Every tab but the coding home, whose composer owns printable keys by design.
    for tab in ['1', '3', '4'] {
        let mut app = with_providers(Defaults::default());

        app.apply(key(KeyCode::Char(tab)));
        app.apply(key(KeyCode::Char(',')));

        assert!(
            matches!(app.overlay, Some(Overlay::Settings(_))),
            "`,` must open settings on tab {tab}"
        );
    }

    // And from the home itself, through the palette that exists for exactly this.
    let mut app = with_providers(Defaults::default());
    app.tab = Tab::Sessions;
    app.apply(ctrl('p'));
    type_text(&mut app, "settings");
    app.apply(key(KeyCode::Enter));

    assert!(matches!(app.overlay, Some(Overlay::Settings(_))));

    let mut app = with_providers(Defaults::default());
    app.apply(key(KeyCode::Char(',')));

    let screen = render(&mut app, 120, 34);

    assert!(
        screen.contains("as reported by the runtime"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("ouroboros@golden"), "{}", screen.text());
    assert!(screen.contains("127.0.0.1:4560"), "{}", screen.text());
    assert!(
        screen.contains(
            "machines opens a guided setup; the other rows are this client's session defaults"
        ),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("standalone · open to create or join a fleet"),
        "the new first row says what Machines is for: {}",
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

    let mut app = with_providers(Defaults::default());
    app.config_path = Some(path.clone());

    app.apply(key(KeyCode::Char(',')));

    // Nothing has been touched, so there is nothing to write — a default is something an
    // operator states, not something a first open invents.
    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("unset — the plane's own default"),
        "{}",
        screen.text()
    );
    assert!(
        !screen.contains("changed, and not written yet"),
        "an untouched overlay has nothing to write: {}",
        screen.text()
    );

    // Machines is the first row. workspace is the second: clear the prefilled launch dir
    // and type one.
    app.apply(key(KeyCode::Down));
    for _ in 0..60 {
        app.apply(key(KeyCode::Backspace));
    }
    type_text(&mut app, "/srv/work");

    // approval: unset -> default -> prompt
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Right));

    let screen = render(&mut app, 120, 34);
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
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    assert!(app.overlay.is_none(), "saving closes the overlay");

    // The App asks; the driver writes. This is that driver step, run against a scratch
    // file rather than anyone's home.
    ouro::ui::persist(&mut app);

    let loaded = config::load(path.clone());

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

    let mut app = with_providers(Defaults::default());
    app.config_path = Some(path.clone());

    app.apply(key(KeyCode::Char(',')));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
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

/// `persist` is the driver's half of the same contract: it reports the failure rather than
/// letting the App believe a file it could not write.
#[test]
fn a_save_with_nowhere_to_write_says_so_instead_of_claiming_success() {
    let mut app = with_providers(Defaults::default());
    app.config_path = None;

    app.apply(key(KeyCode::Char(',')));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    ouro::ui::persist(&mut app);

    let notice = app.notice.as_ref().expect("a refusal");
    assert!(
        notice.text.contains("nowhere to keep preferences"),
        "{}",
        notice.text
    );

    // Drained exactly once: a save that was reported is not queued again on the next frame.
    assert!(app.take_config_save().is_none());
}

#[test]
fn enter_on_a_field_row_moves_rather_than_saving() {
    let mut app = with_providers(Defaults::default());

    app.apply(key(KeyCode::Char(',')));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    let Some(Overlay::Settings(settings)) = &app.overlay else {
        panic!("Enter on a field row must remain in Settings");
    };
    assert_eq!(settings.field, SettingsField::ApprovalMode);
    assert!(app.take_config_save().is_none());
}

#[test]
fn settings_open_on_whatever_the_file_already_said() {
    let mut app = with_providers(Defaults {
        workspace: Some("/srv/stored".into()),
        approval_mode: Some("auto_edit".into()),
        ..Defaults::default()
    });

    app.apply(key(KeyCode::Char(',')));

    let screen = render(&mut app, 130, 34);

    assert!(screen.contains("/srv/stored"), "{}", screen.text());
    assert!(
        screen.contains("auto_edit — edit files without asking"),
        "{}",
        screen.text()
    );
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

/// The sandbox cycler offers every value the schema declares, `unrestricted` included, and
/// the two directions agree about which row each one is.
#[test]
fn the_sandbox_cycler_reaches_every_mode_the_schema_declares() {
    assert_eq!(sandbox_at(0), None, "row zero is an absent parameter");
    assert_eq!(sandbox_index(None), 0);

    for mode in SandboxMode::ALL {
        let index = sandbox_index(Some(mode));
        assert_eq!(sandbox_at(index), Some(mode), "{mode:?}");
    }

    assert_eq!(sandbox_at(99), None);
}

/// `defaults.sandbox_mode = "unrestricted"` survives a write and a read.
///
/// [`config::normalise`] drops a value outside [`SandboxMode::ALL`] with a problem naming
/// it, because sending one would be a `-32602`. `unrestricted` is inside that list, so it
/// must round-trip untouched and reach the start dialog as a prefilled row — a stored
/// posture silently downgraded on load would be the worst possible failure here.
#[test]
fn full_access_survives_a_config_round_trip() {
    let dir = scratch("sandbox-round-trip");
    let path = dir.join(config::CONFIG_FILE);

    let mut written = Config::default();
    written.defaults.sandbox_mode = Some("unrestricted".into());
    written.save(&path).expect("a written config");

    let loaded = config::load(path.clone());

    assert!(
        loaded.problems.is_empty(),
        "a documented value is not a problem: {:?}",
        loaded.problems
    );
    assert_eq!(
        loaded.config.defaults.sandbox_mode(),
        Some(SandboxMode::Unrestricted)
    );
    assert!(
        fs::read_to_string(&path)
            .expect("a readable config")
            .contains("unrestricted"),
        "the file keeps the wire's own word"
    );

    // And a value that is not one of the four is still dropped, with a problem naming it.
    let mut invalid = Config::default();
    invalid.defaults.sandbox_mode = Some("yolo".into());
    invalid.save(&path).expect("a written config");

    let loaded = config::load(path);
    assert_eq!(loaded.config.defaults.sandbox_mode, None);
    assert!(
        loaded
            .problems
            .iter()
            .any(|problem| problem.contains("yolo") && problem.contains("unrestricted")),
        "the problem names the value and the four it could have been: {:?}",
        loaded.problems
    );

    fs::remove_dir_all(&dir).ok();
}

/// A stored full-access default reaches the start dialog as the row it prefills.
#[test]
fn the_start_dialog_opens_on_a_stored_full_access_default() {
    let mut app = ready_for_n(Defaults {
        sandbox_mode: Some("unrestricted".into()),
        ..Defaults::default()
    });

    apply_leader(&mut app, 'N');

    let screen = render(&mut app, 130, 34);
    assert!(
        screen
            .row("files")
            .contains("full access — shell runs with no OS sandbox"),
        "{}",
        screen.text()
    );
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

/// The Sessions tab with a session open. The always-on composer owns printable keys, so
/// the advanced start is `ctrl+x N` rather than a bare `n`.
fn ready_for_n(defaults: Defaults) -> App {
    let mut app = with_providers(defaults);

    app.tab = Tab::Sessions;
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    app.open_session(Plane::Interactive, "session-open".into());
    let _ = app.drain();

    app
}

#[test]
fn the_start_dialog_opens_on_the_defaults_the_file_states() {
    let mut app = ready_for_n(Defaults {
        model: Some("openai_codex:gpt-5.5".into()),
        workspace: Some("/srv/stored".into()),
        approval_mode: Some("auto_edit".into()),
        ..Defaults::default()
    });

    apply_leader(&mut app, 'N');

    let screen = render(&mut app, 130, 34);

    assert!(
        screen.contains("openai_codex:gpt-5.5"),
        "the stored model is what the dialog opens on: {}",
        screen.text()
    );
    assert!(
        screen.contains("/srv/stored"),
        "the stored workspace beats the launch directory: {}",
        screen.text()
    );
    assert!(
        screen.contains("auto_edit — edit files without asking"),
        "{}",
        screen.text()
    );

    // Prefill, not decision: everything is still editable, and the start carries whatever
    // the rows read at the moment it is pressed.
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

    assert_eq!(call.params["model"], "openai_codex:gpt-5.5");
    assert_eq!(call.params["workspace"], "/elsewhere");
    assert_eq!(call.params["approval_mode"], "prompt");
    assert!(
        call.params.get("provider").is_none(),
        "`provider` is not a start option and sending it would be -32602: {}",
        call.params
    );
}

#[test]
fn with_no_file_the_dialog_opens_on_the_model_a_first_session_would_use() {
    let mut app = ready_for_n(Defaults::default());
    apply_leader(&mut app, 'N');

    let screen = render(&mut app, 130, 34);

    assert!(
        screen.contains(ouro::ui::app::DEFAULT_MODEL),
        "no stored model means the one a first session runs on, stated rather than left \
         blank: {}",
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
