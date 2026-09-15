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

/// Opens the settings overlay the way an operator does.
///
/// `settings` is `off` as a bare chord since the key map was realigned (`ui-parity` T1):
/// a message may start with a comma, so the verb is `leader.settings` (`ctrl+x ,`) and
/// `/settings`.
fn open_settings(app: &mut App) {
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(',')));
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
        open_settings(&mut app);
        app.apply(key(KeyCode::F(2)));

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
    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));

    let screen = render(&mut app, 120, 34);

    assert!(
        screen.contains("the rows below are this client's session defaults"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("/home/operator/.config/ouroboros/config.toml"),
        "the file it writes is named on the screen that writes it: {}",
        screen.text()
    );
    assert!(screen.contains("[ save ]"), "{}", screen.text());
    app.apply(key(KeyCode::F(3)));
    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("as reported by the runtime"),
        "{}",
        screen.text()
    );
    // T2.8: the runtime's own name for itself, made readable.
    assert!(screen.contains("ouroboros"), "{}", screen.text());
    assert!(
        !screen.text().contains("ouroboros@golden"),
        "the raw node name reached the settings overlay:\n{}",
        screen.text()
    );
    assert!(screen.contains("127.0.0.1:4560"), "{}", screen.text());
}

#[test]
fn settings_start_unset_and_a_save_writes_exactly_what_the_rows_read() {
    let dir = scratch("save");
    let path = dir.join(config::CONFIG_FILE);

    let mut app = with_providers(Defaults::default());
    app.config_path = Some(path.clone());

    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));

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

    // workspace is the first row: clear the prefilled launch dir and type one
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

    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));
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

    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));
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

    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));
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

    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));

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

fn connection_providers(grok: &str, xai_source: Option<&str>) -> serde_json::Value {
    json!([{ "provider": "native", "status": { "installed": true, "compatible": true,
    "details": { "credentials": [
        {"provider": "openai_codex", "env": "OUROBOROS_OAUTH_FILE", "present": false},
        {"provider": "grok", "env": "OUROBOROS_GROK_AUTH_FILE", "present": grok == "present", "credential_state": grok, "source": "stored", "key": "must-never-be-retained"},
        {"provider": "openai", "env": "OPENAI_API_KEY", "present": false},
        {"provider": "anthropic", "env": "ANTHROPIC_API_KEY", "present": false},
        {"provider": "xai", "env": "XAI_API_KEY", "present": xai_source.is_some(), "source": xai_source},
        {"provider": "google", "env": "GOOGLE_API_KEY", "present": true, "source": "environment"}
    ]}}}])
}

#[test]
fn connections_show_sources_refresh_and_never_retain_secret_fields() {
    let mut app = connected(Defaults::default());
    open_settings(&mut app);
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("present", Some("environment")),
    );
    app.apply(key(KeyCode::Down));
    for (width, height) in [(120, 34), (80, 24)] {
        let screen = render(&mut app, width, height);
        assert!(screen.contains("Grok"), "{}", screen.text());
        assert!(screen.contains("Connected locally"), "{}", screen.text());
        assert!(screen.contains("grok login"), "{}", screen.text());
        assert!(!screen.contains("must-never-be-retained"));
    }
    assert!(!format!("{:?}", app.providers).contains("must-never-be-retained"));
    let _ = app.drain();
    app.apply(key(KeyCode::Char('r')));
    assert!(app
        .drain()
        .iter()
        .any(|call| call.method == "runtime.providers"));
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("invalid", None),
    );
    assert_eq!(app.settings_connections()[1].state(), "Needs attention");
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("unavailable", None),
    );
    assert_eq!(app.settings_connections()[1].state(), "Status unavailable");
}

#[test]
fn key_editor_masks_paste_submits_only_on_save_and_refreshes() {
    let mut app = connected(Defaults::default());
    open_settings(&mut app);
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("absent", None),
    );
    for _ in 0..4 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));
    app.apply(Msg::Paste("xai-private-settings-canary".into()));
    let screen = render(&mut app, 100, 30);
    assert!(screen.contains("xAI API key"), "{}", screen.text());
    assert!(!screen.contains("xai-private-settings-canary"));
    assert!(!format!("{:?}", app.overlay).contains("xai-private-settings-canary"));
    let _ = app.drain();
    app.apply(key(KeyCode::Enter));
    assert!(
        app.drain().is_empty(),
        "Enter in a text field is not a save"
    );
    app.apply(key(KeyCode::Enter));
    let calls = app.drain();
    let call = calls
        .iter()
        .find(|call| call.method == "credentials.xai.set")
        .expect("save key");
    assert_eq!(
        call.params,
        json!({"api_key": "xai-private-settings-canary"})
    );
    app.apply(Msg::Paste("not accepted while saving".into()));
    answer(
        &mut app,
        call.tag.clone(),
        json!({"present": true, "source": "stored"}),
    );
    assert!(app
        .drain()
        .iter()
        .any(|call| call.method == "runtime.providers"));
    assert!(render(&mut app, 120, 34).contains("Credentials saved privately"));
    assert!(
        app.take_config_save().is_none(),
        "keys never go in client preferences"
    );
}

#[test]
fn environment_and_read_scope_block_stored_key_edits() {
    for environment in [true, false] {
        let mut app = connected(Defaults::default());
        if !environment {
            app.hello.scope = "read".into();
        }
        open_settings(&mut app);
        answer(
            &mut app,
            Tag::Providers,
            connection_providers("absent", environment.then_some("environment")),
        );
        for _ in 0..4 {
            app.apply(key(KeyCode::Down));
        }
        let _ = app.drain();
        app.apply(key(KeyCode::Enter));
        assert!(matches!(&app.overlay, Some(Overlay::Settings(s)) if s.editor.is_none()));
        assert!(!app
            .drain()
            .iter()
            .any(|call| call.method == "credentials.xai.set"));
    }
}

#[test]
fn account_dialog_returns_to_settings_without_losing_defaults() {
    let mut app = connected(Defaults::default());
    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));
    type_text(&mut app, "/unsaved");
    app.apply(key(KeyCode::F(1)));
    app.apply(key(KeyCode::Enter));
    assert!(matches!(app.overlay, Some(Overlay::Account(_))));
    app.apply(key(KeyCode::Esc));
    assert!(
        matches!(&app.overlay, Some(Overlay::Settings(s)) if s.workspace.ends_with("/unsaved"))
    );
}

#[test]
fn account_logout_returns_to_settings_and_consumes_the_return_state() {
    let mut app = connected(Defaults::default());
    answer(
        &mut app,
        Tag::Account,
        json!({"credentialState": "present", "account": {"type": "chatgpt"}}),
    );
    open_settings(&mut app);
    app.apply(key(KeyCode::F(2)));
    type_text(&mut app, "/unsaved");
    app.apply(key(KeyCode::F(1)));
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Char('l')));
    answer(&mut app, Tag::AccountLogout, json!({}));
    assert!(
        matches!(&app.overlay, Some(Overlay::Settings(s)) if s.workspace.ends_with("/unsaved"))
    );
    assert!(app.settings_return.is_none());
}

#[test]
fn optional_credential_details_cannot_remove_a_usable_runtime_provider() {
    for details in [
        serde_json::Value::Null,
        json!({"credentials": null}),
        json!({"credentials": [
            {"provider": "xai", "env": "XAI_API_KEY", "present": true, "source": "stored"},
            {"provider": "broken", "present": "unknown"}
        ]}),
    ] {
        let mut app = connected(Defaults::default());
        answer(
            &mut app,
            Tag::Providers,
            json!([{"provider": "native", "status": {
                "installed": true, "compatible": true, "details": details
            }}]),
        );
        let providers = app.providers.value.as_ref().unwrap();
        assert_eq!(
            providers.len(),
            1,
            "optional details must not hide the runtime"
        );
        assert!(providers[0].ready());
        if details["credentials"].is_array() {
            assert_eq!(app.settings_connections()[4].state(), "Key configured");
        }
    }
}

#[test]
fn absent_probe_details_are_unavailable_instead_of_zero_configured() {
    let mut app = with_providers(Defaults::default());
    open_settings(&mut app);
    answer(&mut app, Tag::Providers, providers());
    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("Connection status unavailable"),
        "{}",
        screen.text()
    );
    assert!(!screen.contains("0 configured"));
}

#[test]
fn refreshed_selection_and_setup_target_the_same_connection() {
    let mut app = connected(Defaults::default());
    open_settings(&mut app);
    let mut report = connection_providers("absent", None);
    answer(&mut app, Tag::Providers, report.clone());
    for _ in 0..5 {
        app.apply(key(KeyCode::Down));
    }
    report[0]["status"]["details"]["credentials"]
        .as_array_mut()
        .unwrap()
        .pop();
    answer(&mut app, Tag::Providers, report);
    app.apply(key(KeyCode::Enter));
    assert!(
        matches!(&app.overlay, Some(Overlay::Settings(s)) if s.editor.as_ref().is_some_and(|e| e.provider == "xai"))
    );
}

#[test]
fn saving_a_key_during_a_probe_requests_a_fresh_report_after_that_probe() {
    let mut app = connected(Defaults::default());
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("absent", None),
    );
    open_settings(&mut app);
    assert!(app.providers.pending);
    for _ in 0..4 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));
    app.apply(Msg::Paste("private-key-canary".into()));
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));
    answer(
        &mut app,
        Tag::SettingsCredential {
            provider: "xai".into(),
        },
        json!({}),
    );
    let _ = app.drain();
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("absent", None),
    );
    assert!(
        app.drain()
            .iter()
            .any(|call| call.method == "runtime.providers"),
        "the older in-flight probe cannot satisfy the post-save refresh"
    );
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("absent", Some("stored")),
    );
    assert_eq!(app.settings_connections()[4].state(), "Key configured");
}

#[test]
fn compact_key_editor_keeps_save_and_failure_visible_with_long_workspace_id() {
    let mut app = connected(Defaults::default());
    open_settings(&mut app);
    answer(
        &mut app,
        Tag::Providers,
        connection_providers("absent", None),
    );
    for _ in 0..3 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));
    app.apply(Msg::Paste("private-key-canary".into()));
    assert!(render(&mut app, 60, 18).contains("blank clears saved ID"));
    app.apply(key(KeyCode::Tab));
    app.apply(Msg::Paste(format!("wrkspc_{}", "a".repeat(200))));
    app.apply(key(KeyCode::Tab));
    let screen = render(&mut app, 60, 18);
    assert!(screen.contains("[ Save key ]"), "{}", screen.text());
    app.apply(key(KeyCode::Enter));
    app.apply(Msg::Answer {
        tag: Tag::SettingsCredential {
            provider: "anthropic".into(),
        },
        result: Err(ouro::transport::ClientError::ConnectionClosed),
    });
    let screen = render(&mut app, 60, 18);
    assert!(screen.contains("[ Save key ]"), "{}", screen.text());
    assert!(screen.contains("Could not save"), "{}", screen.text());
    assert!(screen.contains("re-enter"), "{}", screen.text());
    assert!(screen.contains("the key to retry."), "{}", screen.text());
    assert!(!screen.contains("private-key-canary"));
}
