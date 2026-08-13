//! The quick-start screen, the settings overlay, and what the config file prefills.
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
use ouro::model::{ApprovalMode, Plane, SessionStatus};
use ouro::transport::ClientError;
use ouro::ui::app::{
    approval_at, approval_index, provider_choices, should_quick_start, App, Msg, NewField, Overlay,
    ProviderChoice, QuickZone, Tab, Tag,
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

/// Neither provider has an executable: the setup case the screen has to stay useful in.
fn nothing_installed() -> serde_json::Value {
    json!([
        {
            "provider": "claude_code",
            "spec": {},
            "status": {
                "installed": false, "compatible": false, "authenticated": "unknown",
                "executable": "claude"
            },
            "error": null
        },
        {
            "provider": "codex",
            "spec": {},
            "status": {
                "installed": false, "compatible": false, "authenticated": "unknown",
                "executable": "codex"
            },
            "error": null
        }
    ])
}

/// One live interactive session, as `interactive.list` answers it.
fn live_session() -> serde_json::Value {
    json!([{
        "_struct": "Ouroboros.Interactive.State",
        "id": "session-0000000000000000000001",
        "provider": "claude_code",
        "status": "running",
        "updated_at": "2026-01-01T00:00:00.000000Z"
    }])
}

/// An App that has connected and knows where its own files are.
fn connected(defaults: Defaults, onboarding: Onboarding) -> App {
    let mut app = app(full_hello());

    app.launch_dir = Some("/home/operator/project".into());
    app.data_dir = Some("/home/operator/.local/share/ouroboros".into());
    app.config_path = Some(PathBuf::from(
        "/home/operator/.config/ouroboros/config.toml",
    ));
    app.config = Config {
        defaults,
        onboarding,
    };

    app
}

/// The same, with the provider list already answered.
fn with_providers(defaults: Defaults, onboarding: Onboarding) -> App {
    let mut app = connected(defaults, onboarding);

    answer(&mut app, Tag::Providers, providers());
    let _ = app.drain();

    app
}

fn seen() -> Onboarding {
    Onboarding {
        welcomed: true,
        quick_start: true,
    }
}

// ----- when it appears ------------------------------------------------------------------

#[test]
fn the_decision_is_a_first_run_or_an_idle_node_and_nothing_else() {
    // A first run opens it whatever else is true: there is nothing to return to, and the
    // screen is how this client introduces itself.
    assert!(should_quick_start(true, true, 0));
    assert!(should_quick_start(true, true, 4));
    assert!(
        should_quick_start(true, false, 4),
        "the flag is about the steady state; a first run is not one"
    );

    // Afterwards it is the type-and-go path, so it needs both an idle node and the flag.
    assert!(should_quick_start(false, true, 0));
    assert!(!should_quick_start(false, true, 1));
    assert!(!should_quick_start(false, false, 0));
    assert!(!should_quick_start(false, false, 3));
}

#[test]
fn a_first_run_opens_it_at_once_without_waiting_on_a_list() {
    let mut app = connected(Defaults::default(), Onboarding::default());

    app.offer_quick_start();

    assert!(matches!(app.overlay, Some(Overlay::QuickStart(_))));

    // The provider list is what it draws, so that is asked for. The session lists are not:
    // a first run has nothing live by definition.
    let asked: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();

    assert_eq!(asked, vec!["runtime.providers".to_string()], "{asked:?}");
}

#[test]
fn a_returning_operator_gets_it_when_this_node_has_nothing_running() {
    let mut app = with_providers(Defaults::default(), seen());

    app.offer_quick_start();

    assert!(
        app.overlay.is_none(),
        "the answer is not knowable until both lists have spoken"
    );

    let asked: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert!(asked.contains(&"interactive.list".to_string()), "{asked:?}");
    assert!(asked.contains(&"coding.list".to_string()), "{asked:?}");

    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));

    assert!(
        app.overlay.is_none(),
        "one empty list is not the whole node: a coding task is still work to return to"
    );

    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    assert!(matches!(app.overlay, Some(Overlay::QuickStart(_))));
}

#[test]
fn a_node_with_live_work_is_left_alone() {
    let mut app = with_providers(Defaults::default(), seen());

    app.offer_quick_start();
    answer(&mut app, Tag::Sessions(Plane::Interactive), live_session());
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    assert!(
        app.overlay.is_none(),
        "a screen offering to start a session would be interrupting one to do it"
    );
}

#[test]
fn a_closed_session_is_not_work_to_return_to() {
    let mut app = with_providers(Defaults::default(), seen());

    app.offer_quick_start();

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{ "id": "old", "status": "closed" }]),
    );
    answer(
        &mut app,
        Tag::Sessions(Plane::Coding),
        json!([{ "id": "done", "status": "completed" }]),
    );

    assert!(SessionStatus::parse("closed").terminal());
    assert!(matches!(app.overlay, Some(Overlay::QuickStart(_))));
}

#[test]
fn a_status_this_build_does_not_know_counts_as_live() {
    let mut app = with_providers(Defaults::default(), seen());

    app.offer_quick_start();

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{ "id": "odd", "status": "hibernating" }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    assert!(
        app.overlay.is_none(),
        "an unrecognised status is not one this client may declare finished, and the safe \
         direction is to keep a screen off a node that may be busy"
    );
}

#[test]
fn the_flag_turns_the_steady_state_off_without_touching_the_first_run() {
    let off = Onboarding {
        welcomed: true,
        quick_start: false,
    };

    let mut app = with_providers(Defaults::default(), off.clone());
    app.offer_quick_start();

    assert!(app.overlay.is_none());
    assert!(
        app.drain().is_empty(),
        "a decision already made asks the runtime nothing"
    );

    // The same flag on a first run changes nothing: the marker is what that case turns on.
    let mut first = with_providers(
        Defaults::default(),
        Onboarding {
            welcomed: false,
            quick_start: false,
        },
    );

    first.offer_quick_start();
    assert!(matches!(first.overlay, Some(Overlay::QuickStart(_))));
}

#[test]
fn a_refused_session_list_settles_the_question_shut_rather_than_guessing() {
    let mut app = with_providers(Defaults::default(), seen());

    app.offer_quick_start();

    app.apply(Msg::Answer {
        tag: Tag::Sessions(Plane::Interactive),
        result: Err(ClientError::BadJson("nope".into())),
    });
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    assert!(
        app.overlay.is_none(),
        "a list that was refused is not a list that said none"
    );

    // And it stays settled: a later successful poll must not open it mid-session.
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    assert!(app.overlay.is_none());
}

#[test]
fn it_is_never_reopened_once_it_has_been_left() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());

    app.offer_quick_start();
    app.apply(key(KeyCode::Esc));

    assert!(app.overlay.is_none());

    app.offer_quick_start();
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    assert!(
        app.overlay.is_none(),
        "the decision is made once per process, whichever way it went"
    );
}

// ----- what it shows --------------------------------------------------------------------

#[test]
fn it_asks_for_a_model_and_a_prompt_and_states_the_rest() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.offer_quick_start();

    let screen = render(&mut app, 120, 34);

    assert!(
        screen.contains("pick a model, say what it should do, and press Enter."),
        "{}",
        screen.text()
    );

    // The picker: the probe, with the cursor on the one that is ready.
    assert!(
        screen.row("claude_code").contains("1.2.3"),
        "{}",
        screen.text()
    );
    assert!(
        screen.row("claude_code").starts_with("│> ") || screen.row("claude_code").contains("> ✓"),
        "the cursor starts on the provider that can actually run: {}",
        screen.text()
    );
    assert!(
        screen
            .row("gemini")
            .contains("no gemini on the runtime's PATH"),
        "a dim provider names the executable that was looked for: {}",
        screen.text()
    );

    // The prompt, and that leaving it empty is a complete answer.
    assert!(screen.contains("what should it do?"), "{}", screen.text());
    assert!(
        screen.contains("Enter with nothing here just opens a session"),
        "{}",
        screen.text()
    );

    // Stated, with where each came from.
    assert!(
        screen.contains("/home/operator/project — this terminal's directory"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("unset — the plane's own default"),
        "{}",
        screen.text()
    );

    // The ways out, and the two surfaces that own everything this one does not.
    assert!(screen.contains("Esc to the dashboard"), "{}", screen.text());
    assert!(
        screen.contains("n opens the full dialog"),
        "{}",
        screen.text()
    );
    assert!(screen.contains(", settings"), "{}", screen.text());
}

#[test]
fn a_first_run_also_says_where_this_client_keeps_things_and_a_later_one_does_not() {
    let mut first = with_providers(Defaults::default(), Onboarding::default());
    first.offer_quick_start();

    let screen = render(&mut first, 120, 34);

    assert!(screen.contains("first run"), "{}", screen.text());
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

    let mut later = with_providers(Defaults::default(), seen());
    later.offer_quick_start();
    answer(&mut later, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut later, Tag::Sessions(Plane::Coding), json!([]));

    let screen = render(&mut later, 120, 34);

    assert!(screen.contains("pick a model"), "{}", screen.text());
    assert!(
        !screen.contains("first run"),
        "someone who has seen the paths is not shown them every day: {}",
        screen.text()
    );
}

#[test]
fn an_attached_client_does_not_claim_to_know_the_runtimes_data_directory() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.data_dir = None;

    app.offer_quick_start();

    let screen = render(&mut app, 120, 34);

    assert!(
        screen.contains("with whoever started this runtime"),
        "a client that did not spawn it does not know where its files are: {}",
        screen.text()
    );
}

#[test]
fn a_stored_default_is_shown_as_a_stored_default_and_not_as_a_discovery() {
    let mut app = with_providers(
        Defaults {
            provider: Some("gemini".into()),
            workspace: Some("/srv/stated-once".into()),
            approval_mode: Some("auto_edit".into()),
        },
        Onboarding::default(),
    );

    app.offer_quick_start();

    let screen = render(&mut app, 130, 34);

    assert!(
        screen.contains("/srv/stated-once — your stored default"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("auto_edit — your stored default"),
        "{}",
        screen.text()
    );
    assert!(
        screen.row("gemini").contains("> "),
        "the stored provider is where the cursor starts: {}",
        screen.text()
    );
}

// ----- the setup case -------------------------------------------------------------------

#[test]
fn with_nothing_installed_the_screen_is_the_setup_surface() {
    let mut app = connected(Defaults::default(), Onboarding::default());
    answer(&mut app, Tag::Providers, nothing_installed());
    let _ = app.drain();

    app.offer_quick_start();

    let screen = render(&mut app, 120, 34);

    // The probed executables are the content: that hint is the setup instruction.
    assert!(
        screen.contains("no claude on the runtime's PATH"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("no codex on the runtime's PATH"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("none found an executable"),
        "{}",
        screen.text()
    );
    assert!(
        // Wrapped across two rows at this width, so it is asserted in the piece a reader
        // actually sees on one of them.
        screen.contains("the runtime decides, not"),
        "a probe is a heuristic and the screen says so: {}",
        screen.text()
    );

    // Still selectable, and Enter still tries: this client does not overrule the runtime.
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("an uninstalled provider is still the operator's to try");

    assert_eq!(call.params["provider"], "claude_code");
}

#[test]
fn r_probes_again_from_the_picker_and_ctrl_r_from_anywhere() {
    let mut app = connected(Defaults::default(), Onboarding::default());
    answer(&mut app, Tag::Providers, nothing_installed());
    let _ = app.drain();

    app.offer_quick_start();
    let _ = app.drain();

    // The prompt has focus, so a bare `r` is a letter.
    app.apply(key(KeyCode::Char('r')));

    assert!(
        app.drain().is_empty(),
        "letters belong to the prompt; a picker that swallowed one would be a text box \
         that silently is not one"
    );

    // ctrl-r reaches the probe without leaving the prompt.
    app.apply(ctrl('r'));

    let asked: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert_eq!(asked, vec!["runtime.providers".to_string()], "{asked:?}");

    // The answer arrives with the CLI now installed, and the screen says so without the
    // operator having left it.
    answer(&mut app, Tag::Providers, providers());

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.row("claude_code").contains("1.2.3"),
        "{}",
        screen.text()
    );

    // And in the picker zone a bare `r` does the same thing.
    app.apply(key(KeyCode::Tab));
    app.apply(key(KeyCode::Char('r')));

    let asked: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert_eq!(asked, vec!["runtime.providers".to_string()], "{asked:?}");
}

#[test]
fn a_gateway_that_will_not_list_providers_says_so_and_refuses_honestly() {
    // A `read` listener serves no `runtime.providers`, so the call is answered locally with
    // -32601 rather than sent — and the screen says which method, where the list would be.
    let mut app = app(support::hello(&["hello", "runtime.status"]));
    app.config_path = Some(PathBuf::from("/tmp/config.toml"));

    app.offer_quick_start();

    let screen = render(&mut app, 120, 34);

    assert!(
        screen.contains("runtime.providers was refused"),
        "{}",
        screen.text()
    );

    app.apply(key(KeyCode::Enter));

    assert!(
        app.drain().is_empty(),
        "there is nothing to start, so nothing is sent"
    );

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("runtime.providers was refused"),
        "the refusal is shown on the screen that produced it: {}",
        screen.text()
    );

    // And the gateway not serving the start verb is said before Enter, not after: it is
    // knowable from the handshake, and a prompt typed into a listener that will refuse it
    // is a sentence wasted.
    assert!(
        screen.contains("does not serve interactive.start"),
        "{}",
        screen.text()
    );
}

#[test]
fn a_read_listener_says_the_start_will_be_refused_before_a_prompt_is_typed() {
    let mut app = app(support::read_hello(&[
        "hello",
        "runtime.providers",
        "interactive.start",
    ]));

    app.config_path = Some(PathBuf::from("/tmp/config.toml"));
    answer(&mut app, Tag::Providers, providers());
    let _ = app.drain();

    app.offer_quick_start();

    let screen = render(&mut app, 120, 34);

    assert!(
        screen.contains("this listener runs at scope `read`"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("-32003"), "{}", screen.text());
}

// ----- the keyboard ---------------------------------------------------------------------

fn zone(app: &App) -> Option<QuickZone> {
    match &app.overlay {
        Some(Overlay::QuickStart(quick)) => Some(quick.zone),
        _ => None,
    }
}

fn cursor(app: &App) -> Option<usize> {
    match &app.overlay {
        Some(Overlay::QuickStart(quick)) => Some(quick.provider),
        _ => None,
    }
}

fn prompt(app: &App) -> Option<String> {
    match &app.overlay {
        Some(Overlay::QuickStart(quick)) => Some(quick.prompt.clone()),
        _ => None,
    }
}

#[test]
fn typing_starts_immediately_and_letters_never_reach_the_picker() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.offer_quick_start();

    assert_eq!(
        zone(&app),
        Some(QuickZone::Prompt),
        "the first thing a person can do is the thing they came to do"
    );

    // Every one of these is a global binding outside an overlay — a tab switch, a quit
    // dialog, a refresh, a new-session form. Inside the prompt they are letters.
    type_text(&mut app, "just kill 7 sessions, q");

    assert_eq!(prompt(&app).as_deref(), Some("just kill 7 sessions, q"));
    assert_eq!(app.tab, Tab::Dashboard);
    assert!(matches!(app.overlay, Some(Overlay::QuickStart(_))));

    app.apply(key(KeyCode::Backspace));
    assert_eq!(prompt(&app).as_deref(), Some("just kill 7 sessions, "));
}

#[test]
fn the_arrows_and_ctrl_np_move_the_picker_from_either_zone() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.offer_quick_start();

    assert_eq!(cursor(&app), Some(0));

    // Still in the prompt, and the arrows are unambiguous there.
    app.apply(key(KeyCode::Down));
    assert_eq!(cursor(&app), Some(1));
    assert_eq!(
        zone(&app),
        Some(QuickZone::Prompt),
        "arrows do not steal focus"
    );

    app.apply(key(KeyCode::Up));
    assert_eq!(cursor(&app), Some(0));

    // For hands that are already typing.
    app.apply(ctrl('n'));
    assert_eq!(cursor(&app), Some(1));
    assert_eq!(prompt(&app).as_deref(), Some(""), "ctrl-n is not an `n`");

    app.apply(ctrl('p'));
    assert_eq!(cursor(&app), Some(0));

    // Two providers, so moving past either end wraps rather than sticking.
    app.apply(key(KeyCode::Up));
    assert_eq!(cursor(&app), Some(1));
}

#[test]
fn tab_swaps_zones_and_jk_move_only_where_the_picker_has_focus() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.offer_quick_start();

    // In the prompt, `j` and `k` are letters.
    type_text(&mut app, "jk");
    assert_eq!(prompt(&app).as_deref(), Some("jk"));
    assert_eq!(cursor(&app), Some(0));

    app.apply(key(KeyCode::Tab));
    assert_eq!(zone(&app), Some(QuickZone::Picker));

    app.apply(key(KeyCode::Char('j')));
    assert_eq!(cursor(&app), Some(1));
    assert_eq!(
        prompt(&app).as_deref(),
        Some("jk"),
        "and in the picker they are not typed"
    );

    app.apply(key(KeyCode::Char('k')));
    assert_eq!(cursor(&app), Some(0));

    app.apply(key(KeyCode::Tab));
    assert_eq!(zone(&app), Some(QuickZone::Prompt));
}

// ----- Enter, and Esc -------------------------------------------------------------------

#[test]
fn enter_records_the_model_starts_a_session_and_sends_the_prompt() {
    let dir = scratch("enter");
    let path = dir.join(config::CONFIG_FILE);

    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.config_path = Some(path.clone());

    app.offer_quick_start();
    type_text(&mut app, "fix the flaky test");
    app.apply(key(KeyCode::Enter));

    // The start goes through the same `StartRequest` the `n` dialog builds, so it carries
    // exactly the options the gateway allowlists and no more.
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a start");

    assert_eq!(start.params["provider"], "claude_code");
    assert_eq!(start.params["workspace"], "/home/operator/project");
    assert_eq!(
        start.params.as_object().expect("an object").len(),
        2,
        "approval_mode is unset, so it is omitted rather than sent: {:?}",
        start.params
    );
    assert_eq!(start.timeout, Some(ouro::ui::app::START_TIMEOUT));

    // The screen stays up, saying it is waiting, and takes no further edits.
    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("starting"), "{}", screen.text());

    type_text(&mut app, "more");
    assert_eq!(prompt(&app).as_deref(), Some("fix the flaky test"));

    // The provider and the marker are queued for the file the moment Enter is pressed:
    // pressing Enter on a model *is* choosing it.
    ouro::ui::persist(&mut app);

    let loaded = config::load(path.clone());
    assert_eq!(
        loaded.config.defaults.provider.as_deref(),
        Some("claude_code")
    );
    assert!(loaded.config.onboarding.welcomed);

    // The runtime answers, and the prompt goes out as the session's first message — the
    // same order `ouro new -m` uses, because until now there was nothing to send it to.
    answer(
        &mut app,
        Tag::Start {
            plane: Plane::Interactive,
        },
        json!({ "_struct": "Ouroboros.Interactive.Ref", "id": "session-1" }),
    );

    let calls = app.drain();

    let message = calls
        .iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the typed prompt is sent");

    assert_eq!(message.params["id"], "session-1");
    assert_eq!(message.params["input"], "fix the flaky test");

    assert!(
        calls
            .iter()
            .any(|call| call.method == "interactive.subscribe"),
        "and the transcript is subscribed: {calls:?}"
    );

    // The transcript is open with the composer ready for the follow-up.
    assert!(app.overlay.is_none());
    assert_eq!(app.tab, Tab::Sessions);
    assert_eq!(
        app.sessions.open,
        Some((Plane::Interactive, "session-1".into()))
    );
    assert!(
        app.sessions.composer.is_some(),
        "the next thing typed should be the next thing said"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_empty_prompt_is_a_complete_answer() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.offer_quick_start();

    app.apply(key(KeyCode::Enter));

    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a start");

    assert_eq!(start.params["provider"], "claude_code");

    answer(
        &mut app,
        Tag::Start {
            plane: Plane::Interactive,
        },
        json!({ "id": "session-2" }),
    );

    let calls = app.drain();

    assert!(
        !calls
            .iter()
            .any(|call| call.method == "interactive.send_message"),
        "nothing was typed, so nothing is sent: {calls:?}"
    );
    assert!(app.sessions.composer.is_some(), "and the composer is open");
    assert_eq!(app.tab, Tab::Sessions);
}

#[test]
fn a_refusal_renders_on_the_screen_that_produced_it() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());
    app.offer_quick_start();

    type_text(&mut app, "do the thing");
    app.apply(key(KeyCode::Enter));

    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a start");

    app.apply(Msg::Answer {
        tag: start.tag,
        result: Err(ClientError::Rpc(
            serde_json::from_value(json!({
                "code": -32006,
                "message": "the runtime refused the call",
                "data": ["provider_not_authenticated", "claude_code"]
            }))
            .expect("an error"),
        )),
    });

    let screen = render(&mut app, 130, 34);

    assert!(
        screen.contains("pick a model"),
        "the screen is still up: {}",
        screen.text()
    );
    assert!(
        screen.contains("provider_not_authenticated"),
        "the runtime's own reason, verbatim, where it happened: {}",
        screen.text()
    );
    assert!(
        screen.contains("do the thing"),
        "and what was typed is still there to press Enter on again: {}",
        screen.text()
    );

    // The prompt must not be carried into a later session that did start.
    app.apply(key(KeyCode::Enter));
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a second attempt");

    app.apply(Msg::Answer {
        tag: start.tag,
        result: Ok(json!({ "id": "session-3" })),
    });

    let sent = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the retyped prompt is sent once");

    assert_eq!(sent.params["input"], "do the thing");
}

#[test]
fn esc_goes_to_the_dashboard_with_nothing_started_and_the_marker_written() {
    let mut app = with_providers(
        Defaults::default(),
        Onboarding {
            welcomed: false,
            quick_start: true,
        },
    );

    app.offer_quick_start();
    app.apply(key(KeyCode::Down)); // move the cursor somewhere it was not
    app.apply(key(KeyCode::Esc));

    assert!(app.overlay.is_none());
    assert_eq!(app.tab, Tab::Dashboard);

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.start"),
        "escaping starts nothing"
    );

    let pending = app.take_config_save().expect("the marker is written");

    assert!(pending.onboarding.welcomed);
    assert_eq!(
        pending.defaults.provider, None,
        "a provider the cursor happened to be on is not a choice the operator made"
    );
}

#[test]
fn ctrl_c_takes_the_same_exit_esc_does() {
    let mut app = with_providers(Defaults::default(), Onboarding::default());

    app.offer_quick_start();
    app.apply(ctrl('c'));

    assert!(app.overlay.is_none());
    assert_eq!(app.tab, Tab::Dashboard);
    assert!(app.config.onboarding.welcomed);
    assert!(app.take_config_save().is_some());
}

// ----- the settings overlay ------------------------------------------------------------

#[test]
fn comma_opens_settings_from_any_tab_and_keeps_the_two_kinds_of_fact_apart() {
    for tab in ['1', '2', '3', '4', '5', '6', '7'] {
        let mut app = with_providers(Defaults::default(), seen());

        app.apply(key(KeyCode::Char(tab)));
        app.apply(key(KeyCode::Char(',')));

        assert!(
            matches!(app.overlay, Some(Overlay::Settings(_))),
            "`,` must open settings on tab {tab}"
        );
    }

    let mut app = with_providers(Defaults::default(), seen());
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
        screen.contains("defaults this client remembers"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("they prefill the start screens, nothing more"),
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

    let mut app = with_providers(Defaults::default(), seen());
    app.config_path = Some(path.clone());

    app.apply(key(KeyCode::Char(',')));

    // Nothing stored, so the picker starts on "unset" — a default is something an operator
    // states, not something a first open invents.
    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("unset — stated per session"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("on — opens when this node has nothing running"),
        "the quick-start flag is a row like any other: {}",
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

    // quick start: on -> off
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Right));

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("prompt — ask before every action"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("off — go straight to the dashboard"),
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
    assert!(!loaded.config.onboarding.quick_start);
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

    let mut app = with_providers(Defaults::default(), seen());
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
    let mut app = with_providers(Defaults::default(), seen());

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
    let mut app = with_providers(
        Defaults {
            provider: Some("gemini".into()),
            workspace: Some("/srv/stored".into()),
            approval_mode: Some("auto_edit".into()),
        },
        Onboarding {
            welcomed: true,
            quick_start: false,
        },
    );

    app.apply(key(KeyCode::Char(',')));

    let screen = render(&mut app, 130, 34);

    assert!(screen.row("gemini").contains("(3/3)"), "{}", screen.text());
    assert!(screen.contains("/srv/stored"), "{}", screen.text());
    assert!(
        screen.contains("auto_edit — edit files without asking"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("off — go straight to the dashboard"),
        "{}",
        screen.text()
    );
}

#[test]
fn a_stored_provider_this_runtime_does_not_serve_is_shown_rather_than_dropped() {
    let mut app = with_providers(
        Defaults {
            provider: Some("codex".into()),
            ..Defaults::default()
        },
        seen(),
    );

    app.apply(key(KeyCode::Char(',')));

    let screen = render(&mut app, 140, 34);

    assert!(
        screen
            .row("codex")
            .contains("from the config file; this runtime does not report it"),
        "a default written on another machine is a fact, not a value to silently discard: {}",
        screen.text()
    );

    // Still savable as itself: the runtime is the authority on whether a start works, and
    // this client does not overrule a file the operator wrote.
    for _ in 0..4 {
        app.apply(key(KeyCode::Down));
    }
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

/// The Sessions tab, with the quick-start screen already out of the way.
fn ready_for_n(defaults: Defaults) -> App {
    let mut app = with_providers(defaults, seen());

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    let _ = app.drain();

    app
}

#[test]
fn the_start_dialog_opens_on_the_defaults_the_file_states() {
    let mut app = ready_for_n(Defaults {
        provider: Some("gemini".into()),
        workspace: Some("/srv/stored".into()),
        approval_mode: Some("auto_edit".into()),
    });

    app.apply(key(KeyCode::Char('n')));

    let screen = render(&mut app, 130, 34);

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
    let mut app = ready_for_n(Defaults::default());
    app.apply(key(KeyCode::Char('n')));

    let screen = render(&mut app, 130, 34);

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
fn a_provider_list_that_arrives_after_a_dialog_still_places_the_cursor() {
    // The `n` dialog, opened before `runtime.providers` has answered.
    let mut app = connected(
        Defaults {
            provider: Some("gemini".into()),
            ..Defaults::default()
        },
        seen(),
    );

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    app.apply(key(KeyCode::Char('n')));

    let asked = app.drain();
    assert!(
        asked.iter().any(|call| call.method == "runtime.providers"),
        "the dialog asks for the list it is about to draw: {asked:?}"
    );

    answer(&mut app, Tag::Providers, providers());

    let screen = render(&mut app, 130, 34);
    assert!(screen.row("gemini").contains("(2/2)"), "{}", screen.text());

    // And the quick-start screen, which has the same problem and the same answer.
    let mut quick = connected(
        Defaults {
            provider: Some("gemini".into()),
            ..Defaults::default()
        },
        Onboarding::default(),
    );

    quick.offer_quick_start();
    assert_eq!(cursor(&quick), Some(0));

    answer(&mut quick, Tag::Providers, providers());
    assert_eq!(
        cursor(&quick),
        Some(1),
        "the stored default, once it can be pointed at"
    );
}

#[test]
fn a_late_provider_list_does_not_move_a_cursor_the_operator_already_moved() {
    let mut app = ready_for_n(Defaults {
        provider: Some("gemini".into()),
        ..Defaults::default()
    });

    app.apply(key(KeyCode::Char('n')));
    let _ = app.drain();

    app.apply(key(KeyCode::Right)); // gemini -> claude_code, wrapping

    // A refresh answering the same list must not put the cursor back on the default.
    answer(&mut app, Tag::Providers, providers());

    let screen = render(&mut app, 130, 34);
    assert!(
        screen.row("claude_code").contains("(1/2)"),
        "a default is applied once; the cursor is the operator's afterwards: {}",
        screen.text()
    );
}

#[test]
fn a_default_provider_this_runtime_does_not_serve_is_said_rather_than_guessed_at() {
    let mut app = ready_for_n(Defaults {
        provider: Some("codex".into()),
        ..Defaults::default()
    });

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
    let screen = render(&mut app, 130, 34);
    assert!(
        screen.row("claude_code").contains("(1/2)"),
        "{}",
        screen.text()
    );
}

#[test]
fn the_quick_start_screen_falls_back_to_the_first_ready_model() {
    // A stored default this runtime does not serve, on the screen whose whole purpose is
    // to be one keystroke from a running session.
    let mut app = with_providers(
        Defaults {
            provider: Some("codex".into()),
            ..Defaults::default()
        },
        Onboarding::default(),
    );

    app.offer_quick_start();

    assert_eq!(
        cursor(&app),
        Some(0),
        "claude_code is the one whose probe found an executable"
    );

    let notice = app.notice.as_ref().expect("a notice naming the stored one");
    assert!(notice.text.contains("codex"), "{}", notice.text);
}
