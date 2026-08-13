//! The UI against a real runtime, gated by `OUROBOROS_TUI_INTEGRATION=1`.
//!
//! ## What this proves, and what it deliberately does not
//!
//! It spawns `mix run --no-halt` under this client's own spawn posture, attaches with the
//! real transport and the real reconnect hook, and drives the real `App` — the only thing
//! missing is the terminal, which is a `TestBackend`. So it proves that the tabs render
//! from *live* data: the availability matrix the running node reports, the providers it
//! actually serves, the session lists it actually has, and the runtime's own log lines in
//! the ring.
//!
//! **It starts no session, and that is a finding rather than a shortcut.** The
//! deterministic adapter this project tests the interactive plane with —
//! `Ouroboros.Test.HarnessAdapter`, provider `:ouroboros_test` — lives in `test/support`,
//! and [mix.exs](../../mix.exs) compiles that directory only under `MIX_ENV=test`. A
//! `--dev` daemon therefore registers exactly `Jido.Harness.Registry`'s nine builtins —
//! amp, claude, codex, gemini, kimi, opencode, grok, pi, zai — every one of which shells
//! out to a real coding CLI and bills a real account. There is no harmless provider to
//! start a session with, so this test asserts that the *refusals* are typed and readable
//! instead, which is the part a UI has to get right anyway.
//!
//! The runtime is stopped through the same path the quit dialog's "shut down" takes:
//! `runtime.shutdown` first, then `Daemon::terminate`'s SIGTERM → grace → SIGKILL.

mod support;

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use ouro::model::Plane;
use ouro::runtime::{self, Launcher, Output};
use ouro::transport::{self, TransportConfig};
use ouro::ui::app::{App, Mode, Msg, NoticeKind, Tab};

use support::render;

fn enabled() -> bool {
    std::env::var("OUROBOROS_TUI_INTEGRATION").as_deref() == Ok("1")
}

fn scratch_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ouro-ui-integration-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch data directory");
    dir
}

/// Applies whatever the App queued, one round at a time, until it stops asking.
async fn settle(
    app: &mut App,
    client: &ouro::transport::Client,
    sender: &tokio::sync::mpsc::UnboundedSender<Msg>,
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<Msg>,
    notifications: &mut tokio::sync::mpsc::Receiver<ouro::proto::Notification>,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    loop {
        for call in app.drain() {
            let client = client.clone();
            let sender = sender.clone();

            tokio::spawn(async move {
                let result = client.call(&call.method, call.params).await;
                let _ = sender.send(Msg::Answer {
                    tag: call.tag,
                    result,
                });
            });
        }

        let quiet = tokio::select! {
            message = receiver.recv() => {
                if let Some(message) = message { app.apply(message); }
                false
            }
            notification = notifications.recv() => {
                if let Some(notification) = notification {
                    app.apply(Msg::Notification(notification));
                }
                false
            }
            _idle = tokio::time::sleep(Duration::from_millis(250)) => true,
        };

        // `busy` as well as `has_outbound`: `runtime.providers` probes each adapter by
        // shelling out, so the connection is legitimately silent for seconds while the
        // answer is still coming.
        let settled = quiet && !app.has_outbound() && !app.busy();

        if settled || tokio::time::Instant::now() >= deadline {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ui_draws_a_live_dev_runtime_and_stops_it() {
    if !enabled() {
        eprintln!("skipped: set OUROBOROS_TUI_INTEGRATION=1 to run against a real runtime");
        return;
    }

    let repo_root = runtime::find_repo_root(&PathBuf::from(env!("CARGO_MANIFEST_DIR")))
        .expect("an ouroboros checkout above this crate");

    let data_dir = scratch_data_dir();
    let token_file = data_dir.join(runtime::TOKEN_FILE);
    let token = runtime::write_token(&token_file).expect("a token");

    // The lock the second `ouro` would lose: taken here for exactly the spawn window, so
    // the smoke exercises the same acquisition path the binary uses.
    let lock = runtime::acquire_spawn_lock(&data_dir).expect("the spawn lock");

    assert!(
        runtime::acquire_spawn_lock(&data_dir).is_err(),
        "a second client must not be able to spawn into this data directory"
    );

    let launcher = Launcher::Dev {
        repo_root: repo_root.clone(),
    };

    eprintln!("spawning `mix run --no-halt` in {}", repo_root.display());

    let mut daemon =
        runtime::spawn(&launcher, &data_dir, &token_file, Output::Ring).expect("a spawned runtime");

    let publication = match daemon
        .wait_ready(&data_dir, launcher.ready_deadline())
        .await
    {
        Ok(publication) => publication,
        Err(error) => {
            let _ = daemon.terminate(Duration::from_secs(10)).await;
            panic!("the runtime never became ready: {error:#}");
        }
    };

    drop(lock);

    eprintln!(
        "gateway.json: port={} pid={} node={} scope={}",
        publication.port, publication.pid, publication.node, publication.scope
    );

    let address = std::net::SocketAddr::from(([127, 0, 0, 1], publication.port));

    let (hook, channel) = ouro::ui::hook();
    let mut config = TransportConfig::new(address, token);
    config.reconnect = true;

    let connected = match transport::connect(config, hook).await {
        Ok(connected) => connected,
        Err(error) => {
            eprintln!("{}", daemon.log_tail(60));
            let _ = daemon.terminate(Duration::from_secs(10)).await;
            panic!("the handshake failed: {error}");
        }
    };

    let hello = connected.hello.clone();

    eprintln!(
        "hello: server={} node={} role={} scope={} methods={}",
        hello.server,
        hello.node,
        hello.role,
        hello.scope,
        hello.methods.len()
    );

    assert_eq!(hello.protocol, 1);
    assert_eq!(hello.scope, "operate", "the spawner asks for operate scope");
    assert!(hello.serves("runtime.shutdown"));

    let mut app = App::new(
        Mode::Spawned { pid: daemon.pid() },
        address.to_string(),
        hello.clone(),
        Some(daemon.logs()),
    );

    let (cursors, sender, mut receiver) = channel.into_parts();
    app.cursors = cursors;

    let mut notifications = connected.notifications;
    let client = connected.client.clone();

    // ----- tab 1: the Dashboard, from live data -------------------------------------

    app.apply(Msg::Tick);
    settle(
        &mut app,
        &client,
        &sender,
        &mut receiver,
        &mut notifications,
    )
    .await;

    let screen = render(&mut app, 140, 34);
    eprintln!("--- Dashboard ---\n{}", screen.text());

    let status = app
        .status
        .value
        .as_ref()
        .unwrap_or_else(|| panic!("runtime.status never decoded: {:?}", app.status.error));

    assert_eq!(status.node, publication.node);
    assert!(
        !status.availability.is_empty(),
        "an availability map with no planes in it is not a readable one"
    );

    for (plane, state) in &status.availability {
        eprintln!("availability {plane} = {}", state.as_str());
        assert!(screen.contains(plane), "{plane} is not on the Dashboard");
    }

    assert!(screen.contains(&publication.node));

    // ----- runtime.providers, and why no session is started -------------------------

    let providers =
        app.providers.value.as_ref().unwrap_or_else(|| {
            panic!("runtime.providers never decoded: {:?}", app.providers.error)
        });

    let names: Vec<&str> = providers
        .iter()
        .map(|entry| entry.provider.as_str())
        .collect();

    eprintln!("providers: {names:?}");

    assert!(
        !names.contains(&"ouroboros_test"),
        "the deterministic adapter lives in test/support and mix.exs compiles that only \
         under MIX_ENV=test; if this ever passes, the smoke below can start a real session"
    );

    for name in &names {
        assert!(
            !matches!(*name, "ouroboros_test"),
            "unexpected provider {name}"
        );
    }

    // ----- tab 2: empty lists, and a typed refusal ----------------------------------

    app.apply(Msg::Key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('2'),
        crossterm::event::KeyModifiers::NONE,
    )));

    settle(
        &mut app,
        &client,
        &sender,
        &mut receiver,
        &mut notifications,
    )
    .await;

    let sessions = app.sessions.merged();
    eprintln!("sessions: {}", sessions.len());

    assert!(
        sessions.is_empty(),
        "a freshly started dev runtime has no sessions"
    );

    let screen = render(&mut app, 140, 34);
    eprintln!("--- Sessions ---\n{}", screen.text());
    // Wrapped across the narrow pane, so only the head of the sentence is one row.
    assert!(
        screen.contains("no interactive sessions"),
        "{}",
        screen.text()
    );

    // Subscribing to a session that does not exist is the closest this can get to the
    // streaming path without invoking a real provider. The point is that the refusal is
    // typed and lands in the UI as a sentence, not as a hang.
    app.open_session(Plane::Interactive, "session-that-does-not-exist".into());

    settle(
        &mut app,
        &client,
        &sender,
        &mut receiver,
        &mut notifications,
    )
    .await;

    let notice = app
        .notice
        .as_ref()
        .expect("a refusal has to reach the operator");

    eprintln!("refusal notice: {}", notice.text);

    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(
        notice.text.contains("session-that-does-not-exist"),
        "the refusal must name what was refused: {}",
        notice.text
    );
    assert!(
        notice.text.contains("-3200"),
        "the refusal must carry the gateway's code: {}",
        notice.text
    );

    // And the client stopped asking rather than spinning against a session that is not
    // there.
    assert!(!app.has_outbound());

    // ----- the read tabs all draw from live answers ---------------------------------

    for (digit, tab) in [
        ('3', Tab::Agents),
        ('4', Tab::Teams),
        ('5', Tab::Plans),
        ('6', Tab::Upgrade),
        ('7', Tab::Logs),
    ] {
        app.apply(Msg::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(digit),
            crossterm::event::KeyModifiers::NONE,
        )));

        settle(
            &mut app,
            &client,
            &sender,
            &mut receiver,
            &mut notifications,
        )
        .await;

        let screen = render(&mut app, 140, 34);
        eprintln!("--- {} ---\n{}", tab.title(), screen.text());

        assert_eq!(app.tab, tab);
        assert!(screen.contains(tab.title()));
    }

    // The Logs tab is the ring this client filled from the child's own pipes.
    assert!(
        !daemon.logs().is_empty(),
        "a booted runtime prints something, and the Logs tab is where it goes"
    );

    // ----- an operate verb, refused without inventing work --------------------------

    // `interactive.interrupt` on a session that does not exist is a mutating verb this
    // listener is allowed to call, so it proves the operate path end to end without
    // asking a provider to do anything.
    let answer = client
        .call(
            "interactive.interrupt",
            json!({ "id": "session-that-does-not-exist" }),
        )
        .await
        .expect_err("no such session");

    eprintln!("operate refusal: {answer}");
    assert!(answer.code().is_some(), "the refusal has to be typed");

    // ----- stop it the way the quit dialog does -------------------------------------

    app.apply(Msg::Key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('q'),
        crossterm::event::KeyModifiers::NONE,
    )));

    let screen = render(&mut app, 140, 34);
    eprintln!("--- quit ---\n{}", screen.text());

    assert!(
        screen.contains("runtime.shutdown, then SIGTERM"),
        "this gateway advertises runtime.shutdown, so the dialog has to offer it"
    );

    match client.call("runtime.shutdown", json!({})).await {
        Ok(_result) => eprintln!("the runtime accepted runtime.shutdown"),
        Err(error) => {
            eprintln!("runtime.shutdown: {error} (the runtime may stop before it answers)")
        }
    }

    client.stop().await;

    let exit = daemon
        .terminate(Duration::from_secs(30))
        .await
        .expect("the runtime stopped");

    eprintln!("runtime exit: {exit:?}");

    assert!(!runtime::pid_alive(publication.pid));
    assert!(
        runtime::read_publication(&data_dir)
            .expect("a readable data directory")
            .is_none(),
        "a gracefully stopped gateway removes its publication"
    );

    // The spawn lock is not left behind for the next client to reason about.
    assert!(
        !data_dir.join(runtime::SPAWN_LOCK_FILE).exists(),
        "the spawn lock is released when the spawn window closes"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}
