//! The real thing: `mix run --no-halt` under this client's own spawn posture.
//!
//! Gated by `OUROBOROS_TUI_INTEGRATION=1` because it compiles and boots an Elixir
//! runtime, which a plain `cargo test` has no business doing. What it proves is the part
//! no fake server can: that the environment this client assembles actually produces a
//! gateway, that the port it publishes is reachable, that the handshake is accepted, and
//! that `runtime.status` decodes into something a Dashboard could draw.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use ouro::runtime::{self, Launcher, Output};
use ouro::status;
use ouro::transport::{self, NoReconnectHook, ReconnectHook, TransportConfig};

fn enabled() -> bool {
    std::env::var("OUROBOROS_TUI_INTEGRATION").as_deref() == Ok("1")
}

fn scratch_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ouro-integration-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch data directory");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dev_runtime_starts_publishes_answers_hello_and_stops() {
    if !enabled() {
        eprintln!("skipped: set OUROBOROS_TUI_INTEGRATION=1 to run against a real runtime");
        return;
    }

    let repo_root = runtime::find_repo_root(&PathBuf::from(env!("CARGO_MANIFEST_DIR")))
        .expect("an ouroboros checkout above this crate");

    let data_dir = scratch_data_dir();
    let token_file = data_dir.join(runtime::TOKEN_FILE);
    let token = runtime::write_token(&token_file).expect("a token");

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

    eprintln!(
        "gateway.json: port={} pid={} node={} scope={} protocol={}",
        publication.port,
        publication.pid,
        publication.node,
        publication.scope,
        publication.protocol
    );

    assert_eq!(publication.protocol, 1);
    assert_eq!(
        publication.scope, "operate",
        "the spawner asks for operate scope"
    );
    assert!(!publication.node.is_empty());
    assert_eq!(
        publication.pid,
        daemon.pid(),
        "the published pid must be the process this client is supervising"
    );

    let address = std::net::SocketAddr::from(([127, 0, 0, 1], publication.port));

    let mut config = TransportConfig::new(address, token);
    config.reconnect = false;

    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);

    let connected = match transport::connect(config, hook).await {
        Ok(connected) => connected,
        Err(error) => {
            eprintln!("{}", daemon.log_tail(60));
            let _ = daemon.terminate(Duration::from_secs(10)).await;
            panic!("the handshake failed: {error}");
        }
    };

    eprint!(
        "{}",
        status::render_hello(&address.to_string(), &connected.hello)
    );

    assert_eq!(connected.hello.protocol, 1);
    assert_eq!(connected.hello.scope, "operate");
    assert_eq!(connected.hello.node, publication.node);
    assert!(!connected.hello.server.is_empty());
    assert!(connected.hello.serves("hello"));
    assert!(connected.hello.serves("runtime.status"));

    let outcome = connected.client.call("runtime.status", json!({})).await;

    let status_value = match outcome {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{}", daemon.log_tail(60));
            let _ = daemon.terminate(Duration::from_secs(10)).await;
            panic!("runtime.status failed: {error}");
        }
    };

    eprint!("{}", status::render_status(&status_value));

    let availability = status_value
        .get("availability")
        .and_then(Value::as_object)
        .expect("runtime.status carries an availability map");

    assert!(
        !availability.is_empty(),
        "an availability map with no planes in it is not a readable one"
    );

    for (plane, state) in availability {
        let state = state
            .as_str()
            .unwrap_or_else(|| panic!("availability.{plane} is not a string: {state}"));

        assert!(
            matches!(state, "available" | "unavailable" | "disabled"),
            "availability.{plane} is {state}, which is outside the tri-state the runtime \
             documents"
        );
    }

    assert_eq!(
        status_value.get("node").and_then(Value::as_str),
        Some(publication.node.as_str())
    );

    // A method the gateway does not serve must be a typed refusal, not a hang: this is
    // the same path `ouro stop` and the quit dialog take to decide what exists.
    // `mesh.send_message` is deliberately absent from v1 (§2.4) — its `from` is
    // caller-supplied, and the effects plane made principals non-spoofable.
    let refusal = connected
        .client
        .call("mesh.send_message", json!({}))
        .await
        .expect_err("a verb this build does not serve");

    assert_eq!(
        refusal.code(),
        Some(ouro::proto::ErrorCode::MethodNotFound),
        "unexpected refusal: {refusal}"
    );

    assert!(
        !connected.hello.serves("mesh.send_message"),
        "hello must advertise exactly what this build serves"
    );

    // The spawner asks for operate scope and sets OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1, so
    // this build does serve the one verb `ouro stop` prefers over a signal.
    assert!(connected.hello.operates());
    assert!(connected.hello.serves("runtime.shutdown"));

    match connected.client.call("runtime.shutdown", json!({})).await {
        Ok(result) => eprintln!("runtime.shutdown: {result}"),
        // The runtime stopping is what was asked for, and it may stop before it answers.
        Err(error) => eprintln!("runtime.shutdown: {error}"),
    }

    connected.client.stop().await;

    // Already stopping, so this observes the exit rather than causing it; a runtime that
    // ignored the acknowledged stop would still be signalled and killed here.
    let exit = daemon
        .terminate(Duration::from_secs(30))
        .await
        .expect("the runtime stopped");

    eprintln!("runtime exit: {exit:?}");

    assert!(
        !runtime::pid_alive(publication.pid),
        "the runtime must be gone after a graceful stop"
    );

    assert!(
        runtime::read_publication(&data_dir)
            .expect("a readable data directory")
            .is_none(),
        "a gracefully stopped gateway removes its publication"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}
