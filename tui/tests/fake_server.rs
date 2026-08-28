//! The client driven against a scripted server that speaks the gateway's protocol.
//!
//! This pins *transport* behaviour without the Elixir side: the handshake and its two
//! refusals, out-of-order responses, a typed method error, a notification, an oversized
//! frame, a lost connection — and what the client must do about each. The UI driven over
//! the same scripted server lives in `ui_stream.rs`; the scaffolding both use is in
//! `support`, so there is one implementation of the protocol harness rather than two that
//! can disagree. The real runtime is exercised by the tests behind
//! `OUROBOROS_TUI_INTEGRATION=1`.

mod support;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::mpsc;

use ouro::proto::ErrorCode;
use ouro::proto::Hello;
use ouro::transport::{
    self, Client, ClientError, EndpointSource, HookFuture, NoReconnectHook, ReconnectHook, Secret,
};

use support::{config, listener, Peer, PATIENCE, TOKEN};

fn hook() -> Arc<dyn ReconnectHook> {
    Arc::new(NoReconnectHook)
}

#[tokio::test]
async fn completes_a_handshake_calls_a_method_and_routes_a_notification() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello", "runtime.status"]).await;

        let request = peer.request().await.expect("a method call");
        assert_eq!(request["method"], "runtime.status");
        assert_eq!(request["params"], json!({}));

        // A notification ahead of the response it interleaves with: the gateway's event
        // stream is not ordered against RPC completions.
        peer.notify(
            "interactive.event",
            json!({ "id": "s1", "event": { "sequence": 7 } }),
        )
        .await;

        peer.result(
            &request["id"],
            json!({ "availability": { "mesh": "available" } }),
        )
        .await;
    });

    let mut connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    assert_eq!(connected.hello.server, "0.1.0");
    assert_eq!(connected.hello.node, "nonode@nohost");
    assert_eq!(connected.hello.role, "core");
    assert_eq!(connected.hello.protocol, 1);
    assert!(connected.hello.operates());
    assert!(connected.hello.serves("runtime.status"));
    assert!(!connected.hello.serves("runtime.shutdown"));

    let status = tokio::time::timeout(PATIENCE, connected.client.call("runtime.status", json!({})))
        .await
        .expect("an answer in time")
        .expect("a result");

    assert_eq!(status["availability"]["mesh"], "available");

    let notification = tokio::time::timeout(PATIENCE, connected.notifications.recv())
        .await
        .expect("a notification in time")
        .expect("a routed notification");

    assert_eq!(notification.method, "interactive.event");
    assert_eq!(notification.params["event"]["sequence"], 7);
    assert_eq!(connected.client.dropped_notifications(), 0);

    script.await.expect("the script finished");
}

#[tokio::test]
async fn a_rejected_token_is_a_typed_refusal_and_not_a_retry() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        let request = peer.request().await.expect("a hello");

        peer.error(
            &request["id"],
            -32001,
            "hello did not present the token this listener was started with",
            None,
        )
        .await;
    });

    let mut config = config(address);
    // Reconnect on: a refused token must still not be retried.
    config.reconnect = true;

    let error = tokio::time::timeout(PATIENCE, transport::connect(config, hook()))
        .await
        .expect("a refusal in time")
        .expect_err("a refusal");

    assert_eq!(error.code(), Some(ErrorCode::Unauthenticated));
    assert!(error.is_fatal());

    script.await.expect("the script finished");
}

#[tokio::test]
async fn a_protocol_mismatch_carries_the_server_protocol() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        let request = peer.request().await.expect("a hello");

        peer.error(
            &request["id"],
            -32002,
            "this gateway speaks protocol 2, the client asked for 1",
            Some(json!({ "server_protocol": 2 })),
        )
        .await;
    });

    let error = transport::connect(config(address), hook())
        .await
        .expect_err("a refusal");

    match error {
        ClientError::Rpc(rpc) => {
            assert_eq!(rpc.code, ErrorCode::ProtocolMismatch);
            assert_eq!(rpc.server_protocol(), Some(2));
        }
        other => panic!("expected a protocol mismatch, got {other}"),
    }

    script.await.expect("the script finished");
}

#[tokio::test]
async fn responses_correlate_when_they_come_back_out_of_order() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello", "agents.list", "runtime.providers"])
            .await;

        let mut requests = Vec::new();

        for _ in 0..3 {
            requests.push(peer.request().await.expect("a method call"));
        }

        for request in requests.iter().rev() {
            peer.result(&request["id"], json!({ "method": request["method"] }))
                .await;
        }
    });

    let connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    let client = connected.client.clone();

    let calls = [
        tokio::spawn({
            let client = client.clone();
            async move { client.call("agents.list", json!({})).await }
        }),
        tokio::spawn({
            let client = client.clone();
            async move { client.call("runtime.providers", json!({})).await }
        }),
        tokio::spawn({
            let client = client.clone();
            async move { client.call("teams.list", json!({})).await }
        }),
    ];

    let mut answered = Vec::new();

    for call in calls {
        let value = tokio::time::timeout(PATIENCE, call)
            .await
            .expect("an answer in time")
            .expect("no panic")
            .expect("a result");

        answered.push(value["method"].as_str().expect("a method").to_string());
    }

    answered.sort();

    assert_eq!(
        answered,
        vec!["agents.list", "runtime.providers", "teams.list"]
    );

    script.await.expect("the script finished");
}

#[tokio::test]
async fn a_typed_method_error_leaves_the_connection_usable() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello", "plans.get", "agents.list"]).await;

        let first = peer.request().await.expect("a first call");
        peer.error(&first["id"], -32007, "no such record on this node", None)
            .await;

        let second = peer.request().await.expect("a second call");
        peer.result(&second["id"], json!([])).await;
    });

    let connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    let error = connected
        .client
        .call("plans.get", json!({ "id": "missing" }))
        .await
        .expect_err("a refusal");

    assert_eq!(error.code(), Some(ErrorCode::NotFound));
    assert!(!error.is_fatal());

    let agents = connected
        .client
        .call("agents.list", json!({}))
        .await
        .expect("the connection survived the error");

    assert_eq!(agents, json!([]));

    script.await.expect("the script finished");
}

#[tokio::test]
async fn an_error_code_this_build_does_not_know_survives_as_other() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello", "future.method"]).await;

        let request = peer.request().await.expect("a call");
        peer.error(
            &request["id"],
            -32050,
            "a refusal from a newer gateway",
            None,
        )
        .await;
    });

    let connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    let error = connected
        .client
        .call("future.method", json!({}))
        .await
        .expect_err("a refusal");

    assert_eq!(error.code(), Some(ErrorCode::Other(-32050)));

    script.await.expect("the script finished");
}

#[tokio::test]
async fn an_inbound_line_past_the_ceiling_fails_the_call_rather_than_the_process() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello", "agents.state"]).await;

        let _request = peer.request().await.expect("a call");

        // A frame that never terminates inside the limit.
        peer.raw(&vec![b'x'; 4096]).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let mut config = config(address);
    config.max_line = 512;

    let connected = transport::connect(config, hook())
        .await
        .expect("a handshake");

    let error = tokio::time::timeout(
        PATIENCE,
        connected.client.call("agents.state", json!({ "id": "a" })),
    )
    .await
    .expect("an answer in time")
    .expect_err("a refusal");

    assert!(
        matches!(error, ClientError::FrameTooLarge { limit: 512 }),
        "unexpected error: {error}"
    );

    script.abort();
}

#[tokio::test]
async fn a_request_the_gateway_never_answers_times_out_without_poisoning_the_next() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello", "teams.cancel", "teams.list"]).await;

        let abandoned = peer.request().await.expect("a call");

        let second = peer.request().await.expect("a second call");
        peer.result(&second["id"], json!(["a-team"])).await;

        // The abandoned answer arrives late; a client that mixed it up with the second
        // call would render one team's state under another's id.
        peer.result(&abandoned["id"], json!(["wrong"])).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    let error = connected
        .client
        .call_with_timeout(
            "teams.cancel",
            json!({ "id": "t" }),
            Duration::from_millis(300),
        )
        .await
        .expect_err("a timeout");

    assert!(matches!(error, ClientError::Timeout), "got {error}");

    let teams = connected
        .client
        .call("teams.list", json!({}))
        .await
        .expect("the next call is unaffected");

    assert_eq!(teams, json!(["a-team"]));

    script.await.expect("the script finished");
}

#[tokio::test]
async fn an_uncorrelatable_error_frame_ends_the_connection() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello", "agents.list"]).await;

        let _request = peer.request().await.expect("a call");

        peer.error(&Value::Null, -32700, "the frame is not valid JSON", None)
            .await;

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    let error = tokio::time::timeout(PATIENCE, connected.client.call("agents.list", json!({})))
        .await
        .expect("an answer in time")
        .expect_err("a failure");

    assert_eq!(error.code(), Some(ErrorCode::ParseError));

    script.abort();
}

struct RecordReconnect(mpsc::UnboundedSender<Hello>);

impl ReconnectHook for RecordReconnect {
    fn after_reconnect(&self, _client: Client, hello: Hello) -> HookFuture {
        let sender = self.0.clone();

        Box::pin(async move {
            let _ = sender.send(hello);
        })
    }
}

#[tokio::test]
async fn a_dropped_connection_is_re_established_and_re_handshaken() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&server).await;
        first.hello(&["hello", "runtime.status"]).await;
        drop(first);

        let mut second = Peer::accept(&server).await;
        second.hello(&["hello", "runtime.status"]).await;

        let request = second
            .request()
            .await
            .expect("a call on the new connection");
        second
            .result(&request["id"], json!({ "node": "after-reconnect" }))
            .await;

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let (reconnected, mut reconnects) = mpsc::unbounded_channel();

    let mut config = config(address);
    config.reconnect = true;
    config.backoff.initial = Duration::from_millis(20);
    config.backoff.max = Duration::from_millis(50);

    let connected = transport::connect(config, Arc::new(RecordReconnect(reconnected)))
        .await
        .expect("a handshake");

    let hello = tokio::time::timeout(PATIENCE, reconnects.recv())
        .await
        .expect("a reconnect in time")
        .expect("a hook call");

    assert_eq!(hello.node, "nonode@nohost");
    assert_eq!(connected.client.reconnects(), 1);

    let status = tokio::time::timeout(PATIENCE, connected.client.call("runtime.status", json!({})))
        .await
        .expect("an answer in time")
        .expect("a result on the re-established connection");

    assert_eq!(status["node"], "after-reconnect");

    script.await.expect("the script finished");
}

/// The token a restart publishes in this file's scripts. Any value other than `TOKEN`
/// would do; the length just mirrors the real one.
const ROTATED: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// A scripted publication: consult number N answers with step N, the last step repeating.
/// This is the on-disk `gateway.json` + `gateway.token` pair as a state machine, so a test
/// can pin *when* the reconnect loop re-reads it and what each read must produce.
struct ScriptedEndpoint {
    steps: Vec<Option<(SocketAddr, &'static str)>>,
    consulted: AtomicUsize,
}

impl ScriptedEndpoint {
    fn new(steps: Vec<Option<(SocketAddr, &'static str)>>) -> Arc<Self> {
        Arc::new(Self {
            steps,
            consulted: AtomicUsize::new(0),
        })
    }

    fn consulted(&self) -> usize {
        self.consulted.load(Ordering::SeqCst)
    }
}

impl EndpointSource for ScriptedEndpoint {
    fn current(&self) -> Option<(SocketAddr, Secret)> {
        let call = self.consulted.fetch_add(1, Ordering::SeqCst);
        let step = self.steps.get(call).or_else(|| self.steps.last())?;

        step.as_ref()
            .map(|(addr, token)| (*addr, Secret::new((*token).to_string())))
    }
}

fn reconnecting_config(
    address: SocketAddr,
    source: Arc<ScriptedEndpoint>,
) -> transport::TransportConfig {
    let mut config = config(address);
    config.reconnect = true;
    config.backoff.initial = Duration::from_millis(20);
    config.backoff.max = Duration::from_millis(50);
    config.refresh = Some(source);
    config
}

#[tokio::test]
async fn a_reconnect_presents_the_published_token_not_the_one_it_connected_with() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&server).await;
        first.hello(&["hello", "runtime.status"]).await;
        drop(first);

        // The restarted runtime knows only the rotated token; `hello_with_token`
        // asserts that is what the client presented.
        let mut second = Peer::accept(&server).await;
        second
            .hello_with_token(ROTATED, &["hello", "runtime.status"])
            .await;

        let request = second.request().await.expect("a call after the rotation");
        second
            .result(&request["id"], json!({ "node": "after-rotation" }))
            .await;

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let source = ScriptedEndpoint::new(vec![Some((address, ROTATED))]);
    let (reconnected, mut reconnects) = mpsc::unbounded_channel();

    let connected = transport::connect(
        reconnecting_config(address, source.clone()),
        Arc::new(RecordReconnect(reconnected)),
    )
    .await
    .expect("the first handshake still uses the connect-time token");

    tokio::time::timeout(PATIENCE, reconnects.recv())
        .await
        .expect("a reconnect in time")
        .expect("a hook call");

    let status = tokio::time::timeout(PATIENCE, connected.client.call("runtime.status", json!({})))
        .await
        .expect("an answer in time")
        .expect("a result over the re-established connection");

    assert_eq!(status["node"], "after-rotation");
    assert_eq!(connected.client.reconnects(), 1);
    assert!(source.consulted() >= 1, "the publication was never re-read");

    script.await.expect("the script finished");
}

#[tokio::test]
async fn an_unauthenticated_reconnect_re_reads_the_publication_and_survives_the_rotation() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&server).await;
        first.hello(&["hello", "runtime.status"]).await;
        drop(first);

        // The rotation lands between the attempt's re-read and its handshake, so this
        // gateway refuses the stale token the way the real one would.
        let mut refusing = Peer::accept(&server).await;
        let request = refusing.request().await.expect("a stale hello");
        assert_eq!(request["params"]["token"], TOKEN);
        refusing
            .error(
                &request["id"],
                -32001,
                "hello did not present the token this listener was started with",
                None,
            )
            .await;
        drop(refusing);

        let mut third = Peer::accept(&server).await;
        third
            .hello_with_token(ROTATED, &["hello", "runtime.status"])
            .await;

        let request = third.request().await.expect("a call after the refusal");
        third
            .result(&request["id"], json!({ "node": "after-refusal" }))
            .await;

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Read 1 (before the first attempt) still says the stale token; read 2 is the
    // re-read the -32001 must trigger, and it says the publication changed; read 3
    // (before the next attempt) is what that attempt presents.
    let source = ScriptedEndpoint::new(vec![
        Some((address, TOKEN)),
        Some((address, ROTATED)),
        Some((address, ROTATED)),
    ]);
    let (reconnected, mut reconnects) = mpsc::unbounded_channel();

    let connected = transport::connect(
        reconnecting_config(address, source.clone()),
        Arc::new(RecordReconnect(reconnected)),
    )
    .await
    .expect("a handshake");

    tokio::time::timeout(PATIENCE, reconnects.recv())
        .await
        .expect("the refusal of a rotated-away token must not kill the client")
        .expect("a hook call");

    let status = tokio::time::timeout(PATIENCE, connected.client.call("runtime.status", json!({})))
        .await
        .expect("an answer in time")
        .expect("a result over the re-established connection");

    assert_eq!(status["node"], "after-refusal");
    assert!(
        source.consulted() >= 3,
        "an unauthenticated refusal must re-read the publication, saw {} reads",
        source.consulted()
    );

    script.await.expect("the script finished");
}

#[tokio::test]
async fn an_absent_publication_holds_the_reconnect_until_one_returns() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&server).await;
        first.hello(&["hello", "runtime.status"]).await;
        drop(first);

        // Only one further connection: while the publication is absent the client must
        // wait rather than dial the port it remembers.
        let mut second = Peer::accept(&server).await;
        second.hello(&["hello", "runtime.status"]).await;

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Two reads find the runtime down; the third finds the new publication.
    let source = ScriptedEndpoint::new(vec![None, None, Some((address, TOKEN))]);
    let (reconnected, mut reconnects) = mpsc::unbounded_channel();

    let connected = transport::connect(
        reconnecting_config(address, source.clone()),
        Arc::new(RecordReconnect(reconnected)),
    )
    .await
    .expect("a handshake");

    tokio::time::timeout(PATIENCE, reconnects.recv())
        .await
        .expect("a reconnect once the publication returned")
        .expect("a hook call");

    assert_eq!(connected.client.reconnects(), 1);
    assert!(
        source.consulted() >= 3,
        "the absent publication must be polled, saw {} reads",
        source.consulted()
    );

    script.await.expect("the script finished");
}

#[tokio::test]
async fn a_refusal_of_the_currently_published_token_is_still_fatal() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&server).await;
        first.hello(&["hello", "runtime.status"]).await;
        drop(first);

        // The publication has not changed, so this refusal is a decision about the
        // exact credentials the client would present next — retrying it would spin.
        let mut refusing = Peer::accept(&server).await;
        let request = refusing.request().await.expect("a hello");
        refusing
            .error(
                &request["id"],
                -32001,
                "hello did not present the token this listener was started with",
                None,
            )
            .await;

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let source = ScriptedEndpoint::new(vec![Some((address, TOKEN))]);

    let connected = transport::connect(
        reconnecting_config(address, source.clone()),
        Arc::new(NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let reason = tokio::time::timeout(PATIENCE, async {
        loop {
            match connected
                .client
                .call_with_timeout("runtime.status", json!({}), Duration::from_millis(100))
                .await
            {
                Err(ClientError::Stopped(reason)) => return reason,
                _ => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .expect("the client records the refusal in time");

    assert!(
        reason.contains("unauthenticated"),
        "the stop reason must name the refusal, got {reason:?}"
    );
    assert!(
        source.consulted() >= 2,
        "the refusal must be checked against a re-read publication, saw {} reads",
        source.consulted()
    );

    script.await.expect("the script finished");
}

#[tokio::test]
async fn notifications_past_the_channel_are_counted_rather_than_hidden() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(&["hello"]).await;

        for sequence in 0..64 {
            peer.notify("coding.event", json!({ "id": "c1", "sequence": sequence }))
                .await;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let mut config = config(address);
    config.notification_capacity = 4;

    let connected = transport::connect(config, hook())
        .await
        .expect("a handshake");

    // Nothing drains the channel, which is the condition being tested.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        connected.client.dropped_notifications() > 0,
        "a full notification channel must be counted, not silently emptied"
    );

    drop(connected);
    script.abort();
}
