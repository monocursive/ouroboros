//! The client driven against a scripted server that speaks the gateway's protocol.
//!
//! This pins client behaviour without the Elixir side: every path here is one the
//! gateway can produce — the handshake and its two refusals, out-of-order responses,
//! a typed method error, a notification, an oversized frame, a lost connection — and the
//! test says what the client must do about it. The real runtime is exercised separately,
//! by the integration test behind `OUROBOROS_TUI_INTEGRATION=1`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use ouro::proto::ErrorCode;
use ouro::proto::Hello;
use ouro::transport::{
    self, Client, ClientError, HookFuture, NoReconnectHook, ReconnectHook, Secret, TransportConfig,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PATIENCE: Duration = Duration::from_secs(5);

/// One accepted connection, with the frame helpers a script needs.
struct Peer {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Peer {
    async fn accept(listener: &TcpListener) -> Self {
        let (socket, _peer) = listener.accept().await.expect("a connection");
        Self::from_stream(socket)
    }

    fn from_stream(socket: TcpStream) -> Self {
        let (read, write) = socket.into_split();

        Self {
            reader: BufReader::new(read),
            writer: write,
        }
    }

    /// The next request frame. `None` when the client hung up.
    async fn request(&mut self) -> Option<Value> {
        let mut line = String::new();

        match self.reader.read_line(&mut line).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(serde_json::from_str(&line).expect("a JSON request")),
        }
    }

    async fn hello(&mut self, methods: &[&str]) -> Value {
        let request = self.request().await.expect("a hello");

        assert_eq!(request["method"], "hello");
        assert_eq!(request["params"]["protocol"], 1);
        assert_eq!(request["params"]["token"], TOKEN);
        assert!(request["params"]["client"]
            .as_str()
            .expect("a client name")
            .starts_with("ouro "));

        self.result(
            &request["id"],
            json!({
                "server": "0.1.0",
                "node": "nonode@nohost",
                "role": "core",
                "protocol": 1,
                "scope": "operate",
                "methods": methods,
                "a_field_this_client_has_never_heard_of": true
            }),
        )
        .await;

        request
    }

    async fn result(&mut self, id: &Value, result: Value) {
        self.frame(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            .await;
    }

    async fn error(&mut self, id: &Value, code: i64, message: &str, data: Option<Value>) {
        let mut error = json!({ "code": code, "message": message });

        if let Some(data) = data {
            error["data"] = data;
        }

        self.frame(json!({ "jsonrpc": "2.0", "id": id, "error": error }))
            .await;
    }

    async fn notify(&mut self, method: &str, params: Value) {
        self.frame(json!({ "jsonrpc": "2.0", "method": method, "params": params }))
            .await;
    }

    async fn frame(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).expect("encodable");
        bytes.push(b'\n');
        self.raw(&bytes).await;
    }

    async fn raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.expect("a writable peer");
        self.writer.flush().await.expect("a flushable peer");
    }
}

async fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("an ephemeral port");
    let address = listener.local_addr().expect("a bound address");

    (listener, address)
}

fn config(address: SocketAddr) -> TransportConfig {
    let mut config = TransportConfig::new(address, Secret::new(TOKEN.to_string()));
    config.reconnect = false;
    config.request_timeout = Duration::from_secs(2);
    config.connect_timeout = Duration::from_secs(2);
    config
}

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
