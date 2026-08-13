//! Shared test scaffolding: a scripted gateway, a `TestBackend` screen, and a driver.
//!
//! The scripted peer speaks the real line protocol, so a test that drives the UI through
//! it exercises the same transport, the same correlation, and the same reconnect hook the
//! binary uses. The only thing it stands in for is the Elixir side, which has its own
//! tests — and where a shape matters, the golden fixtures are read from disk rather than
//! retyped here.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::Terminal;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use ouro::proto::{Hello, Notification};
use ouro::transport::{self, Client, Secret, TransportConfig};
use ouro::ui::app::{App, Mode, Msg};

pub const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const PATIENCE: Duration = Duration::from_secs(5);

/// One accepted connection, with the frame helpers a script needs.
pub struct Peer {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Peer {
    pub async fn accept(listener: &TcpListener) -> Self {
        let (socket, _peer) = listener.accept().await.expect("a connection");
        Self::from_stream(socket)
    }

    pub fn from_stream(socket: TcpStream) -> Self {
        let (read, write) = socket.into_split();

        Self {
            reader: BufReader::new(read),
            writer: write,
        }
    }

    /// The next request frame. `None` when the client hung up.
    pub async fn request(&mut self) -> Option<Value> {
        let mut line = String::new();

        match self.reader.read_line(&mut line).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(serde_json::from_str(&line).expect("a JSON request")),
        }
    }

    /// The next request for `method`, answering everything else with `otherwise`.
    ///
    /// The UI polls on a timer, so a script that expected the next frame to be the one it
    /// cares about would be racing the Dashboard's `runtime.status`.
    pub async fn request_for(&mut self, method: &str) -> Value {
        loop {
            let request = self
                .request()
                .await
                .unwrap_or_else(|| panic!("a {method} call"));

            if request["method"] == method {
                return request;
            }

            self.result(&request["id"], json!({})).await;
        }
    }

    pub async fn hello(&mut self, methods: &[&str]) -> Value {
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

    pub async fn result(&mut self, id: &Value, result: Value) {
        self.frame(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            .await;
    }

    pub async fn error(&mut self, id: &Value, code: i64, message: &str, data: Option<Value>) {
        let mut error = json!({ "code": code, "message": message });

        if let Some(data) = data {
            error["data"] = data;
        }

        self.frame(json!({ "jsonrpc": "2.0", "id": id, "error": error }))
            .await;
    }

    pub async fn notify(&mut self, method: &str, params: Value) {
        self.frame(json!({ "jsonrpc": "2.0", "method": method, "params": params }))
            .await;
    }

    pub async fn frame(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).expect("encodable");
        bytes.push(b'\n');
        self.raw(&bytes).await;
    }

    pub async fn raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.expect("a writable peer");
        self.writer.flush().await.expect("a flushable peer");
    }
}

pub async fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("an ephemeral port");
    let address = listener.local_addr().expect("a bound address");

    (listener, address)
}

pub fn config(address: SocketAddr) -> TransportConfig {
    let mut config = TransportConfig::new(address, Secret::new(TOKEN.to_string()));
    config.reconnect = false;
    config.request_timeout = Duration::from_secs(2);
    config.connect_timeout = Duration::from_secs(2);
    config
}

/// A golden fixture, read from the checkout so a regeneration is picked up here too.
pub fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test/support/gateway_golden")
        .join(format!("{name}.json"));

    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));

    serde_json::from_slice(&bytes).expect("a JSON fixture")
}

pub fn hello(methods: &[&str]) -> Hello {
    serde_json::from_value(json!({
        "server": "0.1.0",
        "node": "ouroboros@golden",
        "role": "core",
        "protocol": 1,
        "scope": "operate",
        "methods": methods,
    }))
    .expect("a handshake")
}

/// The same handshake at `read` scope: a listener that *advertises* the operate verbs and
/// will refuse every one of them with `-32003`. Scope and `methods` are two separate gates
/// and a client has to honour both.
pub fn read_hello(methods: &[&str]) -> Hello {
    serde_json::from_value(json!({
        "server": "0.1.0",
        "node": "ouroboros@golden",
        "role": "core",
        "protocol": 1,
        "scope": "read",
        "methods": methods,
    }))
    .expect("a handshake")
}

/// A gateway that serves everything the golden `hello` lists.
pub fn full_hello() -> Hello {
    serde_json::from_value(fixture("hello_result")["result"].clone()).expect("a handshake")
}

pub fn app(hello: Hello) -> App {
    App::new(
        Mode::Spawned { pid: 4242 },
        "127.0.0.1:4560".into(),
        hello,
        None,
    )
}

/// What a terminal would show, with the styles still attached.
pub struct Screen {
    pub rows: Vec<String>,
    colours: Vec<Vec<Color>>,
}

impl Screen {
    pub fn text(&self) -> String {
        self.rows.join("\n")
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.rows.iter().any(|row| row.contains(needle))
    }

    /// The row containing `needle`, panicking with the whole screen when there is none —
    /// a failure in a TUI test is unreadable without the frame that produced it.
    pub fn row(&self, needle: &str) -> &str {
        self.rows
            .iter()
            .find(|row| row.contains(needle))
            .map(String::as_str)
            .unwrap_or_else(|| panic!("no row contains {needle:?}\n{}", self.text()))
    }

    /// The foreground colour of `word` on the row containing `row_needle`.
    pub fn colour_of(&self, row_needle: &str, word: &str) -> Color {
        let index = self
            .rows
            .iter()
            .position(|row| row.contains(row_needle))
            .unwrap_or_else(|| panic!("no row contains {row_needle:?}\n{}", self.text()));

        let column = self.rows[index].find(word).unwrap_or_else(|| {
            panic!("{word:?} is not on the {row_needle:?} row\n{}", self.text())
        });

        // `find` is a byte offset and the frame may hold multi-byte glyphs, so the column
        // is counted in characters.
        let column = self.rows[index][..column].chars().count();

        self.colours[index][column]
    }
}

pub fn render(app: &mut App, width: u16, height: u16) -> Screen {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a test terminal");

    terminal
        .draw(|frame| ouro::ui::view::draw(frame, app))
        .expect("a frame");

    let buffer = terminal.backend().buffer();
    let mut rows = Vec::new();
    let mut colours = Vec::new();

    for y in 0..buffer.area.height {
        let mut row = String::new();
        let mut row_colours = Vec::new();

        for x in 0..buffer.area.width {
            let cell = &buffer[(x, y)];
            row.push_str(cell.symbol());
            row_colours.push(cell.style().fg.unwrap_or(Color::Reset));
        }

        rows.push(row);
        colours.push(row_colours);
    }

    Screen { rows, colours }
}

/// The driver `ui::run` is, minus the terminal: drain the App's calls, spawn them, and
/// feed the answers back. A test that used a real terminal would be testing crossterm.
pub struct Harness {
    pub app: App,
    pub client: Client,
    pub sender: mpsc::UnboundedSender<Msg>,
    pub receiver: mpsc::UnboundedReceiver<Msg>,
    pub notifications: mpsc::Receiver<Notification>,
}

impl Harness {
    /// Connects to a scripted server and builds an App wired to the real reconnect hook.
    pub async fn connect(config: TransportConfig, hello_override: Option<Hello>) -> Self {
        let (hook, channel) = ouro::ui::hook();
        let connected = transport::connect(config, hook).await.expect("a handshake");

        let mut app = app(hello_override.unwrap_or_else(|| connected.hello.clone()));

        let (cursors, sender, receiver) = channel.into_parts();
        app.cursors = cursors;

        Self {
            app,
            client: connected.client,
            sender,
            receiver,
            notifications: connected.notifications,
        }
    }

    /// Runs the loop until nothing is outstanding, or the patience runs out.
    pub async fn settle(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

        loop {
            for call in self.app.drain() {
                let client = self.client.clone();
                let sender = self.sender.clone();

                tokio::spawn(async move {
                    let result = client.call(&call.method, call.params).await;
                    let _ = sender.send(Msg::Answer {
                        tag: call.tag,
                        result,
                    });
                });
            }

            let quiet = tokio::select! {
                message = self.receiver.recv() => {
                    if let Some(message) = message { self.app.apply(message); }
                    false
                }
                notification = self.notifications.recv() => {
                    if let Some(notification) = notification {
                        self.app.apply(Msg::Notification(notification));
                    }
                    false
                }
                _idle = tokio::time::sleep(Duration::from_millis(120)) => true,
            };

            if quiet && !self.app.has_outbound() && !self.app.busy() {
                return;
            }

            if tokio::time::Instant::now() >= deadline {
                return;
            }
        }
    }

    /// Settles repeatedly until the App satisfies `done`, so a test can wait for a
    /// reconnect the transport performs on its own schedule.
    pub async fn settle_until(&mut self, mut done: impl FnMut(&App) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6);

        loop {
            self.settle().await;

            if done(&self.app) || tokio::time::Instant::now() >= deadline {
                return;
            }
        }
    }

    pub fn tick(&mut self) {
        self.app.apply(Msg::Tick);
    }

    pub fn screen(&mut self, width: u16, height: u16) -> Screen {
        render(&mut self.app, width, height)
    }
}
