//! The client half of the gateway protocol: one socket, one writer, bounded everything.
//!
//! ## The line is the frame, and it has a ceiling
//!
//! The gateway writes one JSON object per newline-terminated line and refuses inbound
//! frames past `OUROBOROS_GATEWAY_MAX_FRAME`. This client applies the mirror image of
//! that rule to what it reads: [`LineReader`] refuses an unterminated line the moment it
//! exceeds [`DEFAULT_MAX_LINE`] rather than growing a buffer on a peer's say-so. A
//! response payload can legitimately be large — `Ouroboros.Gateway.Wire` caps a tree at
//! 50_000 nodes, not at a byte count — so the inbound ceiling is deliberately looser
//! than the outbound one, which is held at the server's own default so a request that
//! would be chopped is refused here, where the error can name the method.
//!
//! ## Correlation, and what an uncorrelatable frame means
//!
//! Requests carry monotonically increasing numeric ids and responses may return in any
//! order, because the gateway dispatches up to eight at a time and answers in completion
//! order. A response whose id this client never issued is discarded. A response with a
//! *null* id is not: this client only ever writes well-formed object frames with numeric
//! ids, so the gateway answering one uncorrelatably means the two sides disagree about
//! the protocol, and the connection is torn down rather than left with callers waiting
//! for their ceilings to pass.
//!
//! ## Reconnect is transport-level only
//!
//! A dropped connection is retried with capped exponential backoff and jitter, and the
//! handshake is repeated. A *refused* handshake is not retried: a rejected token and an
//! unsupported protocol are decisions, and retrying a decision is a spin, not a repair.
//! [`ReconnectHook`] is where Slice 3b re-subscribes every watched session; Slice 3a
//! leaves it a no-op and only counts the reconnects.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::TryRngCore;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::proto::{self, Hello, HelloParams, Incoming, Notification, Request, RpcError};

/// Inbound line ceiling. Larger than the server's inbound default because responses are
/// answers to a tree walk and requests are not.
pub const DEFAULT_MAX_LINE: usize = 8 * 1024 * 1024;

/// Outbound line ceiling, held at the gateway's own `OUROBOROS_GATEWAY_MAX_FRAME`
/// default so an over-long request is refused where its method name is still in hand.
pub const DEFAULT_MAX_OUTBOUND: usize = 1024 * 1024;

/// Per-request ceiling. Every Slice 1 method declares a 15s gateway ceiling, so 20s
/// leaves room for the answer to arrive rather than racing it.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The gateway closes a connection that has not completed `hello` within 10s, so a
/// handshake that has not finished by then has already failed.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const COMMAND_CAPACITY: usize = 64;
const DEFAULT_NOTIFICATION_CAPACITY: usize = 1024;
const READ_CHUNK: usize = 16 * 1024;

/// Everything that can go wrong, separated into what the server decided and what the
/// transport did.
#[derive(Debug, Clone)]
pub enum ClientError {
    /// A typed error from the gateway, code included.
    Rpc(RpcError),
    ConnectionClosed,
    Timeout,
    FrameTooLarge {
        limit: usize,
    },
    BadJson(String),
    Io(String),
    /// The client is no longer running; the reason it stopped, when there was one.
    Stopped(String),
}

impl ClientError {
    pub fn code(&self) -> Option<proto::ErrorCode> {
        match self {
            Self::Rpc(error) => Some(error.code),
            _ => None,
        }
    }

    /// Whether a reconnect could plausibly change the answer.
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::Rpc(error) => error.code.is_handshake_refusal(),
            Self::Stopped(_) => true,
            _ => false,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(error) => write!(f, "{error}"),
            Self::ConnectionClosed => write!(f, "the connection closed"),
            Self::Timeout => write!(f, "the request exceeded its client ceiling"),
            Self::FrameTooLarge { limit } => {
                write!(f, "a frame exceeded the {limit} byte inbound line limit")
            }
            Self::BadJson(detail) => write!(f, "the server sent something unreadable: {detail}"),
            Self::Io(detail) => write!(f, "transport failure: {detail}"),
            Self::Stopped(reason) if reason.is_empty() => write!(f, "the client is not running"),
            Self::Stopped(reason) => write!(f, "the client stopped: {reason}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A token that never reaches a `Debug` output or outlives its owner in memory.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

/// Capped exponential backoff with jitter, so a runtime that restarts does not meet a
/// thundering client on a fixed cadence.
#[derive(Debug, Clone)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    pub factor: f64,
    /// Fraction of the computed delay that is randomized away, in `0.0..=1.0`.
    pub jitter: f64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(200),
            max: Duration::from_secs(10),
            factor: 2.0,
            jitter: 0.3,
        }
    }
}

impl Backoff {
    pub fn delay(&self, attempt: u32) -> Duration {
        let scaled = self.initial.as_secs_f64() * self.factor.powi(attempt.min(16) as i32);
        let capped = scaled.min(self.max.as_secs_f64()).max(0.0);
        let jitter = self.jitter.clamp(0.0, 1.0);
        let low = capped * (1.0 - jitter);
        Duration::from_secs_f64(low + (capped - low) * unit_random())
    }
}

/// A uniform `0.0..1.0` drawn from the OS. The client already needs an OS random source
/// for the spawn token, so there is no second generator to seed or reason about.
fn unit_random() -> f64 {
    let mut bytes = [0u8; 8];

    if rand::rngs::OsRng.try_fill_bytes(&mut bytes).is_err() {
        return 0.5;
    }

    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

pub type HookFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Run after every successful re-handshake. Slice 3b re-subscribes each watched session
/// here with its last seen `sequence` as cursor; Slice 3a runs [`NoReconnectHook`].
pub trait ReconnectHook: Send + Sync + 'static {
    fn after_reconnect(&self, client: Client, hello: Hello) -> HookFuture;
}

pub struct NoReconnectHook;

impl ReconnectHook for NoReconnectHook {
    fn after_reconnect(&self, _client: Client, _hello: Hello) -> HookFuture {
        Box::pin(async {})
    }
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub addr: SocketAddr,
    pub token: Secret,
    pub client: String,
    pub max_line: usize,
    pub max_outbound: usize,
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub notification_capacity: usize,
    pub backoff: Backoff,
    /// Whether a lost connection is re-established. `ouro stop` turns this off: it asks
    /// the runtime to exit, so the close that follows is the answer, not a fault.
    pub reconnect: bool,
}

impl TransportConfig {
    pub fn new(addr: SocketAddr, token: Secret) -> Self {
        Self {
            addr,
            token,
            client: proto::client_name(),
            max_line: DEFAULT_MAX_LINE,
            max_outbound: DEFAULT_MAX_OUTBOUND,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            notification_capacity: DEFAULT_NOTIFICATION_CAPACITY,
            backoff: Backoff::default(),
            reconnect: true,
        }
    }
}

/// Reads newline-terminated frames and refuses one that never terminates in time.
pub struct LineReader<R> {
    inner: R,
    pending: Vec<u8>,
    scanned: usize,
    max: usize,
    chunk: Vec<u8>,
    poisoned: bool,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            scanned: 0,
            max,
            chunk: vec![0; READ_CHUNK],
            poisoned: false,
        }
    }

    /// The next frame, without its terminator. `Ok(None)` is a clean end of stream.
    ///
    /// Cancel-safe: every mutation happens after the inner read returns, and
    /// `AsyncReadExt::read` guarantees a cancelled read consumed nothing.
    pub async fn next_line(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        if self.poisoned {
            return Err(ClientError::ConnectionClosed);
        }

        loop {
            if let Some(offset) = self.pending[self.scanned..]
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let end = self.scanned + offset;
                let mut line: Vec<u8> = self.pending.drain(..=end).collect();
                self.scanned = 0;
                line.pop();

                if line.last() == Some(&b'\r') {
                    line.pop();
                }

                return Ok(Some(line));
            }

            self.scanned = self.pending.len();

            if self.pending.len() > self.max {
                self.poisoned = true;
                return Err(ClientError::FrameTooLarge { limit: self.max });
            }

            let read = self
                .inner
                .read(&mut self.chunk)
                .await
                .map_err(|error| ClientError::Io(error.to_string()))?;

            if read == 0 {
                if self.pending.is_empty() {
                    return Ok(None);
                }

                self.poisoned = true;
                return Err(ClientError::Io("the connection closed mid-frame".into()));
            }

            self.pending.extend_from_slice(&self.chunk[..read]);
        }
    }
}

/// One connected socket: a bounded reader and the single writer that owns it.
struct Wire<R, W> {
    reader: LineReader<R>,
    writer: W,
    max_outbound: usize,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Wire<R, W> {
    async fn send<T: Serialize>(&mut self, frame: &T) -> Result<(), ClientError> {
        let mut bytes =
            serde_json::to_vec(frame).map_err(|error| ClientError::BadJson(error.to_string()))?;

        if bytes.len() > self.max_outbound {
            return Err(ClientError::FrameTooLarge {
                limit: self.max_outbound,
            });
        }

        bytes.push(b'\n');

        self.writer
            .write_all(&bytes)
            .await
            .map_err(|error| ClientError::Io(error.to_string()))?;

        self.writer
            .flush()
            .await
            .map_err(|error| ClientError::Io(error.to_string()))
    }

    async fn next(&mut self) -> Result<Option<Incoming>, ClientError> {
        match self.reader.next_line().await? {
            None => Ok(None),
            Some(line) => Incoming::decode(&line)
                .map(Some)
                .map_err(|error| ClientError::BadJson(error.to_string())),
        }
    }
}

type TcpWire = Wire<OwnedReadHalf, OwnedWriteHalf>;

enum Command {
    Call {
        id: u64,
        method: String,
        params: Value,
        reply: oneshot::Sender<Result<Value, ClientError>>,
    },
    /// The caller stopped waiting; drop the correlation rather than hold it until the
    /// answer arrives.
    Forget(u64),
    Stop,
}

#[derive(Debug, Default)]
struct Shared {
    dropped_notifications: AtomicU64,
    reconnects: AtomicU64,
    stopped: Mutex<Option<String>>,
}

/// A handle onto one connection. Cloning is cheap and every clone talks to the same
/// socket through the same writer.
#[derive(Clone, Debug)]
pub struct Client {
    commands: mpsc::Sender<Command>,
    ids: Arc<AtomicU64>,
    request_timeout: Duration,
    shared: Arc<Shared>,
}

impl Client {
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        self.call_with_timeout(method, params, self.request_timeout)
            .await
    }

    /// A call under a caller-chosen ceiling. `interactive.start` declares a 120s gateway
    /// ceiling, which no default here should have to accommodate.
    pub async fn call_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, ClientError> {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        let (reply, answer) = oneshot::channel();

        let command = Command::Call {
            id,
            method: method.to_string(),
            params,
            reply,
        };

        // The send is inside the ceiling on purpose: while the client is reconnecting
        // nothing drains this channel, and a caller that is willing to wait 20s for an
        // answer is not willing to wait forever to be allowed to ask.
        let outcome = tokio::time::timeout(timeout, async {
            self.commands
                .send(command)
                .await
                .map_err(|_closed| self.stopped_error())?;

            answer.await.map_err(|_dropped| self.stopped_error())?
        })
        .await;

        match outcome {
            Ok(result) => result,
            Err(_elapsed) => {
                let _ = self.commands.try_send(Command::Forget(id));
                Err(ClientError::Timeout)
            }
        }
    }

    /// Notifications discarded because the consumer did not keep up. Slice 3a drains
    /// nothing into a UI, so this is the honest count of what a 3b tab would have shown.
    pub fn dropped_notifications(&self) -> u64 {
        self.shared.dropped_notifications.load(Ordering::Relaxed)
    }

    pub fn reconnects(&self) -> u64 {
        self.shared.reconnects.load(Ordering::Relaxed)
    }

    pub async fn stop(&self) {
        let _ = self.commands.send(Command::Stop).await;
    }

    fn stopped_error(&self) -> ClientError {
        let reason = self
            .shared
            .stopped
            .lock()
            .ok()
            .and_then(|reason| reason.clone())
            .unwrap_or_default();

        ClientError::Stopped(reason)
    }
}

/// What [`connect`] hands back: the handle, the handshake, and the notification stream.
#[derive(Debug)]
pub struct Connected {
    pub client: Client,
    pub hello: Hello,
    pub notifications: mpsc::Receiver<Notification>,
}

/// Connects, completes the handshake, and starts the connection actor.
///
/// The first handshake is awaited inline so that a rejected token or an unsupported
/// protocol is this function's error rather than a background reconnect loop nobody is
/// watching.
pub async fn connect(
    config: TransportConfig,
    hook: Arc<dyn ReconnectHook>,
) -> Result<Connected, ClientError> {
    let config = Arc::new(config);
    let ids = Arc::new(AtomicU64::new(1));
    let (wire, hello) = connect_once(&config, &ids).await?;

    let (commands, inbox) = mpsc::channel(COMMAND_CAPACITY);
    let (notifications, stream) = mpsc::channel(config.notification_capacity);
    let shared = Arc::new(Shared::default());

    let client = Client {
        commands,
        ids: ids.clone(),
        request_timeout: config.request_timeout,
        shared: shared.clone(),
    };

    let actor = Actor {
        config,
        hook,
        ids,
        inbox,
        notifications,
        shared,
        handle: client.commands.downgrade(),
        request_timeout: client.request_timeout,
        pending: HashMap::new(),
    };

    tokio::spawn(actor.run(wire));

    Ok(Connected {
        client,
        hello,
        notifications: stream,
    })
}

async fn connect_once(
    config: &TransportConfig,
    ids: &AtomicU64,
) -> Result<(TcpWire, Hello), ClientError> {
    let stream = tokio::time::timeout(config.connect_timeout, TcpStream::connect(config.addr))
        .await
        .map_err(|_elapsed| ClientError::Timeout)?
        .map_err(|error| ClientError::Io(error.to_string()))?;

    let _ = stream.set_nodelay(true);

    let (read, write) = stream.into_split();

    let mut wire = Wire {
        reader: LineReader::new(read, config.max_line),
        writer: write,
        max_outbound: config.max_outbound,
    };

    let hello = handshake(&mut wire, config, ids).await?;

    Ok((wire, hello))
}

async fn handshake<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    wire: &mut Wire<R, W>,
    config: &TransportConfig,
    ids: &AtomicU64,
) -> Result<Hello, ClientError> {
    let id = ids.fetch_add(1, Ordering::Relaxed);

    let params = serde_json::to_value(HelloParams {
        token: config.token.expose(),
        protocol: proto::PROTOCOL,
        client: &config.client,
    })
    .map_err(|error| ClientError::BadJson(error.to_string()))?;

    wire.send(&Request::new(id, "hello", params)).await?;

    let deadline = tokio::time::Instant::now() + config.connect_timeout;

    loop {
        let frame = tokio::time::timeout_at(deadline, wire.next())
            .await
            .map_err(|_elapsed| ClientError::Timeout)??;

        match frame {
            None => return Err(ClientError::ConnectionClosed),
            Some(Incoming::Response {
                id: Some(answered),
                outcome,
            }) if answered == id => {
                let result = (*outcome).map_err(ClientError::Rpc)?;

                return serde_json::from_value(result)
                    .map_err(|error| ClientError::BadJson(error.to_string()));
            }
            Some(Incoming::Response { id: None, outcome }) => {
                return Err(match *outcome {
                    Err(error) => ClientError::Rpc(error),
                    Ok(_) => ClientError::BadJson("an unaddressed hello result".into()),
                });
            }
            // Anything else during a handshake is a server this build does not
            // understand yet, and ignoring it costs only the handshake deadline.
            Some(_other) => continue,
        }
    }
}

enum Outcome {
    Stopped,
    Lost(ClientError),
}

struct Actor {
    config: Arc<TransportConfig>,
    hook: Arc<dyn ReconnectHook>,
    ids: Arc<AtomicU64>,
    inbox: mpsc::Receiver<Command>,
    notifications: mpsc::Sender<Notification>,
    shared: Arc<Shared>,
    /// Weak on purpose: the actor holding a live sender to its own inbox would keep the
    /// connection alive after every caller has dropped its handle.
    handle: mpsc::WeakSender<Command>,
    request_timeout: Duration,
    pending: HashMap<u64, oneshot::Sender<Result<Value, ClientError>>>,
}

impl Actor {
    async fn run(mut self, mut wire: TcpWire) {
        loop {
            match self.pump(&mut wire).await {
                Outcome::Stopped => {
                    self.record_stop(String::new());
                    break;
                }
                Outcome::Lost(reason) => {
                    self.fail_pending(reason);

                    match self.reconnect().await {
                        Ok((next, hello)) => {
                            wire = next;
                            self.run_hook(hello);
                        }
                        Err(fatal) => {
                            self.record_stop(fatal.to_string());
                            break;
                        }
                    }
                }
            }
        }

        self.fail_pending(ClientError::ConnectionClosed);
    }

    async fn pump(&mut self, wire: &mut TcpWire) -> Outcome {
        loop {
            tokio::select! {
                command = self.inbox.recv() => match command {
                    None | Some(Command::Stop) => return Outcome::Stopped,
                    Some(Command::Forget(id)) => {
                        self.pending.remove(&id);
                    }
                    Some(Command::Call { id, method, params, reply }) => {
                        if let Err(error) = wire.send(&Request::new(id, &method, params)).await {
                            let _ = reply.send(Err(error.clone()));

                            match error {
                                // A frame this client refused to write says nothing
                                // about the socket, so the connection survives it.
                                ClientError::FrameTooLarge { .. } | ClientError::BadJson(_) => {
                                    continue
                                }
                                other => return Outcome::Lost(other),
                            }
                        }

                        self.pending.insert(id, reply);
                    }
                },
                frame = wire.next() => match frame {
                    Err(error) => return Outcome::Lost(error),
                    Ok(None) => return Outcome::Lost(ClientError::ConnectionClosed),
                    Ok(Some(incoming)) => {
                        if let Some(error) = self.deliver(incoming) {
                            return Outcome::Lost(error);
                        }
                    }
                },
            }
        }
    }

    fn deliver(&mut self, incoming: Incoming) -> Option<ClientError> {
        match incoming {
            Incoming::Response {
                id: Some(id),
                outcome,
            } => {
                if let Some(reply) = self.pending.remove(&id) {
                    let _ = reply.send((*outcome).map_err(ClientError::Rpc));
                }

                None
            }
            Incoming::Response { id: None, outcome } => Some(match *outcome {
                Err(error) => ClientError::Rpc(error),
                Ok(_) => ClientError::BadJson("an unaddressed result".into()),
            }),
            Incoming::Notification(notification) => {
                if self.notifications.try_send(notification).is_err() {
                    self.shared
                        .dropped_notifications
                        .fetch_add(1, Ordering::Relaxed);
                }

                None
            }
            Incoming::Unrecognized => None,
        }
    }

    async fn reconnect(&mut self) -> Result<(TcpWire, Hello), ClientError> {
        if !self.config.reconnect {
            return Err(ClientError::ConnectionClosed);
        }

        let mut attempt = 0u32;

        loop {
            tokio::time::sleep(self.config.backoff.delay(attempt)).await;
            attempt = attempt.saturating_add(1);

            match connect_once(&self.config, &self.ids).await {
                Ok(established) => {
                    self.shared.reconnects.fetch_add(1, Ordering::Relaxed);
                    return Ok(established);
                }
                Err(error) if error.is_fatal() => return Err(error),
                Err(_transient) => continue,
            }
        }
    }

    /// The hook runs in its own task: it is handed a [`Client`] whose calls this actor
    /// has to serve, and awaiting it here would be awaiting itself.
    fn run_hook(&self, hello: Hello) {
        let Some(commands) = self.handle.upgrade() else {
            return;
        };

        let client = Client {
            commands,
            ids: self.ids.clone(),
            request_timeout: self.request_timeout,
            shared: self.shared.clone(),
        };

        let hook = self.hook.clone();

        tokio::spawn(async move { hook.after_reconnect(client, hello).await });
    }

    fn fail_pending(&mut self, reason: ClientError) {
        for (_id, reply) in self.pending.drain() {
            let _ = reply.send(Err(reason.clone()));
        }
    }

    fn record_stop(&self, reason: String) {
        if let Ok(mut stopped) = self.shared.stopped.lock() {
            *stopped = Some(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn drain(mut reader: LineReader<tokio::io::DuplexStream>) -> Vec<String> {
        let mut lines = Vec::new();

        while let Some(line) = reader.next_line().await.expect("a readable stream") {
            lines.push(String::from_utf8(line).expect("utf-8"));
        }

        lines
    }

    #[tokio::test]
    async fn reads_frames_that_arrive_joined_in_one_read() {
        let (mut writer, reader) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            writer.write_all(b"{\"a\":1}\n{\"b\":2}\n").await.unwrap();
        });

        assert_eq!(
            drain(LineReader::new(reader, 1024)).await,
            vec!["{\"a\":1}", "{\"b\":2}"]
        );
    }

    #[tokio::test]
    async fn reads_a_frame_split_across_reads() {
        let (mut writer, reader) = tokio::io::duplex(8);

        tokio::spawn(async move {
            for chunk in [&b"{\"a\":"[..], &b"1234"[..], &b"5}\n"[..]] {
                writer.write_all(chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        assert_eq!(
            drain(LineReader::new(reader, 1024)).await,
            vec!["{\"a\":12345}"]
        );
    }

    #[tokio::test]
    async fn strips_a_carriage_return_before_the_newline() {
        let (mut writer, reader) = tokio::io::duplex(64);

        tokio::spawn(async move {
            writer.write_all(b"{}\r\n").await.unwrap();
        });

        assert_eq!(drain(LineReader::new(reader, 1024)).await, vec!["{}"]);
    }

    #[tokio::test]
    async fn refuses_a_line_that_never_terminates_inside_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            let _ = writer.write_all(&vec![b'x'; 8192]).await;
            std::future::pending::<()>().await;
        });

        let mut reader = LineReader::new(reader, 64);

        assert!(matches!(
            reader.next_line().await,
            Err(ClientError::FrameTooLarge { limit: 64 })
        ));

        // Poisoned: a reader that refused a frame cannot resynchronize, because the rest
        // of that line is indistinguishable from the next one.
        assert!(matches!(
            reader.next_line().await,
            Err(ClientError::ConnectionClosed)
        ));
    }

    #[tokio::test]
    async fn a_clean_end_of_stream_is_not_an_error() {
        let (writer, reader) = tokio::io::duplex(64);
        drop(writer);

        let mut reader = LineReader::new(reader, 1024);

        assert!(reader.next_line().await.expect("clean eof").is_none());
    }

    #[tokio::test]
    async fn an_end_of_stream_mid_frame_is_an_error() {
        let (mut writer, reader) = tokio::io::duplex(64);

        tokio::spawn(async move {
            writer.write_all(b"{\"a\":1}").await.unwrap();
        });

        let mut reader = LineReader::new(reader, 1024);

        assert!(matches!(reader.next_line().await, Err(ClientError::Io(_))));
    }

    #[test]
    fn backoff_is_capped_and_jittered() {
        let backoff = Backoff {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(2),
            factor: 2.0,
            jitter: 0.5,
        };

        for attempt in 0..12 {
            let delay = backoff.delay(attempt);
            assert!(delay <= Duration::from_secs(2), "attempt {attempt}");
        }

        assert!(backoff.delay(0) >= Duration::from_millis(50));
    }

    #[test]
    fn a_secret_does_not_print_itself() {
        let secret = Secret::new("hunter2".into());

        assert_eq!(format!("{secret:?}"), "Secret(redacted)");
        assert_eq!(secret.expose(), "hunter2");
    }
}
