//! The outside HTTP proxy of the `agent` profile (jail-v1 §10), as a library.
//!
//! It runs in the supervisor, outside the sandbox and the execution cgroup, on
//! std threads with blocking I/O and explicit deadlines; there is no async
//! runtime. The caller binds the Unix listener at `<attempt>/proxy/proxy.sock`
//! and hands it over with the attempt's [`Rules`]; wave 2 wires this into the
//! `agent` profile.
//!
//! For every CONNECT or plain-HTTP request the proxy:
//!
//! 1. reads one request head within the header deadline and byte budget and
//!    parses one unambiguous destination ([`http`]);
//! 2. checks the host rule;
//! 3. resolves a name once, through [`Resolver`], within the DNS deadline;
//! 4. refuses forbidden or mixed answer sets ([`Rules::check_answers`]) and
//!    connects only to an approved numeric address, never resolving again;
//! 5. for CONNECT relays bytes both ways; for plain HTTP forwards exactly the
//!    framed request with hop-by-hop headers and proxy credentials removed,
//!    and relays the response as a stream.
//!
//! Each accepted connection yields exactly one [`ProxyResult`] through the
//! [`ProxySink`] (immediately on denial or connect failure, at close for a
//! relayed request), unless it closed before sending a byte, in which case
//! there was no request. Results carry the destination, safe reason codes,
//! the connected address, byte counters and duration, never a path, query,
//! header, token or body. The proxy writes no log.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::network::{AnswerDenial, Destination, Host, Rules};

mod event;
pub mod http;
mod relay;
mod resolve;

pub use event::proxy_event;
pub use resolve::{FixtureAnswer, FixtureResolver, ResolveError, Resolver, SystemResolver};

/// Resource budgets per attempt (§10). These are budgets, not grants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budgets {
    /// Active connections; excess connections are refused with `overload`.
    pub max_connections: usize,
    /// Bytes of one request head (request line, headers, final CRLF).
    pub max_header_bytes: usize,
    /// From accept to a complete request head.
    pub header_deadline: Duration,
    /// For one resolution.
    pub resolve_deadline: Duration,
    /// For connecting upstream, over every approved address.
    pub connect_deadline: Duration,
    /// Total relay buffer bytes; each relay direction reserves an equal
    /// share, `relay_buffer_bytes / (2 * max_connections)`.
    pub relay_buffer_bytes: usize,
}

impl Default for Budgets {
    /// §10: 128 active connections, 32 KiB request headers, 10-second
    /// DNS/connect/header deadline, 1 MiB total relay buffers.
    fn default() -> Self {
        Budgets {
            max_connections: 128,
            max_header_bytes: 32 * 1024,
            header_deadline: Duration::from_secs(10),
            resolve_deadline: Duration::from_secs(10),
            connect_deadline: Duration::from_secs(10),
            relay_buffer_bytes: 1024 * 1024,
        }
    }
}

impl Budgets {
    /// The buffer one relay direction reserves.
    #[must_use]
    pub fn relay_chunk(&self) -> usize {
        self.relay_buffer_bytes
            .checked_div(self.max_connections.saturating_mul(2))
            .unwrap_or(0)
    }
}

/// The longest deadline a budget may carry; beyond it `Instant` arithmetic
/// is not guaranteed and no request needs that long.
pub const MAX_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);

/// Everything the proxy needs.
pub struct ProxyConfig {
    /// Bound by the caller at `<attempt>/proxy/proxy.sock`.
    pub listener: UnixListener,
    /// Allow-host rules and explicit address grants.
    pub rules: Rules,
    /// Resource budgets.
    pub budgets: Budgets,
    /// The host resolver; the jail never resolves inside the sandbox.
    pub resolver: Arc<dyn Resolver + Send + Sync>,
}

/// What kind of request a result describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestKind {
    /// A CONNECT tunnel.
    Connect,
    /// A plain-HTTP absolute-form request.
    Http,
    /// Nothing parseable arrived.
    Unknown,
}

impl RequestKind {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RequestKind::Connect => "connect",
            RequestKind::Http => "http",
            RequestKind::Unknown => "unknown",
        }
    }
}

/// The proxy's policy decision, independent of connect success (§13.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyDecision {
    /// The destination passed every check.
    Allow,
    /// The request was refused.
    Deny,
}

/// A safe reason code. Never contains request data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    /// Allowed, connected and relayed until close.
    Relayed,
    /// Allowed, but no approved address accepted the connection.
    ConnectFailed,
    /// Allowed, but connecting exceeded the deadline.
    ConnectTimeout,
    /// No host rule permits the destination.
    HostNotAllowed,
    /// Every answer is forbidden or unusable.
    ForbiddenAddress,
    /// Allowed and forbidden answers were mixed.
    MixedAnswers,
    /// The resolver returned no address.
    ResolveEmpty,
    /// The resolver failed.
    ResolveFailed,
    /// Resolution exceeded the deadline.
    ResolveTimeout,
    /// The request head is malformed.
    MalformedRequest,
    /// The body framing is ambiguous (duplicate or conflicting lengths).
    AmbiguousFraming,
    /// The absolute-URI authority and Host disagree.
    HostMismatch,
    /// Not a CONNECT or `http://` absolute-form request.
    UnsupportedRequest,
    /// The request head exceeded the byte budget.
    HeaderTooLarge,
    /// The request head did not complete within the deadline.
    HeaderTimeout,
    /// The client closed or failed before completing the head.
    ClientClosed,
    /// The connection budget was exhausted.
    Overload,
    /// The proxy is stopping.
    Stopping,
    /// The handler failed unexpectedly; the request was not relayed.
    InternalError,
}

impl Reason {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Relayed => "relayed",
            Reason::ConnectFailed => "connect_failed",
            Reason::ConnectTimeout => "connect_timeout",
            Reason::HostNotAllowed => "host_not_allowed",
            Reason::ForbiddenAddress => "forbidden_address",
            Reason::MixedAnswers => "mixed_answers",
            Reason::ResolveEmpty => "resolve_empty",
            Reason::ResolveFailed => "resolve_failed",
            Reason::ResolveTimeout => "resolve_timeout",
            Reason::MalformedRequest => "malformed_request",
            Reason::AmbiguousFraming => "ambiguous_framing",
            Reason::HostMismatch => "host_mismatch",
            Reason::UnsupportedRequest => "unsupported_request",
            Reason::HeaderTooLarge => "header_too_large",
            Reason::HeaderTimeout => "header_timeout",
            Reason::ClientClosed => "client_closed",
            Reason::Overload => "overload",
            Reason::Stopping => "stopping",
            Reason::InternalError => "internal_error",
        }
    }

    fn status(self) -> (u16, &'static str) {
        match self {
            Reason::HostNotAllowed | Reason::ForbiddenAddress | Reason::MixedAnswers => {
                (403, "Forbidden")
            }
            Reason::ResolveEmpty | Reason::ResolveFailed | Reason::ConnectFailed => {
                (502, "Bad Gateway")
            }
            Reason::ResolveTimeout | Reason::ConnectTimeout => (504, "Gateway Timeout"),
            Reason::HeaderTooLarge => (431, "Request Header Fields Too Large"),
            Reason::HeaderTimeout => (408, "Request Timeout"),
            Reason::Overload | Reason::Stopping => (503, "Service Unavailable"),
            Reason::InternalError => (500, "Internal Server Error"),
            Reason::MalformedRequest
            | Reason::AmbiguousFraming
            | Reason::HostMismatch
            | Reason::UnsupportedRequest
            | Reason::ClientClosed
            | Reason::Relayed => (400, "Bad Request"),
        }
    }
}

/// How an allowed, connected request ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndReason {
    /// The upstream closed its side first.
    UpstreamClosed,
    /// The client closed its side first.
    ClientClosed,
    /// Reading from or writing to the upstream failed.
    UpstreamError,
    /// Reading from or writing to the client failed.
    ClientError,
    /// The client's request body framing was invalid; forwarding stopped at
    /// the first invalid byte.
    ClientFraming,
    /// The proxy was stopped.
    Stopped,
}

impl EndReason {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EndReason::UpstreamClosed => "upstream_closed",
            EndReason::ClientClosed => "client_closed",
            EndReason::UpstreamError => "upstream_error",
            EndReason::ClientError => "client_error",
            EndReason::ClientFraming => "client_framing",
            EndReason::Stopped => "stopped",
        }
    }
}

/// One proxy result: the facts of one request, never its content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProxyResult {
    /// Unique within this proxy, starting at 1, in accept order.
    pub request_id: u64,
    /// CONNECT, plain HTTP, or unknown.
    pub kind: RequestKind,
    /// The normalized destination, when one was parsed.
    pub destination: Option<Destination>,
    /// Allow or deny.
    pub decision: ProxyDecision,
    /// Why.
    pub reason: Reason,
    /// The numeric address actually connected.
    pub connected: Option<SocketAddr>,
    /// The OS error of a failed connect, when there was one.
    pub connect_errno: Option<i32>,
    /// Bytes relayed from the destination to the client.
    pub bytes_in: u64,
    /// Bytes relayed from the client to the destination (for plain HTTP
    /// including the rewritten request head).
    pub bytes_out: u64,
    /// From accept to the result.
    pub duration: Duration,
    /// How a relayed request ended.
    pub end: Option<EndReason>,
}

/// Receives results. Called from connection threads; must not block for
/// long, because a blocked sink holds that connection's slot.
pub trait ProxySink: Send + Sync {
    /// One result.
    fn emit(&self, result: ProxyResult);
}

/// What [`ProxyHandle::stop`] established.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ProxySummary {
    /// Connections accepted, including the ones refused for overload.
    pub accepted: u64,
    /// Results delivered to the sink.
    pub results_emitted: u64,
    /// Connections whose result could not be emitted because the drain budget
    /// ran out first. Coverage must reflect these.
    pub results_missing: u64,
    /// Connections that closed before sending a byte: no request, no result.
    pub without_request: u64,
    /// The accept loop exited and dropped the listener.
    pub listener_closed: bool,
    /// Every connection finished within the budget.
    pub drained: bool,
}

impl ProxySummary {
    /// Whether every request's result was delivered: no missing result and
    /// a complete drain. When false, `proxy.net` coverage has a gap (§10,
    /// §11.4: "An interrupted drain can leave that result missing; coverage
    /// must reflect it").
    #[must_use]
    pub fn complete(&self) -> bool {
        self.results_missing == 0 && self.drained
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// A closable handle on one socket of a live connection.
enum Closer {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Closer {
    fn shutdown(&self) {
        // Closing is best effort: a socket already closed has nothing left
        // to unblock.
        let _ = match self {
            Closer::Unix(stream) => stream.shutdown(Shutdown::Both),
            Closer::Tcp(stream) => stream.shutdown(Shutdown::Both),
        };
    }
}

#[derive(Default)]
struct Registry {
    stopping: bool,
    live: HashMap<u64, Vec<Closer>>,
}

#[derive(Default)]
struct Accounting {
    accepted: u64,
    emitted: u64,
    without_request: u64,
    sealed: bool,
}

struct Shared {
    rules: Rules,
    budgets: Budgets,
    resolver: Arc<dyn Resolver + Send + Sync>,
    sink: Arc<dyn ProxySink>,
    stopping: AtomicBool,
    registry: Mutex<Registry>,
    accounting: Mutex<Accounting>,
    /// Signalled whenever a connection settles (result or no request).
    settled: Condvar,
    /// Admitted connections still being served. Only the accept thread
    /// increments it, so the admission check cannot overshoot.
    active: AtomicUsize,
    relay_pool: AtomicUsize,
    next_id: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere must not stop accounting; the data stays consistent
    // because every critical section is a few counter updates.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Registers a socket so that stop can shut it down. Refuses (and shuts
    /// the socket down) once stopping has begun.
    fn register(&self, id: u64, closer: Closer) -> bool {
        let mut registry = lock(&self.registry);
        if registry.stopping {
            drop(registry);
            closer.shutdown();
            return false;
        }
        registry.live.entry(id).or_default().push(closer);
        true
    }

    fn unregister(&self, id: u64) {
        lock(&self.registry).live.remove(&id);
    }

    fn emit(&self, result: ProxyResult) {
        let mut accounting = lock(&self.accounting);
        if accounting.sealed {
            // Counted as missing when the seal was computed.
            return;
        }
        accounting.emitted += 1;
        // Emitting under the lock orders results with the seal: a result is
        // either delivered and counted, or dropped and reported missing.
        self.sink.emit(result);
        drop(accounting);
        self.settled.notify_all();
    }

    fn no_request(&self) {
        lock(&self.accounting).without_request += 1;
        self.settled.notify_all();
    }

    fn reserve_relay(&self) -> bool {
        let chunk = self.budgets.relay_chunk();
        let mut current = self.relay_pool.load(Ordering::SeqCst);
        loop {
            let Some(next) = current.checked_sub(chunk.saturating_mul(2)) else {
                return false;
            };
            match self.relay_pool.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn release_relay(&self) {
        self.relay_pool.fetch_add(
            self.budgets.relay_chunk().saturating_mul(2),
            Ordering::SeqCst,
        );
    }
}

// ---------------------------------------------------------------------------
// Start and stop
// ---------------------------------------------------------------------------

/// A running proxy.
pub struct ProxyHandle {
    shared: Arc<Shared>,
    wake: Option<std::os::unix::net::SocketAddr>,
    accept_done: Option<mpsc::Receiver<()>>,
}

/// Starts the proxy on the caller's listener.
///
/// # Errors
/// Returns an error when the budgets are unusable (zero connections, a
/// zero-byte relay share or header budget, a deadline of zero or above
/// [`MAX_DEADLINE`]) or the accept thread cannot start.
pub fn start(config: ProxyConfig, sink: Arc<dyn ProxySink>) -> io::Result<ProxyHandle> {
    let ProxyConfig {
        listener,
        rules,
        budgets,
        resolver,
    } = config;
    let deadline_ok = |deadline: Duration| !deadline.is_zero() && deadline <= MAX_DEADLINE;
    if budgets.max_connections == 0
        || budgets.relay_chunk() == 0
        || budgets.max_header_bytes < 16
        || !deadline_ok(budgets.header_deadline)
        || !deadline_ok(budgets.resolve_deadline)
        || !deadline_ok(budgets.connect_deadline)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the proxy budgets leave no usable connection or have an unusable deadline",
        ));
    }
    listener.set_nonblocking(false)?;
    let wake = listener.local_addr().ok();
    let shared = Arc::new(Shared {
        rules,
        budgets,
        resolver,
        sink,
        stopping: AtomicBool::new(false),
        registry: Mutex::new(Registry::default()),
        accounting: Mutex::new(Accounting::default()),
        settled: Condvar::new(),
        active: AtomicUsize::new(0),
        relay_pool: AtomicUsize::new(budgets.relay_chunk() * 2 * budgets.max_connections),
        next_id: AtomicU64::new(1),
    });
    let (done_tx, done_rx) = mpsc::channel();
    let accept_shared = Arc::clone(&shared);
    thread::Builder::new()
        .name("ouro-proxy-accept".to_owned())
        .spawn(move || {
            accept_loop(&accept_shared, &listener);
            drop(listener);
            let _ = done_tx.send(());
        })?;
    Ok(ProxyHandle {
        shared,
        wake,
        accept_done: Some(done_rx),
    })
}

impl ProxyHandle {
    /// The number of connections currently being handled.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    fn begin_stop(&self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        let live = {
            let mut registry = lock(&self.shared.registry);
            registry.stopping = true;
            std::mem::take(&mut registry.live)
        };
        for closer in live.values().flatten() {
            closer.shutdown();
        }
        // Wake a blocked accept(2): the accept loop sees `stopping` on the
        // next connection and exits, dropping the listener. The connect runs
        // on its own thread because a full backlog blocks a Unix connect.
        if let Some(address) = self.wake.clone() {
            let _ = thread::Builder::new()
                .name("ouro-proxy-wake".to_owned())
                .stack_size(64 * 1024)
                .spawn(move || {
                    let _ = UnixStream::connect_addr(&address);
                });
        }
    }

    /// Closes the listener and every connection, waits up to `budget` for
    /// every accepted connection to settle (emit its result, or close without
    /// a request), then seals: a result that arrives later is dropped and
    /// counted in `results_missing`.
    #[must_use]
    pub fn stop(mut self, budget: Duration) -> ProxySummary {
        let deadline = Instant::now() + budget;
        self.begin_stop();
        let listener_closed = match self.accept_done.take() {
            Some(done) => done
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok(),
            None => false,
        };
        let mut accounting = lock(&self.shared.accounting);
        let unsettled = |accounting: &Accounting| {
            accounting.accepted > accounting.emitted + accounting.without_request
        };
        while unsettled(&accounting) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            accounting = self
                .shared
                .settled
                .wait_timeout(accounting, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let drained = !unsettled(&accounting);
        accounting.sealed = true;
        let missing = accounting
            .accepted
            .saturating_sub(accounting.emitted)
            .saturating_sub(accounting.without_request);
        ProxySummary {
            accepted: accounting.accepted,
            results_emitted: accounting.emitted,
            results_missing: missing,
            without_request: accounting.without_request,
            listener_closed,
            drained,
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if self.accept_done.is_some() {
            self.begin_stop();
        }
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &UnixListener) {
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if shared.is_stopping() {
                    return;
                }
                // A transient accept failure (for example descriptor
                // exhaustion) must not spin: back off briefly and retry.
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        if shared.is_stopping() {
            return;
        }
        let accepted_at = Instant::now();
        let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        lock(&shared.accounting).accepted += 1;
        if shared.active.load(Ordering::SeqCst) >= shared.budgets.max_connections {
            refuse_inline(shared, stream, id, accepted_at, Reason::Overload);
            continue;
        }
        // Register the client for stop before the handler runs, so a stop
        // that begins at any later point closes this connection too.
        let registered = stream
            .try_clone()
            .is_ok_and(|clone| shared.register(id, Closer::Unix(clone)));
        if !registered {
            if shared.is_stopping() {
                // `accepted` counted it; settle it as a refusal.
                shared.emit(denial(
                    id,
                    None,
                    RequestKind::Unknown,
                    Reason::Stopping,
                    accepted_at,
                ));
                return;
            }
            refuse_inline(shared, stream, id, accepted_at, Reason::Overload);
            continue;
        }
        shared.active.fetch_add(1, Ordering::SeqCst);
        let handler_shared = Arc::clone(shared);
        let spawned = thread::Builder::new()
            .name("ouro-proxy-conn".to_owned())
            .stack_size(256 * 1024)
            .spawn(move || handle_connection(&handler_shared, stream, id, accepted_at));
        if spawned.is_err() {
            // The closure (and its stream) was dropped without running:
            // release the admission here and report the refusal.
            shared.unregister(id);
            shared.active.fetch_sub(1, Ordering::SeqCst);
            shared.emit(denial(
                id,
                None,
                RequestKind::Unknown,
                Reason::Overload,
                accepted_at,
            ));
        }
    }
}

/// Refuses a connection on the accept thread without reading from it: the
/// short response goes into an empty socket buffer, never blocking.
fn refuse_inline(
    shared: &Shared,
    stream: UnixStream,
    id: u64,
    accepted_at: Instant,
    reason: Reason,
) {
    shared.emit(denial(id, None, RequestKind::Unknown, reason, accepted_at));
    if stream.set_nonblocking(true).is_ok() {
        let mut stream = stream;
        let _ = stream.write_all(&http::error_response(reason));
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn denial(
    id: u64,
    destination: Option<Destination>,
    kind: RequestKind,
    reason: Reason,
    accepted_at: Instant,
) -> ProxyResult {
    ProxyResult {
        request_id: id,
        kind,
        destination,
        decision: ProxyDecision::Deny,
        reason,
        connected: None,
        connect_errno: None,
        bytes_in: 0,
        bytes_out: 0,
        duration: accepted_at.elapsed(),
        end: None,
    }
}

// ---------------------------------------------------------------------------
// One connection
// ---------------------------------------------------------------------------

/// Guarantees exactly one result (or one "no request" count) per connection,
/// including when the handler panics, and releases the connection's
/// admission just before it settles, so a caller that saw the result can
/// rely on the slot being free.
struct ResultSlot<'a> {
    shared: &'a Shared,
    id: u64,
    accepted_at: Instant,
    kind: RequestKind,
    destination: Option<Destination>,
    admitted: bool,
    done: bool,
}

impl ResultSlot<'_> {
    fn release(&mut self) {
        if self.admitted {
            self.admitted = false;
            self.shared.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn emit(&mut self, result: ProxyResult) {
        if !self.done {
            self.done = true;
            self.release();
            self.shared.emit(result);
        }
    }

    fn deny(&mut self, reason: Reason) {
        let result = denial(
            self.id,
            self.destination.clone(),
            self.kind,
            reason,
            self.accepted_at,
        );
        self.emit(result);
    }

    fn no_request(&mut self) {
        if !self.done {
            self.done = true;
            self.release();
            self.shared.no_request();
        }
    }
}

impl Drop for ResultSlot<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.deny(Reason::InternalError);
        }
        self.release();
    }
}

fn respond(client: &mut UnixStream, reason: Reason, budget: Duration) {
    let _ = client.set_write_timeout(Some(budget.max(Duration::from_millis(1))));
    let _ = client.write_all(&http::error_response(reason));
    let _ = client.shutdown(Shutdown::Both);
}

fn handle_connection(shared: &Shared, client: UnixStream, id: u64, accepted_at: Instant) {
    let mut slot = ResultSlot {
        shared,
        id,
        accepted_at,
        kind: RequestKind::Unknown,
        destination: None,
        admitted: true,
        done: false,
    };
    let respond_budget = shared.budgets.header_deadline;
    let mut client = client;
    let outcome = serve(shared, &mut slot, &mut client, accepted_at);
    shared.unregister(id);
    if let Err(reason) = outcome {
        slot.deny(reason);
        respond(&mut client, reason, respond_budget);
    }
}

/// Serves one request. `Err` is a denial the caller reports and answers;
/// `Ok` means the result was already emitted (or there was no request).
fn serve(
    shared: &Shared,
    slot: &mut ResultSlot<'_>,
    client: &mut UnixStream,
    accepted_at: Instant,
) -> Result<(), Reason> {
    let budgets = shared.budgets;
    let head = match http::read_head(
        client,
        budgets.max_header_bytes,
        accepted_at + budgets.header_deadline,
    ) {
        Ok(head) => head,
        Err(http::HeadError::NoBytes) => {
            slot.no_request();
            return Ok(());
        }
        Err(http::HeadError::Reject(reason)) => {
            return Err(if shared.is_stopping() && reason == Reason::ClientClosed {
                Reason::Stopping
            } else {
                reason
            });
        }
    };
    let request = http::parse_request(head.head())?;
    slot.kind = request.kind();
    slot.destination = Some(request.destination.clone());
    if shared.is_stopping() {
        return Err(Reason::Stopping);
    }
    // Step 1: the host rule.
    if !shared.rules.permits_destination(&request.destination) {
        return Err(Reason::HostNotAllowed);
    }
    // Step 2: resolve on the host, once.
    let answers = match &request.destination.host {
        Host::Ip(address) => vec![*address],
        Host::Name(name) => {
            let deadline = Instant::now() + budgets.resolve_deadline;
            match shared.resolver.resolve(name, deadline) {
                Ok(answers) => answers,
                Err(ResolveError::Timeout) => return Err(Reason::ResolveTimeout),
                Err(_) => return Err(Reason::ResolveFailed),
            }
        }
    };
    // Steps 3 and 4: every answer passes, or none is used.
    let approved = shared
        .rules
        .check_answers(request.destination.port, &answers)
        .map_err(|denial| match denial {
            AnswerDenial::Empty => Reason::ResolveEmpty,
            AnswerDenial::Forbidden => Reason::ForbiddenAddress,
            AnswerDenial::Mixed => Reason::MixedAnswers,
        })?;
    if shared.is_stopping() {
        return Err(Reason::Stopping);
    }
    if !shared.reserve_relay() {
        return Err(Reason::Overload);
    }
    let result = connect_and_relay(shared, slot, client, &request, &approved, head, accepted_at);
    shared.release_relay();
    result
}

fn connect_upstream(
    approved: &[IpAddr],
    port: u16,
    deadline: Instant,
) -> Result<(TcpStream, SocketAddr), (Reason, Option<i32>)> {
    let mut last: (Reason, Option<i32>) = (Reason::ConnectFailed, None);
    for &address in approved {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((Reason::ConnectTimeout, None));
        }
        let target = SocketAddr::new(address, port);
        match TcpStream::connect_timeout(&target, remaining) {
            Ok(stream) => return Ok((stream, target)),
            Err(error) => {
                let reason = if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) {
                    Reason::ConnectTimeout
                } else {
                    Reason::ConnectFailed
                };
                last = (reason, error.raw_os_error());
            }
        }
    }
    Err(last)
}

fn connect_and_relay(
    shared: &Shared,
    slot: &mut ResultSlot<'_>,
    client: &mut UnixStream,
    request: &http::Request,
    approved: &[IpAddr],
    head: http::Head,
    accepted_at: Instant,
) -> Result<(), Reason> {
    let budgets = shared.budgets;
    let deadline = Instant::now() + budgets.connect_deadline;
    let (upstream, connected) = match connect_upstream(approved, request.destination.port, deadline)
    {
        Ok(pair) => pair,
        Err((reason, errno)) => {
            // Allowed by policy; the connection itself failed.
            slot.emit(ProxyResult {
                request_id: slot.id,
                kind: request.kind(),
                destination: Some(request.destination.clone()),
                decision: ProxyDecision::Allow,
                reason,
                connected: None,
                connect_errno: errno,
                bytes_in: 0,
                bytes_out: 0,
                duration: accepted_at.elapsed(),
                end: None,
            });
            respond(client, reason, budgets.header_deadline);
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(true);
    let registered = upstream
        .try_clone()
        .is_ok_and(|clone| shared.register(slot.id, Closer::Tcp(clone)));
    if !registered {
        // The destination was connected, so say so: allowed, connected,
        // nothing relayed, ended by the stop (or by a descriptor failure).
        let _ = upstream.shutdown(Shutdown::Both);
        slot.emit(ProxyResult {
            request_id: slot.id,
            kind: request.kind(),
            destination: Some(request.destination.clone()),
            decision: ProxyDecision::Allow,
            reason: Reason::Relayed,
            connected: Some(connected),
            connect_errno: None,
            bytes_in: 0,
            bytes_out: 0,
            duration: accepted_at.elapsed(),
            end: Some(if shared.is_stopping() {
                EndReason::Stopped
            } else {
                EndReason::ClientError
            }),
        });
        let _ = client.shutdown(Shutdown::Both);
        return Ok(());
    }
    let chunk = budgets.relay_chunk();
    let outcome = match &request.framing {
        http::Framing::Tunnel => relay::tunnel(
            client,
            upstream,
            head.leftover(),
            chunk,
            budgets.header_deadline,
        ),
        framing => relay::http(
            client,
            upstream,
            &request.forward_head,
            framing,
            head.leftover(),
            chunk,
        ),
    };
    let end = if shared.is_stopping() {
        EndReason::Stopped
    } else {
        outcome.end
    };
    slot.emit(ProxyResult {
        request_id: slot.id,
        kind: request.kind(),
        destination: Some(request.destination.clone()),
        decision: ProxyDecision::Allow,
        reason: Reason::Relayed,
        connected: Some(connected),
        connect_errno: None,
        bytes_in: outcome.bytes_in,
        bytes_out: outcome.bytes_out,
        duration: accepted_at.elapsed(),
        end: Some(end),
    });
    Ok(())
}
