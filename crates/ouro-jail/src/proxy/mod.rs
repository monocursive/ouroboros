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
//! One request per client connection: bytes after the first request are
//! read, counted in [`ProxyResult::discarded_bytes`] and dropped, and the
//! connection closes after its response. Deadlines are per phase: the header
//! deadline runs from accept, the resolve and connect deadlines from the start
//! of their phase.
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
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::network::{AnswerDenial, Destination, Host, Rules};

mod event;
pub mod http;
mod relay;
mod resolve;
mod sys;

pub use event::proxy_event;
pub use resolve::{
    FixtureAnswer, FixtureResolver, Lookup, ResolveError, Resolver, SystemResolver, absolute_name,
};
pub use sys::{nofile_limits, open_descriptor_count, raise_nofile_soft_to_hard};

/// Resource budgets per attempt (§10). These are budgets, not grants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budgets {
    /// Active connections; excess connections are refused with `overload`.
    pub max_connections: usize,
    /// Bytes of one request head (request line, headers, final CRLF).
    pub max_header_bytes: usize,
    /// From accept to a complete request head.
    pub header_deadline: Duration,
    /// For one resolution, from its start.
    pub resolve_deadline: Duration,
    /// For connecting upstream, over every approved address, from its start.
    pub connect_deadline: Duration,
    /// Total relay buffer bytes. Each relay direction of an admitted
    /// connection owns `relay_buffer_bytes / (2 * max_connections)`, and at
    /// most `max_connections` connections are admitted, so the total holds
    /// by construction.
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
    /// The buffer one relay direction owns.
    #[must_use]
    pub fn relay_chunk(&self) -> usize {
        self.relay_buffer_bytes
            .checked_div(self.max_connections.saturating_mul(2))
            .unwrap_or(0)
    }

    /// The descriptors the budget needs: [`FDS_PER_CONNECTION`] per
    /// connection plus [`FD_HEADROOM`].
    #[must_use]
    pub fn descriptors_needed(&self) -> usize {
        self.max_connections
            .saturating_mul(FDS_PER_CONNECTION)
            .saturating_add(FD_HEADROOM)
    }
}

/// The longest deadline a budget may carry; beyond it `Instant` arithmetic
/// is not guaranteed and no request needs that long.
pub const MAX_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);

/// Descriptors one admitted connection holds at most: the client's socket
/// and the destination's. Both relay directions and the stop registry share
/// them; nothing is duplicated.
pub const FDS_PER_CONNECTION: usize = 2;

/// Descriptors reserved beyond the connections: the listener and its wake
/// pair, connections being refused for overload, resolver lookups, and the
/// rest of the supervisor.
pub const FD_HEADROOM: usize = 64;

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
    /// The resolver refused: too many lookups outstanding.
    ResolverOverloaded,
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
    /// The proxy ran out of a process resource (descriptors or threads).
    ResourceExhausted,
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
            Reason::ResolverOverloaded => "resolver_overloaded",
            Reason::MalformedRequest => "malformed_request",
            Reason::AmbiguousFraming => "ambiguous_framing",
            Reason::HostMismatch => "host_mismatch",
            Reason::UnsupportedRequest => "unsupported_request",
            Reason::HeaderTooLarge => "header_too_large",
            Reason::HeaderTimeout => "header_timeout",
            Reason::ClientClosed => "client_closed",
            Reason::Overload => "overload",
            Reason::ResourceExhausted => "resource_exhausted",
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
            Reason::Overload
            | Reason::ResourceExhausted
            | Reason::ResolverOverloaded
            | Reason::Stopping => (503, "Service Unavailable"),
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

/// How an allowed, connected, relayed request ended.
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
    /// The numeric address actually connected, whether or not anything was
    /// relayed afterwards.
    pub connected: Option<SocketAddr>,
    /// The OS error of a failed connect, when there was one.
    pub connect_errno: Option<i32>,
    /// Bytes relayed from the destination to the client.
    pub bytes_in: u64,
    /// Bytes relayed from the client to the destination (for plain HTTP
    /// including the rewritten request head).
    pub bytes_out: u64,
    /// Client bytes after the first request (a second, pipelined request,
    /// for example), read and not forwarded: one request per connection.
    pub discarded_bytes: u64,
    /// From accept to the result.
    pub duration: Duration,
    /// How a relayed request ended; `None` when nothing was relayed.
    pub end: Option<EndReason>,
}

/// Receives results. Called from connection threads; must not block for
/// long, because a blocked sink holds that connection's slot.
pub trait ProxySink: Send + Sync {
    /// One result.
    fn emit(&self, result: ProxyResult);
}

/// What [`ProxyHandle::stop`] established. It covers accepted connections
/// only: connections still in the kernel's backlog when stop began are
/// closed without being accepted, so they have no result and no count.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ProxySummary {
    /// Connections accepted, including the ones refused for overload.
    pub accepted: u64,
    /// Results delivered to the sink.
    pub results_emitted: u64,
    /// Accepted connections whose result was not delivered because the drain
    /// budget ran out first. Coverage must reflect these.
    pub results_missing: u64,
    /// Connections that closed before sending a byte: no request, no result.
    pub without_request: u64,
    /// The accept loop exited and dropped the listener within the budget.
    pub listener_closed: bool,
}

impl ProxySummary {
    /// Whether every accepted connection settled: its result was delivered
    /// or it sent no request. When false, `proxy.net` coverage has a gap
    /// (§10, §11.4: "An interrupted drain can leave that result missing;
    /// coverage must reflect it").
    #[must_use]
    pub fn complete(&self) -> bool {
        self.results_missing == 0
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// A socket of a live connection, shared with its handler, so stop can shut
/// it down without holding a second descriptor.
enum Closer {
    Unix(Arc<UnixStream>),
    Tcp(Arc<TcpStream>),
}

impl Closer {
    fn shutdown(&self) {
        // Best effort: a socket already closed has nothing left to unblock.
        let _ = match self {
            Closer::Unix(stream) => stream.shutdown(Shutdown::Both),
            Closer::Tcp(stream) => stream.shutdown(Shutdown::Both),
        };
    }
}

/// The single source of truth for stopping, and the sockets stop closes.
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

impl Accounting {
    fn missing(&self) -> u64 {
        self.accepted
            .saturating_sub(self.emitted)
            .saturating_sub(self.without_request)
    }
}

struct Shared {
    rules: Rules,
    budgets: Budgets,
    resolver: Arc<dyn Resolver + Send + Sync>,
    sink: Arc<dyn ProxySink>,
    registry: Mutex<Registry>,
    accounting: Mutex<Accounting>,
    /// Signalled whenever a connection settles (result or no request).
    settled: Condvar,
    /// Admitted connections that have not settled. Only the accept thread
    /// increments it, under the registry lock, so admission cannot overshoot.
    active: AtomicUsize,
    next_id: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere must not stop accounting; the data stays consistent
    // because every critical section is a few field updates.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the accept thread does with one accepted socket.
enum Admission {
    /// Stop began: close it without a result, like the backlog.
    Stopping,
    /// Over the connection budget: refuse it with a result.
    Overload(u64),
    /// Admitted and registered.
    Admitted(u64),
}

impl Shared {
    fn is_stopping(&self) -> bool {
        lock(&self.registry).stopping
    }

    /// Admits one accepted socket. The stopping check, the id, the accepted
    /// count, the admission and the registration happen under the registry
    /// lock, so stop either sees this connection registered and counted, or
    /// the connection sees stop.
    fn admit(&self, client: &Arc<UnixStream>) -> Admission {
        let mut registry = lock(&self.registry);
        if registry.stopping {
            return Admission::Stopping;
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        lock(&self.accounting).accepted += 1;
        if self.active.load(Ordering::SeqCst) >= self.budgets.max_connections {
            return Admission::Overload(id);
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        registry
            .live
            .insert(id, vec![Closer::Unix(Arc::clone(client))]);
        Admission::Admitted(id)
    }

    /// Registers another socket of a live connection; `false` once stop
    /// began (the caller then closes it).
    fn register(&self, id: u64, closer: Closer) -> bool {
        let mut registry = lock(&self.registry);
        if registry.stopping {
            return false;
        }
        registry.live.entry(id).or_default().push(closer);
        true
    }

    /// Removes a connection's sockets from the registry and shuts them down.
    fn close_connection(&self, id: u64) {
        let closers = lock(&self.registry).live.remove(&id);
        for closer in closers.iter().flatten() {
            closer.shutdown();
        }
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
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
        let mut accounting = lock(&self.accounting);
        if accounting.sealed {
            return;
        }
        accounting.without_request += 1;
        drop(accounting);
        self.settled.notify_all();
    }
}

// ---------------------------------------------------------------------------
// Start and stop
// ---------------------------------------------------------------------------

/// A running proxy.
pub struct ProxyHandle {
    shared: Arc<Shared>,
    /// Writing a byte here wakes the accept thread, whatever happened to the
    /// listener's path.
    wake: Option<UnixStream>,
    accept_done: Option<mpsc::Receiver<()>>,
    // J3-agent begin: whether the accept loop still runs
    serving: Arc<std::sync::atomic::AtomicBool>,
    // J3-agent end
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Raises the soft descriptor limit to the hard one and checks that the
/// budget fits, naming the numbers when it does not.
fn check_descriptors(budgets: &Budgets) -> io::Result<()> {
    let (soft, hard) = sys::raise_nofile_soft_to_hard()?;
    let open = sys::open_descriptor_count()?;
    let need = budgets.descriptors_needed();
    let open = u64::try_from(open).unwrap_or(u64::MAX);
    let free = soft.saturating_sub(open);
    if free < u64::try_from(need).unwrap_or(u64::MAX) {
        return Err(io::Error::other(format!(
            "RLIMIT_NOFILE allows {soft} descriptors (hard limit {hard}) and {open} are open, \
             leaving {free}; the proxy budget needs {} connections x {FDS_PER_CONNECTION} \
             descriptors + {FD_HEADROOM} headroom = {need}",
            budgets.max_connections
        )));
    }
    Ok(())
}

/// Starts the proxy on the caller's listener.
///
/// Raises this process's soft `RLIMIT_NOFILE` to its hard limit, then
/// refuses unless `max_connections x FDS_PER_CONNECTION + FD_HEADROOM`
/// descriptors are free.
///
/// # Errors
/// Returns an error when the budgets are unusable (zero connections, a
/// zero-byte relay share or header budget, a deadline of zero or above
/// [`MAX_DEADLINE`]), when the descriptor budget does not fit, or when the
/// accept thread cannot start.
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
        return Err(invalid(
            "the proxy budgets leave no usable connection or have an unusable deadline".to_owned(),
        ));
    }
    check_descriptors(&budgets)?;
    // Accept only when poll says a connection is pending; a nonblocking
    // listener keeps a vanished connection from blocking the loop.
    listener.set_nonblocking(true)?;
    let (wake, wake_reader) = UnixStream::pair()?;
    let shared = Arc::new(Shared {
        rules,
        budgets,
        resolver,
        sink,
        registry: Mutex::new(Registry::default()),
        accounting: Mutex::new(Accounting::default()),
        settled: Condvar::new(),
        active: AtomicUsize::new(0),
        next_id: AtomicU64::new(1),
    });
    let (done_tx, done_rx) = mpsc::channel();
    let accept_shared = Arc::clone(&shared);
    // J3-agent begin
    let serving = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let serving_flag = Arc::clone(&serving);
    // J3-agent end
    thread::Builder::new()
        .name("ouro-proxy-accept".to_owned())
        .spawn(move || {
            accept_loop(&accept_shared, &listener, &wake_reader);
            serving_flag.store(false, Ordering::SeqCst);
            drop(listener);
            let _ = done_tx.send(());
        })?;
    Ok(ProxyHandle {
        shared,
        wake: Some(wake),
        accept_done: Some(done_rx),
        serving,
    })
}

impl ProxyHandle {
    // J3-agent begin: a proxy that stopped serving is a recorded fact (§10)
    /// Whether the accept loop still runs. It stops on [`ProxyHandle::stop`]
    /// and when its listener is no longer listening (shut down by anything),
    /// after which every new connection to the socket is refused: the proxy
    /// fails closed and nothing reconnects it.
    #[must_use]
    pub fn serving(&self) -> bool {
        self.serving.load(Ordering::SeqCst)
    }
    // J3-agent end

    /// The number of admitted connections that have not settled.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    fn begin_stop(&mut self) {
        let live = {
            let mut registry = lock(&self.shared.registry);
            registry.stopping = true;
            std::mem::take(&mut registry.live)
        };
        for closer in live.values().flatten() {
            closer.shutdown();
        }
        // Wake the accept thread through its own channel, not through the
        // listener's path, which the caller may already have removed.
        if let Some(mut wake) = self.wake.take() {
            let _ = wake.write_all(b"s");
        }
    }

    /// Closes the listener and every connection, waits up to `budget` for
    /// every accepted connection to settle (emit its result, or close without
    /// a request), then seals: a result that arrives later is dropped and
    /// counted in `results_missing`. Connections still in the backlog are
    /// closed without results. A budget too large to represent waits for
    /// every connection to settle.
    #[must_use]
    pub fn stop(mut self, budget: Duration) -> ProxySummary {
        let deadline = Instant::now().checked_add(budget);
        self.begin_stop();
        let remaining = |deadline: Option<Instant>| {
            deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
        };
        let listener_closed = match self.accept_done.take() {
            Some(done) => match remaining(deadline) {
                Some(left) => done.recv_timeout(left).is_ok(),
                None => done.recv().is_ok(),
            },
            None => false,
        };
        let mut accounting = lock(&self.shared.accounting);
        while accounting.missing() > 0 {
            accounting = match remaining(deadline) {
                Some(left) if left.is_zero() => break,
                Some(left) => {
                    self.shared
                        .settled
                        .wait_timeout(accounting, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => self
                    .shared
                    .settled
                    .wait(accounting)
                    .unwrap_or_else(PoisonError::into_inner),
            };
        }
        accounting.sealed = true;
        ProxySummary {
            accepted: accounting.accepted,
            results_emitted: accounting.emitted,
            results_missing: accounting.missing(),
            without_request: accounting.without_request,
            listener_closed,
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if self.wake.is_some() {
            self.begin_stop();
        }
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &UnixListener, wake: &UnixStream) {
    loop {
        match sys::poll(&[listener.as_fd(), wake.as_fd()], libc::POLLIN, None) {
            Ok(revents) if revents.get(1).is_some_and(|&events| events != 0) => return,
            // J3-agent begin: a listening socket reports POLLHUP only once it
            // was shut down (measured on the reference host: accept then
            // returns EAGAIN for ever and every connect is refused). It will
            // never accept again, so the loop ends instead of spinning, and
            // the proxy's death is visible through `serving()`.
            Ok(revents)
                if revents
                    .first()
                    .is_some_and(|&events| events & (libc::POLLHUP | libc::POLLERR) != 0) =>
            {
                return;
            }
            // J3-agent end
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if backoff(wake) {
                    return;
                }
                continue;
            }
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(_) => {
                // Descriptor exhaustion leaves the connection pending, so
                // poll would report it again at once: back off, but on the
                // wake channel, so stop still ends the loop promptly.
                if backoff(wake) {
                    return;
                }
                continue;
            }
        };
        // macOS hands out accepted sockets with the listener's O_NONBLOCK.
        let _ = stream.set_nonblocking(false);
        let accepted_at = Instant::now();
        let client = Arc::new(stream);
        match shared.admit(&client) {
            Admission::Stopping => return,
            Admission::Overload(id) => {
                refuse_inline(shared, &client, id, accepted_at, Reason::Overload);
            }
            Admission::Admitted(id) => spawn_handler(shared, client, id, accepted_at),
        }
    }
}

/// Waits 10 ms on the wake channel; `true` when stop woke it.
fn backoff(wake: &UnixStream) -> bool {
    matches!(
        sys::poll(&[wake.as_fd()], libc::POLLIN, Some(Duration::from_millis(10))),
        Ok(revents) if revents.first().is_some_and(|&events| events != 0)
    )
}

fn spawn_handler(shared: &Arc<Shared>, client: Arc<UnixStream>, id: u64, accepted_at: Instant) {
    // The socket travels by channel, so a failed spawn leaves it here to be
    // answered, instead of dropping it inside the lost closure.
    let (handoff, receive) = mpsc::sync_channel::<Arc<UnixStream>>(1);
    let handler_shared = Arc::clone(shared);
    let spawned = thread::Builder::new()
        .name("ouro-proxy-conn".to_owned())
        .stack_size(256 * 1024)
        .spawn(move || {
            if let Ok(client) = receive.recv() {
                handle_connection(&handler_shared, &client, id, accepted_at);
            }
        });
    let unhandled = match spawned {
        Ok(_) => handoff.send(client).err().map(|error| error.0),
        Err(_) => Some(client),
    };
    if let Some(client) = unhandled {
        shared.close_connection(id);
        shared.release();
        refuse_inline(shared, &client, id, accepted_at, Reason::ResourceExhausted);
    }
}

/// Refuses a connection without reading from it: the short response goes
/// into an empty socket buffer and never blocks.
fn refuse_inline(
    shared: &Shared,
    client: &UnixStream,
    id: u64,
    accepted_at: Instant,
    reason: Reason,
) {
    shared.emit(denial(id, None, RequestKind::Unknown, reason, accepted_at));
    if client.set_nonblocking(true).is_ok() {
        let _ = (&*client).write_all(&http::error_response(reason));
    }
    let _ = client.shutdown(Shutdown::Both);
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
        discarded_bytes: 0,
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
    /// Whether the client may already have received bytes, so no error
    /// response can follow.
    replied: bool,
}

impl ResultSlot<'_> {
    fn release(&mut self) {
        if self.admitted {
            self.admitted = false;
            self.shared.release();
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

    /// An allowed request's result.
    fn allowed(&self, reason: Reason, connected: Option<SocketAddr>) -> ProxyResult {
        ProxyResult {
            request_id: self.id,
            kind: self.kind,
            destination: self.destination.clone(),
            decision: ProxyDecision::Allow,
            reason,
            connected,
            connect_errno: None,
            bytes_in: 0,
            bytes_out: 0,
            discarded_bytes: 0,
            duration: self.accepted_at.elapsed(),
            end: None,
        }
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

fn respond(client: &UnixStream, reason: Reason, budget: Duration) {
    let _ = client.set_write_timeout(Some(budget.max(Duration::from_millis(1))));
    let _ = (&*client).write_all(&http::error_response(reason));
    let _ = client.shutdown(Shutdown::Both);
}

fn handle_connection(shared: &Shared, client: &Arc<UnixStream>, id: u64, accepted_at: Instant) {
    let mut slot = ResultSlot {
        shared,
        id,
        accepted_at,
        kind: RequestKind::Unknown,
        destination: None,
        admitted: true,
        done: false,
        replied: false,
    };
    // A panic anywhere below (a resolver bug, say) still settles the
    // connection once, answers the client if nothing was sent yet, and
    // closes its sockets.
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        serve(shared, &mut slot, client, accepted_at)
    }));
    let refusal = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(reason)) => Some(reason),
        Err(_) => Some(Reason::InternalError),
    };
    if let Some(reason) = refusal {
        slot.deny(reason);
        if !slot.replied {
            respond(client, reason, shared.budgets.header_deadline);
        }
    }
    drop(slot);
    shared.close_connection(id);
    let _ = client.shutdown(Shutdown::Both);
}

/// Serves one request. `Err` is a denial the caller reports and answers;
/// `Ok` means the result was already emitted (or there was no request).
fn serve(
    shared: &Shared,
    slot: &mut ResultSlot<'_>,
    client: &Arc<UnixStream>,
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
            return Err(if reason == Reason::ClientClosed && shared.is_stopping() {
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
                Err(ResolveError::Overloaded) => return Err(Reason::ResolverOverloaded),
                Err(ResolveError::Failed | ResolveError::Invalid) => {
                    return Err(Reason::ResolveFailed);
                }
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
    connect_and_relay(shared, slot, client, &request, &approved, &head)
}

/// Whether a connect error is this process running out of a resource
/// rather than anything the destination did.
fn local_exhaustion(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
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
            Err(error) if local_exhaustion(&error) => {
                return Err((Reason::ResourceExhausted, error.raw_os_error()));
            }
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
    client: &Arc<UnixStream>,
    request: &http::Request,
    approved: &[IpAddr],
    head: &http::Head,
) -> Result<(), Reason> {
    let budgets = shared.budgets;
    let reply_budget = budgets.header_deadline;
    let deadline = Instant::now() + budgets.connect_deadline;
    let (upstream, connected) = match connect_upstream(approved, request.destination.port, deadline)
    {
        Ok(pair) => pair,
        Err((reason, errno)) => {
            // Allowed by policy; the connection itself was not made.
            let mut result = slot.allowed(reason, None);
            result.connect_errno = errno;
            slot.emit(result);
            slot.replied = true;
            respond(client, reason, reply_budget);
            return Ok(());
        }
    };
    let upstream = Arc::new(upstream);
    if !shared.register(slot.id, Closer::Tcp(Arc::clone(&upstream))) {
        // Stop began while connecting: the connection was made, nothing
        // was relayed.
        let _ = upstream.shutdown(Shutdown::Both);
        let mut result = slot.allowed(Reason::Stopping, Some(connected));
        result.end = Some(EndReason::Stopped);
        slot.emit(result);
        slot.replied = true;
        respond(client, Reason::Stopping, reply_budget);
        return Ok(());
    }
    let _ = upstream.set_nodelay(true);
    let chunk = budgets.relay_chunk();
    // From here the client may receive relayed bytes; an error response can
    // no longer follow.
    slot.replied = true;
    let relayed = match request.framing {
        http::Framing::Tunnel => {
            relay::tunnel(client, &upstream, head.leftover(), chunk, reply_budget)
        }
        framing => relay::http(
            client,
            &upstream,
            &request.forward_head,
            framing,
            head.leftover(),
            chunk,
        ),
    };
    let Ok(outcome) = relayed else {
        // The relay could not start; nothing was written to either side.
        let _ = upstream.shutdown(Shutdown::Both);
        slot.emit(slot.allowed(Reason::ResourceExhausted, Some(connected)));
        respond(client, Reason::ResourceExhausted, reply_budget);
        return Ok(());
    };
    let end = if shared.is_stopping() {
        EndReason::Stopped
    } else {
        outcome.end
    };
    let mut result = slot.allowed(Reason::Relayed, Some(connected));
    result.bytes_in = outcome.bytes_in;
    result.bytes_out = outcome.bytes_out;
    result.discarded_bytes = outcome.discarded;
    result.end = Some(end);
    slot.emit(result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn connect_deadline_is_shared_across_answers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("address").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let approved = [
            "127.0.0.1".parse().expect("ip"),
            "127.0.0.1".parse().expect("ip"),
        ];
        // A deadline already spent: no attempt is made at all.
        let spent = Instant::now();
        let error = connect_upstream(&approved, port, spent).expect_err("no time left");
        assert_eq!(error, (Reason::ConnectTimeout, None));
        assert!(listener.accept().is_err(), "nothing connected");
        // With time left the first answer is used.
        let (stream, target) =
            connect_upstream(&approved, port, Instant::now() + Duration::from_secs(10))
                .expect("connects");
        assert_eq!(target.port(), port);
        drop(stream);
    }

    #[test]
    fn local_exhaustion_is_not_blamed_on_the_destination() {
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(local_exhaustion(&io::Error::from_raw_os_error(errno)));
        }
        assert!(!local_exhaustion(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
    }
}
