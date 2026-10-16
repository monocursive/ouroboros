//! The accept loop and the proxy's shared accounting: admission against
//! the connection budget, the registry stop closes, and the seal that makes
//! every accepted connection settle exactly once.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::conn::handle_connection;
use super::{
    Budgets, FD_HEADROOM, FDS_PER_CONNECTION, MAX_DEADLINE, ProxyConfig, ProxyDecision,
    ProxyResult, ProxySink, ProxySummary, Reason, RequestKind, Resolver, Transport, http, sys,
};
use crate::network::{Destination, Rules};
use crate::sync::lock;

/// A socket of a live connection, shared with its handler, so stop can shut
/// it down without holding a second descriptor.
pub(super) enum Closer {
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

pub(super) struct Shared {
    pub(super) vault: Option<Arc<crate::vault::Vault>>,
    pub(super) rules: Rules,
    pub(super) budgets: Budgets,
    pub(super) resolver: Arc<dyn Resolver + Send + Sync>,
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
    pub(super) fn is_stopping(&self) -> bool {
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
    pub(super) fn register(&self, id: u64, closer: Closer) -> bool {
        let mut registry = lock(&self.registry);
        if registry.stopping {
            return false;
        }
        registry.live.entry(id).or_default().push(closer);
        true
    }

    /// Removes a connection's sockets from the registry and shuts them down.
    pub(super) fn close_connection(&self, id: u64) {
        let closers = lock(&self.registry).live.remove(&id);
        for closer in closers.iter().flatten() {
            closer.shutdown();
        }
    }

    pub(super) fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    pub(super) fn emit(&self, result: ProxyResult) {
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

    pub(super) fn no_request(&self) {
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
    // Whether the accept loop still runs
    serving: Arc<std::sync::atomic::AtomicBool>,
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
    start_with_vault(config, sink, None)
}

/// [`start`], with the attempt's vault when credentials are vaulted: every
/// connection then begins with the sealed bridge's origin preamble, and
/// requests are served with the vault's credentials and TLS lane.
///
/// # Errors
/// As [`start`]; also when process-bound credentials leave no descriptors
/// for pinning the processes that initiate connections.
pub fn start_with_vault(
    config: ProxyConfig,
    sink: Arc<dyn ProxySink>,
    vault: Option<Arc<crate::vault::Vault>>,
) -> io::Result<ProxyHandle> {
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
    if let Some(vault) = &vault {
        let bound = vault.has_process_bindings();
        vault.origins.configure(bound, budgets.max_connections);
        if bound {
            use crate::vault::origin::{FDS_PER_PIN, MAX_PINNED};
            let open = sys::open_descriptor_count()?;
            let (soft, _) = sys::nofile_limits()?;
            // At most `configure`'s limit of processes are pinned at once,
            // each with its descriptors and, until claimed, its connection's
            // socket; a published refusal holds none.
            let needed = budgets.descriptors_needed().saturating_add(
                budgets
                    .max_connections
                    .min(MAX_PINNED)
                    .saturating_mul(FDS_PER_PIN),
            );
            if soft.saturating_sub(open as u64) < needed as u64 {
                return Err(invalid(
                    "the proxy descriptor budget cannot reserve pinned process authority".into(),
                ));
            }
        }
    }
    // Accept only when poll says a connection is pending; a nonblocking
    // listener keeps a vanished connection from blocking the loop.
    listener.set_nonblocking(true)?;
    let (wake, wake_reader) = UnixStream::pair()?;
    let shared = Arc::new(Shared {
        vault,
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
    let serving = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let serving_flag = Arc::clone(&serving);
    thread::Builder::new()
        .name("ukai-proxy-accept".to_owned())
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
    // A proxy that stopped serving is a recorded fact (§10)
    /// Whether the accept loop still runs. It stops on [`ProxyHandle::stop`]
    /// and when its listener is no longer listening (shut down by anything),
    /// after which every new connection to the socket is refused: the proxy
    /// fails closed and nothing reconnects it.
    #[must_use]
    pub fn serving(&self) -> bool {
        self.serving.load(Ordering::SeqCst)
    }

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
        if let Some(vault) = &self.shared.vault {
            vault.origins.stop();
        }
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
                Some(left) => crate::sync::wait_timeout(&self.shared.settled, accounting, left).0,
                None => crate::sync::wait(&self.shared.settled, accounting),
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
        let interests = [
            Some((listener.as_fd(), libc::POLLIN)),
            Some((wake.as_fd(), libc::POLLIN)),
        ];
        match sys::poll(&interests, None) {
            Ok(revents) if revents.get(1).is_some_and(|&events| events != 0) => return,
            // A listening socket reports POLLHUP only once it
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
        sys::poll(
            &[Some((wake.as_fd(), libc::POLLIN))],
            Some(Duration::from_millis(10))
        ),
        Ok(revents) if revents.first().is_some_and(|&events| events != 0)
    )
}

fn spawn_handler(shared: &Arc<Shared>, client: Arc<UnixStream>, id: u64, accepted_at: Instant) {
    // The socket travels by channel, so a failed spawn leaves it here to be
    // answered, instead of dropping it inside the lost closure.
    let (handoff, receive) = mpsc::sync_channel::<Arc<UnixStream>>(1);
    let handler_shared = Arc::clone(shared);
    let spawned = thread::Builder::new()
        .name("ukai-proxy-conn".to_owned())
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

pub(super) fn denial(
    id: u64,
    destination: Option<Destination>,
    kind: RequestKind,
    reason: Reason,
    accepted_at: Instant,
) -> ProxyResult {
    ProxyResult {
        request_id: id,
        origin: None,
        origin_verification: None,
        transport: Transport::Http,
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
        credentials: Vec::new(),
    }
}
