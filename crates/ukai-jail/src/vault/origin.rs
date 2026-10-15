//! Connection-initiating executable authority from the seccomp mediator and
//! the sealed bridge. HTTP headers and child argv never supply process
//! identity.
//!
//! The rendezvous: for every connect to a bridge port, the mediator pins the
//! calling process before it connects ([`Origins::prepare`]) and, once the
//! connect succeeded, publishes what it established under the connection's
//! key, its whole loopback 4-tuple ([`Origins::connected`]): the pinned
//! process, held with the socket of the connection it made, or why there is
//! none. The sealed bridge writes the same key ahead of the stream it relays
//! ([`preamble`]), and the proxy claims the outcome published under exactly
//! that key ([`Origins::receive`]); an authority only while its socket still
//! carries that connection. TCP accept and the preamble can beat the
//! publication, so the proxy waits for it, at most [`RENDEZVOUS`]; because
//! every completed bridge connect whose caller the mediator identified
//! publishes, refusals included, the wait ends as soon as the mediator is
//! done.
//!
//! The bridge and the proxy agree by construction: the supervisor seals the
//! bridge with the vault byte exactly when it starts the proxy with a vault,
//! the bridge then writes a preamble ahead of every relayed stream, and a
//! proxy with a vault reads one at the start of every connection.
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read as _};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant};

use crate::proxy::Reason;

/// How long the proxy waits for a connection's authority from the start of
/// the connection: reading the preamble and waiting for the publication
/// share it.
pub(crate) const RENDEZVOUS: Duration = Duration::from_secs(2);
/// How long a published outcome waits for its connection to claim it.
///
/// No authority depends on it: one is handed only to the connection its
/// socket still carries, however long it waits (see [`Origins::publish`]).
/// It bounds how long an unclaimed outcome, and an authority's descriptors,
/// are kept. It must outlast a live connection's way from its connect to
/// its claim, which [`RENDEZVOUS`] does not bound, since the proxy's wait
/// starts only once it accepted: the bridge's accept, the bridge's own
/// connect to the proxy (mediated, so bounded by the mediator's connect
/// deadline) and the proxy's accept. An outcome that outlives it leaves its
/// connection unverified, never another connection authorized, so it is
/// kept at several times that path rather than close to it.
#[cfg(target_os = "linux")]
const RETENTION: Duration = Duration::from_secs(10);
/// The most processes pinned at once.
pub(crate) const MAX_PINNED: usize = 128;
/// Descriptors per unit of the pin limit: a pinned process's pidfd and
/// executable, and one held connection socket ([`Held`]), whose budget has
/// the same limit.
pub(crate) const FDS_PER_PIN: usize = 3;
/// Published outcomes waiting for their connection. Each authority holds a
/// pin and a socket, so their budgets already bound those; this bounds
/// refusals too, which hold neither.
#[cfg(target_os = "linux")]
const MAX_ENTRIES: usize = MAX_PINNED;
const MAGIC: &[u8; 8] = b"UKAIPID2";
/// [`MAGIC`], the client's address as IPv6 (an IPv4 one mapped), the
/// client's port, then the bridge port.
const PREAMBLE_LEN: usize = 8 + 16 + 2 + 2;

/// A bridged connection: the client's address and port and the bridge port
/// it reached, which with the bridge's fixed address is its whole TCP
/// 4-tuple. Two live connections never share one, so neither can claim the
/// other's authority.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Key {
    client: SocketAddr,
    bridge_port: u16,
}
impl Key {
    fn new(client: SocketAddr, bridge_port: u16) -> Self {
        // A v4-mapped IPv6 client is the connection the bridge sees as IPv4.
        Self {
            client: SocketAddr::new(client.ip().to_canonical(), client.port()),
            bridge_port,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    ctime: (i64, i64),
}
fn identity(file: &File) -> io::Result<Identity> {
    let m = file.metadata()?;
    Ok(Identity {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}
pub(super) struct Executable {
    /// Held open, so the identity it was pinned with cannot be handed to
    /// another file, and re-read on every check.
    file: File,
    identity: Identity,
}
impl Executable {
    pub(super) fn pin(path: &str) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "vault executable cannot be pinned")?;
        let m = file
            .metadata()
            .map_err(|_| "vault executable cannot be inspected")?;
        if !m.is_file() || m.mode() & 0o111 == 0 || m.mode() & 0o022 != 0 {
            return Err("vault executable needs a non-writable regular executable".into());
        }
        let identity = identity(&file).map_err(|_| "vault executable cannot be inspected")?;
        Ok(Self { file, identity })
    }
}
#[derive(Clone)]
pub(crate) struct Process(Arc<Pinned>);
struct Pinned {
    pid: i32,
    /// Held so the executable's inode cannot be freed and its identity
    /// reused while this process is compared against it.
    _exe: File,
    pidfd: OwnedFd,
    identity: Identity,
    _reservation: Option<Reservation>,
}
/// One unit of a budget (pinned processes, held sockets), returned when
/// dropped.
struct Reservation(Arc<AtomicUsize>);
impl Reservation {
    /// One unit of `taken`, when fewer than `limit` are.
    #[cfg(target_os = "linux")]
    fn take(taken: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        taken
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < limit).then_some(count + 1)
            })
            .ok()?;
        Some(Self(Arc::clone(taken)))
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Process {
    /// Pins process `pid`, which must have started at `start`: its pidfd,
    /// then its executable, read through the kernel's link with the pidfd
    /// held, the start time checked before and after.
    #[cfg(target_os = "linux")]
    fn capture(pid: i32, start: u64, reservation: Option<Reservation>) -> Option<Self> {
        use crate::platform::linux::identity::{pidfd_open, start_time_ticks};
        let pidfd = pidfd_open(pid).ok()?;
        let same =
            |pidfd: &OwnedFd| alive(pidfd) && start_time_ticks(pid).is_ok_and(|t| t == start);
        if !same(&pidfd) {
            return None;
        }
        let exe = File::open(format!("/proc/{pid}/exe")).ok()?;
        let identity = identity(&exe).ok()?;
        if !same(&pidfd) {
            return None;
        }
        Some(Self(Arc::new(Pinned {
            pid,
            _exe: exe,
            pidfd,
            identity,
            _reservation: reservation,
        })))
    }
    fn alive(&self) -> bool {
        alive(&self.0.pidfd)
    }
    fn current(&self) -> Option<Identity> {
        if !self.alive() {
            return None;
        }
        let file = File::open(format!("/proc/{}/exe", self.0.pid)).ok()?;
        let seen = identity(&file).ok()?;
        (seen == self.0.identity && self.alive()).then_some(seen)
    }
    pub(super) fn permits(&self, allowed: &[Executable]) -> bool {
        let Some(current) = self.current() else {
            return false;
        };
        allowed
            .iter()
            .any(|e| e.identity == current && identity(&e.file).is_ok_and(|i| i == e.identity))
            && self.alive()
    }
}
/// A pidfd polls readable once its process has exited.
fn alive(pidfd: &OwnedFd) -> bool {
    crate::proxy::sys::ready(pidfd.as_fd(), libc::POLLIN).is_ok_and(|exited| !exited)
}

/// What the proxy established about the process that initiated a
/// connection.
#[derive(Clone)]
pub(crate) enum Initiator {
    /// The kernel-pinned process.
    Pinned(Process),
    /// No process authority: the reason a process-bound credential is
    /// refused.
    Unverified(Reason),
}
impl Default for Initiator {
    /// A connection that carries no process authority.
    fn default() -> Self {
        Initiator::Unverified(Reason::CredentialProcessUnverified)
    }
}
impl Initiator {
    /// Whether this initiator may use a credential bound to `allowed`.
    pub(super) fn check(&self, allowed: &[Executable]) -> Result<(), Reason> {
        match self {
            Initiator::Pinned(process) if process.permits(allowed) => Ok(()),
            Initiator::Pinned(_) => Err(Reason::CredentialProcessDenied),
            Initiator::Unverified(reason) => Err(*reason),
        }
    }
}

/// What the mediator published about one bridged connection.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only the Linux mediator publishes")
)]
enum Outcome {
    /// The pinned process, held with its own duplicate of the socket of the
    /// connection it made: the authority is that connection's.
    Authority(Process, Held),
    Refused(Reason),
}
impl From<Outcome> for Initiator {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            // Claimed: the socket has served its purpose and is let go.
            Outcome::Authority(process, _) => Initiator::Pinned(process),
            Outcome::Refused(reason) => Initiator::Unverified(reason),
        }
    }
}

/// A connection's socket, held for its authority and closed by the closer
/// thread, never where it is let go.
///
/// Closing a socket's last descriptor waits, when its process set it to
/// linger, until the data it queued is delivered, which that process can
/// put off for as long as it likes. The rendezvous lets go of sockets on
/// mediator workers, proxy handlers and stop, under the table lock, so the
/// closer takes that wait instead. A socket counts against the socket
/// budget until it is closed: a process that keeps the closer waiting runs
/// that budget out, and authorities are then refused as
/// `resource_exhausted` rather than descriptors running out.
struct Held {
    /// Taken only when dropped.
    closing: Option<Closing>,
    closer: mpsc::Sender<Closing>,
}
/// A held socket, and the unit of the socket budget it releases once it is
/// closed: fields drop in order.
struct Closing {
    socket: OwnedFd,
    _reservation: Reservation,
}
impl Held {
    fn socket(&self) -> Option<BorrowedFd<'_>> {
        self.closing.as_ref().map(|closing| closing.socket.as_fd())
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        if let Some(closing) = self.closing.take() {
            // The closer runs as long as any sender lives, this one too.
            let _ = self.closer.send(closing);
        }
    }
}

/// What the mediator established before connecting: the pinned process, or
/// why there is none. Published once the connect succeeded.
#[cfg(target_os = "linux")]
pub(crate) struct Prepared(Result<Process, Reason>);

#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only the Linux mediator publishes")
)]
struct Entry {
    at: Instant,
    outcome: Outcome,
}
impl Entry {
    /// Whether this outcome may still go to the connection `key` names. A
    /// refusal grants nothing, so it may; an authority only while its socket
    /// still carries that connection.
    fn current(&self, key: Key) -> bool {
        match &self.outcome {
            Outcome::Authority(_, held) => held.socket().is_some_and(|socket| carries(socket, key)),
            Outcome::Refused(_) => true,
        }
    }
}

#[derive(Default)]
struct Table {
    /// Whether any credential is process-bound; without one nothing is
    /// pinned or waited for.
    enabled: bool,
    /// Terminal: set once by [`Origins::stop`].
    stopped: bool,
    /// Processes that may be pinned at once.
    limit: usize,
    entries: HashMap<Key, Entry>,
    /// Receivers waiting for a publication right now.
    #[cfg(test)]
    waiting: usize,
}

pub(crate) struct Origins {
    table: Mutex<Table>,
    /// Notified under the table lock on every publication and on stop.
    published: Condvar,
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "only the Linux mediator pins")
    )]
    pins: Arc<AtomicUsize>,
    /// Held sockets, in the table or waiting for the closer; at most the
    /// pin limit.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "only the Linux mediator publishes")
    )]
    sockets: Arc<AtomicUsize>,
    /// The closer thread's queue, opened with the first held socket.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "only the Linux mediator publishes")
    )]
    closer: Mutex<Option<mpsc::Sender<Closing>>>,
    rendezvous: Duration,
}
impl Default for Origins {
    fn default() -> Self {
        Self::with_rendezvous(RENDEZVOUS)
    }
}
impl Origins {
    fn with_rendezvous(rendezvous: Duration) -> Self {
        Self {
            table: Mutex::new(Table::default()),
            published: Condvar::new(),
            pins: Arc::new(AtomicUsize::new(0)),
            sockets: Arc::new(AtomicUsize::new(0)),
            closer: Mutex::new(None),
            rendezvous,
        }
    }
    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Fixes, as the proxy starts, whether connections are process-bound and
    /// how many processes may be pinned at once. A stopped rendezvous stays
    /// stopped.
    pub(crate) fn configure(&self, enabled: bool, limit: usize) {
        let mut table = self.table();
        table.enabled = enabled;
        table.limit = limit.min(MAX_PINNED);
    }
    /// Ends the rendezvous for good: wakes every waiter, drops every
    /// outcome, and refuses later ones.
    pub(crate) fn stop(&self) {
        // The predicate and its wakeup share the table lock: shutdown cannot
        // race a waiter into sleeping for the whole rendezvous.
        let mut table = self.table();
        table.stopped = true;
        table.entries.clear();
        self.published.notify_all();
    }
    /// Called by the mediator before it connects a socket to `destination`:
    /// pins the calling process when the connect may reach the bridge.
    /// `None` when nothing will be published: no credential is
    /// process-bound, the rendezvous stopped, or the port is no bridge port.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare(
        &self,
        pid: i32,
        start: u64,
        destination: SocketAddr,
    ) -> Option<Prepared> {
        if !bridge_port(destination.port()) {
            return None;
        }
        let limit = {
            let mut table = self.table();
            if !table.enabled || table.stopped {
                return None;
            }
            prune(&mut table.entries);
            table.limit
        };
        let outcome = match Reservation::take(&self.pins, limit) {
            // Published all the same, so the proxy learns at once that the
            // pin budget, not the process, is why there is no authority.
            None => Err(Reason::ResourceExhausted),
            Some(reservation) => Process::capture(pid, start, Some(reservation))
                .ok_or(Reason::CredentialProcessUnverified),
        };
        Some(Prepared(outcome))
    }
    /// Called by the mediator once its connect on `socket` succeeded:
    /// publishes the prepared outcome when the peer is the bridge.
    #[cfg(target_os = "linux")]
    pub(crate) fn connected(&self, prepared: Prepared, socket: BorrowedFd<'_>) {
        if let Some(key) = bridge_key(socket) {
            self.publish(key, self.bind(prepared, socket));
        }
    }
    /// The outcome published for the connection made on `socket`: an
    /// authority holds its own duplicate of that socket, or is refused, as
    /// one that could not be told from a later connection's on the same
    /// address.
    #[cfg(target_os = "linux")]
    fn bind(&self, prepared: Prepared, socket: BorrowedFd<'_>) -> Outcome {
        match prepared.0 {
            Ok(process) => self
                .hold(socket)
                .map_or(Outcome::Refused(Reason::ResourceExhausted), |held| {
                    Outcome::Authority(process, held)
                }),
            Err(reason) => Outcome::Refused(reason),
        }
    }
    #[cfg(target_os = "linux")]
    fn hold(&self, socket: BorrowedFd<'_>) -> Option<Held> {
        let reservation = Reservation::take(&self.sockets, self.table().limit)?;
        let closer = self.closer()?;
        let socket = socket.try_clone_to_owned().ok()?;
        Some(Held {
            closing: Some(Closing {
                socket,
                _reservation: reservation,
            }),
            closer,
        })
    }
    /// The closer's queue, its thread started the first time.
    #[cfg(target_os = "linux")]
    fn closer(&self) -> Option<mpsc::Sender<Closing>> {
        let mut closer = self.closer.lock().unwrap_or_else(PoisonError::into_inner);
        if closer.is_none() {
            let (tx, rx) = mpsc::channel::<Closing>();
            std::thread::Builder::new()
                .name("ukai-origin-closer".to_owned())
                // Ends once every sender is gone: this table's and each
                // held socket's.
                .spawn(move || rx.into_iter().for_each(drop))
                .ok()?;
            *closer = Some(tx);
        }
        closer.clone()
    }
    #[cfg(target_os = "linux")]
    fn publish(&self, key: Key, outcome: Outcome) {
        let mut table = self.table();
        if table.stopped {
            return;
        }
        prune(&mut table.entries);
        if table.entries.len() >= MAX_ENTRIES && !table.entries.contains_key(&key) {
            // The prune dropped every authority whose connection is gone,
            // so what is left are refusals and connections still on their
            // way to the proxy. The oldest goes: at worst its connection
            // waits out the rendezvous and goes unverified.
            let oldest = table
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.at)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                table.entries.remove(&oldest);
            }
        }
        // Why an authority reaches only its own connection. A key names one
        // connection only while that connection lasts: once it is gone,
        // another can take the same 4-tuple (a contained process picks its
        // source port, and Linux reuses a loopback TIME_WAIT 4-tuple), and
        // the one that is gone may never have claimed its outcome: the
        // bridge turns a client away at capacity, or when the proxy is
        // unreachable, after its connect published and before any preamble.
        // Nor are publication and claim ordered: one mediator worker
        // publishes once its connect returned, while the bridge accepts the
        // connection, connects to the proxy (mediated on another worker) and
        // the proxy claims, so a connection's claim can come before its own
        // publication and find whatever is under its key.
        //
        // So an outcome already under this key belongs to an earlier
        // connection and is replaced, and an authority holds its
        // connection's socket and is handed out only while that socket
        // still carries the key's connection ([`carries`]). Two sockets are
        // never connected on one 4-tuple at once (the kernel refuses such a
        // connect); the duplicate held here keeps the socket from being
        // freed whatever its process closes; and a socket that is not freed
        // lets go of its 4-tuple only once both its directions are shut
        // down, it is reset or timed out, or it is disconnected, each of
        // which polls as a hang-up from then on. So by the time another
        // connection on the same 4-tuple exists to claim, this authority
        // shows its own is gone, and the claim drops it and waits for its
        // own. A client the bridge turned away sees the bridge's end of
        // stream at once, so its authority goes at the next prune.
        //
        // What this cannot tell apart is the same socket disconnected and
        // connected again by a process that holds it, inherited or passed:
        // whoever holds a connection's socket holds what it may do.
        table.entries.insert(
            key,
            Entry {
                at: Instant::now(),
                outcome,
            },
        );
        self.published.notify_all();
    }
    /// Reads the bridge's preamble at the start of a proxy connection and
    /// claims the outcome published for it, waiting at most the rendezvous.
    /// `Ok(None)`: the connection closed before its first byte, so there
    /// was no request.
    ///
    /// # Errors
    /// `stopping` once the rendezvous stopped; `client_closed` for a
    /// preamble cut short; `credential_process_unverified` for one that is
    /// late or invalid; `credential_process_denied` for a connection not
    /// made through the mediator.
    pub(crate) fn receive(&self, socket: &UnixStream) -> Result<Option<Initiator>, Reason> {
        if self.table().stopped {
            return Err(Reason::Stopping);
        }
        mediated(socket)?;
        let deadline = Instant::now() + self.rendezvous;
        let Some(key) = read_preamble(socket, deadline)? else {
            return Ok(None);
        };
        self.claim(key, deadline).map(Some)
    }
    /// Takes the outcome published under `key`, waiting for it until
    /// `deadline`.
    fn claim(&self, key: Key, deadline: Instant) -> Result<Initiator, Reason> {
        let mut table = self.table();
        loop {
            if table.stopped {
                return Err(Reason::Stopping);
            }
            if !table.enabled {
                return Ok(Initiator::default());
            }
            // Claimed before the deadline is checked: an outcome published
            // just as the wait timed out still counts. An authority whose
            // connection is gone is dropped, never handed out: this
            // connection's own outcome is still to come.
            if let Some(entry) = table.entries.remove(&key)
                && entry.current(key)
            {
                return Ok(entry.outcome.into());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(Initiator::default());
            }
            #[cfg(test)]
            {
                table.waiting += 1;
            }
            table = self
                .published
                .wait_timeout(table, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            #[cfg(test)]
            {
                table.waiting -= 1;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn bridge_port(port: u16) -> bool {
    use crate::platform::linux::bridge::{HTTP_PORT, SOCKS_PORT};
    port == HTTP_PORT || port == SOCKS_PORT
}

/// The key of a connection the mediator made on `socket`, when its peer is
/// the bridge.
#[cfg(target_os = "linux")]
fn bridge_key(socket: BorrowedFd<'_>) -> Option<Key> {
    connection_key(socket).filter(|key| bridge_port(key.bridge_port))
}

/// The key of the connection on `socket` now, when its peer is on the
/// bridge's loopback address, whatever the port.
#[cfg(target_os = "linux")]
fn connection_key(socket: BorrowedFd<'_>) -> Option<Key> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: `from_raw_fd` needs an open descriptor, which the borrow
    // guarantees while the stream lives, and `ManuallyDrop` keeps the stream
    // from closing a descriptor it does not own. Only its address queries
    // are used, which any socket answers (one that is not an internet socket
    // fails them).
    let stream = std::mem::ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(socket.as_raw_fd()) });
    let (local, peer) = (stream.local_addr().ok()?, stream.peer_addr().ok()?);
    let loopback = IpAddr::V4(crate::platform::linux::bridge::LOOPBACK);
    (peer.ip().to_canonical() == loopback).then(|| Key::new(local, peer.port()))
}

/// Whether `socket` still carries the connection `key` names: connected on
/// that 4-tuple, and polling neither an error, a hang-up nor its peer's end
/// of stream. A live bridged connection shows none of these before its
/// claim: the bridge ends a relayed client's stream only once the proxy
/// ended its own or the relay failed, and the proxy claims before it
/// answers anything. Only a client that shuts down its own reading or both
/// directions first loses its authority this way.
#[cfg(target_os = "linux")]
fn carries(socket: BorrowedFd<'_>, key: Key) -> bool {
    crate::proxy::sys::ready(socket, libc::POLLRDHUP).is_ok_and(|ended| !ended)
        && connection_key(socket) == Some(key)
}
/// Off Linux nothing is published, so no socket carries an authority.
#[cfg(not(target_os = "linux"))]
fn carries(_: BorrowedFd<'_>, _: Key) -> bool {
    false
}

/// Drops outcomes no connection claimed within [`RETENTION`] and
/// authorities whose connection is gone, and releases the pin and socket of
/// a process that has exited: its connection gets the denial
/// [`Process::permits`] would give, without descriptors held for it.
#[cfg(target_os = "linux")]
fn prune(entries: &mut HashMap<Key, Entry>) {
    entries.retain(|key, entry| entry.at.elapsed() < RETENTION && entry.current(*key));
    for entry in entries.values_mut() {
        if matches!(&entry.outcome, Outcome::Authority(process, _) if !process.alive()) {
            entry.outcome = Outcome::Refused(Reason::CredentialProcessDenied);
        }
    }
}

/// The mediator performs connect on the sealed bridge's duplicated
/// descriptor, and Linux stamps the connecting actor's credentials, not the
/// socket creator's: a proxy connection made through mediation carries this
/// process's pid. A child's direct connect to the proxy node is refused by
/// the mediator itself (`restrict_authorized_connector`).
#[cfg(target_os = "linux")]
fn mediated(socket: &UnixStream) -> Result<(), Reason> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| Reason::InternalError)?;
    // SAFETY: `cred` is a writable `ucred` of `len` bytes that outlives the
    // call, and the descriptor is borrowed from `socket`, open for the call.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 || u32::try_from(cred.pid).ok() != Some(std::process::id()) {
        return Err(Reason::CredentialProcessDenied);
    }
    Ok(())
}
/// Off Linux there is no mediator and nothing is ever published, so a
/// preamble can only lead to no authority.
#[cfg(not(target_os = "linux"))]
fn mediated(_: &UnixStream) -> Result<(), Reason> {
    Ok(())
}

/// Reads the preamble before `deadline`. `Ok(None)`: the connection closed
/// before its first byte.
fn read_preamble(socket: &UnixStream, deadline: Instant) -> Result<Option<Key>, Reason> {
    let mut bytes = [0u8; PREAMBLE_LEN];
    let mut read = 0;
    while read < bytes.len() {
        // At least a millisecond: std refuses a zero timeout, and bytes the
        // bridge already sent are still taken once the deadline passed.
        let left = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(left))
            .map_err(|_| Reason::InternalError)?;
        match (&*socket).read(&mut bytes[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err(Reason::ClientClosed),
            Ok(n) => read += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // The bridge writes its preamble as it accepts: one that never
            // comes leaves the initiator unknown.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(Reason::CredentialProcessUnverified);
            }
            Err(_) => return Err(Reason::ClientClosed),
        }
    }
    socket
        .set_read_timeout(None)
        .map_err(|_| Reason::InternalError)?;
    decode(&bytes)
        .map(Some)
        .ok_or(Reason::CredentialProcessUnverified)
}

fn encode(key: Key) -> [u8; PREAMBLE_LEN] {
    let address = match key.client.ip() {
        IpAddr::V4(address) => address.to_ipv6_mapped(),
        IpAddr::V6(address) => address,
    };
    let mut bytes = [0u8; PREAMBLE_LEN];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&address.octets());
    bytes[24..26].copy_from_slice(&key.client.port().to_be_bytes());
    bytes[26..].copy_from_slice(&key.bridge_port.to_be_bytes());
    bytes
}
fn decode(bytes: &[u8; PREAMBLE_LEN]) -> Option<Key> {
    if bytes[..8] != MAGIC[..] {
        return None;
    }
    let mut address = [0u8; 16];
    address.copy_from_slice(&bytes[8..24]);
    let port = u16::from_be_bytes([bytes[24], bytes[25]]);
    let bridge_port = u16::from_be_bytes([bytes[26], bytes[27]]);
    Some(Key::new(
        SocketAddr::new(Ipv6Addr::from(address).into(), port),
        bridge_port,
    ))
}
/// The preamble the sealed bridge writes ahead of a client it relays: the
/// key the mediator published that connection's outcome under.
pub(crate) fn preamble(client: &TcpStream) -> io::Result<[u8; PREAMBLE_LEN]> {
    Ok(encode(Key::new(
        client.peer_addr()?,
        client.local_addr()?.port(),
    )))
}
/// The preamble the bridge writes for a `client` it accepted on
/// `bridge_port`, for tests on either side of it.
#[cfg(test)]
pub(crate) fn preamble_for(client: SocketAddr, bridge_port: u16) -> [u8; PREAMBLE_LEN] {
    encode(Key::new(client, bridge_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn the_preamble_names_the_bridged_connection_and_round_trips() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let key = Key::new(
            client.local_addr().unwrap(),
            listener.local_addr().unwrap().port(),
        );
        let bytes = preamble(&accepted).unwrap();
        assert_eq!(bytes, encode(key));
        assert_eq!(decode(&bytes), Some(key));
        let mut forged = bytes;
        forged[0] ^= 1;
        assert_eq!(decode(&forged), None);
        // The v4-mapped spelling of a client is the same connection.
        let v4 = SocketAddr::from(([127, 0, 0, 1], 40000));
        let v6 = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 40000));
        assert_eq!(Key::new(v6, 3128), Key::new(v4, 3128));
        assert_eq!(
            decode(&encode(Key::new(v4, 3128))),
            Some(Key::new(v4, 3128))
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// A bridge-port destination, as the mediator would pass it.
    const BRIDGE: SocketAddr = SocketAddr::new(
        IpAddr::V4(crate::platform::linux::bridge::LOOPBACK),
        crate::platform::linux::bridge::HTTP_PORT,
    );

    /// A connection from `port` on the IPv4 loopback to `bridge_port`.
    fn loopback(port: u16, bridge_port: u16) -> Key {
        Key::new(SocketAddr::from(([127, 0, 0, 1], port)), bridge_port)
    }

    fn configured(enabled: bool, rendezvous: Duration) -> Arc<Origins> {
        let origins = Arc::new(Origins::with_rendezvous(rendezvous));
        origins.configure(enabled, 2);
        origins
    }

    /// The proxy end of a connection whose bridge already sent `key`.
    fn bridged(key: Key) -> (UnixStream, UnixStream) {
        let (mut bridge, proxy) = UnixStream::pair().unwrap();
        bridge.write_all(&encode(key)).unwrap();
        (bridge, proxy)
    }

    fn this_process() -> (i32, u64) {
        let pid = i32::try_from(std::process::id()).unwrap();
        let start = crate::platform::linux::identity::start_time_ticks(pid).unwrap();
        (pid, start)
    }
    fn me() -> i32 {
        this_process().0
    }

    /// Process `pid`, which started at `start`, pinned as the mediator would
    /// pin its connect.
    fn pin(origins: &Origins, pid: i32, start: u64) -> Process {
        match origins.prepare(pid, start, BRIDGE).unwrap().0 {
            Ok(process) => process,
            Err(reason) => panic!("not pinned: {reason:?}"),
        }
    }
    /// This test process, pinned as the mediator would pin a connect.
    fn pinned(origins: &Origins) -> Process {
        let (pid, start) = this_process();
        pin(origins, pid, start)
    }
    /// The outcome the mediator publishes once `process` connected `client`.
    fn authority(origins: &Origins, process: Process, client: &TcpStream) -> Outcome {
        origins.bind(Prepared(Ok(process)), client.as_fd())
    }

    /// A loopback TCP connection to a stand-in for the bridge: the client
    /// end, the end the bridge accepted, and the connection's key.
    struct Connection {
        client: TcpStream,
        accepted: TcpStream,
        key: Key,
    }
    fn connected_to(listener: &TcpListener, client: TcpStream) -> Connection {
        let (accepted, _) = listener.accept().unwrap();
        let key = Key::new(
            client.local_addr().unwrap(),
            listener.local_addr().unwrap().port(),
        );
        Connection {
            client,
            accepted,
            key,
        }
    }
    fn connection() -> Connection {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        connected_to(&listener, client)
    }

    /// A connection to `listener` from exactly `local`, as a contained
    /// process that picks its own source port makes it.
    fn connect_from(local: SocketAddr, listener: &TcpListener) -> io::Result<TcpStream> {
        use std::os::fd::FromRawFd as _;
        let sockaddr = |address: SocketAddr| {
            let SocketAddr::V4(address) = address else {
                panic!("an IPv4 loopback address");
            };
            libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap(),
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*address.ip()).to_be(),
                },
                sin_zero: [0; 8],
            }
        };
        let (from, to) = (sockaddr(local), sockaddr(listener.local_addr()?));
        let len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap();
        // SAFETY: socket takes three scalars and dereferences nothing.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created by socket and nothing else owns it.
        let stream = unsafe { TcpStream::from_raw_fd(fd) };
        // SAFETY: `from` is a `sockaddr_in` of `len` bytes that outlives the
        // call, and the descriptor is owned by `stream`, open for the call.
        if unsafe { libc::bind(stream.as_raw_fd(), (&raw const from).cast(), len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as for bind, with `to`.
        if unsafe { libc::connect(stream.as_raw_fd(), (&raw const to).cast(), len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stream)
    }

    /// Waits until `socket` polls one of `events` (a hang-up or an error
    /// always counts).
    fn until(socket: &TcpStream, events: libc::c_short) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !crate::proxy::sys::ready(socket.as_fd(), events).unwrap() {
            assert!(Instant::now() < deadline, "the socket never ended");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A process that is not this one, killed when dropped.
    struct Other(std::process::Child);
    impl Other {
        fn spawn() -> Self {
            Self(
                std::process::Command::new("sleep")
                    .arg("60")
                    .spawn()
                    .unwrap(),
            )
        }
        fn pid(&self) -> i32 {
            i32::try_from(self.0.id()).unwrap()
        }
        fn start(&self) -> u64 {
            crate::platform::linux::identity::start_time_ticks(self.pid()).unwrap()
        }
    }
    impl Drop for Other {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn refused() -> Outcome {
        Outcome::Refused(Reason::ResourceExhausted)
    }

    /// Makes closing the last descriptor of `client`'s socket wait, up to
    /// `seconds`: it lingers, with more queued than its peer, which reads
    /// nothing, will take.
    fn lingering(client: &mut TcpStream, seconds: libc::c_int) {
        use std::io::ErrorKind;
        let value = libc::linger {
            l_onoff: 1,
            l_linger: seconds,
        };
        let len = libc::socklen_t::try_from(std::mem::size_of::<libc::linger>()).unwrap();
        // SAFETY: `value` is a `linger` of `len` bytes that outlives the call,
        // and the descriptor is borrowed from `client`, open for the call.
        let rc = unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&raw const value).cast(),
                len,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        client.set_nonblocking(true).unwrap();
        let chunk = [0u8; 1 << 16];
        loop {
            match client.write(&chunk) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        /// Pinned, with the pinned process's pid.
        Pinned(i32),
        Unverified(Reason),
        NoRequest,
    }
    fn seen(received: Result<Option<Initiator>, Reason>) -> Result<Seen, Reason> {
        received.map(|initiator| match initiator {
            None => Seen::NoRequest,
            Some(Initiator::Pinned(process)) => Seen::Pinned(process.0.pid),
            Some(Initiator::Unverified(reason)) => Seen::Unverified(reason),
        })
    }

    /// Receives on another thread and returns once it is waiting for a
    /// publication, so a probe that it is "still waiting" is never vacuous.
    fn receiving(
        origins: &Arc<Origins>,
        proxy: UnixStream,
    ) -> (
        mpsc::Receiver<Result<Seen, Reason>>,
        std::thread::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel();
        let receiver = Arc::clone(origins);
        let thread = std::thread::spawn(move || {
            tx.send(seen(receiver.receive(&proxy))).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while origins.table().waiting == 0 {
            if let Ok(early) = rx.try_recv() {
                panic!("the receiver never waited: it received {early:?}");
            }
            assert!(Instant::now() < deadline, "the receiver never waited");
            std::thread::yield_now();
        }
        (rx, thread)
    }

    #[test]
    fn a_connection_closed_before_or_inside_its_preamble_is_told_apart() {
        // (Linux only: macOS refuses socket options on a socket whose peer
        // already closed.)
        let origins = Origins::default();
        origins.configure(false, 2);
        let (bridge, proxy) = UnixStream::pair().unwrap();
        drop(bridge);
        assert!(
            matches!(origins.receive(&proxy), Ok(None)),
            "no byte: no request"
        );
        let (mut bridge, proxy) = UnixStream::pair().unwrap();
        bridge.write_all(&encode(loopback(1, 2))[..5]).unwrap();
        drop(bridge);
        assert!(matches!(origins.receive(&proxy), Err(Reason::ClientClosed)));
        let (mut bridge, proxy) = UnixStream::pair().unwrap();
        bridge.write_all(&[0; PREAMBLE_LEN]).unwrap();
        assert!(matches!(
            origins.receive(&proxy),
            Err(Reason::CredentialProcessUnverified)
        ));
    }
    #[test]
    fn a_bridge_preamble_before_connect_publication_waits_for_pinned_authority() {
        let origins = configured(true, RENDEZVOUS);
        let connection = connection();
        let (_bridge, proxy) = bridged(connection.key);
        let (rx, thread) = receiving(&origins, proxy);
        let outcome = authority(&origins, pinned(&origins), &connection.client);
        origins.publish(connection.key, outcome);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(Seen::Pinned(me()))
        );
        thread.join().unwrap();
        assert!(origins.table().entries.is_empty());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_outcome_published_as_the_rendezvous_expires_is_still_claimed() {
        // A zero rendezvous: the deadline has passed by the time the table
        // is consulted, yet the published authority is there.
        let origins = configured(true, Duration::ZERO);
        let connection = connection();
        let key = connection.key;
        origins.publish(
            key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        let (_bridge, proxy) = bridged(key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned(me())));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_published_origin_is_single_use_and_a_missing_origin_times_out() {
        let rendezvous = Duration::from_millis(50);
        let origins = configured(true, rendezvous);
        let connection = connection();
        let key = connection.key;
        origins.publish(
            key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        let (_bridge, proxy) = bridged(key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned(me())));
        let (_replay_bridge, replay_proxy) = bridged(key);
        let began = Instant::now();
        assert_eq!(
            seen(origins.receive(&replay_proxy)),
            Ok(Seen::Unverified(Reason::CredentialProcessUnverified))
        );
        assert!(began.elapsed() >= rendezvous);
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn another_connection_key_never_authorizes_a_waiter_and_stop_wakes_it() {
        let origins = configured(true, RENDEZVOUS);
        let (_bridge, proxy) = bridged(loopback(40004, 3128));
        let (rx, thread) = receiving(&origins, proxy);
        let connection = connection();
        origins.publish(
            connection.key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        origins.stop();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(Reason::Stopping)
        );
        thread.join().unwrap();
        assert!(origins.table().entries.is_empty());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
        let (pid, start) = this_process();
        assert!(origins.prepare(pid, start, BRIDGE).is_none());
    }

    #[test]
    fn a_later_connection_replaces_an_unclaimed_outcome_and_stop_is_terminal() {
        let origins = configured(true, RENDEZVOUS);
        let connection = connection();
        let key = connection.key;
        // An earlier connection on the same 4-tuple closed unclaimed; its
        // outcome is not the new connection's.
        origins.publish(key, refused());
        origins.publish(
            key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        let (_bridge, proxy) = bridged(key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned(me())));
        let pending = authority(&origins, pinned(&origins), &connection.client);
        origins.stop();
        origins.publish(key, pending);
        // Stop is terminal: configuring again does not reopen it.
        origins.configure(true, 2);
        let (_late_bridge, late_proxy) = bridged(key);
        assert_eq!(seen(origins.receive(&late_proxy)), Err(Reason::Stopping));
        let (pid, start) = this_process();
        assert!(origins.prepare(pid, start, BRIDGE).is_none());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_authority_is_never_claimed_from_another_loopback_address() {
        let origins = configured(true, Duration::from_millis(50));
        let connection = connection();
        // Same client port, same bridge port, another source address: a
        // different connection, which may be live at the same time.
        let elsewhere = Key::new(
            SocketAddr::from(([127, 0, 0, 2], connection.key.client.port())),
            connection.key.bridge_port,
        );
        origins.publish(
            connection.key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        let (_bridge, proxy) = bridged(elsewhere);
        assert_eq!(
            seen(origins.receive(&proxy)),
            Ok(Seen::Unverified(Reason::CredentialProcessUnverified))
        );
        let (_bridge, proxy) = bridged(connection.key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned(me())));
    }

    #[test]
    fn a_profile_without_process_binding_never_waits_for_origin_authority() {
        let origins = configured(false, RENDEZVOUS);
        let (_bridge, proxy) = bridged(loopback(40007, 3128));
        let began = Instant::now();
        assert_eq!(
            seen(origins.receive(&proxy)),
            Ok(Seen::Unverified(Reason::CredentialProcessUnverified))
        );
        assert!(began.elapsed() < RENDEZVOUS);
        let (pid, start) = this_process();
        assert!(origins.prepare(pid, start, BRIDGE).is_none());
    }

    #[test]
    fn a_connect_refused_at_the_pin_budget_is_published_and_named() {
        let origins = configured(true, RENDEZVOUS);
        let held = [pinned(&origins), pinned(&origins)];
        let (pid, start) = this_process();
        let prepared = origins.prepare(pid, start, BRIDGE).unwrap();
        assert!(matches!(prepared.0, Err(Reason::ResourceExhausted)));
        let connection = connection();
        let (_bridge, proxy) = bridged(connection.key);
        let (rx, thread) = receiving(&origins, proxy);
        // Refused without a descriptor taken for it.
        let outcome = origins.bind(prepared, connection.client.as_fd());
        assert!(matches!(
            outcome,
            Outcome::Refused(Reason::ResourceExhausted)
        ));
        assert_eq!(origins.sockets.load(Ordering::SeqCst), 0);
        origins.publish(connection.key, outcome);
        // Learned at once, not after the whole rendezvous.
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(500)).unwrap(),
            Ok(Seen::Unverified(Reason::ResourceExhausted))
        );
        thread.join().unwrap();
        drop(held);
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn only_a_connect_to_a_bridge_port_is_pinned() {
        let origins = configured(true, RENDEZVOUS);
        let (pid, start) = this_process();
        let elsewhere = SocketAddr::from(([127, 0, 0, 1], 8080));
        assert!(origins.prepare(pid, start, elsewhere).is_none());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
        // The unspecified address reaches the loopback bridge too.
        let any = SocketAddr::from(([0, 0, 0, 0], crate::platform::linux::bridge::SOCKS_PORT));
        assert!(origins.prepare(pid, start, any).is_some());
        // A connection whose peer is not the bridge publishes nothing.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert_eq!(bridge_key(client.as_fd()), None);
    }

    #[test]
    fn an_exited_process_releases_its_pin_and_is_denied() {
        let origins = configured(true, RENDEZVOUS);
        let mut child = Other::spawn();
        let process = pin(&origins, child.pid(), child.start());
        let connection = connection();
        let key = connection.key;
        origins.publish(key, authority(&origins, process, &connection.client));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 1);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        // The next publication prunes it, and its socket with it.
        origins.publish(loopback(40010, 3128), refused());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
        assert!(matches!(
            origins.table().entries[&key].outcome,
            Outcome::Refused(Reason::CredentialProcessDenied)
        ));
        let (_bridge, proxy) = bridged(key);
        assert_eq!(
            seen(origins.receive(&proxy)),
            Ok(Seen::Unverified(Reason::CredentialProcessDenied))
        );
    }

    #[test]
    fn only_the_kernel_pinned_executable_can_authorize_a_connection() {
        let (pid, start) = this_process();
        let process = Process::capture(pid, start, None).unwrap();
        let actual = std::env::current_exe().unwrap().canonicalize().unwrap();
        // Cargo's executable can be group writable under an operator umask.
        // This fixture tests kernel identity separately from the production
        // path constructor's stricter permission rule.
        let file = File::open(actual).unwrap();
        let authority = Executable {
            identity: identity(&file).unwrap(),
            file,
        };
        let pinned = Initiator::Pinned(process);
        assert!(pinned.check(&[authority]).is_ok());
        let other = Executable::pin(
            std::path::Path::new("/usr/bin/true")
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pinned.check(&[other]), Err(Reason::CredentialProcessDenied));
        assert_eq!(
            Initiator::Unverified(Reason::ResourceExhausted).check(&[]),
            Err(Reason::ResourceExhausted)
        );
        assert!(Process::capture(pid, start + 1, None).is_none());
    }

    #[test]
    fn a_live_connection_keeps_its_authority_until_it_claims_it() {
        let origins = configured(true, Duration::from_millis(50));
        let mut connection = connection();
        origins.publish(
            connection.key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        // The client sends its request and ends its side, as some clients
        // do, and the bridge reads it all; none of that ends the connection.
        connection
            .client
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        connection
            .client
            .shutdown(std::net::Shutdown::Write)
            .unwrap();
        let mut request = Vec::new();
        connection.accepted.read_to_end(&mut request).unwrap();
        origins.publish(loopback(40012, 3128), refused());
        assert!(origins.table().entries.contains_key(&connection.key));
        // The same live socket is no authority for a connection it does not
        // carry.
        let elsewhere = Key::new(
            SocketAddr::from(([127, 0, 0, 1], connection.key.client.port() ^ 1)),
            connection.key.bridge_port,
        );
        origins.publish(
            elsewhere,
            authority(&origins, pinned(&origins), &connection.client),
        );
        let (_bridge, proxy) = bridged(elsewhere);
        assert_eq!(
            seen(origins.receive(&proxy)),
            Ok(Seen::Unverified(Reason::CredentialProcessUnverified))
        );
        let (_bridge, proxy) = bridged(connection.key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned(me())));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_connection_the_bridge_turned_away_releases_its_authority_at_once() {
        let origins = configured(true, RENDEZVOUS);
        let mut connection = connection();
        origins.publish(
            connection.key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        // The bridge's answer at capacity: a response, then both directions
        // shut down, long before the retention runs out.
        connection
            .accepted
            .write_all(b"HTTP/1.1 503 \r\n\r\n")
            .unwrap();
        connection
            .accepted
            .shutdown(std::net::Shutdown::Both)
            .unwrap();
        drop(connection.accepted);
        until(&connection.client, libc::POLLRDHUP);
        origins.publish(loopback(40013, 3128), refused());
        assert!(!origins.table().entries.contains_key(&connection.key));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_authority_is_never_claimed_by_a_later_connection_on_its_reused_address() {
        let origins = configured(true, RENDEZVOUS);
        let bridge = TcpListener::bind("127.0.0.1:0").unwrap();
        // An allowed process connects, and its authority is published.
        let allowed = Other::spawn();
        let mut first = connected_to(
            &bridge,
            TcpStream::connect(bridge.local_addr().unwrap()).unwrap(),
        );
        let key = first.key;
        let process = pin(&origins, allowed.pid(), allowed.start());
        origins.publish(key, authority(&origins, process, &first.client));
        // The bridge turns it away at capacity without reading its request,
        // so closing resets it, before any preamble: nothing claims it.
        first.client.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        first.accepted.peek(&mut [0]).unwrap();
        first.accepted.write_all(b"HTTP/1.1 503 \r\n\r\n").unwrap();
        first.accepted.shutdown(std::net::Shutdown::Both).unwrap();
        drop(first.accepted);
        until(&first.client, 0);
        // Another process connects from the same address and port, and its
        // claim comes before its own publication.
        let deadline = Instant::now() + Duration::from_secs(5);
        let reused = loop {
            match connect_from(key.client, &bridge) {
                Ok(client) => break connected_to(&bridge, client),
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "the address stayed taken: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        assert_eq!(reused.key, key);
        let (_bridge, proxy) = bridged(key);
        let (rx, thread) = receiving(&origins, proxy);
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        // The stale authority was dropped, not handed out.
        assert!(!origins.table().entries.contains_key(&key));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
        origins.publish(key, authority(&origins, pinned(&origins), &reused.client));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(Seen::Pinned(me()))
        );
        thread.join().unwrap();
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_held_socket_left_to_linger_never_holds_up_a_claim_or_stop() {
        const LINGER: libc::c_int = 5;
        let origins = configured(true, RENDEZVOUS);
        let (mut claimed, mut stopped) = (connection(), connection());
        for connection in [&mut claimed, &mut stopped] {
            lingering(&mut connection.client, LINGER);
            let outcome = authority(&origins, pinned(&origins), &connection.client);
            origins.publish(connection.key, outcome);
        }
        assert_eq!(origins.sockets.load(Ordering::SeqCst), 2);
        // The process closes its own descriptors: each held duplicate is
        // its socket's last.
        let (claimed_peer, stopped_peer) = (claimed.accepted, stopped.accepted);
        drop((claimed.client, stopped.client));
        let began = Instant::now();
        let (_bridge, proxy) = bridged(claimed.key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned(me())));
        origins.stop();
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "a claim and stop waited {:?} on lingering sockets",
            began.elapsed()
        );
        // The closer waits instead, until each peer goes (resetting the
        // connection it never read) and the socket can close.
        drop((claimed_peer, stopped_peer));
        let deadline = Instant::now() + Duration::from_secs(5);
        while origins.sockets.load(Ordering::SeqCst) != 0 {
            assert!(Instant::now() < deadline, "the closer never closed them");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_full_table_evicts_its_oldest_outcome_and_never_escalates_the_evicted() {
        let origins = configured(true, Duration::from_millis(50));
        let oldest = connection();
        origins.publish(
            oldest.key,
            authority(&origins, pinned(&origins), &oldest.client),
        );
        // Strictly older than everything published after it.
        std::thread::sleep(Duration::from_millis(2));
        let keys: Vec<Key> = (1..=MAX_ENTRIES)
            .map(|port| loopback(u16::try_from(port).unwrap(), 3129))
            .collect();
        let (last, rest) = keys.split_last().unwrap();
        for key in rest {
            origins.publish(*key, refused());
        }
        assert_eq!(origins.table().entries.len(), MAX_ENTRIES);
        assert_eq!(origins.pins.load(Ordering::SeqCst), 1);
        origins.publish(*last, refused());
        {
            let table = origins.table();
            assert_eq!(table.entries.len(), MAX_ENTRIES);
            assert!(!table.entries.contains_key(&oldest.key), "the oldest went");
            assert!(keys.iter().all(|key| table.entries.contains_key(key)));
        }
        // Its pin went with it, and its connection, still live, is not
        // authorized by anything else: it waits out the rendezvous.
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
        let (_bridge, proxy) = bridged(oldest.key);
        assert_eq!(
            seen(origins.receive(&proxy)),
            Ok(Seen::Unverified(Reason::CredentialProcessUnverified))
        );
    }

    #[test]
    fn a_waiter_receives_its_authority_when_its_publication_evicts_another() {
        let origins = configured(true, RENDEZVOUS);
        for port in 1..=MAX_ENTRIES {
            origins.publish(loopback(u16::try_from(port).unwrap(), 3129), refused());
        }
        let connection = connection();
        let (_bridge, proxy) = bridged(connection.key);
        let (rx, thread) = receiving(&origins, proxy);
        origins.publish(
            connection.key,
            authority(&origins, pinned(&origins), &connection.client),
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(Seen::Pinned(me()))
        );
        thread.join().unwrap();
        assert_eq!(origins.table().entries.len(), MAX_ENTRIES - 1);
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }
}
