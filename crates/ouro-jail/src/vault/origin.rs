//! Connection-initiating executable authority from the seccomp mediator and
//! the sealed bridge. HTTP headers and child argv never supply process
//! identity.
//!
//! The rendezvous: for every connect to a bridge port, the mediator pins the
//! calling process before it connects ([`Origins::prepare`]) and, once the
//! connect succeeded, publishes what it established under the connection's
//! key ([`Origins::connected`]): the pinned process, or why there is none.
//! The sealed bridge writes the same key ahead of the stream it relays
//! ([`preamble`]), and the proxy claims the outcome published under exactly
//! that key ([`Origins::receive`]). TCP accept and the preamble can beat the
//! publication, so the proxy waits for it, at most [`RENDEZVOUS`]; because
//! every completed bridge connect publishes, refusals included, the wait
//! ends as soon as the mediator is done.
//!
//! The bridge and the proxy agree by construction: the supervisor seals the
//! bridge with the vault byte exactly when it starts the proxy with a vault,
//! the bridge then writes a preamble ahead of every relayed stream, and a
//! proxy with a vault reads one at the start of every connection.
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read as _};
use std::net::TcpStream;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd as _, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::proxy::Reason;

/// How long the proxy waits for a connection's authority from the start of
/// the connection: reading the preamble and waiting for the publication
/// share it.
pub(crate) const RENDEZVOUS: Duration = Duration::from_secs(2);
/// How long a published outcome waits for its connection to claim it.
#[cfg(target_os = "linux")]
const RETENTION: Duration = Duration::from_secs(10);
/// The most processes pinned at once.
pub(crate) const MAX_PINNED: usize = 128;
/// Descriptors one pinned process holds: its pidfd and its executable.
pub(crate) const FDS_PER_PIN: usize = 2;
/// Published outcomes waiting for their connection. Each authority holds a
/// pin, so the pin budget already bounds those; this bounds refusals too.
#[cfg(target_os = "linux")]
const MAX_ENTRIES: usize = MAX_PINNED;
const MAGIC: &[u8; 8] = b"OUROPID1";
/// [`MAGIC`], then the client port and the bridge port.
const PREAMBLE_LEN: usize = 12;

/// A bridged connection: its client port and the bridge port it reached.
type Key = (u16, u16);

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
/// One unit of the pin budget, returned when its process is dropped.
struct Reservation(Arc<AtomicUsize>);
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

/// What the mediator established about one bridged connection.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only the Linux mediator publishes")
)]
enum Outcome {
    Authority(Process),
    Refused(Reason),
}
impl From<Outcome> for Initiator {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Authority(process) => Initiator::Pinned(process),
            Outcome::Refused(reason) => Initiator::Unverified(reason),
        }
    }
}

/// What the mediator established before connecting, published once the
/// connect succeeded.
#[cfg(target_os = "linux")]
pub(crate) struct Prepared(Outcome);

#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only the Linux mediator publishes")
)]
struct Entry {
    at: Instant,
    outcome: Outcome,
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
        let reserved = self
            .pins
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < limit).then_some(count + 1)
            });
        let outcome = match reserved {
            // Published all the same, so the proxy learns at once that the
            // pin budget, not the process, is why there is no authority.
            Err(_) => Outcome::Refused(Reason::ResourceExhausted),
            Ok(_) => Process::capture(pid, start, Some(Reservation(Arc::clone(&self.pins))))
                .map_or(
                    Outcome::Refused(Reason::CredentialProcessUnverified),
                    Outcome::Authority,
                ),
        };
        Some(Prepared(outcome))
    }
    /// Called by the mediator once its connect on `socket` succeeded:
    /// publishes the prepared outcome when the peer is the bridge.
    #[cfg(target_os = "linux")]
    pub(crate) fn connected(&self, prepared: Prepared, socket: BorrowedFd<'_>) {
        if let Some(key) = bridge_key(socket) {
            self.publish(key, prepared.0);
        }
    }
    #[cfg(target_os = "linux")]
    fn publish(&self, key: Key, outcome: Outcome) {
        let mut table = self.table();
        if table.stopped {
            return;
        }
        prune(&mut table.entries);
        if table.entries.len() >= MAX_ENTRIES && !table.entries.contains_key(&key) {
            // A receiver claims its outcome the moment it is published, so
            // the oldest one belongs to a connection the bridge turned away.
            let oldest = table
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.at)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                table.entries.remove(&oldest);
            }
        }
        // Existing authority cannot be replaced by a later connection.
        table.entries.entry(key).or_insert(Entry {
            at: Instant::now(),
            outcome,
        });
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
            // just as the wait timed out still counts.
            if let Some(entry) = table.entries.remove(&key) {
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
    use std::os::fd::FromRawFd as _;
    // SAFETY: the stream never owns the descriptor: `ManuallyDrop` keeps it
    // from closing it, and the borrow keeps it open while the stream lives.
    // It is an internet socket, the only kind the mediator prepares for.
    let stream = std::mem::ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(socket.as_raw_fd()) });
    let (local, peer) = (stream.local_addr().ok()?, stream.peer_addr().ok()?);
    let loopback = IpAddr::V4(crate::platform::linux::bridge::LOOPBACK);
    (peer.ip().to_canonical() == loopback && bridge_port(peer.port()))
        .then_some((local.port(), peer.port()))
}

/// Drops outcomes no connection claimed within [`RETENTION`], and releases
/// the pin of a process that has exited: its connection gets the denial
/// [`Process::permits`] would give, without descriptors held for it.
#[cfg(target_os = "linux")]
fn prune(entries: &mut HashMap<Key, Entry>) {
    entries.retain(|_, entry| entry.at.elapsed() < RETENTION);
    for entry in entries.values_mut() {
        if matches!(&entry.outcome, Outcome::Authority(process) if !process.alive()) {
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
    let mut bytes = [0u8; PREAMBLE_LEN];
    let (magic, ports) = bytes.split_at_mut(MAGIC.len());
    magic.copy_from_slice(MAGIC);
    ports[..2].copy_from_slice(&key.0.to_be_bytes());
    ports[2..].copy_from_slice(&key.1.to_be_bytes());
    bytes
}
fn decode(bytes: &[u8; PREAMBLE_LEN]) -> Option<Key> {
    let (magic, ports) = bytes.split_at(MAGIC.len());
    (magic == MAGIC).then(|| {
        (
            u16::from_be_bytes([ports[0], ports[1]]),
            u16::from_be_bytes([ports[2], ports[3]]),
        )
    })
}
/// The preamble the sealed bridge writes ahead of a client it relays: the
/// key the mediator published that connection's outcome under.
pub(crate) fn preamble(client: &TcpStream) -> io::Result<[u8; PREAMBLE_LEN]> {
    Ok(encode((
        client.peer_addr()?.port(),
        client.local_addr()?.port(),
    )))
}
/// A preamble as the bridge writes it, for tests that stand in for the
/// bridge in front of a vault proxy.
#[cfg(test)]
pub(super) fn preamble_for(client_port: u16, bridge_port: u16) -> [u8; PREAMBLE_LEN] {
    encode((client_port, bridge_port))
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
        let key = (
            client.local_addr().unwrap().port(),
            listener.local_addr().unwrap().port(),
        );
        let bytes = preamble(&accepted).unwrap();
        assert_eq!(bytes, encode(key));
        assert_eq!(decode(&bytes), Some(key));
        let mut forged = bytes;
        forged[0] ^= 1;
        assert_eq!(decode(&forged), None);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::mpsc;

    /// A bridge-port destination, as the mediator would pass it.
    const BRIDGE: SocketAddr = SocketAddr::new(
        IpAddr::V4(crate::platform::linux::bridge::LOOPBACK),
        crate::platform::linux::bridge::HTTP_PORT,
    );

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

    /// This test process, pinned as the mediator would pin a connect.
    fn pinned(origins: &Origins) -> Outcome {
        let (pid, start) = this_process();
        let outcome = origins.prepare(pid, start, BRIDGE).unwrap().0;
        assert!(matches!(outcome, Outcome::Authority(_)));
        outcome
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Pinned,
        Unverified(Reason),
        NoRequest,
    }
    fn seen(received: Result<Option<Initiator>, Reason>) -> Result<Seen, Reason> {
        received.map(|initiator| match initiator {
            None => Seen::NoRequest,
            Some(Initiator::Pinned(_)) => Seen::Pinned,
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
        bridge.write_all(&encode((1, 2))[..5]).unwrap();
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
        let key = (40001, 3128);
        let (_bridge, proxy) = bridged(key);
        let (rx, thread) = receiving(&origins, proxy);
        let outcome = pinned(&origins);
        origins.publish(key, outcome);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(Seen::Pinned)
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
        let key = (40002, 3128);
        origins.publish(key, pinned(&origins));
        let (_bridge, proxy) = bridged(key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_published_origin_is_single_use_and_a_missing_origin_times_out() {
        let rendezvous = Duration::from_millis(50);
        let origins = configured(true, rendezvous);
        let key = (40003, 3128);
        origins.publish(key, pinned(&origins));
        let (_bridge, proxy) = bridged(key);
        assert_eq!(seen(origins.receive(&proxy)), Ok(Seen::Pinned));
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
        let (_bridge, proxy) = bridged((40004, 3128));
        let (rx, thread) = receiving(&origins, proxy);
        origins.publish((40005, 3128), pinned(&origins));
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
    fn publication_keeps_the_first_authority_and_stopped_origins_stay_closed() {
        let origins = configured(true, RENDEZVOUS);
        let key = (40006, 3129);
        let first = pinned(&origins);
        let Outcome::Authority(process) = &first else {
            unreachable!()
        };
        let first_process = process.clone();
        origins.publish(key, first);
        origins.publish(key, pinned(&origins));
        let (_bridge, proxy) = bridged(key);
        let Ok(Some(Initiator::Pinned(claimed))) = origins.receive(&proxy) else {
            panic!("the first authority was not claimed");
        };
        assert!(Arc::ptr_eq(&claimed.0, &first_process.0));
        drop((claimed, first_process));
        let pending = pinned(&origins);
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
    fn a_profile_without_process_binding_never_waits_for_origin_authority() {
        let origins = configured(false, RENDEZVOUS);
        let (_bridge, proxy) = bridged((40007, 3128));
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
        let refused = origins.prepare(pid, start, BRIDGE).unwrap().0;
        assert!(matches!(
            refused,
            Outcome::Refused(Reason::ResourceExhausted)
        ));
        let key = (40008, 3128);
        let (_bridge, proxy) = bridged(key);
        let (rx, thread) = receiving(&origins, proxy);
        origins.publish(key, refused);
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
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let start = crate::platform::linux::identity::start_time_ticks(pid).unwrap();
        let outcome = origins.prepare(pid, start, BRIDGE).unwrap().0;
        assert!(matches!(outcome, Outcome::Authority(_)));
        let key = (40009, 3128);
        origins.publish(key, outcome);
        assert_eq!(origins.pins.load(Ordering::SeqCst), 1);
        child.kill().unwrap();
        child.wait().unwrap();
        // The next publication prunes it.
        origins.publish((40010, 3128), Outcome::Refused(Reason::ResourceExhausted));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
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
}
