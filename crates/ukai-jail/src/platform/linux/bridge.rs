//! The in-namespace loopback bridge of the `agent` profile: `ukai-jail
//! __bridge`.
//!
//! jail-v1 §10 has the bridge listen on `127.0.0.1:3128` and connect to
//! `/run/ukai/proxy/proxy.sock`; jail-v2 §6.1 adds a SOCKS5 listener on
//! `127.0.0.1:3129`, relayed the same way. It is a byte relay: it parses no
//! request, decides nothing and holds no authority beyond its sockets. The
//! one thing it adds is, when the supervisor sealed it for a vault, a
//! preamble ahead of each relayed stream naming the client's address
//! (`vault::origin::preamble`), under which the proxy finds the process the
//! mediator pinned for that connect. The proxy outside decides every
//! request; the mediator refuses a child's direct connect to
//! `/run/ukai/proxy/proxy.sock`, which only the bridge may reach.
//!
//! The launcher starts it before the target is released, with a double fork,
//! `/dev/null` as stdin and stdout, the report end of a `SOCK_SEQPACKET` pair
//! as stderr (the supervisor holds the other end), no other descriptor, an
//! empty environment and a session of its own. Once the supervisor has
//! discovered and verified the bridge, it seals it over that pair and the
//! bridge makes itself non-dumpable before it serves its first client, so a
//! same-uid target cannot reach its `/proc` entries on any host. It runs under
//! the same seccomp filters as the child, so its `connect` to the proxy socket
//! is mediated: the supervisor allows exactly the pinned proxy socket identity,
//! whatever the path now names. That is what makes the path unredirectable by a
//! child rename, unlink, symlink or mount change — not anything the bridge
//! checks itself.
//!
//! It is one thread with nonblocking sockets and `poll`, bounded at
//! [`MAX_CONNECTIONS`] relays with [`BUFFER`] bytes per direction, so its
//! resource use is fixed, and it charges the attempt's cgroup like any other
//! process in the attempt. It never exits on its own; it dies with the
//! namespace. When the proxy is unreachable it closes the client, and nothing
//! falls back to direct egress: it has no other route.

use std::ffi::OsString;
use std::io;
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// The hidden subcommand token.
pub const SUBCOMMAND: &str = "__bridge";
/// The only address the bridge listens on, on two ports.
pub const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// The HTTP proxy port (jail-v1 §10).
pub const HTTP_PORT: u16 = 3128;
/// SOCKS5 uses the same isolated bridge and outside policy evaluator.
pub const SOCKS_PORT: u16 = 3129;
/// The HTTP proxy listener.
pub const LISTEN: SocketAddrV4 = SocketAddrV4::new(LOOPBACK, HTTP_PORT);
/// The SOCKS5 listener.
pub const SOCKS_LISTEN: SocketAddrV4 = SocketAddrV4::new(LOOPBACK, SOCKS_PORT);
/// The proxy socket as the sandbox sees it.
pub const PROXY_PATH: &str = "/run/ukai/proxy/proxy.sock";
/// The most relays at once: the proxy's own connection budget (§10). A
/// client beyond it is answered [`OVERLOAD_RESPONSE`] and closed at once
/// rather than left in the kernel's backlog until it gives up, and counted:
/// one byte on the report socket, which the supervisor records as the
/// bridge's `rejected_at_capacity`.
pub const MAX_CONNECTIONS: usize = crate::proxy::Budgets::DEFAULT.max_connections;

/// What a client beyond [`MAX_CONNECTIONS`] gets: a complete, fixed
/// `503` in the proxy's own refusal format, written without reading or
/// parsing anything the client sent (§10: "At capacity, reject excess
/// requests with a safe overload reason").
pub const OVERLOAD_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n\
Content-Length: 16\r\nX-Ukai-Proxy-Reason: bridge_overload\r\nConnection: close\r\n\r\nbridge_overload\n";
/// Bytes buffered per relay direction.
pub const BUFFER: usize = 16 * 1024;

/// How long a poll round waits after `accept` failed for fd or memory
/// exhaustion (`EMFILE`, `ENFILE`, `ENOMEM`, `ENOBUFS`). The refusal leaves the
/// listener readable, so without the wait the loop would poll, accept-fail and
/// poll again as fast as it could, burning a core for the attempt's remaining
/// life. The queue that produced the ceiling does not drain by spinning on it.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Exit status when the bridge cannot bind its address.
pub const EXIT_BIND_FAILED: i32 = 126;
/// The report pair's protocol: one byte per `SOCK_SEQPACKET` datagram, so
/// one datagram is one message whatever is queued behind it.
pub(crate) mod report {
    /// Supervisor to bridge: sealed; relay without an origin preamble.
    pub const SEAL: u8 = b's';
    /// Supervisor to bridge: sealed for a vault; prefix each relayed
    /// stream with the client's origin preamble.
    pub const SEAL_VAULT: u8 = b'v';
    /// Bridge to supervisor: one client turned away at capacity.
    pub const REJECTED: u8 = b'o';
}

/// Seals the bridge over the supervisor's end of the report pair: one
/// datagram, [`report::SEAL_VAULT`] when the attempt has a vault, else
/// [`report::SEAL`].
///
/// # Errors
/// The `send` error, or a datagram the socket did not take whole.
pub fn send_seal(report: std::os::fd::BorrowedFd<'_>, vault: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let byte = [if vault {
        report::SEAL_VAULT
    } else {
        report::SEAL
    }];
    // SAFETY: `report` is a live socket descriptor; `byte` outlives the call
    // and its length is the count passed.
    let sent = unsafe {
        libc::send(
            report.as_raw_fd(),
            byte.as_ptr().cast(),
            byte.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    match sent {
        1 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("the seal was not sent whole")),
    }
}

/// Exit status when the supervisor's seal never arrived: the bridge makes
/// itself un-dumpable only on the supervisor's word (see [`await_seal`]),
/// and an unsealed bridge never serves.
pub const EXIT_UNSEALED: i32 = 124;
/// Exit status for arguments the bridge does not take.
pub const EXIT_USAGE: i32 = 125;

/// The HTTP proxy variables' value (jail-v1 §10).
#[must_use]
pub fn proxy_url() -> String {
    format!("http://{LISTEN}")
}

/// `ALL_PROXY`'s value: SOCKS5 with names resolved by the proxy.
#[must_use]
pub fn socks_url() -> String {
    format!("socks5h://{SOCKS_LISTEN}")
}

/// The environment variables `agent` sets, with their value (jail-v1 §10):
/// the three proxy variables in both spellings, and an empty `NO_PROXY`.
#[must_use]
pub fn proxy_environment() -> Vec<(&'static str, String)> {
    let (http, socks) = (proxy_url(), socks_url());
    vec![
        ("HTTP_PROXY", http.clone()),
        ("HTTPS_PROXY", http.clone()),
        ("ALL_PROXY", socks.clone()),
        ("http_proxy", http.clone()),
        ("https_proxy", http),
        ("all_proxy", socks),
        ("NO_PROXY", String::new()),
        ("no_proxy", String::new()),
    ]
}

/// Run the bridge. Never returns.
pub fn bridge_main(args: &[OsString]) -> ! {
    if !args.is_empty() {
        std::process::exit(EXIT_USAGE);
    }
    let listener = match TcpListener::bind(LISTEN) {
        Ok(listener) => listener,
        Err(_) => std::process::exit(EXIT_BIND_FAILED),
    };
    if listener.set_nonblocking(true).is_err() {
        std::process::exit(EXIT_BIND_FAILED);
    }
    let socks = match TcpListener::bind(SOCKS_LISTEN) {
        Ok(listener) => listener,
        Err(_) => std::process::exit(EXIT_BIND_FAILED),
    };
    if socks.set_nonblocking(true).is_err() {
        std::process::exit(EXIT_BIND_FAILED);
    }
    // The supervisor discovers and reads back this bridge while it is still
    // dumpable, then seals it — one datagram on the report pair — and only then
    // is the target released. The seal is the bridge's own signal to drop out
    // of `/proc` reach of a same-uid peer: until it lands, the bridge parks
    // here and serves no one. A peer that closes the pair (the supervisor
    // dying) fails the wait rather than parking the bridge forever.
    let Some(credential_origin) = await_seal() else {
        std::process::exit(EXIT_UNSEALED);
    };
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0, ...)` takes scalars only and cannot
    // fail. From here `/proc/<bridge>` belongs to root: a same-uid target
    // gets `EACCES` on its `mem`, `environ` and `fd` at every Yama scope,
    // including `ptrace_scope=0` hosts.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    serve_many(
        &[&listener, &socks],
        &|| UnixStream::connect(PROXY_PATH),
        &report_rejection,
        credential_origin,
    );
    // `serve` only returns when polling itself fails, which leaves nothing
    // to relay with; the attempt's clients then see connections refused.
    std::process::exit(0);
}

/// Waits for the supervisor's seal on the report pair (fd 2, the same
/// descriptor rejections are later written to). The pair is a
/// `SOCK_SEQPACKET` socket, so one datagram is one seal; `poll` reports the
/// peer's death as `POLLHUP`, which fails the wait rather than parking the
/// bridge forever.
fn await_seal() -> Option<bool> {
    let stderr = std::io::stderr();
    // The infinite wait is fine because the peer's death wakes the poll.
    let revents = crate::sys::poll(&[Some((stderr.as_fd(), libc::POLLIN))], None).ok()?;
    if revents
        .first()
        .is_none_or(|&events| events & libc::POLLIN == 0)
    {
        return None;
    }
    let mut byte = [0u8; 1];
    // SAFETY: the descriptor is a socket this process owns; `byte` is
    // writable and its length matches the count.
    let received = unsafe { libc::recv(libc::STDERR_FILENO, byte.as_mut_ptr().cast(), 1, 0) };
    (received == 1 && matches!(byte[0], report::SEAL | report::SEAL_VAULT))
        .then_some(byte[0] == report::SEAL_VAULT)
}

/// One byte on stderr, the report `SOCK_SEQPACKET` socket the supervisor
/// holds the other end of: the supervisor counts the bridge's rejections
/// from it. A full socket drops the byte rather than stall a relay.
fn report_rejection() {
    use std::io::Write as _;
    let _ = std::io::stderr().write(&[report::REJECTED]);
}

/// One direction of a relay.
struct Pipe {
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
    /// The reading side reached EOF.
    eof: bool,
    /// The writing side was shut down after the EOF was forwarded.
    shut: bool,
}

impl Pipe {
    fn new() -> Self {
        Pipe {
            buffer: vec![0u8; BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            eof: false,
            shut: false,
        }
    }

    fn has_data(&self) -> bool {
        self.start < self.end
    }

    fn wants_read(&self) -> bool {
        !self.eof && self.end < self.buffer.len()
    }

    /// Reads what is available; `Err` ends the relay.
    fn fill(&mut self, from: &mut impl io::Read) -> io::Result<()> {
        match from.read(&mut self.buffer[self.end..]) {
            Ok(0) => self.eof = true,
            Ok(n) => self.end += n,
            Err(error) if would_block(&error) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Writes what is buffered; `Err` ends the relay. An emptied buffer is
    /// rewound at once: a full buffer that drained must be readable again,
    /// or neither side would ever be polled for it.
    fn drain(&mut self, to: &mut impl io::Write) -> io::Result<()> {
        while self.has_data() {
            match to.write(&self.buffer[self.start..self.end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.start += n,
                Err(error) if would_block(&error) => break,
                Err(error) => return Err(error),
            }
        }
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        Ok(())
    }
}

fn would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// One client and its proxy connection.
struct Relay {
    client: TcpStream,
    upstream: UnixStream,
    /// Client to proxy.
    up: Pipe,
    /// Proxy to client.
    down: Pipe,
}

impl Relay {
    fn finished(&self) -> bool {
        self.up.shut && self.down.shut
    }

    /// Forwards an EOF once everything before it was written.
    fn propagate_eof(&mut self) {
        if self.up.eof && !self.up.has_data() && !self.up.shut {
            let _ = self.upstream.shutdown(Shutdown::Write);
            self.up.shut = true;
        }
        if self.down.eof && !self.down.has_data() && !self.down.shut {
            let _ = self.client.shutdown(Shutdown::Write);
            self.down.shut = true;
        }
    }
}

/// The relay loop. `connect` opens one proxy connection; the live bridge
/// passes [`PROXY_PATH`], tests pass their own socket. `rejected` is called
/// once for each client turned away at capacity.
///
/// Returns only when `poll` fails for a reason other than `EINTR`. An accept
/// that fails for fd or memory exhaustion leaves the listener readable, so the
/// round that discovers it sleeps before the next poll instead of spinning;
/// every other accept error is answered as before, with no wait.
pub fn serve(
    listener: &TcpListener,
    connect: &dyn Fn() -> io::Result<UnixStream>,
    rejected: &dyn Fn(),
) {
    serve_many(&[listener], connect, rejected, false);
}

fn serve_many(
    listeners: &[&TcpListener],
    connect: &dyn Fn() -> io::Result<UnixStream>,
    rejected: &dyn Fn(),
    credential_origin: bool,
) {
    let mut relays: Vec<Relay> = Vec::new();
    loop {
        let mut interests: Vec<crate::sys::Interest<'_>> =
            Vec::with_capacity(listeners.len() + relays.len() * 2);
        for listener in listeners {
            interests.push(Some((listener.as_fd(), libc::POLLIN)));
        }
        for relay in &relays {
            let mut client = 0;
            if relay.up.wants_read() {
                client |= libc::POLLIN;
            }
            if relay.down.has_data() {
                client |= libc::POLLOUT;
            }
            let mut upstream = 0;
            if relay.down.wants_read() {
                upstream |= libc::POLLIN;
            }
            if relay.up.has_data() {
                upstream |= libc::POLLOUT;
            }
            // A side with nothing asked of it is left out: a half-closed
            // peer reports POLLHUP whether or not anything was requested,
            // which would otherwise spin.
            interests.push((client != 0).then_some((relay.client.as_fd(), client)));
            interests.push((upstream != 0).then_some((relay.upstream.as_fd(), upstream)));
        }
        let revents = match crate::sys::poll(&interests, None) {
            Ok(revents) => revents,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };

        for (index, relay) in relays.iter_mut().enumerate() {
            let client = revents[listeners.len() + index * 2];
            let upstream = revents[listeners.len() + 1 + index * 2];
            if step(relay, client, upstream).is_err() {
                // Either side failed: close both. The client sees its
                // connection end; nothing else is attempted for it.
                relay.up.shut = true;
                relay.down.shut = true;
            }
        }
        relays.retain(|relay| !relay.finished());

        for (index, listener) in listeners.iter().enumerate() {
            if revents[index] != 0
                && accept_all(listener, connect, rejected, &mut relays, credential_origin)
            {
                // The accept failed on process-wide resource exhaustion while
                // the listener stayed readable; poll once less often rather
                // than spin a core.
                std::thread::sleep(ACCEPT_BACKOFF);
            }
        }
    }
}

fn step(relay: &mut Relay, client: libc::c_short, upstream: libc::c_short) -> io::Result<()> {
    let readable = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
    if client & libc::POLLNVAL != 0 || upstream & libc::POLLNVAL != 0 {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    if client & readable != 0 && relay.up.wants_read() {
        relay.up.fill(&mut relay.client)?;
    }
    if upstream & readable != 0 && relay.down.wants_read() {
        relay.down.fill(&mut relay.upstream)?;
    }
    if relay.up.has_data() {
        relay.up.drain(&mut relay.upstream)?;
    }
    if relay.down.has_data() {
        relay.down.drain(&mut relay.client)?;
    }
    relay.propagate_eof();
    // A relay ends when both directions forwarded their EOF, or when a read
    // or a write fails. A hang-up alone ends nothing: a half-closed client
    // still waits for the proxy's response.
    Ok(())
}

/// Accepts every client waiting now. Returns whether an accept failed for fd or
/// memory exhaustion, which leaves the listener readable and asks [`serve`] for
/// one [`ACCEPT_BACKOFF`] before the next poll round. Any other accept error —
/// a reset connection, a race with a client that went away — is answered as
/// before, with no wait.
fn accept_all(
    listener: &TcpListener,
    connect: &dyn Fn() -> io::Result<UnixStream>,
    rejected: &dyn Fn(),
    relays: &mut Vec<Relay>,
    credential_origin: bool,
) -> bool {
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(error) => {
                return matches!(
                    error.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS),
                );
            }
        };
        if relays.len() >= MAX_CONNECTIONS {
            // A nonblocking best effort: the response is far smaller than a
            // socket buffer, and a client that cannot take it is closed
            // anyway. Nothing is read, so nothing waits on the client.
            use std::io::Write as _;
            // Counted first, so the count is in before the client sees
            // the answer.
            rejected();
            let _ = client.set_nonblocking(true);
            let _ = (&client).write(OVERLOAD_RESPONSE);
            let _ = client.shutdown(Shutdown::Both);
            continue;
        }
        // The preamble is read from the client's own addresses before
        // anything is opened for it: a client already gone (reset before
        // this accept) is closed, neither counted as turned away at capacity
        // nor handed to the proxy as a request.
        let prefix = if credential_origin {
            match crate::vault::origin::preamble(&client) {
                Ok(prefix) => Some(prefix),
                Err(_) => {
                    let _ = client.shutdown(Shutdown::Both);
                    continue;
                }
            }
        } else {
            None
        };
        // A proxy that cannot be reached (dead, replaced, refused by the
        // mediator) closes this client and nothing else: fail closed.
        let Ok(upstream) = connect() else {
            let _ = client.shutdown(Shutdown::Both);
            continue;
        };
        if client.set_nonblocking(true).is_err() || upstream.set_nonblocking(true).is_err() {
            continue;
        }
        let mut up = Pipe::new();
        if let Some(prefix) = prefix {
            up.buffer[..prefix.len()].copy_from_slice(&prefix);
            up.end = prefix.len();
        }
        relays.push(Relay {
            client,
            upstream,
            up,
            down: Pipe::new(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;

    /// A bridge on an ephemeral loopback port, relaying to a Unix listener
    /// this test owns, on a thread that lives for the test process; with the
    /// count of clients it turned away.
    fn bridge_to(
        path: std::path::PathBuf,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let rejected = std::sync::Arc::new(AtomicUsize::new(0));
        let count = rejected.clone();
        std::thread::spawn(move || {
            serve(&listener, &|| UnixStream::connect(&path), &|| {
                count.fetch_add(1, Ordering::SeqCst);
            });
        });
        (address, rejected)
    }

    /// Serves `listener` as a bridge sealed for a vault, which writes the
    /// credential-origin preamble ahead of each client; with the counts of
    /// proxy connections it opened and clients it turned away.
    fn vault_bridge(
        listener: TcpListener,
        path: std::path::PathBuf,
    ) -> (
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        listener.set_nonblocking(true).unwrap();
        let (connects, rejected) = (
            std::sync::Arc::new(AtomicUsize::new(0)),
            std::sync::Arc::new(AtomicUsize::new(0)),
        );
        let (opened, turned_away) = (connects.clone(), rejected.clone());
        std::thread::spawn(move || {
            serve_many(
                &[&listener],
                &|| {
                    opened.fetch_add(1, Ordering::SeqCst);
                    UnixStream::connect(&path)
                },
                &|| {
                    turned_away.fetch_add(1, Ordering::SeqCst);
                },
                true,
            );
        });
        (connects, rejected)
    }

    #[test]
    fn a_vault_bridge_writes_the_origin_preamble_before_the_client_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let upstream = UnixListener::bind(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let _ = vault_bridge(listener, path);
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"hello").unwrap();
        let (mut stream, _) = upstream.accept().unwrap();
        let expected =
            crate::vault::origin::preamble_for(client.local_addr().unwrap(), address.port());
        let mut received = vec![0u8; expected.len() + 5];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(&received[..expected.len()], &expected);
        assert_eq!(&received[expected.len()..], b"hello");
    }

    #[test]
    fn a_client_gone_before_its_preamble_opens_nothing_and_is_not_a_capacity_rejection() {
        use std::os::fd::AsRawFd as _;
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let upstream = UnixListener::bind(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // Queued, then reset, before the bridge accepts it.
        let gone = TcpStream::connect(address).unwrap();
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: `linger` is a valid `linger` of the size passed, and the
        // descriptor belongs to `gone`, open for the call.
        let rc = unsafe {
            libc::setsockopt(
                gone.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&raw const linger).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::linger>()).unwrap(),
            )
        };
        assert_eq!(rc, 0);
        drop(gone);
        let (connects, rejected) = vault_bridge(listener, path);
        // A live client after it: once its relay reaches the proxy, the
        // bridge has dealt with the one before it.
        let mut live = TcpStream::connect(address).unwrap();
        live.write_all(b"x").unwrap();
        let (_stream, _) = upstream.accept().unwrap();
        assert_eq!(connects.load(Ordering::SeqCst), 1, "only the live client");
        assert_eq!(rejected.load(Ordering::SeqCst), 0, "not turned away");
    }

    #[test]
    fn bytes_flow_both_ways_and_half_close_is_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let upstream = UnixListener::bind(&path).unwrap();
        let (address, _) = bridge_to(path);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(b"reply:").unwrap();
            stream.write_all(&request).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        let payload = vec![7u8; 3 * BUFFER + 11];
        client.write_all(&payload).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        server.join().unwrap();
        assert_eq!(&reply[..6], b"reply:");
        assert_eq!(&reply[6..], &payload[..]);
    }

    /// About four descriptors per relay live in this one test process, next
    /// to every other unit test running in parallel: the budget under test is
    /// the bridge's, not the test runner's soft descriptor limit.
    fn raise_soft_descriptor_limit() {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit and setrlimit read or fill a live rlimit.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) == 0 {
                let wanted = limit.rlim_max.min(8192);
                if limit.rlim_cur < wanted {
                    limit.rlim_cur = wanted;
                    libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit);
                }
            }
        }
    }

    #[test]
    fn a_client_beyond_the_budget_is_answered_503_at_once_and_the_rest_are_relayed() {
        use std::os::unix::net::UnixListener;
        raise_soft_descriptor_limit();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let upstream = UnixListener::bind(&path).unwrap();
        let (address, rejected) = bridge_to(path);
        // Fill the budget with relays that stay open, each one accepted by
        // the stand-in proxy so the bridge's connect completes.
        let mut held = Vec::new();
        let mut accepted = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let mut client = TcpStream::connect(address).unwrap();
            client.write_all(b"x").unwrap();
            let (mut stream, _) = upstream.accept().unwrap();
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            held.push(client);
            accepted.push(stream);
        }
        let mut extra = TcpStream::connect(address).unwrap();
        extra
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let started = std::time::Instant::now();
        let mut reply = Vec::new();
        extra.read_to_end(&mut reply).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(reply, OVERLOAD_RESPONSE);
        assert!(reply.starts_with(b"HTTP/1.1 503 "));
        assert_eq!(
            rejected.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "counted, once"
        );
        // Every held relay still carries bytes both ways.
        for (client, stream) in held.iter_mut().zip(&mut accepted) {
            stream.write_all(b"y").unwrap();
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"y");
        }
        // A slot freed is a slot the next client gets.
        drop(held.pop());
        drop(accepted.pop());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut next = TcpStream::connect(address).unwrap();
            next.write_all(b"z").unwrap();
            upstream.set_nonblocking(true).unwrap();
            let relayed = loop {
                match upstream.accept() {
                    Ok((mut stream, _)) => {
                        let mut byte = [0u8; 1];
                        stream.set_nonblocking(false).unwrap();
                        stream.read_exact(&mut byte).unwrap();
                        break byte == *b"z";
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        let mut probe = [0u8; 1];
                        next.set_nonblocking(true).unwrap();
                        if next.read(&mut probe).is_ok() {
                            break false; // answered 503: the slot was not free yet
                        }
                        next.set_nonblocking(false).unwrap();
                        std::thread::yield_now();
                    }
                    Err(error) => panic!("no relay after a slot was freed: {error}"),
                }
            };
            upstream.set_nonblocking(false).unwrap();
            if relayed {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the freed slot never came back"
            );
        }
    }

    #[test]
    fn a_full_buffer_that_drains_is_readable_again() {
        let mut pipe = Pipe::new();
        let bytes = vec![1u8; 2 * BUFFER];
        let mut source: &[u8] = &bytes;
        pipe.fill(&mut source).unwrap();
        assert!(!pipe.wants_read(), "full");
        let mut sink = Vec::new();
        pipe.drain(&mut sink).unwrap();
        assert_eq!(sink.len(), BUFFER);
        assert!(pipe.wants_read(), "a drained buffer takes the next bytes");
        pipe.fill(&mut source).unwrap();
        pipe.drain(&mut sink).unwrap();
        assert_eq!(sink.len(), 2 * BUFFER);
    }

    #[test]
    fn an_unreachable_proxy_closes_the_client_and_nothing_else_happens() {
        let dir = tempfile::tempdir().unwrap();
        let (address, rejected) = bridge_to(dir.path().join("absent.sock"));
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let _ = client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n");
        let mut reply = Vec::new();
        let read = client.read_to_end(&mut reply);
        assert!(
            read.is_ok() || read.is_err_and(|e| e.kind() == io::ErrorKind::ConnectionReset),
            "the client is closed, not left hanging"
        );
        assert!(reply.is_empty(), "the bridge never answers for the proxy");
        assert_eq!(
            rejected.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "not a capacity rejection"
        );
    }

    #[test]
    fn the_proxy_environment_is_both_spellings_and_an_empty_no_proxy() {
        let env = proxy_environment();
        for (name, expected) in [
            ("HTTP_PROXY", "http://127.0.0.1:3128"),
            ("HTTPS_PROXY", "http://127.0.0.1:3128"),
            ("ALL_PROXY", "socks5h://127.0.0.1:3129"),
        ] {
            for spelling in [name.to_owned(), name.to_ascii_lowercase()] {
                assert!(
                    env.iter()
                        .any(|(key, value)| *key == spelling && value == expected),
                    "{spelling}"
                );
            }
        }
        for name in ["NO_PROXY", "no_proxy"] {
            assert!(
                env.iter()
                    .any(|(key, value)| *key == name && value.is_empty())
            );
        }
        assert_eq!(LISTEN.to_string(), "127.0.0.1:3128");
        assert_eq!(SOCKS_LISTEN.to_string(), "127.0.0.1:3129");
    }
}
