//! One HTTP/1.1 request per TLS connection. No opaque forwarding in vault mode.
//!
//! jail-v2 §6.3: the lane "requires a content length for request bodies, and
//! refuses chunked uploads and Expect. It has a 32 KiB decrypted-header
//! bound, a 10 s header deadline, 30 s upstream I/O deadlines and a 300 s
//! client deadline. TLS record state is bounded separately from relay
//! buffers".
use super::{
    Budgets, EndReason, Reason,
    http::{self, Framing},
    origin,
    relay::RelayOutcome,
    sys,
};
use crate::{network::Destination, vault::Vault, vault::origin::Initiator};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// The bound on a decrypted request head, and on the upstream's response
/// head read before anything reaches the client.
const MAX_HEAD: usize = 32 * 1024;
/// From the start of the lane to a complete decrypted request head.
const HEADER_DEADLINE: Duration = Duration::from_secs(10);
/// Each upstream read and write.
const UPSTREAM_IO: Duration = Duration::from_secs(30);
/// The client's whole connection, from the start of the lane.
const CLIENT_DEADLINE: Duration = Duration::from_secs(300);
/// Plaintext one TLS connection buffers, outside the relay budget.
const TLS_BUFFER: usize = 16 * 1024;
/// How long client bytes after the response are still counted and dropped.
const DRAIN: Duration = Duration::from_secs(1);
// The lane's head bound and header deadline are §10's own.
const _: () = assert!(MAX_HEAD == Budgets::DEFAULT.max_header_bytes);
const _: () = assert!(HEADER_DEADLINE.as_nanos() == Budgets::DEFAULT.header_deadline.as_nanos());

struct ClientIo<'a> {
    prefix: &'a [u8],
    socket: &'a UnixStream,
    deadline: Instant,
}
impl Read for ClientIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.prefix.read(bytes)?;
        if n != 0 {
            return Ok(n);
        }
        self.socket
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.socket.read(bytes)
    }
}
impl Write for ClientIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"))
    } else {
        Ok(remaining)
    }
}

pub(super) struct Failure {
    pub reason: Reason,
    pub progress: RelayOutcome,
}

/// One connection through the lane: its two sockets, the destination its
/// certificate and credentials are bound to, the process that initiated it,
/// the client's first flight (read before the lane started) and the relay
/// buffer one direction owns.
pub(super) struct Connection<'a> {
    pub vault: &'a Vault,
    pub client: &'a Arc<UnixStream>,
    pub upstream: &'a Arc<TcpStream>,
    pub target: &'a Destination,
    pub initiator: &'a Initiator,
    pub early: &'a [u8],
    pub chunk: usize,
}

pub(super) fn relay(connection: &Connection<'_>) -> Result<RelayOutcome, Failure> {
    let mut progress = RelayOutcome {
        bytes_in: 0,
        bytes_out: 0,
        discarded: 0,
        end: EndReason::UpstreamClosed,
        head_sent: false,
        head_partial: false,
        credentials: Vec::new(),
        unconfirmed: Vec::new(),
    };
    match relay_inner(connection, &mut progress) {
        Ok(()) => Ok(progress),
        Err(reason) => {
            progress.end = if matches!(
                reason,
                Reason::CredentialRevoked
                    | Reason::CredentialProcessDenied
                    | Reason::CredentialProcessEnvDenied
                    | Reason::CredentialProcessUnverified
            ) {
                EndReason::CredentialRevoked
            } else if reason == Reason::ClientClosed {
                EndReason::ClientError
            } else {
                EndReason::UpstreamError
            };
            Err(Failure { reason, progress })
        }
    }
}

/// The client's side of the lane, decrypted: the first flight's bytes are
/// read before the socket.
type Incoming<'a> = rustls::StreamOwned<rustls::ServerConnection, ClientIo<'a>>;
/// The upstream's side of the lane, re-originated.
type Outgoing<'a> = rustls::StreamOwned<rustls::ClientConnection, &'a TcpStream>;

fn relay_inner(connection: &Connection<'_>, outcome: &mut RelayOutcome) -> Result<(), Reason> {
    let started = Instant::now();
    // One lifetime for the whole connection: every client phase, the pump
    // included, ends by it.
    let lifetime = started + CLIENT_DEADLINE;
    let mut incoming = terminate(connection, started + HEADER_DEADLINE)?;
    let (mut request, length) = read_request(&mut incoming, connection.target)?;
    let mut outgoing = originate(connection)?;
    let websocket_key = request.websocket_key().map(<[u8]>::to_vec);
    let lease = connection
        .vault
        .inject_bound("https", &mut request, connection.initiator)?;
    let lease = Arc::new(lease);
    let watch = crate::vault::lifecycle::Watch::start(
        lease.clone(),
        connection.client.clone(),
        connection.upstream.clone(),
    )?;
    incoming.sock.deadline = lifetime;
    lease.check()?;
    let forwarded = forward(
        &mut incoming,
        &mut outgoing,
        &mut request,
        length,
        connection.chunk,
        outcome,
    );
    // J13: once the substituted head reached the upstream whole, its
    // credentials were used, whatever happens to the body or the response;
    // a head that was begun and not confirmed whole may have carried them.
    outcome.attribute(lease.ids());
    forwarded?;
    let response = read_response(&mut outgoing, &watch, lifetime)?;
    let switched = response.starts_with(b"HTTP/1.1 101 ");
    if switched {
        // A switch nobody asked for is the upstream's protocol error.
        let key = websocket_key.as_deref().ok_or(Reason::UpstreamProtocol)?;
        verify_websocket(&response, key)?;
    }
    incoming
        .write_all(&response)
        .map_err(|_| Reason::ClientClosed)?;
    outcome.bytes_in += response.len() as u64;
    incoming.flush().map_err(|_| Reason::ClientClosed)?;
    let result = pump(
        incoming.conn,
        outgoing.conn,
        incoming.sock.socket,
        outgoing.sock,
        &watch,
        Lane {
            websocket: switched,
            chunk: connection.chunk,
            lifetime,
        },
        outcome,
    );
    connection
        .client
        .set_nonblocking(false)
        .map_err(|_| Reason::InternalError)?;
    connection
        .upstream
        .set_nonblocking(false)
        .map_err(|_| Reason::InternalError)?;
    let server = result?;
    finish(
        server,
        connection.client,
        lifetime,
        connection.chunk,
        outcome,
    );
    if watch.revoked() {
        outcome.end = EndReason::CredentialRevoked;
    }
    Ok(())
}

/// Terminates the client's TLS with a certificate for the destination,
/// reading the first flight before the socket, until `deadline`.
fn terminate<'a>(connection: &Connection<'a>, deadline: Instant) -> Result<Incoming<'a>, Reason> {
    let mut server = connection.vault.server(connection.target)?;
    server.set_buffer_limit(Some(TLS_BUFFER));
    let io = ClientIo {
        prefix: connection.early,
        socket: connection.client,
        deadline,
    };
    Ok(rustls::StreamOwned::new(server, io))
}

/// Reads the decrypted request head, bounded by [`MAX_HEAD`] and the
/// client's deadline, and parses it. Returns the request and its body's
/// length: the lane takes one request whose body has a declared length.
fn read_request(
    incoming: &mut Incoming<'_>,
    target: &Destination,
) -> Result<(http::Request, u64), Reason> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(Reason::HeaderTooLarge);
        }
        let mut byte = [0];
        incoming
            .read_exact(&mut byte)
            .map_err(|error| client_head_failure(&error))?;
        head.push(byte[0]);
    }
    let request = origin::http_request(&head, target, 443)?;
    head.zeroize();
    // Chunked uploads are explicitly unsupported in this minimal TLS lane;
    // never mistake an unframed body or pipeline for part of this request.
    let length = match request.framing {
        Framing::Empty => 0,
        Framing::Length(n) => n,
        _ => return Err(Reason::UnsupportedRequest),
    };
    // `Expect` is refused by header name at line start, not by substring:
    // a longer header name or a value containing "expect:" is none of this
    // lane's business.
    if http::lines(&request.forward_head)
        .filter_map(http::Line::field)
        .any(|(name, _)| name.eq_ignore_ascii_case(b"expect"))
    {
        return Err(Reason::UnsupportedRequest);
    }
    Ok((request, length))
}

/// Re-originates TLS to the upstream with certificate validation, under the
/// upstream I/O deadlines. The handshake completes, and the certificate is
/// verified, before any secret is released.
fn originate<'a>(connection: &Connection<'a>) -> Result<Outgoing<'a>, Reason> {
    let upstream: &'a TcpStream = connection.upstream;
    upstream
        .set_read_timeout(Some(UPSTREAM_IO))
        .map_err(|_| Reason::InternalError)?;
    upstream
        .set_write_timeout(Some(UPSTREAM_IO))
        .map_err(|_| Reason::InternalError)?;
    let mut outgoing =
        rustls::StreamOwned::new(connection.vault.client(connection.target)?, upstream);
    while outgoing.conn.is_handshaking() {
        outgoing
            .conn
            .complete_io(&mut outgoing.sock)
            .map_err(|_| Reason::UpstreamProtocol)?;
    }
    Ok(outgoing)
}

/// Sends the substituted request head, wiping it as soon as it is written,
/// then exactly `length` body bytes from the client, counting what reached
/// the upstream.
fn forward(
    incoming: &mut Incoming<'_>,
    outgoing: &mut Outgoing<'_>,
    request: &mut http::Request,
    length: u64,
    chunk: usize,
    outcome: &mut RelayOutcome,
) -> Result<(), Reason> {
    // From the first write on, part of the head may reach the upstream:
    // rustls writes records to the socket inside `write` and does not say
    // how many before an error.
    outcome.head_partial = true;
    let sent = outgoing.write_all(&request.forward_head);
    let head_bytes = request.forward_head.len() as u64;
    request.forward_head.zeroize();
    sent.map_err(|_| Reason::ConnectFailed)?;
    outgoing.flush().map_err(|_| Reason::ConnectFailed)?;
    outcome.bytes_out = head_bytes;
    outcome.head_sent = true;
    outcome.head_partial = false;
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; chunk.max(1)]);
    let mut remaining_body = length;
    while remaining_body != 0 {
        let n = buffer
            .len()
            .min(usize::try_from(remaining_body).unwrap_or(usize::MAX));
        incoming
            .read_exact(&mut buffer[..n])
            .map_err(|_| Reason::ClientClosed)?;
        outgoing
            .write_all(&buffer[..n])
            .map_err(|_| Reason::ConnectFailed)?;
        remaining_body -= n as u64;
        outgoing.flush().map_err(|_| Reason::ConnectFailed)?;
        outcome.bytes_out += n as u64;
    }
    outgoing.flush().map_err(|_| Reason::ConnectFailed)
}

/// Reads the upstream's response head, bounded by [`MAX_HEAD`], before
/// anything of it reaches the client, so no protocol switch is exposed
/// before it is checked. A revoked lease ends the wait. The loop is also
/// bounded by the lane's lifetime: each read may reset the 30s I/O timeout,
/// so a slow-dripping upstream must not hold the lane past §6.3's 300s.
fn read_response(
    outgoing: &mut Outgoing<'_>,
    watch: &crate::vault::lifecycle::Watch,
    lifetime: Instant,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Reason> {
    let mut response = zeroize::Zeroizing::new(Vec::new());
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_HEAD {
            return Err(Reason::HeaderTooLarge);
        }
        if watch.revoked() {
            return Err(Reason::CredentialRevoked);
        }
        // The per-read I/O timeout covers a silent upstream; the remaining
        // lifetime covers a dripping one: whichever ends first ends the
        // head.
        let remaining = lifetime.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // The lane's lifetime is spent; a zero timeout is not
            // portable, so end the head explicitly.
            return Err(Reason::ConnectFailed);
        }
        outgoing
            .sock
            .set_read_timeout(Some(UPSTREAM_IO.min(remaining)))
            .map_err(|_| Reason::InternalError)?;
        let mut byte = [0];
        outgoing
            .read_exact(&mut byte)
            .map_err(|_| Reason::ConnectFailed)?;
        response.push(byte[0]);
    }
    Ok(response)
}

/// Ends the client's side once the response is complete: its
/// `close_notify` first, then whatever the client still sends counted and
/// dropped for at most [`DRAIN`] within the lifetime.
fn finish(
    server: rustls::ServerConnection,
    client: &UnixStream,
    lifetime: Instant,
    chunk: usize,
    outcome: &mut RelayOutcome,
) {
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; chunk.max(1)]);
    let mut incoming = rustls::StreamOwned::new(
        server,
        ClientIo {
            prefix: &[],
            socket: client,
            deadline: (Instant::now() + DRAIN).min(lifetime),
        },
    );
    // The response is complete: say so first, so a client reading a
    // close-delimited body finishes now and one holding the connection open
    // sees it end, rather than either waiting out the drain below.
    incoming.conn.send_close_notify();
    let _ = incoming.flush();
    // Parity with the plain lanes' `discard_rest`: one request per
    // connection, so anything the client still sends is counted and dropped,
    // not vanished. Bounded to [`DRAIN`] past the response and by the
    // lifetime: counting must never hold the connection's teardown hostage to
    // a client that never stops sending. A client's own `close_notify` in
    // answer to ours ends it at once.
    incoming.sock.deadline = (Instant::now() + DRAIN).min(lifetime);
    loop {
        match incoming.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => outcome.discarded += n as u64,
            Err(_) => break,
        }
    }
}

/// Checks the upstream's `101` against RFC 6455 and the client's nonce.
/// Every failure is the upstream's: `upstream_protocol`.
fn verify_websocket(head: &[u8], key: &[u8]) -> Result<(), Reason> {
    use base64::Engine as _;
    use sha1::{Digest as _, Sha1};
    let utf8 = |bytes| std::str::from_utf8(bytes).map_err(|_| Reason::UpstreamProtocol);
    utf8(head)?;
    let mut fields = std::collections::HashMap::new();
    for (index, line) in http::lines(head).enumerate() {
        // Every line ends in CRLF; a bare LF anywhere refuses.
        if !line.0.ends_with(b"\r\n") {
            return Err(Reason::UpstreamProtocol);
        }
        if index == 0 || line.content().is_empty() {
            continue;
        }
        let (name, value) = line.field().ok_or(Reason::UpstreamProtocol)?;
        if !http::is_token(name) || value.iter().any(|&b| b < 0x20 && b != b'\t') {
            return Err(Reason::UpstreamProtocol);
        }
        if fields
            .insert(utf8(name)?.to_ascii_lowercase(), utf8(value)?.trim())
            .is_some()
        {
            return Err(Reason::UpstreamProtocol);
        }
    }
    let mut digest = Sha1::new();
    digest.update(key);
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = base64::engine::general_purpose::STANDARD.encode(digest.finalize());
    if fields
        .get("upgrade")
        .is_none_or(|v| !v.eq_ignore_ascii_case("websocket"))
        || fields.get("connection").is_none_or(|v| {
            !v.split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
        })
        || fields.get("sec-websocket-accept") != Some(&accept.as_str())
        || fields.contains_key("content-length")
        || fields.contains_key("transfer-encoding")
    {
        return Err(Reason::UpstreamProtocol);
    }
    Ok(())
}

/// Why reading the decrypted request head failed: the client's deadline,
/// or the client closing or failing its side of TLS.
fn client_head_failure(error: &io::Error) -> Reason {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Reason::HeaderTimeout,
        _ => Reason::ClientClosed,
    }
}

/// What one side of the pump waits for: room to write its pending records
/// while it can be given any, and records to read while it can take them. A
/// side with nothing asked of it is left out: a half-closed or failed peer
/// reports POLLHUP whether or not anything was requested, which would
/// otherwise spin.
fn interest<'a>(
    fd: BorrowedFd<'a>,
    conn: &rustls::Connection,
    can_give: bool,
    can_take: bool,
) -> sys::Interest<'a> {
    let mut events = 0;
    if can_give && conn.wants_write() {
        events |= libc::POLLOUT;
    }
    if can_take && conn.wants_read() {
        events |= libc::POLLIN;
    }
    (events != 0).then_some((fd, events))
}

/// What the pump relays, and until when.
struct Lane {
    /// Whether the upstream switched to a verified WebSocket: only then may
    /// the client's bytes reach it.
    websocket: bool,
    chunk: usize,
    /// The connection's lifetime, started with the lane.
    lifetime: Instant,
}

/// Whom one side's failures are put on.
struct Blame {
    /// The relay's end when writing this side's records fails.
    write: EndReason,
    /// The refusal when a record from this side does not decrypt.
    record: Reason,
}

impl Blame {
    const CLIENT: Blame = Blame {
        write: EndReason::ClientError,
        record: Reason::ClientClosed,
    };
    const DESTINATION: Blame = Blame {
        write: EndReason::UpstreamError,
        record: Reason::UpstreamProtocol,
    };
}

/// One side of the pump: its TLS connection and what the pump knows of it.
struct Side {
    conn: rustls::Connection,
    blame: Blame,
    /// Plaintext read from this side and not yet handed to the other.
    read: zeroize::Zeroizing<Vec<u8>>,
    /// The side's records ended: its peer closed, or reading or writing
    /// them failed.
    eof: bool,
    /// Writing to the side's socket failed: nothing more reaches it.
    failed: bool,
    /// Plaintext handed to this side's connection whose records have not
    /// all reached its socket yet; counted once they have.
    pending: u64,
}

/// What taking one side's decrypted plaintext found.
enum Plaintext {
    /// Bytes arrived.
    Read,
    /// The side's plaintext ended: its peer's `close_notify`, or a failure.
    Ended,
    /// Nothing is decrypted yet.
    Waiting,
    /// The buffer is full; nothing was taken.
    Full,
}

impl Side {
    fn new(conn: rustls::Connection, blame: Blame, limit: usize) -> Self {
        Side {
            conn,
            blame,
            read: zeroize::Zeroizing::new(Vec::with_capacity(limit)),
            eof: false,
            failed: false,
            pending: 0,
        }
    }

    /// Moves what the connection has decrypted into the buffer, up to
    /// `limit` bytes, records received before the pump included. With
    /// `discarded`, the bytes are counted there and wiped instead of kept.
    fn take_plaintext(&mut self, limit: usize, discarded: Option<&mut u64>) -> Plaintext {
        if self.read.len() >= limit {
            return Plaintext::Full;
        }
        let used = self.read.len();
        self.read.resize(limit, 0);
        let read = self.conn.reader().read(&mut self.read[used..]);
        let n = read.as_ref().ok().copied().unwrap_or(0);
        self.read.truncate(used + n);
        match read {
            Ok(0) => Plaintext::Ended,
            Ok(n) => {
                if let Some(discarded) = discarded {
                    *discarded += n as u64;
                    self.read[used..].zeroize();
                    self.read.truncate(used);
                }
                Plaintext::Read
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Plaintext::Waiting,
            Err(_) => Plaintext::Ended,
        }
    }

    /// Hands `plaintext` (the other side's) to this side's connection once
    /// its previous records are written, wiping what it took. Whether
    /// anything was taken.
    fn give_plaintext(
        &mut self,
        plaintext: &mut zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<bool, Reason> {
        if plaintext.is_empty() || self.conn.wants_write() {
            return Ok(false);
        }
        match self.conn.writer().write(plaintext) {
            Ok(n) => {
                self.pending += n as u64;
                plaintext[..n].zeroize();
                plaintext.drain(..n);
                Ok(n != 0)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(_) => Err(Reason::ConnectFailed),
        }
    }

    /// Moves records between the connection and `socket` as `revents`
    /// allows: pending records out, then new records in. A hang-up or an
    /// error with records pending is a write attempt too, so a peer that is
    /// gone fails the side instead of being polled for ever. Plaintext whose
    /// records all reached the socket is counted in `delivered`. A failed
    /// write ends the side and records its blame as the relay's `end`; a
    /// record that does not decrypt refuses with its blame.
    fn exchange<S>(
        &mut self,
        mut socket: &S,
        revents: libc::c_short,
        delivered: &mut u64,
        end: &mut EndReason,
    ) -> Result<(), Reason>
    where
        for<'s> &'s S: io::Read + io::Write,
    {
        let writable = revents & libc::POLLOUT != 0
            || revents & (libc::POLLHUP | libc::POLLERR) != 0 && self.conn.wants_write();
        if writable && !self.failed {
            let result = self.conn.write_tls(&mut socket);
            if result.is_ok() && !self.conn.wants_write() {
                *delivered += std::mem::take(&mut self.pending);
            }
            if result.is_err_and(|e| {
                e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::Interrupted
            }) {
                *end = self.blame.write;
                self.eof = true;
                self.failed = true;
            }
        }
        if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            && !self.eof
            && self.conn.wants_read()
        {
            match self.conn.read_tls(&mut socket) {
                Ok(0) => self.eof = true,
                Ok(_) => {
                    let record = self.blame.record;
                    let _state = self.conn.process_new_packets().map_err(|_| record)?;
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => self.eof = true,
            }
        }
        Ok(())
    }
}

// Two nonblocking TLS state machines, bounded plaintext buffers, the
// connection's one absolute lifetime. Only a verified RFC6455 switch enables
// client-to-upstream traffic.
fn pump(
    server: rustls::ServerConnection,
    upstream: rustls::ClientConnection,
    socket: &UnixStream,
    remote: &TcpStream,
    watch: &crate::vault::lifecycle::Watch,
    lane: Lane,
    outcome: &mut RelayOutcome,
) -> Result<rustls::ServerConnection, Reason> {
    let Lane {
        websocket,
        chunk,
        lifetime,
    } = lane;
    let limit = chunk.clamp(1, TLS_BUFFER);
    let mut client = Side::new(rustls::Connection::Server(server), Blame::CLIENT, limit);
    let mut destination = Side::new(
        rustls::Connection::Client(upstream),
        Blame::DESTINATION,
        limit,
    );
    client.conn.set_buffer_limit(Some(TLS_BUFFER));
    destination.conn.set_buffer_limit(Some(TLS_BUFFER));
    socket
        .set_nonblocking(true)
        .map_err(|_| Reason::InternalError)?;
    remote
        .set_nonblocking(true)
        .map_err(|_| Reason::InternalError)?;
    // The upstream's plaintext is all taken: it ended, and nothing of it is
    // left in its connection.
    let mut upstream_drained = false;
    let mut sent_close = false;
    loop {
        if watch.revoked() {
            outcome.end = EndReason::CredentialRevoked;
            break;
        }
        // The proxy's own cap, not anything the upstream did.
        if Instant::now() >= lifetime {
            outcome.end = EndReason::Deadline;
            break;
        }
        // Outside a WebSocket the client may send the upstream nothing more:
        // its bytes are counted and dropped.
        let discarded = (!websocket).then_some(&mut outcome.discarded);
        let mut progress = match client.take_plaintext(limit, discarded) {
            Plaintext::Read => true,
            Plaintext::Ended => {
                client.eof = true;
                false
            }
            Plaintext::Waiting | Plaintext::Full => false,
        };
        match destination.take_plaintext(limit, None) {
            Plaintext::Read => progress = true,
            Plaintext::Ended => {
                destination.eof = true;
                upstream_drained = true;
            }
            Plaintext::Waiting => upstream_drained |= destination.eof,
            Plaintext::Full => {}
        }
        progress |= destination.give_plaintext(&mut client.read)?;
        progress |= client.give_plaintext(&mut destination.read)?;
        if upstream_drained && destination.read.is_empty() && !sent_close {
            client.conn.send_close_notify();
            sent_close = true;
        }
        if sent_close && !client.conn.wants_write() {
            break;
        }
        if websocket && client.eof && client.read.is_empty() {
            destination.conn.send_close_notify();
        }
        // The wait between revocation checks is the lease poll.
        let revents = match sys::poll(
            &[
                interest(
                    socket.as_fd(),
                    &client.conn,
                    !client.failed,
                    !client.eof && client.read.len() < limit,
                ),
                interest(
                    remote.as_fd(),
                    &destination.conn,
                    !destination.failed,
                    !destination.eof && destination.read.len() < limit,
                ),
            ],
            Some(if progress {
                Duration::ZERO
            } else {
                crate::vault::lifecycle::LEASE_POLL
            }),
        ) {
            Ok(revents) => revents,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Reason::InternalError),
        };
        client.exchange(socket, revents[0], &mut outcome.bytes_in, &mut outcome.end)?;
        destination.exchange(remote, revents[1], &mut outcome.bytes_out, &mut outcome.end)?;
        // Nothing more can reach a client whose socket failed: the lane
        // ends now, blamed on the client, rather than at its lifetime.
        if client.failed {
            break;
        }
    }
    let rustls::Connection::Server(server) = client.conn else {
        return Err(Reason::InternalError);
    };
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn websocket_response_is_bound_to_the_request_nonce_and_protocol() {
        let key = b"dGhlIHNhbXBsZSBub25jZQ==";
        let valid=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        assert!(verify_websocket(valid, key).is_ok());
        assert_eq!(
            verify_websocket(valid, b"wrong"),
            Err(Reason::UpstreamProtocol)
        );
        for extra in [
            "Content-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Sec-WebSocket-Accept: forged\r\n",
            "X-Bare: lf\nX-Other: 1\r\n",
            "X-Bare-Cr: a\rb\r\n",
            "Bad Name: 1\r\n",
            "NoColon\r\n",
        ] {
            let mut bad = valid[..valid.len() - 2].to_vec();
            bad.extend_from_slice(extra.as_bytes());
            bad.extend_from_slice(b"\r\n");
            assert_eq!(verify_websocket(&bad, key), Err(Reason::UpstreamProtocol));
        }
    }

    /// J13: `head_sent` is set only once the substituted head was written
    /// and flushed; a head whose write began and failed may have left in
    /// part, so it is `head_partial`, never sent.
    #[test]
    fn a_head_the_upstream_did_not_take_is_not_sent() {
        use std::sync::Arc;
        let vault = crate::vault::Vault::new("test-attempt", Vec::new()).unwrap();
        let target = crate::network::parse_authority("fixture.test:443", None).unwrap();
        let (socket, _client) = UnixStream::pair().unwrap();
        let socket = Arc::new(socket);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _accepted = listener.accept().unwrap();
        remote.shutdown(std::net::Shutdown::Write).unwrap();
        let mut incoming = rustls::StreamOwned::new(
            vault.server(&target).unwrap(),
            ClientIo {
                prefix: b"",
                socket: &socket,
                deadline: Instant::now() + Duration::from_secs(5),
            },
        );
        let mut outgoing = rustls::StreamOwned::new(vault.client(&target).unwrap(), &remote);
        let mut request = crate::proxy::http::parse_request(
            b"GET http://fixture.test:443/ HTTP/1.1\r\nHost: fixture.test:443\r\n\r\n",
        )
        .unwrap();
        let mut outcome = RelayOutcome {
            bytes_in: 0,
            bytes_out: 0,
            discarded: 0,
            end: EndReason::UpstreamClosed,
            head_sent: false,
            head_partial: false,
            credentials: Vec::new(),
            unconfirmed: Vec::new(),
        };
        let forwarded = forward(
            &mut incoming,
            &mut outgoing,
            &mut request,
            0,
            64,
            &mut outcome,
        );
        assert!(forwarded.is_err());
        assert!(!outcome.head_sent);
        assert!(outcome.head_partial);
    }

    #[test]
    fn the_pump_ends_at_the_connection_lifetime_and_says_so() {
        use std::sync::Arc;
        let vault = crate::vault::Vault::new("test-attempt", Vec::new()).unwrap();
        let target = crate::network::parse_authority("fixture.test:443", None).unwrap();
        let (socket, _client) = UnixStream::pair().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        // The upstream is gone too, so a pump that ignored the lifetime
        // would end on that instead, blaming the upstream.
        drop(listener.accept().unwrap());
        let (socket, remote) = (Arc::new(socket), Arc::new(remote));
        let watch = crate::vault::lifecycle::Watch::start(
            Arc::new(crate::vault::lifecycle::Lease::default()),
            Arc::clone(&socket),
            Arc::clone(&remote),
        )
        .unwrap();
        let mut outcome = RelayOutcome {
            bytes_in: 0,
            bytes_out: 0,
            discarded: 0,
            end: EndReason::UpstreamClosed,
            head_sent: false,
            head_partial: false,
            credentials: Vec::new(),
            unconfirmed: Vec::new(),
        };
        let pumped = pump(
            vault.server(&target).unwrap(),
            vault.client(&target).unwrap(),
            &socket,
            &remote,
            &watch,
            Lane {
                websocket: false,
                chunk: 1024,
                lifetime: Instant::now(),
            },
            &mut outcome,
        );
        assert!(pumped.is_ok());
        assert_eq!(outcome.end, EndReason::Deadline);
    }

    /// Runs the pump, for at most [`PUMP_TEST_LIFETIME`], over fresh TLS
    /// connections: the lane's server side on a socket pair, whose other end
    /// `client` gets, and its client side on a loopback TCP connection,
    /// whose accepted end `destination` gets. Each returns its end to keep
    /// it open, or `None` once it closed it. Returns what the pump returned,
    /// its outcome and how long it ran.
    fn pump_against(
        client: impl FnOnce(UnixStream) -> Option<UnixStream>,
        destination: impl FnOnce(TcpStream) -> Option<TcpStream>,
    ) -> (Result<(), Reason>, RelayOutcome, Duration) {
        use std::sync::Arc;
        let vault = crate::vault::Vault::new("test-attempt", Vec::new()).unwrap();
        let target = crate::network::parse_authority("fixture.test:443", None).unwrap();
        let (socket, client_end) = UnixStream::pair().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (destination_end, _) = listener.accept().unwrap();
        let kept = (client(client_end), destination(destination_end));
        let (socket, remote) = (Arc::new(socket), Arc::new(remote));
        let watch = crate::vault::lifecycle::Watch::start(
            Arc::new(crate::vault::lifecycle::Lease::default()),
            Arc::clone(&socket),
            Arc::clone(&remote),
        )
        .unwrap();
        let mut outcome = RelayOutcome {
            bytes_in: 0,
            bytes_out: 0,
            discarded: 0,
            end: EndReason::UpstreamClosed,
            head_sent: false,
            head_partial: false,
            credentials: Vec::new(),
            unconfirmed: Vec::new(),
        };
        let started = Instant::now();
        let pumped = pump(
            vault.server(&target).unwrap(),
            vault.client(&target).unwrap(),
            &socket,
            &remote,
            &watch,
            Lane {
                websocket: false,
                chunk: 1024,
                lifetime: started + PUMP_TEST_LIFETIME,
            },
            &mut outcome,
        )
        .map(drop);
        let ran = started.elapsed();
        drop(kept);
        (pumped, outcome, ran)
    }

    /// The lifetime [`pump_against`] gives the pump: far longer than any
    /// case needs, so ending at it is a failure to end on the cause.
    const PUMP_TEST_LIFETIME: Duration = Duration::from_secs(5);

    /// A slow-dripping upstream — every byte well within the 30s I/O
    /// timeout — must not hold the response head past the lane's lifetime:
    /// each read resets the I/O timeout, so only the lifetime bounds it.
    #[test]
    fn a_dripping_upstream_ends_the_response_head_at_the_lifetime() {
        use std::sync::Arc;
        let vault = crate::vault::Vault::new("test-attempt", Vec::new()).unwrap();
        let target = crate::network::parse_authority("fixture.test:443", None).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let upstream_end = listener.accept().unwrap().0;
        let (watch_socket, watch_peer) = UnixStream::pair().unwrap();
        let watch = crate::vault::lifecycle::Watch::start(
            Arc::new(crate::vault::lifecycle::Lease::default()),
            Arc::new(watch_socket),
            Arc::new(remote.try_clone().unwrap()),
        )
        .unwrap();
        let server_conn = vault.server(&target).unwrap();
        // The upstream handshakes and then drips one byte at a time, never
        // completing the `\r\n\r\n`.
        let dripper = std::thread::spawn(move || {
            let mut server = rustls::StreamOwned::new(server_conn, upstream_end);
            while server.conn.is_handshaking() {
                if server.conn.complete_io(&mut server.sock).is_err() {
                    return;
                }
            }
            loop {
                if server
                    .write_all(b"\r")
                    .and_then(|_| server.flush())
                    .is_err()
                {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        remote.set_read_timeout(Some(UPSTREAM_IO)).unwrap();
        let mut outgoing = rustls::StreamOwned::new(vault.client(&target).unwrap(), &remote);
        let lifetime = Instant::now() + Duration::from_millis(300);
        let started = Instant::now();
        let result = read_response(&mut outgoing, &watch, lifetime);
        // Close the client side so the dripper's next write fails and the
        // thread ends.
        drop(outgoing);
        drop(remote);
        let _ = dripper.join();
        drop(watch_peer);
        assert_eq!(result.unwrap_err(), Reason::ConnectFailed);
        // Ended on the lifetime, not on any 30-second read timeout.
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_record_that_does_not_decrypt_is_blamed_on_the_side_that_sent_it() {
        let corrupt = b"not a TLS record\r\n";
        let (pumped, _, ran) = pump_against(
            |mut client| {
                client.write_all(corrupt).unwrap();
                Some(client)
            },
            Some,
        );
        assert_eq!(pumped, Err(Reason::ClientClosed));
        assert!(ran < PUMP_TEST_LIFETIME);
        let (pumped, _, ran) = pump_against(Some, |mut destination| {
            destination.write_all(corrupt).unwrap();
            Some(destination)
        });
        assert_eq!(pumped, Err(Reason::UpstreamProtocol));
        assert!(ran < PUMP_TEST_LIFETIME);
    }

    /// A client that is gone while the lane has records for it (here the
    /// answer to its ClientHello) ends the pump at once, blamed on the
    /// client: nothing can reach it any more, so waiting out the lifetime
    /// would only spin on its failed socket and then blame the deadline.
    #[test]
    fn a_client_gone_with_records_pending_ends_the_pump_and_is_blamed() {
        let (pumped, outcome, ran) = pump_against(
            |mut client| {
                let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
                let mut hello = rustls::ClientConnection::new(
                    std::sync::Arc::new(config),
                    rustls::pki_types::ServerName::try_from("fixture.test").unwrap(),
                )
                .unwrap();
                let mut bytes = Vec::new();
                hello.write_tls(&mut bytes).unwrap();
                client.write_all(&bytes).unwrap();
                None
            },
            Some,
        );
        assert_eq!(pumped, Ok(()));
        assert_eq!(outcome.end, EndReason::ClientError);
        assert!(ran < PUMP_TEST_LIFETIME / 2, "{ran:?}");
    }

    /// A destination that reset before the lane's ClientHello reached it is
    /// the upstream's failure, and the pump ends without waiting out the
    /// lifetime.
    #[test]
    fn a_destination_write_failure_is_blamed_on_the_upstream() {
        let (pumped, outcome, ran) = pump_against(Some, |destination| {
            use std::os::fd::AsRawFd as _;
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: `linger` is a valid `linger` of the size passed, and
            // the descriptor belongs to `destination`, open for the call.
            let rc = unsafe {
                libc::setsockopt(
                    destination.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&raw const linger).cast(),
                    libc::socklen_t::try_from(std::mem::size_of::<libc::linger>()).unwrap(),
                )
            };
            assert_eq!(rc, 0, "{}", io::Error::last_os_error());
            // Closed with a zero linger: the connection is reset.
            None
        });
        assert_eq!(pumped, Ok(()));
        assert_eq!(outcome.end, EndReason::UpstreamError);
        assert!(ran < PUMP_TEST_LIFETIME / 2, "{ran:?}");
    }

    #[test]
    fn a_failed_client_head_blames_the_deadline_or_the_client() {
        for (kind, reason) in [
            (io::ErrorKind::TimedOut, Reason::HeaderTimeout),
            (io::ErrorKind::WouldBlock, Reason::HeaderTimeout),
            (io::ErrorKind::UnexpectedEof, Reason::ClientClosed),
            (io::ErrorKind::ConnectionReset, Reason::ClientClosed),
            (io::ErrorKind::InvalidData, Reason::ClientClosed),
        ] {
            assert_eq!(client_head_failure(&kind.into()), reason, "{kind:?}");
        }
    }
}
