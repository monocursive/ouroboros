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
use crate::{network::Destination, vault::Vault};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
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
pub(super) fn relay(
    vault: &Vault,
    client: &std::sync::Arc<UnixStream>,
    upstream: &std::sync::Arc<TcpStream>,
    target: &Destination,
    early: &[u8],
    chunk: usize,
    initiator: &crate::vault::origin::Initiator,
) -> Result<RelayOutcome, Failure> {
    let mut progress = RelayOutcome {
        bytes_in: 0,
        bytes_out: 0,
        discarded: 0,
        end: EndReason::UpstreamClosed,
    };
    match relay_inner(
        vault,
        client,
        upstream,
        (target, initiator),
        early,
        chunk,
        &mut progress,
    ) {
        Ok(()) => Ok(progress),
        Err(reason) => {
            progress.end = if matches!(
                reason,
                Reason::CredentialRevoked
                    | Reason::CredentialProcessDenied
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

fn relay_inner(
    vault: &Vault,
    client: &std::sync::Arc<UnixStream>,
    upstream: &std::sync::Arc<TcpStream>,
    authority: (&Destination, &crate::vault::origin::Initiator),
    early: &[u8],
    chunk: usize,
    outcome: &mut RelayOutcome,
) -> Result<(), Reason> {
    let (target, initiator) = authority;
    let started = Instant::now();
    // One lifetime for the whole connection: every client phase, the pump
    // included, ends by it.
    let lifetime = started + CLIENT_DEADLINE;
    let mut server = vault.server(target)?;
    server.set_buffer_limit(Some(TLS_BUFFER));
    let io = ClientIo {
        prefix: early,
        socket: client,
        deadline: started + HEADER_DEADLINE,
    };
    let mut incoming = rustls::StreamOwned::new(server, io);
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
    let mut request = origin::http_request(&head, target, 443)?;
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
    upstream
        .set_read_timeout(Some(UPSTREAM_IO))
        .map_err(|_| Reason::InternalError)?;
    upstream
        .set_write_timeout(Some(UPSTREAM_IO))
        .map_err(|_| Reason::InternalError)?;
    let mut outgoing = rustls::StreamOwned::new(vault.client(target)?, &**upstream);
    // Complete and verify the upstream handshake before releasing any secret.
    while outgoing.conn.is_handshaking() {
        outgoing
            .conn
            .complete_io(&mut outgoing.sock)
            .map_err(|_| Reason::UpstreamProtocol)?;
    }
    let websocket_key = request.websocket_key().map(|key| key.to_vec());
    let lease = vault.inject_bound("https", &mut request, initiator)?;
    let lease = std::sync::Arc::new(lease);
    let watch =
        crate::vault::lifecycle::Watch::start(lease.clone(), client.clone(), upstream.clone())?;
    incoming.sock.deadline = lifetime;
    lease.check()?;
    let sent = outgoing.write_all(&request.forward_head);
    let head_bytes = request.forward_head.len() as u64;
    request.forward_head.zeroize();
    sent.map_err(|_| Reason::ConnectFailed)?;
    outgoing.flush().map_err(|_| Reason::ConnectFailed)?;
    outcome.bytes_out = head_bytes;
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
    outgoing.flush().map_err(|_| Reason::ConnectFailed)?;
    // Read a bounded response head before exposing any protocol switch.
    let mut response = zeroize::Zeroizing::new(Vec::new());
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_HEAD {
            return Err(Reason::HeaderTooLarge);
        }
        if watch.revoked() {
            return Err(Reason::CredentialRevoked);
        }
        let mut byte = [0];
        outgoing
            .read_exact(&mut byte)
            .map_err(|_| Reason::ConnectFailed)?;
        response.push(byte[0]);
    }
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
    let (server, client_io) = (incoming.conn, incoming.sock);
    let (client_conn, socket) = (outgoing.conn, outgoing.sock);
    drop(buffer);
    let result = pump(
        server,
        client_conn,
        client_io.socket,
        socket,
        &watch,
        Lane {
            websocket: switched,
            chunk,
            lifetime,
        },
        outcome,
    );
    client
        .set_nonblocking(false)
        .map_err(|_| Reason::InternalError)?;
    upstream
        .set_nonblocking(false)
        .map_err(|_| Reason::InternalError)?;
    let server = result?;
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
    if watch.revoked() {
        outcome.end = EndReason::CredentialRevoked;
    }
    Ok(())
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

/// What one side of the pump waits for: room to write its pending records,
/// and records to read while it can take them. A side with nothing asked of
/// it is left out: a half-closed peer reports POLLHUP whether or not
/// anything was requested, which would otherwise spin.
fn interest<'a>(
    fd: BorrowedFd<'a>,
    conn: &rustls::Connection,
    can_take: bool,
) -> sys::Interest<'a> {
    let mut events = 0;
    if conn.wants_write() {
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
    let mut incoming = rustls::Connection::Server(server);
    let mut outgoing = rustls::Connection::Client(upstream);
    incoming.set_buffer_limit(Some(TLS_BUFFER));
    outgoing.set_buffer_limit(Some(TLS_BUFFER));
    socket
        .set_nonblocking(true)
        .map_err(|_| Reason::InternalError)?;
    remote
        .set_nonblocking(true)
        .map_err(|_| Reason::InternalError)?;
    let mut up = zeroize::Zeroizing::new(Vec::with_capacity(limit));
    let mut down = zeroize::Zeroizing::new(Vec::with_capacity(limit));
    let mut client_eof = false;
    let mut upstream_eof = false;
    let mut upstream_drained = false;
    let mut sent_close = false;
    let mut pending_out = 0u64;
    let mut pending_in = 0u64;
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
        let mut progress = false;
        // Read decrypted pending bytes, including records received before the pump.
        for (index, (conn, buffer, eof, count_discard)) in [
            (&mut incoming, &mut up, &mut client_eof, !websocket),
            (&mut outgoing, &mut down, &mut upstream_eof, false),
        ]
        .into_iter()
        .enumerate()
        {
            if buffer.len() < limit {
                let used = buffer.len();
                buffer.resize(limit, 0);
                let read = conn.reader().read(&mut buffer[used..]);
                let n = read.as_ref().ok().copied().unwrap_or(0);
                buffer.truncate(used + n);
                match read {
                    Ok(0) => {
                        *eof = true;
                        if index == 1 {
                            upstream_drained = true;
                        }
                    }
                    Ok(n) => {
                        progress = true;
                        if count_discard {
                            outcome.discarded += n as u64;
                            buffer[used..].zeroize();
                            buffer.truncate(used);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if index == 1 && *eof {
                            upstream_drained = true;
                        }
                    }
                    Err(_) => {
                        *eof = true;
                        if index == 1 {
                            upstream_drained = true;
                        }
                    }
                }
            }
        }
        for (conn, buffer, count) in [
            (&mut outgoing, &mut up, &mut pending_out),
            (&mut incoming, &mut down, &mut pending_in),
        ] {
            if !buffer.is_empty() && !conn.wants_write() {
                match conn.writer().write(buffer) {
                    Ok(n) => {
                        progress |= n != 0;
                        *count += n as u64;
                        buffer[..n].zeroize();
                        buffer.drain(..n);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(Reason::ConnectFailed),
                }
            }
        }
        if upstream_drained && down.is_empty() && !sent_close {
            incoming.send_close_notify();
            sent_close = true;
        }
        if sent_close && !incoming.wants_write() {
            break;
        }
        if websocket && client_eof && up.is_empty() {
            outgoing.send_close_notify();
        }
        // The wait between revocation checks is the lease poll.
        let revents = match sys::poll(
            &[
                interest(socket.as_fd(), &incoming, !client_eof && up.len() < limit),
                interest(
                    remote.as_fd(),
                    &outgoing,
                    !upstream_eof && down.len() < limit,
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
        for (index, conn, eof) in [
            (0, &mut incoming, &mut client_eof),
            (1, &mut outgoing, &mut upstream_eof),
        ] {
            let flags = revents[index];
            if flags & libc::POLLOUT != 0 {
                let result = if index == 0 {
                    conn.write_tls(&mut &*socket)
                } else {
                    conn.write_tls(&mut &*remote)
                };
                if result.is_ok() && !conn.wants_write() {
                    if index == 0 {
                        outcome.bytes_in += pending_in;
                        pending_in = 0;
                    } else {
                        outcome.bytes_out += pending_out;
                        pending_out = 0;
                    }
                }
                if result.is_err_and(|e| {
                    e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::Interrupted
                }) {
                    outcome.end = if index == 0 {
                        EndReason::ClientError
                    } else {
                        EndReason::UpstreamError
                    };
                    *eof = true;
                }
            }
            if flags & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                && !*eof
                && conn.wants_read()
            {
                let result = if index == 0 {
                    conn.read_tls(&mut &*socket)
                } else {
                    conn.read_tls(&mut &*remote)
                };
                match result {
                    Ok(0) => *eof = true,
                    Ok(_) => {
                        let _state = conn.process_new_packets().map_err(|_| {
                            if index == 0 {
                                Reason::ClientClosed
                            } else {
                                Reason::UpstreamProtocol
                            }
                        })?;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => *eof = true,
                }
            }
        }
    }
    let rustls::Connection::Server(server) = incoming else {
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
