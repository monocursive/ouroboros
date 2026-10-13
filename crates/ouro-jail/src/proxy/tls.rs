//! One HTTP/1.1 request per TLS connection. No opaque forwarding in vault mode.
use super::{EndReason, Reason, http::Framing, origin, relay::RelayOutcome};
use crate::{network::Destination, vault::Vault};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

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
    process: Option<&crate::vault::origin::Process>,
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
        (target, process),
        early,
        chunk,
        &mut progress,
    ) {
        Ok(()) => Ok(progress),
        Err(reason) => {
            progress.end = if matches!(
                reason,
                Reason::CredentialRevoked | Reason::CredentialProcessDenied
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
    authority: (&Destination, Option<&crate::vault::origin::Process>),
    early: &[u8],
    chunk: usize,
    outcome: &mut RelayOutcome,
) -> Result<(), Reason> {
    let (target, process) = authority;
    let mut server = vault.server(target)?;
    server.set_buffer_limit(Some(16 * 1024));
    let io = ClientIo {
        prefix: early,
        socket: client,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    let mut incoming = rustls::StreamOwned::new(server, io);
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 32 * 1024 {
            return Err(Reason::HeaderTooLarge);
        }
        let mut byte = [0];
        incoming
            .read_exact(&mut byte)
            .map_err(|_| Reason::OriginUnverified)?;
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
    for line in request.forward_head.split_inclusive(|b| *b == b'\n') {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"expect") {
            return Err(Reason::UnsupportedRequest);
        }
    }
    upstream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| Reason::InternalError)?;
    upstream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| Reason::InternalError)?;
    let mut outgoing = rustls::StreamOwned::new(vault.client(target)?, &**upstream);
    // Complete and verify the upstream handshake before releasing any secret.
    while outgoing.conn.is_handshaking() {
        outgoing
            .conn
            .complete_io(&mut outgoing.sock)
            .map_err(|_| Reason::OriginUnverified)?;
    }
    let websocket_key = request.websocket_key().map(|key| key.to_vec());
    let lease = vault.inject_bound("https", &mut request, process)?;
    let lease = std::sync::Arc::new(lease);
    let watch =
        crate::vault::lifecycle::Watch::start(lease.clone(), client.clone(), upstream.clone())?;
    incoming.sock.deadline = Instant::now() + Duration::from_secs(300);
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
        if response.len() >= 32 * 1024 {
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
        let key = websocket_key.as_deref().ok_or(Reason::UnsupportedRequest)?;
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
        (switched, chunk),
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
            deadline: Instant::now() + Duration::from_secs(1),
        },
    );
    // The response is complete: say so first, so a client reading a
    // close-delimited body finishes now and one holding the connection open
    // sees it end, rather than either waiting out the drain below.
    incoming.conn.send_close_notify();
    let _ = incoming.flush();
    // Security 2026-09-29 (audit 6 N3): parity with the plain lanes'
    // `discard_rest` — one request per connection, so anything the client
    // still sends is counted and dropped, not vanished. Bounded to one
    // second past the response: counting must never hold the connection's
    // teardown hostage to a client that never stops sending. A client's own
    // `close_notify` in answer to ours ends it at once.
    incoming.sock.deadline = Instant::now() + Duration::from_secs(1);
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

fn verify_websocket(head: &[u8], key: &[u8]) -> Result<(), Reason> {
    use base64::Engine as _;
    use sha1::{Digest as _, Sha1};
    let text = std::str::from_utf8(head).map_err(|_| Reason::MalformedRequest)?;
    let mut fields = std::collections::HashMap::new();
    for line in text.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(Reason::MalformedRequest)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 0x20 && b != b'\t')
        {
            return Err(Reason::MalformedRequest);
        }
        if fields
            .insert(name.to_ascii_lowercase(), value.trim())
            .is_some()
        {
            return Err(Reason::MalformedRequest);
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
        return Err(Reason::OriginUnverified);
    }
    Ok(())
}

// Two nonblocking TLS state machines, bounded plaintext buffers, one absolute
// lifetime. Only a verified RFC6455 switch enables client-to-upstream traffic.
fn pump(
    server: rustls::ServerConnection,
    upstream: rustls::ClientConnection,
    socket: &UnixStream,
    remote: &TcpStream,
    watch: &crate::vault::lifecycle::Watch,
    mode: (bool, usize),
    outcome: &mut RelayOutcome,
) -> Result<rustls::ServerConnection, Reason> {
    use std::os::fd::AsRawFd as _;
    let (websocket, chunk) = mode;
    let limit = chunk.clamp(1, 16384);
    let mut incoming = rustls::Connection::Server(server);
    let mut outgoing = rustls::Connection::Client(upstream);
    incoming.set_buffer_limit(Some(16384));
    outgoing.set_buffer_limit(Some(16384));
    socket
        .set_nonblocking(true)
        .map_err(|_| Reason::InternalError)?;
    remote
        .set_nonblocking(true)
        .map_err(|_| Reason::InternalError)?;
    let deadline = Instant::now() + Duration::from_secs(300);
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
        if Instant::now() >= deadline {
            outcome.end = EndReason::UpstreamError;
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
        let mut fds = [
            libc::pollfd {
                fd: if (client_eof || !incoming.wants_read() || up.len() >= limit)
                    && !incoming.wants_write()
                {
                    -1
                } else {
                    socket.as_raw_fd()
                },
                events: if incoming.wants_write() {
                    libc::POLLOUT
                } else {
                    0
                } | if !client_eof && incoming.wants_read() && up.len() < limit {
                    libc::POLLIN
                } else {
                    0
                },
                revents: 0,
            },
            libc::pollfd {
                fd: if (upstream_eof || !outgoing.wants_read() || down.len() >= limit)
                    && !outgoing.wants_write()
                {
                    -1
                } else {
                    remote.as_raw_fd()
                },
                events: if outgoing.wants_write() {
                    libc::POLLOUT
                } else {
                    0
                } | if !upstream_eof && outgoing.wants_read() && down.len() < limit {
                    libc::POLLIN
                } else {
                    0
                },
                revents: 0,
            },
        ];
        // SAFETY: two initialized pollfds, bounded lease-check interval.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, if progress { 0 } else { 100 }) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Reason::InternalError);
        }
        for (index, conn, eof) in [
            (0, &mut incoming, &mut client_eof),
            (1, &mut outgoing, &mut upstream_eof),
        ] {
            let flags = fds[index].revents;
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
                        let _state = conn
                            .process_new_packets()
                            .map_err(|_| Reason::OriginUnverified)?;
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
mod websocket_tests {
    use super::*;
    #[test]
    fn websocket_response_is_bound_to_the_request_nonce_and_protocol() {
        let key = b"dGhlIHNhbXBsZSBub25jZQ==";
        let valid=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        assert!(verify_websocket(valid, key).is_ok());
        assert!(verify_websocket(valid, b"wrong").is_err());
        for extra in [
            "Content-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Sec-WebSocket-Accept: forged\r\n",
        ] {
            let mut bad = valid[..valid.len() - 2].to_vec();
            bad.extend_from_slice(extra.as_bytes());
            bad.extend_from_slice(b"\r\n");
            assert!(verify_websocket(&bad, key).is_err());
        }
    }
}
