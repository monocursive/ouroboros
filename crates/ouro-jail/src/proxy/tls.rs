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

pub(super) fn relay(
    vault: &Vault,
    client: &UnixStream,
    upstream: &TcpStream,
    target: &Destination,
    early: &[u8],
    chunk: usize,
) -> Result<RelayOutcome, Reason> {
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
    if request
        .forward_head
        .windows(7)
        .any(|s| s.eq_ignore_ascii_case(b"expect:"))
    {
        return Err(Reason::UnsupportedRequest);
    }
    upstream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| Reason::InternalError)?;
    upstream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| Reason::InternalError)?;
    let mut outgoing = rustls::StreamOwned::new(vault.client(target)?, upstream);
    // Complete and verify the upstream handshake before releasing any secret.
    while outgoing.conn.is_handshaking() {
        outgoing
            .conn
            .complete_io(&mut outgoing.sock)
            .map_err(|_| Reason::OriginUnverified)?;
    }
    vault.inject("https", &mut request)?;
    incoming.sock.deadline = Instant::now() + Duration::from_secs(300);
    let sent = outgoing.write_all(&request.forward_head);
    let mut bytes_out = request.forward_head.len() as u64;
    request.forward_head.zeroize();
    sent.map_err(|_| Reason::ConnectFailed)?;
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
        bytes_out += n as u64;
    }
    outgoing.flush().map_err(|_| Reason::ConnectFailed)?;
    let mut outcome = RelayOutcome {
        bytes_in: 0,
        bytes_out,
        discarded: 0,
        end: EndReason::UpstreamClosed,
    };
    loop {
        let n = match outgoing.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                outcome.end = EndReason::UpstreamError;
                break;
            }
        };
        if incoming.write_all(&buffer[..n]).is_err() {
            outcome.end = EndReason::ClientError;
            break;
        }
        outcome.bytes_in += n as u64;
    }
    incoming.conn.send_close_notify();
    let _ = incoming.flush();
    Ok(outcome)
}
