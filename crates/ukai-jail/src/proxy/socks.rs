//! RFC 1928 CONNECT only. DNS resolution remains in the shared proxy policy.
use super::{Reason, Transport};
use crate::network::{Destination, Host, normalize_host};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// The protocol version byte that starts every SOCKS5 message.
const VERSION: u8 = 5;
/// The one authentication method offered: none.
const NO_AUTHENTICATION: u8 = 0;
/// The method answer when the client offers no acceptable method.
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
/// Commands (RFC 1928 §4).
const CONNECT: u8 = 1;
const BIND: u8 = 2;
/// Address types (RFC 1928 §5).
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;

/// The reply codes the proxy sends (RFC 1928 §6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reply {
    Succeeded = 0,
    GeneralFailure = 1,
    NotAllowed = 2,
    ConnectionRefused = 5,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

/// Which protocol the client speaks, judged by its first byte without
/// consuming it. `Ok(None)`: it closed without sending one.
pub fn detect(stream: &UnixStream, deadline: Instant) -> Result<Option<Transport>, Reason> {
    stream
        .set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(std::time::Duration::from_millis(1)),
        ))
        .map_err(|_| Reason::InternalError)?;
    let mut byte = 0u8;
    // MSG_PEEK selects the protocol without consuming HTTP's request byte.
    let n = loop {
        // SAFETY: `byte` is a writable one-byte buffer that outlives the
        // call, the length passed is 1, and the descriptor belongs to
        // `stream`, which is borrowed (open) for the call.
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                (&raw mut byte).cast(),
                1,
                libc::MSG_PEEK,
            )
        };
        if n >= 0 {
            break n;
        }
        match std::io::Error::last_os_error().kind() {
            // A signal may interrupt the one-byte peek; retry it rather
            // than mislabeling a live request.
            std::io::ErrorKind::Interrupted => continue,
            // A reset or broken peer sent nothing: the same silence as a
            // closed one, not a header timeout.
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                return Ok(None);
            }
            _ => return Err(Reason::HeaderTimeout),
        }
    };
    Ok((n != 0).then_some(if byte == VERSION {
        Transport::Socks5
    } else {
        Transport::Http
    }))
}

fn read(stream: &UnixStream, bytes: &mut [u8], deadline: Instant) -> Result<(), Reason> {
    let mut at = 0;
    while at < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Reason::HeaderTimeout);
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| Reason::InternalError)?;
        match (&*stream).read(&mut bytes[at..]) {
            Ok(0) => return Err(Reason::ClientClosed),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Reason::HeaderTimeout),
        }
    }
    Ok(())
}

pub fn request(stream: &UnixStream, deadline: Instant) -> Result<Destination, Reason> {
    let mut head = [0; 2];
    read(stream, &mut head, deadline)?;
    if head[0] != VERSION || head[1] == 0 {
        return Err(Reason::MalformedRequest);
    }
    let mut methods = vec![0; usize::from(head[1])];
    read(stream, &mut methods, deadline)?;
    let method = if methods.contains(&NO_AUTHENTICATION) {
        NO_AUTHENTICATION
    } else {
        NO_ACCEPTABLE_METHOD
    };
    stream
        .set_write_timeout(Some(super::origin::TIMEOUT))
        .map_err(|_| Reason::InternalError)?;
    (&*stream)
        .write_all(&[VERSION, method])
        .map_err(|_| Reason::ClientClosed)?;
    if method == NO_ACCEPTABLE_METHOD {
        return Err(Reason::UnsupportedRequest);
    }
    let mut header = [0; 4];
    read(stream, &mut header, deadline)?;
    if header[0] != VERSION || header[2] != 0 {
        return Err(Reason::MalformedRequest);
    }
    if header[1] != CONNECT {
        reply(
            stream,
            if header[1] == BIND {
                Reply::NotAllowed
            } else {
                Reply::CommandNotSupported
            },
        )?;
        return Err(Reason::UnsupportedRequest);
    }
    let host = match header[3] {
        IPV4 => {
            let mut ip = [0; 4];
            read(stream, &mut ip, deadline)?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
        }
        IPV6 => {
            let mut ip = [0; 16];
            read(stream, &mut ip, deadline)?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(ip)))
        }
        DOMAIN => {
            let mut len = [0];
            read(stream, &mut len, deadline)?;
            if len[0] == 0 {
                return Err(Reason::MalformedRequest);
            }
            let mut bytes = vec![0; usize::from(len[0])];
            read(stream, &mut bytes, deadline)?;
            normalize_host(std::str::from_utf8(&bytes).map_err(|_| Reason::MalformedRequest)?)
                .map_err(|_| Reason::MalformedRequest)?
        }
        _ => {
            reply(stream, Reply::AddressTypeNotSupported)?;
            return Err(Reason::UnsupportedRequest);
        }
    };
    let mut port = [0; 2];
    read(stream, &mut port, deadline)?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(Reason::MalformedRequest);
    }
    let _ = stream.set_read_timeout(None);
    Ok(Destination { host, port })
}

/// A reply with an all-zero IPv4 bound address: the proxy never discloses
/// the address it connected from.
pub fn reply(stream: &UnixStream, reply: Reply) -> Result<(), Reason> {
    stream
        .set_write_timeout(Some(super::origin::TIMEOUT))
        .map_err(|_| Reason::InternalError)?;
    let result = (&*stream)
        .write_all(&[VERSION, reply as u8, 0, IPV4, 0, 0, 0, 0, 0, 0])
        .map_err(|_| Reason::ClientClosed);
    let _ = stream.set_write_timeout(None);
    result
}
