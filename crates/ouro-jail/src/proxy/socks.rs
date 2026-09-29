//! RFC 1928 CONNECT only. DNS resolution remains in the shared proxy policy.
use super::Reason;
use crate::network::{Destination, Host, normalize_host};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

pub fn detect(stream: &UnixStream, deadline: Instant) -> Result<Option<bool>, Reason> {
    stream
        .set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(std::time::Duration::from_millis(1)),
        ))
        .map_err(|_| Reason::InternalError)?;
    let mut byte = 0u8;
    // MSG_PEEK selects the protocol without consuming HTTP's request byte.
    let n = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            (&raw mut byte).cast(),
            1,
            libc::MSG_PEEK,
        )
    };
    if n < 0 {
        return Err(Reason::HeaderTimeout);
    }
    Ok((n != 0).then_some(byte == 5))
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
    if head[0] != 5 || head[1] == 0 {
        return Err(Reason::MalformedRequest);
    }
    let mut methods = vec![0; usize::from(head[1])];
    read(stream, &mut methods, deadline)?;
    let method = if methods.contains(&0) { 0 } else { 255 };
    stream
        .set_write_timeout(Some(super::origin::TIMEOUT))
        .map_err(|_| Reason::InternalError)?;
    (&*stream)
        .write_all(&[5, method])
        .map_err(|_| Reason::ClientClosed)?;
    if method == 255 {
        return Err(Reason::UnsupportedRequest);
    }
    let mut header = [0; 4];
    read(stream, &mut header, deadline)?;
    if header[0] != 5 || header[2] != 0 {
        return Err(Reason::MalformedRequest);
    }
    if header[1] != 1 {
        reply(stream, if header[1] == 2 { 2 } else { 7 })?;
        return Err(Reason::UnsupportedRequest);
    }
    let host = match header[3] {
        1 => {
            let mut ip = [0; 4];
            read(stream, &mut ip, deadline)?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
        }
        4 => {
            let mut ip = [0; 16];
            read(stream, &mut ip, deadline)?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(ip)))
        }
        3 => {
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
            reply(stream, 8)?;
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

pub fn reply(stream: &UnixStream, code: u8) -> Result<(), Reason> {
    stream
        .set_write_timeout(Some(super::origin::TIMEOUT))
        .map_err(|_| Reason::InternalError)?;
    let result = (&*stream)
        .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(|_| Reason::ClientClosed);
    let _ = stream.set_write_timeout(None);
    result
}
