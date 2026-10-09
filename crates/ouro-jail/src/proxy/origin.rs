//! Bounded first-flight inspection. SNI is a routing name, not an assertion
//! about the encrypted application authority (RFC 6066 and RFC 8446).
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::{Reason, http};
use crate::network::{Destination, Host, normalize_host};

pub const MAX_BYTES: usize = 8192;
pub const TIMEOUT: Duration = Duration::from_secs(5);

pub struct Flight {
    pub bytes: Vec<u8>,
    pub http: Option<http::Request>,
    pub mechanism: &'static str,
}

pub fn inspect(stream: &UnixStream, early: &[u8], target: &Destination) -> Result<Flight, Reason> {
    if matches!(target.host, Host::Ip(_)) {
        return Ok(Flight {
            bytes: early.to_vec(),
            http: None,
            mechanism: "explicit_ip",
        });
    }
    let deadline = Instant::now() + TIMEOUT;
    let mut bytes = early.to_vec();
    let result = (|| loop {
        if bytes.len() > MAX_BYTES {
            return Err(Reason::OriginUnverified);
        }
        if bytes.first() == Some(&22) {
            if let Some(name) = tls_name(&bytes)? {
                if name != target.host {
                    return Err(Reason::OriginMismatch);
                }
                return Ok(Flight {
                    bytes,
                    http: None,
                    mechanism: "tls_sni",
                });
            }
        } else if !bytes.is_empty() {
            if !bytes[0].is_ascii_uppercase() {
                return Err(Reason::OriginUnverified);
            }
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let end = end + 4;
                let request = http_request(&bytes[..end], target, 80)?;
                return Ok(Flight {
                    bytes: bytes[end..].to_vec(),
                    http: Some(request),
                    mechanism: "http_host",
                });
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Reason::OriginTimeout);
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| Reason::InternalError)?;
        let mut buf = [0u8; 2048];
        let room = (MAX_BYTES - bytes.len()).min(buf.len());
        if room == 0 {
            return Err(Reason::OriginUnverified);
        }
        match (&*stream).read(&mut buf[..room]) {
            Ok(0) => return Err(Reason::OriginUnverified),
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(Reason::OriginTimeout);
            }
            Err(_) => return Err(Reason::OriginUnverified),
        }
    })();
    let _ = stream.set_read_timeout(None);
    result
}

pub fn established(stream: &UnixStream) -> Result<(), Reason> {
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|_| Reason::InternalError)?;
    let result = (&*stream)
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .map_err(|_| Reason::ClientClosed);
    let _ = stream.set_write_timeout(None);
    result
}

/// None means incomplete; malformed records always fail closed. Reassembles
/// a fragmented ClientHello, bounded by the same wire-byte budget.
fn tls_name(bytes: &[u8]) -> Result<Option<Host>, Reason> {
    let mut at = 0;
    let mut hello = Vec::new();
    while at < bytes.len() {
        if bytes.len() - at < 5 {
            return Ok(None);
        }
        if bytes[at] != 22 || bytes[at + 1] != 3 || bytes[at + 2] > 3 {
            return Err(Reason::OriginUnverified);
        }
        let len = usize::from(u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]));
        if len == 0 || len > MAX_BYTES - 5 {
            return Err(Reason::OriginUnverified);
        }
        at += 5;
        if bytes.len() - at < len {
            return Ok(None);
        }
        hello.extend_from_slice(&bytes[at..at + len]);
        at += len;
        if hello.len() >= 4 {
            if hello[0] != 1 {
                return Err(Reason::OriginUnverified);
            }
            let size = (usize::from(hello[1]) << 16)
                | (usize::from(hello[2]) << 8)
                | usize::from(hello[3]);
            if size > MAX_BYTES - 4 {
                return Err(Reason::OriginUnverified);
            }
            if hello.len() >= size + 4 {
                return parse_hello(&hello[4..size + 4]).map(Some);
            }
        }
    }
    Ok(None)
}

struct Bytes<'a>(&'a [u8]);
impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Reason> {
        if n > self.0.len() {
            return Err(Reason::OriginUnverified);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn byte(&mut self) -> Result<usize, Reason> {
        Ok(usize::from(self.take(1)?[0]))
    }
    fn word(&mut self) -> Result<usize, Reason> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn vector(&mut self) -> Result<&'a [u8], Reason> {
        let n = self.word()?;
        self.take(n)
    }
}
fn parse_hello(bytes: &[u8]) -> Result<Host, Reason> {
    let mut c = Bytes(bytes);
    let version = c.take(2)?;
    if version[0] != 3 || !(1..=3).contains(&version[1]) {
        return Err(Reason::OriginUnverified);
    }
    c.take(32)?;
    let n = c.byte()?;
    if n > 32 {
        return Err(Reason::OriginUnverified);
    }
    c.take(n)?;
    let suites = c.vector()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(Reason::OriginUnverified);
    }
    let n = c.byte()?;
    if n == 0 {
        return Err(Reason::OriginUnverified);
    }
    c.take(n)?;
    let mut exts = Bytes(c.vector()?);
    if !c.0.is_empty() {
        return Err(Reason::OriginUnverified);
    }
    let mut seen = std::collections::HashSet::new();
    let mut name = None;
    while !exts.0.is_empty() {
        let kind = exts.word()?;
        if !seen.insert(kind)
            || matches!(
                kind,
                // ECH, draft ECH (fe08-fe0c) and ESNI (ffce): none may pass
                // with a `tls_sni` claim.
                0xfe0d | 0xffce | 0xfe08..=0xfe0c
            )
        {
            return Err(Reason::OriginUnverified);
        }
        let data = exts.vector()?;
        if kind == 0 {
            let mut data = Bytes(data);
            let mut names = Bytes(data.vector()?);
            if !data.0.is_empty() || names.byte()? != 0 {
                return Err(Reason::OriginUnverified);
            }
            let raw = names.vector()?;
            if !names.0.is_empty() {
                return Err(Reason::OriginUnverified);
            }
            let raw = std::str::from_utf8(raw).map_err(|_| Reason::OriginUnverified)?;
            if !raw.is_ascii() {
                return Err(Reason::OriginUnverified);
            }
            let host = normalize_host(raw).map_err(|_| Reason::OriginUnverified)?;
            if !matches!(host, Host::Name(_)) {
                return Err(Reason::OriginUnverified);
            }
            name = Some(host);
        }
    }
    name.ok_or(Reason::OriginUnverified)
}

pub(super) fn http_request(
    bytes: &[u8],
    target: &Destination,
    default_port: u16,
) -> Result<http::Request, Reason> {
    let head = std::str::from_utf8(bytes).map_err(|_| Reason::OriginUnverified)?;
    let (line, headers) = head.split_once("\r\n").ok_or(Reason::OriginUnverified)?;
    let words: Vec<_> = line.split(' ').collect();
    if words.len() != 3 || !words[1].starts_with('/') || words[1].starts_with("//") {
        return Err(Reason::OriginUnverified);
    }
    let rewritten = format!(
        "{} http://{}{} {}\r\n{}",
        words[0], target, words[1], words[2], headers
    );
    let request =
        http::parse_request_with_port(rewritten.as_bytes(), default_port).map_err(|reason| {
            if reason == Reason::HostMismatch {
                Reason::OriginMismatch
            } else {
                Reason::OriginUnverified
            }
        })?;
    if request.destination != *target {
        return Err(Reason::OriginMismatch);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(name: &[u8]) -> Vec<u8> {
        hello_ext(name, &[])
    }
    /// A ClientHello with the SNI extension plus one extra extension of the
    /// given kind (with two bytes of data) per entry.
    fn hello_ext(name: &[u8], kinds: &[u16]) -> Vec<u8> {
        let mut h = vec![3, 3];
        h.extend([0; 32]);
        h.extend([0, 0, 2, 0x13, 1, 1, 0]);
        let mut names = vec![0];
        names.extend((name.len() as u16).to_be_bytes());
        names.extend(name);
        let mut sni = Vec::from((names.len() as u16).to_be_bytes());
        sni.extend(names);
        let mut exts = vec![0, 0];
        exts.extend((sni.len() as u16).to_be_bytes());
        exts.extend(sni);
        for &kind in kinds {
            exts.extend(kind.to_be_bytes());
            exts.extend([0, 2, 0, 0]);
        }
        h.extend((exts.len() as u16).to_be_bytes());
        h.extend(exts);
        let mut handshake = vec![1, 0, 0, h.len() as u8];
        handshake.extend(h);
        let mut out = vec![22, 3, 1];
        out.extend((handshake.len() as u16).to_be_bytes());
        out.extend(handshake);
        out
    }
    #[test]
    fn fragmented_hello_and_truncation() {
        let bytes = hello(b"EXAMPLE.COM");
        for n in 0..bytes.len() {
            assert_eq!(tls_name(&bytes[..n]), Ok(None), "{n}");
        }
        assert_eq!(tls_name(&bytes), Ok(Some(Host::Name("example.com".into()))));
        let payload = &bytes[5..];
        let mut fragmented = Vec::new();
        for p in payload.chunks(7) {
            fragmented.extend([22, 3, 3]);
            fragmented.extend((p.len() as u16).to_be_bytes());
            fragmented.extend(p);
        }
        assert_eq!(tls_name(&fragmented), tls_name(&bytes));
    }
    #[test]
    fn malformed_and_non_tls_refuse() {
        assert!(tls_name(&[22, 3, 3, 255, 255]).is_err());
        assert!(tls_name(&hello(b"127.0.0.1")).is_err());
        assert!(tls_name(&hello(b"bad\0name")).is_err());
    }
    /// ECH, its drafts and ESNI must not pass with a `tls_sni` claim.
    #[test]
    fn encrypted_client_hello_refused() {
        for kind in [0xfe0d, 0xfe08, 0xfe0a, 0xfe0c, 0xffce] {
            assert!(
                tls_name(&hello_ext(b"example.com", &[kind])).is_err(),
                "{kind:#06x} passed"
            );
        }
        // A benign unknown extension still resolves the name.
        assert_eq!(
            tls_name(&hello_ext(b"example.com", &[0x001a])),
            Ok(Some(Host::Name("example.com".into())))
        );
    }
    /// jail-v2 §6.2: a ClientHello carrying the same extension kind twice
    /// refuses, even when both are individually benign.
    #[test]
    fn a_duplicated_extension_kind_refuses() {
        for kinds in [
            &[0x001a, 0x001a][..],
            // A repeated SNI kind must also refuse on the duplicate check,
            // not merely because its re-parsed body is malformed.
            &[0x0000, 0x001a][..],
        ] {
            assert!(
                tls_name(&hello_ext(b"example.com", kinds)).is_err(),
                "{kinds:?} repeated and passed"
            );
        }
    }
}
