//! Request-head reading and strict HTTP/1.x proxy request parsing.
//!
//! Only two request shapes are accepted: `CONNECT host:port` (authority form)
//! and `http://` absolute form. Everything ambiguous refuses: bare CR or LF,
//! obs-fold, whitespace before a colon, duplicate or conflicting framing
//! headers, a Host that disagrees with the target, userinfo, escapes and zone
//! identifiers in the authority, fragments, and origin-form targets.
//!
//! Nothing here keeps or reports request content. Parse failures are safe
//! [`Reason`] codes; the forwarded head is built from validated parts only.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::Reason;
use crate::network::{Destination, parse_authority};

/// A complete request head plus any bytes read after it.
pub struct Head {
    buf: Vec<u8>,
    end: usize,
}

impl Head {
    /// The head, ending with its CRLF CRLF.
    #[must_use]
    pub fn head(&self) -> &[u8] {
        self.buf.get(..self.end).unwrap_or_default()
    }

    /// Bytes the client sent after the head.
    #[must_use]
    pub fn leftover(&self) -> &[u8] {
        self.buf.get(self.end..).unwrap_or_default()
    }
}

/// Why no head was read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeadError {
    /// The client closed before sending a byte: there was no request.
    NoBytes,
    /// A refusal.
    Reject(Reason),
}

/// Checks newly arrived bytes: every LF must follow CR, every CR must precede
/// LF, and NUL never appears. Returns the head length once CRLF CRLF arrives.
fn scan(buf: &[u8], from: usize) -> Result<Option<usize>, Reason> {
    let start = from.saturating_sub(3);
    for index in start..buf.len() {
        let byte = buf.get(index).copied().unwrap_or(0);
        match byte {
            0 => return Err(Reason::MalformedRequest),
            b'\n' => {
                if index == 0 || buf.get(index - 1) != Some(&b'\r') {
                    return Err(Reason::MalformedRequest);
                }
                if index >= 3 && buf.get(index - 3..=index) == Some(b"\r\n\r\n".as_slice()) {
                    return Ok(Some(index + 1));
                }
            }
            b'\r' => {
                if let Some(&next) = buf.get(index + 1)
                    && next != b'\n'
                {
                    return Err(Reason::MalformedRequest);
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

/// Reads one request head within `max` bytes and before `deadline`.
///
/// The deadline is absolute from accept, so a client trickling bytes cannot
/// extend it (slowloris). Bytes read past the head are kept as leftover and
/// never exceed `max` in total.
///
/// # Errors
/// [`HeadError::NoBytes`] for a clean close before any byte; otherwise a
/// refusal: `header_timeout`, `header_too_large`, `malformed_request` or
/// `client_closed`.
pub fn read_head(
    stream: &mut UnixStream,
    max: usize,
    deadline: Instant,
) -> Result<Head, HeadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(max.min(4096));
    let mut chunk = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HeadError::Reject(Reason::HeaderTimeout));
        }
        if stream.set_read_timeout(Some(remaining)).is_err() {
            return Err(HeadError::Reject(Reason::InternalError));
        }
        let room = max.saturating_sub(buf.len()).min(chunk.len());
        if room == 0 {
            return Err(HeadError::Reject(Reason::HeaderTooLarge));
        }
        let read = match stream.read(chunk.get_mut(..room).unwrap_or_default()) {
            Ok(read) => read,
            Err(error) => {
                return Err(HeadError::Reject(match error.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Reason::HeaderTimeout,
                    io::ErrorKind::Interrupted => continue,
                    _ => Reason::ClientClosed,
                }));
            }
        };
        if read == 0 {
            return Err(if buf.is_empty() {
                HeadError::NoBytes
            } else {
                HeadError::Reject(Reason::ClientClosed)
            });
        }
        let from = buf.len();
        buf.extend_from_slice(chunk.get(..read).unwrap_or_default());
        match scan(&buf, from) {
            Err(reason) => return Err(HeadError::Reject(reason)),
            Ok(Some(end)) => {
                let _ = stream.set_read_timeout(None);
                return Ok(Head { buf, end });
            }
            Ok(None) => {}
        }
    }
}

/// How the request body is delimited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Framing {
    /// CONNECT: after the head, bytes are tunnel data.
    Tunnel,
    /// No body.
    Empty,
    /// Exactly this many body bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`, without extensions or trailers.
    Chunked,
}

/// A parsed, validated request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request {
    /// The normalized destination.
    pub destination: Destination,
    /// Body framing.
    pub framing: Framing,
    /// For plain HTTP, the head sent upstream: origin-form target, Host from
    /// the validated target, hop-by-hop headers and proxy credentials
    /// removed, `Connection: close`. Empty for CONNECT.
    pub forward_head: Vec<u8>,
}

impl Request {
    /// CONNECT or plain HTTP.
    #[must_use]
    pub fn kind(&self) -> super::RequestKind {
        match self.framing {
            Framing::Tunnel => super::RequestKind::Connect,
            _ => super::RequestKind::Http,
        }
    }
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| is_tchar(b))
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |position| position + 1);
    bytes.get(start..end).unwrap_or_default()
}

/// Headers the proxy consumes or that belong to one hop only (RFC 9110
/// §7.6.1), plus proxy credentials.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
];

struct Field<'a> {
    name: &'a [u8],
    lower: String,
    value: &'a [u8],
}

fn authority_text(bytes: &[u8]) -> Result<&str, Reason> {
    std::str::from_utf8(bytes).map_err(|_| Reason::MalformedRequest)
}

/// Parses one request head (as returned by [`read_head`]).
///
/// # Errors
/// A safe [`Reason`]: `malformed_request`, `ambiguous_framing`,
/// `host_mismatch` or `unsupported_request`.
pub fn parse_request(head: &[u8]) -> Result<Request, Reason> {
    // The same line-ending checks `read_head` applies, so this function is
    // safe on bytes that did not come through it: exactly one CRLF CRLF, at
    // the end, and no bare CR, bare LF or NUL anywhere.
    if scan(head, 0)? != Some(head.len()) {
        return Err(Reason::MalformedRequest);
    }
    let body = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or(Reason::MalformedRequest)?;
    let mut lines = body.split(|&b| b == b'\n').map(|line| {
        // `scan` proved every LF follows a CR; the final line had its CRLF
        // stripped with the terminator.
        line.strip_suffix(b"\r").unwrap_or(line)
    });
    let request_line = lines.next().ok_or(Reason::MalformedRequest)?;
    let mut parts = request_line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Reason::MalformedRequest);
    };
    if !is_token(method) || target.is_empty() {
        return Err(Reason::MalformedRequest);
    }
    let http11 = match version {
        b"HTTP/1.1" => true,
        b"HTTP/1.0" => false,
        _ => return Err(Reason::MalformedRequest),
    };

    let mut fields: Vec<Field<'_>> = Vec::new();
    for line in lines {
        if line.is_empty() {
            return Err(Reason::MalformedRequest);
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(Reason::MalformedRequest)?;
        let name = line.get(..colon).unwrap_or_default();
        if !is_token(name) {
            // Also refuses whitespace between the name and the colon, and
            // every obs-fold line (RFC 9112 §5.2): a line that begins with
            // SP or HTAB has either no colon or a name that is not a token.
            return Err(Reason::MalformedRequest);
        }
        let value = trim_ows(line.get(colon + 1..).unwrap_or_default());
        if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(Reason::MalformedRequest);
        }
        let lower = String::from_utf8_lossy(name).to_ascii_lowercase();
        fields.push(Field { name, lower, value });
    }

    let named = |wanted: &str| -> Vec<&Field<'_>> {
        fields
            .iter()
            .filter(|field| field.lower == wanted)
            .collect()
    };
    let hosts = named("host");
    if hosts.len() > 1 {
        return Err(Reason::MalformedRequest);
    }
    let lengths = named("content-length");
    let encodings = named("transfer-encoding");
    if lengths.len() > 1 || encodings.len() > 1 || (!lengths.is_empty() && !encodings.is_empty()) {
        return Err(Reason::AmbiguousFraming);
    }
    let framing = if let Some(field) = lengths.first() {
        let text = field.value;
        if text.is_empty() || text.len() > 19 || !text.iter().all(u8::is_ascii_digit) {
            return Err(Reason::AmbiguousFraming);
        }
        let length: u64 = std::str::from_utf8(text)
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or(Reason::AmbiguousFraming)?;
        if length == 0 {
            Framing::Empty
        } else {
            Framing::Length(length)
        }
    } else if let Some(field) = encodings.first() {
        if !http11 || !field.value.eq_ignore_ascii_case(b"chunked") {
            return Err(Reason::AmbiguousFraming);
        }
        Framing::Chunked
    } else {
        Framing::Empty
    };

    // Names listed in Connection are removed; a framing or Host field must
    // never be removable that way, or upstream framing would differ from ours.
    let mut listed: Vec<String> = Vec::new();
    for field in named("connection") {
        for token in field.value.split(|&b| b == b',') {
            let token = trim_ows(token);
            if token.is_empty() {
                continue;
            }
            if !is_token(token) {
                return Err(Reason::MalformedRequest);
            }
            let token = String::from_utf8_lossy(token).to_ascii_lowercase();
            if matches!(
                token.as_str(),
                "host" | "content-length" | "transfer-encoding"
            ) {
                return Err(Reason::AmbiguousFraming);
            }
            listed.push(token);
        }
    }

    if method == b"CONNECT" {
        if framing != Framing::Empty || !lengths.is_empty() {
            return Err(Reason::AmbiguousFraming);
        }
        let destination =
            parse_authority(authority_text(target)?, None).map_err(|_| Reason::MalformedRequest)?;
        if let Some(host) = hosts.first() {
            let stated = parse_authority(authority_text(host.value)?, Some(destination.port))
                .map_err(|_| Reason::HostMismatch)?;
            if stated != destination {
                return Err(Reason::HostMismatch);
            }
        }
        return Ok(Request {
            destination,
            framing: Framing::Tunnel,
            forward_head: Vec::new(),
        });
    }

    // Plain HTTP: `http://` absolute form only.
    if target.contains(&b'#') {
        return Err(Reason::MalformedRequest);
    }
    let scheme_end = target
        .windows(3)
        .position(|window| window == b"://")
        .ok_or(Reason::UnsupportedRequest)?;
    let scheme = target.get(..scheme_end).unwrap_or_default();
    if !scheme.eq_ignore_ascii_case(b"http") {
        return Err(Reason::UnsupportedRequest);
    }
    let rest = target.get(scheme_end + 3..).unwrap_or_default();
    let authority_end = rest
        .iter()
        .position(|&b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let authority = rest.get(..authority_end).unwrap_or_default();
    let path = rest.get(authority_end..).unwrap_or_default();
    if !path.iter().all(|&b| (0x21..0x7f).contains(&b)) {
        return Err(Reason::MalformedRequest);
    }
    let destination = parse_authority(authority_text(authority)?, Some(80))
        .map_err(|_| Reason::MalformedRequest)?;
    match hosts.first() {
        Some(host) => {
            let stated = parse_authority(authority_text(host.value)?, Some(80))
                .map_err(|_| Reason::HostMismatch)?;
            if stated != destination {
                return Err(Reason::HostMismatch);
            }
        }
        None if http11 => return Err(Reason::MalformedRequest),
        None => {}
    }

    let mut forward = Vec::with_capacity(head.len() + 64);
    forward.extend_from_slice(method);
    forward.push(b' ');
    if path.first() == Some(&b'/') {
        forward.extend_from_slice(path);
    } else {
        forward.push(b'/');
        forward.extend_from_slice(path);
    }
    forward.push(b' ');
    forward.extend_from_slice(version);
    forward.extend_from_slice(b"\r\nHost: ");
    match (&destination.host, destination.port) {
        (host, 80) => forward.extend_from_slice(host.to_string().as_bytes()),
        (host, port) => forward.extend_from_slice(format!("{host}:{port}").as_bytes()),
    }
    forward.extend_from_slice(b"\r\n");
    for field in &fields {
        if HOP_BY_HOP.contains(&field.lower.as_str()) || listed.contains(&field.lower) {
            continue;
        }
        forward.extend_from_slice(field.name);
        forward.extend_from_slice(b": ");
        forward.extend_from_slice(field.value);
        forward.extend_from_slice(b"\r\n");
    }
    if framing == Framing::Chunked {
        forward.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    forward.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(Request {
        destination,
        framing,
        forward_head: forward,
    })
}

/// The response for a refusal: status, safe reason code, no request data.
#[must_use]
pub fn error_response(reason: Reason) -> Vec<u8> {
    let (status, text) = reason.status();
    let body = format!("{}\n", reason.as_str());
    format!(
        "HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         X-Ouro-Proxy-Reason: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
        reason.as_str()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Request, Reason> {
        parse_request(text.as_bytes())
    }

    #[test]
    fn scan_refuses_bare_line_endings_and_nul() {
        assert_eq!(scan(b"GET / HTTP/1.1\n", 0), Err(Reason::MalformedRequest));
        assert_eq!(scan(b"GET\r / HTTP/1.1", 0), Err(Reason::MalformedRequest));
        assert_eq!(scan(b"GET\0", 0), Err(Reason::MalformedRequest));
        assert_eq!(scan(b"A\r\n\r\nrest", 0), Ok(Some(5)));
        assert_eq!(
            scan(b"A\r", 0),
            Ok(None),
            "a CR at the end may still get its LF"
        );
    }

    #[test]
    fn connect_and_absolute_form_parse() {
        let request = parse("CONNECT Example.COM:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .expect("parses");
        assert_eq!(request.framing, Framing::Tunnel);
        assert_eq!(request.destination.to_string(), "example.com:443");
        let request = parse(
            "GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\n\
             Proxy-Authorization: Basic c2VjcmV0\r\nConnection: x-secret\r\nX-Secret: 1\r\n\
             Accept: */*\r\n\r\n",
        )
        .expect("parses");
        assert_eq!(
            String::from_utf8(request.forward_head).expect("ASCII"),
            "GET /a?b HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn ambiguous_framing_refuses() {
        let cases = [
            "POST http://e.com/ HTTP/1.1\r\nHost: e.com\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "POST http://e.com/ HTTP/1.1\r\nHost: e.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://e.com/ HTTP/1.1\r\nHost: e.com\r\nContent-Length: 1, 1\r\n\r\n",
            "POST http://e.com/ HTTP/1.1\r\nHost: e.com\r\nContent-Length: +1\r\n\r\n",
            "POST http://e.com/ HTTP/1.1\r\nHost: e.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "POST http://e.com/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://e.com/ HTTP/1.1\r\nHost: e.com\r\nConnection: content-length\r\nContent-Length: 1\r\n\r\n",
            "CONNECT e.com:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ];
        for case in cases {
            assert_eq!(
                parse(case).err(),
                Some(Reason::AmbiguousFraming),
                "{case:?}"
            );
        }
    }

    #[test]
    fn malformed_heads_refuse() {
        let cases = [
            "GET http://e.com/ HTTP/1.1\r\nHost: e.com\r\nX: a\r\n b\r\n\r\n",
            "GET http://e.com/ HTTP/1.1\r\nHost: e.com\r\nX: a\r\n\tb: c\r\n\r\n",
            "GET http://e.com/ HTTP/1.1\r\nHost : e.com\r\n\r\n",
            "GET http://e.com/ HTTP/1.1\r\nHost: e.com\r\nX-Bad : v\r\n\r\n",
            "GET http://e.com/ HTTP/1.1\r\nHost: e.com\r\nX Y: z\r\n\r\n",
            "GET  http://e.com/ HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "GET http://e.com/ HTTP/2\r\nHost: e.com\r\n\r\n",
            "GET http://e.com/ HTTP/1.1\r\n\r\n",
            "GET http://e.com/ HTTP/1.1\r\nHost: e.com\r\nHost: e.com\r\n\r\n",
            "GET http://user:pw@e.com/ HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "GET http://e%2ecom/ HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "GET http://e.com/#frag HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "GET http://e.com/\u{e4} HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "GET http://e.com/a\u{7f} HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "GET http://127.1/ HTTP/1.1\r\nHost: 127.1\r\n\r\n",
            "CONNECT e.com HTTP/1.1\r\n\r\n",
            "CONNECT [fe80::1%25lo0]:443 HTTP/1.1\r\n\r\n",
            "CONNECT ::1:443 HTTP/1.1\r\n\r\n",
        ];
        for case in cases {
            assert!(parse(case).is_err(), "{case:?}");
        }
    }

    #[test]
    fn host_must_agree_with_the_target() {
        assert_eq!(
            parse("GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n").err(),
            Some(Reason::HostMismatch)
        );
        assert_eq!(
            parse("GET http://a.example/ HTTP/1.1\r\nHost: a.example:8080\r\n\r\n").err(),
            Some(Reason::HostMismatch)
        );
        assert_eq!(
            parse("CONNECT a.example:443 HTTP/1.1\r\nHost: b.example:443\r\n\r\n").err(),
            Some(Reason::HostMismatch)
        );
        assert!(parse("GET http://A.example./ HTTP/1.1\r\nHost: a.EXAMPLE:80\r\n\r\n").is_ok());
    }

    #[test]
    fn non_proxy_requests_are_unsupported() {
        for case in [
            "GET / HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "GET https://e.com/ HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "OPTIONS * HTTP/1.1\r\nHost: e.com\r\n\r\n",
        ] {
            assert_eq!(
                parse(case).err(),
                Some(Reason::UnsupportedRequest),
                "{case:?}"
            );
        }
    }
}
