//! Network modes: unconnected UDP, a DNS query, and a minimal HTTP/1.1 client
//! that honours the proxy variables.
//!
//! Every socket-level call (`socket`, `connect`, `sendto`) goes through
//! [`crate::raw`] and gets its own report line, so a tracer or a seccomp
//! filter sees exactly the call a line names. Data transfer after that
//! (`read`/`write`/`recvfrom`) is not in the closed set and is summarised on
//! one line per mode instead: byte counts, status, and what stopped it.
//!
//! Two rules keep the lines honest:
//!
//! * No name resolution. A direct connection takes a numeric address (or the
//!   literal `localhost`, mapped to 127.0.0.1 without a lookup and reported
//!   as such); a name reaches the network only as text sent to a proxy or a
//!   resolver the test named. A lookup would issue its own connects and
//!   pollute the trace.
//! * No environment value on a line. A proxy variable is reported by NAME
//!   only (the value may carry credentials); the connect to it says
//!   `"addr_source":"proxy_variable"` instead of an address. A variable that
//!   is set but unusable is refused, never silently bypassed.

use std::ffi::{OsStr, c_int};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;

use serde_json::Value;

use crate::bounded::{self, Deadline, IoFail};
use crate::ops::{Usage, finish};
use crate::raw;
use crate::report::{Emitted, Expect, OpReport, Reporter};
use crate::sockaddr::SockAddr;

/// Largest UDP payload the fixture will build. The kernel still decides.
pub const MAX_UDP_BYTES: usize = 1 << 20;
/// Largest response head the HTTP client accepts before giving up.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Largest body the HTTP client counts before it stops reading.
pub const MAX_BODY_BYTES: u64 = 16 << 20;

// ------------------------------------------------------------ socket lines

/// Create a socket and report it. `cloexec` asks for close-on-exec: in the
/// type argument on Linux, by `fcntl` right after on Darwin (the line says
/// which). Returns the descriptor, or the failure after reporting it.
pub(crate) fn open_socket(
    rep: &Reporter,
    domain: c_int,
    family: &str,
    ty: c_int,
    type_name: &str,
    cloexec: bool,
) -> Result<c_int, IoFail> {
    let mut report = OpReport::new("socket");
    report.set("family", family);
    report.set("type", type_name);
    report.set("mechanism", raw::mechanism());
    #[cfg(target_os = "linux")]
    let ty = if cloexec {
        report.set("cloexec", "SOCK_CLOEXEC");
        ty | libc::SOCK_CLOEXEC
    } else {
        ty
    };
    let emitted = finish(report, raw::socket(domain, ty, 0));
    let fd = emitted.report.ret;
    #[cfg(target_os = "linux")]
    let report = emitted.report;
    #[cfg(not(target_os = "linux"))]
    let report = {
        let mut report = emitted.report;
        if cloexec && fd >= 0 {
            report.set(
                "cloexec",
                match bounded::set_cloexec(fd as c_int) {
                    Ok(()) => "fcntl",
                    Err(_) => "failed",
                },
            );
        }
        report
    };
    let errno = report.errno.as_deref().and_then(crate::errno::value);
    rep.emit(&report);
    if fd >= 0 {
        Ok(fd as c_int)
    } else {
        Err(IoFail::Errno(errno.unwrap_or(libc::EIO)))
    }
}

/// Report a `sendto` of `payload` to `addr`.
fn sendto_line(fd: c_int, payload: &[u8], addr: &SockAddr, shown: Option<&str>) -> Emitted {
    let mut report = OpReport::new("sendto");
    if let Some(a) = shown {
        report.set("addr", a);
    }
    report.set("family", addr.family_name());
    report.set("type", "SOCK_DGRAM");
    report.set("len", payload.len());
    report.set("connected", false);
    report.set("mechanism", raw::mechanism());
    finish(report, raw::sendto(fd, payload, 0, addr))
}

fn numeric(addr: &str) -> Result<SocketAddr, Usage> {
    addr.parse().map_err(|_| {
        format!(
            "`{addr}` is not a numeric ADDR:PORT. The fixture refuses names on purpose: \
             resolving one would issue its own connects and pollute the trace."
        )
    })
}

// ---------------------------------------------------------------- udp-sendto

pub(crate) fn udp_sendto(
    rep: &Reporter,
    addr: &str,
    bytes: usize,
    expect: &Expect,
) -> Result<bool, Usage> {
    let dest = numeric(addr)?;
    if bytes > MAX_UDP_BYTES {
        return Err(format!(
            "--bytes {bytes} is above the fixture's {MAX_UDP_BYTES}-byte bound"
        ));
    }
    let sa = SockAddr::inet(dest);
    let Ok(fd) = open_socket(
        rep,
        sa.domain(),
        sa.family_name(),
        libc::SOCK_DGRAM,
        "SOCK_DGRAM",
        true,
    ) else {
        return Ok(false);
    };
    let emitted = sendto_line(fd, &bounded::pattern(bytes), &sa, Some(addr));
    bounded::close(fd);
    rep.emit(&emitted.report);
    Ok(emitted.satisfies(expect))
}

// ----------------------------------------------------------------- dns-query

/// Encode one DNS query for `name`, type A, class IN, recursion desired.
///
/// Refused: non-ASCII (the fixture does no IDNA), an empty label, a label
/// over 63 bytes, and a name over 255 bytes on the wire.
pub fn encode_query(id: u16, name: &str) -> Result<Vec<u8>, String> {
    if !name.is_ascii() {
        return Err(format!(
            "`{name}` is not ASCII: the fixture sends names as given and does no IDNA"
        ));
    }
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let mut out = Vec::with_capacity(18 + trimmed.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN, NS, AR
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("`{name}` has an empty label or one over 63 bytes"));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() - 12 > 255 {
        return Err(format!("`{name}` is over 255 bytes on the wire"));
    }
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Ok(out)
}

/// What a DNS response said, as far as it could be read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DnsResponse {
    pub id: u16,
    pub is_response: bool,
    pub truncated: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    /// Addresses of the A/IN answers that could be read.
    pub a: Vec<Ipv4Addr>,
    /// Set when the message ended or broke before its sections did.
    pub malformed: Option<&'static str>,
}

/// Skip one encoded name. A compression pointer ends the name, so this never
/// follows one and cannot loop; every step moves strictly forward.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, &'static str> {
    loop {
        let len = *buf.get(pos).ok_or("name_out_of_bounds")?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok(pos + 1),
            0x00 => pos += 1 + usize::from(len),
            0xC0 => {
                buf.get(pos + 1).ok_or("pointer_out_of_bounds")?;
                return Ok(pos + 2);
            }
            _ => return Err("reserved_label_type"),
        }
    }
}

fn be16(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

/// Parse a response. Only a header shorter than 12 bytes is an `Err`; any
/// later breakage keeps the header facts and sets `malformed`.
pub fn parse_response(buf: &[u8]) -> Result<DnsResponse, &'static str> {
    if buf.len() < 12 {
        return Err("short_header");
    }
    let flags = be16(buf, 2).ok_or("short_header")?;
    let mut r = DnsResponse {
        id: be16(buf, 0).ok_or("short_header")?,
        is_response: flags & 0x8000 != 0,
        truncated: flags & 0x0200 != 0,
        rcode: (flags & 0x000F) as u8,
        qdcount: be16(buf, 4).ok_or("short_header")?,
        ancount: be16(buf, 6).ok_or("short_header")?,
        ..DnsResponse::default()
    };
    let mut pos = 12;
    for _ in 0..r.qdcount {
        match skip_name(buf, pos) {
            Ok(p) if p + 4 <= buf.len() => pos = p + 4,
            Ok(_) => {
                r.malformed = Some("truncated_question");
                return Ok(r);
            }
            Err(e) => {
                r.malformed = Some(e);
                return Ok(r);
            }
        }
    }
    // A bound on the work, not on the claim: `ancount` is reported as sent.
    for _ in 0..r.ancount.min(64) {
        let p = match skip_name(buf, pos) {
            Ok(p) => p,
            Err(e) => {
                r.malformed = Some(e);
                return Ok(r);
            }
        };
        let (Some(ty), Some(class), Some(rdlen)) =
            (be16(buf, p), be16(buf, p + 2), be16(buf, p + 8))
        else {
            r.malformed = Some("truncated_answer");
            return Ok(r);
        };
        let start = p + 10;
        let end = start + usize::from(rdlen);
        let Some(rdata) = buf.get(start..end) else {
            r.malformed = Some("rdata_out_of_bounds");
            return Ok(r);
        };
        if ty == 1 && class == 1 && rdata.len() == 4 {
            r.a.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        pos = end;
    }
    Ok(r)
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

fn parse_resolver(resolver: &str) -> Result<SocketAddr, Usage> {
    if let Ok(sa) = resolver.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = resolver.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!(
        "`{resolver}` is not a numeric resolver (IP, IP:PORT or [IPv6]:PORT). \
         The fixture refuses names on purpose."
    ))
}

/// `recvfrom` one datagram and its source. `Ok(None)` source when the
/// address family was not one this function decodes.
fn recv_from(fd: c_int, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>), c_int> {
    // SAFETY: `sockaddr_storage` is plain old data; zero is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `buf` is live and writable for its length; `storage` is live
    // and `len` says exactly its size, so the kernel writes within both.
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            0,
            (&raw mut storage).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    let source = match c_int::from(storage.ss_family) {
        libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family says the storage holds a `sockaddr_in`, the
            // kernel wrote at least its size, and storage is aligned for it.
            let sa = unsafe { &*(&raw const storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(sa.sin_port),
            ))
        }
        libc::AF_INET6 if len as usize >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for `sockaddr_in6`.
            let sa = unsafe { &*(&raw const storage).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr)),
                u16::from_be(sa.sin6_port),
            ))
        }
        _ => None,
    };
    Ok((n as usize, source))
}

fn query_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    ((nanos ^ std::process::id().rotate_left(16)) & 0xFFFF) as u16
}

pub(crate) fn dns_query(
    rep: &Reporter,
    resolver: &str,
    name: &str,
    timeout_ms: u64,
    expect: &Expect,
) -> Result<bool, Usage> {
    let server = parse_resolver(resolver)?;
    let id = query_id();
    let query = encode_query(id, name)?;
    let deadline = Deadline::after_ms(timeout_ms);
    let sa = SockAddr::inet(server);

    let mut summary = OpReport::new("dns-query");
    summary.set("resolver", server.to_string());
    summary.set("name", name);
    summary.set("qtype", "A");
    summary.set("id", id);
    summary.set("timeout_ms", timeout_ms);

    let fd = match open_socket(
        rep,
        sa.domain(),
        sa.family_name(),
        libc::SOCK_DGRAM,
        "SOCK_DGRAM",
        true,
    ) {
        Ok(fd) => fd,
        Err(f) => {
            summary.set("failed_step", "socket");
            summary.set("answered", false);
            f.apply(&mut summary);
            let e = Emitted::done(summary);
            rep.emit(&e.report);
            return Ok(e.satisfies(expect));
        }
    };
    let sent = sendto_line(fd, &query, &sa, Some(&server.to_string()));
    rep.emit(&sent.report);
    if sent.unusable || sent.report.ret < 0 {
        bounded::close(fd);
        summary.set("failed_step", "sendto");
        summary.set("answered", false);
        let errno = sent.report.errno.as_deref().and_then(crate::errno::value);
        summary.result(-1, errno);
        let e = Emitted::done(summary);
        rep.emit(&e.report);
        return Ok(e.satisfies(expect));
    }
    summary.set("query_bytes", query.len());

    let mut ignored = 0u32;
    let mut buf = vec![0u8; 4096];
    let outcome = loop {
        if let Err(f) = bounded::wait_for(fd, libc::POLLIN, deadline) {
            break Err(f);
        }
        match recv_from(fd, &mut buf) {
            Err(e) if e == libc::EINTR || e == libc::EAGAIN => {}
            Err(e) => break Err(IoFail::Errno(e)),
            Ok((n, source)) => {
                // Only a datagram from the resolver that carries this query's
                // id is the answer; anything else is counted and skipped.
                let from_server = source == Some(server);
                let id_matches = buf.len() >= 2 && n >= 2 && buf[..2] == id.to_be_bytes();
                if from_server && id_matches {
                    break Ok(n);
                }
                ignored += 1;
            }
        }
    };
    bounded::close(fd);
    summary.set("ignored_datagrams", ignored);

    match outcome {
        Err(f) => {
            summary.set("answered", false);
            summary.set("failed_step", "recvfrom");
            f.apply(&mut summary);
        }
        Ok(n) => {
            summary.set("answered", true);
            summary.set("response_bytes", n);
            match parse_response(&buf[..n]) {
                Err(why) => {
                    summary.set("malformed", why);
                    summary.result(-1, None);
                }
                Ok(r) => {
                    summary.set("is_response", r.is_response);
                    summary.set("truncated", r.truncated);
                    summary.set("rcode", r.rcode);
                    summary.set("rcode_name", rcode_name(r.rcode));
                    summary.set("ancount", r.ancount);
                    summary.set(
                        "a",
                        Value::Array(r.a.iter().map(|ip| Value::from(ip.to_string())).collect()),
                    );
                    summary.set("malformed", r.malformed.map_or(Value::Null, Value::from));
                    if r.is_response {
                        summary.result(i64::from(r.rcode), None);
                    } else {
                        summary.result(-1, None);
                    }
                }
            }
        }
    }
    let e = Emitted::done(summary);
    rep.emit(&e.report);
    Ok(e.satisfies(expect))
}

// ---------------------------------------------------------------------- http

/// A parsed `http://` URL.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpUrl {
    /// The authority exactly as written (without userinfo, which is refused).
    pub authority: String,
    /// The host without brackets.
    pub host: String,
    pub port: u16,
    /// Path and query, `/` when the URL had none. The fragment is dropped.
    pub path: String,
}

/// Split `host[:port]` or `[v6][:port]`.
pub fn parse_authority(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(String, u16), String> {
    if authority.is_empty() {
        return Err("empty authority".into());
    }
    if authority.contains('@') {
        return Err("userinfo in an authority is not supported by the fixture".into());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("`{authority}` has an unclosed IPv6 bracket"))?;
        h.parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("`{h}` is not an IPv6 literal"))?;
        match after {
            "" => (h.to_string(), None),
            p if p.starts_with(':') => (h.to_string(), Some(&p[1..])),
            _ => return Err(format!("`{authority}` has bytes after the IPv6 literal")),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(format!("`{authority}` has an empty host"));
    }
    let port = match port {
        Some(p) => p
            .parse::<u16>()
            .map_err(|_| format!("`{authority}` has a port that is not 0-65535"))?,
        None => default_port.ok_or_else(|| format!("`{authority}` has no port"))?,
    };
    Ok((host, port))
}

/// Parse an `http://` URL. `https://` is refused: the fixture does no TLS.
pub fn parse_http_url(url: &str) -> Result<HttpUrl, String> {
    let rest = if url.len() >= 7 && url[..7].eq_ignore_ascii_case("http://") {
        &url[7..]
    } else if url.len() >= 8 && url[..8].eq_ignore_ascii_case("https://") {
        return Err(format!(
            "`{url}`: the fixture does no TLS; use `http-connect` for a tunnel"
        ));
    } else {
        return Err(format!("`{url}` is not an http:// URL"));
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let (host, port) = parse_authority(authority, Some(80))?;
    let mut path = rest[end..].split('#').next().unwrap_or("").to_string();
    if path.is_empty() {
        path.push('/');
    } else if path.starts_with('?') {
        path.insert(0, '/');
    }
    Ok(HttpUrl {
        authority: authority.to_string(),
        host,
        port,
        path,
    })
}

/// A host the fixture can connect to without a lookup: an IP literal, or
/// `localhost` mapped to 127.0.0.1 (the second value says it was mapped).
pub fn numeric_host(host: &str, port: u16) -> Option<(SocketAddr, bool)> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some((SocketAddr::new(ip, port), false));
    }
    host.eq_ignore_ascii_case("localhost")
        .then(|| (SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port), true))
}

/// Which proxy the environment names.
#[derive(Debug, PartialEq, Eq)]
pub enum ProxyChoice {
    /// Neither variable is set (or both are empty).
    None,
    /// `var` names a usable plain-HTTP proxy.
    Use {
        var: &'static str,
        addr: SocketAddr,
        localhost_mapped: bool,
    },
    /// `var` is set but cannot be followed. Refused; never bypassed.
    Unusable {
        var: &'static str,
        problem: &'static str,
    },
}

/// Interpret one proxy variable's value. Never echoes it.
pub fn parse_proxy_value(value: &[u8]) -> Result<(SocketAddr, bool), &'static str> {
    let text = std::str::from_utf8(value).map_err(|_| "not_utf8")?;
    let rest = if text.len() >= 7 && text[..7].eq_ignore_ascii_case("http://") {
        &text[7..]
    } else if text.contains("://") {
        return Err("scheme_not_http");
    } else {
        text
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return Err("userinfo_not_supported");
    }
    let (host, port) = parse_authority(authority, None).map_err(|e| {
        if e.contains("no port") {
            "missing_port"
        } else {
            "unparsable"
        }
    })?;
    numeric_host(&host, port).ok_or("name_host_not_supported")
}

/// Look up `names` in order (lowercase first) in `lookup`. An empty value
/// counts as unset, as curl treats it.
pub fn proxy_choice(
    names: [&'static str; 2],
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> ProxyChoice {
    for var in names {
        if let Some(v) = lookup(var) {
            if v.is_empty() {
                continue;
            }
            return match parse_proxy_value(v.as_bytes()) {
                Ok((addr, localhost_mapped)) => ProxyChoice::Use {
                    var,
                    addr,
                    localhost_mapped,
                },
                Err(problem) => ProxyChoice::Unusable { var, problem },
            };
        }
    }
    ProxyChoice::None
}

fn env_proxy(names: [&'static str; 2]) -> ProxyChoice {
    proxy_choice(names, |n| std::env::var_os(OsStr::new(n)))
}

/// Connect a TCP socket without blocking past the deadline. Emits `socket`,
/// `connect` (the raw result, `EINPROGRESS` included) and, when the connect
/// was in progress, the `getsockopt(SO_ERROR)` that completed it.
fn tcp_connect(
    rep: &Reporter,
    addr: SocketAddr,
    shown: Option<&str>,
    deadline: Deadline,
) -> Result<c_int, IoFail> {
    let sa = SockAddr::inet(addr);
    let fd = open_socket(
        rep,
        sa.domain(),
        sa.family_name(),
        libc::SOCK_STREAM,
        "SOCK_STREAM",
        true,
    )?;
    if let Err(e) = bounded::set_nonblocking(fd) {
        bounded::close(fd);
        return Err(IoFail::Errno(e));
    }
    let mut report = OpReport::new("connect");
    match shown {
        Some(a) => report.set("addr", a),
        None => report.set("addr_source", "proxy_variable"),
    }
    report.set("family", sa.family_name());
    report.set("type", "SOCK_STREAM");
    report.set("nonblocking", true);
    report.set("mechanism", raw::mechanism());
    let emitted = finish(report, raw::connect(fd, sa.as_ptr(), sa.len()));
    rep.emit(&emitted.report);
    if emitted.report.ret >= 0 {
        return Ok(fd);
    }
    let errno = emitted
        .report
        .errno
        .as_deref()
        .and_then(crate::errno::value);
    if errno != Some(libc::EINPROGRESS) {
        bounded::close(fd);
        return Err(IoFail::Errno(errno.unwrap_or(libc::EIO)));
    }
    if let Err(f) = bounded::wait_for(fd, libc::POLLOUT, deadline) {
        bounded::close(fd);
        return Err(f);
    }
    let mut report = OpReport::new("getsockopt");
    report.set("level", "SOL_SOCKET");
    report.set("option", "SO_ERROR");
    report.set("completes", "connect");
    let result = match bounded::so_error(fd) {
        Err(e) => {
            report.result(-1, Some(e));
            Err(IoFail::Errno(e))
        }
        Ok(0) => {
            report.set("so_error", Value::Null);
            report.result(0, None);
            Ok(fd)
        }
        Ok(e) => {
            // The call succeeded; the value it returned is the connect's
            // result, reported as the errno it is.
            report.set("so_error", crate::errno::name(e).unwrap_or("unknown"));
            report.result(-1, Some(e));
            Err(IoFail::Errno(e))
        }
    };
    rep.emit(&report);
    if result.is_err() {
        bounded::close(fd);
    }
    result
}

/// What reading a response head produced.
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub status_line: Vec<u8>,
    pub status_code: u16,
    /// Bytes up to and including the blank line.
    pub header_bytes: usize,
    /// `Some(n)` for a consistent Content-Length, `None` without one.
    pub content_length: Option<u64>,
    pub content_length_invalid: bool,
    pub chunked: bool,
    /// Bytes read past the head: the start of the body (or tunnel).
    pub leftover: Vec<u8>,
}

/// Why no usable head was read.
#[derive(Debug, PartialEq, Eq)]
pub enum HeadFail {
    Io(IoFail),
    /// The peer closed before the blank line; carries the bytes seen.
    EofBeforeHead(usize),
    /// More than [`MAX_HEAD_BYTES`] without a blank line.
    Overflow,
    MalformedStatusLine,
}

impl HeadFail {
    fn reason(&self) -> &'static str {
        match self {
            HeadFail::Io(IoFail::Timeout) => "timed_out",
            HeadFail::Io(IoFail::Errno(_)) => "io_error",
            HeadFail::EofBeforeHead(_) => "eof_before_head",
            HeadFail::Overflow => "header_overflow",
            HeadFail::MalformedStatusLine => "malformed_status_line",
        }
    }
}

/// Parse a complete head (everything before and including CRLF CRLF).
pub fn parse_head(head: &[u8]) -> Result<Head, HeadFail> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(HeadFail::MalformedStatusLine)?;
    let status_line = &head[..line_end];
    // `HTTP/1.<digit> <3 digits>`, then a space or the end of the line.
    let code = match status_line {
        [
            b'H',
            b'T',
            b'T',
            b'P',
            b'/',
            b'1',
            b'.',
            minor,
            b' ',
            a,
            b,
            c,
            rest @ ..,
        ] if minor.is_ascii_digit()
            && [a, b, c].iter().all(|d| d.is_ascii_digit())
            && (rest.is_empty() || rest[0] == b' ') =>
        {
            u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0')
        }
        _ => return Err(HeadFail::MalformedStatusLine),
    };
    let mut content_length: Option<u64> = None;
    let mut invalid = false;
    let mut chunked = false;
    for line in head[line_end + 2..].split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"content-length") {
            match std::str::from_utf8(value)
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
            {
                Some(n) if content_length.is_none_or(|c| c == n) => content_length = Some(n),
                _ => invalid = true,
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            let last = value
                .rsplit(|b| *b == b',')
                .next()
                .unwrap_or(b"")
                .trim_ascii();
            chunked |= last.eq_ignore_ascii_case(b"chunked");
        }
    }
    Ok(Head {
        status_line: status_line.to_vec(),
        status_code: code,
        header_bytes: head.len(),
        content_length: if invalid { None } else { content_length },
        content_length_invalid: invalid,
        chunked,
        leftover: Vec::new(),
    })
}

/// Read a response head, starting from `initial` bytes already read.
pub fn read_head(fd: c_int, initial: Vec<u8>, deadline: Deadline) -> Result<Head, HeadFail> {
    let mut buf = initial;
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let mut head = parse_head(&buf[..end + 4])?;
            head.leftover = buf[end + 4..].to_vec();
            return Ok(head);
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(HeadFail::Overflow);
        }
        match bounded::read_some(fd, &mut chunk, deadline) {
            Ok(0) => return Err(HeadFail::EofBeforeHead(buf.len())),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(f) => return Err(HeadFail::Io(f)),
        }
    }
}

/// What reading a body produced. Bytes are counted, never kept.
#[derive(Debug, PartialEq, Eq)]
pub struct Body {
    pub bytes: u64,
    pub framing: &'static str,
    pub complete: bool,
    pub fail: Option<IoFail>,
}

/// Count the body `head` announces. `tunnel` is a 2xx answer to CONNECT,
/// whose "body" is the tunnel and is not read here.
pub fn read_body(
    fd: c_int,
    head: &Head,
    head_request: bool,
    tunnel: bool,
    deadline: Deadline,
) -> Body {
    let code = head.status_code;
    if tunnel {
        return Body {
            bytes: 0,
            framing: "tunnel",
            complete: true,
            fail: None,
        };
    }
    if head_request || (100..200).contains(&code) || code == 204 || code == 304 {
        return Body {
            bytes: 0,
            framing: "none",
            complete: true,
            fail: None,
        };
    }
    if head.content_length_invalid && !head.chunked {
        return Body {
            bytes: 0,
            framing: "invalid_content_length",
            complete: false,
            fail: None,
        };
    }
    let (framing, want) = if head.chunked {
        ("chunked_undecoded", None)
    } else if let Some(n) = head.content_length {
        ("content_length", Some(n))
    } else {
        ("close", None)
    };
    let mut bytes = head.leftover.len() as u64;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(n) = want
            && bytes >= n
        {
            return Body {
                bytes,
                framing,
                complete: bytes == n,
                fail: None,
            };
        }
        if bytes >= MAX_BODY_BYTES {
            return Body {
                bytes,
                framing,
                complete: false,
                fail: None,
            };
        }
        match bounded::read_some(fd, &mut chunk, deadline) {
            Ok(0) => {
                return Body {
                    bytes,
                    framing,
                    complete: want.is_none(),
                    fail: None,
                };
            }
            Ok(n) => bytes += n as u64,
            Err(f) => {
                return Body {
                    bytes,
                    framing,
                    complete: false,
                    fail: Some(f),
                };
            }
        }
    }
}

/// Send `request` and read one response, reporting on `summary`. Returns
/// the head when a status line was read (for a CONNECT that became a
/// tunnel), `None` otherwise. Sets `ret`/`errno` on the summary.
fn exchange(
    fd: c_int,
    request: &[u8],
    initial: Vec<u8>,
    head_request: bool,
    connect_method: bool,
    deadline: Deadline,
    summary: &mut OpReport,
) -> Option<Head> {
    if let Err(f) = bounded::write_all(fd, request, deadline) {
        summary.set("bytes_sent", 0);
        summary.set("failed_step", "write");
        f.apply(summary);
        return None;
    }
    summary.set("bytes_sent", request.len());
    let head = match read_head(fd, initial, deadline) {
        Ok(h) => h,
        Err(fail) => {
            summary.set("failed_step", "read_head");
            summary.set("reason", fail.reason());
            if let HeadFail::EofBeforeHead(n) = fail {
                summary.set("bytes_before_eof", n);
            }
            match fail {
                HeadFail::Io(f) => f.apply(summary),
                _ => summary.result(-1, None),
            }
            return None;
        }
    };
    let tunnel = connect_method && (200..300).contains(&head.status_code);
    summary.set("status_line", bounded::preview(&head.status_line, 256));
    summary.set("status_code", head.status_code);
    summary.set("header_bytes", head.header_bytes);
    let body = read_body(fd, &head, head_request, tunnel, deadline);
    summary.set("body_bytes", body.bytes);
    summary.set("body_framing", body.framing);
    summary.set("body_complete", body.complete);
    if tunnel {
        summary.set("tunnel", true);
    }
    match body.fail {
        Some(IoFail::Timeout) => {
            summary.set("body_timed_out", true);
        }
        Some(IoFail::Errno(e)) => {
            summary.set("body_errno", crate::errno::name(e).unwrap_or("unknown"));
        }
        None => {}
    }
    summary.result(i64::from(head.status_code), None);
    Some(head)
}

fn proxy_refusal(rep: &Reporter, op: &str, var: &str, problem: &str, what: (&str, &str)) -> bool {
    let mut report = OpReport::new(op);
    report.set(what.0, what.1);
    report.set("proxy_var", var);
    report.set("refused", "proxy_variable_unusable");
    report.set("proxy_problem", problem);
    report.result(-1, None);
    let e = Emitted::unusable(report);
    rep.emit(&e.report);
    false
}

pub(crate) fn http_get(
    rep: &Reporter,
    url: &str,
    no_proxy: bool,
    host_header: Option<&str>,
    timeout_ms: u64,
    expect: &Expect,
) -> Result<bool, Usage> {
    let parsed = parse_http_url(url)?;
    let choice = if no_proxy {
        ProxyChoice::None
    } else {
        env_proxy(["http_proxy", "HTTP_PROXY"])
    };
    let deadline = Deadline::after_ms(timeout_ms);
    let host = host_header.unwrap_or(&parsed.authority);

    let mut summary = OpReport::new("http-get");
    summary.set("url", url);
    summary.set("method", "GET");
    summary.set("ignored_proxy_variables", no_proxy);
    summary.set("timeout_ms", timeout_ms);

    let (target_addr, shown, request_target) = match &choice {
        ProxyChoice::Unusable { var, problem } => {
            return Ok(proxy_refusal(rep, "http-get", var, problem, ("url", url)));
        }
        ProxyChoice::Use {
            var,
            addr,
            localhost_mapped,
        } => {
            summary.set("via_proxy", true);
            summary.set("proxy_var", *var);
            summary.set("proxy_localhost_mapped", *localhost_mapped);
            summary.set("request_form", "absolute");
            (
                *addr,
                None,
                format!("http://{}{}", parsed.authority, parsed.path),
            )
        }
        ProxyChoice::None => {
            let (addr, mapped) = numeric_host(&parsed.host, parsed.port).ok_or_else(|| {
                format!(
                    "`{}` is a name and no proxy variable is set. The fixture refuses names \
                     on purpose: resolving one would issue its own connects and pollute the trace.",
                    parsed.host
                )
            })?;
            summary.set("via_proxy", false);
            summary.set("proxy_var", Value::Null);
            summary.set("localhost_mapped", mapped);
            summary.set("request_form", "origin");
            (addr, Some(addr.to_string()), parsed.path.clone())
        }
    };
    summary.set("request_target", request_target.as_str());
    summary.set("host_header", host);

    let fd = match tcp_connect(rep, target_addr, shown.as_deref(), deadline) {
        Ok(fd) => fd,
        Err(f) => {
            summary.set("failed_step", "connect");
            f.apply(&mut summary);
            let e = Emitted::done(summary);
            rep.emit(&e.report);
            return Ok(e.satisfies(expect));
        }
    };
    let request = format!(
        "GET {request_target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ouro-fixture\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n"
    );
    exchange(
        fd,
        request.as_bytes(),
        Vec::new(),
        false,
        false,
        deadline,
        &mut summary,
    );
    bounded::close(fd);
    let e = Emitted::done(summary);
    rep.emit(&e.report);
    Ok(e.satisfies(expect))
}

pub(crate) fn http_connect(
    rep: &Reporter,
    authority: &str,
    then_get: Option<&str>,
    host_header: Option<&str>,
    timeout_ms: u64,
    expect: &Expect,
) -> Result<bool, Usage> {
    parse_authority(authority, None).map_err(|e| format!("HOST:PORT: {e}"))?;
    if let Some(p) = then_get
        && !p.starts_with('/')
    {
        return Err(format!("--then-get `{p}` must start with `/`"));
    }
    let deadline = Deadline::after_ms(timeout_ms);
    let host = host_header.unwrap_or(authority);

    let mut summary = OpReport::new("http-connect");
    summary.set("authority", authority);
    summary.set("method", "CONNECT");
    summary.set("timeout_ms", timeout_ms);

    let proxy = match env_proxy(["https_proxy", "HTTPS_PROXY"]) {
        ProxyChoice::Unusable { var, problem } => {
            return Ok(proxy_refusal(
                rep,
                "http-connect",
                var,
                problem,
                ("authority", authority),
            ));
        }
        ProxyChoice::None => {
            summary.set("refused", "no_proxy_variable");
            summary.set("proxy_var", Value::Null);
            summary.result(-1, None);
            let e = Emitted::unusable(summary);
            rep.emit(&e.report);
            return Ok(false);
        }
        ProxyChoice::Use {
            var,
            addr,
            localhost_mapped,
        } => {
            summary.set("via_proxy", true);
            summary.set("proxy_var", var);
            summary.set("proxy_localhost_mapped", localhost_mapped);
            addr
        }
    };
    summary.set("request_target", authority);
    summary.set("host_header", host);

    let fd = match tcp_connect(rep, proxy, None, deadline) {
        Ok(fd) => fd,
        Err(f) => {
            summary.set("failed_step", "connect");
            f.apply(&mut summary);
            let e = Emitted::done(summary);
            rep.emit(&e.report);
            return Ok(e.satisfies(expect));
        }
    };
    let request =
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ouro-fixture\r\n\r\n");
    let head = exchange(
        fd,
        request.as_bytes(),
        Vec::new(),
        false,
        true,
        deadline,
        &mut summary,
    );
    let outer = Emitted::done(summary);
    rep.emit(&outer.report);
    let mut ok = outer.satisfies(expect);

    if let (Some(path), Some(head)) = (then_get, head)
        && (200..300).contains(&head.status_code)
    {
        let mut inner = OpReport::new("http-get");
        inner.set("via", "tunnel");
        inner.set("authority", authority);
        inner.set("method", "GET");
        inner.set("request_form", "origin");
        inner.set("request_target", path);
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: ouro-fixture\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n"
        );
        exchange(
            fd,
            request.as_bytes(),
            head.leftover,
            false,
            false,
            deadline,
            &mut inner,
        );
        let e = Emitted::done(inner);
        rep.emit(&e.report);
        ok &= e.satisfies(&Expect::Ok);
    }
    bounded::close(fd);
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_is_encoded_label_by_label() {
        let q = encode_query(0x1234, "a.bc.").unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00], "RD only");
        assert_eq!(&q[4..6], &[0, 1], "one question");
        assert_eq!(&q[12..], &[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        assert!(encode_query(1, "a..b").is_err());
        assert!(encode_query(1, &"x".repeat(64)).is_err());
        assert!(encode_query(1, "bücher.example").is_err());
        let long = vec!["abcdefghij"; 30].join(".");
        assert!(encode_query(1, &long).is_err(), "over 255 on the wire");
    }

    fn response(ancount: u16, answers: &[u8]) -> Vec<u8> {
        let mut r = vec![0xAB, 0xCD, 0x81, 0x80, 0, 1];
        r.extend_from_slice(&ancount.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        r.extend_from_slice(&[1, b'x', 0, 0, 1, 0, 1]);
        r.extend_from_slice(answers);
        r
    }

    const A_ANSWER: [u8; 16] = [0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7];

    #[test]
    fn a_response_yields_its_header_and_a_records() {
        let r = parse_response(&response(1, &A_ANSWER)).unwrap();
        assert_eq!(r.id, 0xABCD);
        assert!(r.is_response);
        assert_eq!(r.rcode, 0);
        assert_eq!(r.ancount, 1);
        assert_eq!(r.a, vec![Ipv4Addr::new(192, 0, 2, 7)]);
        assert_eq!(r.malformed, None);
    }

    #[test]
    fn hostile_responses_are_bounded_and_never_read_out_of_range() {
        // The parser's precondition is the buffer's own length: try to make
        // it read past the end, loop, or trust a count.
        assert_eq!(parse_response(&[0; 11]), Err("short_header"));
        // An answer count far above what is present.
        let r = parse_response(&response(u16::MAX, &A_ANSWER)).unwrap();
        assert_eq!(r.ancount, u16::MAX, "the claim is reported as sent");
        assert_eq!(r.a.len(), 1);
        assert!(r.malformed.is_some());
        // rdlength pointing past the end.
        let mut bad = A_ANSWER;
        bad[11] = 200;
        let r = parse_response(&response(1, &bad)).unwrap();
        assert_eq!(r.malformed, Some("rdata_out_of_bounds"));
        // A compression pointer to itself: skipping never follows it.
        let r = parse_response(&response(1, &[0xC0, 30, 0, 1])).unwrap();
        assert_eq!(r.malformed, Some("truncated_answer"));
        // A label length running off the end.
        let mut q = response(0, &[]);
        q.truncate(12);
        q.extend_from_slice(&[63, b'a']);
        let r = parse_response(&q).unwrap();
        assert_eq!(r.malformed, Some("name_out_of_bounds"));
        // Reserved label type bits.
        let mut q = response(0, &[]);
        q.truncate(12);
        q.push(0x80);
        assert_eq!(
            parse_response(&q).unwrap().malformed,
            Some("reserved_label_type")
        );
        // Every prefix of a valid response parses or refuses; none panics.
        let full = response(1, &A_ANSWER);
        for n in 0..full.len() {
            let _ = parse_response(&full[..n]);
        }
    }

    #[test]
    fn urls_and_authorities_parse_strictly() {
        let u = parse_http_url("http://127.0.0.1:8080/a/b?c=d#frag").unwrap();
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 8080);
        assert_eq!(u.authority, "127.0.0.1:8080");
        assert_eq!(u.path, "/a/b?c=d");
        let u = parse_http_url("HTTP://example.test").unwrap();
        assert_eq!((u.port, u.path.as_str()), (80, "/"));
        let u = parse_http_url("http://[::1]:81?q").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("::1", 81, "/?q")
        );
        assert!(parse_http_url("https://x/").unwrap_err().contains("no TLS"));
        assert!(parse_http_url("ftp://x/").is_err());
        assert!(parse_http_url("http://u:p@x/").is_err(), "userinfo refused");
        assert!(parse_http_url("http://x:99999/").is_err());
        assert!(parse_http_url("http://[::1/").is_err());
        assert!(
            parse_authority("host", None)
                .unwrap_err()
                .contains("no port")
        );
        assert_eq!(
            parse_authority("a.b:443", None).unwrap(),
            ("a.b".into(), 443)
        );
    }

    #[test]
    fn proxy_values_are_interpreted_without_being_echoed() {
        assert_eq!(
            parse_proxy_value(b"http://127.0.0.1:3128"),
            Ok(("127.0.0.1:3128".parse().unwrap(), false))
        );
        assert_eq!(
            parse_proxy_value(b"127.0.0.1:3128/"),
            Ok(("127.0.0.1:3128".parse().unwrap(), false))
        );
        assert_eq!(
            parse_proxy_value(b"http://localhost:8080"),
            Ok(("127.0.0.1:8080".parse().unwrap(), true))
        );
        assert_eq!(
            parse_proxy_value(b"http://[::1]:1"),
            Ok(("[::1]:1".parse().unwrap(), false))
        );
        assert_eq!(
            parse_proxy_value(b"http://u:secret@127.0.0.1:1"),
            Err("userinfo_not_supported")
        );
        assert_eq!(
            parse_proxy_value(b"https://127.0.0.1:1"),
            Err("scheme_not_http")
        );
        assert_eq!(
            parse_proxy_value(b"socks5://127.0.0.1:1"),
            Err("scheme_not_http")
        );
        assert_eq!(
            parse_proxy_value(b"http://proxy.example:3128"),
            Err("name_host_not_supported")
        );
        assert_eq!(parse_proxy_value(b"http://127.0.0.1"), Err("missing_port"));
        assert_eq!(parse_proxy_value(&[0xff, 0xfe]), Err("not_utf8"));
    }

    #[test]
    fn lowercase_wins_and_an_empty_value_is_unset() {
        use std::ffi::OsString;
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |n: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| OsString::from(*v))
            }
        };
        let names = ["http_proxy", "HTTP_PROXY"];
        assert_eq!(proxy_choice(names, env(&[])), ProxyChoice::None);
        match proxy_choice(
            names,
            env(&[("http_proxy", "127.0.0.1:1"), ("HTTP_PROXY", "127.0.0.1:2")]),
        ) {
            ProxyChoice::Use { var, addr, .. } => {
                assert_eq!(var, "http_proxy");
                assert_eq!(addr.port(), 1);
            }
            other => panic!("{other:?}"),
        }
        match proxy_choice(
            names,
            env(&[("http_proxy", ""), ("HTTP_PROXY", "127.0.0.1:2")]),
        ) {
            ProxyChoice::Use { var, .. } => assert_eq!(var, "HTTP_PROXY"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            proxy_choice(names, env(&[("HTTP_PROXY", "http://proxy.example:1")])),
            ProxyChoice::Unusable {
                var: "HTTP_PROXY",
                problem: "name_host_not_supported"
            },
            "an unusable variable is refused, not skipped"
        );
    }

    #[test]
    fn a_head_parses_status_and_framing() {
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").unwrap();
        assert_eq!(h.status_code, 200);
        assert_eq!(h.content_length, Some(5));
        assert_eq!(h.header_bytes, 38);
        let h = parse_head(b"HTTP/1.0 403 Forbidden\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
            .unwrap();
        assert!(h.chunked);
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-length: 6\r\n\r\n")
            .unwrap();
        assert!(h.content_length_invalid);
        assert_eq!(h.content_length, None);
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-length: 5\r\n\r\n")
            .unwrap();
        assert_eq!(
            h.content_length,
            Some(5),
            "an identical repeat is consistent"
        );
        assert_eq!(
            parse_head(b"HTTP/2 200\r\n\r\n"),
            Err(HeadFail::MalformedStatusLine)
        );
        assert_eq!(
            parse_head(b"HTTP/1.1 2x0 OK\r\n\r\n"),
            Err(HeadFail::MalformedStatusLine)
        );
        assert_eq!(
            parse_head(b"HTTP/1.x 200 OK\r\n\r\n"),
            Err(HeadFail::MalformedStatusLine),
            "the minor version is a digit"
        );
        assert_eq!(
            parse_head(b"HTTP/1.1 2000 OK\r\n\r\n"),
            Err(HeadFail::MalformedStatusLine),
            "exactly three status digits"
        );
        assert_eq!(
            parse_head(b"HTTP/1.1 204\r\n\r\n").unwrap().status_code,
            204
        );
        assert_eq!(parse_head(b"garbage"), Err(HeadFail::MalformedStatusLine));
    }
}
