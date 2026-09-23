//! A loopback HTTP/1.1 fixture server for proxy and egress tests.
//!
//! It answers every well-formed request with `200 OK` and a fixed body
//! (`Content-Length`, `Connection: close`), and records what it saw: method,
//! request target (so absolute form through a proxy is visible) and the
//! `Host` header. A request is recorded *before* its response is written,
//! so a client that has read a response proves the record exists: tests
//! never sleep to wait for one.
//!
//! One thread accepts and serves connections one at a time, each bounded by
//! a deadline, and stops when told through a private pipe (no polling of a
//! flag). Dropping the server stops it.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::bounded::{self, Deadline};

/// How long one connection may take to send its request head.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// The largest request head the server reads.
pub const MAX_REQUEST_HEAD: usize = 32 * 1024;

/// One request the server saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenRequest {
    pub method: String,
    /// The request target exactly as sent: `/path` in origin form,
    /// `http://host/path` in absolute form, `host:port` for CONNECT.
    pub target: String,
    /// The first `Host` header's value, when there was one.
    pub host: Option<String>,
    /// How many `Host` headers the request carried.
    pub host_headers: usize,
}

#[derive(Default)]
struct Shared {
    requests: Vec<SeenRequest>,
    connections: usize,
    malformed: usize,
}

/// A running fixture server. Stops when dropped.
pub struct HttpServer {
    addr: SocketAddr,
    shared: Arc<Mutex<Shared>>,
    wake: Option<OwnedFd>,
    thread: Option<JoinHandle<()>>,
}

/// Parse a request head: the request line and the `Host` headers.
#[must_use]
pub fn parse_request_head(head: &[u8]) -> Option<SeenRequest> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with("HTTP/1.") || method.is_empty() {
        return None;
    }
    let mut host = None;
    let mut host_headers = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("host")
        {
            host_headers += 1;
            if host.is_none() {
                host = Some(value.trim().to_string());
            }
        }
    }
    Some(SeenRequest {
        method: method.to_string(),
        target: target.to_string(),
        host,
        host_headers,
    })
}

/// Read a request head (through the blank line) from `fd`, bounded.
fn read_request_head(fd: std::ffi::c_int, deadline: Deadline) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf.truncate(end + 4);
            return Some(buf);
        }
        if buf.len() > MAX_REQUEST_HEAD {
            return None;
        }
        match bounded::read_some(fd, &mut chunk, deadline) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn serve_one(conn: &std::net::TcpStream, body: &[u8], shared: &Mutex<Shared>) {
    let fd = conn.as_raw_fd();
    let deadline = Deadline::after_ms(REQUEST_DEADLINE.as_millis() as u64);
    let seen = read_request_head(fd, deadline).and_then(|h| parse_request_head(&h));
    let response = match seen {
        Some(req) => {
            // Record first: a client holding the response proves the record.
            shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .requests
                .push(req);
            let mut r = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            r.extend_from_slice(body);
            r
        }
        None => {
            shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .malformed += 1;
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        }
    };
    let _ = bounded::write_all(fd, &response, deadline);
}

impl HttpServer {
    /// Serve `body` on 127.0.0.1 at a free port.
    pub fn start(body: impl Into<Vec<u8>>) -> io::Result<HttpServer> {
        HttpServer::bind(SocketAddr::from(([127, 0, 0, 1], 0)), body)
    }

    /// Serve `body` on `addr` (port 0 picks a free one), e.g. `[::1]:0`.
    pub fn bind(addr: SocketAddr, body: impl Into<Vec<u8>>) -> io::Result<HttpServer> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let (wake_r, wake_w) = super::pipes::cloexec_pipe()?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let body: Vec<u8> = body.into();
        let worker_shared = Arc::clone(&shared);
        let thread = std::thread::spawn(move || {
            let mut fds = [
                libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake_r.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            loop {
                // SAFETY: `fds` is a live array of two pollfds and the count
                // passed is its length.
                let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
                if r < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return;
                }
                if fds[1].revents != 0 {
                    return;
                }
                while let Ok((conn, _)) = listener.accept() {
                    worker_shared
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .connections += 1;
                    let _ = conn.set_nonblocking(true);
                    serve_one(&conn, &body, &worker_shared);
                }
            }
        });
        Ok(HttpServer {
            addr,
            shared,
            wake: Some(wake_w),
            thread: Some(thread),
        })
    }

    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://<addr><path>`, with an IPv6 address bracketed.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Every well-formed request seen so far, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<SeenRequest> {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .requests
            .clone()
    }

    /// Connections accepted so far, including ones that sent nothing usable.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connections
    }

    /// Connections whose request head was malformed, oversized or cut off.
    #[must_use]
    pub fn malformed(&self) -> usize {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .malformed
    }

    /// Stop serving and return every request seen.
    #[must_use]
    pub fn stop(mut self) -> Vec<SeenRequest> {
        self.shutdown();
        self.requests()
    }

    fn shutdown(&mut self) {
        if let Some(w) = self.wake.take() {
            // Closing the write end makes the read end readable (EOF).
            drop(w);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn a_request_is_recorded_before_its_response_arrives() {
        let server = HttpServer::start(b"hello".to_vec()).unwrap();
        let mut s = std::net::TcpStream::connect(server.addr()).unwrap();
        s.write_all(b"GET http://example.test/x HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        s.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"\r\n\r\nhello"));
        // No wait: the record was made before the response was written.
        let seen = server.requests();
        assert_eq!(
            seen,
            vec![SeenRequest {
                method: "GET".into(),
                target: "http://example.test/x".into(),
                host: Some("example.test".into()),
                host_headers: 1,
            }]
        );
        assert_eq!(server.connections(), 1);
        assert_eq!(server.stop().len(), 1);
    }

    #[test]
    fn a_malformed_head_is_counted_and_answered_400() {
        let server = HttpServer::start(Vec::new()).unwrap();
        let mut s = std::net::TcpStream::connect(server.addr()).unwrap();
        s.write_all(b"NONSENSE\r\n\r\n").unwrap();
        let mut response = Vec::new();
        s.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 400"));
        assert!(server.requests().is_empty());
        assert_eq!(server.malformed(), 1);
    }

    #[test]
    fn request_heads_parse_strictly() {
        let r = parse_request_head(b"CONNECT a.test:443 HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n")
            .unwrap();
        assert_eq!(r.method, "CONNECT");
        assert_eq!(r.target, "a.test:443");
        assert_eq!(r.host.as_deref(), Some("a"));
        assert_eq!(r.host_headers, 2);
        assert!(parse_request_head(b"GET / HTTP/2\r\n\r\n").is_none());
        assert!(parse_request_head(b"GET  / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request_head(&[0xff, b' ', b'/', b' ']).is_none());
    }

    #[test]
    fn stopping_is_prompt_and_idempotent_with_drop() {
        let server = HttpServer::start(Vec::new()).unwrap();
        let started = std::time::Instant::now();
        drop(server);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
