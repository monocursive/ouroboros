//! The in-namespace loopback bridge of the `agent` profile: `ouro-jail
//! __bridge`.
//!
//! jail-v1 §10: "The bridge listens only on `127.0.0.1:3128` and connects to
//! `/run/ouro/proxy/proxy.sock`." It is a byte relay and nothing else: it
//! parses no request, decides nothing and holds no authority beyond its two
//! sockets. The proxy outside decides every request; a child that connects to
//! `/run/ouro/proxy/proxy.sock` directly reaches the same proxy under the same
//! policy.
//!
//! The launcher starts it before the target is released, with a double fork,
//! `/dev/null` as stdio, no other descriptor, an empty environment and a
//! session of its own. It runs under the same seccomp filters as the child,
//! so its `connect` to the proxy socket is mediated: the supervisor allows
//! exactly the pinned proxy socket identity, whatever the path now names.
//! That is what makes the path unredirectable by a child rename, unlink,
//! symlink or mount change — not anything the bridge checks itself.
//!
//! It is one thread with nonblocking sockets and `poll`, bounded at
//! [`MAX_CONNECTIONS`] relays with [`BUFFER`] bytes per direction, so its
//! resource use is fixed, and it charges the attempt's cgroup like any other
//! process in the attempt. It never exits on its own; it dies with the
//! namespace. When the proxy is unreachable it closes the client, and nothing
//! falls back to direct egress: it has no other route.

use std::ffi::OsString;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;

/// The hidden subcommand token.
pub const SUBCOMMAND: &str = "__bridge";
/// The only address the bridge listens on.
pub const LISTEN: &str = "127.0.0.1:3128";
/// The proxy variables' value (jail-v1 §10).
pub const PROXY_URL: &str = "http://127.0.0.1:3128";
/// The proxy socket as the sandbox sees it.
pub const PROXY_PATH: &str = "/run/ouro/proxy/proxy.sock";
/// The most relays at once; beyond it, pending clients wait in the kernel's
/// backlog. It matches the proxy's own connection budget (§10).
pub const MAX_CONNECTIONS: usize = 128;
/// Bytes buffered per relay direction.
pub const BUFFER: usize = 16 * 1024;

/// Exit status when the bridge cannot bind its address.
pub const EXIT_BIND_FAILED: i32 = 126;
/// Exit status for arguments the bridge does not take.
pub const EXIT_USAGE: i32 = 125;

/// The environment variables `agent` sets, with their value (jail-v1 §10):
/// the three proxy variables in both spellings, and an empty `NO_PROXY`.
#[must_use]
pub fn proxy_environment() -> Vec<(&'static str, &'static str)> {
    vec![
        ("HTTP_PROXY", PROXY_URL),
        ("HTTPS_PROXY", PROXY_URL),
        ("ALL_PROXY", PROXY_URL),
        ("http_proxy", PROXY_URL),
        ("https_proxy", PROXY_URL),
        ("all_proxy", PROXY_URL),
        ("NO_PROXY", ""),
        ("no_proxy", ""),
    ]
}

/// Run the bridge. Never returns.
pub fn bridge_main(args: &[OsString]) -> ! {
    if !args.is_empty() {
        std::process::exit(EXIT_USAGE);
    }
    let listener = match TcpListener::bind(LISTEN) {
        Ok(listener) => listener,
        Err(_) => std::process::exit(EXIT_BIND_FAILED),
    };
    if listener.set_nonblocking(true).is_err() {
        std::process::exit(EXIT_BIND_FAILED);
    }
    serve(&listener, &|| UnixStream::connect(PROXY_PATH));
    // `serve` only returns when polling itself fails, which leaves nothing
    // to relay with; the attempt's clients then see connections refused.
    std::process::exit(0);
}

/// One direction of a relay.
struct Pipe {
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
    /// The reading side reached EOF.
    eof: bool,
    /// The writing side was shut down after the EOF was forwarded.
    shut: bool,
}

impl Pipe {
    fn new() -> Self {
        Pipe {
            buffer: vec![0u8; BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            eof: false,
            shut: false,
        }
    }

    fn has_data(&self) -> bool {
        self.start < self.end
    }

    fn wants_read(&self) -> bool {
        !self.eof && self.end < self.buffer.len()
    }

    /// Reads what is available; `Err` ends the relay.
    fn fill(&mut self, from: &mut impl io::Read) -> io::Result<()> {
        match from.read(&mut self.buffer[self.end..]) {
            Ok(0) => self.eof = true,
            Ok(n) => self.end += n,
            Err(error) if would_block(&error) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Writes what is buffered; `Err` ends the relay. An emptied buffer is
    /// rewound at once: a full buffer that drained must be readable again,
    /// or neither side would ever be polled for it.
    fn drain(&mut self, to: &mut impl io::Write) -> io::Result<()> {
        while self.has_data() {
            match to.write(&self.buffer[self.start..self.end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.start += n,
                Err(error) if would_block(&error) => break,
                Err(error) => return Err(error),
            }
        }
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        Ok(())
    }
}

fn would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// One client and its proxy connection.
struct Relay {
    client: TcpStream,
    upstream: UnixStream,
    /// Client to proxy.
    up: Pipe,
    /// Proxy to client.
    down: Pipe,
}

impl Relay {
    fn finished(&self) -> bool {
        self.up.shut && self.down.shut
    }

    /// Forwards an EOF once everything before it was written.
    fn propagate_eof(&mut self) {
        if self.up.eof && !self.up.has_data() && !self.up.shut {
            let _ = self.upstream.shutdown(Shutdown::Write);
            self.up.shut = true;
        }
        if self.down.eof && !self.down.has_data() && !self.down.shut {
            let _ = self.client.shutdown(Shutdown::Write);
            self.down.shut = true;
        }
    }
}

/// The relay loop. `connect` opens one proxy connection; the live bridge
/// passes [`PROXY_PATH`], tests pass their own socket.
///
/// Returns only when `poll` fails for a reason other than `EINTR`.
pub fn serve(listener: &TcpListener, connect: &dyn Fn() -> io::Result<UnixStream>) {
    let mut relays: Vec<Relay> = Vec::new();
    loop {
        let accepting = relays.len() < MAX_CONNECTIONS;
        let mut fds = Vec::with_capacity(1 + relays.len() * 2);
        fds.push(libc::pollfd {
            fd: listener.as_raw_fd(),
            events: if accepting { libc::POLLIN } else { 0 },
            revents: 0,
        });
        for relay in &relays {
            let mut client = 0;
            if relay.up.wants_read() {
                client |= libc::POLLIN;
            }
            if relay.down.has_data() {
                client |= libc::POLLOUT;
            }
            let mut upstream = 0;
            if relay.down.wants_read() {
                upstream |= libc::POLLIN;
            }
            if relay.up.has_data() {
                upstream |= libc::POLLOUT;
            }
            // A side with nothing asked of it is left out (a negative fd is
            // ignored by poll): a half-closed peer reports POLLHUP whether
            // or not anything was requested, which would otherwise spin.
            fds.push(libc::pollfd {
                fd: if client == 0 {
                    -1
                } else {
                    relay.client.as_raw_fd()
                },
                events: client,
                revents: 0,
            });
            fds.push(libc::pollfd {
                fd: if upstream == 0 {
                    -1
                } else {
                    relay.upstream.as_raw_fd()
                },
                events: upstream,
                revents: 0,
            });
        }
        let count = libc::nfds_t::try_from(fds.len()).unwrap_or(libc::nfds_t::MAX);
        // SAFETY: `fds` is a live, initialized array of `count` pollfds; poll
        // writes only their `revents`.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), count, -1) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }

        for (index, relay) in relays.iter_mut().enumerate() {
            let client = fds[1 + index * 2].revents;
            let upstream = fds[2 + index * 2].revents;
            if step(relay, client, upstream).is_err() {
                // Either side failed: close both. The client sees its
                // connection end; nothing else is attempted for it.
                relay.up.shut = true;
                relay.down.shut = true;
            }
        }
        relays.retain(|relay| !relay.finished());

        if accepting && fds[0].revents != 0 {
            accept_all(listener, connect, &mut relays);
        }
    }
}

fn step(relay: &mut Relay, client: libc::c_short, upstream: libc::c_short) -> io::Result<()> {
    let readable = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
    if client & libc::POLLNVAL != 0 || upstream & libc::POLLNVAL != 0 {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    if client & readable != 0 && relay.up.wants_read() {
        relay.up.fill(&mut relay.client)?;
    }
    if upstream & readable != 0 && relay.down.wants_read() {
        relay.down.fill(&mut relay.upstream)?;
    }
    if relay.up.has_data() {
        relay.up.drain(&mut relay.upstream)?;
    }
    if relay.down.has_data() {
        relay.down.drain(&mut relay.client)?;
    }
    relay.propagate_eof();
    // A relay ends when both directions forwarded their EOF, or when a read
    // or a write fails. A hang-up alone ends nothing: a half-closed client
    // still waits for the proxy's response.
    Ok(())
}

fn accept_all(
    listener: &TcpListener,
    connect: &dyn Fn() -> io::Result<UnixStream>,
    relays: &mut Vec<Relay>,
) {
    while relays.len() < MAX_CONNECTIONS {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(_) => return,
        };
        // A proxy that cannot be reached (dead, replaced, refused by the
        // mediator) closes this client and nothing else: fail closed.
        let Ok(upstream) = connect() else {
            let _ = client.shutdown(Shutdown::Both);
            continue;
        };
        if client.set_nonblocking(true).is_err() || upstream.set_nonblocking(true).is_err() {
            continue;
        }
        relays.push(Relay {
            client,
            upstream,
            up: Pipe::new(),
            down: Pipe::new(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;

    /// A bridge on an ephemeral loopback port, relaying to a Unix listener
    /// this test owns, on a thread that lives for the test process.
    fn bridge_to(path: std::path::PathBuf) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || serve(&listener, &|| UnixStream::connect(&path)));
        address
    }

    #[test]
    fn bytes_flow_both_ways_and_half_close_is_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let upstream = UnixListener::bind(&path).unwrap();
        let address = bridge_to(path);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(b"reply:").unwrap();
            stream.write_all(&request).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        let payload = vec![7u8; 3 * BUFFER + 11];
        client.write_all(&payload).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        server.join().unwrap();
        assert_eq!(&reply[..6], b"reply:");
        assert_eq!(&reply[6..], &payload[..]);
    }

    #[test]
    fn a_full_buffer_that_drains_is_readable_again() {
        let mut pipe = Pipe::new();
        let bytes = vec![1u8; 2 * BUFFER];
        let mut source: &[u8] = &bytes;
        pipe.fill(&mut source).unwrap();
        assert!(!pipe.wants_read(), "full");
        let mut sink = Vec::new();
        pipe.drain(&mut sink).unwrap();
        assert_eq!(sink.len(), BUFFER);
        assert!(pipe.wants_read(), "a drained buffer takes the next bytes");
        pipe.fill(&mut source).unwrap();
        pipe.drain(&mut sink).unwrap();
        assert_eq!(sink.len(), 2 * BUFFER);
    }

    #[test]
    fn an_unreachable_proxy_closes_the_client_and_nothing_else_happens() {
        let dir = tempfile::tempdir().unwrap();
        let address = bridge_to(dir.path().join("absent.sock"));
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let _ = client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n");
        let mut reply = Vec::new();
        let read = client.read_to_end(&mut reply);
        assert!(
            read.is_ok() || read.is_err_and(|e| e.kind() == io::ErrorKind::ConnectionReset),
            "the client is closed, not left hanging"
        );
        assert!(reply.is_empty(), "the bridge never answers for the proxy");
    }

    #[test]
    fn the_proxy_environment_is_both_spellings_and_an_empty_no_proxy() {
        let env = proxy_environment();
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            for spelling in [name.to_owned(), name.to_ascii_lowercase()] {
                assert!(
                    env.iter()
                        .any(|(key, value)| *key == spelling && *value == PROXY_URL),
                    "{spelling}"
                );
            }
        }
        assert!(env.contains(&("NO_PROXY", "")) && env.contains(&("no_proxy", "")));
        assert_eq!(PROXY_URL, format!("http://{LISTEN}"));
    }
}
