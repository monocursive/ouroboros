//! Byte relays with backpressure.
//!
//! Each direction owns one fixed buffer (its share of the relay budget) and
//! writes everything it read before reading again, so a slow reader slows its
//! writer and nothing is buffered beyond that share. Response bodies are
//! streamed, never collected.
//!
//! Both directions share the connection's two sockets through `Arc`s, so a
//! relayed connection holds exactly two descriptors: the client's and the
//! destination's. Everything a relay needs besides the sockets (its second
//! thread) is set up before the first byte is written to the client, so a
//! setup failure can still be answered.
//!
//! Termination: when the destination closes or fails, the whole connection
//! closes, so a dead upstream always ends the request. When the client closes
//! its sending side, the destination's sending side is half-closed and the
//! response continues until the destination closes; when the client closes
//! completely, the whole connection closes (see `sys::wait_peer_closed`).

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use super::EndReason;
use super::http::Framing;
use super::sys;

/// Counters and the first way the relay ended.
pub(super) struct RelayOutcome {
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Client bytes after the first request, read and not forwarded.
    pub discarded: u64,
    pub end: EndReason,
    /// Whether the request head (the relay's prefix: a rewritten head, or a
    /// tunnel's early bytes) reached the upstream socket whole.
    pub head_sent: bool,
    /// Whether some of the head may have reached the upstream without the
    /// whole of it being confirmed written: a head whose write failed.
    pub head_partial: bool,
    /// J13: the vault credentials substituted into that head, sorted and
    /// unique; empty unless `head_sent`.
    pub credentials: Vec<String>,
    /// J13: the same, when the head is `head_partial`.
    pub unconfirmed: Vec<String>,
}

impl RelayOutcome {
    /// Copies what the relay established into its connection's result: the
    /// counters and, J13, the credentials its head carried, sent or
    /// unconfirmed.
    pub(super) fn record(&self, result: &mut super::ProxyResult) {
        result.bytes_in = self.bytes_in;
        result.bytes_out = self.bytes_out;
        result.discarded_bytes = self.discarded;
        result.credentials = self.credentials.clone();
        result.credentials_unconfirmed = self.unconfirmed.clone();
    }

    /// J13: names `ids`, the credentials substituted into this relay's head,
    /// for its result: used when the head reached the upstream whole,
    /// unconfirmed when it was begun and not confirmed whole, and nowhere
    /// when none of it left.
    pub(super) fn attribute(&mut self, ids: Vec<String>) {
        if self.head_sent {
            self.credentials = ids;
        } else if self.head_partial {
            self.unconfirmed = ids;
        }
    }
}

/// The relay's second thread could not be started; nothing was written to
/// the client or the destination.
pub(super) struct SetupFailed;

/// Records the first termination only.
#[derive(Clone, Default)]
struct FirstEnd(Arc<Mutex<Option<EndReason>>>);

impl FirstEnd {
    fn set(&self, end: EndReason) {
        let mut slot = crate::sync::lock(&self.0);
        if slot.is_none() {
            *slot = Some(end);
        }
    }

    fn get(&self) -> Option<EndReason> {
        *crate::sync::lock(&self.0)
    }
}

enum Pump {
    /// The source reached EOF.
    SourceEof,
    /// Reading the source failed.
    SourceError,
    /// Writing the sink failed.
    SinkError,
}

fn pump(mut source: impl Read, mut sink: impl Write, buf: &mut [u8], count: &mut u64) -> Pump {
    loop {
        let read = match source.read(buf) {
            Ok(0) => return Pump::SourceEof,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Pump::SourceError,
        };
        if sink.write_all(buf.get(..read).unwrap_or_default()).is_err() {
            return Pump::SinkError;
        }
        *count += u64::try_from(read).unwrap_or(u64::MAX);
    }
}

fn close_both(client: &UnixStream, upstream: &TcpStream) {
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
}

/// The destination-to-client direction, run on the calling thread. Any end
/// closes the whole connection.
fn response_direction(
    client: &UnixStream,
    upstream: &TcpStream,
    chunk: usize,
    first: &FirstEnd,
    finished: &AtomicBool,
) -> u64 {
    let mut buf = vec![0u8; chunk];
    let mut count = 0u64;
    let end = match pump(upstream, client, &mut buf, &mut count) {
        Pump::SourceEof => EndReason::UpstreamClosed,
        Pump::SourceError => EndReason::UpstreamError,
        Pump::SinkError => EndReason::ClientError,
    };
    first.set(end);
    finished.store(true, Ordering::SeqCst);
    let _ = (&*client).flush();
    close_both(client, upstream);
    count
}

/// After the client stopped sending: wait until it has closed completely or
/// the relay has finished, then close the whole connection.
fn after_client_eof(client: &UnixStream, upstream: &TcpStream, finished: &AtomicBool) {
    sys::wait_peer_closed(client.as_fd(), finished);
    close_both(client, upstream);
}

/// The request-direction worker's result: forwarded and discarded bytes.
type Forwarded = (u64, u64);

/// Starts the request-direction worker, which waits for the go-ahead before
/// touching either socket. `false` (or a dropped sender) ends it at once.
fn spawn_worker(
    work: impl FnOnce() -> Forwarded + Send + 'static,
) -> Result<(mpsc::SyncSender<bool>, thread::JoinHandle<Forwarded>), SetupFailed> {
    let (go, wait) = mpsc::sync_channel::<bool>(1);
    let handle = thread::Builder::new()
        .name("ukai-proxy-relay".to_owned())
        .stack_size(64 * 1024)
        .spawn(move || {
            if wait.recv() == Ok(true) {
                work()
            } else {
                (0, 0)
            }
        })
        .map_err(|_| SetupFailed)?;
    Ok((go, handle))
}

/// The request direction's work: given both sockets, the first-end record
/// and the response direction's "finished" flag, forward and count.
type Worker =
    Box<dyn FnOnce(Arc<UnixStream>, Arc<TcpStream>, FirstEnd, Arc<AtomicBool>) -> Forwarded + Send>;

/// Runs one relay: `prefix` (a rewritten head, or a tunnel's early bytes)
/// goes to the destination first; then the request direction runs on a
/// worker thread and the response direction on this one, until the
/// connection ends.
fn relay(
    client: &Arc<UnixStream>,
    upstream: &Arc<TcpStream>,
    prefix: &[u8],
    chunk: usize,
    request: Worker,
) -> Result<RelayOutcome, SetupFailed> {
    let first = FirstEnd::default();
    let finished = Arc::new(AtomicBool::new(false));
    let (go, worker) = {
        let (client, upstream, first, finished) = (
            Arc::clone(client),
            Arc::clone(upstream),
            first.clone(),
            Arc::clone(&finished),
        );
        spawn_worker(move || request(client, upstream, first, finished))?
    };
    // The prefix is written by hand rather than with `write_all`, so the
    // result counts what the upstream socket reported taking. A write that
    // fails cannot say how much of its buffer left first (a blocking write
    // that fails part-way may report none of it), so a failed head may have
    // carried its credentials in part (J13).
    let mut written = 0;
    while written < prefix.len() {
        match (&**upstream).write(&prefix[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if written < prefix.len() {
        let _ = go.send(false);
        close_both(client, upstream);
        let _ = worker.join();
        return Ok(RelayOutcome {
            bytes_in: 0,
            bytes_out: u64::try_from(written).unwrap_or(u64::MAX),
            discarded: 0,
            end: EndReason::UpstreamError,
            head_sent: false,
            head_partial: true,
            credentials: Vec::new(),
            unconfirmed: Vec::new(),
        });
    }
    // Only now may the worker read the client: the prefix is ahead of
    // anything it forwards.
    let _ = go.send(true);
    let bytes_in = response_direction(client, upstream, chunk, &first, &finished);
    let (end, (forwarded, discarded)) = match worker.join() {
        Ok(counts) => (first.get().unwrap_or(EndReason::UpstreamClosed), counts),
        // What a panicked worker forwarded is unknown: the counts are
        // short, and the end says why.
        Err(_) => (EndReason::InternalError, (0, 0)),
    };
    Ok(RelayOutcome {
        bytes_in,
        bytes_out: u64::try_from(prefix.len())
            .unwrap_or(u64::MAX)
            .saturating_add(forwarded),
        discarded,
        end,
        head_sent: true,
        head_partial: false,
        credentials: Vec::new(),
        unconfirmed: Vec::new(),
    })
}

/// A CONNECT tunnel: reply 200, forward `early` (bytes the client sent after
/// the head), then relay both directions until close.
pub(super) fn tunnel(
    client: &Arc<UnixStream>,
    upstream: &Arc<TcpStream>,
    early: &[u8],
    chunk: usize,
) -> Result<RelayOutcome, SetupFailed> {
    let request: Worker = Box::new(move |client, upstream, first, finished| {
        let mut buf = vec![0u8; chunk];
        let mut count = 0u64;
        match pump(&*client, &*upstream, &mut buf, &mut count) {
            Pump::SourceEof => {
                first.set(EndReason::ClientClosed);
                let _ = upstream.shutdown(Shutdown::Write);
                after_client_eof(&client, &upstream, &finished);
            }
            Pump::SourceError => {
                first.set(EndReason::ClientError);
                close_both(&client, &upstream);
            }
            Pump::SinkError => {
                first.set(EndReason::UpstreamError);
                close_both(&client, &upstream);
            }
        }
        (count, 0)
    });
    relay(client, upstream, early, chunk, request)
}

/// Validates strict chunked framing (no extensions, no trailers) and says
/// how many bytes of each piece belong to the body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Chunked {
    Size { digits: u8, value: u64 },
    SizeLf { value: u64 },
    Data(u64),
    DataCr,
    DataLf,
    TrailerCr,
    TrailerLf,
    Done,
}

impl Chunked {
    /// Consumes a prefix of `input`. Returns the number of bytes that belong
    /// to the body, or `None` at the first invalid byte.
    fn feed(&mut self, input: &[u8]) -> Option<usize> {
        let mut used = 0usize;
        while used < input.len() {
            if *self == Chunked::Done {
                break;
            }
            if let Chunked::Data(remaining) = *self {
                let available = input.len() - used;
                let take = usize::try_from(remaining).map_or(available, |r| r.min(available));
                used += take;
                let left = remaining - u64::try_from(take).unwrap_or(remaining);
                *self = if left == 0 {
                    Chunked::DataCr
                } else {
                    Chunked::Data(left)
                };
                continue;
            }
            let byte = *input.get(used)?;
            used += 1;
            *self = match (*self, byte) {
                (Chunked::Size { digits, value }, b'\r') if digits > 0 => Chunked::SizeLf { value },
                (Chunked::Size { digits, value }, byte) if byte.is_ascii_hexdigit() => {
                    if digits >= 16 {
                        return None;
                    }
                    let nibble = u64::from(char::from(byte).to_digit(16)?);
                    Chunked::Size {
                        digits: digits + 1,
                        value: (value << 4) | nibble,
                    }
                }
                (Chunked::SizeLf { value: 0 }, b'\n') => Chunked::TrailerCr,
                (Chunked::SizeLf { value }, b'\n') => Chunked::Data(value),
                (Chunked::DataCr, b'\r') => Chunked::DataLf,
                (Chunked::DataLf, b'\n') => Chunked::Size {
                    digits: 0,
                    value: 0,
                },
                (Chunked::TrailerCr, b'\r') => Chunked::TrailerLf,
                (Chunked::TrailerLf, b'\n') => Chunked::Done,
                _ => return None,
            };
        }
        Some(used)
    }
}

enum Body {
    Done,
    ClientEof,
    ClientError,
    UpstreamError,
    Framing,
}

/// The framed request body, forwarded exactly; whatever the client sends
/// after it is counted as discarded.
struct BodyForwarder {
    framing: Framing,
    remaining: u64,
    chunked: Chunked,
}

impl BodyForwarder {
    fn new(framing: Framing) -> Self {
        BodyForwarder {
            framing,
            remaining: match framing {
                Framing::Length(length) => length,
                _ => 0,
            },
            chunked: Chunked::Size {
                digits: 0,
                value: 0,
            },
        }
    }

    fn complete(&self) -> bool {
        match self.framing {
            Framing::Length(_) => self.remaining == 0,
            Framing::Chunked => self.chunked == Chunked::Done,
            Framing::Empty | Framing::Tunnel => true,
        }
    }

    /// Forwards the part of `piece` that belongs to the body; returns how
    /// many bytes of `piece` it used.
    fn forward(
        &mut self,
        piece: &[u8],
        upstream: &TcpStream,
        count: &mut u64,
    ) -> Result<usize, Body> {
        if self.complete() {
            return Ok(0);
        }
        let take = match self.framing {
            Framing::Length(_) => {
                let take =
                    usize::try_from(self.remaining).map_or(piece.len(), |r| r.min(piece.len()));
                self.remaining -= u64::try_from(take).unwrap_or(self.remaining);
                take
            }
            Framing::Chunked => self.chunked.feed(piece).ok_or(Body::Framing)?,
            Framing::Empty | Framing::Tunnel => 0,
        };
        if take > 0 {
            let mut upstream = upstream;
            upstream
                .write_all(piece.get(..take).unwrap_or_default())
                .map_err(|_| Body::UpstreamError)?;
            *count += u64::try_from(take).unwrap_or(u64::MAX);
        }
        Ok(take)
    }
}

/// Forwards exactly the framed request body: `early` first, then the client.
/// Returns how it ended; `discarded` counts bytes after the body.
fn forward_body(
    client: &UnixStream,
    upstream: &TcpStream,
    framing: Framing,
    early: &[u8],
    buf: &mut [u8],
    count: &mut u64,
    discarded: &mut u64,
) -> Body {
    let mut forwarder = BodyForwarder::new(framing);
    let mut account = |piece: &[u8], forwarder: &mut BodyForwarder| -> Result<bool, Body> {
        let used = forwarder.forward(piece, upstream, count)?;
        *discarded += u64::try_from(piece.len() - used).unwrap_or(u64::MAX);
        Ok(forwarder.complete())
    };
    match account(early, &mut forwarder) {
        Ok(true) => return Body::Done,
        Ok(false) => {}
        Err(body) => return body,
    }
    loop {
        let read = match (&*client).read(buf) {
            Ok(0) => return Body::ClientEof,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Body::ClientError,
        };
        match account(buf.get(..read).unwrap_or_default(), &mut forwarder) {
            Ok(true) => return Body::Done,
            Ok(false) => {}
            Err(body) => return body,
        }
    }
}

/// After the request: one request per connection, so everything else the
/// client sends is read, counted and dropped, until it stops sending; then
/// the connection closes once the client is gone or the response is done.
fn discard_rest(
    client: &UnixStream,
    upstream: &TcpStream,
    buf: &mut [u8],
    discarded: &mut u64,
    finished: &AtomicBool,
) {
    loop {
        match (&*client).read(buf) {
            Ok(0) => break,
            Ok(read) => *discarded += u64::try_from(read).unwrap_or(u64::MAX),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    after_client_eof(client, upstream, finished);
}

/// A plain-HTTP request: send the rewritten head, forward exactly the framed
/// body, and stream the response until the destination closes.
pub(super) fn http(
    client: &Arc<UnixStream>,
    upstream: &Arc<TcpStream>,
    head: &[u8],
    framing: Framing,
    early: &[u8],
    chunk: usize,
) -> Result<RelayOutcome, SetupFailed> {
    let early = early.to_vec();
    let request: Worker = Box::new(move |client, upstream, first, finished| {
        let mut buf = vec![0u8; chunk];
        let (mut count, mut discarded) = (0u64, 0u64);
        let body = forward_body(
            &client,
            &upstream,
            framing,
            &early,
            &mut buf,
            &mut count,
            &mut discarded,
        );
        let end = match body {
            Body::Done => None,
            Body::ClientEof => Some(EndReason::ClientClosed),
            Body::ClientError => Some(EndReason::ClientError),
            Body::UpstreamError => Some(EndReason::UpstreamError),
            Body::Framing => Some(EndReason::ClientFraming),
        };
        match end {
            // An incomplete or invalid body: the upstream must not see
            // anything after it, so the whole connection closes.
            Some(end) => {
                first.set(end);
                close_both(&client, &upstream);
            }
            None => discard_rest(&client, &upstream, &mut buf, &mut discarded, &finished),
        }
        (count, discarded)
    });
    relay(client, upstream, head, chunk, request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> (Option<usize>, Chunked) {
        let mut state = Chunked::Size {
            digits: 0,
            value: 0,
        };
        let used = state.feed(input);
        (used, state)
    }

    /// J13: a sent head's credentials are used, a partly sent head's are
    /// unconfirmed, and a head none of which left names none.
    #[test]
    fn credentials_follow_what_the_upstream_took_of_the_head() {
        let outcome = |head_sent, head_partial| {
            let mut outcome = RelayOutcome {
                bytes_in: 0,
                bytes_out: 0,
                discarded: 0,
                end: EndReason::UpstreamClosed,
                head_sent,
                head_partial,
                credentials: Vec::new(),
                unconfirmed: Vec::new(),
            };
            outcome.attribute(vec!["api".to_owned()]);
            (outcome.credentials, outcome.unconfirmed)
        };
        let api = || vec!["api".to_owned()];
        assert_eq!(outcome(true, false), (api(), Vec::new()));
        assert_eq!(outcome(false, true), (Vec::new(), api()));
        assert_eq!(outcome(false, false), (Vec::new(), Vec::new()));
    }

    /// J13: a result records the credentials its relay attributed, sent and
    /// unconfirmed alike.
    #[test]
    fn a_result_records_the_credentials_of_its_relay() {
        let outcome = RelayOutcome {
            bytes_in: 1,
            bytes_out: 2,
            discarded: 3,
            end: EndReason::UpstreamClosed,
            head_sent: false,
            head_partial: true,
            credentials: vec!["sent".to_owned()],
            unconfirmed: vec!["maybe".to_owned()],
        };
        let mut result = super::super::server::denial(
            1,
            None,
            super::super::RequestKind::Http,
            super::super::Reason::Relayed,
            std::time::Instant::now(),
        );
        outcome.record(&mut result);
        assert_eq!(
            (result.bytes_in, result.bytes_out, result.discarded_bytes),
            (1, 2, 3)
        );
        assert_eq!(result.credentials, ["sent"]);
        assert_eq!(result.credentials_unconfirmed, ["maybe"]);
    }

    /// J13: a head whose write failed after the upstream may have taken
    /// part of it is partial, never sent.
    #[test]
    fn a_prefix_the_upstream_took_in_part_is_partial() {
        let (client, _peer) = UnixStream::pair().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        // The peer reads nothing, then goes away while the relay is still
        // writing a head far larger than both socket buffers.
        let closer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(accepted);
        });
        let head = vec![b'h'; 64 * 1024 * 1024];
        let outcome = relay(
            &Arc::new(client),
            &Arc::new(upstream),
            &head,
            64,
            Box::new(|_, _, _, _| (0, 0)),
        );
        closer.join().unwrap();
        let Ok(outcome) = outcome else {
            panic!("the relay started");
        };
        assert!(!outcome.head_sent);
        assert!(outcome.head_partial);
        assert!(outcome.bytes_out < head.len() as u64);
    }

    /// J13: a prefix the upstream socket refused is not a sent head, so its
    /// credentials are not a use; whether any of it left cannot be known, so
    /// it is partial.
    #[test]
    fn a_prefix_that_cannot_be_written_is_not_sent() {
        let (client, _peer) = UnixStream::pair().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _accepted = listener.accept().unwrap();
        upstream.shutdown(Shutdown::Write).unwrap();
        let outcome = relay(
            &Arc::new(client),
            &Arc::new(upstream),
            b"GET / HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n",
            64,
            Box::new(|_, _, _, _| (0, 0)),
        );
        let Ok(outcome) = outcome else {
            panic!("the relay started");
        };
        assert!(!outcome.head_sent);
        assert!(outcome.head_partial);
        assert_eq!(outcome.end, EndReason::UpstreamError);
    }

    #[test]
    fn a_panicked_request_worker_is_recorded_not_hidden() {
        let (client, _peer) = UnixStream::pair().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        // The destination closes at once, so the response direction ends.
        drop(listener.accept().unwrap());
        let outcome = relay(
            &Arc::new(client),
            &Arc::new(upstream),
            b"",
            64,
            Box::new(|_, _, _, _| panic!("a relay worker bug")),
        );
        let Ok(outcome) = outcome else {
            panic!("the relay started");
        };
        assert_eq!(outcome.end, EndReason::InternalError);
    }

    #[test]
    fn strict_chunked_framing_ends_exactly_after_the_last_chunk() {
        let body = b"5\r\nhello\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n";
        let (used, state) = run(body);
        assert_eq!(used, Some(15));
        assert_eq!(state, Chunked::Done);
    }

    #[test]
    fn chunk_extensions_trailers_and_bare_lf_refuse() {
        assert_eq!(run(b"5;ext=1\r\nhello\r\n0\r\n\r\n").0, None);
        assert_eq!(run(b"0\r\nX-Trailer: 1\r\n\r\n").0, None);
        assert_eq!(run(b"5\nhello\n0\n\n").0, None);
        assert_eq!(run(b"\r\n").0, None, "an empty size");
        assert_eq!(run(b"11111111111111111\r\n").0, None, "more than 16 digits");
        assert_eq!(run(b"5\r\nhelloX").0, None, "data not followed by CRLF");
    }

    #[test]
    fn chunked_framing_can_arrive_in_pieces() {
        let mut state = Chunked::Size {
            digits: 0,
            value: 0,
        };
        let pieces: [&[u8]; 5] = [b"a", b"\r\n0123456", b"789\r", b"\n0\r\n\r", b"\nextra"];
        let used: Vec<Option<usize>> = pieces.iter().map(|piece| state.feed(piece)).collect();
        assert_eq!(used, vec![Some(1), Some(9), Some(4), Some(5), Some(1)]);
        assert_eq!(state, Chunked::Done);
    }
}
