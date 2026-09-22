//! Byte relays with backpressure.
//!
//! Each direction owns one fixed buffer (its share of the relay budget) and
//! writes everything it read before reading again, so a slow reader slows its
//! writer and nothing is buffered beyond that share. Response bodies are
//! streamed, never collected.
//!
//! Termination: when the destination closes or fails, the whole connection
//! closes, so a dead upstream always ends the request. When the client closes
//! its sending side of a tunnel, the upstream's sending side is half-closed
//! and the response direction continues until the destination closes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use super::EndReason;
use super::http::Framing;

/// Counters and the first way the relay ended.
pub(super) struct RelayOutcome {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub end: EndReason,
}

/// Records the first termination only.
#[derive(Clone, Default)]
struct FirstEnd(Arc<Mutex<Option<EndReason>>>);

impl FirstEnd {
    fn set(&self, end: EndReason) {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(end);
        }
    }

    fn get(&self) -> Option<EndReason> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
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

fn pump(source: &mut impl Read, sink: &mut impl Write, buf: &mut [u8], count: &mut u64) -> Pump {
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
    client: &mut UnixStream,
    upstream: &mut TcpStream,
    chunk: usize,
    first: &FirstEnd,
) -> u64 {
    let mut buf = vec![0u8; chunk];
    let mut count = 0u64;
    let end = match pump(upstream, client, &mut buf, &mut count) {
        Pump::SourceEof => EndReason::UpstreamClosed,
        Pump::SourceError => EndReason::UpstreamError,
        Pump::SinkError => EndReason::ClientError,
    };
    first.set(end);
    let _ = client.flush();
    close_both(client, upstream);
    count
}

/// A CONNECT tunnel: reply 200, forward `early` (bytes the client sent after
/// the head), then relay both directions until close.
pub(super) fn tunnel(
    client: &mut UnixStream,
    upstream: TcpStream,
    early: &[u8],
    chunk: usize,
    reply_budget: Duration,
) -> RelayOutcome {
    let mut upstream = upstream;
    let first = FirstEnd::default();
    let _ = client.set_write_timeout(Some(reply_budget.max(Duration::from_millis(1))));
    let replied = client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_ok();
    let _ = client.set_write_timeout(None);
    if !replied {
        close_both(client, &upstream);
        return RelayOutcome {
            bytes_in: 0,
            bytes_out: 0,
            end: EndReason::ClientError,
        };
    }
    let mut bytes_out = 0u64;
    if !early.is_empty() {
        if upstream.write_all(early).is_err() {
            close_both(client, &upstream);
            return RelayOutcome {
                bytes_in: 0,
                bytes_out: 0,
                end: EndReason::UpstreamError,
            };
        }
        bytes_out = u64::try_from(early.len()).unwrap_or(u64::MAX);
    }
    let (Ok(mut client_reader), Ok(mut upstream_writer)) =
        (client.try_clone(), upstream.try_clone())
    else {
        close_both(client, &upstream);
        return RelayOutcome {
            bytes_in: 0,
            bytes_out,
            end: EndReason::ClientError,
        };
    };
    let request_first = first.clone();
    let request = thread::Builder::new()
        .name("ouro-proxy-relay".to_owned())
        .stack_size(64 * 1024)
        .spawn(move || {
            let mut buf = vec![0u8; chunk];
            let mut count = 0u64;
            match pump(
                &mut client_reader,
                &mut upstream_writer,
                &mut buf,
                &mut count,
            ) {
                Pump::SourceEof => {
                    request_first.set(EndReason::ClientClosed);
                    let _ = upstream_writer.shutdown(Shutdown::Write);
                }
                Pump::SourceError => {
                    request_first.set(EndReason::ClientError);
                    close_both(&client_reader, &upstream_writer);
                }
                Pump::SinkError => {
                    request_first.set(EndReason::UpstreamError);
                    close_both(&client_reader, &upstream_writer);
                }
            }
            count
        });
    let Ok(request) = request else {
        close_both(client, &upstream);
        return RelayOutcome {
            bytes_in: 0,
            bytes_out,
            end: EndReason::ClientError,
        };
    };
    let bytes_in = response_direction(client, &mut upstream, chunk, &first);
    bytes_out += request.join().unwrap_or(0);
    RelayOutcome {
        bytes_in,
        bytes_out,
        end: first.get().unwrap_or(EndReason::UpstreamClosed),
    }
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

/// Forwards exactly the framed request body: `early` first, then the client.
fn forward_body(
    client: &mut UnixStream,
    upstream: &mut TcpStream,
    framing: Framing,
    early: &[u8],
    buf: &mut [u8],
    count: &mut u64,
) -> Body {
    let mut remaining = match framing {
        Framing::Length(length) => length,
        _ => 0,
    };
    let mut chunked = Chunked::Size {
        digits: 0,
        value: 0,
    };
    let mut forward =
        |piece: &[u8], upstream: &mut TcpStream, count: &mut u64| -> Result<bool, Body> {
            // Returns Ok(true) when the body is complete.
            let take = match framing {
                Framing::Length(_) => {
                    let take =
                        usize::try_from(remaining).map_or(piece.len(), |r| r.min(piece.len()));
                    remaining -= u64::try_from(take).unwrap_or(remaining);
                    take
                }
                Framing::Chunked => chunked.feed(piece).ok_or(Body::Framing)?,
                Framing::Empty | Framing::Tunnel => 0,
            };
            if take > 0 {
                upstream
                    .write_all(piece.get(..take).unwrap_or_default())
                    .map_err(|_| Body::UpstreamError)?;
                *count += u64::try_from(take).unwrap_or(u64::MAX);
            }
            Ok(match framing {
                Framing::Length(_) => remaining == 0,
                Framing::Chunked => chunked == Chunked::Done,
                Framing::Empty | Framing::Tunnel => true,
            })
        };
    match forward(early, upstream, count) {
        Ok(true) => return Body::Done,
        Ok(false) => {}
        Err(body) => return body,
    }
    loop {
        let read = match client.read(buf) {
            Ok(0) => return Body::ClientEof,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Body::ClientError,
        };
        match forward(buf.get(..read).unwrap_or_default(), upstream, count) {
            Ok(true) => return Body::Done,
            Ok(false) => {}
            Err(body) => return body,
        }
    }
}

/// A plain-HTTP request: send the rewritten head, forward exactly the framed
/// body, and stream the response until the destination closes.
pub(super) fn http(
    client: &mut UnixStream,
    upstream: TcpStream,
    head: &[u8],
    framing: &Framing,
    early: &[u8],
    chunk: usize,
) -> RelayOutcome {
    let mut upstream = upstream;
    let first = FirstEnd::default();
    if upstream.write_all(head).is_err() {
        close_both(client, &upstream);
        return RelayOutcome {
            bytes_in: 0,
            bytes_out: 0,
            end: EndReason::UpstreamError,
        };
    }
    let head_bytes = u64::try_from(head.len()).unwrap_or(u64::MAX);
    let framing = *framing;
    let early = early.to_vec();
    let (Ok(mut client_reader), Ok(mut upstream_writer)) =
        (client.try_clone(), upstream.try_clone())
    else {
        close_both(client, &upstream);
        return RelayOutcome {
            bytes_in: 0,
            bytes_out: head_bytes,
            end: EndReason::ClientError,
        };
    };
    let request_first = first.clone();
    let request = thread::Builder::new()
        .name("ouro-proxy-relay".to_owned())
        .stack_size(64 * 1024)
        .spawn(move || {
            let mut buf = vec![0u8; chunk];
            let mut count = 0u64;
            let end = match forward_body(
                &mut client_reader,
                &mut upstream_writer,
                framing,
                &early,
                &mut buf,
                &mut count,
            ) {
                Body::Done => None,
                Body::ClientEof => Some(EndReason::ClientClosed),
                Body::ClientError => Some(EndReason::ClientError),
                Body::UpstreamError => Some(EndReason::UpstreamError),
                Body::Framing => Some(EndReason::ClientFraming),
            };
            if let Some(end) = end {
                // An incomplete or invalid body: the upstream must not see
                // anything after it, so the whole connection closes.
                request_first.set(end);
                close_both(&client_reader, &upstream_writer);
            }
            count
        });
    let Ok(request) = request else {
        close_both(client, &upstream);
        return RelayOutcome {
            bytes_in: 0,
            bytes_out: head_bytes,
            end: EndReason::ClientError,
        };
    };
    let bytes_in = response_direction(client, &mut upstream, chunk, &first);
    let body_bytes = request.join().unwrap_or(0);
    RelayOutcome {
        bytes_in,
        bytes_out: head_bytes + body_bytes,
        end: first.get().unwrap_or(EndReason::UpstreamClosed),
    }
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
