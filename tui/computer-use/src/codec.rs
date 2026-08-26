//! The helper's stdio framing: one JSON object per `\n`-delimited line, UTF-8, no embedded
//! newlines, bounded by `max_frame_bytes` (doc §7).
//!
//! This module owns *framing only* — turning a byte stream into lines and classifying each
//! line as blank, noise, or a JSON object. It does not know what any method means; that is
//! [`crate::server`]. Splitting the two keeps the byte-bounds honest and unit-testable
//! without a runtime full of protocol.
//!
//! ## Two honesty properties, both bounded
//!
//! **Frames are capped as they are read, not after.** [`read_frame`] never lets `buf` grow
//! past `cap`: a line that runs long is truncated in place and its bytes are drained to the
//! next newline, so a peer cannot grow this process's memory by withholding a `\n`. A naive
//! `read_line` would buffer the whole oversize line first and only then notice — which is
//! the memory exhaustion the cap exists to prevent.
//!
//! **A non-JSON line is noise, not an error to answer.** The helper's peer is the trusted
//! `Native.Desktop.Pool`, not a stranger; garbage on the pipe means the pipe is broken, so
//! [`classify`] reports it and [`crate::server`] counts it toward a budget rather than
//! spewing an error frame per line. The MCP codec takes the same posture.

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// The default frame cap: 8 MiB. One line is a JSON-RPC message, not a file, and a line
/// that never ends is a peer growing this process's memory on its say-so.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// What one read produced. On [`Frame::Line`] the bytes are in the caller's `buf` (newline
/// stripped); on [`Frame::Oversize`] the line exceeded the cap and its content was dropped;
/// [`Frame::Eof`] is the clean end of the stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Line,
    Oversize,
    Eof,
}

/// How a single line reads as a protocol event.
#[derive(Debug)]
pub enum Incoming {
    /// Empty or all-whitespace. Benign; not a message and not noise.
    Blank,
    /// Not UTF-8, not JSON, or JSON that is not an object. Counts toward the noise budget.
    Noise,
    /// A JSON object — a candidate JSON-RPC message for the server to dispatch.
    Message(Value),
}

/// Classifies one line's bytes. "One JSON object per line" is taken literally: a JSON array
/// or scalar is not a message this helper speaks, so it is noise rather than a thing to
/// answer with an error.
pub fn classify(line: &[u8]) -> Incoming {
    let trimmed = line.trim_ascii();
    if trimmed.is_empty() {
        return Incoming::Blank;
    }

    let Ok(text) = std::str::from_utf8(trimmed) else {
        return Incoming::Noise;
    };

    match serde_json::from_str::<Value>(text) {
        Ok(value) if value.is_object() => Incoming::Message(value),
        _ => Incoming::Noise,
    }
}

/// Reads the next line into `buf`, never letting `buf` exceed `cap`.
///
/// `buf` is cleared on entry and, on [`Frame::Line`], holds the line without its trailing
/// newline. A line longer than `cap` returns [`Frame::Oversize`] with `buf` emptied and the
/// overflowing bytes consumed up to the newline, so the next call starts on a fresh line.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    cap: usize,
) -> std::io::Result<Frame> {
    buf.clear();
    let mut overflowed = false;

    loop {
        let available = reader.fill_buf().await?;

        if available.is_empty() {
            // End of stream. A pending line without a trailing newline is still a line.
            return Ok(if buf.is_empty() && !overflowed {
                Frame::Eof
            } else if overflowed {
                buf.clear();
                Frame::Oversize
            } else {
                Frame::Line
            });
        }

        match available.iter().position(|&byte| byte == b'\n') {
            Some(pos) => {
                if !overflowed && push_bounded(buf, &available[..pos], cap) {
                    overflowed = true;
                }
                reader.consume(pos + 1);
                return Ok(if overflowed {
                    buf.clear();
                    Frame::Oversize
                } else {
                    Frame::Line
                });
            }
            None => {
                if !overflowed && push_bounded(buf, available, cap) {
                    overflowed = true;
                }
                let consumed = available.len();
                reader.consume(consumed);
            }
        }
    }
}

/// Appends `src` to `buf` up to `cap` total, returning whether it had to truncate. Once this
/// returns `true` the caller stops appending and only drains to the newline.
fn push_bounded(buf: &mut Vec<u8>, src: &[u8], cap: usize) -> bool {
    let room = cap.saturating_sub(buf.len());
    if src.len() <= room {
        buf.extend_from_slice(src);
        false
    } else {
        buf.extend_from_slice(&src[..room]);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn message_value(incoming: Incoming) -> Value {
        match incoming {
            Incoming::Message(value) => value,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn object_is_a_message() {
        let value = message_value(classify(br#"{"jsonrpc":"2.0","id":1,"method":"doctor"}"#));
        assert_eq!(value["method"], "doctor");
    }

    #[test]
    fn blank_and_whitespace_are_benign() {
        assert!(matches!(classify(b""), Incoming::Blank));
        assert!(matches!(classify(b"   \t  "), Incoming::Blank));
    }

    #[test]
    fn non_object_json_is_noise() {
        // Valid JSON, but not "one JSON object per line".
        assert!(matches!(classify(b"[1,2,3]"), Incoming::Noise));
        assert!(matches!(classify(b"42"), Incoming::Noise));
        assert!(matches!(classify(b"\"a string\""), Incoming::Noise));
    }

    #[test]
    fn garbage_and_non_utf8_are_noise() {
        assert!(matches!(classify(b"not json at all"), Incoming::Noise));
        assert!(matches!(classify(&[0xff, 0xfe, 0x00]), Incoming::Noise));
    }

    #[tokio::test]
    async fn reads_two_lines_then_eof() {
        let data = b"first\nsecond\n".to_vec();
        let mut reader = BufReader::new(&data[..]);
        let mut buf = Vec::new();

        assert_eq!(
            read_frame(&mut reader, &mut buf, 64).await.unwrap(),
            Frame::Line
        );
        assert_eq!(buf, b"first");
        assert_eq!(
            read_frame(&mut reader, &mut buf, 64).await.unwrap(),
            Frame::Line
        );
        assert_eq!(buf, b"second");
        assert_eq!(
            read_frame(&mut reader, &mut buf, 64).await.unwrap(),
            Frame::Eof
        );
    }

    #[tokio::test]
    async fn final_line_without_newline_is_still_a_line() {
        let data = b"trailing".to_vec();
        let mut reader = BufReader::new(&data[..]);
        let mut buf = Vec::new();

        assert_eq!(
            read_frame(&mut reader, &mut buf, 64).await.unwrap(),
            Frame::Line
        );
        assert_eq!(buf, b"trailing");
        assert_eq!(
            read_frame(&mut reader, &mut buf, 64).await.unwrap(),
            Frame::Eof
        );
    }

    #[tokio::test]
    async fn oversize_line_is_bounded_and_the_next_line_survives() {
        // The oversize line is 40 bytes with a cap of 8, so it must never be buffered whole.
        let data = b"0123456789012345678901234567890123456789\nok\n".to_vec();
        let mut reader = BufReader::new(&data[..]);
        let mut buf = Vec::new();

        assert_eq!(
            read_frame(&mut reader, &mut buf, 8).await.unwrap(),
            Frame::Oversize
        );
        assert!(
            buf.is_empty(),
            "oversize content must be dropped, not returned"
        );

        // Framing recovers on the following newline.
        assert_eq!(
            read_frame(&mut reader, &mut buf, 8).await.unwrap(),
            Frame::Line
        );
        assert_eq!(buf, b"ok");
    }

    #[tokio::test]
    async fn a_line_exactly_at_the_cap_is_not_oversize() {
        let data = b"12345678\n".to_vec();
        let mut reader = BufReader::new(&data[..]);
        let mut buf = Vec::new();

        assert_eq!(
            read_frame(&mut reader, &mut buf, 8).await.unwrap(),
            Frame::Line
        );
        assert_eq!(buf, b"12345678");
    }
}
