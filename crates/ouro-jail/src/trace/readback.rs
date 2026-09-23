//! Trace readback: the recogniser for an NDJSON trace (jail-v1 §§13.1, 13.3).
//!
//! §13.3: "A corrupted/truncated last frame must be recognizable at readback."
//! A frame is one JSON object followed by one LF, so a reader can tell three
//! cases apart from the bytes alone:
//!
//! * [`TraceState::Complete`]: every line is one complete JSON object ending
//!   in LF (zero lines included).
//! * [`TraceState::Incomplete`]: every line but the last is a complete frame,
//!   and the last is not one complete JSON object ending in LF. This is what
//!   a writer that stopped mid-frame leaves, and what a reader that left
//!   mid-frame took. It is visibly incomplete, never mistaken for a frame.
//! * [`TraceState::Corrupt`]: a line before the last is not a complete frame,
//!   so a torn frame was followed by more bytes. A writer that follows §13.3
//!   never produces this; seeing it means the stream cannot be trusted past
//!   that offset.
//!
//! Syntax is not the whole story. A trace can end on a frame boundary and
//! still lack its final notes, because a sink that lost evidence keeps only a
//! prefix. [`Readback::last_receipt_note`] exposes the last frame when it is a
//! wrapper `jail.receipt` note, so a reader can compare it with the receipt it
//! holds; a trace whose last frame is not the note of the attempt's final
//! receipt is incomplete, whatever its syntax says.
//!
//! This file is shared verbatim with the test harness in `ouro-fixture`, which
//! includes it by path so that the harness and the product use one
//! recogniser. It therefore depends on nothing but `std` and `serde_json`.

use serde_json::Value;

/// What the bytes of a trace establish about its frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceState {
    /// Every line is one complete JSON object ending in LF.
    Complete,
    /// Only the last line is not one complete JSON object ending in LF.
    Incomplete,
    /// A line before the last is not one complete JSON object.
    Corrupt,
}

/// The frames a reader can trust, and where trust ends.
#[derive(Clone, Debug, PartialEq)]
pub struct Readback {
    /// The classification of the whole byte string.
    pub state: TraceState,
    /// The complete frames before the first line that is not one, in order.
    pub frames: Vec<Value>,
    /// Byte offset of the first line that is not a complete frame, if any.
    pub bad_offset: Option<usize>,
    /// That line's bytes, without its LF (empty when there is none).
    pub bad_line: Vec<u8>,
}

impl Readback {
    /// The `(phase, receipt_digest)` of the last frame, when that frame is a
    /// wrapper `jail.receipt` note.
    ///
    /// Only a [`TraceState::Complete`] trace can end on a note; any other
    /// state returns `None`, because its last line is not a frame.
    #[must_use]
    pub fn last_receipt_note(&self) -> Option<(&str, &str)> {
        if self.state != TraceState::Complete {
            return None;
        }
        let last = self.frames.last()?;
        if last.get("source").and_then(Value::as_str) != Some("wrapper")
            || last.get("operation").and_then(Value::as_str) != Some("jail.receipt")
        {
            return None;
        }
        let fields = last.get("fields")?;
        Some((
            fields.get("phase")?.as_str()?,
            fields.get("receipt_digest")?.as_str()?,
        ))
    }
}

/// One complete JSON object, or nothing.
fn frame(line: &[u8]) -> Option<Value> {
    match serde_json::from_slice::<Value>(line) {
        Ok(value @ Value::Object(_)) => Some(value),
        _ => None,
    }
}

/// Classifies the bytes of a trace (§13.3 readback).
///
/// The frames returned are the ones before the first line that is not a
/// complete frame; nothing after that point is interpreted.
#[must_use]
pub fn read_frames(bytes: &[u8]) -> Readback {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        let Some(end) = rest.iter().position(|byte| *byte == b'\n') else {
            // The last line has no LF: whatever it holds, it is not a frame.
            return Readback {
                state: TraceState::Incomplete,
                frames,
                bad_offset: Some(offset),
                bad_line: rest.to_vec(),
            };
        };
        let line = &rest[..end];
        let next = offset + end + 1;
        if let Some(value) = frame(line) {
            frames.push(value);
            offset = next;
            continue;
        }
        return Readback {
            state: if next == bytes.len() {
                TraceState::Incomplete
            } else {
                TraceState::Corrupt
            },
            frames,
            bad_offset: Some(offset),
            bad_line: line.to_vec(),
        };
    }
    Readback {
        state: TraceState::Complete,
        frames,
        bad_offset: None,
        bad_line: Vec::new(),
    }
}
