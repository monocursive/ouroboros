//! The receipt note `gc` appends to an attempt's local journal when it
//! replaces the receipt (jail-v1 §§13.3, 14.2).
//!
//! A local `trace.ndjson` is complete only when its last frame is the
//! `jail.receipt` note of the attempt's final receipt (§13.3). `gc` replaces
//! a refused or settled receipt to record its completed cleanup, which used
//! to leave a complete journal ending on the note of a receipt that no longer
//! exists, so every later summary of the attempt claimed only lower bounds.
//! Once the replacement is durable, `gc` appends the one note naming the new
//! receipt, and only to a journal that ended complete on the note of the
//! receipt it replaced:
//!
//! - numbered one past that note's `source_seq`: the last frame is the
//!   wrapper's, so it holds the wrapper's last number;
//! - with `observed_at` gc's wall time and `monotonic_ns` copied from that
//!   note: the supervisor's clock ended with the supervisor, so no later
//!   writer has a reading of it, and the copy is the last point the journal
//!   knows on it (the note was written no earlier). A summary's
//!   exec→settled time does not change;
//! - within the local cap ([`crate::trace::LOCAL_CAP`]) with the note.
//!
//! Any other journal is left byte for byte as it is, and the report says
//! why. gc judges only the last frame: whatever else the journal holds (a
//! recorded loss, an unrecorded hole, a corrupt line) reads the same before
//! and after the note.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek as _, SeekFrom};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::time::SystemTime;

use serde_json::Value;

use crate::records::{Event, Phase, Receipt, SCHEMA_EVENT};
use crate::state::{self, AttemptDir, Site};

/// What `gc`'s replacement of a receipt did to the attempt's local journal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum JournalNote {
    /// The note naming the new receipt was appended with this wrapper
    /// `source_seq`.
    Appended(u64),
    /// A dry run: the journal ends complete on the note of the receipt that
    /// would be replaced, so the note would be appended.
    WouldAppend,
    /// No local journal: the run streamed it to `--trace-fd` (§13.3), or
    /// wrote none.
    Absent,
    /// The journal was left exactly as it was; why.
    Unchanged(String),
    /// The journal could not be read or appended to, a failed state access
    /// (§6.4); why. An append that failed part-way was cut back to the
    /// journal's previous end unless the reason says the cut failed too.
    Failed(String),
}

impl JournalNote {
    /// The report's `journal` value.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            JournalNote::Appended(seq) => format!("appended (wrapper source_seq {seq})"),
            JournalNote::WouldAppend => "would_append".to_owned(),
            JournalNote::Absent => "absent".to_owned(),
            JournalNote::Unchanged(reason) => format!("unchanged: {reason}"),
            JournalNote::Failed(reason) => format!("failed: {reason}"),
        }
    }
}

/// The receipt a replacement replaces, as `gc` read it: what the journal's
/// last note must name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Replaced {
    /// `sha256:` over the RFC 8785 canonical bytes of the receipt as read
    /// from disk (§13.1); `None` when they have none.
    pub digest: Option<String>,
}

impl Replaced {
    /// The receipt read as `bytes`.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Replaced {
        Replaced {
            digest: digest_of(bytes),
        }
    }
}

/// `sha256:` over the canonical bytes of the receipt `bytes` hold: the name a
/// reader recomputes from `jail.json` alone.
fn digest_of(bytes: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    crate::records::semantic::receipt_digest(&value).ok()
}

/// The journal's last frame, when it is the note of the replaced receipt.
struct Tail {
    file: File,
    /// The journal's length, where the note goes.
    size: u64,
    source_seq: u64,
    monotonic_ns: u128,
}

/// A dry run of [`append`]: whether the note would be appended to the
/// journal of `receipt` (not yet replaced), and if not, why.
#[must_use]
pub fn check(attempt_dir: &AttemptDir, receipt: &Receipt, replaced: &Replaced) -> JournalNote {
    match tail(
        attempt_dir,
        &receipt.attempt_id,
        receipt.phase,
        replaced,
        false,
    ) {
        Ok(_) => JournalNote::WouldAppend,
        Err(note) => note,
    }
}

/// Appends the note of `written` (the receipt now durable as `bytes`) to
/// the journal, which must end complete on the note of `replaced`, within
/// `cap` bytes ([`crate::trace::LOCAL_CAP`] for `gc`).
#[must_use]
pub fn append(
    attempt_dir: &AttemptDir,
    written: &Receipt,
    bytes: &[u8],
    replaced: &Replaced,
    cap: u64,
) -> JournalNote {
    let mut tail = match tail(
        attempt_dir,
        &written.attempt_id,
        written.phase,
        replaced,
        true,
    ) {
        Ok(tail) => tail,
        Err(note) => return note,
    };
    let Some(digest) = digest_of(bytes) else {
        return JournalNote::Unchanged("the new receipt has no canonical digest".to_owned());
    };
    let seq = tail.source_seq + 1;
    let event = Event::receipt_note(
        &written.attempt_id,
        seq,
        SystemTime::now(),
        tail.monotonic_ns,
        written.phase,
        &digest,
    );
    let mut frame = match serde_json::to_vec(&event) {
        Ok(frame) => frame,
        Err(error) => {
            return JournalNote::Failed(format!("the note cannot be serialized: {error}"));
        }
    };
    frame.push(b'\n');
    let needed = tail.size + frame.len() as u64;
    if needed > cap {
        return JournalNote::Unchanged(format!(
            "the note would take it to {needed} bytes, past its {cap}-byte cap"
        ));
    }
    match write_at_end(&mut tail, &frame) {
        Ok(()) => JournalNote::Appended(seq),
        Err(note) => note,
    }
}

/// Opens the journal (for writing too when `writable`) and checks that it
/// ends on the note of `replaced`; the reason it is not touched otherwise.
fn tail(
    attempt_dir: &AttemptDir,
    attempt_id: &str,
    phase: Phase,
    replaced: &Replaced,
    writable: bool,
) -> Result<Tail, JournalNote> {
    let path = attempt_dir.trace_path();
    let failed = |error: io::Error| JournalNote::Failed(format!("{}: {error}", path.display()));
    // The attempt root is gc's under its lease and private; the journal is
    // one of its state files, so it is never followed, never a FIFO or a
    // terminal, and held to the rules every state file is (§6.2).
    let file = match OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(JournalNote::Absent),
        Err(error) => return Err(failed(error)),
    };
    let metadata = file.metadata().map_err(failed)?;
    if !metadata.is_file() {
        return Err(JournalNote::Failed(format!(
            "{}: is not a regular file",
            path.display()
        )));
    }
    state::check_ownership(&path, metadata.uid(), metadata.mode(), state::FILE_MODE)
        .map_err(|error| JournalNote::Failed(error.message))?;
    if metadata.nlink() != 1 {
        return Err(JournalNote::Failed(format!(
            "{}: has {} links; a journal has one",
            path.display(),
            metadata.nlink()
        )));
    }
    let size = metadata.len();
    let unchanged = |reason: &str| Err(JournalNote::Unchanged(reason.to_owned()));
    if size == 0 {
        return unchanged("it is empty");
    }
    // The last frame and the LF before it: a frame is at most
    // `FRAME_MAX` bytes with its own LF (§13.1).
    let window = size.min(crate::journal::FRAME_MAX as u64 + 1);
    let mut bytes = vec![0; usize::try_from(window).unwrap_or(0)];
    file.read_exact_at(&mut bytes, size - window)
        .map_err(failed)?;
    let Some((b'\n', body)) = bytes.split_last() else {
        return unchanged("its last line is not a complete frame");
    };
    let line = match body.iter().rposition(|byte| *byte == b'\n') {
        Some(end) => &body[end + 1..],
        None if window == size => body,
        None => return unchanged("its last line is longer than a frame"),
    };
    let Ok(Value::Object(last)) = serde_json::from_slice::<Value>(line) else {
        return unchanged("its last line is not a frame");
    };
    let text = |key: &str| last.get(key).and_then(Value::as_str);
    let fields = last.get("fields");
    let field = |key: &str| {
        fields
            .and_then(|fields| fields.get(key))
            .and_then(Value::as_str)
    };
    let phase = serde_json::to_value(phase).ok();
    if text("schema") != Some(SCHEMA_EVENT)
        || text("source") != Some("wrapper")
        || text("operation") != Some("jail.receipt")
    {
        return unchanged("its last frame is not a receipt note");
    }
    if text("attempt_id") != Some(attempt_id) {
        return unchanged("its last frame is another attempt's");
    }
    let Some(digest) = replaced.digest.as_deref() else {
        return unchanged("the receipt gc replaced has no canonical digest to match");
    };
    if field("receipt_digest") != Some(digest)
        || field("phase") != phase.as_ref().and_then(Value::as_str)
    {
        return unchanged("it ends on the note of a receipt other than the one gc replaced");
    }
    let Some(source_seq) = last
        .get("source_seq")
        .and_then(Value::as_u64)
        .filter(|seq| (1..u64::MAX).contains(seq))
    else {
        return unchanged("its last note has no usable source_seq");
    };
    let Some(monotonic_ns) = text("monotonic_ns").and_then(decimal) else {
        return unchanged("its last note has no clock reading");
    };
    Ok(Tail {
        file,
        size,
        source_seq,
        monotonic_ns,
    })
}

/// A canonical decimal (§13.1: no sign, no leading zero), as a number.
fn decimal(text: &str) -> Option<u128> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

/// Writes `frame` (with its LF) where the journal ended and syncs it,
/// through the persistence seam at `gc`'s site (P12). A write that fails
/// part-way is cut back to the journal's previous end, so the journal ends
/// on the replaced receipt's note again, as it would without the note.
fn write_at_end(tail: &mut Tail, frame: &[u8]) -> Result<(), JournalNote> {
    let io = state::current_io();
    let failed = |what: &str, error: &io::Error| JournalNote::Failed(format!("{what}: {error}"));
    // Under the lease nothing else writes the journal; a length that moved
    // since it was read means something did, and nothing is written.
    match tail.file.metadata() {
        Ok(metadata) if metadata.len() == tail.size => {}
        Ok(_) => {
            return Err(JournalNote::Failed(
                "the journal changed while gc read it".to_owned(),
            ));
        }
        Err(error) => return Err(failed("the journal cannot be inspected", &error)),
    }
    tail.file
        .seek(SeekFrom::Start(tail.size))
        .map_err(|error| failed("the journal cannot be positioned", &error))?;
    if let Err(error) = state::write_fully(&*io, Site::GcResume, &mut tail.file, frame) {
        return Err(JournalNote::Failed(match tail.file.set_len(tail.size) {
            Ok(()) => format!("the note was not written: {error}"),
            Err(cut) => format!(
                "the note was not written ({error}), and its partial bytes could not be cut \
                 back ({cut}): the journal's last line is torn"
            ),
        }));
    }
    io.sync_file(Site::GcResume, &tail.file)
        .map_err(|error| failed("the note was written but not synced", &error))
}
