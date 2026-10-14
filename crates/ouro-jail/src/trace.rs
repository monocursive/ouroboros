//! The bounded NDJSON trace transport.
//!
//! Implements jail-v1 §13.3 (storage and pressure): a local `trace.ndjson`
//! with a 64 MiB cap of which 256 KiB is reserved for the final gap and
//! receipt notes, or an external fd written nonblocking with a 4 MiB queue and
//! a one-second no-progress deadline.
//!
//! Every failure here is evidence loss, never silence: the sink records the
//! reason and counts every frame it could not deliver, and the caller decides
//! what strict or best-effort evidence mode means. After a loss a sink keeps
//! a prefix of the stream and accepts only reserve notes (the gap and receipt
//! notes, and the `agent` profile's helper lifecycle notes, at most one per
//! helper, because a helper's end explains a stop), so a reader never finds
//! ordinary frames after a silent hole; a refused reserve note ends the
//! stream, in both sinks, so no note follows a missing one either. An
//! external frame torn by a drain that gave up ends the stream too: nothing
//! is written after it.
//!
//! The external writer queues whole frames and resumes a partially written
//! one at its own offset, never re-sending it as a second event. The local
//! writer truncates a failed write back to the last frame boundary, so a torn
//! frame is never followed by another. [`read_frames`] recognises what is
//! left at readback.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::observer::CoverageClass;
use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

pub(crate) mod readback;
pub use readback::{Readback, TraceState, read_frames};

/// Initial local trace cap (§13.3).
pub const LOCAL_CAP: u64 = 64 * 1024 * 1024;
/// Reserve inside the cap for bounded final gap and receipt notes (§13.3).
pub const LOCAL_RESERVE: u64 = 256 * 1024;
/// External queue bound (§13.3).
pub const EXTERNAL_QUEUE_MAX: usize = 4 * 1024 * 1024;
/// External no-progress deadline (§13.3).
pub const EXTERNAL_NO_PROGRESS: Duration = Duration::from_secs(1);
/// Maximum serialized event (§11.4).
pub const EVENT_MAX: usize = 64 * 1024;

/// Which budget a frame is written against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Priority {
    /// An ordinary event; it may not touch the reserve.
    Normal,
    /// A final gap or receipt note; it may use the reserve.
    Reserve,
}

impl Priority {
    /// Where a sink that refused a frame of this priority stands, at least.
    /// A refused ordinary frame marks it lost: what follows is the prefix
    /// and the reserve notes. A refused reserve note closes it: any later
    /// note would follow a missing one, a silent hole (§13.3).
    fn refused(self) -> SinkState {
        match self {
            Priority::Normal => SinkState::Lost,
            Priority::Reserve => SinkState::Closed,
        }
    }
}

/// Where a sink stands after a loss (§13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SinkState {
    /// Every frame within budget is written.
    Open,
    /// Evidence was lost. Ordinary frames are refused, so what a reader
    /// finds stays a prefix of the stream followed by reserve notes (the
    /// gap and receipt notes): "best-effort keeps a prefix and coalesced gap
    /// summaries", never a stream with a silent hole in the middle.
    Lost,
    /// Nothing more is written: a reserve note was refused, or the
    /// destination failed (a write error, torn bytes that cannot be cut
    /// back), so the trace stays visibly incomplete (its last frame is not
    /// the final receipt note, or its last line is torn).
    Closed,
}

impl SinkState {
    /// At least `state`; a sink never reopens.
    fn latch(self, state: SinkState) -> SinkState {
        match (self, state) {
            (SinkState::Closed, _) | (_, SinkState::Closed) => SinkState::Closed,
            (SinkState::Lost, _) | (_, SinkState::Lost) => SinkState::Lost,
            _ => SinkState::Open,
        }
    }
}

/// Why a sink lost evidence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Loss {
    /// A safe reason string recorded in the coverage gap.
    pub reason: String,
    /// Frames that never reached the sink, when the count is exact.
    pub lost_frames: Option<u64>,
}

fn evidence_lost(reason: &str) -> JailError {
    JailError::new(
        ErrorCode::EvidenceLost,
        ErrorStage::Running,
        Remediation::InspectState,
        reason.to_owned(),
    )
}

/// A trace sink shared by the supervisor and, on Linux, the observer thread.
///
/// §13.1 requires exactly one writer per trace stream; the mutex is that single
/// writer, and both producers take it for one frame at a time.
pub type SharedTrace = Arc<Mutex<TraceWriter>>;

/// The classes a trace stream carries events for, which a transport loss can
/// therefore affect (§11.4): the evidence classes. `limits` is not among
/// them: its count comes from the cgroup counters, never from the trace. The
/// writer cannot know which later events a lost sink will refuse, so its note
/// names them all; the receipt narrows the statement per class
/// (`degrade_trace_coverage` leaves unsupported classes alone).
pub const STREAM_CLASSES: [CoverageClass; 5] = [
    CoverageClass::Exec,
    CoverageClass::FsWrite,
    CoverageClass::FsDeny,
    CoverageClass::Net,
    CoverageClass::ProxyNet,
];

/// The gap reason for a trace transport loss, in the stream and the receipt.
pub const TRANSPORT_LOSS_REASON: &str = "trace_transport_loss";

/// One sequence allocator and loss state for all producers of a stream.
pub struct TraceWriter {
    sink: Box<dyn TraceSink + Send>,
    wrapper_seq: u64,
    local_loss: Option<Loss>,
    /// The attempt this stream belongs to, learned from its first event.
    attempt_id: Option<String>,
    /// The last time every accepted frame had reached the sink's
    /// destination: the last point the stream is known to be healthy. For a
    /// queued sink that is the last time its queue was empty, not the last
    /// time it accepted a frame, so the interval a loss note opens covers
    /// every frame still waiting when the loss was found.
    last_healthy_ns: u128,
    /// Whether the note recording the first loss has been attempted.
    gap_noted: bool,
    // Review item 15
    /// The evidence classes this attempt's stream carries: what a loss note
    /// names. Every class a stream could carry until the supervisor narrows
    /// it to the attempt's own (observation on, proxy applied).
    stream_classes: Vec<CoverageClass>,
    /// Where the first loss note's interval starts, once it was attempted:
    /// the receipts record the same loss from the same point (§13.3).
    loss_start_ns: Option<u128>,
}

impl TraceWriter {
    // Review item 15
    /// Narrows the classes this stream's loss note names to the evidence
    /// classes the attempt actually covers.
    pub fn set_stream_classes(&mut self, classes: &[CoverageClass]) {
        self.stream_classes = classes.to_vec();
    }

    /// The start of the first loss note's interval, once a loss was noted.
    #[must_use]
    pub fn loss_start_ns(&self) -> Option<u128> {
        self.loss_start_ns
    }

    /// Serialize under the stream lock. All wrapper notes share this sequence.
    ///
    /// # Errors
    /// Returns [`ErrorCode::EvidenceLost`] when the event cannot be delivered.
    /// The first time the stream loses evidence, a `coverage_gap` note is
    /// written right after, with reserve priority (§13.1, §13.3).
    pub fn write_event(
        &mut self,
        event: &crate::records::Event,
        priority: Priority,
    ) -> Result<(), JailError> {
        if self.attempt_id.is_none() {
            self.attempt_id = Some(event.attempt_id.clone());
        }
        let result = self.write_one(event, priority);
        self.note_first_loss();
        result
    }

    fn write_one(
        &mut self,
        event: &crate::records::Event,
        priority: Priority,
    ) -> Result<(), JailError> {
        let mut event = event.clone();
        if event.source == crate::records::EventSource::Wrapper {
            self.wrapper_seq += 1;
            event.source_seq = self.wrapper_seq;
        }
        let frame = serde_json::to_vec(&event).map_err(|err| {
            let reason = format!("trace serialization failed: {err}");
            self.local_loss.get_or_insert(Loss {
                reason: reason.clone(),
                lost_frames: None,
            });
            evidence_lost(&reason)
        })?;
        let result = self.sink.write_frame(&frame, priority);
        self.mark_healthy();
        result
    }

    fn mark_healthy(&mut self) {
        if self.loss().is_none() && self.sink.caught_up() {
            self.last_healthy_ns = crate::platform::elapsed_since_start_ns();
        }
    }

    /// Writes the in-band record of the stream's first loss, once.
    ///
    /// The note is a wrapper `coverage_gap` from the last healthy point with
    /// no end (the sink stays lost) and an unknown count, since the frames it
    /// will refuse are not known yet. It uses the reserve, so it still lands
    /// after the payload budget is gone; a sink that cannot take even that
    /// counts it as one more lost frame.
    fn note_first_loss(&mut self) {
        if self.gap_noted || self.loss().is_none() {
            return;
        }
        let Some(attempt_id) = self.attempt_id.clone() else {
            return;
        };
        self.gap_noted = true;
        self.loss_start_ns = Some(self.last_healthy_ns);
        let gap = crate::records::Gap {
            classes: self
                .stream_classes
                .iter()
                .map(|class| class.as_str().to_owned())
                .collect(),
            source: "wrapper".to_owned(),
            start_ns: self.last_healthy_ns.to_string(),
            end_ns: None,
            reason: TRANSPORT_LOSS_REASON.to_owned(),
            lost_count: None,
        };
        let note = crate::records::Event::coverage_gap_note(
            &attempt_id,
            0, // assigned by write_one
            std::time::SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            &gap,
        );
        let _ = self.write_one(&note, Priority::Reserve);
    }
}

impl TraceSink for TraceWriter {
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError> {
        self.sink.write_frame(frame, priority)
    }
    fn poll(&mut self) -> Result<(), JailError> {
        let result = self.sink.poll();
        self.mark_healthy();
        self.note_first_loss();
        result
    }
    fn finish(&mut self) {
        self.sink.finish();
        // A loss found only by the terminal drain still gets its note; the
        // next drain (after the final receipt note) delivers or counts it.
        self.note_first_loss();
    }
    fn loss(&self) -> Option<&Loss> {
        self.local_loss.as_ref().or_else(|| self.sink.loss())
    }
    fn caught_up(&self) -> bool {
        self.sink.caught_up()
    }
}

/// Wraps a sink in the shared handle.
#[must_use]
pub fn shared(sink: impl TraceSink + Send + 'static) -> SharedTrace {
    Arc::new(Mutex::new(TraceWriter {
        sink: Box::new(sink),
        wrapper_seq: 0,
        local_loss: None,
        attempt_id: None,
        last_healthy_ns: 0,
        gap_noted: false,
        stream_classes: STREAM_CLASSES.to_vec(),
        loss_start_ns: None,
    }))
}

/// A test seam (S9): a smaller local trace cap, so a live test can exhaust it
/// without writing 64 MiB. Accepted only as a number of bytes in
/// `TRACE_CAP_SEAM_MIN..=LOCAL_CAP`; anything else is ignored. It can only
/// shrink the cap, which can only lose more evidence, which is then reported:
/// every loss reason of a sink shrunk this way names the seam and its value.
pub const TRACE_CAP_SEAM: &str = "OURO_JAIL_TEST_TRACE_CAP";

/// The smallest cap [`TRACE_CAP_SEAM`] accepts: room for a few notes.
pub const TRACE_CAP_SEAM_MIN: u64 = 4096;

/// The operator's local trace budget (issue draft 03): plain decimal bytes
/// in `TRACE_CAP_SEAM_MIN..=TRACE_CAP_MAX`, read from the documented
/// environment allow-list. Raising it can only preserve more evidence; the
/// sink names the override in every loss reason while one is in force.
pub const TRACE_CAP_ENV: &str = "OURO_JAIL_TRACE_CAP";

/// The largest local trace cap an operator may ask for: a bound against
/// typos, not a physical limit.
pub const TRACE_CAP_MAX: u64 = 1024 * 1024 * 1024;

/// The cap [`TRACE_CAP_ENV`] asks for, when it is a decimal byte count in
/// range.
#[must_use]
pub fn env_cap(env: Option<&str>) -> u64 {
    env.and_then(crate::state::plain_decimal)
        .filter(|cap| (TRACE_CAP_SEAM_MIN..=TRACE_CAP_MAX).contains(cap))
        .unwrap_or(LOCAL_CAP)
}

/// The local `(cap, reserve)` for this attempt, given the operator's
/// [`TRACE_CAP_ENV`] value and the seam's value.
///
/// A shrunk cap keeps half of itself as the reserve, up to [`LOCAL_RESERVE`],
/// so the final gap and receipt notes still fit in a small cap.
#[must_use]
pub fn local_bounds(env: Option<&str>, seam: Option<&str>) -> (u64, u64) {
    let base = env_cap(env);
    let cap = seam
        .and_then(crate::state::plain_decimal)
        .filter(|cap| (TRACE_CAP_SEAM_MIN..=base).contains(cap))
        .unwrap_or(base);
    (cap, LOCAL_RESERVE.min(cap / 2))
}

// The trace-fd write-size seam (R03.5)
/// A test seam (S9, J5 wave 3): `OURO_JAIL_TEST_TRACE_FD_WRITE_MAX=<bytes>`
/// makes the external `--trace-fd` sink put at most that many bytes into each
/// `write(2)`, so every frame longer than it reaches the consumer in several
/// partial writes, each resumed at its offset (§13.3: the writer "preserves
/// unwritten offsets"). Without it a partial write happens only when a pipe
/// fills mid-frame, which a live test cannot arrange: a nonblocking pipe write
/// of at most `PIPE_BUF` bytes is all or nothing, and frames are smaller.
///
/// Accepted only as plain decimal bytes in `1..=EVENT_MAX`; anything else is
/// ignored. It changes how bytes are written, never which: it cannot widen a
/// bound, drop a frame or skip a check, and every loss reason of a sink under
/// it names the seam and its value. Like every `OURO_JAIL_TEST_*` variable it
/// is recorded in jail state and in every receipt's native details
/// (`test_seams`).
pub const TRACE_FD_WRITE_SEAM: &str = "OURO_JAIL_TEST_TRACE_FD_WRITE_MAX";

/// The per-write cap [`TRACE_FD_WRITE_SEAM`] asks for, if its value is one.
#[must_use]
pub fn fd_write_max(seam: Option<&str>) -> Option<usize> {
    seam.and_then(crate::state::plain_decimal)
        .and_then(|max| usize::try_from(max).ok())
        .filter(|max| (1..=EVENT_MAX).contains(max))
}

/// One bounded NDJSON trace sink.
pub trait TraceSink {
    /// Writes one already-serialized frame, without its trailing newline.
    ///
    /// # Errors
    /// Returns [`ErrorCode::EvidenceLost`] when the frame cannot be delivered
    /// within this sink's bounds. The sink stays usable and remembers the loss.
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError>;

    /// Terminal drain at settlement (§13.3).
    ///
    /// The default is nothing: sinks whose writes are synchronous have no
    /// queue to drain. A queued sink waits, bounded by its no-progress
    /// deadline, and records whatever still cannot be delivered as evidence
    /// loss instead of dropping it when the descriptor closes.
    fn finish(&mut self) {}

    /// Progress queued writes even while producers are idle.
    fn poll(&mut self) -> Result<(), JailError> {
        Ok(())
    }

    /// The loss this sink has recorded, if any.
    fn loss(&self) -> Option<&Loss>;

    /// Whether every frame this sink accepted has reached its destination.
    /// Synchronous sinks always have; a queued sink has when its queue is
    /// empty.
    fn caught_up(&self) -> bool {
        true
    }
}

/// The file operations the local sink needs.
///
/// Both take explicit offsets, so a failed write never moves a file position
/// that the next frame would inherit. Separate from [`File`] so a unit test
/// can make the truncation itself fail.
trait LocalFile: Send + std::fmt::Debug {
    /// Writes all of `bytes` at `offset`, or fails having written a prefix.
    fn write_at(&mut self, bytes: &[u8], offset: u64) -> std::io::Result<()>;
    /// Sets the file length to `len`.
    fn truncate(&mut self, len: u64) -> std::io::Result<()>;
}

impl LocalFile for File {
    fn write_at(&mut self, bytes: &[u8], offset: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::write_all_at(self, bytes, offset)
    }
    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        self.set_len(len)
    }
}

/// What a sink lost: the first reason, kept because later losses follow
/// from it and a later message would hide its cause, and every frame lost
/// since.
#[derive(Debug, Default)]
struct LossLedger {
    loss: Option<Loss>,
    lost_frames: u64,
    /// What every reason names besides itself: an override of the sink's
    /// bounds or writes, in force for the attempt.
    qualifier: Option<String>,
}

impl LossLedger {
    /// Records `frames` more lost frames for `reason`, and returns the error
    /// for the frame at hand.
    fn lose(&mut self, reason: &str, frames: u64) -> JailError {
        let reason = match &self.qualifier {
            Some(qualifier) => format!("{reason} ({qualifier})"),
            None => reason.to_owned(),
        };
        self.lost_frames += frames;
        let first = self
            .loss
            .as_ref()
            .map_or_else(|| reason.clone(), |loss| loss.reason.clone());
        self.loss = Some(Loss {
            reason: first,
            lost_frames: Some(self.lost_frames),
        });
        evidence_lost(&reason)
    }

    fn loss(&self) -> Option<&Loss> {
        self.loss.as_ref()
    }
}

/// The bounded local `trace.ndjson` sink (§13.3).
///
/// A write that fails part-way is truncated back to the last frame boundary,
/// so a torn frame is never followed by another one; when even that
/// truncation fails, the sink closes and the torn bytes stay the last line,
/// which readback recognises as visibly incomplete.
#[derive(Debug)]
pub struct FileSink {
    file: Box<dyn LocalFile>,
    /// Bytes of complete frames: the offset of the next frame.
    written: u64,
    cap: u64,
    reserve: u64,
    state: SinkState,
    /// Every loss names an override of the cap in force.
    ledger: LossLedger,
}

impl FileSink {
    /// Opens a sink with the specification's bounds.
    #[must_use]
    pub fn new(file: File) -> Self {
        Self::with_bounds(file, LOCAL_CAP, LOCAL_RESERVE)
    }

    /// Opens a sink with explicit bounds.
    ///
    /// Tests use small bounds to exercise exhaustion without writing 64 MiB;
    /// [`LOCAL_CAP`] and [`LOCAL_RESERVE`] are pinned separately by a test.
    #[must_use]
    pub fn with_bounds(file: File, cap: u64, reserve: u64) -> Self {
        Self::over(Box::new(file), cap, reserve)
    }

    fn over(file: Box<dyn LocalFile>, cap: u64, reserve: u64) -> Self {
        FileSink {
            file,
            written: 0,
            cap,
            reserve,
            state: SinkState::Open,
            ledger: LossLedger::default(),
        }
    }

    /// Opens the attempt's sink with the bounds [`local_bounds`] gives for
    /// the operator's [`TRACE_CAP_ENV`] value and `seam` (the value of
    /// [`TRACE_CAP_SEAM`], if any). When either moves the cap, every loss
    /// reason names it and its value, so the receipt that records the loss
    /// also records the override.
    #[must_use]
    pub fn for_attempt(file: File, env: Option<&str>, seam: Option<&str>) -> Self {
        let base = env_cap(env);
        let (cap, reserve) = local_bounds(env, seam);
        let mut sink = Self::with_bounds(file, cap, reserve);
        let mut notes = Vec::new();
        if base != LOCAL_CAP {
            notes.push(format!(
                "the local trace cap was set to {base} bytes by {TRACE_CAP_ENV}"
            ));
        }
        if cap != base {
            notes.push(format!(
                "the local trace cap was shrunk to {cap} bytes by the test seam {TRACE_CAP_SEAM}"
            ));
        }
        if !notes.is_empty() {
            sink.ledger.qualifier = Some(notes.join("; "));
        }
        sink
    }

    /// Bytes of complete frames written so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Records one more lost frame.
    fn lose(&mut self, reason: &str) -> JailError {
        self.ledger.lose(reason, 1)
    }

    /// Latches at least `state`; a sink never reopens.
    fn latch(&mut self, state: SinkState) {
        self.state = self.state.latch(state);
    }
}

impl TraceSink for FileSink {
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError> {
        match (self.state, priority) {
            (SinkState::Closed, _) => {
                return Err(self.lose("the local trace is closed after an earlier loss"));
            }
            (SinkState::Lost, Priority::Normal) => {
                return Err(self.lose("the local trace keeps only its prefix after a loss"));
            }
            _ => {}
        }
        let on_failure = priority.refused();
        if frame.len() > EVENT_MAX {
            self.latch(on_failure);
            return Err(self.lose("serialized event exceeds the 64 KiB maximum"));
        }
        let needed = frame.len() as u64 + 1;
        let budget = match priority {
            Priority::Normal => self.cap.saturating_sub(self.reserve),
            Priority::Reserve => self.cap,
        };
        if self.written + needed > budget {
            self.latch(on_failure);
            return Err(self.lose(match priority {
                Priority::Normal => "local trace payload budget is exhausted",
                Priority::Reserve => "local trace reserve is exhausted",
            }));
        }
        let mut bytes = Vec::with_capacity(frame.len() + 1);
        bytes.extend_from_slice(frame);
        bytes.push(b'\n');
        match self.file.write_at(&bytes, self.written) {
            Ok(()) => {
                self.written += needed;
                Ok(())
            }
            Err(error) => {
                // A short write followed by a failure (disk full, EFBIG) left
                // part of this frame in the file. Cut it off, so the file ends
                // on the last frame boundary; if that fails too, write nothing
                // more, so the torn bytes stay the visibly incomplete last line.
                // The cap stays bounded either way: `written` never advances
                // past a frame that did not land.
                match self.file.truncate(self.written) {
                    Ok(()) => self.latch(on_failure),
                    Err(_) => self.latch(SinkState::Closed),
                }
                Err(self.lose(&format!("local trace write failed: {error}")))
            }
        }
    }

    fn loss(&self) -> Option<&Loss> {
        self.ledger.loss()
    }
}

/// Reserve inside the external queue for the final gap and receipt notes.
///
/// §13.3 bounds the external queue at 4 MiB and reserves 256 KiB of the local
/// cap for "bounded final gap/receipt notes". The same reserve inside the
/// external bound means the note that records a transport loss, and the final
/// receipt note, can still reach a consumer that resumes reading, while the
/// queue as a whole never exceeds its 4 MiB.
pub const EXTERNAL_RESERVE: usize = 256 * 1024;

/// Whole frames waiting for a nonblocking descriptor, each with a tag (a
/// trace frame's [`Priority`]), the front one possibly written in part.
///
/// A flush writes straight from the front frame at its offset, so its cost
/// is one `write` per frame it moves, whatever the queue holds, and a
/// partly written frame is resumed, never re-sent as a second one. A write
/// that would block leaves the rest queued.
#[derive(Debug)]
pub struct FrameQueue<T> {
    file: File,
    /// Whole frames, oldest first.
    frames: VecDeque<(Vec<u8>, T)>,
    /// Bytes of the front frame already written.
    front_written: usize,
    /// Bytes still to write, over all queued frames.
    queued: usize,
}

impl<T> FrameQueue<T> {
    /// An empty queue for `fd`, which it switches to nonblocking mode.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidFd`] when the descriptor cannot be
    /// switched to nonblocking mode, which is also how a closed one is
    /// detected.
    pub fn new(fd: OwnedFd) -> Result<Self, JailError> {
        set_nonblocking(fd.as_raw_fd())?;
        Ok(FrameQueue {
            file: File::from(fd),
            frames: VecDeque::new(),
            front_written: 0,
            queued: 0,
        })
    }

    /// Queues one whole frame.
    pub fn push(&mut self, frame: Vec<u8>, tag: T) {
        self.queued += frame.len();
        self.frames.push_back((frame, tag));
    }

    /// Bytes queued and not yet written.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queued
    }

    /// Frames queued, a partly written one included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether every queued frame was written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Whether the front frame was written in part: what follows it on the
    /// wire would join its torn bytes on one line.
    #[must_use]
    pub fn torn(&self) -> bool {
        self.front_written > 0
    }

    /// The tags of the queued frames, oldest first.
    pub fn tags(&self) -> impl Iterator<Item = &T> {
        self.frames.iter().map(|(_, tag)| tag)
    }

    /// Drops every queued frame, a partly written one included.
    pub fn clear(&mut self) {
        self.frames.clear();
        self.front_written = 0;
        self.queued = 0;
    }

    /// The descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }

    /// Writes what the descriptor takes right now, at most `write_max` bytes
    /// a write when given. Returns whether any byte was written.
    ///
    /// # Errors
    /// A write's failure other than `WouldBlock` and `Interrupted`: the
    /// descriptor can take nothing more (a reader that closed its end
    /// included). The queue is left as it was.
    pub fn flush(&mut self, write_max: Option<usize>) -> std::io::Result<bool> {
        let mut progressed = false;
        while let Some((front, _)) = self.frames.front() {
            let front_len = front.len();
            let end = write_max.map_or(front_len, |max| (self.front_written + max).min(front_len));
            match (&self.file).write(&front[self.front_written..end]) {
                Ok(0) => break,
                Ok(written) => {
                    progressed = true;
                    self.front_written += written;
                    self.queued -= written;
                    if self.front_written == front_len {
                        self.frames.pop_front();
                        self.front_written = 0;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(progressed)
    }
}

/// The external `--trace-fd` sink (§13.3): nonblocking, with a [`FrameQueue`]
/// bounded at [`EXTERNAL_QUEUE_MAX`], a reserve for the final notes and a
/// no-progress deadline.
#[derive(Debug)]
pub struct FdSink {
    /// Each frame ends in its LF and carries its priority: a drain that
    /// drops a reserve note must not let a later one through.
    queue: FrameQueue<Priority>,
    queue_max: usize,
    reserve: usize,
    no_progress: Duration,
    last_progress: Instant,
    /// §13.3: "best-effort can continue with the sink marked lost". Closed
    /// also when the descriptor failed (a consumer that closed its end, or
    /// any other write error): nothing more can be delivered, and every
    /// frame is counted.
    state: SinkState,
    /// Every loss names the write-size seam when it is in force.
    ledger: LossLedger,
    /// [`TRACE_FD_WRITE_SEAM`]'s cap on each write, when the seam is set.
    write_max: Option<usize>,
}

impl FdSink {
    /// A sink over `fd`, which it marks nonblocking. §6.1 requires that the
    /// invocation own every supplied channel exclusively; the sink closes it
    /// when dropped.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidFd`] when the descriptor cannot be switched
    /// to nonblocking mode, which is also how a closed fd is detected.
    pub fn new(fd: OwnedFd) -> Result<Self, JailError> {
        Ok(FdSink {
            queue: FrameQueue::new(fd)?,
            queue_max: EXTERNAL_QUEUE_MAX,
            reserve: EXTERNAL_RESERVE,
            no_progress: EXTERNAL_NO_PROGRESS,
            last_progress: Instant::now(),
            state: SinkState::Open,
            ledger: LossLedger::default(),
            write_max: None,
        })
    }

    /// A sink over `fd` for an attempt, applying [`TRACE_FD_WRITE_SEAM`]'s
    /// value `seam` if it is one.
    ///
    /// # Errors
    /// As for [`FdSink::new`].
    pub fn for_attempt(fd: OwnedFd, seam: Option<&str>) -> Result<Self, JailError> {
        let mut sink = Self::new(fd)?;
        sink.write_max = fd_write_max(seam);
        sink.ledger.qualifier = sink.write_max.map(|max| {
            format!("trace fd writes capped to {max} bytes by the test seam {TRACE_FD_WRITE_SEAM}")
        });
        Ok(sink)
    }

    /// Overrides the bounds, for tests that must reach them quickly. The
    /// reserve shrinks with the queue: at most a quarter of it.
    #[must_use]
    pub fn with_bounds(mut self, queue_max: usize, no_progress: Duration) -> Self {
        self.queue_max = queue_max;
        self.reserve = EXTERNAL_RESERVE.min(queue_max / 4);
        self.no_progress = no_progress;
        self
    }

    /// Bytes currently waiting in the queue.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.queued()
    }

    /// Drains what the descriptor will accept right now.
    ///
    /// # Errors
    /// Returns [`ErrorCode::EvidenceLost`] when this call records a loss: a
    /// write error (a broken pipe included), or a queue that has made no
    /// progress for the no-progress deadline. A loss already recorded is not
    /// reported again; [`TraceSink::loss`] keeps it.
    pub fn flush_now(&mut self) -> Result<(), JailError> {
        match self.queue.flush(self.write_max) {
            Ok(true) => self.last_progress = Instant::now(),
            Ok(false) => {}
            Err(error) => {
                return Err(self.break_down(&format!("trace fd write failed: {error}")));
            }
        }
        if self.state == SinkState::Open
            && !self.queue.is_empty()
            && self.last_progress.elapsed() > self.no_progress
        {
            self.state = SinkState::Lost;
            return Err(self.lose("trace fd made no progress within its deadline", 0));
        }
        Ok(())
    }

    /// Terminal drain, bounded by the no-progress deadline (§13.3).
    ///
    /// Waits for the external consumer to accept the queued frames, and
    /// counts whatever is still undelivered when the budget ends as lost
    /// instead of dropping it when the descriptor closes. A consumer that
    /// already ran out its deadline without resuming gets no second one, so
    /// a saturated trace never delays settlement by more than one deadline.
    /// After it, the queue is empty: delivered or counted.
    pub fn drain_final(&mut self) {
        if self.queue.is_empty() {
            return;
        }
        let stalled =
            self.state == SinkState::Lost && self.last_progress.elapsed() > self.no_progress;
        if self.state != SinkState::Closed && !stalled {
            let deadline = Instant::now() + self.no_progress;
            while !self.queue.is_empty() && self.state != SinkState::Closed {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                wait_writable(self.queue.as_fd().as_raw_fd(), remaining);
                // A loss found here is recorded by flush_now itself; the
                // loop's own deadline bounds the wait either way.
                let _ = self.flush_now();
            }
        }
        if !self.queue.is_empty() {
            let undelivered = self.queue.len() as u64;
            // A frame already partly on the wire cannot be finished later, and
            // anything written after its torn bytes would join them on one
            // line: a corrupt stream. Nothing more is written then, and the
            // consumer sees a visibly incomplete last line. With no partial
            // frame the stream still ends on a frame boundary, so the reserve
            // notes may follow.
            // A reserve note dropped here (the loss note queued behind a
            // stalled consumer's frames) is a refused reserve note: as in
            // `write_frame`, nothing more is written, so no later note is
            // delivered after the missing one (§13.3).
            let refused = if self.queue.torn() {
                SinkState::Closed
            } else if self.queue.tags().any(|tag| *tag == Priority::Reserve) {
                Priority::Reserve.refused()
            } else {
                Priority::Normal.refused()
            };
            self.queue.clear();
            self.state = self.state.latch(refused);
            let _ = self.lose(
                "trace fd could not deliver its queued frames before settlement",
                undelivered,
            );
        }
    }

    /// The descriptor failed: every queued frame, a partly written one
    /// included, is lost, and nothing more will be written.
    fn break_down(&mut self, reason: &str) -> JailError {
        let undelivered = self.queue.len() as u64;
        self.queue.clear();
        self.state = SinkState::Closed;
        self.lose(reason, undelivered)
    }

    /// Records `frames` more lost frames.
    fn lose(&mut self, reason: &str, frames: u64) -> JailError {
        self.ledger.lose(reason, frames)
    }
}

impl TraceSink for FdSink {
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError> {
        match (self.state, priority) {
            (SinkState::Closed, _) => {
                return Err(self.lose("the trace fd writes nothing more after an earlier loss", 1));
            }
            (SinkState::Lost, Priority::Normal) => {
                return Err(self.lose("the trace fd sink is marked lost", 1));
            }
            _ => {}
        }
        if frame.len() > EVENT_MAX {
            self.state = self.state.latch(priority.refused());
            return Err(self.lose("serialized event exceeds the 64 KiB maximum", 1));
        }
        let budget = match priority {
            Priority::Normal => self.queue_max.saturating_sub(self.reserve),
            Priority::Reserve => self.queue_max,
        };
        if self.queue.queued() + frame.len() + 1 > budget {
            self.state = self.state.latch(priority.refused());
            return Err(self.lose(
                match priority {
                    Priority::Normal => "trace fd queue overflowed its 4 MiB bound",
                    Priority::Reserve => "trace fd queue reserve is exhausted",
                },
                1,
            ));
        }
        if self.queue.is_empty() {
            self.last_progress = Instant::now();
        }
        let mut owned = Vec::with_capacity(frame.len() + 1);
        owned.extend_from_slice(frame);
        owned.push(b'\n');
        self.queue.push(owned, priority);
        self.flush_now()
    }

    fn finish(&mut self) {
        self.drain_final();
    }

    fn poll(&mut self) -> Result<(), JailError> {
        self.flush_now()
    }

    fn loss(&self) -> Option<&Loss> {
        self.ledger.loss()
    }

    fn caught_up(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Wait until `fd` accepts a write, or `timeout` passes. Best effort: a poll
/// error or a spurious wakeup simply returns and the caller retries within
/// its own deadline.
fn wait_writable(fd: RawFd, timeout: Duration) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let millis = i32::try_from(timeout.as_millis().min(1_000)).unwrap_or(1_000);
    // SAFETY: `pfd` is a live, writable pollfd for the call's duration.
    let _ = unsafe { libc::poll(&raw mut pfd, 1, millis.max(1)) };
}

/// Switches `fd` to nonblocking mode.
///
/// Shared with the control channel, which needs the same property for the same
/// reason: a consumer that stops reading must not stall the supervisor.
///
/// # Errors
/// Returns [`ErrorCode::InvalidFd`] when `fcntl` fails, which also detects a
/// descriptor that is not open.
pub fn set_nonblocking(fd: RawFd) -> Result<(), JailError> {
    let invalid = |message: String| {
        JailError::new(
            ErrorCode::InvalidFd,
            ErrorStage::Preparing,
            Remediation::Configuration,
            message,
        )
    };
    // SAFETY: `fcntl` with `F_GETFL` reads the flags of the descriptor the
    // caller owns. It takes no pointer and cannot write to this process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(invalid(format!(
            "descriptor {fd} cannot be inspected: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `F_SETFL` writes back the flags just read plus `O_NONBLOCK`, on
    // the same owned descriptor, with no pointer argument.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(invalid(format!(
            "descriptor {fd} cannot be set nonblocking: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bounds_are_the_ones_the_specification_names() {
        assert_eq!(LOCAL_CAP, 64 * 1024 * 1024);
        assert_eq!(LOCAL_RESERVE, 256 * 1024);
        assert_eq!(EXTERNAL_QUEUE_MAX, 4 * 1024 * 1024);
        assert_eq!(
            EXTERNAL_RESERVE, LOCAL_RESERVE as usize,
            "the external reserve mirrors the local one"
        );
        assert_eq!(TRACE_CAP_SEAM_MIN, 4096);
        assert_eq!(EXTERNAL_NO_PROGRESS, Duration::from_secs(1));
        assert_eq!(EVENT_MAX, 64 * 1024);
        assert_eq!(
            crate::records::GATE_FRAME_MAX,
            1024,
            "every `maximum` in the specification is inclusive"
        );
    }

    #[test]
    fn the_payload_budget_stops_before_the_reserve_and_the_reserve_still_writes() {
        let file = tempfile::NamedTempFile::new().expect("a temporary file");
        let handle = file.reopen().expect("a writable handle");
        let mut sink = FileSink::with_bounds(handle, 100, 40);
        // 30 payload bytes fit under the 60-byte payload budget.
        sink.write_frame(&[b'a'; 29], Priority::Normal)
            .expect("the first frame fits");
        let error = sink
            .write_frame(&[b'b'; 39], Priority::Normal)
            .expect_err("the payload budget is exhausted");
        assert_eq!(error.code, ErrorCode::EvidenceLost);
        sink.write_frame(&[b'c'; 39], Priority::Reserve)
            .expect("a final note may use the reserve");
        assert_eq!(sink.written(), 70);
        assert!(sink.loss().is_some(), "the loss is remembered, not silent");
        let written = std::fs::read(file.path()).expect("readable");
        assert_eq!(
            written.iter().filter(|byte| **byte == b'\n').count(),
            2,
            "only the two accepted frames reached the file"
        );
    }

    /// A file whose writes stop at `limit` bytes, like `RLIMIT_FSIZE` or a
    /// full disk, and whose truncation can be made to fail.
    #[derive(Debug, Default)]
    struct Scripted {
        data: Vec<u8>,
        limit: usize,
        writes: usize,
        truncate_fails: bool,
    }

    #[derive(Debug, Clone, Default)]
    struct Shared(Arc<Mutex<Scripted>>);

    impl LocalFile for Shared {
        fn write_at(&mut self, bytes: &[u8], offset: u64) -> std::io::Result<()> {
            let mut file = self.0.lock().unwrap();
            file.writes += 1;
            let offset = usize::try_from(offset).unwrap();
            let len = offset.max(file.data.len());
            file.data.resize(len, 0);
            let room = file.limit.saturating_sub(offset);
            let taken = bytes.len().min(room);
            file.data.truncate(offset);
            file.data.extend_from_slice(&bytes[..taken]);
            if taken < bytes.len() {
                return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
            }
            Ok(())
        }
        fn truncate(&mut self, len: u64) -> std::io::Result<()> {
            let mut file = self.0.lock().unwrap();
            if file.truncate_fails {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            file.data.truncate(usize::try_from(len).unwrap());
            Ok(())
        }
    }

    fn scripted(limit: usize, truncate_fails: bool) -> (Shared, FileSink) {
        let file = Shared(Arc::new(Mutex::new(Scripted {
            limit,
            truncate_fails,
            ..Scripted::default()
        })));
        let sink = FileSink::over(Box::new(file.clone()), LOCAL_CAP, LOCAL_RESERVE);
        (file, sink)
    }

    fn frame(index: u8) -> Vec<u8> {
        let mut frame = format!("{{\"seq\":{index},\"pad\":\"").into_bytes();
        frame.resize(148, b'x');
        frame.extend(b"\"}");
        frame
    }

    #[test]
    fn a_failed_write_is_cut_back_to_its_frame_boundary() {
        let (file, mut sink) = scripted(500, false);
        for index in 0..3 {
            sink.write_frame(&frame(index), Priority::Normal).unwrap();
        }
        // The fourth frame is written in part, then the file refuses more.
        assert!(sink.write_frame(&frame(3), Priority::Normal).is_err());
        assert_eq!(
            file.0.lock().unwrap().data.len(),
            453,
            "the torn bytes are gone"
        );
        assert!(sink.write_frame(&frame(4), Priority::Normal).is_err());
        file.0.lock().unwrap().limit = 10_000;
        sink.write_frame(&frame(5), Priority::Reserve)
            .expect("a note after the loss lands on the frame boundary");
        let data = file.0.lock().unwrap().data.clone();
        let readback = read_frames(&data);
        assert_eq!(readback.state, TraceState::Complete);
        assert_eq!(readback.frames.len(), 4);
        assert_eq!(sink.loss().unwrap().lost_frames, Some(2));
    }

    #[test]
    fn a_failed_write_that_cannot_be_cut_back_closes_the_sink() {
        let (file, mut sink) = scripted(500, true);
        for index in 0..3 {
            sink.write_frame(&frame(index), Priority::Normal).unwrap();
        }
        assert!(sink.write_frame(&frame(3), Priority::Normal).is_err());
        file.0.lock().unwrap().limit = 10_000;
        let writes = file.0.lock().unwrap().writes;
        assert!(
            sink.write_frame(&frame(5), Priority::Reserve).is_err(),
            "nothing may follow torn bytes that could not be removed"
        );
        assert_eq!(
            file.0.lock().unwrap().writes,
            writes,
            "a closed sink does not even try to write"
        );
        let data = file.0.lock().unwrap().data.clone();
        assert_eq!(data.len(), 500);
        let readback = read_frames(&data);
        assert_eq!(
            readback.state,
            TraceState::Incomplete,
            "the torn frame stays the visibly incomplete last line"
        );
        assert_eq!(readback.frames.len(), 3);
        assert_eq!(sink.loss().unwrap().lost_frames, Some(2));
    }

    #[test]
    fn an_exhausted_reserve_closes_the_sink() {
        let file = tempfile::NamedTempFile::new().expect("a temporary file");
        let handle = file.reopen().expect("a writable handle");
        let mut sink = FileSink::with_bounds(handle, 420, 250);
        sink.write_frame(&frame(0), Priority::Normal).unwrap();
        assert!(sink.write_frame(&frame(1), Priority::Normal).is_err());
        sink.write_frame(&frame(2), Priority::Reserve).unwrap();
        // 302 of 420 bytes are used; this note does not fit.
        assert!(sink.write_frame(&frame(3), Priority::Reserve).is_err());
        // A smaller note would, but it would follow a missing one.
        assert!(
            sink.write_frame(b"{\"n\":1}", Priority::Reserve).is_err(),
            "after the reserve is exhausted the trace stays visibly incomplete"
        );
        assert_eq!(sink.written(), 302);
        assert_eq!(sink.loss().unwrap().lost_frames, Some(3));
    }

    /// A pipe nobody reads, filled to the last byte, so every frame a sink
    /// writes into it stays queued.
    fn full_pipe() -> (std::io::PipeReader, std::os::fd::OwnedFd) {
        let (reader, writer) = std::io::pipe().expect("a pipe");
        let writer = std::os::fd::OwnedFd::from(writer);
        set_nonblocking(writer.as_raw_fd()).expect("nonblocking");
        let mut file = File::from(writer);
        loop {
            match file.write(&[b'f'; 4096]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("filling the pipe: {error}"),
            }
        }
        while file.write(b"f").is_ok() {}
        (reader, std::os::fd::OwnedFd::from(file))
    }

    /// The external sink's twin of `an_exhausted_reserve_closes_the_sink`.
    /// A refused reserve note ends the stream there too: a smaller note
    /// that would still fit is refused, since a reader would find it after
    /// the missing one, a silent hole (§13.3).
    #[test]
    fn an_exhausted_reserve_closes_the_fd_sink() {
        let (reader, writer) = full_pipe();
        let sink = FdSink::new(writer).expect("nonblocking");
        // A 1000-byte queue keeps 250 bytes for the reserve.
        let mut sink = sink.with_bounds(1000, Duration::from_secs(60));
        for index in 0..4 {
            sink.write_frame(&frame(index), Priority::Normal)
                .expect("within the payload budget");
        }
        assert!(sink.write_frame(&frame(4), Priority::Normal).is_err());
        sink.write_frame(&frame(5), Priority::Reserve)
            .expect("the reserve takes a note after the loss");
        sink.write_frame(&frame(6), Priority::Reserve)
            .expect("and another while it fits");
        assert_eq!(sink.queued(), 906);
        // 906 of 1000 bytes are queued; this note does not fit.
        assert!(sink.write_frame(&frame(7), Priority::Reserve).is_err());
        // A smaller note would, but it would follow a missing one.
        assert!(
            sink.write_frame(b"{\"n\":1}", Priority::Reserve).is_err(),
            "after a refused reserve note the stream writes nothing more"
        );
        assert_eq!(sink.queued(), 906);
        assert_eq!(sink.loss().unwrap().lost_frames, Some(3));
        drop(reader);
    }

    /// The same for a reserve note refused for its size: nothing follows it.
    #[test]
    fn an_oversized_reserve_note_closes_the_fd_sink() {
        let (reader, writer) = full_pipe();
        let mut sink = FdSink::new(writer).expect("nonblocking");
        assert!(
            sink.write_frame(&[b'x'; EVENT_MAX + 1], Priority::Reserve)
                .is_err()
        );
        assert!(
            sink.write_frame(b"{\"n\":1}", Priority::Reserve).is_err(),
            "a note after a refused one would hide it"
        );
        assert_eq!(sink.queued(), 0);
        drop(reader);
    }

    // Review item 15, the loss note names what the attempt covers
    /// The first loss note names the evidence classes this attempt's stream
    /// was set to carry, not every class a stream could carry, and the writer
    /// keeps the note's start so the receipts can record the same loss.
    #[test]
    fn the_loss_note_names_the_covered_classes_and_keeps_its_start() {
        let file = tempfile::NamedTempFile::new().expect("a temporary file");
        let trace = shared(FileSink::with_bounds(
            file.reopen().expect("a handle"),
            4096,
            2048,
        ));
        trace
            .lock()
            .unwrap()
            .set_stream_classes(&CoverageClass::AUDIT);
        assert_eq!(trace.lock().unwrap().loss_start_ns(), None);
        let filler = "f".repeat(400);
        for index in 0..100 {
            let event = crate::records::Event::lifecycle_note(
                "att_test",
                0,
                std::time::SystemTime::now(),
                0,
                &format!("filler_{index}_{filler}"),
            );
            if trace
                .lock()
                .unwrap()
                .write_event(&event, Priority::Normal)
                .is_err()
            {
                break;
            }
        }
        let start = trace
            .lock()
            .unwrap()
            .loss_start_ns()
            .expect("the loss note's start is kept");
        let bytes = std::fs::read(file.path()).expect("the trace");
        let readback = read_frames(&bytes);
        let note = readback
            .frames
            .iter()
            .find(|frame| frame["fields"]["reason"] == TRANSPORT_LOSS_REASON)
            .expect("a loss note");
        assert_eq!(
            note["fields"]["classes"],
            serde_json::json!(["exec", "fs.write", "fs.deny", "net"]),
            "no proxy.net: this attempt has no proxy"
        );
        assert_eq!(
            note["fields"]["start_ns"],
            serde_json::json!(start.to_string())
        );
        assert_eq!(note["fields"]["source"], "wrapper");
    }

    /// Found by `trace_loss_recorded` on the reference host (J5-C fix wave):
    /// a consumer that stalls past the no-progress deadline makes the sink
    /// lost with frames still queued, the loss note queued behind them. The
    /// terminal drain then dropped the whole queue, the note with it, and
    /// still delivered the final receipt note written after: a complete-
    /// looking trace with a silent hole where its loss note belongs. A sink
    /// that drops a reserve note now writes nothing more, as the local sink
    /// closes when a reserve note fails (§13.3: after a loss the stream is a
    /// prefix plus the reserve notes, never a later note after a lost one).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_drain_that_drops_a_reserve_note_writes_nothing_after_it() {
        // On Linux a nonblocking pipe write of at most PIPE_BUF bytes is whole
        // or refused, so no frame is left partly written (which would end the
        // stream for a different reason); hence the Linux gate.
        let (reader, writer) = std::io::pipe().expect("a pipe");
        let sink = FdSink::new(OwnedFd::from(writer)).expect("nonblocking");
        let mut sink = sink.with_bounds(EXTERNAL_QUEUE_MAX, Duration::from_millis(50));
        let frame = vec![b'x'; 1000];
        while sink.queued() == 0 {
            sink.write_frame(&frame, Priority::Normal).expect("queued");
        }
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            sink.poll().is_err(),
            "no progress within the deadline is loss"
        );
        sink.write_frame(b"{\"loss\":\"note\"}", Priority::Reserve)
            .expect("the loss note is queued behind the stalled frames");
        sink.finish();
        assert_eq!(
            sink.queued(),
            0,
            "the stalled queue was dropped and counted"
        );
        assert!(
            sink.write_frame(b"{\"final\":\"note\"}", Priority::Reserve)
                .is_err(),
            "after a dropped reserve note nothing more is written"
        );
        drop(reader);
    }

    // The trace-fd write-size seam (R03.5)
    /// The seam's values: plain decimal bytes in `1..=EVENT_MAX`, else no cap.
    #[test]
    fn the_write_size_seam_accepts_only_a_byte_count() {
        assert_eq!(fd_write_max(Some("64")), Some(64));
        assert_eq!(fd_write_max(Some("1")), Some(1));
        assert_eq!(fd_write_max(Some(&EVENT_MAX.to_string())), Some(EVENT_MAX));
        for ignored in [
            None,
            Some(""),
            Some("0"),
            Some("064"),
            Some("-5"),
            Some("x"),
            Some("65537"),
        ] {
            assert_eq!(fd_write_max(ignored), None, "{ignored:?}");
        }
    }

    /// Under the seam every `write(2)` the external sink makes carries at most
    /// the cap, so a frame longer than it is written in several partial
    /// writes, each resumed at its offset: a datagram pair shows each write as
    /// one datagram, and the datagrams reassemble every frame exactly once.
    #[cfg(target_os = "linux")]
    #[test]
    fn under_the_write_size_seam_every_frame_is_written_in_pieces() {
        let (reader, writer) = std::os::unix::net::UnixDatagram::pair().expect("a socket pair");
        let mut sink = FdSink::for_attempt(OwnedFd::from(writer), Some("64")).expect("nonblocking");
        let frames: Vec<Vec<u8>> = (0..20u8)
            .map(|index| format!("{{\"n\":{index},\"pad\":\"{}\"}}", "x".repeat(600)).into_bytes())
            .collect();
        for frame in &frames {
            sink.write_frame(frame, Priority::Normal).expect("queued");
        }
        sink.finish();
        assert!(sink.loss().is_none(), "{:?}", sink.loss());
        drop(sink);
        let mut received = Vec::new();
        let mut writes = 0usize;
        let mut buffer = [0u8; 4096];
        while let Ok(size) = reader.recv(&mut buffer) {
            if size == 0 {
                break;
            }
            assert!(size <= 64, "a write of {size} bytes under a 64-byte cap");
            received.extend_from_slice(&buffer[..size]);
            writes += 1;
            reader.set_nonblocking(true).expect("nonblocking reader");
        }
        let mut expected = Vec::new();
        for frame in &frames {
            expected.extend_from_slice(frame);
            expected.push(b'\n');
        }
        assert_eq!(
            received, expected,
            "every frame once, in order, reassembled"
        );
        assert!(
            writes >= frames.len() * 9,
            "each ~620-byte frame took at least ten writes: {writes}"
        );
    }

    #[test]
    fn an_oversized_event_is_refused_rather_than_truncated() {
        let file = tempfile::NamedTempFile::new().expect("a temporary file");
        let handle = file.reopen().expect("a writable handle");
        let mut sink = FileSink::new(handle);
        let error = sink
            .write_frame(&[b'x'; EVENT_MAX + 1], Priority::Normal)
            .expect_err("an oversized event refuses");
        assert_eq!(error.code, ErrorCode::EvidenceLost);
        assert_eq!(sink.written(), 0);
    }

    /// T1 (§13.3): `last_healthy_ns` does not advance across a failed write,
    /// so the loss note's interval starts at the last *healthy* point, not
    /// after the lost frame.
    #[test]
    fn the_loss_interval_starts_at_the_last_healthy_write() {
        let file = tempfile::NamedTempFile::new().expect("a temporary file");
        let trace = shared(FileSink::with_bounds(
            file.reopen().expect("a handle"),
            4096,
            2048,
        ));
        let mut writer = trace.lock().unwrap();
        let event = crate::records::Event::lifecycle_note(
            "att_test",
            0,
            std::time::SystemTime::now(),
            0,
            "small",
        );
        writer
            .write_event(&event, Priority::Normal)
            .expect("the first event fits");
        let healthy = crate::platform::elapsed_since_start_ns();
        // Long enough that a last_healthy_ns advanced across the failing
        // write would be measurably later than `healthy`.
        std::thread::sleep(Duration::from_millis(60));
        let before = crate::platform::elapsed_since_start_ns();
        let too_big = crate::records::Event::lifecycle_note(
            "att_test",
            1,
            std::time::SystemTime::now(),
            0,
            &"x".repeat(8000),
        );
        assert!(
            writer.write_event(&too_big, Priority::Normal).is_err(),
            "the second event exceeds the payload budget"
        );
        let start = writer.loss_start_ns().expect("the loss was noted");
        assert!(
            start + 30_000_000 < before,
            "the loss interval starts at the last healthy write ({start}), not \
             after the lost frame (before {before})"
        );
        assert!(start <= healthy + 5_000_000, "{start} vs {healthy}");
    }

    /// T4: an `FdSink` that refuses an oversized frame latches `Lost`, so
    /// every ordinary frame afterwards is refused too: the stream stays a
    /// prefix, never a hole plus later frames (§13.3).
    #[test]
    fn an_fd_sink_that_drops_an_oversized_frame_latches_lost() {
        let file = tempfile::NamedTempFile::new().expect("a temporary file");
        let fd = OwnedFd::from(file.reopen().expect("a handle"));
        let mut sink = FdSink::new(fd).expect("nonblocking");
        let error = sink
            .write_frame(&[b'x'; EVENT_MAX + 1], Priority::Normal)
            .expect_err("an oversized frame refuses");
        assert_eq!(error.code, ErrorCode::EvidenceLost);
        let error = sink
            .write_frame(b"{\"n\":1}", Priority::Normal)
            .expect_err("after the oversized frame the sink is latched lost");
        assert!(
            error.message.contains("marked lost"),
            "the refusal must come from the latch, not the queue: {error:?}"
        );
        assert_eq!(sink.loss().expect("the loss is kept").lost_frames, Some(2));
        sink.finish();
        assert!(
            std::fs::read(file.path()).expect("readable").is_empty(),
            "no frame reached the trace, not even after the loss"
        );
    }
}
