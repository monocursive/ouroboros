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
//! notes), so a reader never finds ordinary frames after a silent hole.
//!
//! The external writer queues whole frames and resumes a partially written
//! one at its own offset, never re-sending it as a second event. The local
//! writer truncates a failed write back to the last frame boundary, so a torn
//! frame is never followed by another. [`read_frames`] recognises what is
//! left at readback.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

pub mod readback;
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
/// therefore affect (§11.4). The writer cannot know which later events a lost
/// sink will refuse, so its note names them all; the receipt narrows the
/// statement per class (`degrade_trace_coverage` leaves unsupported classes
/// alone).
pub const STREAM_CLASSES: [&str; 6] = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"];

/// The gap reason for a trace transport loss, in the stream and the receipt.
pub const TRANSPORT_LOSS_REASON: &str = "trace_transport_loss";

/// One sequence allocator and loss state for all producers of a stream.
pub struct TraceWriter {
    sink: Box<dyn TraceSink + Send>,
    wrapper_seq: u64,
    local_loss: Option<Loss>,
    /// The attempt this stream belongs to, learned from its first event.
    attempt_id: Option<String>,
    /// Elapsed time of the last frame the sink accepted: the last point the
    /// stream is known to be healthy.
    last_healthy_ns: u128,
    /// Whether the note recording the first loss has been attempted.
    gap_noted: bool,
}

impl TraceWriter {
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
        if result.is_ok() {
            self.last_healthy_ns = crate::platform::elapsed_since_start_ns();
        }
        result
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
        let gap = crate::records::Gap {
            classes: STREAM_CLASSES
                .iter()
                .map(|class| (*class).to_owned())
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

/// The local `(cap, reserve)` for this attempt, given the seam's value.
///
/// A shrunk cap keeps half of itself as the reserve, up to [`LOCAL_RESERVE`],
/// so the final gap and receipt notes still fit in a small cap.
#[must_use]
pub fn local_bounds(seam: Option<&str>) -> (u64, u64) {
    seam.and_then(|text| text.parse::<u64>().ok())
        .filter(|cap| (TRACE_CAP_SEAM_MIN..=LOCAL_CAP).contains(cap))
        .map_or((LOCAL_CAP, LOCAL_RESERVE), |cap| {
            (cap, LOCAL_RESERVE.min(cap / 2))
        })
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

/// Where a local sink stands after a loss (§13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileState {
    /// Every frame within budget is written.
    Open,
    /// Evidence was lost. Ordinary frames are refused, so the file stays a
    /// prefix of the stream; reserve notes (the gap and receipt notes) are
    /// still written. This is "best-effort keeps a prefix and coalesced gap
    /// summaries".
    Lost,
    /// Nothing more is written: the reserve is exhausted or a reserve note
    /// failed, so the trace stays visibly incomplete (its last frame is not
    /// the final receipt note), or a failed write could not be truncated back
    /// to its frame boundary, so its torn bytes stay the last line.
    Closed,
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
    state: FileState,
    loss: Option<Loss>,
    lost_frames: u64,
    /// Set when [`TRACE_CAP_SEAM`] shrank the cap: every loss says so.
    seam: Option<String>,
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
            state: FileState::Open,
            loss: None,
            lost_frames: 0,
            seam: None,
        }
    }

    /// Opens the attempt's sink with the bounds [`local_bounds`] gives for
    /// `seam` (the value of [`TRACE_CAP_SEAM`], if any). When the seam
    /// shrinks the cap, every loss reason names it and its value, so the
    /// receipt that records the loss also records the seam.
    #[must_use]
    pub fn for_attempt(file: File, seam: Option<&str>) -> Self {
        let (cap, reserve) = local_bounds(seam);
        let mut sink = Self::with_bounds(file, cap, reserve);
        if cap != LOCAL_CAP {
            sink.seam = Some(format!(
                "the local trace cap was shrunk to {cap} bytes by the test seam {TRACE_CAP_SEAM}"
            ));
        }
        sink
    }

    /// Bytes of complete frames written so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Records one more lost frame. The first reason is kept: later losses
    /// follow from it, and a later message would hide its cause.
    fn lose(&mut self, reason: &str) -> JailError {
        let reason = match &self.seam {
            Some(seam) => format!("{reason} ({seam})"),
            None => reason.to_owned(),
        };
        self.lost_frames += 1;
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

    /// Latches at least `state`; a sink never reopens.
    fn latch(&mut self, state: FileState) {
        self.state = match (self.state, state) {
            (FileState::Closed, _) | (_, FileState::Closed) => FileState::Closed,
            (FileState::Lost, _) | (_, FileState::Lost) => FileState::Lost,
            _ => FileState::Open,
        };
    }
}

impl TraceSink for FileSink {
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError> {
        match (self.state, priority) {
            (FileState::Closed, _) => {
                return Err(self.lose("the local trace is closed after an earlier loss"));
            }
            (FileState::Lost, Priority::Normal) => {
                return Err(self.lose("the local trace keeps only its prefix after a loss"));
            }
            _ => {}
        }
        // A note that cannot be written closes the sink, so the notes after
        // a loss stay a prefix too; an ordinary frame only marks it lost.
        let on_failure = match priority {
            Priority::Normal => FileState::Lost,
            Priority::Reserve => FileState::Closed,
        };
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
                    Err(_) => self.latch(FileState::Closed),
                }
                Err(self.lose(&format!("local trace write failed: {error}")))
            }
        }
    }

    fn loss(&self) -> Option<&Loss> {
        self.loss.as_ref()
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

/// Where an external sink stands (§13.3: "best-effort can continue with the
/// sink marked lost").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdState {
    /// Every frame is queued and delivered.
    Open,
    /// Evidence was lost. Only reserve notes are still queued, so what the
    /// consumer reads stays a prefix of the stream followed by final notes,
    /// never a stream with a silent hole in the middle.
    Lost,
    /// The descriptor failed (a consumer that closed its end, or any other
    /// write error). Nothing more can be delivered; every frame is counted.
    Broken,
}

/// The external `--trace-fd` sink (§13.3).
///
/// Nonblocking, with a queue of whole frames: a write that would block leaves
/// the frame queued, and a frame the pipe took in part stays at the front with
/// its written offset. A flush writes straight from the front frame at that
/// offset, so its cost is one `write` per frame it moves, whatever the queue
/// holds, and a partially written frame is resumed, never re-sent.
#[derive(Debug)]
pub struct FdSink {
    file: File,
    /// Whole frames, each ending in its LF; the front one may be partly
    /// written.
    frames: VecDeque<Vec<u8>>,
    /// Bytes of the front frame already written.
    front_written: usize,
    /// Bytes still to write, over all queued frames.
    queued: usize,
    queue_max: usize,
    reserve: usize,
    no_progress: Duration,
    last_progress: Instant,
    state: FdState,
    loss: Option<Loss>,
    lost_frames: u64,
}

impl FdSink {
    /// Takes ownership of `fd` and marks it nonblocking.
    ///
    /// # Safety
    /// `fd` must be an open descriptor that this invocation owns exclusively
    /// (§6.1 requires exactly that of every supplied channel). The sink closes
    /// it when dropped, so no other owner may keep using it.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidFd`] when the descriptor cannot be switched
    /// to nonblocking mode, which is also how a closed fd is detected.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Result<Self, JailError> {
        // SAFETY: the caller guarantees exclusive ownership of an open `fd`.
        let file = unsafe { File::from_raw_fd(fd) };
        set_nonblocking(file.as_raw_fd())?;
        Ok(FdSink {
            file,
            frames: VecDeque::new(),
            front_written: 0,
            queued: 0,
            queue_max: EXTERNAL_QUEUE_MAX,
            reserve: EXTERNAL_RESERVE,
            no_progress: EXTERNAL_NO_PROGRESS,
            last_progress: Instant::now(),
            state: FdState::Open,
            loss: None,
            lost_frames: 0,
        })
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
        self.queued
    }

    /// Drains what the descriptor will accept right now.
    ///
    /// # Errors
    /// Returns [`ErrorCode::EvidenceLost`] when this call records a loss: a
    /// write error (a broken pipe included), or a queue that has made no
    /// progress for the no-progress deadline. A loss already recorded is not
    /// reported again; [`TraceSink::loss`] keeps it.
    pub fn flush_now(&mut self) -> Result<(), JailError> {
        while let Some(front) = self.frames.front() {
            let front_len = front.len();
            match (&self.file).write(&front[self.front_written..]) {
                Ok(0) => break,
                Ok(written) => {
                    self.front_written += written;
                    self.queued -= written;
                    self.last_progress = Instant::now();
                    if self.front_written == front_len {
                        self.frames.pop_front();
                        self.front_written = 0;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(self.break_down(&format!("trace fd write failed: {error}")));
                }
            }
        }
        if self.state == FdState::Open
            && !self.frames.is_empty()
            && self.last_progress.elapsed() > self.no_progress
        {
            self.state = FdState::Lost;
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
        if self.frames.is_empty() {
            return;
        }
        let stalled =
            self.state == FdState::Lost && self.last_progress.elapsed() > self.no_progress;
        if self.state != FdState::Broken && !stalled {
            let deadline = Instant::now() + self.no_progress;
            while !self.frames.is_empty() && self.state != FdState::Broken {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                wait_writable(self.file.as_raw_fd(), remaining);
                // A loss found here is recorded by flush_now itself; the
                // loop's own deadline bounds the wait either way.
                let _ = self.flush_now();
            }
        }
        if !self.frames.is_empty() {
            let undelivered = self.frames.len() as u64;
            self.clear_queue();
            if self.state == FdState::Open {
                self.state = FdState::Lost;
            }
            let _ = self.lose(
                "trace fd could not deliver its queued frames before settlement",
                undelivered,
            );
        }
    }

    fn clear_queue(&mut self) {
        self.frames.clear();
        self.front_written = 0;
        self.queued = 0;
    }

    /// The descriptor failed: every queued frame, a partly written one
    /// included, is lost, and nothing more will be written.
    fn break_down(&mut self, reason: &str) -> JailError {
        let undelivered = self.frames.len() as u64;
        self.clear_queue();
        self.state = FdState::Broken;
        self.lose(reason, undelivered)
    }

    /// Records `frames` more lost frames. The first reason is kept: later
    /// losses follow from it, and a later message would hide its cause.
    fn lose(&mut self, reason: &str, frames: u64) -> JailError {
        self.lost_frames += frames;
        let first = self
            .loss
            .as_ref()
            .map_or_else(|| reason.to_owned(), |loss| loss.reason.clone());
        self.loss = Some(Loss {
            reason: first,
            lost_frames: Some(self.lost_frames),
        });
        evidence_lost(reason)
    }
}

impl TraceSink for FdSink {
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError> {
        if frame.len() > EVENT_MAX {
            if self.state == FdState::Open {
                self.state = FdState::Lost;
            }
            return Err(self.lose("serialized event exceeds the 64 KiB maximum", 1));
        }
        match (self.state, priority) {
            (FdState::Broken, _) => {
                return Err(self.lose("the trace fd consumer is gone", 1));
            }
            (FdState::Lost, Priority::Normal) => {
                return Err(self.lose("the trace fd sink is marked lost", 1));
            }
            _ => {}
        }
        let budget = match priority {
            Priority::Normal => self.queue_max.saturating_sub(self.reserve),
            Priority::Reserve => self.queue_max,
        };
        if self.queued + frame.len() + 1 > budget {
            if self.state == FdState::Open {
                self.state = FdState::Lost;
            }
            return Err(self.lose(
                match priority {
                    Priority::Normal => "trace fd queue overflowed its 4 MiB bound",
                    Priority::Reserve => "trace fd queue reserve is exhausted",
                },
                1,
            ));
        }
        if self.frames.is_empty() {
            self.last_progress = Instant::now();
        }
        let mut owned = Vec::with_capacity(frame.len() + 1);
        owned.extend_from_slice(frame);
        owned.push(b'\n');
        self.queued += owned.len();
        self.frames.push_back(owned);
        self.flush_now()
    }

    fn finish(&mut self) {
        self.drain_final();
    }

    fn poll(&mut self) -> Result<(), JailError> {
        self.flush_now()
    }

    fn loss(&self) -> Option<&Loss> {
        self.loss.as_ref()
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
}
