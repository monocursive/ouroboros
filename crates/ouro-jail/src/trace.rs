//! The bounded NDJSON trace transport.
//!
//! Implements jail-v1 §13.3 (storage and pressure): a local `trace.ndjson`
//! with a 64 MiB cap of which 256 KiB is reserved for the final gap and
//! receipt notes, or an external fd written nonblocking with a 4 MiB queue and
//! a one-second no-progress deadline.
//!
//! Every failure here is evidence loss, never silence: the sink records the
//! reason and the caller decides what strict or best-effort evidence mode
//! means. The external writer keeps a byte queue, so a partially written frame
//! resumes at its own offset and is never re-sent as a second event.

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

/// One sequence allocator and loss state for all producers of a stream.
pub struct TraceWriter {
    sink: Box<dyn TraceSink + Send>,
    wrapper_seq: u64,
    local_loss: Option<Loss>,
}

impl TraceWriter {
    /// Serialize under the stream lock. All wrapper notes share this sequence.
    pub fn write_event(
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
            self.local_loss = Some(Loss {
                reason: reason.clone(),
                lost_frames: None,
            });
            evidence_lost(&reason)
        })?;
        self.write_frame(&frame, priority)
    }
}

impl TraceSink for TraceWriter {
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError> {
        self.sink.write_frame(frame, priority)
    }
    fn poll(&mut self) -> Result<(), JailError> {
        self.sink.poll()
    }
    fn finish(&mut self) {
        self.sink.finish();
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
    }))
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

/// The bounded local `trace.ndjson` sink (§13.3).
#[derive(Debug)]
pub struct FileSink {
    file: File,
    written: u64,
    cap: u64,
    reserve: u64,
    loss: Option<Loss>,
    lost_frames: u64,
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
        FileSink {
            file,
            written: 0,
            cap,
            reserve,
            loss: None,
            lost_frames: 0,
        }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    fn record_loss(&mut self, reason: &str) -> JailError {
        self.lost_frames += 1;
        self.loss = Some(Loss {
            reason: reason.to_owned(),
            lost_frames: Some(self.lost_frames),
        });
        evidence_lost(reason)
    }
}

impl TraceSink for FileSink {
    fn write_frame(&mut self, frame: &[u8], priority: Priority) -> Result<(), JailError> {
        if frame.len() > EVENT_MAX {
            return Err(self.record_loss("serialized event exceeds the 64 KiB maximum"));
        }
        let needed = frame.len() as u64 + 1;
        let budget = match priority {
            Priority::Normal => self.cap.saturating_sub(self.reserve),
            Priority::Reserve => self.cap,
        };
        if self.written + needed > budget {
            return Err(self.record_loss(match priority {
                Priority::Normal => "local trace payload budget is exhausted",
                Priority::Reserve => "local trace reserve is exhausted",
            }));
        }
        let mut bytes = Vec::with_capacity(frame.len() + 1);
        bytes.extend_from_slice(frame);
        bytes.push(b'\n');
        // The budget is charged before the write: a `write_all` that fails
        // part-way has still consumed file space, and a cap that forgot those
        // bytes would let a failing sink grow past 64 MiB.
        self.written += needed;
        if let Err(error) = self.file.write_all(&bytes) {
            return Err(self.record_loss(&format!("local trace write failed: {error}")));
        }
        Ok(())
    }

    fn loss(&self) -> Option<&Loss> {
        self.loss.as_ref()
    }
}

/// The external `--trace-fd` sink (§13.3).
///
/// Nonblocking with a byte queue: a write that would block is queued, and the
/// queue drains on later writes and on [`FdSink::flush_now`].
#[derive(Debug)]
pub struct FdSink {
    file: File,
    queue: VecDeque<u8>,
    queue_max: usize,
    no_progress: Duration,
    last_progress: Instant,
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
            queue: VecDeque::new(),
            queue_max: EXTERNAL_QUEUE_MAX,
            no_progress: EXTERNAL_NO_PROGRESS,
            last_progress: Instant::now(),
            loss: None,
            lost_frames: 0,
        })
    }

    /// Overrides the bounds, for tests that must reach them quickly.
    #[must_use]
    pub fn with_bounds(mut self, queue_max: usize, no_progress: Duration) -> Self {
        self.queue_max = queue_max;
        self.no_progress = no_progress;
        self
    }

    /// Bytes currently waiting in the queue.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Drains what the descriptor will accept right now.
    ///
    /// # Errors
    /// Returns [`ErrorCode::EvidenceLost`] on a broken pipe or when the queue
    /// has made no progress for the no-progress deadline.
    pub fn flush_now(&mut self) -> Result<(), JailError> {
        while !self.queue.is_empty() {
            let (front, _) = self.queue.as_slices();
            let chunk = front.to_vec();
            match self.file.write(&chunk) {
                Ok(0) => break,
                Ok(written) => {
                    self.queue.drain(..written);
                    self.last_progress = Instant::now();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(self.record_loss(&format!("trace fd write failed: {error}")));
                }
            }
        }
        if !self.queue.is_empty() && self.last_progress.elapsed() > self.no_progress {
            return Err(self.record_loss("trace fd made no progress within its deadline"));
        }
        Ok(())
    }

    /// Terminal drain, bounded by the no-progress deadline (§13.3).
    ///
    /// Waits for the external consumer to accept the queued bytes, records
    /// anything still undelivered when the budget ends, and never blocks the
    /// supervisor past the deadline. Called once at settlement; after it, the
    /// queue is either empty or counted as evidence loss.
    pub fn drain_final(&mut self) {
        if self.queue.is_empty() {
            return;
        }
        let deadline = Instant::now() + self.no_progress;
        while !self.queue.is_empty() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            wait_writable(self.file.as_raw_fd(), remaining);
            // A hard write failure is recorded inside flush_now; a slow but
            // progressing consumer keeps last_progress fresh, and the loop's
            // overall deadline bounds the total wait.
            self.last_progress = Instant::now();
            if self.flush_now().is_err() {
                break;
            }
        }
        if !self.queue.is_empty() {
            let _ =
                self.record_loss("trace fd could not deliver its queued frames before settlement");
        }
    }

    fn record_loss(&mut self, reason: &str) -> JailError {
        self.lost_frames += 1;
        self.loss = Some(Loss {
            reason: reason.to_owned(),
            lost_frames: Some(self.lost_frames),
        });
        evidence_lost(reason)
    }
}

impl TraceSink for FdSink {
    fn write_frame(&mut self, frame: &[u8], _priority: Priority) -> Result<(), JailError> {
        if frame.len() > EVENT_MAX {
            return Err(self.record_loss("serialized event exceeds the 64 KiB maximum"));
        }
        if self.queue.len() + frame.len() + 1 > self.queue_max {
            return Err(self.record_loss("trace fd queue overflowed its 4 MiB bound"));
        }
        if self.queue.is_empty() {
            self.last_progress = Instant::now();
        }
        self.queue.extend(frame.iter().copied());
        self.queue.push_back(b'\n');
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
