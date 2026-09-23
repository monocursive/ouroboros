//! The external trace transport against real pipes.
//!
//! §13.3: external writes are nonblocking with a 4 MiB queue and a one-second
//! no-progress deadline; broken pipe, queue overflow or deadline expiry is
//! evidence loss. The writer preserves unwritten offsets and never retries a
//! partially written frame as a second event.
//!
//! The reader here is a real process on the other end of a real pipe: a
//! draining `cat` for the happy path, and a `sleep` that never reads for the
//! back-pressure paths.

use std::io::Read as _;
use std::os::fd::IntoRawFd as _;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ouro_jail::records::ErrorCode;
use ouro_jail::trace::{EXTERNAL_NO_PROGRESS, EXTERNAL_QUEUE_MAX, FdSink, Priority, TraceSink};

/// Serialises every test here that creates a pipe or spawns a process.
///
/// Measured on macOS 27 (a standalone loop of 3000 pipes beside a thread that
/// spawns children, with pipe creation and spawning under one lock): a child
/// can still hold a close-on-exec pipe end that existed while it was spawned,
/// for a moment after `spawn` returns. A test that closes its reader to play
/// a consumer that left then sees its write succeed about once per concurrent
/// spawn. Running these tests one at a time removes the overlap.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn spawn(command: &mut Command) -> Child {
    command.spawn().expect("the helper program is available")
}

/// A child that never reads its stdin, so the pipe fills and stays full.
fn blocked_reader() -> (Child, FdSink) {
    let mut child = spawn(
        Command::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 30")
            .stdin(Stdio::piped()),
    );
    let stdin = child.stdin.take().expect("a piped stdin");
    let fd = stdin.into_raw_fd();
    // SAFETY: the descriptor came from this process's own `Stdio::piped`
    // handle, which was just given up, so the sink owns it exclusively.
    let sink = unsafe { FdSink::from_raw_fd(fd) }.expect("the pipe can be made nonblocking");
    (child, sink)
}

fn frame(index: usize) -> Vec<u8> {
    format!("{{\"seq\":{index},\"pad\":\"{}\"}}", "x".repeat(64)).into_bytes()
}

#[test]
fn frames_reach_a_draining_reader_in_order_and_exactly_once() {
    let _serial = serial();
    let mut child = spawn(
        Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    let stdin = child.stdin.take().expect("a piped stdin");
    let fd = stdin.into_raw_fd();
    // SAFETY: as above, the sink is the only owner of this descriptor.
    let mut sink = unsafe { FdSink::from_raw_fd(fd) }.expect("nonblocking");

    let mut expected = Vec::new();
    // Stay under the pipe capacity in both directions: `cat` is not drained
    // until after the writes, so a larger payload would deadlock the test
    // rather than test the sink.
    for index in 0..100 {
        let payload = frame(index);
        sink.write_frame(&payload, Priority::Normal)
            .expect("a small frame is accepted");
        expected.extend_from_slice(&payload);
        expected.push(b'\n');
    }
    assert!(sink.loss().is_none(), "a draining reader loses nothing");
    drop(sink);

    let mut received = Vec::new();
    child
        .stdout
        .take()
        .expect("a piped stdout")
        .read_to_end(&mut received)
        .expect("the reader drains");
    let _ = child.wait();
    assert_eq!(
        received, expected,
        "every frame arrived once, in order, with one LF each"
    );
}

#[test]
fn a_full_pipe_queues_and_the_queue_bound_is_evidence_loss() {
    let _serial = serial();
    let (mut child, mut sink) = blocked_reader();
    let payload = vec![b'q'; 4096];
    let mut queued_after_first_block = None;
    let mut loss = None;
    // The pipe fills, then the queue fills; the second bound is the one that
    // reports loss.
    for _ in 0..(EXTERNAL_QUEUE_MAX / 4096 + 16) {
        match sink.write_frame(&payload, Priority::Normal) {
            Ok(()) => {
                if sink.queued() > 0 && queued_after_first_block.is_none() {
                    queued_after_first_block = Some(sink.queued());
                }
            }
            Err(error) => {
                loss = Some(error);
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        queued_after_first_block.is_some(),
        "a full pipe must queue rather than block"
    );
    let loss = loss.expect("the queue bound is reached");
    assert_eq!(loss.code, ErrorCode::EvidenceLost);
    assert!(
        sink.queued() <= EXTERNAL_QUEUE_MAX,
        "the queue never exceeds its bound"
    );
    assert!(
        sink.loss().is_some(),
        "the loss is recorded, not silently dropped"
    );
}

#[test]
fn no_progress_within_the_deadline_is_evidence_loss() {
    let _serial = serial();
    let (mut child, mut sink) = blocked_reader();
    // Fill the pipe so that nothing can drain while the reader sleeps.
    let payload = vec![b'p'; 8192];
    for _ in 0..64 {
        if sink.write_frame(&payload, Priority::Normal).is_err() {
            break;
        }
        if sink.queued() > 0 {
            break;
        }
    }
    assert!(sink.queued() > 0, "the pipe is full and the queue is not");
    assert_eq!(
        EXTERNAL_NO_PROGRESS,
        Duration::from_secs(1),
        "the deadline under test is the one the specification names"
    );
    std::thread::sleep(EXTERNAL_NO_PROGRESS + Duration::from_millis(200));
    let error = sink
        .flush_now()
        .expect_err("a queue that cannot drain is evidence loss");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(error.code, ErrorCode::EvidenceLost);
    assert_eq!(
        error.exit_code(),
        1,
        "post-exec evidence loss is a tool error"
    );
}

#[test]
fn a_closed_reader_is_evidence_loss_rather_than_a_signal() {
    let _serial = serial();
    let mut child = spawn(
        Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::piped()),
    );
    let stdin = child.stdin.take().expect("a piped stdin");
    let fd = stdin.into_raw_fd();
    // SAFETY: the sink is the only owner of this descriptor.
    let mut sink = unsafe { FdSink::from_raw_fd(fd) }.expect("nonblocking");
    let _ = child.wait();

    // SIGPIPE is ignored by the Rust runtime, so this surfaces as EPIPE and is
    // recorded as loss rather than killing the supervisor mid-attempt.
    let mut error = None;
    for index in 0..64 {
        if let Err(failure) = sink.write_frame(&frame(index), Priority::Normal) {
            error = Some(failure);
            break;
        }
    }
    let error = error.expect("writing to a closed reader fails");
    assert_eq!(error.code, ErrorCode::EvidenceLost);
    assert!(sink.loss().is_some());
}

// ---------------------------------------------------------------------------
// S8: the readback recogniser (§13.3 "A corrupted/truncated last frame must be
// recognizable at readback").
// ---------------------------------------------------------------------------

#[test]
fn j4_s8_the_recogniser_tells_complete_incomplete_and_corrupt_apart() {
    use ouro_jail::trace::{TraceState, read_frames};

    let complete = read_frames(b"{\"n\":1}\n{\"n\":2}\n");
    assert_eq!(complete.state, TraceState::Complete);
    assert_eq!(complete.frames.len(), 2);
    assert_eq!(complete.bad_offset, None);

    let empty = read_frames(b"");
    assert_eq!(
        empty.state,
        TraceState::Complete,
        "no frame is not a torn frame"
    );
    assert!(empty.frames.is_empty());

    // A torn last frame, with no LF.
    let torn = read_frames(b"{\"n\":1}\n{\"n\":2,\"pa");
    assert_eq!(torn.state, TraceState::Incomplete);
    assert_eq!(torn.frames, vec![serde_json::json!({"n": 1})]);
    assert_eq!(torn.bad_offset, Some(8));
    assert_eq!(torn.bad_line, b"{\"n\":2,\"pa");

    // A last line that happens to be a whole object but has no LF is still
    // not a frame: the writer never finished it.
    let unterminated = read_frames(b"{\"n\":1}\n{\"n\":2}");
    assert_eq!(unterminated.state, TraceState::Incomplete);
    assert_eq!(unterminated.frames.len(), 1);

    // A torn last frame that a later LF happened to close.
    let closed = read_frames(b"{\"n\":1}\n{\"n\":2,\"pa\n");
    assert_eq!(closed.state, TraceState::Incomplete);
    assert_eq!(closed.frames.len(), 1);

    // A torn frame followed by more frames: corrupt, and nothing after the
    // torn line is interpreted.
    let corrupt = read_frames(b"{\"n\":1}\n{\"n\":2,\"pa{\"n\":3}\n{\"n\":4}\n");
    assert_eq!(corrupt.state, TraceState::Corrupt);
    assert_eq!(corrupt.frames, vec![serde_json::json!({"n": 1})]);
    assert_eq!(corrupt.bad_offset, Some(8));

    // A frame is an object: a bare value or an empty line is not one.
    assert_eq!(read_frames(b"1\n{\"n\":1}\n").state, TraceState::Corrupt);
    assert_eq!(read_frames(b"\n{\"n\":1}\n").state, TraceState::Corrupt);
    // Two objects on one line are not one frame.
    assert_eq!(
        read_frames(b"{\"n\":1}{\"n\":2}\n{\"n\":3}\n").state,
        TraceState::Corrupt
    );
}

#[test]
fn j4_s8_the_last_receipt_note_is_read_only_from_a_complete_trace() {
    use ouro_jail::trace::read_frames;

    let note = serde_json::json!({
        "source": "wrapper",
        "operation": "jail.receipt",
        "fields": {"phase": "settled", "receipt_digest": "sha256:ab"}
    });
    let mut bytes = serde_json::to_vec(&serde_json::json!({"source": "audit"})).unwrap();
    bytes.push(b'\n');
    bytes.extend(serde_json::to_vec(&note).unwrap());
    bytes.push(b'\n');
    assert_eq!(
        read_frames(&bytes).last_receipt_note(),
        Some(("settled", "sha256:ab"))
    );

    // A trace that ends on some other frame has no final note.
    let mut prefix = serde_json::to_vec(&note).unwrap();
    prefix.push(b'\n');
    prefix.extend(b"{\"source\":\"audit\"}\n");
    assert_eq!(read_frames(&prefix).last_receipt_note(), None);

    // A torn tail after the note: the note is not the last line.
    bytes.extend(b"{\"source\":");
    assert_eq!(read_frames(&bytes).last_receipt_note(), None);
}

// ---------------------------------------------------------------------------
// R03 (trace half): partial writes, a consumer that leaves, saturation.
// ---------------------------------------------------------------------------

/// A sink over a fresh pipe whose read end the test holds.
fn pipe_sink() -> (std::io::PipeReader, FdSink) {
    use std::os::fd::{IntoRawFd as _, OwnedFd};
    let (reader, writer) = std::io::pipe().expect("a pipe");
    let fd = OwnedFd::from(writer).into_raw_fd();
    // SAFETY: the write end was just created here and handed over whole.
    let sink = unsafe { FdSink::from_raw_fd(fd) }.expect("the pipe can be made nonblocking");
    (reader, sink)
}

/// A JSON frame of exactly `len` bytes carrying its index.
fn sized_frame(index: usize, len: usize) -> Vec<u8> {
    let head = format!("{{\"seq\":{index},\"pad\":\"");
    let pad = len - head.len() - 2;
    let mut frame = head.into_bytes();
    frame.extend(std::iter::repeat_n(b'x', pad));
    frame.extend(b"\"}");
    assert_eq!(frame.len(), len);
    frame
}

/// Read what the pipe holds right now, without blocking.
fn read_available(reader: &mut std::io::PipeReader) -> Vec<u8> {
    use std::os::fd::AsRawFd as _;
    ouro_jail::trace::set_nonblocking(reader.as_raw_fd()).expect("nonblocking reader");
    let mut out = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return out,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return out,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("the test's reader failed: {error}"),
        }
    }
}

#[test]
fn j4_r03_a_partial_write_resumes_at_its_offset_and_never_repeats_a_frame() {
    let _serial = serial();
    use ouro_jail::trace::{TraceState, read_frames};

    let (mut reader, sink) = pipe_sink();
    let mut sink = sink.with_bounds(EXTERNAL_QUEUE_MAX, Duration::from_secs(30));
    // Frames above PIPE_BUF, so a nonblocking write into a pipe with less room
    // than a frame is accepted in part rather than refused whole.
    let len = 10_000;
    let mut sent = Vec::new();
    while sink.queued() % (len + 1) == 0 {
        assert!(sent.len() < 64, "the pipe never took part of a frame");
        let frame = sized_frame(sent.len(), len);
        sink.write_frame(&frame, Priority::Normal)
            .expect("a full pipe queues, it does not lose");
        sent.push(frame);
    }
    // The front frame is now partly in the pipe; queue two more behind it.
    for _ in 0..2 {
        let frame = sized_frame(sent.len(), len);
        sink.write_frame(&frame, Priority::Normal)
            .expect("still within the queue bound");
        sent.push(frame);
    }
    let consumer = std::thread::spawn(move || {
        let mut received = Vec::new();
        reader
            .read_to_end(&mut received)
            .expect("the consumer drains");
        received
    });
    sink.finish();
    assert_eq!(sink.queued(), 0, "the drain delivered everything");
    assert!(
        sink.loss().is_none(),
        "a consumer that drains loses nothing"
    );
    drop(sink);
    let received = consumer.join().expect("the consumer thread");

    let mut expected = Vec::new();
    for frame in &sent {
        expected.extend_from_slice(frame);
        expected.push(b'\n');
    }
    assert_eq!(received.len(), expected.len(), "no byte repeated or lost");
    assert!(
        received == expected,
        "every frame arrived once, in order, and the partly written one resumed at its offset"
    );
    let readback = read_frames(&received);
    assert_eq!(readback.state, TraceState::Complete);
    let seqs: Vec<u64> = readback
        .frames
        .iter()
        .map(|frame| frame["seq"].as_u64().expect("a sequence number"))
        .collect();
    assert_eq!(seqs, (0..sent.len() as u64).collect::<Vec<_>>());
}

#[test]
fn j4_r03_a_reader_that_leaves_mid_frame_is_loss_and_the_tail_is_recognizable() {
    let _serial = serial();
    use ouro_jail::trace::{TraceState, read_frames};

    let (mut reader, sink) = pipe_sink();
    let mut sink = sink.with_bounds(EXTERNAL_QUEUE_MAX, Duration::from_secs(30));
    let len = 1000;
    let size = len + 1;
    let mut enqueued = 0usize;
    while sink.queued() == 0 {
        assert!(enqueued < 1024, "the pipe never filled");
        sink.write_frame(&sized_frame(enqueued, len), Priority::Normal)
            .expect("queued");
        enqueued += 1;
    }
    for _ in 0..3 {
        sink.write_frame(&sized_frame(enqueued, len), Priority::Normal)
            .expect("queued");
        enqueued += 1;
    }
    // Frames the sink handed to the pipe whole; the rest never left it whole.
    let delivered = (enqueued * size - sink.queued()) / size;

    // The consumer takes two and a half frames, then goes away.
    let mut taken = vec![0u8; 2 * size + size / 2];
    reader
        .read_exact(&mut taken)
        .expect("the pipe holds that much");
    drop(reader);

    let error = sink
        .write_frame(&sized_frame(enqueued, len), Priority::Normal)
        .expect_err("writing to a consumer that left is evidence loss");
    enqueued += 1;
    assert_eq!(error.code, ErrorCode::EvidenceLost);
    let lost = sink.loss().expect("the loss is recorded").lost_frames;
    assert_eq!(
        lost,
        Some((enqueued - delivered) as u64),
        "every frame the pipe never took whole is counted, the torn one included"
    );
    assert!(
        sink.write_frame(&sized_frame(enqueued, len), Priority::Reserve)
            .is_err(),
        "nothing is accepted after the consumer left"
    );
    assert_eq!(
        sink.loss().expect("still recorded").lost_frames,
        lost.map(|count| count + 1),
        "a later frame is counted too, never silently dropped"
    );
    assert_eq!(
        sink.queued(),
        0,
        "nothing waits for a consumer that is gone"
    );

    // What the consumer took ends mid-frame, and readback says so.
    let readback = read_frames(&taken);
    assert_eq!(readback.state, TraceState::Incomplete);
    assert_eq!(readback.frames.len(), 2);
    assert_eq!(readback.bad_offset, Some(2 * size));
    assert_eq!(readback.bad_line, sized_frame(2, len)[..size / 2]);
}

#[test]
fn j4_r03_flush_cost_does_not_grow_with_the_queue() {
    let _serial = serial();
    // A consumer that never reads: every flush finds the pipe full. Its cost
    // must not depend on how much is queued, or a saturated trace would slow
    // the supervision loop that polls it (§13.3: backpressure cannot block
    // deadline enforcement).
    fn cost(target: usize) -> Duration {
        let (reader, sink) = pipe_sink();
        let mut sink = sink.with_bounds(EXTERNAL_QUEUE_MAX, Duration::from_secs(600));
        let payload = vec![b'q'; 4000];
        while sink.queued() < target {
            sink.write_frame(&payload, Priority::Normal)
                .expect("within the queue bound");
        }
        // The fastest of three rounds, so scheduler noise does not decide it.
        let mut best = Duration::MAX;
        for _ in 0..3 {
            let started = std::time::Instant::now();
            for _ in 0..2000 {
                sink.flush_now().expect("no deadline can pass here");
            }
            best = best.min(started.elapsed());
        }
        drop(reader);
        best
    }
    let small = cost(64 * 1024);
    let large = cost(EXTERNAL_QUEUE_MAX - 512 * 1024);
    assert!(
        large <= small * 3 + Duration::from_millis(10),
        "2000 flushes took {large:?} with ~3.5 MiB queued and {small:?} with 64 KiB"
    );
}

#[test]
fn j4_r03_after_a_trace_fd_loss_only_reserve_notes_follow() {
    let _serial = serial();
    let (mut reader, sink) = pipe_sink();
    let mut sink = sink.with_bounds(256 * 1024, Duration::from_secs(600));
    let payload = vec![b'n'; 4000];
    let mut refused = None;
    for _ in 0..1024 {
        if let Err(error) = sink.write_frame(&payload, Priority::Normal) {
            refused = Some(error);
            break;
        }
    }
    assert_eq!(
        refused.expect("the queue bound is reached").code,
        ErrorCode::EvidenceLost
    );
    // The loss note that follows still has room: part of the bound is kept
    // for the final gap and receipt notes, as it is for the local cap. It is
    // larger than any slack an ordinary frame could have left.
    let gap_note = sized_frame(0, 8000);
    sink.write_frame(&gap_note, Priority::Reserve)
        .expect("a reserve note is accepted after the payload overflowed");

    // The consumer comes back and drains everything.
    let mut received = Vec::new();
    while sink.queued() > 0 {
        received.extend(read_available(&mut reader));
        sink.poll().expect("draining makes progress");
    }
    received.extend(read_available(&mut reader));
    let mut expected_tail = gap_note.clone();
    expected_tail.push(b'\n');
    assert!(received.ends_with(&expected_tail));

    // The sink stays marked lost: a later ordinary frame would leave a hole
    // in the middle of the stream, so it is refused and counted instead.
    let before = sink.loss().expect("recorded").lost_frames;
    assert!(sink.write_frame(&payload, Priority::Normal).is_err());
    assert_eq!(
        sink.loss().expect("recorded").lost_frames,
        before.map(|count| count + 1)
    );
    sink.write_frame(b"{\"note\":\"receipt\"}", Priority::Reserve)
        .expect("the final receipt note is still accepted");
    sink.poll().expect("the consumer is reading");
    assert!(read_available(&mut reader).ends_with(b"{\"note\":\"receipt\"}\n"));
}

// ---------------------------------------------------------------------------
// R03 / N2: the local trace after a failed write.
// ---------------------------------------------------------------------------

const FSIZE_HELPER: &str = "OURO_J4_FSIZE_HELPER";
const FSIZE_RAISE: &str = "OURO_J4_FSIZE_RAISE";

/// Runs in its own process: lowers `RLIMIT_FSIZE` to 1000 bytes with
/// `SIGXFSZ` ignored, so a frame that crosses the limit is a real short write
/// followed by `EFBIG` (Linux; macOS refuses the whole write), and drives a
/// `FileSink` across it. With `OURO_J4_FSIZE_RAISE` the limit is raised again
/// afterwards, as disk space that frees up would be.
#[test]
#[ignore = "subprocess helper for j4_r03_a_failed_local_write_never_leaves_a_partial_frame_mid_file"]
fn j4_fsize_helper() {
    use ouro_jail::trace::FileSink;
    let Some(path) = std::env::var_os(FSIZE_HELPER) else {
        return;
    };
    let raise = std::env::var_os(FSIZE_RAISE).is_some();
    // SAFETY: SIG_IGN is a valid disposition; this process is the helper.
    unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live rlimit for both calls.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut limit) },
        0
    );
    let hard = limit.rlim_max;
    limit.rlim_cur = 1000;
    // SAFETY: as above.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &raw const limit) },
        0
    );

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("the helper's trace file");
    let mut sink = FileSink::new(file);
    // Six 151-byte frames fit in 1000 bytes; the seventh crosses the limit.
    let accepted: Vec<bool> = (0..8)
        .map(|index| {
            sink.write_frame(&sized_frame(index, 150), Priority::Normal)
                .is_ok()
        })
        .collect();
    if raise {
        limit.rlim_cur = hard;
        // SAFETY: as above; the soft limit goes back up to the hard one.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &raw const limit) },
            0
        );
    }
    let later_normal = sink
        .write_frame(&sized_frame(100, 150), Priority::Normal)
        .is_ok();
    let later_reserve = sink
        .write_frame(&sized_frame(200, 150), Priority::Reserve)
        .is_ok();
    println!(
        "J4FSIZE {}",
        serde_json::json!({
            "accepted": accepted,
            "later_normal": later_normal,
            "later_reserve": later_reserve,
            "lost_frames": sink.loss().and_then(|loss| loss.lost_frames),
        })
    );
}

fn run_fsize_helper(raise: bool) -> (serde_json::Value, Vec<u8>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("trace.ndjson");
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .args(["--ignored", "--exact", "j4_fsize_helper", "--nocapture"])
        .env(FSIZE_HELPER, &path);
    if raise {
        command.env(FSIZE_RAISE, "1");
    }
    let output = command.output().expect("the helper runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the helper failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout
        .lines()
        .find_map(|line| line.strip_prefix("J4FSIZE "))
        .unwrap_or_else(|| panic!("no helper report in {stdout}"));
    (
        serde_json::from_str(report).expect("a JSON report"),
        std::fs::read(&path).expect("the helper's trace"),
    )
}

#[test]
fn j4_r03_a_failed_local_write_never_leaves_a_partial_frame_mid_file() {
    use ouro_jail::trace::{TraceState, read_frames};

    // Space comes back after the failure: nothing may be appended after a
    // torn frame, and no ordinary frame after the hole; the reserve note that
    // records the loss may still be written.
    let (report, bytes) = run_fsize_helper(true);
    let readback = read_frames(&bytes);
    assert_eq!(
        readback.state,
        TraceState::Complete,
        "the file must end on a frame boundary with no torn frame in it: {report} {:?}",
        String::from_utf8_lossy(&readback.bad_line)
    );
    let seqs: Vec<u64> = readback
        .frames
        .iter()
        .map(|frame| frame["seq"].as_u64().expect("a sequence number"))
        .collect();
    assert_eq!(
        seqs,
        vec![0, 1, 2, 3, 4, 5, 200],
        "a prefix, then only the reserve note: {report}"
    );
    assert_eq!(
        report["accepted"],
        serde_json::json!([true, true, true, true, true, true, false, false])
    );
    assert_eq!(report["later_normal"], false);
    assert_eq!(report["later_reserve"], true);
    assert_eq!(
        report["lost_frames"], 3,
        "frames 6, 7 and 100 are counted, each once: {report}"
    );

    // Space never comes back: the file still ends on a frame boundary.
    let (report, bytes) = run_fsize_helper(false);
    let readback = read_frames(&bytes);
    assert_eq!(readback.state, TraceState::Complete, "{report}");
    assert_eq!(readback.frames.len(), 6, "{report}");
    assert_eq!(report["later_reserve"], false);
    assert_eq!(report["lost_frames"], 4, "{report}");
}

#[test]
fn j4_r03_after_local_payload_exhaustion_only_reserve_notes_follow() {
    use ouro_jail::trace::FileSink;
    let file = tempfile::NamedTempFile::new().expect("a temporary file");
    let mut sink = FileSink::with_bounds(file.reopen().expect("a handle"), 1000, 400);
    for index in 0..3 {
        sink.write_frame(&sized_frame(index, 150), Priority::Normal)
            .expect("within the payload budget");
    }
    // 453 bytes written; a 200-byte frame would cross the 600-byte payload.
    assert!(
        sink.write_frame(&sized_frame(3, 200), Priority::Normal)
            .is_err()
    );
    // A smaller ordinary frame would still fit, but writing it would leave a
    // hole in the middle of the trace: best-effort keeps a prefix (§13.3).
    assert!(
        sink.write_frame(&sized_frame(4, 50), Priority::Normal)
            .is_err(),
        "an ordinary frame after the loss must be refused"
    );
    sink.write_frame(&sized_frame(5, 150), Priority::Reserve)
        .expect("the reserve is for the notes that follow a loss");
    assert_eq!(sink.loss().and_then(|loss| loss.lost_frames), Some(2));
    let readback = ouro_jail::trace::read_frames(&std::fs::read(file.path()).unwrap());
    let seqs: Vec<u64> = readback
        .frames
        .iter()
        .map(|frame| frame["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![0, 1, 2, 5]);
}

// ---------------------------------------------------------------------------
// R03: the in-band record of a transport loss.
// ---------------------------------------------------------------------------

fn lifecycle(transition: &str) -> ouro_jail::records::Event {
    ouro_jail::records::Event::lifecycle_note(
        "att_j4_trace",
        0,
        std::time::SystemTime::now(),
        0,
        transition,
    )
}

fn receipt_note() -> ouro_jail::records::Event {
    ouro_jail::records::Event::receipt_note(
        "att_j4_trace",
        0,
        std::time::SystemTime::now(),
        0,
        ouro_jail::records::Phase::Settled,
        "sha256:00",
    )
}

fn is_transport_gap(frame: &serde_json::Value) -> bool {
    frame
        .pointer("/fields/kind")
        .and_then(serde_json::Value::as_str)
        == Some("coverage_gap")
        && frame
            .pointer("/fields/reason")
            .and_then(serde_json::Value::as_str)
            == Some("trace_transport_loss")
}

#[test]
fn j4_r03_a_coverage_gap_note_follows_the_prefix_with_reserve_priority() {
    use ouro_jail::trace::{FileSink, TraceState, read_frames, shared};

    let file = tempfile::NamedTempFile::new().expect("a temporary file");
    let trace = shared(FileSink::with_bounds(
        file.reopen().expect("a handle"),
        8192,
        4096,
    ));
    let mut accepted = 0;
    for index in 0..1000 {
        let written = trace
            .lock()
            .unwrap()
            .write_event(&lifecycle(&format!("step_{index}")), Priority::Normal);
        if written.is_err() {
            break;
        }
        accepted += 1;
    }
    assert!(
        accepted > 0 && accepted < 1000,
        "the payload budget is reached"
    );
    // More ordinary events after the loss: refused, and no second note.
    for _ in 0..3 {
        assert!(
            trace
                .lock()
                .unwrap()
                .write_event(&lifecycle("late"), Priority::Normal)
                .is_err()
        );
    }
    trace
        .lock()
        .unwrap()
        .write_event(&receipt_note(), Priority::Reserve)
        .expect("the final receipt note uses the reserve");

    let readback = read_frames(&std::fs::read(file.path()).unwrap());
    assert_eq!(readback.state, TraceState::Complete);
    let frames = &readback.frames;
    assert_eq!(
        frames.len(),
        accepted + 2,
        "the prefix, one gap note, the receipt note"
    );
    let gap = &frames[accepted];
    assert!(
        is_transport_gap(gap),
        "the note right after the prefix: {gap}"
    );
    assert_eq!(gap["source"], "wrapper");
    assert_eq!(gap["fields"]["end_ns"], serde_json::Value::Null);
    assert_eq!(gap["fields"]["lost_count"], serde_json::Value::Null);
    assert_eq!(
        gap["fields"]["classes"],
        serde_json::json!(["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"])
    );
    assert_eq!(
        frames
            .iter()
            .filter(|frame| is_transport_gap(frame))
            .count(),
        1,
        "one note per loss, not one per refused frame"
    );
    // One wrapper sequence for events and notes: the refused event and the
    // three late ones keep their numbers, so the gaps in it are visible too.
    let seqs: Vec<u64> = frames
        .iter()
        .map(|frame| frame["source_seq"].as_u64().unwrap())
        .collect();
    let accepted_seq = accepted as u64;
    let mut expected: Vec<u64> = (1..=accepted_seq).collect();
    expected.extend([accepted_seq + 2, accepted_seq + 6]);
    assert_eq!(seqs, expected);
    assert_eq!(readback.last_receipt_note(), Some(("settled", "sha256:00")));
}

#[test]
fn j4_r03_a_consumer_that_resumes_after_its_deadline_reads_the_gap_note() {
    use ouro_jail::trace::{TraceState, read_frames, shared};

    let _serial = serial();
    let (mut reader, sink) = pipe_sink();
    let trace = shared(sink.with_bounds(1024 * 1024, Duration::from_millis(50)));
    // Fill the pipe, and then some, while nobody reads.
    let accepted = 400;
    for _ in 0..accepted {
        trace
            .lock()
            .unwrap()
            .write_event(&lifecycle("filling"), Priority::Normal)
            .expect("the queue has room and no deadline has passed");
    }
    std::thread::sleep(Duration::from_millis(120));
    // The supervision loop's poll finds the stall: loss, and the note is
    // queued in the reserve for a consumer that comes back, with no further
    // event needed to trigger it.
    assert!(trace.lock().unwrap().poll().is_err());
    let mut received = Vec::new();
    for _ in 0..1000 {
        received.extend(read_available(&mut reader));
        let _ = trace.lock().unwrap().poll();
        if read_frames(&received)
            .frames
            .last()
            .is_some_and(is_transport_gap)
        {
            break;
        }
    }
    let readback = read_frames(&received);
    assert_eq!(readback.state, TraceState::Complete);
    assert_eq!(readback.frames.len(), accepted + 1);
    assert!(is_transport_gap(readback.frames.last().unwrap()));
    assert!(
        trace
            .lock()
            .unwrap()
            .write_event(&lifecycle("after"), Priority::Normal)
            .is_err(),
        "the sink stays marked lost after the consumer resumed"
    );
}

#[test]
fn j4_r03_the_trace_cap_seam_can_only_shrink() {
    use ouro_jail::trace::{LOCAL_CAP, LOCAL_RESERVE, TRACE_CAP_SEAM, local_bounds};
    assert_eq!(TRACE_CAP_SEAM, "OURO_JAIL_TEST_TRACE_CAP");
    assert_eq!(local_bounds(None), (LOCAL_CAP, LOCAL_RESERVE));
    assert_eq!(local_bounds(Some("65536")), (65536, 32768));
    assert_eq!(local_bounds(Some("4096")), (4096, 2048));
    assert_eq!(
        local_bounds(Some(&LOCAL_CAP.to_string())),
        (LOCAL_CAP, LOCAL_RESERVE)
    );
    for ignored in ["", "abc", "-1", "0", "4095", &(LOCAL_CAP + 1).to_string()] {
        assert_eq!(
            local_bounds(Some(ignored)),
            (LOCAL_CAP, LOCAL_RESERVE),
            "{ignored:?} must not change the bounds"
        );
    }
}

#[test]
fn j4_r03_a_loss_under_the_cap_seam_names_the_seam() {
    use ouro_jail::trace::FileSink;
    let file = tempfile::NamedTempFile::new().expect("a temporary file");
    let mut shrunk = FileSink::for_attempt(file.reopen().unwrap(), Some("4096"));
    let error = (0..100)
        .find_map(|index| {
            shrunk
                .write_frame(&sized_frame(index, 150), Priority::Normal)
                .err()
        })
        .expect("a 4096-byte cap is exhausted");
    for reason in [
        error.message.as_str(),
        shrunk.loss().unwrap().reason.as_str(),
    ] {
        assert!(
            reason.contains("OURO_JAIL_TEST_TRACE_CAP") && reason.contains("4096"),
            "{reason}"
        );
    }
    assert!(
        std::fs::metadata(file.path()).unwrap().len() <= 2048,
        "the shrunk payload is half the shrunk cap"
    );

    let plain = tempfile::NamedTempFile::new().expect("a temporary file");
    let mut sink = FileSink::for_attempt(plain.reopen().unwrap(), None);
    let error = sink
        .write_frame(
            &vec![b'x'; ouro_jail::trace::EVENT_MAX + 1],
            Priority::Normal,
        )
        .expect_err("oversized");
    assert!(
        !error.message.contains("OURO_JAIL_TEST_TRACE_CAP"),
        "{}",
        error.message
    );
}

#[test]
fn j4_r03_a_consumer_past_its_deadline_gets_no_second_one_at_settlement() {
    let _serial = serial();
    let (reader, sink) = pipe_sink();
    let deadline = Duration::from_millis(300);
    let mut sink = sink.with_bounds(1024 * 1024, deadline);
    while sink.queued() == 0 {
        sink.write_frame(&[b'z'; 4000], Priority::Normal)
            .expect("filling");
    }
    std::thread::sleep(deadline + Duration::from_millis(100));
    assert!(sink.flush_now().is_err(), "the stall is found");
    // The final notes are queued for a consumer that might still come back.
    sink.write_frame(b"{\"note\":\"receipt\"}", Priority::Reserve)
        .expect("reserve");
    let queued_frames_lost_before = sink.loss().unwrap().lost_frames.unwrap();
    let started = std::time::Instant::now();
    sink.finish();
    let spent = started.elapsed();
    assert!(
        spent < deadline / 2,
        "settlement waited {spent:?} for a consumer that already ran out its deadline"
    );
    assert_eq!(sink.queued(), 0, "undelivered frames are counted, not kept");
    assert!(
        sink.loss().unwrap().lost_frames.unwrap() > queued_frames_lost_before,
        "the frames still queued at settlement are counted as lost"
    );
    drop(reader);
}
