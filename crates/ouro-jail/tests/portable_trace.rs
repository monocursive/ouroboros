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

/// A child that never reads its stdin, so the pipe fills and stays full.
fn blocked_reader() -> (Child, FdSink) {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec sleep 30")
        .stdin(Stdio::piped())
        .spawn()
        .expect("/bin/sh is available");
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
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("/bin/cat is available");
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
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .stdin(Stdio::piped())
        .spawn()
        .expect("/bin/sh is available");
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
