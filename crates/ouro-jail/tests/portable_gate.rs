//! X02 (portable part): the managed gate parser, over a real pipe.
//!
//! §8.2: the only valid release is one UTF-8 NDJSON frame followed by writer
//! close. Wrong schema, action, identity or digest, malformed JSON, duplicate
//! object keys, an empty EOF, an oversized frame, CRLF, a missing or extra LF
//! and bytes after the LF all refuse. The payload is read through EOF first, so
//! an extra frame cannot be accepted after exec.
//!
//! Each case travels through a real pipe rather than an in-memory cursor: the
//! gate the supervisor inherits is a pipe, and reading one to EOF is part of
//! what is under test.

use std::io::Write as _;
use std::process::{Command, Stdio};

use ouro_jail::records::{ErrorCode, GateExpectation, JailError, read_release};

mod common;

const ATTEMPT: &str = "att_00000000-0000-4000-8000-000000000001";

fn expectation() -> GateExpectation {
    GateExpectation {
        attempt_id: ATTEMPT.to_owned(),
        policy_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn valid_line() -> String {
    format!(
        "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\
         \"policy_digest\":\"sha256:{}\"}}",
        "a".repeat(64)
    )
}

/// Sends `payload` through a real pipe and parses whatever arrives.
fn through_pipe(payload: &[u8]) -> Result<(), JailError> {
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("/bin/cat is available on both supported platforms");
    {
        let mut stdin = child.stdin.take().expect("a piped stdin");
        stdin.write_all(payload).expect("the payload fits the pipe");
        // Dropping the handle closes the write end, which is the writer close
        // the protocol requires.
    }
    let mut stdout = child.stdout.take().expect("a piped stdout");
    let result = read_release(&mut stdout, &expectation()).map(|_| ());
    let _ = child.wait();
    result
}

fn expect_refusal(payload: &[u8], code: ErrorCode, label: &str) {
    match through_pipe(payload) {
        Ok(()) => panic!("`{label}` must refuse"),
        Err(error) => {
            assert_eq!(error.code, code, "`{label}` refused with the wrong code");
            assert_eq!(error.exit_code(), 125, "a gate refusal exits 125");
        }
    }
}

#[test]
fn x02_the_single_valid_frame_releases() {
    let payload = format!("{}\n", valid_line());
    through_pipe(payload.as_bytes()).expect("the canonical frame releases");
}

#[test]
fn x02_json_whitespace_inside_the_single_line_is_accepted() {
    let payload = format!(
        "{{ \"schema\" : \"ouro.jail.gate/1\" , \"action\" : \"release\" , \
         \"attempt_id\" : \"{ATTEMPT}\" , \"policy_digest\" : \"sha256:{}\" }}\n",
        "a".repeat(64)
    );
    through_pipe(payload.as_bytes()).expect("whitespace inside the line is allowed");
}

#[test]
fn x02_an_empty_gate_is_a_closed_gate() {
    expect_refusal(b"", ErrorCode::GateClosed, "empty EOF");
}

#[test]
fn x02_framing_faults_refuse() {
    let line = valid_line();
    for (label, payload) in [
        ("missing LF", line.clone().into_bytes()),
        ("CRLF", format!("{line}\r\n").into_bytes()),
        ("extra LF", format!("{line}\n\n").into_bytes()),
        ("leading blank line", format!("\n{line}\n").into_bytes()),
        (
            "bytes after the LF",
            format!("{line}\ntrailing").into_bytes(),
        ),
        ("a second frame", format!("{line}\n{line}\n").into_bytes()),
        ("bare CR", format!("{line}\r").into_bytes()),
    ] {
        expect_refusal(&payload, ErrorCode::GateInvalid, label);
    }
}

#[test]
fn x02_an_oversized_frame_refuses_rather_than_being_truncated() {
    let padded = format!(
        "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\
         \"policy_digest\":\"sha256:{}\"{}}}\n",
        "a".repeat(64),
        " ".repeat(1024)
    );
    assert!(padded.len() > 1024);
    expect_refusal(padded.as_bytes(), ErrorCode::GateInvalid, "oversized");

    // And a frame that is exactly at the cap still parses, so the bound is the
    // one the specification names rather than an off-by-one.
    let base = format!("{}\n", valid_line());
    let padding = 1024 - base.len();
    let at_cap = format!(
        "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\
         \"policy_digest\":\"sha256:{}\"{}}}\n",
        "a".repeat(64),
        " ".repeat(padding)
    );
    assert_eq!(at_cap.len(), 1024, "the LF counts toward the cap");
    through_pipe(at_cap.as_bytes()).expect("a frame at the cap is valid");
}

#[test]
fn x02_content_faults_refuse() {
    let digest = "a".repeat(64);
    for (label, line) in [
        (
            "wrong schema",
            format!(
                "{{\"schema\":\"ouro.jail.gate/2\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\"policy_digest\":\"sha256:{digest}\"}}"
            ),
        ),
        (
            "wrong action",
            format!(
                "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"cancel\",\"attempt_id\":\"{ATTEMPT}\",\"policy_digest\":\"sha256:{digest}\"}}"
            ),
        ),
        (
            "wrong attempt id",
            format!(
                "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"att_00000000-0000-4000-8000-000000000002\",\"policy_digest\":\"sha256:{digest}\"}}"
            ),
        ),
        (
            "wrong digest",
            format!(
                "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\"policy_digest\":\"sha256:{}\"}}",
                "b".repeat(64)
            ),
        ),
        (
            "duplicate JSON key",
            format!(
                "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\"policy_digest\":\"sha256:{digest}\"}}"
            ),
        ),
        (
            "unknown member",
            format!(
                "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\"policy_digest\":\"sha256:{digest}\",\"force\":true}}"
            ),
        ),
        (
            "missing member",
            format!(
                "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\"}}"
            ),
        ),
        ("malformed JSON", "{not json".to_owned()),
        ("a JSON array", "[]".to_owned()),
    ] {
        expect_refusal(
            format!("{line}\n").as_bytes(),
            ErrorCode::GateInvalid,
            label,
        );
    }
}

#[test]
fn x02_a_non_utf8_frame_refuses() {
    let mut payload = valid_line().into_bytes();
    payload.insert(1, 0xff);
    payload.push(b'\n');
    expect_refusal(&payload, ErrorCode::GateInvalid, "non-UTF-8");
}

/// §8.2: "external gate wait: 60 seconds after prepared", enforced by the
/// supervisor rather than by the owner's willingness to write.
///
/// The budget is a parameter so the deadline mechanism can be tested in
/// milliseconds; the constant itself is asserted separately, so shortening the
/// real wait would still be visible.
#[test]
fn x02_a_gate_that_never_delivers_times_out_rather_than_waiting_forever() {
    use std::time::{Duration, Instant};

    let temp = common::private_tempdir();
    let fifo = temp.path().join("gate.fifo");
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(status.success());

    // A writer that holds the fifo open and sends nothing, so the read blocks
    // rather than seeing EOF.
    let mut holder = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "exec 9>'{}'; exec sleep 30",
            fifo.to_str().expect("a UTF-8 path")
        ))
        .spawn()
        .expect("the holder starts");

    let reader = std::fs::OpenOptions::new()
        .read(true)
        .open(&fifo)
        .expect("the fifo opens for reading");
    let fd = std::os::fd::IntoRawFd::into_raw_fd(reader);

    let started = Instant::now();
    let error =
        ouro_jail::supervisor::await_release(fd, &expectation(), Duration::from_millis(300), None)
            .expect_err("a gate that never delivers must time out");
    let elapsed = started.elapsed();
    let _ = holder.kill();
    let _ = holder.wait();

    assert_eq!(error.code, ErrorCode::PrepareTimeout);
    assert_eq!(error.exit_code(), 125);
    assert!(
        elapsed < Duration::from_secs(5),
        "the wait is bounded by its budget, not by the writer: {elapsed:?}"
    );
    assert_eq!(
        ouro_jail::supervisor::GATE_WAIT,
        Duration::from_secs(60),
        "§8.2 names 60 seconds for the real wait"
    );
}
