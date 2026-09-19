//! `--frames`: the third front end, NDJSON on this process's own stdin and stdout.
//!
//! `docs/proposals/fleet-kiss.md` §8. This is what the runtime's broker runs as a port
//! program, and it replaces the detached worker, its Unix socket, its capability file,
//! attach, takeover and per-session bindings. There is exactly one peer — whoever holds
//! this process's pipes — so a challenge is answered by whoever is on the other end,
//! and the authorization boundary is the gateway method that started the process.
//!
//! Out, one JSON object per line:
//!
//! - `{"event":"state","state":"running|waiting|completed|failed|cancelled"}`
//! - `{"event":"step","step":"install","state":"ok","detail":"…"}`
//! - `{"event":"log","line":"…"}`
//! - `{"event":"challenge","challenge":"<id>","kind":"host_trust|password|passphrase|review","expires_at":"…","metadata":{…}}`
//! - `{"event":"done","state":"completed|failed|cancelled","summary":"…"}`
//!
//! In:
//!
//! - `{"op":"respond","challenge":"<id>","accept":true|false}` for `host_trust` and `review`
//! - `{"op":"respond","challenge":"<id>","secret":"…"}` for `password` and `passphrase`
//! - `{"op":"cancel"}`
//!
//! The process calls `setsid` at start and ignores `SIGHUP` and `SIGPIPE`. Once the
//! review is accepted it needs nothing more from stdin: **on stdin EOF it finishes the
//! operation, keeps writing the journal, and stops writing to stdout.** That is how a
//! local `setup` survives the runtime it was started from, and it is the whole of
//! "survives" — there is no reattach. A challenge nobody answers within five minutes
//! fails the operation `challenge_expired`.
//!
//! Nothing here logs a `respond` frame. It is the one frame that may carry a secret.

use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::challenge::{Answer, Registry};
use super::engine::{Engine, Outcome};
use super::{ChallengeRequest, Conversation, Event, OperationState, MAX_FRAME_BYTES};

/// Everything the frames front end writes, in one place so a secret cannot reach it by
/// accident: this is the only thing that touches stdout.
struct Sink {
    out: Mutex<Option<Box<dyn Write + Send>>>,
}

impl Sink {
    fn new(out: Box<dyn Write + Send>) -> Self {
        Self {
            out: Mutex::new(Some(out)),
        }
    }

    fn emit(&self, frame: Value) {
        let mut held = self
            .out
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(out) = held.as_mut() else {
            return;
        };
        // §8: after stdin EOF the operation keeps going and stops writing to stdout. A
        // broken pipe is the same thing arriving the other way round, so it closes the
        // sink rather than failing the operation.
        if writeln!(out, "{frame}").and_then(|()| out.flush()).is_err() {
            *held = None;
        }
    }

    /// Stop writing, without ending the operation.
    fn close(&self) {
        let mut held = self
            .out
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *held = None;
    }
}

/// The [`Conversation`] the engine talks to when it is speaking frames.
struct FramesConversation {
    sink: Arc<Sink>,
    registry: Arc<Registry>,
    cancelled: Arc<AtomicBool>,
}

impl FramesConversation {
    fn ask_issued(&self, issuer: u64, request: ChallengeRequest) -> Result<Answer> {
        let challenge = self
            .registry
            .issue(request.kind, request.metadata.clone(), issuer)?;
        self.sink.emit(json!({
            "event": "challenge",
            "challenge": challenge.challenge,
            "kind": challenge.kind.as_str(),
            "expires_at": challenge.expires_at,
            "metadata": challenge.metadata,
        }));
        self.sink.emit(json!({
            "event": "state",
            "state": "waiting",
        }));
        self.registry.wait(&challenge.challenge)
    }
}

impl Conversation for FramesConversation {
    fn ask(&self, request: ChallengeRequest) -> Result<Answer> {
        self.ask_issued(0, request)
    }

    fn ask_from(&self, issuer: u64, request: ChallengeRequest) -> Result<Answer> {
        self.ask_issued(issuer, request)
    }

    fn withdraw(&self, issuer: u64, reason: &'static str) {
        self.registry.invalidate_issuer(issuer, reason);
    }

    fn notify(&self, event: Event) {
        match event {
            Event::State(state) => self.sink.emit(json!({
                "event": "state",
                "state": wire_state(state),
            })),
            Event::Step {
                machine,
                step,
                outcome,
                detail,
            } => self.sink.emit(json!({
                "event": "step",
                "machine": machine,
                "step": step,
                "state": outcome,
                "detail": detail,
            })),
            Event::Log(line) => self.sink.emit(json!({
                "event": "log",
                "line": super::sanitize_remote_text(&line, 400),
            })),
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

/// §8's five states, which are not the engine's eleven. Everything that is neither
/// terminal nor a question is `running`.
fn wire_state(state: OperationState) -> &'static str {
    match state {
        OperationState::Completed => "completed",
        OperationState::Failed | OperationState::Interrupted => "failed",
        OperationState::Cancelled => "cancelled",
        state if state.waiting() => "waiting",
        _ => "running",
    }
}

/// Run one operation, speaking §8's frames on `input` and `output`.
///
/// Split from [`serve`] so a harness can drive it over pipes without a terminal, which
/// is exactly what the loopback rig does.
pub fn run(
    engine: Engine,
    input: impl BufRead + Send + 'static,
    output: Box<dyn Write + Send>,
) -> Result<Outcome> {
    let sink = Arc::new(Sink::new(output));
    let registry = Arc::new(Registry::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    let conversation = Arc::new(FramesConversation {
        sink: Arc::clone(&sink),
        registry: Arc::clone(&registry),
        cancelled: Arc::clone(&cancelled),
    });

    let reader = {
        let sink = Arc::clone(&sink);
        let registry = Arc::clone(&registry);
        let cancelled = Arc::clone(&cancelled);
        std::thread::Builder::new()
            .name("fleet-frames-stdin".into())
            .spawn(move || read_requests(input, &sink, &registry, &cancelled))
            .context("starting the frames input reader")?
    };

    let mut engine = engine;
    engine.conversation = conversation;
    // The broker keys everything on the operation id, so every terminal frame carries
    // it — including the one a refusal produces, which has no `Outcome` to read it from.
    let operation = engine.request.operation.clone();
    let dry_run = engine.request.dry_run;
    sink.emit(json!({"event": "state", "state": "running"}));
    let result = engine.run();
    // The reader thread ends at EOF; it is deliberately not joined on the happy path,
    // because §8 says the operation finishes without anything further from stdin.
    drop(reader);

    match &result {
        Ok(outcome) => {
            // A dry run asks nobody anything, so the plan it resolved has no `review`
            // challenge to travel on. It goes out as `log` lines — the same lines §6
            // names and the same ones a review would have carried — and the operation
            // is `completed`, because inspecting and printing is the whole of what it
            // undertook to do. The engine's own state for a dry run is
            // `awaiting_review`, which is not one of §8's five terminal words.
            if dry_run {
                if let Some(plan) = &outcome.plan {
                    for line in plan.lines() {
                        sink.emit(json!({"event": "log", "line": line}));
                    }
                }
            }
            sink.emit(json!({
                "event": "done",
                "state": if dry_run {
                    "completed"
                } else {
                    wire_state(outcome.state)
                },
                "operation": outcome.operation,
                "summary": outcome.summary,
                "next": outcome.next,
            }));
        }
        Err(error) => {
            let reason = super::reason_of(error).unwrap_or("failed");
            let state = if reason == "cancelled" {
                "cancelled"
            } else {
                "failed"
            };
            sink.emit(json!({
                "event": "done",
                "state": state,
                "operation": operation,
                "reason": reason,
                "summary": super::sanitize_remote_text(&format!("{error:#}"), 400),
            }));
        }
    }
    sink.close();
    result
}

/// `ouro fleet <op> --frames`: the same thing, on this process's own stdio.
pub fn serve(engine: Engine) -> Result<Outcome> {
    detach();
    run(
        engine,
        BufReader::new(std::io::stdin()),
        Box::new(std::io::stdout()),
    )
}

/// §8: `setsid`, `SIGHUP` and `SIGPIPE` ignored.
///
/// A local `setup` stops the very runtime that started this process. Without its own
/// session it would be signalled when that runtime's process group goes away, and the
/// machine would be left half-configured with no journal entry saying why.
fn detach() {
    // SAFETY: both calls are process-wide and take no pointer. `setsid` failing because
    // this process is already a group leader is the normal case under a port program.
    unsafe {
        libc::setsid();
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// The input half. Everything it reads is data: one object per line, capped, and only
/// two operations.
fn read_requests(
    mut input: impl BufRead,
    sink: &Arc<Sink>,
    registry: &Arc<Registry>,
    cancelled: &Arc<AtomicBool>,
) {
    loop {
        let mut line = Zeroizing::new(String::new());
        match read_line_bounded(&mut input, &mut line) {
            Ok(0) => {
                // §8: stdin EOF finishes the operation. Nothing is cancelled and nothing
                // is withdrawn — an unanswered challenge still expires on its own clock.
                return;
            }
            Ok(_) => {}
            Err(_) => return,
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(text) else {
            sink.emit(json!({
                "event": "log",
                "line": "a request must be one JSON object per line",
            }));
            continue;
        };
        match request.get("op").and_then(Value::as_str) {
            Some("cancel") => {
                cancelled.store(true, Ordering::Relaxed);
                registry.invalidate_all();
            }
            Some("respond") => {
                let Some(challenge) = request.get("challenge").and_then(Value::as_str) else {
                    sink.emit(json!({
                        "event": "log",
                        "line": "a respond frame names the challenge it answers",
                    }));
                    continue;
                };
                // The response object is the frame itself, minus the routing fields; a
                // failure here is reported without ever quoting what was sent.
                if let Err(error) = registry.respond(challenge, &request) {
                    sink.emit(json!({
                        "event": "log",
                        "line": format!(
                            "that answer was not accepted: {}",
                            super::reason_of(&error).unwrap_or("failed")
                        ),
                    }));
                }
            }
            _ => sink.emit(json!({
                "event": "log",
                "line": "`op` must be `respond` or `cancel`",
            })),
        }
    }
}

/// One line, refusing anything over the frame cap rather than buffering it.
fn read_line_bounded(input: &mut impl BufRead, out: &mut String) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let available = match input.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Ok(total);
        }
        let (consumed, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                out.push_str(&String::from_utf8_lossy(&available[..index]));
                total += index;
                (index + 1, true)
            }
            None => {
                out.push_str(&String::from_utf8_lossy(available));
                total += available.len();
                (available.len(), false)
            }
        };
        input.consume(consumed);
        if total > MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a request line over the frame cap is not read",
            ));
        }
        if done {
            return Ok(total.max(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §8's five wire states, and nothing else on the wire.
    #[test]
    fn every_engine_state_maps_to_one_of_the_five_wire_states() {
        for (state, expected) in [
            (OperationState::Inspecting, "running"),
            (OperationState::Deploying, "running"),
            (OperationState::RestartingHost, "running"),
            (OperationState::CheckingReadiness, "running"),
            (OperationState::AwaitingHostTrust, "waiting"),
            (OperationState::AwaitingAuth, "waiting"),
            (OperationState::AwaitingReview, "waiting"),
            (OperationState::Completed, "completed"),
            (OperationState::Failed, "failed"),
            (OperationState::Interrupted, "failed"),
            (OperationState::Cancelled, "cancelled"),
        ] {
            assert_eq!(wire_state(state), expected, "{state:?}");
        }
    }

    /// A line over the cap is refused rather than buffered.
    #[test]
    fn an_oversized_line_is_refused() {
        let huge = format!("{}\n", "x".repeat(MAX_FRAME_BYTES + 16));
        let mut input = std::io::BufReader::new(huge.as_bytes());
        let mut line = String::new();
        assert!(read_line_bounded(&mut input, &mut line).is_err());
    }

    /// The sink stops writing after a broken pipe instead of failing the operation.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_broken_pipe_closes_the_sink_without_panicking() {
        let sink = Sink::new(Box::new(Broken));
        sink.emit(json!({"event": "log", "line": "one"}));
        sink.emit(json!({"event": "log", "line": "two"}));
    }
}
