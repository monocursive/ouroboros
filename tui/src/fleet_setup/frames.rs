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
use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::challenge::{Answer, Registry};
use super::engine::{Engine, Outcome};
use super::{ChallengeRequest, Conversation, Event, OperationState, MAX_FRAME_BODY_BYTES};

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
        let line = bounded_line(frame);
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
        if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
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

/// One frame's body, never longer than a body may be.
///
/// The fields that can grow are bounded where they are built, so this is a backstop
/// rather than the mechanism — but a backstop that has to hold, because the line this
/// returns plus its newline is what the peer's reader measures against the cap. A body
/// that would not fit is replaced by the routing fields of the same frame and a
/// `truncated` marker: a `done` that loses its summary is still a `done` the broker can
/// branch on, and a frame that never arrives is not.
fn bounded_line(frame: Value) -> String {
    let line = frame.to_string();
    if line.len() <= MAX_FRAME_BODY_BYTES {
        return line;
    }
    let mut minimal = serde_json::Map::new();
    for key in [
        "event",
        "state",
        "operation",
        "challenge",
        "kind",
        "machine",
        "step",
        "reason",
        "expires_at",
    ] {
        if let Some(value) = frame.get(key).filter(|value| !value.is_object()) {
            minimal.insert(key.to_string(), value.clone());
        }
    }
    minimal.insert("truncated".to_string(), json!(true));
    let line = Value::Object(minimal).to_string();
    if line.len() <= MAX_FRAME_BODY_BYTES {
        return line;
    }
    json!({"event": "log", "line": "a frame was too large to send", "truncated": true}).to_string()
}

/// The [`Conversation`] the engine talks to when it is speaking frames.
struct FramesConversation {
    sink: Arc<Sink>,
    registry: Arc<Registry>,
    cancelled: Arc<AtomicBool>,
    /// Set when stdin reached EOF: there is nobody left who can answer a question.
    finishing: Arc<AtomicBool>,
}

impl FramesConversation {
    fn ask_issued(&self, issuer: u64, request: ChallengeRequest) -> Result<Answer> {
        // §8: on stdin EOF the operation *finishes*. It has exactly one peer, and that
        // peer has gone, so a question raised now is a question with no answerable
        // destination; waiting out its five minutes would only park the operation on
        // its own lock. It fails the same way an unanswered one does.
        if self.finishing.load(Ordering::Relaxed) {
            return super::refuse(
                "challenge_expired",
                "the peer closed this operation's input before this question was asked, and there is nobody left to answer it",
            );
        }
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
        // Twice, on purpose, and never the same thing twice over one channel: the frame
        // is for the broker, and the line is this operation's own account of itself in
        // `<data dir>/deploy/<id>.log` (§8). Without the second one a finished
        // operation's log is an empty file — which is what `fleet.deployment.status`
        // was serving as "the scrubbed tail" for every operation whose worker had gone.
        match event {
            Event::State(phase) => {
                self.sink.emit(json!({
                    "event": "state",
                    "state": phase.state().as_str(),
                }));
                // The phase's own word, as a terminal prints it: a log of `running`
                // repeated six times says nothing a person can act on.
                eprintln!("· {}", phase.as_str().replace('_', " "));
            }
            Event::Step {
                machine,
                step,
                outcome,
                detail,
            } => {
                // A step's detail quotes what a target said, so it is bounded and
                // stripped like any other text this process did not author.
                let detail = detail
                    .map(|detail| super::sanitize_remote_text(&detail, super::MAX_FRAME_TEXT));
                self.sink.emit(json!({
                    "event": "step",
                    "machine": machine,
                    "step": step,
                    "state": outcome,
                    "detail": detail,
                }));
                match detail.as_deref().filter(|detail| !detail.is_empty()) {
                    Some(detail) => eprintln!("  {machine}: {step} {outcome} — {detail}"),
                    None => eprintln!("  {machine}: {step} {outcome}"),
                }
            }
            Event::Log(line) => {
                let line = super::sanitize_remote_text(&line, 400);
                self.sink.emit(json!({
                    "event": "log",
                    "line": line,
                }));
                eprintln!("  {line}");
            }
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

/// §8's five states — which are now §6's five states too, so this is the identity map
/// rather than a translation. It stays as the one place the wire's words are produced.
fn wire_state(state: OperationState) -> &'static str {
    state.as_str()
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
    let finishing = Arc::new(AtomicBool::new(false));
    let conversation = Arc::new(FramesConversation {
        sink: Arc::clone(&sink),
        registry: Arc::clone(&registry),
        cancelled: Arc::clone(&cancelled),
        finishing: Arc::clone(&finishing),
    });

    let reader = {
        let sink = Arc::clone(&sink);
        let registry = Arc::clone(&registry);
        let cancelled = Arc::clone(&cancelled);
        let finishing = Arc::clone(&finishing);
        std::thread::Builder::new()
            .name("fleet-frames-stdin".into())
            .spawn(move || read_requests(input, &sink, &registry, &cancelled, &finishing))
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
            // undertook to do. The engine says `completed` for one too, now that its
            // states are §8's five; this only still has to print the plan.
            if dry_run {
                if let Some(plan) = &outcome.plan {
                    for line in plan.lines() {
                        sink.emit(json!({
                            "event": "log",
                            "line": super::sanitize_remote_text(&line, 400),
                        }));
                    }
                }
            }
            sink.emit(json!({
                "event": "done",
                "state": wire_state(outcome.state),
                "operation": outcome.operation,
                "summary": super::sanitize_remote_text(&outcome.summary, super::MAX_FRAME_TEXT),
                "next": super::sanitize_remote_text(&outcome.next, super::MAX_FRAME_TEXT),
            }));
        }
        Err(error) => {
            let reason = super::reason_of(error).unwrap_or("failed");
            let state = if reason == "cancelled" {
                "cancelled"
            } else {
                "failed"
            };
            let summary = super::sanitize_remote_text(&format!("{error:#}"), 400);
            sink.emit(json!({
                "event": "done",
                "state": state,
                "operation": operation,
                "reason": reason,
                "summary": summary,
            }));
            // And into this operation's log, which is where a person sent by FLEET.md
            // looks for why it stopped. The process's own exit message is printed by
            // `main` long after the log has been closed, so it cannot be this.
            eprintln!("· {state}: {reason} — {summary}");
        }
    }
    sink.close();
    result
}

/// §8 frames for a refusal that never reached the engine.
///
/// Some things argv is wrong about are found before an engine exists to report them: an
/// operation id that is not one, a resume that contradicts the journal it names. A
/// `--frames` front end still has to answer in frames — the broker reads `done` and
/// nothing else, and a process that exits non-zero having said nothing is a process it
/// cannot explain. Deliberately no `setsid`: nothing is being detached, and this is
/// about to exit.
pub fn refuse_on_stdio(operation: &str, error: &anyhow::Error) {
    let sink = Sink::new(Box::new(std::io::stdout()));
    sink.emit(json!({"event": "state", "state": "running"}));
    let reason = super::reason_of(error).unwrap_or("failed");
    sink.emit(json!({
        "event": "done",
        "state": if reason == "cancelled" { "cancelled" } else { "failed" },
        "operation": operation,
        "reason": reason,
        "summary": super::sanitize_remote_text(&format!("{error:#}"), 400),
    }));
    sink.close();
}

/// `ouro fleet <op> --frames`: the same thing, on this process's own stdio.
pub fn serve(engine: Engine) -> Result<Outcome> {
    // Before `detach`, because after it this process has no controlling terminal and a
    // diagnostic written in between would have nowhere to go.
    //
    // A dry run is exempt: it promises to create nothing, and `<data dir>/deploy/` is
    // the namespace a real operation journals into — a machine that has never deployed
    // would be left holding it.
    let mut log = None;
    if !engine.request.dry_run {
        match capture_stderr(&engine.data_dir, &engine.request.operation) {
            Ok(capture) => log = Some(capture),
            Err(error) => eprintln!("this operation's log could not be opened: {error:#}"),
        }
    }
    detach();
    let result = run(
        engine,
        BufReader::new(std::io::stdin()),
        Box::new(std::io::stdout()),
    );
    // Explicit rather than at the end of the scope: the log is closed, and everything
    // written to it drained, before this returns — because what happens next is `main`
    // printing an exit message, and a process that exits with a line still inside a pipe
    // has lost it. What `main` prints goes to the stderr this process was handed, which
    // is where a person who ran this by hand is looking.
    drop(log);
    result
}

/// §8: *"Stderr goes to `<data dir>/deploy/<id>.log`, 0600, scrubbed by the same funnel
/// as the journal."*
///
/// It went to whatever descriptor this process inherited, which for the broker's port
/// program is the runtime's own stderr — so `fleet.deployment.status`'s `log`, which
/// reads exactly this path, was empty for every operation whose worker had finished,
/// and `log_path` had one caller in the whole build: the pruner that deletes the file.
///
/// A pipe rather than the file itself, because "scrubbed" has to hold for text this
/// process did not write. An `ssh` child inherits descriptor 2 and prints whatever a
/// remote sent it; a panic prints a path. Both arrive here as lines, go through
/// [`sanitize_remote_text`](super::sanitize_remote_text) — the same funnel, at the same
/// 400 characters the journal's `detail` uses — and are appended one at a time, so a
/// process that is killed loses at most the line it was mid-way through.
fn capture_stderr(data_dir: &std::path::Path, operation: &str) -> Result<OperationLog> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    // The id names a file, so it is the validated id or nothing. Every caller has
    // already validated it; this is the one that would have to be wrong for a
    // `--operation ../../x` to become a path.
    super::validate_operation_id(operation)?;
    super::ensure_deploy_dir(data_dir)?;
    let path = super::log_path(data_dir, operation);
    // Appended to, not truncated: a resumed operation's log is the same operation's log.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    // `mode` applies only on create, and §8 fixes the mode of the file rather than of
    // the moment it first appeared.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("securing {}", path.display()))?;

    let (reader, writer) = stderr_pipe()?;
    // Kept, so the inherited stderr can be put back when the operation ends. Without it
    // the only way to let the drain thread see EOF would be to close descriptor 2 for
    // good, and `main`'s exit message would go nowhere at all.
    // SAFETY: `dup` on an open descriptor this process owns; the new one is owned by
    // the `File` from here on.
    let original = unsafe { libc::dup(libc::STDERR_FILENO) };
    if original < 0 {
        return Err(std::io::Error::last_os_error()).context("keeping this process's stderr");
    }
    // SAFETY: `original` is a fresh descriptor, owned by exactly this `File`.
    let original = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(original) };
    // SAFETY: both are open descriptors this process owns, and `dup2` onto descriptor 2
    // closes whatever was there and duplicates the write end in its place.
    if unsafe { libc::dup2(writer.as_raw_fd(), libc::STDERR_FILENO) } < 0 {
        return Err(std::io::Error::last_os_error()).context("redirecting stderr to the log");
    }
    // Descriptor 2 is the write end now; this handle is not needed, and holding it would
    // mean the reader never sees EOF.
    drop(writer);

    let drain = std::thread::Builder::new()
        .name("fleet-frames-stderr".into())
        .spawn(move || {
            for line in BufReader::new(reader).lines() {
                let Ok(line) = line else { return };
                if line.trim().is_empty() {
                    continue;
                }
                let scrubbed = super::sanitize_remote_text(&line, 400);
                if writeln!(file, "{scrubbed}")
                    .and_then(|()| file.flush())
                    .is_err()
                {
                    return;
                }
            }
        })
        .context("starting the operation log writer")?;
    Ok(OperationLog {
        original: Some(original),
        drain: Some(drain),
    })
}

/// The operation's log, for as long as the operation lasts.
///
/// Dropping it puts the inherited stderr back on descriptor 2 — which drops the pipe's
/// last write end — and then waits for the drain thread to finish writing what is still
/// in the pipe. Both halves matter: a process that exits with a line still in flight
/// has lost it, and that line is usually the one saying why it stopped.
struct OperationLog {
    original: Option<std::fs::File>,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl Drop for OperationLog {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;

        if let Some(original) = self.original.take() {
            // SAFETY: `original` is this process's own kept stderr, open for the whole
            // of this call; `dup2` closes the pipe end that is on descriptor 2 now.
            unsafe {
                libc::dup2(original.as_raw_fd(), libc::STDERR_FILENO);
            }
        }
        if let Some(drain) = self.drain.take() {
            let _ = drain.join();
        }
    }
}

/// One pipe, as two owned files. `libc` rather than `std::io::pipe`, which this repo's
/// Rust floor predates.
fn stderr_pipe() -> Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::FromRawFd as _;

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe` fills the two integers it is given and nothing else.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("creating the operation log pipe");
    }
    // SAFETY: both descriptors are fresh, and each is owned by exactly one `File` from
    // here on.
    unsafe {
        Ok((
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        ))
    }
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
    finishing: &Arc<AtomicBool>,
) {
    loop {
        let mut line = Zeroizing::new(String::new());
        match read_line_bounded(&mut input, &mut line) {
            Ok(0) => {
                // §8: stdin EOF *finishes the operation*. Nothing is cancelled — the
                // steps already taken stand, the journal keeps being written, and a
                // review that was accepted before the pipe closed carries the operation
                // through to its end.
                //
                // What does end here is waiting for anybody. This process has one peer
                // and no reattach, so a question still outstanding is a question that
                // can no longer be answered: it used to sit out the whole five-minute
                // lifetime with the operation's flock held, so the journal read
                // `running` and every `--operation ID` resume was refused
                // `operation_in_progress` until the expiry. It expires now instead, and
                // the operation fails `challenge_expired` — the same end, at the moment
                // it became certain. An answer that arrived before the EOF is kept.
                finishing.store(true, Ordering::Relaxed);
                registry.expire_unanswered();
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
        // `total` counts the body; the cap is on the line, which is the body plus the
        // newline that ends it. A body of exactly `MAX_FRAME_BYTES` arrived on a line
        // one byte over the limit.
        if total > MAX_FRAME_BODY_BYTES {
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
    use super::super::{Phase, MAX_FRAME_BYTES};
    use super::*;

    /// §8's five wire states, and nothing else on the wire.
    ///
    /// Two halves, because there are two ways a word could get out. Every state is one
    /// of the five and goes out as itself — that is §6 and §8 being the same vocabulary
    /// now — and every one of the engine's finer phases is mapped onto one of them
    /// before it is emitted, so a phase can never travel under its own name.
    #[test]
    fn every_engine_phase_maps_to_one_of_the_five_wire_states() {
        const FIVE: [&str; 5] = ["running", "waiting", "completed", "failed", "cancelled"];

        for state in [
            OperationState::Running,
            OperationState::Waiting,
            OperationState::Completed,
            OperationState::Failed,
            OperationState::Cancelled,
        ] {
            assert_eq!(wire_state(state), state.as_str(), "{state:?}");
            assert!(FIVE.contains(&wire_state(state)), "{state:?}");
        }

        for (phase, expected) in [
            (Phase::Inspecting, "running"),
            (Phase::Deploying, "running"),
            (Phase::RestartingHost, "running"),
            (Phase::CheckingReadiness, "running"),
            (Phase::AwaitingHostTrust, "waiting"),
            (Phase::AwaitingAuth, "waiting"),
            (Phase::AwaitingReview, "waiting"),
            (Phase::Completed, "completed"),
            (Phase::Failed, "failed"),
            (Phase::Cancelled, "cancelled"),
        ] {
            assert_eq!(wire_state(phase.state()), expected, "{phase:?}");
        }
    }

    /// A `state` frame carries the mapped word, never the phase's own.
    ///
    /// The bug this pins is the one KR3 fixes at the source: the phase `deploying`
    /// reaching a reader that has words for five states and not for eleven.
    #[test]
    fn a_state_frame_never_carries_a_phase_name() {
        let emitted = Arc::new(Mutex::new(Vec::new()));

        struct Collector(Arc<Mutex<Vec<u8>>>);

        impl Write for Collector {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let conversation = FramesConversation {
            sink: Arc::new(Sink::new(Box::new(Collector(Arc::clone(&emitted))))),
            registry: Arc::new(Registry::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
            finishing: Arc::new(AtomicBool::new(false)),
        };
        for phase in [
            Phase::Inspecting,
            Phase::AwaitingReview,
            Phase::Deploying,
            Phase::RestartingHost,
            Phase::CheckingReadiness,
            Phase::Failed,
        ] {
            conversation.notify(Event::State(phase));
        }

        let written = emitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let text = String::from_utf8(written).expect("frames are UTF-8");
        let states: Vec<String> = text
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("one JSON object per line"))
            .map(|frame| frame["state"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(
            states,
            vec!["running", "waiting", "running", "running", "running", "failed"]
        );
    }

    /// A line over the cap is refused rather than buffered.
    #[test]
    fn an_oversized_line_is_refused() {
        let huge = format!("{}\n", "x".repeat(MAX_FRAME_BODY_BYTES + 16));
        let mut input = std::io::BufReader::new(huge.as_bytes());
        let mut line = String::new();
        assert!(read_line_bounded(&mut input, &mut line).is_err());
    }

    /// The cap is on the *line*, which is the body plus its newline.
    ///
    /// The boundary is settled with the Elixir side: a frame line is at most
    /// `MAX_FRAME_BYTES` bytes including the newline, so a body of exactly that many is
    /// one byte too long — in both directions. Nothing this process emits may sit on
    /// the wrong side of it, and nothing it reads may be accepted there.
    #[test]
    fn a_body_of_exactly_the_cap_is_one_byte_too_long_in_both_directions() {
        assert_eq!(MAX_FRAME_BODY_BYTES + 1, MAX_FRAME_BYTES);

        // Reading: a body of `MAX_FRAME_BODY_BYTES` fits, one more does not.
        for (body, fits) in [(MAX_FRAME_BODY_BYTES, true), (MAX_FRAME_BYTES, false)] {
            let line = format!("{}\n", "x".repeat(body));
            assert_eq!(line.len(), body + 1);
            let mut input = std::io::BufReader::new(line.as_bytes());
            let mut read = String::new();
            assert_eq!(
                read_line_bounded(&mut input, &mut read).is_ok(),
                fits,
                "a body of {body} bytes"
            );
        }

        // Writing: a frame whose body would not fit is replaced by one that does, and
        // the replacement keeps the fields a broker branches on.
        let huge = json!({
            "event": "done",
            "state": "failed",
            "operation": "op-0123456789ab",
            "reason": "failed",
            "summary": "x".repeat(MAX_FRAME_BYTES),
        });
        assert!(huge.to_string().len() > MAX_FRAME_BODY_BYTES);
        let line = bounded_line(huge);
        assert!(
            line.len() <= MAX_FRAME_BODY_BYTES,
            "a body of {} bytes was emitted",
            line.len()
        );
        let shrunk: Value = serde_json::from_str(&line).expect("still one JSON object");
        assert_eq!(shrunk["event"], json!("done"));
        assert_eq!(shrunk["state"], json!("failed"));
        assert_eq!(shrunk["operation"], json!("op-0123456789ab"));
        assert_eq!(shrunk["reason"], json!("failed"));
        assert_eq!(shrunk["truncated"], json!(true));
        assert!(shrunk.get("summary").is_none(), "{shrunk}");

        // A frame that already fits is emitted exactly as it was built.
        let small = json!({"event": "state", "state": "running"});
        assert_eq!(bounded_line(small.clone()), small.to_string());
    }

    /// The fields that can grow are bounded long before the frame cap is in sight.
    #[test]
    fn free_text_in_a_frame_is_bounded_well_below_the_cap() {
        let long = "y".repeat(50_000);
        let bounded = super::super::sanitize_remote_text(&long, super::super::MAX_FRAME_TEXT);
        assert_eq!(bounded.chars().count(), super::super::MAX_FRAME_TEXT + 1);
        assert!(bounded.ends_with('…'));
        // A field cap that approaches the frame cap is not a field cap. Written as a
        // `const` assertion because both sides are constants and an `assert!` over two
        // constants is a lint, not a test.
        const _: () = assert!(super::super::MAX_FRAME_TEXT * 8 < MAX_FRAME_BODY_BYTES);
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
