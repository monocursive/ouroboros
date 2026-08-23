//! `ouro run`: one prompt, the normalised events, and a documented exit code.
//!
//! This is the headless surface. Everything a person would read off the screen — the
//! transcript, the approval modal, the status footer — either becomes a JSON object on
//! stdout or does not exist here, and the exit code is the part a script actually
//! branches on.
//!
//! ## What is on stdout, and what is not
//!
//! `--stream-json` writes **the wire `event` object exactly as the gateway sent it**, one
//! per line, and then one `{"type":"result", …}` object. That object is
//! `interactive.event`'s `params.event` verbatim: it is golden-pinned on the Elixir side
//! ([`test/support/gateway_golden/interactive_event_notification.json`]), and inventing a
//! second shape here would mean two schemas that can disagree about the same turn. The
//! result object is this command's own, and it carries only what the events proved.
//!
//! `--json` prints the result object alone. With neither flag stdout carries the agent's
//! final text and nothing else, so `ouro run "…" | pbcopy` does what it looks like.
//! Progress, warnings, and the "runtime still running" line go to stderr, which is why
//! they cannot corrupt any of the three.
//!
//! ## Honesty
//!
//! A send whose outcome the transport could not establish is retried exactly once under
//! the same caller-minted `turn_id` — the same rule `ouro new -m` follows — and if the
//! stream never resolves it the run reports `status: "lost"`, never `completed`. A
//! session that ends before its turn does is `lost` for the same reason: the turn's
//! outcome was not observed, and a headless caller that read `completed` there would be
//! reading a guess.
//!
//! ## Approvals
//!
//! There is no approver at a pipe. An `approval_requested` is answered `deny`/`once` with
//! a reason saying so, or `approve`/`once` under `--approve-all`. The command never waits
//! on a human it does not have — the failure mode this replaces is a script that hangs
//! until its CI job is killed.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::model::transcript::Diff;
use crate::model::{
    self, ApprovalDecision, ApprovalScope, Event, EventType, Plane, StartRequest, StartedRef,
};
use crate::proto::{ErrorCode, Hello, Notification};
use crate::transport::{Client, ClientError};

/// The reason `deny` is the headless default, said in the place the runtime records it.
pub const HEADLESS_DENY_REASON: &str = "ouro run: headless, no approver";

/// `interactive.start` declares a 120s gateway ceiling because provider readiness is
/// `:infinity` upstream. The same number the UI uses, for the same reason.
const START_TIMEOUT: Duration = Duration::from_secs(130);

/// The gateway refuses a replay limit above 500.
const REPLAY_LIMIT: u64 = 500;

/// How many replay rounds one gap may cost before this command stops asking. Past it the
/// run reports what it has rather than looping against a session producing history faster
/// than it can be read.
const MAX_RESYNC_ROUNDS: u32 = 40;

/// How long an interrupt is given to produce its own event before the run reports the
/// outcome it already knows. Bounded, because the whole point of `--timeout` is that this
/// command ends.
const INTERRUPT_GRACE: Duration = Duration::from_secs(10);

/// Ceiling on the two calls a run makes while it is already ending — the interrupt, and
/// draining an approval answer still on the wire. Neither may extend the run by the
/// transport's whole default.
const INTERRUPT_CEILING: Duration = Duration::from_secs(5);

/// Per-message ceiling on collapsed deltas, matching the transcript's own draft bound.
const MESSAGE_BYTES: usize = 128 * 1024;

/// Ceiling on the assembled final text. A headless caller gets a bounded string or a
/// truncation marker, never whatever the provider felt like emitting.
const TEXT_BYTES: usize = 1024 * 1024;

const TRUNCATION: &str = "\n… truncated by ouro run\n";

/// Ceiling on remembered changed paths, matching the transcript's own.
const MAX_FILES: usize = 256;

/// Ceiling on out-of-order events held while a gap is being replayed.
const MAX_PENDING: usize = 10_000;

/// How stdout is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// The agent's final text, for a person.
    Text,
    /// The result object alone.
    Json,
    /// Every normalised event, then the result object.
    StreamJson,
}

/// Everything the driver needs that is not the connection or the plan.
#[derive(Debug, Clone)]
pub struct Options {
    pub output: Output,
    /// Answer approvals `approve`/`once` instead of the headless `deny`/`once`.
    pub approve_all: bool,
    pub timeout: Duration,
    /// Progress lines on stderr. Never on stdout: stdout is the contract.
    pub verbose: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            output: Output::Text,
            approve_all: false,
            timeout: Duration::from_secs(600),
            verbose: false,
        }
    }
}

/// What this run does once it has a connection.
#[derive(Debug, Clone)]
pub enum Plan {
    /// Start a session, then send the prompt into it.
    Start {
        request: StartRequest,
        /// The validated params, minted before the mutation so a lost reply can only
        /// adopt the same session.
        params: Value,
        prompt: String,
    },
    /// Send the prompt into a session that already exists.
    Resume { session_id: String, prompt: String },
}

/// The documented end state of a run. Exactly five, because a script branches on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Completed,
    Failed,
    Interrupted,
    /// The turn's outcome was not observed. Never a synonym for failure, and never
    /// rounded up to success.
    Lost,
    Timeout,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Lost => "lost",
            Self::Timeout => "timeout",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Completed => 0,
            Self::Failed => 1,
            Self::Interrupted => 2,
            Self::Lost => 3,
            Self::Timeout => 4,
        }
    }
}

/// The process exit code this command ended with, carried as an error so `main` can honour
/// it without every other subcommand learning about exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit(u8);

impl Exit {
    /// A usage error or a refusal: nothing ran.
    pub const USAGE: Exit = Exit(64);

    pub fn code(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ouro run exited {}", self.0)
    }
}

impl std::error::Error for Exit {}

/// One run's answer, and the only thing `--json` prints.
#[derive(Debug, Clone)]
pub struct Report {
    pub session_id: String,
    pub turn_id: String,
    pub status: Status,
    pub provider: Option<String>,
    pub node: Option<String>,
    /// Numbers folded from `usage` events. Never a string, never a nested object.
    pub usage: BTreeMap<String, f64>,
    pub files_changed: Vec<String>,
    pub approvals_requested: u64,
    pub approvals_answered: u64,
    pub duration: Duration,
    pub error: Option<String>,
    /// The agent's own words. Carried for the plain surface, deliberately absent from the
    /// result object: the events already said it, and saying it twice invites the two
    /// copies to diverge.
    pub text: String,
}

impl Report {
    fn new(session_id: String, turn_id: String) -> Self {
        Self {
            session_id,
            turn_id,
            status: Status::Lost,
            provider: None,
            node: None,
            usage: BTreeMap::new(),
            files_changed: Vec::new(),
            approvals_requested: 0,
            approvals_answered: 0,
            duration: Duration::ZERO,
            error: None,
            text: String::new(),
        }
    }

    pub fn exit(&self) -> Exit {
        Exit(self.status.code())
    }

    /// The wire form. Keys with nothing behind them are omitted rather than sent as null:
    /// a `provider` this run never learned is not a provider named `null`.
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("type".into(), Value::String("result".into()));
        object.insert("session_id".into(), Value::String(self.session_id.clone()));
        object.insert("turn_id".into(), Value::String(self.turn_id.clone()));
        object.insert(
            "status".into(),
            Value::String(self.status.as_str().to_string()),
        );

        if let Some(provider) = &self.provider {
            object.insert("provider".into(), Value::String(provider.clone()));
        }
        if let Some(node) = &self.node {
            object.insert("node".into(), Value::String(node.clone()));
        }

        object.insert("usage".into(), usage_json(&self.usage));
        object.insert(
            "files_changed".into(),
            Value::Array(
                self.files_changed
                    .iter()
                    .map(|path| Value::String(path.clone()))
                    .collect(),
            ),
        );
        object.insert(
            "approvals".into(),
            json!({
                "requested": self.approvals_requested,
                "answered": self.approvals_answered,
            }),
        );
        object.insert(
            "duration_ms".into(),
            Value::Number(u64_number(
                self.duration.as_millis().min(u128::from(u64::MAX)) as u64,
            )),
        );

        if let Some(error) = &self.error {
            object.insert("error".into(), Value::String(error.clone()));
        }

        Value::Object(object)
    }
}

fn usage_json(usage: &BTreeMap<String, f64>) -> Value {
    let mut object = Map::new();

    for (key, value) in usage {
        object.insert(key.clone(), number(*value));
    }

    Value::Object(object)
}

/// A whole count stays an integer on the wire. `total_tokens: 12.0` is a token count that
/// reads like a measurement.
fn number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15 {
        return Value::Number(serde_json::Number::from(value as i64));
    }

    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn u64_number(value: u64) -> serde_json::Number {
    serde_json::Number::from(value)
}

/// A refusal: this command declined before it mutated anything.
#[derive(Debug, Clone)]
pub struct Refusal(pub String);

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Refusal {
    /// The `{"type":"error", …}` object `--json` and `--stream-json` print on stdout
    /// beside the sentence on stderr, so a script that only reads stdout still sees it.
    pub fn to_json(&self) -> Value {
        json!({ "type": "error", "error": self.0 })
    }
}

/// Where the driver writes. Two sinks so a test can read both, and so nothing that
/// belongs on stderr can ever reach the JSON on stdout.
pub struct Sinks<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl Sinks<'_> {
    fn line(&mut self, text: &str) {
        let _ = writeln!(self.out, "{text}");
        let _ = self.out.flush();
    }

    fn note(&mut self, verbose: bool, text: &str) {
        if verbose {
            let _ = writeln!(self.err, "ouro run: {text}");
            let _ = self.err.flush();
        }
    }

    fn warn(&mut self, text: &str) {
        let _ = writeln!(self.err, "ouro run: {text}");
        let _ = self.err.flush();
    }
}

/// Runs one prompt to its end and writes the surface `options` asked for.
///
/// Returns the report even when the run failed: every arm below is an *outcome*, not an
/// error, because a headless caller needs the session id and the usage of a turn that
/// failed just as much as of one that did not.
pub async fn drive(
    client: &Client,
    notifications: &mut mpsc::Receiver<Notification>,
    hello: &Hello,
    plan: Plan,
    options: &Options,
    sinks: &mut Sinks<'_>,
) -> Result<Report, Refusal> {
    let started_at = Instant::now();
    let mut run = Run::new(client, options, started_at);

    match plan {
        Plan::Start {
            request,
            params,
            prompt,
        } => run.start(hello, &request, params, prompt, sinks).await?,
        Plan::Resume { session_id, prompt } => run.resume(hello, session_id, prompt, sinks).await?,
    }

    run.stream(notifications, sinks).await;
    run.settle_approvals(sinks).await;

    Ok(run.finish(sinks))
}

/// One in-flight run. Split out from [`drive`] so the fold and the stream loop can share
/// the cursor, the pending window, and the counters without threading eleven arguments.
struct Run<'a> {
    client: &'a Client,
    options: &'a Options,
    started_at: Instant,
    report: Report,
    /// Session routing, when the runtime answered with an owner other than this node.
    node: Option<String>,
    /// The id the provider's own events carry for this turn, once the send named it.
    harness_turn: Option<String>,
    /// The contiguous high-water mark. Everything at or below it has been printed.
    cursor: u64,
    /// Events above `cursor + 1`, held in order until the gap under them is replayed.
    pending: BTreeMap<u64, Event>,
    rounds: u32,
    /// Agent messages, in order, with the in-flight one last.
    messages: Vec<String>,
    draft: Option<String>,
    changed: ChangedFiles,
    approvals: JoinSet<Result<(), ClientError>>,
    /// The send could not be reconciled. Only a turn-terminal event can clear it.
    unreconciled: Option<String>,
    /// The end state this command asked for — a `--timeout` that expired, or a Ctrl-C.
    /// It wins over whatever the stream says afterwards, because "the turn was
    /// interrupted because I interrupted it" is the fact a script is branching on.
    requested: Option<Status>,
    /// Set once a terminal event decided the run.
    settled: Option<Status>,
}

impl<'a> Run<'a> {
    fn new(client: &'a Client, options: &'a Options, started_at: Instant) -> Self {
        Self {
            client,
            options,
            started_at,
            report: Report::new(String::new(), String::new()),
            node: None,
            harness_turn: None,
            cursor: 0,
            pending: BTreeMap::new(),
            rounds: 0,
            messages: Vec::new(),
            draft: None,
            changed: ChangedFiles::default(),
            approvals: JoinSet::new(),
            unreconciled: None,
            requested: None,
            settled: None,
        }
    }

    // ----- establishing the session ------------------------------------------------

    /// `interactive.start`, then subscribe from zero, then send.
    ///
    /// The order matters: subscribing before the send is what makes the turn's first
    /// events unmissable, and a subscribe from cursor 0 answers the session's whole
    /// retained backlog, which for a session this call just created is its own startup.
    async fn start(
        &mut self,
        hello: &Hello,
        request: &StartRequest,
        params: Value,
        prompt: String,
        sinks: &mut Sinks<'_>,
    ) -> Result<(), Refusal> {
        let method = request.method();
        self.require(hello, &method)?;
        self.require(hello, "interactive.subscribe")?;
        self.require(hello, "interactive.send_message")?;

        sinks.note(
            self.options.verbose,
            &format!("starting a {} session", request.provider),
        );

        let started = self.start_call(&method, params).await?;

        let Some(started) = StartedRef::decode(&started) else {
            return Err(Refusal(format!(
                "the runtime answered client session {} with a reference this build cannot \
                 read: {started}",
                request.id
            )));
        };

        if started.id != request.id {
            return Err(Refusal(format!(
                "the runtime answered client session {} with a different session id {}; \
                 refusing to send a prompt because the start identity contract was violated",
                request.id, started.id
            )));
        }

        self.report.session_id = started.id.clone();
        self.report.provider = Some(request.provider.clone());
        self.node = started.node.clone();
        self.report.node = started.node.clone();
        self.report.turn_id = format!("ouro-run:{}", started.id);

        if let Some(failure) = &started.start_failure {
            // Durably created and addressable, but never ready. There is no turn to
            // stream, and calling that anything but a failure would hide a session the
            // caller is still paying for.
            self.report.status = Status::Failed;
            self.report.error = Some(format!(
                "created durable session {}, but it did not become ready: {failure}",
                started.id
            ));
            self.settled = Some(Status::Failed);
            return Ok(());
        }

        sinks.note(
            self.options.verbose,
            &format!("session {} started", started.id),
        );

        self.subscribe(0, sinks).await?;
        self.send("interactive.send_message", &prompt, sinks).await;

        Ok(())
    }

    /// `interactive.info`, then subscribe from where that session already is.
    ///
    /// The cursor is `Ouroboros.Interactive.State`'s own `cursor` field — the session's
    /// contiguous event high-water mark, which `State.public/1` carries through
    /// `interactive.info` verbatim. Subscribing from it is what makes `--resume` print the
    /// new turn and not the session's whole history. A runtime that did not answer one
    /// leaves this at zero and says so on stderr rather than silently replaying
    /// everything as if it were new.
    async fn resume(
        &mut self,
        hello: &Hello,
        session_id: String,
        prompt: String,
        sinks: &mut Sinks<'_>,
    ) -> Result<(), Refusal> {
        self.require(hello, "interactive.info")?;
        self.require(hello, "interactive.subscribe")?;

        self.report.session_id = session_id.clone();

        let info = self
            .client
            .call("interactive.info", json!({ "id": session_id }))
            .await
            .map_err(|error| {
                Refusal(format!(
                    "interactive.info for {session_id} was refused: {}",
                    rendered(&error)
                ))
            })?;

        self.node = info
            .get("node")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|node| !node.is_empty());
        self.report.node = self.node.clone();
        self.report.provider = info
            .get("provider")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|provider| !provider.is_empty());

        let status = info
            .get("status")
            .and_then(Value::as_str)
            .map(model::SessionStatus::parse);

        if let Some(status) = &status {
            if status.terminal() {
                return Err(Refusal(format!(
                    "session {session_id} is {}; a terminal session takes no further turns",
                    status.as_str()
                )));
            }
        }

        let cursor = match info.get("cursor").and_then(Value::as_u64) {
            Some(cursor) => cursor,
            None => {
                sinks.warn(&format!(
                    "interactive.info for {session_id} carried no cursor; streaming from the \
                     start of its retained window, so events older than this turn may print"
                ));
                0
            }
        };

        // The one-in-flight rule: a second immediate `send_message` into a session that is
        // not idle is refused `:busy`, and `follow_up` is the verb that queues instead.
        let busy = status
            .as_ref()
            .map(|status| !matches!(status, model::SessionStatus::Idle))
            .unwrap_or(false);
        let verb = if busy {
            "interactive.follow_up"
        } else {
            "interactive.send_message"
        };

        self.require(hello, verb)?;
        // Fresh, not derived from the cursor: two deliberate `ouro run --resume` calls are
        // two turns, and an id the second one shared with the first would be offered to
        // the gateway as a retry of it.
        self.report.turn_id = new_turn_id();

        sinks.note(
            self.options.verbose,
            &format!("resuming {session_id} from cursor {cursor} with {verb}"),
        );

        self.subscribe(cursor, sinks).await?;
        self.send(verb, &prompt, sinks).await;

        Ok(())
    }

    fn require(&self, hello: &Hello, method: &str) -> Result<(), Refusal> {
        if !hello.serves(method) {
            return Err(Refusal(format!(
                "this gateway does not serve {method}; `ouro run` needs it"
            )));
        }

        if method_mutates(method) && !hello.operates() {
            return Err(Refusal(format!(
                "this gateway serves {method} at scope `{}`; running a prompt mutates the \
                 runtime and needs OUROBOROS_GATEWAY_SCOPE=operate",
                hello.scope
            )));
        }

        Ok(())
    }

    /// The start, with the exact same-id retry `ouro new` performs.
    ///
    /// A transport failure or an upstream timeout may have happened *after* the gateway
    /// durably created the session, so the only safe recovery is replaying the identical
    /// request: it can adopt the same session or report a conflict, never bill a second.
    async fn start_call(&self, method: &str, params: Value) -> Result<Value, Refusal> {
        let first = self
            .client
            .call_with_timeout(method, params.clone(), START_TIMEOUT)
            .await;

        let first_error = match first {
            Ok(started) => return Ok(started),
            Err(error) => error,
        };

        if !model::start_outcome_unknown(&first_error) {
            return Err(Refusal(format!(
                "{method} was refused: {}",
                rendered(&first_error)
            )));
        }

        match self
            .client
            .call_with_timeout(method, params, START_TIMEOUT)
            .await
        {
            Ok(started) => Ok(started),
            Err(retry_error) => {
                let retry_status = if model::start_outcome_unknown(&retry_error) {
                    "also had an unknown outcome"
                } else {
                    "returned a definite refusal, but cannot prove the first request did not \
                     create the session"
                };

                Err(Refusal(format!(
                    "the {method} outcome is unknown; the exact same-id retry {retry_status}. \
                     Run `ouro` and inspect the sessions this runtime holds before starting \
                     another. first attempt: {}; retry: {}",
                    rendered(&first_error),
                    rendered(&retry_error)
                )))
            }
        }
    }

    /// Subscribes and absorbs the backlog the gateway answers with, in order.
    async fn subscribe(&mut self, cursor: u64, sinks: &mut Sinks<'_>) -> Result<(), Refusal> {
        self.cursor = cursor;

        let params = self.routed(json!({ "id": self.report.session_id, "cursor": cursor }));

        match self.client.call("interactive.subscribe", params).await {
            Ok(backlog) => {
                self.absorb(&backlog, cursor, sinks);
                Ok(())
            }
            Err(ClientError::Rpc(rpc)) => {
                if let Some(pruned) = model::CursorPruned::from_error_data(rpc.data.as_ref()) {
                    sinks.warn(&format!(
                        "{}: the runtime no longer retains history below {}; the stream starts \
                         there",
                        self.report.session_id, pruned.floor
                    ));
                    self.cursor = pruned.floor;
                    let params = self
                        .routed(json!({ "id": self.report.session_id, "cursor": pruned.floor }));

                    return match self.client.call("interactive.subscribe", params).await {
                        Ok(backlog) => {
                            self.absorb(&backlog, pruned.floor, sinks);
                            Ok(())
                        }
                        Err(error) => Err(Refusal(format!(
                            "subscribing to {} was refused: {}",
                            self.report.session_id,
                            rendered(&error)
                        ))),
                    };
                }

                Err(Refusal(format!(
                    "subscribing to {} was refused: {}",
                    self.report.session_id,
                    model::refusal(&rpc)
                )))
            }
            Err(error) => Err(Refusal(format!(
                "subscribing to {} failed: {}",
                self.report.session_id,
                rendered(&error)
            ))),
        }
    }

    /// The prompt, under the stable turn id, with the one safe reconciliation.
    ///
    /// Unlike `ouro new --print` this command *is* subscribed, so an unreconciled send is
    /// not the end of the story: the stream may still resolve the turn. What it may not do
    /// is disappear — [`Self::finish`] turns an unresolved one into `lost`.
    async fn send(&mut self, method: &str, prompt: &str, sinks: &mut Sinks<'_>) {
        let params = self.routed(json!({
            "id": self.report.session_id,
            "input": prompt,
            "turn_id": self.report.turn_id,
        }));

        let sent = self.client.call(method, params.clone()).await;
        let failure = match &sent {
            Ok(value) => turn_failure(value),
            Err(error) => Some(SendFailure {
                rendered: rendered(error),
                outcome_unknown: send_outcome_unknown(error),
            }),
        };

        let Some(failure) = failure else {
            if let Ok(value) = &sent {
                self.adopt_harness_turn(value.clone(), sinks);
            }

            sinks.note(
                self.options.verbose,
                &format!("turn {} accepted", self.report.turn_id),
            );
            return;
        };

        if !failure.outcome_unknown {
            self.report.status = Status::Failed;
            self.report.error = Some(format!(
                "the prompt was not accepted: {}",
                failure.rendered.clone()
            ));
            self.settled = Some(Status::Failed);
            return;
        }

        let sent = self.client.call(method, params).await;
        let retry = match &sent {
            Ok(value) => turn_failure(value),
            Err(error) => Some(SendFailure {
                rendered: rendered(error),
                outcome_unknown: send_outcome_unknown(error),
            }),
        };

        match retry {
            None => {
                if let Ok(value) = &sent {
                    self.adopt_harness_turn(value.clone(), sinks);
                }

                sinks.note(
                    self.options.verbose,
                    &format!("turn {} accepted on the same-id retry", self.report.turn_id),
                )
            }
            Some(retry) if retry.outcome_unknown => {
                self.unreconciled = Some(format!(
                    "the prompt's outcome remains unknown after retrying turn {}; first \
                     attempt: {}; retry: {}",
                    self.report.turn_id, failure.rendered, retry.rendered
                ));
                sinks.warn(
                    "the prompt's outcome is unknown; streaming the session to find out what \
                     happened to it",
                );
            }
            Some(retry) => {
                self.report.status = Status::Failed;
                self.report.error = Some(format!(
                    "the prompt was not accepted: turn {} in session {} is terminal. {}",
                    self.report.turn_id, self.report.session_id, retry.rendered
                ));
                self.settled = Some(Status::Failed);
            }
        }
    }

    /// Remembers the id the *provider's* events will actually carry.
    ///
    /// One turn has two identifiers, and this is the seam between them. The caller-minted
    /// `turn_id` is the gateway's durable reconciliation key — it is what makes the
    /// same-id retry above safe, and it is what this run reports. The events the Harness
    /// emits are keyed by an id it mints inside its own worker, which
    /// `interactive.send_message` returns as `harness_turn_id`
    /// ([`lib/ouroboros/interactive/task.ex`] `dispatch_persisted_turn`). Matching only on
    /// the first one meant watching this run's own `turn_completed` go by unrecognised and
    /// then reporting a timeout — a live runtime is the only thing that shows that.
    fn adopt_harness_turn(&mut self, reply: Value, sinks: &mut Sinks<'_>) {
        let Some(harness) = reply
            .get("harness_turn_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
        else {
            return;
        };

        sinks.note(
            self.options.verbose,
            &format!(
                "turn {} is harness turn {harness}; its events carry that id",
                self.report.turn_id
            ),
        );

        self.harness_turn = Some(harness.to_string());
    }

    fn routed(&self, params: Value) -> Value {
        let mut params = params;

        if let (Some(node), Some(fields)) = (self.node.as_deref(), params.as_object_mut()) {
            fields.insert("node".into(), Value::String(node.to_string()));
        }

        params
    }

    // ----- the stream ----------------------------------------------------------------

    /// Drains the session's events until the turn ends, the clock runs out, or the
    /// operator interrupts. Every arm here terminates: there is no branch that waits
    /// forever on anything.
    async fn stream(
        &mut self,
        notifications: &mut mpsc::Receiver<Notification>,
        sinks: &mut Sinks<'_>,
    ) {
        if self.settled.is_some() {
            return;
        }

        let mut signals = interrupts();
        let deadline = tokio::time::Instant::now() + self.options.timeout;
        // Set once an interrupt has been asked for; the run then ends at the turn's own
        // interrupted event or at this bound, whichever comes first.
        let mut grace: Option<tokio::time::Instant> = None;
        let mut seen = 0u32;

        loop {
            if self.settled.is_some() {
                return;
            }

            let ends_at = match grace {
                Some(grace) => grace.min(deadline),
                None => deadline,
            };

            tokio::select! {
                biased;

                Some(()) = signals.recv() => {
                    seen += 1;

                    if seen >= 2 {
                        sinks.warn("interrupted twice; leaving the turn to the runtime");
                        self.report.error.get_or_insert_with(|| {
                            "interrupted twice at the terminal; the turn may still be running \
                             in the runtime".to_string()
                        });
                        self.requested = Some(Status::Interrupted);
                        self.settle(Status::Interrupted);
                        return;
                    }

                    sinks.warn("interrupting the turn");
                    self.requested = Some(Status::Interrupted);
                    self.report.status = Status::Interrupted;
                    self.report.error.get_or_insert_with(|| {
                        "interrupted at the terminal".to_string()
                    });
                    self.interrupt().await;
                    grace = Some(tokio::time::Instant::now() + INTERRUPT_GRACE);
                }

                Some(answered) = self.approvals.join_next(), if !self.approvals.is_empty() => {
                    match answered {
                        Ok(Ok(())) => self.report.approvals_answered += 1,
                        Ok(Err(error)) => sinks.warn(&format!(
                            "answering an approval failed: {}", rendered(&error)
                        )),
                        Err(join) => sinks.warn(&format!("answering an approval panicked: {join}")),
                    }
                }

                notification = notifications.recv() => {
                    let Some(notification) = notification else {
                        // The transport stopped. Whatever the turn is doing, this process
                        // can no longer observe it.
                        self.report.error.get_or_insert_with(|| {
                            "the connection to the runtime closed before the turn ended"
                                .to_string()
                        });
                        self.settle(Status::Lost);
                        return;
                    };

                    self.notification(notification, sinks).await;
                }

                _ = tokio::time::sleep_until(ends_at) => {
                    if grace.is_some() {
                        sinks.warn("the interrupt produced no event in time");
                        self.settle(Status::Lost);
                        return;
                    }

                    sinks.warn(&format!(
                        "the turn exceeded --timeout {}s; interrupting it",
                        self.options.timeout.as_secs()
                    ));
                    self.requested = Some(Status::Timeout);
                    self.report.status = Status::Timeout;
                    self.report.error.get_or_insert_with(|| {
                        format!(
                            "the turn exceeded the {}s ceiling and was interrupted",
                            self.options.timeout.as_secs()
                        )
                    });
                    self.interrupt().await;
                    grace = Some(tokio::time::Instant::now() + INTERRUPT_GRACE);
                }
            }
        }
    }

    async fn notification(&mut self, notification: Notification, sinks: &mut Sinks<'_>) {
        match notification.method.as_str() {
            "interactive.event" => {
                if notification.params.get("id").and_then(Value::as_str)
                    != Some(self.report.session_id.as_str())
                {
                    return;
                }

                let Some(event) = notification.params.get("event") else {
                    return;
                };

                match Event::decode(event) {
                    Ok(event) => self.offer(event, sinks).await,
                    Err(error) => sinks.note(
                        self.options.verbose,
                        &format!("an event this build cannot decode was skipped: {error}"),
                    ),
                }
            }
            "stream.lagged" => {
                let Ok(lagged) = serde_json::from_value::<model::Lagged>(notification.params)
                else {
                    return;
                };

                if lagged.id != self.report.session_id {
                    return;
                }

                sinks.warn(&format!(
                    "the gateway dropped {} event frames; replaying from {}",
                    lagged.dropped, self.cursor
                ));
                self.replay(sinks).await;
            }
            "stream.ended" => {
                let Ok(ended) = serde_json::from_value::<model::Ended>(notification.params) else {
                    return;
                };

                if ended.id != self.report.session_id {
                    return;
                }

                // Whatever the session's own end was, this turn's end was not observed —
                // `turn_completed` would have settled the run before this frame arrived.
                let status = match ended.status.as_str() {
                    "failed" => Status::Failed,
                    "cancelled" => Status::Interrupted,
                    _ => Status::Lost,
                };

                self.report.error.get_or_insert_with(|| {
                    format!(
                        "the event stream for {} ended ({}) before the turn did",
                        ended.id,
                        if ended.status.is_empty() {
                            "no status"
                        } else {
                            &ended.status
                        }
                    )
                });
                self.settle(status);
            }
            other => sinks.note(
                self.options.verbose,
                &format!("a notification this build does not know was ignored: {other}"),
            ),
        }
    }

    /// Takes one event, emits everything that has become contiguous, and repairs a gap.
    async fn offer(&mut self, event: Event, sinks: &mut Sinks<'_>) {
        if event.sequence <= self.cursor {
            // Already printed. Replay windows overlap the live stream by design, and
            // printing an event twice would make the NDJSON a lie about what happened.
            return;
        }

        if self.pending.len() >= MAX_PENDING {
            sinks.warn("more out-of-order events than this run will hold; the stream is ahead");
            return;
        }

        self.pending.insert(event.sequence, event);
        self.drain(sinks);

        if !self.pending.is_empty() && self.settled.is_none() {
            self.replay(sinks).await;
        }
    }

    /// Emits every held event that now sits directly on the cursor.
    ///
    /// Stops at the event that settles the run: a turn that has ended has ended, and the
    /// session's later frames are not this turn's output.
    fn drain(&mut self, sinks: &mut Sinks<'_>) {
        while let Some((&sequence, _)) = self.pending.iter().next() {
            if sequence != self.cursor + 1 || self.settled.is_some() {
                break;
            }

            let event = self.pending.remove(&sequence).expect("the peeked entry");
            self.cursor = sequence;
            self.emit(&event, sinks);
            self.fold(&event, sinks);
        }
    }

    /// `interactive.replay` from the cursor, exactly as the TUI repairs a hole.
    async fn replay(&mut self, sinks: &mut Sinks<'_>) {
        loop {
            self.rounds += 1;

            if self.rounds > MAX_RESYNC_ROUNDS {
                sinks.warn(
                    "this session is producing history faster than `ouro run` can replay it; \
                     the stream keeps its gap",
                );
                return;
            }

            let asked_from = self.cursor;
            let params = self.routed(json!({
                "id": self.report.session_id,
                "cursor": asked_from,
                "limit": REPLAY_LIMIT,
            }));

            let answer = match self.client.call("interactive.replay", params).await {
                Ok(answer) => answer,
                Err(ClientError::Rpc(rpc)) => {
                    match model::CursorPruned::from_error_data(rpc.data.as_ref()) {
                        Some(pruned) if pruned.floor > self.cursor => {
                            sinks.warn(&format!(
                                "{}: the runtime no longer retains history below {}; the \
                                 stream continues there",
                                self.report.session_id, pruned.floor
                            ));
                            self.cursor = pruned.floor;
                            self.drain(sinks);
                            continue;
                        }
                        _ => {
                            sinks.warn(&format!(
                                "replaying {} failed: {}",
                                self.report.session_id,
                                model::refusal(&rpc)
                            ));
                            return;
                        }
                    }
                }
                Err(error) => {
                    sinks.warn(&format!(
                        "replaying {} failed: {}",
                        self.report.session_id,
                        rendered(&error)
                    ));
                    return;
                }
            };

            let count = self.absorb(&answer, asked_from, sinks);

            if self.settled.is_some() || self.pending.is_empty() {
                // This repair is over. The budget is per interruption, not per run: a long
                // session that lags forty separate times has not misbehaved once.
                self.rounds = 0;
                return;
            }

            // Another round only while the last one is still buying ground. A replay that
            // answered nothing new leaves the gap visible rather than looping on it.
            if count == 0 || self.cursor == asked_from {
                sinks.warn(&format!(
                    "{} still has a gap above {}; the stream continues without it",
                    self.report.session_id, self.cursor
                ));
                return;
            }
        }
    }

    /// Absorbs a replay/subscribe answer. Returns how many events it carried.
    ///
    /// Both verbs answer "the retained events after this cursor, in order", so a first
    /// entry above `asked_from + 1` *proves* the ones between are gone — a prune the
    /// gateway had no reason to raise, because the cursor itself was still in the window.
    fn absorb(&mut self, value: &Value, asked_from: u64, sinks: &mut Sinks<'_>) -> usize {
        let (events, refused) = Event::decode_batch(value);

        if refused > 0 {
            sinks.note(
                self.options.verbose,
                &format!("{refused} replayed events this build cannot decode were skipped"),
            );
        }

        if let Some(first) = events.first().map(|event| event.sequence) {
            if first > asked_from + 1 && self.cursor < first - 1 {
                sinks.warn(&format!(
                    "{}: events {}..{} are no longer retained and will not print",
                    self.report.session_id,
                    asked_from + 1,
                    first - 1
                ));
                self.cursor = first - 1;
            }
        }

        let count = events.len();

        for event in events {
            if event.sequence <= self.cursor || self.pending.len() >= MAX_PENDING {
                continue;
            }

            self.pending.insert(event.sequence, event);
        }

        self.drain(sinks);
        count
    }

    /// One event on stdout, byte-for-byte the object the gateway framed.
    fn emit(&self, event: &Event, sinks: &mut Sinks<'_>) {
        if self.options.output != Output::StreamJson {
            return;
        }

        match serde_json::to_string(&event.raw) {
            Ok(line) => sinks.line(&line),
            Err(error) => sinks.warn(&format!("an event could not be re-encoded: {error}")),
        }
    }

    /// Everything the result object is folded from.
    fn fold(&mut self, event: &Event, sinks: &mut Sinks<'_>) {
        if self.report.provider.is_none() {
            self.report.provider = event
                .provider
                .clone()
                .filter(|provider| !provider.is_empty());
        }

        match &event.kind {
            EventType::OutputTextDelta if self.ours(event) => {
                let text = payload_text(&event.payload);

                if !text.is_empty() {
                    let draft = self.draft.get_or_insert_with(String::new);
                    append_bounded(draft, &text, MESSAGE_BYTES);
                }
            }
            EventType::OutputTextFinal if self.ours(event) => {
                let text = payload_text(&event.payload);
                let drafted = self.draft.take().unwrap_or_default();
                let message = if text.is_empty() { drafted } else { text };

                if !message.trim().is_empty() {
                    self.messages.push(message);
                }
            }
            EventType::Usage => fold_usage(&mut self.report.usage, &event.payload),
            EventType::ToolCall if self.ours(event) => self.changed.note_call(&event.payload),
            EventType::ToolResult if self.ours(event) => self.changed.note_result(&event.payload),
            EventType::FileChange => self.changed.note_change(&event.payload),
            EventType::ApprovalRequested => {
                self.report.approvals_requested += 1;
                self.answer_approval(event, sinks);
            }
            EventType::TurnCompleted if self.ours(event) => {
                self.unreconciled = None;
                self.settle(Status::Completed);
            }
            EventType::TurnFailed if self.ours(event) => {
                self.unreconciled = None;
                self.report
                    .error
                    .get_or_insert_with(|| event_detail(&event.payload));
                self.settle(Status::Failed);
            }
            EventType::TurnInterrupted if self.ours(event) => {
                self.unreconciled = None;
                self.report
                    .error
                    .get_or_insert_with(|| event_detail(&event.payload));
                self.settle(Status::Interrupted);
            }
            EventType::SessionFailed => {
                self.report
                    .error
                    .get_or_insert_with(|| event_detail(&event.payload));
                self.settle(Status::Failed);
            }
            EventType::SessionCancelled => {
                self.report
                    .error
                    .get_or_insert_with(|| event_detail(&event.payload));
                self.settle(Status::Interrupted);
            }
            EventType::SessionClosed => {
                // The session ended without this turn ending. Its outcome was not
                // observed, and that is exactly what `lost` means.
                self.report.error.get_or_insert_with(|| {
                    format!(
                        "session {} closed before turn {} ended",
                        self.report.session_id, self.report.turn_id
                    )
                });
                self.settle(Status::Lost);
            }
            _ => {}
        }
    }

    /// Whether an event belongs to the turn this command sent.
    ///
    /// Both identifiers count, because both are this turn's: the caller-minted id the
    /// gateway keys the durable turn on, and the `harness_turn_id` the provider's own
    /// events carry (see [`Self::adopt_harness_turn`]).
    ///
    /// An event with no `turn_id` is accepted — several session-level events carry none.
    /// So is an event whose id this run cannot place *because the reply named no harness
    /// turn*: a session takes one turn at a time, and a headless run's is the one it just
    /// sent. That tolerance is the fallback, not the rule; a runtime that answers with a
    /// `harness_turn_id` gets the exact match instead.
    fn ours(&self, event: &Event) -> bool {
        let Some(turn) = event.turn_id.as_deref() else {
            return true;
        };

        match self.harness_turn.as_deref() {
            Some(harness) => turn == harness || turn == self.report.turn_id,
            None => true,
        }
    }

    /// Settles the run, unless a terminal state was already decided.
    ///
    /// The first terminal event wins: a `session_closed` that follows a `turn_completed`
    /// describes the session's end, not the turn's.
    fn settle(&mut self, status: Status) {
        if self.settled.is_some() {
            return;
        }

        // An end this command asked for keeps its own name. `--timeout` expiring and an
        // operator pressing Ctrl-C are two different facts, and neither of them becomes
        // "the provider stopped on its own" merely because the runtime then confirms the
        // interrupt this command sent it.
        let status = self.requested.unwrap_or(status);

        self.report.status = status;
        self.settled = Some(status);
    }

    fn answer_approval(&mut self, event: &Event, sinks: &mut Sinks<'_>) {
        let Some(request_id) = event.request_id.clone().filter(|id| !id.is_empty()) else {
            sinks.warn("an approval request carried no request id and cannot be answered");
            return;
        };

        let (decision, reason) = if self.options.approve_all {
            (ApprovalDecision::Approve, None)
        } else {
            (ApprovalDecision::Deny, Some(HEADLESS_DENY_REASON))
        };

        sinks.warn(&format!(
            "approval {request_id} answered {} (headless)",
            decision.as_str()
        ));

        let params = self.routed(model::respond_approval_params_with_reason(
            &self.report.session_id,
            &request_id,
            decision,
            ApprovalScope::Once,
            reason,
        ));

        let client = self.client.clone();
        self.approvals.spawn(async move {
            client
                .call("interactive.respond_approval", params)
                .await
                .map(|_value| ())
        });
    }

    async fn interrupt(&self) {
        let params = self.routed(json!({ "id": self.report.session_id }));
        let _ = self
            .client
            .call_with_timeout("interactive.interrupt", params, INTERRUPT_CEILING)
            .await;
    }

    /// Lets an approval answer still on the wire finish, briefly.
    ///
    /// A turn can end while `respond_approval` is in flight, and dropping the task then
    /// would abort a mutation this command already decided to make — and undercount it.
    /// Bounded, because a runtime that never answers must not hold a headless run open.
    async fn settle_approvals(&mut self, sinks: &mut Sinks<'_>) {
        let deadline = tokio::time::Instant::now() + INTERRUPT_CEILING;

        while !self.approvals.is_empty() {
            match tokio::time::timeout_at(deadline, self.approvals.join_next()).await {
                Ok(None) => return,
                Ok(Some(Ok(Ok(())))) => self.report.approvals_answered += 1,
                Ok(Some(Ok(Err(error)))) => sinks.warn(&format!(
                    "answering an approval failed: {}",
                    rendered(&error)
                )),
                Ok(Some(Err(join))) => {
                    sinks.warn(&format!("answering an approval panicked: {join}"))
                }
                Err(_elapsed) => {
                    sinks.warn(
                        "an approval answer had not completed when the turn ended; the result \
                         counts only the ones that did",
                    );
                    return;
                }
            }
        }
    }

    // ----- the answer ------------------------------------------------------------------

    fn finish(mut self, sinks: &mut Sinks<'_>) -> Report {
        // An in-flight draft with no final behind it is still what the agent said.
        if let Some(draft) = self.draft.take() {
            if !draft.trim().is_empty() {
                self.messages.push(draft);
            }
        }

        let mut text = String::new();
        for message in &self.messages {
            if !text.is_empty() {
                text.push('\n');
            }
            append_bounded(&mut text, message, TEXT_BYTES);
        }

        self.report.text = text;
        self.report.files_changed = self.changed.take();
        self.report.duration = self.started_at.elapsed();

        if let Some(unreconciled) = self.unreconciled.take() {
            // The send was never reconciled and no terminal event resolved it. Whatever
            // else this run saw, it did not see this turn end — so `lost`, unless this
            // command is the reason the run stopped, in which case saying so is more use
            // than saying `lost` and the unreconciled sentence still gets told.
            self.report.status = self.requested.unwrap_or(Status::Lost);
            self.report.error = Some(match self.report.error.take() {
                Some(existing) => format!("{unreconciled}; {existing}"),
                None => unreconciled,
            });
        } else if self.settled.is_none() {
            self.report.status = self.requested.unwrap_or(Status::Lost);
            self.report.error.get_or_insert_with(|| {
                format!("turn {} produced no terminal event", self.report.turn_id)
            });
        }

        match self.options.output {
            Output::Text => {
                if !self.report.text.is_empty() {
                    sinks.line(&self.report.text);
                }

                if let Some(error) = &self.report.error {
                    if self.report.status != Status::Completed {
                        let line = format!("{}: {error}", self.report.status.as_str());
                        sinks.warn(&line);
                    }
                }
            }
            Output::Json | Output::StreamJson => {
                match serde_json::to_string(&self.report.to_json()) {
                    Ok(line) => sinks.line(&line),
                    Err(error) => sinks.warn(&format!("the result could not be encoded: {error}")),
                }
            }
        }

        self.report
    }
}

/// A caller-owned turn id for a resumed session, tagged with the surface that minted it.
///
/// A resumed run has no fresh session id to derive one from — that is what `--resume`
/// means — so it mints one, and the `ouro-run-` prefix is what lets a ledger reader tell a
/// headless turn from one somebody typed. OS randomness is the normal path; the
/// process/time/sequence fallback keeps a script working on a platform whose entropy
/// source is briefly unavailable without ever reusing an id inside this process.
fn new_turn_id() -> String {
    use rand::TryRngCore;

    let mut bytes = [0_u8; 16];

    if rand::rngs::OsRng.try_fill_bytes(&mut bytes).is_ok() {
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        return format!("ouro-run-{encoded}");
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let sequence = TURN_ID_FALLBACK_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    format!("ouro-run-{}-{timestamp:x}-{sequence:x}", std::process::id())
}

static TURN_ID_FALLBACK_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// Ctrl-C, as a channel rather than as a future rebuilt on every loop turn.
///
/// `tokio::signal::ctrl_c()` only observes signals that arrive after its listener exists,
/// so a select arm that constructed a fresh one each iteration would have a window — the
/// gap between two events — in which a Ctrl-C is simply lost. One task, listening
/// continuously, has no such gap. The channel holds two because two presses is the whole
/// vocabulary; a third has nothing left to say. The task ends when the receiver drops.
fn interrupts() -> mpsc::Receiver<()> {
    let (sender, receiver) = mpsc::channel(2);

    tokio::spawn(async move {
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                // No handler could be installed. Looping on that would be a spin against
                // an operating system that has already answered.
                return;
            }

            if sender.send(()).await.is_err() {
                return;
            }
        }
    });

    receiver
}

struct SendFailure {
    rendered: String,
    outcome_unknown: bool,
}

/// A successful RPC envelope may still carry a durable turn that is not accepted.
fn turn_failure(value: &Value) -> Option<SendFailure> {
    match model::turn_reply(value) {
        model::TurnReply::Accepted => None,
        model::TurnReply::OutcomeUnknown => Some(SendFailure {
            rendered: model::turn_reply_diagnostic(value),
            outcome_unknown: true,
        }),
        model::TurnReply::Rejected => Some(SendFailure {
            rendered: model::turn_reply_diagnostic(value),
            outcome_unknown: false,
        }),
    }
}

/// A turn-carrying mutation can fail after crossing the dispatch boundary. Typed RPC data
/// decides; every transport failure is indeterminate because the stable turn id may
/// already have reached the runtime.
fn send_outcome_unknown(error: &ClientError) -> bool {
    match error {
        ClientError::Rpc(rpc) => {
            rpc.code == ErrorCode::UpstreamTimeout || model::outcome_unknown(rpc.data.as_ref())
        }
        _ => true,
    }
}

fn rendered(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) => model::refusal(rpc),
        other => other.to_string(),
    }
}

/// Whether a method needs `operate` scope. The four read verbs this command uses are
/// served at `read`; everything else here mutates.
fn method_mutates(method: &str) -> bool {
    !matches!(
        method,
        "interactive.info" | "interactive.list" | "interactive.replay" | "interactive.subscribe"
    )
}

fn payload_text(payload: &Value) -> String {
    payload
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The sentence behind a failure event, or an honest placeholder.
fn event_detail(payload: &Value) -> String {
    for key in ["error", "reason", "message", "detail", "text"] {
        if let Some(value) = payload.get(key).filter(|value| !value.is_null()) {
            let rendered = model::compact(value);

            if !rendered.trim().is_empty() {
                return rendered;
            }
        }
    }

    match payload {
        Value::Object(fields) if fields.is_empty() => "the runtime gave no detail".to_string(),
        Value::Null => "the runtime gave no detail".to_string(),
        other => model::compact(other),
    }
}

/// Folds one `usage` payload into the running totals.
///
/// Usage payloads are *cumulative for the turn* — both CLI mappers emit exactly one at the
/// turn's result, and the Codex app-server dialect forwards a running total — so the newest
/// event's numbers replace the keys it names rather than adding to them. Adding would
/// double a cumulative count; this cannot, and it cannot invent a key the provider never
/// sent. Anything that is not a number is dropped, because the field is called `usage` and
/// a caller summing it must not meet a string.
fn fold_usage(usage: &mut BTreeMap<String, f64>, payload: &Value) {
    let Some(fields) = payload.as_object() else {
        return;
    };

    // A nested `usage`/`token_usage` object is where several providers put the numbers.
    for nested in ["usage", "token_usage", "tokenUsage"] {
        if let Some(inner) = fields.get(nested).filter(|value| value.is_object()) {
            fold_usage(usage, inner);
        }
    }

    for (key, value) in fields {
        let Some(number) = value.as_f64() else {
            continue;
        };

        usage.insert(normalise_key(key), number);
    }

    // The same derivation both mappers perform, applied only when the provider named the
    // parts and not the total.
    if !usage.contains_key("total_tokens") {
        if let (Some(input), Some(output)) = (usage.get("input_tokens"), usage.get("output_tokens"))
        {
            let total = input + output;
            usage.insert("total_tokens".into(), total);
        }
    }
}

/// `inputTokens` and `input_tokens` are the same number with two spellings, and a result
/// object that carried both would be reporting a provider's JSON style as data.
fn normalise_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);

    for (index, character) in key.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 && !out.ends_with('_') {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }

    out
}

/// Every path a `file_change` payload names, in the order it named them.
///
/// Two shapes ship today — `{"diff": …}` for a whole-turn patch and
/// `{"changes": […], "status": …}` for item-level edits — and the generic JSON adapter
/// passes provider records through untouched, so the key list is the tolerant one the
/// transcript already uses rather than a single spelling.
/// The files a run changed, in first-seen order: every path a `file_change` named, plus
/// the target of a well-known write tool once its result came back without an error.
/// Providers whose harness adapter reports no `file_change` — Claude among them — would
/// otherwise finish an edit with `files_changed: []`, which a script reads as "nothing to
/// review". A call is counted on its result, never on its request: a refused or failed
/// write changed nothing.
#[derive(Default)]
struct ChangedFiles {
    order: Vec<String>,
    /// Write tools awaiting their result, by call id.
    pending: BTreeMap<String, Vec<String>>,
}

const MAX_PENDING_WRITES: usize = 64;

/// Tools that write the file they name: the vendors' (Claude Code, Codex, Gemini, the
/// Anthropic editor tool) and this runtime's own. A tool not named here is never inferred
/// to have written anything, whatever its input looks like.
const WRITE_TOOLS: &[&str] = &[
    "Edit",
    "Write",
    "MultiEdit",
    "NotebookEdit",
    "edit",
    "write",
    "apply_patch",
    "write_file",
    "edit_file",
    "create_file",
    "replace",
    "str_replace_based_edit_tool",
    "str_replace_editor",
];

impl ChangedFiles {
    fn note_call(&mut self, payload: &Value) {
        let Some(call_id) = payload.get("call_id").and_then(Value::as_str) else {
            return;
        };

        if self.pending.len() >= MAX_PENDING_WRITES {
            return;
        }

        if let Some(paths) = write_tool_targets(payload) {
            self.pending.insert(call_id.to_string(), paths);
        }
    }

    fn note_result(&mut self, payload: &Value) {
        let Some(call_id) = payload.get("call_id").and_then(Value::as_str) else {
            return;
        };
        let Some(paths) = self.pending.remove(call_id) else {
            return;
        };

        let failed = payload
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || matches!(
                payload.get("status").and_then(Value::as_str),
                Some("failed" | "error" | "errored")
            );

        if !failed {
            for path in paths {
                self.record(path);
            }
        }
    }

    fn note_change(&mut self, payload: &Value) {
        for path in file_paths(payload) {
            self.record(path);
        }
    }

    fn record(&mut self, path: String) {
        if self.order.len() >= MAX_FILES || self.order.iter().any(|held| same_file(held, &path)) {
            return;
        }

        self.order.push(path);
    }

    fn take(&mut self) -> Vec<String> {
        std::mem::take(&mut self.order)
    }
}

/// The files a write tool's call names, or `None` for a tool that is not a write tool.
fn write_tool_targets(payload: &Value) -> Option<Vec<String>> {
    let name = payload.get("name").and_then(Value::as_str)?;

    if !WRITE_TOOLS.contains(&name) {
        return None;
    }

    let input = ["input", "arguments", "args", "params"]
        .iter()
        .find_map(|key| payload.get(key))?;
    let Value::Object(fields) = input else {
        return None;
    };
    let mut paths = Vec::new();

    for key in ["file_path", "path", "notebook_path", "filePath", "file"] {
        if let Some(path) = fields.get(key).and_then(Value::as_str) {
            push_path(path, &mut paths);
        }
    }

    for key in ["patch", "input", "diff"] {
        if let Some(text) = fields.get(key).and_then(Value::as_str) {
            for path in v4a_targets(text) {
                push_path(&path, &mut paths);
            }

            if let Some(path) = Diff::parse(text).path {
                push_path(&path, &mut paths);
            }
        }
    }

    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

/// The files a V4A patch names: `*** Add File:`, `*** Update File:`, `*** Delete File:`,
/// and the destination of a `*** Move to:`.
fn v4a_targets(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            [
                "*** Add File: ",
                "*** Update File: ",
                "*** Delete File: ",
                "*** Move to: ",
            ]
            .iter()
            .find_map(|header| line.strip_prefix(header))
        })
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .collect()
}

fn file_paths(payload: &Value) -> Vec<String> {
    let mut paths = Vec::new();

    collect_paths(payload, &mut paths, 0);

    paths
}

fn collect_paths(value: &Value, paths: &mut Vec<String>, depth: u32) {
    if depth > 4 || paths.len() >= MAX_FILES {
        return;
    }

    match value {
        Value::String(path) => push_path(path, paths),
        Value::Array(items) => {
            for item in items {
                collect_paths(item, paths, depth + 1);
            }
        }
        Value::Object(fields) => {
            for key in ["path", "file", "name", "file_path", "filePath"] {
                if let Some(path) = fields.get(key).and_then(Value::as_str) {
                    push_path(path, paths);
                }
            }

            for key in ["diff", "patch", "delta"] {
                if let Some(text) = fields.get(key).and_then(Value::as_str) {
                    if let Some(path) = Diff::parse(text).path {
                        push_path(&path, paths);
                    }
                }
            }

            for key in ["changes", "files"] {
                if let Some(nested) = fields.get(key) {
                    collect_paths(nested, paths, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn push_path(path: &str, paths: &mut Vec<String>) {
    let path = path.trim();

    if path.is_empty() || paths.len() >= MAX_FILES || paths.iter().any(|held| same_file(held, path))
    {
        return;
    }

    paths.push(path.to_string());
}

/// A `file_change` names its file absolutely and the diff header inside it names the same
/// file relative to the workspace; a result that listed both would count one change as
/// two. Two paths are one file when one is the other, or one ends with the other as a
/// whole path suffix.
fn same_file(held: &str, path: &str) -> bool {
    held == path
        || held
            .strip_suffix(path)
            .is_some_and(|prefix| prefix.ends_with('/'))
        || path
            .strip_suffix(held)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

/// Appends under a ceiling, saying so once rather than growing on a provider's say-so.
fn append_bounded(target: &mut String, text: &str, limit: usize) {
    if target.len() >= limit {
        return;
    }

    let room = limit - target.len();

    if text.len() <= room {
        target.push_str(text);
        return;
    }

    let mut cut = room.saturating_sub(TRUNCATION.len());

    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }

    target.push_str(&text[..cut]);
    target.push_str(TRUNCATION);
}

/// The start request `ouro run` will send, resolved exactly as `ouro new` resolves one.
///
/// Every refusal here happens before anything is mutated, which is why they are all exit
/// 64: nothing started, nothing was billed, and the sentence names the two places the
/// answer could have come from.
pub fn start_plan(
    flags: &crate::config::StartFlags,
    defaults: &crate::config::Defaults,
    config_path: &std::path::Path,
    session_id: String,
    workspace: impl FnOnce(&str, Option<&str>) -> Result<String, String>,
    prompt: String,
) -> Result<Plan, Refusal> {
    let resolved = crate::config::resolve_start(flags, defaults)
        .map_err(|missing| Refusal(missing.message(config_path)))?;
    let machine = resolved.machine.clone().unwrap_or_default();

    let request = StartRequest {
        id: session_id,
        plane: Plane::Interactive,
        provider: resolved.provider.clone(),
        machine: machine.clone(),
        workspace: workspace(&machine, resolved.workspace.as_deref()).map_err(Refusal)?,
        approval_mode: match &resolved.approval_mode {
            None => None,
            Some(name) => Some(model::ApprovalMode::parse(name).ok_or_else(|| {
                Refusal(model::StartError::UnknownApprovalMode(name.clone()).message())
            })?),
        },
        sandbox_mode: match &resolved.sandbox_mode {
            None => None,
            Some(name) => Some(model::SandboxMode::parse(name).ok_or_else(|| {
                Refusal(model::StartError::UnknownSandboxMode(name.clone()).message())
            })?),
        },
        objective: String::new(),
    };

    let params = request
        .params()
        .map_err(|refusal| Refusal(refusal.message()))?;

    if params.get("id").and_then(Value::as_str) != Some(request.id.as_str()) {
        return Err(Refusal(
            "the validated start request did not preserve its stable session id".to_string(),
        ));
    }

    Ok(Plan::Start {
        request,
        params,
        prompt,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_file_named_absolutely_and_relatively_is_one_changed_file() {
        let mut paths = Vec::new();
        super::push_path("/w/ws/lib/a.ex", &mut paths);
        super::push_path("lib/a.ex", &mut paths);
        super::push_path("/w/ws/lib/b.ex", &mut paths);
        // Without the workspace, a bare basename that ends an absolute path held already is
        // taken as that file: diff headers name workspace-relative paths, so the only
        // ambiguity is a root file shadowing a nested one of the same name, and a count is
        // all `files_changed` carries.
        super::push_path("b.ex", &mut paths);
        super::push_path("lib/c.ex", &mut paths);
        assert_eq!(paths, vec!["/w/ws/lib/a.ex", "/w/ws/lib/b.ex", "lib/c.ex"]);
    }

    use super::*;

    fn report() -> Report {
        Report::new("s-1".into(), "ouro-run:s-1".into())
    }

    fn event(kind: &str, sequence: u64, turn: Option<&str>, payload: Value) -> Event {
        let mut raw = json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "payload": payload,
        });

        if let Some(turn) = turn {
            raw["turn_id"] = Value::String(turn.to_string());
        }

        Event::decode(&raw).expect("a decodable event")
    }

    #[test]
    fn the_result_object_omits_what_the_run_never_learned() {
        let mut report = report();
        report.status = Status::Completed;
        report.duration = Duration::from_millis(1234);

        let json = report.to_json();

        assert_eq!(json["type"], "result");
        assert_eq!(json["session_id"], "s-1");
        assert_eq!(json["turn_id"], "ouro-run:s-1");
        assert_eq!(json["status"], "completed");
        assert_eq!(json["duration_ms"], 1234);
        assert_eq!(json["usage"], json!({}));
        assert_eq!(json["files_changed"], json!([]));
        assert_eq!(json["approvals"], json!({ "requested": 0, "answered": 0 }));
        assert!(
            json.get("provider").is_none() && json.get("node").is_none(),
            "a provider this run never learned is not a provider named null: {json}"
        );
        assert!(json.get("error").is_none());
    }

    #[test]
    fn every_status_has_the_documented_exit_code() {
        assert_eq!(Status::Completed.code(), 0);
        assert_eq!(Status::Failed.code(), 1);
        assert_eq!(Status::Interrupted.code(), 2);
        assert_eq!(Status::Lost.code(), 3);
        assert_eq!(Status::Timeout.code(), 4);
        assert_eq!(Exit::USAGE.code(), 64);
    }

    #[test]
    fn usage_folds_the_newest_numbers_and_drops_everything_else() {
        let mut usage = BTreeMap::new();

        fold_usage(
            &mut usage,
            &json!({ "input_tokens": 10, "output_tokens": 4, "model": "sonnet" }),
        );

        assert_eq!(usage.get("input_tokens"), Some(&10.0));
        assert_eq!(usage.get("output_tokens"), Some(&4.0));
        // Derived exactly as both CLI mappers derive it, and only when absent.
        assert_eq!(usage.get("total_tokens"), Some(&14.0));
        assert!(
            !usage.contains_key("model"),
            "usage carries numbers; a caller summing it must not meet a string"
        );

        // Cumulative, so the newer event replaces rather than adds.
        fold_usage(
            &mut usage,
            &json!({ "input_tokens": 25, "output_tokens": 9, "total_tokens": 34 }),
        );

        assert_eq!(usage.get("input_tokens"), Some(&25.0));
        assert_eq!(usage.get("total_tokens"), Some(&34.0));
    }

    #[test]
    fn usage_reads_camel_case_and_nested_shapes_as_the_same_numbers() {
        let mut usage = BTreeMap::new();

        fold_usage(
            &mut usage,
            &json!({ "usage": { "inputTokens": 7, "outputTokens": 3 } }),
        );

        assert_eq!(usage.get("input_tokens"), Some(&7.0));
        assert_eq!(usage.get("output_tokens"), Some(&3.0));
        assert_eq!(usage.get("total_tokens"), Some(&10.0));
    }

    #[test]
    fn whole_counts_stay_integers_on_the_wire() {
        let mut report = report();
        report.usage.insert("total_tokens".into(), 14.0);
        report.usage.insert("cost_usd".into(), 0.5);

        let json = report.to_json();

        assert_eq!(json["usage"]["total_tokens"], json!(14));
        assert_eq!(json["usage"]["cost_usd"], json!(0.5));
    }

    #[test]
    fn file_changes_are_read_from_both_shapes_that_ship() {
        assert_eq!(
            file_paths(&json!({ "changes": [{ "path": "lib/a.ex" }, { "path": "lib/b.ex" }] })),
            vec!["lib/a.ex".to_string(), "lib/b.ex".to_string()]
        );

        assert_eq!(
            file_paths(&json!({
                "diff": "diff --git a/tui/src/run.rs b/tui/src/run.rs\n+++ b/tui/src/run.rs\n+one\n"
            })),
            vec!["tui/src/run.rs".to_string()]
        );

        assert!(file_paths(&json!({ "status": "completed" })).is_empty());
    }

    #[test]
    fn a_path_named_twice_is_one_changed_file() {
        assert_eq!(
            file_paths(&json!({ "path": "a.ex", "changes": [{ "file": "a.ex" }] })),
            vec!["a.ex".to_string()]
        );
    }

    #[test]
    fn a_bounded_append_says_it_truncated_rather_than_growing() {
        let mut text = String::new();
        append_bounded(&mut text, &"x".repeat(100), 32);

        assert!(text.len() <= 32, "{} bytes", text.len());
        assert!(text.ends_with(TRUNCATION.trim_end()) || text.contains("truncated"));
    }

    #[test]
    fn an_event_without_a_turn_id_belongs_to_the_one_turn_in_flight() {
        let decided = event("session_closed", 3, None, json!({}));
        let ours = event("turn_completed", 4, Some("ouro-run:s-1"), json!({}));
        let theirs = event("turn_completed", 5, Some("someone-else"), json!({}));

        assert!(decided.turn_id.is_none());
        assert_eq!(ours.turn_id.as_deref(), Some("ouro-run:s-1"));
        assert_eq!(theirs.turn_id.as_deref(), Some("someone-else"));
    }

    #[test]
    fn a_failure_event_keeps_the_runtimes_own_sentence() {
        assert_eq!(
            event_detail(&json!({ "error": "the provider exited 1" })),
            "the provider exited 1"
        );
        assert_eq!(event_detail(&json!({})), "the runtime gave no detail");
    }

    #[test]
    fn only_the_read_verbs_are_exempt_from_operate_scope() {
        assert!(!method_mutates("interactive.info"));
        assert!(!method_mutates("interactive.subscribe"));
        assert!(!method_mutates("interactive.replay"));
        assert!(method_mutates("interactive.start"));
        assert!(method_mutates("interactive.send_message"));
        assert!(method_mutates("interactive.follow_up"));
        assert!(method_mutates("interactive.respond_approval"));
        assert!(method_mutates("interactive.interrupt"));
    }

    #[test]
    fn a_refusal_is_an_error_object_on_stdout_too() {
        let refusal = Refusal("no provider was named".into());

        assert_eq!(
            refusal.to_json(),
            json!({ "type": "error", "error": "no provider was named" })
        );
    }

    #[test]
    fn a_write_tool_counts_its_file_once_the_result_is_not_an_error() {
        let mut changed = super::ChangedFiles::default();

        changed.note_call(&json!({
            "call_id": "c1", "name": "Edit",
            "input": { "file_path": "/w/ws/main.c", "old_string": "a", "new_string": "b" }
        }));
        changed.note_call(&json!({
            "call_id": "c2", "name": "Write",
            "input": { "file_path": "/w/ws/refused.c", "content": "" }
        }));
        changed.note_call(&json!({
            "call_id": "c3", "name": "Read",
            "input": { "file_path": "/w/ws/read.c" }
        }));
        changed.note_call(&json!({
            "call_id": "c4", "name": "Write",
            "input": { "file_path": "/w/ws/failed.c", "content": "" }
        }));
        changed.note_call(&json!({
            "call_id": "c5", "name": "NotebookEdit",
            "input": { "notebook_path": "/w/ws/never-answered.ipynb" }
        }));

        changed.note_result(&json!({ "call_id": "c1", "is_error": false, "output": "ok" }));
        changed.note_result(&json!({ "call_id": "c2", "is_error": true, "output": "refused" }));
        changed.note_result(&json!({ "call_id": "c3", "is_error": false, "output": "..." }));
        changed.note_result(&json!({ "call_id": "c4", "status": "failed" }));

        // Only the edit that succeeded: the refused write, the failed one, the read, and
        // the call whose result never arrived all changed nothing.
        assert_eq!(changed.take(), vec!["/w/ws/main.c"]);
    }

    #[test]
    fn a_file_change_and_the_edit_that_caused_it_are_one_file() {
        let mut changed = super::ChangedFiles::default();

        changed.note_call(&json!({
            "call_id": "c1", "name": "edit", "input": { "path": "/w/ws/lib/a.ex" }
        }));
        changed.note_result(&json!({ "call_id": "c1", "is_error": false }));
        changed
            .note_change(&json!({ "changes": [{ "path": "lib/a.ex" }, { "path": "lib/b.ex" }] }));

        assert_eq!(changed.take(), vec!["/w/ws/lib/a.ex", "lib/b.ex"]);
    }

    #[test]
    fn a_v4a_patch_names_every_file_it_touches() {
        let targets = super::write_tool_targets(&json!({
            "call_id": "c1", "name": "apply_patch",
            "input": { "patch": "*** Begin Patch\n*** Update File: lib/a.ex\n*** Move to: lib/b.ex\n@@\n-x\n+y\n*** Add File: lib/c.ex\n+1\n*** Delete File: lib/d.ex\n*** End Patch\n" }
        }));

        assert_eq!(
            targets,
            Some(vec![
                "lib/a.ex".to_string(),
                "lib/b.ex".to_string(),
                "lib/c.ex".to_string(),
                "lib/d.ex".to_string()
            ])
        );
        assert_eq!(
            super::write_tool_targets(
                &json!({ "call_id": "c", "name": "Bash", "input": { "command": "rm x" } })
            ),
            None
        );
    }
}
