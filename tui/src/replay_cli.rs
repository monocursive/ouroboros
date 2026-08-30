//! `ouro replay` and `ouro fork`: the client half of deterministic re-execution.
//!
//! Two verbs, one module, because they are two halves of one feature (docs/REPLAY.md §0):
//! **replay** re-reads a session against its record and executes nothing, and **fork**
//! branches at a decision point and substitutes — a different model, a live continuation.
//! Re-calling the model is always a fork and never a replay, and this module keeps the
//! words that far apart on purpose.
//!
//! ## What `ouro replay` actually does
//!
//! Nothing is re-derived here. The client asks the runtime two questions and prints the
//! answers:
//!
//! 1. `interactive.journal` — the hash-chained record of what each turn was derived from.
//!    That becomes the **provenance header**: how many records exist, what the chain head
//!    is, how far it verifies, what the budget dropped, and one row per model call.
//! 2. `interactive.replay` — the existing gap-repair fetch, paged by cursor exactly as
//!    [`crate::run`] and the TUI page it. The events go through [`Event::decode`] into a
//!    [`Watch`], and the watch through [`export::transcript`].
//!
//! **The transcript is the same projection the terminal draws.** Not a second renderer
//! with its own opinions: `Watch::absorb` + `export::transcript` is the offline path the
//! live pane also takes, which is what makes "`ouro replay` twice, and equal to the live
//! client's export at the same width" a property worth asserting rather than a
//! coincidence.
//!
//! ## Deterministic, and that is the whole contract
//!
//! Nothing in this module reads the clock, the environment, or the terminal. Every instant
//! printed came out of a record. `--width` therefore defaults to a fixed 100 columns
//! rather than to the terminal's: a default that varied by window would make two runs on
//! two machines differ for a reason that has nothing to do with the session.
//!
//! ## Which stream carries what
//!
//! The [`crate::ledger_cli`] posture: **stdout carries only the answer.** In the human
//! rendering the provenance header, the verdict, and the transcript are all the answer, so
//! all three go to stdout and only completeness warnings go to stderr. Under `--json`
//! stdout is a machine stream — the raw journal records and then the raw events — so the
//! header and the verdict move to stderr, where they cannot corrupt a pipe.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use crate::model::{
    self, sorted_json, Event, Journal, JournalRecord, Plane, ReplayVerdict, StartedRef,
};
use crate::proto::ErrorCode;
use crate::transport::{Client, ClientError};
use crate::ui::export;
use crate::ui::transcript::Watch;

/// The journal window verb (docs/REPLAY.md §7.1). `read` scope: it reads one file.
pub const JOURNAL_METHOD: &str = "interactive.journal";

/// The **existing** gap-repair fetch, reused verbatim. It is not renamed and not
/// repurposed: `interactive.replay` has meant "the retained events after this cursor" since
/// long before this feature, and the whole point of the offline render is that it needs no
/// new event verb.
pub const EVENTS_METHOD: &str = "interactive.replay";

/// The verify engine's verb. Built by another slice; this client codes against the
/// published reply shape and degrades legibly where it is not served.
pub const VERIFY_METHOD: &str = "interactive.replay_verify";

/// The branch verb, which already ships. `--at`/`--model` are the new params.
pub const FORK_METHOD: &str = "interactive.fork";

/// The gateway bounds both windows at 500. Asking for its ceiling costs the fewest
/// round-trips on a long session.
const PAGE: u64 = 500;

/// A ceiling on paging, so a session producing history faster than this command reads it
/// ends with a stated bound rather than a loop.
const MAX_PAGES: usize = 2_000;

/// How much of a digest a header shows. The whole 64 is unreadable at a glance and twelve
/// is enough to compare two runs by eye.
const DIGEST: usize = 12;

/// The default render measure. Fixed rather than the terminal's — see the module note.
pub const DEFAULT_WIDTH: usize = 100;

/// What `ouro replay`'s flags said.
#[derive(Debug, Clone)]
pub struct Options {
    /// The session to replay.
    pub session: String,
    /// The machine that owns it. Omitted, the one this command reached.
    pub node: Option<String>,
    /// Also ask the engine to re-derive the session and render its verdict.
    pub verify: bool,
    /// Machine output: the raw journal records and the raw events, on stdout.
    pub json: bool,
    /// The measure the transcript wraps prose at.
    pub width: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            session: String::new(),
            node: None,
            verify: false,
            json: false,
            width: DEFAULT_WIDTH,
        }
    }
}

impl Options {
    /// One page of `interactive.journal`.
    pub fn journal_params(&self, since_seq: u64) -> Value {
        let mut params = Map::new();
        params.insert("id".into(), json!(self.session));

        if since_seq > 0 {
            params.insert("since_seq".into(), json!(since_seq));
        }

        params.insert("limit".into(), json!(PAGE));
        self.route(&mut params);
        Value::Object(params)
    }

    /// One page of the existing gap-repair fetch.
    pub fn events_params(&self, cursor: u64) -> Value {
        let mut params = Map::new();
        params.insert("id".into(), json!(self.session));

        if cursor > 0 {
            params.insert("cursor".into(), json!(cursor));
        }

        params.insert("limit".into(), json!(PAGE));
        self.route(&mut params);
        Value::Object(params)
    }

    /// `interactive.replay_verify` takes the session and the routing node and nothing else.
    pub fn verify_params(&self) -> Value {
        let mut params = Map::new();
        params.insert("id".into(), json!(self.session));
        self.route(&mut params);
        Value::Object(params)
    }

    /// The owner node travels on every call or on none. A session read from one machine
    /// and verified on another would be two different questions.
    fn route(&self, params: &mut Map<String, Value>) {
        if let Some(node) = self
            .node
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            params.insert("node".into(), json!(node));
        }
    }
}

/// What the verify verb answered, or why it could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    Verdict(Box<ReplayVerdict>),
    /// The runtime refused, in its own words. A refusal is part of the answer — an
    /// operator who asked `--verify` is owed the reason, not a silent omission.
    Refused(String),
}

/// Asks, then writes. `out` gets the answer and `notes` gets everything about how complete
/// it is.
pub async fn run<O: Write, N: Write>(
    client: &Client,
    options: &Options,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let mut warnings = Vec::new();

    let journal = read_journal(client, options, &mut warnings).await?;

    // Asked before the events are paged so the verdict can sit in the header, which is
    // where a reader looks for "should I trust the transcript below this line".
    let verify = if options.verify {
        Some(read_verdict(client, options).await)
    } else {
        None
    };

    let watch = read_events(client, options, &mut warnings).await?;

    let provenance = render_provenance(options, &journal, verify.as_ref());

    if options.json {
        // stdout is a pipe here, so the header and the verdict go where the warnings go.
        out.write_all(render_json(&journal, &watch).as_bytes())?;
        notes.write_all(provenance.as_bytes())?;
    } else {
        out.write_all(provenance.as_bytes())?;
        out.write_all(export::transcript(&watch, options.width).as_bytes())?;
    }

    out.flush()?;

    for warning in warnings {
        writeln!(notes, "ouro replay: {warning}")?;
    }

    notes.flush()?;
    Ok(())
}

/// Pages `interactive.journal` from the first record until the window stops advancing.
async fn read_journal(
    client: &Client,
    options: &Options,
    warnings: &mut Vec<String>,
) -> Result<Journal> {
    let mut whole = Journal::default();
    let mut since_seq = 0_u64;

    for page in 0..MAX_PAGES {
        let answer = client
            .call(JOURNAL_METHOD, options.journal_params(since_seq))
            .await
            .map_err(|error| refusal(JOURNAL_METHOD, &error))?;

        let window = Journal::decode(&answer);

        // Chain facts are about the whole journal, not about this window, so the newest
        // answer wins and an older page never un-states one.
        whole.count = window.count.or(whole.count);
        whole.head = window.head.clone().or(whole.head);
        whole.head_seq = window.head_seq.or(whole.head_seq);
        whole.verified_through = window.verified_through.or(whole.verified_through);
        whole.truncated_through = window.truncated_through.or(whole.truncated_through);

        let Some(newest) = window.newest_seq() else {
            break;
        };

        whole.records.extend(window.records);

        if newest <= since_seq {
            // The window did not advance. Stopping is the only thing that terminates.
            break;
        }

        since_seq = newest;

        if page + 1 == MAX_PAGES {
            warnings.push(format!(
                "the journal is longer than {} pages of {PAGE}; the provenance above covers \
                 records up to sequence {since_seq} and no further",
                MAX_PAGES
            ));
        }
    }

    // A window is a window: the runtime's own count is the whole file's, and a disagreement
    // with what was read is a fact about this read.
    whole.records.sort_by_key(|record| record.seq);
    whole.records.dedup_by_key(|record| record.seq);

    Ok(whole)
}

/// Pages the gap-repair verb into an offline [`Watch`], the same absorb the pane uses.
async fn read_events(
    client: &Client,
    options: &Options,
    warnings: &mut Vec<String>,
) -> Result<Watch> {
    let mut watch = Watch::new(Plane::Interactive, options.session.clone());
    let mut cursor = 0_u64;

    for _page in 0..MAX_PAGES {
        let asked_from = cursor;

        let answer = match client
            .call(EVENTS_METHOD, options.events_params(asked_from))
            .await
        {
            Ok(answer) => answer,
            Err(ClientError::Rpc(rpc)) => {
                // The runtime no longer retains history below its floor. That is a bound
                // on this replay, recorded as one, and the read continues above it.
                match model::CursorPruned::from_error_data(rpc.data.as_ref()) {
                    Some(pruned) if pruned.floor > cursor => {
                        warnings.push(format!(
                            "the runtime no longer retains events at or below {}; the \
                             transcript starts above them",
                            pruned.floor
                        ));
                        watch.raise_floor(pruned.floor);
                        cursor = pruned.floor;
                        continue;
                    }
                    _ => {
                        return Err(anyhow!(
                            "{EVENTS_METHOD} was refused: {}",
                            model::refusal(&rpc)
                        ))
                    }
                }
            }
            Err(error) => return Err(refusal(EVENTS_METHOD, &error)),
        };

        let (events, refused) = Event::decode_batch(&answer);

        if refused > 0 {
            watch.undecodable += refused;
        }

        // Both this verb and `subscribe` answer "the retained events after this cursor, in
        // order", so a first entry above `asked_from + 1` proves the ones between are gone.
        if let Some(first) = events.first().map(|event| event.sequence) {
            if first > asked_from + 1 {
                watch.raise_floor(first - 1);
            }
        }

        let newest = events.last().map(|event| event.sequence);
        watch.absorb(events);

        match newest {
            // The one case that continues: the window carried ground this walk had not
            // already covered.
            Some(newest) if newest > cursor => cursor = newest,
            // Empty, or entirely at or below the cursor it was asked from. Both are the
            // end of the history the runtime retains, and neither is worth a second round.
            _ => break,
        }
    }

    Ok(watch)
}

/// Asks the engine for its verdict, keeping a refusal as an answer rather than an abort.
///
/// **This path is coded against docs/REPLAY.md §7.1 and is not exercised against a live
/// engine**, because the verb is built by another slice. Which is exactly why a runtime
/// that does not serve it produces a sentence rather than a stack of `-32601`.
async fn read_verdict(client: &Client, options: &Options) -> Verify {
    match client.call(VERIFY_METHOD, options.verify_params()).await {
        Ok(answer) => Verify::Verdict(Box::new(ReplayVerdict::decode(&answer))),
        Err(ClientError::Rpc(rpc)) if rpc.code == ErrorCode::MethodNotFound => Verify::Refused(
            format!("this runtime does not serve {VERIFY_METHOD} yet, so nothing was verified"),
        ),
        Err(ClientError::Rpc(rpc)) => Verify::Refused(model::refusal(&rpc)),
        Err(error) => Verify::Refused(error.to_string()),
    }
}

/// The provenance header: what the record says about itself, before a word of transcript.
pub fn render_provenance(options: &Options, journal: &Journal, verify: Option<&Verify>) -> String {
    let mut text = String::new();

    let _ = writeln!(text, "replay {}", options.session);

    if journal.records.is_empty() && journal.head.is_none() {
        let _ = writeln!(
            text,
            "  no journal: this session predates the turn journal, or its provider never \
             wrote one. Nothing below is verifiable."
        );
        let _ = writeln!(text);
        return text;
    }

    let _ = writeln!(text, "  records read      {}", journal.records.len());

    // Only where the two disagree. Equal numbers said twice is noise; unequal ones are the
    // difference between a window and a file.
    if let Some(count) = journal
        .count
        .filter(|count| *count as usize != journal.records.len())
    {
        let _ = writeln!(text, "  runtime count     {count}");
    }

    let _ = writeln!(
        text,
        "  chain head        {}{}",
        JournalRecord::digest_prefix(journal.head.as_deref(), DIGEST),
        match journal.head_seq {
            Some(seq) => format!(" (seq {seq})"),
            None => String::new(),
        }
    );

    let _ = writeln!(
        text,
        "  verified through  {}",
        match (journal.verified_through, journal.head_seq) {
            (Some(verified), Some(head)) if verified >= head => format!("{verified} of {head}"),
            (Some(verified), Some(head)) =>
                format!("{verified} of {head} — the chain above {verified} is not verified"),
            (Some(verified), None) => verified.to_string(),
            (None, _) => "the runtime did not say".to_string(),
        }
    );

    if let Some(through) = journal.truncated_through {
        let _ = writeln!(
            text,
            "  truncated         everything at or below seq {through} was dropped by the \
             journal budget and cannot be replayed"
        );
    }

    for notice in record_notices(&journal.records) {
        let _ = writeln!(text, "  {notice}");
    }

    let _ = writeln!(text);
    model_calls(&mut text, &journal.records);

    if let Some(verify) = verify {
        let _ = writeln!(text);
        verdict(&mut text, verify);
    }

    let _ = writeln!(text);
    text
}

/// The `gap` and `truncated` records, as sentences. A journal that lost a write says so in
/// its own record vocabulary, and dropping those rows would be the one omission that makes
/// the rest of this header a lie.
fn record_notices(records: &[JournalRecord]) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| match record.kind.as_str() {
            "gap" => Some(format!(
                "gap at seq {}: {}",
                record.seq,
                record
                    .reason
                    .as_deref()
                    .unwrap_or("the runtime did not say why")
            )),
            "truncated" => Some(format!(
                "truncation record at seq {}: everything through {} was dropped from a chain \
                 that headed at {}",
                record.seq,
                record
                    .dropped_through_seq
                    .map(|seq| seq.to_string())
                    .unwrap_or_else(|| "an unstated sequence".to_string()),
                JournalRecord::digest_prefix(record.prior_head.as_deref(), DIGEST)
            )),
            _ => None,
        })
        .collect()
}

/// One row per model call: which pass, which model, which request, which journal sequence.
///
/// The model is resolved from the `turn_started` record of the same turn, because §3.2 puts
/// `model_spec` there and not on the call. A call whose turn is outside this window prints
/// a dash rather than the session's default — this client does not know which model ran a
/// turn it did not read.
fn model_calls(text: &mut String, records: &[JournalRecord]) {
    let models = models_by_turn(records);
    let calls: Vec<&JournalRecord> = records
        .iter()
        .filter(|record| record.is_model_call())
        .collect();

    if calls.is_empty() {
        let _ = writeln!(text, "  model calls       none in the journal read");
        return;
    }

    let _ = writeln!(text, "  model calls ({})", calls.len());

    let model_of = |record: &JournalRecord| -> String {
        record
            .model_spec
            .clone()
            .or_else(|| {
                record
                    .turn_id
                    .as_deref()
                    .and_then(|turn| models.get(turn).cloned())
            })
            .unwrap_or_else(|| "—".to_string())
    };

    let width = calls
        .iter()
        .map(|call| model_of(call).chars().count())
        .max()
        .unwrap_or(0)
        .max("model".len());

    let _ = writeln!(
        text,
        "    {:>6}  {:>9}  {:<width$}  request",
        "seq", "iteration", "model"
    );

    for call in calls {
        let _ = writeln!(
            text,
            "    {:>6}  {:>9}  {:<width$}  {}",
            call.seq,
            call.iteration
                .map(|iteration| iteration.to_string())
                .unwrap_or_else(|| "—".to_string()),
            model_of(call),
            JournalRecord::digest_prefix(call.request_sha256.as_deref(), DIGEST)
        );
    }
}

/// `turn_id` → the model spec that turn was started on.
fn models_by_turn(records: &[JournalRecord]) -> BTreeMap<String, String> {
    let mut models = BTreeMap::new();

    for record in records {
        if let (Some(turn), Some(model)) = (record.turn_id.as_deref(), record.model_spec.as_deref())
        {
            models.insert(turn.to_string(), model.to_string());
        }
    }

    models
}

/// The verdict, or the named divergence, or the refusal — whichever the engine gave.
fn verdict(text: &mut String, verify: &Verify) {
    match verify {
        Verify::Refused(reason) => {
            let _ = writeln!(text, "  verify            not answered: {reason}");
        }
        Verify::Verdict(verdict) => {
            let scope = match (verdict.turns, verdict.records) {
                (Some(turns), Some(records)) => {
                    format!(" · {turns} turn(s), {records} record(s)")
                }
                (Some(turns), None) => format!(" · {turns} turn(s)"),
                (None, Some(records)) => format!(" · {records} record(s)"),
                (None, None) => String::new(),
            };

            match verdict.verified {
                Some(true) => {
                    let _ = writeln!(text, "  verify            verified{scope}");
                }
                // A divergence is a finding about a record or about the code, never a
                // reason to keep going quietly, so it is spelled out field by field. A
                // boundary is neither: the record itself bounds what could be verified,
                // and calling that DIVERGED would accuse an honest record.
                Some(false) | None => {
                    let bounded = verdict
                        .divergence
                        .as_ref()
                        .is_some_and(super::model::ReplayDivergence::boundary);
                    let _ = writeln!(
                        text,
                        "  verify            {}{scope}",
                        match (verdict.verified, bounded) {
                            (Some(false), true) =>
                                "bounded — prefix verified, remainder unverifiable",
                            (Some(false), false) => "DIVERGED",
                            _ => "the runtime returned no verdict",
                        }
                    );
                }
            }

            if let Some(head) = verdict.head.as_deref() {
                let _ = writeln!(
                    text,
                    "  verified head     {}",
                    JournalRecord::digest_prefix(Some(head), DIGEST)
                );
            }

            if let Some(divergence) = verdict.divergence.as_ref() {
                let seq = divergence
                    .seq
                    .map(|seq| seq.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let turn = divergence
                    .turn_id
                    .as_deref()
                    .map(|turn| format!(" of turn {turn}"))
                    .unwrap_or_default();
                if divergence.boundary() {
                    // A boundary names itself and carries no digest pair — printing
                    // placeholder dashes for digests it never claimed would dress the
                    // boundary up as a mismatch.
                    let _ = writeln!(
                        text,
                        "  boundary          {} at seq {seq}{turn}{}",
                        divergence.reason.as_deref().unwrap_or("unnamed"),
                        divergence
                            .detail
                            .as_deref()
                            .map(|detail| format!(" ({detail})"))
                            .unwrap_or_default()
                    );
                } else {
                    let _ = writeln!(
                        text,
                        "  divergence        {} at seq {seq}{turn}",
                        divergence.field.as_deref().unwrap_or("an unnamed field"),
                    );
                    let _ = writeln!(
                        text,
                        "  expected          {}",
                        JournalRecord::digest_prefix(divergence.expected_sha256.as_deref(), DIGEST)
                    );
                    let _ = writeln!(
                        text,
                        "  got               {}",
                        JournalRecord::digest_prefix(divergence.got_sha256.as_deref(), DIGEST)
                    );
                }
            }
        }
    }
}

/// The machine stream: the journal's own records, then the session's own events.
///
/// Both halves are written exactly as the runtime sent them, with keys sorted so two runs
/// produce the same bytes ([`sorted_json`] — the reason [`export::events_ndjson`] does the
/// same). The two are told apart by their own shapes: a journal record carries `seq` and
/// `kind`, an event carries `sequence` and `type`. Nothing is wrapped in an envelope of
/// this client's invention, because the point of `--json` is to diff the records rather
/// than to diff this build's reading of them.
pub fn render_json(journal: &Journal, watch: &Watch) -> String {
    let mut text = String::new();

    for record in &journal.records {
        if let Ok(line) = serde_json::to_string(&sorted_json(&record.raw)) {
            text.push_str(&line);
            text.push('\n');
        }
    }

    text.push_str(&export::events_ndjson(watch));
    text
}

// ----- `ouro fork` -------------------------------------------------------------------

/// What `ouro fork`'s flags said, plus the child id this client minted before calling.
#[derive(Debug, Clone, Default)]
pub struct ForkOptions {
    /// The parent session.
    pub session: String,
    /// The machine that owns it.
    pub node: Option<String>,
    /// **Minted before the mutation**, so a lost reply can only ever adopt the same child.
    pub fork_id: String,
    /// `--at`: the turn to branch at. Sent as `to_turn` only when given.
    pub at: Option<String>,
    /// `--model`: the model the child runs on. Sent only when given.
    pub model: Option<String>,
}

impl ForkOptions {
    /// The params `interactive.fork` is called with.
    ///
    /// **An absent flag is an absent key.** The envelope is closed, so a client that always
    /// sent `to_turn: null` would turn every plain fork into a `-32602` against a runtime
    /// that has not grown the param yet — and the two new params are being added by another
    /// slice, so "has not grown it yet" is the common case for now.
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("id".into(), json!(self.session));
        params.insert("fork_id".into(), json!(self.fork_id));

        if let Some(node) = self
            .node
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            params.insert("node".into(), json!(node));
        }

        if let Some(at) = self
            .at
            .as_deref()
            .map(str::trim)
            .filter(|at| !at.is_empty())
        {
            // The runtime types a turn target as a turn id (string) or a non-negative
            // ordinal (integer). All digits sent as a string falls into the turn-id
            // lookup and misses — `unknown_turn` on a perfectly good ordinal — so
            // digits become the integer the server means. Live-found: `--at 1` was
            // refused while `to_turn: 1` was accepted.
            match at.parse::<u64>() {
                Ok(ordinal) => params.insert("to_turn".into(), json!(ordinal)),
                Err(_) => params.insert("to_turn".into(), json!(at)),
            };
        }

        if let Some(model) = self
            .model
            .as_deref()
            .map(str::trim)
            .filter(|model| !model.is_empty())
        {
            params.insert("model".into(), json!(model));
        }

        Value::Object(params)
    }

    /// Whether this call carries a param the shipped envelope may not know.
    fn asks_for_new_params(&self) -> bool {
        let params = self.params();
        params.get("to_turn").is_some() || params.get("model").is_some()
    }

    /// Which flags those were, for the sentence an older runtime earns.
    fn new_flags(&self) -> String {
        let params = self.params();

        match (
            params.get("to_turn").is_some(),
            params.get("model").is_some(),
        ) {
            (true, true) => "--at and --model".to_string(),
            (true, false) => "--at".to_string(),
            _ => "--model".to_string(),
        }
    }
}

/// Branches a session and prints the child.
///
/// The `ouro new` discipline, unchanged: the id exists before the mutation, and a failure
/// whose outcome the transport cannot rule out is retried **once with the exact same id**
/// before the operator is asked to go and look. A fork creates a durable session and bills
/// a workspace; retrying it under a fresh id is how a client silently makes two.
pub async fn fork<O: Write, N: Write>(
    client: &Client,
    options: &ForkOptions,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let params = options.params();

    let answered = match client.call(FORK_METHOD, params.clone()).await {
        Ok(answer) => answer,
        Err(first) => {
            if let Some(refusal) = unsupported_params(options, &first) {
                return Err(anyhow!("{refusal}"));
            }

            if !model::start_outcome_unknown(&first) {
                return Err(anyhow!("{FORK_METHOD} was refused: {}", rendered(&first)));
            }

            writeln!(
                notes,
                "ouro fork: {FORK_METHOD} did not answer definitely; retrying once with the \
                 same child id {}",
                options.fork_id
            )?;
            notes.flush()?;

            match client.call(FORK_METHOD, params).await {
                Ok(answer) => answer,
                Err(retry) => {
                    return Err(anyhow!(
                        "{}",
                        model::ambiguous_mutation(
                            FORK_METHOD,
                            &options.fork_id,
                            &rendered(&first),
                            &rendered(&retry),
                            model::start_outcome_unknown(&retry),
                        )
                    ))
                }
            }
        }
    };

    out.write_all(render_fork(options, &answered)?.as_bytes())?;
    out.flush()?;
    notes.flush()?;
    Ok(())
}

/// The child, as the runtime answered it.
pub fn render_fork(options: &ForkOptions, answer: &Value) -> Result<String> {
    let Some(child) = StartedRef::decode(answer) else {
        return Err(anyhow!(
            "{FORK_METHOD} answered child {} with a reference this build cannot read: {answer}",
            options.fork_id
        ));
    };

    // The identity contract is the whole reason the id was minted here. A different id back
    // means the retry above could have adopted something else, so it is a refusal.
    if child.id != options.fork_id {
        return Err(anyhow!(
            "asked {FORK_METHOD} for child {} and the runtime answered {}; refusing to report a \
             session this client did not name",
            options.fork_id,
            child.id
        ));
    }

    let mut text = String::new();
    let _ = writeln!(text, "forked {} → {}", options.session, child.id);

    if let Some(node) = child.node.as_deref() {
        let _ = writeln!(text, "  node    {node}");
    }

    let ready = answer.get("ready").and_then(Value::as_bool);
    let _ = writeln!(
        text,
        "  ready   {}",
        match ready {
            Some(true) => "yes".to_string(),
            Some(false) => "no".to_string(),
            None => "the runtime did not say".to_string(),
        }
    );

    // A durable child that did not become ready is addressable and broken, which is two
    // facts an operator needs and not one.
    if let Some(failure) = child.start_failure.as_deref() {
        let _ = writeln!(text, "  error   {failure}");
    } else if ready == Some(false) {
        if let Some(error) = answer.get("error").filter(|error| !error.is_null()) {
            let _ = writeln!(text, "  error   {}", model::compact(error));
        }
    }

    if options.at.is_some() || options.model.is_some() {
        let _ = writeln!(
            text,
            "  asked   {} — what the branch actually carries is the runtime's to say",
            options.new_flags()
        );
    }

    Ok(text)
}

/// A `-32602` on a call that carried `to_turn`/`model` is almost certainly a runtime whose
/// fork envelope predates them, and saying `invalid_params` at an operator who just typed
/// `--at` is the least useful true sentence available.
fn unsupported_params(options: &ForkOptions, error: &ClientError) -> Option<String> {
    let ClientError::Rpc(rpc) = error else {
        return None;
    };

    if rpc.code != ErrorCode::InvalidParams || !options.asks_for_new_params() {
        return None;
    }

    Some(format!(
        "this runtime does not support {} yet: {FORK_METHOD} refused the request with \
         {}. Fork without those flags to branch at the tail",
        options.new_flags(),
        model::refusal(rpc)
    ))
}

fn rendered(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) => model::refusal(rpc),
        other => other.to_string(),
    }
}

fn refusal(method: &str, error: &ClientError) -> anyhow::Error {
    anyhow!("the runtime refused {method}: {}", rendered(error))
}
