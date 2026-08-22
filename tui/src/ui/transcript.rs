//! One watched session's history, and the arithmetic that makes it truthful.
//!
//! ## Why the cursor is the contiguous high-water mark and not the newest sequence
//!
//! `stream.lagged` says "the gateway discarded frames; replay from your last seen
//! sequence". After a lag the *newest* sequence this client holds is a live event from
//! after the hole, so replaying from it would step over the missing history and leave a
//! transcript that looks complete and is not. The cursor is therefore
//! [`Watch::cursor`] — the largest N such that every sequence in `(floor, N]` is held —
//! and it is the same number for all three resync causes.
//!
//! ## Three causes, one repair
//!
//! * **Lag** (`stream.lagged`): the subscription is still live, so the repair is
//!   `replay(cursor:)`.
//! * **Reconnect**: the subscription died with the connection, so the repair is
//!   `subscribe(cursor:)`, which registers and returns the backlog atomically.
//! * **A dropped notification on this side** (`Client::dropped_notifications`): the
//!   gateway sent it and this process could not take it. Indistinguishable from a lag
//!   from the transcript's point of view, and repaired the same way.
//!
//! All three land in [`Watch::absorb`], and all three answer `-32006 cursor_pruned` the
//! same way: raise the floor, forget what is below it, and mark the transcript truncated
//! rather than pretending the missing turns never happened.
//!
//! ## Bounded, like everything else
//!
//! A session retains 10_000 events upstream by default and a long-lived `ouro` would
//! otherwise hold every one of them per session. The window here is smaller, and running
//! past it raises the same floor a prune raises — so the divider a reader sees means
//! exactly one thing ("history before here is gone") whichever side dropped it.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::model::transcript::{PlanUpdate, PresentationEvent, RunStart, UsageReport};
use crate::model::{Event, EventType, Plane};

/// How many events one session's transcript keeps. Past this the oldest are dropped and
/// the floor rises, which is visible rather than silent.
pub const WINDOW: usize = 5_000;

/// How many interruption notes a transcript keeps. A session that lags repeatedly must
/// not accumulate one line per lag forever.
const MAX_NOTES: usize = 64;

/// Something that happened to the *stream*, recorded in place among the events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// Frames the gateway discarded under backpressure.
    Lagged { dropped: u64 },
    /// Frames this client's notification channel could not take.
    ClientDropped,
    /// The connection was lost and re-established here.
    Reconnected,
}

impl Note {
    /// Says what happened, not what is being done about it: the hole itself is a separate
    /// divider that disappears when the replay fills it, and a note that claimed to be
    /// replaying would still say so afterwards.
    pub fn text(&self) -> String {
        match self {
            Self::Lagged { dropped } => {
                format!("the gateway dropped {dropped} event frames here")
            }
            Self::ClientDropped => "this client could not take some event frames here".to_string(),
            Self::Reconnected => "the connection was re-established here".to_string(),
        }
    }
}

/// One approval the session is waiting on.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub sequence: u64,
    pub turn_id: Option<String>,
    pub payload: Value,
}

impl ApprovalRequest {
    /// The tool call the provider is asking permission for, as one line.
    ///
    /// A sandbox escalation should read as `git commit … — writes to .git`, not as the
    /// raw JSON blob of `tool_call`.
    pub fn subject(&self) -> String {
        let command = approval_command(&self.payload);
        let reason = json_nonempty_str(&self.payload, "reason");

        match (command.as_deref(), reason.as_deref()) {
            (Some(command), Some(reason)) => format!("{command} — {reason}"),
            (Some(command), None) => command.to_string(),
            (None, _) => fallback_subject(&self.payload),
        }
    }
}

fn approval_command(payload: &Value) -> Option<String> {
    payload
        .pointer("/tool_call/command")
        .or_else(|| payload.pointer("/tool/command"))
        .or_else(|| payload.get("command"))
        .and_then(render_command)
}

fn render_command(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => nonempty_trimmed(text),
        Value::Array(parts) => {
            let joined = parts
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            nonempty_trimmed(&joined)
        }
        other => nonempty_rendered(other),
    }
}

fn json_nonempty_str(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(nonempty_trimmed)
}

fn nonempty_trimmed(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn nonempty_rendered(value: &Value) -> Option<String> {
    let rendered = crate::model::compact(value);
    if rendered.is_empty() || rendered == "null" {
        None
    } else {
        Some(rendered)
    }
}

fn fallback_subject(payload: &Value) -> String {
    for key in ["tool_call", "tool", "command", "text"] {
        if let Some(value) = payload.get(key) {
            if let Some(rendered) = nonempty_rendered(value) {
                return rendered;
            }
        }
    }

    crate::model::compact(payload)
}

/// What a transcript renders, in order.
#[derive(Debug)]
pub enum Entry<'a> {
    /// History at or below this sequence is no longer held by anyone.
    Floor(u64),
    /// Sequences this client is missing and has asked for.
    Gap {
        from: u64,
        to: u64,
    },
    Note(&'a Note),
    Event(&'a Event),
    /// No further events will arrive.
    Ended(&'a str),
}

/// One subscribed session.
#[derive(Debug)]
pub struct Watch {
    pub plane: Plane,
    pub id: String,
    events: BTreeMap<u64, Event>,
    notes: BTreeMap<u64, Note>,
    /// No history at or below this sequence, whether the gateway pruned it or this window
    /// dropped it.
    floor: u64,
    cursor: u64,
    /// `Some(status)` once `stream.ended` said so. Live events are no longer expected.
    pub ended: Option<String>,
    /// Whether a resync is outstanding, so a second cause does not start a second one.
    pub resyncing: bool,
    /// Whether another cause arrived while one was in flight.
    ///
    /// Dropping it would be a silent loss: the answer already in flight was asked from a
    /// cursor that predates the new interruption, so it cannot repair it. Responses and
    /// notifications reach the UI through different channels and are not ordered against
    /// each other, so this is the ordinary case rather than the rare one.
    pub resync_again: bool,
    pub pending_approvals: BTreeMap<u64, ApprovalRequest>,
    approval_responses_in_flight: BTreeSet<String>,
    /// Cumulative frames known lost, from either side. Shown, because a number that keeps
    /// climbing is the difference between "one hiccup" and "this connection is too slow".
    pub dropped: u64,
    /// Whether the view sticks to the newest event.
    pub follow: bool,
    /// How many rendered rows sit *below* the bottom of the viewport. Zero is the newest
    /// content; only [`Watch::measured`] and the scroll keys change it.
    pub scroll: usize,
    /// What the last frame actually laid out. The renderer is the only thing that knows
    /// how many rows a transcript wraps to, so it reports them back here: the scroll keys
    /// need a ceiling to clamp against, and a scrolled-back viewport needs to know how
    /// much the content grew under it.
    rendered_lines: usize,
    viewport_height: usize,
    /// Events a replay answered that this build could not decode. Counted rather than
    /// hidden: the alternative is a transcript with unexplained holes.
    pub undecodable: usize,
    /// Whether at least one accepted turn has not produced user-visible agent text yet.
    /// Rebuilt from the ordered event ledger after every absorb, so a late replay cannot
    /// move this state backwards by arriving after a newer live event.
    waiting_for_reply: bool,
    /// Session-wide facts folded out of the ledger, for the chrome that has to state them.
    derived: Derived,
}

/// What one session's ordered events add up to.
///
/// Rebuilt from the held events after every absorb rather than accumulated as they arrive:
/// a replay overlaps by design, and a running total that counted the overlap twice would
/// report tokens nobody spent.
#[derive(Debug, Default)]
struct Derived {
    usage: UsageTotals,
    queued: usize,
    model: Option<String>,
    plan: Option<PlanUpdate>,
    /// Sequence of the `plan_updated` `plan` was parsed from, so an unchanged plan is not
    /// re-parsed on every absorb.
    plan_sequence: Option<u64>,
    /// When the turn that is still running started, in epoch milliseconds.
    active_turn_started: Option<i64>,
}

/// The session's token and cost bookkeeping, as reported.
///
/// `complete` is the honest half: once history has been pruned upstream or dropped by this
/// window, the fold no longer sees every report, and every number below is a lower bound.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct UsageTotals {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: Option<f64>,
    /// How many `usage` events the total is made of. Zero means the provider reported none,
    /// which is different from reporting zero.
    pub reports: usize,
    pub complete: bool,
}

impl UsageTotals {
    pub fn is_empty(&self) -> bool {
        self.reports == 0 && self.cost_usd.is_none()
    }

    fn fold(&mut self, report: &UsageReport) {
        self.reports += 1;
        self.input_tokens += report.input_tokens.unwrap_or(0);
        self.output_tokens += report.output_tokens.unwrap_or(0);
        self.cached_tokens += report.cached_tokens.unwrap_or(0);
        self.total_tokens += report.total_tokens.unwrap_or_else(|| {
            report.input_tokens.unwrap_or(0) + report.output_tokens.unwrap_or(0)
        });

        if let Some(cost) = report.cost_usd {
            *self.cost_usd.get_or_insert(0.0) += cost;
        }
    }
}

impl Watch {
    pub fn new(plane: Plane, id: String) -> Self {
        Self {
            plane,
            id,
            events: BTreeMap::new(),
            notes: BTreeMap::new(),
            floor: 0,
            cursor: 0,
            ended: None,
            resyncing: false,
            resync_again: false,
            pending_approvals: BTreeMap::new(),
            approval_responses_in_flight: BTreeSet::new(),
            dropped: 0,
            follow: true,
            scroll: 0,
            rendered_lines: 0,
            viewport_height: 0,
            undecodable: 0,
            waiting_for_reply: false,
            derived: Derived::default(),
        }
    }

    /// Facts about the whole session that the chrome outside this transcript must state.
    ///
    /// These five accessors are the contract between the transcript and everything that
    /// draws around it — the header, the footer, the composer's queue badge — so a pane can
    /// render a model name, a token count, a queue depth, an elapsed turn, or the current
    /// plan without reaching into the event ledger and re-deriving them differently. All
    /// five are recomputed from the held events after every absorb and describe only what
    /// this client still holds: [`UsageTotals::complete`] says when that is less than the
    /// whole session.
    pub fn usage(&self) -> UsageTotals {
        self.derived.usage
    }

    /// How many turns the runtime is holding behind the running one, from the newest
    /// `queue_changed`.
    pub fn queue_len(&self) -> usize {
        self.derived.queued
    }

    /// How long the turn that is still running has been running, in milliseconds.
    ///
    /// `None` when no turn is open, when the stream has ended, or when the runtime's
    /// timestamp could not be read — never a zero standing in for "do not know".
    pub fn active_turn_elapsed(&self) -> Option<i64> {
        if self.ended.is_some() {
            return None;
        }

        let started = self.derived.active_turn_started?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as i64;

        (now >= started).then_some(now - started)
    }

    /// The newest plan the provider published, whatever dialect it arrived in.
    pub fn latest_plan(&self) -> Option<&PlanUpdate> {
        self.derived.plan.as_ref()
    }

    /// The model this session is running, when a provider named one. Only Claude's
    /// `run_started` carries it today, so `None` is the ordinary answer elsewhere.
    pub fn model(&self) -> Option<&str> {
        self.derived.model.as_deref()
    }

    /// The largest [`scroll`](Self::scroll) that still shows content, as of the last frame.
    ///
    /// Zero before anything has been drawn, and zero whenever the whole transcript fits:
    /// there is nothing above the viewport to scroll back to, and an offset that kept
    /// climbing past this would be a key that does nothing on the way up and hundreds of
    /// keys that do nothing on the way back down.
    pub fn max_scroll(&self) -> usize {
        self.rendered_lines.saturating_sub(self.viewport_height)
    }

    /// What the renderer just laid out, and the offset correction that keeps a scrolled-back
    /// reader looking at the same rows.
    ///
    /// `scroll` counts from the bottom, so every appended row — a streamed delta, the
    /// working indicator, a running tool cell rewritten as a completed one —
    /// would otherwise slide the whole viewport downwards under someone reading history.
    /// Moving the offset by the same amount holds the content still. Following the tail is
    /// the one case that *should* move, and it is excluded.
    pub fn measured(&mut self, lines: usize, height: usize) {
        if !self.follow && self.scroll > 0 {
            self.scroll = if lines >= self.rendered_lines {
                self.scroll + (lines - self.rendered_lines)
            } else {
                self.scroll.saturating_sub(self.rendered_lines - lines)
            };
        }

        self.rendered_lines = lines;
        self.viewport_height = height;
        self.scroll = self.scroll.min(self.max_scroll());

        // Clamped back onto the newest content: a header that still said "scrolled back"
        // beside a viewport sitting at the bottom would be describing a state that no
        // longer exists.
        if self.scroll == 0 {
            self.follow = true;
        }
    }

    /// The exclusive cursor every resync uses.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn floor(&self) -> u64 {
        self.floor
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn waiting_for_reply(&self) -> bool {
        self.ended.is_none() && self.waiting_for_reply
    }

    /// The newest sequence held, contiguous or not.
    pub fn newest(&self) -> u64 {
        self.events
            .keys()
            .next_back()
            .copied()
            .unwrap_or(self.floor)
    }

    /// Whether history is missing between the cursor and the newest event held.
    pub fn has_gap(&self) -> bool {
        self.cursor < self.newest()
    }

    /// Takes a batch — a live notification, a subscribe backlog, or a replay answer.
    ///
    /// Idempotent by sequence, so the overlap every resync produces costs nothing: an
    /// event already held is dropped rather than duplicated.
    pub fn absorb(&mut self, events: Vec<Event>) {
        for event in events {
            self.note_approval(&event);
            self.events.insert(event.sequence, event);
        }

        self.trim();
        self.recompute_cursor();
        self.recompute_derived();
    }

    /// Records that history at or below `floor` will never arrive.
    ///
    /// It does **not** discard what this client already holds. A prune is a fact about
    /// what the *runtime* still retains, and events obtained before it are real history —
    /// dropping them to make the divider sit at the top would delete a transcript an
    /// operator is reading. The divider is placed where the hole actually is instead.
    pub fn raise_floor(&mut self, floor: u64) {
        if floor <= self.floor {
            return;
        }

        self.floor = floor;
        self.cursor = self.cursor.max(floor);
        self.recompute_cursor();
    }

    /// Anchors a stream interruption at the newest sequence known, which is where a reader
    /// looking at the transcript would otherwise see an unexplained jump.
    pub fn note(&mut self, note: Note, at: u64) {
        let at = at.max(self.newest());
        self.notes.insert(at, note);

        while self.notes.len() > MAX_NOTES {
            let Some(oldest) = self.notes.keys().next().copied() else {
                break;
            };

            self.notes.remove(&oldest);
        }
    }

    pub fn end(&mut self, status: String) {
        self.ended = Some(status);
        self.resyncing = false;
        self.resync_again = false;
        self.waiting_for_reply = false;
    }

    pub fn resolve_approval(&mut self, request_id: &str) {
        self.pending_approvals
            .retain(|_, request| request.request_id != request_id);
        self.approval_responses_in_flight.remove(request_id);
    }

    /// Marks one response in flight without pretending the runtime has resolved it.
    pub fn mark_approval_response(&mut self, request_id: &str) -> bool {
        let pending = self
            .pending_approvals
            .values()
            .any(|request| request.request_id == request_id);

        pending
            && self
                .approval_responses_in_flight
                .insert(request_id.to_string())
    }

    /// A refused or disconnected RPC can be tried again with the same runtime request id.
    pub fn retry_approval_response(&mut self, request_id: &str) {
        self.approval_responses_in_flight.remove(request_id);
    }

    /// The approval a modal opens on: the oldest outstanding one, so two requests are
    /// answered in the order the provider asked.
    pub fn next_approval(&self) -> Option<&ApprovalRequest> {
        self.pending_approvals.values().find(|request| {
            !self
                .approval_responses_in_flight
                .contains(&request.request_id)
        })
    }

    /// The transcript in order, with the dividers interleaved where they belong.
    pub fn entries(&self) -> Vec<Entry<'_>> {
        let mut entries = Vec::with_capacity(self.events.len() + self.notes.len() + 2);

        // The floor sits where the hole is, not at the top: a client that held events
        // before a prune still holds them, and they are still history.
        let mut floor_emitted = self.floor == 0;
        let mut previous: Option<u64> = None;
        let mut notes_from = 0u64;

        for (sequence, event) in &self.events {
            if !floor_emitted && *sequence > self.floor {
                if notes_from <= self.floor {
                    for (_at, note) in self.notes.range(notes_from..=self.floor) {
                        entries.push(Entry::Note(note));
                    }
                }

                notes_from = self.floor + 1;
                entries.push(Entry::Floor(self.floor));
                floor_emitted = true;

                // Nothing is missing across a floor: what is below it is not a hole this
                // client can fill, and drawing both markers would say it twice.
                previous = None;
            }

            if let Some(previous) = previous {
                if *sequence > previous + 1 {
                    entries.push(Entry::Gap {
                        from: previous + 1,
                        to: sequence - 1,
                    });
                }
            }

            for (_at, note) in self.notes.range(notes_from..=*sequence) {
                entries.push(Entry::Note(note));
            }

            notes_from = sequence + 1;
            entries.push(Entry::Event(event));
            previous = Some(*sequence);
        }

        if !floor_emitted {
            if notes_from <= self.floor {
                for (_at, note) in self.notes.range(notes_from..=self.floor) {
                    entries.push(Entry::Note(note));
                }
            }

            notes_from = self.floor + 1;
            entries.push(Entry::Floor(self.floor));
        }

        for (_at, note) in self.notes.range(notes_from..) {
            entries.push(Entry::Note(note));
        }

        if let Some(status) = &self.ended {
            entries.push(Entry::Ended(status));
        }

        entries
    }

    fn note_approval(&mut self, event: &Event) {
        let Some(request_id) = event.request_id.clone() else {
            return;
        };

        match event.kind {
            EventType::ApprovalRequested => {
                self.pending_approvals.insert(
                    event.sequence,
                    ApprovalRequest {
                        request_id,
                        sequence: event.sequence,
                        turn_id: event.turn_id.clone(),
                        payload: event.payload.clone(),
                    },
                );
            }
            EventType::ApprovalResolved => self.resolve_approval(&request_id),
            _ => {}
        }
    }

    /// Drops the oldest events past the window, raising the floor by exactly as much as
    /// was dropped so the divider states the truth rather than an approximation.
    fn trim(&mut self) {
        while self.events.len() > WINDOW {
            let Some(oldest) = self.events.keys().next().copied() else {
                break;
            };

            self.events.remove(&oldest);
            self.floor = self.floor.max(oldest);
        }

        self.notes.retain(|sequence, _| *sequence > self.floor);
        self.pending_approvals
            .retain(|sequence, _| *sequence > self.floor);
        self.approval_responses_in_flight.retain(|request_id| {
            self.pending_approvals
                .values()
                .any(|request| &request.request_id == request_id)
        });
    }

    fn recompute_cursor(&mut self) {
        let mut cursor = self.cursor.max(self.floor);

        // Only the contiguous prefix counts: the first hole is where a replay has to
        // resume, whatever sits above it.
        while self.events.contains_key(&(cursor + 1)) {
            cursor += 1;
        }

        self.cursor = cursor;
    }

    /// One ordered pass over the held ledger, producing everything derived from it.
    ///
    /// Reply-waiting, token totals, queue depth, model, plan, and the running turn's start
    /// are all "what do these events add up to" questions, and answering them in one walk
    /// keeps the cost of an absorb where it already was.
    fn recompute_derived(&mut self) {
        #[derive(Debug, Default)]
        struct ReplyState {
            pending: bool,
            responded: bool,
            paused: bool,
        }

        let mut turns: BTreeMap<String, ReplyState> = BTreeMap::new();
        let mut usage = UsageTotals {
            complete: self.floor == 0,
            ..UsageTotals::default()
        };
        let mut queued = 0usize;
        let mut model: Option<String> = None;
        let mut plan_sequence: Option<u64> = None;
        let mut turn_starts: BTreeMap<String, i64> = BTreeMap::new();

        for event in self.events.values() {
            match PresentationEvent::from_event(event) {
                PresentationEvent::Usage(report) => usage.fold(&report),
                PresentationEvent::QueueChanged { queued: depth } => queued = depth,
                PresentationEvent::RunStarted(RunStart {
                    model: Some(named), ..
                }) => model = Some(named),
                PresentationEvent::Plan(_) => plan_sequence = Some(event.sequence),
                PresentationEvent::TurnStarted { turn_id, at } => {
                    if let (Some(turn_id), Some(at)) = (turn_id, at) {
                        turn_starts.insert(turn_id, at);
                    }
                }
                PresentationEvent::TurnEnded { turn_id, .. } => {
                    if let Some(turn_id) = turn_id {
                        turn_starts.remove(&turn_id);
                    } else {
                        turn_starts.clear();
                    }
                }
                // A finished run's own report is the only place Claude states a cost.
                PresentationEvent::Lifecycle { .. } if event.kind == EventType::RunCompleted => {
                    if let Some(cost) = event
                        .payload
                        .get("cost_usd")
                        .or_else(|| event.payload.get("total_cost_usd"))
                        .and_then(Value::as_f64)
                    {
                        *usage.cost_usd.get_or_insert(0.0) += cost;
                    }
                }
                _ => {}
            }

            if matches!(
                event.kind,
                EventType::SessionClosed | EventType::SessionFailed | EventType::SessionCancelled
            ) {
                turn_starts.clear();
            }

            let turn = event
                .turn_id
                .clone()
                .unwrap_or_else(|| "__session__".to_string());

            match event.kind {
                EventType::RunStarted
                | EventType::InputAccepted
                | EventType::TurnQueued
                | EventType::TurnStarted => {
                    let state = turns.entry(turn).or_default();
                    state.pending = true;
                    state.responded = false;
                    state.paused = false;
                }
                EventType::OutputTextDelta | EventType::OutputTextFinal
                    if event
                        .payload
                        .get("text")
                        .and_then(Value::as_str)
                        .map(|text| !text.trim().is_empty())
                        .unwrap_or(false) =>
                {
                    turns.entry(turn).or_default().responded = true;
                }
                EventType::ApprovalRequested => {
                    turns.entry(turn).or_default().paused = true;
                }
                EventType::ApprovalResolved => {
                    turns.entry(turn).or_default().paused = false;
                }
                EventType::RunCompleted
                | EventType::RunFailed
                | EventType::RunCancelled
                | EventType::TurnCompleted
                | EventType::TurnFailed
                | EventType::TurnInterrupted => {
                    turns.entry(turn).or_default().pending = false;
                }
                EventType::SessionIdle
                | EventType::SessionClosed
                | EventType::SessionFailed
                | EventType::SessionCancelled => turns.clear(),
                _ => {}
            }
        }

        self.waiting_for_reply = turns
            .values()
            .any(|state| state.pending && !state.responded && !state.paused);
        self.derived.usage = usage;
        self.derived.queued = queued;
        self.derived.model = model;
        self.derived.active_turn_started = turn_starts.values().copied().max();

        if self.derived.plan_sequence != plan_sequence {
            self.derived.plan_sequence = plan_sequence;
            self.derived.plan = plan_sequence
                .and_then(|sequence| self.events.get(&sequence))
                .and_then(|event| match PresentationEvent::from_event(event) {
                    PresentationEvent::Plan(plan) => Some(plan),
                    _ => None,
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(sequence: u64) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": "output_text_final",
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "payload": { "text": format!("line {sequence}") }
        }))
        .expect("an event")
    }

    fn approval(sequence: u64, request_id: &str) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": "approval_requested",
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "request_id": request_id,
            "turn_id": "turn-1",
            "payload": { "tool_call": { "name": "bash", "command": "rm -rf /" } }
        }))
        .expect("an approval event")
    }

    fn lifecycle(sequence: u64, kind: &str, turn_id: &str, text: &str) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "turn_id": turn_id,
            "request_id": if kind.starts_with("approval_") { Some("req-a") } else { None },
            "payload": { "text": text }
        }))
        .expect("a lifecycle event")
    }

    fn watch() -> Watch {
        Watch::new(Plane::Interactive, "s1".into())
    }

    #[test]
    fn the_cursor_follows_the_contiguous_prefix_and_stops_at_the_first_hole() {
        let mut watch = watch();

        watch.absorb((1..=3).map(event).collect());
        assert_eq!(watch.cursor(), 3);
        assert!(!watch.has_gap());

        // A lag: live events resume past a hole. The cursor must not follow them.
        watch.absorb(vec![event(9), event(10)]);
        assert_eq!(
            watch.cursor(),
            3,
            "the resync cursor is not the newest event"
        );
        assert_eq!(watch.newest(), 10);
        assert!(watch.has_gap());

        // The replay that cursor produced fills the hole exactly.
        watch.absorb((4..=8).map(event).collect());
        assert_eq!(watch.cursor(), 10);
        assert!(!watch.has_gap());
    }

    #[test]
    fn reply_waiting_follows_turn_text_approval_and_terminal_events() {
        let mut watch = watch();

        watch.absorb(vec![lifecycle(1, "input_accepted", "turn-1", "fix it")]);
        assert!(watch.waiting_for_reply());

        watch.absorb(vec![lifecycle(2, "output_text_delta", "turn-1", "")]);
        assert!(
            watch.waiting_for_reply(),
            "an empty transport delta is not a visible reply"
        );

        watch.absorb(vec![lifecycle(3, "output_text_delta", "turn-1", "Working")]);
        assert!(!watch.waiting_for_reply());

        // A queued follow-up still waits even though the preceding turn has replied.
        watch.absorb(vec![lifecycle(4, "turn_queued", "turn-2", "")]);
        assert!(watch.waiting_for_reply());

        watch.absorb(vec![lifecycle(5, "approval_requested", "turn-2", "bash")]);
        assert!(
            !watch.waiting_for_reply(),
            "the runtime is waiting on the user"
        );

        watch.absorb(vec![lifecycle(6, "approval_resolved", "turn-2", "")]);
        assert!(
            watch.waiting_for_reply(),
            "the agent resumed without replying yet"
        );

        watch.absorb(vec![lifecycle(7, "turn_failed", "turn-2", "boom")]);
        assert!(!watch.waiting_for_reply());
    }

    #[test]
    fn absorbing_the_same_events_twice_changes_nothing() {
        let mut watch = watch();

        watch.absorb((1..=5).map(event).collect());
        watch.absorb((1..=5).map(event).collect());

        assert_eq!(watch.len(), 5);
        assert_eq!(watch.cursor(), 5);
    }

    #[test]
    fn a_pruned_floor_marks_the_hole_without_deleting_what_was_already_read() {
        let mut watch = watch();

        // Held: 1..3. A replay from 3 answered 8..10, which proves 4..7 are no longer
        // retained — the floor the caller derives from that is 7.
        watch.absorb((1..=3).map(event).collect());
        watch.raise_floor(7);
        watch.absorb((8..=10).map(event).collect());

        assert_eq!(watch.floor(), 7);
        assert_eq!(
            watch.len(),
            6,
            "a prune is about what the runtime retains, not about what was already read"
        );
        assert_eq!(watch.cursor(), 10);
        assert!(!watch.has_gap());

        let entries = watch.entries();
        let shape: Vec<String> = entries
            .iter()
            .map(|entry| match entry {
                Entry::Event(event) => event.sequence.to_string(),
                Entry::Floor(floor) => format!("floor {floor}"),
                Entry::Gap { from, to } => format!("gap {from}..{to}"),
                Entry::Note(_) => "note".into(),
                Entry::Ended(status) => format!("ended {status}"),
            })
            .collect();

        // The divider sits where the hole is, and there is no gap marker across it: what
        // is below the floor is not a hole this client can fill.
        assert_eq!(
            shape,
            vec!["1", "2", "3", "floor 7", "8", "9", "10"],
            "a truncation belongs where the history stops, not at the top"
        );
    }

    #[test]
    fn a_floor_at_the_very_start_is_the_first_thing_shown() {
        let mut watch = watch();

        watch.raise_floor(41);
        watch.absorb(vec![event(42)]);

        assert!(matches!(watch.entries()[0], Entry::Floor(41)));
        assert_eq!(watch.cursor(), 42);
        assert!(!watch.has_gap());
    }

    #[test]
    fn a_gap_is_visible_until_the_replay_fills_it() {
        let mut watch = watch();

        watch.absorb(vec![event(1), event(2), event(7)]);
        watch.note(Note::Lagged { dropped: 4 }, 6);

        let entries = watch.entries();
        let gaps: Vec<String> = entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Gap { from, to } => Some(format!("{from}..{to}")),
                _ => None,
            })
            .collect();

        assert_eq!(gaps, vec!["3..6"]);

        assert!(entries
            .iter()
            .any(|entry| matches!(entry, Entry::Note(Note::Lagged { dropped: 4 }))));

        watch.absorb((3..=6).map(event).collect());

        assert!(
            !watch
                .entries()
                .iter()
                .any(|entry| matches!(entry, Entry::Gap { .. })),
            "a filled hole is not a hole"
        );

        // The record of the interruption survives the repair.
        assert!(watch
            .entries()
            .iter()
            .any(|entry| matches!(entry, Entry::Note(Note::Lagged { .. }))));
    }

    #[test]
    fn the_window_drops_the_oldest_and_raises_the_same_floor_a_prune_raises() {
        let mut watch = watch();

        watch.absorb((1..=(WINDOW as u64 + 10)).map(event).collect());

        assert_eq!(watch.len(), WINDOW);
        assert_eq!(watch.floor(), 10);
        assert!(matches!(watch.entries()[0], Entry::Floor(10)));
    }

    #[test]
    fn an_approval_subject_prefers_the_command_and_reason() {
        let request = ApprovalRequest {
            request_id: "req-git".into(),
            sequence: 1,
            turn_id: Some("turn-1".into()),
            payload: json!({
                "tool_call": {
                    "name": "exec_command",
                    "command": "git commit -am wip"
                },
                "reason": "writes to .git",
                "kind": "sandbox_escalation"
            }),
        };

        assert_eq!(request.subject(), "git commit -am wip — writes to .git");
    }

    #[test]
    fn an_approval_request_is_held_until_it_resolves() {
        let mut watch = watch();

        watch.absorb(vec![event(1), approval(2, "req-a")]);

        let pending = watch.next_approval().expect("a pending approval");
        assert_eq!(pending.request_id, "req-a");
        assert_eq!(pending.turn_id.as_deref(), Some("turn-1"));
        assert_eq!(pending.subject(), "rm -rf /");

        watch.absorb(vec![Event::decode(&json!({
            "id": "evt-3",
            "sequence": 3,
            "type": "approval_resolved",
            "timestamp": "t",
            "request_id": "req-a",
            "payload": {}
        }))
        .expect("a resolution")]);

        assert!(watch.next_approval().is_none());
    }

    #[test]
    fn two_approvals_are_answered_oldest_first() {
        let mut watch = watch();

        watch.absorb(vec![approval(5, "req-b"), approval(4, "req-a")]);

        assert_eq!(watch.next_approval().expect("one").request_id, "req-a");

        assert!(watch.mark_approval_response("req-a"));
        assert_eq!(watch.next_approval().expect("the next").request_id, "req-b");

        watch.retry_approval_response("req-a");
        assert_eq!(watch.next_approval().expect("retry").request_id, "req-a");

        watch.resolve_approval("req-a");
        assert_eq!(watch.next_approval().expect("the next").request_id, "req-b");
    }

    #[test]
    fn a_terminal_stream_says_so_at_the_end_of_the_transcript() {
        let mut watch = watch();

        watch.absorb(vec![event(1)]);
        watch.resyncing = true;
        watch.end("closed".into());

        assert!(!watch.resyncing, "a finished stream has nothing to resync");
        assert!(matches!(
            watch.entries().last(),
            Some(Entry::Ended("closed"))
        ));
    }
}
