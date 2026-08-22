//! The facts the footer states, the window title carries, and the status-line command is
//! fed — gathered in one place so the three cannot disagree.
//!
//! ## The honesty invariant, concretely
//!
//! Every field here comes from the runtime's own declaration (`interactive.info`) or from
//! the event stream. None of it is a client-side table of what a provider "usually" does,
//! and a fact the runtime did not report is `None` and is not drawn — a footer that
//! guessed a model name would be worse than a footer with no model on it.
//!
//! ## The transcript accessors this codes against
//!
//! A7 is specified against `Watch::model()`, `Watch::queue_len()` and
//! `Watch::active_turn_elapsed()`, which arrive with the transcript slice (A2) that also
//! stops dropping `run_started`, `queue_changed`, and the turn terminators. Until that
//! branch lands, [`TranscriptFacts::read`] derives the same three from the event window
//! the `Watch` already holds, in one function, so adopting the real accessors is a body
//! swap rather than a sweep of the call sites.

use serde_json::{json, Value};

use crate::model::{Capabilities, EventType, Plane, SessionInfo, SessionUsage};
use crate::ui::notify::Activity;
use crate::ui::transcript::{Entry, Watch};

use super::{App, Connection, Tab};

/// What the open session is, as of this frame.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionFacts {
    pub id: String,
    pub provider: Option<String>,
    pub workspace: Option<String>,
    /// The owning node, which is the machine a fleet session's work is actually on.
    pub node: Option<String>,
    pub status: String,
    /// `options.model`, else the transcript's `run_started.model`. `None` when neither
    /// said — the provider chose and never reported the choice.
    pub model: Option<String>,
    pub approval_mode: Option<String>,
    pub sandbox_mode: Option<String>,
    pub capabilities: Capabilities,
    pub usage: Option<SessionUsage>,
    /// Whether a turn is running. The runtime's own status, not an inference from the
    /// transcript: `idle` is the one value that means "nothing is happening".
    pub working: bool,
    /// How long the running turn has been running, from its `turn_started` timestamp.
    pub elapsed_ms: Option<u64>,
    /// Durable follow-ups the runtime is holding, from `queue_changed`. `None` where no
    /// such event has been seen — a queue of zero and an unreported queue are different.
    pub queued: Option<u64>,
    /// Approval requests this client has seen and not yet answered.
    pub approvals: usize,
}

/// The three transcript-derived numbers, behind the one function that will become the
/// `Watch` accessors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TranscriptFacts {
    pub queued: Option<u64>,
    pub elapsed_ms: Option<u64>,
}

impl TranscriptFacts {
    /// Walks the retained window newest-first for the last `queue_changed` and for a
    /// `turn_started` with no terminator after it.
    ///
    /// `now_ms` is passed in rather than read here so the arithmetic is testable without
    /// a clock. It is compared against the *runtime's* timestamp, so a client whose clock
    /// disagrees with the session's owner reports an elapsed time that is off by the
    /// skew — the honest alternative, measuring from when this client first saw the turn,
    /// reports nothing at all for a session opened mid-turn.
    pub fn read(watch: &Watch, now_ms: i64) -> Self {
        let entries = watch.entries();
        let mut queued = None;
        let mut elapsed_ms = None;
        let mut turn_ended: Option<&str> = None;

        for entry in entries.iter().rev() {
            let Entry::Event(event) = entry else {
                continue;
            };

            match &event.kind {
                EventType::QueueChanged if queued.is_none() => {
                    queued = event
                        .payload
                        .get("queued_turns")
                        .and_then(Value::as_u64)
                        .or_else(|| event.payload.get("queued").and_then(Value::as_u64));
                }
                // Newest-first, so a terminator is always met before the start it ends.
                // Kept per turn id: a queued follow-up can start while an earlier turn's
                // terminator is still the newest one in the window.
                EventType::TurnCompleted | EventType::TurnFailed | EventType::TurnInterrupted => {
                    if turn_ended.is_none() {
                        turn_ended = Some(event.turn_id.as_deref().unwrap_or(""));
                    }
                }
                EventType::TurnStarted if elapsed_ms.is_none() => {
                    let ended = turn_ended.is_some_and(|turn| {
                        turn.is_empty() || Some(turn) == event.turn_id.as_deref()
                    });

                    if !ended {
                        elapsed_ms = epoch_ms(&event.timestamp)
                            .map(|started| now_ms.saturating_sub(started).max(0) as u64);
                    }
                }
                _other => {}
            }

            if queued.is_some() && elapsed_ms.is_some() {
                break;
            }
        }

        Self { queued, elapsed_ms }
    }
}

/// The transcript's `run_started.model`, newest first.
///
/// Becomes `Watch::model()` with A2; the shape of the payload is the harness's
/// (`%{"model" => …}` on `run_started` for every CLI mapper that reports one).
pub fn transcript_model(watch: &Watch) -> Option<String> {
    watch.entries().iter().rev().find_map(|entry| {
        let Entry::Event(event) = entry else {
            return None;
        };

        if event.kind != EventType::RunStarted {
            return None;
        }

        event
            .payload
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .map(str::to_string)
    })
}

/// `2026-01-01T00:00:00.000000Z` → milliseconds since the Unix epoch.
///
/// Written out rather than pulled in: this client has no date crate, and the one format
/// it has to read is the one `Gateway.Wire` emits for a `DateTime` — ISO-8601 with an
/// optional fraction and an optional offset. Anything else answers `None`, which renders
/// as no elapsed time rather than as a wrong one.
pub fn epoch_ms(timestamp: &str) -> Option<i64> {
    let timestamp = timestamp.trim();
    let (date, rest) = timestamp.split_once(['T', 't', ' '])?;

    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;

    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Where the time ends and the zone begins. `-` cannot be searched for from the left:
    // it never appears in the time itself, but neither does anything else that would
    // stop `find` from hitting the fraction's digits first.
    let (time, offset) = match rest.find(['Z', 'z', '+']) {
        Some(index) => rest.split_at(index),
        None => match rest.rfind('-') {
            Some(index) => rest.split_at(index),
            None => (rest, ""),
        },
    };

    let mut clock = time.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let seconds = clock.next().unwrap_or("0");

    if clock.next().is_some() || hour > 23 || minute > 59 {
        return None;
    }

    let (second, fraction) = match seconds.split_once('.') {
        Some((second, fraction)) => (second, fraction),
        None => (seconds, ""),
    };

    let second: i64 = second.parse().ok()?;
    if second > 60 {
        return None;
    }

    let millis: i64 = format!("{fraction:0<3}")
        .get(..3)
        .and_then(|millis| millis.parse().ok())
        .unwrap_or(0);

    let offset_seconds = offset_seconds(offset)?;

    Some(
        (days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
            - offset_seconds)
            * 1_000
            + millis,
    )
}

fn offset_seconds(offset: &str) -> Option<i64> {
    let offset = offset.trim();

    if offset.is_empty() || offset.eq_ignore_ascii_case("z") {
        return Some(0);
    }

    let sign = match offset.chars().next()? {
        '+' => 1,
        '-' => -1,
        _unreadable => return None,
    };

    let mut parts = offset[1..].split(':');
    let hours: i64 = parts.next()?.parse().ok()?;
    let minutes: i64 = parts.next().unwrap_or("0").parse().ok()?;

    Some(sign * (hours * 3_600 + minutes * 60))
}

/// Howard Hinnant's `days_from_civil`, the standard branch-free civil-to-serial-date
/// conversion. Proleptic Gregorian, valid well beyond any timestamp a session carries.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - 719_468
}

impl App {
    /// Milliseconds since the Unix epoch, for the elapsed-turn arithmetic.
    pub(super) fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_millis() as i64)
            .unwrap_or(0)
    }

    /// The open session's facts, or `None` when there is no open interactive session.
    ///
    /// Interactive only: a coding task runs one objective to completion, takes no input,
    /// and has no approval mode, model, or queue to state.
    pub fn session_facts(&self) -> Option<SessionFacts> {
        let (plane, id) = self.sessions.open.clone()?;

        if plane != Plane::Interactive {
            return None;
        }

        let info: Option<&SessionInfo> = self.sessions.open_info();
        let watch = self.sessions.watches.get(&(plane, id.clone()));

        let transcript = watch
            .map(|watch| TranscriptFacts::read(watch, self.now_ms()))
            .unwrap_or_default();

        let status = info
            .map(|info| info.status.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        Some(SessionFacts {
            id,
            provider: info.and_then(|info| info.provider.clone()),
            workspace: info.and_then(|info| info.workspace.clone()),
            node: info.and_then(|info| info.node.clone()),
            working: status != "idle" && status != "unknown",
            status,
            model: info
                .and_then(|info| info.model.clone())
                .or_else(|| watch.and_then(transcript_model)),
            approval_mode: info.and_then(|info| info.approval_mode.clone()),
            sandbox_mode: info.and_then(|info| info.sandbox_mode.clone()),
            capabilities: info
                .map(|info| info.capabilities.clone())
                .unwrap_or_default(),
            usage: info.and_then(|info| info.usage.clone()),
            elapsed_ms: transcript.elapsed_ms,
            queued: transcript.queued,
            approvals: watch
                .map(|watch| watch.pending_approvals.len())
                .unwrap_or(0),
        })
    }

    /// What the window title's glyph should say.
    ///
    /// "Needs input" wins over everything and is checked across *every* subscribed
    /// session, not only the open one: an approval that scrolled off a background session
    /// is exactly the state a title bar exists to surface. "Working" is the open
    /// session's own status, because that is what the window is showing.
    pub fn activity(&self) -> Activity {
        self.activity_of(self.session_facts().as_ref())
    }

    /// The same answer for facts a caller has already gathered.
    ///
    /// Reading them costs a walk of the retained event window, and the tick and the frame
    /// each want them three or four times over. Gathered once and passed down rather than
    /// cached: a cache would answer with the previous tick's numbers, and these are the
    /// numbers the footer is claiming are current.
    pub(super) fn activity_of(&self, facts: Option<&SessionFacts>) -> Activity {
        if self
            .sessions
            .watches
            .values()
            .any(|watch| !watch.pending_approvals.is_empty())
        {
            return Activity::NeedsInput;
        }

        match facts {
            Some(facts) if facts.working => Activity::Working,
            _idle_or_absent => Activity::Idle,
        }
    }

    /// The workspace the title names: the open session's, else the one this client would
    /// start a session in.
    pub(super) fn title_workspace_of(&self, facts: Option<&SessionFacts>) -> Option<String> {
        facts
            .and_then(|facts| facts.workspace.clone())
            .or_else(|| self.config.defaults.workspace.clone())
            .or_else(|| self.launch_dir.clone())
    }

    /// The single JSON object a `[statusline] command` is fed on stdin.
    ///
    /// Fixed keys with `null` where a fact is unknown, rather than absent keys: a script
    /// that reads `.session.model` should get `null` on a session whose model was never
    /// reported instead of having to distinguish two spellings of the same silence.
    pub fn statusline_payload(&self) -> Value {
        self.statusline_payload_of(self.session_facts().as_ref())
    }

    pub(super) fn statusline_payload_of(&self, facts: Option<&SessionFacts>) -> Value {
        let session = facts
            .map(|facts| {
                json!({
                    "id": facts.id,
                    "provider": facts.provider,
                    "model": facts.model,
                    "workspace": facts.workspace,
                    "machine": facts.node,
                    "status": facts.status,
                })
            })
            .unwrap_or(Value::Null);

        let modes = facts
            .map(|facts| {
                json!({
                    "approval_mode": facts.approval_mode,
                    "sandbox_mode": facts.sandbox_mode,
                })
            })
            .unwrap_or(Value::Null);

        let usage = facts
            .and_then(|facts| facts.usage.as_ref())
            .map(|usage| {
                json!({
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cache_read_tokens": usage.cache_read_tokens,
                    "cache_creation_tokens": usage.cache_creation_tokens,
                    "total_tokens": usage.total_tokens,
                    "turns_with_usage": usage.turns_with_usage,
                    "context_window": usage.context_window,
                })
            })
            .unwrap_or(Value::Null);

        let (state, reason) = match &self.connection {
            Connection::Live => ("live", Value::Null),
            Connection::Lost { reason } => ("lost", Value::String(reason.clone())),
        };

        json!({
            "session": session,
            "modes": modes,
            "usage": usage,
            "cost_usd": facts
                .and_then(|facts| facts.usage.as_ref())
                .and_then(|usage| usage.cost_usd),
            "elapsed_ms": facts.and_then(|facts| facts.elapsed_ms),
            "connection": {
                "state": state,
                "reason": reason,
                "address": self.address,
                "scope": self.hello.scope,
                "node": self.hello.node,
                "spawned": self.spawned(),
            },
        })
    }

    /// Whether the shell's own footer should offer `esc interrupt` right now.
    ///
    /// Both halves have to hold: a turn is running, and the transport declared an
    /// interrupt. A key that cannot work on the open session is not advertised (D14).
    pub fn interrupt_offered(&self) -> bool {
        self.interrupt_offered_for(self.session_facts().as_ref())
    }

    pub fn interrupt_offered_for(&self, facts: Option<&SessionFacts>) -> bool {
        self.tab == Tab::Sessions
            && facts.is_some_and(|facts| facts.working && facts.capabilities.interrupt.offered())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_timestamps_become_epoch_milliseconds() {
        assert_eq!(epoch_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_ms("1970-01-01T00:00:01.500Z"), Some(1_500));
        assert_eq!(
            epoch_ms("2026-01-01T00:00:00.000000Z"),
            Some(1_767_225_600_000)
        );
        // The fraction is truncated to milliseconds, not rounded up into the next second.
        assert_eq!(
            epoch_ms("2026-01-01T00:00:00.999999Z"),
            Some(1_767_225_600_999)
        );
        // Offsets, both directions, and a bare local time.
        assert_eq!(
            epoch_ms("2026-01-01T01:00:00+01:00"),
            epoch_ms("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            epoch_ms("2025-12-31T19:00:00-05:00"),
            epoch_ms("2026-01-01T00:00:00Z")
        );
        assert_eq!(epoch_ms("2026-01-01T00:00:00"), Some(1_767_225_600_000));
    }

    #[test]
    fn an_unreadable_timestamp_is_no_elapsed_time_rather_than_a_wrong_one() {
        assert_eq!(epoch_ms(""), None);
        assert_eq!(epoch_ms("yesterday"), None);
        assert_eq!(epoch_ms("2026-01-01"), None);
        assert_eq!(epoch_ms("2026-13-01T00:00:00Z"), None);
        assert_eq!(epoch_ms("2026-01-01T25:00:00Z"), None);
    }
}
