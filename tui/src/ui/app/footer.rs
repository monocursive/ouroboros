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
use serde_json::{json, Value};

use crate::model::{Capabilities, Plane, SessionInfo, SessionUsage};
use crate::ui::notify::Activity;
use crate::ui::transcript::Watch;

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
    /// B2. Whether this session is planning: read-only, and holding its terminal event at
    /// the end of a planning turn to ask whether to build the plan.
    ///
    /// Three sources, newest first: the `plan_exit` provider event, the `configured`
    /// status event, and `options.plan` on the session row. The first two are live and the
    /// third is a snapshot, so an event that has spoken since the last list wins — and a
    /// runtime that has said nothing at all leaves this `false`, because the badge claims
    /// the session *is* planning and silence must not raise it.
    pub plan: bool,
    pub capabilities: Capabilities,
    pub usage: Option<SessionUsage>,
    /// Whether the open session has a turn in flight, shared with its interrupt action.
    pub working: bool,
    /// How long the running turn has been running, from its `turn_started` timestamp.
    pub elapsed_ms: Option<u64>,
    /// Durable follow-ups the runtime is holding, from `queue_changed`. `None` where no
    /// such event has been seen — a queue of zero and an unreported queue are different.
    pub queued: Option<u64>,
    /// Approval requests this client has seen and not yet answered.
    pub approvals: usize,
}

/// Cached transcript facts used by the footer and status-line command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TranscriptFacts {
    pub queued: Option<u64>,
    pub elapsed_ms: Option<u64>,
}

impl TranscriptFacts {
    pub fn read(watch: &Watch, now_ms: i64) -> Self {
        Self {
            queued: watch.queue_depth().map(|depth| depth as u64),
            elapsed_ms: watch
                .active_turn_elapsed_at(now_ms)
                .map(|elapsed| elapsed as u64),
        }
    }
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
            working: self.turn_running(),
            status,
            model: info
                .and_then(|info| info.model.clone())
                .or_else(|| watch.and_then(Watch::model).map(str::to_string)),
            approval_mode: info.and_then(|info| info.approval_mode.clone()),
            sandbox_mode: info.and_then(|info| info.sandbox_mode.clone()),
            plan: watch
                .and_then(|watch| watch.planning())
                .unwrap_or_else(|| info.is_some_and(|info| info.plan)),
            capabilities: info
                .map(|info| info.capabilities.clone())
                .unwrap_or_default(),
            usage: info.and_then(|info| info.usage.clone()),
            elapsed_ms: transcript.elapsed_ms,
            queued: transcript.queued,
            approvals: watch.map(Watch::unanswered_approvals).unwrap_or(0),
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
    /// The tick and the frame share one snapshot of the current session facts.
    pub(super) fn activity_of(&self, facts: Option<&SessionFacts>) -> Activity {
        // Unanswered, not pending: an approval whose answer is already in flight — a
        // keypress or the auto-approve robot — is not waiting on the person this title
        // glyph is trying to reach.
        if self
            .sessions
            .watches
            .values()
            .any(|watch| watch.unanswered_approvals() > 0)
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
