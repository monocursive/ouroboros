//! The verbs that landed with D9, D6, B7 and G1, from the operator's side.
//!
//! Every one of them is gated twice and refused locally rather than optimistically sent:
//! `hello.methods` says whether this gateway serves the verb at all (§2.3), and — for the
//! four that only a `native` session can honour — the session's own declared transport
//! says whether *this* conversation can. A key that is drawn and always fails is worse
//! than a key that is not drawn, and a refusal that arrives from the far side is a
//! round-trip spent learning something this client already knew.
//!
//! The second rule this module exists to keep is that the runtime's own record wins. A
//! compaction and an operator command each produce a durable event *and* a reply; the
//! reply is drawn as a local note because it carries more, and the durable event is
//! deduped against it rather than drawn a second time in a thinner form
//! ([`Block::key`](crate::ui::transcript_cells::Block::key)).

use serde_json::{json, Value};

use crate::model::native::{
    refusal_tag, Compaction, Delegated, DelegationRow, RewindPoint, Rewound, SessionContext,
    ShellRefusal, ShellResult,
};
use crate::model::Plane;
use crate::proto::ErrorCode;
use crate::transport::ClientError;
use crate::ui::transcript_cells::{compaction_block, Block, Tone};

use super::overlays::Overlay;
use super::{App, Call, NoticeKind, Tag};

/// What a rewind may put back, in the order the chooser lists them.
///
/// Exactly the three the runtime accepts and no more: `interactive.rewind`'s `what` is a
/// closed enum, and a fourth row here would be a promise the wire refuses.
pub const REWIND_WHAT: [(&str, &str); 3] = [
    ("both", "the files and the conversation"),
    ("files", "the files only — the conversation stays as it is"),
    (
        "conversation",
        "the conversation only — the files stay as they are",
    ),
];

/// How many characters of a command the composer echoes back in a note's label.
const COMMAND_LABEL: usize = 96;

impl App {
    // ----- gating ---------------------------------------------------------------------

    /// Whether a verb only a `native` session can honour may be offered here.
    ///
    /// Three questions, and the answer names which one failed so the notice is worth
    /// reading: the gateway must serve the method, a session must be open, and the
    /// transport the runtime declared for it must be `native`. The last is read from
    /// `options.capabilities.transport` — a *label*, not a yes/no — and an undeclared
    /// transport is treated as offerable, because a client that hid a verb on a gateway's
    /// silence would be inventing a ceiling the runtime never stated.
    pub(super) fn native_verb_offered(&self, method: &str) -> Result<(Plane, String), String> {
        let Some((plane, id)) = self.sessions.open.clone() else {
            return Err("open a session first".to_string());
        };

        if !self.hello.serves(method) {
            return Err(format!("this gateway does not serve {method}"));
        }

        let capabilities = self.open_capabilities();

        match capabilities.transport.as_deref() {
            None | Some("native") => Ok((plane, id)),
            Some(transport) => Err(format!(
                "{transport} is not the native transport, so this runtime holds no \
                 conversation of its own to work on here"
            )),
        }
    }

    /// The same gate, said out loud. Used by the four slash verbs.
    fn native_target(&mut self, method: &str) -> Option<(Plane, String)> {
        match self.native_verb_offered(method) {
            Ok(target) => Some(target),
            Err(reason) => {
                self.inform(reason, NoticeKind::Info);
                None
            }
        }
    }

    /// Whether the palette and the `/` menu offer the native context verbs.
    pub fn context_verbs_offered(&self) -> bool {
        self.native_verb_offered("interactive.compact").is_ok()
    }

    /// `interactive.context` answers for *every* transport — with different amounts of
    /// truth — so it is gated on the method alone.
    pub fn context_overlay_offered(&self) -> bool {
        self.sessions.open.is_some() && self.hello.serves("interactive.context")
    }

    pub fn delegation_offered(&self) -> bool {
        self.sessions.open.is_some() && self.hello.serves("interactive.delegate")
    }

    /// B7. `!` is offered where the runtime serves the verb *and* the session is already
    /// at `auto_approve` — the one posture where the operator has said "stop asking me".
    /// Everywhere else the key still works and the refusal explains, because a rule may
    /// allow the command and only the engine knows that.
    pub fn shell_offered(&self) -> bool {
        self.sessions.open.is_some() && self.hello.serves("workspace.exec")
    }

    /// Whether this session's stated posture already permits an operator command, which is
    /// what the composer says before one is sent.
    pub fn shell_auto_approved(&self) -> bool {
        self.sessions
            .open_info()
            .and_then(|session| session.approval_mode.clone())
            .as_deref()
            == Some("auto_approve")
    }

    // ----- D9: `/compact [focus]` -------------------------------------------------------

    pub(super) fn compact_session(&mut self, focus: Option<&str>) {
        let Some((plane, id)) = self.native_target("interactive.compact") else {
            return;
        };

        let mut params = json!({ "id": id });

        if let Some(focus) = focus.map(str::trim).filter(|focus| !focus.is_empty()) {
            params["focus"] = json!(focus);
        }

        let params = self.routed_session_params(plane, &id, params);

        self.issue(Call::new(
            Tag::Compact {
                plane,
                id: id.clone(),
            },
            "interactive.compact",
            params,
        ));

        self.inform(
            "folding this conversation now; the report says what was archived",
            NoticeKind::Info,
        );
    }

    pub(super) fn compacted(&mut self, plane: Plane, id: &str, value: &Value) {
        let Some(report) = Compaction::decode(value) else {
            self.inform(
                "the runtime answered a compaction this client could not read",
                NoticeKind::Warn,
            );
            return;
        };

        self.push_note(plane, id, compaction_block(&report));

        // The meter is stale the moment a fold lands: `context_used` is reset and the
        // prefix fingerprint rotates. Re-reading is cheaper than inferring, and inferring
        // would put a number on screen nobody measured.
        self.read_context(plane, id, false);
    }

    // ----- D9: `/handoff <prompt>` ------------------------------------------------------

    pub(super) fn handoff_session(&mut self, prompt: &str) {
        let Some((plane, id)) = self.native_target("interactive.handoff") else {
            return;
        };

        let prompt = prompt.trim();

        // The child's id is caller-owned for the same reason a fork's is: the verb's
        // ceiling can fire after the child exists, and a client that had to mint a second
        // id to find out would start a second session instead of finding the first.
        let handoff_id = crate::model::new_session_id();

        let mut params = json!({ "id": id, "handoff_id": handoff_id });

        if !prompt.is_empty() {
            params["prompt"] = json!(prompt);
        }

        let params = self.routed_session_params(plane, &id, params);

        self.issue(Call::new(
            Tag::Handoff {
                plane,
                id: id.clone(),
                child: handoff_id,
            },
            "interactive.handoff",
            params,
        ));

        self.inform(
            "writing a handoff packet; the parent keeps running — ending it is your call",
            NoticeKind::Info,
        );
    }

    /// The child is opened the moment the runtime names it. `outcome: "unknown"` is *not*
    /// a failure — the ceiling fired and the child may well exist — so the id is opened
    /// either way and the transcript says which of the two happened.
    pub(super) fn handed_off(&mut self, parent: &str, child: &str, value: &Value) {
        let ready = value.get("ready").and_then(Value::as_bool).unwrap_or(true);
        let named = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .unwrap_or(child)
            .to_string();
        let node = value
            .get("node")
            .and_then(Value::as_str)
            .map(str::to_string);

        self.refresh_session_lists();
        self.open_session_on(Plane::Interactive, named.clone(), node);

        self.inform(
            match ready {
                true => format!("handed off from {parent} — this is the child, {named}"),
                false => format!(
                    "the handoff was accepted but the child {named} is not ready yet; \
                     it is open and will fill in"
                ),
            },
            NoticeKind::Info,
        );
    }

    // ----- D9: `/context` ---------------------------------------------------------------

    pub(super) fn open_context(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "open a session before reading its context",
                NoticeKind::Info,
            );
            return;
        };

        if !self.hello.serves("interactive.context") {
            self.inform(
                "this gateway does not serve interactive.context",
                NoticeKind::Warn,
            );
            return;
        }

        self.read_context(plane, &id, true);
    }

    /// Reads `interactive.context`. `show` opens the overlay when the answer lands;
    /// otherwise the numbers only refresh the meter.
    pub(super) fn read_context(&mut self, plane: Plane, id: &str, show: bool) {
        let params = self.routed_session_params(plane, id, json!({ "id": id }));

        self.issue(Call::new(
            Tag::Context {
                plane,
                id: id.to_string(),
                show,
            },
            "interactive.context",
            params,
        ));
    }

    pub(super) fn context_read(&mut self, plane: Plane, id: &str, show: bool, value: &Value) {
        let Some(context) = SessionContext::decode(value) else {
            self.inform(
                "the runtime answered a context this client could not read",
                NoticeKind::Warn,
            );
            return;
        };

        // The meter reads what this verb reported, for the session it reported it about.
        // Kept here rather than folded into the list row because a row's `usage` is
        // reduced to tokens and cost by the runtime — the window is not in it.
        self.context = Some((plane, id.to_string(), Box::new(context.clone())));

        if show {
            self.overlay = Some(Overlay::Context {
                context: Box::new(context),
                scroll: 0,
            });
        }
    }

    /// What the footer's `%` divides, where a `/context` for the open session reported
    /// both halves.
    pub fn open_context_meter(&self) -> Option<&SessionContext> {
        let (plane, id) = self.sessions.open.as_ref()?;
        let (held_plane, held_id, context) = self.context.as_ref()?;

        (held_plane == plane && held_id == id).then_some(context.as_ref())
    }

    // ----- D6: `/rewind` ------------------------------------------------------------------

    pub(super) fn open_rewind(&mut self) {
        let Some((plane, id)) = self.native_target("interactive.rewind_points") else {
            return;
        };

        let params = self.routed_session_params(plane, &id, json!({ "id": id }));

        self.issue(Call::new(
            Tag::RewindPoints {
                plane,
                id: id.clone(),
            },
            "interactive.rewind_points",
            params,
        ));
    }

    pub(super) fn rewind_points_read(&mut self, plane: Plane, id: &str, value: &Value) {
        let points = RewindPoint::decode_list(value);

        if points.is_empty() {
            self.inform(
                "this session has no checkpointed turns to go back to",
                NoticeKind::Info,
            );
            return;
        }

        let choice = points.len() - 1;

        self.overlay = Some(Overlay::Rewind {
            plane,
            id: id.to_string(),
            points,
            choice,
            what: 0,
            confirming: false,
        });
    }

    /// Sends the rewind for whatever the menu has selected.
    ///
    /// **The target is the turn's 1-based position, not its id.** The gateway's parameter
    /// contract admits either, but `InteractiveSession.rewind/3` guards `is_integer`, so a
    /// turn id would be refused as `invalid_rewind` before it reached the session. The
    /// position is exactly what this menu already knows, having just been handed the list
    /// it indexes into.
    pub(super) fn rewind_confirm(&mut self) {
        let Some(Overlay::Rewind {
            plane,
            id,
            points,
            choice,
            what,
            ..
        }) = self.overlay.take()
        else {
            return;
        };

        if !self.hello.serves("interactive.rewind") {
            self.inform(
                "this gateway does not serve interactive.rewind",
                NoticeKind::Warn,
            );
            return;
        }

        let Some(point) = points.get(choice) else {
            return;
        };

        let (what_name, _description) = REWIND_WHAT[what.min(REWIND_WHAT.len() - 1)];
        let to_turn = choice + 1;
        let label = point
            .turn_id
            .clone()
            .unwrap_or_else(|| format!("turn {to_turn}"));

        let params = self.routed_session_params(
            plane,
            &id,
            json!({ "id": id, "to_turn": to_turn, "what": what_name }),
        );

        self.issue(Call::new(
            Tag::Rewind {
                plane,
                id: id.clone(),
                label,
                what: what_name,
            },
            "interactive.rewind",
            params,
        ));
    }

    pub(super) fn rewound(
        &mut self,
        plane: Plane,
        id: &str,
        label: &str,
        what: &str,
        value: &Value,
    ) {
        let Some(outcome) = Rewound::decode(value) else {
            self.inform(
                "the runtime answered a rewind this client could not read",
                NoticeKind::Warn,
            );
            return;
        };

        let mut facts = Vec::new();

        if !outcome.restored.is_empty() {
            facts.push(format!(
                "restored {} file{}",
                outcome.restored.len(),
                if outcome.restored.len() == 1 { "" } else { "s" }
            ));
        }

        if !outcome.unrestorable.is_empty() {
            facts.push(format!("skipped {}", outcome.unrestorable.len()));
        }

        if let Some(messages) = outcome.messages {
            facts.push(format!("{messages} messages kept"));
        }

        if facts.is_empty() {
            facts.push("nothing had to be put back".to_string());
        }

        // Restored first, then what could not be — in that order and never merged, because
        // the second list is the one the operator has to act on and a mixed list buries it.
        let mut body: Vec<String> = outcome
            .restored
            .iter()
            .map(|file| {
                format!(
                    "  {} {}",
                    match file.action.as_deref() {
                        Some("deleted") => "removed",
                        _rewritten => "restored",
                    },
                    file.path
                )
            })
            .collect();

        if !outcome.unrestorable.is_empty() {
            body.push("  could not be restored:".to_string());
            body.extend(
                outcome
                    .unrestorable
                    .iter()
                    .map(|entry| match &entry.reason {
                        Some(reason) => format!("  · {} — {reason}", entry.subject()),
                        None => format!("  · {}", entry.subject()),
                    }),
            );
        }

        let tone = if outcome.unrestorable.is_empty() {
            Tone::Muted
        } else {
            Tone::Warning
        };

        self.push_note(
            plane,
            id,
            Block::new(
                format!("Rewound to {label} ({what})"),
                facts.join(" · "),
                tone,
            )
            .with_body(body),
        );

        self.refresh_session_lists();
    }

    // ----- B7: `!cmd` ---------------------------------------------------------------------

    /// Sends a draft that began with `!` to `workspace.exec`.
    ///
    /// The composer has already said where it will run; this is only the send. The command
    /// text is kept on the tag because the runtime never records it — the ledger holds a
    /// digest and a working directory and deliberately not the words — so the only place
    /// the line the operator typed can be echoed back is here.
    pub(super) fn run_operator_shell(&mut self, command: &str) {
        let command = command.trim();

        if command.is_empty() {
            self.inform("type a command after the !", NoticeKind::Info);
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform("open a session before running a command", NoticeKind::Info);
            return;
        };

        if plane != Plane::Interactive {
            self.inform(
                "a coding task has no operator shell; open a conversation",
                NoticeKind::Info,
            );
            return;
        }

        if !self.hello.serves("workspace.exec") {
            self.inform(
                "this gateway does not serve workspace.exec",
                NoticeKind::Warn,
            );
            return;
        }

        let params =
            self.routed_session_params(plane, &id, json!({ "id": id, "command": command }));

        self.issue(Call::new(
            Tag::Shell {
                plane,
                id: id.clone(),
                command: command.to_string(),
            },
            "workspace.exec",
            params,
        ));

        self.shell_refusal = None;
        self.inform(
            format!(
                "running it in this session's workspace on {}",
                self.shell_where()
            ),
            NoticeKind::Info,
        );
    }

    /// Which node and directory a `!` will run on, in the words the composer uses.
    pub fn shell_where(&self) -> String {
        let session = self.sessions.open_info();

        let node = session
            .and_then(|session| session.node.clone())
            .unwrap_or_else(|| "this session's owner node".to_string());

        match session.and_then(|session| session.workspace.clone()) {
            Some(workspace) => format!("{node} in {workspace}"),
            None => node,
        }
    }

    pub(super) fn shell_finished(&mut self, plane: Plane, id: &str, command: &str, value: &Value) {
        let Some(result) = ShellResult::decode(value) else {
            self.inform(
                "the runtime answered a command this client could not read",
                NoticeKind::Warn,
            );
            return;
        };

        let mut detail = result.describe();

        if let Some(path) = &result.spilled {
            detail.push_str(&format!(" · full output at {path}"));
        }

        if let Some(error) = &result.spill_error {
            detail.push_str(&format!(" · the rest could not be written: {error}"));
        }

        let failed = result.timed_out || result.exit_status != Some(0);

        self.push_note(
            plane,
            id,
            Block::new(
                format!("$ {}", crate::ui::app::native::label_command(command)),
                detail,
                if failed { Tone::Warning } else { Tone::Muted },
            )
            .with_body(
                result
                    .output
                    .as_deref()
                    .map(crate::ui::transcript_cells::body_rows)
                    .unwrap_or_default(),
            )
            // The runtime writes its own `provider_event` for this command. Keyed on the
            // digest it carries, so that record is not drawn beside this fuller one.
            .with_key(result.command_digest.clone()),
        );
    }

    /// A refused command, and the rule that would have let it.
    ///
    /// Kept on the composer rather than in the notice row: the refusal and the offer to
    /// fix it belong on screen together, and a notice that expires in four seconds is not
    /// somewhere to put a one-key action.
    pub(super) fn shell_refused(&mut self, error: &ClientError) {
        let data = match error {
            ClientError::Rpc(rpc) => rpc.data.as_ref(),
            _other => None,
        };

        // Every other refusal this verb can give — a closed session, a blank command, a
        // ledger that could not record the attempt — reaches the ordinary renderer, which
        // keeps every field the runtime sent rather than summarising it away. It does not
        // reach the composer, because there is no rule to offer for it.
        let Some(refusal) = ShellRefusal::decode(data) else {
            let said = match error {
                ClientError::Rpc(rpc) => crate::model::refusal(rpc),
                other => other.to_string(),
            };

            self.shell_refusal = None;
            self.inform(
                format!("the command was refused: {said}"),
                NoticeKind::Error,
            );
            return;
        };

        // The offer stands only where this client could actually honour it: the rule has
        // to have been suggested by the engine, this gateway has to serve `permissions.add`,
        // and the session has to name a workspace to scope it to. An offer that could not
        // be kept would be worse than none, so the missing half is named instead.
        let workspace = self
            .sessions
            .open_info()
            .and_then(|session| session.workspace.clone())
            .or_else(|| refusal.workspace.clone());

        let offer = match (&refusal.suggested_rule, &workspace) {
            (Some(pattern), Some(workspace)) if self.hello.serves("permissions.add") => {
                Some((pattern.clone(), workspace.clone()))
            }
            _absent => None,
        };

        self.shell_refusal = Some(super::ShellRefusalState {
            reason: refusal.reason.clone(),
            message: refusal.message.clone(),
            denied_by: refusal.denied_by.clone(),
            approval_mode: refusal.approval_mode.clone(),
            suggested_rule: refusal.suggested_rule.clone(),
            offer,
        });
    }

    /// The one-key answer to a refusal: write the rule the engine itself suggested.
    pub(super) fn add_shell_rule(&mut self) {
        let Some(state) = self.shell_refusal.as_ref() else {
            return;
        };

        let Some((pattern, workspace)) = state.offer.clone() else {
            return;
        };

        self.issue(Call::new(
            Tag::PermissionRule {
                pattern: pattern.clone(),
            },
            "permissions.add",
            crate::model::permission_add_params(&pattern, &workspace),
        ));

        self.shell_refusal = None;
    }

    // ----- G1: `/delegate <objective>` ------------------------------------------------------

    pub(super) fn delegate(&mut self, objective: &str) {
        let objective = objective.trim();

        if objective.is_empty() {
            self.inform(
                "say what the child should do: /delegate <objective>",
                NoticeKind::Info,
            );
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform("open a conversation before delegating", NoticeKind::Info);
            return;
        };

        if !self.hello.serves("interactive.delegate") {
            self.inform(
                "this gateway does not serve interactive.delegate",
                NoticeKind::Warn,
            );
            return;
        }

        // Caller-owned for the same reason a start's id is: the verb's ceiling may fire
        // after the child exists, and a repeat under the same id answers with the same
        // delegation rather than making a second one.
        let delegation_id = crate::model::new_session_id();

        let params = self.routed_session_params(
            plane,
            &id,
            json!({ "id": id, "objective": objective, "delegation_id": delegation_id }),
        );

        self.issue(Call::new(
            Tag::Delegate {
                plane,
                id: id.clone(),
            },
            "interactive.delegate",
            params,
        ));

        self.delegating = true;
    }

    pub(super) fn delegated(&mut self, value: &Value) {
        self.delegating = false;

        let Some(reply) = Delegated::decode(value) else {
            self.inform(
                "the runtime answered a delegation this client could not read",
                NoticeKind::Warn,
            );
            return;
        };

        let child = reply
            .task_id
            .clone()
            .unwrap_or_else(|| "the child".to_string());

        self.inform(
            match reply.status.as_deref() {
                Some("existing") => format!("that delegation already exists: {child}"),
                _started => format!("delegated to {child} — it appears under this session"),
            },
            NoticeKind::Info,
        );

        self.refresh_session_lists();
    }

    pub(super) fn open_delegations(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform("open a conversation first", NoticeKind::Info);
            return;
        };

        if !self.hello.serves("interactive.delegations") {
            self.inform(
                "this gateway does not serve interactive.delegations",
                NoticeKind::Warn,
            );
            return;
        }

        let params = self.routed_session_params(plane, &id, json!({ "id": id }));

        self.issue(Call::new(
            Tag::Delegations {
                plane,
                id: id.clone(),
                show: true,
            },
            "interactive.delegations",
            params,
        ));
    }

    /// The same read without the overlay, for the `Ctrl+T` panel.
    pub(super) fn read_delegations(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        if !self.hello.serves("interactive.delegations") {
            return;
        }

        let params = self.routed_session_params(plane, &id, json!({ "id": id }));

        self.issue(Call::new(
            Tag::Delegations {
                plane,
                id,
                show: false,
            },
            "interactive.delegations",
            params,
        ));
    }

    pub(super) fn delegations_read(&mut self, plane: Plane, id: &str, show: bool, value: &Value) {
        let rows = DelegationRow::decode_list(value);

        self.delegations = Some((plane, id.to_string(), rows.clone()));

        if !show {
            return;
        }

        if rows.is_empty() {
            self.inform("this conversation has delegated nothing", NoticeKind::Info);
            return;
        }

        self.overlay = Some(Overlay::Delegations {
            plane,
            id: id.to_string(),
            rows,
            choice: 0,
        });
    }

    /// Opens the transcript of the child the delegations list has selected.
    ///
    /// On the coding plane, because that is what a delegation *is*: a coding task with a
    /// parent, with its own id, its own transcript and its own durable record. There is
    /// no way to message it from here — the parent's composer talks to the parent — and
    /// this client does not pretend otherwise.
    pub(super) fn open_delegation_child(&mut self) {
        let Some(Overlay::Delegations { rows, choice, .. }) = self.overlay.as_ref() else {
            return;
        };

        let Some(row) = rows.get(*choice) else {
            return;
        };

        let Some(task) = row.task_id.clone() else {
            self.inform(
                "the runtime named no task for that delegation yet",
                NoticeKind::Info,
            );
            return;
        };

        let node = row.task_node.clone();

        self.overlay = None;
        self.open_session_on(Plane::Coding, task, node);
    }

    /// The delegations this client last read for the open session.
    pub fn open_delegation_rows(&self) -> &[DelegationRow] {
        let Some((plane, id)) = self.sessions.open.as_ref() else {
            return &[];
        };

        match self.delegations.as_ref() {
            Some((held_plane, held_id, rows)) if held_plane == plane && held_id == id => rows,
            _stale => &[],
        }
    }

    // ----- shared ----------------------------------------------------------------------

    /// Records what one of these verbs answered, in the transcript it was about.
    ///
    /// Silently dropped where the session is not subscribed: a note anchored to a
    /// transcript nobody is holding has nowhere to be, and the notice row has already
    /// said what happened.
    pub(super) fn push_note(&mut self, plane: Plane, id: &str, block: Block) {
        if let Some(watch) = self.sessions.watches.get_mut(&(plane, id.to_string())) {
            watch.local_note(block);
        }
    }

    /// Whether a refusal is the permanent capability answer rather than the retryable one.
    ///
    /// `unsupported_on_transport` means this session will never serve the verb;
    /// `native_transport_unavailable` means it is not up *right now*, which is worth
    /// saying differently because one of the two is worth trying again.
    pub(super) fn native_refusal(error: &ClientError) -> Option<&'static str> {
        let ClientError::Rpc(rpc) = error else {
            return None;
        };

        if rpc.code == ErrorCode::MethodNotFound {
            return None;
        }

        match refusal_tag(rpc.data.as_ref()) {
            Some("unsupported_on_transport") => Some(
                "this session's transport cannot do that — only a native session holds a \
                 conversation this runtime can work on",
            ),
            Some("native_transport_unavailable") => {
                Some("this session's native transport is not up; try again once it is")
            }
            _other => None,
        }
    }
}

/// A command line, cut to something a heading can hold.
pub fn label_command(command: &str) -> String {
    let single: String = command
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ; ");

    if single.chars().count() <= COMMAND_LABEL {
        return single;
    }

    let head: String = single.chars().take(COMMAND_LABEL - 1).collect();
    format!("{head}…")
}
