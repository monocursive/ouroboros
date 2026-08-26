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

use crate::model::transcript::{
    self, Diff, PlanStep, PlanUpdate, PresentationEvent, RunStart, UsageReport,
};
use crate::model::{ApprovalDecision, ApprovalScope, Event, EventType, PlanChoice, Plane};

/// How many events one session's transcript keeps. Past this the oldest are dropped and
/// the floor rises, which is visible rather than silent.
pub const WINDOW: usize = 5_000;

/// How many interruption notes a transcript keeps. A session that lags repeatedly must
/// not accumulate one line per lag forever.
const MAX_NOTES: usize = 64;

/// Something recorded in place among the events, by the stream or by this client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// Frames the gateway discarded under backpressure.
    Lagged { dropped: u64 },
    /// Frames this client's notification channel could not take.
    ClientDropped,
    /// The connection was lost and re-established here.
    Reconnected,
    /// What one of the operator's *own* verbs answered, at the point in the conversation
    /// where they asked: a `/compact` report, a rewind's restored and unrestorable lists,
    /// a `!` command's result (D9, D6, B7).
    ///
    /// Not a claim about the stream and not the agent's words — it is the reply this
    /// client received, drawn where it belongs rather than in a notice row that scrolls
    /// away in four seconds.
    ///
    /// [`Block::key`] is what the runtime's own durable event for the same act is matched
    /// against. The runtime writes a `provider_event` for every compaction and every
    /// operator command, so without it a `!` would draw twice — once from this reply,
    /// once from the event — and the fuller of the two is this one, because a reply
    /// carries the elapsed time and the spill path the event does not.
    ///
    /// [`Block::key`]: crate::ui::transcript_cells::Block::key
    Local {
        block: crate::ui::transcript_cells::Block,
    },
    /// A11. An image that entered the conversation here.
    ///
    /// Client-side for the same reason a `/compact` report is, and for one more: the
    /// runtime's `input_accepted` carries the prompt's `text` and nothing else
    /// (`Interactive.Task.enrich_chat_input/2`), so the attachments a turn was sent with
    /// are simply not in the ledger. Drawing them from the composer's own record is
    /// therefore the only honest way to show them at all — and it is honest, because it is
    /// this client reporting what it itself sent, not a claim about what the runtime saw.
    ///
    /// The consequence is stated rather than hidden: these do **not** survive a reconnect
    /// or a replay from the ledger, because there is nothing in the ledger to replay.
    Image {
        cell: crate::ui::transcript_cells::ImageCell,
    },
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
            Self::Local { block } => block.text(),
            Self::Image { cell } => cell.label(),
        }
    }
}

/// The tail of a transcript, and how much of the ledger it does not reach.
///
/// Two values rather than one because the pane needs both: the entries it draws, and the
/// sentence it draws above them saying what it is not showing. A window that reported only
/// the first would be a transcript that silently starts in the middle.
#[derive(Debug)]
pub struct Recent<'a> {
    pub entries: Vec<Entry<'a>>,
    /// Events held below this window. See [`Watch::recent_entries`] for why events and not
    /// entries.
    pub omitted: usize,
}

/// One approval the session is waiting on.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub sequence: u64,
    pub turn_id: Option<String>,
    pub payload: Value,
}

/// How many provider-offered options one modal will draw.
const APPROVAL_OPTIONS: usize = 8;

/// How many `toolCall.locations` paths one modal will draw.
const APPROVAL_LOCATIONS: usize = 8;

/// How many array entries are searched for a diff before giving up.
const APPROVAL_DIFF_CANDIDATES: usize = 8;

/// How many plan steps the plan-exit modal will draw before saying how many it left out.
///
/// The projection above it already bounds the list; this is the modal's own ceiling, so a
/// hundred-step plan cannot push the three answers off the bottom of the screen.
const PLAN_EXIT_STEPS: usize = 32;

/// B2. One `plan_exit` question, read out of the payload once.
///
/// Present only where `payload.kind` is exactly `"plan_exit"`. Everything else about the
/// approval — its options, its request id, the modal it opens — is the ordinary machinery;
/// this is the extra the question carries, and its absence is what makes an ordinary
/// approval render the ordinary way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanExit {
    /// The runtime's own heading (`"Plan ready"`).
    pub header: Option<String>,
    /// The runtime's own question, including the three sentences describing the choices.
    /// Shown verbatim rather than re-worded: it is the only place the *consequences* of
    /// each answer are stated, and this client does not know them independently.
    pub question: Option<String>,
    /// `plan_tool` or `message` — whether the model used the plan tool or wrote prose.
    /// Labelled rather than hidden, because a plan read out of a final message is a
    /// weaker artifact than a structured one and the modal should not pass it off as a
    /// step list.
    pub source: Option<String>,
    /// The steps, where the turn produced them through the plan tool.
    pub steps: Vec<PlanStep>,
    /// How many steps the runtime sent, which may exceed `steps.len()`.
    pub step_count: usize,
    /// The final message, where the model planned in prose instead.
    pub message: Option<String>,
    /// The three answers, in the payload's own order, each with the vendor's own words.
    pub choices: Vec<PlanOption>,
    /// Options the payload offered that this build cannot map onto a choice it knows how
    /// to send. Named in a note, never drawn as a row: a row that sent something other
    /// than what it said would be the one mistake here that cannot be undone.
    pub unmapped: Vec<String>,
}

/// One plan-exit answer as a row: the wire choice, and the vendor's words for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOption {
    pub choice: PlanChoice,
    pub name: String,
}

impl PlanExit {
    /// `None` for any approval that is not a plan exit, and for a plan exit whose options
    /// this build could not map onto a single known choice — which would be a modal with
    /// no answer it could honestly send, and is better rendered as the ordinary four.
    fn decode(payload: &Value) -> Option<Self> {
        if json_nonempty_str(payload, "kind").as_deref() != Some("plan_exit") {
            return None;
        }

        let mut choices = Vec::new();
        let mut unmapped = Vec::new();

        for option in payload
            .get("options")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .take(APPROVAL_OPTIONS)
        {
            let name = json_nonempty_str(option, "name")
                .or_else(|| json_nonempty_str(option, "label"))
                .unwrap_or_default();

            let id = json_nonempty_str(option, "optionId")
                .or_else(|| json_nonempty_str(option, "option_id"));

            match id.as_deref().and_then(PlanChoice::parse) {
                Some(choice) if !name.is_empty() => choices.push(PlanOption { choice, name }),
                // A named option whose id this build does not know, or one with no name to
                // put on a row. Either way it is reported, not offered.
                _unknown => {
                    if let Some(id) = id.filter(|_| !name.is_empty()) {
                        unmapped.push(format!("{name} ({id})"));
                    } else if !name.is_empty() {
                        unmapped.push(name);
                    }
                }
            }
        }

        if choices.is_empty() {
            return None;
        }

        let plan = payload.get("plan").map(transcript::plan_update);

        Some(Self {
            header: json_nonempty_str(payload, "header"),
            question: json_nonempty_str(payload, "question"),
            source: json_nonempty_str(payload, "plan_source"),
            steps: plan
                .as_ref()
                .map(|plan| {
                    plan.steps
                        .iter()
                        .take(PLAN_EXIT_STEPS)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            step_count: plan.as_ref().map(|plan| plan.step_count).unwrap_or(0),
            message: json_nonempty_str(payload, "message"),
            choices,
            unmapped,
        })
    }

    /// How many steps were sent but not drawn.
    pub fn omitted_steps(&self) -> usize {
        self.step_count.saturating_sub(self.steps.len())
    }
}

/// One answer the provider itself offered, as ACP spells them.
///
/// The `optionId` is kept even though `interactive.respond_approval` refuses
/// `provider_options`: it is what the label *means* on the wire, and a modal that showed a
/// vendor's wording while sending something else would be lying about the button.
/// [`ProviderOption::decision`] is the mapping onto the four-way answer the gateway does
/// accept, and it is the only thing the client acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderOption {
    pub option_id: Option<String>,
    pub name: String,
    pub kind: Option<String>,
}

impl ProviderOption {
    /// Which of the four accepted answers this vendor label corresponds to, where its
    /// `kind` says so. `None` for a `kind` this build does not recognize — an unknown
    /// option is shown with its own words and mapped onto nothing, because guessing
    /// whether a novel option approves or refuses is the one mistake that cannot be undone.
    ///
    /// The tables are `Dialect.ACP.select_permission_option/2`'s, read in the same
    /// direction: there, a decision picks a `kind`; here, a `kind` names the decision it
    /// would have been picked for.
    pub fn decision(&self) -> Option<(ApprovalDecision, ApprovalScope)> {
        match self.kind.as_deref()? {
            "allow_once" | "allow" | "approve" => {
                Some((ApprovalDecision::Approve, ApprovalScope::Once))
            }
            "allow_always" | "allow_session" | "always" => {
                Some((ApprovalDecision::Approve, ApprovalScope::Session))
            }
            "reject_once" | "reject" | "deny" => {
                Some((ApprovalDecision::Deny, ApprovalScope::Once))
            }
            "reject_always" | "deny_always" => {
                Some((ApprovalDecision::Deny, ApprovalScope::Session))
            }
            _unknown => None,
        }
    }
}

/// What the modal draws, read out of the payload once rather than re-derived per frame.
///
/// Every field is optional on purpose: X11's whole complaint was a modal that showed
/// nothing, and the fix is not a modal that *invents* something. A request with no diff
/// says it carries no diff; a provider that named no reason gets no reason line.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalDetail {
    /// `sandbox escalation`, `file change`, `permissions`, or the ACP tool kind — as a
    /// headline, in the words the payload used, spaced rather than snake-cased.
    pub kind: Option<String>,
    /// The provider's own title for the call (ACP `toolCall.title`).
    pub title: Option<String>,
    pub command: Option<String>,
    pub cwd: Option<String>,
    pub reason: Option<String>,
    /// The C1 pattern `Ouroboros.Control.Permissions.suggest/1` computed for this request.
    pub suggested_rule: Option<String>,
    /// Paths the call named (ACP `toolCall.locations`).
    pub locations: Vec<String>,
    pub options: Vec<ProviderOption>,
    pub diff: Option<Diff>,
    /// True when a diff was found but the gateway had already excerpted the leaf, so its
    /// `+`/`-` counts describe the prefix and not the patch.
    pub diff_excerpted: bool,
    /// ACP `{"type": "diff", path, oldText, newText}` content blocks, which carry whole
    /// file bodies rather than a patch. Named rather than diffed — see [`ApprovalEdit`].
    pub edits: Vec<ApprovalEdit>,
    /// B2. Present only for a `plan_exit` question, and the thing the dedicated modal
    /// branches on. `None` is every other approval this runtime raises.
    pub plan: Option<PlanExit>,
    /// Present only where a child agent relayed this request through its parent.
    pub subagent: Option<ApprovalSubagent>,
}

/// Which child agent relayed this request, where the runtime said so.
///
/// `Native.Loop.subagent_approval/2` forwards the child's own payload whole and adds one
/// `subagent` object naming the asker: its description, its task id, and the node it runs
/// on. Every field is optional — an older runtime, or the fallback for a child whose
/// payload was unreadable, may carry any subset — and the object's presence alone is worth
/// the line: this permission was asked for by a child, not by the session itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSubagent {
    pub description: Option<String>,
    pub task_id: Option<String>,
    /// The fleet machine the child runs on.
    pub node: Option<String>,
    /// A runtime that says outright the child ran elsewhere. Today's `subagent_approval/2`
    /// sends only the node, but a payload that does say so is believed without a node
    /// comparison — the same deference `SubagentCell` gives the flag.
    pub remote: Option<bool>,
}

impl ApprovalSubagent {
    /// `None` for every approval the session asked for itself.
    fn decode(payload: &Value) -> Option<Self> {
        let subagent = payload.get("subagent")?;
        subagent.as_object()?;

        Some(Self {
            description: json_nonempty_str(subagent, "description"),
            task_id: json_nonempty_str(subagent, "task_id"),
            node: json_nonempty_str(subagent, "node"),
            remote: subagent.get("remote").and_then(Value::as_bool),
        })
    }

    /// `asked by subagent <description> (<task_id>)`, from whatever subset arrived.
    pub fn attribution(&self) -> String {
        match (self.description.as_deref(), self.task_id.as_deref()) {
            (Some(description), Some(task_id)) => {
                format!("asked by subagent {description} ({task_id})")
            }
            (Some(description), None) => format!("asked by subagent {description}"),
            (None, Some(task_id)) => format!("asked by subagent ({task_id})"),
            (None, None) => "asked by a subagent".to_string(),
        }
    }

    /// The machine the child runs on, only where that is news: the payload marked the
    /// child remote, or named a node that is not the session's own. Every child runs
    /// *somewhere*, so a node on every line would hide the one case that changes the
    /// question — an answer here authorizing a write to a machine the approver is not
    /// looking at.
    pub fn remote_node(&self, session_node: Option<&str>) -> Option<&str> {
        let elsewhere = match (self.node.as_deref(), session_node) {
            (Some(node), Some(local)) => node != local,
            // A node with no local to compare against says nothing about remoteness,
            // exactly as a `node` without `remote` does on the transcript's child row.
            _unknown => false,
        };

        if self.remote == Some(true) || elsewhere {
            Some(self.node.as_deref().unwrap_or("another machine"))
        } else {
            None
        }
    }

    /// The whole line, for a surface that draws it unstyled.
    pub fn line(&self, session_node: Option<&str>) -> String {
        match self.remote_node(session_node) {
            Some(node) => format!("{} on {}", self.attribution(), node),
            None => self.attribution(),
        }
    }
}

/// One ACP diff content block, described rather than rendered as a patch.
///
/// The ACP v1 schema spells a file edit as the whole `oldText` and `newText`, not as a
/// unified diff, and `Dialect.ACP` computes the patch server-side only when the edit
/// becomes a `file_change` event. This client does not compute a second one: a patch it
/// derived itself could disagree with the one the transcript will show, and a modal that
/// showed a diff the runtime never produced would be asserting an edit nobody made. So
/// the modal names the path, the kind, and the two sizes, and says where the patch is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalEdit {
    pub path: String,
    /// `add`, `delete`, or `update` — `Dialect.ACP.change_kind/2`'s own three, from the
    /// same nullness test.
    pub kind: &'static str,
    pub old_bytes: usize,
    pub new_bytes: usize,
}

impl ApprovalRequest {
    /// Whether this request is a question for a person rather than a permission: the
    /// plan-exit question (B2), or the native agent's `ask_user` tool riding the
    /// approval channel with `kind: "question"`.
    ///
    /// The auto-approve mode reads this before answering. Leaving plan mode changes
    /// what every later turn may do, and `ouro run --approve-all` already established
    /// that "answer the approvals" does not include "reconfigure the session" (see
    /// `run.rs::answer_plan_exit`). An `ask_user` question is worse: a robot `approve`
    /// carries no `choice`, so the runtime hands the agent "the operator acknowledged
    /// the question without giving an answer" — the one outcome the tool exists to
    /// prevent.
    pub fn question(&self) -> bool {
        matches!(
            json_nonempty_str(&self.payload, "kind").as_deref(),
            Some("plan_exit") | Some("question")
        ) || self.computer_use()
    }

    /// Computer Use observe/act. Auto-approve must not invent an app allow.
    pub fn computer_use(&self) -> bool {
        matches!(
            self.payload
                .pointer("/tool_call/name")
                .and_then(Value::as_str),
            Some("desktop_state") | Some("desktop_act")
        )
    }

    /// The tool call the provider is asking permission for, as one line.
    ///
    /// A sandbox escalation should read as `git commit … — writes to .git`, not as the
    /// raw JSON blob of `tool_call`.
    pub fn subject(&self) -> String {
        // B2. A plan exit names no command and no tool, so the generic fallback would
        // render the whole payload as JSON in the snack bar. Its own header is the
        // sentence a person needs there.
        if json_nonempty_str(&self.payload, "kind").as_deref() == Some("plan_exit") {
            return json_nonempty_str(&self.payload, "header")
                .unwrap_or_else(|| "plan ready — build it, or keep planning".to_string());
        }

        let command = approval_command(&self.payload);
        let reason = json_nonempty_str(&self.payload, "reason");

        match (command.as_deref(), reason.as_deref()) {
            (Some(command), Some(reason)) => format!("{command} — {reason}"),
            (Some(command), None) => command.to_string(),
            (None, _) => fallback_subject(&self.payload),
        }
    }

    /// Everything the payload actually carries, for the modal to draw.
    pub fn detail(&self) -> ApprovalDetail {
        let payload = &self.payload;
        let call = payload
            .pointer("/tool_call")
            .or_else(|| payload.pointer("/toolCall"))
            .or_else(|| payload.pointer("/tool"));

        let kind = json_nonempty_str(payload, "kind")
            .or_else(|| call.and_then(|call| json_nonempty_str(call, "kind")))
            .or_else(|| call.and_then(|call| json_nonempty_str(call, "name")))
            .map(|kind| kind.replace('_', " "));

        let (diff, diff_excerpted) = approval_diff(payload, call);

        ApprovalDetail {
            kind,
            title: call.and_then(|call| json_nonempty_str(call, "title")),
            command: approval_command(payload),
            cwd: call
                .and_then(|call| json_nonempty_str(call, "cwd"))
                .or_else(|| json_nonempty_str(payload, "cwd")),
            reason: json_nonempty_str(payload, "reason"),
            suggested_rule: json_nonempty_str(payload, "suggested_rule"),
            locations: call.map(approval_locations).unwrap_or_default(),
            options: approval_options(payload),
            diff,
            diff_excerpted,
            edits: call.map(approval_edits).unwrap_or_default(),
            plan: PlanExit::decode(payload),
            subagent: ApprovalSubagent::decode(payload),
        }
    }
}

/// ACP diff content blocks under `toolCall.content`, in the order the provider listed them.
fn approval_edits(call: &Value) -> Vec<ApprovalEdit> {
    call.get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("diff"))
                .filter_map(|block| {
                    let path = json_nonempty_str(block, "path")?;
                    let old = block.get("oldText").and_then(Value::as_str);
                    let new = block.get("newText").and_then(Value::as_str);

                    Some(ApprovalEdit {
                        path,
                        kind: match (old, new) {
                            (None, _) => "add",
                            (_, None) => "delete",
                            _both => "update",
                        },
                        old_bytes: old.map(str::len).unwrap_or(0),
                        new_bytes: new.map(str::len).unwrap_or(0),
                    })
                })
                .take(APPROVAL_LOCATIONS)
                .collect()
        })
        .unwrap_or_default()
}

/// ACP's `options: [{optionId, name, kind}]`, in the order the provider listed them.
///
/// Bounded at [`APPROVAL_OPTIONS`]: these are drawn as rows in a modal, and a provider
/// that offered two hundred of them would push the command off the screen.
fn approval_options(payload: &Value) -> Vec<ProviderOption> {
    payload
        .get("options")
        .and_then(Value::as_array)
        .map(|options| {
            options
                .iter()
                .filter_map(|option| {
                    let name = json_nonempty_str(option, "name")
                        .or_else(|| json_nonempty_str(option, "label"))?;

                    Some(ProviderOption {
                        option_id: json_nonempty_str(option, "optionId")
                            .or_else(|| json_nonempty_str(option, "option_id")),
                        name,
                        kind: json_nonempty_str(option, "kind"),
                    })
                })
                .take(APPROVAL_OPTIONS)
                .collect()
        })
        .unwrap_or_default()
}

/// ACP's `toolCall.locations: [{path, line?}]`, paths only.
fn approval_locations(call: &Value) -> Vec<String> {
    call.get("locations")
        .and_then(Value::as_array)
        .map(|locations| {
            locations
                .iter()
                .filter_map(|location| match location {
                    Value::String(path) => nonempty_trimmed(path),
                    other => json_nonempty_str(other, "path"),
                })
                .take(APPROVAL_LOCATIONS)
                .collect()
        })
        .unwrap_or_default()
}

/// The patch this request is asking about, wherever the dialect put it.
///
/// Three shapes are known and named: a Codex `file_change` payload's `diff`, an ACP
/// content block `{"type": "diff", …}` under `toolCall.content`, and the `changes` list
/// `Dialect.ACP` maps a `diff` update into. The parse is
/// [`crate::model::transcript::Diff::parse`] in every case — the transcript's own parser,
/// not a second one that could disagree with it about what a hunk is.
///
/// The second half of the pair is whether the gateway had already excerpted the leaf. An
/// excerpt is still worth showing; a diffstat computed from one is not a diffstat.
fn approval_diff(payload: &Value, call: Option<&Value>) -> (Option<Diff>, bool) {
    let mut candidates: Vec<&Value> = Vec::new();

    for source in [Some(payload), call].into_iter().flatten() {
        for key in ["diff", "patch", "unified_diff", "unifiedDiff"] {
            if let Some(value) = source.get(key) {
                candidates.push(value);
            }
        }

        for key in ["content", "changes"] {
            let Some(items) = source.get(key).and_then(Value::as_array) else {
                continue;
            };

            for item in items.iter().take(APPROVAL_DIFF_CANDIDATES) {
                for key in ["diff", "patch"] {
                    if let Some(value) = item.get(key) {
                        candidates.push(value);
                    }
                }
            }
        }
    }

    for candidate in candidates {
        match candidate {
            Value::String(text) => {
                let text = text.trim();
                if !text.is_empty() {
                    return (Some(Diff::parse(text)), false);
                }
            }
            Value::Object(_) => {
                // `{"_excerpt": prefix, "_bytes": n}`: the gateway cut this leaf. Draw the
                // prefix, and say it is a prefix.
                if let Some(excerpt) = candidate.get("_excerpt").and_then(Value::as_str) {
                    let mut diff = Diff::parse(excerpt);
                    diff.truncated = true;
                    return (Some(diff), true);
                }

                if let Some(text) = candidate.get("diff").and_then(Value::as_str) {
                    let text = text.trim();
                    if !text.is_empty() {
                        return (Some(Diff::parse(text)), false);
                    }
                }
            }
            _other => {}
        }
    }

    (None, false)
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
    /// B2. The newest planning posture an event reported, or `None` where none has.
    planning: Option<bool>,
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
            planning: None,
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

    /// The last `limit` user turns, oldest first, for the backtrack menu (B5).
    ///
    /// Read out of `input_accepted`, which is the durable record of what this session was
    /// actually asked — not out of the composer's own history, which is per client and
    /// would show a second `ouro` a list of prompts nobody on this screen ever typed.
    /// A steer is excluded: it is an injection into a turn, not a turn to go back to.
    pub fn recent_user_turns(&self, limit: usize) -> Vec<(u64, String)> {
        let mut turns = self
            .events
            .iter()
            .rev()
            .filter(|(_sequence, event)| event.kind == EventType::InputAccepted)
            .filter(|(_sequence, event)| {
                event
                    .payload
                    .get("kind")
                    .and_then(|kind| kind.as_str())
                    .map(|kind| kind != "steer")
                    .unwrap_or(true)
            })
            .filter_map(|(sequence, event)| {
                event
                    .payload
                    .get("text")
                    .and_then(|text| text.as_str())
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .map(|text| (*sequence, text.to_string()))
            })
            .take(limit)
            .collect::<Vec<_>>();

        turns.reverse();
        turns
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
            self.events.insert(event.sequence, event);
        }

        self.trim();
        self.recompute_cursor();
        self.recompute_interactive_state();
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

    /// Records what one of the operator's own verbs answered, at the tail of what this
    /// transcript currently holds.
    ///
    /// Anchored at the newest sequence for the same reason a stream note is: the reply
    /// arrived *now*, and putting it anywhere else would place it beside a turn it is not
    /// about. It shares `MAX_NOTES` with the stream notes, so a session that compacts and
    /// runs commands all day keeps the newest sixty-four of both rather than growing
    /// without bound.
    pub fn local_note(&mut self, block: crate::ui::transcript_cells::Block) {
        self.note(Note::Local { block }, self.newest());
    }

    /// A11. Records an image the composer just sent, where the conversation is now.
    pub fn image_note(&mut self, cell: crate::ui::transcript_cells::ImageCell) {
        self.note(Note::Image { cell }, self.newest());
    }

    /// A11. The most recently recorded image in this conversation, by the path it was
    /// named with. `None` where none was sent — and where the notes have rolled past it,
    /// which is the same bound every other note lives under.
    pub fn newest_image(&self) -> Option<String> {
        self.notes.values().rev().find_map(|note| match note {
            Note::Image { cell } => Some(cell.named.clone()),
            _otherwise => None,
        })
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

    /// Whether one request is still waiting on an answer: pending, and no response in
    /// flight for it. The auto-approve toggle closes an open modal only where this says
    /// its request was actually answered underneath it — a plan-exit or `ask_user`
    /// question the flush skipped keeps its modal.
    pub fn awaiting_answer(&self, request_id: &str) -> bool {
        self.pending_approvals
            .values()
            .any(|request| request.request_id == request_id)
            && !self.approval_responses_in_flight.contains(request_id)
    }

    /// How many approvals are actually waiting on an answer: pending, minus the ones a
    /// response is already in flight for. The footer's count, the bell, and triage all
    /// want this rather than [`pending_approvals`](Self::pending_approvals) — an approval
    /// this client has answered but the runtime has not resolved yet is not waiting on
    /// anyone here, and under auto-approve it would otherwise read as "needs input" for
    /// the round-trip's duration on every tool call.
    pub fn unanswered_approvals(&self) -> usize {
        self.pending_approvals
            .values()
            .filter(|request| {
                !self
                    .approval_responses_in_flight
                    .contains(&request.request_id)
            })
            .count()
    }

    /// The transcript in order, with the dividers interleaved where they belong.
    ///
    /// Walks the whole retained ledger. The conversation pane does not use this — see
    /// [`Self::recent_entries`] — but `/export`, `/details`, and the footer's turn scan do,
    /// because each of them is answering a question about the whole session rather than
    /// drawing one frame of it.
    pub fn entries(&self) -> Vec<Entry<'_>> {
        self.entries_from(None)
    }

    /// The last `limit` entries, and how many events sit below them.
    ///
    /// ## Why this exists
    ///
    /// The pane projects a bounded suffix of the ledger and always has
    /// ([`crate::ui::transcript_cells::CHAT_ENTRY_WINDOW`]). It used to get there by
    /// building the whole list — five thousand `Entry` values, on every frame, twelve
    /// times a second — and throwing away all but the last hundred and twenty-eight. That
    /// is the O(entries) shape A12 exists to catch: measured at roughly half a millisecond
    /// of a three-millisecond debug frame, small today and unbounded in principle.
    ///
    /// This walks the last `limit` *events* — `BTreeMap` iterates backwards in the same
    /// time it iterates forwards — and then runs exactly the same interleaving from there,
    /// so what comes out is the tail of [`Self::entries`] and `tests/perf.rs` asserts that
    /// it is.
    ///
    /// ## What `omitted` counts
    ///
    /// Events, not entries. The number of *entries* below a window cannot be had without
    /// walking to it — gaps are only knowable by looking — and a count that cost the walk
    /// it exists to avoid would be a strange thing to compute. Events are exact, `O(1)`
    /// against the map's own length, and the more useful number anyway: it is how much of
    /// the ledger the pane is not drawing.
    pub fn recent_entries(&self, limit: usize) -> Recent<'_> {
        // `nth` from the back rather than `take(…).last()`: the point of this walk is that
        // it does not touch the events below the window.
        let first = self
            .events
            .keys()
            .rev()
            .nth(limit.max(1) - 1)
            .or_else(|| self.events.keys().next())
            .copied();

        let mut entries = match first {
            // Fewer events than the window: the bounded walk and the whole one are the
            // same walk, and starting it early would only re-derive the same answer.
            Some(_) if self.events.len() <= limit => self.entries_from(None),
            first => self.entries_from(first),
        };

        // The forward walk from a bounded start can produce more than `limit` entries — a
        // gap and the notes around it are entries too — so the tail is taken here.
        if entries.len() > limit {
            entries = entries.split_off(entries.len() - limit);
        }

        Recent {
            omitted: self
                .events
                .len()
                .saturating_sub(self.events.range(first.unwrap_or(0)..).take(limit).count()),
            entries,
        }
    }

    /// [`Self::entries`], optionally starting at an event rather than at the beginning.
    ///
    /// One function for both so the interleaving rules — where a floor marker sits, when a
    /// gap is drawn, which notes belong before which event — exist once. A second copy of
    /// them is a second thing to keep true, and the pane and the export would diverge on
    /// the frame nobody looked at.
    fn entries_from(&self, first: Option<u64>) -> Vec<Entry<'_>> {
        let bounded = first.is_some();
        let start = first.unwrap_or(0);

        let mut entries = Vec::with_capacity(match bounded {
            true => self.notes.len() + 2,
            false => self.events.len() + self.notes.len() + 2,
        });

        // The floor sits where the hole is, not at the top: a client that held events
        // before a prune still holds them, and they are still history. A bounded walk that
        // begins above the floor has begun above the marker too — the whole walk drew it
        // before an event this one is not reaching — but a window wide enough to reach
        // below it still has to draw it, which is the case a `bounded` test alone gets
        // wrong.
        let mut floor_emitted = self.floor == 0 || (bounded && start > self.floor);

        // The event just below the window, so a hole across the boundary is drawn exactly
        // where the unbounded walk draws it.
        let mut previous: Option<u64> = match bounded {
            true => self.events.range(..start).next_back().map(|(at, _)| *at),
            false => None,
        };
        // Where the whole walk's `notes_from` would stand at this point: just past the
        // event below the window, or at the very beginning when there is no event below it.
        let mut notes_from = previous.map_or(0, |previous| previous + 1);

        for (sequence, event) in self.events.range(start..) {
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

            notes_from = notes_from.max(self.floor + 1);
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

    /// B2. Whether this session is planning, where an event said so since the last list.
    ///
    /// `None` means no event has spoken, and the caller falls back to `options.plan` from
    /// the session row. It is not the same as `Some(false)`: a session list that predates
    /// plan mode and a runtime that just left plan mode are different facts, and only the
    /// second one should be able to take a badge *down*.
    pub fn planning(&self) -> Option<bool> {
        self.planning
    }

    /// Rebuilds order-sensitive interactive state from the ordered ledger.
    ///
    /// Live notifications and replay responses are not ordered against each other. Folding
    /// these fields as batches arrive can therefore apply an older request after its newer
    /// resolution. The `BTreeMap` is the authority: replay overlap is idempotent, and one
    /// ordered pass makes approval and planning state independent of arrival order.
    fn recompute_interactive_state(&mut self) {
        let mut planning = None;
        let mut pending = BTreeMap::new();

        for event in self.events.values() {
            let payload = &event.payload;
            let kind = json_nonempty_str(payload, "kind");

            match (&event.kind, kind.as_deref()) {
                (EventType::ProviderEvent, Some("plan_exit")) => {
                    if let Some(value) = payload.get("plan").and_then(Value::as_bool) {
                        planning = Some(value);
                    }
                }
                (EventType::Other(other), Some("configured")) if other == "status" => {
                    if let Some(value) = payload.pointer("/changed/plan").and_then(Value::as_bool) {
                        planning = Some(value);
                    }
                }
                _other => {}
            }

            let Some(request_id) = event.request_id.clone() else {
                continue;
            };

            match &event.kind {
                EventType::ApprovalRequested => {
                    pending.insert(
                        event.sequence,
                        ApprovalRequest {
                            request_id,
                            sequence: event.sequence,
                            turn_id: event.turn_id.clone(),
                            payload: event.payload.clone(),
                        },
                    );
                }
                EventType::ApprovalResolved => {
                    pending.retain(|_, request| request.request_id != request_id);
                }
                _other => {}
            }
        }

        self.planning = planning;
        self.pending_approvals = pending;
        self.approval_responses_in_flight.retain(|request_id| {
            self.pending_approvals
                .values()
                .any(|request| &request.request_id == request_id)
        });
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

    /// The bounded walk's whole contract: whatever the ledger holds, and whatever markers
    /// are interleaved through it, `recent_entries(n)` is the last `n` of `entries()`.
    ///
    /// Driven over a ledger with all four of them — a raised floor, a hole, notes, and a
    /// terminal status — because the interleaving rules are exactly where a second walk
    /// would drift from the first.
    #[test]
    fn the_bounded_walk_is_the_tail_of_the_whole_one() {
        let mut watch = watch();

        watch.absorb((1..=40).map(event).collect());
        // A hole in the middle, so a gap marker sits between two events.
        watch.absorb((60..=120).map(event).collect());
        watch.note(Note::Lagged { dropped: 19 }, 41);
        watch.note(Note::Reconnected, 100);
        watch.raise_floor(5);
        watch.end("completed".into());

        let whole = watch.entries();
        assert!(
            whole.iter().any(|entry| matches!(entry, Entry::Gap { .. })),
            "the fixture has no hole to walk across"
        );

        for limit in [1, 2, 7, 40, 61, 100, whole.len(), whole.len() + 50] {
            let recent = watch.recent_entries(limit);

            assert!(
                recent.entries.len() <= limit,
                "asked for {limit}, got {}",
                recent.entries.len()
            );

            let tail = &whole[whole.len().saturating_sub(recent.entries.len())..];
            assert_eq!(
                format!("{:?}", recent.entries),
                format!("{tail:?}"),
                "the bounded walk at {limit} is not the tail of the whole one"
            );
        }

        // Nothing left out when the window reaches past the ledger.
        assert_eq!(watch.recent_entries(whole.len() + 50).omitted, 0);
        // …and what is left out is counted in events.
        let recent = watch.recent_entries(10);
        assert_eq!(recent.omitted, watch.len() - 10);
    }

    #[test]
    fn a_bounded_walk_over_a_short_ledger_is_the_whole_ledger() {
        let mut watch = watch();
        watch.absorb((1..=3).map(event).collect());

        let recent = watch.recent_entries(128);
        assert_eq!(recent.omitted, 0);
        assert_eq!(
            format!("{:?}", recent.entries),
            format!("{:?}", watch.entries())
        );

        // An empty ledger walks to nothing rather than to a panic.
        let empty = Watch::new(Plane::Interactive, "empty".into());
        assert!(empty.recent_entries(128).entries.is_empty());
        assert_eq!(empty.recent_entries(128).omitted, 0);
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
    fn a_replayed_request_cannot_resurrect_a_newer_resolution() {
        let mut watch = watch();
        let resolved = Event::decode(&json!({
            "id": "evt-3",
            "sequence": 3,
            "type": "approval_resolved",
            "timestamp": "t",
            "request_id": "req-a",
            "payload": {}
        }))
        .expect("a resolution");

        watch.absorb(vec![event(1), resolved]);
        assert!(watch.next_approval().is_none());

        // The request was the lost frame and arrives later from replay. Folding by arrival
        // would revive it; folding the ordered ledger sees the resolution after it.
        watch.absorb(vec![approval(2, "req-a")]);
        assert!(watch.next_approval().is_none());
        assert_eq!(watch.cursor(), 3);
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

    fn typed(sequence: u64, kind: &str, payload: serde_json::Value) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "turn_id": "turn-1",
            "payload": payload
        }))
        .expect("an event")
    }

    /// A replay overlaps the live stream by design. Totals accumulated as events arrived
    /// would count the overlap; these are folded out of the held ledger instead.
    #[test]
    fn usage_totals_survive_the_overlap_every_replay_produces() {
        let mut watch = watch();
        let reports = vec![
            typed(
                1,
                "usage",
                json!({"input_tokens": 100, "output_tokens": 10}),
            ),
            typed(2, "usage", json!({"input_tokens": 50, "output_tokens": 5})),
        ];

        watch.absorb(reports.clone());
        let once = watch.usage();

        // The same two events again, as a replay answer would deliver them.
        watch.absorb(reports);

        assert_eq!(
            watch.usage(),
            once,
            "a replayed report is not a second report"
        );
        assert_eq!(once.reports, 2);
        assert_eq!(once.input_tokens, 150);
        assert_eq!(once.output_tokens, 15);
        assert_eq!(
            once.total_tokens, 165,
            "derived when the provider sent no total"
        );
        assert!(once.complete);
    }

    /// Once history is gone the totals are a lower bound, and the accessor says so rather
    /// than letting a footer present them as the session's whole cost.
    #[test]
    fn usage_totals_state_when_they_no_longer_cover_the_whole_session() {
        let mut watch = watch();

        watch.absorb(vec![typed(5, "usage", json!({"input_tokens": 100}))]);
        assert!(watch.usage().complete);

        watch.raise_floor(4);
        watch.absorb(vec![typed(6, "usage", json!({"input_tokens": 1}))]);

        assert!(
            !watch.usage().complete,
            "a pruned transcript cannot claim a complete total"
        );
    }

    #[test]
    fn a_run_completed_cost_reaches_the_total_because_nothing_else_reports_one() {
        let mut watch = watch();

        watch.absorb(vec![
            typed(1, "usage", json!({"input_tokens": 10, "output_tokens": 2})),
            typed(
                2,
                "run_completed",
                json!({"cost_usd": 0.0125, "num_turns": 3}),
            ),
        ]);

        assert_eq!(watch.usage().cost_usd, Some(0.0125));
    }

    #[test]
    fn the_queue_depth_is_the_newest_one_the_runtime_reported() {
        let mut watch = watch();

        assert_eq!(watch.queue_len(), 0);

        watch.absorb(vec![
            typed(1, "queue_changed", json!({"queued_turns": 3})),
            typed(2, "queue_changed", json!({"queued_turns": 1})),
        ]);

        assert_eq!(watch.queue_len(), 1);
    }

    /// Only `run_started` ever names a model, and only some providers send one.
    #[test]
    fn the_model_is_whatever_a_run_named_and_otherwise_nothing() {
        let mut watch = watch();

        watch.absorb(vec![typed(1, "session_ready", json!({"transport": "acp"}))]);
        assert_eq!(watch.model(), None, "no provider named a model");

        watch.absorb(vec![typed(
            2,
            "run_started",
            json!({"model": "claude-sonnet-5", "tools": []}),
        )]);
        assert_eq!(watch.model(), Some("claude-sonnet-5"));
    }

    #[test]
    fn the_latest_plan_is_the_newest_one_in_whichever_dialect_it_arrived() {
        let mut watch = watch();

        assert!(watch.latest_plan().is_none());

        watch.absorb(vec![typed(
            1,
            "plan_updated",
            json!({"plan": [{"step": "first", "status": "pending"}]}),
        )]);
        assert_eq!(watch.latest_plan().map(|plan| plan.steps.len()), Some(1));

        watch.absorb(vec![typed(
            2,
            "plan_updated",
            json!({"entries": [
                {"content": "first", "status": "completed"},
                {"content": "second", "status": "in_progress"}
            ]}),
        )]);

        let plan = watch.latest_plan().expect("the newest plan");
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].text, "second");
    }

    /// The panel must not lose the plan when the agent stops working: a task list that
    /// vanishes while idle is the documented Codex anti-pattern.
    #[test]
    fn the_latest_plan_survives_the_session_going_idle() {
        let mut watch = watch();

        watch.absorb(vec![
            typed(1, "plan_updated", json!({"plan": [{"step": "ship it"}]})),
            typed(2, "turn_completed", json!({})),
            typed(3, "session_idle", json!({})),
        ]);

        assert_eq!(watch.latest_plan().map(|plan| plan.steps.len()), Some(1));
    }

    #[test]
    fn an_elapsed_turn_is_reported_only_while_one_is_actually_running() {
        let mut watch = watch();

        assert_eq!(watch.active_turn_elapsed(), None);

        // A start far in the past: the elapsed time is real wall-clock arithmetic, so this
        // asserts the sign and the source rather than an exact figure.
        watch.absorb(vec![typed(1, "turn_started", json!({}))]);
        let elapsed = watch.active_turn_elapsed().expect("a running turn");
        assert!(elapsed > 0, "{elapsed}");

        watch.absorb(vec![typed(2, "turn_completed", json!({}))]);
        assert_eq!(
            watch.active_turn_elapsed(),
            None,
            "a finished turn is not still running"
        );

        watch.absorb(vec![typed(3, "turn_started", json!({}))]);
        assert!(watch.active_turn_elapsed().is_some());
        watch.end("closed".into());
        assert_eq!(
            watch.active_turn_elapsed(),
            None,
            "an ended stream has no running turn"
        );
    }

    /// An event whose timestamp this build cannot read must produce no elapsed time rather
    /// than one measured from the epoch.
    #[test]
    fn an_unreadable_timestamp_yields_no_elapsed_turn() {
        let mut watch = watch();

        watch.absorb(vec![Event::decode(&json!({
            "id": "evt-1",
            "sequence": 1,
            "type": "turn_started",
            "timestamp": "",
            "turn_id": "turn-1",
            "payload": {}
        }))
        .expect("an event")]);

        assert_eq!(watch.active_turn_elapsed(), None);
    }
}
