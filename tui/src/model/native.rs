//! The answer shapes of the verbs that landed with D9, D6, B7 and G1.
//!
//! Every type here is a *projection*, not a schema: it reads the keys this client draws
//! and keeps the whole object beside them for the tree widget, exactly as [`SessionInfo`]
//! does. Nothing below refuses a payload for carrying a key this build has not heard of,
//! and nothing below invents one it did not carry — an absent number stays `None` and is
//! not drawn, because a context meter with a zero in it reads as a measurement.
//!
//! [`SessionInfo`]: crate::model::SessionInfo

use serde_json::Value;

use super::transcript::leaf_text;

/// How long a digest, an id, or a reason may be before it stops being a label.
const LABEL_BYTES: usize = 256;

/// What a value cut short says about itself, in the same words the transcript uses.
const TRUNCATION: &str = "… (truncated by this client)";

/// Cuts on a character boundary, never inside one: a digest is ASCII but a path and a
/// refusal message are not, and slicing a UTF-8 string by byte index panics.
fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }

    let mut end = limit.saturating_sub(TRUNCATION.len());

    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    format!("{}{TRUNCATION}", &text[..end])
}

/// `Ns`, `Nm Ns`, or `Nms` — the same three shapes the transcript's own tool rows use.
fn duration(milliseconds: u64) -> String {
    if milliseconds < 1_000 {
        return format!("{milliseconds}ms");
    }

    let seconds = milliseconds / 1_000;

    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m {}s", seconds / 60, seconds % 60)
    }
}

/// How many rows of a list this client will hold from one answer. Bounded here rather
/// than at the draw, so a runtime that answered with ten thousand rewind points costs one
/// bounded allocation instead of one per frame.
pub const MAX_ROWS: usize = 512;

/// How many paths one rewind point names before the rest are counted.
pub const MAX_PATHS: usize = 20;

fn string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| bounded(text, LABEL_BYTES))
}

fn at(map: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    string(map.get(key))
}

fn count(map: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    map.get(key).and_then(Value::as_u64)
}

fn flag(map: &serde_json::Map<String, Value>, key: &str) -> Option<bool> {
    map.get(key).and_then(Value::as_bool)
}

/// A free-text field that is a *sentence* rather than a label, so it gets a longer bound.
fn sentence(map: &serde_json::Map<String, Value>, key: &str, limit: usize) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| bounded(text, limit))
}

/// The `git worktree` a session was given, as `interactive.list` reports it (D7).
///
/// `retired` is the field that keeps the badge honest: a worktree the runtime removed —
/// or kept because it still held uncommitted work — is not somewhere this session is
/// still editing, and the rail says so rather than showing a live branch for a directory
/// that is gone.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Worktree {
    pub path: Option<String>,
    pub root: Option<String>,
    pub branch: Option<String>,
    pub base_commit: Option<String>,
    pub repository: Option<String>,
    /// `"removed"` or `"kept"` once the session ended, absent while it is live.
    pub retired: Option<String>,
}

impl Worktree {
    pub fn decode(value: Option<&Value>) -> Option<Self> {
        let map = value.and_then(Value::as_object)?;

        Some(Self {
            path: at(map, "path"),
            root: at(map, "root"),
            branch: at(map, "branch"),
            base_commit: at(map, "base_commit"),
            repository: at(map, "repository"),
            retired: at(map, "retired"),
        })
    }

    /// What the badge says after `⎇`. The branch where `git worktree add` made one, the
    /// detached base commit's short form where it did not, and the bare word otherwise —
    /// never a path, which is too long for a rail and is in the header already.
    pub fn label(&self) -> String {
        match (&self.branch, &self.base_commit) {
            (Some(branch), _) => branch.clone(),
            (None, Some(commit)) => commit.chars().take(8).collect(),
            (None, None) => "worktree".to_string(),
        }
    }

    pub fn live(&self) -> bool {
        self.retired.is_none()
    }
}

/// The other half of a delegation's nesting: which conversation owns this coding task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    pub plane: Option<String>,
    pub id: String,
}

impl Parent {
    pub fn decode(value: Option<&Value>) -> Option<Self> {
        let map = value.and_then(Value::as_object)?;

        Some(Self {
            plane: at(map, "plane"),
            id: at(map, "id")?,
        })
    }
}

/// One fold of a conversation, as `interactive.compact` and the durable `compaction`
/// event both report it (D9).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Compaction {
    /// `"manual"` for the operator's own `/compact`, `"automatic"` for the threshold.
    pub trigger: Option<String>,
    pub turn: Option<u64>,
    pub archived_messages: Option<u64>,
    /// The archive the folded conversation was written to. Named, never fetched: the
    /// bodies are the conversation that was just folded away.
    pub archive_id: Option<String>,
    pub elided_tool_results: Option<u64>,
    pub summary_tokens: Option<u64>,
    pub before_tokens: Option<u64>,
    pub after_tokens: Option<u64>,
    pub summarised: Option<bool>,
}

impl Compaction {
    pub fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        Some(Self {
            trigger: at(map, "trigger"),
            turn: count(map, "turn"),
            archived_messages: count(map, "archived_messages"),
            archive_id: at(map, "archive_id"),
            elided_tool_results: count(map, "elided_tool_results"),
            summary_tokens: count(map, "summary_tokens"),
            before_tokens: count(map, "before_tokens"),
            after_tokens: count(map, "after_tokens"),
            summarised: flag(map, "summarised"),
        })
    }

    /// One line for a transcript note. Only the numbers the report carried: a fold that
    /// elided tool results without summarising says so by omitting the summary, rather
    /// than by printing a zero that reads as "the summary was empty".
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();

        if let Some(messages) = self.archived_messages.filter(|count| *count > 0) {
            parts.push(format!(
                "archived {messages} message{}",
                if messages == 1 { "" } else { "s" }
            ));
        }

        if let Some(elided) = self.elided_tool_results.filter(|count| *count > 0) {
            parts.push(format!(
                "elided {elided} tool result{}",
                if elided == 1 { "" } else { "s" }
            ));
        }

        match (self.before_tokens, self.after_tokens) {
            (Some(before), Some(after)) => parts.push(format!("{before} → {after} tokens")),
            (Some(before), None) => parts.push(format!("{before} tokens before")),
            (None, Some(after)) => parts.push(format!("{after} tokens after")),
            (None, None) => {}
        }

        if let Some(archive) = &self.archive_id {
            parts.push(format!("archive {archive}"));
        }

        if parts.is_empty() {
            "the conversation was folded".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

/// What `interactive.context` answered (D9).
///
/// `source` is the field the overlay is built around: `"native"` means this session
/// counted these figures itself and every field below may be present; `"usage"` means
/// they are what the provider's own `usage` events reported and nothing more was known.
/// The overlay labels which one it is reading rather than drawing the same panel twice.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionContext {
    pub source: Option<String>,
    pub session_id: Option<String>,
    pub provider: Option<String>,
    pub transport: Option<String>,
    pub model: Option<String>,
    pub provider_session_id: Option<String>,
    pub context_window: Option<u64>,
    pub context_used: Option<u64>,
    pub total_tokens: Option<u64>,
    pub handed_off_from: Option<String>,
    pub handed_off_to: Option<String>,
    // Native only, below.
    pub prefix_fingerprint: Option<String>,
    pub compact_at: Option<f64>,
    pub keep_recent_tokens: Option<u64>,
    pub messages: Option<u64>,
    pub compaction_thrashing: Option<bool>,
    pub compactions: Vec<Compaction>,
    pub archive_ids: Vec<String>,
    pub instruction_files: Vec<String>,
    pub instruction_files_dropped: Vec<DroppedInstruction>,
    pub instruction_bytes: Option<u64>,
    pub tools: Vec<String>,
    /// Everything the answer carried, for `Ctrl+O` and the tree widget.
    pub raw: Value,
}

impl SessionContext {
    pub fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        let names = |key: &str| {
            map.get(key)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_ROWS)
                        .filter_map(|item| string(Some(item)))
                        .collect()
                })
                .unwrap_or_default()
        };

        Some(Self {
            source: at(map, "source"),
            session_id: at(map, "session_id"),
            provider: at(map, "provider"),
            transport: at(map, "transport"),
            model: at(map, "model"),
            provider_session_id: at(map, "provider_session_id"),
            context_window: count(map, "context_window"),
            context_used: count(map, "context_used"),
            total_tokens: count(map, "total_tokens"),
            handed_off_from: at(map, "handed_off_from"),
            handed_off_to: at(map, "handed_off_to"),
            prefix_fingerprint: at(map, "prefix_fingerprint"),
            compact_at: map.get("compact_at").and_then(Value::as_f64),
            keep_recent_tokens: count(map, "keep_recent_tokens"),
            messages: count(map, "messages"),
            compaction_thrashing: flag(map, "compaction_thrashing"),
            compactions: map
                .get("compactions")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_ROWS)
                        .filter_map(Compaction::decode)
                        .collect()
                })
                .unwrap_or_default(),
            archive_ids: names("archive_ids"),
            instruction_files: names("instruction_files"),
            instruction_files_dropped: map
                .get("instruction_files_dropped")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_ROWS)
                        .filter_map(DroppedInstruction::decode)
                        .collect()
                })
                .unwrap_or_default(),
            instruction_bytes: count(map, "instruction_bytes"),
            tools: names("tools"),
            raw: value.clone(),
        })
    }

    /// Whether this answer came from a session that counted its own context.
    pub fn native(&self) -> bool {
        self.source.as_deref() == Some("native")
    }

    /// How full the window is, where both halves were reported. `None` rather than a
    /// guess: a provider that named no window gets no percentage.
    pub fn share(&self) -> Option<u64> {
        let window = self.context_window.filter(|window| *window > 0)?;
        let used = self.context_used?;

        Some((used.saturating_mul(100) / window).min(999))
    }
}

/// An `AGENTS.md` the budget would not fit, and how big it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedInstruction {
    pub path: String,
    pub bytes: Option<u64>,
    pub reason: Option<String>,
}

impl DroppedInstruction {
    fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        Some(Self {
            path: at(map, "path")?,
            bytes: count(map, "bytes"),
            reason: at(map, "reason"),
        })
    }
}

/// One row of `interactive.rewind_points` (D6).
///
/// `commands` is the field the menu is built around: a turn that ran shell commands is
/// only *partly* undoable, and saying so before the choice is the whole point of drawing
/// this list rather than a confirm box.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RewindPoint {
    pub turn_id: Option<String>,
    pub at: Option<String>,
    pub files: u64,
    pub paths: Vec<String>,
    pub commands: u64,
    /// How many of `files` still have prior content in the checkpoint store. Fewer than
    /// `files` means the rest cannot come back.
    pub restorable: Option<u64>,
    pub dropped_turns: Option<u64>,
}

impl RewindPoint {
    pub fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        Some(Self {
            turn_id: at(map, "turn_id"),
            at: at(map, "at"),
            files: count(map, "files").unwrap_or(0),
            paths: map
                .get("paths")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_PATHS)
                        .filter_map(|item| string(Some(item)))
                        .collect()
                })
                .unwrap_or_default(),
            commands: count(map, "commands").unwrap_or(0),
            restorable: count(map, "restorable"),
            dropped_turns: count(map, "dropped_turns"),
        })
    }

    pub fn decode_list(value: &Value) -> Vec<Self> {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .take(MAX_ROWS)
                    .filter_map(Self::decode)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The warning this row carries, or `None` where everything in it can come back.
    ///
    /// Two separate facts, and both are stated: a shell command's effects were never
    /// checkpointed, and a file whose prior bytes were not snapshotted cannot be
    /// rewritten. Neither is discovered after the fact — this is what the menu says
    /// *before* the choice.
    pub fn warning(&self) -> Option<String> {
        let mut parts = Vec::new();

        if self.commands > 0 {
            parts.push(format!(
                "{} shell command{} ran in it — whatever they changed is not checkpointed",
                self.commands,
                if self.commands == 1 { "" } else { "s" }
            ));
        }

        if let Some(restorable) = self.restorable {
            if restorable < self.files {
                parts.push(format!(
                    "{} of {} files have no snapshot",
                    self.files - restorable,
                    self.files
                ));
            }
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }
}

/// What `interactive.rewind` did, and what it could not do (D6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rewound {
    pub restored: Vec<RestoredFile>,
    pub unrestorable: Vec<Unrestorable>,
    /// The turns that were undone.
    pub turns: Vec<String>,
    /// How many messages the conversation was truncated to.
    pub messages: Option<u64>,
}

impl Rewound {
    pub fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        let list = |key: &str| map.get(key).and_then(Value::as_array);

        Some(Self {
            restored: list("restored")
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_ROWS)
                        .filter_map(RestoredFile::decode)
                        .collect()
                })
                .unwrap_or_default(),
            unrestorable: list("unrestorable")
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_ROWS)
                        .filter_map(Unrestorable::decode)
                        .collect()
                })
                .unwrap_or_default(),
            turns: list("turns")
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_ROWS)
                        .filter_map(|item| string(Some(item)))
                        .collect()
                })
                .unwrap_or_default(),
            messages: count(map, "messages"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredFile {
    pub path: String,
    /// `"restored"` for a file rewritten to its prior bytes, `"deleted"` for one that did
    /// not exist before and was removed again.
    pub action: Option<String>,
}

impl RestoredFile {
    fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        Some(Self {
            path: at(map, "path")?,
            action: at(map, "action"),
        })
    }
}

/// Something a rewind named as beyond it. Either a file whose prior bytes were never
/// snapshotted, or a whole turn whose shell commands changed things nothing recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unrestorable {
    pub path: Option<String>,
    pub turn_id: Option<String>,
    pub reason: Option<String>,
}

impl Unrestorable {
    fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        let entry = Self {
            path: at(map, "path"),
            turn_id: at(map, "turn_id"),
            reason: sentence(map, "reason", 512),
        };

        // A row that names neither a file nor a turn cannot be presented as either, and a
        // bare reason floating in a list would read as a claim about the whole rewind.
        if entry.path.is_none() && entry.turn_id.is_none() {
            None
        } else {
            Some(entry)
        }
    }

    pub fn subject(&self) -> String {
        match (&self.path, &self.turn_id) {
            (Some(path), _) => path.clone(),
            (None, Some(turn)) => format!("turn {turn}"),
            (None, None) => "something".to_string(),
        }
    }
}

/// What one `workspace.exec` did (B7).
///
/// A non-zero exit is a *result*, not a failure — the runtime says so and this type keeps
/// the distinction, because a client that coloured every non-zero red would be reporting
/// `grep`'s "no matches" as a broken command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellResult {
    pub effect_id: Option<String>,
    pub command_digest: Option<String>,
    pub cwd: Option<String>,
    pub exit_status: Option<i64>,
    pub timed_out: bool,
    pub duration_ms: Option<u64>,
    /// Head and tail with the middle elided, already bounded at 30 KiB by the runtime.
    pub output: Option<String>,
    pub output_bytes: Option<u64>,
    /// Where the whole of it was written, when it did not fit inline.
    pub spilled: Option<String>,
    /// Why it could not be written there, when that failed.
    pub spill_error: Option<String>,
}

impl ShellResult {
    pub fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        Some(Self {
            effect_id: at(map, "effect_id"),
            command_digest: at(map, "command_digest"),
            cwd: at(map, "cwd"),
            exit_status: map.get("exit_status").and_then(Value::as_i64),
            timed_out: flag(map, "timed_out").unwrap_or(false),
            duration_ms: count(map, "duration_ms"),
            output: map
                .get("output")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_string),
            output_bytes: count(map, "output_bytes"),
            spilled: at(map, "spilled"),
            spill_error: sentence(map, "spill_error", 512),
        })
    }

    /// The status line above the output: what it exited with, and how long it took.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();

        match self.exit_status {
            Some(0) => parts.push("exit 0".to_string()),
            Some(status) => parts.push(format!("exit {status}")),
            None => parts.push("no exit status".to_string()),
        }

        if self.timed_out {
            parts.push("timed out".to_string());
        }

        if let Some(ms) = self.duration_ms {
            parts.push(duration(ms));
        }

        if let Some(bytes) = self.output_bytes {
            parts.push(format!("{bytes} bytes"));
        }

        parts.join(" · ")
    }
}

/// A `workspace.exec` the runtime would not run, and the rule that would have let it.
///
/// `suggested_rule` is the engine's own language, computed server-side, and this client
/// never invents one — which is what makes the one-key "add rule" offer safe to make.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellRefusal {
    pub reason: Option<String>,
    pub session_id: Option<String>,
    pub workspace: Option<String>,
    pub approval_mode: Option<String>,
    pub denied_by: Option<String>,
    pub suggested_rule: Option<String>,
    pub message: Option<String>,
}

impl ShellRefusal {
    /// Reads the `data` of a `["shell_refused", {…}]` refusal, or `None` where this
    /// failure was something else.
    ///
    /// `Gateway.Wire` encodes every Elixir tuple as a JSON array, so a tagged runtime
    /// refusal is always a two-element `[tag, detail]` — the same shape
    /// [`crate::model::refusal`] already renders. Matching on the tag rather than on the
    /// presence of `suggested_rule` is what keeps the composer's one-key offer from
    /// appearing beside a `workspace_conflict` that has nothing to do with permissions.
    pub fn decode(data: Option<&Value>) -> Option<Self> {
        let [tag, detail] = data?.as_array()?.as_slice() else {
            return None;
        };

        if tag.as_str() != Some("shell_refused") {
            return None;
        }

        let detail = detail.as_object()?;

        Some(Self {
            reason: at(detail, "reason"),
            session_id: at(detail, "session_id"),
            workspace: at(detail, "workspace"),
            approval_mode: at(detail, "approval_mode"),
            // The engine answers with a whole rule record; the pattern is the half worth
            // naming, and its id is the fallback for a rule store that returned no
            // pattern rather than an invented sentence.
            denied_by: detail.get("denied_by").and_then(|rule| {
                rule.as_object()
                    .and_then(|rule| at(rule, "pattern").or_else(|| at(rule, "id")))
                    .or_else(|| string(Some(rule)))
            }),
            suggested_rule: at(detail, "suggested_rule"),
            message: sentence(detail, "message", 512),
        })
    }
}

/// The tag of any `[tag, detail]` refusal, for the gates that branch on one.
///
/// Used to tell `unsupported_on_transport` — a permanent capability answer, so the verb
/// stops being offered — from `native_transport_unavailable`, which is worth retrying.
pub fn refusal_tag(data: Option<&Value>) -> Option<&str> {
    let [tag, _detail] = data?.as_array()?.as_slice() else {
        return None;
    };

    tag.as_str()
}

/// What `interactive.delegate` answered (G1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delegated {
    pub delegation_id: Option<String>,
    pub team_id: Option<String>,
    pub task_id: Option<String>,
    pub task_node: Option<String>,
    pub plane: Option<String>,
    pub status: Option<String>,
}

impl Delegated {
    pub fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        Some(Self {
            delegation_id: at(map, "delegation_id"),
            team_id: at(map, "team_id"),
            task_id: at(map, "task_id"),
            task_node: at(map, "task_node"),
            plane: at(map, "plane"),
            status: at(map, "status"),
        })
    }
}

/// One row of `interactive.delegations` (G1).
///
/// `source` is what keeps a status honest: `"team"` means the team that owns the child was
/// read just now, `"session"` means it could not be and this is the conversation's own
/// copy — which is stale exactly when the parent was not running as the child finished.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationRow {
    pub delegation_id: Option<String>,
    pub team_id: Option<String>,
    pub task_id: Option<String>,
    pub task_node: Option<String>,
    pub plane: Option<String>,
    pub objective_digest: Option<String>,
    pub status: Option<String>,
    pub result_digest: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub source: Option<String>,
}

impl DelegationRow {
    pub fn decode(value: &Value) -> Option<Self> {
        let map = value.as_object()?;

        Some(Self {
            delegation_id: at(map, "delegation_id"),
            team_id: at(map, "team_id"),
            task_id: at(map, "task_id"),
            task_node: at(map, "task_node"),
            plane: at(map, "plane"),
            objective_digest: at(map, "objective_digest"),
            status: at(map, "status"),
            result_digest: at(map, "result_digest"),
            created_at: at(map, "created_at"),
            updated_at: at(map, "updated_at"),
            source: at(map, "source"),
        })
    }

    pub fn decode_list(value: &Value) -> Vec<Self> {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .take(MAX_ROWS)
                    .filter_map(Self::decode)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether the runtime says this child has finished, whatever the outcome.
    pub fn terminal(&self) -> bool {
        matches!(
            self.status.as_deref(),
            Some("completed" | "failed" | "cancelled" | "timed_out" | "unreachable")
        )
    }
}

/// A `delegation` event's payload, as the parent's transcript carries it (G1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationEvent {
    pub delegation_id: Option<String>,
    pub task_id: Option<String>,
    pub task_node: Option<String>,
    pub team_id: Option<String>,
    pub objective_digest: Option<String>,
    pub status: Option<String>,
    pub result_digest: Option<String>,
}

impl DelegationEvent {
    pub fn decode(payload: &Value) -> Self {
        let Some(map) = payload.as_object() else {
            return Self::default();
        };

        Self {
            delegation_id: at(map, "delegation_id"),
            task_id: at(map, "task_id"),
            task_node: at(map, "task_node"),
            team_id: at(map, "team_id"),
            objective_digest: at(map, "objective_digest"),
            status: at(map, "status"),
            result_digest: at(map, "result_digest"),
        }
    }
}

/// How many of a settled child's changed paths the parent's transcript names.
///
/// The count beside them is the whole number, so a child that touched three hundred files
/// still reports three hundred — this only bounds how many of them get spelled out in a
/// conversation that is about the parent's work, not the child's.
const SUBAGENT_FILES: usize = 16;

/// Which moment of a child agent's life a `subagent` provider event reports.
///
/// `Other` exists because the runtime may name a phase this build has not heard of, and a
/// client that dropped it would show a child that spawned and then stopped existing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubagentPhase {
    Spawned,
    Progress,
    Settled,
    /// A phase word this build does not model, kept verbatim. Empty where the payload
    /// named no phase at all.
    Other(String),
}

impl SubagentPhase {
    fn decode(word: Option<&str>) -> Self {
        match word {
            Some("spawned") => Self::Spawned,
            Some("progress") => Self::Progress,
            Some("settled") => Self::Settled,
            Some(other) => Self::Other(bounded(other, LABEL_BYTES)),
            None => Self::Other(String::new()),
        }
    }

    pub fn settled(&self) -> bool {
        matches!(self, Self::Settled)
    }
}

/// One `provider_event` whose `kind` is `subagent`: a child agent spawning, reporting, or
/// settling in the parent's own transcript.
///
/// Every field is optional and every default is the honest one. A child may be placed on
/// another fleet machine, in which case the payload names the `node` it ran on and sets
/// `remote`; an older event that predates fleet placement carries neither, and an absent
/// pair means the child ran here — which is why `remote` defaults to `false` rather than
/// to "unknown". Nothing below invents a number the runtime did not send: a zero this
/// client made up would be indistinguishable from a zero the child measured.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SubagentEvent {
    pub phase: Option<SubagentPhase>,
    pub task_id: Option<String>,
    pub description: Option<String>,
    pub provider_session_id: Option<String>,
    /// Where the child was placed. Absent means this machine.
    pub node: Option<String>,
    /// True only where the runtime said so. An absent flag is local, not unknown.
    pub remote: bool,
    pub workspace: Option<String>,
    /// Whether the child was given a worktree of its own — the `spawned` payload's bool,
    /// or the presence of the `settled` payload's map.
    pub worktree: bool,
    /// The settled payload's worktree map, which is the only one that says how it retired.
    pub worktree_detail: Option<Worktree>,
    pub tools: Vec<String>,
    pub background: bool,
    pub depth: Option<u64>,
    pub max_turns: Option<u64>,
    pub deadline_ms: Option<u64>,
    pub turns: Option<u64>,
    pub tool_calls: Option<u64>,
    pub files_changed: Option<u64>,
    /// Named paths, bounded by [`SUBAGENT_FILES`]; `files_changed` stays the whole count.
    pub files: Vec<String>,
    /// `"completed"`, `"failed"`, `"stopped"` or `"timed_out"`, as the runtime spelled it.
    pub status: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub approvals_denied: Option<u64>,
    pub summary_bytes: Option<u64>,
    pub cost_usd: Option<f64>,
    pub error: Option<String>,
}

impl SubagentEvent {
    pub fn decode(payload: &Value) -> Self {
        let Some(map) = payload.as_object() else {
            return Self::default();
        };

        let worktree_detail = Worktree::decode(map.get("worktree"));

        Self {
            phase: Some(SubagentPhase::decode(
                map.get("phase").and_then(Value::as_str),
            )),
            task_id: at(map, "task_id"),
            description: at(map, "description"),
            provider_session_id: at(map, "provider_session_id"),
            node: at(map, "node"),
            remote: flag(map, "remote").unwrap_or(false),
            workspace: at(map, "workspace"),
            // Two shapes for one key: `spawned` sends a bool, `settled` sends the worktree
            // itself. Either one means the child had one.
            worktree: flag(map, "worktree").unwrap_or(false) || worktree_detail.is_some(),
            worktree_detail,
            tools: names(map.get("tools"), usize::MAX),
            background: flag(map, "background").unwrap_or(false),
            depth: count(map, "depth"),
            max_turns: count(map, "max_turns"),
            deadline_ms: count(map, "deadline_ms"),
            turns: count(map, "turns"),
            tool_calls: count(map, "tool_calls"),
            files_changed: count(map, "files_changed"),
            files: names(map.get("files"), SUBAGENT_FILES),
            status: at(map, "status"),
            input_tokens: count(map, "input_tokens"),
            output_tokens: count(map, "output_tokens"),
            approvals_denied: count(map, "approvals_denied"),
            summary_bytes: count(map, "summary_bytes"),
            cost_usd: map.get("cost_usd").and_then(Value::as_f64),
            error: sentence(map, "error", 512),
        }
    }

    pub fn phase(&self) -> SubagentPhase {
        self.phase
            .clone()
            .unwrap_or_else(|| SubagentPhase::Other(String::new()))
    }
}

/// A JSON array of strings, trimmed, bounded, and with the empties dropped.
fn names(value: Option<&Value>, limit: usize) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| string(Some(value)))
                .take(limit)
                .collect()
        })
        .unwrap_or_default()
}

/// The `operator_shell` half of a `provider_event` payload (B7).
///
/// The runtime writes one of these after every command it ran, so a command survives a
/// restart and is visible to a second client watching the same session. It carries less
/// than the reply does — no elapsed time on the failure arm, no spill path — which is why
/// the reply's own note is preferred where this client has both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellEvent {
    pub effect_id: Option<String>,
    pub command_digest: Option<String>,
    pub exit_status: Option<i64>,
    pub duration_ms: Option<u64>,
    pub timed_out: bool,
    pub output_bytes: Option<u64>,
    pub output_excerpt: Option<String>,
    pub spilled: Option<String>,
    /// Set where the runtime could not start the command at all.
    pub error: Option<String>,
}

impl ShellEvent {
    pub fn decode(payload: &Value) -> Self {
        let Some(map) = payload.as_object() else {
            return Self::default();
        };

        Self {
            effect_id: at(map, "effect_id"),
            command_digest: at(map, "command_digest"),
            exit_status: map.get("exit_status").and_then(Value::as_i64),
            duration_ms: count(map, "duration_ms"),
            timed_out: flag(map, "timed_out").unwrap_or(false),
            output_bytes: count(map, "output_bytes"),
            // Through `leaf_text` rather than `as_str`: the gateway replaces a long string
            // *inside an event payload* with `{"_excerpt", "_bytes"}`, and reading this
            // one as a plain string would drop the excerpt on exactly the commands whose
            // output was worth excerpting.
            output_excerpt: map
                .get("output_excerpt")
                .and_then(leaf_text)
                .map(|text| bounded(&text, 4096)),
            spilled: at(map, "spilled"),
            error: sentence(map, "error", 512),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_worktree_badge_prefers_the_branch_then_the_base_commit() {
        let branch = Worktree::decode(Some(&json!({"branch": "feature/x", "base_commit": "abc"})));
        assert_eq!(branch.unwrap().label(), "feature/x");

        let detached = Worktree::decode(Some(&json!({"base_commit": "abcdef0123456789"})));
        assert_eq!(detached.unwrap().label(), "abcdef01");

        let bare = Worktree::decode(Some(&json!({"path": "/tmp/w"})));
        assert_eq!(bare.unwrap().label(), "worktree");
    }

    #[test]
    fn a_retired_worktree_is_not_live() {
        let kept = Worktree::decode(Some(&json!({"branch": "x", "retired": "kept"}))).unwrap();
        assert!(!kept.live());

        let live = Worktree::decode(Some(&json!({"branch": "x"}))).unwrap();
        assert!(live.live());
    }

    #[test]
    fn a_rewind_point_warns_about_shell_commands_and_missing_snapshots() {
        let point = RewindPoint::decode(&json!({
            "turn_id": "t3", "files": 4, "commands": 2, "restorable": 1
        }))
        .unwrap();

        let warning = point.warning().expect("a warning");
        assert!(warning.contains("2 shell commands"), "{warning}");
        assert!(warning.contains("3 of 4 files"), "{warning}");
    }

    #[test]
    fn a_clean_rewind_point_warns_about_nothing() {
        let point =
            RewindPoint::decode(&json!({"turn_id": "t1", "files": 2, "restorable": 2})).unwrap();

        assert_eq!(point.warning(), None);
    }

    #[test]
    fn an_unrestorable_row_naming_neither_a_file_nor_a_turn_is_dropped() {
        let rewound = Rewound::decode(&json!({
            "restored": [{"path": "/w/a.rs", "action": "restored"}],
            "unrestorable": [{"reason": "who knows"}, {"path": null, "turn_id": "t2", "reason": "shell"}],
            "turns": ["t2"],
            "messages": 8
        }))
        .unwrap();

        assert_eq!(rewound.restored.len(), 1);
        assert_eq!(rewound.unrestorable.len(), 1);
        assert_eq!(rewound.unrestorable[0].subject(), "turn t2");
    }

    #[test]
    fn a_context_share_needs_both_halves() {
        let native = SessionContext::decode(&json!({
            "source": "native", "context_window": 200_000, "context_used": 50_000
        }))
        .unwrap();
        assert_eq!(native.share(), Some(25));
        assert!(native.native());

        let bare = SessionContext::decode(&json!({"source": "usage", "context_used": 10})).unwrap();
        assert_eq!(bare.share(), None);
        assert!(!bare.native());
    }

    #[test]
    fn a_shell_refusal_is_read_only_from_its_own_tag() {
        // `Gateway.Wire` encodes `{:shell_refused, %{…}}` as a two-element array.
        let refused = ShellRefusal::decode(Some(&json!([
            "shell_refused",
            {
                "reason": "no_rule",
                "approval_mode": "prompt",
                "denied_by": null,
                "suggested_rule": "Bash(mix test *)",
                "message": "workspace.exec runs a command as your own act"
            }
        ])))
        .expect("a refusal");

        assert_eq!(refused.suggested_rule.as_deref(), Some("Bash(mix test *)"));
        assert_eq!(refused.reason.as_deref(), Some("no_rule"));
        assert_eq!(refused.denied_by, None);

        let denied = ShellRefusal::decode(Some(&json!([
            "shell_refused",
            {"reason": "rule_denied", "denied_by": {"scope": "user", "id": "r1", "pattern": "Bash(rm *)"}}
        ])))
        .expect("a refusal");
        assert_eq!(denied.denied_by.as_deref(), Some("Bash(rm *)"));

        // Every other tagged refusal reaches the same handler and must not be mistaken
        // for one this client can offer a rule for.
        assert!(ShellRefusal::decode(Some(
            &json!(["session_not_executable", {"status": "closed"}])
        ))
        .is_none());
        assert!(ShellRefusal::decode(Some(&json!({"reason": "cursor_pruned"}))).is_none());
        assert!(ShellRefusal::decode(None).is_none());
    }

    #[test]
    fn a_refusal_tag_separates_a_capability_answer_from_a_liveness_one() {
        let unsupported = json!([
            "unsupported_on_transport",
            {"transport": "managed", "verb": "compact"}
        ]);
        let unavailable = json!(["native_transport_unavailable", {"verb": "compact"}]);

        assert_eq!(
            refusal_tag(Some(&unsupported)),
            Some("unsupported_on_transport")
        );
        assert_eq!(
            refusal_tag(Some(&unavailable)),
            Some("native_transport_unavailable")
        );
        assert_eq!(refusal_tag(Some(&json!({"reason": "busy"}))), None);
    }

    #[test]
    fn an_excerpted_command_output_keeps_its_prefix() {
        let event = ShellEvent::decode(&json!({
            "kind": "operator_shell",
            "command_digest": "abc",
            "exit_status": 0,
            "output_excerpt": {"_excerpt": "Compiling ouroboros", "_bytes": 90_000}
        }));

        let excerpt = event.output_excerpt.expect("the prefix survives");
        assert!(excerpt.starts_with("Compiling ouroboros"), "{excerpt}");
        assert!(excerpt.contains("90000 bytes"), "{excerpt}");
    }

    #[test]
    fn a_bound_cuts_on_a_character_boundary() {
        let text = "é".repeat(400);
        let cut = bounded(&text, LABEL_BYTES);

        assert!(cut.len() <= LABEL_BYTES);
        assert!(cut.ends_with(TRUNCATION));
    }

    #[test]
    fn a_compaction_describes_only_the_numbers_it_carried() {
        let full = Compaction::decode(&json!({
            "trigger": "manual", "archived_messages": 12, "archive_id": "arch-1",
            "before_tokens": 100_000, "after_tokens": 20_000, "elided_tool_results": 3
        }))
        .unwrap();

        let text = full.describe();
        assert!(text.contains("archived 12 messages"), "{text}");
        assert!(text.contains("100000 → 20000 tokens"), "{text}");
        assert!(text.contains("archive arch-1"), "{text}");

        let empty = Compaction::decode(&json!({"trigger": "manual"})).unwrap();
        assert_eq!(empty.describe(), "the conversation was folded");
    }

    #[test]
    fn a_delegation_row_knows_a_terminal_status_from_a_running_one() {
        let running = DelegationRow::decode(&json!({"status": "running"})).unwrap();
        assert!(!running.terminal());

        let done = DelegationRow::decode(&json!({"status": "completed"})).unwrap();
        assert!(done.terminal());
    }

    #[test]
    fn lists_are_bounded_and_tolerant_of_rows_this_build_cannot_read() {
        let rows: Vec<_> = (0..(MAX_ROWS + 40))
            .map(|index| json!({"turn_id": format!("t{index}"), "files": 1}))
            .collect();

        assert_eq!(
            RewindPoint::decode_list(&Value::Array(rows)).len(),
            MAX_ROWS
        );
        assert!(RewindPoint::decode_list(&json!("not a list")).is_empty());
        assert_eq!(
            DelegationRow::decode_list(&json!([{"delegation_id": "d1"}, 7])).len(),
            1
        );
    }
}
