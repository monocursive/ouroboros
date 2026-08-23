//! Declarative cells for the conversation-first transcript.
//!
//! Projection is deliberately one-way: normalized durable events become compact display
//! cells, but no decision made here is sent back to the runtime. `/details` continues to
//! show every raw event when this best-effort presentation cannot recognize a newer
//! payload.
//!
//! Chat layout is editorial rather than phone-like: both voices share one readable measure,
//! human intent is marked in amber, runtime output in cyan, and tool/command activity is
//! dimmer and more compact than either speaker.
//!
//! ## Two verbosities, one projection
//!
//! [`Verbosity::Compact`] is the reading view: collapsible cells show a header and a few
//! rows. [`Verbosity::Verbose`] — `Ctrl+O`, the key the field settled on for "show more" —
//! renders the same cells expanded in place. Both remain bounded; verbose raises the
//! per-cell row ceiling to [`VERBOSE_LINES`] rather than removing it, because a transcript
//! that re-lays out a 64 MiB tool result on every frame is a transcript that stops
//! redrawing.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};

use ratatui::layout::Alignment;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use serde_json::Value;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::model::transcript::{
    leaf_text, Diff, FileChange, Lifecycle, PlanStatus, PlanUpdate, PresentationEvent, ToolCall,
    ToolResult, TurnOutcome, UsageReport,
};

use super::markdown;
use super::theme;
use super::transcript::{Entry, Note};

/// The head half of Codex's head/tail layout for a tool result.
const TOOL_HEAD_LINES: usize = 6;
/// The tail half. A result's last rows are where an exit status, a summary, or the failure
/// actually is; showing only the head is why "collapsed tool output" used to be useless.
const TOOL_TAIL_LINES: usize = 6;
/// The compact row ceiling for one tool result, deliberately raised from the three rows
/// this file used to spend. Six-and-six with a counted marker between them is R2 §10c
/// recipe 4/8: enough of a result to recognise it, and an explicit statement of the rest.
const TOOL_OUTPUT_LINES: usize = TOOL_HEAD_LINES + TOOL_TAIL_LINES;
/// The live tail window for streaming command output (Kiro, Cursor): the newest rows, not
/// the oldest, because a command that is still running is watched at its end.
/// How many ledger entries the conversation pane projects.
///
/// A redraw budget, not a retention policy: the projection is rebuilt on every frame, so
/// the surface is bounded to a useful recent suffix and the pane says how much it is not
/// drawing. The complete retained ledger stays available through `/details`.
///
/// It lives here rather than in the pane because two other things are sized against it —
/// [`super::markdown::MEMO_ENTRIES`], which has to be able to hold a whole window of prose
/// or it evicts on the way round, and [`super::transcript::Watch::recent_entries`], which
/// walks exactly this many.
pub const CHAT_ENTRY_WINDOW: usize = 128;

const COMMAND_OUTPUT_LINES: usize = 4;
const DIFF_LINES: usize = super::diff::COMPACT_LINES;
/// How many calls one grouped exploration cell lists before it starts counting instead.
const EXPLORATION_CALLS: usize = 64;
const MESSAGE_LINES: usize = 256;
const STATUS_DETAIL_LINES: usize = 32;
/// The per-cell row ceiling under `Ctrl+O`. Deliberately raised from the compact ceilings
/// rather than removed: the point of verbose is to read a whole tool result on screen, and
/// two thousand rows is more than any terminal shows at once while still bounding the wrap
/// work one frame can be asked to do.
const VERBOSE_LINES: usize = 2_000;
/// How many rows one block of the plain renderer keeps in screen-reader mode.
///
/// Between the pane's compact ceilings and `/raw`'s absence of one. A screen reader plays a
/// block from its first line, so the cost of drawing too much is not a screenful of
/// scrolling — it is minutes of speech before the next label. Thirty-two lines is a long
/// paragraph or a short stack trace, and what is left out is said in a sentence with the
/// key that shows it.
const PLAIN_SPOKEN_LINES: usize = 32;
/// Crush's middle state: the last N lines of a long block, with what came before named.
const THINKING_TAIL_LINES: usize = 200;
const AGENT_OUTPUT_BYTES: usize = 128 * 1024;
const COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const THINKING_BYTES: usize = 128 * 1024;
const TOOL_VALUE_BYTES: usize = 32 * 1024;
const TOOL_INPUT_BYTES: usize = 8 * 1024;
const AGENT_TRUNCATION: &str =
    "\n… agent stream truncated; full updates are available in event details";
const COMMAND_TRUNCATION: &str =
    "\n… command stream truncated; full updates are available in event details";
const THINKING_TRUNCATION: &str =
    "\n… reasoning truncated; full text is available in event details";
const TOOL_VALUE_TRUNCATION: &str =
    "\n… tool value truncated; full value is available in event details";
const TOOL_INPUT_TRUNCATION: &str = " … full input is available in event details";

/// How much of a collapsible cell the transcript draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    #[default]
    Compact,
    Verbose,
    /// Codex's `/raw`: the same cells with no frame, no gutter, no glyph column, and no
    /// app-side wrapping, so a native terminal selection yields logical lines.
    Raw,
}

impl Verbosity {
    /// Whether collapsible cells are drawn expanded. Raw shows everything too — it is a
    /// copying view, and a copying view that folded half the transcript away would be a
    /// worse answer than the one it replaced.
    pub fn verbose(self) -> bool {
        self != Self::Compact
    }

    pub fn raw(self) -> bool {
        self == Self::Raw
    }

    /// The row ceiling for one collapsible cell at this verbosity.
    fn lines(self, compact: usize) -> usize {
        match self {
            Self::Compact => compact,
            Self::Verbose | Self::Raw => VERBOSE_LINES,
        }
    }

    /// The key that shows the rest, in the view the reader is in.
    fn key(self) -> &'static str {
        match self {
            Self::Compact => "ctrl+o",
            Self::Verbose | Self::Raw => "/details",
        }
    }

    /// Where the rest of a cut cell lives, phrased for the view the reader is in.
    ///
    /// Kept short on purpose: this row is drawn inside tool frames as narrow as twenty
    /// cells, and a provenance note that is itself truncated has stopped being provenance.
    ///
    /// Screen-reader mode has no branch here, and deliberately: it does not use this
    /// renderer at all. [`render_plain`] draws every cell in that mode and spells its own
    /// markers out, so a branch here would be a sentence nothing ever says.
    fn provenance(self, what: &str) -> String {
        format!("full {what} · {}", self.key())
    }
}

/// Codex's counted truncation marker, with the key that shows the rest.
///
/// Phrased as `… +N lines · ctrl+o` rather than as a bare ellipsis because a collapsed cell
/// that does not say *how much* it hid is a cell the reader has to expand to find out it
/// hid nothing worth reading. The spoken form of the same fact is
/// [`super::access::omitted`], which is what [`render_plain`] writes instead.
fn more_lines(omitted: usize, verbosity: Verbosity) -> String {
    format!(
        "… +{omitted} line{} · {}",
        if omitted == 1 { "" } else { "s" },
        verbosity.key()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speaker {
    You,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolState {
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Muted,
    Success,
    Warning,
    Error,
}

/// How many rows of a runtime block's body are drawn before the count takes over.
///
/// Head and tail both, like a tool result: the last rows of a command's output are where
/// its failure is, and the first rows of a restored-file list are where the paths a reader
/// is looking for are.
pub const BLOCK_HEAD: usize = 8;
pub const BLOCK_TAIL: usize = 6;

/// One thing this runtime did, as a transcript block.
///
/// Built in exactly two ways and rendered in one: from the durable event the runtime
/// wrote, and from the reply the operator's own verb answered with. The reply is the
/// fuller of the two — it carries the elapsed time, the spill path and the command's own
/// text, none of which the durable event records — so where this client holds both, the
/// reply's block is drawn and the event's is deduped away against `Block::key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The bold first row: `$ mix test`, `Compacted`, `Delegated`.
    pub label: String,
    /// One line of facts under it. Empty draws nothing rather than a placeholder.
    pub detail: String,
    /// Pre-split rows drawn verbatim — command output, restored paths — head and tail with
    /// the count between them.
    pub body: Vec<String>,
    pub tone: Tone,
    /// What the runtime's own durable record of the same act is matched against, so the
    /// two are never drawn side by side. A command's digest, a compaction's archive id.
    pub key: Option<String>,
}

impl Block {
    pub fn new(label: impl Into<String>, detail: impl Into<String>, tone: Tone) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
            body: Vec::new(),
            tone,
            key: None,
        }
    }

    pub fn with_body(mut self, body: Vec<String>) -> Self {
        self.body = body;
        self
    }

    pub fn with_key(mut self, key: Option<String>) -> Self {
        self.key = key;
        self
    }

    /// The whole block as plain text, for `/details` and the screen-reader path.
    pub fn text(&self) -> String {
        let mut text = self.label.clone();

        if !self.detail.trim().is_empty() {
            text.push_str(" — ");
            text.push_str(&self.detail);
        }

        for row in &self.body {
            text.push('\n');
            text.push_str(row);
        }

        text
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCell {
    pub call_id: Option<String>,
    pub name: String,
    /// ACP's `kind`, beside the provider's name rather than instead of it.
    pub kind: Option<String>,
    pub input: Value,
    pub output: Option<Value>,
    pub state: ToolState,
    /// When the call was made, in epoch milliseconds.
    pub started_at: Option<i64>,
    /// When the ledger last had something to say about it: its result's instant for a call
    /// that finished, and the newest instant this window holds for one still running.
    pub settled_at: Option<i64>,
}

impl ToolCell {
    fn new(call_id: Option<String>, name: String, kind: Option<String>, input: Value) -> Self {
        Self {
            call_id,
            name,
            kind,
            input,
            output: None,
            state: ToolState::Running,
            started_at: None,
            settled_at: None,
        }
    }

    /// How long this call took, as far as the ledger can prove it.
    ///
    /// Exact once the result arrived. While the call is still running it is a **floor**:
    /// the projection reads no clock — that is what keeps the same watch rendering and
    /// exporting to the same bytes — so the newest event instant in the window is the
    /// latest moment it can honestly say the call was still going.
    pub fn elapsed(&self) -> Option<i64> {
        let started = self.started_at?;
        let settled = self.settled_at?;

        (settled > started).then_some(settled - started)
    }
}

/// Codex's grouped exploration cell: consecutive read/search/list/glob calls, with nothing
/// else drawn between them, read as one row.
///
/// The point is not to hide the calls — expanded, every one of them is a row — but to stop
/// eight filesystem lookups from occupying eight frames of a conversation about something
/// else. It says `Exploring…` while it is still growing and `Explored N files` once
/// anything else has been drawn.
#[derive(Debug, Clone, PartialEq)]
pub struct ExplorationCell {
    pub calls: Vec<ToolCell>,
    /// Calls beyond [`EXPLORATION_CALLS`], counted rather than listed.
    pub overflow: usize,
    /// Closed: something else was drawn after it, or the turn ended.
    pub done: bool,
}

impl ExplorationCell {
    pub fn total(&self) -> usize {
        self.calls.len() + self.overflow
    }

    fn failed(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| call.state == ToolState::Failed)
            .count()
    }
}

/// One unified diff, parsed once at projection time.
///
/// The parse is what every count and every row comes from. [`Diff::additions`] — the
/// provider's own claim — stays on the payload for `/details` and is deliberately not the
/// number this cell prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffCell {
    pub diff: Diff,
    pub parsed: super::diff::ParsedDiff,
    /// Warp's rule: a diff whose approval is still outstanding stays expanded and says so;
    /// once the approval resolves it collapses back to its header.
    pub pending_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCell {
    pub path: Option<String>,
    pub kind: Option<String>,
}

/// One image in the conversation (A11).
///
/// Everything a renderer needs is decided **before** the cell exists, because projection
/// is clock-free and filesystem-free by contract: the same watch at the same width has to
/// be the same bytes, and a cell that stat'd a file would make the export snapshot depend
/// on what happened to be on disk. So the header was read once, when the image entered the
/// conversation, and what is carried here is the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageCell {
    /// The path exactly as it was named — workspace-relative for an attachment this
    /// client wrote. Never the absolute path it resolved to, which is a fact about this
    /// machine rather than about the conversation, and which would put a home directory
    /// into an `/export` shared with someone else.
    pub named: String,
    /// The pixel size and format, where the file was inside the workspace and readable.
    pub pixels: Option<(u32, u32)>,
    pub format: Option<String>,
    /// Why there is no size, where there is none. Never a bare absence: a placeholder that
    /// did not say why it was a placeholder leaves a reader unsure whether the picture is
    /// missing or the client is broken.
    pub note: Option<String>,
}

impl ImageCell {
    /// The one line every surface draws.
    ///
    /// Built here rather than in three renderers so the pane, the screen reader, and the
    /// export cannot word the same image differently.
    pub fn label(&self) -> String {
        let mut text = String::from("[image ");

        match self.pixels.zip(self.format.as_deref()) {
            Some(((width, height), format)) => text.push_str(&format!("{width}×{height} {format}")),
            None => text.push_str("size unknown"),
        }

        text.push_str(" · ");
        text.push_str(&self.named);

        if let Some(note) = self
            .note
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            text.push_str(" · ");
            text.push_str(note);
        }

        text.push(']');
        text
    }
}

/// What a divider terminates. Turn boundaries are the ones `/diff` counts turns by, so
/// they cannot be told apart from "earlier history is gone" by their wording alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DividerKind {
    TurnEnd,
    Other,
}

/// Crush's three-state collapse, applied to reasoning.
///
/// Collapsed is the default because thinking expanded by default in a long session is a
/// documented 2026 regression (Zed #52536): the reader loses the conversation to the
/// model's monologue. `Tail` is what a block still being written shows, so reasoning can be
/// watched as it arrives; `Full` is `Ctrl+O`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThinkingState {
    Collapsed,
    Tail,
    Full,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Message {
        speaker: Speaker,
        text: String,
        streaming: bool,
    },
    /// Reasoning for one turn, accumulated. Never rendered as the agent's answer.
    Thinking {
        text: String,
        lines: usize,
        state: ThinkingState,
    },
    Plan(PlanUpdate),
    /// One provider token report. Folded into the session total everywhere else; drawn
    /// only under `Ctrl+O`, where the reader has asked for the bookkeeping.
    Usage(UsageReport),
    Tool(ToolCell),
    /// Consecutive filesystem exploration, as one row.
    Exploration(ExplorationCell),
    CommandOutput(String),
    File(FileCell),
    /// A11. An image in the conversation, drawn as a labelled placeholder.
    Image(ImageCell),
    Diff(DiffCell),
    /// What one turn changed, drawn at its end divider: `3 files · +120 −18`.
    DiffStat {
        files: usize,
        additions: usize,
        deletions: usize,
        /// At least one of the diffs behind these numbers was an excerpt.
        in_excerpt: bool,
    },
    Status {
        label: String,
        detail: String,
        tone: Tone,
    },
    /// A muted entry in the conversation itself: something the ledger recorded happening
    /// without recording what was said. Not a divider — nothing was interrupted — and not a
    /// message, because nobody's words are being quoted.
    ChatNote {
        text: String,
    },
    /// Something *this runtime* did, rather than the provider: a fold of the conversation,
    /// a rewind, a delegation, a command the operator ran themselves (D9, D6, G1, B7).
    ///
    /// One cell for all four because they are the same kind of claim — Ouroboros recording
    /// its own act in the conversation it changed — and because a reader scanning a
    /// transcript should be able to tell those apart from the model's work by their shape
    /// alone.
    Runtime(Block),
    Divider {
        text: String,
        tone: Tone,
        kind: DividerKind,
    },
}

#[derive(Debug)]
struct PendingOutput {
    turn_id: Option<String>,
    text: String,
}

/// The open reasoning cell for a turn, and where it sits so later deltas append to it.
#[derive(Debug)]
struct PendingThinking {
    turn_id: Option<String>,
    index: usize,
}

/// Projects one ordered durable transcript into display cells.
pub fn project(entries: Vec<Entry<'_>>) -> Vec<Cell> {
    let mut cells = Vec::new();
    let mut pending = None;
    let mut thinking: Option<PendingThinking> = None;
    let mut tools: BTreeMap<String, ToolSlot> = BTreeMap::new();
    let mut approvals: BTreeMap<String, usize> = BTreeMap::new();
    // Diff cells an outstanding approval is about, so its resolution can collapse them.
    let mut approval_diffs: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    // Approval subjects still unanswered, so a diff that arrives after the request can tell
    // that it is the thing being asked about.
    let mut open_approvals: Vec<(Option<String>, String)> = Vec::new();
    // Which cells hold the diffs seen since the last turn boundary, for that turn's stat.
    let mut turn_diffs: Vec<usize> = Vec::new();
    // The newest instant the ledger holds. A projection reads no clock — that is what keeps
    // one watch rendering and exporting to the same bytes — so this is the only "now" a
    // still-running tool can honestly be measured against.
    let mut newest_at: Option<i64> = None;
    // Turn start instants, so a turn-end divider can state elapsed time instead of
    // implying one. A turn whose start this window no longer holds gets no duration.
    let mut turn_starts: BTreeMap<String, i64> = BTreeMap::new();
    // The last queue depth projected, so an unchanged count is not restated.
    let mut queued: Option<usize> = None;
    // What this client has already drawn in full from an operator verb's own reply, so the
    // runtime's durable record of the same act is not drawn beside it. Gathered in a pass
    // of its own because the two can arrive in either order: the reply usually lands
    // first, but a replay after a reconnect delivers the event before anything else.
    let drawn_locally: BTreeSet<String> = entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Note(Note::Local { block, .. }) => block.key.clone(),
            _other => None,
        })
        .collect();

    for entry in entries {
        match entry {
            Entry::Floor(_) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: "Earlier conversation is no longer available".into(),
                    tone: Tone::Warning,
                    kind: DividerKind::Other,
                });
            }
            Entry::Gap { from, to } => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: format!("Restoring {} missing updates", to - from + 1),
                    tone: Tone::Warning,
                    kind: DividerKind::Other,
                });
            }
            Entry::Note(Note::Local { block }) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Runtime(block.clone()));
            }
            Entry::Note(Note::Image { cell }) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Image(cell.clone()));
            }
            Entry::Note(note) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: chat_note(note).into(),
                    tone: Tone::Warning,
                    kind: DividerKind::Other,
                });
            }
            Entry::Ended(status) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: format!("Session ended ({status})"),
                    tone: Tone::Muted,
                    kind: DividerKind::Other,
                });
            }
            Entry::Event(event) => {
                if let Some(at) = crate::model::transcript::epoch_millis(&event.timestamp) {
                    newest_at = Some(newest_at.map_or(at, |newest: i64| newest.max(at)));
                }

                match PresentationEvent::from_event(event) {
                    PresentationEvent::UserMessage(text) => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::Message {
                            speaker: Speaker::You,
                            text,
                            streaming: false,
                        });
                    }
                    PresentationEvent::UserSteer(text) => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::ChatNote {
                            text: match text {
                                Some(text) => format!("You steered the agent: {text}"),
                                None => "You steered the agent".to_string(),
                            },
                        });
                    }
                    PresentationEvent::UnrecordedInput => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::ChatNote {
                            text: "[message not recorded]".to_string(),
                        });
                    }
                    PresentationEvent::AgentText {
                        turn_id,
                        text,
                        final_text,
                    } => project_agent_text(&mut cells, &mut pending, turn_id, text, final_text),
                    PresentationEvent::Thinking { turn_id, text } => {
                        flush_agent(&mut cells, &mut pending, false);
                        project_thinking(&mut cells, &mut thinking, turn_id, text);
                    }
                    PresentationEvent::Plan(plan) => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::Plan(plan));
                    }
                    PresentationEvent::Usage(usage) => {
                        // Folded into the session total the header and footer read from
                        // `Watch::usage`. The per-event line is verbose-only because one row
                        // per token report would bury the conversation it is describing.
                        flush_agent(&mut cells, &mut pending, false);
                        if !usage.is_empty() {
                            cells.push(Cell::Usage(usage));
                        }
                    }
                    PresentationEvent::RunStarted(run) => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::ChatNote {
                            text: run_started_note(&run),
                        });
                    }
                    PresentationEvent::TurnStarted { turn_id, at } => {
                        // No cell: a running turn is already announced by the working
                        // indicator. The instant is kept so the turn's own end divider can
                        // state how long it took.
                        if let (Some(turn_id), Some(at)) = (turn_id, at) {
                            turn_starts.entry(turn_id).or_insert(at);
                        }
                    }
                    PresentationEvent::TurnEnded {
                        turn_id,
                        at,
                        outcome,
                        detail,
                    } => {
                        flush_agent(&mut cells, &mut pending, false);
                        project_diffstat(&mut cells, &mut turn_diffs);
                        project_turn_end(&mut cells, &turn_starts, turn_id, at, outcome, detail);
                    }
                    PresentationEvent::QueueChanged { queued: depth } => {
                        if queued != Some(depth) {
                            queued = Some(depth);
                            flush_agent(&mut cells, &mut pending, false);
                            cells.push(Cell::ChatNote {
                                text: match depth {
                                    0 => "The follow-up queue is empty".to_string(),
                                    1 => "1 follow-up is queued".to_string(),
                                    depth => format!("{depth} follow-ups are queued"),
                                },
                            });
                        }
                    }
                    PresentationEvent::Lifecycle { marker, detail } => {
                        flush_agent(&mut cells, &mut pending, false);
                        project_lifecycle(&mut cells, marker, detail);
                    }
                    PresentationEvent::ProviderNote { kind, detail } => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::ChatNote {
                            text: provider_note_text(&kind, &detail),
                        });
                    }
                    // B7/D9. Both of these have a reply this client may already have drawn
                    // in full. Where it did, the durable record is skipped rather than
                    // drawn a second time in a thinner form — and where it did not (a
                    // second client watching, a session reopened after a restart), this is
                    // the only copy and it is drawn.
                    PresentationEvent::OperatorShell(shell) => {
                        flush_agent(&mut cells, &mut pending, false);
                        let block = shell_block(&shell);

                        if !block
                            .key
                            .as_ref()
                            .is_some_and(|key| drawn_locally.contains(key))
                        {
                            cells.push(Cell::Runtime(block));
                        }
                    }
                    PresentationEvent::Compaction(report) => {
                        flush_agent(&mut cells, &mut pending, false);
                        let block = compaction_block(&report);

                        if !block
                            .key
                            .as_ref()
                            .is_some_and(|key| drawn_locally.contains(key))
                        {
                            cells.push(Cell::Runtime(block));
                        }
                    }
                    PresentationEvent::Delegation(delegation) => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::Runtime(delegation_block(&delegation)));
                    }
                    PresentationEvent::ToolCall(call) => {
                        flush_agent(&mut cells, &mut pending, false);
                        project_tool_call(&mut cells, &mut tools, call);
                    }
                    PresentationEvent::ToolResult(result) => {
                        flush_agent(&mut cells, &mut pending, false);
                        project_tool_result(&mut cells, &mut tools, result);
                    }
                    PresentationEvent::CommandOutput(text) => {
                        flush_agent(&mut cells, &mut pending, false);
                        append_command_output(&mut cells, text);
                    }
                    PresentationEvent::FileUpdate(update) => {
                        flush_agent(&mut cells, &mut pending, false);
                        let mut emitted_file = false;
                        let inferred_diff_path = if update.changes.len() == 1 {
                            update.changes[0].path.clone()
                        } else {
                            None
                        };

                        for change in update.changes {
                            emitted_file = true;
                            project_file(
                                &mut cells,
                                &mut turn_diffs,
                                &open_approvals,
                                &mut approval_diffs,
                                change,
                                update.status.as_deref(),
                            );
                        }

                        if !emitted_file && update.diff.is_none() {
                            cells.push(Cell::File(FileCell {
                                path: None,
                                kind: update.status.clone(),
                            }));
                        }

                        if let Some(mut diff) = update.diff {
                            if diff.path.is_none() {
                                diff.path = inferred_diff_path;
                            }
                            project_diff(
                                &mut cells,
                                &mut turn_diffs,
                                &open_approvals,
                                &mut approval_diffs,
                                diff,
                            );
                        }
                    }
                    PresentationEvent::ApprovalRequested { request_id, detail } => {
                        flush_agent(&mut cells, &mut pending, false);
                        let index = cells.len();
                        if let Some(request_id) = &request_id {
                            approvals.insert(request_id.clone(), index);
                        }
                        open_approvals.push((request_id, detail.clone()));
                        cells.push(Cell::Status {
                            label: "Approval needed".into(),
                            detail,
                            tone: Tone::Warning,
                        });
                    }
                    PresentationEvent::ApprovalResolved {
                        request_id,
                        decision,
                        detail,
                    } => {
                        flush_agent(&mut cells, &mut pending, false);
                        settle_approved_diffs(
                            &mut cells,
                            &mut approval_diffs,
                            &mut open_approvals,
                            request_id.as_deref(),
                        );
                        project_approval_resolution(
                            &mut cells,
                            &mut approvals,
                            request_id,
                            decision,
                            detail,
                        );
                    }
                    PresentationEvent::Failure(detail) => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::Status {
                            label: "Agent error".into(),
                            detail,
                            tone: Tone::Error,
                        });
                    }
                    PresentationEvent::Interrupted(detail) => {
                        flush_agent(&mut cells, &mut pending, false);
                        cells.push(Cell::Status {
                            label: "Interrupted".into(),
                            detail,
                            tone: Tone::Warning,
                        });
                    }
                    // Drawn as nothing, for a reason the presentation recorded. The event
                    // itself is still in `/details`.
                    PresentationEvent::Hidden(_reason) => {}
                }
            }
        }
    }

    flush_agent(&mut cells, &mut pending, true);
    settle_thinking(&mut cells);
    settle_exploration(&mut cells);
    settle_running_tools(&mut cells, newest_at);
    cells
}

/// Where a correlated tool call was projected: a cell of its own, or one row inside a
/// grouped exploration cell.
#[derive(Debug, Clone, Copy)]
struct ToolSlot {
    cell: usize,
    entry: Option<usize>,
}

fn tool_at(cells: &mut [Cell], slot: ToolSlot) -> Option<&mut ToolCell> {
    match (cells.get_mut(slot.cell)?, slot.entry) {
        (Cell::Tool(tool), None) => Some(tool),
        (Cell::Exploration(group), Some(entry)) => group.calls.get_mut(entry),
        _ => None,
    }
}

/// A grouped exploration cell is open exactly while it is the last thing drawn.
///
/// The rule needs no bookkeeping because it is the same statement as the requirement:
/// "consecutive, with no other cell between them". Anything else pushed — a message, a
/// diff, a turn divider — makes the group no longer last, and it flips to `Explored N`.
fn settle_exploration(cells: &mut [Cell]) {
    let last = cells.len().saturating_sub(1);

    for (index, cell) in cells.iter_mut().enumerate() {
        if let Cell::Exploration(group) = cell {
            group.done = index != last;
        }
    }
}

/// Gives every still-running tool the newest instant this window holds, so its row can
/// state a floor on how long it has been running. See [`ToolCell::elapsed`].
fn settle_running_tools(cells: &mut [Cell], newest_at: Option<i64>) {
    let Some(newest_at) = newest_at else {
        return;
    };

    let mut settle = |tool: &mut ToolCell| {
        if tool.state == ToolState::Running && tool.settled_at.is_none() {
            tool.settled_at = Some(newest_at);
        }
    };

    for cell in cells {
        match cell {
            Cell::Tool(tool) => settle(tool),
            Cell::Exploration(group) => group.calls.iter_mut().for_each(&mut settle),
            _ => {}
        }
    }
}

/// Reasoning is watched while it is still arriving and folds away once it is not.
///
/// "Still arriving" is exactly "nothing has been drawn after it yet", so the rule needs no
/// bookkeeping: every reasoning cell but the last one is collapsed to its header.
fn settle_thinking(cells: &mut [Cell]) {
    let last = cells.len().saturating_sub(1);

    for (index, cell) in cells.iter_mut().enumerate() {
        if let Cell::Thinking { state, .. } = cell {
            *state = if index == last {
                ThinkingState::Tail
            } else {
                ThinkingState::Collapsed
            };
        }
    }
}

fn project_thinking(
    cells: &mut Vec<Cell>,
    thinking: &mut Option<PendingThinking>,
    turn_id: Option<String>,
    text: String,
) {
    let open = thinking.as_ref().filter(|open| {
        open.index + 1 == cells.len()
            && (open.turn_id == turn_id || open.turn_id.is_none() || turn_id.is_none())
    });

    if let Some(open) = open {
        if let Some(Cell::Thinking {
            text: existing,
            lines,
            ..
        }) = cells.get_mut(open.index)
        {
            append_bounded(existing, &text, THINKING_BYTES, THINKING_TRUNCATION);
            *lines = existing.lines().count();
            return;
        }
    }

    *thinking = Some(PendingThinking {
        turn_id,
        index: cells.len(),
    });
    cells.push(Cell::Thinking {
        lines: text.lines().count(),
        text: bound_owned(text, THINKING_BYTES, THINKING_TRUNCATION),
        state: ThinkingState::Tail,
    });
}

/// A provider event nobody modelled, as one line that names what it was.
fn provider_note_text(kind: &str, detail: &str) -> String {
    let mut text = "provider event".to_string();

    if !kind.trim().is_empty() {
        text.push_str(" · ");
        text.push_str(kind.trim());
    }
    if !detail.trim().is_empty() {
        text.push_str(" — ");
        text.push_str(detail.trim());
    }

    text
}

fn run_started_note(run: &crate::model::transcript::RunStart) -> String {
    let mut parts = vec!["run started".to_string()];

    if let Some(model) = &run.model {
        parts.push(model.clone());
    }
    if run.tool_count > 0 {
        parts.push(format!("{} tools", run.tool_count));
    }
    if let Some(cwd) = &run.cwd {
        parts.push(cwd.clone());
    }

    parts.join(" · ")
}

fn project_lifecycle(cells: &mut Vec<Cell>, marker: Lifecycle, detail: String) {
    let label = marker.label();
    // `session_closed` carries `{"reason": "closed"}`, which would otherwise read as
    // "session closed · closed". A detail the label already contains adds nothing.
    let detail = detail.trim();
    let text = if detail.is_empty() || label.contains(&detail.to_ascii_lowercase()) {
        label.to_string()
    } else {
        format!("{label} · {detail}")
    };

    match marker {
        // A closed session is the end of the reading path, so it reads as a rule across it
        // rather than as another muted aside.
        Lifecycle::SessionClosed => cells.push(Cell::Divider {
            text,
            tone: Tone::Muted,
            kind: DividerKind::Other,
        }),
        _ => cells.push(Cell::ChatNote { text }),
    }
}

fn project_turn_end(
    cells: &mut Vec<Cell>,
    turn_starts: &BTreeMap<String, i64>,
    turn_id: Option<String>,
    at: Option<i64>,
    outcome: TurnOutcome,
    detail: String,
) {
    // A failure is still a failure: the divider terminates the turn, and the error the
    // provider reported keeps its own loud cell above it.
    match outcome {
        TurnOutcome::Failed => cells.push(Cell::Status {
            label: "Agent error".into(),
            detail: detail.clone(),
            tone: Tone::Error,
        }),
        TurnOutcome::Interrupted => cells.push(Cell::Status {
            label: "Interrupted".into(),
            detail: detail.clone(),
            tone: Tone::Warning,
        }),
        TurnOutcome::Completed => {}
    }

    let elapsed = turn_id
        .as_ref()
        .and_then(|turn_id| turn_starts.get(turn_id))
        .zip(at)
        .and_then(|(start, end)| end.checked_sub(*start))
        .filter(|elapsed| *elapsed >= 0)
        .map(|elapsed| format!(" · {}", duration(elapsed)));

    cells.push(Cell::Divider {
        text: format!("{}{}", outcome.label(), elapsed.unwrap_or_default()),
        tone: match outcome {
            TurnOutcome::Completed => Tone::Muted,
            TurnOutcome::Failed => Tone::Error,
            TurnOutcome::Interrupted => Tone::Warning,
        },
        kind: DividerKind::TurnEnd,
    });
}

/// Codex's elapsed-time phrasing: `4m 07s`, `1h 02m`, `840ms`.
pub fn duration(millis: i64) -> String {
    let seconds = millis / 1_000;

    if seconds == 0 {
        return format!("{millis}ms");
    }
    if seconds < 60 {
        return format!("{seconds}s");
    }
    if seconds < 3_600 {
        return format!("{}m {:02}s", seconds / 60, seconds % 60);
    }

    format!("{}h {:02}m", seconds / 3_600, (seconds % 3_600) / 60)
}

/// The newest agent message in chat projection, for copy-last-message.
pub fn last_agent_message(entries: Vec<Entry<'_>>) -> Option<String> {
    project(entries)
        .into_iter()
        .rev()
        .find_map(|cell| match cell {
            Cell::Message {
                speaker: Speaker::Agent,
                text,
                streaming: _,
            } if !text.trim().is_empty() => Some(text),
            _ => None,
        })
}

/// Projects and renders a transcript. Kept as one pure call for the session pane and tests.
pub fn render(entries: Vec<Entry<'_>>, width: usize) -> Vec<Line<'static>> {
    render_at(entries, width, 0, Verbosity::Compact)
}

pub fn render_at(
    entries: Vec<Entry<'_>>,
    width: usize,
    tick: u64,
    verbosity: Verbosity,
) -> Vec<Line<'static>> {
    render_cells_at(&project(entries), width, tick, verbosity)
}

pub fn render_cells(cells: &[Cell], width: usize) -> Vec<Line<'static>> {
    render_cells_at(cells, width, 0, Verbosity::Compact)
}

pub fn render_cells_at(
    cells: &[Cell],
    width: usize,
    tick: u64,
    verbosity: Verbosity,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // `/raw` is a different renderer, not a flag threaded through this one. Codex's raw
    // mode exists so a terminal selection yields logical lines, and every `if raw` sprinkled
    // through a decorating renderer is another place a gutter survives the toggle.
    //
    // Screen-reader mode wants the same renderer and a different vocabulary: no boxes, no
    // gutters, no glyph column — and labels that are words with colons rather than the
    // shorthand a sighted reader scans past. So it is one plain renderer and two
    // [`Vocabulary`] values, not a third renderer to keep true.
    if let Some(vocabulary) = Vocabulary::plain(verbosity) {
        for cell in cells {
            render_plain(&mut lines, cell, vocabulary);
        }
        return lines;
    }

    for cell in cells {
        match cell {
            Cell::Message {
                speaker,
                text,
                streaming,
            } => render_message(
                &mut lines, *speaker, text, width, *streaming, tick, verbosity,
            ),
            Cell::Thinking {
                text,
                lines: rows,
                state,
            } => render_thinking(&mut lines, text, *rows, *state, width, verbosity),
            Cell::Plan(plan) => render_plan(&mut lines, plan, width, "Plan"),
            Cell::Usage(usage) => {
                if verbosity.verbose() {
                    render_chat_note(&mut lines, &usage_note(usage), width);
                }
            }
            Cell::Tool(tool) => render_tool(&mut lines, tool, width, tick, verbosity),
            Cell::Exploration(group) => {
                render_exploration(&mut lines, group, width, tick, verbosity)
            }
            Cell::CommandOutput(text) => render_command_output(&mut lines, text, width, verbosity),
            Cell::File(file) => render_file(&mut lines, file, width),
            Cell::Image(image) => render_image(&mut lines, image, width),
            Cell::Diff(diff) => render_diff(&mut lines, diff, width, verbosity),
            Cell::DiffStat {
                files,
                additions,
                deletions,
                in_excerpt,
            } => render_diffstat(&mut lines, *files, *additions, *deletions, *in_excerpt),
            Cell::Status {
                label,
                detail,
                tone,
            } => render_status(&mut lines, label, detail, colour(*tone), width, verbosity),
            Cell::ChatNote { text } => render_chat_note(&mut lines, text, width),
            Cell::Runtime(block) => render_runtime_block(&mut lines, block, width, verbosity),
            Cell::Divider { text, tone, .. } => lines.push(divider(text, width, colour(*tone))),
        }
    }

    lines
}

/// Which plain rendering is being asked for, and therefore which words label a block.
///
/// Both drop the frames, the gutters, the glyph columns, and the app-side wrapping. What
/// separates them is who is reading: `/raw` is for a *selection* — one output row per
/// logical line so a `Shift`-drag yields the text back — and screen-reader mode is for a
/// *voice*, so every label is a word with a colon and every truncation marker is a
/// sentence instead of `… +12 · ctrl+o`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vocabulary {
    Raw,
    ScreenReader,
}

impl Vocabulary {
    /// Which plain rendering applies, or `None` for the ordinary decorated one.
    ///
    /// Screen-reader mode wins over `/raw`: someone who turned it on is not going to want
    /// their next `/raw` to take the labels away again.
    fn plain(verbosity: Verbosity) -> Option<Self> {
        if super::access::screen_reader() {
            return Some(Self::ScreenReader);
        }

        verbosity.raw().then_some(Self::Raw)
    }

    fn screen_reader(self) -> bool {
        self == Self::ScreenReader
    }

    /// One of the eight canonical labels, or the raw mode's bare word.
    fn label(self, label: super::access::Label, raw: &str) -> String {
        match self.screen_reader() {
            true => label.as_str().to_string(),
            false => raw.to_string(),
        }
    }

    /// A label with a detail after it: `tool: Bash · completed` against `Bash · completed`.
    fn detailed(self, label: super::access::Label, raw: &str, detail: &str) -> String {
        match self.screen_reader() {
            true => format!("{} {detail}", label.as_str()),
            false => match raw.is_empty() {
                true => detail.to_string(),
                false => format!("{raw} · {detail}"),
            },
        }
    }
}

fn render_plain(lines: &mut Vec<Line<'static>>, cell: &Cell, vocabulary: Vocabulary) {
    use super::access::Label;

    let spoken = vocabulary.screen_reader();

    let label = move |lines: &mut Vec<Line<'static>>, text: String| {
        if !lines.is_empty() {
            lines.push(Line::from(""));
        }

        // The separators are this client's own punctuation, so they are this client's to
        // spell differently for a reader that has to say them out loud.
        let text = match spoken {
            true => super::access::speakable(&text),
            false => text,
        };

        lines.push(Line::from(Span::styled(text, theme::label())));
    };

    // `/raw` writes everything: it exists so a selection yields the whole thing back, and
    // a copying view that folded half the transcript away would be a worse answer than the
    // one it replaced. Screen-reader mode is the opposite case — a ten-thousand-line tool
    // result read aloud in full is the thing the mode exists to prevent — so it keeps the
    // pane's own budget and says, in a sentence, what it left out.
    let budget = spoken.then_some(PLAIN_SPOKEN_LINES);

    let body = move |lines: &mut Vec<Line<'static>>, text: &str, style: Style| {
        let all: Vec<&str> = text.lines().collect();
        let shown = budget.map_or(all.len(), |budget| all.len().min(budget));

        for line in all.iter().take(shown) {
            lines.push(Line::from(Span::styled((*line).to_string(), style)));
        }

        if let Some(omitted) = all.len().checked_sub(shown).filter(|left| *left > 0) {
            lines.push(Line::from(Span::styled(
                super::access::omitted(omitted, "line", "ctrl+o"),
                theme::quiet(),
            )));
        }
    };

    match cell {
        Cell::Message {
            speaker,
            text,
            streaming,
        } => {
            let still = match streaming {
                true => " still writing",
                false => "",
            };

            label(
                lines,
                match (speaker, vocabulary.screen_reader()) {
                    (Speaker::You, _) => vocabulary.label(Label::You, "you"),
                    (Speaker::Agent, true) => format!("{}{still}", Label::Agent.as_str()),
                    (Speaker::Agent, false) => match streaming {
                        true => "agent · still writing".to_string(),
                        false => "agent".to_string(),
                    },
                },
            );
            body(lines, text, Style::default());
        }
        Cell::Thinking {
            text, lines: rows, ..
        } => {
            label(
                lines,
                vocabulary.detailed(Label::Thinking, "thinking", &format!("{rows} lines")),
            );
            body(lines, text, theme::quiet());
        }
        Cell::Plan(plan) => {
            label(lines, format!("plan · {} steps", plan.step_count));
            for step in &plan.steps {
                // ASCII marks, the same ones the export uses: a glyph column is the first
                // thing a copy loses, and `[x]` says what `✓` says without one.
                let mark = match &step.status {
                    PlanStatus::Done => "[x]".to_string(),
                    PlanStatus::InProgress => "[>]".to_string(),
                    PlanStatus::Pending => "[ ]".to_string(),
                    PlanStatus::Other(word) => format!("[{word}]"),
                };
                lines.push(Line::from(Span::raw(format!(
                    "{mark} {}",
                    step.text.replace('\n', " ")
                ))));
            }
        }
        Cell::Usage(usage) => label(lines, usage_note(usage)),
        Cell::Tool(tool) => {
            // `tool error:` is a label of its own in the taxonomy because "this call
            // failed" is the one thing about a tool row that a reader must not have to
            // infer from a word buried at the end of it.
            let kind = match tool.state {
                ToolState::Failed => Label::ToolError,
                _ => Label::Tool,
            };
            label(lines, vocabulary.detailed(kind, "", &raw_tool_label(tool)));
            if let Some(output) = &tool.output {
                body(lines, &value_text(output), theme::quiet());
            }
        }
        Cell::Exploration(group) => {
            label(
                lines,
                vocabulary.detailed(Label::Tool, "", &exploration_heading(group)),
            );
            for call in &group.calls {
                lines.push(Line::from(Span::raw(raw_tool_label(call))));
            }
            if group.overflow > 0 {
                lines.push(Line::from(Span::styled(
                    match vocabulary.screen_reader() {
                        true => super::access::omitted(group.overflow, "call", "slash details"),
                        false => format!("+{} more calls · /details", group.overflow),
                    },
                    theme::quiet(),
                )));
            }
        }
        Cell::CommandOutput(text) => {
            label(
                lines,
                vocabulary.detailed(Label::Tool, "", "command output"),
            );
            body(lines, text, theme::quiet());
        }
        Cell::File(file) => label(
            lines,
            format!(
                "file {}{}",
                file.path.as_deref().unwrap_or("(path not reported)"),
                file.kind
                    .as_deref()
                    .map(|kind| format!(" · {kind}"))
                    .unwrap_or_default()
            ),
        ),
        // A11. Always the placeholder here, whatever the terminal can do. `/raw` is a
        // copying view and a picture yields nothing to a selection; screen-reader mode is
        // the case the placeholder was written for in the first place.
        Cell::Image(image) => label(lines, image.label()),
        Cell::Diff(diff) => {
            for file in &diff.parsed.files {
                label(lines, diff_heading(file, diff));
                for hunk in &file.hunks {
                    lines.push(Line::from(Span::styled(
                        super::diff::hunk_label(hunk),
                        Style::default().fg(theme::accent()),
                    )));
                    for line in &hunk.lines {
                        lines.push(Line::from(Span::styled(
                            format!("{}{}", raw_sign(line.kind), line.text),
                            raw_diff_style(line.kind),
                        )));
                    }
                }
            }
            if diff.parsed.is_empty() {
                label(lines, "diff".to_string());
                body(lines, &diff.diff.text, theme::quiet());
            }
        }
        Cell::DiffStat {
            files,
            additions,
            deletions,
            in_excerpt,
        } => label(
            lines,
            super::diff::diffstat(*files, *additions, *deletions, *in_excerpt),
        ),
        Cell::Status {
            label: heading,
            detail,
            tone,
        } => {
            let heading = heading.to_ascii_lowercase();
            label(
                lines,
                match vocabulary.screen_reader() {
                    true => attention(*tone, &heading),
                    false => heading,
                },
            );
            body(lines, detail, Style::default());
        }
        Cell::ChatNote { text } => label(lines, text.clone()),
        // The label carries the whole first line so a voice reads "compacted, at your
        // request — archived 12 messages" as one sentence rather than as a heading
        // followed by an orphaned fragment.
        Cell::Runtime(block) => {
            label(
                lines,
                match block.detail.trim().is_empty() {
                    true => block.label.clone(),
                    false => format!("{}: {}", block.label, block.detail),
                },
            );

            if !block.body.is_empty() {
                body(lines, &block.body.join("\n"), theme::quiet());
            }
        }
        // ASCII, not a box rule: a boundary is still content, and a copied line should not
        // arrive somewhere else carrying U+2500.
        Cell::Divider { text, tone, .. } => label(
            lines,
            match vocabulary.screen_reader() {
                true => attention(*tone, text),
                false => format!("-- {text}"),
            },
        ),
    }
}

/// A heading with its attention label in front, said once.
///
/// A heading that already carries the label's own words — the projection's
/// "Approval needed" — becomes the label and nothing else, because "approval needed:
/// approval needed" is what a taxonomy bolted onto text that already had one sounds like.
fn attention(tone: Tone, heading: &str) -> String {
    let Some(named) = tone_label(tone, heading) else {
        return heading.to_string();
    };

    let words = named.as_str().trim_end_matches(':');
    let rest = heading
        .trim()
        .strip_prefix(words)
        .or_else(|| {
            heading
                .to_ascii_lowercase()
                .starts_with(words)
                .then(|| &heading.trim()[words.len()..])
        })
        .map(str::trim)
        .unwrap_or(heading.trim());

    match rest.is_empty() {
        true => named.as_str().to_string(),
        false => format!("{} {rest}", named.as_str()),
    }
}

/// Which of the three attention labels a tone and its heading amount to.
///
/// A status row is the only cell whose *kind* is carried by a colour, so screen-reader
/// mode is the one rendering that has to turn it back into a word. "Approval needed" is
/// picked out of the warning tone by what the heading says rather than by a fourth tone,
/// because the projection already distinguishes them in the only place that matters — the
/// text — and inventing a tone for it would put the same fact in two places.
fn tone_label(tone: Tone, heading: &str) -> Option<super::access::Label> {
    use super::access::Label;

    let heading = heading.to_ascii_lowercase();
    if heading.contains("approval needed") {
        return Some(Label::ApprovalNeeded);
    }

    match tone {
        Tone::Error => Some(Label::Error),
        Tone::Warning => Some(Label::Warning),
        Tone::Muted | Tone::Success => None,
    }
}

fn raw_sign(kind: super::diff::LineKind) -> &'static str {
    match kind {
        super::diff::LineKind::Added => "+",
        super::diff::LineKind::Removed => "-",
        super::diff::LineKind::Context => " ",
        super::diff::LineKind::Meta => "",
    }
}

fn raw_diff_style(kind: super::diff::LineKind) -> Style {
    match kind {
        super::diff::LineKind::Added => theme::diff_added(),
        super::diff::LineKind::Removed => theme::diff_removed(),
        _ => Style::default(),
    }
}

fn raw_tool_label(tool: &ToolCell) -> String {
    let summary = summarise(tool);
    let state = match tool.state {
        ToolState::Running => " · running",
        ToolState::Failed => " · failed",
        ToolState::Completed => "",
    };
    let elapsed = tool
        .elapsed()
        .map(|elapsed| format!(" · {}", duration(elapsed)))
        .unwrap_or_default();

    format!("{}{state}{elapsed}", summary.line())
}

/// One token report, phrased only in the numbers the provider actually sent.
pub fn usage_note(usage: &UsageReport) -> String {
    let mut parts = vec!["usage".to_string()];

    if let Some(input) = usage.input_tokens {
        parts.push(format!("in {input}"));
    }
    if let Some(output) = usage.output_tokens {
        parts.push(format!("out {output}"));
    }
    if let Some(cached) = usage.cached_tokens {
        parts.push(format!("cached {cached}"));
    }
    if let Some(total) = usage.total_tokens {
        parts.push(format!("total {total}"));
    }
    if let Some(cost) = usage.cost_usd {
        parts.push(format!("${cost:.4}"));
    }

    parts.join(" · ")
}

/// The plan as rows, for the transcript cell and the `Ctrl+T` panel alike.
///
/// `◌ ● ✓` are Warp's glyphs. A status this client does not recognise keeps the provider's
/// own word beside a `?`, because a panel that guessed "done" would report finished work
/// that never happened.
pub fn render_plan(lines: &mut Vec<Line<'static>>, plan: &PlanUpdate, width: usize, heading: &str) {
    separate(lines);

    let done = plan
        .steps
        .iter()
        .filter(|step| step.status == PlanStatus::Done)
        .count();
    lines.push(Line::from(vec![
        Span::styled(format!("◇ {heading}  "), theme::heading()),
        Span::styled(
            format!("{done}/{} done", plan.step_count.max(plan.steps.len())),
            theme::quiet(),
        ),
    ]));

    if let Some(explanation) = &plan.explanation {
        for line in wrap_limited(explanation, width.saturating_sub(4).max(8), 8) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(line, theme::quiet()),
            ]));
        }
    }

    for step in &plan.steps {
        let style = match step.status {
            PlanStatus::Done => Style::default()
                .fg(theme::good())
                .add_modifier(Modifier::DIM),
            PlanStatus::InProgress => Style::default().fg(theme::accent()),
            PlanStatus::Pending => theme::quiet(),
            PlanStatus::Other(_) => Style::default().fg(theme::warn()),
        };
        let suffix = match &step.status {
            PlanStatus::Other(status) => format!("  ({status})"),
            _ => String::new(),
        };
        let body = format!("{}{suffix}", step.text.replace('\n', " "));

        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{} ", step.status.glyph()), style),
            Span::styled(
                super::tree::truncate(&body, width.saturating_sub(6).max(8)),
                style,
            ),
        ]));
    }

    if plan.step_count > plan.steps.len() {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!(
                    "… {} more steps; full plan in /details",
                    plan.step_count - plan.steps.len()
                ),
                theme::quiet(),
            ),
        ]));
    }
}

fn render_thinking(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    rows: usize,
    state: ThinkingState,
    width: usize,
    verbosity: Verbosity,
) {
    let state = if verbosity.verbose() {
        ThinkingState::Full
    } else {
        state
    };

    separate(lines);
    lines.push(Line::from(vec![
        Span::styled("◇ thinking  ", theme::quiet()),
        Span::styled(
            format!("{rows} line{}", if rows == 1 { "" } else { "s" }),
            theme::quiet(),
        ),
        Span::styled(
            match state {
                ThinkingState::Collapsed => "  ctrl+o expands",
                _ => "",
            },
            Style::default().fg(theme::muted()),
        ),
    ]));

    let (body, omitted) = match state {
        ThinkingState::Collapsed => return,
        ThinkingState::Full => (text, 0),
        ThinkingState::Tail => tail_lines(text, THINKING_TAIL_LINES),
    };

    if omitted > 0 {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("… {omitted} earlier lines of reasoning; ctrl+o shows them"),
                theme::quiet(),
            ),
        ]));
    }

    render_indented_text(
        lines,
        body,
        width,
        verbosity.lines(THINKING_TAIL_LINES),
        &verbosity.provenance("reasoning"),
    );
}

/// The last `limit` lines of a block, and how many were left above them.
fn tail_lines(text: &str, limit: usize) -> (&str, usize) {
    let total = text.lines().count();
    if total <= limit {
        return (text, 0);
    }

    let skip = total - limit;
    let mut seen = 0;
    for (at, character) in text.char_indices() {
        if character == '\n' {
            seen += 1;
            if seen == skip {
                return (&text[at + 1..], skip);
            }
        }
    }

    (text, 0)
}

fn project_agent_text(
    cells: &mut Vec<Cell>,
    pending: &mut Option<PendingOutput>,
    turn_id: Option<String>,
    text: String,
    final_text: bool,
) {
    let same_turn = pending
        .as_ref()
        .map(|draft| draft.turn_id == turn_id || draft.turn_id.is_none() || turn_id.is_none())
        .unwrap_or(!final_text);

    if !same_turn {
        flush_agent(cells, pending, false);
    }

    if final_text {
        let fallback = pending.take().map(|draft| draft.text).unwrap_or_default();
        let text = if text.is_empty() { fallback } else { text };

        if !text.trim().is_empty() {
            cells.push(Cell::Message {
                speaker: Speaker::Agent,
                text,
                streaming: false,
            });
        }
    } else if !text.is_empty() {
        let draft = pending.get_or_insert_with(|| PendingOutput {
            turn_id,
            text: String::new(),
        });
        append_bounded(&mut draft.text, &text, AGENT_OUTPUT_BYTES, AGENT_TRUNCATION);
    }
}

fn flush_agent(cells: &mut Vec<Cell>, pending: &mut Option<PendingOutput>, streaming: bool) {
    let Some(draft) = pending.take() else {
        return;
    };

    if !draft.text.trim().is_empty() {
        cells.push(Cell::Message {
            speaker: Speaker::Agent,
            text: draft.text,
            streaming,
        });
    }
}

fn project_tool_call(
    cells: &mut Vec<Cell>,
    tools: &mut BTreeMap<String, ToolSlot>,
    call: ToolCall,
) {
    if let Some(slot) = call
        .call_id
        .as_ref()
        .and_then(|call_id| tools.get(call_id))
        .copied()
    {
        if let Some(tool) = tool_at(cells, slot) {
            // Some providers repeat the normalized call when publishing its result.
            // Refresh the descriptive fields but retain the row's lifecycle and output.
            tool.name = call.name;
            tool.kind = call.kind.or_else(|| tool.kind.take());
            tool.input = call.input;
            return;
        }
    }

    let call_id = call.call_id.clone();
    let mut cell = ToolCell::new(call.call_id, call.name, call.kind, call.input);
    cell.started_at = call.at;

    if summarise(&cell).shape.explores() {
        return group_exploration(cells, tools, call_id, cell);
    }

    if let Some(call_id) = call_id {
        tools.insert(
            call_id,
            ToolSlot {
                cell: cells.len(),
                entry: None,
            },
        );
    }
    cells.push(Cell::Tool(cell));
}

/// Codex's coalescing: an exploration call joins the group already at the end of the
/// transcript, or opens a new one.
fn group_exploration(
    cells: &mut Vec<Cell>,
    tools: &mut BTreeMap<String, ToolSlot>,
    call_id: Option<String>,
    cell: ToolCell,
) {
    let index = cells.len().saturating_sub(1);
    if let Some(Cell::Exploration(group)) = cells.last_mut() {
        if group.calls.len() < EXPLORATION_CALLS {
            let entry = group.calls.len();
            group.calls.push(cell);
            if let Some(call_id) = call_id {
                tools.insert(
                    call_id,
                    ToolSlot {
                        cell: index,
                        entry: Some(entry),
                    },
                );
            }
        } else {
            // Past the listing ceiling the call is counted, not held. Its own events remain
            // complete in `/details`; what this cell would lose by holding them is the
            // bound that keeps one runaway loop from owning the transcript.
            group.overflow += 1;
        }
        return;
    }

    if let Some(call_id) = call_id {
        tools.insert(
            call_id,
            ToolSlot {
                cell: cells.len(),
                entry: Some(0),
            },
        );
    }
    cells.push(Cell::Exploration(ExplorationCell {
        calls: vec![cell],
        overflow: 0,
        done: false,
    }));
}

fn project_tool_result(
    cells: &mut Vec<Cell>,
    tools: &mut BTreeMap<String, ToolSlot>,
    result: ToolResult,
) {
    let matched = result
        .call_id
        .as_ref()
        .and_then(|call_id| tools.get(call_id))
        .copied();

    if let Some(slot) = matched {
        if let Some(tool) = tool_at(cells, slot) {
            if tool.name == "tool" {
                if let Some(name) = result.name {
                    tool.name = name;
                }
            }
            if tool.kind.is_none() {
                tool.kind = result.kind;
            }
            tool.state = if result.is_error {
                ToolState::Failed
            } else {
                ToolState::Completed
            };
            tool.settled_at = result.at;
            // Command-output deltas carry no call id, so their presence cannot prove that
            // this result is duplicate. Keep the correlated authoritative result visible;
            // hiding it because another parallel command streamed would lose evidence.
            if !result.output.is_null() {
                tool.output = Some(result.output);
            }
            return;
        }
    }

    let mut cell = ToolCell::new(
        result.call_id,
        result.name.unwrap_or_else(|| "tool result".into()),
        result.kind,
        Value::Object(Default::default()),
    );
    cell.output = (!result.output.is_null()).then_some(result.output);
    cell.state = if result.is_error {
        ToolState::Failed
    } else {
        ToolState::Completed
    };
    cell.settled_at = result.at;

    cells.push(Cell::Tool(cell));
}

/// Pushes one diff cell, parsed, with Warp's pending-approval state resolved.
fn project_diff(
    cells: &mut Vec<Cell>,
    turn_diffs: &mut Vec<usize>,
    open_approvals: &[(Option<String>, String)],
    approval_diffs: &mut BTreeMap<String, Vec<usize>>,
    diff: Diff,
) {
    let parsed = super::diff::parse(&diff.text, diff.path.as_deref());
    let index = cells.len();
    let mut pending_approval = false;

    for (request_id, subject) in open_approvals {
        if !mentions_any(subject, &parsed, diff.path.as_deref()) {
            continue;
        }
        pending_approval = true;
        if let Some(request_id) = request_id {
            approval_diffs
                .entry(request_id.clone())
                .or_default()
                .push(index);
        }
    }

    turn_diffs.push(index);
    cells.push(Cell::Diff(DiffCell {
        diff,
        parsed,
        pending_approval,
    }));
}

/// Whether an outstanding approval's subject names any path this diff touches.
///
/// Deliberately a containment test on the paths the *diff* reported, not a parse of the
/// approval payload: the payload's shape differs per dialect, and a client that guessed
/// wrong would mark an unrelated change "pending approval" — a claim about authority.
fn mentions_any(subject: &str, parsed: &super::diff::ParsedDiff, fallback: Option<&str>) -> bool {
    let candidates = parsed
        .files
        .iter()
        .map(|file| file.path.as_str())
        .chain(fallback);

    candidates.filter(|path| !path.is_empty()).any(|path| {
        subject.contains(path)
            || path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.len() > 3 && subject.contains(name))
    })
}

/// Warp's second half: once the approval resolves, its diffs collapse back to their header.
fn settle_approved_diffs(
    cells: &mut [Cell],
    approval_diffs: &mut BTreeMap<String, Vec<usize>>,
    open_approvals: &mut Vec<(Option<String>, String)>,
    request_id: Option<&str>,
) {
    let Some(request_id) = request_id else {
        // A resolution with no id cannot be matched to one request, so nothing is collapsed
        // on the strength of it. The pending diffs stay expanded until their own id lands.
        return;
    };

    open_approvals.retain(|(id, _)| id.as_deref() != Some(request_id));

    for index in approval_diffs.remove(request_id).unwrap_or_default() {
        if let Some(Cell::Diff(diff)) = cells.get_mut(index) {
            diff.pending_approval = false;
        }
    }
}

/// The post-turn diffstat, counted from the parses rather than from any provider's summary.
fn project_diffstat(cells: &mut Vec<Cell>, turn_diffs: &mut Vec<usize>) {
    let indices = std::mem::take(turn_diffs);
    if indices.is_empty() {
        return;
    }

    let mut paths: Vec<String> = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;
    let mut in_excerpt = false;

    for index in indices {
        let Some(Cell::Diff(diff)) = cells.get(index) else {
            continue;
        };
        in_excerpt |= diff.parsed.truncated || diff.diff.truncated;
        for file in &diff.parsed.files {
            additions += file.additions;
            deletions += file.deletions;
            if !paths.iter().any(|seen| seen == &file.path) {
                paths.push(file.path.clone());
            }
        }
    }

    if paths.is_empty() {
        return;
    }

    cells.push(Cell::DiffStat {
        files: paths.len(),
        additions,
        deletions,
        in_excerpt,
    });
}

fn append_command_output(cells: &mut Vec<Cell>, text: String) {
    if let Some(Cell::CommandOutput(output)) = cells.last_mut() {
        append_bounded(output, &text, COMMAND_OUTPUT_BYTES, COMMAND_TRUNCATION);
    } else if !text.is_empty() {
        cells.push(Cell::CommandOutput(bound_owned(
            text,
            COMMAND_OUTPUT_BYTES,
            COMMAND_TRUNCATION,
        )));
    }
}

fn project_approval_resolution(
    cells: &mut Vec<Cell>,
    approvals: &mut BTreeMap<String, usize>,
    request_id: Option<String>,
    decision: Option<String>,
    resolution: String,
) {
    let (label, tone) = approval_outcome(decision.as_deref());
    let matched = request_id
        .as_ref()
        .and_then(|request_id| approvals.remove(request_id));

    if let Some(index) = matched {
        if let Some(Cell::Status {
            label: existing_label,
            detail,
            tone: existing_tone,
        }) = cells.get_mut(index)
        {
            *existing_label = label.into();
            *existing_tone = tone;
            if !resolution.trim().is_empty() && resolution != "{}" {
                if !detail.trim().is_empty() {
                    detail.push('\n');
                }
                detail.push_str(&resolution);
            }
            return;
        }
    }

    cells.push(Cell::Status {
        label: label.into(),
        detail: resolution,
        tone,
    });
}

fn approval_outcome(decision: Option<&str>) -> (&'static str, Tone) {
    match decision {
        Some("approve" | "approved") => ("Approved", Tone::Success),
        Some("deny" | "denied" | "decline" | "declined") => ("Denied", Tone::Warning),
        _ => ("Approval resolved", Tone::Muted),
    }
}

fn project_file(
    cells: &mut Vec<Cell>,
    turn_diffs: &mut Vec<usize>,
    open_approvals: &[(Option<String>, String)],
    approval_diffs: &mut BTreeMap<String, Vec<usize>>,
    change: FileChange,
    inherited_status: Option<&str>,
) {
    let path = change.path;
    cells.push(Cell::File(FileCell {
        path: path.clone(),
        kind: change
            .kind
            .or_else(|| inherited_status.map(ToOwned::to_owned)),
    }));

    if let Some(mut diff) = change.diff {
        if diff.path.is_none() {
            diff.path = path;
        }
        project_diff(cells, turn_diffs, open_approvals, approval_diffs, diff);
    }
}

/// The divider text for a *stream* note. A local note never reaches this — it is a
/// [`Cell::Runtime`] block, because nothing about it went wrong. Nor does an image note,
/// for the same reason: it is a [`Cell::Image`].
fn chat_note(note: &Note) -> &'static str {
    match note {
        Note::Lagged { .. } => "Some live updates were missed by the gateway",
        Note::ClientDropped => "Some live updates were missed by this client",
        Note::Reconnected => "Connection restored",
        Note::Local { .. } => "A runtime verb answered here",
        Note::Image { .. } => "An image was sent here",
    }
}

#[allow(clippy::too_many_arguments)]
fn render_message(
    lines: &mut Vec<Line<'static>>,
    speaker: Speaker,
    text: &str,
    width: usize,
    streaming: bool,
    tick: u64,
    verbosity: Verbosity,
) {
    separate(lines);
    match speaker {
        Speaker::You => render_user_message(lines, text, width, verbosity),
        Speaker::Agent => render_agent_message(lines, text, width, streaming, tick, verbosity),
    }
}

fn render_user_message(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: usize,
    verbosity: Verbosity,
) {
    let message_lines = verbosity.lines(MESSAGE_LINES);

    if width < 16 {
        lines.push(Line::from(vec![
            Span::styled("▌ ", theme::action()),
            Span::styled("YOU", theme::action()),
        ]));
        for line in wrap_limited(text, width.saturating_sub(2).max(8), message_lines) {
            lines.push(Line::from(Span::raw(line)));
        }
        return;
    }

    let border = Style::default().fg(theme::muted());
    let heading_width = "┌─ ▌ YOU ".width();
    lines.push(Line::from(vec![
        Span::styled("┌─ ", border),
        Span::styled("▌ YOU ", theme::action()),
        Span::styled(
            format!("{}┐", "─".repeat(width.saturating_sub(heading_width + 1))),
            border,
        ),
    ]));

    let wrapped = wrap_limited(
        text,
        width.saturating_sub(4).max(8),
        message_lines.saturating_add(1),
    );
    let shown = wrapped.len().min(message_lines);

    for line in wrapped.iter().take(shown) {
        let padding = width.saturating_sub(line.width() + 4);
        lines.push(Line::from(vec![
            Span::styled("│ ", border),
            Span::raw(line.clone()),
            Span::raw(" ".repeat(padding)),
            Span::styled(" │", border),
        ]));
    }

    if wrapped.len() > shown {
        let omitted = format!("… {}", verbosity.provenance("message"));
        let omitted = super::tree::truncate(&omitted, width.saturating_sub(4).max(8));
        let padding = width.saturating_sub(omitted.width() + 4);
        lines.push(Line::from(vec![
            Span::styled("│ ", border),
            Span::styled(omitted, theme::quiet()),
            Span::raw(" ".repeat(padding)),
            Span::styled(" │", border),
        ]));
    }

    lines.push(Line::from(Span::styled(
        format!("└{}┘", "─".repeat(width.saturating_sub(2))),
        border,
    )));
}

fn render_agent_message(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: usize,
    streaming: bool,
    tick: u64,
    verbosity: Verbosity,
) {
    let message_lines = verbosity.lines(MESSAGE_LINES);
    lines.push(Line::from(vec![
        Span::styled("◆ ", Style::default().fg(theme::system())),
        Span::styled(
            "AGENT",
            Style::default()
                .fg(theme::system())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" / RESPONSE", Style::default().fg(theme::system())),
    ]));

    // Agent prose is Markdown. Everything about how it becomes styled rows — the block
    // vocabulary, the streaming rule, the row budget, the per-(text, width) memo that
    // keeps a settled turn from being re-parsed twelve times a second — lives in one place.
    let rendered = markdown::render_cached(text, width, message_lines, streaming);

    lines.extend(rendered.lines.iter().cloned());

    if !rendered.complete {
        lines.push(Line::from(Span::styled(
            format!("… {}", verbosity.provenance("message")),
            theme::quiet(),
        )));
    }

    if streaming {
        // A caret that blinks is a cell that changes eight times a second forever. Reduced
        // motion keeps the mark — it is still true that this message is not finished — and
        // stops it moving.
        let caret = match super::access::reduced_motion() || tick % 8 < 5 {
            true => "▌",
            false => " ",
        };
        // A caret on a closed frame's floor reads as damage; only live content earns one.
        let on_live_content = lines
            .last()
            .and_then(|line| line.spans.first())
            .is_some_and(|span| !span.content.starts_with('└'));

        if on_live_content {
            if let Some(last_line) = lines.last_mut() {
                last_line
                    .spans
                    .push(Span::styled(caret, Style::default().fg(theme::accent())));
            }
        }
    }
}

/// The head row of a tool cell: state glyph, verb, subject, what the result proved, and how
/// long the ledger says it took.
fn tool_head(tool: &ToolCell, width: usize, tick: u64) -> Vec<Span<'static>> {
    let (mark, mark_style) = match tool.state {
        ToolState::Running => (
            theme::spinner(tick).to_string(),
            Style::default().fg(theme::accent()),
        ),
        ToolState::Completed => ("✓".to_string(), Style::default().fg(theme::good())),
        ToolState::Failed => ("✗".to_string(), Style::default().fg(theme::bad())),
    };
    let name_style = match tool.state {
        ToolState::Failed => Style::default().fg(theme::bad()),
        _ => Style::default(),
    };
    let summary = summarise(tool);
    // A running row says so; a finished one has its outcome instead, and saying both is how
    // a status column ends up restating itself.
    let state_suffix = match tool.state {
        ToolState::Running => "  running".to_string(),
        ToolState::Failed if summary.outcome.is_empty() => "  failed".to_string(),
        _ => String::new(),
    };
    let elapsed = tool
        .elapsed()
        .map(|elapsed| format!("  {}", duration(elapsed)))
        .unwrap_or_default();
    let outcome = if summary.outcome.is_empty() {
        String::new()
    } else {
        format!("  {}", summary.outcome)
    };

    let reserved = mark.width()
        + summary.verb.width()
        + state_suffix.width()
        + outcome.width()
        + elapsed.width()
        + 3;
    let subject = super::tree::truncate(
        &summary.subject,
        width.saturating_sub(4).saturating_sub(reserved),
    );

    let mut head = vec![
        Span::styled(format!("{mark} "), mark_style),
        Span::styled(summary.verb, name_style),
    ];

    if !subject.is_empty() {
        head.push(Span::raw("  "));
        head.push(Span::styled(subject, theme::quiet()));
    }
    if !outcome.is_empty() {
        head.push(Span::styled(
            outcome,
            match tool.state {
                ToolState::Failed => Style::default().fg(theme::bad()),
                _ => theme::quiet(),
            },
        ));
    }
    if !state_suffix.is_empty() {
        head.push(Span::styled(
            state_suffix,
            match tool.state {
                ToolState::Failed => Style::default().fg(theme::bad()),
                _ => theme::quiet(),
            },
        ));
    }
    if !elapsed.is_empty() {
        head.push(Span::styled(elapsed, theme::quiet()));
    }

    head
}

fn render_tool(
    lines: &mut Vec<Line<'static>>,
    tool: &ToolCell,
    width: usize,
    tick: u64,
    verbosity: Verbosity,
) {
    separate(lines);

    let head = tool_head(tool, width, tick);

    if width < 24 {
        lines.push(Line::from(head));
        if let Some(output) = &tool.output {
            let output = value_text(output);
            if !output.trim().is_empty() {
                render_excerpt(
                    lines,
                    &output,
                    width,
                    verbosity.lines(TOOL_OUTPUT_LINES),
                    &verbosity.provenance("result"),
                    if tool.state == ToolState::Failed {
                        Style::default().fg(theme::bad())
                    } else {
                        theme::quiet()
                    },
                );
            }
        }
        return;
    }

    let border = match tool.state {
        ToolState::Running => Style::default().fg(theme::system()),
        ToolState::Completed => Style::default().fg(theme::good()),
        ToolState::Failed => Style::default().fg(theme::bad()),
    };
    lines.push(Line::from(Span::styled(
        format!("┌{}┐", "─".repeat(width.saturating_sub(2))),
        border,
    )));
    lines.push(boxed_tool_row(head, width, border));
    render_tool_body(lines, tool, width, border, verbosity);
    lines.push(Line::from(Span::styled(
        format!("└{}┘", "─".repeat(width.saturating_sub(2))),
        border,
    )));
}

/// Codex's head/tail inside the tool frame: the first rows, a counted marker naming the key
/// that shows the rest, and the last rows.
///
/// A failure gets the head only. The `is_error` text is the message the tool produced, it
/// is written first, and pushing it behind six rows of the same stack trace's tail is how a
/// reader ends up expanding every failed cell to learn what a one-line error said.
fn render_tool_body(
    lines: &mut Vec<Line<'static>>,
    tool: &ToolCell,
    width: usize,
    border: Style,
    verbosity: Verbosity,
) {
    let Some(output) = &tool.output else {
        return;
    };
    let output = value_text(output);
    if output.trim().is_empty() {
        return;
    }

    let body = match tool.state {
        ToolState::Failed => Style::default().fg(theme::bad()),
        _ => theme::quiet(),
    };
    let content_width = width.saturating_sub(4).max(8);
    let mut row = |spans: Vec<Span<'static>>| lines.push(boxed_tool_row(spans, width, border));

    if verbosity.verbose() {
        let wrapped = wrap_limited(&output, content_width, VERBOSE_LINES.saturating_add(1));
        for line in wrapped.iter().take(VERBOSE_LINES) {
            row(vec![Span::styled(line.clone(), body)]);
        }
        if wrapped.len() > VERBOSE_LINES {
            row(vec![Span::styled(
                super::tree::truncate(
                    &format!("… {}", verbosity.provenance("result")),
                    content_width,
                ),
                theme::quiet(),
            )]);
        }
        return;
    }

    let tail_budget = if tool.state == ToolState::Failed {
        0
    } else {
        TOOL_TAIL_LINES
    };
    // Codex's order: head/tail on *source* lines first, then a row budget after wrapping.
    // Both cuts are announced, because a single 32 KiB line and a thousand short ones look
    // identical once the frame closes over them.
    let (head, omitted, tail) = head_tail(&output, TOOL_HEAD_LINES, tail_budget);
    let (head_rows, head_wrapped) = wrap_rows(&head, content_width, TOOL_HEAD_LINES);
    let (tail_rows, tail_wrapped) = wrap_rows(&tail, content_width, TOOL_TAIL_LINES);

    for line in head_rows {
        row(vec![Span::styled(line, body)]);
    }

    if omitted > 0 {
        row(vec![Span::styled(
            super::tree::truncate(&more_lines(omitted, verbosity), content_width),
            theme::quiet(),
        )]);
    }

    for line in tail_rows {
        row(vec![Span::styled(line, body)]);
    }

    if head_wrapped || tail_wrapped {
        row(vec![Span::styled(
            super::tree::truncate(
                &format!("… {}", verbosity.provenance("result")),
                content_width,
            ),
            theme::quiet(),
        )]);
    }
}

/// Wraps source lines into at most `cap` rows, reporting whether the cap cut anything.
fn wrap_rows(sources: &[&str], width: usize, cap: usize) -> (Vec<String>, bool) {
    let mut rows: Vec<String> = Vec::with_capacity(cap.min(sources.len()));

    for source in sources {
        if rows.len() >= cap {
            return (rows, true);
        }

        let room = cap - rows.len();
        // The spare row is how `wrap_limited` reports that more followed, without wrapping
        // the remainder of a line that may be tens of kilobytes long.
        let wrapped = wrap_limited(source, width, room.saturating_add(1));
        let cut = wrapped.len() > room;
        rows.extend(wrapped.into_iter().take(room));

        if cut {
            return (rows, true);
        }
    }

    (rows, false)
}

/// The first `head` and last `tail` source lines, and how many sit between them.
///
/// Walks the text once and keeps at most `head + tail` borrowed slices, so a ten-thousand
/// line result costs one scan and twelve pointers rather than a `Vec` of ten thousand.
fn head_tail(text: &str, head: usize, tail: usize) -> (Vec<&str>, usize, Vec<&str>) {
    let mut leading: Vec<&str> = Vec::with_capacity(head);
    let mut trailing: VecDeque<&str> = VecDeque::with_capacity(tail + 1);
    let mut total = 0usize;

    for line in text.lines() {
        total += 1;
        if leading.len() < head {
            leading.push(line);
            continue;
        }
        if tail == 0 {
            continue;
        }
        trailing.push_back(line);
        if trailing.len() > tail {
            trailing.pop_front();
        }
    }

    let omitted = total.saturating_sub(leading.len() + trailing.len());
    (leading, omitted, trailing.into_iter().collect())
}

/// Codex's grouped exploration cell.
fn render_exploration(
    lines: &mut Vec<Line<'static>>,
    group: &ExplorationCell,
    width: usize,
    tick: u64,
    verbosity: Verbosity,
) {
    separate(lines);

    // A spinner is a claim that something is happening. An open group whose calls have all
    // returned — the transcript simply has not drawn anything after it yet — gets Codex's
    // bullet instead, because the alternative is a client animating work that finished.
    let running = group
        .calls
        .iter()
        .any(|call| call.state == ToolState::Running);
    let (mark, mark_style) = if running {
        (
            theme::spinner(tick).to_string(),
            Style::default().fg(theme::accent()),
        )
    } else {
        ("•".to_string(), theme::quiet())
    };
    let failed = group.failed();
    let mut head = vec![
        Span::styled(format!("{mark} "), mark_style),
        Span::styled(
            super::tree::truncate(&exploration_heading(group), width.saturating_sub(4).max(8)),
            if failed > 0 {
                Style::default().fg(theme::warn())
            } else {
                theme::quiet()
            },
        ),
    ];

    if !verbosity.verbose() {
        // Named because it is the key that works. There is no per-cell focus in this
        // transcript, so advertising `enter` here would advertise a key the composer owns.
        head.push(Span::styled("  ctrl+o expands", theme::quiet()));
    }
    lines.push(Line::from(head));

    if !verbosity.verbose() {
        return;
    }

    for call in &group.calls {
        let mark = match call.state {
            ToolState::Running => theme::spinner(tick).to_string(),
            ToolState::Completed => "✓".to_string(),
            ToolState::Failed => "✗".to_string(),
        };
        let summary = summarise(call);
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(
                format!("{mark} "),
                match call.state {
                    ToolState::Failed => Style::default().fg(theme::bad()),
                    ToolState::Completed => Style::default().fg(theme::good()),
                    ToolState::Running => Style::default().fg(theme::accent()),
                },
            ),
            Span::styled(
                super::tree::truncate(&summary.line(), width.saturating_sub(8).max(8)),
                theme::quiet(),
            ),
        ]));
    }

    if group.overflow > 0 {
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(
                format!("… +{} more calls · /details", group.overflow),
                theme::quiet(),
            ),
        ]));
    }
}

/// `Exploring… (7)` while it is still growing, `Explored 7 files` once it is not.
fn exploration_heading(group: &ExplorationCell) -> String {
    let total = group.total();
    let failed = group.failed();
    let failures = if failed > 0 {
        format!(" · {failed} failed")
    } else {
        String::new()
    };

    if group.done {
        format!(
            "Explored {total} file{}{failures}",
            if total == 1 { "" } else { "s" }
        )
    } else {
        format!("Exploring… ({total}){failures}")
    }
}

fn boxed_tool_row(mut content: Vec<Span<'static>>, width: usize, border: Style) -> Line<'static> {
    let used = content
        .iter()
        .map(|span| span.content.as_ref().width())
        .sum::<usize>();
    let mut spans = vec![Span::styled("│ ", border)];
    spans.append(&mut content);
    spans.push(Span::raw(
        " ".repeat(width.saturating_sub(used.saturating_add(4))),
    ));
    spans.push(Span::styled(" │", border));
    Line::from(spans)
}

/// Streaming command output as a **live tail window** (Kiro; Cursor's "you see the latest
/// output of a streaming command, not the oldest").
///
/// A command that is still running is watched at its end: the newest rows are where the
/// build error, the test failure, or the prompt it is stuck on will be. The rows above are
/// counted, not silently dropped, so the window never implies the command said less than it
/// did.
fn render_command_output(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: usize,
    verbosity: Verbosity,
) {
    if text.trim().is_empty() {
        return;
    }

    if verbosity.verbose() {
        render_excerpt(
            lines,
            text,
            width,
            VERBOSE_LINES,
            &verbosity.provenance("command output"),
            theme::quiet(),
        );
        return;
    }

    let (body, omitted) = tail_lines(text, COMMAND_OUTPUT_LINES);

    if omitted > 0 {
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(
                super::tree::truncate(
                    &more_lines(omitted, verbosity),
                    width.saturating_sub(6).max(8),
                ),
                theme::quiet(),
            ),
        ]));
    }

    render_excerpt(
        lines,
        body,
        width,
        COMMAND_OUTPUT_LINES,
        &verbosity.provenance("command output"),
        theme::quiet(),
    );
}

fn render_file(lines: &mut Vec<Line<'static>>, file: &FileCell, width: usize) {
    let (mark, colour) = file_mark(file.kind.as_deref());
    let path = file.path.as_deref().unwrap_or("files changed");
    let path = super::tree::truncate(path, width.saturating_sub(12).max(8));

    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("{mark} "),
            Style::default().fg(colour).add_modifier(Modifier::DIM),
        ),
        Span::styled("File  ", theme::quiet()),
        Span::styled(
            path,
            Style::default().fg(colour).add_modifier(Modifier::DIM),
        ),
    ]));
}

/// A11. One image, as the row that is drawn wherever a picture cannot be.
///
/// A single line, on the same two-space gutter every other cell uses, and truncated to the
/// pane like every other path. Never more than one row: an image nobody can see should cost
/// a transcript one line, not a box.
fn render_image(lines: &mut Vec<Line<'static>>, image: &ImageCell, width: usize) {
    let label = super::tree::truncate(&image.label(), width.saturating_sub(4).max(8));

    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            "▣ ",
            Style::default()
                .fg(theme::accent())
                .add_modifier(Modifier::DIM),
        ),
        Span::styled(label, theme::quiet()),
    ]));
}

/// One file's header row inside a diff cell: `M lib/app.ex  +12 −3`, plus the two states
/// that change how the number should be read — an excerpt, and a pending approval.
fn diff_heading(file: &super::diff::DiffFile, cell: &DiffCell) -> String {
    let excerpt = if cell.parsed.truncated || cell.diff.truncated {
        " · in excerpt"
    } else {
        ""
    };
    let pending = if cell.pending_approval {
        " · pending approval"
    } else {
        ""
    };
    // The old path is shown only for an actual rename. `--- a/x` / `+++ b/x` records the
    // same path twice for every ordinary edit, and drawing `x ← x` would invent a move.
    let rename = file
        .old_path
        .as_deref()
        .filter(|old| file.status == super::diff::FileStatus::Renamed && *old != file.path)
        .map(|old| format!(" ← {old}"))
        .unwrap_or_default();

    format!(
        "{} {}{rename}  +{} −{}{excerpt}{pending}",
        file.status.mark(),
        file.path,
        file.additions,
        file.deletions
    )
}

/// Warp's rule, and the honesty invariant, in one renderer.
///
/// The counts on the header are the parse's, not the provider's. A diff whose approval is
/// still outstanding is drawn expanded — that is the moment the reader is being asked to
/// judge it — and collapses to its header once the approval resolves.
fn render_diff(
    lines: &mut Vec<Line<'static>>,
    cell: &DiffCell,
    width: usize,
    verbosity: Verbosity,
) {
    if cell.parsed.is_empty() {
        // Nothing parsed: the provider sent something this client cannot read as a unified
        // diff. It is still shown, verbatim and marked, rather than dropped.
        render_unparsed_diff(lines, cell, width, verbosity);
        return;
    }

    // Expanded while an approval is pending, and under `Ctrl+O`; twelve rows otherwise.
    let budget = if cell.pending_approval {
        VERBOSE_LINES
    } else {
        verbosity.lines(DIFF_LINES)
    };
    let mut spent = 0usize;

    for file in &cell.parsed.files {
        let heading =
            super::tree::truncate(&diff_heading(file, cell), width.saturating_sub(4).max(8));
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                heading,
                Style::default()
                    .fg(if cell.pending_approval {
                        theme::warn()
                    } else {
                        file.status.colour()
                    })
                    .add_modifier(Modifier::DIM),
            ),
        ]));

        let remaining = budget.saturating_sub(spent);
        let before = lines.len();
        let undrawn = super::diff::render_file(
            lines,
            file,
            super::diff::Layout::new(width, remaining).indented(2),
        );
        spent += lines.len() - before;

        if undrawn > 0 {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    super::tree::truncate(
                        &more_lines(undrawn, verbosity),
                        width.saturating_sub(4).max(8),
                    ),
                    theme::quiet(),
                ),
            ]));
        }
    }
}

fn render_unparsed_diff(
    lines: &mut Vec<Line<'static>>,
    cell: &DiffCell,
    width: usize,
    verbosity: Verbosity,
) {
    let path = cell.diff.path.as_deref().unwrap_or("changes");
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            super::tree::truncate(
                &format!("Diff  {path}  (no hunks this client could read)"),
                width.saturating_sub(4).max(8),
            ),
            theme::quiet(),
        ),
    ]));

    render_excerpt(
        lines,
        &cell.diff.text,
        width,
        verbosity.lines(DIFF_LINES),
        &verbosity.provenance("diff"),
        theme::quiet(),
    );
}

/// The post-turn diffstat: what the turn changed, counted from the diffs it produced.
fn render_diffstat(
    lines: &mut Vec<Line<'static>>,
    files: usize,
    additions: usize,
    deletions: usize,
    in_excerpt: bool,
) {
    separate(lines);
    lines.push(Line::from(vec![
        Span::styled("  ± ", theme::quiet()),
        Span::styled(
            super::diff::diffstat(files, additions, deletions, in_excerpt),
            Style::default().fg(theme::system()),
        ),
    ]));
}

/// B7. The durable record of a command the operator ran.
///
/// The runtime never writes the command *text* — only its digest — so this cell names the
/// digest and says so. A cell that guessed at the command line from a digest would be
/// inventing the one thing the ledger deliberately does not keep.
pub fn shell_block(shell: &crate::model::native::ShellEvent) -> Block {
    let label = match &shell.command_digest {
        Some(digest) => format!("$ command {}", digest.chars().take(12).collect::<String>()),
        None => "$ command".to_string(),
    };

    let mut facts = Vec::new();

    if let Some(error) = &shell.error {
        facts.push(format!("could not be started: {error}"));
    } else {
        match shell.exit_status {
            Some(0) => facts.push("exit 0".to_string()),
            Some(status) => facts.push(format!("exit {status}")),
            None => facts.push("no exit status".to_string()),
        }
    }

    if shell.timed_out {
        facts.push("timed out".to_string());
    }

    if let Some(ms) = shell.duration_ms {
        facts.push(elapsed_label(ms));
    }

    if let Some(bytes) = shell.output_bytes {
        facts.push(format!("{bytes} bytes"));
    }

    if let Some(path) = &shell.spilled {
        facts.push(format!("full output at {path}"));
    }

    let failed = shell.error.is_some() || shell.timed_out || shell.exit_status != Some(0);

    Block::new(
        label,
        facts.join(" · "),
        if failed { Tone::Warning } else { Tone::Muted },
    )
    .with_body(
        shell
            .output_excerpt
            .as_deref()
            .map(body_rows)
            .unwrap_or_default(),
    )
    .with_key(shell.command_digest.clone())
}

/// D9. One fold of the conversation.
pub fn compaction_block(report: &crate::model::native::Compaction) -> Block {
    let label = match report.trigger.as_deref() {
        Some("manual") => "Compacted, at your request",
        Some("automatic") => "Compacted automatically",
        _unnamed => "Compacted",
    };

    Block::new(label, report.describe(), Tone::Muted).with_key(report.archive_id.clone())
}

/// G1. A coding task this conversation delegated, starting or finishing.
pub fn delegation_block(delegation: &crate::model::native::DelegationEvent) -> Block {
    let started = delegation.status.as_deref() == Some("started");

    let label = match (&delegation.status, started) {
        (_, true) => "Delegated to a coding task".to_string(),
        (Some(status), false) => format!("Delegation {status}"),
        (None, false) => "Delegation".to_string(),
    };

    let mut facts = Vec::new();

    if let Some(task) = &delegation.task_id {
        facts.push(format!("task {task}"));
    }

    if let Some(node) = &delegation.task_node {
        facts.push(node.clone());
    }

    // A digest, never the result: the child's own transcript is the record of what it
    // did, and a parent that quoted it would be presenting a copy as the thing.
    if let Some(digest) = &delegation.result_digest {
        facts.push(format!("result digest {digest}"));
    }

    let tone = match delegation.status.as_deref() {
        Some("failed" | "cancelled" | "lost") => Tone::Warning,
        Some("completed") => Tone::Success,
        _running => Tone::Muted,
    };

    Block::new(label, facts.join(" · "), tone)
}

/// `Nms`, `Ns`, or `Nm Ns` — the same three shapes a tool row's elapsed time takes.
fn elapsed_label(milliseconds: u64) -> String {
    if milliseconds < 1_000 {
        format!("{milliseconds}ms")
    } else if milliseconds < 60_000 {
        format!("{}s", milliseconds / 1_000)
    } else {
        format!(
            "{}m {}s",
            milliseconds / 60_000,
            (milliseconds / 1_000) % 60
        )
    }
}

/// Splits a block of output into rows, bounded so one command cannot own the screen.
pub fn body_rows(text: &str) -> Vec<String> {
    text.lines()
        .map(str::to_string)
        .take(BLOCK_HEAD + BLOCK_TAIL + 1)
        .collect()
}

fn render_runtime_block(
    lines: &mut Vec<Line<'static>>,
    block: &Block,
    width: usize,
    verbosity: Verbosity,
) {
    separate(lines);
    lines.push(Line::from(Span::styled(
        block.label.clone(),
        Style::default()
            .fg(colour(block.tone))
            .add_modifier(Modifier::BOLD),
    )));

    if !block.detail.trim().is_empty() {
        for row in wrap_limited(&block.detail, width.max(8).saturating_sub(2), 4) {
            lines.push(Line::from(Span::styled(format!("  {row}"), theme::muted())));
        }
    }

    if block.body.is_empty() {
        return;
    }

    // Head and tail, like a tool result: the last rows of a command's output are where the
    // failure is, and a head-only excerpt is why a collapsed row used to be worth nothing.
    let budget = if verbosity.raw() {
        block.body.len()
    } else {
        BLOCK_HEAD + BLOCK_TAIL
    };

    if block.body.len() <= budget {
        for row in &block.body {
            lines.push(Line::from(Span::styled(format!("  {row}"), theme::quiet())));
        }
        return;
    }

    for row in block.body.iter().take(BLOCK_HEAD) {
        lines.push(Line::from(Span::styled(format!("  {row}"), theme::quiet())));
    }

    let omitted = block.body.len() - BLOCK_HEAD - BLOCK_TAIL;
    lines.push(Line::from(Span::styled(
        format!("  {}", more_lines(omitted, verbosity)),
        theme::muted(),
    )));

    for row in block.body.iter().skip(block.body.len() - BLOCK_TAIL) {
        lines.push(Line::from(Span::styled(format!("  {row}"), theme::quiet())));
    }
}

fn render_chat_note(lines: &mut Vec<Line<'static>>, text: &str, width: usize) {
    separate(lines);

    for line in wrap_limited(text, width.max(8), MESSAGE_LINES) {
        lines.push(Line::from(Span::styled(line, theme::quiet())).alignment(Alignment::Center));
    }
}

fn render_status(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    detail: &str,
    colour: Color,
    width: usize,
    verbosity: Verbosity,
) {
    separate(lines);
    lines.push(Line::from(Span::styled(
        label.to_string(),
        Style::default().fg(colour).add_modifier(Modifier::BOLD),
    )));
    let detail = if detail.trim().is_empty() {
        "No additional detail was provided."
    } else {
        detail
    };
    render_indented_text(
        lines,
        detail,
        width,
        verbosity.lines(STATUS_DETAIL_LINES),
        &verbosity.provenance("status"),
    );
}

fn render_indented_text(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: usize,
    limit: usize,
    omitted: &str,
) {
    let wrapped = wrap_limited(
        text,
        width.saturating_sub(2).max(8),
        limit.saturating_add(1),
    );
    let shown = wrapped.len().min(limit);

    for line in wrapped.iter().take(shown) {
        lines.push(Line::from(vec![Span::raw("  "), Span::raw(line.clone())]));
    }

    if wrapped.len() > shown {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("… {omitted}"), Style::default().fg(theme::muted())),
        ]));
    }
}

fn render_excerpt(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: usize,
    limit: usize,
    omitted: &str,
    style: Style,
) {
    // The extra row establishes that something was omitted. Wrapping can then stop without
    // tokenizing or allocating the remainder of a long command/tool value.
    let wrapped = wrap_limited(
        text,
        width.saturating_sub(6).max(8),
        limit.saturating_add(1),
    );
    let shown = wrapped.len().min(limit);

    for line in wrapped.iter().take(shown) {
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(line.clone(), style),
        ]));
    }

    if wrapped.len() > shown {
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(format!("… {omitted}"), theme::quiet()),
        ]));
    }
}

fn tool_input(name: &str, input: &Value) -> String {
    let preferred: &[&str] = if command_tool(name) {
        &["cmd", "command"]
    } else {
        &["path", "file", "query", "pattern", "url"]
    };

    for key in preferred {
        // `leaf_text` also reads the gateway's wire markers, so an excerpted command reads
        // as its own prefix rather than as `{"_excerpt": …}`.
        if let Some(text) = input.get(*key).and_then(leaf_text) {
            if !text.trim().is_empty() {
                return bounded_copy(text.trim(), TOOL_INPUT_BYTES, TOOL_INPUT_TRUNCATION);
            }
        }
    }

    match input {
        Value::Null => String::new(),
        Value::Object(fields) if fields.is_empty() => String::new(),
        other => bounded_compact(other, TOOL_INPUT_BYTES, TOOL_INPUT_TRUNCATION),
    }
}

fn value_text(value: &Value) -> String {
    let mut rendered = String::new();
    append_value_text(value, &mut rendered);
    rendered
}

fn append_value_text(value: &Value, rendered: &mut String) -> bool {
    if rendered.ends_with(TOOL_VALUE_TRUNCATION) {
        return true;
    }

    match value {
        Value::String(text) => append_value_piece(rendered, text),
        // A leaf the gateway replaced with a marker: render the label, never the JSON.
        Value::Object(_) if crate::model::transcript::wire_marker(value).is_some() => {
            let marker = crate::model::transcript::wire_marker(value).unwrap_or_default();
            append_value_piece(rendered, &marker)
        }
        Value::Array(items) => {
            let mut wrote = false;
            for item in items {
                wrote |= append_value_text(item, rendered);
                if rendered.ends_with(TOOL_VALUE_TRUNCATION) {
                    break;
                }
            }
            wrote
        }
        Value::Object(fields) => {
            if let Some(preferred) = fields.get("text").or_else(|| fields.get("content")) {
                if append_value_text(preferred, rendered) {
                    return true;
                }
            }

            append_value_piece(
                rendered,
                &bounded_compact(value, TOOL_VALUE_BYTES, TOOL_VALUE_TRUNCATION),
            )
        }
        Value::Null => false,
        other => append_value_piece(
            rendered,
            &bounded_compact(other, TOOL_VALUE_BYTES, TOOL_VALUE_TRUNCATION),
        ),
    }
}

fn append_value_piece(rendered: &mut String, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    if !rendered.is_empty() {
        append_bounded(rendered, "\n", TOOL_VALUE_BYTES, TOOL_VALUE_TRUNCATION);
    }
    append_bounded(rendered, value, TOOL_VALUE_BYTES, TOOL_VALUE_TRUNCATION);
    true
}

fn command_tool(name: &str) -> bool {
    shape_of(name, None) == ToolShape::Bash
}

// ---------------------------------------------------------------------------------------
// Per-tool summarisers
// ---------------------------------------------------------------------------------------

/// What a tool call *is*, independent of what any one vendor called it.
///
/// Three naming systems reach this client and none of them agrees with the others: Claude's
/// tool names (`Read`, `Grep`, `Bash`, `mcp__server__tool`), ACP's `kind` enum
/// (`read | edit | delete | move | search | execute | think | fetch | other`), and Codex's
/// item types, which the runtime already normalises to `exec_command` and the MCP tool's own
/// name. Keying the summary on the shape rather than on any one of them is what lets a row
/// read `Bash $ cargo test` whichever dialect produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolShape {
    Read,
    Edit,
    Write,
    Delete,
    Move,
    Grep,
    Glob,
    List,
    Bash,
    Fetch,
    WebSearch,
    Mcp,
    Think,
    Other,
}

impl ToolShape {
    /// Whether this call is filesystem exploration, and so belongs in a grouped cell.
    ///
    /// Reading, searching, listing and globbing only. An edit, a command, or a fetch is
    /// something the agent *did*, and folding those into a count would hide the actions a
    /// reader is watching for.
    fn explores(self) -> bool {
        matches!(self, Self::Read | Self::Grep | Self::Glob | Self::List)
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Edit => "Edit",
            Self::Write => "Write",
            Self::Delete => "Delete",
            Self::Move => "Move",
            Self::Grep => "Grep",
            Self::Glob => "Glob",
            Self::List => "List",
            Self::Bash => "Bash",
            Self::Fetch => "Fetch",
            Self::WebSearch => "Search",
            Self::Mcp => "MCP",
            Self::Think => "Think",
            Self::Other => "",
        }
    }
}

/// One tool call in the field's vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSummary {
    shape: ToolShape,
    /// `Read`, `Bash`, `MCP`, … or the provider's own name where nothing matched.
    pub verb: String,
    /// Its subject on one line: a path, `$ cargo test`, `"needle" in lib`.
    pub subject: String,
    /// What the *result* proved, and nothing the result did not: `→ 3 matches`, `exit 1`.
    pub outcome: String,
}

impl ToolSummary {
    /// The whole row as one string, for the exploration list and the plain-text export.
    pub fn line(&self) -> String {
        [
            self.verb.as_str(),
            self.subject.as_str(),
            self.outcome.as_str(),
        ]
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ")
    }
}

fn shape_of(name: &str, kind: Option<&str>) -> ToolShape {
    let lower = name.trim().to_ascii_lowercase();

    // MCP first: `mcp__linear__create_issue` would otherwise match `create`.
    if lower.starts_with("mcp__") || lower.starts_with("mcp.") {
        return ToolShape::Mcp;
    }

    let normalised = lower.replace([' ', '-'], "_");
    let matched = match normalised.as_str() {
        "read" | "read_file" | "readfile" | "view" | "view_file" | "open" | "cat"
        | "notebookread" | "notebook_read" | "read_many_files" => Some(ToolShape::Read),
        "edit"
        | "edit_file"
        | "editfile"
        | "str_replace"
        | "str_replace_editor"
        | "str_replace_based_edit_tool"
        | "apply_patch"
        | "applypatch"
        | "patch"
        | "multiedit"
        | "multi_edit"
        | "update_file"
        | "notebookedit"
        | "notebook_edit"
        | "file_change" => Some(ToolShape::Edit),
        "write" | "write_file" | "writefile" | "create" | "create_file" | "new_file" => {
            Some(ToolShape::Write)
        }
        "delete" | "delete_file" | "remove" | "remove_file" | "rm" => Some(ToolShape::Delete),
        "move" | "move_file" | "rename" | "rename_file" | "mv" => Some(ToolShape::Move),
        "grep"
        | "search"
        | "rg"
        | "ripgrep"
        | "grep_search"
        | "search_files"
        | "codebase_search"
        | "search_file_content" => Some(ToolShape::Grep),
        "glob" | "find" | "find_files" | "file_search" | "glob_file_search" => {
            Some(ToolShape::Glob)
        }
        "ls" | "list" | "list_dir" | "list_files" | "list_directory" | "readdir" => {
            Some(ToolShape::List)
        }
        "bash" | "shell" | "exec" | "exec_command" | "run_command" | "runcommand" | "command"
        | "commandexecution" | "command_execution" | "terminal" | "run_terminal_cmd"
        | "bashoutput" => Some(ToolShape::Bash),
        "fetch" | "web_fetch" | "webfetch" | "url_fetch" | "http" | "curl" => {
            Some(ToolShape::Fetch)
        }
        "web_search" | "websearch" | "search_web" | "google_web_search" => {
            Some(ToolShape::WebSearch)
        }
        "think" | "thinking" | "sequentialthinking" => Some(ToolShape::Think),
        _ => None,
    };

    if let Some(shape) = matched {
        return shape;
    }

    // Codex's `mcpToolCall` reaches the client under the MCP tool's *own* name, which is
    // routinely `server.tool`. A dotted name that matched no verb above is that.
    if lower.contains('.') && !lower.contains(' ') && !lower.starts_with('.') {
        return ToolShape::Mcp;
    }

    // ACP's `kind` is the fallback, not the first answer: an agent that sends both a prose
    // `title` and a `kind` is more specific in the title, and only the kind is an enum.
    match kind.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("read") => ToolShape::Read,
        Some("edit") => ToolShape::Edit,
        Some("delete") => ToolShape::Delete,
        Some("move") => ToolShape::Move,
        Some("search") => ToolShape::Grep,
        Some("execute") => ToolShape::Bash,
        Some("think") => ToolShape::Think,
        Some("fetch") => ToolShape::Fetch,
        _ => ToolShape::Other,
    }
}

/// The per-tool summariser. Every claim it makes is read off the call's own input or its
/// result; nothing is inferred from the tool's name alone.
pub fn summarise(tool: &ToolCell) -> ToolSummary {
    let shape = shape_of(&tool.name, tool.kind.as_deref());
    let input = &tool.input;
    let output = tool.output.as_ref().map(value_text);
    let output = output.as_deref();

    let (subject, outcome) = match shape {
        ToolShape::Read => (read_subject(input), counted(output, "line")),
        ToolShape::Edit => (join(path_of(input), edit_stat(input)), String::new()),
        ToolShape::Write => (path_of(input).unwrap_or_default(), String::new()),
        ToolShape::Delete | ToolShape::Move => (path_of(input).unwrap_or_default(), String::new()),
        ToolShape::Grep => (grep_subject(input), counted(output, "match")),
        ToolShape::Glob => (
            field(input, &["pattern", "glob", "query", "filePattern", "path"]).unwrap_or_default(),
            counted(output, "file"),
        ),
        ToolShape::List => (path_of(input).unwrap_or_default(), counted(output, "entry")),
        ToolShape::Bash => (
            field(input, &["cmd", "command", "script", "shell_command"])
                .map(|command| format!("$ {command}"))
                .unwrap_or_default(),
            exit_status(tool, input),
        ),
        ToolShape::Fetch => (
            field(input, &["url", "uri", "href", "link"]).unwrap_or_default(),
            String::new(),
        ),
        ToolShape::WebSearch => (
            field(input, &["query", "q", "search", "prompt"])
                .map(|query| format!("\"{query}\""))
                .unwrap_or_default(),
            String::new(),
        ),
        ToolShape::Mcp => (mcp_subject(&tool.name), String::new()),
        ToolShape::Think => (String::new(), String::new()),
        ToolShape::Other => (tool_input(&tool.name, input), String::new()),
    };

    let verb = match shape {
        ToolShape::Other => display_tool_name(&tool.name),
        shape => shape.verb().to_string(),
    };

    ToolSummary {
        shape,
        verb,
        subject: subject.replace('\n', " ").trim().to_string(),
        outcome,
    }
}

/// `Read path:12-140`, from whatever the provider called its window.
fn read_subject(input: &Value) -> String {
    let Some(path) = path_of(input) else {
        return String::new();
    };

    let number = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| input.get(*key))
            .and_then(|value| match value {
                Value::Number(number) => number.as_u64(),
                Value::String(text) => text.parse().ok(),
                _ => None,
            })
    };

    let offset = number(&["offset", "start_line", "startLine", "line", "from"]);
    let limit = number(&["limit", "count", "num_lines", "length"]);
    let end = number(&["end_line", "endLine", "to"]);

    match (offset, limit, end) {
        (Some(start), _, Some(end)) => format!("{path}:{start}-{end}"),
        (Some(start), Some(limit), None) if limit > 0 => {
            format!("{path}:{start}-{}", start + limit - 1)
        }
        (Some(start), _, None) => format!("{path}:{start}"),
        (None, Some(limit), None) => format!("{path}:1-{limit}"),
        _ => path,
    }
}

/// `(+3 −1)` for an anchored replacement, counted from the two strings the call carries.
///
/// Only ever from strings this client can see. An edit tool that describes its change
/// without carrying it gets no counts rather than a guess, and the authoritative numbers
/// arrive separately as the `file_change` event's diff.
fn edit_stat(input: &Value) -> Option<String> {
    let old = input
        .get("old_string")
        .or_else(|| input.get("oldText"))
        .or_else(|| input.get("old_str"))
        .and_then(leaf_text);
    let new = input
        .get("new_string")
        .or_else(|| input.get("newText"))
        .or_else(|| input.get("new_str"))
        .and_then(leaf_text);

    let (old, new) = (old?, new?);
    let count = |text: &str| {
        if text.is_empty() {
            0
        } else {
            text.lines().count()
        }
    };

    Some(format!("(+{} −{})", count(&new), count(&old)))
}

/// `"needle" in lib/`, in the shape Codex and Claude Code both print.
fn grep_subject(input: &Value) -> String {
    let pattern = field(input, &["pattern", "query", "regex", "search", "q"]);
    let scope = field(
        input,
        &["path", "dir", "directory", "include", "glob", "in"],
    );

    match (pattern, scope) {
        (Some(pattern), Some(scope)) => format!("\"{pattern}\" in {scope}"),
        (Some(pattern), None) => format!("\"{pattern}\""),
        (None, Some(scope)) => scope,
        (None, None) => String::new(),
    }
}

/// `MCP linear.create_issue` — the server and the tool, separated the way both dialects
/// write them.
fn mcp_subject(name: &str) -> String {
    let trimmed = name.trim();

    if let Some(rest) = trimmed
        .strip_prefix("mcp__")
        .or_else(|| trimmed.strip_prefix("mcp."))
    {
        return rest.replacen("__", ".", 1);
    }

    trimmed.to_string()
}

/// Gemini's `→ Returned N lines`, said only where the result is actually held.
///
/// The count is of the text this client has. A result the projection had to bound says so
/// rather than reporting the bounded count as the whole.
fn counted(output: Option<&str>, noun: &str) -> String {
    // English, spelled out rather than derived: "matchs" is what `noun + "s"` produces, and
    // a summary row that misspells its own unit reads as a machine talking to itself.
    let plural = match noun {
        "match" => "matches",
        "entry" => "entries",
        other => return counted_with(output, other, &format!("{other}s")),
    };

    counted_with(output, noun, plural)
}

fn counted_with(output: Option<&str>, singular: &str, plural: &str) -> String {
    let Some(output) = output else {
        return String::new();
    };
    let trimmed = output.trim_end_matches('\n');
    if trimmed.is_empty() {
        return format!("→ no {plural}");
    }

    let bounded = trimmed.ends_with(TOOL_VALUE_TRUNCATION.trim_start_matches('\n'));
    let lines = trimmed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let lines = if bounded {
        lines.saturating_sub(1)
    } else {
        lines
    };

    format!(
        "→ {lines}{} {}",
        if bounded { "+" } else { "" },
        if lines == 1 && !bounded {
            singular
        } else {
            plural
        }
    )
}

/// `exit 1` where a payload carried one, `failed` where only `is_error` did.
///
/// The runtime's Codex dialect folds `exitCode` into `is_error` and does not forward the
/// number, so `failed` is the ordinary answer there and a numeric code appears only for a
/// provider that sends one.
fn exit_status(tool: &ToolCell, input: &Value) -> String {
    let code = ["exit_code", "exitCode", "status_code", "returncode"]
        .iter()
        .find_map(|key| {
            tool.output
                .as_ref()
                .and_then(|output| output.get(*key))
                .or_else(|| input.get(*key))
        })
        .and_then(|value| match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        });

    match (code, tool.state) {
        (Some(code), _) => format!("exit {code}"),
        (None, ToolState::Failed) => "failed".to_string(),
        _ => String::new(),
    }
}

fn path_of(input: &Value) -> Option<String> {
    field(
        input,
        &[
            "path",
            "file_path",
            "filePath",
            "file",
            "filename",
            "absolute_path",
            "abs_path",
            "uri",
            "target",
            "notebook_path",
        ],
    )
}

/// The first of these keys that holds text, already bounded and flattened.
fn field(input: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = input.get(*key).and_then(leaf_text) {
            let text = text.trim();
            if !text.is_empty() {
                return Some(bounded_copy(
                    &text.replace('\n', " "),
                    TOOL_INPUT_BYTES,
                    TOOL_INPUT_TRUNCATION,
                ));
            }
        }
    }

    None
}

fn join(head: Option<String>, tail: Option<String>) -> String {
    match (head, tail) {
        (Some(head), Some(tail)) => format!("{head} {tail}"),
        (Some(only), None) | (None, Some(only)) => only,
        (None, None) => String::new(),
    }
}

fn display_tool_name(name: &str) -> String {
    match name {
        "exec_command" | "run_command" | "bash" | "shell" => "command".into(),
        other => other.replace('_', " "),
    }
}

fn file_mark(kind: Option<&str>) -> (&'static str, Color) {
    let kind = kind.unwrap_or("modified").to_ascii_lowercase();

    if kind.contains("add") || kind.contains("creat") {
        ("A", theme::good())
    } else if kind.contains("delet") || kind.contains("remov") {
        ("D", theme::bad())
    } else if kind.contains("renam") || kind.contains("mov") {
        ("R", theme::accent())
    } else {
        ("M", theme::warn())
    }
}

fn colour(tone: Tone) -> Color {
    match tone {
        Tone::Muted => theme::muted(),
        Tone::Success => theme::good(),
        Tone::Warning => theme::warn(),
        Tone::Error => theme::bad(),
    }
}

fn separate(lines: &mut Vec<Line<'static>>) {
    if !lines.is_empty()
        && !lines
            .last()
            .map(Line::width)
            .is_some_and(|width| width == 0)
    {
        lines.push(Line::from(""));
    }
}

fn divider(text: &str, width: usize, colour: Color) -> Line<'static> {
    let text = super::tree::truncate(text, width.saturating_sub(8));
    let rule = width.saturating_sub(text.width() + 6);

    Line::from(vec![
        Span::styled("──── ".to_string(), Style::default().fg(colour)),
        Span::styled(text, Style::default().fg(colour)),
        Span::styled(
            format!(" {}", "─".repeat(rule)),
            Style::default().fg(colour),
        ),
    ])
}

fn bound_owned(mut text: String, limit: usize, marker: &str) -> String {
    if text.len() <= limit {
        return text;
    }

    let marker = fitting_marker(marker, limit);
    let keep = char_boundary_at_or_before(&text, limit.saturating_sub(marker.len()));
    text.truncate(keep);
    text.push_str(marker);
    text
}

fn bounded_copy(text: &str, limit: usize, marker: &str) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }

    let marker = fitting_marker(marker, limit);
    let keep = char_boundary_at_or_before(text, limit.saturating_sub(marker.len()));
    let mut bounded = String::with_capacity(keep + marker.len());
    bounded.push_str(&text[..keep]);
    bounded.push_str(marker);
    bounded
}

/// Appends only the prefix the transcript owns. Once the marker is present, later stream
/// deltas are deliberately ignored by this projection; their source Events remain complete.
fn append_bounded(target: &mut String, text: &str, limit: usize, marker: &str) -> bool {
    if target.ends_with(marker) {
        return true;
    }

    if target.len().saturating_add(text.len()) <= limit {
        target.push_str(text);
        return false;
    }

    let marker = fitting_marker(marker, limit);
    let content_limit = limit.saturating_sub(marker.len());
    if target.len() > content_limit {
        let keep = char_boundary_at_or_before(target, content_limit);
        target.truncate(keep);
    } else {
        let available = content_limit - target.len();
        let keep = char_boundary_at_or_before(text, available);
        target.push_str(&text[..keep]);
    }
    target.push_str(marker);
    true
}

fn fitting_marker(marker: &str, limit: usize) -> &str {
    if marker.len() <= limit {
        marker
    } else if "…".len() <= limit {
        "…"
    } else {
        ""
    }
}

fn char_boundary_at_or_before(text: &str, limit: usize) -> usize {
    let mut boundary = limit.min(text.len());
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn bounded_compact(value: &Value, limit: usize, marker: &str) -> String {
    match value {
        Value::String(text) => bounded_copy(text, limit, marker),
        Value::Object(fields) if fields.len() == 1 => {
            if let Some(Value::String(inspected)) = fields.get("_opaque") {
                return bounded_copy(inspected, limit, marker);
            }
            if fields.contains_key("_truncated") {
                return "<truncated>".into();
            }
            if let Some(Value::String(encoded)) = fields.get("_b64") {
                return format!("<{} base64 bytes>", encoded.len());
            }
            bounded_json(value, limit, marker)
        }
        other => bounded_json(other, limit, marker),
    }
}

fn bounded_json(value: &Value, limit: usize, marker: &str) -> String {
    let mut writer = LimitedWriter::new(limit);
    let serialized = serde_json::to_writer(&mut writer, value);

    if serialized.is_ok() && !writer.truncated {
        return String::from_utf8(writer.bytes).expect("serde_json always emits UTF-8");
    }

    let marker = fitting_marker(marker, limit);
    let keep_limit = limit.saturating_sub(marker.len());
    let keep = char_boundary_bytes_at_or_before(&writer.bytes, keep_limit);
    writer.bytes.truncate(keep);
    let mut rendered = String::from_utf8(writer.bytes).expect("trimmed to a UTF-8 boundary");
    rendered.push_str(marker);
    rendered
}

fn char_boundary_bytes_at_or_before(bytes: &[u8], limit: usize) -> usize {
    let mut boundary = limit.min(bytes.len());
    while boundary > 0 && std::str::from_utf8(&bytes[..boundary]).is_err() {
        boundary -= 1;
    }
    boundary
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(4 * 1024)),
            limit,
            truncated: false,
        }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if remaining == 0 {
            self.truncated = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "transcript JSON limit reached",
            ));
        }

        let written = remaining.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..written]);
        if written < bytes.len() {
            self.truncated = true;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wrapping is explicit so scroll offsets count the rows the renderer produces.
#[cfg(test)]
fn wrap(text: &str, width: usize) -> Vec<String> {
    wrap_limited(text, width, usize::MAX)
}

pub(super) fn wrap_limited(text: &str, width: usize, max_lines: usize) -> Vec<String> {
    if max_lines == 0 {
        return Vec::new();
    }

    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;
    let mut word = String::new();
    let mut word_width = 0;

    for character in text.chars() {
        match character {
            ' ' => {
                if !place_word(
                    &mut lines,
                    &mut current,
                    &mut current_width,
                    &mut word,
                    &mut word_width,
                    width,
                    max_lines,
                ) {
                    return lines;
                }
            }
            '\n' => {
                if !place_word(
                    &mut lines,
                    &mut current,
                    &mut current_width,
                    &mut word,
                    &mut word_width,
                    width,
                    max_lines,
                ) {
                    return lines;
                }
                if !push_wrapped_line(&mut lines, std::mem::take(&mut current), max_lines) {
                    return lines;
                }
                current_width = 0;
            }
            character => {
                let cells = character.width().unwrap_or(0);

                // Measured in terminal cells: a CJK ideograph and most emoji occupy two,
                // and a combining mark occupies none — so counting characters would build
                // lines twice the pane's width, which the renderer then clips in half.
                if word_width > 0 && word_width + cells > width {
                    if !current.is_empty() {
                        if !push_wrapped_line(&mut lines, std::mem::take(&mut current), max_lines) {
                            return lines;
                        }
                        current_width = 0;
                    }

                    // The word already fills the pane. Emitting it here rather than growing
                    // it is what keeps a multi-megabyte token costing `max_lines` of work
                    // rather than the length of the token.
                    if !push_wrapped_line(&mut lines, std::mem::take(&mut word), max_lines) {
                        return lines;
                    }
                    word_width = 0;
                }

                word.push(character);
                word_width += cells;

                // One character wider than the whole pane. There is nowhere narrower to put
                // it, so it gets a row of its own rather than pushing everything after it.
                if word_width > width {
                    if !current.is_empty() {
                        if !push_wrapped_line(&mut lines, std::mem::take(&mut current), max_lines) {
                            return lines;
                        }
                        current_width = 0;
                    }

                    if !push_wrapped_line(&mut lines, std::mem::take(&mut word), max_lines) {
                        return lines;
                    }
                    word_width = 0;
                }
            }
        }
    }

    if !place_word(
        &mut lines,
        &mut current,
        &mut current_width,
        &mut word,
        &mut word_width,
        width,
        max_lines,
    ) {
        return lines;
    }
    push_wrapped_line(&mut lines, current, max_lines);
    lines
}

#[allow(clippy::too_many_arguments)]
fn place_word(
    lines: &mut Vec<String>,
    current: &mut String,
    current_width: &mut usize,
    word: &mut String,
    word_width: &mut usize,
    width: usize,
    max_lines: usize,
) -> bool {
    if current.is_empty() {
        *current = std::mem::take(word);
        *current_width = std::mem::take(word_width);
        return true;
    }

    if current_width.saturating_add(1).saturating_add(*word_width) <= width {
        current.push(' ');
        current.push_str(word);
        *current_width += 1 + *word_width;
        word.clear();
        *word_width = 0;
        return true;
    }

    if !push_wrapped_line(lines, std::mem::take(current), max_lines) {
        return false;
    }
    *current = std::mem::take(word);
    *current_width = std::mem::take(word_width);
    true
}

fn push_wrapped_line(lines: &mut Vec<String>, line: String, max_lines: usize) -> bool {
    if lines.len() >= max_lines {
        return false;
    }

    lines.push(line);
    lines.len() < max_lines
}

#[cfg(test)]
mod tests {
    use ratatui::style::Modifier;
    use ratatui::text::Line;
    use serde_json::json;

    use crate::model::Event;

    use super::*;

    fn event(sequence: u64, kind: &str, payload: Value) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": "2026-08-14T00:00:00Z",
            "turn_id": "turn-1",
            "payload": payload
        }))
        .expect("an event")
    }

    fn plain(lines: &[Line<'_>]) -> String {
        lines.iter().map(plain_line).collect::<Vec<_>>().join("\n")
    }

    fn plain_line(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn correlates_a_tool_result_into_one_compact_cell() {
        let call = event(
            1,
            "tool_call",
            json!({"call_id": "c1", "name": "write", "input": {"path": "README.md"}}),
        );
        let result = event(
            2,
            "tool_result",
            json!({"call_id": "c1", "output": {"text": "project docs"}, "is_error": false}),
        );
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);

        assert_eq!(cells.len(), 1);
        let Cell::Tool(tool) = &cells[0] else {
            panic!("expected one tool cell")
        };
        assert_eq!(tool.state, ToolState::Completed);

        let text = plain(&render_cells(&cells, 80));
        assert!(text.contains("✓ Write"), "{text}");
        assert!(text.contains("README.md"), "{text}");
        assert!(text.contains("project docs"), "{text}");
        assert!(
            !text.contains("Tool  "),
            "tool chrome stays out of the reading path: {text}"
        );
        assert!(
            !text.contains("c1"),
            "correlation ids belong in details: {text}"
        );
    }

    #[test]
    fn repeated_tool_call_with_the_same_id_updates_one_running_row() {
        let started = event(
            1,
            "tool_call",
            json!({"call_id": "command-1", "name": "exec_command", "input": {"cmd": "mix test"}}),
        );
        let completed_call = event(
            2,
            "tool_call",
            json!({
                "call_id": "command-1",
                "name": "exec_command",
                "input": {"cmd": "mix test", "cwd": "/tmp/project"}
            }),
        );
        let result = event(
            3,
            "tool_result",
            json!({
                "call_id": "command-1",
                "name": "exec_command",
                "output": "12 tests, 0 failures",
                "is_error": false
            }),
        );

        let running = project(vec![Entry::Event(&started), Entry::Event(&completed_call)]);
        assert_eq!(running.len(), 1);
        let Cell::Tool(tool) = &running[0] else {
            panic!("expected one running command cell")
        };
        assert_eq!(tool.state, ToolState::Running);
        assert_eq!(
            tool.input,
            json!({"cmd": "mix test", "cwd": "/tmp/project"})
        );

        let completed = project(vec![
            Entry::Event(&started),
            Entry::Event(&completed_call),
            Entry::Event(&result),
        ]);
        assert_eq!(completed.len(), 1);
        let Cell::Tool(tool) = &completed[0] else {
            panic!("expected one completed command cell")
        };
        assert_eq!(tool.state, ToolState::Completed);
        assert_eq!(
            tool.output,
            Some(Value::String("12 tests, 0 failures".into()))
        );

        let text = plain(&render_cells(&completed, 100));
        assert_eq!(text.matches("mix test").count(), 1, "{text}");
        assert_eq!(text.matches("12 tests, 0 failures").count(), 1, "{text}");
    }

    #[test]
    fn renders_files_and_unified_diff_as_distinct_cells() {
        let update = event(
            1,
            "file_change",
            json!({
                "changes": [{"path": "lib/worker.ex", "kind": "modified"}],
                "diff": "diff --git a/lib/worker.ex b/lib/worker.ex\n--- a/lib/worker.ex\n+++ b/lib/worker.ex\n@@ -1 +1 @@\n-old\n+new"
            }),
        );
        let cells = project(vec![Entry::Event(&update)]);
        let text = plain(&render_cells(&cells, 100));

        assert!(text.contains("M File  lib/worker.ex"), "{text}");
        assert!(text.contains("M lib/worker.ex  +1 −1"), "{text}");
        assert!(
            !text.contains('←'),
            "an ordinary edit is not a rename: {text}"
        );
        assert!(text.contains("-old"), "{text}");
        assert!(text.contains("+new"), "{text}");
    }

    #[test]
    fn a_running_tool_uses_the_working_spinner() {
        let call = event(
            1,
            "tool_call",
            json!({"call_id": "c-run", "name": "bash", "input": {"cmd": "cargo build"}}),
        );
        let cells = project(vec![Entry::Event(&call)]);
        let text = plain(&render_cells_at(&cells, 80, 0, Verbosity::Compact));

        assert!(text.contains(&theme::spinner(0).to_string()), "{text}");
        assert!(text.contains("running"), "{text}");
        assert!(!text.contains('●'), "{text}");
    }

    #[test]
    fn a_streaming_agent_message_carries_a_caret() {
        let delta = event(1, "output_text_delta", json!({"text": "Hello"}));
        let cells = project(vec![Entry::Event(&delta)]);
        let Cell::Message {
            streaming: true, ..
        } = &cells[0]
        else {
            panic!("pending agent text is still streaming")
        };

        let text = plain(&render_cells_at(&cells, 80, 0, Verbosity::Compact));
        assert!(text.contains("Hello▌"), "{text}");

        let hidden = plain(&render_cells_at(&cells, 80, 6, Verbosity::Compact));
        assert!(hidden.contains("Hello "), "{hidden}");
        assert!(!hidden.contains("Hello▌"), "{hidden}");
    }

    #[test]
    fn a_failed_tool_result_stays_visibly_failed() {
        let call = event(
            1,
            "tool_call",
            json!({"call_id": "c2", "name": "write", "input": {"path": "locked.txt"}}),
        );
        let result = event(
            2,
            "tool_result",
            json!({"call_id": "c2", "output": "permission denied", "is_error": true}),
        );
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);

        let Cell::Tool(tool) = &cells[0] else {
            panic!("expected one tool cell")
        };
        assert_eq!(tool.state, ToolState::Failed);

        let text = plain(&render_cells(&cells, 80));
        assert!(text.contains("failed"), "{text}");
        assert!(text.contains("permission denied"), "{text}");
    }

    #[test]
    fn unrelated_streamed_command_output_never_hides_a_correlated_result() {
        let call = event(
            1,
            "tool_call",
            json!({"call_id": "first", "name": "exec_command", "input": {"cmd": "one"}}),
        );
        let streamed = event(2, "command_output_delta", json!({"text": "second output"}));
        let result = event(
            3,
            "tool_result",
            json!({"call_id": "first", "output": "first output", "is_error": false}),
        );
        let cells = project(vec![
            Entry::Event(&call),
            Entry::Event(&streamed),
            Entry::Event(&result),
        ]);
        let text = plain(&render_cells(&cells, 80));

        assert!(text.contains("first output"), "{text}");
        assert!(text.contains("second output"), "{text}");
    }

    #[test]
    fn collapses_streamed_agent_text_and_bounds_verbose_tool_output() {
        let delta = event(1, "output_text_delta", json!({"text": "Hello "}));
        let final_text = event(2, "output_text_final", json!({"text": "Hello there"}));
        let tool = Cell::Tool(ToolCell {
            call_id: Some("long".into()),
            name: "read".into(),
            input: json!({"path": "large.log"}),
            output: Some(Value::String(
                (0..20).map(|n| format!("line {n}\n")).collect(),
            )),
            state: ToolState::Completed,
            kind: None,
            started_at: None,
            settled_at: None,
        });

        let mut cells = project(vec![Entry::Event(&delta), Entry::Event(&final_text)]);
        cells.push(tool);
        let text = plain(&render_cells(&cells, 80));

        assert_eq!(text.matches("Hello there").count(), 1, "{text}");
        // Codex's head/tail: six rows, the counted marker, six rows. The last line of a
        // result is part of the head/tail layout, so what a compact cell hides is the
        // middle — and it says how much.
        assert!(text.contains("line 0"), "{text}");
        assert!(text.contains("… +8 lines · ctrl+o"), "{text}");
        assert!(text.contains("line 19"), "the tail is the point: {text}");
        assert!(
            !text.contains("line 9\n"),
            "the middle is what a compact cell folds: {text}"
        );

        // The same cells under Ctrl+O: expanded in place, still bounded, and the row that
        // said where the rest lives now points only at the ledger.
        let verbose = plain(&render_cells_at(&cells, 80, 0, Verbosity::Verbose));
        assert!(verbose.contains("line 19"), "{verbose}");
        assert!(!verbose.contains("ctrl+o"), "{verbose}");
    }

    #[test]
    fn caps_accumulated_agent_and_command_streams() {
        let chunk = "output".repeat(3 * 1024);
        let agent_events: Vec<_> = (0..12)
            .map(|sequence| event(sequence, "output_text_delta", json!({"text": chunk})))
            .collect();
        let agent_cells = project(agent_events.iter().map(Entry::Event).collect());
        let Cell::Message {
            speaker: Speaker::Agent,
            text: agent_text,
            streaming: _,
        } = &agent_cells[0]
        else {
            panic!("expected accumulated agent text")
        };

        assert!(agent_text.len() <= AGENT_OUTPUT_BYTES);
        assert!(agent_text.ends_with(AGENT_TRUNCATION));

        let command_events: Vec<_> = (0..8)
            .map(|sequence| event(sequence, "command_output_delta", json!({"text": chunk})))
            .collect();
        let command_cells = project(command_events.iter().map(Entry::Event).collect());
        let Cell::CommandOutput(command_text) = &command_cells[0] else {
            panic!("expected accumulated command output")
        };

        assert!(command_text.len() <= COMMAND_OUTPUT_BYTES);
        assert!(command_text.ends_with(COMMAND_TRUNCATION));
    }

    #[test]
    fn wraps_only_the_requested_rows_of_a_multi_megabyte_token() {
        let token = "界".repeat(1024 * 1024);
        assert!(token.len() > 2 * 1024 * 1024);

        let wrapped = wrap_limited(&token, 79, TOOL_OUTPUT_LINES + 1);

        assert_eq!(wrapped.len(), TOOL_OUTPUT_LINES + 1);
        // 39 ideographs, not 79: the pane is measured in cells, and each of these takes
        // two. A line of 79 of them would be drawn 158 cells wide and clipped in half.
        assert!(
            wrapped
                .iter()
                .all(|line| line.width() == 78 && line.chars().count() == 39),
            "{:?}",
            wrapped.first()
        );
    }

    #[test]
    fn a_cjk_line_wraps_to_the_cells_the_pane_actually_has() {
        let wrapped = wrap("設定を確認してから、テストを実行してください", 12);

        assert!(wrapped.iter().all(|line| line.width() <= 12), "{wrapped:?}");
        assert!(wrapped.len() > 1, "{wrapped:?}");
        assert_eq!(
            wrapped.concat(),
            "設定を確認してから、テストを実行してください"
        );
    }

    #[test]
    fn emoji_wrap_by_cell_and_a_single_one_still_gets_a_row() {
        let wrapped = wrap("🚀🚀🚀🚀🚀", 4);

        assert!(wrapped.iter().all(|line| line.width() <= 4), "{wrapped:?}");
        assert_eq!(wrapped.concat(), "🚀🚀🚀🚀🚀");

        // Narrower than one glyph: it gets a row rather than being dropped or looping.
        let narrow = wrap("🚀🚀", 1);
        assert_eq!(narrow.concat(), "🚀🚀");
    }

    #[test]
    fn combining_marks_ride_with_the_character_they_modify() {
        // e + U+0301 is one cell, so eight of them fit a pane of eight.
        let text = "e\u{301}".repeat(8);
        let wrapped = wrap(&text, 8);

        assert_eq!(wrapped, vec![text.clone()]);
        assert_eq!(wrapped[0].width(), 8);
    }

    #[test]
    fn bounds_direct_multi_megabyte_tool_values_before_rendering() {
        let tool = Cell::Tool(ToolCell {
            call_id: None,
            name: "read".into(),
            input: json!({"path": "huge.log"}),
            output: Some(Value::String("x".repeat(3 * 1024 * 1024))),
            state: ToolState::Completed,
            kind: None,
            started_at: None,
            settled_at: None,
        });

        let value = match &tool {
            Cell::Tool(tool) => value_text(tool.output.as_ref().expect("output")),
            _ => unreachable!(),
        };
        assert!(value.len() <= TOOL_VALUE_BYTES);
        assert!(value.ends_with(TOOL_VALUE_TRUNCATION));

        let rendered = render_cells(&[tool], 40);
        assert!(
            rendered.len() <= TOOL_OUTPUT_LINES + 6,
            "{}",
            rendered.len()
        );
        // One three-megabyte token wraps to far more rows than a compact cell spends, and
        // the row that admits it names the count and the key.
        assert!(
            plain(&rendered).contains("full result · ctrl+o"),
            "{}",
            plain(&rendered)
        );
    }

    #[test]
    fn bounds_message_and_status_rows_without_hiding_the_raw_ledger_path() {
        let message = Cell::Message {
            speaker: Speaker::Agent,
            text: "x".repeat(3 * 1024 * 1024),
            streaming: false,
        };
        let rendered = render_cells(&[message], 10);

        assert!(rendered.len() <= MESSAGE_LINES + 2, "{}", rendered.len());
        assert!(plain(&rendered).contains("full message · ctrl+o"));

        let status = Cell::Status {
            label: "Failed".into(),
            detail: "y".repeat(3 * 1024 * 1024),
            tone: Tone::Error,
        };
        let rendered = render_cells(&[status], 10);

        assert!(
            rendered.len() <= STATUS_DETAIL_LINES + 2,
            "{}",
            rendered.len()
        );
        assert!(plain(&rendered).contains("full status · ctrl+o"));
    }

    #[test]
    fn linear_wrapper_keeps_existing_space_and_newline_semantics() {
        assert_eq!(wrap("alpha beta", 7), vec!["alpha", "beta"]);
        assert_eq!(wrap("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
        assert_eq!(wrap("a  b\n", 10), vec!["a  b", ""]);
    }

    #[test]
    fn an_input_the_ledger_did_not_record_still_appears_in_the_chat() {
        let unrecorded = event(1, "input_accepted", json!({"kind": "message"}));
        let steer = event(2, "input_accepted", json!({"kind": "steer"}));
        let told = event(
            3,
            "input_accepted",
            json!({"kind": "steer", "text": "use the smaller fixture"}),
        );

        let cells = project(vec![
            Entry::Event(&unrecorded),
            Entry::Event(&steer),
            Entry::Event(&told),
        ]);

        assert_eq!(
            cells,
            vec![
                Cell::ChatNote {
                    text: "[message not recorded]".into()
                },
                Cell::ChatNote {
                    text: "You steered the agent".into()
                },
                Cell::ChatNote {
                    text: "You steered the agent: use the smaller fixture".into()
                },
            ]
        );

        let text = plain(&render_cells(&cells, 80));
        assert!(text.contains("[message not recorded]"), "{text}");
        assert!(text.contains("You steered the agent"), "{text}");
        assert!(text.contains("use the smaller fixture"), "{text}");
    }

    #[test]
    fn stream_integrity_markers_stay_in_the_reading_path() {
        let cells = project(vec![
            Entry::Floor(41),
            Entry::Gap { from: 42, to: 44 },
            Entry::Ended("closed"),
        ]);
        let text = plain(&render_cells(&cells, 90));

        assert!(text.contains("Earlier conversation is no longer available"));
        assert!(text.contains("Restoring 3 missing updates"));
        assert!(text.contains("Session ended (closed)"));
    }

    #[test]
    fn a_resolved_approval_replaces_the_pending_status() {
        let requested = Event::decode(&json!({
            "id": "evt-1",
            "sequence": 1,
            "type": "approval_requested",
            "timestamp": "2026-08-14T00:00:00Z",
            "request_id": "req-1",
            "payload": {"tool_call": {"name": "bash", "command": "git status"}}
        }))
        .expect("a request");
        let resolved = Event::decode(&json!({
            "id": "evt-2",
            "sequence": 2,
            "type": "approval_resolved",
            "timestamp": "2026-08-14T00:00:01Z",
            "request_id": "req-1",
            "payload": {"decision": "approve", "scope": "once"}
        }))
        .expect("a resolution");

        let cells = project(vec![Entry::Event(&requested), Entry::Event(&resolved)]);
        assert_eq!(cells.len(), 1);
        let text = plain(&render_cells(&cells, 80));

        assert!(text.contains("Approved"), "{text}");
        assert!(text.contains("git status"), "{text}");
        assert!(text.contains("approve · once"), "{text}");
        assert!(!text.contains("Approval needed"), "{text}");
    }

    #[test]
    fn user_and_agent_messages_share_one_readable_editorial_column() {
        let cells = vec![
            Cell::Message {
                speaker: Speaker::You,
                text: "please fix the tests".into(),
                streaming: false,
            },
            Cell::Message {
                speaker: Speaker::Agent,
                text: "The tests are fixed.".into(),
                streaming: false,
            },
        ];
        let lines = render_cells(&cells, 40);
        let you = lines
            .iter()
            .map(plain_line)
            .find(|line| line.contains("YOU"))
            .expect("a YOU label");
        let user_body = lines
            .iter()
            .map(plain_line)
            .find(|line| line.contains("please fix the tests"))
            .expect("the user body");
        let agent = lines
            .iter()
            .map(plain_line)
            .find(|line| line.trim() == "◆ AGENT / RESPONSE")
            .expect("an AGENT label");
        let agent_body = lines
            .iter()
            .map(plain_line)
            .find(|line| line.contains("The tests are fixed."))
            .expect("the agent body");

        assert!(you.starts_with("┌─ ▌ YOU "), "{you:?}");
        assert!(you.ends_with('┐'), "{you:?}");
        assert!(user_body.starts_with("│ "), "{user_body:?}");
        assert_eq!(agent, "◆ AGENT / RESPONSE");
        assert_eq!(agent_body, "The tests are fixed.");
    }

    #[test]
    fn an_agent_code_block_is_framed_labelled_and_highlighted() {
        let cells = vec![Cell::Message {
            speaker: Speaker::Agent,
            text: "Here is the entrypoint:\n```rust\nfn main() {\n    println!(\"hi\");\n}\n```\nDone.".into(),
            streaming: false,
        }];
        let lines = render_cells(&cells, 60);
        let rows: Vec<String> = lines.iter().map(plain_line).collect();
        let text = rows.join("\n");

        assert!(text.contains("┌─ rust "), "{text}");
        assert!(text.contains("│ fn main() {"), "{text}");
        // Indentation survives the frame; the prose wrapper would have collapsed it.
        assert!(text.contains("│     println!(\"hi\");"), "{text}");
        assert!(text.contains("└"), "{text}");
        assert!(text.contains("Done."), "{text}");

        let keyword = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .find(|span| span.content == "fn")
            .expect("the fn keyword");
        assert_eq!(keyword.style.fg, Some(theme::code_keyword()));
    }

    #[test]
    fn inline_backticked_prose_is_styled_without_becoming_a_block() {
        let cells = vec![Cell::Message {
            speaker: Speaker::Agent,
            text: "Run `mix test` to confirm.".into(),
            streaming: false,
        }];

        let lines = render_cells(&cells, 60);
        let code = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .find(|span| span.content.contains("mix test"))
            .expect("the inline code");

        assert_eq!(code.content.as_ref(), "`mix test`");
        assert_eq!(code.style.fg, Some(theme::system()));
    }

    #[test]
    fn a_streaming_block_has_no_floor_and_carries_the_caret() {
        let cells = vec![Cell::Message {
            speaker: Speaker::Agent,
            text: "Working:\n```python\nprint('hi')\n".into(),
            streaming: true,
        }];

        let lines = render_cells_at(&cells, 60, 0, Verbosity::Compact);
        let text = plain(&lines);

        assert!(text.contains("┌─ python "), "{text}");
        assert!(!text.contains('└'), "an open block has no floor: {text}");
        assert!(text.contains("▌"), "{text}");

        // The same text once closed gets its floor back.
        let finished = render_cells(
            &[Cell::Message {
                speaker: Speaker::Agent,
                text: "Working:\n```python\nprint('hi')\n```".into(),
                streaming: false,
            }],
            60,
        );
        assert!(plain(&finished).contains('└'));
    }

    #[test]
    fn an_oversized_code_block_is_capped_inside_its_frame() {
        let block = format!("```elixir\n{}\n```", "line\n".repeat(600));
        let cells = vec![Cell::Message {
            speaker: Speaker::Agent,
            text: block,
            streaming: false,
        }];

        let rendered = render_cells(&cells, 60);
        let text = plain(&rendered);

        assert!(rendered.len() <= MESSAGE_LINES + 2, "{}", rendered.len());
        assert!(
            text.contains("rest of this block in event details"),
            "{text}"
        );
        // The block's own notice replaces the message-level one; both would be noise.
        assert!(!text.contains("full message in event details"), "{text}");
        let floor = plain_line(rendered.last().expect("rows"));
        assert!(floor.starts_with('└'), "the frame still closes: {floor}");
    }

    #[test]
    fn command_activity_is_dimmer_and_more_compact_than_agent_copy() {
        let cells = vec![
            Cell::Message {
                speaker: Speaker::Agent,
                text: "I'll run the suite.".into(),
                streaming: false,
            },
            Cell::Tool(ToolCell {
                call_id: Some("c1".into()),
                name: "exec_command".into(),
                input: json!({"cmd": "mix test"}),
                output: Some(Value::String("3 tests, 0 failures".into())),
                state: ToolState::Completed,
                kind: None,
                started_at: None,
                settled_at: None,
            }),
        ];
        let lines = render_cells(&cells, 80);
        let text = plain(&lines);

        assert!(text.contains("I'll run the suite."), "{text}");
        assert!(text.contains("✓ Bash"), "{text}");
        assert!(text.contains("$ mix test"), "{text}");
        assert!(text.contains("3 tests, 0 failures"), "{text}");
        assert!(!text.contains("Run  "), "{text}");
        assert!(!text.contains("  done"), "{text}");
        assert!(text.contains('┌') && text.contains('└'), "{text}");

        let command = lines
            .iter()
            .find(|line| plain_line(line).contains("✓ Bash"))
            .expect("a command row");
        assert!(
            command
                .spans
                .iter()
                .any(|span| span.style.add_modifier.contains(Modifier::DIM)),
            "{command:?}"
        );

        let agent_body = lines
            .iter()
            .find(|line| plain_line(line).contains("I'll run the suite."))
            .expect("agent copy");
        assert!(
            agent_body
                .spans
                .iter()
                .all(|span| !span.style.add_modifier.contains(Modifier::DIM)),
            "{agent_body:?}"
        );
    }

    fn stamped(sequence: u64, kind: &str, timestamp: &str, payload: Value) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": timestamp,
            "turn_id": "turn-1",
            "payload": payload
        }))
        .expect("an event")
    }

    fn thinking(sequence: u64, lines: usize) -> Event {
        let text: String = (0..lines).map(|line| format!("thought {line}\n")).collect();
        event(sequence, "thinking_delta", json!({ "text": text }))
    }

    /// Crush's three states, and the reason the default is the first one: reasoning
    /// expanded by default in a long session buries the conversation (R2 §10d).
    #[test]
    fn reasoning_collapses_to_a_header_tails_while_live_and_expands_under_ctrl_o() {
        let reasoning = thinking(1, 500);
        let answer = event(2, "output_text_final", json!({"text": "done"}));

        // Still the newest thing in the transcript: the tail is what a reader watches.
        let live = project(vec![Entry::Event(&reasoning)]);
        let Cell::Thinking { lines, state, .. } = &live[0] else {
            panic!("expected a reasoning cell, got {live:?}")
        };
        assert_eq!(*lines, 500);
        assert_eq!(*state, ThinkingState::Tail);

        let tail = plain(&render_cells(&live, 80));
        assert!(tail.contains("\u{25c7} thinking  500 lines"), "{tail}");
        assert!(tail.contains("300 earlier lines of reasoning"), "{tail}");
        assert!(tail.contains("thought 499"), "{tail}");
        assert!(
            !tail.contains("thought 299"),
            "the tail is the last 200: {tail}"
        );

        // Something followed it, so it folds to its header and nothing else.
        let settled = project(vec![Entry::Event(&reasoning), Entry::Event(&answer)]);
        let Cell::Thinking { state, .. } = &settled[0] else {
            panic!("expected a reasoning cell")
        };
        assert_eq!(*state, ThinkingState::Collapsed);

        let collapsed = plain(&render_cells(&settled, 80));
        assert!(
            collapsed.contains("\u{25c7} thinking  500 lines"),
            "{collapsed}"
        );
        assert!(collapsed.contains("ctrl+o expands"), "{collapsed}");
        assert!(!collapsed.contains("thought 499"), "{collapsed}");

        // Ctrl+O: the whole thing, in place.
        let full = plain(&render_cells_at(&settled, 80, 0, Verbosity::Verbose));
        assert!(full.contains("thought 0"), "{full}");
        assert!(full.contains("thought 499"), "{full}");
        assert!(!full.contains("earlier lines of reasoning"), "{full}");
    }

    #[test]
    fn consecutive_reasoning_deltas_accumulate_into_one_cell_per_turn() {
        let first = event(1, "thinking_delta", json!({"text": "first\n"}));
        let second = event(2, "thinking_delta", json!({"text": "second\n"}));
        let cells = project(vec![Entry::Event(&first), Entry::Event(&second)]);

        assert_eq!(cells.len(), 1, "{cells:?}");
        let Cell::Thinking { text, .. } = &cells[0] else {
            panic!("expected one reasoning cell")
        };
        assert_eq!(text, "first\nsecond\n");
    }

    /// X10: a finished turn had no terminator at all, so "did it finish?" was unanswerable.
    #[test]
    fn a_turn_boundary_divider_states_the_elapsed_time_it_measured() {
        let started = stamped(1, "turn_started", "2026-08-14T00:00:00.000000Z", json!({}));
        let text = stamped(
            2,
            "output_text_final",
            "2026-08-14T00:02:00.000000Z",
            json!({"text": "done"}),
        );
        let completed = stamped(
            3,
            "turn_completed",
            "2026-08-14T00:04:07.000000Z",
            json!({}),
        );

        let cells = project(vec![
            Entry::Event(&started),
            Entry::Event(&text),
            Entry::Event(&completed),
        ]);
        let rendered = plain(&render_cells(&cells, 80));

        assert!(
            rendered.contains("turn complete \u{b7} 4m 07s"),
            "{rendered}"
        );
    }

    /// A turn whose start this window no longer holds gets a terminator and no duration —
    /// never a duration measured from an instant nobody has.
    #[test]
    fn a_turn_end_without_its_start_says_nothing_about_duration() {
        let completed = stamped(
            9,
            "turn_completed",
            "2026-08-14T00:04:07.000000Z",
            json!({}),
        );
        let rendered = plain(&render_cells(&project(vec![Entry::Event(&completed)]), 80));

        assert!(rendered.contains("turn complete"), "{rendered}");
        assert!(!rendered.contains("\u{b7} "), "{rendered}");
    }

    /// A failed or interrupted turn is still terminated, and still loud.
    #[test]
    fn a_failed_turn_keeps_its_error_cell_above_the_boundary() {
        let started = stamped(1, "turn_started", "2026-08-14T00:00:00.000000Z", json!({}));
        let failed = stamped(
            2,
            "turn_failed",
            "2026-08-14T00:00:03.000000Z",
            json!({"error": "the provider exited"}),
        );

        let rendered = plain(&render_cells(
            &project(vec![Entry::Event(&started), Entry::Event(&failed)]),
            80,
        ));

        assert!(rendered.contains("Agent error"), "{rendered}");
        assert!(rendered.contains("the provider exited"), "{rendered}");
        assert!(rendered.contains("turn failed \u{b7} 3s"), "{rendered}");
    }

    #[test]
    fn elapsed_time_is_phrased_the_way_a_status_widget_phrases_it() {
        assert_eq!(duration(840), "840ms");
        assert_eq!(duration(9_400), "9s");
        assert_eq!(duration(247_000), "4m 07s");
        assert_eq!(duration(3_720_000), "1h 02m");
    }

    /// X12: `plan_updated` was journaled and dropped.
    #[test]
    fn a_plan_cell_draws_warp_glyphs_and_counts_what_is_done() {
        let plan = event(
            1,
            "plan_updated",
            json!({
                "explanation": "three steps",
                "plan": [
                    {"step": "read the failing test", "status": "completed"},
                    {"step": "fix the projection", "status": "in_progress"},
                    {"step": "run the suite", "status": "pending"}
                ]
            }),
        );

        let cells = project(vec![Entry::Event(&plan)]);
        assert!(matches!(cells[0], Cell::Plan(_)), "{cells:?}");

        let rendered = plain(&render_cells(&cells, 80));
        assert!(rendered.contains("1/3 done"), "{rendered}");
        assert!(rendered.contains("three steps"), "{rendered}");
        assert!(
            rendered.contains("\u{2713} read the failing test"),
            "{rendered}"
        );
        assert!(
            rendered.contains("\u{25cf} fix the projection"),
            "{rendered}"
        );
        assert!(rendered.contains("\u{25cc} run the suite"), "{rendered}");
    }

    #[test]
    fn a_plan_step_whose_status_is_unknown_shows_the_word_the_provider_used() {
        let plan = event(
            1,
            "plan_updated",
            json!({"plan": [{"content": "verify", "status": "awaiting_review"}]}),
        );
        let rendered = plain(&render_cells(&project(vec![Entry::Event(&plan)]), 80));

        assert!(
            rendered.contains("? verify  (awaiting_review)"),
            "{rendered}"
        );
        assert!(rendered.contains("0/1 done"), "{rendered}");
    }

    /// D2: nineteen kinds used to reach this projection and vanish. None of them may.
    #[test]
    fn the_kinds_that_used_to_be_dropped_now_reach_the_reading_path() {
        let events = [
            event(
                1,
                "run_started",
                json!({"model": "claude-sonnet-5", "tools": ["Read", "Edit"]}),
            ),
            event(2, "session_ready", json!({"transport": "acp"})),
            event(3, "queue_changed", json!({"queued_turns": 2})),
            event(
                4,
                "provider_event",
                json!({"kind": "acp_update", "update": {"sessionUpdate": "available_commands_update"}}),
            ),
            event(5, "session_idle", json!({})),
        ];
        let entries = events.iter().map(Entry::Event).collect();
        let rendered = plain(&render_cells(&project(entries), 100));

        assert!(
            rendered.contains("run started \u{b7} claude-sonnet-5 \u{b7} 2 tools"),
            "{rendered}"
        );
        assert!(rendered.contains("session ready \u{b7} acp"), "{rendered}");
        assert!(rendered.contains("2 follow-ups are queued"), "{rendered}");
        assert!(
            rendered.contains("provider event \u{b7} acp_update \u{b7} available_commands_update"),
            "{rendered}"
        );
        assert!(rendered.contains("session idle"), "{rendered}");
    }

    /// The queue depth is a running fact, not an event stream: repeating it unchanged would
    /// put one line in the conversation per turn of a long queue.
    #[test]
    fn an_unchanged_queue_depth_is_not_restated() {
        let events = [
            event(1, "queue_changed", json!({"queued_turns": 1})),
            event(2, "queue_changed", json!({"queued_turns": 1})),
            event(3, "queue_changed", json!({"queued_turns": 0})),
        ];
        let entries = events.iter().map(Entry::Event).collect();
        let rendered = plain(&render_cells(&project(entries), 100));

        assert_eq!(
            rendered.matches("1 follow-up is queued").count(),
            1,
            "{rendered}"
        );
        assert!(
            rendered.contains("The follow-up queue is empty"),
            "{rendered}"
        );
    }

    /// Token reports are the footer's business, not the conversation's — until a reader
    /// asks for the bookkeeping.
    #[test]
    fn a_usage_report_appears_only_under_ctrl_o() {
        let usage = event(
            1,
            "usage",
            json!({"input_tokens": 21088, "output_tokens": 512, "total_tokens": 21600}),
        );
        let cells = project(vec![Entry::Event(&usage)]);

        assert!(plain(&render_cells(&cells, 100)).trim().is_empty());

        let verbose = plain(&render_cells_at(&cells, 100, 0, Verbosity::Verbose));
        assert!(
            verbose.contains("usage \u{b7} in 21088 \u{b7} out 512"),
            "{verbose}"
        );
    }

    /// The gateway will excerpt long string leaves. None of its markers may reach the
    /// screen as JSON, in any projection that reads a leaf.
    #[test]
    fn wire_markers_never_render_as_json_in_a_tool_cell() {
        let call = event(
            1,
            "tool_call",
            json!({
                "call_id": "c1",
                "name": "bash",
                "input": {"cmd": {"_excerpt": "rg --json 'fn '", "_bytes": 40_000}}
            }),
        );
        let result = event(
            2,
            "tool_result",
            json!({
                "call_id": "c1",
                "output": {"_excerpt": "lib/a.ex:1", "_bytes": 5_000_000}
            }),
        );

        let rendered = plain(&render_cells(
            &project(vec![Entry::Event(&call), Entry::Event(&result)]),
            120,
        ));

        assert!(
            rendered.contains("rg --json 'fn '\u{2026} (40000 bytes"),
            "{rendered}"
        );
        assert!(
            rendered.contains("lib/a.ex:1\u{2026} (5000000 bytes"),
            "{rendered}"
        );
        assert!(!rendered.contains("_excerpt"), "{rendered}");
        assert!(!rendered.contains("_bytes"), "{rendered}");
    }

    #[test]
    fn an_opaque_or_binary_leaf_reads_as_a_short_label() {
        let result = event(
            1,
            "tool_result",
            json!({"call_id": "c1", "output": {"_opaque": "#Reference<0.1.2.3>"}}),
        );
        let rendered = plain(&render_cells(&project(vec![Entry::Event(&result)]), 120));

        assert!(
            rendered.contains("[not encodable: #Reference<0.1.2.3>]"),
            "{rendered}"
        );
        assert!(!rendered.contains("_opaque"), "{rendered}");
    }

    /// Verbose is bounded too. `Ctrl+O` is "show me the rest", not "re-lay-out sixty-four
    /// megabytes on every frame".
    #[test]
    fn verbose_expands_cells_in_place_and_still_bounds_them() {
        let tool = Cell::Tool(ToolCell {
            call_id: Some("c1".into()),
            name: "read".into(),
            input: json!({"path": "huge.log"}),
            output: Some(Value::String(
                (0..(VERBOSE_LINES + 500))
                    .map(|n| format!("line {n}\n"))
                    .collect(),
            )),
            state: ToolState::Completed,
            kind: None,
            started_at: None,
            settled_at: None,
        });

        let compact = render_cells(std::slice::from_ref(&tool), 80);
        let verbose = render_cells_at(&[tool], 80, 0, Verbosity::Verbose);

        assert!(verbose.len() > compact.len(), "verbose must show more");
        assert!(
            verbose.len() <= VERBOSE_LINES + 8,
            "verbose is bounded: {}",
            verbose.len()
        );
        assert!(plain(&verbose).contains("full result \u{b7} /details"));
    }

    // ---------------------------------------------------------------------------------
    // A3 — tool cells v2
    // ---------------------------------------------------------------------------------

    fn call(sequence: u64, payload: Value) -> Event {
        event(sequence, "tool_call", payload)
    }

    fn result(sequence: u64, payload: Value) -> Event {
        event(sequence, "tool_result", payload)
    }

    /// The one summariser, exercised through the three naming systems that reach it.
    #[test]
    fn per_tool_summaries_read_the_same_whichever_dialect_named_the_call() {
        let cases: Vec<(Value, &str)> = vec![
            // Claude's own names.
            (
                json!({"name": "Read", "input": {"file_path": "src/lex.rs", "offset": 12, "limit": 40}}),
                "Read src/lex.rs:12-51",
            ),
            (
                json!({"name": "Edit", "input": {
                    "file_path": "src/lex.rs",
                    "old_string": "a\nb",
                    "new_string": "a\nB\nc"
                }}),
                "Edit src/lex.rs (+3 −2)",
            ),
            (
                json!({"name": "Write", "input": {"file_path": "docs/NEW.md"}}),
                "Write docs/NEW.md",
            ),
            (
                json!({"name": "Grep", "input": {"pattern": "needle", "path": "lib"}}),
                "Grep \"needle\" in lib",
            ),
            (
                json!({"name": "Glob", "input": {"pattern": "**/*.ex"}}),
                "Glob **/*.ex",
            ),
            (
                json!({"name": "Bash", "input": {"command": "cargo test"}}),
                "Bash $ cargo test",
            ),
            (
                json!({"name": "WebFetch", "input": {"url": "https://example.test/a"}}),
                "Fetch https://example.test/a",
            ),
            (
                json!({"name": "mcp__linear__create_issue", "input": {}}),
                "MCP linear.create_issue",
            ),
            // Codex item types, as the runtime's dialect normalises them.
            (
                json!({"name": "exec_command", "input": {"cmd": "mix test", "cwd": "/ws"}}),
                "Bash $ mix test",
            ),
            (
                json!({"name": "github.create_pr", "input": {}}),
                "MCP github.create_pr",
            ),
            // ACP `kind`, where the title says nothing an enum would.
            (
                json!({"kind": "read", "title": "Looking at the worker", "input": {"path": "lib/w.ex"}}),
                "Read lib/w.ex",
            ),
            (
                json!({"kind": "execute", "title": "Running the suite", "input": {"command": "mix test"}}),
                "Bash $ mix test",
            ),
            (
                json!({"kind": "search", "title": "Hunting", "input": {"query": "needle"}}),
                "Grep \"needle\"",
            ),
            (
                json!({"kind": "delete", "title": "Tidying", "input": {"path": "tmp/x"}}),
                "Delete tmp/x",
            ),
            (
                json!({"kind": "move", "title": "Shuffling", "input": {"path": "a/b.ex"}}),
                "Move a/b.ex",
            ),
            (
                json!({"kind": "fetch", "title": "Grabbing", "input": {"url": "https://e.test"}}),
                "Fetch https://e.test",
            ),
            (
                json!({"kind": "think", "title": "Pondering", "input": {}}),
                "Think",
            ),
            // Nothing matched: the row keeps the provider's own name and its own input,
            // rather than a verb this client made up for it.
            (
                json!({"kind": "other", "title": "whatever", "input": {"z": 1}}),
                "whatever {\"z\":1}",
            ),
        ];

        for (payload, expected) in cases {
            let event = call(1, payload.clone());
            let cells = project(vec![Entry::Event(&event)]);
            let tool = match &cells[0] {
                Cell::Tool(tool) => tool.clone(),
                Cell::Exploration(group) => group.calls[0].clone(),
                other => panic!("{payload}: unexpected cell {other:?}"),
            };

            assert_eq!(summarise(&tool).line(), expected, "for {payload}");
        }
    }

    /// Gemini's `→ Returned N lines`, said only about text this client actually holds.
    #[test]
    fn a_result_adds_a_count_the_client_can_see_and_never_one_it_cannot() {
        let call = call(
            1,
            json!({"call_id": "g", "name": "grep", "input": {"pattern": "fn"}}),
        );
        let result = result(
            2,
            json!({"call_id": "g", "output": {"text": "a.rs:1\nb.rs:2\nc.rs:3"}}),
        );
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);
        let Cell::Exploration(group) = &cells[0] else {
            panic!("a grep is exploration: {cells:?}")
        };

        assert_eq!(summarise(&group.calls[0]).line(), "Grep \"fn\" → 3 matches");

        // Still running: no result, therefore no count.
        let pending = project(vec![Entry::Event(&call)]);
        let Cell::Exploration(group) = &pending[0] else {
            panic!("a grep is exploration")
        };
        assert_eq!(summarise(&group.calls[0]).line(), "Grep \"fn\"");
    }

    /// A bounded value's count is a floor, and the `+` says so.
    #[test]
    fn a_bounded_result_counts_itself_as_at_least_rather_than_exactly() {
        let call = call(
            1,
            json!({"call_id": "g", "name": "grep", "input": {"pattern": "x"}}),
        );
        let huge: String = (0..40_000).map(|n| format!("hit {n}\n")).collect();
        let result = result(2, json!({"call_id": "g", "output": {"text": huge}}));
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);
        let Cell::Exploration(group) = &cells[0] else {
            panic!("a grep is exploration")
        };

        let line = summarise(&group.calls[0]).line();
        assert!(line.contains('+'), "a floor is marked as one: {line}");
    }

    #[test]
    fn a_command_states_the_exit_code_a_provider_sent_and_says_failed_when_only_is_error_did() {
        let with_code = project(vec![
            Entry::Event(&call(
                1,
                json!({"call_id": "b", "name": "bash", "input": {"cmd": "false"}}),
            )),
            Entry::Event(&result(
                2,
                json!({"call_id": "b", "output": {"exit_code": 3, "text": "boom"}, "is_error": true}),
            )),
        ]);
        let Cell::Tool(tool) = &with_code[0] else {
            panic!("a command is its own cell")
        };
        assert_eq!(summarise(tool).outcome, "exit 3");

        let without = project(vec![
            Entry::Event(&call(
                1,
                json!({"call_id": "b", "name": "bash", "input": {"cmd": "false"}}),
            )),
            Entry::Event(&result(
                2,
                json!({"call_id": "b", "output": "boom", "is_error": true}),
            )),
        ]);
        let Cell::Tool(tool) = &without[0] else {
            panic!("a command is its own cell")
        };
        assert_eq!(summarise(tool).outcome, "failed");
    }

    /// Codex's grouped exploration cell, both states.
    #[test]
    fn consecutive_exploration_collapses_and_flips_when_anything_else_is_drawn() {
        let calls: Vec<Event> = vec![
            call(
                1,
                json!({"call_id": "r1", "name": "read", "input": {"path": "a.ex"}}),
            ),
            call(
                2,
                json!({"call_id": "r2", "name": "grep", "input": {"pattern": "x"}}),
            ),
            call(
                3,
                json!({"call_id": "r3", "name": "glob", "input": {"pattern": "*.ex"}}),
            ),
            call(
                4,
                json!({"call_id": "r4", "name": "ls", "input": {"path": "lib"}}),
            ),
        ];
        let results: Vec<Event> = (1..=4)
            .map(|n| result(10 + n, json!({"call_id": format!("r{n}"), "output": "ok"})))
            .collect();

        let edit = call(
            20,
            json!({"call_id": "e", "name": "edit", "input": {"path": "a.ex"}}),
        );
        let entries = || {
            let mut entries: Vec<Entry> = Vec::new();
            for (call, result) in calls.iter().zip(results.iter()) {
                entries.push(Entry::Event(call));
                entries.push(Entry::Event(result));
            }
            entries
        };

        let open = project(entries());
        assert_eq!(open.len(), 1, "four calls, one cell: {open:?}");
        let Cell::Exploration(group) = &open[0] else {
            panic!("expected one exploration cell")
        };
        assert_eq!(group.total(), 4);
        assert!(!group.done, "nothing has been drawn after it yet");
        assert!(
            plain(&render_cells(&open, 80)).contains("Exploring… (4)"),
            "{}",
            plain(&render_cells(&open, 80))
        );

        // A non-exploration cell after it flips the header.
        let mut with_edit = entries();
        with_edit.push(Entry::Event(&edit));
        let closed = project(with_edit);
        let Cell::Exploration(group) = &closed[0] else {
            panic!("expected the exploration cell first")
        };
        assert!(group.done);
        let text = plain(&render_cells(&closed, 80));
        assert!(text.contains("Explored 4 files"), "{text}");
        assert!(!text.contains("Exploring…"), "{text}");

        // Expanded, every call is its own row.
        let verbose = plain(&render_cells_at(&closed, 80, 0, Verbosity::Verbose));
        for expected in ["Read a.ex", "Grep \"x\"", "Glob *.ex", "List lib"] {
            assert!(
                verbose.contains(expected),
                "{expected} missing from {verbose}"
            );
        }
    }

    /// A turn boundary closes the group even when nothing else was drawn.
    #[test]
    fn a_turn_boundary_closes_an_open_exploration_group() {
        let read = call(
            1,
            json!({"call_id": "r", "name": "read", "input": {"path": "a.ex"}}),
        );
        let end = event(2, "turn_completed", json!({}));
        let cells = project(vec![Entry::Event(&read), Entry::Event(&end)]);
        let Cell::Exploration(group) = &cells[0] else {
            panic!("expected the exploration cell first: {cells:?}")
        };

        assert!(group.done, "the divider is a cell drawn after it");
        assert!(plain(&render_cells(&cells, 80)).contains("Explored 1 file"));
    }

    /// An edit, a command, or a fetch is something the agent *did* and is never folded away.
    #[test]
    fn work_is_never_folded_into_the_exploration_count() {
        for name in ["edit", "write", "bash", "web_fetch", "delete"] {
            let doing = call(
                1,
                json!({"call_id": "d", "name": name, "input": {"path": "a", "cmd": "a", "url": "a"}}),
            );
            let cells = project(vec![Entry::Event(&doing)]);
            assert!(
                matches!(cells[0], Cell::Tool(_)),
                "{name} is work, not exploration: {cells:?}"
            );
        }
    }

    /// A run of exploration is bounded; past the ceiling the calls are counted, and said so.
    #[test]
    fn an_exploration_group_bounds_what_it_lists_and_counts_the_rest() {
        let calls: Vec<Event> = (0..(EXPLORATION_CALLS as u64 + 9))
            .map(|n| {
                call(
                    n + 1,
                    json!({"call_id": format!("r{n}"), "name": "read", "input": {"path": format!("f{n}.ex")}}),
                )
            })
            .collect();
        let cells = project(calls.iter().map(Entry::Event).collect());
        let Cell::Exploration(group) = &cells[0] else {
            panic!("expected one exploration cell")
        };

        assert_eq!(group.calls.len(), EXPLORATION_CALLS);
        assert_eq!(group.overflow, 9);
        assert_eq!(group.total(), EXPLORATION_CALLS + 9);
        assert!(plain(&render_cells_at(&cells, 100, 0, Verbosity::Verbose))
            .contains("… +9 more calls · /details"));
    }

    /// Codex's head/tail, with the exact marker the row is supposed to carry.
    #[test]
    fn a_long_tool_result_shows_a_head_a_counted_marker_and_a_tail() {
        let call = call(
            1,
            json!({"call_id": "b", "name": "bash", "input": {"cmd": "ls"}}),
        );
        let body: String = (0..40).map(|n| format!("row {n}\n")).collect();
        let result = result(2, json!({"call_id": "b", "output": body}));
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);
        let text = plain(&render_cells(&cells, 80));

        for head in 0..TOOL_HEAD_LINES {
            assert!(
                text.contains(&format!("row {head}")),
                "head row {head}: {text}"
            );
        }
        for tail in (40 - TOOL_TAIL_LINES)..40 {
            assert!(
                text.contains(&format!("row {tail}")),
                "tail row {tail}: {text}"
            );
        }
        assert!(
            text.contains("… +28 lines · ctrl+o"),
            "the exact marker Codex prints: {text}"
        );
        assert!(
            !text.contains("row 20"),
            "the middle is what is folded: {text}"
        );
    }

    /// A short result is not decorated with a marker it did not earn.
    #[test]
    fn a_result_that_fits_carries_no_truncation_marker() {
        let call = call(
            1,
            json!({"call_id": "b", "name": "bash", "input": {"cmd": "ls"}}),
        );
        let result = result(2, json!({"call_id": "b", "output": "one\ntwo\nthree"}));
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);
        let text = plain(&render_cells(&cells, 80));

        assert!(text.contains("one") && text.contains("three"), "{text}");
        assert!(!text.contains("ctrl+o"), "{text}");
    }

    /// A failure leads with its own text; the tail is what would push it off the row.
    #[test]
    fn a_failed_tool_shows_the_error_from_the_top() {
        let call = call(
            1,
            json!({"call_id": "b", "name": "bash", "input": {"cmd": "cargo b"}}),
        );
        let body: String = std::iter::once("error[E0432]: unresolved import\n".to_string())
            .chain((0..40).map(|n| format!("note {n}\n")))
            .collect();
        let result = result(2, json!({"call_id": "b", "output": body, "is_error": true}));
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);
        let text = plain(&render_cells(&cells, 80));

        assert!(text.contains("error[E0432]"), "{text}");
        assert!(text.contains("note 4"), "{text}");
        assert!(
            !text.contains("note 39"),
            "a failure gets the head, not the tail: {text}"
        );
        assert!(text.contains("… +35 lines · ctrl+o"), "{text}");
    }

    /// Kiro's live tail: streaming command output shows the newest rows, with the rest
    /// counted above them.
    #[test]
    fn streaming_command_output_is_a_tail_window_not_a_head() {
        let deltas: Vec<Event> = (0..30)
            .map(|n| {
                event(
                    n + 1,
                    "command_output_delta",
                    json!({"text": format!("out {n}\n")}),
                )
            })
            .collect();
        let cells = project(deltas.iter().map(Entry::Event).collect());
        let text = plain(&render_cells(&cells, 80));

        assert!(
            text.contains("out 29"),
            "the newest row is the point: {text}"
        );
        assert!(text.contains("out 26"), "{text}");
        assert!(!text.contains("out 0\n"), "{text}");
        assert!(
            text.contains("… +26 lines · ctrl+o"),
            "the earlier rows are counted, not dropped: {text}"
        );
    }

    /// Elapsed comes from two instants the ledger holds, never from a clock.
    #[test]
    fn a_tool_cell_states_the_elapsed_time_its_two_events_measured() {
        let call = stamped(
            1,
            "tool_call",
            "2026-08-14T09:00:00Z",
            json!({"call_id": "b", "name": "bash", "input": {"cmd": "mix test"}}),
        );
        let done = stamped(
            2,
            "tool_result",
            "2026-08-14T09:00:04.500Z",
            json!({"call_id": "b", "output": "ok"}),
        );
        let cells = project(vec![Entry::Event(&call), Entry::Event(&done)]);
        let Cell::Tool(tool) = &cells[0] else {
            panic!("a command is its own cell")
        };

        assert_eq!(tool.elapsed(), Some(4_500));
        assert!(plain(&render_cells(&cells, 80)).contains("4s"));
    }

    /// A running call is measured against the newest instant this window holds — a floor,
    /// and the only number a projection with no clock can honestly print.
    #[test]
    fn a_running_tool_is_timed_against_the_newest_event_the_window_holds() {
        let call = stamped(
            1,
            "tool_call",
            "2026-08-14T09:00:00Z",
            json!({"call_id": "b", "name": "bash", "input": {"cmd": "sleep 60"}}),
        );
        let later = stamped(
            2,
            "command_output_delta",
            "2026-08-14T09:00:07Z",
            json!({"text": "tick\n"}),
        );
        let cells = project(vec![Entry::Event(&call), Entry::Event(&later)]);
        let Cell::Tool(tool) = &cells[0] else {
            panic!("a command is its own cell")
        };

        assert_eq!(tool.state, ToolState::Running);
        assert_eq!(tool.elapsed(), Some(7_000));

        let text = plain(&render_cells(&cells, 80));
        assert!(text.contains("running"), "{text}");
        assert!(text.contains("7s"), "{text}");
    }

    /// The 10 k-line ceiling from A3's acceptance, with a debug-build allowance.
    #[test]
    fn a_ten_thousand_line_result_projects_and_renders_well_inside_the_frame_budget() {
        let call = call(
            1,
            json!({"call_id": "b", "name": "bash", "input": {"cmd": "cat big"}}),
        );
        let body: String = (0..10_000).map(|n| format!("line {n}\n")).collect();
        let result = result(2, json!({"call_id": "b", "output": body}));

        let started = std::time::Instant::now();
        for _ in 0..5 {
            let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);
            let lines = render_cells(&cells, 120);
            assert!(!lines.is_empty());
        }
        let each = started.elapsed() / 5;

        // The gate is 16 ms of frame time. This runs unoptimised under `cargo test`, so the
        // ceiling is deliberately generous; what it is guarding against is an accidental
        // O(n) *per row* — wrapping ten thousand lines to draw twelve of them.
        assert!(
            each < std::time::Duration::from_millis(150),
            "one projection + render took {each:?}"
        );
    }

    // ---------------------------------------------------------------------------------
    // A4 — diffs v2
    // ---------------------------------------------------------------------------------

    const PATCH: &str = "\
diff --git a/src/lex.rs b/src/lex.rs
--- a/src/lex.rs
+++ b/src/lex.rs
@@ -1,3 +1,3 @@ fn scan
 fn scan(text: &str) {
-    let end = text.find('\\n');
+    let end = text.find(['\\r', '\\n']);
     ok
";

    /// An approval event: the correlation id rides on the envelope, not in the payload.
    fn approval(sequence: u64, kind: &str, payload: Value) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": "2026-08-14T00:00:00Z",
            "request_id": "r1",
            "payload": payload
        }))
        .expect("an approval event")
    }

    fn change(sequence: u64, path: &str, patch: &str) -> Event {
        event(
            sequence,
            "file_change",
            json!({"changes": [{"path": path, "kind": "modified", "diff": patch}]}),
        )
    }

    /// The header's numbers are the parse's, and the gutter numbers both sides.
    #[test]
    fn a_diff_cell_counts_the_hunks_it_holds_and_numbers_the_lines() {
        let update = change(1, "src/lex.rs", PATCH);
        let cells = project(vec![Entry::Event(&update)]);
        let text = plain(&render_cells(&cells, 100));

        assert!(text.contains("M src/lex.rs  +1 −1"), "{text}");
        assert!(text.contains("@@ -1 +1 @@ fn scan"), "{text}");
        assert!(
            text.contains("  2     -    let end = text.find('\\n');"),
            "the removed line is numbered on the old side only: {text}"
        );
        assert!(
            text.contains("      2 +    let end = text.find(['\\r', '\\n']);"),
            "the added line is numbered on the new side only: {text}"
        );
    }

    /// The honesty invariant: the provider's claim never becomes the printed number.
    #[test]
    fn a_diff_prints_what_it_can_count_not_what_the_provider_claimed() {
        let update = event(
            1,
            "file_change",
            json!({
                "changes": [{
                    "path": "src/lex.rs",
                    "diff": PATCH,
                    // A provider summarising a much larger patch.
                    "additions": 400,
                    "deletions": 90
                }]
            }),
        );
        let cells = project(vec![Entry::Event(&update)]);
        let Cell::Diff(diff) = cells
            .iter()
            .find(|cell| matches!(cell, Cell::Diff(_)))
            .unwrap()
        else {
            unreachable!()
        };

        assert_eq!(diff.parsed.additions(), 1);
        assert_eq!(diff.parsed.deletions(), 1);
        let text = plain(&render_cells(&cells, 100));
        assert!(text.contains("+1 −1"), "{text}");
        assert!(!text.contains("+400"), "the claim is not the count: {text}");
    }

    /// Word-level emphasis reaches the rendered spans, not just the parse.
    #[test]
    fn only_the_changed_words_of_a_paired_line_are_drawn_undimmed() {
        let update = change(1, "src/lex.rs", PATCH);
        let cells = project(vec![Entry::Event(&update)]);
        let lines = render_cells(&cells, 100);

        let added = lines
            .iter()
            .find(|line| plain_line(line).contains("+    let end"))
            .expect("the added row");
        let strong: String = added
            .spans
            .iter()
            .filter(|span| span.style.add_modifier.contains(Modifier::BOLD))
            .map(|span| span.content.as_ref())
            .collect();

        assert!(
            strong.contains("['\\r', '\\n']"),
            "the rewritten expression is the emphasis: {strong:?}"
        );
        assert!(
            !strong.contains("let end"),
            "the shared prefix stays dim: {strong:?}"
        );
    }

    /// A collapsed diff spends twelve rows and says what the thirteenth would have been.
    #[test]
    fn a_long_diff_collapses_to_twelve_rows_and_names_the_key_that_opens_it() {
        let body: String = (0..60).map(|n| format!("+line {n}\n")).collect();
        let patch = format!("--- /dev/null\n+++ b/big.txt\n@@ -0,0 +1,60 @@\n{body}");
        let update = change(1, "big.txt", &patch);
        let cells = project(vec![Entry::Event(&update)]);

        let compact = plain(&render_cells(&cells, 100));
        assert!(compact.contains("A big.txt  +60 −0"), "{compact}");
        assert!(compact.contains("line 5"), "{compact}");
        assert!(!compact.contains("line 59"), "{compact}");
        assert!(compact.contains("lines · ctrl+o"), "{compact}");

        let verbose = plain(&render_cells_at(&cells, 100, 0, Verbosity::Verbose));
        assert!(verbose.contains("line 59"), "{verbose}");
        assert!(!verbose.contains("ctrl+o"), "{verbose}");
    }

    /// A long line wraps; the only copy of a change is never cut at the right margin.
    #[test]
    fn a_diff_wraps_long_lines_instead_of_truncating_them() {
        let long = "z".repeat(300);
        let patch = format!("--- a/w.txt\n+++ b/w.txt\n@@ -1,1 +1,1 @@\n+{long}\n");
        let update = change(1, "w.txt", &patch);
        let cells = project(vec![Entry::Event(&update)]);

        for width in [60usize, 100, 160] {
            let lines = render_cells_at(&cells, width, 0, Verbosity::Verbose);
            let text = plain(&lines);
            assert_eq!(
                text.matches('z').count(),
                300,
                "width {width} lost part of the change"
            );
            assert!(
                lines.iter().all(|line| line.width() <= width),
                "width {width} overflowed the pane"
            );
        }
    }

    /// Warp's rule, both halves.
    #[test]
    fn a_diff_under_an_open_approval_stays_expanded_and_says_so() {
        let asked = approval(
            1,
            "approval_requested",
            json!({"tool_call": {"name": "file_change", "path": "big.txt"}}),
        );
        let body: String = (0..60).map(|n| format!("+line {n}\n")).collect();
        let patch = format!("--- /dev/null\n+++ b/big.txt\n@@ -0,0 +1,60 @@\n{body}");
        let update = change(2, "big.txt", &patch);
        let resolved = approval(3, "approval_resolved", json!({"decision": "approve"}));

        let pending = project(vec![Entry::Event(&asked), Entry::Event(&update)]);
        let Cell::Diff(diff) = pending
            .iter()
            .find(|cell| matches!(cell, Cell::Diff(_)))
            .unwrap()
        else {
            unreachable!()
        };
        assert!(diff.pending_approval);

        let text = plain(&render_cells(&pending, 100));
        assert!(text.contains("pending approval"), "{text}");
        assert!(
            text.contains("line 59"),
            "expanded while the operator is being asked to judge it: {text}"
        );

        // Applied: back to the header.
        let applied = project(vec![
            Entry::Event(&asked),
            Entry::Event(&update),
            Entry::Event(&resolved),
        ]);
        let Cell::Diff(diff) = applied
            .iter()
            .find(|cell| matches!(cell, Cell::Diff(_)))
            .unwrap()
        else {
            unreachable!()
        };
        assert!(!diff.pending_approval);

        let text = plain(&render_cells(&applied, 100));
        assert!(!text.contains("pending approval"), "{text}");
        assert!(!text.contains("line 59"), "collapsed after apply: {text}");
    }

    /// An approval about something else never marks an unrelated change as pending.
    #[test]
    fn an_unrelated_approval_does_not_claim_a_diff_it_was_not_about() {
        let asked = approval(
            1,
            "approval_requested",
            json!({"tool_call": {"command": "cargo publish"}}),
        );
        let update = change(2, "src/lex.rs", PATCH);
        let cells = project(vec![Entry::Event(&asked), Entry::Event(&update)]);
        let Cell::Diff(diff) = cells
            .iter()
            .find(|cell| matches!(cell, Cell::Diff(_)))
            .unwrap()
        else {
            unreachable!()
        };

        assert!(!diff.pending_approval);
    }

    /// The post-turn diffstat, at the boundary the turn ended on.
    #[test]
    fn a_turn_end_carries_a_diffstat_of_what_that_turn_changed() {
        let one = change(
            1,
            "a.rs",
            "--- a/a.rs\n+++ b/a.rs\n@@ -1,1 +1,2 @@\n keep\n+added\n",
        );
        let two = change(
            2,
            "b.rs",
            "--- a/b.rs\n+++ b/b.rs\n@@ -1,2 +1,1 @@\n keep\n-gone\n",
        );
        let end = event(3, "turn_completed", json!({}));
        let cells = project(vec![
            Entry::Event(&one),
            Entry::Event(&two),
            Entry::Event(&end),
        ]);

        let stat = cells
            .iter()
            .find_map(|cell| match cell {
                Cell::DiffStat {
                    files,
                    additions,
                    deletions,
                    in_excerpt,
                } => Some((*files, *additions, *deletions, *in_excerpt)),
                _ => None,
            })
            .expect("a diffstat at the turn boundary");

        assert_eq!(stat, (2, 1, 1, false));
        assert!(plain(&render_cells(&cells, 100)).contains("2 files · +1 −1"));
    }

    /// A turn that changed nothing gets no diffstat rather than a row of zeroes.
    #[test]
    fn a_turn_that_changed_nothing_draws_no_diffstat() {
        let said = event(1, "output_text_final", json!({"text": "nothing to do"}));
        let end = event(2, "turn_completed", json!({}));
        let cells = project(vec![Entry::Event(&said), Entry::Event(&end)]);

        assert!(!cells
            .iter()
            .any(|cell| matches!(cell, Cell::DiffStat { .. })));
    }

    /// An excerpted diff's counts are a floor, and every surface that prints one says so.
    #[test]
    fn an_excerpted_diff_marks_its_counts_in_excerpt_everywhere() {
        let update = event(
            1,
            "file_change",
            json!({
                "changes": [{
                    "path": "src/lex.rs",
                    "diff": {"_excerpt": PATCH, "bytes": 40_000}
                }]
            }),
        );
        let end = event(2, "turn_completed", json!({}));
        let cells = project(vec![Entry::Event(&update), Entry::Event(&end)]);
        let text = plain(&render_cells(&cells, 100));

        assert!(text.contains("in excerpt"), "{text}");
        assert!(
            text.contains("· in excerpt"),
            "the diffstat carries it too: {text}"
        );
    }

    /// A payload this client cannot read as a diff is shown anyway, marked as unread.
    #[test]
    fn a_diff_with_no_hunks_is_shown_verbatim_rather_than_dropped() {
        let update = change(1, "notes.md", "the model rewrote three paragraphs");
        let cells = project(vec![Entry::Event(&update)]);
        let text = plain(&render_cells(&cells, 100));

        assert!(text.contains("no hunks this client could read"), "{text}");
        assert!(
            text.contains("the model rewrote three paragraphs"),
            "{text}"
        );
    }

    // ---------------------------------------------------------------------------------
    // A1 — `/raw`, Codex's copy mode
    // ---------------------------------------------------------------------------------

    /// Every cell kind, drawn raw, with nothing a selection would have to survive.
    #[test]
    fn raw_draws_no_box_no_gutter_and_no_glyph_column_for_any_cell() {
        let events = vec![
            event(1, "input_accepted", json!({"text": "please look"})),
            event(2, "thinking_delta", json!({"text": "considering"})),
            event(
                3,
                "output_text_final",
                json!({"text": "here is what I found"}),
            ),
            call(
                4,
                json!({"call_id": "r", "name": "read", "input": {"path": "a.ex"}}),
            ),
            result(5, json!({"call_id": "r", "output": "one\ntwo"})),
            call(
                6,
                json!({"call_id": "b", "name": "bash", "input": {"cmd": "mix test"}}),
            ),
            result(7, json!({"call_id": "b", "output": "3 tests, 0 failures"})),
            event(8, "command_output_delta", json!({"text": "compiling\n"})),
            change(9, "src/lex.rs", PATCH),
            event(
                10,
                "plan_updated",
                json!({"steps": [{"content": "read", "status": "completed"}]}),
            ),
            event(11, "usage", json!({"total_tokens": 42})),
            event(12, "session_idle", json!({})),
            event(13, "turn_completed", json!({})),
        ];
        let cells = project(events.iter().map(Entry::Event).collect());

        // Every cell kind this projection can produce is present, so the assertion below is
        // about the renderer and not about one lucky fixture.
        for expected in [
            "Message",
            "Thinking",
            "Tool",
            "Exploration",
            "CommandOutput",
            "File",
            "Diff",
            "DiffStat",
            "Plan",
            "ChatNote",
            "Divider",
        ] {
            assert!(
                cells
                    .iter()
                    .any(|cell| format!("{cell:?}").starts_with(expected)),
                "the fixture never produced a {expected} cell: {cells:?}"
            );
        }

        let raw = render_cells_at(&cells, 80, 0, Verbosity::Raw);
        let text = plain(&raw);

        for glyph in [
            '┌', '┐', '└', '┘', '│', '├', '┤', '─', '▌', '◆', '◇', '•', '✓', '✗', '±', '›',
        ] {
            assert!(!text.contains(glyph), "raw kept {glyph:?}:\n{text}");
        }

        // A diff keeps its own `+`/`-`/space column — that is the file format, not this
        // app's gutter — but the line numbers this app adds are gone.
        assert!(
            text.lines()
                .any(|line| line == "-    let end = text.find('\\n');"),
            "raw kept a line-number gutter on a diff:\n{text}"
        );
        assert!(
            !text.contains("Read a.ex") || !text.contains("  Read a.ex"),
            "raw indented a grouped call:\n{text}"
        );

        // And the content survived.
        for expected in [
            "please look",
            "here is what I found",
            "Read a.ex",
            "Bash $ mix test",
            "3 tests, 0 failures",
            "compiling",
            "1 file · +1 −1",
        ] {
            assert!(text.contains(expected), "raw lost {expected:?}:\n{text}");
        }
    }

    /// Raw does not wrap: one logical line stays one row, so the terminal owns the fold.
    #[test]
    fn raw_puts_one_logical_line_on_one_row_at_any_width() {
        let long = "a sentence that is a great deal wider than sixty columns of terminal, \
                    deliberately, so that any app-side wrapping would show up as two rows";
        let said = event(1, "output_text_final", json!({ "text": long }));
        let cells = project(vec![Entry::Event(&said)]);

        for width in [40usize, 60, 200] {
            let raw = render_cells_at(&cells, width, 0, Verbosity::Raw);
            let rows = raw
                .iter()
                .filter(|line| plain_line(line).contains("a sentence that is"))
                .count();

            assert_eq!(rows, 1, "raw wrapped at width {width}");
        }

        // Compact, by contrast, folds it to the measure.
        let compact = render_cells(&cells, 60);
        assert!(
            compact
                .iter()
                .filter(|line| !plain_line(line).trim().is_empty())
                .count()
                > 2,
            "the ordinary renderer wraps"
        );
    }

    /// Raw shows everything, because a copying view that folded half the transcript away
    /// would not be one.
    #[test]
    fn raw_expands_what_compact_collapses() {
        let call = call(
            1,
            json!({"call_id": "b", "name": "bash", "input": {"cmd": "ls"}}),
        );
        let body: String = (0..40).map(|n| format!("row {n}\n")).collect();
        let result = result(2, json!({"call_id": "b", "output": body}));
        let cells = project(vec![Entry::Event(&call), Entry::Event(&result)]);

        let raw = plain(&render_cells_at(&cells, 80, 0, Verbosity::Raw));
        assert!(raw.contains("row 20"), "the middle is there: {raw}");
        assert!(
            !raw.contains("ctrl+o"),
            "and no marker says otherwise: {raw}"
        );
    }

    // ---------------------------------------------------------------------------------
    // A4 — the `/diff` overlay's grouping
    // ---------------------------------------------------------------------------------

    #[test]
    fn changes_group_by_the_turn_dividers_the_transcript_already_drew() {
        let first = change(
            1,
            "a.rs",
            "--- a/a.rs\n+++ b/a.rs\n@@ -1,1 +1,2 @@\n keep\n+one\n",
        );
        let end_one = event(2, "turn_completed", json!({}));
        let second = change(
            3,
            "b.rs",
            "--- a/b.rs\n+++ b/b.rs\n@@ -1,1 +1,2 @@\n keep\n+two\n",
        );
        let again = change(
            4,
            "a.rs",
            "--- a/a.rs\n+++ b/a.rs\n@@ -9,1 +9,2 @@\n keep\n+three\n",
        );
        let end_two = event(5, "turn_completed", json!({}));

        let cells = project(vec![
            Entry::Event(&first),
            Entry::Event(&end_one),
            Entry::Event(&second),
            Entry::Event(&again),
            Entry::Event(&end_two),
        ]);
        let turns = super::super::diff::changes_by_turn(&cells);

        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].label(), "turn 1");
        assert_eq!(turns[1].label(), "turn 2");
        assert_eq!(
            turns[1]
                .files
                .iter()
                .map(|file| file.file.path.as_str())
                .collect::<Vec<_>>(),
            vec!["b.rs", "a.rs"]
        );

        // "This session" folds the same file's two turns into one row with summed counts.
        let overlay = super::super::diff::DiffOverlay::new(&cells, 0);
        let rows = overlay.rows();
        assert_eq!(rows.len(), 2, "a.rs once and b.rs once, not three rows");
        let a = rows
            .iter()
            .find(|row| row.file.path == "a.rs")
            .expect("a.rs is listed once");
        assert_eq!((a.file.additions, a.file.deletions), (2, 0));
    }

    /// A turn still running has its changes listed under the turn it belongs to.
    #[test]
    fn an_unfinished_turn_still_gets_a_scope_of_its_own() {
        let done = change(
            1,
            "a.rs",
            "--- a/a.rs\n+++ b/a.rs\n@@ -1,1 +1,2 @@\n keep\n+one\n",
        );
        let end = event(2, "turn_completed", json!({}));
        let live = change(
            3,
            "b.rs",
            "--- a/b.rs\n+++ b/b.rs\n@@ -1,1 +1,2 @@\n keep\n+two\n",
        );

        let cells = project(vec![
            Entry::Event(&done),
            Entry::Event(&end),
            Entry::Event(&live),
        ]);
        let overlay = super::super::diff::DiffOverlay::new(&cells, 0);

        assert_eq!(overlay.scopes(), 3, "this session, turn 1, turn 2");
        assert_eq!(overlay.turns[1].label(), "turn 2");
    }
}
