//! Declarative cells for the conversation-first transcript.
//!
//! Projection is deliberately one-way: normalized durable events become compact display
//! cells, but no decision made here is sent back to the runtime. Ctrl-O continues to show
//! every raw event when this best-effort presentation cannot recognize a newer payload.
//!
//! Chat layout is editorial rather than phone-like: both voices share one readable measure,
//! human intent is marked in amber, runtime output in cyan, and tool/command activity is
//! dimmer and more compact than either speaker.

use std::collections::BTreeMap;
use std::io::{self, Write};

use ratatui::layout::Alignment;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use serde_json::Value;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::model::transcript::{Diff, FileChange, PresentationEvent, ToolCall, ToolResult};

use super::code;
use super::theme;
use super::transcript::{Entry, Note};

const TOOL_OUTPUT_LINES: usize = 3;
const COMMAND_OUTPUT_LINES: usize = 4;
const DIFF_LINES: usize = 12;
const MESSAGE_LINES: usize = 256;
const STATUS_DETAIL_LINES: usize = 32;
const AGENT_OUTPUT_BYTES: usize = 128 * 1024;
const COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const TOOL_VALUE_BYTES: usize = 32 * 1024;
const TOOL_INPUT_BYTES: usize = 8 * 1024;
const AGENT_TRUNCATION: &str =
    "\n… agent stream truncated; full updates are available in event details";
const COMMAND_TRUNCATION: &str =
    "\n… command stream truncated; full updates are available in event details";
const TOOL_VALUE_TRUNCATION: &str =
    "\n… tool value truncated; full value is available in event details";
const TOOL_INPUT_TRUNCATION: &str = " … full input is available in event details";

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

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCell {
    pub call_id: Option<String>,
    pub name: String,
    pub input: Value,
    pub output: Option<Value>,
    pub state: ToolState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCell {
    pub path: Option<String>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Message {
        speaker: Speaker,
        text: String,
        streaming: bool,
    },
    Tool(ToolCell),
    CommandOutput(String),
    File(FileCell),
    Diff(Diff),
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
    Divider {
        text: String,
        tone: Tone,
    },
}

#[derive(Debug)]
struct PendingOutput {
    turn_id: Option<String>,
    text: String,
}

/// Projects one ordered durable transcript into display cells.
pub fn project(entries: Vec<Entry<'_>>) -> Vec<Cell> {
    let mut cells = Vec::new();
    let mut pending = None;
    let mut tools: BTreeMap<String, usize> = BTreeMap::new();
    let mut approvals: BTreeMap<String, usize> = BTreeMap::new();

    for entry in entries {
        match entry {
            Entry::Floor(_) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: "Earlier conversation is no longer available".into(),
                    tone: Tone::Warning,
                });
            }
            Entry::Gap { from, to } => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: format!("Restoring {} missing updates", to - from + 1),
                    tone: Tone::Warning,
                });
            }
            Entry::Note(note) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: chat_note(note).into(),
                    tone: Tone::Warning,
                });
            }
            Entry::Ended(status) => {
                flush_agent(&mut cells, &mut pending, false);
                cells.push(Cell::Divider {
                    text: format!("Session ended ({status})"),
                    tone: Tone::Muted,
                });
            }
            Entry::Event(event) => match PresentationEvent::from_event(event) {
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
                PresentationEvent::ToolCall(call) => {
                    flush_agent(&mut cells, &mut pending, false);
                    project_tool_call(&mut cells, &mut tools, call);
                }
                PresentationEvent::ToolResult(result) => {
                    flush_agent(&mut cells, &mut pending, false);
                    project_tool_result(&mut cells, &tools, result);
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
                        project_file(&mut cells, change, update.status.as_deref());
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
                        cells.push(Cell::Diff(diff));
                    }
                }
                PresentationEvent::ApprovalRequested { request_id, detail } => {
                    flush_agent(&mut cells, &mut pending, false);
                    let index = cells.len();
                    if let Some(request_id) = request_id {
                        approvals.insert(request_id, index);
                    }
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
                PresentationEvent::Ignore => {}
            },
        }
    }

    flush_agent(&mut cells, &mut pending, true);
    cells
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
    render_at(entries, width, 0)
}

pub fn render_at(entries: Vec<Entry<'_>>, width: usize, tick: u64) -> Vec<Line<'static>> {
    render_cells_at(&project(entries), width, tick)
}

pub fn render_cells(cells: &[Cell], width: usize) -> Vec<Line<'static>> {
    render_cells_at(cells, width, 0)
}

pub fn render_cells_at(cells: &[Cell], width: usize, tick: u64) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    for cell in cells {
        match cell {
            Cell::Message {
                speaker,
                text,
                streaming,
            } => render_message(&mut lines, *speaker, text, width, *streaming, tick),
            Cell::Tool(tool) => render_tool(&mut lines, tool, width, tick),
            Cell::CommandOutput(text) => render_command_output(&mut lines, text, width),
            Cell::File(file) => render_file(&mut lines, file, width),
            Cell::Diff(diff) => render_diff(&mut lines, diff, width),
            Cell::Status {
                label,
                detail,
                tone,
            } => render_status(&mut lines, label, detail, colour(*tone), width),
            Cell::ChatNote { text } => render_chat_note(&mut lines, text, width),
            Cell::Divider { text, tone } => lines.push(divider(text, width, colour(*tone))),
        }
    }

    lines
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

fn project_tool_call(cells: &mut Vec<Cell>, tools: &mut BTreeMap<String, usize>, call: ToolCall) {
    if let Some(call_id) = &call.call_id {
        if let Some(index) = tools.get(call_id).copied() {
            if let Some(Cell::Tool(tool)) = cells.get_mut(index) {
                // Some providers repeat the normalized call when publishing its result.
                // Refresh the descriptive fields but retain the row's lifecycle and output.
                tool.name = call.name;
                tool.input = call.input;
                return;
            }
        }

        tools.insert(call_id.clone(), cells.len());
    }

    cells.push(Cell::Tool(ToolCell {
        call_id: call.call_id,
        name: call.name,
        input: call.input,
        output: None,
        state: ToolState::Running,
    }));
}

fn project_tool_result(cells: &mut Vec<Cell>, tools: &BTreeMap<String, usize>, result: ToolResult) {
    let matched = result
        .call_id
        .as_ref()
        .and_then(|call_id| tools.get(call_id))
        .copied();

    if let Some(index) = matched {
        if let Some(Cell::Tool(tool)) = cells.get_mut(index) {
            if tool.name == "tool" {
                if let Some(name) = result.name {
                    tool.name = name;
                }
            }
            tool.state = if result.is_error {
                ToolState::Failed
            } else {
                ToolState::Completed
            };
            // Command-output deltas carry no call id, so their presence cannot prove that
            // this result is duplicate. Keep the correlated authoritative result visible;
            // hiding it because another parallel command streamed would lose evidence.
            if !result.output.is_null() {
                tool.output = Some(result.output);
            }
            return;
        }
    }

    cells.push(Cell::Tool(ToolCell {
        call_id: result.call_id,
        name: result.name.unwrap_or_else(|| "tool result".into()),
        input: Value::Object(Default::default()),
        output: (!result.output.is_null()).then_some(result.output),
        state: if result.is_error {
            ToolState::Failed
        } else {
            ToolState::Completed
        },
    }));
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

fn project_file(cells: &mut Vec<Cell>, change: FileChange, inherited_status: Option<&str>) {
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
        cells.push(Cell::Diff(diff));
    }
}

fn chat_note(note: &Note) -> &'static str {
    match note {
        Note::Lagged { .. } => "Some live updates were missed by the gateway",
        Note::ClientDropped => "Some live updates were missed by this client",
        Note::Reconnected => "Connection restored",
    }
}

fn render_message(
    lines: &mut Vec<Line<'static>>,
    speaker: Speaker,
    text: &str,
    width: usize,
    streaming: bool,
    tick: u64,
) {
    separate(lines);
    match speaker {
        Speaker::You => render_user_message(lines, text, width),
        Speaker::Agent => render_agent_message(lines, text, width, streaming, tick),
    }
}

fn render_user_message(lines: &mut Vec<Line<'static>>, text: &str, width: usize) {
    if width < 16 {
        lines.push(Line::from(vec![
            Span::styled("▌ ", theme::action()),
            Span::styled("YOU", theme::action()),
        ]));
        for line in wrap_limited(text, width.saturating_sub(2).max(8), MESSAGE_LINES) {
            lines.push(Line::from(Span::raw(line)));
        }
        return;
    }

    let border = Style::default().fg(theme::MUTED);
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
        MESSAGE_LINES.saturating_add(1),
    );
    let shown = wrapped.len().min(MESSAGE_LINES);

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
        let omitted = "… full message in event details";
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
) {
    lines.push(Line::from(vec![
        Span::styled("◆ ", Style::default().fg(theme::SYSTEM)),
        Span::styled(
            "AGENT",
            Style::default()
                .fg(theme::SYSTEM)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" / RESPONSE", Style::default().fg(theme::SYSTEM)),
    ]));

    let width = width.max(8);
    let segments = code::split_fences(text);
    let last = segments.len().saturating_sub(1);
    let mut body: Vec<Line<'static>> = Vec::new();
    let mut complete = true;

    // A segment needs room for its own frame plus this function's truncation notice;
    // starting one with less would overshoot the cap by more than it saves.
    for (index, segment) in segments.iter().enumerate() {
        if MESSAGE_LINES.saturating_sub(body.len()) < 4 {
            complete = false;
            break;
        }

        let remaining = MESSAGE_LINES.saturating_sub(body.len());

        match segment {
            code::Segment::Prose(prose) => {
                // The spare row is how wrap_limited reports that more prose followed.
                let wrapped = wrap_limited(prose, width, remaining.saturating_add(1));
                if wrapped.len() > remaining {
                    complete = false;
                }

                for line in wrapped.into_iter().take(remaining) {
                    body.push(Line::from(style_inline_code(&line)));
                }
            }
            code::Segment::Code(block) => {
                // While the agent is still writing this block its frame has no floor yet,
                // so the caret can sit on the newest code row instead of a bottom border.
                let open_tail = streaming && index == last && !block.closed;

                render_code_block(&mut body, block, width, remaining, open_tail);
            }
        }
    }

    lines.extend(body);

    if !complete {
        lines.push(Line::from(Span::styled(
            "… full message in event details",
            theme::quiet(),
        )));
    }

    if streaming {
        let caret = if tick % 8 < 5 { "▌" } else { " " };
        // A caret on a closed frame's floor reads as damage; only live content earns one.
        let on_live_content = lines
            .last()
            .and_then(|line| line.spans.first())
            .is_some_and(|span| !span.content.starts_with('└'));

        if on_live_content {
            if let Some(last_line) = lines.last_mut() {
                last_line
                    .spans
                    .push(Span::styled(caret, Style::default().fg(theme::ACCENT)));
            }
        }
    }
}

/// Lays out one fenced block inside a full-width frame with a language label:
///
/// ```text
/// ┌─ rust ───────────┐
/// │ fn main() {}     │
/// └──────────────────┘
/// ```
///
/// Grows `body` by at most `budget` rows: the header, up to `budget - 3` code rows, a
/// truncation notice when rows were cut, and the floor. An unfinished frame (`open_tail`)
/// omits its bottom border so streaming code can continue under the caret.
fn render_code_block(
    body: &mut Vec<Line<'static>>,
    block: &code::CodeBlock<'_>,
    width: usize,
    budget: usize,
    open_tail: bool,
) {
    let language = code::detect(block.lang);
    let label = match block.lang {
        Some(_) => language.label(),
        None => "code",
    };
    let border = Style::default()
        .fg(theme::MUTED)
        .add_modifier(Modifier::DIM);
    let label_style = Style::default()
        .fg(theme::SYSTEM)
        .add_modifier(Modifier::BOLD);

    let heading = "┌─ ";
    let rule = width
        .saturating_sub(heading.width() + label.width() + 2)
        .max(1);
    body.push(Line::from(vec![
        Span::styled(heading, border),
        Span::styled(label, label_style),
        Span::styled(format!(" {}┐", "─".repeat(rule)), border),
    ]));

    // Header, floor, and a possible notice come out of the same budget as the code.
    let rows_budget = budget.saturating_sub(3).max(1);
    // One row of look-ahead distinguishes "exactly filled" from "cut short", so a block
    // that precisely fits never earns a false truncation notice.
    let highlighted = code::highlight(
        block.code,
        language,
        width.saturating_sub(4).max(8),
        rows_budget.saturating_add(1),
    );
    let complete = highlighted.len() <= rows_budget;

    for line in highlighted.into_iter().take(rows_budget) {
        body.push(framed_row(line.spans, width, border));
    }

    if !complete && !open_tail {
        body.push(framed_row(
            vec![Span::styled(
                "… rest of this block in event details",
                theme::quiet(),
            )],
            width,
            border,
        ));
    }

    if !open_tail {
        body.push(Line::from(Span::styled(
            format!("└{}┘", "─".repeat(width.saturating_sub(2))),
            border,
        )));
    }
}

/// One framed row: left rule, content padded to the pane's width, right rule.
fn framed_row(content: Vec<Span<'static>>, width: usize, border: Style) -> Line<'static> {
    let used: usize = content.iter().map(|span| span.content.width()).sum();

    let mut spans = Vec::with_capacity(content.len() + 2);
    spans.push(Span::styled("│ ", border));
    spans.extend(content);
    spans.push(Span::raw(
        " ".repeat(width.saturating_sub(used.saturating_add(4))),
    ));
    spans.push(Span::styled(" │", border));

    Line::from(spans)
}

/// Styles paired backticks inside one already-wrapped prose line. A pair split across two
/// wrapped rows stays literal rather than guessing where it closed.
fn style_inline_code(line: &str) -> Vec<Span<'static>> {
    let Some(open) = line.find('`') else {
        return vec![Span::raw(line.to_string())];
    };

    let Some(close) = line[open + 1..].find('`').map(|offset| open + 1 + offset) else {
        return vec![Span::raw(line.to_string())];
    };

    let mut spans = Vec::with_capacity(3);
    if open > 0 {
        spans.push(Span::raw(line[..open].to_string()));
    }
    spans.push(Span::styled(
        line[open..=close].to_string(),
        Style::default().fg(theme::SYSTEM),
    ));
    if close + 1 < line.len() {
        spans.push(Span::raw(line[close + 1..].to_string()));
    }
    spans
}

fn render_tool(lines: &mut Vec<Line<'static>>, tool: &ToolCell, width: usize, tick: u64) {
    separate(lines);

    let (mark, mark_style) = match tool.state {
        ToolState::Running => (
            theme::spinner(tick).to_string(),
            Style::default().fg(theme::ACCENT),
        ),
        ToolState::Completed => ("✓".to_string(), Style::default().fg(theme::GOOD)),
        ToolState::Failed => ("✗".to_string(), Style::default().fg(theme::BAD)),
    };
    let name_style = match tool.state {
        ToolState::Failed => Style::default().fg(theme::BAD),
        _ => Style::default(),
    };
    let input = tool_input(&tool.name, &tool.input);
    let state_suffix = match tool.state {
        ToolState::Running => "  running",
        ToolState::Failed => "  failed",
        ToolState::Completed => "",
    };
    let display_name = display_tool_name(&tool.name);
    let reserved = mark.width() + display_name.width() + state_suffix.width() + 3;
    let shown_input = super::tree::truncate(
        &input.replace('\n', " "),
        width.saturating_sub(4).saturating_sub(reserved),
    );
    let mut head = vec![
        Span::styled(format!("{mark} "), mark_style),
        Span::styled(display_name, name_style),
    ];

    if !shown_input.is_empty() {
        head.push(Span::raw("  "));
        head.push(Span::styled(shown_input, theme::quiet()));
    }

    match tool.state {
        ToolState::Running => head.push(Span::styled("  running", theme::quiet())),
        ToolState::Failed => {
            head.push(Span::styled("  failed", Style::default().fg(theme::BAD)));
        }
        ToolState::Completed => {}
    }

    if width < 24 {
        lines.push(Line::from(head));
        if let Some(output) = &tool.output {
            let output = value_text(output);
            if !output.trim().is_empty() {
                render_excerpt(
                    lines,
                    &output,
                    width,
                    TOOL_OUTPUT_LINES,
                    "full result in event details",
                    if tool.state == ToolState::Failed {
                        Style::default().fg(theme::BAD)
                    } else {
                        theme::quiet()
                    },
                );
            }
        }
        return;
    }

    let border = match tool.state {
        ToolState::Running => Style::default().fg(theme::SYSTEM),
        ToolState::Completed => Style::default().fg(theme::GOOD),
        ToolState::Failed => Style::default().fg(theme::BAD),
    };
    lines.push(Line::from(Span::styled(
        format!("┌{}┐", "─".repeat(width.saturating_sub(2))),
        border,
    )));
    lines.push(boxed_tool_row(head, width, border));

    if let Some(output) = &tool.output {
        let output = value_text(output);
        if !output.trim().is_empty() {
            let body = match tool.state {
                ToolState::Failed => Style::default().fg(theme::BAD),
                _ => theme::quiet(),
            };
            let content_width = width.saturating_sub(4).max(8);
            let wrapped = wrap_limited(&output, content_width, 2);
            if let Some(first) = wrapped.first() {
                lines.push(boxed_tool_row(
                    vec![Span::styled(first.clone(), body)],
                    width,
                    border,
                ));
            }
            if wrapped.len() > 1 {
                lines.push(boxed_tool_row(
                    vec![Span::styled(
                        super::tree::truncate("… full result in event details", content_width),
                        theme::quiet(),
                    )],
                    width,
                    border,
                ));
            }
        }
    }
    lines.push(Line::from(Span::styled(
        format!("└{}┘", "─".repeat(width.saturating_sub(2))),
        border,
    )));
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

fn render_command_output(lines: &mut Vec<Line<'static>>, text: &str, width: usize) {
    if text.trim().is_empty() {
        return;
    }

    render_excerpt(
        lines,
        text,
        width,
        COMMAND_OUTPUT_LINES,
        "full command output in event details",
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

fn render_diff(lines: &mut Vec<Line<'static>>, diff: &Diff, width: usize) {
    let path = diff.path.as_deref().unwrap_or("changes");
    let path = super::tree::truncate(path, width.saturating_sub(24).max(8));
    let mut heading = vec![
        Span::raw("  "),
        Span::styled("Diff  ", theme::quiet()),
        Span::styled(path, theme::quiet()),
        Span::styled(
            format!("  +{}", diff.additions),
            Style::default().fg(theme::GOOD).add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!(" -{}", diff.deletions),
            Style::default().fg(theme::BAD).add_modifier(Modifier::DIM),
        ),
    ];
    if diff.truncated {
        heading.push(Span::styled("  in excerpt", theme::quiet()));
    }
    lines.push(Line::from(heading));

    let mut source = diff.text.lines();
    let mut shown = 0;
    while shown < DIFF_LINES {
        let Some(line) = source.next() else {
            break;
        };
        shown += 1;
        let style = if line.starts_with('+') && !line.starts_with("+++") {
            Style::default().fg(theme::GOOD).add_modifier(Modifier::DIM)
        } else if line.starts_with('-') && !line.starts_with("---") {
            Style::default().fg(theme::BAD).add_modifier(Modifier::DIM)
        } else if line.starts_with("@@") {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::DIM)
        } else {
            theme::quiet()
        };
        lines.push(Line::from(vec![
            Span::styled("    ", theme::quiet()),
            Span::styled(
                super::tree::truncate(line, width.saturating_sub(6).max(8)),
                style,
            ),
        ]));
    }

    // Looking one row ahead is enough to know whether this excerpt omitted anything. Do not
    // collect or count the rest of a large diff merely to draw twelve rows of it.
    if source.next().is_some() {
        lines.push(Line::from(vec![
            Span::styled("    ", theme::quiet()),
            Span::styled("… full diff in event details", theme::quiet()),
        ]));
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
        STATUS_DETAIL_LINES,
        "full status in event details",
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
            Span::styled(format!("… {omitted}"), Style::default().fg(theme::MUTED)),
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
        if let Some(text) = input.get(*key).and_then(Value::as_str) {
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
    matches!(
        name.to_ascii_lowercase().as_str(),
        "bash" | "shell" | "exec" | "exec_command" | "run_command"
    )
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
        ("A", theme::GOOD)
    } else if kind.contains("delet") || kind.contains("remov") {
        ("D", theme::BAD)
    } else if kind.contains("renam") || kind.contains("mov") {
        ("R", theme::ACCENT)
    } else {
        ("M", theme::WARN)
    }
}

fn colour(tone: Tone) -> Color {
    match tone {
        Tone::Muted => theme::MUTED,
        Tone::Success => theme::GOOD,
        Tone::Warning => theme::WARN,
        Tone::Error => theme::BAD,
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

fn wrap_limited(text: &str, width: usize, max_lines: usize) -> Vec<String> {
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
            json!({"call_id": "c1", "name": "read", "input": {"path": "README.md"}}),
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
        assert!(text.contains("✓ read"), "{text}");
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
        assert!(text.contains("Diff  lib/worker.ex  +1 -1"), "{text}");
        assert!(text.contains("-old"), "{text}");
        assert!(text.contains("+new"), "{text}");
    }

    #[test]
    fn a_running_tool_uses_the_working_spinner() {
        let call = event(
            1,
            "tool_call",
            json!({"call_id": "c-run", "name": "read", "input": {"path": "Cargo.toml"}}),
        );
        let cells = project(vec![Entry::Event(&call)]);
        let text = plain(&render_cells_at(&cells, 80, 0));

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

        let text = plain(&render_cells_at(&cells, 80, 0));
        assert!(text.contains("Hello▌"), "{text}");

        let hidden = plain(&render_cells_at(&cells, 80, 6));
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
        });

        let mut cells = project(vec![Entry::Event(&delta), Entry::Event(&final_text)]);
        cells.push(tool);
        let text = plain(&render_cells(&cells, 80));

        assert_eq!(text.matches("Hello there").count(), 1, "{text}");
        assert!(text.contains("full result in event details"), "{text}");
        assert!(
            !text.contains("line 19"),
            "verbose output escaped its cell: {text}"
        );
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
        });

        let value = match &tool {
            Cell::Tool(tool) => value_text(tool.output.as_ref().expect("output")),
            _ => unreachable!(),
        };
        assert!(value.len() <= TOOL_VALUE_BYTES);
        assert!(value.ends_with(TOOL_VALUE_TRUNCATION));

        let rendered = render_cells(&[tool], 40);
        assert!(rendered.len() <= TOOL_OUTPUT_LINES + 2);
        assert!(plain(&rendered).contains("full result in event details"));
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
        assert!(plain(&rendered).contains("full message in event details"));

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
        assert!(plain(&rendered).contains("full status in event details"));
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
        assert_eq!(keyword.style.fg, Some(ratatui::style::Color::Magenta));
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
        assert_eq!(code.style.fg, Some(theme::SYSTEM));
    }

    #[test]
    fn a_streaming_block_has_no_floor_and_carries_the_caret() {
        let cells = vec![Cell::Message {
            speaker: Speaker::Agent,
            text: "Working:\n```python\nprint('hi')\n".into(),
            streaming: true,
        }];

        let lines = render_cells_at(&cells, 60, 0);
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
            }),
        ];
        let lines = render_cells(&cells, 80);
        let text = plain(&lines);

        assert!(text.contains("I'll run the suite."), "{text}");
        assert!(text.contains("✓ command"), "{text}");
        assert!(text.contains("mix test"), "{text}");
        assert!(text.contains("3 tests, 0 failures"), "{text}");
        assert!(!text.contains("Run  "), "{text}");
        assert!(!text.contains("  done"), "{text}");
        assert!(text.contains('┌') && text.contains('└'), "{text}");

        let command = lines
            .iter()
            .find(|line| plain_line(line).contains("✓ command"))
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
}
