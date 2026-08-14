//! The coding home, a conversation-first transcript, and its complete event-details view.
//!
//! The transcript is assembled from `replay` plus the live subscription and nothing else —
//! it is never polled. The default view projects those events into messages and compact
//! tool/file/diff cells; `Ctrl-E` reveals the normalized ledger. Stream interruptions remain
//! visible in both views: a reader who cannot see a hole reads a partial transcript as a
//! complete one.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::model::{Event, EventType, Plane, SessionInfo};

use super::app::{App, Pane};
use super::editor::{CompletionKind, Editor};
use super::logo::{self, Treatment};
use super::theme;
use super::transcript::{Entry, Watch};
use super::transcript_cells;
use super::view::{pane, panel_title};

// Projection is rebuilt on every draw, so bound the default conversation surface to a
// useful recent suffix. The complete retained ledger remains available through Ctrl-E.
const CHAT_ENTRY_WINDOW: usize = 128;

pub fn draw(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.sessions.open.is_none() {
        home(frame, area, app);
    } else {
        detail(frame, area, app);
    }
}

fn detail(frame: &mut Frame, area: Rect, app: &mut App) {
    let composer_height = if app
        .sessions
        .open
        .as_ref()
        .map(|(plane, _id)| *plane == Plane::Interactive)
        .unwrap_or(false)
    {
        7 + completion_height(
            app.sessions
                .composer
                .as_ref()
                .map(|composer| &composer.editor),
        )
    } else {
        0
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(composer_height)])
        .split(area);

    transcript(frame, rows[0], app);

    if composer_height > 0 {
        composer(frame, rows[1], app);
    }
}

fn home(frame: &mut Frame, area: Rect, app: &App) {
    let composer_height = 7 + completion_height(Some(&app.home_draft));
    let rows =
        Layout::vertical([Constraint::Min(5), Constraint::Length(composer_height)]).split(area);
    let ready = app.home_ready();
    let requested_workspace = app.home_workspace();

    let message = if ready {
        vec![
            Line::from(Span::styled(
                "Ready in this workspace",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Describe the change, bug, or question below."),
            Line::from(Span::styled(
                if requested_workspace.is_empty() {
                    "Workspace is unstated; the runtime will choose its default. ctrl+p opens runtime details."
                        .to_string()
                } else if app.spawned() || app.config.defaults.workspace.is_some() {
                    format!(
                        "Requested workspace: {}. Runtime and distribution stay in ctrl+p.",
                        super::tree::truncate(&requested_workspace, 46)
                    )
                } else {
                    format!(
                        "Local cwd suggestion: {}. The attached runtime resolves this path.",
                        super::tree::truncate(&requested_workspace, 42)
                    )
                },
                Style::default().fg(theme::MUTED),
            )),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "Connect ChatGPT to start coding",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Use your existing ChatGPT subscription. No API key is required."),
            Line::from(Span::styled(
                "Press Enter to connect, or type / for commands without signing in.",
                Style::default().fg(theme::MUTED),
            )),
        ]
    };

    if rows[0].height > logo::HEIGHT + message.len() as u16 {
        let vertical = Layout::vertical([
            Constraint::Length(logo::HEIGHT),
            Constraint::Length(1),
            Constraint::Length(message.len() as u16),
        ])
        .flex(ratatui::layout::Flex::Center)
        .split(rows[0]);

        logo::draw(frame, vertical[0], Treatment::Static);
        frame.render_widget(
            Paragraph::new(message).alignment(ratatui::layout::Alignment::Center),
            vertical[2],
        );
    } else {
        let vertical = Layout::vertical([Constraint::Length(message.len() as u16)])
            .flex(ratatui::layout::Flex::Center)
            .split(rows[0]);
        frame.render_widget(
            Paragraph::new(message).alignment(ratatui::layout::Alignment::Center),
            vertical[0],
        );
    }

    home_composer(frame, rows[1], app, ready);
}

fn transcript(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.sessions.focus == Pane::Detail;
    let waiting_for_reply = app.waiting_for_open_agent_reply();

    let Some((plane, id)) = app.sessions.open.clone() else {
        let block = pane(panel_title("transcript", false, None, app.ticks), focused);

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "select a session and press Enter to replay its history and follow it live",
                    Style::default().fg(theme::MUTED),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "nothing is subscribed until you open it, so an unopened session costs the \
                     runtime nothing",
                    Style::default().fg(theme::MUTED),
                )),
            ])
            .block(block)
            .wrap(Wrap { trim: false }),
            area,
        );

        return;
    };

    let Some(watch) = app.sessions.watches.get(&(plane, id.clone())) else {
        return;
    };

    let show_event_details = app.sessions.show_event_details;
    let block = pane(
        header(watch, &id, plane, app.ticks, show_event_details),
        focused,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = inner.width.max(8) as usize;
    let entries = watch.entries();
    let mut lines = if show_event_details {
        event_lines(entries, width)
    } else {
        chat_lines(entries, width)
    };

    if !show_event_details && waiting_for_reply {
        push_typing_indicator(&mut lines, app.ticks);
    }

    if lines.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                if show_event_details {
                    "No events retained for this session."
                } else {
                    "No messages yet."
                },
                Style::default().fg(theme::MUTED),
            )),
            inner,
        );

        return;
    }

    let height = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(height);

    let scroll = if watch.follow {
        0
    } else {
        watch.scroll.min(max_scroll)
    };

    let start = max_scroll - scroll;
    let end = (start + height).min(lines.len());

    frame.render_widget(Paragraph::new(lines[start..end].to_vec()), inner);
}

fn header(
    watch: &Watch,
    id: &str,
    plane: Plane,
    tick: u64,
    show_event_details: bool,
) -> Line<'static> {
    if !show_event_details {
        let mut spans = vec![
            Span::styled(" Agent chat ", theme::heading()),
            Span::styled("ctrl+e details ", Style::default().fg(theme::MUTED)),
        ];

        push_stream_state(&mut spans, watch, tick, false);
        return Line::from(spans);
    }

    let mut spans = vec![
        Span::styled(" Event details ", theme::heading()),
        Span::styled("ctrl+e chat  ", Style::default().fg(theme::MUTED)),
        Span::styled(format!("{plane} "), Style::default().fg(theme::MUTED)),
        Span::raw(format!("{id} ")),
        Span::styled(
            format!("cursor {} ", watch.cursor()),
            Style::default().fg(theme::MUTED),
        ),
    ];

    if watch.floor() > 0 {
        spans.push(Span::styled(
            format!("floor {} ", watch.floor()),
            Style::default().fg(theme::WARN),
        ));
    }

    if watch.dropped > 0 {
        spans.push(Span::styled(
            format!("{} dropped ", watch.dropped),
            Style::default().fg(theme::WARN),
        ));
    }

    if watch.undecodable > 0 {
        spans.push(Span::styled(
            format!("{} undecodable ", watch.undecodable),
            Style::default().fg(theme::WARN),
        ));
    }

    push_stream_state(&mut spans, watch, tick, true);

    Line::from(spans)
}

fn push_stream_state(spans: &mut Vec<Span<'static>>, watch: &Watch, tick: u64, technical: bool) {
    if watch.resyncing {
        spans.push(Span::styled(
            format!(
                "{} {} ",
                if technical {
                    "replaying"
                } else {
                    "restoring history"
                },
                theme::spinner(tick)
            ),
            Style::default().fg(theme::ACCENT),
        ));
    }

    if let Some(status) = &watch.ended {
        spans.push(Span::styled(
            format!("ended: {status} "),
            Style::default().fg(theme::MUTED),
        ));
    } else if !watch.follow {
        spans.push(Span::styled(
            "scrolled back ",
            Style::default().fg(theme::MUTED),
        ));
    }
}

fn event_lines(entries: Vec<Entry<'_>>, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    for entry in entries {
        push_event_entry(&mut lines, entry, width);
    }

    lines
}

fn push_event_entry(lines: &mut Vec<Line<'static>>, entry: Entry<'_>, width: usize) {
    match entry {
        Entry::Floor(floor) => lines.push(divider(
            &format!("history truncated below {floor} — the runtime no longer retains it"),
            width,
            theme::WARN,
        )),
        Entry::Gap { from, to } => lines.push(divider(
            &format!(
                "{} events missing ({from}..{to}) — replaying",
                to - from + 1
            ),
            width,
            theme::WARN,
        )),
        Entry::Note(note) => lines.push(divider(&note.text(), width, theme::WARN)),
        Entry::Ended(status) => lines.push(divider(
            &format!("stream ended ({status}) — no further events"),
            width,
            theme::MUTED,
        )),
        Entry::Event(event) => push_event(lines, event, width),
    }
}

fn chat_lines(mut entries: Vec<Entry<'_>>, width: usize) -> Vec<Line<'static>> {
    let omitted = entries.len().saturating_sub(CHAT_ENTRY_WINDOW);
    let visible = if omitted == 0 {
        entries
    } else {
        entries.split_off(omitted)
    };
    let mut lines = transcript_cells::render(visible, width);

    if omitted == 0 {
        return lines;
    }

    let mut bounded = vec![
        divider(
            &format!(
                "{omitted} earlier chat entries omitted here — Ctrl-E shows all retained events"
            ),
            width,
            theme::WARN,
        ),
        Line::from(""),
    ];
    bounded.append(&mut lines);
    bounded
}

fn push_typing_indicator(lines: &mut Vec<Line<'static>>, tick: u64) {
    separate(lines);
    lines.push(Line::from(Span::styled(
        "Agent",
        Style::default()
            .fg(theme::GOOD)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(logo::typing_indicator(tick));
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

fn push_event(lines: &mut Vec<Line<'static>>, event: &Event, width: usize) {
    let prefix = format!("{:>6}  ", event.sequence);
    let kind = event.kind.as_str().to_string();
    let indent = " ".repeat(prefix.len());
    let body_width = width.saturating_sub(prefix.len()).max(8);

    let mut head = vec![
        Span::styled(prefix, Style::default().fg(theme::MUTED)),
        Span::styled(format!("{kind}  "), event_style(&event.kind)),
    ];

    let summary = event.summary();
    let mut wrapped = wrap(&summary, body_width.saturating_sub(kind.len() + 2).max(8));

    if let Some(first) = wrapped.first() {
        head.push(Span::raw(first.clone()));
    }

    lines.push(Line::from(head));

    if wrapped.len() > 1 {
        for rest in wrapped.drain(1..) {
            lines.push(Line::from(vec![Span::raw(indent.clone()), Span::raw(rest)]));
        }
    }
}

fn event_style(kind: &EventType) -> Style {
    match kind {
        EventType::ApprovalRequested => Style::default()
            .fg(theme::WARN)
            .add_modifier(Modifier::BOLD),
        EventType::RunFailed
        | EventType::SessionFailed
        | EventType::TurnFailed
        | EventType::RunCancelled
        | EventType::SessionCancelled
        | EventType::TurnInterrupted => Style::default().fg(theme::BAD),
        EventType::OutputTextFinal | EventType::OutputTextDelta => Style::default(),
        EventType::ThinkingDelta | EventType::Usage | EventType::QueueChanged => {
            Style::default().fg(theme::MUTED)
        }
        EventType::ToolCall | EventType::ToolResult | EventType::FileChange => {
            Style::default().fg(theme::ACCENT)
        }
        _ => Style::default().fg(theme::MUTED),
    }
}

fn divider(text: &str, width: usize, colour: ratatui::style::Color) -> Line<'static> {
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

/// Wrapping done here rather than by `Paragraph` so the scroll offset counts the same
/// lines the reader sees. A transcript whose scroll position is a guess is a transcript
/// that jumps.
///
/// Measured in terminal cells, like everything else this client lays out by hand: a line
/// of CJK counted by character is twice as wide as the pane it was measured for.
fn wrap(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }

    let mut lines = Vec::new();

    for source in text.split('\n') {
        let mut current = String::new();

        for word in source.split(' ') {
            if current.is_empty() {
                current.push_str(word);
            } else if current.width() + 1 + word.width() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(std::mem::take(&mut current));
                current.push_str(word);
            }

            // A single word wider than the pane is cut rather than allowed to overflow.
            while current.width() > width {
                let split = cell_split(&current, width);
                let tail = current.split_off(split);
                lines.push(std::mem::replace(&mut current, tail));
            }
        }

        lines.push(current);
    }

    lines
}

/// The byte offset at which `text` has occupied as many cells as will fit in `width`.
fn cell_split(text: &str, width: usize) -> usize {
    let mut used = 0;

    for (at, character) in text.char_indices() {
        let cells = character.width().unwrap_or(0);

        if used + cells > width {
            return at;
        }

        used += cells;
    }

    text.len()
}

fn composer(frame: &mut Frame, area: Rect, app: &App) {
    let active = app.sessions.composer.as_ref();
    let verb = active
        .map(|composer| composer.verb.title())
        .unwrap_or("message");
    let session = app.sessions.open_info();
    let provider = session
        .and_then(|session| session.provider.as_deref())
        .unwrap_or("agent");
    let approval = session_policy(session, "approval_mode");
    let sandbox = session_policy(session, "sandbox_mode");

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if active.is_some() {
            theme::ACCENT
        } else {
            theme::MUTED
        }))
        .title(Line::from(vec![
            Span::styled(" MODE ", theme::label()),
            Span::styled("Build", Style::default().fg(theme::ACCENT)),
            Span::raw("   "),
            Span::styled(" PROVIDER ", theme::label()),
            Span::raw(provider.to_string()),
            Span::raw("   "),
            Span::styled(" APPROVAL ", theme::label()),
            Span::styled(approval, Style::default().fg(theme::WARN)),
            Span::styled(" SANDBOX ", theme::label()),
            Span::styled(sandbox, Style::default().fg(theme::WARN)),
            Span::styled(format!("   {verb}"), Style::default().fg(theme::MUTED)),
        ]));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let completion_rows = active
        .and_then(|composer| composer.editor.completion())
        .map(|menu| menu.items.len().min(3) as u16)
        .unwrap_or(0);
    let rows = Layout::vertical([
        Constraint::Min(2),
        Constraint::Length(completion_rows),
        Constraint::Length(1),
    ])
    .split(inner);

    if let Some(composer) = active {
        render_editor(
            frame,
            rows[0],
            &composer.editor,
            "Ask a follow-up or request edits…",
        );
        render_completions(frame, rows[1], &composer.editor);
    } else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Press i to write a follow-up",
                Style::default().fg(theme::MUTED),
            ))),
            rows[0],
        );
    }

    let footer = if active
        .and_then(|composer| composer.editor.completion())
        .is_some()
    {
        "↑↓ choose · Tab complete · Esc close       Shift+Enter/Ctrl+J newline · Enter sends"
    } else {
        "@ paths · / commands · ↑ history          Shift+Enter/Ctrl+J newline · Enter sends"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            footer,
            Style::default().fg(theme::MUTED),
        ))),
        rows[2],
    );
}

fn session_policy(session: Option<&SessionInfo>, key: &str) -> String {
    let Some(value) = session
        .and_then(|session| session.raw.get("options"))
        .and_then(|options| options.get(key))
    else {
        return "unknown".to_string();
    };

    match value {
        serde_json::Value::Null => "provider default".to_string(),
        serde_json::Value::String(value) if !value.trim().is_empty() => value.clone(),
        other => super::tree::truncate(&crate::model::compact(other), 24),
    }
}

fn home_composer(frame: &mut Frame, area: Rect, app: &App, ready: bool) {
    let permission = app
        .config
        .defaults
        .approval_mode()
        .map(|mode| mode.as_str())
        .unwrap_or("ask");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if ready { theme::ACCENT } else { theme::MUTED }))
        .title(Line::from(vec![
            Span::styled(" MODE ", theme::label()),
            Span::styled("Build", Style::default().fg(theme::ACCENT)),
            Span::raw("   "),
            Span::styled(" PROVIDER ", theme::label()),
            Span::raw(app.home_provider().to_string()),
            Span::raw("   "),
            Span::styled(" REQUESTED APPROVAL ", theme::label()),
            Span::styled(permission.to_string(), Style::default().fg(theme::WARN)),
            Span::styled(" SANDBOX ", theme::label()),
            Span::styled("runtime default", Style::default().fg(theme::MUTED)),
        ]));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let completion_rows = app
        .home_draft
        .completion()
        .map(|menu| menu.items.len().min(3) as u16)
        .unwrap_or(0);
    let rows = Layout::vertical([
        Constraint::Min(2),
        Constraint::Length(completion_rows),
        Constraint::Length(1),
    ])
    .split(inner);

    if app.home_pending {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("{} starting the agent…", theme::spinner(app.ticks)),
                Style::default().fg(theme::ACCENT),
            ))),
            rows[0],
        );
    } else if ready || !app.home_draft.text().is_empty() {
        render_editor(
            frame,
            rows[0],
            &app.home_draft,
            "Ask the agent to build, fix, explain, or review…",
        );
        render_completions(frame, rows[1], &app.home_draft);
    } else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Type / for commands or press Enter to connect ChatGPT",
                Style::default().fg(theme::MUTED),
            ))),
            rows[0],
        );
    }

    let footer = if let Some(error) = &app.home_error {
        Line::from(Span::styled(
            super::tree::truncate(error, inner.width.saturating_sub(1) as usize),
            Style::default().fg(theme::BAD),
        ))
    } else if app.home_draft.completion().is_some() {
        Line::from(Span::styled(
            "↑↓ choose · Tab complete · Esc close       Shift+Enter/Ctrl+J newline · Enter starts",
            Style::default().fg(theme::MUTED),
        ))
    } else {
        Line::from(Span::styled(
            if ready {
                "@ paths · / commands · ↑ history          Shift+Enter/Ctrl+J newline · Enter starts"
            } else {
                "/ commands                                               Enter connects"
            },
            Style::default().fg(theme::MUTED),
        ))
    };
    frame.render_widget(Paragraph::new(footer), rows[2]);
}

fn completion_height(editor: Option<&Editor>) -> u16 {
    editor
        .and_then(Editor::completion)
        .map(|menu| menu.items.len().min(3) as u16)
        .unwrap_or(0)
}

fn render_editor(frame: &mut Frame, area: Rect, editor: &Editor, placeholder: &str) {
    if area.width < 3 || area.height == 0 {
        return;
    }

    if editor.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("▌ ", Style::default().fg(theme::ACCENT)),
                Span::styled(placeholder.to_string(), Style::default().fg(theme::MUTED)),
            ])),
            area,
        );
        frame.set_cursor_position((area.x.saturating_add(2), area.y));
        return;
    }

    let window = editor_window(
        editor.text(),
        editor.cursor(),
        area.width as usize,
        area.height as usize,
    );
    let lines = window
        .lines
        .into_iter()
        .enumerate()
        .map(|(offset, content)| {
            let prefix = if window.start + offset == 0 {
                "▌ "
            } else {
                "  "
            };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(theme::ACCENT)),
                Span::raw(content),
            ])
        })
        .collect::<Vec<_>>();

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    frame.set_cursor_position((
        area.x
            .saturating_add(2)
            .saturating_add(window.cursor_column as u16)
            .min(area.right().saturating_sub(1)),
        area.y
            .saturating_add(window.cursor_row as u16)
            .min(area.bottom().saturating_sub(1)),
    ));
}

fn render_completions(frame: &mut Frame, area: Rect, editor: &Editor) {
    let Some(menu) = editor.completion() else {
        return;
    };
    let count = area.height as usize;
    let start = menu
        .selected
        .saturating_sub(count.saturating_sub(1))
        .min(menu.items.len().saturating_sub(count));
    let lines = menu
        .items
        .iter()
        .enumerate()
        .skip(start)
        .take(count)
        .map(|(index, item)| {
            let marker = if item.kind == CompletionKind::Command {
                "command"
            } else {
                "file"
            };
            let text = format!("  {}  {:<8} {}", item.value, marker, item.detail);
            Line::from(Span::styled(
                super::tree::truncate(&text, area.width as usize),
                if index == menu.selected {
                    theme::selected()
                } else {
                    Style::default().fg(theme::MUTED)
                },
            ))
        })
        .collect::<Vec<_>>();

    frame.render_widget(Paragraph::new(lines), area);
}

struct EditorWindow {
    lines: Vec<String>,
    start: usize,
    cursor_row: usize,
    cursor_column: usize,
}

fn editor_window(text: &str, cursor: usize, width: usize, height: usize) -> EditorWindow {
    let content_width = width.saturating_sub(2).max(1);
    let mut lines = vec![String::new()];
    let mut row = 0;
    let mut column = 0;
    let mut cursor_position = None;

    for (at, character) in text.char_indices() {
        if at == cursor {
            cursor_position = Some((row, column));
        }

        if character == '\n' {
            row += 1;
            column = 0;
            lines.push(String::new());
            continue;
        }

        let rendered = if character == '\t' {
            " ".repeat(4 - column % 4)
        } else {
            character.to_string()
        };
        let cell_width = Line::from(rendered.clone()).width();

        if column > 0 && column + cell_width > content_width {
            row += 1;
            column = 0;
            lines.push(String::new());
        }

        lines[row].push_str(&rendered);
        column += cell_width;
    }

    let (cursor_row, cursor_column) = cursor_position.unwrap_or((row, column));
    let visible_height = height.max(1);
    let start = cursor_row.saturating_add(1).saturating_sub(visible_height);
    let lines = lines.into_iter().skip(start).take(visible_height).collect();

    EditorWindow {
        lines,
        start,
        cursor_row: cursor_row - start,
        cursor_column,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_projection_names_the_ledger_when_older_entries_are_bounded() {
        let entries = (0..=CHAT_ENTRY_WINDOW)
            .map(|_| Entry::Ended("closed"))
            .collect();

        let lines = chat_lines(entries, 160);

        assert!(
            lines[0]
                .to_string()
                .contains("1 earlier chat entries omitted here"),
            "{}",
            lines[0]
        );
        assert!(lines[0].to_string().contains("Ctrl-E"), "{}", lines[0]);
    }
}
