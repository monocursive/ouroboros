//! The coding home, a conversation-first transcript, and its complete event-details view.
//!
//! The transcript is assembled from `replay` plus the live subscription and nothing else —
//! it is never polled. The default view projects those events into user and agent messages;
//! `Ctrl-E` reveals the normalized ledger. Stream interruptions remain visible in both views:
//! a reader who cannot see a hole reads a partial transcript as a complete one.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::{Event, EventType, Plane};

use super::app::{App, Pane};
use super::logo::{self, Treatment};
use super::theme;
use super::transcript::{Entry, Note, Watch};
use super::view::{pane, panel_title};

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
        7
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
    let rows = Layout::vertical([Constraint::Min(5), Constraint::Length(7)]).split(area);
    let connected = app.chatgpt_connected();

    let message = if connected {
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
                "The agent starts in the current folder. Runtime and distribution stay in ctrl+p.",
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
                "Press Enter to open the supported Codex sign-in flow.",
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

    home_composer(frame, rows[1], app, connected);
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
        if !lines.is_empty() {
            lines.push(Line::from(""));
        }
        lines.extend(logo::lines(Treatment::Loading { tick: app.ticks }));
        lines.push(
            Line::from(Span::styled(
                "waiting for agent reply",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ))
            .alignment(ratatui::layout::Alignment::Center),
        );
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

#[derive(Debug)]
struct PendingOutput {
    turn_id: Option<String>,
    text: String,
}

fn chat_lines(entries: Vec<Entry<'_>>, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut pending: Option<PendingOutput> = None;

    for entry in entries {
        match entry {
            Entry::Floor(_) => {
                flush_pending(&mut lines, &mut pending, width);
                lines.push(divider(
                    "Earlier conversation is no longer available",
                    width,
                    theme::WARN,
                ));
            }
            Entry::Gap { from, to } => {
                flush_pending(&mut lines, &mut pending, width);
                lines.push(divider(
                    &format!("Restoring {} missing updates", to - from + 1),
                    width,
                    theme::WARN,
                ));
            }
            Entry::Note(note) => {
                flush_pending(&mut lines, &mut pending, width);
                lines.push(divider(chat_note(note), width, theme::WARN));
            }
            Entry::Ended(status) => {
                flush_pending(&mut lines, &mut pending, width);
                lines.push(divider(
                    &format!("Session ended ({status})"),
                    width,
                    theme::MUTED,
                ));
            }
            Entry::Event(event) => push_chat_event(&mut lines, &mut pending, event, width),
        }
    }

    flush_pending(&mut lines, &mut pending, width);
    lines
}

fn chat_note(note: &Note) -> &'static str {
    match note {
        Note::Lagged { .. } => "Some live updates were missed by the gateway",
        Note::ClientDropped => "Some live updates were missed by this client",
        Note::Reconnected => "Connection restored",
    }
}

fn push_chat_event(
    lines: &mut Vec<Line<'static>>,
    pending: &mut Option<PendingOutput>,
    event: &Event,
    width: usize,
) {
    match event.kind {
        EventType::InputAccepted => {
            flush_pending(lines, pending, width);

            if let Some(text) = event
                .payload
                .get("text")
                .and_then(serde_json::Value::as_str)
            {
                if !text.trim().is_empty() {
                    push_message(lines, "You", text, theme::ACCENT, width);
                }
            }
        }
        EventType::OutputTextDelta => {
            let Some(text) = event
                .payload
                .get("text")
                .and_then(serde_json::Value::as_str)
            else {
                return;
            };

            if text.is_empty() {
                return;
            }

            let same_turn = pending
                .as_ref()
                .map(|draft| {
                    draft.turn_id == event.turn_id
                        || draft.turn_id.is_none()
                        || event.turn_id.is_none()
                })
                .unwrap_or(true);

            if !same_turn {
                flush_pending(lines, pending, width);
            }

            let draft = pending.get_or_insert_with(|| PendingOutput {
                turn_id: event.turn_id.clone(),
                text: String::new(),
            });
            draft.text.push_str(text);
        }
        EventType::OutputTextFinal => {
            let final_text = event
                .payload
                .get("text")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            let same_turn = pending
                .as_ref()
                .map(|draft| {
                    draft.turn_id == event.turn_id
                        || draft.turn_id.is_none()
                        || event.turn_id.is_none()
                })
                .unwrap_or(false);

            let fallback = if same_turn {
                pending.take().map(|draft| draft.text)
            } else {
                flush_pending(lines, pending, width);
                None
            };
            let text = if final_text.is_empty() {
                fallback.as_deref().unwrap_or("")
            } else {
                final_text
            };

            if !text.trim().is_empty() {
                push_message(lines, "Agent", text, theme::GOOD, width);
            }
        }
        EventType::ApprovalRequested => {
            flush_pending(lines, pending, width);
            push_status(
                lines,
                "Approval needed",
                &event.summary(),
                theme::WARN,
                width,
            );
        }
        EventType::RunFailed | EventType::SessionFailed | EventType::TurnFailed => {
            flush_pending(lines, pending, width);
            push_status(lines, "Agent error", &event.summary(), theme::BAD, width);
        }
        EventType::RunCancelled | EventType::SessionCancelled | EventType::TurnInterrupted => {
            flush_pending(lines, pending, width);
            push_status(lines, "Interrupted", &event.summary(), theme::WARN, width);
        }
        // Lifecycle, usage, reasoning, provider stderr, tools, and bookkeeping remain in
        // Event details. They are still retained and can be inspected with Ctrl-E.
        _ => {}
    }
}

fn flush_pending(
    lines: &mut Vec<Line<'static>>,
    pending: &mut Option<PendingOutput>,
    width: usize,
) {
    let Some(draft) = pending.take() else {
        return;
    };

    if !draft.text.trim().is_empty() {
        push_message(lines, "Agent", &draft.text, theme::GOOD, width);
    }
}

fn push_message(
    lines: &mut Vec<Line<'static>>,
    author: &str,
    text: &str,
    colour: ratatui::style::Color,
    width: usize,
) {
    separate(lines);
    lines.push(Line::from(Span::styled(
        author.to_string(),
        Style::default().fg(colour).add_modifier(Modifier::BOLD),
    )));

    for line in wrap(text, width.saturating_sub(2).max(8)) {
        lines.push(Line::from(vec![Span::raw("  "), Span::raw(line)]));
    }
}

fn push_status(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    detail: &str,
    colour: ratatui::style::Color,
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

    for line in wrap(detail, width.saturating_sub(2).max(8)) {
        lines.push(Line::from(vec![Span::raw("  "), Span::raw(line)]));
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
    let rule = width.saturating_sub(text.chars().count() + 6);

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
            } else if current.chars().count() + 1 + word.chars().count() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(std::mem::take(&mut current));
                current.push_str(word);
            }

            // A single word longer than the pane is cut rather than allowed to overflow.
            while current.chars().count() > width {
                let head: String = current.chars().take(width).collect();
                let tail: String = current.chars().skip(width).collect();
                lines.push(head);
                current = tail;
            }
        }

        lines.push(current);
    }

    lines
}

fn composer(frame: &mut Frame, area: Rect, app: &App) {
    let active = app.sessions.composer.as_ref();
    let (verb, buffer) = active
        .map(|composer| (composer.verb.title(), composer.buffer.as_str()))
        .unwrap_or(("message", ""));
    let permission = app
        .config
        .defaults
        .approval_mode()
        .map(|mode| mode.as_str())
        .unwrap_or("ask");

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
            Span::raw("Codex"),
            Span::raw("   "),
            Span::styled(" PERMISSIONS ", theme::label()),
            Span::styled(permission.to_string(), Style::default().fg(theme::WARN)),
            Span::styled(format!("   {verb}"), Style::default().fg(theme::MUTED)),
        ]));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([Constraint::Min(2), Constraint::Length(1)]).split(inner);
    let content = if active.is_none() {
        Line::from(Span::styled(
            "Press i to write a follow-up",
            Style::default().fg(theme::MUTED),
        ))
    } else if buffer.is_empty() {
        Line::from(vec![
            Span::styled("▌ ", Style::default().fg(theme::ACCENT)),
            Span::styled(
                "Ask a follow-up or request edits…",
                Style::default().fg(theme::MUTED),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("▌ ", Style::default().fg(theme::ACCENT)),
            Span::raw(buffer.to_string()),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ])
    };

    frame.render_widget(Paragraph::new(content).wrap(Wrap { trim: false }), rows[0]);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "@ mention   / commands   ctrl+p menu",
                Style::default().fg(theme::MUTED),
            ),
            Span::styled(
                "                                      Enter sends",
                Style::default().fg(theme::ACCENT),
            ),
        ])),
        rows[1],
    );
}

fn home_composer(frame: &mut Frame, area: Rect, app: &App, connected: bool) {
    let permission = app
        .config
        .defaults
        .approval_mode()
        .map(|mode| mode.as_str())
        .unwrap_or("ask");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if connected {
            theme::ACCENT
        } else {
            theme::MUTED
        }))
        .title(Line::from(vec![
            Span::styled(" MODE ", theme::label()),
            Span::styled("Build", Style::default().fg(theme::ACCENT)),
            Span::raw("   "),
            Span::styled(" PROVIDER ", theme::label()),
            Span::raw("Codex"),
            Span::raw("   "),
            Span::styled(" PERMISSIONS ", theme::label()),
            Span::styled(permission.to_string(), Style::default().fg(theme::WARN)),
        ]));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([Constraint::Min(2), Constraint::Length(1)]).split(inner);

    let input = if app.home_pending {
        Line::from(Span::styled(
            format!("{} starting the agent…", theme::spinner(app.ticks)),
            Style::default().fg(theme::ACCENT),
        ))
    } else if !connected {
        Line::from(Span::styled(
            "Press Enter to connect ChatGPT",
            Style::default().fg(theme::MUTED),
        ))
    } else if app.home_draft.is_empty() {
        Line::from(vec![
            Span::styled("▌ ", Style::default().fg(theme::ACCENT)),
            Span::styled(
                "Ask the agent to build, fix, explain, or review…",
                Style::default().fg(theme::MUTED),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("▌ ", Style::default().fg(theme::ACCENT)),
            Span::raw(app.home_draft.clone()),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ])
    };
    frame.render_widget(Paragraph::new(input).wrap(Wrap { trim: false }), rows[0]);

    let footer = if let Some(error) = &app.home_error {
        Line::from(Span::styled(
            super::tree::truncate(error, inner.width.saturating_sub(1) as usize),
            Style::default().fg(theme::BAD),
        ))
    } else {
        Line::from(vec![
            Span::styled(
                "@ mention   / commands   ctrl+p menu",
                Style::default().fg(theme::MUTED),
            ),
            Span::styled(
                if connected {
                    "                                      Enter starts"
                } else {
                    "                                      Enter connects"
                },
                Style::default().fg(theme::ACCENT),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(footer), rows[1]);
}
