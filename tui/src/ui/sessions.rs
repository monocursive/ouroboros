//! Tab 2: both planes' sessions in one list, and the focused one's transcript.
//!
//! The transcript is assembled from `replay` plus the live subscription and nothing else —
//! it is never polled. Every interruption in it is drawn as a divider rather than closed
//! over: a pruned floor, a hole waiting for a replay, a lag the gateway reported, a lag
//! this client caused, and the end of the stream all have a line of their own. A reader
//! who cannot see the hole reads a partial transcript as a complete one, which is the
//! failure this whole slice is built to avoid.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::{Event, EventType, Plane, SessionInfo};

use super::app::{App, Pane};
use super::theme;
use super::transcript::{Entry, Watch};
use super::view::{pane, panel_title};

pub fn draw(frame: &mut Frame, area: Rect, app: &mut App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(area);

    list(frame, columns[0], app);
    detail(frame, columns[1], app);
}

fn list(frame: &mut Frame, area: Rect, app: &App) {
    let pending = app.sessions.interactive.pending || app.sessions.coding.pending;
    let error = app
        .sessions
        .interactive
        .error
        .as_ref()
        .or(app.sessions.coding.error.as_ref());

    let block = pane(
        panel_title("sessions", pending, error, app.ticks),
        app.sessions.focus == Pane::List,
    );

    let sessions = app.sessions.merged();

    if sessions.is_empty() {
        let message = if app.sessions.interactive.value.is_some() {
            "no interactive sessions and no coding tasks on this node"
        } else {
            "listing sessions"
        };

        frame.render_widget(
            Paragraph::new(Span::styled(message, Style::default().fg(theme::MUTED)))
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );

        return;
    }

    let items: Vec<ListItem> = sessions.iter().map(|session| row(session, app)).collect();

    let mut state = ListState::default().with_selected(Some(app.sessions.selected));

    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(if app.sessions.focus == Pane::List {
                theme::selected()
            } else {
                theme::selected_unfocused()
            }),
        area,
        &mut state,
    );
}

fn row(session: &SessionInfo, app: &App) -> ListItem<'static> {
    let watched = app
        .sessions
        .watches
        .contains_key(&(session.plane, session.id.clone()));

    let approvals = app
        .sessions
        .watches
        .get(&(session.plane, session.id.clone()))
        .and_then(Watch::next_approval)
        .is_some();

    let mut spans = vec![
        Span::styled(
            format!("{:<5}", session.plane.tag()),
            Style::default().fg(theme::MUTED),
        ),
        Span::raw(super::tree::truncate(&session.id, 28)),
    ];

    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        session.status.as_str().to_string(),
        theme::session_status(&session.status),
    ));

    if approvals {
        spans.push(Span::styled(
            "  [approval]",
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
    } else if watched {
        spans.push(Span::styled("  •", Style::default().fg(theme::ACCENT)));
    }

    ListItem::new(Line::from(spans))
}

fn detail(frame: &mut Frame, area: Rect, app: &mut App) {
    let composer_height = if app.sessions.composer.is_some() {
        3
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

fn transcript(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.sessions.focus == Pane::Detail;

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

    let block = pane(header(watch, &id, plane, app.ticks), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = inner.width.max(8) as usize;
    let mut lines: Vec<Line> = Vec::new();

    for entry in watch.entries() {
        push(&mut lines, entry, width);
    }

    if lines.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "no events retained for this session",
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

fn header(watch: &Watch, id: &str, plane: Plane, tick: u64) -> Line<'static> {
    let mut spans = vec![
        Span::styled(format!(" {plane} "), theme::heading()),
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

    if watch.resyncing {
        spans.push(Span::styled(
            format!("replaying {} ", theme::spinner(tick)),
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

    Line::from(spans)
}

fn push(lines: &mut Vec<Line<'static>>, entry: Entry<'_>, width: usize) {
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
    let Some(composer) = &app.sessions.composer else {
        return;
    };

    let block = pane(
        Line::from(vec![
            Span::styled(format!(" {} ", composer.verb.title()), theme::heading()),
            Span::styled(
                "Enter sends, Esc cancels ",
                Style::default().fg(theme::MUTED),
            ),
        ]),
        true,
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(composer.buffer.clone()),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ]))
        .block(block)
        .wrap(Wrap { trim: false }),
        area,
    );
}
