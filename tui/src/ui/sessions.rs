//! The coding home, a conversation-first transcript, and its complete event-details view.
//!
//! The transcript is assembled from `replay` plus the live subscription and nothing else —
//! it is never polled. The default view projects those events into messages and compact
//! tool/file/diff/thinking/plan cells; `Ctrl-O` redraws the same conversation with every
//! collapsible cell expanded, `Ctrl-T` opens the plan panel, and `/details` (or `ctrl+x d`)
//! reveals the normalized ledger. Stream interruptions remain visible in every view: a
//! reader who cannot see a hole reads a partial transcript as a complete one.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::model::{AttachmentKind, Event, EventType, Plane, SessionInfo, SessionStatus};

use super::app::{App, Composer, ComposerVerb, Connection};
use super::editor::{CompletionKind, Editor};
use super::logo::{self, Treatment};
use super::theme;
use super::transcript::{Entry, Watch};
use super::transcript_cells::{self, Verbosity};

// Projection is rebuilt on every draw, so bound the default conversation surface to a
// useful recent suffix. The complete retained ledger remains available through /details.
const CHAT_ENTRY_WINDOW: usize = 128;

/// Rows the plan panel may occupy above the composer, borders included. Past this it
/// scrolls to its own tail rather than eating the conversation.
const PLAN_PANEL_ROWS: u16 = 12;

/// How many local drafts the queue lists before it stops listing and starts counting.
///
/// The queue is a reminder of what is coming, not a second transcript: past a handful of
/// rows it is taking space from the conversation it is about.
const QUEUE_ROWS: u16 = 3;

/// Progressive disclosure keeps the conversation usable before it keeps the ornament.
/// The Figma workspace deliberately keeps all three surfaces on a tall, laptop-sized
/// terminal: the rails become narrower before either disappears. Short terminals still
/// spend their rows on the transcript and composer because stacked telemetry is not useful
/// when it can only show card headings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceLayout {
    Focused,
    SessionRail,
    Full,
}

fn workspace_layout(area: Rect) -> WorkspaceLayout {
    if area.width >= 112 && area.height >= 34 {
        WorkspaceLayout::Full
    } else if area.width >= 96 && area.height >= 22 {
        WorkspaceLayout::SessionRail
    } else {
        WorkspaceLayout::Focused
    }
}

pub fn draw(frame: &mut Frame, area: Rect, app: &mut App) {
    // The empty harness is intentionally singular: a session rail with nothing to select
    // spends width while a person is composing the task that will create the first row.
    // The full mark and any reconciliation error therefore retain the entire terminal.
    if app.sessions.open.is_none() {
        home(frame, area, app);
        return;
    }

    match workspace_layout(area) {
        WorkspaceLayout::Focused => primary(frame, area, app, true),
        WorkspaceLayout::SessionRail => {
            let columns =
                Layout::horizontal([Constraint::Length(24), Constraint::Min(60)]).split(area);
            session_rail(frame, columns[0], app);
            primary(frame, columns[1], app, true);
        }
        WorkspaceLayout::Full => {
            let left = if area.width >= 140 { 27 } else { 23 };
            let right = if area.width >= 140 { 37 } else { 30 };
            let columns = Layout::horizontal([
                Constraint::Length(left),
                Constraint::Min(58),
                Constraint::Length(right),
            ])
            .split(area);
            session_rail(frame, columns[0], app);
            context_rail(frame, columns[2], app);
            primary(frame, columns[1], app, false);
        }
    }
}

fn primary(frame: &mut Frame, area: Rect, app: &mut App, inline_context: bool) {
    if app.sessions.open.is_none() {
        home(frame, area, app);
    } else {
        detail(frame, area, app, inline_context);
    }
}

fn session_rail(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(Style::default().fg(theme::MUTED));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let sessions = app.sessions.merged();
    let summary = app.machine_summary();
    let footer_height = 7.min(inner.height.saturating_sub(4));
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(footer_height),
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" SESSIONS", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!(" / {:02}", sessions.len()),
                    Style::default().fg(theme::MUTED),
                ),
            ]),
            Line::from(vec![
                Span::styled(" ctrl+x l ", theme::action()),
                Span::styled("switch", Style::default().fg(theme::MUTED)),
            ]),
            Line::from(Span::styled(
                "─".repeat(inner.width as usize),
                Style::default().fg(theme::MUTED),
            )),
        ]),
        rows[0],
    );

    // Four cards are enough to preserve peripheral awareness without allowing a long tail
    // of dead sessions to turn the navigation rail into the visually dominant surface.
    // The complete list remains one leader chord away.
    let raw_capacity = ((rows[1].height as usize).saturating_add(1) / 5).max(1);
    let needs_summary = sessions.len() > raw_capacity.min(4);
    let capacity = if needs_summary {
        ((rows[1].height as usize) / 5).max(1)
    } else {
        raw_capacity
    };
    let visible_count = capacity.min(4);
    let selected_index = app.sessions.open.as_ref().and_then(|(plane, id)| {
        sessions
            .iter()
            .position(|session| session.plane == *plane && session.id == *id)
    });
    let start = selected_index
        .unwrap_or(0)
        .saturating_sub(visible_count.saturating_sub(1))
        .min(sessions.len().saturating_sub(visible_count));
    for (offset, session) in sessions.iter().skip(start).take(visible_count).enumerate() {
        let selected = app
            .sessions
            .open
            .as_ref()
            .is_some_and(|(plane, id)| *plane == session.plane && id == &session.id);
        let title_style = if selected {
            theme::action()
        } else if session.last_known {
            theme::quiet()
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };
        let card_width = rows[1].width;
        let label = session
            .objective
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| super::tree::truncate(value, card_width.saturating_sub(6) as usize))
            .unwrap_or_else(|| {
                format!(
                    "Session {}",
                    session_id_suffix(&session.id, card_width.saturating_sub(12))
                )
            });
        let provider = session.provider.as_deref().unwrap_or(session.plane.tag());
        let (signal, status) = session_signal(&session.status);
        let border_style = if selected {
            Style::default().fg(theme::ACTION)
        } else {
            match &session.status {
                SessionStatus::Running | SessionStatus::Starting => {
                    Style::default().fg(theme::SYSTEM)
                }
                SessionStatus::Failed | SessionStatus::Lost => Style::default().fg(theme::BAD),
                _ => Style::default().fg(theme::MUTED),
            }
        };
        let card = Rect::new(
            rows[1].x,
            rows[1].y.saturating_add((offset as u16).saturating_mul(5)),
            rows[1].width,
            4.min(rows[1].height),
        );
        if card.y.saturating_add(card.height) > rows[1].bottom() {
            break;
        }
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style);
        let content = block.inner(card);
        frame.render_widget(block, card);
        let marker = if selected { "▌" } else { signal };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(format!("{marker} "), border_style),
                    Span::styled(label, title_style),
                ]),
                Line::from(vec![
                    Span::styled(session.status.as_str().to_uppercase(), status),
                    Span::styled(
                        format!(" · {}", super::tree::truncate(provider, 9)),
                        Style::default().fg(theme::MUTED),
                    ),
                ]),
            ]),
            content,
        );
    }

    if sessions.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    " No sessions yet",
                    Style::default().fg(theme::MUTED),
                )),
                Line::from(Span::styled(
                    " Start in the composer",
                    Style::default().fg(theme::MUTED),
                )),
            ]),
            rows[1],
        );
    } else if sessions.len() > visible_count {
        let summary_y = rows[1]
            .y
            .saturating_add((visible_count as u16).saturating_mul(5));
        if summary_y < rows[1].bottom() {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!(
                        " +{:02} more · ctrl+x l",
                        sessions.len().saturating_sub(visible_count)
                    ),
                    Style::default().fg(theme::MUTED),
                ))),
                Rect::new(rows[1].x, summary_y, rows[1].width, 1),
            );
        }
    }

    let fleet = summary.fleet.as_deref().unwrap_or(summary.mode.as_str());
    let health_style = if summary.offline.unwrap_or(0) > 0 {
        Style::default().fg(theme::WARN)
    } else {
        Style::default().fg(theme::GOOD)
    };
    let fleet_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::MUTED))
        .title(Span::styled(
            format!(
                " FLEET / {} ",
                super::tree::truncate(&summary.machine, inner.width.saturating_sub(11) as usize)
            ),
            theme::label(),
        ));
    let fleet_inner = fleet_block.inner(rows[2]);
    frame.render_widget(fleet_block, rows[2]);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" ● ", health_style),
                Span::styled(
                    super::tree::truncate(fleet, inner.width.saturating_sub(4) as usize),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(Span::styled(
                format!(
                    "   {} / {} connected",
                    summary.connected,
                    summary.expected.unwrap_or(summary.connected)
                ),
                Style::default().fg(theme::MUTED),
            )),
            Line::from(Span::styled(summary.mode.to_uppercase(), theme::label())),
        ]),
        fleet_inner,
    );
}

fn compact_session_id(id: &str, width: u16) -> String {
    let width = width.max(8) as usize;
    if id.width() <= width {
        return id.to_string();
    }

    let tail = id
        .chars()
        .rev()
        .take(width.saturating_sub(1))
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("…{tail}")
}

fn session_id_suffix(id: &str, width: u16) -> String {
    id.chars()
        .rev()
        .take(width.max(6) as usize)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn session_signal(status: &SessionStatus) -> (&'static str, Style) {
    let signal = match status {
        SessionStatus::Starting | SessionStatus::Running | SessionStatus::Closing => "◆",
        SessionStatus::AwaitingApproval => "!",
        SessionStatus::Idle => "○",
        SessionStatus::Completed | SessionStatus::Closed => "✓",
        SessionStatus::Failed | SessionStatus::Lost => "×",
        SessionStatus::Cancelled => "–",
        SessionStatus::Other(_) => "?",
    };
    (signal, theme::session_status(status))
}

fn context_rail(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::LEFT)
        .border_style(Style::default().fg(theme::MUTED));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let session = app.sessions.open_info();
    let watch = app.sessions.open_watch();
    let summary = app.machine_summary();
    let (sandbox, writable) = app.open_sandbox().unwrap_or_else(|| {
        let (label, writable) = app.home_sandbox();
        (label.to_string(), writable)
    });
    let approval = session
        .map(|session| session_policy(Some(session), "approval_mode"))
        .unwrap_or_else(|| {
            app.config
                .defaults
                .approval_mode()
                .map(|mode| mode.as_str().to_string())
                .unwrap_or_else(|| "ask".to_string())
        });
    let panel_width = inner.width.saturating_sub(2);
    let provider = session
        .and_then(|session| session.provider.as_deref())
        .unwrap_or("unknown");
    let workspace = session
        .and_then(|session| session.workspace.as_deref())
        .unwrap_or("unknown");
    let (session_label, session_style) = session
        .map(|session| {
            let (signal, style) = session_signal(&session.status);
            (
                format!("{signal} {}", session.status.as_str().to_uppercase()),
                style.add_modifier(Modifier::BOLD),
            )
        })
        .unwrap_or_else(|| ("○ NEW SESSION".to_string(), theme::action()));
    let (stream_label, stream_style) = if let Some(watch) = watch {
        if watch.resyncing {
            ("RESTORING", Style::default().fg(theme::SYSTEM))
        } else if watch.ended.is_some() {
            ("ENDED", Style::default().fg(theme::MUTED))
        } else if watch.follow {
            ("STREAMING", Style::default().fg(theme::SYSTEM))
        } else {
            ("SCROLLED", Style::default().fg(theme::WARN))
        }
    } else {
        ("DETACHED", Style::default().fg(theme::MUTED))
    };
    let (link_label, link_style) = match &app.connection {
        Connection::Live => ("LINK HEALTHY".to_string(), Style::default().fg(theme::GOOD)),
        Connection::Lost { reason } => (
            format!("LINK LOST · {}", super::tree::truncate(reason, 12)),
            Style::default().fg(theme::BAD),
        ),
    };
    let event_count = watch.map(Watch::len).unwrap_or(0);
    let cursor = watch.map(Watch::cursor).unwrap_or(0);
    let dropped = watch.map(|watch| watch.dropped).unwrap_or(0);
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Length(7),
        Constraint::Length(1),
        Constraint::Length(7),
        Constraint::Length(1),
        Constraint::Length(7),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(inner);

    let compact_header = inner.width < 33;
    let header_columns = Layout::horizontal([
        Constraint::Min(16),
        Constraint::Length(if compact_header { 7 } else { 11 }),
    ])
    .split(rows[0]);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " RUNTIME / CONTEXT",
            theme::label(),
        ))),
        header_columns[0],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("● ", stream_style),
            Span::styled(
                if compact_header { "LIVE" } else { stream_label },
                stream_style.add_modifier(Modifier::BOLD),
            ),
        ])),
        header_columns[1],
    );

    render_context_panel(
        frame,
        rows[2],
        " SIGIL / CONTEXT CHANNEL ",
        theme::SYSTEM,
        vec![
            Line::from(Span::styled(
                format!(
                    "◇──[ {} ]──◇",
                    super::tree::truncate(
                        &summary.machine,
                        panel_width.saturating_sub(12) as usize
                    )
                ),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!("{event_count} events · {stream_label}"),
                Style::default().fg(theme::MUTED),
            )),
        ],
    );

    render_context_panel(
        frame,
        rows[4],
        " ACTIVE CONTEXT ",
        theme::MUTED,
        vec![
            context_panel_value("PROVIDER", provider, panel_width, Style::default()),
            context_panel_value("WORKSPACE", workspace, panel_width, Style::default()),
            context_panel_value("APPROVAL", &approval, panel_width, theme::action()),
            context_panel_value(
                "FILES",
                &sandbox,
                panel_width,
                Style::default().fg(if writable { theme::GOOD } else { theme::WARN }),
            ),
            Line::from(Span::styled(session_label, session_style)),
        ],
    );

    render_context_panel(
        frame,
        rows[6],
        " EXECUTION TRACE ",
        theme::MUTED,
        vec![
            context_panel_value(
                "EVENTS",
                &event_count.to_string(),
                panel_width,
                Style::default(),
            ),
            context_panel_value("CURSOR", &cursor.to_string(), panel_width, Style::default()),
            context_panel_value(
                "DROPPED",
                &dropped.to_string(),
                panel_width,
                Style::default(),
            ),
            context_panel_value(
                "NODES",
                &format!(
                    "{} / {} connected",
                    summary.connected,
                    summary.expected.unwrap_or(summary.connected)
                ),
                panel_width,
                Style::default(),
            ),
            Line::from(Span::styled(link_label, link_style)),
        ],
    );

    render_context_panel(
        frame,
        rows[8],
        " BOUNDARIES ",
        theme::MUTED,
        vec![
            context_panel_value("MODE", &summary.mode, panel_width, Style::default()),
            context_panel_value("MACHINE", &summary.machine, panel_width, Style::default()),
            context_panel_value("ENDPOINT", &app.address, panel_width, Style::default()),
            context_panel_value("APPROVAL", &approval, panel_width, theme::action()),
            context_panel_value(
                "FILES",
                &sandbox,
                panel_width,
                Style::default().fg(if writable { theme::GOOD } else { theme::WARN }),
            ),
        ],
    );

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " HERMETIC CORE · LEGIBLE EDGE",
            Style::default().fg(theme::MUTED),
        ))),
        rows[10],
    );
}

fn render_context_panel(
    frame: &mut Frame,
    area: Rect,
    title: &'static str,
    colour: ratatui::style::Color,
    lines: Vec<Line<'static>>,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::MUTED))
        .title(Span::styled(
            title,
            Style::default().fg(colour).add_modifier(Modifier::BOLD),
        ));
    let content = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content);
}

fn context_panel_value(label: &str, value: &str, width: u16, style: Style) -> Line<'static> {
    let available = width
        .saturating_sub(label.width() as u16)
        .saturating_sub(1)
        .max(4) as usize;
    Line::from(vec![
        Span::styled(format!("{label} "), theme::label()),
        Span::styled(super::tree::truncate(value, available), style),
    ])
}

fn detail(frame: &mut Frame, area: Rect, app: &mut App, inline_context: bool) {
    let composer_height = if app
        .sessions
        .open
        .as_ref()
        .map(|(plane, _id)| *plane == Plane::Interactive)
        .unwrap_or(false)
    {
        composer_block_height(app.sessions.composer.as_ref(), area.width)
    } else {
        0
    };

    let plan_height = plan_panel_height(app, area);
    let queue_height = queue_panel_height(app, area, plan_height);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(plan_height),
            Constraint::Length(queue_height),
            Constraint::Length(composer_height),
        ])
        .split(area);

    transcript(frame, rows[0], app);

    if plan_height > 0 {
        plan_panel(frame, rows[1], app);
    }

    if queue_height > 0 {
        queue_panel(frame, rows[2], app);
    }

    if composer_height > 0 {
        composer(frame, rows[3], app, inline_context);
    }
}

/// How many rows the queue wants above the composer, or zero when nothing is waiting.
///
/// Claude Code draws the queue immediately above the input; so does this. It is bounded
/// on two sides — [`QUEUE_ROWS`] rows at most, and never on a terminal so short that the
/// conversation would lose its last lines to it.
fn queue_panel_height(app: &App, area: Rect, plan_height: u16) -> u16 {
    if !app
        .sessions
        .open
        .as_ref()
        .is_some_and(|(plane, _id)| *plane == Plane::Interactive)
    {
        return 0;
    }

    let local = app.sessions.open_queued_drafts().len();
    let runtime = app.sessions.open_runtime_queue();

    if local == 0 && runtime == 0 {
        return 0;
    }

    if area.height.saturating_sub(plan_height) < 14 {
        return 0;
    }

    // The top border, the heading, one row for the runtime's depth when it has one, and
    // one row per local draft up to the ceiling.
    let rows = 2 + u16::from(runtime > 0) + (local as u16).min(QUEUE_ROWS);
    rows.saturating_add(u16::from(local as u16 > QUEUE_ROWS))
}

/// The queue: what the runtime durably holds, and what is still only here.
///
/// The distinction is the whole point of drawing it. `queue_changed` reports a *depth* and
/// nothing else — the runtime does not replay the text of a turn it has not started — so
/// the durable half is stated as a count and the rows with text on them are exactly the
/// ones this client is still holding and could still lose.
fn queue_panel(frame: &mut Frame, area: Rect, app: &App) {
    let local = app.sessions.open_queued_drafts();
    let runtime = app.sessions.open_runtime_queue();

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme::MUTED));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![Line::from(vec![
        Span::styled("QUEUE ", theme::label()),
        Span::styled(
            format!("{} durable · {} here", runtime, local.len()),
            Style::default().fg(theme::MUTED),
        ),
        Span::styled(
            if local.is_empty() {
                String::new()
            } else {
                "   ↑ takes the newest back".to_string()
            },
            Style::default().fg(theme::MUTED),
        ),
    ])];

    if runtime > 0 {
        lines.push(Line::from(vec![
            Span::styled("  runtime  ", Style::default().fg(theme::GOOD)),
            Span::styled(
                format!(
                    "{runtime} follow-up{} the runtime is holding; their text is durable there",
                    if runtime == 1 { "" } else { "s" }
                ),
                Style::default().fg(theme::MUTED),
            ),
        ]));
    }

    let width = inner.width.max(20) as usize;
    let preview = width.saturating_sub(14);

    for (index, draft) in local.iter().take(QUEUE_ROWS as usize).enumerate() {
        let carried = draft.input.attachments.len();
        lines.push(Line::from(vec![
            Span::styled(format!("  {}. local  ", index + 1), theme::label()),
            Span::raw(super::tree::truncate(
                &draft.input.prompt().replace('\n', " "),
                preview,
            )),
            Span::styled(
                if carried == 0 {
                    String::new()
                } else {
                    format!("  +{carried} attached")
                },
                Style::default().fg(theme::MUTED),
            ),
        ]));
    }

    if local.len() > QUEUE_ROWS as usize {
        lines.push(Line::from(Span::styled(
            format!("  +{} more here", local.len() - QUEUE_ROWS as usize),
            Style::default().fg(theme::MUTED),
        )));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

/// How many rows the `Ctrl+T` plan panel wants, or zero when it is closed or has nothing.
///
/// The panel stays open across idle redraws — a task list that disappears the moment the
/// agent stops working is the Codex #18920 anti-pattern — but it never takes the
/// conversation's last rows on a short terminal.
fn plan_panel_height(app: &App, area: Rect) -> u16 {
    if !app.sessions.show_plan || area.height < 16 {
        return 0;
    }

    let Some(plan) = app.sessions.open_watch().and_then(Watch::latest_plan) else {
        return 0;
    };

    // Heading, the explanation's first wrapped rows, one row per step, and the borders.
    let body = 1 + plan.steps.len() as u16 + u16::from(plan.explanation.is_some());
    body.saturating_add(2).min(PLAN_PANEL_ROWS)
}

fn plan_panel(frame: &mut Frame, area: Rect, app: &App) {
    let Some(plan) = app.sessions.open_watch().and_then(Watch::latest_plan) else {
        return;
    };

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme::MUTED));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::new();
    transcript_cells::render_plan(
        &mut lines,
        plan,
        inner.width.max(8) as usize,
        "Plan  ctrl+t",
    );

    // The newest rows are the ones being worked on, so a plan longer than the panel keeps
    // its tail rather than its head.
    let height = inner.height as usize;
    let start = lines.len().saturating_sub(height);

    frame.render_widget(Paragraph::new(lines[start..].to_vec()), inner);
}

/// The three lines a first-time operator needs, on the one screen they always see (B9).
///
/// Empty once three prompts have been sent. An undiscoverable power feature is R1 4d(8) —
/// OpenCode's fork keybind defaulting to `none`, `/compact` that people found months in —
/// and the fix everyone converged on is to say it where the eyes already are, once.
fn first_run_tips(app: &App) -> Vec<Line<'static>> {
    if !app.onboarding() {
        return Vec::new();
    }

    [
        "@ attaches a file from this workspace, / opens the command list",
        "ctrl+o expands every cell, ctrl+t shows the plan while it works",
        "esc interrupts the turn and keeps what is queued; ? lists every key",
    ]
    .into_iter()
    .map(|tip| Line::from(Span::styled(tip, Style::default().fg(theme::ACCENT))))
    .collect()
}

fn home(frame: &mut Frame, area: Rect, app: &App) {
    // The home composer has no session and therefore no chips: its height is the editor's.
    let composer_height = COMPOSER_CHROME
        + editor_rows(Some(&app.home_draft), area.width)
        + completion_rows(Some(&app.home_draft));
    let rows =
        Layout::vertical([Constraint::Min(5), Constraint::Length(composer_height)]).split(area);
    let ready = app.home_ready();
    let requested_workspace = app.home_workspace();

    let mut message: Vec<Line> = if ready {
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
            Line::from(Span::styled(
                app.machine_hint(),
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
            Line::from(Span::styled(
                app.machine_hint(),
                Style::default().fg(theme::MUTED),
            )),
        ]
    };

    // B9's tips never cost the logo. On a terminal with room for both they are added; on
    // one that could show the logo without them they are not; on one too short for the
    // logo at all they are, because there is nothing left for them to displace.
    let tips = first_run_tips(app);
    let logo_without_tips = rows[0].height > logo::HEIGHT + message.len() as u16;
    let logo_with_tips = rows[0].height > logo::HEIGHT + (message.len() + tips.len()) as u16;

    if logo_with_tips || !logo_without_tips {
        message.extend(tips);
    }

    if rows[0].height > logo::HEIGHT + message.len() as u16 {
        let vertical = Layout::vertical([
            Constraint::Length(logo::HEIGHT),
            Constraint::Length(1),
            Constraint::Length(message.len() as u16),
        ])
        .flex(ratatui::layout::Flex::Center)
        .split(rows[0]);

        logo::draw(frame, vertical[0], Treatment::Alive { tick: app.ticks });
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
    let waiting_for_reply = app.waiting_for_open_agent_reply();
    let session_status = app
        .sessions
        .open_info()
        .map(|session| session.status.as_str().to_string());
    let conversation_title = app
        .sessions
        .open_info()
        .and_then(|session| session.objective.as_deref())
        .filter(|objective| !objective.trim().is_empty())
        .map(str::to_uppercase)
        .unwrap_or_else(|| "AGENT CHAT".to_string());
    let conversation_provider = app
        .sessions
        .open_info()
        .and_then(|session| session.provider.as_deref())
        .unwrap_or("unknown")
        .to_string();

    let Some((plane, id)) = app.sessions.open.clone() else {
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
            .wrap(Wrap { trim: false }),
            area,
        );

        return;
    };

    let ticks = app.ticks;
    let show_event_details = app.sessions.show_event_details;
    // Raw outranks verbose: it is a copying view, and a copying view that still drew
    // frames would not be one.
    let verbosity = if app.sessions.raw_mode {
        Verbosity::Raw
    } else if app.sessions.verbose_transcript {
        Verbosity::Verbose
    } else {
        Verbosity::Compact
    };
    let header_height = if area.width >= 52 && area.height >= 12 {
        3
    } else {
        1
    };
    let rows =
        Layout::vertical([Constraint::Length(header_height), Constraint::Min(1)]).split(area);
    let inner = rows[1];

    let Some(watch) = app.sessions.watches.get_mut(&(plane, id.clone())) else {
        return;
    };

    let width = inner.width.max(8) as usize;
    let resyncing = watch.resyncing;
    let entries = watch.entries();
    let mut lines = if show_event_details {
        event_lines(entries, width)
    } else {
        chat_lines(entries, width, ticks, verbosity)
    };

    if !show_event_details {
        let empty = lines.is_empty();
        if waiting_for_reply {
            push_working_indicator(&mut lines, ticks, theme::working_verb(ticks));
        } else if resyncing {
            push_working_indicator(
                &mut lines,
                ticks,
                if empty {
                    "Loading conversation"
                } else {
                    "Restoring history"
                },
            );
        } else if empty
            && session_status
                .as_deref()
                .is_some_and(|status| matches!(status, "running" | "starting"))
        {
            push_working_indicator(
                &mut lines,
                ticks,
                if session_status.as_deref() == Some("starting") {
                    "Starting"
                } else {
                    theme::working_verb(ticks)
                },
            );
        }
    }

    // The renderer is the only thing that knows how many rows this wrapped to, so it is
    // the only thing that can hold a scrolled-back viewport still while the tail grows.
    watch.measured(lines.len(), inner.height as usize);

    if header_height == 1 {
        frame.render_widget(
            Paragraph::new(header(
                watch,
                &id,
                plane,
                ticks,
                show_event_details,
                verbosity,
            )),
            rows[0],
        );
    } else {
        render_conversation_header(
            frame,
            rows[0],
            watch,
            ConversationHeader {
                id: &id,
                plane,
                title: &conversation_title,
                provider: &conversation_provider,
                show_event_details,
                verbosity,
            },
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

    // `measured` already clamped this against exactly these numbers.
    let scroll = if watch.follow { 0 } else { watch.scroll };

    let start = max_scroll.saturating_sub(scroll);
    let end = (start + height).min(lines.len());

    frame.render_widget(Paragraph::new(lines[start..end].to_vec()), inner);
}

struct ConversationHeader<'a> {
    id: &'a str,
    plane: Plane,
    title: &'a str,
    provider: &'a str,
    show_event_details: bool,
    verbosity: Verbosity,
}

fn render_conversation_header(
    frame: &mut Frame,
    area: Rect,
    watch: &Watch,
    header: ConversationHeader<'_>,
) {
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    let action_width = if area.width >= 72 { 24 } else { 13 };
    let columns =
        Layout::horizontal([Constraint::Min(20), Constraint::Length(action_width)]).split(rows[0]);
    let heading = if header.show_event_details {
        "EVENT DETAILS".to_string()
    } else {
        super::tree::truncate(header.title, columns[0].width.saturating_sub(1) as usize)
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {heading}"),
            Style::default().add_modifier(Modifier::BOLD),
        ))),
        columns[0],
    );

    let (stream, stream_style) = if watch.resyncing {
        ("RESTORING", Style::default().fg(theme::SYSTEM))
    } else if watch.ended.is_some() {
        ("ENDED", Style::default().fg(theme::MUTED))
    } else if watch.follow {
        ("FOLLOWING", Style::default().fg(theme::SYSTEM))
    } else {
        ("SCROLLED", Style::default().fg(theme::WARN))
    };
    let action = if area.width >= 72 {
        Line::from(vec![
            Span::styled("● ", stream_style),
            Span::styled(stream, stream_style.add_modifier(Modifier::BOLD)),
            Span::styled(
                if header.show_event_details {
                    "  ^O VERBOSE"
                } else if header.verbosity.verbose() {
                    "  ^O COMPACT"
                } else {
                    "  ^O VERBOSE"
                },
                theme::label(),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("● ", stream_style),
            Span::styled(stream, stream_style.add_modifier(Modifier::BOLD)),
        ])
    };
    frame.render_widget(Paragraph::new(action), columns[1]);

    let meta = if header.show_event_details {
        format!(
            " {} · {} · cursor {}",
            header.plane,
            compact_session_id(header.id, 14),
            watch.cursor()
        )
    } else {
        // `run_started` is the only event that ever names a model, so a session whose
        // provider never sent one shows the provider alone rather than an invented name.
        let mut facts = vec![
            header.plane.to_string(),
            super::tree::truncate(header.provider, 14),
        ];

        if let Some(model) = watch.model() {
            facts.push(super::tree::truncate(model, 24));
        }

        facts.push(compact_session_id(header.id, area.width.saturating_sub(24)));
        format!(" {}", facts.join(" · "))
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(meta, theme::label()))),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(area.width as usize),
            Style::default().fg(theme::MUTED),
        ))),
        rows[2],
    );
}

fn header(
    watch: &Watch,
    id: &str,
    plane: Plane,
    tick: u64,
    show_event_details: bool,
    verbosity: Verbosity,
) -> Line<'static> {
    if !show_event_details {
        let mut spans = vec![
            Span::styled(" Agent chat ", theme::heading()),
            Span::styled(
                if verbosity.verbose() {
                    "ctrl+o compact "
                } else {
                    "ctrl+o verbose "
                },
                Style::default().fg(theme::MUTED),
            ),
        ];

        push_stream_state(&mut spans, watch, tick, false);
        return Line::from(spans);
    }

    let mut spans = vec![
        Span::styled(" Event details ", theme::heading()),
        Span::styled("/details chat  ", Style::default().fg(theme::MUTED)),
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

fn chat_lines(
    mut entries: Vec<Entry<'_>>,
    width: usize,
    tick: u64,
    verbosity: Verbosity,
) -> Vec<Line<'static>> {
    let omitted = entries.len().saturating_sub(CHAT_ENTRY_WINDOW);
    let visible = if omitted == 0 {
        entries
    } else {
        entries.split_off(omitted)
    };
    let mut lines = transcript_cells::render_at(visible, width, tick, verbosity);

    if omitted == 0 {
        return lines;
    }

    let mut bounded = vec![
        divider(
            &format!(
                "{omitted} earlier chat entries omitted here — /details shows all retained events"
            ),
            width,
            theme::WARN,
        ),
        Line::from(""),
    ];
    bounded.append(&mut lines);
    bounded
}

fn push_working_indicator(lines: &mut Vec<Line<'static>>, tick: u64, message: &str) {
    separate(lines);
    lines.push(theme::working(tick, message.to_string()));
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

fn composer(frame: &mut Frame, area: Rect, app: &App, inline_context: bool) {
    let active = app.sessions.composer.as_ref();
    let verb = active
        .map(|composer| composer.verb.title())
        .unwrap_or("message");
    let session = app.sessions.open_info();
    let provider = session
        .and_then(|session| session.provider.as_deref())
        .unwrap_or("agent");
    let approval = session_policy(session, "approval_mode");
    let (sandbox, sandbox_writable) = app
        .open_sandbox()
        .unwrap_or_else(|| ("unknown".to_string(), false));
    let sandbox_style = if sandbox_writable {
        Style::default().fg(theme::GOOD)
    } else {
        Style::default().fg(theme::WARN)
    };

    let title = if inline_context {
        Line::from(vec![
            Span::styled(" INSERT ", theme::action()),
            Span::styled("· PROVIDER ", theme::label()),
            Span::raw(provider.to_string()),
            Span::styled("  ·  APPROVAL ", theme::label()),
            Span::styled(approval, Style::default().fg(theme::WARN)),
            Span::styled("  ·  FILES ", theme::label()),
            Span::styled(sandbox, sandbox_style),
            Span::styled(format!("   {verb}"), Style::default().fg(theme::MUTED)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" INSERT ", theme::action()),
            Span::styled(format!("· {verb}"), Style::default().fg(theme::MUTED)),
        ])
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if active.is_some() {
            theme::ACTION
        } else {
            theme::MUTED
        }))
        .title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(chip_rows(active)),
        Constraint::Min(2),
        Constraint::Length(completion_rows(active.map(|composer| &composer.editor))),
        Constraint::Length(1),
    ])
    .split(inner);

    if let Some(composer) = active {
        render_chips(frame, rows[0], composer);
    }

    let rows = &rows[1..];

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
                "This coding task takes no further input. ctrl+x x cancels it.",
                Style::default().fg(theme::MUTED),
            ))),
            rows[0],
        );
    }

    // What Enter does right now. `follow_up` is Harness's durable queueing verb, so on a
    // busy session the key really does queue rather than send, and saying "sends" there
    // is the queue/steer blur R1 §4d(2) names.
    let verb_key = match active.map(|composer| composer.verb) {
        Some(ComposerVerb::FollowUp) => "queues",
        Some(ComposerVerb::Steer) => "steers",
        _ => "sends",
    };

    let pending_reconciliations = app.open_pending_reconciliation_count();
    let footer = if pending_reconciliations > 0 {
        format!(
            "{pending_reconciliations} outcome-unknown turn{} · Enter reconciles first · draft kept",
            if pending_reconciliations == 1 { "" } else { "s" }
        )
    } else if active
        .and_then(|composer| composer.editor.completion())
        .is_some()
    {
        key_footer(
            "↑↓ choose · Tab complete · Esc close",
            app.keyboard_enhanced,
            "sends",
        )
    } else if area.width < 76 {
        format!(
            "Esc abort · {} · Ctrl+J newline · Enter {verb_key}",
            if sandbox_writable {
                "/ commands"
            } else {
                "/write"
            }
        )
    } else {
        // B3/D14. `alt+enter` is the steer key, and it is named only where the runtime
        // said this transport can steer *and* the terminal reports the modifier at all —
        // without the kitty protocol `Alt+Enter` arrives as a bare `Enter`, which sends.
        // On a narrow pane it is the cell that yields, exactly as the footer's do: a hint
        // cut in half is worse than a hint that waited for the width to hold it.
        let steer = if app.steer_offered() && app.keyboard_enhanced && area.width >= 100 {
            " · alt+enter steers"
        } else {
            ""
        };

        key_footer(
            &format!(
                "{}{steer}",
                if sandbox_writable {
                    "esc abort · shift+↑ scroll · / commands"
                } else {
                    "esc abort · /write to edit · / commands"
                }
            ),
            app.keyboard_enhanced,
            verb_key,
        )
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
    let (sandbox, sandbox_writable) = app.home_sandbox();
    let sandbox_style = if sandbox_writable {
        Style::default().fg(theme::GOOD)
    } else {
        Style::default().fg(theme::WARN)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if ready { theme::ACTION } else { theme::MUTED }))
        .title(Line::from(vec![
            Span::styled(" PROVIDER ", theme::label()),
            Span::raw(app.home_provider().to_string()),
            Span::styled("  ·  REQUESTED APPROVAL ", theme::label()),
            Span::styled(permission.to_string(), Style::default().fg(theme::WARN)),
            Span::styled("  ·  FILES ", theme::label()),
            Span::styled(sandbox.to_string(), sandbox_style),
        ]));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([
        Constraint::Min(2),
        Constraint::Length(completion_rows(Some(&app.home_draft))),
        Constraint::Length(1),
    ])
    .split(inner);

    if app.home_pending {
        frame.render_widget(
            Paragraph::new(theme::working(app.ticks, "Starting the agent…")),
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
            key_footer(
                "↑↓ choose · Tab complete · Esc close",
                app.keyboard_enhanced,
                "starts",
            ),
            Style::default().fg(theme::MUTED),
        ))
    } else if ready {
        Line::from(Span::styled(
            key_footer(
                "@ paths · / commands · ↑ history",
                app.keyboard_enhanced,
                "starts",
            ),
            Style::default().fg(theme::MUTED),
        ))
    } else {
        Line::from(Span::styled(
            "/ commands                                               Enter connects",
            Style::default().fg(theme::MUTED),
        ))
    };
    frame.render_widget(Paragraph::new(footer), rows[2]);
}

/// A composer footer, naming only the newline bindings this terminal actually has.
///
/// `Shift+Enter` needs the kitty keyboard protocol to be distinguishable from `Enter` at
/// all. Where it is not — Terminal.app, iTerm2's default profile, tmux without passthrough
/// — a footer offering it would be telling someone that the key which sends their
/// half-written message inserts a newline. `Ctrl+J` always works, so it is always named.
fn key_footer(left: &str, enhanced: bool, verb: &str) -> String {
    let newline = if enhanced {
        "Shift+Enter/Ctrl+J"
    } else {
        "Ctrl+J"
    };

    // Padded to a column so the two halves line up, but never *less* than a gap: a `left`
    // that outgrew the column must still read as two things rather than one run-on word.
    let gap = 42usize.saturating_sub(left.chars().count()).max(3);

    format!("{left}{}{newline} newline · Enter {verb}", " ".repeat(gap))
}

/// How many matches the popup lists before it stops listing and starts counting.
const COMPLETION_ROWS: usize = 3;
const COMPOSER_EDITOR_MIN: u16 = 2;
const COMPOSER_EDITOR_MAX: u16 = 6;
const COMPOSER_CHROME: u16 = 3;

fn composer_block_height(composer: Option<&Composer>, width: u16) -> u16 {
    let editor = composer.map(|composer| &composer.editor);

    COMPOSER_CHROME + chip_rows(composer) + editor_rows(editor, width) + completion_rows(editor)
}

/// How many rows the attachment chips and their refusal want, above the editor.
///
/// Zero for the ordinary turn, which is most of them: a composer with nothing attached
/// draws exactly what it drew before B4.
fn chip_rows(composer: Option<&Composer>) -> u16 {
    let Some(composer) = composer else {
        return 0;
    };

    let chips = u16::from(!composer.attachments.is_empty() || composer.reasoning_effort.is_some());

    chips + u16::from(composer.attachment_refusal.is_some())
}

/// The chips: what this turn will carry as `params.input.attachments`, and the per-turn
/// effort beside them.
///
/// Chips rather than the substituted text alone because they are the only place the
/// structured half of the turn is visible. The text still says `@src/app.rs`; the chip is
/// what says that path is *also* travelling as an attachment the runtime will canonicalise.
fn render_chips(frame: &mut Frame, area: Rect, composer: &Composer) {
    if chip_rows(Some(composer)) == 0 {
        return;
    }

    let mut lines = Vec::new();

    if !composer.attachments.is_empty() || composer.reasoning_effort.is_some() {
        let mut spans = Vec::new();

        for attachment in &composer.attachments {
            spans.push(Span::styled(
                format!(
                    " {}{} ",
                    if attachment.kind == AttachmentKind::Image {
                        "▣ "
                    } else {
                        "@"
                    },
                    attachment.label()
                ),
                theme::label(),
            ));
            spans.push(Span::raw(" "));
        }

        if let Some(effort) = composer.reasoning_effort {
            spans.push(Span::styled(
                format!(" effort {} ", effort.as_str()),
                Style::default().fg(theme::ACCENT),
            ));
            spans.push(Span::raw(" "));
        }

        if !composer.attachments.is_empty() {
            spans.push(Span::styled(
                "backspace on an empty draft removes the last",
                Style::default().fg(theme::MUTED),
            ));
        }

        lines.push(Line::from(spans));
    }

    if let Some(refusal) = composer.attachment_refusal.as_deref() {
        lines.push(Line::from(Span::styled(
            super::tree::truncate(refusal, area.width.max(20) as usize),
            Style::default().fg(theme::WARN),
        )));
    }

    frame.render_widget(Paragraph::new(lines), area);
}

fn editor_rows(editor: Option<&Editor>, width: u16) -> u16 {
    let Some(editor) = editor else {
        return COMPOSER_EDITOR_MIN;
    };
    if editor.is_empty() {
        return COMPOSER_EDITOR_MIN;
    }
    let content_width = width.saturating_sub(4).max(1) as usize;
    visual_line_count(editor.text(), content_width)
        .clamp(COMPOSER_EDITOR_MIN as usize, COMPOSER_EDITOR_MAX as usize) as u16
}

fn visual_line_count(text: &str, width: usize) -> usize {
    let width = width.max(1);
    let mut row = 0usize;
    let mut column = 0usize;

    for character in text.chars() {
        if character == '\n' {
            row += 1;
            column = 0;
            continue;
        }

        let cell_width = if character == '\t' {
            4 - (column % 4)
        } else {
            character.width().unwrap_or(0)
        };

        if column > 0 && column + cell_width > width {
            row += 1;
            column = 0;
        }

        column += cell_width;
    }

    row + 1
}

/// The height the completion popup needs: the listed rows, plus one for the line that says
/// how many are not listed.
fn completion_rows(editor: Option<&Editor>) -> u16 {
    editor
        .and_then(Editor::completion)
        .map(|menu| {
            menu.items.len().min(COMPLETION_ROWS) + usize::from(menu.items.len() > COMPLETION_ROWS)
        })
        .unwrap_or(0) as u16
}

fn render_editor(frame: &mut Frame, area: Rect, editor: &Editor, placeholder: &str) {
    if area.width < 3 || area.height == 0 {
        return;
    }

    if editor.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("▌ ", Style::default().fg(theme::ACTION)),
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
                Span::styled(prefix, Style::default().fg(theme::ACTION)),
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

    // A `@` on its own matches up to fifty paths and three of them fit. Showing three with
    // nothing to say the rest exist reads as "these are your matches", so the row that would
    // have been a fourth match counts them instead.
    let hidden = menu.items.len().saturating_sub(COMPLETION_ROWS);
    let count = (area.height as usize).saturating_sub(usize::from(hidden > 0));

    if count == 0 {
        return;
    }

    let start = menu
        .selected
        .saturating_sub(count.saturating_sub(1))
        .min(menu.items.len().saturating_sub(count));
    let mut lines = menu
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

    if hidden > 0 {
        lines.push(Line::from(Span::styled(
            super::tree::truncate(
                &format!("  +{hidden} more — keep typing to narrow, ↑↓ to move"),
                area.width as usize,
            ),
            Style::default().fg(theme::MUTED),
        )));
    }

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

        let lines = chat_lines(entries, 160, 0, Verbosity::Compact);

        assert!(
            lines[0]
                .to_string()
                .contains("1 earlier chat entries omitted here"),
            "{}",
            lines[0]
        );
        assert!(lines[0].to_string().contains("/details"), "{}", lines[0]);
    }

    /// The window is a redraw budget, not a retention policy: the ledger keeps everything
    /// and the divider says how much this pane is not drawing.
    #[test]
    fn the_chat_window_still_bounds_the_newest_entries_it_projects() {
        let events: Vec<Event> = (1..=(CHAT_ENTRY_WINDOW as u64 + 72))
            .map(|sequence| {
                Event::decode(&serde_json::json!({
                    "id": format!("evt-{sequence}"),
                    "sequence": sequence,
                    "type": "output_text_final",
                    "timestamp": "2026-01-01T00:00:00.000000Z",
                    "turn_id": format!("turn-{sequence}"),
                    "payload": { "text": format!("message-{sequence}") }
                }))
                .expect("an event")
            })
            .collect();
        let entries: Vec<Entry<'_>> = events.iter().map(Entry::Event).collect();

        let rendered = chat_lines(entries, 120, 0, Verbosity::Compact)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            rendered.contains("72 earlier chat entries omitted here"),
            "{rendered}"
        );
        assert!(!rendered.contains("message-72 "), "{rendered}");
        assert!(rendered.contains("message-73"), "{rendered}");
        assert!(rendered.contains("message-200"), "{rendered}");
    }

    #[test]
    fn visual_line_count_grows_with_newlines() {
        assert_eq!(visual_line_count("one line", 40), 1);
        assert_eq!(visual_line_count("one\ntwo\nthree", 40), 3);
        assert_eq!(visual_line_count("abcdefghij", 4), 3);
    }

    #[test]
    fn workspace_layout_protects_the_conversation_before_disclosing_telemetry() {
        assert_eq!(
            workspace_layout(Rect::new(0, 0, 80, 24)),
            WorkspaceLayout::Focused
        );
        assert_eq!(
            workspace_layout(Rect::new(0, 0, 120, 30)),
            WorkspaceLayout::SessionRail
        );
        assert_eq!(
            workspace_layout(Rect::new(0, 0, 116, 58)),
            WorkspaceLayout::Full,
            "a tall laptop viewport keeps the designed contextual rail"
        );
        assert_eq!(
            workspace_layout(Rect::new(0, 0, 160, 40)),
            WorkspaceLayout::Full
        );
        assert_eq!(
            workspace_layout(Rect::new(0, 0, 160, 20)),
            WorkspaceLayout::Focused,
            "short terminals must spend their rows on chat and the composer"
        );
    }
}
