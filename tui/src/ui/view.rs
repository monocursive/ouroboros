//! The transcript-first harness shell, its command palette, and secondary operator panels.
//!
//! Drawing is a pure function of [`App`] plus mutable tree/scroll state, so a `TestBackend`
//! renders exactly what a terminal does. Nothing here calls the runtime, and nothing here
//! decides anything: a panel that is empty because a method failed says which method and
//! why, because "no agents" and "agents.list was refused" are different facts.

use ratatui::layout::{Alignment, Constraint, Direction, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::access;
use super::app::{
    provider_choices, AccountDialog, AccountFlow, AddField, AddMachine, AddMethod, AddStep, App,
    ApprovalRule, CommandPalette, Connection, FormField, FormKind, MachineForm, MachineReport,
    MachineSecurity, Machines, Mode, NewField, NewSession, NoticeKind, Overlay, ProviderChoice,
    SessionFacts, Settings, SettingsField, Tab, APPROVAL_CHOICES,
};
use super::editor::COMMANDS;
use super::theme;
use super::transcript::ApprovalDetail;
use crate::keymap::{Action, Scope};
use crate::model::{Plane, ProviderEntry};

pub fn draw(frame: &mut Frame, app: &mut App) {
    // The scriptable status line gets its own row above the footer, and only when a
    // command is configured *and* it printed something — an empty row where an operator's
    // script used to be would be this client reserving space for a fact it does not have.
    let scripted = app.statusline().line().map(str::to_string);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(u16::from(scripted.is_some())),
            Constraint::Length(1),
        ])
        .split(frame.area());

    shell_header(frame, rows[0], app);

    match app.tab {
        Tab::Dashboard => super::dashboard::draw(frame, rows[1], app),
        Tab::Sessions => super::sessions::draw(frame, rows[1], app),
        Tab::Agents | Tab::Teams | Tab::Plans | Tab::Upgrade => {
            super::explorer::draw(frame, rows[1], app)
        }
        Tab::Logs => super::logs::draw(frame, rows[1], app),
    }

    if let Some(scripted) = scripted {
        frame.render_widget(
            Paragraph::new(super::statusline::render(&scripted)),
            rows[2],
        );
    }

    status_line(frame, rows[3], app);
    overlay(frame, frame.area(), app);

    if app.leader_pending() {
        leader_hint(frame, frame.area(), app);
    }
}

fn shell_header(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(access::borders(Borders::BOTTOM))
        .border_style(Style::default().fg(theme::muted()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let workspace = if app.sessions.open.is_some() {
        app.sessions
            .open_info()
            .and_then(|session| session.workspace.as_deref())
            .filter(|path| !path.trim().is_empty())
            .map(|path| format!("workspace {}", super::tree::truncate(path, 32)))
            .unwrap_or_else(|| "session workspace unknown".to_string())
    } else if let Some(path) = app
        .config
        .defaults
        .workspace
        .as_deref()
        .filter(|path| !path.trim().is_empty())
    {
        format!("requested {}", super::tree::truncate(path, 32))
    } else if let Some(path) = app
        .launch_dir
        .as_deref()
        .filter(|path| !path.trim().is_empty())
    {
        let label = if app.spawned() {
            "requested"
        } else {
            "local cwd suggestion"
        };
        format!("{label} {}", super::tree::truncate(path, 32))
    } else {
        "requested workspace unset".to_string()
    };

    let context = if app.tab == Tab::Sessions {
        match &app.sessions.open {
            Some((_plane, _id)) => {
                let session = "Agent chat".to_string();
                if app.waiting_for_open_agent_reply() {
                    format!("{} {session}", theme::spinner(app.ticks))
                } else {
                    session
                }
            }
            None => "New coding session".to_string(),
        }
    } else {
        format!("Runtime & distribution: {}", app.tab.title())
    };

    let brand = Line::from(vec![
        Span::styled("◌ ", theme::action()),
        Span::styled("OUROBOROS", Style::default().add_modifier(Modifier::BOLD)),
    ]);

    let visible_provider = if app.sessions.open.is_some() {
        app.sessions
            .open_info()
            .and_then(|session| session.provider.as_deref())
    } else {
        Some(app.home_provider())
    };

    let account = if visible_provider.is_some_and(|provider| provider != "codex") {
        Line::from(vec![
            Span::styled("Provider ", Style::default().fg(theme::muted())),
            Span::styled(
                visible_provider.expect("checked provider"),
                Style::default().fg(theme::accent()),
            ),
        ])
    } else if visible_provider.is_none() {
        Line::from(Span::styled(
            "Provider unknown",
            Style::default().fg(theme::muted()),
        ))
    } else if let Some(state) = &app.account.value {
        if let Some(identity) = &state.account {
            let plan = state
                .plan_label()
                .map(|plan| format!(" {plan}"))
                .unwrap_or_default();
            let identity = identity
                .email
                .as_deref()
                .map(|email| format!("  • {email}"))
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(format!("ChatGPT{plan}"), Style::default().fg(theme::good())),
                Span::styled(identity, Style::default().fg(theme::muted())),
            ])
        } else if state.requires_openai_auth == Some(false) {
            // An API-key install. There is no subscription to name and nothing to connect,
            // and "not connected" would read as a problem the operator has to go and fix.
            Line::from(vec![
                Span::styled("Codex ready", Style::default().fg(theme::good())),
                Span::styled(
                    "  • no ChatGPT sign-in needed",
                    Style::default().fg(theme::muted()),
                ),
            ])
        } else {
            Line::from(Span::styled(
                "ChatGPT not connected",
                Style::default().fg(theme::warn()),
            ))
        }
    } else if app.account.pending {
        Line::from(Span::styled(
            format!("{} checking ChatGPT", theme::spinner(app.ticks)),
            Style::default().fg(theme::muted()),
        ))
    } else {
        Line::from(Span::styled(
            "ChatGPT unavailable",
            Style::default().fg(theme::warn()),
        ))
    };

    let (ready_label, ready_style) = match &app.connection {
        Connection::Live => ("LOCAL READY", Style::default().fg(theme::good())),
        Connection::Lost { .. } => ("LINK LOST", Style::default().fg(theme::bad())),
    };
    let mode_label = if app.tab == Tab::Sessions {
        "CODE".to_string()
    } else {
        app.tab.title().to_uppercase()
    };
    let badges = Line::from(vec![
        Span::styled("[", theme::label()),
        Span::styled("ctrl+p", theme::action()),
        Span::styled(" COMMANDS]  [", theme::label()),
        Span::styled("● ", ready_style),
        Span::styled(ready_label, ready_style.add_modifier(Modifier::BOLD)),
        Span::styled("]  [", theme::label()),
        Span::styled(mode_label, theme::action()),
        Span::styled("]", theme::label()),
    ]);
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(inner);
    if inner.width >= 96 {
        let top = Layout::horizontal([Constraint::Min(30), Constraint::Length(46)]).split(rows[0]);
        frame.render_widget(Paragraph::new(brand), top[0]);
        frame.render_widget(Paragraph::new(badges).alignment(Alignment::Right), top[1]);

        // The account chip is measured, not fixed-width: a guessed pane length is what
        // let the workspace path run into "ChatGPT Pro" with no seam between them.
        let right = (account.width() as u16).saturating_add(2).min(inner.width);
        let bottom =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(right)]).split(rows[1]);
        let subtitle = shell_subtitle(&context, &workspace, bottom[0].width as usize, app);
        frame.render_widget(Paragraph::new(subtitle), bottom[0]);
        frame.render_widget(
            Paragraph::new(account).alignment(Alignment::Right),
            bottom[1],
        );
    } else {
        frame.render_widget(Paragraph::new(brand), rows[0]);
        let subtitle = shell_subtitle(&context, &workspace, rows[1].width as usize, app);
        frame.render_widget(Paragraph::new(subtitle), rows[1]);
    }
}

/// The header's left half, fitted to the space it actually has.
///
/// The workspace segment is the flexible part: it ellipsizes while there is room to say
/// something useful and yields its place entirely when there is not, so this line never
/// relies on the renderer clipping it mid-path right beside the account chip.
fn shell_subtitle(context: &str, workspace: &str, budget: usize, app: &App) -> Line<'static> {
    use unicode_width::UnicodeWidthStr;

    let lead = "COMMAND WORKSPACE / LOCAL";
    let separator = "  ·  ";
    let context_style = if app.sessions.open.is_some() {
        theme::heading()
    } else {
        theme::action()
    };
    let mut spans = vec![
        Span::styled(lead.to_string(), theme::label()),
        Span::styled(separator.to_string(), Style::default().fg(theme::muted())),
        Span::styled(context.to_string(), context_style),
    ];

    let used = lead.width() + separator.width() + context.width();
    let room = budget.saturating_sub(used + separator.width());
    if !workspace.is_empty() && room >= 12 {
        spans.push(Span::styled(
            separator.to_string(),
            Style::default().fg(theme::muted()),
        ));
        spans.push(Span::styled(
            super::tree::truncate(workspace, room),
            Style::default().fg(theme::muted()),
        ));
    }

    Line::from(spans)
}

fn status_line(frame: &mut Frame, area: Rect, app: &App) {
    if let Some(notice) = &app.notice {
        let style = match notice.kind {
            NoticeKind::Info => Style::default().fg(theme::accent()),
            NoticeKind::Warn => Style::default().fg(theme::warn()),
            NoticeKind::Error => Style::default().fg(theme::bad()),
        };

        // The status line is one row, and a refusal that carried a remainder arrives with
        // a newline in it. Folded onto one line rather than truncated at it: the dialogs
        // are where a refusal is read in full, and this row must not silently end at a
        // break the operator cannot see.
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                notice.text.replace('\n', " · "),
                style,
            ))),
            area,
        );

        return;
    }

    // Read once for the whole row: gathering them walks the retained event window, and
    // both halves of the footer want the same answer.
    let facts = app.session_facts();
    let mut left = runtime_identity(app);
    left.extend(footer_facts(app, facts.as_ref()));
    let keys = footer_keys(app, facts.as_ref());

    if area.width >= 112 {
        // One ranking across both columns, not a budget each. The two halves compete for
        // the same row, so deciding independently is how a footer ends up with a `ctrl+q
        // quit` hint and no model on it.
        let (left, keys) = fit_pair(left, keys, area.width as usize);

        // Sized from what Ratatui will actually draw. A fixed 43-cell column clipped the
        // last digit off ordinary five-digit loopback ports, making two attached local
        // runtimes look identical in the footer.
        let keys_width = segments_width(&keys).min(area.width as usize) as u16;
        let columns =
            Layout::horizontal([Constraint::Min(1), Constraint::Length(keys_width)]).split(area);

        frame.render_widget(Paragraph::new(Line::from(join(left))), columns[0]);
        frame.render_widget(
            Paragraph::new(Line::from(join(keys))).alignment(Alignment::Right),
            columns[1],
        );
    } else if let Connection::Lost { reason } = &app.connection {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!(
                    "● DISCONNECTED · {} · ctrl+p commands",
                    super::tree::truncate(reason, area.width.saturating_sub(39) as usize)
                ),
                Style::default().fg(theme::bad()),
            )),
            area,
        );
    } else {
        // Narrow: one column, same ranking, and the runtime identity's detail is the
        // first thing to yield — it is on the Dashboard and in the header, and the open
        // session's facts are not anywhere else.
        left.extend(keys);
        frame.render_widget(
            Paragraph::new(Line::from(join(fit(left, area.width as usize)))),
            area,
        );
    }
}

/// `● LIVE` and the runtime it is live to, as two separately droppable facts.
fn runtime_identity(app: &App) -> Vec<Segment> {
    match &app.connection {
        Connection::Live => vec![
            Segment::new("● LIVE", Style::default().fg(theme::good()), 12),
            Segment::new(
                format!(
                    "{} · {} · {}",
                    if app.spawned() {
                        "OWN RUNTIME"
                    } else {
                        "ATTACHED"
                    },
                    if app.hello.scope.trim().is_empty() {
                        "scope?"
                    } else {
                        app.hello.scope.trim()
                    },
                    super::tree::truncate(&app.address, 22)
                ),
                Style::default().fg(theme::muted()),
                1,
            ),
        ],
        // A lost connection is the only fact on the row that matters, so both halves of
        // it outrank everything else.
        Connection::Lost { reason } => vec![
            Segment::new("● DISCONNECTED", Style::default().fg(theme::bad()), 13),
            Segment::new(
                super::tree::truncate(reason, 27),
                Style::default().fg(theme::bad()),
                11,
            ),
        ],
    }
}

/// One `·`-separated cell of the footer.
#[derive(Debug, Clone)]
struct Segment {
    text: String,
    style: Style,
    /// Lower drops first when the row runs out of room.
    rank: u8,
}

impl Segment {
    fn new(text: impl Into<String>, style: Style, rank: u8) -> Self {
        Self {
            text: text.into(),
            style,
            rank,
        }
    }

    fn key(text: impl Into<String>) -> Self {
        Self::new(text, Style::default().fg(theme::muted()), 8)
    }
}

/// Narrow on purpose. The header can afford `  ·  `; a footer carrying eight facts and
/// four keys spends a fifth of an eighty-column row on separators at that width.
const SEPARATOR: &str = " · ";

fn segments_width(segments: &[Segment]) -> usize {
    use unicode_width::UnicodeWidthStr;

    segments
        .iter()
        .map(|segment| segment.text.width())
        .sum::<usize>()
        + SEPARATOR.width() * segments.len().saturating_sub(1)
}

/// Drops the lowest-ranked segments until the rest fit, keeping display order.
///
/// Dropping rather than ellipsizing: a truncated `12.3k tok…` is a fact rendered as
/// noise, and the footer's job is to be readable at a glance in a 96-column tmux pane.
fn fit(mut segments: Vec<Segment>, budget: usize) -> Vec<Segment> {
    while segments.len() > 1 && segments_width(&segments) > budget {
        match weakest(&segments) {
            Some((index, _rank)) => {
                segments.remove(index);
            }
            None => break,
        }
    }

    if segments.len() == 1 && segments_width(&segments) > budget {
        segments[0].text = super::tree::truncate(&segments[0].text, budget);
    }

    segments
}

/// The gap the two columns keep between them when both are drawn.
const COLUMN_GAP: usize = 3;

/// Drops the globally weakest segment until the left column, the gap, and the right
/// column all fit on one row.
fn fit_pair(
    mut left: Vec<Segment>,
    mut keys: Vec<Segment>,
    budget: usize,
) -> (Vec<Segment>, Vec<Segment>) {
    loop {
        let width = segments_width(&left)
            + segments_width(&keys)
            + if left.is_empty() || keys.is_empty() {
                0
            } else {
                COLUMN_GAP
            };

        if width <= budget || left.len() + keys.len() <= 1 {
            break;
        }

        let from_left = weakest(&left);
        let from_keys = weakest(&keys);

        match (from_left, from_keys) {
            (Some((index, rank)), Some((_, other))) if rank <= other => {
                left.remove(index);
            }
            (_, Some((index, _))) => {
                keys.remove(index);
            }
            (Some((index, _)), None) => {
                left.remove(index);
            }
            (None, None) => break,
        }
    }

    (left, keys)
}

/// The index of the segment to drop next, and its rank. Ties go to the later one, so a
/// row shortens from its tail.
fn weakest(segments: &[Segment]) -> Option<(usize, u8)> {
    segments
        .iter()
        .enumerate()
        .min_by_key(|(index, segment)| (segment.rank, std::cmp::Reverse(*index)))
        .map(|(index, segment)| (index, segment.rank))
}

fn join(segments: Vec<Segment>) -> Vec<Span<'static>> {
    let mut spans = Vec::with_capacity(segments.len() * 2);

    for segment in segments {
        if !spans.is_empty() {
            spans.push(Span::styled(
                SEPARATOR,
                Style::default()
                    .fg(theme::muted())
                    .add_modifier(Modifier::DIM),
            ));
        }

        spans.push(Span::styled(segment.text, segment.style));
    }

    spans
}

/// What the open session is, in the order it reads best.
///
/// Every entry comes from `interactive.info` or from the event stream. Nothing here is a
/// client-side table of what a provider "usually" does, and a fact the runtime has not
/// reported is absent rather than guessed (D14).
fn footer_facts(app: &App, facts: Option<&SessionFacts>) -> Vec<Segment> {
    let Some(facts) = facts else {
        return Vec::new();
    };

    let mut segments = Vec::new();

    if let Some(model) = &facts.model {
        segments.push(Segment::new(
            super::tree::truncate(model, 28),
            Style::default().fg(theme::accent()),
            5,
        ));
    }

    if let Some((badge, style)) = mode_badge(facts.approval_mode.as_deref()) {
        segments.push(Segment::new(badge, style, 9));
    }

    // Its own cell rather than a suffix on the badge: the two are separate statements —
    // who is asked, and what can be written — and on a narrow row the first is the one
    // that has to survive.
    if let Some(sandbox) = &facts.sandbox_mode {
        segments.push(Segment::new(
            sandbox.replace('_', "-"),
            Style::default().fg(theme::muted()),
            6,
        ));
    }

    if facts.working {
        let elapsed = facts
            .elapsed_ms
            .map(|elapsed| format!(" {}", duration(elapsed)))
            .unwrap_or_default();

        // Ranked with `esc interrupt`, because they are one statement: something is
        // running, and this is the key that stops it.
        segments.push(Segment::new(
            format!("{} Working{elapsed}", theme::spinner(app.ticks)),
            Style::default().fg(theme::system()),
            10,
        ));
    }

    if let Some(queued) = facts.queued.filter(|queued| *queued > 0) {
        segments.push(Segment::new(
            format!("{queued} queued"),
            Style::default().fg(theme::muted()),
            4,
        ));
    }

    // G2. The open session's own approvals, and — beside them — how many rows across the
    // whole fleet are in each triage group. One cell, because they answer the same
    // question at two scales: what is waiting on me here, and what is waiting on me
    // anywhere. The fleet half is drawn only where there is more than one session, so a
    // single-session terminal keeps the cell it always had.
    let [needs, working, _done] = app.sessions.triage_counts();
    let fleet = if needs + working > 0 && app.sessions.merged().len() > 1 {
        format!(" · {needs} waiting · {working} working")
    } else {
        String::new()
    };

    if facts.approvals > 0 {
        segments.push(Segment::new(
            format!(
                "{} approval{}{fleet}",
                facts.approvals,
                if facts.approvals == 1 { "" } else { "s" }
            ),
            Style::default().fg(theme::warn()),
            11,
        ));
    } else if !fleet.is_empty() {
        segments.push(Segment::new(
            format!("{needs} waiting · {working} working"),
            Style::default().fg(if needs > 0 {
                theme::warn()
            } else {
                theme::muted()
            }),
            8,
        ));
    }

    if let Some(usage) = &facts.usage {
        if let Some(total) = usage.total_tokens.filter(|total| *total > 0) {
            // D9. The percentage is drawn only where *both* halves were reported, and the
            // numerator is `context_used` — what the last request actually cost — never
            // the session's cumulative spend, which crosses its own window many times
            // over on a long conversation. `/context` is preferred over the session row
            // because a row's `usage` is reduced by the runtime to tokens and cost; a
            // context meter divided by a number this client invented would be a lie
            // presented as a measurement, and so would one divided by the wrong number.
            let share = app
                .open_context_meter()
                .and_then(crate::model::native::SessionContext::share)
                .or_else(|| usage.context_share())
                .map(|share| format!(" · {share}%"))
                .unwrap_or_default();

            segments.push(Segment::new(
                format!("{} tokens{share}", tokens(total)),
                Style::default().fg(theme::muted()),
                3,
            ));
        }

        if let Some(cost) = usage.cost_usd.filter(|cost| *cost > 0.0) {
            // I2. `[budget] max_cost_usd` is a soft limit: past it the cell turns WARN and
            // a notice is said once. Nothing is stopped — a client cannot refuse a turn the
            // runtime runs, and colouring a number is the whole of what it can honestly do.
            // Ranked up with it, so the row that carries the warning is the last to drop
            // the cell it is about.
            let over = app
                .config
                .budget
                .max_cost_usd()
                .is_some_and(|limit| cost >= limit);

            segments.push(Segment::new(
                money(cost),
                if over {
                    Style::default().fg(theme::warn())
                } else {
                    Style::default().fg(theme::muted())
                },
                if over { 11 } else { 2 },
            ));
        }
    }

    segments
}

/// The keys this footer is allowed to advertise.
///
/// `esc interrupt` appears only while a turn is running *and* the session's transport
/// declared an interrupt — a footer that offers a key the open session cannot honour is
/// the exact failure D14 names.
fn footer_keys(app: &App, facts: Option<&SessionFacts>) -> Vec<Segment> {
    // B8/D14: the chord comes out of the resolved keymap, so a rebound key is the one the
    // footer offers. A key an operator set to `off` produces no hint at all, for the same
    // reason a transport that cannot steer gets no steer hint — advertising a key that
    // does nothing is how an operator learns a chord by being ignored by it.
    let hint = |action: Action, verb: &str| -> Option<String> {
        app.bound(action)
            .then(|| format!("{} {verb}", app.keymap.label(action)))
    };

    if app.tab != Tab::Sessions {
        let mut keys = Vec::new();

        if let Some(text) = hint(Action::Palette, "commands") {
            keys.push(Segment::key(text));
        }

        keys.push(Segment::key("Esc returns to coding"));
        keys.push(Segment::key("r refresh"));
        return keys;
    }

    let mut keys = Vec::new();

    if app.interrupt_offered_for(facts) {
        if let Some(text) = hint(Action::Interrupt, "interrupt") {
            keys.push(Segment::new(
                text,
                Style::default().fg(theme::action_colour()),
                10,
            ));
        }
    }

    if let Some(text) = hint(Action::Palette, "commands") {
        keys.push(Segment::key(text));
    }

    // B9. Until three prompts have been sent, the row points at the page that explains
    // the rest of it. Ranked lowest of everything so it is the first thing a narrow
    // terminal drops: a hint is worth having and never worth a fact.
    if app.onboarding() {
        if let Some(text) = hint(Action::Help, "new here") {
            keys.push(Segment::new(text, Style::default().fg(theme::accent()), 1));
        }
    }

    // Discoverable through the palette and `?`; the first to yield when the row is tight.
    for action in [Action::Leader, Action::Quit] {
        let verb = if action == Action::Leader {
            "leader"
        } else {
            "quit"
        };

        if let Some(text) = hint(action, verb) {
            keys.push(Segment::new(text, Style::default().fg(theme::muted()), 0));
        }
    }

    keys
}

/// The permission-mode badge, in the vocabulary the field converged on: `⏸` for "ask me",
/// `⏵⏵` for "edit without asking", `✓` for "never ask".
///
/// `None` when the runtime did not report a mode. That is the ordinary case for a session
/// started without one — the plane's own default then applies, and this client does not
/// know what it is. Naming a guess would be worse than saying nothing.
fn mode_badge(approval_mode: Option<&str>) -> Option<(String, Style)> {
    let mode = approval_mode?;

    let (glyph, style) = match mode {
        "prompt" => ("⏸", Style::default().fg(theme::good())),
        "auto_edit" => ("⏵⏵", Style::default().fg(theme::action_colour())),
        "auto_approve" => ("✓", Style::default().fg(theme::warn())),
        // `default` and anything a later runtime adds: named, not glossed.
        _stated => ("⏵", Style::default().fg(theme::muted())),
    };

    Some((format!("{glyph} {}", mode.replace('_', "-")), style))
}

/// Codex's elapsed format: `4m 07s`, and an hour where there is one.
fn duration(milliseconds: u64) -> String {
    let seconds = milliseconds / 1_000;
    let (hours, minutes, seconds) = (seconds / 3_600, (seconds / 60) % 60, seconds % 60);

    match (hours, minutes) {
        (0, 0) => format!("{seconds}s"),
        (0, _) => format!("{minutes}m {seconds:02}s"),
        _ => format!("{hours}h {minutes:02}m"),
    }
}

/// Token counts, short enough for a footer and never rounded up to a wrong order of
/// magnitude.
pub fn tokens(total: u64) -> String {
    match total {
        0..=999 => total.to_string(),
        1_000..=999_999 => format!("{:.1}k", total as f64 / 1_000.0),
        _ => format!("{:.1}M", total as f64 / 1_000_000.0),
    }
}

/// Cost, to the cent, with a spend too small to show said as too small rather than as
/// zero.
pub fn money(cost: f64) -> String {
    if cost < 0.005 {
        return "<$0.01".to_string();
    }

    format!("${cost:.2}")
}

fn overlay(frame: &mut Frame, area: Rect, app: &App) {
    let Some(overlay) = &app.overlay else {
        return;
    };

    // Preserve spatial context behind a modal, but drop it out of the active visual
    // hierarchy. This also keeps the few columns outside a narrow popup from competing
    // with wrapped dialog copy.
    frame
        .buffer_mut()
        .set_style(area, Style::default().add_modifier(Modifier::DIM));

    match overlay {
        Overlay::Commands(palette) => command_palette(frame, area, app, palette),
        Overlay::Account(dialog) => account_dialog(frame, area, app, dialog),
        Overlay::SessionPicker { selected } => session_picker(frame, area, app, selected.as_ref()),
        Overlay::Help => help(frame, area, app),
        // B8/I2. Both draw in [`super::panels`]: this file is where parallel work
        // collides, and neither page needs anything from it but `centered`.
        Overlay::Keys { scroll } => super::panels::keymap(frame, area, app, *scroll),
        Overlay::Cost { scroll } => super::panels::cost(frame, area, app, *scroll),
        Overlay::Quit { options, choice } => chooser(
            frame,
            area,
            "quit",
            &quit_detail(app),
            &options
                .iter()
                .map(|(label, _)| label.clone())
                .collect::<Vec<_>>(),
            *choice,
        ),
        Overlay::Confirm {
            title,
            detail,
            options,
            choice,
        } => chooser(
            frame,
            area,
            title,
            detail,
            &options
                .iter()
                .map(|(label, _)| label.clone())
                .collect::<Vec<_>>(),
            *choice,
        ),
        Overlay::Approval {
            id,
            request_id,
            subject,
            choice,
            detail,
            rule,
            rule_absent,
            expanded,
            ..
        } => approval(
            frame,
            area,
            ApprovalModal {
                id,
                request_id,
                subject,
                detail,
                rule: rule.as_ref(),
                rule_absent: *rule_absent,
                choice: *choice,
                expanded: *expanded,
            },
        ),
        Overlay::Prompt { label, buffer, .. } => prompt(frame, area, label, buffer),
        Overlay::New(dialog) => new_session(frame, area, app, dialog),
        Overlay::Backtrack {
            entries,
            choice,
            fork_offered,
            rewind_offered,
            ..
        } => backtrack(
            frame,
            area,
            entries,
            *choice,
            *fork_offered,
            *rewind_offered,
        ),
        // D9/D6/G1. All three draw in [`super::panels`], beside `/keys` and `/cost`: this
        // file is where parallel work collides, and none of them needs anything from it.
        Overlay::Context { context, scroll } => {
            super::panels::context(frame, area, context, *scroll)
        }
        Overlay::Rewind {
            points,
            choice,
            what,
            confirming,
            ..
        } => super::panels::rewind(frame, area, points, *choice, *what, *confirming),
        Overlay::Delegations { rows, choice, .. } => {
            super::panels::delegations(frame, area, rows, *choice)
        }
        Overlay::Peek {
            title, text, id, ..
        } => super::panels::peek(frame, area, app, title, id, text.as_deref()),
        Overlay::Settings(settings) => self_settings(frame, area, app, settings),
        Overlay::Machines(machines_state) => machines(frame, area, app, machines_state),
        Overlay::Diff(state) => changed_files(frame, area, state),
    }
}

/// Claude Code's `/diff`, scoped to what a client that never reads the filesystem holds.
///
/// `←`/`→` moves between "this session" and one scope per turn that changed a file, `↑`/`↓`
/// picks a file, `Enter` opens it in a pager inside the overlay, `Esc` steps back out. The
/// footer states the scope's own totals and, when the window dropped history, says the list
/// is partial — a file list that looked like the session and was not would be worse than no
/// list at all.
fn changed_files(frame: &mut Frame, area: Rect, state: &super::diff::DiffOverlay) {
    let popup = centered(area, if area.width < 100 { 96 } else { 78 }, area.height);
    frame.render_widget(Clear, popup);

    let rows = state.rows();
    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .border_style(Style::default().fg(theme::muted()))
        .title(Line::from(vec![
            Span::styled(" /diff ", theme::heading()),
            Span::styled(state.scope_label(), Style::default().fg(theme::accent())),
            Span::styled(
                format!(
                    "  +{} −{} ",
                    rows.iter().map(|row| row.file.additions).sum::<usize>(),
                    rows.iter().map(|row| row.file.deletions).sum::<usize>()
                ),
                Style::default().fg(theme::muted()),
            ),
        ]));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let panes = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(inner);
    let width = panes[0].width.max(8) as usize;
    let height = panes[0].height.max(1) as usize;

    let mut body: Vec<Line<'static>> = Vec::new();

    if rows.is_empty() {
        body.push(Line::from(Span::styled(
            "No file changes reached this client in this scope.",
            Style::default().fg(theme::muted()),
        )));
    } else if let Some(offset) = state.pager {
        let Some(open) = state.current() else {
            return;
        };
        body.push(Line::from(vec![
            Span::styled(
                format!("{} {} ", open.file.status.mark(), open.file.path),
                Style::default().fg(open.file.status.colour()),
            ),
            Span::styled(
                format!("+{} −{}", open.file.additions, open.file.deletions),
                Style::default().fg(theme::muted()),
            ),
        ]));
        body.push(Line::from(""));

        // The whole file is laid out and then windowed, so `↓` moves one row rather than
        // one hunk and the pager cannot run off the end of a file it has not measured.
        let mut file_lines = Vec::new();
        super::diff::render_file(
            &mut file_lines,
            &open.file,
            super::diff::Layout::new(width, super::diff::MAX_OVERLAY_ROWS),
        );
        let last = file_lines.len().saturating_sub(1);
        let start = offset.min(last);
        body.extend(file_lines.into_iter().skip(start).take(height));
    } else {
        let numbers = rows
            .iter()
            .map(|row| format!("+{} −{}", row.file.additions, row.file.deletions).len())
            .max()
            .unwrap_or(0);

        for (index, row) in rows.iter().enumerate() {
            let selected = index == state.selected;
            let stats = format!(
                "{:>numbers$}",
                format!("+{} −{}", row.file.additions, row.file.deletions)
            );
            body.push(Line::from(vec![
                Span::styled(
                    if selected { "› " } else { "  " },
                    Style::default().fg(theme::accent()),
                ),
                Span::styled(
                    format!("{} ", row.file.status.mark()),
                    Style::default().fg(row.file.status.colour()),
                ),
                Span::styled(
                    super::tree::truncate(&row.file.path, width.saturating_sub(numbers + 8)),
                    if selected {
                        theme::selected()
                    } else {
                        Style::default()
                    },
                ),
                Span::raw("  "),
                Span::styled(stats, Style::default().fg(theme::muted())),
                Span::styled(
                    if row.in_excerpt { "  in excerpt" } else { "" },
                    Style::default().fg(theme::warn()),
                ),
            ]));
        }
    }

    frame.render_widget(Paragraph::new(body), panes[0]);

    let keys = if state.pager.is_some() {
        "↑/↓ scroll · pgup/pgdn page · esc back to the list"
    } else {
        "↑/↓ file · ←/→ scope · enter opens · esc closes"
    };
    let scope = format!(
        "{} of {} · {}",
        state.scope + 1,
        state.scopes(),
        if state.pruned > 0 {
            format!(
                "only what this client holds — everything at or below sequence {} was dropped",
                state.pruned
            )
        } else {
            "every change this client has seen in this session".to_string()
        }
    );

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(keys, Style::default().fg(theme::muted()))),
            Line::from(Span::styled(scope, Style::default().fg(theme::muted()))),
        ]),
        panes[1],
    );
}

fn command_palette(frame: &mut Frame, area: Rect, app: &App, palette: &CommandPalette) {
    let commands = app.palette_commands(palette);
    let width = if area.width >= 110 {
        // Widened first: `u16 * 40` overflows in a debug build at 1639 columns, which is an
        // ordinary width for a full-screen terminal on a wide display.
        (u32::from(area.width) * 40 / 100) as u16
    } else {
        area.width.saturating_sub(4)
    };
    let height = 28.min(area.height.saturating_sub(4));
    let popup = Rect::new(
        area.right().saturating_sub(width + 2),
        area.y
            .saturating_add(5)
            .min(area.bottom().saturating_sub(height)),
        width,
        height,
    );

    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .border_style(Style::default().fg(theme::muted()))
        .title(Line::from(vec![
            Span::styled(" ctrl+p commands", Style::default().fg(theme::muted())),
            Span::styled(format!(" · {} ", commands.len()), theme::quiet()),
        ]));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("↑↓", Style::default().fg(theme::muted())),
            Span::styled(
                " navigate   enter select   esc close",
                Style::default().fg(theme::muted()),
            ),
        ]))
        .alignment(Alignment::Right),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  search  ", Style::default().fg(theme::muted())),
            Span::raw(if palette.query.is_empty() {
                "type a command".to_string()
            } else {
                palette.query.clone()
            }),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ]))
        .block(Block::default().borders(access::borders(Borders::ALL))),
        rows[1],
    );

    let mut lines = Vec::new();
    let mut previous_group = "";
    let mut selected_line = 0;
    let content_width = rows[2].width as usize;

    for (index, command) in commands.iter().enumerate() {
        if command.group() != previous_group {
            if !previous_group.is_empty() {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                command.group(),
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD),
            )));
            previous_group = command.group();
        }

        let selected = index == palette.selected;
        if selected {
            selected_line = lines.len();
        }
        let prefix = if selected { "  › " } else { "    " };
        let start = format!("{prefix}{}", command.label());
        // B8/D14: the keymap, never a literal. A command whose chord the operator rebound
        // shows the chord they rebound it to.
        let shortcut = app.command_shortcut(*command);
        let gap = content_width.saturating_sub(start.chars().count() + shortcut.chars().count());
        let row = format!("{start}{}{shortcut}", " ".repeat(gap));

        lines.push(if selected {
            Line::styled(row, theme::selected())
        } else {
            Line::from(vec![
                Span::raw(row[..row.len().saturating_sub(shortcut.len())].to_string()),
                Span::styled(shortcut, Style::default().fg(theme::muted())),
            ])
        });
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("no command matches \"{}\"", palette.query.trim()),
            Style::default().fg(theme::muted()),
        )));
    }

    let height = rows[2].height as usize;
    let start = selected_line.saturating_sub(height.saturating_sub(1));
    let end = (start + height).min(lines.len());
    frame.render_widget(Paragraph::new(lines[start..end].to_vec()), rows[2]);
}

/// The managed sign-in dialog.
///
/// The device code is the one thing the operator has to read off this screen and type
/// somewhere else, so it is the first thing on it. It used to follow the URL, and on an
/// 80-column terminal a long verification URL wrapped far enough to push the code out of a
/// fixed-height popup — the dialog showed everything except the part that was the point.
/// The URL is cut to one line instead, `o` reopens it in a browser, and the popup is sized
/// to what it holds.
fn account_dialog(frame: &mut Frame, area: Rect, app: &App, dialog: &AccountDialog) {
    let connected = app.chatgpt_connected();
    let mut lines = Vec::new();

    if connected {
        let account = app
            .account
            .value
            .as_ref()
            .and_then(|state| state.account.as_ref());
        let plan = app
            .account
            .value
            .as_ref()
            .and_then(|state| state.plan_label())
            .unwrap_or_else(|| "connected".to_string());
        lines.push(Line::from(Span::styled(
            format!("ChatGPT {plan}"),
            Style::default()
                .fg(theme::good())
                .add_modifier(Modifier::BOLD),
        )));
        if let Some(email) = account.and_then(|account| account.email.as_deref()) {
            lines.push(Line::from(Span::styled(
                email.to_string(),
                Style::default().fg(theme::muted()),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Codex keeps the subscription credentials on the runtime host.",
        ));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Enter/Esc closes  ·  l disconnects",
            Style::default().fg(theme::muted()),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            match dialog.flow {
                AccountFlow::Browser => "Connect your ChatGPT subscription in the browser.",
                AccountFlow::DeviceCode => {
                    "Connect ChatGPT to the runtime host with a device code."
                }
            },
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        // First, and unabbreviated: this is the string a person has to carry to another
        // device, and it is short enough to always fit.
        if let Some(code) = &dialog.code {
            lines.push(Line::from(vec![
                Span::styled("Code  ", theme::label()),
                Span::styled(
                    code.clone(),
                    Style::default()
                        .fg(theme::warn())
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(""));
        }

        if let Some(url) = &dialog.url {
            // Cut rather than wrapped. A sign-in URL is not something anyone retypes, and a
            // popup that grew three rows to show one in full would push the code off it.
            lines.push(Line::from(vec![
                Span::styled("Open  ", theme::label()),
                Span::styled(
                    super::tree::truncate(url, ACCOUNT_INNER.saturating_sub(6)),
                    Style::default().fg(theme::accent()),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                "      press o to open it in a browser",
                Style::default().fg(theme::muted()),
            )));
        }

        if dialog.url.is_none() && dialog.pending {
            lines.push(Line::from(Span::styled(
                format!("{} preparing a secure sign-in", theme::spinner(app.ticks)),
                Style::default().fg(theme::accent()),
            )));
        } else if dialog.pending {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("{} waiting for ChatGPT", theme::spinner(app.ticks)),
                Style::default().fg(theme::accent()),
            )));
        }

        if let Some(error) = &dialog.error {
            lines.push(Line::from(""));
            lines.extend(refusal_lines(error));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Esc cancels. Ouroboros never receives or stores your token.",
            Style::default().fg(theme::muted()),
        )));
    }

    // Sized to what it holds, and clamped to the frame: a fixed height clipped the last
    // rows of this dialog on a short terminal, and those rows are the ones that say what to
    // press.
    let height = (wrapped(&lines, inner_width(area, ACCOUNT_WIDTH)) + 2).min(area.height);
    let popup = centered(area, ACCOUNT_WIDTH, height);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(" ChatGPT account ", theme::heading()));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// How wide the account dialog is, as a percentage of the frame.
const ACCOUNT_WIDTH: u16 = 58;

/// The narrowest that percentage can be: 58% of an 80-column terminal, less the border.
const ACCOUNT_INNER: usize = 80 * 58 / 100 - 2;

fn session_picker(frame: &mut Frame, area: Rect, app: &App, selected: Option<&(Plane, String)>) {
    let rows = app.sessions.triaged();
    let sessions: Vec<_> = rows.iter().map(|(_group, session)| *session).collect();
    let height = (sessions.len() + 5).clamp(7, 20) as u16;
    let popup = centered(area, 72, height);
    frame.render_widget(Clear, popup);

    // G2. The counts are in the title rather than in heading rows, because this is a
    // `List` whose selection is an index: a heading row would be selectable, and a
    // selectable row that cannot be opened is a row that lies about what Enter does. The
    // grouping is still visible on every row, in the column below.
    let [needs, working, done] = app.sessions.triage_counts();

    // The counts above and the keys below: at eighty columns one title cannot hold both,
    // and dropping the keys would leave a list whose two new verbs nobody ever finds.
    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(
            format!(" sessions · {needs} need input · {working} working · {done} done "),
            theme::heading(),
        ))
        .title_bottom(Span::styled(
            " space peek · r reply · enter open · x end ",
            Style::default().fg(theme::muted()),
        ));

    if sessions.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                if app.sessions.interactive.pending || app.sessions.coding.pending {
                    "Listing sessions…"
                } else {
                    "No sessions yet. Esc closes; use New session from ctrl+p."
                },
                Style::default().fg(theme::muted()),
            ))
            .block(block),
            popup,
        );
        return;
    }

    let choice = app.sessions.picker_index(selected);
    let items = rows
        .iter()
        .map(|(group, session)| {
            let mut spans = vec![
                Span::styled(
                    format!("{:<12}", group.label().to_ascii_lowercase()),
                    match group {
                        crate::model::Triage::NeedsInput => Style::default().fg(theme::warn()),
                        crate::model::Triage::Working => Style::default().fg(theme::system()),
                        crate::model::Triage::Done => Style::default().fg(theme::muted()),
                    },
                ),
                Span::styled(
                    format!("{:<6}", session.plane.tag()),
                    Style::default().fg(theme::muted()),
                ),
                Span::raw(super::tree::truncate(&session.id, 36)),
            ];

            // G2. Which machine, on the row, because the list spans every fleet node.
            if let Some(node) = session.node.as_deref() {
                spans.push(Span::styled(
                    format!("  {}", super::tree::truncate(node, 24)),
                    Style::default().fg(theme::muted()),
                ));
            }
            if let Some(owners) = app.sessions.owner_conflict(session.plane, &session.id) {
                spans.push(Span::styled(
                    format!(
                        "  ID conflict · {}",
                        super::tree::truncate(&owners.join(" + "), 46)
                    ),
                    Style::default().fg(theme::bad()),
                ));
            } else if session.last_known {
                spans.push(Span::styled(
                    format!("  last-known · owner offline · {}", session.status.as_str()),
                    Style::default().fg(theme::warn()),
                ));
            } else {
                spans.push(Span::styled(
                    format!("  {}", session.status.as_str()),
                    theme::session_status(&session.status),
                ));
            }

            // I2. `tokens · cost`, where the runtime reported one. `interactive.list` does
            // not carry `usage` on every gateway and never will on `coding.list`; a row
            // without it shows nothing rather than a zero that reads as a free session.
            if let Some(cell) = super::panels::usage_cell(session.usage.as_ref()) {
                spans.push(Span::styled(
                    format!("  {cell}"),
                    Style::default().fg(theme::muted()),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(choice));
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(theme::selected()),
        popup,
        &mut state,
    );
}

/// How wide the settings overlay is, as a percentage of the frame. Named because its height
/// is computed against the same number and the two must not drift apart.
const SETTINGS_WIDTH: u16 = 80;
const MACHINES_WIDTH: u16 = 104;

/// The drawable width inside a popup of `percent`, which is what a line has to fit in.
fn inner_width(area: Rect, percent: u16) -> usize {
    ((area.width as usize) * (percent as usize) / 100).saturating_sub(2)
}

/// How many terminal rows these lines occupy once `Wrap` has had them.
///
/// An estimate of ratatui's own wrapping rather than a call into it: `Paragraph` will not
/// say how tall it wants to be, and a panel sized to `lines.len()` silently loses whatever
/// wrapped — which on these screens is a line naming a path, the worst kind to half-show.
///
/// Deliberately one row long for anything that wraps at all. `Wrap` breaks on words, so a
/// label followed by an unbreakable 140-character path takes *three* rows where the
/// character count says two: the path does not fit beside the label, so it starts on a row
/// of its own. Erring long costs blank space in a popup that is clamped to the frame
/// anyway; erring short costs the path.
fn wrapped(lines: &[Line<'_>], inner: usize) -> u16 {
    if inner == 0 {
        return lines.len() as u16;
    }

    lines
        .iter()
        .map(|line| {
            let width = line.width();

            if width <= inner {
                1
            } else {
                width.div_ceil(inner) as u16 + 1
            }
        })
        .sum()
}

/// The `,` overlay. Facts above, preferences below, and the line between them labelled.
fn self_settings(frame: &mut Frame, area: Rect, app: &App, settings: &Settings) {
    let facts = vec![
        Line::from(Span::styled(
            "as reported by the runtime — not editable here",
            theme::label(),
        )),
        field("address", &app.address),
        field("node", &blank(&app.hello.node)),
        field("scope", &blank(&app.hello.scope)),
        field("protocol", &app.hello.protocol.to_string()),
        field(
            "data dir",
            &match &app.data_dir {
                Some(dir) => dir.clone(),
                None => "not this client's — it attached to a runtime it did not start".into(),
            },
        ),
        field(
            "config",
            &match &app.config_path {
                Some(path) => path.display().to_string(),
                None => "nowhere: neither XDG_CONFIG_HOME nor a home directory is set".into(),
            },
        ),
        Line::from(""),
        Line::from(Span::styled(
            "machines opens a guided setup; the other rows are this client's session defaults",
            theme::label(),
        )),
    ];

    // The facts wrap, because the one most likely to overflow is the path of the file this
    // overlay writes — and a half-shown path is a path nobody can act on.
    let width = inner_width(area, SETTINGS_WIDTH);
    let fact_rows = wrapped(&facts, width);

    // Two footer rows plus a blank, on top of the facts and the editable rows.
    let height = fact_rows + SettingsField::ALL.len() as u16 + 5;
    let popup = centered(area, SETTINGS_WIDTH, height.min(area.height));

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(" settings ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(fact_rows),
            Constraint::Length(SettingsField::ALL.len() as u16),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(Paragraph::new(facts).wrap(Wrap { trim: false }), chunks[0]);

    let choices = provider_choices(
        app.providers.value.as_deref().unwrap_or_default(),
        app.config.defaults.provider.as_deref(),
    );

    let mut rows = Vec::new();
    let machine_summary = app.machine_summary();

    for row in SettingsField::ALL {
        let focused = row == settings.field;

        let (label, value, style) = match row {
            SettingsField::Machines => {
                let expected = machine_summary
                    .expected
                    .map(|expected| expected.to_string())
                    .unwrap_or_else(|| "?".into());
                let value = if machine_summary.mode == "Standalone" {
                    "standalone · open to create or join a fleet".to_string()
                } else {
                    let security = match machine_summary.security {
                        MachineSecurity::Secure => "secure",
                        MachineSecurity::Insecure => "TLS not active",
                        MachineSecurity::Mismatch => "configuration mismatch",
                        MachineSecurity::Unknown => "security unknown",
                        MachineSecurity::Standalone => "standalone",
                    };
                    format!(
                        "{}/{} connected · {}",
                        machine_summary.connected, expected, security
                    )
                };
                let style = match machine_summary.security {
                    MachineSecurity::Secure | MachineSecurity::Standalone => {
                        Style::default().fg(theme::good())
                    }
                    MachineSecurity::Insecure | MachineSecurity::Mismatch => {
                        Style::default().fg(theme::bad())
                    }
                    MachineSecurity::Unknown => Style::default().fg(theme::warn()),
                };
                ("machines", value, style)
            }
            SettingsField::Provider => {
                let (value, style) = settings_provider_cell(&choices, settings.provider, app);
                ("provider", value, style)
            }
            SettingsField::Workspace => (
                "workspace",
                text_or_hint(&settings.workspace, "unset — stated per session"),
                hint_style(&settings.workspace),
            ),
            SettingsField::ApprovalMode => {
                ("approval", settings.approval_label(), Style::default())
            }
            SettingsField::SandboxMode => ("files", settings.sandbox_label(), Style::default()),
            SettingsField::Save => (
                "",
                "[ save ]".to_string(),
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD),
            ),
        };

        let mut spans = vec![
            Span::styled(
                if focused { "> " } else { "  " },
                Style::default().fg(theme::accent()),
            ),
            // A fixed label column keeps edited preferences scannable.
            Span::styled(format!("{label:<12}"), theme::label()),
            Span::styled(value, style),
        ];

        if focused && row == SettingsField::Workspace {
            spans.push(Span::styled(
                "_",
                Style::default().add_modifier(Modifier::SLOW_BLINK),
            ));
        }

        rows.push(Line::from(spans));
    }

    frame.render_widget(Paragraph::new(rows), chunks[1]);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Tab/arrows move · Enter opens Machines or advances · Enter on [ save ] writes \
                 the file · Esc closes",
                Style::default().fg(theme::muted()),
            )),
            Line::from(Span::styled(
                if settings.edited {
                    "changed, and not written yet"
                } else {
                    ""
                },
                Style::default().fg(theme::warn()),
            )),
        ])
        .wrap(Wrap { trim: false }),
        chunks[2],
    );
}

/// Settings → Machines: a menu of fleet actions that run after confirm, not a CLI cheat sheet.
fn machines(frame: &mut Frame, area: Rect, app: &App, machines: &Machines) {
    let items = app.machine_menu_for(machines);
    let height = match (&machines.add, &machines.form, &machines.report) {
        (Some(add), _, _) if add.step == AddStep::Pick => 8 + machines.candidates.len() as u16,
        (Some(_), _, _) | (_, Some(_), _) | (_, _, Some(_)) => 36,
        _ => 10 + items.len() as u16 + 8,
    };
    let popup = centered(area, MACHINES_WIDTH, height.min(area.height));

    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(" machines ", theme::heading()));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    if let Some(add) = machines.add.as_ref() {
        add_machine(frame, inner, app, machines, add);
        return;
    }
    if let Some(form) = machines.form.as_ref() {
        machine_form(frame, inner, form);
        return;
    }
    if let Some(report) = machines.report.as_ref() {
        machine_report(frame, inner, report);
        return;
    }

    let summary = app.machine_summary();

    let rows = Layout::vertical([
        Constraint::Length(6),
        Constraint::Length(items.len() as u16 + 1),
        Constraint::Min(4),
        Constraint::Length(2),
    ])
    .split(inner);

    let expected = summary
        .expected
        .map(|expected| expected.to_string())
        .unwrap_or_else(|| "unknown".into());
    let offline = summary
        .offline
        .map(|offline| offline.to_string())
        .unwrap_or_else(|| "unknown".into());
    let fleet = summary
        .fleet
        .as_deref()
        .map(|fleet| super::tree::truncate(fleet, 44))
        .unwrap_or_else(|| {
            if summary.mode == "Standalone" {
                "not created yet".into()
            } else {
                "name unavailable from this connection".into()
            }
        });
    let local = match &summary.host {
        Some(host) => format!("{} at {host}", summary.machine),
        None => summary.machine.clone(),
    };
    let security_style = match summary.security {
        MachineSecurity::Standalone | MachineSecurity::Secure => Style::default().fg(theme::good()),
        MachineSecurity::Insecure | MachineSecurity::Mismatch => Style::default().fg(theme::bad()),
        MachineSecurity::Unknown => Style::default().fg(theme::warn()),
    };
    let mut facts = vec![
        Line::from(vec![
            Span::styled(format!("{} · ", summary.mode), theme::heading()),
            Span::raw(fleet),
        ]),
        Line::from(Span::raw(local)),
        Line::from(vec![
            Span::raw(format!(
                "Known {expected} · Connected {} · Offline {offline} · ",
                summary.connected
            )),
            Span::styled(summary.security.label(), security_style),
        ]),
        Line::from(Span::styled(summary.recovery, theme::label())),
        Line::from(Span::styled(
            "Boundary: live provider work does not migrate after a full host loss.",
            Style::default().fg(theme::warn()),
        )),
    ];
    if !summary.offline_names.is_empty() {
        facts.push(Line::from(Span::styled(
            format!("Offline: {}", summary.offline_names.join(", ")),
            Style::default().fg(theme::warn()),
        )));
    }
    frame.render_widget(Paragraph::new(facts).wrap(Wrap { trim: false }), rows[0]);

    let mut actions = vec![Line::from(Span::styled(
        "Enter runs the selected action",
        theme::label(),
    ))];
    let selected = machines.selected.min(items.len().saturating_sub(1));
    for (index, item) in items.iter().copied().enumerate() {
        let focused = selected == index;
        actions.push(Line::from(vec![
            Span::styled(
                if focused { "> " } else { "  " },
                Style::default().fg(theme::accent()),
            ),
            Span::styled(format!("{:<28}", item.label(machines)), Style::default()),
            Span::styled(item.hint(machines), Style::default().fg(theme::muted())),
        ]));
    }
    frame.render_widget(Paragraph::new(actions), rows[1]);

    let mut detail = Vec::new();
    if let Some(item) = items.get(selected).copied() {
        detail.push(Line::from(Span::styled(
            item.label(machines),
            theme::heading(),
        )));
        detail.push(Line::from(item.preview().to_string()));
        detail.push(Line::from(Span::styled(
            item.command(machines),
            Style::default().fg(theme::accent()),
        )));
    }
    frame.render_widget(Paragraph::new(detail).wrap(Wrap { trim: false }), rows[2]);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "↑↓ choose · Enter run · y copy CLI · r refresh · Esc close",
            Style::default().fg(theme::muted()),
        ))),
        rows[3],
    );
}

fn machine_form(frame: &mut Frame, area: Rect, form: &MachineForm) {
    let mut lines = vec![Line::from(Span::styled(form.title(), theme::heading()))];
    lines.push(Line::from(""));
    match form.step {
        AddStep::Form => {
            for (index, field) in form.fields().iter().copied().enumerate() {
                let focused = form.field == index;
                lines.push(form_field_row(form, field, focused));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Tab moves · Enter reviews · Esc back",
                Style::default().fg(theme::muted()),
            )));
        }
        AddStep::Confirm => {
            lines.push(Line::from("Review, then Enter runs this on this machine:"));
            lines.push(Line::from(""));
            match form.kind {
                FormKind::Create => {
                    lines.push(form_fact("this Mac", &form.machine));
                    lines.push(form_fact("host", &form.host));
                    lines.push(Line::from(
                        "The running standalone daemon will stop, this Mac becomes the owner, then the TUI comes back.",
                    ));
                }
                FormKind::Join => {
                    lines.push(form_fact("invitation", &form.path));
                    lines.push(form_fact(
                        "delete after join",
                        if form.delete_invite { "yes" } else { "no" },
                    ));
                    lines.push(form_fact(
                        "write recovery unit",
                        if form.install_service { "yes" } else { "no" },
                    ));
                    lines.push(Line::from(
                        "The invitation file is never printed. This machine restarts once to join.",
                    ));
                }
                FormKind::Invite => {
                    lines.push(form_fact("machine", &form.machine));
                    lines.push(form_fact("host", &form.host));
                    lines.push(form_fact(
                        "out",
                        if form.path.trim().is_empty() {
                            "private pending file"
                        } else {
                            form.path.trim()
                        },
                    ));
                    lines.push(Line::from(
                        "The file stays mode 0600. Copy it privately; contents never appear here.",
                    ));
                }
                FormKind::Service => {
                    lines.push(Line::from(
                        "Writes a launchd or systemd user unit. It does not start the daemon.",
                    ));
                    lines.push(Line::from(
                        "After it writes, run the activation command it prints. Do not also run ouro daemon.",
                    ));
                }
                FormKind::SyncExport => {
                    lines.push(form_fact("roster", &form.path));
                    lines.push(Line::from(
                        "Copy the signed roster privately. Import on other members still needs them stopped.",
                    ));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter run · y copy CLI · Esc back",
                Style::default().fg(theme::muted()),
            )));
        }
        AddStep::Working => {
            lines.push(Line::from("Working…"));
            for line in &form.log {
                lines.push(Line::from(line.clone()));
            }
        }
        AddStep::Done => {
            lines.push(Line::from(Span::styled(
                "Done",
                Style::default().fg(theme::good()),
            )));
            for line in &form.log {
                lines.push(Line::from(line.clone()));
            }
            if let Some(recipe) = &form.recipe {
                lines.push(Line::from(""));
                for line in recipe.lines() {
                    lines.push(Line::from(line.to_string()));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter or Esc back to the menu · y copy result",
                Style::default().fg(theme::muted()),
            )));
        }
        AddStep::Method | AddStep::Pick => {}
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(theme::bad()),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn form_field_row(form: &MachineForm, field: FormField, focused: bool) -> Line<'static> {
    let (label, value) = match field {
        FormField::Machine => (
            "machine",
            if form.machine.is_empty() {
                "—"
            } else {
                form.machine.as_str()
            }
            .to_string(),
        ),
        FormField::Host => (
            "host",
            if form.host.is_empty() {
                "—"
            } else {
                form.host.as_str()
            }
            .to_string(),
        ),
        FormField::Path => (
            match form.kind {
                FormKind::Join => "invitation",
                FormKind::Invite => "out",
                FormKind::SyncExport => "roster",
                _ => "path",
            },
            if form.path.is_empty() {
                "—"
            } else {
                form.path.as_str()
            }
            .to_string(),
        ),
        FormField::DeleteInvite => (
            "delete after join",
            if form.delete_invite { "yes" } else { "no" }.into(),
        ),
        FormField::InstallService => (
            "write recovery unit",
            if form.install_service { "yes" } else { "no" }.into(),
        ),
    };
    let mut spans = vec![
        Span::styled(
            if focused { "> " } else { "  " },
            Style::default().fg(theme::accent()),
        ),
        Span::styled(format!("{label:<20}"), theme::label()),
        Span::raw(value),
    ];
    if focused && !matches!(field, FormField::DeleteInvite | FormField::InstallService) {
        spans.push(Span::styled(
            "_",
            Style::default().add_modifier(Modifier::SLOW_BLINK),
        ));
    }
    Line::from(spans)
}

fn form_fact(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<20}"), theme::label()),
        Span::raw(value.to_string()),
    ])
}

fn machine_report(frame: &mut Frame, area: Rect, report: &MachineReport) {
    let mut lines = vec![Line::from(Span::styled(
        report.title.clone(),
        theme::heading(),
    ))];
    lines.push(Line::from(""));
    if report.pending {
        lines.push(Line::from("Working…"));
    } else if report.body.is_empty() {
        lines.push(Line::from("No output."));
    } else {
        for line in report.body.lines() {
            lines.push(Line::from(line.to_string()));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        if report.pending {
            "Esc waits for this check to finish"
        } else {
            "Enter or Esc back to the menu · y copy"
        },
        Style::default().fg(theme::muted()),
    )));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn add_machine(frame: &mut Frame, area: Rect, app: &App, machines: &Machines, add: &AddMachine) {
    let standalone = app.fleet_profile.is_none();
    let mut lines = vec![Line::from(Span::styled(
        "Add another machine from this instance",
        theme::heading(),
    ))];

    match add.step {
        AddStep::Method => {
            lines.push(Line::from(""));
            lines.push(Line::from("How should this Mac reach the other machine?"));
            lines.push(method_row(
                add.method == AddMethod::Ssh,
                "I can SSH to it (laptop on Tailscale, VPS with a key)",
            ));
            lines.push(method_row(
                add.method == AddMethod::Prepare,
                "I'll run a command on that machine myself",
            ));
            if !machines.candidates.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!(
                        "Next: pick from {} hosts this Mac already knows.",
                        machines.candidates.len()
                    ),
                    theme::label(),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "↑↓ choose · Enter continue · Esc back",
                Style::default().fg(theme::muted()),
            )));
        }
        AddStep::Pick => {
            lines.push(Line::from(""));
            lines.push(Line::from("Which machine?"));
            for (index, candidate) in machines.candidates.iter().enumerate() {
                lines.push(method_row(
                    add.candidate == index,
                    &format!(
                        "{}. {}  {}  {}",
                        index + 1,
                        candidate.label,
                        candidate.target,
                        candidate.detail
                    ),
                ));
            }
            lines.push(method_row(
                add.candidate == machines.candidates.len(),
                "Type a host myself",
            ));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "↑↓ choose · 1-9 jump · Enter continue · Esc back",
                Style::default().fg(theme::muted()),
            )));
        }
        AddStep::Form => {
            lines.push(Line::from(""));
            for field in add.fields(standalone) {
                lines.push(add_field_row(add, field, add.field == field));
            }
            if add.method == AddMethod::Ssh {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "A Mac binary will not run on Linux. Leave dest. binary empty if that host already has matching ouro, or pass a Linux build.",
                    Style::default().fg(theme::muted()),
                )));
            }
            if let Some(error) = &add.error {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    error.clone(),
                    Style::default().fg(theme::bad()),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Tab fields · Enter review · Esc back. Invitation contents stay off screen.",
                Style::default().fg(theme::muted()),
            )));
        }
        AddStep::Confirm => {
            lines.push(Line::from(""));
            if standalone {
                lines.push(Line::from(Span::styled(
                    "This Mac will restart once to become a fleet, then add the other machine.",
                    Style::default().fg(theme::warn()),
                )));
            }
            lines.push(Line::from(Span::styled(
                app.add_command_preview(),
                Style::default().fg(theme::accent()),
            )));
            if let Some(error) = &add.error {
                lines.push(Line::from(Span::styled(
                    error.clone(),
                    Style::default().fg(theme::bad()),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter runs this plan · y copy · Esc edit. No cookies are printed.",
                Style::default().fg(theme::muted()),
            )));
        }
        AddStep::Working => {
            lines.push(Line::from(""));
            lines.push(theme::working(app.ticks, "Adding the machine…"));
            for line in add.log.iter().rev().take(8).rev() {
                lines.push(Line::from(Span::styled(
                    line.clone(),
                    Style::default().fg(theme::muted()),
                )));
            }
        }
        AddStep::Done => {
            lines.push(Line::from(""));
            for line in &add.log {
                lines.push(Line::from(line.clone()));
            }
            if let Some(recipe) = &add.recipe {
                lines.push(Line::from(""));
                for line in recipe.lines() {
                    lines.push(Line::from(Span::styled(
                        line.to_string(),
                        Style::default().fg(theme::accent()),
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter/Esc close · y copy recipe. Provider sign-in is still on that machine.",
                Style::default().fg(theme::muted()),
            )));
        }
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn method_row(focused: bool, label: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            if focused { "> " } else { "  " },
            Style::default().fg(theme::accent()),
        ),
        Span::raw(label.to_string()),
    ])
}

fn add_field_row(add: &AddMachine, field: AddField, focused: bool) -> Line<'static> {
    let (label, value) = match field {
        AddField::Target => ("ssh target", add.target.as_str()),
        AddField::Machine => ("machine", add.machine.as_str()),
        AddField::Host => ("fleet host", add.host.as_str()),
        AddField::Via => ("via", add.via_label()),
        AddField::Binary => ("dest. binary", add.binary.as_str()),
        AddField::OwnerHost => ("this Mac host", add.owner_host.as_str()),
        AddField::OwnerMachine => ("this Mac name", add.owner_machine.as_str()),
    };
    let mut spans = vec![
        Span::styled(
            if focused { "> " } else { "  " },
            Style::default().fg(theme::accent()),
        ),
        Span::styled(format!("{label:<16}"), theme::label()),
        Span::raw(if value.is_empty() { "—" } else { value }.to_string()),
    ];
    if focused && field != AddField::Via {
        spans.push(Span::styled(
            "_",
            Style::default().add_modifier(Modifier::SLOW_BLINK),
        ));
    }
    Line::from(spans)
}

fn settings_provider_cell(choices: &[ProviderChoice], index: usize, app: &App) -> (String, Style) {
    let Some(choice) = choices.get(index) else {
        return (
            if app.providers.pending {
                "asking the runtime which providers it serves".to_string()
            } else {
                "unset — stated per session".to_string()
            },
            Style::default().fg(theme::muted()),
        );
    };

    let position = format!("({}/{})", index + 1, choices.len());

    match choice {
        ProviderChoice::Unset => (
            format!("unset — stated per session {position}"),
            Style::default().fg(theme::muted()),
        ),
        ProviderChoice::Probed { name, ready: true } => (
            format!("{name} {position}"),
            Style::default().fg(theme::good()),
        ),
        ProviderChoice::Probed { name, ready: false } => (
            format!("{name} — no executable found {position}"),
            Style::default().fg(theme::muted()),
        ),
        // The config names it and the runtime does not. Said, rather than dropped.
        ProviderChoice::Unserved { name } => (
            format!("{name} — from the config file; this runtime does not report it {position}"),
            Style::default().fg(theme::warn()),
        ),
    }
}

/// The new-session form: every choice on screen at once, none of them made for you.
/// A choice the runtime's own spec says this provider cannot take.
fn unavailable_style() -> Style {
    Style::default()
        .fg(theme::muted())
        .add_modifier(Modifier::DIM)
}

fn approval_mode_name(dialog: &NewSession) -> String {
    dialog
        .approval_mode()
        .map(|mode| mode.as_str().to_string())
        .unwrap_or_else(|| "unset".to_string())
}

fn sandbox_mode_name(dialog: &NewSession) -> String {
    dialog
        .sandbox_mode()
        .map(|mode| mode.as_str().to_string())
        .unwrap_or_else(|| "unset".to_string())
}

fn new_session(frame: &mut Frame, area: Rect, app: &App, dialog: &NewSession) {
    let providers = app.providers.value.as_deref().unwrap_or_default();
    let machines = app.machine_choices();
    let rows = dialog.fields();
    let height = (rows.len() + 8).min(area.height as usize) as u16;
    let popup = centered(area, 76, height);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(" new session ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(rows.len() as u16),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    let mut lines = Vec::new();

    for field in &rows {
        let focused = *field == dialog.field;

        let (label, value, style) = match field {
            NewField::Plane => (
                "plane",
                match dialog.request.plane {
                    Plane::Interactive => {
                        "interactive — a conversation you send messages to".to_string()
                    }
                    Plane::Coding => "coding — one objective, run to completion".to_string(),
                },
                Style::default(),
            ),
            NewField::Machine => {
                let selected = dialog.request.machine.trim();
                if selected.is_empty() {
                    (
                        "machine",
                        machines
                            .first()
                            .map(|machine| machine.label())
                            .unwrap_or_else(|| "This machine".into()),
                        Style::default(),
                    )
                } else if let Some(machine) = machines
                    .iter()
                    .find(|machine| machine.wire_name() == Some(selected))
                {
                    ("machine", machine.label(), Style::default())
                } else {
                    (
                        "machine",
                        format!("{selected} — no longer connected; start will be refused"),
                        Style::default().fg(theme::warn()),
                    )
                }
            }
            NewField::Provider => provider_cell(
                providers,
                dialog.provider,
                !dialog.request.machine.trim().is_empty(),
            ),
            NewField::Objective => (
                "objective",
                text_or_hint(&dialog.request.objective, "required"),
                hint_style(&dialog.request.objective),
            ),
            NewField::Workspace => (
                "workspace",
                text_or_hint(
                    &dialog.request.workspace,
                    if dialog.request.machine.trim().is_empty() {
                        "none — the plane decides"
                    } else {
                        "required — absolute path on destination"
                    },
                ),
                hint_style(&dialog.request.workspace),
            ),
            // A value the selected provider cannot take is drawn dim and says whose
            // limit it is. It stays selectable: the runtime is the authority on whether a
            // start succeeds, and refusing here on spec data would be this client
            // overruling it — the same rule the provider list already follows for an
            // uninstalled executable.
            NewField::ApprovalMode => match dialog.approval_refusal(providers) {
                Some(reason) => (
                    "approval",
                    format!("{} — {reason}", approval_mode_name(dialog)),
                    unavailable_style(),
                ),
                None => ("approval", dialog.approval_label(), Style::default()),
            },
            NewField::SandboxMode => match dialog.sandbox_refusal(providers) {
                Some(reason) => (
                    "files",
                    format!("{} — {reason}", sandbox_mode_name(dialog)),
                    unavailable_style(),
                ),
                None => ("files", dialog.sandbox_label(), Style::default()),
            },
            // D7. Two gates, and the row says which one is closed. A gateway that does
            // not serve `interactive.start`'s worktree option cannot honour the toggle,
            // and a toggle silently ignored is worse than none.
            NewField::Worktree => (
                "worktree",
                if dialog.request.worktree {
                    "yes — its own git worktree, so two sessions can share a repository".to_string()
                } else {
                    "no — the workspace itself, which takes an exclusive lease".to_string()
                },
                if dialog.request.worktree {
                    Style::default().fg(theme::accent())
                } else {
                    Style::default()
                },
            ),
            NewField::Start => (
                "",
                if dialog.pending {
                    format!("starting {} ", theme::spinner(app.ticks))
                } else {
                    "[ start ]".to_string()
                },
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD),
            ),
        };

        let mut spans = vec![
            Span::styled(
                if focused { "> " } else { "  " },
                Style::default().fg(theme::accent()),
            ),
            Span::styled(format!("{label:<11}"), theme::label()),
            Span::styled(value, style),
        ];

        // The caret only where typing goes somewhere.
        if focused && matches!(field, NewField::Workspace | NewField::Objective) && !dialog.pending
        {
            spans.push(Span::styled(
                "_",
                Style::default().add_modifier(Modifier::SLOW_BLINK),
            ));
        }

        lines.push(Line::from(spans));
    }

    frame.render_widget(Paragraph::new(lines), chunks[0]);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            if dialog.pending {
                "Waiting for this exact start · the form stays open until its answer"
            } else if dialog.reconciling {
                "Tab/arrows move · Enter on [ start ] reconciles the same id · edits stay locked"
            } else {
                "Tab/arrows move · left/right change · Enter on [ start ] · Esc cancels"
            },
            Style::default().fg(theme::muted()),
        ))),
        chunks[1],
    );

    let mut footer = Vec::new();

    if let Some(error) = &dialog.error {
        footer.extend(refusal_lines(error));
    } else if providers.is_empty() {
        footer.push(Line::from(Span::styled(
            if app.providers.pending {
                "asking the runtime which providers it serves"
            } else {
                "this runtime serves no coding providers, so there is nothing to start"
            },
            Style::default().fg(theme::warn()),
        )));
    } else if dialog.request.machine.trim().is_empty()
        && !providers
            .get(dialog.provider)
            .map(|entry| entry.ready())
            .unwrap_or(true)
    {
        // Selectable anyway: "installed" means a probe found an executable, and the
        // runtime is the authority on whether a session can start.
        footer.push(Line::from(Span::styled(
            "no executable was found for it — the runtime decides, not this probe",
            Style::default().fg(theme::warn()),
        )));
    }

    if !dialog.request.machine.trim().is_empty() {
        footer.push(Line::from(Span::styled(
            "Connected checks reachability, not provider readiness. Install and sign in to the provider on that destination; fleet invites never copy credentials.",
            Style::default().fg(theme::warn()),
        )));
        footer.push(Line::from(Span::styled(
            "Workspace paths are resolved on that destination machine, not on this terminal.",
            Style::default().fg(theme::muted()),
        )));
    }

    frame.render_widget(Paragraph::new(footer).wrap(Wrap { trim: false }), chunks[2]);
}

fn provider_cell(
    providers: &[ProviderEntry],
    index: usize,
    remote: bool,
) -> (&'static str, String, Style) {
    let Some(entry) = providers.get(index) else {
        return (
            "provider",
            "none available".to_string(),
            Style::default().fg(theme::warn()),
        );
    };

    let position = format!("({}/{})", index + 1, providers.len());

    if remote {
        return (
            "provider",
            format!(
                "{} — readiness unknown on destination {position}",
                entry.provider
            ),
            Style::default().fg(theme::warn()),
        );
    }

    if entry.ready() {
        return (
            "provider",
            format!("{} {position}", entry.provider),
            Style::default().fg(theme::good()),
        );
    }

    (
        "provider",
        format!("{} — not installed {position}", entry.provider),
        Style::default().fg(theme::muted()),
    )
}

/// A refusal, split where [`crate::model::refusal`] put its line break.
///
/// The sentence to act on is the first line and is drawn as the error; whatever the
/// payload carried that the sentence did not use follows it dimly. Two styles rather than
/// one, because the second line exists so that nothing is *lost* — not because anybody
/// needs to read it first.
fn refusal_lines(error: &str) -> Vec<Line<'static>> {
    error
        .split('\n')
        .enumerate()
        .map(|(index, line)| {
            Line::from(Span::styled(
                line.to_string(),
                if index == 0 {
                    Style::default().fg(theme::bad())
                } else {
                    Style::default().fg(theme::muted())
                },
            ))
        })
        .collect()
}

/// A labelled fact, in the same shape the Dashboard's panes use so the two read as one UI.
fn field(name: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        // Padded to line up with the editable rows beneath them on the settings overlay:
        // two for the cursor gutter plus the same twelve-wide label column.
        Span::styled(format!("  {name:<12}"), theme::label()),
        Span::raw(value.to_string()),
    ])
}

fn blank(value: &str) -> String {
    if value.is_empty() {
        "unknown".to_string()
    } else {
        value.to_string()
    }
}

fn text_or_hint(value: &str, hint: &str) -> String {
    if value.is_empty() {
        hint.to_string()
    } else {
        value.to_string()
    }
}

fn hint_style(value: &str) -> Style {
    if value.is_empty() {
        Style::default().fg(theme::muted())
    } else {
        Style::default()
    }
}

fn quit_detail(app: &App) -> String {
    match app.mode {
        Mode::Spawned { .. } if app.shutdown_served() => {
            "this client started the runtime. Detaching leaves it running and reachable with \
             `ouro attach`."
                .into()
        }
        Mode::Spawned { .. } => "this client started the runtime, and this gateway does not \
             advertise runtime.shutdown, so stopping it is a signal."
            .into(),
        Mode::Attached => "this client did not start the runtime; quitting only closes the \
             connection."
            .into(),
    }
}

/// Everything one approval modal draws, gathered so the signature stays readable.
struct ApprovalModal<'a> {
    id: &'a str,
    request_id: &'a str,
    /// The one-line summary the transcript cell and the snack bar also use.
    subject: &'a str,
    detail: &'a ApprovalDetail,
    rule: Option<&'a ApprovalRule>,
    rule_absent: Option<&'static str>,
    choice: usize,
    expanded: bool,
}

/// How many rows the command may take before it is cut. Two, and it says how much it cut.
const APPROVAL_COMMAND_ROWS: usize = 2;

/// How many rows the reason may take.
const APPROVAL_REASON_ROWS: usize = 3;

/// The fewest diff rows worth drawing at all. Below this the modal says the diff is there
/// and how long it is rather than showing a two-line sliver of it.
const APPROVAL_DIFF_FLOOR: usize = 4;

/// The diff ceiling under `ctrl+o`. Still bounded: a modal is not a pager, and a patch
/// longer than this is read in the transcript or in `/details`.
const APPROVAL_DIFF_EXPANDED: usize = 400;

/// X11's modal: the kind, the exact command and its cwd, the diff while the approval is
/// pending, the provider's own option labels, the reason it gave, and the rule a
/// "don't ask again" would write — each drawn only where the payload actually carries it.
///
/// The honesty rules this obeys, in one place:
///
/// * A request with no diff says so. A modal that quietly showed nothing where a diff
///   would go is X11 itself.
/// * A diff the gateway had already excerpted is labelled an excerpt, so its `+`/`-`
///   counts are never read as a diffstat of the whole patch.
/// * The fifth answer names the exact pattern and the exact scope it will write, before
///   it is chosen. Where there is a suggestion this client cannot act on, it says which
///   of the two reasons applies rather than dropping the row.
/// * A provider option whose `kind` this build does not recognize is listed with the
///   provider's own words and mapped onto nothing.
///
/// Warp's rule for the diff — expanded while the approval is pending — is the default
/// here, bounded by the rows the popup can spare; `ctrl+o` raises the ceiling in place.
fn approval(frame: &mut Frame, area: Rect, modal: ApprovalModal<'_>) {
    let detail = modal.detail;
    let answers = approval_answers(&modal);
    let width_percent = if area.width < 100 { 100 } else { 78 };
    let inner = inner_width(area, width_percent).max(20);

    let mut body: Vec<Line<'static>> = Vec::new();

    body.push(Line::from(vec![
        Span::styled("request ", theme::quiet()),
        Span::raw(super::tree::truncate(
            modal.request_id,
            inner.saturating_sub(10),
        )),
    ]));
    body.push(Line::from(Span::styled(
        super::tree::truncate(modal.id, inner),
        theme::quiet(),
    )));

    if let Some(title) = &detail.title {
        body.push(Line::from(Span::raw(super::tree::truncate(title, inner))));
    }

    match &detail.command {
        Some(command) => {
            let rows = wrap_rows(command, inner.saturating_sub(2), APPROVAL_COMMAND_ROWS);
            for (index, row) in rows.shown.iter().enumerate() {
                body.push(Line::from(vec![
                    Span::styled(
                        if index == 0 { "$ " } else { "  " },
                        Style::default().fg(theme::accent()),
                    ),
                    Span::styled(row.clone(), Style::default().add_modifier(Modifier::BOLD)),
                ]));
            }
            if rows.omitted > 0 {
                body.push(Line::from(Span::styled(
                    format!("  … {} more line(s) of command · /details", rows.omitted),
                    theme::quiet(),
                )));
            }
        }
        // Not every approval is about a command: an ACP permission request can carry only
        // a tool title. Saying which is the honest half.
        None => body.push(Line::from(Span::styled(
            super::tree::truncate(modal.subject, inner),
            Style::default().add_modifier(Modifier::BOLD),
        ))),
    }

    if let Some(cwd) = &detail.cwd {
        body.push(Line::from(vec![
            Span::styled("cwd ", theme::quiet()),
            Span::styled(
                super::tree::truncate(cwd, inner.saturating_sub(4)),
                theme::quiet(),
            ),
        ]));
    }

    for path in &detail.locations {
        body.push(Line::from(vec![
            Span::styled("path ", theme::quiet()),
            Span::styled(
                super::tree::truncate(path, inner.saturating_sub(5)),
                theme::quiet(),
            ),
        ]));
    }

    if let Some(reason) = &detail.reason {
        let rows = wrap_rows(reason, inner.saturating_sub(2), APPROVAL_REASON_ROWS);
        for (index, row) in rows.shown.iter().enumerate() {
            body.push(Line::from(vec![
                Span::styled(if index == 0 { "· " } else { "  " }, theme::quiet()),
                Span::styled(row.clone(), Style::default().fg(theme::warn())),
            ]));
        }
        if rows.omitted > 0 {
            body.push(Line::from(Span::styled(
                format!("  … {} more line(s) of reason", rows.omitted),
                theme::quiet(),
            )));
        }
    }

    // Everything above is chrome the popup must keep; whatever height is left after it and
    // the answer rows is the diff's budget.
    let fixed = body.len() + answers.len() + approval_notes(&modal).len() + 5;
    let budget = if modal.expanded {
        APPROVAL_DIFF_EXPANDED
    } else {
        (area.height as usize).saturating_sub(fixed)
    };

    approval_diff_rows(&mut body, detail, inner, budget);

    for note in approval_notes(&modal) {
        body.push(note);
    }

    body.push(Line::from(Span::styled(
        if modal.expanded {
            "enter answers · tab or r attach a reason · ctrl+o collapses the diff · esc closes"
        } else {
            "enter answers · tab or r attach a reason · ctrl+o expands the diff · esc closes"
        },
        theme::quiet(),
    )));

    let heading = match &detail.kind {
        Some(kind) => format!(" approval requested — {kind} "),
        None => " approval requested ".to_string(),
    };

    let height = (body.len() + answers.len() + 2).min(area.height as usize) as u16;
    let popup = centered(area, width_percent, height);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .border_style(Style::default().fg(theme::warn()))
        .title(Span::styled(heading, theme::heading()));
    let inner_area = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(answers.len() as u16)])
        .split(inner_area);

    frame.render_widget(Paragraph::new(body), rows[0]);

    let items: Vec<ListItem> = answers
        .into_iter()
        .enumerate()
        .map(|(index, label)| ListItem::new(Line::from(access::numbered(index, &label))))
        .collect();
    let mut state = ListState::default().with_selected(Some(modal.choice));

    frame.render_stateful_widget(
        List::new(items).highlight_style(theme::selected()),
        rows[1],
        &mut state,
    );
}

/// The answer rows: the four the gateway accepts, carrying the provider's own wording
/// where its `options` named one, plus the durable fifth where there is one.
fn approval_answers(modal: &ApprovalModal<'_>) -> Vec<String> {
    let mut answers: Vec<String> = APPROVAL_CHOICES
        .iter()
        .map(|(decision, scope)| {
            let label = format!("{} ({})", decision.as_str(), scope.as_str());

            // The provider's own words for the same answer, where it offered them. Shown
            // beside the wire spelling rather than instead of it: the row still has to say
            // what will be sent.
            match modal
                .detail
                .options
                .iter()
                .find(|option| option.decision() == Some((*decision, *scope)))
            {
                Some(option) => format!("{label} — {}", option.name),
                None => label,
            }
        })
        .collect();

    if let Some(rule) = modal.rule {
        answers.push(format!(
            "approve, and don't ask again for {} (workspace rule)",
            rule.pattern
        ));
    }

    answers
}

/// The lines under the diff: what a "don't ask again" would write, or why it is not
/// offered, and any provider option this build could not map onto an answer.
fn approval_notes(modal: &ApprovalModal<'_>) -> Vec<Line<'static>> {
    let mut notes = Vec::new();

    if let Some(rule) = modal.rule {
        notes.push(Line::from(vec![
            Span::styled("don't ask again writes ", theme::quiet()),
            Span::styled(
                rule.pattern.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(" as a workspace allow rule in ", theme::quiet()),
            Span::styled(rule.workspace.clone(), theme::quiet()),
        ]));
    } else if let Some(absent) = modal.rule_absent {
        notes.push(Line::from(Span::styled(absent.to_string(), theme::quiet())));
    }

    let unmapped: Vec<&str> = modal
        .detail
        .options
        .iter()
        .filter(|option| option.decision().is_none())
        .map(|option| option.name.as_str())
        .collect();

    if !unmapped.is_empty() {
        notes.push(Line::from(Span::styled(
            format!(
                "the provider also offered {}, which this build cannot map onto an answer it \
                 may send",
                unmapped.join(", ")
            ),
            theme::quiet(),
        )));
    }

    notes
}

/// The diff, or the sentence saying there is not one.
fn approval_diff_rows(
    body: &mut Vec<Line<'static>>,
    detail: &ApprovalDetail,
    inner: usize,
    budget: usize,
) {
    let Some(diff) = &detail.diff else {
        if detail.edits.is_empty() {
            body.push(Line::from(Span::styled(
                "this request carries no diff".to_string(),
                theme::quiet(),
            )));
            return;
        }

        for edit in &detail.edits {
            body.push(Line::from(vec![
                Span::styled("edit ", theme::quiet()),
                Span::styled(
                    super::tree::truncate(&edit.path, inner.saturating_sub(30)),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        " · {} · {} → {} bytes",
                        edit.kind, edit.old_bytes, edit.new_bytes
                    ),
                    theme::quiet(),
                ),
            ]));
        }

        body.push(Line::from(Span::styled(
            "this request carries the whole before and after text, not a patch; the unified \
             diff appears in the file change when the edit is applied"
                .to_string(),
            theme::quiet(),
        )));
        return;
    };

    let total = diff.text.lines().count();
    let mut heading = vec![
        Span::styled("diff ", theme::quiet()),
        Span::styled(
            diff.path.clone().unwrap_or_else(|| "changes".into()),
            theme::quiet(),
        ),
        Span::styled(
            format!("  +{}", diff.additions),
            Style::default().fg(theme::good()),
        ),
        Span::styled(
            format!(" -{}", diff.deletions),
            Style::default().fg(theme::bad()),
        ),
    ];

    if diff.truncated || detail.diff_excerpted {
        heading.push(Span::styled(
            "  in excerpt — the counts describe the prefix",
            theme::quiet(),
        ));
    }

    body.push(Line::from(heading));

    // Below the floor there is no room for a diff worth reading, so say what is there
    // instead of showing two lines of it.
    if budget < APPROVAL_DIFF_FLOOR {
        body.push(Line::from(Span::styled(
            format!("{total} line(s) · ctrl+o expands, or read it in /details"),
            theme::quiet(),
        )));
        return;
    }

    let shown = budget.min(total);

    for line in diff.text.lines().take(shown) {
        let style = if line.starts_with('+') && !line.starts_with("+++") {
            Style::default().fg(theme::good())
        } else if line.starts_with('-') && !line.starts_with("---") {
            Style::default().fg(theme::bad())
        } else if line.starts_with("@@") {
            Style::default().fg(theme::accent())
        } else {
            theme::quiet()
        };

        body.push(Line::from(Span::styled(
            super::tree::truncate(line, inner),
            style,
        )));
    }

    if total > shown {
        body.push(Line::from(Span::styled(
            format!("… +{} lines · ctrl+o", total - shown),
            theme::quiet(),
        )));
    }
}

/// What fits, and how many source lines did not.
struct WrappedRows {
    shown: Vec<String>,
    omitted: usize,
}

/// `text` wrapped to `width` cells, cut to `rows` rows.
///
/// Its own function rather than `Paragraph`'s wrap because the caller has to know how much
/// it dropped: "+N lines" is the difference between a bounded command and a lie about one.
fn wrap_rows(text: &str, width: usize, rows: usize) -> WrappedRows {
    let width = width.max(8);
    let mut all: Vec<String> = Vec::new();

    for source in text.lines() {
        let mut current = String::new();

        for word in source.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
            } else if current.chars().count() + 1 + word.chars().count() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                all.push(std::mem::take(&mut current));
                current.push_str(word);
            }

            while current.chars().count() > width {
                let split = current
                    .char_indices()
                    .nth(width)
                    .map(|(index, _)| index)
                    .unwrap_or(current.len());
                let tail = current.split_off(split);
                all.push(std::mem::replace(&mut current, tail));
            }
        }

        all.push(current);
    }

    let omitted = all.len().saturating_sub(rows);
    all.truncate(rows);

    WrappedRows {
        shown: all,
        omitted,
    }
}

fn chooser(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    detail: &str,
    options: &[String],
    choice: usize,
) {
    // A 70% dialog is comfortably readable on a wide terminal but needlessly clips the
    // consequence of destructive choices at 80 columns. Measure the wrapped explanation
    // against the width it will actually receive and let narrow terminals use the edges.
    let width_percent = if area.width < 90 {
        100
    } else if area.width < 110 {
        92
    } else {
        70
    };
    let detail_lines = detail.lines().map(Line::from).collect::<Vec<_>>();
    let detail_height = wrapped(&detail_lines, inner_width(area, width_percent)).max(1);
    let height = (options.len() as u16 + detail_height + 4).min(area.height);
    let popup = centered(area, width_percent, height);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(format!(" {title} "), theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(detail_height), Constraint::Min(1)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(detail.to_string())
            .style(Style::default().fg(theme::muted()))
            .wrap(Wrap { trim: false }),
        rows[0],
    );

    let items: Vec<ListItem> = options
        .iter()
        .enumerate()
        .map(|(index, label)| ListItem::new(Line::from(access::numbered(index, label))))
        .collect();

    let mut state = ListState::default().with_selected(Some(choice));

    frame.render_stateful_widget(
        List::new(items).highlight_style(theme::selected()),
        rows[1],
        &mut state,
    );
}

fn prompt(frame: &mut Frame, area: Rect, label: &str, buffer: &str) {
    let popup = centered(area, 60, 5);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(format!(" {label} "), theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("> ", Style::default().fg(theme::accent())),
            Span::raw(buffer.to_string()),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ])),
        inner,
    );
}

/// B5. The last user turns, and the two honest things that can be done with one.
///
/// The header states what each verb *is*, before it is pressed, because this is the menu
/// R1 §4d(4) is about: a rewind that silently under-delivers (Claude Code #18516) is worse
/// than no rewind. Neither of these removes anything — "edit and resend" adds a turn, and
/// the fork is the runtime's, which is why the row for it does not promise where the
/// branch starts.
fn backtrack(
    frame: &mut Frame,
    area: Rect,
    entries: &[(u64, String)],
    choice: usize,
    fork_offered: bool,
    rewind_offered: bool,
) {
    let mut verbs = vec![if fork_offered {
        "enter forks"
    } else {
        "enter edits and resends as a new turn"
    }];

    if fork_offered {
        verbs.push("e edits and resends as a new turn");
    }

    // D6. Named last because it is the only one of the three that *removes* something,
    // and because it leaves this menu for one that states what it cannot restore.
    if rewind_offered {
        verbs.push("r rewinds");
    }

    verbs.push("esc closes");

    let mut lines = vec![Line::from(Span::styled(
        verbs.join(" · "),
        Style::default().fg(theme::muted()),
    ))];

    if fork_offered {
        lines.push(Line::from(Span::styled(
            "the fork is the runtime's: where the branch starts is the transport's decision",
            Style::default().fg(theme::muted()),
        )));
    }

    lines.push(Line::from(Span::styled(
        if rewind_offered {
            "the two verbs above only add a turn; the rewind is the one that undoes"
        } else {
            "nothing here removes an earlier turn; both verbs only add one"
        },
        Style::default().fg(theme::muted()),
    )));
    lines.push(Line::from(""));

    let width = inner_width(area, 72).saturating_sub(6);

    for (index, (sequence, text)) in entries.iter().enumerate() {
        let selected = index == choice;
        lines.push(Line::from(vec![
            Span::styled(
                if selected { " \u{25b8} " } else { "   " },
                Style::default().fg(theme::accent()),
            ),
            Span::styled(
                format!("#{sequence:<5} "),
                Style::default().fg(theme::muted()),
            ),
            Span::styled(
                super::tree::truncate(&text.replace('\n', " "), width),
                if selected {
                    Style::default()
                        .fg(theme::accent())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ),
        ]));
    }

    let popup = centered(area, 72, (lines.len() as u16 + 2).min(area.height));
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .border_style(Style::default().fg(theme::accent()))
        .title(Span::styled(" go back to a message ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The rows the `?` panel is generated from, grouped by the question someone is asking
/// when they open it (B9).
///
/// Four groups, in the order a session is lived: what you are typing into, what you do
/// while the agent is working, what you do to the session, and what belongs to the runtime
/// around it. A flat list of forty chords is a list nobody reads twice.
///
/// Every row that *is* a chord reads its key out of the resolved keymap, so the panel
/// states the effective binding and not a literal this file happened to carry (D14, B8).
/// The rows that are not chords — `@ path`, the tab digits, the wheel, the `/` verbs — are
/// spelled here because they are not rebindable, and the "keys are data" row below says so
/// rather than leaving a reader to infer it.
fn help_keys(app: &App) -> Vec<(&'static str, String, &'static str)> {
    let keymap = &app.keymap;
    let mut rows: Vec<(&'static str, String, &'static str)> = Vec::new();

    // A free helper rather than a closure over `rows`: the interleaved literal rows below
    // need the vector too, and a closure holding it would lock them out.
    fn row(keymap: &crate::keymap::Keymap, action: Action) -> (&'static str, String, &'static str) {
        (action.group(), keymap.label(action), action.describe())
    }

    rows.push(row(keymap, Action::Send));
    rows.push(row(keymap, Action::Steer));
    rows.push(row(keymap, Action::Newline));
    rows.push((
        "composing",
        "@ path".to_string(),
        "completes a workspace file, and attaches it to the turn",
    ));
    rows.push(row(keymap, Action::PasteImage));
    rows.push((
        "composing",
        "backspace".to_string(),
        "on an empty draft, removes the newest attachment",
    ));
    rows.push(row(keymap, Action::QueueRetract));
    rows.push((
        "composing",
        format!(
            "{} / {} / {}",
            keymap.label(Action::EditorKillWordBack),
            keymap.label(Action::EditorKillLine),
            keymap.label(Action::EditorKillToStart)
        ),
        "kill word, to line end, to line start",
    ));
    rows.push((
        "composing",
        format!(
            "{} / {}",
            keymap.label(Action::EditorWordBack),
            keymap.label(Action::EditorWordForward)
        ),
        "move by word",
    ));
    rows.push(row(keymap, Action::Editor));

    rows.push(row(keymap, Action::Interrupt));
    rows.push(row(keymap, Action::Backtrack));
    rows.push(row(keymap, Action::Cancel));
    rows.push(row(keymap, Action::Verbose));
    rows.push(row(keymap, Action::PlanPanel));

    rows.push((
        "session",
        "/model /effort".to_string(),
        "the model, and reasoning effort for the next turn only",
    ));
    rows.push((
        "session",
        "/fork".to_string(),
        "branch this session, where the runtime serves it",
    ));
    rows.push((
        "session",
        format!(
            "{} / {}",
            keymap.label(Action::LeaderScrollback),
            keymap.spec(Action::LeaderEditorView)
        ),
        "this transcript into native scrollback / into $EDITOR",
    ));
    rows.push((
        "session",
        "1-7 / Tab".to_string(),
        "runtime tabs when the prompt is not focused",
    ));

    rows.push(row(keymap, Action::Leader));
    rows.push(row(keymap, Action::Palette));
    rows.push(row(keymap, Action::Quit));
    rows.push((
        "runtime",
        format!(
            "{} / {}",
            keymap.label(Action::Help),
            keymap.label(Action::Settings)
        ),
        "this page / settings, when the prompt is empty",
    ));
    rows.push((
        "runtime",
        "wheel".to_string(),
        "scrolls; shift/ctrl+\u{2191}\u{2193}, pageup/down; config mouse = false frees it",
    ));
    rows.push((
        "runtime",
        "/keys".to_string(),
        "every action, its key, and which came from config.toml",
    ));
    rows.push((
        "runtime",
        "/cost".to_string(),
        "what this session has spent, as the provider reported it",
    ));

    rows
}

fn leader_hint(frame: &mut Frame, area: Rect, app: &App) {
    // A chord the open session cannot honour is not drawn (D14). `steer` is
    // `{:error, :unsupported}` on every transport but `pi`'s, and offering it in a
    // which-key overlay is how an operator learns a key by being refused by it.
    //
    // The list itself is the keymap's, not a table beside it: a rebound verb is drawn on
    // the key that reaches it, and a verb turned `off` is not drawn at all.
    let chords = app
        .keymap
        .live(Scope::Leader)
        .into_iter()
        .filter(|action| *action != Action::LeaderSteer || app.steer_offered())
        .filter(|action| *action != Action::LeaderApproval || app.approvals_offered())
        .map(|action| (app.keymap.spec(action).to_string(), action.describe()))
        .collect::<Vec<_>>();

    let height = (chords.len() as u16).saturating_add(2).min(area.height);
    let width = area.width.clamp(24, 56);
    let popup = Rect::new(
        area.x.saturating_add(2),
        area.bottom().saturating_sub(height + 1),
        width,
        height,
    );

    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::accent()))
        .title(Span::styled(
            format!(" {} ", app.keymap.label(Action::Leader)),
            theme::heading(),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let lines = chords
        .iter()
        .map(|(key, description)| {
            Line::from(vec![
                Span::styled(format!(" {key:<4}"), Style::default().fg(theme::accent())),
                Span::raw(*description),
            ])
        })
        .collect::<Vec<_>>();

    frame.render_widget(Paragraph::new(lines), inner);
}

fn help(frame: &mut Frame, area: Rect, app: &App) {
    let (rows, limits) = help_sections(app);

    // The panel never reaches the last row: the notice line lives there, and a help panel
    // that covered it would hide the sentence explaining why a key did nothing.
    let wanted = (rows.len() + limits.len()) as u16 + 2;
    let ceiling = area.height.saturating_sub(2).max(6);
    let popup = centered(area, 84, wanted.min(ceiling));

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(" hotkeys ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // The limits are pinned rather than scrolled. They are the part of this panel that
    // stops it being a brochure, and a reader who never pressed a key would not see them.
    let split = Layout::vertical([Constraint::Min(1), Constraint::Length(limits.len() as u16)])
        .split(inner);

    let height = split[0].height as usize;
    let hidden = rows.len().saturating_sub(height);
    let scroll = app.help_scroll.min(hidden);

    let mut visible = rows[scroll..].to_vec();

    if hidden > 0 {
        // The last visible row says there is more, because a panel that silently ends is
        // one whose remaining half nobody finds (R1 4d(8)).
        let marker = Line::from(Span::styled(
            format!(
                "\u{2191}\u{2193} scrolls \u{b7} {} more row{}",
                hidden - scroll,
                if hidden - scroll == 1 { "" } else { "s" }
            ),
            Style::default().fg(theme::accent()),
        ));

        if hidden > scroll && visible.len() >= height && height > 0 {
            visible[height - 1] = marker;
        }
    }

    frame.render_widget(Paragraph::new(visible).wrap(Wrap { trim: false }), split[0]);
    frame.render_widget(Paragraph::new(limits).wrap(Wrap { trim: false }), split[1]);
}

/// The help panel, split into the part that scrolls and the part that never does.
fn help_sections(app: &App) -> (Vec<Line<'static>>, Vec<Line<'static>>) {
    let mut rows: Vec<Line> = Vec::new();
    let mut group = "";

    for (heading, key, description) in help_keys(app) {
        if heading != group {
            group = heading;
            rows.push(Line::from(Span::styled(
                heading.to_uppercase(),
                theme::label(),
            )));
        }

        rows.push(Line::from(vec![
            Span::styled(format!("{key:<15}"), Style::default().fg(theme::accent())),
            Span::raw(description),
        ]));
    }

    // The verb list is derived, never restated: the editor's completion table is the
    // single source of truth, so help cannot advertise what completion does not offer.
    rows.push(Line::from(Span::styled("COMMANDS", theme::label())));
    let commands: Vec<&str> = COMMANDS.iter().map(|(name, _)| *name).collect();
    for chunk in commands.chunks(8) {
        rows.push(Line::from(vec![
            Span::styled(format!("{:<15}", ""), Style::default().fg(theme::accent())),
            Span::raw(chunk.join("  ")),
        ]));
    }

    // The honest limits, in the place someone looks when they are confused. Two short
    // lines rather than one long one, so a narrow terminal cannot wrap either of them
    // into something that reads as a different claim.
    let mut limits = vec![
        Line::from(Span::styled(
            format!(
                "one gateway view of the fleet through {}",
                if app.hello.node.is_empty() {
                    "this runtime".to_string()
                } else {
                    app.hello.node.clone()
                }
            ),
            Style::default().fg(theme::muted()),
        )),
        Line::from(Span::styled(
            "the token authenticates; it is not a sandbox",
            Style::default().fg(theme::muted()),
        )),
    ];

    if !app.hello.operates() {
        limits.push(Line::from(Span::styled(
            "this listener runs at scope `read`: every mutating verb is refused with -32003",
            Style::default().fg(theme::warn()),
        )));
    }

    // The honesty invariant for this panel specifically: what it shows is the *effective*
    // map, and a line of `[keys]` this build could not act on is named rather than left to
    // be discovered by pressing the key it did not bind.
    let problems = app.keymap.problems().len();

    if problems > 0 {
        limits.push(Line::from(Span::styled(
            format!(
                "{problems} line{} of [keys] could not be used; /keys names {}",
                if problems == 1 { "" } else { "s" },
                if problems == 1 { "it" } else { "them" }
            ),
            Style::default().fg(theme::warn()),
        )));
    }

    (rows, limits)
}

/// A popup of `width` percent and an explicit height, clamped to the frame.
pub fn centered(area: Rect, width_percent: u16, height: u16) -> Rect {
    let horizontal = Layout::horizontal([Constraint::Percentage(width_percent)])
        .flex(Flex::Center)
        .split(area);

    Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .split(horizontal[0])[0]
}

/// A pane title carrying a spinner while a refresh is in flight and an error when the
/// last attempt failed. The value on screen stays the last good one either way.
pub fn panel_title(name: &str, pending: bool, error: Option<&String>, tick: u64) -> Line<'static> {
    let mut spans = vec![Span::styled(format!(" {name} "), theme::heading())];

    if pending {
        spans.push(Span::styled(
            format!("{} ", theme::spinner(tick)),
            Style::default().fg(theme::muted()),
        ));
    }

    if let Some(error) = error {
        spans.push(Span::styled(
            format!("[{}] ", super::tree::truncate(error, 60)),
            Style::default().fg(theme::bad()),
        ));
    }

    Line::from(spans)
}

/// The block every pane uses, so focus is visible in exactly one way.
pub fn pane(title: Line<'static>, focused: bool) -> Block<'static> {
    Block::default()
        .borders(access::borders(Borders::ALL))
        .border_style(if focused {
            Style::default().fg(theme::accent())
        } else {
            Style::default().fg(theme::muted())
        })
        .title(title)
}
