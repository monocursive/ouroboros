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

use super::app::{
    provider_choices, AccountDialog, AccountFlow, AddField, AddMachine, AddMethod, AddStep, App,
    CommandPalette, Connection, FormField, FormKind, MachineForm, MachineReport, MachineSecurity,
    Machines, Mode, NewField, NewSession, NoticeKind, Overlay, ProviderChoice, Settings,
    SettingsField, Tab, APPROVAL_CHOICES, LEADER_KEYS,
};
use super::editor::COMMANDS;
use super::theme;
use crate::model::{Plane, ProviderEntry};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
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

    status_line(frame, rows[2], app);
    overlay(frame, frame.area(), app);

    if app.leader_pending() {
        leader_hint(frame, frame.area());
    }
}

fn shell_header(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(theme::MUTED));
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
            Span::styled("Provider ", Style::default().fg(theme::MUTED)),
            Span::styled(
                visible_provider.expect("checked provider"),
                Style::default().fg(theme::ACCENT),
            ),
        ])
    } else if visible_provider.is_none() {
        Line::from(Span::styled(
            "Provider unknown",
            Style::default().fg(theme::MUTED),
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
                Span::styled(format!("ChatGPT{plan}"), Style::default().fg(theme::GOOD)),
                Span::styled(identity, Style::default().fg(theme::MUTED)),
            ])
        } else if state.requires_openai_auth == Some(false) {
            // An API-key install. There is no subscription to name and nothing to connect,
            // and "not connected" would read as a problem the operator has to go and fix.
            Line::from(vec![
                Span::styled("Codex ready", Style::default().fg(theme::GOOD)),
                Span::styled(
                    "  • no ChatGPT sign-in needed",
                    Style::default().fg(theme::MUTED),
                ),
            ])
        } else {
            Line::from(Span::styled(
                "ChatGPT not connected",
                Style::default().fg(theme::WARN),
            ))
        }
    } else if app.account.pending {
        Line::from(Span::styled(
            format!("{} checking ChatGPT", theme::spinner(app.ticks)),
            Style::default().fg(theme::MUTED),
        ))
    } else {
        Line::from(Span::styled(
            "ChatGPT unavailable",
            Style::default().fg(theme::WARN),
        ))
    };

    let (ready_label, ready_style) = match &app.connection {
        Connection::Live => ("LOCAL READY", Style::default().fg(theme::GOOD)),
        Connection::Lost { .. } => ("LINK LOST", Style::default().fg(theme::BAD)),
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
        Span::styled(separator.to_string(), Style::default().fg(theme::MUTED)),
        Span::styled(context.to_string(), context_style),
    ];

    let used = lead.width() + separator.width() + context.width();
    let room = budget.saturating_sub(used + separator.width());
    if !workspace.is_empty() && room >= 12 {
        spans.push(Span::styled(
            separator.to_string(),
            Style::default().fg(theme::MUTED),
        ));
        spans.push(Span::styled(
            super::tree::truncate(workspace, room),
            Style::default().fg(theme::MUTED),
        ));
    }

    Line::from(spans)
}

fn status_line(frame: &mut Frame, area: Rect, app: &App) {
    if let Some(notice) = &app.notice {
        let style = match notice.kind {
            NoticeKind::Info => Style::default().fg(theme::ACCENT),
            NoticeKind::Warn => Style::default().fg(theme::WARN),
            NoticeKind::Error => Style::default().fg(theme::BAD),
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

    let runtime = match &app.connection {
        Connection::Live => Line::from(vec![
            Span::styled("● LIVE", Style::default().fg(theme::GOOD)),
            Span::styled(
                format!(
                    "  {} · {} · {}",
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
                Style::default().fg(theme::MUTED),
            ),
        ]),
        Connection::Lost { reason } => Line::from(vec![
            Span::styled("● DISCONNECTED  ", Style::default().fg(theme::BAD)),
            Span::styled(
                super::tree::truncate(reason, 27),
                Style::default().fg(theme::BAD),
            ),
        ]),
    };
    let shortcuts = if app.tab == Tab::Sessions {
        "ctrl+p commands  ·  ctrl+x leader  ·  esc interrupt  ·  ctrl+q quit"
    } else {
        "ctrl+p commands  ·  Esc returns to coding  ·  r refresh"
    };

    if area.width >= 112 {
        // Size this column from what Ratatui will actually draw. A fixed 43-cell column
        // clipped the last digit from ordinary five-digit loopback ports, making two
        // attached local runtimes look identical in the footer.
        let runtime_width = runtime.width().min(area.width as usize) as u16;
        let columns =
            Layout::horizontal([Constraint::Length(runtime_width), Constraint::Min(1)]).split(area);
        frame.render_widget(Paragraph::new(runtime), columns[0]);
        frame.render_widget(
            Paragraph::new(Span::styled(shortcuts, Style::default().fg(theme::MUTED)))
                .alignment(Alignment::Right),
            columns[1],
        );
    } else {
        let compact = match &app.connection {
            Connection::Lost { reason } => format!(
                "● DISCONNECTED · {} · ctrl+p commands",
                super::tree::truncate(reason, area.width.saturating_sub(39) as usize)
            ),
            Connection::Live if app.tab == Tab::Sessions => {
                "ctrl+p commands · ctrl+x leader · ctrl+q quit".to_string()
            }
            Connection::Live => shortcuts.to_string(),
        };
        frame.render_widget(
            Paragraph::new(Span::styled(
                compact,
                if matches!(&app.connection, Connection::Lost { .. }) {
                    Style::default().fg(theme::BAD)
                } else {
                    Style::default().fg(theme::MUTED)
                },
            )),
            area,
        );
    }
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
        Overlay::Commands(palette) => command_palette(frame, area, palette),
        Overlay::Account(dialog) => account_dialog(frame, area, app, dialog),
        Overlay::SessionPicker { selected } => session_picker(frame, area, app, selected.as_ref()),
        Overlay::Help => help(frame, area, app),
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
            ..
        } => chooser(
            frame,
            area,
            &format!("approval requested — {id}"),
            &format!("request {request_id}\n{subject}\nr — attach a reason before answering"),
            &APPROVAL_CHOICES
                .iter()
                .map(|(decision, scope)| format!("{} ({})", decision.as_str(), scope.as_str()))
                .collect::<Vec<_>>(),
            *choice,
        ),
        Overlay::Prompt { label, buffer, .. } => prompt(frame, area, label, buffer),
        Overlay::New(dialog) => new_session(frame, area, app, dialog),
        Overlay::Settings(settings) => self_settings(frame, area, app, settings),
        Overlay::Machines(machines_state) => machines(frame, area, app, machines_state),
    }
}

fn command_palette(frame: &mut Frame, area: Rect, palette: &CommandPalette) {
    let commands = palette.visible();
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
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::MUTED))
        .title(Line::from(vec![
            Span::styled(" ctrl+p commands", Style::default().fg(theme::MUTED)),
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
            Span::styled("↑↓", Style::default().fg(theme::MUTED)),
            Span::styled(
                " navigate   enter select   esc close",
                Style::default().fg(theme::MUTED),
            ),
        ]))
        .alignment(Alignment::Right),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  search  ", Style::default().fg(theme::MUTED)),
            Span::raw(if palette.query.is_empty() {
                "type a command".to_string()
            } else {
                palette.query.clone()
            }),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ]))
        .block(Block::default().borders(Borders::ALL)),
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
                    .fg(theme::ACCENT)
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
        let gap = content_width
            .saturating_sub(start.chars().count() + command.shortcut().chars().count());
        let row = format!(
            "{start}{}{shortcut}",
            " ".repeat(gap),
            shortcut = command.shortcut()
        );

        lines.push(if selected {
            Line::styled(row, theme::selected())
        } else {
            Line::from(vec![
                Span::raw(row[..row.len().saturating_sub(command.shortcut().len())].to_string()),
                Span::styled(command.shortcut(), Style::default().fg(theme::MUTED)),
            ])
        });
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("no command matches \"{}\"", palette.query.trim()),
            Style::default().fg(theme::MUTED),
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
                .fg(theme::GOOD)
                .add_modifier(Modifier::BOLD),
        )));
        if let Some(email) = account.and_then(|account| account.email.as_deref()) {
            lines.push(Line::from(Span::styled(
                email.to_string(),
                Style::default().fg(theme::MUTED),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Codex keeps the subscription credentials on the runtime host.",
        ));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Enter/Esc closes  ·  l disconnects",
            Style::default().fg(theme::MUTED),
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
                        .fg(theme::WARN)
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
                    Style::default().fg(theme::ACCENT),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                "      press o to open it in a browser",
                Style::default().fg(theme::MUTED),
            )));
        }

        if dialog.url.is_none() && dialog.pending {
            lines.push(Line::from(Span::styled(
                format!("{} preparing a secure sign-in", theme::spinner(app.ticks)),
                Style::default().fg(theme::ACCENT),
            )));
        } else if dialog.pending {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("{} waiting for ChatGPT", theme::spinner(app.ticks)),
                Style::default().fg(theme::ACCENT),
            )));
        }

        if let Some(error) = &dialog.error {
            lines.push(Line::from(""));
            lines.extend(refusal_lines(error));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Esc cancels. Ouroboros never receives or stores your token.",
            Style::default().fg(theme::MUTED),
        )));
    }

    // Sized to what it holds, and clamped to the frame: a fixed height clipped the last
    // rows of this dialog on a short terminal, and those rows are the ones that say what to
    // press.
    let height = (wrapped(&lines, inner_width(area, ACCOUNT_WIDTH)) + 2).min(area.height);
    let popup = centered(area, ACCOUNT_WIDTH, height);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
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
    let sessions = app.sessions.merged();
    let height = (sessions.len() + 5).clamp(7, 20) as u16;
    let popup = centered(area, 62, height);
    frame.render_widget(Clear, popup);

    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        " switch session · enter open · x end ",
        theme::heading(),
    ));

    if sessions.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                if app.sessions.interactive.pending || app.sessions.coding.pending {
                    "Listing sessions…"
                } else {
                    "No sessions yet. Esc closes; use New session from ctrl+p."
                },
                Style::default().fg(theme::MUTED),
            ))
            .block(block),
            popup,
        );
        return;
    }

    let choice = app.sessions.picker_index(selected);
    let items = sessions
        .iter()
        .map(|session| {
            let mut spans = vec![
                Span::styled(
                    format!("{:<6}", session.plane.tag()),
                    Style::default().fg(theme::MUTED),
                ),
                Span::raw(super::tree::truncate(&session.id, 42)),
            ];
            if let Some(owners) = app.sessions.owner_conflict(session.plane, &session.id) {
                spans.push(Span::styled(
                    format!(
                        "  ID conflict · {}",
                        super::tree::truncate(&owners.join(" + "), 46)
                    ),
                    Style::default().fg(theme::BAD),
                ));
            } else if session.last_known {
                spans.push(Span::styled(
                    format!("  last-known · owner offline · {}", session.status.as_str()),
                    Style::default().fg(theme::WARN),
                ));
            } else {
                spans.push(Span::styled(
                    format!("  {}", session.status.as_str()),
                    theme::session_status(&session.status),
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
        .borders(Borders::ALL)
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
                        Style::default().fg(theme::GOOD)
                    }
                    MachineSecurity::Insecure | MachineSecurity::Mismatch => {
                        Style::default().fg(theme::BAD)
                    }
                    MachineSecurity::Unknown => Style::default().fg(theme::WARN),
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
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        };

        let mut spans = vec![
            Span::styled(
                if focused { "> " } else { "  " },
                Style::default().fg(theme::ACCENT),
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
                Style::default().fg(theme::MUTED),
            )),
            Line::from(Span::styled(
                if settings.edited {
                    "changed, and not written yet"
                } else {
                    ""
                },
                Style::default().fg(theme::WARN),
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
        .borders(Borders::ALL)
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
        MachineSecurity::Standalone | MachineSecurity::Secure => Style::default().fg(theme::GOOD),
        MachineSecurity::Insecure | MachineSecurity::Mismatch => Style::default().fg(theme::BAD),
        MachineSecurity::Unknown => Style::default().fg(theme::WARN),
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
            Style::default().fg(theme::WARN),
        )),
    ];
    if !summary.offline_names.is_empty() {
        facts.push(Line::from(Span::styled(
            format!("Offline: {}", summary.offline_names.join(", ")),
            Style::default().fg(theme::WARN),
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
                Style::default().fg(theme::ACCENT),
            ),
            Span::styled(format!("{:<28}", item.label(machines)), Style::default()),
            Span::styled(item.hint(machines), Style::default().fg(theme::MUTED)),
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
            Style::default().fg(theme::ACCENT),
        )));
    }
    frame.render_widget(Paragraph::new(detail).wrap(Wrap { trim: false }), rows[2]);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "↑↓ choose · Enter run · y copy CLI · r refresh · Esc close",
            Style::default().fg(theme::MUTED),
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
                Style::default().fg(theme::MUTED),
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
                Style::default().fg(theme::MUTED),
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
                Style::default().fg(theme::GOOD),
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
                Style::default().fg(theme::MUTED),
            )));
        }
        AddStep::Method | AddStep::Pick => {}
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(theme::BAD),
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
            Style::default().fg(theme::ACCENT),
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
        Style::default().fg(theme::MUTED),
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
                Style::default().fg(theme::MUTED),
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
                Style::default().fg(theme::MUTED),
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
                    Style::default().fg(theme::MUTED),
                )));
            }
            if let Some(error) = &add.error {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    error.clone(),
                    Style::default().fg(theme::BAD),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Tab fields · Enter review · Esc back. Invitation contents stay off screen.",
                Style::default().fg(theme::MUTED),
            )));
        }
        AddStep::Confirm => {
            lines.push(Line::from(""));
            if standalone {
                lines.push(Line::from(Span::styled(
                    "This Mac will restart once to become a fleet, then add the other machine.",
                    Style::default().fg(theme::WARN),
                )));
            }
            lines.push(Line::from(Span::styled(
                app.add_command_preview(),
                Style::default().fg(theme::ACCENT),
            )));
            if let Some(error) = &add.error {
                lines.push(Line::from(Span::styled(
                    error.clone(),
                    Style::default().fg(theme::BAD),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter runs this plan · y copy · Esc edit. No cookies are printed.",
                Style::default().fg(theme::MUTED),
            )));
        }
        AddStep::Working => {
            lines.push(Line::from(""));
            lines.push(theme::working(app.ticks, "Adding the machine…"));
            for line in add.log.iter().rev().take(8).rev() {
                lines.push(Line::from(Span::styled(
                    line.clone(),
                    Style::default().fg(theme::MUTED),
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
                        Style::default().fg(theme::ACCENT),
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter/Esc close · y copy recipe. Provider sign-in is still on that machine.",
                Style::default().fg(theme::MUTED),
            )));
        }
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn method_row(focused: bool, label: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            if focused { "> " } else { "  " },
            Style::default().fg(theme::ACCENT),
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
            Style::default().fg(theme::ACCENT),
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
            Style::default().fg(theme::MUTED),
        );
    };

    let position = format!("({}/{})", index + 1, choices.len());

    match choice {
        ProviderChoice::Unset => (
            format!("unset — stated per session {position}"),
            Style::default().fg(theme::MUTED),
        ),
        ProviderChoice::Probed { name, ready: true } => (
            format!("{name} {position}"),
            Style::default().fg(theme::GOOD),
        ),
        ProviderChoice::Probed { name, ready: false } => (
            format!("{name} — no executable found {position}"),
            Style::default().fg(theme::MUTED),
        ),
        // The config names it and the runtime does not. Said, rather than dropped.
        ProviderChoice::Unserved { name } => (
            format!("{name} — from the config file; this runtime does not report it {position}"),
            Style::default().fg(theme::WARN),
        ),
    }
}

/// The new-session form: every choice on screen at once, none of them made for you.
fn new_session(frame: &mut Frame, area: Rect, app: &App, dialog: &NewSession) {
    let providers = app.providers.value.as_deref().unwrap_or_default();
    let machines = app.machine_choices();
    let rows = dialog.fields();
    let height = (rows.len() + 8).min(area.height as usize) as u16;
    let popup = centered(area, 76, height);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
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
                        Style::default().fg(theme::WARN),
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
            NewField::ApprovalMode => ("approval", dialog.approval_label(), Style::default()),
            NewField::SandboxMode => ("files", dialog.sandbox_label(), Style::default()),
            NewField::Start => (
                "",
                if dialog.pending {
                    format!("starting {} ", theme::spinner(app.ticks))
                } else {
                    "[ start ]".to_string()
                },
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        };

        let mut spans = vec![
            Span::styled(
                if focused { "> " } else { "  " },
                Style::default().fg(theme::ACCENT),
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
            Style::default().fg(theme::MUTED),
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
            Style::default().fg(theme::WARN),
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
            Style::default().fg(theme::WARN),
        )));
    }

    if !dialog.request.machine.trim().is_empty() {
        footer.push(Line::from(Span::styled(
            "Connected checks reachability, not provider readiness. Install and sign in to the provider on that destination; fleet invites never copy credentials.",
            Style::default().fg(theme::WARN),
        )));
        footer.push(Line::from(Span::styled(
            "Workspace paths are resolved on that destination machine, not on this terminal.",
            Style::default().fg(theme::MUTED),
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
            Style::default().fg(theme::WARN),
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
            Style::default().fg(theme::WARN),
        );
    }

    if entry.ready() {
        return (
            "provider",
            format!("{} {position}", entry.provider),
            Style::default().fg(theme::GOOD),
        );
    }

    (
        "provider",
        format!("{} — not installed {position}", entry.provider),
        Style::default().fg(theme::MUTED),
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
                    Style::default().fg(theme::BAD)
                } else {
                    Style::default().fg(theme::MUTED)
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
        Style::default().fg(theme::MUTED)
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
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(detail_height), Constraint::Min(1)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(detail.to_string())
            .style(Style::default().fg(theme::MUTED))
            .wrap(Wrap { trim: false }),
        rows[0],
    );

    let items: Vec<ListItem> = options
        .iter()
        .map(|label| ListItem::new(Line::from(label.clone())))
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
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {label} "), theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("> ", Style::default().fg(theme::ACCENT)),
            Span::raw(buffer.to_string()),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ])),
        inner,
    );
}

const KEYS: &[(&str, &str)] = &[
    (
        "enter",
        "send, or queue a follow-up while the agent is busy",
    ),
    (
        "ctrl+j",
        "newline (shift+enter where the terminal reports it)",
    ),
    ("esc", "abort the running turn; empty prompt returns home"),
    (
        "ctrl+c",
        "clear the prompt; empty + running interrupts; twice quits",
    ),
    ("ctrl+p", "command palette"),
    (
        "ctrl+x",
        "leader: n new · l sessions · d details · x end · e editor · y copy · q quit",
    ),
    (
        "ctrl+x [ / v",
        "this transcript into native scrollback / into $EDITOR",
    ),
    ("ctrl+g", "edit the prompt in $VISUAL or $EDITOR"),
    (
        "ctrl+o",
        "expand, and collapse again, every cell in the conversation",
    ),
    (
        "ctrl+t",
        "plan and tasks panel, while a provider publishes one",
    ),
    ("ctrl+q", "quit dialog"),
    ("? / ,", "this page / settings, when the prompt is empty"),
    (
        "wheel",
        "scrolls; shift/ctrl+↑↓, pageup/down; config mouse = false frees it",
    ),
    ("↑ / ↓", "prompt history (or a line in a multiline draft)"),
    ("ctrl+w/k/u", "kill word, to line end, to line start"),
    ("alt+b / alt+f", "move by word"),
    (
        "/ commands",
        "type / for completions — every verb the editor offers",
    ),
    ("1-7 / Tab", "runtime tabs when the prompt is not focused"),
];

fn leader_hint(frame: &mut Frame, area: Rect) {
    let height = (LEADER_KEYS.len() as u16)
        .saturating_add(2)
        .min(area.height);
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
        .border_style(Style::default().fg(theme::ACCENT))
        .title(Span::styled(" ctrl+x ", theme::heading()));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let lines = LEADER_KEYS
        .iter()
        .map(|(key, description)| {
            Line::from(vec![
                Span::styled(format!(" {key:<4}"), Style::default().fg(theme::ACCENT)),
                Span::raw(*description),
            ])
        })
        .collect::<Vec<_>>();

    frame.render_widget(Paragraph::new(lines), inner);
}

fn help(frame: &mut Frame, area: Rect, app: &App) {
    let lines = help_lines(app);

    // Sized from the built rows, because the derived command block grows with the
    // editor's verb table and a fixed budget would push the honest limits off-screen.
    let popup = centered(area, 84, (lines.len() as u16 + 2).min(area.height));

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" hotkeys ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// Every row of the help overlay, honest limits included.
fn help_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = KEYS
        .iter()
        .map(|(key, description)| {
            Line::from(vec![
                Span::styled(format!("{key:<14}"), Style::default().fg(theme::ACCENT)),
                Span::raw(*description),
            ])
        })
        .collect();

    // The verb list is derived, never restated: the editor's completion table is the
    // single source of truth, so help cannot advertise what completion does not offer.
    let commands: Vec<&str> = COMMANDS.iter().map(|(name, _)| *name).collect();
    for (index, chunk) in commands.chunks(6).enumerate() {
        let label = if index == 0 { "/ commands" } else { "" };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<14}", label), Style::default().fg(theme::ACCENT)),
            Span::raw(chunk.join("  ")),
        ]));
    }

    lines.push(Line::from(""));

    // The honest limits, in the place someone looks when they are confused. Two short
    // lines rather than one long one, so a narrow terminal cannot wrap either of them
    // into something that reads as a different claim.
    lines.push(Line::from(Span::styled(
        format!(
            "one gateway view of the fleet through {}",
            if app.hello.node.is_empty() {
                "this runtime".to_string()
            } else {
                app.hello.node.clone()
            }
        ),
        Style::default().fg(theme::MUTED),
    )));

    lines.push(Line::from(Span::styled(
        "the token authenticates; it is not a sandbox",
        Style::default().fg(theme::MUTED),
    )));

    if !app.hello.operates() {
        lines.push(Line::from(Span::styled(
            "this listener runs at scope `read`: every mutating verb is refused with -32003",
            Style::default().fg(theme::WARN),
        )));
    }

    lines
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
            Style::default().fg(theme::MUTED),
        ));
    }

    if let Some(error) = error {
        spans.push(Span::styled(
            format!("[{}] ", super::tree::truncate(error, 60)),
            Style::default().fg(theme::BAD),
        ));
    }

    Line::from(spans)
}

/// The block every pane uses, so focus is visible in exactly one way.
pub fn pane(title: Line<'static>, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            Style::default().fg(theme::ACCENT)
        } else {
            Style::default().fg(theme::MUTED)
        })
        .title(title)
}
