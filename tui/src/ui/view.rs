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

use crate::model::{Plane, ProviderEntry};

use super::app::{
    provider_choices, AccountDialog, AccountFlow, App, CommandPalette, Connection, MachineAction,
    MachineSecurity, Machines, Mode, NewField, NewSession, NoticeKind, Overlay, ProviderChoice,
    Settings, SettingsField, Tab, APPROVAL_CHOICES, LEADER_KEYS,
};
use super::theme;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
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

    let columns =
        Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).split(inner);

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
            Some((_plane, id)) => {
                let session = format!("Session: {}", super::tree::truncate(id, 36));
                if app.waiting_for_open_agent_reply() {
                    format!("{}  {session}", theme::spinner(app.ticks))
                } else {
                    session
                }
            }
            None => "New coding session".to_string(),
        }
    } else {
        format!("Runtime & distribution: {}", app.tab.title())
    };

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("ouroboros", theme::heading()),
            Span::styled("  │  ", Style::default().fg(theme::MUTED)),
            Span::styled(workspace, Style::default().fg(theme::MUTED)),
            Span::styled("  │  ", Style::default().fg(theme::MUTED)),
            Span::raw(context),
        ])),
        columns[0],
    );

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

    frame.render_widget(
        Paragraph::new(account).alignment(Alignment::Right),
        columns[1],
    );
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

    let mut spans = vec![Span::styled(
        if app.tab == Tab::Sessions {
            "ctrl+p commands  ·  ctrl+x leader  ·  esc interrupt  ·  ctrl+q quit"
        } else {
            "ctrl+p commands  ·  Esc returns to coding  ·  r refresh"
        },
        Style::default().fg(theme::MUTED),
    )];

    // Which runtime this is talking to, and at what scope. Terse, and always present: an
    // `ouro` attached over a tunnel is driving a node somewhere else, and every path it
    // names — every workspace, every log file — belongs to that node rather than to this
    // machine. The scope rides along because it is what decides whether a verb will be
    // refused at all.
    spans.push(Span::styled(
        format!(
            "  ·  {} {} {}",
            if app.spawned() { "own" } else { "attached" },
            if app.hello.scope.trim().is_empty() {
                "scope?"
            } else {
                app.hello.scope.trim()
            },
            super::tree::truncate(&app.address, 30)
        ),
        Style::default().fg(theme::MUTED),
    ));

    if let Connection::Lost { reason } = &app.connection {
        spans.push(Span::styled(
            format!("  disconnected: {reason}"),
            Style::default().fg(theme::BAD),
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn overlay(frame: &mut Frame, area: Rect, app: &App) {
    let Some(overlay) = &app.overlay else {
        return;
    };

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
            &format!("request {request_id}\n{subject}"),
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
        .title(Span::styled(
            " ctrl+p commands ",
            Style::default().fg(theme::MUTED),
        ));
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

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" switch session ", theme::heading()));

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

/// Settings → Machines: a vocabulary-first fleet setup and recovery surface. It never
/// executes a fleet command. Copying the selected command is the only mutation, and the
/// exact command remains an ordinary terminal action so an invite can never be created or
/// imported by an accidental keypress.
fn machines(frame: &mut Frame, area: Rect, app: &App, machines: &Machines) {
    let summary = app.machine_summary();
    let popup = centered(area, MACHINES_WIDTH, 32.min(area.height));

    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" machines ", theme::heading()));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::vertical([
        Constraint::Length(9),
        Constraint::Length(MachineAction::ALL.len() as u16 + 1),
        Constraint::Min(6),
        Constraint::Length(4),
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
    let offline_names = if summary.offline_names.is_empty() {
        None
    } else {
        Some(format!("Offline: {}", summary.offline_names.join(", ")))
    };

    let security_style = match summary.security {
        MachineSecurity::Standalone | MachineSecurity::Secure => Style::default().fg(theme::GOOD),
        MachineSecurity::Insecure | MachineSecurity::Mismatch => Style::default().fg(theme::BAD),
        MachineSecurity::Unknown => Style::default().fg(theme::WARN),
    };

    let mut facts = vec![
        Line::from(Span::styled(
            "Run agents on this machine alone, or connect trusted machines as one fleet.",
            theme::label(),
        )),
        field("mode", &summary.mode),
        field("fleet", &fleet),
        field("local", &local),
        Line::from(vec![
            Span::styled("machines    ", theme::label()),
            Span::raw(format!(
                "Known {expected} · Connected {} · Offline {offline}",
                summary.connected
            )),
        ]),
        Line::from(vec![
            Span::styled("security    ", theme::label()),
            Span::styled(summary.security.label(), security_style),
        ]),
        Line::from(vec![
            Span::styled("recovery    ", theme::label()),
            Span::raw(summary.recovery),
        ]),
    ];
    if let Some(offline_names) = offline_names {
        facts.push(Line::from(Span::styled(
            offline_names,
            Style::default().fg(theme::WARN),
        )));
    }
    frame.render_widget(Paragraph::new(facts).wrap(Wrap { trim: false }), rows[0]);

    let mut actions = vec![Line::from(Span::styled(
        "Choose a next step — the guide shows commands but never runs them",
        theme::label(),
    ))];
    for (index, action) in MachineAction::ALL.iter().copied().enumerate() {
        let focused = machines.selected == index;
        actions.push(Line::from(vec![
            Span::styled(
                if focused { "> " } else { "  " },
                Style::default().fg(theme::ACCENT),
            ),
            Span::styled(format!("{:<28}", action.label()), Style::default()),
            Span::styled(action.command(), Style::default().fg(theme::ACCENT)),
        ]));
    }
    frame.render_widget(Paragraph::new(actions), rows[1]);

    let selected = machines.guide.unwrap_or_else(|| machines.selected());
    let mut detail = vec![Line::from(vec![
        Span::styled(
            if machines.guide.is_some() {
                format!("{}  ", selected.label())
            } else {
                format!("Preview: {}  ", selected.label())
            },
            theme::heading(),
        ),
        Span::styled(selected.command(), Style::default().fg(theme::ACCENT)),
    ])];
    detail.extend(machine_guidance(selected, machines.guide.is_some()));
    frame.render_widget(Paragraph::new(detail).wrap(Wrap { trim: false }), rows[2]);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Network recovery: a running Ouroboros process retries fleet membership automatically.",
                Style::default().fg(theme::WARN),
            )),
            Line::from(Span::styled(
                "Process/reboot: activate the service for crash/login recovery; Linux pre-login boot needs optional linger.",
                Style::default().fg(theme::WARN),
            )),
            Line::from(Span::styled(
                "Boundary: live provider work does not migrate after a full host loss.",
                Style::default().fg(theme::WARN),
            )),
            Line::from(Span::styled(
                "↑↓ choose · Enter open guide · y copy command · r refresh · Esc back/close",
                Style::default().fg(theme::MUTED),
            )),
        ])
        .wrap(Wrap { trim: false }),
        rows[3],
    );
}

fn machine_guidance(action: MachineAction, expanded: bool) -> Vec<Line<'static>> {
    if !expanded {
        return vec![Line::from(Span::styled(
            "Press Enter for plain-language steps, or y to copy this command. No Erlang settings are needed.",
            Style::default().fg(theme::MUTED),
        ))];
    }

    let lines: &[&str] = match action {
        MachineAction::Create => &[
            "If this TUI is attached to a standalone runtime, quit or detach first: run `ouro stop`, then `ouro fleet create`, then `ouro daemon`.",
            "On separate machines, first run `tailscale status`, `tailscale ip -4`, and `tailscale ping PEER`; use the private IPv4 or one-record MagicDNS name when `--host` is requested.",
            "Fleet creation refuses to change a live runtime. On a stopped first machine, Ouroboros safely detects its name and reachable hostname.",
            "If detection cannot prove the hostname is reachable, it asks for `--host HOST`; `--machine NAME` is an optional friendly-name override.",
            "The output prints the exact private TCP ports to allow between fleet devices. Keys and cookies stay in mode-0600 files, never process arguments.",
            "Then choose Add another machine to make one invite per machine.",
        ],
        MachineAction::Join => &[
            "Install the same Ouroboros release on the invited machine and copy its .ouro invite there using a private channel.",
            "Set the copied invite to mode 0600, then run the join command. It imports identity; you do not type cookies, certificates, or node names.",
            "Start `ouro daemon`, then use `ouro fleet status` on either machine.",
        ],
        MachineAction::Invite => &[
            "Run this on the fleet's original owner machine (the one holding invitation authority). NAME is a friendly label; HOST is how the other machines reach the new one.",
            "The invite is private membership material. Send it only to that machine and do not paste its contents into chat or logs.",
            "Create a separate invite for every machine. A lost file can be reissued for the exact same identity with `--replace`.",
            "For an abandoned or mistyped invite, run `ouro fleet invite cancel --machine NAME --out fleet.ouro-roster`. It is safe live; restart the owner when convenient so its boot-time seeds refresh.",
            "Cancel fixes the expected list but does not revoke a copied credential. A leak requires whole-fleet credential rotation, so keep every invite private even before it is used.",
        ],
        MachineAction::Service => &[
            "Run this after create or join on every packaged macOS or Linux machine that should recover without you.",
            "Install only writes a private user service; it deliberately does not start anything behind your back.",
            "Review and run the exact activation command it prints, then check `ouro fleet service status`; do not also run a separate daemon.",
            "Once activated, the OS service restores Ouroboros after a crash and at login; Linux pre-login boot is an optional advanced setup printed by the command.",
        ],
        MachineAction::Status => &[
            "Shows which machines are known, connected, or offline and whether encrypted distribution is active.",
            "An offline known machine stays visible. Its running daemon retries membership; the recovery service handles process crashes and reboots.",
            "Start work with `ouro new --machine NAME --provider PROVIDER --workspace /absolute/path/on/NAME/project`; that path is on the destination. The New Session form enforces the same rule.",
        ],
        MachineAction::Doctor => &[
            "Checks names, reachability, versions, encrypted distribution, and the daemon's restart setup.",
            "Each failed check includes a concrete fix. The command never prints cookies, private keys, or invite contents.",
        ],
        MachineAction::Sync => &[
            "Owner: `ouro fleet sync export --out fleet.ouro-roster`. On each recipient, first run `ouro fleet service status`.",
            "Use its exact deactivation command when installed; otherwise run `ouro stop`.",
            "Then run `ouro fleet sync import fleet.ouro-roster`. Copy this mode-0600 file privately; sync does not revoke credentials.",
            "After import, reactivate that unit with its printed command or run `ouro daemon`, then `ouro fleet doctor`. Doctor's host/service checks are local.",
        ],
    };

    lines
        .iter()
        .map(|line| Line::from((*line).to_string()))
        .collect()
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
    let height = (options.len() + detail.lines().count() + 4).min(area.height as usize) as u16;
    let popup = centered(area, 70, height);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(detail.lines().count() as u16),
            Constraint::Min(1),
        ])
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
        "leader: n new · l sessions · e editor · y copy · q quit",
    ),
    ("ctrl+g", "edit the prompt in $VISUAL or $EDITOR"),
    ("ctrl+o", "toggle agent chat and complete event details"),
    ("ctrl+q", "quit dialog"),
    ("?", "this page, when the prompt is empty"),
    (
        "wheel",
        "scroll the transcript; shift/ctrl+↑↓ and pageup/down too",
    ),
    ("↑ / ↓", "prompt history (or a line in a multiline draft)"),
    ("ctrl+w/k/u", "kill word, to line end, to line start"),
    ("alt+b / alt+f", "move by word"),
    (
        "/ commands",
        "new, write, switch, preview, admit, capabilities, help, quit",
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
    let popup = centered(area, 84, (KEYS.len() + 8) as u16);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" hotkeys ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines: Vec<Line> = KEYS
        .iter()
        .map(|(key, description)| {
            Line::from(vec![
                Span::styled(format!("{key:<14}"), Style::default().fg(theme::ACCENT)),
                Span::raw(*description),
            ])
        })
        .collect();

    lines.push(Line::from(""));

    // The honest limits, in the place someone looks when they are confused. Two short
    // lines rather than one long one, so a narrow terminal cannot wrap either of them
    // into something that reads as a different claim.
    lines.push(Line::from(Span::styled(
        format!(
            "one gateway view of the fleet through {}",
            if app.hello.node.is_empty() {
                "this runtime"
            } else {
                &app.hello.node
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

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
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
