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

use crate::model::{compact, Plane, ProviderEntry};

use super::app::{
    provider_choices, AccountDialog, AccountFlow, App, CommandPalette, Connection, Mode, NewField,
    NewSession, NoticeKind, Overlay, ProviderChoice, QuickStart, QuickZone, Settings,
    SettingsField, Tab, APPROVAL_CHOICES,
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
}

fn shell_header(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(theme::MUTED));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let columns =
        Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).split(inner);

    let workspace = app
        .launch_dir
        .as_deref()
        .map(|path| super::tree::truncate(path, 42))
        .unwrap_or_else(|| "workspace unset".to_string());

    let context = if app.tab == Tab::Sessions {
        match &app.sessions.open {
            Some((_plane, id)) => format!("Session: {}", super::tree::truncate(id, 36)),
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

    let account = if let Some(state) = &app.account.value {
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
            "ctrl+p commands  ·  ctrl+q quit  ·  ctrl+c interrupt"
        } else {
            "ctrl+p commands  ·  Esc returns to coding  ·  r refresh"
        },
        Style::default().fg(theme::MUTED),
    )];

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
        Overlay::SessionPicker { choice } => session_picker(frame, area, app, *choice),
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
        Overlay::QuickStart(quick) => quick_start(frame, area, app, quick),
        Overlay::Settings(settings) => self_settings(frame, area, app, settings),
    }
}

fn command_palette(frame: &mut Frame, area: Rect, palette: &CommandPalette) {
    let commands = palette.visible();
    let width = if area.width >= 110 {
        area.width * 40 / 100
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

    frame.render_widget(Paragraph::new(lines), rows[2]);
}

fn account_dialog(frame: &mut Frame, area: Rect, app: &App, dialog: &AccountDialog) {
    let connected = app.chatgpt_connected();
    let popup = centered(area, 58, if connected { 10 } else { 14 });
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" ChatGPT account ", theme::heading()));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

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

        if let Some(url) = &dialog.url {
            lines.push(Line::from(vec![
                Span::styled("Open  ", theme::label()),
                Span::styled(url.clone(), Style::default().fg(theme::ACCENT)),
            ]));
        }
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

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn session_picker(frame: &mut Frame, area: Rect, app: &App, choice: usize) {
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

    let items = sessions
        .iter()
        .map(|session| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<6}", session.plane.tag()),
                    Style::default().fg(theme::MUTED),
                ),
                Span::raw(super::tree::truncate(&session.id, 42)),
                Span::styled(
                    format!("  {}", session.status.as_str()),
                    theme::session_status(&session.status),
                ),
            ]))
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

/// The quick-start screen: pick a model, say what it should do, press Enter.
///
/// The shortest honest path from an open terminal to a running agent, on one surface. Only
/// two things are *asked*, because only two of them are things nobody else can answer:
/// which model, and what for. Everything else is **stated**, with where it came from — a
/// screen that asked for a workspace it could already work out would be adding a decision
/// rather than removing one.
///
/// The two kinds of fact stay apart here as everywhere: the provider rows are the
/// runtime's own probe, the paths under them are this client's. A first run adds those
/// paths; a returning operator has seen them and is not shown them again.
fn quick_start(frame: &mut Frame, area: Rect, app: &App, quick: &QuickStart) {
    let picker = provider_rows(app, quick);

    let mut lines = vec![
        Line::from(Span::styled(
            "pick a model, say what it should do, and press Enter.",
            Style::default().fg(theme::MUTED),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("model", theme::label()),
            Span::styled(
                if app.providers.pending {
                    format!("  {} probing", theme::spinner(app.ticks))
                } else {
                    String::new()
                },
                Style::default().fg(theme::MUTED),
            ),
        ]),
    ];

    lines.extend(picker);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "what should it do?",
        theme::label(),
    )));
    lines.push(prompt_row(quick));
    lines.push(Line::from(""));

    // Stated, not asked — and each one says where it came from, because "the directory this
    // terminal is in" and "the default you stored" are different claims.
    lines.push(field(
        "workspace",
        &match (&app.config.defaults.workspace, &app.launch_dir) {
            (Some(stored), _) => format!("{stored} — your stored default"),
            (None, Some(here)) => format!("{here} — this terminal's directory"),
            (None, None) => "none — the plane decides".to_string(),
        },
    ));

    lines.push(field(
        "approval",
        &match app.config.defaults.approval_mode() {
            Some(mode) => format!("{} — your stored default", mode.as_str()),
            None => "unset — the plane's own default".to_string(),
        },
    ));

    // Said before Enter rather than after it. `hello.methods` is the feature gate (§2.3),
    // so this is knowable from the handshake, and a screen that let someone type a prompt
    // into a listener that will refuse to start anything would be wasting their sentence.
    if !app.hello.serves("interactive.start") {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "this gateway does not serve interactive.start, so Enter has nothing to call",
            Style::default().fg(theme::WARN),
        )));
    } else if !app.hello.operates() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(
                "this listener runs at scope `{}`; starting a session mutates the runtime \
                 and will be refused with -32003",
                app.hello.scope
            ),
            Style::default().fg(theme::WARN),
        )));
    }

    if let Some(error) = &quick.error {
        lines.push(Line::from(""));
        lines.extend(refusal_lines(error));
    }

    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled(
        if quick.pending {
            format!("starting {} ", theme::spinner(app.ticks))
        } else {
            "Tab swaps zones · ↑↓ or ctrl-n/ctrl-p pick a model · r (ctrl-r anywhere) \
             probes again · Enter starts · Esc to the dashboard"
                .to_string()
        },
        if quick.pending {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::MUTED)
        },
    )));

    lines.push(Line::from(Span::styled(
        "n opens the full dialog (plane, workspace, approval) · , settings · ? keys",
        Style::default().fg(theme::MUTED),
    )));

    if quick.first_run {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "first run — where this client keeps things",
            theme::label(),
        )));

        lines.push(field(
            "state",
            &match &app.data_dir {
                Some(dir) => dir.clone(),
                // Attach mode: this client did not choose where that runtime keeps
                // anything, and will not print a local path under a remote node.
                None => "with whoever started this runtime — not this client".to_string(),
            },
        ));

        lines.push(field(
            "config",
            &match &app.config_path {
                Some(path) => path.display().to_string(),
                None => "nowhere: neither XDG_CONFIG_HOME nor a home directory is set".to_string(),
            },
        ));
    }

    // Sized to what it actually holds, wrapping included. A constant height would either
    // clip the last line of a long provider list or float a short one in empty space, and
    // the line most likely to be clipped is the one naming a path — which is exactly the
    // kind of line a panel must not half-show.
    let rows = wrapped(&lines, inner_width(area, QUICK_WIDTH));
    let popup = centered(area, QUICK_WIDTH, (rows + 2).min(area.height));

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" ouroboros ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// How wide the quick-start panel is, as a percentage of the frame. Named because its
/// height is computed against the same number and the two must not drift apart.
const QUICK_WIDTH: u16 = 82;

/// How wide the settings overlay is, for the same reason.
const SETTINGS_WIDTH: u16 = 80;

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

/// The typed prompt, with a caret where typing goes and a hint where it has not started.
fn prompt_row(quick: &QuickStart) -> Line<'static> {
    let focused = quick.zone == QuickZone::Prompt && !quick.pending;

    let mut spans = vec![Span::styled(
        if focused { "> " } else { "  " },
        Style::default().fg(theme::ACCENT),
    )];

    if quick.prompt.is_empty() {
        // An empty prompt is a complete answer, and saying so is what stops the box reading
        // as a required field.
        spans.push(Span::styled(
            "optional — Enter with nothing here just opens a session",
            Style::default().fg(theme::MUTED),
        ));
    } else {
        spans.push(Span::raw(quick.prompt.clone()));
    }

    if focused {
        spans.push(Span::styled(
            "_",
            Style::default().add_modifier(Modifier::SLOW_BLINK),
        ));
    }

    Line::from(spans)
}

/// The selectable model list: what `runtime.providers` reported, with the cursor on it.
///
/// An entry whose probe found no executable is drawn dim and names the executable that was
/// looked for — that hint *is* the setup instruction, and it is why this screen stays
/// useful on a machine with nothing installed. It stays selectable regardless: "installed"
/// is a probe finding a file, the runtime is the authority on whether a session can start,
/// and refusing on a heuristic would be this client overruling it.
fn provider_rows(app: &App, quick: &QuickStart) -> Vec<Line<'static>> {
    let Some(providers) = &app.providers.value else {
        // A list that was asked for and refused is not the same fact as one nobody has
        // asked for yet, and a screen that showed them the same way would be reporting a
        // gateway that cannot answer as a gateway nobody has spoken to.
        if let Some(error) = &app.providers.error {
            return vec![Line::from(Span::styled(
                format!("  runtime.providers was refused: {error}"),
                Style::default().fg(theme::WARN),
            ))];
        }

        return vec![Line::from(Span::styled(
            if app.providers.pending {
                "  asking the runtime which providers it serves"
            } else {
                "  not asked yet"
            },
            Style::default().fg(theme::MUTED),
        ))];
    };

    if providers.is_empty() {
        return vec![Line::from(Span::styled(
            "  this runtime serves no coding providers, so there is nothing to start here",
            Style::default().fg(theme::WARN),
        ))];
    }

    let focused = quick.zone == QuickZone::Picker;
    let anything_ready = providers.iter().any(|entry| entry.ready());

    // Two past the longest name, so the column after it is a column rather than a word
    // touching the one before it.
    let width = providers
        .iter()
        .map(|entry| entry.provider.len())
        .max()
        .unwrap_or(1)
        + 2;

    let mut lines: Vec<Line> = providers
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            // A marker rather than a reversed row: the row's own colour is carrying the
            // probe result, and inverting it would make the one fact on the line unreadable
            // exactly where the cursor is.
            let mut spans = vec![Span::styled(
                if index == quick.provider { "> " } else { "  " },
                Style::default().fg(if focused { theme::ACCENT } else { theme::MUTED }),
            )];

            spans.extend(provider_cells(entry, width));
            Line::from(spans)
        })
        .collect();

    if !anything_ready {
        lines.push(Line::from(Span::styled(
            "  none found an executable. Install one of the CLIs above and press r — the \
             runtime decides, not this probe, so any of them is still yours to try.",
            Style::default().fg(theme::WARN),
        )));
    }

    lines
}

/// One provider's cells: the mark, the name, and the one line that says why it is dim.
fn provider_cells(entry: &ProviderEntry, width: usize) -> Vec<Span<'static>> {
    match &entry.status {
        Some(probe) if probe.installed && probe.compatible => vec![
            Span::styled("✓ ", Style::default().fg(theme::GOOD)),
            Span::raw(format!("{:<width$}", entry.provider)),
            Span::styled(
                probe.version.clone().unwrap_or_default(),
                Style::default().fg(theme::MUTED),
            ),
        ],
        Some(probe) => vec![
            Span::styled("· ", Style::default().fg(theme::MUTED)),
            Span::styled(
                format!("{:<width$}", entry.provider),
                Style::default().fg(theme::MUTED),
            ),
            Span::styled(
                match &probe.executable {
                    Some(executable) if !probe.installed => {
                        format!("no {executable} on the runtime's PATH")
                    }
                    // Installed but not compatible is a version the harness will not drive,
                    // which is a different sentence from a missing file.
                    Some(executable) => {
                        format!("{executable} is installed but not a version this harness drives")
                    }
                    None => "the runtime named no executable for it".to_string(),
                },
                Style::default().fg(theme::MUTED),
            ),
        ],
        // A probe that failed is not the same fact as a provider that is missing.
        None => vec![
            Span::styled("? ", Style::default().fg(theme::WARN)),
            Span::raw(format!("{:<width$}", entry.provider)),
            Span::styled(
                format!("probe failed: {}", compact(&entry.error)),
                Style::default().fg(theme::WARN),
            ),
        ],
    }
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
            "defaults this client remembers — they prefill the start screens, nothing more",
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

    for row in SettingsField::ALL {
        let focused = row == settings.field;

        let (label, value, style) = match row {
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
            SettingsField::QuickStart => (
                "quick start",
                if settings.quick_start {
                    "on — opens when this node has nothing running".to_string()
                } else {
                    "off — go straight to the dashboard".to_string()
                },
                Style::default(),
            ),
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
            // Twelve, not eleven: `quick start` is eleven characters, and a label column
            // exactly as wide as its widest label leaves a value touching it.
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
                "Tab/arrows move · left/right change · Enter on [ save ] writes the file · Esc \
                 closes without saving",
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
            NewField::Provider => provider_cell(providers, dialog.provider),
            NewField::Objective => (
                "objective",
                text_or_hint(&dialog.request.objective, "required"),
                hint_style(&dialog.request.objective),
            ),
            NewField::Workspace => (
                "workspace",
                text_or_hint(&dialog.request.workspace, "none — the plane decides"),
                hint_style(&dialog.request.workspace),
            ),
            NewField::ApprovalMode => ("approval", dialog.approval_label(), Style::default()),
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
            "Tab/arrows move · left/right change · Enter on [ start ] · Esc cancels",
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
    } else if !providers
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

    frame.render_widget(Paragraph::new(footer).wrap(Wrap { trim: false }), chunks[2]);
}

fn provider_cell(providers: &[ProviderEntry], index: usize) -> (&'static str, String, Style) {
    let Some(entry) = providers.get(index) else {
        return (
            "provider",
            "none available".to_string(),
            Style::default().fg(theme::WARN),
        );
    };

    let position = format!("({}/{})", index + 1, providers.len());

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
    ("1-7 / Tab", "switch tab"),
    ("n", "start a new session (Sessions tab)"),
    ("j k / arrows", "move; in a transcript, scroll"),
    (
        "h l / arrows",
        "move between panes; collapse or expand a tree node",
    ),
    (
        "Enter",
        "open a session, toggle a tree node, send a composed message",
    ),
    ("i", "compose a message for the open session"),
    ("s", "steer the open session"),
    ("a", "reopen the pending approval"),
    (
        "ctrl+e",
        "toggle between agent chat and complete event details",
    ),
    ("x", "close or kill the open session (confirmed)"),
    (
        "ctrl-c",
        "interrupt the open session's active turn — never this client",
    ),
    (
        "Esc",
        "leave the composer, then the transcript, then the session",
    ),
    ("r", "refresh this tab now"),
    (
        ",",
        "settings: this client's defaults, and where they are kept",
    ),
    ("q", "quit dialog"),
    ("?", "this page"),
];

fn help(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered(area, 84, (KEYS.len() + 8) as u16);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" keys ", theme::heading()));

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
            "a single-node view of {}",
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
