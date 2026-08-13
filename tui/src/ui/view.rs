//! The frame: the tab bar, the status line, the overlays, and which tab draws the middle.
//!
//! Drawing is a pure function of [`App`] plus mutable tree/scroll state, so a `TestBackend`
//! renders exactly what a terminal does. Nothing here calls the runtime, and nothing here
//! decides anything: a panel that is empty because a method failed says which method and
//! why, because "no agents" and "agents.list was refused" are different facts.

use ratatui::layout::{Constraint, Direction, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use crate::model::{compact, Plane, ProviderEntry};

use super::app::{
    provider_choices, App, Connection, Mode, NewField, NewSession, NoticeKind, Overlay,
    ProviderChoice, Settings, SettingsField, Tab, APPROVAL_CHOICES,
};
use super::theme;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

    tab_bar(frame, rows[0], app);

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

fn tab_bar(frame: &mut Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(index, tab)| {
            Line::from(vec![
                Span::styled(format!("{} ", index + 1), Style::default().fg(theme::MUTED)),
                Span::raw(tab.title()),
            ])
        })
        .collect();

    frame.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .highlight_style(theme::heading())
            .divider("│"),
        area,
    );
}

fn status_line(frame: &mut Frame, area: Rect, app: &App) {
    if let Some(notice) = &app.notice {
        let style = match notice.kind {
            NoticeKind::Info => Style::default().fg(theme::ACCENT),
            NoticeKind::Warn => Style::default().fg(theme::WARN),
            NoticeKind::Error => Style::default().fg(theme::BAD),
        };

        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(notice.text.clone(), style))),
            area,
        );

        return;
    }

    let mut spans = vec![
        Span::styled(app.address.clone(), Style::default().fg(theme::MUTED)),
        Span::raw("  "),
        Span::raw(if app.hello.node.is_empty() {
            "unknown node".to_string()
        } else {
            app.hello.node.clone()
        }),
        Span::raw("  scope "),
        Span::styled(
            if app.hello.scope.is_empty() {
                "unknown".to_string()
            } else {
                app.hello.scope.clone()
            },
            if app.hello.operates() {
                Style::default().fg(theme::WARN)
            } else {
                Style::default().fg(theme::MUTED)
            },
        ),
    ];

    match &app.mode {
        Mode::Spawned { pid } => {
            spans.push(Span::styled(
                format!("  spawned pid {pid}"),
                Style::default().fg(theme::MUTED),
            ));
        }
        Mode::Attached => spans.push(Span::styled(
            "  attached",
            Style::default().fg(theme::MUTED),
        )),
    }

    if let Connection::Lost { reason } = &app.connection {
        spans.push(Span::styled(
            format!("  disconnected: {reason}"),
            Style::default().fg(theme::BAD),
        ));
    }

    spans.push(Span::styled(
        "   ? keys   q quit",
        Style::default().fg(theme::MUTED),
    ));

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn overlay(frame: &mut Frame, area: Rect, app: &App) {
    let Some(overlay) = &app.overlay else {
        return;
    };

    match overlay {
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
        Overlay::Welcome => welcome(frame, area, app),
        Overlay::Settings(settings) => self_settings(frame, area, app, settings),
    }
}

/// The first-run panel: what this machine is, where its state is, what it can run, and the
/// four keys that matter. No questions — everything on it is already true.
///
/// Every line is labelled with where it came from, because two different kinds of fact are
/// on one screen: the node and the providers are the *runtime's* answers, the data
/// directory and the config file are this *client's* paths. A panel that ran them together
/// would let a reader believe the runtime had confirmed something it was never asked.
fn welcome(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered(area, 80, area.height.min(24));

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" ouroboros ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            "one runtime, on this machine, that you started.",
            Style::default().fg(theme::MUTED),
        )),
        Line::from(""),
        Line::from(Span::styled("as the runtime reports it", theme::label())),
        field("node", &blank(&app.hello.node)),
        field(
            "scope",
            &format!(
                "{}{}",
                blank(&app.hello.scope),
                if app.hello.operates() {
                    " — this client may start and stop work"
                } else {
                    " — every mutating verb is refused"
                }
            ),
        ),
        field("address", &app.address),
        Line::from(""),
        Line::from(Span::styled("this client's own paths", theme::label())),
    ];

    lines.push(field(
        "state",
        &match &app.data_dir {
            Some(dir) => dir.clone(),
            // Attach mode: this client did not choose where that runtime keeps anything.
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

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "providers, as this runtime probed them",
        theme::label(),
    )));
    lines.extend(provider_summary(app));

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("n", Style::default().fg(theme::ACCENT)),
        Span::raw(" start a session   "),
        Span::styled("?", Style::default().fg(theme::ACCENT)),
        Span::raw(" keys   "),
        Span::styled(",", Style::default().fg(theme::ACCENT)),
        Span::raw(" settings   "),
        Span::styled("q", Style::default().fg(theme::ACCENT)),
        Span::raw(" quit"),
    ]));
    lines.push(Line::from(Span::styled(
        "any key closes this; it is shown once",
        Style::default().fg(theme::MUTED),
    )));

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// The provider lines the welcome panel shows: available ones marked, missing ones dim and
/// naming the executable the runtime looked for.
fn provider_summary(app: &App) -> Vec<Line<'static>> {
    let Some(providers) = &app.providers.value else {
        // A list that was asked for and refused is not the same fact as one nobody has
        // asked for yet, and a panel that showed them the same way would be reporting a
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

    let ready: Vec<&ProviderEntry> = providers.iter().filter(|entry| entry.ready()).collect();

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
        .map(|entry| {
            match &entry.status {
                Some(probe) if probe.installed && probe.compatible => Line::from(vec![
                    Span::styled("  ✓ ", Style::default().fg(theme::GOOD)),
                    Span::raw(format!("{:<width$}", entry.provider)),
                    Span::styled(
                        probe.version.clone().unwrap_or_default(),
                        Style::default().fg(theme::MUTED),
                    ),
                ]),
                Some(probe) => Line::from(vec![
                    Span::styled("  · ", Style::default().fg(theme::MUTED)),
                    Span::styled(
                        format!("{:<width$}", entry.provider),
                        Style::default().fg(theme::MUTED),
                    ),
                    Span::styled(
                        match &probe.executable {
                            Some(executable) if !probe.installed => {
                                format!("no {executable} on the runtime's PATH")
                            }
                            // Installed but not compatible is a version the harness will
                            // not drive, which is a different sentence from a missing file.
                            Some(executable) => {
                                format!("{executable} is installed but not a version this harness drives")
                            }
                            None => "the runtime named no executable for it".to_string(),
                        },
                        Style::default().fg(theme::MUTED),
                    ),
                ]),
                // A probe that failed is not the same fact as a provider that is missing.
                None => Line::from(vec![
                    Span::styled("  ? ", Style::default().fg(theme::WARN)),
                    Span::raw(format!("{:<width$}", entry.provider)),
                    Span::styled(
                        format!("probe failed: {}", compact(&entry.error)),
                        Style::default().fg(theme::WARN),
                    ),
                ]),
            }
        })
        .collect();

    if ready.is_empty() {
        lines.push(Line::from(Span::styled(
            "  none of them found an executable. Install one of the CLIs above and press r \
             on the Dashboard; the runtime decides, not this client.",
            Style::default().fg(theme::WARN),
        )));
    }

    lines
}

/// The `,` overlay. Facts above, preferences below, and the line between them labelled.
fn self_settings(frame: &mut Frame, area: Rect, app: &App, settings: &Settings) {
    let popup = centered(area, 80, area.height.min(22));

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" settings ", theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

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
            "defaults this client remembers — they prefill `n`, nothing more",
            theme::label(),
        )),
    ];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(facts.len() as u16),
            Constraint::Length(SettingsField::ALL.len() as u16),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(Paragraph::new(facts), chunks[0]);

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
            Span::styled(format!("{label:<11}"), theme::label()),
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
        footer.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(theme::BAD),
        )));
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

/// A labelled fact, in the same shape the Dashboard's panes use so the two read as one UI.
fn field(name: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {name:<10}"), theme::label()),
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
