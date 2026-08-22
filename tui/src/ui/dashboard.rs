//! Tab 1: what this node is, which planes are up, and what it can run.
//!
//! The availability matrix is the point of the tab, and it is rendered from *whatever
//! keys the runtime sent* rather than from a list compiled into this binary — a plane
//! added upstream tomorrow appears here today. Its three states are three colours
//! (`super::theme::availability`), and `disabled` is deliberately not one of the alarming
//! ones: the control plane and the workspace plane report it when nobody configured them.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::compact;

use super::app::App;
use super::theme;
use super::view::{pane, panel_title};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(3)])
        .split(columns[0]);

    node(frame, left[0], app);
    nodes(frame, left[1], app);
    right(frame, columns[1], app);
}

fn node(frame: &mut Frame, area: Rect, app: &App) {
    let block = pane(
        panel_title(
            "runtime",
            app.status.pending,
            app.status.error.as_ref(),
            app.ticks,
        ),
        false,
    );

    let mut lines = vec![
        field("server", &blank(&app.hello.server)),
        field("protocol", &app.hello.protocol.to_string()),
        field("methods", &app.hello.methods.len().to_string()),
    ];

    match &app.status.value {
        Some(status) => {
            lines.push(field("node", &blank(&status.node)));
            lines.push(field("role", &blank(&status.role)));
            lines.push(field("cluster", &status.cluster_summary()));
            lines.push(field(
                "upgrade",
                status.mode("upgrade").unwrap_or("unknown"),
            ));
            lines.push(field(
                "release",
                status.mode("release").unwrap_or("unknown"),
            ));
            lines.push(field(
                "control",
                &format!(
                    "{} ({} runs)",
                    status
                        .availability
                        .get("control")
                        .map(|availability| availability.as_str())
                        .unwrap_or("unknown"),
                    status.control.runs.len()
                ),
            ));
            lines.push(field("forge", &status.forge_summary()));
        }
        None => {
            lines.push(field("node", &blank(&app.hello.node)));
            lines.push(field("role", &blank(&app.hello.role)));
            lines.push(Line::from(Span::styled(
                "waiting for runtime.status",
                Style::default().fg(theme::muted()),
            )));
        }
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn nodes(frame: &mut Frame, area: Rect, app: &App) {
    let block = pane(panel_title("machines", false, None, app.ticks), false);
    let summary = app.machine_summary();
    let expected = summary
        .expected
        .map(|expected| expected.to_string())
        .unwrap_or_else(|| "?".into());
    let offline = summary
        .offline
        .map(|offline| offline.to_string())
        .unwrap_or_else(|| "?".into());
    let security_style = match summary.security {
        super::app::MachineSecurity::Standalone | super::app::MachineSecurity::Secure => {
            Style::default().fg(theme::good())
        }
        super::app::MachineSecurity::Insecure | super::app::MachineSecurity::Mismatch => {
            Style::default().fg(theme::bad())
        }
        super::app::MachineSecurity::Unknown => Style::default().fg(theme::warn()),
    };

    let mut lines = vec![
        field("mode", &summary.mode),
        field("local", &summary.machine),
        Line::from(format!(
            "Expected {expected} · Connected {} · Offline {offline}",
            summary.connected
        )),
        Line::from(Span::styled(summary.security.label(), security_style)),
    ];

    match &app.status.value {
        Some(status) if !status.connected_nodes.is_empty() => lines.extend(
            status
                .connected_nodes
                .iter()
                .map(|node| Line::from(format!("connected  {node}"))),
        ),
        Some(_) if summary.mode == "Standalone" => lines.push(Line::from(Span::styled(
            // Kept as a reassuring state, not an error: a laptop daemon is standalone by
            // default and the guided surface is where a second machine is added.
            "none — this runtime is not connected to other nodes",
            Style::default().fg(theme::muted()),
        ))),
        Some(_) => lines.push(Line::from(Span::styled(
            summary.recovery,
            Style::default().fg(theme::warn()),
        ))),
        None => lines.push(Line::from(Span::styled(
            "waiting for live machine status",
            Style::default().fg(theme::muted()),
        ))),
    }

    lines.push(Line::from(Span::styled(
        "Open /machines for guided setup and recovery",
        Style::default().fg(theme::accent()),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn right(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    availability(frame, rows[0], app);
    providers(frame, rows[1], app);
}

fn availability(frame: &mut Frame, area: Rect, app: &App) {
    let block = pane(
        panel_title(
            "availability",
            app.status.pending,
            app.status.error.as_ref(),
            app.ticks,
        ),
        false,
    );

    let Some(status) = &app.status.value else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "waiting for runtime.status",
                Style::default().fg(theme::muted()),
            ))
            .block(block),
            area,
        );

        return;
    };

    if status.availability.is_empty() {
        // The gateway answered, so this is the runtime reporting no matrix at all rather
        // than a plane being down, and it is said that way.
        frame.render_widget(
            Paragraph::new(Span::styled(
                "the runtime reported no availability map",
                Style::default().fg(theme::warn()),
            ))
            .block(block),
            area,
        );

        return;
    }

    let width = status
        .availability
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(1)
        .max(1);

    let items: Vec<ListItem> = status
        .availability
        .iter()
        .map(|(plane, state)| {
            ListItem::new(Line::from(vec![
                Span::raw(format!("{plane:<width$}  ")),
                Span::styled(state.as_str().to_string(), theme::availability(state)),
            ]))
        })
        .collect();

    frame.render_widget(List::new(items).block(block), area);
}

fn providers(frame: &mut Frame, area: Rect, app: &App) {
    let block = pane(
        panel_title(
            "providers",
            app.providers.pending,
            app.providers.error.as_ref(),
            app.ticks,
        ),
        false,
    );

    let Some(providers) = &app.providers.value else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "probing providers",
                Style::default().fg(theme::muted()),
            ))
            .block(block),
            area,
        );

        return;
    };

    if providers.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "this runtime serves no coding providers",
                Style::default().fg(theme::muted()),
            ))
            .block(block),
            area,
        );

        return;
    }

    let width = providers
        .iter()
        .map(|entry| entry.provider.len())
        .max()
        .unwrap_or(1);

    let items: Vec<ListItem> = providers
        .iter()
        .map(|entry| {
            let mut spans = vec![Span::raw(format!("{:<width$}  ", entry.provider))];

            match &entry.status {
                Some(probe) => {
                    spans.push(Span::styled(
                        if probe.installed {
                            "installed"
                        } else {
                            "not installed"
                        }
                        .to_string(),
                        if probe.installed {
                            Style::default().fg(theme::good())
                        } else {
                            Style::default().fg(theme::muted())
                        },
                    ));

                    if probe.installed && !probe.compatible {
                        spans.push(Span::styled(
                            "  incompatible",
                            Style::default().fg(theme::warn()),
                        ));
                    }

                    spans.push(Span::styled(
                        format!("  auth {}", compact(&probe.authenticated)),
                        Style::default().fg(theme::muted()),
                    ));

                    if let Some(version) = &probe.version {
                        spans.push(Span::styled(
                            format!("  {version}"),
                            Style::default().fg(theme::muted()),
                        ));
                    }
                }
                // A probe that failed is not the same fact as a provider that is missing.
                None => spans.push(Span::styled(
                    format!("probe failed: {}", compact(&entry.error)),
                    Style::default().fg(theme::warn()),
                )),
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    frame.render_widget(List::new(items).block(block), area);
}

fn field(name: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{name:<10}"), theme::label()),
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
