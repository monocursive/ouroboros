//! Tabs 3 through 6: a list on the left, a value tree on the right.
//!
//! Four tabs share one renderer because they are one shape. Agents, teams, plans, control
//! runs, rollouts, signing decisions and grants differ in which method fills the list and
//! which fills the detail — never in what the detail *is*, which is a `Gateway.Wire` tree
//! that nothing here decodes. That is the point: `Mesh.state/1` answers a
//! `Jido.AgentServer.State` dense with pids, refs and `:queue` tuples, and a forged
//! `Ouroboros.Capability.*` module answers something this binary has never seen. Both
//! render, because both are trees.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use serde_json::Value;

use super::app::{App, Explorer, Pane, Tab, UpgradeSection};
use super::theme;
use super::tree::TreeView;
use super::view::{pane, panel_title};

pub fn draw(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.tab {
        Tab::Agents => single(frame, area, app.ticks, "agents", "agent state", true, {
            let ticks = app.ticks;
            let _ = ticks;
            &mut app.agents
        }),
        Tab::Teams => single(
            frame,
            area,
            app.ticks,
            "teams",
            "team state",
            true,
            &mut app.teams,
        ),
        Tab::Plans => plans(frame, area, app),
        Tab::Upgrade => upgrade(frame, area, app),
        _ => {}
    }
}

fn single(
    frame: &mut Frame,
    area: Rect,
    ticks: u64,
    list_title: &str,
    detail_title: &str,
    focused_tab: bool,
    explorer: &mut Explorer,
) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    list(frame, columns[0], ticks, list_title, explorer, focused_tab);
    detail(
        frame,
        columns[1],
        ticks,
        detail_title,
        explorer,
        focused_tab,
    );
}

fn plans(frame: &mut Frame, area: Rect, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let on_control = app.plans_on_control;
    let ticks = app.ticks;

    single(
        frame,
        rows[0],
        ticks,
        "orchestration plans",
        "plan",
        !on_control,
        &mut app.plans,
    );

    single(
        frame,
        rows[1],
        ticks,
        "control runs",
        "run",
        on_control,
        &mut app.control,
    );
}

fn list(
    frame: &mut Frame,
    area: Rect,
    ticks: u64,
    title: &str,
    explorer: &Explorer,
    tab_focused: bool,
) {
    let focused = tab_focused && explorer.focus == Pane::List;

    let block = pane(
        panel_title(
            title,
            explorer.rows.pending,
            explorer.rows.error.as_ref(),
            ticks,
        ),
        focused,
    );

    let Some(rows) = &explorer.rows.value else {
        // "loading" for a list the runtime refused is a pane that never resolves. A plane
        // that is configured off answers `-32004`, and saying so is the difference between
        // "there is nothing here" and "this node does not run that".
        let message = explorer
            .rows
            .error
            .clone()
            .unwrap_or_else(|| "loading".to_string());

        frame.render_widget(
            Paragraph::new(Span::styled(message, Style::default().fg(theme::MUTED)))
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );

        return;
    };

    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("no {title} on this node"),
                Style::default().fg(theme::MUTED),
            ))
            .block(block)
            .wrap(Wrap { trim: false }),
            area,
        );

        return;
    }

    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| {
            let mut spans = vec![Span::raw(super::tree::truncate(&row.label, 60))];

            if let Some(status) = &row.status {
                spans.push(Span::styled(
                    format!("  {status}"),
                    Style::default().fg(theme::MUTED),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default().with_selected(Some(explorer.selected));

    frame.render_stateful_widget(
        List::new(items).block(block).highlight_style(if focused {
            theme::selected()
        } else {
            theme::selected_unfocused()
        }),
        area,
        &mut state,
    );
}

fn detail(
    frame: &mut Frame,
    area: Rect,
    ticks: u64,
    title: &str,
    explorer: &mut Explorer,
    tab_focused: bool,
) {
    let focused = tab_focused && explorer.focus == Pane::Detail;

    let block = pane(
        panel_title(
            title,
            explorer.detail.pending,
            explorer.detail.error.as_ref(),
            ticks,
        ),
        focused,
    );

    let Some(value) = explorer.detail.value.clone() else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                if explorer.detail.error.is_some() {
                    "the runtime refused this detail; the reason is in the pane title"
                } else {
                    "select a row"
                },
                Style::default().fg(theme::MUTED),
            ))
            .block(block)
            .wrap(Wrap { trim: false }),
            area,
        );

        return;
    };

    let root = explorer
        .detail_of
        .clone()
        .unwrap_or_else(|| title.to_string());

    TreeView::new(&root, &value).render_block(frame, area, &mut explorer.tree, focused, block);
}

fn upgrade(frame: &mut Frame, area: Rect, app: &mut App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(20)])
        .split(area);

    sections(frame, columns[0], app);

    let section = app.upgrade.current();
    let focused = app.upgrade.focus == Pane::Detail;

    let panel = app.upgrade.panel(section);
    let block = pane(
        panel_title(
            section.title(),
            panel.pending,
            panel.error.as_ref(),
            app.ticks,
        ),
        focused,
    );

    // Two sections need a parameter the client has to be told, because the runtime has no
    // list-all for either: `upgrade.history` takes a module, and `Control.Grants.list/1`
    // is per-principal by design.
    let hint: Option<&str> = match section {
        UpgradeSection::History if app.upgrade.history_module.is_none() => {
            Some("press Enter to name a module; upgrade.history has no list-all")
        }
        UpgradeSection::Grants if app.upgrade.grants_principal.is_none() => Some(
            "press Enter to name a principal; Control.Grants.list/1 is per-principal by \
                  design and the gateway did not add a list-all",
        ),
        UpgradeSection::Signing if !app.hello.serves("signing.decisions") => {
            Some("this gateway does not serve signing.decisions")
        }
        _ => None,
    };

    if let Some(hint) = hint {
        frame.render_widget(
            Paragraph::new(Span::styled(hint, Style::default().fg(theme::MUTED)))
                .block(block)
                .wrap(Wrap { trim: false }),
            columns[1],
        );

        return;
    }

    let Some(value) = panel.value.clone() else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                if panel.error.is_some() {
                    "refused; the reason is in the pane title"
                } else {
                    "loading"
                },
                Style::default().fg(theme::MUTED),
            ))
            .block(block)
            .wrap(Wrap { trim: false }),
            columns[1],
        );

        return;
    };

    let root = root_label(app, section);

    TreeView::new(&root, &value).render_block(
        frame,
        columns[1],
        &mut app.upgrade.tree,
        focused,
        block,
    );
}

fn root_label(app: &App, section: UpgradeSection) -> String {
    match section {
        UpgradeSection::History => app
            .upgrade
            .history_module
            .clone()
            .unwrap_or_else(|| section.title().to_string()),
        UpgradeSection::Grants => app
            .upgrade
            .grants_principal
            .clone()
            .unwrap_or_else(|| section.title().to_string()),
        other => other.title().to_string(),
    }
}

fn sections(frame: &mut Frame, area: Rect, app: &App) {
    let block = pane(
        panel_title("upgrade", false, None, app.ticks),
        app.upgrade.focus == Pane::List,
    );

    let items: Vec<ListItem> = UpgradeSection::ALL
        .iter()
        .map(|section| {
            let panel = app.upgrade.panel(*section);
            let served = app.hello.serves(section.method());

            let mut spans = vec![Span::styled(
                section.title().to_string(),
                if served {
                    Style::default()
                } else {
                    // `hello.methods` is the feature gate and the only one (§2.3): a verb
                    // this build does not serve is shown as absent, not tried.
                    Style::default().fg(theme::MUTED)
                },
            )];

            if panel.error.is_some() {
                spans.push(Span::styled("  !", Style::default().fg(theme::BAD)));
            } else if let Some(Value::Array(items)) = &panel.value {
                spans.push(Span::styled(
                    format!("  {}", items.len()),
                    Style::default().fg(theme::MUTED),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default().with_selected(Some(app.upgrade.section));

    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(if app.upgrade.focus == Pane::List {
                theme::selected()
            } else {
                theme::selected_unfocused()
            }),
        area,
        &mut state,
    );
}
