//! The Upgrade tab: a section list on the left, a value tree on the right.
//!
//! Rollouts, signing decisions and grants differ in which method fills the detail — never
//! in what the detail *is*, which is a `Gateway.Wire` tree that nothing here decodes. That
//! is the point: a forged `Ouroboros.Capability.*` module answers something this binary
//! has never seen, and it renders, because it is a tree.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use serde_json::Value;

use super::app::{App, Pane, Tab, UpgradeSection};
use super::theme;
use super::tree::TreeView;
use super::view::{pane, panel_title};

pub fn draw(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.tab == Tab::Upgrade {
        upgrade(frame, area, app);
    }
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

    // One section needs a parameter the client has to be told, because the runtime has no
    // list-all for it: `Control.Grants.list/1` is per-principal by design.
    let hint: Option<&str> = match section {
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
            Paragraph::new(Span::styled(hint, Style::default().fg(theme::muted())))
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
                Style::default().fg(theme::muted()),
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
                    Style::default().fg(theme::muted())
                },
            )];

            if panel.error.is_some() {
                spans.push(Span::styled("  !", Style::default().fg(theme::bad())));
            } else if let Some(Value::Array(items)) = &panel.value {
                spans.push(Span::styled(
                    format!("  {}", items.len()),
                    Style::default().fg(theme::muted()),
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
