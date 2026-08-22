//! The read-only page this client answers a question with: `/keys`.
//!
//! Its own module rather than another function in [`super::view`], which is already three
//! thousand lines and is where parallel work collides. It is a pure function of [`App`]
//! plus a scroll offset, like everything else that draws.
//!
//! ## `/keys` (B8)
//!
//! The *effective* map, which is the whole point: an operator who rebound a chord and an
//! operator who mistyped one both need to see what the client actually bound, not what its
//! defaults are. Rows that came out of `config.toml` are marked, and the lines of `[keys]`
//! this build could not act on are printed underneath by name — the map ran on its default
//! for those actions and saying so is the honesty invariant, not a nicety.
//!

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::keymap::{Action, Scope, Source};

use super::app::App;
use super::theme;
use super::view::centered;

/// How wide this page is, as a percentage of the frame. Narrower than `?` because it is
/// two columns of short text rather than a table of sentences.
const WIDTH: u16 = 76;

/// Draws a scrollable page of `lines` inside a titled block, with the same "there is more"
/// discipline the `?` panel uses: the last visible row says how much was not drawn, because
/// a panel that silently ends is one whose remaining half nobody finds (R1 4d(8)).
fn page(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line<'static>>, scroll: usize) {
    let wanted = lines.len() as u16 + 2;
    let ceiling = area.height.saturating_sub(2).max(6);
    let popup = centered(area, WIDTH, wanted.min(ceiling));

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), theme::heading()));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let height = inner.height as usize;
    let hidden = lines.len().saturating_sub(height);
    let scroll = scroll.min(hidden);
    let mut visible = lines[scroll..].to_vec();

    if hidden > scroll && visible.len() >= height && height > 0 {
        visible[height - 1] = Line::from(Span::styled(
            format!(
                "\u{2191}\u{2193} scrolls \u{b7} {} more row{}",
                hidden - scroll,
                if hidden - scroll == 1 { "" } else { "s" }
            ),
            Style::default().fg(theme::ACCENT),
        ));
    }

    frame.render_widget(Paragraph::new(visible).wrap(Wrap { trim: false }), inner);
}

/// `/keys`: every action, the key that reaches it, and where that key came from.
pub fn keymap(frame: &mut Frame, area: Rect, app: &App, scroll: usize) {
    page(frame, area, "keys", keymap_lines(app), scroll);
}

/// The rows, so a test can read them without a terminal.
pub fn keymap_lines(app: &App) -> Vec<Line<'static>> {
    let map = &app.keymap;
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        "action = \"key\" in [keys] of config.toml; \"off\" removes a key",
        theme::label(),
    )));

    // First, not last. Someone who opened this page because a chord did nothing is here
    // for exactly this block, and a forty-row table between them and it is a page that
    // answered a different question.
    let problems = map.problems();

    if problems.is_empty() {
        lines.push(Line::from(Span::styled(
            "every line of [keys] was used",
            Style::default().fg(theme::MUTED),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "NOT USED \u{2014} these lines were reported at start and ignored",
            Style::default().fg(theme::WARN),
        )));

        for problem in problems {
            lines.push(Line::from(Span::styled(
                problem.clone(),
                Style::default().fg(theme::WARN),
            )));
        }
    }

    for (scope, heading) in [
        (Scope::Global, "GLOBAL"),
        (Scope::Leader, "LEADER"),
        (Scope::Editor, "COMPOSER"),
    ] {
        lines.push(Line::from(Span::styled(heading, theme::label())));

        for action in Action::ALL.into_iter().filter(|a| a.scope() == scope) {
            let spec = map.spec(action);
            // Leader verbs are shown as the operator presses them, which is the leader and
            // then the verb — the same string the `?` panel and the palette print.
            let key = map.label(action);

            let key_style = if spec.is_off() {
                Style::default()
                    .fg(theme::MUTED)
                    .add_modifier(Modifier::DIM)
            } else if map.source(action) == Source::File {
                Style::default().fg(theme::ACTION)
            } else {
                Style::default().fg(theme::ACCENT)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("{:<20}", action.name()), Style::default()),
                Span::styled(format!("{key:<14}"), key_style),
                Span::styled(
                    if map.source(action) == Source::File {
                        "config  "
                    } else {
                        "default "
                    },
                    Style::default().fg(theme::MUTED),
                ),
                Span::styled(action.describe(), Style::default().fg(theme::MUTED)),
            ]));
        }
    }

    lines
}
