//! The two read-only pages this client answers a question with: `/keys` and `/cost`.
//!
//! Their own module rather than another two functions in [`super::view`], which is already
//! three thousand lines and is where parallel work collides. Both are pure functions of
//! [`App`] plus a scroll offset, like everything else that draws.
//!
//! ## `/keys` (B8)
//!
//! The *effective* map, which is the whole point: an operator who rebound a chord and an
//! operator who mistyped one both need to see what the client actually bound, not what its
//! defaults are. Rows that came out of `config.toml` are marked, and the lines of `[keys]`
//! this build could not act on are printed underneath by name — the map ran on its default
//! for those actions and saying so is the honesty invariant, not a nicety.
//!
//! ## `/cost` (I2)
//!
//! Two accounts side by side, because they answer different questions and disagreeing is
//! normal:
//!
//! - **as the runtime reports it** — `interactive.info`'s `usage`, folded by
//!   `Interactive.State` over the whole session including the part this client never saw.
//!   `cost_usd` is absent rather than zero where the provider reported no cost.
//! - **as this transcript folds** — [`Watch::usage`], over the events still held here. It
//!   is labelled *partial* whenever the window no longer covers the session, because a
//!   total built from a pruned window is a lower bound and printing it as a total would be
//!   a measurement presented as a fact.
//!
//! The `[budget] max_cost_usd` line states the soft limit and says, in the overlay, that
//! this client only warns. Budgets that refuse work are the runtime's; a client cannot
//! stop a turn it does not run.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::keymap::{Action, Scope, Source};
use crate::ui::transcript::UsageTotals;

use super::app::App;
use super::theme;
use super::view::{centered, money, tokens};

/// How wide these pages are, as a percentage of the frame. Narrower than `?` because both
/// are two columns of short text rather than a table of sentences.
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
            Style::default().fg(theme::accent()),
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
            Style::default().fg(theme::muted()),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "NOT USED \u{2014} these lines were reported at start and ignored",
            Style::default().fg(theme::warn()),
        )));

        for problem in problems {
            lines.push(Line::from(Span::styled(
                problem.clone(),
                Style::default().fg(theme::warn()),
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
                    .fg(theme::muted())
                    .add_modifier(Modifier::DIM)
            } else if map.source(action) == Source::File {
                Style::default().fg(theme::action_colour())
            } else {
                Style::default().fg(theme::accent())
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
                    Style::default().fg(theme::muted()),
                ),
                Span::styled(action.describe(), Style::default().fg(theme::muted())),
            ]));
        }
    }

    lines
}

/// `/cost` and `/usage`: what this session has spent.
pub fn cost(frame: &mut Frame, area: Rect, app: &App, scroll: usize) {
    page(frame, area, "cost", cost_lines(app), scroll);
}

/// One `label  value` row, or nothing at all where the value was never reported.
///
/// Absent rather than zero, everywhere: a session whose provider reported no cache reads
/// and a session whose provider does not report cache reads are different facts, and a
/// `0` standing in for the second is this client inventing a measurement.
fn count(label: &str, value: Option<u64>) -> Option<Line<'static>> {
    let value = value?;

    Some(Line::from(vec![
        Span::styled(
            format!("  {label:<22}"),
            Style::default().fg(theme::muted()),
        ),
        Span::raw(format!("{} ({value})", tokens(value))),
    ]))
}

pub fn cost_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let facts = app.session_facts();

    let Some(facts) = facts else {
        lines.push(Line::from(Span::styled(
            "no interactive session is open, so there is nothing spent to report",
            Style::default().fg(theme::muted()),
        )));
        return lines;
    };

    lines.push(Line::from(vec![
        Span::styled("session  ", Style::default().fg(theme::muted())),
        Span::raw(super::tree::truncate(&facts.id, 48)),
    ]));

    if let Some(model) = &facts.model {
        lines.push(Line::from(vec![
            Span::styled("model    ", Style::default().fg(theme::muted())),
            Span::raw(super::tree::truncate(model, 48)),
        ]));
    }

    // ----- as the runtime reports it ---------------------------------------------------
    lines.push(Line::from(Span::styled(
        "AS THE RUNTIME REPORTS IT (interactive.info)",
        theme::label(),
    )));

    match &facts.usage {
        None => lines.push(Line::from(Span::styled(
            "  this session's usage has not been reported",
            Style::default().fg(theme::muted()),
        ))),
        Some(usage) => {
            lines.extend(count("input tokens", usage.input_tokens));
            lines.extend(count("output tokens", usage.output_tokens));
            lines.extend(count("cache read", usage.cache_read_tokens));
            lines.extend(count("cache creation", usage.cache_creation_tokens));
            lines.extend(count("total tokens", usage.total_tokens));
            lines.extend(count("turns with usage", usage.turns_with_usage));

            match usage.cost_usd {
                Some(spent) => lines.push(Line::from(vec![
                    Span::styled(
                        "  cost                  ",
                        Style::default().fg(theme::muted()),
                    ),
                    Span::styled(money(spent), Style::default().fg(theme::accent())),
                ])),
                // The one number the field most wants and the one most often absent. Said
                // as not-reported rather than left off the page, so nobody reads a missing
                // row as a free session.
                None => lines.push(Line::from(Span::styled(
                    "  cost                  not reported by this provider",
                    Style::default().fg(theme::muted()),
                ))),
            }

            // A window nothing reports today (`runtime.models` is where it is meant to
            // arrive), so the percentage is drawn only when there is one to divide by.
            if let (Some(total), Some(window)) = (usage.total_tokens, usage.context_window) {
                if window > 0 {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "  context window        ",
                            Style::default().fg(theme::muted()),
                        ),
                        Span::raw(format!(
                            "{} \u{b7} {}% used",
                            tokens(window),
                            (total * 100 / window).min(999)
                        )),
                    ]));
                }
            }
        }
    }

    // ----- as this transcript folds ----------------------------------------------------
    let held = app
        .sessions
        .open_watch()
        .map(|watch| watch.usage())
        .unwrap_or_default();

    lines.push(Line::from(Span::styled(
        if held.complete {
            "AS THIS TRANSCRIPT FOLDS (every usage event this client holds)"
        } else {
            "AS THIS TRANSCRIPT FOLDS \u{2014} PARTIAL (older events were dropped)"
        },
        if held.complete {
            theme::label()
        } else {
            Style::default().fg(theme::warn())
        },
    )));

    if held.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no usage event has arrived on this connection",
            Style::default().fg(theme::muted()),
        )));
    } else {
        lines.extend(count("input tokens", Some(held.input_tokens)));
        lines.extend(count("output tokens", Some(held.output_tokens)));
        lines.extend(count("cached tokens", Some(held.cached_tokens)));
        lines.extend(count("total tokens", Some(held.total_tokens)));
        lines.push(Line::from(vec![
            Span::styled(
                "  usage events          ",
                Style::default().fg(theme::muted()),
            ),
            Span::raw(held.reports.to_string()),
        ]));

        if let Some(spent) = held.cost_usd {
            lines.push(Line::from(vec![
                Span::styled(
                    "  cost                  ",
                    Style::default().fg(theme::muted()),
                ),
                Span::styled(money(spent), Style::default().fg(theme::accent())),
            ]));
        }
    }

    // ----- the soft limit ---------------------------------------------------------------
    lines.extend(budget_lines(app, &facts.usage, held));

    lines
}

/// The `[budget] max_cost_usd` rows, and the sentence that keeps them honest.
fn budget_lines(
    app: &App,
    reported: &Option<crate::model::SessionUsage>,
    _held: UsageTotals,
) -> Vec<Line<'static>> {
    let Some(limit) = app.config.budget.max_cost_usd() else {
        return vec![Line::from(Span::styled(
            "no [budget] max_cost_usd is set; this client is not watching a limit",
            Style::default().fg(theme::muted()),
        ))];
    };

    let spent = reported.as_ref().and_then(|usage| usage.cost_usd);
    let over = spent.is_some_and(|spent| spent >= limit);

    vec![
        Line::from(vec![
            Span::styled("budget   ", Style::default().fg(theme::muted())),
            Span::styled(
                money(limit),
                if over {
                    Style::default().fg(theme::warn())
                } else {
                    Style::default().fg(theme::muted())
                },
            ),
            Span::styled(
                match spent {
                    Some(spent) if over => format!("  \u{b7} passed at {}", money(spent)),
                    Some(_) => "  \u{b7} not reached".to_string(),
                    None => "  \u{b7} this provider reports no cost, so it cannot be reached"
                        .to_string(),
                },
                Style::default().fg(if over { theme::warn() } else { theme::muted() }),
            ),
        ]),
        Line::from(Span::styled(
            "a soft limit: this client warns and never stops a turn \u{2014} budgets that \
             refuse work are the runtime's",
            Style::default().fg(theme::muted()),
        )),
    ]
}

/// The `tokens · cost` cell a session list row carries, or `None` where the runtime has
/// not reported one.
///
/// Tolerant by construction (I2): `interactive.list` does not carry `usage` on every
/// gateway, and the rows that lack it show nothing rather than a zero. `interactive.info`
/// does, so the open session's row fills in as soon as its info arrives.
pub fn usage_cell(usage: Option<&crate::model::SessionUsage>) -> Option<String> {
    let parts = usage_parts(usage);
    (!parts.is_empty()).then(|| parts.join(" \u{b7} "))
}

/// The same cell for a row with no width to spare: the cost where there is one, else the
/// token count.
///
/// The cost first because it is the number an operator is watching when the column is too
/// narrow for both — and dropping the other half is the footer's rule, not a truncation: a
/// half-drawn `42.5k \u{b7} $0.4` is a fact rendered as noise.
pub fn usage_cell_short(usage: Option<&crate::model::SessionUsage>) -> Option<String> {
    let usage = usage?;

    usage
        .cost_usd
        .filter(|spent| *spent > 0.0)
        .map(money)
        .or_else(|| usage.total_tokens.filter(|total| *total > 0).map(tokens))
}

fn usage_parts(usage: Option<&crate::model::SessionUsage>) -> Vec<String> {
    let Some(usage) = usage else {
        return Vec::new();
    };

    let mut parts = Vec::new();

    if let Some(total) = usage.total_tokens.filter(|total| *total > 0) {
        parts.push(tokens(total));
    }

    if let Some(spent) = usage.cost_usd.filter(|spent| *spent > 0.0) {
        parts.push(money(spent));
    }

    parts
}
