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

// ----- D9/D6/G1: the pages the native context verbs answer with ------------------------

/// How many cells the context meter's bar is. Fixed, so two readings taken minutes apart
/// are comparable at a glance rather than scaled to whatever the terminal happened to be.
const METER_CELLS: usize = 32;

fn meter(used: u64, window: u64) -> String {
    let filled =
        ((used.saturating_mul(METER_CELLS as u64) / window.max(1)) as usize).min(METER_CELLS);

    format!(
        "[{}{}]",
        "\u{2588}".repeat(filled),
        "\u{00b7}".repeat(METER_CELLS - filled)
    )
}

fn heading(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        theme::label().add_modifier(Modifier::BOLD),
    ))
}

fn row(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {label:<22}"),
            Style::default().fg(theme::muted()),
        ),
        Span::raw(value.into()),
    ])
}

fn note(text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        text.into(),
        Style::default().fg(theme::muted()),
    ))
}

/// How many lines of the last agent message a peek shows. A glance, not a transcript:
/// deciding whether a session needs you takes the top of what it said, and the rest is one
/// `Enter` away.
const PEEK_LINES: usize = 12;

/// G2. `Space` on a row: the last thing that session's agent said.
pub fn peek(frame: &mut Frame, area: Rect, app: &App, title: &str, id: &str, text: Option<&str>) {
    let mut lines = vec![
        Line::from(Span::styled(
            crate::ui::tree::truncate(title, 64),
            theme::label().add_modifier(Modifier::BOLD),
        )),
        note(crate::ui::tree::truncate(id, 64)),
        Line::from(""),
    ];

    match text {
        Some(text) => {
            for row in text.lines().take(PEEK_LINES) {
                lines.push(Line::from(Span::raw(row.to_string())));
            }

            let omitted = text.lines().count().saturating_sub(PEEK_LINES);

            if omitted > 0 {
                lines.push(note(format!(
                    "… {omitted} more line{}",
                    if omitted == 1 { "" } else { "s" }
                )));
            }
        }
        // Two different silences, and only one of them is about the session. This client
        // holds no transcript for a row it never subscribed to, and saying "nothing was
        // said" there would be a claim about someone else's conversation.
        None => lines.push(note(
            "this client is not holding this session's transcript, so it has no last \
             message to show — enter opens it",
        )),
    }

    lines.push(Line::from(""));
    lines.push(note(format!(
        "r replies · enter opens · esc closes · {} lists them all",
        app.keymap.label(Action::LeaderSessions)
    )));

    page(frame, area, "peek", lines, 0);
}

/// `/context` (D9): what this session can honestly say about its own context window.
pub fn context(
    frame: &mut Frame,
    area: Rect,
    context: &crate::model::native::SessionContext,
    scroll: usize,
) {
    page(frame, area, "context", context_lines(context), scroll);
}

pub fn context_lines(context: &crate::model::native::SessionContext) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // The first thing on the page, because it decides what the rest of it means. A
    // `usage` answer is not a thinner native one — it is a different claim, made by the
    // provider rather than by this runtime — and a page that did not say so would read as
    // though the missing rows were zeroes.
    if context.native() {
        lines.push(note(
            "source  native \u{2014} this session counted these figures itself",
        ));
    } else {
        lines.push(note(format!(
            "source  {} \u{2014} only what this transport's own usage events reported",
            context.source.as_deref().unwrap_or("usage")
        )));
    }

    if let Some(transport) = &context.transport {
        lines.push(row("transport", transport.clone()));
    }

    if let Some(model) = &context.model {
        lines.push(row("model", model.clone()));
    }

    lines.push(Line::from(""));
    lines.push(heading("WINDOW"));

    match (context.context_window, context.context_used) {
        (Some(window), Some(used)) => {
            lines.push(row("window", format!("{} tokens", tokens(window))));
            lines.push(row(
                "used by the last request",
                format!("{} tokens", tokens(used)),
            ));

            let share = context.share().unwrap_or(0);
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<22}", ""), Style::default().fg(theme::muted())),
                Span::styled(
                    format!("{} {share}%", meter(used, window)),
                    Style::default().fg(if share >= 80 {
                        theme::warn()
                    } else {
                        theme::accent()
                    }),
                ),
            ]));
        }
        (Some(window), None) => {
            lines.push(row("window", format!("{} tokens", tokens(window))));
            lines.push(note(
                "  no request has been counted yet, so there is nothing to divide",
            ));
        }
        (None, _nothing_to_divide) => lines.push(note(
            "  this provider named no context window, so there is no percentage to draw",
        )),
    }

    if let Some(total) = context.total_tokens.filter(|total| *total > 0) {
        lines.push(row("session total", format!("{} tokens", tokens(total))));
    }

    if let Some(compact_at) = context.compact_at {
        lines.push(row(
            "folds at",
            format!("{}% of the window", (compact_at * 100.0).round() as i64),
        ));
    }

    if let Some(keep) = context.keep_recent_tokens {
        lines.push(row("keeps recent", format!("{} tokens", tokens(keep))));
    }

    if !context.native() {
        lines.push(Line::from(""));
        lines.push(note(
            "Compactions, archives, the cached prefix and the instruction files are things",
        ));
        lines.push(note(
            "only a native session has, so this page reports the subset this one knows.",
        ));
        return lines;
    }

    if let Some(fingerprint) = &context.prefix_fingerprint {
        lines.push(Line::from(""));
        lines.push(heading("PREFIX"));
        lines.push(row(
            "fingerprint",
            fingerprint.chars().take(16).collect::<String>(),
        ));
        lines.push(row("tools", context.tools.len().to_string()));

        if let Some(messages) = context.messages {
            lines.push(row("messages held", messages.to_string()));
        }
    }

    lines.push(Line::from(""));
    lines.push(heading("COMPACTIONS"));

    if context.compactions.is_empty() {
        lines.push(note("  none \u{2014} nothing has been folded away"));
    } else {
        for (index, fold) in context.compactions.iter().enumerate() {
            lines.push(row(
                &format!("{}.", index + 1),
                format!(
                    "{} \u{b7} {}",
                    fold.trigger.as_deref().unwrap_or("fold"),
                    fold.describe()
                ),
            ));
        }
    }

    if context.compaction_thrashing == Some(true) {
        lines.push(Line::from(Span::styled(
            "  automatic compaction has stopped: two folds inside three turns is a window \
             that cannot hold this conversation, not a context that needs folding",
            Style::default().fg(theme::warn()),
        )));
    }

    if !context.archive_ids.is_empty() {
        lines.push(row("archives", context.archive_ids.join(", ")));
        lines.push(note(
            "  ids only \u{2014} the bodies are the conversation that was folded away",
        ));
    }

    lines.push(Line::from(""));
    lines.push(heading("INSTRUCTIONS"));

    if context.instruction_files.is_empty() {
        lines.push(note("  no project instruction files were loaded"));
    } else {
        for path in &context.instruction_files {
            lines.push(row("loaded", path.clone()));
        }
    }

    for dropped in &context.instruction_files_dropped {
        lines.push(Line::from(Span::styled(
            format!(
                "  dropped               {} ({} bytes, {})",
                dropped.path,
                dropped.bytes.unwrap_or(0),
                dropped.reason.as_deref().unwrap_or("over budget")
            ),
            Style::default().fg(theme::warn()),
        )));
    }

    if let Some(bytes) = context.instruction_bytes.filter(|bytes| *bytes > 0) {
        lines.push(row("instruction bytes", bytes.to_string()));
    }

    if let Some(child) = &context.handed_off_to {
        lines.push(Line::from(""));
        lines.push(row("handed off to", child.clone()));
    }

    if let Some(parent) = &context.handed_off_from {
        lines.push(row("handed off from", parent.clone()));
    }

    lines
}

/// `/rewind` (D6): the turns this session can go back to, and what each cannot put back.
pub fn rewind(
    frame: &mut Frame,
    area: Rect,
    points: &[crate::model::native::RewindPoint],
    choice: usize,
    what: usize,
    confirming: bool,
) {
    let lines = if confirming {
        rewind_choice_lines(points, choice, what)
    } else {
        rewind_menu_lines(points, choice)
    };

    page(frame, area, "rewind", lines, 0);
}

/// How many turns the menu draws around the selection. A session with four hundred
/// checkpointed turns must not make this page four hundred rows long.
const REWIND_WINDOW: usize = 10;

pub fn rewind_menu_lines(
    points: &[crate::model::native::RewindPoint],
    choice: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![note(
        "Pick the turn to return to. Everything after it is undone.",
    )];

    let start = choice
        .saturating_sub(REWIND_WINDOW / 2)
        .min(points.len().saturating_sub(REWIND_WINDOW));

    if start > 0 {
        lines.push(note(format!("  \u{2026} {start} earlier turns")));
    }

    for (index, point) in points.iter().enumerate().skip(start).take(REWIND_WINDOW) {
        let selected = index == choice;
        let mut facts = Vec::new();

        if point.files > 0 {
            facts.push(format!(
                "{} file{}",
                point.files,
                if point.files == 1 { "" } else { "s" }
            ));
        }

        if point.commands > 0 {
            facts.push(format!(
                "{} shell command{}",
                point.commands,
                if point.commands == 1 { "" } else { "s" }
            ));
        }

        if let Some(at) = &point.at {
            facts.push(at.clone());
        }

        lines.push(Line::from(Span::styled(
            format!(
                "{} {}  {}",
                if selected { "\u{25b8}" } else { " " },
                point
                    .turn_id
                    .clone()
                    .unwrap_or_else(|| format!("turn {}", index + 1)),
                facts.join(" \u{b7} ")
            ),
            if selected {
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            },
        )));

        // The warning sits under the row it is about and is drawn for every row, not only
        // the selected one: a menu that revealed the catch only once you moved onto it is
        // a menu that hides the catch.
        if let Some(warning) = point.warning() {
            lines.push(Line::from(Span::styled(
                format!("    {warning}"),
                Style::default().fg(theme::warn()),
            )));
        }
    }

    let shown = points.len().saturating_sub(start).min(REWIND_WINDOW);

    if start + shown < points.len() {
        lines.push(note(format!(
            "  \u{2026} {} later turns",
            points.len() - start - shown
        )));
    }

    lines.push(Line::from(""));
    lines.push(note(
        "\u{2191}\u{2193} picks a turn \u{b7} enter chooses what to restore \u{b7} esc leaves",
    ));

    lines
}

pub fn rewind_choice_lines(
    points: &[crate::model::native::RewindPoint],
    choice: usize,
    what: usize,
) -> Vec<Line<'static>> {
    use crate::ui::app::native::REWIND_WHAT;

    let mut lines = Vec::new();

    let Some(point) = points.get(choice) else {
        return lines;
    };

    lines.push(heading(&format!(
        "Return to {}",
        point
            .turn_id
            .clone()
            .unwrap_or_else(|| format!("turn {}", choice + 1))
    )));

    // Stated again, on the screen where the choice is actually made. This is the whole
    // point of the two screens: a rewind says what it cannot restore *before* it acts.
    if let Some(warning) = point.warning() {
        lines.push(Line::from(Span::styled(
            format!("  {warning}"),
            Style::default().fg(theme::warn()),
        )));
        lines.push(note(
            "  Those changes are not checkpointed, so this cannot put them back.",
        ));
    } else {
        lines.push(note(
            "  Every file this turn changed has a snapshot, so all of them can come back.",
        ));
    }

    lines.push(Line::from(""));
    lines.push(heading("RESTORE"));

    for (index, (name, description)) in REWIND_WHAT.iter().enumerate() {
        let selected = index == what;

        lines.push(Line::from(Span::styled(
            format!(
                "{} {name:<14} {description}",
                if selected { "\u{25b8}" } else { " " }
            ),
            if selected {
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            },
        )));
    }

    lines.push(Line::from(""));
    lines.push(note(
        "\u{2191}\u{2193} picks \u{b7} enter rewinds \u{b7} esc goes back to the turns",
    ));

    lines
}

/// `/delegations` (G1): the coding tasks this conversation started, and a way into each.
pub fn delegations(
    frame: &mut Frame,
    area: Rect,
    rows: &[crate::model::native::DelegationRow],
    choice: usize,
) {
    page(
        frame,
        area,
        "delegations",
        delegation_lines(rows, Some(choice)),
        0,
    );
}

/// D4. `/mcp`: the MCP servers one node runs for the native agent, and every entry its
/// loader read and refused.
///
/// The honesty rules here:
///
/// * **`configured` is not a failure.** A server declared and never started has no uptime
///   and no tools, and saying so is different from saying it is broken.
/// * **A broken server says why**, in the runtime's own words, because that string is the
///   only thing that distinguishes a missing binary from a crash loop.
/// * **Refusals are a section, not a footnote.** An entry the loader rejected is the only
///   way to tell "my `mcp.json` was ignored" from "my `mcp.json` was read and found
///   wanting", and each one carries its typed reason.
/// * **An environment is a count.** The runtime puts `env_count` on the wire and never the
///   names or the values, and there is no field on this panel that could hold one.
pub fn mcp(
    frame: &mut Frame,
    area: Rect,
    node: Option<&str>,
    list: &crate::model::McpList,
    choice: usize,
) {
    page(frame, area, "mcp servers", mcp_lines(node, list, choice), 0);
}

fn mcp_lines(
    node: Option<&str>,
    list: &crate::model::McpList,
    choice: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let mut header = vec![node
        .or(list.node.as_deref())
        .unwrap_or("this node")
        .to_string()];

    // `enabled: false` is a posture, not an error: the servers list is empty because
    // nothing was started, not because nothing was configured.
    header.push(if list.enabled {
        format!("{} server(s)", list.servers.len())
    } else {
        "MCP is off on this node".to_string()
    });

    if list.broken() > 0 {
        header.push(format!("{} broken", list.broken()));
    }

    if let Some(version) = &list.protocol_version {
        header.push(format!("protocol {version}"));
    }

    lines.push(Line::from(Span::styled(
        header.join("  \u{b7} "),
        theme::label(),
    )));

    // The transports this build implements, which is exactly why a `url` entry below is
    // refused rather than attempted.
    if !list.transports.is_empty() {
        lines.push(note(format!("transports: {}", list.transports.join(", "))));
    }

    if list.servers.is_empty() && list.refusals.is_empty() {
        lines.push(note(
            "no MCP servers are configured for this node or workspace",
        ));
        return lines;
    }

    for (index, server) in list.servers.iter().enumerate() {
        let selected = choice == index;

        let state = server.state.as_deref().unwrap_or("unknown");
        let mut facts = vec![state.to_string()];

        if let Some(scope) = &server.scope {
            facts.push(scope.clone());
        }

        // A tool count is only meaningful once a server has started; `configured` has not,
        // and printing "0 tools" beside it would read as "it advertises none".
        if state == "ready" {
            facts.push(format!("{} tool(s)", server.tools));
        }

        if server.env_count > 0 {
            facts.push(format!("{} env var(s)", server.env_count));
        }

        if server.restarts > 0 {
            facts.push(format!("{} restart(s)", server.restarts));
        }

        lines.push(Line::from(Span::styled(
            format!(
                "{} {}  {}",
                if selected { "\u{25b8}" } else { " " },
                server.name,
                facts.join(" \u{b7} ")
            ),
            match (selected, state) {
                (true, _) => Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD),
                (false, "broken") => Style::default().fg(theme::warn()),
                (false, "ready") => Style::default(),
                (false, _) => Style::default().fg(theme::muted()),
            },
        )));

        if let Some(command) = &server.command {
            let argv = if server.args.is_empty() {
                command.clone()
            } else {
                format!("{command} {}", server.args.join(" "))
            };

            lines.push(note(format!(
                "    {}",
                crate::ui::tree::truncate(&argv, 88)
            )));
        }

        if let Some(reason) = &server.broken_reason {
            lines.push(Line::from(Span::styled(
                format!("    {}", crate::ui::tree::truncate(reason, 88)),
                Style::default().fg(theme::warn()),
            )));
        }

        // Only for the selected row: the tool names are the thing a model actually sees,
        // and every row's worth of them would bury the list.
        if selected && !server.tool_names.is_empty() {
            lines.push(note(format!(
                "    {}",
                crate::ui::tree::truncate(&server.tool_names.join("  "), 88)
            )));
        }

        if selected {
            if let Some(source) = &server.source {
                lines.push(note(format!(
                    "    from {}",
                    crate::ui::tree::truncate(source, 82)
                )));
            }
        }
    }

    if !list.refusals.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("REFUSED  {}", list.refusals.len()),
            theme::label(),
        )));

        for (index, refusal) in list.refusals.iter().enumerate() {
            let selected = choice == list.servers.len() + index;

            lines.push(Line::from(Span::styled(
                format!(
                    "{} {}  {}",
                    if selected { "\u{25b8}" } else { " " },
                    refusal.name.as_deref().unwrap_or("(unnamed entry)"),
                    refusal.reason.as_deref().unwrap_or("refused")
                ),
                if selected {
                    Style::default()
                        .fg(theme::accent())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme::warn())
                },
            )));

            if let Some(detail) = &refusal.detail {
                lines.push(note(format!(
                    "    {}",
                    crate::ui::tree::truncate(detail, 88)
                )));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(note("r re-reads \u{b7} esc closes"));

    lines
}

/// `choice` is `None` for the read-only list the `Ctrl+T` panel draws beside the plan.
pub fn delegation_lines(
    rows: &[crate::model::native::DelegationRow],
    choice: Option<usize>,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    if rows.is_empty() {
        lines.push(note("this conversation has delegated nothing"));
        return lines;
    }

    for (index, entry) in rows.iter().enumerate() {
        let selected = choice == Some(index);
        let mut facts = vec![entry.status.as_deref().unwrap_or("unknown").to_string()];

        if let Some(node) = &entry.task_node {
            facts.push(node.clone());
        }

        // Which of the two answers this status is. A parent that was not running when its
        // child finished holds a stale copy, and the runtime says which it read rather
        // than letting the two look alike.
        match entry.source.as_deref() {
            Some("session") => facts.push("as this conversation last heard".to_string()),
            Some("team") | None => {}
            Some(other) => facts.push(other.to_string()),
        }

        lines.push(Line::from(Span::styled(
            format!(
                "{} {}  {}",
                if selected { "\u{25b8}" } else { " " },
                entry.task_id.as_deref().unwrap_or("(unnamed task)"),
                facts.join(" \u{b7} ")
            ),
            match (selected, entry.terminal()) {
                (true, _) => Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD),
                (false, true) => Style::default().fg(theme::muted()),
                (false, false) => Style::default(),
            },
        )));

        if let Some(digest) = &entry.result_digest {
            lines.push(note(format!("    result digest {digest}")));
        }
    }

    if choice.is_some() {
        lines.push(Line::from(""));
        lines.push(note(
            "\u{2191}\u{2193} picks \u{b7} enter opens the child's transcript \u{b7} esc leaves",
        ));
    }

    lines
}
