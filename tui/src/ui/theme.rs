//! One place for every colour, so that "what does red mean here" has a single answer.
//!
//! The palette is the terminal's own sixteen colours rather than an RGB scheme: `ouro`
//! runs in whatever terminal an operator already has configured, and a hard-coded
//! background is how a TUI ends up unreadable in someone else's theme.
//!
//! The load-bearing rule is [`availability`]. `:disabled` is a *posture* — the control
//! plane and the workspace plane report it when they were never configured — so it is
//! rendered dim rather than red. A dashboard that painted a deliberate choice the same
//! colour as an outage would teach an operator to ignore the colour.

use ratatui::style::{Color, Modifier, Style};

use crate::model::{Availability, SessionStatus};

/// Machine activity and agent output. Cyan is deliberately reserved for things the
/// runtime is doing, so a moving cyan mark always means "system" rather than "click me".
pub const SYSTEM: Color = Color::Cyan;
/// Human intent: the composer caret, the selected session, and actionable prompts.
pub const ACTION: Color = Color::Yellow;
/// Backwards-compatible name for the system channel used throughout the operator views.
pub const ACCENT: Color = SYSTEM;
pub const MUTED: Color = Color::DarkGray;
pub const GOOD: Color = Color::Green;
/// Warnings remain distinct from the warmer action channel on ANSI terminals that expose
/// both yellow intensities. Terminal palettes still own the exact hue.
pub const WARN: Color = Color::LightYellow;
pub const BAD: Color = Color::Red;

pub fn heading() -> Style {
    Style::default().fg(SYSTEM).add_modifier(Modifier::BOLD)
}

pub fn action() -> Style {
    Style::default().fg(ACTION).add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    Style::default().fg(MUTED)
}

/// Secondary transcript matter: tool calls, command output, footnotes. Dimmer than
/// either speaker's words, so the conversation stays the thing the eye lands on.
pub fn quiet() -> Style {
    Style::default().fg(MUTED).add_modifier(Modifier::DIM)
}

/// A Markdown heading, by level.
///
/// Never a banner. A terminal heading is a line of ordinary text that reads heavier than
/// the lines around it, so the six levels are separated by weight and channel rather than
/// by size: the first two carry the system colour that already means "the machine is
/// talking", the middle two are weight alone, and the deepest two fade toward the muted
/// channel the rest of the transcript uses for secondary matter. Levels above six do not
/// exist in CommonMark; anything out of range renders as the deepest one.
pub fn markdown_heading(level: u8) -> Style {
    match level {
        1 => Style::default()
            .fg(SYSTEM)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        2 => Style::default().fg(SYSTEM).add_modifier(Modifier::BOLD),
        3 => Style::default().add_modifier(Modifier::BOLD),
        4 => Style::default().add_modifier(Modifier::BOLD | Modifier::DIM),
        _ => Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
    }
}

/// Inline code, and the backticks that still delimit it.
pub fn markdown_code() -> Style {
    Style::default().fg(SYSTEM)
}

/// Link text. Underlined rather than coloured: the action channel is reserved for things
/// a keystroke acts on, and a URL in a transcript is not one of them.
pub fn markdown_link() -> Style {
    Style::default().add_modifier(Modifier::UNDERLINED)
}

/// The `(url)` that follows link text, so the destination is readable and copyable
/// without being mistaken for the sentence it sits in.
pub fn markdown_url() -> Style {
    Style::default().fg(MUTED)
}

/// The bar down the left of a block quote, and the rule of a horizontal break.
pub fn markdown_rule() -> Style {
    Style::default().fg(MUTED).add_modifier(Modifier::DIM)
}

/// A table's header row: the only row in a table that is not data.
pub fn markdown_table_header() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// A task-list checkbox. Done is the good channel because it is a completed thing;
/// pending is muted because an unticked box is not a warning.
pub fn markdown_task(done: bool) -> Style {
    match done {
        true => Style::default().fg(GOOD),
        false => Style::default().fg(MUTED),
    }
}

/// The cursor row, as an inversion rather than a colour.
///
/// White-on-blue is a colour scheme this client does not own: it is illegible on a light
/// terminal theme, and it overrides whatever the row's own colour was carrying. `REVERSED`
/// swaps the terminal's own foreground and background, so a selection reads the same way in
/// every palette an operator has configured — which is the rule the rest of this module
/// follows.
pub fn selected() -> Style {
    Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

/// A pane that does not have focus still shows its selection, dimmed, because losing the
/// highlight entirely makes a two-pane tab look like it forgot where you were.
pub fn selected_unfocused() -> Style {
    Style::default().add_modifier(Modifier::DIM | Modifier::REVERSED)
}

pub fn availability(state: &Availability) -> Style {
    match state {
        Availability::Available => Style::default().fg(GOOD),
        Availability::Unavailable => Style::default().fg(BAD),
        // Configured off on purpose. Dim, never red.
        Availability::Disabled => Style::default().fg(MUTED),
        Availability::Other(_) => Style::default().fg(WARN),
    }
}

pub fn session_status(status: &SessionStatus) -> Style {
    match status {
        SessionStatus::Running | SessionStatus::Starting => Style::default().fg(ACCENT),
        SessionStatus::AwaitingApproval => Style::default().fg(WARN).add_modifier(Modifier::BOLD),
        SessionStatus::Idle => Style::default().fg(GOOD),
        SessionStatus::Completed | SessionStatus::Closed => Style::default().fg(MUTED),
        SessionStatus::Failed | SessionStatus::Lost => Style::default().fg(BAD),
        SessionStatus::Cancelled | SessionStatus::Closing => Style::default().fg(WARN),
        SessionStatus::Other(_) => Style::default(),
    }
}

/// Pi / OpenCode braille frames. Each glyph is one terminal cell.
const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Verbs beside the working spinner, rotated so a quiet model still reads as alive.
const WORKING_VERBS: [&str; 3] = ["Working", "Thinking", "Planning"];

/// Ticks between verb changes. ~3s at an 80ms frame, matching OpenCode's spinner copy.
pub const WORKING_VERB_TICKS: u64 = 38;

pub fn spinner(tick: u64) -> char {
    SPINNER_FRAMES[(tick as usize) % SPINNER_FRAMES.len()]
}

pub fn working_verb(tick: u64) -> &'static str {
    WORKING_VERBS[((tick / WORKING_VERB_TICKS) as usize) % WORKING_VERBS.len()]
}

/// One-line working indicator: `⠋  Working`.
pub fn working(tick: u64, message: impl Into<String>) -> ratatui::text::Line<'static> {
    use ratatui::text::{Line, Span};

    Line::from(vec![
        Span::raw("  "),
        Span::styled(
            spinner(tick).to_string(),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(message.into(), Style::default().fg(MUTED)),
    ])
}
