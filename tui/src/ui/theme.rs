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

pub const ACCENT: Color = Color::Cyan;
pub const MUTED: Color = Color::DarkGray;
pub const GOOD: Color = Color::Green;
pub const WARN: Color = Color::Yellow;
pub const BAD: Color = Color::Red;

pub fn heading() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    Style::default().fg(MUTED)
}

/// Secondary transcript matter: tool calls, command output, footnotes. Dimmer than
/// either speaker's words, so the conversation stays the thing the eye lands on.
pub fn quiet() -> Style {
    Style::default().fg(MUTED).add_modifier(Modifier::DIM)
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
