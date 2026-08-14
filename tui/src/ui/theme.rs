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

pub fn selected() -> Style {
    Style::default()
        .fg(Color::White)
        .bg(Color::Blue)
        .add_modifier(Modifier::BOLD)
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

/// Four frames rather than a braille spinner: a stale panel with a refresh in flight has
/// to be legible in a terminal that does not do wide glyphs.
pub fn spinner(tick: u64) -> char {
    ['|', '/', '-', '\\'][(tick % 4) as usize]
}
