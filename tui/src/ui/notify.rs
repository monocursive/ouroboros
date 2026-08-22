//! Terminal title, bell, and OSC 9 — the three ways a terminal can get a person's
//! attention back, and the rules about when it is allowed to.
//!
//! ## Why the App does not write any of this
//!
//! [`crate::ui::app::App`] is a state machine with no I/O in it, so it decides *that* a
//! notification is due and *what* the title should read, and the driver in
//! [`super`] drains those decisions and writes the escape sequences. Everything below the
//! decision line lives here: which channel `auto` resolves to on this terminal, what the
//! bytes are, and how the title is put back on the way out.
//!
//! ## What is never notified
//!
//! A keystroke. Notifications fire on exactly two things a *session* did —
//! `approval_requested` and a turn reaching a terminal state — and only for events that
//! arrived on the live stream, never for the backlog a replay hands over when a session
//! is opened. Opening a three-day-old transcript must not ring three days of bells.

use std::io::{self, Write};

use crate::config::{NotifyMode, NotifyWhen};

/// What a session did that is worth interrupting someone for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// `approval_requested`: the agent has stopped and cannot continue without a person.
    NeedsInput,
    /// A turn reached a terminal state — completed, failed, or interrupted.
    TurnDone,
}

impl Signal {
    /// The body OSC 9 carries. Terminals render it as the notification text; the bell
    /// carries nothing at all, which is why this is only used on the OSC 9 path.
    pub fn text(self) -> &'static str {
        match self {
            Self::NeedsInput => "ouro: waiting for your approval",
            Self::TurnDone => "ouro: the turn finished",
        }
    }
}

/// What the window title's glyph says the session is doing.
///
/// Gemini CLI's `dynamicWindowTitle` vocabulary, because it is the one that already
/// distinguishes "busy" from "blocked on you" — the distinction that decides whether
/// someone switches back now or in ten minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Working,
    NeedsInput,
    Idle,
}

impl Activity {
    pub fn glyph(self) -> &'static str {
        match self {
            Self::Working => "✦",
            Self::NeedsInput => "✋",
            Self::Idle => "◇",
        }
    }
}

/// How a notification reaches the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// `BEL`. Universally understood, and universally ugly where the terminal turns it
    /// into an audible beep the operator did not ask for.
    Bell,
    /// `ESC ] 9 ; text BEL` — a desktop notification on the terminals that implement it,
    /// and inert bytes on the ones that do not.
    Osc9,
}

/// What terminal this is, as its own environment reports it.
///
/// Read once by the driver and kept on the App so that resolving `mode = "auto"` stays a
/// pure function of state a test can set, rather than of the process environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Terminal {
    /// `TERM_PROGRAM`.
    pub program: Option<String>,
    /// `TERM`.
    pub term: Option<String>,
}

impl Terminal {
    /// What the process this client is running in says about itself.
    pub fn from_env() -> Self {
        Self {
            program: std::env::var("TERM_PROGRAM").ok(),
            term: std::env::var("TERM").ok(),
        }
    }

    /// Whether OSC 9 is known to become a real notification here.
    ///
    /// A short allowlist rather than a probe: there is no query that asks a terminal
    /// whether it implements OSC 9, and the failure mode of guessing wrong in the
    /// optimistic direction is a notification that silently never arrives. The names are
    /// the four terminals R2 §5 records as implementing it; anything else gets the bell,
    /// which every terminal does something with.
    pub fn renders_osc9(&self) -> bool {
        const PROGRAMS: [&str; 4] = ["iterm.app", "wezterm", "ghostty", "kitty"];

        let program = self.program.as_deref().unwrap_or("").to_ascii_lowercase();
        let term = self.term.as_deref().unwrap_or("").to_ascii_lowercase();

        PROGRAMS.iter().any(|name| program.contains(name))
            || PROGRAMS.iter().any(|name| term.contains(name))
    }
}

/// Which channel a configured mode resolves to on this terminal, or `None` for off.
///
/// `auto` resolves to the bell in screen-reader mode even on a terminal that renders
/// OSC 9. A desktop notification is a thing on a screen; the bell is the one channel that
/// reaches a person who is listening rather than looking, and A10's rule is a bell.
/// An operator who wrote `mode = "osc9"` still gets OSC 9, and `off` is still off — a mode
/// that overrode an explicit answer would be this client deciding for them.
pub fn channel(mode: NotifyMode, terminal: &Terminal) -> Option<Channel> {
    match mode {
        NotifyMode::Off => None,
        NotifyMode::Bell => Some(Channel::Bell),
        NotifyMode::Osc9 => Some(Channel::Osc9),
        NotifyMode::Auto if super::access::screen_reader() => Some(Channel::Bell),
        NotifyMode::Auto if terminal.renders_osc9() => Some(Channel::Osc9),
        NotifyMode::Auto => Some(Channel::Bell),
    }
}

/// Whether the configured condition allows a notification right now.
///
/// Screen-reader mode rings whether or not this terminal has focus. "Unfocused" is a
/// default built on the assumption that a person looking at the screen has already seen
/// what happened, and that assumption is exactly the one the mode exists to drop.
pub fn permitted(when: NotifyWhen, focused: bool) -> bool {
    if super::access::screen_reader() {
        return true;
    }

    match when {
        NotifyWhen::Always => true,
        NotifyWhen::Unfocused => !focused,
    }
}

/// The title bar text for a session.
///
/// `ouro · <glyph> <workspace basename>`, with the basename omitted rather than faked
/// when there is no workspace to name. The basename and not the path: a title bar is
/// twenty columns of a tab strip, and the leading half of `/Users/…/code/` is the half
/// that is the same for every window.
pub fn title(activity: Activity, workspace: Option<&str>) -> String {
    match workspace_name(workspace) {
        Some(name) => format!("ouro · {} {name}", activity.glyph()),
        None => format!("ouro · {}", activity.glyph()),
    }
}

fn workspace_name(workspace: Option<&str>) -> Option<String> {
    let path = workspace.map(str::trim).filter(|path| !path.is_empty())?;

    let name = path
        .trim_end_matches('/')
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or(path);

    // A control character in a title is an escape-sequence injection, and this string
    // came off a wire. Nothing but printable characters reaches the terminal.
    let cleaned = name
        .chars()
        .filter(|character| !character.is_control())
        .take(48)
        .collect::<String>();

    Some(cleaned).filter(|name| !name.is_empty())
}

/// Sets the window and icon titles (OSC 0), which is the pair every terminal in R2 §5
/// honours.
pub fn set_title(text: &str) {
    write_escape(&format!("\x1b]0;{}\x07", sanitise(text)));
}

/// Puts the title back on the way out.
///
/// An empty OSC 0, because there is no portable way to *read* the title a terminal had
/// before this process started — OSC 21 is answered by almost nothing. Emptying it is
/// what returns a tab to the terminal's own default, and an interactive shell rewrites it
/// on the next prompt anyway. Stated rather than implied: this restores the default, not
/// necessarily the exact string that was there before.
pub fn clear_title() {
    write_escape("\x1b]0;\x07");
}

/// Rings the terminal, through whichever channel was resolved.
pub fn emit(channel: Channel, signal: Signal) {
    match channel {
        Channel::Bell => write_escape("\x07"),
        Channel::Osc9 => write_escape(&format!("\x1b]9;{}\x07", sanitise(signal.text()))),
    }
}

/// Control characters cannot cross into an escape sequence's payload: `ESC` would start a
/// new one, and `BEL` would end this one early with the rest of the string landing on the
/// screen as text.
fn sanitise(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

fn write_escape(bytes: &str) {
    let mut stdout = io::stdout();
    let _ = stdout.write_all(bytes.as_bytes());
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_picks_osc9_only_on_terminals_that_render_it() {
        let iterm = Terminal {
            program: Some("iTerm.app".into()),
            term: Some("xterm-256color".into()),
        };
        let plain = Terminal {
            program: Some("Apple_Terminal".into()),
            term: Some("xterm-256color".into()),
        };
        let ghostty = Terminal {
            program: None,
            term: Some("xterm-ghostty".into()),
        };

        assert_eq!(channel(NotifyMode::Auto, &iterm), Some(Channel::Osc9));
        assert_eq!(channel(NotifyMode::Auto, &ghostty), Some(Channel::Osc9));
        assert_eq!(channel(NotifyMode::Auto, &plain), Some(Channel::Bell));
        assert_eq!(channel(NotifyMode::Off, &iterm), None);
        assert_eq!(channel(NotifyMode::Bell, &iterm), Some(Channel::Bell));
        assert_eq!(channel(NotifyMode::Osc9, &plain), Some(Channel::Osc9));
    }

    #[test]
    fn unfocused_is_the_default_condition() {
        assert!(permitted(NotifyWhen::Unfocused, false));
        assert!(!permitted(NotifyWhen::Unfocused, true));
        assert!(permitted(NotifyWhen::Always, true));
    }

    #[test]
    fn a_title_names_the_workspace_basename_and_never_carries_control_bytes() {
        assert_eq!(
            title(Activity::Working, Some("/Users/x/code/ouroboros/")),
            "ouro · ✦ ouroboros"
        );
        assert_eq!(title(Activity::Idle, None), "ouro · ◇");
        assert_eq!(
            title(Activity::NeedsInput, Some("/tmp/we\x1b]0;pwned\x07ird")),
            "ouro · ✋ we]0;pwnedird"
        );
    }
}
