//! Screen-reader mode and reduced motion: the two settings that change *what* is drawn
//! rather than what colour it is drawn in.
//!
//! ## Why this is a mode and not a theme
//!
//! A theme swaps colours. Screen-reader mode swaps the vocabulary: a box becomes a label,
//! a spinning braille glyph becomes the word `working:`, `… +12 lines · ctrl+o` becomes a
//! sentence, and a menu's selected row becomes a number a person can type. None of that is
//! expressible as a palette, and all of it is Claude Code's `--ax-screen-reader`
//! ([R2 §7](../../../docs/research/agent-ux-2026/R2-display-rendering.md)).
//!
//! ## Labels are a closed taxonomy
//!
//! [`Label`] is the whole list, and it is the list [`super::export`] already writes: `you`,
//! `agent`, `thinking`, `tool`, and so on. Screen-reader mode adds the colon and the two
//! labels a *live* transcript needs that a file does not — `tool error:` and
//! `approval needed:` — and nothing else. A second vocabulary would be a second thing to
//! keep true.
//!
//! ## Three flags, one process
//!
//! Like [`super::MOUSE_CAPTURE`](super), these are process-wide atomics rather than state
//! on the `App`: [`super::theme::working`] and the cell renderers are called from
//! functions that never had a handle on one, and threading a settings struct through every
//! `Line`-building function is a much larger diff for a value that is read and never
//! written after startup. The resolution itself — [`resolve`] — is a pure function of the
//! four things that decide it, so the matrix is a table in a test.

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether the plain, labelled, box-free rendering is on.
static SCREEN_READER: AtomicBool = AtomicBool::new(false);

/// Whether spinners advance and the streaming caret blinks.
static REDUCED_MOTION: AtomicBool = AtomicBool::new(false);

pub fn screen_reader() -> bool {
    SCREEN_READER.load(Ordering::Relaxed)
}

pub fn reduced_motion() -> bool {
    REDUCED_MOTION.load(Ordering::Relaxed)
}

/// States both answers before anything draws. Called once, from `main`.
pub fn install(settings: Settings) {
    SCREEN_READER.store(settings.screen_reader, Ordering::Relaxed);
    REDUCED_MOTION.store(settings.reduced_motion, Ordering::Relaxed);
}

/// What the accessibility settings resolved to, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settings {
    pub screen_reader: bool,
    pub reduced_motion: bool,
}

/// The environment variables that can turn either of these on, read once so that
/// [`resolve`] stays a function of its arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    /// `OURO_SCREEN_READER`. Any value but `0`, `false`, or empty turns it on.
    pub screen_reader: Option<String>,
    /// `OURO_REDUCED_MOTION`, and the cross-platform spelling terminals and desktops
    /// increasingly export.
    pub reduced_motion: Option<String>,
}

impl Env {
    pub fn from_env() -> Self {
        Self {
            screen_reader: std::env::var("OURO_SCREEN_READER").ok(),
            reduced_motion: std::env::var("OURO_REDUCED_MOTION")
                .ok()
                .or_else(|| std::env::var("PREFERS_REDUCED_MOTION").ok()),
        }
    }
}

/// Whether a variable that exists is *asserting* something.
///
/// The `NO_COLOR` convention — presence is the signal — with the two spellings that mean
/// "no" honoured anyway, because a person who exported `OURO_SCREEN_READER=0` to turn it
/// off has said something clear and a client that read it as "on" would be unusable.
fn asserted(value: Option<&str>) -> bool {
    match value.map(str::trim) {
        None => false,
        Some("") | Some("0") => false,
        Some(word) if word.eq_ignore_ascii_case("false") => false,
        Some(word) if word.eq_ignore_ascii_case("no") => false,
        Some(_) => true,
    }
}

/// Which settings a config file, a flag, and the environment add up to.
///
/// Any of the three turning something on turns it on: these are accessibility settings,
/// and the failure mode of an unreadable screen is much worse than the failure mode of a
/// plainer one. Screen-reader mode implies reduced motion — a spinner that a screen reader
/// re-reads ten times a second is the exact thing the mode exists to stop — and that
/// implication is one-way.
pub fn resolve(config: impl Accessibility, flag: bool, env: &Env) -> Settings {
    let screen_reader = flag || config.screen_reader() || asserted(env.screen_reader.as_deref());
    let reduced_motion =
        screen_reader || config.reduced_motion() || asserted(env.reduced_motion.as_deref());

    Settings {
        screen_reader,
        reduced_motion,
    }
}

/// The `[accessibility]` table, as [`crate::config`] read it.
///
/// A trait rather than the struct so this module does not depend on the config module and
/// the config module does not depend on this one.
pub trait Accessibility: Copy {
    fn screen_reader(self) -> bool;
    fn reduced_motion(self) -> bool;
}

impl Accessibility for Settings {
    fn screen_reader(self) -> bool {
        self.screen_reader
    }

    fn reduced_motion(self) -> bool {
        self.reduced_motion
    }
}

/// What a line of the transcript is, said in a word.
///
/// Claude Code's taxonomy. Every one of these is a prefix on a line of its own, never a
/// glyph and never a colour, because a label a screen reader can read is the entire point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    You,
    Agent,
    Thinking,
    Tool,
    ToolError,
    Error,
    Warning,
    ApprovalNeeded,
}

impl Label {
    /// Every label, so a test can walk them.
    pub const ALL: [Label; 8] = [
        Self::You,
        Self::Agent,
        Self::Thinking,
        Self::Tool,
        Self::ToolError,
        Self::Error,
        Self::Warning,
        Self::ApprovalNeeded,
    ];

    /// The prefix, colon included. The colon is what makes a label sound like one when it
    /// is spoken rather than seen.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::You => "you:",
            Self::Agent => "agent:",
            Self::Thinking => "thinking:",
            Self::Tool => "tool:",
            Self::ToolError => "tool error:",
            Self::Error => "error:",
            Self::Warning => "warning:",
            Self::ApprovalNeeded => "approval needed:",
        }
    }
}

/// A truncation marker, spelled out.
///
/// The pane's own marker is `… +12 lines · ctrl+o`, which is three pieces of shorthand and
/// a glyph. Spoken, it is nothing. This is the same fact as a sentence.
pub fn omitted(count: usize, what: &str, key: &str) -> String {
    format!(
        "{count} more {what}{} not shown here; press {key} to show all",
        if count == 1 { "" } else { "s" }
    )
}

/// A menu row's number, as Claude Code numbers them: `1.` through `9.`, then nothing.
///
/// Past nine there is no single digit to press, so a row gets no number rather than a
/// number that is a lie about which key selects it.
pub fn row_number(index: usize) -> Option<usize> {
    (index < 9).then_some(index + 1)
}

/// The digit a keystroke names, as a row index, or `None` for a key that is not one.
pub fn row_for_digit(character: char) -> Option<usize> {
    character
        .to_digit(10)
        .filter(|digit| (1..=9).contains(digit))
        .map(|digit| digit as usize - 1)
}

/// A menu row's label with its number in front, or unchanged past the ninth.
pub fn numbered(index: usize, text: &str) -> String {
    match row_number(index) {
        Some(number) => format!("{number}. {text}"),
        None => format!("   {text}"),
    }
}

/// OSC 133 semantic-prompt markers.
///
/// `A` opens a prompt region and `B` closes it, which is what lets a terminal that
/// implements the sequence jump between prompts and a screen reader announce where the
/// input is. This client is a full-screen application rather than a shell, so the region
/// it marks is the composer and the marker is emitted around the frame that draws it —
/// stated rather than implied, because a shell's `A`/`B` bracket a line of text and this
/// one brackets a screen.
pub const PROMPT_START: &str = "\x1b]133;A\x07";
pub const PROMPT_END: &str = "\x1b]133;B\x07";

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct Config {
        screen_reader: bool,
        reduced_motion: bool,
    }

    impl Accessibility for Config {
        fn screen_reader(self) -> bool {
            self.screen_reader
        }

        fn reduced_motion(self) -> bool {
            self.reduced_motion
        }
    }

    const OFF: Config = Config {
        screen_reader: false,
        reduced_motion: false,
    };

    fn env(screen_reader: Option<&str>, reduced_motion: Option<&str>) -> Env {
        Env {
            screen_reader: screen_reader.map(str::to_string),
            reduced_motion: reduced_motion.map(str::to_string),
        }
    }

    #[test]
    fn nothing_set_is_nothing_on() {
        assert_eq!(resolve(OFF, false, &Env::default()), Settings::default());
    }

    #[test]
    fn any_of_the_three_turns_screen_reader_mode_on() {
        let from_flag = resolve(OFF, true, &Env::default());
        let from_env = resolve(OFF, false, &env(Some("1"), None));
        let from_config = resolve(
            Config {
                screen_reader: true,
                reduced_motion: false,
            },
            false,
            &Env::default(),
        );

        for settings in [from_flag, from_env, from_config] {
            assert!(settings.screen_reader);
            // One-way implication: the mode exists to stop the animation.
            assert!(settings.reduced_motion);
        }
    }

    #[test]
    fn reduced_motion_does_not_imply_screen_reader_mode() {
        let settings = resolve(OFF, false, &env(None, Some("1")));
        assert!(settings.reduced_motion);
        assert!(!settings.screen_reader);
    }

    #[test]
    fn a_variable_that_says_no_means_no() {
        for value in ["0", "false", "FALSE", "no", "", "   "] {
            let settings = resolve(OFF, false, &env(Some(value), Some(value)));
            assert_eq!(settings, Settings::default(), "{value:?} read as on");
        }
    }

    #[test]
    fn every_label_is_a_word_with_a_colon() {
        for label in Label::ALL {
            let text = label.as_str();
            assert!(text.ends_with(':'), "{text:?}");
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_lowercase() || c == ' ' || c == ':'),
                "{text:?} is not plain lowercase words"
            );
        }

        assert_eq!(Label::ToolError.as_str(), "tool error:");
        assert_eq!(Label::ApprovalNeeded.as_str(), "approval needed:");
    }

    #[test]
    fn a_truncation_marker_is_a_sentence() {
        assert_eq!(
            omitted(12, "line", "ctrl+o"),
            "12 more lines not shown here; press ctrl+o to show all"
        );
        assert_eq!(
            omitted(1, "line", "ctrl+o"),
            "1 more line not shown here; press ctrl+o to show all"
        );
        // No ellipsis, no middle dot, no glyph: everything here is spoken.
        assert!(!omitted(3, "line", "ctrl+o").contains('…'));
        assert!(!omitted(3, "line", "ctrl+o").contains('·'));
    }

    #[test]
    fn rows_are_numbered_only_while_a_digit_can_select_them() {
        assert_eq!(numbered(0, "Yes"), "1. Yes");
        assert_eq!(numbered(8, "Ninth"), "9. Ninth");
        assert_eq!(numbered(9, "Tenth"), "   Tenth");

        assert_eq!(row_number(0), Some(1));
        assert_eq!(row_number(9), None);

        assert_eq!(row_for_digit('1'), Some(0));
        assert_eq!(row_for_digit('9'), Some(8));
        assert_eq!(row_for_digit('0'), None);
        assert_eq!(row_for_digit('a'), None);
    }

    #[test]
    fn the_prompt_markers_are_the_osc_133_bytes() {
        assert_eq!(PROMPT_START, "\u{1b}]133;A\u{7}");
        assert_eq!(PROMPT_END, "\u{1b}]133;B\u{7}");
    }
}
