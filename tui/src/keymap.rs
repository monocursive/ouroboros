//! Keys as data: every chord this client binds is a named action, and every action can be
//! rebound from `[keys]` in `config.toml`.
//!
//! ## Why the map exists at all
//!
//! Claude Code #43717 is a hardcoded double-Escape that "cannot be rebound or disabled",
//! and it breaks zsh vi-mode for everyone who uses it. A chord that ships without its
//! setting is that bug waiting to be filed, so B8/D4 makes the whole grammar data: the
//! actions below are the client's entire vocabulary of keys, the defaults are what it
//! bound before this file existed, and an operator's `config.toml` overrides any of them.
//!
//! ## The map is the authority, never a literal string (D14)
//!
//! Everything that *shows* a key reads it back out of here — the `?` panel, the footer
//! hints, the `ctrl+x` which-key overlay, the command palette's shortcut column, the
//! session rail. A rebound key is therefore what the UI says it is. `/keys` prints the
//! effective map with the entries that came from the file marked, which is the same
//! invariant stated once more for someone who wants to check it.
//!
//! ## What a broken line does, and does not, do
//!
//! Nothing here can fail a start. An unknown action name, an unparsable spec, or two
//! actions claiming one key are each reported in [`Keymap::problems`] — said in a notice
//! at startup and listed in `/keys` — and the offending line is *ignored*. It never
//! silently rebinds something else, and it never turns into `off`: quietly disabling a key
//! because a file had a typo in it is the same failure in the other direction.
//!
//! ## Scopes
//!
//! Three, because a key means different things depending on what is claiming it:
//!
//! - [`Scope::Global`] — the shell's own chords, claimed before anything else sees them.
//! - [`Scope::Leader`] — the single key pressed *after* [`Action::Leader`]. Its spec is
//!   normally one bare chord (`"d"`); a two-chord spec is accepted when its first chord is
//!   the leader itself, so `leader.details = "ctrl+x d"` — which is what the `?` panel
//!   shows an operator — means what it looks like it means.
//! - [`Scope::Editor`] — composer motions, which only ever run while the draft has focus.
//!
//! Conflicts are checked *within* a scope. A global chord and an editor motion on the same
//! key are not a conflict in this map (the global handler simply wins, as it always did),
//! and pretending otherwise would refuse a working configuration.

use std::collections::BTreeMap;
use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// Where an action is claimed from, which is also the set it can collide inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Global,
    Leader,
    Editor,
}

/// Everything this client binds a key to.
///
/// The order is the order `/keys` and the `?` panel list them in: global chords by the
/// question someone is asking, then the leader verbs, then the composer motions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    // ----- global ------------------------------------------------------------------
    Send,
    Steer,
    Newline,
    QueueRetract,
    PasteImage,
    Editor,
    Interrupt,
    Backtrack,
    Cancel,
    Verbose,
    PlanPanel,
    Palette,
    Leader,
    Help,
    Settings,
    Quit,
    QuitEmpty,
    // ----- leader verbs ------------------------------------------------------------
    LeaderNew,
    LeaderNewOptions,
    LeaderSessions,
    LeaderWritable,
    LeaderEditor,
    LeaderCopy,
    LeaderScrollback,
    LeaderEditorView,
    /// A11. Hand the newest image in this conversation to the system opener.
    LeaderOpenImage,
    LeaderSteer,
    LeaderApproval,
    /// Toggle the client-side auto-approve mode on the open session: `a` answers the
    /// approval that is asking; `A` answers everything the session will ask.
    LeaderAutoApprove,
    /// B7. Save the permission rule a refused `!` command's refusal named.
    LeaderShellRule,
    LeaderEnd,
    LeaderDetails,
    LeaderQuit,
    LeaderHelp,
    StarterExplore,
    StarterReview,
    StarterPlan,
    // ----- composer motions --------------------------------------------------------
    EditorWordBack,
    EditorWordForward,
    EditorKillWordBack,
    EditorKillWordForward,
    EditorKillLine,
    EditorKillToStart,
    EditorYank,
    EditorLineStart,
    EditorLineEnd,
}

impl Action {
    /// Every action, in listing order.
    pub const ALL: [Action; 46] = [
        Self::StarterExplore,
        Self::StarterReview,
        Self::StarterPlan,
        Self::Send,
        Self::Steer,
        Self::Newline,
        Self::QueueRetract,
        Self::PasteImage,
        Self::Editor,
        Self::Interrupt,
        Self::Backtrack,
        Self::Cancel,
        Self::Verbose,
        Self::PlanPanel,
        Self::Palette,
        Self::Leader,
        Self::Help,
        Self::Settings,
        Self::Quit,
        Self::QuitEmpty,
        Self::LeaderNew,
        Self::LeaderNewOptions,
        Self::LeaderSessions,
        Self::LeaderWritable,
        Self::LeaderEditor,
        Self::LeaderCopy,
        Self::LeaderScrollback,
        Self::LeaderEditorView,
        Self::LeaderOpenImage,
        Self::LeaderSteer,
        Self::LeaderApproval,
        Self::LeaderAutoApprove,
        Self::LeaderShellRule,
        Self::LeaderEnd,
        Self::LeaderDetails,
        Self::LeaderQuit,
        Self::LeaderHelp,
        Self::EditorWordBack,
        Self::EditorWordForward,
        Self::EditorKillWordBack,
        Self::EditorKillWordForward,
        Self::EditorKillLine,
        Self::EditorKillToStart,
        Self::EditorYank,
        Self::EditorLineStart,
        Self::EditorLineEnd,
    ];

    /// The name this action answers to in `[keys]`.
    pub fn name(self) -> &'static str {
        match self {
            Self::StarterExplore => "starter_explore",
            Self::StarterReview => "starter_review",
            Self::StarterPlan => "starter_plan",
            Self::Send => "send",
            Self::Steer => "steer",
            Self::Newline => "newline",
            Self::QueueRetract => "queue_retract",
            Self::PasteImage => "paste_image",
            Self::Editor => "editor",
            Self::Interrupt => "interrupt",
            Self::Backtrack => "backtrack",
            Self::Cancel => "cancel",
            Self::Verbose => "verbose",
            Self::PlanPanel => "plan_panel",
            Self::Palette => "palette",
            Self::Leader => "leader",
            Self::Help => "help",
            Self::Settings => "settings",
            Self::Quit => "quit",
            Self::QuitEmpty => "quit_empty",
            Self::LeaderNew => "leader.new",
            Self::LeaderNewOptions => "leader.new_options",
            Self::LeaderSessions => "leader.sessions",
            Self::LeaderWritable => "leader.writable",
            Self::LeaderEditor => "leader.editor",
            Self::LeaderCopy => "leader.copy",
            Self::LeaderScrollback => "leader.scrollback",
            Self::LeaderEditorView => "leader.editor_view",
            Self::LeaderOpenImage => "leader.open_image",
            Self::LeaderSteer => "leader.steer",
            Self::LeaderApproval => "leader.approval",
            Self::LeaderAutoApprove => "leader.auto_approve",
            Self::LeaderShellRule => "leader.shell_rule",
            Self::LeaderEnd => "leader.end",
            Self::LeaderDetails => "leader.details",
            Self::LeaderQuit => "leader.quit",
            Self::LeaderHelp => "leader.help",
            Self::EditorWordBack => "editor.word_back",
            Self::EditorWordForward => "editor.word_forward",
            Self::EditorKillWordBack => "editor.kill_word_back",
            Self::EditorKillWordForward => "editor.kill_word_forward",
            Self::EditorKillLine => "editor.kill_line",
            Self::EditorKillToStart => "editor.kill_to_start",
            Self::EditorYank => "editor.yank",
            Self::EditorLineStart => "editor.line_start",
            Self::EditorLineEnd => "editor.line_end",
        }
    }

    /// The action named `name`, or `None` — which is what makes an unknown key in the
    /// file reportable instead of silently dropped.
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|action| action.name() == name)
    }

    pub fn scope(self) -> Scope {
        match self {
            Self::LeaderNew
            | Self::LeaderNewOptions
            | Self::LeaderSessions
            | Self::LeaderWritable
            | Self::LeaderEditor
            | Self::LeaderCopy
            | Self::LeaderScrollback
            | Self::LeaderEditorView
            | Self::LeaderOpenImage
            | Self::LeaderSteer
            | Self::LeaderApproval
            | Self::LeaderAutoApprove
            | Self::LeaderShellRule
            | Self::LeaderEnd
            | Self::LeaderDetails
            | Self::LeaderQuit
            | Self::LeaderHelp => Scope::Leader,
            Self::EditorWordBack
            | Self::EditorWordForward
            | Self::EditorKillWordBack
            | Self::EditorKillWordForward
            | Self::EditorKillLine
            | Self::EditorKillToStart
            | Self::EditorYank
            | Self::EditorLineStart
            | Self::EditorLineEnd => Scope::Editor,
            _global => Scope::Global,
        }
    }

    /// What this client bound before `[keys]` existed. That these all parse is a unit
    /// test: a default that did not would be a map with a hole in it.
    pub fn default_spec(self) -> &'static str {
        match self {
            Self::StarterExplore => "f2",
            Self::StarterReview => "f3",
            Self::StarterPlan => "f4",
            Self::Send => "enter",
            Self::Steer => "alt+enter",
            Self::Newline => "ctrl+j",
            Self::QueueRetract => "up",
            Self::PasteImage => "ctrl+v",
            Self::Editor => "ctrl+g",
            Self::Interrupt => "esc",
            Self::Backtrack => "esc esc",
            Self::Cancel => "ctrl+c",
            Self::Verbose => "ctrl+o",
            Self::PlanPanel => "ctrl+t",
            Self::Palette => "ctrl+p",
            Self::Leader => "ctrl+x",
            Self::Help => "?",
            Self::Settings => ",",
            Self::Quit => "ctrl+q",
            Self::QuitEmpty => "ctrl+d",
            Self::LeaderNew => "n",
            Self::LeaderNewOptions => "N",
            Self::LeaderSessions => "l",
            Self::LeaderWritable => "w",
            Self::LeaderEditor => "e",
            Self::LeaderCopy => "y",
            Self::LeaderScrollback => "[",
            Self::LeaderEditorView => "v",
            Self::LeaderOpenImage => "i",
            Self::LeaderSteer => "s",
            Self::LeaderApproval => "a",
            Self::LeaderAutoApprove => "A",
            Self::LeaderShellRule => "r",
            Self::LeaderEnd => "x",
            Self::LeaderDetails => "d",
            Self::LeaderQuit => "q",
            Self::LeaderHelp => "?",
            Self::EditorWordBack => "alt+b",
            Self::EditorWordForward => "alt+f",
            Self::EditorKillWordBack => "ctrl+w",
            Self::EditorKillWordForward => "alt+d",
            Self::EditorKillLine => "ctrl+k",
            Self::EditorKillToStart => "ctrl+u",
            Self::EditorYank => "ctrl+y",
            Self::EditorLineStart => "ctrl+a",
            Self::EditorLineEnd => "ctrl+e",
        }
    }

    /// One line, for `/keys` and for the `?` panel.
    pub fn describe(self) -> &'static str {
        match self {
            Self::StarterExplore => "draft a project walkthrough, on an empty home",
            Self::StarterReview => "draft a review of local changes, on an empty home",
            Self::StarterPlan => "draft a small improvement plan, on an empty home",
            Self::Send => "send, or queue a follow-up while the agent is busy",
            Self::Steer => "steer the running turn, where the transport can be steered",
            Self::Newline => "newline (shift+enter where the terminal reports it)",
            Self::QueueRetract => "take a queued draft back, then walk prompt history",
            Self::PasteImage => "paste a clipboard image as an attachment",
            Self::Editor => "edit the prompt in $VISUAL or $EDITOR",
            Self::Interrupt => "interrupt the turn; the queue is kept",
            Self::Backtrack => "go back to an earlier message",
            Self::Cancel => "clear the prompt; empty + running interrupts; twice quits",
            Self::Verbose => "expand, and collapse again, every cell in the conversation",
            Self::PlanPanel => "plan and tasks panel, while a provider publishes one",
            Self::Palette => "command palette",
            Self::Leader => "the leader; the verbs below follow it",
            Self::Help => "this page, when the prompt is empty",
            Self::Settings => "settings, when the prompt is empty",
            Self::Quit => "quit dialog",
            Self::QuitEmpty => "quit dialog, on an empty prompt",
            Self::LeaderNew => "new session",
            Self::LeaderNewOptions => "session options",
            Self::LeaderSessions => "switch session",
            Self::LeaderWritable => "writable session",
            Self::LeaderEditor => "external editor",
            Self::LeaderCopy => "copy last message",
            Self::LeaderScrollback => "transcript to scrollback",
            Self::LeaderEditorView => "transcript in $EDITOR",
            Self::LeaderOpenImage => "newest image in the system viewer",
            Self::LeaderSteer => "steer",
            Self::LeaderApproval => "approval",
            Self::LeaderAutoApprove => "auto-approve everything this session asks",
            Self::LeaderShellRule => "save the rule a refused ! command named",
            Self::LeaderEnd => "end or remove session",
            Self::LeaderDetails => "event details",
            Self::LeaderQuit => "quit",
            Self::LeaderHelp => "keyboard help",
            Self::EditorWordBack => "move back one word",
            Self::EditorWordForward => "move forward one word",
            Self::EditorKillWordBack => "kill the word before the caret",
            Self::EditorKillWordForward => "kill the word after the caret",
            Self::EditorKillLine => "kill to the end of the line",
            Self::EditorKillToStart => "kill to the start of the line",
            Self::EditorYank => "yank what was last killed",
            Self::EditorLineStart => "move to the start of the line",
            Self::EditorLineEnd => "move to the end of the line",
        }
    }

    /// The `?` panel's grouping, in the order a session is lived.
    pub fn group(self) -> &'static str {
        match self.scope() {
            Scope::Leader => "leader",
            Scope::Editor => "composing",
            Scope::Global => match self {
                Self::StarterExplore | Self::StarterReview | Self::StarterPlan => "getting started",
                Self::Send
                | Self::Steer
                | Self::Newline
                | Self::QueueRetract
                | Self::PasteImage
                | Self::Editor => "composing",
                Self::Interrupt
                | Self::Backtrack
                | Self::Cancel
                | Self::Verbose
                | Self::PlanPanel => "while the agent works",
                _runtime => "runtime",
            },
        }
    }
}

/// One key press: a code and the modifiers that must be held with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chord {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

/// How many chords a spec may name. Two is what `esc esc` and `ctrl+x d` need, and a
/// bounded grammar is one an operator cannot turn into a state machine by accident.
pub const MAX_CHORDS: usize = 2;

impl Chord {
    pub fn new(code: KeyCode, modifiers: KeyModifiers) -> Self {
        Self { code, modifiers }
    }

    /// `"ctrl+o"`, `"alt+enter"`, `"esc"`, `"?"`. `None` when this build cannot read it,
    /// which is reported rather than guessed at.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();

        if text.is_empty() {
            return None;
        }

        // A bare `+` is the key itself, not an empty modifier list: splitting first would
        // read `"+"` as two empty halves and refuse a key a terminal can send.
        if text == "+" {
            return Some(Self::new(KeyCode::Char('+'), KeyModifiers::NONE));
        }

        let mut modifiers = KeyModifiers::NONE;
        let mut parts = text.split('+').peekable();
        let mut code = None;

        while let Some(part) = parts.next() {
            // The last segment is the key; everything before it is a modifier. `+` as the
            // key arrives as an empty final segment (`"ctrl++"` splits to `["ctrl", ""]`).
            if parts.peek().is_none() {
                code = Some(if part.trim().is_empty() {
                    KeyCode::Char('+')
                } else {
                    key_code(part.trim())?
                });
                break;
            }

            modifiers |= match part.trim().to_ascii_lowercase().as_str() {
                "ctrl" | "control" => KeyModifiers::CONTROL,
                "alt" | "opt" | "option" | "meta" => KeyModifiers::ALT,
                "shift" => KeyModifiers::SHIFT,
                _unknown => return None,
            };
        }

        // A capital letter carries Shift already, as far as every terminal is concerned;
        // recording the modifier as well would make `N` unmatchable, since crossterm
        // reports `Char('N')` with SHIFT on some terminals and without it on others.
        // Matching normalises the same way — see [`Chord::hit`].
        Some(Self::new(code?, modifiers))
    }

    /// Whether a key event is this chord.
    ///
    /// SHIFT is ignored for character keys, because the case of the character already
    /// carries it and terminals disagree about whether to report both.
    pub fn hit(&self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }

        let (wanted, got) = match (self.code, key.code) {
            (KeyCode::Char(mine), KeyCode::Char(theirs)) if mine != theirs => return false,
            (KeyCode::Char(_), KeyCode::Char(_)) => (
                self.modifiers - KeyModifiers::SHIFT,
                key.modifiers - KeyModifiers::SHIFT,
            ),
            (mine, theirs) if mine == theirs => (self.modifiers, key.modifiers),
            _mismatch => return false,
        };

        // Only the three modifiers this grammar names are compared. The kitty protocol
        // reports KEYPAD and the terminal's own state bits on ordinary keys, and a strict
        // equality would make every chord unreachable there.
        let mask = KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT;
        (wanted & mask) == (got & mask)
    }
}

impl fmt::Display for Chord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.modifiers.contains(KeyModifiers::CONTROL) {
            write!(formatter, "ctrl+")?;
        }
        if self.modifiers.contains(KeyModifiers::ALT) {
            write!(formatter, "alt+")?;
        }
        if self.modifiers.contains(KeyModifiers::SHIFT) && !matches!(self.code, KeyCode::Char(_)) {
            write!(formatter, "shift+")?;
        }

        match self.code {
            KeyCode::Char(' ') => write!(formatter, "space"),
            KeyCode::Char(character) => write!(formatter, "{character}"),
            KeyCode::Enter => write!(formatter, "enter"),
            KeyCode::Esc => write!(formatter, "esc"),
            KeyCode::Tab => write!(formatter, "tab"),
            KeyCode::BackTab => write!(formatter, "backtab"),
            KeyCode::Backspace => write!(formatter, "backspace"),
            KeyCode::Delete => write!(formatter, "delete"),
            KeyCode::Insert => write!(formatter, "insert"),
            KeyCode::Home => write!(formatter, "home"),
            KeyCode::End => write!(formatter, "end"),
            KeyCode::PageUp => write!(formatter, "pageup"),
            KeyCode::PageDown => write!(formatter, "pagedown"),
            KeyCode::Up => write!(formatter, "up"),
            KeyCode::Down => write!(formatter, "down"),
            KeyCode::Left => write!(formatter, "left"),
            KeyCode::Right => write!(formatter, "right"),
            KeyCode::F(number) => write!(formatter, "f{number}"),
            _unnameable => write!(formatter, "?"),
        }
    }
}

fn key_code(name: &str) -> Option<KeyCode> {
    let lower = name.to_ascii_lowercase();

    let code = match lower.as_str() {
        "enter" | "return" | "cr" => KeyCode::Enter,
        "esc" | "escape" => KeyCode::Esc,
        "tab" => KeyCode::Tab,
        "backtab" => KeyCode::BackTab,
        "backspace" | "bs" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "insert" | "ins" => KeyCode::Insert,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" | "pgup" => KeyCode::PageUp,
        "pagedown" | "pgdn" | "pgdown" => KeyCode::PageDown,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "space" | "spc" => KeyCode::Char(' '),
        _character_or_function_key => {
            if let Some(number) = lower
                .strip_prefix('f')
                .and_then(|rest| rest.parse::<u8>().ok())
            {
                if (1..=24).contains(&number) {
                    return Some(KeyCode::F(number));
                }
            }

            // A single character, taken verbatim so case survives: `N` and `n` are two
            // different leader verbs and always have been.
            let mut characters = name.chars();
            let first = characters.next()?;

            if characters.next().is_some() {
                return None;
            }

            KeyCode::Char(first)
        }
    };

    Some(code)
}

/// What an action is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    /// `"off"`. The action keeps its verb — `/backtrack`, the palette — and loses its key.
    Off,
    /// One or [`MAX_CHORDS`] chords, in the order they must be pressed.
    Keys(Vec<Chord>),
}

impl Spec {
    /// The whole grammar: `"off"`, one chord, or chords separated by whitespace.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();

        if text.is_empty() {
            return Err("is empty".to_string());
        }

        if text.eq_ignore_ascii_case("off") || text.eq_ignore_ascii_case("none") {
            return Ok(Self::Off);
        }

        let mut chords = Vec::new();

        for part in text.split_whitespace() {
            let chord = Chord::parse(part)
                .ok_or_else(|| format!("names {part:?}, which this build cannot read"))?;
            chords.push(chord);
        }

        if chords.len() > MAX_CHORDS {
            return Err(format!("names more than {MAX_CHORDS} keys"));
        }

        Ok(Self::Keys(chords))
    }

    pub fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }

    pub fn chords(&self) -> &[Chord] {
        match self {
            Self::Off => &[],
            Self::Keys(chords) => chords,
        }
    }
}

impl fmt::Display for Spec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => write!(formatter, "off"),
            Self::Keys(chords) => {
                for (index, chord) in chords.iter().enumerate() {
                    if index > 0 {
                        write!(formatter, " ")?;
                    }
                    write!(formatter, "{chord}")?;
                }
                Ok(())
            }
        }
    }
}

/// Where an effective binding came from, which is the honest half of `/keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// This client's own default.
    Builtin,
    /// `[keys]` in the operator's `config.toml`.
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub spec: Spec,
    pub source: Source,
}

/// The effective map, plus everything that was wrong with the file that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keymap {
    bindings: BTreeMap<Action, Binding>,
    problems: Vec<String>,
}

impl Default for Keymap {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Keymap {
    /// The defaults, with nothing from a file.
    pub fn builtin() -> Self {
        let bindings = Action::ALL
            .into_iter()
            .map(|action| {
                let spec = Spec::parse(action.default_spec())
                    .unwrap_or_else(|_| panic!("built-in binding for {} parses", action.name()));

                (
                    action,
                    Binding {
                        spec,
                        source: Source::Builtin,
                    },
                )
            })
            .collect();

        Self {
            bindings,
            problems: Vec::new(),
        }
    }

    /// The defaults, overridden by `[keys]`.
    ///
    /// Deterministic in the face of a broken file: entries are applied in name order (the
    /// `BTreeMap` the caller hands over), an entry this build cannot act on is reported
    /// and skipped, and the first action to claim a key in a scope keeps it.
    pub fn resolve(overrides: &BTreeMap<String, String>) -> Self {
        let mut map = Self::builtin();

        for (name, text) in overrides {
            let Some(action) = Action::parse(name) else {
                map.problems.push(format!(
                    "[keys] {name} is not a key this build binds; ignored"
                ));
                continue;
            };

            let spec = match Spec::parse(text) {
                Ok(spec) => spec,
                Err(why) => {
                    map.problems.push(format!(
                        "[keys] {} = {text:?} {why}; keeping {}",
                        action.name(),
                        action.default_spec()
                    ));
                    continue;
                }
            };

            // A leader verb may be written the way the `?` panel shows it. Accept the
            // long form when its first chord is the leader, and refuse a two-chord spec
            // that is not — a leader verb is one key, and pretending otherwise would bind
            // something the leader handler can never reach.
            let spec = match (action.scope(), &spec) {
                (Scope::Leader, Spec::Keys(chords)) if chords.len() == MAX_CHORDS => {
                    if Some(chords[0]) == map.first(Action::Leader) {
                        Spec::Keys(vec![chords[1]])
                    } else {
                        map.problems.push(format!(
                            "[keys] {} = {spec} is two keys and the first is not the leader; \
                             keeping {}",
                            action.name(),
                            action.default_spec()
                        ));
                        continue;
                    }
                }
                _single_or_off => spec,
            };

            if let Some(other) = map.claimant(action, &spec) {
                map.problems.push(format!(
                    "[keys] {} = {spec} is already {}'s key; ignored",
                    action.name(),
                    other.name()
                ));
                continue;
            }

            map.bindings.insert(
                action,
                Binding {
                    spec,
                    source: Source::File,
                },
            );
        }

        map
    }

    /// The action already holding `spec` in this action's scope, if any.
    fn claimant(&self, action: Action, spec: &Spec) -> Option<Action> {
        if spec.is_off() {
            return None;
        }

        self.bindings
            .iter()
            .find(|(other, binding)| {
                **other != action
                    && other.scope() == action.scope()
                    && !binding.spec.is_off()
                    && binding.spec == *spec
            })
            .map(|(other, _)| *other)
    }

    /// What was wrong with the file, in the order it was read.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    pub fn binding(&self, action: Action) -> &Binding {
        self.bindings
            .get(&action)
            .expect("every action has a binding")
    }

    pub fn spec(&self, action: Action) -> &Spec {
        &self.binding(action).spec
    }

    pub fn source(&self, action: Action) -> Source {
        self.binding(action).source
    }

    /// Whether this action's binding came out of the operator's file.
    pub fn rebound(&self, action: Action) -> bool {
        self.source(action) == Source::File
    }

    /// The chord to *show* for an action — the map is the authority, never a literal
    /// string (D14). Leader verbs are shown with the leader in front of them, which is
    /// what an operator has to press.
    pub fn label(&self, action: Action) -> String {
        let spec = self.spec(action);

        if spec.is_off() || action.scope() != Scope::Leader {
            return spec.to_string();
        }

        match self.spec(Action::Leader) {
            Spec::Off => spec.to_string(),
            leader => format!("{leader} {spec}"),
        }
    }

    /// Whether a key event is this action's binding.
    ///
    /// Single-chord actions only: a sequence has to be driven by whoever holds the arm, so
    /// [`Keymap::first`] and [`Keymap::rest`] are what a two-key chord is matched through.
    /// `false` for `off`, always — a disabled key matches nothing.
    pub fn hits(&self, action: Action, key: KeyEvent) -> bool {
        match self.spec(action) {
            Spec::Off => false,
            Spec::Keys(chords) => chords.len() == 1 && chords[0].hit(key),
        }
    }

    /// The first chord of an action's binding, for the arm of a two-key chord.
    pub fn first(&self, action: Action) -> Option<Chord> {
        self.spec(action).chords().first().copied()
    }

    /// The remaining chord, which for this grammar is at most one.
    pub fn rest(&self, action: Action) -> Option<Chord> {
        self.spec(action).chords().get(1).copied()
    }

    /// Whether this action needs two keys.
    pub fn is_sequence(&self, action: Action) -> bool {
        self.spec(action).chords().len() > 1
    }

    /// The leader verb a key selects, once the leader is pending.
    ///
    /// A shifted letter is tried in upper case *first*, because that is the only way `N`
    /// and `n` stay two verbs: crossterm reports Shift+N as `Char('N')` on most terminals
    /// and as `Char('n')` with SHIFT on some, and case is what distinguishes the two
    /// bindings. Without this the terminals in the second group would reach `n`.
    pub fn leader_verb(&self, key: KeyEvent) -> Option<Action> {
        let verbs = || {
            Action::ALL
                .into_iter()
                .filter(|action| action.scope() == Scope::Leader)
        };

        if key.modifiers.contains(KeyModifiers::SHIFT) {
            if let KeyCode::Char(character) = key.code {
                let upper = character.to_ascii_uppercase();

                if upper != character {
                    let shifted = KeyEvent {
                        code: KeyCode::Char(upper),
                        ..key
                    };

                    if let Some(action) = verbs().find(|action| self.hits(*action, shifted)) {
                        return Some(action);
                    }
                }
            }
        }

        verbs().find(|action| self.hits(*action, key))
    }

    /// Every action in a scope that still has a key, in listing order.
    pub fn live(&self, scope: Scope) -> Vec<Action> {
        Action::ALL
            .into_iter()
            .filter(|action| action.scope() == scope && !self.spec(*action).is_off())
            .collect()
    }
}

/// The built-in map, for the surfaces that have no operator config to read — the editor's
/// own unit tests, and any caller that would otherwise rebuild it per keystroke.
pub fn builtin() -> &'static Keymap {
    use std::sync::OnceLock;

    static BUILTIN: OnceLock<Keymap> = OnceLock::new();
    BUILTIN.get_or_init(Keymap::builtin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_built_in_binding_parses() {
        for action in Action::ALL {
            Spec::parse(action.default_spec())
                .unwrap_or_else(|why| panic!("{} default {why}", action.name()));
        }
    }

    #[test]
    fn every_action_name_round_trips() {
        for action in Action::ALL {
            assert_eq!(Action::parse(action.name()), Some(action));
        }
    }

    #[test]
    fn the_grammar_reads_every_form_it_documents() {
        assert_eq!(
            Spec::parse("ctrl+o"),
            Ok(Spec::Keys(vec![Chord::new(
                KeyCode::Char('o'),
                KeyModifiers::CONTROL
            )]))
        );
        assert_eq!(
            Spec::parse("alt+enter"),
            Ok(Spec::Keys(vec![Chord::new(
                KeyCode::Enter,
                KeyModifiers::ALT
            )]))
        );
        assert_eq!(
            Spec::parse("esc esc"),
            Ok(Spec::Keys(vec![
                Chord::new(KeyCode::Esc, KeyModifiers::NONE),
                Chord::new(KeyCode::Esc, KeyModifiers::NONE),
            ]))
        );
        assert_eq!(
            Spec::parse("ctrl+x d"),
            Ok(Spec::Keys(vec![
                Chord::new(KeyCode::Char('x'), KeyModifiers::CONTROL),
                Chord::new(KeyCode::Char('d'), KeyModifiers::NONE),
            ]))
        );
        assert_eq!(Spec::parse("off"), Ok(Spec::Off));
        assert_eq!(Spec::parse("OFF"), Ok(Spec::Off));
        assert_eq!(
            Spec::parse("f5"),
            Ok(Spec::Keys(vec![Chord::new(
                KeyCode::F(5),
                KeyModifiers::NONE
            )]))
        );
    }

    #[test]
    fn a_spec_this_build_cannot_read_is_an_error_rather_than_a_guess() {
        assert!(Spec::parse("").is_err());
        assert!(Spec::parse("hyper+z").is_err());
        assert!(Spec::parse("ctrl+nonsense").is_err());
        assert!(Spec::parse("esc esc esc").is_err());
    }

    #[test]
    fn display_round_trips_through_the_parser() {
        for text in [
            "ctrl+o",
            "alt+enter",
            "esc esc",
            "ctrl+x d",
            "?",
            "up",
            "off",
        ] {
            let spec = Spec::parse(text).expect("parses");
            assert_eq!(spec.to_string(), text, "{text}");
        }
    }
}
