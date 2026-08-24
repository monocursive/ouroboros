//! The operator's own preferences, on disk, and the resolution order every start surface
//! reads them through.
//!
//! ## What belongs here, and what deliberately does not
//!
//! Nothing in this file is a runtime fact. The data directory, the node name, the scope,
//! the provider probes — those come from the daemon and from [`crate::runtime`], and a
//! screen that shows one of them says so. What is kept here is the small set of answers a
//! person would otherwise retype into every `ouro new`: which provider, which workspace,
//! which approval mode, which sandbox. They are *defaults for a form*, not decisions: every one of them
//! is prefilled into the coding home and the `n` dialog and stays editable, and `ouro new`
//! still accepts a flag that overrides the file.
//!
//! This is what keeps the "not a choice this client makes for you" rule intact while
//! removing the retyping. The client still refuses to *invent* a provider. It will use one
//! the operator chose, once, explicitly, in a file they can read — which is a different
//! statement from a node's default silently deciding which vendor runs their code. The
//! coding home writes `defaults.provider` for exactly that reason: pressing Enter with a
//! displayed provider is choosing it, so the next run does not ask again.
//!
//! `[onboarding]` retains the schema-1 welcome marker. Its former quick-start toggle is
//! gone: unknown keys are ignored on read, so a file that still names it loads unchanged
//! and the next save simply omits it.
//!
//! `[terminal]` is the one table here that is not a form default. `mouse` decides whether
//! this client captures the mouse at all, and that is a statement about the operator's
//! terminal rather than about their agents: a captured mouse gives `ouro` the wheel and
//! takes native selection away, so the person who would rather keep drag-to-copy and let
//! the terminal scroll needs a way to say so before the screen is taken over.
//!
//! ## Reading is total; writing is atomic
//!
//! [`load`] never fails. A missing file is the ordinary case, and a file that does not
//! parse is reported as a problem beside a default config rather than as a reason to
//! refuse to start a runtime: a corrupt preference file must not stand between an operator
//! and their agents. Every problem it collects names the file and what was wrong with it,
//! and the surfaces surface exactly those strings.
//!
//! [`Config::save`] writes a temporary file beside the target and renames it, so an
//! interrupted write leaves the previous file intact rather than half of this one. The
//! rewrite is whole: comments and key order in a hand-edited file do not survive a save,
//! which is why the file this client writes says so in its own header.
//!
//! ## Unknown keys are kept out of the way, not rejected
//!
//! A newer `ouro` may write keys this build has never heard of. Every struct here ignores
//! them on read (serde's default), for the same reason [`crate::model`] does: refusing a
//! file because it carries a field from a later version is how a client goes blind. They
//! are not *preserved* through a save, and that is stated rather than hidden — a save from
//! an older build is an older build's idea of the file.
//!
//! ## `--dev` reads the same file
//!
//! A development daemon gets its own data directory, because a `gateway.json` shared with
//! a real one would make each discoverable as the other. It does **not** get its own
//! preferences: which provider a person prefers is a fact about the person, not about
//! which runtime they happened to start.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{ApprovalMode, SandboxMode};
use crate::runtime::xdg_root;
use crate::ui::theme::ThemeName;

/// The directory this client keeps its preferences in, under the XDG config root.
pub const CONFIG_DIR: &str = "ouroboros";

/// The file itself.
pub const CONFIG_FILE: &str = "config.toml";

/// What a save writes above the tables, so someone who opens the file knows what wrote it
/// and what a later save will do to their edits.
const HEADER: &str = "\
# ouro preferences, schema 1. Hand-editing is fine: every key is optional, and keys this
# build does not know are ignored rather than refused.
#
# `ouro` rewrites this file whole when you save from the settings overlay (`,`), so
# comments and key order below this header are not preserved by that write.
";

/// Everything `ouro` remembers between runs. All of it optional, none of it a runtime
/// fact.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub onboarding: Onboarding,
    #[serde(default)]
    pub terminal: Terminal,
    #[serde(default)]
    pub statusline: StatusLineConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub keys: KeysConfig,
    #[serde(default)]
    pub theme: ThemeConfig,
    #[serde(default)]
    pub accessibility: AccessibilityConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
}

/// Which palette this client draws in. `[theme]` in `config.toml`.
///
/// One key, because a theme is a name and not a set of overrides: custom palettes are a
/// file format, a hot-reload story, and a validation surface, and none of those are what
/// A10 is. The names are [`crate::ui::theme::ThemeName`], and an unreadable one is
/// reported by [`normalise`] rather than silently swapped — an operator who wrote
/// `solarized` should be told this build does not have it, not left looking at dark and
/// wondering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThemeConfig {
    /// `auto` (the default), `dark`, `light`, `ansi`, `dark-daltonized`,
    /// `light-daltonized`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ThemeConfig {
    pub fn name(&self) -> ThemeName {
        self.name
            .as_deref()
            .and_then(ThemeName::parse)
            .unwrap_or_default()
    }
}

/// `[accessibility]`: the two settings that change what is drawn rather than what colour
/// it is drawn in.
///
/// Neither is a form default and neither is guessed. A screen reader is a fact about the
/// person at the keyboard, and this client has no way to detect one — which is why the
/// answer is a file, a flag, and an environment variable rather than a probe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityConfig {
    /// Labelled lines, no box drawing, static spinners, numbered menus, a bell on
    /// attention. Claude Code's `--ax-screen-reader`.
    #[serde(default)]
    pub screen_reader: bool,
    /// Stops the spinner and the streaming caret. Implied by `screen_reader`, and settable
    /// on its own by anyone who finds a moving terminal unpleasant without needing the
    /// rest of the mode.
    #[serde(default)]
    pub reduced_motion: bool,
}

impl crate::ui::access::Accessibility for &AccessibilityConfig {
    fn screen_reader(self) -> bool {
        self.screen_reader
    }

    fn reduced_motion(self) -> bool {
        self.reduced_motion
    }
}

/// Chords this operator has rebound.
///
/// It started with one entry, and it was the one the field got wrong: Claude Code #43717
/// is "double-Esc cannot be rebound or disabled", which breaks zsh vi-mode for everyone
/// who uses it. Making a chord rebindable *from day one* is R1 §4d(1), so the chord and
/// its setting landed together rather than the chord landing first.
///
/// B8 finished the job: every chord this client binds is now a named action in
/// [`crate::keymap`], and any of them can appear here. `backtrack` keeps its own field
/// because it predates the rest and its three documented spellings — `"esc esc"`,
/// `"alt+up"`, `"off"` — are all valid specs in the general grammar, so a file written for
/// the old build resolves to exactly what it always did.
///
/// The remaining entries land in [`KeysConfig::bindings`] through serde's `flatten`, which
/// is what lets a name this build has never heard of be *reported* rather than refused:
/// [`crate::keymap::Keymap::resolve`] names it in a notice and ignores the line.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysConfig {
    /// `"esc esc"` (the default), `"alt+up"`, `"off"`, or anything else the key-spec
    /// grammar reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backtrack: Option<String>,
    /// Every other `action = "spec"` line, verbatim, in name order.
    ///
    /// [`toml::Value`] rather than `String` for the reason the module header gives: a
    /// `flatten` of `String` would make `[keys] something = true` refuse the *whole* file,
    /// and a client that goes blind because one line has the wrong type is worse than one
    /// that names the line. [`normalise`] drops the non-strings and says which.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, toml::Value>,
}

impl KeysConfig {
    /// The whole `[keys]` table as the keymap reads it: the flattened string entries plus
    /// `backtrack`, which is a field here for backward compatibility and an ordinary
    /// action there.
    pub fn overrides(&self) -> BTreeMap<String, String> {
        let mut overrides: BTreeMap<String, String> = self
            .bindings
            .iter()
            .filter_map(|(name, value)| {
                value
                    .as_str()
                    .map(|spec| (name.clone(), spec.trim().to_string()))
            })
            .filter(|(_, spec)| !spec.is_empty())
            .collect();

        if let Some(backtrack) = self.backtrack.as_deref().map(str::trim) {
            if !backtrack.is_empty() {
                overrides.insert("backtrack".to_string(), backtrack.to_string());
            }
        }

        overrides
    }
}

/// A soft ceiling on what one session is allowed to have cost before this client says so.
///
/// Soft is the whole contract, and it is stated in the overlay as well as here: crossing
/// it turns the footer's cost cell `WARN` and produces one notice. **This client never
/// stops anything.** It has no authority to — a turn is the runtime's to run, budgets that
/// actually refuse work belong on the runtime side, and a client that pretended otherwise
/// would be claiming a guarantee it cannot keep. The reported cost is also whatever the
/// provider reported: a session whose provider reports no cost never crosses any threshold.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// US dollars. Absent, zero, or negative disables the warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,
}

impl BudgetConfig {
    /// The ceiling, once, with the values that mean "no ceiling" folded to `None`.
    pub fn max_cost_usd(&self) -> Option<f64> {
        self.max_cost_usd
            .filter(|limit| limit.is_finite() && *limit > 0.0)
    }
}

/// What opens the backtrack menu.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Backtrack {
    /// Two Escapes inside [`crate::ui::app::BACKTRACK_WINDOW_MS`].
    #[default]
    EscEsc,
    /// One chord, for a terminal or a shell mode where a doubled Escape is someone else's.
    AltUp,
    /// Nothing opens it by key. `/backtrack` and the palette still do.
    Off,
}

impl Backtrack {
    pub const ALL: [Backtrack; 3] = [Self::EscEsc, Self::AltUp, Self::Off];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EscEsc => "esc esc",
            Self::AltUp => "alt+up",
            Self::Off => "off",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
        Self::ALL.into_iter().find(|chord| chord.as_str() == name)
    }
}

impl KeysConfig {
    pub fn backtrack(&self) -> Backtrack {
        self.backtrack
            .as_deref()
            .and_then(Backtrack::parse)
            .unwrap_or_default()
    }
}

/// An operator-supplied command whose first line of output becomes a row above the
/// footer (Claude Code's `statusLine`, R2 §5).
///
/// Off unless `command` is set. The contract is deliberately the narrow one: this client
/// runs a shell command on the machine the *client* is on, feeds it one JSON object on
/// stdin, waits a bounded time, and draws the first line of what came back. It is not a
/// plugin system and it does not get to decide anything — a command that fails, hangs, or
/// prints nothing leaves the row absent rather than leaving the footer wrong.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusLineConfig {
    /// Run through `sh -c`, so a pipeline is a valid answer. `None` disables the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl StatusLineConfig {
    /// The command, once, with blank treated as absent.
    pub fn command(&self) -> Option<&str> {
        self.command
            .as_deref()
            .map(str::trim)
            .filter(|command| !command.is_empty())
    }
}

/// Terminal-title, bell, and OSC 9 notifications (Codex's `tui.notifications` and
/// `notification_condition`, R2 §5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationsConfig {
    /// `auto` | `bell` | `osc9` | `off`. Absent means `auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// `unfocused` | `always`. Absent means `unfocused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
}

/// How a notification is delivered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NotifyMode {
    /// OSC 9 where the terminal is known to render it, and the bell everywhere else.
    #[default]
    Auto,
    Bell,
    Osc9,
    Off,
}

impl NotifyMode {
    pub const ALL: [NotifyMode; 4] = [Self::Auto, Self::Bell, Self::Osc9, Self::Off];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Bell => "bell",
            Self::Osc9 => "osc9",
            Self::Off => "off",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == name)
    }
}

/// When a notification is allowed to fire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NotifyWhen {
    /// Only while this terminal does not have focus. The default, because a bell for
    /// something happening on the screen you are already looking at is noise.
    #[default]
    Unfocused,
    Always,
}

impl NotifyWhen {
    pub const ALL: [NotifyWhen; 2] = [Self::Unfocused, Self::Always];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unfocused => "unfocused",
            Self::Always => "always",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|when| when.as_str() == name)
    }
}

impl NotificationsConfig {
    pub fn mode(&self) -> NotifyMode {
        self.mode
            .as_deref()
            .and_then(NotifyMode::parse)
            .unwrap_or_default()
    }

    pub fn when(&self) -> NotifyWhen {
        self.when
            .as_deref()
            .and_then(NotifyWhen::parse)
            .unwrap_or_default()
    }
}

/// The answers the `n` dialog and `ouro new` prefill from.
///
/// Every field is a string rather than a parsed type because the file is the operator's to
/// edit and a value this build cannot read is reported, not crashed on. [`normalise`]
/// turns the unreadable ones back into "unset" and says so.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Defaults {
    /// A provider name. Not validated against a runtime here — which providers exist is a
    /// fact only a running node can report, and this file is read before there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// A full direct model spec such as `openai_codex:gpt-5.6-sol`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// A workspace path, as the operator wrote it. Resolved where it is used, against the
    /// directory the command was typed in, exactly like `--workspace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// One of [`ApprovalMode::ALL`]. Anything else is dropped by [`normalise`] with a
    /// problem naming it, because sending it would be a `-32602` naming the parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<String>,
    /// One of [`SandboxMode::ALL`]. Anything else is dropped by [`normalise`] with a
    /// problem naming it, because sending it would be a `-32602` naming the parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_mode: Option<String>,
}

impl Defaults {
    /// The stored mode as the enum both start surfaces build parameters from.
    pub fn approval_mode(&self) -> Option<ApprovalMode> {
        self.approval_mode.as_deref().and_then(ApprovalMode::parse)
    }

    pub fn sandbox_mode(&self) -> Option<SandboxMode> {
        self.sandbox_mode.as_deref().and_then(SandboxMode::parse)
    }

    /// Whether anything at all has been stated. A settings screen shows a different
    /// sentence for "nothing is set" than for "these are your answers".
    pub fn is_empty(&self) -> bool {
        self.provider.is_none()
            && self.model.is_none()
            && self.workspace.is_none()
            && self.approval_mode.is_none()
            && self.sandbox_mode.is_none()
    }
}

/// What this operator has already been shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Onboarding {
    /// Whether the coding home has been reached once.
    ///
    /// A marker rather than a timestamp: the only question it answers is "has this person
    /// seen this client introduce itself", and a date would invite a client to decide the
    /// answer expires.
    #[serde(default)]
    pub welcomed: bool,
    /// Whether the "the mouse is captured, here is how to select text anyway" line has
    /// been shown.
    ///
    /// Once per operator rather than once per session: a hint that reappears every launch
    /// is a hint nobody reads, and the thing it explains does not change between runs.
    #[serde(default)]
    pub mouse_hint_shown: bool,
    /// How many prompts this operator has sent, counted only up to the point where the
    /// "new here?" hint stops (see [`ONBOARDING_PROMPTS`]).
    ///
    /// A count rather than a flag because the hint is about *practice*, not about having
    /// been told: someone who started a session, read the screen, and closed it has not
    /// yet learned where `@` and `/` are. It stops counting at the threshold so this file
    /// does not accumulate a running total of the operator's work.
    #[serde(default)]
    pub prompts_sent: u32,
}

/// How many prompts before the coding home's tips and the footer's "new here?" retire.
///
/// Three: enough that the keys have been seen in use, few enough that the row is gone
/// before it becomes furniture.
pub const ONBOARDING_PROMPTS: u32 = 3;

/// How this client treats the terminal it was started in.
///
/// Not a form default: nothing prefills from this and no dialog edits it. It is the
/// operator's answer to a question only they can answer — whether they want `ouro` to own
/// the mouse — and it is read once, before the screen is taken over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terminal {
    /// Whether to capture the mouse.
    ///
    /// `true` (the default) gives `ouro` the wheel, and the terminal's own selection then
    /// needs a modifier — Shift on most terminals, Option on iTerm2, Fn on Terminal.app.
    /// `false` captures nothing: drag-to-copy and the terminal's own scrollback keys work
    /// exactly as they do in a shell, and `ouro` scrolls by keyboard only.
    #[serde(default = "yes")]
    pub mouse: bool,
}

impl Default for Terminal {
    fn default() -> Self {
        Self { mouse: true }
    }
}

/// serde needs a function for a non-`false` default on a `bool` field.
fn yes() -> bool {
    true
}

/// A config file as it was found: what it said, where it is, and what was wrong with it.
///
/// `problems` is separate from the config rather than folded into an error, because both
/// halves matter at once — the client runs on the defaults *and* says the file did not
/// parse, naming it. A caller that dropped one of the two would either hide a broken file
/// or refuse to start over one.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    pub path: PathBuf,
    pub problems: Vec<String>,
}

/// Where the preferences live: `$XDG_CONFIG_HOME/ouroboros/config.toml` when that variable
/// names an absolute path, and `~/.config/ouroboros/config.toml` otherwise.
///
/// The same rule [`crate::runtime::Paths`] uses for the data and cache roots, and for the
/// same reason: this client follows the XDG variables directly rather than the platform
/// conventions `dirs` would apply, so a caller who sets one gets the directory they named.
pub fn path() -> Result<PathBuf> {
    Ok(xdg_root("XDG_CONFIG_HOME", ".config")?
        .join(CONFIG_DIR)
        .join(CONFIG_FILE))
}

/// Reads the file at [`path`], or reports why it could not be read.
///
/// Total by construction: every failure produces a default config and a sentence naming
/// this file. `ouro` starting a runtime must not depend on a preference file being
/// well-formed.
pub fn load_default() -> Loaded {
    match path() {
        Ok(path) => load(path),
        Err(error) => Loaded {
            config: Config::default(),
            // There is no path to name, so the one thing this can report is that there is
            // nowhere to keep preferences — which is the same condition `Paths::discover`
            // refuses on, and here it is only a lost default.
            path: PathBuf::from(CONFIG_FILE),
            problems: vec![format!("no config file location: {error:#}")],
        },
    }
}

/// [`load_default`] against a path the caller names. The tests drive this one.
pub fn load(path: PathBuf) -> Loaded {
    let mut problems = Vec::new();

    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        // The ordinary first run. Not a problem, and not worth a sentence.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Loaded {
                config: Config::default(),
                path,
                problems,
            }
        }
        Err(error) => {
            problems.push(format!(
                "{} could not be read ({error}); running on defaults",
                path.display()
            ));

            return Loaded {
                config: Config::default(),
                path,
                problems,
            };
        }
    };

    let mut config = match toml::from_str::<Config>(&text) {
        Ok(config) => config,
        Err(error) => {
            // The whole message, not the first line: toml points at the line and column,
            // which is the part that makes it fixable.
            problems.push(format!(
                "{} is not readable as TOML ({}); running on defaults",
                path.display(),
                one_line(&error.to_string())
            ));

            Config::default()
        }
    };

    normalise(&mut config, &path, &mut problems);

    Loaded {
        config,
        path,
        problems,
    }
}

/// Turns values this build cannot act on back into "unset", saying which and why.
///
/// A blank string is quietly treated as absent: `""` and "no answer" are the same
/// statement, and [`crate::model::StartRequest`] trims for the same reason. An approval
/// mode outside the schema is *not* quiet — the gateway refuses it by name, so a client
/// that carried it silently would fail a start with an error about a parameter the
/// operator never typed.
fn normalise(config: &mut Config, path: &Path, problems: &mut Vec<String>) {
    blank_to_none(&mut config.defaults.provider);
    blank_to_none(&mut config.defaults.model);
    blank_to_none(&mut config.defaults.workspace);
    blank_to_none(&mut config.defaults.approval_mode);
    blank_to_none(&mut config.defaults.sandbox_mode);
    blank_to_none(&mut config.statusline.command);
    blank_to_none(&mut config.notifications.mode);
    blank_to_none(&mut config.notifications.when);
    blank_to_none(&mut config.keys.backtrack);
    blank_to_none(&mut config.theme.name);

    if let Some(name) = config.theme.name.clone() {
        if ThemeName::parse(&name).is_none() {
            problems.push(format!(
                "{}: theme.name is {name:?}, which is not one of {}; treating it as unset \
                 (auto)",
                path.display(),
                ThemeName::ALL
                    .iter()
                    .map(|theme| theme.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            config.theme.name = None;
        }
    }

    // `backtrack` predates the general grammar and its three documented spellings are all
    // valid specs, so anything [`crate::keymap`] can read is kept and resolved there. Only
    // a chord *neither* vocabulary knows is turned back into "unset" here, and it is named
    // rather than silently disabled — quietly turning a typo into `off` is the same
    // failure as ignoring it.
    if let Some(chord) = config.keys.backtrack.clone() {
        if Backtrack::parse(&chord).is_none() && crate::keymap::Spec::parse(&chord).is_err() {
            problems.push(format!(
                "{}: keys.backtrack is {chord:?}, which is neither {} nor a key this build can \
                 read; treating it as unset (esc esc)",
                path.display(),
                Backtrack::ALL
                    .iter()
                    .map(|chord| chord.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            config.keys.backtrack = None;
        }
    }

    // A `[keys]` line whose value is not a string cannot be a key spec. Dropped and named
    // here rather than in the keymap, because the keymap is handed strings and this is the
    // one layer that still knows what TOML type the file actually carried.
    config.keys.bindings.retain(|name, value| {
        if value.is_str() {
            return true;
        }

        problems.push(format!(
            "{}: keys.{name} is {}, not a key spec; ignored",
            path.display(),
            value.type_str()
        ));

        false
    });

    if let Some(mode) = config.notifications.mode.clone() {
        if NotifyMode::parse(&mode).is_none() {
            problems.push(format!(
                "{}: notifications.mode is {mode:?}, which is not one of {}; treating it as \
                 unset (auto)",
                path.display(),
                NotifyMode::ALL
                    .iter()
                    .map(|mode| mode.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            config.notifications.mode = None;
        }
    }

    if let Some(when) = config.notifications.when.clone() {
        if NotifyWhen::parse(&when).is_none() {
            problems.push(format!(
                "{}: notifications.when is {when:?}, which is not one of {}; treating it as \
                 unset (unfocused)",
                path.display(),
                NotifyWhen::ALL
                    .iter()
                    .map(|when| when.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            config.notifications.when = None;
        }
    }

    if let Some(mode) = config.defaults.approval_mode.clone() {
        if ApprovalMode::parse(&mode).is_none() {
            problems.push(format!(
                "{}: defaults.approval_mode is {mode:?}, which is not one of {}; treating it \
                 as unset",
                path.display(),
                ApprovalMode::ALL
                    .iter()
                    .map(|mode| mode.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            config.defaults.approval_mode = None;
        }
    }

    if let Some(mode) = config.defaults.sandbox_mode.clone() {
        if SandboxMode::parse(&mode).is_none() {
            problems.push(format!(
                "{}: defaults.sandbox_mode is {mode:?}, which is not one of {}; treating it \
                 as unset",
                path.display(),
                SandboxMode::ALL
                    .iter()
                    .map(|mode| mode.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            config.defaults.sandbox_mode = None;
        }
    }
}

fn blank_to_none(value: &mut Option<String>) {
    if value.as_deref().map(str::trim).unwrap_or("").is_empty() {
        *value = None;
    }
}

/// A multi-line error folded onto one line, for a notice line that is one row tall.
fn one_line(text: &str) -> String {
    text.split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

impl Config {
    /// Writes the file, creating its directory, without ever leaving a partial one behind.
    ///
    /// Temp-and-rename in the *same* directory: `rename` is atomic within a filesystem, so
    /// a reader either sees the whole previous file or the whole new one. A write straight
    /// onto the target would have a window in which the file is truncated, and a client
    /// that crashed inside it would have eaten the operator's preferences to save them.
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

        let body = toml::to_string_pretty(self).context("encoding the config file")?;

        let temp = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| CONFIG_FILE.to_string()),
            std::process::id()
        ));

        // 0600 like everything else this client writes into its own directories. Nothing
        // here is a secret, but a workspace path is nobody else's business either.
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .with_context(|| format!("writing {}", temp.display()))?;

        let written = io::Write::write_all(&mut file, HEADER.as_bytes())
            .and_then(|()| io::Write::write_all(&mut file, body.as_bytes()))
            .and_then(|()| io::Write::flush(&mut file))
            // Durability before the rename, so a crash cannot publish a name that points
            // at bytes the filesystem has not committed.
            .and_then(|()| file.sync_all());

        if let Err(error) = written {
            let _ = fs::remove_file(&temp);
            return Err(anyhow::Error::from(error).context(format!("writing {}", temp.display())));
        }

        drop(file);

        if let Err(error) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(anyhow::Error::from(error).context(format!(
                "renaming {} onto {}",
                temp.display(),
                path.display()
            )));
        }

        Ok(())
    }
}

/// What one `ouro new` invocation stated on its command line. `None` means the flag was
/// absent, which is what makes the config file reachable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartFlags {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub workspace: Option<String>,
    pub approval_mode: Option<String>,
    pub sandbox_mode: Option<String>,
    /// A one-shot fleet placement choice. It is intentionally not a sticky default:
    /// machines can be offline, and silently reusing one would turn convenience into an
    /// unexplained start failure.
    pub machine: Option<String>,
}

/// The parameters a start will be built from, and where each of them came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStart {
    pub provider: String,
    pub model: Option<String>,
    pub workspace: Option<String>,
    pub approval_mode: Option<String>,
    pub sandbox_mode: Option<String>,
    pub machine: Option<String>,
}

/// Retained for API compatibility; direct Native is now always a provider fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    Provider,
}

impl Missing {
    pub fn message(&self, _config_path: &Path) -> String {
        "the direct Native provider could not be selected".to_string()
    }
}

/// Flag, then the config file, then the direct Native default.
pub fn resolve_start(flags: &StartFlags, defaults: &Defaults) -> Result<ResolvedStart, Missing> {
    let provider = first(&flags.provider, &defaults.provider).unwrap_or_else(|| "native".into());

    Ok(ResolvedStart {
        provider,
        model: first(&flags.model, &defaults.model),
        workspace: first(&flags.workspace, &defaults.workspace),
        approval_mode: first(&flags.approval_mode, &defaults.approval_mode),
        sandbox_mode: first(&flags.sandbox_mode, &defaults.sandbox_mode),
        machine: first(&flags.machine, &None),
    })
}

/// The flag if it says something, the stored default if it does, otherwise nothing.
fn first(flag: &Option<String>, stored: &Option<String>) -> Option<String> {
    for candidate in [flag, stored] {
        let value = candidate.as_deref().unwrap_or("").trim();

        if !value.is_empty() {
            return Some(value.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    /// A directory of this test's own under the OS temp root. The real home is never
    /// touched: every path below is built from here, and `path()` is exercised by pointing
    /// `XDG_CONFIG_HOME` at one of these rather than by reading the caller's environment.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ouro-config-{name}-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));

        fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn a_config_round_trips_through_the_file_it_writes() {
        let dir = scratch("round-trip");
        let path = dir.join(CONFIG_FILE);

        let config = Config {
            defaults: Defaults {
                provider: Some("claude".into()),
                model: Some("anthropic:claude-sonnet-5".into()),
                workspace: Some("/home/me/project".into()),
                approval_mode: Some("auto_edit".into()),
                sandbox_mode: Some("read_only".into()),
            },
            onboarding: Onboarding {
                welcomed: true,
                mouse_hint_shown: true,
                ..Onboarding::default()
            },
            terminal: Terminal { mouse: false },
            ..Config::default()
        };

        config.save(&path).expect("a written config");

        let loaded = load(path.clone());

        assert_eq!(loaded.config, config);
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
        assert_eq!(loaded.path, path);
        assert_eq!(
            loaded.config.defaults.approval_mode(),
            Some(ApprovalMode::AutoEdit)
        );
        assert_eq!(
            loaded.config.defaults.sandbox_mode(),
            Some(SandboxMode::ReadOnly)
        );

        // The file says what wrote it and what a save does to hand edits.
        let text = fs::read_to_string(&path).expect("a readable config");
        assert!(text.contains("schema 1"), "{text}");
        assert!(text.contains("[defaults]"), "{text}");
        assert!(text.contains("[onboarding]"), "{text}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_is_the_first_run_rather_than_a_problem() {
        let dir = scratch("absent");
        let loaded = load(dir.join(CONFIG_FILE));

        assert_eq!(loaded.config, Config::default());
        assert!(!loaded.config.onboarding.welcomed);
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keys_a_newer_ouro_wrote_are_ignored_rather_than_refused() {
        let dir = scratch("unknown-keys");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "schema = 2\n\
             [defaults]\n\
             provider = \"codex\"\n\
             telepathy = true\n\
             [onboarding]\n\
             welcomed = true\n\
             greeted_at = \"2031-01-01\"\n\
             [a_table_from_a_later_build]\n\
             enabled = true\n",
        )
        .expect("a forward-looking config");

        let loaded = load(path);

        assert_eq!(loaded.config.defaults.provider.as_deref(), Some("codex"));
        assert!(loaded.config.onboarding.welcomed);
        assert!(
            loaded.problems.is_empty(),
            "a newer file is not a broken one: {:?}",
            loaded.problems
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// The quick-start screen is gone and so is its toggle. A file that still names it is
    /// an ordinary file with a key this build does not know, which is the one thing
    /// [`load`] must never refuse.
    #[test]
    fn a_config_naming_the_retired_quick_start_toggle_still_loads() {
        let dir = scratch("quick-start");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "[defaults]\nprovider = \"codex\"\n\
             [onboarding]\nwelcomed = true\nquick_start = false\n",
        )
        .expect("a config from a build that had the screen");

        let loaded = load(path.clone());

        assert_eq!(loaded.config.defaults.provider.as_deref(), Some("codex"));
        assert!(loaded.config.onboarding.welcomed);
        assert!(
            loaded.problems.is_empty(),
            "a retired key is not a broken file: {:?}",
            loaded.problems
        );

        // And the next save simply stops writing it.
        loaded.config.save(&path).expect("a rewrite");
        let text = fs::read_to_string(&path).expect("the rewritten config");
        assert!(!text.contains("quick_start"), "{text}");
        assert!(load(path).config.onboarding.welcomed);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_mouse_is_captured_unless_the_file_says_otherwise() {
        let dir = scratch("mouse");

        // No file at all is the ordinary first run, and the wheel works there.
        assert!(load(dir.join(CONFIG_FILE)).config.terminal.mouse);

        // A file with no `[terminal]` table is a file from before this key existed.
        let path = dir.join(CONFIG_FILE);
        fs::write(&path, "[defaults]\nprovider = \"codex\"\n").expect("an older config");
        let loaded = load(path.clone());
        assert!(loaded.config.terminal.mouse);
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);

        // And the one value that changes anything.
        fs::write(&path, "[terminal]\nmouse = false\n").expect("a config that opts out");
        let loaded = load(path.clone());
        assert!(!loaded.config.terminal.mouse);
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);

        // A save carries the answer back, rather than quietly restoring the default.
        loaded.config.save(&path).expect("a rewrite");
        assert!(!load(path).config.terminal.mouse);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_file_falls_back_to_defaults_and_names_itself() {
        let dir = scratch("corrupt");
        let path = dir.join(CONFIG_FILE);

        fs::write(&path, "[defaults\nprovider = ").expect("a broken config");

        let loaded = load(path.clone());

        assert_eq!(loaded.config, Config::default());
        assert_eq!(loaded.problems.len(), 1, "{:?}", loaded.problems);
        assert!(
            loaded.problems[0].contains(&path.display().to_string()),
            "the problem must name the file: {}",
            loaded.problems[0]
        );
        assert!(
            loaded.problems[0].contains("defaults"),
            "and carry what TOML said: {}",
            loaded.problems[0]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_approval_mode_outside_the_schema_is_dropped_and_reported() {
        let dir = scratch("bad-mode");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "[defaults]\nprovider = \"codex\"\napproval_mode = \"yolo\"\n",
        )
        .expect("a config with a typo");

        let loaded = load(path);

        // The rest of the file still counts: one bad value is not a bad file.
        assert_eq!(loaded.config.defaults.provider.as_deref(), Some("codex"));
        assert_eq!(loaded.config.defaults.approval_mode, None);
        assert_eq!(loaded.config.defaults.approval_mode(), None);
        assert_eq!(loaded.problems.len(), 1);
        assert!(
            loaded.problems[0].contains("yolo") && loaded.problems[0].contains("auto_approve"),
            "the problem names the value and what would have been accepted: {}",
            loaded.problems[0]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sandbox_mode_outside_the_schema_is_dropped_and_reported() {
        let dir = scratch("bad-sandbox");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "[defaults]\nprovider = \"codex\"\nsandbox_mode = \"yolo\"\n",
        )
        .expect("a config with a typo");

        let loaded = load(path);

        assert_eq!(loaded.config.defaults.provider.as_deref(), Some("codex"));
        assert_eq!(loaded.config.defaults.sandbox_mode, None);
        assert_eq!(loaded.config.defaults.sandbox_mode(), None);
        assert_eq!(loaded.problems.len(), 1);
        assert!(
            loaded.problems[0].contains("yolo") && loaded.problems[0].contains("workspace_write"),
            "the problem names the value and what would have been accepted: {}",
            loaded.problems[0]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_blank_value_is_the_same_statement_as_an_absent_one() {
        let dir = scratch("blank");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "[defaults]\nprovider = \"\"\nworkspace = \"   \"\napproval_mode = \"\"\nsandbox_mode = \"\"\n",
        )
        .expect("a blank config");

        let loaded = load(path);

        assert!(loaded.config.defaults.is_empty());
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_save_replaces_the_previous_file_whole_and_leaves_no_temp_behind() {
        let dir = scratch("atomic");
        let path = dir.join(CONFIG_FILE);

        let first = Config {
            defaults: Defaults {
                provider: Some("claude".into()),
                ..Defaults::default()
            },
            onboarding: Onboarding::default(),
            terminal: Terminal::default(),
            ..Config::default()
        };

        first.save(&path).expect("a first write");

        let second = Config {
            defaults: Defaults {
                workspace: Some("/srv/work".into()),
                ..Defaults::default()
            },
            onboarding: Onboarding {
                welcomed: true,
                mouse_hint_shown: false,
                ..Onboarding::default()
            },
            terminal: Terminal::default(),
            ..Config::default()
        };

        second.save(&path).expect("a second write");

        assert_eq!(load(path.clone()).config, second);

        // Nothing but the file itself: the temp is renamed onto the target, never left.
        let entries: Vec<String> = fs::read_dir(&dir)
            .expect("a readable directory")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .collect();

        assert_eq!(entries, vec![CONFIG_FILE.to_string()], "{entries:?}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_save_creates_the_directories_its_path_names() {
        let dir = scratch("mkdir");
        let path = dir.join("nested").join("deeper").join(CONFIG_FILE);

        Config::default().save(&path).expect("a written config");

        assert!(path.is_file());
        assert_eq!(load(path).config, Config::default());

        fs::remove_dir_all(&dir).ok();
    }

    /// `path()` reads process-wide environment, so the two cases it distinguishes are
    /// exercised in one test rather than in two that could interleave.
    #[test]
    fn the_config_root_follows_xdg_config_home_only_when_it_is_absolute() {
        let dir = scratch("xdg");

        let previous = std::env::var_os("XDG_CONFIG_HOME");
        let previous_home = std::env::var_os("HOME");

        // SAFETY: `cargo test` runs test functions on threads of one process, and this
        // test is the only one that touches these two variables; it restores both.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &dir);
        }

        assert_eq!(
            path().expect("a config path"),
            dir.join(CONFIG_DIR).join(CONFIG_FILE)
        );

        // Relative is not a root. The variable is ignored and the home fallback applies,
        // which is `xdg_root`'s rule and is checked here against a home of this test's own
        // rather than against the caller's.
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("a scratch home");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", "relative/config");
            std::env::set_var("HOME", &home);
        }

        assert_eq!(
            path().expect("a config path"),
            home.join(".config").join(CONFIG_DIR).join(CONFIG_FILE)
        );

        unsafe {
            match previous {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }

            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_flag_beats_the_file_and_the_file_beats_nothing() {
        let defaults = Defaults {
            provider: Some("claude".into()),
            model: Some("anthropic:claude-sonnet-5".into()),
            workspace: Some("/home/me/project".into()),
            approval_mode: Some("auto_edit".into()),
            sandbox_mode: Some("read_only".into()),
        };

        // Nothing stated: every answer comes from the file.
        let resolved = resolve_start(&StartFlags::default(), &defaults).expect("a resolution");

        assert_eq!(resolved.provider, "claude");
        assert_eq!(resolved.model.as_deref(), Some("anthropic:claude-sonnet-5"));
        assert_eq!(resolved.workspace.as_deref(), Some("/home/me/project"));
        assert_eq!(resolved.approval_mode.as_deref(), Some("auto_edit"));
        assert_eq!(resolved.sandbox_mode.as_deref(), Some("read_only"));
        assert_eq!(resolved.machine, None);

        // Stated: the flag wins, field by field.
        let flags = StartFlags {
            provider: Some("codex".into()),
            approval_mode: Some("prompt".into()),
            sandbox_mode: Some("workspace_write".into()),
            machine: Some("builder-one".into()),
            ..StartFlags::default()
        };

        let resolved = resolve_start(&flags, &defaults).expect("a resolution");

        assert_eq!(resolved.provider, "codex");
        assert_eq!(
            resolved.workspace.as_deref(),
            Some("/home/me/project"),
            "a flag that was not passed does not clear the default"
        );
        assert_eq!(resolved.approval_mode.as_deref(), Some("prompt"));
        assert_eq!(resolved.sandbox_mode.as_deref(), Some("workspace_write"));
        assert_eq!(resolved.machine.as_deref(), Some("builder-one"));
    }

    #[test]
    fn nothing_stated_uses_the_direct_native_default() {
        let resolved =
            resolve_start(&StartFlags::default(), &Defaults::default()).expect("a resolution");

        assert_eq!(resolved.provider, "native");
        assert_eq!(resolved.model, None);
    }

    #[test]
    fn a_workspace_and_an_approval_mode_are_allowed_to_be_unstated() {
        let flags = StartFlags {
            provider: Some("native".into()),
            ..StartFlags::default()
        };

        let resolved = resolve_start(&flags, &Defaults::default()).expect("a resolution");

        assert_eq!(resolved.provider, "native");
        assert_eq!(resolved.workspace, None);
        assert_eq!(resolved.approval_mode, None);
        assert_eq!(resolved.sandbox_mode, None);
    }
}
