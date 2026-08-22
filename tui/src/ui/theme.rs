//! One place for every colour, so that "what does red mean here" has a single answer.
//!
//! ## A resolved value, not a constant
//!
//! The palette used to be a handful of `const Color`s. It is now a [`Theme`] chosen once at
//! startup — from `[theme] name` in `config.toml`, from `NO_COLOR`, and from what the
//! terminal answered when asked for its own background — and switchable at runtime by
//! `/theme`. Every drawing surface reads it through the accessors below rather than naming
//! a colour, so a theme switch is one store and the next frame.
//!
//! The active theme is an index into [`PALETTES`] held in an atomic, not a lock. Colour
//! accessors are called thousands of times per frame; a `RwLock` read on each of them
//! would be a cost paid on the hot path for a value that changes when a person presses a
//! key. The index is `Relaxed` because a frame drawn half in the old theme and half in the
//! new one is not a correctness problem — the following frame is whole either way.
//!
//! ## Named ANSI colours, and when this client stops using them
//!
//! [`Palette::Dark`] and [`Palette::Ansi`] are the terminal's own sixteen colours rather
//! than an RGB scheme: `ouro` runs in whatever terminal an operator already has
//! configured, and a hard-coded background is how a TUI ends up unreadable in someone
//! else's theme. [`Palette::Ansi`] is Kiro's "safe" theme — named colours *only*, so an
//! operator who remapped their palette gets their own hues.
//!
//! The light and daltonized palettes are RGB, and that is a deliberate exception rather
//! than a drift. The sixteen ANSI colours contain no green, cyan, or yellow that is
//! legible on a white ground (measured: 2.16, 1.98 and 1.70 against white), so a light
//! theme built from names would be a light theme nobody can read. Where this client picks
//! the hue it owns the contrast, and [`contrast`] is checked in tests for every token.
//!
//! ## `NO_COLOR`
//!
//! <https://no-color.org> is answered with [`Palette::Monochrome`]: every colour token is
//! `Color::Reset` — the terminal's own foreground — and the distinctions that were
//! carrying meaning in colour are carried by modifiers instead. That is why
//! [`availability`], [`session_status`] and the diff line styles are functions here rather
//! than colours at their call sites: they are the places where the colour *was* the whole
//! message, so they are the places that need a second channel.
//!
//! ## The load-bearing rule
//!
//! [`availability`]. `:disabled` is a *posture* — the control plane and the workspace plane
//! report it when they were never configured — so it is rendered dim rather than red. A
//! dashboard that painted a deliberate choice the same colour as an outage would teach an
//! operator to ignore the colour.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use ratatui::style::{Color, Modifier, Style};

use crate::model::{Availability, SessionStatus};

/// A palette this build ships. Resolved from a name plus the environment; never `auto`,
/// because `auto` is a question and this is an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Palette {
    /// Today's palette, unchanged: the terminal's own sixteen colours on a dark ground.
    Dark = 0,
    /// RGB, tuned against white.
    Light = 1,
    /// Named ANSI colours only, so a remapped terminal palette is the one that applies.
    Ansi = 2,
    /// Dark ground, with diff add/remove on the blue/orange axis instead of green/red.
    DarkDaltonized = 3,
    /// Light ground, same axis.
    LightDaltonized = 4,
    /// `NO_COLOR`. Modifiers only.
    Monochrome = 5,
}

/// The name an operator writes in `config.toml`, including the one that is a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeName {
    /// Ask the terminal for its background and pick dark or light from the answer.
    #[default]
    Auto,
    Dark,
    Light,
    Ansi,
    DarkDaltonized,
    LightDaltonized,
}

impl ThemeName {
    pub const ALL: [ThemeName; 6] = [
        Self::Auto,
        Self::Dark,
        Self::Light,
        Self::Ansi,
        Self::DarkDaltonized,
        Self::LightDaltonized,
    ];

    /// The names `/theme` cycles through. `auto` is not among them: cycling is a person
    /// choosing a look, and re-entering "ask the terminal" mid-session would answer the
    /// choice with a probe.
    pub const CYCLE: [ThemeName; 5] = [
        Self::Dark,
        Self::Light,
        Self::Ansi,
        Self::DarkDaltonized,
        Self::LightDaltonized,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dark => "dark",
            Self::Light => "light",
            Self::Ansi => "ansi",
            Self::DarkDaltonized => "dark-daltonized",
            Self::LightDaltonized => "light-daltonized",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|theme| theme.as_str() == name)
    }

    /// The next name in [`CYCLE`], starting from `dark` for anything not in it.
    pub fn next(self) -> Self {
        let at = Self::CYCLE.iter().position(|name| *name == self);
        Self::CYCLE[at.map_or(0, |at| (at + 1) % Self::CYCLE.len())]
    }
}

/// What a terminal answered when asked what colour its background is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Background {
    Dark,
    Light,
}

/// The ground a palette was designed against, and therefore the ground its contrast was
/// measured on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ground {
    Dark,
    Light,
    /// The terminal's own, whatever it is. Only [`Palette::Ansi`] and
    /// [`Palette::Monochrome`] claim this, and it is the reason neither can be checked
    /// against a reference background: the colours they name belong to the terminal.
    Terminal,
}

/// Every colour this client draws with, and nothing else.
///
/// Deliberately flat. A theme with structure is a theme with places to put a colour that
/// no test walks, and [`Theme::tokens`] is what makes "every token is defined in every
/// theme" a thing a test can assert rather than a thing a reviewer has to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub palette: Palette,
    pub name: &'static str,
    pub ground: Ground,
    /// Whether every colour here is one of the sixteen names. The safety property of the
    /// `ansi` theme, asserted rather than described.
    pub named_ansi: bool,
    /// Whether colour carries no meaning at all, so the helpers below reach for modifiers.
    pub monochrome: bool,

    /// Machine activity and agent output. Cyan on the dark palette, and deliberately
    /// reserved for things the runtime is doing, so a moving mark always means "system"
    /// rather than "click me".
    pub system: Color,
    /// Human intent: the composer caret, the selected session, and actionable prompts.
    pub action: Color,
    pub muted: Color,
    pub good: Color,
    /// Warnings, distinct from the warmer action channel.
    pub warn: Color,
    pub bad: Color,

    /// Diff additions and removals. Separate tokens from `good`/`bad` because the
    /// daltonized palettes move exactly these two off the green/red axis and leave the
    /// availability channel where it was.
    pub diff_added: Color,
    pub diff_removed: Color,

    pub code_keyword: Color,
    pub code_string: Color,
    pub code_number: Color,
    pub code_function: Color,
    pub code_key: Color,
    pub code_type: Color,
    pub code_comment: Color,

    /// A value the wire redacted or base64'd, in the details tree.
    pub opaque: Color,
}

/// What every accessor is asked for, by name. Walked by the test that proves no palette
/// left one out and by the contrast check.
pub const TOKENS: [&str; 15] = [
    "system",
    "action",
    "muted",
    "good",
    "warn",
    "bad",
    "diff_added",
    "diff_removed",
    "code_keyword",
    "code_string",
    "code_number",
    "code_function",
    "code_key",
    "code_type",
    "code_comment",
];

impl Theme {
    /// Every token, paired with the name [`TOKENS`] lists it under.
    ///
    /// `opaque` is absent on purpose: it is a details-tree accent over a value that is
    /// already dim, and it is the one colour here that never carries a word's meaning.
    pub fn tokens(&self) -> [(&'static str, Color); 15] {
        [
            ("system", self.system),
            ("action", self.action),
            ("muted", self.muted),
            ("good", self.good),
            ("warn", self.warn),
            ("bad", self.bad),
            ("diff_added", self.diff_added),
            ("diff_removed", self.diff_removed),
            ("code_keyword", self.code_keyword),
            ("code_string", self.code_string),
            ("code_number", self.code_number),
            ("code_function", self.code_function),
            ("code_key", self.code_key),
            ("code_type", self.code_type),
            ("code_comment", self.code_comment),
        ]
    }
}

/// The dark palette: exactly the colours this client drew before themes existed.
const DARK: Theme = Theme {
    palette: Palette::Dark,
    name: "dark",
    ground: Ground::Dark,
    named_ansi: true,
    monochrome: false,
    system: Color::Cyan,
    action: Color::Yellow,
    muted: Color::DarkGray,
    good: Color::Green,
    warn: Color::LightYellow,
    bad: Color::Red,
    diff_added: Color::Green,
    diff_removed: Color::Red,
    code_keyword: Color::Magenta,
    code_string: Color::Green,
    code_number: Color::Yellow,
    // `Color::Blue` measures 2.23:1 against black on the reference palette — below every
    // threshold there is. The bright variant is the same hue and 4.43:1.
    code_function: Color::LightBlue,
    code_key: Color::LightBlue,
    code_type: Color::Cyan,
    code_comment: Color::DarkGray,
    opaque: Color::Magenta,
};

/// White ground. RGB, because the sixteen names have nothing legible on white.
const LIGHT: Theme = Theme {
    palette: Palette::Light,
    name: "light",
    ground: Ground::Light,
    named_ansi: false,
    monochrome: false,
    system: Color::Rgb(0, 92, 175),
    action: Color::Rgb(150, 60, 0),
    muted: Color::Rgb(90, 90, 90),
    good: Color::Rgb(0, 110, 60),
    warn: Color::Rgb(140, 80, 0),
    bad: Color::Rgb(185, 28, 28),
    diff_added: Color::Rgb(0, 110, 60),
    diff_removed: Color::Rgb(185, 28, 28),
    code_keyword: Color::Rgb(140, 40, 140),
    code_string: Color::Rgb(0, 110, 60),
    code_number: Color::Rgb(150, 60, 0),
    code_function: Color::Rgb(0, 92, 175),
    code_key: Color::Rgb(0, 92, 175),
    code_type: Color::Rgb(0, 105, 138),
    code_comment: Color::Rgb(90, 90, 90),
    opaque: Color::Rgb(140, 40, 140),
};

/// Kiro's "safe" theme: named colours only, so the operator's own palette is the one that
/// renders. This client makes no claim about the resulting contrast, and cannot — the
/// hues belong to the terminal.
const ANSI: Theme = Theme {
    palette: Palette::Ansi,
    name: "ansi",
    ground: Ground::Terminal,
    named_ansi: true,
    monochrome: false,
    system: Color::Blue,
    action: Color::Magenta,
    muted: Color::DarkGray,
    good: Color::Green,
    warn: Color::Yellow,
    bad: Color::Red,
    diff_added: Color::Green,
    diff_removed: Color::Red,
    code_keyword: Color::Magenta,
    code_string: Color::Green,
    code_number: Color::Yellow,
    code_function: Color::Blue,
    code_key: Color::Blue,
    code_type: Color::Cyan,
    code_comment: Color::DarkGray,
    opaque: Color::Magenta,
};

/// Claude Code's daltonized dark: additions and removals on the blue/orange axis, which
/// survives every common form of red/green colour blindness.
const DARK_DALTONIZED: Theme = Theme {
    palette: Palette::DarkDaltonized,
    name: "dark-daltonized",
    ground: Ground::Dark,
    named_ansi: false,
    monochrome: false,
    system: Color::Rgb(125, 211, 252),
    action: Color::Rgb(253, 224, 71),
    muted: Color::Rgb(148, 148, 148),
    good: Color::Rgb(96, 165, 250),
    warn: Color::Rgb(251, 191, 36),
    bad: Color::Rgb(251, 146, 60),
    diff_added: Color::Rgb(96, 165, 250),
    diff_removed: Color::Rgb(251, 146, 60),
    code_keyword: Color::Rgb(216, 180, 254),
    code_string: Color::Rgb(125, 211, 252),
    code_number: Color::Rgb(253, 224, 71),
    code_function: Color::Rgb(96, 165, 250),
    code_key: Color::Rgb(96, 165, 250),
    code_type: Color::Rgb(125, 211, 252),
    code_comment: Color::Rgb(148, 148, 148),
    opaque: Color::Rgb(216, 180, 254),
};

const LIGHT_DALTONIZED: Theme = Theme {
    palette: Palette::LightDaltonized,
    name: "light-daltonized",
    ground: Ground::Light,
    named_ansi: false,
    monochrome: false,
    system: Color::Rgb(0, 105, 138),
    action: Color::Rgb(150, 60, 0),
    muted: Color::Rgb(90, 90, 90),
    good: Color::Rgb(0, 82, 204),
    warn: Color::Rgb(140, 80, 0),
    bad: Color::Rgb(166, 74, 0),
    diff_added: Color::Rgb(0, 82, 204),
    diff_removed: Color::Rgb(166, 74, 0),
    code_keyword: Color::Rgb(140, 40, 140),
    code_string: Color::Rgb(0, 105, 138),
    code_number: Color::Rgb(150, 60, 0),
    code_function: Color::Rgb(0, 82, 204),
    code_key: Color::Rgb(0, 82, 204),
    code_type: Color::Rgb(0, 105, 138),
    code_comment: Color::Rgb(90, 90, 90),
    opaque: Color::Rgb(140, 40, 140),
};

/// `NO_COLOR`. Every token is the terminal's own foreground; the helpers below carry what
/// the colour was carrying.
const MONOCHROME: Theme = Theme {
    palette: Palette::Monochrome,
    name: "no-color",
    ground: Ground::Terminal,
    named_ansi: true,
    monochrome: true,
    system: Color::Reset,
    action: Color::Reset,
    muted: Color::Reset,
    good: Color::Reset,
    warn: Color::Reset,
    bad: Color::Reset,
    diff_added: Color::Reset,
    diff_removed: Color::Reset,
    code_keyword: Color::Reset,
    code_string: Color::Reset,
    code_number: Color::Reset,
    code_function: Color::Reset,
    code_key: Color::Reset,
    code_type: Color::Reset,
    code_comment: Color::Reset,
    opaque: Color::Reset,
};

/// Indexed by [`Palette`], which is why the discriminants are written out above.
pub const PALETTES: [Theme; 6] = [
    DARK,
    LIGHT,
    ANSI,
    DARK_DALTONIZED,
    LIGHT_DALTONIZED,
    MONOCHROME,
];

/// Which palette is drawing. Dark until [`install`] says otherwise, which is what this
/// client did before the setting existed.
static ACTIVE: AtomicU8 = AtomicU8::new(Palette::Dark as u8);

/// Bumped by every [`install`]. Render caches key on it, because rows built from one
/// palette are not rows the next palette would have produced.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// The theme every accessor reads.
pub fn current() -> &'static Theme {
    let at = ACTIVE.load(Ordering::Relaxed) as usize;
    // `install` is the only writer and it only ever stores a discriminant, so this cannot
    // be out of range. Clamped anyway rather than indexed blind: a panic inside a draw
    // takes the terminal with it.
    &PALETTES[at.min(PALETTES.len() - 1)]
}

/// What the memoising renderers add to their keys.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Relaxed)
}

/// Makes a palette the one every following frame draws with.
pub fn install(palette: Palette) {
    if ACTIVE.swap(palette as u8, Ordering::Relaxed) != palette as u8 {
        GENERATION.fetch_add(1, Ordering::Relaxed);
    }
}

/// Which palette a configured name, the environment, and the terminal's answer add up to.
///
/// A pure function of its four arguments, so the matrix is a table in a test rather than a
/// thing that can only be observed by starting a terminal.
///
/// `NO_COLOR` wins over everything, including an explicitly named theme. That is the
/// standard's own rule — the variable means "do not emit colour", not "prefer not to" —
/// and a client that honoured a config file over it would be a client that does not
/// support `NO_COLOR`. The name the operator asked for is still reported by
/// [`resolution_note`] rather than silently swallowed.
pub fn resolve(name: ThemeName, no_color: bool, background: Option<Background>) -> Palette {
    if no_color {
        return Palette::Monochrome;
    }

    match name {
        ThemeName::Dark => Palette::Dark,
        ThemeName::Light => Palette::Light,
        ThemeName::Ansi => Palette::Ansi,
        ThemeName::DarkDaltonized => Palette::DarkDaltonized,
        ThemeName::LightDaltonized => Palette::LightDaltonized,
        // The terminal that did not answer is not assumed to be light: a light palette on
        // a dark ground is unreadable, and a dark palette on a light ground is merely
        // low-contrast. The asymmetry is the whole reason the fallback is `dark`.
        ThemeName::Auto => match background {
            Some(Background::Light) => Palette::Light,
            Some(Background::Dark) | None => Palette::Dark,
        },
    }
}

/// What a terminal's OSC 11 answer means, or `None` for bytes that are not one.
///
/// The reply is `ESC ] 11 ; rgb:RRRR/GGGG/BBBB` followed by `BEL` or `ESC \`, and the
/// component width is the terminal's choice: xterm answers in four hex digits per channel,
/// others in one, two, or three. Each component is therefore scaled by its own width
/// rather than assumed to be sixteen bits — a client that read `rgb:0/0/0` as a two-digit
/// pair would decide a black background was a light one.
///
/// Split out from the I/O so the parse is a pure function over bytes: the read needs a
/// terminal, and the thing that decides dark from light does not.
pub fn parse_osc11(bytes: &[u8]) -> Option<Background> {
    let text = String::from_utf8_lossy(bytes);
    let at = text.find("]11;")?;
    let rest = &text[at + "]11;".len()..];

    // Whatever terminated it, and it must be terminated: a half-arrived reply is not an
    // answer, and treating it as one would read `rgb:ff` as a dark background.
    let body = rest
        .split(['\x07', '\x1b'])
        .next()
        .map(str::trim)
        .filter(|_| rest.contains('\x07') || rest.contains('\x1b'))?;

    let digits = body
        .strip_prefix("rgb:")
        .or_else(|| body.strip_prefix("RGB:"))?;

    let mut channels = [0f64; 3];
    let mut seen = 0usize;

    for (index, component) in digits.split('/').enumerate() {
        if index >= 3 {
            return None;
        }

        let component = component.trim();
        if component.is_empty() || component.len() > 4 {
            return None;
        }

        let value = u32::from_str_radix(component, 16).ok()?;
        let full = 16u32.pow(component.len() as u32) - 1;
        channels[index] = f64::from(value) / f64::from(full);
        seen += 1;
    }

    if seen != 3 {
        return None;
    }

    // Perceptual, not arithmetic: a saturated blue background has a high green-weighted
    // luminance of almost nothing and is a dark background by every eye that sees it.
    let luminance = 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];

    Some(match luminance > 0.5 {
        true => Background::Light,
        false => Background::Dark,
    })
}

/// What to say about a resolution that is not what was asked for.
///
/// The honesty invariant applied to a palette: an operator who wrote
/// `name = "light-daltonized"` and got monochrome because `NO_COLOR` is exported is told
/// so, rather than left to wonder why their theme did nothing.
pub fn resolution_note(
    name: ThemeName,
    no_color: bool,
    background: Option<Background>,
) -> Option<String> {
    if no_color {
        return Some(match name {
            ThemeName::Auto => "NO_COLOR is set, so ouro is drawing without colour".to_string(),
            named => format!(
                "NO_COLOR is set, so ouro is drawing without colour; the {} theme in \
                 config.toml is not being used",
                named.as_str()
            ),
        });
    }

    match (name, background) {
        (ThemeName::Auto, None) => Some(
            "this terminal did not answer what colour its background is, so ouro is using \
             the dark theme; set [theme] name in config.toml to choose"
                .to_string(),
        ),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------
// Colour accessors. Every drawing surface reads the palette through exactly these.
// ---------------------------------------------------------------------------------------

pub fn system() -> Color {
    current().system
}

/// The colour of the action channel. Named apart from [`action`], which is the whole
/// style, because both are wanted at different call sites.
pub fn action_colour() -> Color {
    current().action
}

/// Backwards-compatible name for the system channel used throughout the operator views.
pub fn accent() -> Color {
    current().system
}

pub fn muted() -> Color {
    current().muted
}

pub fn good() -> Color {
    current().good
}

pub fn warn() -> Color {
    current().warn
}

pub fn bad() -> Color {
    current().bad
}

pub fn opaque() -> Color {
    current().opaque
}

/// The diff channel as a bare colour, for the file-status marks that sit beside a path
/// rather than on a `+`/`-` line.
pub fn diff_added_colour() -> Color {
    current().diff_added
}

pub fn diff_removed_colour() -> Color {
    current().diff_removed
}

pub fn code_keyword() -> Color {
    current().code_keyword
}

pub fn code_string() -> Color {
    current().code_string
}

pub fn code_number() -> Color {
    current().code_number
}

pub fn code_function() -> Color {
    current().code_function
}

pub fn code_key() -> Color {
    current().code_key
}

pub fn code_type() -> Color {
    current().code_type
}

pub fn code_comment() -> Color {
    current().code_comment
}

pub fn heading() -> Style {
    Style::default().fg(system()).add_modifier(Modifier::BOLD)
}

pub fn action() -> Style {
    Style::default()
        .fg(action_colour())
        .add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    Style::default().fg(muted())
}

/// Secondary transcript matter: tool calls, command output, footnotes. Dimmer than
/// either speaker's words, so the conversation stays the thing the eye lands on.
pub fn quiet() -> Style {
    Style::default().fg(muted()).add_modifier(Modifier::DIM)
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
            .fg(system())
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        2 => Style::default().fg(system()).add_modifier(Modifier::BOLD),
        3 => Style::default().add_modifier(Modifier::BOLD),
        4 => Style::default().add_modifier(Modifier::BOLD | Modifier::DIM),
        _ => Style::default().fg(muted()).add_modifier(Modifier::BOLD),
    }
}

/// Inline code, and the backticks that still delimit it.
pub fn markdown_code() -> Style {
    match current().monochrome {
        // Without colour, inline code and prose would be the same bytes. Italic is the one
        // modifier the surrounding emphasis vocabulary is not already using.
        true => Style::default().add_modifier(Modifier::ITALIC),
        false => Style::default().fg(system()),
    }
}

/// Link text. Underlined rather than coloured: the action channel is reserved for things
/// a keystroke acts on, and a URL in a transcript is not one of them.
pub fn markdown_link() -> Style {
    Style::default().add_modifier(Modifier::UNDERLINED)
}

/// The `(url)` that follows link text, so the destination is readable and copyable
/// without being mistaken for the sentence it sits in.
pub fn markdown_url() -> Style {
    Style::default().fg(muted())
}

/// The bar down the left of a block quote, and the rule of a horizontal break.
pub fn markdown_rule() -> Style {
    Style::default().fg(muted()).add_modifier(Modifier::DIM)
}

/// A table's header row: the only row in a table that is not data.
pub fn markdown_table_header() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// A task-list checkbox. Done is the good channel because it is a completed thing;
/// pending is muted because an unticked box is not a warning.
pub fn markdown_task(done: bool) -> Style {
    match done {
        true => Style::default().fg(good()),
        false => Style::default().fg(muted()).add_modifier(Modifier::DIM),
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

/// A diff line's style, by what the line is.
///
/// A function rather than two colours because without colour the two have to differ by
/// something, and the sign column alone is a single character an eye skips. Bold for an
/// addition and dim for a removal is the same pairing the rest of this module uses for
/// "arrived" and "went away".
pub fn diff_added() -> Style {
    match current().monochrome {
        true => Style::default().add_modifier(Modifier::BOLD),
        false => Style::default().fg(current().diff_added),
    }
}

pub fn diff_removed() -> Style {
    match current().monochrome {
        true => Style::default().add_modifier(Modifier::DIM),
        false => Style::default().fg(current().diff_removed),
    }
}

pub fn availability(state: &Availability) -> Style {
    let theme = current();

    match state {
        Availability::Available => Style::default().fg(theme.good),
        Availability::Unavailable => match theme.monochrome {
            // The one distinction in this enum that colour was carrying alone.
            true => Style::default().add_modifier(Modifier::BOLD),
            false => Style::default().fg(theme.bad),
        },
        // Configured off on purpose. Dim, never red.
        Availability::Disabled => Style::default().fg(theme.muted).add_modifier(Modifier::DIM),
        Availability::Other(_) => match theme.monochrome {
            true => Style::default().add_modifier(Modifier::UNDERLINED),
            false => Style::default().fg(theme.warn),
        },
    }
}

pub fn session_status(status: &SessionStatus) -> Style {
    let theme = current();
    let mono = theme.monochrome;

    match status {
        SessionStatus::Running | SessionStatus::Starting => Style::default().fg(theme.system),
        SessionStatus::AwaitingApproval => {
            Style::default().fg(theme.warn).add_modifier(Modifier::BOLD)
        }
        SessionStatus::Idle => Style::default().fg(theme.good),
        SessionStatus::Completed | SessionStatus::Closed => {
            Style::default().fg(theme.muted).add_modifier(if mono {
                Modifier::DIM
            } else {
                Modifier::empty()
            })
        }
        SessionStatus::Failed | SessionStatus::Lost => {
            Style::default().fg(theme.bad).add_modifier(if mono {
                Modifier::BOLD
            } else {
                Modifier::empty()
            })
        }
        SessionStatus::Cancelled | SessionStatus::Closing => {
            Style::default().fg(theme.warn).add_modifier(if mono {
                Modifier::UNDERLINED
            } else {
                Modifier::empty()
            })
        }
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
    match super::access::reduced_motion() {
        // A frame that never advances. Kept as a glyph rather than dropped so the row is
        // the same width it was, and the caller that wants a word instead asks for one.
        true => '·',
        false => SPINNER_FRAMES[(tick as usize) % SPINNER_FRAMES.len()],
    }
}

pub fn working_verb(tick: u64) -> &'static str {
    match super::access::reduced_motion() {
        // Rotating the verb is animation with extra steps: it is a moving word.
        true => WORKING_VERBS[0],
        false => WORKING_VERBS[((tick / WORKING_VERB_TICKS) as usize) % WORKING_VERBS.len()],
    }
}

/// One-line working indicator: `⠋  Working`.
///
/// In screen-reader mode the spinner is a word — `working:` — because a braille glyph that
/// changes ten times a second is a line a screen reader re-reads ten times a second.
pub fn working(tick: u64, message: impl Into<String>) -> ratatui::text::Line<'static> {
    use ratatui::text::{Line, Span};

    let message = message.into();

    if super::access::screen_reader() {
        return Line::from(vec![
            Span::styled(
                "working: ".to_string(),
                Style::default().fg(accent()).add_modifier(Modifier::BOLD),
            ),
            Span::styled(message, Style::default().fg(muted())),
        ]);
    }

    Line::from(vec![
        Span::raw("  "),
        Span::styled(
            spinner(tick).to_string(),
            Style::default().fg(accent()).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(message, Style::default().fg(muted())),
    ])
}

// ---------------------------------------------------------------------------------------
// Contrast
// ---------------------------------------------------------------------------------------

/// The xterm palette, as the reference for what a named ANSI colour "is".
///
/// A reference and not a claim: the whole point of naming colours is that the operator's
/// terminal supplies the hue, so these numbers say what a *default* terminal would draw
/// and nothing more. They are here so the contrast check has something to measure, and the
/// check treats a named-colour theme accordingly.
pub const REFERENCE_ANSI: [(u8, u8, u8); 16] = [
    (0, 0, 0),
    (205, 0, 0),
    (0, 205, 0),
    (205, 205, 0),
    (0, 0, 238),
    (205, 0, 205),
    (0, 205, 205),
    (229, 229, 229),
    (127, 127, 127),
    (255, 0, 0),
    (0, 255, 0),
    (255, 255, 0),
    (92, 92, 255),
    (255, 0, 255),
    (0, 255, 255),
    (255, 255, 255),
];

/// A colour's reference RGB, or `None` for one that has no fixed value at all.
///
/// `Color::Reset` is the terminal's own foreground. It has no RGB here and it never needs
/// one: it is by construction the colour the operator's terminal draws readable text in.
pub fn reference_rgb(colour: Color) -> Option<(u8, u8, u8)> {
    let indexed = |index: usize| Some(REFERENCE_ANSI[index]);

    match colour {
        Color::Reset => None,
        Color::Black => indexed(0),
        Color::Red => indexed(1),
        Color::Green => indexed(2),
        Color::Yellow => indexed(3),
        Color::Blue => indexed(4),
        Color::Magenta => indexed(5),
        Color::Cyan => indexed(6),
        Color::Gray => indexed(7),
        Color::DarkGray => indexed(8),
        Color::LightRed => indexed(9),
        Color::LightGreen => indexed(10),
        Color::LightYellow => indexed(11),
        Color::LightBlue => indexed(12),
        Color::LightMagenta => indexed(13),
        Color::LightCyan => indexed(14),
        Color::White => indexed(15),
        Color::Rgb(r, g, b) => Some((r, g, b)),
        Color::Indexed(index) => REFERENCE_ANSI.get(index as usize).copied(),
        // ratatui may grow a colour this build has never heard of; a contrast check that
        // invented an RGB for it would be measuring a number nobody drew.
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

/// Whether a colour is one of the sixteen names — the property that makes a remapped
/// terminal palette apply.
pub fn is_named_ansi(colour: Color) -> bool {
    matches!(
        colour,
        Color::Reset
            | Color::Black
            | Color::Red
            | Color::Green
            | Color::Yellow
            | Color::Blue
            | Color::Magenta
            | Color::Cyan
            | Color::Gray
            | Color::DarkGray
            | Color::LightRed
            | Color::LightGreen
            | Color::LightYellow
            | Color::LightBlue
            | Color::LightMagenta
            | Color::LightCyan
            | Color::White
    )
}

/// WCAG 2.1 relative luminance.
fn luminance((r, g, b): (u8, u8, u8)) -> f64 {
    fn channel(value: u8) -> f64 {
        let value = f64::from(value) / 255.0;
        match value <= 0.039_28 {
            true => value / 12.92,
            false => ((value + 0.055) / 1.055).powf(2.4),
        }
    }

    0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

/// WCAG 2.1 contrast ratio, 1.0 through 21.0.
pub fn contrast(foreground: (u8, u8, u8), background: (u8, u8, u8)) -> f64 {
    let (a, b) = (luminance(foreground), luminance(background));
    let (high, low) = match a > b {
        true => (a, b),
        false => (b, a),
    };

    (high + 0.05) / (low + 0.05)
}

/// The reference grounds a theme's contrast is measured against.
pub fn reference_ground(ground: Ground) -> Option<(u8, u8, u8)> {
    match ground {
        Ground::Dark => Some(REFERENCE_ANSI[0]),
        Ground::Light => Some(REFERENCE_ANSI[15]),
        Ground::Terminal => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG AA for body text. Binding on the palettes where this client chose the hue.
    const RGB_MINIMUM: f64 = 4.5;

    /// WCAG AA for large text and user-interface components. The bar for a palette built
    /// from names, where the reference RGB is a stand-in for whatever the operator's own
    /// terminal draws and the real contrast is theirs to set.
    const NAMED_MINIMUM: f64 = 3.0;

    #[test]
    fn every_palette_defines_every_token() {
        for theme in PALETTES {
            let tokens = theme.tokens();
            assert_eq!(
                tokens.len(),
                TOKENS.len(),
                "{} has {} tokens, the list has {}",
                theme.name,
                tokens.len(),
                TOKENS.len()
            );

            for (index, (name, _)) in tokens.iter().enumerate() {
                assert_eq!(
                    *name, TOKENS[index],
                    "{} names token {index} {name:?}, the list says {:?}",
                    theme.name, TOKENS[index]
                );
            }
        }
    }

    #[test]
    fn a_coloured_palette_leaves_no_token_at_the_terminal_default() {
        for theme in PALETTES.iter().filter(|theme| !theme.monochrome) {
            for (name, colour) in theme.tokens() {
                assert_ne!(
                    colour,
                    Color::Reset,
                    "{} left {name} unset, so it would draw as ordinary text",
                    theme.name
                );
            }
        }
    }

    #[test]
    fn the_monochrome_palette_is_every_token_at_the_terminal_default() {
        for (name, colour) in MONOCHROME.tokens() {
            assert_eq!(colour, Color::Reset, "NO_COLOR left {name} coloured");
        }
        assert_eq!(MONOCHROME.opaque, Color::Reset);
    }

    /// The safe theme's whole contract: a remapped terminal palette applies to it, which
    /// is only true while every colour in it is one of the sixteen names.
    #[test]
    fn the_named_palettes_name_only_ansi_colours() {
        for theme in PALETTES.iter().filter(|theme| theme.named_ansi) {
            for (name, colour) in theme.tokens() {
                assert!(
                    is_named_ansi(colour),
                    "{} declares {name} as {colour:?}, which a remapped palette cannot reach",
                    theme.name
                );
            }
            assert!(is_named_ansi(theme.opaque), "{} opaque", theme.name);
        }
    }

    #[test]
    fn every_declared_pair_clears_its_ground() {
        for theme in PALETTES {
            let Some(ground) = reference_ground(theme.ground) else {
                // `Ground::Terminal` has no reference background to measure against, on
                // purpose: `ansi` and `no-color` hand the question to the terminal.
                continue;
            };

            let minimum = match theme.named_ansi {
                true => NAMED_MINIMUM,
                false => RGB_MINIMUM,
            };

            for (name, colour) in theme.tokens() {
                let Some(rgb) = reference_rgb(colour) else {
                    continue;
                };
                let ratio = contrast(rgb, ground);
                assert!(
                    ratio >= minimum,
                    "{}: {name} is {ratio:.2}:1 on its own ground, below {minimum}",
                    theme.name
                );
            }
        }
    }

    /// Both grounds are exercised, and by more than one palette each — otherwise "checked
    /// on both grounds" would be a claim one theme could quietly stop supporting.
    #[test]
    fn both_grounds_are_covered_by_the_palettes_that_declare_one() {
        let dark = PALETTES
            .iter()
            .filter(|theme| theme.ground == Ground::Dark)
            .count();
        let light = PALETTES
            .iter()
            .filter(|theme| theme.ground == Ground::Light)
            .count();

        assert!(dark >= 2, "{dark} palette(s) declare a dark ground");
        assert!(light >= 2, "{light} palette(s) declare a light ground");
    }

    #[test]
    fn a_daltonized_palette_moves_the_diff_off_the_green_red_axis() {
        for theme in [DARK_DALTONIZED, LIGHT_DALTONIZED] {
            let added = reference_rgb(theme.diff_added).expect("an rgb addition colour");
            let removed = reference_rgb(theme.diff_removed).expect("an rgb removal colour");

            // Blue against orange: the addition is the bluer of the two by a wide margin,
            // and the removal is the redder. A green/red pair would fail both halves.
            assert!(
                added.2 > added.0,
                "{}: additions are not on the blue side ({added:?})",
                theme.name
            );
            assert!(
                removed.0 > removed.2,
                "{}: removals are not on the warm side ({removed:?})",
                theme.name
            );
            assert!(
                i32::from(added.2) - i32::from(added.0) > 80,
                "{}: additions are not blue enough to separate ({added:?})",
                theme.name
            );
        }
    }

    #[test]
    fn no_color_wins_over_every_named_theme() {
        for name in ThemeName::ALL {
            assert_eq!(
                resolve(name, true, Some(Background::Light)),
                Palette::Monochrome,
                "{} survived NO_COLOR",
                name.as_str()
            );
            assert!(
                resolution_note(name, true, None).is_some(),
                "{} was swapped without a word",
                name.as_str()
            );
        }
    }

    #[test]
    fn the_resolution_matrix() {
        let cases: [(ThemeName, bool, Option<Background>, Palette); 12] = [
            (ThemeName::Auto, false, None, Palette::Dark),
            (
                ThemeName::Auto,
                false,
                Some(Background::Dark),
                Palette::Dark,
            ),
            (
                ThemeName::Auto,
                false,
                Some(Background::Light),
                Palette::Light,
            ),
            (
                ThemeName::Auto,
                true,
                Some(Background::Light),
                Palette::Monochrome,
            ),
            (
                ThemeName::Dark,
                false,
                Some(Background::Light),
                Palette::Dark,
            ),
            (
                ThemeName::Light,
                false,
                Some(Background::Dark),
                Palette::Light,
            ),
            (ThemeName::Ansi, false, None, Palette::Ansi),
            (ThemeName::Ansi, true, None, Palette::Monochrome),
            (
                ThemeName::DarkDaltonized,
                false,
                None,
                Palette::DarkDaltonized,
            ),
            (
                ThemeName::LightDaltonized,
                false,
                None,
                Palette::LightDaltonized,
            ),
            (
                ThemeName::DarkDaltonized,
                true,
                Some(Background::Dark),
                Palette::Monochrome,
            ),
            (ThemeName::Light, false, None, Palette::Light),
        ];

        for (name, no_color, background, expected) in cases {
            assert_eq!(
                resolve(name, no_color, background),
                expected,
                "{} · NO_COLOR={no_color} · background={background:?}",
                name.as_str()
            );
        }
    }

    #[test]
    fn an_unanswered_terminal_says_so_rather_than_guessing_quietly() {
        assert!(resolution_note(ThemeName::Auto, false, None).is_some());
        assert!(resolution_note(ThemeName::Auto, false, Some(Background::Dark)).is_none());
        // A named theme asked no question, so there is nothing to report.
        assert!(resolution_note(ThemeName::Dark, false, None).is_none());
    }

    #[test]
    fn names_round_trip_and_cycle_without_returning_to_auto() {
        for name in ThemeName::ALL {
            assert_eq!(ThemeName::parse(name.as_str()), Some(name));
        }
        assert_eq!(ThemeName::parse("  DARK  "), Some(ThemeName::Dark));
        assert_eq!(ThemeName::parse("solarized"), None);

        let mut seen = Vec::new();
        let mut name = ThemeName::Auto;
        for _ in 0..ThemeName::CYCLE.len() {
            name = name.next();
            assert_ne!(name, ThemeName::Auto, "the cycle re-entered auto");
            seen.push(name);
        }

        assert_eq!(seen.len(), ThemeName::CYCLE.len());
        assert_eq!(name.next(), ThemeName::Dark, "the cycle did not close");
    }

    #[test]
    fn the_dark_palette_is_the_one_this_client_always_drew() {
        assert_eq!(DARK.system, Color::Cyan);
        assert_eq!(DARK.action, Color::Yellow);
        assert_eq!(DARK.muted, Color::DarkGray);
        assert_eq!(DARK.good, Color::Green);
        assert_eq!(DARK.warn, Color::LightYellow);
        assert_eq!(DARK.bad, Color::Red);
    }

    #[test]
    fn an_osc11_reply_is_read_at_whatever_width_the_terminal_answered_in() {
        // xterm's four hex digits per channel, BEL-terminated: black.
        assert_eq!(
            parse_osc11(b"\x1b]11;rgb:0000/0000/0000\x07"),
            Some(Background::Dark)
        );
        // …and white.
        assert_eq!(
            parse_osc11(b"\x1b]11;rgb:ffff/ffff/ffff\x07"),
            Some(Background::Light)
        );
        // ST-terminated, two digits.
        assert_eq!(
            parse_osc11(b"\x1b]11;rgb:1e/1e/2e\x1b\\"),
            Some(Background::Dark)
        );
        // One digit per channel, which is a width a client that assumed four would read as
        // almost black whatever it said.
        assert_eq!(
            parse_osc11(b"\x1b]11;rgb:f/f/f\x07"),
            Some(Background::Light)
        );
        assert_eq!(
            parse_osc11(b"\x1b]11;rgb:0/0/0\x07"),
            Some(Background::Dark)
        );
        // Three digits, and mixed case.
        assert_eq!(
            parse_osc11(b"\x1b]11;RGB:FFF/FFF/FFF\x07"),
            Some(Background::Light)
        );
    }

    #[test]
    fn a_saturated_blue_background_is_a_dark_one() {
        // Arithmetically it is a third of the way up; perceptually it is nearly black, and
        // a light palette drawn on it would be unreadable.
        assert_eq!(
            parse_osc11(b"\x1b]11;rgb:0000/0000/ffff\x07"),
            Some(Background::Dark)
        );
    }

    #[test]
    fn anything_that_is_not_a_complete_reply_is_not_an_answer() {
        for bytes in [
            &b""[..],
            &b"\x1b]11;rgb:ffff/ffff/ffff"[..],
            &b"\x1b]10;rgb:ffff/ffff/ffff\x07"[..],
            &b"\x1b]11;#ffffff\x07"[..],
            &b"\x1b]11;rgb:ffff/ffff\x07"[..],
            &b"\x1b]11;rgb:ffff/ffff/ffff/ffff\x07"[..],
            &b"\x1b]11;rgb:zzzz/0/0\x07"[..],
            &b"\x1b]11;rgb:00000/0/0\x07"[..],
            &b"hello\x07"[..],
        ] {
            assert_eq!(
                parse_osc11(bytes),
                None,
                "{:?} was read as an answer",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn a_reply_is_found_among_bytes_that_arrived_around_it() {
        // A terminal may have echoed something first; the reply is still the reply.
        assert_eq!(
            parse_osc11(b"\x1b[?1u\x1b]11;rgb:ffff/ffff/ffff\x07"),
            Some(Background::Light)
        );
    }

    #[test]
    fn installing_a_palette_moves_the_generation_and_leaves_it_alone_otherwise() {
        // Restored on the way out, because every other test in this binary reads the
        // active palette and they run in one process.
        let before = current().palette;
        let started_at = generation();

        install(Palette::Light);
        assert_eq!(current().palette, Palette::Light);
        let moved = generation();
        assert!(moved > started_at, "a switch did not move the generation");

        // Installing the same palette twice is not a change, and a cache that missed on it
        // would re-render a screenful of prose for nothing.
        install(Palette::Light);
        assert_eq!(generation(), moved);

        install(before);
    }

    #[test]
    fn contrast_is_the_wcag_ratio() {
        let black = (0, 0, 0);
        let white = (255, 255, 255);

        assert!((contrast(white, black) - 21.0).abs() < 0.01);
        assert!((contrast(black, black) - 1.0).abs() < 0.01);
        // Symmetric, so a caller cannot get a different answer by swapping the arguments.
        assert!((contrast(white, black) - contrast(black, white)).abs() < 1e-9);
    }
}
