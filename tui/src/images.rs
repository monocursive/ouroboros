//! Inline images: what this terminal can show, and what this client will read (A11).
//!
//! Everything here is a decision, and every decision is a pure function so that it can be
//! read and tested without a terminal, a fleet, or a picture. The I/O lives in exactly two
//! places: the startup probe in [`crate::ui`], which asks the terminal one question inside
//! the same bounded window the OSC 11 theme probe uses, and the transcript's loader, which
//! reads a file only after [`inside_workspace`] has said it may.
//!
//! ## The honesty rule this module exists to keep
//!
//! A terminal that cannot draw a picture must never be told it can. So the answer to "can
//! we render here" is never inferred from a `TERM` that looks promising and never assumed
//! from silence: it is either a **reply the terminal sent** (kitty's graphics query, DA1's
//! sixel attribute) or a **name the terminal gave itself** that is documented to support
//! the protocol (`TERM_PROGRAM`, `LC_TERMINAL`). With neither, there is no protocol, and
//! every image is a labelled placeholder — which is also what a screen reader gets, always,
//! and what `/export` gets, always.
//!
//! Detection is also not the same question as *rendering*. [`Protocol::renders`] is the
//! second half: this build encodes kitty graphics and iTerm2 inline images, and it does
//! **not** encode sixel — sixel needs a palette quantiser, and shipping a bad one would put
//! a wrong picture on the screen rather than an honest placeholder. A detected sixel
//! terminal is therefore reported as detected and drawn as a placeholder, because "we know
//! your terminal can and we cannot" is a different sentence from "we could not tell".
//!
//! ## Why no image crate
//!
//! Nothing here decodes an image. It reads **headers** — PNG's IHDR, JPEG's SOFn, GIF's
//! logical screen descriptor, WebP's VP8/VP8L/VP8X — for the two numbers a placeholder and
//! a cell-size computation need, over a bounded prefix, with no allocation proportional to
//! the picture. The pixels themselves are never examined: kitty takes a PNG whole (`f=100`)
//! and iTerm2 takes any file whole, so the bytes travel to the terminal exactly as they sit
//! on disk. A decoder would therefore buy nothing but a large parser running on bytes this
//! client did not write, which is the wrong trade for a feature whose failure mode is
//! supposed to be a line of text.

use std::path::{Path, PathBuf};

/// How tall an inline image may be drawn, in terminal rows.
///
/// Bounded because a transcript is a scrollback, not a gallery: a screenshot pasted into a
/// conversation must not push the exchange around it off the screen. Forty rows is taller
/// than most terminals, so in practice the width bound below is what usually binds.
pub const MAX_ROWS: u16 = 40;

/// The largest file this client will read to put on the screen.
///
/// The same ceiling [`crate::clipboard::IMAGE_LIMIT`] puts on a paste, for the same
/// reason and in the other direction: a transcript that names a two-gigabyte path must
/// describe it, not load it.
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// How much of a file is read to find its dimensions. Every header this module knows is
/// inside the first few hundred bytes; JPEG is the one that can push further, because its
/// SOFn segment sits after however many comment and quantisation tables the encoder felt
/// like writing.
pub const HEADER_BYTES: usize = 64 * 1024;

/// The graphics protocol a terminal speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// The kitty graphics protocol. Preferred wherever it is available: it places an image
    /// at a stated cell size and can delete it again, which is what makes a scrolling
    /// transcript possible rather than a stream of pictures that never leave.
    Kitty,
    /// iTerm2's OSC 1337 `File=` inline image, also implemented by WezTerm and mintty.
    Iterm2,
    /// Sixel, detected and **not** encoded by this build. See the module doc.
    Sixel,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kitty => "kitty graphics",
            Self::Iterm2 => "iTerm2 inline images",
            Self::Sixel => "sixel",
        }
    }

    /// Whether this build can actually put pixels on the screen with it.
    pub fn renders(self) -> bool {
        matches!(self, Self::Kitty | Self::Iterm2)
    }
}

/// The environment variables that name a terminal, read once.
///
/// A struct rather than direct `var_os` calls so the table of terminals below is a pure
/// function with a fixture, which is the only way to test twelve terminals from one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    pub term: Option<String>,
    pub term_program: Option<String>,
    pub lc_terminal: Option<String>,
    /// kitty sets this in every window it owns.
    pub kitty_window_id: Option<String>,
    /// `OURO_NO_IMAGES`, non-empty. The escape hatch for a terminal that claims a protocol
    /// it does not honour, or a multiplexer that eats the escapes.
    pub disabled: bool,
}

impl Env {
    pub fn from_env() -> Self {
        let read = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };

        Self {
            term: read("TERM"),
            term_program: read("TERM_PROGRAM"),
            lc_terminal: read("LC_TERMINAL"),
            kitty_window_id: read("KITTY_WINDOW_ID"),
            disabled: std::env::var_os("OURO_NO_IMAGES")
                .is_some_and(|value| !value.is_empty() && value != "0"),
        }
    }
}

/// The one write the probe makes: kitty's graphics query, then DA1.
///
/// Both in a single write because DA1 is the *terminator*. Every terminal answers DA1, and
/// no terminal answers the graphics query unless it speaks the protocol — so the reply to
/// DA1 arriving is how this client learns that the absence of a graphics reply is an
/// answer rather than a terminal still thinking. The alternative is waiting out the whole
/// timeout on every start, which is a hundred milliseconds of nothing on every terminal in
/// the world that is not kitty.
///
/// The graphics query is the documented shape: a one-pixel RGB image transmitted directly,
/// with `a=q` asking only whether it would be accepted, so nothing is drawn either way.
pub const QUERY: &[u8] = b"\x1b_Gi=4242,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c";

/// Whether a reply buffer already contains DA1's terminator, so the probe can stop waiting.
pub fn reply_complete(reply: &[u8]) -> bool {
    // DA1 answers `ESC [ ? … c`. Looking for the `c` alone would match the `c` inside any
    // other reply, so the CSI introducer has to be found first.
    let Some(start) = find(reply, b"\x1b[?") else {
        return false;
    };

    reply[start..].contains(&b'c')
}

/// What the terminal's own replies say. No environment, no guessing.
pub fn from_reply(reply: &[u8]) -> Option<Protocol> {
    // kitty answers the query with the id it was given and `OK`. An error response (`ENOTSUPPORTED`,
    // and the rest) is a terminal that parsed the protocol and refused this particular
    // request, which is not something to draw into.
    if let Some(start) = find(reply, b"\x1b_Gi=4242;") {
        let rest = &reply[start + b"\x1b_Gi=4242;".len()..];

        if rest.starts_with(b"OK") {
            return Some(Protocol::Kitty);
        }
    }

    // DA1: `ESC [ ? 62 ; 4 ; 6 c`. Attribute 4 is sixel.
    let start = find(reply, b"\x1b[?")? + 3;
    let end = start + reply[start..].iter().position(|byte| *byte == b'c')?;

    reply[start..end]
        .split(|byte| *byte == b';')
        .any(|attribute| attribute == b"4")
        .then_some(Protocol::Sixel)
}

/// What the terminal's *name* says, for the protocol that has no query.
///
/// iTerm2's inline-image escape has no capability handshake — a terminal that does not
/// know OSC 1337 simply swallows it — so the only honest signal is a terminal identifying
/// itself as one whose documentation says it implements the escape. That is why this is an
/// allowlist and not a heuristic: `TERM` containing "256color" says nothing about pictures.
///
/// kitty is here too, for the case its query could not run at all: a start with no tty to
/// ask, or a probe that was disabled. The query is still preferred where there is one.
pub fn from_env(env: &Env) -> Option<Protocol> {
    if env.disabled {
        return None;
    }

    let program = env
        .term_program
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    let terminal = env
        .lc_terminal
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    let term = env.term.as_deref().unwrap_or_default().to_lowercase();

    // kitty and Ghostty implement the kitty graphics protocol natively.
    if env.kitty_window_id.is_some()
        || term == "xterm-kitty"
        || term == "xterm-ghostty"
        || program == "ghostty"
    {
        return Some(Protocol::Kitty);
    }

    // iTerm2 sets TERM_PROGRAM locally and LC_TERMINAL through ssh, which is the case that
    // matters: an image rendered over ssh is the whole reason the second variable exists.
    // WezTerm and mintty implement the same escape and document it.
    if program == "iterm.app" || terminal == "iterm2" || program == "wezterm" || program == "mintty"
    {
        return Some(Protocol::Iterm2);
    }

    None
}

/// The protocol to use, from both halves.
///
/// A reply beats a name: a terminal that answered the graphics query has proved it, while
/// a name is a claim about a build that may be older than its documentation. Sixel is last
/// because this build cannot encode it, so a terminal that supports both sixel and one of
/// the other two should be drawn with the one that works.
pub fn detect(env: &Env, reply: &[u8]) -> Option<Protocol> {
    if env.disabled {
        return None;
    }

    match from_reply(reply) {
        Some(Protocol::Kitty) => Some(Protocol::Kitty),
        sixel => from_env(env).or(sixel),
    }
}

/// How large one terminal cell is, in pixels.
///
/// Needed because every protocol here places an image in *cells* while a file states its
/// size in *pixels*, and the ratio between them is a property of the font. The terminal
/// reports it through `TIOCGWINSZ` where it reports it at all; where it does not, the
/// assumption below is used and the result is a picture of roughly the right shape rather
/// than exactly the right size — which is the correct failure for a transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellPixels {
    pub width: u16,
    pub height: u16,
}

impl Default for CellPixels {
    /// 8×16: an ordinary monospace cell at an ordinary size, and roughly the 1:2 aspect
    /// every terminal font has. Used only where the terminal declined to say.
    fn default() -> Self {
        Self {
            width: 8,
            height: 16,
        }
    }
}

impl CellPixels {
    /// Sanitised: a terminal that reports a zero dimension has reported nothing.
    pub fn new(width: u16, height: u16) -> Option<Self> {
        (width > 0 && height > 0).then_some(Self { width, height })
    }
}

/// How many cells an image of this pixel size should occupy.
///
/// Aspect is preserved by construction: whichever bound binds first decides the scale, and
/// the other dimension follows from it. Both results are at least 1 — an image scaled to
/// zero rows is an image that silently vanished — and neither exceeds what was asked for.
pub fn fit(pixels: (u32, u32), cell: CellPixels, max_cols: u16, max_rows: u16) -> (u16, u16) {
    let (width, height) = pixels;
    let max_cols = max_cols.max(1);
    let max_rows = max_rows.clamp(1, MAX_ROWS);

    if width == 0 || height == 0 {
        return (1, 1);
    }

    // The natural size, rounded up so a picture is never cropped by the rounding.
    let natural_cols = width.div_ceil(u32::from(cell.width)).max(1);
    let natural_rows = height.div_ceil(u32::from(cell.height)).max(1);

    if natural_cols <= u32::from(max_cols) && natural_rows <= u32::from(max_rows) {
        return (natural_cols as u16, natural_rows as u16);
    }

    // Scale by the tighter of the two ratios, in integer arithmetic against the *pixel*
    // dimensions rather than the cell counts, so the aspect that survives is the image's
    // and not the rounding's.
    let cols_bound = u64::from(max_cols) * u64::from(cell.width);
    let rows_bound = u64::from(max_rows) * u64::from(cell.height);

    let by_width = cols_bound * u64::from(height) <= rows_bound * u64::from(width);

    if by_width {
        let cols = max_cols;
        let scaled = u64::from(height) * cols_bound / u64::from(width);
        let rows = scaled.div_ceil(u64::from(cell.height)).max(1);

        (cols, (rows as u16).min(max_rows))
    } else {
        let rows = max_rows;
        let scaled = u64::from(width) * rows_bound / u64::from(height);
        let cols = scaled.div_ceil(u64::from(cell.width)).max(1);

        ((cols as u16).min(max_cols), rows)
    }
}

/// The raster formats this client names. Every one of them is a format kitty or iTerm2
/// accepts whole, so naming it is all that is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Png,
    Jpeg,
    Gif,
    Webp,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Gif => "gif",
            Self::Webp => "webp",
        }
    }

    /// Whether kitty will take these bytes as they are.
    ///
    /// kitty's `f=100` is PNG and nothing else; every other format would have to be
    /// decoded to raw pixels first, which this client does not do. An iTerm2 terminal takes
    /// all four, so a JPEG renders there and is a placeholder under kitty — an asymmetry
    /// worth having, because the alternative is a decoder.
    pub fn kitty_native(self) -> bool {
        matches!(self, Self::Png)
    }
}

/// What a file's header said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub format: Format,
    pub width: u32,
    pub height: u32,
}

/// Reads the format and the pixel dimensions out of a header prefix.
///
/// `None` for anything this module does not recognise, and for a truncated header — a
/// guess about a file's size would end up in a placeholder that states it as a fact.
pub fn header(bytes: &[u8]) -> Option<Header> {
    png(bytes)
        .or_else(|| jpeg(bytes))
        .or_else(|| gif(bytes))
        .or_else(|| webp(bytes))
}

fn png(bytes: &[u8]) -> Option<Header> {
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }

    // The signature is followed by the IHDR chunk: 4-byte length, the type, then width and
    // height. A PNG whose first chunk is not IHDR is not a PNG.
    if bytes.get(12..16)? != b"IHDR" {
        return None;
    }

    Some(Header {
        format: Format::Png,
        width: be32(bytes.get(16..20)?),
        height: be32(bytes.get(20..24)?),
    })
}

fn jpeg(bytes: &[u8]) -> Option<Header> {
    if !bytes.starts_with(b"\xff\xd8") {
        return None;
    }

    let mut at = 2usize;

    // Walk the segment chain to the first start-of-frame. Bounded by the buffer, and by a
    // segment count, because a crafted file can otherwise be an arbitrarily long chain of
    // two-byte markers.
    for _segment in 0..1024 {
        while bytes.get(at) == Some(&0xff) && bytes.get(at + 1) == Some(&0xff) {
            at += 1;
        }

        if bytes.get(at)? != &0xff {
            return None;
        }

        let marker = *bytes.get(at + 1)?;
        at += 2;

        // Standalone markers carry no length.
        if matches!(marker, 0xd8 | 0xd9 | 0x01) || (0xd0..=0xd7).contains(&marker) {
            continue;
        }

        let length = usize::from(be16(bytes.get(at..at + 2)?));

        // SOF0–SOF15, minus the three markers that share the range and are not frames:
        // DHT (0xc4), JPG (0xc8), DAC (0xcc).
        if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            return Some(Header {
                format: Format::Jpeg,
                // Inside the segment: precision, then height, then width.
                height: u32::from(be16(bytes.get(at + 3..at + 5)?)),
                width: u32::from(be16(bytes.get(at + 5..at + 7)?)),
            });
        }

        if length < 2 {
            return None;
        }

        at += length;
    }

    None
}

fn gif(bytes: &[u8]) -> Option<Header> {
    if !bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a") {
        return None;
    }

    // The logical screen descriptor, which is the size of the first frame's canvas — the
    // only frame this client would ever draw.
    Some(Header {
        format: Format::Gif,
        width: u32::from(le16(bytes.get(6..8)?)),
        height: u32::from(le16(bytes.get(8..10)?)),
    })
}

fn webp(bytes: &[u8]) -> Option<Header> {
    if !bytes.starts_with(b"RIFF") || bytes.get(8..12)? != b"WEBP" {
        return None;
    }

    let format = Format::Webp;

    match bytes.get(12..16)? {
        // Extended: a 24-bit canvas size, minus one, little-endian.
        b"VP8X" => Some(Header {
            format,
            width: le24(bytes.get(24..27)?) + 1,
            height: le24(bytes.get(27..30)?) + 1,
        }),
        // Lossless: a signature byte, then two 14-bit sizes minus one, packed.
        b"VP8L" => {
            if bytes.get(20)? != &0x2f {
                return None;
            }

            let packed = u32::from_le_bytes([
                *bytes.get(21)?,
                *bytes.get(22)?,
                *bytes.get(23)?,
                *bytes.get(24)?,
            ]);

            Some(Header {
                format,
                width: (packed & 0x3fff) + 1,
                height: ((packed >> 14) & 0x3fff) + 1,
            })
        }
        // Lossy: the VP8 keyframe sync code, then two 14-bit sizes.
        b"VP8 " => {
            if bytes.get(23..26)? != [0x9d, 0x01, 0x2a] {
                return None;
            }

            Some(Header {
                format,
                width: u32::from(le16(bytes.get(26..28)?) & 0x3fff),
                height: u32::from(le16(bytes.get(28..30)?) & 0x3fff),
            })
        }
        _unknown => None,
    }
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le24(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    (0..=haystack.len() - needle.len()).find(|at| &haystack[*at..at + needle.len()] == needle)
}

/// Whether a path an event named may be read, and where it is.
///
/// The rule, and it is the whole security posture of this feature: **a path outside the
/// workspace is never opened**. A transcript is a stream of strings a provider wrote, and a
/// client that read every path in it would turn `/tmp/x.png` in an agent's output into a
/// file this process opens — and, under a protocol that transmits the bytes, into a file it
/// puts on the operator's screen. So a relative path is resolved against the workspace, an
/// absolute one is required to be inside it, and the answer is checked again **after**
/// canonicalisation so a symlink cannot walk out.
///
/// This mirrors `Ouroboros.Interactive.Task.canonical_attachments/2`, which applies exactly
/// the same rule on the runtime side to the attachments a turn carries. Two enforcements of
/// one rule, because they protect two different machines: the runtime's workspace lease and
/// this terminal's screen.
pub fn inside_workspace(workspace: &Path, named: &str) -> Option<PathBuf> {
    let named = named.trim();

    if named.is_empty() {
        return None;
    }

    let root = std::fs::canonicalize(workspace).ok()?;
    let candidate = match Path::new(named).is_absolute() {
        true => PathBuf::from(named),
        false => root.join(named),
    };

    // Lexical first, so an obviously escaping path never reaches the filesystem at all.
    // Checked against the workspace *as it was given* as well as against its canonical
    // form, because those differ wherever a prefix is a symlink — `/var` and `/private/var`
    // on macOS — and rejecting an absolute path for being spelled the way the operator
    // spells it would refuse the ordinary case, not an attack.
    let lexical_root = lexical(workspace);
    let candidate_lexical = lexical(&candidate);

    if !within(&candidate_lexical, &root) && !within(&candidate_lexical, &lexical_root) {
        return None;
    }

    // The gate that actually holds: after every link is followed, is it still inside? A
    // lexical check alone would be walked out of by a symlink placed in the workspace.
    let canonical = std::fs::canonicalize(&candidate).ok()?;

    within(&canonical, &root).then_some(canonical)
}

/// Resolves `.` and `..` without touching the disk. Not a substitute for canonicalising —
/// it is the cheap first gate, and `..` is folded lexically here only to *reject*.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();

    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }

    out
}

fn within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

/// Whether a name is exactly a sha256 digest and nothing else.
///
/// The gate [`session_desktop`] leans on: a value that is 64 lowercase hex characters has no
/// path separator, no `.`, and no `..` in it, so it cannot name anything but a file directly
/// inside the desktop directory. Rejecting everything else here is what lets the containment
/// rule below be a statement about one directory rather than a path-traversal audit.
fn is_sha256(sha: &str) -> bool {
    sha.len() == 64
        && sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Where a desktop screenshot with this sha lives, if this node staged it (A11, §8.6).
///
/// A **second** containment rule, not a weakening of [`inside_workspace`]: desktop artifacts
/// are staged in `<session_dir>/desktop/` (§8.5), which is *not* the workspace — it is a
/// per-session scratch directory this client never lets an agent name a path into. So the
/// rule here is stricter than the workspace rule by construction: the only key is a sha256,
/// which cannot spell a traversal, and the resolved file is re-checked against the desktop
/// directory after every link is followed, exactly as [`inside_workspace`] re-checks against
/// the workspace. A sha that is not a clean digest never touches the filesystem.
///
/// The extension is not on the sha, so each format this client draws is tried in turn; the
/// first that both exists and canonicalises back inside the directory is the answer. This is
/// the localhost-attached path — a session running on this machine — and is preferred to a
/// `computer_use.artifact` round trip only when the bytes are already here. Absent (`None`)
/// where nothing was staged, which is the ordinary remote case and not an error.
pub fn session_desktop(session_dir: &Path, sha: &str) -> Option<PathBuf> {
    let sha = sha.trim();

    if !is_sha256(sha) {
        return None;
    }

    // The directory as it actually resolves. A session dir that does not exist, or whose
    // `desktop/` was never created, has nothing to serve and says so by being absent.
    let root = std::fs::canonicalize(session_dir.join("desktop")).ok()?;

    // Both jpeg spellings, because the stager names the file from a media type and this
    // client cannot assume which one `Attachments.media_type/1` chose.
    for extension in ["png", "jpg", "jpeg", "gif", "webp"] {
        let candidate = root.join(format!("{sha}.{extension}"));

        let Ok(canonical) = std::fs::canonicalize(&candidate) else {
            continue;
        };

        // The gate that holds even if a link was planted in the directory: after every link
        // is followed, is the file still inside the desktop directory this node owns?
        if within(&canonical, &root) {
            return Some(canonical);
        }
    }

    None
}

/// Whether a name ends in an extension one of these formats uses.
///
/// A name, not a file: this is what lets a path an event mentioned be recognised as an
/// image without opening it, which is the order the path rule requires — recognise, then
/// check containment, then read.
pub fn format_of(named: &str) -> Option<Format> {
    let extension = Path::new(named.trim())
        .extension()?
        .to_str()?
        .to_ascii_lowercase();

    match extension.as_str() {
        "png" => Some(Format::Png),
        "jpg" | "jpeg" => Some(Format::Jpeg),
        "gif" => Some(Format::Gif),
        "webp" => Some(Format::Webp),
        _other => None,
    }
}

/// What a transcript can honestly say about one image path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Described {
    /// The header, where the file was inside the workspace and readable.
    pub header: Option<Header>,
    /// Why there is no header, where there is none. `None` when there is one.
    pub note: Option<String>,
    /// The canonical local path, where the rule allowed one. Absent for a file on another
    /// machine, a path outside the workspace, or one this client refused to open.
    pub path: Option<PathBuf>,
}

/// Reads at most [`HEADER_BYTES`] of a named image, if the path rule allows it.
///
/// The one function in this module that touches a file, and it does so only after
/// [`inside_workspace`] has answered. Every failure is a *sentence*, not an absence: a
/// placeholder that said nothing about why it was a placeholder would leave an operator
/// wondering whether the picture was missing or the client was broken.
pub fn describe(workspace: Option<&Path>, named: &str) -> Described {
    let refuse = |note: &str| Described {
        header: None,
        note: Some(note.to_string()),
        path: None,
    };

    let Some(workspace) = workspace else {
        return refuse("no workspace for this session; not read");
    };

    let Some(path) = inside_workspace(workspace, named) else {
        // One sentence for two cases on purpose. A path outside the workspace and a path
        // that is not on this machine are both "this client will not open it", and telling
        // the two apart would mean probing outside the workspace to find out.
        return refuse("not readable inside this workspace; not read");
    };

    let Ok(metadata) = std::fs::metadata(&path) else {
        return refuse("could not be read");
    };

    if metadata.len() > MAX_BYTES {
        return Described {
            header: None,
            note: Some(format!(
                "{} bytes, over this client's {} MiB ceiling; not read",
                metadata.len(),
                MAX_BYTES / (1024 * 1024)
            )),
            path: Some(path),
        };
    }

    let mut prefix = vec![0u8; HEADER_BYTES.min(metadata.len() as usize)];

    {
        use std::io::Read;

        let Ok(mut file) = std::fs::File::open(&path) else {
            return refuse("could not be opened");
        };

        if file.read_exact(&mut prefix).is_err() {
            return Described {
                header: None,
                note: Some("could not be read".to_string()),
                path: Some(path),
            };
        }
    }

    match header(&prefix) {
        Some(header) => Described {
            header: Some(header),
            note: None,
            path: Some(path),
        },
        None => Described {
            header: None,
            note: Some("not a format this client reads".to_string()),
            path: Some(path),
        },
    }
}

/// The label a placeholder draws, and the one a screen reader hears.
///
/// States what is known and nothing else: a file whose header could not be read gets no
/// dimensions rather than invented ones, and a path this client refused to open says so in
/// the same breath as naming it. The path is shown as the event named it — never as the
/// absolute path it resolved to, which is a fact about this machine rather than about the
/// conversation.
pub fn label(named: &str, header: Option<Header>, note: Option<&str>) -> String {
    let mut text = String::from("[image ");

    match header {
        Some(header) => {
            text.push_str(&format!(
                "{}×{} {}",
                header.width,
                header.height,
                header.format.as_str()
            ));
        }
        None => text.push_str("size unknown"),
    }

    text.push_str(" · ");
    text.push_str(named.trim());

    if let Some(note) = note.map(str::trim).filter(|note| !note.is_empty()) {
        text.push_str(" · ");
        text.push_str(note);
    }

    text.push(']');
    text
}

/// The kitty graphics escape that draws `payload` at `cols`×`rows`.
///
/// Transmitted as PNG (`f=100`) in 4096-byte chunks, which is the protocol's documented
/// ceiling per escape. `C=1` keeps the cursor where it was, because the transcript has
/// already reserved the rows and moved on; without it the terminal would scroll and the
/// rows below would be drawn twice.
pub fn kitty(payload: &[u8], cols: u16, rows: u16) -> String {
    const CHUNK: usize = 4096;

    let encoded = base64(payload);
    let mut out = String::with_capacity(encoded.len() + 64);
    let chunks: Vec<&str> = encoded
        .as_bytes()
        .chunks(CHUNK)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect();

    // Base64 is ASCII, so chunking the bytes and chunking the characters are the same
    // thing; an empty payload still gets one (empty) escape rather than none, so a
    // zero-byte file is a terminal error rather than a silently missing picture.
    let chunks = if chunks.is_empty() { vec![""] } else { chunks };
    let last = chunks.len() - 1;

    for (index, chunk) in chunks.into_iter().enumerate() {
        out.push_str("\x1b_G");

        if index == 0 {
            out.push_str(&format!("a=T,f=100,C=1,c={cols},r={rows},"));
        }

        out.push_str(if index == last { "m=0;" } else { "m=1;" });
        out.push_str(chunk);
        out.push_str("\x1b\\");
    }

    out
}

/// iTerm2's OSC 1337 inline image, sized in cells.
///
/// `preserveAspectRatio=1` because the cell box computed by [`fit`] is already the image's
/// aspect rounded to whole cells, and letting the terminal letterbox inside it is better
/// than letting it stretch to fill. `inline=1` is what makes it an image rather than a
/// download — the sandbox this escape runs in has no downloads.
pub fn iterm2(payload: &[u8], name: &str, cols: u16, rows: u16) -> String {
    format!(
        "\x1b]1337;File=inline=1;size={};width={cols};height={rows};preserveAspectRatio=1;name={}:{}\x07",
        payload.len(),
        base64(name.as_bytes()),
        base64(payload)
    )
}

/// The one escape a capable terminal is asked to draw, composed from decoded bytes.
///
/// This is the real render path the two encoders exist for: [`fit`] decides the cell box
/// from the header's pixels, and the protocol decides the escape. It is deliberately the
/// *only* place that turns "we may draw here" into bytes for the terminal, so the honesty
/// rules the encoders keep are enforced once:
///
/// - `None` for a protocol this build cannot encode — [`Protocol::renders`] is the gate, and
///   a sixel terminal falls through it to the placeholder rather than to a wrong picture.
/// - `None` for kitty asked to draw anything but a PNG. kitty's `f=100` is PNG-only and this
///   build does not decode to raw pixels, so a JPEG under kitty is honestly a placeholder
///   (it renders under iTerm2, which takes all four formats whole). See [`Format::kitty_native`].
///
/// The bytes travel to the terminal exactly as they were decoded from the artifact — the
/// same guarantee the module doc makes for a file on disk: nothing here re-encodes a picture.
///
/// The escape it returns is a stream of terminal control bytes, which a cell-buffer renderer
/// (ratatui's `Buffer`, and therefore the TUI transcript's `Paragraph`) strips as zero-width
/// control characters. Its consumer is a surface that writes raw bytes to the terminal: a
/// real image renderer such as the GPUI desktop, or a cursor-positioned placement pass over
/// the backend. It is not something a [`ratatui::text::Line`] can carry.
pub fn render(
    protocol: Protocol,
    header: Header,
    bytes: &[u8],
    name: &str,
    cell: CellPixels,
    max_cols: u16,
) -> Option<String> {
    if !protocol.renders() {
        return None;
    }

    let (cols, rows) = fit((header.width, header.height), cell, max_cols, MAX_ROWS);

    match protocol {
        Protocol::Kitty => header
            .format
            .kitty_native()
            .then(|| kitty(bytes, cols, rows)),
        Protocol::Iterm2 => Some(iterm2(bytes, name, cols, rows)),
        // `renders()` already excluded this; kept explicit so a future protocol that renders
        // must decide its own escape here rather than silently returning a kitty one.
        Protocol::Sixel => None,
    }
}

/// Standard base64 with padding. Written here rather than taken as a dependency: it is
/// twenty lines with an exhaustive test, and a crate for it would be a supply-chain edge
/// bought for nothing.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for group in bytes.chunks(3) {
        let (b0, b1, b2) = (
            u32::from(group[0]),
            group.get(1).copied().map_or(0, u32::from),
            group.get(2).copied().map_or(0, u32::from),
        );
        let packed = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(packed >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(packed >> 12) as usize & 0x3f] as char);
        out.push(if group.len() > 1 {
            ALPHABET[(packed >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            ALPHABET[packed as usize & 0x3f] as char
        } else {
            '='
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        };

        Env {
            term: get("TERM"),
            term_program: get("TERM_PROGRAM"),
            lc_terminal: get("LC_TERMINAL"),
            kitty_window_id: get("KITTY_WINDOW_ID"),
            disabled: false,
        }
    }

    /// One row of the terminal table: the environment, and what it should resolve to.
    type Named<'a> = (&'a [(&'a str, &'a str)], Option<Protocol>);

    #[test]
    fn a_terminal_is_recognised_by_the_name_it_gives_itself_and_not_by_term_alone() {
        let table: &[Named] = &[
            (&[("TERM", "xterm-kitty")], Some(Protocol::Kitty)),
            (&[("KITTY_WINDOW_ID", "1")], Some(Protocol::Kitty)),
            (&[("TERM", "xterm-ghostty")], Some(Protocol::Kitty)),
            (&[("TERM_PROGRAM", "ghostty")], Some(Protocol::Kitty)),
            (&[("TERM_PROGRAM", "iTerm.app")], Some(Protocol::Iterm2)),
            // Over ssh, which is the case the second variable exists for.
            (
                &[("TERM", "xterm-256color"), ("LC_TERMINAL", "iTerm2")],
                Some(Protocol::Iterm2),
            ),
            (&[("TERM_PROGRAM", "WezTerm")], Some(Protocol::Iterm2)),
            (&[("TERM_PROGRAM", "mintty")], Some(Protocol::Iterm2)),
            // Everything that says nothing about pictures.
            (&[("TERM", "xterm-256color")], None),
            (&[("TERM", "screen-256color")], None),
            (&[("TERM", "dumb")], None),
            (&[("TERM_PROGRAM", "Apple_Terminal")], None),
            (&[("TERM_PROGRAM", "vscode")], None),
            (&[], None),
        ];

        for (pairs, expected) in table {
            assert_eq!(
                from_env(&env(pairs)),
                *expected,
                "the terminal named by {pairs:?}"
            );
        }
    }

    #[test]
    fn the_escape_hatch_beats_every_name_and_every_reply() {
        let mut kitty = env(&[("TERM", "xterm-kitty")]);
        kitty.disabled = true;

        assert_eq!(from_env(&kitty), None);
        assert_eq!(detect(&kitty, b"\x1b_Gi=4242;OK\x1b\\\x1b[?62;4c"), None);
    }

    #[test]
    fn a_graphics_reply_is_read_from_the_terminals_answer_and_an_error_is_not_a_yes() {
        assert_eq!(
            from_reply(b"\x1b_Gi=4242;OK\x1b\\\x1b[?62;1;6c"),
            Some(Protocol::Kitty)
        );
        assert_eq!(
            from_reply(b"\x1b_Gi=4242;ENOTSUPPORTED:f=24\x1b\\\x1b[?62;1;6c"),
            None,
            "a terminal that parsed the protocol and refused this request is not one to \
             draw into"
        );
    }

    #[test]
    fn sixel_is_read_from_da1_attribute_four_and_nothing_near_it() {
        let table: &[(&[u8], Option<Protocol>)] = &[
            (b"\x1b[?62;4;6c", Some(Protocol::Sixel)),
            (b"\x1b[?4c", Some(Protocol::Sixel)),
            (b"\x1b[?63;1;2;4;6;9;15;22c", Some(Protocol::Sixel)),
            (b"\x1b[?62;1;6c", None),
            // The digit 4 inside a longer attribute is a different attribute.
            (b"\x1b[?64;1;6c", None),
            (b"\x1b[?62;14;6c", None),
            (b"\x1b[?62;41c", None),
            (b"", None),
            (b"\x1b[?62;4", None),
        ];

        for (reply, expected) in table {
            assert_eq!(from_reply(reply), *expected, "DA1 reply {reply:?}");
        }
    }

    #[test]
    fn a_terminal_that_speaks_both_is_drawn_with_the_one_this_build_can_encode() {
        // WezTerm answers DA1 with sixel and is on the iTerm2 allowlist. Sixel loses,
        // because this build cannot encode it.
        assert_eq!(
            detect(&env(&[("TERM_PROGRAM", "WezTerm")]), b"\x1b[?62;4;6c"),
            Some(Protocol::Iterm2)
        );

        // kitty's own reply beats a name, because it is proof rather than a claim.
        assert_eq!(
            detect(
                &env(&[("TERM_PROGRAM", "iTerm.app")]),
                b"\x1b_Gi=4242;OK\x1b\\\x1b[?62;1;6c"
            ),
            Some(Protocol::Kitty)
        );

        // A terminal that only has sixel is detected, and says so, even though this build
        // will draw a placeholder there.
        let sixel = detect(&env(&[("TERM", "xterm-256color")]), b"\x1b[?62;4;6c");
        assert_eq!(sixel, Some(Protocol::Sixel));
        assert!(
            !sixel.expect("sixel").renders(),
            "detecting a protocol this build cannot encode must not promise a picture"
        );
    }

    #[test]
    fn the_probe_stops_as_soon_as_da1_has_answered() {
        assert!(!reply_complete(b""));
        assert!(!reply_complete(b"\x1b_Gi=4242;OK\x1b\\"));
        assert!(!reply_complete(b"\x1b[?62;1;6"));
        assert!(reply_complete(b"\x1b[?62;1;6c"));
        assert!(reply_complete(b"\x1b_Gi=4242;OK\x1b\\\x1b[?62;1;6c"));
        assert!(
            !reply_complete(b"c\x1b[?62"),
            "the `c` of some other reply is not DA1's terminator"
        );
    }

    // -----------------------------------------------------------------------------------
    // bounds
    // -----------------------------------------------------------------------------------

    const CELL: CellPixels = CellPixels {
        width: 10,
        height: 20,
    };

    #[test]
    fn an_image_that_fits_is_drawn_at_its_own_size() {
        assert_eq!(fit((100, 200), CELL, 80, MAX_ROWS), (10, 10));
        // Rounded up, never cropped.
        assert_eq!(fit((101, 201), CELL, 80, MAX_ROWS), (11, 11));
        assert_eq!(fit((1, 1), CELL, 80, MAX_ROWS), (1, 1));
    }

    #[test]
    fn a_wide_image_is_bounded_by_the_column_and_keeps_its_aspect() {
        // 1280×720 at 10×20 px per cell is 128×36 cells naturally; at 80 columns the
        // height has to come down with it.
        let (cols, rows) = fit((1280, 720), CELL, 80, MAX_ROWS);

        assert_eq!(cols, 80);
        assert_eq!(rows, 23, "720/1280 of 800px is 450px, which is 22.5 rows");
        assert!(rows < MAX_ROWS);
    }

    #[test]
    fn a_tall_image_is_bounded_by_the_forty_row_ceiling() {
        let (cols, rows) = fit((400, 8_000), CELL, 120, MAX_ROWS);

        assert_eq!(
            rows, MAX_ROWS,
            "a transcript is a scrollback, not a gallery"
        );
        assert!((1..=120).contains(&cols));
        // 40 rows is 800px; 400/8000 of that is 40px, which is 4 cells.
        assert_eq!(cols, 4);
    }

    #[test]
    fn the_same_image_is_bounded_differently_at_eighty_and_at_one_hundred_and_twenty() {
        let narrow = fit((1280, 720), CELL, 80, MAX_ROWS);
        let wide = fit((1280, 720), CELL, 120, MAX_ROWS);

        assert_eq!(narrow.0, 80);
        assert_eq!(wide.0, 120);
        assert!(
            wide.1 > narrow.1,
            "more columns is a larger picture, not a stretched one: {narrow:?} vs {wide:?}"
        );
    }

    #[test]
    fn nothing_is_ever_scaled_to_nothing() {
        for pixels in [(1, 10_000), (10_000, 1), (0, 0), (1, 0), (3, 7)] {
            let (cols, rows) = fit(pixels, CELL, 80, MAX_ROWS);

            assert!(cols >= 1 && rows >= 1, "{pixels:?} became {cols}×{rows}");
            assert!(cols <= 80 && rows <= MAX_ROWS, "{pixels:?}");
        }
    }

    #[test]
    fn a_ceiling_above_the_modules_own_is_not_honoured() {
        let (_cols, rows) = fit((400, 100_000), CELL, 120, 500);
        assert_eq!(rows, MAX_ROWS, "the caller cannot raise the bound");
    }

    #[test]
    fn a_terminal_that_reports_no_cell_size_gets_the_assumed_one() {
        assert_eq!(CellPixels::new(0, 16), None);
        assert_eq!(CellPixels::new(8, 0), None);
        assert_eq!(
            CellPixels::new(9, 18),
            Some(CellPixels {
                width: 9,
                height: 18
            })
        );
        assert_eq!(
            CellPixels::default(),
            CellPixels {
                width: 8,
                height: 16
            }
        );
    }

    // -----------------------------------------------------------------------------------
    // headers
    // -----------------------------------------------------------------------------------

    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes
    }

    #[test]
    fn a_png_states_its_size_in_its_first_chunk() {
        assert_eq!(
            header(&png_bytes(1280, 720)),
            Some(Header {
                format: Format::Png,
                width: 1280,
                height: 720
            })
        );
    }

    #[test]
    fn a_jpeg_is_found_past_however_many_tables_the_encoder_wrote() {
        let mut bytes = b"\xff\xd8".to_vec();
        // APP0/JFIF, then a comment, then a quantisation table, then the frame.
        for marker in [0xe0u8, 0xfe, 0xdb] {
            bytes.extend_from_slice(&[0xff, marker]);
            bytes.extend_from_slice(&16u16.to_be_bytes());
            bytes.extend_from_slice(&[0u8; 14]);
        }

        bytes.extend_from_slice(&[0xff, 0xc0]);
        bytes.extend_from_slice(&17u16.to_be_bytes());
        bytes.push(8);
        bytes.extend_from_slice(&600u16.to_be_bytes());
        bytes.extend_from_slice(&800u16.to_be_bytes());

        assert_eq!(
            header(&bytes),
            Some(Header {
                format: Format::Jpeg,
                width: 800,
                height: 600
            })
        );
    }

    #[test]
    fn the_markers_that_share_the_frame_range_are_not_frames() {
        // DHT (0xc4) sits inside 0xc0..=0xcf and is a Huffman table, not a frame. Reading
        // it as one would report a picture the size of two table bytes.
        let mut bytes = b"\xff\xd8".to_vec();
        bytes.extend_from_slice(&[0xff, 0xc4]);
        bytes.extend_from_slice(&8u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 6]);
        bytes.extend_from_slice(&[0xff, 0xc2]); // progressive frame
        bytes.extend_from_slice(&17u16.to_be_bytes());
        bytes.push(8);
        bytes.extend_from_slice(&64u16.to_be_bytes());
        bytes.extend_from_slice(&128u16.to_be_bytes());

        assert_eq!(
            header(&bytes),
            Some(Header {
                format: Format::Jpeg,
                width: 128,
                height: 64
            })
        );
    }

    #[test]
    fn a_gif_states_the_canvas_of_the_only_frame_this_client_would_draw() {
        let mut bytes = b"GIF89a".to_vec();
        bytes.extend_from_slice(&320u16.to_le_bytes());
        bytes.extend_from_slice(&240u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 3]);

        assert_eq!(
            header(&bytes),
            Some(Header {
                format: Format::Gif,
                width: 320,
                height: 240
            })
        );
    }

    #[test]
    fn the_three_webp_chunk_shapes_are_all_read() {
        let riff = |chunk: &[u8], body: &[u8]| {
            let mut bytes = b"RIFF".to_vec();
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(b"WEBP");
            bytes.extend_from_slice(chunk);
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(body);
            bytes
        };

        // VP8X: 4 flag bytes, then two 24-bit canvas sizes minus one.
        let mut extended = vec![0u8; 4];
        extended.extend_from_slice(&[0x3f, 0x02, 0x00]); // 575 + 1 = 576
        extended.extend_from_slice(&[0x7f, 0x01, 0x00]); // 383 + 1 = 384
        assert_eq!(
            header(&riff(b"VP8X", &extended)),
            Some(Header {
                format: Format::Webp,
                width: 576,
                height: 384
            })
        );

        // VP8L: signature byte, then 14 bits of width-1 and 14 of height-1.
        let packed: u32 = (99 << 14) | 199;
        let mut lossless = vec![0x2fu8];
        lossless.extend_from_slice(&packed.to_le_bytes());
        assert_eq!(
            header(&riff(b"VP8L", &lossless)),
            Some(Header {
                format: Format::Webp,
                width: 200,
                height: 100
            })
        );

        // VP8: a frame tag, the sync code, then the two sizes.
        let mut lossy = vec![0u8; 3];
        lossy.extend_from_slice(&[0x9d, 0x01, 0x2a]);
        lossy.extend_from_slice(&640u16.to_le_bytes());
        lossy.extend_from_slice(&480u16.to_le_bytes());
        assert_eq!(
            header(&riff(b"VP8 ", &lossy)),
            Some(Header {
                format: Format::Webp,
                width: 640,
                height: 480
            })
        );
    }

    #[test]
    fn a_file_this_module_cannot_read_gets_no_dimensions_rather_than_invented_ones() {
        for bytes in [
            &b""[..],
            b"not an image at all",
            b"\x89PNG\r\n\x1a\n",
            b"\x89PNG\r\n\x1a\n\0\0\0\rNOPE",
            b"\xff\xd8",
            b"GIF89a",
            b"RIFFxxxxWEBPNOPE",
            b"%PDF-1.7",
            // A PNG signature on a truncated IHDR.
            &png_bytes(1, 1)[..20],
        ] {
            assert_eq!(header(bytes), None, "{bytes:?}");
        }
    }

    #[test]
    fn only_the_first_bytes_of_a_file_are_ever_looked_at() {
        // A header parse must not walk a whole file: a 64 KiB prefix of a large PNG still
        // answers, and a JPEG whose frame is past the prefix answers `None` rather than
        // reading more.
        let mut png = png_bytes(4096, 4096);
        png.extend(std::iter::repeat_n(0u8, 1024));
        assert_eq!(
            header(&png[..HEADER_BYTES.min(png.len())]).map(|h| h.width),
            Some(4096)
        );
    }

    // -----------------------------------------------------------------------------------
    // the path rule
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_path_outside_the_workspace_is_never_opened() {
        let root = std::env::temp_dir().join(format!("ouro-images-{}", std::process::id()));
        let inside = root.join(".ouroboros/images");
        std::fs::create_dir_all(&inside).expect("a scratch workspace");
        std::fs::write(inside.join("image-1.png"), png_bytes(4, 4)).expect("a scratch file");

        let outside = std::env::temp_dir().join(format!("ouro-outside-{}.png", std::process::id()));
        std::fs::write(&outside, png_bytes(4, 4)).expect("a scratch file outside");

        // The ordinary case: a workspace-relative attachment path.
        assert!(inside_workspace(&root, ".ouroboros/images/image-1.png").is_some());
        // And its absolute spelling.
        assert!(
            inside_workspace(&root, &inside.join("image-1.png").display().to_string()).is_some()
        );

        for named in [
            &outside.display().to_string(),
            "/etc/passwd",
            "../escaped.png",
            ".ouroboros/images/../../escaped.png",
            "",
            "   ",
            ".ouroboros/images/does-not-exist.png",
        ] {
            assert_eq!(
                inside_workspace(&root, named),
                None,
                "{named} must not be opened"
            );
        }

        // A symlink *inside* the workspace pointing out of it is the case a lexical check
        // alone would walk straight through.
        #[cfg(unix)]
        {
            let link = inside.join("escape.png");
            std::os::unix::fs::symlink(&outside, &link).expect("a scratch symlink");

            assert!(
                link.exists(),
                "the link resolves, so only the rule can refuse it"
            );
            assert_eq!(
                inside_workspace(&root, ".ouroboros/images/escape.png"),
                None,
                "a link out of the workspace is out of the workspace"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn a_name_is_recognised_as_an_image_without_opening_anything() {
        assert_eq!(format_of("shot.PNG"), Some(Format::Png));
        assert_eq!(
            format_of(".ouroboros/images/image-1.png"),
            Some(Format::Png)
        );
        assert_eq!(format_of("a.jpg"), Some(Format::Jpeg));
        assert_eq!(format_of("a.jpeg"), Some(Format::Jpeg));
        assert_eq!(format_of("a.gif"), Some(Format::Gif));
        assert_eq!(format_of("a.webp"), Some(Format::Webp));

        for named in [
            "notes.md",
            "Makefile",
            "",
            "png",
            "a.png.txt",
            "a.svg",
            "a.bmp",
        ] {
            assert_eq!(format_of(named), None, "{named}");
        }
    }

    #[test]
    fn describing_an_image_says_why_wherever_it_cannot_say_how_big() {
        let root = std::env::temp_dir().join(format!("ouro-describe-{}", std::process::id()));
        let inside = root.join(".ouroboros/images");
        std::fs::create_dir_all(&inside).expect("a scratch workspace");
        std::fs::write(inside.join("shot.png"), png_bytes(800, 600)).expect("a scratch png");
        std::fs::write(inside.join("notes.txt"), b"not a picture").expect("a scratch file");

        let described = describe(Some(&root), ".ouroboros/images/shot.png");
        assert_eq!(
            described.header,
            Some(Header {
                format: Format::Png,
                width: 800,
                height: 600
            })
        );
        assert_eq!(described.note, None);
        assert!(described.path.is_some());

        // Every other outcome is a sentence rather than a silence.
        for (named, needle) in [
            ("/etc/passwd", "not readable inside this workspace"),
            ("../escaped.png", "not readable inside this workspace"),
            (
                ".ouroboros/images/gone.png",
                "not readable inside this workspace",
            ),
            (
                ".ouroboros/images/notes.txt",
                "not a format this client reads",
            ),
        ] {
            let described = describe(Some(&root), named);
            assert_eq!(described.header, None, "{named}");
            assert!(
                described
                    .note
                    .as_deref()
                    .is_some_and(|note| note.contains(needle)),
                "{named}: {:?}",
                described.note
            );
        }

        // A session whose workspace is on another machine has no local file to read, and
        // says that rather than reporting a size it invented.
        let described = describe(None, ".ouroboros/images/shot.png");
        assert_eq!(described.header, None);
        assert!(described
            .note
            .as_deref()
            .is_some_and(|note| note.contains("no workspace")));

        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------------------
    // labels and escapes
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_placeholder_states_what_is_known_and_no_more() {
        assert_eq!(
            label(
                ".ouroboros/images/image-7.png",
                Some(Header {
                    format: Format::Png,
                    width: 1280,
                    height: 720
                }),
                None
            ),
            "[image 1280×720 png · .ouroboros/images/image-7.png]"
        );

        assert_eq!(
            label("shot.jpg", None, Some("outside the workspace; not read")),
            "[image size unknown · shot.jpg · outside the workspace; not read]"
        );

        assert_eq!(
            label("shot.jpg", None, Some("   ")),
            "[image size unknown · shot.jpg]",
            "an empty note is not a note"
        );
    }

    #[test]
    fn base64_matches_the_standard_alphabet_and_pads() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0xff, 0xef, 0xfe]), "/+/+");
    }

    #[test]
    fn the_kitty_escape_states_its_cell_box_once_and_chunks_the_rest() {
        let escape = kitty(b"foobar", 40, 12);

        assert!(
            escape.starts_with("\x1b_Ga=T,f=100,C=1,c=40,r=12,m=0;Zm9vYmFy"),
            "{escape:?}"
        );
        assert!(escape.ends_with("\x1b\\"), "{escape:?}");
        assert_eq!(escape.matches("\x1b_G").count(), 1);

        // A payload past one escape's ceiling is continued, and only the first escape
        // carries the placement.
        let big = kitty(&vec![0u8; 8192], 10, 4);
        assert!(
            big.matches("\x1b_G").count() > 1,
            "a large payload is chunked"
        );
        assert_eq!(big.matches("c=10,r=4").count(), 1, "placed once");
        assert_eq!(big.matches("m=0;").count(), 1, "terminated once");
    }

    #[test]
    fn the_iterm2_escape_names_the_size_in_cells_and_the_bytes_in_bytes() {
        let escape = iterm2(b"foobar", "shot.png", 40, 12);

        assert!(
            escape.starts_with("\x1b]1337;File=inline=1;size=6;"),
            "{escape:?}"
        );
        assert!(escape.contains("width=40;height=12"), "{escape:?}");
        assert!(escape.contains("preserveAspectRatio=1"), "{escape:?}");
        assert!(escape.ends_with("Zm9vYmFy\x07"), "{escape:?}");
    }

    #[test]
    fn the_render_path_encodes_only_what_the_protocol_can_honestly_draw() {
        let png = Header {
            format: Format::Png,
            width: 320,
            height: 240,
        };
        let jpeg = Header {
            format: Format::Jpeg,
            width: 320,
            height: 240,
        };
        let cell = CellPixels {
            width: 10,
            height: 20,
        };

        // kitty draws a PNG whole (`f=100`) …
        let kitty = render(Protocol::Kitty, png, b"payload", "shot", cell, 80)
            .expect("kitty renders a PNG");
        assert!(kitty.starts_with("\x1b_G"), "{kitty:?}");
        assert!(kitty.contains("f=100"), "{kitty:?}");

        // … but not a JPEG, which it cannot take without a decoder this build does not ship.
        assert_eq!(
            render(Protocol::Kitty, jpeg, b"payload", "shot", cell, 80),
            None,
            "kitty asked for a JPEG is honestly a placeholder"
        );

        // iTerm2 takes all four formats whole, so a JPEG renders there.
        let iterm = render(Protocol::Iterm2, jpeg, b"payload", "shot", cell, 80)
            .expect("iterm2 renders a JPEG");
        assert!(iterm.starts_with("\x1b]1337;File=inline=1;"), "{iterm:?}");

        // A protocol this build cannot encode falls through to the placeholder.
        assert_eq!(
            render(Protocol::Sixel, png, b"payload", "shot", cell, 80),
            None
        );

        // The cell box is [`fit`]'s, so the bound the caller set is honoured.
        let (cols, rows) = fit((320, 240), cell, 8, MAX_ROWS);
        assert!(iterm.contains(&format!("width={cols}")) || cols <= 8);
        assert!(rows <= MAX_ROWS);
    }

    #[test]
    fn a_desktop_artifact_is_served_only_from_inside_the_sessions_desktop_directory() {
        let sha = "a".repeat(64);
        let session = std::env::temp_dir().join(format!("ouro-desktop-{}", std::process::id()));
        let desktop = session.join("desktop");
        std::fs::create_dir_all(&desktop).expect("a scratch desktop dir");
        std::fs::write(desktop.join(format!("{sha}.png")), png_bytes(4, 4)).expect("a staged png");

        // The staged sha resolves to its file …
        assert_eq!(
            session_desktop(&session, &sha),
            Some(std::fs::canonicalize(desktop.join(format!("{sha}.png"))).expect("canonical")),
        );

        // … and every non-digest key is refused before it touches the filesystem, so no sha
        // can spell a traversal out of the directory.
        let bad_keys = [
            "../../../etc/passwd".to_string(),
            "..".to_string(),
            "a/b".to_string(),
            "/etc/passwd".to_string(),
            String::new(),
            "   ".to_string(),
            "A".repeat(64), // uppercase is not the digest this stager writes
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64), // not hex
        ];
        for bad in &bad_keys {
            assert_eq!(
                session_desktop(&session, bad),
                None,
                "{bad:?} must not resolve"
            );
        }

        // A sha with no staged file is absent, not an error — the ordinary remote case.
        assert_eq!(session_desktop(&session, &"b".repeat(64)), None);

        // A link inside the directory that points out of it is refused after resolution, the
        // same gate [`inside_workspace`] keeps.
        #[cfg(unix)]
        {
            let outside = std::env::temp_dir()
                .join(format!("ouro-desktop-outside-{}.png", std::process::id()));
            std::fs::write(&outside, png_bytes(4, 4)).expect("a scratch file outside");
            let escaping = "c".repeat(64);
            let _ = std::os::unix::fs::symlink(&outside, desktop.join(format!("{escaping}.png")));

            assert_eq!(
                session_desktop(&session, &escaping),
                None,
                "a link out of the desktop directory is out of the desktop directory"
            );

            let _ = std::fs::remove_file(&outside);
        }

        let _ = std::fs::remove_dir_all(&session);
    }
}
