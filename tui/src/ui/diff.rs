//! Unified diffs: parsed once, rendered from the parse.
//!
//! ## Why a parse rather than a line filter
//!
//! The transcript used to colour a diff by looking at each line's first byte. That is
//! enough to tint `+` green and it is not enough for anything else a 2026 reader expects:
//! per-file grouping, line numbers, per-file `+N −M` that were *counted* rather than
//! quoted, word-level emphasis on the pair of lines that actually differ, and a post-turn
//! diffstat. All of those need to know where a file starts, what a hunk claims, and which
//! removed line pairs with which added one. So the text is parsed exactly once, into
//! [`ParsedDiff`], and every consumer — the transcript cell, the `/diff` overlay, the
//! diffstat — reads that.
//!
//! ## The counts are ours
//!
//! [`DiffFile::additions`] and [`DiffFile::deletions`] are counted from the hunk bodies in
//! this file. The provider's own claim (`Diff::additions`) is never propagated here,
//! because a provider that summarises a 400-line patch and sends a 40-line excerpt would
//! otherwise have this client repeat a number it cannot see. When the text this client
//! holds is an excerpt, [`ParsedDiff::truncated`] is set and every surface that shows a
//! count says **in excerpt** beside it.
//!
//! ## Colour
//!
//! Context lines are syntax-coloured through [`super::code`], keyed on the file's
//! extension. Added and removed lines are painted in the add/remove colour instead, with
//! the *changed words* undimmed and bold on top of a dimmed remainder — Claude Code's
//! `diffAddedWord`/`diffRemovedWord` idea. Letting the highlighter repaint a `+` line would
//! trade the one signal a diff exists to carry for a second copy of colouring the reader
//! already has on the context rows around it.
//!
//! ## Wrapping, not truncating
//!
//! A long line wraps at the pane width with a blank gutter on its continuation rows. A diff
//! is frequently the only copy of a change on screen; cutting it at the right margin hides
//! the half of an edit that a reviewer needs. What *is* bounded is how many rows a
//! collapsed cell spends, and that bound announces itself.

use std::ops::Range;

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::code::{self, Language};
use super::theme;
use super::transcript_cells::Cell;

/// How many files one parse keeps. A patch touching more than this is a repository
/// operation, not a change to read in a transcript.
const MAX_FILES: usize = 64;
/// How many body lines one parse keeps across all files. The source text is already capped
/// at 128 KiB by the transcript projection; this bounds the row count a pathological
/// single-column patch could still reach.
const MAX_LINES: usize = 20_000;
/// Row budget for a collapsed diff cell.
pub const COMPACT_LINES: usize = 12;
/// Row ceiling for one file laid out in the `/diff` pager. Larger than any transcript cell
/// spends and still bounded, because the pager lays a whole file out before windowing it.
pub const MAX_OVERLAY_ROWS: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    Added,
    Deleted,
    Renamed,
    Modified,
    Binary,
}

impl FileStatus {
    /// The one-letter mark git uses, so a reader who knows `git status` needs no legend.
    pub fn mark(self) -> &'static str {
        match self {
            Self::Added => "A",
            Self::Deleted => "D",
            Self::Renamed => "R",
            Self::Modified => "M",
            Self::Binary => "B",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Deleted => "deleted",
            Self::Renamed => "renamed",
            Self::Modified => "modified",
            Self::Binary => "binary",
        }
    }

    pub fn colour(self) -> ratatui::style::Color {
        match self {
            // The diff channel rather than the availability channel: the daltonized
            // palettes move exactly these two onto the blue/orange axis and leave "this
            // plane is up" where it was.
            Self::Added => theme::diff_added_colour(),
            Self::Deleted => theme::diff_removed_colour(),
            Self::Renamed => theme::accent(),
            Self::Modified => theme::warn(),
            Self::Binary => theme::muted(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Context,
    Added,
    Removed,
    /// `\ No newline at end of file`, and anything else git writes into a hunk body that is
    /// neither context nor a change. Kept rather than dropped: it is a fact about the file.
    Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: LineKind,
    pub old_no: Option<usize>,
    pub new_no: Option<usize>,
    /// The line's content with its `+`/`-`/space marker already removed.
    pub text: String,
    /// The byte range of `text` that differs from the line this one pairs with, when a
    /// removed line pairs 1:1 with an added one. Empty when nothing paired.
    pub emphasis: Option<Range<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub old_start: usize,
    pub new_start: usize,
    /// Whatever the provider wrote after the closing `@@` — usually the enclosing function.
    pub section: String,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffFile {
    pub path: String,
    /// Set only for a rename, where both halves matter.
    pub old_path: Option<String>,
    pub status: FileStatus,
    pub hunks: Vec<Hunk>,
    /// Counted from the hunk bodies above, never quoted from the provider.
    pub additions: usize,
    pub deletions: usize,
}

impl DiffFile {
    /// How many rows this file's body occupies before wrapping: one per hunk header plus
    /// one per body line.
    pub fn rows(&self) -> usize {
        self.hunks
            .iter()
            .map(|hunk| hunk.lines.len() + 1)
            .sum::<usize>()
    }

    fn language(&self) -> Language {
        code::detect_path(&self.path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedDiff {
    pub files: Vec<DiffFile>,
    /// The text this client holds was cut before it reached here, or this parse hit its own
    /// ceiling. Either way every count derived from it is a floor, and says so.
    pub truncated: bool,
}

impl ParsedDiff {
    pub fn additions(&self) -> usize {
        self.files.iter().map(|file| file.additions).sum()
    }

    pub fn deletions(&self) -> usize {
        self.files.iter().map(|file| file.deletions).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Parses unified-diff text. `fallback_path` names the file when the text carries no
/// `---`/`+++` header of its own, which is how a provider that sends bare hunks arrives.
pub fn parse(text: &str, fallback_path: Option<&str>) -> ParsedDiff {
    let mut parser = Parser {
        files: Vec::new(),
        current: None,
        truncated: false,
        rows: 0,
        refused: 0,
        refusing: false,
    };

    for raw in text.split('\n') {
        // CRLF: the carriage return belongs to the transport, not to the line.
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if parser.rows >= MAX_LINES {
            parser.truncated = true;
            break;
        }
        parser.line(line);
    }

    parser.flush();

    let mut files = parser.files;
    if files.len() > MAX_FILES {
        files.truncate(MAX_FILES);
        parser.truncated = true;
    }

    // Every `@@` line was written in a dialect this build cannot read, so the `---`/`+++`
    // pair above them is all that survived. Reporting a file with no hunks would draw a
    // header over an empty body; reporting nothing hands the text to the caller's
    // verbatim fallback, which shows the change as the provider wrote it.
    if parser.refused > 0 && files.iter().all(|file| file.hunks.is_empty()) {
        files.clear();
    }

    for file in &mut files {
        if file.path.is_empty() {
            file.path = fallback_path.unwrap_or("(path not reported)").to_string();
        }
        for hunk in &mut file.hunks {
            emphasise(&mut hunk.lines);
        }
    }

    ParsedDiff {
        files,
        truncated: parser.truncated,
    }
}

struct Parser {
    files: Vec<DiffFile>,
    current: Option<DiffFile>,
    truncated: bool,
    rows: usize,
    /// How many `@@` lines this parse could not read.
    refused: usize,
    /// Inside the body of a hunk whose header was refused. Its lines belong to no hunk
    /// this parse holds, and appending them to the one above would count another hunk's
    /// changes as that one's.
    refusing: bool,
}

impl Parser {
    fn flush(&mut self) {
        self.refusing = false;

        if let Some(file) = self.current.take() {
            // A `diff --git` pair with no hunks and no status is a mode change or an empty
            // rename; it is still a file the turn touched.
            self.files.push(file);
        }
    }

    fn file(&mut self) -> &mut DiffFile {
        self.current.get_or_insert_with(|| DiffFile {
            path: String::new(),
            old_path: None,
            status: FileStatus::Modified,
            hunks: Vec::new(),
            additions: 0,
            deletions: 0,
        })
    }

    fn line(&mut self, line: &str) {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            self.flush();
            let (old, new) = git_header_paths(rest);
            let file = self.file();
            file.path = new.clone().or_else(|| old.clone()).unwrap_or_default();
            if let (Some(old), Some(new)) = (&old, &new) {
                if old != new {
                    file.old_path = Some(old.clone());
                    file.status = FileStatus::Renamed;
                }
            }
            return;
        }

        if let Some(rest) = line.strip_prefix("--- ") {
            // A second `---` inside a file that already has a body is the next file in a
            // headerless multi-file patch.
            if self
                .current
                .as_ref()
                .is_some_and(|file| !file.hunks.is_empty())
            {
                self.flush();
            }
            let path = strip_prefix_path(rest);
            let file = self.file();
            if path.is_none() {
                file.status = FileStatus::Added;
            } else if file.old_path.is_none() && file.status != FileStatus::Renamed {
                file.old_path = path.clone();
            }
            if file.path.is_empty() {
                file.path = path.unwrap_or_default();
            }
            return;
        }

        if let Some(rest) = line.strip_prefix("+++ ") {
            let path = strip_prefix_path(rest);
            let file = self.file();
            match path {
                None => file.status = FileStatus::Deleted,
                Some(path) => {
                    if file.status != FileStatus::Renamed || file.path.is_empty() {
                        file.path = path;
                    }
                }
            }
            return;
        }

        if line.starts_with("@@") {
            match hunk_header(line) {
                Some(hunk) => {
                    self.refusing = false;
                    self.rows += 1;
                    self.file().hunks.push(hunk);
                }
                None => {
                    self.refusing = true;
                    self.refused += 1;
                }
            }
            return;
        }

        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            let file = self.file();
            file.status = FileStatus::Binary;
            if file.path.is_empty() {
                file.path = binary_path(line).unwrap_or_default();
            }
            return;
        }

        if line.starts_with("new file mode") {
            self.file().status = FileStatus::Added;
            return;
        }
        if line.starts_with("deleted file mode") {
            self.file().status = FileStatus::Deleted;
            return;
        }
        if let Some(rest) = line.strip_prefix("rename from ") {
            let file = self.file();
            file.status = FileStatus::Renamed;
            file.old_path = Some(rest.to_string());
            return;
        }
        if let Some(rest) = line.strip_prefix("rename to ") {
            let file = self.file();
            file.status = FileStatus::Renamed;
            file.path = rest.to_string();
            return;
        }

        // Only a line inside an open hunk is body. Everything else at this point — `index`,
        // mode lines, a commit message above the patch — is metadata this view ignores.
        if self.refusing {
            return;
        }

        let Some(file) = self.current.as_mut() else {
            return;
        };
        let Some(hunk) = file.hunks.last_mut() else {
            return;
        };

        let (kind, text) = match line.as_bytes().first() {
            Some(b'+') => (LineKind::Added, &line[1..]),
            Some(b'-') => (LineKind::Removed, &line[1..]),
            Some(b' ') => (LineKind::Context, &line[1..]),
            Some(b'\\') => (LineKind::Meta, line),
            // A stripped-blank context line. Tools that trim trailing whitespace emit these
            // constantly, and reading one as "end of hunk" loses the rest of the file.
            None => (LineKind::Context, line),
            _ => return,
        };

        let (old_no, new_no) = match kind {
            LineKind::Added => {
                file.additions += 1;
                (None, Some(next_no(hunk, false)))
            }
            LineKind::Removed => {
                file.deletions += 1;
                (Some(next_no(hunk, true)), None)
            }
            LineKind::Context => (Some(next_no(hunk, true)), Some(next_no(hunk, false))),
            LineKind::Meta => (None, None),
        };

        self.rows += 1;
        hunk.lines.push(DiffLine {
            kind,
            old_no,
            new_no,
            text: text.to_string(),
            emphasis: None,
        });
    }
}

/// The next old- or new-side number for a hunk, from its header plus what it already holds.
fn next_no(hunk: &Hunk, old_side: bool) -> usize {
    let used = hunk
        .lines
        .iter()
        .filter(|line| {
            if old_side {
                line.old_no.is_some()
            } else {
                line.new_no.is_some()
            }
        })
        .count();

    if old_side {
        hunk.old_start + used
    } else {
        hunk.new_start + used
    }
}

fn hunk_header(line: &str) -> Option<Hunk> {
    let rest = line.strip_prefix("@@")?;
    let close = rest.find("@@")?;
    let ranges = &rest[..close];
    let section = rest[close + 2..].trim().to_string();

    let mut old_start = 1;
    let mut new_start = 1;
    for token in ranges.split_whitespace() {
        // By character, not by byte: a provider that wrote the Unicode minus in
        // `@@ −1,4 +1,6 @@` would otherwise split this token inside a code point.
        let mut characters = token.chars();
        let sign = characters.next()?;
        let start = characters
            .as_str()
            .split(',')
            .next()
            .and_then(|number| number.parse::<usize>().ok())?;
        match sign {
            '-' => old_start = start,
            '+' => new_start = start,
            _ => return None,
        }
    }

    Some(Hunk {
        old_start,
        new_start,
        section,
        lines: Vec::new(),
    })
}

/// `a/lib/app.ex\t2026-08-22` → `lib/app.ex`; `/dev/null` → `None`.
fn strip_prefix_path(rest: &str) -> Option<String> {
    let path = rest.split('\t').next().unwrap_or(rest).trim_end();
    if path == "/dev/null" || path.is_empty() {
        return None;
    }

    Some(
        path.strip_prefix("a/")
            .or_else(|| path.strip_prefix("b/"))
            .unwrap_or(path)
            .to_string(),
    )
}

/// `a/lib/app.ex b/lib/app.ex` → both halves. A path containing a space is ambiguous in
/// this header, so the split is taken at the ` b/` git always writes.
fn git_header_paths(rest: &str) -> (Option<String>, Option<String>) {
    match rest.find(" b/") {
        Some(at) => (
            strip_prefix_path(&rest[..at]),
            strip_prefix_path(rest[at + 1..].trim_start()),
        ),
        None => {
            let mut parts = rest.split_whitespace();
            (
                parts.next().and_then(strip_prefix_path),
                parts.next().and_then(strip_prefix_path),
            )
        }
    }
}

fn binary_path(line: &str) -> Option<String> {
    let rest = line.strip_prefix("Binary files ")?;
    let at = rest.find(" and ")?;
    strip_prefix_path(&rest[..at])
}

/// Marks the middle of every removed/added pair that differs only in its middle.
///
/// Pairing is deliberately conservative: a run of removed lines pairs with the run of added
/// lines directly below it **only when the two runs are the same length**, which is when
/// index *i* on one side is genuinely the rewrite of index *i* on the other. Any other
/// shape (three lines becoming one, an insert with no matching delete) gets no emphasis
/// rather than emphasis pointing at the wrong words.
fn emphasise(lines: &mut [DiffLine]) {
    let mut at = 0;
    while at < lines.len() {
        if lines[at].kind != LineKind::Removed {
            at += 1;
            continue;
        }

        let removed_start = at;
        while at < lines.len() && lines[at].kind == LineKind::Removed {
            at += 1;
        }
        let added_start = at;
        while at < lines.len() && lines[at].kind == LineKind::Added {
            at += 1;
        }

        let removed = added_start - removed_start;
        let added = at - added_start;
        if removed == 0 || removed != added {
            continue;
        }

        for offset in 0..removed {
            let (old, new) = (removed_start + offset, added_start + offset);
            let (old_range, new_range) = word_ranges(&lines[old].text, &lines[new].text);
            lines[old].emphasis = old_range;
            lines[new].emphasis = new_range;
        }
    }
}

/// The byte ranges of the two lines that are not their shared prefix and suffix, tokenized
/// on word boundaries so an emphasis never lands mid-identifier.
///
/// `None` on both sides when the lines are identical, or when the difference spans the
/// whole line — emphasising every word says nothing the `+`/`-` colour did not already say.
fn word_ranges(old: &str, new: &str) -> (Option<Range<usize>>, Option<Range<usize>>) {
    if old == new {
        return (None, None);
    }

    let old_tokens = tokens(old);
    let new_tokens = tokens(new);

    let mut prefix = 0;
    while prefix < old_tokens.len()
        && prefix < new_tokens.len()
        && old[old_tokens[prefix].clone()] == new[new_tokens[prefix].clone()]
    {
        prefix += 1;
    }

    let mut suffix = 0;
    while suffix < old_tokens.len() - prefix
        && suffix < new_tokens.len() - prefix
        && old[old_tokens[old_tokens.len() - 1 - suffix].clone()]
            == new[new_tokens[new_tokens.len() - 1 - suffix].clone()]
    {
        suffix += 1;
    }

    if prefix == 0 && suffix == 0 {
        return (None, None);
    }

    (
        span(&old_tokens, prefix, suffix, old.len()),
        span(&new_tokens, prefix, suffix, new.len()),
    )
}

fn span(tokens: &[Range<usize>], prefix: usize, suffix: usize, len: usize) -> Option<Range<usize>> {
    let last = tokens.len().checked_sub(suffix)?;
    if prefix >= last {
        // Nothing left in the middle: this side only had the other's shared text, so the
        // insertion point is between two shared tokens and there is no run to underline.
        return None;
    }

    let start = tokens[prefix].start;
    let end = tokens[last - 1].end.min(len);
    (start < end).then_some(start..end)
}

/// A word is a run of identifier characters; every other character is its own token, so a
/// changed delimiter is as findable as a changed name.
fn tokens(text: &str) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut open: Option<usize> = None;

    for (at, character) in text.char_indices() {
        if character.is_alphanumeric() || character == '_' {
            open.get_or_insert(at);
            continue;
        }

        if let Some(start) = open.take() {
            spans.push(start..at);
        }
        spans.push(at..at + character.len_utf8());
    }

    if let Some(start) = open {
        spans.push(start..text.len());
    }

    spans
}

/// How a diff body is laid out for one pane.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub width: usize,
    /// The row ceiling for the whole body. Rows beyond it are announced, not dropped
    /// silently.
    pub max_rows: usize,
    /// Left indent applied to every row, so a transcript cell can sit inside the
    /// conversation's measure.
    pub indent: usize,
    /// Whether the two-column line-number gutter is drawn. Dropped automatically on a pane
    /// too narrow to hold it and the content both.
    pub gutter: bool,
}

impl Layout {
    pub fn new(width: usize, max_rows: usize) -> Self {
        Self {
            width,
            max_rows,
            indent: 0,
            gutter: width >= 48,
        }
    }

    pub fn indented(mut self, indent: usize) -> Self {
        self.indent = indent;
        self
    }
}

/// Renders one file's hunks. Returns how many rows were left undrawn, so the caller can
/// state where the rest lives in its own vocabulary.
pub fn render_file(lines: &mut Vec<Line<'static>>, file: &DiffFile, layout: Layout) -> usize {
    let language = file.language();
    let numbers = number_width(file);
    let gutter = if layout.gutter { numbers * 2 + 3 } else { 0 };
    let content_width = layout
        .width
        .saturating_sub(layout.indent + gutter + 2)
        .max(8);
    let mut drawn = 0;
    let mut remaining = 0;

    for hunk in &file.hunks {
        if drawn >= layout.max_rows {
            remaining += hunk.lines.len() + 1;
            continue;
        }

        drawn += 1;
        lines.push(row(
            layout,
            blank_gutter(gutter),
            vec![Span::styled(
                super::tree::truncate(&hunk_label(hunk), content_width + 1),
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::DIM),
            )],
        ));

        for line in &hunk.lines {
            if drawn >= layout.max_rows {
                remaining += 1;
                continue;
            }

            let wrapped = content_spans(line, language, content_width);
            let mut first = true;
            for spans in wrapped {
                if drawn >= layout.max_rows {
                    remaining += 1;
                    break;
                }
                drawn += 1;
                let gutter_spans = if first {
                    number_gutter(line, numbers, layout.gutter)
                } else {
                    blank_gutter(gutter)
                };
                let mut content = vec![Span::styled(
                    if first { sign(line.kind) } else { " " }.to_string(),
                    sign_style(line.kind),
                )];
                content.extend(spans);
                lines.push(row(layout, gutter_spans, content));
                first = false;
            }
        }
    }

    remaining
}

fn row(layout: Layout, gutter: Vec<Span<'static>>, content: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = Vec::with_capacity(gutter.len() + content.len() + 1);
    if layout.indent > 0 {
        spans.push(Span::raw(" ".repeat(layout.indent)));
    }
    spans.extend(gutter);
    spans.extend(content);
    Line::from(spans)
}

fn blank_gutter(width: usize) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }

    vec![Span::raw(" ".repeat(width))]
}

fn number_gutter(line: &DiffLine, numbers: usize, gutter: bool) -> Vec<Span<'static>> {
    if !gutter {
        return Vec::new();
    }

    let cell = |value: Option<usize>| match value {
        Some(number) => format!("{number:>numbers$}"),
        None => " ".repeat(numbers),
    };

    vec![Span::styled(
        format!("{} {} ", cell(line.old_no), cell(line.new_no)),
        theme::quiet(),
    )]
}

fn number_width(file: &DiffFile) -> usize {
    let highest = file
        .hunks
        .iter()
        .map(|hunk| hunk.old_start.max(hunk.new_start) + hunk.lines.len())
        .max()
        .unwrap_or(1);

    highest.to_string().len().clamp(3, 6)
}

pub fn hunk_label(hunk: &Hunk) -> String {
    let header = format!("@@ -{} +{} @@", hunk.old_start, hunk.new_start);
    if hunk.section.is_empty() {
        header
    } else {
        format!("{header} {}", hunk.section)
    }
}

fn sign(kind: LineKind) -> &'static str {
    match kind {
        LineKind::Added => "+",
        LineKind::Removed => "-",
        LineKind::Context => " ",
        LineKind::Meta => " ",
    }
}

fn sign_style(kind: LineKind) -> Style {
    match kind {
        LineKind::Added => theme::diff_added(),
        LineKind::Removed => theme::diff_removed(),
        _ => theme::quiet(),
    }
}

/// One body line's content, wrapped to `width`. Context is syntax-coloured; a change is
/// painted in its own colour with the differing words undimmed.
fn content_spans(line: &DiffLine, language: Language, width: usize) -> Vec<Vec<Span<'static>>> {
    let spans = match line.kind {
        LineKind::Context => code::highlight_source_line(&line.text, language),
        LineKind::Meta => vec![Span::styled(line.text.clone(), theme::quiet())],
        LineKind::Added | LineKind::Removed => {
            // The whole style, not the colour: without colour at all these two still have
            // to differ, and `theme` is the one place that knows how.
            let channel = if line.kind == LineKind::Added {
                theme::diff_added()
            } else {
                theme::diff_removed()
            };
            let base = channel.add_modifier(Modifier::DIM);
            let strong = channel.add_modifier(Modifier::BOLD);

            match &line.emphasis {
                Some(range) if range.end <= line.text.len() => {
                    let mut spans = Vec::with_capacity(3);
                    if range.start > 0 {
                        spans.push(Span::styled(line.text[..range.start].to_string(), base));
                    }
                    spans.push(Span::styled(line.text[range.clone()].to_string(), strong));
                    if range.end < line.text.len() {
                        spans.push(Span::styled(line.text[range.end..].to_string(), base));
                    }
                    spans
                }
                _ => vec![Span::styled(line.text.clone(), base)],
            }
        }
    };

    if spans.iter().all(|span| span.content.is_empty()) {
        return vec![vec![Span::raw(String::new())]];
    }

    let wrapped = code::wrap_spans(&spans, width.max(1));
    if wrapped.is_empty() {
        vec![vec![Span::raw(String::new())]]
    } else {
        wrapped
    }
}

/// `3 files · +120 −18`, the post-turn diffstat's one row.
pub fn diffstat(files: usize, additions: usize, deletions: usize, truncated: bool) -> String {
    format!(
        "{files} file{} · +{additions} −{deletions}{}",
        if files == 1 { "" } else { "s" },
        if truncated { " · in excerpt" } else { "" }
    )
}

// ---------------------------------------------------------------------------------------
// The `/diff` overlay: what this client holds, grouped the way the turn produced it.
// ---------------------------------------------------------------------------------------

/// One file a turn changed, with the parse behind it so the pager needs no second walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    pub file: DiffFile,
    /// The text this client holds for it was an excerpt.
    pub in_excerpt: bool,
}

/// The files one turn changed.
///
/// Turns are numbered from the *oldest turn this client still holds*, not from the start of
/// the session: the window prunes, and a number counted off a floor that moved would point
/// at a different turn every time history was dropped. The overlay's footer says the list
/// is partial whenever that floor is above zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnChanges {
    pub turn: usize,
    pub files: Vec<ChangedFile>,
}

impl TurnChanges {
    pub fn label(&self) -> String {
        format!("turn {}", self.turn)
    }

    pub fn additions(&self) -> usize {
        self.files.iter().map(|file| file.file.additions).sum()
    }

    pub fn deletions(&self) -> usize {
        self.files.iter().map(|file| file.file.deletions).sum()
    }

    pub fn in_excerpt(&self) -> bool {
        self.files.iter().any(|file| file.in_excerpt)
    }
}

/// Groups the diffs a projection produced by the turn that produced them.
///
/// Turns are counted by the turn-end dividers the projection already emits, so this needs
/// no second reading of the ledger and cannot disagree with the transcript about which turn
/// a change belongs to. A file changed twice in one turn keeps one row, with the counts
/// summed and the newest parse kept for the pager.
pub fn changes_by_turn(cells: &[Cell]) -> Vec<TurnChanges> {
    let mut turns: Vec<TurnChanges> = Vec::new();
    // The first block belongs to the turn the first divider ends, not to a turn before it.
    let mut turn = 1usize;
    let mut current: Vec<ChangedFile> = Vec::new();

    for cell in cells {
        match cell {
            Cell::Diff(diff) => {
                for file in &diff.parsed.files {
                    merge(&mut current, file, diff.parsed.truncated);
                }
            }
            Cell::Divider {
                kind: super::transcript_cells::DividerKind::TurnEnd,
                ..
            } => {
                if !current.is_empty() {
                    turns.push(TurnChanges {
                        turn,
                        files: std::mem::take(&mut current),
                    });
                }
                turn += 1;
            }
            _ => {}
        }
    }

    if !current.is_empty() {
        turns.push(TurnChanges {
            turn,
            files: current,
        });
    }

    turns
}

fn merge(into: &mut Vec<ChangedFile>, file: &DiffFile, in_excerpt: bool) {
    if let Some(existing) = into.iter_mut().find(|entry| entry.file.path == file.path) {
        existing.file.additions += file.additions;
        existing.file.deletions += file.deletions;
        existing.file.hunks = file.hunks.clone();
        existing.in_excerpt |= in_excerpt;
        return;
    }

    into.push(ChangedFile {
        file: file.clone(),
        in_excerpt,
    });
}

/// Claude Code's `/diff`, scoped to what a client that never reads the filesystem can hold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiffOverlay {
    /// 0 = this session; 1..=n selects [`DiffOverlay::turns`]`[n - 1]`.
    pub scope: usize,
    pub selected: usize,
    /// `Some(first visible row)` once Enter opened the selected file.
    pub pager: Option<usize>,
    pub turns: Vec<TurnChanges>,
    /// The sequence below which this client holds nothing. Non-zero means the list is a
    /// partial view of the session, and the footer says so rather than implying otherwise.
    pub pruned: u64,
}

impl DiffOverlay {
    pub fn new(cells: &[Cell], pruned: u64) -> Self {
        Self {
            scope: 0,
            selected: 0,
            pager: None,
            turns: changes_by_turn(cells),
            pruned,
        }
    }

    /// Every scope the `←`/`→` keys move between: "this session" plus one per turn.
    pub fn scopes(&self) -> usize {
        self.turns.len() + 1
    }

    pub fn scope_label(&self) -> String {
        match self.scope {
            0 => "this session".to_string(),
            index => self.turns[index - 1].label(),
        }
    }

    /// The rows the current scope lists. "This session" folds every turn together so a file
    /// touched by three turns is one row with the summed counts.
    pub fn rows(&self) -> Vec<ChangedFile> {
        match self.scope {
            0 => {
                let mut all: Vec<ChangedFile> = Vec::new();
                for turn in &self.turns {
                    for file in &turn.files {
                        merge(&mut all, &file.file, file.in_excerpt);
                    }
                }
                all
            }
            index => self
                .turns
                .get(index - 1)
                .map(|turn| turn.files.clone())
                .unwrap_or_default(),
        }
    }

    pub fn current(&self) -> Option<ChangedFile> {
        self.rows().into_iter().nth(self.selected)
    }

    /// Handles one key. `false` asks the caller to close the overlay.
    pub fn key(&mut self, code: crossterm::event::KeyCode, page: usize) -> bool {
        use crossterm::event::KeyCode;

        let rows = self.rows().len();

        match code {
            KeyCode::Esc => {
                if self.pager.take().is_some() {
                    return true;
                }
                return false;
            }
            KeyCode::Enter => {
                if self.pager.is_none() && rows > 0 {
                    self.pager = Some(0);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => match &mut self.pager {
                Some(offset) => *offset = offset.saturating_add(1),
                None => self.selected = (self.selected + 1).min(rows.saturating_sub(1)),
            },
            KeyCode::Up | KeyCode::Char('k') => match &mut self.pager {
                Some(offset) => *offset = offset.saturating_sub(1),
                None => self.selected = self.selected.saturating_sub(1),
            },
            KeyCode::PageDown | KeyCode::Char(' ') => {
                if let Some(offset) = &mut self.pager {
                    *offset = offset.saturating_add(page.max(1));
                }
            }
            KeyCode::PageUp => {
                if let Some(offset) = &mut self.pager {
                    *offset = offset.saturating_sub(page.max(1));
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.pager = None;
                self.scope = self.scope.saturating_sub(1);
                self.selected = 0;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.pager = None;
                self.scope = (self.scope + 1).min(self.scopes().saturating_sub(1));
                self.selected = 0;
            }
            _ => {}
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use unicode_width::UnicodeWidthStr;

    use super::*;

    fn plain(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    const MULTI: &str = "\
diff --git a/lib/one.ex b/lib/one.ex
index 111..222 100644
--- a/lib/one.ex
+++ b/lib/one.ex
@@ -1,3 +1,3 @@ defmodule One
 alpha
-beta
+BETA
 gamma
diff --git a/lib/two.ex b/lib/two.ex
--- a/lib/two.ex
+++ b/lib/two.ex
@@ -10,2 +10,3 @@
 keep
+added
 tail
";

    #[test]
    fn parses_a_multi_file_patch_into_files_hunks_and_counted_stats() {
        let parsed = parse(MULTI, None);

        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files[0].path, "lib/one.ex");
        assert_eq!(parsed.files[0].status, FileStatus::Modified);
        assert_eq!(
            (parsed.files[0].additions, parsed.files[0].deletions),
            (1, 1)
        );
        assert_eq!(parsed.files[1].path, "lib/two.ex");
        assert_eq!(
            (parsed.files[1].additions, parsed.files[1].deletions),
            (1, 0)
        );
        assert_eq!(parsed.additions(), 2);
        assert_eq!(parsed.deletions(), 1);
        assert!(!parsed.truncated);

        let hunk = &parsed.files[0].hunks[0];
        assert_eq!(hunk.section, "defmodule One");
        assert_eq!(
            hunk.lines.iter().map(|line| line.kind).collect::<Vec<_>>(),
            vec![
                LineKind::Context,
                LineKind::Removed,
                LineKind::Added,
                LineKind::Context
            ]
        );
        // Numbering runs from the header on both sides independently.
        assert_eq!(
            (hunk.lines[0].old_no, hunk.lines[0].new_no),
            (Some(1), Some(1))
        );
        assert_eq!(
            (hunk.lines[1].old_no, hunk.lines[1].new_no),
            (Some(2), None)
        );
        assert_eq!(
            (hunk.lines[2].old_no, hunk.lines[2].new_no),
            (None, Some(2))
        );
        assert_eq!(
            (hunk.lines[3].old_no, hunk.lines[3].new_no),
            (Some(3), Some(3))
        );

        assert_eq!(parsed.files[1].hunks[0].lines[1].new_no, Some(11));
    }

    #[test]
    fn reads_renames_new_files_deletions_and_binaries() {
        let parsed = parse(
            "\
diff --git a/old/name.rs b/new/name.rs
similarity index 92%
rename from old/name.rs
rename to new/name.rs
diff --git a/fresh.rs b/fresh.rs
new file mode 100644
--- /dev/null
+++ b/fresh.rs
@@ -0,0 +1,2 @@
+one
+two
diff --git a/gone.rs b/gone.rs
deleted file mode 100644
--- a/gone.rs
+++ /dev/null
@@ -1,1 +0,0 @@
-bye
diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
",
            None,
        );

        let by_path = |path: &str| {
            parsed
                .files
                .iter()
                .find(|file| file.path == path)
                .unwrap_or_else(|| panic!("{path} parsed"))
        };

        assert_eq!(by_path("new/name.rs").status, FileStatus::Renamed);
        assert_eq!(
            by_path("new/name.rs").old_path.as_deref(),
            Some("old/name.rs")
        );
        assert_eq!(by_path("fresh.rs").status, FileStatus::Added);
        assert_eq!(by_path("fresh.rs").additions, 2);
        assert_eq!(by_path("gone.rs").status, FileStatus::Deleted);
        assert_eq!(by_path("gone.rs").deletions, 1);
        assert_eq!(by_path("logo.png").status, FileStatus::Binary);
        assert!(by_path("logo.png").hunks.is_empty());
    }

    #[test]
    fn crlf_and_a_missing_trailing_newline_are_read_as_the_file_says() {
        let parsed = parse(
            "--- a/x.txt\r\n+++ b/x.txt\r\n@@ -1,1 +1,1 @@\r\n-old\r\n+new\r\n\\ No newline at end of file\r\n",
            None,
        );

        let hunk = &parsed.files[0].hunks[0];
        assert_eq!(hunk.lines[0].text, "old", "the CR belongs to the transport");
        assert_eq!(hunk.lines[1].text, "new");
        assert_eq!(hunk.lines[2].kind, LineKind::Meta);
        assert_eq!(hunk.lines[2].text, "\\ No newline at end of file");
        assert_eq!((parsed.additions(), parsed.deletions()), (1, 1));
    }

    #[test]
    fn a_headerless_hunk_takes_the_path_the_cell_already_knew() {
        let parsed = parse("@@ -1,1 +1,1 @@\n-a\n+b\n", Some("lib/known.ex"));

        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].path, "lib/known.ex");
    }

    #[test]
    fn intra_line_emphasis_marks_only_the_words_that_changed() {
        let parsed = parse(
            "--- a/a.rs\n+++ b/a.rs\n@@ -1,1 +1,1 @@\n-let total = alpha + beta;\n+let total = alpha + gamma;\n",
            None,
        );
        let lines = &parsed.files[0].hunks[0].lines;

        let removed = lines[0].emphasis.clone().expect("a paired removal");
        let added = lines[1].emphasis.clone().expect("a paired addition");
        assert_eq!(&lines[0].text[removed], "beta");
        assert_eq!(&lines[1].text[added], "gamma");
    }

    #[test]
    fn unequal_runs_get_no_emphasis_rather_than_a_wrong_one() {
        let parsed = parse(
            "--- a/a.rs\n+++ b/a.rs\n@@ -1,3 +1,1 @@\n-one\n-two\n+three\n",
            None,
        );
        let lines = &parsed.files[0].hunks[0].lines;

        assert!(lines.iter().all(|line| line.emphasis.is_none()));
    }

    #[test]
    fn a_wholly_rewritten_line_is_not_emphasised_word_by_word() {
        let parsed = parse(
            "--- a/a.rs\n+++ b/a.rs\n@@ -1,1 +1,1 @@\n-alpha\n+omega\n",
            None,
        );
        let lines = &parsed.files[0].hunks[0].lines;

        assert!(lines[0].emphasis.is_none());
        assert!(lines[1].emphasis.is_none());
    }

    #[test]
    fn renders_with_a_two_column_gutter_at_every_ordinary_width() {
        let parsed = parse(MULTI, None);

        for width in [60usize, 100, 160] {
            let mut lines = Vec::new();
            let remaining = render_file(
                &mut lines,
                &parsed.files[0],
                Layout::new(width, 64).indented(2),
            );
            let rendered = plain(&lines);

            assert_eq!(remaining, 0, "width {width} drew the whole file");
            assert_eq!(
                rendered,
                vec![
                    "           @@ -1 +1 @@ defmodule One",
                    "    1   1  alpha",
                    // Only the side a line exists on is numbered, which is what makes a
                    // removal and its replacement legible as one change.
                    "    2     -beta",
                    "        2 +BETA",
                    "    3   3  gamma",
                ],
                "width {width}"
            );
            assert!(
                rendered.iter().all(|row| row.width() <= width),
                "width {width} kept every row inside the pane: {rendered:?}"
            );
        }
    }

    #[test]
    fn a_narrow_pane_drops_the_gutter_instead_of_the_change() {
        let parsed = parse(MULTI, None);
        let mut lines = Vec::new();
        render_file(&mut lines, &parsed.files[0], Layout::new(30, 64));
        let rendered = plain(&lines);

        assert!(rendered.iter().any(|row| row.trim() == "-beta"));
        assert!(rendered.iter().all(|row| row.width() <= 30));
    }

    #[test]
    fn a_long_line_wraps_rather_than_losing_the_only_copy_of_the_change() {
        let long = "x".repeat(200);
        let parsed = parse(
            &format!("--- a/a.txt\n+++ b/a.txt\n@@ -1,1 +1,1 @@\n+{long}\n"),
            None,
        );

        let mut lines = Vec::new();
        let remaining = render_file(&mut lines, &parsed.files[0], Layout::new(60, 64));

        assert_eq!(remaining, 0);
        let joined = plain(&lines).join("");
        assert_eq!(
            joined.matches('x').count(),
            200,
            "every cell of the added line survived the wrap"
        );
    }

    #[test]
    fn the_row_budget_reports_what_it_did_not_draw() {
        let parsed = parse(MULTI, None);
        let mut lines = Vec::new();
        let remaining = render_file(&mut lines, &parsed.files[0], Layout::new(100, 3));

        assert_eq!(lines.len(), 3);
        assert_eq!(
            remaining, 2,
            "one hunk header plus four body rows, three drawn"
        );
    }

    #[test]
    fn the_parse_bounds_itself_and_says_so() {
        let mut text = String::from("--- a/big.txt\n+++ b/big.txt\n@@ -1,1 +1,60000 @@\n");
        for index in 0..(MAX_LINES + 10) {
            text.push_str(&format!("+line {index}\n"));
        }

        let parsed = parse(&text, None);
        assert!(parsed.truncated);
        assert!(parsed.additions() <= MAX_LINES);
    }

    /// A header whose signs are not ASCII `+`/`-` is written in a dialect this build does
    /// not read. It used to split the token at byte 1, which is inside the code point for
    /// every one of these.
    #[test]
    fn a_hunk_header_in_another_dialect_is_refused_rather_than_split_mid_character() {
        for header in ["@@ −1,4 +1,6 @@", "@@ ±1,4 ±1,6 @@", "@@ 🙂1,4 🙂1,6 @@"] {
            assert!(hunk_header(header).is_none(), "{header}");

            let parsed = parse(
                &format!("--- a/lib/one.ex\n+++ b/lib/one.ex\n{header}\n alpha\n-beta\n+BETA\n"),
                None,
            );

            // Nothing was read as a hunk, so the parse reports nothing and the cell falls
            // back to showing the provider's text as it was written.
            assert!(parsed.is_empty(), "{header}: {parsed:?}");
            assert_eq!((parsed.additions(), parsed.deletions()), (0, 0), "{header}");
        }
    }

    /// The refusal is per header, not per patch: a file whose hunks this build *can* read
    /// keeps them.
    #[test]
    fn a_readable_hunk_survives_an_unreadable_one_beside_it() {
        let parsed = parse(
            "\
--- a/lib/one.ex
+++ b/lib/one.ex
@@ -1,2 +1,2 @@
-beta
+BETA
@@ −9,1 +9,1 @@
-gamma
",
            None,
        );

        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].hunks.len(), 1);
        assert_eq!((parsed.additions(), parsed.deletions()), (1, 1));
    }

    #[test]
    fn the_diffstat_phrase_names_files_and_both_counts() {
        assert_eq!(diffstat(3, 120, 18, false), "3 files · +120 −18");
        assert_eq!(diffstat(1, 2, 0, true), "1 file · +2 −0 · in excerpt");
    }
}
