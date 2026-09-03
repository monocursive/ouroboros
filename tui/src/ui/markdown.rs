//! Agent prose as Markdown, rendered into styled terminal rows.
//!
//! Agents write Markdown. Until this module the transcript rendered it as the characters
//! that arrived — `**bold**` kept its asterisks, a table was a column of pipes, a list was
//! a column of hyphens — with one exception, the first pair of backticks on each wrapped
//! row. This turns the whole vocabulary into terminal styling: weight and colour for
//! headings, modifiers for emphasis, hanging indents for lists, a bar for quotes, real
//! columns for tables.
//!
//! Three rules shape the implementation.
//!
//! **The source is the copy of record.** Rendering is lossy on purpose: emphasis becomes a
//! modifier, a link becomes `text (url)`, a table becomes columns. `/raw` and
//! [`super::export`] therefore take the message's own text and never the rows below.
//! [`Rendered`] carries display rows and nothing else, and [`plain`] exists so a caller
//! that genuinely wants the *rendered* text does not have to scrape spans for it.
//!
//! **Nothing renders from text that has not finished arriving.** The cell re-renders on
//! every frame while deltas are still landing, so the tail of the text is, at any moment,
//! half of something. Goose's `MarkdownBuffer` rule applies: complete blocks render as
//! Markdown, and the fragment still being typed stays plain text. Concretely, while
//! `streaming` is true the message's final line is held out of the block parse until a
//! newline terminates it, and is drawn as the characters that arrived. A half-typed
//! `**bold`, an unfinished `[text](htt`, a lone `*` and a half-written table row therefore
//! read as themselves rather than as a construct guessed from them — and, more quietly,
//! `Hello\n--` does not promote `Hello` to a heading for the one frame before the third
//! hyphen lands. An unterminated fence is the one construct that keeps its shape while
//! open: [`super::code`] already renders it as a frame with no floor, and streaming code
//! with syntax highlighting beats streaming code as prose.
//!
//! **The work is bounded by what is drawn, not by what arrived.** Every row goes through
//! one budget check, so a three-megabyte message costs the rows the pane asked for rather
//! than the rows the text implies, and the pull parser stops being pulled once the budget
//! is spent.
//!
//! Links render as `text (url)`. There is no OSC 8 hyperlink: Ratatui has no cell
//! attribute for one, and an escape sequence smuggled into a `Span` would be measured as
//! printable cells by the wrapper, the buffer diff, and the scroll arithmetic alike. This
//! is the same call [`super::statusline`] already makes for the same reason.

use std::cell::{Cell, RefCell};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use pulldown_cmark::{Alignment, CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::code;
use super::theme;

/// Bullets by nesting depth, cycling. Each is one cell in this client's measure, which is
/// the measure the wrapper and the scroll offset also use.
const BULLETS: [char; 4] = ['•', '◦', '▪', '·'];

/// The narrowest a table column may become before the table stops being a table. Below
/// this every column is one broken word per row, which reads worse than the stacked
/// `Header: value` form Claude Code's screen-reader mode uses.
const MIN_TABLE_COLUMN: usize = 8;

/// How many rows one table cell may wrap to. A cell that needs more than this is a
/// paragraph in a table, and the table is the wrong shape for it.
const MAX_CELL_ROWS: usize = 24;

/// One rendered message: the rows to draw, and whether they are all of it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Rendered {
    pub lines: Vec<Line<'static>>,
    /// False when the row budget cut the message short. The caller owns the notice that
    /// says where the rest lives, because only the caller knows which view it is in.
    pub complete: bool,
}

/// Renders a whole agent message with no row budget.
///
/// The deterministic function the slice is specified in terms of: the same `text`, `width`
/// and `streaming` always produce the same rows. Callers drawing into a pane want
/// [`render_limited`] instead — this one will happily turn a megabyte into a megabyte.
pub fn render(text: &str, width: usize, streaming: bool) -> Rendered {
    render_limited(text, width, usize::MAX, streaming)
}

/// Renders a whole agent message, stopping after `max_lines` rows.
pub fn render_limited(text: &str, width: usize, max_lines: usize, streaming: bool) -> Rendered {
    let width = width.max(8);
    let segments = code::split_fences(text);
    let last = segments.len().saturating_sub(1);

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut complete = true;

    // A segment needs room for its own frame plus the caller's truncation notice; starting
    // one with less would overshoot the cap by more than it saves.
    for (index, segment) in segments.iter().enumerate() {
        if max_lines.saturating_sub(lines.len()) < 4 {
            complete = false;
            break;
        }

        if index > 0 {
            separate(&mut lines);
        }

        let remaining = max_lines.saturating_sub(lines.len());

        match segment {
            code::Segment::Prose(prose) => {
                // Only the message's last segment can still be growing.
                let live = streaming && index == last;
                let rendered = prose_rows(prose, width, remaining, live);
                complete &= rendered.complete;
                lines.extend(rendered.lines);
            }
            code::Segment::Code(block) => {
                // While the agent is still writing this block its frame has no floor yet,
                // so the caret can sit on the newest code row instead of a bottom border.
                let open_tail = streaming && index == last && !block.closed;
                code::render_block(&mut lines, block, width, remaining, open_tail);
            }
        }
    }

    Rendered { lines, complete }
}

/// The plain text of rendered rows, one row per line.
///
/// A projection of the *display*, not a copy of the source: the asterisks are gone, the
/// link's URL has moved into parentheses, and the table has become columns. Useful for
/// tests, for a screen-reader path, and for anything that wants the pane's own words —
/// never for `/raw`, which must hand back what the agent actually wrote.
pub fn plain(rendered: &Rendered) -> String {
    rendered
        .lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// How many rendered messages one thread keeps.
///
/// The conversation pane projects [`crate::ui::sessions::CHAT_ENTRY_WINDOW`] entries and
/// re-renders every one of them on every frame, so the memo has to be able to hold a whole
/// window's worth of prose or it evicts on the way round and hits nothing. Sixteen was a
/// screenful and measured a 0% hit rate at five thousand entries; this is the window, with
/// [`MEMO_BYTES`] still the real ceiling.
pub const MEMO_ENTRIES: usize = 192;

/// …and how much source text those entries may hold between them. A cap in bytes as well
/// as in entries, because the cost of remembering a message is the message.
pub const MEMO_BYTES: usize = 4 * 1024 * 1024;

/// What a memo is filed under. The rows are a function of exactly these five things.
///
/// `theme` is the palette generation: every span these rows carry was styled with the
/// palette that was active when they were built, so a `/theme` switch has to miss. It is a
/// counter rather than the palette itself because "which theme" is the theme module's
/// business and "did it change" is all this needs.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    hash: u64,
    width: usize,
    max_lines: usize,
    streaming: bool,
    theme: u64,
}

struct Memo {
    key: Key,
    /// Kept so a hit is confirmed against the text and not against a hash of it. A memo
    /// that answered a collision with the wrong message would be a transcript that lies.
    text: String,
    rendered: Rc<Rendered>,
}

thread_local! {
    static MEMOS: RefCell<Vec<Memo>> = const { RefCell::new(Vec::new()) };
    static COUNTS: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

/// What the memo has been asked for and what it managed to answer.
///
/// A cache with no hit rate is a cache nobody can tell is working: at five thousand
/// entries the previous ceiling of sixteen memos was evicting a whole conversation window
/// on every frame and answering *none* of them, and the only visible symptom was that
/// scrolling felt slow. `tests/perf.rs` asserts the rate; these are the numbers it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoStats {
    pub hits: u64,
    pub misses: u64,
    /// How many rendered messages are resident.
    pub entries: usize,
    /// How much source text they hold between them.
    pub bytes: usize,
}

impl MemoStats {
    /// Hits as a fraction of lookups, or `None` before anything has been asked.
    pub fn hit_rate(self) -> Option<f64> {
        let asked = self.hits + self.misses;
        (asked > 0).then(|| self.hits as f64 / asked as f64)
    }
}

pub fn memo_stats() -> MemoStats {
    let (hits, misses) = COUNTS.with(Cell::get);
    let (entries, bytes) = MEMOS.with(|memos| {
        let memos = memos.borrow();
        (
            memos.len(),
            memos.iter().map(|memo| memo.text.len()).sum::<usize>(),
        )
    });

    MemoStats {
        hits,
        misses,
        entries,
        bytes,
    }
}

/// Forgets the counters, so a measurement is of the frames it meant to measure.
pub fn reset_memo_stats() {
    COUNTS.with(|counts| counts.set((0, 0)));
}

/// Empties the memo. Only a test that is measuring a cold cache has any use for this.
pub fn clear_memo() {
    MEMOS.with(|memos| memos.borrow_mut().clear());
    reset_memo_stats();
}

/// [`render_limited`], remembered.
///
/// The transcript re-renders every visible cell on every frame, and the text of a settled
/// message never changes — so the parse, the fold and the table arithmetic behind one
/// agent turn are paid once per width rather than twelve times a second. A streaming
/// message misses on every delta, which is correct: its text really did change.
///
/// Bounded by [`MEMO_ENTRIES`] and [`MEMO_BYTES`], most-recently-used first, per thread.
pub fn render_cached(text: &str, width: usize, max_lines: usize, streaming: bool) -> Rc<Rendered> {
    let key = Key {
        hash: hash_of(text),
        width,
        max_lines,
        streaming,
        theme: theme::generation(),
    };

    let hit = MEMOS.with(|memos| {
        let mut memos = memos.borrow_mut();
        let found = memos
            .iter()
            .position(|memo| memo.key == key && memo.text == text)?;

        // Most recent first, so the turns actually on screen stay resident.
        let memo = memos.remove(found);
        let rendered = Rc::clone(&memo.rendered);
        memos.insert(0, memo);
        Some(rendered)
    });

    COUNTS.with(|counts| {
        let (hits, misses) = counts.get();
        match hit.is_some() {
            true => counts.set((hits + 1, misses)),
            false => counts.set((hits, misses + 1)),
        }
    });

    if let Some(rendered) = hit {
        return rendered;
    }

    let rendered = Rc::new(render_limited(text, width, max_lines, streaming));

    MEMOS.with(|memos| {
        let mut memos = memos.borrow_mut();
        memos.insert(
            0,
            Memo {
                key,
                text: text.to_string(),
                rendered: Rc::clone(&rendered),
            },
        );

        let mut bytes: usize = memos.iter().map(|memo| memo.text.len()).sum();
        while memos.len() > 1 && (memos.len() > MEMO_ENTRIES || bytes > MEMO_BYTES) {
            if let Some(dropped) = memos.pop() {
                bytes -= dropped.text.len();
            }
        }
    });

    rendered
}

fn hash_of(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// One prose segment: complete blocks as Markdown, plus the fragment still being typed.
fn prose_rows(prose: &str, width: usize, max_lines: usize, live: bool) -> Rendered {
    let (settled, tail) = match live {
        true => hold_out_tail(prose),
        false => (prose, ""),
    };

    let mut renderer = Renderer::new(width, max_lines);
    renderer.run(settled);
    let mut rendered = renderer.finish();

    if tail.is_empty() {
        return rendered;
    }

    // Where the fragment sits while it is being typed is where it lands. A blank line in
    // the source already announced a new block, so it gets its gap now rather than gaining
    // one — and shunting everything down a row — when the newline arrives. Without one it
    // is the next few words of the paragraph above, or the rest of that list item, and it
    // stays with the block it belongs to.
    match settled.ends_with("\n\n") {
        true if rendered.lines.len() < max_lines => separate(&mut rendered.lines),
        true => {}
        false => {
            while rendered.lines.last().is_some_and(|line| line.width() == 0) {
                rendered.lines.pop();
            }
        }
    }

    let budget = max_lines.saturating_sub(rendered.lines.len());
    // The spare row is how the folder reports that more text followed.
    let rows = fold(
        &[Span::raw(tail.to_string())],
        width,
        budget.saturating_add(1),
    );
    rendered.complete &= rows.len() <= budget;
    rendered
        .lines
        .extend(rows.into_iter().take(budget).map(Line::from));

    rendered
}

/// Splits a still-growing prose segment into the part that has finished arriving and the
/// line that has not.
///
/// A line is finished when a newline has terminated it. Everything up to and including the
/// last newline is complete Markdown input; whatever follows is the fragment the agent is
/// mid-word on, and it renders as the characters that arrived. A segment ending on a
/// newline holds nothing back, and a segment with no newline at all holds all of itself
/// back — which is right for the opening sentence of a reply, where nothing yet says what
/// block it will turn out to be.
fn hold_out_tail(prose: &str) -> (&str, &str) {
    match prose.rfind('\n') {
        Some(at) => prose.split_at(at + 1),
        None => ("", prose),
    }
}

/// A blank row between blocks, unless the last row is already blank.
fn separate(lines: &mut Vec<Line<'static>>) {
    if !lines.is_empty() && lines.last().map(Line::width) != Some(0) {
        lines.push(Line::from(""));
    }
}

/// One list's shape: where its markers sit, and how wide a marker may be.
struct ListFrame {
    /// Column the marker starts at, in cells.
    indent: usize,
    /// Cells reserved for `marker + space`. Every row of every item in this list — the
    /// wrapped continuations, the nested lists, the second paragraph — measures its indent
    /// from `indent + marker_cells`, which is what keeps depth 3 aligned with depth 2.
    marker_cells: usize,
    /// Next ordinal, or `None` for a bulleted list.
    number: Option<u64>,
    /// Which bullet this depth draws.
    bullet: char,
}

/// A marker waiting for the block that will carry it.
struct Marker {
    indent: usize,
    text: String,
}

/// A table under construction. Cells arrive one at a time and the widths cannot be chosen
/// until the last one has landed.
#[derive(Default)]
struct TableBuild {
    alignments: Vec<Alignment>,
    header: Vec<Vec<Span<'static>>>,
    rows: Vec<Vec<Vec<Span<'static>>>>,
    row: Vec<Vec<Span<'static>>>,
    in_head: bool,
}

/// A link under construction: where its text started, and where it points.
struct LinkBuild {
    dest: String,
    start: usize,
}

/// Walks the parser's events and lays them out.
struct Renderer {
    width: usize,
    max_lines: usize,
    lines: Vec<Line<'static>>,
    complete: bool,

    /// Inline content of the block currently being read.
    inline: Vec<Span<'static>>,
    /// Inline style stack: the block's base style at the bottom, one entry per open
    /// emphasis, link, or heading.
    styles: Vec<Style>,

    lists: Vec<ListFrame>,
    quote: usize,
    marker: Option<Marker>,

    table: Option<TableBuild>,
    link: Option<LinkBuild>,
    image: Option<usize>,
    code_block: Option<(Option<String>, String)>,
}

impl Renderer {
    fn new(width: usize, max_lines: usize) -> Self {
        Self {
            width,
            max_lines,
            lines: Vec::new(),
            complete: true,
            inline: Vec::new(),
            styles: vec![Style::default()],
            lists: Vec::new(),
            quote: 0,
            marker: None,
            table: None,
            link: None,
            image: None,
            code_block: None,
        }
    }

    fn finish(self) -> Rendered {
        Rendered {
            lines: self.lines,
            complete: self.complete,
        }
    }

    fn run(&mut self, text: &str) {
        let options =
            Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;

        for event in Parser::new_ext(text, options) {
            // The pull parser is pulled no further than the pane can draw. This is the
            // whole of the linearity argument: a message costs its rows, not its bytes.
            if self.lines.len() >= self.max_lines {
                self.complete = false;
                break;
            }

            self.event(event);
        }

        self.flush_inline();
    }

    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(text) => match &mut self.code_block {
                Some((_, body)) => body.push_str(&text),
                None => self.push_text(&text),
            },
            // The backticks stay. Inline code is verbatim content, and the delimiters are
            // what say where the verbatim region begins and ends — which matters when it
            // holds spaces at its edges, or reads like ordinary prose. Emphasis has no
            // such ambiguity, so its markers go.
            Event::Code(code) => {
                let style = self.style().patch(theme::markdown_code());
                self.inline.push(Span::styled(format!("`{code}`"), style));
            }
            // Passed through as the text it is. A terminal cannot render HTML, and
            // swallowing it would hide content the agent chose to send.
            Event::Html(html) | Event::InlineHtml(html) => self.push_text(&html),
            Event::SoftBreak => self.push_text(" "),
            Event::HardBreak => self.push_text("\n"),
            Event::Rule => self.rule(),
            Event::TaskListMarker(done) => {
                let mark = match done {
                    true => "[x] ",
                    false => "[ ] ",
                };
                self.inline
                    .push(Span::styled(mark, theme::markdown_task(done)));
            }
            Event::FootnoteReference(label) => self.push_text(&format!("[^{label}]")),
            Event::InlineMath(math) => self.push_text(&format!("${math}$")),
            Event::DisplayMath(math) => self.push_text(&format!("$${math}$$")),
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        // A tight list keeps its item text loose in the item, with no paragraph around it,
        // so the arrival of any block is what ends it. Without this, a nested list's first
        // item lands on the end of the sentence that introduced it.
        if matches!(
            tag,
            Tag::Paragraph
                | Tag::Heading { .. }
                | Tag::BlockQuote(_)
                | Tag::CodeBlock(_)
                | Tag::HtmlBlock
                | Tag::List(_)
                | Tag::Table(_)
        ) {
            self.close_inline();
        }

        match tag {
            Tag::Paragraph | Tag::HtmlBlock => self.gap(),
            Tag::Heading { level, .. } => {
                self.gap();
                self.styles.push(theme::markdown_heading(level as u8));
            }
            Tag::BlockQuote(_) => {
                self.gap();
                self.quote += 1;
            }
            Tag::CodeBlock(kind) => {
                self.gap();
                let info = match kind {
                    CodeBlockKind::Fenced(info) => info
                        .split_whitespace()
                        .next()
                        .filter(|word| !word.is_empty())
                        .map(str::to_ascii_lowercase),
                    CodeBlockKind::Indented => None,
                };
                self.code_block = Some((info, String::new()));
            }
            Tag::List(start) => {
                self.gap();
                let indent = self.content_indent();
                let marker_cells = match start {
                    Some(first) => digits(first) + 2,
                    None => 2,
                };
                let bullet = BULLETS[self.lists.len() % BULLETS.len()];

                self.lists.push(ListFrame {
                    indent,
                    marker_cells,
                    number: start,
                    bullet,
                });
            }
            Tag::Item => {
                let Some(frame) = self.lists.last() else {
                    return;
                };

                let text = match frame.number {
                    Some(number) => format!("{number}. "),
                    None => format!("{} ", frame.bullet),
                };
                let padding = frame
                    .marker_cells
                    .saturating_sub(UnicodeWidthStr::width(text.as_str()));

                self.marker = Some(Marker {
                    indent: frame.indent,
                    text: format!("{text}{}", " ".repeat(padding)),
                });
            }
            Tag::Table(alignments) => {
                self.gap();
                self.table = Some(TableBuild {
                    alignments,
                    ..TableBuild::default()
                });
            }
            Tag::TableHead => {
                if let Some(table) = &mut self.table {
                    table.in_head = true;
                }
            }
            Tag::Emphasis => self.push_style(Modifier::ITALIC),
            Tag::Strong => self.push_style(Modifier::BOLD),
            Tag::Strikethrough => self.push_style(Modifier::CROSSED_OUT),
            Tag::Link { dest_url, .. } => {
                self.link = Some(LinkBuild {
                    dest: dest_url.to_string(),
                    start: self.inline.len(),
                });
                let style = self.style().patch(theme::markdown_link());
                self.styles.push(style);
            }
            Tag::Image { .. } => self.image = Some(self.inline.len()),
            Tag::TableRow | Tag::TableCell | Tag::MetadataBlock(_) => {}
            Tag::FootnoteDefinition(_) | Tag::DefinitionList => {}
            Tag::DefinitionListTitle | Tag::DefinitionListDefinition => {}
            Tag::Superscript | Tag::Subscript => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph | TagEnd::Heading(_) => {
                self.flush_inline();
                if matches!(tag, TagEnd::Heading(_)) {
                    self.pop_style();
                }
            }
            TagEnd::BlockQuote(_) => self.quote = self.quote.saturating_sub(1),
            TagEnd::CodeBlock => {
                if let Some((info, body)) = self.code_block.take() {
                    self.code_block_rows(info.as_deref(), &body);
                }
            }
            TagEnd::List(_) => {
                self.lists.pop();
            }
            TagEnd::Item => {
                // A tight list puts its text straight inside the item, with no paragraph
                // around it, so the item is where that text is flushed.
                self.flush_inline();
                if let Some(frame) = self.lists.last_mut() {
                    frame.number = frame.number.map(|number| number.saturating_add(1));
                }
            }
            TagEnd::Table => {
                if let Some(table) = self.table.take() {
                    self.table_rows(table);
                }
            }
            TagEnd::TableHead => {
                if let Some(table) = &mut self.table {
                    table.in_head = false;
                    table.header = std::mem::take(&mut table.row);
                }
            }
            TagEnd::TableRow => {
                if let Some(table) = &mut self.table {
                    let row = std::mem::take(&mut table.row);
                    table.rows.push(row);
                }
            }
            TagEnd::TableCell => {
                let cell = std::mem::take(&mut self.inline);
                if let Some(table) = &mut self.table {
                    table.row.push(cell);
                }
            }
            TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough => self.pop_style(),
            TagEnd::Link => {
                self.pop_style();
                self.close_link();
            }
            TagEnd::Image => self.close_image(),
            TagEnd::HtmlBlock => self.close_inline(),
            TagEnd::MetadataBlock(_) => {}
            TagEnd::FootnoteDefinition | TagEnd::DefinitionList => {}
            TagEnd::DefinitionListTitle | TagEnd::DefinitionListDefinition => {}
            TagEnd::Superscript | TagEnd::Subscript => {}
        }
    }

    fn style(&self) -> Style {
        self.styles.last().copied().unwrap_or_default()
    }

    fn push_style(&mut self, modifier: Modifier) {
        let style = self.style().add_modifier(modifier);
        self.styles.push(style);
    }

    fn pop_style(&mut self) {
        if self.styles.len() > 1 {
            self.styles.pop();
        }
    }

    fn push_text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }

        let style = self.style();
        match self.inline.last_mut() {
            Some(span) if span.style == style => span.content.to_mut().push_str(text),
            _ => self.inline.push(Span::styled(text.to_string(), style)),
        }
    }

    /// `text (url)`, with the URL dropped when it would only repeat the text — which is
    /// what an autolink is, and what a bare URL in prose becomes.
    fn close_link(&mut self) {
        let Some(link) = self.link.take() else {
            return;
        };

        if link.dest.is_empty() {
            return;
        }

        let shown: String = self.inline[link.start.min(self.inline.len())..]
            .iter()
            .map(|span| span.content.as_ref())
            .collect();

        if shown.trim() == link.dest {
            return;
        }

        self.inline.push(Span::styled(
            format!(" ({})", link.dest),
            self.style().patch(theme::markdown_url()),
        ));
    }

    /// Images are alt text in brackets. A terminal that can draw one is a later slice; a
    /// terminal that cannot must still be told something was there.
    fn close_image(&mut self) {
        let Some(start) = self.image.take() else {
            return;
        };

        let start = start.min(self.inline.len());
        let alt: String = self.inline[start..]
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        self.inline.truncate(start);

        let alt = match alt.trim().is_empty() {
            true => "image".to_string(),
            false => alt.trim().to_string(),
        };
        let style = self.style().patch(theme::markdown_url());
        self.inline.push(Span::styled(format!("[{alt}]"), style));
    }

    /// The column an item's content — and any list nested inside it — starts at.
    fn content_indent(&self) -> usize {
        self.lists
            .last()
            .map(|frame| frame.indent + frame.marker_cells)
            .unwrap_or(0)
    }

    /// The bars for however many block quotes are open.
    fn quote_prefix(&self) -> Vec<Span<'static>> {
        (0..self.quote)
            .map(|_| Span::styled("│ ", theme::markdown_rule()))
            .collect()
    }

    /// A blank row before a new block, at the outermost level only. Inside a list the rows
    /// of one item, and the items of one list, stay together.
    fn gap(&mut self) {
        if !self.lists.is_empty() || self.lines.is_empty() {
            return;
        }

        if self.lines.last().map(Line::width) == Some(0) {
            return;
        }

        self.push_line(Line::from(""));
    }

    fn push_line(&mut self, line: Line<'static>) -> bool {
        if self.lines.len() >= self.max_lines {
            self.complete = false;
            return false;
        }

        self.lines.push(line);
        true
    }

    /// Ends the inline content a new block is interrupting — and only that. Unlike
    /// [`Self::flush_inline`] it never spends a pending marker, so the paragraph that a
    /// loose list item opens with still gets the bullet.
    fn close_inline(&mut self) {
        if !self.inline.is_empty() {
            self.flush_inline();
        }
    }

    /// Lays out whatever inline content has accumulated as one block.
    fn flush_inline(&mut self) {
        let spans = std::mem::take(&mut self.inline);
        if spans.is_empty() && self.marker.is_none() {
            return;
        }

        self.emit(spans);
    }

    /// One block of inline content, wrapped under its marker and its quote bars.
    fn emit(&mut self, spans: Vec<Span<'static>>) {
        let quote = self.quote_prefix();
        let quote_cells: usize = quote.iter().map(span_cells).sum();

        // An indent of nothing is no span at all: an empty span carries a style into the
        // row that the row's first word is then read through.
        let (first, hang) = match self.marker.take() {
            Some(marker) => {
                let hang = marker.indent + UnicodeWidthStr::width(marker.text.as_str());
                let mut first = indent_span(marker.indent);
                first.push(Span::styled(marker.text, theme::markdown_rule()));
                (first, hang)
            }
            None => {
                let indent = self.content_indent();
                (indent_span(indent), indent)
            }
        };

        let first_cells: usize = first.iter().map(span_cells).sum();
        let content = self
            .width
            .saturating_sub(quote_cells + first_cells.max(hang))
            .max(4);

        let budget = self.max_lines.saturating_sub(self.lines.len());
        // The spare row is how the folder reports that more content followed, so a block
        // that exactly fills the pane never earns a false truncation notice.
        let mut rows = fold(&spans, content, budget.saturating_add(1));

        // A block that ends on a line break — an HTML block, a hard break at the end of a
        // paragraph — folds to a trailing empty row. Between blocks that row is the gap's
        // job, and two of them read as a hole in the transcript.
        while rows.len() > 1 && rows.last().is_some_and(|row| row_cells(row) == 0) {
            rows.pop();
        }

        self.complete &= rows.len() <= budget;

        // An item whose text is empty still owns a row: the marker is the content.
        let rows = match rows.is_empty() {
            true => vec![Vec::new()],
            false => rows,
        };

        for (index, row) in rows.into_iter().take(budget).enumerate() {
            let mut line = quote.clone();
            match index {
                0 => line.extend(first.iter().cloned()),
                _ => line.extend(indent_span(hang)),
            }
            line.extend(row);

            if !self.push_line(Line::from(line)) {
                return;
            }
        }
    }

    fn rule(&mut self) {
        self.close_inline();
        self.gap();
        let quote = self.quote_prefix();
        let quote_cells: usize = quote.iter().map(span_cells).sum();
        let rule = self.width.saturating_sub(quote_cells).max(1);

        let mut line = quote;
        line.push(Span::styled("─".repeat(rule), theme::markdown_rule()));
        self.push_line(Line::from(line));
    }

    /// A fenced or indented block found inside the Markdown — a fence indented into a list
    /// item, say, which the top-level fence split leaves alone. Framed by the same code
    /// that frames a top-level block, then shifted under whatever indent it sits in.
    fn code_block_rows(&mut self, info: Option<&str>, body: &str) {
        let quote = self.quote_prefix();
        let quote_cells: usize = quote.iter().map(span_cells).sum();
        let indent = self.content_indent();
        let width = self.width.saturating_sub(quote_cells + indent).max(12);
        let budget = self.max_lines.saturating_sub(self.lines.len());

        let block = code::CodeBlock {
            lang: info,
            code: body,
            closed: true,
        };

        let mut framed = Vec::new();
        code::render_block(&mut framed, &block, width, budget, false);

        for row in framed {
            let mut line = quote.clone();
            if indent > 0 {
                line.push(Span::raw(" ".repeat(indent)));
            }
            line.extend(row.spans);

            if !self.push_line(Line::from(line)) {
                return;
            }
        }
    }

    /// A table, wrapped to whatever width is left — or, when even the minimum will not
    /// fit, the stacked `Header: value` form, which degrades instead of overflowing.
    fn table_rows(&mut self, table: TableBuild) {
        let quote = self.quote_prefix();
        let quote_cells: usize = quote.iter().map(span_cells).sum();
        let indent = self.content_indent();
        let available = self.width.saturating_sub(quote_cells + indent);

        let columns = table
            .alignments
            .len()
            .max(table.header.len())
            .max(table.rows.iter().map(Vec::len).max().unwrap_or(0));

        if columns == 0 {
            return;
        }

        // "│ a │ b │": one cell of padding either side of every column, plus the rules.
        let overhead = 3 * columns + 1;
        let budget = available.saturating_sub(overhead);

        if budget < columns * MIN_TABLE_COLUMN {
            self.stacked_table(table, columns);
            return;
        }

        let widths = column_widths(&table, columns, budget);
        self.framed_table(table, &widths, quote, indent);
    }

    fn framed_table(
        &mut self,
        table: TableBuild,
        widths: &[usize],
        quote: Vec<Span<'static>>,
        indent: usize,
    ) {
        let border = theme::markdown_rule();
        let pad = " ".repeat(indent);

        let rule = |left: &str, join: &str, right: &str| {
            let middle: Vec<String> = widths
                .iter()
                .map(|width| "─".repeat(width + 2))
                .collect::<Vec<_>>();
            format!("{left}{}{right}", middle.join(join))
        };

        let emit = |renderer: &mut Self, text: String| {
            let mut line = quote.clone();
            if indent > 0 {
                line.push(Span::raw(pad.clone()));
            }
            line.push(Span::styled(text, border));
            renderer.push_line(Line::from(line))
        };

        if !emit(self, rule("┌", "┬", "┐")) {
            return;
        }

        if !table.header.is_empty() {
            let header: Vec<Vec<Span<'static>>> = table
                .header
                .iter()
                .map(|cell| restyle(cell, theme::markdown_table_header()))
                .collect();

            if !self.table_row(&header, widths, &table.alignments, &quote, indent) {
                return;
            }
            if !emit(self, rule("├", "┼", "┤")) {
                return;
            }
        }

        for row in &table.rows {
            if !self.table_row(row, widths, &table.alignments, &quote, indent) {
                return;
            }
        }

        emit(self, rule("└", "┴", "┘"));
    }

    /// One table row, however many rows of wrapped text its tallest cell needs.
    fn table_row(
        &mut self,
        cells: &[Vec<Span<'static>>],
        widths: &[usize],
        alignments: &[Alignment],
        quote: &[Span<'static>],
        indent: usize,
    ) -> bool {
        let border = theme::markdown_rule();
        let wrapped: Vec<Vec<Vec<Span<'static>>>> = widths
            .iter()
            .enumerate()
            .map(|(column, width)| match cells.get(column) {
                Some(cell) => fold(cell, *width, MAX_CELL_ROWS),
                None => Vec::new(),
            })
            .collect();

        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);

        for row in 0..height {
            let mut line = quote.to_vec();
            if indent > 0 {
                line.push(Span::raw(" ".repeat(indent)));
            }

            for (column, width) in widths.iter().enumerate() {
                line.push(Span::styled("│ ", border));

                let empty = Vec::new();
                let content = wrapped
                    .get(column)
                    .and_then(|cell| cell.get(row))
                    .unwrap_or(&empty);
                let used: usize = content.iter().map(span_cells).sum();
                let slack = width.saturating_sub(used);
                let alignment = alignments.get(column).copied().unwrap_or(Alignment::None);

                let (before, after) = match alignment {
                    Alignment::Right => (slack, 0),
                    Alignment::Center => (slack / 2, slack - slack / 2),
                    _ => (0, slack),
                };

                if before > 0 {
                    line.push(Span::raw(" ".repeat(before)));
                }
                line.extend(content.iter().cloned());
                line.push(Span::raw(" ".repeat(after + 1)));
            }

            line.push(Span::styled("│", border));

            if !self.push_line(Line::from(line)) {
                return false;
            }
        }

        true
    }

    /// The degraded form: one `Header: value` block per cell, per row. Claude Code's
    /// screen-reader rendering, used here for the same reason — a table nobody can read a
    /// column of is not carrying its shape any more.
    fn stacked_table(&mut self, table: TableBuild, columns: usize) {
        for (index, row) in table.rows.iter().enumerate() {
            if index > 0 {
                self.gap();
            }

            for column in 0..columns {
                let label: String = table
                    .header
                    .get(column)
                    .map(|cell| {
                        cell.iter()
                            .map(|span| span.content.as_ref())
                            .collect::<String>()
                    })
                    .filter(|label| !label.trim().is_empty())
                    .unwrap_or_else(|| format!("column {}", column + 1));

                let mut spans = vec![Span::styled(
                    format!("{}: ", label.trim()),
                    theme::markdown_table_header(),
                )];
                if let Some(cell) = row.get(column) {
                    spans.extend(cell.iter().cloned());
                }

                self.emit(spans);

                if self.lines.len() >= self.max_lines {
                    return;
                }
            }
        }
    }
}

/// Column widths that fit `budget` cells, measured in cells rather than characters.
///
/// Every column keeps its natural width while the row fits. When it does not, the widest
/// columns give way first — a water level found by bisection rather than by shaving one
/// cell at a time, so a cell holding a megabyte costs a logarithm and not a megabyte —
/// and no column falls below [`MIN_TABLE_COLUMN`].
fn column_widths(table: &TableBuild, columns: usize, budget: usize) -> Vec<usize> {
    let mut natural = vec![0usize; columns];

    for row in std::iter::once(&table.header).chain(table.rows.iter()) {
        for (column, cell) in row.iter().enumerate().take(columns) {
            let cells: usize = cell.iter().map(span_cells).sum();
            natural[column] = natural[column].max(cells.min(budget));
        }
    }

    let total: usize = natural.iter().sum();
    if total <= budget {
        return natural;
    }

    let level = |cap: usize| -> usize {
        natural
            .iter()
            .map(|width| (*width).min(cap).max(MIN_TABLE_COLUMN))
            .sum()
    };

    let (mut low, mut high) = (MIN_TABLE_COLUMN, budget);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        match level(middle) <= budget {
            true => low = middle,
            false => high = middle - 1,
        }
    }

    let mut widths: Vec<usize> = natural
        .iter()
        .map(|width| (*width).min(low).max(MIN_TABLE_COLUMN))
        .collect();

    // Bisection lands on the largest uniform cap that fits; whatever is left over goes to
    // the columns that still want it, left to right.
    let mut slack = budget.saturating_sub(widths.iter().sum::<usize>());
    for column in 0..columns {
        if slack == 0 {
            break;
        }
        if widths[column] < natural[column] {
            widths[column] += 1;
            slack -= 1;
        }
    }

    widths
}

/// The same spans under a different base style, keeping whatever each span added.
fn restyle(spans: &[Span<'static>], style: Style) -> Vec<Span<'static>> {
    spans
        .iter()
        .map(|span| Span::styled(span.content.clone(), style.patch(span.style)))
        .collect()
}

fn span_cells(span: &Span<'static>) -> usize {
    UnicodeWidthStr::width(span.content.as_ref())
}

fn row_cells(row: &[Span<'static>]) -> usize {
    row.iter().map(span_cells).sum()
}

/// Leading blanks as a span, or nothing at all when there are none to draw.
fn indent_span(cells: usize) -> Vec<Span<'static>> {
    match cells {
        0 => Vec::new(),
        cells => vec![Span::raw(" ".repeat(cells))],
    }
}

fn digits(number: u64) -> usize {
    let mut digits = 1;
    let mut value = number;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// Word-wraps styled inline content to `width` cells, stopping after `max_rows`.
///
/// The break rules are the transcript's own — the ones
/// [`super::transcript_cells::wrap_limited`] applies to unstyled prose, down to the
/// treatment of runs of spaces and of a word wider than the whole pane — because the pane
/// and the export must fold the same paragraph the same way. What that function cannot do
/// is carry a style across the break, which is the whole point of rendering Markdown, and
/// what [`super::code::wrap_spans`] cannot do is break on a word, because code must break
/// exactly where it runs out of cells. Hence a third folder rather than a fourth measure:
/// cells come from `unicode-width` either way, so a CJK ideograph is two and a combining
/// mark is none here as well.
///
/// Callers ask for one row more than they can draw and read truncation off the count, the
/// way the rest of the transcript already does.
fn fold(spans: &[Span<'static>], width: usize, max_rows: usize) -> Vec<Vec<Span<'static>>> {
    let mut folder = Folder::new(width, max_rows);
    let complete = folder.feed(spans);
    folder.finish(complete)
}

struct Folder {
    width: usize,
    max_rows: usize,
    rows: Vec<Vec<Span<'static>>>,
    current: Vec<Span<'static>>,
    current_width: usize,
    word: Vec<Span<'static>>,
    word_width: usize,
    /// The style of the space that last ended a word, so a break inside underlined link
    /// text does not leave an un-underlined gap behind.
    separator: Style,
}

impl Folder {
    fn new(width: usize, max_rows: usize) -> Self {
        Self {
            width: width.max(1),
            max_rows,
            rows: Vec::new(),
            current: Vec::new(),
            current_width: 0,
            word: Vec::new(),
            word_width: 0,
            separator: Style::default(),
        }
    }

    fn feed(&mut self, spans: &[Span<'static>]) -> bool {
        if self.max_rows == 0 {
            return false;
        }

        for span in spans {
            for character in span.content.chars() {
                if !self.character(character, span.style) {
                    return false;
                }
            }
        }

        true
    }

    fn character(&mut self, character: char, style: Style) -> bool {
        match character {
            ' ' => {
                // The word that just ended is joined by the space *before* it, which is
                // the one recorded on the previous pass; this space belongs to the join
                // that has not happened yet.
                let placed = self.place();
                self.separator = style;
                placed
            }
            '\n' => {
                if !self.place() {
                    return false;
                }
                let row = std::mem::take(&mut self.current);
                self.current_width = 0;
                self.push_row(row)
            }
            character => {
                let cells = UnicodeWidthChar::width(character).unwrap_or(0);

                // Measured in terminal cells: a CJK ideograph and most emoji occupy two,
                // and a combining mark occupies none.
                if self.word_width > 0 && self.word_width + cells > self.width && !self.break_word()
                {
                    return false;
                }

                push_char(&mut self.word, character, style);
                self.word_width += cells;

                // One character wider than the whole pane. There is nowhere narrower to
                // put it, so it gets a row of its own — and emitting it here rather than
                // growing it is what keeps a multi-megabyte token costing `max_rows` of
                // work rather than the length of the token.
                if self.word_width > self.width {
                    return self.break_word();
                }

                true
            }
        }
    }

    /// Flushes the row under construction and the over-long word sitting after it.
    fn break_word(&mut self) -> bool {
        if !self.current.is_empty() {
            let row = std::mem::take(&mut self.current);
            self.current_width = 0;
            if !self.push_row(row) {
                return false;
            }
        }

        let word = std::mem::take(&mut self.word);
        self.word_width = 0;
        self.push_row(word)
    }

    /// Moves the finished word onto the row under construction, breaking first if it does
    /// not fit.
    fn place(&mut self) -> bool {
        if self.current.is_empty() {
            self.current = std::mem::take(&mut self.word);
            self.current_width = std::mem::take(&mut self.word_width);
            return true;
        }

        if self.current_width + 1 + self.word_width <= self.width {
            push_char(&mut self.current, ' ', self.separator);
            extend_merged(&mut self.current, std::mem::take(&mut self.word));
            self.current_width += 1 + std::mem::take(&mut self.word_width);
            return true;
        }

        let row = std::mem::take(&mut self.current);
        if !self.push_row(row) {
            return false;
        }

        self.current = std::mem::take(&mut self.word);
        self.current_width = std::mem::take(&mut self.word_width);
        true
    }

    fn push_row(&mut self, row: Vec<Span<'static>>) -> bool {
        if self.rows.len() >= self.max_rows {
            return false;
        }

        self.rows.push(row);
        self.rows.len() < self.max_rows
    }

    fn finish(mut self, complete: bool) -> Vec<Vec<Span<'static>>> {
        if !complete || !self.place() {
            return self.rows;
        }

        let row = std::mem::take(&mut self.current);
        self.push_row(row);
        self.rows
    }
}

/// Appends one character, extending the last span when the style has not changed.
fn push_char(buffer: &mut Vec<Span<'static>>, character: char, style: Style) {
    match buffer.last_mut() {
        Some(span) if span.style == style => span.content.to_mut().push(character),
        _ => buffer.push(Span::styled(character.to_string(), style)),
    }
}

/// Appends spans, welding the seam when the styles either side of it agree.
///
/// A run of one style must arrive as one span. Splitting `` `mix test` `` at its space
/// would leave two spans that each hold half of a thing that is one thing — and every
/// consumer downstream, from the buffer diff to a test asking what the inline code says,
/// reads spans rather than rows.
fn extend_merged(target: &mut Vec<Span<'static>>, source: Vec<Span<'static>>) {
    for span in source {
        match target.last_mut() {
            Some(last) if last.style == span.style => last.content.to_mut().push_str(&span.content),
            _ => target.push(span),
        }
    }
}

#[cfg(test)]
mod tests {
    use ratatui::style::Color;

    use super::*;

    /// Every construct in one document, so a change to one is visible against the rest.
    const SAMPLER: &str = "\
# Title

Some **bold** and *italic* and ~~struck~~ and `code()` in a sentence long enough to fold.

## Section

- first
- second
  - nested a
    - deeper
      - deepest
- third

1. one
2. two

- [ ] pending
- [x] finished

> a quoted claim
> continued on the next line

---

| Name | Count | Notes |
|---|---:|---|
| alpha | 1 | short |
| beta | 22 | a longer note that has to fold somewhere |

See [the docs](https://example.com/docs) and <https://example.com/bare>.

![a diagram](https://example.com/d.png)

<span>raw html</span>

Done.";

    fn rows(text: &str, width: usize) -> Vec<String> {
        plain(&render(text, width, false))
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn shown(text: &str, width: usize) -> String {
        plain(&render(text, width, false))
    }

    fn spans_of(text: &str, width: usize) -> Vec<Span<'static>> {
        render(text, width, false)
            .lines
            .into_iter()
            .flat_map(|line| line.spans)
            .collect()
    }

    fn find<'a>(spans: &'a [Span<'static>], needle: &str) -> &'a Span<'static> {
        spans
            .iter()
            .find(|span| span.content.contains(needle))
            .unwrap_or_else(|| panic!("no span holding {needle:?}"))
    }

    /// No rendered row may be wider than the pane it was rendered for. Eight cells is the
    /// floor the renderer clamps to, so a narrower request is measured against that.
    fn within(text: &str, width: usize) {
        let width = width.max(8);
        for line in render(text, width, false).lines {
            assert!(
                line.width() <= width,
                "row {:?} is {} cells in a pane of {width}",
                plain(&Rendered {
                    lines: vec![line.clone()],
                    complete: true
                }),
                line.width()
            );
        }
    }

    /// A message the size of the transcript's own per-message cap, in the shape agents
    /// actually write: headings, prose, lists, tables, fences.
    fn big_message() -> String {
        let mut text = String::new();
        let mut block = 0;

        while text.len() < 128 * 1024 {
            block += 1;
            text.push_str(&format!("## Section {block}\n\n"));
            text.push_str(
                "Some **bold** and `inline()` prose about the change, long enough that it \
                 folds across more than one row of any pane a person actually uses.\n\n",
            );
            text.push_str("- first item\n- second item\n  - nested item\n\n");
            text.push_str("| Name | Count |\n|---|---|\n| alpha | 1 |\n| beta | 2 |\n\n");
            text.push_str("```rust\nfn step() -> usize { 1 }\n```\n\n");
            text.push_str("> a quoted aside\n\n");
        }

        text
    }

    #[test]
    fn a_message_the_size_of_the_cap_renders_inside_a_frame() {
        let text = big_message();
        assert!(text.len() >= 128 * 1024, "{}", text.len());

        // Warm the code paths so the measurement is of rendering, not of first touch.
        let _ = render_limited(&text, 100, 16, false);

        let started = std::time::Instant::now();
        let rendered = render_limited(&text, 100, 256, false);
        let elapsed = started.elapsed();

        assert_eq!(rendered.lines.len(), 256);
        assert!(!rendered.complete);
        // The slice budget is 16 ms. Unoptimised, under the test harness, this measures
        // about 2 ms on the machine it was written on; the assert is ten frames wide
        // because CI shares its cores. A regression that matters blows past it anyway.
        assert!(
            elapsed < std::time::Duration::from_millis(160),
            "128 KiB took {elapsed:?}"
        );
    }

    #[test]
    fn the_cost_of_a_message_follows_the_rows_drawn_rather_than_the_bytes_arrived() {
        let small = big_message();
        let large = small.repeat(8);

        let time = |text: &str| {
            let started = std::time::Instant::now();
            let rendered = render_limited(text, 100, 256, false);
            assert_eq!(rendered.lines.len(), 256);
            started.elapsed()
        };

        let _ = time(&small);
        let _ = time(&large);

        // The fastest of several interleaved samples is the render's own cost; a single
        // sample is that plus whatever the scheduler did to the thread in between, and on
        // a shared runner that once read as the budget failing to bound the work.
        let fastest = |text: &str| (0..5).map(|_| time(text)).min().unwrap();
        let (mut small_time, mut large_time) = (fastest(&small), fastest(&large));
        small_time = small_time.min(fastest(&small));
        large_time = large_time.min(fastest(&large));

        // Eight times the input for the same 256 rows. Linear-in-input work would show up
        // as roughly eight times the time; the budget check means it does not.
        assert!(
            large_time < small_time * 4 + std::time::Duration::from_millis(8),
            "budget did not bound the work: {large_time:?} for 8x versus {small_time:?}"
        );
    }

    #[test]
    fn a_settled_message_is_rendered_once_per_width() {
        let text = "# Title\n\nA paragraph with `code` in it.\n";

        let first = render_cached(text, 80, 256, false);
        let again = render_cached(text, 80, 256, false);
        assert!(Rc::ptr_eq(&first, &again), "the same request re-rendered");

        // Every part of the key is part of the key.
        assert!(!Rc::ptr_eq(&first, &render_cached(text, 100, 256, false)));
        assert!(!Rc::ptr_eq(&first, &render_cached(text, 80, 32, false)));
        assert!(!Rc::ptr_eq(&first, &render_cached(text, 80, 256, true)));
        assert!(!Rc::ptr_eq(
            &first,
            &render_cached("# Other\n", 80, 256, false)
        ));

        // A hit answers with the same rows a fresh render would have produced.
        assert_eq!(*render_cached(text, 80, 256, false), *first);
        assert_eq!(*first, render_limited(text, 80, 256, false));
    }

    #[test]
    fn the_memo_is_bounded_and_keeps_what_is_on_screen() {
        let recent = "# Recent\n";
        let _ = render_cached(recent, 80, 256, false);

        for index in 0..(MEMO_ENTRIES * 2) {
            let _ = render_cached(&format!("# Filler {index}\n"), 80, 256, false);
            // Touching the newest turn is what a redraw does.
            let _ = render_cached(recent, 80, 256, false);
        }

        let (entries, bytes) = MEMOS.with(|memos| {
            let memos = memos.borrow();
            (
                memos.len(),
                memos.iter().map(|memo| memo.text.len()).sum::<usize>(),
            )
        });

        assert!(entries <= MEMO_ENTRIES, "{entries} memos");
        assert!(bytes <= MEMO_BYTES, "{bytes} bytes");

        let kept = render_cached(recent, 80, 256, false);
        assert!(Rc::ptr_eq(&kept, &render_cached(recent, 80, 256, false)));
    }

    #[test]
    fn one_oversized_message_cannot_hold_the_memo_open() {
        let huge = "word ".repeat(MEMO_BYTES / 4);
        assert!(huge.len() > MEMO_BYTES);

        let _ = render_cached(&huge, 80, 32, false);
        let _ = render_cached("# After\n", 80, 32, false);

        let bytes = MEMOS.with(|memos| {
            memos
                .borrow()
                .iter()
                .map(|memo| memo.text.len())
                .sum::<usize>()
        });

        assert!(bytes <= MEMO_BYTES, "{bytes} bytes still held");
    }

    /// Renders `text` cut at three points inside its last construct, the way a delta
    /// stream would deliver it, and hands each prefix to `check`.
    fn at_cut_points(text: &str, mut check: impl FnMut(&str, String)) {
        let bytes = text.len();
        let mut cuts: Vec<usize> = [bytes / 2, bytes * 3 / 4, bytes.saturating_sub(1)]
            .into_iter()
            .map(|cut| {
                let mut cut = cut.min(bytes);
                while cut > 0 && !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                cut
            })
            .collect();
        cuts.dedup();

        for cut in cuts {
            let prefix = &text[..cut];
            check(prefix, plain(&render(prefix, 40, true)));
        }
    }

    #[test]
    fn a_message_cut_anywhere_renders_without_a_stray_construct_marker() {
        // Every construct, cut mid-stream, must read as the characters that arrived —
        // never as a heading, a rule, a list or a table conjured from half of one.
        let constructs = [
            "Some **bold text** here",
            "Some *italic text* here",
            "Some ~~struck text~~ here",
            "Run `mix test --stale` now",
            "See [the docs](https://example.com/d) now",
            "An ![image alt](https://example.com/i.png) here",
            "Heading\n=======\n",
            "Heading\n-------\n",
            "# A heading line\n",
            "- one\n- two\n- three\n",
            "1. one\n2. two\n3. three\n",
            "- [ ] open\n- [x] shut\n",
            "> a quoted claim\n> and its second row\n",
            "before\n\n---\n\nafter\n",
            "| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n",
            "<div>some raw html</div>\n",
            "Look:\n```rust\nfn main() {}\n```\n",
        ];

        for construct in constructs {
            at_cut_points(construct, |prefix, shown| {
                assert!(
                    !shown.contains('\u{1b}'),
                    "escape from {prefix:?}: {shown:?}"
                );
                // A frame either has both its shoulders or is a fence still being written.
                let framed = shown.contains('┌');
                let floored = shown.contains('└');
                let fence = prefix.contains("```");
                assert!(
                    !floored || framed,
                    "a floor with no roof from {prefix:?}: {shown:?}"
                );
                assert!(
                    !framed || floored || fence,
                    "an open frame that is not a fence from {prefix:?}: {shown:?}"
                );
            });
        }
    }

    #[test]
    fn a_half_typed_inline_construct_reads_as_the_characters_that_arrived() {
        for (partial, expected) in [
            ("Some **bol", "Some **bol"),
            ("Some *ital", "Some *ital"),
            ("Some ~~stru", "Some ~~stru"),
            ("Run `mix te", "Run `mix te"),
            ("See [the docs](htt", "See [the docs](htt"),
            ("An ![alt](htt", "An ![alt](htt"),
            ("A lone * marker", "A lone * marker"),
        ] {
            assert_eq!(plain(&render(partial, 60, true)), expected, "{partial:?}");
        }
    }

    #[test]
    fn a_setext_underline_does_not_restyle_the_line_above_it_until_it_lands() {
        // The one construct that reaches backwards. Held out, it cannot.
        for partial in ["Hello\n-", "Hello\n--", "Hello\n=", "Hello\n=="] {
            assert_eq!(plain(&render(partial, 40, true)), partial, "{partial:?}");
        }

        // And once the newline arrives it is a heading, in the heading's own weight.
        let settled = render("Hello\n---\n", 40, false);
        assert_eq!(plain(&settled), "Hello");
        assert_eq!(
            find(&settled.lines[0].spans, "Hello").style,
            theme::markdown_heading(2)
        );
    }

    #[test]
    fn an_unfinished_table_row_never_lands_inside_the_frame() {
        let shown = plain(&render("| a | b |\n|---|---|\n| 1 | 2 |\n| 3 ", 40, true));
        let rows: Vec<&str> = shown.lines().collect();

        assert!(rows.iter().any(|row| row.starts_with('└')), "{shown}");
        assert_eq!(
            rows.last().copied(),
            Some("| 3 "),
            "the half row stays outside the frame: {shown}"
        );
    }

    #[test]
    fn where_the_fragment_sits_while_it_is_typed_is_where_it_lands() {
        // A blank line in the source has already announced a new block, so the fragment
        // gets its gap now. Gaining one when the newline arrives would shunt the row down
        // at every paragraph boundary of every reply — one row of flicker, endlessly.
        assert_eq!(
            plain(&render("A claim.\n\nA seco", 60, true)),
            "A claim.\n\nA seco"
        );
        assert_eq!(
            plain(&render("- one\n\nAfter th", 60, true)),
            "• one\n\nAfter th"
        );

        // Without one the fragment is the next words of the block above, and stays there.
        assert_eq!(
            plain(&render("A claim.\nAnd its se", 60, true)),
            "A claim.\nAnd its se"
        );
        assert_eq!(plain(&render("- one\n- tw", 60, true)), "• one\n- tw");

        // And in every case the rows above it are already in their settled places.
        for (partial, whole) in [
            ("A claim.\n\nA seco", "A claim.\n\nA second claim.\n"),
            ("- one\n\nAfter th", "- one\n\nAfter the list.\n"),
            ("- one\n- tw", "- one\n- two\n"),
            (
                "# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\nAnd th",
                "# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\nAnd then some prose.\n",
            ),
        ] {
            let streaming = plain(&render(partial, 60, true));
            let settled = plain(&render(whole, 60, false));

            let rows: Vec<&str> = streaming.lines().collect();
            let above = &rows[..rows.len() - 1];
            let landed: Vec<&str> = settled.lines().take(above.len()).collect();

            assert_eq!(
                above,
                landed.as_slice(),
                "{partial:?} moved when it settled"
            );
        }
    }

    #[test]
    fn a_list_still_being_typed_keeps_its_finished_items() {
        let shown = plain(&render("- one\n- two\n- thr", 40, true));

        assert_eq!(shown, "• one\n• two\n- thr");
    }

    #[test]
    fn an_open_fence_keeps_its_frame_and_its_highlighting() {
        let shown = plain(&render("Look:\n```rust\nfn main() {", 40, true));

        assert!(shown.contains("┌─ rust "), "{shown}");
        assert!(shown.contains("│ fn main() {"), "{shown}");
        assert!(!shown.contains('└'), "an open block has no floor: {shown}");
    }

    #[test]
    fn a_fence_opener_still_being_typed_is_not_yet_a_frame() {
        // `at_line_start` only sees a fence once the line it opens has ended, so a
        // language name mid-word must not open a frame it may never close.
        let shown = plain(&render("Look:\n```ru", 40, true));

        assert!(!shown.contains('┌'), "{shown}");
        assert!(shown.ends_with("```ru"), "{shown}");
    }

    #[test]
    fn the_settled_render_is_what_the_stream_converges_on() {
        // The last frame of a stream and the first frame after it must agree on the
        // blocks; only the still-typed line differs, and at the end there is none.
        let text = "# Title\n\n- one\n- two\n\n> quoted\n\n| a | b |\n|---|---|\n| 1 | 2 |\n";
        assert_eq!(
            plain(&render(text, 60, true)),
            plain(&render(text, 60, false))
        );
    }

    #[test]
    fn rendering_is_a_function_of_the_text_the_width_and_the_stream_state() {
        for streaming in [true, false] {
            for width in [60usize, 100, 160] {
                assert_eq!(
                    render(SAMPLER, width, streaming),
                    render(SAMPLER, width, streaming),
                    "{width}/{streaming}"
                );
            }
        }
    }

    #[test]
    fn the_sampler_renders_the_same_way_at_every_width_it_is_asked_for() {
        for width in [60usize, 100, 160] {
            within(SAMPLER, width);

            let text = shown(SAMPLER, width);

            // Headings keep their words and lose their hashes.
            assert!(text.contains("Title"), "{width}: {text}");
            assert!(!text.contains("# Title"), "{width}: {text}");
            // Emphasis is a modifier, so its markers are gone from the text.
            assert!(text.contains("bold"), "{width}: {text}");
            assert!(!text.contains("**bold**"), "{width}: {text}");
            assert!(!text.contains("~~struck~~"), "{width}: {text}");
            // Inline code keeps its delimiters: they say where the verbatim region is.
            assert!(text.contains("`code()`"), "{width}: {text}");
            // Lists, checkboxes, quotes, rules, tables, links, images, html.
            assert!(text.contains("• first"), "{width}: {text}");
            assert!(text.contains("1. one"), "{width}: {text}");
            assert!(text.contains("[x] finished"), "{width}: {text}");
            assert!(text.contains("│ a quoted claim"), "{width}: {text}");
            assert!(text.contains("────"), "{width}: {text}");
            assert!(text.contains("│ alpha"), "{width}: {text}");
            assert!(
                text.contains("the docs (https://example.com/docs)"),
                "{width}: {text}"
            );
            assert!(text.contains("[a diagram]"), "{width}: {text}");
            assert!(text.contains("<span>raw html</span>"), "{width}: {text}");
        }
    }

    #[test]
    fn headings_are_separated_by_weight_and_colour_rather_than_by_size() {
        let text = "# One\n\n## Two\n\n### Three\n\n#### Four\n\n##### Five\n";
        let spans = spans_of(text, 60);

        assert!(find(&spans, "One")
            .style
            .add_modifier
            .contains(Modifier::BOLD));
        assert_eq!(find(&spans, "One").style.fg, Some(theme::system()));
        assert!(find(&spans, "One")
            .style
            .add_modifier
            .contains(Modifier::UNDERLINED));

        assert_eq!(find(&spans, "Two").style.fg, Some(theme::system()));
        assert!(!find(&spans, "Two")
            .style
            .add_modifier
            .contains(Modifier::UNDERLINED));

        assert_eq!(find(&spans, "Three").style.fg, None);
        assert!(find(&spans, "Three")
            .style
            .add_modifier
            .contains(Modifier::BOLD));

        assert_eq!(find(&spans, "Five").style.fg, Some(theme::muted()));

        // Never a banner: one source line of heading is one rendered row.
        assert_eq!(
            shown(text, 60)
                .lines()
                .filter(|row| !row.is_empty())
                .count(),
            5
        );
    }

    #[test]
    fn emphasis_becomes_a_modifier_and_inline_code_keeps_its_channel() {
        let spans = spans_of(
            "A **strong** and *weak* and ~~gone~~ claim about `mix test`.",
            60,
        );

        assert!(find(&spans, "strong")
            .style
            .add_modifier
            .contains(Modifier::BOLD));
        assert!(find(&spans, "weak")
            .style
            .add_modifier
            .contains(Modifier::ITALIC));
        assert!(find(&spans, "gone")
            .style
            .add_modifier
            .contains(Modifier::CROSSED_OUT));

        let code = find(&spans, "mix test");
        assert_eq!(code.content.as_ref(), "`mix test`");
        assert_eq!(code.style.fg, Some(theme::system()));
    }

    #[test]
    fn every_inline_code_run_is_styled_not_only_the_first_pair() {
        let spans = spans_of("Run `one` then `two` then `three`.", 60);

        for needle in ["`one`", "`two`", "`three`"] {
            assert_eq!(
                find(&spans, needle).style.fg,
                Some(theme::system()),
                "{needle} lost its channel"
            );
        }
    }

    #[test]
    fn a_code_run_broken_across_a_fold_keeps_its_channel_on_both_rows() {
        let spans = spans_of("Run `alpha beta gamma delta` now.", 16);

        for needle in ["`alpha", "delta`"] {
            assert_eq!(
                find(&spans, needle).style.fg,
                Some(theme::system()),
                "{needle}"
            );
        }
    }

    #[test]
    fn nested_lists_hang_from_a_marker_that_stays_put_to_depth_four() {
        let text = "- one\n  - two\n    - three\n      - four and a sentence long enough that it has to fold\n";
        let rows = rows(text, 40);

        assert_eq!(rows[0], "• one");
        assert_eq!(rows[1], "  ◦ two");
        assert_eq!(rows[2], "    ▪ three");
        assert!(rows[3].starts_with("      · four"), "{rows:?}");

        // The hanging indent: a folded continuation aligns under its own item's text,
        // which is where depth 3 misaligns when the indent is guessed per level.
        let continuation = &rows[4];
        assert!(
            continuation.starts_with("        ") && !continuation.starts_with("         "),
            "continuation {continuation:?} does not hang under the item"
        );
    }

    #[test]
    fn an_ordered_list_numbers_from_its_own_start_and_reserves_the_width() {
        let rows = rows("3. three\n4. four\n", 40);

        assert_eq!(rows[0], "3. three");
        assert_eq!(rows[1], "4. four");
    }

    #[test]
    fn a_task_list_draws_a_box_the_terminal_can_measure() {
        let spans = spans_of("- [ ] open\n- [x] shut\n", 40);

        assert_eq!(find(&spans, "[ ] ").style.fg, Some(theme::muted()));
        assert_eq!(find(&spans, "[x] ").style.fg, Some(theme::good()));
    }

    #[test]
    fn a_block_quote_carries_a_bar_on_every_row_it_folds_to() {
        let text = "> a claim that is long enough to need more than one row in this pane\n";
        let rows = rows(text, 30);

        assert!(rows.len() > 1, "{rows:?}");
        assert!(rows.iter().all(|row| row.starts_with("│ ")), "{rows:?}");
    }

    #[test]
    fn a_nested_quote_stacks_its_bars() {
        let rows = rows("> outer\n>\n> > inner\n", 40);

        assert!(
            rows.iter().any(|row| row.starts_with("│ │ inner")),
            "{rows:?}"
        );
    }

    #[test]
    fn a_horizontal_rule_spans_the_pane() {
        for width in [60usize, 100, 160] {
            let rows = rows("above\n\n---\n\nbelow\n", width);
            let rule = rows
                .iter()
                .find(|row| row.starts_with('─'))
                .unwrap_or_else(|| panic!("a rule at {width}"));
            assert_eq!(rule.chars().count(), width, "{rule:?}");
        }
    }

    #[test]
    fn a_table_keeps_its_columns_while_they_fit_and_folds_the_cells_that_do_not() {
        let text = "| Name | Notes |\n|---|---|\n| alpha | a note long enough that it has to fold inside its column |\n";

        for width in [60usize, 100, 160] {
            within(text, width);
            let rows = rows(text, width);

            assert!(
                rows[0].starts_with('┌') && rows[0].ends_with('┐'),
                "{rows:?}"
            );
            assert!(rows.iter().any(|row| row.starts_with('├')), "{rows:?}");
            assert!(
                rows.last().is_some_and(|row| row.starts_with('└')),
                "{rows:?}"
            );
            // Every row of a framed table is the same width, or the frame is not a frame.
            let widths: Vec<usize> = rows.iter().map(|row| row.chars().count()).collect();
            assert!(
                widths.windows(2).all(|pair| pair[0] == pair[1]),
                "{width}: ragged frame {widths:?}"
            );
        }
    }

    #[test]
    fn a_table_wider_than_the_pane_stacks_rather_than_overflowing() {
        let text =
            "| Name | Kind | Notes | Owner |\n|---|---|---|---|\n| alpha | one | two | three |\n";

        within(text, 24);
        let text_at_24 = shown(text, 24);

        assert!(!text_at_24.contains('┌'), "still a frame: {text_at_24}");
        assert!(text_at_24.contains("Name: alpha"), "{text_at_24}");
        assert!(text_at_24.contains("Owner: three"), "{text_at_24}");
    }

    #[test]
    fn table_columns_are_measured_in_cells_so_cjk_stays_inside_its_frame() {
        let text = "| 名前 | 説明 |\n|---|---|\n| 設定 | 確認してください |\n";

        within(text, 30);
        let rows = rows(text, 30);
        let widths: Vec<usize> = rows
            .iter()
            .map(|row| UnicodeWidthStr::width(row.as_str()))
            .collect();

        assert!(
            widths.windows(2).all(|pair| pair[0] == pair[1]),
            "ragged in cells: {widths:?}"
        );
    }

    #[test]
    fn cjk_and_emoji_prose_folds_on_a_cell_boundary() {
        within("設定を確認してから、テストを実行してください。", 12);
        let folded = rows("設定を確認してから、テストを実行してください。", 12);

        assert!(folded
            .iter()
            .all(|row| UnicodeWidthStr::width(row.as_str()) <= 12));
        assert_eq!(folded[0], "設定を確認し");

        // Eight is the narrowest pane this renderer accepts, and an emoji is two cells.
        within("🚀🚀🚀🚀🚀", 8);
        assert_eq!(rows("🚀🚀🚀🚀🚀", 8), vec!["🚀🚀🚀🚀", "🚀"]);
    }

    #[test]
    fn a_link_reads_as_text_and_destination_and_an_autolink_says_it_once() {
        let spans = spans_of("See [the docs](https://example.com/d) now.", 60);

        assert_eq!(
            find(&spans, "the docs").style.add_modifier,
            Modifier::UNDERLINED
        );
        assert_eq!(
            find(&spans, "(https://example.com/d)").style.fg,
            Some(theme::muted())
        );

        let once = shown("See <https://example.com/d>.", 60);
        assert_eq!(once.matches("https://example.com/d").count(), 1, "{once}");
    }

    #[test]
    fn an_image_is_its_alt_text_in_brackets() {
        assert!(shown("![a chart](x.png)", 60).contains("[a chart]"));
        assert!(shown("![](x.png)", 60).contains("[image]"));
    }

    #[test]
    fn a_fenced_block_still_reaches_the_frame_that_highlights_it() {
        let text = shown("Here:\n\n```rust\nfn main() {}\n```\n\nDone.", 60);

        assert!(text.contains("┌─ rust "), "{text}");
        assert!(text.contains("│ fn main() {}"), "{text}");
        assert!(text.contains('└'), "{text}");
        assert!(text.contains("Done."), "{text}");
    }

    #[test]
    fn a_fence_indented_inside_a_list_item_is_framed_under_its_item() {
        let text = "- step one\n\n      indented code\n";
        let rows = rows(text, 60);

        let frame = rows
            .iter()
            .find(|row| row.contains("┌─ code"))
            .unwrap_or_else(|| panic!("{rows:?}"));
        assert!(frame.starts_with("  ┌─ code"), "{frame:?}");
    }

    #[test]
    fn the_row_budget_bounds_a_message_and_reports_that_it_did() {
        let long = "a word ".repeat(50_000);
        let rendered = render_limited(&long, 40, 16, false);

        assert_eq!(rendered.lines.len(), 16);
        assert!(!rendered.complete);
    }

    #[test]
    fn a_block_that_exactly_fills_the_budget_is_not_called_short() {
        let rendered = render_limited("alpha beta gamma delta", 8, 4, false);

        assert_eq!(rendered.lines.len(), 4, "{:?}", plain(&rendered));
        assert!(rendered.complete, "{:?}", plain(&rendered));
    }

    #[test]
    fn folding_agrees_with_the_transcript_wrapper_it_shares_a_measure_with() {
        // The pane, the export, and this module must fold one paragraph the same way.
        for (text, width) in [
            ("alpha beta", 7),
            ("abcdefghij", 4),
            ("a  b\n", 10),
            ("設定を確認してから、テストを実行してください", 12),
            ("🚀🚀🚀🚀🚀", 4),
        ] {
            let folded: Vec<String> = fold(&[Span::raw(text.to_string())], width, usize::MAX)
                .into_iter()
                .map(|row| {
                    row.iter()
                        .map(|span| span.content.as_ref())
                        .collect::<String>()
                })
                .collect();

            assert_eq!(
                folded,
                super::super::transcript_cells::wrap_limited(text, width, usize::MAX),
                "{text:?} at {width}"
            );
        }
    }

    #[test]
    fn a_word_wider_than_the_pane_costs_the_rows_asked_for_rather_than_its_length() {
        let token = "界".repeat(1024 * 1024);
        let rendered = render_limited(&token, 79, 8, false);

        assert_eq!(rendered.lines.len(), 8);
        assert!(!rendered.complete);
        assert!(rendered.lines.iter().all(|line| line.width() <= 79));
    }

    #[test]
    fn nothing_a_terminal_cannot_draw_reaches_a_span() {
        // OSC 8 is decided against, not forgotten: no escape may enter the buffer, because
        // the wrapper and the diff would measure it as printable cells.
        let text = plain(&render(SAMPLER, 100, false));
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{7}'),
            "an escape reached the rows"
        );
        assert_eq!(
            text.matches("https://example.com/docs").count(),
            1,
            "the destination is said once, in parentheses"
        );
    }

    #[test]
    fn html_survives_as_the_text_it_is_and_does_not_swallow_what_follows() {
        let rows = rows("<div>raw</div>\n\nAfter.", 60);

        assert!(rows.iter().any(|row| row == "<div>raw</div>"), "{rows:?}");
        assert!(rows.iter().any(|row| row == "After."), "{rows:?}");
    }

    /// Every colour this renderer emits is one the active [`theme`] declared.
    ///
    /// Named through the tokens rather than as literals: the point of the check is that
    /// nothing here invented a hue, and a list of `Color::Cyan` and friends would only be
    /// true of the palette that happens to be installed.
    #[test]
    fn colour_stays_inside_the_palette_the_client_owns() {
        let declared: Vec<Color> = theme::current()
            .tokens()
            .iter()
            .map(|(_name, colour)| *colour)
            .collect();

        for span in spans_of(SAMPLER, 100) {
            if let Some(colour) = span.style.fg {
                assert!(
                    declared.contains(&colour),
                    "{colour:?} is outside the transcript's palette"
                );
            }
        }
    }
}
