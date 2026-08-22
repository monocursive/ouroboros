//! `/details` — the normalized event ledger, as a tree rather than a list of lines.
//!
//! ## Why a tree
//!
//! The ledger used to be one `{seq} {kind} {summary}` row per event, with the summary a
//! flattened `key=value key=value` rendering of the payload. That is readable for a
//! `usage` event and useless for a `tool_result`: the one place in this client that is
//! supposed to discard nothing was the place where a nested payload became a single line
//! of run-together JSON.
//!
//! So each event is now a collapsible node over [`crate::model::Event::raw`] — the whole
//! wire object the client kept, envelope included — drawn by the same
//! [`super::tree::TreeView`] that draws agent state and upgrade history. Collapsed is one
//! summary line, which is what the list was; expanded is the payload, which is what the
//! list could not be.
//!
//! ## The excerpt seam (X6)
//!
//! Streamed and replayed events are byte-capped by `Gateway.Wire` (§2.7): a string leaf
//! over `event_leaf_bytes` arrives as `{"_excerpt": prefix, "_bytes": n}`. Such a leaf is
//! drawn as its prefix with the full size named, and `Enter` on it calls
//! `interactive.event_detail {id, sequence}` — the one method that re-encodes a single
//! event under `detail_leaf_bytes` instead. The answer replaces that event's tree **for
//! this view only**: the transcript's own projection keeps reading the capped event it
//! absorbed, because the fetched copy is a fact about one reader's screen and not about
//! the session's history.
//!
//! That fetch is bounded by this client's inbound line ceiling
//! ([`crate::transport::DEFAULT_MAX_LINE`], 8 MiB) and not by the server's cap. The
//! runtime's `detail_leaf_bytes` default sits under it deliberately; a runtime configured
//! past about 7 MiB produces a frame this client truncates rather than decodes, and the
//! notice says so rather than showing a leaf that is still short and claiming it is whole.
//!
//! ## Bounded
//!
//! The ledger shows every event the local window retains, and each expanded payload is
//! bounded by the gateway's own depth and node caps, which the tree draws as the markers
//! they are. Nothing here re-reads the clock or the environment, so the rows a filter
//! produces are a pure function of the watch and the filter text.

use std::collections::{BTreeMap, BTreeSet};

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState};
use ratatui::Frame;
use serde_json::Value;

use crate::model::{Event, EventType, Plane};

use super::theme;
use super::transcript::{Entry, Watch};
use super::tree::{self, TreeState, TreeView};

/// How many characters of an event's summary the collapsed row carries.
const SUMMARY_CELLS: usize = 120;

/// One drawn row of the ledger.
#[derive(Debug, Clone, PartialEq)]
pub enum Row {
    /// One event, collapsed or open.
    Event {
        sequence: u64,
        kind: String,
        summary: String,
        /// `Gateway.Wire`'s `_struct` tag. Carried here because the tree draws it beside
        /// the *root* label, and the root row is this one.
        struct_tag: Option<String>,
        expanded: bool,
        /// Whether this event's tree is being read from an `event_detail` answer rather
        /// than from the capped copy the stream delivered.
        fetched: bool,
    },
    /// A node inside one event's payload tree.
    Node { sequence: u64, node: tree::Row },
    /// A floor, gap, note, or end-of-stream marker — the transcript's own dividers, which
    /// the ledger keeps because a hole is part of the ledger.
    Divider(String),
}

impl Row {
    /// The event this row belongs to, if any. A divider belongs to none.
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Event { sequence, .. } | Self::Node { sequence, .. } => Some(*sequence),
            Self::Divider(_) => None,
        }
    }
}

/// What survives across frames: which events are open, where the cursor is, what is
/// filtered, and which events have been fetched whole.
#[derive(Debug, Default)]
pub struct DetailsView {
    /// Which session this state describes. A different one resets it: expansion keyed by
    /// sequence would otherwise open arbitrary events of the next session.
    subject: Option<(Plane, String)>,
    /// One [`TreeState`] per open event, so the tree's own path keys cannot collide
    /// between two events that both have a `payload` node.
    open: BTreeMap<u64, TreeState>,
    /// `event_detail` answers, by sequence. This view only.
    fetched: BTreeMap<u64, Value>,
    /// Fetches in flight, so `Enter` held down does not ask four times.
    fetching: BTreeSet<u64>,
    selected: usize,
    offset: usize,
    /// The active filter, empty for none.
    pub filter: String,
    /// Whether keystrokes are going into the filter rather than to navigation.
    pub filtering: bool,
}

impl DetailsView {
    /// Points the view at one session, forgetting the previous one's state if it changed.
    pub fn focus(&mut self, plane: Plane, id: &str) {
        let subject = (plane, id.to_string());

        if self.subject.as_ref() == Some(&subject) {
            return;
        }

        self.subject = Some(subject);
        self.open.clear();
        self.fetched.clear();
        self.fetching.clear();
        self.selected = 0;
        self.offset = 0;
        self.filter.clear();
        self.filtering = false;
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Records an `event_detail` answer. The bare event object the method returns is kept
    /// as-is: it is the same shape the stream delivers, only encoded under the larger cap.
    pub fn fetched(&mut self, sequence: u64, event: Value) {
        self.fetching.remove(&sequence);
        self.fetched.insert(sequence, event);
        // A fetch is only ever asked for from an open event, but arriving at a collapsed
        // one and silently doing nothing would look like the fetch failed.
        self.open.entry(sequence).or_insert_with(TreeState::opened);
    }

    /// Records that a fetch failed, so the same leaf can be asked for again.
    pub fn fetch_failed(&mut self, sequence: u64) {
        self.fetching.remove(&sequence);
    }

    pub fn is_fetching(&self, sequence: u64) -> bool {
        self.fetching.contains(&sequence)
    }

    /// The rows this watch produces under the current filter and expansion.
    pub fn rows(&self, watch: &Watch) -> Vec<Row> {
        let filter = self.filter.trim().to_ascii_lowercase();
        let mut rows = Vec::new();

        for entry in watch.entries() {
            match entry {
                Entry::Event(event) => {
                    if !matches(event, &filter) {
                        continue;
                    }

                    self.push_event(&mut rows, event);
                }
                // A divider is never filtered out: a filter that hid the note saying
                // history is missing would make a filtered ledger look complete.
                Entry::Floor(floor) => rows.push(Row::Divider(format!(
                    "history truncated below {floor} — the runtime no longer retains it"
                ))),
                Entry::Gap { from, to } => rows.push(Row::Divider(format!(
                    "{} events missing ({from}..{to}) — replaying",
                    to - from + 1
                ))),
                Entry::Note(note) => rows.push(Row::Divider(note.text())),
                Entry::Ended(status) => rows.push(Row::Divider(format!(
                    "stream ended ({status}) — no further events"
                ))),
            }
        }

        rows
    }

    fn push_event(&self, rows: &mut Vec<Row>, event: &Event) {
        let state = self.open.get(&event.sequence);
        let fetched = self.fetched.get(&event.sequence);

        rows.push(Row::Event {
            sequence: event.sequence,
            kind: event.kind.as_str().to_string(),
            summary: tree::truncate(&one_line(&event.summary()), SUMMARY_CELLS),
            struct_tag: state.is_some().then(|| event.struct_tag.clone()).flatten(),
            expanded: state.is_some(),
            fetched: fetched.is_some(),
        });

        let Some(state) = state else {
            return;
        };

        let value = fetched.unwrap_or(&event.raw);

        // The root row is the event line already pushed, so it is dropped here rather than
        // drawn twice under two different labels.
        for node in TreeView::new("event", value)
            .rows(state)
            .into_iter()
            .skip(1)
        {
            rows.push(Row::Node {
                sequence: event.sequence,
                node,
            });
        }
    }

    /// Moves the cursor, clamped to what exists.
    pub fn move_by(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.selected = 0;
            return;
        }

        let next = self.selected as isize + delta;
        self.selected = next.clamp(0, len as isize - 1) as usize;
    }

    pub fn move_to(&mut self, index: usize, len: usize) {
        self.selected = index.min(len.saturating_sub(1));
    }

    /// Opens the row under the cursor, answering with the event whose full detail should
    /// be fetched when the cursor is on an excerpted leaf.
    pub fn expand(&mut self, rows: &[Row]) -> Option<u64> {
        match rows.get(self.selected)? {
            Row::Event { sequence, .. } => {
                self.open.entry(*sequence).or_insert_with(TreeState::opened);
                None
            }
            Row::Node { sequence, node } => {
                if node.marker.is_excerpt() {
                    // Already whole, or already asked for: `Enter` on it again is a no-op
                    // rather than a second identical request.
                    if self.fetched.contains_key(sequence) || !self.fetching.insert(*sequence) {
                        return None;
                    }

                    return Some(*sequence);
                }

                if node.expandable {
                    if let Some(state) = self.open.get_mut(sequence) {
                        state.expand(&node.path);
                    }
                }

                None
            }
            Row::Divider(_) => None,
        }
    }

    /// Closes the row under the cursor. A closed node inside an event collapses that node;
    /// a closed event collapses the whole event.
    pub fn collapse(&mut self, rows: &[Row]) {
        match rows.get(self.selected) {
            Some(Row::Event { sequence, .. }) => {
                self.open.remove(sequence);
            }
            Some(Row::Node { sequence, node }) => {
                if let Some(state) = self.open.get_mut(sequence) {
                    if node.expanded {
                        state.collapse(&node.path);
                    } else {
                        // Already a leaf: close the event it belongs to, so `left` walks
                        // out of a deep tree rather than doing nothing.
                        self.open.remove(sequence);
                    }
                }
            }
            _none => {}
        }
    }

    /// Toggles the row under the cursor, for `Enter` on an already-open node.
    pub fn toggle(&mut self, rows: &[Row]) -> Option<u64> {
        match rows.get(self.selected) {
            Some(Row::Event {
                sequence,
                expanded: true,
                ..
            }) => {
                self.open.remove(sequence);
                None
            }
            Some(Row::Node {
                sequence,
                node: node @ tree::Row { expanded: true, .. },
            }) => {
                if let Some(state) = self.open.get_mut(sequence) {
                    state.collapse(&node.path);
                }
                None
            }
            _closed => self.expand(rows),
        }
    }
}

/// Whether one event survives the filter — by kind or by any text in its summary.
fn matches(event: &Event, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }

    event.kind.as_str().to_ascii_lowercase().contains(filter)
        || event.summary().to_ascii_lowercase().contains(filter)
        || event.sequence.to_string() == filter
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Draws the ledger, clamping the cursor to what is actually there.
pub fn render(frame: &mut Frame, area: Rect, view: &mut DetailsView, rows: &[Row]) {
    if view.selected >= rows.len() {
        view.selected = rows.len().saturating_sub(1);
    }

    let items: Vec<ListItem> = rows.iter().map(|row| ListItem::new(line(row))).collect();
    let mut state = ListState::default()
        .with_selected(Some(view.selected))
        .with_offset(view.offset);

    frame.render_stateful_widget(
        List::new(items).highlight_style(theme::selected()),
        area,
        &mut state,
    );

    view.offset = state.offset();
}

fn line(row: &Row) -> Line<'static> {
    match row {
        Row::Event {
            sequence,
            kind,
            summary,
            struct_tag,
            expanded,
            fetched,
        } => {
            let mut spans = vec![
                Span::styled(
                    if *expanded { "v " } else { "> " },
                    Style::default().fg(theme::muted()),
                ),
                Span::styled(
                    format!("{sequence:>6}  "),
                    Style::default().fg(theme::muted()),
                ),
                Span::styled(format!("{kind}  "), event_style(kind)),
            ];

            if *fetched {
                spans.push(Span::styled(
                    "[whole]  ",
                    Style::default()
                        .fg(theme::good())
                        .add_modifier(Modifier::DIM),
                ));
            }

            if let Some(tag) = struct_tag {
                spans.push(Span::styled(
                    format!("«{tag}»  "),
                    Style::default().fg(theme::accent()),
                ));
            }

            spans.push(Span::raw(summary.clone()));
            Line::from(spans)
        }
        Row::Node { node, .. } => {
            let mut line = tree::line(node);
            // The event rows carry a six-column sequence gutter; the tree rows sit under
            // it rather than beside it.
            line.spans.insert(0, Span::raw("        "));
            line
        }
        Row::Divider(text) => Line::from(Span::styled(
            format!("──── {text}"),
            Style::default().fg(theme::warn()),
        )),
    }
}

/// The same colours the flat ledger used, keyed on the kind's wire name so a kind this
/// build has never heard of still gets the muted default rather than no row.
fn event_style(kind: &str) -> Style {
    match EventType::parse(kind) {
        EventType::ApprovalRequested => Style::default()
            .fg(theme::warn())
            .add_modifier(Modifier::BOLD),
        EventType::RunFailed
        | EventType::SessionFailed
        | EventType::TurnFailed
        | EventType::RunCancelled
        | EventType::SessionCancelled
        | EventType::TurnInterrupted => Style::default().fg(theme::bad()),
        EventType::OutputTextFinal | EventType::OutputTextDelta => Style::default(),
        EventType::ToolCall | EventType::ToolResult | EventType::FileChange => {
            Style::default().fg(theme::accent())
        }
        _other => Style::default().fg(theme::muted()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn event(sequence: u64, kind: &str, payload: Value) -> Event {
        Event::decode(&json!({
            "_struct": "Ouroboros.Interactive.Event",
            "id": format!("evt-{sequence}"),
            "session_id": "s1",
            "sequence": sequence,
            "type": kind,
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "turn_id": "turn-1",
            "payload": payload
        }))
        .expect("an event")
    }

    fn watch() -> Watch {
        let mut watch = Watch::new(Plane::Interactive, "s1".into());

        watch.absorb(vec![
            event(1, "input_accepted", json!({ "text": "read the lexer" })),
            event(
                2,
                "tool_call",
                json!({ "call_id": "c1", "name": "read", "input": { "path": "src/lex.rs" } }),
            ),
            event(
                3,
                "file_change",
                json!({
                    "path": "src/lex.rs",
                    "diff": { "_excerpt": "--- a/src/lex.rs\n+++ b/", "_bytes": 4096 }
                }),
            ),
        ]);

        watch
    }

    fn view() -> DetailsView {
        let mut view = DetailsView::default();
        view.focus(Plane::Interactive, "s1");
        view
    }

    #[test]
    fn every_event_is_one_collapsed_row_until_it_is_opened() {
        let watch = watch();
        let view = view();
        let rows = view.rows(&watch);

        assert_eq!(rows.len(), 3, "{rows:?}");
        assert!(matches!(
            rows[1],
            Row::Event {
                sequence: 2,
                expanded: false,
                ..
            }
        ));
    }

    #[test]
    fn enter_opens_one_event_into_its_wire_object_and_closes_it_again() {
        let watch = watch();
        let mut view = view();

        view.move_to(1, 3);
        assert_eq!(view.toggle(&view.rows(&watch)), None);

        let rows = view.rows(&watch);
        let labels: Vec<String> = rows
            .iter()
            .filter_map(|row| match row {
                Row::Node { node, .. } => Some(node.label.clone()),
                _other => None,
            })
            .collect();

        // The envelope is part of the ledger, not only the payload.
        for key in ["id", "payload", "sequence", "session_id", "type"] {
            assert!(labels.contains(&key.to_string()), "{labels:?}");
        }

        view.toggle(&rows);
        assert_eq!(view.rows(&watch).len(), 3);
    }

    #[test]
    fn an_excerpted_leaf_names_its_size_and_answers_enter_with_the_sequence_to_fetch() {
        let watch = watch();
        let mut view = view();

        // Open the file_change event, then its payload.
        view.move_to(2, 3);
        view.toggle(&view.rows(&watch));

        let rows = view.rows(&watch);
        let payload = rows
            .iter()
            .position(|row| matches!(row, Row::Node { node, .. } if node.label == "payload"))
            .expect("a payload node");
        view.move_to(payload, rows.len());
        view.expand(&view.rows(&watch));

        let rows = view.rows(&watch);
        let (index, node) = rows
            .iter()
            .enumerate()
            .find_map(|(index, row)| match row {
                Row::Node { node, .. } if node.label == "diff" => Some((index, node)),
                _other => None,
            })
            .expect("the excerpted diff leaf");

        assert!(node.marker.is_excerpt());
        assert!(
            node.summary.contains("(4096 bytes) · enter fetches"),
            "{}",
            node.summary
        );

        view.move_to(index, rows.len());
        assert_eq!(
            view.expand(&rows),
            Some(3),
            "enter on an excerpt asks for that event, whole"
        );
        assert!(view.is_fetching(3));
        assert_eq!(
            view.expand(&rows),
            None,
            "a second enter does not ask a second time"
        );

        view.fetched(
            3,
            json!({
                "id": "evt-3",
                "sequence": 3,
                "type": "file_change",
                "payload": { "path": "src/lex.rs", "diff": "the whole patch" }
            }),
        );

        let rows = view.rows(&watch);
        assert!(
            rows.iter().any(|row| matches!(
                row,
                Row::Event {
                    sequence: 3,
                    fetched: true,
                    ..
                }
            )),
            "the fetched event says it is the whole one"
        );
    }

    #[test]
    fn the_filter_keeps_kinds_and_text_and_never_hides_a_divider() {
        let mut watch = watch();
        watch.raise_floor(0);
        watch.end("closed".into());

        let mut view = view();
        view.filter = "tool".into();

        let rows = view.rows(&watch);
        let events: Vec<u64> = rows.iter().filter_map(Row::sequence).collect();
        assert_eq!(events, vec![2], "{rows:?}");
        assert!(
            rows.iter().any(|row| matches!(row, Row::Divider(_))),
            "a filter that hid the end-of-stream marker would make a partial ledger look \
             complete: {rows:?}"
        );

        view.filter = "lexer".into();
        let events: Vec<u64> = view.rows(&watch).iter().filter_map(Row::sequence).collect();
        assert_eq!(events, vec![1], "the filter reads the summary too");
    }

    #[test]
    fn focusing_a_different_session_forgets_what_was_open() {
        let watch = watch();
        let mut view = view();

        view.move_to(1, 3);
        view.toggle(&view.rows(&watch));
        assert!(view.rows(&watch).len() > 3);

        view.focus(Plane::Interactive, "s2");
        view.focus(Plane::Interactive, "s1");
        assert_eq!(view.rows(&watch).len(), 3);
    }
}
