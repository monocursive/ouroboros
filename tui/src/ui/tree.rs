//! The polymorphism renderer: any `Gateway.Wire` tree, drawn without knowing what it is.
//!
//! This is the Rust half of design invariant 4. `Ouroboros.Gateway.Wire` walks a runtime
//! term and substitutes at the *leaf*: pids become `{"_opaque": "#PID<0.1.0>"}`, structs
//! keep their name under `"_struct"`, non-UTF-8 binaries become `{"_b64": …}`, and
//! anything past the depth or node cap becomes `{"_truncated": true}`. Everything else is
//! a map, a list, or a scalar. So a widget that can draw those five markers can draw the
//! state of an `Ouroboros.Capability.*` module that was forged after this binary was
//! compiled — which is the claim, and the reason none of the tabs decode agent state into
//! a type.
//!
//! Two rules keep it honest:
//!
//! * **The markers are named, not hidden.** A truncation is a thing the gateway did to
//!   the payload, and a reader who cannot see it will read a partial tree as a whole one.
//!   Same for `_opaque`: a pid is not a value, and showing it as one would invite someone
//!   to believe it round-trips.
//! * **Nothing is dropped for being unrecognized.** Keys are rendered in sorted order —
//!   sorted here, at render time, rather than read off the `Map`: `serde_json`'s `Map` is
//!   only a `BTreeMap` until something enables `preserve_order`, and the desktop build's
//!   gpui dependency tree does. The same tree must read the same in both binaries.

use std::collections::HashSet;

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState};
use ratatui::Frame;
use serde_json::Value;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::theme;

/// Path separator. A unit separator cannot appear in a JSON key that came from an atom or
/// a struct field, so joining on it cannot collide with a key that contains the joiner.
const SEP: char = '\u{1f}';

/// What one node turned out to be. The last four are `Wire`'s markers; the first four are
/// ordinary JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Marker {
    Scalar,
    Text,
    Map,
    List,
    /// A struct, tagged with the module that produced it.
    Struct(String),
    /// A pid, port, reference, or function — inspected, never a value.
    Opaque,
    /// A binary that was not valid UTF-8.
    B64,
    /// The gateway's depth cap (32) or node cap (50_000) cut the tree here.
    Truncated,
    /// A string leaf the gateway's byte cap cut (§2.7): the prefix it kept, and how many
    /// bytes the whole leaf was. The rest exists — `interactive.event_detail` will fetch
    /// it — which is exactly why this is its own marker and not a `Map` of two keys.
    Excerpt {
        bytes: u64,
    },
}

impl Marker {
    fn style(&self) -> Style {
        match self {
            Self::Struct(_) => Style::default().fg(theme::accent()),
            Self::Opaque => Style::default().fg(theme::opaque()),
            Self::B64 => Style::default().fg(theme::opaque()),
            Self::Truncated | Self::Excerpt { .. } => Style::default().fg(theme::warn()),
            Self::Map | Self::List => Style::default().fg(theme::muted()),
            Self::Text | Self::Scalar => Style::default(),
        }
    }

    /// Whether this node is a leaf the gateway cut and a detail fetch could complete.
    pub fn is_excerpt(&self) -> bool {
        matches!(self, Self::Excerpt { .. })
    }
}

/// One visible line of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub path: String,
    pub depth: usize,
    pub label: String,
    pub marker: Marker,
    pub summary: String,
    pub expandable: bool,
    pub expanded: bool,
}

/// What survives across renders: which nodes are open, and where the cursor is.
///
/// Expansion is keyed by path rather than by index so that a poll which changed the
/// underlying value does not silently re-point every open node at a different subtree.
#[derive(Debug, Clone, Default)]
pub struct TreeState {
    expanded: HashSet<String>,
    selected: usize,
    offset: usize,
}

impl TreeState {
    /// A tree with its root open, which is what a detail pane wants on first draw.
    pub fn opened() -> Self {
        let mut state = Self::default();
        state.expanded.insert(String::new());
        state
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn is_expanded(&self, path: &str) -> bool {
        self.expanded.contains(path)
    }

    pub fn toggle(&mut self, path: &str) {
        if !self.expanded.remove(path) {
            self.expanded.insert(path.to_string());
        }
    }

    pub fn expand(&mut self, path: &str) {
        self.expanded.insert(path.to_string());
    }

    pub fn collapse(&mut self, path: &str) {
        self.expanded.remove(path);
    }

    /// Forgets every open node. Used when the pane is pointed at a different subject —
    /// keeping paths from the previous one would open arbitrary branches of the new tree.
    pub fn reset(&mut self) {
        self.expanded.clear();
        self.expanded.insert(String::new());
        self.selected = 0;
        self.offset = 0;
    }

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
}

/// A tree over one value, under one root label.
pub struct TreeView<'a> {
    root_label: &'a str,
    value: &'a Value,
}

impl<'a> TreeView<'a> {
    pub fn new(root_label: &'a str, value: &'a Value) -> Self {
        Self { root_label, value }
    }

    /// The visible rows, given what is open.
    pub fn rows(&self, state: &TreeState) -> Vec<Row> {
        let mut rows = Vec::new();
        push_rows(
            self.root_label,
            String::new(),
            self.value,
            0,
            state,
            &mut rows,
        );
        rows
    }

    /// Draws into `area`, clamping the selection to what is actually visible.
    pub fn render(&self, frame: &mut Frame, area: Rect, state: &mut TreeState, focused: bool) {
        self.render_in(frame, area, state, focused, None);
    }

    pub fn render_block(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &mut TreeState,
        focused: bool,
        block: Block<'a>,
    ) {
        self.render_in(frame, area, state, focused, Some(block));
    }

    fn render_in(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &mut TreeState,
        focused: bool,
        block: Option<Block<'a>>,
    ) {
        let rows = self.rows(state);

        if state.selected >= rows.len() {
            state.selected = rows.len().saturating_sub(1);
        }

        let items: Vec<ListItem> = rows.iter().map(|row| ListItem::new(line(row))).collect();

        let mut list = List::new(items).highlight_style(if focused {
            theme::selected()
        } else {
            theme::selected_unfocused()
        });

        if let Some(block) = block {
            list = list.block(block);
        }

        let mut list_state = ListState::default()
            .with_selected(Some(state.selected))
            .with_offset(state.offset);

        frame.render_stateful_widget(list, area, &mut list_state);
        state.offset = list_state.offset();
    }
}

/// One tree row as a drawn line. Public so a view that interleaves tree rows with rows of
/// its own — `/details` puts one per event — draws them exactly as the tree does.
pub fn line(row: &Row) -> Line<'static> {
    let mut spans = Vec::new();

    spans.push(Span::raw("  ".repeat(row.depth)));

    spans.push(Span::styled(
        if !row.expandable {
            "  ".to_string()
        } else if row.expanded {
            "v ".to_string()
        } else {
            "> ".to_string()
        },
        Style::default().fg(theme::muted()),
    ));

    spans.push(Span::styled(
        row.label.clone(),
        Style::default().add_modifier(Modifier::BOLD),
    ));

    if let Marker::Struct(name) = &row.marker {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            format!("«{name}»"),
            Style::default().fg(theme::accent()),
        ));
    }

    if !row.summary.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(row.summary.clone(), row.marker.style()));
    }

    Line::from(spans)
}

fn push_rows(
    label: &str,
    path: String,
    value: &Value,
    depth: usize,
    state: &TreeState,
    rows: &mut Vec<Row>,
) {
    let marker = classify(value);
    let children = children(value, &marker);
    let expandable = !children.is_empty();
    let expanded = expandable && state.is_expanded(&path);

    rows.push(Row {
        path: path.clone(),
        depth,
        label: label.to_string(),
        marker: marker.clone(),
        summary: summary(value, &marker, children.len()),
        expandable,
        expanded,
    });

    if !expanded {
        return;
    }

    for (key, child) in children {
        let child_path = format!("{path}{SEP}{key}");
        push_rows(&key, child_path, child, depth + 1, state, rows);
    }
}

/// Which of `Wire`'s shapes this node is.
pub fn classify(value: &Value) -> Marker {
    match value {
        Value::Object(fields) => {
            if fields.len() == 1 {
                if let Some(Value::String(_)) = fields.get("_opaque") {
                    return Marker::Opaque;
                }

                if let Some(Value::String(_)) = fields.get("_b64") {
                    return Marker::B64;
                }

                if fields.contains_key("_truncated") {
                    return Marker::Truncated;
                }
            }

            // `{"_excerpt": prefix, "_bytes": n}`, the byte cap's marker. Two keys, so it
            // is checked outside the one-key block above.
            if fields.len() == 2 && fields.contains_key("_excerpt") {
                if let Some(bytes) = fields.get("_bytes").and_then(Value::as_u64) {
                    return Marker::Excerpt { bytes };
                }
            }

            match fields.get("_struct") {
                Some(Value::String(name)) => Marker::Struct(name.clone()),
                _ => Marker::Map,
            }
        }
        Value::Array(_) => Marker::List,
        Value::String(_) => Marker::Text,
        _ => Marker::Scalar,
    }
}

fn children<'a>(value: &'a Value, marker: &Marker) -> Vec<(String, &'a Value)> {
    match marker {
        // A marker's own key is its whole content; opening it would show the reader the
        // sentinel they are already looking at.
        Marker::Opaque
        | Marker::B64
        | Marker::Truncated
        | Marker::Excerpt { .. }
        | Marker::Text
        | Marker::Scalar => Vec::new(),
        Marker::Struct(_) | Marker::Map => value
            .as_object()
            .map(|fields| {
                let mut entries: Vec<(String, &Value)> = fields
                    .iter()
                    .filter(|(key, _)| key.as_str() != "_struct")
                    .map(|(key, value)| (key.clone(), value))
                    .collect();
                // Sorted at render time, not read off the map — see the module doc.
                entries.sort_by(|left, right| left.0.cmp(&right.0));
                entries
            })
            .unwrap_or_default(),
        Marker::List => value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (format!("[{index}]"), item))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn summary(value: &Value, marker: &Marker, child_count: usize) -> String {
    match marker {
        Marker::Opaque => value
            .get("_opaque")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Marker::B64 => format!(
            "<{} base64 bytes, not valid UTF-8>",
            value
                .get("_b64")
                .and_then(Value::as_str)
                .unwrap_or("")
                .len()
        ),
        Marker::Truncated => "<truncated by the gateway's depth or node cap>".to_string(),
        Marker::Excerpt { bytes } => format!(
            "{}… ({bytes} bytes) · enter fetches",
            one_line(value.get("_excerpt").and_then(Value::as_str).unwrap_or(""))
        ),
        Marker::Map => plural(child_count, "key", "keys"),
        Marker::Struct(_) => plural(child_count, "field", "fields"),
        Marker::List => plural(child_count, "item", "items"),
        Marker::Text => one_line(value.as_str().unwrap_or_default()),
        Marker::Scalar => value.to_string(),
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{count} {one}")
    } else {
        format!("{count} {many}")
    }
}

/// A multi-line string collapsed onto the one line a tree row has. The full value is
/// still in the payload; this is a label, and a label that wrapped would break the tree.
fn one_line(text: &str) -> String {
    let flattened: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    truncate(flattened.trim(), 160)
}

/// Cuts `text` to `limit` *terminal cells*, not characters.
///
/// A CJK ideograph or an emoji occupies two cells, and a combining mark occupies none.
/// Counting characters here would hand the renderer a string twice as wide as the pane it
/// was measured for, which ratatui then clips — so the right half of a Japanese path or a
/// filename with an emoji in it would simply not be drawn.
pub fn truncate(text: &str, limit: usize) -> String {
    if text.width() <= limit {
        return text.to_string();
    }

    // The ellipsis is itself one cell.
    let budget = limit.saturating_sub(1);
    let mut kept = String::new();
    let mut used = 0;

    for character in text.chars() {
        let cells = character.width().unwrap_or(0);

        if used + cells > budget {
            break;
        }

        kept.push(character);
        used += cells;
    }

    kept.push('…');
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn labels(rows: &[Row]) -> Vec<String> {
        rows.iter()
            .map(|row| format!("{}{}", "  ".repeat(row.depth), row.label))
            .collect()
    }

    #[test]
    fn a_collapsed_tree_shows_only_its_root() {
        let value = json!({ "a": 1, "b": { "c": 2 } });
        let view = TreeView::new("state", &value);

        let rows = view.rows(&TreeState::default());

        assert_eq!(labels(&rows), vec!["state"]);
        assert_eq!(rows[0].summary, "2 keys");
        assert!(rows[0].expandable);
        assert!(!rows[0].expanded);
    }

    #[test]
    fn expanding_walks_only_the_opened_paths() {
        let value = json!({ "a": 1, "b": { "c": 2 } });
        let view = TreeView::new("state", &value);

        let mut state = TreeState::opened();
        assert_eq!(labels(&view.rows(&state)), vec!["state", "  a", "  b"]);

        let rows = view.rows(&state);
        let branch = rows
            .iter()
            .find(|row| row.label == "b")
            .expect("the b branch");
        state.toggle(&branch.path);

        assert_eq!(
            labels(&view.rows(&state)),
            vec!["state", "  a", "  b", "    c"]
        );
    }

    #[test]
    fn every_wire_marker_is_named_rather_than_rendered_as_a_value() {
        let value = json!({
            "pid": { "_opaque": "#PID<0.123.0>" },
            "blob": { "_b64": "AAECAw==" },
            "deep": { "_truncated": true },
        });

        let view = TreeView::new("agent", &value);
        let rows = view.rows(&TreeState::opened());

        let by_label = |name: &str| {
            rows.iter()
                .find(|row| row.label == name)
                .unwrap_or_else(|| panic!("a {name} row"))
                .clone()
        };

        let pid = by_label("pid");
        assert_eq!(pid.marker, Marker::Opaque);
        assert_eq!(pid.summary, "#PID<0.123.0>");
        assert!(!pid.expandable, "a sentinel has nothing under it to open");

        let blob = by_label("blob");
        assert_eq!(blob.marker, Marker::B64);
        assert!(blob.summary.contains("not valid UTF-8"));

        let deep = by_label("deep");
        assert_eq!(deep.marker, Marker::Truncated);
        assert!(deep.summary.contains("truncated"));
    }

    #[test]
    fn a_struct_keeps_its_module_name_and_hides_the_tag_from_its_fields() {
        let value = json!({
            "_struct": "Ouroboros.Interactive.Event",
            "sequence": 42,
            "type": "output_text_final"
        });

        let view = TreeView::new("event", &value);
        let rows = view.rows(&TreeState::opened());

        assert_eq!(
            rows[0].marker,
            Marker::Struct("Ouroboros.Interactive.Event".into())
        );
        assert_eq!(rows[0].summary, "2 fields");
        assert_eq!(labels(&rows), vec!["event", "  sequence", "  type"]);
    }

    #[test]
    fn a_module_this_build_has_never_heard_of_renders_with_zero_changes() {
        // The whole claim, as a test: a forged capability's state is a tree, and a tree
        // is all this widget needs.
        let value = json!({
            "_struct": "Ouroboros.Capability.ForgedAtRuntime",
            "invented_field": { "_struct": "Ouroboros.Capability.Inner", "depth": 2 },
            "handles": [{ "_opaque": "#Reference<0.1.2.3>" }]
        });

        let view = TreeView::new("state", &value);
        let mut state = TreeState::opened();

        let rows = view.rows(&state);
        let inner = rows
            .iter()
            .find(|row| row.label == "invented_field")
            .expect("the nested struct");

        assert_eq!(
            inner.marker,
            Marker::Struct("Ouroboros.Capability.Inner".into())
        );

        state.expand(&inner.path);
        assert!(view
            .rows(&state)
            .iter()
            .any(|row| row.label == "depth" && row.summary == "2"));
    }

    #[test]
    fn lists_are_indexed_and_empty_containers_do_not_open() {
        let value = json!({ "items": ["a", "b"], "none": [], "empty": {} });
        let view = TreeView::new("root", &value);
        let mut state = TreeState::opened();

        let rows = view.rows(&state);
        let items = rows.iter().find(|row| row.label == "items").unwrap();

        assert_eq!(items.summary, "2 items");
        state.expand(&items.path);

        assert_eq!(
            labels(&view.rows(&state)),
            vec!["root", "  empty", "  items", "    [0]", "    [1]", "  none"]
        );

        assert!(!rows.iter().find(|r| r.label == "none").unwrap().expandable);
        assert!(!rows.iter().find(|r| r.label == "empty").unwrap().expandable);
    }

    #[test]
    fn a_multi_line_string_is_flattened_onto_its_row_and_bounded() {
        let value = json!({ "text": format!("first\nsecond{}", "x".repeat(400)) });
        let view = TreeView::new("root", &value);

        let rows = view.rows(&TreeState::opened());
        let text = rows.iter().find(|row| row.label == "text").unwrap();

        assert!(!text.summary.contains('\n'));
        assert!(text.summary.chars().count() <= 160);
        assert!(text.summary.ends_with('…'));
    }

    #[test]
    fn truncation_is_measured_in_terminal_cells() {
        // Ten ideographs are twenty cells wide. A character-counting cut would hand the
        // renderer a string twice the width it was asked for, and the pane would clip it.
        let wide = "設定を確認してから".to_string();
        assert_eq!(wide.width(), 18);

        let cut = truncate(&wide, 10);
        assert!(cut.width() <= 10, "{cut:?} is {} cells", cut.width());
        assert!(cut.ends_with('…'));

        // Combining marks cost nothing, so nothing is cut off a string that already fits.
        let combining = "e\u{301}".repeat(6);
        assert_eq!(truncate(&combining, 6), combining);

        // Anything that fits is returned whole, ellipsis and all.
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("🚀🚀🚀", 6), "🚀🚀🚀");
        assert!(truncate("🚀🚀🚀", 5).width() <= 5);
    }

    #[test]
    fn expansion_survives_a_value_that_changed_under_it() {
        let first = json!({ "turns": { "t1": { "status": "running" } } });
        let mut state = TreeState::opened();

        let view = TreeView::new("session", &first);
        let turns = view
            .rows(&state)
            .into_iter()
            .find(|row| row.label == "turns")
            .unwrap();
        state.expand(&turns.path);

        // A poll answered with an extra turn; the open path still names the same node.
        let second = json!({
            "turns": { "t1": { "status": "completed" }, "t2": { "status": "running" } }
        });

        let labels = labels(&TreeView::new("session", &second).rows(&state));

        assert_eq!(labels, vec!["session", "  turns", "    t1", "    t2"]);
    }
}
