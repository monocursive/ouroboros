//! A small, I/O-free editor for the two conversational input surfaces.
//!
//! The terminal driver supplies paste events and a bounded workspace file index. This
//! type only edits text and derives completion state, which keeps key behaviour testable
//! without a terminal or filesystem.

use std::collections::VecDeque;
use std::fs;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

const HISTORY_LIMIT: usize = 100;
pub const WORKSPACE_FILE_LIMIT: usize = 4_000;

pub(crate) const COMMANDS: [(&str, &str); 28] = [
    ("/new", "start a new coding session"),
    ("/write", "start a session that can edit files"),
    ("/switch", "switch sessions"),
    ("/sessions", "switch sessions"),
    ("/details", "toggle normalized event details"),
    ("/copy", "copy the last agent message"),
    ("/interrupt", "abort the running turn"),
    ("/steer", "steer the running turn"),
    ("/editor", "edit this prompt in $EDITOR"),
    ("/connect", "connect or inspect ChatGPT"),
    ("/runtime", "open runtime and distribution"),
    ("/agents", "open agents"),
    ("/teams", "open teams"),
    ("/plans", "open plans and control"),
    ("/upgrades", "open upgrades"),
    ("/capabilities", "list workspace capability proposals"),
    ("/preview", "preview a capability proposal"),
    ("/admit", "admit a capability proposal"),
    ("/logs", "open runtime logs"),
    ("/settings", "open settings"),
    ("/help", "show keyboard help"),
    ("/hotkeys", "show keyboard help"),
    ("/quit", "detach, disconnect, or stop the runtime"),
    ("/clear", "clear this draft"),
    ("/close", "end or remove the selected session"),
    (
        "/options",
        "new session with provider and workspace options",
    ),
    ("/machines", "open the fleet machines menu"),
    ("/fleet", "open the fleet machines menu"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    Command,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionItem {
    pub value: String,
    pub detail: String,
    pub kind: CompletionKind,
}

#[derive(Debug, Clone)]
pub struct CompletionMenu {
    pub items: Vec<CompletionItem>,
    pub selected: usize,
    start: usize,
    end: usize,
}

impl CompletionMenu {
    pub fn selected(&self) -> Option<&CompletionItem> {
        self.items.get(self.selected)
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompletionCatalog {
    files: Vec<String>,
    /// Slash commands the open session cannot honour (B0/D14): `/steer` on a transport
    /// whose `steer` capability is `false`, and so on. Empty by default — a catalog that
    /// has not been told anything hides nothing, which is what an older gateway's silence
    /// about capabilities has to mean.
    hidden: Vec<&'static str>,
}

impl CompletionCatalog {
    pub fn set_files(&mut self, mut files: Vec<String>) {
        files.sort();
        files.dedup();
        self.files = files;
    }

    /// Names with their leading `/`, as [`COMMANDS`] spells them.
    pub fn hide_commands(&mut self, hidden: Vec<&'static str>) {
        self.hidden = hidden;
    }

    fn hides(&self, name: &str) -> bool {
        self.hidden.contains(&name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorAction {
    None,
    Submit,
    Cancel,
    Scroll(isize),
}

/// Cursor positions are UTF-8 byte offsets and are always kept on a character boundary.
#[derive(Debug, Clone, Default)]
pub struct Editor {
    text: String,
    cursor: usize,
    preferred_column: Option<usize>,
    history: Vec<String>,
    history_index: Option<usize>,
    history_draft: Option<(String, usize)>,
    completion: Option<CompletionMenu>,
    yank: Option<String>,
}

impl Editor {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn completion(&self) -> Option<&CompletionMenu> {
        self.completion.as_ref()
    }

    pub fn update_completions(&mut self, catalog: &CompletionCatalog) {
        self.refresh_completion(catalog);
    }

    pub fn has_state(&self) -> bool {
        !self.text.is_empty() || !self.history.is_empty()
    }

    /// What has been submitted through this editor, oldest first.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Adopts a history from a previous editor over the same conversation. The composer is
    /// rebuilt every time it opens, and an Up arrow that forgot everything typed before the
    /// last Esc is a recall that cannot be relied on.
    pub fn restore_history(&mut self, history: Vec<String>) {
        self.history = history;

        if self.history.len() > HISTORY_LIMIT {
            let excess = self.history.len() - HISTORY_LIMIT;
            self.history.drain(..excess);
        }

        self.history_index = None;
        self.history_draft = None;
    }

    pub fn clear_text(&mut self) {
        self.text.clear();
        self.cursor = 0;
        self.preferred_column = None;
        self.history_index = None;
        self.history_draft = None;
        self.completion = None;
    }

    pub fn submission(&self) -> Option<String> {
        let value = self.text.trim();
        (!value.is_empty()).then(|| value.to_string())
    }

    /// Records and clears a successfully accepted draft.
    pub fn accept_submission(&mut self) -> Option<String> {
        let value = self.submission()?;

        if self.history.last() != Some(&value) {
            self.history.push(value.clone());
            if self.history.len() > HISTORY_LIMIT {
                self.history.remove(0);
            }
        }

        self.clear_text();
        Some(value)
    }

    pub fn paste(&mut self, text: &str, catalog: &CompletionCatalog) {
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        self.insert(&normalized);
        self.refresh_completion(catalog);
    }

    pub fn handle_key(&mut self, key: KeyEvent, catalog: &CompletionCatalog) -> EditorAction {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        let action = match key.code {
            KeyCode::Esc => {
                if self.completion.take().is_some() {
                    EditorAction::None
                } else {
                    EditorAction::Cancel
                }
            }
            // Only reachable where the terminal reports the modifier at all: without the
            // kitty keyboard protocol, `Shift+Enter` arrives as a bare `Enter` and submits.
            // The footers advertise it on exactly that condition; `Ctrl+J` below is the
            // newline every terminal can send.
            KeyCode::Enter if shift || alt => {
                self.insert("\n");
                EditorAction::None
            }
            KeyCode::Enter => EditorAction::Submit,
            KeyCode::Char('j') if ctrl => {
                self.insert("\n");
                EditorAction::None
            }
            KeyCode::Tab if self.apply_completion() => EditorAction::None,
            KeyCode::Tab => EditorAction::None,
            KeyCode::BackTab if self.completion.is_some() => {
                self.select_completion(-1);
                EditorAction::None
            }
            KeyCode::Backspace if ctrl || alt => {
                self.delete_word_backward();
                EditorAction::None
            }
            KeyCode::Char('w') if ctrl => {
                self.delete_word_backward();
                EditorAction::None
            }
            KeyCode::Char('h') if ctrl => {
                self.backspace();
                EditorAction::None
            }
            KeyCode::Backspace => {
                self.backspace();
                EditorAction::None
            }
            KeyCode::Delete if ctrl || alt => {
                self.delete_word_forward();
                EditorAction::None
            }
            KeyCode::Char('d') if alt => {
                self.delete_word_forward();
                EditorAction::None
            }
            KeyCode::Char('d') if ctrl => {
                self.delete();
                EditorAction::None
            }
            KeyCode::Delete => {
                self.delete();
                EditorAction::None
            }
            KeyCode::Char('u') if ctrl => {
                self.delete_to_line_start();
                EditorAction::None
            }
            KeyCode::Char('k') if ctrl => {
                self.delete_to_line_end();
                EditorAction::None
            }
            KeyCode::Char('y') if ctrl => {
                self.yank_insert();
                EditorAction::None
            }
            KeyCode::Left if ctrl || alt => {
                self.move_word_left();
                EditorAction::None
            }
            KeyCode::Char('b') if alt => {
                self.move_word_left();
                EditorAction::None
            }
            KeyCode::Left => {
                self.move_left();
                EditorAction::None
            }
            KeyCode::Char('b') if ctrl => {
                self.move_left();
                EditorAction::None
            }
            KeyCode::Right if ctrl || alt => {
                self.move_word_right();
                EditorAction::None
            }
            KeyCode::Char('f') if alt => {
                self.move_word_right();
                EditorAction::None
            }
            KeyCode::Right => {
                self.move_right();
                EditorAction::None
            }
            KeyCode::Char('f') if ctrl => {
                self.move_right();
                EditorAction::None
            }
            KeyCode::Home => {
                self.move_line_start();
                EditorAction::None
            }
            KeyCode::Char('a') if ctrl => {
                self.move_line_start();
                EditorAction::None
            }
            KeyCode::End => {
                self.move_line_end();
                EditorAction::None
            }
            KeyCode::Char('e') if ctrl => {
                self.move_line_end();
                EditorAction::None
            }
            KeyCode::Up if self.completion.is_some() => {
                self.select_completion(-1);
                EditorAction::None
            }
            KeyCode::Down if self.completion.is_some() => {
                self.select_completion(1);
                EditorAction::None
            }
            KeyCode::Char('p') if ctrl && self.completion.is_some() => {
                self.select_completion(-1);
                EditorAction::None
            }
            KeyCode::Char('n') if ctrl && self.completion.is_some() => {
                self.select_completion(1);
                EditorAction::None
            }
            KeyCode::Up => {
                if !self.move_vertical(-1) {
                    self.history_previous();
                }
                EditorAction::None
            }
            KeyCode::Down => {
                if self.history_index.is_some() {
                    self.history_next();
                } else {
                    self.move_vertical(1);
                }
                EditorAction::None
            }
            KeyCode::PageUp => EditorAction::Scroll(-1),
            KeyCode::PageDown => EditorAction::Scroll(1),
            // ALT is excluded as well as CONTROL: a terminal reports Alt-B and Alt-F as
            // `Char('b')`/`Char('f')` with the modifier set, and inserting the letter turns
            // a word-motion chord into typing.
            KeyCode::Char(c) if !ctrl && !alt => {
                self.insert(&c.to_string());
                EditorAction::None
            }
            _ => return EditorAction::None,
        };

        if !matches!(key.code, KeyCode::Tab | KeyCode::BackTab | KeyCode::Esc)
            && !matches!(
                action,
                EditorAction::Submit | EditorAction::Cancel | EditorAction::Scroll(_)
            )
        {
            self.refresh_completion(catalog);
        }

        action
    }

    fn insert(&mut self, value: &str) {
        self.detach_history();
        self.text.insert_str(self.cursor, value);
        self.cursor += value.len();
        self.preferred_column = None;
    }

    fn backspace(&mut self) {
        let Some(previous) = previous_boundary(&self.text, self.cursor) else {
            return;
        };

        self.detach_history();
        self.text.drain(previous..self.cursor);
        self.cursor = previous;
        self.preferred_column = None;
    }

    fn delete(&mut self) {
        let Some(next) = next_boundary(&self.text, self.cursor) else {
            return;
        };

        self.detach_history();
        self.text.drain(self.cursor..next);
        self.preferred_column = None;
    }

    fn delete_word_backward(&mut self) {
        let start = word_left(&self.text, self.cursor);
        self.kill_range(start, self.cursor);
    }

    fn delete_word_forward(&mut self) {
        let end = word_right(&self.text, self.cursor);
        self.kill_range(self.cursor, end);
    }

    fn delete_to_line_start(&mut self) {
        let start = line_start(&self.text, self.cursor);
        self.kill_range(start, self.cursor);
    }

    fn delete_to_line_end(&mut self) {
        let end = line_end(&self.text, self.cursor);
        if end == self.cursor && end < self.text.len() && self.text[end..].starts_with('\n') {
            self.kill_range(self.cursor, end + 1);
        } else {
            self.kill_range(self.cursor, end);
        }
    }

    fn kill_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }

        self.detach_history();
        let killed = self.text[start..end].to_string();
        self.text.drain(start..end);
        self.cursor = start;
        self.preferred_column = None;
        self.yank = Some(killed);
    }

    fn yank_insert(&mut self) {
        let Some(text) = self.yank.clone() else {
            return;
        };
        self.insert(&text);
    }

    fn move_word_left(&mut self) {
        self.cursor = word_left(&self.text, self.cursor);
        self.preferred_column = None;
    }

    fn move_word_right(&mut self) {
        self.cursor = word_right(&self.text, self.cursor);
        self.preferred_column = None;
    }

    fn move_left(&mut self) {
        if let Some(previous) = previous_boundary(&self.text, self.cursor) {
            self.cursor = previous;
            self.preferred_column = None;
        }
    }

    fn move_right(&mut self) {
        if let Some(next) = next_boundary(&self.text, self.cursor) {
            self.cursor = next;
            self.preferred_column = None;
        }
    }

    fn move_line_start(&mut self) {
        self.cursor = line_start(&self.text, self.cursor);
        self.preferred_column = None;
    }

    fn move_line_end(&mut self) {
        self.cursor = line_end(&self.text, self.cursor);
        self.preferred_column = None;
    }

    fn move_vertical(&mut self, delta: isize) -> bool {
        let start = self.text[..self.cursor].rfind('\n').map_or(0, |at| at + 1);
        let end = self.text[self.cursor..]
            .find('\n')
            .map_or(self.text.len(), |at| self.cursor + at);
        let column = column_of(&self.text[start..self.cursor]);
        let wanted = self.preferred_column.unwrap_or(column);

        let target = if delta < 0 {
            if start == 0 {
                return false;
            }
            let previous_end = start - 1;
            let previous_start = self.text[..previous_end].rfind('\n').map_or(0, |at| at + 1);
            (previous_start, previous_end)
        } else {
            if end == self.text.len() {
                return false;
            }
            let next_start = end + 1;
            let next_end = self.text[next_start..]
                .find('\n')
                .map_or(self.text.len(), |at| next_start + at);
            (next_start, next_end)
        };

        self.cursor = byte_at_column(&self.text, target.0, target.1, wanted);
        self.preferred_column = Some(wanted);
        true
    }

    fn history_previous(&mut self) {
        if self.history.is_empty() {
            return;
        }

        let next = match self.history_index {
            Some(index) => index.saturating_sub(1),
            None => {
                self.history_draft = Some((self.text.clone(), self.cursor));
                self.history.len() - 1
            }
        };

        self.history_index = Some(next);
        self.text = self.history[next].clone();
        self.cursor = self.text.len();
        self.preferred_column = None;
    }

    fn history_next(&mut self) {
        let Some(index) = self.history_index else {
            return;
        };

        if index + 1 < self.history.len() {
            let next = index + 1;
            self.history_index = Some(next);
            self.text = self.history[next].clone();
            self.cursor = self.text.len();
        } else {
            self.history_index = None;
            let (draft, cursor) = self.history_draft.take().unwrap_or_default();
            self.text = draft;
            self.cursor = cursor.min(self.text.len());
        }

        self.preferred_column = None;
    }

    fn detach_history(&mut self) {
        if self.history_index.take().is_some() {
            self.history_draft = None;
        }
    }

    fn refresh_completion(&mut self, catalog: &CompletionCatalog) {
        // Scanned as characters, not bytes: a non-breaking space (Option+Space, and every
        // browser paste) or an ideographic space is whitespace that is two or three bytes
        // wide, and `at + 1` past one of them lands mid-character. Slicing there panics.
        let start = self.text[..self.cursor]
            .char_indices()
            .rev()
            .find(|(_at, character)| character.is_whitespace())
            .map_or(0, |(at, character)| at + character.len_utf8());
        let end = self.text[self.cursor..]
            .find(char::is_whitespace)
            .map_or(self.text.len(), |at| self.cursor + at);
        let token = &self.text[start..self.cursor];
        let old_value = self
            .completion
            .as_ref()
            .and_then(CompletionMenu::selected)
            .map(|item| item.value.clone());

        let items = if let Some(query) = token.strip_prefix('/') {
            if !self.text[..start].trim().is_empty() {
                Vec::new()
            } else {
                matching_commands(query, catalog)
            }
        } else if let Some(query) = token.strip_prefix('@') {
            matching_files(query, &catalog.files)
        } else {
            Vec::new()
        };

        if items.is_empty() {
            self.completion = None;
            return;
        }

        let selected = old_value
            .and_then(|value| items.iter().position(|item| item.value == value))
            .unwrap_or(0);

        self.completion = Some(CompletionMenu {
            items,
            selected,
            start,
            end,
        });
    }

    fn select_completion(&mut self, delta: isize) {
        let Some(menu) = self.completion.as_mut() else {
            return;
        };

        menu.selected =
            (menu.selected as isize + delta).rem_euclid(menu.items.len() as isize) as usize;
    }

    fn apply_completion(&mut self) -> bool {
        let Some(menu) = self.completion.take() else {
            return false;
        };
        let Some(item) = menu.selected().cloned() else {
            return false;
        };

        self.detach_history();
        self.text.replace_range(menu.start..menu.end, &item.value);
        self.cursor = menu.start + item.value.len();

        if item.kind == CompletionKind::File {
            self.text.insert(self.cursor, ' ');
            self.cursor += 1;
        }

        self.preferred_column = None;
        true
    }
}

impl PartialEq<&str> for Editor {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

fn matching_commands(query: &str, catalog: &CompletionCatalog) -> Vec<CompletionItem> {
    let query = query.to_ascii_lowercase();
    COMMANDS
        .iter()
        .filter(|(name, _detail)| !catalog.hides(name))
        .filter(|(name, detail)| {
            name[1..].to_ascii_lowercase().contains(&query)
                || detail.to_ascii_lowercase().contains(&query)
        })
        .map(|(name, detail)| CompletionItem {
            value: (*name).to_string(),
            detail: (*detail).to_string(),
            kind: CompletionKind::Command,
        })
        .collect()
}

fn matching_files(query: &str, files: &[String]) -> Vec<CompletionItem> {
    let query = query.to_ascii_lowercase();
    files
        .iter()
        .filter(|path| path.to_ascii_lowercase().contains(&query))
        .take(50)
        .map(|path| CompletionItem {
            value: format!("@{path}"),
            detail: "local workspace path".to_string(),
            kind: CompletionKind::File,
        })
        .collect()
}

/// Motion and deletion step by *grapheme cluster*, not by `char`.
///
/// `e` + U+0301 and a ZWJ emoji sequence are each one thing on screen and several `char`s
/// in memory. Stepping by `char` put the cursor inside them, so one Left moved nowhere
/// visible and one Backspace left a stray combining mark attached to whatever preceded it.
fn line_start(text: &str, cursor: usize) -> usize {
    text[..cursor].rfind('\n').map_or(0, |at| at + 1)
}

fn line_end(text: &str, cursor: usize) -> usize {
    text[cursor..]
        .find('\n')
        .map_or(text.len(), |at| cursor + at)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClusterClass {
    Space,
    Word,
    Other,
}

fn cluster_class(cluster: &str) -> ClusterClass {
    if cluster.chars().all(char::is_whitespace) {
        ClusterClass::Space
    } else if cluster
        .chars()
        .all(|character| character.is_alphanumeric() || character == '_')
    {
        ClusterClass::Word
    } else {
        ClusterClass::Other
    }
}

fn word_left(text: &str, mut cursor: usize) -> usize {
    while let Some(previous) = previous_boundary(text, cursor) {
        if cluster_class(&text[previous..cursor]) != ClusterClass::Space {
            break;
        }
        cursor = previous;
    }

    let Some(previous) = previous_boundary(text, cursor) else {
        return 0;
    };
    let class = cluster_class(&text[previous..cursor]);
    cursor = previous;

    while let Some(previous) = previous_boundary(text, cursor) {
        if cluster_class(&text[previous..cursor]) != class {
            break;
        }
        cursor = previous;
    }

    cursor
}

fn word_right(text: &str, mut cursor: usize) -> usize {
    let Some(next) = next_boundary(text, cursor) else {
        return text.len();
    };
    let mut class = cluster_class(&text[cursor..next]);
    if class == ClusterClass::Space {
        cursor = next;
        while let Some(next) = next_boundary(text, cursor) {
            class = cluster_class(&text[cursor..next]);
            if class != ClusterClass::Space {
                break;
            }
            cursor = next;
        }
    }

    while let Some(next) = next_boundary(text, cursor) {
        if cluster_class(&text[cursor..next]) != class {
            break;
        }
        cursor = next;
    }

    cursor
}

fn previous_boundary(text: &str, cursor: usize) -> Option<usize> {
    text[..cursor]
        .grapheme_indices(true)
        .next_back()
        .map(|(at, _cluster)| at)
}

fn next_boundary(text: &str, cursor: usize) -> Option<usize> {
    let mut clusters = text[cursor..].grapheme_indices(true);
    clusters.next()?;
    clusters
        .next()
        .map(|(at, _cluster)| cursor + at)
        .or(Some(text.len()))
}

/// The display column of the text before the cursor, which is what a vertical move should
/// preserve: a line of CJK above a line of ASCII is twice as many columns as it is
/// characters, and counting characters would land the cursor half a line early.
fn column_of(text: &str) -> usize {
    text.width()
}

/// The grapheme boundary in `text[start..end]` nearest `column` without passing it.
fn byte_at_column(text: &str, start: usize, end: usize, column: usize) -> usize {
    let mut used = 0;

    for (at, cluster) in text[start..end].grapheme_indices(true) {
        if used + cluster.width() > column {
            return start + at;
        }

        used += cluster.width();
    }

    end
}

/// Builds a deterministic, bounded local index without following directory symlinks.
pub fn index_workspace(root: &Path) -> Vec<String> {
    if !root.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();
    let mut pending = VecDeque::from([root.to_path_buf()]);

    while let Some(directory) = pending.pop_front() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        let mut entries = entries.filter_map(Result::ok).collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();

            if kind.is_dir() {
                if !matches!(
                    name.as_ref(),
                    ".git" | "node_modules" | "target" | "deps" | "_build"
                ) {
                    pending.push_back(path);
                }
                continue;
            }

            if kind.is_file() || kind.is_symlink() {
                if let Ok(relative) = path.strip_prefix(root) {
                    files.push(path_string(relative));
                    if files.len() == WORKSPACE_FILE_LIMIT {
                        files.sort();
                        return files;
                    }
                }
            }
        }
    }

    files.sort();
    files
}

fn path_string(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn modified(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn cursor_edits_unicode_and_multiple_lines() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        editor.paste("one\ntrès", &catalog);
        editor.handle_key(key(KeyCode::Left), &catalog);
        editor.handle_key(key(KeyCode::Backspace), &catalog);
        editor.handle_key(key(KeyCode::Home), &catalog);
        editor.handle_key(key(KeyCode::Char('✓')), &catalog);

        assert_eq!(editor.text(), "one\n✓trs");
        assert!(editor.text().is_char_boundary(editor.cursor()));

        editor.handle_key(modified(KeyCode::Enter, KeyModifiers::SHIFT), &catalog);
        assert_eq!(editor.text(), "one\n✓\ntrs");
    }

    #[test]
    fn history_restores_the_draft_after_the_newest_entry() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        editor.paste("first", &catalog);
        assert_eq!(editor.accept_submission().as_deref(), Some("first"));
        editor.paste("unfinished", &catalog);
        editor.handle_key(key(KeyCode::Up), &catalog);
        assert_eq!(editor.text(), "first");
        editor.handle_key(key(KeyCode::Down), &catalog);
        assert_eq!(editor.text(), "unfinished");
    }

    #[test]
    fn command_and_file_completion_replace_the_active_token() {
        let mut catalog = CompletionCatalog::default();
        catalog.set_files(vec!["src/ui/app.rs".into(), "src/main.rs".into()]);
        let mut editor = Editor::default();

        editor.paste("/sett", &catalog);
        assert_eq!(
            editor.completion().unwrap().selected().unwrap().value,
            "/settings"
        );
        editor.handle_key(key(KeyCode::Tab), &catalog);
        assert_eq!(editor.text(), "/settings");

        editor.clear_text();
        editor.paste("inspect @ui/app", &catalog);
        editor.handle_key(key(KeyCode::Tab), &catalog);
        assert_eq!(editor.text(), "inspect @src/ui/app.rs ");
    }

    /// Every listed command completes from its own prefix, and the two fleet verbs the
    /// dispatcher serves are among them: help advertises them, so completion must too.
    #[test]
    fn every_command_completes_from_its_own_prefix() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        for (name, _) in COMMANDS {
            editor.clear_text();
            editor.paste(name, &catalog);
            let offered = editor
                .completion()
                .expect("command completions")
                .items
                .iter()
                .any(|item| item.value == *name);
            assert!(offered, "{name} must complete from its own prefix");
        }

        editor.clear_text();
        editor.paste("/mach", &catalog);
        assert_eq!(
            editor.completion().unwrap().selected().unwrap().value,
            "/machines"
        );
    }

    #[test]
    fn paste_normalizes_terminal_line_endings() {
        let mut editor = Editor::default();
        editor.paste("a\r\nb\rc", &CompletionCatalog::default());
        assert_eq!(editor.text(), "a\nb\nc");
    }

    /// Option+Space on macOS. The completion scan used to step one byte past it and slice
    /// through the middle of the character.
    #[test]
    fn a_typed_non_breaking_space_does_not_split_a_character() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        editor.handle_key(key(KeyCode::Char('a')), &catalog);
        editor.handle_key(key(KeyCode::Char('\u{a0}')), &catalog);
        editor.handle_key(key(KeyCode::Char('b')), &catalog);

        assert_eq!(editor.text(), "a\u{a0}b");
        assert!(editor.text().is_char_boundary(editor.cursor()));
    }

    #[test]
    fn pasted_text_containing_a_non_breaking_space_survives_a_later_keystroke() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        editor.paste("review the\u{a0}diff", &catalog);
        editor.handle_key(key(KeyCode::Char('!')), &catalog);

        assert_eq!(editor.text(), "review the\u{a0}diff!");
        assert!(editor.text().is_char_boundary(editor.cursor()));
    }

    /// The word separator a Japanese or Chinese IME produces.
    #[test]
    fn an_ideographic_space_is_whitespace_rather_than_a_byte_offset() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        editor.paste("直す\u{3000}/set", &catalog);

        assert_eq!(editor.text(), "直す\u{3000}/set");
        // The `/` follows whitespace but not the start of the line, so it is a path-like
        // token rather than a command: what matters here is that scanning it did not panic.
        assert!(editor.text().is_char_boundary(editor.cursor()));
    }

    /// One thing on screen is one thing to the cursor, however many `char`s it is made of.
    #[test]
    fn motion_and_deletion_step_by_grapheme_cluster() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        // A ZWJ family emoji: five chars, one cluster.
        editor.paste("ok 👨‍👩‍👧", &catalog);
        assert_eq!(editor.text().chars().count(), 8);
        assert_eq!(editor.text().graphemes(true).count(), 4);

        editor.handle_key(key(KeyCode::Backspace), &catalog);
        assert_eq!(
            editor.text(),
            "ok ",
            "one Backspace removes the whole emoji, not its last codepoint"
        );

        // A base letter and its combining acute.
        editor.clear_text();
        editor.paste("cafe\u{301}", &catalog);
        editor.handle_key(key(KeyCode::Left), &catalog);
        assert_eq!(editor.cursor(), 3, "Left clears the accent with its letter");

        editor.handle_key(key(KeyCode::Right), &catalog);
        assert_eq!(editor.cursor(), editor.text().len());

        editor.handle_key(key(KeyCode::Backspace), &catalog);
        assert_eq!(editor.text(), "caf");
    }

    /// A vertical move keeps the *column*, and a line of CJK is twice as many columns as it
    /// is characters.
    #[test]
    fn vertical_movement_counts_display_columns() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        editor.paste("設定確認\nabcdefgh", &catalog);
        // End of the second line, column 8.
        assert_eq!(editor.cursor(), editor.text().len());

        editor.handle_key(key(KeyCode::Up), &catalog);

        // Column 8 on the first line is four ideographs in, which is its end.
        assert_eq!(&editor.text()[..editor.cursor()], "設定確認");

        editor.handle_key(key(KeyCode::Down), &catalog);
        assert_eq!(editor.cursor(), editor.text().len());
    }

    #[test]
    fn readline_word_and_line_kills_match_the_agent_editors() {
        let catalog = CompletionCatalog::default();
        let mut editor = Editor::default();

        editor.paste("hello world", &catalog);
        editor.handle_key(modified(KeyCode::Char('b'), KeyModifiers::ALT), &catalog);
        assert_eq!(&editor.text()[..editor.cursor()], "hello ");
        editor.handle_key(modified(KeyCode::Char('f'), KeyModifiers::ALT), &catalog);
        assert_eq!(editor.cursor(), editor.text().len());

        editor.handle_key(
            modified(KeyCode::Char('w'), KeyModifiers::CONTROL),
            &catalog,
        );
        assert_eq!(editor.text(), "hello ");

        editor.handle_key(
            modified(KeyCode::Char('y'), KeyModifiers::CONTROL),
            &catalog,
        );
        assert_eq!(editor.text(), "hello world");

        editor.handle_key(
            modified(KeyCode::Char('a'), KeyModifiers::CONTROL),
            &catalog,
        );
        editor.handle_key(
            modified(KeyCode::Char('k'), KeyModifiers::CONTROL),
            &catalog,
        );
        assert_eq!(editor.text(), "");
        editor.handle_key(
            modified(KeyCode::Char('y'), KeyModifiers::CONTROL),
            &catalog,
        );
        assert_eq!(editor.text(), "hello world");

        editor.paste("\nnext", &catalog);
        editor.handle_key(
            modified(KeyCode::Char('u'), KeyModifiers::CONTROL),
            &catalog,
        );
        assert_eq!(editor.text(), "hello world\n");
    }

    #[test]
    fn a_completed_path_with_a_unicode_space_takes_the_next_keystroke() {
        let mut catalog = CompletionCatalog::default();
        catalog.set_files(vec!["notes\u{a0}draft.md".into()]);
        let mut editor = Editor::default();

        editor.paste("@notes", &catalog);
        editor.handle_key(key(KeyCode::Tab), &catalog);
        assert_eq!(editor.text(), "@notes\u{a0}draft.md ");

        editor.handle_key(key(KeyCode::Backspace), &catalog);

        assert_eq!(editor.text(), "@notes\u{a0}draft.md");
        assert!(editor.text().is_char_boundary(editor.cursor()));
    }
}
