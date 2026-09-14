//! Cached layout of a complete conversation. Only visible rows are copied to the terminal.
//!
//! Each cell owns a row range. Content changes and animation ticks refresh only those
//! cells, shifting later ranges when necessary without re-parsing their settled prose.

use std::collections::BTreeSet;

use ratatui::text::Line;

use super::transcript_cells::{render_cell_into, Cell, ToolState, Verbosity};
use super::{access, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Format {
    width: usize,
    verbosity: Verbosity,
    theme: u64,
    screen_reader: bool,
    reduced_motion: bool,
}

#[derive(Debug, Default)]
pub(crate) struct ChatLayout {
    revision: Option<u64>,
    ended: Option<String>,
    cells: Vec<Cell>,
    // Includes the final end offset, so every cell has a start..end range.
    starts: Vec<usize>,
    pub lines: Vec<Line<'static>>,
    dirty: BTreeSet<usize>,
    animated: Vec<usize>,
    format: Option<Format>,
    tick: u64,
}

impl ChatLayout {
    pub fn current(&self, revision: u64, ended: &Option<String>) -> bool {
        self.revision == Some(revision) && self.ended == *ended
    }

    pub fn replace(&mut self, cells: Vec<Cell>, revision: u64, ended: Option<String>) {
        for (index, cell) in cells.iter().enumerate() {
            if self.cells.get(index) != Some(cell) {
                self.dirty.insert(index);
            }
        }
        self.animated = cells
            .iter()
            .enumerate()
            .filter_map(|(index, cell)| {
                let animated = match cell {
                    Cell::Message { streaming, .. } => *streaming,
                    Cell::Tool(tool) => tool.state == ToolState::Running,
                    Cell::Exploration(group) => group
                        .calls
                        .iter()
                        .any(|call| call.state == ToolState::Running),
                    _ => false,
                };
                animated.then_some(index)
            })
            .collect();
        self.cells = cells;
        self.revision = Some(revision);
        self.ended = ended;
    }

    pub fn render(&mut self, width: usize, tick: u64, verbosity: Verbosity) {
        let format = Format {
            width,
            verbosity,
            theme: theme::generation(),
            screen_reader: access::screen_reader(),
            reduced_motion: access::reduced_motion(),
        };
        if self.format != Some(format) {
            self.lines.clear();
            self.starts.clear();
            self.starts.push(0);
            for cell in &self.cells {
                render_cell_into(&mut self.lines, cell, width, tick, verbosity);
                self.starts.push(self.lines.len());
            }
            self.dirty.clear();
            self.format = Some(format);
            self.tick = tick;
            return;
        }
        if self.tick != tick && !format.screen_reader && !format.reduced_motion && !verbosity.raw()
        {
            self.dirty.extend(&self.animated);
        }
        self.tick = tick;

        // Remove vanished cells and allocate empty ranges for newly appended cells.
        if self.starts.len() > self.cells.len() + 1 {
            self.lines.truncate(self.starts[self.cells.len()]);
            self.starts.truncate(self.cells.len() + 1);
        }
        self.starts.resize(self.cells.len() + 1, self.lines.len());

        while let Some(index) = self.dirty.pop_first() {
            if index >= self.cells.len() {
                continue;
            }
            let start = self.starts[index];
            let end = self.starts[index + 1];
            let old_boundary = boundary(&self.lines, end);
            // Spacing uses the preceding row. Seed it, then keep only the cell's rows.
            let mut refreshed = match start.checked_sub(1) {
                Some(previous) => vec![self.lines[previous].clone()],
                None => Vec::new(),
            };
            let prefix = refreshed.len();
            render_cell_into(&mut refreshed, &self.cells[index], width, tick, verbosity);
            let new_len = refreshed.len() - prefix;
            self.lines
                .splice(start..end, refreshed.into_iter().skip(prefix));
            for offset in &mut self.starts[index + 1..] {
                *offset = *offset - (end - start) + new_len;
            }
            if boundary(&self.lines, start + new_len) != old_boundary
                && index + 1 < self.cells.len()
            {
                // A cell becoming empty can change the next cell's leading separator.
                self.dirty.insert(index + 1);
            }
        }
    }
}

// None means no preceding row; Some(true) means a blank row already separates cells.
fn boundary(lines: &[Line<'static>], end: usize) -> Option<bool> {
    end.checked_sub(1).map(|last| lines[last].width() == 0)
}
