//! The Ouroboros mark and its compact chat shorthand.
//!
//! A terminal cell is roughly twice as tall as it is wide, so two logical pixel rows are
//! folded into one cell with `▀`, `▄`, and `█`. Chat uses a single-cell clockwise serpent
//! beside a conventional three-dot typing cadence, retaining the identity without placing
//! the full mark between two messages.

use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use super::theme;

/// The rendered terminal height after two logical rows are folded into each cell row.
pub const HEIGHT: u16 = 7;

const WIDTH: usize = 16;

/// The selected thin-ring 16x14 master. `#` is one square game-snake pixel.
const MASTER: [&str; 14] = [
    ".....#..........",
    "....###.####....",
    "...###......#...",
    "..#..........#..",
    ".#............#.",
    "#..............#",
    "#..............#",
    "#..............#",
    "#..............#",
    "#..............#",
    ".#............#.",
    "..#..........#..",
    "...#........#...",
    "....########....",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Treatment {
    Static,
}

pub fn draw(frame: &mut Frame, area: Rect, treatment: Treatment) {
    frame.render_widget(
        ratatui::widgets::Paragraph::new(lines(treatment)).alignment(Alignment::Center),
        area,
    );
}

pub fn lines(treatment: Treatment) -> Vec<Line<'static>> {
    (0..MASTER.len())
        .step_by(2)
        .map(|top| line(top, treatment))
        .collect()
}

/// A quiet, one-line form of the mark for the next agent-message position in chat.
pub fn typing_indicator(tick: u64) -> Line<'static> {
    let active = ((tick / 2) % 3) as usize;
    let mut spans = vec![
        Span::raw("  "),
        Span::styled(
            "⟳",
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
    ];

    for dot in 0..3 {
        if dot > 0 {
            spans.push(Span::raw(" "));
        }

        spans.push(if dot == active {
            Span::styled(
                "•",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("·", Style::default().fg(theme::MUTED))
        });
    }

    Line::from(spans)
}

fn line(top: usize, treatment: Treatment) -> Line<'static> {
    let mut spans = Vec::with_capacity(WIDTH);

    for x in 0..WIDTH {
        let upper = occupied(top, x);
        let lower = occupied(top + 1, x);
        let glyph = match (upper, lower) {
            (true, true) => '█',
            (true, false) => '▀',
            (false, true) => '▄',
            (false, false) => ' ',
        };

        spans.push(Span::styled(glyph.to_string(), style(treatment)));
    }

    Line::from(spans).alignment(Alignment::Center)
}

fn occupied(y: usize, x: usize) -> bool {
    MASTER
        .get(y)
        .and_then(|row| row.as_bytes().get(x))
        .map(|pixel| *pixel == b'#')
        .unwrap_or(false)
}

fn style(treatment: Treatment) -> Style {
    match treatment {
        Treatment::Static => Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(treatment: Treatment) -> Vec<String> {
        lines(treatment)
            .into_iter()
            .map(|line| line.spans.into_iter().map(|span| span.content).collect())
            .collect()
    }

    #[test]
    fn terminal_geometry_matches_the_selected_pixel_master() {
        assert_eq!(
            text(Treatment::Static),
            vec![
                "    ▄█▄ ▄▄▄▄    ",
                "  ▄▀▀▀      ▀▄  ",
                "▄▀            ▀▄",
                "█              █",
                "█              █",
                " ▀▄          ▄▀ ",
                "   ▀▄▄▄▄▄▄▄▄▀   ",
            ]
        );
    }

    #[test]
    fn typing_indicator_is_compact_and_advances() {
        let text = |tick| {
            typing_indicator(tick)
                .spans
                .into_iter()
                .map(|span| span.content)
                .collect::<String>()
        };

        assert_eq!(text(0), "  ⟳  • · ·");
        assert_eq!(text(2), "  ⟳  · • ·");
        assert_eq!(text(4), "  ⟳  · · •");
    }
}
