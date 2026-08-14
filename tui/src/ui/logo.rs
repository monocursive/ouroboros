//! The Ouroboros mark, drawn from the same 16-column pixel master in every surface.
//!
//! A terminal cell is roughly twice as tall as it is wide, so two logical pixel rows are
//! folded into one cell with `▀`, `▄`, and `█`. The loading treatment never changes the
//! silhouette: a cyan highlight travels clockwise around the muted serpent, which keeps
//! the logo recognizable in monochrome and avoids depending on wide glyphs or a fixed
//! terminal background.

use std::f32::consts::TAU;

use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use super::theme;

/// The rendered terminal height after two logical rows are folded into each cell row.
pub const HEIGHT: u16 = 7;

const WIDTH: usize = 16;
const SECTORS: i16 = 16;

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
    Loading { tick: u64 },
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

        spans.push(Span::styled(
            glyph.to_string(),
            style(treatment, x, top, upper, lower),
        ));
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

fn style(treatment: Treatment, x: usize, top: usize, upper: bool, lower: bool) -> Style {
    match treatment {
        Treatment::Static => Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
        Treatment::Loading { tick } if upper || lower => {
            let y = top as f32
                + match (upper, lower) {
                    (true, true) => 0.5,
                    (false, true) => 1.0,
                    _ => 0.0,
                };
            let sector = sector(x as f32, y);
            let active = (tick % SECTORS as u64) as i16;
            let distance = (sector - active).abs();
            let distance = distance.min(SECTORS - distance);

            if distance <= 1 {
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else if distance == 2 {
                Style::default()
            } else {
                Style::default().fg(theme::MUTED)
            }
        }
        Treatment::Loading { .. } => Style::default(),
    }
}

/// Sixteen clockwise sectors, beginning at twelve o'clock.
fn sector(x: f32, y: f32) -> i16 {
    let dx = x - 7.5;
    let dy = y - 6.5;
    let clockwise_from_top = dx.atan2(-dy).rem_euclid(TAU);

    ((clockwise_from_top / TAU * SECTORS as f32).round() as i16).rem_euclid(SECTORS)
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
    fn loading_changes_only_colour_not_the_logo_silhouette() {
        assert_eq!(
            text(Treatment::Loading { tick: 0 }),
            text(Treatment::Loading { tick: 7 })
        );

        let at_zero = lines(Treatment::Loading { tick: 0 });
        let later = lines(Treatment::Loading { tick: 7 });
        assert_ne!(at_zero, later, "the clockwise highlight must advance");
    }
}
