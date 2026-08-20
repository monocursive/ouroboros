//! Tab 7: the runtime's own output, when this client owns it.
//!
//! The gateway does not stream logs — §6 records that as deferred, not as done — so there
//! are exactly two truthful things this tab can say. In spawn mode it is the bounded ring
//! `runtime::spawn` fills from the child's pipes. In attach mode it says where the logs
//! actually are, which is with whoever started the daemon, rather than showing an empty
//! pane that reads like a runtime with nothing to say.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::runtime::Stream;

use super::app::App;
use super::theme;
use super::view::{pane, panel_title};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let Some(ring) = &app.logs else {
        let block = pane(panel_title("logs", false, None, app.ticks), false);

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "logs live with the spawner",
                    Style::default().fg(theme::MUTED),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "this client attached to a runtime it did not start, and the gateway does \
                     not stream the daemon's output. `ouro daemon` writes live application logs \
                     to runtime.log and bootstrap/VM/crash output to daemon.log in its data \
                     directory.",
                    Style::default().fg(theme::MUTED),
                )),
            ])
            .block(block)
            .wrap(Wrap { trim: false }),
            area,
        );

        return;
    };

    let dropped = ring.dropped();

    let mut title = vec![Span::styled(" logs ", theme::heading())];

    if dropped > 0 {
        title.push(Span::styled(
            format!("{dropped} lines dropped by the ring "),
            Style::default().fg(theme::WARN),
        ));
    }

    let block = pane(Line::from(title), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let height = inner.height as usize;
    // One page beyond what fits, so scrolling back has somewhere to go without holding
    // the whole ring as `Line`s on every frame.
    let lines = ring.tail(height + app.log_scroll);

    if lines.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "the runtime has printed nothing yet",
                Style::default().fg(theme::MUTED),
            )),
            inner,
        );

        return;
    }

    let end = lines.len().saturating_sub(app.log_scroll.min(lines.len()));
    let start = end.saturating_sub(height);

    let rendered: Vec<Line> = lines[start..end]
        .iter()
        .map(|line| {
            Line::from(Span::styled(
                line.text.clone(),
                if line.stream == Stream::Stderr {
                    // The gateway routes the default logger to stderr on purpose (§2.9),
                    // so stderr here is ordinary runtime logging, not a fault.
                    Style::default()
                } else {
                    Style::default().fg(theme::MUTED)
                },
            ))
        })
        .collect();

    frame.render_widget(Paragraph::new(rendered), inner);
}
