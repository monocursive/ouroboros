//! Small, terminal-safe rasterizations of the bundled provider logos.
use ratatui::text::Line;

pub fn lines(provider: &str) -> Option<Vec<Line<'static>>> {
    let rows: [u16; 12] = match provider {
        "openai" | "openai_codex" => include!("../../assets/providers/openai.rs"),
        "anthropic" => include!("../../assets/providers/anthropic.rs"),
        "grok" => include!("../../assets/providers/grok.rs"),
        "xai" => include!("../../assets/providers/xai.rs"),
        _ => return None,
    };
    Some(
        (0..6)
            .map(|y| {
                Line::from(
                    (0..12)
                        .map(
                            |x| match ((rows[y * 2] >> x) & 1, (rows[y * 2 + 1] >> x) & 1) {
                                (1, 1) => '█',
                                (1, 0) => '▀',
                                (0, 1) => '▄',
                                _ => ' ',
                            },
                        )
                        .collect::<String>(),
                )
            })
            .collect(),
    )
}
