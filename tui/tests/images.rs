//! A11: images as they reach the drawn rows, the screen reader, and `/export`.
//!
//! The decisions — which protocol a terminal speaks, how large a picture may be, which
//! paths may be opened, what a header says — are unit-tested beside the code in
//! `src/images.rs`, where they are pure functions over fixtures. What is here is what only
//! a rendering can show: that a placeholder is one line at every width, that it says the
//! same thing to a screen reader as to a screen, that it survives `/export` as a path and
//! never as bytes, and that a path this client would not read is drawn as text rather than
//! quietly dropped.
//!
//! ## Why these tests serialise
//!
//! Screen-reader mode is a process-wide flag, so the two that set it share a mutex and put
//! it back, exactly as `tests/accessibility.rs` does for the same reason.

mod support;

use std::sync::{Mutex, MutexGuard};

use ratatui::text::Line;

use ouro::images::{self, CellPixels, Format};
use ouro::ui::access::{self, Settings};
use ouro::ui::transcript_cells::{render_cells_at, Cell, ImageCell, Verbosity};

static MODE: Mutex<()> = Mutex::new(());

struct Held<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        access::install(Settings::default());
    }
}

fn screen_reader() -> Held<'static> {
    let guard = MODE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    access::install(Settings {
        screen_reader: true,
        reduced_motion: true,
    });

    Held { _guard: guard }
}

fn text(lines: &[Line<'static>]) -> Vec<String> {
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

fn shot() -> ImageCell {
    ImageCell {
        named: ".ouroboros/images/image-7.png".into(),
        pixels: Some((1280, 720)),
        format: Some("png".into()),
        note: None,
    }
}

fn draw(cell: Cell, width: usize) -> Vec<String> {
    text(&render_cells_at(&[cell], width, 0, Verbosity::Compact))
}

#[test]
fn an_image_is_one_labelled_row_at_eighty_and_at_one_hundred_and_twenty_columns() {
    for width in [80usize, 120] {
        let rows = draw(Cell::Image(shot()), width);

        assert_eq!(
            rows.len(),
            1,
            "an image nobody can see costs a transcript one line, not a box: {rows:?}"
        );

        let row = &rows[0];
        assert!(row.contains("1280×720 png"), "{row}");
        assert!(row.contains(".ouroboros/images/image-7.png"), "{row}");
        assert!(
            row.chars().count() <= width,
            "the row must fit the pane it was drawn for: {} at {width}",
            row.chars().count()
        );
    }
}

/// The one thing a narrow pane may do to a placeholder is shorten it — never wrap it into
/// a second row, which would make one image cost two lines on a small terminal.
#[test]
fn a_long_path_is_truncated_rather_than_wrapped() {
    let long = ImageCell {
        named: format!(".ouroboros/images/{}.png", "a".repeat(200)),
        ..shot()
    };

    let rows = draw(Cell::Image(long), 60);

    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].chars().count() <= 60, "{}", rows[0]);
    assert!(rows[0].contains('…'), "{}", rows[0]);
}

/// The four sentences a placeholder can carry instead of a size, and the rule behind each.
#[test]
fn a_placeholder_says_why_it_is_a_placeholder() {
    let cases = [
        (
            "not readable inside this workspace; not read",
            "/etc/passwd",
        ),
        ("no workspace for this session; not read", "shot.png"),
        ("not a format this client reads", "notes.txt"),
        ("could not be read", "gone.png"),
    ];

    for (note, named) in cases {
        let cell = ImageCell {
            named: named.into(),
            pixels: None,
            format: None,
            note: Some(note.into()),
        };

        let rows = draw(Cell::Image(cell), 120);

        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(rows[0].contains("size unknown"), "{}", rows[0]);
        assert!(rows[0].contains(named), "{}", rows[0]);
        assert!(
            rows[0].contains(note),
            "a placeholder that did not say why is a placeholder nobody can act on: {}",
            rows[0]
        );
    }
}

/// The path rule, at the surface that shows it: a file outside the workspace becomes text
/// naming the path, and this client never opened it to find out how big it was.
#[test]
fn a_path_outside_the_workspace_is_drawn_as_text_and_never_read() {
    let root = std::env::temp_dir().join(format!("ouro-a11-{}", std::process::id()));
    let outside = std::env::temp_dir().join(format!("ouro-a11-outside-{}.png", std::process::id()));

    std::fs::create_dir_all(root.join(".ouroboros/images")).expect("a scratch workspace");

    // A real, readable PNG — so that anything reporting its size proves it was opened.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&13u32.to_be_bytes());
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&64u32.to_be_bytes());
    png.extend_from_slice(&48u32.to_be_bytes());
    png.extend_from_slice(&[8, 6, 0, 0, 0]);
    std::fs::write(&outside, &png).expect("a scratch png outside the workspace");

    let described = images::describe(Some(&root), &outside.display().to_string());

    assert_eq!(
        described.header, None,
        "a readable file outside the workspace must still report no size, because it was \
         never opened"
    );
    assert_eq!(described.path, None, "and no path to open it by either");

    let cell = ImageCell {
        named: outside.display().to_string(),
        pixels: None,
        format: None,
        note: described.note.clone(),
    };
    let rows = draw(Cell::Image(cell), 200);

    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains("not readable inside this workspace"),
        "{}",
        rows[0]
    );
    assert!(
        !rows[0].contains("64×48"),
        "reporting the size would mean the file had been opened: {}",
        rows[0]
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_file(&outside);
}

#[test]
fn screen_reader_mode_hears_the_same_sentence_the_screen_shows_and_no_glyph() {
    let plain = draw(Cell::Image(shot()), 120);
    let _held = screen_reader();
    let spoken = draw(Cell::Image(shot()), 120);

    assert_eq!(spoken.len(), 1, "{spoken:?}");
    assert!(spoken[0].contains("1280"), "{}", spoken[0]);
    assert!(spoken[0].contains("720"), "{}", spoken[0]);
    assert!(spoken[0].contains("png"), "{}", spoken[0]);
    assert!(spoken[0].contains("image-7.png"), "{}", spoken[0]);

    assert!(
        !spoken[0].contains('▣'),
        "a glyph a screen reader has to spell out is not a label: {}",
        spoken[0]
    );
    assert!(
        plain[0].contains('▣'),
        "and the glyph is still there for a screen: {}",
        plain[0]
    );
}

/// A11's hard rule for `/export`: by path, never by bytes.
#[test]
fn an_export_carries_the_path_and_never_the_picture() {
    let cell = shot();
    let label = cell.label();

    assert!(label.contains(".ouroboros/images/image-7.png"), "{label}");
    assert!(label.contains("1280×720 png"), "{label}");

    // Nothing in the cell can carry pixels in the first place — it holds a path, two
    // numbers, and a format name — which is what makes the export rule structural rather
    // than a discipline someone has to remember.
    let encoded = images::kitty(b"pretend this is a picture", 10, 4);
    assert!(
        !label.contains(&encoded),
        "an export must never be able to reach the bytes"
    );
    assert!(
        !label.contains("base64") && !label.contains('\u{1b}'),
        "and never an escape sequence: {label}"
    );
}

/// The bound the transcript would place a picture in, at the two widths the placeholder
/// tests use. Here rather than in the unit tests because it is the pane's width that
/// decides it, and that is the number this file is about.
#[test]
fn the_cell_box_for_one_screenshot_is_bounded_by_whichever_edge_binds() {
    let cell = CellPixels::default();

    let (narrow_cols, narrow_rows) = images::fit((1280, 720), cell, 80, images::MAX_ROWS);
    let (wide_cols, wide_rows) = images::fit((1280, 720), cell, 120, images::MAX_ROWS);

    assert_eq!(narrow_cols, 80);
    assert_eq!(wide_cols, 120);
    assert!(narrow_rows <= images::MAX_ROWS && wide_rows <= images::MAX_ROWS);
    assert!(wide_rows > narrow_rows, "{wide_rows} vs {narrow_rows}");

    // A very tall screenshot is held to the row ceiling instead, at both widths.
    for width in [80, 120] {
        let (_cols, rows) = images::fit((900, 30_000), cell, width, images::MAX_ROWS);
        assert_eq!(rows, images::MAX_ROWS, "at {width} columns");
    }
}

#[test]
fn only_a_name_this_client_can_read_is_treated_as_an_image() {
    assert_eq!(images::format_of("shot.png"), Some(Format::Png));
    assert_eq!(images::format_of("shot.svg"), None);
    assert_eq!(images::format_of("README.md"), None);
}
