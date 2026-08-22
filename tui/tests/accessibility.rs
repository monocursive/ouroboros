//! A10: screen-reader mode and reduced motion, as they reach the drawn rows.
//!
//! The pure half — how a config file, a flag, and three environment variables resolve, and
//! what each label and truncation marker says — is unit-tested beside the code in
//! `src/ui/access.rs`. What is here is what only a rendering can show: that every cell kind
//! comes out as a labelled line with no box drawing in it, that an overlay's rows are
//! numbered and a digit picks one, that the caret and the spinner stop moving, and that the
//! bell rings whether or not this terminal has focus.
//!
//! ## Why these tests serialise
//!
//! Screen-reader mode is a process-wide flag, for the reason `src/ui/access.rs` gives: the
//! renderers that need it are functions with no handle on any state. `cargo test` runs a
//! binary's tests on many threads, so [`MODE`] is the mutex that makes each of these the
//! only one with the flag set, and every one of them puts it back.

mod support;

use std::sync::{Mutex, MutexGuard};

use ratatui::style::Modifier;
use ratatui::text::Line;
use serde_json::json;

use ouro::config::{NotifyMode, NotifyWhen};
use ouro::model::transcript::Diff;
use ouro::ui::access::{self, Label, Settings};
use ouro::ui::notify::{self, Channel, Terminal};
use ouro::ui::transcript_cells::{
    render_cells_at, Cell, FileCell, Speaker, ThinkingState, Tone, ToolCell, ToolState, Verbosity,
};

static MODE: Mutex<()> = Mutex::new(());

struct Held<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        access::install(Settings::default());
    }
}

fn holding(settings: Settings) -> Held<'static> {
    let guard = MODE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    access::install(settings);

    Held { _guard: guard }
}

fn screen_reader() -> Held<'static> {
    holding(Settings {
        screen_reader: true,
        reduced_motion: true,
    })
}

/// Every character a box, a gutter, a glyph column, or a spinner is drawn out of.
///
/// Listed rather than derived: "no box drawing" has to mean a specific set of code points
/// or it means whatever the next renderer decides it means.
const DRAWING: [char; 21] = [
    '┌', '┐', '└', '┘', '│', '├', '┤', '─', '┬', '┴', '┼', '▌', '◆', '◇', '•', '✓', '✗', '…', '·',
    '⠋', '⠹',
];

fn text_of(lines: &[Line<'static>]) -> String {
    lines
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

fn assert_plain(text: &str) {
    if let Some(found) = text.chars().find(|c| DRAWING.contains(c)) {
        panic!("screen-reader mode drew {found:?}\n{text}");
    }
}

fn tool(name: &str, state: ToolState) -> ToolCell {
    ToolCell {
        call_id: Some("call-1".into()),
        name: name.into(),
        kind: Some("execute".into()),
        input: json!({ "command": "cargo test" }),
        output: Some(json!("ok")),
        state,
        started_at: Some(1_000),
        settled_at: Some(2_400),
    }
}

/// One cell of every kind the projection can produce a labelled line for.
fn every_kind() -> Vec<(&'static str, Cell)> {
    vec![
        (
            "user message",
            Cell::Message {
                speaker: Speaker::You,
                text: "run the tests please".into(),
                streaming: false,
            },
        ),
        (
            "agent message",
            Cell::Message {
                speaker: Speaker::Agent,
                text: "Running them now.".into(),
                streaming: false,
            },
        ),
        (
            "agent message still streaming",
            Cell::Message {
                speaker: Speaker::Agent,
                text: "Running".into(),
                streaming: true,
            },
        ),
        (
            "thinking",
            Cell::Thinking {
                text: "The test suite is large.".into(),
                lines: 3,
                state: ThinkingState::Collapsed,
            },
        ),
        ("tool", Cell::Tool(tool("Bash", ToolState::Completed))),
        ("failed tool", Cell::Tool(tool("Bash", ToolState::Failed))),
        (
            "command output",
            Cell::CommandOutput("test result: ok. 12 passed".into()),
        ),
        (
            "file",
            Cell::File(FileCell {
                path: Some("src/lib.rs".into()),
                kind: Some("modified".into()),
            }),
        ),
        (
            "error status",
            Cell::Status {
                label: "Turn failed".into(),
                detail: "the provider hung up".into(),
                tone: Tone::Error,
            },
        ),
        (
            "warning status",
            Cell::Status {
                label: "Interrupted".into(),
                detail: "you stopped the turn".into(),
                tone: Tone::Warning,
            },
        ),
        (
            "approval status",
            Cell::Status {
                label: "Approval needed".into(),
                detail: "rm -rf build".into(),
                tone: Tone::Warning,
            },
        ),
        (
            "divider",
            Cell::Divider {
                text: "Turn finished in 4.2s".into(),
                tone: Tone::Muted,
                kind: ouro::ui::transcript_cells::DividerKind::Other,
            },
        ),
        (
            "chat note",
            Cell::ChatNote {
                text: "this turn's words were not recorded".into(),
            },
        ),
    ]
}

#[test]
fn every_cell_kind_comes_out_as_a_labelled_line_with_no_box_drawing() {
    let _held = screen_reader();

    for (what, cell) in every_kind() {
        let lines = render_cells_at(&[cell], 100, 7, Verbosity::Compact);
        let text = text_of(&lines);

        assert!(!text.trim().is_empty(), "{what} drew nothing");
        assert_plain(&text);
    }
}

#[test]
fn the_labels_are_the_canonical_taxonomy() {
    let _held = screen_reader();

    let rendered = |cell: Cell| text_of(&render_cells_at(&[cell], 100, 0, Verbosity::Compact));

    let you = rendered(Cell::Message {
        speaker: Speaker::You,
        text: "hello".into(),
        streaming: false,
    });
    assert!(you.starts_with("you:"), "{you:?}");

    let agent = rendered(Cell::Message {
        speaker: Speaker::Agent,
        text: "hello".into(),
        streaming: false,
    });
    assert!(agent.starts_with("agent:"), "{agent:?}");

    let streaming = rendered(Cell::Message {
        speaker: Speaker::Agent,
        text: "hel".into(),
        streaming: true,
    });
    assert!(
        streaming.starts_with("agent: still writing"),
        "{streaming:?}"
    );

    let thinking = rendered(Cell::Thinking {
        text: "hmm".into(),
        lines: 1,
        state: ThinkingState::Collapsed,
    });
    assert!(thinking.starts_with("thinking: 1 lines"), "{thinking:?}");

    let ran = rendered(Cell::Tool(tool("Bash", ToolState::Completed)));
    assert!(ran.starts_with("tool: "), "{ran:?}");

    let failed = rendered(Cell::Tool(tool("Bash", ToolState::Failed)));
    assert!(failed.starts_with("tool error: "), "{failed:?}");

    let failure = rendered(Cell::Status {
        label: "Turn failed".into(),
        detail: "gone".into(),
        tone: Tone::Error,
    });
    assert!(failure.starts_with("error: turn failed"), "{failure:?}");

    let warned = rendered(Cell::Status {
        label: "Interrupted".into(),
        detail: "you stopped it".into(),
        tone: Tone::Warning,
    });
    assert!(warned.starts_with("warning: interrupted"), "{warned:?}");

    // Said once: the projection's own heading already carries these words.
    let approval = rendered(Cell::Status {
        label: "Approval needed".into(),
        detail: "rm -rf build".into(),
        tone: Tone::Warning,
    });
    assert!(approval.starts_with("approval needed:"), "{approval:?}");
    assert_eq!(
        approval.matches("approval needed").count(),
        1,
        "the label was said twice: {approval:?}"
    );

    // Every label in the taxonomy is one this renderer can actually produce.
    for label in Label::ALL {
        assert!(label.as_str().ends_with(':'), "{:?}", label.as_str());
    }
}

#[test]
fn a_truncation_marker_is_a_sentence_rather_than_an_ellipsis() {
    let long = (0..90)
        .map(|n| format!("line {n}"))
        .collect::<Vec<_>>()
        .join("\n");

    let cell = || Cell::CommandOutput(long.clone());

    {
        // `/raw` writes everything: it is a copying view and there is nothing to mark.
        let _held = holding(Settings::default());
        let raw = text_of(&render_cells_at(&[cell()], 100, 0, Verbosity::Raw));
        assert!(raw.contains("line 89"), "raw mode dropped a line:\n{raw}");
        assert!(!raw.contains("not shown here"), "{raw}");
    }

    let _held = screen_reader();
    let spoken = text_of(&render_cells_at(&[cell()], 100, 0, Verbosity::Compact));

    assert!(!spoken.contains('…'), "{spoken}");
    assert!(!spoken.contains('·'), "{spoken}");
    assert!(
        spoken.contains("more lines not shown here; press ctrl+o to show all"),
        "the marker was not a sentence:\n{spoken}"
    );
    // The count is the count, not a rounding.
    assert!(spoken.contains("58 more lines"), "{spoken}");
}

#[test]
fn a_diff_keeps_its_signs_without_a_gutter() {
    let _held = screen_reader();

    let text = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,2 @@\n-old line\n+new line\n";
    let diff = Diff {
        path: Some("src/lib.rs".into()),
        text: text.into(),
        additions: 1,
        deletions: 1,
        truncated: false,
    };
    let parsed = ouro::ui::diff::parse(&diff.text, diff.path.as_deref());

    let rendered = text_of(&render_cells_at(
        &[Cell::Diff(ouro::ui::transcript_cells::DiffCell {
            diff,
            parsed,
            pending_approval: false,
        })],
        100,
        0,
        Verbosity::Compact,
    ));

    assert!(rendered.contains("+new line"), "{rendered}");
    assert!(rendered.contains("-old line"), "{rendered}");
    // No frame, no `│` gutter — the sign column is the whole signal, and it is ASCII.
    for drawn in ['┌', '│', '└', '─'] {
        assert!(!rendered.contains(drawn), "{drawn:?} survived\n{rendered}");
    }
}

#[test]
fn the_working_indicator_is_a_word_rather_than_a_spinning_glyph() {
    {
        // Held even for the "off" half: the flag is process-wide, and reading it without
        // the lock is reading whatever another test happened to leave there.
        let _held = holding(Settings::default());
        let ordinary = ouro::ui::theme::working(3, "Working");
        let spun: String = ordinary
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(spun.chars().any(|c| "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏".contains(c)), "{spun:?}");
    }

    let _held = screen_reader();
    let plain = ouro::ui::theme::working(3, "Working");
    let said: String = plain
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect();

    assert!(said.starts_with("working: "), "{said:?}");
    assert_plain(&said);
}

#[test]
fn reduced_motion_holds_the_spinner_and_the_caret_still() {
    let _held = holding(Settings {
        screen_reader: false,
        reduced_motion: true,
    });

    // The spinner is one frame forever.
    let frames: Vec<char> = (0..20).map(ouro::ui::theme::spinner).collect();
    assert!(
        frames.windows(2).all(|pair| pair[0] == pair[1]),
        "the spinner still advances: {frames:?}"
    );

    // …and so is the verb beside it.
    let verbs: Vec<&str> = (0..200)
        .step_by(7)
        .map(ouro::ui::theme::working_verb)
        .collect();
    assert!(
        verbs.windows(2).all(|pair| pair[0] == pair[1]),
        "the verb still rotates: {verbs:?}"
    );

    // The streaming caret is present on every tick rather than half of them.
    let cell = || Cell::Message {
        speaker: Speaker::Agent,
        text: "still going".into(),
        streaming: true,
    };
    for tick in 0..16 {
        let text = text_of(&render_cells_at(&[cell()], 60, tick, Verbosity::Compact));
        assert!(text.contains('▌'), "tick {tick} lost the caret:\n{text}");
    }
}

#[test]
fn motion_is_still_motion_when_nothing_asked_for_it_to_stop() {
    let _held = holding(Settings::default());

    let frames: Vec<char> = (0..20).map(ouro::ui::theme::spinner).collect();
    assert!(
        frames.windows(2).any(|pair| pair[0] != pair[1]),
        "the spinner stopped without being asked: {frames:?}"
    );

    let blinked = (0..16).any(|tick| {
        !text_of(&render_cells_at(
            &[Cell::Message {
                speaker: Speaker::Agent,
                text: "still going".into(),
                streaming: true,
            }],
            60,
            tick,
            Verbosity::Compact,
        ))
        .contains('▌')
    });
    assert!(blinked, "the caret stopped blinking without being asked");
}

#[test]
fn a_menu_row_is_numbered_and_the_number_is_the_key() {
    let _held = screen_reader();

    assert_eq!(access::numbered(0, "Yes"), "1. Yes");
    assert_eq!(access::numbered(3, "No"), "4. No");
    // Past nine there is no digit to press, so there is no number claiming there is.
    assert_eq!(access::numbered(9, "Tenth"), "   Tenth");

    assert_eq!(access::row_for_digit('4'), Some(3));
    assert_eq!(access::row_for_digit('0'), None);
}

#[test]
fn nothing_is_numbered_while_the_mode_is_off() {
    let _held = holding(Settings::default());
    assert_eq!(access::numbered(0, "Yes"), "Yes");
}

#[test]
fn a_block_keeps_its_edges_until_screen_reader_mode_takes_them() {
    use ratatui::widgets::Borders;

    {
        let _held = holding(Settings::default());
        assert_eq!(access::borders(Borders::ALL), Borders::ALL);
        assert_eq!(access::borders(Borders::BOTTOM), Borders::BOTTOM);
    }

    let _held = screen_reader();
    assert_eq!(access::borders(Borders::ALL), Borders::NONE);
    assert_eq!(access::borders(Borders::BOTTOM), Borders::NONE);
}

#[test]
fn the_bell_rings_whether_or_not_this_terminal_has_focus() {
    let iterm = Terminal {
        program: Some("iTerm.app".into()),
        term: Some("xterm-256color".into()),
    };

    {
        let _held = holding(Settings::default());
        // Focused and unfocused are different answers, and a terminal that renders OSC 9
        // gets a desktop notification rather than a beep.
        assert!(!notify::permitted(NotifyWhen::Unfocused, true));
        assert_eq!(
            notify::channel(NotifyMode::Auto, &iterm),
            Some(Channel::Osc9)
        );
    }

    let _held = screen_reader();
    assert!(notify::permitted(NotifyWhen::Unfocused, true));
    assert!(notify::permitted(NotifyWhen::Unfocused, false));
    // The bell is the channel that reaches someone who is listening rather than looking.
    assert_eq!(
        notify::channel(NotifyMode::Auto, &iterm),
        Some(Channel::Bell)
    );
    // …and an explicit answer is still the operator's.
    assert_eq!(notify::channel(NotifyMode::Off, &iterm), None);
    assert_eq!(
        notify::channel(NotifyMode::Osc9, &iterm),
        Some(Channel::Osc9)
    );
}

#[test]
fn the_frame_is_bracketed_by_osc_133_only_in_screen_reader_mode() {
    /// A `Write` whose bytes are readable afterwards. `CrosstermBackend` owns its writer
    /// and does not lend it back, so the test keeps the other end.
    #[derive(Clone, Default)]
    struct Tap(std::sync::Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Tap {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("the tap").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn drawn() -> String {
        let tap = Tap::default();
        // A fixed viewport, because a `CrosstermBackend` over a plain buffer would ask the
        // process's own terminal how big it is and this one has none.
        let mut terminal = ratatui::Terminal::with_options(
            ratatui::backend::CrosstermBackend::new(tap.clone()),
            ratatui::TerminalOptions {
                viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 80, 24)),
            },
        )
        .expect("a terminal over a buffer");

        ouro::ui::draw_synchronized(&mut terminal, |frame| {
            frame.render_widget(ratatui::widgets::Paragraph::new("hello"), frame.area());
        })
        .expect("a frame");

        let bytes = tap.0.lock().expect("the tap").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    {
        let _held = holding(Settings::default());
        let bytes = drawn();
        assert!(!bytes.contains(access::PROMPT_START), "{bytes:?}");
        assert!(!bytes.contains(access::PROMPT_END), "{bytes:?}");
    }

    let _held = screen_reader();
    let bytes = drawn();

    let start = bytes
        .find(access::PROMPT_START)
        .unwrap_or_else(|| panic!("no OSC 133 A in {bytes:?}"));
    let end = bytes
        .find(access::PROMPT_END)
        .unwrap_or_else(|| panic!("no OSC 133 B in {bytes:?}"));

    assert!(start < end, "the markers were emitted out of order");
    // Inside the synchronized bracket, where the cursor escapes already are.
    let open = bytes.find("\x1b[?2026h");
    let close = bytes.find("\x1b[?2026l");
    if let (Some(open), Some(close)) = (open, close) {
        assert!(
            open < start && end < close,
            "a marker leaked out of the frame"
        );
    }
}

#[test]
fn raw_mode_keeps_its_own_shorthand_when_nobody_asked_for_words() {
    let _held = holding(Settings::default());

    let text = text_of(&render_cells_at(
        &[Cell::Message {
            speaker: Speaker::Agent,
            text: "hello".into(),
            streaming: true,
        }],
        80,
        0,
        Verbosity::Raw,
    ));

    // `/raw` is for a selection, not a voice: no colons, no sentences.
    assert!(text.starts_with("agent · still writing"), "{text:?}");
}

#[test]
fn screen_reader_mode_outranks_raw_mode() {
    let _held = screen_reader();

    let text = text_of(&render_cells_at(
        &[Cell::Message {
            speaker: Speaker::You,
            text: "hello".into(),
            streaming: false,
        }],
        80,
        0,
        Verbosity::Raw,
    ));

    assert!(text.starts_with("you:"), "{text:?}");
}

#[test]
fn without_colour_a_diff_still_tells_its_two_halves_apart() {
    use ouro::ui::theme::{self, Palette};

    // The palette is process-wide too, and the diff tests in this binary read it.
    let _held = holding(Settings::default());
    let before = theme::current().palette;
    theme::install(Palette::Monochrome);

    let added = theme::diff_added();
    let removed = theme::diff_removed();

    assert_eq!(added.fg, None, "monochrome painted an addition");
    assert_eq!(removed.fg, None, "monochrome painted a removal");
    assert_ne!(
        added.add_modifier, removed.add_modifier,
        "the two halves are indistinguishable without colour"
    );
    assert!(added.add_modifier.contains(Modifier::BOLD));

    theme::install(before);
}
