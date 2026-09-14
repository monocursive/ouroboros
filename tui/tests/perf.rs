//! Full-history rendering and scrolling performance.
//!
//! Complete replies are projected once per event revision. The conversation retains its
//! laid-out rows and redraws only a changed suffix or animated cells; idle frames and scrolling
//! must not parse old prose again. These tests exercise that same cache, with 5,000
//! mixed events and a prose-heavy conversation, rather than measuring a truncated tail.

mod support;

use std::time::{Duration, Instant};

use serde_json::json;

use ouro::model::{Event, Plane};
use ouro::ui::markdown;
use ouro::ui::transcript::Watch;
use ouro::ui::transcript_cells::{self, Verbosity};

const HISTORY_SIZE: usize = 5_000;
/// The terminal width this gate measures at.
const WIDTH: u16 = 120;

/// The debug-build ceiling for one frame.
///
/// An order-of-magnitude tripwire for warm redraws, not a stopwatch.
const FRAME_CEILING: Duration = Duration::from_millis(40);

fn event(sequence: u64, kind: &str, payload: serde_json::Value) -> Event {
    Event::decode(&json!({
        "id": format!("evt-{sequence}"),
        "sequence": sequence,
        "type": kind,
        "timestamp": format!("2026-01-01T{:02}:{:02}:{:02}.000000Z", sequence / 3600, sequence / 60 % 60, sequence % 60),
        "turn_id": format!("turn-{}", sequence / 10),
        "payload": payload,
    }))
    .expect("an event")
}

fn agent_markdown(turn: u64) -> String {
    format!(
        "## Turn {turn}\n\n\
         I looked at the failing case and it comes down to **three** things:\n\n\
         1. the parser keeps `state` across lines\n\
         2. the wrapper collapses runs of spaces\n\
         3. the memo is keyed on width alone\n\n\
         | file | change |\n|---|---|\n| `src/lib.rs` | rewrote `parse` |\n\
         | `src/ui.rs` | widened the key |\n\n\
         ```rust\n\
         fn parse(text: &str) -> Result<Ast> {{\n\
         \x20   // turn {turn}\n\
         \x20   let mut cursor = 0;\n\
         \x20   while cursor < text.len() {{\n\
         \x20       cursor += 1;\n\
         \x20   }}\n\
         \x20   Ok(Ast::default())\n\
         }}\n\
         ```\n\n\
         > The remaining question is whether the width belongs in the key at all.\n"
    )
}

fn diff_text(turn: u64) -> String {
    format!(
        "--- a/src/ui/render.rs\n\
         +++ b/src/ui/render.rs\n\
         @@ -{},8 +{},9 @@ fn render(width: usize) {{\n\
         \x20    let mut lines = Vec::new();\n\
         -    for cell in cells {{\n\
         -        lines.extend(render_cell(cell, width));\n\
         +    for cell in cells.iter().take(visible) {{\n\
         +        lines.extend(render_cell(cell, width));\n\
         +        // turn {turn}\n\
         \x20    }}\n\
         \x20    lines\n\
         \x20}}\n",
        turn * 3,
        turn * 3
    )
}

/// One session of `count` events, in the proportions a real one arrives in.
///
/// Ten events to a turn, cycling through every kind that produces a cell with work behind
/// it. A synthetic session of five thousand `output_text_final`s would measure the one
/// renderer that is already memoised and nothing else.
fn synthetic(count: u64) -> Watch {
    let mut watch = Watch::new(Plane::Interactive, "perf-session".into());
    let mut events = Vec::with_capacity(count as usize);

    for sequence in 1..=count {
        let turn = sequence / 10;

        let (kind, payload) = match sequence % 10 {
            0 => ("turn_started", json!({})),
            1 => (
                "input_accepted",
                json!({ "text": format!("please look at the failing case in turn {turn}") }),
            ),
            2 => (
                "reasoning_delta",
                json!({
                    "text": format!(
                        "The failure is in the wrapper.\nIt collapses spaces.\n\
                         That destroys indentation for turn {turn}.\n"
                    )
                }),
            ),
            3 => (
                "tool_call",
                json!({
                    "id": format!("call-{sequence}"),
                    "name": "Read",
                    "kind": "read",
                    "input": { "path": format!("src/ui/render_{turn}.rs"), "limit": 200 }
                }),
            ),
            4 => (
                "tool_result",
                json!({
                    "id": format!("call-{sequence}"),
                    "tool_call_id": format!("call-{}", sequence - 1),
                    "output": {
                        "lines": 200,
                        "bytes": 8_192,
                        "excerpt": "fn render(width: usize) -> Vec<Line<'static>> { … }"
                    }
                }),
            ),
            5 => (
                "command_output_delta",
                json!({
                    "text": format!(
                        "   Compiling ouro v0.1.0\n\
                         warning: unused variable `turn` ({turn})\n\
                             Finished dev profile in 4.02s\n"
                    )
                }),
            ),
            6 => (
                "file_change",
                json!({
                    "path": "src/ui/render.rs",
                    "kind": "modified",
                    "diff": diff_text(turn),
                    "additions": 3,
                    "deletions": 2
                }),
            ),
            7 => ("output_text_final", json!({ "text": agent_markdown(turn) })),
            8 => (
                "usage",
                json!({
                    "input_tokens": 12_400 + turn,
                    "output_tokens": 820,
                    "total_tokens": 13_220 + turn
                }),
            ),
            _ => (
                "turn_completed",
                json!({ "outcome": "completed", "detail": "" }),
            ),
        };

        events.push(event(sequence, kind, payload));
    }

    watch.absorb(events);
    watch
}

fn chat_heavy(count: u64) -> Watch {
    let mut watch = Watch::new(Plane::Interactive, "chat-session".into());
    let events = (1..=count)
        .map(|sequence| match sequence % 2 {
            0 => event(
                sequence,
                "output_text_final",
                json!({ "text": agent_markdown(sequence) }),
            ),
            _ => event(
                sequence,
                "input_accepted",
                json!({ "text": format!("and what about case {sequence}?") }),
            ),
        })
        .collect();

    watch.absorb(events);
    watch
}

fn frame(watch: &mut Watch, tick: u64) -> usize {
    watch
        .chat_lines(WIDTH as usize, tick, Verbosity::Compact)
        .len()
}

fn worst_warm(watch: &mut Watch) -> Duration {
    let _ = frame(watch, 0);
    (1..=8)
        .map(|tick| {
            let started = Instant::now();
            let _ = frame(watch, tick);
            started.elapsed()
        })
        .max()
        .unwrap()
}

#[test]
fn five_thousand_entries_render_one_frame_inside_the_budget() {
    let mut watch = synthetic(HISTORY_SIZE as u64);
    let started = Instant::now();
    assert!(frame(&mut watch, 0) > 0);
    let cold = started.elapsed();
    let warm = worst_warm(&mut watch);
    println!("full history: cold {cold:?}, warm {warm:?}");
    assert!(
        warm < FRAME_CEILING,
        "warm frame {warm:?} exceeds {FRAME_CEILING:?}"
    );
}

#[test]
fn a_ten_times_longer_conversation_does_not_make_idle_frames_ten_times_slower() {
    let small = worst_warm(&mut synthetic(500));
    let large = worst_warm(&mut synthetic(HISTORY_SIZE as u64));
    assert!(
        large <= small * 4 + Duration::from_millis(1),
        "500 events {small:?}, 5000 events {large:?}"
    );
}

#[test]
fn scrolling_a_prose_heavy_conversation_does_not_reparse_old_messages() {
    let mut watch = chat_heavy(HISTORY_SIZE as u64);
    markdown::clear_memo();
    let rows = frame(&mut watch, 0);
    assert!(rows > HISTORY_SIZE);
    markdown::reset_memo_stats();
    for tick in 1..=40 {
        assert_eq!(frame(&mut watch, tick), rows);
    }
    let stats = markdown::memo_stats();
    assert_eq!(stats.misses, 0, "scrolling re-parsed settled prose");
    assert_eq!(stats.hits, 0, "scrolling revisited the Markdown renderer");
    assert!(stats.entries <= markdown::MEMO_ENTRIES);
    assert!(stats.bytes <= markdown::MEMO_BYTES);
}

#[test]
fn new_output_renders_only_the_changed_suffix_of_a_long_conversation() {
    let mut watch = chat_heavy(HISTORY_SIZE as u64);
    let _ = frame(&mut watch, 0);
    markdown::reset_memo_stats();
    watch.absorb(vec![event(
        HISTORY_SIZE as u64 + 1,
        "output_text_final",
        json!({"text":"newest answer"}),
    )]);
    let lines = watch.chat_lines(WIDTH as usize, 1, Verbosity::Compact);
    assert!(lines
        .iter()
        .any(|line| line.to_string().contains("newest answer")));
    let stats = markdown::memo_stats();
    assert_eq!(stats.misses, 1, "only the new answer needs parsing");
    assert_eq!(stats.hits, 0, "settled history should use the layout cache");
    assert_eq!(watch.len(), HISTORY_SIZE + 1);
    assert_eq!(watch.floor(), 0);
}

#[test]
fn an_older_running_tool_does_not_relayout_settled_messages_on_each_tick() {
    let mut watch = chat_heavy(HISTORY_SIZE as u64);
    watch.absorb(vec![event(
        0,
        "tool_call",
        json!({
            "id": "unfinished", "name": "Bash", "input": {"command": "long-running-job"}
        }),
    )]);
    let _ = frame(&mut watch, 0);
    markdown::reset_memo_stats();
    for tick in 1..=8 {
        let _ = frame(&mut watch, tick);
    }
    let stats = markdown::memo_stats();
    assert_eq!(stats.misses, 0);
    assert_eq!(stats.hits, 0, "only the tool's animated rows should redraw");
    let expected =
        transcript_cells::render_at(watch.entries(), WIDTH as usize, 8, Verbosity::Compact);
    assert_eq!(
        watch.chat_lines(WIDTH as usize, 8, Verbosity::Compact),
        expected
    );
}

#[test]
fn live_updates_and_tool_completion_reuse_later_message_layouts() {
    let mut watch = chat_heavy(HISTORY_SIZE as u64);
    watch.absorb(vec![event(
        0,
        "tool_call",
        json!({
            "id":"unfinished", "name":"Bash", "input":{"command":"long-running-job"}
        }),
    )]);
    let _ = frame(&mut watch, 0);
    for (n, kind, payload, misses) in [
        (
            5001,
            "output_text_delta",
            json!({"text":"new streamed answer"}),
            1,
        ),
        (
            5002,
            "tool_result",
            json!({"id":"unfinished", "tool_call_id":"unfinished", "output":"done\nwith several\noutput rows"}),
            1,
        ),
        (
            5003,
            "output_text_final",
            json!({"text":"new streamed answer, complete"}),
            1,
        ),
    ] {
        markdown::clear_memo();
        markdown::reset_memo_stats();
        watch.absorb(vec![event(n, kind, payload)]);
        let started = Instant::now();
        let actual = watch
            .chat_lines(WIDTH as usize, n, Verbosity::Compact)
            .to_vec();
        println!("live event {n}: {:?}", started.elapsed());
        let stats = markdown::memo_stats();
        assert_eq!(
            stats.misses, misses,
            "settled messages must survive earlier tool updates"
        );
        assert_eq!(stats.hits, 0);
        let expected =
            transcript_cells::render_at(watch.entries(), WIDTH as usize, n, Verbosity::Compact);
        assert_eq!(actual, expected);
    }
}

#[test]
fn cached_layout_matches_the_complete_projection_after_resize_and_new_output() {
    let mut watch = synthetic(HISTORY_SIZE as u64);
    for (width, tick, verbosity) in [
        (120, 0, Verbosity::Compact),
        (60, 1, Verbosity::Verbose),
        (80, 2, Verbosity::Raw),
    ] {
        let expected = transcript_cells::render_at(watch.entries(), width, tick, verbosity);
        assert_eq!(
            watch.chat_lines(width, tick, verbosity),
            expected.as_slice()
        );
    }
    watch.absorb(vec![event(
        HISTORY_SIZE as u64 + 1,
        "output_text_delta",
        json!({"text":"streamed suffix"}),
    )]);
    for tick in 3..=8 {
        let expected = transcript_cells::render_at(watch.entries(), 100, tick, Verbosity::Compact);
        assert_eq!(
            watch.chat_lines(100, tick, Verbosity::Compact),
            expected.as_slice()
        );
    }
}

#[test]
fn cached_layout_reconciles_replay_tool_completion_and_stream_finalization() {
    use ouro::ui::transcript::Note;

    let mut watch = Watch::new(Plane::Interactive, "replay".into());
    let events = [
        event(1, "input_accepted", json!({"text":"please review"})),
        event(
            3,
            "tool_call",
            json!({"id":"read", "name":"Read", "input":{"path":"src/lib.rs"}}),
        ),
        event(4, "output_text_delta", json!({"text":"Review starts"})),
        // Out-of-order replay fills a hole in the cached prefix.
        event(2, "output_text_final", json!({"text":"I'll inspect it."})),
        event(
            5,
            "tool_result",
            json!({"id":"read", "tool_call_id":"read", "output":"file contents"}),
        ),
        event(6, "output_text_delta", json!({"text":" and ends here."})),
        event(
            7,
            "output_text_final",
            json!({"text":"Review starts and ends here."}),
        ),
    ];
    for event in events {
        watch.absorb(vec![event]);
        for tick in [0, 5] {
            let expected =
                transcript_cells::render_at(watch.entries(), 100, tick, Verbosity::Compact);
            assert_eq!(watch.chat_lines(100, tick, Verbosity::Compact), expected);
        }
    }
    watch.note(Note::Reconnected, 7);
    let expected = transcript_cells::render_at(watch.entries(), 100, 0, Verbosity::Compact);
    assert_eq!(watch.chat_lines(100, 0, Verbosity::Compact), expected);
    watch.raise_floor(9);
    let expected = transcript_cells::render_at(watch.entries(), 100, 0, Verbosity::Compact);
    assert_eq!(watch.chat_lines(100, 0, Verbosity::Compact), expected);
    watch.end("completed".into());
    let expected = transcript_cells::render_at(watch.entries(), 100, 0, Verbosity::Compact);
    assert_eq!(watch.chat_lines(100, 0, Verbosity::Compact), expected);
}
