//! A12: the five-thousand-message gate.
//!
//! R2 §8 records what a long thread costs the field — Amp Neo's 5,000-message thread went
//! from 84.1% CPU and 1,814 MB idle to 17.4% and 540 MB, and OpenCode's issue tracker is
//! what the alternative looks like from the outside. The number is 5,000 because that is
//! the number the field publishes, and because it is [`ouro::ui::transcript::WINDOW`] — the
//! most this client will ever hold for one session.
//!
//! ## What is measured
//!
//! One frame: `Watch::entries` → `transcript_cells::project` → `render_cells_at` at
//! 120×40, over a synthetic session of 5,000 events with the mix a real one has (user
//! turns, agent Markdown with headings, lists, tables and fenced code, reasoning, tool
//! calls with JSON results, command output, unified diffs, plans, usage reports, and turn
//! boundaries).
//!
//! ## The numbers, measured on this machine
//!
//! Apple Silicon, macOS 25.5. The worst of eight warm frames after the caches have filled,
//! three runs each:
//!
//! | build | cold frame | worst warm frame |
//! |---|---|---|
//! | `--release` | 1.2–2.0 ms | **0.63–1.30 ms** |
//! | debug (`cargo test`) | 4.5–4.9 ms | **2.63–2.68 ms** |
//!
//! The release figure is the one A12 budgets — **well under the 16 ms frame**, by more
//! than a factor of twelve at its worst. The ceiling asserted below is the debug one, and
//! deliberately generous: an unoptimised build on a loaded CI box is not what the budget is
//! about, and a gate that fails on a busy machine is a gate people delete. What this
//! catches is the *shape* — an O(entries) renderer, or a cache that stopped answering —
//! and those are order-of-magnitude regressions rather than percentages.
//!
//! ## What the gate found
//!
//! Two things, both fixed in the commit that added this file:
//!
//! * `Watch::entries` built a 5,000-element `Vec` on every frame so that `chat_lines` could
//!   throw away all but the last 128. It is [`Watch::recent_entries`] now, which walks the
//!   tail; the frame went from 3.16 ms to 2.76 ms in debug, and, more to the point, a
//!   500-entry session and a 5,000-entry one now cost the same.
//! * The Markdown memo held sixteen renders against a 128-entry window. On the agentic
//!   fixture that happened to be enough — thirteen agent turns fit in a window of ten
//!   events each — but on a prose-heavy session, where the window holds sixty-four agent
//!   messages, it measured **0 hits in 640 lookups**: every frame evicted exactly what the
//!   next frame wanted, and every settled message on screen re-parsed twelve times a
//!   second. The ceiling is the window now, and the same measurement is 640 of 640.
//!
//! Both numbers above were taken by putting the old constant back and re-running
//! `a_prose_heavy_window_still_fits_in_the_memo`, which is the test that holds them.

mod support;

use std::time::{Duration, Instant};

use serde_json::json;

use ouro::model::{Event, Plane};
use ouro::ui::markdown;
use ouro::ui::transcript::{Watch, WINDOW};
use ouro::ui::transcript_cells::{self, Verbosity};

/// The terminal this gate measures at. A12 names 120×40.
const WIDTH: u16 = 120;
const HEIGHT: u16 = 40;

/// The debug-build ceiling for one frame.
///
/// Deliberately generous — see the module docs. Measured at 2.6–2.7 ms here, so this is
/// fifteen times the observed cost: an order-of-magnitude tripwire, not a stopwatch.
const FRAME_CEILING: Duration = Duration::from_millis(40);

fn event(sequence: u64, kind: &str, payload: serde_json::Value) -> Event {
    Event::decode(&json!({
        "id": format!("evt-{sequence}"),
        "sequence": sequence,
        "type": kind,
        "timestamp": format!("2026-01-01T00:00:{:02}.000000Z", sequence % 60),
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

/// One frame's worth of work: the projection and the rows it becomes.
fn frame(watch: &Watch) -> usize {
    let recent = watch.recent_entries(transcript_cells::CHAT_ENTRY_WINDOW);
    let cells = transcript_cells::project(recent.entries);
    transcript_cells::render_cells_at(&cells, WIDTH as usize, 0, Verbosity::Compact).len()
}

fn time<T>(mut work: impl FnMut() -> T) -> (T, Duration) {
    let started = Instant::now();
    let value = work();
    (value, started.elapsed())
}

#[test]
fn five_thousand_entries_render_one_frame_inside_the_budget() {
    let watch = synthetic(WINDOW as u64);
    assert_eq!(watch.len(), WINDOW, "the window did not fill");

    markdown::clear_memo();

    // The first frame pays for the caches. It is not the frame a person waits on twelve
    // times a second, so it is measured and reported rather than gated.
    let (rows, cold) = time(|| frame(&watch));
    assert!(rows > 0, "the frame drew nothing");

    // Warm: the steady state, which is what a scrolling reader actually experiences.
    let mut worst = Duration::ZERO;
    for _ in 0..8 {
        let (_rows, elapsed) = time(|| frame(&watch));
        worst = worst.max(elapsed);
    }

    println!("perf: 5000 entries · {WIDTH}x{HEIGHT} · cold {cold:?} · worst warm {worst:?}");

    assert!(
        worst <= FRAME_CEILING,
        "a warm frame at {WINDOW} entries took {worst:?}, over the {FRAME_CEILING:?} ceiling \
         (cold frame {cold:?})"
    );
}

#[test]
fn the_cost_of_a_frame_does_not_follow_the_length_of_the_session() {
    // The claim A12 is really about: a session ten times longer is not a frame ten times
    // dearer, because the renderer's cost follows what is on screen.
    let short = synthetic(500);
    let long = synthetic(WINDOW as u64);

    let worst = |watch: &Watch| {
        markdown::clear_memo();
        let _ = frame(watch);

        let mut worst = Duration::ZERO;
        for _ in 0..8 {
            let (_rows, elapsed) = time(|| frame(watch));
            worst = worst.max(elapsed);
        }
        worst
    };

    let small = worst(&short);
    let large = worst(&long);

    println!("perf: 500 entries {small:?} · 5000 entries {large:?}");

    // Ten times the session for at most four times the frame, plus a millisecond of floor
    // so a timer's own noise cannot fail this on an idle machine.
    assert!(
        large <= small * 4 + Duration::from_millis(1),
        "a ten-times-longer session cost {large:?} against {small:?}: the renderer is \
         following the ledger rather than the viewport"
    );
}

/// A session that is mostly prose: one user turn and one agent answer, over and over.
///
/// The shape the memo is sized against, and the one the agentic mix above does *not*
/// exercise: ten events to a turn puts thirteen agent messages inside the window, and a
/// memo of any size at all answers those. Alternating puts sixty-four there.
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

#[test]
fn a_prose_heavy_window_still_fits_in_the_memo() {
    let watch = chat_heavy(WINDOW as u64);

    markdown::clear_memo();
    let _ = frame(&watch);
    markdown::reset_memo_stats();

    for _ in 0..10 {
        let _ = frame(&watch);
    }

    let stats = markdown::memo_stats();
    let rate = stats.hit_rate().expect("the memo was asked something");

    println!(
        "perf: prose-heavy memo {} hits / {} lookups ({:.0}%), {} entries, {} bytes",
        stats.hits,
        stats.hits + stats.misses,
        rate * 100.0,
        stats.entries,
        stats.bytes
    );

    // Sixty-four agent messages in a hundred-and-twenty-eight-entry window. At the old
    // ceiling of sixteen memos this measured 0% — every frame evicted what the next one
    // wanted — and the symptom was a conversation that felt slower the longer it got.
    assert!(
        stats.entries > 32,
        "the fixture is not prose-heavy: only {} memos resident",
        stats.entries
    );
    assert!(
        rate >= 0.99,
        "the memo answered {:.0}% of {} lookups on a prose-heavy window",
        rate * 100.0,
        stats.hits + stats.misses
    );
}

#[test]
fn scrolling_to_the_top_and_back_re_renders_nothing_whose_inputs_did_not_change() {
    let watch = synthetic(WINDOW as u64);

    markdown::clear_memo();
    // Fill the memo with the window that is on screen.
    let _ = frame(&watch);
    markdown::reset_memo_stats();

    // Scrolling does not change which entries are projected — the pane slices *rows* — so
    // every frame drawn on the way up and back down asks the memo for the same messages.
    // Forty frames is a held PageUp and a held PageDown.
    for _ in 0..40 {
        let _ = frame(&watch);
    }

    let stats = markdown::memo_stats();
    let rate = stats.hit_rate().expect("the memo was asked something");

    println!(
        "perf: memo {} hits / {} lookups ({:.0}%), {} entries, {} bytes",
        stats.hits,
        stats.hits + stats.misses,
        rate * 100.0,
        stats.entries,
        stats.bytes
    );

    assert!(
        rate >= 0.99,
        "the memo answered {:.0}% of {} lookups: a scroll is re-rendering settled prose",
        rate * 100.0,
        stats.hits + stats.misses
    );
    assert_eq!(stats.misses, 0, "a settled message was re-rendered");
}

#[test]
fn the_caches_stay_bounded_at_five_thousand_entries() {
    let watch = synthetic(WINDOW as u64);

    markdown::clear_memo();
    for _ in 0..8 {
        let _ = frame(&watch);
    }

    let stats = markdown::memo_stats();

    // The memo is bounded in entries and in bytes, and both ceilings are the module's own.
    assert!(
        stats.entries <= markdown::MEMO_ENTRIES,
        "{} memos resident, ceiling {}",
        stats.entries,
        markdown::MEMO_ENTRIES
    );
    assert!(
        stats.bytes <= markdown::MEMO_BYTES,
        "{} bytes resident, ceiling {}",
        stats.bytes,
        markdown::MEMO_BYTES
    );

    // …and the ledger behind it is the window, not the session. Everything older raised
    // the floor rather than accumulating.
    assert_eq!(watch.len(), WINDOW);
    assert!(
        watch.floor() == 0,
        "a 5,000-event session should sit exactly on the window without dropping any"
    );

    // One more event past the window drops exactly one, visibly.
    let mut watch = watch;
    watch.absorb(vec![event(
        WINDOW as u64 + 1,
        "output_text_final",
        json!({ "text": "one more" }),
    )]);

    assert_eq!(watch.len(), WINDOW, "the window grew");
    assert_eq!(watch.floor(), 1, "the floor did not follow the drop");
}

#[test]
fn a_frame_projects_the_window_rather_than_the_ledger() {
    let watch = synthetic(WINDOW as u64);

    let recent = watch.recent_entries(transcript_cells::CHAT_ENTRY_WINDOW);

    assert_eq!(
        recent.entries.len(),
        transcript_cells::CHAT_ENTRY_WINDOW,
        "the tail was not bounded"
    );
    assert!(recent.omitted > 0, "nothing was reported as left out");
    assert_eq!(
        recent.entries.len() + recent.omitted,
        watch.entries().len(),
        "the omitted count does not add up to the whole ledger"
    );

    // The tail is the tail: the newest entry is the newest entry either way.
    let all = watch.entries();
    assert_eq!(
        format!("{:?}", all.last()),
        format!("{:?}", recent.entries.last()),
        "the bounded walk ended somewhere else"
    );
    assert_eq!(
        format!("{:?}", &all[all.len() - recent.entries.len()..]),
        format!("{:?}", recent.entries),
        "the bounded walk is not the tail of the whole one"
    );
}
