//! One watched session as plain text: the same conversation, with nothing folded away.
//!
//! ## Why this exists beside the renderer
//!
//! The transcript pane is a *bounded* view. A tool result shows three lines, a command
//! four, a diff twelve, and every one of them sits inside the app's own frame. That is the
//! right shape for a live conversation and the wrong shape for the two questions a person
//! actually asks a terminal — "let me search this" and "let me copy that". Those belong to
//! the terminal, which is why [`super::app::App`] can hand the whole thing back to it:
//! into the native scrollback (`ctrl+x [`) or into `$EDITOR` (`ctrl+x v`).
//!
//! So this module renders the same cells the pane renders — [`transcript_cells::project`]
//! is the single projection, and nothing here re-decides what an event means — but with
//! the render-time caps removed and the gutters, colours, and boxes gone.
//!
//! ## What wraps and what does not
//!
//! Prose wraps at the caller's width: messages, notes, statuses, and details are meant to
//! be read, and a paragraph that runs off the right edge is a paragraph nobody reads.
//!
//! Everything pre-formatted — tool input and output, command output, diffs — is written
//! **verbatim**, one source line per output line. Re-wrapping a unified diff destroys it,
//! and re-wrapping a stack trace or a JSON blob turns a copyable artefact into something
//! that has to be repaired by hand. A long line here is soft-wrapped by the terminal, which
//! is exactly the behaviour that makes a selection yield the logical line back.
//!
//! ## Bounded, and it says so
//!
//! An export can only contain what this client still holds: [`Watch`] keeps
//! [`transcript::WINDOW`] events and the gateway prunes below its own floor. When anything
//! was dropped, the last line of the output says so and names the sequence — an export that
//! looked complete and was not would be worse than no export at all.
//!
//! ## Deterministic
//!
//! Nothing here reads the clock, the environment, or the terminal. The same watch at the
//! same width is the same bytes, which is what makes the snapshot tests below meaningful
//! and what will let `/export` reuse this untouched.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::model::transcript::PresentationEvent;

use super::transcript::{Entry, Watch};
use super::transcript_cells::{self, Cell, Speaker, ToolState};

/// One watched session as plain text, wrapped at `width`.
pub fn transcript(watch: &Watch, width: usize) -> String {
    let entries = watch.entries();
    let stamps = user_message_stamps(&entries);

    let mut out = String::new();
    let width = width.max(20);

    header(&mut out, watch, width);

    let cells = transcript_cells::project(entries);
    let mut said = 0usize;

    for cell in &cells {
        block(&mut out, cell, &stamps, &mut said, width);
    }

    if cells.is_empty() {
        paragraph(&mut out, "Nothing has happened in this session yet.", width);
    }

    footer(&mut out, watch, width);
    out
}

/// The timestamp of every user message, in the order the projection will emit them.
///
/// [`transcript_cells::project`] pushes exactly one `Message { speaker: You }` per
/// [`PresentationEvent::UserMessage`], unconditionally and in sequence order, so the *n*th
/// of one is the *n*th of the other. Agent messages get no stamp because they are the
/// conditional ones — an agent run that streamed only whitespace produces no cell — and a
/// clock that drifted off its own text would be worse than no clock.
fn user_message_stamps(entries: &[Entry<'_>]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Event(event) => matches!(
                PresentationEvent::from_event(event),
                PresentationEvent::UserMessage(_)
            )
            .then(|| event.timestamp.clone()),
            _ => None,
        })
        .collect()
}

fn header(out: &mut String, watch: &Watch, width: usize) {
    rule(out, width);
    line(out, &format!("ouro transcript · {}", watch.id));
    line(
        out,
        &format!(
            "{} · {} events held{}",
            watch.plane.as_str(),
            watch.len(),
            match (watch.floor(), watch.newest()) {
                (_, 0) => String::new(),
                (floor, newest) => format!(" · sequences {}–{newest}", floor + 1),
            }
        ),
    );

    if let Some(status) = &watch.ended {
        line(out, &format!("ended: {status}"));
    }

    rule(out, width);
    out.push('\n');
}

/// The last line, and the only place this file makes a claim about completeness.
fn footer(out: &mut String, watch: &Watch, width: usize) {
    rule(out, width);

    let floor = watch.floor();

    if floor > 0 {
        line(
            out,
            &format!(
                "bounded: everything at or below sequence {floor} was dropped by the gateway \
                 or by this client's {} event window, and is not in this export",
                super::transcript::WINDOW
            ),
        );
    } else {
        line(out, "complete: no history was dropped from this session");
    }

    if watch.undecodable > 0 {
        line(
            out,
            &format!(
                "{} event(s) this build could not decode are counted, not shown",
                watch.undecodable
            ),
        );
    }
}

fn block(out: &mut String, cell: &Cell, stamps: &[String], said: &mut usize, width: usize) {
    match cell {
        Cell::Message {
            speaker: Speaker::You,
            text,
            ..
        } => {
            let stamp = stamps.get(*said).map(String::as_str);
            *said += 1;

            match stamp {
                Some(stamp) => label(out, &format!("you · {stamp}")),
                None => label(out, "you"),
            }
            paragraph(out, text, width);
        }
        Cell::Message {
            speaker: Speaker::Agent,
            text,
            streaming,
        } => {
            label(
                out,
                if *streaming {
                    "agent · still writing"
                } else {
                    "agent"
                },
            );
            paragraph(out, text, width);
        }
        Cell::Tool(tool) => {
            let state = match tool.state {
                ToolState::Running => "running",
                ToolState::Completed => "completed",
                ToolState::Failed => "failed",
            };
            match &tool.call_id {
                Some(call_id) => label(out, &format!("tool {} · {state} · {call_id}", tool.name)),
                None => label(out, &format!("tool {} · {state}", tool.name)),
            }

            if !tool.input.is_null() {
                line(out, "input:");
                verbatim(out, &value_text(&tool.input));
            }

            match &tool.output {
                Some(output) if !output.is_null() => {
                    line(out, "output:");
                    verbatim(out, &value_text(output));
                }
                // Said rather than left blank: a tool row with no output line reads as a
                // tool that returned nothing, which is a different claim from "not yet".
                _ if tool.state == ToolState::Running => line(out, "output: not yet"),
                _ => line(out, "output: none recorded"),
            }

            out.push('\n');
        }
        Cell::CommandOutput(text) => {
            label(out, "command output");
            verbatim(out, text);
            out.push('\n');
        }
        Cell::File(file) => {
            let path = file.path.as_deref().unwrap_or("(path not reported)");
            match &file.kind {
                Some(kind) => label(out, &format!("file {path} · {kind}")),
                None => label(out, &format!("file {path}")),
            }
            out.push('\n');
        }
        Cell::Diff(diff) => {
            let path = diff.path.as_deref().unwrap_or("(path not reported)");
            label(
                out,
                &format!(
                    "diff {path} · +{} −{}{}",
                    diff.additions,
                    diff.deletions,
                    if diff.truncated {
                        " · truncated before it reached this client"
                    } else {
                        ""
                    }
                ),
            );
            verbatim(out, &diff.text);
            out.push('\n');
        }
        Cell::Status {
            label: heading,
            detail,
            ..
        } => {
            label(out, heading);
            paragraph(out, detail, width);
        }
        Cell::ChatNote { text } => {
            paragraph(out, text, width);
        }
        Cell::Divider { text, .. } => {
            paragraph(out, &format!("── {text} ──"), width);
        }
    }
}

/// A block heading. Bare text on its own line: a gutter is exactly what this export exists
/// to remove, so nothing here is drawn with a box character a copy would have to survive.
fn label(out: &mut String, text: &str) {
    line(out, text);
}

fn line(out: &mut String, text: &str) {
    out.push_str(text.trim_end());
    out.push('\n');
}

fn rule(out: &mut String, width: usize) {
    out.push_str(&"─".repeat(width.min(120)));
    out.push('\n');
}

/// Prose, wrapped, with a blank line after it.
fn paragraph(out: &mut String, text: &str, width: usize) {
    for wrapped in wrap(text, width) {
        line(out, &wrapped);
    }

    out.push('\n');
}

/// Pre-formatted content, one source line per output line and no wrapping.
fn verbatim(out: &mut String, text: &str) {
    for source in text.trim_end_matches('\n').split('\n') {
        line(out, source);
    }
}

/// A JSON value as the text a person would want to copy.
///
/// A string is its own contents — a tool that returned a stack trace should export the
/// stack trace, not a quoted one-liner with `\n` in it — and the `{"text": …}` /
/// `{"content": …}` envelope every adapter wraps output in is unwrapped for the same
/// reason. That is the convention [`super::transcript_cells`] already renders by; the
/// difference here is that it applies no byte cap, because an export whose whole purpose
/// is the untruncated result must not truncate.
///
/// Anything else is pretty-printed, which is stable: this crate's `serde_json` has no
/// `preserve_order` feature, so object keys come back sorted.
fn value_text(value: &serde_json::Value) -> String {
    use serde_json::Value;

    match value {
        Value::String(text) => text.clone(),
        Value::Object(fields) => fields
            .get("text")
            .or_else(|| fields.get("content"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| pretty(value)),
        other => pretty(other),
    }
}

fn pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// Word wrapping in terminal cells, preserving the text's own line breaks.
///
/// Its own rather than [`super::transcript_cells`]'s, which wraps into styled `Line`s
/// against a row budget. This one has no budget: an export that dropped a paragraph to
/// stay inside a viewport would be the bounded view it exists to escape.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();

    for source in text.split('\n') {
        if source.trim().is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut current = String::new();
        let mut current_width = 0usize;

        for word in source.split_whitespace() {
            for piece in split_to_width(word, width) {
                let piece_width = piece.width();

                if current.is_empty() {
                    current = piece;
                    current_width = piece_width;
                } else if current_width + 1 + piece_width <= width {
                    current.push(' ');
                    current.push_str(&piece);
                    current_width += 1 + piece_width;
                } else {
                    lines.push(std::mem::take(&mut current));
                    current = piece;
                    current_width = piece_width;
                }
            }
        }

        lines.push(current);
    }

    lines
}

/// A single word cut into pieces no wider than the measure.
///
/// Measured in cells, not characters: a CJK ideograph is two columns and a combining mark
/// is none, so a character count would build lines twice as wide as the pane and hand the
/// terminal something to fold in the wrong place.
fn split_to_width(word: &str, width: usize) -> Vec<String> {
    if word.width() <= width {
        return vec![word.to_string()];
    }

    let mut pieces = Vec::new();
    let mut piece = String::new();
    let mut piece_width = 0usize;

    for character in word.chars() {
        let cells = character.width().unwrap_or(0);

        if piece_width + cells > width && !piece.is_empty() {
            pieces.push(std::mem::take(&mut piece));
            piece_width = 0;
        }

        piece.push(character);
        piece_width += cells;
    }

    if !piece.is_empty() {
        pieces.push(piece);
    }

    pieces
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::model::{Event, Plane};

    use super::super::transcript::{Note, Watch};
    use super::*;

    fn event(sequence: u64, kind: &str, payload: Value) -> Event {
        Event::decode(&json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": format!("2026-08-14T09:0{}:00Z", sequence.min(9)),
            "turn_id": "turn-1",
            "payload": payload
        }))
        .expect("an event")
    }

    /// One session with a message, a tool call whose result is longer than the pane would
    /// ever show, a command, a file, a diff, an approval, and a stream interruption.
    fn session() -> Watch {
        let mut watch = Watch::new(Plane::Interactive, "sess-a1".into());

        watch.absorb(vec![
            event(
                1,
                "input_accepted",
                json!({"text": "Please read the lexer and tell me why the fenced block test \
                                fails on a CRLF fixture."}),
            ),
            event(
                2,
                "output_text_final",
                json!({"text": "I'll read src/lex.rs first, then the fixture."}),
            ),
            event(
                3,
                "tool_call",
                json!({"call_id": "c1", "name": "read", "input": {"path": "src/lex.rs"}}),
            ),
            event(
                4,
                "tool_result",
                json!({
                    "call_id": "c1",
                    "output": {"text": "line one\nline two\nline three\nline four\nline five"},
                    "is_error": false
                }),
            ),
            event(
                5,
                "command_output_delta",
                json!({"text": "running 3 tests\ntest lex::crlf ... FAILED\ntest result: FAILED"}),
            ),
            event(
                6,
                "file_change",
                json!({
                    "status": "modified",
                    "changes": [{"path": "src/lex.rs", "kind": "modified"}],
                    "diff": "--- a/src/lex.rs\n+++ b/src/lex.rs\n@@ -1,3 +1,3 @@\n-    let end = text.find('\\n');\n+    let end = text.find(['\\r', '\\n']);\n     ok"
                }),
            ),
            event(
                7,
                "approval_requested",
                json!({"request_id": "r1", "tool_call": {"command": "cargo test --all"}}),
            ),
        ]);

        watch.note(Note::Lagged { dropped: 4 }, 7);
        watch
    }

    #[test]
    fn an_export_is_stable_at_every_width_it_is_asked_for() {
        for width in [60usize, 100, 160] {
            let text = transcript(&session(), width);

            assert_eq!(
                text,
                transcript(&session(), width),
                "the same session at width {width} must be the same bytes"
            );

            // Every voice, every artefact, at every measure.
            for expected in [
                "ouro transcript · sess-a1",
                "interactive · 7 events held · sequences 1–7",
                "you · 2026-08-14T09:01:00Z",
                "agent",
                "tool read · completed · c1",
                "command output",
                "file src/lex.rs · modified",
                "diff src/lex.rs",
                "Approval needed",
                "Some live updates were missed by the gateway",
            ] {
                assert!(
                    text.contains(expected),
                    "width {width} lost {expected:?}:\n{text}"
                );
            }
        }
    }

    #[test]
    fn prose_is_folded_to_the_measure_and_pre_formatted_content_is_not() {
        let narrow = transcript(&session(), 60);

        // The operator's own sentence is longer than 60 columns and must have been folded.
        let asked: Vec<&str> = narrow
            .lines()
            .skip_while(|line| !line.starts_with("you · "))
            .skip(1)
            .take_while(|line| !line.is_empty())
            .collect();

        assert!(asked.len() > 1, "the question was not wrapped: {asked:?}");
        assert!(
            asked.iter().all(|line| line.width() <= 60),
            "a wrapped line ran past the measure: {asked:?}"
        );

        // The diff is not: a folded `@@` header is a diff nobody can apply.
        assert!(
            narrow.contains("-    let end = text.find('\\n');"),
            "the diff line was rewritten:\n{narrow}"
        );
        assert!(narrow.contains("@@ -1,3 +1,3 @@"), "{narrow}");
    }

    #[test]
    fn a_tool_result_is_whole_rather_than_the_three_lines_the_pane_shows() {
        let text = transcript(&session(), 100);

        for line in [
            "line one",
            "line two",
            "line three",
            "line four",
            "line five",
        ] {
            assert!(text.contains(line), "{line} was truncated away:\n{text}");
        }
    }

    #[test]
    fn the_last_line_says_whether_anything_was_dropped() {
        let complete = transcript(&session(), 100);
        assert!(
            complete
                .trim_end()
                .ends_with("complete: no history was dropped from this session"),
            "{complete}"
        );

        let mut pruned = session();
        pruned.raise_floor(3);
        let bounded = transcript(&pruned, 100);

        assert!(
            bounded.trim_end().ends_with("is not in this export"),
            "{bounded}"
        );
        assert!(
            bounded.contains("everything at or below sequence 3 was dropped"),
            "{bounded}"
        );
    }

    #[test]
    fn an_empty_session_exports_a_sentence_rather_than_a_header_and_nothing() {
        let watch = Watch::new(Plane::Coding, "sess-empty".into());
        let text = transcript(&watch, 80);

        assert!(text.contains("coding · 0 events held"), "{text}");
        assert!(
            text.contains("Nothing has happened in this session yet."),
            "{text}"
        );
    }

    #[test]
    fn a_double_width_word_is_cut_on_a_cell_boundary_not_a_character_one() {
        let lines = wrap(&"漢".repeat(40), 20);

        assert!(
            lines.iter().all(|line| line.width() <= 20),
            "a CJK run overflowed the measure: {lines:?}"
        );
        assert_eq!(lines.concat(), "漢".repeat(40), "characters were lost");
    }
}
