//! The words every golden transcript fixture renders, written out as literals.
//!
//! `test/support/gateway_golden/event_*.json` is one frame per event payload a client has
//! to turn into a sentence. This file is the Rust half of what that corpus is for: each
//! fixture goes through the real pipeline — JSON → [`Event::decode`] →
//! [`PresentationEvent::from_event`] → [`project`] — and every claim below is the finished
//! text, spelled out. No snapshot files and no golden-output library: a reviewer reading
//! this file can see what the client says without running it, and a second implementation
//! reading it knows exactly what it has to say.
//!
//! **These literals are the parity contract.** `Ouroboros.Web` reimplements both stages in
//! Elixir (`docs/WEB.md` §5), and the two suites cannot call each other. The same fixture
//! bytes and the same asserted words on both sides is the only mechanism that keeps them
//! agreeing, so a change to any string here is a change to a contract with another
//! toolchain rather than a test edit.
//!
//! What is deliberately *not* asserted here is layout: widths, colours, wrapping and the
//! ratatui spans are the terminal's own and no browser will reproduce them. Cell kind,
//! the tool summariser's verb/subject/outcome, the note and divider text, and the approval
//! detail fields are the parts both surfaces owe the reader identically.

use std::path::Path;

use serde_json::Value;

use ouro::model::transcript::{Hidden, PlanStatus, PresentationEvent};
use ouro::model::Event;
use ouro::ui::transcript::{ApprovalRequest, Entry};
use ouro::ui::transcript_cells::{
    project, summarise, Block, Cell, DividerKind, Speaker, SubagentCell, ThinkingState, Tone,
    ToolCell, ToolState,
};

/// One fixture's event, decoded the way the transport hands it to the model.
///
/// Read from the checkout rather than embedded, so a regeneration on the Elixir side is
/// picked up by the next `cargo test` with no copy step — the same rule the fixture reader
/// in `src/model.rs` follows.
fn event(name: &str) -> Event {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test/support/gateway_golden")
        .join(format!("{name}.json"));

    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));

    let frame: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("{} is not JSON: {error}", path.display()));

    Event::decode(&frame["params"]["event"])
        .unwrap_or_else(|error| panic!("{name} does not decode as an event: {error}"))
}

fn presentation(name: &str) -> PresentationEvent {
    PresentationEvent::from_event(&event(name))
}

/// The cells one ordered run of fixtures projects to.
fn cells(names: &[&str]) -> Vec<Cell> {
    let events: Vec<Event> = names.iter().map(|name| event(name)).collect();
    project(events.iter().map(Entry::Event).collect())
}

/// The single cell one fixture projects to, when it projects to exactly one.
fn cell(name: &str) -> Cell {
    let mut projected = cells(&[name]);

    assert_eq!(
        projected.len(),
        1,
        "{name} projected to {} cells, not one: {projected:?}",
        projected.len()
    );

    projected.remove(0)
}

fn message(cell: &Cell) -> (Speaker, &str, bool) {
    match cell {
        Cell::Message {
            speaker,
            text,
            streaming,
        } => (*speaker, text.as_str(), *streaming),
        other => panic!("not a message cell: {other:?}"),
    }
}

fn chat_note(cell: &Cell) -> &str {
    match cell {
        Cell::ChatNote { text } => text.as_str(),
        other => panic!("not a chat note: {other:?}"),
    }
}

fn divider(cell: &Cell) -> (&str, Tone) {
    match cell {
        Cell::Divider { text, tone, .. } => (text.as_str(), *tone),
        other => panic!("not a divider: {other:?}"),
    }
}

fn status(cell: &Cell) -> (&str, &str, Tone) {
    match cell {
        Cell::Status {
            label,
            detail,
            tone,
        } => (label.as_str(), detail.as_str(), *tone),
        other => panic!("not a status cell: {other:?}"),
    }
}

fn tool(cell: &Cell) -> &ToolCell {
    match cell {
        Cell::Tool(tool) => tool,
        other => panic!("not a tool cell: {other:?}"),
    }
}

fn runtime_block(cell: &Cell) -> &Block {
    match cell {
        Cell::Runtime(block) => block,
        other => panic!("not a runtime block: {other:?}"),
    }
}

fn subagent(cell: &Cell) -> &SubagentCell {
    match cell {
        Cell::Subagent(child) => child,
        other => panic!("not a subagent cell: {other:?}"),
    }
}

/// The three strings the tool summariser produces, as one tuple to assert against.
fn summary(cell: &Cell) -> (String, String, String) {
    let summarised = summarise(tool(cell));
    (summarised.verb, summarised.subject, summarised.outcome)
}

/// The modal's reading of an approval fixture, built the way the pane builds it.
fn approval(name: &str) -> ApprovalRequest {
    let event = event(name);

    ApprovalRequest {
        request_id: event.request_id.clone().expect("an approval carries one"),
        sequence: event.sequence,
        turn_id: event.turn_id.clone(),
        payload: event.payload.clone(),
    }
}

// ---------------------------------------------------------------------------
// What a person typed
// ---------------------------------------------------------------------------

#[test]
fn an_accepted_prompt_is_the_operators_own_message() {
    assert_eq!(
        presentation("event_input_accepted"),
        PresentationEvent::UserMessage("Check the workspace is clean, then run the suite.".into())
    );

    assert_eq!(
        message(&cell("event_input_accepted")),
        (
            Speaker::You,
            "Check the workspace is clean, then run the suite.",
            false
        )
    );
}

#[test]
fn a_steer_is_a_note_naming_the_words_that_steered() {
    assert_eq!(
        presentation("event_input_accepted_steer"),
        PresentationEvent::UserSteer(Some("actually, skip the slow tests".into()))
    );

    assert_eq!(
        chat_note(&cell("event_input_accepted_steer")),
        "You steered the agent: actually, skip the slow tests"
    );
}

/// The turn whose words the ledger does not hold is still drawn. A transcript that
/// silently omitted it would be a transcript that cannot be trusted about the turns it
/// does show, and this is the exact placeholder both surfaces owe.
#[test]
fn an_acceptance_with_no_recorded_words_is_still_a_row() {
    assert_eq!(
        presentation("event_input_accepted_unrecorded"),
        PresentationEvent::UnrecordedInput
    );

    assert_eq!(
        chat_note(&cell("event_input_accepted_unrecorded")),
        "[message not recorded]"
    );
}

// ---------------------------------------------------------------------------
// What the agent said
// ---------------------------------------------------------------------------

#[test]
fn a_text_delta_is_a_streaming_agent_message_and_a_final_is_a_settled_one() {
    assert_eq!(
        message(&cell("event_output_text_delta")),
        (Speaker::Agent, "Running the suite now.", true)
    );

    assert_eq!(
        message(&cell("event_output_text_final")),
        (
            Speaker::Agent,
            "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
            false
        )
    );
}

/// A delta and the final of the same turn are one cell, not two: the final replaces the
/// draft rather than being appended below it.
#[test]
fn a_delta_and_its_final_settle_into_one_message() {
    let projected = cells(&["event_output_text_delta", "event_output_text_final"]);

    assert_eq!(projected.len(), 1, "{projected:?}");
    assert_eq!(
        message(&projected[0]),
        (
            Speaker::Agent,
            "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
            false
        )
    );
}

/// The case the test above cannot reach: a provider note and a usage row land between the
/// draft and the final that supersedes it.
///
/// A note flushes the pending draft so it can be drawn *after* the words it follows. That
/// leaves nothing for the final to absorb, and both clients used to push a second message
/// carrying the same answer — a duplicate an operator saw in a live browser.
///
/// The corpus is one event per file, so no single fixture can express an interleaving; the
/// ordering is the test's and every payload is the corpus's, which is the same composition
/// `cells` already does elsewhere. `event_output_text_delta_partial` exists for this: its
/// text is a literal prefix of the final's, which the other delta fixture deliberately is
/// not.
#[test]
fn a_final_settles_the_draft_a_note_flushed_early() {
    let projected = cells(&[
        "event_output_text_delta_partial",
        "event_provider_event_compaction",
        "event_usage",
        "event_output_text_final",
        "event_turn_completed",
    ]);

    // One message, and the notes still sit after the words they follow.
    assert_eq!(projected.len(), 4, "{projected:?}");
    assert_eq!(
        message(&projected[0]),
        (
            Speaker::Agent,
            "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
            false
        )
    );
    assert!(matches!(projected[1], Cell::Runtime(_)), "{projected:?}");
    assert!(matches!(projected[2], Cell::Usage(_)), "{projected:?}");
    assert!(
        matches!(
            projected[3],
            Cell::Divider {
                kind: DividerKind::TurnEnd,
                ..
            }
        ),
        "{projected:?}"
    );
}

/// The guard on the rule above: a turn that says something, calls a tool, then says
/// something else must keep both halves. The final's text does not begin with the flushed
/// draft's, so it is a new block and is pushed rather than folded into it.
#[test]
fn a_later_block_of_the_same_turn_is_its_own_message() {
    let projected = cells(&[
        "event_output_text_delta",
        "event_tool_call_bash",
        "event_tool_result_bash",
        "event_output_text_final",
    ]);

    assert_eq!(projected.len(), 3, "{projected:?}");
    assert_eq!(
        message(&projected[0]),
        (Speaker::Agent, "Running the suite now.", false)
    );
    assert!(matches!(projected[1], Cell::Tool(_)), "{projected:?}");
    assert_eq!(
        message(&projected[2]),
        (
            Speaker::Agent,
            "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
            false
        )
    );
}

#[test]
fn reasoning_is_its_own_cell_and_never_the_agents_answer() {
    match cell("event_thinking_delta") {
        Cell::Thinking { text, lines, state } => {
            assert_eq!(
                text,
                "The failure is in the diff parser, not the transport."
            );
            assert_eq!(lines, 1);
            // Last cell drawn, so it is still being watched rather than folded away.
            assert_eq!(state, ThinkingState::Tail);
        }
        other => panic!("not a thinking cell: {other:?}"),
    }
}

#[test]
fn a_command_output_delta_is_its_own_cell() {
    match cell("event_command_output_delta") {
        Cell::CommandOutput(text) => assert_eq!(text, "Compiling ouroboros v0.1.0\n"),
        other => panic!("not a command-output cell: {other:?}"),
    }
}

/// Every `Hidden` arm is a payload that carried no content, never a kind this client
/// declines to show. The corpus carries no empty-text fixture on purpose — an empty
/// `text` is a transport keep-alive rather than a shape a runtime records — so this
/// states the rule against a hand-built payload and keeps the reason readable.
#[test]
fn only_an_empty_payload_is_drawn_as_nothing() {
    let mut empty = event("event_output_text_delta");
    empty.payload = serde_json::json!({"text": ""});

    assert_eq!(
        PresentationEvent::from_event(&empty),
        PresentationEvent::Hidden(Hidden::EmptyText)
    );
    assert_eq!(
        Hidden::EmptyText.reason(),
        "an output event carrying no text"
    );
}

// ---------------------------------------------------------------------------
// What it ran
// ---------------------------------------------------------------------------

#[test]
fn a_claude_command_call_reads_as_bash_and_its_command_line() {
    let projected = cell("event_tool_call_bash");
    let running = tool(&projected);

    assert_eq!(running.name, "Bash");
    assert_eq!(running.kind, None, "the Claude dialect sends no ACP kind");
    assert_eq!(running.state, ToolState::Running);

    assert_eq!(
        summary(&projected),
        (
            "Bash".to_string(),
            "$ mix test --stale".to_string(),
            String::new()
        )
    );
}

#[test]
fn a_command_result_settles_the_call_it_names() {
    let projected = cells(&["event_tool_call_bash", "event_tool_result_bash"]);

    assert_eq!(projected.len(), 1, "one row, not two: {projected:?}");

    let settled = tool(&projected[0]);
    assert_eq!(settled.name, "Bash");
    assert_eq!(settled.state, ToolState::Completed);

    // No `exit N`: no dialect in this build forwards an exit code on the wire — the
    // runtime folds it into `is_error` — so the summary claims nothing about one.
    assert_eq!(
        summary(&projected[0]),
        (
            "Bash".to_string(),
            "$ mix test --stale".to_string(),
            String::new()
        )
    );
}

/// A result whose call this window never saw is still a row. Dropping it because the call
/// is missing would hide work the session did.
#[test]
fn an_orphaned_command_result_is_a_row_of_its_own() {
    let projected = cell("event_tool_result_bash");

    assert_eq!(tool(&projected).name, "Bash");
    assert_eq!(tool(&projected).state, ToolState::Completed);
}

#[test]
fn a_read_folds_into_the_exploration_cell_and_counts_its_lines() {
    match cell("event_tool_call_read") {
        Cell::Exploration(group) => {
            assert_eq!(group.total(), 1);
            // Still the last cell drawn, so the group is open.
            assert!(!group.done);

            let summarised = summarise(&group.calls[0]);
            assert_eq!(summarised.verb, "Read");
            assert_eq!(summarised.subject, "lib/ouroboros/gateway/wire.ex:120-159");
            assert_eq!(summarised.outcome, "");
        }
        other => panic!("a read must group: {other:?}"),
    }

    let settled = cells(&["event_tool_call_read", "event_tool_result_read"]);

    match &settled[0] {
        Cell::Exploration(group) => {
            let summarised = summarise(&group.calls[0]);
            assert_eq!(
                (
                    summarised.verb.as_str(),
                    summarised.subject.as_str(),
                    summarised.outcome.as_str()
                ),
                ("Read", "lib/ouroboros/gateway/wire.ex:120-159", "→ 3 lines")
            );
        }
        other => panic!("a read must group: {other:?}"),
    }
}

/// The ACP dialect names a call in prose and says what it *is* only in `kind`. The
/// summariser reads both: the title is the row's name, the kind is what picks the verb.
#[test]
fn an_acp_edit_reads_as_an_edit_with_the_lines_the_call_carried() {
    let projected = cell("event_tool_call_acp_edit");
    let edit = tool(&projected);

    assert_eq!(edit.name, "Edit lib/ouroboros/web/transcript.ex");
    assert_eq!(edit.kind.as_deref(), Some("edit"));

    assert_eq!(
        summary(&projected),
        (
            "Edit".to_string(),
            "lib/ouroboros/web/transcript.ex (+4 −3)".to_string(),
            String::new()
        )
    );
}

#[test]
fn an_acp_status_of_completed_settles_the_edit_without_an_is_error_field() {
    let projected = cells(&["event_tool_call_acp_edit", "event_tool_result_acp_edit"]);

    assert_eq!(projected.len(), 1, "{projected:?}");
    assert_eq!(tool(&projected[0]).state, ToolState::Completed);
    assert_eq!(
        summary(&projected[0]),
        (
            "Edit".to_string(),
            "lib/ouroboros/web/transcript.ex (+4 −3)".to_string(),
            String::new()
        )
    );
}

/// A Computer Use result is two cells in a fixed order: the tool row, then the picture it
/// produced. The image carries the sha and the size the gateway stated and no bytes — the
/// pixels are fetched by sha through `computer_use.artifact`.
#[test]
fn a_computer_use_result_is_a_tool_row_and_then_a_labelled_image() {
    let projected = cells(&["event_tool_result_computer_use"]);

    assert_eq!(projected.len(), 2, "{projected:?}");
    assert_eq!(tool(&projected[0]).name, "desktop_state");
    assert_eq!(tool(&projected[0]).state, ToolState::Completed);
    assert_eq!(
        summary(&projected[0]),
        ("desktop state".to_string(), String::new(), String::new())
    );

    match &projected[1] {
        Cell::Image(image) => {
            assert_eq!(image.named, "desktop capture · abababababab");
            assert_eq!(image.pixels, Some((1512, 982)));
            assert_eq!(image.format.as_deref(), Some("png"));
            assert_eq!(image.media_type.as_deref(), Some("image/png"));
            assert_eq!(image.sha.as_deref(), Some(&"ab".repeat(32)[..]));
            assert_eq!(image.note, None);
            assert_eq!(
                image.label(),
                "[image 1512×982 png · desktop capture · abababababab]"
            );
        }
        other => panic!("not an image cell: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// What changed
// ---------------------------------------------------------------------------

#[test]
fn a_file_change_is_a_file_row_and_the_patch_under_it() {
    let projected = cells(&["event_file_change"]);

    assert_eq!(projected.len(), 2, "{projected:?}");

    match &projected[0] {
        Cell::File(file) => {
            assert_eq!(
                file.path.as_deref(),
                Some("lib/ouroboros/web/presentation.ex")
            );
            assert_eq!(file.kind.as_deref(), Some("update"));
        }
        other => panic!("not a file cell: {other:?}"),
    }

    match &projected[1] {
        Cell::Diff(diff) => {
            // Counted from the hunk body, never from the payload's own `added_lines`.
            assert_eq!(diff.diff.additions, 4);
            assert_eq!(diff.diff.deletions, 2);
            assert!(!diff.diff.truncated);
            assert_eq!(
                diff.diff.path.as_deref(),
                Some("lib/ouroboros/web/presentation.ex")
            );
            assert!(!diff.pending_approval, "nothing is waiting on this patch");
        }
        other => panic!("not a diff cell: {other:?}"),
    }
}

/// The diffstat is drawn at the turn boundary and states what the turn changed.
#[test]
fn a_turn_that_changed_a_file_ends_with_its_diffstat() {
    let projected = cells(&["event_file_change", "event_turn_completed"]);

    let stat = projected
        .iter()
        .find(|cell| matches!(cell, Cell::DiffStat { .. }))
        .expect("a diffstat at the turn boundary");

    match stat {
        Cell::DiffStat {
            files,
            additions,
            deletions,
            in_excerpt,
        } => {
            assert_eq!((*files, *additions, *deletions), (1, 4, 2));
            assert!(!in_excerpt);
        }
        other => panic!("not a diffstat: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The bookkeeping
// ---------------------------------------------------------------------------

#[test]
fn a_plan_keeps_every_step_and_the_status_word_the_provider_used() {
    match cell("event_plan_updated") {
        Cell::Plan(plan) => {
            assert_eq!(
                plan.explanation.as_deref(),
                Some("Land the golden corpus before the renderer.")
            );
            assert_eq!(plan.step_count, 3);

            let steps: Vec<(&str, &str, &str)> = plan
                .steps
                .iter()
                .map(|step| (step.text.as_str(), step.status.glyph(), step.status.label()))
                .collect();

            assert_eq!(
                steps,
                vec![
                    ("Extend the fixture list", "✓", "done"),
                    ("Assert the rendered words in Rust", "●", "in progress"),
                    ("Port the projection to Elixir", "◌", "pending"),
                ]
            );

            assert_eq!(plan.steps[0].status, PlanStatus::Done);
        }
        other => panic!("not a plan cell: {other:?}"),
    }
}

/// Absent fields stay absent. A zero this client invented would be indistinguishable from
/// a zero a provider measured, which is why `cached_tokens` is read from the runtime's own
/// `cache_read_tokens` spelling rather than defaulted.
#[test]
fn a_usage_report_keeps_the_numbers_the_provider_sent_and_no_others() {
    match cell("event_usage") {
        Cell::Usage(usage) => {
            assert_eq!(usage.input_tokens, Some(18_400));
            assert_eq!(usage.output_tokens, Some(2_100));
            assert_eq!(usage.total_tokens, Some(20_500));
            assert_eq!(usage.cached_tokens, Some(12_000));
            assert_eq!(usage.cost_usd, Some(0.0731));
            assert!(!usage.is_empty());
        }
        other => panic!("not a usage cell: {other:?}"),
    }
}

#[test]
fn a_queue_depth_is_stated_in_words_and_pluralised() {
    assert_eq!(
        presentation("event_queue_changed"),
        PresentationEvent::QueueChanged { queued: 2 }
    );

    assert_eq!(
        chat_note(&cell("event_queue_changed")),
        "2 follow-ups are queued"
    );
}

// ---------------------------------------------------------------------------
// The turn
// ---------------------------------------------------------------------------

#[test]
fn a_queued_turn_is_one_muted_line() {
    assert_eq!(chat_note(&cell("event_turn_queued")), "turn queued");
}

/// A running turn is already announced by the working indicator, so its start draws no
/// cell at all. What the instant is kept for is the divider below.
#[test]
fn a_turn_starting_draws_nothing() {
    assert!(cells(&["event_turn_started"]).is_empty());
}

#[test]
fn a_turn_ending_states_how_long_it_took_from_the_two_instants_the_ledger_holds() {
    assert_eq!(
        divider(&cell("event_turn_completed")),
        ("turn complete", Tone::Muted),
        "with no start in the window there is no duration to state"
    );

    let projected = cells(&["event_turn_started", "event_turn_completed"]);

    assert_eq!(projected.len(), 1, "{projected:?}");
    assert_eq!(
        divider(&projected[0]),
        ("turn complete · 1m 30s", Tone::Muted)
    );
}

#[test]
fn a_failed_turn_keeps_its_error_loud_above_the_divider() {
    let projected = cells(&["event_turn_failed"]);

    assert_eq!(projected.len(), 2, "{projected:?}");
    assert_eq!(
        status(&projected[0]),
        (
            "Agent error",
            "the model stream ended mid-tool-call",
            Tone::Error
        )
    );
    assert_eq!(divider(&projected[1]), ("turn failed", Tone::Error));
}

#[test]
fn an_interrupted_turn_says_so_twice_in_its_own_register() {
    let projected = cells(&["event_turn_interrupted"]);

    assert_eq!(projected.len(), 2, "{projected:?}");
    assert_eq!(
        status(&projected[0]),
        ("Interrupted", "interrupted", Tone::Warning)
    );
    assert_eq!(divider(&projected[1]), ("turn interrupted", Tone::Warning));
}

// ---------------------------------------------------------------------------
// The session and the run
// ---------------------------------------------------------------------------

#[test]
fn the_session_lifecycle_reads_as_one_line_each() {
    assert_eq!(chat_note(&cell("event_session_started")), "session started");

    // `session_ready` is where the transport facts are; `session_started` names only its
    // working directory, which is not a sentence worth a line.
    assert_eq!(
        chat_note(&cell("event_session_ready")),
        "session ready · acp · stable"
    );

    assert_eq!(chat_note(&cell("event_session_idle")), "session idle");

    // A closed session ends the reading path, so it is a rule across it rather than
    // another muted aside — and its `{"reason": "closed"}` is not restated.
    assert_eq!(
        divider(&cell("event_session_closed")),
        ("session closed", Tone::Muted)
    );
}

#[test]
fn a_session_that_died_and_one_that_was_killed_are_told_apart() {
    assert_eq!(
        status(&cell("event_session_failed")),
        (
            "Agent error",
            "the provider process exited with status 1",
            Tone::Error
        )
    );

    assert_eq!(
        status(&cell("event_session_cancelled")),
        ("Interrupted", "killed", Tone::Warning)
    );
}

/// The one event in the stream that names the model. Nothing else ever does.
#[test]
fn a_run_starting_names_the_model_the_tool_count_and_the_workspace() {
    assert_eq!(
        chat_note(&cell("event_run_started")),
        "run started · claude-sonnet-4-5-20260514 · 5 tools · /srv/repo"
    );
}

#[test]
fn a_failed_run_and_a_cancelled_one_carry_the_words_the_provider_used() {
    assert_eq!(
        status(&cell("event_run_failed")),
        (
            "Agent error",
            "the CLI exited before the run completed",
            Tone::Error
        )
    );

    assert_eq!(
        status(&cell("event_run_cancelled")),
        ("Interrupted", "cancelled", Tone::Warning)
    );
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

#[test]
fn an_ordinary_permission_asks_with_the_command_the_reason_and_the_rule_that_would_end_it() {
    assert_eq!(
        status(&cell("event_approval_requested_permission")),
        (
            "Approval needed",
            r#"{"command":"git push --force origin main","cwd":"/srv/repo","name":"bash"}"#,
            Tone::Warning
        )
    );

    let request = approval("event_approval_requested_permission");

    assert!(!request.question(), "a command is not a question");
    assert!(!request.computer_use());
    assert_eq!(
        request.subject(),
        "git push --force origin main — no permission rule engine is configured on this \
         node, so every tool call is put to you"
    );

    let detail = request.detail();

    assert_eq!(detail.kind.as_deref(), Some("command"));
    assert_eq!(
        detail.command.as_deref(),
        Some("git push --force origin main")
    );
    assert_eq!(detail.cwd.as_deref(), Some("/srv/repo"));
    assert_eq!(
        detail.reason.as_deref(),
        Some(
            "no permission rule engine is configured on this node, so every tool call is put \
             to you"
        )
    );
    assert_eq!(detail.suggested_rule.as_deref(), Some("Bash(git push:*)"));
    assert_eq!(detail.plan, None);
    assert_eq!(detail.subagent, None);
    assert!(detail.options.is_empty());
    assert_eq!(detail.diff, None);
}

/// `ask_user` rides the approval channel to put a question to a person. Auto-approve must
/// refuse it: a robot `approve` carries no answer, which is the one outcome the tool
/// exists to prevent.
#[test]
fn a_question_is_marked_as_one_and_its_options_are_words_rather_than_decisions() {
    let request = approval("event_approval_requested_question");

    assert!(request.question());

    let detail = request.detail();

    assert_eq!(detail.kind.as_deref(), Some("question"));
    assert_eq!(detail.command, None);

    assert_eq!(
        request.question_text().as_deref(),
        Some("Need a decision — Which database should the staging environment point at?")
    );
    assert_eq!(
        request.subject(),
        "Need a decision — Which database should the staging environment point at?",
        "the words it asks, not the whole payload as JSON"
    );

    assert_eq!(
        detail.options,
        vec![],
        "ask_user options are plain strings, not the provider options a modal maps"
    );

    assert_eq!(
        status(&cell("event_approval_requested_question")),
        (
            "Approval needed",
            "Need a decision — Which database should the staging environment point at?",
            Tone::Warning
        )
    );
}

#[test]
fn a_plan_exit_carries_its_own_heading_question_steps_and_three_answers() {
    let request = approval("event_approval_requested_plan_exit");

    assert!(
        request.question(),
        "leaving plan mode is never auto-answered"
    );
    assert_eq!(
        request.subject(),
        "Plan ready",
        "the header, not the whole payload as JSON"
    );

    let detail = request.detail();
    let plan = detail.plan.expect("a plan exit decodes its plan");

    assert_eq!(plan.header.as_deref(), Some("Plan ready"));
    assert_eq!(plan.source.as_deref(), Some("plan_tool"));
    assert_eq!(plan.message, None);
    assert_eq!(plan.step_count, 3);
    assert_eq!(
        plan.steps
            .iter()
            .map(|step| step.text.as_str())
            .collect::<Vec<_>>(),
        vec![
            "Extend the fixture list",
            "Assert the rendered words in Rust",
            "Port the projection to Elixir",
        ]
    );

    assert_eq!(
        plan.choices
            .iter()
            .map(|choice| choice.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "Yes, auto-accept edits",
            "Yes, manual approvals",
            "No, keep planning",
        ]
    );
    assert!(
        plan.unmapped.is_empty(),
        "every option maps onto an answer this build can send"
    );

    assert_eq!(
        plan.question.as_deref(),
        Some(
            "This session has been planning. Ready to build it?\n\
             · Yes, auto-accept edits — edits inside the workspace apply without asking; \
             commands still ask.\n\
             · Yes, manual approvals — every write and command is put to you.\n\
             · No, keep planning — nothing changes and the session stays read-only."
        ),
        "shown verbatim: it is the only place the consequences of each answer are stated"
    );
}

/// The escalation asks the same question as an ordinary command approval, which is what
/// keeps a client that never learned the kind useful. Its `suggested_rule` is a map rather
/// than a pattern, so there is no rule line to draw — and inventing one from the map would
/// claim a rule nobody wrote.
#[test]
fn a_sandbox_escalation_reads_as_a_command_and_offers_no_rule_line() {
    let request = approval("event_approval_requested_sandbox_escalation");
    let detail = request.detail();

    assert_eq!(detail.kind.as_deref(), Some("sandbox escalation"));
    assert_eq!(detail.command.as_deref(), Some("cargo build --release"));
    assert_eq!(detail.cwd.as_deref(), Some("/srv/repo"));
    assert_eq!(
        detail.reason.as_deref(),
        Some("the command wrote outside the workspace and the sandbox stopped it")
    );
    assert_eq!(detail.suggested_rule, None);

    assert_eq!(
        request.subject(),
        "cargo build --release — the command wrote outside the workspace and the sandbox \
         stopped it"
    );
}

/// A permission a child relayed authorizes a change to a filesystem the approver is not
/// looking at, and the line says so.
#[test]
fn a_relayed_permission_names_the_child_and_the_machine_it_is_asking_about() {
    let request = approval("event_approval_requested_subagent");
    let detail = request.detail();
    let child = detail.subagent.expect("the asker is named");

    assert_eq!(child.description.as_deref(), Some("audit the parser"));
    assert_eq!(child.task_id.as_deref(), Some("task-subagent-000000000001"));
    assert_eq!(child.node.as_deref(), Some("ouroboros@worker"));
    assert_eq!(child.remote, Some(true));

    assert_eq!(
        child.attribution(),
        "asked by subagent audit the parser (task-subagent-000000000001)"
    );
    assert_eq!(
        child.line(Some("ouroboros@golden")),
        "asked by subagent audit the parser (task-subagent-000000000001) on ouroboros@worker"
    );
    assert_eq!(
        child.remote_node(Some("ouroboros@golden")),
        Some("ouroboros@worker")
    );

    assert_eq!(detail.command.as_deref(), Some("rm -rf target"));
}

/// The resolution rewrites the request's own cell rather than appending a second one, so a
/// transcript never shows a question that looks unanswered next to its answer.
#[test]
fn an_answer_rewrites_the_row_that_asked() {
    assert_eq!(
        status(&cell("event_approval_resolved")),
        ("Approved", "approve · once", Tone::Success),
        "an answer whose request this window never saw is still a row"
    );

    let projected = cells(&[
        "event_approval_requested_permission",
        "event_approval_resolved",
    ]);

    assert_eq!(projected.len(), 1, "one row, rewritten: {projected:?}");
    assert_eq!(
        status(&projected[0]),
        (
            "Approved",
            "{\"command\":\"git push --force origin main\",\"cwd\":\"/srv/repo\",\"name\":\
             \"bash\"}\napprove · once",
            Tone::Success
        )
    );
}

// ---------------------------------------------------------------------------
// The two envelope fixtures that also carry a renderable payload
// ---------------------------------------------------------------------------

/// `run_completed` gets no `event_*` frame of its own because it already has one: the
/// coding notification that has pinned the second plane's envelope since the corpus
/// existed. The kind is still a kind a client renders, so its words are asserted here
/// rather than left to the fixture that happens to carry them.
#[test]
fn the_coding_notification_is_a_finished_run_and_reads_as_one() {
    assert_eq!(
        chat_note(&cell("coding_event_notification")),
        "run finished · objective satisfied"
    );
}

/// The gateway replaces an oversized leaf with `{"_excerpt", "_bytes"}`, and a patch that
/// arrived as one is still worth colouring — but its `+`/`-` counts describe the prefix
/// and not the patch. So the diff is marked truncated, which is what makes the turn's
/// diffstat say `in excerpt` instead of asserting a number it cannot know.
#[test]
fn an_excerpted_patch_is_drawn_and_says_its_counts_are_only_the_prefix() {
    let projected = cells(&["interactive_event_excerpt_notification"]);

    let diff = projected
        .iter()
        .find_map(|cell| match cell {
            Cell::Diff(diff) => Some(diff),
            _other => None,
        })
        .expect("an excerpted patch is still a patch");

    assert!(
        diff.diff.truncated,
        "the counts describe the excerpt, not the patch"
    );
    assert_eq!(
        diff.diff.text,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa… (600 bytes; full event via /details)",
        "the excerpt keeps its prefix and names what did not arrive"
    );
}

// ---------------------------------------------------------------------------
// The provider's own events
// ---------------------------------------------------------------------------

#[test]
fn an_operator_shell_command_is_the_runtimes_own_block() {
    let projected = cell("event_provider_event_operator_shell");
    let block = runtime_block(&projected);

    assert_eq!(block.label, "$ command 9f2c4e1a7b53");
    assert_eq!(block.detail, "exit 0 · 1s · 48 bytes");
    assert_eq!(
        block.body,
        vec!["Compiling 1 file (.ex)", "Generated ouroboros app"]
    );
    assert_eq!(block.tone, Tone::Muted);
    assert_eq!(
        block.key.as_deref(),
        Some("9f2c4e1a7b53d0086a1c"),
        "the whole digest, so the verb's own reply dedupes against it"
    );
    assert_eq!(
        block.text(),
        "$ command 9f2c4e1a7b53 — exit 0 · 1s · 48 bytes\nCompiling 1 file (.ex)\nGenerated \
         ouroboros app"
    );
}

/// The numbers in a fold are the only record a reader has of history that is no longer in
/// front of them, so the block states them and never a zero it made up.
#[test]
fn a_compaction_states_what_it_archived_and_where() {
    let projected = cell("event_provider_event_compaction");
    let block = runtime_block(&projected);

    assert_eq!(block.label, "Compacted automatically");
    assert_eq!(
        block.detail,
        "archived 12 messages · elided 3 tool results · 148000 → 21500 tokens · archive \
         archive-00000000000000001"
    );
    assert_eq!(block.tone, Tone::Muted);
    assert_eq!(block.key.as_deref(), Some("archive-00000000000000001"));
}

#[test]
fn a_settled_child_agent_is_one_row_naming_its_machine_and_its_digest() {
    let projected = cell("event_provider_event_subagent");
    let child = subagent(&projected);

    assert!(child.settled);
    assert_eq!(child.status.as_deref(), Some("completed"));
    assert_eq!(child.tone(), Tone::Success);

    assert_eq!(
        child.headline(),
        "Subagent audit the parser · ⇄ ouroboros@worker"
    );
    assert_eq!(
        child.digest(),
        "9 turns · 31 tool calls · 4 files · 18400 in / 2100 out tokens · $0.0731"
    );
    assert_eq!(
        child.detail(),
        "completed · 9 turns · 31 tool calls · 4 files · 18400 in / 2100 out tokens · $0.0731"
    );
    assert_eq!(child.rows(), vec!["session provider-0000000000000009"]);
    assert!(
        child.unknown_phases.is_empty(),
        "`settled` is a phase this build models"
    );
}

/// B2's own record of how the plan-exit question was answered. This client does not model
/// it, and the rule is that an unmodelled kind is a named line rather than nothing — which
/// is what keeps a transcript trustworthy about the events it *does* show.
#[test]
fn the_runtimes_plan_exit_record_reads_as_a_named_provider_note() {
    assert_eq!(
        presentation("event_provider_event_plan_exit"),
        PresentationEvent::ProviderNote {
            kind: "plan_exit".into(),
            detail: String::new(),
        }
    );

    assert_eq!(
        chat_note(&cell("event_provider_event_plan_exit")),
        "provider event · plan_exit"
    );
}

/// The must-render case. ACP wraps every update it does not map in
/// `{"kind": "acp_update", "update": …}`, and the update's own `sessionUpdate` type is the
/// informative half — so it is lifted out and both halves are named.
#[test]
fn an_unmodelled_provider_event_is_a_line_that_names_both_halves_of_its_kind() {
    assert_eq!(
        presentation("event_provider_event_unknown"),
        PresentationEvent::ProviderNote {
            kind: "acp_update · terminal_output".into(),
            detail: String::new(),
        }
    );

    assert_eq!(
        chat_note(&cell("event_provider_event_unknown")),
        "provider event · acp_update · terminal_output"
    );
}

// ---------------------------------------------------------------------------
// The types this runtime mints itself
// ---------------------------------------------------------------------------

/// A delegation is a fact about work this session caused, so the parent's transcript draws
/// it — with a digest of the result and never the result, which is the child's own record.
#[test]
fn a_settled_delegation_is_a_block_with_a_digest_and_no_result() {
    let projected = cell("event_delegation");
    let block = runtime_block(&projected);

    assert_eq!(block.label, "Delegation completed");
    assert_eq!(
        block.detail,
        "task task-0000000000000000000000002 · ouroboros@worker · result digest b7e40aa1"
    );
    assert_eq!(block.tone, Tone::Success);
    assert_eq!(
        block.key, None,
        "nothing local ever drew this, so there is nothing to dedupe against"
    );
}

/// `status` is Ouroboros's own type and no client models it, so it takes the same
/// named-note path an unrecognised provider kind does.
#[test]
fn a_runtime_status_event_reads_as_a_named_note() {
    assert_eq!(
        chat_note(&cell("event_status_resumed")),
        "provider event · status"
    );
}

// ---------------------------------------------------------------------------
// The corpus itself
// ---------------------------------------------------------------------------

/// Every `event_*` fixture is named above and reaches a presentation that is not a silent
/// drop. The list is spelled out rather than globbed for the same reason
/// `every_golden_fixture_is_accounted_for` spells its own out: a fixture added on the
/// Elixir side must be given words here on purpose, and this is where that is refused.
#[test]
fn every_transcript_fixture_renders_something_a_reader_can_see() {
    let corpus = [
        "event_approval_requested_permission",
        "event_approval_requested_plan_exit",
        "event_approval_requested_question",
        "event_approval_requested_sandbox_escalation",
        "event_approval_requested_subagent",
        "event_approval_resolved",
        "event_command_output_delta",
        "event_delegation",
        "event_file_change",
        "event_input_accepted",
        "event_input_accepted_steer",
        "event_input_accepted_unrecorded",
        "event_output_text_delta",
        "event_output_text_delta_partial",
        "event_output_text_final",
        "event_plan_updated",
        "event_provider_event_compaction",
        "event_provider_event_operator_shell",
        "event_provider_event_plan_exit",
        "event_provider_event_subagent",
        "event_provider_event_unknown",
        "event_queue_changed",
        "event_run_cancelled",
        "event_run_failed",
        "event_run_started",
        "event_session_cancelled",
        "event_session_closed",
        "event_session_failed",
        "event_session_idle",
        "event_session_ready",
        "event_session_started",
        "event_status_resumed",
        "event_thinking_delta",
        "event_tool_call_acp_edit",
        "event_tool_call_bash",
        "event_tool_call_read",
        "event_tool_result_acp_edit",
        "event_tool_result_bash",
        "event_tool_result_computer_use",
        "event_tool_result_read",
        "event_turn_completed",
        "event_turn_failed",
        "event_turn_interrupted",
        "event_turn_queued",
        "event_turn_started",
        "event_usage",
    ];

    let mut found: Vec<String> = std::fs::read_dir(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../test/support/gateway_golden"),
    )
    .expect("the golden fixtures")
    .filter_map(|entry| {
        let name = entry.ok()?.file_name().into_string().ok()?;
        name.strip_suffix(".json")
            .filter(|name| name.starts_with("event_"))
            .map(str::to_string)
    })
    .collect();

    found.sort();

    assert_eq!(found, corpus, "the transcript corpus has changed");

    for name in corpus {
        let presented = PresentationEvent::from_event(&event(name));

        assert!(
            !matches!(presented, PresentationEvent::Hidden(_)),
            "{name} is drawn as nothing; a hide must be an empty payload, never a kind"
        );

        // `turn_started` is the one event with no cell of its own: a running turn is
        // already announced by the working indicator, and the instant it carries is what
        // the turn's end divider states its duration from.
        if name != "event_turn_started" {
            assert!(
                !cells(&[name]).is_empty(),
                "{name} projected to no cells at all"
            );
        }
    }
}
