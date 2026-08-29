defmodule Ouroboros.Web.CorpusParityTest do
  @moduledoc """
  The drift lock between the two transcript implementations (`docs/WEB.md` §6).

  `test/support/gateway_golden/event_*.json` is one frame per event payload a client has
  to turn into a sentence. `tui/tests/presentation_corpus.rs` is the Rust half: it runs
  each fixture through `Event::decode` → `PresentationEvent::from_event` → `project` and
  writes the finished words out as plain literals. This file is the Elixir half, running
  the same fixture bytes through `Ouroboros.Web.Presentation.from_event/1` →
  `Ouroboros.Web.Transcript.project/1` and asserting **the same literals**.

  Every expected string here was copied by hand from a named Rust test, and each block
  says which one. The two suites cannot call each other and are compiled by different
  toolchains, so the same bytes in and the same words asserted out is the only mechanism
  that keeps them agreeing: **a change to any literal here is a change to a contract with
  another toolchain**, not a test edit. The Rust literals are the contract and this side
  conforms — a mismatch is a bug in `Ouroboros.Web.{Presentation,Transcript}`.

  What is deliberately *not* asserted, on both sides, is layout: widths, colours, wrapping
  and the ratatui spans are the terminal's own and no browser will reproduce them. Cell
  kind, the tool summariser's verb/subject/outcome, the note and divider text, and the
  approval detail fields are the parts both surfaces owe the reader identically.

  The fixtures are read from the checkout rather than embedded, exactly as the Rust reader
  does, so a regeneration is picked up by the next run of either suite with no copy step.
  """

  use ExUnit.Case, async: true

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Interactive.Event
  alias Ouroboros.Web.Presentation
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.{Approval, Cell, Entry, Tools}

  alias Ouroboros.Web.Presentation.{
    Hidden,
    PlanStatus,
    ProviderNote,
    QueueChanged,
    UnrecordedInput,
    UserMessage,
    UserSteer
  }

  # The event types this corpus carries, as the runtime spells them. `delegation` (G1) and
  # `status` (D6) are Ouroboros's own and so are not in `canonical_types/0`. Spelled out
  # rather than derived with `String.to_existing_atom/1` so a fixture carrying a type this
  # build does not know fails loudly here instead of decoding into something plausible.
  @types Map.new(
           Presentation.canonical_types() ++ [:delegation, :status],
           &{Atom.to_string(&1), &1}
         )

  # `Ouroboros.Gateway.Wire` writes the provider as its string; the in-process subscriber
  # holds the atom the runtime minted.
  @providers %{"claude_code" => :claude_code, "native" => :native}

  # ------------------------------------------------------------------------------------
  # One fixture's event, decoded the way the transport hands it to the model.
  # ------------------------------------------------------------------------------------

  # Mirrors `presentation_corpus.rs`'s own `event/1`: the same file, the same
  # `params.event` object, rebuilt into the struct an in-process reader would be holding.
  # A coding-plane frame names its subject `task_id` rather than `session_id`; nothing in
  # either module reads that field, and carrying it keeps the struct honest anyway.
  defp event(name) do
    frame = name |> Golden.path() |> File.read!() |> JSON.decode!()
    fields = get_in(frame, ["params", "event"])

    %Event{
      id: fields["id"],
      session_id: fields["session_id"] || fields["task_id"],
      sequence: fields["sequence"],
      type: decode_type(fields["type"]),
      timestamp: fields["timestamp"],
      payload: fields["payload"],
      harness_session_id: fields["harness_session_id"],
      provider: decode_provider(fields["provider"]),
      provider_session_id: fields["provider_session_id"],
      turn_id: fields["turn_id"],
      request_id: fields["request_id"]
    }
  end

  defp decode_type(type) do
    Map.get(@types, type) ||
      raise ArgumentError, "the corpus carries an event type this test does not know: #{type}"
  end

  defp decode_provider(nil), do: nil

  defp decode_provider(provider) do
    Map.get(@providers, provider) ||
      raise ArgumentError, "the corpus carries a provider this test does not know: #{provider}"
  end

  defp presentation(name), do: name |> event() |> Presentation.from_event()

  # The cells one ordered run of fixtures projects to.
  defp cells(names) do
    names |> Enum.map(&%Entry.Event{event: event(&1)}) |> Transcript.project()
  end

  # The single cell one fixture projects to, when it projects to exactly one.
  defp cell(name) do
    case cells([name]) do
      [only] ->
        only

      projected ->
        flunk("#{name} projected to #{length(projected)} cells, not one: #{inspect(projected)}")
    end
  end

  defp message(%Cell.Message{speaker: speaker, text: text, streaming: streaming}),
    do: {speaker, text, streaming}

  defp message(other), do: flunk("not a message cell: #{inspect(other)}")

  defp chat_note(%Cell.ChatNote{text: text}), do: text
  defp chat_note(other), do: flunk("not a chat note: #{inspect(other)}")

  defp divider(%Cell.Divider{text: text, tone: tone}), do: {text, tone}
  defp divider(other), do: flunk("not a divider: #{inspect(other)}")

  defp status(%Cell.Status{label: label, detail: detail, tone: tone}), do: {label, detail, tone}
  defp status(other), do: flunk("not a status cell: #{inspect(other)}")

  defp tool(%Cell.Tool{} = tool), do: tool
  defp tool(other), do: flunk("not a tool cell: #{inspect(other)}")

  defp runtime_block(%Cell.Runtime{} = block), do: block
  defp runtime_block(other), do: flunk("not a runtime block: #{inspect(other)}")

  defp subagent(%Cell.Subagent{} = child), do: child
  defp subagent(other), do: flunk("not a subagent cell: #{inspect(other)}")

  # The three strings the tool summariser produces, as one tuple to assert against.
  defp summary(%Cell.Tool{} = tool) do
    summarised = Tools.summarise(tool)
    {summarised.verb, summarised.subject, summarised.outcome}
  end

  defp summary(cell), do: cell |> tool() |> summary()

  # The modal's reading of an approval fixture, built the way the pane builds it —
  # through the production reducer rather than by hand, so the payload normalization the
  # pane applies is the one under test.
  defp approval(name) do
    event = event(name)

    case Transcript.pending_approvals(%{event.sequence => event}) do
      [request] -> request
      other -> flunk("#{name} is not one outstanding approval: #{inspect(other)}")
    end
  end

  # ------------------------------------------------------------------------------------
  # What a person typed
  # ------------------------------------------------------------------------------------

  describe "what a person typed" do
    # Mirrors `an_accepted_prompt_is_the_operators_own_message`.
    test "an_accepted_prompt_is_the_operators_own_message" do
      assert presentation("event_input_accepted") ==
               %UserMessage{text: "Check the workspace is clean, then run the suite."}

      assert message(cell("event_input_accepted")) ==
               {:you, "Check the workspace is clean, then run the suite.", false}
    end

    # Mirrors `a_steer_is_a_note_naming_the_words_that_steered`.
    test "a_steer_is_a_note_naming_the_words_that_steered" do
      assert presentation("event_input_accepted_steer") ==
               %UserSteer{text: "actually, skip the slow tests"}

      assert chat_note(cell("event_input_accepted_steer")) ==
               "You steered the agent: actually, skip the slow tests"
    end

    # Mirrors `an_acceptance_with_no_recorded_words_is_still_a_row`. The turn whose words
    # the ledger does not hold is still drawn: a transcript that silently omitted it would
    # be a transcript that cannot be trusted about the turns it does show.
    test "an_acceptance_with_no_recorded_words_is_still_a_row" do
      assert presentation("event_input_accepted_unrecorded") == %UnrecordedInput{}

      assert chat_note(cell("event_input_accepted_unrecorded")) == "[message not recorded]"
    end
  end

  # ------------------------------------------------------------------------------------
  # What the agent said
  # ------------------------------------------------------------------------------------

  describe "what the agent said" do
    # Mirrors `a_text_delta_is_a_streaming_agent_message_and_a_final_is_a_settled_one`.
    test "a_text_delta_is_a_streaming_agent_message_and_a_final_is_a_settled_one" do
      assert message(cell("event_output_text_delta")) ==
               {:agent, "Running the suite now.", true}

      assert message(cell("event_output_text_final")) ==
               {:agent, "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
                false}
    end

    # Mirrors `a_delta_and_its_final_settle_into_one_message`. A delta and the final of the
    # same turn are one cell, not two: the final replaces the draft rather than being
    # appended below it.
    test "a_delta_and_its_final_settle_into_one_message" do
      projected = cells(["event_output_text_delta", "event_output_text_final"])

      assert length(projected) == 1, inspect(projected)

      assert message(hd(projected)) ==
               {:agent, "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
                false}
    end

    # Mirrors `a_final_settles_the_draft_a_note_flushed_early`. The case the adjacent test
    # above cannot reach: a provider note and a usage row land between the draft and the
    # final that supersedes it.
    #
    # A note flushes the pending draft so it can be drawn *after* the words it follows.
    # That leaves nothing for the final to absorb, and both clients used to push a second
    # message carrying the same answer — a duplicate an operator saw in a live browser.
    #
    # The corpus is one event per file, so no single fixture can express an interleaving;
    # the ordering is the test's and every payload is the corpus's, which is the same
    # composition `cells/1` already does elsewhere. `event_output_text_delta_partial`
    # exists for this: its text is a literal prefix of the final's, which the other delta
    # fixture deliberately is not.
    test "a_final_settles_the_draft_a_note_flushed_early" do
      projected =
        cells([
          "event_output_text_delta_partial",
          "event_provider_event_compaction",
          "event_usage",
          "event_output_text_final",
          "event_turn_completed"
        ])

      # One message, and the notes still sit after the words they follow.
      assert [message, %Cell.Runtime{}, %Cell.Usage{}, %Cell.Divider{kind: :turn_end}] = projected

      assert message(message) ==
               {:agent, "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
                false}
    end

    # Mirrors `a_later_block_of_the_same_turn_is_its_own_message`. The guard on the rule
    # above: a turn that says something, calls a tool, then says something else must keep
    # both halves. The final's text does not begin with the flushed draft's, so it is a
    # new block and is pushed rather than folded into it.
    test "a_later_block_of_the_same_turn_is_its_own_message" do
      projected =
        cells([
          "event_output_text_delta",
          "event_tool_call_bash",
          "event_tool_result_bash",
          "event_output_text_final"
        ])

      assert [first, %Cell.Tool{}, second] = projected

      assert message(first) == {:agent, "Running the suite now.", false}

      assert message(second) ==
               {:agent, "The suite passed: 412 tests, 0 failures.\n\nNothing else to change.",
                false}
    end

    # Mirrors `reasoning_is_its_own_cell_and_never_the_agents_answer`.
    test "reasoning_is_its_own_cell_and_never_the_agents_answer" do
      assert %Cell.Thinking{text: text, lines: lines, state: state} =
               cell("event_thinking_delta")

      assert text == "The failure is in the diff parser, not the transport."
      assert lines == 1
      # Last cell drawn, so it is still being watched rather than folded away.
      assert state == :tail
    end

    # Mirrors `a_command_output_delta_is_its_own_cell`.
    test "a_command_output_delta_is_its_own_cell" do
      assert %Cell.CommandOutput{text: "Compiling ouroboros v0.1.0\n"} =
               cell("event_command_output_delta")
    end

    # Mirrors `only_an_empty_payload_is_drawn_as_nothing`. Every `Hidden` arm is a payload
    # that carried no content, never a kind this client declines to show. The corpus
    # carries no empty-text fixture on purpose — an empty `text` is a transport keep-alive
    # rather than a shape a runtime records — so this states the rule against a hand-built
    # payload and keeps the reason readable.
    test "only_an_empty_payload_is_drawn_as_nothing" do
      empty = %{event("event_output_text_delta") | payload: %{"text" => ""}}

      assert Presentation.from_event(empty) == %Hidden{reason: :empty_text}
      assert Hidden.reason(:empty_text) == "an output event carrying no text"
    end
  end

  # ------------------------------------------------------------------------------------
  # What it ran
  # ------------------------------------------------------------------------------------

  describe "what it ran" do
    # Mirrors `a_claude_command_call_reads_as_bash_and_its_command_line`.
    test "a_claude_command_call_reads_as_bash_and_its_command_line" do
      running = tool(cell("event_tool_call_bash"))

      assert running.name == "Bash"
      assert running.kind == nil, "the Claude dialect sends no ACP kind"
      assert running.state == :running

      assert summary(running) == {"Bash", "$ mix test --stale", ""}
    end

    # Mirrors `a_command_result_settles_the_call_it_names`.
    test "a_command_result_settles_the_call_it_names" do
      projected = cells(["event_tool_call_bash", "event_tool_result_bash"])

      assert length(projected) == 1, "one row, not two: #{inspect(projected)}"

      settled = tool(hd(projected))
      assert settled.name == "Bash"
      assert settled.state == :completed

      # No `exit N`: no dialect in this build forwards an exit code on the wire — the
      # runtime folds it into `is_error` — so the summary claims nothing about one.
      assert summary(settled) == {"Bash", "$ mix test --stale", ""}
    end

    # Mirrors `an_orphaned_command_result_is_a_row_of_its_own`. A result whose call this
    # window never saw is still a row; dropping it would hide work the session did.
    test "an_orphaned_command_result_is_a_row_of_its_own" do
      orphan = tool(cell("event_tool_result_bash"))

      assert orphan.name == "Bash"
      assert orphan.state == :completed
    end

    # Mirrors `a_read_folds_into_the_exploration_cell_and_counts_its_lines`.
    test "a_read_folds_into_the_exploration_cell_and_counts_its_lines" do
      assert %Cell.Exploration{} = group = cell("event_tool_call_read")

      assert Cell.Exploration.total(group) == 1
      # Still the last cell drawn, so the group is open.
      refute group.done

      assert summary(hd(group.calls)) == {"Read", "lib/ouroboros/gateway/wire.ex:120-159", ""}

      assert [%Cell.Exploration{} = settled | _rest] =
               cells(["event_tool_call_read", "event_tool_result_read"])

      assert summary(hd(settled.calls)) ==
               {"Read", "lib/ouroboros/gateway/wire.ex:120-159", "→ 3 lines"}
    end

    # Mirrors `an_acp_edit_reads_as_an_edit_with_the_lines_the_call_carried`. The ACP
    # dialect names a call in prose and says what it *is* only in `kind`. The summariser
    # reads both: the title is the row's name, the kind is what picks the verb.
    test "an_acp_edit_reads_as_an_edit_with_the_lines_the_call_carried" do
      edit = tool(cell("event_tool_call_acp_edit"))

      assert edit.name == "Edit lib/ouroboros/web/transcript.ex"
      assert edit.kind == "edit"

      assert summary(edit) == {"Edit", "lib/ouroboros/web/transcript.ex (+4 −3)", ""}
    end

    # Mirrors `an_acp_status_of_completed_settles_the_edit_without_an_is_error_field`.
    test "an_acp_status_of_completed_settles_the_edit_without_an_is_error_field" do
      projected = cells(["event_tool_call_acp_edit", "event_tool_result_acp_edit"])

      assert length(projected) == 1, inspect(projected)
      assert tool(hd(projected)).state == :completed

      assert summary(hd(projected)) == {"Edit", "lib/ouroboros/web/transcript.ex (+4 −3)", ""}
    end

    # Mirrors `a_computer_use_result_is_a_tool_row_and_then_a_labelled_image`. A Computer
    # Use result is two cells in a fixed order: the tool row, then the picture it produced.
    # The image carries the sha and the size the gateway stated and no bytes — the pixels
    # are fetched by sha through `computer_use.artifact`.
    test "a_computer_use_result_is_a_tool_row_and_then_a_labelled_image" do
      projected = cells(["event_tool_result_computer_use"])

      assert length(projected) == 2, inspect(projected)
      assert tool(hd(projected)).name == "desktop_state"
      assert tool(hd(projected)).state == :completed
      assert summary(hd(projected)) == {"desktop state", "", ""}

      assert %Cell.Image{} = image = Enum.at(projected, 1)

      assert image.named == "desktop capture · abababababab"
      assert image.pixels == {1512, 982}
      assert image.format == "png"
      assert image.media_type == "image/png"
      assert image.sha == String.duplicate("ab", 32)
      assert image.note == nil
      assert Cell.Image.label(image) == "[image 1512×982 png · desktop capture · abababababab]"
    end
  end

  # ------------------------------------------------------------------------------------
  # What changed
  # ------------------------------------------------------------------------------------

  describe "what changed" do
    # Mirrors `a_file_change_is_a_file_row_and_the_patch_under_it`.
    test "a_file_change_is_a_file_row_and_the_patch_under_it" do
      projected = cells(["event_file_change"])

      assert length(projected) == 2, inspect(projected)

      assert %Cell.File{path: path, kind: kind} = hd(projected)
      assert path == "lib/ouroboros/web/presentation.ex"
      assert kind == "update"

      assert %Cell.Diff{} = diff = Enum.at(projected, 1)

      # Counted from the hunk body, never from the payload's own `added_lines`.
      assert diff.diff.additions == 4
      assert diff.diff.deletions == 2
      refute diff.diff.truncated
      assert diff.diff.path == "lib/ouroboros/web/presentation.ex"
      refute diff.pending_approval, "nothing is waiting on this patch"
    end

    # Mirrors `a_turn_that_changed_a_file_ends_with_its_diffstat`. The diffstat is drawn at
    # the turn boundary and states what the turn changed.
    test "a_turn_that_changed_a_file_ends_with_its_diffstat" do
      projected = cells(["event_file_change", "event_turn_completed"])

      assert %Cell.DiffStat{} = stat = Enum.find(projected, &match?(%Cell.DiffStat{}, &1))

      assert {stat.files, stat.additions, stat.deletions} == {1, 4, 2}
      refute stat.in_excerpt
    end
  end

  # ------------------------------------------------------------------------------------
  # The bookkeeping
  # ------------------------------------------------------------------------------------

  describe "the bookkeeping" do
    # Mirrors `a_plan_keeps_every_step_and_the_status_word_the_provider_used`.
    test "a_plan_keeps_every_step_and_the_status_word_the_provider_used" do
      assert %Cell.Plan{plan: plan} = cell("event_plan_updated")

      assert plan.explanation == "Land the golden corpus before the renderer."
      assert plan.step_count == 3

      steps =
        Enum.map(
          plan.steps,
          &{&1.text, PlanStatus.glyph(&1.status), PlanStatus.label(&1.status)}
        )

      assert steps == [
               {"Extend the fixture list", "✓", "done"},
               {"Assert the rendered words in Rust", "●", "in progress"},
               {"Port the projection to Elixir", "◌", "pending"}
             ]

      assert hd(plan.steps).status == :done
    end

    # Mirrors `a_usage_report_keeps_the_numbers_the_provider_sent_and_no_others`. Absent
    # fields stay absent: a zero this client invented would be indistinguishable from a
    # zero a provider measured, which is why `cached_tokens` is read from the runtime's own
    # `cache_read_tokens` spelling rather than defaulted.
    test "a_usage_report_keeps_the_numbers_the_provider_sent_and_no_others" do
      assert %Cell.Usage{usage: usage} = cell("event_usage")

      assert usage.input_tokens == 18_400
      assert usage.output_tokens == 2_100
      assert usage.total_tokens == 20_500
      assert usage.cached_tokens == 12_000
      assert usage.cost_usd == 0.0731
      refute Presentation.UsageReport.empty?(usage)
    end

    # Mirrors `a_queue_depth_is_stated_in_words_and_pluralised`.
    test "a_queue_depth_is_stated_in_words_and_pluralised" do
      assert presentation("event_queue_changed") == %QueueChanged{queued: 2}

      assert chat_note(cell("event_queue_changed")) == "2 follow-ups are queued"
    end
  end

  # ------------------------------------------------------------------------------------
  # The turn
  # ------------------------------------------------------------------------------------

  describe "the turn" do
    # Mirrors `a_queued_turn_is_one_muted_line`.
    test "a_queued_turn_is_one_muted_line" do
      assert chat_note(cell("event_turn_queued")) == "turn queued"
    end

    # Mirrors `a_turn_starting_draws_nothing`. A running turn is already announced by the
    # working indicator, so its start draws no cell at all. What the instant is kept for is
    # the divider below.
    test "a_turn_starting_draws_nothing" do
      assert cells(["event_turn_started"]) == []
    end

    # Mirrors `a_turn_ending_states_how_long_it_took_from_the_two_instants_the_ledger_holds`.
    test "a_turn_ending_states_how_long_it_took_from_the_two_instants_the_ledger_holds" do
      assert divider(cell("event_turn_completed")) == {"turn complete", :muted},
             "with no start in the window there is no duration to state"

      projected = cells(["event_turn_started", "event_turn_completed"])

      assert length(projected) == 1, inspect(projected)
      assert divider(hd(projected)) == {"turn complete · 1m 30s", :muted}
    end

    # Mirrors `a_failed_turn_keeps_its_error_loud_above_the_divider`.
    test "a_failed_turn_keeps_its_error_loud_above_the_divider" do
      projected = cells(["event_turn_failed"])

      assert length(projected) == 2, inspect(projected)

      assert status(hd(projected)) ==
               {"Agent error", "the model stream ended mid-tool-call", :error}

      assert divider(Enum.at(projected, 1)) == {"turn failed", :error}
    end

    # Mirrors `an_interrupted_turn_says_so_twice_in_its_own_register`.
    test "an_interrupted_turn_says_so_twice_in_its_own_register" do
      projected = cells(["event_turn_interrupted"])

      assert length(projected) == 2, inspect(projected)
      assert status(hd(projected)) == {"Interrupted", "interrupted", :warning}
      assert divider(Enum.at(projected, 1)) == {"turn interrupted", :warning}
    end
  end

  # ------------------------------------------------------------------------------------
  # The session and the run
  # ------------------------------------------------------------------------------------

  describe "the session and the run" do
    # Mirrors `the_session_lifecycle_reads_as_one_line_each`.
    test "the_session_lifecycle_reads_as_one_line_each" do
      assert chat_note(cell("event_session_started")) == "session started"

      # `session_ready` is where the transport facts are; `session_started` names only its
      # working directory, which is not a sentence worth a line.
      assert chat_note(cell("event_session_ready")) == "session ready · acp · stable"

      assert chat_note(cell("event_session_idle")) == "session idle"

      # A closed session ends the reading path, so it is a rule across it rather than
      # another muted aside — and its `{"reason": "closed"}` is not restated.
      assert divider(cell("event_session_closed")) == {"session closed", :muted}
    end

    # Mirrors `a_session_that_died_and_one_that_was_killed_are_told_apart`.
    test "a_session_that_died_and_one_that_was_killed_are_told_apart" do
      assert status(cell("event_session_failed")) ==
               {"Agent error", "the provider process exited with status 1", :error}

      assert status(cell("event_session_cancelled")) == {"Interrupted", "killed", :warning}
    end

    # Mirrors `a_run_starting_names_the_model_the_tool_count_and_the_workspace`. The one
    # event in the stream that names the model. Nothing else ever does.
    test "a_run_starting_names_the_model_the_tool_count_and_the_workspace" do
      assert chat_note(cell("event_run_started")) ==
               "run started · claude-sonnet-4-5-20260514 · 5 tools · /srv/repo"
    end

    # Mirrors `a_failed_run_and_a_cancelled_one_carry_the_words_the_provider_used`.
    test "a_failed_run_and_a_cancelled_one_carry_the_words_the_provider_used" do
      assert status(cell("event_run_failed")) ==
               {"Agent error", "the CLI exited before the run completed", :error}

      assert status(cell("event_run_cancelled")) == {"Interrupted", "cancelled", :warning}
    end
  end

  # ------------------------------------------------------------------------------------
  # Approvals
  # ------------------------------------------------------------------------------------

  describe "approvals" do
    # Mirrors
    # `an_ordinary_permission_asks_with_the_command_the_reason_and_the_rule_that_would_end_it`.
    test "an_ordinary_permission_asks_with_the_command_the_reason_and_the_rule_that_would_end_it" do
      assert status(cell("event_approval_requested_permission")) ==
               {"Approval needed",
                ~S({"command":"git push --force origin main","cwd":"/srv/repo","name":"bash"}),
                :warning}

      request = approval("event_approval_requested_permission")

      refute Approval.question?(request), "a command is not a question"
      refute Approval.computer_use?(request)

      assert Approval.subject(request) ==
               "git push --force origin main — no permission rule engine is configured on this " <>
                 "node, so every tool call is put to you"

      detail = Approval.detail(request)

      assert detail.kind == "command"
      assert detail.command == "git push --force origin main"
      assert detail.cwd == "/srv/repo"

      assert detail.reason ==
               "no permission rule engine is configured on this node, so every tool call is put " <>
                 "to you"

      assert detail.suggested_rule == "Bash(git push:*)"
      assert detail.plan == nil
      assert detail.subagent == nil
      assert detail.options == []
      assert detail.diff == nil
    end

    # Mirrors `a_question_reads_as_the_words_it_asks_and_offers_its_options_as_answers`.
    # `ask_user` rides the approval channel to put a question to a person. Auto-approve
    # must refuse it: a robot `approve` carries no answer, which is the one outcome the
    # tool exists to prevent.
    test "a_question_reads_as_the_words_it_asks_and_offers_its_options_as_answers" do
      request = approval("event_approval_requested_question")

      assert Approval.question?(request)

      detail = Approval.detail(request)

      assert detail.kind == "question"
      assert detail.command == nil

      assert Approval.question_text(request.payload) ==
               "Need a decision — Which database should the staging environment point at?"

      assert Approval.subject(request) ==
               "Need a decision — Which database should the staging environment point at?",
             "the words it asks, not the whole payload as JSON"

      # `AskUser.question/1` writes plain strings, which both readers used to drop for
      # having no `name`. They are the answers themselves: the string is the label and the
      # words sent back, and nothing on the wire says what they mean.
      assert Enum.map(detail.options, & &1.name) == ["staging-db", "scratch-db"]
      assert Enum.map(detail.options, & &1.answer) == ["staging-db", "scratch-db"]
      assert Enum.map(detail.options, & &1.option_id) == [nil, nil]
      assert Enum.map(detail.options, & &1.kind) == [nil, nil]

      assert Enum.map(detail.options, &Approval.Option.decision/1) == [nil, nil],
             "no vendor kind said what these mean, so the four-way table maps nothing"

      assert Enum.all?(detail.options, &Approval.Option.answerable?/1),
             "a bare-string option is an answer, and choosing it sends those words"

      assert status(cell("event_approval_requested_question")) ==
               {"Approval needed",
                "Need a decision — Which database should the staging environment point at?",
                :warning}
    end

    # Mirrors `a_plan_exit_carries_its_own_heading_question_steps_and_three_answers`.
    test "a_plan_exit_carries_its_own_heading_question_steps_and_three_answers" do
      request = approval("event_approval_requested_plan_exit")

      assert Approval.question?(request), "leaving plan mode is never auto-answered"

      assert Approval.subject(request) == "Plan ready",
             "the header, not the whole payload as JSON"

      plan = Approval.detail(request).plan
      assert plan, "a plan exit decodes its plan"

      assert plan.header == "Plan ready"
      assert plan.source == "plan_tool"
      assert plan.message == nil
      assert plan.step_count == 3

      assert Enum.map(plan.steps, & &1.text) == [
               "Extend the fixture list",
               "Assert the rendered words in Rust",
               "Port the projection to Elixir"
             ]

      assert Enum.map(plan.choices, & &1.name) == [
               "Yes, auto-accept edits",
               "Yes, manual approvals",
               "No, keep planning"
             ]

      assert plan.unmapped == [],
             "every option maps onto an answer this build can send"

      assert plan.question ==
               "This session has been planning. Ready to build it?\n" <>
                 "· Yes, auto-accept edits — edits inside the workspace apply without asking; " <>
                 "commands still ask.\n" <>
                 "· Yes, manual approvals — every write and command is put to you.\n" <>
                 "· No, keep planning — nothing changes and the session stays read-only.",
             "shown verbatim: it is the only place the consequences of each answer are stated"
    end

    # Mirrors `a_sandbox_escalation_reads_as_a_command_and_offers_no_rule_line`. The
    # escalation asks the same question as an ordinary command approval, which is what
    # keeps a client that never learned the kind useful. Its `suggested_rule` is a map
    # rather than a pattern, so there is no rule line to draw — and inventing one from the
    # map would claim a rule nobody wrote.
    test "a_sandbox_escalation_reads_as_a_command_and_offers_no_rule_line" do
      request = approval("event_approval_requested_sandbox_escalation")
      detail = Approval.detail(request)

      assert detail.kind == "sandbox escalation"
      assert detail.command == "cargo build --release"
      assert detail.cwd == "/srv/repo"

      assert detail.reason ==
               "the command wrote outside the workspace and the sandbox stopped it"

      assert detail.suggested_rule == nil

      assert Approval.subject(request) ==
               "cargo build --release — the command wrote outside the workspace and the sandbox " <>
                 "stopped it"
    end

    # Mirrors `a_relayed_permission_names_the_child_and_the_machine_it_is_asking_about`. A
    # permission a child relayed authorizes a change to a filesystem the approver is not
    # looking at, and the line says so.
    test "a_relayed_permission_names_the_child_and_the_machine_it_is_asking_about" do
      detail = "event_approval_requested_subagent" |> approval() |> Approval.detail()
      child = detail.subagent
      assert child, "the asker is named"

      assert child.description == "audit the parser"
      assert child.task_id == "task-subagent-000000000001"
      assert child.node == "ouroboros@worker"
      assert child.remote == true

      assert Approval.Subagent.attribution(child) ==
               "asked by subagent audit the parser (task-subagent-000000000001)"

      assert Approval.Subagent.line(child, "ouroboros@golden") ==
               "asked by subagent audit the parser (task-subagent-000000000001) on ouroboros@worker"

      assert Approval.Subagent.remote_node(child, "ouroboros@golden") == "ouroboros@worker"

      assert detail.command == "rm -rf target"
    end

    # Mirrors `an_answer_rewrites_the_row_that_asked`. The resolution rewrites the
    # request's own cell rather than appending a second one, so a transcript never shows a
    # question that looks unanswered next to its answer.
    test "an_answer_rewrites_the_row_that_asked" do
      assert status(cell("event_approval_resolved")) == {"Approved", "approve · once", :success},
             "an answer whose request this window never saw is still a row"

      projected =
        cells(["event_approval_requested_permission", "event_approval_resolved"])

      assert length(projected) == 1, "one row, rewritten: #{inspect(projected)}"

      assert status(hd(projected)) ==
               {"Approved",
                ~S({"command":"git push --force origin main","cwd":"/srv/repo","name":"bash"}) <>
                  "\napprove · once", :success}
    end
  end

  # ------------------------------------------------------------------------------------
  # The two envelope fixtures that also carry a renderable payload
  # ------------------------------------------------------------------------------------

  describe "the envelope fixtures that also carry a renderable payload" do
    # Mirrors `the_coding_notification_is_a_finished_run_and_reads_as_one`. `run_completed`
    # gets no `event_*` frame of its own because it already has one: the coding
    # notification that has pinned the second plane's envelope since the corpus existed.
    # The kind is still a kind a client renders, so its words are asserted here rather than
    # left to the fixture that happens to carry them.
    test "the_coding_notification_is_a_finished_run_and_reads_as_one" do
      assert chat_note(cell("coding_event_notification")) == "run finished · objective satisfied"
    end

    # Mirrors `an_excerpted_patch_is_drawn_and_says_its_counts_are_only_the_prefix`. The
    # gateway replaces an oversized leaf with `{"_excerpt", "_bytes"}`, and a patch that
    # arrived as one is still worth colouring — but its `+`/`-` counts describe the prefix
    # and not the patch. So the diff is marked truncated, which is what makes the turn's
    # diffstat say `in excerpt` instead of asserting a number it cannot know.
    test "an_excerpted_patch_is_drawn_and_says_its_counts_are_only_the_prefix" do
      projected = cells(["interactive_event_excerpt_notification"])

      diff = Enum.find(projected, &match?(%Cell.Diff{}, &1))
      assert diff, "an excerpted patch is still a patch"

      assert diff.diff.truncated, "the counts describe the excerpt, not the patch"

      assert diff.diff.text ==
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa… (600 bytes; full event via /details)",
             "the excerpt keeps its prefix and names what did not arrive"
    end
  end

  # ------------------------------------------------------------------------------------
  # The provider's own events
  # ------------------------------------------------------------------------------------

  describe "the provider's own events" do
    # Mirrors `an_operator_shell_command_is_the_runtimes_own_block`.
    test "an_operator_shell_command_is_the_runtimes_own_block" do
      block = runtime_block(cell("event_provider_event_operator_shell"))

      assert block.label == "$ command 9f2c4e1a7b53"
      assert block.detail == "exit 0 · 1s · 48 bytes"
      assert block.body == ["Compiling 1 file (.ex)", "Generated ouroboros app"]
      assert block.tone == :muted

      assert block.key == "9f2c4e1a7b53d0086a1c",
             "the whole digest, so the verb's own reply dedupes against it"

      assert Cell.Runtime.text(block) ==
               "$ command 9f2c4e1a7b53 — exit 0 · 1s · 48 bytes\nCompiling 1 file (.ex)\n" <>
                 "Generated ouroboros app"
    end

    # Mirrors `a_compaction_states_what_it_archived_and_where`. The numbers in a fold are
    # the only record a reader has of history that is no longer in front of them, so the
    # block states them and never a zero it made up.
    test "a_compaction_states_what_it_archived_and_where" do
      block = runtime_block(cell("event_provider_event_compaction"))

      assert block.label == "Compacted automatically"

      assert block.detail ==
               "archived 12 messages · elided 3 tool results · 148000 → 21500 tokens · archive " <>
                 "archive-00000000000000001"

      assert block.tone == :muted
      assert block.key == "archive-00000000000000001"
    end

    # Mirrors `a_settled_child_agent_is_one_row_naming_its_machine_and_its_digest`.
    test "a_settled_child_agent_is_one_row_naming_its_machine_and_its_digest" do
      child = subagent(cell("event_provider_event_subagent"))

      assert child.settled
      assert child.status == "completed"
      assert Cell.Subagent.tone(child) == :success

      assert Cell.Subagent.headline(child) == "Subagent audit the parser · ⇄ ouroboros@worker"

      assert Cell.Subagent.digest(child) ==
               "9 turns · 31 tool calls · 4 files · 18400 in / 2100 out tokens · $0.0731"

      assert Cell.Subagent.detail(child) ==
               "completed · 9 turns · 31 tool calls · 4 files · 18400 in / 2100 out tokens · " <>
                 "$0.0731"

      assert Cell.Subagent.rows(child) == ["session provider-0000000000000009"]

      assert child.unknown_phases == [], "`settled` is a phase this build models"
    end

    # Mirrors `the_runtimes_plan_exit_record_reads_as_a_named_provider_note`. B2's own
    # record of how the plan-exit question was answered. This client does not model it, and
    # the rule is that an unmodelled kind is a named line rather than nothing — which is
    # what keeps a transcript trustworthy about the events it *does* show.
    test "the_runtimes_plan_exit_record_reads_as_a_named_provider_note" do
      assert presentation("event_provider_event_plan_exit") ==
               %ProviderNote{kind: "plan_exit", detail: ""}

      assert chat_note(cell("event_provider_event_plan_exit")) == "provider event · plan_exit"
    end

    # Mirrors `an_unmodelled_provider_event_is_a_line_that_names_both_halves_of_its_kind`.
    # The must-render case. ACP wraps every update it does not map in
    # `{"kind": "acp_update", "update": …}`, and the update's own `sessionUpdate` type is
    # the informative half — so it is lifted out and both halves are named.
    test "an_unmodelled_provider_event_is_a_line_that_names_both_halves_of_its_kind" do
      assert presentation("event_provider_event_unknown") ==
               %ProviderNote{kind: "acp_update · terminal_output", detail: ""}

      assert chat_note(cell("event_provider_event_unknown")) ==
               "provider event · acp_update · terminal_output"
    end
  end

  # ------------------------------------------------------------------------------------
  # The types this runtime mints itself
  # ------------------------------------------------------------------------------------

  describe "the types this runtime mints itself" do
    # Mirrors `a_settled_delegation_is_a_block_with_a_digest_and_no_result`. A delegation
    # is a fact about work this session caused, so the parent's transcript draws it — with
    # a digest of the result and never the result, which is the child's own record.
    test "a_settled_delegation_is_a_block_with_a_digest_and_no_result" do
      block = runtime_block(cell("event_delegation"))

      assert block.label == "Delegation completed"

      assert block.detail ==
               "task task-0000000000000000000000002 · ouroboros@worker · result digest b7e40aa1"

      assert block.tone == :success

      assert block.key == nil,
             "nothing local ever drew this, so there is nothing to dedupe against"
    end

    # Mirrors `a_runtime_status_event_reads_as_a_named_note`. `status` is Ouroboros's own
    # type and no client models it, so it takes the same named-note path an unrecognised
    # provider kind does.
    test "a_runtime_status_event_reads_as_a_named_note" do
      assert chat_note(cell("event_status_resumed")) == "provider event · status"
    end
  end

  # ------------------------------------------------------------------------------------
  # The corpus itself
  # ------------------------------------------------------------------------------------

  describe "the corpus itself" do
    # Mirrors `every_transcript_fixture_renders_something_a_reader_can_see`. Every `event_*`
    # fixture is named above and reaches a presentation that is not a silent drop. The list
    # is spelled out rather than globbed for the same reason the Rust half spells its own
    # out: a fixture added on either side must be given words on both, on purpose, and this
    # is where that is refused.
    test "every_transcript_fixture_renders_something_a_reader_can_see" do
      corpus = [
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
        "event_usage"
      ]

      found =
        Golden.directory()
        |> File.ls!()
        |> Enum.filter(&String.starts_with?(&1, "event_"))
        |> Enum.map(&String.replace_suffix(&1, ".json", ""))
        |> Enum.sort()

      assert found == corpus, "the transcript corpus has changed"

      for name <- corpus do
        refute match?(%Hidden{}, presentation(name)),
               "#{name} is drawn as nothing; a hide must be an empty payload, never a kind"

        # `turn_started` is the one event with no cell of its own: a running turn is already
        # announced by the working indicator, and the instant it carries is what the turn's
        # end divider states its duration from.
        if name != "event_turn_started" do
          refute cells([name]) == [], "#{name} projected to no cells at all"
        end
      end
    end

    # The one transform `from_event/1` applies before reading is `wire_shape/1`
    # (`presentation.ex:953`), which flattens the atoms an in-process coding-plane payload
    # can carry. A fixture payload has already been through `Ouroboros.Gateway.Wire`, so
    # applying it again must change nothing — otherwise every literal above would be
    # asserting the words of a payload no reader ever holds.
    test "wire_shape is the identity over a payload the wire already encoded" do
      for name <- File.ls!(Golden.directory()), String.ends_with?(name, ".json") do
        payload =
          Golden.directory()
          |> Path.join(name)
          |> File.read!()
          |> JSON.decode!()
          |> get_in(["params", "event", "payload"])

        if is_map(payload) do
          assert Presentation.wire_shape(payload) == payload,
                 "#{name}: wire_shape changed a payload the wire had already encoded"
        end
      end
    end
  end
end
