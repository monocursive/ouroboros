defmodule Ouroboros.Web.TranscriptTest do
  @moduledoc """
  Unit cover for the Elixir port of `project()` and its supporting tables.

  Test names mirror `tui/src/ui/transcript_cells.rs`'s own where one exists, so the golden
  corpus can be wired against the same behaviours by name (W1 → W2, `docs/WEB.md` §6).
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Web.Presentation
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.{Approval, Cell, Entry, Tools}
  alias Ouroboros.Web.Transcript.Diff, as: ParsedDiff

  @at "2026-08-14T00:00:00Z"

  defp event(type, payload, fields \\ []) do
    %Event{
      id: "evt-#{Keyword.get(fields, :sequence, 1)}",
      session_id: "sess-1",
      sequence: Keyword.get(fields, :sequence, 1),
      type: type,
      timestamp: Keyword.get(fields, :timestamp, @at),
      payload: payload,
      turn_id: Keyword.get(fields, :turn_id, "turn-1"),
      request_id: Keyword.get(fields, :request_id)
    }
  end

  defp entries(events), do: Enum.map(events, &%Entry.Event{event: &1})

  defp project(events), do: events |> entries() |> Transcript.project()

  defp at(offset) do
    seconds = rem(offset, 60)
    minutes = div(offset, 60)
    "2026-08-14T00:#{pad(minutes)}:#{pad(seconds)}Z"
  end

  defp pad(value), do: String.pad_leading(Integer.to_string(value), 2, "0")

  # ------------------------------------------------------------------------------------

  describe "entries" do
    test "a contiguous ledger interleaves nothing but its events" do
      events = %{1 => event(:session_ready, %{}), 2 => event(:turn_started, %{})}

      assert [%Entry.Event{}, %Entry.Event{}] = Transcript.entries(events)
    end

    test "a hole between two held sequences is drawn as a gap exactly once" do
      events = %{1 => event(:session_ready, %{}), 5 => event(:turn_started, %{})}

      assert [
               %Entry.Event{},
               %Entry.Gap{from: 2, to: 4},
               %Entry.Event{}
             ] = Transcript.entries(events)
    end

    test "the floor sits where the hole is, not at the top of a transcript still held" do
      # A client that held events before a prune still holds them, and they are still
      # history (`tui/src/ui/transcript.rs:1038-1043`).
      events = %{3 => event(:session_ready, %{}), 10 => event(:turn_started, %{})}

      assert [
               %Entry.Event{},
               %Entry.Floor{sequence: 5},
               %Entry.Event{}
             ] = Transcript.entries(events, floor: 5)
    end

    test "nothing is reported missing across a floor" do
      events = %{3 => event(:session_ready, %{}), 10 => event(:turn_started, %{})}

      refute Enum.any?(Transcript.entries(events, floor: 5), &match?(%Entry.Gap{}, &1))
    end

    test "a floor of zero draws no marker at all" do
      events = %{1 => event(:session_ready, %{})}

      refute Enum.any?(Transcript.entries(events, floor: 0), &match?(%Entry.Floor{}, &1))
    end

    test "a floor above everything held is still stated, after the events" do
      events = %{1 => event(:session_ready, %{})}

      assert [%Entry.Event{}, %Entry.Floor{sequence: 9}] =
               Transcript.entries(events, floor: 9)
    end

    test "a note is drawn just before the event it is anchored at, and ended comes last" do
      # `notes.range(notes_from..=sequence)` runs *before* the event is pushed
      # (`tui/src/ui/transcript.rs:1290-1295`), so a note anchored at sequence 1 sits above
      # event 1 rather than below it. Ported as written: a divider that moved would put an
      # interruption marker beside a different turn on the two surfaces.
      events = %{1 => event(:session_ready, %{}), 2 => event(:turn_started, %{})}
      notes = %{1 => :reconnected, 9 => {:lagged, 4}}

      assert [
               %Entry.Note{note: :reconnected},
               %Entry.Event{},
               %Entry.Event{},
               %Entry.Note{note: {:lagged, 4}},
               %Entry.Ended{status: "completed"}
             ] = Transcript.entries(events, notes: notes, ended: "completed")
    end

    test "an empty ledger with a floor and an end still says both" do
      assert [%Entry.Floor{sequence: 3}, %Entry.Ended{status: "failed"}] =
               Transcript.entries(%{}, floor: 3, ended: "failed")
    end
  end

  describe "dividers from entries" do
    test "stream_integrity_markers_stay_in_the_reading_path" do
      cells =
        Transcript.project([
          %Entry.Floor{sequence: 4},
          %Entry.Gap{from: 5, to: 7},
          %Entry.Note{note: {:lagged, 12}},
          %Entry.Note{note: :client_dropped},
          %Entry.Note{note: :reconnected},
          %Entry.Ended{status: "completed"}
        ])

      assert Enum.map(cells, & &1.text) == [
               "Earlier conversation is no longer available",
               "Restoring 3 missing updates",
               "Some live updates were missed by the gateway",
               "Some live updates were missed by this client",
               "Connection restored",
               "Session ended (completed)"
             ]

      assert Enum.all?(cells, &match?(%Cell.Divider{}, &1))
    end

    test "a local note draws the runtime block itself rather than a divider" do
      block = %Cell.Runtime{label: "$ command abc", detail: "exit 0", key: "abc"}

      assert [%Cell.Runtime{label: "$ command abc"}] =
               Transcript.project([%Entry.Note{note: {:local, block}}])
    end
  end

  describe "agent text" do
    test "collapses_streamed_agent_text_into_one_message_cell_per_turn" do
      cells =
        project([
          event(:output_text_delta, %{"text" => "Hello "}, sequence: 1),
          event(:output_text_delta, %{"text" => "there"}, sequence: 2),
          event(:output_text_delta, %{"text" => ", friend"}, sequence: 3)
        ])

      assert [%Cell.Message{speaker: :agent, text: "Hello there, friend", streaming: true}] =
               cells
    end

    test "a final text replaces the accumulated draft rather than appending to it" do
      cells =
        project([
          event(:output_text_delta, %{"text" => "partial"}, sequence: 1),
          event(:output_text_final, %{"text" => "the whole answer"}, sequence: 2)
        ])

      assert [%Cell.Message{text: "the whole answer", streaming: false}] = cells
    end

    test "an empty final falls back to the draft the deltas built" do
      cells =
        project([
          event(:output_text_delta, %{"text" => "only the deltas"}, sequence: 1),
          event(:output_text_final, %{"text" => ""}, sequence: 2)
        ])

      # The empty final hides, so the draft flushes at the end of the projection.
      assert [%Cell.Message{text: "only the deltas", streaming: true}] = cells
    end

    test "a delta for a different turn flushes the draft before starting a new one" do
      cells =
        project([
          event(:output_text_delta, %{"text" => "turn one"}, sequence: 1, turn_id: "t1"),
          event(:output_text_delta, %{"text" => "turn two"}, sequence: 2, turn_id: "t2")
        ])

      assert [
               %Cell.Message{text: "turn one", streaming: false},
               %Cell.Message{text: "turn two", streaming: true}
             ] = cells
    end

    test "anything drawn between deltas closes the message that was open" do
      cells =
        project([
          event(:output_text_delta, %{"text" => "before"}, sequence: 1),
          event(:tool_call, %{"call_id" => "c1", "name" => "bash"}, sequence: 2),
          event(:output_text_delta, %{"text" => "after"}, sequence: 3)
        ])

      assert [
               %Cell.Message{text: "before", streaming: false},
               %Cell.Tool{name: "bash"},
               %Cell.Message{text: "after", streaming: true}
             ] = cells
    end

    test "caps_accumulated_agent_streams" do
      deltas =
        for index <- 1..300 do
          event(:output_text_delta, %{"text" => String.duplicate("x", 1024)}, sequence: index)
        end

      assert [%Cell.Message{text: text}] = project(deltas)
      assert byte_size(text) <= 128 * 1024
      assert String.ends_with?(text, "full updates are available in event details")
    end

    test "an_input_the_ledger_did_not_record_still_appears_in_the_chat" do
      cells =
        project([
          event(:input_accepted, %{"kind" => "message"}, sequence: 1),
          event(:input_accepted, %{"kind" => "steer", "text" => "stop"}, sequence: 2)
        ])

      assert [
               %Cell.ChatNote{text: "[message not recorded]"},
               %Cell.ChatNote{text: "You steered the agent: stop"}
             ] = cells
    end
  end

  describe "thinking" do
    test "consecutive_reasoning_deltas_accumulate_into_one_cell_per_turn" do
      cells =
        project([
          event(:thinking_delta, %{"text" => "first\n"}, sequence: 1),
          event(:thinking_delta, %{"text" => "second\n"}, sequence: 2)
        ])

      assert [%Cell.Thinking{text: "first\nsecond\n", lines: 2}] = cells
    end

    test "reasoning_tails_while_live_and_collapses_once_anything_follows_it" do
      live = project([event(:thinking_delta, %{"text" => "still going"}, sequence: 1)])
      assert [%Cell.Thinking{state: :tail}] = live

      settled =
        project([
          event(:thinking_delta, %{"text" => "done thinking"}, sequence: 1),
          event(:output_text_final, %{"text" => "the answer"}, sequence: 2)
        ])

      assert [%Cell.Thinking{state: :collapsed}, %Cell.Message{}] = settled
    end

    test "only the last reasoning cell tails, whatever came before it" do
      cells =
        project([
          event(:thinking_delta, %{"text" => "one"}, sequence: 1, turn_id: "t1"),
          event(:output_text_final, %{"text" => "a"}, sequence: 2, turn_id: "t1"),
          event(:thinking_delta, %{"text" => "two"}, sequence: 3, turn_id: "t2")
        ])

      assert [
               %Cell.Thinking{state: :collapsed, text: "one"},
               %Cell.Message{},
               %Cell.Thinking{state: :tail, text: "two"}
             ] = cells
    end

    test "a reasoning delta that is not adjacent opens a new cell" do
      cells =
        project([
          event(:thinking_delta, %{"text" => "one"}, sequence: 1),
          event(:tool_call, %{"call_id" => "c", "name" => "bash"}, sequence: 2),
          event(:thinking_delta, %{"text" => "two"}, sequence: 3)
        ])

      assert [%Cell.Thinking{text: "one"}, %Cell.Tool{}, %Cell.Thinking{text: "two"}] = cells
    end
  end

  describe "tool correlation" do
    test "correlates_a_tool_result_into_one_compact_cell" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "bash", "input" => %{"cmd" => "ls"}},
            sequence: 1,
            timestamp: at(0)
          ),
          event(:tool_result, %{"call_id" => "c1", "output" => "a\nb\n"},
            sequence: 2,
            timestamp: at(3)
          )
        ])

      assert [%Cell.Tool{} = tool] = cells
      assert tool.name == "bash"
      assert tool.state == :completed
      assert tool.output == "a\nb\n"
      assert Cell.Tool.elapsed(tool) == 3_000
    end

    test "a_failed_tool_result_stays_visibly_failed" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "bash"}, sequence: 1),
          event(:tool_result, %{"call_id" => "c1", "is_error" => true, "output" => "nope"},
            sequence: 2
          )
        ])

      assert [%Cell.Tool{state: :failed}] = cells
    end

    test "repeated_tool_call_with_the_same_id_updates_one_running_row" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "tool"}, sequence: 1),
          event(:tool_call, %{"call_id" => "c1", "name" => "bash", "input" => %{"cmd" => "ls"}},
            sequence: 2
          )
        ])

      assert [%Cell.Tool{name: "bash", input: %{"cmd" => "ls"}, state: :running}] = cells
    end

    test "an uncorrelated result still gets a row rather than vanishing" do
      assert [%Cell.Tool{name: "tool result", state: :completed}] =
               project([event(:tool_result, %{"output" => "orphan"}, sequence: 1)])
    end

    test "a result names the tool when the call never did" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1"}, sequence: 1),
          event(:tool_result, %{"call_id" => "c1", "name" => "Grep"}, sequence: 2)
        ])

      assert [%Cell.Tool{name: "Grep"}] = cells
    end

    test "a_running_tool_is_timed_against_the_newest_event_the_window_holds" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "bash"},
            sequence: 1,
            timestamp: at(0)
          ),
          event(:output_text_delta, %{"text" => "meanwhile"}, sequence: 2, timestamp: at(9))
        ])

      assert [%Cell.Tool{state: :running} = tool, %Cell.Message{}] = cells
      assert Cell.Tool.elapsed(tool) == 9_000
    end

    test "unrelated_streamed_command_output_never_hides_a_correlated_result" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "bash"}, sequence: 1),
          event(:command_output_delta, %{"text" => "streaming\n"}, sequence: 2),
          event(:tool_result, %{"call_id" => "c1", "output" => "authoritative"}, sequence: 3)
        ])

      assert [%Cell.Tool{output: "authoritative"}, %Cell.CommandOutput{text: "streaming\n"}] =
               cells
    end

    test "a_desktop_state_result_projects_a_tool_cell_and_an_image_cell" do
      sha = String.duplicate("cd", 32)

      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "desktop_state"}, sequence: 1),
          event(
            :tool_result,
            %{
              "call_id" => "c1",
              "output" => "captured",
              "artifacts" => [
                %{
                  "kind" => "image",
                  "sha256" => sha,
                  "media_type" => "image/png",
                  "width" => 100,
                  "height" => 50
                }
              ]
            },
            sequence: 2
          )
        ])

      assert [%Cell.Tool{name: "desktop_state"}, %Cell.Image{} = image] = cells
      assert image.sha == sha
      assert image.pixels == {100, 50}
      assert image.format == "png"
      assert Cell.Image.label(image) == "[image 100×50 png · desktop capture · cdcdcdcdcdcd]"
    end
  end

  describe "exploration folding" do
    test "consecutive_exploration_collapses_and_flips_when_anything_else_is_drawn" do
      reads =
        for index <- 1..3 do
          event(
            :tool_call,
            %{"call_id" => "c#{index}", "name" => "read", "input" => %{"path" => "a#{index}.ex"}},
            sequence: index
          )
        end

      assert [%Cell.Exploration{calls: calls, done: false}] = project(reads)
      assert length(calls) == 3

      assert [%Cell.Exploration{done: true}, %Cell.Message{}] =
               project(reads ++ [event(:output_text_final, %{"text" => "done"}, sequence: 9)])
    end

    test "work_is_never_folded_into_the_exploration_count" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "read"}, sequence: 1),
          event(:tool_call, %{"call_id" => "c2", "name" => "bash"}, sequence: 2),
          event(:tool_call, %{"call_id" => "c3", "name" => "write"}, sequence: 3),
          event(:tool_call, %{"call_id" => "c4", "name" => "grep"}, sequence: 4)
        ])

      assert [
               %Cell.Exploration{calls: [%{name: "read"}]},
               %Cell.Tool{name: "bash"},
               %Cell.Tool{name: "write"},
               %Cell.Exploration{calls: [%{name: "grep"}]}
             ] = cells
    end

    test "an_exploration_group_bounds_what_it_lists_and_counts_the_rest" do
      reads =
        for index <- 1..100 do
          event(:tool_call, %{"call_id" => "c#{index}", "name" => "read"}, sequence: index)
        end

      assert [%Cell.Exploration{} = group] = project(reads)
      assert length(group.calls) == 64
      assert group.overflow == 36
      assert Cell.Exploration.total(group) == 100
    end

    test "a result correlates into the grouped call it belongs to" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "read"}, sequence: 1),
          event(:tool_call, %{"call_id" => "c2", "name" => "read"}, sequence: 2),
          event(:tool_result, %{"call_id" => "c2", "is_error" => true}, sequence: 3)
        ])

      assert [%Cell.Exploration{calls: [%{state: :running}, %{state: :failed}]} = group] = cells
      assert Cell.Exploration.failed(group) == 1
    end

    test "a_turn_boundary_closes_an_open_exploration_group" do
      cells =
        project([
          event(:tool_call, %{"call_id" => "c1", "name" => "read"}, sequence: 1),
          event(:turn_completed, %{}, sequence: 2)
        ])

      assert [%Cell.Exploration{done: true}, %Cell.Divider{kind: :turn_end}] = cells
    end
  end

  describe "diffs" do
    @diff """
    diff --git a/lib/a.ex b/lib/a.ex
    --- a/lib/a.ex
    +++ b/lib/a.ex
    @@ -1,3 +1,4 @@
     defmodule A do
    -  def old, do: 1
    +  def new, do: 2
    +  def extra, do: 3
     end
    """

    test "a_diff_prints_what_it_can_count_not_what_the_provider_claimed" do
      cells =
        project([
          event(:file_change, %{"diff" => @diff, "additions" => 999, "deletions" => 999},
            sequence: 1
          )
        ])

      assert [%Cell.Diff{parsed: parsed, diff: held}] = cells

      # The numbers a surface prints are counted from the hunk bodies. The provider
      # claimed 999 of each and neither number reaches any cell
      # (`tui/src/ui/diff.rs:14-21`).
      assert ParsedDiff.additions(parsed) == 2
      assert ParsedDiff.deletions(parsed) == 1
      assert held.additions == 2
      assert held.deletions == 1
    end

    test "a_diff_cell_counts_the_hunks_it_holds_and_numbers_the_lines" do
      parsed = ParsedDiff.parse(@diff)

      assert [file] = parsed.files
      assert file.path == "lib/a.ex"
      assert file.status == :modified
      assert file.additions == 2
      assert file.deletions == 1

      assert [hunk] = file.hunks
      assert hunk.old_start == 1
      assert hunk.new_start == 1

      # The trailing newline yields one more empty line, and an empty line inside a hunk is
      # context, not the end of it: tools that trim trailing whitespace emit these
      # constantly, and reading one as "end of hunk" loses the rest of the file
      # (`tui/src/ui/diff.rs:389-391`).
      assert Enum.map(hunk.lines, &{&1.kind, &1.old_no, &1.new_no}) == [
               {:context, 1, 1},
               {:removed, 2, nil},
               {:added, nil, 2},
               {:added, nil, 3},
               {:context, 3, 4},
               {:context, 4, 5}
             ]
    end

    test "a new and a deleted file are read from their /dev/null halves" do
      added = ParsedDiff.parse("--- /dev/null\n+++ b/new.ex\n@@ -0,0 +1 @@\n+hello\n")
      assert [%{path: "new.ex", status: :added, additions: 1}] = added.files

      deleted = ParsedDiff.parse("--- a/gone.ex\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye\n")
      assert [%{path: "gone.ex", status: :deleted, deletions: 1}] = deleted.files
    end

    test "a rename keeps both halves and a binary patch says so" do
      renamed =
        ParsedDiff.parse("diff --git a/old.ex b/new.ex\nrename from old.ex\nrename to new.ex\n")

      assert [%{path: "new.ex", old_path: "old.ex", status: :renamed}] = renamed.files

      binary = ParsedDiff.parse("Binary files a/logo.png and b/logo.png differ\n")
      assert [%{path: "logo.png", status: :binary}] = binary.files
    end

    test "a bare-hunk diff takes the fallback path the caller named" do
      parsed = ParsedDiff.parse("@@ -1 +1 @@\n-a\n+b\n", "lib/known.ex")
      assert [%{path: "lib/known.ex", additions: 1, deletions: 1}] = parsed.files
    end

    test "a_diff_with_no_hunks_is_shown_verbatim_rather_than_dropped" do
      # Every `@@` was written in a dialect this build cannot read.
      parsed = ParsedDiff.parse("--- a/x\n+++ b/x\n@@ nonsense @@\n+a\n")
      assert parsed.files == []
      assert ParsedDiff.empty?(parsed)
    end

    test "a_diff_under_an_open_approval_stays_expanded_and_says_so" do
      cells =
        project([
          event(
            :approval_requested,
            %{"tool_call" => %{"name" => "edit", "path" => "lib/a.ex"}},
            sequence: 1,
            request_id: "req-1"
          ),
          event(:file_change, %{"diff" => @diff}, sequence: 2)
        ])

      assert [%Cell.Status{label: "Approval needed"}, %Cell.Diff{pending_approval: true}] = cells
    end

    test "an_unrelated_approval_does_not_claim_a_diff_it_was_not_about" do
      cells =
        project([
          event(
            :approval_requested,
            %{"tool_call" => %{"name" => "bash", "command" => "make release"}},
            sequence: 1,
            request_id: "req-1"
          ),
          event(:file_change, %{"diff" => @diff}, sequence: 2)
        ])

      assert [%Cell.Status{}, %Cell.Diff{pending_approval: false}] = cells
    end

    test "a resolved approval collapses the diffs it was about" do
      cells =
        project([
          event(
            :approval_requested,
            %{"tool_call" => %{"name" => "edit", "path" => "lib/a.ex"}},
            sequence: 1,
            request_id: "req-1"
          ),
          event(:file_change, %{"diff" => @diff}, sequence: 2),
          event(:approval_resolved, %{"decision" => "approve"}, sequence: 3, request_id: "req-1")
        ])

      assert [%Cell.Status{label: "Approved"}, %Cell.Diff{pending_approval: false}] = cells
    end

    test "a_turn_end_carries_a_diffstat_of_what_that_turn_changed" do
      cells =
        project([
          event(:file_change, %{"diff" => @diff}, sequence: 1),
          event(:turn_completed, %{}, sequence: 2)
        ])

      assert [
               %Cell.Diff{},
               %Cell.DiffStat{files: 1, additions: 2, deletions: 1, in_excerpt: false},
               %Cell.Divider{kind: :turn_end}
             ] = cells
    end

    test "a_turn_that_changed_nothing_draws_no_diffstat" do
      cells = project([event(:turn_completed, %{}, sequence: 1)])
      assert [%Cell.Divider{kind: :turn_end}] = cells
    end

    test "an_excerpted_diff_marks_its_counts_in_excerpt_everywhere" do
      excerpt = "--- a/lib/a.ex\n+++ b/lib/a.ex\n@@ -1 +1,2 @@\n one\n+two\n"

      cells =
        project([
          event(:file_change, %{"diff" => %{"_excerpt" => excerpt, "_bytes" => 9_000}},
            sequence: 1
          ),
          event(:turn_completed, %{}, sequence: 2)
        ])

      assert [%Cell.Diff{diff: %{truncated: true}}, %Cell.DiffStat{in_excerpt: true}, _divider] =
               cells
    end

    test "an excerpt that parsed to no file at all draws no diffstat to be wrong about" do
      cells =
        project([
          event(:file_change, %{"diff" => %{"_excerpt" => "+one\n", "_bytes" => 9_000}},
            sequence: 1
          ),
          event(:turn_completed, %{}, sequence: 2)
        ])

      assert [%Cell.Diff{}, %Cell.Divider{kind: :turn_end}] = cells
    end

    test "a file change with a path draws a file row and then its diff" do
      cells =
        project([
          event(
            :file_change,
            %{
              "status" => "completed",
              "changes" => [%{"path" => "lib/a.ex", "kind" => "modify", "diff" => @diff}]
            },
            sequence: 1
          )
        ])

      assert [%Cell.File{path: "lib/a.ex", kind: "modify"}, %Cell.Diff{}] = cells
    end

    test "a file change with no path and no diff still says something happened" do
      assert [%Cell.File{path: nil, kind: "completed"}] =
               project([event(:file_change, %{"status" => "completed"}, sequence: 1)])
    end
  end

  describe "approvals" do
    test "a_resolved_approval_replaces_the_pending_status" do
      cells =
        project([
          event(:approval_requested, %{"command" => "rm -rf /"}, sequence: 1, request_id: "r1"),
          event(:approval_resolved, %{"decision" => "deny", "reason" => "too broad"},
            sequence: 2,
            request_id: "r1"
          )
        ])

      assert [%Cell.Status{label: "Denied", tone: :warning, detail: detail}] = cells
      assert detail =~ "rm -rf /"
      assert detail =~ "deny · too broad"
    end

    test "an approval resolved with no matching request still gets its own row" do
      cells =
        project([
          event(:approval_resolved, %{"decision" => "approve"}, sequence: 1, request_id: "r9")
        ])

      assert [%Cell.Status{label: "Approved", tone: :success}] = cells
    end

    test "a decision this build does not know resolves without inventing a verdict" do
      cells =
        project([
          event(:approval_requested, %{"command" => "x"}, sequence: 1, request_id: "r1"),
          event(:approval_resolved, %{"decision" => "escalated"}, sequence: 2, request_id: "r1")
        ])

      assert [%Cell.Status{label: "Approval resolved", tone: :muted}] = cells
    end

    test "pending approvals are rebuilt from the whole ledger, not folded incrementally" do
      # The resolution is absorbed *before* the request in arrival order; the ordered
      # rebuild still answers that nothing is pending
      # (`tui/src/ui/transcript.rs:1331-1337`).
      events = %{
        1 => event(:approval_requested, %{"command" => "a"}, sequence: 1, request_id: "r1"),
        2 => event(:approval_resolved, %{"decision" => "approve"}, sequence: 2, request_id: "r1"),
        3 => event(:approval_requested, %{"command" => "b"}, sequence: 3, request_id: "r2")
      }

      assert [%Approval{request_id: "r2", sequence: 3}] = Transcript.pending_approvals(events)

      # Absorbing the same events in any other order changes nothing.
      shuffled = Map.new(Enum.shuffle(Map.to_list(events)))
      assert Transcript.pending_approvals(shuffled) == Transcript.pending_approvals(events)
    end

    test "an approval event with no request id is not pending anything" do
      events = %{1 => event(:approval_requested, %{"command" => "a"}, sequence: 1)}
      assert Transcript.pending_approvals(events) == []
    end

    test "planning is nil until an event speaks, and only an event takes it down" do
      assert Transcript.planning(%{}) == nil

      assert Transcript.planning(%{
               1 => event(:provider_event, %{"kind" => "plan_exit", "plan" => true}, sequence: 1)
             }) == true

      assert Transcript.planning(%{
               1 => event(:provider_event, %{"kind" => "plan_exit", "plan" => true}, sequence: 1),
               2 =>
                 event(:status, %{"kind" => "configured", "changed" => %{"plan" => false}},
                   sequence: 2
                 )
             }) == false
    end
  end

  describe "approval detail" do
    test "every field is optional and none is invented" do
      request = %Approval{request_id: "r1", sequence: 1, payload: %{}}
      detail = Approval.detail(request)

      assert detail.kind == nil
      assert detail.title == nil
      assert detail.command == nil
      assert detail.reason == nil
      assert detail.suggested_rule == nil
      assert detail.locations == []
      assert detail.options == []
      assert detail.diff == nil
      assert detail.edits == []
      assert detail.plan == nil
      assert detail.subagent == nil
    end

    test "a sandbox escalation reads its command, reason and suggested rule" do
      request = %Approval{
        request_id: "r1",
        sequence: 1,
        payload: %{
          "kind" => "sandbox_escalation",
          "tool_call" => %{"name" => "bash", "command" => "git commit", "cwd" => "/w"},
          "reason" => "writes to .git",
          "suggested_rule" => "Bash(git commit:*)"
        }
      }

      detail = Approval.detail(request)
      assert detail.kind == "sandbox escalation"
      assert detail.command == "git commit"
      assert detail.cwd == "/w"
      assert detail.reason == "writes to .git"
      assert detail.suggested_rule == "Bash(git commit:*)"
      assert Approval.subject(request) == "git commit — writes to .git"
    end

    test "a suggested rule that arrived as a map is not rendered as one" do
      # `Control.Permissions.suggest/1` answers a string; the sandbox-escalation path
      # sends a map. Only the string form is a rule this surface can offer to save.
      request = %Approval{
        request_id: "r1",
        sequence: 1,
        payload: %{"suggested_rule" => %{"pattern" => "Bash(git:*)", "scope" => "workspace"}}
      }

      assert Approval.detail(request).suggested_rule == nil
    end

    test "a command sent as an argv array reads as one line" do
      request = %Approval{
        request_id: "r1",
        sequence: 1,
        payload: %{"tool_call" => %{"command" => ["git", "commit", "-m", "wip"]}}
      }

      assert Approval.detail(request).command == "git commit -m wip"
    end

    test "provider options keep their own words and map only what they name" do
      request = %Approval{
        request_id: "r1",
        sequence: 1,
        payload: %{
          "options" => [
            %{"optionId" => "a", "name" => "Allow once", "kind" => "allow_once"},
            %{"optionId" => "b", "name" => "Always allow", "kind" => "allow_always"},
            %{"optionId" => "c", "name" => "Reject", "kind" => "reject_once"},
            %{"optionId" => "d", "name" => "Never again", "kind" => "reject_always"},
            %{"optionId" => "e", "name" => "Escalate to a human", "kind" => "escalate"}
          ]
        }
      }

      options = Approval.detail(request).options

      assert Enum.map(options, &Approval.Option.decision/1) == [
               {:approve, :once},
               {:approve, :session},
               {:deny, :once},
               {:deny, :session},
               nil
             ]

      assert Enum.map(options, & &1.name) |> List.last() == "Escalate to a human"
    end

    test "acp locations and diff content blocks are named, never diffed a second time" do
      request = %Approval{
        request_id: "r1",
        sequence: 1,
        payload: %{
          "toolCall" => %{
            "locations" => [%{"path" => "lib/a.ex"}, "lib/b.ex"],
            "content" => [
              %{"type" => "diff", "path" => "lib/a.ex", "oldText" => "one", "newText" => "three"},
              %{"type" => "diff", "path" => "lib/new.ex", "newText" => "fresh"},
              %{"type" => "text", "text" => "ignored"}
            ]
          }
        }
      }

      detail = Approval.detail(request)
      assert detail.locations == ["lib/a.ex", "lib/b.ex"]

      assert [
               %Approval.Edit{path: "lib/a.ex", kind: "update", old_bytes: 3, new_bytes: 5},
               %Approval.Edit{path: "lib/new.ex", kind: "add", old_bytes: 0, new_bytes: 5}
             ] = detail.edits
    end

    test "an excerpted approval diff is drawn as a prefix and marked as one" do
      request = %Approval{
        request_id: "r1",
        sequence: 1,
        payload: %{"diff" => %{"_excerpt" => "+one\n", "_bytes" => 4_000}}
      }

      detail = Approval.detail(request)
      assert detail.diff_excerpted == true
      assert detail.diff.truncated == true
    end

    test "a subagent-attributed request names the child that asked" do
      request = %Approval{
        request_id: "r1",
        sequence: 1,
        payload: %{
          "subagent" => %{
            "description" => "run the tests",
            "task_id" => "task-9",
            "node" => "worker@host"
          }
        }
      }

      subagent = Approval.detail(request).subagent
      assert Approval.Subagent.attribution(subagent) == "asked by subagent run the tests (task-9)"
      # Every child runs somewhere; the node is drawn only where it is news.
      assert Approval.Subagent.remote_node(subagent, "worker@host") == nil
      assert Approval.Subagent.remote_node(subagent, "primary@host") == "worker@host"
      assert Approval.Subagent.remote_node(subagent, nil) == nil
    end
  end

  describe "the question carve-out" do
    test "a plan exit and an ask_user question are questions, not permissions" do
      for kind <- ["plan_exit", "question"] do
        assert Transcript.question?(%Approval{
                 request_id: "r",
                 sequence: 1,
                 payload: %{"kind" => kind}
               })
      end
    end

    test "computer use observe and act are questions so auto-approve cannot answer them" do
      for name <- ["desktop_state", "desktop_act"] do
        assert Transcript.question?(%Approval{
                 request_id: "r",
                 sequence: 1,
                 payload: %{"tool_call" => %{"name" => name}}
               })
      end
    end

    test "an ordinary permission is not a question" do
      refute Transcript.question?(%Approval{
               request_id: "r",
               sequence: 1,
               payload: %{"kind" => "permissions", "tool_call" => %{"name" => "bash"}}
             })
    end
  end

  describe "plan exit" do
    defp plan_exit_payload(options) do
      %{
        "kind" => "plan_exit",
        "header" => "Plan ready",
        "question" => "Build it, or keep planning?",
        "plan_source" => "plan_tool",
        "plan" => %{"plan" => [%{"step" => "write the port", "status" => "pending"}]},
        "options" => options
      }
    end

    test "the three answers decode in the payload's own order" do
      plan =
        Approval.plan_exit(
          plan_exit_payload([
            %{"optionId" => "auto_edit", "name" => "Build it"},
            %{"optionId" => "prompt", "name" => "Build it, asking first"},
            %{"optionId" => "keep_planning", "name" => "Keep planning"}
          ])
        )

      assert plan.header == "Plan ready"
      assert plan.source == "plan_tool"
      assert plan.step_count == 1
      assert [%{text: "write the port"}] = plan.steps

      assert Enum.map(plan.choices, &{&1.choice, &1.name}) == [
               {:auto_edit, "Build it"},
               {:prompt, "Build it, asking first"},
               {:keep_planning, "Keep planning"}
             ]

      assert plan.unmapped == []
    end

    test "an option this build cannot map is reported, never offered" do
      plan =
        Approval.plan_exit(
          plan_exit_payload([
            %{"optionId" => "auto_edit", "name" => "Build it"},
            %{"optionId" => "delegate_to_a_team", "name" => "Hand it to a team"},
            %{"name" => "A nameless id"}
          ])
        )

      assert Enum.map(plan.choices, & &1.choice) == [:auto_edit]
      assert plan.unmapped == ["Hand it to a team (delegate_to_a_team)", "A nameless id"]
    end

    test "a plan exit whose options map onto nothing is not a plan exit card" do
      plan =
        Approval.plan_exit(
          plan_exit_payload([%{"optionId" => "something_new", "name" => "Something new"}])
        )

      assert plan == nil
    end

    test "an approval that is not a plan exit decodes no plan" do
      assert Approval.plan_exit(%{"kind" => "permissions", "options" => []}) == nil
    end

    test "each choice degrades to the four-way answer the runtime falls back to" do
      assert Approval.PlanChoice.decision(:auto_edit) == {:approve, :session}
      assert Approval.PlanChoice.decision(:prompt) == {:approve, :once}
      assert Approval.PlanChoice.decision(:keep_planning) == {:deny, :once}
      assert Approval.PlanChoice.parse("nope") == nil
    end

    test "the plan-exit subject is the runtime's own header, never the payload as JSON" do
      request = %Approval{request_id: "r1", sequence: 1, payload: plan_exit_payload([])}
      assert Approval.subject(request) == "Plan ready"

      bare = %Approval{request_id: "r1", sequence: 1, payload: %{"kind" => "plan_exit"}}
      assert Approval.subject(bare) == "plan ready — build it, or keep planning"
    end
  end

  describe "the suggested-rule gate" do
    test "three conditions have to hold, and each failure is named" do
      methods = ["permissions.add", "interactive.start"]

      assert {%Approval.Rule{pattern: "Bash(ls:*)", workspace: "/w"}, nil} =
               Transcript.suggested_rule("Bash(ls:*)", methods, "/w")

      # The runtime suggested nothing: no offer, and nothing to explain.
      assert {nil, nil} = Transcript.suggested_rule(nil, methods, "/w")

      # This runtime does not serve the verb that would save it.
      assert {nil, reason} = Transcript.suggested_rule("Bash(ls:*)", ["interactive.start"], "/w")
      assert reason == "this runtime does not serve permissions.add, so the rule cannot be saved"

      # The session names no workspace to scope it in.
      assert {nil, reason} = Transcript.suggested_rule("Bash(ls:*)", methods, nil)
      assert reason == "this session names no workspace, so there is no scope to save the rule in"

      assert {nil, ^reason} = Transcript.suggested_rule("Bash(ls:*)", methods, "   ")
    end

    test "a ComputerUse pattern is user-scoped, so a missing workspace does not hide it" do
      assert {%Approval.Rule{pattern: "ComputerUse(Safari)", workspace: ""}, nil} =
               Transcript.suggested_rule("ComputerUse(Safari)", ["permissions.add"], nil)
    end
  end

  describe "subagent folding" do
    test "one row per task_id, rewritten rather than appended" do
      cells =
        project([
          subagent(1, %{
            "phase" => "spawned",
            "task_id" => "t1",
            "description" => "run the tests",
            "background" => true,
            "depth" => 2
          }),
          subagent(2, %{"phase" => "progress", "task_id" => "t1", "turns" => 2}),
          subagent(3, %{"phase" => "progress", "task_id" => "t1", "turns" => 4}),
          subagent(4, %{
            "phase" => "settled",
            "task_id" => "t1",
            "status" => "completed",
            "tool_calls" => 9,
            "input_tokens" => 100,
            "output_tokens" => 20
          })
        ])

      assert [%Cell.Subagent{} = cell] = cells
      assert cell.task_id == "t1"
      assert cell.settled == true
      assert cell.status == "completed"
      assert cell.turns == 4
      assert cell.tool_calls == 9
      assert Cell.Subagent.tone(cell) == :success
      assert Cell.Subagent.headline(cell) == "Subagent run the tests · background · depth 2"

      assert Cell.Subagent.detail(cell) ==
               "completed · 4 turns · 9 tool calls · 100 in / 20 out tokens"
    end

    test "a progress report that omits a counter leaves the last one standing" do
      cells =
        project([
          subagent(1, %{"phase" => "spawned", "task_id" => "t1", "background" => true}),
          subagent(2, %{"phase" => "progress", "task_id" => "t1", "tool_calls" => 5}),
          subagent(3, %{"phase" => "progress", "task_id" => "t1", "turns" => 3})
        ])

      assert [%Cell.Subagent{tool_calls: 5, turns: 3, background: true}] = cells
    end

    test "absorbing the same event twice changes nothing" do
      once = project([subagent(1, %{"phase" => "settled", "task_id" => "t1", "turns" => 2})])

      twice =
        project([
          subagent(1, %{"phase" => "settled", "task_id" => "t1", "turns" => 2}),
          subagent(2, %{"phase" => "settled", "task_id" => "t1", "turns" => 2})
        ])

      assert once == twice
    end

    test "a settled child this window never saw spawn still gets a row" do
      cells =
        project([
          subagent(1, %{"phase" => "settled", "task_id" => "t9", "status" => "failed"})
        ])

      assert [%Cell.Subagent{settled: true, status: "failed"} = cell] = cells
      assert Cell.Subagent.tone(cell) == :error
    end

    test "two children get two rows, and an unnamed task gets one row per event" do
      folded =
        project([
          subagent(1, %{"phase" => "spawned", "task_id" => "a"}),
          subagent(2, %{"phase" => "spawned", "task_id" => "b"})
        ])

      assert [%Cell.Subagent{task_id: "a"}, %Cell.Subagent{task_id: "b"}] = folded

      unnamed =
        project([
          subagent(1, %{"phase" => "spawned"}),
          subagent(2, %{"phase" => "spawned"})
        ])

      assert [%Cell.Subagent{task_id: nil}, %Cell.Subagent{task_id: nil}] = unnamed
    end

    test "a phase this build does not model is named on the row, deduped" do
      cells =
        project([
          subagent(1, %{"phase" => "hibernating", "task_id" => "t1"}),
          subagent(2, %{"phase" => "hibernating", "task_id" => "t1"}),
          subagent(3, %{"task_id" => "t1"})
        ])

      assert [%Cell.Subagent{unknown_phases: ["hibernating", "unnamed"]} = cell] = cells
      assert Cell.Subagent.rows(cell) |> hd() =~ "phase hibernating"
    end

    test "a kept worktree is worth a line and a removed one is not" do
      kept =
        project([
          subagent(1, %{
            "phase" => "settled",
            "task_id" => "t1",
            "worktree" => %{"path" => "/w/sub", "retired" => "kept"}
          })
        ])

      assert [%Cell.Subagent{worktree_kept: "/w/sub", worktree: true}] = kept

      removed =
        project([
          subagent(1, %{
            "phase" => "settled",
            "task_id" => "t1",
            "worktree" => %{"path" => "/w/sub", "retired" => "removed"}
          })
        ])

      assert [%Cell.Subagent{worktree_kept: nil}] = removed
    end

    test "a remote child badges where it ran, and a local one does not" do
      remote =
        project([
          subagent(1, %{
            "phase" => "spawned",
            "task_id" => "t1",
            "remote" => true,
            "node" => "w@h"
          })
        ])

      assert [cell] = remote
      assert Cell.Subagent.badges(cell) == ["⇄ w@h"]

      local = project([subagent(1, %{"phase" => "spawned", "task_id" => "t1", "node" => "w@h"})])
      assert [cell] = local
      assert Cell.Subagent.badges(cell) == []
    end

    defp subagent(sequence, payload) do
      event(:provider_event, Map.put(payload, "kind", "subagent"), sequence: sequence)
    end
  end

  describe "runtime blocks" do
    test "an operator command reads as its own block, deduped against a local reply" do
      shell =
        event(
          :provider_event,
          %{
            "kind" => "operator_shell",
            "command_digest" => "abcdef0123456789",
            "exit_status" => 1,
            "duration_ms" => 1_500,
            "output_bytes" => 12,
            "output_excerpt" => "boom\n"
          },
          sequence: 1
        )

      assert [%Cell.Runtime{} = block] = project([shell])
      assert block.label == "$ command abcdef012345"
      assert block.detail == "exit 1 · 1s · 12 bytes"
      assert block.body == ["boom"]
      assert block.tone == :warning
      assert block.key == "abcdef0123456789"

      # The reply this client already drew in full wins; the durable record is skipped.
      local = %Cell.Runtime{label: "$ mix test", detail: "exit 1", key: "abcdef0123456789"}

      assert [%Cell.Runtime{label: "$ mix test"}] =
               Transcript.project([
                 %Entry.Note{note: {:local, local}},
                 %Entry.Event{event: shell}
               ])
    end

    test "a compaction block names its trigger and its numbers" do
      cells =
        project([
          event(
            :provider_event,
            %{
              "kind" => "compaction",
              "trigger" => "manual",
              "archived_messages" => 1,
              "archive_id" => "arch-7"
            },
            sequence: 1
          )
        ])

      assert [%Cell.Runtime{label: "Compacted, at your request", detail: detail, key: "arch-7"}] =
               cells

      assert detail == "archived 1 message · archive arch-7"
    end

    test "a delegation block carries a digest and never the child's result" do
      cells =
        project([
          event(
            :delegation,
            %{
              "task_id" => "task-2",
              "task_node" => "coder@host",
              "status" => "completed",
              "result_digest" => "sha-9"
            },
            sequence: 1
          )
        ])

      assert [%Cell.Runtime{label: "Delegation completed", detail: detail, tone: :success}] =
               cells

      assert detail == "task task-2 · coder@host · result digest sha-9"
    end
  end

  describe "lifecycle, queue and provider notes" do
    test "the_kinds_that_used_to_be_dropped_now_reach_the_reading_path" do
      cells =
        project([
          event(:run_started, %{"model" => "claude-opus-5", "tools" => ["a", "b"]}, sequence: 1),
          event(:session_ready, %{"transport" => "jsonl"}, sequence: 2),
          event(:usage, %{"input_tokens" => 10}, sequence: 3),
          event(:provider_event, %{"kind" => "acp_update"}, sequence: 4),
          event(:session_closed, %{"reason" => "closed"}, sequence: 5)
        ])

      assert [
               %Cell.ChatNote{text: "run started · claude-opus-5 · 2 tools"},
               %Cell.ChatNote{text: "session ready · jsonl"},
               %Cell.Usage{},
               %Cell.ChatNote{text: "provider event · acp_update"},
               %Cell.Divider{text: "session closed", tone: :muted}
             ] = cells
    end

    test "a lifecycle detail the label already contains is not said twice" do
      assert [%Cell.Divider{text: "session closed"}] =
               project([event(:session_closed, %{"reason" => "closed"}, sequence: 1)])
    end

    test "an_unchanged_queue_depth_is_not_restated" do
      cells =
        project([
          event(:queue_changed, %{"queued" => 2}, sequence: 1),
          event(:queue_changed, %{"queued" => 2}, sequence: 2),
          event(:queue_changed, %{"queued" => 1}, sequence: 3),
          event(:queue_changed, %{"queued" => 0}, sequence: 4)
        ])

      assert [
               %Cell.ChatNote{text: "2 follow-ups are queued"},
               %Cell.ChatNote{text: "1 follow-up is queued"},
               %Cell.ChatNote{text: "The follow-up queue is empty"}
             ] = cells
    end

    test "a usage report that carried nothing draws no cell" do
      assert [] = project([event(:usage, %{}, sequence: 1)])
    end
  end

  describe "turn boundaries" do
    test "a_turn_boundary_divider_states_the_elapsed_time_it_measured" do
      cells =
        project([
          event(:turn_started, %{}, sequence: 1, timestamp: at(0)),
          event(:turn_completed, %{}, sequence: 2, timestamp: at(7))
        ])

      assert [%Cell.Divider{text: "turn complete · 7s", kind: :turn_end, tone: :muted}] = cells
    end

    test "a_turn_end_without_its_start_says_nothing_about_duration" do
      assert [%Cell.Divider{text: "turn complete"}] =
               project([event(:turn_completed, %{}, sequence: 1)])
    end

    test "a_failed_turn_keeps_its_error_cell_above_the_boundary" do
      cells =
        project([event(:turn_failed, %{"error" => "the model refused"}, sequence: 1)])

      assert [
               %Cell.Status{label: "Agent error", detail: "the model refused", tone: :error},
               %Cell.Divider{text: "turn failed", tone: :error, kind: :turn_end}
             ] = cells
    end

    test "an interrupted turn is warned about, not errored about" do
      cells = project([event(:turn_interrupted, %{"reason" => "you stopped it"}, sequence: 1)])

      assert [
               %Cell.Status{label: "Interrupted", tone: :warning},
               %Cell.Divider{text: "turn interrupted", tone: :warning}
             ] = cells
    end

    test "elapsed_time_is_phrased_the_way_a_status_widget_phrases_it" do
      assert Transcript.duration(840) == "840ms"
      assert Transcript.duration(7_000) == "7s"
      assert Transcript.duration(247_000) == "4m 07s"
      assert Transcript.duration(3_720_000) == "1h 02m"
    end
  end

  describe "the vendor tables" do
    test "per_tool_summaries_read_the_same_whichever_dialect_named_the_call" do
      for name <- ["read", "Read", "read_file", "view_file", "notebookRead"] do
        assert Tools.shape_of(name, nil) == :read, name
      end

      assert Tools.shape_of("Bash", nil) == :bash
      assert Tools.shape_of("exec_command", nil) == :bash
      assert Tools.shape_of("run terminal cmd", nil) == :bash
      assert Tools.shape_of("mcp__linear__create_issue", nil) == :mcp
      assert Tools.shape_of("linear.create_issue", nil) == :mcp
      assert Tools.shape_of("apply_patch", nil) == :edit
      assert Tools.shape_of("glob_file_search", nil) == :glob
      assert Tools.shape_of("google_web_search", nil) == :web_search
    end

    test "the acp kind is a fallback, never the first answer" do
      # A prose title with a kind beside it: the title matched nothing, so the kind wins.
      assert Tools.shape_of("Reading the file", "read") == :read
      # A name that matched wins over a kind that disagrees.
      assert Tools.shape_of("bash", "read") == :bash
      # A kind this build does not know leaves the call shapeless rather than guessed.
      assert Tools.shape_of("something novel", "teleport") == :other
    end

    test "only reading, searching, listing and globbing are exploration" do
      assert Enum.filter(
               [:read, :grep, :glob, :list, :edit, :bash, :write, :fetch],
               &Tools.explores?/1
             ) ==
               [:read, :grep, :glob, :list]
    end

    test "a_result_adds_a_count_the_client_can_see_and_never_one_it_cannot" do
      read = %Cell.Tool{name: "Read", input: %{"path" => "lib/a.ex"}, output: "one\ntwo\nthree\n"}
      assert %{verb: "Read", subject: "lib/a.ex", outcome: "→ 3 lines"} = Tools.summarise(read)

      # No result yet: no count, rather than a zero the surface invented.
      running = %Cell.Tool{name: "Read", input: %{"path" => "lib/a.ex"}}
      assert %{outcome: ""} = Tools.summarise(running)

      empty = %Cell.Tool{name: "Grep", input: %{"pattern" => "needle"}, output: ""}
      assert %{subject: ~s("needle"), outcome: "→ no matches"} = Tools.summarise(empty)

      one = %Cell.Tool{name: "Grep", input: %{"pattern" => "n"}, output: "hit\n"}
      assert %{outcome: "→ 1 match"} = Tools.summarise(one)
    end

    test "a read states the window the provider named" do
      assert %{subject: "lib/a.ex:10-19"} =
               Tools.summarise(%Cell.Tool{
                 name: "Read",
                 input: %{"path" => "lib/a.ex", "offset" => 10, "limit" => 10}
               })

      assert %{subject: "lib/a.ex:10-40"} =
               Tools.summarise(%Cell.Tool{
                 name: "Read",
                 input: %{"path" => "lib/a.ex", "start_line" => 10, "end_line" => 40}
               })

      assert %{subject: "lib/a.ex:1-25"} =
               Tools.summarise(%Cell.Tool{
                 name: "Read",
                 input: %{"path" => "lib/a.ex", "limit" => 25}
               })
    end

    test "an edit counts only from the two strings the call actually carried" do
      assert %{verb: "Edit", subject: "lib/a.ex (+2 −1)"} =
               Tools.summarise(%Cell.Tool{
                 name: "Edit",
                 input: %{"path" => "lib/a.ex", "old_string" => "one", "new_string" => "a\nb"}
               })

      # An edit tool that describes its change without carrying it gets no counts.
      assert %{subject: "lib/a.ex"} =
               Tools.summarise(%Cell.Tool{name: "Edit", input: %{"path" => "lib/a.ex"}})
    end

    test "a_command_states_the_exit_code_a_provider_sent_and_says_failed_when_only_is_error_did" do
      assert %{verb: "Bash", subject: "$ cargo test", outcome: "exit 1"} =
               Tools.summarise(%Cell.Tool{
                 name: "Bash",
                 input: %{"cmd" => "cargo test"},
                 output: %{"exit_code" => 1},
                 state: :failed
               })

      assert %{outcome: "failed"} =
               Tools.summarise(%Cell.Tool{
                 name: "Bash",
                 input: %{"cmd" => "cargo test"},
                 state: :failed
               })

      assert %{outcome: ""} =
               Tools.summarise(%Cell.Tool{
                 name: "Bash",
                 input: %{"cmd" => "cargo test"},
                 state: :completed
               })
    end

    test "an mcp call names its server and its tool" do
      assert %{verb: "MCP", subject: "linear.create_issue"} =
               Tools.summarise(%Cell.Tool{name: "mcp__linear__create_issue"})

      assert %{verb: "MCP", subject: "linear.create_issue"} =
               Tools.summarise(%Cell.Tool{name: "linear.create_issue"})
    end

    test "a tool with no shape falls back to its own name and its own input" do
      assert %{verb: "teleport agent", subject: "somewhere"} =
               Tools.summarise(%Cell.Tool{
                 name: "teleport_agent",
                 input: %{"query" => "somewhere"}
               })
    end

    test "wire_markers_never_render_as_json_in_a_tool_cell" do
      assert %{subject: "$ git log --onel… (2000 bytes; full event via /details)"} =
               Tools.summarise(%Cell.Tool{
                 name: "Bash",
                 input: %{"cmd" => %{"_excerpt" => "git log --onel", "_bytes" => 2_000}}
               })
    end

    test "an_opaque_or_binary_leaf_reads_as_a_short_label" do
      assert Tools.value_text(%{"_opaque" => "#PID<0.1.0>"}) == "[not encodable: #PID<0.1.0>]"
      assert Tools.value_text(%{"_b64" => "AAAA"}) == "[binary value; full event via /details]"
    end

    test "a value prefers the text or content field before falling back to json" do
      assert Tools.value_text(%{"text" => "the words"}) == "the words"
      assert Tools.value_text(%{"content" => "the words"}) == "the words"
      assert Tools.value_text([%{"text" => "one"}, %{"text" => "two"}]) == "one\ntwo"
      assert Tools.value_text(%{"other" => 1}) == ~s({"other":1})
      assert Tools.value_text(nil) == ""
    end

    test "a_bounded_result_counts_itself_as_at_least_rather_than_exactly" do
      giant = String.duplicate("a line of output\n", 4_000)

      assert %{outcome: outcome} =
               Tools.summarise(%Cell.Tool{
                 name: "Read",
                 input: %{"path" => "big.txt"},
                 output: giant
               })

      assert String.ends_with?(outcome, "+ lines")
    end
  end

  describe "command output" do
    test "streamed command output accumulates into one cell" do
      cells =
        project([
          event(:command_output_delta, %{"text" => "one\n"}, sequence: 1),
          event(:command_output_delta, %{"text" => "two\n"}, sequence: 2)
        ])

      assert [%Cell.CommandOutput{text: "one\ntwo\n"}] = cells
    end

    test "caps_accumulated_command_streams" do
      deltas =
        for index <- 1..200 do
          event(:command_output_delta, %{"text" => String.duplicate("y", 1024)}, sequence: index)
        end

      assert [%Cell.CommandOutput{text: text}] = project(deltas)
      assert byte_size(text) <= 64 * 1024
      assert String.ends_with?(text, "full updates are available in event details")
    end
  end

  describe "the projection contract" do
    test "projecting the same entries twice yields the same cells" do
      events = [
        event(:input_accepted, %{"kind" => "message", "text" => "go"}, sequence: 1),
        event(:tool_call, %{"call_id" => "c1", "name" => "bash"}, sequence: 2),
        event(:tool_result, %{"call_id" => "c1", "output" => "ok"}, sequence: 3),
        event(:file_change, %{"diff" => @diff}, sequence: 4),
        event(:turn_completed, %{}, sequence: 5)
      ]

      assert project(events) == project(events)
    end

    test "an empty ledger projects no cells at all" do
      assert Transcript.project([]) == []
    end

    test "every presentation the port can mint has a projection arm" do
      # The companion to `every_normalized_kind_has_a_presentation_and_none_is_dropped`:
      # that one proves `from_event/1` names every kind, this one proves `project/1`
      # draws every name. Together they close the loop a catch-all would have hidden.
      payload = %{
        "text" => "words",
        "kind" => "acp_update",
        "call_id" => "c1",
        "decision" => "approve"
      }

      runtime_native = [
        {:provider_event, %{"kind" => "operator_shell", "command_digest" => "d"}},
        {:provider_event, %{"kind" => "compaction", "trigger" => "manual"}},
        {:provider_event, %{"kind" => "subagent", "phase" => "spawned", "task_id" => "t"}},
        {:delegation, %{"task_id" => "t", "status" => "started"}},
        {:a_kind_no_build_knows, %{"reason" => "novel"}}
      ]

      cases =
        Enum.map(Presentation.canonical_types(), &{&1, payload}) ++
          runtime_native ++
          [
            {:output_text_delta, %{"text" => ""}},
            {:thinking_delta, %{}},
            {:command_output_delta, %{}}
          ]

      for {type, payload} <- cases do
        events = [event(type, payload, sequence: 1, request_id: "r1")]

        assert is_list(project(events)),
               "#{type} has a presentation with no projection arm"
      end
    end

    test "a hidden presentation draws nothing but never removes what came before" do
      cells =
        project([
          event(:output_text_final, %{"text" => "kept"}, sequence: 1),
          event(:thinking_delta, %{}, sequence: 2),
          event(:command_output_delta, %{"text" => ""}, sequence: 3)
        ])

      assert [%Cell.Message{text: "kept"}] = cells
    end
  end
end
