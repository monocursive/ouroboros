defmodule Ouroboros.Web.PresentationTest do
  @moduledoc """
  Unit cover for the Elixir port of `PresentationEvent::from_event`.

  Test names mirror `tui/src/model/transcript.rs`'s own where one exists, so the golden
  corpus can be wired against the same behaviours by name rather than by reading both
  suites (W1 → W2, `docs/WEB.md` §6).
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Web.Presentation

  alias Ouroboros.Web.Presentation.{
    AgentText,
    ApprovalRequested,
    ApprovalResolved,
    CommandOutput,
    Compaction,
    DelegationEvent,
    Diff,
    Failure,
    FileChange,
    FileUpdate,
    Hidden,
    ImageArtifact,
    Interrupted,
    Lifecycle,
    PlanStep,
    PlanUpdate,
    ProviderNote,
    QueueChanged,
    RunStart,
    ShellEvent,
    SubagentEvent,
    Thinking,
    ToolCall,
    ToolResult,
    TurnEnded,
    TurnStarted,
    UnrecordedInput,
    UsageReport,
    UserMessage,
    UserSteer
  }

  @at "2026-08-14T00:00:00Z"

  defp event(type, payload, fields \\ []) do
    %Event{
      id: "evt-1",
      session_id: "sess-1",
      sequence: Keyword.get(fields, :sequence, 1),
      type: type,
      timestamp: Keyword.get(fields, :timestamp, @at),
      payload: payload,
      turn_id: Keyword.get(fields, :turn_id, "turn-1"),
      request_id: Keyword.get(fields, :request_id)
    }
  end

  defp fixture_at, do: Presentation.epoch_millis(@at)

  describe "the normalized tool contract" do
    test "parses_the_normalized_tool_contract_without_provider_fields" do
      call =
        event(:tool_call, %{
          "call_id" => "call-7",
          "name" => "read",
          "input" => %{"path" => "lib/ouroboros.ex"}
        })

      result =
        event(:tool_result, %{
          "call_id" => "call-7",
          "output" => %{"text" => "defmodule Ouroboros"},
          "is_error" => false
        })

      assert %ToolCall{
               call_id: "call-7",
               name: "read",
               kind: nil,
               input: %{"path" => "lib/ouroboros.ex"},
               at: at
             } = Presentation.from_event(call)

      assert at == fixture_at()

      assert %ToolResult{
               call_id: "call-7",
               name: nil,
               output: %{"text" => "defmodule Ouroboros"},
               is_error: false,
               artifacts: []
             } = Presentation.from_event(result)
    end

    test "tolerates_acp_camel_case_tool_updates_without_leaking_protocol_into_the_renderer" do
      call =
        event(:tool_call, %{
          "toolCallId" => "acp-1",
          "title" => "Reading lib/app.ex",
          "kind" => "read",
          "rawInput" => %{"path" => "lib/app.ex"}
        })

      assert %ToolCall{call_id: "acp-1", name: "Reading lib/app.ex", kind: "read"} =
               Presentation.from_event(call)
    end

    test "a tool call with no recognisable name is still a call" do
      assert %ToolCall{name: "tool", input: %{}, call_id: nil} =
               Presentation.from_event(event(:tool_call, %{}))
    end

    test "an is_error absent but a failed status still reads as an error" do
      assert %ToolResult{is_error: true} =
               Presentation.from_event(event(:tool_result, %{"status" => "failed"}))

      assert %ToolResult{is_error: false} =
               Presentation.from_event(event(:tool_result, %{"status" => "ok"}))
    end

    test "a tool result output that is JSON null stays null rather than becoming absent" do
      assert %ToolResult{output: nil} =
               Presentation.from_event(event(:tool_result, %{"output" => nil}))
    end
  end

  describe "desktop image artifacts" do
    test "decodes_desktop_image_artifacts_and_tolerates_a_newer_gateways_extra_fields" do
      sha = String.duplicate("ab", 32)

      result =
        event(:tool_result, %{
          "call_id" => "call-9",
          "output" => "captured",
          "artifacts" => [
            %{
              "kind" => "image",
              "sha256" => String.upcase(sha),
              "media_type" => "image/png",
              "bytes" => 4096,
              "width" => 800,
              "height" => 600,
              "a_field_from_a_newer_gateway" => true
            },
            %{"kind" => "sound", "sha256" => sha},
            %{"sha256" => "too-short"},
            %{"media_type" => "image/png"}
          ]
        })

      assert %ToolResult{artifacts: [artifact]} = Presentation.from_event(result)

      assert %ImageArtifact{
               sha256: ^sha,
               media_type: "image/png",
               size: 4096,
               width: 800,
               height: 600
             } = artifact
    end

    test "an artifact naming no kind is taken as an image" do
      sha = String.duplicate("0", 64)

      assert %ToolResult{artifacts: [%ImageArtifact{sha256: ^sha}]} =
               Presentation.from_event(
                 event(:tool_result, %{"artifacts" => [%{"sha256" => sha}]})
               )
    end
  end

  describe "file changes and diffs" do
    test "parses_file_lists_and_diff_metadata_without_treating_them_as_authority" do
      update =
        event(:file_change, %{
          "status" => "completed",
          "changes" => [
            %{"path" => "lib/a.ex", "kind" => "modify"},
            "lib/b.ex"
          ],
          "diff" => "--- a/lib/a.ex\n+++ b/lib/a.ex\n@@ -1 +1 @@\n-old\n+new\n",
          "additions" => 999
        })

      assert %FileUpdate{status: "completed", changes: changes, diff: diff} =
               Presentation.from_event(update)

      assert [
               %FileChange{path: "lib/a.ex", kind: "modify"},
               %FileChange{path: "lib/b.ex", kind: nil}
             ] = changes

      # The provider's own `additions: 999` is never read.
      assert %Diff{path: "lib/a.ex", additions: 1, deletions: 1, truncated: false} = diff
    end

    test "a file change naming neither a path nor a kind is dropped" do
      assert %FileUpdate{changes: [], diff: nil} =
               Presentation.from_event(event(:file_change, %{"unrelated" => 1}))
    end

    test "caps_large_file_lists_in_the_presentation_projection" do
      changes = for index <- 1..300, do: %{"path" => "lib/file_#{index}.ex"}

      assert %FileUpdate{changes: projected} =
               Presentation.from_event(event(:file_change, %{"changes" => changes}))

      assert length(projected) == 257
      assert List.last(projected).path == "… additional files in event details"
    end

    test "bounds_a_multi_megabyte_diff_before_copying_or_counting_it" do
      body = String.duplicate("+a line that is added\n", 200_000)
      diff = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n" <> body

      assert %FileUpdate{diff: %Diff{text: text, truncated: true}} =
               Presentation.from_event(event(:file_change, %{"diff" => diff}))

      assert byte_size(text) <= 128 * 1024
      assert String.ends_with?(text, "full diff is available in event details")
    end

    test "a diff counts additions and deletions and never the +++ or --- headers" do
      diff =
        Presentation.parse_diff(
          "diff --git a/x.ex b/x.ex\n--- a/x.ex\n+++ b/x.ex\n@@ -1,2 +1,3 @@\n keep\n-gone\n+one\n+two\n"
        )

      assert %Diff{path: "x.ex", additions: 2, deletions: 1} = diff
    end
  end

  describe "accepted input" do
    test "an_accepted_input_without_text_is_named_rather_than_dropped" do
      assert %UnrecordedInput{} =
               Presentation.from_event(event(:input_accepted, %{"kind" => "message"}))

      assert %UnrecordedInput{} =
               Presentation.from_event(event(:input_accepted, %{"text" => "   "}))
    end

    test "a_steer_carries_its_text_once_the_runtime_sends_one" do
      assert %UserSteer{text: "stop and read"} =
               Presentation.from_event(
                 event(:input_accepted, %{"kind" => "steer", "text" => "stop and read"})
               )

      assert %UserSteer{text: nil} =
               Presentation.from_event(event(:input_accepted, %{"kind" => "steer"}))
    end

    test "an accepted message with words is the operator's turn" do
      assert %UserMessage{text: "hello"} =
               Presentation.from_event(
                 event(:input_accepted, %{"kind" => "message", "text" => "hello"})
               )
    end
  end

  describe "every normalized kind" do
    test "every_normalized_kind_has_a_presentation_and_none_is_dropped" do
      expected = %{
        run_started: RunStart,
        run_completed: Lifecycle,
        run_failed: Failure,
        run_cancelled: Interrupted,
        session_started: Lifecycle,
        session_ready: Lifecycle,
        session_idle: Lifecycle,
        session_closed: Lifecycle,
        session_failed: Failure,
        session_cancelled: Interrupted,
        input_accepted: UserMessage,
        turn_queued: Lifecycle,
        turn_started: TurnStarted,
        output_text_delta: AgentText,
        output_text_final: AgentText,
        thinking_delta: Thinking,
        command_output_delta: CommandOutput,
        tool_call: ToolCall,
        tool_result: ToolResult,
        file_change: FileUpdate,
        plan_updated: PlanUpdate,
        usage: UsageReport,
        turn_completed: TurnEnded,
        turn_failed: TurnEnded,
        turn_interrupted: TurnEnded,
        approval_requested: ApprovalRequested,
        approval_resolved: ApprovalResolved,
        queue_changed: QueueChanged,
        provider_event: ProviderNote
      }

      # The list this asserts against is the runtime's own, so a type added upstream
      # without a presentation fails here rather than disappearing from a transcript.
      assert MapSet.new(Map.keys(expected)) == MapSet.new(Presentation.canonical_types())
      assert map_size(expected) == 29

      for {type, module} <- expected do
        # A payload carrying enough for each arm to be its named shape rather than Hidden.
        projected =
          Presentation.from_event(event(type, %{"text" => "words", "kind" => "acp_update"}))

        assert projected.__struct__ == module,
               "#{type} projected to #{inspect(projected.__struct__)}, expected #{inspect(module)}"
      end
    end

    test "an_empty_payload_hides_with_a_stated_reason_rather_than_by_default" do
      assert %Hidden{reason: :empty_text} =
               Presentation.from_event(event(:output_text_delta, %{"text" => ""}))

      assert %Hidden{reason: :empty_text} =
               Presentation.from_event(event(:output_text_final, %{}))

      assert %Hidden{reason: :empty_thinking} =
               Presentation.from_event(event(:thinking_delta, %{}))

      assert %Hidden{reason: :empty_command_output} =
               Presentation.from_event(event(:command_output_delta, %{}))

      assert Hidden.reason(:empty_text) == "an output event carrying no text"
      assert Hidden.reason(:empty_thinking) == "a reasoning delta carrying no text"
      assert Hidden.reason(:empty_command_output) == "a command-output delta carrying no bytes"
    end

    test "a final text event is marked final and a delta is not" do
      assert %AgentText{final_text: true, turn_id: "turn-1", text: "done"} =
               Presentation.from_event(event(:output_text_final, %{"text" => "done"}))

      assert %AgentText{final_text: false} =
               Presentation.from_event(event(:output_text_delta, %{"text" => "part"}))
    end

    test "thinking reads whichever of the three keys the provider used" do
      for key <- ["text", "thinking", "reasoning"] do
        assert %Thinking{text: "pondering"} =
                 Presentation.from_event(event(:thinking_delta, %{key => "pondering"}))
      end
    end

    test "a lifecycle marker with only bookkeeping behind it reads as a marker" do
      assert %Lifecycle{marker: :session_ready, detail: "jsonl · stable"} =
               Presentation.from_event(
                 event(:session_ready, %{"transport" => "jsonl", "maturity" => "stable"})
               )

      assert %Lifecycle{marker: :session_started, detail: ""} =
               Presentation.from_event(event(:session_started, %{}))
    end

    test "a queue depth is read from whichever key names it, or from a list" do
      assert %QueueChanged{queued: 3} =
               Presentation.from_event(event(:queue_changed, %{"queued_turns" => 3}))

      assert %QueueChanged{queued: 2} =
               Presentation.from_event(event(:queue_changed, %{"queued" => ["a", "b"]}))

      assert %QueueChanged{queued: 0} = Presentation.from_event(event(:queue_changed, %{}))
    end
  end

  describe "unknown kinds" do
    test "unknown_payload_shapes_are_named_rather_than_dropped" do
      assert %ProviderNote{kind: "some_new_runtime_fact", detail: "the reason"} =
               Presentation.from_event(event(:some_new_runtime_fact, %{"reason" => "the reason"}))
    end

    test "a_provider_event_names_its_own_kind" do
      assert %ProviderNote{kind: "acp_update · agent_thought_chunk"} =
               Presentation.from_event(
                 event(:provider_event, %{
                   "kind" => "acp_update",
                   "update" => %{"sessionUpdate" => "agent_thought_chunk"}
                 })
               )

      assert %ProviderNote{kind: ""} =
               Presentation.from_event(event(:provider_event, %{}))
    end

    test "a_provider_event_whose_kind_is_plan_exit_falls_through_to_the_generic_note" do
      # There are exactly three explicit arms in the sub-dispatch — `operator_shell`,
      # `compaction`, `subagent` (`tui/src/model/transcript.rs:533`, `:538`, `:546`). A
      # `plan_exit` provider event is not one of them and must read as the ordinary note;
      # the plan-exit *question* rides the approval channel, not this one.
      assert %ProviderNote{kind: "plan_exit", detail: "Plan ready"} =
               Presentation.from_event(
                 event(:provider_event, %{
                   "kind" => "plan_exit",
                   "message" => "Plan ready",
                   "plan" => true
                 })
               )
    end

    test "a runtime status event reads as a note naming its own type" do
      assert %ProviderNote{kind: "status"} =
               Presentation.from_event(event(:status, %{"kind" => "configured"}))
    end
  end

  describe "the three runtime-native provider_event arms" do
    test "an operator shell event is drawn in full rather than as a dim note" do
      assert %ShellEvent{
               effect_id: "eff-1",
               command_digest: "abc123",
               exit_status: 0,
               duration_ms: 1_500,
               timed_out: false,
               output_bytes: 42,
               output_excerpt: "hello",
               spilled: nil,
               error: nil
             } =
               Presentation.from_event(
                 event(:provider_event, %{
                   "kind" => "operator_shell",
                   "effect_id" => "eff-1",
                   "command_digest" => "abc123",
                   "exit_status" => 0,
                   "duration_ms" => 1_500,
                   "timed_out" => false,
                   "output_bytes" => 42,
                   "output_excerpt" => "hello"
                 })
               )
    end

    test "an excerpted shell output reads as its prefix rather than as JSON" do
      assert %ShellEvent{output_excerpt: excerpt} =
               Presentation.from_event(
                 event(:provider_event, %{
                   "kind" => "operator_shell",
                   "output_excerpt" => %{"_excerpt" => "first line", "_bytes" => 9_000}
                 })
               )

      assert excerpt == "first line… (9000 bytes; full event via /details)"
    end

    test "a compaction is drawn in full and describes only the numbers it carried" do
      report =
        Presentation.from_event(
          event(:provider_event, %{
            "kind" => "compaction",
            "trigger" => "automatic",
            "archived_messages" => 12,
            "before_tokens" => 100_000,
            "after_tokens" => 20_000,
            "archive_id" => "arch-1"
          })
        )

      assert %Compaction{trigger: "automatic", archived_messages: 12} = report

      assert Compaction.describe(report) ==
               "archived 12 messages · 100000 → 20000 tokens · archive arch-1"
    end

    test "a compaction that carried no numbers says only that the fold happened" do
      report = Presentation.from_event(event(:provider_event, %{"kind" => "compaction"}))
      assert Compaction.describe(report) == "the conversation was folded"
    end

    test "a subagent event decodes its phase and its counters" do
      assert %SubagentEvent{
               phase: :settled,
               task_id: "task-1",
               description: "run the tests",
               status: "completed",
               turns: 4,
               tool_calls: 11,
               files_changed: 2,
               files: ["lib/a.ex", "lib/b.ex"],
               remote: true,
               node: "worker@host",
               worktree: true
             } =
               Presentation.from_event(
                 event(:provider_event, %{
                   "kind" => "subagent",
                   "phase" => "settled",
                   "task_id" => "task-1",
                   "description" => "run the tests",
                   "status" => "completed",
                   "turns" => 4,
                   "tool_calls" => 11,
                   "files_changed" => 2,
                   "files" => ["lib/a.ex", "lib/b.ex"],
                   "remote" => true,
                   "node" => "worker@host",
                   "worktree" => %{"branch" => "sub/1", "retired" => "kept", "path" => "/w/sub"}
                 })
               )
    end

    test "a subagent phase this build does not model is kept verbatim" do
      assert %SubagentEvent{phase: {:other, "hibernating"}} =
               Presentation.from_event(
                 event(:provider_event, %{"kind" => "subagent", "phase" => "hibernating"})
               )

      assert %SubagentEvent{phase: {:other, ""}} =
               Presentation.from_event(event(:provider_event, %{"kind" => "subagent"}))
    end

    test "a delegation is its own runtime-native type in the same sequence space" do
      assert %DelegationEvent{
               delegation_id: "del-1",
               task_id: "task-2",
               task_node: "coder@host",
               status: "completed",
               result_digest: "sha-9"
             } =
               Presentation.from_event(
                 event(:delegation, %{
                   "delegation_id" => "del-1",
                   "task_id" => "task-2",
                   "task_node" => "coder@host",
                   "status" => "completed",
                   "result_digest" => "sha-9"
                 })
               )
    end
  end

  describe "approvals" do
    test "approval_events_keep_the_correlation_and_resolution" do
      requested =
        event(
          :approval_requested,
          %{"tool_call" => %{"name" => "bash", "command" => "rm -rf /"}},
          request_id: "req-1"
        )

      resolved =
        event(
          :approval_resolved,
          %{"decision" => "deny", "scope" => "once", "reason" => "too broad"},
          request_id: "req-1"
        )

      assert %ApprovalRequested{request_id: "req-1", detail: detail} =
               Presentation.from_event(requested)

      assert detail == ~s({"command":"rm -rf /","name":"bash"})

      assert %ApprovalResolved{
               request_id: "req-1",
               decision: "deny",
               detail: "deny · once · too broad"
             } = Presentation.from_event(resolved)
    end

    test "a resolution carrying nothing renders the payload rather than an empty line" do
      assert %ApprovalResolved{detail: "{}"} =
               Presentation.from_event(event(:approval_resolved, %{}, request_id: "req-2"))
    end
  end

  describe "plans" do
    test "both_plan_dialects_project_to_the_same_steps" do
      codex =
        Presentation.from_event(
          event(:plan_updated, %{
            "explanation" => "the shape of it",
            "plan" => [
              %{"step" => "read the module", "status" => "completed"},
              %{"step" => "write the port", "status" => "in_progress"}
            ]
          })
        )

      acp =
        Presentation.from_event(
          event(:plan_updated, %{
            "explanation" => "the shape of it",
            "entries" => [
              %{"content" => "read the module", "status" => "done", "priority" => "high"},
              %{"content" => "write the port", "status" => "running", "priority" => "high"}
            ]
          })
        )

      assert %PlanUpdate{explanation: "the shape of it", step_count: 2, steps: codex_steps} =
               codex

      assert %PlanUpdate{step_count: 2, steps: acp_steps} = acp

      assert Enum.map(codex_steps, &{&1.text, &1.status}) ==
               Enum.map(acp_steps, &{&1.text, &1.status})

      assert [
               %PlanStep{text: "read the module", status: :done},
               %PlanStep{text: "write the port", status: :in_progress}
             ] = codex_steps
    end

    test "an_unknown_plan_status_is_kept_verbatim_rather_than_guessed" do
      assert %PlanUpdate{steps: [%PlanStep{status: {:other, "blocked"}}]} =
               Presentation.from_event(
                 event(:plan_updated, %{"plan" => [%{"step" => "wait", "status" => "blocked"}]})
               )
    end

    test "a_plan_longer_than_the_projection_ceiling_says_how_many_it_left_out" do
      steps = for index <- 1..200, do: %{"step" => "step #{index}"}

      assert %PlanUpdate{step_count: 200, steps: projected} =
               Presentation.from_event(event(:plan_updated, %{"plan" => steps}))

      assert length(projected) == 64
    end

    test "a bare string plan entry is a pending step" do
      assert %PlanUpdate{steps: [%PlanStep{text: "do the thing", status: :pending}]} =
               Presentation.from_event(event(:plan_updated, %{"plan" => ["do the thing"]}))
    end
  end

  describe "usage and run starts" do
    test "usage_reports_only_the_numbers_the_provider_sent" do
      usage =
        Presentation.from_event(event(:usage, %{"input_tokens" => 100, "cost_usd" => 0.25}))

      assert %UsageReport{
               input_tokens: 100,
               output_tokens: nil,
               cached_tokens: nil,
               total_tokens: nil,
               cost_usd: 0.25
             } = usage

      refute UsageReport.empty?(usage)
      assert UsageReport.empty?(Presentation.from_event(event(:usage, %{})))
    end

    test "run_started_carries_the_model_and_tool_count_the_header_states" do
      assert %RunStart{
               model: "claude-opus-5",
               cwd: "/w",
               tools: ["Read", "Bash"],
               tool_count: 2
             } =
               Presentation.from_event(
                 event(:run_started, %{
                   "model" => "claude-opus-5",
                   "cwd" => "/w",
                   "tools" => ["Read", %{"name" => "Bash"}]
                 })
               )
    end

    test "a run declaring more tools than the header holds still counts them all" do
      tools = for index <- 1..300, do: "tool_#{index}"

      assert %RunStart{tools: kept, tool_count: 300} =
               Presentation.from_event(event(:run_started, %{"tools" => tools}))

      assert length(kept) == 128
    end
  end

  describe "turn boundaries and timestamps" do
    test "a_turn_boundary_carries_the_timestamp_the_divider_measures_elapsed_time_from" do
      assert %TurnStarted{turn_id: "turn-1", at: at} =
               Presentation.from_event(event(:turn_started, %{}))

      assert at == fixture_at()

      assert %TurnEnded{outcome: :completed, detail: ""} =
               Presentation.from_event(event(:turn_completed, %{}))

      assert %TurnEnded{outcome: :failed, detail: "boom"} =
               Presentation.from_event(event(:turn_failed, %{"error" => "boom"}))

      assert %TurnEnded{outcome: :interrupted} =
               Presentation.from_event(event(:turn_interrupted, %{}))
    end

    test "iso_timestamps_parse_and_an_unreadable_one_yields_no_elapsed_time" do
      assert Presentation.epoch_millis("1970-01-01T00:00:00Z") == 0
      assert Presentation.epoch_millis("2026-08-14T00:00:00Z") == 1_786_665_600_000
      assert Presentation.epoch_millis("2026-08-14t00:00:00z") == 1_786_665_600_000
      assert Presentation.epoch_millis("2026-08-14 00:00:00") == 1_786_665_600_000
      assert Presentation.epoch_millis("2026-08-14T00:00:00.250Z") == 1_786_665_600_250
      assert Presentation.epoch_millis("2026-08-14T00:00:00.25Z") == 1_786_665_600_250

      # An offset moves the instant, and is split off before the clock is read.
      assert Presentation.epoch_millis("2026-08-14T05:30:00+05:30") == 1_786_665_600_000
      assert Presentation.epoch_millis("2026-08-13T16:00:00-0800") == 1_786_665_600_000

      for unreadable <- ["", "nope", "2026-08-14", "2026-13-01T00:00:00Z", "2026-08-14T99:00:00Z"] do
        assert Presentation.epoch_millis(unreadable) == nil, unreadable
      end

      assert %ToolCall{at: nil} =
               Presentation.from_event(event(:tool_call, %{}, timestamp: "not a time"))
    end
  end

  describe "wire markers" do
    test "wire_markers_render_as_labels_and_an_excerpt_keeps_its_prefix" do
      assert Presentation.wire_marker(%{"_opaque" => "#PID<0.1.0>"}) ==
               "[not encodable: #PID<0.1.0>]"

      assert Presentation.wire_marker(%{"_b64" => "AAAA"}) ==
               "[binary value; full event via /details]"

      assert Presentation.wire_marker(%{"_truncated" => true}) ==
               "[truncated; full event via /details]"

      assert Presentation.wire_marker(%{"_excerpt" => "the start", "_bytes" => 900}) ==
               "the start… (900 bytes; full event via /details)"

      assert Presentation.wire_marker(%{"_excerpt" => "the start"}) ==
               "the start… (full value; full event via /details)"

      # A `_truncated` beside other fields is a real payload, not a marker.
      assert Presentation.wire_marker(%{"_truncated" => true, "text" => "hi"}) == nil
      assert Presentation.wire_marker("plain") == nil
    end

    test "an_excerpted_text_leaf_reads_as_its_prefix_and_an_excerpted_diff_is_marked" do
      assert %AgentText{text: "the words so far… (5000 bytes; full event via /details)"} =
               Presentation.from_event(
                 event(:output_text_delta, %{
                   "text" => %{"_excerpt" => "the words so far", "_bytes" => 5_000}
                 })
               )

      assert %FileUpdate{diff: %Diff{truncated: true, text: text}} =
               Presentation.from_event(
                 event(:file_change, %{"diff" => %{"_excerpt" => "+one line", "_bytes" => 900}})
               )

      assert String.starts_with?(text, "+one line…")
    end
  end

  describe "the display ceilings" do
    test "bounds_multi_megabyte_tool_values_without_touching_the_source_event" do
      giant = String.duplicate("x", 2_000_000)
      source = event(:tool_call, %{"input" => %{"text" => giant}})

      assert %ToolCall{input: %{"text" => bounded}} = Presentation.from_event(source)

      assert byte_size(bounded) <= 64 * 1024
      assert String.ends_with?(bounded, "full value is available in event details")
      # The source event is untouched.
      assert byte_size(source.payload["input"]["text"]) == 2_000_000
    end

    test "a value deeper than the depth ceiling is marked truncated rather than walked" do
      deep = Enum.reduce(1..40, "leaf", fn _step, acc -> %{"nested" => acc} end)

      assert %ToolCall{input: input} =
               Presentation.from_event(event(:tool_call, %{"input" => deep}))

      assert truncation_depth(input) < 40
    end

    test "a value with more nodes than the ceiling stops and says so" do
      wide = for index <- 1..5_000, into: %{}, do: {"k#{index}", index}

      assert %ToolCall{input: input} =
               Presentation.from_event(event(:tool_call, %{"input" => wide}))

      assert map_size(input) < 5_000
      assert Map.get(input, "_truncated") == true
    end

    test "a text ceiling cuts on a character boundary and never mid-codepoint" do
      # 3-byte codepoints, so a naive byte cut would land inside one.
      text = String.duplicate("あ", 40_000)

      assert %AgentText{text: bounded} =
               Presentation.from_event(event(:output_text_delta, %{"text" => text}))

      assert byte_size(bounded) <= 64 * 1024
      assert String.valid?(bounded)
    end

    defp truncation_depth(%{"_truncated" => true}), do: 0
    defp truncation_depth(%{"nested" => nested}), do: 1 + truncation_depth(nested)
    defp truncation_depth(_leaf), do: 1_000
  end

  describe "compact rendering" do
    test "compact sorts object keys so two runs of one fixture say the same thing" do
      assert Presentation.compact(%{"b" => 1, "a" => [1, 2], "c" => %{"z" => true, "y" => nil}}) ==
               ~s({"a":[1,2],"b":1,"c":{"y":null,"z":true}})
    end

    test "compact renders a string as itself and a marker as its short label" do
      assert Presentation.compact("just words") == "just words"
      assert Presentation.compact(nil) == "null"
      assert Presentation.compact(%{"_opaque" => "#Ref<0.1>"}) == "#Ref<0.1>"
      assert Presentation.compact(%{"_truncated" => true}) == "<truncated>"
      assert Presentation.compact(%{"_b64" => "AAAA"}) == "<4 base64 bytes>"
    end

    test "compact escapes the control characters a terminal would otherwise interpret" do
      control = "a\nb\tc\"d\\e" <> <<0x01>>

      assert Presentation.compact(%{"k" => control}) ==
               ~S({"k":"a\nb\tc\"d\\e\u0001"})
    end
  end

  describe "payload key types" do
    test "a coding-plane internal payload's atom keys are read like the wire reads them" do
      # `Coding.Event.internal/4` skips the stringification every harness event gets, and
      # all eight of its call sites build atom-keyed maps
      # (`lib/ouroboros/coding/task.ex:368-374`). The gateway's `Wire` flattens those on
      # the way out, so an in-process reader has to do the same or the browser and the TUI
      # would word the same event differently.
      assert %ProviderNote{kind: "worktree_retained", detail: "still dirty"} =
               Presentation.from_event(
                 event(:worktree_retained, %{
                   path: "/w/task",
                   reason: "still dirty",
                   message: "commit or discard"
                 })
               )
    end

    test "atom values flatten the way the wire flattens them, and nil and booleans do not" do
      assert Presentation.wire_shape(%{status: :completed, done: true, missing: nil}) ==
               %{"status" => "completed", "done" => true, "missing" => nil}

      assert Presentation.wire_shape(%{mod: Ouroboros.Web.Presentation}) ==
               %{"mod" => "Ouroboros.Web.Presentation"}

      assert Presentation.wire_shape([%{a: 1}, :two]) == [%{"a" => 1}, "two"]
    end
  end
end
