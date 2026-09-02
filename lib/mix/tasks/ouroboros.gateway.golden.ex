defmodule Mix.Tasks.Ouroboros.Gateway.Golden do
  @shortdoc "Regenerates the gateway's cross-language golden fixtures"

  @moduledoc """
  Writes `test/support/gateway_golden/*.json` — the frames the `ouro` client decodes.

      mix ouroboros.gateway.golden

  ## Why these files exist

  The protocol has two implementations that are compiled by different toolchains and
  cannot call each other's tests. These files are the seam: this task writes them from the
  same `Ouroboros.Gateway.Conn` envelope functions and the same `Ouroboros.Gateway.Wire`
  encoder the socket is written from, and the Rust client decodes the same bytes in its
  own suite. A change on either side that the other has not accepted shows up as a failing
  test rather than as a field that silently stopped arriving.

  `test/ouroboros/gateway/golden_test.exs` re-derives every frame here through the live
  code and compares, so a fixture cannot drift from the build that produced it. Running
  this task after changing the gateway is how that test goes green again — and the diff it
  produces is the review artifact for a protocol change.

  ## Static by construction

  Nothing here reads the clock, the node name, a random id, or a live plane. Every
  timestamp, id, and sequence is a literal, so regenerating on another machine on another
  day writes the same bytes. The one thing taken from the running build is
  `Ouroboros.Gateway.Methods.names/0` in the `hello` fixture — the method list *is* the
  contract, and a fixture that hid a change to it would defeat the purpose.

  The pid in `runtime_status_result.json` is `:erlang.list_to_pid/1` of a literal, so it
  walks the real `Wire` pid path and still inspects identically everywhere.

  `interactive_event_excerpt_notification.json` states its byte caps rather than taking the
  128 KiB default, for the same reason: a fixture pinning the default would be 128 KiB of
  one repeated character, and the thing a second implementation has to agree about is the
  shape of the marker, not the size of the excerpt. The arithmetic behind the caps is
  asserted in `Ouroboros.Gateway.WireTest`, where numbers belong.

  ## Byte stability

  Objects are written with their keys sorted and two-space indentation by the encoder in
  this module rather than by `JSON.encode!/1`, so a regeneration that changed nothing
  produces a zero-line diff. The bytes are pretty-printed for review; the protocol itself
  is one compact line per frame, and the test asserts both forms decode to the same term.
  """

  use Mix.Task

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.CodeIntel.Diagnostics
  alias Ouroboros.Coding.Event, as: CodingEvent
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.Event, as: InteractiveEvent

  @directory "test/support/gateway_golden"

  @node "ouroboros@golden"
  @session_id "session-0000000000000000000001"
  @task_id "task-0000000000000000000000002"
  @timestamp "2026-01-01T00:00:00.000000Z"

  # Ninety seconds after `@timestamp`, and the only other instant in this file. A turn's
  # end divider states elapsed time from two instants the ledger holds rather than from a
  # clock, so pinning that sentence needs a second timestamp and exactly one.
  @turn_end_timestamp "2026-01-01T00:01:30.000000Z"

  @turn_id "turn-0000000000000000000001"
  @harness_session_id "harness-0000000000000000001"
  @provider_session_id "provider-0000000000000001"

  @diagnostic %{
    range: %{start: %{line: 11, character: 4}, end: %{line: 11, character: 12}},
    severity: :error,
    code: "E0425",
    source: "fake",
    message: "cannot find value `widget` in this scope",
    tags: []
  }

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.config")
    File.mkdir_p!(@directory)

    written =
      Enum.map(fixtures(), fn {name, frame} ->
        path = path(name)
        File.write!(path, encode(frame))
        path
      end)

    stale = Path.wildcard(Path.join(@directory, "*.json")) -- written

    Enum.each(stale, fn path ->
      File.rm!(path)
      Mix.shell().info("removed #{path}")
    end)

    Enum.each(written, &Mix.shell().info("wrote #{&1}"))
  end

  @doc "Where one fixture lives, by name."
  @spec path(String.t()) :: Path.t()
  def path(name), do: Path.join(@directory, name <> ".json")

  @doc "The directory holding every fixture."
  @spec directory() :: Path.t()
  def directory, do: @directory

  @doc """
  Every fixture, as `{name, frame}` where `frame` came from the live envelope functions.

  Public because the test that proves these files match the build calls it. Building the
  frames anywhere other than through `Ouroboros.Gateway.Conn` would make the comparison
  circular — it would prove the fixtures match themselves.
  """
  @spec fixtures() :: [{String.t(), map()}]
  def fixtures do
    protocol_fixtures() ++ transcript_fixtures()
  end

  defp protocol_fixtures do
    [
      {"hello_result", hello_result()},
      {"runtime_status_result", runtime_status_result()},
      {"interactive_event_notification", interactive_event_notification()},
      {"coding_event_notification", coding_event_notification()},
      {"interactive_event_excerpt_notification", interactive_event_excerpt_notification()},
      {"interactive_event_detail_result", interactive_event_detail_result()},
      {"coding_event_detail_result", coding_event_detail_result()},
      {"code_intel_diagnostics_result", code_intel_diagnostics_result()},
      {"mcp_list_result", mcp_list_result()},
      {"wasm_status_result", wasm_status_result()},
      {"wasm_list_result", wasm_list_result()},
      {"agents_message_result", agents_message_result()},
      {"wasm_upload_result", wasm_upload_result()},
      {"wasm_sign_result", wasm_sign_result()},
      {"wasm_deploy_result", wasm_deploy_result()},
      {"wasm_rollback_result", wasm_rollback_result()},
      {"agents_message_truncated_result", agents_message_truncated_result()},
      {"workspace_browse_result", workspace_browse_result()},
      {"ledger_list_result", ledger_list_result()},
      {"ledger_export_result", ledger_export_result()},
      {"interactive_journal_result", interactive_journal_result()},
      {"interactive_replay_verify_result", interactive_replay_verify_result()},
      {"stream_lagged_notification", stream_lagged_notification()},
      {"stream_ended_notification", stream_ended_notification()},
      {"error_unauthenticated", error_unauthenticated()},
      {"error_protocol_mismatch", error_protocol_mismatch()},
      {"error_scope_denied", error_scope_denied()},
      {"error_upstream_timeout_unknown", error_upstream_timeout_unknown()},
      {"error_cursor_pruned", error_cursor_pruned()},
      {"error_not_found", error_not_found()},
      {"error_invalid_request", error_invalid_request()}
    ]
  end

  # ---------------------------------------------------------------------------
  # The transcript corpus
  # ---------------------------------------------------------------------------

  @doc """
  One fixture per event shape a client turns into words, with the gloss that places it.

  The twenty frames above pin the *envelope*: the framing, the refusals, the excerpt
  marker, the lag and end notifications. They carry almost no payload, which was fine
  while one client rendered transcripts and its own suite was the only reader. It stops
  being fine the moment a second implementation has to produce the same sentences from
  the same bytes, because there is nothing in this directory for it to be held to.

  So this list is the payload half of the same seam: every `Jido.Harness.Event` type,
  every `provider_event.kind` this runtime writes itself, every `approval_requested`
  variant, and the two runtime-native types — one frame each, built from the field
  vocabulary the emitting module actually uses. Field names are copied from the emitters
  (`Ouroboros.Provider.Native.Loop`, `.Session`, `.Tools.AskUser`, `.Subagent`,
  `Ouroboros.Provider.Session.Dialect.ACP`, `Ouroboros.Interactive.Task` and its `Shell`
  and `Approvals` submodules, and `Jido.Harness`'s own session and run workers); nothing
  here is a shape invented for a test.

  The same static discipline as everything else in this file: literal ids, two literal
  timestamps, literal sequences. The `run_*` kinds ride the coding envelope because that
  is the plane that emits them, and everything else rides the interactive one.

  Each entry is `{name, gloss, plane, sequence, type, payload, fields}`. The gloss is what
  `mix ouroboros.protocol.docs` prints beside the file, so "what this fixture pins" is
  written once, here, next to the payload it describes.
  """
  @spec transcript_corpus() :: [
          {String.t(), String.t(), :interactive | :coding, pos_integer(), atom(), map(),
           keyword()}
        ]
  def transcript_corpus do
    [
      # -- what a person typed ------------------------------------------------
      {"event_input_accepted", "a prompt the runtime accepted, with the words it recorded",
       :interactive, 100, :input_accepted,
       %{"kind" => "message", "text" => "Check the workspace is clean, then run the suite."}, []},
      {"event_input_accepted_steer",
       "a steer, which the harness records as an acceptance and Ouroboros enriches with " <>
         "the prompt", :interactive, 101, :input_accepted,
       %{"kind" => "steer", "text" => "actually, skip the slow tests"},
       request_id: "req-steer-00000000000000001"},
      {"event_input_accepted_unrecorded",
       "an acceptance whose words the ledger does not hold — the turn a client must still " <>
         "draw", :interactive, 102, :input_accepted, %{"kind" => "message"}, []},

      # -- the agent's own stream ---------------------------------------------
      {"event_output_text_delta", "one streaming chunk of agent prose", :interactive, 103,
       :output_text_delta, %{"text" => "Running the suite now."}, []},
      {"event_output_text_final", "the settled agent message for a turn", :interactive, 104,
       :output_text_final,
       %{"text" => "The suite passed: 412 tests, 0 failures.\n\nNothing else to change."}, []},
      # The same turn's answer, half-arrived. Its text is a literal **prefix** of
      # `event_output_text_final`'s, which is what a real delta stream is and what the
      # other delta above deliberately is not: that one is a separate sentence, so the two
      # of them together cannot express the case where a settled final supersedes the
      # draft it was streamed from. This one can, and both renderers use the pair to pin
      # what happens when a provider note lands between the draft and its final.
      {"event_output_text_delta_partial",
       "a streaming chunk that is a prefix of this turn's settled text", :interactive, 105,
       :output_text_delta, %{"text" => "The suite passed: 412 "}, []},
      {"event_thinking_delta", "reasoning the provider chose to publish", :interactive, 105,
       :thinking_delta, %{"text" => "The failure is in the diff parser, not the transport."}, []},
      {"event_command_output_delta", "a chunk of live command output", :interactive, 106,
       :command_output_delta, %{"text" => "Compiling ouroboros v0.1.0\n"}, []},

      # -- tools, both dialects ------------------------------------------------
      {"event_tool_call_bash",
       "a Claude-dialect command call: `name`/`call_id`/`input`, no ACP `kind`", :interactive,
       107, :tool_call,
       %{
         "name" => "Bash",
         "call_id" => "toolu_01Bash000000000000001",
         "input" => %{
           "command" => "mix test --stale",
           "description" => "Run the stale suite"
         }
       }, []},
      {"event_tool_result_bash", "its result: a string `output` and an explicit `is_error`",
       :interactive, 108, :tool_result,
       %{
         "name" => "Bash",
         "call_id" => "toolu_01Bash000000000000001",
         "output" => "412 tests, 0 failures\n",
         "is_error" => false
       }, []},
      {"event_tool_call_read", "a read, which folds into the grouped exploration cell",
       :interactive, 109, :tool_call,
       %{
         "name" => "Read",
         "call_id" => "toolu_01Read000000000000001",
         "input" => %{
           "file_path" => "lib/ouroboros/gateway/wire.ex",
           "offset" => 120,
           "limit" => 40
         }
       }, []},
      {"event_tool_result_read", "its result, which is where the `→ N lines` count comes from",
       :interactive, 110, :tool_result,
       %{
         "name" => "Read",
         "call_id" => "toolu_01Read000000000000001",
         "output" =>
           "  1→defmodule Ouroboros.Gateway.Wire do\n" <>
             "  2→  @moduledoc \"The encoder the socket is written from.\"\n" <>
             "  3→end\n",
         "is_error" => false
       }, []},
      {"event_tool_call_acp_edit",
       "an ACP tool call: the agent's raw camelCase update, where `kind` is the only enum",
       :interactive, 111, :tool_call,
       %{
         "sessionUpdate" => "tool_call",
         "toolCallId" => "acp-call-0000000000000001",
         "title" => "Edit lib/ouroboros/web/transcript.ex",
         "kind" => "edit",
         "status" => "pending",
         "rawInput" => %{
           "path" => "lib/ouroboros/web/transcript.ex",
           "oldText" => "  def project(events) do\n    events\n  end\n",
           "newText" =>
             "  def project(events, cursor) do\n    events\n    |> Enum.sort()\n  end\n"
         },
         "locations" => [%{"path" => "lib/ouroboros/web/transcript.ex"}]
       }, []},
      {"event_tool_result_acp_edit",
       "the ACP `tool_call_update` that settles it, carrying `status` rather than `is_error`",
       :interactive, 112, :tool_result,
       %{
         "sessionUpdate" => "tool_call_update",
         "toolCallId" => "acp-call-0000000000000001",
         "status" => "completed",
         "content" => [
           %{
             "type" => "content",
             "content" => %{
               "type" => "text",
               "text" => "Applied 1 edit to lib/ouroboros/web/transcript.ex"
             }
           }
         ]
       }, []},
      {"event_tool_result_computer_use",
       "a Computer Use result: metadata-only image artifacts, sha-addressed, no pixels",
       :interactive, 113, :tool_result,
       %{
         "name" => "desktop_state",
         "call_id" => "toolu_01Desktop00000000001",
         "output" => "Captured the frontmost window of Calculator.",
         "is_error" => false,
         "artifacts" => [
           %{
             "kind" => "image",
             "sha256" => String.duplicate("ab", 32),
             "media_type" => "image/png",
             "bytes" => 184_320,
             "width" => 1512,
             "height" => 982
           }
         ]
       }, []},

      # -- what changed on disk ------------------------------------------------
      {"event_file_change",
       "one edit with a real unified diff, whose ± counts a client reads from the hunk " <>
         "body and not from the payload's claim", :interactive, 114, :file_change,
       %{
         "status" => "completed",
         "changes" => [
           %{
             "path" => "lib/ouroboros/web/presentation.ex",
             "relative_path" => "lib/ouroboros/web/presentation.ex",
             "kind" => "update",
             "diff" => presentation_diff(),
             "added_lines" => 4,
             "removed_lines" => 2
           }
         ]
       }, []},

      # -- bookkeeping ---------------------------------------------------------
      {"event_plan_updated", "a replace-wholesale plan with all three step statuses",
       :interactive, 115, :plan_updated,
       %{
         "explanation" => "Land the golden corpus before the renderer.",
         "plan" => [
           %{"step" => "Extend the fixture list", "status" => "completed"},
           %{"step" => "Assert the rendered words in Rust", "status" => "in_progress"},
           %{"step" => "Port the projection to Elixir", "status" => "pending"}
         ]
       }, []},
      {"event_usage", "one token report in the runtime's own spelling, with the context meter",
       :interactive, 116, :usage,
       %{
         "input_tokens" => 18_400,
         "output_tokens" => 2_100,
         "total_tokens" => 20_500,
         "cache_read_tokens" => 12_000,
         "cache_creation_tokens" => 0,
         "reasoning_tokens" => 0,
         "model" => "anthropic:claude-sonnet-4-5",
         "cost_usd" => 0.0731,
         "context_used" => 20_500,
         "context_window" => 200_000
       }, []},
      {"event_queue_changed", "how many turns the runtime is holding behind the running one",
       :interactive, 117, :queue_changed, %{"queued_turns" => 2}, []},

      # -- the turn ------------------------------------------------------------
      {"event_turn_queued", "a turn accepted behind another, with no payload of its own",
       :interactive, 118, :turn_queued, %{}, []},
      {"event_turn_started", "the native turn header: model, tool catalogue, and posture",
       :interactive, 119, :turn_started,
       %{
         "model" => "anthropic:claude-sonnet-4-5",
         "tools" => ["bash", "read", "edit"],
         "approval_mode" => "prompt",
         "sandbox_mode" => "workspace_write",
         "hooks" => 0,
         "workspace_trusted" => true
       }, []},
      {"event_turn_completed",
       "the same turn ending ninety seconds later, which is where the divider's elapsed " <>
         "time comes from", :interactive, 120, :turn_completed,
       %{
         "status" => "completed",
         "iterations" => 3,
         "input_tokens" => 18_400,
         "output_tokens" => 2_100,
         "cost_usd" => 0.0731
       }, timestamp: @turn_end_timestamp},
      {"event_turn_failed", "a turn that ended on an error the provider named", :interactive, 121,
       :turn_failed,
       %{"error" => "the model stream ended mid-tool-call", "reason" => "stream_failed"}, []},
      {"event_turn_interrupted", "a turn stopped on purpose", :interactive, 122,
       :turn_interrupted, %{"reason" => "interrupted"}, []},

      # -- the session ---------------------------------------------------------
      {"event_session_started", "the session opening, which names only its working directory",
       :interactive, 123, :session_started, %{"cwd" => "/srv/repo"}, []},
      {"event_session_ready",
       "the transport facts, which are on `session_ready` and not on `session_started`",
       :interactive, 124, :session_ready,
       %{"transport" => "acp", "maturity" => "stable", "process" => "persistent"}, []},
      {"event_session_idle", "a conversation waiting for its next prompt", :interactive, 125,
       :session_idle, %{}, []},
      {"event_session_closed", "the end of the reading path", :interactive, 126, :session_closed,
       %{"reason" => "closed"}, []},
      {"event_session_failed", "a session that died rather than closed", :interactive, 127,
       :session_failed, %{"error" => "the provider process exited with status 1"}, []},
      {"event_session_cancelled", "a session killed from outside", :interactive, 128,
       :session_cancelled, %{"reason" => "killed"}, []},

      # -- the run (the coding plane's own lifecycle) --------------------------
      {"event_run_started",
       "the Claude `init` record: the only place in the stream that names the model", :coding,
       129, :run_started,
       %{
         "cwd" => "/srv/repo",
         "model" => "claude-sonnet-4-5-20260514",
         "tools" => ["Bash", "Read", "Edit", "Grep", "Glob"]
       }, []},
      {"event_run_failed", "a run that ended on a failure", :coding, 130, :run_failed,
       %{
         "error" => "the CLI exited before the run completed",
         "subtype" => "error_during_execution"
       }, []},
      {"event_run_cancelled", "a run stopped from outside", :coding, 131, :run_cancelled,
       %{"reason" => "cancelled"}, []},

      # -- approvals, all five shapes ------------------------------------------
      {"event_approval_requested_permission",
       "an ordinary permission: command, cwd, reason, and the C1 pattern as a string",
       :interactive, 132, :approval_requested,
       %{
         "kind" => "command",
         "tool_call" => %{
           "name" => "bash",
           "command" => "git push --force origin main",
           "cwd" => "/srv/repo"
         },
         "paths" => [],
         "reason" =>
           "no permission rule engine is configured on this node, so every tool call is " <>
             "put to you",
         "suggested_rule" => "Bash(git push *)"
       }, request_id: "req-permission-000000000001"},
      {"event_approval_requested_question",
       "the native `ask_user` question, whose options are plain strings and not the " <>
         "provider options a modal maps onto a decision", :interactive, 133, :approval_requested,
       %{
         "kind" => "question",
         "question" => "Which database should the staging environment point at?",
         "header" => "Need a decision",
         "options" => ["staging-db", "scratch-db"]
       }, request_id: "req-question-0000000000001"},
      {"event_approval_requested_plan_exit",
       "the plan-exit question, with the three answers in the runtime's own words", :interactive,
       134, :approval_requested, plan_exit_payload(), request_id: "req-plan-exit-000000000001"},
      {"event_approval_requested_sandbox_escalation",
       "a re-run outside the sandbox, carrying the C1 pattern its remember row would " <>
         "save — the shape every `suggested_rule` has, on the path where it matters most",
       :interactive, 135, :approval_requested,
       %{
         "kind" => "sandbox_escalation",
         "tool_call" => %{
           "name" => "bash",
           "command" => "cargo build --release",
           "cwd" => "/srv/repo"
         },
         "paths" => ["/srv/repo/target"],
         "reason" => "the command wrote outside the workspace and the sandbox stopped it",
         "suggested_rule" => "Bash(cargo build *)"
       }, request_id: "req-escalation-00000000001"},
      {"event_approval_requested_subagent",
       "a child agent's own permission, relayed whole with one key naming the asker and " <>
         "the machine it is asking about", :interactive, 136, :approval_requested,
       %{
         "kind" => "command",
         "tool_call" => %{
           "name" => "bash",
           "command" => "rm -rf target",
           "cwd" => "/srv/worker-repo"
         },
         "paths" => ["/srv/worker-repo/target"],
         "reason" => "the session has no rule for this command",
         "subagent" => %{
           "task_id" => "task-subagent-000000000001",
           "description" => "audit the parser",
           "provider_session_id" => "provider-0000000000000009",
           "node" => "ouroboros@worker",
           "remote" => true
         }
       }, request_id: "req-subagent-0000000000001"},
      {"event_approval_resolved",
       "the answer to the permission above, by `request_id`, in the wire's own vocabulary " <>
         "(`source`, never `actor`)", :interactive, 137, :approval_resolved,
       %{
         "decision" => "approve",
         "scope" => "once",
         "source" => "human",
         "origin" => "external",
         "request_id" => "req-permission-000000000001",
         "ledger_ref" => %{"node" => @node, "id" => "effect-000000000000000000002"}
       }, request_id: "req-permission-000000000001"},

      # -- provider events, the four this runtime writes and one it does not ----
      {"event_provider_event_operator_shell",
       "a command the operator ran through `workspace.exec`, as the session's own record",
       :interactive, 138, :provider_event,
       %{
         "kind" => "operator_shell",
         "effect_id" => "effect-000000000000000000003",
         "command_digest" => "9f2c4e1a7b53d0086a1c",
         "exit_status" => 0,
         "duration_ms" => 1_240,
         "timed_out" => false,
         "output_bytes" => 48,
         "output_excerpt" => "Compiling 1 file (.ex)\nGenerated ouroboros app\n"
       }, []},
      {"event_provider_event_compaction", "one fold of the conversation, with its numbers",
       :interactive, 139, :provider_event,
       %{
         "kind" => "compaction",
         "trigger" => "automatic",
         "archived_messages" => 12,
         "archive_id" => "archive-00000000000000001",
         "elided_tool_results" => 3,
         "summary_tokens" => 640,
         "before_tokens" => 148_000,
         "after_tokens" => 21_500,
         "summary" => "The session refactored the wire encoder and added the excerpt marker."
       }, []},
      {"event_provider_event_subagent", "a child agent settling on another fleet machine",
       :interactive, 140, :provider_event,
       %{
         "kind" => "subagent",
         "phase" => "settled",
         "task_id" => "task-subagent-000000000001",
         "description" => "audit the parser",
         "provider_session_id" => "provider-0000000000000009",
         "status" => "completed",
         "turns" => 9,
         "tool_calls" => 31,
         "files_changed" => 4,
         "files" => [
           "lib/ouroboros/web/presentation.ex",
           "lib/ouroboros/web/transcript.ex",
           "test/web/presentation_test.exs",
           "test/web/transcript_test.exs"
         ],
         "input_tokens" => 18_400,
         "output_tokens" => 2_100,
         "approvals_denied" => 0,
         "summary_bytes" => 512,
         "node" => "ouroboros@worker",
         "remote" => true,
         "cost_usd" => 0.0731
       }, []},
      {"event_provider_event_plan_exit",
       "the runtime's record of how a plan-exit question was answered — which no client " <>
         "models, so it must read as a named note rather than as nothing", :interactive, 141,
       :provider_event,
       %{
         "kind" => "plan_exit",
         "choice" => "auto_edit",
         "approval_mode" => "auto_edit",
         "sandbox_mode" => "workspace_write",
         "plan" => false,
         "applied" => true,
         "follow_up" => false
       }, request_id: "req-plan-exit-000000000001"},
      {"event_provider_event_unknown",
       "an ACP update this client does not model, whose nested `sessionUpdate` is the " <>
         "informative half: the must-render-as-a-note case", :interactive, 142, :provider_event,
       %{
         "kind" => "acp_update",
         "update" => %{
           "sessionUpdate" => "terminal_output",
           "terminalId" => "term-0000000000000001",
           "output" => "waiting for the container to come up"
         }
       }, []},

      # -- the runtime's own types ---------------------------------------------
      {"event_delegation",
       "a coding task this conversation delegated, settling — a digest, never the result",
       :interactive, 143, :delegation,
       %{
         "delegation_id" => "delegation-00000000000001",
         "team_id" => "team-alpha",
         "task_id" => @task_id,
         "task_node" => "ouroboros@worker",
         "objective_digest" => "3f9a1c2b",
         "status" => "completed",
         "result_digest" => "b7e40aa1"
       }, []},
      {"event_status_resumed",
       "a fact no provider reports: this session was resumed onto a fresh Harness session",
       :interactive, 144, :status,
       %{
         "kind" => "resumed",
         "provider_session_id" => @provider_session_id,
         "previous_harness_session_id" => "harness-0000000000000000000"
       }, []}
    ]
  end

  defp transcript_fixtures do
    Enum.map(transcript_corpus(), fn {name, _gloss, plane, sequence, type, payload, fields} ->
      {name, transcript_frame(plane, sequence, type, payload, fields)}
    end)
  end

  defp transcript_frame(:interactive, sequence, type, payload, fields) do
    Conn.notification_frame("interactive.event", %{
      "id" => @session_id,
      "event" => %InteractiveEvent{
        id: event_id(sequence),
        session_id: @session_id,
        sequence: sequence,
        type: type,
        timestamp: Keyword.get(fields, :timestamp, @timestamp),
        payload: payload,
        harness_session_id: @harness_session_id,
        provider: :claude_code,
        provider_session_id: @provider_session_id,
        turn_id: @turn_id,
        request_id: Keyword.get(fields, :request_id)
      }
    })
  end

  defp transcript_frame(:coding, sequence, type, payload, fields) do
    Conn.notification_frame("coding.event", %{
      "id" => @task_id,
      "event" => %CodingEvent{
        id: event_id(sequence),
        task_id: @task_id,
        sequence: sequence,
        type: type,
        timestamp: Keyword.get(fields, :timestamp, @timestamp),
        payload: payload,
        provider: :native,
        provider_session_id: "provider-0000000000000002",
        harness_sequence: sequence
      }
    })
  end

  # The durable id is a hash of `{session_id, sequence}` in the running system. Deriving
  # it from the sequence here keeps every fixture's id unique, readable, and identical on
  # every machine — which the hash would also be, but not readably.
  defp event_id(sequence) do
    "evt-" <> String.pad_leading(Integer.to_string(sequence), 25, "0")
  end

  # A real patch, because the client counts additions and deletions from the hunk body and
  # never from `added_lines`/`removed_lines`. Four and two, and the payload says so too, so
  # a reader can see the two numbers agreeing rather than having to trust that they do.
  defp presentation_diff do
    """
    --- a/lib/ouroboros/web/presentation.ex
    +++ b/lib/ouroboros/web/presentation.ex
    @@ -1,5 +1,7 @@
     defmodule Ouroboros.Web.Presentation do
    -  def from_event(event) do
    -    event.type
    +  def from_event(%{type: type} = event) do
    +    case type do
    +      :output_text_final -> {:agent_text, event.payload["text"]}
    +    end
       end
     end
    """
  end

  # `Ouroboros.Provider.Native.Session`'s own plan-exit question, verbatim: the three
  # sentences are the only place the consequences of each answer are stated, and a client
  # shows them rather than re-wording them.
  defp plan_exit_payload do
    %{
      "kind" => "plan_exit",
      "header" => "Plan ready",
      "question" =>
        "This session has been planning. Ready to build it?\n" <>
          "· Yes, auto-accept edits — edits inside the workspace apply without asking; " <>
          "commands still ask.\n" <>
          "· Yes, manual approvals — every write and command is put to you.\n" <>
          "· No, keep planning — nothing changes and the session stays read-only.",
      "plan_source" => "plan_tool",
      "options" => [
        %{
          "optionId" => "auto_edit",
          "name" => "Yes, auto-accept edits",
          "kind" => "allow_always"
        },
        %{"optionId" => "prompt", "name" => "Yes, manual approvals", "kind" => "allow_once"},
        %{"optionId" => "keep_planning", "name" => "No, keep planning", "kind" => "reject_once"}
      ],
      "plan" => %{
        "explanation" => "Land the golden corpus before the renderer.",
        "plan" => [
          %{"step" => "Extend the fixture list", "status" => "completed"},
          %{"step" => "Assert the rendered words in Rust", "status" => "in_progress"},
          %{"step" => "Port the projection to Elixir", "status" => "pending"}
        ]
      }
    }
  end

  @doc """
  Encodes one frame as the bytes a fixture file holds: sorted keys, two-space indent.

  `JSON.encode!/1` is what the socket uses and it does not sort or indent. Both encoders
  produce the same term; only this one produces the same *bytes* on every machine, which
  is what keeps a regeneration from being a diff nobody can review.
  """
  @spec encode(term()) :: iodata()
  def encode(value), do: [pretty(value, ""), ?\n]

  defp hello_result do
    Conn.result_frame(1, %{
      "server" => "0.1.0",
      "node" => @node,
      "role" => "core",
      "protocol" => 1,
      "scope" => "operate",
      "methods" => Methods.names()
    })
  end

  # A hand-written term in the shape `Ouroboros.status/0` returns, not a capture of a live
  # node: the point is to pin the *encoding* of every leaf kind a client has to render —
  # tri-state availability words, an opaque pid inside an otherwise readable map, atoms as
  # strings, empty lists — while staying identical on every machine. A client must treat
  # each nested status map as open: the planes add keys and this is a projection.
  defp runtime_status_result do
    Conn.result_frame(2, %{
      node: :ouroboros@golden,
      role: :core,
      connected_nodes: [],
      # The exact shape `Ouroboros.Cluster.status/0` returns — no `mode` key, whatever the
      # `%{mode: :unavailable}` fallback in `Ouroboros.status/0` might suggest to a client
      # author reading only that line.
      cluster: %{
        node: :ouroboros@golden,
        role: :core,
        distributed: false,
        connected_nodes: [],
        roles: %{core: [], builder: [], signer: [], unreachable: []},
        formation: %{strategy: :none, topologies: [], supervised: false},
        security: %{
          distributed: false,
          proto_dist: :inet_tcp,
          tls: false,
          cookie: :unset
        }
      },
      availability: %{
        cluster: :available,
        mesh: :available,
        coding: :available,
        interactive: :available,
        teams: :available,
        orchestration: :available,
        control: :disabled,
        effect_ledger: :available,
        workspace: :disabled,
        hot_upgrade: :available,
        release: :available
      },
      agents: [
        %{
          id: "reviewer-1",
          pid: :erlang.list_to_pid(~c"<0.123.0>"),
          node: :ouroboros@golden,
          replicas: 1
        }
      ],
      coding_tasks: [
        %{
          id: @task_id,
          node: :ouroboros@golden,
          provider: :native,
          status: :running,
          created_at: @timestamp,
          updated_at: @timestamp
        }
      ],
      interactive_sessions: [
        %{
          id: @session_id,
          node: :ouroboros@golden,
          provider: :claude_code,
          status: :idle,
          created_at: @timestamp,
          updated_at: @timestamp
        }
      ],
      teams: [
        %{
          id: "team-alpha",
          status: :active,
          worker_count: 2,
          delegation_count: 1,
          updated_at: @timestamp
        }
      ],
      orchestration_plans: [],
      control: %{runs: []},
      effect_ledger: %{
        durability: :synced_checkpoint,
        retained: 3,
        in_flight: 1,
        ambiguous: 0,
        retention_limit: 1_000,
        next_sequence: 5
      },
      upgrade: %{
        node: :ouroboros@golden,
        mode: :ready,
        quarantine_reason: nil,
        last_epoch: 7,
        prepared: [],
        rollback_receipts: [],
        operations: []
      },
      release: %{mode: :ready, handler_releases: [], ephemeral_capability_count: 0},
      forge: %{signer: :deny, admit_possible?: false, live_count: 0, live: []}
    })
  end

  # A realistic event: the payload is already redacted where it is constructed
  # ([interactive/event.ex](../lib/ouroboros/interactive/event.ex)) and the gateway adds no
  # raw surface, so what a client renders is what this shows. `sequence` is the resync
  # cursor the whole streaming contract turns on.
  defp interactive_event_notification do
    Conn.notification_frame("interactive.event", %{
      "id" => @session_id,
      "event" => %InteractiveEvent{
        id: "evt-0000000000000000000000001",
        session_id: @session_id,
        sequence: 42,
        type: :output_text_final,
        timestamp: @timestamp,
        payload: %{"text" => "the workspace is clean", "token" => "[REDACTED]"},
        harness_session_id: "harness-0000000000000000001",
        provider: :claude_code,
        provider_session_id: "provider-0000000000000001",
        turn_id: "turn-0000000000000000000001",
        request_id: nil
      }
    })
  end

  # The coding struct names its session `task_id`, not `session_id`, while the
  # notification's own `id` parameter is the same value under the name every other method
  # uses. Both spellings are in this fixture on purpose.
  defp coding_event_notification do
    Conn.notification_frame("coding.event", %{
      "id" => @task_id,
      "event" => %CodingEvent{
        id: "evt-0000000000000000000000002",
        task_id: @task_id,
        sequence: 17,
        type: :run_completed,
        timestamp: @timestamp,
        payload: %{"text" => "objective satisfied"},
        provider: :native,
        provider_session_id: "provider-0000000000000002",
        harness_sequence: 31
      }
    })
  end

  # One `file_change` payload, four rules at once. The caps are stated at 48 and 96 bytes
  # rather than left at the 128 KiB and 512 KiB defaults, so this file pins the *shape* —
  # `_excerpt` beside `_bytes` — in bytes a reviewer can read:
  #
  #   * `diff` spends the per-leaf cap and names its true size.
  #   * `note` is cut where a three-byte character straddles the boundary, so it retreats
  #     to the last whole character and the excerpt is 46 bytes rather than 48. A client
  #     decoding this frame is owed valid UTF-8.
  #   * `path` is short enough that the marker map would cost more than the string, so it
  #     is left whole even though the budget is already gone.
  #   * `tail` arrives after the budget is spent: the excerpt is empty and `_bytes` is the
  #     only thing left that is true about it.
  #
  # Every envelope field is untouched, because a client resyncs by `sequence`.
  defp interactive_event_excerpt_notification do
    Conn.notification_frame(
      "interactive.event",
      %{"id" => @session_id, "event" => excerpted_event()},
      event_leaf_bytes: 48,
      event_payload_bytes: 96
    )
  end

  # The answer to `interactive.event_detail`: one event, bare — not an array and not
  # wrapped, because `interactive.replay` is the method that answers with a list. It is the
  # same event as the notification above, encoded under the raised `detail_leaf_bytes` cap
  # that is the whole reason the method exists, so a reviewer can read the two files side
  # by side and see the excerpts become the leaves they came from.
  defp interactive_event_detail_result do
    Conn.result_frame(7, excerpted_event(),
      event_leaf_bytes: 8_388_608,
      event_payload_bytes: 8_388_608
    )
  end

  defp coding_event_detail_result do
    Conn.result_frame(
      8,
      %CodingEvent{
        id: "evt-0000000000000000000000004",
        task_id: @task_id,
        sequence: 18,
        type: :file_change,
        timestamp: @timestamp,
        payload: %{"diff" => String.duplicate("b", 600)},
        provider: :native,
        provider_session_id: "provider-0000000000000002",
        harness_sequence: 32
      },
      event_leaf_bytes: 8_388_608,
      event_payload_bytes: 8_388_608
    )
  end

  defp excerpted_event do
    %InteractiveEvent{
      id: "evt-0000000000000000000000003",
      session_id: @session_id,
      sequence: 43,
      type: :file_change,
      timestamp: @timestamp,
      payload: %{
        "diff" => String.duplicate("a", 600),
        "note" => "x" <> String.duplicate("☃", 200),
        "path" => "lib/ouroboros/gateway/wire.ex",
        "tail" => String.duplicate("z", 700)
      },
      harness_session_id: "harness-0000000000000000001",
      provider: :claude_code,
      provider_session_id: "provider-0000000000000001",
      turn_id: "turn-0000000000000000000001",
      request_id: nil
    }
  end

  defp stream_lagged_notification do
    Conn.notification_frame("stream.lagged", %{
      "id" => @session_id,
      "plane" => "interactive",
      "dropped" => 128,
      "last_sequence" => 512
    })
  end

  defp stream_ended_notification do
    Conn.notification_frame("stream.ended", %{
      "id" => @session_id,
      "plane" => "interactive",
      "status" => "closed"
    })
  end

  defp error_unauthenticated do
    Conn.error_frame(
      1,
      Methods.code(:unauthenticated),
      "hello did not present the token this listener was started with"
    )
  end

  defp error_protocol_mismatch do
    Conn.error_frame(
      1,
      Methods.code(:protocol_mismatch),
      "this gateway speaks protocol 1, the client asked for 2",
      %{"server_protocol" => 1}
    )
  end

  defp error_scope_denied do
    Conn.error_frame(
      3,
      Methods.code(:scope_denied),
      "interactive.start mutates the runtime and this listener was started with " <>
        "OUROBOROS_GATEWAY_SCOPE=read"
    )
  end

  # The `:infinity` verbs. A gateway ceiling stops the waiting, not the work, so the
  # answer says which of the two it is: the client reconciles by reading `teams.state`.
  defp error_upstream_timeout_unknown do
    Conn.error_frame(
      4,
      Methods.code(:upstream_timeout),
      "teams.close exceeded the gateway ceiling of 60000ms; the runtime may still be " <>
        "working on it",
      %{"outcome" => "unknown"}
    )
  end

  # The one error whose `data` a client branches on rather than displays: it restarts from
  # `floor` and marks everything below it as truncated history.
  defp error_cursor_pruned do
    Conn.error_frame(
      5,
      Methods.code(:upstream_error),
      "the session no longer retains events at or below that cursor; replay from 96",
      %{"reason" => "cursor_pruned", "floor" => 96}
    )
  end

  # E2. One diagnostics answer, with the field that makes the new-only rule work across a
  # process boundary: `signature` is derived here through the live
  # `CodeIntel.Diagnostics.signature/1`, so a change to what "the same diagnostic" means
  # is a diff in this file rather than a hook that silently starts re-reporting fixed
  # errors. Positions stay 0-based, exactly as the protocol reports them.
  defp code_intel_diagnostics_result do
    Conn.result_frame(9, %{
      status: :ok,
      version: 4,
      source: "fake",
      truncated: 0,
      counts: %{error: 1, warning: 0, information: 0, hint: 0, unknown: 0},
      items: Enum.map([@diagnostic], &Map.put(&1, :signature, Diagnostics.signature(&1)))
    })
  end

  # D4. Every state a client has to render at once: a running server with its tools, one
  # this node marked broken, one it has configured but never started, and a refusal that
  # is not a server at all. `env_count` is here rather than an `env` map because that is
  # the whole rule — an MCP server's environment is a secret carrier and only its size
  # ever leaves this node. A row for a server that has never run carries no `uptime_ms`,
  # `idle_ms`, or `broken_*`, because it has none; a client must read a server row as
  # open and key on `state`.
  defp mcp_list_result do
    Conn.result_frame(12, %{
      node: :ouroboros@golden,
      enabled: true,
      supervised: true,
      protocol_version: "2026-07-28",
      transports: [:stdio],
      servers: [
        %{
          name: "fake",
          workspace: "/srv/repo",
          state: :ready,
          scope: :node,
          source: nil,
          command: "/usr/bin/fake-mcp",
          args: ["--stdio"],
          cwd: nil,
          transport: :stdio,
          env_count: 1,
          tools: 2,
          tool_names: ["mcp__fake__echo", "mcp__fake__add"],
          restarts: 0,
          claims: 1,
          uptime_ms: 61_000,
          idle_ms: 1_000,
          broken_reason: nil,
          broken_until_ms: nil
        },
        %{
          name: "flaky",
          workspace: "/srv/repo",
          state: :broken,
          scope: :user,
          source: "/home/operator/.config/ouroboros/mcp.json",
          command: "flaky-mcp",
          args: [],
          cwd: nil,
          transport: :stdio,
          env_count: 0,
          tools: 0,
          tool_names: [],
          restarts: 4,
          claims: 0,
          uptime_ms: 12_000,
          idle_ms: 12_000,
          broken_reason: "{:restart_limit, {:server_exited, 1}}",
          broken_until_ms: 288_000
        },
        %{
          name: "notes",
          workspace: "/srv/repo",
          state: :configured,
          scope: :workspace,
          source: "/srv/repo/.ouroboros/mcp.json",
          command: "./bin/notes-mcp",
          args: [],
          cwd: nil,
          transport: :stdio,
          env_count: 0,
          tools: 0,
          tool_names: [],
          restarts: 0,
          claims: 0
        }
      ],
      refusals: [
        %{
          name: "remote",
          workspace: "/srv/repo",
          scope: :user,
          reason: :unsupported_transport,
          detail: "`url` names an HTTP/SSE server; this client speaks stdio only"
        }
      ]
    })
  end

  # D11. One directory listing, from literal paths rather than from a walk of whatever
  # machine runs this task — a fixture that read a real filesystem would differ on every
  # one of them, and what a second implementation has to agree about is the shape: an
  # absolute `path`, a `parent` that is `null` at a root boundary and an absolute path
  # everywhere else, the `roots` the answer was held to, entry rows that are directories
  # and say so, and `truncated`.
  #
  # This is the ordinary answer, so `truncated` is `false` and the entry list is short.
  # Pinning the cut here would mean either five hundred rows nobody reviews or three rows
  # beside a flag claiming five hundred were dropped, which is a frame this build cannot
  # produce; the cut itself is asserted where it is cheap and real — against a directory
  # the test makes — in `Ouroboros.Gateway.WorkspaceBrowseTest`.
  defp workspace_browse_result do
    Conn.result_frame(13, %{
      "path" => "/srv/repo",
      "parent" => "/srv",
      "roots" => ["/home/operator", "/srv"],
      "entries" => [
        %{"name" => "apps", "dir" => true},
        %{"name" => "deps", "dir" => true},
        %{"name" => "lib", "dir" => true}
      ],
      "truncated" => false
    })
  end

  # I3. A fleet answer, which is the shape that matters: entries carry the node they were
  # minted on, and a machine that did not answer is a row in `nodes` rather than a shorter
  # list that looks complete.
  defp ledger_list_result do
    Conn.result_frame(10, %{
      entries: [ledger_entry()],
      nodes: [
        %{node: :ouroboros@golden, status: :ok},
        %{node: :ouroboros@offline, status: :unavailable, reason: %{"erpc" => "noconnection"}}
      ]
    })
  end

  # I1's export, derived through `Methods.chain/1` so the fixture *is* the chain a client
  # verifies. `line` is the byte string its own hash covers.
  defp ledger_export_result do
    Conn.result_frame(
      11,
      [ledger_entry()]
      |> Methods.chain()
      |> Map.merge(%{node: :ouroboros@golden, format: "jsonl", limit: 500, since: 0})
    )
  end

  # R1. A window of the turn journal. The shape a second implementation has to agree
  # about is the framing every record shares — `seq`, `at`, `turn_id`, `kind`, `prev`,
  # `hash` — plus the four fields that bound what the window *means*: the chain `head`,
  # the `head_seq` it belongs to, how far the chain `verified_through`, and what the
  # budget dropped. `truncated_through` is `null` here because this journal is whole,
  # which is the ordinary answer; a truncated one carries the sequence it dropped through
  # and is asserted where it is cheap and real, against a journal the test writes, in
  # `Ouroboros.Provider.Native.JournalTest`.
  #
  # The hashes are literals rather than a chain computed here. `Encode.chain/1` is derived
  # in `ledger_export_result` because that verb *is* the chain and a fixture that hid a
  # change to it would defeat the purpose; this verb hands back records a session already
  # sealed, so the fixture pins the field a client reads and not this build's arithmetic.
  defp interactive_journal_result do
    Conn.result_frame(14, %{
      head: String.duplicate("c", 64),
      head_seq: 4,
      verified_through: 4,
      truncated_through: nil,
      count: 4,
      records: [
        %{
          "seq" => 3,
          "at" => @timestamp,
          "turn_id" => @turn_id,
          "kind" => "model_call",
          "prev" => String.duplicate("a", 64),
          "hash" => String.duplicate("b", 64),
          "iteration" => 1,
          "request_sha256" => String.duplicate("1", 64),
          "system_sha256" => String.duplicate("2", 64),
          "tools_sha256" => String.duplicate("3", 64),
          "message_count" => 7,
          "ledger_effect_id" => "inference-00000000000000000000000000000001"
        },
        %{
          "seq" => 4,
          "at" => @turn_end_timestamp,
          "turn_id" => @turn_id,
          "kind" => "turn_settled",
          "prev" => String.duplicate("b", 64),
          "hash" => String.duplicate("c", 64),
          "status" => "complete",
          "message_count" => 7,
          "conversation_digest" => String.duplicate("4", 64)
        }
      ]
    })
  end

  # R2. A verdict from verified replay, and deliberately the *bounded* one rather than the
  # happy answer: `verified: false` with `turns: 2` is the shape a client is most likely to
  # get wrong, because the two fields together say something neither says alone — the record
  # was verified as far as it went, and it stopped going at a named record. A fixture that
  # showed only `verified: true, divergence: null` would let a client ship treating the
  # boolean as the whole answer.
  #
  # `divergence` is one object with a `kind` discriminator either way. `boundary` carries
  # `reason` and an optional `detail`; the other kind is `diverged` and carries `field`,
  # `expected_sha256` and `got_sha256` instead. Both always carry `seq`, because the one
  # question a reader always has is *which record*.
  defp interactive_replay_verify_result do
    Conn.result_frame(15, %{
      "verified" => false,
      "turns" => 2,
      "records" => 19,
      "head" => String.duplicate("c", 64),
      "divergence" => %{
        "kind" => "boundary",
        "reason" => "compaction",
        "detail" => nil,
        "seq" => 12
      }
    })
  end

  # W5. A hand-written term in the shape `Ouroboros.Wasm.Surface.status/1` returns, not a
  # capture of a live pool: a fixture that started a helper would need one on the machine
  # regenerating it, and what a second implementation has to agree about is the shape.
  #
  # Fully populated on purpose — a ready helper with an accepted `doctor` report, two of
  # sixteen hook-component slots spent, a store holding bytes a rollout protects, rollouts
  # in three of the five states, boot on — so a client's decode is exercised on every field
  # rather than on the two a quiet node happens to fill.
  #
  # **Every nested map here is an open projection.** `helper`, `store`, `rollouts` and
  # `boot` gain keys as the lane grows, and `helper.limits` is the *helper's own* bounds
  # table, forwarded under the names it reported with no list of them restated on this
  # side. A client keys on what it knows and ignores the rest.
  #
  # A field this node cannot answer is `null`, never a missing key and never `false`: an
  # unreadable store and an empty one are different facts, and `held: null` is how a client
  # tells them apart.
  #
  # `helper.path` and `store.root` are **basenames, not paths**, and the fixture pins them
  # that way because that is what `Ouroboros.Wasm.Surface` answers: both verbs are `:read`,
  # the lowest scope this gateway has, and an absolute path names an install prefix and
  # often an account to anyone who may merely look. A client that renders either as a path
  # is rendering something this protocol does not send.
  defp wasm_status_result do
    Conn.result_frame(16, %{
      node: :ouroboros@golden,
      helper: %{
        present: true,
        path: "ouro-wasm",
        world: "ouroboros:capability@0.1.0",
        phase: :ready,
        os_pid: 4242,
        instances: 2,
        owned: 1,
        pending_drops: 0,
        hook_components: 2,
        hook_component_budget: 16,
        usable: true,
        worlds: ["ouroboros:capability@0.1.0"],
        wasmtime: "43.0.1",
        limits: %{
          "max_component_bytes" => 67_108_864,
          "max_components" => 64,
          "max_deadline_ms" => 60_000,
          "max_instances" => 256,
          "max_memory_bytes" => 268_435_456,
          "max_result_bytes" => 1_048_576
        },
        broken_reason: nil
      },
      store: %{
        root: "components",
        budget_bytes: 536_870_912,
        held: 2,
        bytes: 3_145_728,
        protected: 1
      },
      rollouts: %{
        total: 3,
        by_state: %{deploying: 0, live: 1, quarantined: 1, rolled_back: 0, superseded: 1}
      },
      boot: %{enabled: true}
    })
  end

  # W5. The listing half, in the shape `Ouroboros.Wasm.Surface.list/1` returns.
  #
  # Both lists are sorted by their own identity — `artifact_id` and `sha256` — because two
  # reads of an unchanged node must produce the same bytes, and neither a directory listing
  # nor a map traversal promises that. The count beside each list is the total the node
  # holds, which is how a client sees a list that was cut at the ceiling.
  #
  # A rollout row carries no `detail` and no `eval_report`: those are arbitrary terms a
  # deployment put there, and this is a listing. `name` is the lane-W module's `"wasm/"`
  # prefix removed, because that prefix is how the register keeps a component out of the
  # atom table and is not part of what anybody deployed. `nodes` are strings for the same
  # reason: a node name a client turned back into an atom is an atom this build minted from
  # the wire.
  defp wasm_list_result do
    Conn.result_frame(17, %{
      node: :ouroboros@golden,
      rollouts: [
        %{
          artifact_id: "wasm-0000000000000000000001",
          name: "vet",
          component_sha256: String.duplicate("a", 64),
          epoch: 7,
          state: :live,
          nodes: ["ouroboros@golden", "ouroboros@peer"],
          created_at: @timestamp,
          updated_at: @timestamp
        },
        %{
          artifact_id: "wasm-0000000000000000000002",
          name: "vet",
          component_sha256: String.duplicate("b", 64),
          epoch: 6,
          state: :superseded,
          nodes: ["ouroboros@golden"],
          created_at: @timestamp,
          updated_at: @turn_end_timestamp
        },
        %{
          artifact_id: "wasm-0000000000000000000003",
          name: "lint",
          component_sha256: String.duplicate("c", 64),
          epoch: 5,
          state: :quarantined,
          nodes: ["ouroboros@peer"],
          created_at: @timestamp,
          updated_at: @turn_end_timestamp
        }
      ],
      rollout_count: 3,
      components: [
        %{sha256: String.duplicate("a", 64), size: 2_097_152, mtime: 1_767_225_600},
        %{sha256: String.duplicate("b", 64), size: 1_048_576, mtime: 1_767_225_600}
      ],
      component_count: 2
    })
  end

  # W13. One message into a lane-W capability and the reply back out.
  #
  # The fixture is a capability on purpose. `agents.message` reaches any mesh agent, but the
  # capability case is the one where the reply is a *component's* words, and pinning it here
  # is what pins the two facts a client has to carry with it: `untrusted` beside the reply,
  # and `truncated` saying whether what it is holding is the reply or a prefix of one. The
  # reply keeps string keys because that is what the wrapper decodes a guest's JSON into and
  # nothing on this path ever mints an atom from the wire.
  defp agents_message_result do
    Conn.result_frame(18, %{
      to: "wasm/vet",
      from: "gateway",
      untrusted: true,
      truncated: false,
      reply: %{"findings" => [], "checked" => 12}
    })
  end

  # W12. The four operator verbs, in the shapes `Ouroboros.Wasm.Upload`,
  # `Ouroboros.Wasm.Deploy` and `Ouroboros.Wasm.Surface` produce.
  #
  # A chunk's receipt, mid-transfer. `sha256` is `null` until the frame that closes the
  # upload, because a digest over half a file is a number that means nothing and would
  # invite a client to check it. `chunk_bytes` is the node's own ceiling, stated so a
  # client sizes its next frame from the answer rather than from a constant of its own.
  defp wasm_upload_result do
    Conn.result_frame(18, %{
      upload: "9f2c1d4e8a7b6053f1e2d3c4b5a69780",
      received: 524_288,
      complete: false,
      sha256: nil,
      chunk_bytes: 524_288
    })
  end

  # What a signature buys, and what comes back for it. Not the bundle: the **prefix** —
  # the header and the envelope — which the client writes followed by the component it
  # already holds. `bundle_bytes` is what that file will weigh, so a client can say so
  # before it writes one.
  defp wasm_sign_result do
    Conn.result_frame(19, %{
      artifact_id: "wasm-0000000000000000000001",
      name: "vet",
      epoch: 7,
      component_sha256: String.duplicate("a", 64),
      size: 2_097_152,
      world: "ouroboros:capability@0.1.0",
      imports: ["log"],
      created_at: @timestamp,
      signer: "release-key",
      start_id: "wasm/vet",
      extension: ".ouro-wasm",
      bundle_prefix: Base.encode64(wasm_bundle_prefix()),
      bundle_bytes: byte_size(wasm_bundle_prefix()) + 2_097_152
    })
  end

  # A real bundle prefix, of a realistic length, built from a literal envelope rather than
  # from `Ouroboros.Wasm.Bundle.prefix/1`: a manifest's `term_to_binary` is a fact about
  # this OTP and a fixture must be the same bytes on every machine. The framing is exact —
  # magic, version, the two lengths — so the Rust client's decode is held to the real
  # header rather than to a plausible-looking blob.
  defp wasm_bundle_prefix do
    envelope =
      ~s({"bundle":1,) <>
        ~s("manifest":"#{String.duplicate("QUJDRA", 40)}",) <>
        ~s("signature":"#{String.duplicate("A", 86)}==",) <>
        ~s("signer":"release-key"})

    "OUROWASM" <> <<1::8, byte_size(envelope)::32, 2_097_152::32>> <> envelope
  end

  # A rollout that reached `:live`, with every gate's evidence per node. Each gate is
  # `%{outcome:, detail:}` rather than the term the rollout actually held, because a stage
  # failure can carry an exception and an ambiguity an exit reason, and neither is a term a
  # socket hands out. Node names are map *keys* here and they are strings, for the reason
  # `wasm.list`'s `nodes` are: an atom a client minted from the wire is an atom nothing
  # collects.
  defp wasm_deploy_result do
    Conn.result_frame(20, %{
      artifact_id: "wasm-0000000000000000000001",
      name: "vet",
      module: "wasm/vet",
      component_sha256: String.duplicate("a", 64),
      epoch: 7,
      state: :live,
      stage: :evaluate,
      nodes: ["ouroboros@golden", "ouroboros@peer"],
      started: %{
        id: "wasm/vet",
        node: "ouroboros@golden",
        already_started: false,
        claimed_by: nil,
        errors: %{}
      },
      warnings: [],
      eval: %{
        probes: 2,
        required: "all",
        budget_ms: 10_000,
        nodes: %{
          "ouroboros@golden" => %{
            outcome: :passed,
            detail: nil,
            probes: 2,
            passed: 2,
            failed: 0,
            total_ms: 41
          },
          "ouroboros@peer" => %{
            outcome: :passed,
            detail: nil,
            probes: 2,
            passed: 2,
            failed: 0,
            total_ms: 63
          }
        }
      },
      deployment: %{
        "ouroboros@golden" => %{
          stage: %{outcome: :ok, detail: nil},
          probe: %{outcome: :ok, detail: nil},
          eval: %{
            outcome: :passed,
            detail: nil,
            probes: 2,
            passed: 2,
            failed: 0,
            total_ms: 41
          },
          recovery: nil
        },
        "ouroboros@peer" => %{
          stage: %{outcome: :ok, detail: nil},
          probe: %{outcome: :ok, detail: nil},
          eval: %{
            outcome: :passed,
            detail: nil,
            probes: 2,
            passed: 2,
            failed: 0,
            total_ms: 63
          },
          recovery: nil
        }
      }
    })
  end

  # Rollback to absence. `:rolled_back` is earned only where every node proved it, and the
  # per-node recovery says which proof each one gave: `:rolled_back` stopped a wrapper,
  # `:not_needed` found none, `:unchanged` found somebody else's, and `:quarantined` is a
  # node that could not be shown either way.
  defp wasm_rollback_result do
    Conn.result_frame(21, %{
      artifact_id: "wasm-0000000000000000000001",
      name: "vet",
      module: "wasm/vet",
      component_sha256: String.duplicate("a", 64),
      epoch: 7,
      start_id: "wasm/vet",
      state: :rolled_back,
      nodes: ["ouroboros@golden", "ouroboros@peer"],
      recovery: %{
        "ouroboros@golden" => :rolled_back,
        "ouroboros@peer" => :not_needed
      }
    })
  end

  # W13. The same verb when the reply did not fit, which is a different shape and not a
  # smaller one: `reply` is a **string** rather than the structure the agent answered with,
  # and the marker inside it is the only thing that says so. A client that read `reply` as
  # JSON whenever it was a string, or that trusted `truncated` without looking at the value,
  # would parse a prefix and report a syntax error the user cannot act on. The fixture keeps
  # a short body because what is pinned is the envelope, not the ceiling.
  defp agents_message_truncated_result do
    Conn.result_frame(19, %{
      to: "wasm/vet",
      from: "gateway",
      untrusted: true,
      truncated: true,
      reply: "{\"findings\":[{\"file\":\"lib/a.ex\"… truncated at 65536 bytes."
    })
  end

  defp ledger_entry do
    %EffectLedger.Entry{
      sequence: 12,
      started_sequence: 11,
      id: "effect-000000000000000000001",
      effect: :permission,
      principal: "session:#{@session_id}",
      claimed_from: nil,
      attempt: %{
        tool: "Bash",
        mode: :prompt,
        provider: :claude_code,
        fingerprint: %{sha256: String.duplicate("a", 64), bytes: 42}
      },
      authority: %{decision: :allow, reason: :rule},
      cause: %{signal_id: "sig-0000000000000000000001"},
      status: :ok,
      result: %{decision: :allow, scope: :once, actor: :human, rule_id: nil},
      error: nil,
      started_at: @timestamp,
      settled_at: @timestamp,
      origin_node: :ouroboros@golden
    }
  end

  defp error_not_found do
    Conn.error_frame(6, Methods.code(:not_found), "no such record on this node")
  end

  defp error_invalid_request do
    Conn.error_frame(
      nil,
      Methods.code(:invalid_request),
      "every request must carry a string or number id; this protocol has no client " <>
        "notifications"
    )
  end

  defp pretty(value, _indent) when is_map(value) and map_size(value) == 0, do: "{}"
  defp pretty([], _indent), do: "[]"

  defp pretty(value, indent) when is_map(value) do
    inner = indent <> "  "

    pairs =
      value
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.map(fn {key, member} ->
        [inner, JSON.encode!(key), ": ", pretty(member, inner)]
      end)

    ["{\n", Enum.intersperse(pairs, ",\n"), "\n", indent, "}"]
  end

  defp pretty(value, indent) when is_list(value) do
    inner = indent <> "  "
    members = Enum.map(value, fn member -> [inner, pretty(member, inner)] end)

    ["[\n", Enum.intersperse(members, ",\n"), "\n", indent, "]"]
  end

  defp pretty(value, _indent), do: JSON.encode!(value)
end
