defmodule Ouroboros.Provider.Native.LoopJournalTest do
  @moduledoc """
  R1 — what a turn writes down about itself, and what it spends doing so.

  The claims here are the ones verified replay is worthless without: the record covers
  every decision point in the order it happened, it holds the model's whole streamed
  answer (thinking included, which nothing durable held before), the tool result it holds
  is the message that entered the conversation rather than the tool's raw output, the
  chain verifies, and a model call nobody could account for never happened.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Test.NativeModelScript

  setup do
    root =
      Path.join(System.tmp_dir!(), "native-journal-loop-#{System.unique_integer([:positive])}")

    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(root, "workspace/lib/a.ex"), "defmodule A do\nend\n")
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)
    session_id = "journal-sess-#{System.unique_integer([:positive, :monotonic])}"

    %{
      root: root,
      scope: scope,
      session_dir: Path.join(root, "session"),
      session_id: session_id,
      principal: "session:" <> session_id
    }
  end

  describe "a whole turn, written down" do
    test "every decision point lands in the record, in order", context do
      {loop, _agent} =
        start_loop(context, [
          [
            {:thinking, "let me look at the file"},
            {:text, "reading"},
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}},
            {:usage, %{input_tokens: 120, output_tokens: 8}},
            {:finish, :tool_calls}
          ],
          [
            {:text, "all done"},
            {:usage, %{input_tokens: 200, output_tokens: 3}},
            {:finish, :stop}
          ]
        ])

      run(loop)
      collect()

      records = records(context)

      assert Enum.map(records, & &1["kind"]) == [
               "turn_started",
               "prompt",
               "model_call",
               "model_result",
               "tool_result",
               "model_call",
               "model_result",
               "turn_settled"
             ]

      assert Enum.all?(records, &(&1["turn_id"] == "turn-1"))
      assert Enum.map(records, & &1["seq"]) == Enum.to_list(1..8)

      # The whole file verifies, which is the claim the chain exists to make.
      assert {:ok, %{verified_through: 8}} = Journal.verify(Journal.path(context.session_dir))
    end

    test "turn_started names the posture the turn actually ran under", context do
      {loop, _agent} = start_loop(context, [[{:text, "hi"}, {:finish, :stop}]])
      run(loop)
      collect()

      started = record(context, "turn_started")

      assert started["approval_mode"] == "auto_approve"
      assert started["sandbox_mode"] == "workspace_write"
      assert started["max_iterations"] == 100
      assert started["reasoning_effort"] == nil
      assert started["prefix_fingerprint"] == "fingerprint-abc"

      assert started["system_sha256"] ==
               :sha256 |> :crypto.hash("system") |> Base.encode16(case: :lower)
    end

    test "the prompt recorded is the prompt as it entered the conversation", context do
      {loop, _agent} = start_loop(context, [[{:text, "hi"}, {:finish, :stop}]])
      run(loop, "please look at lib/a.ex")
      collect()

      assert record(context, "prompt")["content"] == "please look at lib/a.ex"
      assert record(context, "prompt")["attachments"] == []
    end

    test "turn_settled carries the digest the checkpoint computed", context do
      digest = String.duplicate("d", 64)

      {loop, _agent} =
        start_loop(context, [[{:text, "hi"}, {:finish, :stop}]],
          checkpoint: fn _snapshot -> {:ok, digest} end
        )

      run(loop)
      collect()

      settled = record(context, "turn_settled")
      assert settled["status"] == "complete"
      assert settled["conversation_digest"] == digest
      # The prompt and the model's answer: the two messages this turn added.
      assert settled["message_count"] == 2
    end

    test "a failed turn settles as failed, by name", context do
      {loop, _agent} =
        start_loop(
          context,
          [
            [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
            [{:tool_call, %{id: "c2", name: "read", input: %{"path" => "lib/a.ex"}}}]
          ],
          max_iterations: 2
        )

      run(loop)
      collect()

      assert record(context, "turn_settled")["status"] == "failed:max_iterations"
    end
  end

  describe "the model's answer" do
    test "thinking is retained, which nothing durable did before", context do
      {loop, _agent} =
        start_loop(context, [
          [
            {:thinking, "first I consider"},
            {:thinking, " then I decide"},
            {:text, "the answer"},
            {:finish, :stop}
          ]
        ])

      run(loop)
      collect()

      chunks = record(context, "model_result")["chunks"]

      assert chunks == [
               ["thinking", "first I consider"],
               ["thinking", " then I decide"],
               ["text", "the answer"],
               ["finish", "stop"]
             ]
    end

    test "the chunk list keeps stream order and every chunk kind", context do
      {loop, _agent} =
        start_loop(context, [
          [
            {:text, "a"},
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}},
            {:reasoning_details, [%{text: "why", index: 0}]},
            {:provider_metadata, %{request_id: "req-1"}},
            {:usage, %{input_tokens: 5, output_tokens: 2}},
            {:finish, :tool_calls}
          ],
          [{:text, "done"}, {:finish, :stop}]
        ])

      run(loop)
      collect()

      [first | _rest] = records_of(context, "model_result")
      kinds = Enum.map(first["chunks"], &hd/1)

      assert kinds == ~w(text tool_call reasoning_details provider_metadata usage finish)
      assert first["duration_ms"] >= 0
    end

    test "model_call records provenance, not the prompt", context do
      {loop, _agent} = start_loop(context, [[{:text, "hi"}, {:finish, :stop}]])
      run(loop, "a secret prompt nobody should find here")
      collect()

      call = record(context, "model_call")

      assert call["iteration"] == 1
      assert byte_size(call["request_sha256"]) == 64
      assert byte_size(call["tools_sha256"]) == 64
      assert call["message_count"] == 1
      assert String.starts_with?(call["ledger_effect_id"], "inference-")

      assert call["system_sha256"] ==
               :sha256 |> :crypto.hash("system") |> Base.encode16(case: :lower)

      refute call |> Journal.canonical_json() =~ "a secret prompt"
    end

    test "the reserved final round's empty tool list changes the digest", context do
      {loop, _agent} =
        start_loop(
          context,
          [
            [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
            [{:text, "done"}, {:finish, :stop}]
          ],
          max_iterations: 2
        )

      run(loop)
      collect()

      [first, final] = records_of(context, "model_call")

      # The final round is tool-free by construction, and the digest says so — which is the
      # whole reason it is taken over the projected request rather than over `messages`.
      assert first["tools_sha256"] != final["tools_sha256"]
      assert final["tools_sha256"] == Journal.digest([])
      assert first["request_sha256"] != final["request_sha256"]
    end
  end

  describe "the tool result recorded is the message that entered the conversation" do
    test "post-hook, post-diagnostics content, not the tool's raw output", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      run(loop)
      events = collect()

      result = record(context, "tool_result")
      emitted = Enum.find(events, &(&1.type == :tool_result))

      assert result["call_id"] == "c1"
      assert result["tool"] == "read"
      assert result["is_error"] == false
      assert result["content"] == emitted.payload["output"]
      assert result["output_bytes"] > 0
      assert is_integer(result["duration_ms"])
      assert String.starts_with?(result["ledger_ref"], "tool-")

      # The pointer resolves to the entry the ledger holds for the same call.
      assert {:ok, entry} = EffectLedger.get(result["ledger_ref"])
      assert entry.attempt.call_id == "c1"
    end

    test "a tool the session does not have records a result and no ledger pointer", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "teleport", input: %{}}}],
          [{:text, "no such tool"}, {:finish, :stop}]
        ])

      run(loop)
      collect()

      result = record(context, "tool_result")
      assert result["is_error"] == true
      assert result["ledger_ref"] == nil
      assert result["content"] =~ "not a tool in this session"
    end
  end

  describe "injected messages say where they came from" do
    test "a steer lands as an injected record at the boundary it landed at", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      pid = run(loop)
      send(pid, {:native_steer, "actually, stop reading"})
      collect()

      assert [injected] = records_of(context, "injected")
      assert injected["origin"] == "steer"
      assert injected["content"] == "actually, stop reading"
    end
  end

  describe "the inference ledger entry" do
    test "one settled entry per model round-trip, correlated by iteration", context do
      {loop, _agent} =
        start_loop(context, [
          [
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}},
            {:usage, %{input_tokens: 120, output_tokens: 8}}
          ],
          [{:text, "done"}, {:usage, %{input_tokens: 200, output_tokens: 3}}, {:finish, :stop}]
        ])

      run(loop)
      collect()

      assert [first, second] = inferences(context)

      assert first.status == :ok
      assert first.attempt.iteration == 1
      assert first.attempt.turn_id == "turn-1"
      assert first.attempt.session_id == context.session_id
      assert first.attempt.provider == :native
      assert byte_size(first.attempt.prompt_sha256) == 64
      assert first.result.status == :completed
      assert first.result.input_tokens == 120
      assert first.result.output_tokens == 8
      assert is_integer(first.result.duration_ms)

      assert second.attempt.iteration == 2
      assert second.result.input_tokens == 200

      # `journal_seq` is a pointer, and it resolves to this call's own `model_result`.
      results = records_of(context, "model_result")

      assert Enum.map(results, & &1["seq"]) == [
               first.result.journal_seq,
               second.result.journal_seq
             ]
    end

    test "the entry names identities and never the prompt", context do
      secret = "sk-live-never-in-a-ledger"
      {loop, _agent} = start_loop(context, [[{:text, "hi"}, {:finish, :stop}]])
      run(loop, secret)
      collect()

      assert [entry] = inferences(context)
      assert entry.cause.signal_type == "native.inference"
      assert entry.authority == %{decision: :allow, reason: "session"}
      refute inspect(entry) =~ secret
    end

    test "a provider that reported no tokens has no token keys", context do
      {loop, _agent} = start_loop(context, [[{:text, "hi"}, {:finish, :stop}]])
      run(loop)
      collect()

      assert [entry] = inferences(context)
      refute Map.has_key?(entry.result, :input_tokens)
      refute Map.has_key?(entry.result, :output_tokens)
    end
  end

  describe "a journal that cannot be written never refuses an effect" do
    test "the turn completes, says so once, and the record names the gap", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      # Written before the turn so the loop's `sync/1` finds it, then made unwritable.
      path = Journal.path(context.session_dir)
      File.write!(path, "")
      File.chmod!(path, 0o400)

      run(loop)
      events = collect()

      assert Enum.find(events, &(&1.type == :turn_completed)),
             "a journal failure refused the turn"

      degraded =
        Enum.filter(events, fn event ->
          event.type == :provider_event and event.payload["kind"] == "journal_degraded"
        end)

      assert length(degraded) == 1, "the degradation was announced #{length(degraded)} times"

      # And the effects themselves are still fully accounted for.
      assert [_first, _second] = inferences(context)

      File.chmod!(path, 0o600)
      assert Journal.open(context.session_dir) |> Journal.append("configure", %{}) != nil
      assert record(context, "gap")["dropped_kinds"] != []
    end
  end

  # ------------------------------------------------------------------ helpers

  defp start_loop(context, script, overrides \\ []) do
    {model_spec, agent} = NativeModelScript.start(script)
    test = self()

    loop =
      struct!(
        %Loop{
          emit: fn event -> send(test, {:event, event}) end,
          model_module: NativeModelScript,
          model_spec: model_spec,
          system: "system",
          prefix_fingerprint: "fingerprint-abc",
          scope: context.scope,
          session_dir: context.session_dir,
          session_id: context.session_id,
          provider_session_id: "native-journal-test",
          turn_id: "turn-1",
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000,
          journal: Journal.open(context.session_dir)
        },
        overrides
      )

    {loop, agent}
  end

  defp run(loop, prompt \\ "do the thing") do
    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, prompt)}) end)
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        # The loop writes `turn_settled` after the terminal event's `persist`, so wait for
        # the process to finish rather than racing its last append.
        receive do
          {:finished, _result} -> :ok
        after
          20_000 -> flunk("the loop did not return")
        end

        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      20_000 -> flunk("no terminal turn event within 20s")
    end
  end

  defp records(context) do
    {:ok, %{records: records}} = Journal.window(Journal.path(context.session_dir), limit: 500)
    records
  end

  defp records_of(context, kind), do: context |> records() |> Enum.filter(&(&1["kind"] == kind))
  defp record(context, kind), do: context |> records_of(kind) |> List.first()

  defp inferences(context) do
    {:ok, entries} = EffectLedger.list(principal: context.principal, effect: :inference)
    Enum.sort_by(entries, & &1.started_sequence)
  end
end
