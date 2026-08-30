defmodule Ouroboros.Provider.Native.ReplayParityTest do
  @moduledoc """
  R2's headline claim, at corpus grade: a replayed turn *reads* like the turn it replays.

  A real turn runs through the real `Loop.run_turn/2` against a scripted model; its events
  are captured as they were emitted. The session is then verify-replayed and the two event
  streams are compared twice — first as raw payloads, then through the same projection a
  client renders with (`Ouroboros.Web.Presentation.from_event/1` →
  `Ouroboros.Web.Transcript.project/1`, the Elixir half of the drift lock in
  `corpus_parity_test.exs`). Equal cells mean equal words on every surface that reads them.

  ## Two honest deviations from REPLAY.md §5.2, stated rather than papered over

  **The instants are not byte-identical, and cannot be from R1's record.** D9 says every
  emitted event re-carries the recorded `at`. The journal records an `at` per *journal
  record*, and several emitted events have no record of their own — `tool_call`, every
  `output_text_delta`, every `usage` — so the finest instant replay can honestly attach is
  the instant of the record the event came out of, which is not the instant the live event
  was minted. The projection reads `event.timestamp`, so the two streams are projected
  under one fixed instant here and the recorded-instant claim is asserted separately, on the
  events that *do* have a record. Closing this properly needs an `at` per emitted event in
  R1's record, and that is a recording change, not an engine change.

  **The turn has no tool call and no steer.** Both are blocked on the same missing wiring:
  `tool_source` is defined on the `Loop` struct and consulted only by the inference ledger
  gate, so a replayed tool call would dispatch the tool for real — and a steer cannot be
  recorded without a tool call, because `apply_steer/1` is only reachable after
  `run_tools/2`. The engine refuses such a turn by name rather than running it, and the last
  test here pins that refusal so it converts into coverage the day the seam lands.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Replay
  alias Ouroboros.Provider.Native.Replay.Seam
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Test.NativeModelScript
  alias Ouroboros.Web.Transcript

  # One instant for both streams. See the moduledoc: the projection reads the event's
  # timestamp, and the record does not carry a per-event one to give it.
  @instant "2026-08-30T12:00:00.000000Z"

  setup do
    root = Path.join(System.tmp_dir!(), "native-parity-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(root, "workspace/lib/a.ex"), "defmodule A do\nend\n")
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

    %{
      scope: scope,
      session_dir: Path.join(root, "session"),
      session_id: "parity-sess-#{System.unique_integer([:positive, :monotonic])}"
    }
  end

  describe "a replayed turn reads like the turn it replays" do
    test "the raw event stream is the same stream", context do
      live =
        run(context, [
          [
            {:thinking, "deciding"},
            {:text, "the answer is "},
            {:text, "forty two"},
            {:usage, %{input_tokens: 120, output_tokens: 9}},
            {:finish, :stop}
          ]
        ])

      assert {:ok, %{verified: true} = verdict} = verify(context)

      assert Enum.map(live, & &1.type) == Enum.map(verdict.events, & &1.type)
      assert Enum.map(live, & &1.payload) == Enum.map(verdict.events, & &1.payload)
      assert Enum.map(live, & &1.turn_id) == Enum.map(verdict.events, & &1.turn_id)
    end

    test "and it projects to the same cells", context do
      live =
        run(context, [
          [
            {:thinking, "deciding"},
            {:text, "the answer is forty two"},
            {:usage, %{input_tokens: 120, output_tokens: 9}},
            {:finish, :stop}
          ]
        ])

      assert {:ok, %{verified: true} = verdict} = verify(context)

      assert project(live) == project(verdict.events)
      # Not a vacuous equality: the turn really did render something.
      refute project(live) == []
    end

    test "two verifications of one session project identically", context do
      run(context, [[{:text, "stable"}, {:finish, :stop}]])

      assert {:ok, first} = verify(context)
      assert {:ok, second} = verify(context)
      assert project(first.events) == project(second.events)
      assert first.head == second.head
    end

    test "the events that have a record carry that record's instant (D9)", context do
      run(context, [[{:text, "timed"}, {:finish, :stop}]])

      assert {:ok, verdict} = verify(context)
      recorded = Map.new(records(context), &{&1["kind"], &1["at"]})

      assert Enum.find(verdict.events, &(&1.type == :turn_started)).at == recorded["turn_started"]

      assert Enum.find(verdict.events, &(&1.type == :turn_completed)).at ==
               recorded["turn_settled"]

      # The stream's own events came out of `model_result`, and carry its instant.
      assert Enum.find(verdict.events, &(&1.type == :output_text_final)).at ==
               recorded["model_result"]
    end
  end

  describe "the tool seam R1 has not wired yet" do
    test "a turn that called a tool is refused by name rather than re-run", context do
      run(context, [
        [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
        [{:text, "read it"}, {:finish, :stop}]
      ])

      assert {:ok, verdict} = verify(context)

      if Seam.tool_dispatch_honored?() do
        # The day `Loop.dispatch/2` answers from `tool_source`, this turn verifies and the
        # boundary below stops being the honest answer.
        assert verdict.verified, "the seam is wired but the turn did not verify"
        assert verdict.turns == 1
      else
        refute verdict.verified
        assert {:replay_boundary, :tool_source_seam_unwired, seq} = verdict.divergence
        assert seq == Enum.find(records(context), &(&1["kind"] == "tool_result"))["seq"]
        assert verdict.turns == 0
      end
    end

    test "the probe never executes anything, whatever it answers", _context do
      Seam.forget()
      answer = Seam.tool_dispatch_honored?()
      assert is_boolean(answer)
      # Memoised: the second call is the same answer without a second throwaway turn.
      assert Seam.tool_dispatch_honored?() == answer
    end
  end

  # ------------------------------------------------------------------ helpers

  defp run(context, script) do
    {model_spec, _agent} = NativeModelScript.start(script)
    {:ok, prefix} = prefix(context, model_spec)
    test = self()

    loop = %Loop{
      emit: fn event -> send(test, {:event, event}) end,
      model_module: NativeModelScript,
      model_spec: model_spec,
      system: prefix.system,
      context_window: prefix.context_window,
      prefix_fingerprint: prefix.fingerprint,
      scope: context.scope,
      session_dir: context.session_dir,
      session_id: context.session_id,
      provider_session_id: "native-parity-test",
      turn_id: "turn-1",
      approval_mode: :auto_approve,
      approval_timeout_ms: 2_000,
      journal: Journal.open(context.session_dir),
      checkpoint: fn snapshot -> {:ok, Checkpoint.digest_of(snapshot.messages)} end
    }

    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "do the thing")}) end)
    collect()
  end

  defp prefix(context, model_spec) do
    window = Window.resolve(model_spec)

    Context.build(
      system_prompt: nil,
      cwd: context.scope.root,
      add_dirs: [],
      sandbox_mode: context.scope.sandbox_mode,
      approval_mode: :auto_approve,
      tools:
        Tools.specs(nil, nil,
          workspace: context.scope.root,
          context_window: window,
          subagent_depth: 0
        ),
      model_module: NativeModelScript,
      model_spec: model_spec,
      context_window: window,
      reasoning_effort: nil,
      compactions: 0
    )
  end

  defp verify(context) do
    Replay.verify(context.session_dir,
      workspace: context.scope.root,
      add_dirs: [],
      session_id: context.session_id,
      provider_session_id: "native-parity-test",
      model_module: NativeModelScript
    )
  end

  # The struct an in-process subscriber holds, built the way `corpus_parity_test.exs` builds
  # it from a fixture: the same fields, so the same projection code runs over both streams.
  defp project(events) do
    events
    |> Enum.with_index(1)
    |> Enum.map(fn {event, index} ->
      %Transcript.Entry.Event{
        event: %Event{
          id: "event-#{index}",
          session_id: "parity",
          sequence: index,
          type: event.type,
          timestamp: @instant,
          payload: event.payload,
          provider: :native,
          provider_session_id: "native-parity-test",
          turn_id: event.turn_id,
          request_id: event.request_id
        }
      }
    end)
    |> Transcript.project()
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        receive do
          {:finished, {:ok, _state}} -> :ok
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
end
