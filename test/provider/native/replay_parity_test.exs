defmodule Ouroboros.Provider.Native.ReplayParityTest do
  @moduledoc """
  R2's headline claim, at corpus grade: a replayed turn *reads* like the turn it replays.

  A real turn runs through the real `Loop.run_turn/2` against a scripted model; its events
  are captured as they were emitted. The session is then verify-replayed and the two event
  streams are compared twice — first as raw payloads, then through the same projection a
  client renders with (`Ouroboros.EventPresentation.from_event/1` →
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

  Tool calls and steers are covered. `tool_source` is wired into `Loop.dispatch/2`, so a
  replayed tool call answers from the record instead of dispatching, and a steer — only
  reachable after `run_tools/2`, so it needs a tool call to exist at all — is fed back at
  its recorded position. This file used to pin the `:tool_source_seam_unwired` refusal
  here instead; that boundary is no longer the honest answer.
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

  describe "a turn that called a tool, and was steered mid-flight" do
    test "the seam is wired, so the engine re-runs the turn instead of bounding it" do
      # The claim every other test in this block rests on. If this ever goes false the
      # engine falls back to `:tool_source_seam_unwired` and the parity assertions below
      # would be asserting nothing, so it is stated on its own.
      Seam.forget()
      assert Seam.tool_dispatch_honored?()
    end

    test "it replays to the same stream, and to the same cells", context do
      live = run(context, tool_and_steer_script(), steer: "actually, just summarise it")

      # Not a vacuous setup: the record really does hold both a tool result and the steer.
      kinds = context |> records() |> Enum.map(& &1["kind"])
      assert "tool_result" in kinds
      assert "injected" in kinds

      assert {:ok, %{verified: true} = verdict} = verify(context)
      assert verdict.turns == 1

      assert Enum.map(live, & &1.type) == Enum.map(verdict.events, & &1.type)
      assert Enum.map(live, & &1.payload) == Enum.map(verdict.events, & &1.payload)
      assert Enum.map(live, & &1.turn_id) == Enum.map(verdict.events, & &1.turn_id)

      assert project(live) == project(verdict.events)
      refute project(live) == []
    end

    test "the replayed tool_call event carries the recorded ledger_ref", context do
      live = run(context, tool_and_steer_script(), steer: "and stop there")

      assert {:ok, verdict} = verify(context)

      live_call = Enum.find(live, &(&1.type == :tool_call))
      replayed = Enum.find(verdict.events, &(&1.type == :tool_call))
      recorded = Enum.find(records(context), &(&1["kind"] == "tool_result"))

      # Replay opens no entry of its own, so the only honest reference is the live run's —
      # and it has to be present, not merely equal-if-present: a dropped key is a payload
      # difference the projection would render as a row without a ledger link.
      assert is_map(replayed.payload["ledger_ref"])
      assert replayed.payload["ledger_ref"]["id"] == recorded["ledger_ref"]
      assert replayed.payload["ledger_ref"] == live_call.payload["ledger_ref"]
    end

    test "the steer lands after the tool result it followed, as it did live", context do
      live = run(context, tool_and_steer_script(), steer: "after the read, please")

      assert {:ok, %{verified: true} = verdict} = verify(context)

      # The ordering the control feed exists to reproduce: a steer drained before the turn
      # even reached the model is still applied *after* the tool results, so both streams
      # put the tool result ahead of the second model call.
      assert order(live) == order(verdict.events)
      assert [:tool_call, :tool_result | _rest] = order(live)
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

  # A tool call, then a final answer. The steer `run/3` sends is drained at the top of the
  # first iteration and applied after `run_tools/2` returns, which is the only position a
  # steer can occupy — and the reason a steer cannot be recorded without a tool call.
  defp tool_and_steer_script do
    [
      [
        {:text, "reading"},
        {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
      ],
      [{:text, "read it"}, {:finish, :stop}]
    ]
  end

  defp order(events),
    do: events |> Enum.map(& &1.type) |> Enum.filter(&(&1 in [:tool_call, :tool_result]))

  defp run(context, script, opts \\ []) do
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
    pid = spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "do the thing")}) end)

    # Queued before the loop has drained anything, so where it *lands* is decided by the
    # loop rather than by this scheduler — which is what makes the position reproducible.
    case Keyword.get(opts, :steer) do
      nil -> :ok
      text -> send(pid, {:native_steer, text})
    end

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
